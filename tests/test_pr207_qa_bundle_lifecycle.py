"""PR207 — Docker01 QA bundle validate/history/compare lifecycle.

These tests exercise the artifact-only lifecycle surface added to
``scripts/docker01_operator_qa_bundle.py``:

* ``validate_bundle`` — proves an existing PR206-style bundle is structurally
  complete, internally consistent, and (when a manifest is present) untampered.
* ``discover_history`` — discovers and filters bundles under a root directory.
* ``compare_bundles`` / ``compare_latest`` — report meaningful deltas between
  two bundles without re-running smoke QA.

Lifecycle modes are artifact-only: they read existing bundle files, parse JSON,
and compute hashes. They never run Docker, ShellForgeAI, or
``validation_status.py``, never use subprocess, never mutate a bundle or
Docker01, and never touch the network. Every bundle in these tests is a fake
directory built under ``tmp_path``; no real Docker daemon or real ``/tmp`` is
used.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
HELPER_PATH = SCRIPTS / "docker01_operator_qa_bundle.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


qa = _load("pr207_qa_bundle", HELPER_PATH)


PR = 206
COMMIT = "0123456789abcdef0123456789abcdef01234567"
SHORT = COMMIT[:12]


# --------------------------------------------------------------------------- #
# Fake bundle builder
# --------------------------------------------------------------------------- #


def _commands(*, version_status: str = "passed") -> list[dict]:
    entries = [
        {
            "key": "version",
            "label": "version",
            "raw_file": "raw/version.txt",
            "status": version_status,
        },
        {"key": "doctor", "label": "doctor", "raw_file": "raw/doctor.txt", "status": "passed"},
        {
            "key": "ops_report",
            "label": "ops report",
            "raw_file": "raw/ops-report.json",
            "status": "passed",
        },
    ]
    return entries


def _assertions(*, mutation_ok: bool = True) -> list[dict]:
    return [
        {"name": "ops_report_read_only", "passed": True, "detail": "ok"},
        {"name": "no_mutation_performed", "passed": mutation_ok, "detail": "ok"},
        {"name": "v1_quick_passed", "passed": True, "detail": "ok"},
    ]


def write_bundle(
    base: Path,
    name: str = "sfai-pr206-0123456789ab-qa-bundle-20240101T000000Z",
    *,
    pr: int = PR,
    commit: str = COMMIT,
    status: str = "passed",
    created_at: str = "2024-01-01T00:00:00+00:00",
    commands: list[dict] | None = None,
    assertions: list[dict] | None = None,
    mutation_performed: bool = False,
    container: dict | None = None,
    validation: dict | None = None,
    read_only: bool = True,
    manifest: bool = True,
    write_files: bool = True,
) -> Path:
    """Create a PR206-style bundle directory on disk and return its path."""
    bundle = base / name
    raw = bundle / "raw"
    raw.mkdir(parents=True, exist_ok=True)

    commands = commands if commands is not None else _commands()
    assertions = assertions if assertions is not None else _assertions()

    if write_files:
        for entry in commands:
            (bundle / entry["raw_file"]).parent.mkdir(parents=True, exist_ok=True)
            (bundle / entry["raw_file"]).write_text("raw output\n", encoding="utf-8")

    passed = sum(1 for c in commands if c["status"] == "passed")
    failed = sum(1 for c in commands if c["status"] == "failed")
    a_passed = sum(1 for a in assertions if a["passed"])
    a_failed = sum(1 for a in assertions if not a["passed"])

    qa_results = {
        "schema_version": 1,
        "mode": "docker01_operator_qa_bundle",
        "status": status,
        "pr": pr,
        "commit": commit,
        "short_sha": commit[:12],
        "created_at": created_at,
        "bundle_path": str(bundle),
        "read_only": read_only,
        "mutation_performed": mutation_performed,
        "summary": {
            "commands_total": len(commands),
            "commands_passed": passed,
            "commands_failed": failed,
            "commands_skipped": 0,
            "safety_assertions_passed": a_passed,
            "safety_assertions_failed": a_failed,
        },
        "commands": commands,
        "safety": {"read_only": read_only, "mutation_performed": mutation_performed},
        "first_safe_command": f"cat {bundle / 'qa-summary.md'}",
        "warnings": [],
    }

    container = (
        container
        if container is not None
        else {
            "available": True,
            "status": "running",
            "health": "healthy",
            "restart_count": 0,
            "image": "shellforgeai:latest",
            "labels": {},
            "disk": {"use_percent": "20%", "size": "252G", "used": "7G"},
        }
    )
    validation = (
        validation
        if validation is not None
        else {
            "requested_pr": pr,
            "requested_commit": commit,
            "available": True,
            "captured": True,
            "status": "passed",
            "classification": "passed",
            "pass_eligible": True,
            "rerun_required": False,
            "source": "heartbeat",
            "scope_matched": True,
        }
    )

    if write_files:
        (bundle / "qa-summary.md").write_text(
            "# Docker01 Operator QA Bundle\n\nreviewer still provides final merge verdict\n",
            encoding="utf-8",
        )
        _wj(bundle / "qa-results.json", qa_results)
        _wj(
            bundle / "safety-assertions.json",
            {
                "schema_version": 1,
                "mode": "docker01_operator_qa_bundle",
                "status": "passed" if a_failed == 0 else "failed",
                "summary": {"total": len(assertions), "passed": a_passed, "failed": a_failed},
                "assertions": assertions,
            },
        )
        _wj(bundle / "container-state.json", container)
        _wj(bundle / "validation-status.json", validation)
        _wj(
            bundle / "commands-run.json",
            {"schema_version": 1, "mode": "docker01_operator_qa_bundle", "commands": commands},
        )
        if manifest:
            from datetime import UTC, datetime

            now = datetime(2024, 1, 1, tzinfo=UTC)
            _wj(bundle / qa.MANIFEST_FILE, qa.build_manifest(bundle, pr, commit, now))

    return bundle


def _wj(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# Validation (1-14)
# --------------------------------------------------------------------------- #


def test_01_validates_complete_bundle(tmp_path):
    bundle = write_bundle(tmp_path)
    result = qa.validate_bundle(bundle)
    assert result["status"] == "valid"
    assert result["mode"] == "docker01_qa_bundle_validate"
    assert result["checks_failed"] == 0
    assert result["pr"] == PR
    assert result["short_sha"] == SHORT


def test_02_generated_bundle_has_validatable_manifest(tmp_path):
    # A bundle produced by the real generator carries a manifest that validates.
    from test_pr206_docker01_operator_qa_bundle import FakeRunner

    out = tmp_path / "gen"
    qa.generate_bundle(pr=PR, commit=COMMIT, out=out, runner=FakeRunner())
    manifest = json.loads((out / qa.MANIFEST_FILE).read_text())
    assert manifest["mode"] == "docker01_qa_bundle_manifest"
    assert any(f["path"] == "qa-results.json" for f in manifest["files"])
    assert any(f["path"].startswith("raw/") for f in manifest["files"])
    result = qa.validate_bundle(out)
    assert result["status"] == "valid", result["errors"]


def test_03_legacy_bundle_without_manifest_warns(tmp_path):
    bundle = write_bundle(tmp_path, manifest=False)
    result = qa.validate_bundle(bundle)
    assert result["status"] == "valid"
    assert any("bundle-manifest.json missing" in w for w in result["warnings"])


def test_04_fails_when_qa_results_missing(tmp_path):
    bundle = write_bundle(tmp_path)
    (bundle / "qa-results.json").unlink()
    result = qa.validate_bundle(bundle)
    assert result["status"] == "invalid"
    assert any("qa-results.json" in e for e in result["errors"])


def test_05_fails_when_qa_results_invalid_json(tmp_path):
    bundle = write_bundle(tmp_path)
    (bundle / "qa-results.json").write_text("{not json", encoding="utf-8")
    result = qa.validate_bundle(bundle)
    assert result["status"] == "invalid"
    assert any("strict JSON" in e for e in result["errors"])


def test_06_fails_when_qa_summary_empty(tmp_path):
    bundle = write_bundle(tmp_path)
    (bundle / "qa-summary.md").write_text("   \n", encoding="utf-8")
    result = qa.validate_bundle(bundle)
    assert result["status"] == "invalid"
    assert any("non-empty" in e for e in result["errors"])


def test_07_fails_when_raw_output_missing(tmp_path):
    bundle = write_bundle(tmp_path)
    (bundle / "raw" / "ops-report.json").unlink()
    result = qa.validate_bundle(bundle)
    assert result["status"] == "invalid"
    assert any("raw" in e for e in result["errors"])


def test_08_fails_when_command_counts_mismatch(tmp_path):
    bundle = write_bundle(tmp_path, manifest=False)
    data = json.loads((bundle / "qa-results.json").read_text())
    data["summary"]["commands_total"] = 99
    _wj(bundle / "qa-results.json", data)
    result = qa.validate_bundle(bundle)
    assert result["status"] == "invalid"
    assert any("commands_total" in e for e in result["errors"])


def test_09_fails_when_assertion_counts_mismatch(tmp_path):
    bundle = write_bundle(tmp_path, manifest=False)
    data = json.loads((bundle / "safety-assertions.json").read_text())
    data["summary"]["passed"] = 99
    _wj(bundle / "safety-assertions.json", data)
    result = qa.validate_bundle(bundle)
    assert result["status"] == "invalid"
    assert any("assertion summary passed" in e for e in result["errors"])


def test_10_validation_scope_pr_mismatch_is_flagged(tmp_path):
    bundle = write_bundle(
        tmp_path,
        manifest=False,
        validation={
            "requested_pr": 999,
            "requested_commit": COMMIT,
            "available": True,
            "captured": True,
            "status": "passed",
            "classification": "passed",
            "pass_eligible": True,
            "rerun_required": False,
            "source": "heartbeat",
            "scope_matched": True,
        },
    )
    result = qa.validate_bundle(bundle)
    assert result["status"] == "invalid"
    assert any("requested_pr" in e for e in result["errors"])


def test_11_scoped_not_found_is_clean(tmp_path):
    bundle = write_bundle(
        tmp_path,
        validation={
            "requested_pr": PR,
            "requested_commit": COMMIT,
            "available": False,
            "captured": True,
            "status": "not_found",
            "classification": "not_found",
            "pass_eligible": False,
            "rerun_required": True,
            "source": "unknown",
            "scope_matched": None,
        },
    )
    result = qa.validate_bundle(bundle)
    assert result["status"] == "valid", result["errors"]


def test_12_scope_matched_false_warns_not_valid_current(tmp_path):
    bundle = write_bundle(
        tmp_path,
        validation={
            "requested_pr": PR,
            "requested_commit": COMMIT,
            "available": False,
            "captured": True,
            "status": "not_found",
            "classification": "passed",
            "pass_eligible": False,
            "rerun_required": True,
            "source": "heartbeat",
            "scope_matched": False,
        },
    )
    result = qa.validate_bundle(bundle)
    assert result["status"] == "warning"
    assert any("scope_matched=false" in w for w in result["warnings"])


def test_13_detects_manifest_hash_mismatch(tmp_path):
    bundle = write_bundle(tmp_path)
    # Tamper with a file after the manifest was written.
    (bundle / "qa-summary.md").write_text(
        "# Docker01 Operator QA Bundle\n\ntampered\n", encoding="utf-8"
    )
    result = qa.validate_bundle(bundle)
    assert result["status"] == "invalid"
    assert any("sha256 mismatch" in e for e in result["errors"])


def test_14_validate_json_is_strict_and_stable(tmp_path):
    bundle = write_bundle(tmp_path)
    result = qa.validate_bundle(bundle)
    reparsed = json.loads(json.dumps(result))
    assert reparsed == result
    for key in ("schema_version", "mode", "status", "checks_total", "checks", "errors", "warnings"):
        assert key in result


# --------------------------------------------------------------------------- #
# History (15-22)
# --------------------------------------------------------------------------- #


def test_15_discovers_bundles_under_root(tmp_path):
    write_bundle(tmp_path, name="sfai-pr206-aaaaaaaaaaaa-qa-bundle-20240101T000000Z")
    write_bundle(tmp_path, name="sfai-pr206-bbbbbbbbbbbb-qa-bundle-20240102T000000Z")
    result = qa.discover_history(tmp_path)
    assert result["bundles_total"] == 2


def test_16_ignores_unrelated_directories(tmp_path):
    write_bundle(tmp_path)
    (tmp_path / "not-a-bundle").mkdir()
    (tmp_path / "sfai-other-thing").mkdir()
    result = qa.discover_history(tmp_path)
    assert result["bundles_total"] == 1


def test_17_sorts_newest_first(tmp_path):
    write_bundle(
        tmp_path,
        name="sfai-pr206-aaaaaaaaaaaa-qa-bundle-20240101T000000Z",
        created_at="2024-01-01T00:00:00+00:00",
    )
    write_bundle(
        tmp_path,
        name="sfai-pr206-bbbbbbbbbbbb-qa-bundle-20240105T000000Z",
        created_at="2024-01-05T00:00:00+00:00",
    )
    result = qa.discover_history(tmp_path)
    assert result["bundles"][0]["created_at"] == "2024-01-05T00:00:00+00:00"


def test_18_filters_by_pr(tmp_path):
    write_bundle(tmp_path, name="sfai-pr206-aaaaaaaaaaaa-qa-bundle-20240101T000000Z", pr=206)
    write_bundle(tmp_path, name="sfai-pr207-bbbbbbbbbbbb-qa-bundle-20240102T000000Z", pr=207)
    result = qa.discover_history(tmp_path, pr=207)
    assert result["bundles_total"] == 1
    assert result["bundles"][0]["pr"] == 207


def test_19_filters_by_commit(tmp_path):
    write_bundle(
        tmp_path, name="sfai-pr206-aaaaaaaaaaaa-qa-bundle-20240101T000000Z", commit="a" * 40
    )
    write_bundle(
        tmp_path, name="sfai-pr206-bbbbbbbbbbbb-qa-bundle-20240102T000000Z", commit="b" * 40
    )
    result = qa.discover_history(tmp_path, commit="bbbb")
    assert result["bundles_total"] == 1
    assert result["bundles"][0]["commit"] == "b" * 40


def test_20_filters_by_status(tmp_path):
    write_bundle(
        tmp_path, name="sfai-pr206-aaaaaaaaaaaa-qa-bundle-20240101T000000Z", status="passed"
    )
    write_bundle(
        tmp_path,
        name="sfai-pr206-bbbbbbbbbbbb-qa-bundle-20240102T000000Z",
        status="failed",
        commands=_commands(version_status="failed"),
    )
    result = qa.discover_history(tmp_path, status="failed")
    assert result["bundles_total"] == 1
    assert result["bundles"][0]["status"] == "failed"


def test_21_handles_invalid_bundle_without_crashing(tmp_path):
    write_bundle(tmp_path, name="sfai-pr206-aaaaaaaaaaaa-qa-bundle-20240101T000000Z")
    broken = tmp_path / "sfai-pr206-bbbbbbbbbbbb-qa-bundle-20240102T000000Z"
    broken.mkdir()
    (broken / "qa-results.json").write_text("{broken", encoding="utf-8")
    result = qa.discover_history(tmp_path)
    assert result["bundles_total"] == 2
    statuses = {b["bundle_validation"] for b in result["bundles"]}
    assert "invalid" in statuses


def test_22_reports_validation_status_per_bundle(tmp_path):
    write_bundle(tmp_path)
    result = qa.discover_history(tmp_path)
    entry = result["bundles"][0]
    assert entry["validation"]["status"] == "passed"
    assert entry["validation"]["pass_eligible"] is True
    assert entry["bundle_validation"] == "valid"


# --------------------------------------------------------------------------- #
# Compare (23-33)
# --------------------------------------------------------------------------- #


def test_23_identical_bundles_are_same(tmp_path):
    old = write_bundle(tmp_path / "a", name="b")
    new = write_bundle(tmp_path / "b", name="b")
    result = qa.compare_bundles(old, new)
    assert result["status"] == "same"


def test_24_detects_status_regression(tmp_path):
    old = write_bundle(tmp_path / "a", name="b", status="passed")
    new = write_bundle(
        tmp_path / "b",
        name="b",
        status="failed",
        commands=_commands(version_status="failed"),
    )
    result = qa.compare_bundles(old, new)
    assert result["status"] == "regressed"
    assert result["deltas"]["status_changed"] is True


def test_25_detects_status_improvement(tmp_path):
    old = write_bundle(
        tmp_path / "a", name="b", status="failed", commands=_commands(version_status="failed")
    )
    new = write_bundle(tmp_path / "b", name="b", status="passed")
    result = qa.compare_bundles(old, new)
    assert result["status"] == "improved"


def test_26_detects_command_regression(tmp_path):
    old = write_bundle(tmp_path / "a", name="b", status="partial")
    new = write_bundle(
        tmp_path / "b",
        name="b",
        status="partial",
        commands=_commands(version_status="failed"),
    )
    result = qa.compare_bundles(old, new)
    assert "version" in result["deltas"]["commands_regressed"]
    assert result["status"] == "regressed"


def test_27_detects_command_improvement(tmp_path):
    old = write_bundle(
        tmp_path / "a", name="b", status="partial", commands=_commands(version_status="failed")
    )
    new = write_bundle(tmp_path / "b", name="b", status="partial")
    result = qa.compare_bundles(old, new)
    assert "version" in result["deltas"]["commands_improved"]


def test_28_detects_safety_assertion_regression(tmp_path):
    old = write_bundle(tmp_path / "a", name="b")
    new = write_bundle(tmp_path / "b", name="b", assertions=_assertions(mutation_ok=False))
    result = qa.compare_bundles(old, new)
    assert "no_mutation_performed" in result["deltas"]["safety_regressed"]
    assert result["status"] == "regressed"


def test_29_detects_mutation_flip_as_regression(tmp_path):
    old = write_bundle(tmp_path / "a", name="b", mutation_performed=False)
    new = write_bundle(tmp_path / "b", name="b", mutation_performed=True, status="failed")
    result = qa.compare_bundles(old, new)
    assert result["status"] == "regressed"
    assert any("mutation_performed" in w for w in result["deltas"]["warnings"])


def test_30_detects_validation_status_change(tmp_path):
    old = write_bundle(tmp_path / "a", name="b")
    changed_validation = {
        "requested_pr": PR,
        "requested_commit": COMMIT,
        "available": False,
        "captured": True,
        "status": "not_found",
        "classification": "not_found",
        "pass_eligible": False,
        "rerun_required": True,
        "source": "unknown",
        "scope_matched": None,
    }
    new = write_bundle(tmp_path / "b", name="b", validation=changed_validation)
    result = qa.compare_bundles(old, new)
    assert "status" in result["deltas"]["validation_changed"]
    assert result["status"] != "same"


def test_31_detects_validation_scope_mismatch_as_regression(tmp_path):
    old = write_bundle(tmp_path / "a", name="b")
    scope_false = {
        "requested_pr": PR,
        "requested_commit": COMMIT,
        "available": False,
        "captured": True,
        "status": "not_found",
        "classification": "passed",
        "pass_eligible": False,
        "rerun_required": True,
        "source": "heartbeat",
        "scope_matched": False,
    }
    new = write_bundle(tmp_path / "b", name="b", validation=scope_false)
    result = qa.compare_bundles(old, new)
    assert result["status"] == "regressed"
    assert any("scope_matched" in w for w in result["deltas"]["warnings"])


def test_32_detects_container_restart_count_change(tmp_path):
    old = write_bundle(tmp_path / "a", name="b")
    busy_container = {
        "available": True,
        "status": "running",
        "health": "unhealthy",
        "restart_count": 3,
        "image": "shellforgeai:latest",
        "labels": {},
        "disk": {"use_percent": "20%", "size": "252G", "used": "7G"},
    }
    new = write_bundle(tmp_path / "b", name="b", container=busy_container)
    result = qa.compare_bundles(old, new)
    assert "restart_count" in result["deltas"]["container_changed"]
    assert result["status"] == "regressed"
    assert any("restart_count increased" in w for w in result["deltas"]["warnings"])
    assert any("healthy -> unhealthy" in w for w in result["deltas"]["warnings"])


def test_33_compare_json_is_strict(tmp_path):
    old = write_bundle(tmp_path / "a", name="b")
    new = write_bundle(tmp_path / "b", name="b")
    result = qa.compare_bundles(old, new)
    assert json.loads(json.dumps(result)) == result


def test_compare_invalid_bundle(tmp_path):
    old = write_bundle(tmp_path / "a", name="b")
    missing = tmp_path / "nope"
    result = qa.compare_bundles(old, missing)
    assert result["status"] == "invalid"


# --------------------------------------------------------------------------- #
# Compare-latest (34-38)
# --------------------------------------------------------------------------- #


def test_34_compare_latest_picks_newest_two(tmp_path):
    write_bundle(
        tmp_path,
        name="sfai-pr206-aaaaaaaaaaaa-qa-bundle-20240101T000000Z",
        created_at="2024-01-01T00:00:00+00:00",
    )
    write_bundle(
        tmp_path,
        name="sfai-pr206-bbbbbbbbbbbb-qa-bundle-20240103T000000Z",
        created_at="2024-01-03T00:00:00+00:00",
    )
    write_bundle(
        tmp_path,
        name="sfai-pr206-cccccccccccc-qa-bundle-20240105T000000Z",
        created_at="2024-01-05T00:00:00+00:00",
    )
    result = qa.compare_latest(tmp_path, pr=206)
    assert result["selected"]["new"].endswith("20240105T000000Z")
    assert result["selected"]["old"].endswith("20240103T000000Z")


def test_35_compare_latest_respects_pr_filter(tmp_path):
    write_bundle(
        tmp_path,
        name="sfai-pr206-aaaaaaaaaaaa-qa-bundle-20240101T000000Z",
        pr=206,
        created_at="2024-01-01T00:00:00+00:00",
    )
    write_bundle(
        tmp_path,
        name="sfai-pr207-bbbbbbbbbbbb-qa-bundle-20240102T000000Z",
        pr=207,
        created_at="2024-01-02T00:00:00+00:00",
    )
    write_bundle(
        tmp_path,
        name="sfai-pr207-cccccccccccc-qa-bundle-20240103T000000Z",
        pr=207,
        created_at="2024-01-03T00:00:00+00:00",
    )
    result = qa.compare_latest(tmp_path, pr=207)
    assert result["status"] != "not_enough_bundles"
    assert result["new"]["pr"] == 207
    assert result["old"]["pr"] == 207


def test_36_compare_latest_respects_commit_filter(tmp_path):
    write_bundle(
        tmp_path,
        name="sfai-pr206-aaaaaaaaaaaa-qa-bundle-20240101T000000Z",
        commit="a" * 40,
        created_at="2024-01-01T00:00:00+00:00",
    )
    write_bundle(
        tmp_path,
        name="sfai-pr206-bbbbbbbbbbbb-qa-bundle-20240102T000000Z",
        commit="b" * 40,
        created_at="2024-01-02T00:00:00+00:00",
    )
    write_bundle(
        tmp_path,
        name="sfai-pr206-bbbbbbbbbbbb-qa-bundle-20240103T000000Z",
        commit="b" * 40,
        created_at="2024-01-03T00:00:00+00:00",
    )
    result = qa.compare_latest(tmp_path, pr=206, commit="b" * 40)
    assert result["status"] != "not_enough_bundles"
    assert result["new"]["commit"] == "b" * 40
    assert result["old"]["commit"] == "b" * 40


def test_37_compare_latest_not_enough_bundles(tmp_path):
    write_bundle(tmp_path, name="sfai-pr206-aaaaaaaaaaaa-qa-bundle-20240101T000000Z")
    result = qa.compare_latest(tmp_path, pr=206)
    assert result["status"] == "not_enough_bundles"
    assert result["bundles_found"] == 1
    assert json.loads(json.dumps(result)) == result


def test_38_compare_latest_does_not_read_outside_root(tmp_path):
    inside = tmp_path / "inside"
    outside = tmp_path / "outside"
    inside.mkdir()
    outside.mkdir()
    write_bundle(outside, name="sfai-pr206-aaaaaaaaaaaa-qa-bundle-20240101T000000Z")
    write_bundle(outside, name="sfai-pr206-bbbbbbbbbbbb-qa-bundle-20240102T000000Z")
    # Only the empty `inside` root is searched; the outside bundles are ignored.
    result = qa.compare_latest(inside, pr=206)
    assert result["status"] == "not_enough_bundles"
    assert result["bundles_found"] == 0


# --------------------------------------------------------------------------- #
# CLI / compatibility (39-45)
# --------------------------------------------------------------------------- #


def test_39_pr206_generation_argparse_forms_still_work(tmp_path):
    from test_pr206_docker01_operator_qa_bundle import FakeRunner

    # The original PR206 generation forms still parse and run (with a fake runner
    # injected via generate_bundle; CLI parsing proven below).
    parser = qa.build_arg_parser()
    args = parser.parse_args(["--pr", "206", "--commit", COMMIT, "--out", str(tmp_path / "b")])
    assert args.pr == 206 and args.commit == COMMIT
    result = qa.generate_bundle(pr=206, commit=COMMIT, out=tmp_path / "b", runner=FakeRunner())
    assert result["status"] in ("passed", "partial")


def test_40_dry_run_executes_nothing(tmp_path):
    from test_pr206_docker01_operator_qa_bundle import FakeRunner

    runner = FakeRunner()
    result = qa.generate_bundle(
        pr=206, commit=COMMIT, out=tmp_path / "b", runner=runner, dry_run=True
    )
    assert result["status"] == "dry_run"
    assert runner.calls == []
    assert not (tmp_path / "b").exists()


def test_41_lifecycle_does_not_invoke_command_runner(tmp_path, monkeypatch):
    bundle = write_bundle(tmp_path)

    def boom(*args, **kwargs):
        raise AssertionError("lifecycle must not run commands")

    monkeypatch.setattr(qa, "run_one", boom)
    monkeypatch.setattr(qa, "default_runner", boom)
    qa.validate_bundle(bundle)
    qa.discover_history(tmp_path)


def test_42_lifecycle_does_not_call_subprocess(tmp_path, monkeypatch):
    bundle = write_bundle(tmp_path)
    new = write_bundle(tmp_path / "n", name="b")

    def boom(*args, **kwargs):
        raise AssertionError("lifecycle must not call subprocess")

    monkeypatch.setattr(qa.subprocess, "run", boom)
    monkeypatch.setattr(qa.subprocess, "Popen", boom)
    qa.validate_bundle(bundle)
    qa.discover_history(tmp_path)
    qa.compare_bundles(bundle, new)
    qa.compare_latest(tmp_path, pr=PR)


def test_43_lifecycle_human_output_is_pasteable(tmp_path, capsys):
    bundle = write_bundle(tmp_path)
    rc = qa.main(["--validate-bundle", str(bundle)])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.strip()
    assert "validate" in out

    rc = qa.main(["--history", "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "history" in out


def test_44_lifecycle_json_emits_strict_json_only(tmp_path, capsys):
    bundle = write_bundle(tmp_path)
    rc = qa.main(["--validate-bundle", str(bundle), "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    parsed = json.loads(out)  # strict: the whole stream is JSON
    assert parsed["mode"] == "docker01_qa_bundle_validate"


def test_45_unsafe_command_allowlist_still_holds():
    # PR206 allowlist behavior is unchanged by the lifecycle additions.
    assert qa.is_command_allowed(["docker", "ps", "--filter", "name=shellforgeai"])
    assert not qa.is_command_allowed(["docker", "restart", "shellforgeai"])
    assert not qa.is_command_allowed(["docker", "compose", "down"])
    assert not qa.is_command_allowed(["rm", "-rf", "/data"])


# --------------------------------------------------------------------------- #
# CLI dispatch guards
# --------------------------------------------------------------------------- #


def test_compare_cli_two_args(tmp_path, capsys):
    old = write_bundle(tmp_path / "a", name="b")
    new = write_bundle(tmp_path / "b", name="b")
    rc = qa.main(["--compare", str(old), str(new), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["status"] == "same"


def test_compare_latest_cli_exit_code(tmp_path, capsys):
    write_bundle(tmp_path, name="sfai-pr206-aaaaaaaaaaaa-qa-bundle-20240101T000000Z")
    rc = qa.main(["--compare-latest", "--root", str(tmp_path), "--pr", "206", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert out["status"] == "not_enough_bundles"


def test_two_lifecycle_modes_rejected(tmp_path):
    bundle = write_bundle(tmp_path)
    try:
        qa.main(["--validate-bundle", str(bundle), "--history"])
    except SystemExit as exc:
        assert exc.code != 0
    else:  # pragma: no cover
        raise AssertionError("expected argparse error for two lifecycle modes")
