import argparse
import importlib.util
import json
from pathlib import Path

import pytest


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, Path(rel))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


lane = _load("sfai_docker01_pr_lane", "scripts/sfai_docker01_pr_lane.py")
validation_status = _load("validation_status", "scripts/validation_status.py")


COMMIT = "abcdef1234567890"


def _plan(full=False):
    return lane.plan_docker01_lane(
        changed_files=["scripts/sfai_docker01_pr_lane.py"],
        pr_number="214",
        profile="targeted_runtime",
        full_validation=full,
        full_validation_reason="PR lane requires full validation" if full else None,
    )


def _records(plan, status="passed"):
    records = []
    for command in plan["_commands"]:
        records.append(lane._command_record(command, status=status, duration=0.001, log_path=None))
    return records


def _write(tmp_path, *, pr="214", commit=COMMIT, status="passed", classification=None, full=False):
    plan = _plan(full=full)
    records = _records(plan, status="passed" if status == "passed" else "failed")
    manifest = lane.build_validation_manifest(
        plan,
        pr_number=pr,
        head_commit=commit,
        commands=records,
        status="incomplete" if status == "interrupted" else status,
        classification=classification,
        pass_eligible=status == "passed",
        rerun_required=status != "passed",
        full_pytest_exit_code=0 if status == "passed" and full else None,
    )
    run_dir = tmp_path / f"sfai-pr{pr}-{commit[:12]}-validation-20260615T000000"
    lane.write_lane_validation_evidence(
        run_dir=run_dir,
        manifest=manifest,
        command_records=records,
        log_path=None,
        created_at="2026-06-15T00:00:00Z",
    )
    return run_dir


def _read(run_dir, name):
    return json.loads((run_dir / name).read_text())


def test_successful_targeted_lane_writes_required_files_and_strict_json(tmp_path):
    run_dir = _write(tmp_path)
    assert (run_dir / "validation-status.json").is_file()
    assert (run_dir / "validation-manifest.json").is_file()
    assert (run_dir / "validation-summary.md").is_file()
    assert (run_dir / "commands-run.json").is_file()
    assert (run_dir / "logs").is_dir()
    status = _read(run_dir, "validation-status.json")
    manifest = _read(run_dir, "validation-manifest.json")
    commands = _read(run_dir, "commands-run.json")
    summary = (run_dir / "validation-summary.md").read_text()
    assert status["mode"] == "docker01_pr_lane_validation_status"
    assert manifest["mode"] == "docker01_pr_lane_validation_manifest"
    assert summary.startswith("# Docker01 PR Lane Validation Evidence")
    assert "| Command | Status | Exit code |" in summary
    assert commands


def test_manifest_includes_sha256_and_size_for_artifacts(tmp_path):
    run_dir = _write(tmp_path)
    manifest = _read(run_dir, "validation-manifest.json")
    paths = {item["path"] for item in manifest["artifacts"]}
    assert {
        "validation-status.json",
        "validation-manifest.json",
        "validation-summary.md",
        "commands-run.json",
    } <= paths
    for item in manifest["artifacts"]:
        assert len(item["sha256"]) == 64
        assert item["size_bytes"] > 0


@pytest.mark.parametrize(
    "status, classification, expected_status, expected_class, eligible, rerun",
    [
        ("passed", None, "passed", "passed", True, False),
        ("failed", None, "failed", "failed", False, True),
        ("failed", "setup_failure", "setup_failure", "setup_failure", False, True),
        (
            "interrupted",
            "interrupted_or_incomplete",
            "interrupted",
            "interrupted_or_incomplete",
            False,
            True,
        ),
    ],
)
def test_status_classification_and_pass_eligibility(
    tmp_path, status, classification, expected_status, expected_class, eligible, rerun
):
    run_dir = _write(tmp_path, status=status, classification=classification)
    doc = _read(run_dir, "validation-status.json")
    assert doc["status"] == expected_status
    assert doc["classification"] == expected_class
    assert doc["pass_eligible"] is eligible
    assert doc["rerun_required"] is rerun


def test_pr_commit_short_sha_scoping(tmp_path):
    run_dir = _write(tmp_path, pr="214", commit=COMMIT)
    doc = _read(run_dir, "validation-status.json")
    assert doc["pr"] == 214
    assert doc["commit"] == COMMIT
    assert doc["short_sha"] == COMMIT[:12]


def test_validation_status_finds_exact_pr_commit_and_ignores_stale(tmp_path, monkeypatch):
    stale = _write(tmp_path, pr="213", commit="1111111111112222")
    current = _write(tmp_path, pr="214", commit=COMMIT)
    monkeypatch.setenv(validation_status.RUNS_DIR_ENV, str(tmp_path))
    args = argparse.Namespace(
        latest=True,
        pr=214,
        commit=COMMIT,
        run_root=None,
        include_legacy=False,
        explain_selection=True,
        run_dir=None,
        heartbeat=None,
        status_file=None,
        manifest=None,
        summary=None,
        log=None,
        json=True,
    )
    report = validation_status.generate_report(args)
    assert report["status"] == "passed"
    assert report["classification"] == "passed"
    assert report["pass_eligible"] is True
    assert report["rerun_required"] is False
    assert report["source"]["kind"] == "run_dir"
    assert report["source"]["run_dir"] == str(current)
    skipped = {c["path"]: c["skipped_reason"] for c in report["selection"]["candidates"]}
    assert skipped[str(stale)] == "PR mismatch"


def test_validation_status_returns_not_found_for_missing_pr_commit(tmp_path, monkeypatch):
    _write(tmp_path, pr="213", commit="1111111111112222")
    monkeypatch.setenv(validation_status.RUNS_DIR_ENV, str(tmp_path))
    args = argparse.Namespace(
        latest=True,
        pr=214,
        commit=COMMIT,
        run_root=None,
        include_legacy=False,
        explain_selection=True,
        run_dir=None,
        heartbeat=None,
        status_file=None,
        manifest=None,
        summary=None,
        log=None,
        json=True,
    )
    report = validation_status.generate_report(args)
    assert report["status"] == "not_found"
    assert report["pass_eligible"] is False


def test_commands_run_records_expected_commands_and_full_pytest(tmp_path):
    targeted = _read(_write(tmp_path), "commands-run.json")
    keys = {item["key"] for item in targeted}
    assert "ruff" in keys
    assert "compileall" in keys
    assert "targeted_pytest" in keys
    full = _read(_write(tmp_path / "full", full=True), "commands-run.json")
    assert "full_pytest" in {item["key"] for item in full}
    assert all(len(item["log_excerpt"]) <= 1000 for item in full)


def test_safety_block_and_parser_do_not_introduce_mutation_options(tmp_path):
    run_dir = _write(tmp_path)
    safety = _read(run_dir, "validation-status.json")["safety"]
    assert safety["read_only"] is True
    for key in (
        "mutation_performed",
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
        "docker_prune_executed",
        "docker_image_removed",
        "file_deleted",
        "shell_true",
        "cloud_apply_merge_push",
    ):
        assert safety[key] is False
    option_strings = {
        opt for action in lane.build_parser()._actions for opt in action.option_strings
    }
    forbidden = {
        "--execute-cleanup",
        "--cleanup",
        "--delete",
        "--prune",
        "--restart",
        "--apply",
    }
    assert option_strings.isdisjoint(forbidden)
