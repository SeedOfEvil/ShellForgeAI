import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_hygiene_report.py"


def _load(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


h = _load("pr212_hygiene_review_bundle", HELPER_PATH)


def _report(created="2026-01-01T00:00:00+00:00", **summary):
    s = {
        "disk_use_percent": "50%",
        "candidate_cleanup_items_total": 2,
        "candidate_cleanup_bytes_estimated": 1234,
        "docker_images_total": 3,
        "shellforgeai_images_total": 2,
        "compose_backups_total": 1,
        "qa_bundles_total": 1,
        "validation_artifacts_total": 1,
        "receipt_artifacts_total": 1,
    }
    s.update(summary)
    return {
        "schema_version": 1,
        "mode": h.MODE,
        "status": "ok",
        "created_at": created,
        "report_path": "/tmp/source",
        "read_only": True,
        "mutation_performed": False,
        "summary": s,
        "candidate_cleanup": [
            {
                "category": "qa_bundles",
                "item": "/tmp/sfai-pr-x",
                "reason": "old evidence",
                "risk_note": "review first",
                "proposed_operator_review_action": "review in a separate cleanup PR/lane",
            }
        ],
        "safety": h.safety_block(),
        "warnings": [],
        "first_safe_command": "cat /tmp/source/hygiene-summary.md",
    }


def _commands():
    return [
        {
            "key": spec.key,
            "argv": list(spec.argv),
            "returncode": 0,
            "stdout": "",
            "stderr": "",
            "available": True,
            "reason": "",
        }
        for spec in h.COMMAND_SPECS
    ]


def make_report(root, name="sfai-docker01-hygiene-report-a", report=None):
    d = root / name
    (d / "raw").mkdir(parents=True)
    (d / "hygiene-report.json").write_text(json.dumps(report or _report()))
    (d / "hygiene-summary.md").write_text("# Docker01 Hygiene Report\n\n* no cleanup performed\n")
    (d / "candidate-cleanup-plan.md").write_text(
        "# Candidate Cleanup Plan (Proposal Only)\n"
        "No cleanup was performed.\n"
        "This report does not prune Docker.\n"
    )
    (d / "commands-run.json").write_text(json.dumps(_commands()))
    (d / "raw" / "disk.txt").write_text("ok")
    return d


def payload(capsys):
    return json.loads(capsys.readouterr().out)


def test_review_bundle_writes_required_files_strict_json_manifest_checksums(tmp_path, capsys):
    source = make_report(tmp_path)
    out = tmp_path / "bundle"
    assert h.main(["--review-bundle", str(source), "--out", str(out), "--json"]) == 0
    data = payload(capsys)
    required = {
        "hygiene-review-summary.md",
        "hygiene-review.json",
        "manifest.json",
        "checksums.json",
        "source-hygiene-report.json",
        "source-hygiene-summary.md",
        "source-candidate-cleanup-plan.md",
        "validation-result.json",
        "history-snapshot.json",
        "compare-latest.json",
        "safety-notes.md",
    }
    assert required <= {p.name for p in out.iterdir()}
    assert json.loads((out / "hygiene-review.json").read_text())["mode"] == h.REVIEW_BUNDLE_MODE
    manifest = json.loads((out / "manifest.json").read_text())
    checksums = json.loads((out / "checksums.json").read_text())
    assert required <= {a["path"] for a in manifest["artifacts"]}
    assert required <= set(checksums)
    assert (
        (out / "hygiene-review-summary.md")
        .read_text()
        .startswith("# Docker01 Hygiene Review Bundle")
    )
    assert "evidence only" in (out / "safety-notes.md").read_text()
    assert "No cleanup was performed" in (out / "safety-notes.md").read_text()
    assert data["safety"]["cleanup_executed"] is False
    assert data["safety"]["file_deleted"] is False


def test_latest_selects_newest_valid_and_skips_malformed(tmp_path, capsys):
    make_report(tmp_path, "sfai-docker01-hygiene-report-old", _report("2026-01-01T00:00:00+00:00"))
    new = make_report(
        tmp_path, "sfai-docker01-hygiene-report-new", _report("2026-01-03T00:00:00+00:00")
    )
    bad = make_report(
        tmp_path, "sfai-docker01-hygiene-report-bad", _report("2026-01-04T00:00:00+00:00")
    )
    (bad / "hygiene-report.json").write_text("{")
    assert (
        h.main(
            [
                "--review-bundle-latest",
                "--root",
                str(tmp_path),
                "--out",
                str(tmp_path / "b"),
                "--json",
            ]
        )
        == 0
    )
    data = payload(capsys)
    assert data["source_report_dir"] == str(new.resolve())


def test_latest_fails_when_no_valid_report(tmp_path, capsys):
    assert h.main(["--review-bundle-latest", "--root", str(tmp_path), "--json"]) == 1
    assert "no valid" in payload(capsys)["error"]


def test_partial_compare_unavailable_validation_failure_and_oversized(tmp_path, capsys):
    source = make_report(tmp_path)
    assert h.main(["--review-bundle", str(source), "--out", str(tmp_path / "one"), "--json"]) == 0
    data = payload(capsys)
    assert data["summary"]["compare_latest_status"] == "not_available"
    assert data["warnings"]

    invalid = make_report(tmp_path / "invalidroot")
    (invalid / "candidate-cleanup-plan.md").unlink()
    assert (
        h.main(
            ["--review-bundle", str(invalid), "--out", str(tmp_path / "invalidbundle"), "--json"]
        )
        == 0
    )
    assert payload(capsys)["status"] == "partial"

    huge = make_report(tmp_path / "hugeroot")
    (huge / "hygiene-summary.md").write_text("x" * (h.MAX_MARKDOWN_VALIDATE_BYTES + 1))
    assert (
        h.main(["--review-bundle", str(huge), "--out", str(tmp_path / "hugebundle"), "--json"]) == 1
    )
    assert payload(capsys)["status"] == "failed"


def test_review_bundle_no_docker_generation_or_source_mutation(tmp_path, monkeypatch, capsys):
    source = make_report(tmp_path)
    before = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}

    def boom(*args, **kwargs):
        raise AssertionError("must not run docker or generate report")

    monkeypatch.setattr(h, "write_report", boom)
    monkeypatch.setattr(h, "run_allowed_command", boom)
    assert (
        h.main(["--review-bundle", str(source), "--out", str(tmp_path / "bundle"), "--json"]) == 0
    )
    data = payload(capsys)
    after = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    assert before == after
    assert data["summary"]["source_validation_status"] == "passed"


def test_source_safety_no_shell_true_no_mutation_options_or_unsafe_examples():
    source = HELPER_PATH.read_text()
    assert "shell=True" not in source
    for forbidden in [
        "--execute",
        "--apply",
        "--cleanup",
        "--delete",
        "--prune",
        "--restart",
        "--rm",
        "--rmi",
    ]:
        assert forbidden not in source
    assert "docker system prune" not in source


def test_regressions_generation_validation_history_compare_dry_run(tmp_path, capsys):
    def runner(spec):
        out = (
            "Filesystem Size Used Avail Use% Mounted on\n/dev/root 10G 1G 9G 10% /\n"
            if spec.key == "disk"
            else ("[]" if spec.parse == "json" else "")
        )
        return h.CommandResult(spec.key, list(spec.argv), 0, out, "", True, "")

    generated = tmp_path / "generated"
    h.write_report(generated, runner=runner, roots=(str(tmp_path / "missing"),))
    assert h.validate_report(generated)["status"] == "passed"
    make_report(tmp_path, "sfai-docker01-hygiene-report-1", _report("2026-01-01T00:00:00+00:00"))
    make_report(tmp_path, "sfai-docker01-hygiene-report-2", _report("2026-01-02T00:00:00+00:00"))
    assert h.main(["--history", "--root", str(tmp_path), "--json"]) == 0
    payload(capsys)
    assert h.main(["--compare-latest", "--root", str(tmp_path), "--json"]) == 0
    payload(capsys)
    before = set(tmp_path.iterdir())
    assert h.main(["--dry-run", "--out", str(tmp_path / "dry"), "--json"]) == 0
    payload(capsys)
    assert set(tmp_path.iterdir()) == before
