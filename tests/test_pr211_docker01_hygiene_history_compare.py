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


h = _load("pr211_hygiene_history_compare", HELPER_PATH)


def _report(created="2026-01-01T00:00:00+00:00", **summary):
    base = {
        "disk_use_percent": "47%",
        "candidate_cleanup_items_total": 10,
        "candidate_cleanup_bytes_estimated": 1000,
        "docker_images_total": 2,
        "shellforgeai_images_total": 1,
        "compose_backups_total": 1,
        "qa_bundles_total": 1,
        "validation_artifacts_total": 1,
        "receipt_artifacts_total": 0,
    }
    base.update(summary)
    return {
        "schema_version": 1,
        "mode": h.MODE,
        "status": "ok",
        "created_at": created,
        "report_path": "/tmp/x",
        "read_only": True,
        "mutation_performed": False,
        "summary": base,
        "candidate_cleanup": [],
        "safety": h.safety_block(),
        "warnings": [],
        "first_safe_command": "cat /tmp/x/hygiene-summary.md",
    }


def make_report(root, name, report=None):
    d = root / name
    d.mkdir(parents=True)
    (d / "hygiene-report.json").write_text(json.dumps(report if report is not None else _report()))
    (d / "hygiene-summary.md").write_text("# Docker01 Hygiene Report\nno cleanup performed\n")
    (d / "candidate-cleanup-plan.md").write_text(
        "# Candidate Cleanup Plan (Proposal Only)\nNo cleanup was performed.\n"
    )
    (d / "commands-run.json").write_text("[]")
    return d


def payload(capsys):
    return json.loads(capsys.readouterr().out)


def test_history_json_lists_valid_reports_sorts_and_safety(tmp_path, capsys):
    old = make_report(
        tmp_path, "sfai-docker01-hygiene-report-old", _report("2026-01-01T00:00:00+00:00")
    )
    new = make_report(
        tmp_path,
        "sfai-pr211-hygiene-new",
        _report("2026-01-02T00:00:00+00:00", candidate_cleanup_items_total=20),
    )
    assert h.main(["--history", "--json", "--root", str(tmp_path)]) == 0
    data = payload(capsys)
    assert data["mode"] == h.HISTORY_MODE
    assert data["status"] == "ok"
    assert [r["report_dir"] for r in data["reports"]] == [str(new.resolve()), str(old.resolve())]
    assert data["summary"]["reports_total"] == 2
    assert data["summary"]["latest_report_dir"] == str(new.resolve())
    assert data["read_only"] is True and data["mutation_performed"] is False
    assert data["safety"]["read_only"] is True
    assert all(v is False for k, v in data["safety"].items() if k != "read_only")


def test_history_malformed_and_empty(tmp_path, capsys):
    bad = tmp_path / "sfai-docker01-hygiene-report-bad"
    bad.mkdir()
    (bad / "hygiene-report.json").write_text("{")
    assert h.main(["--history", "--json", "--root", str(tmp_path)]) == 0
    data = payload(capsys)
    assert data["status"] == "partial"
    assert data["reports"][0]["valid_shape"] is False
    assert data["warnings"]
    empty = tmp_path / "empty"
    empty.mkdir()
    assert h.main(["--history", "--json", "--root", str(empty)]) == 0
    data = payload(capsys)
    assert data["status"] == "empty"


def test_compare_json_deltas_notable_and_human_no_cleanup(tmp_path, capsys):
    old = make_report(
        tmp_path, "sfai-docker01-hygiene-report-old", _report("2026-01-01T00:00:00+00:00")
    )
    new = make_report(
        tmp_path,
        "sfai-docker01-hygiene-report-new",
        _report(
            "2026-01-02T00:00:00+00:00",
            disk_use_percent="54%",
            candidate_cleanup_items_total=70,
            candidate_cleanup_bytes_estimated=120 * 1024 * 1024,
            docker_images_total=4,
            shellforgeai_images_total=5,
            compose_backups_total=12,
            qa_bundles_total=30,
            validation_artifacts_total=30,
            receipt_artifacts_total=1,
        ),
    )
    assert h.main(["--compare", str(old), str(new), "--json"]) == 0
    data = payload(capsys)
    assert data["mode"] == h.COMPARE_MODE
    assert data["status"] == "ok"
    assert data["delta"]["disk_use_percent_points"] == 7
    assert data["delta"]["candidate_cleanup_items_total"] == 60
    assert data["delta"]["candidate_cleanup_bytes_estimated"] == 120 * 1024 * 1024 - 1000
    assert data["delta"]["docker_images_total"] == 2
    assert data["delta"]["shellforgeai_images_total"] == 4
    assert data["delta"]["compose_backups_total"] == 11
    assert data["delta"]["qa_bundles_total"] == 29
    assert data["delta"]["validation_artifacts_total"] == 29
    assert data["delta"]["receipt_artifacts_total"] == 1
    assert len(data["notable_changes"]) >= 6
    assert data["read_only"] is True and data["mutation_performed"] is False
    assert data["safety"]["cleanup_executed"] is False
    assert h.main(["--compare", str(old), str(new)]) == 0
    assert "compare only; no cleanup performed" in capsys.readouterr().out


def test_compare_no_notable_below_threshold(tmp_path, capsys):
    old = make_report(tmp_path, "sfai-docker01-hygiene-report-old", _report())
    new = make_report(
        tmp_path,
        "sfai-docker01-hygiene-report-new",
        _report(
            "2026-01-02T00:00:00+00:00",
            disk_use_percent="51%",
            candidate_cleanup_items_total=59,
            candidate_cleanup_bytes_estimated=50 * 1024 * 1024,
        ),
    )
    assert h.main(["--compare", str(old), str(new), "--json"]) == 0
    assert payload(capsys)["notable_changes"] == []


def test_compare_missing_malformed_and_wrong_mode_fail(tmp_path, capsys):
    good = make_report(tmp_path, "sfai-docker01-hygiene-report-good")
    assert h.main(["--compare", str(tmp_path / "missing"), str(good), "--json"]) == 1
    assert payload(capsys)["status"] == "failed"
    malformed = make_report(tmp_path, "sfai-docker01-hygiene-report-malformed")
    (malformed / "hygiene-report.json").write_text("{")
    assert h.main(["--compare", str(good), str(malformed), "--json"]) == 1
    assert "invalid or partial" in " ".join(payload(capsys)["warnings"])
    wrong = make_report(
        tmp_path, "sfai-docker01-hygiene-report-wrong", {**_report(), "mode": "wrong"}
    )
    assert h.main(["--compare", str(good), str(wrong), "--json"]) == 1
    assert payload(capsys)["status"] == "failed"


def test_compare_latest_uses_two_newest_valid_and_skips_malformed(tmp_path, capsys):
    older = make_report(
        tmp_path,
        "sfai-docker01-hygiene-report-older",
        _report("2026-01-01T00:00:00+00:00", candidate_cleanup_items_total=1),
    )
    newest = make_report(
        tmp_path,
        "sfai-docker01-hygiene-report-newest",
        _report("2026-01-03T00:00:00+00:00", candidate_cleanup_items_total=5),
    )
    malformed = make_report(
        tmp_path, "sfai-docker01-hygiene-report-malformed", _report("2026-01-04T00:00:00+00:00")
    )
    (malformed / "hygiene-report.json").write_text("{")
    assert h.main(["--compare-latest", "--json", "--root", str(tmp_path)]) == 0
    data = payload(capsys)
    assert data["old_report_dir"] == str(older.resolve())
    assert data["new_report_dir"] == str(newest.resolve())
    assert data["delta"]["candidate_cleanup_items_total"] == 4


def test_compare_latest_fails_with_fewer_than_two_valid(tmp_path, capsys):
    make_report(tmp_path, "sfai-docker01-hygiene-report-one")
    assert h.main(["--compare-latest", "--json", "--root", str(tmp_path)]) == 1
    data = payload(capsys)
    assert data["status"] == "failed"
    assert "fewer than two" in data["warnings"][0]


def test_history_compare_do_not_run_docker_create_report_or_delete(tmp_path, monkeypatch, capsys):
    old = make_report(tmp_path, "sfai-docker01-hygiene-report-old")
    new = make_report(
        tmp_path, "sfai-docker01-hygiene-report-new", _report("2026-01-02T00:00:00+00:00")
    )
    marker = tmp_path / "keep"
    marker.write_text("keep")

    def boom(*args, **kwargs):
        raise AssertionError("must not generate or run commands")

    monkeypatch.setattr(h, "write_report", boom)
    monkeypatch.setattr(h, "run_allowed_command", boom)
    assert h.main(["--history", "--json", "--root", str(tmp_path)]) == 0
    payload(capsys)
    assert h.main(["--compare", str(old), str(new), "--json"]) == 0
    data = payload(capsys)
    assert marker.exists()
    assert not (tmp_path / "sfai-docker01-hygiene-report-created").exists()
    assert data["safety"]["docker_prune_executed"] is False
    assert data["safety"]["docker_image_removed"] is False
    assert data["safety"]["file_deleted"] is False
    assert data["safety"]["container_restarted"] is False


def test_source_safety_no_shell_true_no_mutation_options_no_unsafe_examples():
    source = HELPER_PATH.read_text()
    assert "shell=True" not in source
    for forbidden in [
        "--execute",
        "--apply",
        "--cleanup",
        "--delete",
        "--prune",
        "--restart",
        "--fix",
        "--rm",
        "--rmi",
    ]:
        assert forbidden not in source
    assert "docker system prune" not in source


def test_pr209_generation_pr210_validation_and_dry_run_regressions(tmp_path, capsys):
    def runner(spec):
        out = (
            "Filesystem Size Used Avail Use% Mounted on\n/dev/root 10G 1G 9G 10% /\n"
            if spec.key == "disk"
            else ("[]" if spec.key == "docker_inspect" else "")
        )
        return h.CommandResult(spec.key, list(spec.argv), 0, out, "", True, "")

    report = h.write_report(
        tmp_path / "generated", runner=runner, roots=(str(tmp_path / "missing"),)
    )
    assert report["read_only"] is True
    realistic = _report(candidate_cleanup_items_total=593)
    realistic["candidate_cleanup"] = [
        {
            "category": "x",
            "item": f"item-{i}",
            "reason": "r",
            "risk_note": "n",
            "proposed_operator_review_action": "review",
        }
        for i in range(593)
    ]
    d = make_report(tmp_path, "sfai-docker01-hygiene-report-realistic", realistic)
    assert h.validate_report(d)["status"] == "passed"
    dry = tmp_path / "dry"
    assert h.main(["--dry-run", "--json", "--out", str(dry)]) == 0
    assert payload(capsys)["report_written"] is False
    assert not dry.exists()
