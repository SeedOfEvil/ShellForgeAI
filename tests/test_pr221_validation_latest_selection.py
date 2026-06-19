import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


validation_status = load_script("validation_status_latest_pr221", "validation_status.py")
v2 = load_script("v2_latest_pr221", "docker01_v2_readiness.py")
merge = load_script("merge_latest_pr221", "docker01_merge_readiness.py")
lane = load_script("lane_latest_pr221", "sfai_docker01_pr_lane.py")

PR = 221
COMMIT = "96eb1e27224a3ca13414dbe589a32827a2dbb196"


def patch_roots(monkeypatch, tmp_path):
    for module in (validation_status, lane.validation_status_viewer):
        monkeypatch.setattr(module, "TMP_ROOT", tmp_path)
        monkeypatch.setattr(module, "MAINLINE_TMP_ROOT", tmp_path / "validation-runs")
        monkeypatch.setattr(module, "PERSISTED_ROOT", tmp_path / "persisted")
        monkeypatch.setattr(module, "LEGACY_ROOT", tmp_path / "legacy")


def args(**overrides):
    values = {
        "latest": False,
        "pr": None,
        "commit": None,
        "include_legacy": False,
        "run_root": None,
        "explain_selection": True,
        "run_dir": None,
        "heartbeat": None,
        "status_file": None,
        "manifest": None,
        "summary": None,
        "log": None,
        "preflight": None,
        "fallback_packet": None,
        "json": True,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def write_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def write_lane_validation(
    tmp_path, *, status="passed", classification="passed", pr=PR, commit=COMMIT
):
    run = tmp_path / f"sfai-pr{pr}-{commit[:7]}-lane-20260619T191247Z" / "validation"
    run.mkdir(parents=True)
    write_json(
        run / "validation-preflight.json",
        {
            "schema_version": 1,
            "mode": validation_status.PREFLIGHT_MODE,
            "status": "failed",
            "classification": "setup_failure",
            "reason": "host setup_failure",
        },
    )
    full_pytest = {
        "result": "passed" if status == "passed" else "failed",
        "exit_code": 0 if status == "passed" else 1,
    }
    write_json(
        run / "validation-status.json",
        {
            "schema_version": 1,
            "mode": "docker01_pr_lane_validation_status",
            "status": status,
            "classification": classification,
            "pass_eligible": status == "passed",
            "rerun_required": status != "passed",
            "pr": pr,
            "commit": commit,
            "short_sha": commit[:12],
            "lane": "full",
            "full_validation": True,
            "full_validation_reason": "Lane C disposable fallback",
            "duplicate_full_pytest_detected": False,
            "full_pytest": full_pytest,
            "warnings": ["host setup_failure; disposable validation fallback finalized evidence"],
        },
    )
    return run


def report_latest():
    return validation_status.generate_report(
        args(latest=True, pr=PR, commit=COMMIT, explain_selection=True)
    )


def test_run_dir_and_latest_select_later_fallback_pass(tmp_path, monkeypatch):
    patch_roots(monkeypatch, tmp_path)
    run = write_lane_validation(tmp_path)

    explicit = validation_status.generate_report(args(run_dir=str(run)))
    latest = report_latest()

    for doc in (explicit, latest):
        assert doc["status"] == "passed"
        assert doc["classification"] == "passed"
        assert doc["pass_eligible"] is True
        assert doc["rerun_required"] is False
        assert doc["full_validation"] is True
        assert doc["full_pytest"] == {"result": "passed", "exit_code": 0}
        assert doc["duplicate_full_pytest_detected"] is False
        assert any("superseded" in warning for warning in doc["warnings"])
    assert latest["selection"].get("superseded_non_pass_evidence") is True
    assert (
        latest["selection"].get("selected_reason")
        == "latest_exact_pr_commit_completed_fallback_pass"
    )
    assert latest["source"]["run_dir"] == str(run)


def test_latest_ignores_stale_pr_or_commit(tmp_path, monkeypatch):
    patch_roots(monkeypatch, tmp_path)
    write_lane_validation(tmp_path, pr=222, commit=COMMIT)
    write_lane_validation(tmp_path, pr=PR, commit="abcdef1234567890abcdef1234567890abcdef12")

    doc = report_latest()

    assert doc["status"] == "not_found"
    assert doc["pass_eligible"] is False


def test_setup_failure_without_later_pass_remains_not_pass_eligible(tmp_path, monkeypatch):
    patch_roots(monkeypatch, tmp_path)
    run = tmp_path / f"sfai-pr{PR}-{COMMIT[:7]}-lane-20260619T191247Z" / "validation"
    run.mkdir(parents=True)
    write_json(
        run / "validation-status.json",
        {
            "schema_version": 1,
            "mode": "docker01_pr_lane_validation_status",
            "status": "setup_failure",
            "classification": "setup_failure",
            "pass_eligible": False,
            "rerun_required": True,
            "pr": PR,
            "commit": COMMIT,
            "full_validation": False,
            "full_pytest": {"result": "unknown", "exit_code": None},
        },
    )

    doc = report_latest()

    assert doc["status"] == "failed"
    assert doc["classification"] == "setup_failure"
    assert doc["pass_eligible"] is False
    assert doc["rerun_required"] is True


def test_fallback_failure_supersedes_setup_but_does_not_pass(tmp_path, monkeypatch):
    patch_roots(monkeypatch, tmp_path)
    write_lane_validation(tmp_path, status="failed", classification="test_failure")

    doc = report_latest()

    assert doc["status"] == "failed"
    assert doc["pass_eligible"] is False
    assert doc["selection"].get("superseded_non_pass_evidence") is True
    assert (
        doc["selection"].get("selected_reason")
        == "latest_exact_pr_commit_completed_fallback_failure"
    )


def test_downstream_consumes_corrected_latest_validation(tmp_path, monkeypatch):
    patch_roots(monkeypatch, tmp_path)
    write_lane_validation(tmp_path)
    validation_doc = report_latest()
    qa_dir = tmp_path / f"sfai-pr{PR}-{COMMIT[:7]}-convergence-20260619T191500Z" / "operator-qa"
    write_json(
        qa_dir / "qa-results.json",
        {
            "mode": "docker01_operator_qa_bundle",
            "status": "passed",
            "pr": PR,
            "commit": COMMIT,
            "summary": {
                "commands_passed": 21,
                "commands_failed": 0,
                "safety_assertions_passed": 17,
                "safety_assertions_failed": 0,
            },
            "hygiene": {"history_status": "ok", "compare_latest_status": "ok"},
        },
    )
    monkeypatch.setenv("SFAI_QA_BUNDLE_ROOT", str(tmp_path))
    good_lane = {
        "status": "already_complete",
        "state": {"container_status": "running", "container_health": "healthy", "restart_count": 0},
        "checks": [
            {"name": "source_head_matches", "passed": True},
            {"name": "compose_image_matches", "passed": True},
            {"name": "container_labels_match", "passed": True},
            {"name": "container_image_matches", "passed": True},
            {"name": "container_running", "passed": True},
            {"name": "container_healthy", "passed": True},
            {"name": "restart_count_acceptable", "passed": True},
        ],
    }
    monkeypatch.setattr(lane, "_status_git_head", lambda runner=None: COMMIT)
    monkeypatch.setattr(
        lane, "_read_compose_image", lambda: f"lab/shellforgeai:pr{PR}-{COMMIT[:7]}"
    )
    monkeypatch.setattr(
        lane,
        "_status_container",
        lambda runner=None: {
            "container_image": f"lab/shellforgeai:pr{PR}-{COMMIT[:7]}",
            "container_image_id": "sha256:abc",
            "container_status": "running",
            "container_health": "healthy",
            "restart_count": 0,
            "labels": {"homelab.pr": str(PR), "homelab.commit": COMMIT},
        },
    )
    assert lane.build_pr_lane_status(pr=PR, commit=COMMIT)["status"] == "already_complete"

    monkeypatch.setattr(merge, "load_pr_lane_status", lambda pr, commit: good_lane)
    monkeypatch.setattr(merge, "load_validation_status", lambda pr, commit: validation_doc)
    merge_doc = merge.build_report(PR, COMMIT)[0]
    assert merge_doc["status"] == "pass_candidate"

    monkeypatch.setattr(v2, "load_pr_lane_status", lambda pr, commit: good_lane)
    monkeypatch.setattr(v2, "load_validation_status", lambda pr, commit: validation_doc)
    monkeypatch.setattr(v2, "load_merge_readiness", lambda pr, commit: merge_doc)
    assert v2.build_report(PR, COMMIT)[0]["status"] == "v2_candidate"
