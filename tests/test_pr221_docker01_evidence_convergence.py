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


validation_status = load_script("validation_status_convergence_pr221", "validation_status.py")
lane = load_script("lane_convergence_pr221", "sfai_docker01_pr_lane.py")
merge = load_script("merge_convergence_pr221", "docker01_merge_readiness.py")
v2 = load_script("v2_convergence_pr221", "docker01_v2_readiness.py")

PR = 221
COMMIT = "159229e27a5335da4589e87135f379743c1bf943"


def patch_validation_roots(monkeypatch, tmp_path):
    for module in (validation_status, lane.validation_status_viewer):
        monkeypatch.setattr(module, "TMP_ROOT", tmp_path)
        monkeypatch.setattr(module, "MAINLINE_TMP_ROOT", tmp_path / "validation-runs")
        monkeypatch.setattr(module, "PERSISTED_ROOT", tmp_path / "persisted")
        monkeypatch.setattr(module, "LEGACY_ROOT", tmp_path / "legacy")


def write_real_style_validation_log(tmp_path, *, body: str, commit: str = COMMIT):
    path = tmp_path / f"sfai-pr{PR}-{commit[:7]}-validation-20260619T135302Z.log"
    path.write_text(body, encoding="utf-8")
    return path


def full_success_log():
    return "\n".join(
        [
            f"Docker01 validation lane for PR {PR} commit {COMMIT}",
            "ruff passed",
            "compileall passed",
            "PR221 targeted tests passed: 24/24",
            "full pytest passed once: 100%, exit 0, xdist used, 575.5s",
            "lane summary: validation passed",
        ]
    )


def validation_report():
    args = argparse.Namespace(
        latest=True,
        pr=PR,
        commit=COMMIT,
        include_legacy=False,
        run_root=None,
        explain_selection=True,
        run_dir=None,
        heartbeat=None,
        status_file=None,
        manifest=None,
        summary=None,
        log=None,
        preflight=None,
        fallback_packet=None,
    )
    return validation_status.generate_report(args)


def write_nested_qa(tmp_path, *, status="passed", commit: str = COMMIT, pr: int = PR):
    bundle = tmp_path / f"sfai-pr{pr}-{commit[:7]}-convergence-20260619T140507Z" / "operator-qa"
    bundle.mkdir(parents=True)
    doc = {
        "mode": "docker01_operator_qa_bundle",
        "status": status,
        "pr": pr,
        "commit": commit,
        "short_sha": commit[:12],
        "summary": {
            "commands_passed": 21 if status == "passed" else 20,
            "commands_failed": 0 if status == "passed" else 1,
            "safety_assertions_passed": 17,
            "safety_assertions_failed": 0,
        },
        "hygiene": {"history_status": "ok", "compare_latest_status": "ok", "warnings": []},
        "warnings": [],
        "commands": [] if status == "passed" else [{"key": "qa", "status": "failed"}],
    }
    (bundle / "qa-results.json").write_text(json.dumps(doc), encoding="utf-8")
    return bundle


def good_lane():
    return {
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


def validation_doc(status="passed", classification="passed", eligible=True, rerun=False):
    return {
        "status": status,
        "classification": classification,
        "pass_eligible": eligible,
        "rerun_required": rerun,
        "full_validation": status == "passed",
        "full_pytest": {
            "result": "passed" if status == "passed" else "unknown",
            "exit_code": 0 if status == "passed" else None,
        },
        "source": {"kind": "legacy_docker01_validation_log", "log_path": "/tmp/log"},
    }


def test_real_style_legacy_validation_log_is_pass_eligible(tmp_path, monkeypatch):
    patch_validation_roots(monkeypatch, tmp_path)
    log = write_real_style_validation_log(tmp_path, body=full_success_log())

    doc = validation_report()

    assert doc["status"] == "passed"
    assert doc["classification"] == "passed"
    assert doc["pass_eligible"] is True
    assert doc["rerun_required"] is False
    assert doc["full_validation"] is True
    assert doc["full_pytest"] == {"result": "passed", "exit_code": 0}
    assert doc["source"]["log_path"] == str(log)
    assert doc["selection"]["selected_reason"] == "exact_pr_commit_legacy_log_pass_markers"


def test_stale_and_ambiguous_validation_logs_do_not_pass(tmp_path, monkeypatch):
    patch_validation_roots(monkeypatch, tmp_path)
    write_real_style_validation_log(
        tmp_path,
        commit="abcdef1234567890abcdef1234567890abcdef12",
        body=full_success_log(),
    )
    assert validation_report()["status"] == "not_found"

    write_real_style_validation_log(tmp_path, body="ruff passed\ncompileall passed\n")
    doc = validation_report()
    assert doc["status"] == "unknown"
    assert doc["pass_eligible"] is False
    assert doc["rerun_required"] is True


def test_failed_validation_log_is_not_pass_eligible(tmp_path, monkeypatch):
    patch_validation_roots(monkeypatch, tmp_path)
    write_real_style_validation_log(
        tmp_path,
        body=(
            "ruff passed\ncompileall passed\n"
            "PR221 targeted tests passed: 24/24\n"
            "full pytest failed\nexit code 1\n"
        ),
    )
    doc = validation_report()
    assert doc["status"] == "failed"
    assert doc["pass_eligible"] is False


def test_nested_convergence_qa_bundle_is_discovered(tmp_path, monkeypatch):
    monkeypatch.setenv("SFAI_QA_BUNDLE_ROOT", str(tmp_path))
    bundle = write_nested_qa(tmp_path)

    merge_summary, _ = merge.find_qa_bundle(PR, COMMIT)
    v2_summary, _ = v2.find_qa_bundle(PR, COMMIT)

    assert merge_summary["status"] == "passed"
    assert merge_summary["bundle_path"] == str(bundle)
    assert merge_summary["commands_passed"] == 21
    assert v2_summary["status"] == "passed"
    assert v2_summary["safety_assertions_passed"] == 17


def test_stale_nested_qa_bundle_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("SFAI_QA_BUNDLE_ROOT", str(tmp_path))
    write_nested_qa(tmp_path, commit="abcdef1234567890abcdef1234567890abcdef12")
    summary, _ = v2.find_qa_bundle(PR, COMMIT)
    assert summary["status"] == "not_found"


def test_downstream_merge_and_v2_converge_with_nested_qa(tmp_path, monkeypatch):
    monkeypatch.setenv("SFAI_QA_BUNDLE_ROOT", str(tmp_path))
    write_nested_qa(tmp_path)
    monkeypatch.setattr(merge, "load_pr_lane_status", lambda pr, commit: good_lane())
    monkeypatch.setattr(merge, "load_validation_status", lambda pr, commit: validation_doc())
    merge_report = merge.build_report(PR, COMMIT, created_at="2026-06-19T00:00:00Z")[0]
    assert merge_report["status"] == "pass_candidate"
    assert merge_report["evidence"]["qa_bundle"]["status"] == "passed"

    monkeypatch.setattr(v2, "load_pr_lane_status", lambda pr, commit: good_lane())
    monkeypatch.setattr(v2, "load_validation_status", lambda pr, commit: validation_doc())
    monkeypatch.setattr(v2, "load_merge_readiness", lambda pr, commit: merge_report)
    v2_report = v2.build_report(PR, COMMIT, created_at="2026-06-19T00:00:00Z")[0]
    assert v2_report["status"] == "v2_candidate"
    assert v2_report["summary"]["qa_bundle_passed"] is True
    assert v2_report["summary"]["validation_pass_eligible"] is True


def test_v2_missing_or_failed_evidence_remains_conservative(tmp_path, monkeypatch):
    monkeypatch.setenv("SFAI_QA_BUNDLE_ROOT", str(tmp_path))
    monkeypatch.setattr(v2, "load_pr_lane_status", lambda pr, commit: good_lane())
    monkeypatch.setattr(v2, "load_merge_readiness", lambda pr, commit: {"status": "hold_candidate"})

    monkeypatch.setattr(
        v2,
        "load_validation_status",
        lambda pr, commit: {
            "status": "not_found",
            "classification": "not_found",
            "pass_eligible": False,
            "rerun_required": True,
        },
    )
    missing = v2.build_report(PR, COMMIT, created_at="2026-06-19T00:00:00Z")[0]
    assert missing["status"] == "v2_unknown"

    write_nested_qa(tmp_path, status="failed")
    monkeypatch.setattr(
        v2,
        "load_validation_status",
        lambda pr, commit: validation_doc(
            status="failed", classification="test_failure", eligible=False, rerun=True
        ),
    )
    failed = v2.build_report(PR, COMMIT, created_at="2026-06-19T00:00:00Z")[0]
    assert failed["status"] == "v2_not_ready"


def test_pr_lane_status_consumes_validation_and_nested_qa(tmp_path, monkeypatch):
    monkeypatch.setenv("SFAI_QA_BUNDLE_ROOT", str(tmp_path))
    write_nested_qa(tmp_path)
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
    monkeypatch.setattr(lane, "_validation_latest", lambda pr, commit: validation_doc())

    doc = lane.build_pr_lane_status(pr=PR, commit=COMMIT)

    assert doc["status"] == "already_complete"
    assert doc["validation"]["pass_eligible"] is True
    assert doc["qa_bundle"]["status"] == "passed"


def test_sources_keep_read_only_safety_guards(monkeypatch, tmp_path):
    for path in (
        SCRIPTS / "validation_status.py",
        SCRIPTS / "docker01_v2_readiness.py",
        SCRIPTS / "docker01_merge_readiness.py",
    ):
        text = path.read_text(encoding="utf-8")
        assert "shell=True)" not in text
        assert "shell=True," not in text
    monkeypatch.setenv("SFAI_QA_BUNDLE_ROOT", str(tmp_path))
    monkeypatch.setattr(v2, "load_pr_lane_status", lambda pr, commit: good_lane())
    monkeypatch.setattr(v2, "load_validation_status", lambda pr, commit: validation_doc())
    monkeypatch.setattr(v2, "load_merge_readiness", lambda pr, commit: {"status": "pass_candidate"})
    write_nested_qa(tmp_path)
    report, _ = v2.build_report(
        PR,
        COMMIT,
        created_at="2026-06-19T00:00:00Z",
    )
    assert all(value is False for key, value in report["safety"].items() if key != "read_only")
