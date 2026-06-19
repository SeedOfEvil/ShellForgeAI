import argparse
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, filename: str):
    helper_dir = str(ROOT / "scripts")
    if helper_dir not in sys.path:
        sys.path.insert(0, helper_dir)
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


validation_status = load_script("validation_status_legacy_pr221", "validation_status.py")
lane = load_script("lane_legacy_pr221", "sfai_docker01_pr_lane.py")
v2 = load_script("v2_legacy_pr221", "docker01_v2_readiness.py")

PR = 221
COMMIT = "0fabcc5d2a63c85c17440eb91b43fcf7415549f2"


def patch_roots(monkeypatch, tmp_path):
    for module in (validation_status, lane.validation_status_viewer):
        monkeypatch.setattr(module, "TMP_ROOT", tmp_path)
        monkeypatch.setattr(module, "MAINLINE_TMP_ROOT", tmp_path / "validation-runs")
        monkeypatch.setattr(module, "PERSISTED_ROOT", tmp_path / "persisted")
        monkeypatch.setattr(module, "LEGACY_ROOT", tmp_path / "legacy")


def write_log(tmp_path, *, commit=COMMIT, body=""):
    path = tmp_path / f"sfai-pr{PR}-{commit[:7]}-validation-20260619T040814Z.log"
    path.write_text(body, encoding="utf-8")
    return path


def report():
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


def full_success_log():
    return "\n".join(
        [
            "Docker01 validation lane for PR 221 commit 0fabcc5d2a63c85c17440eb91b43fcf7415549f2",
            "ruff passed",
            "compileall passed",
            "PR221 targeted tests passed: 19/19",
            "scripts/run_full_pytest.py completed successfully",
            "full pytest passed: 100%, exit code 0",
            "lane summary: validation passed",
        ]
    )


def test_exact_legacy_full_validation_log_becomes_pass_eligible(tmp_path, monkeypatch):
    patch_roots(monkeypatch, tmp_path)
    log = write_log(tmp_path, body=full_success_log())

    doc = report()

    assert doc["status"] == "passed"
    assert doc["classification"] == "passed"
    assert doc["pass_eligible"] is True
    assert doc["rerun_required"] is False
    assert doc["full_validation"] is True
    assert doc["full_pytest"] == {"result": "passed", "exit_code": 0}
    assert doc["duplicate_full_pytest_detected"] is False
    assert doc["source"]["kind"] == "legacy_docker01_validation_log"
    assert doc["source"]["log_path"] == str(log)
    assert doc["selection"]["selected_reason"] == "exact_pr_commit_legacy_log_pass_markers"
    assert doc["selection"]["legacy_log_classified"] is True
    assert doc["selection"]["exact_pr_commit_matched"] is True
    assert any("trusted pass markers" in warning for warning in doc["warnings"])


def test_exact_pr_commit_matching_required_for_legacy_logs(tmp_path, monkeypatch):
    patch_roots(monkeypatch, tmp_path)
    write_log(tmp_path, commit="abcdef0123456789abcdef0123456789abcdef01", body=full_success_log())

    doc = report()

    assert doc["status"] == "not_found"
    assert doc["pass_eligible"] is False


def test_pr_lane_status_consumes_classified_legacy_log(tmp_path, monkeypatch):
    patch_roots(monkeypatch, tmp_path)
    write_log(tmp_path, body=full_success_log())

    doc = lane._validation_latest(PR, COMMIT)

    assert doc["status"] == "passed"
    assert doc["pass_eligible"] is True
    assert doc["full_validation"] is True
    assert doc["full_pytest"]["result"] == "passed"


def test_legacy_log_negative_cases_are_not_pass_eligible(tmp_path, monkeypatch):
    cases = [
        ("pytest", "ruff passed\ncompileall passed\nfull pytest failed\nexit code 1\n", "failed"),
        (
            "ruff",
            "ruff failed\ncompileall passed\nfull pytest passed 100%, exit code 0\n",
            "failed",
        ),
        (
            "compile",
            "ruff passed\ncompileall failed\nfull pytest passed 100%, exit code 0\n",
            "failed",
        ),
        (
            "truncated",
            "ruff passed\ncompileall passed\nfull pytest 100%\ntruncated\n",
            "incomplete",
        ),
        (
            "setup",
            "ruff passed\ncompileall passed\nfull pytest passed 100%, exit code 0\nsetup_failure\n",
            "failed",
        ),
        ("ambiguous", "ruff passed\ncompileall passed\n", "unknown"),
    ]
    for name, body, expected_status in cases:
        case_root = tmp_path / name
        case_root.mkdir()
        patch_roots(monkeypatch, case_root)
        write_log(case_root, body=body)

        doc = report()

        assert doc["status"] == expected_status
        assert doc["pass_eligible"] is False
        assert doc["rerun_required"] is True


def test_v2_readiness_preserves_legacy_validation_outcomes(monkeypatch):
    base_validation = {
        "status": "passed",
        "classification": "passed",
        "pass_eligible": True,
        "rerun_required": False,
        "full_validation": True,
        "full_pytest": {"result": "passed", "exit_code": 0},
    }
    lane_status = {
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
    monkeypatch.setattr(v2, "load_pr_lane_status", lambda pr, commit: lane_status)
    monkeypatch.setattr(v2, "load_merge_readiness", lambda pr, commit: {"status": "pass_candidate"})
    monkeypatch.setattr(
        v2,
        "find_qa_bundle",
        lambda pr, commit: (
            {"status": "passed", "safety_assertions_failed": 0, "commands_failed": 0},
            {},
        ),
    )
    monkeypatch.setattr(v2, "load_validation_status", lambda pr, commit: dict(base_validation))
    candidate, _ = v2.build_report(PR, COMMIT)
    assert candidate["status"] == "v2_candidate"
    assert candidate["evidence"]["validation"]["full_validation"] is True

    monkeypatch.setattr(
        v2,
        "load_validation_status",
        lambda pr, commit: {
            **base_validation,
            "status": "unknown",
            "classification": "unknown",
            "pass_eligible": False,
            "rerun_required": True,
        },
    )
    unknown, _ = v2.build_report(PR, COMMIT)
    assert unknown["status"] == "v2_unknown"

    monkeypatch.setattr(
        v2,
        "load_validation_status",
        lambda pr, commit: {
            **base_validation,
            "status": "failed",
            "classification": "failed",
            "pass_eligible": False,
            "rerun_required": True,
        },
    )
    failed, _ = v2.build_report(PR, COMMIT)
    assert failed["status"] == "v2_not_ready"
