import argparse
import importlib.util
import json
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


lane = load_script("lane_pr221", "sfai_docker01_pr_lane.py")
validation_status = load_script("validation_status_pr221", "validation_status.py")
v2 = load_script("v2_pr221", "docker01_v2_readiness.py")

PR = 221
COMMIT = "1417017dec03342e4af2009c35f93d2e18fd8f07"
CREATED = "2026-06-19T01:02:03Z"


def manifest(status="passed", classification="passed", full=False):
    return {
        "status": status,
        "classification": classification,
        "pr": {"number": PR, "head_commit": COMMIT},
        "lane": {"full_validation_required": full, "full_validation_reason": ""},
        "non_blockers": [],
        "artifacts": {},
    }


def command_records(status="passed"):
    return [
        {
            "name": "lint",
            "command": ["ruff", "check", "."],
            "status": status,
            "duration_seconds": 1.0,
            "log_path": None,
        },
        {
            "name": "compile",
            "command": ["python", "-m", "compileall", "-q", "scripts", "tests"],
            "status": status,
            "duration_seconds": 1.0,
            "log_path": None,
        },
        {
            "name": "pytest_targeted",
            "command": ["pytest", "-q", "tests/test_pr221_docker01_v2_readiness.py"],
            "status": status,
            "duration_seconds": 1.0,
            "log_path": None,
        },
    ]


def status_report(tmp_path, pr=PR, commit=COMMIT):
    args = argparse.Namespace(
        latest=True,
        pr=pr,
        commit=commit,
        include_legacy=False,
        run_root=None,
        explain_selection=True,
        run_dir=None,
        heartbeat=None,
        status_file=None,
        manifest=None,
        summary=None,
        log=None,
    )
    return validation_status.generate_report(args)


def test_targeted_success_auto_finalizes_discoverable_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv(validation_status.RUNS_DIR_ENV, str(tmp_path))
    run_dir = lane._default_validation_run_dir(
        pr_number=str(PR), short_commit=COMMIT[:12], created_at=CREATED
    )
    doc = manifest()
    evidence_manifest = lane.write_lane_validation_evidence(
        run_dir=run_dir,
        manifest=doc,
        command_records=command_records(),
        log_path=None,
        created_at=CREATED,
    )
    check = lane.write_validation_evidence_check_artifacts(
        pr=PR, commit=COMMIT, run_dir=run_dir, expected_pass_eligible=True, created_at=CREATED
    )

    assert (run_dir / "validation-status.json").is_file()
    assert (run_dir / "validation-manifest.json").is_file()
    assert (run_dir / "validation-summary.md").is_file()
    assert (run_dir / "commands-run.json").is_file()
    assert (run_dir / "validation-evidence-check.json").is_file()
    assert (run_dir / "validation-evidence-check.md").is_file()
    status_doc = json.loads((run_dir / "validation-status.json").read_text())
    assert status_doc["status"] == "passed"
    assert status_doc["classification"] == "passed"
    assert status_doc["pass_eligible"] is True
    assert status_doc["rerun_required"] is False
    assert status_doc["lane"] == "targeted"
    assert status_doc["full_validation"] is False
    assert status_doc["duplicate_full_pytest_detected"] is False
    assert status_doc["pr"] == PR
    assert status_doc["commit"] == COMMIT
    assert evidence_manifest["run_dir"] == str(run_dir)
    assert doc["validation_evidence"]["run_dir"] == str(run_dir)
    assert check["status"] == "passed"

    report = status_report(tmp_path)
    assert report["status"] == "passed"
    assert report["classification"] == "passed"
    assert report["pass_eligible"] is True
    assert report["rerun_required"] is False
    assert report["lane"] == "targeted"
    assert report["full_validation"] is False
    assert lane._validation_latest(PR, COMMIT)["pass_eligible"] is True


def test_targeted_failure_setup_and_interrupted_evidence_are_not_pass_eligible(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(validation_status.RUNS_DIR_ENV, str(tmp_path))
    cases = [
        ("failed", "failed", "failed"),
        ("failed", "setup_failure", "setup_failure"),
        ("incomplete", "interrupted_or_incomplete", "interrupted"),
    ]
    for idx, (status, classification, expected_status) in enumerate(cases):
        run_dir = tmp_path / f"sfai-pr{PR}-{COMMIT[:12]}-validation-{idx}"
        doc = manifest(status=status, classification=classification)
        lane.write_lane_validation_evidence(
            run_dir=run_dir,
            manifest=doc,
            command_records=command_records("failed"),
            log_path=None,
            created_at=CREATED,
        )
        status_doc = json.loads((run_dir / "validation-status.json").read_text())
        assert status_doc["status"] == expected_status
        assert status_doc["pass_eligible"] is False
        assert status_doc["rerun_required"] is True


def test_discovery_ignores_stale_and_empty_run_dirs(tmp_path, monkeypatch):
    monkeypatch.setenv(validation_status.RUNS_DIR_ENV, str(tmp_path))
    stale = tmp_path / f"sfai-pr{PR}-000000000000-validation-stale"
    lane.write_lane_validation_evidence(
        run_dir=stale,
        manifest={
            **manifest(),
            "pr": {"number": PR, "head_commit": "0000000000000000000000000000000000000000"},
        },
        command_records=command_records(),
        log_path=None,
        created_at=CREATED,
    )
    empty = tmp_path / f"sfai-pr{PR}-{COMMIT[:12]}-validation-empty"
    empty.mkdir()
    report = status_report(tmp_path)
    assert report["status"] == "not_found"


def test_validation_success_missing_evidence_self_check_fails_clearly(tmp_path, monkeypatch):
    monkeypatch.setenv(validation_status.RUNS_DIR_ENV, str(tmp_path))
    check = lane.write_validation_evidence_check_artifacts(
        pr=PR, commit=COMMIT, run_dir=tmp_path / "empty-check", expected_pass_eligible=True
    )
    assert check["status"] == "failed"
    assert check["validation_status"]["status"] == "not_found"
    assert (tmp_path / "empty-check" / "validation-evidence-check.json").is_file()


def test_downstream_v2_candidate_when_validation_qa_merge_and_state_are_clean(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(validation_status.RUNS_DIR_ENV, str(tmp_path))
    run_dir = tmp_path / f"sfai-pr{PR}-{COMMIT[:12]}-validation-good"
    lane.write_lane_validation_evidence(
        run_dir=run_dir,
        manifest=manifest(),
        command_records=command_records(),
        log_path=None,
        created_at=CREATED,
    )
    vstatus = status_report(tmp_path)

    monkeypatch.setenv(v2.QA_BUNDLE_ROOT_ENV, str(tmp_path))
    qa_dir = tmp_path / f"sfai-pr{PR}-{COMMIT[:12]}-operator-qa-bundle-20260619T010203Z"
    qa_dir.mkdir()
    (qa_dir / "qa-results.json").write_text(
        json.dumps(
            {
                "status": "passed",
                "pr": PR,
                "commit": COMMIT,
                "summary": {
                    "commands_passed": 21,
                    "commands_failed": 0,
                    "safety_assertions_passed": 17,
                    "safety_assertions_failed": 0,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        v2,
        "load_pr_lane_status",
        lambda pr, commit: {
            "status": "already_complete",
            "state": {
                "container_status": "running",
                "container_health": "healthy",
                "restart_count": 0,
            },
            "checks": [
                {"name": "source_head_matches", "passed": True},
                {"name": "compose_image_matches", "passed": True},
                {"name": "container_labels_match", "passed": True},
                {"name": "container_image_matches", "passed": True},
                {"name": "container_running", "passed": True},
                {"name": "container_healthy", "passed": True},
                {"name": "restart_count_acceptable", "passed": True},
            ],
        },
    )
    monkeypatch.setattr(v2, "load_validation_status", lambda pr, commit: vstatus)
    monkeypatch.setattr(v2, "load_merge_readiness", lambda pr, commit: {"status": "pass_candidate"})
    report, _raw = v2.build_report(PR, COMMIT, created_at=CREATED)
    assert report["status"] == "v2_candidate"
