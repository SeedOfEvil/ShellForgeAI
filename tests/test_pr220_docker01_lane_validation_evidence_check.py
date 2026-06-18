import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lane = load("scripts/sfai_docker01_pr_lane.py", "lane_pr220")
finalizer = load("scripts/docker01_validation_evidence.py", "finalizer_pr220")
viewer = load("scripts/validation_status.py", "viewer_pr220")
merge = load("scripts/docker01_merge_readiness.py", "merge_pr220")

PR = 220
COMMIT = "abcdef1234567890abcdef1234567890abcdef12"


def finalize(root, name, *, status="passed", full=True, warnings=None):
    run_dir = root / name
    log = root / f"{name}.log"
    text = {
        "passed": "ruff passed\ncompileall passed\ntargeted tests passed\nfull pytest passed\n",
        "failed": "pytest failed\n",
        "setup_failure": "missing pytest\n",
        "interrupted": "interrupted by SIGINT\n",
        "unknown": "unclassified output\n",
    }.get(status, "")
    log.write_text(text, encoding="utf-8")
    return finalizer.finalize_validation_evidence(
        pr=PR,
        commit=COMMIT,
        log_path=log,
        run_dir=run_dir,
        status=status,
        lane="full" if full else "targeted",
        commands=[
            {"key": "ruff", "argv": ["ruff", "check", "."], "status": "passed", "exit_code": 0}
        ]
        if status == "passed"
        else [],
        full_validation=full,
        duplicate_full_pytest_detected=False,
        warnings=warnings or [],
    )


def test_successful_validation_writes_json_md_and_manifest_summary(tmp_path, monkeypatch):
    finalize(tmp_path, "sfai-pr220-abcdef123456-validation-20260618T000000", status="passed")
    monkeypatch.setenv(viewer.RUNS_DIR_ENV, str(tmp_path))
    check_dir = tmp_path / "lane-run"
    doc = lane.write_validation_evidence_check_artifacts(
        pr=PR, commit=COMMIT, run_dir=check_dir, expected_pass_eligible=True
    )
    assert doc["status"] == "passed"
    assert (check_dir / "validation-evidence-check.json").is_file()
    assert (check_dir / "validation-evidence-check.md").is_file()
    loaded = json.loads((check_dir / "validation-evidence-check.json").read_text())
    assert loaded["mode"] == "docker01_pr_lane_validation_evidence_check"
    assert loaded["read_only"] is True
    assert loaded["mutation_performed"] is False
    assert loaded["validation_status"]["status"] == "passed"
    assert loaded["validation_status"]["pass_eligible"] is True
    assert loaded["validation_status"]["rerun_required"] is False
    assert loaded["validation_status"]["full_validation"] is True
    assert loaded["validation_status"]["duplicate_full_pytest_detected"] is False
    md = (check_dir / "validation-evidence-check.md").read_text()
    assert "# Docker01 Validation Evidence Check" in md
    assert "No validation/pytest/QA was executed" in md
    manifest = {
        "validation_evidence_check": {
            "status": doc["status"],
            "json_path": str(check_dir / "validation-evidence-check.json"),
            **doc["validation_status"],
        },
        "pr": {"number": PR, "head_commit": COMMIT},
        "lane": {"selected": "full", "reason": "test"},
        "deployment": {},
        "final_container": {},
        "validation": {},
        "safety": lane._default_safety(),
        "logs": {},
        "artifacts": {},
    }
    summary = lane.render_human_summary(manifest)
    assert "Validation evidence self-check:" in summary
    assert "* status: passed" in summary


def test_setup_failure_then_fallback_pass_selects_pass_and_warns(tmp_path, monkeypatch):
    finalize(tmp_path, "sfai-pr220-abcdef123456-validation-20260618T000000", status="setup_failure")
    finalize(
        tmp_path,
        "sfai-pr220-abcdef123456-validation-20260618T010000",
        status="passed",
        warnings=["earlier setup_failure preserved from host attempt"],
    )
    monkeypatch.setenv(viewer.RUNS_DIR_ENV, str(tmp_path))
    doc = lane.build_validation_evidence_check(
        pr=PR, commit=COMMIT, run_dir=tmp_path / "lane", expected_pass_eligible=True
    )
    assert doc["status"] == "passed"
    assert doc["validation_status"]["status"] == "passed"
    assert doc["validation_status"]["pass_eligible"] is True
    assert any("setup_failure" in w for w in doc["warnings"])


def test_non_pass_scenarios_confirm_non_pass_without_false_pass(tmp_path, monkeypatch):
    for status in ("setup_failure", "failed", "interrupted", "unknown"):
        root = tmp_path / status
        root.mkdir()
        finalize(root, "sfai-pr220-abcdef123456-validation-20260618T000000", status=status)
        monkeypatch.setenv(viewer.RUNS_DIR_ENV, str(root))
        doc = lane.build_validation_evidence_check(
            pr=PR, commit=COMMIT, run_dir=root / "lane", expected_pass_eligible=False
        )
        assert doc["status"] == "passed"
        assert doc["validation_status"]["pass_eligible"] is False
        assert doc["validation_status"]["rerun_required"] is True


def test_evidence_not_found_is_failed_needs_followup(tmp_path, monkeypatch):
    monkeypatch.setenv(viewer.RUNS_DIR_ENV, str(tmp_path))
    doc = lane.build_validation_evidence_check(
        pr=PR, commit=COMMIT, run_dir=tmp_path / "lane", expected_pass_eligible=True
    )
    assert doc["status"] == "failed"
    assert doc["validation_status"]["status"] == "not_found"
    assert doc["validation_status"]["pass_eligible"] is False
    assert doc["validation_status"]["rerun_required"] is True


def test_read_only_safety_flags_and_no_shell_true():
    safety = lane.validation_evidence_check_safety()
    forbidden_true = [
        "validation_executed",
        "pytest_executed",
        "qa_executed",
        "cleanup_executed",
        "docker_prune_executed",
        "docker_image_removed",
        "file_deleted",
        "docker_compose_executed",
        "container_restarted",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
        "natural_language_execution",
        "shell_true",
        "cloud_apply_merge_push",
    ]
    assert safety["read_only"] is True
    assert all(safety[k] is False for k in forbidden_true)
    assert "shell=True" not in (ROOT / "scripts" / "sfai_docker01_pr_lane.py").read_text()


def test_evidence_check_only_mode_writes_no_deploy_artifacts(tmp_path, monkeypatch, capsys):
    finalize(tmp_path, "sfai-pr220-abcdef123456-validation-20260618T000000", status="passed")
    monkeypatch.setenv(viewer.RUNS_DIR_ENV, str(tmp_path))
    out_dir = tmp_path / "check-only"
    rc = lane.main(
        [
            "--pr",
            str(PR),
            "--commit",
            COMMIT,
            "--evidence-check-only",
            "--json",
            "--run-dir",
            str(out_dir),
        ]
    )
    captured = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert captured["status"] == "passed"
    assert (out_dir / "validation-evidence-check.json").is_file()
    assert not (out_dir / "docker01-lane-manifest.json").exists()
    assert not (out_dir / "commands-run.json").exists()


def test_downstream_validation_status_pr_lane_and_merge_readiness_agree(tmp_path, monkeypatch):
    finalize(tmp_path, "sfai-pr220-abcdef123456-validation-20260618T000000", status="passed")
    monkeypatch.setenv(viewer.RUNS_DIR_ENV, str(tmp_path))
    report = viewer.generate_report(
        type(
            "Args",
            (),
            {
                "latest": True,
                "pr": PR,
                "commit": COMMIT,
                "include_legacy": False,
                "run_root": None,
                "explain_selection": True,
                "run_dir": None,
                "heartbeat": None,
                "status_file": None,
                "manifest": None,
                "summary": None,
                "log": None,
            },
        )()
    )
    assert report["status"] == "passed"
    assert report["pass_eligible"] is True
    pr_status = lane.build_pr_lane_status(
        pr=PR,
        commit=COMMIT,
        runner=lambda *a, **k: type("C", (), {"returncode": 1, "stdout": "", "stderr": ""})(),
    )
    assert pr_status["validation"]["pass_eligible"] is True
    qa = tmp_path / "sfai-pr220-abcdef123456-qa-bundle-20260618T000000"
    qa.mkdir()
    (qa / "qa-results.json").write_text(
        json.dumps(
            {
                "status": "passed",
                "pr": PR,
                "commit": COMMIT,
                "summary": {
                    "commands_passed": 3,
                    "commands_failed": 0,
                    "safety_assertions_failed": 0,
                    "safety_assertions_passed": 5,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv(merge.QA_BUNDLE_ROOT_ENV, str(tmp_path))
    hold, _ = merge.build_report(PR, COMMIT)
    assert hold["status"] in {"hold_candidate", "unknown"}
