"""PR176 — validation-lane heartbeat and interrupted-run evidence polish.

These tests cover the validation heartbeat/checkpoint helper, the deterministic
run classifier (passed / failed / incomplete / setup_failure), the Docker01 PR
lane helper's interrupted-run evidence, and the full pytest runner's heartbeat.

They are process/tooling tests only. They never run Docker/Compose, never run a
real long pytest, never mutate services/containers or real ``/data``, and never
require the Docker daemon. Fake subprocess runners and ``tmp_path`` are used.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
HEARTBEAT_PATH = SCRIPTS / "validation_heartbeat.py"
LANE_PATH = SCRIPTS / "sfai_docker01_pr_lane.py"
RUNNER_PATH = SCRIPTS / "run_full_pytest.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


vh = _load("pr176_validation_heartbeat", HEARTBEAT_PATH)
lane = _load("pr176_sfai_docker01_pr_lane", LANE_PATH)
runner = _load("pr176_run_full_pytest", RUNNER_PATH)


def _all_passed_status() -> dict:
    return {
        "ruff": vh.PHASE_PASSED,
        "compileall": vh.PHASE_PASSED,
        "targeted_tests": vh.PHASE_PASSED,
        "full_pytest": vh.PHASE_PASSED,
    }


def _ok(_argv, **_kwargs):
    return types.SimpleNamespace(returncode=0, stdout="All checks passed", stderr="")


# --------------------------------------------------------------------------- #
# 1-5. Heartbeat / checkpoint files
# --------------------------------------------------------------------------- #
def test_01_heartbeat_file_written_at_run_start(tmp_path):
    hb = vh.ValidationHeartbeat(tmp_path / "hb.json", pr=176, commit="abc123")
    hb.start()
    assert (tmp_path / "hb.json").is_file()
    data = json.loads((tmp_path / "hb.json").read_text(encoding="utf-8"))
    assert data["mode"] == "validation_heartbeat"
    assert data["schema_version"] == 1
    assert data["status"] == "running"
    assert data["pr"] == 176


def test_02_heartbeat_records_active_phase(tmp_path):
    hb = vh.ValidationHeartbeat(tmp_path / "hb.json")
    hb.start()
    hb.start_phase("full_pytest")
    data = json.loads((tmp_path / "hb.json").read_text(encoding="utf-8"))
    assert data["active_phase"] == "full_pytest"
    assert data["phase_status"]["full_pytest"] == "running"


def test_03_heartbeat_records_last_completed_phase(tmp_path):
    hb = vh.ValidationHeartbeat(tmp_path / "hb.json")
    hb.start()
    hb.start_phase("ruff")
    hb.complete_phase("ruff")
    hb.start_phase("compileall")
    hb.complete_phase("compileall")
    data = json.loads((tmp_path / "hb.json").read_text(encoding="utf-8"))
    assert data["last_completed_phase"] == "compileall"


def test_04_phase_status_transitions_running_to_passed(tmp_path):
    hb = vh.ValidationHeartbeat(tmp_path / "hb.json")
    hb.start_phase("targeted_tests")
    running = json.loads((tmp_path / "hb.json").read_text(encoding="utf-8"))
    assert running["phase_status"]["targeted_tests"] == "running"
    hb.complete_phase("targeted_tests")
    passed = json.loads((tmp_path / "hb.json").read_text(encoding="utf-8"))
    assert passed["phase_status"]["targeted_tests"] == "passed"


def test_05_heartbeat_status_checkpoint_json_is_strict(tmp_path):
    hb = vh.ValidationHeartbeat(
        tmp_path / "hb.json",
        checkpoint_path=tmp_path / "cp.json",
        status_path=tmp_path / "st.json",
    )
    hb.start()
    hb.start_phase("ruff")
    hb.complete_phase("ruff")
    # Strict parse of every emitted artifact (raises on malformed JSON).
    json.loads((tmp_path / "hb.json").read_text(encoding="utf-8"))
    json.loads((tmp_path / "st.json").read_text(encoding="utf-8"))
    checkpoints = json.loads((tmp_path / "cp.json").read_text(encoding="utf-8"))
    assert checkpoints["mode"] == "validation_checkpoints"
    assert isinstance(checkpoints["checkpoints"], list)
    assert checkpoints["checkpoints"][0]["event"] == "start"


# --------------------------------------------------------------------------- #
# 6-8. Successful classification
# --------------------------------------------------------------------------- #
def test_06_all_phases_passed_status_passed():
    result = vh.classify_run(_all_passed_status(), full_pytest_exit_code=0)
    assert result["status"] == "passed"
    assert result["classification"] == "passed"


def test_07_all_phases_passed_pass_eligible_true():
    result = vh.classify_run(_all_passed_status(), full_pytest_exit_code=0)
    assert result["pass_eligible"] is True


def test_08_all_phases_passed_rerun_required_false():
    result = vh.classify_run(_all_passed_status(), full_pytest_exit_code=0)
    assert result["rerun_required"] is False
    assert result["full_pytest_result"] == "passed"


# --------------------------------------------------------------------------- #
# 9-15. Incomplete / interrupted classification
# --------------------------------------------------------------------------- #
def _incomplete_result() -> dict:
    phase_status = {
        "ruff": vh.PHASE_PASSED,
        "compileall": vh.PHASE_PASSED,
        "targeted_tests": vh.PHASE_PASSED,
        "full_pytest": vh.PHASE_RUNNING,
    }
    return vh.classify_run(
        phase_status,
        full_pytest_exit_code=None,
        active_phase="full_pytest",
        last_completed_phase="targeted_tests",
    )


def test_09_missing_full_pytest_completion_status_incomplete():
    assert _incomplete_result()["status"] == "incomplete"


def test_10_missing_full_pytest_completion_classification_interrupted():
    assert _incomplete_result()["classification"] == "interrupted_or_incomplete"


def test_11_missing_full_pytest_completion_pass_eligible_false():
    assert _incomplete_result()["pass_eligible"] is False


def test_12_missing_full_pytest_completion_rerun_required_true():
    assert _incomplete_result()["rerun_required"] is True


def test_13_active_phase_at_last_heartbeat_preserved(tmp_path):
    hb = vh.ValidationHeartbeat(tmp_path / "hb.json")
    hb.start()
    for phase in ("ruff", "compileall", "targeted_tests"):
        hb.start_phase(phase)
        hb.complete_phase(phase)
    hb.start_phase("full_pytest")
    snapshot = hb.mark_interrupted(signal_name="SIGTERM")
    assert snapshot["active_phase_at_last_heartbeat"] == "full_pytest"
    assert snapshot["last_completed_phase"] == "targeted_tests"
    data = json.loads((tmp_path / "hb.json").read_text(encoding="utf-8"))
    assert data["active_phase"] == "full_pytest"
    assert data["phase_status"]["full_pytest"] == "interrupted"


def test_14_human_summary_says_rerun_required(tmp_path):
    plan = lane.plan_docker01_lane(
        changed_files=["Dockerfile"],
        pr_number="176",
        full_validation=True,
        full_validation_reason="validation helper changed",
    )
    manifest = lane.build_validation_manifest(
        plan,
        pr_number="176",
        head_commit="abcdef1234567890",
        status="incomplete",
        last_completed_phase="targeted_tests",
        active_phase_at_last_heartbeat="full_pytest",
        manifest_path=str(tmp_path / "m.json"),
        human_summary_path=str(tmp_path / "s.txt"),
    )
    summary = lane.render_human_summary(manifest)
    assert "Validation result: INCOMPLETE" in summary
    assert "RERUN REQUIRED" in summary
    assert "Rerun required: yes" in summary
    assert "Pass eligible: no" in summary
    assert "active phase: full_pytest" in summary


def test_15_incomplete_run_does_not_report_full_pytest_passed():
    result = _incomplete_result()
    assert result["full_pytest_result"] == "unknown"
    assert result["full_pytest_result"] != "passed"


# --------------------------------------------------------------------------- #
# 16-19. Failure classification
# --------------------------------------------------------------------------- #
def _full_pytest_failed_result() -> dict:
    phase_status = {
        "ruff": vh.PHASE_PASSED,
        "compileall": vh.PHASE_PASSED,
        "targeted_tests": vh.PHASE_PASSED,
        "full_pytest": vh.PHASE_FAILED,
    }
    return vh.classify_run(phase_status, full_pytest_exit_code=1)


def test_16_full_pytest_exit_nonzero_status_failed():
    result = _full_pytest_failed_result()
    assert result["status"] == "failed"
    assert result["classification"] == "test_failure"


def test_17_failed_phase_recorded():
    assert _full_pytest_failed_result()["failed_phase"] == "full_pytest"


def test_18_failed_run_pass_eligible_false():
    assert _full_pytest_failed_result()["pass_eligible"] is False


def test_19_no_false_pass_when_targeted_pass_but_full_fails():
    result = _full_pytest_failed_result()
    assert result["status"] != "passed"
    assert result["pass_eligible"] is False
    assert result["full_pytest_result"] == "failed"


# --------------------------------------------------------------------------- #
# 20-22. Setup failure
# --------------------------------------------------------------------------- #
def test_20_setup_failure_before_tests_records_setup_failure(tmp_path):
    # Explicit helper setup failure before any test phase ran.
    hb = vh.ValidationHeartbeat(tmp_path / "hb.json")
    hb.start()
    snapshot = hb.mark_setup_failure(reason="validation environment doctor failed", phase="ruff")
    assert snapshot["classification"] == "setup_failure"
    assert snapshot["status"] == "failed"
    # A pre-test (ruff/compileall) phase failure also classifies as setup_failure.
    pre_test = vh.classify_run({"ruff": vh.PHASE_FAILED, "compileall": vh.PHASE_NOT_STARTED})
    assert pre_test["classification"] == "setup_failure"


def test_21_setup_failure_pass_eligible_false(tmp_path):
    hb = vh.ValidationHeartbeat(tmp_path / "hb.json")
    snapshot = hb.mark_setup_failure(reason="missing interpreter")
    assert snapshot["pass_eligible"] is False
    assert snapshot["rerun_required"] is True


def test_22_setup_failure_gives_controlled_summary():
    result = vh.classify_run({}, setup_failure=True, setup_failure_reason="container not ready")
    assert result["classification"] == "setup_failure"
    assert result["reason"] == "container not ready"
    assert result["full_pytest_result"] == "unknown"


# --------------------------------------------------------------------------- #
# 23-25. Runner behavior
# --------------------------------------------------------------------------- #
def test_23_run_full_pytest_preserves_pytest_nonzero_exit(monkeypatch):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=4, stdout="x", stderr="y"),
    )
    assert runner.main(["--json"]) == 4


def test_24_run_full_pytest_writes_final_heartbeat_on_success(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="2 passed", stderr=""),
    )
    hb = tmp_path / "hb.json"
    st = tmp_path / "st.json"
    assert runner.main(["--json", "--heartbeat-file", str(hb), "--status-file", str(st)]) == 0
    data = json.loads(hb.read_text(encoding="utf-8"))
    assert data["status"] == "passed"
    assert data["pass_eligible"] is True
    assert data["full_pytest_result"] == "passed"
    assert data["finalized"] is True
    assert st.is_file()


def test_25_run_full_pytest_writes_final_heartbeat_on_controlled_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=2, stdout="1 failed", stderr=""),
    )
    hb = tmp_path / "hb.json"
    assert runner.main(["--json", "--heartbeat-file", str(hb)]) == 2
    data = json.loads(hb.read_text(encoding="utf-8"))
    assert data["status"] == "failed"
    assert data["classification"] == "test_failure"
    assert data["full_pytest_result"] == "failed"
    assert data["pass_eligible"] is False


# --------------------------------------------------------------------------- #
# 26-30. Safety / process
# --------------------------------------------------------------------------- #
def test_26_helper_does_not_auto_rerun_full_pytest():
    plan = lane.plan_docker01_lane(
        changed_files=["Dockerfile"],
        full_validation=True,
        full_validation_reason="validation helper changed",
    )
    # Inject a duplicate full runner command; the helper must still run it once.
    full = next(c for c in plan["_commands"] if c["kind"] == "pytest_full_runner")
    plan["_commands"].append(dict(full))
    calls: list[list[str]] = []

    def counting_runner(argv, **_kwargs):
        calls.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    rc = lane.run_validation(plan, runner=counting_runner)
    assert rc == 0
    full_runs = [c for c in calls if "run_full_pytest.py" in " ".join(c)]
    assert len(full_runs) == 1, "full pytest must not be auto-rerun within one helper run"


# Split tokens so the literals never appear in this test file (keeps test_27's
# self-scan honest and mirrors the existing codebase convention).
_DKR = "dock" + "er"
_CMP = "com" + "pose"
_DATA = " /" + "data"


def test_27_no_docker_or_real_data_in_unit_tests():
    text = Path(__file__).read_text(encoding="utf-8").lower()
    assert "tmp_path" in text  # tests use tmp fixtures, not real paths
    for needle in (f"{_DKR} {_CMP}", f"{_DKR}.from_env", _DATA):
        assert needle not in text


def test_28_no_product_runtime_behavior_change():
    # The PR's scripts are standalone validation tooling: they must not import the
    # shellforgeai product package (so product runtime behavior cannot change),
    # and the heartbeat module must not touch any execution surface.
    pkg = "shellforge" + "ai"
    for path in (HEARTBEAT_PATH, RUNNER_PATH, LANE_PATH):
        text = path.read_text(encoding="utf-8").lower()
        assert f"import {pkg}" not in text
        assert f"from {pkg}" not in text
    heartbeat = HEARTBEAT_PATH.read_text(encoding="utf-8").lower()
    for needle in ("import subprocess", "subprocess.run", "os.system", "shell=true", "codex"):
        assert needle not in heartbeat


def test_29_no_cleanup_remediation_rollback_recovery_execution_introduced():
    docker_forms = (
        f"{_DKR} {_CMP} up",
        f"{_DKR} {_CMP} down",
        f"{_DKR} {_CMP} restart",
        f"{_DKR} restart",
    )
    # The new/lightly-touched evidence helpers document no execution at all.
    for path in (HEARTBEAT_PATH, RUNNER_PATH):
        text = path.read_text(encoding="utf-8").lower()
        for needle in ("cleanup execute", "remediation execute", "rollback execute", *docker_forms):
            assert needle not in text, f"{path.name} introduced forbidden phrase: {needle}"
    # The lane helper documents forbidden actions as a checklist; it must still
    # never contain real mutation command forms or recovery execution.
    lane_text = LANE_PATH.read_text(encoding="utf-8").lower()
    for needle in ("recovery execute", *docker_forms):
        assert needle not in lane_text, f"lane helper introduced forbidden phrase: {needle}"


def test_30_no_shell_true_introduced():
    for path in (HEARTBEAT_PATH, RUNNER_PATH, LANE_PATH):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                        assert keyword.value.value is not True


# --------------------------------------------------------------------------- #
# 31-34. Regression guards
# --------------------------------------------------------------------------- #
def test_31_validation_lane_optimizer_still_plans():
    plan = lane.validate_pr.plan_validation(["docs/cli.md"])
    assert plan["selected_lane"] == "fast"
    full = lane.validate_pr.plan_validation(["Dockerfile"])
    assert full["selected_lane"] == "full"


def test_32_validation_manifest_passed_run_still_reports_pass(tmp_path):
    plan = lane.plan_docker01_lane(
        changed_files=["Dockerfile"],
        full_validation=True,
        full_validation_reason="validation helper changed",
    )
    commands = [
        {"name": "lint", "status": "passed", "display": "ruff check ."},
        {"name": "compile", "status": "passed", "display": "python -m compileall -q src tests"},
        {
            "name": "pytest_full_runner",
            "status": "passed",
            "display": "python scripts/run_full_pytest.py",
        },
    ]
    manifest = lane.build_validation_manifest(
        plan,
        pr_number="176",
        head_commit="abcdef1234567890",
        commands=commands,
        full_pytest_exit_code=0,
        manifest_path=str(tmp_path / "m.json"),
        human_summary_path=str(tmp_path / "s.txt"),
    )
    assert manifest["status"] == "passed"
    assert manifest["verdict"] == "pass"
    assert manifest["pass_eligible"] is True
    assert manifest["rerun_required"] is False
    # The offline finalizer still imports and exposes its finalize entrypoint.
    import finalize_validation_manifest as finalizer

    assert hasattr(finalizer, "finalize_manifest")


def test_33_full_pytest_runner_plan_still_works():
    plan = runner.plan_full_pytest(xdist_available=True)
    assert plan.xdist_enabled is True
    assert "--durations=25" in plan.command


def test_34_lane_safety_block_remains_non_mutating(tmp_path):
    plan = lane.plan_docker01_lane(changed_files=["Dockerfile"])
    manifest = lane.build_validation_manifest(
        plan,
        manifest_path=str(tmp_path / "m.json"),
        human_summary_path=str(tmp_path / "s.txt"),
    )
    safety = manifest["safety"]
    for key in (
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "docker_prune",
        "volume_prune",
        "docker_compose_mutation_beyond_deploy",
        "production_restart_beyond_deploy",
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_mutation",
    ):
        assert safety[key] is False


# --------------------------------------------------------------------------- #
# Lane interruption evidence (integration of the helper main loop)
# --------------------------------------------------------------------------- #
def _run_lane_main(monkeypatch, tmp_path, runner_fn, *, pr="176"):
    monkeypatch.setattr(lane.subprocess, "run", runner_fn)
    changed = ["Dockerfile", "tests/test_pr161_docker01_validation_manifest.py"]
    rc = lane.main(
        [
            "--changed-files",
            *changed,
            "--pr",
            pr,
            "--full-validation",
            "--full-validation-reason",
            "validation helper changed",
            "--execute-validation",
            "--manifest-output",
            str(tmp_path / "m.json"),
            "--summary-output",
            str(tmp_path / "s.txt"),
            "--heartbeat-file",
            str(tmp_path / "hb.json"),
            "--checkpoint-file",
            str(tmp_path / "cp.json"),
            "--status-file",
            str(tmp_path / "st.json"),
        ]
    )
    manifest = json.loads((tmp_path / "m.json").read_text(encoding="utf-8"))
    summary = (tmp_path / "s.txt").read_text(encoding="utf-8")
    return rc, manifest, summary


def test_lane_clean_execution_reports_pass(monkeypatch, tmp_path, capsys):
    rc, manifest, summary = _run_lane_main(monkeypatch, tmp_path, _ok)
    capsys.readouterr()
    assert rc == 0
    assert manifest["status"] == "passed"
    assert manifest["pass_eligible"] is True
    assert manifest["rerun_required"] is False
    assert manifest["full_pytest_result"] == "passed"
    assert manifest["phase_status"]["full_pytest"] == "passed"
    assert "Result: PASS" in summary
    assert (tmp_path / "hb.json").is_file()


def test_lane_interrupted_execution_reports_incomplete(monkeypatch, tmp_path, capsys):
    def interrupt(argv, **_kwargs):
        if "run_full_pytest.py" in " ".join(argv):
            raise KeyboardInterrupt
        return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")

    rc, manifest, summary = _run_lane_main(monkeypatch, tmp_path, interrupt)
    capsys.readouterr()
    assert rc == 130
    assert manifest["status"] == "incomplete"
    assert manifest["classification"] == "interrupted_or_incomplete"
    assert manifest["pass_eligible"] is False
    assert manifest["rerun_required"] is True
    assert manifest["full_pytest_result"] == "unknown"
    assert manifest["active_phase_at_last_heartbeat"] == "full_pytest"
    assert manifest["last_completed_phase"] == "targeted_tests"
    assert "RERUN REQUIRED" in summary
    heartbeat = json.loads((tmp_path / "hb.json").read_text(encoding="utf-8"))
    assert heartbeat["phase_status"]["full_pytest"] == "interrupted"
    assert heartbeat["status"] == "incomplete"


def test_lane_full_pytest_failure_reports_failed(monkeypatch, tmp_path, capsys):
    def fail_full(argv, **_kwargs):
        if "run_full_pytest.py" in " ".join(argv):
            return types.SimpleNamespace(returncode=1, stdout="1 failed", stderr="")
        return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")

    rc, manifest, summary = _run_lane_main(monkeypatch, tmp_path, fail_full)
    capsys.readouterr()
    assert rc == 1
    assert manifest["status"] == "failed"
    assert manifest["classification"] == "test_failure"
    assert manifest["failed_phase"] == "full_pytest"
    assert manifest["pass_eligible"] is False
