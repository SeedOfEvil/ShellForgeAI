"""PR177 — read-only validation evidence status viewer.

These tests cover ``scripts/validation_status.py``: a read-only viewer that
reads PR176 heartbeat/status JSON and validation manifest evidence and classifies
a run as passed / failed / incomplete / unknown, reporting ``pass_eligible`` and
``rerun_required`` for both humans and automation.

They are tooling tests only. They never run Docker/Compose, never run a real
long pytest, never mutate services/containers or real ``/data``, and never
require the Docker daemon. ``tmp_path`` fixtures and fake JSON evidence are used.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
VIEWER_PATH = SCRIPTS / "validation_status.py"
HEARTBEAT_PATH = SCRIPTS / "validation_heartbeat.py"
RUNNER_PATH = SCRIPTS / "run_full_pytest.py"
LANE_PATH = SCRIPTS / "sfai_docker01_pr_lane.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


vs = _load("pr177_validation_status", VIEWER_PATH)
vh = _load("pr177_validation_heartbeat", HEARTBEAT_PATH)


# --------------------------------------------------------------------------- #
# Fake evidence builders
# --------------------------------------------------------------------------- #
def _passed_heartbeat() -> dict:
    return {
        "schema_version": 1,
        "mode": "validation_heartbeat",
        "run_id": "validation-pr177-abc",
        "pr": 177,
        "commit": "abcdef1234567890",
        "status": "passed",
        "classification": "passed",
        "active_phase": None,
        "last_completed_phase": "full_pytest",
        "phase_status": {
            "ruff": "passed",
            "compileall": "passed",
            "targeted_tests": "passed",
            "full_pytest": "passed",
        },
        "required_phases": ["ruff", "compileall", "targeted_tests", "full_pytest"],
        "full_pytest_exit_code": 0,
        "full_pytest_result": "passed",
        "pass_eligible": True,
        "rerun_required": False,
        "finalized": True,
        "started_at": "2026-06-09T00:00:00Z",
        "last_update": "2026-06-09T00:10:00Z",
    }


def _incomplete_heartbeat() -> dict:
    return {
        "schema_version": 1,
        "mode": "validation_heartbeat",
        "run_id": "validation-pr177-inc",
        "pr": 177,
        "status": "running",
        "active_phase": "full_pytest",
        "last_completed_phase": "targeted_tests",
        "phase_status": {
            "ruff": "passed",
            "compileall": "passed",
            "targeted_tests": "passed",
            "full_pytest": "running",
        },
        "required_phases": ["ruff", "compileall", "targeted_tests", "full_pytest"],
        "full_pytest_exit_code": None,
        "full_pytest_result": "unknown",
        "pass_eligible": False,
        "rerun_required": True,
        "finalized": False,
        "started_at": "2026-06-09T00:00:00Z",
        "last_update": "2026-06-09T00:05:00Z",
    }


def _failed_heartbeat() -> dict:
    return {
        "schema_version": 1,
        "mode": "validation_heartbeat",
        "status": "failed",
        "classification": "test_failure",
        "active_phase": None,
        "last_completed_phase": "targeted_tests",
        "phase_status": {
            "ruff": "passed",
            "compileall": "passed",
            "targeted_tests": "passed",
            "full_pytest": "failed",
        },
        "required_phases": ["ruff", "compileall", "targeted_tests", "full_pytest"],
        "full_pytest_exit_code": 1,
        "full_pytest_result": "failed",
        "failed_phase": "full_pytest",
        "pass_eligible": False,
        "rerun_required": True,
    }


def _setup_failure_heartbeat() -> dict:
    return {
        "schema_version": 1,
        "mode": "validation_heartbeat",
        "status": "failed",
        "classification": "setup_failure",
        "phase_status": {
            "ruff": "failed",
            "compileall": "not_started",
            "targeted_tests": "not_started",
            "full_pytest": "not_started",
        },
        "required_phases": ["ruff", "compileall", "targeted_tests", "full_pytest"],
        "full_pytest_exit_code": None,
        "failed_phase": "ruff",
        "pass_eligible": False,
        "rerun_required": True,
    }


def _write(path: Path, data: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _run_dir_with(tmp_path: Path, *, heartbeat=None, status=None, manifest=None) -> Path:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    if heartbeat is not None:
        _write(run_dir / "validation-heartbeat.json", heartbeat)
    if status is not None:
        _write(run_dir / "validation-status.json", status)
    if manifest is not None:
        _write(run_dir / "manifest.json", manifest)
    return run_dir


def _human(argv: list[str], capsys) -> str:
    assert vs.main(argv) == 0
    return capsys.readouterr().out


def _json(argv: list[str], capsys) -> dict:
    assert vs.main(argv) == 0
    out = capsys.readouterr().out
    return json.loads(out)


# --------------------------------------------------------------------------- #
# 1-5. Basic rendering
# --------------------------------------------------------------------------- #
def test_01_renders_passed_human(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _passed_heartbeat())
    out = _human(["--heartbeat", str(hb)], capsys)
    assert "Validation evidence status" in out
    assert "Status: PASSED" in out
    assert "Pass eligible: yes" in out
    assert "Rerun required: no" in out
    assert "* full_pytest: passed" in out
    assert "First safe command:" in out


def test_02_renders_incomplete_human(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _incomplete_heartbeat())
    out = _human(["--heartbeat", str(hb)], capsys)
    assert "Status: INCOMPLETE" in out
    assert "Classification: interrupted_or_incomplete" in out
    assert "Pass eligible: no" in out
    assert "Rerun required: yes" in out
    assert "active phase: full_pytest" in out
    assert "last completed phase: targeted_tests" in out
    assert "must not be used as merge evidence" in out


def test_03_renders_failed_human(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _failed_heartbeat())
    out = _human(["--heartbeat", str(hb)], capsys)
    assert "Status: FAILED" in out
    assert "Pass eligible: no" in out
    assert "Failed phase:" in out
    assert "* full_pytest" in out


def test_04_renders_unknown_no_evidence_human(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    out = _human(["--run-dir", str(empty)], capsys)
    assert "Status: UNKNOWN" in out
    assert "Classification: no_evidence" in out
    assert "Pass eligible: no" in out
    assert "No validation heartbeat/status/manifest evidence was found." in out


def test_05_json_strict(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _passed_heartbeat())
    assert vs.main(["--heartbeat", str(hb), "--json"]) == 0
    out = capsys.readouterr().out
    # No human text before/after the JSON: the whole stream parses.
    parsed = json.loads(out)
    assert parsed["mode"] == "validation_evidence_status"
    assert out.strip() == json.dumps(parsed, sort_keys=True)


# --------------------------------------------------------------------------- #
# 6-15. Classification
# --------------------------------------------------------------------------- #
def test_06_all_passed_full_exit0_status_passed(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _passed_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert report["status"] == "passed"
    assert report["full_pytest"]["exit_code"] == 0


def test_07_passed_evidence_pass_eligible_true(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _passed_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert report["pass_eligible"] is True
    assert report["rerun_required"] is False


def test_08_missing_full_pytest_completion_status_incomplete(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _incomplete_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert report["status"] == "incomplete"


def test_09_missing_full_pytest_completion_pass_eligible_false(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _incomplete_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert report["pass_eligible"] is False


def test_10_missing_full_pytest_completion_rerun_required_true(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _incomplete_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert report["rerun_required"] is True


def test_11_full_pytest_exit_nonzero_status_failed(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _failed_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert report["status"] == "failed"
    assert report["classification"] == "test_failure"


def test_12_setup_failure_classification(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _setup_failure_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert report["status"] == "failed"
    assert report["classification"] == "setup_failure"


def test_13_no_evidence_classification(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    report = _json(["--run-dir", str(empty), "--json"], capsys)
    assert report["status"] == "unknown"
    assert report["classification"] == "no_evidence"
    assert report["pass_eligible"] is False
    assert report["rerun_required"] is True


def test_14_conflicting_evidence_never_pass_eligible(tmp_path, capsys):
    # Manifest claims passed, but heartbeat shows an interrupted/incomplete run.
    manifest = {
        "schema_version": 1,
        "mode": "docker01_pr_validation_manifest",
        "status": "passed",
        "classification": "passed",
        "pass_eligible": True,
        "rerun_required": False,
        "phase_status": {
            "ruff": "passed",
            "compileall": "passed",
            "targeted_tests": "passed",
            "full_pytest": "passed",
        },
        "full_pytest_exit_code": 0,
        "full_pytest_result": "passed",
    }
    run_dir = _run_dir_with(tmp_path, manifest=manifest, heartbeat=_incomplete_heartbeat())
    report = _json(["--run-dir", str(run_dir), "--json"], capsys)
    assert report["pass_eligible"] is False
    assert report["status"] in ("incomplete", "failed")
    assert any("conflict" in w.lower() for w in report["warnings"])


def test_15_targeted_passed_alone_not_pass(tmp_path, capsys):
    hb = {
        "schema_version": 1,
        "mode": "validation_heartbeat",
        "status": "running",
        "active_phase": "full_pytest",
        "last_completed_phase": "targeted_tests",
        "phase_status": {
            "ruff": "passed",
            "compileall": "passed",
            "targeted_tests": "passed",
            "full_pytest": "not_started",
        },
        "full_pytest_exit_code": None,
    }
    path = _write(tmp_path / "hb.json", hb)
    report = _json(["--heartbeat", str(path), "--json"], capsys)
    assert report["status"] != "passed"
    assert report["pass_eligible"] is False


# --------------------------------------------------------------------------- #
# 16-22. Source loading
# --------------------------------------------------------------------------- #
def test_16_run_dir_loads_all_sources(tmp_path, capsys):
    run_dir = _run_dir_with(
        tmp_path,
        heartbeat=_passed_heartbeat(),
        status=_passed_heartbeat(),
        manifest={
            "mode": "docker01_pr_validation_manifest",
            "status": "passed",
            "phase_status": {
                "ruff": "passed",
                "compileall": "passed",
                "targeted_tests": "passed",
                "full_pytest": "passed",
            },
            "full_pytest_exit_code": 0,
        },
    )
    report = _json(["--run-dir", str(run_dir), "--json"], capsys)
    src = report["source"]
    assert src["heartbeat_path"].endswith("validation-heartbeat.json")
    assert src["status_path"].endswith("validation-status.json")
    assert src["manifest_path"].endswith("manifest.json")
    assert report["status"] == "passed"


def test_17_explicit_heartbeat_loads(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _passed_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert report["source"]["heartbeat_path"] == str(hb)
    assert report["status"] == "passed"


def test_18_explicit_status_file_loads(tmp_path, capsys):
    st = _write(tmp_path / "st.json", _incomplete_heartbeat())
    report = _json(["--status-file", str(st), "--json"], capsys)
    assert report["source"]["status_path"] == str(st)
    assert report["status"] == "incomplete"


def test_19_explicit_manifest_loads(tmp_path, capsys):
    manifest = {
        "mode": "docker01_pr_validation_manifest",
        "status": "failed",
        "classification": "test_failure",
        "phase_status": {
            "ruff": "passed",
            "compileall": "passed",
            "targeted_tests": "passed",
            "full_pytest": "failed",
        },
        "full_pytest_exit_code": 1,
        "failed_phase": "full_pytest",
    }
    mf = _write(tmp_path / "m.json", manifest)
    report = _json(["--manifest", str(mf), "--json"], capsys)
    assert report["source"]["manifest_path"] == str(mf)
    assert report["status"] == "failed"


def test_20_malformed_json_handled_with_warning(tmp_path, capsys):
    bad = tmp_path / "hb.json"
    bad.write_text("{not valid json", encoding="utf-8")
    report = _json(["--heartbeat", str(bad), "--json"], capsys)
    assert report["status"] == "unknown"
    assert any("could not read" in w for w in report["warnings"])


def test_21_missing_explicit_path_controlled_error(tmp_path, capsys):
    missing = tmp_path / "nope.json"
    rc = vs.main(["--heartbeat", str(missing)])
    out = capsys.readouterr()
    assert rc == 2
    assert "does not exist" in out.err


def test_22_latest_chooses_most_recent_run(tmp_path, capsys, monkeypatch):
    older = tmp_path / "runs" / "old"
    newer = tmp_path / "runs" / "new"
    _write(older / "manifest.json", {"mode": "m", "status": "failed"})
    _write(newer / "manifest.json", _passed_heartbeat())
    # Make ``newer`` the most recently modified run directory.
    old_time = 1_000_000
    new_time = 2_000_000
    os.utime(older / "manifest.json", (old_time, old_time))
    os.utime(newer / "manifest.json", (new_time, new_time))
    monkeypatch.setenv(vs.RUNS_DIR_ENV, str(tmp_path / "runs"))
    report = _json(["--latest", "--json"], capsys)
    assert report["source"]["latest"] is True
    assert report["source"]["run_dir"].endswith("new")


# --------------------------------------------------------------------------- #
# 23-30. JSON contract
# --------------------------------------------------------------------------- #
def test_23_json_includes_schema_version(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _passed_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert report["schema_version"] == 1


def test_24_json_includes_pass_eligible(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _passed_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert "pass_eligible" in report


def test_25_json_includes_rerun_required(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _passed_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert "rerun_required" in report


def test_26_json_includes_phase_status(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _passed_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    phase_status = report["phases"]["phase_status"]
    for phase in ("ruff", "compileall", "targeted_tests", "full_pytest"):
        assert phase in phase_status


def test_27_json_includes_safety_block(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _passed_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert report["safety"]["read_only"] is True
    assert report["safety"]["mutation_performed"] is False


def test_28_safety_validation_executed_false(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _passed_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert report["safety"]["validation_executed"] is False


def test_29_safety_pytest_executed_false(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _passed_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert report["safety"]["pytest_executed"] is False


def test_30_safety_docker_compose_executed_false(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _passed_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert report["safety"]["docker_compose_executed"] is False
    assert report["safety"]["container_restarted"] is False
    assert report["safety"]["model_called"] is False


# --------------------------------------------------------------------------- #
# 31-33. Script behavior
# --------------------------------------------------------------------------- #
# Split forbidden tokens so they never appear literally in this test file.
_SUB = "subprocess"
_SHELL_TRUE = "shell" + "=True"


def test_31_viewer_does_not_call_subprocess_or_pytest():
    text = VIEWER_PATH.read_text(encoding="utf-8")
    assert f"import {_SUB}" not in text
    assert f"{_SUB}.run" not in text
    assert f"{_SUB}.Popen" not in text
    assert "os.system" not in text


def test_32_viewer_does_not_use_shell_true():
    tree = ast.parse(VIEWER_PATH.read_text(encoding="utf-8"), filename=str(VIEWER_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                    assert keyword.value.value is not True
    assert _SHELL_TRUE not in VIEWER_PATH.read_text(encoding="utf-8")


def test_33_invalid_arguments_fail_cleanly(capsys):
    import pytest

    with pytest.raises(SystemExit) as exc:
        vs.main(["--not-a-flag"])
    assert exc.value.code == 2


# --------------------------------------------------------------------------- #
# 34-37. Integration / regression
# --------------------------------------------------------------------------- #
def test_34_lane_helper_output_mentions_viewer(monkeypatch, tmp_path, capsys):
    lane = _load("pr177_sfai_docker01_pr_lane", LANE_PATH)
    monkeypatch.setattr(
        lane.subprocess,
        "run",
        lambda *a, **k: __import__("types").SimpleNamespace(returncode=0, stdout="ok", stderr=""),
    )
    rc = lane.main(
        [
            "--changed-files",
            "docs/cli.md",
            "--manifest-output",
            str(tmp_path / "m.json"),
            "--summary-output",
            str(tmp_path / "s.txt"),
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "Validation status viewer:" in out
    assert "validation_status.py" in out


def test_35_pr176_heartbeat_tests_still_present():
    # The PR176 heartbeat module/classifier are unchanged and still importable.
    assert hasattr(vh, "classify_run")
    result = vh.classify_run(
        {
            "ruff": "passed",
            "compileall": "passed",
            "targeted_tests": "passed",
            "full_pytest": "passed",
        },
        full_pytest_exit_code=0,
    )
    assert result["status"] == "passed"


def test_36_manifest_validation_rollup_classified(tmp_path, capsys):
    # A mainline manifest (validation rollup, no phase_status) classifies cleanly.
    manifest = {
        "mode": "mainline_validation_manifest",
        "status": "passed",
        "validation": {
            "ruff": "passed",
            "compileall": "passed",
            "targeted_tests": "passed",
            "full_pytest": "passed",
        },
    }
    mf = _write(tmp_path / "m.json", manifest)
    report = _json(["--manifest", str(mf), "--json"], capsys)
    assert report["status"] == "passed"
    assert report["pass_eligible"] is True


def test_37_run_full_pytest_module_unchanged():
    runner = _load("pr177_run_full_pytest", RUNNER_PATH)
    plan = runner.plan_full_pytest(xdist_available=True)
    assert plan.xdist_enabled is True


# --------------------------------------------------------------------------- #
# 38-47. Safety
# --------------------------------------------------------------------------- #
_DKR = "dock" + "er"
_CMP = "com" + "pose"
_DATA = "/" + "data/validation"


def test_38_no_cleanup_or_remediation_execution_in_viewer():
    text = VIEWER_PATH.read_text(encoding="utf-8").lower()
    for needle in (
        "cleanup execute",
        "remediation execute",
        "rollback execute",
        "recovery execute",
    ):
        assert needle not in text


def test_39_no_docker_compose_mutation_forms_in_viewer():
    text = VIEWER_PATH.read_text(encoding="utf-8").lower()
    for needle in (
        f"{_DKR} {_CMP} up",
        f"{_DKR} {_CMP} down",
        f"{_DKR} {_CMP} restart",
        f"{_DKR} restart",
        f"{_DKR}.from_env",
    ):
        assert needle not in text


def test_40_no_model_or_natural_language_execution_in_viewer():
    text = VIEWER_PATH.read_text(encoding="utf-8").lower()
    assert "codex" not in text
    assert "openai" not in text


def test_41_no_product_runtime_import_in_viewer():
    pkg = "shellforge" + "ai"
    text = VIEWER_PATH.read_text(encoding="utf-8").lower()
    assert f"import {pkg}" not in text
    assert f"from {pkg}" not in text


def test_42_safety_block_all_execution_flags_false(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _passed_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    safety = report["safety"]
    for key in (
        "validation_executed",
        "pytest_executed",
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
        "docker_compose_executed",
        "container_restarted",
        "production_restart_executed",
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_execution",
        "model_called",
    ):
        assert safety[key] is False


def test_43_viewer_only_writes_stdout(tmp_path, capsys):
    # Running the viewer against a run dir must not create or modify files there.
    run_dir = _run_dir_with(tmp_path, heartbeat=_passed_heartbeat())
    before = {p.name: p.stat().st_mtime for p in run_dir.iterdir()}
    _json(["--run-dir", str(run_dir), "--json"], capsys)
    after = {p.name: p.stat().st_mtime for p in run_dir.iterdir()}
    assert before == after


def test_44_no_real_docker_or_data_in_unit_tests():
    text = Path(__file__).read_text(encoding="utf-8").lower()
    assert "tmp_path" in text
    for needle in (f"{_DKR} {_CMP}", f"{_DKR}.from_env", _DATA):
        assert needle not in text


def test_45_incomplete_never_reports_full_pytest_passed(tmp_path, capsys):
    hb = _write(tmp_path / "hb.json", _incomplete_heartbeat())
    report = _json(["--heartbeat", str(hb), "--json"], capsys)
    assert report["full_pytest"]["result"] != "passed"


def test_46_unknown_evidence_not_merge_eligible(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    report = _json(["--run-dir", str(empty), "--json"], capsys)
    assert report["pass_eligible"] is False


def test_47_no_runtime_behavior_change_viewer_is_standalone():
    # The viewer is standalone validation tooling: it imports only the sibling
    # heartbeat helper (for the classifier), never the product package.
    tree = ast.parse(VIEWER_PATH.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert ("shellforge" + "ai") not in imported
