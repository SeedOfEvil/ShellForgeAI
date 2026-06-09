"""PR178 — validation environment preflight and container fallback guidance.

These tests cover the read-only validation environment preflight
(``scripts/validation_env_preflight.py``), its integration into the Docker01 PR
lane helper (stop before ruff/compileall/pytest on setup failure), and the
PR177 validation status viewer's summary of preflight setup failures.

They are process/evidence-tooling tests only. They never install packages,
never run Docker/Compose, never run a real long pytest, never mutate
services/containers or real ``/data``, and never require the Docker daemon.
Fake check functions, fake subprocess runners, and ``tmp_path`` are used.
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
PREFLIGHT_PATH = SCRIPTS / "validation_env_preflight.py"
LANE_PATH = SCRIPTS / "sfai_docker01_pr_lane.py"
VIEWER_PATH = SCRIPTS / "validation_status.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


pf = _load("pr178_validation_env_preflight", PREFLIGHT_PATH)
lane = _load("pr178_sfai_docker01_pr_lane", LANE_PATH)
viewer = _load("pr178_validation_status", VIEWER_PATH)


# --------------------------------------------------------------------------- #
# Standalone preflight helpers
# --------------------------------------------------------------------------- #
def _run_preflight(tmp_path, *, missing=(), missing_helpers=(), require_xdist=False):
    """Run the preflight with fake module/tool/helper lookups."""
    missing = set(missing)
    missing_helpers = set(missing_helpers)
    return pf.run_preflight(
        artifact_dir=tmp_path,
        require_xdist=require_xdist,
        module_available=lambda name: name not in missing,
        tool_path=lambda name: None if name in missing else f"/usr/bin/{name}",
        helper_exists=lambda rel: rel not in missing_helpers,
    )


def _ok_runner(calls):
    def run(argv, **_kwargs):
        calls.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")

    return run


def _run_lane_main(monkeypatch, tmp_path, *, preflight_report=None, calls=None, pr="178"):
    """Run the lane helper main with a fake runner and optional fake preflight."""
    calls = calls if calls is not None else []
    monkeypatch.setattr(lane.subprocess, "run", _ok_runner(calls))
    if preflight_report is not None:
        monkeypatch.setattr(
            lane.validation_env_preflight, "run_preflight", lambda **_kw: preflight_report
        )
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
            str(tmp_path / "validation-manifest.json"),
            "--summary-output",
            str(tmp_path / "validation-summary.txt"),
            "--heartbeat-file",
            str(tmp_path / "validation-heartbeat.json"),
            "--checkpoint-file",
            str(tmp_path / "validation-checkpoints.json"),
            "--status-file",
            str(tmp_path / "validation-status.json"),
        ]
    )
    manifest = json.loads((tmp_path / "validation-manifest.json").read_text(encoding="utf-8"))
    summary = (tmp_path / "validation-summary.txt").read_text(encoding="utf-8")
    return rc, manifest, summary, calls


def _failed_preflight_report(tmp_path, *, missing=("ruff",)):
    return _run_preflight(tmp_path, missing=missing)


def _warning_preflight_report(tmp_path):
    report = _run_preflight(tmp_path, missing=("xdist",))
    assert report["status"] == "passed_with_warnings"
    return report


def _passed_preflight_report(tmp_path):
    report = _run_preflight(tmp_path)
    assert report["status"] == "passed"
    return report


# --------------------------------------------------------------------------- #
# 1-11. Standalone preflight
# --------------------------------------------------------------------------- #
def test_01_preflight_json_is_strict_json(tmp_path):
    report = _run_preflight(tmp_path)
    parsed = json.loads(pf.render_json(report))
    assert parsed["schema_version"] == 1
    assert parsed["mode"] == "validation_environment_preflight"
    assert isinstance(parsed["checks"], list)
    assert isinstance(parsed["summary"], dict)


def test_02_all_required_tools_present_passes(tmp_path):
    report = _run_preflight(tmp_path)
    assert report["status"] == "passed"
    assert report["classification"] == "passed"
    assert report["summary"]["required_failed"] == 0
    assert pf.exit_code_for(report) == 0


def test_03_missing_ruff_fails(tmp_path):
    report = _run_preflight(tmp_path, missing=("ruff",))
    assert report["status"] == "failed"
    assert report["classification"] == "setup_failure"
    assert "ruff" in report["failed_checks"]
    ruff_check = next(c for c in report["checks"] if c["name"] == "ruff")
    assert ruff_check["status"] == "failed"
    assert ruff_check["required"] is True
    assert pf.exit_code_for(report) == 1


def test_04_missing_pytest_fails(tmp_path):
    report = _run_preflight(tmp_path, missing=("pytest",))
    assert report["status"] == "failed"
    assert report["classification"] == "setup_failure"
    assert "pytest" in report["failed_checks"]
    assert pf.exit_code_for(report) == 1


def test_05_missing_xdist_warns_unless_required(tmp_path):
    optional = _run_preflight(tmp_path, missing=("xdist",))
    assert optional["status"] == "passed_with_warnings"
    assert "pytest_xdist" in optional["warning_checks"]
    assert pf.exit_code_for(optional) == 0

    strict = _run_preflight(tmp_path, missing=("xdist",), require_xdist=True)
    assert strict["status"] == "failed"
    assert "pytest_xdist" in strict["failed_checks"]
    assert pf.exit_code_for(strict) == 1


def test_06_artifact_dir_not_writable_fails(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    report = _run_preflight(blocker / "sub")
    assert report["status"] == "failed"
    assert "artifact_dir_writable" in report["failed_checks"]
    assert "heartbeat_write" in report["failed_checks"]


def test_07_heartbeat_probe_failure_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(
        pf, "_heartbeat_probe", lambda _directory: (False, "simulated probe failure")
    )
    report = _run_preflight(tmp_path)
    assert report["status"] == "failed"
    assert report["classification"] == "setup_failure"
    assert "heartbeat_write" in report["failed_checks"]


def test_08_failed_preflight_human_output_says_setup_failure(tmp_path):
    report = _run_preflight(tmp_path, missing=("ruff",))
    text = pf.render_human(report)
    assert "Classification: setup_failure" in text
    assert "setup failure, not evidence that product tests failed" in text
    assert "Rerun required: yes" in text
    assert "disposable validation container" in text


def test_09_failed_preflight_pass_eligible_false(tmp_path):
    report = _run_preflight(tmp_path, missing=("ruff",))
    assert report["pass_eligible"] is False


def test_10_failed_preflight_rerun_required_true(tmp_path):
    report = _run_preflight(tmp_path, missing=("ruff",))
    assert report["rerun_required"] is True


def test_11_preflight_safety_flags(tmp_path):
    report = _run_preflight(tmp_path, missing=("ruff", "pytest"))
    safety = report["safety"]
    assert safety["packages_installed"] is False
    assert safety["validation_executed"] is False
    assert safety["pytest_executed"] is False
    assert safety["ruff_executed"] is False
    assert safety["docker_compose_executed"] is False
    assert safety["read_only"] is True
    for value in safety.values():
        assert value in (True, False)


def test_11b_preflight_probe_file_is_removed(tmp_path):
    report = pf.run_preflight(artifact_dir=tmp_path)
    assert report["status"] in ("passed", "passed_with_warnings", "failed")
    leftovers = list(tmp_path.glob(".sfai-preflight-probe-*.json"))
    assert leftovers == []


# --------------------------------------------------------------------------- #
# 12-18. Helper integration (Docker01 PR lane)
# --------------------------------------------------------------------------- #
def test_12_lane_stops_before_ruff_when_preflight_fails(monkeypatch, tmp_path, capsys):
    report = _failed_preflight_report(tmp_path / "pf")
    rc, manifest, _summary, calls = _run_lane_main(monkeypatch, tmp_path, preflight_report=report)
    capsys.readouterr()
    assert rc != 0
    # No validation command (ruff/compileall/pytest) was executed at all; only
    # the lane's read-only git metadata lookups touch subprocess.
    assert all(argv and argv[0] == "git" for argv in calls)
    assert all(record["status"] == "not_run" for record in manifest["commands"])


def test_13_failed_preflight_writes_validation_evidence_dir(monkeypatch, tmp_path, capsys):
    report = _failed_preflight_report(tmp_path / "pf")
    _rc, _manifest, _summary, _calls = _run_lane_main(
        monkeypatch, tmp_path, preflight_report=report
    )
    capsys.readouterr()
    assert (tmp_path / "validation-manifest.json").is_file()
    assert (tmp_path / "validation-summary.txt").is_file()
    assert (tmp_path / "validation-heartbeat.json").is_file()
    assert (tmp_path / "validation-status.json").is_file()
    preflight_file = tmp_path / "validation-preflight.json"
    assert preflight_file.is_file()
    saved = json.loads(preflight_file.read_text(encoding="utf-8"))
    assert saved["status"] == "failed"
    assert saved["classification"] == "setup_failure"


def test_14_failed_preflight_manifest_is_setup_failure(monkeypatch, tmp_path, capsys):
    report = _failed_preflight_report(tmp_path / "pf")
    _rc, manifest, _summary, _calls = _run_lane_main(monkeypatch, tmp_path, preflight_report=report)
    capsys.readouterr()
    assert manifest["status"] == "failed"
    assert manifest["classification"] == "setup_failure"
    assert manifest["pass_eligible"] is False
    assert manifest["rerun_required"] is True
    status_doc = json.loads((tmp_path / "validation-status.json").read_text(encoding="utf-8"))
    assert status_doc["classification"] == "setup_failure"


def test_15_failed_preflight_failed_phase_is_environment_preflight(monkeypatch, tmp_path, capsys):
    report = _failed_preflight_report(tmp_path / "pf")
    _rc, manifest, summary, _calls = _run_lane_main(monkeypatch, tmp_path, preflight_report=report)
    capsys.readouterr()
    assert manifest["failed_phase"] == "environment_preflight"
    assert "Validation environment preflight failed" in summary
    assert "setup failure, not product test failure" in summary


def test_16_failed_preflight_does_not_mark_full_pytest_passed(monkeypatch, tmp_path, capsys):
    report = _failed_preflight_report(tmp_path / "pf")
    _rc, manifest, _summary, _calls = _run_lane_main(monkeypatch, tmp_path, preflight_report=report)
    capsys.readouterr()
    assert manifest["full_pytest_result"] != "passed"
    assert manifest["phase_status"]["full_pytest"] != "passed"
    assert manifest["validation"]["full_pytest"] != "passed"


def test_17_warning_only_preflight_continues(monkeypatch, tmp_path, capsys):
    report = _warning_preflight_report(tmp_path / "pf")
    rc, manifest, _summary, calls = _run_lane_main(monkeypatch, tmp_path, preflight_report=report)
    capsys.readouterr()
    assert rc == 0
    assert any(argv and argv[0] != "git" for argv in calls), (
        "validation commands should run after a warning-only preflight"
    )
    assert manifest["status"] == "passed"
    assert manifest["environment_preflight"]["status"] == "passed_with_warnings"
    assert "pytest_xdist" in manifest["environment_preflight"]["warning_checks"]
    assert any("preflight warning" in note for note in manifest["non_blockers"])


def test_18_passed_preflight_continues(monkeypatch, tmp_path, capsys):
    report = _passed_preflight_report(tmp_path / "pf")
    rc, manifest, _summary, calls = _run_lane_main(monkeypatch, tmp_path, preflight_report=report)
    capsys.readouterr()
    assert rc == 0
    assert any(argv and argv[0] != "git" for argv in calls)
    assert manifest["status"] == "passed"
    assert manifest["pass_eligible"] is True
    assert manifest["environment_preflight"]["status"] == "passed"
    assert manifest["phase_status"]["environment_preflight"] == "passed"


def test_18b_preflight_only_mode_runs_without_changed_files(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        lane.validation_env_preflight,
        "run_preflight",
        lambda **_kw: _passed_preflight_report(tmp_path / "pf"),
    )
    rc = lane.main(["--preflight-only", "--preflight-output", str(tmp_path / "pf.json")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Validation environment preflight" in out
    assert json.loads((tmp_path / "pf.json").read_text(encoding="utf-8"))["status"] == "passed"


# --------------------------------------------------------------------------- #
# 19-22. Viewer integration (validation_status.py)
# --------------------------------------------------------------------------- #
def _viewer_report_for_failed_preflight(monkeypatch, tmp_path, capsys):
    report = _failed_preflight_report(tmp_path / "pf")
    _run_lane_main(monkeypatch, tmp_path, preflight_report=report)
    capsys.readouterr()
    args = viewer.build_parser().parse_args(["--run-dir", str(tmp_path), "--json"])
    return viewer.generate_report(args)


def test_19_viewer_summarizes_preflight_setup_failure(monkeypatch, tmp_path, capsys):
    report = _viewer_report_for_failed_preflight(monkeypatch, tmp_path, capsys)
    assert report["status"] == "failed"
    assert report["classification"] == "setup_failure"
    assert report["failed_phase"] == "environment_preflight"
    assert "validation_env_preflight" in report["first_safe_command"]
    human = viewer.render_human(report)
    assert "setup failure" in human
    assert "disposable validation container" in human


def test_20_viewer_reports_pass_eligible_false(monkeypatch, tmp_path, capsys):
    report = _viewer_report_for_failed_preflight(monkeypatch, tmp_path, capsys)
    assert report["pass_eligible"] is False


def test_21_viewer_reports_rerun_required_true(monkeypatch, tmp_path, capsys):
    report = _viewer_report_for_failed_preflight(monkeypatch, tmp_path, capsys)
    assert report["rerun_required"] is True


def test_22_viewer_remains_read_only(monkeypatch, tmp_path, capsys):
    report = _viewer_report_for_failed_preflight(monkeypatch, tmp_path, capsys)
    safety = report["safety"]
    assert safety["read_only"] is True
    assert safety["validation_executed"] is False
    assert safety["pytest_executed"] is False
    assert safety["mutation_performed"] is False
    # The viewer module never imports subprocess (no execution capability).
    tree = ast.parse(VIEWER_PATH.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name != "subprocess" for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module != "subprocess"


def test_22b_viewer_standalone_failed_preflight_artifact(tmp_path, capsys):
    # A run dir containing only the preflight report still summarizes clearly.
    pf_report = _failed_preflight_report(tmp_path / "probe")
    pf.write_report(pf_report, tmp_path / "validation-preflight.json")
    args = viewer.build_parser().parse_args(["--run-dir", str(tmp_path), "--json"])
    report = viewer.generate_report(args)
    capsys.readouterr()
    assert report["status"] == "failed"
    assert report["classification"] == "setup_failure"
    assert report["failed_phase"] == "environment_preflight"
    assert report["pass_eligible"] is False
    assert report["rerun_required"] is True


# --------------------------------------------------------------------------- #
# 23-30. Safety / process
# --------------------------------------------------------------------------- #
def _preflight_source() -> str:
    return PREFLIGHT_PATH.read_text(encoding="utf-8")


def test_23_no_package_install_invoked(tmp_path):
    source = _preflight_source()
    assert "pip install" not in source
    assert "ensurepip" not in source
    report = _run_preflight(tmp_path, missing=("ruff", "pytest", "xdist"))
    assert report["safety"]["packages_installed"] is False


def test_24_no_docker_compose_invoked(tmp_path):
    report = _run_preflight(tmp_path, missing=("ruff",))
    assert report["safety"]["docker_compose_executed"] is False
    # The container path is recommendation text only, never an execution.
    assert "disposable validation container" in report["recommendation"]
    tree = ast.parse(_preflight_source())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name != "subprocess" for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module != "subprocess"


def test_25_preflight_never_executes_pytest(tmp_path, monkeypatch):
    # No subprocess capability exists in the module, and the check is a spec
    # lookup only: pytest "available" must not mean pytest "executed".
    executed = []
    monkeypatch.setattr(
        pf,
        "_module_available",
        lambda name: executed.append(name) or True,
    )
    report = pf.run_preflight(artifact_dir=tmp_path)
    assert "pytest" in executed  # checked for availability...
    assert report["safety"]["pytest_executed"] is False  # ...but never run


def test_26_preflight_never_executes_ruff_check(tmp_path):
    source = _preflight_source()
    assert "ruff check" not in source.replace("``ruff check``", "")
    report = _run_preflight(tmp_path)
    assert report["safety"]["ruff_executed"] is False


def test_27_no_shell_true_introduced():
    for path in (PREFLIGHT_PATH, LANE_PATH, VIEWER_PATH):
        assert "shell=True" not in path.read_text(encoding="utf-8"), path


def test_28_no_product_runtime_changes():
    # The preflight imports no ShellForgeAI runtime modules and the lane
    # helper's forbidden-runtime-action railing is unchanged.
    tree = ast.parse(_preflight_source())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(not alias.name.startswith("shellforgeai") for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("shellforgeai")
    assert "cleanup execute" in lane.FORBIDDEN_RUNTIME_ACTIONS
    assert "remediation execute" in lane.FORBIDDEN_RUNTIME_ACTIONS
    assert "rollback execute" in lane.FORBIDDEN_RUNTIME_ACTIONS


def test_29_no_cleanup_remediation_rollback_recovery(tmp_path):
    report = _run_preflight(tmp_path, missing=("ruff",))
    safety = report["safety"]
    assert safety["cleanup_executed"] is False
    assert safety["remediation_executed"] is False
    assert safety["rollback_executed"] is False
    assert safety["recovery_executed"] is False
    assert safety["container_restarted"] is False


def test_30_no_natural_language_execution(tmp_path):
    report = _run_preflight(tmp_path, missing=("ruff",))
    assert report["safety"]["natural_language_execution"] is False
    assert report["safety"]["arbitrary_command_execution"] is False
    assert report["safety"]["model_called"] is False
    # First safe commands stay deterministic argv-style strings.
    assert report["first_safe_command"].startswith("python scripts/")
    for command in report["safe_next_commands"]:
        assert command.startswith("python scripts/")
