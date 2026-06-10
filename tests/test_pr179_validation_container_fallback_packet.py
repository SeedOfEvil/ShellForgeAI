"""PR179 — validation container fallback packet generator.

These tests cover ``scripts/validation_container_fallback.py`` (the disposable
validation-container fallback packet written after a validation environment
setup failure), its integration into ``scripts/sfai_docker01_pr_lane.py``
(packet generation on preflight setup failure), and the PR177 validation
status viewer's read-only reporting of an existing packet.

They are process/evidence-tooling tests only. They never install packages,
never call the Docker daemon, never run Docker Compose, never run a real
pytest/ruff, never mutate services/containers or real ``/data``. Fake evidence
files and ``tmp_path`` fixtures are used throughout.
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
FALLBACK_PATH = SCRIPTS / "validation_container_fallback.py"
LANE_PATH = SCRIPTS / "sfai_docker01_pr_lane.py"
VIEWER_PATH = SCRIPTS / "validation_status.py"
PREFLIGHT_PATH = SCRIPTS / "validation_env_preflight.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


fb = _load("pr179_validation_container_fallback", FALLBACK_PATH)
lane = _load("pr179_sfai_docker01_pr_lane", LANE_PATH)
viewer = _load("pr179_validation_status", VIEWER_PATH)
pf = _load("pr179_validation_env_preflight", PREFLIGHT_PATH)


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #
def _failed_preflight_doc(missing=("ruff", "pytest")) -> dict:
    return {
        "schema_version": 1,
        "mode": "validation_environment_preflight",
        "status": "failed",
        "classification": "setup_failure",
        "pass_eligible": False,
        "rerun_required": True,
        "failed_checks": list(missing),
        "warning_checks": [],
    }


def _setup_failure_run_dir(tmp_path: Path, *, missing=("ruff", "pytest")) -> Path:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "validation-preflight.json").write_text(
        json.dumps(_failed_preflight_doc(missing)), encoding="utf-8"
    )
    return run_dir


def _passed_run_dir(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "validation-status.json").write_text(
        json.dumps(
            {
                "status": "passed",
                "classification": "passed",
                "phase_status": {"full_pytest": "passed"},
                "full_pytest_exit_code": 0,
            }
        ),
        encoding="utf-8",
    )
    return run_dir


def _generate(run_dir: Path, **kwargs) -> dict:
    return fb.generate_packet(run_dir=run_dir, **kwargs)


def _packet_doc(run_dir: Path) -> dict:
    return json.loads((run_dir / fb.FALLBACK_JSON_NAME).read_text(encoding="utf-8"))


def _command_text(run_dir: Path) -> str:
    return (run_dir / fb.FALLBACK_COMMAND_NAME).read_text(encoding="utf-8")


def _ok_runner(calls):
    def run(argv, **_kwargs):
        calls.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")

    return run


def _run_lane_setup_failure(monkeypatch, tmp_path):
    """Run the Docker01 lane helper with a fake failed preflight."""
    calls: list[list[str]] = []
    monkeypatch.setattr(lane.subprocess, "run", _ok_runner(calls))
    monkeypatch.setattr(
        lane.validation_env_preflight, "run_preflight", lambda **_kw: _lane_preflight_report()
    )
    rc = lane.main(
        [
            "--changed-files",
            "Dockerfile",
            "--pr",
            "179",
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


def _lane_preflight_report() -> dict:
    report = _failed_preflight_doc()
    report.update({"checks": [], "warnings": []})
    return report


# --------------------------------------------------------------------------- #
# 1-7. Packet creation
# --------------------------------------------------------------------------- #
def test_01_setup_failure_creates_packet(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path)
    report = _generate(run_dir)
    assert report["status"] == "created"
    assert report["packet"]["created"] is True
    for name in fb.PACKET_FILES:
        assert (run_dir / name).is_file(), name
    assert fb.exit_code_for(report) == 0


def test_02_missing_tools_carried_into_packet(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path, missing=("ruff", "pytest", "pytest_xdist"))
    report = _generate(run_dir)
    missing = report["source"]["missing_required_tools"]
    assert "ruff" in missing
    assert "pytest" in missing
    assert "pytest-xdist" in missing
    doc = _packet_doc(run_dir)
    assert doc["source"]["missing_required_tools"] == missing
    markdown = (run_dir / fb.FALLBACK_MD_NAME).read_text(encoding="utf-8")
    assert "`ruff`" in markdown
    assert "`pytest`" in markdown


def test_03_fallback_json_is_strict_json(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path)
    report = _generate(run_dir)
    parsed = json.loads(fb.render_json(report))
    assert parsed["schema_version"] == 1
    assert parsed["mode"] == "validation_container_fallback_packet"
    on_disk = _packet_doc(run_dir)
    assert on_disk["mode"] == "validation_container_fallback_packet"
    assert on_disk["source"]["classification"] == "setup_failure"
    assert on_disk["container_validation"]["auto_execute"] is False


def test_04_fallback_markdown_written(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path)
    _generate(run_dir)
    markdown = (run_dir / fb.FALLBACK_MD_NAME).read_text(encoding="utf-8")
    assert "setup failure, not product test" in markdown
    assert "disposable validation container" in markdown
    assert "did **not** run this command" in markdown
    assert "No host packages were installed" in markdown


def test_05_command_text_written(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path)
    report = _generate(run_dir)
    text = _command_text(run_dir)
    assert report["container_validation"]["command_preview"] in text
    assert "NOT executed" in text
    argv = json.loads((run_dir / fb.FALLBACK_ARGV_NAME).read_text(encoding="utf-8"))
    assert argv == report["container_validation"]["command_argv"]
    assert argv[0] == "docker"


def test_06_first_safe_command_points_to_command_text(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path)
    report = _generate(run_dir)
    assert report["first_safe_command"] == f"cat {run_dir / fb.FALLBACK_COMMAND_NAME}"


def test_07_safe_next_commands_present(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path)
    report = _generate(run_dir)
    commands = report["safe_next_commands"]
    assert any(str(run_dir / fb.FALLBACK_COMMAND_NAME) in cmd for cmd in commands)
    assert any("validation_status.py" in cmd for cmd in commands)


# --------------------------------------------------------------------------- #
# 8-14. No false execution
# --------------------------------------------------------------------------- #
def _fallback_source() -> str:
    return FALLBACK_PATH.read_text(encoding="utf-8")


def _module_never_imports_subprocess(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name != "subprocess" for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module != "subprocess"


def test_08_packet_generation_does_not_execute_docker(tmp_path):
    # The generator module has no subprocess capability at all: the docker
    # command is text/argv evidence only and is never executed.
    _module_never_imports_subprocess(FALLBACK_PATH)
    run_dir = _setup_failure_run_dir(tmp_path)
    report = _generate(run_dir)
    assert report["safety"]["docker_executed"] is False
    assert report["container_validation"]["auto_execute"] is False
    assert report["container_validation"]["operator_invoked"] is True


def test_09_packet_generation_does_not_execute_docker_compose(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path)
    report = _generate(run_dir)
    assert report["safety"]["docker_compose_executed"] is False
    assert "compose" not in report["container_validation"]["command_preview"]


def test_10_packet_generation_does_not_execute_ruff(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path)
    report = _generate(run_dir)
    assert report["safety"]["ruff_executed"] is False


def test_11_packet_generation_does_not_execute_pytest(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path)
    report = _generate(run_dir)
    assert report["safety"]["pytest_executed"] is False
    assert report["safety"]["validation_executed"] is False


def test_12_packet_generation_does_not_install_packages(tmp_path):
    source = _fallback_source()
    # The only "pip install" anywhere is inside the generated container command
    # text; the generator itself never invokes pip or ensurepip.
    assert "ensurepip" not in source
    run_dir = _setup_failure_run_dir(tmp_path)
    report = _generate(run_dir)
    assert report["safety"]["packages_installed"] is False
    assert report["container_validation"]["host_package_install_required"] is False


def test_13_packet_generation_writes_only_inside_run_dir(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.chdir(outside)
    run_dir = _setup_failure_run_dir(tmp_path)
    before = {p.name for p in run_dir.iterdir()}
    _generate(run_dir)
    after = {p.name for p in run_dir.iterdir()}
    assert after - before == set(fb.PACKET_FILES)
    assert list(outside.iterdir()) == []


def test_14_no_shell_true_in_implementation():
    assert "shell=True" not in _fallback_source()
    assert "shell=True" not in LANE_PATH.read_text(encoding="utf-8")
    assert "shell=True" not in VIEWER_PATH.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# 15-18. Status behavior
# --------------------------------------------------------------------------- #
def test_15_clean_run_returns_not_needed(tmp_path):
    run_dir = _passed_run_dir(tmp_path)
    report = _generate(run_dir)
    assert report["status"] == "not_needed"
    assert report["packet"]["created"] is False
    # No artifact churn: nothing new is written for a clean run.
    assert not (run_dir / fb.FALLBACK_JSON_NAME).exists()
    assert fb.exit_code_for(report) == 0


def test_16_missing_run_dir_returns_not_found(tmp_path):
    report = _generate(tmp_path / "does-not-exist")
    assert report["status"] == "not_found"
    assert fb.exit_code_for(report) != 0
    assert report["packet"]["created"] is False


def test_16b_missing_run_dir_cli_no_traceback(tmp_path, capsys):
    rc = fb.main(["--run-dir", str(tmp_path / "missing"), "--json"])
    out = capsys.readouterr()
    assert rc == 2
    parsed = json.loads(out.out)
    assert parsed["status"] == "not_found"
    assert "Traceback" not in out.out + out.err


def test_17_malformed_evidence_returns_failed(tmp_path, capsys):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "validation-preflight.json").write_text("{not valid json", encoding="utf-8")
    rc = fb.main(["--run-dir", str(run_dir), "--json"])
    out = capsys.readouterr()
    assert rc == 1
    parsed = json.loads(out.out)
    assert parsed["status"] == "failed"
    assert parsed["warnings"]
    assert "Traceback" not in out.out + out.err


def test_18_force_creates_packet_for_clean_run(tmp_path):
    run_dir = _passed_run_dir(tmp_path)
    report = _generate(run_dir, force=True)
    assert report["status"] == "created"
    assert report["forced"] is True
    assert (run_dir / fb.FALLBACK_JSON_NAME).is_file()


# --------------------------------------------------------------------------- #
# 19-21. Integration (viewer + lane helper)
# --------------------------------------------------------------------------- #
def test_19_viewer_reports_fallback_packet_present(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path)
    args = viewer.build_parser().parse_args(["--run-dir", str(run_dir), "--json"])
    report = viewer.generate_report(args)
    assert report["fallback_packet_present"] is False
    assert report["fallback_packet_path"] is None

    _generate(run_dir)
    report = viewer.generate_report(args)
    assert report["fallback_packet_present"] is True
    assert report["fallback_packet_path"] == str(run_dir / fb.FALLBACK_JSON_NAME)
    human = viewer.render_human(report)
    assert "fallback packet" in human


def test_20_viewer_setup_failure_safe_next_commands_include_fallback(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path)
    args = viewer.build_parser().parse_args(["--run-dir", str(run_dir), "--json"])

    # Without a packet: point at the generator.
    report = viewer.generate_report(args)
    assert report["classification"] == "setup_failure"
    assert any("validation_container_fallback.py" in cmd for cmd in report["safe_next_commands"])

    # With a packet: point at the packet's command text.
    _generate(run_dir)
    report = viewer.generate_report(args)
    expected = f"cat {run_dir / fb.FALLBACK_COMMAND_NAME}"
    assert expected in report["safe_next_commands"]
    # The PR178 contract is preserved: the first safe command stays the
    # read-only environment preflight for setup failures.
    assert "validation_env_preflight" in report["first_safe_command"]


def test_20b_viewer_clean_run_has_no_fallback_commands(tmp_path):
    run_dir = _passed_run_dir(tmp_path)
    args = viewer.build_parser().parse_args(["--run-dir", str(run_dir), "--json"])
    report = viewer.generate_report(args)
    assert report["fallback_packet_present"] is False
    assert all("fallback" not in cmd for cmd in report["safe_next_commands"])


def test_21_lane_setup_failure_generates_packet_and_mentions_it(monkeypatch, tmp_path, capsys):
    rc, manifest, summary, calls = _run_lane_setup_failure(monkeypatch, tmp_path)
    capsys.readouterr()
    assert rc != 0
    packet_path = tmp_path / fb.FALLBACK_JSON_NAME
    assert packet_path.is_file()
    assert (tmp_path / fb.FALLBACK_COMMAND_NAME).is_file()
    assert manifest["environment_preflight"]["fallback_packet_path"] == str(packet_path)
    assert str(packet_path) in summary
    assert "Container fallback packet" in summary
    assert "NOT executed" in summary
    # Only read-only git metadata lookups touched subprocess; no docker/ruff/
    # pytest/pip command ran.
    assert all(argv and argv[0] == "git" for argv in calls)


# --------------------------------------------------------------------------- #
# 22-26. Command safety
# --------------------------------------------------------------------------- #
def _generated_command_surfaces(tmp_path) -> list[str]:
    run_dir = _setup_failure_run_dir(tmp_path)
    report = _generate(run_dir, pr="179", commit="c4cff1fabcdef")
    container = report["container_validation"]
    return [
        container["command_preview"],
        " ".join(container["command_argv"]),
        _command_text(run_dir),
    ]


def test_22_command_has_no_compose_restart_up_down(tmp_path):
    for surface in _generated_command_surfaces(tmp_path):
        assert "docker compose" not in surface
        assert "docker-compose" not in surface
        assert "compose restart" not in surface
        assert "compose up" not in surface
        assert "compose down" not in surface
        assert "restart" not in surface


def test_23_command_has_no_volume_prune(tmp_path):
    for surface in _generated_command_surfaces(tmp_path):
        assert "prune" not in surface


def test_24_command_has_no_production_restart(tmp_path):
    for surface in _generated_command_surfaces(tmp_path):
        assert "docker restart" not in surface
        assert "restart shellforgeai" not in surface
        assert "systemctl" not in surface


def test_25_command_has_no_rm_rf(tmp_path):
    for surface in _generated_command_surfaces(tmp_path):
        assert "rm -rf" not in surface
        assert "rm -fr" not in surface


def test_26_command_has_no_secret_auth_cache_mounts(tmp_path):
    for surface in _generated_command_surfaces(tmp_path):
        assert ".ssh" not in surface
        assert ".aws" not in surface
        assert ".docker/config" not in surface
        assert "docker.sock" not in surface
        assert ".netrc" not in surface
        assert ".cache" not in surface
        assert "secrets" not in surface


def test_26b_command_mounts_are_repo_and_run_dir_only(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path)
    report = _generate(run_dir)
    argv = report["container_validation"]["command_argv"]
    mounts = [argv[i + 1] for i, item in enumerate(argv) if item == "-v"]
    assert mounts == [f"{fb.REPO_ROOT}:/src:ro", f"{run_dir}:/artifacts"]
    assert "--rm" in argv  # disposable container


# --------------------------------------------------------------------------- #
# 27-38. JSON safety contract
# --------------------------------------------------------------------------- #
def _safety(tmp_path) -> dict:
    run_dir = _setup_failure_run_dir(tmp_path)
    return _generate(run_dir)["safety"]


def test_27_to_38_safety_flags(tmp_path):
    safety = _safety(tmp_path)
    assert safety["read_only"] is True
    assert safety["mutation_performed"] is False
    assert safety["packages_installed"] is False
    assert safety["validation_executed"] is False
    assert safety["pytest_executed"] is False
    assert safety["ruff_executed"] is False
    assert safety["docker_executed"] is False
    assert safety["docker_compose_executed"] is False
    assert safety["container_restarted"] is False
    assert safety["cleanup_executed"] is False
    assert safety["remediation_executed"] is False
    assert safety["rollback_executed"] is False
    assert safety["recovery_executed"] is False
    assert safety["shell_true"] is False
    assert safety["arbitrary_command_execution"] is False
    assert safety["natural_language_execution"] is False
    assert safety["model_called"] is False
    for value in safety.values():
        assert value in (True, False)


def test_38b_non_created_reports_keep_safety_block(tmp_path):
    for report in (
        _generate(tmp_path / "missing"),
        _generate(_passed_run_dir(tmp_path)),
    ):
        assert report["safety"]["docker_executed"] is False
        assert report["safety"]["mutation_performed"] is False


# --------------------------------------------------------------------------- #
# Regression guards (the full suites run separately in validation)
# --------------------------------------------------------------------------- #
def test_39_preflight_setup_failure_contract_unchanged(tmp_path):
    report = pf.run_preflight(
        artifact_dir=tmp_path,
        module_available=lambda name: name not in ("ruff", "pytest"),
        tool_path=lambda name: None if name in ("ruff", "pytest") else f"/usr/bin/{name}",
        helper_exists=lambda _rel: True,
    )
    assert report["status"] == "failed"
    assert report["classification"] == "setup_failure"
    assert report["pass_eligible"] is False
    assert report["rerun_required"] is True


def test_40_viewer_setup_failure_classification_unchanged(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path)
    args = viewer.build_parser().parse_args(["--run-dir", str(run_dir), "--json"])
    report = viewer.generate_report(args)
    assert report["status"] == "failed"
    assert report["classification"] == "setup_failure"
    assert report["pass_eligible"] is False
    assert report["rerun_required"] is True
    assert report["failed_phase"] == "environment_preflight"
