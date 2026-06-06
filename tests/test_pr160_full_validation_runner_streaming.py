"""PR160 — full-validation live output and slow-test optimization guards."""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = REPO_ROOT / "scripts" / "run_full_pytest.py"
PR116_PATH = REPO_ROOT / "tests" / "test_pr116_v1_packet_history_compare.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("pr160_run_full_pytest", RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["pr160_run_full_pytest"] = module
    spec.loader.exec_module(module)
    return module


runner = load_runner()


def command_from_output(stdout: str) -> str:
    for line in stdout.splitlines():
        if line.startswith("Would run: "):
            return line.removeprefix("Would run: ")
    raise AssertionError(stdout)


def test_execution_mode_uses_subprocess_argv_list(monkeypatch):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)
    calls: list[tuple[tuple, dict]] = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    assert runner.main([]) == 0
    args, _kwargs = calls[0]
    assert isinstance(args[0], list)
    assert args[0] == [
        "python",
        "-m",
        "pytest",
        "-q",
        "-n",
        "auto",
        "--dist",
        "loadscope",
        "--durations=25",
    ]


def test_execution_mode_does_not_use_shell_true(monkeypatch):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)

    def fake_run(_argv, **kwargs):
        assert kwargs.get("shell") is not True
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    assert runner.main([]) == 0


def test_dry_run_with_xdist_available_includes_parallel_duration_command(monkeypatch, capsys):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)

    assert runner.main(["--dry-run"]) == 0

    command = command_from_output(capsys.readouterr().out)
    assert "python -m pytest" in command
    assert " -q" in command
    assert "-n auto" in command
    assert "--dist loadscope" in command
    assert "--durations=25" in command


def test_dry_run_without_xdist_includes_serial_duration_command(monkeypatch, capsys):
    monkeypatch.setattr(runner, "detect_xdist", lambda: False)

    assert runner.main(["--dry-run"]) == 0

    out = capsys.readouterr().out
    command = command_from_output(out)
    assert "python -m pytest" in command
    assert " -q" in command
    assert "--durations=25" in command
    assert " -n " not in command
    assert "--dist" not in command
    assert "falling back to serial full pytest" in out


def test_dry_run_json_emits_strict_json_only(monkeypatch, capsys):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)

    assert runner.main(["--dry-run", "--json"]) == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert captured.err == ""
    assert data["mode"] == "full_pytest_runner"
    assert data["command"] == [
        "python",
        "-m",
        "pytest",
        "-q",
        "-n",
        "auto",
        "--dist",
        "loadscope",
        "--durations=25",
    ]
    assert "Running full pytest" not in captured.out


def test_no_xdist_forces_serial_command(monkeypatch, capsys):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)

    assert runner.main(["--dry-run", "--no-xdist"]) == 0

    command = command_from_output(capsys.readouterr().out)
    assert "--durations=25" in command
    assert " -n " not in command
    assert "--dist" not in command


def test_durations_option_emits_requested_duration_count(monkeypatch, capsys):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)

    assert runner.main(["--dry-run", "--durations", "10"]) == 0

    command = command_from_output(capsys.readouterr().out)
    assert "--durations=10" in command
    assert "--durations=25" not in command


def test_execution_mode_streams_by_not_capturing_output(monkeypatch):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)

    def fake_run(_argv, **kwargs):
        assert "capture_output" not in kwargs
        assert "stdout" not in kwargs
        assert "stderr" not in kwargs
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    assert runner.main([]) == 0


def test_execution_mode_reports_command_and_elapsed_time(monkeypatch, capsys):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)
    ticks = iter([10.0, 12.5])
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(ticks))

    def fake_run(_argv, **_kwargs):
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    assert runner.main([]) == 0

    out = capsys.readouterr().out
    assert "Running full pytest with xdist: yes" in out
    assert "Command: python -m pytest -q -n auto --dist loadscope --durations=25" in out
    assert "Pytest output streams live below." in out
    assert "Full pytest finished with exit code 0 in 2.5s" in out


def test_runner_ast_contains_no_shell_true():
    tree = ast.parse(RUNNER_PATH.read_text(encoding="utf-8"), filename=str(RUNNER_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                    assert keyword.value.value is not True


def test_packet_compare_history_tests_keep_schema_checksum_safety_guards():
    text = PR116_PATH.read_text(encoding="utf-8")
    assert "SCHEMA_VERSION" in text
    assert "PACKET_MODE" in text
    assert "checksums" in text
    assert "_sha256_file" in text
    assert "_safety" in text
    assert "mutation_performed" in text
    assert "safety_drift" in text


def test_targeted_slow_tests_do_not_require_docker_or_real_data():
    combined = "\n".join(
        [
            PR116_PATH.read_text(encoding="utf-8"),
            (REPO_ROOT / "tests" / "test_pr111_v1_readiness_check.py").read_text(encoding="utf-8"),
        ]
    ).lower()
    assert "docker.from_env" not in combined
    assert "docker compose" not in combined
    assert " /data" not in combined
    assert "shellforgeai_data_dir" in combined
    assert "tmp_path" in combined


def test_runner_does_not_add_forbidden_mutation_language():
    text = RUNNER_PATH.read_text(encoding="utf-8").lower()
    forbidden = [
        "cleanup execute",
        "remediation execute",
        "rollback execute",
        "docker compose up",
        "docker compose down",
        "docker compose restart",
        "docker restart",
        "natural-language mutation",
        "arbitrary command execution",
    ]
    for needle in forbidden:
        assert needle not in text


def test_docker01_full_runner_invocation_does_not_capture_output():
    lane_path = REPO_ROOT / "scripts" / "sfai_docker01_pr_lane.py"
    text = lane_path.read_text(encoding="utf-8")
    full_branch = text.split('if command["kind"] == "pytest_full_runner":', 1)[1].split("else:", 1)[
        0
    ]
    assert "capture_output" not in full_branch
    assert "text=True" not in full_branch
