"""PR158 — parallel full-validation runner and slow-test visibility."""

from __future__ import annotations

import ast
import importlib.util
import json
import subprocess
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = REPO_ROOT / "scripts" / "run_full_pytest.py"
VALIDATE_PATH = REPO_ROOT / "scripts" / "validate_pr.py"
PYPROJECT = REPO_ROOT / "pyproject.toml"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runner = load_module("pr158_run_full_pytest", RUNNER_PATH)
vp = load_module("pr158_validate_pr", VALIDATE_PATH)


def command_from_output(stdout: str) -> str:
    for line in stdout.splitlines():
        if line.startswith("Would run: "):
            return line.removeprefix("Would run: ")
    raise AssertionError(stdout)


def test_01_runner_dry_run_with_xdist_available_emits_parallel_command(monkeypatch, capsys):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)

    assert runner.main(["--dry-run"]) == 0

    out = capsys.readouterr().out
    command = command_from_output(out)
    assert "python -m pytest" in command
    assert " -q" in command
    assert "-n auto" in command
    assert "--dist loadscope" in command
    assert "--durations=25" in command


def test_02_runner_dry_run_without_xdist_emits_serial_fallback(monkeypatch, capsys):
    monkeypatch.setattr(runner, "detect_xdist", lambda: False)

    assert runner.main(["--dry-run"]) == 0

    out = capsys.readouterr().out
    command = command_from_output(out)
    assert "python -m pytest" in command
    assert " -q" in command
    assert "--durations=25" in command
    assert " -n " not in command
    assert "--dist" not in command
    assert "pytest-xdist not available; falling back to serial full pytest" in out


def test_03_no_xdist_forces_serial_even_when_xdist_available(monkeypatch, capsys):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)

    assert runner.main(["--dry-run", "--no-xdist"]) == 0

    out = capsys.readouterr().out
    command = command_from_output(out)
    assert " -n " not in command
    assert "--dist" not in command
    assert "--durations=25" in command
    assert "xdist disabled by --no-xdist" in out


def test_04_durations_option_changes_duration_reporting(monkeypatch, capsys):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)

    assert runner.main(["--dry-run", "--durations", "10"]) == 0

    command = command_from_output(capsys.readouterr().out)
    assert "--durations=10" in command
    assert "--durations=25" not in command


def test_05_dry_run_does_not_execute_pytest(monkeypatch):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)

    def boom(*args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("dry-run must not execute pytest")

    monkeypatch.setattr(runner.subprocess, "run", boom)
    assert runner.main(["--dry-run"]) == 0


def test_06_execution_mode_uses_subprocess_argv_list_with_shell_false(monkeypatch):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)
    calls: list[tuple[tuple, dict]] = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    assert runner.main([]) == 0
    assert calls
    args, kwargs = calls[0]
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
    assert kwargs.get("shell") is not True


def test_07_runner_json_dry_run_is_strict_parseable_json(monkeypatch, capsys):
    monkeypatch.setattr(runner, "detect_xdist", lambda: True)

    assert runner.main(["--dry-run", "--json"]) == 0

    data = json.loads(capsys.readouterr().out)
    assert data == {
        "mode": "full_pytest_runner",
        "xdist_available": True,
        "command": [
            "python",
            "-m",
            "pytest",
            "-q",
            "-n",
            "auto",
            "--dist",
            "loadscope",
            "--durations=25",
        ],
        "fallback": False,
        "durations": 25,
    }


def test_08_validate_pr_full_lane_recommends_full_runner():
    plan = vp.plan_validation(["Dockerfile"])
    assert plan["selected_lane"] == "full"
    assert "python scripts/run_full_pytest.py" in plan["recommended_commands"]
    assert plan["full_pytest_runner"] == "python scripts/run_full_pytest.py"


def test_09_validate_pr_fast_lane_does_not_recommend_full_runner():
    plan = vp.plan_validation(["docs/cli.md"])
    assert plan["selected_lane"] == "fast"
    assert "python scripts/run_full_pytest.py" not in plan["recommended_commands"]
    assert plan["full_pytest_runner"] is None


def test_10_validate_pr_targeted_lane_does_not_recommend_full_runner_by_default():
    plan = vp.plan_validation(["src/shellforgeai/core/ask_routing.py"])
    assert plan["selected_lane"] == "targeted_runtime"
    assert "python scripts/run_full_pytest.py" not in plan["recommended_commands"]
    assert plan["full_pytest_runner"] is None


def test_11_full_lane_helper_output_includes_duration_reporting():
    plan = vp.plan_validation(["Dockerfile"])
    rendered = vp.render_human(plan)
    assert plan["duration_reporting"] is True
    assert "duration_reporting=true" in rendered


def test_12_full_lane_helper_output_explains_xdist_use_and_fallback():
    plan = vp.plan_validation(["Dockerfile"])
    rendered = vp.render_human(plan)
    assert plan["xdist_used_if_available"] is True
    assert "xdist_used_if_available=true" in rendered
    assert "uses pytest-xdist when available and falls back to serial pytest" in rendered


def test_13_pyproject_declares_marker_foundation():
    text = PYPROJECT.read_text(encoding="utf-8")
    for marker in ["slow", "integration", "safety", "artifact", "interactive"]:
        assert f'"{marker}:' in text
    assert '"docker:' in text


def test_14_marker_definitions_do_not_alter_default_pytest_selection():
    text = PYPROJECT.read_text(encoding="utf-8")
    assert "-m not" not in text
    assert "--ignore" not in text
    assert "--deselect" not in text


def test_15_no_test_introduces_docker_requirement():
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = getattr(node.func, "attr", getattr(node.func, "id", ""))
            assert func not in {"from_env"}


def test_16_no_script_subprocess_call_uses_shell_true():
    for path in [RUNNER_PATH, VALIDATE_PATH]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                        assert keyword.value.value is not True, path


def test_17_no_script_calls_mutating_docker_or_runtime_paths():
    forbidden = [
        "docker compose",
        " compose restart",
        " compose up",
        " compose down",
        "restart",
        "prune",
        "cleanup execute",
        "remediation execute",
        "rollback execute",
    ]
    for path in [RUNNER_PATH]:
        text = path.read_text(encoding="utf-8").lower()
        for needle in forbidden:
            assert needle not in text


def test_validate_pr_cli_json_full_lane_includes_pr158_fields():
    result = subprocess.run(
        [sys.executable, str(VALIDATE_PATH), "--changed-files", "Dockerfile", "--json"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["selected_lane"] == "full"
    assert data["full_pytest_required"] is True
    assert data["full_pytest_runner"] == "python scripts/run_full_pytest.py"
    assert data["duration_reporting"] is True
    assert data["xdist_used_if_available"] is True
