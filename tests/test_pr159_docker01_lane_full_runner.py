"""PR159 — Docker01 PR lane uses the xdist-aware full pytest runner."""

from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "sfai_docker01_pr_lane.py"
PYPROJECT = REPO_ROOT / "pyproject.toml"

if str(SCRIPT.parent) not in sys.path:
    sys.path.insert(0, str(SCRIPT.parent))


def load_module():
    spec = importlib.util.spec_from_file_location("pr159_docker01_lane", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


lane = load_module()


def displays(plan: dict) -> list[str]:
    return list(plan["recommended_commands"])


def test_01_full_validation_path_uses_runner_not_raw_pytest():
    plan = lane.plan_docker01_lane(changed_files=["Dockerfile"])
    commands = displays(plan)
    assert "python scripts/run_full_pytest.py" in commands
    assert "pytest -q" not in commands
    assert plan["_commands"][-1]["argv"] == [sys.executable, "scripts/run_full_pytest.py"]


def test_02_full_validation_preserves_runner_failure(capsys):
    plan = lane.plan_docker01_lane(changed_files=["Dockerfile"])
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        if argv == [sys.executable, "scripts/run_full_pytest.py"]:
            return types.SimpleNamespace(
                returncode=7,
                stdout="xdist: unavailable, falling back to serial pytest\n",
                stderr="duration reporting: --durations=25\n",
            )
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    assert lane.run_validation(plan, runner=fake_run) == 7
    assert calls[-1] == [sys.executable, "scripts/run_full_pytest.py"]
    out = capsys.readouterr().out
    assert "Full pytest runner: python scripts/run_full_pytest.py" in out
    assert "xdist: unavailable, falling back to serial pytest" in out


def test_03_full_validation_logs_runner_command_and_xdist_output(capsys):
    plan = lane.plan_docker01_lane(
        changed_files=["docs/cli.md"],
        full_validation=True,
        full_validation_reason="runtime safety boundary changed",
    )

    def fake_run(argv, **kwargs):
        if argv == [sys.executable, "scripts/run_full_pytest.py"]:
            return types.SimpleNamespace(
                returncode=0,
                stdout=(
                    "xdist: available, using -n auto --dist loadscope\n"
                    "duration_reporting=true (--durations=25)\n"
                ),
                stderr="",
            )
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    assert lane.run_validation(plan, runner=fake_run) == 0
    out = capsys.readouterr().out
    assert "Full pytest runner: python scripts/run_full_pytest.py" in out
    assert "xdist: available, using -n auto --dist loadscope" in out
    assert "duration_reporting=true (--durations=25)" in out


def test_04_dry_run_planning_output_shows_runner():
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--changed-files",
            "Dockerfile",
            "--dry-run",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Full pytest runner: python scripts/run_full_pytest.py" in result.stdout
    assert "  - python scripts/run_full_pytest.py" in result.stdout


def test_05_targeted_default_lane_does_not_run_full_runner():
    plan = lane.plan_docker01_lane(changed_files=["src/shellforgeai/core/ask_routing.py"])
    assert plan["selected_lane"] == "targeted_runtime"
    assert "python scripts/run_full_pytest.py" not in displays(plan)


def test_06_fast_docs_lane_does_not_run_full_runner():
    plan = lane.plan_docker01_lane(changed_files=["docs/cli.md"])
    assert plan["selected_lane"] == "fast"
    assert "python scripts/run_full_pytest.py" not in displays(plan)


def test_07_full_validation_flag_forces_full_lane():
    plan = lane.plan_docker01_lane(
        changed_files=["docs/cli.md"],
        full_validation=True,
        full_validation_reason="reviewer requested full validation",
    )
    assert plan["selected_lane"] == "full"
    assert plan["docker01_full_validation_forced"] is True
    assert "python scripts/run_full_pytest.py" in displays(plan)


def test_08_full_validation_reason_required_when_forcing_full():
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--changed-files",
            "docs/cli.md",
            "--full-validation",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "--full-validation-reason is required" in result.stderr


def test_09_no_cache_behavior_remains_explicit_and_validation_unchanged():
    plan = lane.plan_docker01_lane(changed_files=["Dockerfile"])
    rendered = lane.render_plan(plan, no_cache=True)
    assert "Docker build cache: disabled by --no-cache" in rendered
    assert "python scripts/run_full_pytest.py" in rendered
    assert "--no-cache" not in " ".join(displays(plan))


def test_10_guarded_compose_update_railings_are_present():
    railings = "\n".join(lane.GUARDED_COMPOSE_UPDATE_RAILINGS).lower()
    for expected in [
        "proxmox snapshot before mutation",
        "compose backup",
        "compose.yml.tmp",
        "marker checks",
        "docker compose config validation",
        "atomic replace",
        "cached build default",
        "no direct compose write",
        "no destructive cleanup",
        "no volume prune",
    ]:
        assert expected in railings


def test_11_helper_does_not_add_forbidden_runtime_actions():
    text = SCRIPT.read_text(encoding="utf-8").lower()
    forbidden_execute = ["cleanup execute", "remediation execute", "rollback execute"]
    for needle in forbidden_execute:
        assert text.count(needle) <= 1  # checklist-only forbidden-action tuple
    assert "docker volume prune" in text  # forbidden-action tuple only
    assert "docker compose up" not in text
    assert "docker compose down" not in text
    assert "docker restart" not in text


def test_12_helper_subprocess_calls_do_not_use_shell_true():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                    assert keyword.value.value is not True


def test_13_helper_executes_argv_lists_only():
    plan = lane.plan_docker01_lane(changed_files=["Dockerfile"])
    seen: list[list[str]] = []

    def fake_run(argv, **kwargs):
        assert isinstance(argv, list)
        assert kwargs.get("shell") is not True
        seen.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    assert lane.run_validation(plan, runner=fake_run) == 0
    assert [sys.executable, "scripts/run_full_pytest.py"] in seen


def test_14_pyproject_dev_deps_include_pytest_xdist():
    text = PYPROJECT.read_text(encoding="utf-8")
    assert "[project.optional-dependencies]" in text
    assert "pytest-xdist" in text


def test_15_rendered_full_plan_states_selection_reason_and_duration():
    plan = lane.plan_docker01_lane(
        changed_files=["docs/cli.md"],
        full_validation=True,
        full_validation_reason="runtime safety boundary changed",
    )
    rendered = lane.render_plan(plan)
    assert "Full validation selected: runtime safety boundary changed" in rendered
    assert "Full pytest runner: python scripts/run_full_pytest.py" in rendered
    assert "duration reporting: --durations=25" in rendered
