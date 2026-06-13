"""PR199 — CLI command-module split: remediation self-test.

Behavior-preserving extraction checks: ``remediation self-test`` registration
moved from ``cli.py`` into ``src/shellforgeai/commands/remediation.py`` while
the command surface, quick/standard/full profile behavior, JSON/human output,
skipped-by-default live disposable execute gate, and safety flags stay
unchanged. The tests run the CLI in-process via ``CliRunner`` with the
model/provider factory blocked and Docker restart/inspect hooks poisoned, so
no model call, Docker call, restart, cleanup, remediation, rollback, or
recovery execution can occur. No Docker daemon is required and no real
``/data`` is touched.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app

runner = CliRunner()

MODULE_PATH = Path("src/shellforgeai/commands/remediation.py")
CLI_PATH = Path("src/shellforgeai/cli.py")


def _env(tmp_path: Path) -> dict[str, str]:
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


@pytest.fixture(autouse=True)
def _no_execution_hooks(monkeypatch):
    """Fail loudly if the self-test ever touches model or Docker mutation paths."""

    def _no_model(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("remediation self-test must not call the model/provider")

    def _no_docker_restart(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("remediation self-test must not run a Docker restart by default")

    monkeypatch.setattr(cli_mod, "build_provider", _no_model, raising=False)
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.run_exact_docker_restart",
        _no_docker_restart,
    )


# --------------------------------------------------------------------------
# Module split / registration
# --------------------------------------------------------------------------


def test_remediation_command_module_exists() -> None:
    assert MODULE_PATH.exists()
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert "def register(remediation_app: typer.Typer, root_app: typer.Typer)" in source
    assert '@remediation_app.command("self-test")' in source
    assert "def remediation_self_test(" in source


def test_cli_wires_remediation_module_and_no_longer_owns_the_handler_body() -> None:
    cli_source = CLI_PATH.read_text(encoding="utf-8")
    assert "from shellforgeai.commands import remediation as remediation_commands" in cli_source
    assert "remediation_commands.register(remediation_app, app)" in cli_source
    assert '@remediation_app.command("self-test")' not in cli_source
    assert "def remediation_self_test(" not in cli_source
    assert "sfai-remediation-selftest-" not in cli_source
    assert "_live_disposable_restart_verified" not in cli_source


def test_remediation_group_help_exits_zero_and_lists_self_test() -> None:
    result = runner.invoke(app, ["remediation", "--help"])
    assert result.exit_code == 0
    for name in ("self-test", "eligibility", "plan", "preflight", "audit", "status", "receipt"):
        assert name in result.stdout


def test_remediation_self_test_help_preserves_options() -> None:
    result = runner.invoke(app, ["remediation", "self-test", "--help"])
    assert result.exit_code == 0
    assert "--profile" in result.stdout
    assert "--json" in result.stdout
    assert "--fail-on-warn" in result.stdout
    # The long opt-in flag renders truncated in 80-col help output.
    assert "--include-live-disposable-exec" in result.stdout
    assert "--target" in result.stdout
    assert "--confirm-live-disposable" in result.stdout


# --------------------------------------------------------------------------
# Self-test behavior (quick / standard / full)
# --------------------------------------------------------------------------


def _summary_shape_ok(payload: dict[str, Any]) -> None:
    summary = payload["summary"]
    assert set(summary) == {"passed", "failed", "warned", "skipped"}
    assert all(isinstance(v, int) for v in summary.values())
    assert summary["passed"] + summary["failed"] == len(payload["checks"])
    assert summary["warned"] == len(payload["warnings"])
    assert summary["skipped"] == len(payload["skipped"])


def test_quick_profile_json_works_and_preserves_summary_shape(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["remediation", "self-test", "--profile", "quick", "--json"], env=_env(tmp_path)
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["mode"] == "remediation_self_test"
    assert payload["profile"] == "quick"
    assert payload["status"] == "ok"
    assert payload["ci_status"] == "passed"
    _summary_shape_ok(payload)
    assert payload["summary"]["failed"] == 0
    assert payload["next_safe_commands"]


def test_standard_profile_json_works_and_preserves_summary_shape(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["remediation", "self-test", "--profile", "standard", "--json"], env=_env(tmp_path)
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["profile"] == "standard"
    _summary_shape_ok(payload)
    assert payload["summary"]["passed"] >= 2
    assert payload["summary"]["skipped"] >= 1
    assert "live docker-disposable execute skipped by default" in payload["skipped"]


def test_full_profile_json_works_and_preserves_summary_shape(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["remediation", "self-test", "--profile", "full", "--json", "--fail-on-warn"],
        env=_env(tmp_path),
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["profile"] == "full"
    assert payload["status"] == "ok"
    assert payload["ci_status"] == "passed"
    assert payload["warnings"] == []
    _summary_shape_ok(payload)
    check_names = {c["name"] for c in payload["checks"]}
    assert {"full_plan", "full_validate", "full_proof_execute", "full_audit"} <= check_names


def test_full_profile_preserves_skipped_live_disposable_execute_default(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["remediation", "self-test", "--profile", "full", "--json"], env=_env(tmp_path)
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "live docker-disposable execute skipped by default" in payload["skipped"]
    assert payload["safety"]["live_disposable_execute"] is False
    assert payload["safety"]["docker_disposable_executed"] is False
    assert payload["safety"]["proof_execution_performed"] is True
    assert payload["safety"]["temp_data_dir_used"] is True
    assert payload["live_disposable_proof"]["requested"] is False
    assert payload["live_disposable_proof"]["docker_restart_attempted"] is False


def test_invalid_profile_fails_cleanly(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["remediation", "self-test", "--profile", "nope"], env=_env(tmp_path)
    )
    assert result.exit_code != 0
    output = result.stdout + (result.stderr or "")
    assert "Traceback" not in output


def test_human_output_exits_cleanly(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["remediation", "self-test", "--profile", "quick"], env=_env(tmp_path)
    )
    assert result.exit_code == 0
    assert "Disposable remediation lane self-test" in result.stdout
    assert "Profile: quick" in result.stdout
    assert "skipped by default" in result.stdout
    assert "Next safe commands:" in result.stdout


def test_live_disposable_gates_are_preserved(tmp_path: Path) -> None:
    missing_target = runner.invoke(
        app,
        [
            "remediation",
            "self-test",
            "--profile",
            "full",
            "--include-live-disposable-execute",
            "--json",
        ],
        env=_env(tmp_path),
    )
    assert missing_target.exit_code != 0
    payload = json.loads(missing_target.stdout)
    assert payload["live_disposable_proof"]["requested"] is True
    assert payload["safety"]["mutation_performed"] is False

    missing_confirm = runner.invoke(
        app,
        [
            "remediation",
            "self-test",
            "--profile",
            "full",
            "--include-live-disposable-execute",
            "--target",
            "sfai-pr103-user-sim",
            "--json",
        ],
        env=_env(tmp_path),
    )
    assert missing_confirm.exit_code != 0
    payload = json.loads(missing_confirm.stdout)
    assert payload["live_disposable_proof"]["confirmed"] is False
    assert payload["safety"]["mutation_performed"] is False


# --------------------------------------------------------------------------
# Safety
# --------------------------------------------------------------------------


def test_module_source_has_no_execution_primitives() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    # The module docstring documents the safety posture in prose (it names the
    # forbidden primitives); scan only the executable source below it.
    docstring = ast.get_docstring(ast.parse(source), clean=False)
    assert docstring, "module must keep its safety-posture docstring"
    source = source.replace(docstring, "", 1)
    assert "shell=True" not in source
    assert "subprocess" not in source
    assert "os.system" not in source
    assert "Popen" not in source
    assert "build_provider" not in source


def test_all_profiles_run_with_model_and_docker_restart_blocked(tmp_path: Path) -> None:
    # The autouse fixture poisons cli.build_provider and the exact Docker
    # restart hook; every default profile must still pass, proving the
    # self-test makes no model call and performs no restart by default.
    for profile in ("quick", "standard", "full"):
        result = runner.invoke(
            app, ["remediation", "self-test", "--profile", profile, "--json"], env=_env(tmp_path)
        )
        assert result.exit_code == 0, result.stdout
        payload = json.loads(result.stdout)
        assert payload["status"] == "ok"


def test_json_safety_flags_remain_false_across_profiles(tmp_path: Path) -> None:
    for profile in ("quick", "standard", "full"):
        result = runner.invoke(
            app, ["remediation", "self-test", "--profile", profile, "--json"], env=_env(tmp_path)
        )
        assert result.exit_code == 0
        safety = json.loads(result.stdout)["safety"]
        assert safety["read_only"] is True
        for key in (
            "mutation_performed",
            "plan_created",
            "remediation_executed",
            "rollback_executed",
            "cleanup_executed",
            "proposal_created",
            "mission_created",
            "apply_executed",
            "docker_compose_executed",
            "container_restarted",
            "natural_language_execution",
            "shell_true",
            "arbitrary_command_execution",
            "live_disposable_execute",
        ):
            assert safety[key] is False, f"{profile}: safety[{key!r}] must stay false"


def test_full_profile_does_not_write_remediation_artifacts_to_data_dir(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    result = runner.invoke(
        app, ["remediation", "self-test", "--profile", "full", "--json"], env=_env(tmp_path)
    )
    assert result.exit_code == 0
    leaked = [p for p in data_dir.rglob("*") if "remediation" in p.name.lower()]
    assert leaked == [], "full profile must keep lifecycle artifacts in its temp data dir"
