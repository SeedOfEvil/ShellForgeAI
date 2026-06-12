from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app

runner = CliRunner()


def _env(tmp_path: Path) -> dict[str, str]:
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


def _payload(profile: str, *, status: str = "ok") -> dict[str, Any]:
    warned = 1 if status == "warn" else 0
    failed = 1 if status == "failed" else 0
    passed = 7 if profile == "quick" else 14
    return {
        "schema_version": 1,
        "mode": "v1_readiness_check",
        "profile": profile,
        "status": status,
        "ci_status": "failed" if failed else ("failed_on_warn" if warned else "passed"),
        "summary": {
            "passed": passed,
            "failed": failed,
            "warned": warned,
            "skipped": 0,
        },
        "checks": [
            {
                "name": "command_surface_version",
                "status": "passed",
                "message": "version surface",
                "mutation": False,
            }
        ],
        "warnings": ["warning"] if warned else [],
        "skipped": [],
        "safety": {
            "read_only": True,
            "mutation_performed": False,
            "cleanup_executed": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "recovery_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "production_restarted": False,
            "natural_language_execution": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "model_called": False,
        },
        "next_safe_commands": ["shellforgeai doctor --json"],
    }


def _fake_readiness(_root_app: Any, profile: str = "standard") -> dict[str, Any]:
    if profile not in {"quick", "standard", "full"}:
        raise ValueError("invalid profile; valid profiles: quick, standard, full")
    return _payload(profile)


def test_v1_module_exists_and_cli_wires_registration() -> None:
    module_path = Path("src/shellforgeai/commands/v1.py")
    cli_path = Path("src/shellforgeai/cli.py")
    assert module_path.exists()
    module_source = module_path.read_text(encoding="utf-8")
    cli_source = cli_path.read_text(encoding="utf-8")

    assert "def register(v1_app: typer.Typer, root_app: typer.Typer)" in module_source
    assert '@v1_app.command("check")' in module_source
    assert "from shellforgeai.commands import v1 as v1_commands" in cli_source
    assert "v1_commands.register(v1_app, app)" in cli_source
    assert '@v1_app.command("check")' not in cli_source
    assert "def v1_check(" not in cli_source
    assert "run_v1_readiness_check(app, profile=profile)" not in cli_source


def test_v1_help_and_check_help_preserve_options() -> None:
    v1_help = runner.invoke(app, ["v1", "--help"])
    assert v1_help.exit_code == 0
    assert "check" in v1_help.stdout
    assert "packet" in v1_help.stdout

    check_help = runner.invoke(app, ["v1", "check", "--help"])
    assert check_help.exit_code == 0
    assert "--profile" in check_help.stdout
    assert "--json" in check_help.stdout
    assert "--fail-on-warn" in check_help.stdout


def test_quick_profile_json_and_human_are_preserved(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.core.v1_readiness.run_v1_readiness_check", _fake_readiness)
    result = runner.invoke(app, ["v1", "check", "--profile", "quick", "--json"], env=_env(tmp_path))
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["ci_status"] == "passed"
    assert payload["summary"] == {"passed": 7, "failed": 0, "warned": 0, "skipped": 0}
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False

    human = runner.invoke(app, ["v1", "check", "--profile", "quick"], env=_env(tmp_path))
    assert human.exit_code == 0
    assert "ShellForgeAI V1 readiness check" in human.stdout
    assert "Profile: quick" in human.stdout
    assert "Status: ok" in human.stdout


def test_standard_profile_json_and_human_are_preserved(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.core.v1_readiness.run_v1_readiness_check", _fake_readiness)
    result = runner.invoke(
        app, ["v1", "check", "--profile", "standard", "--json"], env=_env(tmp_path)
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["ci_status"] == "passed"
    assert payload["summary"] == {"passed": 14, "failed": 0, "warned": 0, "skipped": 0}
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False

    human = runner.invoke(app, ["v1", "check", "--profile", "standard"], env=_env(tmp_path))
    assert human.exit_code == 0
    assert "Profile: standard" in human.stdout
    assert "Status: ok" in human.stdout


def test_invalid_profile_is_controlled_without_traceback(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.core.v1_readiness.run_v1_readiness_check", _fake_readiness)
    result = runner.invoke(app, ["v1", "check", "--profile", "nope", "--json"], env=_env(tmp_path))
    assert result.exit_code == 1
    assert "Traceback" not in result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "failed"
    assert "valid profiles" in payload["error"]

    human = runner.invoke(app, ["v1", "check", "--profile", "nope"], env=_env(tmp_path))
    assert human.exit_code == 1
    assert "Traceback" not in human.stdout + human.stderr
    assert "Error: invalid profile" in human.stdout


def test_v1_check_module_preserves_safety_boundary(monkeypatch, tmp_path: Path) -> None:
    def fail_model(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("v1 check must not call the model/provider")

    monkeypatch.setattr(cli_mod, "build_provider", fail_model, raising=False)
    monkeypatch.setattr("shellforgeai.core.v1_readiness.run_v1_readiness_check", _fake_readiness)

    source = Path("src/shellforgeai/commands/v1.py").read_text(encoding="utf-8")
    forbidden_tokens = (
        "cleanup execute",
        "remediation execute",
        "rollback-execute",
        "recovery-execute",
        "docker restart",
        "docker compose restart",
        "docker compose up",
        "docker compose down",
        "production restart",
        "repair",
        "delete artifact",
        "shell=True",
        "subprocess.run",
        "build_provider(",
    )
    for token in forbidden_tokens:
        assert token not in source

    result = runner.invoke(app, ["v1", "check", "--profile", "quick", "--json"], env=_env(tmp_path))
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    safety = payload["safety"]
    for key in (
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
        "docker_compose_executed",
        "container_restarted",
        "production_restarted",
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_execution",
        "model_called",
    ):
        assert safety[key] is False
