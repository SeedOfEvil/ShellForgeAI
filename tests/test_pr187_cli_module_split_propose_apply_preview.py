"""PR187: propose / apply-preview command-module extraction guardrails.

Proves the behavior-preserving move of the read-only V2 ``propose`` and
``apply-preview`` handlers from ``cli.py`` into
``shellforgeai/commands/propose.py`` and
``shellforgeai/commands/apply_preview.py``: registration, help, JSON, brief,
safety posture, and no-execution guarantees stay unchanged.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app

runner = CliRunner()

MODULE_PATHS = {
    "propose": Path("src/shellforgeai/commands/propose.py"),
    "apply_preview": Path("src/shellforgeai/commands/apply_preview.py"),
}


def _safety() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "model_called": False,
    }


def _patch_triage(monkeypatch, tmp_path: Path, *, suspects: list | None = None) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    containers = []
    for suspect in suspects or []:
        containers.append(
            {
                "name": suspect["name"],
                "labels": suspect.get("labels", {}),
                "state": "running",
            }
        )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: {"containers": containers},
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene",
        lambda scene: {
            "status": "ok",
            "summary": {
                "containers_seen": len(containers),
                "suspects_ranked": len(suspects or []),
                "critical": 0,
                "high": len(suspects or []),
            },
            "suspects": list(suspects or []),
            "warnings": [],
            "safety": _safety(),
        },
    )


def _forbid_execution(monkeypatch) -> None:
    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"command must not run subprocesses: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("command must not call model provider")

    monkeypatch.setattr(cli_mod.subprocess, "run", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)


# ---------------------------------------------------------------------------
# Module split / registration
# ---------------------------------------------------------------------------


def test_propose_and_apply_preview_modules_exist_and_cli_wires_registration() -> None:
    cli_source = Path("src/shellforgeai/cli.py").read_text(encoding="utf-8")
    propose_source = MODULE_PATHS["propose"].read_text(encoding="utf-8")
    apply_source = MODULE_PATHS["apply_preview"].read_text(encoding="utf-8")
    assert "def register(app: typer.Typer)" in propose_source
    assert "def register(app: typer.Typer)" in apply_source
    assert "def propose(" in propose_source
    assert '@app.command("apply-preview")' in apply_source
    assert "from shellforgeai.commands import propose as propose_commands" in cli_source
    assert "from shellforgeai.commands import apply_preview as apply_preview_commands" in cli_source
    assert "propose_commands.register(app)" in cli_source
    assert "apply_preview_commands.register(app)" in cli_source


def test_cli_no_longer_owns_propose_or_apply_preview_handler_bodies() -> None:
    cli_source = Path("src/shellforgeai/cli.py").read_text(encoding="utf-8")
    assert "\ndef propose(" not in cli_source
    assert "\ndef apply_preview(" not in cli_source
    assert '@app.command("apply-preview")' not in cli_source


def test_help_surfaces_exit_zero_and_preserve_options() -> None:
    propose_help = runner.invoke(app, ["propose", "--help"])
    assert propose_help.exit_code == 0
    for option in ("--json", "--brief", "--target", "--from-triage"):
        assert option in propose_help.stdout
    apply_help = runner.invoke(app, ["apply-preview", "--help"])
    assert apply_help.exit_code == 0
    for option in ("--json", "--brief", "--target", "--from-propose", "--from-triage"):
        assert option in apply_help.stdout


# ---------------------------------------------------------------------------
# Propose behavior
# ---------------------------------------------------------------------------


def test_propose_no_suspects_human_json_brief_preserved(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    human = runner.invoke(app, ["propose"])
    assert human.exit_code == 0
    json_result = runner.invoke(app, ["propose", "--json"])
    assert json_result.exit_code == 0
    payload = json.loads(json_result.stdout)
    assert payload["mode"] == "v2_propose"
    assert payload["proposal_status"] == "no_action_needed"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False
    assert payload["first_safe_command"] == "shellforgeai status --json"
    brief = runner.invoke(app, ["propose", "--brief"])
    assert brief.exit_code == 0


def test_propose_with_suspect_keeps_safe_commands_and_safety_fields(monkeypatch, tmp_path) -> None:
    _patch_triage(
        monkeypatch,
        tmp_path,
        suspects=[{"name": "web-1", "labels": {}, "evidence": ["restarting"]}],
    )
    result = runner.invoke(app, ["propose", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["target"] == "web-1"
    assert payload["first_safe_command"]
    assert payload["plan_created"] is False
    assert "no remediation executed" in payload["not_executed"]
    assert payload["safety"]["model_called"] is False


def test_propose_unknown_target_is_controlled_blocked(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["propose", "--json", "--target", "ghost"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["proposal_status"] == "not_found"
    assert payload["status"] == "blocked"
    assert payload["first_safe_command"] == "shellforgeai triage"
    assert payload["safety"]["mutation_performed"] is False


# ---------------------------------------------------------------------------
# Apply-preview behavior
# ---------------------------------------------------------------------------


def test_apply_preview_human_json_brief_preserved(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    human = runner.invoke(app, ["apply-preview"])
    assert human.exit_code == 0
    assert "no action was taken" in human.stdout.lower()  # execution-boundary language
    json_result = runner.invoke(app, ["apply-preview", "--json"])
    assert json_result.exit_code == 0
    payload = json.loads(json_result.stdout)
    assert payload["mode"] == "v2_apply_preview"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False
    assert payload["first_safe_command"]
    assert payload["safe_next_commands"]
    brief = runner.invoke(app, ["apply-preview", "--brief"])
    assert brief.exit_code == 0


def test_apply_preview_states_no_action_executed(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["apply-preview"])
    assert result.exit_code == 0
    text = result.stdout.lower()
    assert "preview" in text
    assert "action was executed" in text  # "No ... action was executed." boundary language


def test_apply_preview_context_flags_preserved(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    for flags in (["--from-propose"], ["--from-triage"]):
        result = runner.invoke(app, ["apply-preview", "--json", *flags])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["mode"] == "v2_apply_preview"
        assert payload["mutation_performed"] is False


# ---------------------------------------------------------------------------
# Safety: no execution primitives, no model calls
# ---------------------------------------------------------------------------


def test_propose_and_apply_preview_never_execute_or_call_model(monkeypatch, tmp_path) -> None:
    _patch_triage(
        monkeypatch,
        tmp_path,
        suspects=[{"name": "web-1", "labels": {}, "evidence": ["restarting"]}],
    )
    _forbid_execution(monkeypatch)
    for argv in (
        ["propose", "--json"],
        ["propose", "--json", "--from-triage"],
        ["apply-preview", "--json"],
        ["apply-preview", "--json", "--target", "web-1"],
    ):
        result = runner.invoke(app, argv)
        assert result.exit_code == 0, argv
        payload = json.loads(result.stdout)
        safety = payload["safety"]
        assert safety["cleanup_executed"] is False
        assert safety["remediation_executed"] is False
        assert safety["rollback_executed"] is False
        assert safety["docker_compose_executed"] is False
        assert safety["container_restarted"] is False
        assert safety["shell_true"] is False
        assert safety["arbitrary_command_execution"] is False
        assert safety["natural_language_execution"] is False
        assert safety["model_called"] is False


def test_command_modules_have_no_forbidden_execution_primitives() -> None:
    for module_path in MODULE_PATHS.values():
        source = module_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    assert not (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    )
        for banned in (
            "import subprocess",
            "subprocess.",
            "os.system",
            "Popen",
            "shell=True",
            "build_provider",
            "docker compose",
            "docker restart",
        ):
            assert banned not in source, f"{module_path}: forbidden token {banned!r}"
