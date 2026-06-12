"""PR189 read-only recipe registry/preflight command-module extraction guardrails.

These tests prove the read-only ``recipes`` registry, list, inspect,
eligibility, and preflight (build/save/validate) handlers are wired from
``shellforgeai.commands.recipes`` while preserving command surfaces, strict
JSON behavior, target gating, owned preflight artifacts, and no-execution
safety fields. Governed execution (``recipes execute`` and receipt
recovery-execute) must remain in ``shellforgeai.cli`` unchanged.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.commands import recipes as recipes_commands

runner = CliRunner()

MODULE_PATH = Path("src/shellforgeai/commands/recipes.py")
CLI_PATH = Path("src/shellforgeai/cli.py")

SAFETY_FALSE_FLAGS = (
    "mutation_performed",
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
    "command_executed",
)


def _scene(labels: dict[str, str] | None = None) -> dict:
    return {
        "containers": [
            {
                "name": "sfai-pr189",
                "state": "running",
                "status": "Up",
                "labels": labels
                if labels is not None
                else {
                    "shellforgeai.disposable": "true",
                    "shellforgeai.allow_restart": "true",
                },
            },
            {"name": "unlabeled", "state": "running", "status": "Up", "labels": {}},
        ]
    }


def _patch_scene(monkeypatch, scene: dict | None = None) -> None:
    from shellforgeai.core import triage_ranking

    monkeypatch.setattr(triage_ranking, "collect_scene", lambda: scene or _scene())


def _forbid_execution(monkeypatch) -> None:
    """Fail loudly if any subprocess or model/provider call happens."""

    import subprocess as subprocess_mod

    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"read-only recipe command must not run subprocesses: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("read-only recipe command must not call a model provider")

    monkeypatch.setattr(subprocess_mod, "run", fail_run)
    monkeypatch.setattr(subprocess_mod, "Popen", fail_run)
    monkeypatch.setattr(subprocess_mod, "check_output", fail_run)
    monkeypatch.setattr(subprocess_mod, "call", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)


def _invoke(args: list[str], tmp_path: Path | None = None):
    env = {"SHELLFORGEAI_DATA_DIR": str(tmp_path)} if tmp_path else None
    return runner.invoke(app, args, env=env)


def _strict_json(result) -> dict:
    stripped = result.stdout.strip()
    assert stripped.startswith("{") and stripped.endswith("}"), result.stdout
    return json.loads(stripped)


def _assert_read_only_safety(payload: dict) -> None:
    safety_raw = payload.get("safety")
    safety: dict = safety_raw if isinstance(safety_raw, dict) else {}
    assert payload.get("read_only", safety.get("read_only")) is True
    for flag in SAFETY_FALSE_FLAGS:
        if flag in payload or flag in safety:
            assert payload.get(flag, safety.get(flag)) is False, flag


# ---------------------------------------------------------------------------
# Module split / registration
# ---------------------------------------------------------------------------


def test_recipes_module_exists_and_cli_wires_registration() -> None:
    assert MODULE_PATH.exists()
    module_source = MODULE_PATH.read_text(encoding="utf-8")
    cli_source = CLI_PATH.read_text(encoding="utf-8")
    assert (
        "def register(recipes_app: typer.Typer, recipes_preflight_app: typer.Typer)"
        in module_source
    )
    for marker in (
        'command("list")',
        'command("inspect")',
        'command("eligibility")',
        'command("validate")',
        "recipes_app.callback(invoke_without_command=True)",
        "recipes_preflight_app.callback(invoke_without_command=True)",
    ):
        assert marker in module_source
    assert "from shellforgeai.commands import recipes as recipes_commands" in cli_source
    assert "recipes_commands.register(recipes_app, recipes_preflight_app)" in cli_source


def test_cli_no_longer_owns_read_only_recipe_handler_bodies() -> None:
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    for moved in (
        "recipes_root",
        "recipes_list",
        "recipes_inspect",
        "recipes_eligibility",
        "recipes_preflight_root",
        "recipes_preflight_validate",
        "_render_recipe_groups_human",
        "_render_recipe_detail_human",
        "_render_recipe_eligibility_human",
        "_render_recipe_preflight_human",
        "_render_recipe_preflight_validate_human",
        "_collect_recipe_scene",
    ):
        assert moved not in function_names, moved


def test_governed_execution_handlers_remain_in_cli() -> None:
    """Execution boundary: execute/recovery handlers must stay out of recipes.py."""
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    for kept in (
        "recipes_execute",
        "recipes_receipt_recovery_execute",
        "recipes_receipt_recovery_status",
        "recipes_receipt_recovery_validate",
    ):
        assert kept in function_names, kept


def test_recipes_module_does_not_import_execution_surfaces() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    forbidden = (
        "execute_disposable_restart",
        "execute_receipt_recovery",
        "preview_receipt_rollback",
        "subprocess",
        "build_provider",
        "shell=True",
        "docker compose",
        "docker restart",
        "os.system",
    )
    for token in forbidden:
        assert token not in source, token


def test_help_surfaces_exit_zero_and_preserve_existing_options() -> None:
    root_help = runner.invoke(app, ["recipes", "--help"])
    assert root_help.exit_code == 0, root_help.output
    for token in ("list", "inspect", "eligibility", "preflight", "execute", "receipt", "--json"):
        assert token in root_help.stdout

    preflight_help = runner.invoke(app, ["recipes", "preflight", "--help"])
    assert preflight_help.exit_code == 0, preflight_help.output
    for token in ("--recipe", "--target", "--save", "--json", "validate"):
        assert token in preflight_help.stdout

    expectations = {
        ("recipes", "list", "--help"): ("--json",),
        ("recipes", "inspect", "--help"): ("--json", "RECIPE_ID"),
        ("recipes", "eligibility", "--help"): ("--recipe", "--target", "--json"),
        ("recipes", "preflight", "validate", "--help"): ("--json", "PREFLIGHT_REF"),
    }
    for argv, options in expectations.items():
        result = runner.invoke(app, list(argv))
        assert result.exit_code == 0, result.output
        for option in options:
            assert option in result.stdout, (argv, option)


# ---------------------------------------------------------------------------
# Recipe list / registry behavior
# ---------------------------------------------------------------------------


def test_recipes_list_human_output_still_works(monkeypatch) -> None:
    _forbid_execution(monkeypatch)
    for argv in (["recipes"], ["recipes", "list"]):
        result = _invoke(argv)
        assert result.exit_code == 0, result.output
        assert "ShellForgeAI V2 governed recipe registry" in result.stdout
        assert "docker.disposable_restart" in result.stdout
        assert "This command is read-only. No recipe was executed." in result.stdout


def test_recipes_list_json_strict_read_only_includes_disposable_restart(monkeypatch) -> None:
    _forbid_execution(monkeypatch)
    for argv in (["recipes", "--json"], ["recipes", "list", "--json"]):
        result = _invoke(argv)
        assert result.exit_code == 0, result.output
        payload = _strict_json(result)
        assert payload["mode"] == "v2_recipe_registry"
        _assert_read_only_safety(payload)
        recipe_ids = [r.get("recipe_id") for r in payload.get("recipes", [])]
        assert "docker.disposable_restart" in recipe_ids


def test_recipes_inspect_and_eligibility_preserved(monkeypatch) -> None:
    _forbid_execution(monkeypatch)
    _patch_scene(monkeypatch)

    inspect_json = _invoke(["recipes", "inspect", "docker.disposable_restart", "--json"])
    assert inspect_json.exit_code == 0, inspect_json.output
    payload = _strict_json(inspect_json)
    assert payload["recipe"]["recipe_id"] == "docker.disposable_restart"
    _assert_read_only_safety(payload)

    missing = _invoke(["recipes", "inspect", "no.such.recipe", "--json"])
    assert missing.exit_code == 1
    assert _strict_json(missing)["status"] == "not_found"

    eligibility = _invoke(
        [
            "recipes",
            "eligibility",
            "--recipe",
            "docker.disposable_restart",
            "--target",
            "sfai-pr189",
            "--json",
        ]
    )
    assert eligibility.exit_code == 0, eligibility.output
    payload = _strict_json(eligibility)
    assert payload["target"] == "sfai-pr189"
    _assert_read_only_safety(payload)


# ---------------------------------------------------------------------------
# Recipe preflight behavior
# ---------------------------------------------------------------------------


def test_disposable_restart_preflight_ready_json_unchanged(monkeypatch) -> None:
    _forbid_execution(monkeypatch)
    _patch_scene(monkeypatch)
    result = _invoke(
        [
            "recipes",
            "preflight",
            "--recipe",
            "docker.disposable_restart",
            "--target",
            "sfai-pr189",
            "--json",
        ]
    )
    assert result.exit_code == 0, result.output
    payload = _strict_json(result)
    assert payload["mode"] == "v2_recipe_preflight"
    assert payload["status"] == "preflight_ready"
    assert payload["action_preview"]["argv"] == ["docker", "restart", "sfai-pr189"]
    assert payload["command_executed"] is False
    assert payload["execution_available"] is False
    assert payload["first_safe_command"]
    _assert_read_only_safety(payload)


def test_disposable_restart_preflight_human_states_no_execution(monkeypatch) -> None:
    _forbid_execution(monkeypatch)
    _patch_scene(monkeypatch)
    result = _invoke(
        [
            "recipes",
            "preflight",
            "--recipe",
            "docker.disposable_restart",
            "--target",
            "sfai-pr189",
        ]
    )
    assert result.exit_code == 0, result.output
    assert "Recipe preflight: ready" in result.stdout
    assert "No command was executed." in result.stdout
    assert "No container was restarted." in result.stdout
    assert "First safe command:" in result.stdout


def test_production_target_preflight_remains_blocked(monkeypatch) -> None:
    _forbid_execution(monkeypatch)
    _patch_scene(monkeypatch)
    result = _invoke(
        [
            "recipes",
            "preflight",
            "--recipe",
            "docker.disposable_restart",
            "--target",
            "shellforgeai",
            "--json",
        ]
    )
    assert result.exit_code == 0, result.output
    payload = _strict_json(result)
    assert payload["status"] in {"blocked", "not_found"}
    assert any("production target refused" in blocker for blocker in payload["blockers"])
    _assert_read_only_safety(payload)


def test_missing_unknown_and_unlabeled_targets_remain_controlled(monkeypatch) -> None:
    _forbid_execution(monkeypatch)
    _patch_scene(monkeypatch)
    for target, expected in (
        ("does-not-exist", "target not found"),
        ("unlabeled", "missing required label"),
        ("*", "broad target refused"),
    ):
        result = _invoke(
            [
                "recipes",
                "preflight",
                "--recipe",
                "docker.disposable_restart",
                "--target",
                target,
                "--json",
            ]
        )
        assert result.exit_code == 0, result.output
        payload = _strict_json(result)
        assert payload["status"] in {"blocked", "not_found"}
        assert any(expected in blocker for blocker in payload["blockers"]), payload
        _assert_read_only_safety(payload)

    missing_args = _invoke(["recipes", "preflight", "--json"])
    assert missing_args.exit_code == 2
    payload = _strict_json(missing_args)
    assert payload["status"] == "error"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False


def test_ask_preflight_target_extraction_behavior_unchanged(monkeypatch) -> None:
    _forbid_execution(monkeypatch)
    _patch_scene(monkeypatch)
    result = _invoke(["ask", "preflight docker restart for sfai-pr189"])
    assert result.exit_code == 0, result.output
    assert "deterministic ask routing" in result.stdout
    assert "sfai-pr189" in result.stdout
    assert "No action was taken." in result.stdout

    no_target = _invoke(["ask", "preflight restart"])
    assert no_target.exit_code == 0, no_target.output
    assert "Specify the exact container target" in no_target.stdout


def test_preflight_save_packet_and_validate_behavior_unchanged(monkeypatch, tmp_path: Path) -> None:
    _forbid_execution(monkeypatch)
    _patch_scene(monkeypatch)
    saved = _invoke(
        [
            "recipes",
            "preflight",
            "--recipe",
            "docker.disposable_restart",
            "--target",
            "sfai-pr189",
            "--save",
            "--json",
        ],
        tmp_path,
    )
    assert saved.exit_code == 0, saved.output
    payload = _strict_json(saved)
    assert payload["artifact_written"] is True
    artifact_dir = Path(payload["preflight_path"])
    assert tmp_path in artifact_dir.parents
    assert (artifact_dir / "recipe-preflight.json").exists()
    assert (artifact_dir / "recipe-preflight.md").exists()
    assert (artifact_dir / "manifest.json").exists()
    _assert_read_only_safety(payload)

    validated = _invoke(
        ["recipes", "preflight", "validate", payload["preflight_id"], "--json"], tmp_path
    )
    assert validated.exit_code == 0, validated.output
    assert _strict_json(validated)["status"] == "ok"

    missing = _invoke(["recipes", "preflight", "validate", "does-not-exist", "--json"], tmp_path)
    assert missing.exit_code != 0
    assert _strict_json(missing)["status"] == "not_found"


# ---------------------------------------------------------------------------
# Execution boundary
# ---------------------------------------------------------------------------


def test_preflight_and_list_perform_no_execution_of_any_kind(monkeypatch, tmp_path: Path) -> None:
    """Preflight/list must not restart, compose, cleanup, remediate, roll back,
    recover, call a model, use shell=True, or execute any command."""
    _forbid_execution(monkeypatch)
    _patch_scene(monkeypatch)

    from shellforgeai.core import recipe_execution, recipe_receipt_recovery

    def fail_execute(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("read-only recipe command must not invoke governed execution")

    monkeypatch.setattr(recipe_execution, "execute_disposable_restart", fail_execute)
    monkeypatch.setattr(recipe_receipt_recovery, "execute_receipt_recovery", fail_execute)
    monkeypatch.setattr(cli_mod, "execute_disposable_restart", fail_execute)
    monkeypatch.setattr(cli_mod, "execute_receipt_recovery", fail_execute)

    for argv in (
        ["recipes", "list", "--json"],
        ["recipes", "--json"],
        [
            "recipes",
            "preflight",
            "--recipe",
            "docker.disposable_restart",
            "--target",
            "sfai-pr189",
            "--json",
        ],
        [
            "recipes",
            "preflight",
            "--recipe",
            "docker.disposable_restart",
            "--target",
            "sfai-pr189",
            "--save",
            "--json",
        ],
    ):
        result = _invoke(argv, tmp_path)
        assert result.exit_code == 0, (argv, result.output)
        _assert_read_only_safety(_strict_json(result))


def test_natural_language_execution_still_refused_after_split(monkeypatch) -> None:
    _forbid_execution(monkeypatch)
    _patch_scene(monkeypatch)
    result = _invoke(["ask", "execute the restart recipe"])
    assert result.exit_code == 0, result.output
    assert "Refused" in result.stdout
    assert "No container was restarted." in result.stdout


# ---------------------------------------------------------------------------
# Module/renderer reuse regression
# ---------------------------------------------------------------------------


def test_cli_safe_actions_and_ask_reuse_module_renderers(monkeypatch) -> None:
    """cli.py callers (safe-actions, ask routing) delegate to the moved
    renderers so there is exactly one implementation."""
    cli_source = CLI_PATH.read_text(encoding="utf-8")
    assert "recipes_commands._render_recipe_groups_human" in cli_source
    assert "recipes_commands._render_recipe_preflight_human" in cli_source
    assert "recipes_commands._collect_recipe_scene" in cli_source

    _forbid_execution(monkeypatch)
    _patch_scene(monkeypatch)
    rendered = recipes_commands._render_recipe_groups_human({"recipes": []})
    assert "read-only" in rendered

    safe_actions = _invoke(["safe-actions"])
    assert safe_actions.exit_code == 0, safe_actions.output
    assert "ShellForgeAI V2 governed recipe registry" in safe_actions.stdout
    assert "No action was taken." in safe_actions.stdout
