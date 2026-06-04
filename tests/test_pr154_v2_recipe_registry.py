from __future__ import annotations

import io
import json
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.repl import (
    _interactive_mutation_refusal,
    _run_interactive_cli_dispatch,
)

runner = CliRunner()


def _invoke(args: list[str]):
    return runner.invoke(app, args)


def _json(args: list[str]) -> dict:
    result = _invoke(args)
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def _ids(payload: dict) -> set[str]:
    return {r["recipe_id"] for r in payload["recipes"]}


def _fake_scene(*, unlabeled: bool = False) -> dict:
    labels = (
        {}
        if unlabeled
        else {
            "shellforgeai.disposable": "true",
            "shellforgeai.allow_restart": "true",
        }
    )
    return {
        "containers": [
            {"name": "sfai-crashloop", "state": "running", "status": "Up", "labels": labels},
            {"name": "unlabeled", "state": "running", "status": "Up", "labels": {}},
        ]
    }


# Registry/list -----------------------------------------------------------------


def test_recipes_list_human_output_works() -> None:
    result = _invoke(["recipes", "list"])
    assert result.exit_code == 0
    assert "ShellForgeAI V2 governed recipe registry" in result.output
    assert "Available read-only" in result.output
    assert "This command is read-only. No recipe was executed." in result.output


def test_recipes_json_strict_and_contains_expected_registry() -> None:
    payload = _json(["recipes", "--json"])
    assert payload["mode"] == "v2_recipe_registry"
    ids = _ids(payload)
    assert "status.report" in ids
    assert "triage.docker" in ids
    assert "propose.next_action" in ids
    assert "apply.preview" in ids
    assert "verify.current_state" in ids
    assert "handoff.operator" in ids
    docker_recipe = next(
        r for r in payload["recipes"] if r["recipe_id"] == "docker.disposable_restart"
    )
    assert docker_recipe["status"] in {"disabled_until_execute_lane", "preview_only"}
    assert docker_recipe["executable"] is False
    cleanup_review = next(
        r for r in payload["recipes"] if r["recipe_id"] == "metadata.cleanup_review"
    )
    assert cleanup_review["status"] == "available_read_only"
    assert "shell.arbitrary" not in ids
    assert "production.restart" not in ids


# Inspect -----------------------------------------------------------------------


def test_recipes_inspect_status_report_works() -> None:
    result = _invoke(["recipes", "inspect", "status.report"])
    assert result.exit_code == 0
    assert "Recipe: status.report" in result.output
    assert "Mutation class: none" in result.output
    assert "No action was taken." in result.output


def test_recipes_inspect_docker_restart_shows_gates_and_disabled() -> None:
    payload = _json(["recipes", "inspect", "docker.disposable_restart", "--json"])
    recipe = payload["recipe"]
    assert recipe["status"] in {"disabled_until_execute_lane", "preview_only"}
    assert "explicit operator confirmation" in recipe["approval_gates"]
    assert recipe["receipt_required"] is True
    assert recipe["executable"] is False


def test_unknown_recipe_returns_controlled_not_found() -> None:
    result = _invoke(["recipes", "inspect", "nope.missing", "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["status"] == "not_found"
    assert payload["safe_next_commands"] == ["shellforgeai recipes list"]
    assert "Traceback" not in result.output


# Eligibility -------------------------------------------------------------------


def test_docker_disposable_restart_shellforgeai_blocked_production(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene", lambda: {"containers": []}
    )
    payload = _json(
        [
            "recipes",
            "eligibility",
            "--recipe",
            "docker.disposable_restart",
            "--target",
            "shellforgeai",
            "--json",
        ]
    )
    assert payload["eligibility"] in {"blocked", "disabled"}
    assert payload["eligible"] is False
    assert payload["target_metadata"]["production_target"] is True
    assert "production target refused" in payload["blockers"]
    assert payload["first_safe_command"] == "shellforgeai status --json"


def test_docker_disposable_restart_missing_target_blocked(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene", lambda: {"containers": []}
    )
    payload = _json(
        [
            "recipes",
            "eligibility",
            "--recipe",
            "docker.disposable_restart",
            "--target",
            "sfai-crashloop",
            "--json",
        ]
    )
    assert payload["eligible"] is False
    assert payload["target_metadata"]["target_found"] is False
    assert "target not found" in payload["blockers"]
    assert payload["first_safe_command"] == "shellforgeai triage --json"


def test_docker_disposable_restart_unlabeled_target_blocked(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene", lambda: _fake_scene(unlabeled=True)
    )
    payload = _json(
        [
            "recipes",
            "eligibility",
            "--recipe",
            "docker.disposable_restart",
            "--target",
            "sfai-crashloop",
            "--json",
        ]
    )
    assert payload["eligible"] is False
    assert any("missing required label" in blocker for blocker in payload["blockers"])
    assert "shellforgeai.disposable=true" in payload["target_metadata"]["required_labels_missing"]


def test_metadata_cleanup_review_eligible_read_only(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene", lambda: {"containers": []}
    )
    payload = _json(
        [
            "recipes",
            "eligibility",
            "--recipe",
            "metadata.cleanup_review",
            "--target",
            "metadata",
            "--json",
        ]
    )
    assert payload["eligibility"] == "eligible_read_only"
    assert payload["eligible"] is True
    assert payload["first_safe_command"] == "shellforgeai audit cleanup review"


def test_metadata_cleanup_execute_gated_disabled_not_first_execute_step(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene", lambda: {"containers": []}
    )
    payload = _json(
        [
            "recipes",
            "eligibility",
            "--recipe",
            "metadata.cleanup_execute",
            "--target",
            "metadata",
            "--json",
        ]
    )
    assert payload["eligibility"] == "disabled"
    assert payload["eligible"] is False
    assert payload["first_safe_command"] == "shellforgeai audit cleanup review"
    assert "execute" not in payload["first_safe_command"].lower()


def test_eligibility_json_safety_complete(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.core.triage_ranking.collect_scene", lambda: _fake_scene())
    payload = _json(
        [
            "recipes",
            "eligibility",
            "--recipe",
            "docker.disposable_restart",
            "--target",
            "sfai-crashloop",
            "--json",
        ]
    )
    assert payload["mode"] == "v2_recipe_eligibility"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
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


# Ask routing -------------------------------------------------------------------


def test_ask_safe_next_routes_deterministically_to_recipes() -> None:
    result = _invoke(["ask", "what can ShellForgeAI safely do next?"])
    assert result.exit_code == 0
    assert "governed recipe registry" in result.output.lower()
    assert "shellforgeai recipes" in result.output.lower()
    assert "No action was taken." in result.output


def test_ask_fixes_available_distinguishes_readonly_and_disabled() -> None:
    result = _invoke(["ask", "what fixes are available?"])
    assert result.exit_code == 0
    assert "Available read-only" in result.output
    assert "disabled" in result.output.lower()
    assert "No action was taken." in result.output


def test_ask_can_restart_safely_points_to_eligibility_and_preview() -> None:
    result = _invoke(["ask", "can you restart this safely?"])
    assert result.exit_code == 0
    assert "apply-preview" in result.output
    assert "Governed fixes are not executable yet" in result.output
    assert "No action was taken." in result.output


def test_ask_execute_recipe_refuses_mutation() -> None:
    result = _invoke(["ask", "execute the recipe"])
    assert result.exit_code == 0
    assert "Refused" in result.output
    assert "No recipe was executed" in result.output
    assert "No action was taken" in result.output


def test_ask_show_safe_actions_and_restart_compose_refuses_compose() -> None:
    result = _invoke(["ask", "show safe actions and restart compose"])
    assert result.exit_code == 0
    assert "recipe registry" in result.output.lower()
    assert "Refused mutation portion" in result.output
    assert "No action was taken." in result.output


# Interactive -------------------------------------------------------------------


def test_interactive_recipes_routes_to_cli_dispatch() -> None:
    routed = route_input("recipes")
    assert routed.name == "cli_dispatch"
    assert routed.argv == ("recipes",)


def test_interactive_recipes_json_dispatch_outputs_json() -> None:
    output = _run_interactive_cli_dispatch(Console(file=io.StringIO()), ("recipes", "--json"))
    payload = json.loads(output)
    assert payload["mode"] == "v2_recipe_registry"


def test_interactive_recipes_inspect_dispatch() -> None:
    routed = route_input("recipes inspect docker.disposable_restart")
    assert routed.name == "cli_dispatch"
    assert routed.argv == ("recipes", "inspect", "docker.disposable_restart")


def test_interactive_eligibility_dispatch() -> None:
    routed = route_input(
        "recipes eligibility --recipe docker.disposable_restart --target sfai-crashloop"
    )
    assert routed.name == "cli_dispatch"
    assert routed.argv == (
        "recipes",
        "eligibility",
        "--recipe",
        "docker.disposable_restart",
        "--target",
        "sfai-crashloop",
    )


def test_interactive_execute_recipe_refuses() -> None:
    routed = route_input("execute recipe")
    assert routed.name == "mutation_refused"
    refusal = _interactive_mutation_refusal("execute recipe")
    assert "No action was taken" in refusal
    assert "recipes list" in refusal


# Regression/safety --------------------------------------------------------------


def test_existing_v2_spine_commands_still_pass_minimal_json() -> None:
    for args in (
        ["status", "--json"],
        ["triage", "--json"],
        ["propose", "--json"],
        ["apply-preview", "--json"],
        ["verify", "--json"],
        ["handoff", "--json"],
    ):
        result = _invoke(list(args))
        assert result.exit_code == 0, (args, result.output)
        json.loads(result.output)


def test_mutation_refusal_still_blocks_restart_now() -> None:
    result = _invoke(["ask", "restart it now"])
    assert result.exit_code == 0
    assert "Refused" in result.output or "can't" in result.output.lower()
    assert "No action" in result.output


def test_pr154_registry_module_does_not_introduce_execution_surfaces() -> None:
    blob = Path("src/shellforgeai/core/recipe_registry.py").read_text(encoding="utf-8")
    assert "subprocess" not in blob
    assert "docker compose restart" not in blob.lower()
    assert "docker restart" not in blob.lower()
    assert "shell" + "=True" not in blob
    assert "shell" + " = True" not in blob
    assert "arbitrary command execution enabled" not in blob.lower()
