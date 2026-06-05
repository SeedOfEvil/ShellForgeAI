"""PR156 — deterministic recipe-preflight ask target extraction.

PR155 added the read-only governed recipe preflight packet. Its live ask route
safely refused mutation but parsed the target of
``preflight docker restart for shellforgeai`` as the connector word ``for``
instead of ``shellforgeai``. Exact target identity is central to the governed
recipe safety model, so this PR fixes natural-language target extraction for the
common "for " / eligibility / gates phrasings.

These tests assert:

* correct exact-target extraction for the documented phrasings,
* production/broad/ambiguous targets stay blocked or request clarification,
* the connector word ``for`` is never returned or routed as a target,
* mixed and direct execution phrasings remain refused,
* the route stays strictly read-only (no restart/remediation/cleanup/rollback,
  no Docker/Compose mutation, no shell=True, no arbitrary execution).
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.ask_routing import extract_recipe_preflight_target
from shellforgeai.core.recipe_preflight import build_preflight_packet, recipe_preflight_safety

runner = CliRunner()


def _scene() -> dict:
    """Scene with a production container, an eligible disposable, and unlabeled."""
    return {
        "containers": [
            {"name": "shellforgeai", "state": "running", "status": "Up", "labels": {}},
            {
                "name": "sfai-test",
                "state": "running",
                "status": "Up",
                "labels": {
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


def _ask(prompt: str, monkeypatch, tmp_path: Path | None = None) -> str:
    _patch_scene(monkeypatch)
    env = {"SHELLFORGEAI_DATA_DIR": str(tmp_path)} if tmp_path else None
    result = runner.invoke(app, ["ask", prompt], env=env)
    assert result.exit_code == 0, result.output
    return result.output


# Phrases that would betray real mutation/execution leaking into the read-only
# recipe-preflight ask route. The route only ever previews argv as text.
_FORBIDDEN_EXECUTION = (
    "shell=true",
    "container restarted: true",
    "restarting container",
    "executing docker restart",
    "executed the restart",
    "mutation performed: true",
    "remediation executed",
    "rollback executed",
    "cleanup executed",
    "compose executed",
)


def _assert_read_only(output: str) -> None:
    low = output.lower()
    for phrase in _FORBIDDEN_EXECUTION:
        assert phrase not in low, f"unexpected execution phrase {phrase!r} in:\n{output}"
    assert "no action was taken" in low


# 1-8: correct exact-target extraction -----------------------------------------


def test_extract_preflight_docker_restart_for_production_target() -> None:
    assert (
        extract_recipe_preflight_target("preflight docker restart for shellforgeai")
        == "shellforgeai"
    )


def test_extract_preflight_docker_restart_for_named_target() -> None:
    assert (
        extract_recipe_preflight_target("preflight docker restart for sfai-crashloop")
        == "sfai-crashloop"
    )


def test_extract_check_if_you_could_restart_production_safely() -> None:
    assert (
        extract_recipe_preflight_target("check if you could restart shellforgeai safely")
        == "shellforgeai"
    )


def test_extract_check_if_you_could_restart_named_safely() -> None:
    assert (
        extract_recipe_preflight_target("check if you could restart sfai-crashloop safely")
        == "sfai-crashloop"
    )


def test_extract_is_production_eligible_for_disposable_restart() -> None:
    assert (
        extract_recipe_preflight_target("is shellforgeai eligible for disposable restart?")
        == "shellforgeai"
    )


def test_extract_is_named_eligible_for_disposable_restart() -> None:
    assert (
        extract_recipe_preflight_target("is sfai-crashloop eligible for disposable restart?")
        == "sfai-crashloop"
    )


def test_extract_preflight_restart_recipe_for_production() -> None:
    assert (
        extract_recipe_preflight_target("preflight restart recipe for shellforgeai")
        == "shellforgeai"
    )


def test_extract_what_gates_are_needed_to_restart_production() -> None:
    assert (
        extract_recipe_preflight_target("what gates are needed to restart shellforgeai?")
        == "shellforgeai"
    )


# 9-11: production target safety -----------------------------------------------


def test_ask_shellforgeai_blocked_as_production_target(monkeypatch) -> None:
    out = _ask("preflight docker restart for shellforgeai", monkeypatch)
    assert "deterministic ask routing" in out
    assert "Target: shellforgeai" in out
    assert "production target refused" in out
    assert "No container was restarted." in out
    _assert_read_only(out)


def test_ask_production_target_states_no_action_and_no_mutation_flags(monkeypatch) -> None:
    out = _ask("preflight docker restart for shellforgeai", monkeypatch)
    # No restart/remediation/cleanup/rollback flags flipped on the ask route.
    packet = build_preflight_packet("docker.disposable_restart", "shellforgeai", scene=_scene())
    safety = packet["safety"]
    assert safety["container_restarted"] is False
    assert safety["remediation_executed"] is False
    assert safety["cleanup_executed"] is False
    assert safety["rollback_executed"] is False
    assert packet["command_executed"] is False
    assert "No action was taken." in out


# 12-13: missing / unlabeled target --------------------------------------------


def test_ask_named_target_is_not_parsed_as_connector_for(monkeypatch) -> None:
    out = _ask("preflight docker restart for sfai-crashloop", monkeypatch)
    assert "Target: sfai-crashloop" in out
    assert "Target: for" not in out
    _assert_read_only(out)


def test_ask_missing_target_reports_not_found_or_blocked(monkeypatch) -> None:
    out = _ask("preflight docker restart for sfai-missing", monkeypatch)
    assert "Target: sfai-missing" in out
    low = out.lower()
    assert "not_found" in low or "target not found" in low or "blocked" in low
    _assert_read_only(out)


def test_ask_unlabeled_target_reports_missing_labels(monkeypatch) -> None:
    out = _ask("preflight docker restart for unlabeled", monkeypatch)
    assert "Target: unlabeled" in out
    assert "missing required label" in out
    _assert_read_only(out)


# 14-18: ambiguous / broad targets ---------------------------------------------


def test_ask_broad_all_is_blocked_as_broad(monkeypatch) -> None:
    out = _ask("preflight docker restart for all", monkeypatch)
    assert "Target: all" in out
    assert "broad target refused" in out
    _assert_read_only(out)


def test_ask_broad_star_is_blocked_as_broad(monkeypatch) -> None:
    out = _ask("preflight docker restart for *", monkeypatch)
    assert "Target: *" in out
    assert "broad target refused" in out
    _assert_read_only(out)


def test_ask_broad_everything_is_blocked_as_broad(monkeypatch) -> None:
    out = _ask("preflight docker restart for everything", monkeypatch)
    assert "Target: everything" in out
    assert "broad target refused" in out
    _assert_read_only(out)


def test_ask_pronoun_it_requests_target_clarification(monkeypatch) -> None:
    out = _ask("preflight docker restart for it", monkeypatch)
    assert "Specify the exact container target" in out
    assert "Target: it" not in out
    assert "Target: for" not in out
    _assert_read_only(out)


def test_target_is_never_parsed_as_connector_for() -> None:
    assert extract_recipe_preflight_target("preflight docker restart for it") == ""
    assert extract_recipe_preflight_target("preflight docker restart for") == ""
    for prompt in (
        "preflight docker restart for shellforgeai",
        "preflight restart recipe for sfai-crashloop",
        "is shellforgeai eligible for disposable restart?",
        "what gates are needed to restart sfai-crashloop?",
    ):
        assert extract_recipe_preflight_target(prompt) != "for"


# 19-21: mixed execution -------------------------------------------------------


def test_ask_mixed_preflight_then_execute_refuses_execution(monkeypatch) -> None:
    out = _ask("preflight docker restart for shellforgeai and then do it", monkeypatch)
    assert "Target: shellforgeai" in out
    assert "production target refused" in out
    assert "Refused mutation portion" in out
    assert "No container was restarted." in out
    assert "No action was taken." in out
    _assert_read_only(out)


# 22-23: direct mutation remains refused ---------------------------------------


def test_ask_direct_restart_now_refuses_mutation(monkeypatch) -> None:
    _patch_scene(monkeypatch)
    result = runner.invoke(app, ["ask", "restart shellforgeai now"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "Refused" in out
    assert "No action was taken" in out
    _assert_read_only(out)


def test_ask_execute_restart_recipe_refuses_mutation(monkeypatch) -> None:
    _patch_scene(monkeypatch)
    result = runner.invoke(app, ["ask", "execute the restart recipe for shellforgeai"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "Refused" in out
    assert "No recipe was executed" in out
    assert "No container was restarted." in out


# 24-31: safety assertions -----------------------------------------------------


def test_recipe_preflight_safety_ledger_is_strictly_read_only() -> None:
    safety = recipe_preflight_safety()
    assert safety["read_only"] is True
    for flag in (
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "docker_compose_executed",
        "container_restarted",
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_execution",
        "model_called",
    ):
        assert safety[flag] is False, flag


def test_preflight_packet_for_extracted_target_carries_no_mutation(monkeypatch) -> None:
    target = extract_recipe_preflight_target("preflight docker restart for shellforgeai")
    packet = build_preflight_packet("docker.disposable_restart", target, scene=_scene())
    assert packet["read_only"] is True
    assert packet["mutation_performed"] is False
    assert packet["command_executed"] is False
    assert packet["execution_available"] is False
    safety = packet["safety"]
    assert safety["container_restarted"] is False
    assert safety["docker_compose_executed"] is False
    assert safety["shell_true"] is False
    assert safety["arbitrary_command_execution"] is False
    assert safety["natural_language_execution"] is False
    assert safety["cleanup_executed"] is False
    assert safety["remediation_executed"] is False
    assert safety["rollback_executed"] is False


def test_ask_preflight_route_writes_no_execution_artifacts(monkeypatch, tmp_path) -> None:
    out = _ask("preflight docker restart for sfai-test", monkeypatch, tmp_path)
    assert "No action was taken." in out
    # The read-only ask route must not create preflight/mission/apply records.
    assert not (tmp_path / "recipe_preflights").exists()
    assert not (tmp_path / "missions").exists()
    assert not (tmp_path / "remediations").exists()


# 32-35: regression ------------------------------------------------------------


def test_regression_eligible_preflight_ask_still_routes_read_only(monkeypatch) -> None:
    out = _ask("preflight docker restart for sfai-test", monkeypatch)
    assert "deterministic ask routing" in out
    assert "No action was taken." in out
    _assert_read_only(out)


def test_regression_v2_spine_surfaces_remain_read_only(monkeypatch) -> None:
    _patch_scene(monkeypatch)
    for args in (
        ["recipes", "--json"],
        ["propose", "--json"],
        ["apply-preview", "--json"],
        ["verify", "--json"],
        ["handoff", "--json"],
    ):
        result = runner.invoke(app, args)
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload.get("read_only") is True
        assert payload.get("mutation_performed") is False
