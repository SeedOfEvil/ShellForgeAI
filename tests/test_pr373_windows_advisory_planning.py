from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.intent_nuance import MUTATION_REQUEST, PLAN_HELP, classify_intent_nuance
from shellforgeai.core.operator_solution import OperatorSolution
from shellforgeai.core.windows_advisory_planning import render_windows_advisory_plan
from shellforgeai.core.windows_operator_ux import (
    WINDOWS_OPERATOR_INTENT_ADVISORY_PLAN,
    WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL,
    WindowsOperatorRoute,
    classify_windows_operator_intent,
    windows_operator_safe_commands,
)
from shellforgeai.interactive.commands import route_input

ADVISORY_PROMPTS = (
    "How would you investigate this Windows host?",
    "What plan should I follow for these Windows service issues?",
    "How would you remediate this Windows problem?",
    "What would you check before restarting this Windows service?",
)
MUTATION_PROMPTS = ("Restart Spooler.", "Fix it now.", "Apply that plan.", "Kill the process.")
runner = CliRunner()


@pytest.mark.parametrize("prompt", ADVISORY_PROMPTS)
def test_plan_help_uses_shared_nuance_and_windows_route(prompt: str) -> None:
    assert classify_intent_nuance(prompt).category == PLAN_HELP
    route = classify_windows_operator_intent(prompt, host_system="Windows")
    assert route == WindowsOperatorRoute(WINDOWS_OPERATOR_INTENT_ADVISORY_PLAN, True, True)


@pytest.mark.parametrize("prompt", MUTATION_PROMPTS)
def test_mutation_precedence_remains_refusal(prompt: str) -> None:
    assert classify_intent_nuance(prompt).category == MUTATION_REQUEST
    assert route_input(prompt).name in {"ask", "mutation_refused"}
    route = classify_windows_operator_intent(prompt, host_system="Windows")
    if route is not None:
        assert route.intent == WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL
    assert route is None or route.intent != WINDOWS_OPERATOR_INTENT_ADVISORY_PLAN


def test_orchestrator_collects_builds_and_renders_once(monkeypatch: pytest.MonkeyPatch) -> None:
    import shellforgeai.core.windows_advisory_planning as module

    packet: dict[str, Any] = {"host": {"hostname": "win-host"}}
    calls = {"evidence": 0, "builder": 0, "renderer": 0}
    solution = object()

    def evidence() -> dict[str, Any]:
        calls["evidence"] += 1
        return packet

    def build(value: dict[str, Any], route: WindowsOperatorRoute, **kwargs: Any) -> Any:
        calls["builder"] += 1
        assert value is packet
        assert route.intent == WINDOWS_OPERATOR_INTENT_ADVISORY_PLAN
        assert kwargs["target"] == "win-host"
        return solution

    def render(value: OperatorSolution) -> str:
        calls["renderer"] += 1
        assert value is solution
        return "canonical\n"

    monkeypatch.setattr(module, "build_windows_evidence_context", evidence)
    monkeypatch.setattr(module, "build_windows_operator_solution_from_evidence", build)
    monkeypatch.setattr(module, "render_operator_solution_markdown", render)
    route = WindowsOperatorRoute(WINDOWS_OPERATOR_INTENT_ADVISORY_PLAN, True, True)
    assert render_windows_advisory_plan(route) == "canonical\n"
    assert calls == {"evidence": 1, "builder": 1, "renderer": 1}


def test_non_windows_explicit_request_collects_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    import shellforgeai.core.windows_advisory_planning as module

    monkeypatch.setattr(
        module,
        "build_windows_evidence_context",
        lambda: pytest.fail("Windows-local evidence must not be collected"),
    )
    route = classify_windows_operator_intent(ADVISORY_PROMPTS[0], host_system="Linux")
    assert route == WindowsOperatorRoute(WINDOWS_OPERATOR_INTENT_ADVISORY_PLAN, False, True)
    rendered = render_windows_advisory_plan(route)
    assert "non-Windows host" in rendered
    assert "No Windows probing was performed" in rendered
    assert "No command was executed. No action was taken" in rendered
    assert "docker" not in rendered.casefold()


def test_plan_commands_are_only_maintained_windows_read_only_commands() -> None:
    commands = windows_operator_safe_commands(WINDOWS_OPERATOR_INTENT_ADVISORY_PLAN)
    assert commands
    assert all(command.startswith("shellforgeai windows ") for command in commands)
    forbidden = ("systemctl", "journalctl", "docker", "compose", "restart", "powershell", "cmd.exe")
    assert not any(term in "\n".join(commands).casefold() for term in forbidden)


def test_ask_and_interactive_delegate_to_shared_orchestrator_before_generic_planning() -> None:
    ask = Path("src/shellforgeai/commands/ask.py").read_text(encoding="utf-8")
    repl = Path("src/shellforgeai/interactive/repl.py").read_text(encoding="utf-8")
    assert "render_windows_advisory_plan(windows_route)" in ask
    assert "render_windows_advisory_plan(shared_windows_route)" in repl
    assert ask.index("WINDOWS_OPERATOR_INTENT_ADVISORY_PLAN") < ask.index("_handle_v2_propose_ask")


def test_ask_plan_route_calls_shared_orchestrator_without_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import shellforgeai.commands.ask as ask_module
    import shellforgeai.core.windows_advisory_planning as planning

    calls = {"planning": 0}
    monkeypatch.setattr(ask_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(ask_module, "_cli", lambda: __import__("shellforgeai.cli", fromlist=["*"]))
    monkeypatch.setattr("shellforgeai.cli._ctx", lambda ctx: object())

    def render(route: WindowsOperatorRoute) -> str:
        calls["planning"] += 1
        assert route.intent == WINDOWS_OPERATOR_INTENT_ADVISORY_PLAN
        return "canonical Windows OperatorSolution\n"

    monkeypatch.setattr(planning, "render_windows_advisory_plan", render)
    result = runner.invoke(app, ["ask", ADVISORY_PROMPTS[0]])
    assert result.exit_code == 0
    assert result.stdout == "canonical Windows OperatorSolution\n"
    assert calls == {"planning": 1}
