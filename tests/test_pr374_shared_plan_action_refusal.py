from __future__ import annotations

import builtins
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.intent_nuance import (
    MUTATION_REQUEST,
    PLAN_HELP,
    classify_intent_nuance,
)
from shellforgeai.interactive import repl
from shellforgeai.interactive.commands import route_input

PURE_ADVISORY = (
    "What would you check before restarting this service?",
    "How would you remediate this problem?",
    "What plan should I follow before restarting this container?",
    "What command would restart this?",
)

MIXED_ACTION = (
    "What plan should I follow for this Docker service? Restart it now.",
    "How would you investigate this Linux host? Apply the fix.",
    "What would you check before restarting this container? Then restart it.",
    "How would you remediate this problem? Go ahead and apply it.",
)


@pytest.mark.parametrize("prompt", PURE_ADVISORY)
def test_shared_classifier_preserves_pure_plan_help(prompt: str) -> None:
    assert classify_intent_nuance(prompt).category == PLAN_HELP


@pytest.mark.parametrize("prompt", MIXED_ACTION)
def test_shared_classifier_and_router_refuse_distinct_action(prompt: str) -> None:
    assert classify_intent_nuance(prompt).category == MUTATION_REQUEST
    assert route_input(prompt).name == "mutation_refused"


@pytest.mark.parametrize("prompt", MIXED_ACTION[:2])
def test_ask_refuses_before_advisory_operational_or_model_routes(
    monkeypatch: pytest.MonkeyPatch, prompt: str
) -> None:
    import shellforgeai.cli as cli_module
    import shellforgeai.commands.ask as ask_module
    import shellforgeai.core.windows_advisory_planning as windows_planning

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("advisory, proposal, diagnosis, evidence, or model route was entered")

    monkeypatch.setattr(ask_module, "_cli", lambda: cli_module)
    monkeypatch.setattr(cli_module, "_handle_v2_propose_ask", forbidden)
    monkeypatch.setattr(cli_module, "_handle_broad_triage_ask", forbidden)
    monkeypatch.setattr(cli_module, "diagnose_target", forbidden)
    monkeypatch.setattr(cli_module, "build_provider", forbidden)
    monkeypatch.setattr(windows_planning, "render_windows_advisory_plan", forbidden)
    result = CliRunner().invoke(app, ["ask", prompt])
    assert result.exit_code == 0
    assert "Refused: natural-language mutation is not allowed." in result.stdout
    assert "Plan-only command:" not in result.stdout


def test_pure_generic_plan_help_still_renders_advisory_guidance() -> None:
    result = CliRunner().invoke(app, ["ask", PURE_ADVISORY[0]])
    assert result.exit_code == 0
    assert "Plan-only command:" in result.stdout
    assert "Refused: natural-language mutation is not allowed." not in result.stdout


def test_interactive_mixed_action_refuses_before_plan_diagnosis_or_model(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    printed: list[str] = []

    class CapturedConsole:
        def print(self, *args: Any, **_kwargs: Any) -> None:
            printed.append(" ".join(str(arg) for arg in args))

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("plan renderer, diagnosis, provider, or execution route was entered")

    inputs = iter((MIXED_ACTION[1], "/exit"))
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(inputs))
    monkeypatch.setattr(repl, "Console", lambda *_args, **_kwargs: CapturedConsole())
    monkeypatch.setattr(repl, "_confirm_workspace", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(repl.WorkspaceTrustStore, "is_trusted", lambda *_args: True)
    monkeypatch.setattr(repl, "render_intent_nuance", forbidden)
    monkeypatch.setattr(repl, "diagnose_target", forbidden)
    monkeypatch.setattr(repl, "build_provider", forbidden)
    monkeypatch.setattr(repl, "_run_interactive_cli_dispatch", forbidden)
    runtime = SimpleNamespace(
        session=SimpleNamespace(
            session_id="sf_pr374_mixed",
            data_dir=tmp_path,
            artifact_dir=tmp_path / "artifacts",
            mode="inspect",
        ),
        profile=SimpleNamespace(name="standard", online_allowed=False, allow_shell_raw=False),
        settings=SimpleNamespace(
            model=SimpleNamespace(provider="forbidden", model="forbidden", timeout_seconds=1)
        ),
    )

    repl.start_interactive(runtime, no_trust_cache=True)

    output = "\n".join(printed)
    assert "Refused: natural-language mutation is not allowed." in output
    assert "Plan-only command:" not in output
