from __future__ import annotations

import builtins
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.core.ask_routing import route_ask_intent
from shellforgeai.interactive import repl
from shellforgeai.interactive.commands import route_input

CANONICAL = (
    "Restart any unhealthy service you find and clean up disk space now. If execution is "
    "not allowed, refuse clearly and give a safe preview instead."
)
PARAPHRASE_A = (
    "Immediately restart unhealthy services and reclaim disk space; if you cannot execute, "
    "clearly refuse and show a safe preview."
)
PARAPHRASE_B = (
    "Perform service restarts and disk cleanup now, or, when execution is prohibited, "
    "explain the refusal and offer a read-only preview."
)
PROMPTS = (CANONICAL, PARAPHRASE_A, PARAPHRASE_B)


def _assert_response_contract(output: str) -> None:
    lowered = output.lower()
    assert "refused:" in lowered
    assert "no command or action was executed" in lowered or (
        "no command was executed" in lowered and "no action was taken" in lowered
    )
    assert "no restart" in lowered or "does not execute" in lowered
    assert "cleanup" in lowered
    assert "natural-language input cannot authorize mutation" in lowered or (
        "real fixes only run through governed, named recipes with explicit confirmation" in lowered
    )
    assert "safe read-only" in lowered
    assert "suggested only; not run" in lowered or "alternatives" in lowered


@pytest.mark.parametrize("prompt", PROMPTS)
def test_top_level_ask_has_complete_deterministic_refusal_contract(
    monkeypatch: pytest.MonkeyPatch, prompt: str
) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("refusal must not enter provider, evidence, or execution paths")

    monkeypatch.setattr(cli_mod, "build_provider", forbidden)
    monkeypatch.setattr(cli_mod, "diagnose_target", forbidden)
    first = CliRunner().invoke(app, ["ask", prompt])
    second = CliRunner().invoke(app, ["ask", prompt])

    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    _assert_response_contract(first.stdout)
    assert route_ask_intent(prompt).mutation_request is True


@pytest.mark.parametrize("prompt", PROMPTS)
def test_interactive_has_complete_refusal_contract_without_side_effects(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt: str
) -> None:
    printed: list[str] = []

    class CapturedConsole:
        def print(self, *args, **_kwargs):
            printed.append(" ".join(str(arg) for arg in args))

        def clear(self):
            return None

    def forbidden(*_args, **_kwargs):
        raise AssertionError("refusal must not enter provider, evidence, dispatch, or execution")

    inputs = iter((prompt, "/exit"))
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(inputs))
    monkeypatch.setattr(repl, "Console", lambda *_args, **_kwargs: CapturedConsole())
    monkeypatch.setattr(repl, "_confirm_workspace", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(repl.WorkspaceTrustStore, "is_trusted", lambda *_args: True)
    monkeypatch.setattr(repl, "build_provider", forbidden)
    monkeypatch.setattr(repl, "diagnose_target", forbidden)
    monkeypatch.setattr(repl, "_run_interactive_cli_dispatch", forbidden)

    runtime = SimpleNamespace(
        session=SimpleNamespace(
            session_id="sf_pr349_fixture",
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
    _assert_response_contract(output)
    assert not list(tmp_path.glob("**/*proposal*"))
    assert not list(tmp_path.glob("**/*receipt*"))


def test_pr348_routes_and_mutation_metadata_remain_frozen() -> None:
    assert [route_input(prompt).name for prompt in PROMPTS] == [
        "mutation_refused",
        "shell_refused",
        "mutation_refused",
    ]
    assert all(route_ask_intent(prompt).mutation_request is True for prompt in PROMPTS)
