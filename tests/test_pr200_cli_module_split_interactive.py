"""PR200 — CLI command-module split: interactive launcher.

Behavior-preserving extraction checks: the top-level ``interactive`` launcher
moved from ``cli.py`` into ``src/shellforgeai/commands/interactive.py`` while the
command surface, ``--no-trust-cache``/``--yes-trust`` options, runtime hand-off
to ``shellforgeai.interactive.start_interactive``, deterministic read-only
routing, mutation refusal, and not-a-shell posture stay unchanged.

The launcher itself executes nothing. These tests never drive the real REPL
loop: they monkeypatch ``start_interactive`` to capture the hand-off, and they
exercise the unchanged deterministic router (``shellforgeai.interactive.commands
.route_input``) directly to prove read-only routing and mutation refusal are
unchanged. No model/provider call, Docker call, restart, cleanup, remediation,
rollback, or recovery execution can occur; no Docker daemon is required and no
real ``/data`` is touched.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.interactive.commands import route_input

runner = CliRunner()

MODULE_PATH = Path("src/shellforgeai/commands/interactive.py")
CLI_PATH = Path("src/shellforgeai/cli.py")


@pytest.fixture
def _capture_start_interactive(monkeypatch):
    """Capture the launcher hand-off so the real REPL loop never runs."""

    calls: list[dict[str, Any]] = []

    def _fake_start_interactive(runtime, **kwargs):  # noqa: ANN001, ANN003
        calls.append({"runtime": runtime, "kwargs": kwargs})

    monkeypatch.setattr("shellforgeai.interactive.start_interactive", _fake_start_interactive)
    return calls


# --------------------------------------------------------------------------
# Module split / registration
# --------------------------------------------------------------------------


def test_interactive_command_module_exists() -> None:
    assert MODULE_PATH.exists()
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert "def register(app: typer.Typer)" in source
    assert '@app.command("interactive")' in source
    assert "def interactive(" in source


def test_cli_wires_interactive_module_and_no_longer_owns_the_launcher_body() -> None:
    cli_source = CLI_PATH.read_text(encoding="utf-8")
    assert "from shellforgeai.commands import interactive as interactive_commands" in cli_source
    assert "interactive_commands.register(app)" in cli_source
    # The top-level launcher body is gone from cli.py (the root callback's
    # no-subcommand interactive *fallback* in ``main`` intentionally stays).
    assert '@app.command("interactive")' not in cli_source
    assert "def interactive(" not in cli_source


def test_interactive_help_exits_zero_and_preserves_options() -> None:
    result = runner.invoke(app, ["interactive", "--help"])
    assert result.exit_code == 0
    assert "--no-trust-cache" in result.stdout
    assert "--yes-trust" in result.stdout
    assert "trust" in result.stdout


def test_top_level_help_still_lists_interactive() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "interactive" in result.stdout


# --------------------------------------------------------------------------
# Launcher hand-off (no REPL loop runs)
# --------------------------------------------------------------------------


def test_interactive_launches_start_interactive_with_runtime(_capture_start_interactive) -> None:
    result = runner.invoke(app, ["interactive"])
    assert result.exit_code == 0
    assert len(_capture_start_interactive) == 1
    call = _capture_start_interactive[0]
    assert call["runtime"] is not None
    assert call["kwargs"] == {"no_trust_cache": False, "yes_trust": False}


def test_interactive_forwards_trust_flags(_capture_start_interactive) -> None:
    result = runner.invoke(app, ["interactive", "--no-trust-cache", "--yes-trust"])
    assert result.exit_code == 0
    assert len(_capture_start_interactive) == 1
    assert _capture_start_interactive[0]["kwargs"] == {
        "no_trust_cache": True,
        "yes_trust": True,
    }


def test_root_no_subcommand_fallback_still_launches_interactive(
    _capture_start_interactive,
) -> None:
    # The root callback's interactive fallback stays in cli.py and must keep
    # working after the top-level launcher extraction.
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert len(_capture_start_interactive) == 1


# --------------------------------------------------------------------------
# Deterministic read-only routing (unchanged; router was not moved)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "status",
        "ops report",
        "triage docker",
        "recipes receipt audit --json",
        "recipes receipt integrity --json",
        "recipes receipt explain --finding checksum_mismatch",
    ],
)
def test_interactive_read_only_commands_route_to_cli_dispatch(text: str) -> None:
    routed = route_input(text)
    assert routed.name == "cli_dispatch"


def test_interactive_exit_is_controlled() -> None:
    routed = route_input("exit")
    assert routed.name in {"/exit", "exit"}


def test_interactive_unknown_command_is_controlled() -> None:
    routed = route_input("zzzznotacommand")
    # Unknown input is never executed as a shell command; it is classified into
    # a controlled, non-mutating route (unknown/ask/diagnose), not cli_dispatch
    # of arbitrary argv.
    assert routed.name in {"unknown_command", "ask", "diagnose", "noop"}


# --------------------------------------------------------------------------
# Mutation refusal (unchanged; router was not moved)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Clean up docker and restart compose to fix it",
        "rollback now",
        "recover it again",
        "rerun receipt",
        "restart from receipt",
    ],
)
def test_interactive_mutation_phrases_are_refused(text: str) -> None:
    routed = route_input(text)
    assert routed.name in {"mutation_refused", "logs_mutation_refused"}


def test_interactive_is_not_a_shell() -> None:
    # Arbitrary shell-looking text is never turned into a shell command.
    for text in ("rm -rf /", "sudo reboot", "docker compose down"):
        routed = route_input(text)
        assert routed.name != "shell"
        assert routed.name in {
            "mutation_refused",
            "logs_mutation_refused",
            "unknown_command",
            "ask",
            "diagnose",
            "noop",
            "cli_dispatch",
        }


# --------------------------------------------------------------------------
# Safety — module source has no execution primitives
# --------------------------------------------------------------------------


def test_module_source_has_no_execution_primitives() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    docstring = ast.get_docstring(ast.parse(source), clean=False)
    assert docstring, "module must keep its safety-posture docstring"
    body = source.replace(docstring, "", 1)
    for forbidden in (
        "shell=True",
        "subprocess",
        "os.system",
        "Popen",
        "build_provider",
        "compose",
        "restart",
        "cleanup",
        "rollback",
        "recovery",
    ):
        assert forbidden not in body, f"interactive launcher must not reference {forbidden!r}"


def test_module_only_wires_and_delegates_to_existing_repl() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    # The launcher must delegate to the existing REPL entrypoint, not
    # re-implement it.
    assert "from shellforgeai.interactive import start_interactive" in source
    assert "start_interactive(" in source


def test_cli_module_still_imports_interactive_command_module() -> None:
    # Regression guard: the module is importable and wired without circular
    # import errors (importing cli imports the module at module load time).
    assert hasattr(cli_mod, "interactive_commands")
