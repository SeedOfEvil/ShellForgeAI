"""PR382 shared natural-language command-execution suffix refusal."""

from __future__ import annotations

import builtins
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from shellforgeai import cli as cli_module
from shellforgeai.cli import app
from shellforgeai.core import ask_docker_grounding as docker_grounding_module
from shellforgeai.core import windows_operator_ux as windows_ux
from shellforgeai.interactive import repl
from shellforgeai.interactive.commands import route_input

WINDOWS_SUFFIX = "Which running Windows processes have the largest working set? Then run whoami."
DOCKER_SUFFIX = "Rank the observed Docker containers by attention, and then run docker ps."
LINUX_SUFFIX = "Assess this Linux host. Then run systemctl status sshd."
WINDOWS_ANALYTICAL = (
    "Which running Windows processes have the largest working set, "
    "and do any deserve attention?"
)


@pytest.mark.parametrize("prompt", (WINDOWS_SUFFIX, DOCKER_SUFFIX, LINUX_SUFFIX))
def test_command_execution_suffix_uses_shared_not_a_shell_route(prompt: str) -> None:
    routed = route_input(prompt)
    assert routed.name == "shell_refused"
    assert routed.args == prompt


def test_canonical_refusal_precedes_all_downstream_ask_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args, **_kwargs):
        pytest.fail("refusal must precede evidence, diagnostics, provider, and execution")

    monkeypatch.setattr(cli_module, "build_provider", forbidden)
    monkeypatch.setattr(cli_module, "diagnose_target", forbidden)
    monkeypatch.setattr(docker_grounding_module, "build_docker_evidence_context", forbidden)
    monkeypatch.setattr(
        "shellforgeai.core.windows_evidence_context.build_windows_evidence_context", forbidden
    )

    result = CliRunner().invoke(app, ["ask", WINDOWS_SUFFIX])

    assert result.exit_code == 0, result.stdout
    assert "ShellForgeAI ask is not a shell" in result.stdout
    assert "No command was executed" in result.stdout
    assert "No evidence was collected" in result.stdout
    assert "No action was taken" in result.stdout


@pytest.mark.parametrize(
    "prompt",
    (
        DOCKER_SUFFIX,
        LINUX_SUFFIX,
    ),
)
def test_cross_platform_refusal_precedes_evidence_and_model(
    monkeypatch: pytest.MonkeyPatch, prompt: str
) -> None:
    def forbidden(*_args, **_kwargs):
        pytest.fail("shared refusal must precede downstream analytical work")

    monkeypatch.setattr(cli_module, "build_provider", forbidden)
    monkeypatch.setattr(cli_module, "diagnose_target", forbidden)
    monkeypatch.setattr(docker_grounding_module, "build_docker_evidence_context", forbidden)
    monkeypatch.setattr(
        "shellforgeai.core.windows_evidence_context.build_windows_evidence_context", forbidden
    )

    result = CliRunner().invoke(app, ["ask", prompt])

    assert result.exit_code == 0, result.stdout
    assert "not a shell" in result.stdout
    assert "No command was executed" in result.stdout
    assert "No evidence was collected" in result.stdout


@pytest.mark.parametrize(
    "prompt",
    (
        "cat /etc/hostname",
        "Assess this host; whoami",
        "Assess this host | whoami",
        "Assess this host > result.txt",
        "Assess this host $(whoami)",
    ),
)
def test_existing_shell_syntax_remains_refused(prompt: str) -> None:
    assert route_input(prompt).name == "shell_refused"


@pytest.mark.parametrize(
    "prompt",
    (
        "What command would I run to inspect this?",
        "How would I run a read-only check?",
        "Explain how the service runs.",
        "Give me a runbook for investigating this.",
    ),
)
def test_command_help_and_run_prose_are_not_captured(prompt: str) -> None:
    assert route_input(prompt).name != "shell_refused"


@pytest.mark.parametrize(
    "prompt",
    (
        "Which running Windows processes have the largest working set? Restart the worst one.",
        "Which running Windows processes have the largest working set? Kill PID 123.",
    ),
)
def test_mutation_follow_on_retains_mutation_authority(prompt: str) -> None:
    assert route_input(prompt).name == "mutation_refused"


def test_pr381_windows_analysis_without_execution_suffix_is_unchanged() -> None:
    route = windows_ux.classify_windows_operator_intent(WINDOWS_ANALYTICAL, host_system="Windows")
    assert route is not None
    assert route.intent == windows_ux.WINDOWS_OPERATOR_INTENT_RUNNING_INVENTORY
    assert route_input(WINDOWS_ANALYTICAL).name != "shell_refused"


@pytest.mark.parametrize(
    "prompt",
    (
        "Rank the observed Docker containers by attention.",
        "Assess this Linux host.",
        WINDOWS_ANALYTICAL,
    ),
)
def test_analytical_prompts_without_execution_suffix_remain_allowed(prompt: str) -> None:
    assert route_input(prompt).name != "shell_refused"


def test_interactive_canonical_refuses_before_windows_routing_or_downstream_work(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    printed: list[str] = []

    class CapturedConsole:
        def print(self, *args, **_kwargs):
            printed.append(" ".join(str(arg) for arg in args))

        def clear(self):
            return None

        def status(self, *_args, **_kwargs):
            pytest.fail("refusal must not begin downstream work")

    def forbidden(*_args, **_kwargs):
        pytest.fail("refusal must precede Windows/evidence/model/execution routing")

    inputs = iter((WINDOWS_SUFFIX, "/exit"))
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(inputs))
    monkeypatch.setattr(repl, "Console", lambda *_args, **_kwargs: CapturedConsole())
    monkeypatch.setattr(repl, "_confirm_workspace", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(repl.WorkspaceTrustStore, "is_trusted", lambda *_args: True)
    monkeypatch.setattr(
        repl,
        "_windows_route",
        lambda text, **_kwargs: forbidden(text) if text == WINDOWS_SUFFIX else None,
    )
    monkeypatch.setattr(repl, "diagnose_target", forbidden)
    monkeypatch.setattr(repl, "build_windows_evidence_context", forbidden)
    monkeypatch.setattr(repl, "build_provider", forbidden)
    monkeypatch.setattr(repl, "_run_interactive_cli_dispatch", forbidden)

    runtime = SimpleNamespace(
        session=SimpleNamespace(
            session_id="sf_pr382_fixture",
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
    assert "not a shell" in output
    assert "No command was executed" in output
    assert "No action was taken" in output
