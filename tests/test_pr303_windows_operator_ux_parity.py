from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from shellforgeai.core import windows_operator_ux as ux


def test_helper_is_pure_deterministic_and_commands_safe() -> None:
    assert ux.normalize_windows_operator_text(" Windows--STATUS!! ") == "windows status"
    r1 = ux.classify_windows_operator_intent("system status", host_system="Windows")
    r2 = ux.classify_windows_operator_intent("system status", host_system="windows")
    assert r1 == r2 == ux.WindowsOperatorRoute(ux.WINDOWS_OPERATOR_INTENT_STATUS, True, False)
    with pytest.raises(AttributeError):
        r1.intent = "changed"  # type: ignore[misc,union-attr]
    body1 = ux.render_windows_operator_guidance(r1)
    body2 = ux.render_windows_operator_guidance(r2)
    assert body1 == body2
    for intent in (
        ux.WINDOWS_OPERATOR_INTENT_STATUS,
        ux.WINDOWS_OPERATOR_INTENT_NEXT_CHECK,
        ux.WINDOWS_OPERATOR_INTENT_PERFORMANCE,
        ux.WINDOWS_OPERATOR_INTENT_STRONGEST_SIGNAL,
        ux.WINDOWS_OPERATOR_INTENT_HANDOFF,
    ):
        commands = ux.windows_operator_safe_commands(intent)
        assert commands[0] == ux.WINDOWS_STANDARD_EVIDENCE_COMMAND
        assert len(commands) == len(set(commands))
        assert all("sfai.cmd" not in c for c in commands)
        assert not any(
            any(term in c for term in ("cleanup", "restart", "kill", "terminate")) for c in commands
        )
        commands += ("x",)
        assert ux.windows_operator_safe_commands(intent)[-1] != "x"


@pytest.mark.parametrize(
    "text",
    [
        "show me the system status",
        "show system status",
        "system status",
        "what is happening on this machine",
        "is this system healthy",
        "machine health",
    ],
)
def test_status_windows_and_linux_boundary(text: str) -> None:
    assert (
        ux.classify_windows_operator_intent(text, host_system="Windows").intent
        == ux.WINDOWS_OPERATOR_INTENT_STATUS
    )
    assert ux.classify_windows_operator_intent(text, host_system="Linux") is None
    assert ux.classify_windows_operator_intent(f"Windows {text}", host_system="Linux") is not None
    assert (
        ux.classify_windows_operator_intent("docker container status", host_system="Linux") is None
    )


@pytest.mark.parametrize(
    "text",
    [
        "what should I check first",
        "what should we check first",
        "what should I check next",
        "what do I check first",
        "next check",
        "next checks",
        "what next",
    ],
)
def test_next_check_variants(text: str) -> None:
    assert (
        ux.classify_windows_operator_intent(text, host_system="Windows").intent
        == ux.WINDOWS_OPERATOR_INTENT_NEXT_CHECK
    )
    assert ux.classify_windows_operator_intent(text, host_system="Linux") is None
    assert (
        ux.classify_windows_operator_intent(f"{text} on Windows", host_system="Linux").intent
        == ux.WINDOWS_OPERATOR_INTENT_NEXT_CHECK
    )


@pytest.mark.parametrize(
    "text",
    ["system feels slow", "weird latency", "laggy", "first-pass diagnosis", "performance issue"],
)
def test_performance_variants(text: str) -> None:
    assert (
        ux.classify_windows_operator_intent(text, host_system="Windows").intent
        == ux.WINDOWS_OPERATOR_INTENT_PERFORMANCE
    )
    assert (
        ux.classify_windows_operator_intent("this slow cooker is nice", host_system="Linux") is None
    )


def test_strongest_handoff_and_mutation_priority() -> None:
    strongest = "Compare CPU memory disk and processes for the strongest signal"
    assert (
        ux.classify_windows_operator_intent(strongest, host_system="Windows").intent
        == ux.WINDOWS_OPERATOR_INTENT_STRONGEST_SIGNAL
    )
    assert ux.classify_windows_operator_intent("cpu memory disk", host_system="Windows") is None
    assert (
        ux.classify_windows_operator_intent("operator handoff", host_system="Windows").intent
        == ux.WINDOWS_OPERATOR_INTENT_HANDOFF
    )
    assert (
        ux.classify_windows_operator_intent("handoff for the current host", host_system="Linux")
        is None
    )
    assert (
        ux.classify_windows_operator_intent(
            "handoff for this Windows host", host_system="Linux"
        ).intent
        == ux.WINDOWS_OPERATOR_INTENT_HANDOFF
    )
    for text in (
        "Clean up Windows and restart services to fix it",
        "restart Windows service",
        "terminate Windows process",
        "remediate Windows",
        "rollback Windows change",
        "Windows system feels slow; restart services",
    ):
        assert (
            ux.classify_windows_operator_intent(text, host_system="Linux").intent
            == ux.WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL
        )
    assert ux.classify_windows_operator_intent("show service status", host_system="Windows") is None


def test_rendering_contract_windows_and_non_windows_and_refusal() -> None:
    win = ux.render_windows_operator_guidance(
        ux.WindowsOperatorRoute(ux.WINDOWS_OPERATOR_INTENT_NEXT_CHECK, True, False)
    )
    assert "Context: Windows local read-only." in win
    assert (
        "Start with this bounded read-only check:\n- "
        "shellforgeai windows evidence --profile standard --json"
    ) in win
    assert "No command was executed. No action was taken." in win
    assert (
        "No cleanup, restart, service control, process termination, remediation, "
        "rollback, or recovery was performed."
    ) in win
    non = ux.render_windows_operator_guidance(
        ux.WindowsOperatorRoute(ux.WINDOWS_OPERATOR_INTENT_STATUS, False, True)
    )
    assert "Context: Windows guidance requested from a non-Windows host." in non
    assert "No Windows probing was performed." in non
    assert "shellforgeai platform doctor --json" in non
    refusal = ux.render_windows_operator_guidance(
        ux.WindowsOperatorRoute(ux.WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL, True, True)
    )
    assert refusal.startswith(
        
            "Refused: natural-language mutation is not allowed.\n"
            "No command was executed. No action was taken."
        
    )
    assert "This request did not select, approve, prepare, or execute a recipe." in refusal


def test_ask_pure_route_precedes_runtime_and_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    from shellforgeai import cli

    runner = CliRunner()
    monkeypatch.setattr("platform.system", lambda: "Linux")
    monkeypatch.setattr(cli, "_ctx", lambda _ctx: pytest.fail("runtime context initialized"))
    result = runner.invoke(cli.app, ["ask", "What should I check first on Windows?"])
    assert result.exit_code == 0, result.stdout
    assert "No Windows probing was performed." in result.stdout
    assert "shellforgeai windows evidence --profile standard --json" in result.stdout
    assert "sfai.cmd" not in result.stdout


def test_ask_no_evidence_bypasses_pr303(monkeypatch: pytest.MonkeyPatch) -> None:
    from shellforgeai import cli

    runner = CliRunner()
    monkeypatch.setattr("platform.system", lambda: "Linux")
    result = runner.invoke(
        cli.app, ["ask", "--no-evidence", "What should I check first on Windows?"]
    )
    assert "Windows guidance requested from a non-Windows host" not in result.stdout


def test_source_guardrails_positive_control() -> None:
    helper = Path("src/shellforgeai/core/windows_operator_ux.py").read_text(encoding="utf-8")
    ask = Path("src/shellforgeai/commands/ask.py").read_text(encoding="utf-8")
    repl = Path("src/shellforgeai/interactive/repl.py").read_text(encoding="utf-8")
    forbidden_helper = (
        "subprocess",
        "os.system",
        "shell=True",
        "PowerShell",
        "WinRM",
        "WMI",
        "CIM",
        "build_provider",
        "auth_cache",
        "secret",
        "windows_evidence",
    )
    assert not any(term in helper for term in forbidden_helper)
    assert "classify_windows_operator_intent" in ask
    assert "classify_windows_operator_intent" in repl
    unsafe = helper + "\nsubprocess.run(['x'])\n"
    assert "subprocess" in unsafe
