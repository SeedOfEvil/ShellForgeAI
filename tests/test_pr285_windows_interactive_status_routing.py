"""PR285 deterministic Windows interactive status routing tests."""

from __future__ import annotations

from pathlib import Path

from shellforgeai.core.latest_context import render_latest_context_pending
from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.repl import (
    _render_windows_read_only_intent,
    _windows_interactive_pending_context,
)

WINDOWS_PHRASES = [
    ("show me the windows status", "windows_status"),
    ("windows status", "windows_status"),
    ("show windows status", "windows_status"),
    ("show me windows doctor", "windows_doctor"),
    ("windows doctor", "windows_doctor"),
    ("show me windows evidence", "windows_evidence"),
    ("windows evidence", "windows_evidence"),
    ("show me windows processes", "windows_processes"),
    ("windows processes", "windows_processes"),
]


def test_windows_read_only_phrases_route_to_deterministic_intents() -> None:
    for phrase, intent in WINDOWS_PHRASES:
        routed = route_input(phrase)
        assert routed.name == "windows_read_only_intent"
        assert routed.args == intent


def test_windows_processes_limit_10_routes_with_limit() -> None:
    for phrase in ("show me windows processes limit 10", "windows processes limit 10"):
        routed = route_input(phrase)
        assert routed.name == "windows_read_only_intent"
        assert routed.args == "windows_processes"
        assert routed.argv == ("windows_processes", "10")


def test_windows_status_response_is_deterministic_read_only_guidance() -> None:
    rendered = _render_windows_read_only_intent(intent="windows_status", is_windows=True)
    assert "windows-local-read-only" in rendered
    assert "sfai.cmd windows status --json" in rendered
    assert "sfai.cmd windows doctor --json" in rendered
    assert "sfai.cmd windows evidence --json" in rendered
    assert "sfai.cmd windows processes --json --limit 10" in rendered
    assert "read-only" in rendered
    assert "No shell" in rendered or "no shell" in rendered
    assert "AGENTS.md" not in rendered
    assert "follow the AGENTS.md invariants" not in rendered


def test_pending_after_windows_status_prefers_windows_safe_next_commands() -> None:
    ctx = _windows_interactive_pending_context(
        session_id="test-session",
        intent="windows_status",
        source_command="sfai.cmd windows status --json",
    )
    rendered = render_latest_context_pending(ctx)
    assert "windows-local-read-only" in rendered
    assert "windows_status" in rendered
    assert "sfai.cmd windows status --json" in rendered
    assert "sfai.cmd windows doctor --json" in rendered
    assert "sfai.cmd windows evidence --json" in rendered
    assert "sfai.cmd windows processes --json --limit 10" in rendered
    stale = (
        "shellforgeai triage docker",
        "shellforgeai triage docker detail performance",
        "shellforgeai remediation eligibility --target performance --explain",
        "shellforgeai remediation self-test --profile standard",
    )
    assert all(command not in rendered for command in stale)


def test_non_windows_response_is_unsupported_without_windows_probe() -> None:
    rendered = _render_windows_read_only_intent(intent="windows_status", is_windows=False)
    assert "not Windows" in rendered
    assert "no Windows probing was performed" in rendered
    assert "shellforgeai platform doctor --json" in rendered
    assert "sfai.cmd windows status --json" in rendered
    assert "PowerShell" in rendered
    assert "WinRM" in rendered


def test_unknown_freeform_does_not_become_execution() -> None:
    routed = route_input("please tell me a story about windows status dashboards")
    assert routed.name not in {"windows_read_only_intent", "cli_dispatch"}
    assert "powershell" not in tuple(token.lower() for token in routed.argv)


def test_mutation_phrase_mixed_with_windows_context_is_refused() -> None:
    for phrase in (
        "clean up windows status",
        "restart windows processes",
        "fix windows evidence",
    ):
        routed = route_input(phrase)
        assert routed.name == "mutation_refused"


def test_source_safety_no_routing_shell_powershell_winrm_subprocess_or_exec_lanes() -> None:
    commands_source = Path("src/shellforgeai/interactive/commands.py").read_text()
    repl_source = Path("src/shellforgeai/interactive/repl.py").read_text()
    combined = commands_source + repl_source
    pr285_slice = "\n".join(
        line
        for line in combined.splitlines()
        if "windows_read_only" in line.lower()
        or "WINDOWS_INTERACTIVE" in line
        or "windows-local-read-only" in line
    )
    assert "shell=True" not in pr285_slice
    assert "subprocess" not in pr285_slice
    assert "PowerShell execution" not in pr285_slice
    assert "WinRM/remote execution" not in pr285_slice
    assert "cleanup execute" not in pr285_slice
    assert "remediation execute" not in pr285_slice
    assert "rollback" not in pr285_slice.lower()
    assert "recovery" not in pr285_slice.lower()
    assert "auth" not in pr285_slice.lower()
    assert "build_provider" not in pr285_slice
