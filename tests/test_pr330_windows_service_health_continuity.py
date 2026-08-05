"""PR330 Windows service-health routing and interactive continuity."""

from __future__ import annotations

import json
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core import windows_operator_ux as ux
from shellforgeai.core.followup_grounding import (
    FollowupGroundingState,
    update_grounding_from_latest_context,
)
from shellforgeai.core.latest_context import render_latest_context_pending
from shellforgeai.interactive import repl
from shellforgeai.interactive.commands import route_input

SERVICES_COMMAND = "shellforgeai windows services --json --limit 25"
EXACT_PHRASE = "Show me the local service health and explain what matters to an operator on call"


def _payload() -> dict[str, Any]:
    return {
        "status": "ok",
        "platform": {"system": "windows"},
        "read_only": True,
        "mutation_performed": False,
        "services": {
            "total_count": 131,
            "state_counts": {"running": 51, "stopped": 80},
            "runtime_summary": {
                "running_with_process_id": 50,
                "pending_services": 0,
                "services_with_nonzero_win32_exit_code": 1,
                "services_with_nonzero_service_specific_exit_code": 0,
                "services_running_in_system_process": 2,
            },
            "items": [],
            "collection_limits": {"max_services": 25, "truncated": True},
        },
    }


@pytest.mark.parametrize(
    "phrase",
    (
        "local service health",
        "show me the local service health",
        "show me the local service health and explain what matters to an operator on call",
        EXACT_PHRASE + ".",
    ),
)
def test_bounded_local_service_health_phrases_classify(phrase: str) -> None:
    route = ux.classify_windows_interactive_intent(phrase, host_system="Windows")
    assert route is not None
    assert route.intent == ux.WINDOWS_OPERATOR_INTENT_SERVICES


@pytest.mark.parametrize(
    "phrase",
    (
        "customer service status",
        "customer service health",
        "service desk",
        "service account health",
        "software as a service",
        "SaaS",
        "Linux systemd service health",
        "Docker Compose service health",
        "This application prose mentions service incidentally",
    ),
)
def test_false_positive_and_foreign_scopes_are_not_windows_services(phrase: str) -> None:
    route = ux.classify_windows_interactive_intent(phrase, host_system="Windows")
    assert route is None or route.intent != ux.WINDOWS_OPERATOR_INTENT_SERVICES


@pytest.mark.parametrize(
    "phrase",
    (
        "restart the WinRM service now",
        "stop Windows services",
        "clean up services and restart them",
        "terminate a service process",
        "apply a service fix",
    ),
)
def test_mutation_refusal_retains_priority(phrase: str) -> None:
    route = ux.classify_windows_interactive_intent(phrase, host_system="Windows")
    assert route is not None
    assert route.intent == ux.WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL


def test_context_grounding_pending_and_summary_remain_services_first() -> None:
    ctx = repl._windows_services_latest_context(session_id="pr330", payload=_payload())
    grounding = update_grounding_from_latest_context(FollowupGroundingState(), ctx)
    state = repl.InteractiveSessionSummaryState(session_id="pr330")
    repl._record_latest_context_in_session_summary(state, ctx)

    assert grounding.last_target == "windows-local-read-only"
    assert grounding.last_safe_next_command == SERVICES_COMMAND
    assert "items" not in ctx.facts
    assert repl._latest_context_is_windows_services(ctx)
    assert repl._first_safe_summary_command(state) == SERVICES_COMMAND
    pending = render_latest_context_pending(ctx)
    assert "Diagnosis kind: windows_services" in pending
    assert "Total services: 131" in pending
    assert "Collection limit: max_services=25; truncated=true" in pending
    assert pending.index(SERVICES_COMMAND) < pending.index("shellforgeai windows events")


def test_exact_windows_session_preserves_service_context(monkeypatch: Any, tmp_path: Any) -> None:
    calls = {"services": 0, "diagnose": 0, "provider": 0, "dispatch": 0}

    def collect(*, max_services: int) -> dict[str, Any]:
        assert max_services == 25
        calls["services"] += 1
        return _payload()

    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(repl.platform, "system", lambda: "Windows")
    monkeypatch.setattr(repl, "windows_services_payload", collect)
    monkeypatch.setattr(repl, "diagnose_target", lambda *a, **k: calls.__setitem__("diagnose", 1))
    monkeypatch.setattr(repl, "build_provider", lambda *a, **k: calls.__setitem__("provider", 1))
    monkeypatch.setattr(
        repl,
        "_run_interactive_cli_dispatch",
        lambda *a, **k: calls.__setitem__("dispatch", 1),
    )
    result = CliRunner().invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input=(
            "show me the windows status\n"
            f"{EXACT_PHRASE}\n"
            "Restart the WinRM service now\n"
            "What should I check next?\n"
            "/pending\n/summary\n/exit\n"
        ),
    )
    out = result.stdout
    assert result.exception is None, out
    assert calls == {"services": 0, "diagnose": 0, "provider": 1, "dispatch": 0}
    assert "## Windows evidence" in out
    assert "Intent: windows_services" in out
    assert "Refused: natural-language mutation is not allowed." in out
    assert "Diagnosis kind: windows_services" in out
    assert "Using latest windows_services diagnosis context." in out
    assert "windows mutation request refused" in out
    assert out.rfind("First safe next command:") < out.rfind(SERVICES_COMMAND)
    assert (
        "shellforgeai remediation eligibility --target windows-local-read-only --explain" not in out
    )
    for forbidden in ("systemctl", "journalctl", "container-limited", "container-unknown"):
        assert forbidden not in out.lower()


def test_linux_routing_and_explicit_windows_guidance_are_preserved(monkeypatch: Any) -> None:
    assert ux.classify_windows_interactive_intent(EXACT_PHRASE, host_system="Linux") is None
    routed = route_input(EXACT_PHRASE)
    assert routed.name == "diagnose"
    assert routed.args == "services"

    explicit = ux.classify_windows_interactive_intent(
        "show me the Windows service health", host_system="Linux"
    )
    assert explicit is not None and explicit.host_is_windows is False
    rendered = ux.render_windows_operator_guidance(explicit)
    assert "No Windows probing was performed." in rendered
    assert SERVICES_COMMAND in rendered


def test_canonical_services_command_parser_is_unchanged(monkeypatch: Any) -> None:
    seen: dict[str, int] = {}

    def capture(**kwargs: int) -> dict[str, Any]:
        seen.update(kwargs)
        return _payload()

    monkeypatch.setattr("shellforgeai.commands.windows.windows_services_payload", capture)
    result = CliRunner().invoke(app, ["windows", "services", "--json", "--limit", "25"])
    assert result.exit_code == 0, result.stdout
    assert seen == {"max_services": 25}
    payload = json.loads(result.stdout)
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
