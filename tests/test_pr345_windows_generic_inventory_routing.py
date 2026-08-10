from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core import windows_operator_ux as ux
from shellforgeai.interactive import repl

CANONICAL = (
    "Summarize what is running on this system using concrete evidence. Separate processes, "
    "services, and containers when the evidence supports them, and state any collection limits."
)


@pytest.mark.parametrize(
    "text",
    [
        CANONICAL,
        "What is running on this system?",
        "Give me an evidence-backed inventory of what is running.",
        "Show the running processes and services on this host.",
        "What processes, services, and containers can you actually see?",
        "Inventory the active components on this machine and tell me what you cannot observe.",
        "Summarize what is running on this Windows host using observed evidence.",
    ],
)
def test_shared_classifier_recognizes_bounded_inventory_family(text: str) -> None:
    route = ux.classify_windows_operator_intent(text, host_system="Windows")
    assert route is not None
    assert route.intent == ux.WINDOWS_OPERATOR_INTENT_RUNNING_INVENTORY
    if "windows" not in text.casefold():
        assert ux.classify_windows_operator_intent(text, host_system="Linux") is None


@pytest.mark.parametrize(
    "text",
    [
        "What Docker containers are running?",
        "Summarize the Docker services on this host.",
        "What is systemd running?",
        "Show Linux services.",
        "What is running in Compose?",
    ],
)
def test_explicit_non_windows_scope_is_not_stolen(text: str) -> None:
    assert ux.classify_windows_operator_intent(text, host_system="Windows") is None


def test_specialized_and_safety_routes_keep_precedence() -> None:
    assert (
        ux.classify_windows_interactive_intent(
            "Show running Windows services.", host_system="Windows"
        ).intent
        == ux.WINDOWS_OPERATOR_INTENT_SERVICES
    )
    assert (
        ux.classify_windows_operator_intent("System feels sluggish.", host_system="Windows").intent
        == ux.WINDOWS_OPERATOR_INTENT_PERFORMANCE
    )
    assert (
        ux.classify_windows_operator_intent(
            "Summarize what is running and restart anything unhealthy.", host_system="Windows"
        ).intent
        == ux.WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL
    )


def test_ask_inventory_uses_one_native_packet_and_never_linux_diagnose(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    calls: list[str] = []
    packet = {
        "platform": "windows",
        "visibility": "windows-local-read-only",
        "read_only": True,
        "mutation_performed": False,
        "host": {"hostname": "WIN-TEST"},
        "platform_detail": {"release": "2025"},
        "memory": {"available": False},
        "disk": {"available": False},
        "processes": {
            "available": True,
            "total_count": 120,
            "returned_count": 10,
            "limit": 10,
            "truncated": True,
            "items": [{"pid": 4, "name": "System", "thread_count": 100}],
        },
        "services": {
            "available": True,
            "total_count": 80,
            "returned_count": 25,
            "limit": 25,
            "truncated": True,
            "running_count": 55,
            "stopped_count": 25,
            "state_counts": {"running": 55, "stopped": 25},
            "items": [{"name": "EventLog", "state": "running"}],
        },
        "events": {"available": False},
        "network": {"available": False},
        "volumes": {"available": False},
        "limitations": [],
        "evidence_gaps": [],
        "safe_next_commands": [],
    }

    def build_packet() -> dict[str, Any]:
        calls.append("evidence")
        return packet

    class Provider:
        def complete(self, request):
            calls.append("model")
            assert "processes total=120 returned=10" in request.prompt
            assert '"limit": 10' in request.prompt
            assert '"truncated": true' in request.prompt
            assert "services total=80 running=55 stopped=25" in request.prompt
            assert '"limit": 25' in request.prompt
            assert "Container inventory is not collected" in request.prompt
            return type(
                "Response",
                (),
                {
                    "ok": True,
                    "text": "Native Windows inventory is bounded and read-only.",
                    "provider": "fake",
                    "model": "fake",
                    "raw": {},
                    "error": None,
                    "usage": None,
                },
            )()

    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "shellforgeai.core.windows_evidence_context.build_windows_evidence_context", build_packet
    )
    monkeypatch.setattr("shellforgeai.cli.build_provider", lambda *_: Provider())
    monkeypatch.setattr(
        "shellforgeai.cli.diagnose_target",
        lambda *args, **kwargs: pytest.fail("Linux-oriented diagnose route was invoked"),
    )

    result = CliRunner().invoke(app, ["ask", CANONICAL])
    assert result.exit_code == 0, result.stdout
    assert calls == ["evidence", "model"]
    assert "Container inventory is not collected" in result.stdout
    assert "Native Windows inventory is bounded" in result.stdout


def test_interactive_inventory_handler_is_evidence_first_and_bounded(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    calls: list[str] = []
    packet = {
        "host": {"hostname": "WIN-TEST"},
        "platform_detail": {"release": "2025"},
        "memory": {"available": False},
        "disk": {"available": False},
        "processes": {"available": True, "total_count": 2, "returned_count": 1},
        "services": {
            "available": True,
            "total_count": 3,
            "running_count": 2,
            "stopped_count": 1,
        },
        "limitations": ["Process preview limit=1; service preview limit=1."],
        "evidence_gaps": [],
        "safe_next_commands": [],
    }

    class Console:
        file = None

        def print(self, value):
            calls.append("evidence" if "## Windows evidence" in str(value) else "output")

    class Provider:
        def complete(self, request):
            assert calls[0] == "packet"
            assert "evidence" in calls
            assert "Container inventory is not collected" in request.prompt
            calls.append("model")
            return SimpleNamespace(ok=True, text="Bounded native inventory assessment.")

    monkeypatch.setattr(
        repl,
        "build_windows_evidence_context",
        lambda: calls.append("packet") or packet,
    )
    monkeypatch.setattr(repl, "build_provider", lambda settings: Provider())
    runtime = SimpleNamespace(
        session=SimpleNamespace(session_id="pr345", artifact_dir=tmp_path),
        settings=SimpleNamespace(
            model=SimpleNamespace(model="fake", provider="fake", timeout_seconds=1)
        ),
    )

    context = repl._handle_windows_symptom_route(
        Console(),
        runtime,
        CANONICAL,
        intent=ux.WINDOWS_OPERATOR_INTENT_RUNNING_INVENTORY,
    )
    assert calls.count("packet") == 1
    assert calls.index("evidence") < calls.index("model")
    assert ux.WINDOWS_INVENTORY_CONTAINER_LIMITATION in context.limitations
    assert context.model_assessment_status == "available"
