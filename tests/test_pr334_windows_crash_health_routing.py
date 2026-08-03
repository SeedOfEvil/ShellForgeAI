from __future__ import annotations

from io import StringIO
from types import SimpleNamespace

import pytest
from rich.console import Console

from shellforgeai.core.windows_operator_ux import (
    WINDOWS_OPERATOR_INTENT_FAILURE_HEALTH,
    WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL,
    classify_windows_interactive_intent,
)
from shellforgeai.interactive import repl


@pytest.mark.parametrize(
    "phrase",
    [
        "Is anything crashing?",
        "Are any processes crashing?",
        "Are any services crashing?",
        "Do you see any crash signals?",
        "Do you see any failures or crashes?",
        "Is anything crashing on this Windows host?",
    ],
)
def test_native_windows_bounded_phrases_classify_as_failure_health(phrase: str) -> None:
    route = classify_windows_interactive_intent(phrase, host_system="Windows")
    assert route is not None
    assert route.intent == WINDOWS_OPERATOR_INTENT_FAILURE_HEALTH
    assert route.host_is_windows is True


@pytest.mark.parametrize(
    "phrase",
    [
        "Is my Docker container crashing?",
        "Is the container crashing?",
        "Is Docker Compose crashing?",
        "Why is this Docker service crashing?",
        "Is the container crashing on Windows?",
        "Is nginx crashing inside the container?",
    ],
)
def test_explicit_docker_targets_are_not_windows_failure_health(phrase: str) -> None:
    route = classify_windows_interactive_intent(phrase, host_system="Windows")
    assert route is None or route.intent != WINDOWS_OPERATOR_INTENT_FAILURE_HEALTH


@pytest.mark.parametrize(
    "phrase",
    [
        "Is anything crashing?",
        "Are any processes crashing?",
        "Do you see any failures or crashes?",
    ],
)
def test_linux_unqualified_phrases_do_not_create_windows_route(phrase: str) -> None:
    assert classify_windows_interactive_intent(phrase, host_system="Linux") is None


def test_explicit_windows_phrase_on_linux_is_unsupported_route_only() -> None:
    route = classify_windows_interactive_intent(
        "Is anything crashing on the Windows host?", host_system="Linux"
    )
    assert route is not None
    assert route.intent == WINDOWS_OPERATOR_INTENT_FAILURE_HEALTH
    assert route.host_is_windows is False


@pytest.mark.parametrize(
    "phrase",
    [
        "Restart whatever is crashing.",
        "Kill the crashing process.",
        "Stop the failing service.",
        "Clean up whatever failed.",
    ],
)
def test_shared_mutation_refusal_keeps_priority(phrase: str) -> None:
    route = classify_windows_interactive_intent(phrase, host_system="Windows")
    assert route is not None
    assert route.intent == WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL


def _packet() -> dict[str, object]:
    return {
        "limitations": ["Event Log evidence is unavailable in this bounded collection."],
        "evidence_gaps": ["No crash records or dump history were collected."],
        "safe_next_commands": ["shellforgeai windows events --json --limit 50 --since-hours 24"],
    }


def _rows(_packet: dict[str, object]) -> list[dict[str, str]]:
    return [
        {"status": "ok", "summary": "Memory available=8 GiB of 16 GiB."},
        {"status": "ok", "summary": "Windows process count=42; top process=worker."},
        {"status": "ok", "summary": "Windows services running=30 stopped=2."},
        {"status": "ok", "summary": "C: free=120 GiB."},
    ]


def _runtime() -> SimpleNamespace:
    return SimpleNamespace(
        session=SimpleNamespace(session_id="session-334"),
        settings=SimpleNamespace(
            model=SimpleNamespace(model="fake", provider="fake", timeout_seconds=1)
        ),
    )


def test_failure_health_collects_once_renders_before_provider_and_retains_context(
    monkeypatch,
) -> None:
    events: list[str] = []
    output = StringIO()
    console = Console(file=output, force_terminal=False, width=120)

    def collect():
        events.append("collect")
        return _packet()

    class Provider:
        def complete(self, request):
            events.append("provider")
            assert "Event Log evidence is unavailable" in request.prompt
            assert "Windows process count=42" in request.prompt
            assert "journalctl" not in request.prompt
            return SimpleNamespace(
                ok=True,
                text=(
                    "The current Windows snapshot shows no confirmed immediate crash signal. "
                    "It cannot establish historical stability without Event Log evidence."
                ),
            )

    monkeypatch.setattr(repl, "build_windows_evidence_context", collect)
    monkeypatch.setattr(repl, "windows_evidence_prompt_facts", _rows)
    monkeypatch.setattr(repl, "build_provider", lambda *_: Provider())
    ctx = repl._handle_windows_failure_health_route(console, _runtime(), "Is anything crashing?")
    rendered = output.getvalue()
    assert events == ["collect", "provider"]
    assert rendered.index("## Windows evidence") < rendered.index("## Model assessment")
    assert rendered.count("## Windows evidence") == 1
    assert "Model assessment pending" in rendered
    assert "Event Log evidence is unavailable" in rendered
    assert "read_only=true" in rendered
    assert "mutation_performed=false" in rendered
    assert ctx.platform == "windows"
    assert ctx.collection_id
    assert ctx.deterministic_facts
    assert ctx.selected_signal is None


@pytest.mark.parametrize(
    ("response", "failure_class"),
    [
        (SimpleNamespace(ok=False, text="private failure"), "provider_failure"),
        (
            SimpleNamespace(ok=True, text="Run journalctl and inspect the Docker container."),
            "rejected_windows_model_answer",
        ),
    ],
)
def test_failure_or_rejection_keeps_single_evidence_block_without_retry(
    monkeypatch, response, failure_class: str
) -> None:
    calls = 0
    output = StringIO()

    class Provider:
        def complete(self, request):
            nonlocal calls
            calls += 1
            return response

    monkeypatch.setattr(repl, "build_windows_evidence_context", _packet)
    monkeypatch.setattr(repl, "windows_evidence_prompt_facts", _rows)
    monkeypatch.setattr(repl, "build_provider", lambda *_: Provider())
    ctx = repl._handle_windows_failure_health_route(
        Console(file=output, force_terminal=False, width=120),
        _runtime(),
        "Is anything crashing?",
    )
    rendered = output.getvalue()
    assert calls == 1
    assert rendered.count("## Windows evidence") == 1
    assert failure_class in rendered
    assert "journalctl" not in rendered
    assert "private failure" not in rendered
    assert ctx.selected_signal is None
    assert ctx.deterministic_facts


def test_exact_three_turn_sequence_reuses_one_collection(monkeypatch) -> None:
    collections = 0
    prompts: list[str] = []
    output = StringIO()
    console = Console(file=output, force_terminal=False, width=120)

    def collect():
        nonlocal collections
        collections += 1
        return _packet()

    class Provider:
        def complete(self, request):
            prompts.append(request.prompt)
            if len(prompts) == 2:
                return SimpleNamespace(ok=True, text="Memory availability is the strongest signal.")
            if len(prompts) == 3:
                assert "Memory availability is the strongest signal" in request.prompt
                assert "Memory available=8 GiB" in request.prompt
                assert "Event Log evidence is unavailable" in request.prompt
                return SimpleNamespace(
                    ok=True,
                    text="Inspect the bounded Windows Event Log read-only to fill the history gap.",
                )
            return SimpleNamespace(
                ok=True,
                text="No immediate failure is confirmed; historical crash evidence is unavailable.",
            )

    monkeypatch.setattr(repl, "build_windows_evidence_context", collect)
    monkeypatch.setattr(repl, "windows_evidence_prompt_facts", _rows)
    monkeypatch.setattr(repl, "build_provider", lambda *_: Provider())
    runtime = _runtime()
    ctx = repl._handle_windows_failure_health_route(console, runtime, "Is anything crashing?")
    repl._render_retained_analytical_followup(
        console,
        runtime,
        ctx,
        "What is the strongest CPU, memory, disk, or process signal?",
        "strongest_signal",
    )
    assert ctx.selected_signal == "Memory availability is the strongest signal."
    assert ctx.selected_signal not in ctx.deterministic_facts
    repl._render_retained_analytical_followup(
        console,
        runtime,
        ctx,
        "Based on evidence already collected, what is the best read-only next check?",
        "next_check",
    )
    assert collections == 1
    assert len(prompts) == 3
    assert output.getvalue().count("## Windows evidence") == 3
