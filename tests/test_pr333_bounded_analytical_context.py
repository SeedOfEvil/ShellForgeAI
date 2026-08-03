from __future__ import annotations

from io import StringIO
from types import SimpleNamespace

from rich.console import Console

from shellforgeai.core.latest_context import (
    build_latest_diagnosis_context,
    valid_retained_context,
)
from shellforgeai.interactive import repl


def _context(platform: str = "linux"):
    target = "windows-local-read-only" if platform == "windows" else "performance"
    return build_latest_diagnosis_context(
        session_id="session-1",
        target=target,
        diagnosis_kind="performance",
        checks=[],
        facts={"container": platform == "linux", "top_process": "worker cpu=82%"},
        evidence_highlights=[
            "CPU load=4.2",
            "memory used=71%",
            "disk root free=8GiB",
            "process worker cpu=82%",
        ],
    )


def test_projection_is_bounded_and_keeps_provenance_separate() -> None:
    ctx = build_latest_diagnosis_context(
        session_id="session-1",
        target="performance",
        diagnosis_kind="performance",
        checks=[],
        facts={},
        evidence_highlights=["x" * 500] * 20,
    )
    assert len(ctx.deterministic_facts) == 8
    assert max(map(len, ctx.deterministic_facts)) == 280
    ctx.retain_selected_signal("disk is strongest " * 40)
    assert ctx.selected_signal == ctx.derived_findings[0]
    assert ctx.selected_signal not in ctx.deterministic_facts
    assert len(ctx.selected_signal) == 280


def test_context_binding_rejects_session_and_platform_changes() -> None:
    ctx = _context()
    assert valid_retained_context(ctx, session_id="session-1", platform_name="Linux")
    assert not valid_retained_context(ctx, session_id="session-2", platform_name="Linux")
    assert not valid_retained_context(ctx, session_id="session-1", platform_name="Windows")
    ctx.collection_id = ""
    assert not valid_retained_context(ctx, session_id="session-1", platform_name="Linux")


def test_analytical_prompt_carries_fact_limitation_and_selected_signal() -> None:
    ctx = _context()
    ctx.limitations = ["Event history was not collected."]
    ctx.retain_selected_signal("The worker CPU observation is the strongest signal.")
    prompt = repl._retained_analytical_prompt(
        "Based on evidence already collected, what is next?", ctx, "next_check"
    )
    assert "worker cpu=82%" in prompt
    assert "Event history was not collected" in prompt
    assert "previous_model_derived_selected_signal" in prompt
    assert "strongest signal" in prompt
    assert "authoritative collected facts" in prompt


def test_followup_renders_evidence_first_and_retains_only_accepted_signal(monkeypatch) -> None:
    events: list[str] = []
    ctx = _context()
    output = StringIO()
    console = Console(file=output, force_terminal=False, width=120)

    class Provider:
        def complete(self, request):
            events.append("provider")
            assert "process worker cpu=82%" in request.prompt
            return SimpleNamespace(ok=True, text="Worker CPU is the strongest signal.")

    monkeypatch.setattr(repl, "build_provider", lambda *_: Provider())
    runtime = SimpleNamespace(
        settings=SimpleNamespace(
            model=SimpleNamespace(model="fake", provider="fake", timeout_seconds=1)
        )
    )
    repl._render_retained_analytical_followup(
        console,
        runtime,
        ctx,
        "What is the strongest CPU, memory, disk, or process signal?",
        "strongest_signal",
    )
    rendered = output.getvalue()
    assert rendered.index("## Linux evidence") < rendered.index("## Model assessment")
    assert rendered.count("## Linux evidence") == 1
    assert events == ["provider"]
    assert ctx.selected_signal == "Worker CPU is the strongest signal."
    assert ctx.selected_signal not in ctx.deterministic_facts


def test_windows_rejection_keeps_evidence_and_does_not_retain(monkeypatch) -> None:
    ctx = _context("windows")
    output = StringIO()
    console = Console(file=output, force_terminal=False, width=120)

    class Provider:
        def complete(self, request):
            return SimpleNamespace(ok=True, text="Run journalctl and systemctl now.")

    monkeypatch.setattr(repl, "build_provider", lambda *_: Provider())
    runtime = SimpleNamespace(
        settings=SimpleNamespace(
            model=SimpleNamespace(model="fake", provider="fake", timeout_seconds=1)
        )
    )
    repl._render_retained_analytical_followup(
        console, runtime, ctx, "What is the strongest CPU or process signal?", "strongest_signal"
    )
    rendered = output.getvalue()
    assert rendered.count("## Windows evidence") == 1
    assert "rejected_windows_model_answer" in rendered
    assert "journalctl" not in rendered
    assert ctx.selected_signal is None


def test_provider_failure_keeps_retained_context_without_derived_finding(monkeypatch) -> None:
    ctx = _context()
    output = StringIO()
    console = Console(file=output, force_terminal=False, width=120)
    calls = 0

    class Provider:
        def complete(self, request):
            nonlocal calls
            calls += 1
            return SimpleNamespace(ok=False, text="raw secret failure")

    monkeypatch.setattr(repl, "build_provider", lambda *_: Provider())
    runtime = SimpleNamespace(
        settings=SimpleNamespace(
            model=SimpleNamespace(model="fake", provider="fake", timeout_seconds=1)
        )
    )
    repl._render_retained_analytical_followup(
        console, runtime, ctx, "What is the strongest CPU or process signal?", "strongest_signal"
    )
    rendered = output.getvalue()
    assert rendered.count("## Linux evidence") == 1
    assert "provider_failure" in rendered
    assert "raw secret" not in rendered
    assert calls == 1
    assert ctx.selected_signal is None
