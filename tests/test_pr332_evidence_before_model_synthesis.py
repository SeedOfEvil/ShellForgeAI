from __future__ import annotations

from shellforgeai.core.evidence_first_response import (
    EvidenceFirstResponse,
    EvidenceResponseTimeline,
    render_evidence_first,
    render_model_assessment,
    render_model_unavailable,
)


class Clock:
    def __init__(self, *values: float) -> None:
        self.values = iter(values)

    def __call__(self) -> float:
        return next(self.values)


def _response(**changes: object) -> EvidenceFirstResponse:
    values = {
        "platform": "Linux/Docker",
        "evidence_label": "Docker triage evidence",
        "evidence_source": "typed collector",
        "intent": "health diagnosis",
        "evidence_available": True,
        "findings": ("suspect=web", "severity=high", "theme=timeout", "unbounded"),
        "limitations": ("bounded view", "point in time", "unbounded"),
        "safe_next_commands": ("shellforgeai triage docker --json",),
    }
    values.update(changes)
    return EvidenceFirstResponse(**values)  # type: ignore[arg-type]


def test_bounded_evidence_contract_precedes_supplemental_assessment() -> None:
    evidence = render_evidence_first(_response())
    assessment = render_model_assessment("Evidence-grounded interpretation.")
    output = evidence + "\n" + assessment

    assert output.index("## Linux/Docker evidence") < output.index("Model assessment pending")
    assert output.index("Model assessment pending") < output.index("## Model assessment")
    assert "suspect=web" in evidence
    assert "unbounded" not in evidence
    assert "Safe next step:\nshellforgeai triage docker --json" in evidence
    assert "read_only=true" in evidence
    assert "mutation_performed=false" in evidence


def test_evidence_unavailable_never_invents_a_finding() -> None:
    rendered = render_evidence_first(
        _response(evidence_available=False, findings=(), limitations=("Timeout.",))
    )
    assert "evidence_available=false" in rendered
    assert "No deterministic finding was established" in rendered
    assert "Model assessment pending" in rendered


def test_model_failure_is_bounded_and_does_not_repeat_evidence() -> None:
    evidence = render_evidence_first(_response())
    failure = render_model_unavailable("provider_timeout\nraw stderr must not appear")
    output = evidence + "\n" + failure
    assert output.count("## Linux/Docker evidence") == 1
    assert "Failure class: provider_timeout" in failure
    assert "raw stderr" not in failure
    assert "deterministic evidence above remains" in failure.lower()


def test_timeline_meets_budget_and_orders_render_before_model() -> None:
    timeline = EvidenceResponseTimeline(clock=Clock(10.0, 10.2, 14.9, 15.0, 16.0))
    timeline.mark_evidence_ready()
    timeline.mark_evidence_rendered()
    timeline.mark_model_start()
    timeline.mark_model_end()
    assert timeline.evidence_budget_met is True
    assert timeline.time_to_first_evidence_ms == 4900.0
    assert timeline.evidence_rendered < timeline.model_start
    assert timeline.model_duration_ms == 1000.0


def test_timeline_records_budget_miss_without_cancellation() -> None:
    timeline = EvidenceResponseTimeline(clock=Clock(1.0, 2.0, 6.001, 7.0, 9.0))
    timeline.mark_evidence_ready()
    timeline.mark_evidence_rendered()
    timeline.mark_model_start()
    timeline.mark_model_end()
    assert timeline.evidence_budget_met is False
    assert timeline.model_end == 9.0
    assert timeline.as_dict()["model_duration_ms"] == 2000.0
