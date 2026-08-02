"""Bounded, deterministic evidence-first presentation for model-assisted turns.

This module is presentation-only.  It neither collects evidence nor invokes a
provider, and its clock is injectable so operator-visible ordering and timing
can be tested without sleeping.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Literal

EVIDENCE_FIRST_TARGET_MS = 5000.0
ModelStatus = Literal["not_requested", "pending", "completed", "failed", "timed_out"]


@dataclass(frozen=True)
class EvidenceFirstResponse:
    platform: str
    evidence_label: str
    evidence_source: str
    intent: str
    evidence_available: bool
    findings: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    safe_next_commands: tuple[str, ...] = ()
    model_status: ModelStatus = "pending"
    schema_version: str = "shellforgeai.evidence-first.v1"
    read_only: bool = True
    mutation_performed: bool = False
    deterministic_only: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", self.findings[:3])
        object.__setattr__(self, "limitations", self.limitations[:2])
        object.__setattr__(self, "safe_next_commands", self.safe_next_commands[:2])


@dataclass
class EvidenceResponseTimeline:
    """Monotonic timestamps for the synchronous two-stage response."""

    clock: Callable[[], float] = time.monotonic
    request_start: float = field(init=False)
    evidence_ready: float | None = None
    evidence_rendered: float | None = None
    model_start: float | None = None
    model_end: float | None = None

    def __post_init__(self) -> None:
        self.request_start = self.clock()

    def mark_evidence_ready(self) -> None:
        self.evidence_ready = self.clock()

    def mark_evidence_rendered(self) -> None:
        self.evidence_rendered = self.clock()

    def mark_model_start(self) -> None:
        self.model_start = self.clock()

    def mark_model_end(self) -> None:
        self.model_end = self.clock()

    @property
    def time_to_first_evidence_ms(self) -> float | None:
        if self.evidence_rendered is None:
            return None
        return max(0.0, (self.evidence_rendered - self.request_start) * 1000.0)

    @property
    def model_duration_ms(self) -> float | None:
        if self.model_start is None or self.model_end is None:
            return None
        return max(0.0, (self.model_end - self.model_start) * 1000.0)

    @property
    def evidence_budget_met(self) -> bool | None:
        elapsed = self.time_to_first_evidence_ms
        return None if elapsed is None else elapsed <= EVIDENCE_FIRST_TARGET_MS

    def as_dict(self) -> dict[str, float | bool | None]:
        return {
            "request_start": self.request_start,
            "evidence_ready": self.evidence_ready,
            "evidence_rendered": self.evidence_rendered,
            "model_start": self.model_start,
            "model_end": self.model_end,
            "time_to_first_evidence_ms": self.time_to_first_evidence_ms,
            "model_duration_ms": self.model_duration_ms,
            "evidence_budget_met": self.evidence_budget_met,
        }


def render_evidence_first(response: EvidenceFirstResponse) -> str:
    """Render the bounded authoritative stage, including the pending transition."""

    lines = [
        f"## {response.platform} evidence",
        f"Evidence label: {response.evidence_label}",
        f"Evidence source: {response.evidence_source}",
        f"Intent: {response.intent}",
        f"evidence_available={str(response.evidence_available).lower()}",
    ]
    if response.findings:
        lines.extend(["", "Findings:", *(f"- {item}" for item in response.findings)])
    else:
        lines.extend(["", "Findings:", "- No deterministic finding was established."])
    lines.extend(["", "Limitations:"])
    lines.extend(f"- {item}" for item in (response.limitations or ("Evidence is bounded.",)))
    if response.safe_next_commands:
        heading = (
            "Safe next step:" if len(response.safe_next_commands) == 1 else "Safe next commands:"
        )
        lines.extend(["", heading, *response.safe_next_commands])
    lines.extend(
        [
            "",
            f"read_only={str(response.read_only).lower()}",
            f"mutation_performed={str(response.mutation_performed).lower()}",
            "Deterministic evidence above is the authoritative current evidence.",
            "",
            "Model assessment pending...",
        ]
    )
    return "\n".join(lines)


def render_model_assessment(text: str) -> str:
    return f"## Model assessment\n\n{text.strip()}"


def render_model_unavailable(failure_class: str) -> str:
    bounded = (failure_class or "unknown").strip().splitlines()[0][:80]
    return (
        "## Model assessment unavailable\n\n"
        f"Failure class: {bounded}\n"
        "The deterministic evidence above remains the current answer."
    )


def with_model_status(
    response: EvidenceFirstResponse, status: ModelStatus
) -> EvidenceFirstResponse:
    return replace(response, model_status=status)
