"""Bounded orchestration for evidence-backed Linux/Docker advisory planning."""

from __future__ import annotations

from typing import Any

from shellforgeai.core.diagnose import diagnose_target
from shellforgeai.core.operator_solution import render_operator_solution_markdown
from shellforgeai.core.operator_solution_builder import (
    build_linux_operator_solution_from_diagnosis,
)

LINUX_ADVISORY_FAILURE = (
    "Canonical Linux/Docker operator solution could not be produced from the available "
    "read-only evidence.\nNo action was taken."
)


def render_linux_advisory_plan(runtime: Any, target: str, *, since: str = "30m") -> str:
    """Diagnose once, build once, and canonically render one advisory solution."""

    try:
        diagnosis = diagnose_target(runtime, target, online=False, since=since)
        solution = build_linux_operator_solution_from_diagnosis(diagnosis)
        return render_operator_solution_markdown(solution)
    except Exception:
        # Diagnosis, canonical validation, and rendering failures are deliberately
        # bounded here: this path must never downgrade to a model or another planner.
        return LINUX_ADVISORY_FAILURE


__all__ = [
    "LINUX_ADVISORY_FAILURE",
    "render_linux_advisory_plan",
]
