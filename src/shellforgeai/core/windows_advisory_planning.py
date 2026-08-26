"""Shared orchestration for native Windows advisory planning."""

from __future__ import annotations

from shellforgeai.core.evidence import TargetType
from shellforgeai.core.operator_solution import render_operator_solution_markdown
from shellforgeai.core.windows_evidence_context import build_windows_evidence_context
from shellforgeai.core.windows_operator_solution_builder import (
    build_windows_operator_solution_from_evidence,
)
from shellforgeai.core.windows_operator_ux import (
    WINDOWS_OPERATOR_INTENT_HANDOFF,
    WindowsOperatorRoute,
    render_windows_operator_guidance,
)


def render_windows_advisory_plan(route: WindowsOperatorRoute) -> str:
    """Collect once, build once, and canonically render one advisory solution."""
    if not route.host_is_windows:
        return render_windows_operator_guidance(route)
    try:
        evidence = build_windows_evidence_context()
        host = evidence.get("host") if isinstance(evidence.get("host"), dict) else {}
        target = str(host.get("hostname") or "current Windows host")
        solution = build_windows_operator_solution_from_evidence(
            evidence,
            route,
            target=target,
            target_type=TargetType.host,
        )
        return render_operator_solution_markdown(solution)
    except Exception:
        purpose = (
            "operator handoff"
            if route.intent == WINDOWS_OPERATOR_INTENT_HANDOFF
            else "advisory plan"
        )
        return (
            f"Windows {purpose} unavailable.\n"
            "Context/visibility: windows-local-read-only.\n"
            "The bounded evidence packet did not contain enough safe observed evidence to "
            "produce a canonical OperatorSolution. No model was called and no action was taken."
        )


__all__ = ["render_windows_advisory_plan"]
