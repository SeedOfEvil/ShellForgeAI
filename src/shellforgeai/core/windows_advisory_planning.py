"""Shared orchestration for native Windows advisory planning."""

from __future__ import annotations

from shellforgeai.core.evidence import TargetType
from shellforgeai.core.operator_solution import render_operator_solution_markdown
from shellforgeai.core.windows_evidence_context import build_windows_evidence_context
from shellforgeai.core.windows_operator_solution_builder import (
    WindowsOperatorSolutionBuildError,
    build_windows_operator_solution_from_evidence,
)
from shellforgeai.core.windows_operator_ux import (
    WindowsOperatorRoute,
    render_windows_operator_guidance,
)


def render_windows_advisory_plan(route: WindowsOperatorRoute) -> str:
    """Collect once, build once, and canonically render one advisory solution."""
    if not route.host_is_windows:
        return render_windows_operator_guidance(route)
    evidence = build_windows_evidence_context()
    host = evidence.get("host") if isinstance(evidence.get("host"), dict) else {}
    target = str(host.get("hostname") or "current Windows host")
    try:
        solution = build_windows_operator_solution_from_evidence(
            evidence,
            route,
            target=target,
            target_type=TargetType.host,
        )
    except WindowsOperatorSolutionBuildError:
        return (
            "Windows advisory plan unavailable.\n"
            "Context/visibility: windows-local-read-only.\n"
            "The bounded evidence packet did not contain enough safe observed evidence to "
            "produce a canonical OperatorSolution. No model was called and no action was taken."
        )
    return render_operator_solution_markdown(solution)


__all__ = ["render_windows_advisory_plan"]
