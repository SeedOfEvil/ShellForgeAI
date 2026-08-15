"""Deterministically adapt a completed Linux diagnosis to an operator solution.

The adapter consumes existing domain objects only.  It performs no collection,
execution, model call, persistence, authorization, or platform detection.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable

from shellforgeai.core.diagnose import DiagnosisResult, Finding
from shellforgeai.core.operator_solution import (
    Confidence,
    LikelyCause,
    OperatorProcedureStep,
    OperatorSolution,
    ProvenanceKind,
    ProvenanceReference,
    RecoveryMode,
    Risk,
    RollbackRecoveryGuidance,
    VerificationCriterion,
)
from shellforgeai.core.plans import PlanStep
from shellforgeai.core.runbook import RunbookOption, build_runbook


class OperatorSolutionBuildError(ValueError):
    """A deterministic, controlled failure to build a safe solution."""


_UNSAFE_TRUE_KEYS = {
    "mutation_performed",
    "natural_language_execution",
    "arbitrary_command_execution",
    "shell_execution",
    "shell_true",
    "remediation_executed",
    "rollback_executed",
    "cleanup_executed",
    "docker_compose_executed",
    "container_restarted",
    "execution_allowed",
    "execution_available",
    "approval_granted",
    "preflight_executed",
}
_RISK_ORDER = {Risk.unknown: -1, Risk.low: 0, Risk.medium: 1, Risk.high: 2, Risk.critical: 3}


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        clean = " ".join(str(value).split())
        if clean and clean not in seen:
            seen.add(clean)
            result.append(clean)
    return tuple(result)


def _identifier(prefix: str, value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._:-]+", "-", value.strip()).strip("-._:") or "unknown"
    candidate = f"{prefix}:{clean}"
    if len(candidate) <= 128:
        return candidate
    digest = hashlib.sha256(candidate.encode()).hexdigest()[:12]
    return f"{candidate[:115]}-{digest}"


def _risk(value: str) -> Risk:
    try:
        return Risk(value.lower())
    except ValueError:
        return Risk.unknown


def _confidence(findings: list[Finding]) -> Confidence:
    actionable = [f for f in findings if f.severity.lower() in {"critical", "warning"}]
    if not actionable:
        return Confidence.unknown
    values = {f.confidence.lower() for f in actionable}
    if "low" in values or "unknown" in values:
        return Confidence.low
    if values == {"high"}:
        return Confidence.high
    return Confidence.medium


def _platform_is_windows(diagnosis: DiagnosisResult) -> bool:
    """Use structured platform evidence/context, never target prose."""
    for item in diagnosis.evidence.items:
        if (
            item.source == "platform.detect"
            and str(item.metadata.get("platform", "")).lower() == "windows"
        ):
            return True
    return diagnosis.runtime_context.get("visibility") == "windows_local_read_only"


def _validate_source(diagnosis: DiagnosisResult) -> None:
    if _platform_is_windows(diagnosis):
        raise OperatorSolutionBuildError(
            "Windows OperatorSolution generation is deferred to the native Windows producer"
        )
    unsafe = sorted(key for key in _UNSAFE_TRUE_KEYS if diagnosis.safety.get(key) is True)
    if unsafe:
        raise OperatorSolutionBuildError(
            "diagnosis safety state is incompatible: " + ", ".join(unsafe)
        )
    if not diagnosis.evidence.items or not any(
        item.ok and any((item.title.strip(), item.summary.strip(), item.content.strip()))
        for item in diagnosis.evidence.items
    ):
        raise OperatorSolutionBuildError("diagnosis has insufficient usable evidence")


def _selected_options(options: list[RunbookOption]) -> list[RunbookOption]:
    # Runbook order is already its deterministic recommended order.  Distinct
    # problems are a combined procedure, not fabricated alternatives.
    return [option for option in options if option.steps]


def build_linux_operator_solution_from_diagnosis(
    diagnosis: DiagnosisResult,
) -> OperatorSolution:
    """Build one validated PR358 solution from an already-completed diagnosis."""
    if not isinstance(diagnosis, DiagnosisResult):
        raise OperatorSolutionBuildError("source must be a completed DiagnosisResult")
    _validate_source(diagnosis)

    runbook = build_runbook(
        session_id=diagnosis.session_id,
        target=diagnosis.target,
        evidence_items=diagnosis.evidence.items,
        findings=diagnosis.findings,
        source_artifacts=[],
    )
    options = _selected_options(runbook.operator_steps)

    provenance: list[ProvenanceReference] = []
    declared: set[str] = set()

    def declare(kind: ProvenanceKind, ref: str) -> str:
        if ref not in declared:
            provenance.append(ProvenanceReference(kind=kind, ref=ref))
            declared.add(ref)
        return ref

    evidence_refs: dict[str, str] = {}
    for item in diagnosis.evidence.items:
        evidence_refs.setdefault(
            item.source, declare(ProvenanceKind.evidence, _identifier("evidence", item.source))
        )

    causes: list[LikelyCause] = []
    for index, finding in enumerate(diagnosis.findings, 1):
        if finding.severity.lower() not in {"critical", "warning"}:
            continue
        finding_ref = declare(ProvenanceKind.finding, f"finding:{index:04d}")
        refs = _unique(
            [
                finding_ref,
                *(
                    evidence_refs[source]
                    for source in finding.evidence_refs
                    if source in evidence_refs
                ),
            ]
        )
        causes.append(
            LikelyCause(
                id=f"cause:{index:04d}",
                inference=finding.title,
                rationale=finding.detail,
                uncertainty=(
                    f"This {finding.confidence.lower()}-confidence diagnosis is an inference, "
                    "not proof."
                ),
                evidence_refs=refs,
            )
        )

    procedure: list[OperatorProcedureStep] = []
    selected_risks: list[Risk] = []
    if options:
        runbook_ref = declare(ProvenanceKind.runbook, "runbook:diagnosis-derived")
        for option_index, option in enumerate(options, 1):
            option_risk = _risk(option.risk)
            selected_risks.append(option_risk)
            for step_index, instruction in enumerate(_unique(option.steps), 1):
                procedure.append(
                    OperatorProcedureStep(
                        id=f"step:{option_index:03d}-{step_index:03d}",
                        title=option.title,
                        instruction=instruction,
                        risk=option_risk,
                        evidence_refs=(runbook_ref,),
                    )
                )
    else:
        plan_ref = declare(ProvenanceKind.plan, "plan:diagnosis-proposed")
        plan_steps: list[PlanStep] = []
        seen_instructions: set[str] = set()
        for step in diagnosis.proposed_plan.steps:
            if step.destructive:
                raise OperatorSolutionBuildError(
                    "diagnosis proposed plan contains a destructive step"
                )
            instruction = " ".join(step.description.split())
            if instruction in seen_instructions:
                continue
            seen_instructions.add(instruction)
            plan_steps.append(step)
        for index, step in enumerate(plan_steps, 1):
            procedure.append(
                OperatorProcedureStep(
                    id=f"step:{index:03d}",
                    title=step.title,
                    instruction=step.description,
                    risk=_risk(step.risk),
                    evidence_refs=(plan_ref,),
                )
            )
            selected_risks.append(_risk(step.risk))
    if not procedure:
        raise OperatorSolutionBuildError("diagnosis has no usable advisory procedure")

    runbook_ref = declare(ProvenanceKind.runbook, "runbook:diagnosis-derived")
    verification_text = _unique(
        [*(text for option in options for text in option.verification), *runbook.validation]
    )
    verification = tuple(
        VerificationCriterion(
            id=f"verify:{index:03d}", criterion=text, evidence_refs=(runbook_ref,)
        )
        for index, text in enumerate(verification_text, 1)
    )

    prerequisites = _unique(
        [*runbook.prechecks, *(p for option in options for p in option.preconditions)]
    )
    impacts = _unique(option.impact for option in options)
    rollback = _unique(
        [*(line for option in options for line in option.rollback), *runbook.rollback]
    )
    change_guidance = bool(options and rollback)
    visibility = _unique(
        [
            "Evidence is a point-in-time view and may not represent current target state.",
            *(str(x) for x in diagnosis.runtime_context.get("limitations", []) if str(x).strip()),
            *(
                f"Limitation: {f.detail}"
                for f in diagnosis.findings
                if f.severity.lower() == "limitation"
            ),
            *diagnosis.evidence.warnings,
            *diagnosis.evidence.errors,
            *diagnosis.warnings,
            *diagnosis.errors,
        ]
    )
    summary_parts = [f"{f.severity}: {f.title}" for f in diagnosis.findings]
    summary = "; ".join(summary_parts) or "No diagnostic findings were recorded."
    desired = options[0].title if options else diagnosis.proposed_plan.goal
    risk = max(selected_risks, key=_RISK_ORDER.get, default=Risk.unknown)
    identity = json.dumps(
        {
            "session_ref": diagnosis.session_id,
            "target": diagnosis.target,
            "target_type": diagnosis.target_type.value,
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    return OperatorSolution(
        solution_id=f"solution:{hashlib.sha256(identity.encode()).hexdigest()[:24]}",
        session_ref=diagnosis.session_id,
        platform_system="linux",
        target=diagnosis.target,
        target_type=diagnosis.target_type,
        desired_outcome=desired,
        diagnosis_summary=summary,
        diagnosis_confidence=_confidence(diagnosis.findings),
        likely_causes=tuple(causes),
        provenance_references=tuple(provenance),
        prerequisites=prerequisites,
        expected_impact="; ".join(impacts)
        if impacts
        else "Read-only diagnostic follow-up only; no mutation by ShellForgeAI.",
        blast_radius=(
            f"Limited to the diagnosed {diagnosis.target_type.value} target: {diagnosis.target}."
        ),
        risk=risk,
        procedure=tuple(procedure),
        alternatives=(),
        verification_criteria=verification,
        rollback_recovery=RollbackRecoveryGuidance(
            mode=RecoveryMode.rollback if change_guidance else RecoveryMode.not_applicable,
            guidance=rollback if change_guidance else (),
        ),
        assumptions=(),
        unresolved_questions=(),
        visibility_limits=visibility,
    )


__all__ = ["OperatorSolutionBuildError", "build_linux_operator_solution_from_diagnosis"]
