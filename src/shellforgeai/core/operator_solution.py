"""Canonical, inert operator-ready solution contract.

This module contains data models and deterministic serializers only.  It does
not collect evidence, execute instructions, persist artifacts, or authorize an
operator action.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from shellforgeai.core.evidence import TargetType
from shellforgeai.platform_detection import PlatformSystem

SCHEMA_VERSION = "v1"
ARTIFACT_TYPE = "operator_solution"

ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
LongText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000)]
Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class Confidence(StrEnum):
    """Bounded confidence in an inference; confidence is not proof."""

    low = "low"
    medium = "medium"
    high = "high"
    unknown = "unknown"


class Risk(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"
    unknown = "unknown"


class ProvenanceKind(StrEnum):
    evidence = "evidence"
    finding = "finding"
    plan = "plan"
    runbook = "runbook"
    report = "report"
    handoff = "handoff"


class RecoveryMode(StrEnum):
    not_applicable = "not_applicable"
    rollback = "rollback"
    recovery = "recovery"
    manual = "manual"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ProvenanceReference(_FrozenModel):
    """Logical reference to an upstream source, never its raw payload."""

    kind: ProvenanceKind
    ref: Identifier
    sha256: Sha256 | None = None

    @model_validator(mode="after")
    def reject_path_like_reference(self) -> ProvenanceReference:
        if ".." in self.ref or "/" in self.ref or "\\" in self.ref:
            raise ValueError("provenance ref must be a logical identifier, not a path")
        return self


class LikelyCause(_FrozenModel):
    id: Identifier
    inference: LongText
    rationale: LongText
    uncertainty: LongText
    evidence_refs: tuple[Identifier, ...] = Field(min_length=1, max_length=64)


class OperatorProcedureStep(_FrozenModel):
    id: Identifier
    title: ShortText
    instruction: LongText
    risk: Risk
    evidence_refs: tuple[Identifier, ...] = Field(default=(), max_length=64)


class OperatorAlternative(_FrozenModel):
    id: Identifier
    title: ShortText
    rationale: LongText
    trade_offs: tuple[LongText, ...] = Field(min_length=1, max_length=32)
    conditions: tuple[LongText, ...] = Field(min_length=1, max_length=32)


class VerificationCriterion(_FrozenModel):
    id: Identifier
    criterion: LongText
    evidence_refs: tuple[Identifier, ...] = Field(default=(), max_length=64)


class RollbackRecoveryGuidance(_FrozenModel):
    mode: RecoveryMode
    guidance: tuple[LongText, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def mode_matches_guidance(self) -> RollbackRecoveryGuidance:
        if self.mode is RecoveryMode.not_applicable and self.guidance:
            raise ValueError("not_applicable recovery cannot contain guidance")
        if self.mode is not RecoveryMode.not_applicable and not self.guidance:
            raise ValueError("rollback/recovery/manual mode requires guidance")
        return self


class OperatorSolution(_FrozenModel):
    """Normalized advisory endpoint; it is not an execution or approval input."""

    schema_version: Literal["v1"] = SCHEMA_VERSION
    artifact_type: Literal["operator_solution"] = ARTIFACT_TYPE
    solution_id: Identifier
    session_ref: Identifier | None = None
    platform_system: PlatformSystem
    target: ShortText
    target_type: TargetType
    desired_outcome: LongText
    diagnosis_summary: LongText
    diagnosis_confidence: Confidence
    likely_causes: tuple[LikelyCause, ...] = Field(default=(), max_length=64)
    provenance_references: tuple[ProvenanceReference, ...] = Field(min_length=1, max_length=256)
    prerequisites: tuple[LongText, ...] = Field(default=(), max_length=64)
    expected_impact: LongText
    blast_radius: LongText
    risk: Risk
    procedure: tuple[OperatorProcedureStep, ...] = Field(min_length=1, max_length=128)
    alternatives: tuple[OperatorAlternative, ...] = Field(default=(), max_length=32)
    verification_criteria: tuple[VerificationCriterion, ...] = Field(min_length=1, max_length=128)
    rollback_recovery: RollbackRecoveryGuidance
    assumptions: tuple[LongText, ...] = Field(default=(), max_length=64)
    unresolved_questions: tuple[LongText, ...] = Field(default=(), max_length=64)
    visibility_limits: tuple[LongText, ...] = Field(min_length=1, max_length=64)
    advisory_only: Literal[True] = True
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = "not_executed"

    @model_validator(mode="after")
    def semantic_coherence(self) -> OperatorSolution:
        groups = {
            "provenance refs": [item.ref for item in self.provenance_references],
            "likely-cause IDs": [item.id for item in self.likely_causes],
            "procedure IDs": [item.id for item in self.procedure],
            "alternative IDs": [item.id for item in self.alternatives],
            "verification IDs": [item.id for item in self.verification_criteria],
        }
        for label, values in groups.items():
            if len(values) != len(set(values)):
                raise ValueError(f"duplicate {label}")

        declared = set(groups["provenance refs"])
        used = {
            ref
            for item in (*self.likely_causes, *self.procedure, *self.verification_criteria)
            for ref in item.evidence_refs
        }
        undeclared = sorted(used - declared)
        if undeclared:
            raise ValueError(f"undeclared provenance refs: {', '.join(undeclared)}")
        return self


class OperatorSolutionValidationResult(_FrozenModel):
    valid: bool
    schema_version: Literal["v1"] = SCHEMA_VERSION
    issues: tuple[str, ...] = Field(default=(), max_length=64)


def validate_operator_solution(solution: OperatorSolution) -> OperatorSolutionValidationResult:
    """Confirm schema-v1 coherence, not safety, authority, freshness, or outcome."""

    if not isinstance(solution, OperatorSolution):
        return OperatorSolutionValidationResult(valid=False, issues=("not an OperatorSolution",))
    # Construction has already run the closed structural and cross-field checks.
    return OperatorSolutionValidationResult(valid=True)


def canonical_operator_solution_json(solution: OperatorSolution) -> str:
    """Return compact canonical JSON with no BOM or trailing newline."""

    validated = OperatorSolution.model_validate(solution)
    return json.dumps(
        validated.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_operator_solution_sha256(solution: OperatorSolution) -> str:
    """Hash only canonical UTF-8 JSON; the digest is not part of the payload."""

    payload = canonical_operator_solution_json(solution).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _section(lines: list[str], title: str, values: tuple[str, ...]) -> None:
    lines.extend(["", f"## {title}"])
    lines.extend(f"- {value}" for value in values)


def render_operator_solution_markdown(solution: OperatorSolution) -> str:
    """Render deterministic Markdown in a fixed, human-oriented section order."""

    value = OperatorSolution.model_validate(solution)
    lines = [
        "# ShellForgeAI Operator Solution",
        "",
        f"- schema_version: {value.schema_version}",
        f"- artifact_type: {value.artifact_type}",
        f"- solution_id: {value.solution_id}",
        f"- session_ref: {value.session_ref or 'none'}",
        f"- platform_system: {value.platform_system}",
        f"- target: {value.target}",
        f"- target_type: {value.target_type.value}",
        "- advisory_only: true",
        "- read_only: true",
        "- mutation_performed: false",
        "- execution_allowed: false",
        "- execution_available: false",
        "- execution_status: not_executed",
    ]
    _section(lines, "Desired outcome", (value.desired_outcome,))
    _section(
        lines,
        "Diagnosis",
        (value.diagnosis_summary, f"Confidence: {value.diagnosis_confidence.value}"),
    )
    lines.extend(["", "## Likely causes"])
    if value.likely_causes:
        for cause in value.likely_causes:
            lines.extend(
                [
                    f"### {cause.id}: {cause.inference}",
                    f"- Rationale: {cause.rationale}",
                    f"- Uncertainty: {cause.uncertainty}",
                    f"- Evidence: {', '.join(cause.evidence_refs)}",
                ]
            )
    else:
        lines.append("- None identified.")
    _section(
        lines,
        "Provenance",
        tuple(
            f"{p.ref} ({p.kind.value})" + (f" sha256={p.sha256}" if p.sha256 else "")
            for p in value.provenance_references
        ),
    )
    _section(lines, "Prerequisites", value.prerequisites or ("None declared.",))
    _section(lines, "Expected impact", (value.expected_impact,))
    _section(lines, "Blast radius and risk", (value.blast_radius, f"Risk: {value.risk.value}"))
    lines.extend(["", "## Ordered advisory operator procedure"])
    for number, step in enumerate(value.procedure, 1):
        lines.extend(
            [
                f"### {number}. {step.title} (`{step.id}`)",
                step.instruction,
                f"- Risk: {step.risk.value}",
                f"- Evidence: {', '.join(step.evidence_refs) or 'none'}",
            ]
        )
    lines.extend(["", "## Alternatives"])
    if value.alternatives:
        for alternative in value.alternatives:
            lines.extend(
                [
                    f"### {alternative.title} (`{alternative.id}`)",
                    alternative.rationale,
                    f"- Trade-offs: {'; '.join(alternative.trade_offs)}",
                    f"- Conditions: {'; '.join(alternative.conditions)}",
                ]
            )
    else:
        lines.append("- None identified.")
    _section(
        lines,
        "Verification criteria",
        tuple(
            f"{item.id}: {item.criterion} (evidence: {', '.join(item.evidence_refs) or 'none'})"
            for item in value.verification_criteria
        ),
    )
    _section(
        lines,
        "Rollback or recovery",
        (f"Mode: {value.rollback_recovery.mode.value}", *value.rollback_recovery.guidance),
    )
    _section(lines, "Assumptions", value.assumptions or ("None declared.",))
    _section(lines, "Unresolved questions", value.unresolved_questions or ("None declared.",))
    _section(lines, "Visibility limits", value.visibility_limits)
    return "\n".join(lines) + "\n"


__all__ = [
    "Confidence",
    "LikelyCause",
    "OperatorAlternative",
    "OperatorProcedureStep",
    "OperatorSolution",
    "OperatorSolutionValidationResult",
    "ProvenanceKind",
    "ProvenanceReference",
    "RecoveryMode",
    "Risk",
    "RollbackRecoveryGuidance",
    "VerificationCriterion",
    "canonical_operator_solution_json",
    "compute_operator_solution_sha256",
    "render_operator_solution_markdown",
    "validate_operator_solution",
]
