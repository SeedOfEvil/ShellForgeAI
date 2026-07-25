"""Reviewed supplemental-context contract for approved-change construction (PR314).

This module is intentionally pure, immutable, deterministic, and inert. It
defines the complete, separately reviewed input package that must exist before
any future operation could construct a PR309 ``ApprovedChangeSubject`` under the
PR311 field-source policy.

It deliberately provides no construction API. It does not accept a legacy
``Proposal``, extract candidate values, build a draft or final subject, create an
``ApprovalAttestation`` or ``ApprovedChangeContract``, persist anything, register
capabilities, run preflight, link receipts, or enable execution.

Private canonicalization and text helpers are imported from the PR309 contract
module on purpose: reviewed values must satisfy exactly the same semantic
constraints and canonicalization rules as their eventual PR309 destination.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from shellforgeai.core.approved_change_construction_policy import (
    CONSTRUCTION_POLICY_SCHEMA_VERSION,
    CONTRACT_CONSTANT_FIELDS,
    DIRECT_CANDIDATE_ALLOWLIST,
    EXPLICIT_CONTEXT_ONLY_FIELDS,
)
from shellforgeai.core.approved_change_contract import (
    _CAPABILITY_RE,
    ApprovedChangeSubject,
    ApprovedChangeTarget,
    EvidenceReference,
    ProcedureStep,
    RollbackPosture,
    _canonicalize,
    _is_wildcard,
    _require_aware,
    _require_text,
    _require_text_tuple,
)
from shellforgeai.core.approved_change_contract import (
    SCHEMA_VERSION as APPROVED_CHANGE_SCHEMA_VERSION,
)

SUPPLEMENTAL_CONTEXT_SCHEMA_VERSION = "1"
CANDIDATE_REVIEW_SCHEMA_VERSION = "1"
EXECUTION_STATUS_NOT_EXECUTED = "not_executed"

MAX_REVIEW_ACTOR_LENGTH = 128
MAX_REVIEW_REASON_LENGTH = 1024
MAX_REVIEWED_TEXT_LENGTH = 4096
MAX_CAPABILITY_ID_LENGTH = 128

VALIDATION_STATUSES = (
    "supplemental_context_valid",
    "supplemental_context_invalid",
    "invalid_validation_input",
)

CandidateDecision = Literal["accepted", "rejected"]
ValidationStatus = Literal[
    "supplemental_context_valid",
    "supplemental_context_invalid",
    "invalid_validation_input",
]

#: The 12 PR311 ``explicit_context_only`` destinations, deterministically sorted.
EXPLICIT_CONTEXT_DESTINATIONS: tuple[str, ...] = tuple(sorted(EXPLICIT_CONTEXT_ONLY_FIELDS))
#: The exact five PR311 reviewed direct-candidate destination -> legacy source mappings.
CANDIDATE_DESTINATION_SOURCES: tuple[tuple[str, str], ...] = tuple(
    sorted(DIRECT_CANDIDATE_ALLOWLIST)
)
#: The five reviewed candidate destinations, deterministically sorted.
CANDIDATE_DESTINATIONS: tuple[str, ...] = tuple(dest for dest, _ in CANDIDATE_DESTINATION_SOURCES)

PERMANENT_WARNINGS: tuple[str, ...] = (
    "review provenance is not authenticated identity, approval, or authorization",
    "supplemental-context identity is not a PR309 subject hash, approval hash, or fingerprint",
    "a valid reviewed context creates no subject, approval, contract, or execution eligibility",
)


def _bounded_text(value: str, limit: int, label: str) -> str:
    cleaned = _require_text(value)
    if len(cleaned) > limit:
        raise ValueError(f"{label} must be at most {limit} characters")
    return cleaned


def _bounded_text_tuple(value: tuple[str, ...], limit: int, label: str) -> tuple[str, ...]:
    return tuple(_bounded_text(item, limit, label) for item in _require_text_tuple(value))


def _require_capability_id(value: str) -> str:
    cleaned = _bounded_text(value, MAX_CAPABILITY_ID_LENGTH, "capability_id")
    if _is_wildcard(cleaned) or not _CAPABILITY_RE.fullmatch(cleaned):
        raise ValueError("capability_id must be a bounded exact identifier")
    return cleaned


def _require_unique_step_ids(steps: tuple[ProcedureStep, ...], label: str) -> None:
    ids = [step.step_id for step in steps]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{label} step IDs must be unique")


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ReviewProvenance(_FrozenModel):
    """Who reviewed a single destination value, when, and why.

    This is review bookkeeping only. It is not authenticated identity, an
    ``ApprovalAttestation``, authorization, approval portability, execution
    confirmation, or proof that the stated actor controls the named identity.
    """

    reviewed_by: str
    reviewed_at: datetime
    review_reason: str

    @field_validator("reviewed_by")
    @classmethod
    def _validate_actor(cls, value: str) -> str:
        return _bounded_text(value, MAX_REVIEW_ACTOR_LENGTH, "reviewed_by")

    @field_validator("review_reason")
    @classmethod
    def _validate_reason(cls, value: str) -> str:
        return _bounded_text(value, MAX_REVIEW_REASON_LENGTH, "review_reason")

    @field_validator("reviewed_at")
    @classmethod
    def _validate_reviewed_at(cls, value: datetime) -> datetime:
        return _require_aware(value)


class _ExplicitContextReviewBase(_FrozenModel):
    provenance: ReviewProvenance


class _TextContextReview(_ExplicitContextReviewBase):
    reviewed_value: str

    @field_validator("reviewed_value")
    @classmethod
    def _validate_reviewed_value(cls, value: str) -> str:
        return _bounded_text(value, MAX_REVIEWED_TEXT_LENGTH, "reviewed_value")


class _TextTupleContextReview(_ExplicitContextReviewBase):
    reviewed_value: tuple[str, ...]

    @field_validator("reviewed_value")
    @classmethod
    def _validate_reviewed_value(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _bounded_text_tuple(value, MAX_REVIEWED_TEXT_LENGTH, "reviewed_value")


class CapabilityIdContextReview(_ExplicitContextReviewBase):
    destination_field: Literal["capability_id"] = "capability_id"
    reviewed_value: str

    @field_validator("reviewed_value")
    @classmethod
    def _validate_reviewed_value(cls, value: str) -> str:
        return _require_capability_id(value)


class TargetContextReview(_ExplicitContextReviewBase):
    destination_field: Literal["target"] = "target"
    reviewed_value: ApprovedChangeTarget


class DesiredOutcomeContextReview(_TextContextReview):
    destination_field: Literal["desired_outcome"] = "desired_outcome"


class DiagnosisSummaryContextReview(_TextContextReview):
    destination_field: Literal["diagnosis_summary"] = "diagnosis_summary"


class EvidenceReferencesContextReview(_ExplicitContextReviewBase):
    destination_field: Literal["evidence_references"] = "evidence_references"
    reviewed_value: tuple[EvidenceReference, ...]

    @model_validator(mode="after")
    def _validate_reviewed_value(self) -> EvidenceReferencesContextReview:
        if not self.reviewed_value:
            raise ValueError("at least one evidence reference is required")
        refs = [ref.reference_id for ref in self.reviewed_value]
        if len(refs) != len(set(refs)):
            raise ValueError("evidence reference IDs must be unique")
        return self


class ChangeSummaryContextReview(_TextContextReview):
    destination_field: Literal["change_summary"] = "change_summary"


class BlastRadiusContextReview(_TextContextReview):
    destination_field: Literal["blast_radius"] = "blast_radius"


class ProcedureContextReview(_ExplicitContextReviewBase):
    destination_field: Literal["procedure"] = "procedure"
    reviewed_value: tuple[ProcedureStep, ...]

    @model_validator(mode="after")
    def _validate_reviewed_value(self) -> ProcedureContextReview:
        if not self.reviewed_value:
            raise ValueError("at least one procedure step is required")
        _require_unique_step_ids(self.reviewed_value, "procedure")
        return self


class RevalidationRequirementsContextReview(_TextTupleContextReview):
    destination_field: Literal["revalidation_requirements"] = "revalidation_requirements"


class RollbackPostureContextReview(_ExplicitContextReviewBase):
    destination_field: Literal["rollback_posture"] = "rollback_posture"
    reviewed_value: RollbackPosture


class AuditRequirementsContextReview(_TextTupleContextReview):
    destination_field: Literal["audit_requirements"] = "audit_requirements"


class UnsupportedOrIrreversibleAspectsContextReview(_TextTupleContextReview):
    destination_field: Literal["unsupported_or_irreversible_aspects"] = (
        "unsupported_or_irreversible_aspects"
    )


ExplicitContextReview = Annotated[
    (
        AuditRequirementsContextReview
        | BlastRadiusContextReview
        | CapabilityIdContextReview
        | ChangeSummaryContextReview
        | DesiredOutcomeContextReview
        | DiagnosisSummaryContextReview
        | EvidenceReferencesContextReview
        | ProcedureContextReview
        | RevalidationRequirementsContextReview
        | RollbackPostureContextReview
        | TargetContextReview
        | UnsupportedOrIrreversibleAspectsContextReview
    ),
    Field(discriminator="destination_field"),
]


def canonical_candidate_payload(
    destination_field: str, legacy_source_field: str, candidate_value: Any
) -> dict[str, Any]:
    """Return the deterministic canonical payload bound by a candidate hash."""
    return _canonicalize(
        {
            "schema_version": CANDIDATE_REVIEW_SCHEMA_VERSION,
            "destination_field": destination_field,
            "legacy_source_field": legacy_source_field,
            "candidate_value": candidate_value,
        }
    )


def canonical_candidate_json(
    destination_field: str, legacy_source_field: str, candidate_value: Any
) -> str:
    """Return deterministic canonical candidate JSON (sorted keys, compact, UTF-8)."""
    return json.dumps(
        canonical_candidate_payload(destination_field, legacy_source_field, candidate_value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_candidate_sha256(
    destination_field: str, legacy_source_field: str, candidate_value: Any
) -> str:
    """Compute the reviewed-candidate identity SHA-256.

    This is not a legacy proposal fingerprint, a PR309 subject hash, approval
    binding, or authorization.
    """
    payload = canonical_candidate_json(destination_field, legacy_source_field, candidate_value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class _LegacyCandidateReviewBase(_FrozenModel):
    candidate_sha256: str
    decision: CandidateDecision
    provenance: ReviewProvenance

    @field_validator("candidate_sha256")
    @classmethod
    def _validate_candidate_sha256(cls, value: str) -> str:
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("candidate_sha256 must be 64 lowercase hexadecimal characters")
        return value

    @model_validator(mode="after")
    def _validate_candidate_decision(self) -> _LegacyCandidateReviewBase:
        expected = compute_candidate_sha256(
            self.destination_field, self.legacy_source_field, self.candidate_value
        )
        if expected != self.candidate_sha256:
            raise ValueError(
                f"candidate_sha256 does not match the canonical candidate payload for "
                f"{self.destination_field}"
            )
        if self.decision == "accepted" and self.final_reviewed_value != self.candidate_value:
            raise ValueError(
                f"accepted candidate for {self.destination_field} must keep the exact "
                "candidate value as the final reviewed value"
            )
        if self.decision == "rejected" and self.final_reviewed_value == self.candidate_value:
            raise ValueError(
                f"rejected candidate for {self.destination_field} must differ from the "
                "candidate value; use decision=accepted for an intentionally identical value"
            )
        return self


class _TextCandidateReview(_LegacyCandidateReviewBase):
    candidate_value: str
    final_reviewed_value: str

    @field_validator("candidate_value", "final_reviewed_value")
    @classmethod
    def _validate_text(cls, value: str) -> str:
        return _bounded_text(value, MAX_REVIEWED_TEXT_LENGTH, "candidate value")


class _TextTupleCandidateReview(_LegacyCandidateReviewBase):
    candidate_value: tuple[str, ...]
    final_reviewed_value: tuple[str, ...]

    @field_validator("candidate_value", "final_reviewed_value")
    @classmethod
    def _validate_text_tuple(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _bounded_text_tuple(value, MAX_REVIEWED_TEXT_LENGTH, "candidate value")


class SourceProposalReferenceCandidateReview(_TextCandidateReview):
    destination_field: Literal["source_proposal_reference"] = "source_proposal_reference"
    legacy_source_field: Literal["proposal_id"] = "proposal_id"


class RiskCandidateReview(_LegacyCandidateReviewBase):
    destination_field: Literal["risk"] = "risk"
    legacy_source_field: Literal["risk"] = "risk"
    candidate_value: Literal["low", "medium", "high"]
    final_reviewed_value: Literal["low", "medium", "high"]


class ImpactCandidateReview(_TextCandidateReview):
    destination_field: Literal["impact"] = "impact"
    legacy_source_field: Literal["impact"] = "impact"


class PreconditionsCandidateReview(_TextTupleCandidateReview):
    destination_field: Literal["preconditions"] = "preconditions"
    legacy_source_field: Literal["preconditions"] = "preconditions"


class VerificationCriteriaCandidateReview(_TextTupleCandidateReview):
    destination_field: Literal["verification_criteria"] = "verification_criteria"
    legacy_source_field: Literal["verification"] = "verification"


LegacyCandidateReview = Annotated[
    (
        ImpactCandidateReview
        | PreconditionsCandidateReview
        | RiskCandidateReview
        | SourceProposalReferenceCandidateReview
        | VerificationCriteriaCandidateReview
    ),
    Field(discriminator="destination_field"),
]


class ApprovedChangeSupplementalContext(_FrozenModel):
    """The complete, separately reviewed input package for future construction.

    Holding a valid context does not construct, approve, persist, bind, or
    execute anything. It only records that every non-constant PR309 destination
    has an explicitly reviewed value with review provenance.
    """

    schema_version: Literal["1"] = SUPPLEMENTAL_CONTEXT_SCHEMA_VERSION
    construction_policy_schema_version: Literal["1"] = CONSTRUCTION_POLICY_SCHEMA_VERSION
    approved_change_schema_version: Literal["1"] = APPROVED_CHANGE_SCHEMA_VERSION
    explicit_context_reviews: tuple[ExplicitContextReview, ...]
    legacy_candidate_reviews: tuple[LegacyCandidateReview, ...]

    @model_validator(mode="after")
    def _freeze_sequences(self) -> ApprovedChangeSupplementalContext:
        object.__setattr__(self, "explicit_context_reviews", tuple(self.explicit_context_reviews))
        object.__setattr__(self, "legacy_candidate_reviews", tuple(self.legacy_candidate_reviews))
        return self


class SupplementalContextValidationResult(_FrozenModel):
    """Structured, non-throwing reviewed-context validation result."""

    status: ValidationStatus
    context_valid: bool
    coverage_complete: bool
    computed_supplemental_context_sha256: str
    expected_destination_fields: tuple[str, ...]
    covered_destination_fields: tuple[str, ...]
    missing_destination_fields: tuple[str, ...]
    duplicate_destination_fields: tuple[str, ...]
    unknown_destination_fields: tuple[str, ...]
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_WARNINGS
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    subject_created: Literal[False] = False
    contract_created: Literal[False] = False
    approval_created: Literal[False] = False
    persistence_performed: Literal[False] = False
    receipt_created: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


def canonical_supplemental_context_payload(
    context: ApprovedChangeSupplementalContext,
) -> dict[str, Any]:
    """Return the deterministic canonical payload bound by the context hash."""
    payload = context.model_dump(mode="python")
    payload["explicit_context_reviews"] = [
        _canonical_explicit_review(review)
        for review in sorted(
            payload["explicit_context_reviews"], key=lambda item: item["destination_field"]
        )
    ]
    payload["legacy_candidate_reviews"] = sorted(
        payload["legacy_candidate_reviews"], key=lambda item: item["destination_field"]
    )
    return _canonicalize(payload)


def _canonical_explicit_review(review: dict[str, Any]) -> dict[str, Any]:
    """Apply PR309 canonical ordering to set-like reviewed values."""
    destination = review["destination_field"]
    if destination == "target":
        review["reviewed_value"]["identity_claims"] = sorted(
            review["reviewed_value"]["identity_claims"],
            key=lambda item: (item["key"], item["value"]),
        )
    elif destination == "evidence_references":
        review["reviewed_value"] = sorted(
            review["reviewed_value"], key=lambda item: item["reference_id"]
        )
    return review


def canonical_supplemental_context_json(context: ApprovedChangeSupplementalContext) -> str:
    """Return deterministic canonical context JSON (sorted keys, compact, UTF-8)."""
    return json.dumps(
        canonical_supplemental_context_payload(context),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_supplemental_context_sha256(context: ApprovedChangeSupplementalContext) -> str:
    """Compute the reviewed-input (supplemental-context) identity SHA-256.

    This identity is never a PR309 subject SHA-256, an approval hash, a legacy
    proposal fingerprint, or execution confirmation.
    """
    return hashlib.sha256(canonical_supplemental_context_json(context).encode("utf-8")).hexdigest()


def _raw_destinations(data: Any, key: str) -> tuple[str, ...]:
    """Best-effort destination extraction from untrusted input for reporting."""
    if not isinstance(data, dict):
        return ()
    section = data.get(key)
    if not isinstance(section, (list, tuple)):
        return ()
    out: list[str] = []
    for item in section:
        dest = item.get("destination_field") if isinstance(item, dict) else None
        out.append(dest if isinstance(dest, str) else "")
    return tuple(out)


def _result(
    status: ValidationStatus,
    errors: list[str],
    *,
    context_sha256: str,
    covered: tuple[str, ...],
    missing: tuple[str, ...],
    duplicate: tuple[str, ...],
    unknown: tuple[str, ...],
) -> SupplementalContextValidationResult:
    unique_errors = tuple(sorted(set(errors)))
    return SupplementalContextValidationResult(
        status=status,
        context_valid=status == "supplemental_context_valid",
        coverage_complete=not missing and not duplicate and not unknown,
        computed_supplemental_context_sha256=context_sha256,
        expected_destination_fields=tuple(sorted(ApprovedChangeSubject.model_fields)),
        covered_destination_fields=covered,
        missing_destination_fields=missing,
        duplicate_destination_fields=duplicate,
        unknown_destination_fields=unknown,
        errors=unique_errors,
    )


def _coverage(
    explicit: tuple[str, ...], candidates: tuple[str, ...]
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    expected = set(ApprovedChangeSubject.model_fields)
    seen = tuple(CONTRACT_CONSTANT_FIELDS) + explicit + candidates
    counts = Counter(field for field in seen if field)
    duplicate = tuple(sorted(field for field, count in counts.items() if count > 1))
    covered = tuple(sorted(set(counts) & expected))
    missing = tuple(sorted(expected - set(counts)))
    unknown = tuple(sorted(set(counts) - expected))
    return covered, missing, duplicate, unknown


def _validate_sections(
    context: ApprovedChangeSupplementalContext, errors: list[str]
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    explicit = tuple(review.destination_field for review in context.explicit_context_reviews)
    candidates = tuple(review.destination_field for review in context.legacy_candidate_reviews)
    if explicit != tuple(sorted(explicit)):
        errors.append("explicit_context_reviews must be sorted deterministically by destination")
    if candidates != tuple(sorted(candidates)):
        errors.append("legacy_candidate_reviews must be sorted deterministically by destination")
    if set(explicit) != set(EXPLICIT_CONTEXT_DESTINATIONS) or len(explicit) != len(
        EXPLICIT_CONTEXT_DESTINATIONS
    ):
        errors.append(
            "explicit_context_reviews must contain exactly one review for each of the "
            f"{len(EXPLICIT_CONTEXT_DESTINATIONS)} explicit-context destinations"
        )
    if set(candidates) != set(CANDIDATE_DESTINATIONS) or len(candidates) != len(
        CANDIDATE_DESTINATIONS
    ):
        errors.append(
            "legacy_candidate_reviews must contain exactly one review for each of the "
            f"{len(CANDIDATE_DESTINATIONS)} allowlisted candidate destinations"
        )
    if set(explicit) & set(candidates):
        errors.append("a destination may not be both explicit-context and candidate sourced")
    return explicit, candidates


def _validate_candidates(context: ApprovedChangeSupplementalContext, errors: list[str]) -> None:
    allowed = dict(CANDIDATE_DESTINATION_SOURCES)
    for review in context.legacy_candidate_reviews:
        destination = review.destination_field
        source = review.legacy_source_field
        if allowed.get(destination) != source:
            errors.append(f"candidate mapping is not allowlisted: {source} -> {destination}")
        expected = compute_candidate_sha256(destination, source, review.candidate_value)
        if expected != review.candidate_sha256:
            errors.append(f"candidate_sha256 mismatch for {destination}")
        if review.decision == "accepted" and review.final_reviewed_value != review.candidate_value:
            errors.append(f"accepted candidate value mismatch for {destination}")
        if review.decision == "rejected" and review.final_reviewed_value == review.candidate_value:
            errors.append(f"rejected candidate must change the final value for {destination}")


def _validate_versions(context: ApprovedChangeSupplementalContext, errors: list[str]) -> None:
    if context.schema_version != SUPPLEMENTAL_CONTEXT_SCHEMA_VERSION:
        errors.append("supplemental-context schema_version mismatch")
    if context.construction_policy_schema_version != CONSTRUCTION_POLICY_SCHEMA_VERSION:
        errors.append("construction_policy_schema_version mismatch")
    if context.approved_change_schema_version != APPROVED_CHANGE_SCHEMA_VERSION:
        errors.append("approved_change_schema_version mismatch")


def validate_approved_change_supplemental_context(
    context: ApprovedChangeSupplementalContext | dict[str, Any],
) -> SupplementalContextValidationResult:
    """Validate a reviewed supplemental context without throwing or mutating.

    Untrusted dictionaries are parsed defensively: a malformed payload returns a
    structured invalid result instead of raising or producing a partial object.
    A valid result reports only that reviewed input coverage is complete; it
    grants no construction, approval, persistence, binding, or execution.
    """
    errors: list[str] = []
    if not isinstance(context, ApprovedChangeSupplementalContext):
        if not isinstance(context, dict):
            covered, missing, duplicate, unknown = _coverage((), ())
            return _result(
                "invalid_validation_input",
                ["supplemental context must be a model instance or a mapping"],
                context_sha256="",
                covered=covered,
                missing=missing,
                duplicate=duplicate,
                unknown=unknown,
            )
        raw_explicit = _raw_destinations(context, "explicit_context_reviews")
        raw_candidates = _raw_destinations(context, "legacy_candidate_reviews")
        try:
            context = ApprovedChangeSupplementalContext.model_validate(context)
        except Exception as exc:  # pydantic exposes many structured subclasses.
            covered, missing, duplicate, unknown = _coverage(raw_explicit, raw_candidates)
            return _result(
                "supplemental_context_invalid",
                [f"supplemental context model validation failed: {exc}"],
                context_sha256="",
                covered=covered,
                missing=missing,
                duplicate=duplicate,
                unknown=unknown,
            )

    explicit, candidates = _validate_sections(context, errors)
    _validate_candidates(context, errors)
    _validate_versions(context, errors)
    covered, missing, duplicate, unknown = _coverage(explicit, candidates)
    for field in missing:
        errors.append(f"missing destination field: {field}")
    for field in duplicate:
        errors.append(f"duplicate destination field: {field}")
    for field in unknown:
        errors.append(f"unknown destination field: {field}")
    status: ValidationStatus = (
        "supplemental_context_valid" if not errors else "supplemental_context_invalid"
    )
    return _result(
        status,
        errors,
        context_sha256=compute_supplemental_context_sha256(context),
        covered=covered,
        missing=missing,
        duplicate=duplicate,
        unknown=unknown,
    )
