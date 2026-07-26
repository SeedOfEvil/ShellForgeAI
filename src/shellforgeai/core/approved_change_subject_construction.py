"""Reviewed approved-change subject construction (PR315).

This module adds exactly one pure, deterministic, fail-closed, in-memory
operation: given a complete PR314 reviewed supplemental context plus an explicit
expected supplemental-context SHA-256, construct exactly one PR309
``ApprovedChangeSubject`` together with immutable field-by-field construction
evidence.

It is deliberately inert. It loads no legacy ``Proposal``, extracts no candidate
values, infers nothing, defaults nothing, transforms nothing, creates no
``ApprovalAttestation`` or ``ApprovedChangeContract``, persists nothing, binds no
capability, evaluates no capability support, runs no preflight, links no
receipt, and enables no execution.

Private canonicalization helpers are imported from the PR309 contract module on
purpose: constructed field identities must obey exactly the same canonical
ordering and timestamp rules as the PR309 destination schema.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections import Counter
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from shellforgeai.core.approved_change_construction_policy import (
    APPROVED_CHANGE_CONSTRUCTION_POLICY,
    CONSTRUCTION_POLICY_SCHEMA_VERSION,
    CONTRACT_CONSTANT_FIELDS,
    ApprovedChangeConstructionPolicy,
    validate_approved_change_construction_policy,
)
from shellforgeai.core.approved_change_contract import (
    SCHEMA_VERSION as APPROVED_CHANGE_SCHEMA_VERSION,
)
from shellforgeai.core.approved_change_contract import (
    ApprovedChangeSubject,
    _canonicalize,
    compute_subject_sha256,
)
from shellforgeai.core.approved_change_supplemental_context import (
    CANDIDATE_DESTINATION_SOURCES,
    CANDIDATE_DESTINATIONS,
    EXPLICIT_CONTEXT_DESTINATIONS,
    SUPPLEMENTAL_CONTEXT_SCHEMA_VERSION,
    ApprovedChangeSupplementalContext,
    CandidateDecision,
    ReviewProvenance,
    compute_supplemental_context_sha256,
    validate_approved_change_supplemental_context,
)

CONSTRUCTION_EVIDENCE_SCHEMA_VERSION = "1"
FIELD_VALUE_IDENTITY_SCHEMA_VERSION = "1"
EXECUTION_STATUS_NOT_EXECUTED = "not_executed"

#: The PR309 schema constant is the only non-reviewed value authority.
CONTRACT_CONSTANT_SOURCE_AUTHORITY = "approved_change_contract.SCHEMA_VERSION"
EXPLICIT_CONTEXT_SECTION = "explicit_context_reviews"
LEGACY_CANDIDATE_SECTION = "legacy_candidate_reviews"

CONSTRUCTION_STATUSES = (
    "subject_constructed",
    "construction_blocked",
    "invalid_construction_input",
)

ConstructionStatus = Literal[
    "subject_constructed",
    "construction_blocked",
    "invalid_construction_input",
]
AuthorityKind = Literal[
    "contract_constant",
    "explicit_context_reviewed_value",
    "legacy_candidate_final_reviewed_value",
]

#: PR311 source classification -> PR315 field-authority kind. There is no other
#: classification, no wildcard entry, and no fallback entry.
POLICY_CLASSIFICATION_AUTHORITY_KINDS: tuple[tuple[str, str], ...] = (
    ("contract_constant", "contract_constant"),
    ("explicit_context_only", "explicit_context_reviewed_value"),
    (
        "legacy_candidate_requires_explicit_review",
        "legacy_candidate_final_reviewed_value",
    ),
)

PERMANENT_CONSTRUCTION_WARNINGS: tuple[str, ...] = (
    "a constructed subject is not approved, authorized, bound, persisted, or executable",
    "capability support was not evaluated; a syntactically valid capability_id is not support",
    "construction evidence is field-authority bookkeeping, not an approval attestation",
    "review provenance is not authenticated identity, approval, authorization, or execution "
    "confirmation",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Field-value identity
# ---------------------------------------------------------------------------


def _canonical_field_value(destination_field: str, value: Any) -> Any:
    """Apply PR309 canonical ordering to set-like destination values."""
    canonical = _canonicalize(value)
    if destination_field == "target" and isinstance(canonical, dict):
        claims = canonical.get("identity_claims")
        if isinstance(claims, list):
            canonical["identity_claims"] = sorted(
                claims, key=lambda item: (item["key"], item["value"])
            )
    elif destination_field == "evidence_references" and isinstance(canonical, list):
        canonical = sorted(canonical, key=lambda item: item["reference_id"])
    return canonical


def canonical_field_value_payload(destination_field: str, value: Any) -> dict[str, Any]:
    """Return the deterministic canonical payload bound by a field-value identity."""
    return {
        "schema_version": FIELD_VALUE_IDENTITY_SCHEMA_VERSION,
        "destination_field": destination_field,
        "value": _canonical_field_value(destination_field, value),
    }


def canonical_field_value_json(destination_field: str, value: Any) -> str:
    """Return deterministic canonical field-value JSON (sorted keys, compact, UTF-8)."""
    return json.dumps(
        canonical_field_value_payload(destination_field, value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_constructed_field_value_sha256(destination_field: str, value: Any) -> str:
    """Compute one constructed destination field's value identity.

    This is field audit metadata only. It is not a subject hash, a candidate
    hash, a supplemental-context hash, an approval hash, a legacy fingerprint,
    approval, authorization, or execution eligibility.
    """
    payload = canonical_field_value_json(destination_field, value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Field-authority evidence records
# ---------------------------------------------------------------------------


class ContractConstantFieldAuthority(_FrozenModel):
    """Authority record for the single PR309 contract-constant destination.

    It has no reviewer provenance because no reviewer supplies the value.
    """

    destination_field: Literal["schema_version"] = "schema_version"
    authority_kind: Literal["contract_constant"] = "contract_constant"
    source_authority: Literal["approved_change_contract.SCHEMA_VERSION"] = (
        CONTRACT_CONSTANT_SOURCE_AUTHORITY
    )
    final_value_sha256: str
    subject_field_matches: Literal[True] = True


class ExplicitContextFieldAuthority(_FrozenModel):
    """Authority record binding one destination to a PR314 ``reviewed_value``."""

    destination_field: str
    authority_kind: Literal["explicit_context_reviewed_value"] = "explicit_context_reviewed_value"
    source_section: Literal["explicit_context_reviews"] = EXPLICIT_CONTEXT_SECTION
    source_destination_field: str
    provenance: ReviewProvenance
    final_value_sha256: str
    subject_field_matches: Literal[True] = True


class LegacyCandidateFieldAuthority(_FrozenModel):
    """Authority record binding one destination to a ``final_reviewed_value``.

    The bound value is always the reviewed final value. A rejected candidate's
    raw ``candidate_value`` never reaches the constructed subject; it is
    represented here only by its candidate SHA-256 and decision.
    """

    destination_field: str
    authority_kind: Literal["legacy_candidate_final_reviewed_value"] = (
        "legacy_candidate_final_reviewed_value"
    )
    source_section: Literal["legacy_candidate_reviews"] = LEGACY_CANDIDATE_SECTION
    legacy_source_field: str
    candidate_decision: CandidateDecision
    candidate_sha256: str
    provenance: ReviewProvenance
    final_value_sha256: str
    subject_field_matches: Literal[True] = True


ConstructedFieldAuthority = Annotated[
    (
        ContractConstantFieldAuthority
        | ExplicitContextFieldAuthority
        | LegacyCandidateFieldAuthority
    ),
    Field(discriminator="authority_kind"),
]


class ApprovedChangeSubjectConstructionEvidence(_FrozenModel):
    """Immutable, deterministic field-by-field construction evidence.

    It records which authority supplied every PR309 destination field, binds the
    exact reviewed input identity to the exact constructed subject identity, and
    grants nothing. It carries no implicit timestamp: determinism relies only on
    reviewed input and maintained schema/policy state.
    """

    schema_version: Literal["1"] = CONSTRUCTION_EVIDENCE_SCHEMA_VERSION
    approved_change_schema_version: Literal["1"] = APPROVED_CHANGE_SCHEMA_VERSION
    construction_policy_schema_version: Literal["1"] = CONSTRUCTION_POLICY_SCHEMA_VERSION
    supplemental_context_schema_version: Literal["1"] = SUPPLEMENTAL_CONTEXT_SCHEMA_VERSION
    supplemental_context_sha256: str
    subject_sha256: str
    field_authorities: tuple[ConstructedFieldAuthority, ...]
    warnings: tuple[str, ...] = PERMANENT_CONSTRUCTION_WARNINGS

    @model_validator(mode="after")
    def _freeze_sequences(self) -> ApprovedChangeSubjectConstructionEvidence:
        object.__setattr__(self, "field_authorities", tuple(self.field_authorities))
        object.__setattr__(self, "warnings", tuple(self.warnings))
        return self


class ApprovedChangeSubjectConstructionResult(_FrozenModel):
    """Structured, non-throwing reviewed-construction result.

    A successful result means one exact reviewed subject was assembled in
    memory. It never means the subject was approved, authorized, bound to a
    capability, persisted, or made executable.
    """

    status: ConstructionStatus
    construction_succeeded: bool
    expected_supplemental_context_sha256: str
    computed_supplemental_context_sha256: str
    computed_subject_sha256: str
    computed_construction_evidence_sha256: str
    subject: ApprovedChangeSubject | None = None
    construction_evidence: ApprovedChangeSubjectConstructionEvidence | None = None
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_CONSTRUCTION_WARNINGS
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    construction_performed: bool
    subject_created: bool
    approval_created: Literal[False] = False
    contract_created: Literal[False] = False
    persistence_performed: Literal[False] = False
    receipt_created: Literal[False] = False
    capability_support_evaluated: Literal[False] = False
    capability_supported: Literal[False] = False
    approval_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


# ---------------------------------------------------------------------------
# Canonical construction-evidence identity
# ---------------------------------------------------------------------------


def canonical_construction_evidence_payload(
    evidence: ApprovedChangeSubjectConstructionEvidence,
) -> dict[str, Any]:
    """Return the deterministic canonical payload bound by the evidence hash.

    The evidence SHA-256 is never included in its own canonical payload.
    """
    payload = evidence.model_dump(mode="python")
    payload["field_authorities"] = sorted(
        payload["field_authorities"], key=lambda item: item["destination_field"]
    )
    return _canonicalize(payload)


def canonical_construction_evidence_json(
    evidence: ApprovedChangeSubjectConstructionEvidence,
) -> str:
    """Return deterministic canonical evidence JSON (sorted keys, compact, UTF-8)."""
    return json.dumps(
        canonical_construction_evidence_payload(evidence),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_construction_evidence_sha256(
    evidence: ApprovedChangeSubjectConstructionEvidence,
) -> str:
    """Compute the construction-evidence identity SHA-256.

    This identity is distinct from the reviewed supplemental-context identity
    and from the PR309 subject identity. It is not an approval hash, a legacy
    fingerprint, or execution confirmation.
    """
    payload = canonical_construction_evidence_json(evidence)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Structured results
# ---------------------------------------------------------------------------


def _echo_expected(expected: Any) -> str:
    return expected if isinstance(expected, str) else ""


def _blocked(
    status: ConstructionStatus,
    errors: list[str],
    *,
    expected: Any,
    computed_context_sha256: str = "",
) -> ApprovedChangeSubjectConstructionResult:
    """Return a fail-closed result carrying no subject and no evidence."""
    return ApprovedChangeSubjectConstructionResult(
        status=status,
        construction_succeeded=False,
        expected_supplemental_context_sha256=_echo_expected(expected),
        computed_supplemental_context_sha256=computed_context_sha256,
        computed_subject_sha256="",
        computed_construction_evidence_sha256="",
        subject=None,
        construction_evidence=None,
        errors=tuple(sorted(set(errors))),
        construction_performed=False,
        subject_created=False,
    )


# ---------------------------------------------------------------------------
# Fresh policy verification
# ---------------------------------------------------------------------------


def _policy_authority_kinds(policy: Any) -> tuple[dict[str, str], list[str]]:
    """Return destination -> expected authority kind under the live PR311 policy."""
    errors: list[str] = []
    classification_kinds = dict(POLICY_CLASSIFICATION_AUTHORITY_KINDS)
    if not isinstance(policy, ApprovedChangeConstructionPolicy):
        return {}, ["canonical construction policy is not the maintained policy model"]
    rules = policy.rules
    destinations = tuple(rule.destination_field for rule in rules)
    counts = Counter(destinations)
    for destination, count in sorted(counts.items()):
        if count > 1:
            errors.append(f"duplicate policy authority for destination: {destination}")

    kinds: dict[str, str] = {}
    constants: list[str] = []
    explicit: list[str] = []
    candidates: dict[str, str] = {}
    for rule in rules:
        destination = rule.destination_field
        classification = rule.source_classification
        if classification not in classification_kinds:
            errors.append(f"unknown policy source classification on {destination}")
            continue
        if (
            rule.auto_copy_allowed
            or rule.inference_allowed
            or rule.default_allowed
            or rule.approval_portable
            or rule.fingerprint_reusable
        ):
            errors.append(f"permanent false policy safety flag enabled on {destination}")
        kinds[destination] = classification_kinds[classification]
        if classification == "contract_constant":
            constants.append(destination)
        elif classification == "explicit_context_only":
            explicit.append(destination)
            if rule.legacy_candidate_fields:
                errors.append(
                    f"explicit-context destination carries a legacy candidate: {destination}"
                )
        else:
            if len(rule.legacy_candidate_fields) != 1:
                errors.append(
                    f"candidate destination must map exactly one legacy field: {destination}"
                )
                continue
            candidates[destination] = rule.legacy_candidate_fields[0]

    if tuple(sorted(constants)) != tuple(sorted(CONTRACT_CONSTANT_FIELDS)):
        errors.append("policy must define exactly one contract-constant destination")
    if tuple(sorted(explicit)) != EXPLICIT_CONTEXT_DESTINATIONS:
        errors.append(
            "policy must define exactly the "
            f"{len(EXPLICIT_CONTEXT_DESTINATIONS)} explicit-context destinations"
        )
    if tuple(sorted(candidates.items())) != CANDIDATE_DESTINATION_SOURCES:
        errors.append(
            "policy must define exactly the "
            f"{len(CANDIDATE_DESTINATION_SOURCES)} reviewed candidate mappings"
        )
    expected_fields = set(ApprovedChangeSubject.model_fields)
    if set(kinds) != expected_fields:
        errors.append("policy destination coverage does not match the PR309 subject schema")
    return kinds, errors


def _verify_construction_policy() -> tuple[dict[str, str], list[str]]:
    """Freshly validate the maintained canonical PR311 policy."""
    policy = APPROVED_CHANGE_CONSTRUCTION_POLICY
    result = validate_approved_change_construction_policy(policy)
    errors: list[str] = []
    if result.status != "policy_valid" or not result.policy_valid:
        errors.append("canonical construction policy is not policy_valid")
    if not result.coverage_complete:
        errors.append("canonical construction policy coverage is incomplete")
    errors.extend(f"construction policy error: {error}" for error in result.errors)
    kinds, mapping_errors = _policy_authority_kinds(policy)
    errors.extend(mapping_errors)
    return kinds, errors


# ---------------------------------------------------------------------------
# Reviewed input reconfirmation
# ---------------------------------------------------------------------------


def _reviewed_sections(
    context: ApprovedChangeSupplementalContext,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """Reconfirm exact PR314 destination coverage and exact candidate mappings."""
    errors: list[str] = []
    explicit: dict[str, Any] = {}
    for review in context.explicit_context_reviews:
        if review.destination_field in explicit:
            errors.append(f"duplicate explicit-context review: {review.destination_field}")
        explicit[review.destination_field] = review
    candidates: dict[str, Any] = {}
    for review in context.legacy_candidate_reviews:
        if review.destination_field in candidates:
            errors.append(f"duplicate candidate review: {review.destination_field}")
        candidates[review.destination_field] = review

    if tuple(sorted(explicit)) != EXPLICIT_CONTEXT_DESTINATIONS:
        errors.append(
            "reviewed context must supply exactly the "
            f"{len(EXPLICIT_CONTEXT_DESTINATIONS)} explicit-context destinations"
        )
    if tuple(sorted(candidates)) != CANDIDATE_DESTINATIONS:
        errors.append(
            "reviewed context must supply exactly the "
            f"{len(CANDIDATE_DESTINATIONS)} reviewed candidate destinations"
        )
    allowed_sources = dict(CANDIDATE_DESTINATION_SOURCES)
    for destination, review in sorted(candidates.items()):
        source = review.legacy_source_field
        if allowed_sources.get(destination) != source:
            errors.append(f"candidate mapping is not allowlisted: {source} -> {destination}")
    if set(explicit) & set(candidates):
        errors.append("a destination may not be both explicit-context and candidate sourced")
    return explicit, candidates, errors


def _verify_authority_classes(kinds: dict[str, str], errors: list[str]) -> None:
    """Confirm the live policy classifies every destination exactly as PR315 uses it."""
    if kinds.get("schema_version") != "contract_constant":
        errors.append("policy no longer classifies schema_version as the contract constant")
    for destination in EXPLICIT_CONTEXT_DESTINATIONS:
        if kinds.get(destination) != "explicit_context_reviewed_value":
            errors.append(f"policy no longer classifies {destination} as explicit-context only")
    for destination in CANDIDATE_DESTINATIONS:
        if kinds.get(destination) != "legacy_candidate_final_reviewed_value":
            errors.append(f"policy no longer classifies {destination} as a reviewed candidate")


# ---------------------------------------------------------------------------
# Explicit, exhaustive field authority mapping
# ---------------------------------------------------------------------------


def _subject_payload(explicit: dict[str, Any], candidates: dict[str, Any]) -> dict[str, Any]:
    """Build the one explicit, exhaustive PR309 subject payload.

    Every destination is named literally. There is no generic copy loop, no
    wildcard lookup, no dynamic passthrough, no default, and no inference. The
    contract constant comes from the PR309 schema constant; the 12 explicit
    destinations come only from ``reviewed_value``; the five candidate-backed
    destinations come only from ``final_reviewed_value``.
    """
    return {
        "schema_version": APPROVED_CHANGE_SCHEMA_VERSION,
        "audit_requirements": explicit["audit_requirements"].reviewed_value,
        "blast_radius": explicit["blast_radius"].reviewed_value,
        "capability_id": explicit["capability_id"].reviewed_value,
        "change_summary": explicit["change_summary"].reviewed_value,
        "desired_outcome": explicit["desired_outcome"].reviewed_value,
        "diagnosis_summary": explicit["diagnosis_summary"].reviewed_value,
        "evidence_references": explicit["evidence_references"].reviewed_value,
        "procedure": explicit["procedure"].reviewed_value,
        "revalidation_requirements": explicit["revalidation_requirements"].reviewed_value,
        "rollback_posture": explicit["rollback_posture"].reviewed_value,
        "target": explicit["target"].reviewed_value,
        "unsupported_or_irreversible_aspects": explicit[
            "unsupported_or_irreversible_aspects"
        ].reviewed_value,
        "source_proposal_reference": candidates["source_proposal_reference"].final_reviewed_value,
        "risk": candidates["risk"].final_reviewed_value,
        "impact": candidates["impact"].final_reviewed_value,
        "preconditions": candidates["preconditions"].final_reviewed_value,
        "verification_criteria": candidates["verification_criteria"].final_reviewed_value,
    }


def _subject_field_values(subject: ApprovedChangeSubject) -> dict[str, Any]:
    """Read back every PR309 destination explicitly, with no dynamic attribute access."""
    return {
        "schema_version": subject.schema_version,
        "audit_requirements": subject.audit_requirements,
        "blast_radius": subject.blast_radius,
        "capability_id": subject.capability_id,
        "change_summary": subject.change_summary,
        "desired_outcome": subject.desired_outcome,
        "diagnosis_summary": subject.diagnosis_summary,
        "evidence_references": subject.evidence_references,
        "impact": subject.impact,
        "preconditions": subject.preconditions,
        "procedure": subject.procedure,
        "revalidation_requirements": subject.revalidation_requirements,
        "risk": subject.risk,
        "rollback_posture": subject.rollback_posture,
        "source_proposal_reference": subject.source_proposal_reference,
        "target": subject.target,
        "unsupported_or_irreversible_aspects": subject.unsupported_or_irreversible_aspects,
        "verification_criteria": subject.verification_criteria,
    }


def _build_field_authorities(
    explicit: dict[str, Any],
    candidates: dict[str, Any],
    subject_values: dict[str, Any],
) -> tuple[ConstructedFieldAuthority, ...]:
    """Build exactly one deterministic authority record per PR309 destination."""
    authorities: list[Any] = [
        ContractConstantFieldAuthority(
            final_value_sha256=compute_constructed_field_value_sha256(
                "schema_version", subject_values["schema_version"]
            )
        )
    ]
    for destination in EXPLICIT_CONTEXT_DESTINATIONS:
        review = explicit[destination]
        authorities.append(
            ExplicitContextFieldAuthority(
                destination_field=destination,
                source_destination_field=review.destination_field,
                provenance=review.provenance,
                final_value_sha256=compute_constructed_field_value_sha256(
                    destination, subject_values[destination]
                ),
            )
        )
    for destination in CANDIDATE_DESTINATIONS:
        review = candidates[destination]
        authorities.append(
            LegacyCandidateFieldAuthority(
                destination_field=destination,
                legacy_source_field=review.legacy_source_field,
                candidate_decision=review.decision,
                candidate_sha256=review.candidate_sha256,
                provenance=review.provenance,
                final_value_sha256=compute_constructed_field_value_sha256(
                    destination, subject_values[destination]
                ),
            )
        )
    return tuple(sorted(authorities, key=lambda record: record.destination_field))


# ---------------------------------------------------------------------------
# Evidence verification
# ---------------------------------------------------------------------------


def _verify_contract_constant_authority(record: Any, subject_values: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(record, ContractConstantFieldAuthority):
        return ["schema_version authority record has the wrong authority type"]
    if record.source_authority != CONTRACT_CONSTANT_SOURCE_AUTHORITY:
        errors.append("schema_version authority does not name the PR309 schema constant")
    if subject_values["schema_version"] != APPROVED_CHANGE_SCHEMA_VERSION:
        errors.append("constructed schema_version does not equal the PR309 schema constant")
    return errors


def _verify_explicit_authority(
    record: Any, explicit: dict[str, Any], subject_values: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    destination = record.destination_field
    if not isinstance(record, ExplicitContextFieldAuthority):
        return [f"{destination} authority record has the wrong authority type"]
    review = explicit[destination]
    if record.source_section != EXPLICIT_CONTEXT_SECTION:
        errors.append(f"{destination} authority names the wrong reviewed section")
    if record.source_destination_field != review.destination_field:
        errors.append(f"{destination} authority names another destination's review")
    if record.provenance != review.provenance:
        errors.append(f"{destination} authority provenance does not match the reviewed record")
    if subject_values[destination] != review.reviewed_value:
        errors.append(f"{destination} subject value does not equal the reviewed value")
    return errors


def _verify_candidate_authority(
    record: Any, candidates: dict[str, Any], subject_values: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    destination = record.destination_field
    if not isinstance(record, LegacyCandidateFieldAuthority):
        return [f"{destination} authority record has the wrong authority type"]
    review = candidates[destination]
    if record.source_section != LEGACY_CANDIDATE_SECTION:
        errors.append(f"{destination} authority names the wrong reviewed section")
    if record.legacy_source_field != review.legacy_source_field:
        errors.append(f"{destination} authority names the wrong legacy source field")
    if record.candidate_decision != review.decision:
        errors.append(f"{destination} authority records the wrong candidate decision")
    if record.candidate_sha256 != review.candidate_sha256:
        errors.append(f"{destination} authority records the wrong candidate identity")
    if record.provenance != review.provenance:
        errors.append(f"{destination} authority provenance does not match the reviewed record")
    if subject_values[destination] != review.final_reviewed_value:
        errors.append(f"{destination} subject value does not equal the final reviewed value")
    return errors


def _verify_field_authorities(
    authorities: tuple[Any, ...],
    kinds: dict[str, str],
    explicit: dict[str, Any],
    candidates: dict[str, Any],
    subject_values: dict[str, Any],
) -> list[str]:
    """Prove the evidence exactly describes the constructed subject before success."""
    errors: list[str] = []
    destinations = tuple(record.destination_field for record in authorities)
    expected = tuple(sorted(ApprovedChangeSubject.model_fields))
    counts = Counter(destinations)
    for destination, count in sorted(counts.items()):
        if count > 1:
            errors.append(f"duplicate field authority: {destination}")
    for destination in sorted(set(expected) - set(destinations)):
        errors.append(f"missing field authority: {destination}")
    for destination in sorted(set(destinations) - set(expected)):
        errors.append(f"unknown field authority: {destination}")
    if destinations != tuple(sorted(destinations)):
        errors.append("field authorities must be sorted deterministically by destination field")
    if set(subject_values) != set(expected):
        errors.append("constructed subject fields do not match the PR309 subject schema")
    if errors:
        return errors

    for record in authorities:
        destination = record.destination_field
        if kinds.get(destination) != record.authority_kind:
            errors.append(f"{destination} authority classification does not match the policy")
            continue
        if record.authority_kind == "contract_constant":
            errors.extend(_verify_contract_constant_authority(record, subject_values))
        elif record.authority_kind == "explicit_context_reviewed_value":
            errors.extend(_verify_explicit_authority(record, explicit, subject_values))
        else:
            errors.extend(_verify_candidate_authority(record, candidates, subject_values))
        if record.subject_field_matches is not True:
            errors.append(f"{destination} authority does not assert a subject-field match")
        if record.final_value_sha256 != compute_constructed_field_value_sha256(
            destination, subject_values[destination]
        ):
            errors.append(
                f"{destination} authority final value identity does not match the subject"
            )
    return errors


# ---------------------------------------------------------------------------
# Public construction operation
# ---------------------------------------------------------------------------


def construct_approved_change_subject(
    context: ApprovedChangeSupplementalContext | dict[str, Any],
    *,
    expected_supplemental_context_sha256: str,
) -> ApprovedChangeSubjectConstructionResult:
    """Construct exactly one PR309 subject from a reviewed PR314 context.

    The operation is pure, deterministic, and fail closed. It accepts only a
    reviewed supplemental context plus the exact expected supplemental-context
    SHA-256. It accepts no legacy ``Proposal``, field mapping, policy override,
    capability registry, approval metadata, execution object, or arbitrary
    destination value.

    A successful result carries one subject and one construction-evidence
    object. Every failure returns a structured result with no subject, no
    evidence, no partial authority map, and no approval, persistence, capability
    support, or execution claim.
    """
    expected = expected_supplemental_context_sha256

    # 1. Expected supplemental-context identity format.
    if not isinstance(expected, str) or not _SHA256_RE.fullmatch(expected):
        return _blocked(
            "invalid_construction_input",
            [
                "expected_supplemental_context_sha256 must be 64 lowercase hexadecimal characters",
            ],
            expected=expected,
        )

    # 2. Fresh canonical PR311 construction-policy validation.
    kinds, policy_errors = _verify_construction_policy()
    if policy_errors:
        return _blocked("construction_blocked", policy_errors, expected=expected)

    # 3. Fresh PR314 reviewed-context validation.
    if isinstance(context, ApprovedChangeSupplementalContext):
        parsed = context
    elif isinstance(context, dict):
        try:
            parsed = ApprovedChangeSupplementalContext.model_validate(context)
        except Exception as exc:  # pydantic exposes many structured subclasses.
            fallback = validate_approved_change_supplemental_context(context)
            return _blocked(
                "invalid_construction_input",
                [f"supplemental context model validation failed: {exc}", *fallback.errors],
                expected=expected,
            )
    else:
        return _blocked(
            "invalid_construction_input",
            ["supplemental context must be a model instance or a mapping"],
            expected=expected,
        )

    validation = validate_approved_change_supplemental_context(parsed)
    if (
        validation.status != "supplemental_context_valid"
        or not validation.context_valid
        or not validation.coverage_complete
    ):
        return _blocked(
            "construction_blocked",
            ["reviewed supplemental context is not valid", *validation.errors],
            expected=expected,
        )

    # 4-5. Recompute and constant-time compare the reviewed-input identity.
    computed_context_sha256 = compute_supplemental_context_sha256(parsed)
    if not hmac.compare_digest(computed_context_sha256, expected):
        return _blocked(
            "construction_blocked",
            [
                "expected_supplemental_context_sha256 does not match the reviewed context identity",
            ],
            expected=expected,
            computed_context_sha256=computed_context_sha256,
        )

    # 6. Reconfirm exact destination coverage and authority classes.
    explicit, candidates, section_errors = _reviewed_sections(parsed)
    _verify_authority_classes(kinds, section_errors)
    if section_errors:
        return _blocked(
            "construction_blocked",
            section_errors,
            expected=expected,
            computed_context_sha256=computed_context_sha256,
        )

    # 7-8. Build the one explicit payload and instantiate exactly one subject.
    payload = _subject_payload(explicit, candidates)
    try:
        subject = ApprovedChangeSubject(**payload)
    except Exception as exc:  # PR309 validation stays authoritative and unweakened.
        return _blocked(
            "construction_blocked",
            [f"approved-change subject validation failed: {exc}"],
            expected=expected,
            computed_context_sha256=computed_context_sha256,
        )

    # 9. Canonical PR309 subject identity.
    subject_sha256 = compute_subject_sha256(subject)

    # 10. Complete field-by-field construction evidence.
    subject_values = _subject_field_values(subject)
    authorities = _build_field_authorities(explicit, candidates, subject_values)

    # 11. Prove the evidence exactly describes the constructed subject.
    evidence_errors = _verify_field_authorities(
        authorities, kinds, explicit, candidates, subject_values
    )
    if evidence_errors:
        return _blocked(
            "construction_blocked",
            ["construction evidence verification failed", *evidence_errors],
            expected=expected,
            computed_context_sha256=computed_context_sha256,
        )

    try:
        evidence = ApprovedChangeSubjectConstructionEvidence(
            supplemental_context_sha256=computed_context_sha256,
            subject_sha256=subject_sha256,
            field_authorities=authorities,
        )
    except Exception as exc:  # evidence stays fail-closed on schema drift
        return _blocked(
            "construction_blocked",
            [f"construction evidence validation failed: {exc}"],
            expected=expected,
            computed_context_sha256=computed_context_sha256,
        )

    # 12-13. Evidence identity and the one successful immutable result.
    return ApprovedChangeSubjectConstructionResult(
        status="subject_constructed",
        construction_succeeded=True,
        expected_supplemental_context_sha256=expected,
        computed_supplemental_context_sha256=computed_context_sha256,
        computed_subject_sha256=subject_sha256,
        computed_construction_evidence_sha256=compute_construction_evidence_sha256(evidence),
        subject=subject,
        construction_evidence=evidence,
        errors=(),
        construction_performed=True,
        subject_created=True,
    )
