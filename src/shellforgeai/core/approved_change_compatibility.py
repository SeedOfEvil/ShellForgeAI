"""Legacy Proposal to approved-change compatibility assessment (PR310).

This module is intentionally pure, read-only, deterministic, and inert. It
performs in-memory findings-only inspection of legacy Proposal schema v1 values
against PR309 approved-change contract schema v1 requirements. It never creates
subjects, attestations, contracts, hashes, files, execution payloads, or runtime
integration.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from shellforgeai.core.approvals import PROPOSAL_SCHEMA_VERSION, Proposal
from shellforgeai.core.approved_change_contract import (
    SCHEMA_VERSION as APPROVED_CHANGE_SCHEMA_VERSION,
)

COMPATIBILITY_SCHEMA_VERSION = "1"
STATUS_REQUIRES_EXPLICIT_CONTEXT = "requires_explicit_context"
STATUS_INVALID_LEGACY_PROPOSAL = "invalid_legacy_proposal"
EXECUTION_STATUS_NOT_EXECUTED = "not_executed"

CandidateField = Literal[
    "impact",
    "notes",
    "preconditions",
    "proposal_id",
    "risk",
    "rollback",
    "source.evidence",
    "source.runbook",
    "source.summary",
    "source_hashes",
    "title",
    "verification",
]

MissingField = Literal[
    "audit_requirements",
    "blast_radius",
    "capability_id",
    "change_summary",
    "desired_outcome",
    "diagnosis_summary",
    "evidence_observation_timestamps",
    "evidence_reference_ids",
    "evidence_sha256_references",
    "evidence_source_identity",
    "exact_subject_only_attestation_scope",
    "pr309_subject_sha256",
    "procedure_steps",
    "revalidation_requirements",
    "rollback_posture",
    "target_identity",
    "unsupported_or_irreversible_aspects",
]

AmbiguousField = Literal[
    "approval",
    "component",
    "evidence",
    "fingerprint",
    "kind",
    "proposed_steps",
    "rollback",
    "source_hashes",
    "target",
]

ProhibitedInference = Literal[
    "audit_requirements",
    "blast_radius",
    "capability_id",
    "desired_outcome",
    "diagnosis_summary",
    "evidence_reference_identity",
    "evidence_timestamps",
    "expected_effects",
    "pr309_attestation",
    "revalidation_requirements",
    "rollback_reversibility",
    "step_ids",
    "subject_hash",
    "target_identity",
    "unsupported_or_irreversible_aspects",
]

FindingCategory = Literal[
    "ambiguous_semantics",
    "candidate_mapping",
    "invalid_legacy_proposal",
    "missing_required_context",
    "non_equivalent_fingerprint",
    "nonportable_approval",
    "prohibited_inference",
]
FindingSeverity = Literal["blocking", "info", "warning"]

CANDIDATE_SOURCE_FIELDS: tuple[CandidateField, ...] = (
    "impact",
    "notes",
    "preconditions",
    "proposal_id",
    "risk",
    "rollback",
    "source.evidence",
    "source.runbook",
    "source.summary",
    "source_hashes",
    "title",
    "verification",
)
MISSING_REQUIRED_FIELDS: tuple[MissingField, ...] = tuple(sorted(MissingField.__args__))
AMBIGUOUS_FIELDS: tuple[AmbiguousField, ...] = tuple(sorted(AmbiguousField.__args__))
PROHIBITED_INFERENCES: tuple[ProhibitedInference, ...] = tuple(sorted(ProhibitedInference.__args__))


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class CompatibilityFinding(_FrozenModel):
    code: str
    category: FindingCategory
    severity: FindingSeverity
    legacy_field: str
    approved_change_field: str
    message: str
    candidate_reuse: bool = False
    requires_explicit_context: bool = True


class LegacyProposalCompatibilityReport(_FrozenModel):
    schema_version: Literal["1"] = COMPATIBILITY_SCHEMA_VERSION
    legacy_schema_version: str
    approved_change_schema_version: Literal["1"] = APPROVED_CHANGE_SCHEMA_VERSION
    legacy_proposal_id: str
    legacy_status: str
    status: Literal["invalid_legacy_proposal", "requires_explicit_context"]
    compatible_as_is: Literal[False] = False
    approval_portable: Literal[False] = False
    fingerprint_equivalent: Literal[False] = False
    candidate_source_fields: tuple[str, ...]
    missing_required_fields: tuple[str, ...]
    ambiguous_fields: tuple[str, ...]
    prohibited_inferences: tuple[str, ...]
    findings: tuple[CompatibilityFinding, ...]
    explicit_context_required: bool = True
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    contract_created: Literal[False] = False
    approval_created: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


def _candidate_findings(proposal: Proposal) -> tuple[CompatibilityFinding, ...]:
    fields = {
        "proposal_id": "source_proposal_reference",
        "risk": "risk",
        "impact": "impact",
        "preconditions": "preconditions",
        "verification": "verification_criteria",
        "rollback": "rollback_posture",
        "title": "reviewed_context",
        "notes": "reviewed_context",
        "source.evidence": "evidence_source_context",
        "source.runbook": "source_location_context",
        "source.summary": "source_location_context",
        "source_hashes": "source_location_context",
    }
    out = []
    for legacy, approved in sorted(fields.items()):
        out.append(
            CompatibilityFinding(
                code=f"candidate_source_{legacy.replace('.', '_')}",
                category="candidate_mapping",
                severity="info",
                legacy_field=legacy,
                approved_change_field=approved,
                message=(
                    "Legacy value may be displayed as candidate source context only; it is not "
                    "equivalent, automatically reusable, or already approved."
                ),
                candidate_reuse=True,
                requires_explicit_context=True,
            )
        )
    return tuple(out)


def _required_findings() -> tuple[CompatibilityFinding, ...]:
    return tuple(
        CompatibilityFinding(
            code=f"missing_{field}",
            category="missing_required_context",
            severity="blocking",
            legacy_field="",
            approved_change_field=field,
            message=(
                "Legacy Proposal schema v1 does not explicitly and safely provide this "
                "PR309 approved-change subject or attestation requirement."
            ),
        )
        for field in MISSING_REQUIRED_FIELDS
    )


def _ambiguity_findings() -> tuple[CompatibilityFinding, ...]:
    messages = {
        "kind": (
            "kind",
            "capability_id",
            (
                "Legacy Proposal.kind is not automatically a PR309 capability_id; no "
                "namespace, normalization, mapping, or capability lookup is performed."
            ),
        ),
        "target": (
            "target",
            "target.identity_claims",
            (
                "Legacy target text is not exact PR309 target identity; no host, "
                "service, container, or wildcard identity is inferred."
            ),
        ),
        "component": (
            "component",
            "target.identity_claims",
            (
                "Legacy component text is not exact PR309 target identity; no environment "
                "resolution is performed."
            ),
        ),
        "proposed_steps": (
            "proposed_steps",
            "procedure",
            (
                "Legacy free-form proposed steps are not PR309 ProcedureStep objects; no "
                "commands, shells, IDs, or expected effects are parsed."
            ),
        ),
        "rollback": (
            "rollback",
            "rollback_posture",
            (
                "Legacy rollback text is not structured RollbackPosture; reversibility, "
                "limitations, and typed rollback steps are not inferred."
            ),
        ),
        "evidence": (
            "evidence",
            "evidence_references",
            (
                "Legacy evidence strings are not PR309 EvidenceReference values; reference "
                "IDs, source identity, hashes, and timestamps are not synthesized."
            ),
        ),
        "source_hashes": (
            "source_hashes",
            "evidence_references",
            "Legacy source hashes are not PR309 evidence references or reviewed evidence identity.",
        ),
        "approval": (
            "approval",
            "approval",
            (
                "Legacy status and ProposalApproval metadata are historical source metadata "
                "only; they are not authenticated identity and are not bound with "
                "exact_subject_only scope."
            ),
        ),
        "fingerprint": (
            "fingerprint",
            "subject_sha256",
            (
                "Legacy Proposal fingerprint binds a different field set and normalization; "
                "no PR309 subject was constructed and no replacement subject hash exists."
            ),
        ),
    }
    return tuple(
        CompatibilityFinding(
            code=f"ambiguous_{key}",
            category="ambiguous_semantics",
            severity="blocking",
            legacy_field=legacy,
            approved_change_field=approved,
            message=message,
        )
        for key, (legacy, approved, message) in sorted(messages.items())
    )


def _prohibited_findings() -> tuple[CompatibilityFinding, ...]:
    return tuple(
        CompatibilityFinding(
            code=f"prohibited_infer_{item}",
            category="prohibited_inference",
            severity="blocking",
            legacy_field="",
            approved_change_field=item,
            message=(
                "Future conversion would require separately supplied, reviewed context; "
                "PR310 does not infer, synthesize, migrate, or authorize this value."
            ),
        )
        for item in PROHIBITED_INFERENCES
    )


def _fixed_findings(proposal: Proposal) -> tuple[CompatibilityFinding, ...]:
    findings = (
        *_candidate_findings(proposal),
        *_required_findings(),
        *_ambiguity_findings(),
        CompatibilityFinding(
            code="legacy_approval_not_portable",
            category="nonportable_approval",
            severity="blocking",
            legacy_field="status,approval",
            approved_change_field="ApprovalAttestation",
            message=(
                "Legacy approval is not bound to a PR309 subject hash, lacks "
                "exact_subject_only scope, and actor metadata is not authenticated "
                "identity; approval portability remains false."
            ),
        ),
        CompatibilityFinding(
            code="legacy_fingerprint_not_subject_sha256",
            category="non_equivalent_fingerprint",
            severity="blocking",
            legacy_field="fingerprint",
            approved_change_field="subject_sha256",
            message=(
                "Legacy Proposal fingerprint semantics, field set, and normalization differ "
                "from PR309 subject SHA-256; it cannot be reused, copied, renamed, "
                "or treated as approval binding."
            ),
        ),
        *_prohibited_findings(),
    )
    return tuple(
        sorted(
            findings, key=lambda f: (f.category, f.code, f.legacy_field, f.approved_change_field)
        )
    )


def assess_legacy_proposal_compatibility(
    proposal: Proposal | dict[str, Any],
) -> LegacyProposalCompatibilityReport:
    """Assess legacy Proposal schema v1 compatibility with PR309 contracts.

    Malformed input returns an immutable ``invalid_legacy_proposal`` report with
    no compatibility claims. Valid legacy Proposal schema v1 objects always
    require explicit reviewed context and are never compatible, approval
    portable, or fingerprint equivalent as-is.
    """
    try:
        parsed = proposal if isinstance(proposal, Proposal) else Proposal.model_validate(proposal)
        if parsed.schema_version != PROPOSAL_SCHEMA_VERSION:
            raise ValueError("unsupported legacy proposal schema_version")
    except (TypeError, ValueError, ValidationError) as exc:
        finding = CompatibilityFinding(
            code="invalid_legacy_proposal",
            category="invalid_legacy_proposal",
            severity="blocking",
            legacy_field="proposal",
            approved_change_field="ApprovedChangeSubject",
            message=f"Input is not a valid legacy Proposal schema v1 object: {type(exc).__name__}.",
        )
        return LegacyProposalCompatibilityReport(
            legacy_schema_version="unknown",
            legacy_proposal_id="",
            legacy_status="invalid",
            status=STATUS_INVALID_LEGACY_PROPOSAL,
            candidate_source_fields=(),
            missing_required_fields=MISSING_REQUIRED_FIELDS,
            ambiguous_fields=(),
            prohibited_inferences=PROHIBITED_INFERENCES,
            findings=(finding,),
        )

    return LegacyProposalCompatibilityReport(
        legacy_schema_version=parsed.schema_version,
        legacy_proposal_id=parsed.proposal_id,
        legacy_status=parsed.status,
        status=STATUS_REQUIRES_EXPLICIT_CONTEXT,
        candidate_source_fields=CANDIDATE_SOURCE_FIELDS,
        missing_required_fields=MISSING_REQUIRED_FIELDS,
        ambiguous_fields=AMBIGUOUS_FIELDS,
        prohibited_inferences=PROHIBITED_INFERENCES,
        findings=_fixed_findings(parsed),
    )
