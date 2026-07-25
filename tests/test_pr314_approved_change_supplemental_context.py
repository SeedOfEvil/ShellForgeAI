from __future__ import annotations

import ast
import copy
import inspect
import os
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from shellforgeai.core import approved_change_supplemental_context as ctx_module
from shellforgeai.core.approvals import Proposal
from shellforgeai.core.approved_change_construction_policy import (
    CONSTRUCTION_POLICY_SCHEMA_VERSION,
    CONTRACT_CONSTANT_FIELDS,
    DIRECT_CANDIDATE_ALLOWLIST,
    EXPLICIT_CONTEXT_ONLY_FIELDS,
)
from shellforgeai.core.approved_change_contract import (
    SCHEMA_VERSION as APPROVED_CHANGE_SCHEMA_VERSION,
)
from shellforgeai.core.approved_change_contract import (
    ApprovalAttestation,
    ApprovedChangeContract,
    ApprovedChangeSubject,
    ApprovedChangeTarget,
    EvidenceReference,
    ProcedureStep,
    RollbackPosture,
    TargetIdentityClaim,
    compute_subject_sha256,
    verify_approval_binding,
)
from shellforgeai.core.approved_change_supplemental_context import (
    CANDIDATE_DESTINATION_SOURCES,
    CANDIDATE_DESTINATIONS,
    EXPLICIT_CONTEXT_DESTINATIONS,
    SUPPLEMENTAL_CONTEXT_SCHEMA_VERSION,
    ApprovedChangeSupplementalContext,
    AuditRequirementsContextReview,
    BlastRadiusContextReview,
    CapabilityIdContextReview,
    ChangeSummaryContextReview,
    DesiredOutcomeContextReview,
    DiagnosisSummaryContextReview,
    EvidenceReferencesContextReview,
    ImpactCandidateReview,
    PreconditionsCandidateReview,
    ProcedureContextReview,
    RevalidationRequirementsContextReview,
    ReviewProvenance,
    RiskCandidateReview,
    RollbackPostureContextReview,
    SourceProposalReferenceCandidateReview,
    TargetContextReview,
    UnsupportedOrIrreversibleAspectsContextReview,
    VerificationCriteriaCandidateReview,
    canonical_candidate_json,
    canonical_supplemental_context_json,
    compute_candidate_sha256,
    compute_supplemental_context_sha256,
    validate_approved_change_supplemental_context,
)

REVIEW_TIME = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)
EXPECTED_CANDIDATES = {
    "source_proposal_reference": "proposal_id",
    "risk": "risk",
    "impact": "impact",
    "preconditions": "preconditions",
    "verification_criteria": "verification",
}
CANDIDATE_CLASSES = {
    "source_proposal_reference": SourceProposalReferenceCandidateReview,
    "risk": RiskCandidateReview,
    "impact": ImpactCandidateReview,
    "preconditions": PreconditionsCandidateReview,
    "verification_criteria": VerificationCriteriaCandidateReview,
}
CANDIDATE_VALUES = {
    "source_proposal_reference": "prop-2026-07-24-01",
    "risk": "medium",
    "impact": "one reviewed container only",
    "preconditions": ("operator confirms maintenance window", "backup verified"),
    "verification_criteria": ("fresh evidence satisfies health criteria", "no restart loop"),
}


def provenance(actor="operator-a", at=REVIEW_TIME, reason="explicit field review"):
    return ReviewProvenance(reviewed_by=actor, reviewed_at=at, review_reason=reason)


def target(claims=(("id", "abc123"), ("host", "docker01"))):
    return ApprovedChangeTarget(
        kind="container",
        name="demo",
        identity_claims=tuple(TargetIdentityClaim(key=k, value=v) for k, v in claims),
    )


def evidence(order=("ev-1", "ev-2")):
    return tuple(
        EvidenceReference(
            reference_id=ref,
            source="ops-report",
            sha256="a" * 64 if ref == "ev-1" else "b" * 64,
            observed_at=REVIEW_TIME,
        )
        for ref in order
    )


def steps(ids=("step-1", "step-2")):
    return tuple(
        ProcedureStep(
            step_id=step_id,
            description=f"perform reviewed action {step_id}",
            expected_effect=f"target matches reviewed state after {step_id}",
        )
        for step_id in ids
    )


def rollback(procedure_ids=("rollback-1", "rollback-2")):
    return RollbackPosture(
        reversible=True,
        summary="manual recovery expected",
        procedure=steps(procedure_ids),
        limitations=("automatic rollback unsupported",),
    )


def explicit_reviews(**overrides):
    values = {
        "audit_requirements": ("record reviewed context hash and verification outcome",),
        "blast_radius": "one reviewed target only",
        "capability_id": "example.synthetic_bounded_change",
        "change_summary": "bounded descriptive correction",
        "desired_outcome": "restore the reviewed healthy state",
        "diagnosis_summary": "reviewed evidence indicates configuration drift",
        "evidence_references": evidence(),
        "procedure": steps(),
        "revalidation_requirements": ("re-check target identity and current evidence",),
        "rollback_posture": rollback(),
        "target": target(),
        "unsupported_or_irreversible_aspects": ("none identified",),
    }
    values.update(overrides)
    classes = {
        "audit_requirements": AuditRequirementsContextReview,
        "blast_radius": BlastRadiusContextReview,
        "capability_id": CapabilityIdContextReview,
        "change_summary": ChangeSummaryContextReview,
        "desired_outcome": DesiredOutcomeContextReview,
        "diagnosis_summary": DiagnosisSummaryContextReview,
        "evidence_references": EvidenceReferencesContextReview,
        "procedure": ProcedureContextReview,
        "revalidation_requirements": RevalidationRequirementsContextReview,
        "rollback_posture": RollbackPostureContextReview,
        "target": TargetContextReview,
        "unsupported_or_irreversible_aspects": UnsupportedOrIrreversibleAspectsContextReview,
    }
    return tuple(
        classes[field](reviewed_value=values[field], provenance=provenance())
        for field in sorted(classes)
    )


def candidate(destination, *, value=None, decision="accepted", final=None, prov=None, sha=None):
    value = CANDIDATE_VALUES[destination] if value is None else value
    source = EXPECTED_CANDIDATES[destination]
    return CANDIDATE_CLASSES[destination](
        candidate_value=value,
        candidate_sha256=sha or compute_candidate_sha256(destination, source, value),
        decision=decision,
        final_reviewed_value=value if final is None else final,
        provenance=prov or provenance(),
    )


def candidate_reviews(**overrides):
    return tuple(
        overrides.get(destination) or candidate(destination)
        for destination in sorted(CANDIDATE_VALUES)
    )


def context(explicit=None, candidates=None, **overrides):
    payload = {
        "explicit_context_reviews": explicit_reviews() if explicit is None else explicit,
        "legacy_candidate_reviews": candidate_reviews() if candidates is None else candidates,
    }
    payload.update(overrides)
    return ApprovedChangeSupplementalContext(**payload)


def as_data(obj=None):
    return (obj or context()).model_dump(mode="json")


def validate(value=None):
    return validate_approved_change_supplemental_context(context() if value is None else value)


# --------------------------------------------------------------------------
# Exact coverage
# --------------------------------------------------------------------------


def test_complete_destination_coverage_equals_all_pr309_subject_fields():
    result = validate()
    assert result.context_valid is True
    assert result.status == "supplemental_context_valid"
    assert result.coverage_complete is True
    assert result.expected_destination_fields == tuple(sorted(ApprovedChangeSubject.model_fields))
    assert result.covered_destination_fields == result.expected_destination_fields
    assert len(result.expected_destination_fields) == 18
    assert len(CONTRACT_CONSTANT_FIELDS) + len(EXPLICIT_CONTEXT_DESTINATIONS) + len(
        CANDIDATE_DESTINATIONS
    ) == len(ApprovedChangeSubject.model_fields)
    assert result.missing_destination_fields == ()
    assert result.duplicate_destination_fields == ()
    assert result.unknown_destination_fields == ()


def test_schema_version_is_the_sole_contract_constant():
    assert CONTRACT_CONSTANT_FIELDS == ("schema_version",)
    assert "schema_version" not in EXPLICIT_CONTEXT_DESTINATIONS
    assert "schema_version" not in CANDIDATE_DESTINATIONS


def test_exact_explicit_and_candidate_field_sets_equal_pr311_constants():
    assert len(EXPLICIT_CONTEXT_DESTINATIONS) == 12
    assert set(EXPLICIT_CONTEXT_DESTINATIONS) == set(EXPLICIT_CONTEXT_ONLY_FIELDS)
    assert list(EXPLICIT_CONTEXT_DESTINATIONS) == sorted(EXPLICIT_CONTEXT_DESTINATIONS)
    assert len(CANDIDATE_DESTINATIONS) == 5
    assert set(CANDIDATE_DESTINATION_SOURCES) == set(DIRECT_CANDIDATE_ALLOWLIST)
    assert dict(CANDIDATE_DESTINATION_SOURCES) == EXPECTED_CANDIDATES
    reviews = context().explicit_context_reviews
    assert tuple(r.destination_field for r in reviews) == EXPLICIT_CONTEXT_DESTINATIONS


class _SubjectFieldsStub:
    def __init__(self, fields):
        self.model_fields = fields


def test_renamed_or_removed_pr309_subject_field_fails_closed(monkeypatch):
    added = dict(ApprovedChangeSubject.model_fields)
    added["future_reviewed_field"] = added["blast_radius"]
    monkeypatch.setattr(ctx_module, "ApprovedChangeSubject", _SubjectFieldsStub(added))
    result = validate()
    assert result.context_valid is False
    assert result.coverage_complete is False
    assert "future_reviewed_field" in result.missing_destination_fields

    shrunk = {k: v for k, v in ApprovedChangeSubject.model_fields.items() if k != "blast_radius"}
    monkeypatch.setattr(ctx_module, "ApprovedChangeSubject", _SubjectFieldsStub(shrunk))
    result = validate()
    assert result.context_valid is False
    assert "blast_radius" in result.unknown_destination_fields


# --------------------------------------------------------------------------
# Candidate mappings
# --------------------------------------------------------------------------


@pytest.mark.parametrize("destination, source", sorted(EXPECTED_CANDIDATES.items()))
def test_each_canonical_candidate_mapping(destination, source):
    review = candidate(destination)
    assert review.destination_field == destination
    assert review.legacy_source_field == source
    assert review.candidate_sha256 == compute_candidate_sha256(
        destination, source, CANDIDATE_VALUES[destination]
    )
    assert validate().context_valid is True


@pytest.mark.parametrize(
    "destination, bad_source",
    [
        ("risk", "impact"),
        ("impact", "notes"),
        ("source_proposal_reference", "fingerprint"),
        ("preconditions", "approval"),
        ("verification_criteria", "verification_criteria"),
        ("risk", "*"),
        ("risk", "unknown_legacy_field"),
        ("capability_id", "kind"),
        ("target", "target"),
        ("procedure", "proposed_steps"),
        ("rollback_posture", "rollback"),
        ("evidence_references", "evidence"),
    ],
)
def test_rejects_altered_prohibited_and_unknown_candidate_sources(destination, bad_source):
    data = as_data()
    entry = copy.deepcopy(data["legacy_candidate_reviews"][0])
    entry["destination_field"] = destination
    entry["legacy_source_field"] = bad_source
    data["legacy_candidate_reviews"][0] = entry
    result = validate(data)
    assert result.context_valid is False
    assert result.errors


def test_rejects_altered_destination_field_for_candidate():
    data = as_data()
    data["legacy_candidate_reviews"][0]["destination_field"] = "blast_radius"
    result = validate(data)
    assert result.context_valid is False
    assert result.errors


def test_rejects_duplicate_candidate_destination_and_multiple_sources():
    data = as_data()
    data["legacy_candidate_reviews"].append(copy.deepcopy(data["legacy_candidate_reviews"][0]))
    duplicated = validate(data)
    assert duplicated.context_valid is False
    assert "impact" in duplicated.duplicate_destination_fields

    data = as_data()
    data["legacy_candidate_reviews"][0]["legacy_source_field"] = ["impact", "notes"]
    assert validate(data).context_valid is False


def test_rejects_legacy_approval_and_fingerprint_as_candidate_sources():
    for prohibited in ("approval", "fingerprint"):
        data = as_data()
        data["legacy_candidate_reviews"][0]["legacy_source_field"] = prohibited
        result = validate(data)
        assert result.context_valid is False
        assert result.errors


def test_no_generic_context_bag_or_extra_field_is_accepted():
    data = as_data()
    data["extra_reviewed_context"] = {"anything": "value"}
    assert validate(data).context_valid is False
    data = as_data()
    data["explicit_context_reviews"][0]["unexpected"] = "value"
    assert validate(data).context_valid is False


# --------------------------------------------------------------------------
# Candidate decisions
# --------------------------------------------------------------------------


def test_valid_accepted_and_rejected_decisions():
    accepted = candidate("impact")
    assert accepted.decision == "accepted"
    assert accepted.final_reviewed_value == accepted.candidate_value

    rejected = candidate(
        "impact",
        decision="rejected",
        final="two reviewed containers after explicit re-scoping",
        prov=provenance(reason="legacy impact understated the reviewed blast radius"),
    )
    assert rejected.final_reviewed_value != rejected.candidate_value
    assert validate(context(candidates=candidate_reviews(impact=rejected))).context_valid is True


def test_accepted_candidate_value_mismatch_is_rejected():
    with pytest.raises(ValidationError):
        candidate("impact", decision="accepted", final="a different reviewed impact")
    data = as_data()
    for entry in data["legacy_candidate_reviews"]:
        if entry["destination_field"] == "impact":
            entry["final_reviewed_value"] = "a different reviewed impact"
    assert validate(data).context_valid is False


def test_rejected_candidate_with_unchanged_value_is_rejected():
    with pytest.raises(ValidationError):
        candidate("impact", decision="rejected")
    data = as_data()
    for entry in data["legacy_candidate_reviews"]:
        if entry["destination_field"] == "impact":
            entry["decision"] = "rejected"
    assert validate(data).context_valid is False


@pytest.mark.parametrize(
    "destination, bad_value",
    [
        ("risk", "critical"),
        ("risk", ""),
        ("impact", ""),
        ("impact", "   "),
        ("source_proposal_reference", ""),
        ("preconditions", ()),
        ("verification_criteria", ()),
        ("preconditions", ("",)),
    ],
)
def test_invalid_candidate_values(destination, bad_value):
    with pytest.raises(ValidationError):
        candidate(destination, value=bad_value)


def test_candidate_sha_mismatch_is_rejected():
    with pytest.raises(ValidationError):
        candidate("impact", sha="0" * 64)
    with pytest.raises(ValidationError):
        candidate("impact", sha="not-a-sha")
    data = as_data()
    for entry in data["legacy_candidate_reviews"]:
        if entry["destination_field"] == "impact":
            entry["candidate_sha256"] = "0" * 64
    result = validate(data)
    assert result.context_valid is False


@pytest.mark.parametrize(
    "destination, other_value",
    [
        ("source_proposal_reference", "prop-2026-07-24-02"),
        ("risk", "high"),
        ("impact", "two reviewed containers"),
        ("preconditions", ("operator confirms maintenance window",)),
        ("verification_criteria", ("fresh evidence satisfies health criteria",)),
    ],
)
def test_candidate_hash_changes_for_every_candidate_value_change(destination, other_value):
    source = EXPECTED_CANDIDATES[destination]
    base = compute_candidate_sha256(destination, source, CANDIDATE_VALUES[destination])
    assert base != compute_candidate_sha256(destination, source, other_value)


def test_candidate_hash_binds_destination_and_source():
    value = "one reviewed container only"
    assert compute_candidate_sha256("impact", "impact", value) != compute_candidate_sha256(
        "blast_radius", "impact", value
    )
    assert compute_candidate_sha256("impact", "impact", value) != compute_candidate_sha256(
        "impact", "notes", value
    )


def test_final_reviewed_value_changes_the_whole_context_hash():
    base = compute_supplemental_context_sha256(context())
    changed = candidate(
        "impact",
        decision="rejected",
        final="explicitly re-scoped reviewed impact",
        prov=provenance(reason="legacy impact rejected after review"),
    )
    other = compute_supplemental_context_sha256(
        context(candidates=candidate_reviews(impact=changed))
    )
    assert base != other


def test_decision_change_changes_identity():
    base = compute_supplemental_context_sha256(context())
    rejected = candidate(
        "impact",
        decision="rejected",
        final="explicitly re-scoped reviewed impact",
    )
    assert base != compute_supplemental_context_sha256(
        context(candidates=candidate_reviews(impact=rejected))
    )


# --------------------------------------------------------------------------
# Explicit context reviews
# --------------------------------------------------------------------------


def test_each_typed_explicit_review_record():
    reviews = {r.destination_field: r for r in context().explicit_context_reviews}
    assert set(reviews) == set(EXPLICIT_CONTEXT_DESTINATIONS)
    assert isinstance(reviews["target"].reviewed_value, ApprovedChangeTarget)
    assert isinstance(reviews["rollback_posture"].reviewed_value, RollbackPosture)
    assert all(
        isinstance(v, EvidenceReference) for v in reviews["evidence_references"].reviewed_value
    )
    assert all(isinstance(v, ProcedureStep) for v in reviews["procedure"].reviewed_value)
    assert reviews["capability_id"].reviewed_value == "example.synthetic_bounded_change"
    for review in reviews.values():
        assert isinstance(review.provenance, ReviewProvenance)


def test_valid_target_identity_and_duplicate_identity_keys():
    assert TargetContextReview(reviewed_value=target(), provenance=provenance())
    with pytest.raises(ValidationError):
        TargetContextReview(
            reviewed_value=target((("id", "abc"), ("id", "def"))), provenance=provenance()
        )


def test_valid_and_duplicate_evidence_reference_ids():
    assert EvidenceReferencesContextReview(reviewed_value=evidence(), provenance=provenance())
    with pytest.raises(ValidationError):
        EvidenceReferencesContextReview(
            reviewed_value=evidence(("ev-1", "ev-1")), provenance=provenance()
        )
    with pytest.raises(ValidationError):
        EvidenceReferencesContextReview(reviewed_value=(), provenance=provenance())


def test_valid_ordered_procedure_and_duplicate_step_ids():
    assert ProcedureContextReview(reviewed_value=steps(), provenance=provenance())
    with pytest.raises(ValidationError):
        ProcedureContextReview(reviewed_value=steps(("s1", "s1")), provenance=provenance())
    with pytest.raises(ValidationError):
        ProcedureContextReview(reviewed_value=(), provenance=provenance())


def test_valid_and_invalid_rollback_posture():
    assert RollbackPostureContextReview(reviewed_value=rollback(), provenance=provenance())
    with pytest.raises(ValidationError):
        RollbackPostureContextReview(
            reviewed_value={"reversible": True, "summary": "", "limitations": ["none"]},
            provenance=provenance(),
        )
    with pytest.raises(ValidationError):
        RollbackPostureContextReview(
            reviewed_value={"reversible": False, "summary": "no recovery", "limitations": []},
            provenance=provenance(),
        )


@pytest.mark.parametrize(
    "bad_capability", ["", "*", "all", "any", "Windows.Runtime", "has space", "x" * 200]
)
def test_invalid_capability_identifiers(bad_capability):
    with pytest.raises(ValidationError):
        CapabilityIdContextReview(reviewed_value=bad_capability, provenance=provenance())


@pytest.mark.parametrize(
    "review_class, bad_value",
    [
        (BlastRadiusContextReview, ""),
        (BlastRadiusContextReview, "  "),
        (BlastRadiusContextReview, "*"),
        (AuditRequirementsContextReview, ()),
        (AuditRequirementsContextReview, ("",)),
        (RevalidationRequirementsContextReview, ()),
        (UnsupportedOrIrreversibleAspectsContextReview, ("any",)),
    ],
)
def test_empty_required_text_or_tuple_values(review_class, bad_value):
    with pytest.raises(ValidationError):
        review_class(reviewed_value=bad_value, provenance=provenance())


def test_missing_provenance_is_rejected():
    with pytest.raises(ValidationError):
        BlastRadiusContextReview(reviewed_value="one target")
    data = as_data()
    data["explicit_context_reviews"][0].pop("provenance")
    assert validate(data).context_valid is False


@pytest.mark.parametrize(
    "actor, reason, moment",
    [
        ("", "reviewed", REVIEW_TIME),
        ("*", "reviewed", REVIEW_TIME),
        ("operator", "", REVIEW_TIME),
        ("operator", "any", REVIEW_TIME),
        ("operator", "reviewed", datetime(2026, 7, 24, 12, 0, 0)),
        ("x" * 200, "reviewed", REVIEW_TIME),
    ],
)
def test_invalid_review_provenance(actor, reason, moment):
    with pytest.raises(ValidationError):
        ReviewProvenance(reviewed_by=actor, reviewed_at=moment, review_reason=reason)


def test_provenance_forbids_extra_fields():
    with pytest.raises(ValidationError):
        ReviewProvenance(
            reviewed_by="operator",
            reviewed_at=REVIEW_TIME,
            review_reason="reviewed",
            authenticated=True,
        )


# --------------------------------------------------------------------------
# Determinism and canonical identity
# --------------------------------------------------------------------------


def test_canonical_json_and_hash_are_byte_identical_across_calls():
    fixture = context()
    assert canonical_supplemental_context_json(fixture) == canonical_supplemental_context_json(
        fixture
    )
    assert compute_supplemental_context_sha256(fixture) == compute_supplemental_context_sha256(
        context()
    )
    assert canonical_supplemental_context_json(fixture).encode("utf-8") == (
        canonical_supplemental_context_json(context()).encode("utf-8")
    )


def test_non_ascii_text_is_deterministic_and_not_escaped():
    reviews = explicit_reviews(blast_radius="un solo contenedor révisé — 単一のみ")
    first = context(explicit=reviews)
    assert "révisé" in canonical_supplemental_context_json(first)
    assert compute_supplemental_context_sha256(first) == compute_supplemental_context_sha256(
        context(explicit=explicit_reviews(blast_radius="un solo contenedor révisé — 単一のみ"))
    )


def test_equivalent_timezone_offsets_canonicalize_to_the_same_identity():
    offset = timezone(timedelta(hours=-6))
    shifted = REVIEW_TIME.astimezone(offset)
    assert shifted.utcoffset() == timedelta(hours=-6)
    base = context()
    other = ApprovedChangeSupplementalContext(
        explicit_context_reviews=tuple(
            type(r)(reviewed_value=r.reviewed_value, provenance=provenance(at=shifted))
            for r in base.explicit_context_reviews
        ),
        legacy_candidate_reviews=tuple(
            candidate(r.destination_field, prov=provenance(at=shifted))
            for r in base.legacy_candidate_reviews
        ),
    )
    assert compute_supplemental_context_sha256(base) == compute_supplemental_context_sha256(other)


def test_set_like_input_order_does_not_affect_identity():
    reordered_claims = explicit_reviews(target=target((("host", "docker01"), ("id", "abc123"))))
    reordered_evidence = explicit_reviews(evidence_references=evidence(("ev-2", "ev-1")))
    base = compute_supplemental_context_sha256(context())
    assert compute_supplemental_context_sha256(context(explicit=reordered_claims)) == base
    assert compute_supplemental_context_sha256(context(explicit=reordered_evidence)) == base


def test_semantic_ordering_does_affect_identity():
    base = compute_supplemental_context_sha256(context())
    assert (
        compute_supplemental_context_sha256(
            context(explicit=explicit_reviews(procedure=steps(("step-2", "step-1"))))
        )
        != base
    )
    assert (
        compute_supplemental_context_sha256(
            context(
                explicit=explicit_reviews(rollback_posture=rollback(("rollback-2", "rollback-1")))
            )
        )
        != base
    )
    reordered_preconditions = candidate(
        "preconditions", value=tuple(reversed(CANDIDATE_VALUES["preconditions"]))
    )
    assert (
        compute_supplemental_context_sha256(
            context(candidates=candidate_reviews(preconditions=reordered_preconditions))
        )
        != base
    )
    reordered_verification = candidate(
        "verification_criteria", value=tuple(reversed(CANDIDATE_VALUES["verification_criteria"]))
    )
    assert (
        compute_supplemental_context_sha256(
            context(candidates=candidate_reviews(verification_criteria=reordered_verification))
        )
        != base
    )


@pytest.mark.parametrize(
    "actor, moment, reason",
    [
        ("operator-b", REVIEW_TIME, "explicit field review"),
        ("operator-a", REVIEW_TIME + timedelta(seconds=1), "explicit field review"),
        ("operator-a", REVIEW_TIME, "a different reviewed rationale"),
    ],
)
def test_provenance_changes_change_identity(actor, moment, reason):
    base = compute_supplemental_context_sha256(context())
    changed = explicit_reviews()
    replacement = tuple(
        type(r)(reviewed_value=r.reviewed_value, provenance=provenance(actor, moment, reason))
        if r.destination_field == "blast_radius"
        else r
        for r in changed
    )
    assert compute_supplemental_context_sha256(context(explicit=replacement)) != base


def test_reviewed_value_change_changes_identity():
    base = compute_supplemental_context_sha256(context())
    assert (
        compute_supplemental_context_sha256(
            context(explicit=explicit_reviews(blast_radius="two reviewed targets"))
        )
        != base
    )


def test_version_change_blocks_validation_or_changes_identity():
    for field in (
        "schema_version",
        "construction_policy_schema_version",
        "approved_change_schema_version",
    ):
        data = as_data()
        data[field] = "2"
        result = validate(data)
        assert result.context_valid is False
        assert result.errors
    assert SUPPLEMENTAL_CONTEXT_SCHEMA_VERSION == "1"
    assert CONSTRUCTION_POLICY_SCHEMA_VERSION == "1"
    assert APPROVED_CHANGE_SCHEMA_VERSION == "1"
    payload = canonical_supplemental_context_json(context())
    assert '"schema_version":"1"' in payload
    assert '"construction_policy_schema_version":"1"' in payload
    assert '"approved_change_schema_version":"1"' in payload


def test_canonical_json_shape_is_compact_and_sorted():
    payload = canonical_supplemental_context_json(context())
    assert ", " not in payload
    assert '": ' not in payload
    assert payload.index('"approved_change_schema_version"') < payload.index('"schema_version"')
    assert "2026-07-24T12:00:00Z" in payload
    assert canonical_candidate_json("impact", "impact", "reviewed") == (
        '{"candidate_value":"reviewed","destination_field":"impact",'
        '"legacy_source_field":"impact","schema_version":"1"}'
    )


# --------------------------------------------------------------------------
# Hash separation (test-only future subject construction)
# --------------------------------------------------------------------------


def future_subject_from_reviewed_values():
    """Test-only illustration of a future PR315 construction. Not production code."""
    fixture = context()
    explicit = {r.destination_field: r.reviewed_value for r in fixture.explicit_context_reviews}
    final = {r.destination_field: r.final_reviewed_value for r in fixture.legacy_candidate_reviews}
    return ApprovedChangeSubject(**explicit, **final)


def test_supplemental_and_candidate_identities_are_not_subject_identity():
    subject = future_subject_from_reviewed_values()
    subject_sha = compute_subject_sha256(subject)
    context_sha = compute_supplemental_context_sha256(context())
    candidate_sha = candidate("impact").candidate_sha256
    assert len({subject_sha, context_sha, candidate_sha}) == 3
    assert context_sha != subject_sha
    assert candidate_sha != subject_sha
    assert canonical_supplemental_context_json(context()) != canonical_candidate_json(
        "impact", "impact", CANDIDATE_VALUES["impact"]
    )


def test_neither_identity_validates_as_an_approval_subject_hash():
    subject = future_subject_from_reviewed_values()
    wrong_identities = (
        compute_supplemental_context_sha256(context()),
        candidate("impact").candidate_sha256,
    )
    for wrong in wrong_identities:
        contract = ApprovedChangeContract(
            subject=subject,
            approval=ApprovalAttestation(
                approved_by="operator",
                approved_at=REVIEW_TIME,
                reason="reviewed exact subject",
                subject_sha256=wrong,
            ),
        )
        assert verify_approval_binding(contract).approval_binding_valid is False


def test_validation_result_field_names_are_not_subject_or_approval_identity():
    fields = type(validate()).model_fields
    assert "computed_supplemental_context_sha256" in fields
    assert "subject_sha256" not in fields
    assert "computed_subject_sha256" not in fields
    assert "fingerprint" not in fields


# --------------------------------------------------------------------------
# Validation behavior
# --------------------------------------------------------------------------


def test_valid_model_and_dictionary_input_agree():
    from_model = validate(context())
    from_dict = validate(as_data())
    assert from_model.context_valid is from_dict.context_valid is True
    assert (
        from_model.computed_supplemental_context_sha256
        == from_dict.computed_supplemental_context_sha256
    )


@pytest.mark.parametrize(
    "bad_input",
    [None, "context", 7, [], ("explicit_context_reviews",), object()],
)
def test_invalid_validation_input_is_structured_and_non_throwing(bad_input):
    result = validate_approved_change_supplemental_context(bad_input)
    assert result.status == "invalid_validation_input"
    assert result.context_valid is False
    assert result.computed_supplemental_context_sha256 == ""
    assert result.errors


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"explicit_context_reviews": []},
        {"legacy_candidate_reviews": []},
        {"explicit_context_reviews": {}, "legacy_candidate_reviews": {}},
        {"explicit_context_reviews": [{"destination_field": "unknown_field"}]},
        {"explicit_context_reviews": "not-a-list", "legacy_candidate_reviews": 3},
    ],
)
def test_malformed_dictionaries_return_structured_invalid_results(data):
    result = validate_approved_change_supplemental_context(data)
    assert result.status == "supplemental_context_invalid"
    assert result.context_valid is False
    assert result.coverage_complete is False
    assert result.errors
    assert all(isinstance(error, str) for error in result.errors)
    assert "Traceback" not in " ".join(result.errors)


def test_missing_sections_report_missing_destinations():
    data = as_data()
    data["explicit_context_reviews"] = []
    result = validate(data)
    assert result.context_valid is False
    assert set(EXPLICIT_CONTEXT_DESTINATIONS) <= set(result.missing_destination_fields)

    data = as_data()
    data["legacy_candidate_reviews"] = []
    result = validate(data)
    assert set(CANDIDATE_DESTINATIONS) <= set(result.missing_destination_fields)


def test_partial_context_is_rejected():
    trimmed = context().explicit_context_reviews[:-1]
    result = validate(context(explicit=trimmed))
    assert result.context_valid is False
    assert result.coverage_complete is False
    assert "unsupported_or_irreversible_aspects" in result.missing_destination_fields


def test_unsorted_records_are_rejected_not_repaired():
    unsorted_explicit = tuple(reversed(context().explicit_context_reviews))
    result = validate(context(explicit=unsorted_explicit))
    assert result.context_valid is False
    assert any("sorted deterministically" in error for error in result.errors)

    unsorted_candidates = tuple(reversed(context().legacy_candidate_reviews))
    result = validate(context(candidates=unsorted_candidates))
    assert result.context_valid is False
    assert any("sorted deterministically" in error for error in result.errors)


def test_duplicate_and_unknown_explicit_records():
    reviews = context().explicit_context_reviews
    duplicated = tuple(sorted(reviews + (reviews[0],), key=lambda r: r.destination_field))
    result = validate(context(explicit=duplicated))
    assert result.context_valid is False
    assert "audit_requirements" in result.duplicate_destination_fields

    for unknown in ("not_a_subject_field", "*", "all", ""):
        data = as_data()
        data["explicit_context_reviews"][0]["destination_field"] = unknown
        result = validate(data)
        assert result.context_valid is False
        assert result.coverage_complete is False
        assert "audit_requirements" in result.missing_destination_fields


def test_structured_error_ordering_is_deterministic_and_sorted():
    data = as_data()
    data["explicit_context_reviews"] = []
    data["legacy_candidate_reviews"] = []
    first = validate(data)
    second = validate(copy.deepcopy(data))
    assert first.errors == second.errors
    assert list(first.errors) == sorted(set(first.errors))


def test_permanent_inert_safety_flags_on_every_result():
    results = [
        validate(),
        validate({}),
        validate_approved_change_supplemental_context(None),
        validate(context(explicit=context().explicit_context_reviews[:2])),
    ]
    for result in results:
        assert result.read_only is True
        assert result.mutation_performed is False
        assert result.subject_created is False
        assert result.contract_created is False
        assert result.approval_created is False
        assert result.persistence_performed is False
        assert result.receipt_created is False
        assert result.execution_allowed is False
        assert result.execution_available is False
        assert result.execution_status == "not_executed"


def test_validation_warnings_never_imply_approval_or_execution():
    warnings = " ".join(validate().warnings)
    assert "not authenticated identity" in warnings
    assert "not a PR309 subject hash" in warnings
    assert "no subject, approval, contract, or execution eligibility" in warnings


# --------------------------------------------------------------------------
# Immutability
# --------------------------------------------------------------------------


def test_top_level_and_nested_models_are_frozen():
    fixture = context()
    with pytest.raises(ValidationError):
        fixture.schema_version = "2"
    with pytest.raises(ValidationError):
        fixture.explicit_context_reviews[0].reviewed_value = ("changed",)
    with pytest.raises(ValidationError):
        fixture.legacy_candidate_reviews[0].decision = "rejected"
    with pytest.raises(ValidationError):
        fixture.explicit_context_reviews[0].provenance.reviewed_by = "someone-else"
    with pytest.raises(ValidationError):
        validate().status = "supplemental_context_valid"


def test_nested_collections_cannot_be_appended_to():
    fixture = context()
    assert isinstance(fixture.explicit_context_reviews, tuple)
    assert isinstance(fixture.legacy_candidate_reviews, tuple)
    with pytest.raises(AttributeError):
        fixture.explicit_context_reviews.append(fixture.explicit_context_reviews[0])
    with pytest.raises(AttributeError):
        fixture.legacy_candidate_reviews.append(fixture.legacy_candidate_reviews[0])
    procedure = {r.destination_field: r for r in fixture.explicit_context_reviews}["procedure"]
    with pytest.raises(AttributeError):
        procedure.reviewed_value.append(procedure.reviewed_value[0])


# --------------------------------------------------------------------------
# Side-effect and static purity guards
# --------------------------------------------------------------------------


def test_no_side_effect_runtime_guards(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("side effect attempted")

    monkeypatch.setattr(Path, "read_text", boom)
    monkeypatch.setattr(Path, "write_text", boom)
    monkeypatch.setattr(Path, "open", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(os, "system", boom)
    monkeypatch.setattr(socket, "socket", boom)
    before = dict(os.environ)
    assert validate().context_valid is True
    assert compute_supplemental_context_sha256(context())
    assert compute_candidate_sha256("impact", "impact", "reviewed")
    assert dict(os.environ) == before


def module_code_without_docstrings():
    """Return the production module's executable code with docstrings removed."""
    tree = ast.parse(Path(ctx_module.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef):
            continue
        first = node.body[0] if node.body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            node.body.pop(0)
            if not node.body:
                node.body.append(ast.Pass())
    return ast.unparse(tree)


def test_static_no_construction_api_persistence_execution_or_io():
    source = module_code_without_docstrings()
    forbidden = [
        "subprocess",
        "os.system",
        "socket",
        "docker",
        "compose",
        "powershell",
        "winrm",
        "open(",
        "write_text",
        "read_text",
        "Path",
        "os.environ",
        "getenv",
        "requests",
        "httpx",
        "urllib",
        "provider",
        "ApprovedChangeSubject(",
        "ApprovalAttestation(",
        "ApprovedChangeContract(",
        "datetime.now",
        "utcnow",
        "now()",
    ]
    for token in forbidden:
        assert token not in source, token
    for proposal_token in ("import Proposal", "Proposal(", ": Proposal", "core.approvals"):
        assert proposal_token not in source, proposal_token
    for name in (
        "construct_approved_change_subject",
        "build_subject",
        "create_subject",
        "extract_candidate_values",
        "load_proposal",
        "persist_supplemental_context",
        "save_supplemental_context",
    ):
        assert not hasattr(ctx_module, name)


def test_static_signatures_never_take_proposal_or_return_pr309_top_level_models():
    for _, obj in inspect.getmembers(ctx_module, inspect.isfunction):
        signature = inspect.signature(obj)
        assert all(param.annotation is not Proposal for param in signature.parameters.values())
        assert signature.return_annotation not in {
            ApprovedChangeSubject,
            ApprovalAttestation,
            ApprovedChangeContract,
        }
        assert "Proposal" not in str(signature)


def test_module_exposes_no_cli_or_registry_surface():
    for name in ("app", "cli", "main", "register", "REGISTRY", "CAPABILITY_REGISTRY"):
        assert not hasattr(ctx_module, name)
    assert "windows.runtime_reconcile" not in module_code_without_docstrings()
