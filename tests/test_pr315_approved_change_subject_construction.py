from __future__ import annotations

import ast
import copy
import inspect
import os
import re
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from shellforgeai.core import approved_change_subject_construction as build_module
from shellforgeai.core.approvals import Proposal
from shellforgeai.core.approved_change_construction_policy import (
    APPROVED_CHANGE_CONSTRUCTION_POLICY,
    CONSTRUCTION_POLICY_SCHEMA_VERSION,
    CONTRACT_CONSTANT_FIELDS,
    ApprovedChangeConstructionPolicy,
    ConstructionFieldSourceRule,
    ConstructionPolicyValidationResult,
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
    canonical_subject_json,
    compute_subject_sha256,
    verify_approval_binding,
)
from shellforgeai.core.approved_change_subject_construction import (
    CONSTRUCTION_EVIDENCE_SCHEMA_VERSION,
    CONTRACT_CONSTANT_SOURCE_AUTHORITY,
    FIELD_VALUE_IDENTITY_SCHEMA_VERSION,
    PERMANENT_CONSTRUCTION_WARNINGS,
    ApprovedChangeSubjectConstructionEvidence,
    ApprovedChangeSubjectConstructionResult,
    ContractConstantFieldAuthority,
    ExplicitContextFieldAuthority,
    LegacyCandidateFieldAuthority,
    canonical_construction_evidence_json,
    canonical_field_value_json,
    compute_constructed_field_value_sha256,
    compute_construction_evidence_sha256,
    construct_approved_change_subject,
)
from shellforgeai.core.approved_change_supplemental_context import (
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
    compute_candidate_sha256,
    compute_supplemental_context_sha256,
)

REVIEW_TIME = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)
NOT_A_HASH = "0" * 64

EXPECTED_CANDIDATE_SOURCES = {
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
EXPLICIT_CLASSES = {
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


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


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


EXPLICIT_VALUES = {
    "audit_requirements": ("record reviewed context hash and verification outcome",),
    "blast_radius": "one reviewed target only",
    "capability_id": "example.synthetic_bounded_change",
    "change_summary": "bounded descriptive correction",
    "desired_outcome": "restore the reviewed healthy state",
    "diagnosis_summary": "reviewed evidence indicates configuration drift",
    "revalidation_requirements": ("re-check target identity and current evidence",),
    "unsupported_or_irreversible_aspects": ("none identified",),
}


def explicit_values(**overrides):
    values = dict(EXPLICIT_VALUES)
    values.update(
        {
            "evidence_references": evidence(),
            "procedure": steps(),
            "rollback_posture": rollback(),
            "target": target(),
        }
    )
    values.update(overrides)
    return values


def explicit_reviews(prov=None, **overrides):
    values = explicit_values(**overrides)
    return tuple(
        EXPLICIT_CLASSES[field](reviewed_value=values[field], provenance=prov or provenance())
        for field in sorted(EXPLICIT_CLASSES)
    )


def candidate(destination, *, value=None, decision="accepted", final=None, prov=None, sha=None):
    value = CANDIDATE_VALUES[destination] if value is None else value
    source = EXPECTED_CANDIDATE_SOURCES[destination]
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


_UNSET = object()


def build(value=None, expected=_UNSET):
    """Construct from a fixture using its own exact reviewed-context identity."""
    fixture = context() if value is None else value
    if expected is _UNSET:
        expected = compute_supplemental_context_sha256(fixture)
    return construct_approved_change_subject(fixture, expected_supplemental_context_sha256=expected)


def authorities(result):
    return {r.destination_field: r for r in result.construction_evidence.field_authorities}


class _SubjectSpy:
    """Counting stand-in for the module's single ``ApprovedChangeSubject`` call site."""

    def __init__(self, *, fail=False):
        self.calls = 0
        self.payloads = []
        self.fail = fail
        self.model_fields = ApprovedChangeSubject.model_fields

    def __call__(self, **kwargs):
        self.calls += 1
        self.payloads.append(kwargs)
        if self.fail:
            raise ValueError("PR309 subject validation rejected the assembled payload")
        return ApprovedChangeSubject(**kwargs)


def spy_build(monkeypatch, value=None, expected=_UNSET, *, fail=False):
    spy = _SubjectSpy(fail=fail)
    monkeypatch.setattr(build_module, "ApprovedChangeSubject", spy)
    return spy, build(value, expected)


def assert_blocked(result, *, expected_status=None):
    assert result.construction_succeeded is False
    assert result.status in {"construction_blocked", "invalid_construction_input"}
    if expected_status is not None:
        assert result.status == expected_status
    assert result.subject is None
    assert result.construction_evidence is None
    assert result.construction_performed is False
    assert result.subject_created is False
    assert result.computed_subject_sha256 == ""
    assert result.computed_construction_evidence_sha256 == ""
    assert result.errors
    assert all(isinstance(error, str) for error in result.errors)
    assert "Traceback" not in " ".join(result.errors)
    assert_permanent_safety(result)


def assert_permanent_safety(result):
    assert result.read_only is True
    assert result.mutation_performed is False
    assert result.approval_created is False
    assert result.contract_created is False
    assert result.persistence_performed is False
    assert result.receipt_created is False
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert result.approval_evaluated is False
    assert result.authorization_evaluated is False
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"


# --------------------------------------------------------------------------
# Successful construction
# --------------------------------------------------------------------------


def test_complete_valid_context_constructs_one_subject_and_one_evidence_object():
    fixture = context()
    expected = compute_supplemental_context_sha256(fixture)
    result = build(fixture)

    assert result.status == "subject_constructed"
    assert result.construction_succeeded is True
    assert result.construction_performed is True
    assert result.subject_created is True
    assert result.errors == ()
    assert isinstance(result.subject, ApprovedChangeSubject)
    assert isinstance(result.construction_evidence, ApprovedChangeSubjectConstructionEvidence)
    assert result.expected_supplemental_context_sha256 == expected
    assert result.computed_supplemental_context_sha256 == expected
    assert result.computed_subject_sha256 == compute_subject_sha256(result.subject)
    assert result.computed_construction_evidence_sha256 == compute_construction_evidence_sha256(
        result.construction_evidence
    )
    assert len(result.construction_evidence.field_authorities) == 18
    assert result.warnings == PERMANENT_CONSTRUCTION_WARNINGS
    assert_permanent_safety(result)


def test_evidence_records_expected_and_recomputed_context_identity_identically():
    result = build()
    assert (
        result.expected_supplemental_context_sha256
        == result.computed_supplemental_context_sha256
        == result.construction_evidence.supplemental_context_sha256
    )
    assert result.construction_evidence.subject_sha256 == result.computed_subject_sha256


def test_evidence_schema_versions_bind_all_three_maintained_contracts():
    evidence_record = build().construction_evidence
    assert evidence_record.schema_version == CONSTRUCTION_EVIDENCE_SCHEMA_VERSION
    assert evidence_record.approved_change_schema_version == APPROVED_CHANGE_SCHEMA_VERSION
    assert evidence_record.construction_policy_schema_version == CONSTRUCTION_POLICY_SCHEMA_VERSION
    assert (
        evidence_record.supplemental_context_schema_version == SUPPLEMENTAL_CONTEXT_SCHEMA_VERSION
    )
    assert evidence_record.warnings == PERMANENT_CONSTRUCTION_WARNINGS


def test_every_subject_field_comes_from_its_exact_expected_source():
    fixture = context()
    result = build(fixture)
    subject = result.subject
    explicit = {r.destination_field: r for r in fixture.explicit_context_reviews}
    candidates = {r.destination_field: r for r in fixture.legacy_candidate_reviews}

    assert subject.schema_version == APPROVED_CHANGE_SCHEMA_VERSION
    for destination in EXPLICIT_CONTEXT_DESTINATIONS:
        assert getattr(subject, destination) == explicit[destination].reviewed_value
    for destination in CANDIDATE_DESTINATIONS:
        assert getattr(subject, destination) == candidates[destination].final_reviewed_value
    assert set(EXPLICIT_CONTEXT_DESTINATIONS) | set(CANDIDATE_DESTINATIONS) | set(
        CONTRACT_CONSTANT_FIELDS
    ) == set(ApprovedChangeSubject.model_fields)


def test_success_creates_no_approval_contract_persistence_or_execution_claim():
    result = build()
    fields = type(result).model_fields
    assert "approval" not in fields
    assert "contract" not in fields
    assert "receipt" not in fields
    assert "artifact_path" not in fields
    assert_permanent_safety(result)


# --------------------------------------------------------------------------
# Exactly one subject
# --------------------------------------------------------------------------


def test_exactly_one_subject_is_constructed_on_complete_success(monkeypatch):
    spy, result = spy_build(monkeypatch)
    assert result.status == "subject_constructed"
    assert spy.calls == 1
    assert set(spy.payloads[0]) == set(ApprovedChangeSubject.model_fields)


def test_zero_subjects_for_invalid_expected_hash(monkeypatch):
    spy, result = spy_build(monkeypatch, expected="not-a-hash")
    assert_blocked(result, expected_status="invalid_construction_input")
    assert spy.calls == 0


def test_zero_subjects_for_mismatched_expected_hash(monkeypatch):
    spy, result = spy_build(monkeypatch, expected=NOT_A_HASH)
    assert_blocked(result, expected_status="construction_blocked")
    assert spy.calls == 0


def test_zero_subjects_for_invalid_context(monkeypatch):
    trimmed = context(explicit=context().explicit_context_reviews[:-1])
    spy, result = spy_build(monkeypatch, trimmed)
    assert_blocked(result, expected_status="construction_blocked")
    assert spy.calls == 0


def test_zero_subjects_for_invalid_policy(monkeypatch):
    monkeypatch.setattr(
        build_module, "APPROVED_CHANGE_CONSTRUCTION_POLICY", policy_without("blast_radius")
    )
    spy, result = spy_build(monkeypatch)
    assert_blocked(result, expected_status="construction_blocked")
    assert spy.calls == 0


def test_zero_subjects_when_evidence_verification_fails(monkeypatch):
    original = build_module._build_field_authorities

    def tampered(explicit, candidates, subject_values):
        records = list(original(explicit, candidates, subject_values))
        return tuple(records[:-1])

    monkeypatch.setattr(build_module, "_build_field_authorities", tampered)
    spy, result = spy_build(monkeypatch)
    assert_blocked(result, expected_status="construction_blocked")
    assert spy.calls == 1
    assert any("missing field authority" in error for error in result.errors)


# --------------------------------------------------------------------------
# Explicit-context mapping
# --------------------------------------------------------------------------


@pytest.mark.parametrize("destination", EXPLICIT_CONTEXT_DESTINATIONS)
def test_each_explicit_destination_uses_only_its_matching_reviewed_value(destination):
    fixture = context()
    result = build(fixture)
    review = {r.destination_field: r for r in fixture.explicit_context_reviews}[destination]
    assert getattr(result.subject, destination) == review.reviewed_value

    record = authorities(result)[destination]
    assert isinstance(record, ExplicitContextFieldAuthority)
    assert record.authority_kind == "explicit_context_reviewed_value"
    assert record.source_section == "explicit_context_reviews"
    assert record.source_destination_field == destination
    assert record.provenance == review.provenance
    assert record.final_value_sha256 == compute_constructed_field_value_sha256(
        destination, review.reviewed_value
    )


def test_review_provenance_never_enters_the_constructed_subject():
    result = build()
    payload = canonical_subject_json(result.subject)
    for token in ("reviewed_by", "reviewed_at", "review_reason", "provenance", "operator-a"):
        assert token not in payload
    assert "approved_by" not in payload
    assert "approved_by" not in str(type(result.subject).model_fields)


def test_another_fields_review_cannot_populate_a_destination(monkeypatch):
    reviews = list(explicit_reviews())
    replaced = tuple(
        DesiredOutcomeContextReview(
            reviewed_value="a second desired outcome review", provenance=provenance()
        )
        if r.destination_field == "blast_radius"
        else r
        for r in reviews
    )
    spy, result = spy_build(
        monkeypatch, context(explicit=tuple(sorted(replaced, key=lambda r: r.destination_field)))
    )
    assert_blocked(result)
    assert spy.calls == 0


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda reviews: reviews[:-1], id="missing"),
        pytest.param(
            lambda reviews: tuple(
                sorted(reviews + (reviews[0],), key=lambda r: r.destination_field)
            ),
            id="duplicate",
        ),
        pytest.param(lambda reviews: tuple(reversed(reviews)), id="unsorted"),
    ],
)
def test_missing_duplicate_or_unsorted_explicit_records_block(monkeypatch, mutate):
    spy, result = spy_build(monkeypatch, context(explicit=mutate(explicit_reviews())))
    assert_blocked(result, expected_status="construction_blocked")
    assert spy.calls == 0


def test_unknown_or_misclassified_explicit_record_blocks(monkeypatch):
    data = as_data()
    data["explicit_context_reviews"][0]["destination_field"] = "not_a_subject_field"
    spy = _SubjectSpy()
    monkeypatch.setattr(build_module, "ApprovedChangeSubject", spy)
    result = construct_approved_change_subject(
        data, expected_supplemental_context_sha256=compute_supplemental_context_sha256(context())
    )
    assert_blocked(result, expected_status="invalid_construction_input")
    assert spy.calls == 0


# --------------------------------------------------------------------------
# Candidate mapping
# --------------------------------------------------------------------------


@pytest.mark.parametrize("destination, source", sorted(EXPECTED_CANDIDATE_SOURCES.items()))
def test_each_candidate_destination_uses_only_the_final_reviewed_value(destination, source):
    fixture = context()
    result = build(fixture)
    review = {r.destination_field: r for r in fixture.legacy_candidate_reviews}[destination]
    assert getattr(result.subject, destination) == review.final_reviewed_value

    record = authorities(result)[destination]
    assert isinstance(record, LegacyCandidateFieldAuthority)
    assert record.authority_kind == "legacy_candidate_final_reviewed_value"
    assert record.source_section == "legacy_candidate_reviews"
    assert record.legacy_source_field == source
    assert record.candidate_decision == review.decision
    assert record.candidate_sha256 == review.candidate_sha256
    assert record.provenance == review.provenance
    assert record.final_value_sha256 == compute_constructed_field_value_sha256(
        destination, review.final_reviewed_value
    )


def test_accepted_candidate_uses_the_exact_candidate_value():
    fixture = context()
    result = build(fixture)
    for review in fixture.legacy_candidate_reviews:
        assert review.decision == "accepted"
        assert getattr(result.subject, review.destination_field) == review.candidate_value


REJECTED = {
    "source_proposal_reference": "prop-2026-07-24-99-rescoped",
    "risk": "high",
    "impact": "two reviewed containers after explicit re-scoping",
    "preconditions": ("operator re-confirms a narrower maintenance window",),
    "verification_criteria": ("re-scoped verification requires two fresh evidence samples",),
}


def rejected_candidate(destination):
    return candidate(
        destination,
        decision="rejected",
        final=REJECTED[destination],
        prov=provenance(reason="legacy candidate rejected after explicit review"),
    )


@pytest.mark.parametrize("destination", sorted(REJECTED))
def test_rejected_candidate_uses_the_explicit_replacement_and_never_leaks(destination):
    review = rejected_candidate(destination)
    fixture = context(candidates=candidate_reviews(**{destination: review}))
    result = build(fixture)

    assert result.status == "subject_constructed"
    assert getattr(result.subject, destination) == REJECTED[destination]
    assert getattr(result.subject, destination) != CANDIDATE_VALUES[destination]

    payload = canonical_subject_json(result.subject)
    raw = CANDIDATE_VALUES[destination]
    for token in (raw,) if isinstance(raw, str) else raw:
        assert token not in payload

    record = authorities(result)[destination]
    assert record.candidate_decision == "rejected"
    assert record.candidate_sha256 == review.candidate_sha256
    assert record.final_value_sha256 == compute_constructed_field_value_sha256(
        destination, REJECTED[destination]
    )
    assert record.final_value_sha256 != compute_constructed_field_value_sha256(destination, raw)


@pytest.mark.parametrize(
    "field, value",
    [
        ("legacy_source_field", "notes"),
        ("legacy_source_field", "fingerprint"),
        ("legacy_source_field", "*"),
        ("destination_field", "blast_radius"),
        ("candidate_sha256", NOT_A_HASH),
        ("decision", "rejected"),
    ],
)
def test_altered_candidate_mapping_hash_or_decision_blocks(monkeypatch, field, value):
    data = as_data()
    for entry in data["legacy_candidate_reviews"]:
        if entry["destination_field"] == "impact":
            entry[field] = value
    spy = _SubjectSpy()
    monkeypatch.setattr(build_module, "ApprovedChangeSubject", spy)
    result = construct_approved_change_subject(
        data, expected_supplemental_context_sha256=compute_supplemental_context_sha256(context())
    )
    assert_blocked(result)
    assert spy.calls == 0


def test_candidate_value_is_never_a_direct_subject_source():
    source = inspect.getsource(build_module._subject_payload)
    assert "final_reviewed_value" in source
    assert "candidate_value" not in source
    assert "reviewed_value" in source


# --------------------------------------------------------------------------
# Context identity gate
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "not-a-hash",
        "a" * 63,
        "a" * 65,
        "A" * 64,
        None,
        7,
        b"a" * 64,
    ],
)
def test_malformed_expected_context_hash_is_invalid_input(monkeypatch, bad):
    spy, result = spy_build(monkeypatch, expected=bad)
    assert_blocked(result, expected_status="invalid_construction_input")
    assert spy.calls == 0
    assert any("64 lowercase hexadecimal" in error for error in result.errors)


def test_uppercase_form_of_the_correct_hash_is_rejected(monkeypatch):
    correct = compute_supplemental_context_sha256(context())
    spy, result = spy_build(monkeypatch, expected=correct.upper())
    assert_blocked(result, expected_status="invalid_construction_input")
    assert spy.calls == 0


def test_hash_from_another_context_is_rejected(monkeypatch):
    other = context(explicit=explicit_reviews(blast_radius="two reviewed targets"))
    spy, result = spy_build(monkeypatch, expected=compute_supplemental_context_sha256(other))
    assert_blocked(result, expected_status="construction_blocked")
    assert spy.calls == 0
    assert result.computed_supplemental_context_sha256 == compute_supplemental_context_sha256(
        context()
    )


def test_candidate_subject_and_evidence_hashes_are_rejected_as_context_identity(monkeypatch):
    success = build()
    wrong_identities = (
        candidate("impact").candidate_sha256,
        success.computed_subject_sha256,
        success.computed_construction_evidence_sha256,
        compute_constructed_field_value_sha256("blast_radius", "one reviewed target only"),
    )
    for wrong in wrong_identities:
        spy, result = spy_build(monkeypatch, expected=wrong)
        assert_blocked(result, expected_status="construction_blocked")
        assert spy.calls == 0


def test_exact_valid_context_hash_is_required_and_sufficient():
    fixture = context()
    assert build(fixture).status == "subject_constructed"
    assert (
        build(fixture, expected=compute_supplemental_context_sha256(fixture)).status
        == "subject_constructed"
    )


# --------------------------------------------------------------------------
# Fresh policy validation
# --------------------------------------------------------------------------


def policy_rules():
    return list(APPROVED_CHANGE_CONSTRUCTION_POLICY.rules)


def policy_without(destination):
    return ApprovedChangeConstructionPolicy(
        rules=tuple(r for r in policy_rules() if r.destination_field != destination)
    )


def policy_replacing(destination, **changes):
    rules = []
    for rule in policy_rules():
        if rule.destination_field == destination:
            rules.append(rule.model_copy(update=changes))
        else:
            rules.append(rule)
    return ApprovedChangeConstructionPolicy(
        rules=tuple(sorted(rules, key=lambda r: r.destination_field))
    )


def test_canonical_policy_is_valid_and_permits_construction():
    assert build().status == "subject_constructed"


@pytest.mark.parametrize(
    "policy_factory, label",
    [
        (lambda: policy_without("blast_radius"), "missing mapping"),
        (
            lambda: ApprovedChangeConstructionPolicy(
                rules=tuple(
                    sorted(policy_rules() + [policy_rules()[0]], key=lambda r: r.destination_field)
                )
            ),
            "duplicate mapping",
        ),
        (
            lambda: ApprovedChangeConstructionPolicy(
                rules=tuple(
                    sorted(
                        policy_rules()
                        + [
                            ConstructionFieldSourceRule(
                                destination_field="extra_destination",
                                source_classification="explicit_context_only",
                                explicit_review_required=True,
                                notes="extra",
                            )
                        ],
                        key=lambda r: r.destination_field,
                    )
                )
            ),
            "extra mapping",
        ),
        (
            lambda: policy_replacing(
                "blast_radius",
                source_classification="legacy_candidate_requires_explicit_review",
                legacy_candidate_fields=("impact",),
            ),
            "altered source classification",
        ),
        (
            lambda: policy_replacing("risk", legacy_candidate_fields=("*",)),
            "wildcard mapping",
        ),
        (
            lambda: policy_replacing("risk", legacy_candidate_fields=("fallback",)),
            "fallback mapping",
        ),
    ],
)
def test_invalid_policy_blocks_construction(monkeypatch, policy_factory, label):
    monkeypatch.setattr(build_module, "APPROVED_CHANGE_CONSTRUCTION_POLICY", policy_factory())
    spy, result = spy_build(monkeypatch)
    assert_blocked(result, expected_status="construction_blocked")
    assert spy.calls == 0, label


def test_non_policy_object_blocks_construction(monkeypatch):
    monkeypatch.setattr(build_module, "APPROVED_CHANGE_CONSTRUCTION_POLICY", object())
    spy, result = spy_build(monkeypatch)
    assert_blocked(result, expected_status="construction_blocked")
    assert spy.calls == 0


def test_policy_schema_version_mismatch_blocks_construction(monkeypatch):
    def invalid_policy_validation(_policy):
        return ConstructionPolicyValidationResult(
            status="policy_invalid",
            policy_valid=False,
            coverage_complete=False,
            expected_destination_fields=(),
            covered_destination_fields=(),
            missing_destination_fields=(),
            unknown_destination_fields=(),
            duplicate_destination_fields=(),
            errors=("construction policy schema_version mismatch",),
        )

    monkeypatch.setattr(
        build_module, "validate_approved_change_construction_policy", invalid_policy_validation
    )
    spy, result = spy_build(monkeypatch)
    assert_blocked(result, expected_status="construction_blocked")
    assert spy.calls == 0
    assert any("schema_version mismatch" in error for error in result.errors)


def test_pr311_production_policy_remains_untouched():
    from shellforgeai.core.approved_change_construction_policy import (
        validate_approved_change_construction_policy,
    )

    result = validate_approved_change_construction_policy(APPROVED_CHANGE_CONSTRUCTION_POLICY)
    assert result.policy_valid is True
    assert result.coverage_complete is True


# --------------------------------------------------------------------------
# Field-authority evidence
# --------------------------------------------------------------------------


def test_exactly_eighteen_sorted_unique_authority_records():
    records = build().construction_evidence.field_authorities
    destinations = [r.destination_field for r in records]
    assert len(records) == 18
    assert destinations == sorted(destinations)
    assert len(set(destinations)) == 18
    assert set(destinations) == set(ApprovedChangeSubject.model_fields)
    assert len(CONTRACT_CONSTANT_FIELDS) + len(EXPLICIT_CONTEXT_DESTINATIONS) + len(
        CANDIDATE_DESTINATIONS
    ) == len(destinations)


def test_contract_constant_authority_is_exact_and_carries_no_provenance():
    record = authorities(build())["schema_version"]
    assert isinstance(record, ContractConstantFieldAuthority)
    assert record.authority_kind == "contract_constant"
    assert record.source_authority == CONTRACT_CONSTANT_SOURCE_AUTHORITY
    assert record.subject_field_matches is True
    assert record.final_value_sha256 == compute_constructed_field_value_sha256(
        "schema_version", APPROVED_CHANGE_SCHEMA_VERSION
    )
    assert "provenance" not in type(record).model_fields
    assert (
        "reviewed_by"
        not in canonical_construction_evidence_json(build().construction_evidence).split(
            '"destination_field":"schema_version"'
        )[1][:200]
    )


def test_every_authority_kind_matches_the_policy_classification():
    records = authorities(build())
    assert records["schema_version"].authority_kind == "contract_constant"
    for destination in EXPLICIT_CONTEXT_DESTINATIONS:
        assert records[destination].authority_kind == "explicit_context_reviewed_value"
    for destination in CANDIDATE_DESTINATIONS:
        assert records[destination].authority_kind == "legacy_candidate_final_reviewed_value"


def test_provenance_present_for_reviewed_fields_only():
    records = authorities(build())
    for destination in (*EXPLICIT_CONTEXT_DESTINATIONS, *CANDIDATE_DESTINATIONS):
        assert isinstance(records[destination].provenance, ReviewProvenance)
    assert not hasattr(records["schema_version"], "provenance")


def test_all_final_value_hashes_match_the_constructed_subject_fields():
    result = build()
    for destination, record in authorities(result).items():
        assert record.final_value_sha256 == compute_constructed_field_value_sha256(
            destination, getattr(result.subject, destination)
        )


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param(
            lambda records: tuple(
                r.model_copy(update={"final_value_sha256": NOT_A_HASH})
                if r.destination_field == "impact"
                else r
                for r in records
            ),
            id="wrong-final-hash",
        ),
        pytest.param(
            lambda records: tuple(
                r.model_copy(update={"candidate_sha256": NOT_A_HASH})
                if r.destination_field == "risk"
                else r
                for r in records
            ),
            id="wrong-candidate-hash",
        ),
        pytest.param(
            lambda records: tuple(
                r.model_copy(update={"candidate_decision": "rejected"})
                if r.destination_field == "risk"
                else r
                for r in records
            ),
            id="wrong-decision",
        ),
        pytest.param(
            lambda records: tuple(
                r.model_copy(update={"legacy_source_field": "notes"})
                if r.destination_field == "impact"
                else r
                for r in records
            ),
            id="wrong-legacy-source",
        ),
        pytest.param(
            lambda records: tuple(
                r.model_copy(update={"source_destination_field": "change_summary"})
                if r.destination_field == "blast_radius"
                else r
                for r in records
            ),
            id="wrong-source-destination",
        ),
        pytest.param(
            lambda records: tuple(
                r.model_copy(
                    update={
                        "provenance": ReviewProvenance(
                            reviewed_by="someone-else",
                            reviewed_at=REVIEW_TIME,
                            review_reason="unrelated",
                        )
                    }
                )
                if r.destination_field == "blast_radius"
                else r
                for r in records
            ),
            id="wrong-provenance",
        ),
        pytest.param(lambda records: records + records[:1], id="duplicate-authority"),
        pytest.param(lambda records: tuple(reversed(records)), id="unsorted-authorities"),
        pytest.param(lambda records: records[1:], id="missing-authority"),
    ],
)
def test_tampered_authority_evidence_fails_verification_before_success(monkeypatch, tamper):
    original = build_module._build_field_authorities

    def tampered(explicit, candidates, subject_values):
        return tamper(original(explicit, candidates, subject_values))

    monkeypatch.setattr(build_module, "_build_field_authorities", tampered)
    result = build()
    assert_blocked(result, expected_status="construction_blocked")
    assert any("verification failed" in error for error in result.errors)


def test_unknown_authority_destination_fails_verification(monkeypatch):
    original = build_module._build_field_authorities

    def tampered(explicit, candidates, subject_values):
        records = original(explicit, candidates, subject_values)
        rogue = records[1].model_copy(update={"destination_field": "not_a_subject_field"})
        return tuple(sorted(records + (rogue,), key=lambda r: r.destination_field))

    monkeypatch.setattr(build_module, "_build_field_authorities", tampered)
    result = build()
    assert_blocked(result, expected_status="construction_blocked")
    assert any("unknown field authority" in error for error in result.errors)


# --------------------------------------------------------------------------
# Identity separation
# --------------------------------------------------------------------------


def identities(result):
    return (
        result.computed_supplemental_context_sha256,
        result.computed_subject_sha256,
        result.computed_construction_evidence_sha256,
    )


def test_context_subject_and_evidence_identities_are_distinct():
    context_sha, subject_sha, evidence_sha = identities(build())
    assert len({context_sha, subject_sha, evidence_sha}) == 3
    assert candidate("impact").candidate_sha256 not in {context_sha, subject_sha, evidence_sha}


def test_construction_identities_never_validate_as_an_approval_binding():
    result = build()
    for wrong in (
        result.computed_supplemental_context_sha256,
        result.computed_construction_evidence_sha256,
    ):
        contract = ApprovedChangeContract(
            subject=result.subject,
            approval=ApprovalAttestation(
                approved_by="operator",
                approved_at=REVIEW_TIME,
                reason="reviewed exact subject",
                subject_sha256=wrong,
            ),
        )
        assert verify_approval_binding(contract).approval_binding_valid is False


@pytest.mark.parametrize(
    "actor, moment, reason",
    [
        ("operator-b", REVIEW_TIME, "explicit field review"),
        ("operator-a", REVIEW_TIME + timedelta(seconds=1), "explicit field review"),
        ("operator-a", REVIEW_TIME, "a different reviewed rationale"),
    ],
)
def test_provenance_only_change_keeps_the_subject_identity_stable(actor, moment, reason):
    base = build()
    changed_reviews = tuple(
        type(r)(reviewed_value=r.reviewed_value, provenance=provenance(actor, moment, reason))
        if r.destination_field == "blast_radius"
        else r
        for r in explicit_reviews()
    )
    other = build(context(explicit=changed_reviews))
    assert other.status == "subject_constructed"
    assert other.computed_subject_sha256 == base.computed_subject_sha256
    assert other.computed_supplemental_context_sha256 != base.computed_supplemental_context_sha256
    assert other.computed_construction_evidence_sha256 != base.computed_construction_evidence_sha256


def test_rejected_candidate_change_with_same_final_value_keeps_subject_identity_stable():
    first = candidate(
        "impact",
        decision="rejected",
        final=REJECTED["impact"],
        prov=provenance(reason="legacy candidate rejected after explicit review"),
    )
    second = candidate(
        "impact",
        value="a materially different legacy impact claim",
        decision="rejected",
        final=REJECTED["impact"],
        prov=provenance(reason="legacy candidate rejected after explicit review"),
    )
    left = build(context(candidates=candidate_reviews(impact=first)))
    right = build(context(candidates=candidate_reviews(impact=second)))

    assert left.status == right.status == "subject_constructed"
    assert left.computed_subject_sha256 == right.computed_subject_sha256
    assert left.computed_supplemental_context_sha256 != right.computed_supplemental_context_sha256
    assert left.computed_construction_evidence_sha256 != right.computed_construction_evidence_sha256


def test_final_reviewed_value_change_changes_every_identity():
    base = build()
    changed = build(context(candidates=candidate_reviews(impact=rejected_candidate("impact"))))
    assert changed.status == "subject_constructed"
    for left, right in zip(identities(base), identities(changed), strict=True):
        assert left != right


def test_explicit_reviewed_value_change_changes_every_identity():
    base = build()
    changed = build(context(explicit=explicit_reviews(blast_radius="two reviewed targets")))
    for left, right in zip(identities(base), identities(changed), strict=True):
        assert left != right


def test_evidence_hash_excludes_its_own_identity():
    evidence_record = build().construction_evidence
    payload = canonical_construction_evidence_json(evidence_record)
    assert compute_construction_evidence_sha256(evidence_record) not in payload
    assert "construction_evidence_sha256" not in payload
    assert "evidence_sha256" not in payload


def test_evidence_payload_binds_every_required_component():
    result = build()
    payload = canonical_construction_evidence_json(result.construction_evidence)
    assert result.computed_supplemental_context_sha256 in payload
    assert result.computed_subject_sha256 in payload
    assert '"schema_version":"1"' in payload
    assert '"approved_change_schema_version":"1"' in payload
    assert '"construction_policy_schema_version":"1"' in payload
    assert '"supplemental_context_schema_version":"1"' in payload
    assert payload.count('"final_value_sha256"') == 18
    assert payload.count('"candidate_sha256"') == 5
    assert payload.count('"provenance"') == 17
    for warning in PERMANENT_CONSTRUCTION_WARNINGS:
        assert warning in payload


# --------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------


def test_repeated_construction_is_byte_identical():
    first, second = build(), build()
    assert canonical_construction_evidence_json(
        first.construction_evidence
    ) == canonical_construction_evidence_json(second.construction_evidence)
    assert canonical_construction_evidence_json(first.construction_evidence).encode("utf-8") == (
        canonical_construction_evidence_json(second.construction_evidence).encode("utf-8")
    )
    assert canonical_subject_json(first.subject) == canonical_subject_json(second.subject)
    assert identities(first) == identities(second)


def test_canonical_evidence_json_is_compact_and_sorted():
    payload = canonical_construction_evidence_json(build().construction_evidence)
    assert re.search(r'[}\]"],\s', payload) is None
    assert '": ' not in payload
    assert payload.index('"approved_change_schema_version"') < payload.index('"schema_version"')
    assert "2026-07-24T12:00:00Z" in payload


def test_non_ascii_reviewed_values_stay_deterministic_and_unescaped():
    reviews = explicit_reviews(blast_radius="un solo contenedor révisé — 単一のみ")
    first = build(context(explicit=reviews))
    second = build(
        context(explicit=explicit_reviews(blast_radius="un solo contenedor révisé — 単一のみ"))
    )
    assert first.status == "subject_constructed"
    assert "révisé" in canonical_subject_json(first.subject)
    assert identities(first) == identities(second)


def test_equivalent_timezone_offsets_normalize_to_the_same_identities():
    shifted = REVIEW_TIME.astimezone(timezone(timedelta(hours=-6)))
    assert shifted.utcoffset() == timedelta(hours=-6)
    base = build()
    other = build(
        context(
            explicit=explicit_reviews(prov=provenance(at=shifted)),
            candidates=tuple(
                candidate(destination, prov=provenance(at=shifted))
                for destination in sorted(CANDIDATE_VALUES)
            ),
        )
    )
    assert other.status == "subject_constructed"
    assert identities(other) == identities(base)


@pytest.mark.parametrize(
    "reviews",
    [
        pytest.param(
            explicit_reviews(target=target((("host", "docker01"), ("id", "abc123")))),
            id="identity-claims",
        ),
        pytest.param(
            explicit_reviews(evidence_references=evidence(("ev-2", "ev-1"))),
            id="evidence-references",
        ),
    ],
)
def test_set_like_input_order_does_not_affect_identity(reviews):
    base = build()
    reordered = build(context(explicit=reviews))
    assert reordered.status == "subject_constructed"
    assert identities(reordered) == identities(base)


@pytest.mark.parametrize(
    "fixture_factory, label",
    [
        (
            lambda: context(explicit=explicit_reviews(procedure=steps(("step-2", "step-1")))),
            "procedure",
        ),
        (
            lambda: context(
                explicit=explicit_reviews(rollback_posture=rollback(("rollback-2", "rollback-1")))
            ),
            "rollback procedure",
        ),
        (
            lambda: context(
                candidates=candidate_reviews(
                    preconditions=candidate(
                        "preconditions", value=tuple(reversed(CANDIDATE_VALUES["preconditions"]))
                    )
                )
            ),
            "preconditions",
        ),
        (
            lambda: context(
                candidates=candidate_reviews(
                    verification_criteria=candidate(
                        "verification_criteria",
                        value=tuple(reversed(CANDIDATE_VALUES["verification_criteria"])),
                    )
                )
            ),
            "verification criteria",
        ),
    ],
)
def test_semantic_ordering_changes_every_identity(fixture_factory, label):
    base = build()
    reordered = build(fixture_factory())
    assert reordered.status == "subject_constructed", label
    for left, right in zip(identities(base), identities(reordered), strict=True):
        assert left != right, label


def test_field_value_identity_binds_schema_destination_and_value():
    payload = canonical_field_value_json("blast_radius", "one reviewed target only")
    assert payload == (
        '{"destination_field":"blast_radius","schema_version":"1",'
        '"value":"one reviewed target only"}'
    )
    assert FIELD_VALUE_IDENTITY_SCHEMA_VERSION == "1"
    assert compute_constructed_field_value_sha256(
        "blast_radius", "x"
    ) != compute_constructed_field_value_sha256("change_summary", "x")
    assert compute_constructed_field_value_sha256(
        "blast_radius", "x"
    ) != compute_constructed_field_value_sha256("blast_radius", "y")


def test_field_value_identity_applies_pr309_set_like_ordering():
    assert compute_constructed_field_value_sha256(
        "target", target()
    ) == compute_constructed_field_value_sha256(
        "target", target((("host", "docker01"), ("id", "abc123")))
    )
    assert compute_constructed_field_value_sha256(
        "evidence_references", evidence()
    ) == compute_constructed_field_value_sha256("evidence_references", evidence(("ev-2", "ev-1")))
    assert compute_constructed_field_value_sha256(
        "procedure", steps()
    ) != compute_constructed_field_value_sha256("procedure", steps(("step-2", "step-1")))


# --------------------------------------------------------------------------
# Subject-model failure
# --------------------------------------------------------------------------


def test_pr309_subject_rejection_returns_no_subject_and_no_evidence(monkeypatch):
    spy, result = spy_build(monkeypatch, fail=True)
    assert spy.calls == 1
    assert_blocked(result, expected_status="construction_blocked")
    assert any("subject validation failed" in error for error in result.errors)


def test_pr309_validation_is_not_weakened():
    with pytest.raises(ValidationError):
        ApprovedChangeSubject(source_proposal_reference="", capability_id="*", target=target())


# --------------------------------------------------------------------------
# Non-throwing structured behavior
# --------------------------------------------------------------------------


def test_valid_model_and_dictionary_input_agree():
    fixture = context()
    expected = compute_supplemental_context_sha256(fixture)
    from_model = construct_approved_change_subject(
        fixture, expected_supplemental_context_sha256=expected
    )
    from_dict = construct_approved_change_subject(
        as_data(fixture), expected_supplemental_context_sha256=expected
    )
    assert from_model.status == from_dict.status == "subject_constructed"
    assert identities(from_model) == identities(from_dict)


@pytest.mark.parametrize(
    "bad_input",
    [None, "context", 7, [], ("explicit_context_reviews",), object(), b"{}"],
)
def test_non_mapping_input_is_structured_invalid(monkeypatch, bad_input):
    spy = _SubjectSpy()
    monkeypatch.setattr(build_module, "ApprovedChangeSubject", spy)
    result = construct_approved_change_subject(
        bad_input, expected_supplemental_context_sha256=NOT_A_HASH
    )
    assert_blocked(result, expected_status="invalid_construction_input")
    assert spy.calls == 0


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
def test_malformed_dictionaries_return_structured_results(monkeypatch, data):
    spy = _SubjectSpy()
    monkeypatch.setattr(build_module, "ApprovedChangeSubject", spy)
    result = construct_approved_change_subject(
        data, expected_supplemental_context_sha256=NOT_A_HASH
    )
    assert_blocked(result, expected_status="invalid_construction_input")
    assert spy.calls == 0


@pytest.mark.parametrize(
    "field",
    ["schema_version", "construction_policy_schema_version", "approved_change_schema_version"],
)
def test_invalid_context_versions_block(monkeypatch, field):
    data = as_data()
    data[field] = "2"
    spy = _SubjectSpy()
    monkeypatch.setattr(build_module, "ApprovedChangeSubject", spy)
    result = construct_approved_change_subject(
        data, expected_supplemental_context_sha256=compute_supplemental_context_sha256(context())
    )
    assert_blocked(result)
    assert spy.calls == 0


def test_extra_fields_are_rejected_not_repaired(monkeypatch):
    data = as_data()
    data["extra_reviewed_context"] = {"anything": "value"}
    spy = _SubjectSpy()
    monkeypatch.setattr(build_module, "ApprovedChangeSubject", spy)
    result = construct_approved_change_subject(
        data, expected_supplemental_context_sha256=compute_supplemental_context_sha256(context())
    )
    assert_blocked(result, expected_status="invalid_construction_input")
    assert spy.calls == 0


def test_invalid_input_is_never_silently_reordered_into_validity(monkeypatch):
    unsorted_context = context(explicit=tuple(reversed(explicit_reviews())))
    spy, result = spy_build(
        monkeypatch,
        unsorted_context,
        expected=compute_supplemental_context_sha256(unsorted_context),
    )
    assert_blocked(result, expected_status="construction_blocked")
    assert spy.calls == 0
    assert any("not valid" in error for error in result.errors)


def test_errors_are_deterministic_sorted_and_deduplicated():
    first = build(context(explicit=explicit_reviews()[:3]))
    second = build(context(explicit=explicit_reviews()[:3]))
    assert first.errors == second.errors
    assert list(first.errors) == sorted(set(first.errors))


def test_public_construction_never_raises_for_untrusted_input():
    for bad in (None, {}, [], "x", 3, object(), {"explicit_context_reviews": None}):
        for expected in (None, "", NOT_A_HASH, "ZZ", 5):
            result = construct_approved_change_subject(
                bad, expected_supplemental_context_sha256=expected
            )
            assert isinstance(result, ApprovedChangeSubjectConstructionResult)
            assert result.construction_succeeded is False


# --------------------------------------------------------------------------
# Immutability
# --------------------------------------------------------------------------


def test_result_subject_evidence_and_authority_records_are_frozen():
    result = build()
    with pytest.raises(ValidationError):
        result.status = "construction_blocked"
    with pytest.raises(ValidationError):
        result.subject.blast_radius = "changed"
    with pytest.raises(ValidationError):
        result.construction_evidence.subject_sha256 = NOT_A_HASH
    record = authorities(result)["impact"]
    with pytest.raises(ValidationError):
        record.final_value_sha256 = NOT_A_HASH
    with pytest.raises(ValidationError):
        record.provenance.reviewed_by = "someone-else"


def test_nested_tuples_cannot_be_appended_to():
    result = build()
    assert isinstance(result.construction_evidence.field_authorities, tuple)
    assert isinstance(result.warnings, tuple)
    assert isinstance(result.construction_evidence.warnings, tuple)
    with pytest.raises(AttributeError):
        result.construction_evidence.field_authorities.append(
            result.construction_evidence.field_authorities[0]
        )
    with pytest.raises(AttributeError):
        result.subject.procedure.append(result.subject.procedure[0])


def test_reused_fixture_is_not_mutated_by_construction():
    fixture = context()
    before = fixture.model_dump(mode="json")
    build(fixture)
    assert fixture.model_dump(mode="json") == before
    assert copy.deepcopy(before) == before


# --------------------------------------------------------------------------
# Side-effect guards
# --------------------------------------------------------------------------


def test_no_side_effects_on_success_or_blocked_paths(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("side effect attempted")

    monkeypatch.setattr(Path, "read_text", boom)
    monkeypatch.setattr(Path, "write_text", boom)
    monkeypatch.setattr(Path, "open", boom)
    monkeypatch.setattr(Path, "mkdir", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(os, "system", boom)
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)

    before = dict(os.environ)
    assert build().status == "subject_constructed"
    assert build(expected=NOT_A_HASH).construction_succeeded is False
    assert construct_approved_change_subject({}, expected_supplemental_context_sha256=NOT_A_HASH)
    assert compute_constructed_field_value_sha256("blast_radius", "reviewed")
    assert dict(os.environ) == before


def test_construction_creates_no_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    build()
    build(expected=NOT_A_HASH)
    assert list(tmp_path.iterdir()) == []


# --------------------------------------------------------------------------
# Static source guards
# --------------------------------------------------------------------------


def module_code_without_docstrings():
    """Return the production module's executable code with docstrings removed."""
    tree = ast.parse(Path(build_module.__file__).read_text(encoding="utf-8"))
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


def test_static_no_io_execution_persistence_or_model_paths():
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
        "datetime.now",
        "utcnow",
        "now()",
        "json.dump(",
        "json.load(",
        "save_",
        "persist_",
        "write_artifact",
        "preflight",
        "receipt_linkage",
        "windows.runtime_reconcile",
        "recipe",
        "RECIPE",
        "typer",
        "app.command",
    ]
    for token in forbidden:
        assert token not in source, token


def test_static_no_proposal_approval_or_contract_construction():
    source = module_code_without_docstrings()
    for token in ("Proposal", "core.approvals", "ApprovalAttestation", "ApprovedChangeContract"):
        assert token not in source, token
    assert source.count("ApprovedChangeSubject(") == 1
    assert "ApprovedChangeSubjectConstructionEvidence(" in source


def test_static_no_pr313_execution_or_registry_imports():
    tree = ast.parse(Path(build_module.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    assert imported == {
        "hashlib",
        "hmac",
        "json",
        "re",
        "collections",
        "typing",
        "pydantic",
        "shellforgeai.core.approved_change_construction_policy",
        "shellforgeai.core.approved_change_contract",
        "shellforgeai.core.approved_change_supplemental_context",
        "__future__",
    }


def test_static_signatures_never_take_proposal_or_return_approval_types():
    for _, obj in inspect.getmembers(build_module, inspect.isfunction):
        signature = inspect.signature(obj)
        assert all(param.annotation is not Proposal for param in signature.parameters.values())
        assert signature.return_annotation not in {ApprovalAttestation, ApprovedChangeContract}
        assert "Proposal" not in str(signature)


def test_module_exposes_no_cli_registry_or_persistence_surface():
    for name in (
        "app",
        "cli",
        "main",
        "register",
        "REGISTRY",
        "CAPABILITY_REGISTRY",
        "load_proposal",
        "extract_candidate_values",
        "persist_subject",
        "save_construction_evidence",
        "evaluate_capability_support",
        "bind_capability",
    ):
        assert not hasattr(build_module, name)


@pytest.mark.parametrize("function_name", ["_subject_payload", "_subject_field_values"])
def test_field_mapping_is_literal_and_exhaustive_with_no_generic_fallback(function_name):
    tree = ast.parse(inspect.getsource(getattr(build_module, function_name)).lstrip())
    function = tree.body[0]
    returns = [node for node in ast.walk(function) if isinstance(node, ast.Return)]
    assert len(returns) == 1
    mapping = returns[0].value
    assert isinstance(mapping, ast.Dict)
    keys = [key.value for key in mapping.keys]
    assert all(isinstance(key.value, str) for key in mapping.keys)
    assert sorted(keys) == sorted(ApprovedChangeSubject.model_fields)
    assert len(keys) == 18
    for node in ast.walk(function):
        assert not isinstance(node, ast.For | ast.While | ast.DictComp | ast.comprehension)
        if isinstance(node, ast.Attribute):
            assert node.attr not in {"get", "setdefault", "pop"}
        assert not (isinstance(node, ast.Name) and node.id == "getattr")


def test_source_documents_the_reviewer_provenance_and_capability_boundaries():
    warnings = " ".join(PERMANENT_CONSTRUCTION_WARNINGS)
    assert "not approved, authorized, bound, persisted, or executable" in warnings
    assert "capability support was not evaluated" in warnings
    assert "not an approval attestation" in warnings
    assert "not authenticated identity" in warnings
