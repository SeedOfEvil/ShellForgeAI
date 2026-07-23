from __future__ import annotations

import builtins
import json
import os
import socket
import subprocess

import pytest
from pydantic import ValidationError

from shellforgeai.core import approved_change_contract as contract_mod
from shellforgeai.core.approvals import (
    STATUS_APPROVED,
    STATUS_ARCHIVED,
    STATUS_CANCELED,
    STATUS_PENDING,
    STATUS_REJECTED,
    Proposal,
    ProposalApproval,
    ProposalSource,
)
from shellforgeai.core.approved_change_compatibility import (
    AMBIGUOUS_FIELDS,
    CANDIDATE_SOURCE_FIELDS,
    MISSING_REQUIRED_FIELDS,
    PROHIBITED_INFERENCES,
    CompatibilityFinding,
    LegacyProposalCompatibilityReport,
    assess_legacy_proposal_compatibility,
)


def proposal(status: str = STATUS_PENDING) -> Proposal:
    return Proposal(
        proposal_id="pr310-proposal",
        status=status,
        source=ProposalSource(
            session_id="session-1",
            runbook="runbook-a",
            evidence="evidence-a",
            summary="source summary",
        ),
        target="web01",
        component="nginx",
        kind="docker_restart",
        title="Restart nginx container",
        risk="medium",
        impact="brief interruption",
        evidence=["container unhealthy"],
        preconditions=["operator has maintenance window"],
        proposed_steps=["docker restart nginx"],
        rollback=["restart previous container manually"],
        verification=["check health endpoint"],
        notes="review notes",
        fingerprint={"sha256": "a" * 64},
        source_hashes={"runbook": "sha256:" + "b" * 64},
    )


def codes(report: LegacyProposalCompatibilityReport) -> set[str]:
    return {finding.code for finding in report.findings}


def messages(report: LegacyProposalCompatibilityReport) -> str:
    return "\n".join(f.message for f in report.findings)


def test_baseline_pending_proposal_requires_explicit_context_and_fixed_safety() -> None:
    report = assess_legacy_proposal_compatibility(proposal())

    assert report.status == "requires_explicit_context"
    assert report.legacy_status == STATUS_PENDING
    assert report.compatible_as_is is False
    assert report.approval_portable is False
    assert report.fingerprint_equivalent is False
    assert report.candidate_source_fields == CANDIDATE_SOURCE_FIELDS
    assert set(report.missing_required_fields) == set(MISSING_REQUIRED_FIELDS)
    assert set(report.ambiguous_fields) == set(AMBIGUOUS_FIELDS)
    assert set(report.prohibited_inferences) == set(PROHIBITED_INFERENCES)
    assert report.read_only is True
    assert report.mutation_performed is False
    assert report.contract_created is False
    assert report.approval_created is False
    assert report.execution_allowed is False
    assert report.execution_available is False
    assert report.execution_status == "not_executed"
    assert all(
        not hasattr(report, attr) for attr in ("subject", "approval_attestation", "contract")
    )


def test_approved_proposal_does_not_gain_compatibility_or_create_approval() -> None:
    approved = proposal(STATUS_APPROVED)
    approved.approval = ProposalApproval(
        approved_by="operator",
        approved_at="2026-07-20T12:00:00Z",
        reason="legacy approval",
    )

    report = assess_legacy_proposal_compatibility(approved)

    assert report.legacy_status == STATUS_APPROVED
    assert report.status == "requires_explicit_context"
    assert report.compatible_as_is is False
    assert report.approval_portable is False
    assert report.approval_created is False
    assert "legacy_approval_not_portable" in codes(report)
    assert "exact_subject_only" in messages(report)
    assert "authenticated identity" in messages(report)
    assert not hasattr(report, "subject_sha256")


@pytest.mark.parametrize("status", [STATUS_REJECTED, STATUS_CANCELED, STATUS_ARCHIVED])
def test_other_legacy_statuses_remain_nonportable_and_incompatible(status: str) -> None:
    report = assess_legacy_proposal_compatibility(proposal(status))

    assert report.legacy_status == status
    assert report.compatible_as_is is False
    assert report.approval_portable is False
    assert report.contract_created is False
    assert report.approval_created is False
    assert report.execution_allowed is False


def test_candidate_mapping_limited_to_explicitly_permitted_sources() -> None:
    report = assess_legacy_proposal_compatibility(proposal().model_dump())

    assert report.candidate_source_fields == tuple(sorted(report.candidate_source_fields))
    for field in ("proposal_id", "risk", "impact", "preconditions", "verification", "rollback"):
        assert field in report.candidate_source_fields
    forbidden = {"kind", "target", "component", "proposed_steps", "approval", "fingerprint"}
    assert forbidden.isdisjoint(report.candidate_source_fields)
    assert all(
        f.candidate_reuse is True for f in report.findings if f.category == "candidate_mapping"
    )
    assert all(
        "automatically" in f.message for f in report.findings if f.category == "candidate_mapping"
    )


def test_missing_ambiguity_and_prohibited_inference_coverage() -> None:
    report = assess_legacy_proposal_compatibility(proposal())

    assert set(report.missing_required_fields) == {
        "capability_id",
        "target_identity",
        "desired_outcome",
        "diagnosis_summary",
        "evidence_reference_ids",
        "evidence_source_identity",
        "evidence_sha256_references",
        "evidence_observation_timestamps",
        "change_summary",
        "blast_radius",
        "procedure_steps",
        "revalidation_requirements",
        "rollback_posture",
        "audit_requirements",
        "unsupported_or_irreversible_aspects",
        "pr309_subject_sha256",
        "exact_subject_only_attestation_scope",
    }
    for code in (
        "ambiguous_kind",
        "ambiguous_target",
        "ambiguous_proposed_steps",
        "ambiguous_rollback",
        "ambiguous_evidence",
        "legacy_approval_not_portable",
        "legacy_fingerprint_not_subject_sha256",
    ):
        assert code in codes(report)
    for inference in (
        "capability_id",
        "target_identity",
        "evidence_timestamps",
        "step_ids",
        "expected_effects",
        "blast_radius",
        "revalidation_requirements",
        "audit_requirements",
        "pr309_attestation",
        "subject_hash",
    ):
        assert inference in report.prohibited_inferences
        assert f"prohibited_infer_{inference}" in codes(report)


def test_fingerprint_is_never_equivalent_and_subject_hash_not_computed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_compute(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("compute_subject_sha256 must not be called")

    monkeypatch.setattr(contract_mod, "compute_subject_sha256", fail_compute)
    with_fp = assess_legacy_proposal_compatibility(proposal())
    changed = proposal()
    changed.fingerprint = {"sha256": "c" * 64}
    with_changed_fp = assess_legacy_proposal_compatibility(changed)
    removed = proposal()
    removed.fingerprint = {}
    without_fp = assess_legacy_proposal_compatibility(removed)

    for report in (with_fp, with_changed_fp, without_fp):
        assert report.fingerprint_equivalent is False
        assert report.compatible_as_is is False
        assert "legacy_fingerprint_not_subject_sha256" in codes(report)
        assert "different field set" in messages(report)
        assert "no PR309 subject was constructed" in messages(report)


def test_invalid_legacy_proposal_behavior_is_documented_report() -> None:
    report = assess_legacy_proposal_compatibility({"schema_version": "1"})

    assert report.status == "invalid_legacy_proposal"
    assert report.compatible_as_is is False
    assert report.approval_portable is False
    assert report.fingerprint_equivalent is False
    assert report.candidate_source_fields == ()
    assert report.legacy_status == "invalid"
    assert [f.code for f in report.findings] == ["invalid_legacy_proposal"]


def test_deterministic_output_and_ordering() -> None:
    report1 = assess_legacy_proposal_compatibility(proposal())
    report2 = assess_legacy_proposal_compatibility(proposal())

    assert report1.model_dump(mode="json") == report2.model_dump(mode="json")
    assert json.dumps(report1.model_dump(mode="json"), sort_keys=True) == json.dumps(
        report2.model_dump(mode="json"), sort_keys=True
    )
    assert report1.candidate_source_fields == tuple(sorted(report1.candidate_source_fields))
    assert report1.missing_required_fields == tuple(sorted(report1.missing_required_fields))
    assert report1.ambiguous_fields == tuple(sorted(report1.ambiguous_fields))
    assert report1.prohibited_inferences == tuple(sorted(report1.prohibited_inferences))
    ordered = [
        (f.category, f.code, f.legacy_field, f.approved_change_field) for f in report1.findings
    ]
    assert ordered == sorted(ordered)
    assert "2026" not in json.dumps(report1.model_dump(mode="json"))


def test_report_and_nested_findings_are_immutable() -> None:
    report = assess_legacy_proposal_compatibility(proposal())

    with pytest.raises(ValidationError):
        report.compatible_as_is = True  # type: ignore[misc]
    with pytest.raises(ValidationError):
        report.findings[0].message = "changed"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        report.findings.append(
            CompatibilityFinding(  # type: ignore[attr-defined]
                code="x",
                category="candidate_mapping",
                severity="info",
                legacy_field="x",
                approved_change_field="x",
                message="x",
            )
        )


def test_input_proposal_is_not_mutated() -> None:
    original = proposal()
    before = original.model_dump(mode="json")

    assess_legacy_proposal_compatibility(original)

    assert original.model_dump(mode="json") == before


def test_import_and_assessment_have_no_operational_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("operational side effect attempted")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)

    report = assess_legacy_proposal_compatibility(proposal())

    assert report.read_only is True
    assert report.mutation_performed is False
    assert report.execution_status == "not_executed"


def test_ast_contains_no_side_effect_imports_or_calls() -> None:
    from pathlib import Path

    text = Path("src/shellforgeai/core/approved_change_compatibility.py").read_text(
        encoding="utf-8"
    )
    forbidden = (
        "subprocess",
        "socket",
        "requests",
        "urllib",
        "Path(",
        ".write_text",
        ".read_text",
        "os.environ",
        "compute_subject_sha256",
        "ApprovedChangeSubject(",
        "ApprovalAttestation(",
        "ApprovedChangeContract(",
    )
    for token in forbidden:
        assert token not in text
