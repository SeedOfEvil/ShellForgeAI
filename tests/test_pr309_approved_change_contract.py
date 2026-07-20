from __future__ import annotations

import ast
import importlib
import os
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from shellforgeai.core.approved_change_contract import (
    ApprovalAttestation,
    ApprovedChangeContract,
    ApprovedChangeSubject,
    ApprovedChangeTarget,
    ContractValidationResult,
    EvidenceReference,
    ProcedureStep,
    RollbackPosture,
    TargetIdentityClaim,
    canonical_subject_json,
    canonical_subject_payload,
    compute_subject_sha256,
    validate_approved_change_contract,
    verify_approval_binding,
)

CAP = "test.synthetic_bounded_change"
SHA_A = "a" * 64
SHA_B = "b" * 64


def subject(**overrides):
    data = dict(
        schema_version="1",
        source_proposal_reference="proposal:synthetic-1",
        capability_id=CAP,
        target=ApprovedChangeTarget(
            kind="container",
            name="demo",
            identity_claims=(
                TargetIdentityClaim(key="container_id", value="abc123"),
                TargetIdentityClaim(key="compose_service", value="web"),
            ),
        ),
        desired_outcome="restore healthy response",
        diagnosis_summary="configuration drift caused a failed health check",
        risk="medium",
        evidence_references=(
            EvidenceReference(
                reference_id="ev-2",
                source="health-report",
                sha256=SHA_B,
                observed_at=datetime(2026, 7, 20, 10, tzinfo=timezone.utc),
            ),
            EvidenceReference(
                reference_id="ev-1",
                source="logs-report",
                sha256=SHA_A,
                observed_at=datetime(2026, 7, 20, 9, tzinfo=timezone(timedelta(hours=-4))),
            ),
        ),
        change_summary="bounded reviewed configuration correction",
        impact="single service may refresh state",
        blast_radius="one synthetic target only",
        procedure=(
            ProcedureStep(
                step_id="step-1",
                description="inspect approved state",
                expected_effect="state is understood",
            ),
            ProcedureStep(
                step_id="step-2",
                description="apply bounded correction description",
                expected_effect="configuration matches review",
            ),
        ),
        preconditions=("operator is in an approved maintenance window",),
        revalidation_requirements=("re-read current target identity before any future execution",),
        verification_criteria=("health check reports healthy",),
        rollback_posture=RollbackPosture(
            reversible=True,
            summary="manual recovery is expected to be possible",
            procedure=(
                ProcedureStep(
                    step_id="rb-1",
                    description="restore previous reviewed state",
                    expected_effect="target returns to prior state",
                ),
            ),
            limitations=("automatic rollback is unsupported",),
        ),
        audit_requirements=("record subject hash and verification result",),
        unsupported_or_irreversible_aspects=("none identified during review",),
    )
    data.update(overrides)
    return ApprovedChangeSubject(**data)


def contract(subj=None, *, sha=None):
    subj = subj or subject()
    return ApprovedChangeContract(
        schema_version="1",
        subject=subj,
        approval=ApprovalAttestation(
            schema_version="1",
            approved_by="operator@example.test",
            approved_at=datetime(2026, 7, 20, 12, tzinfo=timezone.utc),
            reason="reviewed exact subject",
            subject_sha256=sha or compute_subject_sha256(subj),
            scope="exact_subject_only",
        ),
    )


def assert_inert_valid(res: ContractValidationResult):
    assert res.status == "contract_valid"
    assert res.contract_valid is True
    assert res.approval_binding_valid is True
    assert res.capability_supported is True
    assert res.read_only is True
    assert res.mutation_performed is False
    assert res.execution_allowed is False
    assert res.execution_available is False
    assert res.execution_status == "not_executed"


def test_baseline_valid_contract_and_exact_capability_support_only():
    c = contract()
    with pytest.raises(ValidationError):
        c.subject.desired_outcome = "changed"
    assert_inert_valid(validate_approved_change_contract(c, {CAP}))
    assert validate_approved_change_contract(c, set()).status == "unsupported_capability"
    assert validate_approved_change_contract(c, {CAP + ".extra"}).status == "unsupported_capability"
    assert verify_approval_binding(c).approval_binding_valid is True


def test_canonical_hash_stability_unordered_identity_and_evidence_and_timezone_normalization():
    baseline = subject()
    reordered = subject(
        target=ApprovedChangeTarget(
            kind="container",
            name="demo",
            identity_claims=tuple(reversed(baseline.target.identity_claims)),
        ),
        evidence_references=tuple(reversed(baseline.evidence_references)),
    )
    assert canonical_subject_json(baseline) == canonical_subject_json(reordered)
    assert compute_subject_sha256(baseline) == compute_subject_sha256(reordered)
    assert canonical_subject_json(baseline).encode() == canonical_subject_json(baseline).encode()
    assert canonical_subject_payload(baseline)["evidence_references"][0]["observed_at"].endswith(
        "Z"
    )


def test_canonical_hash_preserves_microsecond_precision_and_invalidates_attestation():
    observed_100ms = datetime(2026, 7, 20, 12, 0, 0, 100000, tzinfo=timezone.utc)
    observed_200ms = datetime(2026, 7, 20, 12, 0, 0, 200000, tzinfo=timezone.utc)
    baseline = subject(
        evidence_references=(
            EvidenceReference(
                reference_id="ev-1",
                source="logs-report",
                sha256=SHA_A,
                observed_at=observed_100ms,
            ),
        )
    )
    mutated = subject(
        evidence_references=(
            EvidenceReference(
                reference_id="ev-1",
                source="logs-report",
                sha256=SHA_A,
                observed_at=observed_200ms,
            ),
        )
    )
    assert "2026-07-20T12:00:00.100000Z" in canonical_subject_json(baseline)
    assert "2026-07-20T12:00:00.200000Z" in canonical_subject_json(mutated)
    assert canonical_subject_json(baseline) != canonical_subject_json(mutated)
    assert compute_subject_sha256(baseline) != compute_subject_sha256(mutated)

    approved = contract(baseline)
    assert verify_approval_binding(approved).approval_binding_valid is True
    mismatch = ApprovedChangeContract(subject=mutated, approval=approved.approval)
    binding = verify_approval_binding(mismatch)
    validation = validate_approved_change_contract(mismatch, {CAP})
    assert binding.status == "approval_mismatch"
    assert validation.status == "approval_mismatch"
    assert validation.execution_allowed is False
    assert validation.execution_available is False
    assert validation.execution_status == "not_executed"


def test_canonical_hash_keeps_timezone_equivalence_with_equal_microseconds():
    utc_subject = subject(
        evidence_references=(
            EvidenceReference(
                reference_id="ev-1",
                source="logs-report",
                sha256=SHA_A,
                observed_at=datetime(2026, 7, 20, 12, 0, 0, 100000, tzinfo=timezone.utc),
            ),
        )
    )
    offset_subject = subject(
        evidence_references=(
            EvidenceReference(
                reference_id="ev-1",
                source="logs-report",
                sha256=SHA_A,
                observed_at=datetime(
                    2026, 7, 20, 8, 0, 0, 100000, tzinfo=timezone(timedelta(hours=-4))
                ),
            ),
        )
    )
    assert canonical_subject_json(utc_subject) == canonical_subject_json(offset_subject)
    assert compute_subject_sha256(utc_subject) == compute_subject_sha256(offset_subject)


def test_procedure_order_and_contents_are_hash_significant():
    baseline = subject()
    swapped = subject(procedure=tuple(reversed(baseline.procedure)))
    changed = subject(
        procedure=(
            ProcedureStep(
                step_id="step-1x",
                description="inspect approved state",
                expected_effect="state is understood",
            ),
            baseline.procedure[1],
        )
    )
    changed_desc = subject(
        procedure=(
            ProcedureStep(
                step_id="step-1",
                description="inspect different state",
                expected_effect="state is understood",
            ),
            baseline.procedure[1],
        )
    )
    changed_effect = subject(
        procedure=(
            ProcedureStep(
                step_id="step-1",
                description="inspect approved state",
                expected_effect="different effect",
            ),
            baseline.procedure[1],
        )
    )
    hashes = {
        compute_subject_sha256(item)
        for item in (baseline, swapped, changed, changed_desc, changed_effect)
    }
    assert len(hashes) == 5


MUTATIONS = [
    ("source proposal reference", lambda s: subject(source_proposal_reference="proposal:changed")),
    ("capability ID", lambda s: subject(capability_id="test.synthetic_other")),
    (
        "target kind",
        lambda s: subject(
            target=ApprovedChangeTarget(
                kind="host", name=s.target.name, identity_claims=s.target.identity_claims
            )
        ),
    ),
    (
        "target name",
        lambda s: subject(
            target=ApprovedChangeTarget(
                kind=s.target.kind, name="other", identity_claims=s.target.identity_claims
            )
        ),
    ),
    (
        "target identity key",
        lambda s: subject(
            target=ApprovedChangeTarget(
                kind=s.target.kind,
                name=s.target.name,
                identity_claims=(
                    TargetIdentityClaim(key="other", value="abc123"),
                    s.target.identity_claims[1],
                ),
            )
        ),
    ),
    (
        "target identity value",
        lambda s: subject(
            target=ApprovedChangeTarget(
                kind=s.target.kind,
                name=s.target.name,
                identity_claims=(
                    TargetIdentityClaim(key="container_id", value="xyz"),
                    s.target.identity_claims[1],
                ),
            )
        ),
    ),
    ("desired outcome", lambda s: subject(desired_outcome="different outcome")),
    ("diagnosis summary", lambda s: subject(diagnosis_summary="different diagnosis")),
    ("risk", lambda s: subject(risk="high")),
    (
        "evidence reference ID",
        lambda s: subject(
            evidence_references=(
                EvidenceReference(
                    reference_id="ev-x",
                    source="health-report",
                    sha256=SHA_B,
                    observed_at=s.evidence_references[0].observed_at,
                ),
                s.evidence_references[1],
            )
        ),
    ),
    (
        "evidence source",
        lambda s: subject(
            evidence_references=(
                EvidenceReference(
                    reference_id="ev-2",
                    source="other",
                    sha256=SHA_B,
                    observed_at=s.evidence_references[0].observed_at,
                ),
                s.evidence_references[1],
            )
        ),
    ),
    (
        "evidence sha",
        lambda s: subject(
            evidence_references=(
                EvidenceReference(
                    reference_id="ev-2",
                    source="health-report",
                    sha256="c" * 64,
                    observed_at=s.evidence_references[0].observed_at,
                ),
                s.evidence_references[1],
            )
        ),
    ),
    (
        "evidence observed",
        lambda s: subject(
            evidence_references=(
                EvidenceReference(
                    reference_id="ev-2",
                    source="health-report",
                    sha256=SHA_B,
                    observed_at=datetime(2026, 7, 21, tzinfo=timezone.utc),
                ),
                s.evidence_references[1],
            )
        ),
    ),
    ("change summary", lambda s: subject(change_summary="different change")),
    ("impact", lambda s: subject(impact="different impact")),
    ("blast radius", lambda s: subject(blast_radius="different blast")),
    (
        "procedure",
        lambda s: subject(
            procedure=s.procedure
            + (ProcedureStep(step_id="step-3", description="third", expected_effect="reviewed"),)
        ),
    ),
    ("preconditions", lambda s: subject(preconditions=("different precondition",))),
    ("revalidation", lambda s: subject(revalidation_requirements=("different revalidation",))),
    ("verification", lambda s: subject(verification_criteria=("different verification",))),
    (
        "rollback reversible",
        lambda s: subject(
            rollback_posture=RollbackPosture(
                reversible=False,
                summary=s.rollback_posture.summary,
                procedure=s.rollback_posture.procedure,
                limitations=s.rollback_posture.limitations,
            )
        ),
    ),
    (
        "rollback summary",
        lambda s: subject(
            rollback_posture=RollbackPosture(
                reversible=True,
                summary="different rollback",
                procedure=s.rollback_posture.procedure,
                limitations=s.rollback_posture.limitations,
            )
        ),
    ),
    (
        "rollback procedure",
        lambda s: subject(
            rollback_posture=RollbackPosture(
                reversible=True,
                summary=s.rollback_posture.summary,
                procedure=(
                    ProcedureStep(
                        step_id="rb-x", description="different", expected_effect="different"
                    ),
                ),
                limitations=s.rollback_posture.limitations,
            )
        ),
    ),
    (
        "rollback limitations",
        lambda s: subject(
            rollback_posture=RollbackPosture(
                reversible=True,
                summary=s.rollback_posture.summary,
                procedure=s.rollback_posture.procedure,
                limitations=("different limitation",),
            )
        ),
    ),
    ("audit", lambda s: subject(audit_requirements=("different audit",))),
    ("unsupported", lambda s: subject(unsupported_or_irreversible_aspects=("different aspect",))),
]


@pytest.mark.parametrize(("label", "mutate"), MUTATIONS)
def test_every_approval_bound_field_mutation_changes_hash_and_invalidates_attestation(
    label, mutate
):
    base = subject()
    c = contract(base)
    mutated = mutate(base)
    assert compute_subject_sha256(mutated) != compute_subject_sha256(base), label
    mismatched = ApprovedChangeContract(subject=mutated, approval=c.approval)
    res = verify_approval_binding(mismatched)
    assert res.status == "approval_mismatch"
    assert res.computed_subject_sha256 != c.approval.subject_sha256


def test_attestation_validation_and_limits():
    c = contract(sha="0" * 64)
    assert verify_approval_binding(c).status == "approval_mismatch"
    for field, value in [
        ("subject_sha256", "ABC"),
        ("approved_at", datetime(2026, 1, 1)),
        ("approved_by", ""),
        ("reason", ""),
        ("scope", "all"),
    ]:
        data = contract().approval.model_dump()
        data[field] = value
        with pytest.raises(ValidationError):
            ApprovalAttestation(**data)
    assert "authenticated identity" in verify_approval_binding(contract()).warnings[0]


def test_capability_validation_requires_explicit_exact_safe_set():
    c = contract()
    assert validate_approved_change_contract(c, {CAP}).status == "contract_valid"
    assert (
        validate_approved_change_contract(c, {"test.synthetic"}).status == "unsupported_capability"
    )
    assert validate_approved_change_contract(c, set()).status == "unsupported_capability"
    assert validate_approved_change_contract(c, {"*"}).status == "invalid_validation_input"
    assert validate_approved_change_contract(c, None).status == "invalid_validation_input"
    with pytest.raises(ValidationError):
        subject(capability_id="*")


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("ALL", "exact"),
        ("All", "exact"),
        ("aNy", "exact"),
        ("exact", "ANY"),
        ("exact", "Any"),
        ("exact", "aLl"),
        ("  Any  ", "exact"),
        ("exact", "  aLl  "),
    ],
)
def test_case_variant_wildcard_identity_claims_are_rejected(key, value):
    with pytest.raises(ValidationError):
        TargetIdentityClaim(key=key, value=value)


@pytest.mark.parametrize("field", ["kind", "name"])
def test_case_variant_wildcard_target_kind_and_name_are_rejected(field):
    kwargs = {
        "kind": "container",
        "name": "demo",
        "identity_claims": (TargetIdentityClaim(key="Exact", value="Value"),),
    }
    kwargs[field] = "  Any  "
    with pytest.raises(ValidationError):
        ApprovedChangeTarget(**kwargs)


def test_case_variant_wildcard_capability_and_supported_inputs_are_rejected_but_casing_retained():
    claim = TargetIdentityClaim(key="ExactKey", value="ExactValue")
    assert claim.key == "ExactKey"
    assert claim.value == "ExactValue"
    with pytest.raises(ValidationError):
        subject(capability_id="ALL")
    assert (
        validate_approved_change_contract(contract(), {"ANY"}).status == "invalid_validation_input"
    )
    assert (
        validate_approved_change_contract(contract(), {"  aLl  "}).status
        == "invalid_validation_input"
    )


@pytest.mark.parametrize(
    "make_kwargs",
    [
        lambda: {
            "target": ApprovedChangeTarget(
                kind="container",
                name="demo",
                identity_claims=(
                    TargetIdentityClaim(key="k", value="v"),
                    TargetIdentityClaim(key="k", value="v2"),
                ),
            )
        },
        lambda: {"target": ApprovedChangeTarget(kind="container", name="demo", identity_claims=())},
        lambda: {"evidence_references": ()},
        lambda: {
            "evidence_references": (
                EvidenceReference(
                    reference_id="ev",
                    source="s",
                    sha256=SHA_A,
                    observed_at=datetime.now(timezone.utc),
                ),
                EvidenceReference(
                    reference_id="ev",
                    source="s2",
                    sha256=SHA_B,
                    observed_at=datetime.now(timezone.utc),
                ),
            )
        },
        lambda: {"procedure": ()},
        lambda: {
            "procedure": (
                ProcedureStep(step_id="dup", description="a", expected_effect="b"),
                ProcedureStep(step_id="dup", description="c", expected_effect="d"),
            )
        },
        lambda: {"preconditions": ()},
        lambda: {"revalidation_requirements": ()},
        lambda: {"verification_criteria": ()},
        lambda: {"rollback_posture": None},
        lambda: {"audit_requirements": ()},
        lambda: {"risk": "critical"},
        lambda: {"desired_outcome": ""},
    ],
)
def test_structural_validation_rejects_malformed_contract_parts(make_kwargs):
    with pytest.raises((ValidationError, ValueError)):
        subject(**make_kwargs())
    with pytest.raises(ValidationError):
        EvidenceReference(
            reference_id="ev", source="s", sha256="ABC", observed_at=datetime.now(timezone.utc)
        )
    with pytest.raises(ValidationError):
        EvidenceReference(
            reference_id="ev", source="s", sha256=SHA_A, observed_at=datetime(2026, 1, 1)
        )


@pytest.mark.parametrize(
    "extra",
    [
        "command",
        "argv",
        "script",
        "shell",
        "powershell",
        "subprocess",
        "working_directory",
        "parameters",
    ],
)
def test_execution_shaped_extras_are_forbidden(extra):
    with pytest.raises(ValidationError):
        ProcedureStep(step_id="x", description="y", expected_effect="z", **{extra: "no"})
    payload = subject().model_dump(mode="python")
    payload[extra] = "no"
    with pytest.raises(ValidationError):
        ApprovedChangeSubject.model_validate(payload)


def test_deep_immutability():
    c = contract()
    with pytest.raises(ValidationError):
        c.subject = subject()
    with pytest.raises(ValidationError):
        c.subject.target.name = "other"
    with pytest.raises(TypeError):
        c.subject.procedure[0] = ProcedureStep(step_id="x", description="y", expected_effect="z")
    with pytest.raises(AttributeError):
        c.subject.procedure.append(ProcedureStep(step_id="x", description="y", expected_effect="z"))
    with pytest.raises(ValidationError):
        c.approval.reason = "changed"
    result = validate_approved_change_contract(c, {CAP})
    with pytest.raises(ValidationError):
        result.execution_allowed = True


def test_import_purity_runtime_and_static(tmp_path, monkeypatch):
    calls = []
    monkeypatch.chdir(tmp_path)
    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append("subprocess.run"))
    monkeypatch.setattr(os, "system", lambda *a, **k: calls.append("os.system"))
    monkeypatch.setattr(socket, "socket", lambda *a, **k: calls.append("socket"))
    sys.modules.pop("shellforgeai.core.approved_change_contract", None)
    importlib.import_module("shellforgeai.core.approved_change_contract")
    after = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    assert before == after
    assert calls == []
    tree = ast.parse(
        (
            Path(__file__).parents[1] / "src/shellforgeai/core/approved_change_contract.py"
        ).read_text()
    )
    banned = {"subprocess", "socket", "docker", "compose"}
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not banned & imports
