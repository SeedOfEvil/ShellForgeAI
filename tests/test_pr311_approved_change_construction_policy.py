from __future__ import annotations

import copy
import inspect
import os
import socket
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from shellforgeai.core import approved_change_construction_policy as policy_module
from shellforgeai.core.approvals import Proposal
from shellforgeai.core.approved_change_construction_policy import (
    APPROVED_CHANGE_CONSTRUCTION_POLICY,
    DESTINATION_REVIEW_CONTEXT_ALLOWLIST,
    DIRECT_CANDIDATE_ALLOWLIST,
    EXPLICIT_CONTEXT_ONLY_FIELDS,
    REVIEW_CONTEXT_ALLOWLIST,
    validate_approved_change_construction_policy,
)
from shellforgeai.core.approved_change_contract import (
    ApprovalAttestation,
    ApprovedChangeContract,
    ApprovedChangeSubject,
)

EXPECTED_CANDIDATES = {
    "source_proposal_reference": "proposal_id",
    "risk": "risk",
    "impact": "impact",
    "preconditions": "preconditions",
    "verification_criteria": "verification",
}


def as_data():
    return APPROVED_CHANGE_CONSTRUCTION_POLICY.model_dump(mode="json")


def validation(data=None):
    return validate_approved_change_construction_policy(data or APPROVED_CHANGE_CONSTRUCTION_POLICY)


def test_exact_schema_coverage_and_deterministic_ordering():
    destinations = [r.destination_field for r in APPROVED_CHANGE_CONSTRUCTION_POLICY.rules]
    assert set(destinations) == set(ApprovedChangeSubject.model_fields)
    assert len(destinations) == len(set(destinations)) == 18
    assert destinations == sorted(destinations)
    result = validation()
    assert result.policy_valid is True
    assert result.coverage_complete is True
    assert result.expected_destination_fields == tuple(sorted(ApprovedChangeSubject.model_fields))
    assert result.covered_destination_fields == result.expected_destination_fields


@pytest.mark.parametrize(
    "mutator, expected",
    [
        (lambda d: d["rules"].pop(), "missing destination field"),
        (lambda d: d["rules"].append(copy.deepcopy(d["rules"][0])), "duplicate destination field"),
        (
            lambda d: d["rules"].append(
                {**copy.deepcopy(d["rules"][0]), "destination_field": "future_field"}
            ),
            "unknown destination field",
        ),
        (
            lambda d: d["rules"].__setitem__(0, {**d["rules"][0], "destination_field": "*"}),
            "invalid destination field",
        ),
        (
            lambda d: d["rules"].__setitem__(0, {**d["rules"][0], "destination_field": ""}),
            "invalid destination field",
        ),
    ],
)
def test_schema_coverage_fails_closed(mutator, expected):
    data = as_data()
    mutator(data)
    result = validation(data)
    assert result.policy_valid is False
    assert any(expected in error for error in result.errors)


def test_exact_candidate_allowlist():
    actual = {
        r.destination_field: r.legacy_candidate_fields[0]
        for r in APPROVED_CHANGE_CONSTRUCTION_POLICY.rules
        if r.source_classification == "legacy_candidate_requires_explicit_review"
    }
    assert actual == EXPECTED_CANDIDATES
    assert set(DIRECT_CANDIDATE_ALLOWLIST) == {
        (dest, src) for dest, src in EXPECTED_CANDIDATES.items()
    }


@pytest.mark.parametrize(
    "dest, src",
    [
        ("desired_outcome", "title"),
        ("risk", "impact"),
        ("impact", "unknown_legacy"),
        ("capability_id", "kind"),
        ("target", "target"),
        ("target", "component"),
        ("procedure", "proposed_steps"),
        ("rollback_posture", "rollback"),
        ("evidence_references", "evidence"),
        ("evidence_references", "source_hashes"),
        ("risk", "approval"),
        ("risk", "fingerprint"),
    ],
)
def test_rejects_extra_unknown_and_prohibited_direct_candidates(dest, src):
    data = as_data()
    for rule in data["rules"]:
        if rule["destination_field"] == dest:
            rule["source_classification"] = "legacy_candidate_requires_explicit_review"
            rule["legacy_candidate_fields"] = [src]
            rule["explicit_review_required"] = True
            break
    result = validation(data)
    assert result.policy_valid is False
    assert result.errors


def test_rejects_multiple_candidate_fields_for_one_destination():
    data = as_data()
    for rule in data["rules"]:
        if rule["destination_field"] == "risk":
            rule["legacy_candidate_fields"] = ["risk", "impact"]
    result = validation(data)
    assert any("multiple direct candidates" in error for error in result.errors)


def test_explicit_context_only_enforcement():
    rules = {r.destination_field: r for r in APPROVED_CHANGE_CONSTRUCTION_POLICY.rules}
    assert set(EXPLICIT_CONTEXT_ONLY_FIELDS) == {
        "capability_id",
        "target",
        "desired_outcome",
        "diagnosis_summary",
        "evidence_references",
        "change_summary",
        "blast_radius",
        "procedure",
        "revalidation_requirements",
        "rollback_posture",
        "audit_requirements",
        "unsupported_or_irreversible_aspects",
    }
    for field in EXPLICIT_CONTEXT_ONLY_FIELDS:
        rule = rules[field]
        assert rule.source_classification == "explicit_context_only"
        assert rule.legacy_candidate_fields == ()
        assert rule.explicit_review_required is True
        assert not rule.auto_copy_allowed
        assert not rule.inference_allowed
        assert not rule.default_allowed
        assert not rule.approval_portable
        assert not rule.fingerprint_reusable


def test_contract_constant_enforcement():
    constants = [
        r
        for r in APPROVED_CHANGE_CONSTRUCTION_POLICY.rules
        if r.source_classification == "contract_constant"
    ]
    assert [r.destination_field for r in constants] == ["schema_version"]
    assert constants[0].legacy_candidate_fields == ()
    for bad_class in ["explicit_context_only", "legacy_candidate_requires_explicit_review"]:
        data = as_data()
        for rule in data["rules"]:
            if rule["destination_field"] == "schema_version":
                rule["source_classification"] = bad_class
                rule["explicit_review_required"] = True
                if bad_class == "legacy_candidate_requires_explicit_review":
                    rule["legacy_candidate_fields"] = ["proposal_id"]
        assert validation(data).policy_valid is False


def test_review_context_only_allowlist_and_destination_mapping():
    assert tuple(sorted(REVIEW_CONTEXT_ALLOWLIST)) == REVIEW_CONTEXT_ALLOWLIST
    assert dict(DESTINATION_REVIEW_CONTEXT_ALLOWLIST) == {
        "change_summary": ("notes", "title"),
        "desired_outcome": ("notes", "title"),
        "diagnosis_summary": ("notes", "source.evidence", "source.summary", "title"),
        "evidence_references": (
            "source.evidence",
            "source.runbook",
            "source.summary",
            "source_hashes",
        ),
        "rollback_posture": ("rollback",),
    }
    data = as_data()
    for rule in data["rules"]:
        if rule["destination_field"] == "desired_outcome":
            rule["legacy_review_context_fields"].append("source.runbook")
    assert validation(data).policy_valid is False


@pytest.mark.parametrize(
    "flag",
    [
        "auto_copy_allowed",
        "inference_allowed",
        "default_allowed",
        "approval_portable",
        "fingerprint_reusable",
    ],
)
def test_permanent_false_behavior_flags(flag):
    data = as_data()
    data["rules"][0][flag] = True
    result = validation(data)
    assert result.policy_valid is False
    assert result.read_only is True
    assert result.mutation_performed is False
    assert result.subject_created is False
    assert result.contract_created is False
    assert result.approval_created is False
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"


def test_validation_result_safety_for_valid_and_invalid():
    for result in (validation(), validation({"rules": []})):
        assert result.read_only is True
        assert result.mutation_performed is False
        assert result.subject_created is False
        assert result.contract_created is False
        assert result.approval_created is False
        assert result.execution_allowed is False
        assert result.execution_available is False
        assert result.execution_status == "not_executed"


def test_determinism_and_alternate_order_rejected_not_repaired():
    assert (
        APPROVED_CHANGE_CONSTRUCTION_POLICY.model_dump_json()
        == APPROVED_CHANGE_CONSTRUCTION_POLICY.model_dump_json()
    )
    assert validation().model_dump_json() == validation().model_dump_json()
    data = as_data()
    data["rules"] = list(reversed(data["rules"]))
    result = validation(data)
    assert result.policy_valid is False
    assert any("sorted deterministically" in error for error in result.errors)
    assert "timestamp" not in APPROVED_CHANGE_CONSTRUCTION_POLICY.model_dump_json().lower()


def test_immutability():
    with pytest.raises(ValidationError):
        APPROVED_CHANGE_CONSTRUCTION_POLICY.policy_name = "changed"
    with pytest.raises(ValidationError):
        APPROVED_CHANGE_CONSTRUCTION_POLICY.rules[0].notes = "changed"
    with pytest.raises(AttributeError):
        APPROVED_CHANGE_CONSTRUCTION_POLICY.rules.append(
            APPROVED_CHANGE_CONSTRUCTION_POLICY.rules[0]
        )
    with pytest.raises(ValidationError):
        validation().status = "policy_invalid"


def test_no_side_effect_runtime_guards(monkeypatch, tmp_path):
    def boom(*args, **kwargs):
        raise AssertionError("side effect attempted")

    monkeypatch.setattr(Path, "read_text", boom)
    monkeypatch.setattr(Path, "write_text", boom)
    monkeypatch.setattr(Path, "open", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(os, "system", boom)
    monkeypatch.setattr(socket, "socket", boom)
    before = dict(os.environ)
    assert validation().policy_valid is True
    assert dict(os.environ) == before


def test_static_no_side_effect_and_no_construction_api():
    source = Path(policy_module.__file__).read_text()
    forbidden = [
        "subprocess",
        "os.system",
        "socket",
        "docker",
        "compose",
        "open(",
        "write_text",
        "read_text",
        "ApprovedChangeSubject(",
        "ApprovalAttestation(",
        "ApprovedChangeContract(",
        "hash_approved_change_subject",
    ]
    for token in forbidden:
        assert token not in source
    for _, obj in inspect.getmembers(policy_module, inspect.isfunction):
        sig = inspect.signature(obj)
        assert all(param.annotation is not Proposal for param in sig.parameters.values())
        assert sig.return_annotation not in {
            ApprovedChangeSubject,
            ApprovalAttestation,
            ApprovedChangeContract,
        }
    assert not hasattr(policy_module, "extract_candidate_values")
    assert not hasattr(policy_module, "create_supplemental_context")
