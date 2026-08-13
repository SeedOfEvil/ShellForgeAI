"""Focused tests for the fixed approval-assertion recency policy."""

from __future__ import annotations

import inspect
import json

import pytest
from pydantic import ValidationError

from shellforgeai.core import approved_change_approval_assertion_age as age
from shellforgeai.core import approved_change_approval_assertion_recency as recency


def age_evaluation(
    age_microseconds: int | None = 0,
    *,
    age_milliseconds_ceiling: int | None = None,
    consistent: bool = True,
):
    if age_milliseconds_ceiling is None and age_microseconds is not None:
        age_milliseconds_ceiling = (age_microseconds + 999) // 1000
    outcome = (
        "approval_assertion_age_evaluated"
        if consistent
        else "approval_assertion_clock_inconsistent"
    )
    return age.ApprovedChangeApprovalAssertionAgeEvaluation(
        approval_artifact_id="aca_" + "a" * 64,
        approval_artifact_identity_sha256="a" * 64,
        subject_sha256="b" * 64,
        approval_asserted_at_utc="2026-08-12T12:00:00.000000Z",
        evaluator_reference_utc="2026-08-13T12:00:00.000000Z",
        clock_consistent=consistent,
        age_microseconds=age_microseconds,
        age_milliseconds_ceiling=age_milliseconds_ceiling,
        chronology_outcome=outcome,
    )


def evaluate(model):
    age_identity = age.compute_approval_assertion_age_evaluation_sha256(model)
    policy_identity = recency.compute_approval_assertion_recency_policy_sha256(
        recency.maintained_approval_assertion_recency_policy()
    )
    return recency.evaluate_approval_assertion_recency(
        model,
        confirm_approval_assertion_age_evaluation_sha256=age_identity,
        confirm_approval_assertion_recency_policy_sha256=policy_identity,
    )


def test_policy_is_fixed_frozen_extra_forbidden_and_deterministic():
    policy = recency.maintained_approval_assertion_recency_policy()
    assert policy.max_approval_assertion_age_microseconds == 86_400_000_000
    assert policy.comparison_basis == "pr353_exact_age_microseconds"
    assert policy.boundary_rule == "less_than_or_equal_is_within_window"
    first = recency.compute_approval_assertion_recency_policy_sha256(policy)
    second = recency.compute_approval_assertion_recency_policy_sha256(policy)
    assert first == second and len(first) == 64 and first == first.lower()
    with pytest.raises(ValidationError):
        recency.ApprovedChangeApprovalAssertionRecencyPolicy(
            max_approval_assertion_age_microseconds=1
        )
    with pytest.raises(ValidationError):
        recency.ApprovedChangeApprovalAssertionRecencyPolicy.model_validate(
            {**policy.model_dump(), "extra": True}
        )
    with pytest.raises(ValidationError):
        policy.policy_scope = "changed"


@pytest.mark.parametrize("field", ["age", "policy"])
def test_malformed_confirmations_stop_before_upstream_sha_or_policy(monkeypatch, field):
    model = age_evaluation()
    monkeypatch.setattr(
        recency,
        "compute_approval_assertion_age_evaluation_sha256",
        lambda *_: pytest.fail("upstream SHA authority called"),
    )
    monkeypatch.setattr(
        recency,
        "maintained_approval_assertion_recency_policy",
        lambda: pytest.fail("policy constructed"),
    )
    result = recency.evaluate_approval_assertion_recency(
        model,
        confirm_approval_assertion_age_evaluation_sha256=("bad" if field == "age" else "a" * 64),
        confirm_approval_assertion_recency_policy_sha256=("bad" if field == "policy" else "b" * 64),
    )
    assert result.status == "invalid_approval_assertion_recency_input"
    assert not result.recency_policy_evaluated and not result.recency_evaluated


def test_invalid_evaluation_stops_before_policy(monkeypatch):
    monkeypatch.setattr(
        recency,
        "maintained_approval_assertion_recency_policy",
        lambda: pytest.fail("policy constructed"),
    )
    result = recency.evaluate_approval_assertion_recency(
        {"not": "PR353"},
        confirm_approval_assertion_age_evaluation_sha256="a" * 64,
        confirm_approval_assertion_recency_policy_sha256="b" * 64,
    )
    assert result.status == "invalid_approval_assertion_recency_input"
    assert not result.recency_policy_evaluated


def test_confirmations_are_ordered_and_constant_time(monkeypatch):
    calls = []
    monkeypatch.setattr(
        recency.hmac,
        "compare_digest",
        lambda left, right: calls.append((left, right)) or left == right,
    )
    model = age_evaluation()
    wrong = recency.evaluate_approval_assertion_recency(
        model,
        confirm_approval_assertion_age_evaluation_sha256="f" * 64,
        confirm_approval_assertion_recency_policy_sha256="e" * 64,
    )
    assert wrong.status == "approval_assertion_age_evaluation_confirmation_mismatch"
    assert len(calls) == 1 and not wrong.recency_policy_evaluated

    calls.clear()
    identity = age.compute_approval_assertion_age_evaluation_sha256(model)
    wrong_policy = recency.evaluate_approval_assertion_recency(
        model,
        confirm_approval_assertion_age_evaluation_sha256=identity,
        confirm_approval_assertion_recency_policy_sha256="e" * 64,
    )
    assert wrong_policy.status == "approval_assertion_recency_policy_confirmation_mismatch"
    assert len(calls) == 2 and not wrong_policy.recency_evaluated


@pytest.mark.parametrize(
    ("microseconds", "within"),
    [
        (0, True),
        (1, True),
        (86_399_999_999, True),
        (86_400_000_000, True),
        (86_400_000_001, False),
    ],
)
def test_exact_microsecond_boundary(microseconds, within):
    result = evaluate(age_evaluation(microseconds))
    assert result.recency_evaluated
    assert result.approval_assertion_within_age_window is within
    assert result.approval_assertion_outside_age_window is not within
    assert result.status == (
        "approval_assertion_within_age_window"
        if within
        else "approval_assertion_outside_age_window"
    )


def test_ceiling_milliseconds_do_not_control_boundary():
    # Both presentations say 86,400,001 ms; exact microseconds alone decide.
    within = evaluate(age_evaluation(86_400_000_000, age_milliseconds_ceiling=86_400_001))
    outside = evaluate(age_evaluation(86_400_000_001, age_milliseconds_ceiling=86_400_001))
    assert within.approval_assertion_within_age_window
    assert outside.approval_assertion_outside_age_window


def test_clock_inconsistent_chronology_is_unavailable_not_classified():
    result = evaluate(age_evaluation(None, age_milliseconds_ceiling=None, consistent=False))
    assert result.status == "approval_assertion_recency_unavailable"
    assert not result.recency_evaluated
    assert not result.approval_assertion_within_age_window
    assert not result.approval_assertion_outside_age_window


def test_recency_identity_is_deterministic_non_circular_and_fact_sensitive():
    first = evaluate(age_evaluation(10))
    same = evaluate(age_evaluation(10))
    changed_age = evaluate(age_evaluation(11))
    assert first.recency_evaluation_identity_sha256 == same.recency_evaluation_identity_sha256
    assert (
        first.recency_evaluation_identity_sha256 != changed_age.recency_evaluation_identity_sha256
    )
    canonical = recency.canonical_approval_assertion_recency_evaluation_json(first.evaluation)
    assert "recency_evaluation_identity_sha256" not in json.loads(canonical)

    changed_upstream = first.evaluation.model_copy(
        update={"approval_assertion_age_evaluation_sha256": "c" * 64}
    )
    changed_policy = first.evaluation.model_copy(update={"policy_identity_sha256": "d" * 64})
    digest = recency.compute_approval_assertion_recency_evaluation_sha256
    assert digest(first.evaluation) != digest(changed_upstream)
    assert digest(first.evaluation) != digest(changed_policy)


def test_trust_boundary_and_safety_ledger_remain_non_authoritative():
    result = evaluate(age_evaluation())
    assert result.evaluation.approval_time_trust == "self_asserted_untrusted_assertion"
    assert result.evaluation.evaluator_clock_trust == "untrusted_local_system_clock"
    assert result.read_only and result.approval_assertion_recency_evaluated
    assert not result.mutation_performed and not result.clock_read_performed
    assert not result.filesystem_accessed and not result.approval_time_authenticated
    assert not result.authenticated_identity_evaluated and not result.approval_freshness_evaluated
    assert not result.approval_expiration_evaluated and not result.approval_revocation_evaluated
    assert not result.windows_identity_binding_evaluated
    assert not result.pr304_evidence_freshness_evaluated
    assert not result.current_state_revalidation_evaluated
    assert not result.authorization_evaluated and not result.preflight_evaluated
    assert not result.receipt_created and not result.receipt_linked
    assert not result.persistence_performed and not result.recency_evaluation_persisted
    assert not result.subprocess_executed and not result.shell_executed
    assert not result.network_call and not result.model_called
    assert not result.execution_allowed and not result.execution_available
    assert result.execution_status == "not_executed"


def test_public_contract_and_import_boundary_are_pure():
    signature = inspect.signature(recency.evaluate_approval_assertion_recency)
    assert list(signature.parameters) == [
        "approval_assertion_age_evaluation",
        "confirm_approval_assertion_age_evaluation_sha256",
        "confirm_approval_assertion_recency_policy_sha256",
    ]
    forbidden_parameters = {
        "threshold",
        "max_age",
        "hours",
        "seconds",
        "microseconds",
        "ttl",
        "clock",
        "now",
        "data_dir",
        "approval_artifact_id",
    }
    assert forbidden_parameters.isdisjoint(signature.parameters)
    source = inspect.getsource(recency)
    for forbidden in (
        "datetime.now",
        "time.time",
        "pathlib",
        "load_persisted_approved_change_approval_artifact",
        "approved_change_windows_identity_binding",
        "approved_change_pr304_evidence_freshness",
        "socket",
        "requests",
    ):
        assert forbidden not in source
    assert "subprocess" not in recency.__dict__
