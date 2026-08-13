"""Classify exact PR353 approval-assertion chronology under a fixed age policy.

This authority is pure and read-only.  It consumes chronology already evaluated
by PR353 and does not read a clock, an artifact, or any other external state.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from shellforgeai.core.approved_change_approval_assertion_age import (
    ApprovedChangeApprovalAssertionAgeEvaluation,
    compute_approval_assertion_age_evaluation_sha256,
)

MAX_APPROVAL_ASSERTION_AGE_MICROSECONDS = 86_400_000_000
POLICY_TYPE = "approved_change_approval_assertion_recency"
COMPARISON_BASIS = "pr353_exact_age_microseconds"
BOUNDARY_RULE = "less_than_or_equal_is_within_window"
APPROVAL_TIME_TRUST = "self_asserted_untrusted_assertion"
REFERENCE_CLOCK_TRUST = "untrusted_local_system_clock"
POLICY_SCOPE = "recency_classification_only"
COMPARISON_SCOPE = "exact_pr353_approval_assertion_chronology_only"

WARNINGS = (
    "this is recency classification of a self-asserted approval timestamp",
    "approved_at remains untrusted assertion metadata",
    "evaluator UTC captured by PR353 remains an untrusted local clock",
    "this classifies assertion recency, not verified real-world approval time",
    "within the age window is not authenticated approval or approval validity",
    "outside the age window is not revocation, expiration, or deletion",
    "no trusted-time authority was consulted",
    "this does not authenticate the approver",
    "this does not evaluate credentials, MFA, roles, groups, privileges, elevation, or RBAC",
    "this does not consume PR352 identity provenance",
    "this does not evaluate PR304 freshness or current state",
    "this is not authorization or execution preflight",
    "this creates or links no receipt and grants no execution eligibility",
    "PR313 execution is not invoked",
    "natural language cannot convert this result into execution",
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ApprovedChangeApprovalAssertionRecencyPolicy(_Frozen):
    """The single source-maintained approval-assertion recency policy."""

    schema_version: Literal[1] = 1
    policy_type: Literal["approved_change_approval_assertion_recency"] = POLICY_TYPE
    max_approval_assertion_age_microseconds: Literal[86400000000] = (
        MAX_APPROVAL_ASSERTION_AGE_MICROSECONDS
    )
    comparison_basis: Literal["pr353_exact_age_microseconds"] = COMPARISON_BASIS
    boundary_rule: Literal["less_than_or_equal_is_within_window"] = BOUNDARY_RULE
    approval_time_trust: Literal["self_asserted_untrusted_assertion"] = APPROVAL_TIME_TRUST
    reference_clock_trust: Literal["untrusted_local_system_clock"] = REFERENCE_CLOCK_TRUST
    policy_scope: Literal["recency_classification_only"] = POLICY_SCOPE


class ApprovedChangeApprovalAssertionRecencyEvaluation(_Frozen):
    """Canonical, non-circular facts from one completed policy evaluation."""

    schema_version: Literal[1] = 1
    evaluation_type: Literal["approved_change_approval_assertion_recency_evaluation"] = (
        "approved_change_approval_assertion_recency_evaluation"
    )
    approval_artifact_id: str
    approval_artifact_identity_sha256: str
    subject_sha256: str
    approval_assertion_age_evaluation_sha256: str
    approval_asserted_at_utc: str
    evaluator_reference_utc: str
    age_microseconds: int
    policy_identity_sha256: str
    max_approval_assertion_age_microseconds: Literal[86400000000] = (
        MAX_APPROVAL_ASSERTION_AGE_MICROSECONDS
    )
    comparison_basis: Literal["pr353_exact_age_microseconds"] = COMPARISON_BASIS
    boundary_rule: Literal["less_than_or_equal_is_within_window"] = BOUNDARY_RULE
    approval_time_trust: Literal["self_asserted_untrusted_assertion"] = APPROVAL_TIME_TRUST
    evaluator_clock_trust: Literal["untrusted_local_system_clock"] = REFERENCE_CLOCK_TRUST
    recency_status: Literal[
        "approval_assertion_within_age_window", "approval_assertion_outside_age_window"
    ]
    comparison_scope: Literal["exact_pr353_approval_assertion_chronology_only"] = COMPARISON_SCOPE


Status = Literal[
    "approval_assertion_within_age_window",
    "approval_assertion_outside_age_window",
    "approval_assertion_recency_unavailable",
    "approval_assertion_age_evaluation_confirmation_mismatch",
    "approval_assertion_recency_policy_confirmation_mismatch",
    "invalid_approval_assertion_recency_input",
    "approval_assertion_recency_evaluation_failed",
]


class ApprovedChangeApprovalAssertionRecencyResult(_Frozen):
    """Detailed fail-closed result and permanent non-authority ledger."""

    schema_version: Literal[1] = 1
    operation_type: Literal["evaluate_approval_assertion_recency"] = (
        "evaluate_approval_assertion_recency"
    )
    status: Status
    reason: str
    approval_assertion_age_evaluation_sha256: str = ""
    confirmed_approval_assertion_age_evaluation_sha256: str = ""
    recency_policy_identity_sha256: str = ""
    confirmed_recency_policy_identity_sha256: str = ""
    approval_assertion_age_evaluation_validated: bool = False
    approval_assertion_age_evaluation_identity_confirmed: bool = False
    recency_policy_evaluated: bool = False
    recency_policy_identity_confirmed: bool = False
    recency_evaluated: bool = False
    approval_assertion_within_age_window: bool = False
    approval_assertion_outside_age_window: bool = False
    recency_evaluation_identity_sha256: str = ""
    evaluation: ApprovedChangeApprovalAssertionRecencyEvaluation | None = None
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = WARNINGS
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    clock_read_performed: Literal[False] = False
    filesystem_accessed: Literal[False] = False
    approval_time_authenticated: Literal[False] = False
    trusted_approval_time_evaluated: Literal[False] = False
    verified_human_identity: Literal[False] = False
    authenticated_identity_evaluated: Literal[False] = False
    approved_by_comparison_evaluated: Literal[False] = False
    mfa_evaluated: Literal[False] = False
    credential_validity_evaluated: Literal[False] = False
    credential_read: Literal[False] = False
    secret_read: Literal[False] = False
    auth_cache_read: Literal[False] = False
    group_membership_evaluated: Literal[False] = False
    role_membership_evaluated: Literal[False] = False
    privileges_evaluated: Literal[False] = False
    elevation_evaluated: Literal[False] = False
    integrity_level_evaluated: Literal[False] = False
    rbac_evaluated: Literal[False] = False
    approval_assertion_recency_evaluated: bool = False
    approval_freshness_evaluated: Literal[False] = False
    approval_expiration_evaluated: Literal[False] = False
    approval_revocation_evaluated: Literal[False] = False
    windows_identity_binding_evaluated: Literal[False] = False
    pr304_evidence_freshness_evaluated: Literal[False] = False
    current_state_revalidation_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    persistence_performed: Literal[False] = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    recency_evaluation_persisted: Literal[False] = False
    powershell_executed: Literal[False] = False
    winrm_used: Literal[False] = False
    qga_used: Literal[False] = False
    remote_execution: Literal[False] = False
    subprocess_executed: Literal[False] = False
    shell_executed: Literal[False] = False
    network_call: Literal[False] = False
    model_called: Literal[False] = False
    service_control_executed: Literal[False] = False
    process_termination_executed: Literal[False] = False
    registry_modified: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    natural_language_execution: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = "not_executed"


def maintained_approval_assertion_recency_policy() -> ApprovedChangeApprovalAssertionRecencyPolicy:
    return ApprovedChangeApprovalAssertionRecencyPolicy()


def _canonical(value: BaseModel) -> str:
    return json.dumps(
        value.model_dump(mode="python"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def canonical_approval_assertion_recency_policy_json(
    value: ApprovedChangeApprovalAssertionRecencyPolicy | Mapping[str, Any],
) -> str:
    model = (
        value
        if isinstance(value, ApprovedChangeApprovalAssertionRecencyPolicy)
        else ApprovedChangeApprovalAssertionRecencyPolicy.model_validate(value)
    )
    return _canonical(model)


def compute_approval_assertion_recency_policy_sha256(
    value: ApprovedChangeApprovalAssertionRecencyPolicy | Mapping[str, Any],
) -> str:
    return hashlib.sha256(
        canonical_approval_assertion_recency_policy_json(value).encode("utf-8")
    ).hexdigest()


def canonical_approval_assertion_recency_evaluation_json(
    value: ApprovedChangeApprovalAssertionRecencyEvaluation | Mapping[str, Any],
) -> str:
    model = (
        value
        if isinstance(value, ApprovedChangeApprovalAssertionRecencyEvaluation)
        else ApprovedChangeApprovalAssertionRecencyEvaluation.model_validate(value)
    )
    return _canonical(model)


def compute_approval_assertion_recency_evaluation_sha256(
    value: ApprovedChangeApprovalAssertionRecencyEvaluation | Mapping[str, Any],
) -> str:
    return hashlib.sha256(
        canonical_approval_assertion_recency_evaluation_json(value).encode("utf-8")
    ).hexdigest()


def _result(status: Status, reason: str, *, errors=(), **values: Any):
    return ApprovedChangeApprovalAssertionRecencyResult(
        status=status, reason=reason, errors=tuple(sorted(set(errors))), **values
    )


def evaluate_approval_assertion_recency(
    approval_assertion_age_evaluation: ApprovedChangeApprovalAssertionAgeEvaluation
    | Mapping[str, Any],
    *,
    confirm_approval_assertion_age_evaluation_sha256: str,
    confirm_approval_assertion_recency_policy_sha256: str,
) -> ApprovedChangeApprovalAssertionRecencyResult:
    """Classify one confirmed PR353 evaluation against the maintained policy."""
    base = {
        "confirmed_approval_assertion_age_evaluation_sha256": (
            confirm_approval_assertion_age_evaluation_sha256
            if isinstance(confirm_approval_assertion_age_evaluation_sha256, str)
            else ""
        ),
        "confirmed_recency_policy_identity_sha256": (
            confirm_approval_assertion_recency_policy_sha256
            if isinstance(confirm_approval_assertion_recency_policy_sha256, str)
            else ""
        ),
    }
    errors = []
    if not isinstance(
        approval_assertion_age_evaluation,
        (ApprovedChangeApprovalAssertionAgeEvaluation, Mapping),
    ):
        errors.append("PR353 evaluation must be a maintained model or mapping")
    if not isinstance(
        confirm_approval_assertion_age_evaluation_sha256, str
    ) or not _SHA256.fullmatch(confirm_approval_assertion_age_evaluation_sha256):
        errors.append("PR353 evaluation confirmation must be 64 lowercase hexadecimal characters")
    if not isinstance(
        confirm_approval_assertion_recency_policy_sha256, str
    ) or not _SHA256.fullmatch(confirm_approval_assertion_recency_policy_sha256):
        errors.append("recency-policy confirmation must be 64 lowercase hexadecimal characters")
    if errors:
        return _result(
            "invalid_approval_assertion_recency_input",
            "one or more pure input formats are invalid",
            errors=errors,
            **base,
        )

    try:
        model = (
            approval_assertion_age_evaluation
            if isinstance(
                approval_assertion_age_evaluation,
                ApprovedChangeApprovalAssertionAgeEvaluation,
            )
            else ApprovedChangeApprovalAssertionAgeEvaluation.model_validate(
                approval_assertion_age_evaluation
            )
        )
        age_identity = compute_approval_assertion_age_evaluation_sha256(model)
    except (ValidationError, TypeError, ValueError) as exc:
        return _result(
            "invalid_approval_assertion_recency_input",
            "the PR353 evaluation failed maintained validation",
            errors=[str(exc)],
            **base,
        )
    base.update(
        approval_assertion_age_evaluation_validated=True,
        approval_assertion_age_evaluation_sha256=age_identity,
    )
    if not hmac.compare_digest(age_identity, confirm_approval_assertion_age_evaluation_sha256):
        return _result(
            "approval_assertion_age_evaluation_confirmation_mismatch",
            "exact PR353 evaluation identity confirmation mismatch",
            **base,
        )
    base["approval_assertion_age_evaluation_identity_confirmed"] = True

    policy = maintained_approval_assertion_recency_policy()
    policy_identity = compute_approval_assertion_recency_policy_sha256(policy)
    base.update(
        recency_policy_evaluated=True,
        recency_policy_identity_sha256=policy_identity,
    )
    if not hmac.compare_digest(policy_identity, confirm_approval_assertion_recency_policy_sha256):
        return _result(
            "approval_assertion_recency_policy_confirmation_mismatch",
            "exact maintained recency-policy identity confirmation mismatch",
            **base,
        )
    base["recency_policy_identity_confirmed"] = True

    if model.chronology_outcome == "approval_assertion_clock_inconsistent":
        return _result(
            "approval_assertion_recency_unavailable",
            "PR353 chronology is clock-inconsistent and cannot receive a recency classification",
            **base,
        )
    if (
        model.chronology_outcome != "approval_assertion_age_evaluated"
        or not model.clock_consistent
        or model.age_microseconds is None
        or model.age_microseconds < 0
    ):
        return _result(
            "approval_assertion_recency_evaluation_failed",
            "PR353 chronology is not eligible for recency classification",
            **base,
        )

    within = model.age_microseconds <= MAX_APPROVAL_ASSERTION_AGE_MICROSECONDS
    status: Status = (
        "approval_assertion_within_age_window"
        if within
        else "approval_assertion_outside_age_window"
    )
    evaluation = ApprovedChangeApprovalAssertionRecencyEvaluation(
        approval_artifact_id=model.approval_artifact_id,
        approval_artifact_identity_sha256=model.approval_artifact_identity_sha256,
        subject_sha256=model.subject_sha256,
        approval_assertion_age_evaluation_sha256=age_identity,
        approval_asserted_at_utc=model.approval_asserted_at_utc,
        evaluator_reference_utc=model.evaluator_reference_utc,
        age_microseconds=model.age_microseconds,
        policy_identity_sha256=policy_identity,
        recency_status=status,
    )
    return _result(
        status,
        "the exact PR353 approval assertion chronology falls within the maintained "
        "24-hour age window"
        if within
        else "the exact PR353 approval assertion chronology falls outside the maintained "
        "24-hour age window",
        recency_evaluated=True,
        approval_assertion_recency_evaluated=True,
        approval_assertion_within_age_window=within,
        approval_assertion_outside_age_window=not within,
        evaluation=evaluation,
        recency_evaluation_identity_sha256=(
            compute_approval_assertion_recency_evaluation_sha256(evaluation)
        ),
        **base,
    )
