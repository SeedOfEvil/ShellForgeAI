"""Measure chronology for one exact persisted approval-time assertion.

This read-only authority deliberately measures age without deciding freshness,
validity, authorization, preflight readiness, or execution eligibility.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from shellforgeai.core.approved_change_approval_persistence import (
    load_persisted_approved_change_approval_artifact,
)

APPROVAL_TIME_SOURCE = "ApprovalAttestation.approved_at"
APPROVAL_TIME_TRUST = "self_asserted_untrusted_assertion"
EVALUATOR_CLOCK_SOURCE = "evaluator_local_system_utc"
EVALUATOR_CLOCK_TRUST = "untrusted_local_system_clock"
COMPARISON_SCOPE = "exact_persisted_approval_assertion_to_evaluator_local_utc_only"

WARNINGS = (
    "approved_at is self-asserted approval metadata, not a trusted timestamp",
    "the exact persisted artifact proves what timestamp was asserted, not when the "
    "real-world approval event occurred",
    "evaluator-local UTC is an untrusted local system clock",
    "age is chronology relative to that untrusted evaluator clock only",
    "clock consistency does not establish clock correctness",
    "this does not classify approval freshness or expiration",
    "this does not authenticate the approver",
    "this does not evaluate credentials, MFA, roles, privileges, or RBAC",
    "this does not evaluate authorization or current-state readiness",
    "this is not execution preflight and creates or links no receipt",
    "this grants no execution eligibility and PR313 execution is not invoked",
    "natural language cannot convert this temporal evidence into execution",
)

_ARTIFACT_ID = re.compile(r"^aca_[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ApprovedChangeApprovalAssertionAgeEvaluation(_Frozen):
    """Canonical, non-authoritative chronology facts hashed for identity."""

    schema_version: Literal[1] = 1
    evaluation_type: Literal["approved_change_approval_assertion_age_evaluation"] = (
        "approved_change_approval_assertion_age_evaluation"
    )
    approval_artifact_id: str
    approval_artifact_identity_sha256: str
    subject_sha256: str
    approval_asserted_at_utc: str
    approval_time_source: Literal["ApprovalAttestation.approved_at"] = APPROVAL_TIME_SOURCE
    approval_time_trust: Literal["self_asserted_untrusted_assertion"] = APPROVAL_TIME_TRUST
    evaluator_reference_utc: str
    evaluator_clock_source: Literal["evaluator_local_system_utc"] = EVALUATOR_CLOCK_SOURCE
    evaluator_clock_trust: Literal["untrusted_local_system_clock"] = EVALUATOR_CLOCK_TRUST
    clock_consistent: bool
    age_microseconds: int | None
    age_milliseconds_ceiling: int | None
    comparison_scope: Literal["exact_persisted_approval_assertion_to_evaluator_local_utc_only"] = (
        COMPARISON_SCOPE
    )
    chronology_outcome: Literal[
        "approval_assertion_age_evaluated", "approval_assertion_clock_inconsistent"
    ]


class ApprovedChangeApprovalAssertionAgeResult(_Frozen):
    """Detailed fail-closed result and permanent safety ledger."""

    schema_version: Literal[1] = 1
    operation_type: Literal["measure_exact_persisted_approval_assertion_age"] = (
        "measure_exact_persisted_approval_assertion_age"
    )
    status: Literal[
        "approval_assertion_age_evaluated",
        "approval_assertion_clock_inconsistent",
        "invalid_approval_assertion_age_input",
        "approval_artifact_not_available",
        "approval_artifact_confirmation_mismatch",
        "approval_assertion_time_invalid",
        "approval_assertion_age_evaluation_failed",
    ]
    reason: str = ""
    requested_approval_artifact_id: str = ""
    approval_artifact_id: str = ""
    approval_artifact_identity_sha256: str = ""
    confirmed_approval_artifact_identity_sha256: str = ""
    subject_sha256: str = ""
    approval_asserted_at_utc: str = ""
    evaluator_reference_utc: str = ""
    clock_consistent: bool = False
    age_microseconds: int | None = None
    age_milliseconds_ceiling: int | None = None
    evaluation_identity_sha256: str = ""
    evaluation: ApprovedChangeApprovalAssertionAgeEvaluation | None = None
    approval_artifact_load_evaluated: bool = False
    approval_artifact_loaded: bool = False
    approval_artifact_identity_confirmed: bool = False
    approval_assertion_time_evaluated: bool = False
    evaluator_clock_evaluated: bool = False
    clock_consistency_evaluated: bool = False
    approval_assertion_age_evaluated: bool = False
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = WARNINGS
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
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
    approval_freshness_evaluated: Literal[False] = False
    approval_expiration_evaluated: Literal[False] = False
    evidence_freshness_evaluated: Literal[False] = False
    pr304_evidence_freshness_evaluated: Literal[False] = False
    windows_identity_binding_evaluated: Literal[False] = False
    current_state_revalidation_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    persistence_performed: Literal[False] = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    approval_assertion_age_persisted: Literal[False] = False
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


def canonical_approval_assertion_age_evaluation_json(
    value: ApprovedChangeApprovalAssertionAgeEvaluation | Mapping[str, Any],
) -> str:
    model = (
        value
        if isinstance(value, ApprovedChangeApprovalAssertionAgeEvaluation)
        else ApprovedChangeApprovalAssertionAgeEvaluation.model_validate(value)
    )
    return json.dumps(
        model.model_dump(mode="python"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_approval_assertion_age_evaluation_sha256(
    value: ApprovedChangeApprovalAssertionAgeEvaluation | Mapping[str, Any],
) -> str:
    return hashlib.sha256(
        canonical_approval_assertion_age_evaluation_json(value).encode("utf-8")
    ).hexdigest()


def _utc_now() -> datetime:
    """Private evaluator-owned clock seam; production callers cannot set it."""
    return datetime.now(UTC)


def _canonical_utc(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _elapsed_microseconds(start: datetime, end: datetime) -> int:
    delta = end - start
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


def _result(status: str, reason: str, *, errors=(), **values: Any):
    return ApprovedChangeApprovalAssertionAgeResult(
        status=status, reason=reason, errors=tuple(sorted(set(errors))), **values
    )


def measure_persisted_approval_assertion_age(
    approval_artifact_id: str,
    *,
    data_dir: Path | str,
    confirm_approval_artifact_identity_sha256: str,
) -> ApprovedChangeApprovalAssertionAgeResult:
    """Measure one confirmed persisted assertion against one local UTC read."""
    base = {
        "requested_approval_artifact_id": approval_artifact_id
        if isinstance(approval_artifact_id, str)
        else "",
        "confirmed_approval_artifact_identity_sha256": (
            confirm_approval_artifact_identity_sha256
            if isinstance(confirm_approval_artifact_identity_sha256, str)
            else ""
        ),
    }
    errors = []
    if not isinstance(approval_artifact_id, str) or not _ARTIFACT_ID.fullmatch(
        approval_artifact_id
    ):
        errors.append("approval artifact ID must be aca_ plus 64 lowercase hexadecimal characters")
    if not isinstance(confirm_approval_artifact_identity_sha256, str) or not _SHA256.fullmatch(
        confirm_approval_artifact_identity_sha256
    ):
        errors.append("approval-artifact confirmation must be 64 lowercase hexadecimal characters")
    if errors:
        return _result(
            "invalid_approval_assertion_age_input",
            "one or more exact pure input formats are invalid",
            errors=errors,
            **base,
        )

    loaded = load_persisted_approved_change_approval_artifact(
        approval_artifact_id, data_dir=data_dir
    )
    base["approval_artifact_load_evaluated"] = True
    if loaded.status != "persisted_approval_artifact_loaded" or loaded.artifact is None:
        return _result(
            "approval_artifact_not_available",
            "the exact PR319 approval artifact was not available and valid",
            errors=loaded.errors,
            **base,
        )
    base.update(
        approval_artifact_loaded=True,
        approval_artifact_id=loaded.approval_artifact_id,
        approval_artifact_identity_sha256=loaded.approval_artifact_identity_sha256,
        subject_sha256=loaded.subject_sha256,
    )
    if loaded.approval_artifact_id != approval_artifact_id or not hmac.compare_digest(
        loaded.approval_artifact_identity_sha256,
        confirm_approval_artifact_identity_sha256,
    ):
        return _result(
            "approval_artifact_confirmation_mismatch",
            "loaded artifact ID or exact approval-artifact identity confirmation mismatched",
            errors=["exact persisted approval-artifact provenance was not confirmed"],
            **base,
        )
    base["approval_artifact_identity_confirmed"] = True

    try:
        asserted = loaded.artifact.contract.approval.approved_at
        asserted_text = _canonical_utc(asserted)
    except (AttributeError, TypeError, ValueError) as exc:
        return _result(
            "approval_assertion_time_invalid",
            "the maintained loaded approval assertion time was invalid",
            errors=[str(exc)],
            **base,
        )
    base.update(approval_assertion_time_evaluated=True, approval_asserted_at_utc=asserted_text)

    reference = _utc_now()  # Exactly one evaluator-owned wall-clock read, after confirmation.
    base["evaluator_clock_evaluated"] = True
    try:
        reference_text = _canonical_utc(reference)
    except (TypeError, ValueError) as exc:
        return _result(
            "approval_assertion_age_evaluation_failed",
            "the evaluator-local UTC clock returned an invalid timestamp",
            errors=[str(exc)],
            **base,
        )
    asserted_utc = asserted.astimezone(UTC)
    reference_utc = reference.astimezone(UTC)
    consistent = reference_utc >= asserted_utc
    base.update(
        evaluator_reference_utc=reference_text,
        clock_consistency_evaluated=True,
        clock_consistent=consistent,
    )
    age_us = _elapsed_microseconds(asserted_utc, reference_utc) if consistent else None
    age_ms = (age_us + 999) // 1000 if age_us is not None else None
    status = (
        "approval_assertion_age_evaluated"
        if consistent
        else "approval_assertion_clock_inconsistent"
    )
    evaluation = ApprovedChangeApprovalAssertionAgeEvaluation(
        approval_artifact_id=loaded.approval_artifact_id,
        approval_artifact_identity_sha256=loaded.approval_artifact_identity_sha256,
        subject_sha256=loaded.subject_sha256,
        approval_asserted_at_utc=asserted_text,
        evaluator_reference_utc=reference_text,
        clock_consistent=consistent,
        age_microseconds=age_us,
        age_milliseconds_ceiling=age_ms,
        chronology_outcome=status,
    )
    return _result(
        status,
        "assertion age was measured relative to evaluator-local UTC"
        if consistent
        else "evaluator-local UTC precedes the asserted approval time",
        age_microseconds=age_us,
        age_milliseconds_ceiling=age_ms,
        approval_assertion_age_evaluated=consistent,
        evaluation=evaluation,
        evaluation_identity_sha256=compute_approval_assertion_age_evaluation_sha256(evaluation),
        **base,
    )
