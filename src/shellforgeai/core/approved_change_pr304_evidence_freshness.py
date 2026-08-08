"""Read-only temporal freshness classification for an exact PR304 evidence set."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from shellforgeai.core.windows_runtime_integrity_contract import (
    Pr304RuntimeIntegrityEvidenceSet,
    compute_evidence_set_identity_sha256,
    parse_pr304_canonical_utc,
)

MAX_OLDEST_EVIDENCE_AGE_MS = 300_000
POLICY_TYPE = "pr304_runtime_integrity_evidence_freshness"
AGE_BASIS = "earliest_capture_start_to_evaluator_local_utc"
REFERENCE_CLOCK_SOURCE = "local_system_utc"
CLOCK_TRUST = "untrusted_local_system_clock"
_SHA = re.compile(r"^[0-9a-f]{64}$")

WARNINGS = (
    "freshness uses evaluator local system UTC",
    "local UTC is not authenticated or externally trusted",
    "cross-host clock synchronization is not proven",
    "evidence freshness is not approval freshness",
    "evidence freshness is not current-state validation and does not solve TOCTOU",
    "state may change immediately after capture",
    "freshness is not authorization, execution preflight, or execution eligibility",
    "packet status remains an independent evidence fact",
    "legacy untimed evidence cannot receive a freshness classification",
    "no evidence or result is persisted",
    "natural language cannot invoke execution through this result",
    "PR313 execution is not invoked",
)


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Pr304EvidenceFreshnessPolicy(_Frozen):
    schema_version: Literal[1] = 1
    policy_type: Literal["pr304_runtime_integrity_evidence_freshness"] = POLICY_TYPE
    max_oldest_evidence_age_ms: Literal[300000] = MAX_OLDEST_EVIDENCE_AGE_MS
    age_basis: Literal["earliest_capture_start_to_evaluator_local_utc"] = AGE_BASIS
    reference_clock_source: Literal["local_system_utc"] = REFERENCE_CLOCK_SOURCE
    clock_trust: Literal["untrusted_local_system_clock"] = CLOCK_TRUST


class Pr304EvidenceFreshnessEvaluation(_Frozen):
    schema_version: Literal[1] = 1
    evaluation_type: Literal["pr304_runtime_integrity_evidence_freshness_evaluation"] = (
        "pr304_runtime_integrity_evidence_freshness_evaluation"
    )
    evidence_set_identity_sha256: str
    freshness_policy_identity_sha256: str
    reference_time_utc: str
    reference_clock_source: Literal["local_system_utc"] = REFERENCE_CLOCK_SOURCE
    reference_time_trusted: Literal[False] = False
    earliest_capture_started_at_utc: str
    latest_capture_completed_at_utc: str
    oldest_evidence_age_ms: int
    latest_completion_age_ms: int
    capture_pair_span_ms: int
    freshness_status: Literal["evidence_fresh", "evidence_stale"]


Status = Literal[
    "evidence_fresh",
    "evidence_stale",
    "freshness_unavailable",
    "freshness_clock_inconsistent",
    "evidence_set_confirmation_mismatch",
    "freshness_policy_confirmation_mismatch",
    "invalid_freshness_input",
    "freshness_evaluation_failed",
]


class Pr304EvidenceFreshnessEvaluationResult(_Frozen):
    status: Status
    reason: str
    evidence_set_identity_sha256: str = ""
    confirmed_evidence_set_identity_sha256: str = ""
    freshness_policy_identity_sha256: str = ""
    confirmed_freshness_policy_identity_sha256: str = ""
    max_oldest_evidence_age_ms: Literal[300000] = MAX_OLDEST_EVIDENCE_AGE_MS
    evidence_set_validated: bool = False
    evidence_set_identity_confirmed: bool = False
    freshness_policy_evaluated: bool = False
    freshness_policy_identity_confirmed: bool = False
    capture_chronology_available: bool = False
    capture_chronology_valid: bool = False
    reference_time_evaluated: bool = False
    reference_time_utc: str = ""
    reference_clock_source: Literal["local_system_utc"] = REFERENCE_CLOCK_SOURCE
    reference_time_trusted: Literal[False] = False
    oldest_evidence_age_ms: int | None = None
    latest_completion_age_ms: int | None = None
    capture_pair_span_ms: int | None = None
    freshness_evaluated: bool = False
    evidence_fresh: bool = False
    evidence_stale: bool = False
    freshness_evaluation_identity_sha256: str = ""
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = WARNINGS
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    pr304_packets_persisted: Literal[False] = False
    evidence_set_persisted: Literal[False] = False
    freshness_evaluation_persisted: Literal[False] = False
    current_state_persisted: Literal[False] = False
    authenticated_identity_evaluated: Literal[False] = False
    approval_freshness_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    current_state_revalidation_evaluated: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    file_create_executed: Literal[False] = False
    file_replace_executed: Literal[False] = False
    backup_created: Literal[False] = False
    parent_directory_create_executed: Literal[False] = False
    compensation_executed: Literal[False] = False
    service_control_executed: Literal[False] = False
    process_termination_executed: Literal[False] = False
    registry_modified: Literal[False] = False
    powershell_executed: Literal[False] = False
    winrm_used: Literal[False] = False
    qga_used: Literal[False] = False
    remote_execution: Literal[False] = False
    subprocess_executed: Literal[False] = False
    shell_executed: Literal[False] = False
    natural_language_execution: Literal[False] = False
    network_call: Literal[False] = False
    model_called: Literal[False] = False
    secret_read: Literal[False] = False
    auth_cache_read: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = "not_executed"


def maintained_pr304_evidence_freshness_policy() -> Pr304EvidenceFreshnessPolicy:
    return Pr304EvidenceFreshnessPolicy()


def _canonical(value: BaseModel) -> str:
    return json.dumps(
        value.model_dump(mode="python"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def canonical_pr304_evidence_freshness_policy_json(
    value: Pr304EvidenceFreshnessPolicy | Mapping[str, Any],
) -> str:
    model = (
        value
        if isinstance(value, Pr304EvidenceFreshnessPolicy)
        else Pr304EvidenceFreshnessPolicy.model_validate(value)
    )
    return _canonical(model)


def compute_pr304_evidence_freshness_policy_identity_sha256(
    value: Pr304EvidenceFreshnessPolicy | Mapping[str, Any],
) -> str:
    return hashlib.sha256(
        canonical_pr304_evidence_freshness_policy_json(value).encode("utf-8")
    ).hexdigest()


def canonical_pr304_evidence_freshness_evaluation_json(
    value: Pr304EvidenceFreshnessEvaluation | Mapping[str, Any],
) -> str:
    model = (
        value
        if isinstance(value, Pr304EvidenceFreshnessEvaluation)
        else Pr304EvidenceFreshnessEvaluation.model_validate(value)
    )
    return _canonical(model)


def compute_pr304_evidence_freshness_evaluation_identity_sha256(
    value: Pr304EvidenceFreshnessEvaluation | Mapping[str, Any],
) -> str:
    return hashlib.sha256(
        canonical_pr304_evidence_freshness_evaluation_json(value).encode("utf-8")
    ).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _ceil_ms(delta) -> int:
    microseconds = delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds
    return (microseconds + 999) // 1000


def _result(
    status: Status, reason: str, *, errors=(), **values: Any
) -> Pr304EvidenceFreshnessEvaluationResult:
    return Pr304EvidenceFreshnessEvaluationResult(
        status=status, reason=reason, errors=tuple(sorted(set(errors))), **values
    )


def evaluate_pr304_evidence_set_freshness(
    evidence_set: Pr304RuntimeIntegrityEvidenceSet | Mapping[str, Any],
    *,
    confirm_evidence_set_identity_sha256: str,
    confirm_freshness_policy_identity_sha256: str,
) -> Pr304EvidenceFreshnessEvaluationResult:
    """Classify temporal age after all pure confirmation and chronology gates."""
    base = {
        "confirmed_evidence_set_identity_sha256": confirm_evidence_set_identity_sha256
        if isinstance(confirm_evidence_set_identity_sha256, str)
        else "",
        "confirmed_freshness_policy_identity_sha256": confirm_freshness_policy_identity_sha256
        if isinstance(confirm_freshness_policy_identity_sha256, str)
        else "",
    }
    errors = []
    if not isinstance(evidence_set, (Pr304RuntimeIntegrityEvidenceSet, Mapping)):
        errors.append("evidence set must be a maintained model or mapping")
    if not isinstance(confirm_evidence_set_identity_sha256, str) or not _SHA.fullmatch(
        confirm_evidence_set_identity_sha256
    ):
        errors.append("evidence-set confirmation must be 64 lowercase hexadecimal characters")
    if not isinstance(confirm_freshness_policy_identity_sha256, str) or not _SHA.fullmatch(
        confirm_freshness_policy_identity_sha256
    ):
        errors.append("freshness-policy confirmation must be 64 lowercase hexadecimal characters")
    if errors:
        return _result(
            "invalid_freshness_input",
            "one or more pure input formats are invalid",
            errors=errors,
            **base,
        )
    try:
        model = (
            evidence_set
            if isinstance(evidence_set, Pr304RuntimeIntegrityEvidenceSet)
            else Pr304RuntimeIntegrityEvidenceSet.model_validate(evidence_set)
        )
        evidence_identity = compute_evidence_set_identity_sha256(model)
    except (ValidationError, TypeError, ValueError) as exc:
        return _result(
            "invalid_freshness_input",
            "the evidence set failed maintained validation",
            errors=[str(exc)],
            **base,
        )
    base.update(evidence_set_validated=True, evidence_set_identity_sha256=evidence_identity)
    if not hmac.compare_digest(evidence_identity, confirm_evidence_set_identity_sha256):
        return _result(
            "evidence_set_confirmation_mismatch",
            "exact evidence-set identity confirmation mismatch",
            **base,
        )
    base["evidence_set_identity_confirmed"] = True
    policy = maintained_pr304_evidence_freshness_policy()
    policy_identity = compute_pr304_evidence_freshness_policy_identity_sha256(policy)
    base.update(freshness_policy_evaluated=True, freshness_policy_identity_sha256=policy_identity)
    if not hmac.compare_digest(policy_identity, confirm_freshness_policy_identity_sha256):
        return _result(
            "freshness_policy_confirmation_mismatch",
            "exact freshness-policy identity confirmation mismatch",
            **base,
        )
    base["freshness_policy_identity_confirmed"] = True
    base.update(
        capture_chronology_available=model.capture_chronology_available,
        capture_chronology_valid=model.capture_chronology_valid,
    )
    if not model.stable_field_comparison_evaluated or not model.stable_fields_consistent:
        return _result(
            "freshness_evaluation_failed",
            "stable-field consistency is required",
            errors=model.stable_field_mismatches,
            **base,
        )
    if not model.capture_chronology_available:
        return _result(
            "freshness_unavailable",
            "legacy untimed evidence has no freshness classification",
            **base,
        )
    start = parse_pr304_canonical_utc(model.earliest_capture_started_at_utc)
    completed = parse_pr304_canonical_utc(model.latest_capture_completed_at_utc)
    if (
        not model.capture_chronology_valid
        or start is None
        or completed is None
        or completed < start
    ):
        return _result(
            "freshness_evaluation_failed",
            "capture chronology is malformed or internally invalid",
            **base,
        )
    reference = _utc_now()  # Exactly one evaluator-owned wall-clock read.
    reference_text = reference.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    reference_naive = parse_pr304_canonical_utc(reference_text)
    base.update(reference_time_evaluated=True, reference_time_utc=reference_text)
    if reference_naive < completed:
        return _result(
            "freshness_clock_inconsistent",
            "evaluator UTC precedes latest capture completion",
            **base,
        )
    oldest_ms = _ceil_ms(reference_naive - start)
    latest_ms = _ceil_ms(reference_naive - completed)
    span_ms = _ceil_ms(completed - start)
    status: Status = (
        "evidence_fresh" if oldest_ms <= MAX_OLDEST_EVIDENCE_AGE_MS else "evidence_stale"
    )
    evaluation = Pr304EvidenceFreshnessEvaluation(
        evidence_set_identity_sha256=evidence_identity,
        freshness_policy_identity_sha256=policy_identity,
        reference_time_utc=reference_text,
        earliest_capture_started_at_utc=model.earliest_capture_started_at_utc,
        latest_capture_completed_at_utc=model.latest_capture_completed_at_utc,
        oldest_evidence_age_ms=oldest_ms,
        latest_completion_age_ms=latest_ms,
        capture_pair_span_ms=span_ms,
        freshness_status=status,
    )
    return _result(
        status,
        "oldest evidence is within the maintained age window"
        if status == "evidence_fresh"
        else "oldest evidence exceeds the maintained age window",
        oldest_evidence_age_ms=oldest_ms,
        latest_completion_age_ms=latest_ms,
        capture_pair_span_ms=span_ms,
        freshness_evaluated=True,
        evidence_fresh=status == "evidence_fresh",
        evidence_stale=status == "evidence_stale",
        freshness_evaluation_identity_sha256=compute_pr304_evidence_freshness_evaluation_identity_sha256(
            evaluation
        ),
        **base,
    )
