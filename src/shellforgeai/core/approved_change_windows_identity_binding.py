"""Bind exact Windows process-token evidence to exact approval provenance."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from shellforgeai.core.approved_change_approval_persistence import (
    load_persisted_approved_change_approval_artifact,
)
from shellforgeai.core.windows_process_identity_evidence import (
    WindowsProcessIdentityEvidence,
    compute_windows_process_identity_evidence_sha256,
)

COMPARISON_SCOPE = "exact_windows_process_identity_evidence_to_exact_approval_artifact_only"
WARNINGS = (
    "this binds exact Windows process-token identity evidence to one exact durable "
    "approval-artifact provenance identity only",
    "the Windows SID is OS process-token principal evidence, not verified physical-human identity",
    "AuthenticationId/LUID is authentication-session evidence and is not durable",
    "approved_by was not compared or authenticated",
    "this is not approval or evidence freshness",
    "this is not authorization, RBAC, role, or privilege evaluation",
    "this is not current-state revalidation or execution preflight",
    "this creates or links no receipt and grants no execution eligibility",
    "PR313 execution was not invoked",
    "natural language cannot invoke or convert this binding into execution",
)
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^aca_[0-9a-f]{64}$")


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ApprovedChangeWindowsIdentityBinding(_Frozen):
    schema_version: Literal[1] = 1
    binding_type: Literal["approved_change_windows_process_identity_binding"] = (
        "approved_change_windows_process_identity_binding"
    )
    approval_artifact_id: str
    approval_artifact_identity_sha256: str
    subject_sha256: str
    identity_evidence_type: str
    identity_source: str
    collector_scope: str
    principal_sid: str
    authentication_session_luid: str
    token_type: str
    identity_evidence_sha256: str
    comparison_scope: Literal[
        "exact_windows_process_identity_evidence_to_exact_approval_artifact_only"
    ] = COMPARISON_SCOPE


class ApprovedChangeWindowsIdentityBindingResult(_Frozen):
    schema_version: Literal[1] = 1
    operation_type: Literal["bind_windows_process_identity_to_approval_artifact"] = (
        "bind_windows_process_identity_to_approval_artifact"
    )
    status: Literal[
        "identity_binding_constructed",
        "invalid_identity_binding_input",
        "identity_evidence_invalid",
        "identity_evidence_confirmation_mismatch",
        "approval_artifact_not_available",
        "approval_artifact_confirmation_mismatch",
        "identity_binding_validation_failed",
    ]
    reason: str = ""
    requested_approval_artifact_id: str = ""
    approval_artifact_id: str = ""
    approval_artifact_identity_sha256: str = ""
    confirmed_approval_artifact_identity_sha256: str = ""
    subject_sha256: str = ""
    identity_evidence_sha256: str = ""
    confirmed_identity_evidence_sha256: str = ""
    identity_binding_identity_sha256: str = ""
    binding: ApprovedChangeWindowsIdentityBinding | None = None
    identity_evidence_validated: bool = False
    identity_evidence_identity_confirmed: bool = False
    approval_artifact_load_evaluated: bool = False
    approval_artifact_loaded: bool = False
    approval_artifact_identity_confirmed: bool = False
    identity_binding_evaluated: bool = False
    identity_evidence_bound: bool = False
    os_identity_evaluated: bool = False
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = WARNINGS
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    approved_by_comparison_evaluated: Literal[False] = False
    verified_human_identity: Literal[False] = False
    authenticated_identity_evaluated: Literal[False] = False
    mfa_evaluated: Literal[False] = False
    credential_validity_evaluated: Literal[False] = False
    credential_read: Literal[False] = False
    secret_read: Literal[False] = False
    auth_cache_read: Literal[False] = False
    group_membership_evaluated: Literal[False] = False
    privileges_evaluated: Literal[False] = False
    elevation_evaluated: Literal[False] = False
    integrity_level_evaluated: Literal[False] = False
    rbac_evaluated: Literal[False] = False
    role_membership_evaluated: Literal[False] = False
    approval_freshness_evaluated: Literal[False] = False
    evidence_freshness_evaluated: Literal[False] = False
    pr304_evidence_freshness_evaluated: Literal[False] = False
    current_state_revalidation_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    persistence_performed: Literal[False] = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    identity_binding_persisted: Literal[False] = False
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


def canonical_windows_identity_binding_json(
    value: ApprovedChangeWindowsIdentityBinding | Mapping[str, Any],
) -> str:
    model = (
        value
        if isinstance(value, ApprovedChangeWindowsIdentityBinding)
        else ApprovedChangeWindowsIdentityBinding.model_validate(value)
    )
    return json.dumps(
        model.model_dump(mode="python"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def compute_windows_identity_binding_sha256(
    value: ApprovedChangeWindowsIdentityBinding | Mapping[str, Any],
) -> str:
    return hashlib.sha256(
        canonical_windows_identity_binding_json(value).encode("utf-8")
    ).hexdigest()


def _result(status: str, reason: str, errors: list[str] = None, **values: Any):
    return ApprovedChangeWindowsIdentityBindingResult(
        status=status, reason=reason, errors=tuple(sorted(set(errors or ()))), **values
    )


def bind_windows_process_identity_to_approval_artifact(
    approval_artifact_id: str,
    identity_evidence: WindowsProcessIdentityEvidence | Mapping[str, Any],
    *,
    data_dir: Path | str,
    confirm_approval_artifact_identity_sha256: str,
    confirm_identity_evidence_sha256: str,
) -> ApprovedChangeWindowsIdentityBindingResult:
    """Validate pure evidence first, then load and bind exactly one approval artifact."""
    base = {
        "requested_approval_artifact_id": approval_artifact_id
        if isinstance(approval_artifact_id, str)
        else "",
        "confirmed_approval_artifact_identity_sha256": (
            confirm_approval_artifact_identity_sha256
            if isinstance(confirm_approval_artifact_identity_sha256, str)
            else ""
        ),
        "confirmed_identity_evidence_sha256": (
            confirm_identity_evidence_sha256
            if isinstance(confirm_identity_evidence_sha256, str)
            else ""
        ),
    }
    errors = []
    if not isinstance(approval_artifact_id, str) or not _ID.fullmatch(approval_artifact_id):
        errors.append("approval artifact ID must be aca_ plus 64 lowercase hexadecimal characters")
    for value, label in (
        (confirm_approval_artifact_identity_sha256, "approval-artifact confirmation"),
        (confirm_identity_evidence_sha256, "identity-evidence confirmation"),
    ):
        if not isinstance(value, str) or not _SHA.fullmatch(value):
            errors.append(f"{label} must be 64 lowercase hexadecimal characters")
    if errors:
        return _result(
            "invalid_identity_binding_input",
            "one or more exact input formats are invalid",
            errors,
            **base,
        )

    try:
        evidence = (
            identity_evidence
            if isinstance(identity_evidence, WindowsProcessIdentityEvidence)
            else WindowsProcessIdentityEvidence.model_validate(identity_evidence)
        )
        evidence_sha = compute_windows_process_identity_evidence_sha256(evidence)
    except (ValidationError, TypeError, ValueError) as exc:
        return _result(
            "identity_evidence_invalid",
            "the supplied evidence failed maintained PR342 validation",
            [str(exc)],
            **base,
        )
    base.update(
        identity_evidence_validated=True,
        os_identity_evaluated=True,
        identity_evidence_sha256=evidence_sha,
    )
    if not hmac.compare_digest(evidence_sha, confirm_identity_evidence_sha256):
        return _result(
            "identity_evidence_confirmation_mismatch",
            "exact PR342 evidence identity confirmation mismatch",
            ["exact PR342 evidence identity confirmation mismatch"],
            **base,
        )
    base["identity_evidence_identity_confirmed"] = True

    loaded = load_persisted_approved_change_approval_artifact(
        approval_artifact_id, data_dir=data_dir
    )
    base["approval_artifact_load_evaluated"] = True
    if loaded.status != "persisted_approval_artifact_loaded" or loaded.artifact is None:
        return _result(
            "approval_artifact_not_available",
            "the exact PR319 approval artifact was not available and valid",
            list(loaded.errors),
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
            "exact PR319 approval-artifact identity confirmation mismatch",
            ["exact PR319 approval-artifact identity confirmation mismatch"],
            **base,
        )
    base["approval_artifact_identity_confirmed"] = True

    try:
        binding = ApprovedChangeWindowsIdentityBinding(
            approval_artifact_id=loaded.approval_artifact_id,
            approval_artifact_identity_sha256=loaded.approval_artifact_identity_sha256,
            subject_sha256=loaded.subject_sha256,
            identity_evidence_type=evidence.identity_evidence_type,
            identity_source=evidence.identity_source,
            collector_scope=evidence.collector_scope,
            principal_sid=evidence.principal_sid,
            authentication_session_luid=evidence.authentication_session_luid,
            token_type=evidence.token_type,
            identity_evidence_sha256=evidence_sha,
        )
        binding = ApprovedChangeWindowsIdentityBinding.model_validate(binding.model_dump())
        binding_sha = compute_windows_identity_binding_sha256(binding)
    except (ValidationError, TypeError, ValueError) as exc:
        return _result(
            "identity_binding_validation_failed",
            "the bounded provenance binding failed validation",
            [str(exc)],
            identity_binding_evaluated=True,
            **base,
        )
    return _result(
        "identity_binding_constructed",
        "exact Windows process-token evidence was associated with exact approval provenance",
        binding=binding,
        identity_binding_identity_sha256=binding_sha,
        identity_binding_evaluated=True,
        identity_evidence_bound=True,
        **base,
    )
