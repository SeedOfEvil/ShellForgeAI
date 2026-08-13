"""Canonical in-memory evidence for one maintained PR338 observation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from shellforgeai.core import approved_change_plan_current_state as pr338
from shellforgeai.core.approved_change_plan_link import (
    WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
    WINDOWS_RUNTIME_RECONCILE_LANE_ID,
)

EVIDENCE_SCOPE = "exact_pr338_persisted_plan_link_current_state_evidence_content_only"
EXPECTED_MAPPINGS = (
    ("config/profiles/inspect.yaml", "config/profiles/inspect.yaml"),
    ("scripts/windows/sfai.cmd", "bin/sfai.cmd"),
)
WARNINGS = (
    "this evidence identifies exact canonical point-in-time current-state facts only",
    "state may change immediately after inspection",
    "the evidence identity does not establish freshness",
    "no observation timestamp or trusted clock is included",
    "identical state evidence content may produce the same identity across separate invocations",
    "persisted plan-link provenance is not authorization",
    "current-state match is not authenticated approval and does not authenticate a human",
    "this does not compare Windows SID/LUID with approved_by",
    "credentials, MFA, roles, groups, privileges, elevation, and RBAC are not evaluated",
    "PR352 identity provenance, PR354 approval recency, and PR304 freshness are not consumed",
    "this is not authorization or execution preflight",
    "this creates or links no receipt, persists nothing, and grants no execution eligibility",
    "PR313 execution is not invoked; natural language cannot invoke execution through "
    "this evidence",
)
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ACPL = re.compile(r"^acpl_[0-9a-f]{64}$")


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class PersistedPlanLinkCurrentStateMappingEvidence(_Frozen):
    relative_source: str
    relative_destination: str
    planned_operation: str
    current_operation: str
    source_exists: bool
    destination_exists: bool
    source_hash_matches: bool
    destination_hash_matches: bool
    parent_state: str
    current_state_matched: Literal[True] = True
    reason_codes: tuple[str, ...] = ()


class ApprovedChangePersistedPlanLinkCurrentStateEvidence(_Frozen):
    schema_version: Literal[1] = 1
    evidence_type: Literal["approved_change_persisted_plan_link_current_state_evidence"] = (
        "approved_change_persisted_plan_link_current_state_evidence"
    )
    source_operation_type: Literal["persisted_plan_link_artifact_current_state_revalidation"] = (
        "persisted_plan_link_artifact_current_state_revalidation"
    )
    plan_link_artifact_id: str
    plan_link_artifact_identity_sha256: str
    plan_link_identity_sha256: str
    approval_artifact_id: str
    approval_artifact_identity_sha256: str
    subject_sha256: str
    capability_binding_identity_sha256: str
    capability_catalog_identity_sha256: str
    lane_declaration_identity_sha256: str
    capability_id: str
    lane_id: str
    plan_sha256: str
    plan_mode: str
    recipe_id: str
    plan_status: str
    current_state_scope: str
    staged_source_root_fingerprint: str
    durable_runtime_root_fingerprint: str
    mappings: tuple[PersistedPlanLinkCurrentStateMappingEvidence, ...]
    evidence_scope: Literal[
        "exact_pr338_persisted_plan_link_current_state_evidence_content_only"
    ] = EVIDENCE_SCOPE
    source_status: Literal["current_state_confirmed"] = "current_state_confirmed"


class ApprovedChangePersistedPlanLinkCurrentStateEvidenceResult(_Frozen):
    schema_version: Literal[1] = 1
    operation_type: Literal["construct_persisted_plan_link_current_state_evidence"] = (
        "construct_persisted_plan_link_current_state_evidence"
    )
    status: Literal[
        "current_state_evidence_constructed",
        "current_state_evidence_unavailable",
        "current_state_evidence_not_confirmed",
        "invalid_current_state_evidence_input",
        "current_state_evidence_validation_failed",
    ]
    reason: str = ""
    source_status: str = ""
    evidence: ApprovedChangePersistedPlanLinkCurrentStateEvidence | None = None
    evidence_identity_sha256: str = ""
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = WARNINGS
    read_only: Literal[True] = True
    current_state_revalidation_evaluated: bool = False
    current_state_matched: bool = False
    current_state_evidence_constructed: bool = False
    filesystem_accessed: bool = False
    mutation_performed: Literal[False] = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    current_state_evidence_persisted: Literal[False] = False
    authenticated_identity_evaluated: Literal[False] = False
    verified_human_identity: Literal[False] = False
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
    windows_identity_binding_evaluated: Literal[False] = False
    approval_assertion_recency_evaluated: Literal[False] = False
    approval_freshness_evaluated: Literal[False] = False
    pr304_evidence_freshness_evaluated: Literal[False] = False
    current_state_freshness_evaluated: Literal[False] = False
    observation_time_recorded: Literal[False] = False
    trusted_time_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
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


def canonical_persisted_plan_link_current_state_evidence_json(
    value: ApprovedChangePersistedPlanLinkCurrentStateEvidence | Mapping[str, Any],
) -> str:
    model = (
        value
        if isinstance(value, ApprovedChangePersistedPlanLinkCurrentStateEvidence)
        else ApprovedChangePersistedPlanLinkCurrentStateEvidence.model_validate(value)
    )
    return json.dumps(
        model.model_dump(mode="python"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def compute_persisted_plan_link_current_state_evidence_sha256(
    value: ApprovedChangePersistedPlanLinkCurrentStateEvidence | Mapping[str, Any],
) -> str:
    return hashlib.sha256(
        canonical_persisted_plan_link_current_state_evidence_json(value).encode("utf-8")
    ).hexdigest()


def _consistent(result: pr338.PersistedPlanLinkCurrentStateResult, requested: str) -> bool:
    required = (
        result.plan_validated,
        result.plan_identity_confirmed,
        result.plan_link_artifact_load_evaluated,
        result.plan_link_artifact_loaded,
        result.plan_link_artifact_identity_confirmed,
        result.plan_link_validated,
        result.plan_link_plan_comparison_evaluated,
        result.plan_link_plan_matched,
        result.current_state_revalidation_evaluated,
        result.current_state_matched,
    )
    identities = (
        result.plan_link_artifact_identity_sha256,
        result.plan_link_identity_sha256,
        result.approval_artifact_identity_sha256,
        result.subject_sha256,
        result.capability_binding_identity_sha256,
        result.capability_catalog_identity_sha256,
        result.lane_declaration_identity_sha256,
        result.plan_sha256,
        result.confirmed_plan_sha256,
        result.staged_source_root_fingerprint,
        result.durable_runtime_root_fingerprint,
    )
    pairs = tuple((m.relative_source, m.relative_destination) for m in result.mappings)
    mappings_ok = pairs == EXPECTED_MAPPINGS and all(
        m.current_state_matched
        and m.planned_operation == m.current_operation
        and bool(m.planned_operation)
        and bool(m.parent_state)
        for m in result.mappings
    )
    return (
        result.status == "current_state_confirmed"
        and all(required)
        and result.requested_plan_link_artifact_id == requested
        and bool(_ACPL.fullmatch(requested))
        and all(_SHA.fullmatch(value) for value in identities)
        and result.plan_sha256 == result.confirmed_plan_sha256
        and result.capability_id == WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID
        and result.lane_id == WINDOWS_RUNTIME_RECONCILE_LANE_ID
        and bool(result.approval_artifact_id)
        and bool(result.plan_mode and result.recipe_id and result.plan_status)
        and result.current_state_scope == pr338.CURRENT_STATE_SCOPE
        and mappings_ok
    )


def construct_persisted_plan_link_current_state_evidence(
    plan_link_artifact_id: str,
    plan_packet: Mapping[str, Any],
    *,
    data_dir: Path | str,
    staged_source_root: Path | str,
    durable_runtime_root: Path | str,
    confirm_plan_link_artifact_identity_sha256: str,
    confirm_plan_sha256: str,
) -> ApprovedChangePersistedPlanLinkCurrentStateEvidenceResult:
    """Call PR338 once and canonically identify only a coherent success result."""
    result = pr338.revalidate_persisted_plan_link_artifact_current_state(
        plan_link_artifact_id,
        plan_packet,
        data_dir=data_dir,
        staged_source_root=staged_source_root,
        durable_runtime_root=durable_runtime_root,
        confirm_plan_link_artifact_identity_sha256=confirm_plan_link_artifact_identity_sha256,
        confirm_plan_sha256=confirm_plan_sha256,
    )
    base = dict(
        source_status=result.status,
        current_state_revalidation_evaluated=result.current_state_revalidation_evaluated,
        current_state_matched=result.current_state_matched,
        filesystem_accessed=result.current_state_revalidation_evaluated,
    )
    if result.status != "current_state_confirmed":
        return ApprovedChangePersistedPlanLinkCurrentStateEvidenceResult(
            status="current_state_evidence_unavailable"
            if result.status == "unsupported"
            else "current_state_evidence_not_confirmed",
            reason="maintained current-state authority did not confirm the exact state",
            **base,
        )
    if not _consistent(result, plan_link_artifact_id):
        return ApprovedChangePersistedPlanLinkCurrentStateEvidenceResult(
            status="current_state_evidence_validation_failed",
            reason="maintained current-state success facts were internally inconsistent",
            errors=("contradictory current-state-confirmed result",),
            **base,
        )
    evidence = ApprovedChangePersistedPlanLinkCurrentStateEvidence(
        plan_link_artifact_id=result.requested_plan_link_artifact_id,
        plan_link_artifact_identity_sha256=result.plan_link_artifact_identity_sha256,
        plan_link_identity_sha256=result.plan_link_identity_sha256,
        approval_artifact_id=result.approval_artifact_id,
        approval_artifact_identity_sha256=result.approval_artifact_identity_sha256,
        subject_sha256=result.subject_sha256,
        capability_binding_identity_sha256=result.capability_binding_identity_sha256,
        capability_catalog_identity_sha256=result.capability_catalog_identity_sha256,
        lane_declaration_identity_sha256=result.lane_declaration_identity_sha256,
        capability_id=result.capability_id,
        lane_id=result.lane_id,
        plan_sha256=result.plan_sha256,
        plan_mode=result.plan_mode,
        recipe_id=result.recipe_id,
        plan_status=result.plan_status,
        current_state_scope=result.current_state_scope,
        staged_source_root_fingerprint=result.staged_source_root_fingerprint,
        durable_runtime_root_fingerprint=result.durable_runtime_root_fingerprint,
        mappings=tuple(
            PersistedPlanLinkCurrentStateMappingEvidence.model_validate(m.model_dump())
            for m in result.mappings
        ),
    )
    return ApprovedChangePersistedPlanLinkCurrentStateEvidenceResult(
        status="current_state_evidence_constructed",
        reason="exact canonical current-state evidence content was constructed",
        evidence=evidence,
        evidence_identity_sha256=compute_persisted_plan_link_current_state_evidence_sha256(
            evidence
        ),
        current_state_evidence_constructed=True,
        **base,
    )
