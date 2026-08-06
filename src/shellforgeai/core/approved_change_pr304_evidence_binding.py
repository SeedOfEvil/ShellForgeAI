"""Read-only binding of exact PR337 provenance to exact PR304 evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from shellforgeai.core.approved_change_plan_link import validate_approved_change_plan_link
from shellforgeai.core.approved_change_plan_link_artifact_persistence import (
    load_persisted_approved_change_plan_link_artifact,
)
from shellforgeai.core.windows_runtime_integrity_contract import (
    prepare_pr304_runtime_integrity_evidence_set,
)
from shellforgeai.core.windows_runtime_reconcile_plan_contract import (
    validate_saved_windows_runtime_reconcile_plan_packet,
)

COMPARISON_SCOPE = "exact_persisted_plan_link_to_exact_validated_pr304_two_packet_evidence_set_only"
WARNINGS = (
    "evidence-set identity is not evidence freshness",
    "packet timestamps are not added or trusted by PR339",
    "state may already have changed",
    "packet role labels are caller-assigned and not authenticated",
    "PR304 packet status is an evidence fact, not authorization",
    "persisted plan-link provenance is not authorization",
    "the full saved plan packet was not persisted",
    "the PR304 packets were not persisted by PR339",
    "this is not authenticated identity, approval freshness, current-state revalidation, "
    "or execution preflight",
    "this creates and links no receipt and grants no execution eligibility",
    "PR313 execution was not invoked; natural language cannot invoke this operation",
    "one exact full acpl_ ID and all exact confirmations remain mandatory",
)
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^acpl_[0-9a-f]{64}$")


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ApprovedChangePr304EvidenceBinding(_Frozen):
    schema_version: Literal[1] = 1
    binding_type: Literal["approved_change_pr304_evidence_binding"] = (
        "approved_change_pr304_evidence_binding"
    )
    requested_plan_link_artifact_id: str
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
    source_root_packet_identity_sha256: str
    system32_packet_identity_sha256: str
    evidence_set_identity_sha256: str
    comparison_scope: Literal[
        "exact_persisted_plan_link_to_exact_validated_pr304_two_packet_evidence_set_only"
    ] = COMPARISON_SCOPE


class ApprovedChangePr304EvidenceBindingResult(_Frozen):
    schema_version: Literal[1] = 1
    operation_type: Literal["bind_persisted_plan_link_to_pr304_evidence_set"] = (
        "bind_persisted_plan_link_to_pr304_evidence_set"
    )
    status: Literal[
        "evidence_binding_constructed",
        "evidence_set_invalid",
        "evidence_set_inconsistent",
        "evidence_set_confirmation_mismatch",
        "plan_link_artifact_not_available",
        "plan_link_artifact_confirmation_mismatch",
        "persisted_link_plan_mismatch",
        "invalid_evidence_binding_input",
        "evidence_binding_validation_failed",
    ]
    reason: str = ""
    requested_plan_link_artifact_id: str = ""
    plan_link_artifact_identity_sha256: str = ""
    plan_link_identity_sha256: str = ""
    approval_artifact_id: str = ""
    approval_artifact_identity_sha256: str = ""
    subject_sha256: str = ""
    capability_binding_identity_sha256: str = ""
    capability_catalog_identity_sha256: str = ""
    lane_declaration_identity_sha256: str = ""
    capability_id: str = ""
    lane_id: str = ""
    plan_sha256: str = ""
    confirmed_plan_sha256: str = ""
    plan_mode: str = ""
    recipe_id: str = ""
    plan_status: str = ""
    source_root_packet_identity_sha256: str = ""
    source_root_packet_status: str = ""
    system32_packet_identity_sha256: str = ""
    system32_packet_status: str = ""
    evidence_set_identity_sha256: str = ""
    confirmed_evidence_set_identity_sha256: str = ""
    evidence_binding_identity_sha256: str = ""
    binding: ApprovedChangePr304EvidenceBinding | None = None
    plan_validated: bool = False
    plan_identity_confirmed: bool = False
    evidence_packets_validated: bool = False
    evidence_set_prepared: bool = False
    evidence_set_identity_confirmed: bool = False
    stable_field_comparison_evaluated: bool = False
    stable_fields_consistent: bool = False
    stable_field_mismatches: tuple[str, ...] = ()
    plan_link_artifact_load_evaluated: bool = False
    plan_link_artifact_loaded: bool = False
    plan_link_artifact_identity_confirmed: bool = False
    plan_link_validated: bool = False
    persisted_link_plan_comparison_evaluated: bool = False
    persisted_link_plan_matched: bool = False
    evidence_binding_evaluated: bool = False
    evidence_bound: bool = False
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = WARNINGS
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    plan_packet_persisted: Literal[False] = False
    pr304_packets_persisted: Literal[False] = False
    evidence_set_persisted: Literal[False] = False
    evidence_binding_persisted: Literal[False] = False
    current_state_persisted: Literal[False] = False
    current_state_revalidation_evaluated: Literal[False] = False
    evidence_freshness_evaluated: Literal[False] = False
    pr304_evidence_freshness_evaluated: Literal[False] = False
    authenticated_identity_evaluated: Literal[False] = False
    approval_freshness_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    file_create_executed: Literal[False] = False
    file_replace_executed: Literal[False] = False
    backup_created: Literal[False] = False
    atomic_runtime_replace_executed: Literal[False] = False
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


def canonical_evidence_binding_json(
    value: ApprovedChangePr304EvidenceBinding | Mapping[str, Any],
) -> str:
    model = (
        value
        if isinstance(value, ApprovedChangePr304EvidenceBinding)
        else ApprovedChangePr304EvidenceBinding.model_validate(value)
    )
    return json.dumps(
        model.model_dump(mode="python"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def compute_evidence_binding_identity_sha256(
    value: ApprovedChangePr304EvidenceBinding | Mapping[str, Any],
) -> str:
    return hashlib.sha256(canonical_evidence_binding_json(value).encode("utf-8")).hexdigest()


def _result(
    status: str, reason: str, errors: list[str] | tuple[str, ...] = (), **values: Any
) -> ApprovedChangePr304EvidenceBindingResult:
    return ApprovedChangePr304EvidenceBindingResult(
        status=status, reason=reason, errors=tuple(sorted(set(errors))), **values
    )


def bind_persisted_plan_link_to_pr304_evidence_set(
    plan_link_artifact_id: str,
    plan_packet: Mapping[str, Any],
    source_root_packet: Mapping[str, Any],
    system32_packet: Mapping[str, Any],
    *,
    data_dir: Path | str,
    confirm_plan_link_artifact_identity_sha256: str,
    confirm_plan_sha256: str,
    confirm_evidence_set_identity_sha256: str,
) -> ApprovedChangePr304EvidenceBindingResult:
    """Validate pure inputs before loading exactly one PR337 artifact, then bind in memory."""
    base = {
        "requested_plan_link_artifact_id": plan_link_artifact_id
        if isinstance(plan_link_artifact_id, str)
        else "",
        "confirmed_plan_sha256": confirm_plan_sha256
        if isinstance(confirm_plan_sha256, str)
        else "",
        "confirmed_evidence_set_identity_sha256": confirm_evidence_set_identity_sha256
        if isinstance(confirm_evidence_set_identity_sha256, str)
        else "",
    }
    format_errors = []
    if not isinstance(plan_link_artifact_id, str) or not _ID.fullmatch(plan_link_artifact_id):
        format_errors.append(
            "plan-link artifact ID must be acpl_ plus 64 lowercase hexadecimal characters"
        )
    for value, label in (
        (confirm_plan_link_artifact_identity_sha256, "artifact confirmation"),
        (confirm_plan_sha256, "plan confirmation"),
        (confirm_evidence_set_identity_sha256, "evidence-set confirmation"),
    ):
        if not isinstance(value, str) or not _SHA.fullmatch(value):
            format_errors.append(f"{label} must be 64 lowercase hexadecimal characters")
    if format_errors:
        return _result(
            "invalid_evidence_binding_input",
            "one or more exact input formats are invalid",
            format_errors,
            **base,
        )
    plan = validate_saved_windows_runtime_reconcile_plan_packet(plan_packet)
    base.update(
        plan_validated=plan.plan_valid,
        plan_sha256=plan.plan_sha256,
        plan_mode=plan.plan_mode,
        recipe_id=plan.plan_recipe_id,
        plan_status=plan.plan_status,
    )
    if not plan.plan_valid:
        return _result(
            "invalid_evidence_binding_input",
            "the plan failed maintained PR305/PR313 validation",
            list(plan.errors),
            **base,
        )
    if not hmac.compare_digest(plan.plan_sha256, confirm_plan_sha256):
        return _result(
            "invalid_evidence_binding_input",
            "canonical plan confirmation mismatch",
            ["canonical plan confirmation mismatch"],
            **base,
        )
    base["plan_identity_confirmed"] = True
    prepared = prepare_pr304_runtime_integrity_evidence_set(source_root_packet, system32_packet)
    base.update(
        evidence_packets_validated=prepared.evidence_packets_validated,
        evidence_set_prepared=prepared.evidence_set_prepared,
        evidence_set_identity_sha256=prepared.evidence_set_identity_sha256,
        source_root_packet_identity_sha256=prepared.source_root_packet_identity_sha256,
        system32_packet_identity_sha256=prepared.system32_packet_identity_sha256,
        stable_field_comparison_evaluated=prepared.stable_field_comparison_evaluated,
        stable_fields_consistent=prepared.stable_fields_consistent,
        stable_field_mismatches=prepared.stable_field_mismatches,
    )
    if prepared.status != "evidence_set_prepared":
        return _result(prepared.status, prepared.reason, list(prepared.errors), **base)
    assert prepared.evidence_set is not None
    base.update(
        source_root_packet_status=prepared.evidence_set.source_root_observation.packet_status,
        system32_packet_status=prepared.evidence_set.system32_observation.packet_status,
    )
    if not hmac.compare_digest(
        prepared.evidence_set_identity_sha256, confirm_evidence_set_identity_sha256
    ):
        return _result(
            "evidence_set_confirmation_mismatch",
            "exact evidence-set confirmation mismatch",
            ["exact evidence-set confirmation mismatch"],
            **base,
        )
    base["evidence_set_identity_confirmed"] = True
    loaded = load_persisted_approved_change_plan_link_artifact(data_dir, plan_link_artifact_id)
    base["plan_link_artifact_load_evaluated"] = True
    if loaded.status != "plan_link_artifact_loaded" or loaded.artifact is None:
        return _result(
            "plan_link_artifact_not_available",
            "the exact PR337 artifact was not available",
            list(loaded.errors),
            **base,
        )
    base.update(
        plan_link_artifact_loaded=True,
        plan_link_artifact_identity_sha256=loaded.artifact_identity_sha256,
    )
    if loaded.artifact_id != plan_link_artifact_id or not hmac.compare_digest(
        loaded.artifact_identity_sha256, confirm_plan_link_artifact_identity_sha256
    ):
        return _result(
            "plan_link_artifact_confirmation_mismatch",
            "exact PR337 artifact identity confirmation mismatch",
            ["exact PR337 artifact identity confirmation mismatch"],
            **base,
        )
    base["plan_link_artifact_identity_confirmed"] = True
    artifact = loaded.artifact
    link = artifact.plan_link
    checked_link = validate_approved_change_plan_link(link, plan_validation=plan)
    base.update(
        plan_link_validated=checked_link.link_valid,
        plan_link_identity_sha256=artifact.plan_link_identity_sha256,
        persisted_link_plan_comparison_evaluated=True,
    )
    mismatch = list(checked_link.errors)
    if artifact.plan_sha256 != plan.plan_sha256:
        mismatch.append("persisted plan SHA does not match the supplied plan")
    if mismatch:
        return _result(
            "persisted_link_plan_mismatch",
            "the persisted link does not match the exact validated plan",
            mismatch,
            **base,
        )
    base["persisted_link_plan_matched"] = True
    binding = ApprovedChangePr304EvidenceBinding(
        requested_plan_link_artifact_id=plan_link_artifact_id,
        plan_link_artifact_identity_sha256=loaded.artifact_identity_sha256,
        plan_link_identity_sha256=artifact.plan_link_identity_sha256,
        approval_artifact_id=artifact.approval_artifact_id,
        approval_artifact_identity_sha256=artifact.approval_artifact_identity_sha256,
        subject_sha256=artifact.subject_sha256,
        capability_binding_identity_sha256=artifact.capability_binding_identity_sha256,
        capability_catalog_identity_sha256=artifact.capability_catalog_identity_sha256,
        lane_declaration_identity_sha256=artifact.lane_declaration_identity_sha256,
        capability_id=artifact.capability_id,
        lane_id=artifact.lane_id,
        plan_sha256=plan.plan_sha256,
        source_root_packet_identity_sha256=prepared.source_root_packet_identity_sha256,
        system32_packet_identity_sha256=prepared.system32_packet_identity_sha256,
        evidence_set_identity_sha256=prepared.evidence_set_identity_sha256,
    )
    identity = compute_evidence_binding_identity_sha256(binding)
    base.update(
        approval_artifact_id=artifact.approval_artifact_id,
        approval_artifact_identity_sha256=artifact.approval_artifact_identity_sha256,
        subject_sha256=artifact.subject_sha256,
        capability_binding_identity_sha256=artifact.capability_binding_identity_sha256,
        capability_catalog_identity_sha256=artifact.capability_catalog_identity_sha256,
        lane_declaration_identity_sha256=artifact.lane_declaration_identity_sha256,
        capability_id=artifact.capability_id,
        lane_id=artifact.lane_id,
        evidence_binding_evaluated=True,
        evidence_bound=True,
        evidence_binding_identity_sha256=identity,
        binding=binding,
    )
    return _result(
        "evidence_binding_constructed",
        "exact persisted plan-link provenance was bound in memory to the exact ordered "
        "PR304 evidence set",
        **base,
    )
