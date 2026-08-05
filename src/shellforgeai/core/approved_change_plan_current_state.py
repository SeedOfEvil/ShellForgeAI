"""Point-in-time revalidation of one exact PR323-linked reconcile plan.

This module is deliberately not an execution preflight.  It performs the same
bounded, read-only file and parent evaluation used by PR313, but never enters
the PR313 execution operation and never persists its result.
"""

from __future__ import annotations

import hmac
import platform
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from shellforgeai.core.approved_change_capability_binding import (
    compute_capability_lane_declaration_sha256,
    maintained_windows_runtime_reconcile_lane_declaration,
)
from shellforgeai.core.approved_change_capability_support import (
    compute_approved_change_capability_support_catalog_sha256,
    maintained_approved_change_capability_support_catalog,
)
from shellforgeai.core.approved_change_plan_link import (
    WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
    WINDOWS_RUNTIME_RECONCILE_LANE_ID,
    compute_approved_change_plan_link_sha256,
    link_persisted_approved_change_to_windows_runtime_reconcile_plan,
    validate_approved_change_plan_link,
)
from shellforgeai.core.approved_change_plan_link_artifact_persistence import (
    load_persisted_approved_change_plan_link_artifact,
)
from shellforgeai.core.windows_runtime_reconcile_execution import (
    ALLOWLIST,
    _evaluate_file,
    load_validators,
    root_fingerprint,
)
from shellforgeai.core.windows_runtime_reconcile_plan_contract import (
    ACCEPTED_PLAN_STATUSES,
    canonical_plan_sha256,
    validate_saved_windows_runtime_reconcile_plan_packet,
)

CURRENT_STATE_SCHEMA_VERSION = "1"
CURRENT_STATE_SCOPE = "exact_pr313_two_file_linked_plan_point_in_time"
PERMANENT_CURRENT_STATE_WARNINGS = (
    "current-state revalidation is point-in-time only",
    "state may change immediately after inspection",
    "this result is not authorization",
    "this result is not authenticated approval or approval freshness",
    "this result does not evaluate subject, target, or procedure semantics",
    "this result does not evaluate PR304 evidence freshness",
    "this result does not create or link a receipt",
    "this result grants no execution eligibility and persists no preflight artifact",
    "PR313 execution was not invoked",
    "natural language cannot invoke this operation",
    "one exact aca_ artifact ID and all exact identity confirmations remain required",
)

PERMANENT_PERSISTED_CURRENT_STATE_WARNINGS = (
    "current-state revalidation is point-in-time only",
    "state may change immediately after inspection",
    "the persisted plan-link artifact is provenance only",
    "artifact persistence is not current-state freshness",
    "the full saved plan packet was not persisted",
    "the caller-supplied plan was validated for this invocation only",
    "this is not authenticated identity",
    "this is not approval freshness",
    "this is not authorization",
    "this is not PR304 evidence freshness",
    "this is not execution preflight",
    "this creates no receipt",
    "this links no receipt",
    "this grants no execution eligibility",
    "PR313 execution was not invoked",
    "natural language cannot invoke this operation",
    "one exact full acpl_ ID and both exact confirmations remain mandatory",
)

Status = Literal[
    "current_state_confirmed",
    "current_state_changed",
    "current_state_blocked",
    "unsupported",
    "invalid_current_state_input",
    "current_state_validation_failed",
]

PersistedStatus = Literal[
    "current_state_confirmed",
    "current_state_changed",
    "current_state_blocked",
    "unsupported",
    "invalid_current_state_input",
    "plan_link_artifact_not_available",
    "plan_link_artifact_confirmation_mismatch",
    "persisted_link_plan_mismatch",
    "current_state_validation_failed",
]


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class CurrentStateMapping(_FrozenModel):
    relative_source: str
    relative_destination: str
    planned_operation: str
    current_operation: str
    source_exists: bool
    destination_exists: bool
    source_hash_matches: bool
    destination_hash_matches: bool
    parent_state: str
    current_state_matched: bool
    reason_codes: tuple[str, ...] = ()


class ApprovedChangePlanCurrentStateResult(_FrozenModel):
    schema_version: Literal["1"] = CURRENT_STATE_SCHEMA_VERSION
    operation_type: Literal["approved_change_plan_current_state_revalidation"] = (
        "approved_change_plan_current_state_revalidation"
    )
    status: Status
    reason: str = ""
    requested_approval_artifact_id: str = ""
    approval_artifact_identity_sha256: str = ""
    subject_sha256: str = ""
    capability_binding_identity_sha256: str = ""
    capability_catalog_identity_sha256: str = ""
    lane_declaration_identity_sha256: str = ""
    lane_id: str = ""
    plan_sha256: str = ""
    plan_link_identity_sha256: str = ""
    plan_mode: str = ""
    recipe_id: str = ""
    plan_status: str = ""
    current_state_scope: Literal["exact_pr313_two_file_linked_plan_point_in_time"] = (
        CURRENT_STATE_SCOPE
    )
    staged_source_root_fingerprint: str = ""
    durable_runtime_root_fingerprint: str = ""
    mappings: tuple[CurrentStateMapping, ...] = ()
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_CURRENT_STATE_WARNINGS
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    current_state_revalidation_evaluated: bool = False
    current_state_matched: bool = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    approval_selected: Literal[False] = False
    approval_created: Literal[False] = False
    approval_persisted: Literal[False] = False
    contract_created: Literal[False] = False
    contract_persisted: Literal[False] = False
    capability_support_evaluated: bool = False
    capability_supported: bool = False
    capability_binding_evaluated: bool = False
    capability_bound: bool = False
    binding_persisted: Literal[False] = False
    plan_validated: bool = False
    plan_identity_confirmed: bool = False
    plan_link_evaluated: bool = False
    plan_linked: bool = False
    plan_link_persisted: Literal[False] = False
    plan_link_identity_confirmed: bool = False
    subject_semantic_compatibility_evaluated: Literal[False] = False
    target_compatibility_evaluated: Literal[False] = False
    procedure_compatibility_evaluated: Literal[False] = False
    evidence_compatibility_evaluated: Literal[False] = False
    pr304_evidence_freshness_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    file_create_executed: Literal[False] = False
    file_replace_executed: Literal[False] = False
    backup_created: Literal[False] = False
    atomic_replace_executed: Literal[False] = False
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


def _valid_confirmation(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _result(status: Status, **values: Any) -> ApprovedChangePlanCurrentStateResult:
    if "errors" in values:
        values["errors"] = tuple(sorted(set(values["errors"])))
    return ApprovedChangePlanCurrentStateResult(status=status, **values)


class PersistedPlanLinkCurrentStateResult(_FrozenModel):
    schema_version: Literal["1"] = CURRENT_STATE_SCHEMA_VERSION
    operation_type: Literal["persisted_plan_link_artifact_current_state_revalidation"] = (
        "persisted_plan_link_artifact_current_state_revalidation"
    )
    status: PersistedStatus
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
    current_state_scope: Literal["exact_pr313_two_file_linked_plan_point_in_time"] = (
        CURRENT_STATE_SCOPE
    )
    staged_source_root_fingerprint: str = ""
    durable_runtime_root_fingerprint: str = ""
    mappings: tuple[CurrentStateMapping, ...] = ()
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_PERSISTED_CURRENT_STATE_WARNINGS
    plan_validated: bool = False
    plan_identity_confirmed: bool = False
    plan_link_artifact_load_evaluated: bool = False
    plan_link_artifact_loaded: bool = False
    plan_link_artifact_identity_confirmed: bool = False
    plan_link_validated: bool = False
    plan_link_plan_comparison_evaluated: bool = False
    plan_link_plan_matched: bool = False
    current_state_revalidation_evaluated: bool = False
    current_state_matched: bool = False
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    plan_packet_persisted: Literal[False] = False
    current_state_persisted: Literal[False] = False
    approval_selected: Literal[False] = False
    approval_created: Literal[False] = False
    approval_persisted: Literal[False] = False
    contract_created: Literal[False] = False
    contract_persisted: Literal[False] = False
    authenticated_identity_evaluated: Literal[False] = False
    approval_freshness_evaluated: Literal[False] = False
    pr304_evidence_freshness_evaluated: Literal[False] = False
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


def _persisted_result(
    status: PersistedStatus, **values: Any
) -> PersistedPlanLinkCurrentStateResult:
    if "errors" in values:
        values["errors"] = tuple(sorted(set(values["errors"])))
    return PersistedPlanLinkCurrentStateResult(status=status, **values)


def _evaluate_current_state(
    plan_packet: Mapping[str, Any], staged_source_root: Path | str, durable_runtime_root: Path | str
) -> tuple[str, str, tuple[CurrentStateMapping, ...], bool, tuple[str, ...], str]:
    try:
        source_root = Path(staged_source_root)
        runtime_root = Path(durable_runtime_root)
    except Exception:
        return "invalid", "", (), False, ("governed root preparation failed safely",), ""
    try:
        source_fp = root_fingerprint(source_root) or ""
        runtime_fp = root_fingerprint(runtime_root) or ""
    except Exception:
        return "blocked", "", (), False, ("governed root preparation failed safely",), ""
    try:
        validators = load_validators()
        root_errors = validators.pr305_root_safe(runtime_root)
        if not source_root.is_absolute() or not source_root.is_dir():
            root_errors = [*root_errors, "staged source root is not an absolute directory"]
        if root_errors:
            return "root_blocked", source_fp, (), False, tuple(root_errors), runtime_fp
        fresh = [
            validators.pr305_operation(source_root, runtime_root, source, destination)
            for source, destination in ALLOWLIST
        ]
        saved = list(plan_packet["operations"])
        evaluations = [
            _evaluate_file(
                index=index,
                saved_operation=saved[index],
                fresh_operation=fresh[index],
                staged_source_root=source_root,
                durable_runtime_root=runtime_root,
                markers=validators.wrapper_markers,
                parent_evaluator=validators.pr305_destination_parent,
            )
            for index in range(len(ALLOWLIST))
        ]
    except Exception:
        return (
            "blocked",
            source_fp,
            (),
            False,
            ("governed filesystem inspection failed",),
            runtime_fp,
        )
    mappings = []
    for item in evaluations:
        matched = (
            not item.blockers
            and item.revalidated_operation == item.saved_operation
            and not item.narrowed_to_no_op
        )
        mappings.append(
            CurrentStateMapping(
                relative_source=item.relative_source,
                relative_destination=item.relative_destination,
                planned_operation=item.saved_operation,
                current_operation=item.revalidated_operation,
                source_exists=item.source_sha256 is not None,
                destination_exists=item.current_destination_sha256 is not None,
                source_hash_matches=item.source_sha256 == item.saved_source_sha256,
                destination_hash_matches=(
                    item.current_destination_sha256 == item.saved_destination_sha256
                    if item.saved_destination_sha256 is not None
                    else item.current_destination_sha256 is None
                ),
                parent_state=str(item.parent.get("revalidated_state", "blocked")),
                current_state_matched=matched,
                reason_codes=tuple(
                    sorted(set("current_state_rule_blocked" for _ in item.blockers))
                ),
            )
        )
    matched = all(item.current_state_matched for item in mappings)
    return "ok", source_fp, tuple(mappings), matched, (), runtime_fp


def _plan_link_plan_errors(
    link: Any, plan_packet: Mapping[str, Any], plan_validation: Any, plan_sha: str
) -> list[str]:
    errors: list[str] = []
    if not hmac.compare_digest(link.plan_sha256, plan_sha):
        errors.append("plan_sha256 mismatch")
    if link.capability_id != WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID:
        errors.append("capability_id mismatch")
    if link.lane_id != WINDOWS_RUNTIME_RECONCILE_LANE_ID:
        errors.append("lane_id mismatch")
    if link.plan_mode != plan_validation.plan_mode:
        errors.append("plan_mode mismatch")
    if link.plan_recipe_id != plan_validation.plan_recipe_id:
        errors.append("recipe_id mismatch")
    if link.plan_status != plan_validation.plan_status:
        errors.append("plan_status mismatch")
    if (
        link.destination_parent_contract_version
        != plan_validation.destination_parent_contract_version
    ):
        errors.append("destination_parent_contract_version mismatch")
    operations = list(plan_packet.get("operations", ())) if isinstance(plan_packet, Mapping) else []
    scope = [
        (op.get("allowlist_source"), op.get("allowlist_destination"), op.get("operation"))
        for op in operations
        if isinstance(op, Mapping)
    ]
    expected = [
        (
            src,
            dst,
            operations[index].get("operation")
            if index < len(operations) and isinstance(operations[index], Mapping)
            else None,
        )
        for index, (src, dst) in enumerate(ALLOWLIST)
    ]
    if scope != expected:
        errors.append("fixed two-file allowlist or operation ordering mismatch")
    return errors


def revalidate_persisted_plan_link_artifact_current_state(
    plan_link_artifact_id: str,
    plan_packet: Mapping[str, Any],
    *,
    data_dir: Path | str,
    staged_source_root: Path | str,
    durable_runtime_root: Path | str,
    confirm_plan_link_artifact_identity_sha256: str,
    confirm_plan_sha256: str,
) -> PersistedPlanLinkCurrentStateResult:
    """Revalidate one exact persisted PR337 plan-link artifact against one plan."""
    requested = plan_link_artifact_id if isinstance(plan_link_artifact_id, str) else ""
    base: dict[str, Any] = {"requested_plan_link_artifact_id": requested}
    if (
        not isinstance(plan_link_artifact_id, str)
        or not plan_link_artifact_id.startswith("acpl_")
        or len(plan_link_artifact_id) != 69
        or not _valid_confirmation(plan_link_artifact_id[5:])
    ):
        return _persisted_result(
            "invalid_current_state_input",
            reason="plan-link artifact ID must be acpl_ plus 64 lowercase hexadecimal characters",
            errors=["invalid plan-link artifact ID"],
            **base,
        )
    if not _valid_confirmation(confirm_plan_link_artifact_identity_sha256):
        return _persisted_result(
            "invalid_current_state_input",
            reason="artifact identity confirmation must be an exact lowercase SHA-256 value",
            **base,
        )
    if not _valid_confirmation(confirm_plan_sha256):
        return _persisted_result(
            "invalid_current_state_input",
            reason="plan identity confirmation must be an exact lowercase SHA-256 value",
            **base,
        )
    try:
        plan_validation = validate_saved_windows_runtime_reconcile_plan_packet(plan_packet)
    except Exception:
        return _persisted_result(
            "invalid_current_state_input", reason="plan validation failed safely", **base
        )
    base.update(
        plan_validated=plan_validation.status == "plan_packet_accepted",
        plan_status=plan_validation.plan_status,
        plan_mode=plan_validation.plan_mode,
        recipe_id=plan_validation.plan_recipe_id,
    )
    if (
        plan_validation.status != "plan_packet_accepted"
        or plan_validation.plan_status not in ACCEPTED_PLAN_STATUSES
    ):
        return _persisted_result(
            "invalid_current_state_input",
            reason="plan packet is not accepted",
            errors=plan_validation.errors,
            **base,
        )
    plan_sha = canonical_plan_sha256(plan_packet)
    base.update(plan_sha256=plan_sha, confirmed_plan_sha256=confirm_plan_sha256)
    if not hmac.compare_digest(confirm_plan_sha256, plan_sha):
        return _persisted_result(
            "invalid_current_state_input", reason="plan identity confirmation mismatch", **base
        )
    base["plan_identity_confirmed"] = True

    load = load_persisted_approved_change_plan_link_artifact(data_dir, plan_link_artifact_id)
    base["plan_link_artifact_load_evaluated"] = True
    if load.status != "plan_link_artifact_loaded" or load.artifact is None:
        return _persisted_result(
            "plan_link_artifact_not_available",
            reason="persisted plan-link artifact was not loaded",
            errors=load.errors,
            **base,
        )
    artifact = load.artifact
    base.update(
        plan_link_artifact_loaded=True,
        plan_link_artifact_identity_sha256=load.artifact_identity_sha256,
        approval_artifact_id=artifact.approval_artifact_id,
        approval_artifact_identity_sha256=artifact.approval_artifact_identity_sha256,
        subject_sha256=artifact.subject_sha256,
        capability_binding_identity_sha256=artifact.capability_binding_identity_sha256,
        capability_catalog_identity_sha256=artifact.capability_catalog_identity_sha256,
        lane_declaration_identity_sha256=artifact.lane_declaration_identity_sha256,
        capability_id=artifact.capability_id,
        lane_id=artifact.lane_id,
        plan_link_identity_sha256=artifact.plan_link_identity_sha256,
    )
    if not hmac.compare_digest(
        confirm_plan_link_artifact_identity_sha256, load.artifact_identity_sha256
    ):
        return _persisted_result(
            "plan_link_artifact_confirmation_mismatch",
            reason="artifact identity confirmation mismatch",
            **base,
        )
    base["plan_link_artifact_identity_confirmed"] = True
    if (artifact_id := load.artifact_id) and not hmac.compare_digest(
        artifact_id, plan_link_artifact_id
    ):
        return _persisted_result(
            "plan_link_artifact_not_available", reason="loaded artifact ID mismatch", **base
        )
    link_validation = validate_approved_change_plan_link(artifact.plan_link)
    base["plan_link_validated"] = link_validation.link_valid
    if not link_validation.link_valid:
        return _persisted_result(
            "current_state_validation_failed",
            reason="embedded plan link failed maintained validation",
            errors=link_validation.errors,
            **base,
        )
    base["plan_link_plan_comparison_evaluated"] = True
    comparison_errors = _plan_link_plan_errors(
        artifact.plan_link, plan_packet, plan_validation, plan_sha
    )
    if not hmac.compare_digest(artifact.plan_sha256, plan_sha) or not hmac.compare_digest(
        artifact.plan_link.plan_sha256, plan_sha
    ):
        comparison_errors.append("persisted artifact plan_sha256 mismatch")
    if comparison_errors:
        return _persisted_result(
            "persisted_link_plan_mismatch",
            reason="persisted plan link does not match supplied plan",
            errors=comparison_errors,
            **base,
        )
    base["plan_link_plan_matched"] = True
    if platform.system().lower() != "windows":
        return _persisted_result(
            "unsupported", reason="current-state revalidation is supported only on Windows", **base
        )
    state, source_fp, mappings, matched, errors, runtime_fp = _evaluate_current_state(
        plan_packet, staged_source_root, durable_runtime_root
    )
    base.update(
        staged_source_root_fingerprint=source_fp, durable_runtime_root_fingerprint=runtime_fp
    )
    if state == "invalid":
        return _persisted_result(
            "invalid_current_state_input",
            reason="governed root input is invalid",
            errors=errors,
            **base,
        )
    if state in {"blocked", "root_blocked"}:
        return _persisted_result(
            "current_state_blocked",
            reason="complete current-state inspection was not possible"
            if state == "blocked"
            else "a governed root is invalid",
            errors=errors,
            **base,
        )
    return _persisted_result(
        "current_state_confirmed" if matched else "current_state_changed",
        reason="persisted linked plan assumptions matched at inspection time"
        if matched
        else "persisted linked plan assumptions changed",
        mappings=mappings,
        current_state_revalidation_evaluated=True,
        current_state_matched=matched,
        **base,
    )


def revalidate_linked_windows_runtime_reconcile_plan_current_state(
    approval_artifact_id: str,
    plan_packet: Mapping[str, Any],
    *,
    data_dir: Path | str,
    staged_source_root: Path | str,
    durable_runtime_root: Path | str,
    confirm_capability_catalog_identity_sha256: str,
    confirm_lane_declaration_identity_sha256: str,
    confirm_plan_sha256: str,
    confirm_plan_link_identity_sha256: str,
) -> ApprovedChangePlanCurrentStateResult:
    """Answer whether one exact linked plan still matches its governed files."""
    requested = approval_artifact_id if isinstance(approval_artifact_id, str) else ""
    try:
        validation = validate_saved_windows_runtime_reconcile_plan_packet(plan_packet)
    except Exception:
        return _result("invalid_current_state_input", reason="plan validation failed safely")
    base = {
        "requested_approval_artifact_id": requested,
        "plan_validated": validation.status == "plan_packet_accepted",
        "plan_status": validation.plan_status,
        "plan_mode": validation.plan_mode,
        "recipe_id": validation.plan_recipe_id,
    }
    if (
        validation.status != "plan_packet_accepted"
        or validation.plan_status not in ACCEPTED_PLAN_STATUSES
    ):
        return _result(
            "invalid_current_state_input",
            reason="plan packet is not accepted",
            errors=validation.errors,
            **base,
        )
    plan_sha = canonical_plan_sha256(plan_packet)
    base["plan_sha256"] = plan_sha
    confirmations = (
        confirm_capability_catalog_identity_sha256,
        confirm_lane_declaration_identity_sha256,
        confirm_plan_sha256,
        confirm_plan_link_identity_sha256,
    )
    if not all(_valid_confirmation(value) for value in confirmations):
        return _result(
            "invalid_current_state_input",
            reason="all confirmations must be exact lowercase SHA-256 values",
            **base,
        )
    if not hmac.compare_digest(confirm_plan_sha256, plan_sha):
        return _result(
            "invalid_current_state_input", reason="plan identity confirmation mismatch", **base
        )
    base["plan_identity_confirmed"] = True
    catalog_sha = compute_approved_change_capability_support_catalog_sha256(
        maintained_approved_change_capability_support_catalog()
    )
    lane_sha = compute_capability_lane_declaration_sha256(
        maintained_windows_runtime_reconcile_lane_declaration()
    )
    if not hmac.compare_digest(confirm_capability_catalog_identity_sha256, catalog_sha):
        return _result(
            "invalid_current_state_input", reason="catalog identity confirmation mismatch", **base
        )
    if not hmac.compare_digest(confirm_lane_declaration_identity_sha256, lane_sha):
        return _result(
            "invalid_current_state_input", reason="lane identity confirmation mismatch", **base
        )
    link_result = link_persisted_approved_change_to_windows_runtime_reconcile_plan(
        approval_artifact_id,
        plan_packet,
        data_dir=data_dir,
        confirm_capability_catalog_identity_sha256=confirm_capability_catalog_identity_sha256,
        confirm_lane_declaration_identity_sha256=confirm_lane_declaration_identity_sha256,
        confirm_plan_sha256=confirm_plan_sha256,
    )
    base.update(
        capability_support_evaluated=link_result.capability_support_evaluated,
        capability_supported=link_result.capability_supported,
        capability_binding_evaluated=link_result.capability_binding_evaluated,
        capability_bound=link_result.capability_bound,
        plan_link_evaluated=True,
        plan_linked=link_result.plan_linked,
    )
    if not link_result.link_complete or link_result.plan_link is None:
        return _result(
            "current_state_blocked",
            reason="maintained plan link was not complete",
            errors=link_result.errors,
            **base,
        )
    link_sha = compute_approved_change_plan_link_sha256(link_result.plan_link)
    base.update(
        approval_artifact_identity_sha256=link_result.plan_link.approval_artifact_identity_sha256,
        subject_sha256=link_result.plan_link.subject_sha256,
        capability_binding_identity_sha256=link_result.plan_link.capability_binding_identity_sha256,
        capability_catalog_identity_sha256=catalog_sha,
        lane_declaration_identity_sha256=lane_sha,
        lane_id=link_result.plan_link.lane_id,
        plan_link_identity_sha256=link_sha,
    )
    if not hmac.compare_digest(confirm_plan_link_identity_sha256, link_sha):
        return _result(
            "invalid_current_state_input", reason="plan-link identity confirmation mismatch", **base
        )
    base["plan_link_identity_confirmed"] = True
    if platform.system().lower() != "windows":
        return _result(
            "unsupported", reason="current-state revalidation is supported only on Windows", **base
        )
    state, source_fp, mappings, matched, errors, runtime_fp = _evaluate_current_state(
        plan_packet, staged_source_root, durable_runtime_root
    )
    base.update(
        staged_source_root_fingerprint=source_fp,
        durable_runtime_root_fingerprint=runtime_fp,
    )
    if state == "invalid":
        return _result(
            "invalid_current_state_input",
            reason="governed root input is invalid",
            errors=errors,
            **base,
        )
    if state in {"blocked", "root_blocked"}:
        return _result(
            "current_state_blocked",
            reason="complete current-state inspection was not possible"
            if state == "blocked"
            else "a governed root is invalid",
            errors=errors,
            **base,
        )
    return _result(
        "current_state_confirmed" if matched else "current_state_changed",
        reason="linked plan assumptions matched at inspection time"
        if matched
        else "linked plan assumptions changed",
        mappings=mappings,
        current_state_revalidation_evaluated=True,
        current_state_matched=matched,
        **base,
    )
