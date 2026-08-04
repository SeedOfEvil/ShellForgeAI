"""Immutable persistence for exact PR323 approved-change plan links (PR337).

This module persists provenance only.  It deliberately has no inventory,
selection, current-state, authorization, preflight, receipt, or execution
surface.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from shellforgeai.core.approved_change_approval_persistence import (
    PERSISTED_DIRECTORY_MODE,
    PERSISTED_FILE_MODE,
    AtomicNoReplaceOutcome,
    CleanupStatus,
    _check_child_containment,
    _fsync_directory,
    _is_reparse_stat,
    _is_symlink_or_reparse,
    _path_exists_without_following,
    _read_bounded,
    _validate_data_dir,
    atomic_no_replace_approval_directory_publish,
)
from shellforgeai.core.approved_change_plan_link import (
    ApprovedChangePlanLinkResult,
    ApprovedChangeWindowsRuntimeReconcilePlanLink,
    canonical_approved_change_plan_link_payload,
    compute_approved_change_plan_link_sha256,
    link_persisted_approved_change_to_windows_runtime_reconcile_plan,
    validate_approved_change_plan_link,
)

PLAN_LINK_ARTIFACT_SCHEMA_VERSION = "1"
PLAN_LINK_ARTIFACT_TYPE = "approved_change_plan_link_artifact"
APPROVED_CHANGE_PLAN_LINKS_DIRNAME = "approved_change_plan_links"
APPROVED_CHANGE_PLAN_LINK_FILENAME = "approved-change-plan-link.json"
PLAN_LINK_ARTIFACT_ID_PREFIX = "acpl_"
MAX_PERSISTED_PLAN_LINK_ARTIFACT_BYTES = 1_048_576
TEMPORARY_DIRECTORY_PREFIX = ".pending-"

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^acpl_[0-9a-f]{64}$")

PERMANENT_PLAN_LINK_ARTIFACT_WARNINGS = (
    "this artifact stores an exact approved-change-to-plan identity association only",
    "persistence is not authentication",
    "persistence is not authorization",
    "persistence is not approval freshness",
    "persisted approved_by metadata remains self-asserted unless a separate "
    "authenticated-identity mechanism exists",
    "the artifact does not validate subject free-text semantics",
    "the artifact does not validate target semantics",
    "the artifact does not validate procedure semantics",
    "the artifact does not evaluate PR304 evidence freshness",
    "the artifact does not inspect current staged-source or durable-runtime state",
    "the artifact does not persist or evaluate PR328 current-state observations",
    "the artifact is not an execution preflight",
    "the artifact does not prove preconditions remain true",
    "the artifact creates or links no receipt",
    "the artifact grants no execution eligibility or availability",
    "PR313 execution was not invoked",
    "natural language cannot publish or execute this artifact",
    "one exact full aca_ approval-artifact ID and exact confirmations remain required",
    "no inventory, latest, current, or automatic selection was used",
    "the full saved plan packet was not persisted",
)


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class _PlanLinkArtifactSafetyLedger(_FrozenModel):
    """Typed permanent PR337 non-authority and non-action ledger."""

    plan_packet_persisted: Literal[False] = False
    plan_packet_freshly_revalidated: Literal[False] = False
    authenticated_identity_evaluated: Literal[False] = False
    approval_freshness_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    current_state_revalidation_evaluated: Literal[False] = False
    pr304_evidence_freshness_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = "not_executed"
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


class ApprovedChangePlanLinkArtifact(_FrozenModel):
    """The non-circular canonical payload persisted by PR337."""

    schema_version: Literal["1"] = PLAN_LINK_ARTIFACT_SCHEMA_VERSION
    artifact_type: Literal["approved_change_plan_link_artifact"] = PLAN_LINK_ARTIFACT_TYPE
    approval_artifact_id: str
    approval_artifact_identity_sha256: str
    subject_sha256: str
    capability_binding_identity_sha256: str
    capability_catalog_identity_sha256: str
    lane_declaration_identity_sha256: str
    capability_id: str
    lane_id: str
    plan_sha256: str
    plan_link_identity_sha256: str
    plan_link: ApprovedChangeWindowsRuntimeReconcilePlanLink


def canonical_approved_change_plan_link_artifact_payload(
    artifact: ApprovedChangePlanLinkArtifact | Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(artifact, ApprovedChangePlanLinkArtifact):
        artifact = ApprovedChangePlanLinkArtifact.model_validate(artifact)
    payload = artifact.model_dump(mode="python")
    payload["plan_link"] = canonical_approved_change_plan_link_payload(artifact.plan_link)
    return {key: payload[key] for key in sorted(payload)}


def canonical_approved_change_plan_link_artifact_json(
    artifact: ApprovedChangePlanLinkArtifact | Mapping[str, Any],
) -> str:
    return json.dumps(
        canonical_approved_change_plan_link_artifact_payload(artifact),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def canonical_approved_change_plan_link_artifact_bytes(
    artifact: ApprovedChangePlanLinkArtifact | Mapping[str, Any],
) -> bytes:
    return canonical_approved_change_plan_link_artifact_json(artifact).encode("utf-8")


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _load_strict_json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_strict_json_object)


def compute_approved_change_plan_link_artifact_identity_sha256(
    artifact: ApprovedChangePlanLinkArtifact | Mapping[str, Any],
) -> str:
    return hashlib.sha256(canonical_approved_change_plan_link_artifact_bytes(artifact)).hexdigest()


def derive_approved_change_plan_link_artifact_id(identity_sha256: str) -> str:
    if not isinstance(identity_sha256, str) or not _SHA_RE.fullmatch(identity_sha256):
        raise ValueError("artifact identity must be exactly 64 lowercase hexadecimal characters")
    return f"{PLAN_LINK_ARTIFACT_ID_PREFIX}{identity_sha256}"


class ApprovedChangePlanLinkArtifactValidationResult(_PlanLinkArtifactSafetyLedger):
    status: Literal[
        "plan_link_artifact_valid",
        "plan_link_artifact_invalid",
        "invalid_plan_link_artifact_validation_input",
    ]
    artifact_valid: bool = False
    artifact_identity_sha256: str = ""
    artifact_id: str = ""
    canonical_byte_length: int = 0
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_PLAN_LINK_ARTIFACT_WARNINGS
    read_only: Literal[True] = True
    filesystem_accessed: Literal[False] = False
    mutation_performed: Literal[False] = False


def validate_approved_change_plan_link_artifact(
    artifact: ApprovedChangePlanLinkArtifact | Mapping[str, Any],
    *,
    artifact_identity_sha256: str | None = None,
    artifact_id: str | None = None,
) -> ApprovedChangePlanLinkArtifactValidationResult:
    """Purely revalidate the embedded link and every duplicated identity."""
    if not isinstance(artifact, (ApprovedChangePlanLinkArtifact, Mapping)):
        return ApprovedChangePlanLinkArtifactValidationResult(
            status="invalid_plan_link_artifact_validation_input",
            errors=("artifact must be the maintained model or a mapping",),
        )
    try:
        value = (
            artifact
            if isinstance(artifact, ApprovedChangePlanLinkArtifact)
            else ApprovedChangePlanLinkArtifact.model_validate(artifact)
        )
    except Exception as exc:
        return ApprovedChangePlanLinkArtifactValidationResult(
            status="plan_link_artifact_invalid", errors=(str(exc),)
        )
    errors: list[str] = []
    link_validation = validate_approved_change_plan_link(value.plan_link)
    if not link_validation.link_valid:
        errors.extend(
            ("embedded plan link failed maintained PR323 validation", *link_validation.errors)
        )
    link_identity = compute_approved_change_plan_link_sha256(value.plan_link)
    pairs = (
        (value.approval_artifact_id, value.plan_link.approval_artifact_id, "approval_artifact_id"),
        (
            value.approval_artifact_identity_sha256,
            value.plan_link.approval_artifact_identity_sha256,
            "approval_artifact_identity_sha256",
        ),
        (value.subject_sha256, value.plan_link.subject_sha256, "subject_sha256"),
        (
            value.capability_binding_identity_sha256,
            value.plan_link.capability_binding_identity_sha256,
            "capability_binding_identity_sha256",
        ),
        (
            value.capability_catalog_identity_sha256,
            value.plan_link.capability_catalog_identity_sha256,
            "capability_catalog_identity_sha256",
        ),
        (
            value.lane_declaration_identity_sha256,
            value.plan_link.lane_declaration_identity_sha256,
            "lane_declaration_identity_sha256",
        ),
        (value.capability_id, value.plan_link.capability_id, "capability_id"),
        (value.lane_id, value.plan_link.lane_id, "lane_id"),
        (value.plan_sha256, value.plan_link.plan_sha256, "plan_sha256"),
        (value.plan_link_identity_sha256, link_identity, "plan_link_identity_sha256"),
    )
    for actual, expected, label in pairs:
        if not hmac.compare_digest(actual, expected):
            errors.append(f"{label} does not match the embedded PR323 plan link")
    for name in (
        "approval_artifact_identity_sha256",
        "subject_sha256",
        "capability_binding_identity_sha256",
        "capability_catalog_identity_sha256",
        "lane_declaration_identity_sha256",
        "plan_sha256",
        "plan_link_identity_sha256",
    ):
        if not _SHA_RE.fullmatch(getattr(value, name)):
            errors.append(f"{name} must be exactly 64 lowercase hexadecimal characters")
    identity = compute_approved_change_plan_link_artifact_identity_sha256(value)
    derived_id = f"acpl_{identity}"
    if artifact_identity_sha256 is not None:
        if not isinstance(artifact_identity_sha256, str) or not _SHA_RE.fullmatch(
            artifact_identity_sha256
        ):
            errors.append(
                "artifact_identity_sha256 must be exactly 64 lowercase hexadecimal characters"
            )
        elif not hmac.compare_digest(identity, artifact_identity_sha256):
            errors.append("artifact identity does not match canonical artifact bytes")
    if artifact_id is not None:
        if not isinstance(artifact_id, str) or not _ID_RE.fullmatch(artifact_id):
            errors.append("artifact_id must be acpl_ plus 64 lowercase hexadecimal characters")
        elif not hmac.compare_digest(derived_id, artifact_id):
            errors.append("artifact ID does not match canonical artifact identity")
    errors = sorted(set(errors))
    return ApprovedChangePlanLinkArtifactValidationResult(
        status="plan_link_artifact_invalid" if errors else "plan_link_artifact_valid",
        artifact_valid=not errors,
        artifact_identity_sha256=identity,
        artifact_id=derived_id,
        canonical_byte_length=len(canonical_approved_change_plan_link_artifact_bytes(value)),
        errors=tuple(errors),
    )


class ApprovedChangePlanLinkArtifactConstructionResult(_PlanLinkArtifactSafetyLedger):
    status: Literal[
        "plan_link_artifact_constructed",
        "plan_link_not_available",
        "plan_link_artifact_validation_failed",
    ]
    artifact: ApprovedChangePlanLinkArtifact | None = None
    artifact_identity_sha256: str = ""
    artifact_id: str = ""
    canonical_bytes: bytes = b""
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_PLAN_LINK_ARTIFACT_WARNINGS
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False


def construct_approved_change_plan_link_artifact(
    source: ApprovedChangePlanLinkResult | ApprovedChangeWindowsRuntimeReconcilePlanLink,
) -> ApprovedChangePlanLinkArtifactConstructionResult:
    link = source.plan_link if isinstance(source, ApprovedChangePlanLinkResult) else source
    if isinstance(source, ApprovedChangePlanLinkResult) and (
        source.status != "plan_link_constructed" or not source.link_complete or link is None
    ):
        return ApprovedChangePlanLinkArtifactConstructionResult(status="plan_link_not_available")
    validation = validate_approved_change_plan_link(link)
    if link is None or not validation.link_valid:
        return ApprovedChangePlanLinkArtifactConstructionResult(
            status="plan_link_artifact_validation_failed", errors=validation.errors
        )
    link_identity = compute_approved_change_plan_link_sha256(link)
    if isinstance(source, ApprovedChangePlanLinkResult) and not hmac.compare_digest(
        source.plan_link_identity_sha256, link_identity
    ):
        return ApprovedChangePlanLinkArtifactConstructionResult(
            status="plan_link_artifact_validation_failed",
            errors=("PR323 result plan-link identity does not match its canonical link",),
        )
    artifact = ApprovedChangePlanLinkArtifact(
        approval_artifact_id=link.approval_artifact_id,
        approval_artifact_identity_sha256=link.approval_artifact_identity_sha256,
        subject_sha256=link.subject_sha256,
        capability_binding_identity_sha256=link.capability_binding_identity_sha256,
        capability_catalog_identity_sha256=link.capability_catalog_identity_sha256,
        lane_declaration_identity_sha256=link.lane_declaration_identity_sha256,
        capability_id=link.capability_id,
        lane_id=link.lane_id,
        plan_sha256=link.plan_sha256,
        plan_link_identity_sha256=link_identity,
        plan_link=link,
    )
    checked = validate_approved_change_plan_link_artifact(artifact)
    if not checked.artifact_valid:
        return ApprovedChangePlanLinkArtifactConstructionResult(
            status="plan_link_artifact_validation_failed", errors=checked.errors
        )
    return ApprovedChangePlanLinkArtifactConstructionResult(
        status="plan_link_artifact_constructed",
        artifact=artifact,
        artifact_identity_sha256=checked.artifact_identity_sha256,
        artifact_id=checked.artifact_id,
        canonical_bytes=canonical_approved_change_plan_link_artifact_bytes(artifact),
    )


class ApprovedChangePlanLinkArtifactLoadResult(_PlanLinkArtifactSafetyLedger):
    status: Literal[
        "plan_link_artifact_loaded",
        "plan_link_artifact_not_found",
        "plan_link_artifact_invalid",
        "invalid_plan_link_artifact_id",
        "plan_link_artifact_load_blocked",
    ]
    artifact_id: str = ""
    artifact_identity_sha256: str = ""
    artifact: ApprovedChangePlanLinkArtifact | None = None
    total_bytes_read: int = 0
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_PLAN_LINK_ARTIFACT_WARNINGS
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    filesystem_accessed: bool = False
    plan_link_artifact_persisted: bool = False


def _load(status: str, **kwargs: Any) -> ApprovedChangePlanLinkArtifactLoadResult:
    if "errors" in kwargs:
        kwargs["errors"] = tuple(sorted(set(kwargs["errors"])))
    return ApprovedChangePlanLinkArtifactLoadResult(status=status, **kwargs)


def load_persisted_approved_change_plan_link_artifact(
    data_dir: Path | str, artifact_id: str
) -> ApprovedChangePlanLinkArtifactLoadResult:
    if not isinstance(artifact_id, str) or not _ID_RE.fullmatch(artifact_id):
        return _load(
            "invalid_plan_link_artifact_id",
            errors=["artifact ID must be acpl_ plus 64 lowercase hexadecimal characters"],
        )
    checked = _validate_data_dir(data_dir)
    if checked.path is None:
        return _load(
            "plan_link_artifact_load_blocked",
            artifact_id=artifact_id,
            errors=list(checked.errors),
            filesystem_accessed=checked.filesystem_accessed,
        )
    root = checked.path / APPROVED_CHANGE_PLAN_LINKS_DIRNAME
    if root.parent != checked.path or root.name != APPROVED_CHANGE_PLAN_LINKS_DIRNAME:
        return _load(
            "plan_link_artifact_load_blocked",
            artifact_id=artifact_id,
            errors=["unsafe fixed persistence root"],
            filesystem_accessed=True,
        )
    if not _path_exists_without_following(root):
        return _load(
            "plan_link_artifact_not_found", artifact_id=artifact_id, filesystem_accessed=True
        )
    if _is_symlink_or_reparse(root) or not stat.S_ISDIR(os.lstat(root).st_mode):
        return _load(
            "plan_link_artifact_load_blocked",
            artifact_id=artifact_id,
            errors=["persistence root must be a real directory"],
            filesystem_accessed=True,
        )
    directory = root / artifact_id
    if _check_child_containment(root, directory, "plan-link artifact directory"):
        return _load(
            "plan_link_artifact_load_blocked",
            artifact_id=artifact_id,
            errors=["unsafe artifact directory"],
            filesystem_accessed=True,
        )
    if not _path_exists_without_following(directory):
        return _load(
            "plan_link_artifact_not_found", artifact_id=artifact_id, filesystem_accessed=True
        )
    if _is_symlink_or_reparse(directory) or not stat.S_ISDIR(os.lstat(directory).st_mode):
        return _load(
            "plan_link_artifact_invalid",
            artifact_id=artifact_id,
            errors=["artifact directory must be a real directory"],
            filesystem_accessed=True,
        )
    try:
        entries = sorted(entry.name for entry in os.scandir(directory))
    except OSError as exc:
        return _load(
            "plan_link_artifact_load_blocked",
            artifact_id=artifact_id,
            errors=[f"artifact directory cannot be inspected: {exc}"],
            filesystem_accessed=True,
        )
    if entries != [APPROVED_CHANGE_PLAN_LINK_FILENAME]:
        return _load(
            "plan_link_artifact_invalid",
            artifact_id=artifact_id,
            errors=["artifact directory must contain exactly the fixed artifact file"],
            filesystem_accessed=True,
        )
    path = directory / APPROVED_CHANGE_PLAN_LINK_FILENAME
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or _is_reparse_stat(info, path):
            raise OSError("artifact file must be a real regular file")
        if info.st_size > MAX_PERSISTED_PLAN_LINK_ARTIFACT_BYTES:
            raise OSError("artifact file exceeds the bounded size limit")
        raw = _read_bounded(path, info.st_size)
        payload = _load_strict_json(raw)
        artifact = ApprovedChangePlanLinkArtifact.model_validate(payload)
    except Exception as exc:
        return _load(
            "plan_link_artifact_invalid",
            artifact_id=artifact_id,
            errors=[f"artifact could not be loaded: {exc}"],
            filesystem_accessed=True,
        )
    validation = validate_approved_change_plan_link_artifact(artifact, artifact_id=artifact_id)
    canonical = canonical_approved_change_plan_link_artifact_bytes(artifact)
    errors = list(validation.errors)
    if raw != canonical:
        errors.append("persisted artifact bytes are not canonical")
    if errors:
        return _load(
            "plan_link_artifact_invalid",
            artifact_id=artifact_id,
            artifact_identity_sha256=validation.artifact_identity_sha256,
            errors=errors,
            total_bytes_read=len(raw),
            filesystem_accessed=True,
        )
    return _load(
        "plan_link_artifact_loaded",
        artifact_id=artifact_id,
        artifact_identity_sha256=validation.artifact_identity_sha256,
        artifact=artifact,
        total_bytes_read=len(raw),
        filesystem_accessed=True,
        plan_link_artifact_persisted=True,
    )


class ApprovedChangePlanLinkArtifactPublicationResult(_PlanLinkArtifactSafetyLedger):
    status: Literal[
        "plan_link_artifact_published",
        "plan_link_artifact_already_present",
        "plan_link_artifact_conflict",
        "plan_link_not_available",
        "artifact_confirmation_mismatch",
        "invalid_plan_link_artifact_input",
        "plan_link_artifact_publication_blocked",
        "plan_link_artifact_validation_failed",
    ]
    artifact_id: str = ""
    artifact_identity_sha256: str = ""
    confirmation_matched: bool = False
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_PLAN_LINK_ARTIFACT_WARNINGS
    read_only: bool = True
    mutation_performed: bool = False
    filesystem_accessed: bool = False
    artifact_write_performed: bool = False
    publication_performed: bool = False
    persistence_performed: bool = False
    existing_identical_no_op: bool = False
    plan_validated: bool = False
    plan_identity_confirmed: bool = False
    plan_link_evaluated: bool = False
    plan_linked: bool = False
    plan_link_artifact_persisted: bool = False
    approval_selected: Literal[False] = False
    approval_created: Literal[False] = False
    approval_persisted: Literal[False] = False
    temporary_directory_created: bool = False
    temporary_directory_cleaned: bool = False
    cleanup_status: CleanupStatus = "not_required"
    residual_temporary_directory: str = ""
    atomic_publish_outcome: Literal[
        "not_attempted", "published", "destination_exists", "rejected", "unsupported", "failed"
    ] = "not_attempted"


def _published(status: str, **kwargs: Any) -> ApprovedChangePlanLinkArtifactPublicationResult:
    if "errors" in kwargs:
        kwargs["errors"] = tuple(sorted(set(kwargs["errors"])))
    return ApprovedChangePlanLinkArtifactPublicationResult(status=status, **kwargs)


def _cleanup_invocation_temporary_directory(
    temporary: Path | None, prepared_file: Path | None
) -> tuple[CleanupStatus, bool, str, list[str]]:
    """Clean only this invocation's unpublished PR337 temporary directory."""
    if temporary is None:
        return "not_required", False, "", []
    residual = temporary.name
    errors: list[str] = []
    try:
        info = os.lstat(temporary)
    except OSError:
        return "completed", True, "", []
    if not stat.S_ISDIR(info.st_mode) or _is_reparse_stat(info, temporary):
        return (
            "incomplete",
            False,
            residual,
            ["the temporary path is no longer a real directory owned by this invocation"],
        )
    if prepared_file is not None and prepared_file.parent == temporary:
        try:
            finfo = os.lstat(prepared_file)
            if stat.S_ISREG(finfo.st_mode) and not _is_reparse_stat(finfo, prepared_file):
                os.unlink(prepared_file)
            else:
                errors.append("the tracked temporary file is no longer a real regular file")
        except FileNotFoundError:
            pass
        except OSError as exc:
            errors.append(f"the tracked temporary file could not be removed: {exc}")
    try:
        remaining = sorted(entry.name for entry in os.scandir(temporary))
    except OSError as exc:
        return (
            "incomplete",
            False,
            residual,
            [
                *errors,
                f"the temporary directory could not be listed: {exc}",
            ],
        )
    if remaining:
        return (
            "incomplete",
            False,
            residual,
            [
                *errors,
                "the temporary directory holds entries this invocation did not create",
            ],
        )
    try:
        os.rmdir(temporary)
    except OSError as exc:
        return (
            "incomplete",
            False,
            residual,
            [
                *errors,
                f"the empty temporary directory could not be removed: {exc}",
            ],
        )
    return (
        ("incomplete" if errors else "completed"),
        not errors,
        "" if not errors else residual,
        errors,
    )


def publish_approved_change_plan_link_artifact(
    approval_artifact_id: str,
    plan_packet: Mapping[str, Any],
    *,
    data_dir: Path | str,
    confirm_capability_catalog_identity_sha256: str,
    confirm_lane_declaration_identity_sha256: str,
    confirm_plan_sha256: str,
    confirm_plan_link_artifact_identity_sha256: str,
) -> ApprovedChangePlanLinkArtifactPublicationResult:
    """Construct PR323 exactly once, confirm PR337, then atomically publish."""
    temporary: Path | None = None
    path: Path | None = None
    temporary_created = False
    atomic_outcome: AtomicNoReplaceOutcome | None = None
    link_result = link_persisted_approved_change_to_windows_runtime_reconcile_plan(
        approval_artifact_id,
        plan_packet,
        data_dir=data_dir,
        confirm_capability_catalog_identity_sha256=confirm_capability_catalog_identity_sha256,
        confirm_lane_declaration_identity_sha256=confirm_lane_declaration_identity_sha256,
        confirm_plan_sha256=confirm_plan_sha256,
    )
    if link_result.status != "plan_link_constructed":
        return _published(
            "plan_link_not_available",
            errors=list(link_result.errors),
            filesystem_accessed=link_result.filesystem_accessed,
            plan_validated=link_result.plan_validated,
            plan_identity_confirmed=link_result.plan_identity_confirmed,
            plan_link_evaluated=link_result.plan_link_evaluated,
            plan_linked=False,
        )
    construction = construct_approved_change_plan_link_artifact(link_result)
    if construction.artifact is None:
        return _published(
            "plan_link_artifact_validation_failed",
            errors=list(construction.errors),
            filesystem_accessed=link_result.filesystem_accessed,
            plan_validated=True,
            plan_identity_confirmed=True,
            plan_link_evaluated=True,
            plan_linked=True,
        )
    identity, artifact_id = construction.artifact_identity_sha256, construction.artifact_id
    if not isinstance(confirm_plan_link_artifact_identity_sha256, str) or not _SHA_RE.fullmatch(
        confirm_plan_link_artifact_identity_sha256
    ):
        return _published(
            "invalid_plan_link_artifact_input",
            artifact_id=artifact_id,
            artifact_identity_sha256=identity,
            errors=["artifact confirmation must be exactly 64 lowercase hexadecimal characters"],
            filesystem_accessed=link_result.filesystem_accessed,
            plan_validated=True,
            plan_identity_confirmed=True,
            plan_link_evaluated=True,
            plan_linked=True,
        )
    if not hmac.compare_digest(identity, confirm_plan_link_artifact_identity_sha256):
        return _published(
            "artifact_confirmation_mismatch",
            artifact_id=artifact_id,
            artifact_identity_sha256=identity,
            errors=["artifact confirmation does not match the canonical artifact identity"],
            filesystem_accessed=link_result.filesystem_accessed,
            plan_validated=True,
            plan_identity_confirmed=True,
            plan_link_evaluated=True,
            plan_linked=True,
        )
    checked = _validate_data_dir(data_dir)
    if checked.path is None:
        return _published(
            "plan_link_artifact_publication_blocked",
            artifact_id=artifact_id,
            artifact_identity_sha256=identity,
            confirmation_matched=True,
            errors=list(checked.errors),
            filesystem_accessed=True,
            plan_validated=True,
            plan_identity_confirmed=True,
            plan_link_evaluated=True,
            plan_linked=True,
        )
    root = checked.path / APPROVED_CHANGE_PLAN_LINKS_DIRNAME
    final = root / artifact_id
    try:
        if not root.exists():
            os.mkdir(root, PERSISTED_DIRECTORY_MODE)
        if (
            _is_symlink_or_reparse(root)
            or root.parent != checked.path
            or root.name != APPROVED_CHANGE_PLAN_LINKS_DIRNAME
        ):
            raise OSError("unsafe fixed persistence root")
        if _path_exists_without_following(final):
            loaded = load_persisted_approved_change_plan_link_artifact(checked.path, artifact_id)
            if (
                loaded.status == "plan_link_artifact_loaded"
                and loaded.artifact is not None
                and canonical_approved_change_plan_link_artifact_bytes(loaded.artifact)
                == construction.canonical_bytes
            ):
                return _published(
                    "plan_link_artifact_already_present",
                    artifact_id=artifact_id,
                    artifact_identity_sha256=identity,
                    confirmation_matched=True,
                    filesystem_accessed=True,
                    existing_identical_no_op=True,
                    plan_validated=True,
                    plan_identity_confirmed=True,
                    plan_link_evaluated=True,
                    plan_linked=True,
                    plan_link_artifact_persisted=True,
                )
            return _published(
                "plan_link_artifact_conflict",
                artifact_id=artifact_id,
                artifact_identity_sha256=identity,
                confirmation_matched=True,
                errors=[
                    "the exact destination exists but is not the same valid canonical artifact"
                ],
                filesystem_accessed=True,
                plan_validated=True,
                plan_identity_confirmed=True,
                plan_link_evaluated=True,
                plan_linked=True,
            )
        temporary = root / f"{TEMPORARY_DIRECTORY_PREFIX}{secrets.token_hex(8)}"
        os.mkdir(temporary, PERSISTED_DIRECTORY_MODE)
        temporary_created = True
        path = temporary / APPROVED_CHANGE_PLAN_LINK_FILENAME
        try:
            fd = os.open(
                path,
                os.O_CREAT
                | os.O_EXCL
                | os.O_WRONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                PERSISTED_FILE_MODE,
            )
            try:
                data = construction.canonical_bytes
                offset = 0
                while offset < len(data):
                    offset += os.write(fd, data[offset:])
                os.fsync(fd)
            finally:
                os.close(fd)
            observed = _read_bounded(path, len(data))
            if observed != data:
                raise OSError("prepared bytes differ")
            payload = ApprovedChangePlanLinkArtifact.model_validate(_load_strict_json(observed))
            if not validate_approved_change_plan_link_artifact(
                payload, artifact_id=artifact_id
            ).artifact_valid:
                raise OSError("prepared artifact failed validation")
            _fsync_directory(temporary)
            outcome = atomic_no_replace_approval_directory_publish(temporary, final)
            atomic_outcome = outcome
            if outcome.outcome == "destination_exists":
                loaded = load_persisted_approved_change_plan_link_artifact(
                    checked.path, artifact_id
                )
                cleanup_status, cleaned, residual, cleanup_errors = (
                    _cleanup_invocation_temporary_directory(temporary, path)
                )
                if (
                    loaded.status == "plan_link_artifact_loaded"
                    and loaded.artifact is not None
                    and canonical_approved_change_plan_link_artifact_bytes(loaded.artifact) == data
                ):
                    return _published(
                        "plan_link_artifact_already_present",
                        artifact_id=artifact_id,
                        artifact_identity_sha256=identity,
                        confirmation_matched=True,
                        filesystem_accessed=True,
                        existing_identical_no_op=True,
                        plan_validated=True,
                        plan_identity_confirmed=True,
                        plan_link_evaluated=True,
                        plan_linked=True,
                        plan_link_artifact_persisted=True,
                        temporary_directory_created=temporary_created,
                        temporary_directory_cleaned=cleaned,
                        cleanup_status=cleanup_status,
                        residual_temporary_directory=residual,
                        atomic_publish_outcome=outcome.outcome,
                        errors=cleanup_errors,
                    )
                return _published(
                    "plan_link_artifact_conflict"
                    if cleanup_status != "incomplete"
                    else "plan_link_artifact_publication_blocked",
                    artifact_id=artifact_id,
                    artifact_identity_sha256=identity,
                    confirmation_matched=True,
                    errors=[
                        "atomic publication found a conflicting destination",
                        *cleanup_errors,
                    ],
                    filesystem_accessed=True,
                    plan_validated=True,
                    plan_identity_confirmed=True,
                    plan_link_evaluated=True,
                    plan_linked=True,
                    temporary_directory_created=temporary_created,
                    temporary_directory_cleaned=cleaned,
                    cleanup_status=cleanup_status,
                    residual_temporary_directory=residual,
                    atomic_publish_outcome=outcome.outcome,
                )
            if outcome.outcome != "published":
                cleanup_status, cleaned, residual, cleanup_errors = (
                    _cleanup_invocation_temporary_directory(temporary, path)
                )
                return _published(
                    "plan_link_artifact_publication_blocked",
                    artifact_id=artifact_id,
                    artifact_identity_sha256=identity,
                    confirmation_matched=True,
                    errors=[
                        f"atomic no-replace publication failed closed: {outcome.outcome}",
                        *([outcome.detail] if outcome.detail else []),
                        *cleanup_errors,
                    ],
                    filesystem_accessed=True,
                    plan_validated=True,
                    plan_identity_confirmed=True,
                    plan_link_evaluated=True,
                    plan_linked=True,
                    mutation_performed=True,
                    artifact_write_performed=True,
                    temporary_directory_created=temporary_created,
                    temporary_directory_cleaned=cleaned,
                    cleanup_status=cleanup_status,
                    residual_temporary_directory=residual,
                    atomic_publish_outcome=outcome.outcome,
                )
            _fsync_directory(root)
            loaded = load_persisted_approved_change_plan_link_artifact(checked.path, artifact_id)
            if loaded.status != "plan_link_artifact_loaded":
                return _published(
                    "plan_link_artifact_validation_failed",
                    artifact_id=artifact_id,
                    artifact_identity_sha256=identity,
                    confirmation_matched=True,
                    errors=list(loaded.errors),
                    filesystem_accessed=True,
                    mutation_performed=True,
                    artifact_write_performed=True,
                    publication_performed=True,
                    persistence_performed=True,
                    plan_validated=True,
                    plan_identity_confirmed=True,
                    plan_link_evaluated=True,
                    plan_linked=True,
                    plan_link_artifact_persisted=True,
                )
            return _published(
                "plan_link_artifact_published",
                artifact_id=artifact_id,
                artifact_identity_sha256=identity,
                confirmation_matched=True,
                filesystem_accessed=True,
                read_only=False,
                mutation_performed=True,
                artifact_write_performed=True,
                publication_performed=True,
                persistence_performed=True,
                plan_validated=True,
                plan_identity_confirmed=True,
                plan_link_evaluated=True,
                plan_linked=True,
                plan_link_artifact_persisted=True,
                temporary_directory_created=temporary_created,
                temporary_directory_cleaned=False,
                cleanup_status="not_required",
                atomic_publish_outcome=outcome.outcome,
            )
        except Exception:
            cleanup_status, cleaned, residual, cleanup_errors = (
                _cleanup_invocation_temporary_directory(temporary, path)
            )
            if cleanup_status == "incomplete":
                raise OSError(
                    "publication failed and invocation temporary cleanup is incomplete: "
                    + "; ".join(cleanup_errors)
                ) from None
            raise
    except Exception as exc:
        return _published(
            "plan_link_artifact_conflict"
            if isinstance(exc, FileExistsError)
            else "plan_link_artifact_publication_blocked",
            artifact_id=artifact_id,
            artifact_identity_sha256=identity,
            confirmation_matched=True,
            errors=[str(exc)],
            filesystem_accessed=True,
            plan_validated=True,
            plan_identity_confirmed=True,
            plan_link_evaluated=True,
            plan_linked=True,
            temporary_directory_created=temporary_created,
            temporary_directory_cleaned=False,
            cleanup_status="not_required" if not temporary_created else "completed",
            atomic_publish_outcome=atomic_outcome.outcome if atomic_outcome else "not_attempted",
        )
