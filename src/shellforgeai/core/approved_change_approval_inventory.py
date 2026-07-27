"""Bounded, deterministic, read-only approval-artifact inventory (PR320).

PR319 persists exactly one canonical approval artifact per publication and
offers exactly one way to read one back: the exact-ID loader. It deliberately
provides no listing, no search, no index, and no ``latest``/``current``/"most
recent" resolution. This module adds the smallest safe discovery layer on top
of that boundary and nothing else.

It adds exactly one public operation:

* :func:`inventory_persisted_approved_change_approval_artifacts` — accept one
  explicit ShellForgeAI ``data_dir``, derive the fixed PR319
  ``<data_dir>/approved_change_approvals`` root, enumerate its *direct*
  children once, enforce one fixed conservative entry-count bound, treat only
  exact ``aca_`` + 64-lowercase-hex names as artifact candidates, validate each
  such candidate *only* through the maintained PR319 exact-ID loader, and
  return one immutable result holding immutable summaries sorted only by exact
  artifact ID plus one explicit anomaly for every other direct child.

Inventory is discovery, not selection. It never chooses, resolves, recommends,
ranks, filters, or returns a "current" approval; it never orders by filesystem
mtime or by approval time; it creates no index, pointer, or cache; and it never
writes, creates, repairs, rewrites, republishes, renames, quarantines, or
deletes anything. It authenticates no approver, creates no approval or
contract, evaluates or binds no capability, runs no preflight, creates or links
no receipt, grants no execution eligibility, registers no CLI route, and
reaches no shell, subprocess, network, model, or provider.

Artifact parsing, canonicalization, identity recomputation, PR309
approval-binding revalidation, and exact PR317 source-bundle revalidation all
stay in PR319. This module owns no parser and no loader of its own: an entry
appears only because the maintained PR319 loader returned a fully valid
artifact for that exact ID.
"""

from __future__ import annotations

import os
import stat as stat_module
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from shellforgeai.core.approved_change_approval_artifact import (
    APPROVAL_ARTIFACT_ID_PREFIX,
    PERMANENT_APPROVAL_ARTIFACT_WARNINGS,
    canonical_approval_artifact_payload,
)
from shellforgeai.core.approved_change_approval_persistence import (
    _ARTIFACT_ID_RE,
    APPROVED_CHANGE_APPROVALS_DIRNAME,
    _check_publication_root_containment,
    _is_reparse_stat,
    _path_exists_without_following,
    _publication_root,
    _real,
    _validate_data_dir,
    load_persisted_approved_change_approval_artifact,
)
from shellforgeai.core.approved_change_artifact_bundle import EXECUTION_STATUS_NOT_EXECUTED

APPROVAL_INVENTORY_SCHEMA_VERSION = "1"

#: The one fixed conservative direct-child bound. It is a maintained constant,
#: never a caller-controlled parameter, and never a retention policy: it exists
#: only so one read-only operation cannot be driven into unbounded directory
#: enumeration and unbounded artifact validation work. A root holding more than
#: this many direct children fails closed and returns no partial inventory.
MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES = 1024

#: The exact PR319 loader status that alone permits an inventory entry.
REQUIRED_APPROVAL_ARTIFACT_LOAD_STATUS = "persisted_approval_artifact_loaded"

#: The PR319 loader status meaning the exact candidate is no longer present.
_LOADER_NOT_FOUND_STATUS = "persisted_approval_artifact_not_found"

INVENTORY_STATUSES = (
    "approval_artifact_inventory_loaded",
    "approval_artifact_inventory_empty",
    "approval_artifact_inventory_loaded_with_anomalies",
    "approval_artifact_inventory_blocked",
    "approval_artifact_inventory_limit_exceeded",
    "invalid_inventory_input",
)
InventoryStatus = Literal[
    "approval_artifact_inventory_loaded",
    "approval_artifact_inventory_empty",
    "approval_artifact_inventory_loaded_with_anomalies",
    "approval_artifact_inventory_blocked",
    "approval_artifact_inventory_limit_exceeded",
    "invalid_inventory_input",
]

INVENTORY_ANOMALY_CATEGORIES = (
    "entry_changed_during_inventory",
    "entry_disappeared",
    "entry_not_inspectable",
    "invalid_approval_artifact",
    "non_directory_entry",
    "symlink_or_reparse_entry",
    "unexpected_name",
)
InventoryAnomalyCategory = Literal[
    "entry_changed_during_inventory",
    "entry_disappeared",
    "entry_not_inspectable",
    "invalid_approval_artifact",
    "non_directory_entry",
    "symlink_or_reparse_entry",
    "unexpected_name",
]

#: Warnings every inventory result carries, whatever its status. The
#: inventory-specific statements come first; the maintained PR319 approval
#: statements follow verbatim so no competing wording is introduced.
PERMANENT_APPROVAL_INVENTORY_WARNINGS: tuple[str, ...] = (
    "inventory is discovery only and selects no approval",
    "inventory ordering is lexicographic by exact approval-artifact ID only",
    "inventory ordering is not chronological, priority-based, risk-based, or authoritative",
    'no "latest", "current", or "most recent approval" is resolved',
    "an exact aca_ approval-artifact ID remains required for subsequent loading or any future "
    "operation",
    "an anomalous inventory is explicitly incomplete and is never a complete trusted approval set",
    "no persisted index, pointer, or cache is created or consulted",
    "no artifact is repaired, overwritten, renamed, quarantined, or deleted",
    *PERMANENT_APPROVAL_ARTIFACT_WARNINGS,
)


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Internal deterministic seam
#
# This is private. It exists so root-replacement and mid-scan races can be
# exercised deterministically. It is not part of the public API, it accepts no
# caller-supplied path, and it never does anything.
# ---------------------------------------------------------------------------


def _inventory_stage(name: str) -> None:
    """Internal no-op stage seam used only by focused tests."""
    return None


# ---------------------------------------------------------------------------
# Immutable result models
# ---------------------------------------------------------------------------


class ApprovedChangeApprovalArtifactInventoryEntry(_FrozenModel):
    """One immutable summary of one fully valid persisted approval artifact.

    Every field is already-validated maintained metadata taken from one
    successful PR319 load result. The summary is deliberately partial: it never
    carries the approval reason, the full contract, a filesystem timestamp, a
    host absolute path, or any mutable status, and it is never capability
    support, authorization, or execution eligibility. The exact-ID PR319 loader
    remains the only way to retrieve the complete artifact.
    """

    schema_version: Literal["1"] = APPROVAL_INVENTORY_SCHEMA_VERSION
    approval_artifact_id: str
    approval_artifact_identity_sha256: str
    artifact_byte_length: int
    source_bundle_id: str
    source_bundle_identity_sha256: str
    subject_sha256: str
    approved_by: str
    approved_at: str
    approval_scope: str
    approval_binding_valid: bool


class ApprovedChangeApprovalArtifactInventoryAnomaly(_FrozenModel):
    """One immutable report of one direct child that is not a valid artifact.

    ``entry_name`` is the direct child's single safe name and nothing else: no
    host absolute path, no parent path, and no path taken from artifact
    content. The anomalous entry is never followed, never recursed into, never
    repaired, never renamed, and never removed.
    """

    schema_version: Literal["1"] = APPROVAL_INVENTORY_SCHEMA_VERSION
    entry_name: str
    category: InventoryAnomalyCategory
    loader_status: str = ""
    reason: str = ""
    errors: tuple[str, ...] = ()


class ApprovedChangeApprovalArtifactInventoryResult(_FrozenModel):
    """Structured, non-throwing, read-only approval-artifact inventory result.

    ``inventory_complete`` is the only field that states whether the returned
    entries are the whole safe truth about the fixed root. It is true only for
    a fully clean scan and for an empty root. No automated consumer may treat
    ``inventory_complete=false`` as a complete inventory.
    """

    schema_version: Literal["1"] = APPROVAL_INVENTORY_SCHEMA_VERSION
    status: InventoryStatus
    reason: str = ""
    inventory_complete: bool = False
    inventory_root_present: bool = False
    relative_inventory_root: str = APPROVED_CHANGE_APPROVALS_DIRNAME
    max_inventory_entries: int = MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES
    scanned_entry_count: int = 0
    valid_entry_count: int = 0
    anomaly_count: int = 0
    entries: tuple[ApprovedChangeApprovalArtifactInventoryEntry, ...] = ()
    anomalies: tuple[ApprovedChangeApprovalArtifactInventoryAnomaly, ...] = ()
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_APPROVAL_INVENTORY_WARNINGS

    # Accurate safety ledger. Inventory reads and reports; it changes nothing.
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    filesystem_accessed: bool = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    inventory_performed: bool = False
    inventory_index_written: Literal[False] = False
    approval_selected: Literal[False] = False
    approval_created: Literal[False] = False
    approval_persisted: Literal[False] = False
    contract_created: Literal[False] = False
    contract_persisted: Literal[False] = False
    source_bundle_mutation_performed: Literal[False] = False
    overwrite_performed: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    capability_support_evaluated: Literal[False] = False
    capability_supported: Literal[False] = False
    capability_bound: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result(
    status: InventoryStatus,
    *,
    reason: str = "",
    inventory_complete: bool = False,
    inventory_root_present: bool = False,
    scanned_entry_count: int = 0,
    entries: tuple[ApprovedChangeApprovalArtifactInventoryEntry, ...] = (),
    anomalies: tuple[ApprovedChangeApprovalArtifactInventoryAnomaly, ...] = (),
    errors: list[str] | None = None,
    filesystem_accessed: bool = False,
    inventory_performed: bool = False,
) -> ApprovedChangeApprovalArtifactInventoryResult:
    return ApprovedChangeApprovalArtifactInventoryResult(
        status=status,
        reason=reason,
        inventory_complete=inventory_complete,
        inventory_root_present=inventory_root_present,
        scanned_entry_count=scanned_entry_count,
        valid_entry_count=len(entries),
        anomaly_count=len(anomalies),
        entries=entries,
        anomalies=anomalies,
        errors=tuple(sorted(set(errors or ()))),
        filesystem_accessed=filesystem_accessed,
        inventory_performed=inventory_performed,
    )


def _redactor(data_dir: Path) -> Any:
    """Return a redactor that strips host absolute paths from reported text.

    Every path PR319 can name lies beneath the explicit data root, so replacing
    that root — in both its given and its resolved spelling — with a fixed
    placeholder is sufficient and fully deterministic. No traceback is ever
    reported, and no path is ever reconstructed from artifact content.
    """
    roots = sorted({str(data_dir), str(_real(data_dir))}, key=lambda item: (-len(item), item))

    def redact(text: str) -> str:
        cleaned = text
        for root in roots:
            if root:
                cleaned = cleaned.replace(root, "<data_dir>")
        return cleaned

    return redact


def _anomaly(
    entry_name: str,
    category: InventoryAnomalyCategory,
    *,
    reason: str,
    loader_status: str = "",
    errors: tuple[str, ...] | list[str] = (),
) -> ApprovedChangeApprovalArtifactInventoryAnomaly:
    return ApprovedChangeApprovalArtifactInventoryAnomaly(
        entry_name=entry_name,
        category=category,
        loader_status=loader_status,
        reason=reason,
        errors=tuple(sorted(set(errors))),
    )


def _entry_from_load_result(load_result: Any) -> ApprovedChangeApprovalArtifactInventoryEntry:
    """Build one summary from one successful PR319 load result.

    Nothing is reparsed and nothing is recomputed here: the approval timestamp
    is taken from the maintained PR319 canonical payload so the reported value
    is exactly the persisted canonical spelling on every platform.
    """
    artifact = load_result.artifact
    payload = canonical_approval_artifact_payload(artifact)
    approval = payload["contract"]["approval"]
    return ApprovedChangeApprovalArtifactInventoryEntry(
        approval_artifact_id=artifact.approval_artifact_id,
        approval_artifact_identity_sha256=artifact.approval_artifact_identity_sha256,
        artifact_byte_length=artifact.byte_length,
        source_bundle_id=artifact.source_bundle_id,
        source_bundle_identity_sha256=artifact.source_bundle_identity_sha256,
        subject_sha256=artifact.subject_sha256,
        approved_by=approval["approved_by"],
        approved_at=approval["approved_at"],
        approval_scope=load_result.artifact_validation.approval_scope,
        approval_binding_valid=load_result.approval_binding_valid,
    )


def _filesystem_identity(path: Path) -> tuple[int, int]:
    info = os.lstat(path)
    return (info.st_dev, info.st_ino)


def _root_identity_unchanged(root: Path, captured: tuple[int, int]) -> bool:
    try:
        return _filesystem_identity(root) == captured
    except OSError:
        return False


# ---------------------------------------------------------------------------
# The one public inventory operation
# ---------------------------------------------------------------------------


def inventory_persisted_approved_change_approval_artifacts(
    *,
    data_dir: Path | str,
) -> ApprovedChangeApprovalArtifactInventoryResult:
    """Enumerate the fixed PR319 approval-artifact root, once, read-only.

    The operation accepts only the explicit ShellForgeAI data root. It accepts
    no arbitrary approval root, no artifact directory, no artifact ID, subject,
    source-bundle, approver, or approval-time query, no sort key, no descending
    flag, no entry-limit override, no ``latest``/``current``/"most recent"
    reference, no capability ID, no capability registry, no execution target,
    no caller-supplied artifact, and no output path.

    It inspects only the direct children of that fixed root, never recurses,
    never follows a symlink or reparse point, and validates an exact ``aca_``
    candidate only by calling the maintained PR319 exact-ID loader. It sorts
    entries lexicographically by exact artifact ID and by nothing else — never
    by filesystem mtime, approval time, actor, source bundle, or subject — and
    it resolves no preferred, current, or most recent approval. It performs no
    filesystem or host mutation of any kind.
    """
    # 1. The explicit data root, structurally first.
    data_dir_check = _validate_data_dir(data_dir)
    resolved_data_dir = data_dir_check.path
    if resolved_data_dir is None:
        if not data_dir_check.filesystem_accessed:
            return _result(
                "invalid_inventory_input",
                reason="the explicit data directory is not a structurally valid absolute path",
                errors=list(data_dir_check.errors),
            )
        return _result(
            "approval_artifact_inventory_blocked",
            reason="the explicit data directory is not a safe existing absolute directory",
            errors=list(data_dir_check.errors),
            filesystem_accessed=True,
        )

    redact = _redactor(resolved_data_dir)

    # 2-3. The fixed PR319 approval root, and whether it safely exists.
    root = _publication_root(resolved_data_dir)
    root_errors = _check_publication_root_containment(resolved_data_dir, root)
    if root_errors:
        return _result(
            "approval_artifact_inventory_blocked",
            reason="the fixed approval-artifact root is not a safe direct child of data_dir",
            errors=[redact(item) for item in root_errors],
            filesystem_accessed=True,
        )

    # 4. An absent root is an empty complete inventory. It is never created.
    if not _path_exists_without_following(root):
        return _result(
            "approval_artifact_inventory_empty",
            reason="the fixed approval-artifact root does not exist and is never created",
            inventory_complete=True,
            filesystem_accessed=True,
            inventory_performed=True,
        )

    # 5-6. The root is present: capture its stable filesystem identity.
    try:
        root_identity = _filesystem_identity(root)
    except OSError as exc:
        return _result(
            "approval_artifact_inventory_blocked",
            reason="the fixed approval-artifact root is not inspectable",
            errors=[f"approval-artifact root is not inspectable: {redact(str(exc))}"],
            filesystem_accessed=True,
            inventory_root_present=True,
        )
    _inventory_stage("root_identity_captured")

    # 7. One non-recursive direct-child enumeration.
    try:
        raw_names = os.listdir(root)
    except OSError as exc:
        return _result(
            "approval_artifact_inventory_blocked",
            reason="the fixed approval-artifact root could not be safely enumerated",
            errors=[f"approval-artifact root enumeration failed: {redact(str(exc))}"],
            filesystem_accessed=True,
            inventory_root_present=True,
        )
    scanned = len(raw_names)

    # 8. The fixed bound, enforced before any artifact is loaded.
    if scanned > MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES:
        return _result(
            "approval_artifact_inventory_limit_exceeded",
            reason=(
                "the fixed approval-artifact root holds more direct children than the fixed "
                "inventory bound permits, so no partial inventory is returned"
            ),
            errors=[
                f"the fixed approval-artifact root holds {scanned} direct children and this "
                f"operation inspects at most {MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES}"
            ],
            filesystem_accessed=True,
            inventory_root_present=True,
            scanned_entry_count=scanned,
        )

    # 9. Deterministic processing order.
    names = sorted(raw_names)
    _inventory_stage("entries_enumerated")

    entries: list[ApprovedChangeApprovalArtifactInventoryEntry] = []
    anomalies: list[ApprovedChangeApprovalArtifactInventoryAnomaly] = []

    for name in names:
        # 10-11. A malformed name is reported without being inspected at all,
        # so an unexpected entry is never opened, followed, or recursed into.
        if not _ARTIFACT_ID_RE.fullmatch(name):
            anomalies.append(
                _anomaly(
                    name,
                    "unexpected_name",
                    reason=(
                        "the direct child is not exactly "
                        f"{APPROVAL_ARTIFACT_ID_PREFIX!r} followed by 64 lowercase hexadecimal "
                        "characters, so it is not an approval-artifact candidate"
                    ),
                )
            )
            continue

        try:
            info = os.lstat(root / name)
        except FileNotFoundError:
            anomalies.append(
                _anomaly(
                    name,
                    "entry_disappeared",
                    reason="the direct child disappeared before it could be inspected",
                )
            )
            continue
        except OSError as exc:
            anomalies.append(
                _anomaly(
                    name,
                    "entry_not_inspectable",
                    reason="the direct child could not be safely inspected",
                    errors=[f"direct child is not inspectable: {redact(str(exc))}"],
                )
            )
            continue

        if _is_reparse_stat(info, root / name):
            anomalies.append(
                _anomaly(
                    name,
                    "symlink_or_reparse_entry",
                    reason=("the direct child is a symlink or reparse point and is never followed"),
                )
            )
            continue
        if not stat_module.S_ISDIR(info.st_mode):
            anomalies.append(
                _anomaly(
                    name,
                    "non_directory_entry",
                    reason="the direct child carries an exact artifact ID but is not a directory",
                )
            )
            continue

        entry_identity = (info.st_dev, info.st_ino)

        # 12. Exact candidates are validated only by the PR319 loader.
        load_result = load_persisted_approved_change_approval_artifact(
            name, data_dir=resolved_data_dir
        )

        try:
            reinspected = _filesystem_identity(root / name)
        except OSError:
            anomalies.append(
                _anomaly(
                    name,
                    "entry_disappeared",
                    loader_status=load_result.status,
                    reason="the direct child disappeared while it was being validated",
                )
            )
            continue
        if reinspected != entry_identity:
            anomalies.append(
                _anomaly(
                    name,
                    "entry_changed_during_inventory",
                    loader_status=load_result.status,
                    reason="the direct child changed identity while it was being validated",
                )
            )
            continue

        # 13-14. An entry exists only for a fully valid loaded artifact.
        if (
            load_result.status == REQUIRED_APPROVAL_ARTIFACT_LOAD_STATUS
            and load_result.artifact is not None
            and load_result.artifact_validation is not None
            and load_result.artifact_validation.artifact_valid
            and load_result.approval_binding_valid
        ):
            entries.append(_entry_from_load_result(load_result))
            continue

        if load_result.status == _LOADER_NOT_FOUND_STATUS:
            anomalies.append(
                _anomaly(
                    name,
                    "entry_disappeared",
                    loader_status=load_result.status,
                    reason="the exact artifact ID no longer resolves to a persisted artifact",
                )
            )
            continue

        anomalies.append(
            _anomaly(
                name,
                "invalid_approval_artifact",
                loader_status=load_result.status,
                reason=(
                    "the maintained exact-ID loader did not return a fully valid approval artifact"
                ),
                errors=[redact(item) for item in load_result.errors],
            )
        )

    # 15-16. The root must still be the same object it was when the scan began.
    if not _root_identity_unchanged(root, root_identity):
        return _result(
            "approval_artifact_inventory_blocked",
            reason="the fixed approval-artifact root changed identity during the inventory",
            errors=["approval-artifact root identity changed during the inventory"],
            filesystem_accessed=True,
            inventory_root_present=True,
            scanned_entry_count=scanned,
        )

    # 17-18. Lexicographic order, and nothing else.
    ordered_entries = tuple(sorted(entries, key=lambda item: item.approval_artifact_id))
    ordered_anomalies = tuple(sorted(anomalies, key=lambda item: (item.entry_name, item.category)))

    # 19. One structured immutable result.
    if ordered_anomalies:
        return _result(
            "approval_artifact_inventory_loaded_with_anomalies",
            reason=(
                "the fixed approval-artifact root was scanned safely but at least one direct "
                "child is unexpected, unsafe, missing, or invalid, so this inventory is "
                "explicitly incomplete"
            ),
            inventory_complete=False,
            inventory_root_present=True,
            scanned_entry_count=scanned,
            entries=ordered_entries,
            anomalies=ordered_anomalies,
            filesystem_accessed=True,
            inventory_performed=True,
        )
    if not ordered_entries:
        return _result(
            "approval_artifact_inventory_empty",
            reason="the fixed approval-artifact root exists and holds no direct children",
            inventory_complete=True,
            inventory_root_present=True,
            scanned_entry_count=scanned,
            filesystem_accessed=True,
            inventory_performed=True,
        )
    return _result(
        "approval_artifact_inventory_loaded",
        reason=(
            "every direct child of the fixed approval-artifact root is a valid approval artifact"
        ),
        inventory_complete=True,
        inventory_root_present=True,
        scanned_entry_count=scanned,
        entries=ordered_entries,
        filesystem_accessed=True,
        inventory_performed=True,
    )
