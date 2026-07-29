"""Governed two-file Windows durable-runtime reconciliation execution (PR313).

This module completes the deliberately deferred PR305 apply lane for exactly one
named capability, ``windows.runtime_reconcile``.  It reconciles exactly two fixed
mappings and nothing else:

``config/profiles/inspect.yaml -> config/profiles/inspect.yaml``
``scripts/windows/sfai.cmd     -> bin/sfai.cmd``

It is a local Windows file-integrity repair lane.  It is not a generic file
copier, launcher generator, release activator, package installer, cleanup lane,
remote-administration facility, or autonomous remediation system.  It never uses
a shell, subprocess, PowerShell, WinRM, QGA, registry, service control, model, or
network path, and natural language never reaches it.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import platform
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from shellforgeai.core.windows_runtime_reconcile_plan_contract import (
    ACCEPTED_PLAN_STATUSES,  # noqa: F401 - maintained PR313 constant re-export
    ALLOWLIST,
    AUTHORIZED_PARENT_DIRECTORIES,
    PARENT_CONTRACT_VERSION,
    PARENT_CREATION_ALLOWED,
    PARENT_RELATIVE,
    PARENT_STATES,
    PLAN_SCHEMA_VERSION,
    SAVED_OPERATIONS,
    canonical_plan_json,  # noqa: F401 - maintained PR313 helper re-export
    canonical_plan_sha256,
    confirmation_matches,
    is_plan_sha256,
    saved_plan_executable_contract_errors,
)

SCHEMA_VERSION = PLAN_SCHEMA_VERSION
RECIPE_ID = "windows.runtime_reconcile"
PLAN_MODE = "windows_runtime_reconcile"
EXECUTE_MODE = "windows_runtime_reconcile_execute"
RECEIPT_MODE = "windows_runtime_reconcile_execution_receipt"
RECEIPT_VALIDATE_MODE = "windows_runtime_reconcile_receipt_validate"
VERIFY_MODE = "windows_runtime_reconcile_verify"
MANIFEST_KIND = "windows_runtime_reconcile_execution_receipt"
MANIFEST_MODE = "windows_runtime_reconcile_receipt_manifest"

RECEIPT_JSON = "windows-runtime-reconcile-receipt.json"
RECEIPT_MD = "windows-runtime-reconcile-receipt.md"
RECEIPT_MANIFEST = "manifest.json"
RECEIPT_REQUIRED_FILES = (RECEIPT_JSON, RECEIPT_MD, RECEIPT_MANIFEST)
RECEIPT_ROOT_NAME = "windows_runtime_reconcile_receipts"

#: The complete, fixed, ordered execution allowlist and the exact fixed
#: destination-parent contract.  Both are the maintained pure plan-contract
#: constants, re-exported here so every existing PR313 consumer keeps its exact
#: import surface while exactly one definition exists.  Nothing else is
#: reachable: only the inspect-profile destination may have its parent chain
#: created, and only the exact ``config`` / ``config/profiles`` components
#: beneath an already-existing durable runtime root.  The wrapper parent ``bin``
#: must already exist.  No generic mkdir, bootstrap, installer, or
#: caller-supplied directory is reachable.
__all_plan_contract_reexports__ = (
    "ALLOWLIST",
    "AUTHORIZED_PARENT_DIRECTORIES",
    "PARENT_CONTRACT_VERSION",
    "PARENT_CREATION_ALLOWED",
    "PARENT_RELATIVE",
    "PARENT_STATES",
)

#: Conservative per-source maximum sizes enforced before any preparation.
MAX_SOURCE_BYTES: Mapping[str, int] = {
    "config/profiles/inspect.yaml": 1024 * 1024,
    "scripts/windows/sfai.cmd": 256 * 1024,
}

INSPECT_PROFILE_NAME = "inspect"
BACKUP_MARKER = "sfai-pr305-backup"
TEMP_MARKER = "sfai-pr313-tmp"

STATUS_EXECUTED = "executed"
STATUS_PARTIAL_EXECUTED = "partial_executed"
STATUS_NO_CHANGE = "no_change"
STATUS_FAILED_COMPENSATED = "failed_compensated"
STATUS_FAILED_COMPENSATION_INCOMPLETE = "failed_compensation_incomplete"
STATUS_VERIFICATION_FAILED = "verification_failed"
STATUS_BLOCKED = "blocked"
STATUS_UNSUPPORTED = "unsupported"

EXECUTION_STATUSES = (
    STATUS_EXECUTED,
    STATUS_PARTIAL_EXECUTED,
    STATUS_NO_CHANGE,
    STATUS_FAILED_COMPENSATED,
    STATUS_FAILED_COMPENSATION_INCOMPLETE,
    STATUS_VERIFICATION_FAILED,
    STATUS_BLOCKED,
    STATUS_UNSUPPORTED,
)
#: Statuses that reach current-state evaluation and therefore persist a receipt.
RECEIPT_STATUSES = tuple(s for s in EXECUTION_STATUSES if s != STATUS_UNSUPPORTED)

VERIFY_STATUS_VERIFIED = "verified"
VERIFY_STATUS_FAILED = "verification_failed"
VERIFY_STATUS_BLOCKED = "blocked"
VERIFY_STATUS_UNSUPPORTED = "unsupported"
VERIFY_STATUSES = (
    VERIFY_STATUS_VERIFIED,
    VERIFY_STATUS_FAILED,
    VERIFY_STATUS_BLOCKED,
    VERIFY_STATUS_UNSUPPORTED,
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ABSOLUTE_PATH_RE = re.compile(r"(^[A-Za-z]:[\\/])|(^\\\\)|(^/[^/\s]+/)|(^~[\\/])")

#: Safety ledger keys that must always be false for this lane.
SAFETY_FALSE_KEYS: tuple[str, ...] = (
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
    "software_install_executed",
    "software_uninstall_executed",
    "service_control_executed",
    "process_termination_executed",
    "registry_modified",
    "execution_policy_modified",
    "powershell_executed",
    "winrm_used",
    "qga_used",
    "remote_execution",
    "subprocess_executed",
    "shell_executed",
    "shell_true",
    "arbitrary_command_execution",
    "natural_language_execution",
    "docker_compose_executed",
    "container_restarted",
    "network_call",
    "model_called",
    "secret_read",
    "auth_cache_read",
)
#: Safety ledger keys whose value reflects what this execution actually did.
SAFETY_DYNAMIC_KEYS: tuple[str, ...] = (
    "file_create_executed",
    "file_replace_executed",
    "backup_created",
    "atomic_replace_executed",
    "compensation_executed",
    "parent_directory_create_executed",
    "parent_directory_compensation_executed",
)

#: Receipt keys that would leak content, environment, credentials, or host paths.
FORBIDDEN_RECEIPT_KEYS: frozenset[str] = frozenset(
    {
        "auth_cache",
        "backup_path",
        "contents",
        "credential",
        "credentials",
        "destination_content",
        "destination_path",
        "durable_runtime_root",
        "env",
        "environ",
        "environment",
        "file_contents",
        "manifest_path",
        "password",
        "profile_content",
        "receipt_path",
        "secret",
        "secrets",
        "source_content",
        "source_path",
        "staged_source_root",
        "temp_path",
        "temporary_path",
        "token",
        "user",
        "username",
        "wrapper_content",
        "wrapper_text",
        "yaml_content",
    }
)


# --------------------------------------------------------------------------- #
# Small deterministic helpers
# --------------------------------------------------------------------------- #


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def _case(value: str) -> str:
    return value.casefold() if is_windows() else value


def _norm(path: Path | str | None) -> str | None:
    if path is None:
        return None
    candidate = Path(path).expanduser()
    try:
        return str(candidate.resolve(strict=False))
    except OSError:
        return str(candidate.absolute())


def _contained(child: Path, parent: Path) -> bool:
    child_s = _case(_norm(child) or "")
    parent_s = (_case(_norm(parent) or "")).rstrip("\\/")
    return (
        child_s == parent_s
        or child_s.startswith(parent_s + "/")
        or child_s.startswith(parent_s + "\\")
        or child_s.startswith(parent_s + os.sep)
    )


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str | None:
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError:
        return None


def _is_reparse(path: Path) -> bool:
    try:
        stat_result = os.lstat(path)
    except OSError:
        return False
    return bool(getattr(stat_result, "st_file_attributes", 0) & 0x400) or path.is_symlink()


def reparse_chain_components(root: Path, relative: str) -> list[str]:
    """Return the sanitized component names that are reparse points.

    Only the fixed root marker and allowlisted relative components can ever be
    reported, so no host path is disclosed.
    """
    hits: list[str] = []
    current = root
    if _is_reparse(current):
        hits.append("<root>")
    for part in PurePosixPath(relative).parts:
        current = current / part
        if _is_reparse(current):
            hits.append(part)
    return hits


def _now(clock: Callable[[], datetime] | None) -> datetime:
    return (clock or (lambda: datetime.now(timezone.utc)))()


def _stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _iso(moment: datetime) -> str:
    return (
        moment.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sanitize(text: object, *, limit: int = 240) -> str:
    """Reduce arbitrary text to a bounded, path-free, secret-free summary."""
    value = str(text or "")
    value = re.sub(
        r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+",
        r"\1=<redacted>",
        value,
    )
    value = re.sub(r"[A-Za-z]:[\\/][^\s\"']*", "<path>", value)
    value = re.sub(r"\\\\[^\s\"']+", "<path>", value)
    value = re.sub(r"(?<![\w.])/[^\s\"']*/[^\s\"']*", "<path>", value)
    value = " ".join(value.split())
    return value[:limit]


def sanitize_exception(exc: BaseException, *, limit: int = 200) -> str:
    return f"{exc.__class__.__name__}: {sanitize(exc, limit=limit)}"


def root_fingerprint(root: Path | str | None) -> str | None:
    """Stable non-reversible identity for a root, recorded instead of the path."""
    normalized = _norm(root)
    if normalized is None:
        return None
    return hashlib.sha256(_case(normalized).encode("utf-8")).hexdigest()


def windows_reconcile_receipt_root(data_dir: Path | str) -> Path:
    return Path(data_dir).expanduser() / RECEIPT_ROOT_NAME


# --------------------------------------------------------------------------- #
# Reuse of the maintained PR304 / PR305 helpers
# --------------------------------------------------------------------------- #


def load_helper_module(path: Path):
    """Load a maintained standalone helper script as a module (no execution)."""
    spec = importlib.util.spec_from_file_location(f"_sfai_pr313_{path.stem}", path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load helper module: {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def candidate_scripts_dirs() -> tuple[Path, ...]:
    """Bounded candidate list; no PATH, home, drive, or recursive discovery."""
    here = Path(__file__).resolve()
    return (
        here.parents[3] / "scripts",
        here.parents[2] / "scripts",
        Path.cwd() / "scripts",
    )


def resolve_scripts_dir(scripts_dir: Path | str | None = None) -> Path:
    if scripts_dir is not None:
        return Path(scripts_dir).expanduser()
    for candidate in candidate_scripts_dirs():
        if (candidate / "windows_runtime_reconcile_preflight.py").is_file():
            return candidate
    raise FileNotFoundError("maintained PR304/PR305 helper scripts were not resolved")


@dataclass(frozen=True)
class ReconcileValidators:
    """Injected reuse of the maintained PR304/PR305 builders and validators."""

    pr304_validate: Callable[[dict[str, Any]], list[str]]
    pr304_compare: Callable[[list[dict[str, Any]]], list[str]]
    pr305_errs: Callable[[dict[str, Any]], list[str]]
    pr305_operation: Callable[[Path, Path, str, str], dict[str, Any]]
    pr305_destination_parent: Callable[[Path, str], dict[str, Any]]
    pr305_root_safe: Callable[[Path], list[str]]
    wrapper_markers: Mapping[str, str]


def load_validators(scripts_dir: Path | str | None = None) -> ReconcileValidators:
    base = resolve_scripts_dir(scripts_dir)
    integrity = load_helper_module(base / "windows_runtime_integrity.py")
    integrity_acceptance = load_helper_module(base / "windows_runtime_integrity_acceptance.py")
    preflight = load_helper_module(base / "windows_runtime_reconcile_preflight.py")
    reconcile_acceptance = load_helper_module(base / "windows_runtime_reconcile_acceptance.py")
    return ReconcileValidators(
        pr304_validate=integrity_acceptance.validate,
        pr304_compare=integrity_acceptance.compare,
        pr305_errs=reconcile_acceptance.errs,
        pr305_operation=preflight.operation,
        pr305_destination_parent=preflight.destination_parent,
        pr305_root_safe=preflight.root_safe,
        wrapper_markers=dict(integrity.MARKERS),
    )


# --------------------------------------------------------------------------- #
# Safety ledger, posture, and result envelopes
# --------------------------------------------------------------------------- #


def safety_ledger(
    *,
    mutation_performed: bool = False,
    file_create_executed: bool = False,
    file_replace_executed: bool = False,
    backup_created: bool = False,
    atomic_replace_executed: bool = False,
    compensation_executed: bool = False,
    parent_directory_create_executed: bool = False,
    parent_directory_compensation_executed: bool = False,
) -> dict[str, bool]:
    return {
        "read_only": not mutation_performed,
        "mutation_performed": bool(mutation_performed),
        "file_create_executed": bool(file_create_executed),
        "file_replace_executed": bool(file_replace_executed),
        "backup_created": bool(backup_created),
        "atomic_replace_executed": bool(atomic_replace_executed),
        "compensation_executed": bool(compensation_executed),
        "parent_directory_create_executed": bool(parent_directory_create_executed),
        "parent_directory_compensation_executed": bool(
            parent_directory_compensation_executed
        ),
        **{key: False for key in SAFETY_FALSE_KEYS},
        "exact_two_file_allowlist": True,
    }


def recovery_posture() -> dict[str, Any]:
    return {
        "automatic_rollback_after_success": False,
        "bounded_same_execution_compensation_only": True,
        "compensation_scope": "files committed by this exact execution only",
        "backups_retained": True,
        "backup_pruning_executed": False,
        "post_success_rollback_command_available": False,
        "note": (
            "Compensation is transaction-local. Backups from a successful execution are "
            "retained and never pruned; there is no post-success rollback command."
        ),
    }


def next_verification_commands() -> list[str]:
    return [
        (
            "python scripts/windows_runtime_reconcile_receipt_acceptance.py <receipt-id> "
            "--data-dir <shellforgeai-data-dir> --json"
        ),
        (
            "python scripts/windows_runtime_reconcile_verify.py <receipt-id> "
            "--staged-pr304 <artifact.json> --system32-pr304 <artifact.json> "
            "--staged-source-root <root> --durable-runtime-root <root> "
            "--data-dir <shellforgeai-data-dir> --json"
        ),
        "direct System32 V1 quick and standard checks run separately by the operator",
    ]


def _envelope(
    *,
    status: str,
    reason: str = "",
    blockers: Sequence[str] = (),
    warnings: Sequence[str] = (),
    safety: Mapping[str, bool] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "mode": EXECUTE_MODE,
        "recipe_id": RECIPE_ID,
        "status": status,
        "reason": reason,
        "receipt_id": None,
        "receipt_path": None,
        "mutation_performed": bool((safety or {}).get("mutation_performed", False)),
        "blockers": list(blockers),
        "warnings": list(warnings),
        "safety": dict(safety or safety_ledger()),
        "recovery_posture": recovery_posture(),
    }
    payload.update(extra)
    return payload


# --------------------------------------------------------------------------- #
# Source content validation
# --------------------------------------------------------------------------- #


def validate_inspect_profile_bytes(data: bytes) -> list[str]:
    """Validate staged ``inspect.yaml`` bytes without normalizing or rewriting."""
    errors: list[str] = []
    limit = MAX_SOURCE_BYTES["config/profiles/inspect.yaml"]
    if len(data) > limit:
        errors.append("staged inspect profile exceeds the conservative maximum size")
        return errors
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return ["staged inspect profile is not readable as UTF-8 or UTF-8 with BOM"]
    try:
        import yaml

        parsed = yaml.safe_load(text)
    except Exception as exc:
        return [f"staged inspect profile is not safe-parsable YAML ({exc.__class__.__name__})"]
    if not isinstance(parsed, dict):
        return ["staged inspect profile must be a YAML mapping"]
    if parsed.get("name") != INSPECT_PROFILE_NAME:
        errors.append("staged inspect profile name does not match the inspect profile contract")
    try:
        from shellforgeai.core.profiles import Profile

        Profile.model_validate(parsed)
    except Exception as exc:
        errors.append(
            "staged inspect profile failed maintained profile validation "
            f"({exc.__class__.__name__})"
        )
    return errors


def validate_wrapper_bytes(data: bytes, markers: Mapping[str, str]) -> list[str]:
    """Validate staged ``sfai.cmd`` bytes against PR304 canonical wrapper semantics."""
    errors: list[str] = []
    limit = MAX_SOURCE_BYTES["scripts/windows/sfai.cmd"]
    if len(data) > limit:
        errors.append("staged wrapper exceeds the conservative maximum size")
        return errors
    text = data.decode("utf-8", errors="replace")
    missing = sorted(name for name, needle in markers.items() if needle not in text)
    if missing:
        errors.append("staged wrapper is missing required semantic markers: " + ",".join(missing))
    return errors


_SOURCE_VALIDATORS: Mapping[str, str] = {
    "config/profiles/inspect.yaml": "profile",
    "scripts/windows/sfai.cmd": "wrapper",
}


def _validate_source_bytes(
    relative_source: str, data: bytes, markers: Mapping[str, str]
) -> list[str]:
    kind = _SOURCE_VALIDATORS[relative_source]
    if kind == "profile":
        return validate_inspect_profile_bytes(data)
    return validate_wrapper_bytes(data, markers)


# --------------------------------------------------------------------------- #
# Per-file evaluation
# --------------------------------------------------------------------------- #


@dataclass
class FileEvaluation:
    relative_source: str
    relative_destination: str
    saved_operation: str = "blocked"
    saved_source_sha256: str | None = None
    saved_destination_sha256: str | None = None
    source_sha256: str | None = None
    current_destination_sha256: str | None = None
    revalidated_operation: str = "blocked"
    mutation_required: bool = False
    expected_post_change_sha256: str | None = None
    narrowed_to_no_op: bool = False
    blockers: list[str] = field(default_factory=list)
    source_bytes: bytes | None = None
    destination: Path | None = None
    parent: dict[str, Any] = field(default_factory=dict)
    created_directories: list[str] = field(default_factory=list)
    compensated_directories: list[str] = field(default_factory=list)

    def parent_record(self) -> dict[str, Any]:
        record = dict(self.parent)
        record["created_directories"] = list(self.created_directories)
        record["compensated_directories"] = [
            item
            for item in AUTHORIZED_PARENT_DIRECTORIES
            if item in set(self.compensated_directories)
        ]
        record["remaining_created_directories"] = [
            item for item in self.created_directories
            if item not in set(self.compensated_directories)
        ]
        return record

    def public(self) -> dict[str, Any]:
        return {
            "relative_source": self.relative_source,
            "relative_destination": self.relative_destination,
            "saved_operation": self.saved_operation,
            "revalidated_operation": self.revalidated_operation,
            "mutation_required": self.mutation_required,
            "narrowed_to_no_op": self.narrowed_to_no_op,
            "source_sha256": self.source_sha256,
            "saved_destination_sha256": self.saved_destination_sha256,
            "current_pre_change_sha256": self.current_destination_sha256,
            "expected_post_change_sha256": self.expected_post_change_sha256,
            "destination_parent": self.parent_record(),
            "blockers": list(self.blockers),
        }


def _evaluate_file(
    *,
    index: int,
    saved_operation: Mapping[str, Any],
    fresh_operation: Mapping[str, Any],
    staged_source_root: Path,
    durable_runtime_root: Path,
    markers: Mapping[str, str],
    parent_evaluator: Callable[[Path, str], dict[str, Any]],
) -> FileEvaluation:
    relative_source, relative_destination = ALLOWLIST[index]
    evaluation = FileEvaluation(
        relative_source=relative_source,
        relative_destination=relative_destination,
        saved_operation=str(saved_operation.get("operation") or "blocked"),
        saved_source_sha256=saved_operation.get("source_sha256"),
        saved_destination_sha256=saved_operation.get("existing_destination_sha256"),
    )
    source = staged_source_root / relative_source
    destination = durable_runtime_root / relative_destination
    evaluation.destination = destination
    blockers = evaluation.blockers

    if evaluation.saved_operation not in SAVED_OPERATIONS:
        blockers.append(f"{relative_destination}: saved operation is not executable")

    # Containment and reparse safety across the full chain, both sides.
    if not _contained(source, staged_source_root):
        blockers.append(f"{relative_source}: source path escapes the staged source root")
    if not _contained(destination, durable_runtime_root):
        blockers.append(
            f"{relative_destination}: destination path escapes the durable runtime root"
        )
    source_reparse = reparse_chain_components(staged_source_root, relative_source)
    destination_reparse = reparse_chain_components(durable_runtime_root, relative_destination)
    if source_reparse:
        blockers.append(
            f"{relative_source}: source path chain contains a reparse point or symlink "
            f"({','.join(source_reparse)})"
        )
    if destination_reparse:
        blockers.append(
            f"{relative_destination}: destination path chain contains a reparse point or "
            f"symlink ({','.join(destination_reparse)})"
        )

    # Source must be a present, regular, size-bounded, content-valid file.
    try:
        source_is_file = source.is_file()
    except OSError:
        source_is_file = False
    if not source_is_file:
        blockers.append(f"{relative_source}: staged source is missing or not a regular file")
    elif not blockers:
        try:
            data = source.read_bytes()
        except OSError as exc:
            data = None
            blockers.append(f"{relative_source}: staged source is unreadable ({sanitize(exc)})")
        if data is not None:
            evaluation.source_bytes = data
            evaluation.source_sha256 = _sha256_bytes(data)
            evaluation.expected_post_change_sha256 = evaluation.source_sha256
            blockers.extend(
                f"{relative_source}: {message}"
                for message in _validate_source_bytes(relative_source, data, markers)
            )

    # The exact fixed destination parent must be present, or safely creatable under
    # the authorized chain, revalidated against the accepted plan.
    parent_record, parent_blockers = _revalidate_parent(
        relative_destination=relative_destination,
        saved_parent=saved_operation.get("destination_parent"),
        current_parent=parent_evaluator(durable_runtime_root, relative_destination),
    )
    evaluation.parent = parent_record
    blockers.extend(parent_blockers)
    destination_exists = destination.exists()
    if destination_exists and not destination.is_file():
        blockers.append(
            f"{relative_destination}: destination exists and is not a regular file"
        )
    if destination_exists and destination.is_file() and not destination_reparse:
        evaluation.current_destination_sha256 = _sha256_file(destination)
        if evaluation.current_destination_sha256 is None:
            blockers.append(f"{relative_destination}: destination sha256 is unavailable")

    # The maintained PR305 planner must agree that this file is safe right now.
    fresh_status = str(fresh_operation.get("operation") or "blocked")
    if fresh_status == "blocked":
        blockers.append(
            f"{relative_destination}: maintained PR305 re-evaluation blocked this operation"
        )

    # Source drift from the accepted plan blocks the whole transaction.
    if (
        evaluation.source_sha256 is not None
        and evaluation.saved_source_sha256 is not None
        and evaluation.source_sha256 != evaluation.saved_source_sha256
    ):
        blockers.append(f"{relative_source}: staged source drifted from the accepted plan")

    if blockers:
        evaluation.revalidated_operation = "blocked"
        return evaluation

    evaluation.revalidated_operation, narrowed, reason = _revalidate_operation(
        saved_operation=evaluation.saved_operation,
        saved_destination_sha256=evaluation.saved_destination_sha256,
        source_sha256=evaluation.source_sha256,
        current_destination_sha256=evaluation.current_destination_sha256,
    )
    evaluation.narrowed_to_no_op = narrowed
    if evaluation.revalidated_operation == "blocked":
        blockers.append(f"{relative_destination}: {reason}")
    evaluation.mutation_required = evaluation.revalidated_operation in {
        "create_required",
        "replace_required",
    }
    return evaluation


def _revalidate_parent(
    *,
    relative_destination: str,
    saved_parent: Any,
    current_parent: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Revalidate the exact fixed parent chain and apply safe narrowing.

    The saved parent metadata is an authorization ceiling and a historical claim.
    A saved chain may only shrink to the still-missing exact suffix; it can never
    grow, move, or reach a directory outside the fixed contract.
    """
    expected_relative = PARENT_RELATIVE[relative_destination]
    creation_allowed = PARENT_CREATION_ALLOWED[relative_destination]
    blockers: list[str] = []
    record: dict[str, Any] = {
        "contract_version": PARENT_CONTRACT_VERSION,
        "relative_path": expected_relative,
        "creation_allowed": creation_allowed,
        "saved_state": None,
        "revalidated_state": "blocked",
        "saved_creation_chain": [],
        "revalidated_creation_chain": [],
        "narrowed": False,
        "preparation_result": "not_required",
        "compensation_result": "not_required",
        "blockers": [],
    }

    def finish() -> tuple[dict[str, Any], list[str]]:
        record["blockers"] = [sanitize(item) for item in blockers]
        return record, blockers

    if not isinstance(saved_parent, dict):
        blockers.append(
            f"{expected_relative}: saved plan carries no destination-parent contract; "
            "regenerate the PR305 plan"
        )
        return finish()
    if saved_parent.get("contract_version") != PARENT_CONTRACT_VERSION:
        blockers.append(f"{expected_relative}: saved destination-parent contract version mismatch")
    if saved_parent.get("relative_path") != expected_relative:
        blockers.append(f"{expected_relative}: saved destination-parent path mismatch")
    if bool(saved_parent.get("creation_allowed")) is not creation_allowed:
        blockers.append(f"{expected_relative}: saved parent creation permission mismatch")

    saved_state = saved_parent.get("state")
    saved_chain = list(saved_parent.get("creation_chain") or [])
    record["saved_state"] = saved_state
    record["saved_creation_chain"] = saved_chain
    if saved_state not in {"present", "create_required"}:
        blockers.append(f"{expected_relative}: saved parent state is not executable")
    if saved_chain and not creation_allowed:
        blockers.append(f"{expected_relative}: saved plan authorizes an unpermitted parent create")
    if any(item not in AUTHORIZED_PARENT_DIRECTORIES for item in saved_chain):
        blockers.append(f"{expected_relative}: saved parent chain leaves the exact allowlist")
    if blockers:
        return finish()

    current_state = str(current_parent.get("state") or "blocked")
    current_chain = list(current_parent.get("creation_chain") or [])
    if current_state == "blocked":
        blockers.extend(
            f"{expected_relative}: {item}" for item in (current_parent.get("blockers") or [])
        )
        return finish()

    if saved_state == "present":
        if current_state != "present":
            blockers.append(
                f"{expected_relative}: parent was present in the accepted plan but is no "
                "longer a safe existing directory; fresh PR304 evidence and a new PR305 "
                "plan are required"
            )
            return finish()
        record["revalidated_state"] = "present"
        return finish()

    # Saved create_required: narrow to the remaining exact missing suffix.
    if current_state == "present":
        record["revalidated_state"] = "present"
        record["narrowed"] = True
        return finish()
    if any(item not in saved_chain for item in current_chain):
        blockers.append(
            f"{expected_relative}: current parent chain exceeds the accepted plan; a new "
            "PR305 plan is required"
        )
        return finish()
    if current_chain != [item for item in saved_chain if item in current_chain]:
        blockers.append(f"{expected_relative}: current parent chain ordering mismatch")
        return finish()
    record["revalidated_state"] = "create_required"
    record["revalidated_creation_chain"] = current_chain
    record["narrowed"] = current_chain != saved_chain
    return finish()


def _revalidate_operation(
    *,
    saved_operation: str,
    saved_destination_sha256: str | None,
    source_sha256: str | None,
    current_destination_sha256: str | None,
) -> tuple[str, bool, str]:
    """Apply the saved-plan-as-authorization-ceiling narrowing rules."""
    matches_source = (
        current_destination_sha256 is not None and current_destination_sha256 == source_sha256
    )
    if saved_operation == "create_required":
        if current_destination_sha256 is None:
            return "create_required", False, ""
        if matches_source:
            return "no_change", True, ""
        return (
            "blocked",
            False,
            "planned create found a conflicting destination; fresh PR304 evidence and a new "
            "PR305 plan are required",
        )
    if saved_operation == "replace_required":
        if current_destination_sha256 is None:
            return (
                "blocked",
                False,
                "planned replacement destination disappeared; fresh PR304 evidence and a new "
                "PR305 plan are required",
            )
        if matches_source:
            return "no_change", True, ""
        if current_destination_sha256 == saved_destination_sha256:
            return "replace_required", False, ""
        return (
            "blocked",
            False,
            "planned replacement destination changed to a third hash; fresh PR304 evidence and "
            "a new PR305 plan are required",
        )
    if saved_operation == "no_change":
        if current_destination_sha256 is None:
            return (
                "blocked",
                False,
                "planned no-change destination disappeared; fresh PR304 evidence and a new "
                "PR305 plan are required",
            )
        if matches_source:
            return "no_change", False, ""
        return (
            "blocked",
            False,
            "planned no-change destination no longer matches the staged source; fresh PR304 "
            "evidence and a new PR305 plan are required",
        )
    return "blocked", False, "saved operation is not executable"


# --------------------------------------------------------------------------- #
# Preparation, commit, and bounded same-run compensation
# --------------------------------------------------------------------------- #


@dataclass
class _Prepared:
    evaluation: FileEvaluation
    destination: Path
    operation: str
    source_sha256: str
    pre_change_sha256: str | None = None
    temp_path: Path | None = None
    backup_path: Path | None = None
    backup_relative_path: str | None = None
    backup_sha256: str | None = None
    committed: bool = False
    post_change_sha256: str | None = None
    commit_result: str = "not_attempted"
    hash_verification: str = "not_attempted"
    temporary_preparation: str = "not_prepared"


def _fsync_write(handle_fd: int, data: bytes) -> None:
    os.write(handle_fd, data)
    with suppress(OSError, AttributeError):  # pragma: no cover - platform dependent
        os.fsync(handle_fd)


#: ``os.open`` defaults to text mode on Windows, where the C runtime rewrites "\n"
#: as "\r\n" on write. That would silently corrupt backups, temporary files, and
#: restores, so binary mode is requested explicitly. ``os.O_BINARY`` does not exist
#: on POSIX, where the flag is unnecessary and resolves to 0.
_O_BINARY = getattr(os, "O_BINARY", 0)


def _exclusive_write(path: Path, data: bytes) -> None:
    """Create a new file exclusively and write exactly ``data``, byte for byte."""
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | _O_BINARY, 0o600)
    try:
        _fsync_write(fd, data)
    finally:
        os.close(fd)


def _create_backup(
    prepared: _Prepared, *, stamp: str, plan_short: str, durable_runtime_root: Path
) -> None:
    destination = prepared.destination
    data = destination.read_bytes()
    prepared.pre_change_sha256 = _sha256_bytes(data)
    base = f"{destination.name}.{BACKUP_MARKER}-{stamp}-{plan_short}"
    for attempt in range(64):
        suffix = "" if attempt == 0 else f"-{attempt:02d}"
        candidate = destination.parent / f"{base}{suffix}.bak"
        try:
            _exclusive_write(candidate, data)
        except FileExistsError:
            continue
        prepared.backup_path = candidate
        prepared.backup_sha256 = _sha256_file(candidate)
        prepared.backup_relative_path = _relative_to_root(candidate, durable_runtime_root)
        break
    else:  # pragma: no cover - defensive
        raise OSError("no collision-free backup name was available")
    if prepared.backup_sha256 != prepared.pre_change_sha256:
        raise OSError("backup hash verification failed")


def _create_temp(prepared: _Prepared, *, data: bytes) -> None:
    destination = prepared.destination
    for _ in range(64):
        candidate = destination.parent / f"{destination.name}.{TEMP_MARKER}-{uuid.uuid4().hex[:12]}"
        try:
            _exclusive_write(candidate, data)
        except FileExistsError:  # pragma: no cover - defensive
            continue
        prepared.temp_path = candidate
        break
    else:  # pragma: no cover - defensive
        raise OSError("no collision-free temporary name was available")
    if _sha256_file(prepared.temp_path) != prepared.source_sha256:
        raise OSError("temporary file hash verification failed")
    prepared.temporary_preparation = "prepared_and_verified"


def _relative_to_root(path: Path, root: Path) -> str:
    """Fixed relative path under the durable runtime root; never an absolute path."""
    try:
        return Path(_norm(path) or "").relative_to(Path(_norm(root) or "")).as_posix()
    except ValueError:  # pragma: no cover - containment already enforced
        return path.name


def _discard_temp(prepared: _Prepared) -> None:
    if prepared.temp_path is None:
        return
    with suppress(OSError):  # pragma: no cover - best effort
        prepared.temp_path.unlink()
    prepared.temp_path = None
    prepared.temporary_preparation = "removed_without_commit"


def _compensate(committed: list[_Prepared], durable_runtime_root: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    complete = True
    for prepared in reversed(committed):
        entry: dict[str, Any] = {
            "relative_destination": _relative_to_root(prepared.destination, durable_runtime_root),
            "committed_operation": prepared.operation,
        }
        if prepared.operation == "replace_required":
            entry["action"] = "restore_from_execution_backup"
            entry.update(_restore_from_backup(prepared))
        else:
            entry["action"] = "remove_execution_created_file"
            entry.update(_remove_created(prepared))
        if entry.get("result") not in {"restored", "removed"}:
            complete = False
        entries.append(entry)
    return {
        "attempted": True,
        "complete": complete,
        "entries": entries,
        "scope": "files committed by this exact execution only",
    }


def _restore_from_backup(prepared: _Prepared) -> dict[str, Any]:
    if prepared.backup_path is None or prepared.backup_sha256 is None:
        return {"result": "refused_missing_verified_backup"}
    if _sha256_file(prepared.backup_path) != prepared.backup_sha256:
        return {"result": "refused_backup_hash_mismatch"}
    try:
        data = prepared.backup_path.read_bytes()
        restore = prepared.destination.parent / (
            f"{prepared.destination.name}.{TEMP_MARKER}-restore-{uuid.uuid4().hex[:12]}"
        )
        _exclusive_write(restore, data)
        if _sha256_file(restore) != prepared.backup_sha256:
            restore.unlink(missing_ok=True)
            return {"result": "failed_restore_hash_mismatch"}
        os.replace(restore, prepared.destination)
    except OSError as exc:
        return {"result": "failed", "error": sanitize_exception(exc)}
    current = _sha256_file(prepared.destination)
    if current != prepared.backup_sha256:
        return {"result": "failed_post_restore_hash_mismatch", "restored_sha256": current}
    return {"result": "restored", "restored_sha256": current}


def _remove_created(prepared: _Prepared) -> dict[str, Any]:
    if prepared.pre_change_sha256 is not None:
        return {"result": "refused_destination_existed_before_execution"}
    current = _sha256_file(prepared.destination)
    if current is None:
        return {"result": "removed", "removed_sha256": None}
    if current != prepared.source_sha256:
        return {"result": "refused_drifted_created_file", "current_sha256": current}
    try:
        prepared.destination.unlink()
    except OSError as exc:
        return {"result": "failed", "error": sanitize_exception(exc)}
    if prepared.destination.exists():  # pragma: no cover - defensive
        return {"result": "failed_still_present"}
    return {"result": "removed", "removed_sha256": current}


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #


def _load_json_object(path: Path) -> tuple[dict[str, Any] | None, list[str], str | None]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return None, [f"{path.name}: unreadable ({exc.__class__.__name__})"], None
    digest = _sha256_bytes(raw)
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except Exception as exc:
        return None, [f"{path.name}: invalid JSON ({exc.__class__.__name__})"], digest
    if not isinstance(payload, dict):
        return None, [f"{path.name}: JSON must be an object"], digest
    return payload, [], digest


def _plan_contract_errors(packet: Mapping[str, Any]) -> list[str]:
    """Delegate to the maintained pure executable-plan contract."""
    return saved_plan_executable_contract_errors(packet)


def execute_windows_runtime_reconcile(
    packet_path: Path | str,
    artifact_paths: Sequence[Path | str],
    *,
    staged_source_root: Path | str,
    durable_runtime_root: Path | str,
    confirm_plan_sha256: str,
    data_dir: Path | str,
    validators: ReconcileValidators | None = None,
    clock: Callable[[], datetime] | None = None,
    failure_hook: Callable[[str, str], str | None] | None = None,
) -> dict[str, Any]:
    """Execute the governed two-file Windows runtime reconciliation.

    Mutation is reachable only after the platform, packet, artifact, root,
    allowlist, confirmation, content, and current-state gates all pass.  Nothing
    outside the fixed allowlist is ever touched.
    """
    if not is_windows():
        return _envelope(
            status=STATUS_UNSUPPORTED,
            reason="windows runtime reconciliation execution is unsupported on this host",
            plan={"confirmation_matched": False},
            operations=[],
            platform={"system": platform.system().lower()},
        )

    hook = failure_hook or (lambda phase, target: None)
    moment = _now(clock)

    # --- Confirmation format (before anything is read or evaluated) --------- #
    if not is_plan_sha256(confirm_plan_sha256):
        return _envelope(
            status=STATUS_BLOCKED,
            reason="confirmation must be exactly 64 lowercase hexadecimal characters",
            blockers=["missing or malformed --confirm-plan-sha256"],
            plan={"confirmation_matched": False},
            operations=[],
        )

    # --- Saved PR305 packet ------------------------------------------------- #
    packet, packet_errors, packet_file_sha256 = _load_json_object(Path(packet_path))
    if packet is None:
        return _envelope(
            status=STATUS_BLOCKED,
            reason="saved PR305 packet could not be loaded",
            blockers=packet_errors,
            plan={"confirmation_matched": False, "artifact_file_sha256": packet_file_sha256},
            operations=[],
        )

    active = validators or load_validators()
    plan_errors = [sanitize(item) for item in active.pr305_errs(packet)]
    plan_errors.extend(_plan_contract_errors(packet))
    if plan_errors:
        return _envelope(
            status=STATUS_BLOCKED,
            reason="saved PR305 packet failed maintained acceptance or contract validation",
            blockers=plan_errors[:8],
            plan={"confirmation_matched": False, "artifact_file_sha256": packet_file_sha256},
            operations=[],
        )

    canonical_sha256 = canonical_plan_sha256(packet)
    if not confirmation_matches(confirm_plan_sha256, canonical_sha256):
        return _envelope(
            status=STATUS_BLOCKED,
            reason="confirmation does not match the accepted plan canonical SHA-256",
            blockers=["plan-hash confirmation mismatch"],
            plan={
                "confirmation_matched": False,
                "canonical_packet_sha256": canonical_sha256,
                "artifact_file_sha256": packet_file_sha256,
            },
            operations=[],
        )

    plan_block = {
        "canonical_packet_sha256": canonical_sha256,
        "artifact_file_sha256": packet_file_sha256,
        "confirmation_matched": True,
        "confirmation_scope": "recipe_specific_plan_hash_authorization_only",
        "plan_mode": PLAN_MODE,
        "plan_status": packet.get("status"),
    }

    # --- Fresh PR304 evidence ---------------------------------------------- #
    evidence, evidence_errors = _validate_artifacts(artifact_paths, active)
    blockers = list(evidence_errors)

    # --- Explicit roots must match the accepted plan ------------------------ #
    source_root = Path(staged_source_root).expanduser()
    runtime_root = Path(durable_runtime_root).expanduser()
    roots_block, root_errors = _validate_roots(source_root, runtime_root, packet)
    blockers.extend(root_errors)
    blockers.extend(
        f"durable runtime root: {item}" for item in active.pr305_root_safe(runtime_root)
    )

    if blockers:
        return _envelope(
            status=STATUS_BLOCKED,
            reason="fresh evidence or explicit roots did not satisfy the accepted plan",
            blockers=blockers[:8],
            plan=plan_block,
            evidence=evidence,
            roots=roots_block,
            operations=[],
        )

    # --- Fresh PR305 re-evaluation and current-state gates ------------------ #
    fresh_operations = [
        active.pr305_operation(source_root, runtime_root, rel_src, rel_dst)
        for rel_src, rel_dst in ALLOWLIST
    ]
    saved_operations = list(packet.get("operations") or [])
    evaluations = [
        _evaluate_file(
            index=index,
            saved_operation=saved_operations[index],
            fresh_operation=fresh_operations[index],
            staged_source_root=source_root,
            durable_runtime_root=runtime_root,
            markers=active.wrapper_markers,
            parent_evaluator=active.pr305_destination_parent,
        )
        for index in range(len(ALLOWLIST))
    ]

    context = _ExecutionContext(
        evaluations=evaluations,
        plan_block=plan_block,
        evidence=evidence,
        roots_block=roots_block,
        durable_runtime_root=runtime_root,
        data_dir=data_dir,
        moment=moment,
        canonical_sha256=canonical_sha256,
        hook=hook,
    )

    transaction_blockers = [item for evaluation in evaluations for item in evaluation.blockers]
    if transaction_blockers:
        return context.finish(
            status=STATUS_BLOCKED,
            reason=(
                "transaction blocked before preparation; fresh PR304 evidence and a new PR305 "
                "plan are required"
            ),
            blockers=transaction_blockers,
        )

    if not any(evaluation.mutation_required for evaluation in evaluations):
        return context.finish(
            status=STATUS_NO_CHANGE,
            reason="both allowlisted destinations already match the validated staged sources",
        )

    return context.run()


@dataclass
class _ExecutionContext:
    evaluations: list[FileEvaluation]
    plan_block: dict[str, Any]
    evidence: dict[str, Any]
    roots_block: dict[str, Any]
    durable_runtime_root: Path
    data_dir: Path | str
    moment: datetime
    canonical_sha256: str
    hook: Callable[[str, str], str | None]
    prepared: list[_Prepared] = field(default_factory=list)
    committed: list[_Prepared] = field(default_factory=list)
    created_directories: list[tuple[str, Path, FileEvaluation]] = field(default_factory=list)
    directory_compensation: dict[str, Any] = field(
        default_factory=lambda: {"attempted": False, "complete": True, "entries": []}
    )
    compensation: dict[str, Any] = field(default_factory=lambda: {"attempted": False})
    post_verification: dict[str, Any] = field(
        default_factory=lambda: {"status": "not_run", "entries": []}
    )
    warnings: list[str] = field(default_factory=list)
    all_prepared_before_commit: bool = False

    # -- orchestration ---------------------------------------------------- #

    def run(self) -> dict[str, Any]:
        stamp = _stamp(self.moment)
        plan_short = self.canonical_sha256[:8]
        try:
            self._prepare(stamp=stamp, plan_short=plan_short)
        except (_InjectedFailure, OSError) as exc:
            self._discard_all_temps()
            return self._fail(
                exc,
                blocked_reason="preparation failed before any destination mutation",
                compensated_reason=(
                    "preparation failed after authorized parent directories were created; "
                    "bounded compensation ran"
                ),
            )
        self.all_prepared_before_commit = True

        try:
            self._commit()
        except (_InjectedFailure, OSError) as exc:
            self._discard_all_temps()
            return self._fail(
                exc,
                blocked_reason="commit refused before any destination mutation",
                compensated_reason=(
                    "commit failed after partial mutation; bounded compensation ran"
                ),
            )

        self._post_verify()
        if self.post_verification.get("status") == "failed":
            return self.finish(
                status=STATUS_VERIFICATION_FAILED,
                reason=(
                    "all commits succeeded but the separate post-verification phase failed; "
                    "backups are retained and no automatic restoration ran"
                ),
            )

        mutated = sum(1 for prepared in self.committed if prepared.committed)
        no_ops = sum(
            1 for item in self.evaluations if item.revalidated_operation == "no_change"
        )
        status = STATUS_EXECUTED if no_ops == 0 else STATUS_PARTIAL_EXECUTED
        reason = (
            "both allowlisted destinations were reconciled"
            if status == STATUS_EXECUTED
            else f"{mutated} allowlisted destination(s) reconciled; {no_ops} already compliant"
        )
        return self.finish(status=status, reason=reason)

    def _fail(
        self, exc: BaseException, *, blocked_reason: str, compensated_reason: str
    ) -> dict[str, Any]:
        """Compensate files then directories, and report the honest terminal status."""
        failure = (
            sanitize(exc) if isinstance(exc, _InjectedFailure) else sanitize_exception(exc)
        )
        if self.committed:
            self.compensation = _compensate(self.committed, self.durable_runtime_root)
        if self.created_directories:
            self.directory_compensation = _compensate_directories(
                self.created_directories, self.durable_runtime_root
            )
        if not self.committed and not self.created_directories:
            return self.finish(status=STATUS_BLOCKED, reason=blocked_reason, blockers=[failure])
        complete = bool(self.compensation.get("complete", True)) and bool(
            self.directory_compensation.get("complete", True)
        )
        status = (
            STATUS_FAILED_COMPENSATED if complete else STATUS_FAILED_COMPENSATION_INCOMPLETE
        )
        return self.finish(status=status, reason=compensated_reason, blockers=[failure])

    # -- phases ------------------------------------------------------------ #

    def _create_parent_directories(self) -> None:
        """Create only the exact authorized missing parent components, one at a time."""
        root = self.durable_runtime_root
        for evaluation in self.evaluations:
            if not evaluation.mutation_required:
                continue
            parent = evaluation.parent
            if parent.get("revalidated_state") != "create_required":
                continue
            if not parent.get("creation_allowed"):
                raise OSError("parent creation is not authorized for this destination")
            for relative in parent.get("revalidated_creation_chain") or []:
                if relative not in AUTHORIZED_PARENT_DIRECTORIES:
                    raise OSError("parent component is outside the exact allowlist")
                self._fail_if_injected("parent_directory", relative)
                node = root / relative
                prefix = node.parent
                if not prefix.is_dir() or _is_reparse(prefix):
                    raise OSError("parent prefix is no longer a safe existing directory")
                if not _contained(node, root):
                    raise OSError("parent component escapes the durable runtime root")
                try:
                    os.mkdir(node)
                    owned = True
                except FileExistsError:
                    # Benign race: accept only if it appeared as the exact safe directory.
                    owned = False
                if not node.is_dir() or _is_reparse(node):
                    raise OSError("parent component is not a safe directory after creation")
                if owned:
                    self.created_directories.append((relative, node, evaluation))
                    evaluation.created_directories.append(relative)
            parent["preparation_result"] = "created_and_verified"

    def _prepare(self, *, stamp: str, plan_short: str) -> None:
        self._create_parent_directories()
        for evaluation in self.evaluations:
            if not evaluation.mutation_required:
                continue
            assert evaluation.destination is not None
            assert evaluation.source_sha256 is not None
            prepared = _Prepared(
                evaluation=evaluation,
                destination=evaluation.destination,
                operation=evaluation.revalidated_operation,
                source_sha256=evaluation.source_sha256,
            )
            self.prepared.append(prepared)
            if prepared.operation == "replace_required":
                self._fail_if_injected("backup", evaluation.relative_destination)
                _create_backup(
                    prepared,
                    stamp=stamp,
                    plan_short=plan_short,
                    durable_runtime_root=self.durable_runtime_root,
                )
            self._fail_if_injected("temp", evaluation.relative_destination)
            assert evaluation.source_bytes is not None
            _create_temp(prepared, data=evaluation.source_bytes)
        for prepared in self.prepared:
            if prepared.temporary_preparation != "prepared_and_verified":
                raise OSError("temporary preparation verification failed")
            if prepared.operation == "replace_required" and prepared.backup_sha256 is None:
                raise OSError("backup verification failed")

    def _commit(self) -> None:
        for prepared in self.prepared:
            relative = prepared.evaluation.relative_destination
            self._fail_if_injected("commit", relative)
            if prepared.operation == "create_required" and prepared.destination.exists():
                _discard_temp(prepared)
                prepared.commit_result = "refused_destination_appeared"
                raise OSError("destination appeared between preparation and commit")
            assert prepared.temp_path is not None
            os.replace(prepared.temp_path, prepared.destination)
            prepared.temp_path = None
            prepared.temporary_preparation = "committed"
            prepared.committed = True
            prepared.commit_result = "committed"
            self.committed.append(prepared)
            self._fail_if_injected("verify", relative)
            prepared.post_change_sha256 = _sha256_file(prepared.destination)
            if prepared.post_change_sha256 != prepared.source_sha256:
                prepared.hash_verification = "failed"
                raise OSError("direct post-commit hash verification failed")
            prepared.hash_verification = "passed"

    def _post_verify(self) -> None:
        entries: list[dict[str, Any]] = []
        failed = False
        for prepared in self.committed:
            relative = prepared.evaluation.relative_destination
            injected = self.hook("post_verify", relative)
            current = _sha256_file(prepared.destination)
            ok = current == prepared.source_sha256 and not injected
            failed = failed or not ok
            entries.append(
                {
                    "relative_destination": relative,
                    "expected_sha256": prepared.source_sha256,
                    "observed_sha256": current,
                    "result": "passed" if ok else "failed",
                }
            )
        self.post_verification = {
            "status": "failed" if failed else ("passed" if entries else "not_run"),
            "entries": entries,
        }
        if failed:
            self.warnings.append(
                "post-verification failed after successful commits; backups retained and no "
                "automatic restoration was attempted"
            )

    # -- helpers ----------------------------------------------------------- #

    def _fail_if_injected(self, phase: str, target: str) -> None:
        message = self.hook(phase, target)
        if message:
            raise _InjectedFailure(f"{phase} phase failure: {sanitize(message)}")

    def _discard_all_temps(self) -> None:
        for prepared in self.prepared:
            if not prepared.committed:
                _discard_temp(prepared)

    def finish(
        self,
        *,
        status: str,
        reason: str,
        blockers: Sequence[str] = (),
    ) -> dict[str, Any]:
        operations = self._operation_records()
        for evaluation in self.evaluations:
            if evaluation.compensated_directories:
                evaluation.parent["compensation_result"] = (
                    "removed"
                    if self.directory_compensation.get("complete")
                    else "incomplete"
                )
            elif self.directory_compensation.get("attempted"):
                evaluation.parent["compensation_result"] = "attempted"
        created_any = bool(self.created_directories)
        safety = safety_ledger(
            mutation_performed=(
                any(item["mutation_performed"] for item in operations) or created_any
            ),
            file_create_executed=any(
                item["mutation_performed"] and item["revalidated_operation"] == "create_required"
                for item in operations
            ),
            file_replace_executed=any(
                item["mutation_performed"] and item["revalidated_operation"] == "replace_required"
                for item in operations
            ),
            backup_created=any(item["backup_created"] for item in operations),
            atomic_replace_executed=any(item["mutation_performed"] for item in operations),
            compensation_executed=bool(self.compensation.get("attempted")),
            parent_directory_create_executed=created_any,
            parent_directory_compensation_executed=bool(
                self.directory_compensation.get("attempted")
            ),
        )
        receipt = write_execution_receipt(
            data_dir=self.data_dir,
            status=status,
            reason=reason,
            moment=self.moment,
            plan=self.plan_block,
            evidence=self.evidence,
            roots=self.roots_block,
            operations=operations,
            compensation=self.compensation,
            directory_compensation=self.directory_compensation,
            post_verification=self.post_verification,
            transaction={
                "all_prepared_before_commit": self.all_prepared_before_commit,
                "blocked_before_preparation": not self.prepared and status == STATUS_BLOCKED,
                "commit_order": [
                    prepared.evaluation.relative_destination for prepared in self.committed
                ],
            },
            safety=safety,
            blockers=[sanitize(item) for item in blockers],
            warnings=[sanitize(item) for item in self.warnings],
        )
        return _envelope(
            status=status,
            reason=reason,
            blockers=[sanitize(item) for item in blockers],
            warnings=list(self.warnings),
            safety=safety,
            plan=self.plan_block,
            evidence=self.evidence,
            roots=self.roots_block,
            operations=operations,
            compensation=self.compensation,
            directory_compensation=self.directory_compensation,
            post_verification=self.post_verification,
            receipt_id=receipt["receipt_id"],
            receipt_path=receipt["receipt_path"],
        )

    def _operation_records(self) -> list[dict[str, Any]]:
        by_destination = {
            prepared.evaluation.relative_destination: prepared for prepared in self.prepared
        }
        records: list[dict[str, Any]] = []
        for evaluation in self.evaluations:
            prepared = by_destination.get(evaluation.relative_destination)
            record = evaluation.public()
            record.update(
                {
                    "backup_created": bool(prepared and prepared.backup_path is not None),
                    "backup_relative_path": prepared.backup_relative_path if prepared else None,
                    "backup_sha256": prepared.backup_sha256 if prepared else None,
                    "temporary_preparation": (
                        prepared.temporary_preparation if prepared else "not_required"
                    ),
                    "commit_result": (
                        prepared.commit_result if prepared else "not_required"
                    ),
                    "hash_verification": (
                        prepared.hash_verification if prepared else "not_required"
                    ),
                    "post_change_sha256": prepared.post_change_sha256 if prepared else None,
                    "mutation_performed": bool(prepared and prepared.committed),
                }
            )
            records.append(record)
        return records


def _compensate_directories(
    created: list[tuple[str, Path, FileEvaluation]], durable_runtime_root: Path
) -> dict[str, Any]:
    """Remove only this execution's own empty authorized directories, in reverse."""
    entries: list[dict[str, Any]] = []
    complete = True
    for relative, node, evaluation in reversed(created):
        entry: dict[str, Any] = {
            "relative_directory": relative,
            "action": "remove_created_directory",
        }
        if relative not in AUTHORIZED_PARENT_DIRECTORIES:
            entry["result"] = "refused_outside_authorized_chain"
        elif not _contained(node, durable_runtime_root):
            entry["result"] = "refused_outside_durable_root"
        elif _is_reparse(node):
            entry["result"] = "refused_reparse_point"
        elif not node.is_dir():
            entry["result"] = "refused_not_a_directory"
        elif any(node.iterdir()):
            entry["result"] = "refused_not_empty"
        else:
            try:
                os.rmdir(node)
                entry["result"] = "removed"
                evaluation.compensated_directories.append(relative)
            except OSError as exc:
                entry["result"] = "failed"
                entry["error"] = sanitize_exception(exc)
        if entry["result"] != "removed":
            complete = False
        entries.append(entry)
    return {
        "attempted": True,
        "complete": complete,
        "entries": entries,
        "scope": "empty directories created by this exact execution only",
    }


class _InjectedFailure(RuntimeError):
    """Test-injectable deterministic failure raised inside a governed phase."""


def _validate_artifacts(
    artifact_paths: Sequence[Path | str], validators: ReconcileValidators
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    payloads: list[dict[str, Any]] = []
    digests: list[str] = []
    paths = list(artifact_paths)
    if len(paths) not in (1, 2):
        errors.append("one or two fresh PR304 artifacts are required")
    for value in paths:
        payload, load_errors, digest = _load_json_object(Path(value))
        errors.extend(load_errors)
        if digest is not None:
            digests.append(digest)
        if payload is not None:
            payloads.append(payload)
            errors.extend(
                f"PR304 artifact: {sanitize(item)}" for item in validators.pr304_validate(payload)
            )
    identity_errors: list[str] = []
    if len(payloads) == len(paths) and len(payloads) > 1:
        identity_errors = [
            f"PR304 stable identity: {sanitize(item)}"
            for item in validators.pr304_compare(payloads)
        ]
        errors.extend(identity_errors)
    evidence = {
        "pr304_artifact_count": len(paths),
        "pr304_artifact_sha256": digests,
        "pr304_stable_identity_compared": len(payloads) > 1,
        "pr304_stable_identity_matched": len(payloads) > 1 and not identity_errors,
        "pr305_revalidated": True,
    }
    return evidence, errors


def _validate_roots(
    source_root: Path, runtime_root: Path, packet: Mapping[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    if not source_root.is_absolute():
        errors.append("staged source root must be an absolute path")
    if not runtime_root.is_absolute():
        errors.append("durable runtime root must be an absolute path")
    normalized_source = _norm(source_root)
    normalized_runtime = _norm(runtime_root)
    plan_source = packet.get("staged_source_root")
    plan_runtime = packet.get("durable_runtime_root")
    source_matches = _case(normalized_source or "") == _case(str(plan_source or ""))
    runtime_matches = _case(normalized_runtime or "") == _case(str(plan_runtime or ""))
    if not source_matches:
        errors.append("explicit staged source root does not match the accepted plan")
    if not runtime_matches:
        errors.append("explicit durable runtime root does not match the accepted plan")
    block = {
        "staged_source_root_fingerprint_sha256": root_fingerprint(source_root),
        "durable_runtime_root_fingerprint_sha256": root_fingerprint(runtime_root),
        "plan_staged_source_root_fingerprint_sha256": root_fingerprint(plan_source)
        if plan_source
        else None,
        "plan_durable_runtime_root_fingerprint_sha256": root_fingerprint(plan_runtime)
        if plan_runtime
        else None,
        "roots_match_plan": bool(source_matches and runtime_matches),
    }
    return block, errors


# --------------------------------------------------------------------------- #
# Receipt bundle
# --------------------------------------------------------------------------- #


def write_execution_receipt(
    *,
    data_dir: Path | str,
    status: str,
    reason: str,
    moment: datetime,
    plan: Mapping[str, Any],
    evidence: Mapping[str, Any],
    roots: Mapping[str, Any],
    operations: Sequence[Mapping[str, Any]],
    compensation: Mapping[str, Any],
    directory_compensation: Mapping[str, Any],
    post_verification: Mapping[str, Any],
    transaction: Mapping[str, Any],
    safety: Mapping[str, bool],
    blockers: Sequence[str],
    warnings: Sequence[str],
) -> dict[str, Any]:
    receipt_id = f"wrr_{_stamp(moment)}_{uuid.uuid4().hex[:6]}"
    directory = windows_reconcile_receipt_root(data_dir) / receipt_id
    directory.mkdir(parents=True, exist_ok=False)
    counts = {
        "total_operations": len(operations),
        "no_change": sum(
            1 for item in operations if item.get("revalidated_operation") == "no_change"
        ),
        "created": sum(
            1
            for item in operations
            if item.get("mutation_performed")
            and item.get("revalidated_operation") == "create_required"
        ),
        "replaced": sum(
            1
            for item in operations
            if item.get("mutation_performed")
            and item.get("revalidated_operation") == "replace_required"
        ),
        "blocked": sum(
            1 for item in operations if item.get("revalidated_operation") == "blocked"
        ),
        "mutations": sum(1 for item in operations if item.get("mutation_performed")),
    }
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "mode": RECEIPT_MODE,
        "recipe_id": RECIPE_ID,
        "receipt_id": receipt_id,
        "status": status,
        "reason": sanitize(reason, limit=400),
        "created_at": _iso(moment),
        "plan": dict(plan),
        "evidence": dict(evidence),
        "roots": dict(roots),
        "allowlist": [{"source": a, "destination": b} for a, b in ALLOWLIST],
        "exact_two_file_allowlist": True,
        "operations": [dict(item) for item in operations],
        "summary": counts,
        "transaction": dict(transaction),
        "compensation": dict(compensation),
        "directory_compensation": dict(directory_compensation),
        "destination_parent_contract_version": PARENT_CONTRACT_VERSION,
        "post_verification": dict(post_verification),
        "read_only": not safety.get("mutation_performed", False),
        "mutation_performed": bool(safety.get("mutation_performed", False)),
        "safety": dict(safety),
        "recovery_posture": recovery_posture(),
        "next_verification_commands": next_verification_commands(),
        "blockers": list(blockers),
        "warnings": list(warnings),
    }
    (directory / RECEIPT_MD).write_text(render_receipt_markdown(receipt), encoding="utf-8")
    (directory / RECEIPT_JSON).write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksums = {
        RECEIPT_JSON: _sha256_file(directory / RECEIPT_JSON),
        RECEIPT_MD: _sha256_file(directory / RECEIPT_MD),
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": MANIFEST_KIND,
        "mode": MANIFEST_MODE,
        "receipt_id": receipt_id,
        "recipe_id": RECIPE_ID,
        "status": status,
        "created_at": _iso(moment),
        "files": [RECEIPT_JSON, RECEIPT_MD, RECEIPT_MANIFEST],
        "checksums": checksums,
        "safety": dict(safety),
    }
    (directory / RECEIPT_MANIFEST).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {"receipt_id": receipt_id, "receipt_path": str(directory), "receipt": receipt}


def render_receipt_markdown(receipt: Mapping[str, Any]) -> str:
    lines = [
        "# ShellForgeAI Windows Runtime Reconciliation Receipt",
        "",
        f"- status: {receipt.get('status')}",
        f"- recipe: {receipt.get('recipe_id')}",
        f"- receipt_id: {receipt.get('receipt_id')}",
        f"- created_at: {receipt.get('created_at')}",
        f"- reason: {receipt.get('reason')}",
        "",
        "## Plan confirmation",
        f"- canonical_packet_sha256: {(receipt.get('plan') or {}).get('canonical_packet_sha256')}",
        f"- confirmation_matched: {(receipt.get('plan') or {}).get('confirmation_matched')}",
        f"- confirmation_scope: {(receipt.get('plan') or {}).get('confirmation_scope')}",
        "",
        "## Operations",
    ]
    for item in receipt.get("operations") or []:
        lines.extend(
            [
                f"### {item.get('relative_source')} -> {item.get('relative_destination')}",
                f"- saved_operation: {item.get('saved_operation')}",
                f"- revalidated_operation: {item.get('revalidated_operation')}",
                f"- mutation_performed: {str(bool(item.get('mutation_performed'))).lower()}",
                f"- source_sha256: {item.get('source_sha256')}",
                f"- current_pre_change_sha256: {item.get('current_pre_change_sha256')}",
                f"- expected_post_change_sha256: {item.get('expected_post_change_sha256')}",
                f"- post_change_sha256: {item.get('post_change_sha256')}",
                f"- backup_created: {str(bool(item.get('backup_created'))).lower()}",
                f"- backup_relative_path: {item.get('backup_relative_path')}",
                f"- commit_result: {item.get('commit_result')}",
                f"- hash_verification: {item.get('hash_verification')}",
                "",
            ]
        )
    compensation = receipt.get("compensation") or {}
    lines.extend(
        [
            "## Compensation",
            f"- attempted: {str(bool(compensation.get('attempted'))).lower()}",
            f"- complete: {str(bool(compensation.get('complete'))).lower()}",
            "",
            "## Post verification",
            f"- status: {(receipt.get('post_verification') or {}).get('status')}",
            "",
            "## Safety",
        ]
    )
    for key, value in (receipt.get("safety") or {}).items():
        lines.append(f"- {key}: {str(value).lower()}")
    lines.extend(["", "## Recovery posture"])
    for key, value in (receipt.get("recovery_posture") or {}).items():
        lines.append(f"- {key}: {value}")
    for label, items in (
        ("Blockers", receipt.get("blockers") or []),
        ("Warnings", receipt.get("warnings") or []),
    ):
        if items:
            lines.extend(["", f"## {label}"])
            lines.extend(f"- {item}" for item in items)
    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# Saved receipt validation
# --------------------------------------------------------------------------- #


def resolve_receipt_ref(ref: str, root: Path) -> Path | None:
    raw = str(ref or "").strip()
    if not raw:
        return None
    candidate = Path(raw).expanduser()
    if candidate.is_absolute() or "/" in raw or "\\" in raw:
        resolved = candidate.resolve()
        if resolved.is_file():
            resolved = resolved.parent
    else:
        if ".." in raw:
            return None
        resolved = (root / raw).resolve()
    return resolved


def _as_mapping(value: Any) -> dict[str, Any]:
    """Narrow untrusted saved-artifact JSON to a plain mapping."""
    return dict(value) if isinstance(value, dict) else {}


def _scan_forbidden(payload: Any, findings: list[str], *, path: str = "") -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if str(key).casefold() in FORBIDDEN_RECEIPT_KEYS:
                findings.append(f"forbidden receipt field: {key}")
            _scan_forbidden(value, findings, path=f"{path}.{key}" if path else str(key))
    elif isinstance(payload, list):
        for item in payload:
            _scan_forbidden(item, findings, path=path)
    elif isinstance(payload, str) and _ABSOLUTE_PATH_RE.search(payload):
        findings.append(f"absolute path recorded at {path or '<root>'}")


def _receipt_status_precedence_errors(receipt: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    status = receipt.get("status")
    operations = receipt.get("operations")
    if not isinstance(operations, list):
        return ["operations must be a list"]
    mutated = [item for item in operations if item.get("mutation_performed")]
    no_ops = [item for item in operations if item.get("revalidated_operation") == "no_change"]
    blocked = [item for item in operations if item.get("revalidated_operation") == "blocked"]
    compensation = _as_mapping(receipt.get("compensation"))
    verification = _as_mapping(receipt.get("post_verification"))
    directory_compensation = _as_mapping(receipt.get("directory_compensation"))
    attempted = bool(compensation.get("attempted")) or bool(
        directory_compensation.get("attempted")
    )
    compensation_complete = bool(compensation.get("complete", True)) and bool(
        directory_compensation.get("complete", True)
    )
    if status == STATUS_BLOCKED and mutated:
        errors.append("blocked receipt records mutation")
    if status == STATUS_BLOCKED and any(
        (item.get("destination_parent") or {}).get("created_directories") for item in operations
    ):
        errors.append("blocked receipt records created directories")
    if status == STATUS_NO_CHANGE and (mutated or blocked or len(no_ops) != len(ALLOWLIST)):
        errors.append("no_change receipt state mismatch")
    if status == STATUS_EXECUTED and len(mutated) != len(ALLOWLIST):
        errors.append("executed receipt must record two mutations")
    if status == STATUS_PARTIAL_EXECUTED and not (mutated and no_ops):
        errors.append("partial_executed receipt must record one mutation and one no-op")
    if status == STATUS_FAILED_COMPENSATED and not (attempted and compensation_complete):
        errors.append("failed_compensated receipt must record complete compensation")
    if status == STATUS_FAILED_COMPENSATION_INCOMPLETE and not (
        attempted and not compensation_complete
    ):
        errors.append("failed_compensation_incomplete receipt must record incomplete compensation")
    if status == STATUS_VERIFICATION_FAILED and verification.get("status") != "failed":
        errors.append("verification_failed receipt must record a failed post-verification")
    if attempted and status not in {
        STATUS_FAILED_COMPENSATED,
        STATUS_FAILED_COMPENSATION_INCOMPLETE,
    }:
        errors.append("compensation recorded for a non-compensating status")
    return errors


def _receipt_operation_errors(receipt: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    operations = receipt.get("operations") or []
    pairs = [
        (item.get("relative_source"), item.get("relative_destination")) for item in operations
    ]
    if pairs != list(ALLOWLIST):
        errors.append("operation ordering or allowlist mismatch")
    if receipt.get("allowlist") != [{"source": a, "destination": b} for a, b in ALLOWLIST]:
        errors.append("receipt allowlist mismatch")
    if receipt.get("exact_two_file_allowlist") is not True:
        errors.append("exact_two_file_allowlist must be true")
    for item in operations:
        destination = item.get("relative_destination")
        if item.get("saved_operation") not in SAVED_OPERATIONS:
            errors.append(f"{destination}: invalid saved operation")
        if item.get("revalidated_operation") not in (*SAVED_OPERATIONS, "blocked"):
            errors.append(f"{destination}: invalid revalidated operation")
        if not is_plan_sha256(item.get("source_sha256") or "") and item.get(
            "revalidated_operation"
        ) != "blocked":
            errors.append(f"{destination}: missing or invalid source sha256")
        if item.get("expected_post_change_sha256") != item.get("source_sha256"):
            errors.append(f"{destination}: expected post-change hash mismatch")
        if item.get("mutation_performed"):
            if item.get("post_change_sha256") != item.get("source_sha256"):
                errors.append(f"{destination}: post-change hash does not match the source")
            if item.get("commit_result") != "committed":
                errors.append(f"{destination}: mutation recorded without a commit result")
            if item.get("revalidated_operation") == "create_required" and item.get(
                "current_pre_change_sha256"
            ):
                errors.append(f"{destination}: create recorded a pre-change destination hash")
        else:
            if item.get("post_change_sha256") is not None:
                errors.append(f"{destination}: post-change hash without mutation")
        if item.get("backup_created"):
            if item.get("revalidated_operation") != "replace_required":
                errors.append(f"{destination}: backup created outside a replacement")
            if not is_plan_sha256(item.get("backup_sha256") or ""):
                errors.append(f"{destination}: backup hash is missing or invalid")
            if item.get("backup_sha256") != item.get("current_pre_change_sha256"):
                errors.append(f"{destination}: backup hash does not match the pre-change state")
            relative = str(item.get("backup_relative_path") or "")
            if not relative or _ABSOLUTE_PATH_RE.search(relative) or ".." in relative:
                errors.append(f"{destination}: backup path is not a safe relative path")
        elif item.get("backup_sha256") or item.get("backup_relative_path"):
            errors.append(f"{destination}: backup fields recorded without a backup")
    return errors


def _receipt_parent_errors(receipt: Mapping[str, Any]) -> list[str]:
    """Validate the recorded destination-parent contract and directory actions."""
    errors: list[str] = []
    if receipt.get("destination_parent_contract_version") != PARENT_CONTRACT_VERSION:
        errors.append("receipt destination_parent_contract_version must be 1")
    operations = receipt.get("operations") or []
    safety = _as_mapping(receipt.get("safety"))
    status = receipt.get("status")
    total_created: list[str] = []
    for item in operations:
        destination = item.get("relative_destination")
        parent = item.get("destination_parent")
        if not isinstance(parent, dict):
            errors.append(f"{destination}: missing destination_parent record")
            continue
        if destination not in PARENT_RELATIVE:
            errors.append("destination_parent on a non-allowlisted destination")
            continue
        allowed = PARENT_CREATION_ALLOWED[destination]
        if parent.get("contract_version") != PARENT_CONTRACT_VERSION:
            errors.append(f"{destination}: parent contract version mismatch")
        if parent.get("relative_path") != PARENT_RELATIVE[destination]:
            errors.append(f"{destination}: parent relative path mismatch")
        if parent.get("creation_allowed") is not allowed:
            errors.append(f"{destination}: parent creation permission mismatch")
        for key in ("saved_creation_chain", "revalidated_creation_chain", "created_directories",
                    "compensated_directories", "remaining_created_directories"):
            value = parent.get(key)
            if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
                errors.append(f"{destination}: {key} must be a list of relative directories")
                continue
            if not allowed and value:
                errors.append(f"{destination}: directory action recorded for a non-creating parent")
            for entry in value:
                if entry not in AUTHORIZED_PARENT_DIRECTORIES:
                    errors.append(f"{destination}: {key} entry outside the exact allowlist")
                elif _ABSOLUTE_PATH_RE.search(entry) or ".." in entry.split("/"):
                    errors.append(f"{destination}: {key} entry is not a safe relative path")
            if len(set(value)) != len(value):
                errors.append(f"{destination}: {key} contains duplicates")
            if value != [x for x in AUTHORIZED_PARENT_DIRECTORIES if x in value]:
                errors.append(f"{destination}: {key} ordering mismatch")
        created = list(parent.get("created_directories") or [])
        compensated = list(parent.get("compensated_directories") or [])
        remaining = list(parent.get("remaining_created_directories") or [])
        chain = list(parent.get("revalidated_creation_chain") or [])
        if any(entry not in chain for entry in created):
            errors.append(f"{destination}: created directory outside the revalidated chain")
        if any(entry not in created for entry in compensated):
            errors.append(f"{destination}: compensated directory was never created here")
        expected_remaining = [entry for entry in created if entry not in set(compensated)]
        if remaining != expected_remaining:
            errors.append(f"{destination}: retained directory list is inconsistent")
        if parent.get("revalidated_state") not in PARENT_STATES:
            errors.append(f"{destination}: invalid revalidated parent state")
        if parent.get("revalidated_state") != "create_required" and created:
            errors.append(f"{destination}: directories created without a create_required parent")
        total_created.extend(created)

    if status in {STATUS_BLOCKED, STATUS_NO_CHANGE, STATUS_UNSUPPORTED} and total_created:
        errors.append(f"{status} receipt records created directories")
    if bool(safety.get("parent_directory_create_executed")) != bool(total_created):
        errors.append("safety parent_directory_create_executed disagrees with the receipt")
    directory_compensation = _as_mapping(receipt.get("directory_compensation"))
    attempted = bool(directory_compensation.get("attempted"))
    if bool(safety.get("parent_directory_compensation_executed")) != attempted:
        errors.append("safety parent_directory_compensation_executed disagrees with the receipt")
    if attempted:
        entries = directory_compensation.get("entries")
        if not isinstance(entries, list) or not entries:
            errors.append("directory compensation recorded without entries")
        else:
            for entry in entries:
                if entry.get("action") != "remove_created_directory":
                    errors.append("directory compensation action outside the bounded scope")
                if entry.get("relative_directory") not in AUTHORIZED_PARENT_DIRECTORIES:
                    errors.append("directory compensation touched a non-allowlisted directory")
        if not total_created:
            errors.append("directory compensation without any created directory")
    return errors


def _receipt_safety_errors(receipt: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    safety = _as_mapping(receipt.get("safety"))
    if not safety:
        return ["safety ledger is missing"]
    for key in SAFETY_FALSE_KEYS:
        if safety.get(key) is not False:
            errors.append(f"unsafe safety flag: {key}")
    if safety.get("exact_two_file_allowlist") is not True:
        errors.append("safety.exact_two_file_allowlist must be true")
    for key in (*SAFETY_DYNAMIC_KEYS, "read_only", "mutation_performed"):
        if not isinstance(safety.get(key), bool):
            errors.append(f"missing safety flag: {key}")
    mutation = bool(safety.get("mutation_performed"))
    if safety.get("read_only") is not (not mutation):
        errors.append("safety read_only/mutation_performed disagree")
    if receipt.get("mutation_performed") is not mutation:
        errors.append("receipt mutation flag disagrees with the safety ledger")
    if receipt.get("read_only") is not (not mutation):
        errors.append("receipt read_only flag disagrees with the safety ledger")
    operations = receipt.get("operations") or []
    created_any = any(
        (item.get("destination_parent") or {}).get("created_directories")
        for item in operations
    )
    if mutation and not (
        any(item.get("mutation_performed") for item in operations) or created_any
    ):
        errors.append("safety claims mutation without a mutated operation or created directory")
    if not mutation and any(item.get("mutation_performed") for item in operations):
        errors.append("safety understates a recorded mutation")
    if safety.get("backup_created") and not any(
        item.get("backup_created") for item in operations
    ):
        errors.append("safety claims a backup without a backed-up operation")
    if safety.get("atomic_replace_executed") and not mutation:
        errors.append("safety claims atomic replacement without mutation")
    return errors


def validate_saved_receipt(receipt_ref: str, data_dir: Path | str) -> dict[str, Any]:
    """Validate a saved PR313 execution receipt bundle. Read-only."""
    root = windows_reconcile_receipt_root(data_dir)
    checks = {
        "required_files": False,
        "json_parse": False,
        "schema": False,
        "recipe_id": False,
        "manifest": False,
        "checksums": False,
        "allowlist_and_operations": False,
        "plan_confirmation": False,
        "status_precedence": False,
        "safety": False,
        "compensation": False,
        "destination_parent": False,
        "no_sensitive_fields": False,
    }
    directory = resolve_receipt_ref(receipt_ref, root)
    base = {
        "schema_version": SCHEMA_VERSION,
        "mode": RECEIPT_VALIDATE_MODE,
        "recipe_id": RECIPE_ID,
        "read_only": True,
        "mutation_performed": False,
        "receipt_id": directory.name if directory is not None else None,
        "checks": dict(checks),
        "failures": [],
    }
    if directory is None or not directory.is_dir():
        return {**base, "status": "not_found", "failures": ["receipt bundle not found"]}
    if any(not (directory / name).is_file() for name in RECEIPT_REQUIRED_FILES):
        return {**base, "status": "failed", "failures": ["missing required receipt files"]}
    checks["required_files"] = True
    try:
        receipt = json.loads((directory / RECEIPT_JSON).read_text(encoding="utf-8"))
        manifest = json.loads((directory / RECEIPT_MANIFEST).read_text(encoding="utf-8"))
    except Exception:
        return {
            **base,
            "status": "failed",
            "checks": dict(checks),
            "failures": ["malformed receipt or manifest JSON"],
        }
    if not isinstance(receipt, dict) or not isinstance(manifest, dict):
        return {
            **base,
            "status": "failed",
            "checks": dict(checks),
            "failures": ["receipt and manifest must be JSON objects"],
        }
    checks["json_parse"] = True
    failures: list[str] = []

    checks["schema"] = (
        receipt.get("schema_version") == SCHEMA_VERSION
        and receipt.get("mode") == RECEIPT_MODE
        and receipt.get("status") in RECEIPT_STATUSES
    )
    checks["recipe_id"] = receipt.get("recipe_id") == manifest.get("recipe_id") == RECIPE_ID
    checks["manifest"] = (
        manifest.get("kind") == MANIFEST_KIND
        and manifest.get("mode") == MANIFEST_MODE
        and manifest.get("receipt_id") == receipt.get("receipt_id")
        and manifest.get("status") == receipt.get("status")
        and list(manifest.get("files") or []) == list(RECEIPT_REQUIRED_FILES)
    )

    manifest_checksums = _as_mapping(manifest.get("checksums"))
    checks["checksums"] = bool(manifest_checksums) and set(manifest_checksums) == {
        RECEIPT_JSON,
        RECEIPT_MD,
    }
    for relative, expected in manifest_checksums.items():
        target = directory / relative
        if not target.is_file() or _sha256_file(target) != expected:
            checks["checksums"] = False
            failures.append(f"checksum mismatch: {relative}")

    operation_errors = _receipt_operation_errors(receipt)
    checks["allowlist_and_operations"] = not operation_errors
    failures.extend(operation_errors)

    plan = _as_mapping(receipt.get("plan"))
    plan_errors: list[str] = []
    if not is_plan_sha256(plan.get("canonical_packet_sha256") or ""):
        plan_errors.append("canonical plan hash is missing or malformed")
    if plan.get("confirmation_matched") is not True:
        plan_errors.append("receipt does not record a matched plan-hash confirmation")
    if plan.get("confirmation_scope") != "recipe_specific_plan_hash_authorization_only":
        plan_errors.append("confirmation scope must be recipe-specific authorization only")
    if plan.get("plan_mode") != PLAN_MODE:
        plan_errors.append("receipt plan mode mismatch")
    checks["plan_confirmation"] = not plan_errors
    failures.extend(plan_errors)

    precedence_errors = _receipt_status_precedence_errors(receipt)
    checks["status_precedence"] = not precedence_errors
    failures.extend(precedence_errors)

    safety_errors = _receipt_safety_errors(receipt)
    checks["safety"] = not safety_errors
    failures.extend(safety_errors)

    compensation = _as_mapping(receipt.get("compensation"))
    compensation_errors: list[str] = []
    if compensation.get("attempted"):
        entries = compensation.get("entries")
        if not isinstance(entries, list) or not entries:
            compensation_errors.append("compensation recorded without entries")
        else:
            allowed = {"restore_from_execution_backup", "remove_execution_created_file"}
            for entry in entries:
                if entry.get("action") not in allowed:
                    compensation_errors.append("compensation action outside the bounded scope")
                if entry.get("relative_destination") not in {
                    destination for _, destination in ALLOWLIST
                }:
                    compensation_errors.append("compensation touched a non-allowlisted path")
        if compensation.get("scope") != "files committed by this exact execution only":
            compensation_errors.append("compensation scope statement is missing")
    checks["compensation"] = not compensation_errors
    failures.extend(compensation_errors)

    parent_errors = _receipt_parent_errors(receipt)
    checks["destination_parent"] = not parent_errors
    failures.extend(parent_errors)

    sensitive: list[str] = []
    _scan_forbidden(receipt, sensitive)
    checks["no_sensitive_fields"] = not sensitive
    failures.extend(sensitive)

    failures.extend(f"{key} check failed" for key, ok in checks.items() if not ok)
    return {
        **base,
        "status": "ok" if all(checks.values()) else "failed",
        "receipt_id": receipt.get("receipt_id") or (directory.name if directory else None),
        "receipt_status": receipt.get("status"),
        "checks": dict(checks),
        "failures": sorted(set(failures)),
    }


# --------------------------------------------------------------------------- #
# Read-only post-change verification
# --------------------------------------------------------------------------- #


_SYSTEM32_SUFFIXES = ("\\windows\\system32", "/windows/system32")


def _check(name: str, ok: bool, detail: str = "") -> dict[str, Any]:
    record: dict[str, Any] = {"name": name, "status": "passed" if ok else "failed"}
    if detail:
        record["detail"] = sanitize(detail)
    return record


def _artifact_check_status(payload: Mapping[str, Any], check_id: str) -> str | None:
    for item in payload.get("checks") or []:
        if isinstance(item, dict) and item.get("id") == check_id:
            return item.get("status")
    return None


def verify_windows_runtime_reconcile(
    receipt_ref: str,
    *,
    staged_pr304: Path | str,
    system32_pr304: Path | str,
    staged_source_root: Path | str,
    durable_runtime_root: Path | str,
    data_dir: Path | str,
    validators: ReconcileValidators | None = None,
) -> dict[str, Any]:
    """Read-only post-change verification. Never repairs, restores, or mutates."""
    if not is_windows():
        return {
            **_verify_result(
                status=VERIFY_STATUS_UNSUPPORTED,
                reason=(
                    "windows runtime reconciliation verification is unsupported on this host"
                ),
                receipt_id=None,
                checks=[],
                operations=[],
                failures=[],
            ),
            "platform": {"system": platform.system().lower()},
        }

    active = validators or load_validators()
    checks: list[dict[str, Any]] = []
    failures: list[str] = []

    receipt_validation = validate_saved_receipt(receipt_ref, data_dir)
    bundle_ok = receipt_validation.get("status") == "ok"
    checks.append(_check("receipt.bundle_integrity", bundle_ok))
    if not bundle_ok:
        return _verify_result(
            status=VERIFY_STATUS_BLOCKED,
            reason="receipt bundle failed validation",
            receipt_id=receipt_validation.get("receipt_id"),
            checks=checks,
            operations=[],
            failures=[sanitize(item) for item in receipt_validation.get("failures") or []][:8],
        )

    directory = resolve_receipt_ref(receipt_ref, windows_reconcile_receipt_root(data_dir))
    assert directory is not None
    receipt = json.loads((directory / RECEIPT_JSON).read_text(encoding="utf-8"))

    evidence, artifact_errors = _validate_artifacts([staged_pr304, system32_pr304], active)
    checks.append(_check("pr304.artifact_validation", not artifact_errors))
    checks.append(
        _check("pr304.stable_identity", bool(evidence.get("pr304_stable_identity_matched")))
    )
    failures.extend(artifact_errors[:6])
    if artifact_errors:
        return _verify_result(
            status=VERIFY_STATUS_BLOCKED,
            reason="fresh PR304 artifacts failed validation or stable identity comparison",
            receipt_id=receipt.get("receipt_id"),
            checks=checks,
            operations=[],
            failures=[sanitize(item) for item in failures],
        )

    staged_payload = json.loads(Path(staged_pr304).read_text(encoding="utf-8-sig"))
    system32_payload = json.loads(Path(system32_pr304).read_text(encoding="utf-8-sig"))

    source_root = Path(staged_source_root).expanduser()
    runtime_root = Path(durable_runtime_root).expanduser()
    receipt_roots = _as_mapping(receipt.get("roots"))
    roots_ok = (
        root_fingerprint(source_root)
        == receipt_roots.get("staged_source_root_fingerprint_sha256")
        and root_fingerprint(runtime_root)
        == receipt_roots.get("durable_runtime_root_fingerprint_sha256")
    )
    checks.append(_check("roots.match_receipt", roots_ok))
    if not roots_ok:
        failures.append("explicit roots do not match the receipt root fingerprints")
        return _verify_result(
            status=VERIFY_STATUS_BLOCKED,
            reason="explicit roots do not match the receipt",
            receipt_id=receipt.get("receipt_id"),
            checks=checks,
            operations=[],
            failures=failures,
        )

    staged_cwd = ((staged_payload.get("invocation") or {}).get("cwd")) or ""
    staged_context_ok = bool(staged_cwd) and _contained(Path(staged_cwd), source_root)
    checks.append(_check("pr304.staged_source_context", staged_context_ok))
    if not staged_context_ok:
        failures.append("staged PR304 artifact was not produced from the staged source context")

    system32_cwd = _case(((system32_payload.get("invocation") or {}).get("cwd")) or "").rstrip(
        "\\/"
    )
    system32_ok = any(system32_cwd.endswith(suffix) for suffix in _SYSTEM32_SUFFIXES)
    checks.append(_check("pr304.system32_context", system32_ok))
    if not system32_ok:
        failures.append("System32 PR304 artifact does not report a System32 invocation context")

    for label, payload in (("staged", staged_payload), ("system32", system32_payload)):
        for check_id, name in (
            ("runtime.profile_context", "runtime.profile_resolution"),
            ("wrapper.exists", "wrapper.exists"),
            ("wrapper.semantic_markers", "wrapper.semantic_markers"),
            ("wrapper.canonical_match", "wrapper.canonical_match"),
            ("shellforgeai.import", "import.resolved"),
            ("shellforgeai.expected_source", "import.expected_source_identity"),
        ):
            status = _artifact_check_status(payload, check_id)
            ok = status == "pass"
            checks.append(_check(f"{label}.{name}", ok, "" if ok else f"status={status}"))
            if not ok:
                failures.append(f"{label} PR304 check {check_id} is {status}")
        if (payload.get("shellforgeai_import") or {}).get("expected_source_match") is not True:
            checks.append(_check(f"{label}.import.exact_source_match", False))
            failures.append(f"{label} PR304 artifact does not report an exact source match")
        else:
            checks.append(_check(f"{label}.import.exact_source_match", True))

    # Every directory this execution created and retained must still be a safe
    # directory. The verifier never creates, repairs, or removes anything.
    for item in receipt.get("operations") or []:
        parent = item.get("destination_parent") or {}
        relative_destination = str(item.get("relative_destination") or "")
        if parent.get("creation_allowed") is not PARENT_CREATION_ALLOWED.get(
            relative_destination
        ):
            checks.append(_check(f"parent.creation_permission.{relative_destination}", False))
            failures.append(f"{relative_destination}: receipt parent creation permission mismatch")
        for retained in parent.get("remaining_created_directories") or []:
            if retained not in AUTHORIZED_PARENT_DIRECTORIES:
                checks.append(_check(f"parent.authorized.{retained}", False))
                failures.append(f"{retained}: retained directory outside the exact allowlist")
                continue
            node = runtime_root / retained
            reparse = reparse_chain_components(runtime_root, retained)
            ok = node.is_dir() and not reparse
            checks.append(_check(f"parent.retained_directory.{retained}", ok))
            if not ok:
                failures.append(
                    f"{retained}: retained execution-created directory is missing or unsafe"
                )

    operations: list[dict[str, Any]] = []
    for item in receipt.get("operations") or []:
        relative = str(item.get("relative_destination") or "")
        expected = item.get("expected_post_change_sha256")
        destination = runtime_root / relative
        reparse = reparse_chain_components(runtime_root, relative)
        observed = None if reparse else _sha256_file(destination)
        ok = bool(expected) and observed == expected and not reparse
        operations.append(
            {
                "relative_destination": relative,
                "expected_post_change_sha256": expected,
                "observed_sha256": observed,
                "result": "verified" if ok else "failed",
            }
        )
        checks.append(_check(f"destination.hash.{relative}", ok))
        if not ok:
            failures.append(f"{relative}: durable destination hash does not match the receipt")

    status = VERIFY_STATUS_VERIFIED if not failures else VERIFY_STATUS_FAILED
    return _verify_result(
        status=status,
        reason=(
            "durable runtime matches the receipt and fresh PR304 evidence"
            if status == VERIFY_STATUS_VERIFIED
            else "post-change verification failed"
        ),
        receipt_id=receipt.get("receipt_id"),
        checks=checks,
        operations=operations,
        failures=[sanitize(item) for item in failures],
        evidence=evidence,
        roots={
            "staged_source_root_fingerprint_sha256": root_fingerprint(source_root),
            "durable_runtime_root_fingerprint_sha256": root_fingerprint(runtime_root),
            "roots_match_receipt": True,
        },
    )


def _verify_result(
    *,
    status: str,
    reason: str,
    receipt_id: str | None,
    checks: Sequence[Mapping[str, Any]],
    operations: Sequence[Mapping[str, Any]],
    failures: Sequence[str],
    evidence: Mapping[str, Any] | None = None,
    roots: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": VERIFY_MODE,
        "recipe_id": RECIPE_ID,
        "status": status,
        "reason": reason,
        "receipt_id": receipt_id,
        "checks": [dict(item) for item in checks],
        "operations": [dict(item) for item in operations],
        "evidence": dict(evidence or {}),
        "roots": dict(roots or {}),
        "failures": list(failures),
        "repair_executed": False,
        "rollback_executed": False,
        "read_only": True,
        "mutation_performed": False,
        "safety": safety_ledger(),
    }
