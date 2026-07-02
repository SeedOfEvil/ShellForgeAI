"""Local read-only Windows disk/root usage summary preview.

The PR270 disks preview is intentionally stdlib-only. It discovers local drive
roots through ``os.listdrives`` when available (falling back to the current
drive root only) and reads per-root capacity via ``shutil.disk_usage``. It
never executes shells, enumerates directories or files, reads user files,
reads secrets or credential caches, queries device or volume APIs, reads the
registry, uses remoting, opens network connections, writes files, or mutates
host state. Since PR273 the safety block explicitly reports the disk-specific
flags ``directory_scan_performed``, ``file_scan_performed``, and
``disk_mutation_performed`` as false in both the standalone payload and the
embedded evidence-bundle component; this is schema normalization only, with no
collection change.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import sys
from collections.abc import Callable, Sequence
from typing import Any

from shellforgeai.platform_detection import PlatformInfo, detect_platform

WINDOWS_DISKS_NEXT_SAFE_COMMAND = "shellforgeai windows status --json"
UNSUPPORTED_NEXT_SAFE_COMMAND = "shellforgeai platform doctor --json"

DEFAULT_DISKS_LIMIT = 32
MIN_DISKS_LIMIT = 1
MAX_DISKS_LIMIT = 64

COLLECTION_METHOD = "stdlib_only"
ROOT_DISCOVERY_LABEL = "os.listdrives_or_current_root_fallback"

_NOT_COLLECTED_PR270 = {
    "drive_labels": "not collected because PR270 uses stdlib-only root usage checks",
    "volume_serials": "not collected because PR270 does not query Windows APIs or registry",
    "bitlocker": "planned for later read-only Windows evidence PR only if safe",
    "smart_health": "not collected because PR270 does not query device health APIs",
    "file_inventory": "not collected because PR270 does not enumerate files or directories",
}

_WINDOWS_DISKS_SAFETY = {
    "read_only": True,
    "mutation_performed": False,
    "powershell_executed": False,
    "winrm_used": False,
    "remote_execution": False,
    "directory_scan_performed": False,
    "file_scan_performed": False,
    "disk_mutation_performed": False,
    "service_restart_executed": False,
    "process_termination_executed": False,
    "registry_modified": False,
    "execution_policy_modified": False,
    "software_install_executed": False,
    "cleanup_executed": False,
    "remediation_executed": False,
    "rollback_executed": False,
    "recovery_executed": False,
    "natural_language_execution": False,
    "shell_true": False,
    "arbitrary_command_execution": False,
    "secret_read": False,
    "auth_cache_read": False,
    "model_called": False,
    "network_call": False,
}

_UNSUPPORTED_SAFETY_KEYS = (
    "read_only",
    "mutation_performed",
    "powershell_executed",
    "winrm_used",
    "remote_execution",
    "directory_scan_performed",
    "file_scan_performed",
    "natural_language_execution",
    "shell_true",
    "arbitrary_command_execution",
    "secret_read",
    "auth_cache_read",
    "model_called",
    "network_call",
)

RootDiscovery = Callable[[], Sequence[str]]
DiskUsage = Callable[[str], Any]


def validate_disks_limit(value: int) -> int:
    """Validate the bounded root limit; invalid values fail instead of clamping."""

    try:
        numeric = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"--limit must be an integer, got {value!r}") from exc
    if isinstance(value, bool) or numeric < MIN_DISKS_LIMIT or numeric > MAX_DISKS_LIMIT:
        raise ValueError(
            f"--limit must be between {MIN_DISKS_LIMIT} and {MAX_DISKS_LIMIT}, got {value!r}"
        )
    return numeric


def normalized_sorted_roots(roots: Sequence[str]) -> list[str]:
    """Deduplicate and deterministically sort discovered drive roots."""

    unique = {str(root) for root in roots if str(root)}
    return sorted(unique, key=lambda root: (root.casefold(), root))


def _discover_windows_roots() -> list[str]:
    """Discover local drive roots via ``os.listdrives`` or the current root only.

    ``os.listdrives`` (Python 3.12+, Windows-only) returns drive roots without
    touching directories or files. When it is unavailable, only the current
    working drive root (or the interpreter's drive root) is reported; no other
    discovery mechanism is used.
    """

    listdrives = getattr(os, "listdrives", None)
    if callable(listdrives):
        return [str(root) for root in listdrives()]
    for anchor in (pathlib.Path.cwd().anchor, pathlib.Path(sys.executable).anchor):
        if anchor:
            return [str(anchor)]
    return []


def _disk_item(root: str, disk_usage: DiskUsage) -> dict[str, Any]:
    try:
        total_bytes, used_bytes, free_bytes = disk_usage(root)
    except Exception:  # per-root failures must stay sanitized, never traceback
        return {"root": root, "status": "unavailable", "error": "disk_usage_failed"}
    return {
        "root": root,
        "status": "ok",
        "total_bytes": int(total_bytes),
        "used_bytes": int(used_bytes),
        "free_bytes": int(free_bytes),
    }


def windows_disks_payload(
    info: PlatformInfo | None = None,
    *,
    root_discovery: RootDiscovery | None = None,
    disk_usage: DiskUsage | None = None,
    limit: int = DEFAULT_DISKS_LIMIT,
) -> dict[str, Any]:
    """Build the PR270 Windows disks JSON-compatible payload."""

    info = info or detect_platform()
    if info.system != "windows":
        return windows_disks_unsupported_payload(info)

    bounded_limit = validate_disks_limit(limit)
    root_discovery = root_discovery or _discover_windows_roots
    disk_usage = disk_usage or shutil.disk_usage
    try:
        roots = normalized_sorted_roots(list(root_discovery()))
    except Exception as exc:  # discovery failures must stay structured, never traceback
        return windows_disks_error_payload(
            info, reason=f"root discovery failed: {type(exc).__name__}"
        )

    total_roots = len(roots)
    truncated = total_roots > bounded_limit
    disks = [_disk_item(root, disk_usage) for root in roots[:bounded_limit]]
    available_roots = sum(1 for item in disks if item["status"] == "ok")
    return {
        "schema_version": 1,
        "mode": "windows_disks",
        "status": "ok",
        "platform": {"system": info.system},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_disks",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "collection": {
            "method": COLLECTION_METHOD,
            "root_discovery": ROOT_DISCOVERY_LABEL,
            "directory_scan_performed": False,
            "file_scan_performed": False,
            "limit": bounded_limit,
            "truncated": truncated,
        },
        "summary": {
            "total_roots": total_roots,
            "returned_roots": len(disks),
            "available_roots": available_roots,
            "unavailable_roots": len(disks) - available_roots,
        },
        "disks": disks,
        "not_collected_in_pr270": dict(_NOT_COLLECTED_PR270),
        "safety": dict(_WINDOWS_DISKS_SAFETY),
        "next_safe_command": WINDOWS_DISKS_NEXT_SAFE_COMMAND,
    }


def windows_disks_error_payload(info: PlatformInfo | None = None, *, reason: str) -> dict[str, Any]:
    """Build a structured, non-traceback error payload for discovery failures."""

    info = info or detect_platform()
    return {
        "schema_version": 1,
        "mode": "windows_disks",
        "status": "error",
        "platform": {"system": info.system},
        "reason": reason,
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_disks",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "not_collected_in_pr270": dict(_NOT_COLLECTED_PR270),
        "safety": dict(_WINDOWS_DISKS_SAFETY),
        "next_safe_command": WINDOWS_DISKS_NEXT_SAFE_COMMAND,
    }


def windows_disks_unsupported_payload(info: PlatformInfo | None = None) -> dict[str, Any]:
    """Build deterministic unsupported output for non-Windows hosts."""

    info = info or detect_platform()
    return {
        "schema_version": 1,
        "mode": "windows_disks",
        "status": "unsupported",
        "platform": {"system": info.system},
        "reason": "Windows disks preview is only available on Windows hosts.",
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": False,
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "safety": {key: _WINDOWS_DISKS_SAFETY[key] for key in _UNSUPPORTED_SAFETY_KEYS},
        "next_safe_command": UNSUPPORTED_NEXT_SAFE_COMMAND,
    }


def render_windows_disks_text(payload: dict[str, Any]) -> str:
    """Render concise operator-facing text for the Windows disks payload."""

    platform_system = payload.get("platform", {}).get("system", "unknown")
    windows_v1 = payload.get("windows_v1", {})
    lines = [
        "ShellForgeAI Windows disks",
        f"Status: {payload.get('status', 'unknown')}",
        f"Platform: {platform_system}",
        f"Windows V1 available: {str(windows_v1.get('available', False)).lower()}",
        f"Read-only: {str(payload.get('read_only', False)).lower()}",
        f"Mutation performed: {str(payload.get('mutation_performed', True)).lower()}",
    ]
    summary = payload.get("summary") or {}
    if summary:
        lines.append(
            "Roots: "
            f"total={summary.get('total_roots', 0)}; "
            f"returned={summary.get('returned_roots', 0)}; "
            f"available={summary.get('available_roots', 0)}; "
            f"unavailable={summary.get('unavailable_roots', 0)}"
        )
        available = [item for item in payload.get("disks", []) if item.get("status") == "ok"]
        free_bytes = sum(int(item.get("free_bytes", 0)) for item in available)
        total_bytes = sum(int(item.get("total_bytes", 0)) for item in available)
        lines.append(
            f"Disk usage: free={free_bytes} of total={total_bytes} bytes "
            f"across {len(available)} available root(s)"
        )
        collection = payload.get("collection") or {}
        lines.append(
            "Collection limit: "
            f"limit={collection.get('limit', DEFAULT_DISKS_LIMIT)}; "
            f"truncated={str(collection.get('truncated', False)).lower()}"
        )
    if payload.get("status") in ("unsupported", "error"):
        lines.append(str(payload.get("reason", "Windows disks preview is unavailable.")))
    lines.append(
        "Not collected yet: drive labels, volume serials, BitLocker, SMART health, "
        "file/directory inventory."
    )
    lines.append(
        f"Next safe command: {payload.get('next_safe_command', UNSUPPORTED_NEXT_SAFE_COMMAND)}"
    )
    return os.linesep.join(lines)
