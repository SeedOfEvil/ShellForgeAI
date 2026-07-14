"""Bounded read-only Windows local drive-root volume/filesystem collector."""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Sequence
from typing import Any

from shellforgeai.platform_detection import PlatformInfo, detect_platform

MODE = "windows_volumes"
METHOD = "psutil_local_drive_roots"
DEFAULT_VOLUMES_LIMIT = 32
MIN_VOLUMES_LIMIT = 1
MAX_VOLUMES_LIMIT = 64
UNSUPPORTED_NEXT_SAFE_COMMAND = "shellforgeai platform doctor --json"
LIMITATIONS = [
    "Only local drive-root volumes were inspected.",
    (
        "No files, directories, network shares, volume GUIDs, labels, serials, "
        "encryption state, physical disks, or storage health were inspected."
    ),
]
_DRIVE_ROOT_RE = re.compile(r"^[A-Za-z]:\\\\?$")
_GUID_RE = re.compile(r"volume\{[0-9a-fA-F-]+\}")

_SAFETY = {
    "read_only": True,
    "mutation_performed": False,
    "directory_scan_performed": False,
    "file_scan_performed": False,
    "remote_execution": False,
    "network_call": False,
    "powershell_executed": False,
    "winrm_used": False,
    "shell_true": False,
    "arbitrary_command_execution": False,
    "registry_modified": False,
    "disk_mutation_performed": False,
    "cleanup_executed": False,
    "remediation_executed": False,
    "rollback_executed": False,
    "recovery_executed": False,
    "secret_read": False,
    "auth_cache_read": False,
    "model_called": False,
}

PartitionSource = Callable[[], Sequence[Any]]
UsageSource = Callable[[str], Any]


def validate_volumes_limit(value: int) -> int:
    try:
        numeric = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"--limit must be an integer, got {value!r}") from exc
    if isinstance(value, bool) or numeric < MIN_VOLUMES_LIMIT or numeric > MAX_VOLUMES_LIMIT:
        raise ValueError(
            f"--limit must be between {MIN_VOLUMES_LIMIT} and {MAX_VOLUMES_LIMIT}, got {value!r}"
        )
    return numeric


def _psutil_sources() -> tuple[PartitionSource, UsageSource]:
    try:
        import psutil  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover - injection covers behavior
        raise RuntimeError("psutil volume APIs are unavailable") from exc
    return lambda: psutil.disk_partitions(all=False), psutil.disk_usage


def _options(partition: Any) -> set[str]:
    raw = getattr(partition, "opts", "") or ""
    return {item.strip().casefold() for item in str(raw).split(",") if item.strip()}


def classify_volume_kind(options: set[str]) -> str:
    if "cdrom" in options:
        return "cdrom"
    if "removable" in options:
        return "removable"
    if "ramdisk" in options:
        return "ramdisk"
    if "fixed" in options:
        return "fixed"
    return "unknown"


def classify_access(options: set[str]) -> str:
    if "ro" in options or "readonly" in options or "read-only" in options:
        return "read_only"
    if "rw" in options or "readwrite" in options or "read-write" in options:
        return "read_write"
    return "unknown"


def _drive_root(value: Any) -> str | None:
    text = str(value or "").strip().replace("/", "\\")
    if _DRIVE_ROOT_RE.fullmatch(text):
        return text[:2].upper() + "\\"
    return None


def _unsafe(value: Any) -> bool:
    text = str(value or "")
    return text.startswith("\\\\") or "\\\\?\\" in text or bool(_GUID_RE.search(text.casefold()))


def _filesystem(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    return text[:32]


def _safe_usage(raw: Any) -> tuple[int | None, int | None, int | None, float | None, list[str]]:
    warnings: list[str] = []
    try:
        if hasattr(raw, "total"):
            total = int(raw.total)
            used = int(raw.used)
            free = int(raw.free)
        else:
            total = int(raw[0])
            used = int(raw[1])
            free = int(raw[2])
    except Exception:
        return None, None, None, None, ["capacity values unavailable or malformed"]
    if min(total, used, free) < 0 or used > total or free > total:
        return None, None, None, None, ["capacity values unavailable or malformed"]
    percent = None if total <= 0 else round(used / total * 100, 1)
    return total, used, free, percent, warnings


def windows_volumes_payload(
    info: PlatformInfo | None = None,
    *,
    partition_source: PartitionSource | None = None,
    disk_usage: UsageSource | None = None,
    limit: int = DEFAULT_VOLUMES_LIMIT,
) -> dict[str, Any]:
    info = info or detect_platform()
    if info.system != "windows":
        return windows_volumes_unsupported_payload(info)
    bounded_limit = validate_volumes_limit(limit)
    warnings: list[str] = []
    try:
        if partition_source is None or disk_usage is None:
            ps_parts, ps_usage = _psutil_sources()
            partition_source = partition_source or ps_parts
            disk_usage = disk_usage or ps_usage
        partitions = list(partition_source() or [])
    except Exception:
        return windows_volumes_error_payload(info, reason="partition_enumeration_failed")

    candidates: dict[str, dict[str, Any]] = {}
    skipped_remote = skipped_non_root = skipped_unsafe = 0
    for part in partitions:
        mount = getattr(part, "mountpoint", "")
        device = getattr(part, "device", "")
        opts = _options(part)
        if "remote" in opts or "network" in opts:
            skipped_remote += 1
            continue
        if _unsafe(mount) or _unsafe(device):
            skipped_unsafe += 1
            continue
        root = _drive_root(mount)
        if root is None:
            skipped_non_root += 1
            continue
        drive = root[:2]
        candidates.setdefault(
            drive.casefold(),
            {
                "drive": drive.upper(),
                "mountpoint": root,
                "filesystem": _filesystem(getattr(part, "fstype", None)),
                "kind": classify_volume_kind(opts),
                "access": classify_access(opts),
            },
        )
    ordered = sorted(candidates.values(), key=lambda v: (v["drive"].casefold(), v["mountpoint"]))
    truncated = len(ordered) > bounded_limit
    volumes: list[dict[str, Any]] = []
    for item in ordered[:bounded_limit]:
        record = {**item, "status": "ok", "warnings": []}
        try:
            total, used, free, pct, iwarnings = _safe_usage(disk_usage(item["mountpoint"]))
        except Exception:
            record.update({"status": "unavailable", "error": "disk_usage_failed"})
        else:
            record["warnings"] = iwarnings
            if iwarnings:
                record.update({"status": "unavailable", "error": "capacity_values_malformed"})
            else:
                record.update(
                    {
                        "total_bytes": total,
                        "used_bytes": used,
                        "free_bytes": free,
                        "used_percent": pct,
                    }
                )
        volumes.append(record)
    available = sum(1 for v in volumes if v["status"] == "ok")
    return {
        "schema_version": 1,
        "mode": MODE,
        "status": "ok",
        "platform": {"system": info.system},
        "read_only": True,
        "mutation_performed": False,
        "collection": {
            "method": METHOD,
            "limit": bounded_limit,
            "truncated": truncated,
            "directory_scan_performed": False,
            "file_scan_performed": False,
            "remote_volume_probe_performed": False,
        },
        "summary": {
            "partitions_observed": len(partitions),
            "local_drive_roots": len(ordered),
            "returned_volumes": len(volumes),
            "available_volumes": available,
            "unavailable_volumes": len(volumes) - available,
            "fixed_volumes": sum(1 for v in volumes if v["kind"] == "fixed"),
            "removable_volumes": sum(1 for v in volumes if v["kind"] == "removable"),
            "cdrom_volumes": sum(1 for v in volumes if v["kind"] == "cdrom"),
            "read_only_volumes": sum(1 for v in volumes if v["access"] == "read_only"),
            "skipped_remote": skipped_remote,
            "skipped_non_drive_root": skipped_non_root,
            "skipped_unsafe_identifier": skipped_unsafe,
        },
        "volumes": volumes,
        "limitations": list(LIMITATIONS),
        "warnings": warnings,
        "errors": [],
        "safety": dict(_SAFETY),
    }


def windows_volumes_error_payload(
    info: PlatformInfo | None = None, *, reason: str
) -> dict[str, Any]:
    info = info or detect_platform()
    payload = windows_volumes_unsupported_payload(info)
    payload.update({"status": "error", "reason": reason, "errors": [reason]})
    payload["platform"] = {"system": info.system}
    return payload


def windows_volumes_unsupported_payload(info: PlatformInfo | None = None) -> dict[str, Any]:
    info = info or detect_platform()
    return {
        "schema_version": 1,
        "mode": MODE,
        "status": "unsupported",
        "platform": {"system": info.system},
        "reason": "Windows volumes are only available on Windows hosts.",
        "read_only": True,
        "mutation_performed": False,
        "collection": {
            "method": METHOD,
            "limit": DEFAULT_VOLUMES_LIMIT,
            "truncated": False,
            "directory_scan_performed": False,
            "file_scan_performed": False,
            "remote_volume_probe_performed": False,
        },
        "summary": {
            "partitions_observed": 0,
            "local_drive_roots": 0,
            "returned_volumes": 0,
            "available_volumes": 0,
            "unavailable_volumes": 0,
            "fixed_volumes": 0,
            "removable_volumes": 0,
            "cdrom_volumes": 0,
            "read_only_volumes": 0,
            "skipped_remote": 0,
            "skipped_non_drive_root": 0,
            "skipped_unsafe_identifier": 0,
        },
        "volumes": [],
        "limitations": list(LIMITATIONS),
        "warnings": [],
        "errors": [],
        "safety": dict(_SAFETY),
        "next_safe_command": UNSUPPORTED_NEXT_SAFE_COMMAND,
    }


def _gib(value: Any) -> str:
    return f"{int(value) / (1024**3):.1f} GiB"


def render_windows_volumes_text(payload: dict[str, Any]) -> str:
    lines = ["ShellForgeAI Windows volumes", f"Status: {payload.get('status', 'unknown')}"]
    summary = payload.get("summary") or {}
    lines.append(
        "Volumes: "
        f"{summary.get('local_drive_roots', 0)} local drive roots; "
        f"{summary.get('available_volumes', 0)} available; "
        f"{summary.get('unavailable_volumes', 0)} unavailable"
    )
    if payload.get("status") == "unsupported":
        lines.append(str(payload.get("reason", "Windows volumes are unavailable.")))
    for volume in payload.get("volumes", []):
        lines.append("")
        lines.append(str(volume.get("mountpoint", volume.get("drive", "unknown"))))
        lines.append(f"  Filesystem: {volume.get('filesystem') or 'unknown'}")
        lines.append(f"  Kind: {volume.get('kind', 'unknown')}")
        access = str(volume.get("access", "unknown")).replace("_", "-")
        lines.append(f"  Access: {access}")
        if volume.get("status") == "ok":
            lines.append(
                "  Usage: "
                f"{_gib(volume.get('used_bytes', 0))} used / "
                f"{_gib(volume.get('total_bytes', 0))} total; "
                f"{_gib(volume.get('free_bytes', 0))} free; "
                f"{volume.get('used_percent')}%"
            )
        else:
            lines.append("  Usage: unavailable")
    if (
        summary.get("skipped_remote")
        or summary.get("skipped_non_drive_root")
        or summary.get("skipped_unsafe_identifier")
    ):
        lines.append(
            "Skipped: "
            f"remote={summary.get('skipped_remote', 0)}; "
            f"non_drive_root={summary.get('skipped_non_drive_root', 0)}; "
            f"unsafe_identifier={summary.get('skipped_unsafe_identifier', 0)}"
        )
    lines.append(f"Read-only: {str(payload.get('read_only', False)).lower()}")
    lines.append(
        "Limitations: local drive roots only; no files, directories, remote shares, GUIDs, "
        "labels, serials, encryption, SMART, or physical-disk inspection."
    )
    return os.linesep.join(lines)
