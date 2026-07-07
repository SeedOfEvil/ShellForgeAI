"""Local read-only Windows status report.

The Windows V1 status report is intentionally stdlib-only. It collects narrow
local host basics and filesystem capacity metadata without executing shells,
using remoting, reading credential caches, opening network connections, or
mutating host state.
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from shellforgeai.platform_detection import PlatformInfo, detect_platform
from shellforgeai.windows_memory import (
    LOAD_AVERAGE_UNAVAILABLE_MARKER,
    MemorySource,
    windows_memory_payload,
    windows_memory_summary,
)

WINDOWS_STATUS_NEXT_SAFE_COMMAND = "shellforgeai windows doctor --json"
UNSUPPORTED_NEXT_SAFE_COMMAND = "shellforgeai platform doctor --json"

_NOT_COLLECTED_PR262 = {
    "powershell_version": "not collected because PR262 does not execute PowerShell",
    "execution_policy": "not collected because PR262 does not execute PowerShell",
    "services": "planned for later read-only Windows evidence PR",
    "processes": "planned for later read-only Windows evidence PR",
    "event_logs": "planned for later read-only Windows evidence PR",
    "firewall": "planned for later read-only Windows evidence PR",
    "windows_update": "planned for later read-only Windows evidence PR",
}

_WINDOWS_STATUS_SAFETY = {
    "read_only": True,
    "mutation_performed": False,
    "powershell_executed": False,
    "winrm_used": False,
    "remote_execution": False,
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
    "natural_language_execution",
    "shell_true",
    "arbitrary_command_execution",
    "secret_read",
    "auth_cache_read",
    "model_called",
    "network_call",
)

DiskUsageCollector = Callable[[str | Path], tuple[int, int, int]]


def _platform_block(info: PlatformInfo) -> dict[str, str]:
    payload = info.to_dict()
    payload["version"] = platform.version()
    return payload


def _usage_block(path: str | Path, disk_usage: DiskUsageCollector) -> dict[str, int]:
    usage = disk_usage(path)
    return {"total_bytes": usage[0], "used_bytes": usage[1], "free_bytes": usage[2]}


def _safe_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return ""


def _safe_fqdn(hostname: str) -> str:
    try:
        return socket.getfqdn(hostname or None)
    except Exception:
        return hostname


def _windows_root_path(cwd: Path) -> str:
    anchor = cwd.anchor or "C:\\"
    if len(anchor) >= 2 and anchor[1] == ":":
        return anchor
    return "C:\\"


def windows_status_payload(
    info: PlatformInfo | None = None,
    *,
    disk_usage: DiskUsageCollector | None = None,
    cwd: Path | None = None,
    memory_source: MemorySource | None = None,
) -> dict[str, Any]:
    """Build the PR262 Windows status JSON-compatible payload.

    Since PR287 the payload also carries an honest, read-only Windows physical
    memory summary reused from the Windows memory collector, plus explicit
    load-average unavailable markers. Memory fails soft: when it cannot be
    collected the ``memory`` block reports ``available`` false with an explicit
    limitation instead of inventing zero values.
    """

    info = info or detect_platform()
    if info.system != "windows":
        return windows_status_unsupported_payload(info)

    cwd_path = cwd or Path.cwd()
    disk_usage = disk_usage or shutil.disk_usage
    root_path = _windows_root_path(cwd_path)
    hostname = _safe_hostname()
    fqdn = _safe_fqdn(hostname)
    memory_payload = windows_memory_payload(info, memory_source=memory_source)
    memory_block = memory_payload.get("memory", {})
    return {
        "schema_version": 1,
        "mode": "windows_status",
        "status": "ok",
        "platform": _platform_block(info),
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_status",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "host": {
            "hostname": hostname,
            "fqdn": fqdn,
            "cwd": str(cwd_path),
            "user_context_collected": False,
            "secret_or_auth_cache_read": False,
        },
        "python_runtime": {
            "executable": sys.executable,
            "version": sys.version.split()[0],
            "implementation": platform.python_implementation(),
        },
        "filesystem": {
            "collection": "stdlib_only",
            "cwd_usage": _usage_block(cwd_path, disk_usage),
            "root_usage": {
                "path": root_path,
                **_usage_block(root_path, disk_usage),
            },
        },
        "memory": memory_block,
        "resource_limitations": [LOAD_AVERAGE_UNAVAILABLE_MARKER],
        "network": {
            "collection": "stdlib_only",
            "hostname": hostname,
            "fqdn": fqdn,
            "remote_probe_performed": False,
            "network_call": False,
        },
        "not_collected_in_pr262": dict(_NOT_COLLECTED_PR262),
        "safety": dict(_WINDOWS_STATUS_SAFETY),
        "next_safe_command": WINDOWS_STATUS_NEXT_SAFE_COMMAND,
    }


def windows_status_unsupported_payload(info: PlatformInfo | None = None) -> dict[str, Any]:
    """Build deterministic unsupported output for non-Windows hosts."""

    info = info or detect_platform()
    return {
        "schema_version": 1,
        "mode": "windows_status",
        "status": "unsupported",
        "platform": {"system": info.system},
        "reason": "Windows status is only available on Windows hosts.",
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": False,
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "safety": {key: _WINDOWS_STATUS_SAFETY[key] for key in _UNSUPPORTED_SAFETY_KEYS},
        "next_safe_command": UNSUPPORTED_NEXT_SAFE_COMMAND,
    }


def render_windows_status_text(payload: dict[str, Any]) -> str:
    """Render concise operator-facing text for the Windows status payload."""

    platform_system = payload.get("platform", {}).get("system", "unknown")
    windows_v1 = payload.get("windows_v1", {})
    lines = [
        "ShellForgeAI Windows status",
        f"Status: {payload.get('status', 'unknown')}",
        f"Platform: {platform_system}",
        f"Windows V1 available: {str(windows_v1.get('available', False)).lower()}",
        f"Read-only: {str(payload.get('read_only', False)).lower()}",
        f"Mutation performed: {str(payload.get('mutation_performed', True)).lower()}",
    ]
    host = payload.get("host") or {}
    if host:
        lines.append(f"Host: {host.get('hostname', '')} / {host.get('fqdn', '')}")
    filesystem = payload.get("filesystem") or {}
    cwd_usage = filesystem.get("cwd_usage") or {}
    root_usage = filesystem.get("root_usage") or {}
    if cwd_usage or root_usage:
        lines.append(
            "Disk: "
            f"cwd_free={cwd_usage.get('free_bytes', 'unknown')} bytes; "
            f"root_free={root_usage.get('free_bytes', 'unknown')} bytes "
            "(disk/root free space collected from Windows local read-only evidence)"
        )
    memory = payload.get("memory") or {}
    if memory:
        lines.append("Memory: " + windows_memory_summary(payload))
    if payload.get("status") == "unsupported":
        lines.append(str(payload.get("reason", "Windows status is not available on this host.")))
    if payload.get("status") == "ok":
        lines.append(f"- {LOAD_AVERAGE_UNAVAILABLE_MARKER}.")
    lines.append(
        "Not collected yet: PowerShell version, execution policy, services, processes, event logs."
    )
    lines.append(
        f"Next safe command: {payload.get('next_safe_command', UNSUPPORTED_NEXT_SAFE_COMMAND)}"
    )
    return os.linesep.join(lines)
