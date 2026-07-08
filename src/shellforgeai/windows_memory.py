"""Local read-only Windows physical memory summary.

PR287 adds an honest, Windows-native, read-only memory summary that reuses the
same bounded ``ctypes`` + ``kernel32`` pattern already established by the
read-only Windows processes and services previews. It calls the documented,
read-only ``GlobalMemoryStatusEx`` Win32 API to report total/available/used
physical memory. It never executes subprocesses, shells, PowerShell,
WinRM/remoting, reads process memory, writes files, opens network connections,
calls a model, or reads secrets/auth caches.

Windows semantics stay honest: Windows does not expose a Linux-style load
average, so ``load average`` is reported as an explicit unavailable marker
rather than mapped into a fake Linux field. When memory cannot be collected the
payload fails soft with ``status`` ``ok`` and an explicit limitation instead of
crashing or inventing zero values.
"""

from __future__ import annotations

import ctypes
import os
from collections.abc import Callable
from typing import Any

from shellforgeai.platform_detection import PlatformInfo, detect_platform

METHOD = "ctypes_global_memory_status_ex"
MEMORY_SOURCE = METHOD
WINDOWS_MEMORY_NEXT_SAFE_COMMAND = "shellforgeai windows status --json"
UNSUPPORTED_NEXT_SAFE_COMMAND = "shellforgeai platform doctor --json"

LOAD_AVERAGE_UNAVAILABLE_MARKER = "Load average is not available on Windows"
MEMORY_UNAVAILABLE_MARKER = "Memory summary unavailable from this collector on Windows"

_WINDOWS_MEMORY_SAFETY = {
    "read_only": True,
    "mutation_performed": False,
    "powershell_executed": False,
    "winrm_used": False,
    "remote_execution": False,
    "process_memory_read": False,
    "process_termination_executed": False,
    "service_restart_executed": False,
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

# A memory source returns raw physical-memory facts: total_bytes,
# available_bytes, and the OS-reported memory-load percentage.
MemorySource = Callable[[], dict[str, int]]


def _read_global_memory_status() -> dict[str, int]:
    """Read physical memory facts via the read-only ``GlobalMemoryStatusEx`` API.

    Uses the same bounded ``ctypes`` + ``kernel32`` mechanism as the existing
    read-only Windows process/service previews. ``ctypes.WinDLL`` only exists on
    Windows, so on any other platform this raises and the caller fails soft.
    """

    windll = getattr(ctypes, "WinDLL", None)
    if windll is None:  # not a Windows interpreter; fail soft in the caller
        raise OSError("GlobalMemoryStatusEx is only available on Windows")

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    kernel32 = windll("kernel32", use_last_error=True)
    kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
    kernel32.GlobalMemoryStatusEx.restype = ctypes.c_int

    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise OSError("GlobalMemoryStatusEx call failed")
    return {
        "total_bytes": int(status.ullTotalPhys),
        "available_bytes": int(status.ullAvailPhys),
        "memory_load_percent": int(status.dwMemoryLoad),
    }


def _unavailable_memory_block() -> dict[str, Any]:
    return {
        "available": False,
        "total_bytes": None,
        "available_bytes": None,
        "used_bytes": None,
        "used_percent": None,
        "source": MEMORY_SOURCE,
        "limitations": [MEMORY_UNAVAILABLE_MARKER],
    }


def _available_memory_block(raw: dict[str, int]) -> dict[str, Any] | None:
    try:
        total = int(raw["total_bytes"])
        available = int(raw["available_bytes"])
    except (KeyError, TypeError, ValueError):
        return None
    if total <= 0 or available < 0 or available > total:
        return None
    used = total - available
    used_percent = round(used / total * 100, 1) if total else None
    return {
        "available": True,
        "total_bytes": total,
        "available_bytes": available,
        "used_bytes": used,
        "used_percent": used_percent,
        "source": MEMORY_SOURCE,
        "limitations": [],
    }


def windows_memory_payload(
    info: PlatformInfo | None = None,
    *,
    memory_source: MemorySource | None = None,
) -> dict[str, Any]:
    """Build the PR287 Windows memory JSON-compatible payload.

    Fails soft: if physical-memory facts cannot be collected the payload keeps
    ``status`` ``ok`` and reports an explicit unavailable limitation instead of
    inventing zero values or raising.
    """

    info = info or detect_platform()
    if info.system != "windows":
        return windows_memory_unsupported_payload(info)

    memory_source = memory_source or _read_global_memory_status
    memory_block: dict[str, Any] | None = None
    try:
        raw = memory_source()
    except Exception:  # memory reads must fail soft, never traceback
        memory_block = None
    else:
        memory_block = _available_memory_block(raw)
    if memory_block is None:
        memory_block = _unavailable_memory_block()

    limitations = [LOAD_AVERAGE_UNAVAILABLE_MARKER]
    if not memory_block["available"]:
        limitations.append(MEMORY_UNAVAILABLE_MARKER)

    return {
        "schema_version": 1,
        "mode": "windows_memory",
        "status": "ok",
        "platform": {"system": info.system},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_memory",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "method": METHOD,
        "memory": memory_block,
        "limitations": limitations,
        "safety": dict(_WINDOWS_MEMORY_SAFETY),
        "next_safe_command": WINDOWS_MEMORY_NEXT_SAFE_COMMAND,
    }


def windows_memory_unsupported_payload(info: PlatformInfo | None = None) -> dict[str, Any]:
    """Build deterministic unsupported output for non-Windows hosts."""

    info = info or detect_platform()
    return {
        "schema_version": 1,
        "mode": "windows_memory",
        "status": "unsupported",
        "platform": {"system": info.system},
        "reason": "Windows memory summary is only available on Windows hosts.",
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": False,
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "safety": {key: _WINDOWS_MEMORY_SAFETY[key] for key in _UNSUPPORTED_SAFETY_KEYS},
        "next_safe_command": UNSUPPORTED_NEXT_SAFE_COMMAND,
    }


def _bytes_gib(value: Any) -> str:
    try:
        return f"{float(value) / (1024**3):.1f}GiB"
    except (TypeError, ValueError):
        return "unknown"


def windows_memory_summary(payload: dict[str, Any]) -> str:
    """One-line honest memory summary reused by status/evidence aggregation."""

    memory = payload.get("memory") or {}
    if not memory.get("available"):
        return MEMORY_UNAVAILABLE_MARKER
    total = memory.get("total_bytes")
    available = memory.get("available_bytes")
    used_percent = memory.get("used_percent")
    return (
        f"memory used={used_percent}% "
        f"available={_bytes_gib(available)}/{_bytes_gib(total)} (Windows local read-only)"
    )


def render_windows_memory_text(payload: dict[str, Any]) -> str:
    """Render concise operator-facing text for the Windows memory payload."""

    platform_system = payload.get("platform", {}).get("system", "unknown")
    lines = [
        "ShellForgeAI Windows memory",
        f"Status: {payload.get('status', 'unknown')}",
        f"Platform: {platform_system}",
        f"Read-only: {str(payload.get('read_only', False)).lower()}",
        f"Mutation performed: {str(payload.get('mutation_performed', True)).lower()}",
    ]
    if payload.get("status") == "unsupported":
        lines.append(str(payload.get("reason", "Windows memory summary is unavailable.")))
    else:
        lines.append("Memory: " + windows_memory_summary(payload))
    for limitation in payload.get("limitations", []):
        lines.append(f"- {limitation}.")
    lines.append(
        f"Next safe command: {payload.get('next_safe_command', UNSUPPORTED_NEXT_SAFE_COMMAND)}"
    )
    return os.linesep.join(lines)
