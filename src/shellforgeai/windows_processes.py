"""Local read-only Windows process preview.

The collector returns bounded, local, safe process metadata from Windows
Toolhelp snapshots and a point-in-time working-set counter for selected rows.
It never uses subprocesses, shells, PowerShell, WinRM/remoting, process control,
retained process handles, command lines, environments, memory-content reads, modules, owners,
network mapping, file writes, model calls, or secrets/auth-cache reads.
"""

from __future__ import annotations

import ctypes
import os
from collections.abc import Callable, Sequence
from typing import Any

from shellforgeai.platform_detection import PlatformInfo, detect_platform

DEFAULT_PROCESSES_LIMIT = 50
MIN_PROCESSES_LIMIT = 1
MAX_PROCESSES_LIMIT = 200

METHOD = "ctypes_toolhelp32_snapshot"
WINDOWS_PROCESSES_NEXT_SAFE_COMMAND = "shellforgeai windows processes --json --limit 10"
UNSUPPORTED_NEXT_SAFE_COMMAND = "shellforgeai platform doctor --json"

_ALLOWED_PROCESS_KEYS = {
    "pid",
    "parent_pid",
    "name",
    "thread_count",
    "working_set_bytes",
    "working_set_available",
}

_NOT_COLLECTED_PR274 = {
    "command_line": "not collected because PR274 does not inspect process command lines",
    "environment": "not collected because PR274 does not inspect process environments",
    "memory": "process memory contents are not read; only a working-set counter is queried",
    "handles": "process handle tables are not inspected; short-lived query handles are used",
    "modules": "not collected because PR274 does not enumerate modules",
    "owner_user": "not collected because PR274 does not inspect process tokens/users",
    "network_connections": "not collected because PR274 does not map network connections",
}

_WINDOWS_PROCESSES_SAFETY = {
    "read_only": True,
    "mutation_performed": False,
    "powershell_executed": False,
    "winrm_used": False,
    "remote_execution": False,
    "process_termination_executed": False,
    "process_control_executed": False,
    "process_config_modified": False,
    "process_memory_read": False,
    "process_working_set_collection_enabled": True,
    "process_query_handles_may_open": True,
    "process_command_line_read": False,
    "process_environment_read": False,
    "process_handles_read": False,
    "process_modules_read": False,
    "process_owner_read": False,
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
    "process_termination_executed",
    "process_control_executed",
    "process_memory_read",
    "process_command_line_read",
    "process_environment_read",
    "process_handles_read",
    "process_modules_read",
    "natural_language_execution",
    "shell_true",
    "arbitrary_command_execution",
    "secret_read",
    "auth_cache_read",
    "model_called",
    "network_call",
)

ProcessEnumerator = Callable[[], Sequence[dict[str, Any]]]
WorkingSetObserver = Callable[[int], int]


def validate_processes_limit(value: int) -> int:
    """Validate the bounded process limit; invalid values fail instead of clamping."""

    try:
        numeric = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"--limit must be an integer, got {value!r}") from exc
    if isinstance(value, bool) or numeric < MIN_PROCESSES_LIMIT or numeric > MAX_PROCESSES_LIMIT:
        raise ValueError(
            "--limit must be between "
            f"{MIN_PROCESSES_LIMIT} and {MAX_PROCESSES_LIMIT}, got {value!r}"
        )
    return numeric


def _process_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "pid": int(item.get("pid", 0)),
        "parent_pid": int(item.get("parent_pid", 0)),
        "name": os.path.basename(str(item.get("name", ""))),
        "thread_count": int(item.get("thread_count", 0)),
    }


def _enumerate_toolhelp_processes() -> list[dict[str, Any]]:
    # Constants are from the documented Toolhelp snapshot API.
    th32cs_snapprocess = 0x00000002
    invalid_handle_value = ctypes.c_void_p(-1).value
    max_path = 260

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong),
            ("cntUsage", ctypes.c_ulong),
            ("th32ProcessID", ctypes.c_ulong),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", ctypes.c_ulong),
            ("cntThreads", ctypes.c_ulong),
            ("th32ParentProcessID", ctypes.c_ulong),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong),
            ("szExeFile", ctypes.c_wchar * max_path),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = ctypes.c_int
    kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    snapshot = kernel32.CreateToolhelp32Snapshot(th32cs_snapprocess, 0)
    if snapshot == invalid_handle_value:
        raise OSError("toolhelp snapshot failed")
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        processes: list[dict[str, Any]] = []
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            processes.append(
                {
                    "pid": int(entry.th32ProcessID),
                    "parent_pid": int(entry.th32ParentProcessID),
                    "name": os.path.basename(str(entry.szExeFile)),
                    "thread_count": int(entry.cntThreads),
                }
            )
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        return processes
    finally:
        kernel32.CloseHandle(snapshot)


def _query_process_working_set_bytes(pid: int) -> int:
    """Return one current working-set counter using a short-lived query handle."""

    process_query_limited_information = 0x1000

    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    psapi.GetProcessMemoryInfo.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
        ctypes.c_ulong,
    ]
    psapi.GetProcessMemoryInfo.restype = ctypes.c_int

    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        raise OSError(getattr(ctypes, "get_last_error", lambda: 0)(), "OpenProcess failed")
    try:
        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            raise OSError(
                getattr(ctypes, "get_last_error", lambda: 0)(), "GetProcessMemoryInfo failed"
            )
        return int(counters.WorkingSetSize)
    finally:
        kernel32.CloseHandle(handle)


def windows_processes_payload(
    info: PlatformInfo | None = None,
    *,
    process_enumerator: ProcessEnumerator | None = None,
    working_set_observer: WorkingSetObserver | None = None,
    limit: int = DEFAULT_PROCESSES_LIMIT,
) -> dict[str, Any]:
    """Build the PR274 Windows processes JSON-compatible payload."""

    info = info or detect_platform()
    if info.system != "windows":
        return windows_processes_unsupported_payload(info)

    bounded_limit = validate_processes_limit(limit)
    process_enumerator = process_enumerator or _enumerate_toolhelp_processes
    state = {"enumeration_failed": False}
    try:
        all_processes = [_process_item(item) for item in process_enumerator()]
    except Exception:
        state["enumeration_failed"] = True
        all_processes = []

    total_count = len(all_processes)
    processes = all_processes[:bounded_limit]
    observer = working_set_observer or _query_process_working_set_bytes
    for process in processes:
        try:
            working_set_bytes = observer(process["pid"])
            if isinstance(working_set_bytes, bool) or working_set_bytes < 0:
                raise ValueError("working set must be a non-negative integer")
            process["working_set_bytes"] = int(working_set_bytes)
            process["working_set_available"] = True
        except Exception:
            process["working_set_bytes"] = None
            process["working_set_available"] = False
    return {
        "schema_version": 1,
        "mode": "windows_processes",
        "status": "ok",
        "platform": {"system": info.system},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_processes_preview",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "method": METHOD,
        "limit": bounded_limit,
        "total_count": total_count,
        "returned_count": len(processes),
        "truncated": total_count > bounded_limit,
        "state": state,
        "processes": processes,
        "not_collected_in_pr274": dict(_NOT_COLLECTED_PR274),
        "safety": dict(_WINDOWS_PROCESSES_SAFETY),
        "next_safe_command": WINDOWS_PROCESSES_NEXT_SAFE_COMMAND,
    }


def windows_processes_unsupported_payload(info: PlatformInfo | None = None) -> dict[str, Any]:
    """Build deterministic unsupported output for non-Windows hosts."""

    info = info or detect_platform()
    return {
        "schema_version": 1,
        "mode": "windows_processes",
        "status": "unsupported",
        "platform": {"system": info.system},
        "reason": "Windows processes preview is only available on Windows hosts.",
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": False,
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "safety": {key: _WINDOWS_PROCESSES_SAFETY[key] for key in _UNSUPPORTED_SAFETY_KEYS},
        "next_safe_command": UNSUPPORTED_NEXT_SAFE_COMMAND,
    }


def render_windows_processes_text(payload: dict[str, Any]) -> str:
    """Render concise operator-facing text for the Windows processes payload."""

    platform_system = payload.get("platform", {}).get("system", "unknown")
    lines = [
        "ShellForgeAI Windows processes",
        f"Status: {payload.get('status', 'unknown')}",
        f"Platform: {platform_system}",
        f"Method: {payload.get('method', 'unavailable')}",
        f"Read-only: {str(payload.get('read_only', False)).lower()}",
        f"Mutation performed: {str(payload.get('mutation_performed', True)).lower()}",
    ]
    if payload.get("status") == "unsupported":
        lines.append(str(payload.get("reason", "Windows processes preview is unavailable.")))
    else:
        total = payload.get("total_count", 0)
        returned = payload.get("returned_count", 0)
        limit = payload.get("limit", DEFAULT_PROCESSES_LIMIT)
        truncated = str(payload.get("truncated", False)).lower()
        lines.append(
            f"Processes: total={total}; returned={returned}; limit={limit}; truncated={truncated}"
        )
        for item in payload.get("processes", [])[:5]:
            safe_item = {key: item.get(key) for key in sorted(_ALLOWED_PROCESS_KEYS)}
            lines.append(
                (
                    "- pid={pid} parent_pid={parent_pid} name={name} thread_count={thread_count} "
                    "working_set_bytes={working_set}"
                ).format(
                    **safe_item,
                    working_set=(
                        safe_item["working_set_bytes"]
                        if safe_item["working_set_available"]
                        else "unavailable"
                    ),
                )
            )
    lines.append(
        "Not collected: command lines, environments, process memory contents, "
        "handle tables, modules, "
        "owners/tokens, network connections."
    )
    lines.append(
        f"Next safe command: {payload.get('next_safe_command', UNSUPPORTED_NEXT_SAFE_COMMAND)}"
    )
    return os.linesep.join(lines)
