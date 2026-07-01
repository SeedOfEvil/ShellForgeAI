"""Local read-only Windows services state summary preview.

The PR267 services preview is intentionally stdlib-only. It enumerates local
service names, display names, and current states through read-only Service
Control Manager access only. It never executes shells, controls or configures
services, opens per-service handles, reads the registry, uses remoting, reads
credential caches, opens network connections, writes files, or mutates host
state.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from shellforgeai.platform_detection import PlatformInfo, detect_platform

WINDOWS_SERVICES_NEXT_SAFE_COMMAND = "shellforgeai windows status --json"
UNSUPPORTED_NEXT_SAFE_COMMAND = "shellforgeai platform doctor --json"

DEFAULT_MAX_SERVICES = 500
_MIN_MAX_SERVICES = 1
_HARD_MAX_SERVICES = 500

_NOT_COLLECTED_PR267 = {
    "service_binary_path": (
        "not collected because PR267 does not read service configuration or registry"
    ),
    "service_account": (
        "not collected because PR267 does not read service configuration or registry"
    ),
    "service_description": "planned for later read-only Windows evidence PR",
    "service_dependencies": "planned for later read-only Windows evidence PR",
    "service_recovery_options": "planned for later read-only Windows evidence PR",
    "process_details": "planned for later read-only Windows evidence PR",
    "event_logs": "planned for later read-only Windows evidence PR",
    "firewall": "planned for later read-only Windows evidence PR",
    "windows_update": "planned for later read-only Windows evidence PR",
}

_WINDOWS_SERVICES_SAFETY = {
    "read_only": True,
    "mutation_performed": False,
    "powershell_executed": False,
    "winrm_used": False,
    "remote_execution": False,
    "service_restart_executed": False,
    "service_control_executed": False,
    "service_config_modified": False,
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
    "service_restart_executed",
    "service_control_executed",
    "natural_language_execution",
    "shell_true",
    "arbitrary_command_execution",
    "secret_read",
    "auth_cache_read",
    "model_called",
    "network_call",
)

# SERVICE_STATUS dwCurrentState values from the Windows SDK. Anything outside
# this table is reported as "unknown" rather than guessed.
_SERVICE_STATE_BY_CODE = {
    1: "stopped",
    2: "start_pending",
    3: "stop_pending",
    4: "running",
    5: "continue_pending",
    6: "pause_pending",
    7: "paused",
}

_STATE_COUNT_KEYS = (
    "running",
    "stopped",
    "paused",
    "start_pending",
    "stop_pending",
    "continue_pending",
    "pause_pending",
    "unknown",
)

# SERVICE_STATUS dwServiceType values from the Windows SDK, with the
# SERVICE_INTERACTIVE_PROCESS flag (0x100) stripped before lookup.
_SERVICE_TYPE_BY_CODE = {
    0x00000001: "kernel_driver",
    0x00000002: "file_system_driver",
    0x00000010: "win32_own_process",
    0x00000020: "win32_share_process",
    0x00000050: "user_own_process",
    0x00000060: "user_share_process",
}
_SERVICE_INTERACTIVE_PROCESS_FLAG = 0x00000100


@dataclass(frozen=True)
class RawServiceRecord:
    """One enumerated service: identity and current state only."""

    name: str
    display_name: str
    state_code: int
    service_type_code: int


ServiceEnumerator = Callable[[], Sequence[RawServiceRecord]]


def service_state_label(state_code: int) -> str:
    """Map a SERVICE_STATUS current-state code to a deterministic label."""

    return _SERVICE_STATE_BY_CODE.get(state_code, "unknown")


def service_type_label(service_type_code: int) -> str:
    """Map a SERVICE_STATUS service-type code to a deterministic label."""

    base = service_type_code & ~_SERVICE_INTERACTIVE_PROCESS_FLAG
    return _SERVICE_TYPE_BY_CODE.get(base, "unknown")


def bounded_max_services(value: int) -> int:
    """Clamp a requested collection limit into the supported bounded range."""

    try:
        numeric = int(value)
    except (TypeError, ValueError):
        return DEFAULT_MAX_SERVICES
    return max(_MIN_MAX_SERVICES, min(numeric, _HARD_MAX_SERVICES))


def summarize_service_states(records: Sequence[RawServiceRecord]) -> dict[str, int]:
    """Count services per state with every known state key present."""

    counts = dict.fromkeys(_STATE_COUNT_KEYS, 0)
    for record in records:
        counts[service_state_label(record.state_code)] += 1
    return counts


def _sorted_records(records: Sequence[RawServiceRecord]) -> list[RawServiceRecord]:
    return sorted(records, key=lambda record: (record.name.casefold(), record.name))


def _service_item(record: RawServiceRecord) -> dict[str, str]:
    return {
        "name": record.name,
        "display_name": record.display_name,
        "state": service_state_label(record.state_code),
        "service_type": service_type_label(record.service_type_code),
    }


def _enumerate_windows_services() -> list[RawServiceRecord]:
    """Enumerate local services via read-only Service Control Manager access.

    Only ``OpenSCManagerW`` with enumerate rights, ``EnumServicesStatusExW``,
    and ``CloseServiceHandle`` are used. No per-service handles are opened and
    no control, configuration, registry, or process APIs are touched.
    """

    import ctypes
    from ctypes import wintypes

    sc_manager_enumerate_service = 0x0004
    sc_enum_process_info = 0
    service_win32 = 0x00000030
    service_state_all = 0x00000003
    error_more_data = 234

    class _ServiceStatusProcess(ctypes.Structure):
        _fields_ = (
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
            ("dwProcessId", wintypes.DWORD),
            ("dwServiceFlags", wintypes.DWORD),
        )

    class _EnumServiceStatusProcessW(ctypes.Structure):
        _fields_ = (
            ("lpServiceName", wintypes.LPWSTR),
            ("lpDisplayName", wintypes.LPWSTR),
            ("ServiceStatusProcess", _ServiceStatusProcess),
        )

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.OpenSCManagerW.restype = ctypes.c_void_p
    advapi32.OpenSCManagerW.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
    advapi32.CloseServiceHandle.restype = wintypes.BOOL
    advapi32.CloseServiceHandle.argtypes = (ctypes.c_void_p,)
    advapi32.EnumServicesStatusExW.restype = wintypes.BOOL
    advapi32.EnumServicesStatusExW.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPCWSTR,
    )

    scm_handle = advapi32.OpenSCManagerW(None, None, sc_manager_enumerate_service)
    if not scm_handle:
        raise ctypes.WinError(ctypes.get_last_error())

    records: list[RawServiceRecord] = []
    try:
        bytes_needed = wintypes.DWORD(0)
        services_returned = wintypes.DWORD(0)
        resume_handle = wintypes.DWORD(0)
        buffer_size = 0
        while True:
            buffer = (ctypes.c_char * max(buffer_size, 1))()
            success = advapi32.EnumServicesStatusExW(
                scm_handle,
                sc_enum_process_info,
                service_win32,
                service_state_all,
                buffer,
                buffer_size,
                ctypes.byref(bytes_needed),
                ctypes.byref(services_returned),
                ctypes.byref(resume_handle),
                None,
            )
            error_code = ctypes.get_last_error()
            if not success and error_code != error_more_data:
                raise ctypes.WinError(error_code)
            entries = ctypes.cast(
                buffer,
                ctypes.POINTER(_EnumServiceStatusProcessW * services_returned.value),
            ).contents
            for entry in entries:
                status = entry.ServiceStatusProcess
                records.append(
                    RawServiceRecord(
                        name=str(entry.lpServiceName or ""),
                        display_name=str(entry.lpDisplayName or ""),
                        state_code=int(status.dwCurrentState),
                        service_type_code=int(status.dwServiceType),
                    )
                )
            if success:
                break
            buffer_size = bytes_needed.value
    finally:
        advapi32.CloseServiceHandle(scm_handle)
    return records


def windows_services_payload(
    info: PlatformInfo | None = None,
    *,
    enumerator: ServiceEnumerator | None = None,
    max_services: int = DEFAULT_MAX_SERVICES,
) -> dict[str, Any]:
    """Build the PR267 Windows services JSON-compatible payload."""

    info = info or detect_platform()
    if info.system != "windows":
        return windows_services_unsupported_payload(info)

    limit = bounded_max_services(max_services)
    enumerator = enumerator or _enumerate_windows_services
    try:
        records = list(enumerator())
    except Exception as exc:  # normal permission/API failures must not traceback
        return windows_services_error_payload(
            info, reason=f"service enumeration failed: {type(exc).__name__}"
        )

    ordered = _sorted_records(records)
    total_count = len(ordered)
    truncated = total_count > limit
    return {
        "schema_version": 1,
        "mode": "windows_services",
        "status": "ok",
        "platform": {"system": info.system},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_services",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "services": {
            "collection": "local_windows_service_state_summary",
            "total_count": total_count,
            "state_counts": summarize_service_states(ordered),
            "items": [_service_item(record) for record in ordered[:limit]],
            "collection_limits": {
                "max_services": limit,
                "truncated": truncated,
            },
        },
        "not_collected_in_pr267": dict(_NOT_COLLECTED_PR267),
        "safety": dict(_WINDOWS_SERVICES_SAFETY),
        "next_safe_command": WINDOWS_SERVICES_NEXT_SAFE_COMMAND,
    }


def windows_services_error_payload(
    info: PlatformInfo | None = None, *, reason: str
) -> dict[str, Any]:
    """Build a structured, non-traceback error payload for enumeration failures."""

    info = info or detect_platform()
    return {
        "schema_version": 1,
        "mode": "windows_services",
        "status": "error",
        "platform": {"system": info.system},
        "reason": reason,
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_services",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "not_collected_in_pr267": dict(_NOT_COLLECTED_PR267),
        "safety": dict(_WINDOWS_SERVICES_SAFETY),
        "next_safe_command": WINDOWS_SERVICES_NEXT_SAFE_COMMAND,
    }


def windows_services_unsupported_payload(info: PlatformInfo | None = None) -> dict[str, Any]:
    """Build deterministic unsupported output for non-Windows hosts."""

    info = info or detect_platform()
    return {
        "schema_version": 1,
        "mode": "windows_services",
        "status": "unsupported",
        "platform": {"system": info.system},
        "reason": "Windows services evidence is only available on Windows hosts.",
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": False,
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "safety": {key: _WINDOWS_SERVICES_SAFETY[key] for key in _UNSUPPORTED_SAFETY_KEYS},
        "next_safe_command": UNSUPPORTED_NEXT_SAFE_COMMAND,
    }


def render_windows_services_text(payload: dict[str, Any]) -> str:
    """Render concise operator-facing text for the Windows services payload."""

    platform_system = payload.get("platform", {}).get("system", "unknown")
    windows_v1 = payload.get("windows_v1", {})
    lines = [
        "ShellForgeAI Windows services",
        f"Status: {payload.get('status', 'unknown')}",
        f"Platform: {platform_system}",
        f"Windows V1 available: {str(windows_v1.get('available', False)).lower()}",
        f"Read-only: {str(payload.get('read_only', False)).lower()}",
        f"Mutation performed: {str(payload.get('mutation_performed', True)).lower()}",
    ]
    services = payload.get("services") or {}
    if services:
        lines.append(f"Total services: {services.get('total_count', 0)}")
        state_counts = services.get("state_counts") or {}
        lines.append(
            "States: " + "; ".join(f"{key}={state_counts.get(key, 0)}" for key in _STATE_COUNT_KEYS)
        )
        limits = services.get("collection_limits") or {}
        lines.append(
            "Collection limit: "
            f"max_services={limits.get('max_services', DEFAULT_MAX_SERVICES)}; "
            f"truncated={str(limits.get('truncated', False)).lower()}"
        )
    if payload.get("status") in ("unsupported", "error"):
        lines.append(
            str(payload.get("reason", "Windows services evidence is unavailable on this host."))
        )
    lines.append(
        "Not collected yet: service binary paths/accounts/config, descriptions, "
        "dependencies, recovery options, process details, event logs, firewall, "
        "Windows Update."
    )
    lines.append(
        f"Next safe command: {payload.get('next_safe_command', UNSUPPORTED_NEXT_SAFE_COMMAND)}"
    )
    return os.linesep.join(lines)
