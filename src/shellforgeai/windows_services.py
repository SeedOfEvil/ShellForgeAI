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
    "service_binary_path": "not collected; service configuration and registry are not read",
    "service_executable_command_line": (
        "not collected; process/configuration inspection is out of scope"
    ),
    "service_account": "not collected; service configuration and registry are not read",
    "service_description": "not collected; service configuration is out of scope",
    "service_dependencies": "not collected; dependency traversal is out of scope",
    "delayed_auto_start_configuration": "not collected; service configuration is out of scope",
    "trigger_configuration": "not collected; service configuration is out of scope",
    "service_recovery_options": "not collected; recovery/failure actions are out of scope",
    "failure_actions": "not collected; recovery/failure actions are out of scope",
    "security_descriptor": "not collected; permissions/ACLs are out of scope",
    "permissions_acls": "not collected; permissions/ACLs are out of scope",
    "registry_configuration": "not collected; registry access is out of scope",
    "process_details": "not collected; process inspection is out of scope",
    "process_details_beyond_scm_pid": (
        "not collected; the PID already returned by SCM is not opened or inspected"
    ),
    "event_logs": "not collected; event-log collection is out of scope",
    "process_owner": "not collected; process inspection is out of scope",
    "process_command_line": "not collected; process inspection is out of scope",
    "process_environment": "not collected; process inspection is out of scope",
    "service_event_logs": "not collected; event-log collection is out of scope",
    "service_restart_history": "not collected; event-log/recovery collection is out of scope",
    "remote_service_state": "not collected; remote collection is out of scope",
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
    """One enumerated service from SERVICE_STATUS_PROCESS."""

    name: str
    display_name: str
    state_code: int
    service_type_code: int
    process_id: int = 0
    controls_accepted_mask: int = 0
    win32_exit_code: int = 0
    service_specific_exit_code: int = 0
    checkpoint: int = 0
    wait_hint_ms: int = 0
    service_flags: int = 0


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


_PENDING_STATES = {"start_pending", "stop_pending", "continue_pending", "pause_pending"}
_SERVICE_RUNS_IN_SYSTEM_PROCESS = 0x00000001
_ACCEPTED_CONTROLS: tuple[tuple[int, str], ...] = (
    (0x00000001, "stop"),
    (0x00000002, "pause_continue"),
    (0x00000004, "shutdown"),
    (0x00000008, "param_change"),
    (0x00000010, "netbind_change"),
    (0x00000020, "hardware_profile_change"),
    (0x00000040, "power_event"),
    (0x00000080, "session_change"),
    (0x00000100, "preshutdown"),
    (0x00000200, "time_change"),
    (0x00000400, "trigger_event"),
    (0x00000800, "user_logoff"),
)
_KNOWN_ACCEPTED_CONTROLS_MASK = 0
for _mask, _label in _ACCEPTED_CONTROLS:
    _KNOWN_ACCEPTED_CONTROLS_MASK |= _mask


def normalize_controls(mask: int) -> tuple[list[str], int]:
    numeric = max(0, int(mask))
    return [
        label for bit, label in _ACCEPTED_CONTROLS if numeric & bit
    ], numeric & ~_KNOWN_ACCEPTED_CONTROLS_MASK


def runtime_signals(record: RawServiceRecord) -> list[str]:
    state = service_state_label(record.state_code)
    signals: list[str] = []
    if state in _PENDING_STATES:
        signals.append("pending")
    if record.process_id > 0:
        signals.append("process_attached")
    if record.win32_exit_code > 0:
        signals.append("nonzero_win32_exit_code")
    if record.service_specific_exit_code > 0:
        signals.append("nonzero_service_specific_exit_code")
    if record.checkpoint > 0:
        signals.append("checkpoint_present")
    if record.wait_hint_ms > 0:
        signals.append("wait_hint_present")
    if record.service_flags & _SERVICE_RUNS_IN_SYSTEM_PROCESS:
        signals.append("runs_in_system_process")
    return signals


def summarize_service_states(records: Sequence[RawServiceRecord]) -> dict[str, int]:
    """Count services per state with every known state key present."""

    counts = dict.fromkeys(_STATE_COUNT_KEYS, 0)
    for record in records:
        counts[service_state_label(record.state_code)] += 1
    return counts


def _sorted_records(records: Sequence[RawServiceRecord]) -> list[RawServiceRecord]:
    return sorted(records, key=lambda record: (record.name.casefold(), record.name))


def _service_item(record: RawServiceRecord) -> dict[str, Any]:
    controls, unknown_mask = normalize_controls(record.controls_accepted_mask)
    return {
        "name": record.name,
        "display_name": record.display_name,
        "state": service_state_label(record.state_code),
        "service_type": service_type_label(record.service_type_code),
        "process_id": record.process_id if record.process_id > 0 else None,
        "controls_accepted": controls,
        "controls_accepted_unknown_mask": unknown_mask,
        "win32_exit_code": max(0, int(record.win32_exit_code)),
        "service_specific_exit_code": max(0, int(record.service_specific_exit_code)),
        "checkpoint": max(0, int(record.checkpoint)),
        "wait_hint_ms": max(0, int(record.wait_hint_ms)),
        "runs_in_system_process": bool(record.service_flags & _SERVICE_RUNS_IN_SYSTEM_PROCESS),
        "runtime_signals": runtime_signals(record),
    }


def summarize_service_runtime(records: Sequence[RawServiceRecord]) -> dict[str, int]:
    summary = {
        "running_with_process_id": 0,
        "running_without_process_id": 0,
        "pending_services": 0,
        "services_with_nonzero_win32_exit_code": 0,
        "services_with_nonzero_service_specific_exit_code": 0,
        "services_with_checkpoint": 0,
        "services_with_wait_hint": 0,
        "services_accepting_stop": 0,
        "services_accepting_pause_continue": 0,
        "services_running_in_system_process": 0,
        "runtime_signal_services": 0,
    }
    for record in records:
        state = service_state_label(record.state_code)
        controls, _unknown = normalize_controls(record.controls_accepted_mask)
        signals = runtime_signals(record)
        if state == "running" and record.process_id > 0:
            summary["running_with_process_id"] += 1
        if state == "running" and record.process_id <= 0:
            summary["running_without_process_id"] += 1
        if state in _PENDING_STATES:
            summary["pending_services"] += 1
        if record.win32_exit_code > 0:
            summary["services_with_nonzero_win32_exit_code"] += 1
        if record.service_specific_exit_code > 0:
            summary["services_with_nonzero_service_specific_exit_code"] += 1
        if record.checkpoint > 0:
            summary["services_with_checkpoint"] += 1
        if record.wait_hint_ms > 0:
            summary["services_with_wait_hint"] += 1
        if "stop" in controls:
            summary["services_accepting_stop"] += 1
        if "pause_continue" in controls:
            summary["services_accepting_pause_continue"] += 1
        if record.service_flags & _SERVICE_RUNS_IN_SYSTEM_PROCESS:
            summary["services_running_in_system_process"] += 1
        if signals:
            summary["runtime_signal_services"] += 1
    return summary


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
                        process_id=int(status.dwProcessId),
                        controls_accepted_mask=int(status.dwControlsAccepted),
                        win32_exit_code=int(status.dwWin32ExitCode),
                        service_specific_exit_code=int(status.dwServiceSpecificExitCode),
                        checkpoint=int(status.dwCheckPoint),
                        wait_hint_ms=int(status.dwWaitHint),
                        service_flags=int(status.dwServiceFlags),
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
            "runtime_summary": summarize_service_runtime(ordered),
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
        runtime = services.get("runtime_summary") or {}
        nonzero_exit_codes = runtime.get("services_with_nonzero_win32_exit_code", 0) + runtime.get(
            "services_with_nonzero_service_specific_exit_code", 0
        )
        lines.append(
            "Runtime: "
            f"running_with_pid={runtime.get('running_with_process_id', 0)}; "
            f"pending={runtime.get('pending_services', 0)}; "
            f"nonzero_exit_codes={nonzero_exit_codes}; "
            f"system_process={runtime.get('services_running_in_system_process', 0)}"
        )
        lines.append("Runtime signals are point-in-time observations, not failure diagnoses.")
        preview = [
            item
            for item in services.get("items", [])
            if item.get("state") in _PENDING_STATES
            or item.get("win32_exit_code", 0) > 0
            or item.get("service_specific_exit_code", 0) > 0
        ]
        preview = sorted(
            preview,
            key=lambda item: (str(item.get("name", "")).casefold(), str(item.get("name", ""))),
        )
        if preview:
            lines.append("Runtime signal preview:")
            for item in preview[:10]:
                pid = item.get("process_id")
                pid_text = f" pid={pid};" if pid else ""
                lines.append(
                    f"- {item.get('name', '')}: state={item.get('state', 'unknown')};{pid_text} "
                    f"win32_exit_code={item.get('win32_exit_code', 0)}; "
                    f"service_specific_exit_code={item.get('service_specific_exit_code', 0)}; "
                    f"checkpoint={item.get('checkpoint', 0)}; "
                    f"wait_hint_ms={item.get('wait_hint_ms', 0)}"
                )
            if len(preview) > 10:
                lines.append(
                    "Runtime signal preview truncated: "
                    f"{len(preview) - 10} additional services not shown."
                )
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
