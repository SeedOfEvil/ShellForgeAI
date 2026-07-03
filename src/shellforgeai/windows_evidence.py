"""Consolidated local read-only Windows evidence bundle preview.

The PR264 bundle reuses the existing Windows doctor and status payload builders.
PR269 adds an explicit, bounded, opt-in services component that reuses the
existing PR267 read-only services payload builder. PR272 adds an explicit,
bounded, opt-in disks component that reuses the existing PR270 read-only disks
payload builder. PR276 adds an explicit, bounded, opt-in processes component
that reuses the existing PR274 read-only processes payload builder. The bundle
does not add probes, execute commands, use remoting, control or configure
services, scan directories or files, mutate disks, terminate/control
processes, read process command lines, environments, memory, handles, modules,
or owners, map network connections, read credential caches, write files, or
mutate host state.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from shellforgeai.platform_detection import PlatformInfo, detect_platform
from shellforgeai.windows_disks import (
    DEFAULT_DISKS_LIMIT,
    MAX_DISKS_LIMIT,
    windows_disks_payload,
)
from shellforgeai.windows_doctor import windows_doctor_payload
from shellforgeai.windows_processes import MAX_PROCESSES_LIMIT, windows_processes_payload
from shellforgeai.windows_services import DEFAULT_MAX_SERVICES, windows_services_payload
from shellforgeai.windows_status import windows_status_payload

WINDOWS_EVIDENCE_NEXT_SAFE_COMMAND = "shellforgeai windows status --json"
WINDOWS_EVIDENCE_DISKS_NEXT_SAFE_COMMAND = "shellforgeai windows disks --json"
WINDOWS_EVIDENCE_PROCESSES_NEXT_SAFE_COMMAND = "shellforgeai windows processes --json --limit 10"
UNSUPPORTED_NEXT_SAFE_COMMAND = "shellforgeai platform doctor --json"

EVIDENCE_SERVICES_DEFAULT_LIMIT = 25
EVIDENCE_SERVICES_MAX_LIMIT = DEFAULT_MAX_SERVICES
EVIDENCE_DISKS_DEFAULT_LIMIT = DEFAULT_DISKS_LIMIT
EVIDENCE_DISKS_MAX_LIMIT = MAX_DISKS_LIMIT
EVIDENCE_PROCESSES_DEFAULT_LIMIT = 25
EVIDENCE_PROCESSES_MAX_LIMIT = MAX_PROCESSES_LIMIT

_NOT_COLLECTED_PR264 = {
    "powershell_version": "not collected because PR264 does not execute PowerShell",
    "execution_policy": "not collected because PR264 does not execute PowerShell",
    "services": "planned for later read-only Windows evidence PR",
    "processes": "planned for later read-only Windows evidence PR",
    "event_logs": "planned for later read-only Windows evidence PR",
    "firewall": "planned for later read-only Windows evidence PR",
    "windows_update": "planned for later read-only Windows evidence PR",
}

_WINDOWS_EVIDENCE_SAFETY = {
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

_EVIDENCE_DISKS_SAFETY = {
    "directory_scan_performed": False,
    "file_scan_performed": False,
    "disk_mutation_performed": False,
}

_NOT_COLLECTED_PR272 = {
    "directory_scan": "not collected because PR272 only uses root-level stdlib disk usage",
    "file_scan": "not collected because PR272 does not scan files",
    "disk_repair": "not available because PR272 is read-only",
}

_EVIDENCE_PROCESSES_SAFETY = {
    "process_control_executed": False,
    "process_config_modified": False,
    "process_memory_read": False,
    "process_command_line_read": False,
    "process_environment_read": False,
    "process_handles_read": False,
    "process_modules_read": False,
    "process_owner_read": False,
}

_NOT_COLLECTED_PR276 = {
    "command_line": (
        "not collected because PR276 reuses the bounded PR274 preview and does not "
        "inspect process command lines"
    ),
    "environment": "not collected because PR276 does not inspect process environments",
    "memory": "not collected because PR276 does not inspect process memory",
    "handles": "not collected because PR276 does not inspect process handles",
    "modules": "not collected because PR276 does not enumerate modules",
    "owner_user": "not collected because PR276 does not inspect process owners/users/tokens",
    "network_connections": "not collected because PR276 does not map network connections",
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

PayloadBuilder = Callable[[PlatformInfo], dict[str, Any]]
ServicesBuilder = Callable[[PlatformInfo, int], dict[str, Any]]
DisksBuilder = Callable[[PlatformInfo, int], dict[str, Any]]
ProcessesBuilder = Callable[[PlatformInfo, int], dict[str, Any]]


def validate_evidence_services_limit(value: Any) -> int:
    """Validate the opt-in bundled services limit as a bounded positive integer."""

    message = (
        f"services limit must be a positive integer between 1 and {EVIDENCE_SERVICES_MAX_LIMIT}"
    )
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(message)
    if value < 1 or value > EVIDENCE_SERVICES_MAX_LIMIT:
        raise ValueError(message)
    return value


def validate_evidence_disks_limit(value: Any) -> int:
    """Validate the opt-in bundled disks limit as a bounded positive integer."""

    message = f"disks limit must be a positive integer between 1 and {EVIDENCE_DISKS_MAX_LIMIT}"
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(message)
    if value < 1 or value > EVIDENCE_DISKS_MAX_LIMIT:
        raise ValueError(message)
    return value


def validate_evidence_processes_limit(value: Any) -> int:
    """Validate the opt-in bundled processes limit as a bounded positive integer."""

    message = (
        f"processes limit must be a positive integer between 1 and {EVIDENCE_PROCESSES_MAX_LIMIT}"
    )
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(message)
    if value < 1 or value > EVIDENCE_PROCESSES_MAX_LIMIT:
        raise ValueError(message)
    return value


def _default_services_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_services_payload(info, max_services=limit)


def _default_disks_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_disks_payload(info, limit=limit)


def _default_processes_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_processes_payload(info, limit=limit)


def _embedded_services_component(payload: dict[str, Any], limit: int) -> dict[str, Any]:
    """Wrap the reused services payload with explicit bounded-output fields."""

    component = dict(payload)
    component["limit"] = limit
    services = payload.get("services")
    if isinstance(services, dict):
        items = services.get("items")
        limits = services.get("collection_limits")
        component["total_count"] = services.get("total_count")
        component["returned_count"] = len(items) if isinstance(items, list) else 0
        component["truncated"] = bool(
            limits.get("truncated") if isinstance(limits, dict) else False
        )
    return component


def _embedded_disks_component(payload: dict[str, Any], limit: int) -> dict[str, Any]:
    """Wrap the reused disks payload with explicit bounded-output fields."""

    component = dict(payload)
    component["limit"] = limit
    summary = payload.get("summary")
    collection = payload.get("collection")
    component["total_roots"] = summary.get("total_roots", 0) if isinstance(summary, dict) else 0
    component["returned_roots"] = (
        summary.get("returned_roots", 0) if isinstance(summary, dict) else 0
    )
    component["truncated"] = bool(
        collection.get("truncated") if isinstance(collection, dict) else False
    )
    return component


def _embedded_processes_component(payload: dict[str, Any], limit: int) -> dict[str, Any]:
    """Wrap the reused PR274 processes payload with explicit bounded-output fields.

    A swallowed enumeration failure in the reused payload keeps status "ok" in
    the standalone command; the bundle reports it honestly as a failed component.
    """

    component = dict(payload)
    component["limit"] = limit
    state = payload.get("state")
    if isinstance(state, dict) and state.get("enumeration_failed"):
        component["status"] = "error"
        component["reason"] = "process_enumeration_failed"
    return component


def _component_summary(components: dict[str, dict[str, Any]]) -> dict[str, Any]:
    ok_components = [name for name, payload in components.items() if payload.get("status") == "ok"]
    failed_components = [
        name for name, payload in components.items() if payload.get("status") != "ok"
    ]
    return {
        "component_count": len(components),
        "ok_components": ok_components,
        "failed_components": failed_components,
    }


def windows_evidence_payload(
    info: PlatformInfo | None = None,
    *,
    doctor_builder: PayloadBuilder = windows_doctor_payload,
    status_builder: PayloadBuilder = windows_status_payload,
    include_services: bool = False,
    services_limit: int | None = None,
    services_builder: ServicesBuilder = _default_services_builder,
    include_disks: bool = False,
    disks_limit: int | None = None,
    disks_builder: DisksBuilder = _default_disks_builder,
    include_processes: bool = False,
    processes_limit: int | None = None,
    processes_builder: ProcessesBuilder = _default_processes_builder,
) -> dict[str, Any]:
    """Build the Windows evidence bundle payload.

    The bundle stays doctor/status-only by default. Services are included only
    when ``include_services`` is explicitly requested, bounded by a validated
    limit, and built by reusing the existing PR267 read-only services payload.
    Disks are included only when ``include_disks`` is explicitly requested,
    bounded by a validated limit, and built by reusing the existing PR270
    read-only disks payload. Processes are included only when
    ``include_processes`` is explicitly requested, bounded by a validated
    limit, and built by reusing the existing PR274 read-only processes payload.
    """

    info = info or detect_platform()
    if info.system != "windows":
        return windows_evidence_unsupported_payload(info)

    components = {
        "doctor": doctor_builder(info),
        "status": status_builder(info),
    }
    not_collected = dict(_NOT_COLLECTED_PR264)
    next_safe_command = WINDOWS_EVIDENCE_NEXT_SAFE_COMMAND
    safety = dict(_WINDOWS_EVIDENCE_SAFETY)
    if include_services:
        limit = validate_evidence_services_limit(
            EVIDENCE_SERVICES_DEFAULT_LIMIT if services_limit is None else services_limit
        )
        components["services"] = _embedded_services_component(services_builder(info, limit), limit)
        not_collected["services"] = (
            "included as an explicit opt-in bounded component via --include-services"
        )
        next_safe_command = f"shellforgeai windows services --json --limit {limit}"
    embedded_disks: dict[str, Any] | None = None
    if include_disks:
        bounded_disks_limit = validate_evidence_disks_limit(
            EVIDENCE_DISKS_DEFAULT_LIMIT if disks_limit is None else disks_limit
        )
        disks_component = _embedded_disks_component(
            disks_builder(info, bounded_disks_limit), bounded_disks_limit
        )
        components["disks"] = disks_component
        embedded_disks = {
            "included": True,
            "limit": bounded_disks_limit,
            "returned_roots": disks_component["returned_roots"],
            "total_roots": disks_component["total_roots"],
            "truncated": disks_component["truncated"],
        }
        safety.update(_EVIDENCE_DISKS_SAFETY)
        next_safe_command = WINDOWS_EVIDENCE_DISKS_NEXT_SAFE_COMMAND
    embedded_processes: dict[str, Any] | None = None
    if include_processes:
        bounded_processes_limit = validate_evidence_processes_limit(
            EVIDENCE_PROCESSES_DEFAULT_LIMIT if processes_limit is None else processes_limit
        )
        processes_component = _embedded_processes_component(
            processes_builder(info, bounded_processes_limit), bounded_processes_limit
        )
        components["processes"] = processes_component
        embedded_processes = {
            "included": True,
            "limit": bounded_processes_limit,
            "returned_count": processes_component.get("returned_count", 0),
            "total_count": processes_component.get("total_count", 0),
            "truncated": bool(processes_component.get("truncated", False)),
        }
        not_collected["processes"] = (
            "included as an explicit opt-in bounded component via --include-processes"
        )
        safety.update(_EVIDENCE_PROCESSES_SAFETY)
        next_safe_command = WINDOWS_EVIDENCE_PROCESSES_NEXT_SAFE_COMMAND
    summary = _component_summary(components)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "mode": "windows_evidence_bundle",
        "status": "ok" if not summary["failed_components"] else "component_failure",
        "platform": {"system": info.system},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_evidence_bundle",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "components": components,
        "summary": summary,
        "safety": safety,
        "not_collected_in_pr264": not_collected,
        "next_safe_command": next_safe_command,
    }
    if embedded_disks is not None:
        payload["embedded_disks"] = embedded_disks
        payload["not_collected_in_pr272"] = dict(_NOT_COLLECTED_PR272)
    if embedded_processes is not None:
        payload["embedded_processes"] = embedded_processes
        payload["not_collected_in_pr276"] = dict(_NOT_COLLECTED_PR276)
    return payload


def windows_evidence_unsupported_payload(info: PlatformInfo | None = None) -> dict[str, Any]:
    """Build deterministic unsupported output for non-Windows hosts."""

    info = info or detect_platform()
    return {
        "schema_version": 1,
        "mode": "windows_evidence_bundle",
        "status": "unsupported",
        "platform": {"system": info.system},
        "reason": "Windows evidence bundle is only available on Windows hosts.",
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": False,
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "safety": {key: _WINDOWS_EVIDENCE_SAFETY[key] for key in _UNSUPPORTED_SAFETY_KEYS},
        "next_safe_command": UNSUPPORTED_NEXT_SAFE_COMMAND,
    }


def render_windows_evidence_text(payload: dict[str, Any]) -> str:
    """Render concise operator-facing text for the Windows evidence bundle."""

    platform_system = payload.get("platform", {}).get("system", "unknown")
    windows_v1 = payload.get("windows_v1", {})
    summary = payload.get("summary", {})
    components = payload.get("components", {})
    component_names = ", ".join(components) if components else "none"
    lines = [
        "ShellForgeAI Windows evidence bundle",
        f"Status: {payload.get('status', 'unknown')}",
        f"Platform: {platform_system}",
        f"Windows V1 available: {str(windows_v1.get('available', False)).lower()}",
        f"Read-only: {str(payload.get('read_only', False)).lower()}",
        f"Mutation performed: {str(payload.get('mutation_performed', True)).lower()}",
        f"Components included: {component_names}",
    ]
    if summary:
        lines.append(
            "Component summary: "
            f"ok={','.join(summary.get('ok_components', [])) or 'none'}; "
            f"failed={','.join(summary.get('failed_components', [])) or 'none'}"
        )
    services_component = components.get("services") if isinstance(components, dict) else None
    if isinstance(services_component, dict):
        parts = [
            f"status={services_component.get('status', 'unknown')}",
            f"returned={services_component.get('returned_count', 0)}",
            f"total={services_component.get('total_count', 0)}",
            f"truncated={str(services_component.get('truncated', False)).lower()}",
        ]
        state_counts = (services_component.get("services") or {}).get("state_counts") or {}
        if state_counts:
            parts.append(f"running={state_counts.get('running', 0)}")
            parts.append(f"stopped={state_counts.get('stopped', 0)}")
        lines.append("Services component: " + "; ".join(parts))
    disks_component = components.get("disks") if isinstance(components, dict) else None
    if isinstance(disks_component, dict):
        lines.append(
            "Disks component: "
            f"status={disks_component.get('status', 'unknown')}; "
            f"returned={disks_component.get('returned_roots', 0)}; "
            f"total={disks_component.get('total_roots', 0)}; "
            f"limit={disks_component.get('limit', 0)}; "
            f"truncated={str(disks_component.get('truncated', False)).lower()}"
        )
    processes_component = components.get("processes") if isinstance(components, dict) else None
    if isinstance(processes_component, dict):
        lines.append(
            "Processes component: "
            f"status={processes_component.get('status', 'unknown')}; "
            f"returned={processes_component.get('returned_count', 0)}; "
            f"total={processes_component.get('total_count', 0)}; "
            f"limit={processes_component.get('limit', 0)}; "
            f"truncated={str(processes_component.get('truncated', False)).lower()}"
        )
    if payload.get("status") == "unsupported":
        lines.append(str(payload.get("reason", "Windows evidence bundle is unavailable.")))
    pending = [
        "PowerShell version",
        "execution policy",
        "services",
        "processes",
        "event logs",
        "firewall",
        "Windows Update",
    ]
    if isinstance(services_component, dict):
        pending.remove("services")
    if isinstance(processes_component, dict):
        pending.remove("processes")
    lines.append("Not collected yet: " + ", ".join(pending) + ".")
    lines.append(
        f"Next safe command: {payload.get('next_safe_command', UNSUPPORTED_NEXT_SAFE_COMMAND)}"
    )
    return os.linesep.join(lines)
