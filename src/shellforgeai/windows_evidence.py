"""Consolidated local read-only Windows evidence bundle preview.

The PR264 bundle reuses the existing Windows doctor and status payload builders.
PR269 adds an explicit, bounded, opt-in services component that reuses the
existing PR267 read-only services payload builder. The bundle does not add
probes, execute commands, use remoting, control or configure services, open
network connections, read credential caches, write files, or mutate host state.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from shellforgeai.platform_detection import PlatformInfo, detect_platform
from shellforgeai.windows_doctor import windows_doctor_payload
from shellforgeai.windows_services import DEFAULT_MAX_SERVICES, windows_services_payload
from shellforgeai.windows_status import windows_status_payload

WINDOWS_EVIDENCE_NEXT_SAFE_COMMAND = "shellforgeai windows status --json"
UNSUPPORTED_NEXT_SAFE_COMMAND = "shellforgeai platform doctor --json"

EVIDENCE_SERVICES_DEFAULT_LIMIT = 25
EVIDENCE_SERVICES_MAX_LIMIT = DEFAULT_MAX_SERVICES

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


def _default_services_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_services_payload(info, max_services=limit)


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
) -> dict[str, Any]:
    """Build the Windows evidence bundle payload.

    The bundle stays doctor/status-only by default. Services are included only
    when ``include_services`` is explicitly requested, bounded by a validated
    limit, and built by reusing the existing PR267 read-only services payload.
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
    if include_services:
        limit = validate_evidence_services_limit(
            EVIDENCE_SERVICES_DEFAULT_LIMIT if services_limit is None else services_limit
        )
        components["services"] = _embedded_services_component(services_builder(info, limit), limit)
        not_collected["services"] = (
            "included as an explicit opt-in bounded component via --include-services"
        )
        next_safe_command = f"shellforgeai windows services --json --limit {limit}"
    summary = _component_summary(components)
    return {
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
        "safety": dict(_WINDOWS_EVIDENCE_SAFETY),
        "not_collected_in_pr264": not_collected,
        "next_safe_command": next_safe_command,
    }


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
    lines.append("Not collected yet: " + ", ".join(pending) + ".")
    lines.append(
        f"Next safe command: {payload.get('next_safe_command', UNSUPPORTED_NEXT_SAFE_COMMAND)}"
    )
    return os.linesep.join(lines)
