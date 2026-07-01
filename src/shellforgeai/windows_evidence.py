"""Consolidated local read-only Windows evidence bundle preview.

The PR264 bundle reuses the existing Windows doctor and status payload builders.
It does not add probes, execute commands, use remoting, open network
connections, read credential caches, write files, or mutate host state.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from shellforgeai.platform_detection import PlatformInfo, detect_platform
from shellforgeai.windows_doctor import windows_doctor_payload
from shellforgeai.windows_status import windows_status_payload

WINDOWS_EVIDENCE_NEXT_SAFE_COMMAND = "shellforgeai windows status --json"
UNSUPPORTED_NEXT_SAFE_COMMAND = "shellforgeai platform doctor --json"

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
) -> dict[str, Any]:
    """Build the PR264 Windows evidence bundle payload."""

    info = info or detect_platform()
    if info.system != "windows":
        return windows_evidence_unsupported_payload(info)

    components = {
        "doctor": doctor_builder(info),
        "status": status_builder(info),
    }
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
        "not_collected_in_pr264": dict(_NOT_COLLECTED_PR264),
        "next_safe_command": WINDOWS_EVIDENCE_NEXT_SAFE_COMMAND,
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
    if payload.get("status") == "unsupported":
        lines.append(str(payload.get("reason", "Windows evidence bundle is unavailable.")))
    lines.append(
        "Not collected yet: PowerShell version, execution policy, services, "
        "processes, event logs, firewall, Windows Update."
    )
    lines.append(
        f"Next safe command: {payload.get('next_safe_command', UNSUPPORTED_NEXT_SAFE_COMMAND)}"
    )
    return os.linesep.join(lines)
