"""Local read-only Windows doctor prototype.

The PR261 doctor is intentionally stdlib-only and does not execute commands,
open network connections, read credential caches, or mutate host state.
"""

from __future__ import annotations

import os
import platform
import socket
import sys
from typing import Any

from shellforgeai.platform_detection import PlatformInfo, detect_platform

NEXT_SAFE_COMMAND = "shellforgeai platform doctor --json"

_WINDOWS_NOT_COLLECTED_PR261 = {
    "powershell_version": "not collected because PR261 does not execute PowerShell",
    "execution_policy": "not collected because PR261 does not execute PowerShell",
    "services": "planned for later read-only Windows evidence PR",
    "processes": "planned for later read-only Windows evidence PR",
    "event_logs": "planned for later read-only Windows evidence PR",
    "firewall": "planned for later read-only Windows evidence PR",
    "windows_update": "planned for later read-only Windows evidence PR",
}

_WINDOWS_SAFETY = {
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


def _platform_block(info: PlatformInfo) -> dict[str, str]:
    payload = info.to_dict()
    payload["version"] = platform.version()
    return payload


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


def windows_doctor_payload(info: PlatformInfo | None = None) -> dict[str, Any]:
    """Build the PR261 Windows doctor JSON-compatible payload."""

    info = info or detect_platform()
    if info.system != "windows":
        return windows_doctor_unsupported_payload(info)

    hostname = _safe_hostname()
    fqdn = _safe_fqdn(hostname)
    return {
        "schema_version": 1,
        "mode": "windows_doctor",
        "status": "ok",
        "platform": _platform_block(info),
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_doctor",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "host": {
            "hostname": hostname,
            "fqdn": fqdn,
            "user_context_collected": False,
            "secret_or_auth_cache_read": False,
        },
        "python_runtime": {
            "executable": sys.executable,
            "version": sys.version.split()[0],
            "implementation": platform.python_implementation(),
        },
        "filesystem": {"roots_checked": [], "collection": "stdlib_only"},
        "network": {"hostname": hostname, "fqdn": fqdn, "collection": "stdlib_only"},
        "not_collected_in_pr261": dict(_WINDOWS_NOT_COLLECTED_PR261),
        "safety": dict(_WINDOWS_SAFETY),
        "next_safe_command": NEXT_SAFE_COMMAND,
    }


def windows_doctor_unsupported_payload(info: PlatformInfo | None = None) -> dict[str, Any]:
    """Build deterministic unsupported output for non-Windows hosts."""

    info = info or detect_platform()
    return {
        "schema_version": 1,
        "mode": "windows_doctor",
        "status": "unsupported",
        "platform": {"system": info.system},
        "reason": "Windows doctor is only available on Windows hosts.",
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": False,
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "safety": {key: _WINDOWS_SAFETY[key] for key in _UNSUPPORTED_SAFETY_KEYS},
        "next_safe_command": NEXT_SAFE_COMMAND,
    }


def render_windows_doctor_text(payload: dict[str, Any]) -> str:
    """Render concise operator-facing text for the Windows doctor payload."""

    platform_system = payload.get("platform", {}).get("system", "unknown")
    windows_v1 = payload.get("windows_v1", {})
    available = str(windows_v1.get("available", False)).lower()
    lines = [
        "ShellForgeAI Windows doctor",
        f"Status: {payload.get('status', 'unknown')}",
        f"Platform: {platform_system}",
        f"Windows V1 available: {available}",
        f"Read-only: {str(payload.get('read_only', False)).lower()}",
        f"Mutation performed: {str(payload.get('mutation_performed', True)).lower()}",
    ]
    if payload.get("status") == "unsupported":
        lines.append(str(payload.get("reason", "Windows doctor is not available on this host.")))
    else:
        lines.append("Local read-only host basics collected; no shell or remoting used.")
    lines.append(f"Next safe command: {payload.get('next_safe_command', NEXT_SAFE_COMMAND)}")
    return os.linesep.join(lines)
