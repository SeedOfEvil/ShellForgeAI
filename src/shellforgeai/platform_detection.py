"""Read-only platform detection and unsupported-platform payloads.

This module is intentionally narrow for Windows/PowerShell V1 foundation work:
it uses only Python standard library platform metadata and never shells out,
probes Docker, reads secrets, calls a model, or touches the network.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import dataclass
from typing import Any, Literal

PlatformSystem = Literal["linux", "windows", "darwin", "unknown"]
SupportLane = Literal["linux_docker_v1", "windows_read_only_doctor_v1", "unsupported"]


@dataclass(frozen=True)
class PlatformInfo:
    system: PlatformSystem
    python_platform: str
    os_name: str
    release: str
    machine: str

    def to_dict(self) -> dict[str, str]:
        return {
            "system": self.system,
            "python_platform": self.python_platform,
            "os_name": self.os_name,
            "release": self.release,
            "machine": self.machine,
        }


def _classify_system(raw_system: str) -> PlatformSystem:
    normalized = (raw_system or "").strip().lower()
    if normalized == "linux":
        return "linux"
    if normalized == "windows":
        return "windows"
    if normalized == "darwin":
        return "darwin"
    return "unknown"


def detect_platform() -> PlatformInfo:
    """Return read-only platform metadata using Python standard library only."""

    return PlatformInfo(
        system=_classify_system(platform.system()),
        python_platform=platform.platform(aliased=False, terse=True),
        os_name=os.name,
        release=platform.release(),
        machine=platform.machine(),
    )


def support_status(info: PlatformInfo | None = None) -> dict[str, Any]:
    """Return ShellForgeAI support status for the detected/classified platform."""

    info = info or detect_platform()
    if info.system == "linux":
        return {
            "supported": True,
            "lane": "linux_docker_v1",
            "windows_v1_available": False,
            "linux_docker_available": True,
        }
    if info.system == "windows":
        return {
            "supported": False,
            "lane": "windows_read_only_doctor_v1",
            "windows_v1_available": True,
            "windows_read_only_doctor_available": True,
            "linux_docker_available": False,
        }
    return {
        "supported": False,
        "lane": "unsupported",
        "windows_v1_available": False,
        "windows_read_only_doctor_available": False,
        "linux_docker_available": False,
    }


def _limited_evidence(reason: str) -> dict[str, Any]:
    return {"status": "limited", "value": None, "reason": reason}


def _safe_text_evidence(label: str, collector) -> dict[str, Any]:
    try:
        value = collector()
    except Exception as exc:  # defensive evidence capture; never crash doctor output
        return _limited_evidence(f"{label}_unavailable: {type(exc).__name__}")
    if value in (None, ""):
        return _limited_evidence(f"{label}_unavailable")
    return {"status": "ok", "value": str(value), "reason": None}


def windows_doctor_evidence(info: PlatformInfo | None = None) -> dict[str, Any]:
    """Return narrow local Windows evidence without shelling out or mutating state."""

    info = info or detect_platform()
    try:
        version, build, _platform_type, service_pack = platform.win32_ver()
    except Exception:
        version, build, service_pack = "", "", ""
    shell_availability = {
        "powershell": {
            "available": shutil.which("powershell") is not None,
            "discovery": "shutil.which",
            "version": _limited_evidence("not_collected_without_shelling_out"),
        },
        "pwsh": {
            "available": shutil.which("pwsh") is not None,
            "discovery": "shutil.which",
            "version": _limited_evidence("not_collected_without_shelling_out"),
        },
    }
    return {
        "schema_version": 1,
        "mode": "windows_read_only_doctor_evidence",
        "status": "ok" if info.system == "windows" else "unsupported",
        "platform_name": "Windows" if info.system == "windows" else info.system,
        "os_family": "windows" if info.system == "windows" else info.system,
        "windows_version": _safe_text_evidence("windows_version", lambda: version),
        "windows_build": _safe_text_evidence("windows_build", lambda: build),
        "windows_service_pack": _safe_text_evidence("windows_service_pack", lambda: service_pack),
        "architecture": _safe_text_evidence("architecture", lambda: info.machine),
        "python_version": _safe_text_evidence("python_version", lambda: sys.version.split()[0]),
        "python_platform": _safe_text_evidence("python_platform", lambda: info.python_platform),
        "shell_availability": shell_availability,
        "unsupported_or_limited": [
            "PowerShell versions are not collected because that would require executing a shell.",
            "Registry, services, firewall, network, event logs, credentials, and broad "
            "inventory are out of scope.",
        ],
        "read_only": True,
        "mutation_performed": False,
    }


def platform_doctor_payload(info: PlatformInfo | None = None) -> dict[str, Any]:
    """Build deterministic JSON-compatible platform doctor output."""

    info = info or detect_platform()
    support = support_status(info)
    if info.system == "linux":
        status = "ok"
        message = "Linux detected. ShellForgeAI Linux/Docker V1 operational lane is available."
        next_safe_command = "shellforgeai doctor"
    elif info.system == "windows":
        status = "limited"
        message = "Windows detected. Limited Windows read-only doctor evidence is available."
        next_safe_command = "shellforgeai platform doctor --json"
    elif info.system == "darwin":
        status = "unsupported"
        message = "Darwin detected. Current ShellForgeAI operational lanes are Linux/Docker only."
        next_safe_command = "shellforgeai platform doctor --json"
    else:
        status = "unknown"
        message = (
            "Unknown platform detected. Current ShellForgeAI operational lanes are "
            "Linux/Docker only."
        )
        next_safe_command = "shellforgeai platform doctor --json"

    payload = {
        "schema_version": 1,
        "mode": "platform_doctor",
        "status": status,
        "platform": info.to_dict(),
        "support": support,
        "read_only": True,
        "mutation_performed": False,
        "message": message,
        "next_safe_command": next_safe_command,
    }
    if info.system == "windows":
        payload["windows_evidence"] = windows_doctor_evidence(info)
    return payload


def unsupported_platform_payload(
    *,
    platform_system: PlatformSystem | str,
    requested_lane: str,
    reason: str,
    supported_lanes: list[str] | None = None,
    next_safe_command: str = "shellforgeai platform doctor --json",
) -> dict[str, Any]:
    """Build a deterministic reusable unsupported-platform response."""

    return {
        "schema_version": 1,
        "mode": "unsupported_platform",
        "status": "unsupported",
        "platform": platform_system,
        "requested_lane": requested_lane,
        "supported_lanes": list(supported_lanes or ["platform_doctor"]),
        "read_only": True,
        "mutation_performed": False,
        "reason": reason,
        "next_safe_command": next_safe_command,
    }
