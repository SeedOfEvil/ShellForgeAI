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
from shellforgeai.windows_events import (
    DEFAULT_EVENTS_LIMIT,
    DEFAULT_SINCE_HOURS,
    validate_events_limit,
    validate_since_hours,
    windows_events_payload,
)
from shellforgeai.windows_network import (
    _SAFETY as WINDOWS_NETWORK_SAFETY,
)
from shellforgeai.windows_network import (
    LIMITATION as WINDOWS_NETWORK_LIMITATION,
)
from shellforgeai.windows_network import (
    MAX_ADDRESSES_PER_INTERFACE,
    MAX_INTERFACES,
    windows_network_payload,
)
from shellforgeai.windows_network import (
    METHOD as WINDOWS_NETWORK_METHOD,
)
from shellforgeai.windows_network import (
    MODE as WINDOWS_NETWORK_MODE,
)
from shellforgeai.windows_processes import MAX_PROCESSES_LIMIT, windows_processes_payload
from shellforgeai.windows_services import DEFAULT_MAX_SERVICES, windows_services_payload
from shellforgeai.windows_status import windows_status_payload
from shellforgeai.windows_volumes import (
    _SAFETY as WINDOWS_VOLUMES_SAFETY,
)
from shellforgeai.windows_volumes import (
    DEFAULT_VOLUMES_LIMIT,
    MAX_VOLUMES_LIMIT,
    windows_volumes_payload,
)
from shellforgeai.windows_volumes import (
    LIMITATIONS as WINDOWS_VOLUMES_LIMITATIONS,
)
from shellforgeai.windows_volumes import (
    METHOD as WINDOWS_VOLUMES_METHOD,
)
from shellforgeai.windows_volumes import (
    MODE as WINDOWS_VOLUMES_MODE,
)

WINDOWS_EVIDENCE_NEXT_SAFE_COMMAND = "shellforgeai windows status --json"
WINDOWS_EVIDENCE_DISKS_NEXT_SAFE_COMMAND = "shellforgeai windows disks --json"
WINDOWS_EVIDENCE_PROCESSES_NEXT_SAFE_COMMAND = "shellforgeai windows processes --json --limit 10"
WINDOWS_EVIDENCE_EVENTS_NEXT_SAFE_COMMAND = (
    "shellforgeai windows events --json --limit {limit} --since-hours {since_hours}"
)
WINDOWS_EVIDENCE_NETWORK_NEXT_SAFE_COMMAND = "shellforgeai windows network --json"
WINDOWS_EVIDENCE_VOLUMES_NEXT_SAFE_COMMAND = "shellforgeai windows volumes --json"
UNSUPPORTED_NEXT_SAFE_COMMAND = "shellforgeai platform doctor --json"

EVIDENCE_SERVICES_DEFAULT_LIMIT = 25
EVIDENCE_SERVICES_MAX_LIMIT = DEFAULT_MAX_SERVICES
EVIDENCE_DISKS_DEFAULT_LIMIT = DEFAULT_DISKS_LIMIT
EVIDENCE_DISKS_MAX_LIMIT = MAX_DISKS_LIMIT
EVIDENCE_PROCESSES_DEFAULT_LIMIT = 25
EVIDENCE_PROCESSES_MAX_LIMIT = MAX_PROCESSES_LIMIT
EVIDENCE_NETWORK_DEFAULT_INTERFACE_LIMIT = MAX_INTERFACES
EVIDENCE_NETWORK_DEFAULT_ADDRESS_LIMIT = MAX_ADDRESSES_PER_INTERFACE
EVIDENCE_VOLUMES_DEFAULT_LIMIT = DEFAULT_VOLUMES_LIMIT
EVIDENCE_VOLUMES_MAX_LIMIT = MAX_VOLUMES_LIMIT

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
EventsBuilder = Callable[[PlatformInfo, int, int], dict[str, Any]]
NetworkBuilder = Callable[[PlatformInfo, int, int], dict[str, Any]]
VolumesBuilder = Callable[[PlatformInfo, int], dict[str, Any]]


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


def validate_evidence_network_interface_limit(value: Any) -> int:
    """Validate the opt-in bundled Windows network interface limit."""

    message = f"network interface limit must be a positive integer between 1 and {MAX_INTERFACES}"
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(message)
    if value < 1 or value > MAX_INTERFACES:
        raise ValueError(message)
    return value


def validate_evidence_network_address_limit(value: Any) -> int:
    """Validate the opt-in bundled Windows network per-interface address limit."""

    message = (
        "network address limit must be a positive integer between "
        f"1 and {MAX_ADDRESSES_PER_INTERFACE}"
    )
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(message)
    if value < 1 or value > MAX_ADDRESSES_PER_INTERFACE:
        raise ValueError(message)
    return value


def validate_evidence_volumes_limit(value: Any) -> int:
    """Validate the opt-in bundled Windows volumes limit."""

    message = f"volumes limit must be a positive integer between 1 and {EVIDENCE_VOLUMES_MAX_LIMIT}"
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(message)
    if value < 1 or value > EVIDENCE_VOLUMES_MAX_LIMIT:
        raise ValueError(message)
    return value


def _default_services_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_services_payload(info, max_services=limit)


def _default_disks_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_disks_payload(info, limit=limit)


def _default_processes_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_processes_payload(info, limit=limit)


def _default_events_builder(info: PlatformInfo, limit: int, since_hours: int) -> dict[str, Any]:
    return windows_events_payload(info, limit=limit, since_hours=since_hours)


def _default_network_builder(
    info: PlatformInfo, interface_limit: int, address_limit: int
) -> dict[str, Any]:
    return windows_network_payload(
        info,
        max_interfaces=interface_limit,
        max_addresses_per_interface=address_limit,
    )


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


def validate_evidence_events_limit(value: Any) -> int:
    """Validate the opt-in bundled Windows System events limit."""

    return validate_events_limit(value)


def validate_evidence_events_since_hours(value: Any) -> int:
    """Validate the opt-in bundled Windows System events lookback."""

    return validate_since_hours(value)


def _embedded_events_summary(component: dict[str, Any]) -> dict[str, Any]:
    summary = component.get("summary") if isinstance(component.get("summary"), dict) else {}
    collection = (
        component.get("collection") if isinstance(component.get("collection"), dict) else {}
    )
    return {
        "included": True,
        "status": component.get("status", "unknown"),
        "limit": int(summary.get("limit", collection.get("limit", 0)) or 0),
        "since_hours": int(summary.get("since_hours", collection.get("since_hours", 0)) or 0),
        "returned_count": int(summary.get("events_returned", 0) or 0),
        "truncated": bool(summary.get("truncated", collection.get("truncated", False))),
        "critical": int(summary.get("critical", 0) or 0),
        "error": int(summary.get("error", 0) or 0),
        "warning": int(summary.get("warning", 0) or 0),
        "unknown": int(summary.get("unknown", 0) or 0),
    }


def _events_component_error(info: PlatformInfo, limit: int, since_hours: int) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "windows_events",
        "status": "error",
        "platform": {"system": info.system},
        "read_only": True,
        "mutation_performed": False,
        "collection": {
            "method": "wevtapi_system_metadata",
            "channel": "System",
            "levels": ["critical", "error", "warning"],
            "since_hours": since_hours,
            "limit": limit,
            "truncated": False,
            "rendered_messages_collected": False,
            "event_xml_collected": False,
            "event_data_collected": False,
            "user_data_collected": False,
            "remote_session_used": False,
        },
        "summary": {
            "events_returned": 0,
            "critical": 0,
            "error": 0,
            "warning": 0,
            "unknown": 0,
            "truncated": False,
            "since_hours": since_hours,
            "limit": limit,
        },
        "events": [],
        "top_provider_event_pairs": [],
        "warnings": [],
        "errors": [
            {
                "type": "events_component_failed",
                "message": "Windows Event Log metadata component failed.",
            }
        ],
        "limitations": [
            "Only local System-channel Critical, Error, and Warning metadata was requested."
        ],
        "safety": {
            "read_only": True,
            "mutation_performed": False,
            "powershell_executed": False,
            "winrm_used": False,
            "remote_execution": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "event_log_write_performed": False,
            "event_log_clear_performed": False,
            "event_log_export_performed": False,
            "event_subscription_created": False,
            "registry_modified": False,
            "service_control_executed": False,
            "process_termination_executed": False,
            "cleanup_executed": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "recovery_executed": False,
            "secret_read": False,
            "auth_cache_read": False,
            "model_called": False,
            "network_call": False,
        },
    }


def _network_zero_summary() -> dict[str, Any]:
    return {
        "interfaces_total": 0,
        "interfaces_returned": 0,
        "interfaces_up": 0,
        "interfaces_down": 0,
        "ipv4_addresses": 0,
        "ipv6_addresses": 0,
        "interfaces_with_errors": 0,
        "truncated": False,
    }


def _network_component_error(
    info: PlatformInfo, interface_limit: int, address_limit: int
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": WINDOWS_NETWORK_MODE,
        "status": "error",
        "platform": {"system": info.system},
        "read_only": True,
        "mutation_performed": False,
        "method": WINDOWS_NETWORK_METHOD,
        "caps": {
            "max_interfaces": interface_limit,
            "max_addresses_per_interface": address_limit,
        },
        "summary": _network_zero_summary(),
        "interfaces": [],
        "limitations": [WINDOWS_NETWORK_LIMITATION],
        "warnings": [],
        "errors": [
            {
                "type": "network_component_failed",
                "message": "Windows network interface metadata component failed.",
            }
        ],
        "safety": dict(WINDOWS_NETWORK_SAFETY),
    }


def _is_healthy_network_component(component: Any) -> bool:
    if not isinstance(component, dict):
        return False
    if component.get("status") != "ok":
        return False
    if component.get("mode") != WINDOWS_NETWORK_MODE:
        return False
    if component.get("method") != WINDOWS_NETWORK_METHOD:
        return False
    if not isinstance(component.get("caps"), dict):
        return False
    if not isinstance(component.get("summary"), dict):
        return False
    return isinstance(component.get("interfaces"), list)


def _volumes_zero_summary() -> dict[str, int]:
    return {
        "partitions_observed": 0,
        "local_drive_roots": 0,
        "returned_volumes": 0,
        "available_volumes": 0,
        "unavailable_volumes": 0,
        "fixed_volumes": 0,
        "removable_volumes": 0,
        "cdrom_volumes": 0,
        "read_only_volumes": 0,
        "skipped_remote": 0,
        "skipped_non_drive_root": 0,
        "skipped_unsafe_identifier": 0,
    }


def _volumes_component_error(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": WINDOWS_VOLUMES_MODE,
        "status": "error",
        "platform": {"system": info.system},
        "read_only": True,
        "mutation_performed": False,
        "collection": {
            "method": WINDOWS_VOLUMES_METHOD,
            "limit": limit,
            "truncated": False,
            "directory_scan_performed": False,
            "file_scan_performed": False,
            "remote_volume_probe_performed": False,
        },
        "summary": _volumes_zero_summary(),
        "volumes": [],
        "limitations": list(WINDOWS_VOLUMES_LIMITATIONS),
        "warnings": [],
        "errors": [
            {
                "type": "volumes_component_failed",
                "message": "Windows volume/filesystem metadata component failed.",
            }
        ],
        "safety": dict(WINDOWS_VOLUMES_SAFETY),
    }


def _is_healthy_volumes_component(component: Any, info: PlatformInfo, limit: int) -> bool:
    if not isinstance(component, dict):
        return False
    if component.get("status") != "ok" or component.get("mode") != WINDOWS_VOLUMES_MODE:
        return False
    if component.get("platform", {}).get("system") != info.system:
        return False
    if component.get("read_only") is not True or component.get("mutation_performed") is not False:
        return False
    collection = component.get("collection")
    summary = component.get("summary")
    if not isinstance(collection, dict) or not isinstance(summary, dict):
        return False
    if collection.get("method") != WINDOWS_VOLUMES_METHOD or collection.get("limit") != limit:
        return False
    if not isinstance(collection.get("truncated"), bool):
        return False
    required_counts = _volumes_zero_summary().keys()
    if any(
        isinstance(summary.get(key), bool) or not isinstance(summary.get(key), int)
        for key in required_counts
    ):
        return False
    return isinstance(component.get("volumes"), list) and isinstance(component.get("safety"), dict)


def _embedded_volumes_summary(component: dict[str, Any]) -> dict[str, Any]:
    collection = (
        component.get("collection") if isinstance(component.get("collection"), dict) else {}
    )
    summary = component.get("summary") if isinstance(component.get("summary"), dict) else {}
    return {
        "included": True,
        "status": component.get("status", "unknown"),
        "limit": int(collection.get("limit", 0) or 0),
        "partitions_observed": int(summary.get("partitions_observed", 0) or 0),
        "local_drive_roots": int(summary.get("local_drive_roots", 0) or 0),
        "returned_volumes": int(summary.get("returned_volumes", 0) or 0),
        "available_volumes": int(summary.get("available_volumes", 0) or 0),
        "unavailable_volumes": int(summary.get("unavailable_volumes", 0) or 0),
        "fixed_volumes": int(summary.get("fixed_volumes", 0) or 0),
        "removable_volumes": int(summary.get("removable_volumes", 0) or 0),
        "cdrom_volumes": int(summary.get("cdrom_volumes", 0) or 0),
        "read_only_volumes": int(summary.get("read_only_volumes", 0) or 0),
        "skipped_remote": int(summary.get("skipped_remote", 0) or 0),
        "skipped_non_drive_root": int(summary.get("skipped_non_drive_root", 0) or 0),
        "skipped_unsafe_identifier": int(summary.get("skipped_unsafe_identifier", 0) or 0),
        "truncated": bool(collection.get("truncated", False)),
    }


def _default_volumes_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_volumes_payload(info, limit=limit)


def _embedded_network_summary(component: dict[str, Any]) -> dict[str, Any]:
    caps = component.get("caps") if isinstance(component.get("caps"), dict) else {}
    summary = component.get("summary") if isinstance(component.get("summary"), dict) else {}
    return {
        "included": True,
        "status": component.get("status", "unknown"),
        "max_interfaces": int(caps.get("max_interfaces", 0) or 0),
        "max_addresses_per_interface": int(caps.get("max_addresses_per_interface", 0) or 0),
        "interfaces_total": int(summary.get("interfaces_total", 0) or 0),
        "interfaces_returned": int(summary.get("interfaces_returned", 0) or 0),
        "interfaces_up": int(summary.get("interfaces_up", 0) or 0),
        "interfaces_down": int(summary.get("interfaces_down", 0) or 0),
        "ipv4_addresses": int(summary.get("ipv4_addresses", 0) or 0),
        "ipv6_addresses": int(summary.get("ipv6_addresses", 0) or 0),
        "interfaces_with_errors": int(summary.get("interfaces_with_errors", 0) or 0),
        "truncated": bool(summary.get("truncated", False)),
    }


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
    include_events: bool = False,
    events_limit: int | None = None,
    events_since_hours: int | None = None,
    events_builder: EventsBuilder = _default_events_builder,
    include_network: bool = False,
    network_interface_limit: int | None = None,
    network_address_limit: int | None = None,
    network_builder: NetworkBuilder = _default_network_builder,
    include_volumes: bool = False,
    volumes_limit: int | None = None,
    volumes_builder: VolumesBuilder = _default_volumes_builder,
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

    if not include_events and events_limit is not None:
        raise ValueError("events limit requires include_events=True")
    if not include_events and events_since_hours is not None:
        raise ValueError("events since-hours requires include_events=True")
    if not include_network and network_interface_limit is not None:
        raise ValueError("network interface limit requires include_network=True")
    if not include_network and network_address_limit is not None:
        raise ValueError("network address limit requires include_network=True")
    if not include_volumes and volumes_limit is not None:
        raise ValueError("volumes limit requires include_volumes=True")

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
    embedded_events: dict[str, Any] | None = None
    if include_events:
        bounded_events_limit = validate_evidence_events_limit(
            DEFAULT_EVENTS_LIMIT if events_limit is None else events_limit
        )
        bounded_events_since_hours = validate_evidence_events_since_hours(
            DEFAULT_SINCE_HOURS if events_since_hours is None else events_since_hours
        )
        try:
            events_component = events_builder(
                info, bounded_events_limit, bounded_events_since_hours
            )
        except Exception:
            events_component = _events_component_error(
                info, bounded_events_limit, bounded_events_since_hours
            )
        components["events"] = events_component
        embedded_events = _embedded_events_summary(events_component)
        not_collected["event_logs"] = (
            "included as explicit opt-in bounded local System Event metadata via --include-events"
        )
        next_safe_command = WINDOWS_EVIDENCE_EVENTS_NEXT_SAFE_COMMAND.format(
            limit=bounded_events_limit, since_hours=bounded_events_since_hours
        )
    embedded_network: dict[str, Any] | None = None
    if include_network:
        bounded_network_interface_limit = validate_evidence_network_interface_limit(
            EVIDENCE_NETWORK_DEFAULT_INTERFACE_LIMIT
            if network_interface_limit is None
            else network_interface_limit
        )
        bounded_network_address_limit = validate_evidence_network_address_limit(
            EVIDENCE_NETWORK_DEFAULT_ADDRESS_LIMIT
            if network_address_limit is None
            else network_address_limit
        )
        try:
            network_component = network_builder(
                info, bounded_network_interface_limit, bounded_network_address_limit
            )
        except Exception:
            network_component = _network_component_error(
                info, bounded_network_interface_limit, bounded_network_address_limit
            )
        if not _is_healthy_network_component(network_component):
            network_component = _network_component_error(
                info, bounded_network_interface_limit, bounded_network_address_limit
            )
        components["network"] = network_component
        embedded_network = _embedded_network_summary(network_component)
        next_safe_command = WINDOWS_EVIDENCE_NETWORK_NEXT_SAFE_COMMAND
    embedded_volumes: dict[str, Any] | None = None
    if include_volumes:
        bounded_volumes_limit = validate_evidence_volumes_limit(
            EVIDENCE_VOLUMES_DEFAULT_LIMIT if volumes_limit is None else volumes_limit
        )
        try:
            volumes_component = volumes_builder(info, bounded_volumes_limit)
        except Exception:
            volumes_component = _volumes_component_error(info, bounded_volumes_limit)
        if not _is_healthy_volumes_component(volumes_component, info, bounded_volumes_limit):
            volumes_component = _volumes_component_error(info, bounded_volumes_limit)
        components["volumes"] = volumes_component
        embedded_volumes = _embedded_volumes_summary(volumes_component)
        next_safe_command = WINDOWS_EVIDENCE_VOLUMES_NEXT_SAFE_COMMAND
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
    if embedded_events is not None:
        payload["embedded_events"] = embedded_events
    if embedded_network is not None:
        payload["embedded_network"] = embedded_network
    if embedded_volumes is not None:
        payload["embedded_volumes"] = embedded_volumes
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
    events_summary = payload.get("embedded_events")
    if isinstance(events_summary, dict):
        lines.append(
            "Events component: "
            f"status={events_summary.get('status', 'unknown')}; "
            f"returned={events_summary.get('returned_count', 0)}; "
            f"limit={events_summary.get('limit', 0)}; "
            f"since_hours={events_summary.get('since_hours', 0)}; "
            f"truncated={str(events_summary.get('truncated', False)).lower()}; "
            f"critical={events_summary.get('critical', 0)}; "
            f"error={events_summary.get('error', 0)}; "
            f"warning={events_summary.get('warning', 0)}; "
            f"unknown={events_summary.get('unknown', 0)}"
        )
    network_summary = payload.get("embedded_network")
    if isinstance(network_summary, dict):
        lines.append(
            "Network component: "
            f"status={network_summary.get('status', 'unknown')}; "
            f"returned={network_summary.get('interfaces_returned', 0)}/"
            f"{network_summary.get('interfaces_total', 0)}; "
            f"up={network_summary.get('interfaces_up', 0)}; "
            f"down={network_summary.get('interfaces_down', 0)}; "
            f"ipv4={network_summary.get('ipv4_addresses', 0)}; "
            f"ipv6={network_summary.get('ipv6_addresses', 0)}; "
            f"errors={network_summary.get('interfaces_with_errors', 0)}; "
            f"interface_limit={network_summary.get('max_interfaces', 0)}; "
            f"address_limit={network_summary.get('max_addresses_per_interface', 0)}; "
            f"truncated={str(network_summary.get('truncated', False)).lower()}"
        )
    volumes_summary = payload.get("embedded_volumes")
    if isinstance(volumes_summary, dict):
        lines.append(
            "Volumes component: "
            f"status={volumes_summary.get('status', 'unknown')}; "
            f"returned={volumes_summary.get('returned_volumes', 0)}/"
            f"{volumes_summary.get('local_drive_roots', 0)}; "
            f"available={volumes_summary.get('available_volumes', 0)}; "
            f"unavailable={volumes_summary.get('unavailable_volumes', 0)}; "
            f"fixed={volumes_summary.get('fixed_volumes', 0)}; "
            f"removable={volumes_summary.get('removable_volumes', 0)}; "
            f"cdrom={volumes_summary.get('cdrom_volumes', 0)}; "
            f"read_only={volumes_summary.get('read_only_volumes', 0)}; "
            f"limit={volumes_summary.get('limit', 0)}; "
            f"truncated={str(volumes_summary.get('truncated', False)).lower()}"
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
    if isinstance(events_summary, dict):
        pending.remove("event logs")
    lines.append("Not collected yet: " + ", ".join(pending) + ".")
    lines.append(
        f"Next safe command: {payload.get('next_safe_command', UNSUPPORTED_NEXT_SAFE_COMMAND)}"
    )
    return os.linesep.join(lines)
