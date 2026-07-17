#!/usr/bin/env python3
"""Validate saved Windows smoke JSON artifacts.

This helper is local-only: it reads JSON files captured from ShellForgeAI
Windows smoke commands and reports whether the saved artifacts satisfy the
Windows acceptance safety contract. It intentionally does not invoke
ShellForgeAI, shells, remoting tools, or network APIs.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SAFETY_FALSE_KEYS = (
    "powershell_executed",
    "winrm_used",
    "remote_execution",
    "service_restart_executed",
    "process_termination_executed",
    "registry_modified",
    "execution_policy_modified",
    "software_install_executed",
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
    "natural_language_execution",
    "shell_true",
    "arbitrary_command_execution",
    "secret_read",
    "auth_cache_read",
    "model_called",
    "network_call",
)
SERVICES_SAFETY_FALSE_KEYS = (
    "powershell_executed",
    "winrm_used",
    "remote_execution",
    "service_restart_executed",
    "service_control_executed",
    "service_config_modified",
    "process_termination_executed",
    "registry_modified",
    "execution_policy_modified",
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
    "natural_language_execution",
    "shell_true",
    "arbitrary_command_execution",
    "secret_read",
    "auth_cache_read",
    "model_called",
    "network_call",
)
SERVICES_STATE_COUNT_KEYS = ("running", "stopped", "unknown")
DISKS_SAFETY_FALSE_KEYS = (
    "powershell_executed",
    "winrm_used",
    "remote_execution",
    "directory_scan_performed",
    "file_scan_performed",
    "disk_mutation_performed",
    "service_restart_executed",
    "process_termination_executed",
    "registry_modified",
    "execution_policy_modified",
    "software_install_executed",
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
    "natural_language_execution",
    "shell_true",
    "arbitrary_command_execution",
    "secret_read",
    "auth_cache_read",
    "model_called",
    "network_call",
)
DISKS_OPTIONAL_SAFETY_FALSE_KEYS = (
    "disk_mutation_executed",
    "mount_modified",
    "format_executed",
)
DISKS_SUMMARY_COUNT_KEYS = (
    "total_roots",
    "returned_roots",
    "available_roots",
    "unavailable_roots",
)
DISKS_MIN_LIMIT = 1
DISKS_MAX_LIMIT = 64
_SANITIZED_DISK_ERROR_RE = re.compile(r"[a-z0-9_]{1,64}")
_UNAVAILABLE_DISK_ITEM_KEYS = frozenset({"root", "status", "error"})
PROCESSES_SAFETY_FALSE_KEYS = (
    "powershell_executed",
    "winrm_used",
    "remote_execution",
    "process_termination_executed",
    "process_control_executed",
    "process_config_modified",
    "process_memory_read",
    "process_command_line_read",
    "process_environment_read",
    "process_handles_read",
    "process_modules_read",
    "process_owner_read",
    "service_restart_executed",
    "registry_modified",
    "execution_policy_modified",
    "software_install_executed",
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
    "natural_language_execution",
    "shell_true",
    "arbitrary_command_execution",
    "secret_read",
    "auth_cache_read",
    "model_called",
    "network_call",
)
NETWORK_SAFETY_FALSE_KEYS = (
    "powershell_executed",
    "winrm_used",
    "remote_execution",
    "packet_capture",
    "sock" + "et_inventory",
    "dns_lookup",
    "route_table_lookup",
    "network_mutation",
    "shell_true",
    "arbitrary_command_execution",
    "secret_read",
    "auth_cache_read",
    "model_called",
    "network_call",
)

MEMORY_SAFETY_FALSE_KEYS = (
    "powershell_executed",
    "winrm_used",
    "remote_execution",
    "process_memory_read",
    "process_termination_executed",
    "service_restart_executed",
    "registry_modified",
    "execution_policy_modified",
    "software_install_executed",
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
    "natural_language_execution",
    "shell_true",
    "arbitrary_command_execution",
    "secret_read",
    "auth_cache_read",
    "model_called",
    "network_call",
)
PROCESSES_MIN_LIMIT = 1
PROCESSES_MAX_LIMIT = 200
PROCESSES_METHOD = "ctypes_toolhelp32_snapshot"
_ALLOWED_PROCESS_ITEM_KEYS = frozenset({"pid", "parent_pid", "name", "thread_count"})
PROCESSES_NOT_COLLECTED_PR274_KEYS = (
    "command_line",
    "environment",
    "memory",
    "handles",
    "modules",
    "owner_user",
    "network_connections",
)
WINDOWS_V1_FALSE_KEYS = ("powershell_executed", "winrm_used", "remote_execution")
EVENTS_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$")

NOT_COLLECTED_PR264_KEYS = (
    "powershell_version",
    "execution_policy",
    "services",
    "processes",
    "event_logs",
)


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": self.name, "passed": self.passed}
        if self.reason:
            payload["reason"] = self.reason
        return payload


def _check(name: str, passed: bool, reason: str | None = None) -> Check:
    return Check(name=name, passed=passed, reason=None if passed else reason or "check failed")


def _decode_json_bytes(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig")


def _read_json_file(path: Path, label: str) -> tuple[Any | None, list[Check]]:
    if not path.exists():
        return None, [_check(f"{label}.file_exists", False, f"file not found: {path}")]
    if not path.is_file():
        return None, [_check(f"{label}.is_file", False, f"not a file: {path}")]
    try:
        text = _decode_json_bytes(path.read_bytes())
    except UnicodeError as exc:
        return None, [_check(f"{label}.encoding_decode", False, f"invalid text encoding: {exc}")]
    except OSError as exc:
        return None, [_check(f"{label}.json_read", False, str(exc))]
    try:
        return json.loads(text), [_check(f"{label}.json_parse", True)]
    except json.JSONDecodeError as exc:
        return None, [_check(f"{label}.json_parse", False, f"invalid JSON: {exc.msg}")]


def _nested(payload: dict[str, Any], *keys: str) -> Any:
    current: Any = payload
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _python_matches(version: str | None, expected: str) -> bool:
    return isinstance(version, str) and (version == expected or version.startswith(expected))


def _validate_common(
    payload: Any,
    *,
    label: str,
    expected_mode: str,
    expected_host: str | None,
    expected_python: str | None,
    require_details: bool = True,
    expected_statuses: frozenset[str] = frozenset({"ok"}),
) -> list[Check]:
    checks: list[Check] = []
    checks.append(
        _check(f"{label}.object", isinstance(payload, dict), "top-level JSON must be an object")
    )
    if not isinstance(payload, dict):
        return checks

    checks.extend(
        [
            _check(
                f"{label}.mode",
                payload.get("mode") == expected_mode,
                f"expected mode {expected_mode!r}",
            ),
            _check(
                f"{label}.status",
                payload.get("status") in expected_statuses,
                f"expected status in {sorted(expected_statuses)!r}",
            ),
            _check(
                f"{label}.platform.system",
                _nested(payload, "platform", "system") == "windows",
                "expected platform.system 'windows'",
            ),
            _check(
                f"{label}.read_only", payload.get("read_only") is True, "expected read_only true"
            ),
            _check(
                f"{label}.mutation_performed",
                payload.get("mutation_performed") is False,
                "expected mutation_performed false",
            ),
            _check(
                f"{label}.windows_v1.available",
                _nested(payload, "windows_v1", "available") is True,
                "expected windows_v1.available true",
            ),
        ]
    )
    scopes = {
        "windows_status": "local_read_only_status",
        "windows_doctor": "local_read_only_doctor",
        "windows_evidence_bundle": "local_read_only_evidence_bundle",
    }
    checks.append(
        _check(
            f"{label}.windows_v1.scope",
            _nested(payload, "windows_v1", "scope") == scopes[expected_mode],
            f"expected {scopes[expected_mode]} scope",
        )
    )

    for key in WINDOWS_V1_FALSE_KEYS:
        checks.append(
            _check(
                f"{label}.windows_v1.{key}",
                _nested(payload, "windows_v1", key) is False,
                f"expected {key} false",
            )
        )
    for key in SAFETY_FALSE_KEYS:
        checks.append(
            _check(
                f"{label}.safety.{key}",
                _nested(payload, "safety", key) is False,
                f"expected {key} false",
            )
        )

    host = payload.get("host")
    if require_details:
        checks.append(
            _check(
                f"{label}.host.present",
                isinstance(host, dict) and bool(host),
                "expected host basics",
            )
        )
    if expected_host is not None and isinstance(host, dict) and host:
        checks.append(
            _check(
                f"{label}.host.expected",
                host.get("hostname") == expected_host,
                f"expected host hostname {expected_host!r}",
            )
        )

    runtime = payload.get("python_runtime")
    if require_details:
        checks.append(
            _check(
                f"{label}.python_runtime.present",
                isinstance(runtime, dict)
                and bool(runtime.get("version"))
                and bool(runtime.get("executable")),
                "expected Python runtime basics",
            )
        )
    if expected_python is not None and isinstance(runtime, dict) and runtime.get("version"):
        checks.append(
            _check(
                f"{label}.python_runtime.expected",
                _python_matches(runtime.get("version"), expected_python),
                f"expected Python version prefix or exact {expected_python!r}",
            )
        )

    filesystem = payload.get("filesystem")
    if require_details:
        checks.append(
            _check(
                f"{label}.filesystem.present",
                isinstance(filesystem, dict) and bool(filesystem),
                "expected filesystem basics",
            )
        )
    return checks


def _validate_evidence(
    payload: Any, expected_host: str | None, expected_python: str | None
) -> list[Check]:
    checks = _validate_common(
        payload,
        label="evidence",
        expected_mode="windows_evidence_bundle",
        expected_host=expected_host,
        expected_python=expected_python,
        require_details=False,
        expected_statuses=frozenset({"ok", "component_failure"}),
    )
    if not isinstance(payload, dict):
        return checks
    checks.insert(
        1,
        _check(
            "evidence.schema_version",
            payload.get("schema_version") == 1,
            "expected schema_version 1",
        ),
    )

    components = payload.get("components")
    doctor = _nested(payload, "components", "doctor")
    status = _nested(payload, "components", "status")
    checks.extend(
        [
            _check(
                "evidence.components.object",
                isinstance(components, dict),
                "expected components object",
            ),
            _check(
                "evidence.components.doctor.exists",
                isinstance(doctor, dict),
                "expected doctor component",
            ),
            _check(
                "evidence.components.status.exists",
                isinstance(status, dict),
                "expected status component",
            ),
        ]
    )
    if isinstance(doctor, dict):
        checks.extend(
            _validate_common(
                doctor,
                label="evidence.components.doctor",
                expected_mode="windows_doctor",
                expected_host=expected_host,
                expected_python=expected_python,
            )
        )
    if isinstance(status, dict):
        checks.extend(
            _validate_common(
                status,
                label="evidence.components.status",
                expected_mode="windows_status",
                expected_host=expected_host,
                expected_python=expected_python,
            )
        )

    services = _nested(payload, "components", "services")
    has_services = isinstance(components, dict) and "services" in components
    if has_services:
        checks.extend(
            _validate_services(
                services,
                expected_host,
                expected_python,
                label="evidence.components.services",
                embedded=True,
            )
        )

    disks = _nested(payload, "components", "disks")
    has_disks = isinstance(components, dict) and "disks" in components
    if has_disks:
        checks.extend(
            _validate_disks(
                disks,
                expected_host,
                expected_python,
                label="evidence.components.disks",
                embedded=True,
            )
        )
        checks.extend(_validate_embedded_disks_block(payload, disks))

    processes = _nested(payload, "components", "processes")
    has_processes = isinstance(components, dict) and "processes" in components
    if has_processes:
        checks.extend(
            _validate_processes(
                processes,
                expected_host,
                expected_python,
                label="evidence.components.processes",
            )
        )
        checks.extend(_validate_embedded_processes_block(payload, processes))

    network = _nested(payload, "components", "network")
    has_network = isinstance(components, dict) and "network" in components
    if has_network and isinstance(network, dict):
        checks.extend(_validate_network(network, label="evidence.components.network"))
        checks.extend(_validate_embedded_network_block(payload, network))
        if network.get("status") == "error":
            checks.extend(
                [
                    _check(
                        "evidence.network_failure.summary_zero",
                        network.get("summary")
                        == {
                            "interfaces_total": 0,
                            "interfaces_returned": 0,
                            "interfaces_up": 0,
                            "interfaces_down": 0,
                            "ipv4_addresses": 0,
                            "ipv6_addresses": 0,
                            "interfaces_with_errors": 0,
                            "truncated": False,
                        },
                    ),
                    _check(
                        "evidence.network_failure.interfaces_empty", network.get("interfaces") == []
                    ),
                    _check(
                        "evidence.network_failure.error_envelope",
                        network.get("errors")
                        == [
                            {
                                "type": "network_component_failed",
                                "message": "Windows network interface metadata component failed.",
                            }
                        ],
                    ),
                ]
            )
    else:
        checks.append(
            _check(
                "evidence.default_no_network_component",
                isinstance(components, dict) and "network" not in components,
            )
        )
        checks.append(
            _check("evidence.default_no_embedded_network", "embedded_network" not in payload)
        )

    events = _nested(payload, "components", "events")
    has_events = isinstance(components, dict) and "events" in components
    if has_events and isinstance(events, dict):
        checks.extend(_validate_events_artifact(events))
        embedded_events = payload.get("embedded_events")
        summary = events.get("summary", {}) if isinstance(events.get("summary"), dict) else {}
        collection = (
            events.get("collection", {}) if isinstance(events.get("collection"), dict) else {}
        )
        checks.append(
            _check(
                "evidence.components.events.platform",
                events.get("platform", {}).get("system") == "windows",
            )
        )
        checks.extend(
            [
                _check("evidence.embedded_events.object", isinstance(embedded_events, dict)),
                _check(
                    "evidence.embedded_events.included",
                    isinstance(embedded_events, dict) and embedded_events.get("included") is True,
                ),
                _check(
                    "evidence.embedded_events.status",
                    isinstance(embedded_events, dict)
                    and embedded_events.get("status") == events.get("status"),
                ),
                _check(
                    "evidence.embedded_events.limit",
                    isinstance(embedded_events, dict)
                    and embedded_events.get("limit")
                    == summary.get("limit", collection.get("limit")),
                ),
                _check(
                    "evidence.embedded_events.since_hours",
                    isinstance(embedded_events, dict)
                    and embedded_events.get("since_hours")
                    == summary.get("since_hours", collection.get("since_hours")),
                ),
                _check(
                    "evidence.embedded_events.returned_count",
                    isinstance(embedded_events, dict)
                    and embedded_events.get("returned_count") == summary.get("events_returned"),
                ),
                _check(
                    "evidence.embedded_events.truncated",
                    isinstance(embedded_events, dict)
                    and embedded_events.get("truncated")
                    == summary.get("truncated", collection.get("truncated")),
                ),
                _check(
                    "evidence.embedded_events.critical",
                    isinstance(embedded_events, dict)
                    and embedded_events.get("critical") == summary.get("critical"),
                ),
                _check(
                    "evidence.embedded_events.error",
                    isinstance(embedded_events, dict)
                    and embedded_events.get("error") == summary.get("error"),
                ),
                _check(
                    "evidence.embedded_events.warning",
                    isinstance(embedded_events, dict)
                    and embedded_events.get("warning") == summary.get("warning"),
                ),
                _check(
                    "evidence.embedded_events.unknown",
                    isinstance(embedded_events, dict)
                    and embedded_events.get("unknown") == summary.get("unknown"),
                ),
            ]
        )
        if events.get("status") == "error":
            checks.extend(
                [
                    _check(
                        "evidence.events_failure.bounds.limit",
                        isinstance(collection.get("limit"), int),
                    ),
                    _check(
                        "evidence.events_failure.bounds.since_hours",
                        isinstance(collection.get("since_hours"), int),
                    ),
                    _check(
                        "evidence.events_failure.summary_zero", summary.get("events_returned") == 0
                    ),
                    _check("evidence.events_failure.critical_zero", summary.get("critical") == 0),
                    _check("evidence.events_failure.error_zero", summary.get("error") == 0),
                    _check("evidence.events_failure.warning_zero", summary.get("warning") == 0),
                    _check("evidence.events_failure.unknown_zero", summary.get("unknown") == 0),
                    _check("evidence.events_failure.events_empty", events.get("events") == []),
                    _check(
                        "evidence.events_failure.sanitized",
                        _event_error_values_are_sanitized(events.get("errors")),
                    ),
                ]
            )
    else:
        checks.append(
            _check(
                "evidence.default_no_events_component",
                isinstance(components, dict) and "events" not in components,
            )
        )
        checks.append(
            _check("evidence.default_no_embedded_events", "embedded_events" not in payload)
        )

    expected_component_count = (
        2
        + int(has_services)
        + int(has_disks)
        + int(has_processes)
        + int(has_events)
        + int(has_network)
    )
    expected_ok = {"doctor", "status"}
    if has_services:
        expected_ok.add("services")
    if has_disks:
        expected_ok.add("disks")
    if has_processes:
        expected_ok.add("processes")
    if has_events and isinstance(events, dict) and events.get("status") == "ok":
        expected_ok.add("events")
    if has_network and isinstance(network, dict) and network.get("status") == "ok":
        expected_ok.add("network")
    ok_components = _nested(payload, "summary", "ok_components")
    failed_components = _nested(payload, "summary", "failed_components")
    checks.extend(
        [
            _check(
                "evidence.summary.component_count",
                _nested(payload, "summary", "component_count") == expected_component_count,
                f"expected component_count {expected_component_count}",
            ),
            _check(
                "evidence.summary.failed_components",
                failed_components
                == [
                    name
                    for name in ("services", "disks", "processes", "events", "network")
                    if isinstance(components, dict)
                    and isinstance(components.get(name), dict)
                    and components[name].get("status") != "ok"
                ],
                "expected failed components to match unhealthy optional components",
            ),
            _check(
                "evidence.summary.ok_components",
                isinstance(ok_components, list) and expected_ok.issubset(set(ok_components)),
                f"expected {', '.join(sorted(expected_ok))} ok components",
            ),
        ]
    )
    expected_evidence_status = (
        "component_failure" if isinstance(failed_components, list) and failed_components else "ok"
    )
    checks.append(
        _check(
            "evidence.status_matches_component_health",
            payload.get("status") == expected_evidence_status,
            f"expected evidence status {expected_evidence_status!r}",
        )
    )
    not_collected = payload.get("not_collected_in_pr264")
    for key in NOT_COLLECTED_PR264_KEYS:
        checks.append(
            _check(
                f"evidence.not_collected_in_pr264.{key}",
                isinstance(not_collected, dict) and key in not_collected,
                f"expected not_collected_in_pr264.{key}",
            )
        )
    return checks


def _non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _validate_embedded_network_block(
    payload: dict[str, Any], network: dict[str, Any]
) -> list[Check]:
    embedded = payload.get("embedded_network")
    summary = network.get("summary") if isinstance(network.get("summary"), dict) else {}
    caps = network.get("caps") if isinstance(network.get("caps"), dict) else {}
    checks = [
        _check("evidence.embedded_network.object", isinstance(embedded, dict)),
        _check(
            "evidence.embedded_network.included",
            isinstance(embedded, dict) and embedded.get("included") is True,
        ),
        _check(
            "evidence.embedded_network.status",
            isinstance(embedded, dict) and embedded.get("status") == network.get("status"),
        ),
    ]
    for embedded_key, source in (
        ("max_interfaces", caps.get("max_interfaces")),
        ("max_addresses_per_interface", caps.get("max_addresses_per_interface")),
        ("interfaces_total", summary.get("interfaces_total")),
        ("interfaces_returned", summary.get("interfaces_returned")),
        ("interfaces_up", summary.get("interfaces_up")),
        ("interfaces_down", summary.get("interfaces_down")),
        ("ipv4_addresses", summary.get("ipv4_addresses")),
        ("ipv6_addresses", summary.get("ipv6_addresses")),
        ("interfaces_with_errors", summary.get("interfaces_with_errors")),
        ("truncated", summary.get("truncated")),
    ):
        checks.append(
            _check(
                f"evidence.embedded_network.{embedded_key}",
                isinstance(embedded, dict) and embedded.get(embedded_key) == source,
            )
        )
    return checks


def _validate_services(
    payload: Any,
    expected_host: str | None,
    expected_python: str | None,
    *,
    label: str = "services",
    embedded: bool = False,
) -> list[Check]:
    checks = [
        _check(f"{label}.object", isinstance(payload, dict), "top-level JSON must be an object")
    ]
    if not isinstance(payload, dict):
        return checks

    checks.extend(
        [
            _check(
                f"{label}.schema_version",
                payload.get("schema_version") == 1,
                "expected schema_version 1",
            ),
            _check(
                f"{label}.mode",
                payload.get("mode") == "windows_services",
                "expected mode 'windows_services'",
            ),
            _check(f"{label}.status", payload.get("status") == "ok", "expected status 'ok'"),
            _check(
                f"{label}.platform.system",
                _nested(payload, "platform", "system") == "windows",
                "expected platform.system 'windows'",
            ),
            _check(
                f"{label}.read_only", payload.get("read_only") is True, "expected read_only true"
            ),
            _check(
                f"{label}.mutation_performed",
                payload.get("mutation_performed") is False,
                "expected mutation_performed false",
            ),
            _check(
                f"{label}.windows_v1.available",
                _nested(payload, "windows_v1", "available") is True,
                "expected windows_v1.available true",
            ),
            _check(
                f"{label}.windows_v1.scope",
                _nested(payload, "windows_v1", "scope") == "local_read_only_services",
                "expected local_read_only_services scope",
            ),
        ]
    )
    for key in WINDOWS_V1_FALSE_KEYS:
        checks.append(
            _check(
                f"{label}.windows_v1.{key}",
                _nested(payload, "windows_v1", key) is False,
                f"expected {key} false",
            )
        )
    for key in SERVICES_SAFETY_FALSE_KEYS:
        checks.append(
            _check(
                f"{label}.safety.{key}",
                _nested(payload, "safety", key) is False,
                f"expected {key} false",
            )
        )

    if embedded:
        checks.extend(_validate_embedded_services_bounds(payload, label))

    summary = payload.get("services")
    checks.append(
        _check(
            f"{label}.services.object",
            isinstance(summary, dict) and bool(summary),
            "expected services summary object",
        )
    )
    if isinstance(summary, dict):
        total = summary.get("total_count")
        checks.append(
            _check(
                f"{label}.services.total_count",
                _non_negative_int(total),
                "expected non-negative integer total_count",
            )
        )
        for key in SERVICES_STATE_COUNT_KEYS:
            checks.append(
                _check(
                    f"{label}.services.state_counts.{key}",
                    _non_negative_int(_nested(summary, "state_counts", key)),
                    f"expected non-negative integer state_counts.{key}",
                )
            )

        runtime_summary = summary.get("runtime_summary")
        if isinstance(runtime_summary, dict):
            for key in (
                "running_with_process_id",
                "running_without_process_id",
                "pending_services",
                "services_with_nonzero_win32_exit_code",
                "services_with_nonzero_service_specific_exit_code",
                "services_with_checkpoint",
                "services_with_wait_hint",
                "services_accepting_stop",
                "services_accepting_pause_continue",
                "services_running_in_system_process",
                "runtime_signal_services",
            ):
                checks.append(
                    _check(
                        f"{label}.services.runtime_summary.{key}",
                        _non_negative_int(runtime_summary.get(key)),
                        f"expected non-negative integer runtime_summary.{key}",
                    )
                )
        items = summary.get("items")
        checks.append(
            _check(f"{label}.services.items", isinstance(items, list), "expected services list")
        )
        if isinstance(items, list):
            allowed_controls = {
                "stop",
                "pause_continue",
                "shutdown",
                "param_change",
                "netbind_change",
                "hardware_profile_change",
                "power_event",
                "session_change",
                "preshutdown",
                "time_change",
                "trigger_event",
                "user_logoff",
            }
            allowed_signals = {
                "pending",
                "process_attached",
                "nonzero_win32_exit_code",
                "nonzero_service_specific_exit_code",
                "checkpoint_present",
                "wait_hint_present",
                "runs_in_system_process",
            }
            forbidden_item_keys = {
                "binary_path",
                "command_line",
                "account",
                "description",
                "dependencies",
                "recovery_options",
                "registry",
                "owner",
                "environment",
                "modules",
                "handles",
            }
            for index, item in enumerate(items):
                checks.append(
                    _check(
                        f"{label}.services.items.{index}.runtime_fields",
                        isinstance(item, dict)
                        and {"name", "display_name", "state"}.issubset(item)
                        and (
                            "process_id" not in item
                            or {
                                "process_id",
                                "controls_accepted",
                                "controls_accepted_unknown_mask",
                                "win32_exit_code",
                                "service_specific_exit_code",
                                "checkpoint",
                                "wait_hint_ms",
                                "runs_in_system_process",
                                "runtime_signals",
                            }.issubset(item)
                        ),
                        "expected service identity and PR297 runtime fields when present",
                    )
                )
                if not isinstance(item, dict):
                    continue
                if "process_id" not in item:
                    continue
                pid = item.get("process_id")
                controls = item.get("controls_accepted")
                signals = item.get("runtime_signals")
                checks.extend(
                    [
                        _check(
                            f"{label}.services.items.{index}.process_id",
                            pid is None or (_non_negative_int(pid) and pid > 0),
                            "expected null or positive integer process_id",
                        ),
                        _check(
                            f"{label}.services.items.{index}.controls_accepted",
                            isinstance(controls, list)
                            and len(controls) == len(set(controls))
                            and set(controls).issubset(allowed_controls),
                            "expected bounded normalized controls list",
                        ),
                        _check(
                            f"{label}.services.items.{index}.controls_unknown",
                            _non_negative_int(item.get("controls_accepted_unknown_mask")),
                            "expected non-negative controls_accepted_unknown_mask",
                        ),
                        _check(
                            f"{label}.services.items.{index}.numeric_runtime",
                            all(
                                _non_negative_int(item.get(key))
                                for key in (
                                    "win32_exit_code",
                                    "service_specific_exit_code",
                                    "checkpoint",
                                    "wait_hint_ms",
                                )
                            ),
                            "expected non-negative integer runtime fields",
                        ),
                        _check(
                            f"{label}.services.items.{index}.runtime_signals",
                            isinstance(signals, list)
                            and len(signals) == len(set(signals))
                            and set(signals).issubset(allowed_signals),
                            "expected bounded runtime_signals list",
                        ),
                        _check(
                            f"{label}.services.items.{index}.no_config_or_process_details",
                            forbidden_item_keys.isdisjoint(item),
                            "expected no service config or process detail fields",
                        ),
                    ]
                )
        limits = summary.get("collection_limits")
        truncated = _nested(summary, "collection_limits", "truncated")
        checks.append(
            _check(
                f"{label}.services.collection_limits",
                isinstance(limits, dict) and isinstance(truncated, bool),
                "expected collection_limits with boolean truncated",
            )
        )
        if truncated is True:
            max_services = _nested(summary, "collection_limits", "max_services")
            consistent = (
                _non_negative_int(max_services)
                and max_services >= 1
                and _non_negative_int(total)
                and total > max_services
                and isinstance(items, list)
                and len(items) <= max_services
            )
            checks.append(
                _check(
                    f"{label}.services.truncation_consistent",
                    consistent,
                    "expected truncated=true limit metadata consistent with "
                    "max_services, total_count, and items",
                )
            )

    host = payload.get("host")
    if expected_host is not None and isinstance(host, dict) and host.get("hostname") is not None:
        checks.append(
            _check(
                f"{label}.host.expected",
                host.get("hostname") == expected_host,
                f"expected host hostname {expected_host!r}",
            )
        )
    runtime = payload.get("python_runtime")
    if expected_python is not None and isinstance(runtime, dict) and runtime.get("version"):
        checks.append(
            _check(
                f"{label}.python_runtime.expected",
                _python_matches(runtime.get("version"), expected_python),
                f"expected Python version prefix or exact {expected_python!r}",
            )
        )
    return checks


def _validate_embedded_services_bounds(payload: dict[str, Any], label: str) -> list[Check]:
    """Check the PR269 embedded services component bounded-output fields."""

    limit = payload.get("limit")
    returned = payload.get("returned_count")
    total = payload.get("total_count")
    truncated = payload.get("truncated")
    checks = [
        _check(
            f"{label}.limit",
            _non_negative_int(limit) and limit >= 1,
            "expected positive integer limit",
        ),
        _check(
            f"{label}.returned_count",
            _non_negative_int(returned),
            "expected non-negative integer returned_count",
        ),
        _check(
            f"{label}.total_count",
            _non_negative_int(total),
            "expected non-negative integer total_count",
        ),
        _check(
            f"{label}.truncated",
            isinstance(truncated, bool),
            "expected boolean truncated",
        ),
    ]
    if (
        _non_negative_int(limit)
        and limit >= 1
        and _non_negative_int(returned)
        and _non_negative_int(total)
        and isinstance(truncated, bool)
    ):
        consistent = returned <= limit and total >= returned and truncated == (total > returned)
        checks.append(
            _check(
                f"{label}.bounded_consistent",
                consistent,
                "expected returned_count <= limit, total_count >= returned_count, "
                "and truncated consistent with total/returned counts",
            )
        )
    return checks


def _validate_embedded_disks_bounds(payload: dict[str, Any], label: str) -> list[Check]:
    """Check the PR272 embedded disks component bounded-output fields."""

    limit = payload.get("limit")
    returned = payload.get("returned_roots")
    total = payload.get("total_roots")
    truncated = payload.get("truncated")
    checks = [
        _check(
            f"{label}.limit",
            _non_negative_int(limit) and DISKS_MIN_LIMIT <= limit <= DISKS_MAX_LIMIT,
            f"expected integer limit between {DISKS_MIN_LIMIT} and {DISKS_MAX_LIMIT}",
        ),
        _check(
            f"{label}.returned_roots",
            _non_negative_int(returned),
            "expected non-negative integer returned_roots",
        ),
        _check(
            f"{label}.total_roots",
            _non_negative_int(total),
            "expected non-negative integer total_roots",
        ),
        _check(
            f"{label}.truncated",
            isinstance(truncated, bool),
            "expected boolean truncated",
        ),
    ]
    if (
        _non_negative_int(limit)
        and DISKS_MIN_LIMIT <= limit <= DISKS_MAX_LIMIT
        and _non_negative_int(returned)
        and _non_negative_int(total)
        and isinstance(truncated, bool)
    ):
        consistent = returned <= limit and total >= returned and truncated == (total > returned)
        checks.append(
            _check(
                f"{label}.bounded_consistent",
                consistent,
                "expected returned_roots <= limit, total_roots >= returned_roots, "
                "and truncated consistent with total/returned root counts",
            )
        )
    return checks


def _validate_embedded_disks_block(payload: dict[str, Any], component: Any) -> list[Check]:
    """Check the optional top-level PR272 embedded_disks summary block."""

    block = payload.get("embedded_disks")
    if block is None:
        return []
    checks = [
        _check(
            "evidence.embedded_disks.object",
            isinstance(block, dict),
            "expected embedded_disks object",
        )
    ]
    if not isinstance(block, dict):
        return checks
    checks.append(
        _check(
            "evidence.embedded_disks.included",
            block.get("included") is True,
            "expected embedded_disks.included true",
        )
    )
    if isinstance(component, dict):
        consistent = all(
            block.get(key) == component.get(key)
            for key in ("limit", "returned_roots", "total_roots", "truncated")
        )
        checks.append(
            _check(
                "evidence.embedded_disks.consistent",
                consistent,
                "expected embedded_disks limit/returned_roots/total_roots/truncated "
                "to match the embedded disks component",
            )
        )
    return checks


def _validate_embedded_processes_block(payload: dict[str, Any], component: Any) -> list[Check]:
    """Check the optional top-level PR276 embedded_processes summary block."""

    block = payload.get("embedded_processes")
    if block is None:
        return []
    checks = [
        _check(
            "evidence.embedded_processes.object",
            isinstance(block, dict),
            "expected embedded_processes object",
        )
    ]
    if not isinstance(block, dict):
        return checks
    checks.append(
        _check(
            "evidence.embedded_processes.included",
            block.get("included") is True,
            "expected embedded_processes.included true",
        )
    )
    if isinstance(component, dict):
        consistent = all(
            block.get(key) == component.get(key)
            for key in ("limit", "returned_count", "total_count", "truncated")
        )
        checks.append(
            _check(
                "evidence.embedded_processes.consistent",
                consistent,
                "expected embedded_processes limit/returned_count/total_count/truncated "
                "to match the embedded processes component",
            )
        )
    return checks


def _disk_item_checks(item: Any, label: str) -> list[Check]:
    if not isinstance(item, dict):
        return [_check(f"{label}.object", False, "expected disk item object")]
    checks = [
        _check(
            f"{label}.root",
            isinstance(item.get("root"), str) and bool(item.get("root")),
            "expected non-empty root string",
        ),
        _check(
            f"{label}.status",
            item.get("status") in ("ok", "unavailable"),
            "expected status 'ok' or 'unavailable'",
        ),
    ]
    if item.get("status") == "ok":
        for key in ("total_bytes", "used_bytes", "free_bytes"):
            checks.append(
                _check(
                    f"{label}.{key}",
                    _non_negative_int(item.get(key)),
                    f"expected non-negative integer {key}",
                )
            )
    elif item.get("status") == "unavailable":
        extra_keys = set(item) - _UNAVAILABLE_DISK_ITEM_KEYS
        error = item.get("error")
        checks.extend(
            [
                _check(
                    f"{label}.sanitized_fields",
                    not extra_keys,
                    "unavailable root must carry only root/status/error, no raw "
                    f"exception detail fields: {', '.join(sorted(extra_keys))}",
                ),
                _check(
                    f"{label}.sanitized_error",
                    isinstance(error, str)
                    and _SANITIZED_DISK_ERROR_RE.fullmatch(error) is not None,
                    "expected sanitized failure token such as 'disk_usage_failed', "
                    "never tracebacks",
                ),
            ]
        )
    return checks


def _validate_disks(
    payload: Any,
    expected_host: str | None,
    expected_python: str | None,
    *,
    label: str = "disks",
    embedded: bool = False,
) -> list[Check]:
    checks = [
        _check(f"{label}.object", isinstance(payload, dict), "top-level JSON must be an object")
    ]
    if not isinstance(payload, dict):
        return checks

    checks.extend(
        [
            _check(
                f"{label}.schema_version",
                payload.get("schema_version") == 1,
                "expected schema_version 1",
            ),
            _check(
                f"{label}.mode",
                payload.get("mode") == "windows_disks",
                "expected mode 'windows_disks'",
            ),
            _check(f"{label}.status", payload.get("status") == "ok", "expected status 'ok'"),
            _check(
                f"{label}.platform.system",
                _nested(payload, "platform", "system") == "windows",
                "expected platform.system 'windows'",
            ),
            _check(
                f"{label}.read_only", payload.get("read_only") is True, "expected read_only true"
            ),
            _check(
                f"{label}.mutation_performed",
                payload.get("mutation_performed") is False,
                "expected mutation_performed false",
            ),
            _check(
                f"{label}.windows_v1.available",
                _nested(payload, "windows_v1", "available") is True,
                "expected windows_v1.available true",
            ),
            _check(
                f"{label}.windows_v1.scope",
                _nested(payload, "windows_v1", "scope") == "local_read_only_disks",
                "expected local_read_only_disks scope",
            ),
        ]
    )
    for key in WINDOWS_V1_FALSE_KEYS:
        checks.append(
            _check(
                f"{label}.windows_v1.{key}",
                _nested(payload, "windows_v1", key) is False,
                f"expected {key} false",
            )
        )
    safety = payload.get("safety")
    for key in DISKS_SAFETY_FALSE_KEYS:
        checks.append(
            _check(
                f"{label}.safety.{key}",
                _nested(payload, "safety", key) is False,
                f"expected {key} false",
            )
        )
    for key in DISKS_OPTIONAL_SAFETY_FALSE_KEYS:
        if isinstance(safety, dict) and key in safety:
            checks.append(
                _check(
                    f"{label}.safety.{key}",
                    safety.get(key) is False,
                    f"expected {key} false",
                )
            )

    if embedded:
        checks.extend(_validate_embedded_disks_bounds(payload, label))

    collection = payload.get("collection")
    limit = _nested(payload, "collection", "limit")
    truncated = _nested(payload, "collection", "truncated")
    checks.extend(
        [
            _check(
                f"{label}.collection.object",
                isinstance(collection, dict) and bool(collection),
                "expected collection object",
            ),
            _check(
                f"{label}.collection.method",
                _nested(payload, "collection", "method") == "stdlib_only",
                "expected collection method 'stdlib_only'",
            ),
            _check(
                f"{label}.collection.directory_scan_performed",
                _nested(payload, "collection", "directory_scan_performed") is False,
                "expected directory_scan_performed false",
            ),
            _check(
                f"{label}.collection.file_scan_performed",
                _nested(payload, "collection", "file_scan_performed") is False,
                "expected file_scan_performed false",
            ),
            _check(
                f"{label}.collection.limit",
                _non_negative_int(limit) and DISKS_MIN_LIMIT <= limit <= DISKS_MAX_LIMIT,
                f"expected integer limit between {DISKS_MIN_LIMIT} and {DISKS_MAX_LIMIT}",
            ),
            _check(
                f"{label}.collection.truncated",
                isinstance(truncated, bool),
                "expected boolean truncated",
            ),
        ]
    )

    summary = payload.get("summary")
    checks.append(
        _check(
            f"{label}.summary.object",
            isinstance(summary, dict) and bool(summary),
            "expected root/disk summary object",
        )
    )
    total = _nested(payload, "summary", "total_roots")
    returned = _nested(payload, "summary", "returned_roots")
    available = _nested(payload, "summary", "available_roots")
    unavailable = _nested(payload, "summary", "unavailable_roots")
    for key in DISKS_SUMMARY_COUNT_KEYS:
        checks.append(
            _check(
                f"{label}.summary.{key}",
                _non_negative_int(_nested(payload, "summary", key)),
                f"expected non-negative integer {key}",
            )
        )
    if _non_negative_int(total) and _non_negative_int(returned):
        checks.append(
            _check(
                f"{label}.summary.returned_le_total",
                returned <= total,
                "expected returned_roots <= total_roots",
            )
        )
        if isinstance(truncated, bool):
            checks.append(
                _check(
                    f"{label}.summary.truncation_consistent",
                    truncated == (total > returned),
                    "expected truncated consistent with total_roots and returned_roots",
                )
            )
    if (
        _non_negative_int(returned)
        and _non_negative_int(available)
        and _non_negative_int(unavailable)
    ):
        checks.append(
            _check(
                f"{label}.summary.availability_consistent",
                available + unavailable == returned,
                "expected available_roots + unavailable_roots == returned_roots",
            )
        )

    disks = payload.get("disks")
    checks.append(_check(f"{label}.disks.list", isinstance(disks, list), "expected disks list"))
    if isinstance(disks, list):
        for index, item in enumerate(disks):
            checks.extend(_disk_item_checks(item, f"{label}.disks[{index}]"))
        ok_items = sum(1 for item in disks if isinstance(item, dict) and item.get("status") == "ok")
        if _non_negative_int(returned):
            checks.append(
                _check(
                    f"{label}.disks.returned_count_consistent",
                    len(disks) == returned,
                    "expected disks list length to match returned_roots",
                )
            )
        if _non_negative_int(available):
            checks.append(
                _check(
                    f"{label}.disks.available_count_consistent",
                    ok_items == available,
                    "expected ok disk items to match available_roots",
                )
            )
        if _non_negative_int(limit) and DISKS_MIN_LIMIT <= limit <= DISKS_MAX_LIMIT:
            checks.append(
                _check(
                    f"{label}.disks.bounded_by_limit",
                    len(disks) <= limit,
                    "expected disks list length <= limit",
                )
            )

    host = payload.get("host")
    if expected_host is not None and isinstance(host, dict) and host.get("hostname") is not None:
        checks.append(
            _check(
                f"{label}.host.expected",
                host.get("hostname") == expected_host,
                f"expected host hostname {expected_host!r}",
            )
        )
    runtime = payload.get("python_runtime")
    if expected_python is not None and isinstance(runtime, dict) and runtime.get("version"):
        checks.append(
            _check(
                f"{label}.python_runtime.expected",
                _python_matches(runtime.get("version"), expected_python),
                f"expected Python version prefix or exact {expected_python!r}",
            )
        )
    return checks


def _process_item_checks(item: Any, label: str) -> list[Check]:
    if not isinstance(item, dict):
        return [_check(f"{label}.object", False, "expected process item object")]
    extra_keys = set(item) - _ALLOWED_PROCESS_ITEM_KEYS
    checks = [
        _check(
            f"{label}.allowed_fields_only",
            not extra_keys,
            "process item must carry only pid/parent_pid/name/thread_count, never "
            "command lines, environments, memory, handles, modules, owners/users, "
            "network connections, or executable paths: "
            f"{', '.join(sorted(extra_keys))}",
        )
    ]
    for key in ("pid", "parent_pid", "thread_count"):
        checks.append(
            _check(
                f"{label}.{key}",
                _non_negative_int(item.get(key)),
                f"expected non-negative integer {key}",
            )
        )
    checks.append(
        _check(
            f"{label}.name",
            isinstance(item.get("name"), str),
            "expected string process image basename",
        )
    )
    return checks


def _validate_network(payload: Any, *, label: str = "network") -> list[Check]:
    checks = [
        _check(f"{label}.object", isinstance(payload, dict), "top-level JSON must be an object")
    ]
    if not isinstance(payload, dict):
        return checks
    checks.extend(
        [
            _check(f"{label}.schema_version", payload.get("schema_version") == 1),
            _check(f"{label}.mode", payload.get("mode") == "windows_network"),
            _check(f"{label}.status", payload.get("status") in {"ok", "error"}),
            _check(f"{label}.platform.system", _nested(payload, "platform", "system") == "windows"),
            _check(f"{label}.read_only", payload.get("read_only") is True),
            _check(f"{label}.mutation_performed", payload.get("mutation_performed") is False),
        ]
    )
    for key in NETWORK_SAFETY_FALSE_KEYS:
        checks.append(_check(f"{label}.safety.{key}", _nested(payload, "safety", key) is False))
    summary = payload.get("summary")
    interfaces = payload.get("interfaces")
    checks.append(_check(f"{label}.summary.object", isinstance(summary, dict)))
    checks.append(_check(f"{label}.interfaces.list", isinstance(interfaces, list)))
    if isinstance(summary, dict):
        for key in (
            "interfaces_total",
            "interfaces_returned",
            "interfaces_up",
            "interfaces_down",
            "ipv4_addresses",
            "ipv6_addresses",
            "interfaces_with_errors",
        ):
            checks.append(_check(f"{label}.summary.{key}", _non_negative_int(summary.get(key))))
        returned = summary.get("interfaces_returned")
        total = summary.get("interfaces_total")
        cap = _nested(payload, "caps", "max_interfaces")
        address_cap = _nested(payload, "caps", "max_addresses_per_interface")
        checks.append(
            _check(f"{label}.caps.max_interfaces", isinstance(cap, int) and 1 <= cap <= 32)
        )
        checks.append(
            _check(
                f"{label}.caps.max_addresses_per_interface",
                isinstance(address_cap, int) and 1 <= address_cap <= 16,
            )
        )
        if _non_negative_int(returned) and _non_negative_int(total):
            checks.append(_check(f"{label}.summary.returned_lte_total", returned <= total))
        if _non_negative_int(returned) and _non_negative_int(cap):
            checks.append(_check(f"{label}.summary.returned_lte_cap", returned <= cap))
    if isinstance(interfaces, list):
        for index, iface in enumerate(interfaces):
            prefix = f"{label}.interfaces[{index}]"
            checks.append(
                _check(
                    f"{prefix}.name",
                    isinstance(iface, dict)
                    and isinstance(iface.get("name"), str)
                    and bool(iface.get("name")),
                )
            )
            if isinstance(iface, dict):
                checks.append(
                    _check(f"{prefix}.no_mac_field", "mac" not in iface and "guid" not in iface)
                )
                addresses = iface.get("addresses")
                checks.append(_check(f"{prefix}.addresses.list", isinstance(addresses, list)))
                if isinstance(addresses, list) and _non_negative_int(
                    _nested(payload, "caps", "max_addresses_per_interface")
                ):
                    checks.append(
                        _check(
                            f"{prefix}.addresses.bounded",
                            len(addresses)
                            <= _nested(payload, "caps", "max_addresses_per_interface"),
                        )
                    )
                if isinstance(addresses, list):
                    for a_index, address in enumerate(addresses):
                        family = address.get("family") if isinstance(address, dict) else None
                        checks.append(
                            _check(
                                f"{prefix}.addresses[{a_index}].family", family in {"ipv4", "ipv6"}
                            )
                        )
    serialized = json.dumps(payload, sort_keys=True).lower()
    checks.extend(
        [
            _check(f"{label}.privacy.no_mac_field", "mac_address" not in serialized),
            _check(
                f"{label}.privacy.no_guid_field",
                "adapter_guid" not in serialized and "pnp" not in serialized,
            ),
        ]
    )
    return checks


def _validate_volumes(payload: Any, *, label: str = "volumes") -> list[Check]:
    checks: list[Check] = []
    if not isinstance(payload, dict):
        return [_check(f"{label}.object", False, "expected JSON object")]
    checks.extend(
        [
            _check(f"{label}.mode", payload.get("mode") == "windows_volumes"),
            _check(f"{label}.platform", _nested(payload, "platform", "system") == "windows"),
            _check(f"{label}.read_only", payload.get("read_only") is True),
            _check(f"{label}.mutation_performed", payload.get("mutation_performed") is False),
            _check(
                f"{label}.no_scans",
                _nested(payload, "collection", "directory_scan_performed") is False
                and _nested(payload, "collection", "file_scan_performed") is False,
            ),
            _check(
                f"{label}.no_remote_probe",
                _nested(payload, "collection", "remote_volume_probe_performed") is False,
            ),
            _check(f"{label}.no_model", _nested(payload, "safety", "model_called") is False),
            _check(f"{label}.no_network", _nested(payload, "safety", "network_call") is False),
            _check(f"{label}.no_shell", _nested(payload, "safety", "shell_true") is False),
            _check(
                f"{label}.no_powershell_winrm",
                _nested(payload, "safety", "powershell_executed") is False
                and _nested(payload, "safety", "winrm_used") is False,
            ),
        ]
    )
    volumes = payload.get("volumes")
    checks.append(_check(f"{label}.volumes.list", isinstance(volumes, list)))
    limit = _nested(payload, "collection", "limit")
    if isinstance(volumes, list):
        if isinstance(limit, int):
            checks.append(_check(f"{label}.volumes.bounded", len(volumes) <= limit))
        guid_re = re.compile(r"volume\{[0-9a-fA-F-]+\}")
        for index, volume in enumerate(volumes):
            prefix = f"{label}.volumes[{index}]"
            drive = volume.get("drive") if isinstance(volume, dict) else None
            mount = volume.get("mountpoint") if isinstance(volume, dict) else None
            checks.append(
                _check(
                    f"{prefix}.drive",
                    isinstance(drive, str) and re.fullmatch(r"[A-Z]:", drive or "") is not None,
                )
            )
            checks.append(
                _check(
                    f"{prefix}.mountpoint",
                    isinstance(mount, str) and re.fullmatch(r"[A-Z]:\\", mount or "") is not None,
                )
            )
            text = json.dumps(volume, sort_keys=True) if isinstance(volume, dict) else ""
            checks.append(
                _check(
                    f"{prefix}.privacy",
                    not guid_re.search(text.lower())
                    and "serial" not in text.lower()
                    and "label" not in text.lower(),
                )
            )
            fs = volume.get("filesystem") if isinstance(volume, dict) else None
            checks.append(
                _check(
                    f"{prefix}.filesystem_bounded",
                    fs is None or (isinstance(fs, str) and len(fs) <= 32),
                )
            )
            for key in ("total_bytes", "used_bytes", "free_bytes"):
                value = volume.get(key) if isinstance(volume, dict) else None
                if value is not None:
                    checks.append(_check(f"{prefix}.{key}", isinstance(value, int) and value >= 0))
            pct = volume.get("used_percent") if isinstance(volume, dict) else None
            if pct is not None:
                checks.append(
                    _check(
                        f"{prefix}.used_percent", isinstance(pct, int | float) and 0 <= pct <= 100
                    )
                )
    return checks


def _validate_memory(payload: Any, *, label: str = "memory") -> list[Check]:
    checks = [
        _check(f"{label}.object", isinstance(payload, dict), "top-level JSON must be an object")
    ]
    if not isinstance(payload, dict):
        return checks
    checks.extend(
        [
            _check(f"{label}.schema_version", payload.get("schema_version") == 1),
            _check(f"{label}.mode", payload.get("mode") == "windows_memory"),
            _check(f"{label}.status", payload.get("status") == "ok"),
            _check(f"{label}.platform.system", _nested(payload, "platform", "system") == "windows"),
            _check(f"{label}.read_only", payload.get("read_only") is True),
            _check(f"{label}.mutation_performed", payload.get("mutation_performed") is False),
            _check(
                f"{label}.windows_v1.available", _nested(payload, "windows_v1", "available") is True
            ),
        ]
    )
    for key in WINDOWS_V1_FALSE_KEYS:
        checks.append(
            _check(f"{label}.windows_v1.{key}", _nested(payload, "windows_v1", key) is False)
        )
    for key in MEMORY_SAFETY_FALSE_KEYS:
        checks.append(_check(f"{label}.safety.{key}", _nested(payload, "safety", key) is False))
    memory = payload.get("memory")
    checks.append(
        _check(f"{label}.memory.object", isinstance(memory, dict), "memory object required")
    )
    if isinstance(memory, dict) and memory.get("available") is True:
        total = memory.get("total_bytes")
        available = memory.get("available_bytes")
        used = memory.get("used_bytes")
        percent = memory.get("used_percent")
        checks.extend(
            [
                _check(f"{label}.memory.total_bytes", isinstance(total, int) and total > 0),
                _check(
                    f"{label}.memory.available_bytes", isinstance(available, int) and available >= 0
                ),
                _check(f"{label}.memory.used_bytes", isinstance(used, int) and used >= 0),
                _check(
                    f"{label}.memory.available_lte_total",
                    isinstance(total, int) and isinstance(available, int) and available <= total,
                ),
                _check(
                    f"{label}.memory.used_lte_total",
                    isinstance(total, int) and isinstance(used, int) and used <= total,
                ),
                _check(
                    f"{label}.memory.used_percent",
                    isinstance(percent, int | float) and 0 <= percent <= 100,
                ),
            ]
        )
    return checks


def _validate_processes(
    payload: Any,
    expected_host: str | None,
    expected_python: str | None,
    *,
    label: str = "processes",
) -> list[Check]:
    checks = [
        _check(f"{label}.object", isinstance(payload, dict), "top-level JSON must be an object")
    ]
    if not isinstance(payload, dict):
        return checks

    checks.extend(
        [
            _check(
                f"{label}.schema_version",
                payload.get("schema_version") == 1,
                "expected schema_version 1",
            ),
            _check(
                f"{label}.mode",
                payload.get("mode") == "windows_processes",
                "expected mode 'windows_processes'",
            ),
            _check(f"{label}.status", payload.get("status") == "ok", "expected status 'ok'"),
            _check(
                f"{label}.platform.system",
                _nested(payload, "platform", "system") == "windows",
                "expected platform.system 'windows'",
            ),
            _check(
                f"{label}.read_only", payload.get("read_only") is True, "expected read_only true"
            ),
            _check(
                f"{label}.mutation_performed",
                payload.get("mutation_performed") is False,
                "expected mutation_performed false",
            ),
            _check(
                f"{label}.windows_v1.available",
                _nested(payload, "windows_v1", "available") is True,
                "expected windows_v1.available true",
            ),
            _check(
                f"{label}.windows_v1.scope",
                _nested(payload, "windows_v1", "scope") == "local_read_only_processes_preview",
                "expected local_read_only_processes_preview scope",
            ),
        ]
    )
    for key in WINDOWS_V1_FALSE_KEYS:
        checks.append(
            _check(
                f"{label}.windows_v1.{key}",
                _nested(payload, "windows_v1", key) is False,
                f"expected {key} false",
            )
        )
    for key in PROCESSES_SAFETY_FALSE_KEYS:
        checks.append(
            _check(
                f"{label}.safety.{key}",
                _nested(payload, "safety", key) is False,
                f"expected {key} false",
            )
        )

    limit = payload.get("limit")
    total = payload.get("total_count")
    returned = payload.get("returned_count")
    truncated = payload.get("truncated")
    checks.extend(
        [
            _check(
                f"{label}.method",
                payload.get("method") == PROCESSES_METHOD,
                f"expected method {PROCESSES_METHOD!r}",
            ),
            _check(
                f"{label}.limit",
                _non_negative_int(limit) and PROCESSES_MIN_LIMIT <= limit <= PROCESSES_MAX_LIMIT,
                f"expected integer limit between {PROCESSES_MIN_LIMIT} and {PROCESSES_MAX_LIMIT}",
            ),
            _check(
                f"{label}.total_count",
                _non_negative_int(total),
                "expected non-negative integer total_count",
            ),
            _check(
                f"{label}.returned_count",
                _non_negative_int(returned),
                "expected non-negative integer returned_count",
            ),
            _check(
                f"{label}.truncated",
                isinstance(truncated, bool),
                "expected boolean truncated",
            ),
        ]
    )
    if _non_negative_int(returned) and _non_negative_int(limit) and limit >= PROCESSES_MIN_LIMIT:
        checks.append(
            _check(
                f"{label}.returned_le_limit",
                returned <= limit,
                "expected returned_count <= limit",
            )
        )
    if _non_negative_int(returned) and _non_negative_int(total):
        checks.append(
            _check(
                f"{label}.returned_le_total",
                returned <= total,
                "expected returned_count <= total_count",
            )
        )
        if isinstance(truncated, bool):
            checks.append(
                _check(
                    f"{label}.truncation_consistent",
                    truncated == (total > returned),
                    "expected truncated consistent with total_count and returned_count",
                )
            )

    processes = payload.get("processes")
    checks.append(
        _check(f"{label}.processes.list", isinstance(processes, list), "expected processes list")
    )
    if isinstance(processes, list):
        for index, item in enumerate(processes):
            checks.extend(_process_item_checks(item, f"{label}.processes[{index}]"))
        if _non_negative_int(returned):
            checks.append(
                _check(
                    f"{label}.processes.returned_count_consistent",
                    len(processes) == returned,
                    "expected processes list length to match returned_count",
                )
            )
        if _non_negative_int(limit) and PROCESSES_MIN_LIMIT <= limit <= PROCESSES_MAX_LIMIT:
            checks.append(
                _check(
                    f"{label}.processes.bounded_by_limit",
                    len(processes) <= limit,
                    "expected processes list length <= limit",
                )
            )

    not_collected = payload.get("not_collected_in_pr274")
    for key in PROCESSES_NOT_COLLECTED_PR274_KEYS:
        checks.append(
            _check(
                f"{label}.not_collected_in_pr274.{key}",
                isinstance(not_collected, dict) and key in not_collected,
                f"expected not_collected_in_pr274.{key}",
            )
        )

    host = payload.get("host")
    if expected_host is not None and isinstance(host, dict) and host.get("hostname") is not None:
        checks.append(
            _check(
                f"{label}.host.expected",
                host.get("hostname") == expected_host,
                f"expected host hostname {expected_host!r}",
            )
        )
    runtime = payload.get("python_runtime")
    if expected_python is not None and isinstance(runtime, dict) and runtime.get("version"):
        checks.append(
            _check(
                f"{label}.python_runtime.expected",
                _python_matches(runtime.get("version"), expected_python),
                f"expected Python version prefix or exact {expected_python!r}",
            )
        )
    return checks


def _artifact_summary(payload: Any, expected_mode: str, validated: bool) -> dict[str, Any]:
    artifact = {"mode": None, "status": None, "validated": validated}
    if isinstance(payload, dict):
        artifact["mode"] = payload.get("mode")
        artifact["status"] = payload.get("status")
    elif validated:
        artifact["mode"] = expected_mode
    return artifact


def _cross_check(
    evidence: Any,
    status: Any,
    doctor: Any,
    services: Any = None,
    disks: Any = None,
    processes: Any = None,
) -> list[Check]:
    checks: list[Check] = []
    if not isinstance(evidence, dict):
        return checks
    if isinstance(status, dict) and isinstance(_nested(evidence, "components", "status"), dict):
        component = _nested(evidence, "components", "status")
        checks.extend(
            [
                _check(
                    "cross_check.status.mode",
                    component.get("mode") == status.get("mode"),
                    "evidence status mode differs from standalone status mode",
                ),
                _check(
                    "cross_check.status.status",
                    component.get("status") == status.get("status"),
                    "evidence status differs from standalone status",
                ),
            ]
        )
    if isinstance(doctor, dict) and isinstance(_nested(evidence, "components", "doctor"), dict):
        component = _nested(evidence, "components", "doctor")
        checks.extend(
            [
                _check(
                    "cross_check.doctor.mode",
                    component.get("mode") == doctor.get("mode"),
                    "evidence doctor mode differs from standalone doctor mode",
                ),
                _check(
                    "cross_check.doctor.status",
                    component.get("status") == doctor.get("status"),
                    "evidence doctor status differs from standalone doctor status",
                ),
            ]
        )
    if isinstance(services, dict) and isinstance(_nested(evidence, "components", "services"), dict):
        component = _nested(evidence, "components", "services")
        checks.extend(
            [
                _check(
                    "cross_check.services.mode",
                    component.get("mode") == services.get("mode"),
                    "evidence services mode differs from standalone services mode",
                ),
                _check(
                    "cross_check.services.status",
                    component.get("status") == services.get("status"),
                    "evidence services status differs from standalone services status",
                ),
            ]
        )
        embedded_total = _nested(component, "services", "total_count")
        standalone_total = _nested(services, "services", "total_count")
        if _non_negative_int(embedded_total) and _non_negative_int(standalone_total):
            checks.append(
                _check(
                    "cross_check.services.total_count",
                    embedded_total == standalone_total,
                    "evidence services total_count differs from standalone services total_count",
                )
            )
    if isinstance(disks, dict) and isinstance(_nested(evidence, "components", "disks"), dict):
        component = _nested(evidence, "components", "disks")
        checks.extend(
            [
                _check(
                    "cross_check.disks.mode",
                    component.get("mode") == disks.get("mode"),
                    "evidence disks mode differs from standalone disks mode",
                ),
                _check(
                    "cross_check.disks.status",
                    component.get("status") == disks.get("status"),
                    "evidence disks status differs from standalone disks status",
                ),
            ]
        )
        embedded_total = _nested(component, "summary", "total_roots")
        standalone_total = _nested(disks, "summary", "total_roots")
        if _non_negative_int(embedded_total) and _non_negative_int(standalone_total):
            checks.append(
                _check(
                    "cross_check.disks.total_roots",
                    embedded_total == standalone_total,
                    "evidence disks total_roots differs from standalone disks total_roots",
                )
            )
    if isinstance(processes, dict) and isinstance(
        _nested(evidence, "components", "processes"), dict
    ):
        component = _nested(evidence, "components", "processes")
        checks.extend(
            [
                _check(
                    "cross_check.processes.mode",
                    component.get("mode") == processes.get("mode"),
                    "evidence processes mode differs from standalone processes mode",
                ),
                _check(
                    "cross_check.processes.status",
                    component.get("status") == processes.get("status"),
                    "evidence processes status differs from standalone processes status",
                ),
                _check(
                    "cross_check.processes.method",
                    component.get("method") == processes.get("method"),
                    "evidence processes method differs from standalone processes method",
                ),
            ]
        )
    return checks


def _result(args: argparse.Namespace) -> dict[str, Any]:
    checks: list[Check] = []
    payloads: dict[str, Any] = {
        "evidence": None,
        "status": None,
        "doctor": None,
        "services": None,
        "disks": None,
        "processes": None,
        "memory": None,
        "network": None,
        "volumes": None,
        "events": None,
    }
    services_json = getattr(args, "services_json", None)
    disks_json = getattr(args, "disks_json", None)
    processes_json = getattr(args, "processes_json", None)
    memory_json = getattr(args, "memory_json", None)
    network_json = getattr(args, "network_json", None)
    volumes_json = getattr(args, "volumes_json", None)
    events_json = getattr(args, "events_json", None)

    if args.evidence_json:
        payloads["evidence"], read_checks = _read_json_file(Path(args.evidence_json), "evidence")
        checks.extend(read_checks)
        if payloads["evidence"] is not None:
            checks.extend(
                _validate_evidence(payloads["evidence"], args.expected_host, args.expected_python)
            )

    if args.status_json:
        payloads["status"], read_checks = _read_json_file(Path(args.status_json), "status")
        checks.extend(read_checks)
        if payloads["status"] is not None:
            checks.extend(
                _validate_common(
                    payloads["status"],
                    label="status",
                    expected_mode="windows_status",
                    expected_host=args.expected_host,
                    expected_python=args.expected_python,
                )
            )

    if args.doctor_json:
        payloads["doctor"], read_checks = _read_json_file(Path(args.doctor_json), "doctor")
        checks.extend(read_checks)
        if payloads["doctor"] is not None:
            checks.extend(
                _validate_common(
                    payloads["doctor"],
                    label="doctor",
                    expected_mode="windows_doctor",
                    expected_host=args.expected_host,
                    expected_python=args.expected_python,
                )
            )

    if services_json:
        payloads["services"], read_checks = _read_json_file(Path(services_json), "services")
        checks.extend(read_checks)
        if payloads["services"] is not None:
            checks.extend(
                _validate_services(payloads["services"], args.expected_host, args.expected_python)
            )

    if disks_json:
        payloads["disks"], read_checks = _read_json_file(Path(disks_json), "disks")
        checks.extend(read_checks)
        if payloads["disks"] is not None:
            checks.extend(
                _validate_disks(payloads["disks"], args.expected_host, args.expected_python)
            )

    if processes_json:
        payloads["processes"], read_checks = _read_json_file(Path(processes_json), "processes")
        checks.extend(read_checks)
        if payloads["processes"] is not None:
            checks.extend(
                _validate_processes(payloads["processes"], args.expected_host, args.expected_python)
            )

    if memory_json:
        payloads["memory"], read_checks = _read_json_file(Path(memory_json), "memory")
        checks.extend(read_checks)
        if payloads["memory"] is not None:
            checks.extend(_validate_memory(payloads["memory"]))

    if network_json:
        payloads["network"], read_checks = _read_json_file(Path(network_json), "network")
        checks.extend(read_checks)
        if payloads["network"] is not None:
            checks.extend(_validate_network(payloads["network"]))

    if events_json:
        payloads["events"], read_checks = _read_json_file(Path(events_json), "events")
        checks.extend(read_checks)
        if payloads["events"] is not None:
            checks.extend(_validate_events_artifact(payloads["events"]))

    if volumes_json:
        payloads["volumes"], read_checks = _read_json_file(Path(volumes_json), "volumes")
        checks.extend(read_checks)
        if payloads["volumes"] is not None:
            checks.extend(_validate_volumes(payloads["volumes"]))

    checks.extend(
        _cross_check(
            payloads["evidence"],
            payloads["status"],
            payloads["doctor"],
            payloads["services"],
            payloads["disks"],
            payloads["processes"],
        )
    )

    inputs = {
        "evidence_json": str(Path(args.evidence_json)) if args.evidence_json else None,
        "status_json": str(Path(args.status_json)) if args.status_json else None,
        "doctor_json": str(Path(args.doctor_json)) if args.doctor_json else None,
    }
    artifacts = {
        "evidence": _artifact_summary(
            payloads["evidence"], "windows_evidence_bundle", bool(args.evidence_json)
        ),
        "status": _artifact_summary(payloads["status"], "windows_status", bool(args.status_json)),
        "doctor": _artifact_summary(payloads["doctor"], "windows_doctor", bool(args.doctor_json)),
    }
    if services_json:
        inputs["services_json"] = str(Path(services_json))
        artifacts["services"] = _artifact_summary(payloads["services"], "windows_services", True)
    if disks_json:
        inputs["disks_json"] = str(Path(disks_json))
        artifacts["disks"] = _artifact_summary(payloads["disks"], "windows_disks", True)
    if processes_json:
        inputs["processes_json"] = str(Path(processes_json))
        artifacts["processes"] = _artifact_summary(payloads["processes"], "windows_processes", True)
    if memory_json:
        inputs["memory_json"] = str(Path(memory_json))
        artifacts["memory"] = _artifact_summary(payloads["memory"], "windows_memory", True)
    if network_json:
        inputs["network_json"] = str(Path(network_json))
        artifacts["network"] = _artifact_summary(payloads["network"], "windows_network", True)
    if events_json:
        inputs["events_json"] = str(Path(events_json))
    if volumes_json:
        inputs["volumes_json"] = str(Path(volumes_json))
        artifacts["volumes"] = _artifact_summary(payloads["volumes"], "windows_volumes", True)

    passed = sum(1 for check in checks if check.passed)
    failed = len(checks) - passed
    return {
        "schema_version": 1,
        "mode": "windows_smoke_acceptance",
        "status": "ok" if failed == 0 else "failed",
        "read_only": True,
        "mutation_performed": False,
        "inputs": inputs,
        "artifacts": artifacts,
        "checks": [check.to_dict() for check in checks],
        "summary": {"passed": passed, "failed": failed},
    }


def _render_text(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "Windows smoke acceptance",
        f"Status: {result['status']}",
        f"Passed: {summary['passed']}",
        f"Failed: {summary['failed']}",
    ]
    failed = [check for check in result["checks"] if not check["passed"]]
    if failed:
        lines.append("Failed checks:")
        lines.extend(
            f"- {check['name']}: {check.get('reason', 'check failed')}" for check in failed
        )
    return "\n".join(lines)


EVENTS_FALLBACK_ERROR = {
    "type": "events_component_failed",
    "message": "Windows Event Log metadata component failed.",
}
EVENTS_COLLECTION_ERROR_MESSAGE = "Windows Event Log metadata collection failed."
_EVENTS_ERROR_VALUE_FORBIDDEN_RE = re.compile(
    r"(Traceback|OSError|RuntimeError|C:\\|secret-marker|raw query|"
    r"System\[\(Level=|0x[0-9a-fA-F]{6,})"
)


def _event_error_values_are_sanitized(errors: Any) -> bool:
    if not isinstance(errors, list) or len(errors) > 1:
        return False
    for entry in errors:
        if not isinstance(entry, dict):
            return False
        for key, value in entry.items():
            if key == "type":
                continue
            if isinstance(value, str) and _EVENTS_ERROR_VALUE_FORBIDDEN_RE.search(value):
                return False
    return True


def _validate_events_errors(payload: dict[str, Any]) -> list[Check]:
    errors = payload.get("errors", [])
    checks = [_check("events.errors.list", isinstance(errors, list))]
    if not isinstance(errors, list):
        return checks
    checks.append(_check("events.errors.bounded", len(errors) <= 1))
    for idx, entry in enumerate(errors):
        checks.append(_check(f"events.errors.{idx}.object", isinstance(entry, dict)))
        if not isinstance(entry, dict):
            continue
        if entry.get("type") == "events_component_failed":
            checks.extend(
                [
                    _check(
                        f"events.errors.{idx}.fallback_keys",
                        set(entry) == set(EVENTS_FALLBACK_ERROR),
                    ),
                    _check(
                        f"events.errors.{idx}.fallback_exact",
                        entry == EVENTS_FALLBACK_ERROR,
                    ),
                ]
            )
        else:
            checks.extend(
                [
                    _check(
                        f"events.errors.{idx}.collection_keys",
                        set(entry) <= {"type", "message", "winerror"},
                    ),
                    _check(
                        f"events.errors.{idx}.collection_type",
                        isinstance(entry.get("type"), str) and bool(entry.get("type")),
                    ),
                    _check(
                        f"events.errors.{idx}.collection_message",
                        entry.get("message") == EVENTS_COLLECTION_ERROR_MESSAGE,
                    ),
                ]
            )
        checks.append(
            _check(
                f"events.errors.{idx}.sanitized_values",
                _event_error_values_are_sanitized([entry]),
            )
        )
    return checks


def _validate_events_artifact(payload: dict[str, Any]) -> list[Check]:
    checks: list[Check] = []
    checks.append(_check("events.mode", payload.get("mode") == "windows_events"))
    checks.append(_check("events.platform", payload.get("platform", {}).get("system") == "windows"))
    checks.append(_check("events.read_only", payload.get("read_only") is True))
    checks.append(_check("events.no_mutation", payload.get("mutation_performed") is False))
    collection = payload.get("collection", {})
    checks.append(_check("events.channel_system", collection.get("channel") == "System"))
    checks.append(
        _check("events.levels", collection.get("levels") == ["critical", "error", "warning"])
    )
    limit = collection.get("limit")
    checks.append(_check("events.limit_bounded", isinstance(limit, int) and 1 <= limit <= 200))
    checks.append(
        _check(
            "events.lookback_bounded",
            isinstance(collection.get("since_hours"), int)
            and 1 <= collection.get("since_hours") <= 168,
        )
    )
    events = payload.get("events", [])
    checks.append(_check("events.array", isinstance(events, list)))
    if isinstance(events, list) and isinstance(limit, int):
        checks.append(_check("events.count_within_limit", len(events) <= limit))
        allowed = {
            "provider",
            "event_id",
            "level",
            "time_created_utc",
            "record_id",
            "task",
            "opcode",
            "keywords",
        }
        last_key: tuple[str, int] | None = None
        for idx, event in enumerate(events):
            if not isinstance(event, dict):
                checks.append(_check(f"events.item_{idx}.object", False))
                continue
            checks.append(_check(f"events.item_{idx}.keys", set(event) <= allowed))
            required = {"provider", "event_id", "level", "time_created_utc", "record_id"}
            checks.append(_check(f"events.item_{idx}.required_keys", required <= set(event)))
            checks.append(
                _check(
                    f"events.item_{idx}.provider",
                    isinstance(event.get("provider"), str)
                    and 0 < len(event.get("provider", "")) <= 256,
                )
            )
            checks.append(
                _check(
                    f"events.item_{idx}.event_id",
                    isinstance(event.get("event_id"), int)
                    and not isinstance(event.get("event_id"), bool)
                    and 0 <= event.get("event_id") <= 65535,
                )
            )
            checks.append(
                _check(
                    f"events.item_{idx}.level",
                    event.get("level") in {"critical", "error", "warning"},
                )
            )
            rid = event.get("record_id")
            checks.append(
                _check(
                    f"events.item_{idx}.record_id",
                    isinstance(rid, int) and not isinstance(rid, bool) and rid > 0,
                )
            )
            for optional_key, maximum in (
                ("task", 65535),
                ("opcode", 255),
                ("keywords", (2**64) - 1),
            ):
                if optional_key in event:
                    value = event.get(optional_key)
                    checks.append(
                        _check(
                            f"events.item_{idx}.{optional_key}",
                            isinstance(value, int)
                            and not isinstance(value, bool)
                            and 0 <= value <= maximum,
                        )
                    )
            ts = event.get("time_created_utc")
            checks.append(
                _check(
                    f"events.item_{idx}.timestamp",
                    isinstance(ts, str) and EVENTS_TIMESTAMP_RE.match(ts) is not None,
                )
            )
            key = (ts or "", int(rid or 0))
            if last_key is not None:
                checks.append(_check(f"events.item_{idx}.newest_first", key <= last_key))
            last_key = key
    summary = payload.get("summary", {})
    if payload.get("status") == "ok":
        checks.append(_check("events.summary_unknown_zero", summary.get("unknown", 0) == 0))
    emitted_pairs = {
        (event.get("provider"), event.get("event_id"), event.get("level"))
        for event in events
        if isinstance(event, dict)
    }
    top_pairs = payload.get("top_provider_event_pairs", [])
    checks.append(_check("events.top_provider_event_pairs.array", isinstance(top_pairs, list)))
    for idx, pair in enumerate(top_pairs if isinstance(top_pairs, list) else []):
        if not isinstance(pair, dict):
            checks.append(_check(f"events.aggregation_{idx}.object", False))
            continue
        checks.append(
            _check(
                f"events.aggregation_{idx}.keys",
                set(pair) <= {"provider", "event_id", "level", "count", "most_recent_utc"},
            )
        )
        most_recent = pair.get("most_recent_utc")
        if most_recent is not None:
            checks.append(
                _check(
                    f"events.aggregation_{idx}.most_recent_timestamp",
                    isinstance(most_recent, str)
                    and EVENTS_TIMESTAMP_RE.match(most_recent) is not None,
                )
            )
        checks.append(
            _check(
                f"events.aggregation_{idx}.represented",
                (pair.get("provider"), pair.get("event_id"), pair.get("level")) in emitted_pairs,
            )
        )
    if payload.get("status") == "ok" and not events:
        invalid_warnings = [
            warning
            for warning in payload.get("warnings", [])
            if isinstance(warning, dict)
            and str(warning.get("category", "")).startswith("invalid_required_")
        ]
        checks.append(_check("events.no_hidden_all_invalid_success", not invalid_warnings))

    checks.extend(_validate_events_errors(payload))

    safety = payload.get("safety", {})
    for key in (
        "powershell_executed",
        "winrm_used",
        "remote_execution",
        "shell_true",
        "arbitrary_command_execution",
        "model_called",
        "network_call",
        "event_log_write_performed",
        "event_log_clear_performed",
        "event_log_export_performed",
        "event_subscription_created",
    ):
        checks.append(_check(f"events.safety.{key}", safety.get(key) is False))
    return checks


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate saved ShellForgeAI Windows smoke JSON artifacts."
    )
    parser.add_argument(
        "--evidence-json",
        help="Optional path to saved 'shellforgeai windows evidence --json' output.",
    )
    parser.add_argument(
        "--status-json", help="Optional path to saved 'shellforgeai windows status --json' output."
    )
    parser.add_argument(
        "--doctor-json", help="Optional path to saved 'shellforgeai windows doctor --json' output."
    )
    parser.add_argument(
        "--services-json",
        help="Optional path to saved 'shellforgeai windows services --json' output.",
    )
    parser.add_argument(
        "--disks-json",
        help="Optional path to saved 'shellforgeai windows disks --json' output.",
    )
    parser.add_argument(
        "--processes-json",
        help="Optional path to saved 'shellforgeai windows processes --json' output.",
    )
    parser.add_argument(
        "--memory-json",
        help="Optional path to saved 'shellforgeai windows memory --json' output.",
    )
    parser.add_argument(
        "--network-json",
        help="Optional path to saved 'shellforgeai windows network --json' output.",
    )
    parser.add_argument(
        "--events-json",
        type=Path,
        help=(
            "Optional path to saved 'shellforgeai windows events --json "
            "--since-hours 24 --limit 50' output."
        ),
    )
    parser.add_argument(
        "--volumes-json",
        help="Optional path to saved 'shellforgeai windows volumes --json' output.",
    )
    parser.add_argument(
        "--expected-host", help="Optional expected Windows hostname, for example WIN2025-SFAI01."
    )
    parser.add_argument(
        "--expected-python",
        help="Optional expected Python version prefix or exact value, for example 3.14.6.",
    )
    parser.add_argument("--json", action="store_true", help="Emit deterministic JSON output.")
    args = parser.parse_args(argv)
    if not (
        args.evidence_json
        or args.status_json
        or args.doctor_json
        or args.services_json
        or args.disks_json
        or args.processes_json
        or args.memory_json
        or args.network_json
        or args.volumes_json
        or args.events_json
    ):
        parser.error(
            "at least one of --evidence-json, --status-json, --doctor-json, "
            "--services-json, --disks-json, --processes-json, --memory-json, "
            "--network-json, --events-json, or --volumes-json is required"
        )
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    result = _result(args)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(_render_text(result))
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
