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
WINDOWS_V1_FALSE_KEYS = ("powershell_executed", "winrm_used", "remote_execution")
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

    expected_component_count = 2 + int(has_services) + int(has_disks)
    expected_ok = {"doctor", "status"}
    if has_services:
        expected_ok.add("services")
    if has_disks:
        expected_ok.add("disks")
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
                failed_components == [],
                "expected no failed components",
            ),
            _check(
                "evidence.summary.ok_components",
                isinstance(ok_components, list) and expected_ok.issubset(set(ok_components)),
                f"expected {', '.join(sorted(expected_ok))} ok components",
            ),
        ]
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
        items = summary.get("items")
        checks.append(
            _check(f"{label}.services.items", isinstance(items, list), "expected services list")
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


def _artifact_summary(payload: Any, expected_mode: str, validated: bool) -> dict[str, Any]:
    artifact = {"mode": None, "status": None, "validated": validated}
    if isinstance(payload, dict):
        artifact["mode"] = payload.get("mode")
        artifact["status"] = payload.get("status")
    elif validated:
        artifact["mode"] = expected_mode
    return artifact


def _cross_check(
    evidence: Any, status: Any, doctor: Any, services: Any = None, disks: Any = None
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
    return checks


def _result(args: argparse.Namespace) -> dict[str, Any]:
    checks: list[Check] = []
    payloads: dict[str, Any] = {
        "evidence": None,
        "status": None,
        "doctor": None,
        "services": None,
        "disks": None,
    }
    services_json = getattr(args, "services_json", None)
    disks_json = getattr(args, "disks_json", None)

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

    checks.extend(
        _cross_check(
            payloads["evidence"],
            payloads["status"],
            payloads["doctor"],
            payloads["services"],
            payloads["disks"],
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
    ):
        parser.error(
            "at least one of --evidence-json, --status-json, --doctor-json, "
            "--services-json, or --disks-json is required"
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
