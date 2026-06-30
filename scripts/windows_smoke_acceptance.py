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
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SAFETY_FALSE_KEYS = (
    "shell_true",
    "arbitrary_command_execution",
    "network_call",
    "model_called",
    "secret_read",
    "auth_cache_read",
    "service_restart_executed",
    "process_termination_executed",
    "registry_modified",
    "execution_policy_modified",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
)

TOP_LEVEL_FALSE_KEYS = ("mutation_performed",)
WINDOWS_V1_FALSE_KEYS = ("powershell_executed", "winrm_used", "remote_execution")


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


def _read_json_file(path: Path, label: str) -> tuple[Any | None, list[Check]]:
    if not path.exists():
        return None, [_check(f"{label}.file_exists", False, f"file not found: {path}")]
    if not path.is_file():
        return None, [_check(f"{label}.is_file", False, f"not a file: {path}")]
    try:
        return json.loads(path.read_text(encoding="utf-8")), [_check(f"{label}.json_parse", True)]
    except json.JSONDecodeError as exc:
        return None, [_check(f"{label}.json_parse", False, f"invalid JSON: {exc.msg}")]
    except OSError as exc:
        return None, [_check(f"{label}.json_read", False, str(exc))]


def _nested(payload: dict[str, Any], *keys: str) -> Any:
    current: Any = payload
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _validate_common(
    payload: Any,
    *,
    label: str,
    expected_mode: str,
    expected_host: str | None,
    expected_python: str | None,
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
    if expected_mode == "windows_status":
        checks.append(
            _check(
                f"{label}.windows_v1.scope",
                _nested(payload, "windows_v1", "scope") == "local_read_only_status",
                "expected local_read_only_status scope",
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
    checks.append(
        _check(
            f"{label}.host.present", isinstance(host, dict) and bool(host), "expected host basics"
        )
    )
    if expected_host is not None:
        checks.append(
            _check(
                f"{label}.host.expected",
                isinstance(host, dict) and host.get("hostname") == expected_host,
                f"expected host hostname {expected_host!r}",
            )
        )

    runtime = payload.get("python_runtime")
    checks.append(
        _check(
            f"{label}.python_runtime.present",
            isinstance(runtime, dict)
            and bool(runtime.get("version"))
            and bool(runtime.get("executable")),
            "expected Python runtime basics",
        )
    )
    if expected_python is not None:
        checks.append(
            _check(
                f"{label}.python_runtime.expected",
                isinstance(runtime, dict) and runtime.get("version") == expected_python,
                f"expected Python version {expected_python!r}",
            )
        )

    filesystem = payload.get("filesystem")
    checks.append(
        _check(
            f"{label}.filesystem.present",
            isinstance(filesystem, dict) and bool(filesystem),
            "expected filesystem basics",
        )
    )
    return checks


def _result(args: argparse.Namespace) -> dict[str, Any]:
    checks: list[Check] = []
    status_payload, status_checks = _read_json_file(Path(args.status_json), "status")
    checks.extend(status_checks)
    if status_payload is not None:
        checks.extend(
            _validate_common(
                status_payload,
                label="status",
                expected_mode="windows_status",
                expected_host=args.expected_host,
                expected_python=args.expected_python,
            )
        )

    doctor_input = None
    if args.doctor_json:
        doctor_input = str(Path(args.doctor_json))
        doctor_payload, doctor_checks = _read_json_file(Path(args.doctor_json), "doctor")
        checks.extend(doctor_checks)
        if doctor_payload is not None:
            checks.extend(
                _validate_common(
                    doctor_payload,
                    label="doctor",
                    expected_mode="windows_doctor",
                    expected_host=args.expected_host,
                    expected_python=args.expected_python,
                )
            )

    passed = sum(1 for check in checks if check.passed)
    failed = len(checks) - passed
    return {
        "schema_version": 1,
        "mode": "windows_smoke_acceptance",
        "status": "ok" if failed == 0 else "failed",
        "read_only": True,
        "mutation_performed": False,
        "inputs": {"status_json": str(Path(args.status_json)), "doctor_json": doctor_input},
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
        "--status-json",
        required=True,
        help="Path to saved 'shellforgeai windows status --json' output.",
    )
    parser.add_argument(
        "--doctor-json", help="Optional path to saved 'shellforgeai windows doctor --json' output."
    )
    parser.add_argument(
        "--expected-host", help="Optional expected Windows hostname, for example WIN2025-SFAI01."
    )
    parser.add_argument(
        "--expected-python", help="Optional expected Python version, for example 3.12.10."
    )
    parser.add_argument("--json", action="store_true", help="Emit deterministic JSON output.")
    return parser.parse_args(argv)


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
