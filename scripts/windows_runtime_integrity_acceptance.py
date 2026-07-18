#!/usr/bin/env python3
"""Validate saved Windows runtime integrity JSON artifacts only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

MODE = "windows_runtime_integrity"
ALLOWED_STATUS = {"ok", "attention", "blocked", "unsupported"}
ALLOWED_CHECK = {"pass", "attention", "blocked", "not_requested", "unsupported"}
FALSE_KEYS = (
    "natural_language_execution",
    "powershell_executed",
    "winrm_used",
    "qga_used",
    "remote_execution",
    "subprocess_executed",
    "shell_executed",
    "shell_true",
    "arbitrary_command_execution",
    "network_call",
    "model_called",
    "secret_read",
    "auth_cache_read",
    "software_install_executed",
    "software_uninstall_executed",
    "wrapper_modified",
    "file_deleted",
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
    "service_control_executed",
    "process_termination_executed",
    "registry_modified",
    "execution_policy_modified",
)
STABLE_PATHS = (
    ("status",),
    ("python_runtime", "executable"),
    ("shellforgeai_import", "module_file"),
    ("shellforgeai_import", "package_root"),
    ("shellforgeai_import", "expected_source_match"),
    ("runtime_context", "resolved"),
    ("runtime_context", "runtime_root"),
    ("runtime_context", "profile_root"),
    ("runtime_context", "source"),
    ("runtime_context", "checked_sources"),
    ("wrapper", "sha256"),
    ("wrapper", "canonical_sha256"),
    ("wrapper", "normalized_text_equal"),
    ("wrapper", "material_match"),
    ("embedded_python", "expected_path"),
    ("embedded_python", "exists"),
    ("entrypoint", "path"),
    ("entrypoint", "exists"),
    ("invalid_distribution_residue", "matches"),
    ("invalid_distribution_residue", "residue_count"),
)


def _get(obj: dict[str, Any], path: tuple[str, ...]) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _expected_status(payload: dict[str, Any]) -> str:
    checks = payload.get("checks", [])
    platform = payload.get("platform", {})
    if platform.get("system") != "windows":
        return "unsupported"
    states = {item.get("status") for item in checks if isinstance(item, dict)}
    if "blocked" in states:
        return "blocked"
    if states & {"attention", "not_requested"}:
        return "attention"
    return "ok"


def validate(payload: dict[str, Any], expect_status: str | None = None) -> list[str]:
    errors: list[str] = []
    if payload.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if payload.get("mode") != MODE:
        errors.append("mode must be windows_runtime_integrity")
    status = payload.get("status")
    if status not in ALLOWED_STATUS:
        errors.append("invalid top-level status")
    if expect_status and status != expect_status:
        errors.append(f"expected status {expect_status}, got {status}")
    checks = payload.get("checks")
    if not isinstance(checks, list) or not all(isinstance(item, dict) for item in checks):
        errors.append("checks must be a list of objects")
        checks = []
    states = [item.get("status") for item in checks]
    if any(state not in ALLOWED_CHECK for state in states):
        errors.append("invalid check status")
    summary = payload.get("summary")
    if not isinstance(summary, dict):
        errors.append("summary must be an object")
    else:
        for state in ALLOWED_CHECK:
            if summary.get(state, 0) != states.count(state):
                errors.append(f"summary count mismatch for {state}")
    if status in ALLOWED_STATUS and status != _expected_status(payload):
        errors.append("top-level status precedence is incorrect")
    if payload.get("read_only") is not True or payload.get("mutation_performed") is not False:
        errors.append("top-level read-only/mutation flags are unsafe")
    safety = payload.get("safety")
    if (
        not isinstance(safety, dict)
        or safety.get("read_only") is not True
        or safety.get("mutation_performed") is not False
    ):
        errors.append("safety block read-only/mutation flags are unsafe")
    else:
        for key in FALSE_KEYS:
            if safety.get(key) is not False:
                errors.append(f"unsafe safety flag: {key}")
    first = payload.get("first_safe_command")
    if not isinstance(first, str) or not first.strip():
        errors.append("first_safe_command is missing")
    elif any(
        bad in first.casefold()
        for bad in (" pip ", "install", "cleanup", "delete", "remove", "powershell")
    ):
        errors.append("first_safe_command appears mutating or executes wrapper")
    if status == "unsupported" and payload.get("platform", {}).get("system") == "windows":
        errors.append("unsupported artifact claims Windows platform")
    if status == "blocked" and "blocked" not in states:
        errors.append("blocked artifact lacks blocked check")
    if status == "attention" and (
        "blocked" in states or not ({"attention", "not_requested"} & set(states))
    ):
        errors.append("attention artifact state mismatch")
    if status == "ok" and ({"blocked", "attention", "not_requested", "unsupported"} & set(states)):
        errors.append("ok artifact has non-pass checks")
    return errors


def read_artifact(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, [f"{path}: invalid JSON: {exc}"]
    if not isinstance(payload, dict):
        return None, [f"{path}: JSON must be an object"]
    return payload, []


def compare(payloads: list[dict[str, Any]]) -> list[str]:
    if len(payloads) < 2:
        return []
    errors: list[str] = []
    first = payloads[0]
    for index, payload in enumerate(payloads[1:], start=2):
        for path in STABLE_PATHS:
            if _get(first, path) != _get(payload, path):
                errors.append(f"artifact {index} stable field mismatch: {'.'.join(path)}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="+")
    parser.add_argument("--expect-status", choices=sorted(ALLOWED_STATUS))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    payloads: list[dict[str, Any]] = []
    failures: list[str] = []
    for value in args.artifacts:
        payload, errs = read_artifact(Path(value))
        failures.extend(errs)
        if payload is not None:
            payloads.append(payload)
            failures.extend(f"{value}: {err}" for err in validate(payload, args.expect_status))
    failures.extend(compare(payloads))
    result = {"accepted": not failures, "artifact_count": len(args.artifacts), "failures": failures}
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print("accepted" if not failures else "rejected")
        for failure in failures:
            print(f"- {failure}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
