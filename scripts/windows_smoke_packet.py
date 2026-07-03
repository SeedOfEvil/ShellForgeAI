#!/usr/bin/env python3
"""Build deterministic QA packets from saved Windows smoke artifacts.

Local-only helper: reads saved JSON files, reuses the Windows smoke acceptance
validator, hashes inputs, and emits JSON and/or Markdown. It does not invoke
ShellForgeAI product commands, child processes, remoting, shells, or network APIs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import windows_smoke_acceptance as acceptance  # noqa: E402

SAFETY = {
    "read_only": True,
    "mutation_performed": False,
    "powershell_executed": False,
    "winrm_used": False,
    "remote_execution": False,
    "shell_true": False,
    "arbitrary_command_execution": False,
    "network_call": False,
    "model_called": False,
    "secret_read": False,
    "auth_cache_read": False,
}


def _hash_file(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}


def _artifact(path_value: str, validator_artifact: dict[str, Any]) -> dict[str, Any]:
    path = Path(path_value)
    payload: dict[str, Any] = {"path": str(path)}
    if path.exists() and path.is_file():
        payload.update(_hash_file(path))
    else:
        payload.update({"sha256": None, "size_bytes": None})
    payload["mode"] = validator_artifact.get("mode")
    payload["status"] = validator_artifact.get("status")
    return payload


def _services_counts(path_value: str) -> dict[str, Any]:
    counts: dict[str, Any] = {"total": None, "running": None, "stopped": None, "unknown": None}
    payload, _ = acceptance._read_json_file(Path(path_value), "services")
    summary = payload.get("services") if isinstance(payload, dict) else None
    if isinstance(summary, dict):
        counts["total"] = summary.get("total_count")
        state_counts = summary.get("state_counts")
        if isinstance(state_counts, dict):
            for key in ("running", "stopped", "unknown"):
                counts[key] = state_counts.get(key)
    return counts


DISK_SAFETY_KEYS = (
    "directory_scan_performed",
    "file_scan_performed",
    "disk_mutation_performed",
)


def _disks_counts(path_value: str) -> dict[str, Any]:
    counts: dict[str, Any] = {
        "total_roots": None,
        "returned_roots": None,
        "available_roots": None,
        "unavailable_roots": None,
        "limit": None,
        "truncated": None,
        "disk_safety": {key: None for key in DISK_SAFETY_KEYS},
    }
    payload, _ = acceptance._read_json_file(Path(path_value), "disks")
    summary = payload.get("summary") if isinstance(payload, dict) else None
    if isinstance(summary, dict):
        for key in ("total_roots", "returned_roots", "available_roots", "unavailable_roots"):
            counts[key] = summary.get(key)
    collection = payload.get("collection") if isinstance(payload, dict) else None
    if isinstance(collection, dict):
        counts["limit"] = collection.get("limit")
        counts["truncated"] = collection.get("truncated")
    safety = payload.get("safety") if isinstance(payload, dict) else None
    if isinstance(safety, dict):
        for key in DISK_SAFETY_KEYS:
            counts["disk_safety"][key] = safety.get(key)
    return counts


PROCESSES_SUMMARY_KEYS = ("total_count", "returned_count", "limit", "truncated")


def _processes_summary(path_value: str) -> dict[str, Any]:
    summary: dict[str, Any] = {"method": None}
    summary.update({key: None for key in PROCESSES_SUMMARY_KEYS})
    payload, _ = acceptance._read_json_file(Path(path_value), "processes")
    if isinstance(payload, dict):
        summary["method"] = payload.get("method")
        for key in PROCESSES_SUMMARY_KEYS:
            summary[key] = payload.get(key)
    return summary


def _embedded_services_summary(evidence_path: str) -> dict[str, Any] | None:
    """Summarize the opt-in PR269 services component embedded in the evidence bundle."""

    payload, _ = acceptance._read_json_file(Path(evidence_path), "evidence")
    component = None
    if isinstance(payload, dict):
        components = payload.get("components")
        if isinstance(components, dict):
            component = components.get("services")
    if not isinstance(component, dict):
        return None
    summary: dict[str, Any] = {
        "mode": component.get("mode"),
        "status": component.get("status"),
        "limit": component.get("limit"),
        "returned_count": component.get("returned_count"),
        "total_count": component.get("total_count"),
        "truncated": component.get("truncated"),
        "running": None,
        "stopped": None,
        "unknown": None,
    }
    state_counts = component.get("services")
    state_counts = state_counts.get("state_counts") if isinstance(state_counts, dict) else None
    if isinstance(state_counts, dict):
        for key in ("running", "stopped", "unknown"):
            summary[key] = state_counts.get(key)
    return summary


def _embedded_disks_summary(evidence_path: str) -> dict[str, Any] | None:
    """Summarize the opt-in PR272 disks component embedded in the evidence bundle."""

    payload, _ = acceptance._read_json_file(Path(evidence_path), "evidence")
    component = None
    if isinstance(payload, dict):
        components = payload.get("components")
        if isinstance(components, dict):
            component = components.get("disks")
    if not isinstance(component, dict):
        return None
    summary: dict[str, Any] = {
        "mode": component.get("mode"),
        "status": component.get("status"),
        "limit": component.get("limit"),
        "returned_roots": component.get("returned_roots"),
        "total_roots": component.get("total_roots"),
        "truncated": component.get("truncated"),
        "available_roots": None,
        "unavailable_roots": None,
    }
    root_summary = component.get("summary")
    if isinstance(root_summary, dict):
        summary["available_roots"] = root_summary.get("available_roots")
        summary["unavailable_roots"] = root_summary.get("unavailable_roots")
    return summary


def _embedded_processes_summary(evidence_path: str) -> dict[str, Any] | None:
    """Summarize the opt-in PR276 processes component embedded in the evidence bundle."""

    payload, _ = acceptance._read_json_file(Path(evidence_path), "evidence")
    component = None
    if isinstance(payload, dict):
        components = payload.get("components")
        if isinstance(components, dict):
            component = components.get("processes")
    if not isinstance(component, dict):
        return None
    return {
        "mode": component.get("mode"),
        "status": component.get("status"),
        "method": component.get("method"),
        "limit": component.get("limit"),
        "returned_count": component.get("returned_count"),
        "total_count": component.get("total_count"),
        "truncated": component.get("truncated"),
    }


def _windows_summary(args: argparse.Namespace, validator: dict[str, Any]) -> dict[str, Any]:
    evidence_path = validator.get("inputs", {}).get("evidence_json")
    host = args.expected_host
    python = args.expected_python
    if evidence_path:
        payload, _ = acceptance._read_json_file(Path(evidence_path), "evidence")
        if isinstance(payload, dict):
            if host is None and isinstance(payload.get("host"), dict):
                host = payload["host"].get("hostname")
            if python is None and isinstance(payload.get("python_runtime"), dict):
                python = payload["python_runtime"].get("version")
    return {"host": host, "python": python, "platform_system": "windows"}


def build_packet(args: argparse.Namespace) -> dict[str, Any]:
    validator = acceptance._result(args)
    artifacts = validator.get("artifacts", {})
    packet = {
        "schema_version": 1,
        "mode": "windows_smoke_packet",
        "status": "ok" if validator["status"] == "ok" else "failed",
        "pr": int(args.pr) if args.pr is not None else None,
        "commit": args.commit,
        "read_only": True,
        "mutation_performed": False,
        "validator": {
            "mode": validator["mode"],
            "status": validator["status"],
            "summary": validator["summary"],
        },
        "artifacts": {
            "evidence_json": _artifact(args.evidence_json, artifacts.get("evidence", {})),
            "status_json": _artifact(args.status_json, artifacts.get("status", {})),
            "doctor_json": _artifact(args.doctor_json, artifacts.get("doctor", {})),
        },
        "windows": _windows_summary(args, validator),
        "safety": dict(SAFETY),
    }
    embedded_services = _embedded_services_summary(args.evidence_json)
    if embedded_services is not None:
        packet["embedded_services"] = embedded_services
    embedded_disks = _embedded_disks_summary(args.evidence_json)
    if embedded_disks is not None:
        packet["embedded_disks"] = embedded_disks
    embedded_processes = _embedded_processes_summary(args.evidence_json)
    if embedded_processes is not None:
        packet["embedded_processes"] = embedded_processes
    services_json = getattr(args, "services_json", None)
    if services_json:
        services_artifact = _artifact(services_json, artifacts.get("services", {}))
        services_artifact.update(_services_counts(services_json))
        packet["artifacts"]["services_json"] = services_artifact
    disks_json = getattr(args, "disks_json", None)
    if disks_json:
        disks_artifact = _artifact(disks_json, artifacts.get("disks", {}))
        disks_artifact.update(_disks_counts(disks_json))
        packet["artifacts"]["disks_json"] = disks_artifact
    processes_json = getattr(args, "processes_json", None)
    if processes_json:
        packet["artifacts"]["processes_json"] = _artifact(
            processes_json, artifacts.get("processes", {})
        )
        packet["windows"]["processes"] = _processes_summary(processes_json)
    failed = [check for check in validator.get("checks", []) if not check.get("passed")]
    if failed:
        packet["failed_checks"] = failed
    return packet


def render_markdown(packet: dict[str, Any]) -> str:
    lines = ["# Windows Smoke Evidence Packet", ""]
    if packet.get("pr") is not None:
        lines.append(f"- PR: #{packet['pr']}")
    if packet.get("commit"):
        lines.append(f"- Commit: `{packet['commit']}`")
    lines.extend(
        [
            f"- Packet status: **{packet['status']}**",
            f"- Validator status: **{packet['validator']['status']}**",
            (
                f"- Validator summary: {packet['validator']['summary']['passed']} passed, "
                f"{packet['validator']['summary']['failed']} failed"
            ),
            "",
            "## Artifacts",
            "",
            "| Artifact | Path | SHA256 | Size bytes | Mode | Status |",
            "| --- | --- | --- | ---: | --- | --- |",
        ]
    )
    for name, artifact in packet["artifacts"].items():
        lines.append(
            "| {name} | `{path}` | `{sha}` | {size} | {mode} | {status} |".format(
                name=name,
                path=artifact["path"],
                sha=artifact.get("sha256"),
                size=artifact.get("size_bytes"),
                mode=artifact.get("mode"),
                status=artifact.get("status"),
            )
        )
    windows = packet["windows"]
    lines.extend(
        [
            "",
            "## Windows summary",
            "",
            f"- Host: {windows.get('host') or 'not provided'}",
            f"- Python: {windows.get('python') or 'not provided'}",
            f"- Platform system: {windows.get('platform_system')}",
        ]
    )
    embedded = packet.get("embedded_services")
    if embedded is not None:
        lines.extend(["", "## Embedded services component", ""])
        for label, key in (
            ("Mode", "mode"),
            ("Status", "status"),
            ("Limit", "limit"),
            ("Returned services", "returned_count"),
            ("Total services", "total_count"),
            ("Truncated", "truncated"),
            ("Running", "running"),
            ("Stopped", "stopped"),
            ("Unknown", "unknown"),
        ):
            value = embedded.get(key)
            if isinstance(value, bool):
                value = str(value).lower()
            lines.append(f"- {label}: {value if value is not None else 'not available'}")
    embedded_disks = packet.get("embedded_disks")
    if embedded_disks is not None:
        lines.extend(["", "## Embedded disks component", ""])
        for label, key in (
            ("Mode", "mode"),
            ("Status", "status"),
            ("Limit", "limit"),
            ("Returned roots", "returned_roots"),
            ("Total roots", "total_roots"),
            ("Available roots", "available_roots"),
            ("Unavailable roots", "unavailable_roots"),
            ("Truncated", "truncated"),
        ):
            value = embedded_disks.get(key)
            if isinstance(value, bool):
                value = str(value).lower()
            lines.append(f"- {label}: {value if value is not None else 'not available'}")
    embedded_processes = packet.get("embedded_processes")
    if embedded_processes is not None:
        lines.extend(["", "## Embedded processes component", ""])
        for label, key in (
            ("Mode", "mode"),
            ("Status", "status"),
            ("Method", "method"),
            ("Limit", "limit"),
            ("Returned processes", "returned_count"),
            ("Total processes", "total_count"),
            ("Truncated", "truncated"),
        ):
            value = embedded_processes.get(key)
            if isinstance(value, bool):
                value = str(value).lower()
            lines.append(f"- {label}: {value if value is not None else 'not available'}")
        lines.append(
            "- Command lines, environments, memory, handles, modules, owners/users, "
            "and network connections were not collected."
        )
    services = packet["artifacts"].get("services_json")
    if services is not None:
        lines.extend(["", "## Services summary", ""])
        for label, key in (
            ("Total services", "total"),
            ("Running", "running"),
            ("Stopped", "stopped"),
            ("Unknown", "unknown"),
        ):
            value = services.get(key)
            lines.append(f"- {label}: {value if value is not None else 'not available'}")
    disks = packet["artifacts"].get("disks_json")
    if disks is not None:
        lines.extend(["", "## Disks summary", ""])
        for label, key in (
            ("Total roots", "total_roots"),
            ("Returned roots", "returned_roots"),
            ("Available roots", "available_roots"),
            ("Unavailable roots", "unavailable_roots"),
            ("Limit", "limit"),
            ("Truncated", "truncated"),
        ):
            value = disks.get(key)
            if isinstance(value, bool):
                value = str(value).lower()
            lines.append(f"- {label}: {value if value is not None else 'not available'}")
        disk_safety = disks.get("disk_safety")
        if isinstance(disk_safety, dict):
            for label, key in (
                ("Directory scan performed", "directory_scan_performed"),
                ("File scan performed", "file_scan_performed"),
                ("Disk mutation performed", "disk_mutation_performed"),
            ):
                value = disk_safety.get(key)
                if isinstance(value, bool):
                    value = str(value).lower()
                lines.append(f"- {label}: {value if value is not None else 'not available'}")
        lines.append(
            "- Unavailable roots are accepted only when sanitized as safe disk usage "
            "failures (for example `disk_usage_failed`), never tracebacks."
        )
    processes = packet["windows"].get("processes")
    if processes is not None:
        lines.extend(["", "## Processes summary", ""])
        for label, key in (
            ("Method", "method"),
            ("Total processes", "total_count"),
            ("Returned processes", "returned_count"),
            ("Limit", "limit"),
            ("Truncated", "truncated"),
        ):
            value = processes.get(key)
            if isinstance(value, bool):
                value = str(value).lower()
            lines.append(f"- {label}: {value if value is not None else 'not available'}")
        lines.append(
            "- Command lines, environments, memory, handles, modules, owners/users, "
            "and network connections were not collected."
        )
    lines.extend(
        [
            "",
            "## Safety summary",
            "",
            (
                "This helper validated saved artifacts only and did not run "
                "ShellForgeAI commands or contact Windows hosts."
            ),
        ]
    )
    for key, value in packet["safety"].items():
        lines.append(f"- {key}: {str(value).lower()}")
    if packet.get("failed_checks"):
        lines.extend(["", "## Failed validation checks", ""])
        for check in packet["failed_checks"]:
            lines.append(f"- {check['name']}: {check.get('reason', 'check failed')}")
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a saved Windows smoke QA evidence packet.")
    parser.add_argument("--evidence-json", required=True)
    parser.add_argument("--status-json", required=True)
    parser.add_argument("--doctor-json", required=True)
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
    parser.add_argument("--expected-host")
    parser.add_argument("--expected-python")
    parser.add_argument("--commit")
    parser.add_argument("--pr", type=int)
    parser.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    parser.add_argument("--markdown", action="store_true", help="Emit Markdown to stdout.")
    parser.add_argument("--out-json", help="Optional explicit JSON output path.")
    parser.add_argument("--out-markdown", help="Optional explicit Markdown output path.")
    args = parser.parse_args(argv)
    if not (args.json or args.markdown or args.out_json or args.out_markdown):
        parser.error(
            "select at least one output mode: --json, --markdown, --out-json, or --out-markdown"
        )
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    packet = build_packet(args)
    json_text = json.dumps(packet, indent=2, sort_keys=True) + "\n"
    markdown_text = render_markdown(packet)
    if args.out_json:
        Path(args.out_json).write_text(json_text, encoding="utf-8")
    if args.out_markdown:
        Path(args.out_markdown).write_text(markdown_text, encoding="utf-8")
    if args.json:
        print(json_text, end="")
    if args.markdown:
        print(markdown_text, end="")
    return 0 if packet["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
