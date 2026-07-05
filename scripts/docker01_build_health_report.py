#!/usr/bin/env python3
"""Read-only Docker01 build-lane health report helper.

Reports local host, filesystem, process, Docker CLI availability, and known
Dockerfile ownership-layer risk indicators before Docker01 PR lanes. The helper
is diagnostic-only: it never performs image construction, pruning, killing, restarts, cleanup,
remediation, rollback, recovery, package installation, or Docker/Compose mutation,
services, filesystems, snapshots, containers, images, volumes, or processes.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MODE = "docker01_build_health_report"
BROAD_CHOWN_PATTERN = "chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai"
DEFAULT_DOCKER_ROOT = Path("/var/lib/docker")
DEFAULT_WORKSPACE = Path("/srv/data/shellforgeai/src")
DEFAULT_DOCKERFILE = Path("Dockerfile")
DISK_ATTENTION_PERCENT = 85.0
DISK_BLOCKED_PERCENT = 95.0
COMMAND_TIMEOUT_SECONDS = 5
BUILD_TOKENS = ("build", "buildkit", "buildx", "dockerfile", "chown", "pip")


@dataclass(frozen=True)
class CommandSpec:
    key: str
    argv: tuple[str, ...]
    timeout: int = COMMAND_TIMEOUT_SECONDS


ALLOWED_DOCKER_COMMANDS = (
    CommandSpec("docker_info", ("docker", "info", "--format", "{{json .}}")),
    CommandSpec("docker_system_df", ("docker", "system", "df", "--format", "json")),
    CommandSpec("docker_ps", ("docker", "ps", "--format", "json")),
    CommandSpec("docker_buildx_ls", ("docker", "buildx", "ls")),
)
FORBIDDEN_COMMAND_TOKENS = {
    "build",
    "compose",
    "up",
    "down",
    "restart",
    "prune",
    "rm",
    "rmi",
    "kill",
    "stop",
    "start",
    "volume",
    "exec",
}


def safety_block() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "docker_build_executed": False,
        "docker_prune_executed": False,
        "docker_compose_mutation_executed": False,
        "container_kill_executed": False,
        "process_kill_executed": False,
        "service_restart_executed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "recovery_executed": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
    }


def disk_entry(path: Path, usage_fn: Callable[[Path], shutil._ntuple_diskusage]) -> dict[str, Any]:
    available = path.exists()
    target = path if available else path.parent if path.parent.exists() else Path("/")
    try:
        usage = usage_fn(target)
        used = usage.total - usage.free
        used_percent = round((used / usage.total) * 100, 2) if usage.total else 0.0
        return {
            "path": str(path),
            "available": available,
            "total_bytes": int(usage.total),
            "used_bytes": int(used),
            "free_bytes": int(usage.free),
            "used_percent": used_percent,
        }
    except OSError:
        return {
            "path": str(path),
            "available": False,
            "total_bytes": 0,
            "used_bytes": 0,
            "free_bytes": 0,
            "used_percent": 0.0,
        }


def root_disk_entry(usage_fn: Callable[[Path], shutil._ntuple_diskusage]) -> dict[str, Any]:
    item = disk_entry(Path("/"), usage_fn)
    item.pop("available", None)
    return item


def scan_dockerfile(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "available": False,
            "detected": False,
            "path": str(path),
            "reason": "dockerfile_not_found",
        }
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"available": False, "detected": False, "path": str(path), "reason": str(exc)}
    return {"available": True, "detected": BROAD_CHOWN_PATTERN in text, "path": str(path)}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def scan_processes(proc_root: Path = Path("/proc")) -> dict[str, Any]:
    build_related: list[dict[str, Any]] = []
    possible_stuck_io: list[dict[str, Any]] = []
    if not proc_root.exists():
        return {"build_related": [], "possible_stuck_io": [], "count": 0}
    for child in sorted(proc_root.iterdir(), key=lambda p: p.name):
        if not child.name.isdigit():
            continue
        status = _read_text(child / "status")
        comm = _read_text(child / "comm").strip()
        cmdline = _read_text(child / "cmdline").replace("\x00", " ").strip()
        haystack = f"{comm} {cmdline}".lower()
        if not any(token in haystack for token in BUILD_TOKENS):
            continue
        state = ""
        for line in status.splitlines():
            if line.startswith("State:"):
                state = line.split(":", 1)[1].strip()
                break
        item = {"pid": int(child.name), "name": comm, "state": state, "cmdline": cmdline[:240]}
        build_related.append(item)
        if state.startswith("D"):
            possible_stuck_io.append(item)
    return {
        "build_related": build_related,
        "possible_stuck_io": possible_stuck_io,
        "count": len(build_related),
    }


def run_read_only_docker_commands(timeout: int = COMMAND_TIMEOUT_SECONDS) -> dict[str, Any]:
    results = []
    docker_available = shutil.which("docker") is not None
    info_available = False
    df_available = False
    indicators: list[str] = []
    for spec in ALLOWED_DOCKER_COMMANDS:
        assert not any(part in FORBIDDEN_COMMAND_TOKENS for part in spec.argv[1:]), spec.argv
        try:
            completed = subprocess.run(  # noqa: S603 fixed allowlist, shell=False
                list(spec.argv),
                check=False,
                capture_output=True,
                text=True,
                timeout=min(timeout, spec.timeout),
                shell=False,
            )
            ok = completed.returncode == 0
            reason = "" if ok else "command_failed"
            stdout = (completed.stdout or "")[:2000]
            stderr = (completed.stderr or "")[:1000]
        except FileNotFoundError as exc:
            ok = False
            reason = "command_unavailable"
            stdout = ""
            stderr = str(exc)
        except subprocess.TimeoutExpired as exc:
            ok = False
            reason = "timeout"
            stdout = (exc.stdout or "")[:2000]
            stderr = (exc.stderr or "")[:1000]
        results.append(
            {
                "key": spec.key,
                "argv": list(spec.argv),
                "available": ok,
                "reason": reason,
                "stdout": stdout,
                "stderr": stderr,
            }
        )
        if spec.key == "docker_info":
            info_available = ok
        if spec.key == "docker_system_df":
            df_available = ok
        if not ok:
            indicators.append(f"{spec.key}:{reason}")
    return {
        "docker_available": docker_available,
        "docker_info_available": info_available,
        "system_df_available": df_available,
        "buildkit_indicators": indicators,
        "read_only_commands": results,
    }


def determine_readiness(report: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    status = "ok"
    for key in ("root", "docker_root", "workspace"):
        entry = report["filesystem"][key]
        if entry.get("used_percent", 0.0) >= DISK_BLOCKED_PERCENT:
            status = "blocked"
            reasons.append(f"{key}_disk_used_percent_blocked")
        elif entry.get("used_percent", 0.0) >= DISK_ATTENTION_PERCENT and status != "blocked":
            status = "attention"
            reasons.append(f"{key}_disk_used_percent_high")
    if report["processes"]["possible_stuck_io"]:
        status = "blocked"
        reasons.append("build_related_process_in_d_state")
    elif report["processes"]["build_related"] and status == "ok":
        status = "attention"
        reasons.append("build_related_process_present")
    if report["known_risks"]["broad_recursive_ownership_layer"]["detected"] and status == "ok":
        status = "attention"
        reasons.append("known_broad_recursive_ownership_layer_present")
    if not report["known_risks"]["dockerfile"]["available"] and status == "ok":
        status = "unknown"
        reasons.append("source_dockerfile_unknown")
    if not report["docker"]["docker_available"] and status == "ok":
        status = "unknown"
        reasons.append("docker_cli_unavailable")
    return {
        "status": status,
        "reasons": reasons,
        "recommended_next_safe_command": "python scripts/sfai_docker01_pr_lane.py --help",
    }


def build_report(
    docker_root: Path = DEFAULT_DOCKER_ROOT,
    workspace: Path = DEFAULT_WORKSPACE,
    dockerfile: Path = DEFAULT_DOCKERFILE,
    proc_root: Path = Path("/proc"),
    usage_fn: Callable[[Path], shutil._ntuple_diskusage] = shutil.disk_usage,
    include_docker_cli: bool = True,
) -> dict[str, Any]:
    dockerfile_scan = scan_dockerfile(dockerfile)
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": "ok",
        "read_only": True,
        "mutation_performed": False,
        "host": {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "cwd": os.getcwd(),
        },
        "filesystem": {
            "root": root_disk_entry(usage_fn),
            "docker_root": disk_entry(docker_root, usage_fn),
            "workspace": disk_entry(workspace, usage_fn),
        },
        "processes": scan_processes(proc_root),
        "docker": run_read_only_docker_commands()
        if include_docker_cli
        else {
            "docker_available": False,
            "docker_info_available": False,
            "system_df_available": False,
            "buildkit_indicators": ["docker_cli_checks_disabled"],
            "read_only_commands": [],
        },
        "known_risks": {
            "broad_recursive_ownership_layer": {
                "detected": bool(dockerfile_scan["detected"]),
                "pattern": BROAD_CHOWN_PATTERN,
            },
            "docker01_io_pressure": {"detected": False},
            "dockerfile": dockerfile_scan,
        },
        "readiness": {},
        "safety": safety_block(),
    }
    report["known_risks"]["docker01_io_pressure"]["detected"] = bool(
        report["processes"]["possible_stuck_io"]
        or any(
            report["filesystem"][k].get("used_percent", 0) >= DISK_ATTENTION_PERCENT
            for k in ("root", "docker_root", "workspace")
        )
    )
    report["readiness"] = determine_readiness(report)
    report["status"] = report["readiness"]["status"]
    return report


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Docker01 build lane health report",
        "",
        f"- Schema version: {report['schema_version']}",
        f"- Mode: `{report['mode']}`",
        f"- Readiness status: `{report['readiness']['status']}`",
        f"- Read-only: `{str(report['read_only']).lower()}`",
        f"- Mutation performed: `{str(report['mutation_performed']).lower()}`",
        "",
        "## Readiness reasons",
    ]
    reasons = report["readiness"].get("reasons") or ["none"]
    lines.extend(f"- {reason}" for reason in reasons)
    lines.extend(["", "## Filesystem"])
    for name, entry in report["filesystem"].items():
        used = entry["used_percent"]
        free = entry["free_bytes"]
        lines.append(f"- {name}: path `{entry['path']}`, used {used}%, free {free} bytes")
    stuck_count = len(report["processes"]["possible_stuck_io"])
    broad_chown = str(report["known_risks"]["broad_recursive_ownership_layer"]["detected"]).lower()
    io_pressure = str(report["known_risks"]["docker01_io_pressure"]["detected"]).lower()
    docker_df = str(report["docker"]["system_df_available"]).lower()
    lines.extend(
        [
            "",
            "## Processes",
            f"- Build-related process count: {report['processes']['count']}",
            f"- Possible D-state/uninterruptible I/O count: {stuck_count}",
            "",
            "## Known risks",
            f"- Broad recursive ownership layer detected: `{broad_chown}`",
            f"- Docker01 I/O pressure detected: `{io_pressure}`",
            "",
            "## Docker CLI read-only checks",
            f"- Docker available: `{str(report['docker']['docker_available']).lower()}`",
            f"- docker info available: `{str(report['docker']['docker_info_available']).lower()}`",
            f"- docker system df available: `{docker_df}`",
            "",
            "## Safety",
            "- Diagnostic/report helper only; no cleanup, prune, kill, restart, image "
            "construction, repair, remediation, rollback, recovery, shell=True, or "
            "arbitrary command execution.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print deterministic JSON report")
    parser.add_argument(
        "--markdown", action="store_true", help="print deterministic Markdown report"
    )
    parser.add_argument("--out-json", type=Path, help="write deterministic JSON report")
    parser.add_argument("--out-markdown", type=Path, help="write deterministic Markdown report")
    args = parser.parse_args(argv)
    if not (args.json or args.markdown or args.out_json or args.out_markdown):
        parser.error("choose --json, --markdown, --out-json, or --out-markdown")
    report = build_report()
    json_text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    markdown_text = render_markdown(report)
    if args.out_json:
        args.out_json.write_text(json_text, encoding="utf-8")
    if args.out_markdown:
        args.out_markdown.write_text(markdown_text, encoding="utf-8")
    if args.json:
        print(json_text, end="")
    if args.markdown:
        print(markdown_text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
