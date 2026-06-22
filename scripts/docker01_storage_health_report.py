#!/usr/bin/env python3
"""Read-only Docker01 storage/filesystem health evidence report helper.

PR230: collect bounded, read-only evidence about Docker01 storage health after
PR229 observed a slow Docker build chown layer and pre-existing EXT4/dm-10
kernel warnings on Docker01. This helper is evidence-only. It never repairs
filesystems, runs fsck/e2fsck/xfs_repair, mounts/remounts, prunes Docker,
removes images, deletes files, restarts containers, or mutates Docker/Compose.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import socket
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MODE = "docker01_storage_health_report"
SCHEMA_VERSION = 1
DEFAULT_TIMEOUT = 15
DEFAULT_MAX_DMESG_LINES = 200
DEFAULT_MAX_WARNING_LINES = 50
LINE_LIMIT = 300
DEFAULT_DOCKER_DATA_PATH = "/var/lib/docker"
PROC_MOUNTS = Path("/proc/mounts")
DISK_PRESSURE_WARNING = 80
DISK_PRESSURE_CRITICAL = 90

REQUIRED_OUT_FILES = (
    "storage-health-report.json",
    "storage-health-summary.md",
    "commands-run.json",
    "manifest.json",
    "checksums.json",
)

FIRST_SAFE_COMMAND = "python scripts/docker01_storage_health_report.py --json"


# Read-only command allowlist. Every entry uses shell=False with a fixed argv.
@dataclass(frozen=True)
class CommandSpec:
    key: str
    argv: tuple[str, ...]
    timeout: int = DEFAULT_TIMEOUT


@dataclass
class CommandResult:
    key: str
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    available: bool
    reason: str = ""


# Fixed read-only command forms. df/findmnt/dmesg are exact; journalctl allows a
# bounded numeric -n value validated separately.
ALLOWED_COMMAND_FORMS = {
    ("df", "-P", "-B1"),
    ("findmnt", "--json"),
    ("dmesg", "--level=err,warn", "--ctime"),
}
ALLOWED_EXECUTABLES = {"df", "findmnt", "dmesg", "journalctl"}

# Forbidden command/token families. Used only to reject unsafe argv if one is
# ever passed; this helper never builds these.
FORBIDDEN_TOKENS = {
    "fsck",
    "e2fsck",
    "xfs_repair",
    "mount",
    "umount",
    "remount",
    "rm",
    "unlink",
    "shred",
    "truncate",
    "prune",
    "rmi",
    "restart",
    "systemctl",
    "apt",
    "apt-get",
    "pip",
    "pip3",
    "curl",
    "wget",
    "gh",
    "codex",
    "sh",
    "bash",
}

# Kernel/storage warning patterns. Each line is scored against every pattern so
# a single line (for example "EXT4-fs error (device dm-10)") can count toward
# more than one family.
KERNEL_WARNING_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("EXT4", re.compile(r"ext4", re.I)),
    ("dm-", re.compile(r"\bdm-\d+\b|device-mapper", re.I)),
    ("I/O error", re.compile(r"i/o error|buffer i/o", re.I)),
    ("journal", re.compile(r"journal", re.I)),
    ("inode", re.compile(r"inode", re.I)),
)


def safety_block() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
        "docker_prune_executed": False,
        "docker_image_removed": False,
        "file_deleted": False,
        "filesystem_repair_executed": False,
        "fsck_executed": False,
        "mount_modified": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "recovery_executed": False,
        "natural_language_execution": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "cloud_apply_merge_push": False,
        "github_post_approve_merge": False,
    }


def journalctl_spec(max_lines: int) -> CommandSpec:
    bounded = max(1, min(int(max_lines), 5000))
    return CommandSpec(
        "journalctl_kernel",
        ("journalctl", "-k", "-p", "warning..alert", "--no-pager", "-n", str(bounded)),
    )


def command_specs(max_dmesg_lines: int) -> list[CommandSpec]:
    return [
        CommandSpec("df", ("df", "-P", "-B1")),
        CommandSpec("findmnt", ("findmnt", "--json")),
        CommandSpec("dmesg", ("dmesg", "--level=err,warn", "--ctime")),
        journalctl_spec(max_dmesg_lines),
    ]


def is_allowlisted_command(argv: tuple[str, ...] | list[str]) -> bool:
    argv = tuple(argv)
    if argv in ALLOWED_COMMAND_FORMS:
        return True
    return (
        len(argv) == 7
        and argv[:6] == ("journalctl", "-k", "-p", "warning..alert", "--no-pager", "-n")
        and argv[6].isdigit()
    )


def command_is_forbidden(argv: tuple[str, ...] | list[str]) -> bool:
    return any(part in FORBIDDEN_TOKENS for part in argv)


def run_allowed_command(spec: CommandSpec) -> CommandResult:
    if not is_allowlisted_command(spec.argv):
        raise ValueError(f"command is not allowlisted: {spec.argv!r}")
    try:
        completed = subprocess.run(  # noqa: S603 fixed allowlist, shell=False
            list(spec.argv),
            check=False,
            capture_output=True,
            text=True,
            timeout=spec.timeout,
            shell=False,
        )
    except FileNotFoundError as exc:
        return CommandResult(
            spec.key, list(spec.argv), None, "", str(exc), False, "command unavailable"
        )
    except PermissionError as exc:
        return CommandResult(
            spec.key, list(spec.argv), None, "", str(exc), False, "permission denied"
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            spec.key, list(spec.argv), None, exc.stdout or "", exc.stderr or "", False, "timeout"
        )
    available = completed.returncode == 0
    reason = ""
    if not available:
        stderr_lower = (completed.stderr or "").lower()
        if "permission" in stderr_lower or "not permitted" in stderr_lower:
            reason = "permission denied"
        else:
            reason = "command failed"
    return CommandResult(
        spec.key,
        list(spec.argv),
        completed.returncode,
        completed.stdout,
        completed.stderr,
        available,
        reason,
    )


def _sanitize_line(line: str) -> str:
    cleaned = "".join(ch if ch.isprintable() else " " for ch in line).strip()
    return cleaned[:LINE_LIMIT]


def read_proc_mounts(path: Path = PROC_MOUNTS) -> dict[str, dict[str, str]]:
    """Map mount point -> {source, fstype} from /proc/mounts (read-only)."""
    mapping: dict[str, dict[str, str]] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return mapping
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) >= 3:
            source, mount, fstype = parts[0], parts[1], parts[2]
            mapping.setdefault(mount, {"source": source, "fstype": fstype})
    return mapping


def parse_df_bytes(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    lines = [line for line in text.splitlines() if line.strip()]
    for raw in lines[1:]:
        parts = raw.split()
        if len(parts) < 6:
            continue
        try:
            total = int(parts[1])
            used = int(parts[2])
            free = int(parts[3])
        except ValueError:
            continue
        percent = parts[4].rstrip("%")
        try:
            used_percent = int(percent)
        except ValueError:
            used_percent = round(used / total * 100) if total else 0
        rows.append(
            {
                "mount": parts[5],
                "source": parts[0],
                "total_bytes": total,
                "used_bytes": used,
                "free_bytes": free,
                "used_percent": used_percent,
            }
        )
    return rows


def build_filesystems(df_text: str, mounts: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    filesystems: list[dict[str, Any]] = []
    rows = parse_df_bytes(df_text) if df_text else []
    if rows:
        for row in rows:
            mount_meta = mounts.get(row["mount"], {})
            filesystems.append(
                {
                    "mount": row["mount"],
                    "source": row["source"] or mount_meta.get("source", "unknown"),
                    "fstype": mount_meta.get("fstype", "unknown"),
                    "total_bytes": row["total_bytes"],
                    "used_bytes": row["used_bytes"],
                    "free_bytes": row["free_bytes"],
                    "used_percent": row["used_percent"],
                }
            )
        return filesystems
    # Fallback: /proc/mounts gives mapping but no sizes.
    for mount, meta in mounts.items():
        filesystems.append(
            {
                "mount": mount,
                "source": meta.get("source", "unknown"),
                "fstype": meta.get("fstype", "unknown"),
                "total_bytes": 0,
                "used_bytes": 0,
                "free_bytes": 0,
                "used_percent": 0,
            }
        )
    return filesystems


def _severity_for_line(line: str) -> str:
    lower = line.lower()
    if "i/o error" in lower or "error" in lower:
        return "error"
    if "warn" in lower:
        return "warning"
    return "unknown"


def scan_kernel_warnings(
    text: str, source: str, max_lines: int, max_warning_lines: int
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    warnings: list[dict[str, Any]] = []
    counts = {"EXT4": 0, "dm-": 0, "I/O error": 0, "journal": 0, "inode": 0, "total_lines": 0}
    lines = text.splitlines()[:max_lines]
    for raw in lines:
        matched = [label for label, pattern in KERNEL_WARNING_PATTERNS if pattern.search(raw)]
        if not matched:
            continue
        counts["total_lines"] += 1
        for label in matched:
            counts[label] += 1
        if len(warnings) < max_warning_lines:
            warnings.append(
                {
                    "source": source,
                    "severity": _severity_for_line(raw),
                    "matched_pattern": matched[0],
                    "line": _sanitize_line(raw),
                }
            )
    return warnings, counts


def collect_kernel_warnings(
    results: dict[str, CommandResult], max_lines: int, max_warning_lines: int
) -> tuple[list[dict[str, Any]], dict[str, int], str, list[str]]:
    warnings_out: list[str] = []
    dmesg = results.get("dmesg")
    journal = results.get("journalctl_kernel")
    if dmesg and dmesg.available and dmesg.stdout.strip():
        entries, counts = scan_kernel_warnings(dmesg.stdout, "dmesg", max_lines, max_warning_lines)
        return entries, counts, "dmesg", warnings_out
    if journal and journal.available and journal.stdout.strip():
        entries, counts = scan_kernel_warnings(
            journal.stdout, "journalctl", max_lines, max_warning_lines
        )
        return entries, counts, "journalctl", warnings_out
    # Neither source produced readable output.
    reason = "kernel warning evidence unavailable"
    if dmesg and dmesg.reason:
        reason = f"dmesg {dmesg.reason}"
    elif journal and journal.reason:
        reason = f"journalctl {journal.reason}"
    warnings_out.append(reason)
    empty = {"EXT4": 0, "dm-": 0, "I/O error": 0, "journal": 0, "inode": 0, "total_lines": 0}
    return [], empty, "not_available", warnings_out


def disk_pressure_level(used_percent: int | None) -> str:
    if used_percent is None:
        return "unknown"
    if used_percent >= DISK_PRESSURE_CRITICAL:
        return "critical"
    if used_percent >= DISK_PRESSURE_WARNING:
        return "warning"
    return "ok"


def collect_root_usage(disk_usage_fn: Callable[[str], Any]) -> dict[str, Any] | None:
    try:
        usage = disk_usage_fn("/")
    except OSError:
        return None
    total = int(usage.total)
    free = int(usage.free)
    used = int(usage.used)
    used_percent = round(used / total * 100) if total else 0
    return {
        "total_bytes": total,
        "used_bytes": used,
        "free_bytes": free,
        "used_percent": used_percent,
    }


def collect_docker_data(
    disk_usage_fn: Callable[[str], Any], path: str = DEFAULT_DOCKER_DATA_PATH
) -> dict[str, Any]:
    target = Path(path)
    if not target.exists():
        return {"docker_data_path": path, "docker_data_used_percent": "unknown", "available": False}
    try:
        usage = disk_usage_fn(path)
    except OSError:
        return {"docker_data_path": path, "docker_data_used_percent": "unknown", "available": False}
    total = int(usage.total)
    used = int(usage.used)
    used_percent = round(used / total * 100) if total else 0
    return {
        "docker_data_path": path,
        "docker_data_used_percent": used_percent,
        "available": True,
    }


def _hostname() -> str:
    try:
        name = socket.gethostname().strip()
    except OSError:
        return "unknown"
    return name or "unknown"


def build_report(
    *,
    runner: Callable[[CommandSpec], CommandResult] | None = None,
    disk_usage_fn: Callable[[str], Any] | None = None,
    proc_mounts: Path = PROC_MOUNTS,
    docker_data_path: str = DEFAULT_DOCKER_DATA_PATH,
    max_dmesg_lines: int = DEFAULT_MAX_DMESG_LINES,
    max_warning_lines: int = DEFAULT_MAX_WARNING_LINES,
    report_path: Path | None = None,
) -> tuple[dict[str, Any], list[CommandResult]]:
    # Resolve defaults at call time so callers/tests can monkeypatch the module.
    runner = runner or run_allowed_command
    disk_usage_fn = disk_usage_fn or shutil.disk_usage
    warnings: list[str] = []
    errors: list[str] = []

    specs = command_specs(max_dmesg_lines)
    results = [runner(spec) for spec in specs]
    by_key = {r.key: r for r in results}

    root = collect_root_usage(disk_usage_fn)
    mounts = read_proc_mounts(proc_mounts)
    df_result = by_key.get("df")
    df_text = df_result.stdout if df_result and df_result.available else ""
    filesystems = build_filesystems(df_text, mounts)

    kernel_warnings, counts, source, kw_warnings = collect_kernel_warnings(
        by_key, max_dmesg_lines, max_warning_lines
    )
    warnings.extend(kw_warnings)
    kernel_evidence_unavailable = source == "not_available"

    docker_data = collect_docker_data(disk_usage_fn, docker_data_path)

    checks: list[dict[str, Any]] = []

    if root is None:
        errors.append("core root filesystem usage could not be collected")
        pressure = "unknown"
        root_summary = {
            "root_total_bytes": 0,
            "root_used_bytes": 0,
            "root_free_bytes": 0,
            "root_used_percent": 0,
        }
        checks.append(
            {
                "name": "root_disk_pressure",
                "status": "failed",
                "detail": "shutil.disk_usage('/') failed",
            }
        )
    else:
        pressure = disk_pressure_level(root["used_percent"])
        root_summary = {
            "root_total_bytes": root["total_bytes"],
            "root_used_bytes": root["used_bytes"],
            "root_free_bytes": root["free_bytes"],
            "root_used_percent": root["used_percent"],
        }
        pressure_status = {
            "ok": "passed",
            "warning": "warning",
            "critical": "failed",
            "unknown": "unknown",
        }[pressure]
        checks.append(
            {
                "name": "root_disk_pressure",
                "status": pressure_status,
                "detail": f"root used {root['used_percent']}% -> {pressure}",
            }
        )

    total_kernel = counts["total_lines"]
    if kernel_evidence_unavailable:
        checks.append(
            {
                "name": "kernel_storage_warnings",
                "status": "unknown",
                "detail": "dmesg/journalctl kernel evidence unavailable",
            }
        )
    else:
        checks.append(
            {
                "name": "kernel_storage_warnings",
                "status": "warning" if total_kernel else "passed",
                "detail": f"{total_kernel} storage warning line(s) from {source}",
            }
        )
    checks.append(
        {
            "name": "ext4_warning_patterns",
            "status": "warning" if counts["EXT4"] else "passed",
            "detail": f"{counts['EXT4']} EXT4 pattern line(s)",
        }
    )
    checks.append(
        {
            "name": "dm_warning_patterns",
            "status": "warning" if counts["dm-"] else "passed",
            "detail": f"{counts['dm-']} dm/device-mapper pattern line(s)",
        }
    )
    io_journal_inode = counts["I/O error"] + counts["journal"] + counts["inode"]
    checks.append(
        {
            "name": "io_journal_inode_patterns",
            "status": "warning" if io_journal_inode else "passed",
            "detail": (
                f"I/O={counts['I/O error']} journal={counts['journal']} inode={counts['inode']}"
            ),
        }
    )
    checks.append(
        {
            "name": "mount_metadata",
            "status": "passed" if filesystems else "unknown",
            "detail": f"{len(filesystems)} filesystem(s) observed",
        }
    )
    checks.append(
        {
            "name": "docker_data_path",
            "status": "passed" if docker_data["available"] else "unknown",
            "detail": (
                f"{docker_data['docker_data_path']} used {docker_data['docker_data_used_percent']}"
            ),
        }
    )

    found_warning_signal = (
        pressure in {"warning", "critical"} or total_kernel > 0 if root is not None else False
    )

    if errors:
        status = "failed"
    elif found_warning_signal:
        status = "warning"
    elif kernel_evidence_unavailable:
        status = "partial"
    else:
        status = "ok"

    report = {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "created_at": datetime.now(UTC).isoformat(),
        "host": _hostname(),
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            **root_summary,
            "disk_pressure_level": pressure,
            "kernel_storage_warnings_found": total_kernel,
            "ext4_warning_patterns_found": counts["EXT4"],
            "dm_warning_patterns_found": counts["dm-"],
            "docker_data_path": docker_data["docker_data_path"],
            "docker_data_used_percent": docker_data["docker_data_used_percent"],
        },
        "kernel_warning_counts": {
            "ext4": counts["EXT4"],
            "dm": counts["dm-"],
            "io_error": counts["I/O error"],
            "journal": counts["journal"],
            "inode": counts["inode"],
            "total_lines": counts["total_lines"],
        },
        "filesystems": filesystems,
        "kernel_warnings": kernel_warnings,
        "checks": checks,
        "warnings": warnings,
        "errors": errors,
        "first_safe_command": FIRST_SAFE_COMMAND,
        "safety": safety_block(),
    }
    if report_path is not None:
        report["report_path"] = str(report_path)
    return report, results


def render_summary(report: dict[str, Any]) -> str:
    s = report["summary"]
    root_pct = s["root_used_percent"]
    fs_lines = []
    for fs in report["filesystems"][:20]:
        fs_lines.append(
            f"  * {fs['mount']} ({fs['fstype']}, {fs['source']}): {fs['used_percent']}% used"
        )
    kernel_source = "not available"
    if report["kernel_warnings"]:
        kernel_source = report["kernel_warnings"][0]["source"]
    elif report["warnings"]:
        kernel_source = "not available (see warnings)"
    lines = [
        "# Docker01 Storage Health Report",
        "",
        f"Status: {report['status']}",
        f"Generated: {report['created_at']}",
        "Read-only: yes",
        "",
        "## Disk usage",
        f"* root filesystem: {root_pct}% used "
        f"({s['root_used_bytes']} / {s['root_total_bytes']} bytes)",
        f"* Docker data path: {s['docker_data_path']} (used {s['docker_data_used_percent']})",
        f"* disk pressure: {s['disk_pressure_level']}",
    ]
    if fs_lines:
        lines.append("* filesystems:")
        lines.extend(fs_lines)
    lines.extend(
        [
            "",
            "## Kernel/storage warnings",
            f"* EXT4 patterns: {s['ext4_warning_patterns_found']}",
            f"* dm/device-mapper patterns: {s['dm_warning_patterns_found']}",
            f"* I/O/journal/inode patterns: {_io_count(report)}",
            f"* total storage warning lines: {s['kernel_storage_warnings_found']}",
            f"* evidence source: {kernel_source}",
            "",
            "## Notes",
            "* no repair performed",
            "* no cleanup performed",
            "* no Docker prune/image removal",
            "* no restart/remediation/rollback/recovery",
            "",
            "## Safe next",
            "* review this report",
            "* if host storage warnings persist, investigate outside ShellForgeAI mutation lanes",
            "",
        ]
    )
    return "\n".join(lines)


def _io_count(report: dict[str, Any]) -> int:
    counts = report.get("kernel_warning_counts", {})
    return counts.get("io_error", 0) + counts.get("journal", 0) + counts.get("inode", 0)


def _commands_run_records(results: list[CommandResult]) -> list[dict[str, Any]]:
    """Bounded read-only command log: argv/returncode/availability only.

    Raw stdout/stderr logs are intentionally not copied in full.
    """
    records = []
    for r in results:
        records.append(
            {
                "key": r.key,
                "argv": r.argv,
                "read_only": True,
                "returncode": r.returncode,
                "available": r.available,
                "reason": r.reason,
                "stdout_lines": len(r.stdout.splitlines()) if r.stdout else 0,
            }
        )
    return records


def _sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_output_dir(
    out: Path, report: dict[str, Any], results: list[CommandResult]
) -> dict[str, Any]:
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report = {**report, "report_path": str(out)}
    write_text(
        out / "storage-health-report.json", json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    write_text(out / "storage-health-summary.md", render_summary(report))
    write_text(
        out / "commands-run.json",
        json.dumps(_commands_run_records(results), indent=2, sort_keys=True) + "\n",
    )

    artifact_names = [
        "storage-health-report.json",
        "storage-health-summary.md",
        "commands-run.json",
    ]
    artifacts = [
        {
            "path": name,
            "sha256": _sha256_file(out / name),
            "size_bytes": (out / name).stat().st_size,
        }
        for name in artifact_names
    ]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "created_at": report["created_at"],
        "artifacts": artifacts,
    }
    write_text(out / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    artifacts_with_manifest = artifacts + [
        {
            "path": "manifest.json",
            "sha256": _sha256_file(out / "manifest.json"),
            "size_bytes": (out / "manifest.json").stat().st_size,
        }
    ]
    checksums = {a["path"]: a["sha256"] for a in artifacts_with_manifest}
    write_text(out / "checksums.json", json.dumps(checksums, indent=2, sort_keys=True) + "\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only Docker01 storage/filesystem health evidence report."
    )
    parser.add_argument("--json", action="store_true", help="print strict JSON result")
    parser.add_argument("--out", type=Path, default=None, help="report output directory")
    parser.add_argument(
        "--max-dmesg-lines",
        type=int,
        default=DEFAULT_MAX_DMESG_LINES,
        help="maximum kernel log lines to scan",
    )
    parser.add_argument(
        "--max-warning-lines",
        type=int,
        default=DEFAULT_MAX_WARNING_LINES,
        help="maximum matched warning lines to record",
    )
    args = parser.parse_args(argv)

    try:
        report, results = build_report(
            max_dmesg_lines=args.max_dmesg_lines,
            max_warning_lines=args.max_warning_lines,
            report_path=args.out,
        )
        if args.out is not None:
            report = write_output_dir(args.out, report, results)
    except Exception as exc:  # noqa: BLE001 — fail closed with strict JSON, never crash mid-write
        payload = {
            "schema_version": SCHEMA_VERSION,
            "mode": MODE,
            "status": "failed",
            "read_only": True,
            "mutation_performed": False,
            "error": str(exc),
            "safety": safety_block(),
        }
        print(
            json.dumps(payload, indent=2, sort_keys=True)
            if args.json
            else f"failed to create storage health report: {exc}"
        )
        return 1

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_summary(report))
        if args.out is not None:
            print(f"\nReport directory: {args.out}")
    return 0 if report["status"] != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
