from __future__ import annotations

from pathlib import Path

from shellforgeai.util.subprocess import run_command

from .base import ToolResult
from .logs import search_errors


def context() -> ToolResult:
    mounts = Path("/proc/mounts")
    if not mounts.exists():
        return ToolResult(tool="storage.context", ok=False, exit_code=1, stderr="unavailable")
    rows = mounts.read_text(errors="ignore").splitlines()[:256]
    root_fs = "unknown"
    root_rw = "unknown"
    overlay = False
    for ln in rows:
        p = ln.split()
        if len(p) < 4:
            continue
        if p[1] == "/":
            root_fs = p[2]
            root_rw = "ro" not in p[3].split(",")
            overlay = p[2] == "overlay"
            break
    rw = "yes" if root_rw is True else "no" if root_rw is False else "unknown"
    summary = f"root_fs={root_fs} root_rw={rw} mounts={len(rows)}"
    if overlay:
        summary += " overlay=yes"
    return ToolResult(tool="storage.context", stdout="\n".join(rows), stderr=summary)


def pressure() -> ToolResult:
    psi = Path("/proc/pressure/io")
    if not psi.exists():
        return ToolResult(tool="storage.pressure", ok=False, exit_code=1, stderr="unavailable")
    data = psi.read_text(errors="ignore").strip()
    return ToolResult(tool="storage.pressure", stdout=data)


def error_summary() -> ToolResult:
    patterns = [
        "i/o error",
        "buffer i/o error",
        "ext4-fs error",
        "xfs",
        "btrfs",
        "nvme timeout",
        "ata error",
        "blk_update_request",
        "read-only filesystem",
        "remount-ro",
        "corruption",
    ]
    for path in ["/var/log/kern.log", "/var/log/syslog", "/var/log/messages"]:
        r = search_errors(path, patterns=patterns, max_matches=40)
        if r.ok and r.stdout.strip():
            return ToolResult(tool="storage.error_summary", stdout=r.stdout)
    d = run_command(["dmesg"], timeout=4)
    if d.exit_code == 0:
        lines = []
        for ln in d.stdout.splitlines()[-800:]:
            low = ln.lower()
            if any(p in low for p in patterns):
                lines.append(ln)
            if len(lines) >= 40:
                break
        if lines:
            return ToolResult(tool="storage.error_summary", stdout="\n".join(lines))
    return ToolResult(tool="storage.error_summary", stdout="no recent storage error patterns found")
