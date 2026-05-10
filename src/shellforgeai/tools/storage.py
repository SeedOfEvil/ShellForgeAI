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
        if len(p) >= 4 and p[1] == "/":
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
    return ToolResult(tool="storage.pressure", stdout=psi.read_text(errors="ignore").strip())


def error_summary() -> ToolResult:
    patterns = ["i/o error", "buffer i/o error", "ext4-fs error", "xfs", "btrfs", "nvme timeout"]
    for path in ["/var/log/kern.log", "/var/log/syslog", "/var/log/messages"]:
        r = search_errors(path, patterns=patterns, max_matches=40)
        if r.ok and r.stdout.strip():
            return ToolResult(tool="storage.error_summary", stdout=r.stdout)
    d = run_command(["dmesg"], timeout=4)
    if d.exit_code == 0:
        lines = [
            ln for ln in d.stdout.splitlines()[-800:] if any(p in ln.lower() for p in patterns)
        ][:40]
        if lines:
            return ToolResult(tool="storage.error_summary", stdout="\n".join(lines))
    return ToolResult(tool="storage.error_summary", stdout="no recent storage error patterns found")


def mounts() -> ToolResult:
    p = Path("/proc/mounts")
    if not p.exists():
        return ToolResult(tool="storage.mounts", ok=False, exit_code=1, stderr="unavailable")
    rows = p.read_text(errors="ignore").splitlines()[:512]
    ro_count = 0
    tmpfs = 0
    root_fs = "unknown"
    root_rw = "unknown"
    overlay = False
    for ln in rows:
        parts = ln.split()
        if len(parts) < 4:
            continue
        opts = parts[3].split(",")
        ro_count += int("ro" in opts)
        tmpfs += int(parts[2] == "tmpfs")
        if parts[1] == "/":
            root_fs = parts[2]
            root_rw = "ro" not in opts
            overlay = parts[2] == "overlay"
    rw = "yes" if root_rw is True else "no" if root_rw is False else "unknown"
    summary = (
        f"root={root_fs} rw={rw} mounts={len(rows)} tmpfs={tmpfs} "
        f"overlay={'yes' if overlay else 'no'} ro_mounts={ro_count}"
    )
    return ToolResult(tool="storage.mounts", stdout="\n".join(rows), stderr=summary, ok=True)


def mount_target(path: str) -> ToolResult:
    r = run_command(["findmnt", "-T", path, "-o", "TARGET,SOURCE,FSTYPE,OPTIONS", "-n"])
    if r.exit_code != 0:
        return ToolResult(
            tool="storage.mount_target",
            ok=False,
            exit_code=r.exit_code,
            stderr="mount target unavailable",
        )
    return ToolResult(
        tool="storage.mount_target", command=r.command, stdout=r.stdout.strip(), ok=True
    )
