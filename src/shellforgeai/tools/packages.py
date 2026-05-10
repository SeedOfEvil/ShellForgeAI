from __future__ import annotations

import json
from pathlib import Path

from shellforgeai.util.subprocess import run_command

from .base import ToolResult


def _as_tool_result(name: str, result) -> ToolResult:
    return ToolResult(
        tool=name,
        command=result.command,
        stdout=result.stdout,
        stderr=result.stderr,
        ok=result.exit_code == 0,
        exit_code=result.exit_code,
    )


def manager_detect() -> ToolResult:
    bins = ["apt", "dpkg", "dnf", "yum", "rpm", "apk", "pacman", "snap", "flatpak"]
    found = {}
    for b in bins:
        r = run_command(["sh", "-lc", f"command -v {b} >/dev/null 2>&1 && echo yes || true"])
        found[b] = bool((r.stdout or "").strip())
    primary = "unknown"
    if found.get("apt") or found.get("dpkg"):
        primary = "apt/dpkg"
    elif found.get("dnf") or found.get("yum") or found.get("rpm"):
        primary = "dnf/yum/rpm"
    elif found.get("apk"):
        primary = "apk"
    os_id = "unknown"
    os_release = Path("/etc/os-release")
    if os_release.exists():
        for ln in os_release.read_text(errors="ignore").splitlines():
            if ln.startswith("ID="):
                os_id = ln.split("=", 1)[1].strip().strip('"')
                break
    return ToolResult(
        tool="package.manager_detect",
        stdout=json.dumps({"os": os_id, "available": found, "primary": primary}),
    )


def query(name: str) -> ToolResult:
    p = json.loads(manager_detect().stdout).get("primary", "unknown")
    if p == "apt/dpkg":
        return _as_tool_result(
            "package.query",
            run_command(["sh", "-lc", f"dpkg -s {name} 2>/dev/null | sed -n '1,8p'"]),
        )
    if p == "dnf/yum/rpm":
        return _as_tool_result(
            "package.query",
            run_command(["sh", "-lc", f"rpm -qi {name} 2>/dev/null | sed -n '1,10p'"]),
        )
    if p == "apk":
        return _as_tool_result(
            "package.query",
            run_command(["sh", "-lc", f"apk info -e {name} && apk info -v {name} | head -n 3"]),
        )
    return ToolResult(
        tool="package.query", ok=False, exit_code=1, stderr="package manager unavailable"
    )


def file_owner(path: str) -> ToolResult:
    p = json.loads(manager_detect().stdout).get("primary", "unknown")
    if p == "apt/dpkg":
        return _as_tool_result(
            "package.file_owner",
            run_command(["sh", "-lc", f"dpkg -S {path} 2>/dev/null | head -n 1"]),
        )
    if p == "dnf/yum/rpm":
        return _as_tool_result(
            "package.file_owner",
            run_command(["sh", "-lc", f"rpm -qf {path} 2>/dev/null | head -n 1"]),
        )
    if p == "apk":
        return _as_tool_result(
            "package.file_owner",
            run_command(["sh", "-lc", f"apk info -W {path} 2>/dev/null | head -n 1"]),
        )
    return ToolResult(
        tool="package.file_owner", ok=False, exit_code=1, stderr="package manager unavailable"
    )


def recent_history(lines: int = 80) -> ToolResult:
    cmd = (
        "tail -n {n} /var/log/apt/history.log /var/log/dpkg.log "
        "/var/log/yum.log /var/log/dnf.log /var/log/apk.log 2>/dev/null"
    )
    return _as_tool_result(
        "package.recent_history", run_command(["sh", "-lc", cmd.format(n=max(20, min(lines, 200)))])
    )
