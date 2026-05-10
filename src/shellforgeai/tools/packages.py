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
    manager = json.loads(manager_detect().stdout).get("primary", "unknown")
    payload = {
        "query": name,
        "manager": manager,
        "installed": "unknown",
        "package_name": None,
        "version": None,
        "architecture": None,
        "raw_status": None,
        "limitation": None,
    }
    if manager == "apt/dpkg":
        r = run_command(
            [
                "sh",
                "-lc",
                (
                    "dpkg-query -W -f='${Status}|${Package}|${Version}|${Architecture}' "
                    f"{name} 2>/dev/null"
                ),
            ]
        )
        txt = (r.stdout or "").strip()
        if r.exit_code == 0 and txt:
            parts = txt.split("|")
            payload["raw_status"] = parts[0] if parts else ""
            payload["package_name"] = parts[1] if len(parts) > 1 else name
            payload["version"] = parts[2] if len(parts) > 2 else None
            payload["architecture"] = parts[3] if len(parts) > 3 else None
            payload["installed"] = bool("installed" in (parts[0] if parts else ""))
        else:
            payload["installed"] = False
            payload["raw_status"] = "not-installed"
        return ToolResult(tool="package.query", stdout=json.dumps(payload), ok=True)
    payload["limitation"] = "package manager unavailable"
    return ToolResult(
        tool="package.query",
        stdout=json.dumps(payload),
        ok=False,
        exit_code=1,
        stderr="package manager unavailable",
    )


def file_owner(path: str) -> ToolResult:
    p = Path(path)
    exists = p.exists() or p.is_symlink()
    symlink_target = str(p.resolve()) if p.is_symlink() else None
    manager = json.loads(manager_detect().stdout).get("primary", "unknown")
    payload = {
        "path": path,
        "exists": exists,
        "symlink_target": symlink_target,
        "manager": manager,
        "owner_package": None,
        "owner_status": "error",
        "limitation": None,
    }
    if not exists:
        payload["owner_status"] = "path_missing"
        return ToolResult(tool="package.file_owner", stdout=json.dumps(payload), ok=True)
    if manager != "apt/dpkg":
        payload["owner_status"] = "manager_unavailable"
        payload["limitation"] = "package manager unavailable"
        return ToolResult(
            tool="package.file_owner",
            stdout=json.dumps(payload),
            ok=False,
            exit_code=1,
            stderr="package manager unavailable",
        )

    check_paths = [path]
    if symlink_target and symlink_target != path:
        check_paths.append(symlink_target)
    for cp in check_paths:
        r = run_command(["sh", "-lc", f"dpkg -S {cp} 2>/dev/null | head -n 1"])
        line = (r.stdout or "").strip()
        if r.exit_code == 0 and ":" in line:
            payload["owner_package"] = line.split(":", 1)[0].strip()
            payload["owner_status"] = "owned"
            return ToolResult(tool="package.file_owner", stdout=json.dumps(payload), ok=True)
    payload["owner_status"] = "not_owned"
    return ToolResult(tool="package.file_owner", stdout=json.dumps(payload), ok=True)


def recent_history(lines: int = 80) -> ToolResult:
    cmd = (
        "tail -n {n} /var/log/apt/history.log /var/log/dpkg.log "
        "/var/log/yum.log /var/log/dnf.log /var/log/apk.log 2>/dev/null"
    )
    return _as_tool_result(
        "package.recent_history", run_command(["sh", "-lc", cmd.format(n=max(20, min(lines, 200)))])
    )
