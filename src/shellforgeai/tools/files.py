from __future__ import annotations

import fnmatch
import os

try:
    import grp
except ModuleNotFoundError:  # Windows: POSIX group database is unavailable.
    grp = None
try:
    import pwd
except ModuleNotFoundError:  # Windows: POSIX password database is unavailable.
    pwd = None
from pathlib import Path

from .base import ToolResult

DENY_PATTERNS = [
    "/etc/shadow",
    "/etc/gshadow",
    "/proc/kcore",
    "*/.codex/auth.json",
    "~/.codex/auth.json",
    "*.key",
    "*.pem",
    "*id_rsa*",
    "*id_ed25519*",
]


def _denied(path: str) -> bool:
    expanded = str(Path(path).expanduser())
    return any(fnmatch.fnmatch(expanded, p) for p in DENY_PATTERNS)


def _redact(text: str) -> str:
    keys = [
        "password",
        "secret",
        "token",
        "api_key",
        "authorization",
        "private_key",
        "access_token",
        "refresh_token",
    ]
    out = []
    for ln in text.splitlines():
        low = ln.lower()
        if any(k in low for k in keys):
            out.append("[REDACTED]")
        elif ".env" in low and "=" in ln:
            out.append(ln.split("=")[0] + "=***")
        else:
            out.append(ln)
    return "\n".join(out)


def exists(path: str) -> ToolResult:
    p = Path(path)
    if _denied(path):
        return ToolResult(
            tool="files.exists", ok=False, exit_code=1, stderr="sensitive path denied"
        )
    e = p.exists()
    t = "other"
    if e:
        t = (
            "dir"
            if p.is_dir()
            else "file"
            if p.is_file()
            else "symlink"
            if p.is_symlink()
            else "other"
        )
    payload = {
        "exists": e,
        "type": t,
        "readable": (e and p.exists()),
        "size": p.stat().st_size if e else 0,
    }
    return ToolResult(tool="files.exists", stdout=str(payload))


def safe_list(path: str, max_entries: int = 200) -> ToolResult:
    p = Path(path)
    if not p.is_dir():
        return ToolResult(tool="files.safe_list", ok=False, exit_code=1, stderr="not a directory")
    names = sorted([x.name for x in p.iterdir()])[:max_entries]
    return ToolResult(tool="files.safe_list", stdout="\n".join(names))


def head(path: str, lines: int = 40) -> ToolResult:
    return read_text(path, max_bytes=65536, lines=lines, tail_mode=False)


def tail(path: str, lines: int = 100) -> ToolResult:
    return read_text(path, max_bytes=65536, lines=lines, tail_mode=True)


def read(path: str, max_bytes: int = 65536) -> ToolResult:
    return read_text(path, max_bytes=max_bytes)


def read_text(
    path: str,
    max_bytes: int = 65536,
    redact_secrets: bool = True,
    lines: int | None = None,
    tail_mode: bool = False,
) -> ToolResult:
    p = Path(path).expanduser()
    if _denied(str(p)):
        return ToolResult(
            tool="files.read_text", ok=False, exit_code=1, stderr="sensitive path denied"
        )
    if not p.exists() or p.is_dir():
        return ToolResult(tool="files.read_text", ok=False, exit_code=1, stderr="invalid path")
    b = p.read_bytes()[: max_bytes + 1]
    if b"\x00" in b:
        return ToolResult(tool="files.read_text", ok=False, exit_code=1, stderr="binary file")
    text = b.decode(errors="ignore")
    split = text.splitlines()
    if lines is not None:
        split = split[-lines:] if tail_mode else split[:lines]
    out = "\n".join(split)
    if redact_secrets:
        out = _redact(out)
    return ToolResult(tool="files.read_text", stdout=out)


def stat(path: str) -> ToolResult:
    p = Path(path)
    if _denied(path):
        return ToolResult(tool="files.stat", ok=False, exit_code=1, stderr="sensitive path denied")
    if not (p.exists() or p.is_symlink()):
        return ToolResult(
            tool="files.stat",
            stdout=str({"path": path, "exists": False}),
            ok=True,
        )
    st = p.lstat()
    mode = oct(st.st_mode & 0o777)
    is_exec = bool(st.st_mode & 0o111)
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name if pwd is not None else str(st.st_uid)
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name if grp is not None else str(st.st_gid)
    except KeyError:
        group = str(st.st_gid)
    payload = {
        "path": path,
        "exists": True,
        "type": (
            "symlink"
            if p.is_symlink()
            else "dir"
            if p.is_dir()
            else "file"
            if p.is_file()
            else "other"
        ),
        "owner": owner,
        "group": group,
        "mode": mode,
        "executable": is_exec,
        "size": st.st_size,
        "symlink_target": os.readlink(path) if p.is_symlink() else None,
    }
    return ToolResult(tool="files.stat", stdout=str(payload), ok=True)
