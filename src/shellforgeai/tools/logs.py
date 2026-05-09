from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from shellforgeai.util.subprocess import run_command

from . import files, host
from .base import ToolResult

COMMON = {
    "nginx": ["/var/log/nginx/error.log", "/var/log/nginx/access.log"],
    "ssh": ["/var/log/auth.log", "/var/log/secure"],
    "sshd": ["/var/log/auth.log", "/var/log/secure"],
    "docker": ["/var/log/docker.log"],
    "apache": ["/var/log/apache2/error.log", "/var/log/httpd/error_log"],
    "apache2": ["/var/log/apache2/error.log"],
    "httpd": ["/var/log/httpd/error_log"],
    "caddy": ["/var/log/caddy"],
    "mysql": ["/var/log/mysql"],
    "mariadb": ["/var/log/mariadb"],
    "postgres": ["/var/log/postgresql"],
    "postgresql": ["/var/log/postgresql"],
    "redis": ["/var/log/redis"],
    "shellforgeai": ["/data/sessions", "/data/artifacts"],
}

COMMON_LOG_PATHS = [
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/daemon.log",
    "/var/log/kern.log",
    "/var/log/dmesg",
    "/var/log/nginx/error.log",
    "/var/log/nginx/access.log",
    "/var/log/apache2/error.log",
    "/var/log/httpd/error_log",
    "/var/log/caddy",
    "/var/log/mysql",
    "/var/log/mariadb",
    "/var/log/postgresql",
    "/var/log/redis",
    "/var/log/docker.log",
    "/var/log/journal",
    "/data/logs",
]

DEFAULT_ERROR_TERMS = [
    "error",
    "failed",
    "failure",
    "critical",
    "panic",
    "exception",
    "traceback",
    "timeout",
    "timed out",
    "refused",
    "unreachable",
    "denied",
    "permission denied",
    "segfault",
    "oom",
    "killed process",
    "read-only file system",
    "no space left",
    "disk full",
    "i/o error",
    "tls",
    "certificate",
    "auth failed",
    "login failed",
]

AUTH_TERMS = [
    "failed password",
    "authentication failure",
    "auth failed",
    "invalid user",
    "session opened",
    "pam_unix",
    "pam authenticate",
    "sudo:",
    "incorrect password",
    "permission denied",
    "account locked",
    "ldap",
    "login failed",
]

KERNEL_TERMS = [
    "i/o error",
    " ata",
    " nvme",
    "ext4",
    "xfs",
    "zfs",
    "btrfs",
    "oom",
    "killed process",
    "segfault",
    "call trace",
    "kernel panic",
    "panic",
    "read-only file system",
    "link down",
    "link up",
    "network unreachable",
    "reset",
    "thermal",
    "throttling",
]

_REDACT_PATTERNS = [
    (re.compile(r"(?i)(password\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(token\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(secret\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(authorization:\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(bearer\s+)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(cookie:\s*)\S+"), r"\1[REDACTED]"),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
        "[REDACTED PRIVATE KEY]",
    ),
]


def _redact_line(line: str) -> str:
    out = line
    for pat, repl in _REDACT_PATTERNS:
        out = pat.sub(repl, out)
    return out


def _truncate_line(line: str, max_len: int = 240) -> str:
    return line if len(line) <= max_len else line[:max_len] + "..."


def find_common(service: str) -> ToolResult:
    paths = [p for p in COMMON.get(service.lower(), []) if Path(p).exists()]
    return ToolResult(tool="logs.find_common", stdout="\n".join(paths) or "none")


def file_tail(path: str, lines: int = 100) -> ToolResult:
    r = files.tail(path, lines=lines)
    return ToolResult(
        tool="logs.file_tail", ok=r.ok, exit_code=r.exit_code, stdout=r.stdout, stderr=r.stderr
    )


def search_errors(
    path: str, patterns: list[str] | None = None, max_matches: int = 50
) -> ToolResult:
    patterns = patterns or [
        "error",
        "failed",
        "denied",
        "refused",
        "timeout",
        "address already in use",
        "no such file",
        "permission",
    ]
    r = files.read_text(path, max_bytes=131072)
    if not r.ok:
        return ToolResult(tool="logs.search_errors", ok=False, exit_code=1, stderr=r.stderr)
    matches = []
    for ln in r.stdout.splitlines():
        low = ln.lower()
        if any(p in low for p in patterns):
            matches.append(ln)
        if len(matches) >= max_matches:
            break
    return ToolResult(tool="logs.search_errors", stdout="\n".join(matches))


def common_paths(extra_paths: list[str] | None = None) -> ToolResult:
    paths = list(COMMON_LOG_PATHS)
    if extra_paths:
        paths.extend(extra_paths)
    readable: list[dict] = []
    unreadable = 0
    missing = 0
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            missing += 1
            continue
        try:
            ptype = "dir" if p.is_dir() else "file"
            size = p.stat().st_size if p.is_file() else 0
            mtime = int(p.stat().st_mtime)
        except OSError:
            unreadable += 1
            continue
        try:
            if p.is_file():
                with p.open("rb") as fh:
                    fh.read(1)
            else:
                next(iter(p.iterdir()), None)
        except (OSError, PermissionError):
            unreadable += 1
            continue
        readable.append({"path": str(p), "type": ptype, "size": size, "mtime": mtime})
    payload = {
        "readable": readable,
        "unreadable_count": unreadable,
        "missing_count": missing,
        "total_checked": len(paths),
    }
    short = ", ".join(r["path"] for r in readable[:5]) or "none"
    summary = (
        f"readable_logs={len(readable)} unreadable={unreadable} missing={missing} samples={short}"
    )
    return ToolResult(tool="logs.common_paths", stdout=json.dumps(payload), stderr=summary)


def _scan_file_for_terms(
    path: Path,
    terms: list[str],
    max_bytes: int = 65536,
    max_lines: int = 200,
) -> tuple[list[str], int]:
    if not path.exists() or not path.is_file():
        return [], 0
    try:
        b = path.read_bytes()
    except (OSError, PermissionError):
        return [], 0
    if b"\x00" in b[:4096]:
        return [], 0
    if len(b) > max_bytes:
        b = b[-max_bytes:]
    text = b.decode(errors="ignore")
    lines = text.splitlines()
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    matches: list[str] = []
    total = 0
    for ln in lines:
        low = ln.lower()
        if any(t in low for t in terms):
            matches.append(_truncate_line(_redact_line(ln)))
            total += 1
    return matches, total


def _dedupe_lines(lines: list[str]) -> list[tuple[str, int]]:
    counter: Counter[str] = Counter(lines)
    return list(counter.items())


def recent_errors(
    target: str | None = None,
    paths: list[str] | None = None,
    terms: list[str] | None = None,
    max_files: int = 8,
    max_bytes_per_file: int = 65536,
    max_lines_per_file: int = 200,
    max_total_samples: int = 30,
) -> ToolResult:
    terms = [t.lower() for t in (terms or DEFAULT_ERROR_TERMS)]
    candidate_paths: list[str] = []
    if paths:
        candidate_paths.extend(paths)
    if target and target.lower() in COMMON:
        candidate_paths.extend(COMMON[target.lower()])
    candidate_paths.extend(COMMON_LOG_PATHS)
    seen: set[str] = set()
    ordered: list[str] = []
    for p in candidate_paths:
        if p in seen:
            continue
        seen.add(p)
        ordered.append(p)
    scanned = 0
    sources: list[dict] = []
    all_samples: list[str] = []
    for raw in ordered:
        if scanned >= max_files:
            break
        p = Path(raw)
        if not p.exists():
            continue
        if p.is_dir():
            try:
                for sub in sorted(p.iterdir()):
                    if scanned >= max_files:
                        break
                    if sub.is_file() and sub.suffix not in (".gz", ".xz", ".zip"):
                        m, count = _scan_file_for_terms(
                            sub, terms, max_bytes_per_file, max_lines_per_file
                        )
                        scanned += 1
                        if m:
                            sources.append({"path": str(sub), "matches": count})
                            all_samples.extend(m)
            except (OSError, PermissionError):
                continue
            continue
        m, count = _scan_file_for_terms(p, terms, max_bytes_per_file, max_lines_per_file)
        scanned += 1
        if m:
            sources.append({"path": str(p), "matches": count})
            all_samples.extend(m)
    deduped = _dedupe_lines(all_samples)
    deduped.sort(key=lambda x: x[1], reverse=True)
    samples_short = [{"line": line, "count": count} for line, count in deduped[:max_total_samples]]
    payload = {
        "files_scanned": scanned,
        "sources": sources,
        "samples": samples_short,
        "total_matches": sum(s["matches"] for s in sources),
    }
    if not sources:
        summary = "no recent error-like patterns found in visible logs"
    else:
        themes = ", ".join(f"{s['path']}={s['matches']}" for s in sources[:4])
        summary = f"recent_errors total={payload['total_matches']} files={scanned} {themes}"
    return ToolResult(tool="logs.recent_errors", stdout=json.dumps(payload), stderr=summary)


def service_errors(
    service: str,
    since: str = "30m",
    max_lines: int = 150,
) -> ToolResult:
    svc = service.lower().strip()
    journal_payload: dict | None = None
    journal_summary = "journal unavailable"
    journ = host.command_exists("journalctl")
    if journ.ok and (journ.stdout or "").strip():
        r = run_command(
            [
                "journalctl",
                "-u",
                svc,
                "--since",
                since,
                "-n",
                str(max_lines),
                "--no-pager",
            ]
        )
        if r.exit_code == 0 and r.stdout.strip():
            redacted = "\n".join(_truncate_line(_redact_line(ln)) for ln in r.stdout.splitlines())
            terms_low = [t.lower() for t in DEFAULT_ERROR_TERMS]
            errs = [ln for ln in redacted.splitlines() if any(t in ln.lower() for t in terms_low)]
            journal_payload = {
                "available": True,
                "lines": len(redacted.splitlines()),
                "error_lines": errs[-30:],
            }
            journal_summary = f"journal_lines={len(redacted.splitlines())} errors={len(errs)}"
        else:
            journal_payload = {"available": True, "lines": 0, "error_lines": []}
            journal_summary = "journal: no entries for this service"

    common_files = [str(Path(p)) for p in COMMON.get(svc, []) if Path(p).exists()]
    file_scan = recent_errors(target=svc, paths=common_files or None, max_files=6)
    file_payload = json.loads(file_scan.stdout)

    payload = {
        "service": svc,
        "journal": journal_payload,
        "files": file_payload,
    }
    summary_parts = [f"service={svc}", journal_summary]
    if file_payload.get("sources"):
        summary_parts.append(f"file_matches={file_payload['total_matches']}")
    else:
        summary_parts.append("file_matches=0")
    summary = " ".join(summary_parts)
    return ToolResult(tool="logs.service_errors", stdout=json.dumps(payload), stderr=summary)


def auth_errors(max_files: int = 4) -> ToolResult:
    paths = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/audit/audit.log",
    ]
    res = recent_errors(paths=paths, terms=AUTH_TERMS, max_files=max_files)
    payload = json.loads(res.stdout)
    payload["category"] = "auth"
    summary = res.stderr.replace("logs.recent_errors", "logs.auth_errors")
    if not payload.get("sources"):
        summary = "no auth logs visible or no recent auth failures"
    else:
        summary = f"auth_errors total={payload.get('total_matches', 0)}"
    return ToolResult(tool="logs.auth_errors", stdout=json.dumps(payload), stderr=summary)


def kernel_errors(max_files: int = 4) -> ToolResult:
    paths = [
        "/var/log/kern.log",
        "/var/log/dmesg",
        "/var/log/syslog",
        "/var/log/messages",
    ]
    res = recent_errors(paths=paths, terms=KERNEL_TERMS, max_files=max_files)
    payload = json.loads(res.stdout)
    payload["category"] = "kernel"

    dmesg_avail = host.command_exists("dmesg")
    if dmesg_avail.ok and (dmesg_avail.stdout or "").strip():
        r = run_command(["dmesg", "--ctime"])
        if r.exit_code == 0 and r.stdout.strip():
            terms_low = [t.lower() for t in KERNEL_TERMS]
            errs = []
            for ln in r.stdout.splitlines()[-300:]:
                low = ln.lower()
                if any(t in low for t in terms_low):
                    errs.append(_truncate_line(_redact_line(ln)))
            payload.setdefault(
                "dmesg", {"available": True, "matches": len(errs), "samples": errs[-15:]}
            )
        else:
            payload.setdefault("dmesg", {"available": False})
    else:
        payload.setdefault("dmesg", {"available": False})

    if not payload.get("sources") and not payload.get("dmesg", {}).get("matches"):
        summary = "no visible kernel storage/network/OOM errors found"
    else:
        summary = (
            f"kernel_errors files_total={payload.get('total_matches', 0)} "
            f"dmesg_matches={payload.get('dmesg', {}).get('matches', 0)}"
        )
    return ToolResult(tool="logs.kernel_errors", stdout=json.dumps(payload), stderr=summary)


_THEMES: list[tuple[str, list[str], str, str]] = [
    ("connection refused", ["connection refused", "refused"], "warning", "network"),
    (
        "dns failure",
        ["temporary failure in name resolution", "name resolution", "dns"],
        "warning",
        "dns",
    ),
    ("permission denied", ["permission denied"], "warning", "permission"),
    (
        "auth failed",
        [
            "failed password",
            "authentication failure",
            "auth failed",
            "invalid user",
            "login failed",
        ],
        "warning",
        "auth",
    ),
    ("disk full", ["no space left", "disk full"], "critical", "storage"),
    ("read-only fs", ["read-only file system"], "critical", "storage"),
    ("oom killed", ["oom", "killed process", "out of memory"], "critical", "memory"),
    ("io error", ["i/o error"], "critical", "storage"),
    ("tls/cert failure", ["certificate", "tls", "ssl handshake"], "warning", "tls/cert"),
    ("timeout", ["timeout", "timed out"], "warning", "network"),
    ("kernel panic", ["kernel panic", "panic:"], "critical", "kernel"),
    ("segfault", ["segfault"], "warning", "service"),
]


def error_themes(
    samples: list[str] | None = None, sources_payload: dict | None = None
) -> ToolResult:
    lines: list[str] = []
    if samples:
        lines.extend(samples)
    if sources_payload:
        for s in sources_payload.get("samples", []) or []:
            if isinstance(s, dict) and "line" in s:
                lines.append(s["line"])
            elif isinstance(s, str):
                lines.append(s)
    themes_out: list[dict] = []
    for theme_name, keywords, severity, angle in _THEMES:
        matched = []
        for ln in lines:
            low = ln.lower()
            if any(k in low for k in keywords):
                matched.append(ln)
        if matched:
            themes_out.append(
                {
                    "name": theme_name,
                    "count": len(matched),
                    "severity": severity,
                    "angle": angle,
                    "samples": [_truncate_line(_redact_line(m)) for m in matched[:3]],
                }
            )
    themes_out.sort(key=lambda t: (-t["count"], t["name"]))
    payload = {"themes": themes_out, "input_lines": len(lines)}
    if themes_out:
        summary = "themes: " + ", ".join(f"{t['name']}={t['count']}" for t in themes_out[:4])
    else:
        summary = "no recognized error themes"
    return ToolResult(tool="logs.error_themes", stdout=json.dumps(payload), stderr=summary)


def safe_tail(path: str, lines: int = 100, max_bytes: int = 65536) -> ToolResult:
    if not path or any(c in path for c in ["*", "?", "\n"]):
        return ToolResult(
            tool="logs.safe_tail", ok=False, exit_code=1, stderr="unsafe path or glob"
        )
    p = Path(path).expanduser()
    allowed = False
    candidate = str(p)
    for base in COMMON_LOG_PATHS + ["/var/log", "/data/logs", "/data/sessions", "/data/artifacts"]:
        if candidate == base or candidate.startswith(base.rstrip("/") + "/"):
            allowed = True
            break
    if not allowed:
        return ToolResult(
            tool="logs.safe_tail",
            ok=False,
            exit_code=1,
            stderr="path outside permitted log roots",
        )
    if not p.exists() or not p.is_file():
        return ToolResult(
            tool="logs.safe_tail", ok=False, exit_code=1, stderr="not a readable file"
        )
    try:
        b = p.read_bytes()
    except (OSError, PermissionError) as exc:
        return ToolResult(tool="logs.safe_tail", ok=False, exit_code=1, stderr=str(exc))
    if b"\x00" in b[:4096]:
        return ToolResult(tool="logs.safe_tail", ok=False, exit_code=1, stderr="binary file")
    if len(b) > max_bytes:
        b = b[-max_bytes:]
    text = b.decode(errors="ignore")
    split = text.splitlines()
    if lines and len(split) > lines:
        split = split[-lines:]
    redacted = "\n".join(_truncate_line(_redact_line(ln)) for ln in split)
    return ToolResult(
        tool="logs.safe_tail",
        stdout=redacted,
        stderr=f"path={p} lines={len(split)}",
    )
