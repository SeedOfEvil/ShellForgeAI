"""Read-only Docker visibility collectors.

Wraps a small bounded subset of the docker CLI:
- docker ps / docker ps -a
- docker inspect <id>
- docker logs --tail N <id>

Forbidden: docker start/stop/restart/rm/exec/cp/build/pull, compose
mutation, prune, volume/network mutation. The collectors here never
invoke those commands.
"""

from __future__ import annotations

import json
import re
from typing import Any

from shellforgeai.core.compose_context import parse_compose_context
from shellforgeai.util.subprocess import run_command

from . import host
from .base import ToolResult

_DOCKER_PS_FORMAT = (
    "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.State}}\t{{.RunningFor}}\t{{.Labels}}"
)

_REDACT_PATTERNS = [
    (re.compile(r"(?i)(password\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(token\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(secret\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(authorization:\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(bearer\s+)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(cookie:\s*)\S+"), r"\1[REDACTED]"),
]


def _redact(text: str) -> str:
    out = text
    for pat, repl in _REDACT_PATTERNS:
        out = pat.sub(repl, out)
    return out


def _docker_available() -> bool:
    r = host.command_exists("docker")
    return bool(r.ok and (r.stdout or "").strip())


def _labels_to_dict(raw: str) -> dict[str, str]:
    labels: dict[str, str] = {}
    for part in (raw or "").split(","):
        token = part.strip()
        if not token or "=" not in token:
            continue
        k, v = token.split("=", 1)
        k = k.strip()
        if not k:
            continue
        labels[k] = v.strip()
    return labels


def containers(all_containers: bool = True) -> ToolResult:
    """List containers (running and exited) with bounded fields."""
    if not _docker_available():
        return ToolResult(
            tool="docker.containers",
            ok=False,
            exit_code=127,
            stderr="docker CLI not available",
        )
    cmd = ["docker", "ps", "--no-trunc", "--format", _DOCKER_PS_FORMAT]
    if all_containers:
        cmd.append("-a")
    r = run_command(cmd, timeout=10)
    if r.exit_code != 0:
        msg = (r.stderr or "").strip().splitlines()[0] if r.stderr else "docker ps failed"
        return ToolResult(
            tool="docker.containers",
            command=cmd,
            ok=False,
            exit_code=r.exit_code,
            stderr=f"docker visibility unavailable: {msg}",
        )
    rows: list[dict[str, Any]] = []
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        cid = parts[0].strip()
        name = parts[1].strip()
        image = parts[2].strip()
        status = parts[3].strip()
        state = parts[4].strip().lower()
        running_for = parts[5].strip() if len(parts) > 5 else ""
        labels_raw = parts[6].strip() if len(parts) > 6 else ""
        labels = _labels_to_dict(labels_raw)
        rows.append(
            {
                "id": cid[:12],
                "name": name,
                "image": image,
                "status": status,
                "state": state,
                "running_for": running_for,
                "labels": labels,
                "compose": parse_compose_context(labels),
            }
        )
    payload = {"containers": rows, "total": len(rows)}
    summary = (
        f"docker containers={len(rows)} "
        f"running={sum(1 for c in rows if c['state'] == 'running')} "
        f"exited={sum(1 for c in rows if c['state'] == 'exited')} "
        f"restarting={sum(1 for c in rows if c['state'] == 'restarting')}"
    )
    return ToolResult(
        tool="docker.containers", command=cmd, stdout=json.dumps(payload), stderr=summary
    )


def inspect(container: str) -> ToolResult:
    """Inspect a single container, returning bounded fields."""
    if not _docker_available():
        return ToolResult(
            tool="docker.inspect", ok=False, exit_code=127, stderr="docker CLI not available"
        )
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}", container or ""):
        return ToolResult(
            tool="docker.inspect", ok=False, exit_code=1, stderr="invalid container reference"
        )
    cmd = ["docker", "inspect", container]
    r = run_command(cmd, timeout=10)
    if r.exit_code != 0:
        return ToolResult(
            tool="docker.inspect",
            command=cmd,
            ok=False,
            exit_code=r.exit_code,
            stderr=f"inspect failed for {container}",
        )
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return ToolResult(
            tool="docker.inspect",
            command=cmd,
            ok=False,
            exit_code=1,
            stderr="inspect returned non-JSON",
        )
    if not isinstance(data, list) or not data:
        return ToolResult(
            tool="docker.inspect",
            command=cmd,
            ok=False,
            exit_code=1,
            stderr="inspect returned empty payload",
        )
    info = data[0]
    state = info.get("State", {}) or {}
    health_raw = state.get("Health")
    health = health_raw.get("Status") if isinstance(health_raw, dict) else None
    labels = (info.get("Config") or {}).get("Labels") or {}
    payload = {
        "name": (info.get("Name") or "").lstrip("/"),
        "id": (info.get("Id") or "")[:12],
        "image": (info.get("Config") or {}).get("Image"),
        "status": state.get("Status"),
        "running": bool(state.get("Running")),
        "exit_code": state.get("ExitCode"),
        "restart_count": info.get("RestartCount"),
        "health": health,
        "started_at": state.get("StartedAt"),
        "finished_at": state.get("FinishedAt"),
        "error": state.get("Error") or "",
        "oom_killed": bool(state.get("OOMKilled")),
        "compose": parse_compose_context(labels if isinstance(labels, dict) else {}),
    }
    summary = (
        f"{payload['name']} status={payload['status']} exit={payload['exit_code']} "
        f"restarts={payload['restart_count']} health={payload['health']}"
    )
    return ToolResult(
        tool="docker.inspect", command=cmd, stdout=json.dumps(payload), stderr=summary
    )


def container_logs(container: str, tail: int = 200, max_bytes: int = 65536) -> ToolResult:
    """Read bounded recent container logs (no follow)."""
    if not _docker_available():
        return ToolResult(
            tool="docker.container_logs",
            ok=False,
            exit_code=127,
            stderr="docker CLI not available",
        )
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}", container or ""):
        return ToolResult(
            tool="docker.container_logs",
            ok=False,
            exit_code=1,
            stderr="invalid container reference",
        )
    tail = max(1, min(int(tail), 1000))
    cmd = ["docker", "logs", "--tail", str(tail), container]
    r = run_command(cmd, timeout=10)
    if r.exit_code != 0 and not r.stdout and not r.stderr:
        return ToolResult(
            tool="docker.container_logs",
            command=cmd,
            ok=False,
            exit_code=r.exit_code,
            stderr=f"docker logs failed for {container}",
        )
    text = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
    if len(text) > max_bytes:
        text = text[-max_bytes:]
    redacted = _redact(text)
    lines = redacted.splitlines()
    return ToolResult(
        tool="docker.container_logs",
        command=cmd,
        stdout="\n".join(lines),
        stderr=f"container={container} lines={len(lines)}",
        ok=True,
    )


_PROBLEM_PATTERNS = [
    (
        "missing_required_setting",
        re.compile(
            r"(?i)required[_ ]setting\s+is\s+missing"
            r"|missing\s+required\s+(?:env|environment|setting|config)"
        ),
    ),
    ("simulated_crash", re.compile(r"(?i)simulated\s+crash")),
    ("permission_denied", re.compile(r"(?i)permission denied")),
    ("read_only_fs", re.compile(r"(?i)read-only file system")),
    (
        "dns_failure",
        re.compile(
            r"(?i)temporary failure in name resolution|name or service not known|"
            r"could not resolve host|no such host|getaddrinfo|dns lookup failed|"
            r"servfail|nxdomain|bad address|bad host name|bad host\b|"
            r"wget:\s*bad address|ping:\s*bad address|"
            r"unable to resolve|name resolution failed"
        ),
    ),
    (
        "connection_refused",
        re.compile(r"(?i)connection refused|econnrefused|connect\(\) failed|upstream refused"),
    ),
    (
        "timeout",
        re.compile(
            r"(?i)connection timed out|i/o timeout|read timed out|"
            r"timeout connecting|upstream timeout|deadline exceeded|"
            r"\btimed out\b|\btimout\b"
        ),
    ),
    (
        "tls_certificate",
        re.compile(
            r"(?i)certificate verify failed|tls handshake (?:failed|timeout)|"
            r"unknown authority|x509[: ]|self[- ]signed certificate|"
            r"certificate has expired|ssl[:_ ]error"
        ),
    ),
    (
        "upstream_unreachable",
        re.compile(
            r"(?i)network is unreachable|no route to host|"
            r"upstream (?:unreachable|host|connect|down)|host is unreachable|"
            r"connection reset by peer|destination unreachable"
        ),
    ),
    (
        "unknown_network_error",
        re.compile(
            r"(?i)wget:\s*(?:download timed out|can't connect|server returned)|"
            r"curl:\s*\(\d+\)|network error|"
            r"socket (?:hang up|closed)|broken pipe"
        ),
    ),
    ("oom", re.compile(r"(?i)out of memory|oom[\- ]killed|killed process")),
    ("config_error", re.compile(r"(?i)config(uration)? error|invalid config")),
    ("traceback", re.compile(r"(?i)traceback \(most recent call last\)")),
    ("error_line", re.compile(r"(?im)^\s*(?:\[?ERROR\]?|ERR:|FATAL)\b")),
    ("warn_line", re.compile(r"(?im)^\s*(?:\[?WARN(?:ING)?\]?)\b")),
]


def _classify_log(text: str) -> dict[str, int]:
    hits: dict[str, int] = {}
    for name, pat in _PROBLEM_PATTERNS:
        n = len(pat.findall(text))
        if n:
            hits[name] = n
    return hits


def problem_summary(log_tail: int = 80) -> ToolResult:
    """Combine container inventory + bounded logs into a problem signal payload."""
    if not _docker_available():
        return ToolResult(
            tool="docker.problem_summary",
            ok=False,
            exit_code=127,
            stderr="docker visibility unavailable",
        )
    inv = containers(all_containers=True)
    if not inv.ok:
        return ToolResult(
            tool="docker.problem_summary",
            ok=False,
            exit_code=1,
            stderr=inv.stderr or "docker visibility unavailable",
        )
    try:
        inv_payload = json.loads(inv.stdout)
    except json.JSONDecodeError:
        return ToolResult(
            tool="docker.problem_summary",
            ok=False,
            exit_code=1,
            stderr="docker inventory parse failed",
        )
    rows = inv_payload.get("containers", []) or []
    failing: list[dict[str, Any]] = []
    noisy: list[dict[str, Any]] = []
    for row in rows:
        name = row.get("name") or ""
        state = (row.get("state") or "").lower()
        ins = inspect(name) if name else ToolResult(tool="docker.inspect", ok=False)
        info: dict[str, Any] = {}
        if ins.ok:
            try:
                info = json.loads(ins.stdout)
            except json.JSONDecodeError:
                info = {}
        exit_code = info.get("exit_code")
        oom = bool(info.get("oom_killed"))
        is_failing = state in {"restarting", "dead"} or oom
        if state == "exited" and (exit_code is None or exit_code != 0):
            is_failing = True
        log_text = ""
        log_themes: dict[str, int] = {}
        if name and state in {"running", "restarting", "exited", "dead"}:
            lr = container_logs(name, tail=log_tail)
            if lr.ok:
                log_text = lr.stdout or ""
                log_themes = _classify_log(log_text)
        entry = {
            "name": name,
            "image": row.get("image"),
            "state": state,
            "status": row.get("status"),
            "exit_code": exit_code,
            "restart_count": info.get("restart_count"),
            "health": info.get("health"),
            "oom_killed": oom,
            "log_themes": log_themes,
            "log_sample": (log_text.splitlines()[-5:] if log_text else []),
            "compose": row.get("compose")
            if isinstance(row.get("compose"), dict)
            else parse_compose_context(row.get("labels") or {}),
        }
        if is_failing:
            failing.append(entry)
        elif state == "running" and log_themes:
            noisy.append(entry)
    payload = {
        "available": True,
        "total": len(rows),
        "failing": failing,
        "noisy": noisy,
    }
    summary_parts = [f"docker_total={len(rows)}", f"failing={len(failing)}", f"noisy={len(noisy)}"]
    if failing:
        summary_parts.append("failing_names=" + ",".join(f["name"] for f in failing[:5]))
    summary = " ".join(summary_parts)
    return ToolResult(tool="docker.problem_summary", stdout=json.dumps(payload), stderr=summary)
