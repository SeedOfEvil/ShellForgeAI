from __future__ import annotations

import re
import socket
import time
from pathlib import Path
from urllib.parse import urlparse

from shellforgeai.tools import firewall, system
from shellforgeai.util.subprocess import run_command

from .base import ToolResult


def listeners() -> ToolResult:
    r = run_command(["ss", "-lntup"])
    return ToolResult(
        tool="network.listeners",
        command=r.command,
        exit_code=r.exit_code,
        stdout=r.stdout,
        stderr=r.stderr,
        duration_ms=r.duration_ms,
        ok=r.exit_code == 0,
    )


def routes() -> ToolResult:
    r = run_command(["ip", "route", "show"])
    return ToolResult(
        tool="network.routes",
        command=r.command,
        exit_code=r.exit_code,
        stdout=r.stdout,
        stderr=r.stderr,
        duration_ms=r.duration_ms,
        ok=r.exit_code == 0,
    )


def dns() -> ToolResult:
    r = run_command(["cat", "/etc/resolv.conf"])
    return ToolResult(
        tool="network.dns",
        command=r.command,
        exit_code=r.exit_code,
        stdout=r.stdout,
        stderr=r.stderr,
        duration_ms=r.duration_ms,
        ok=r.exit_code == 0,
    )


def interfaces() -> ToolResult:
    r = run_command(["ip", "-brief", "address"])
    if r.exit_code == 0 and r.stdout.strip():
        return ToolResult(
            tool="network.interfaces", command=r.command, stdout=r.stdout, duration_ms=r.duration_ms
        )
    sys_net = Path("/sys/class/net")
    if sys_net.exists():
        names = sorted([p.name for p in sys_net.iterdir() if p.is_dir()])
        out = "\n".join(f"{n} UNKNOWN" for n in names)
        return ToolResult(tool="network.interfaces", command=["/sys/class/net"], stdout=out)
    return ToolResult(
        tool="network.interfaces",
        command=r.command,
        ok=False,
        exit_code=r.exit_code,
        stderr=r.stderr or "interfaces unavailable",
    )


def default_route() -> ToolResult:
    r = run_command(["ip", "route", "show", "default"])
    if r.exit_code == 0 and r.stdout.strip():
        return ToolResult(tool="network.default_route", command=r.command, stdout=r.stdout)
    full = run_command(["ip", "route"])
    if full.exit_code == 0:
        defaults = [ln for ln in full.stdout.splitlines() if ln.startswith("default ")]
        return ToolResult(
            tool="network.default_route",
            command=full.command,
            stdout="\n".join(defaults) or "no default route found",
        )
    try:
        raw = Path("/proc/net/route").read_text(encoding="utf-8", errors="ignore")
        return ToolResult(
            tool="network.default_route", command=["cat", "/proc/net/route"], stdout=raw
        )
    except OSError as exc:
        return ToolResult(tool="network.default_route", ok=False, exit_code=1, stderr=str(exc))


def resolution_test(hostname: str = "example.com", timeout_seconds: float = 3.0) -> ToolResult:
    socket.setdefaulttimeout(max(0.5, min(timeout_seconds, 10.0)))
    try:
        infos = socket.getaddrinfo(hostname, None)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        return ToolResult(
            tool="network.resolution_test",
            stdout=f"{hostname} resolved to {len(ips)} addresses: {', '.join(ips[:4])}",
        )
    except Exception as exc:
        return ToolResult(
            tool="network.resolution_test",
            ok=False,
            exit_code=1,
            stderr=f"DNS resolution failed: {exc}",
        )


def tcp_connect_test(host: str, port: int, timeout_seconds: float = 3.0) -> ToolResult:
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=max(0.5, min(timeout_seconds, 10.0))):
            pass
        elapsed = int((time.monotonic() - start) * 1000)
        return ToolResult(
            tool="network.tcp_connect_test", stdout=f"tcp connect {host}:{port} ok in {elapsed}ms"
        )
    except Exception as exc:
        return ToolResult(
            tool="network.tcp_connect_test",
            ok=False,
            exit_code=1,
            stderr=f"tcp connect {host}:{port} failed: {exc}",
        )


def connect_test_readonly(target: str, port: int = 443, timeout_seconds: int = 3) -> ToolResult:
    host = urlparse(target).hostname or target
    return tcp_connect_test(host, port, timeout_seconds)


def firewall_context() -> ToolResult:
    checks = firewall.detect()
    container = system.container_detect()
    in_container = (container.stdout or "").strip().lower() not in {"", "none", "unknown", "host"}
    found = []
    for item in checks:
        if item.tool == "command.exists" and item.command and (item.stdout or "").strip():
            found.append(item.command[-1])
    text = f"firewall tools visible: {', '.join(found)}" if found else "no firewall tools found"
    if in_container and not found:
        text += "; host firewall state not visible from container"
    return ToolResult(tool="network.firewall_context", stdout=text)


def listener_attribution() -> ToolResult:
    base = listeners()
    if not base.ok:
        return ToolResult(
            tool="network.listener_attribution",
            ok=False,
            exit_code=base.exit_code,
            stderr=base.stderr,
        )
    lines = base.stdout.splitlines()
    data = lines[1:] if len(lines) > 1 else lines
    out = []
    for ln in data[:200]:
        parts = re.split(r"\s+", ln.strip())
        if len(parts) < 5:
            continue
        proto = parts[0]
        local = parts[4]
        proc = parts[-1] if parts else "-"
        out.append(f"{proto} {local} process={proc if proc != '*' else 'owner unavailable'}")
    return ToolResult(tool="network.listener_attribution", stdout="\n".join(out) or "no listeners")


def namespace_context() -> ToolResult:
    c = system.container_detect()
    d = dns()
    r = default_route()
    hints = []
    if "127.0.0.11" in (d.stdout or ""):
        hints.append("docker_dns")
    if "172." in (r.stdout or ""):
        hints.append("bridge_route_hint")
    base = (c.stdout or "unknown").strip().lower()
    if base in {"docker", "container", "lxc"} or hints:
        out = "container_view=yes runtime_hint=docker; host routes/firewall may differ"
    elif base in {"none", "host"}:
        out = "container_view=no runtime_hint=host"
    else:
        out = "container_view=unknown runtime_hint=unknown"
    return ToolResult(tool="network.namespace_context", stdout=out)


def listeners_filtered(pattern: str) -> ToolResult:
    base = listeners()
    if not base.ok:
        return ToolResult(
            tool="network.listeners.filtered",
            command=base.command,
            ok=False,
            exit_code=base.exit_code,
            stderr=base.stderr,
        )
    lines = [ln for ln in base.stdout.splitlines() if pattern.lower() in ln.lower()]
    return ToolResult(
        tool="network.listeners.filtered", command=base.command, stdout="\n".join(lines), ok=True
    )
