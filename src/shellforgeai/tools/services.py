from __future__ import annotations

import json
from pathlib import Path

from shellforgeai.util.subprocess import run_command

from . import files, host, logs, network, process, system
from .base import ToolResult

EXPECTED_PORTS = {
    "nginx": [80, 443],
    "httpd": [80, 443],
    "apache": [80, 443],
    "caddy": [80, 443],
    "ssh": [22],
    "sshd": [22],
    "postgres": [5432],
    "postgresql": [5432],
    "mysql": [3306],
    "mariadb": [3306],
    "redis": [6379],
}


def _bool(r: ToolResult) -> bool:
    return r.ok and bool((r.stdout or "").strip())


def _pid1_comm() -> str:
    r = run_command(["ps", "-p", "1", "-o", "comm="])
    return (r.stdout or "").strip() or "unknown"


def manager_detect() -> ToolResult:
    systemctl = host.command_exists("systemctl")
    journalctl = host.command_exists("journalctl")
    service_cmd = host.command_exists("service")
    container = system.container_detect()
    pid1 = _pid1_comm()
    has_run_systemd = Path("/run/systemd/system").exists()
    manager = "unknown"
    if _bool(systemctl) or has_run_systemd or pid1 == "systemd":
        manager = "systemd"
    elif _bool(service_cmd):
        manager = "sysvinit"
    elif "docker" in container.stdout.lower() or "container" in container.stdout.lower():
        manager = "container-none"
    payload = {
        "manager": manager,
        "systemctl_available": _bool(systemctl),
        "journalctl_available": _bool(journalctl),
        "pid1_comm": pid1,
        "container_hint": (container.stdout or "unknown").strip(),
        "limitations": [] if manager != "container-none" else ["host service manager not visible"],
    }
    summary = (
        f"manager={manager} pid1={pid1} "
        f"systemctl={'yes' if payload['systemctl_available'] else 'no'} "
        f"journalctl={'yes' if payload['journalctl_available'] else 'no'}"
    )
    return ToolResult(tool="service.manager_detect", stdout=json.dumps(payload), stderr=summary)


def status(service: str) -> ToolResult:
    mgr = manager_detect()
    mgr_data = json.loads(mgr.stdout)
    if not mgr_data.get("systemctl_available"):
        return ToolResult(
            tool="service.status",
            ok=False,
            exit_code=1,
            stderr="systemd unavailable in this container",
        )
    active = run_command(["systemctl", "is-active", service])
    enabled = run_command(["systemctl", "is-enabled", service])
    show = run_command(
        [
            "systemctl",
            "show",
            service,
            "--property=ActiveState,SubState,LoadState,UnitFileState,MainPID,ExecMainStatus,Restart,NRestarts",
            "--no-pager",
        ]
    )
    active_txt = (active.stdout or active.stderr).strip()
    enabled_txt = (enabled.stdout or enabled.stderr).strip()
    summary = f"{service} active={active_txt} enabled={enabled_txt}"
    return ToolResult(
        tool="service.status",
        command=["systemctl", "status", service],
        stdout=show.stdout,
        stderr=summary,
        ok=show.exit_code == 0,
        exit_code=show.exit_code,
    )


def processes(service: str) -> ToolResult:
    r = process.find(service)
    return ToolResult(
        tool="service.processes",
        command=r.command,
        stdout=r.stdout,
        stderr=r.stderr,
        ok=r.ok,
        exit_code=r.exit_code,
    )


def ports(service: str) -> ToolResult:
    listeners = network.listeners()
    exp = EXPECTED_PORTS.get(service.lower(), [])
    matches = []
    for line in listeners.stdout.splitlines():
        if any(f":{p}" in line for p in exp) or service.lower() in line.lower():
            matches.append(line)
    expected = ",".join(str(p) for p in exp) or "unknown"
    seen = "none" if not matches else str(len(matches))
    return ToolResult(
        tool="service.ports",
        command=listeners.command,
        stdout="\n".join(matches[:50]),
        stderr=f"{service} expected_ports={expected} listeners={seen}",
        ok=listeners.ok,
        exit_code=listeners.exit_code,
    )


def config_hints(service: str) -> ToolResult:
    hints = {
        "nginx": [
            "/etc/nginx/nginx.conf",
            "/etc/nginx/sites-enabled",
            "/etc/nginx/conf.d",
            "/var/log/nginx",
        ],
        "ssh": [
            "/etc/ssh/sshd_config",
            "/etc/ssh/ssh_config",
            "/var/log/auth.log",
            "/var/log/secure",
        ],
        "docker": ["/etc/docker/daemon.json", "/var/run/docker.sock", "/run/docker.sock"],
    }
    rows = []
    for p in hints.get(service.lower(), []):
        e = files.exists(p)
        rows.append(f"{p}={'present' if _bool(e) else 'missing'}")
    return ToolResult(
        tool="service.config_hints", stdout="\n".join(rows) or "no known hints", ok=True
    )


def unit_file(service: str) -> ToolResult:
    r = run_command(["systemctl", "cat", service])
    if r.exit_code == 0 and r.stdout.strip():
        return ToolResult(
            tool="service.unit_file", command=r.command, stdout=r.stdout[:12000], ok=True
        )
    return ToolResult(
        tool="service.unit_file", ok=False, exit_code=r.exit_code, stderr="unit file unavailable"
    )


def service_logs(service: str, since: str = "30m", limit: int = 120) -> ToolResult:
    journ = host.command_exists("journalctl")
    if _bool(journ):
        r = run_command(
            ["journalctl", "-u", service, "--since", since, "-n", str(limit), "--no-pager"]
        )
        return ToolResult(
            tool="service.logs",
            command=r.command,
            stdout=r.stdout[:16000],
            stderr=r.stderr,
            ok=r.exit_code == 0,
            exit_code=r.exit_code,
        )
    common = logs.find_common(service)
    if common.stdout.strip() and common.stdout.strip() != "none":
        first = common.stdout.splitlines()[0]
        tail = logs.file_tail(first, lines=limit)
        return ToolResult(
            tool="service.logs",
            stdout=tail.stdout,
            stderr="journal unavailable; tailed common log",
            ok=tail.ok,
            exit_code=tail.exit_code,
        )
    return ToolResult(
        tool="service.logs",
        ok=False,
        exit_code=1,
        stderr="journal unavailable; common log paths unavailable",
    )


def nginx_detect() -> list[ToolResult]:
    return [
        manager_detect(),
        status("nginx"),
        processes("nginx"),
        ports("nginx"),
        config_hints("nginx"),
        service_logs("nginx"),
    ]


def ssh_detect() -> list[ToolResult]:
    return [
        manager_detect(),
        status("ssh"),
        processes("sshd"),
        ports("ssh"),
        config_hints("ssh"),
        service_logs("ssh"),
    ]


def docker_detect() -> list[ToolResult]:
    return [
        manager_detect(),
        status("docker"),
        processes("dockerd"),
        ports("docker"),
        config_hints("docker"),
        service_logs("docker"),
    ]
