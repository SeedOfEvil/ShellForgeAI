from __future__ import annotations

import json
from ast import literal_eval
from typing import Any

from shellforgeai.core.evidence import EvidenceCategory, EvidenceItem
from shellforgeai.knowledge.audits import search_recent_audits
from shellforgeai.knowledge.search import search_local
from shellforgeai.platform_detection import PlatformInfo, detect_platform
from shellforgeai.tools import (
    audit_recent,
    configs,
    containers,
    disk,
    files,
    firewall,
    host,
    logs,
    network,
    packages,
    process,
    services,
    storage,
    system,
    systemd,
)
from shellforgeai.tools.services import docker_detect, nginx_detect, ssh_detect
from shellforgeai.util.text import truncate_text
from shellforgeai.windows_disks import windows_disks_payload
from shellforgeai.windows_memory import windows_memory_payload, windows_memory_summary
from shellforgeai.windows_status import windows_status_payload

PARSE_FAILED: Any = object()
"""Sentinel returned by :func:`parse_collector_payload` when parsing fails.

Distinct from ``None`` because JSON ``null`` legitimately parses to ``None``.
"""


def parse_collector_payload(text: str | None, default: Any = PARSE_FAILED) -> Any:
    """Parse collector stdout that may be JSON or a legacy Python literal.

    Most collector tools emit JSON, which allows ``null``/``true``/``false`` —
    values ``ast.literal_eval`` rejects with ``ValueError: malformed node or
    string``. ``json.loads`` is tried first; ``ast.literal_eval`` remains as a
    fallback for legacy ``str(dict)`` payloads such as ``host.info``. When
    neither parser accepts the payload, ``default`` is returned so callers can
    degrade to a safe summary instead of crashing.
    """
    if not isinstance(text, str):
        return default
    candidate = text.strip()
    if not candidate:
        return default
    try:
        return json.loads(candidate)
    except ValueError:
        pass
    try:
        return literal_eval(candidate)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return default


def _payload_mapping(text: str | None) -> dict:
    """Parse a collector payload expected to be a mapping; ``{}`` on failure."""
    data = parse_collector_payload(text, default=None)
    return data if isinstance(data, dict) else {}


def _payload_float(value: Any, default: float = 0.0) -> float:
    """Coerce a payload field to float, treating null/non-numeric as default."""
    if value is None or isinstance(value, bool):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _summarize(result) -> str:
    first = (
        (result.stderr or result.stdout or "").splitlines()[0]
        if (result.stderr or result.stdout)
        else ""
    )
    if result.tool == "command.exists":
        cmd = result.command[-1] if result.command else "command"
        return (
            f"{cmd}: found at {result.stdout.strip()}"
            if result.stdout.strip()
            else f"{cmd}: not found"
        )
    if result.tool == "system.os_release" and result.stdout.strip().startswith("{"):
        data = _payload_mapping(result.stdout)
        name = data.get("name") or "Unknown"
        ver = str(data.get("version") or "").strip()
        pretty = f"{name} {ver}".strip()
        return pretty if pretty else "os release unavailable"
    if result.tool == "host.info" and "hostname" in result.stdout:
        return result.stdout.replace("'", "").replace("{", "").replace("}", "")[:120]
    if result.tool == "system.cpu_memory" and result.stdout.strip().startswith("{"):
        data = _payload_mapping(result.stdout)
        if not data:
            return "cpu/memory summary unavailable"
        mem_used = _payload_float(data.get("mem_used_mb")) / 1024
        mem_total = _payload_float(data.get("mem_total_mb")) / 1024
        cpus = data.get("cpus")
        cpus_text = cpus if cpus is not None else "?"
        if mem_total <= 0:
            # Never render fake "0.0GiB/0.0GiB" as if it were valid evidence.
            return f"cpus={cpus_text} memory summary unavailable from this collector"
        swap_used = _payload_float(data.get("swap_used_mb"))
        swap_total = _payload_float(data.get("swap_total_mb")) / 1024
        swap_text = "swap=0B/0B"
        if swap_total > 0:
            swap_text = (
                f"swap=0B/{swap_total:.1f}GiB"
                if swap_used <= 0.01
                else f"swap={swap_used / 1024:.1f}GiB/{swap_total:.1f}GiB"
            )
        return f"cpus={cpus_text} mem={mem_used:.1f}GiB/{mem_total:.1f}GiB {swap_text}"
    if result.tool == "system.container_detect":
        val = (result.stdout or "").strip().replace("\n", " ")
        return f"container={val}" if val else "container=unknown"
    if result.tool in {"disk.usage", "disk.inodes"}:
        vals = []
        for ln in (result.stdout or "").splitlines()[1:4]:
            parts = ln.split()
            if len(parts) >= 6:
                vals.append(f"{parts[5]} {parts[4]} used")
        return ", ".join(vals) or (first or "unavailable")
    if result.tool == "network.routes":
        return first or "route summary unavailable"
    if result.tool.startswith("process.find"):
        target = result.tool.split(" ", 1)[1] if " " in result.tool else "process"
        if result.ok and (result.stdout or "").splitlines():
            pid = (result.stdout.splitlines()[0].split() or ["?"])[0]
            return f"found {target} pid={pid}"
        return f"no matching {target} process"
    if result.tool == "host.resources":
        if "loadavg" in first:
            val = first.split("loadavg", 1)[-1]
            val = val.replace(":", "=").replace("(", "").replace(")", "").replace(" ", "")
            if "None" in val:
                # os.getloadavg is unavailable (e.g. Windows); do not render
                # "loadavg=None" as if it were a valid metric.
                return "load average unavailable from this collector"
            return val
        return first
    if result.tool == "network.listeners":
        lines = (result.stdout or "").splitlines()
        data = lines[1:] if len(lines) > 1 else lines
        ports = []
        for ln in data:
            parts = ln.split()
            if len(parts) >= 5:
                local = parts[4]
                if ":" in local:
                    ports.append(local.rsplit(":", 1)[-1])
        uniq = []
        for p in ports:
            if p not in uniq:
                uniq.append(p)
        rows = len(data)
        if rows == 0:
            return "no listening sockets"
        shown = ",".join(uniq[:6]) if uniq else "unknown"
        return f"{rows} listening sockets ports={shown}"
    if result.tool == "network.listeners.filtered":
        port = result.command[-1] if result.command else "port"
        return f"port {port.lstrip(':')}: {'listener found' if first else 'no listener'}"
    if result.tool == "storage.mount_target":
        return (result.stdout or "mount target unavailable").strip()[:180]
    if result.tool == "files.exists":
        path = result.command[-1] if result.command else "path"
        return f"{path}: {'exists' if result.ok else 'missing'}"
    if result.tool == "files.stat" and (result.stdout or "").startswith("{"):
        data = _payload_mapping(result.stdout)
        if not data.get("exists"):
            return f"{data.get('path', 'path')}: missing"
        return (
            f"{data.get('path', 'path')}: owner={data.get('owner')}:{data.get('group')} "
            f"mode={data.get('mode')} exec={'yes' if data.get('executable') else 'no'}"
        )
    if result.tool == "process.top":
        if not result.ok or not result.stdout.strip():
            return "process details unavailable from this context"
        lines = result.stdout.splitlines()
        if len(lines) < 2:
            return "process details unavailable from this context"
        top = lines[1].split()
        if len(top) >= 5:
            return f"top_cpu={top[4]} pid={top[0]} cpu={top[2]}%"
        return "process details unavailable from this context"
    if result.tool == "process.snapshot":
        return (result.stdout or "process snapshot unavailable").strip()
    if result.tool == "storage.context":
        return (result.stderr or "storage context available").strip()
    if result.tool == "storage.pressure":
        return result.stdout.splitlines()[0] if result.stdout else "storage pressure unavailable"
    if result.tool == "storage.error_summary":
        return (
            result.stdout.splitlines()[0] if result.stdout else "storage error summary unavailable"
        )
    if result.tool == "system.pressure":
        return "pressure samples collected" if result.ok else "pressure unavailable"
    if result.tool == "package.query" and (result.stdout or "").strip().startswith("{"):
        try:
            data = json.loads(result.stdout)
        except (ValueError, json.JSONDecodeError):
            data = {}
        inst = data.get("installed")
        pkg = data.get("package_name") or data.get("query") or "package"
        ver = data.get("version")
        if inst is True:
            return f"{pkg} installed" + (f" version={ver}" if ver else "")
        if inst is False:
            return f"{pkg} not installed"
        return f"{pkg} install status unknown"
    if result.tool == "package.file_owner" and (result.stdout or "").strip().startswith("{"):
        try:
            data = json.loads(result.stdout)
        except (ValueError, json.JSONDecodeError):
            data = {}
        status = data.get("owner_status")
        path = data.get("path") or "path"
        if status == "owned":
            return f"{path} owned by {data.get('owner_package') or 'package'}"
        if status == "path_missing":
            return f"{path} is missing"
        if status == "not_owned":
            return f"{path} has no installed package owner"
        return f"{path} ownership unavailable"
    if result.tool == "network.dns" and "nameserver" in (result.stdout or ""):
        ns = [ln.split()[1] for ln in result.stdout.splitlines() if ln.startswith("nameserver")]
        return (
            f"docker resolver {ns[0]}"
            if ns and ns[0] == "127.0.0.11"
            else (f"nameservers={','.join(ns)}" if ns else "dns unavailable")
        )
    return first[:120] if first else ("ok" if result.ok else "unavailable")


def _status_for_result(result) -> str:
    if result.tool == "command.exists":
        return "ok" if result.stdout.strip() else "not_found"
    if result.tool.startswith("process.find"):
        return "ok" if result.ok else "not_found"
    if not result.ok and "permission denied" in (result.stderr or "").lower():
        return "denied"
    return "ok" if result.ok else "unavailable"


def _dedupe_items(items: list[EvidenceItem]) -> list[EvidenceItem]:
    seen = set()
    out = []
    for i in items:
        key = (i.source, i.path or "", str(i.metadata.get("target", "")), " ".join(i.command or []))
        if key in seen:
            continue
        seen.add(key)
        out.append(i)
    return out


def _to_item(result, category: EvidenceCategory, title: str) -> EvidenceItem:
    content, truncated = truncate_text(result.stdout or result.stderr)
    return EvidenceItem(
        source=(
            f"{result.tool} {result.command[-1]}"
            if result.tool == "command.exists" and result.command
            else result.tool
        ),
        category=category,
        command=result.command,
        ok=result.ok,
        exit_code=result.exit_code,
        title=title,
        summary=_summarize(result),
        content=content,
        truncated=truncated,
        metadata={"status": _status_for_result(result)},
    )


def collect_host_evidence(context) -> list[EvidenceItem]:
    return [
        _to_item(host.host_info(), EvidenceCategory.host, "Host information"),
        _to_item(host.host_resources(), EvidenceCategory.host, "Host resources"),
        _to_item(host.host_uptime(), EvidenceCategory.host, "Host uptime"),
    ]


def collect_service_evidence(context, service_name: str, since: str = "30m") -> list[EvidenceItem]:
    target = service_name.lower().strip()
    items = [
        _to_item(system.container_detect(), EvidenceCategory.host, "Container detection"),
        _to_item(services.manager_detect(), EvidenceCategory.service, "Service manager context"),
        _to_item(network.listeners(), EvidenceCategory.network, "Listeners"),
        _to_item(process.snapshot(), EvidenceCategory.host, "Process snapshot"),
        _to_item(process.top(), EvidenceCategory.host, "Top processes"),
    ]
    if target in {"services", "service-discovery", "ports", "listening"}:
        for daemon in ["nginx", "ssh", "docker", "caddy", "redis", "postgres", "mysql"]:
            items.append(
                _to_item(
                    services.processes(daemon),
                    EvidenceCategory.host,
                    f"{daemon} process check",
                )
            )
        return _dedupe_items(items)

    items.extend(
        [
            _to_item(
                services.status(service_name), EvidenceCategory.service, f"{service_name} status"
            ),
            _to_item(
                services.unit_file(service_name),
                EvidenceCategory.service,
                f"{service_name} unit file",
            ),
            _to_item(
                services.processes(service_name),
                EvidenceCategory.host,
                f"{service_name} processes",
            ),
            _to_item(
                services.ports(service_name), EvidenceCategory.network, f"{service_name} listeners"
            ),
            _to_item(
                services.config_hints(service_name),
                EvidenceCategory.files,
                f"{service_name} config hints",
            ),
            _to_item(
                services.service_logs(service_name, since=since),
                EvidenceCategory.logs,
                f"{service_name} logs",
            ),
        ]
    )
    return _dedupe_items(items)


def collect_disk_evidence(context) -> list[EvidenceItem]:
    items = [
        _to_item(host.host_info(), EvidenceCategory.host, "Host information"),
        _to_item(host.host_resources(), EvidenceCategory.host, "Host resources"),
        _to_item(disk.usage(), EvidenceCategory.host, "Disk usage"),
        _to_item(disk.inodes(), EvidenceCategory.host, "Inode usage"),
    ]
    for hit in search_recent_audits(context.session.data_dir, query="disk inode space", limit=5):
        items.append(
            EvidenceItem(
                source="audit.recent",
                category=EvidenceCategory.knowledge,
                title="Recent disk context",
                summary=f"{hit.get('session_id', 'unknown')}: {hit.get('summary', 'no summary')}"[
                    :160
                ],
                content=str(hit),
                metadata={"status": "ok"},
            )
        )
    return _dedupe_items(items)


def collect_network_evidence(context) -> list[EvidenceItem]:
    return [
        _to_item(host.host_info(), EvidenceCategory.host, "Host information"),
        _to_item(host.host_resources(), EvidenceCategory.host, "Host resources"),
        _to_item(system.container_detect(), EvidenceCategory.host, "Container detection"),
        _to_item(
            network.namespace_context(), EvidenceCategory.network, "Network namespace context"
        ),
        _to_item(network.interfaces(), EvidenceCategory.network, "Interfaces"),
        _to_item(network.default_route(), EvidenceCategory.network, "Default route"),
        _to_item(network.dns(), EvidenceCategory.network, "DNS config"),
        _to_item(network.resolution_test(), EvidenceCategory.network, "DNS resolution test"),
        _to_item(network.listeners(), EvidenceCategory.network, "Listeners"),
        _to_item(network.firewall_context(), EvidenceCategory.network, "Firewall context"),
    ]


def collect_local_knowledge_evidence(context, query: str) -> list[EvidenceItem]:
    hits = search_local(context.settings.knowledge.local_paths, query)
    text = "\n".join(f"{h.path}:{h.line} {h.snippet}" for h in hits) or "No local knowledge hits"
    return [
        EvidenceItem(
            source="knowledge.search_local",
            category=EvidenceCategory.knowledge,
            title=f"Local knowledge: {query}",
            summary=f"{len(hits)} hits",
            content=text,
        )
    ]


def collect_health_evidence(context) -> list[EvidenceItem]:
    items = (
        [
            _to_item(system.os_release(), EvidenceCategory.host, "OS release"),
            _to_item(system.cpu_memory(), EvidenceCategory.host, "CPU/memory"),
            _to_item(system.container_detect(), EvidenceCategory.host, "Container detection"),
        ]
        + collect_host_evidence(context)
        + collect_disk_evidence(context)
        + collect_network_evidence(context)
        + [_to_item(process.top(), EvidenceCategory.host, "Top processes")]
        + [_to_item(process.snapshot(), EvidenceCategory.host, "Process snapshot")]
        + collect_storage_evidence(context)
        + [_to_item(systemd.list_failed(), EvidenceCategory.service, "Failed systemd units")]
    )
    for hit in search_recent_audits(context.session.data_dir, query="health glitch slow", limit=5):
        items.append(
            EvidenceItem(
                source="audit.recent",
                category=EvidenceCategory.knowledge,
                title="Recent health context",
                summary=f"{hit.get('session_id', 'unknown')}: {hit.get('summary', 'no summary')}"[
                    :160
                ],
                content=str(hit),
                metadata={"status": "ok"},
            )
        )
    return _dedupe_items(items)


def collect_performance_evidence(context) -> list[EvidenceItem]:
    items = [
        _to_item(host.host_info(), EvidenceCategory.host, "Host information"),
        _to_item(host.host_uptime(), EvidenceCategory.host, "Host uptime"),
        _to_item(host.host_resources(), EvidenceCategory.host, "Host resources"),
        _to_item(system.os_release(), EvidenceCategory.host, "OS release"),
        _to_item(system.cpu_memory(), EvidenceCategory.host, "CPU/memory"),
        _to_item(system.container_detect(), EvidenceCategory.host, "Container detection"),
        _to_item(disk.usage(), EvidenceCategory.host, "Disk usage"),
        _to_item(disk.inodes(), EvidenceCategory.host, "Inode usage"),
        _to_item(process.top(), EvidenceCategory.host, "Top processes"),
        _to_item(process.io(), EvidenceCategory.host, "Process I/O"),
        _to_item(system.pressure(), EvidenceCategory.host, "Pressure"),
        _to_item(system.cgroup_limits(), EvidenceCategory.host, "Cgroup limits"),
        _to_item(storage.mounts(), EvidenceCategory.host, "Storage mounts"),
        _to_item(audit_recent.recent(), EvidenceCategory.knowledge, "Recent audit trend"),
        _to_item(systemd.list_failed(), EvidenceCategory.service, "Failed systemd units"),
    ]
    for hit in search_recent_audits(
        context.session.data_dir, query="disk performance network", limit=5
    ):
        items.append(
            EvidenceItem(
                source="audit.recent",
                category=EvidenceCategory.knowledge,
                title="Recent audit context",
                summary=f"{hit.get('session_id', 'unknown')}: {hit.get('summary', 'no summary')}"[
                    :160
                ],
                content=str(hit),
                metadata={"status": "ok"},
            )
        )
    return _dedupe_items(items)


LINUX_ONLY_COLLECTOR_SKIP_STATUS = "linux_only_collector_skipped"
WINDOWS_METRIC_UNAVAILABLE_STATUS = "windows_metric_unavailable"
NOT_COLLECTED_ON_WINDOWS_REASON = "not_collected_on_windows"

WINDOWS_PERFORMANCE_NEXT_SAFE_COMMANDS: tuple[str, ...] = (
    "shellforgeai windows status --json",
    "shellforgeai windows disks --json",
    "shellforgeai windows processes --json --limit 10",
)

# Linux-oriented performance collectors that must never execute on Windows.
# Each entry is (source, title, mechanism) where mechanism names the Linux
# command or path the collector would otherwise touch.
LINUX_ONLY_PERFORMANCE_COLLECTOR_SKIPS: tuple[tuple[str, str, str], ...] = (
    ("host.uptime", "Host uptime", "uptime"),
    ("disk.usage", "Disk usage", "df"),
    ("disk.inodes", "Inode usage", "df -i"),
    ("network.interfaces", "Interfaces", "ip addr"),
    ("network.default_route", "Default route", "ip route"),
    ("network.dns", "DNS config", "/etc/resolv.conf"),
    ("network.listeners", "Listeners", "ss"),
    ("process.top", "Top processes", "ps"),
    ("process.io", "Process I/O", "/proc I/O counters"),
    ("system.os_release", "OS release", "/etc/os-release"),
    ("system.container_detect", "Container detection", "/proc/1/cgroup"),
    ("system.pressure", "Pressure", "/proc/pressure"),
    ("system.cgroup_limits", "Cgroup limits", "/sys/fs/cgroup"),
    ("storage.mounts", "Storage mounts", "/proc/mounts"),
    ("systemd.list_failed", "Failed systemd units", "systemctl"),
)


def _linux_only_skip_item(source: str, title: str, mechanism: str) -> EvidenceItem:
    """Structured, non-scary skip record for a Linux-only collector on Windows."""
    return EvidenceItem(
        source=source,
        category=EvidenceCategory.host,
        ok=True,
        title=title,
        summary=f"Linux-only collector skipped on Windows: {title} ({mechanism})",
        content=json.dumps(
            {
                "status": LINUX_ONLY_COLLECTOR_SKIP_STATUS,
                "reason": NOT_COLLECTED_ON_WINDOWS_REASON,
                "collector": source,
                "mechanism": mechanism,
            }
        ),
        metadata={"status": LINUX_ONLY_COLLECTOR_SKIP_STATUS, "platform": "windows"},
    )


def _windows_metric_unavailable_item(source: str, title: str, summary: str) -> EvidenceItem:
    """Explicit unavailable marker instead of fake zero/None metric values."""
    return EvidenceItem(
        source=source,
        category=EvidenceCategory.host,
        ok=True,
        title=title,
        summary=summary,
        content=json.dumps(
            {
                "status": WINDOWS_METRIC_UNAVAILABLE_STATUS,
                "reason": NOT_COLLECTED_ON_WINDOWS_REASON,
            }
        ),
        metadata={"status": WINDOWS_METRIC_UNAVAILABLE_STATUS, "platform": "windows"},
    )


def _bytes_gib(value: Any) -> str:
    try:
        return f"{float(value) / (1024**3):.1f}GiB"
    except (TypeError, ValueError):
        return "unknown"


def _windows_status_summary(payload: dict) -> str:
    host_block = payload.get("host") or {}
    fs = payload.get("filesystem") or {}
    root = fs.get("root_usage") or {}
    free = root.get("free_bytes")
    total = root.get("total_bytes")
    hostname = host_block.get("hostname") or "unknown"
    if isinstance(free, int) and isinstance(total, int) and total > 0:
        return f"hostname={hostname} root_free={_bytes_gib(free)}/{_bytes_gib(total)}"
    return f"hostname={hostname} (read-only Windows status collected)"


def _windows_disks_summary(payload: dict) -> str:
    summary = payload.get("summary") or {}
    returned = summary.get("returned_roots")
    available = summary.get("available_roots")
    if isinstance(returned, int) and isinstance(available, int):
        primary_free = summary.get("primary_root_free_bytes")
        free_suffix = (
            f" primary_root_free={_bytes_gib(primary_free)}" if primary_free is not None else ""
        )
        return f"drive_roots={returned} available={available}{free_suffix} (stdlib read-only)"
    return "windows disks preview collected (read-only)"


def _windows_memory_item(info: PlatformInfo) -> EvidenceItem:
    """Reuse the read-only Windows memory summary as ``system.cpu_memory`` evidence.

    When physical-memory facts are collectible the item carries an honest
    Windows-native memory posture; otherwise it degrades to the explicit
    unavailable marker instead of a fake ``0.0GiB/0.0GiB`` value.
    """
    try:
        payload = windows_memory_payload(info)
    except Exception:  # memory reuse must never crash the diagnosis route
        payload = {}
    memory = payload.get("memory") if isinstance(payload, dict) else None
    if isinstance(memory, dict) and memory.get("available"):
        content, truncated = truncate_text(json.dumps(payload))
        return EvidenceItem(
            source="system.cpu_memory",
            category=EvidenceCategory.host,
            ok=True,
            title="CPU/memory",
            summary=windows_memory_summary(payload),
            content=content,
            truncated=truncated,
            metadata={"status": "ok", "platform": "windows"},
        )
    return _windows_metric_unavailable_item(
        "system.cpu_memory",
        "CPU/memory",
        "Memory summary unavailable from this collector on Windows",
    )


def _windows_payload_item(source: str, title: str, builder, summarizer) -> EvidenceItem:
    """Reuse an existing safe Windows payload as evidence; degrade without tracebacks."""
    try:
        payload = builder()
    except Exception as exc:  # payload reuse must never crash the diagnosis route
        return _windows_metric_unavailable_item(
            source,
            title,
            f"{title} unavailable from this collector "
            f"({WINDOWS_METRIC_UNAVAILABLE_STATUS}: {type(exc).__name__})",
        )
    if not isinstance(payload, dict) or payload.get("status") not in {"ok", "limited"}:
        return _windows_metric_unavailable_item(
            source, title, f"{title} unavailable from this collector"
        )
    content, truncated = truncate_text(json.dumps(payload))
    return EvidenceItem(
        source=source,
        category=EvidenceCategory.host,
        ok=True,
        title=title,
        summary=summarizer(payload),
        content=content,
        truncated=truncated,
        metadata={"status": "ok", "platform": "windows"},
    )


def collect_windows_performance_evidence(
    context, info: PlatformInfo | None = None
) -> list[EvidenceItem]:
    """Windows-aware slow-system evidence: bounded, read-only, no new collection.

    Linux-only collectors are recorded as structured skips instead of running.
    Missing metrics (load average, /proc-based memory) are rendered as explicit
    unavailable markers rather than ``loadavg=None`` or ``0.0GiB/0.0GiB``. The
    only payloads reused are the existing stdlib-only ``windows status`` and
    ``windows disks`` read-only payloads; no shell execution, no remoting, and
    no mutation is involved.
    """
    info = info or detect_platform()
    items: list[EvidenceItem] = [
        EvidenceItem(
            source="platform.detect",
            category=EvidenceCategory.host,
            ok=True,
            title="Platform detection",
            summary=(
                f"Windows host detected ({info.release or 'unknown release'}); "
                "Linux-only collectors are skipped"
            ),
            content=json.dumps(info.to_dict()),
            metadata={"status": "ok", "platform": "windows"},
        ),
        _to_item(host.host_info(), EvidenceCategory.host, "Host information"),
        _windows_payload_item(
            "windows.status",
            "Windows status (read-only)",
            lambda: windows_status_payload(info),
            _windows_status_summary,
        ),
        _windows_payload_item(
            "windows.disks",
            "Windows disks preview (read-only)",
            lambda: windows_disks_payload(info),
            _windows_disks_summary,
        ),
        _windows_metric_unavailable_item(
            "host.resources",
            "Host resources",
            "Load average is not available on Windows",
        ),
        _windows_memory_item(info),
    ]
    items.extend(
        _linux_only_skip_item(source, title, mechanism)
        for source, title, mechanism in LINUX_ONLY_PERFORMANCE_COLLECTOR_SKIPS
    )
    return _dedupe_items(items)


def collect_nginx_evidence(context) -> list[EvidenceItem]:
    return [_to_item(r, EvidenceCategory.service, "nginx collector") for r in nginx_detect()]


def collect_ssh_evidence(context) -> list[EvidenceItem]:
    return [_to_item(r, EvidenceCategory.service, "ssh collector") for r in ssh_detect()]


def collect_docker_evidence(context) -> list[EvidenceItem]:
    items = [_to_item(r, EvidenceCategory.service, "docker collector") for r in docker_detect()]
    items.extend(collect_docker_problem_evidence(context))
    return _dedupe_items(items)


def collect_firewall_evidence(context) -> list[EvidenceItem]:
    return _dedupe_items(
        [_to_item(r, EvidenceCategory.network, "firewall collector") for r in firewall.detect()]
    )


def collect_docker_problem_evidence(context) -> list[EvidenceItem]:
    items = [_to_item(containers.containers(), EvidenceCategory.host, "Container inventory")]
    summary = containers.problem_summary()
    items.append(_to_item(summary, EvidenceCategory.logs, "Container problem summary"))
    if summary.ok and summary.stdout:
        try:
            payload = json.loads(summary.stdout)
        except (ValueError, json.JSONDecodeError):
            payload = {}
        for entry in (payload.get("failing", []) or [])[:6]:
            name = entry.get("name") or ""
            if not name:
                continue
            items.append(
                _to_item(
                    containers.container_logs(name, tail=120),
                    EvidenceCategory.logs,
                    f"{name} logs",
                )
            )
    return items


def collect_logs_basic_evidence(context) -> list[EvidenceItem]:
    items = [
        _to_item(host.host_info(), EvidenceCategory.host, "Host information"),
        _to_item(host.host_resources(), EvidenceCategory.host, "Host resources"),
        _to_item(system.container_detect(), EvidenceCategory.host, "Container detection"),
        _to_item(services.manager_detect(), EvidenceCategory.service, "Service manager context"),
        _to_item(logs.common_paths(), EvidenceCategory.logs, "Common log paths"),
        _to_item(logs.recent_errors(), EvidenceCategory.logs, "Recent error scan"),
        _to_item(logs.kernel_errors(), EvidenceCategory.logs, "Kernel error scan"),
        _to_item(logs.auth_errors(), EvidenceCategory.logs, "Auth error scan"),
        _to_item(audit_recent.recent(), EvidenceCategory.knowledge, "Recent audit trend"),
    ]
    items.extend(collect_docker_problem_evidence(context))
    recent = logs.recent_errors()
    try:
        payload = json.loads(recent.stdout) if recent.stdout.strip().startswith("{") else None
    except (ValueError, json.JSONDecodeError):
        payload = None
    if isinstance(payload, dict):
        themes = logs.error_themes(sources_payload=payload)
        items.append(_to_item(themes, EvidenceCategory.logs, "Error themes"))
    return _dedupe_items(items)


def collect_logs_service_evidence(
    context, service_name: str, since: str = "30m"
) -> list[EvidenceItem]:
    target = service_name.lower().strip() or "service-discovery"
    items = collect_logs_basic_evidence(context)
    items.extend(
        [
            _to_item(services.status(target), EvidenceCategory.service, f"{target} status"),
            _to_item(services.processes(target), EvidenceCategory.host, f"{target} processes"),
            _to_item(
                services.service_logs(target, since=since),
                EvidenceCategory.logs,
                f"{target} logs",
            ),
            _to_item(
                logs.service_errors(target, since=since),
                EvidenceCategory.logs,
                f"{target} log errors",
            ),
        ]
    )
    return _dedupe_items(items)


def collect_logs_auth_evidence(context) -> list[EvidenceItem]:
    items = [
        _to_item(system.container_detect(), EvidenceCategory.host, "Container detection"),
        _to_item(logs.common_paths(), EvidenceCategory.logs, "Common log paths"),
        _to_item(logs.auth_errors(), EvidenceCategory.logs, "Auth error scan"),
        _to_item(services.status("ssh"), EvidenceCategory.service, "ssh status"),
        _to_item(services.ports("ssh"), EvidenceCategory.network, "ssh listeners"),
    ]
    auth = logs.auth_errors()
    try:
        payload = json.loads(auth.stdout) if auth.stdout.strip().startswith("{") else None
    except (ValueError, json.JSONDecodeError):
        payload = None
    if isinstance(payload, dict):
        themes = logs.error_themes(sources_payload=payload)
        items.append(_to_item(themes, EvidenceCategory.logs, "Auth error themes"))
    return _dedupe_items(items)


def collect_logs_deep_dive_evidence(context) -> list[EvidenceItem]:
    items = collect_logs_basic_evidence(context)
    items.extend(
        [
            _to_item(
                logs.recent_errors(max_files=12, max_bytes_per_file=131072),
                EvidenceCategory.logs,
                "Expanded recent error scan",
            ),
            _to_item(audit_recent.recent(), EvidenceCategory.knowledge, "Recent audit trend"),
        ]
    )
    return _dedupe_items(items)


def collect_storage_evidence(context) -> list[EvidenceItem]:
    return [
        _to_item(storage.context(), EvidenceCategory.host, "Storage context"),
        _to_item(storage.pressure(), EvidenceCategory.host, "Storage pressure"),
        _to_item(storage.error_summary(), EvidenceCategory.logs, "Storage errors"),
    ]


def collect_package_evidence(context, target: str = "", owner_path: str = "") -> list[EvidenceItem]:
    items = [
        _to_item(packages.manager_detect(), EvidenceCategory.packages, "Package manager detection"),
        _to_item(packages.recent_history(), EvidenceCategory.packages, "Recent package history"),
    ]
    if target:
        items.append(
            _to_item(packages.query(target), EvidenceCategory.packages, f"Package query: {target}")
        )
    if owner_path:
        items.append(
            _to_item(
                packages.file_owner(owner_path),
                EvidenceCategory.packages,
                f"Package owner for {owner_path}",
            )
        )
    return _dedupe_items(items)


def collect_config_evidence(context, target: str = "") -> list[EvidenceItem]:
    t = target or "nginx"
    items = [
        _to_item(configs.find_common(t), EvidenceCategory.files, f"Common config paths for {t}"),
        _to_item(configs.recent_changes(), EvidenceCategory.files, "Recent config changes"),
    ]
    return _dedupe_items(items)


def collect_path_ownership_evidence(context, path: str) -> list[EvidenceItem]:
    return [
        _to_item(files.stat(path), EvidenceCategory.files, f"Path stat: {path}"),
        _to_item(storage.mounts(path), EvidenceCategory.host, f"Storage mounts: {path}"),
    ]
