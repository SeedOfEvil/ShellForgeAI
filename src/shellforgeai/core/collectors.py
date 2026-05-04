from __future__ import annotations

from ast import literal_eval

from shellforgeai.core.evidence import EvidenceCategory, EvidenceItem
from shellforgeai.knowledge.audits import search_recent_audits
from shellforgeai.knowledge.search import search_local
from shellforgeai.tools import (
    disk,
    files,
    firewall,
    host,
    journal,
    network,
    process,
    storage,
    system,
    systemd,
)
from shellforgeai.tools.services import docker_detect, nginx_detect, ssh_detect
from shellforgeai.util.text import truncate_text


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
    if result.tool == "host.info" and "hostname" in result.stdout:
        return result.stdout.replace("'", "").replace("{", "").replace("}", "")[:120]
    if result.tool == "system.cpu_memory" and result.stdout.strip().startswith("{"):
        data = literal_eval(result.stdout)
        return (
            f"cpus={data.get('cpus', '?')} "
            f"mem_used={data.get('mem_used_mb', '?')}/{data.get('mem_total_mb', '?')}MB "
            f"swap_used={data.get('swap_used_mb', '?')}/{data.get('swap_total_mb', '?')}MB"
        )
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
        return first.replace("{'loadavg': ", "loadavg=").replace("}", "")
    if result.tool == "network.listeners":
        rows = max(0, len((result.stdout or "").splitlines()) - 1)
        return "no listening sockets" if rows == 0 else f"{rows} listening sockets"
    if result.tool == "network.listeners.filtered":
        port = result.command[-1] if result.command else "port"
        return f"port {port.lstrip(':')}: {'listener found' if first else 'no listener'}"
    if result.tool == "files.exists":
        path = result.command[-1] if result.command else "path"
        return f"{path}: {'exists' if result.ok else 'missing'}"
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
    items = [
        _to_item(
            systemd.status(service_name), EvidenceCategory.service, f"systemd status {service_name}"
        ),
        _to_item(
            journal.unit(service_name, since=since),
            EvidenceCategory.logs,
            f"Journal for {service_name}",
        ),
        _to_item(systemd.list_failed(), EvidenceCategory.service, "Failed systemd units"),
    ]
    if not items[0].ok:
        items.append(
            _to_item(
                host.command_exists(service_name),
                EvidenceCategory.service,
                f"command exists {service_name}",
            )
        )
        items.append(
            _to_item(
                process.find(service_name), EvidenceCategory.service, f"process find {service_name}"
            )
        )
        if service_name.lower() == "nginx":
            items.append(
                _to_item(
                    network.listeners_filtered(":80"),
                    EvidenceCategory.network,
                    "nginx likely listener 80",
                )
            )
            items.append(
                _to_item(
                    network.listeners_filtered(":443"),
                    EvidenceCategory.network,
                    "nginx likely listener 443",
                )
            )
            items.append(
                _to_item(
                    files.stat("/etc/nginx/nginx.conf"), EvidenceCategory.files, "nginx config path"
                )
            )
            items.append(
                _to_item(files.stat("/var/log/nginx"), EvidenceCategory.files, "nginx log dir")
            )
    return items


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
        _to_item(network.listeners(), EvidenceCategory.network, "Listeners"),
        _to_item(network.routes(), EvidenceCategory.network, "Routes"),
        _to_item(network.dns(), EvidenceCategory.network, "DNS config"),
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


def collect_nginx_evidence(context) -> list[EvidenceItem]:
    return [_to_item(r, EvidenceCategory.service, "nginx collector") for r in nginx_detect()]


def collect_ssh_evidence(context) -> list[EvidenceItem]:
    return [_to_item(r, EvidenceCategory.service, "ssh collector") for r in ssh_detect()]


def collect_docker_evidence(context) -> list[EvidenceItem]:
    return _dedupe_items(
        [_to_item(r, EvidenceCategory.service, "docker collector") for r in docker_detect()]
    )


def collect_firewall_evidence(context) -> list[EvidenceItem]:
    return _dedupe_items(
        [_to_item(r, EvidenceCategory.network, "firewall collector") for r in firewall.detect()]
    )


def collect_storage_evidence(context) -> list[EvidenceItem]:
    return [
        _to_item(storage.context(), EvidenceCategory.host, "Storage context"),
        _to_item(storage.pressure(), EvidenceCategory.host, "Storage pressure"),
        _to_item(storage.error_summary(), EvidenceCategory.logs, "Storage errors"),
    ]
