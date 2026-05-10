from __future__ import annotations

import json
from ast import literal_eval

from shellforgeai.core.evidence import EvidenceCategory, EvidenceItem
from shellforgeai.knowledge.audits import search_recent_audits
from shellforgeai.knowledge.search import search_local
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
        data = literal_eval(result.stdout)
        name = data.get("name", "Unknown")
        ver = data.get("version", "").strip()
        pretty = f"{name} {ver}".strip()
        return pretty if pretty else "os release unavailable"
    if result.tool == "host.info" and "hostname" in result.stdout:
        return result.stdout.replace("'", "").replace("{", "").replace("}", "")[:120]
    if result.tool == "system.cpu_memory" and result.stdout.strip().startswith("{"):
        data = literal_eval(result.stdout)
        mem_used = float(data.get("mem_used_mb", 0)) / 1024
        mem_total = float(data.get("mem_total_mb", 0)) / 1024
        swap_used = float(data.get("swap_used_mb", 0))
        swap_total = float(data.get("swap_total_mb", 0)) / 1024
        swap_text = "swap=0B/0B"
        if swap_total > 0:
            swap_text = (
                f"swap=0B/{swap_total:.1f}GiB"
                if swap_used <= 0.01
                else f"swap={swap_used / 1024:.1f}GiB/{swap_total:.1f}GiB"
            )
        return f"cpus={data.get('cpus', '?')} mem={mem_used:.1f}GiB/{mem_total:.1f}GiB {swap_text}"
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
            return val.replace(":", "=").replace("(", "").replace(")", "").replace(" ", "")
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
        try:
            data = literal_eval(result.stdout)
        except (ValueError, SyntaxError):
            data = {}
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
