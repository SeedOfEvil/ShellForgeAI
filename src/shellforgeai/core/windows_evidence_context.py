"""Windows interactive evidence-context parity (PR289).

Shared by the ``ask`` command and the interactive REPL model fallback so
Windows model-backed answers are grounded in actual host evidence instead of
project/policy preamble. This module only builds a bounded read-only evidence
packet by reusing the existing stdlib-only Windows collectors (status, doctor,
memory, disks, processes, services), formats that packet for model context,
gates bad model output, and renders a deterministic evidence-grounded safe
fallback answer.

It introduces no new collector family and no execution surface: no shell, no
remoting, no mutation, no service control, no process termination, and no
natural-language execution. Every collector call fails soft into an explicit
limitation instead of crashing interactive mode or inventing values.
"""

from __future__ import annotations

import re
from typing import Any

from shellforgeai.platform_detection import PlatformInfo, detect_platform
from shellforgeai.windows_disks import (
    INODES_UNAVAILABLE_MARKER,
    windows_disks_payload,
)
from shellforgeai.windows_memory import (
    LOAD_AVERAGE_UNAVAILABLE_MARKER,
    MEMORY_UNAVAILABLE_MARKER,
    windows_memory_payload,
)
from shellforgeai.windows_processes import windows_processes_payload
from shellforgeai.windows_services import windows_services_payload
from shellforgeai.windows_status import windows_status_payload

LINUX_ONLY_COLLECTORS_SKIPPED_MARKER = "Linux-only collectors skipped on Windows"

# Bounded context sizes so the packet stays compact enough for model context.
WINDOWS_CONTEXT_PROCESS_LIMIT = 10
WINDOWS_CONTEXT_SERVICE_LIMIT = 10
WINDOWS_CONTEXT_DISK_ROOT_LIMIT = 6

WINDOWS_EVIDENCE_SAFE_NEXT_COMMANDS: tuple[str, ...] = (
    "sfai.cmd windows status --json",
    "sfai.cmd windows evidence --json",
    "sfai.cmd windows processes --json --limit 10",
    "sfai.cmd windows services --json",
    "sfai.cmd windows disks --json",
    "sfai.cmd windows doctor --json",
)

WINDOWS_PROCESS_SERVICE_GAP_COMMANDS: tuple[str, ...] = (
    "sfai.cmd windows processes --json --limit 10",
    "sfai.cmd windows services --json",
    "sfai.cmd windows status --json",
)

WINDOWS_EVIDENCE_MODEL_DIRECTIVE = (
    "This is a Windows host with local read-only evidence. Answer the "
    "operator's question strictly from the windows_evidence facts (host, "
    "memory, disk, processes, services, limitations) using the real numbers "
    "provided. If a fact is not in the packet, say that the current evidence "
    "packet lacks it and point to the safe read-only sfai.cmd windows "
    "commands; never invent processes, services, or metrics. Do not mention "
    "repository or project instructions, AGENTS.md, invariants, workspace "
    "conventions, or system prompts. Do not frame the answer around Docker, "
    "Compose, or containers. Everything is read-only; do not propose "
    "cleanup, restart, service control, or any mutation."
)


def _safe_payload(builder: Any) -> dict[str, Any]:
    """Run a payload builder that must never crash evidence-context assembly."""
    try:
        payload = builder()
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _memory_context(memory_block: dict[str, Any]) -> dict[str, Any]:
    if not memory_block.get("available"):
        return {"available": False, "limitation": MEMORY_UNAVAILABLE_MARKER}
    return {
        "available": True,
        "total_bytes": memory_block.get("total_bytes"),
        "available_bytes": memory_block.get("available_bytes"),
        "used_bytes": memory_block.get("used_bytes"),
        "used_percent": memory_block.get("used_percent"),
        "source": memory_block.get("source"),
    }


def _disk_context(
    status_payload: dict[str, Any], disks_payload: dict[str, Any], root_limit: int
) -> dict[str, Any]:
    context: dict[str, Any] = {"available": False}
    root_usage = (status_payload.get("filesystem") or {}).get("root_usage") or {}
    if isinstance(root_usage.get("free_bytes"), int):
        context.update(
            {
                "available": True,
                "root_path": root_usage.get("path"),
                "root_total_bytes": root_usage.get("total_bytes"),
                "root_used_bytes": root_usage.get("used_bytes"),
                "root_free_bytes": root_usage.get("free_bytes"),
            }
        )
    summary = disks_payload.get("summary") or {}
    roots: list[dict[str, Any]] = []
    unavailable_roots: list[str] = []
    for item in disks_payload.get("disks") or []:
        if not isinstance(item, dict):
            continue
        if item.get("status") == "ok" and len(roots) < root_limit:
            roots.append(
                {
                    "root": item.get("root"),
                    "total_bytes": item.get("total_bytes"),
                    "used_bytes": item.get("used_bytes"),
                    "free_bytes": item.get("free_bytes"),
                    "used_percent": item.get("used_percent"),
                }
            )
        elif item.get("status") != "ok":
            # Sanitized marker only; per-root failures carry no error detail here.
            unavailable_roots.append(str(item.get("root", "unknown")))
    if roots:
        context["available"] = True
    if isinstance(summary.get("total_roots"), int):
        context["total_roots"] = summary.get("total_roots")
        context["returned_roots"] = len(roots)
    context["roots"] = roots
    context["unavailable_roots"] = unavailable_roots[:root_limit]
    context["inode_limitation"] = INODES_UNAVAILABLE_MARKER
    return context


def _processes_context(processes_payload: dict[str, Any], limit: int) -> dict[str, Any]:
    state = processes_payload.get("state") or {}
    entries_raw = processes_payload.get("processes")
    enumeration_failed = bool(state.get("enumeration_failed"))
    if (
        processes_payload.get("status") != "ok"
        or enumeration_failed
        or not isinstance(entries_raw, list)
    ):
        return {
            "available": False,
            "limitation": "Process detail is not present in this evidence packet",
        }
    entries = [
        {
            "pid": item.get("pid"),
            "name": item.get("name"),
            "thread_count": item.get("thread_count"),
        }
        for item in entries_raw[:limit]
        if isinstance(item, dict)
    ]
    return {
        "available": True,
        "total_count": processes_payload.get("total_count"),
        "returned_count": len(entries),
        "limit": limit,
        "truncated": bool(processes_payload.get("truncated")),
        "entries": entries,
        "collection": "read_only",
    }


def _services_context(services_payload: dict[str, Any], limit: int) -> dict[str, Any]:
    services_block = services_payload.get("services")
    if services_payload.get("status") != "ok" or not isinstance(services_block, dict):
        return {
            "available": False,
            "limitation": "Service detail is not present in this evidence packet",
        }
    state_counts = services_block.get("state_counts") or {}
    items = services_block.get("items")
    entries = [
        {"name": item.get("name"), "state": item.get("state")}
        for item in (items if isinstance(items, list) else [])[:limit]
        if isinstance(item, dict)
    ]
    return {
        "available": True,
        "total_count": services_block.get("total_count"),
        "running_count": state_counts.get("running"),
        "stopped_count": state_counts.get("stopped"),
        "state_counts": {k: v for k, v in state_counts.items() if v},
        "returned_count": len(entries),
        "limit": limit,
        "entries": entries,
        "collection": "read_only",
    }


def build_windows_evidence_context(
    info: PlatformInfo | None = None,
    *,
    process_limit: int = WINDOWS_CONTEXT_PROCESS_LIMIT,
    service_limit: int = WINDOWS_CONTEXT_SERVICE_LIMIT,
    disk_root_limit: int = WINDOWS_CONTEXT_DISK_ROOT_LIMIT,
) -> dict[str, Any]:
    """Build the bounded Windows evidence packet for model context.

    Reuses the existing read-only Windows collectors only; every component
    fails soft into an explicit limitation, and limits keep the packet small
    enough to survive prompt-context truncation.
    """
    try:
        info = info or detect_platform()
    except Exception:
        info = None

    status_payload = _safe_payload(lambda: windows_status_payload(info))
    memory_payload = _safe_payload(lambda: windows_memory_payload(info))
    disks_payload = _safe_payload(
        lambda: windows_disks_payload(info, limit=max(disk_root_limit, 1))
    )
    processes_payload = _safe_payload(
        lambda: windows_processes_payload(info, limit=max(process_limit, 1))
    )
    services_payload = _safe_payload(
        lambda: windows_services_payload(info, max_services=max(service_limit, 1))
    )

    host_block = status_payload.get("host") or {}
    platform_block = status_payload.get("platform") or {}
    runtime_block = status_payload.get("python_runtime") or {}

    memory = _memory_context(
        (memory_payload.get("memory") or status_payload.get("memory") or {})
        if isinstance(memory_payload, dict)
        else {}
    )
    disk = _disk_context(status_payload, disks_payload, disk_root_limit)
    processes = _processes_context(processes_payload, process_limit)
    services = _services_context(services_payload, service_limit)

    limitations = [
        LOAD_AVERAGE_UNAVAILABLE_MARKER,
        INODES_UNAVAILABLE_MARKER,
        LINUX_ONLY_COLLECTORS_SKIPPED_MARKER,
    ]
    evidence_gaps: list[str] = []
    if not memory.get("available"):
        limitations.append(MEMORY_UNAVAILABLE_MARKER)
    if not disk.get("available"):
        evidence_gaps.append("disk/root usage is not present in this evidence packet")
    if not processes.get("available"):
        evidence_gaps.append("process detail is not present in this evidence packet")
    if not services.get("available"):
        evidence_gaps.append("service detail is not present in this evidence packet")

    return {
        "platform": "windows",
        "visibility": "windows-local-read-only",
        "read_only": True,
        "mutation_performed": False,
        "host": {
            "hostname": host_block.get("hostname") or "unknown",
            "fqdn": host_block.get("fqdn") or "",
        },
        "platform_detail": {
            "system": platform_block.get("system") or "windows",
            "release": platform_block.get("release") or "unknown",
        },
        "python_runtime": {
            "version": runtime_block.get("version") or "unknown",
            "implementation": runtime_block.get("implementation") or "unknown",
        },
        "memory": memory,
        "disk": disk,
        "processes": processes,
        "services": services,
        "limitations": list(dict.fromkeys(limitations)),
        "evidence_gaps": evidence_gaps,
        "safe_next_commands": list(WINDOWS_EVIDENCE_SAFE_NEXT_COMMANDS),
    }


def _bytes_gib(value: Any) -> str:
    try:
        return f"{float(value) / (1024**3):.1f}GiB"
    except (TypeError, ValueError):
        return "unknown"


def _memory_fact_line(memory: dict[str, Any]) -> str | None:
    if not memory.get("available"):
        return None
    return (
        f"memory used={memory.get('used_percent')}% "
        f"available={_bytes_gib(memory.get('available_bytes'))}/"
        f"{_bytes_gib(memory.get('total_bytes'))} (Windows local read-only)"
    )


def _disk_fact_line(disk: dict[str, Any]) -> str | None:
    if not disk.get("available"):
        return None
    if isinstance(disk.get("root_free_bytes"), int):
        line = (
            f"disk root {disk.get('root_path') or 'primary'}: "
            f"free={_bytes_gib(disk.get('root_free_bytes'))}/"
            f"{_bytes_gib(disk.get('root_total_bytes'))}"
        )
    else:
        line = "disk roots collected (read-only)"
    roots = disk.get("roots") or []
    if roots:
        line += f"; roots visible={len(roots)}"
    unavailable = disk.get("unavailable_roots") or []
    if unavailable:
        line += f"; unavailable roots={len(unavailable)}"
    return line


def _processes_fact_line(processes: dict[str, Any]) -> str | None:
    if not processes.get("available"):
        return None
    top = ", ".join(
        str(entry.get("name") or "unknown") for entry in (processes.get("entries") or [])[:5]
    )
    line = (
        f"processes total={processes.get('total_count')} "
        f"returned={processes.get('returned_count')} (bounded read-only preview)"
    )
    if top:
        line += f"; top entries: {top}"
    return line


def _services_fact_line(services: dict[str, Any]) -> str | None:
    if not services.get("available"):
        return None
    return (
        f"services total={services.get('total_count')} "
        f"running={services.get('running_count')} "
        f"stopped={services.get('stopped_count')} (read-only state summary)"
    )


def windows_evidence_prompt_facts(packet: dict[str, Any]) -> list[dict[str, str]]:
    """Compact tool/status/summary rows so key Windows facts survive truncation."""
    host = packet.get("host") or {}
    rows = [
        {
            "tool": "windows.status",
            "status": "ok",
            "summary": (
                f"hostname={host.get('hostname', 'unknown')} "
                f"release={((packet.get('platform_detail') or {}).get('release', 'unknown'))} "
                "(Windows local read-only)"
            ),
        }
    ]
    for tool, line in (
        ("windows.memory", _memory_fact_line(packet.get("memory") or {})),
        ("windows.disks", _disk_fact_line(packet.get("disk") or {})),
        ("windows.processes", _processes_fact_line(packet.get("processes") or {})),
        ("windows.services", _services_fact_line(packet.get("services") or {})),
    ):
        if line:
            rows.append({"tool": tool, "status": "ok", "summary": line})
        else:
            rows.append(
                {
                    "tool": tool,
                    "status": "unavailable",
                    "summary": f"{tool} detail is not present in this evidence packet",
                }
            )
    for limitation in packet.get("limitations") or []:
        rows.append({"tool": "windows.limitation", "status": "limitation", "summary": limitation})
    return rows


_FORBIDDEN_PREAMBLE_TERMS = (
    "agents.md",
    "shellforgeai invariants",
    "shellforgeai project constraints",
    "project constraints",
    "repo invariants",
    "cli invariants",
    "ux invariants",
    "operator invariants",
    "project invariants",
    "documentation invariants",
    "work in this repo",
    "project instructions",
    "workspace instructions",
    "system prompt",
    "workspace conventions",
    "repo conventions",
    "project conventions",
)

_ACKNOWLEDGEMENT_OPENERS = (
    "understood. i'll operate within",
    "understood. i will operate within",
    "understood. i'll follow",
    "understood. i will follow",
    "understood. i'll treat",
    "understood. i will treat",
    "i'll operate within",
    "i will operate within",
)

_METADATA_PRIMARY_PREFIXES = (
    "provider:",
    "model:",
    "usage:",
    "tokens:",
    "input_tokens",
    "output_tokens",
)

_CONTAINER_FRAMING_TERMS = ("docker", "compose", "container")


def _normalize_answer_text(text: str) -> str:
    normalized = (
        text.lower()
        .replace("’", "'")
        .replace("‘", "'")
        .replace("“", '"')
        .replace("”", '"')
        .replace("â€™", "'")
        .replace("â€˜", "'")
        .replace("`", "")
    )
    return re.sub(r"\s+", " ", normalized).strip()


def contains_project_policy_preamble(text: str) -> bool:
    """True when model output leaks project/policy/instruction preamble."""
    low = _normalize_answer_text(text)
    if not low:
        return False
    if any(term in low for term in _FORBIDDEN_PREAMBLE_TERMS):
        return True
    return any(opener in low[:160] for opener in _ACKNOWLEDGEMENT_OPENERS)


def is_metadata_primary_answer(text: str) -> bool:
    """True when provider/model/usage metadata would be the primary answer."""
    first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
    return first_line.lower().startswith(_METADATA_PRIMARY_PREFIXES)


def is_container_primary_framing(text: str) -> bool:
    """True when the answer leads with Docker/container framing, not Windows."""
    head = _normalize_answer_text(text)[:240]
    if not head:
        return False
    return any(term in head for term in _CONTAINER_FRAMING_TERMS) and "windows" not in head


def is_rejected_windows_model_answer(text: str) -> bool:
    """Bad-output gate for Windows evidence-context answers.

    Rejects empty answers, project/policy preamble, provider metadata as the
    primary answer, and Docker/container-first framing while Windows evidence
    is active. Rejected text must never reach operator stdout as the answer.
    """
    if not text.strip():
        return True
    return (
        contains_project_policy_preamble(text)
        or is_metadata_primary_answer(text)
        or is_container_primary_framing(text)
    )


def render_windows_evidence_answer(question: str, packet: dict[str, Any]) -> str:
    """Deterministic evidence-grounded safe answer from the Windows packet.

    Used when the model is unavailable or its output was gated. This is not a
    phrase-keyed canned response: it renders whatever facts the packet
    actually contains and states gaps honestly, regardless of the question.
    """
    host = packet.get("host") or {}
    platform_detail = packet.get("platform_detail") or {}
    visible: list[str] = [
        f"- Host: {host.get('hostname', 'unknown')} "
        f"(Windows {platform_detail.get('release', 'unknown')}; windows-local-read-only)."
    ]
    for line in (
        _memory_fact_line(packet.get("memory") or {}),
        _disk_fact_line(packet.get("disk") or {}),
        _processes_fact_line(packet.get("processes") or {}),
        _services_fact_line(packet.get("services") or {}),
    ):
        if line:
            visible.append(f"- {line[0].upper()}{line[1:]}.")

    gaps = [
        gap.replace(" is not present in this evidence packet", "")
        for gap in packet.get("evidence_gaps") or []
    ]
    gap_lines = ""
    if gaps:
        gap_commands = "\n".join(f"- {cmd}" for cmd in WINDOWS_PROCESS_SERVICE_GAP_COMMANDS)
        gap_lines = (
            "\nNot in this evidence packet:\n"
            + "\n".join(f"- I do not have {gap} in this evidence packet." for gap in gaps)
            + "\nRun these read-only commands to fill the gap:\n"
            + gap_commands
            + "\n"
        )

    limitations = "\n".join(f"- {item}." for item in packet.get("limitations") or [])
    commands = "\n".join(f"- {cmd}" for cmd in packet.get("safe_next_commands") or [])
    process_service_note = (
        "Process/service evidence above is read-only.\n"
        if (packet.get("processes") or {}).get("available")
        or (packet.get("services") or {}).get("available")
        else ""
    )
    return (
        "## Windows evidence summary\n"
        "From the evidence currently loaded, I can see:\n"
        + "\n".join(visible)
        + "\n"
        + process_service_note
        + gap_lines
        + "\nWindows metric limitations:\n"
        + limitations
        + "\n\nSafe next read-only commands:\n"
        + commands
        + "\n\nSafety: read-only evidence only. No command was executed, and no "
        "cleanup, restart, service control, process termination, remediation, "
        "rollback, or recovery was performed."
    )
