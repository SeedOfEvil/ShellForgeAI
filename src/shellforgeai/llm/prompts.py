from __future__ import annotations

import json
import re

from shellforgeai.llm.system_prompt import SHELLFORGE_SYSTEM_PROMPT, WINDOWS_EVIDENCE_SYSTEM_PROMPT

SECRET_RE = re.compile(
    r"(api_key|token|secret|password|bearer|authorization|private_key|client_secret|refresh_token|access_token|auth\.json)",
    re.IGNORECASE,
)


def redact_text(value: str) -> str:
    out = []
    for line in value.splitlines():
        if SECRET_RE.search(line):
            out.append("[REDACTED]")
        else:
            out.append(line)
    return "\n".join(out)


def build_model_prompt(question: str, context: dict, max_chars: int = 2000) -> str:
    capability_map = """Available ShellForgeAI read-only collectors:
Host:
- host.info, host.resources, host.uptime
- system.os_release, system.cpu_memory, system.container_detect
Disk:
- disk.usage, disk.inodes
Network:
- network.dns, network.routes, network.listeners
- network.listeners.filtered, firewall.detect
Processes:
- process.top, process.find
Files/logs:
- files.exists, files.stat, files.read_text, files.safe_list
- files.head, files.tail, logs.file_tail, logs.find_common, logs.search_errors
Services:
- systemd.status, systemd.list_failed, journal.unit
- nginx.detect, ssh.detect, docker.detect
Knowledge:
- knowledge.search_local

In normal operator answers, do not expose internal collector names
or ask the operator to run collectors manually."""
    evidence_rows = context.get("evidence") or context.get("machine_health") or []
    evidence_label = context.get("evidence_label", "evidence")
    evidence_block = ""
    if isinstance(evidence_rows, list) and evidence_rows:
        lines = []
        for row in evidence_rows[:30]:
            if isinstance(row, dict):
                tool = row.get("tool") or row.get("source") or "unknown"
                status = row.get("status") or row.get("metadata", {}).get("status") or "unknown"
                summary = row.get("summary") or ""
                lines.append(f"- {tool}: {status} — {summary}".strip())
        evidence_block = f"ShellForgeAI already collected {evidence_label}:\n" + "\n".join(lines)
    payload = redact_text(json.dumps(context, indent=2, ensure_ascii=False))[:max_chars]
    return (
        f"{SHELLFORGE_SYSTEM_PROMPT}\n\n{capability_map}\n\n"
        f"{evidence_block}\n\n"
        "Analyze collected evidence first.\n"
        "Do not ask for checks already attempted; acknowledge those results first.\n"
        "Do not ask operators to rerun collectors already collected unless context changed.\n"
        "Prefer ShellForgeAI collector names before raw shell commands.\n"
        "Mutating/service-impacting actions are operator-run and approval-required.\n"
        f"Question: {question}\nContext:\n{payload}"
    )


def build_contextual_prompt(question: str, context: dict, mode: str = "standard") -> str:
    max_chars = 800 if mode == "minimal" else 2500 if mode == "standard" else 5000
    return build_model_prompt(question, context, max_chars=max_chars)


def build_windows_evidence_model_prompt(
    question: str, context: dict, *, mode: str = "standard"
) -> str:
    """Build the dedicated prompt for an already-selected Windows evidence path."""
    from shellforgeai.core.windows_evidence_context import (
        project_windows_evidence_for_model,
        windows_evidence_prompt_facts,
    )

    max_chars = 800 if mode == "minimal" else 2500 if mode == "standard" else 5000
    packet = context.get("windows_evidence") or {}
    projected = project_windows_evidence_for_model(packet)
    model_context = {
        "identity": "Windows host with Windows-local read-only evidence",
        "windows_evidence": projected,
        "windows_evidence_facts": windows_evidence_prompt_facts(projected),
        "evidence_gaps": projected.get("evidence_gaps", []),
        "read_only": True,
        "mutation_permitted": False,
    }
    capability_map = """Available Windows read-only evidence capabilities:
- Windows status and host information; Windows doctor
- physical and virtual memory
- drives and volumes, storage capacity, and free space
- Windows processes and Windows services with service state
- Windows events and Event Logs
- Windows network evidence

Use only capabilities and facts represented by the supplied Windows evidence packet."""
    payload = redact_text(json.dumps(model_context, indent=2, ensure_ascii=False))[:max_chars]
    return (
        f"{WINDOWS_EVIDENCE_SYSTEM_PROMPT}\n\n{capability_map}\n\n"
        "Ground the answer only in the supplied Windows-local read-only evidence. "
        "Preserve evidence gaps and do not infer health. No mutation is permitted.\n"
        f"Question: {question}\nContext:\n{payload}"
    )
