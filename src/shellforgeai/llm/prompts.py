from __future__ import annotations

import json
import re

from shellforgeai.llm.system_prompt import SHELLFORGE_SYSTEM_PROMPT

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
        "Do not ask operators to rerun collectors already collected unless context changed.\n"
        "Prefer ShellForgeAI collector names before raw shell commands.\n"
        "Mutating/service-impacting actions are operator-run and approval-required.\n"
        f"Question: {question}\nContext:\n{payload}"
    )


def build_contextual_prompt(question: str, context: dict, mode: str = "standard") -> str:
    max_chars = 800 if mode == "minimal" else 2500 if mode == "standard" else 5000
    return build_model_prompt(question, context, max_chars=max_chars)
