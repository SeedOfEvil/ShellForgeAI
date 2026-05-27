"""In-session latest-evidence memory for the interactive REPL.

This module holds a small, structured snapshot of the most recent
read-only diagnosis so that interactive follow-up questions
("what did you find?", "why is it slow?", "is it running normally?")
can be grounded in real collected evidence instead of generic context.

It is deliberately read-only:
- it never runs collectors
- it never executes shell, remediation, rollback, cleanup, or Docker mutation
- it only stores compact metadata and already-rendered highlights
"""

from __future__ import annotations

import re
import time
from typing import Any

from pydantic import BaseModel, Field

from shellforgeai.core.command_suggestions import (
    remediation_eligibility_explain_command,
    triage_detail_command,
)

# Compact caps so we never hold large logs or raw model output in memory.
_MAX_HIGHLIGHTS = 8
_MAX_FINDINGS = 8
_MAX_SUMMARY_LEN = 280


class LatestDiagnosisContext(BaseModel):
    """Compact in-memory snapshot of the latest read-only diagnosis."""

    session_id: str
    created_at: str
    target: str
    diagnosis_kind: str
    artifact_dir: str | None = None
    evidence_path: str | None = None
    summary_path: str | None = None
    plan_path: str | None = None
    evidence_highlights: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    safe_next_commands: list[str] = Field(default_factory=list)
    suggested_followup_categories: list[str] = Field(default_factory=list)
    source_command: str = ""
    deterministic_only: bool = True
    model_assessment_status: str | None = None
    facts: dict[str, Any] = Field(default_factory=dict)


def _safe_next_commands(target: str | None) -> list[str]:
    """Read-only follow-up commands only. Never mutation or execution."""
    cmds = ["shellforgeai ops report", "shellforgeai triage docker"]
    candidate = (target or "").strip()
    if candidate and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", candidate):
        try:
            cmds.append(triage_detail_command(candidate))
            cmds.append(remediation_eligibility_explain_command(candidate))
        except ValueError:
            pass
    cmds.append("shellforgeai remediation self-test --profile standard")
    # de-duplicate while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for c in cmds:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _limitations_from_facts(facts: dict[str, Any]) -> list[str]:
    limits: list[str] = []
    if facts.get("container"):
        limits.append(
            "Container-limited view: host systemd/journal and host-level processes "
            "may not be visible from here."
        )
    else:
        limits.append(
            "Read-only snapshot from the current runtime context; host-level state "
            "outside this view may differ."
        )
    if facts.get("load") is None and facts.get("cpu_mem") is None:
        limits.append("CPU/load/memory detail was not captured in this evidence set.")
    if facts.get("storage_pressure") is None:
        limits.append("Storage/I/O pressure (PSI) may be unavailable in this environment.")
    return limits


def build_latest_diagnosis_context(
    *,
    session_id: str,
    target: str,
    diagnosis_kind: str,
    checks: list[dict[str, str]],
    facts: dict[str, Any],
    evidence_highlights: list[str],
    findings: list[str] | None = None,
    artifact_dir: str | None = None,
    evidence_path: str | None = None,
    summary_path: str | None = None,
    plan_path: str | None = None,
    source_command: str = "",
    deterministic_only: bool = True,
    model_assessment_status: str | None = None,
    suggested_followup_categories: list[str] | None = None,
) -> LatestDiagnosisContext:
    """Assemble a compact latest-diagnosis context from collected evidence.

    Only summaries/highlights are retained — never raw logs, secrets, or
    raw model JSONL.
    """
    compact_facts: dict[str, Any] = {}
    for key in (
        "load",
        "cpu_mem",
        "disk_pct",
        "disk_summary",
        "inode_pct",
        "inode_summary",
        "storage_pressure",
        "storage_pressure_raw",
        "container",
        "container_label",
    ):
        if key in facts:
            compact_facts[key] = facts[key]
    top = facts.get("top_process")
    if isinstance(top, str):
        compact_facts["top_process"] = top[:_MAX_SUMMARY_LEN]

    return LatestDiagnosisContext(
        session_id=session_id,
        created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        target=target,
        diagnosis_kind=diagnosis_kind,
        artifact_dir=artifact_dir,
        evidence_path=evidence_path,
        summary_path=summary_path,
        plan_path=plan_path,
        evidence_highlights=list(evidence_highlights)[:_MAX_HIGHLIGHTS],
        findings=[f[:_MAX_SUMMARY_LEN] for f in (findings or [])][:_MAX_FINDINGS],
        limitations=_limitations_from_facts(compact_facts),
        safe_next_commands=_safe_next_commands(target),
        suggested_followup_categories=list(
            suggested_followup_categories
            or ["performance", "health_status", "system_role", "artifacts", "next_steps"]
        ),
        source_command=source_command,
        deterministic_only=deterministic_only,
        model_assessment_status=model_assessment_status,
        facts=compact_facts,
    )


# --- follow-up intent recognition ----------------------------------------

_INTENT_PHRASES: dict[str, tuple[str, ...]] = {
    "performance": (
        "why is it slow",
        "why is this slow",
        "why is the system slow",
        "why is it so slow",
        "what is making it slow",
        "what's making it slow",
        "why so slow",
    ),
    "health_status": (
        "is it running normally",
        "is it running ok",
        "is it running okay",
        "is everything running normally",
        "is the system running normally",
        "is it healthy",
        "is this running normally",
        "is this system healthy",
        "does this look normal",
        "give me a quick health check",
        "what should i check first",
    ),
    "system_role": (
        "what does this system do",
        "what does this box do",
        "what is this system",
        "what is this box",
        "what's this system",
        "what is this machine",
        "what does this machine do",
        "what is this machine for",
        "what role is this server playing",
    ),
    "next_steps": (
        "what should i check next",
        "what should we check next",
        "what next",
        "what do i check next",
        "what else should i check",
    ),
    "artifacts": (
        "where are the artifacts",
        "where is the evidence",
        "where are the evidence files",
        "where did you save",
        "where are the files",
    ),
    "limitations": (
        "what were the limitations",
        "what are the limitations",
        "what couldn't you see",
        "what could you not see",
        "what is the blind spot",
    ),
    "summary": (
        "what did you find",
        "summarize the latest diagnosis",
        "summarise the latest diagnosis",
        "summarize the diagnosis",
        "what evidence do we have",
        "show the latest evidence",
        "show latest evidence",
        "what did the diagnosis find",
    ),
}

# Mutation-y short follow-ups must never be answered from latest context.
_MUTATION_FOLLOWUP_PHRASES: tuple[str, ...] = (
    "fix it",
    "fix this",
    "fix that",
    "repair it",
    "repair this",
    "just fix it",
    "go fix it",
    "remediate it",
    "resolve it automatically",
)


def _normalize(text: str) -> str:
    return " ".join((text or "").lower().split()).strip("?.!,")


def is_mutation_followup(text: str) -> bool:
    """True for short follow-ups that ask for a mutation/fix."""
    norm = _normalize(text)
    return any(p == norm or norm.startswith(p) for p in _MUTATION_FOLLOWUP_PHRASES)


def detect_latest_context_intent(text: str) -> str | None:
    """Return a follow-up intent category if the text is a latest-context question.

    Returns None for mutation requests and anything not recognized as a
    grounded follow-up question.
    """
    norm = _normalize(text)
    if not norm:
        return None
    if is_mutation_followup(norm):
        return None
    for intent, phrases in _INTENT_PHRASES.items():
        if any(p == norm or norm.startswith(p) or p in norm for p in phrases):
            return intent
    return None


# --- follow-up answering --------------------------------------------------


def _artifact_lines(ctx: LatestDiagnosisContext) -> list[str]:
    lines: list[str] = []
    if ctx.evidence_path:
        lines.append(f"- evidence: {ctx.evidence_path}")
    if ctx.summary_path:
        lines.append(f"- summary: {ctx.summary_path}")
    if ctx.plan_path:
        lines.append(f"- plan: {ctx.plan_path}")
    if not lines and ctx.artifact_dir:
        lines.append(f"- artifacts: {ctx.artifact_dir}")
    return lines


def _safe_block(ctx: LatestDiagnosisContext) -> str:
    cmds = "\n".join(f"- {c}" for c in ctx.safe_next_commands)
    return f"Safe next commands:\n{cmds}" if cmds else ""


def _limitation_block(ctx: LatestDiagnosisContext) -> str:
    if not ctx.limitations:
        return ""
    return "Limitations:\n" + "\n".join(f"- {limit}" for limit in ctx.limitations)


def _performance_lines(ctx: LatestDiagnosisContext) -> list[str]:
    facts = ctx.facts
    lines: list[str] = []
    cpu_mem = facts.get("cpu_mem")
    if isinstance(cpu_mem, dict):
        lines.append(
            f"- CPU/memory: {cpu_mem.get('cpus', '?')} CPUs visible, "
            f"{cpu_mem.get('mem_used_gib', '?')} GiB / "
            f"{cpu_mem.get('mem_total_gib', '?')} GiB used"
            + ("" if cpu_mem.get("swap_unused") else ", swap in use")
        )
    load = facts.get("load")
    if isinstance(load, (list, tuple)) and len(load) == 3:
        lines.append(f"- Load average: {load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}")
    sp = facts.get("storage_pressure")
    if isinstance(sp, (list, tuple)) and len(sp) == 3:
        if sp[0] or sp[1] or sp[2]:
            lines.append(f"- Storage/I/O pressure: avg10 {sp[0]:g} / {sp[1]:g} / {sp[2]:g}")
        else:
            lines.append("- Storage/I/O pressure: none reported")
    if facts.get("disk_summary"):
        lines.append(f"- Disk: {facts['disk_summary']}")
    if facts.get("top_process"):
        lines.append(f"- Top process: {facts['top_process']}")
    if not lines:
        lines = list(ctx.evidence_highlights)
    return lines


def answer_from_latest_context(ctx: LatestDiagnosisContext, intent: str) -> str:
    """Render a concise, evidence-backed, read-only answer for a follow-up.

    Never invents system role or evidence; always surfaces limitations and
    safe read-only next commands.
    """
    header = f"Based on the latest {ctx.diagnosis_kind} diagnosis (target: {ctx.target}):"
    parts: list[str] = []

    if intent == "performance":
        parts.append("Why it may feel slow, from the latest collected evidence:")
        parts.extend(_performance_lines(ctx))
    elif intent == "health_status":
        parts.append(
            "From the latest collected evidence, nothing in the read-only checks "
            "points to a confirmed failure, but this is a bounded view:"
        )
        parts.extend(ctx.evidence_highlights or _performance_lines(ctx))
        parts.append(
            "Confidence: medium. I can report what the evidence shows, but I cannot "
            "fully confirm host-level health from this view."
        )
    elif intent == "system_role":
        scope = "container-limited view" if ctx.facts.get("container") else "current runtime view"
        parts.append(
            f"From the latest collected evidence ({scope}), I can describe what is "
            "observable but cannot fully infer the host's role:"
        )
        parts.extend(ctx.evidence_highlights[:5])
        parts.append("I will not invent a system role beyond what the evidence supports.")
    elif intent == "next_steps":
        parts.append("Suggested read-only next steps based on the latest diagnosis:")
        if ctx.suggested_followup_categories:
            parts.append("- Follow-up areas: " + ", ".join(ctx.suggested_followup_categories))
    elif intent == "artifacts":
        parts.append("Artifacts saved for the latest diagnosis:")
        art = _artifact_lines(ctx)
        parts.extend(art or ["- No artifact files were recorded for this diagnosis."])
    elif intent == "limitations":
        parts.append("Limitations of the latest diagnosis:")
        parts.extend(f"- {limit}" for limit in ctx.limitations)
    else:  # summary / default
        parts.extend(ctx.evidence_highlights or ["- No evidence highlights were recorded."])
        art = _artifact_lines(ctx)
        if art:
            parts.append("Artifacts:")
            parts.extend(art)

    blocks = [header, "\n".join(parts)]
    if intent != "limitations":
        lim = _limitation_block(ctx)
        if lim:
            blocks.append(lim)
    if intent != "artifacts":
        art = _artifact_lines(ctx)
        if art and intent not in {"summary"}:
            blocks.append("Artifacts:\n" + "\n".join(art))
    safe = _safe_block(ctx)
    if safe:
        blocks.append(safe)
    return "\n\n".join(b for b in blocks if b)


def no_latest_context_reply() -> str:
    """Clean, safe reply when there is no latest evidence to ground a follow-up."""
    return (
        "I don't have any collected evidence from this session yet, so I can't ground "
        "that answer in real diagnostics. Nothing was run or changed.\n\n"
        "To collect read-only evidence first, try:\n"
        "- diagnose performance\n"
        "- diagnose disk\n"
        "- shellforgeai ops report\n\n"
        'Once evidence exists, follow-ups like "what did you find?" or '
        '"is it running normally?" will use it.'
    )


def render_latest_context_pending(ctx: LatestDiagnosisContext) -> str:
    """Render `/pending` output from latest diagnosis context (no formal pending)."""
    lines = [
        "No formal pending investigation. Showing latest diagnosis context:",
        f"- Time: {ctx.created_at}",
        f"- Target: {ctx.target}",
        f"- Diagnosis kind: {ctx.diagnosis_kind}",
    ]
    if ctx.artifact_dir:
        lines.append(f"- Artifacts dir: {ctx.artifact_dir}")
    if ctx.evidence_path:
        lines.append(f"- Evidence: {ctx.evidence_path}")
    if ctx.summary_path:
        lines.append(f"- Summary: {ctx.summary_path}")
    if ctx.suggested_followup_categories:
        lines.append(
            "- Suggested follow-up categories: " + ", ".join(ctx.suggested_followup_categories)
        )
    if ctx.safe_next_commands:
        lines.append("- Safe next commands:")
        lines.extend(f"  - {c}" for c in ctx.safe_next_commands)
    return "\n".join(lines)
