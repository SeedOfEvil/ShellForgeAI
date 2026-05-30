"""Session-local follow-up grounding for interactive operator dialogue.

This module is intentionally small and read-only. It remembers compact
session-local references (latest target, top suspect, evidence paths, safe
next command) so pronouns like "it" or ranked references like "the first one"
can be resolved without inventing targets. It never executes commands.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

from shellforgeai.core.command_suggestions import (
    remediation_eligibility_explain_command,
    triage_detail_command,
)
from shellforgeai.core.latest_context import LatestDiagnosisContext

_TARGET_RE = re.compile(r"\b(sfai-[A-Za-z0-9_.-]+|[A-Za-z0-9][A-Za-z0-9_.-]{2,127})\b")
_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

_RANK_REFERENCE_PHRASES = (
    "top suspect",
    "top one",
    "first one",
    "the first one",
    "number one",
    "#1",
)
_PRONOUN_REFERENCE_PHRASES = (
    "it",
    "that",
    "that one",
    "this one",
    "that container",
    "this container",
    "what about it",
    "what about that",
    "check it",
    "check that",
    "check that one",
    "show me details",
    "show details",
    "details",
)
_EVIDENCE_REFERENCE_PHRASES = (
    "what did you find",
    "dig deeper",
    "get that info",
    "get the info",
    "show latest evidence",
    "show me the evidence",
)
_DETAIL_REFERENCE_PHRASES = (
    "show me details",
    "show details",
    "details",
    "check that one",
    "check it",
    "check that",
    "what about it",
    "what about that",
)
_TRIAGE_EXPLAIN_PHRASES = (
    "is that scary",
    "is it scary",
    "why is it high",
    "why is that high",
    "what should i check next",
    "what should we check next",
    "what should i do next",
)
_MUTATION_VERBS = (
    "restart",
    "fix",
    "clean it up",
    "clean that up",
    "cleanup",
    "delete",
    "remove",
    "stop",
    "start",
    "run that",
    "run it",
    "apply",
    "remediate",
    "rollback",
)
_EXPLICIT_COMMAND_PREFIXES = (
    "shellforgeai ",
    "triage ",
    "remediation ",
    "ops ",
    "diagnose ",
)
_GENERIC_WORDS = {
    "what",
    "about",
    "that",
    "this",
    "container",
    "show",
    "details",
    "check",
    "first",
    "one",
    "top",
    "suspect",
    "why",
    "high",
    "scary",
    "next",
    "run",
    "fix",
    "restart",
}


@dataclass
class FollowupGroundingState:
    """Compact session-local references used for follow-up resolution."""

    last_target: str = ""
    last_target_kind: str = ""
    last_intent: str = ""
    last_triage_result: str = ""
    last_top_suspect: str = ""
    last_evidence_summary: str = ""
    last_artifact_paths: list[str] = field(default_factory=list)
    last_safe_next_command: str = ""
    last_read_only_action: str = ""
    last_refusal_reason: str = ""
    last_candidates: list[str] = field(default_factory=list)
    updated_at: str = ""

    def touch(self) -> None:
        self.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def remember_target(
        self,
        target: str,
        *,
        target_kind: str = "target",
        intent: str = "",
        top_suspect: bool = False,
        safe_next_command: str = "",
        evidence_summary: str = "",
        artifact_paths: list[str] | None = None,
        candidates: list[str] | None = None,
        read_only_action: str = "",
        triage_result: str = "",
    ) -> None:
        clean = (target or "").strip()
        if clean and _SAFE_TARGET_RE.fullmatch(clean):
            self.last_target = clean
            self.last_target_kind = target_kind or self.last_target_kind or "target"
            if top_suspect:
                self.last_top_suspect = clean
        if intent:
            self.last_intent = intent
        if safe_next_command:
            self.last_safe_next_command = safe_next_command
        elif clean and target_kind in {"container", "docker_container", "suspect"}:
            self.last_safe_next_command = triage_detail_command(clean)
        if evidence_summary:
            self.last_evidence_summary = evidence_summary[:500]
        if artifact_paths is not None:
            self.last_artifact_paths = [p for p in artifact_paths if p][:8]
        if candidates is not None:
            self.last_candidates = [c for c in candidates if c][:8]
        if read_only_action:
            self.last_read_only_action = read_only_action
        if triage_result:
            self.last_triage_result = triage_result[:500]
        self.touch()


@dataclass(frozen=True)
class GroundingResolution:
    kind: str
    target: str = ""
    target_kind: str = ""
    intent: str = ""
    phrase: str = ""
    safe_command: str = ""
    explanation: str = ""
    candidates: tuple[str, ...] = ()

    @property
    def resolved(self) -> bool:
        return self.kind in {"target", "evidence", "mutation_refusal"}


def _normalize(text: str) -> str:
    lowered = re.sub(r"[^a-z0-9#_.\-/\s]", " ", (text or "").lower())
    return re.sub(r"\s+", " ", lowered).strip()


def _contains_any(norm: str, phrases: tuple[str, ...]) -> bool:
    for phrase in phrases:
        if phrase == norm:
            return True
        if " " in phrase:
            if phrase in norm:
                return True
            continue
        if re.search(rf"\b{re.escape(phrase)}\b", norm):
            return True
    return False


def _is_mutation_reference(norm: str) -> bool:
    return any(p == norm or norm.startswith(p) or p in norm for p in _MUTATION_VERBS)


def _explicit_target(text: str) -> str:
    norm = _normalize(text)
    if not norm or norm.startswith(_EXPLICIT_COMMAND_PREFIXES):
        return ""
    for match in _TARGET_RE.finditer(text):
        candidate = match.group(1).strip(".,?!")
        if candidate.lower() in _GENERIC_WORDS:
            continue
        if candidate.startswith("sfai-"):
            return candidate
    return ""


def _safe_detail_command(target: str) -> str:
    if not _SAFE_TARGET_RE.fullmatch(target or ""):
        return "shellforgeai ops report"
    return triage_detail_command(target)


def safe_commands_for_target(target: str) -> list[str]:
    if not _SAFE_TARGET_RE.fullmatch(target or ""):
        return ["shellforgeai ops report", "shellforgeai triage docker"]
    return [
        triage_detail_command(target),
        remediation_eligibility_explain_command(target),
    ]


def update_grounding_from_latest_context(
    state: FollowupGroundingState, ctx: LatestDiagnosisContext
) -> FollowupGroundingState:
    artifacts = [
        p for p in (ctx.evidence_path, ctx.summary_path, ctx.plan_path, ctx.artifact_dir) if p
    ]
    safe = ctx.safe_next_commands[0] if ctx.safe_next_commands else ""
    state.remember_target(
        ctx.target,
        target_kind=ctx.diagnosis_kind or "diagnosis",
        intent=ctx.diagnosis_kind,
        safe_next_command=safe,
        evidence_summary="; ".join(ctx.evidence_highlights[:3]),
        artifact_paths=artifacts,
        read_only_action=ctx.source_command,
    )
    return state


def update_grounding_from_ops_report_text(
    state: FollowupGroundingState, text: str
) -> FollowupGroundingState:
    top = ""
    candidates: list[str] = []
    for line in (text or "").splitlines():
        m_top = re.search(r"Top suspect:\s*([A-Za-z0-9_.-]+)", line, flags=re.I)
        if m_top:
            top = m_top.group(1)
        m_rank = re.search(r"^\s*\d+[.)]\s+([A-Za-z0-9_.-]+)\s+—", line)
        if m_rank:
            candidates.append(m_rank.group(1))
    if not top and candidates:
        top = candidates[0]
    if top:
        state.remember_target(
            top,
            target_kind="container",
            intent="ops_report",
            top_suspect=True,
            safe_next_command=triage_detail_command(top),
            evidence_summary="latest ops report top suspect",
            candidates=candidates or [top],
            read_only_action="shellforgeai ops report",
        )
    return state


def update_grounding_from_triage_detail_text(
    state: FollowupGroundingState, target: str, text: str = ""
) -> FollowupGroundingState:
    summary_lines = []
    for line in (text or "").splitlines():
        if any(key in line.lower() for key in ("severity", "confidence", "evidence", "why")):
            summary_lines.append(line.strip())
        if len(summary_lines) >= 4:
            break
    state.remember_target(
        target,
        target_kind="container",
        intent="triage_detail",
        safe_next_command=triage_detail_command(target),
        evidence_summary="; ".join(summary_lines),
        read_only_action=triage_detail_command(target),
        triage_result="; ".join(summary_lines),
    )
    return state


def resolve_followup_reference(text: str, state: FollowupGroundingState) -> GroundingResolution:
    raw = (text or "").strip()
    norm = _normalize(raw)
    if not norm:
        return GroundingResolution(kind="none")
    explicit = _explicit_target(raw)
    if explicit:
        return GroundingResolution(
            kind="target",
            target=explicit,
            target_kind="explicit",
            intent="explicit_target",
            phrase=raw,
            safe_command=_safe_detail_command(explicit),
        )
    if _is_mutation_reference(norm):
        target = state.last_target or state.last_top_suspect
        if target:
            return GroundingResolution(
                kind="mutation_refusal",
                target=target,
                target_kind=state.last_target_kind,
                intent="mutation_refusal",
                phrase=raw,
                safe_command=_safe_detail_command(target),
            )
        return GroundingResolution(
            kind="ambiguous",
            intent="mutation_refusal",
            phrase=raw,
            candidates=tuple(state.last_candidates),
        )
    if _contains_any(norm, _RANK_REFERENCE_PHRASES):
        target = state.last_top_suspect or (
            state.last_candidates[0] if state.last_candidates else ""
        )
        if target:
            return GroundingResolution(
                kind="target",
                target=target,
                target_kind="container",
                intent="rank_reference",
                phrase=raw,
                safe_command=_safe_detail_command(target),
            )
    if _contains_any(norm, _TRIAGE_EXPLAIN_PHRASES):
        target = state.last_target or state.last_top_suspect
        if target:
            return GroundingResolution(
                kind="target",
                target=target,
                target_kind=state.last_target_kind or "target",
                intent="triage_explain",
                phrase=raw,
                safe_command=state.last_safe_next_command or _safe_detail_command(target),
            )
    if _contains_any(norm, _EVIDENCE_REFERENCE_PHRASES):
        if state.last_evidence_summary or state.last_artifact_paths or state.last_read_only_action:
            return GroundingResolution(
                kind="evidence",
                target=state.last_target,
                target_kind=state.last_target_kind,
                intent="latest_evidence",
                phrase=raw,
                safe_command=state.last_safe_next_command,
            )
        return GroundingResolution(kind="no_context", phrase=raw)
    if _contains_any(norm, _PRONOUN_REFERENCE_PHRASES):
        target = state.last_target or state.last_top_suspect
        if target:
            intent = (
                "triage_detail"
                if _contains_any(norm, _DETAIL_REFERENCE_PHRASES)
                else "target_followup"
            )
            return GroundingResolution(
                kind="target",
                target=target,
                target_kind=state.last_target_kind or "target",
                intent=intent,
                phrase=raw,
                safe_command=_safe_detail_command(target),
            )
        return GroundingResolution(
            kind="ambiguous" if state.last_candidates else "no_context",
            phrase=raw,
            candidates=tuple(state.last_candidates),
        )
    return GroundingResolution(kind="none")


def render_grounded_resolution(state: FollowupGroundingState, res: GroundingResolution) -> str:
    if res.kind == "mutation_refusal":
        commands = safe_commands_for_target(res.target)
        return (
            f"I’m not {_mutation_gerund(res.phrase)} {res.target} from natural language.\n"
            "No action was taken.\n"
            "Safe read-only alternatives:\n" + "\n".join(f"  {cmd}" for cmd in commands)
        )
    if res.kind == "target":
        phrase = res.phrase or "that"
        intro = f"Interpreting “{phrase}” as {res.target}"
        if res.intent == "rank_reference":
            intro += " from the latest ops report."
        elif state.last_intent == "triage_detail":
            intro += " from the latest triage detail."
        else:
            intro += " from the latest session context."
        if res.intent == "triage_explain":
            evidence = (
                state.last_triage_result
                or state.last_evidence_summary
                or "Use the detail command for current evidence."
            )
            return (
                f"{intro}\n"
                f"What I know: {evidence}\n"
                "Safe read-only next command:\n"
                f"  {res.safe_command or _safe_detail_command(res.target)}"
            )
        return (
            f"{intro}\n"
            "Safe read-only detail path:\n"
            f"  {res.safe_command or _safe_detail_command(res.target)}"
        )
    if res.kind == "evidence":
        where = (
            ", ".join(state.last_artifact_paths) if state.last_artifact_paths else "this session"
        )
        summary = state.last_evidence_summary or "No compact evidence summary was recorded."
        cmd = state.last_safe_next_command or "shellforgeai ops report"
        diagnosis = state.last_intent or "diagnosis"
        return (
            f"Using the latest {diagnosis} diagnosis context from {where}.\n"
            f"What I found: {summary}\n"
            "Safe read-only next command:\n"
            f"  {cmd}"
        )
    if res.kind == "ambiguous":
        choices = "\n".join(f"- {c}" for c in res.candidates[:5])
        suffix = f"\nSafe choices:\n{choices}" if choices else ""
        return "I can’t tell what target you mean. No action was taken." + suffix
    if res.kind == "no_context":
        return (
            "I don’t have a clear prior target or evidence context for that. No action was taken."
        )
    return ""


def _mutation_gerund(phrase: str) -> str:
    norm = _normalize(phrase)
    if "restart" in norm:
        return "restarting"
    if "fix" in norm:
        return "fixing"
    if "clean" in norm:
        return "cleaning up"
    if "run" in norm:
        return "running"
    if "stop" in norm:
        return "stopping"
    if "start" in norm:
        return "starting"
    return "executing changes against"


def grounding_debug_snapshot(state: FollowupGroundingState) -> dict[str, Any]:
    return {
        "last_target": state.last_target,
        "last_target_kind": state.last_target_kind,
        "last_intent": state.last_intent,
        "last_top_suspect": state.last_top_suspect,
        "last_artifact_paths": list(state.last_artifact_paths),
        "last_safe_next_command": state.last_safe_next_command,
        "last_read_only_action": state.last_read_only_action,
        "last_candidates": list(state.last_candidates),
        "updated_at": state.updated_at,
    }
