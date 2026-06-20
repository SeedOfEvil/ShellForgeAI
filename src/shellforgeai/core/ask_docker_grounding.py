"""PR222 — ground model-backed ``ask`` in deterministic Docker evidence.

When a Docker/operator question reaches the model-backed ``ask`` path, the
model must explain and route from deterministic ShellForgeAI evidence rather
than inventing unsupported commands or acting like no evidence exists. This
module builds a *bounded, read-only* evidence context from the existing
deterministic triage ranking engine (``core.triage_ranking``) and renders the
grounded human answer described in the PR222 response contract.

Strictly read-only. Nothing here restarts, stops, removes, prunes, cleans up,
remediates, rolls back, recovers, mutates Docker/Compose, runs a shell, or
executes natural language. It only *reads* the current Docker scene through the
same collectors ``shellforgeai triage docker`` already uses and summarizes it.
"""

from __future__ import annotations

from typing import Any

from shellforgeai.core.ask_routing import (
    EVIDENCE_BACKED,
    is_autofix_mutation_intent,
    is_mutation_request,
    is_triage_mutation_intent,
    route_ask_intent,
)
from shellforgeai.core.command_suggestions import suggest_safe_next_command
from shellforgeai.interactive.commands import _normalize_intent_text

EVIDENCE_SOURCE = "deterministic_shellforgeai"
TOPIC = "docker"
EVIDENCE_GATHERING_COMMAND = suggest_safe_next_command("docker")

# Operator-facing labels for the deterministic triage classes (see
# ``core.triage_ranking`` CLASS_* constants). Themes are what the operator
# reads ("restart churn"), not internal scorer keys ("crashloop").
_CLASS_THEME_LABELS: dict[str, str] = {
    "crashloop": "restart churn",
    "restart_storm": "restart churn",
    "noisy_errors": "log error signal",
    "bad_http": "bad http / upstream errors",
    "disk_pressure": "disk pressure",
    "permission_denied": "permission denied",
    "high_cpu_watch": "high cpu",
}

# Docker/operator question detection -----------------------------------------

_DOCKER_NOUNS: tuple[str, ...] = (
    "docker",
    "container",
    "containers",
    "compose",
    "the box",
    "the docker box",
)

# Operator "something is wrong" symptom words. Kept Docker/operator-flavored so
# plain conceptual questions ("explain DNS") never match. Performance words
# ("slow", "sluggish") are intentionally excluded — those route to the existing
# performance evidence path, not Docker triage grounding.
_OPERATOR_SYMPTOMS: tuple[str, ...] = (
    "wrong",
    "broken",
    "broke",
    "on fire",
    "suspicious",
    "suspect",
    "failing",
    "failed",
    "unhealthy",
    "crashing",
    "crashloop",
    "crash loop",
    "restarting",
    "restart loop",
    "misbehaving",
    "acting up",
    "not working",
    "down",
)

# A hyphenated lowercase token that looks like a container/service name
# (e.g. ``beszel-agent``). Used so "why is beszel-agent suspicious?" — which
# names no literal "docker" noun — still grounds in Docker triage evidence.
import re as _re  # noqa: E402  (kept local to this module's intent detection)

_CONTAINER_NAME_RE = _re.compile(r"\b[a-z][a-z0-9]*(?:[-_][a-z0-9]+)+\b")


def is_docker_operator_ask(text: str) -> bool:
    """Return True when an ``ask`` question is a Docker/operator question.

    These are the questions whose model-backed answer must be grounded in
    deterministic Docker triage evidence. Mutation / autonomous-fix asks are
    excluded here — those are refused earlier in the ask chain and must never
    be treated as groundable read-only questions.
    """
    raw = (text or "").strip()
    if not raw:
        return False
    if (
        is_mutation_request(raw)
        or is_triage_mutation_intent(raw)
        or is_autofix_mutation_intent(raw)
    ):
        return False
    # 1) The deterministic router already maps this to Docker/log evidence.
    route = route_ask_intent(raw)
    if route.mode == EVIDENCE_BACKED and route.target in {"docker", "logs"}:
        return True
    lowered = _normalize_intent_text(raw)
    raw_lower = raw.lower()
    has_symptom = any(sym in lowered for sym in _OPERATOR_SYMPTOMS) or any(
        sym in raw_lower for sym in _OPERATOR_SYMPTOMS
    )
    if not has_symptom:
        return False
    # 2) Operator symptom + an explicit Docker noun ("what is wrong with docker?").
    if any(noun in lowered for noun in _DOCKER_NOUNS):
        return True
    # 3) Operator symptom about a container-like name ("why is beszel-agent
    #    suspicious?"). The container-name regex runs on the raw lowercased
    #    text because intent normalization strips the hyphen that makes the
    #    name look like a container. The deterministic triage evidence surfaces
    #    the real suspect; we do not parse the name out of the question.
    return bool(_CONTAINER_NAME_RE.search(raw_lower))


# Deterministic evidence context ---------------------------------------------


def _evidence_themes(suspect: dict[str, Any]) -> list[str]:
    themes: list[str] = []
    for cls in suspect.get("classes") or []:
        label = _CLASS_THEME_LABELS.get(str(cls), str(cls).replace("_", " "))
        if label not in themes:
            themes.append(label)
    if themes:
        return themes
    # Fall back to evidence types if a suspect somehow carries no classes.
    for ev in suspect.get("evidence") or []:
        if isinstance(ev, dict):
            kind = str(ev.get("type") or "").split(":", 1)[-1].replace("_", " ").strip()
            if kind and kind not in themes:
                themes.append(kind)
        if len(themes) >= 3:
            break
    return themes


def _safe_next_command_for(top_name: str | None) -> str:
    return suggest_safe_next_command("docker", suspect=top_name)


def build_docker_evidence_context(*, top: int = 5) -> dict[str, Any]:
    """Build a bounded read-only Docker triage evidence context.

    Uses the existing deterministic ranking engine (``collect_scene`` +
    ``rank_scene``). Returns a context dict with the top suspect, severity,
    confidence, evidence themes, a real supported safe-next command, and a
    compact ``prompt_block`` suitable for the model context. On collection
    failure or an empty/healthy scene it returns an ungrounded context whose
    ``safe_next_command`` is a real evidence-gathering command — it never
    invents a suspect.
    """
    from shellforgeai.core import triage_ranking

    collection_error: str | None = None
    suspects: list[dict[str, Any]] = []
    containers_seen = 0
    try:
        scene = triage_ranking.collect_scene()
        ranked = triage_ranking.rank_scene(scene)
        suspects = list(ranked.get("suspects") or [])[: max(1, int(top))]
        summary = ranked.get("summary") if isinstance(ranked.get("summary"), dict) else {}
        containers_seen = int(summary.get("containers_seen", 0) or 0)
    except Exception as exc:  # collection failure: degrade, never hallucinate
        collection_error = f"{type(exc).__name__}: {exc}"

    top_suspect = suspects[0] if suspects else None
    top_name = str(top_suspect.get("name")) if top_suspect else None
    severity = str(top_suspect.get("severity")) if top_suspect else None
    confidence = str(top_suspect.get("confidence")) if top_suspect else None
    themes = _evidence_themes(top_suspect) if top_suspect else []
    safe_next_command = _safe_next_command_for(top_name)
    grounded = top_name is not None

    prompt_block = {
        "evidence_source": EVIDENCE_SOURCE,
        "topic": TOPIC,
        "grounded": grounded,
        "top_suspect": top_name,
        "severity": severity,
        "confidence": confidence,
        "evidence_themes": themes,
        "safe_next_command": safe_next_command,
        "mutation_allowed": False,
        "directive": (
            "Use ONLY this deterministic ShellForgeAI Docker triage evidence. "
            "Do not invent container names, suspects, severities, or commands. "
            "If grounded is false, tell the operator to run safe_next_command to "
            "gather evidence instead of guessing a diagnosis. Only suggest "
            "supported read-only ShellForgeAI commands (status, doctor, ops "
            "report, triage docker [detail <suspect>], propose/apply-preview/"
            "verify/handoff docker, remediation eligibility --explain). Never "
            "suggest cleanup, prune, image removal, file deletion, restart, "
            "compose mutation, 'shellforgeai diagnose <container>', "
            "'shellforgeai fix ...', or any mutation. ShellForgeAI is read-only "
            "here; real fixes are operator-run governed recipes only."
        ),
    }

    return {
        "evidence_source": EVIDENCE_SOURCE,
        "topic": TOPIC,
        "grounded": grounded,
        "evidence_available": bool(grounded or containers_seen > 0),
        "top_suspect": top_name,
        "severity": severity,
        "confidence": confidence,
        "evidence_themes": themes,
        "safe_next_command": safe_next_command,
        "evidence_gathering_command": EVIDENCE_GATHERING_COMMAND,
        "mutation_allowed": False,
        "suspects_ranked": len(suspects),
        "containers_seen": containers_seen,
        "collection_error": collection_error,
        "prompt_block": prompt_block,
    }


def render_docker_grounding_block(ctx: dict[str, Any]) -> str:
    """Render the deterministic grounded human answer (PR222 response contract).

    When a top suspect exists, the answer names the actual suspect, severity,
    confidence, and evidence themes and offers a real supported read-only safe
    next command. When evidence is missing it states that plainly and points to
    a real evidence-gathering command — it never guesses a suspect or a fix.
    Always ends with the no-mutation safety statement.
    """
    no_mutation = "No cleanup, restart, remediation, rollback, or Docker mutation was performed."
    if ctx.get("grounded") and ctx.get("top_suspect"):
        themes = ctx.get("evidence_themes") or []
        themes_text = ", ".join(str(t) for t in themes) if themes else "deterministic triage signal"
        lines = [
            "I'm using current ShellForgeAI Docker triage evidence.",
            "",
            f"Top suspect: {ctx.get('top_suspect')}",
            f"Severity: {ctx.get('severity')}",
            f"Confidence: {ctx.get('confidence')}",
            f"Evidence themes: {themes_text}",
            "",
            "Safe next step:",
            str(ctx.get("safe_next_command") or EVIDENCE_GATHERING_COMMAND),
            "",
            no_mutation,
        ]
        return "\n".join(lines).rstrip() + "\n"

    gather = str(ctx.get("evidence_gathering_command") or EVIDENCE_GATHERING_COMMAND)
    lines = [
        "I do not have current deterministic Docker triage evidence for this answer.",
        "",
        "Run:",
        gather,
        "",
        no_mutation,
    ]
    return "\n".join(lines).rstrip() + "\n"


def build_docker_evidence_explainability(ctx: dict[str, Any] | None) -> dict[str, Any]:
    """Build bounded ask evidence explainability metadata (PR224).

    The metadata is render-only and registry-backed. It never executes cleanup,
    restart, remediation, rollback, recovery, Docker/Compose mutation, a shell,
    or natural-language instructions.
    """
    grounded = bool(ctx and ctx.get("grounded") and ctx.get("top_suspect"))
    sources = [
        {
            "name": "docker_triage",
            "status": "used" if grounded else "missing",
            "path": None,
            "summary": "Top Docker suspect from deterministic triage.",
        },
        {
            "name": "docker_status",
            "status": "used" if grounded else "missing",
            "path": None,
            "summary": "Current Docker status/report evidence.",
        },
    ]
    safe_command = (
        str(ctx.get("safe_next_command"))
        if grounded and ctx and ctx.get("safe_next_command")
        else EVIDENCE_GATHERING_COMMAND
    )
    return {
        "enabled": True,
        "sources": sources,
        "missing_sources": [s["name"] for s in sources if s["status"] == "missing"],
        "top_suspect": ctx.get("top_suspect") if grounded and ctx else None,
        "severity": ctx.get("severity") if grounded and ctx else None,
        "confidence": ctx.get("confidence") if grounded and ctx else None,
        "evidence_themes": list(ctx.get("evidence_themes") or []) if grounded and ctx else [],
        "safe_next_command": safe_command,
        "grounding_limits": [
            "Answer is based on deterministic ShellForgeAI evidence."
            if grounded
            else "No diagnosis guessed without deterministic evidence.",
            "No cleanup performed.",
            "No restart performed.",
            "No remediation performed.",
            "No Docker/Compose mutation performed.",
        ],
    }


def render_docker_evidence_explainability(ctx: dict[str, Any] | None) -> str:
    """Render a concise human evidence explanation for ``ask --explain-evidence``."""
    meta = build_docker_evidence_explainability(ctx)
    by_name = {str(src["name"]): str(src["status"]) for src in meta["sources"]}
    lines = [
        "Evidence used:",
        f"- Docker triage evidence: {by_name.get('docker_triage', 'missing')}",
        f"- Docker status / ops report: {by_name.get('docker_status', 'missing')}",
    ]
    if meta.get("top_suspect"):
        lines.extend(
            [
                f"- Top suspect: {meta.get('top_suspect')}",
                f"- Severity: {meta.get('severity')}",
                f"- Confidence: {meta.get('confidence')}",
                "- Evidence themes: "
                + (", ".join(str(t) for t in meta.get("evidence_themes") or []) or "none"),
                "",
                "Safe next command:",
                str(meta.get("safe_next_command") or "no supported safe command is available"),
            ]
        )
    else:
        lines.extend(
            [
                "",
                "To gather evidence, run:",
                str(meta.get("safe_next_command") or "no supported safe command is available"),
            ]
        )
    lines.extend(["", "Boundaries:"])
    for limit in meta["grounding_limits"]:
        lines.append(f"- {limit}")
    return "\n".join(lines).rstrip() + "\n"


def docker_grounding_safety_flags() -> dict[str, bool]:
    """Read-only safety flags for the ask-grounding envelope/audit details."""
    return {
        "cleanup_executed": False,
        "docker_prune_executed": False,
        "docker_image_removed": False,
        "file_deleted": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "recovery_executed": False,
        "natural_language_execution": False,
        "shell_true": False,
    }


def build_docker_grounding_envelope(
    ctx: dict[str, Any], *, removed_commands: list[str] | None = None
) -> dict[str, Any]:
    """Build the read-only JSON envelope described in the PR222 response contract.

    Not wired to a CLI ``--json`` flag in this PR (``ask`` has no JSON mode);
    provided so the grounded shape is testable and reusable by the audit path.
    """
    return {
        "mode": "ask",
        "topic": TOPIC,
        "grounded": bool(ctx.get("grounded")),
        "evidence_source": EVIDENCE_SOURCE,
        "top_suspect": ctx.get("top_suspect"),
        "severity": ctx.get("severity"),
        "confidence": ctx.get("confidence"),
        "evidence_themes": list(ctx.get("evidence_themes") or []),
        "safe_next_command": ctx.get("safe_next_command"),
        "evidence_explainability": build_docker_evidence_explainability(ctx),
        "safe_command_registry": {
            "validated": True,
            "command_id": ("triage_docker_detail" if ctx.get("top_suspect") else "triage_docker"),
            "removed_suggestions": list(removed_commands or []),
        },
        "unsupported_command_suggestions_removed": list(removed_commands or []),
        "read_only": True,
        "mutation_performed": False,
        "safety": docker_grounding_safety_flags(),
    }
