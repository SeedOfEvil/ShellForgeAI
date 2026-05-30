"""PR131 — intent nuance for command-help vs mutation requests.

ShellForgeAI is explanation-first and refusal-deterministic. A long-standing
UX gap is that it can *over-refuse* operator questions that only ask "what
command would I run?" / "how would I propose this?" — these are read-only
guidance requests, not execution requests.

This module is a small, deterministic classifier (no model, no I/O, no
execution) that distinguishes:

- ``command_help``        — "what command would I run to inspect X?"
- ``plan_help``           — "how would I propose remediation for X?"
- ``cleanup_review_help`` — "how do I review cleanup safely?"
- ``mutation_request``    — "restart it", "execute the plan", "clean it up"
- ``ambiguous_execute``   — "run that", "do it now" (no governed context)
- ``none``                — anything else (route normally)

Key nuance: a mutation verb appearing *inside* a command-help frame is
guidance, not execution. ``what command would restart this?`` is
``plan_help``; ``restart this`` is ``mutation_request``.

The render helpers emit operator-facing guidance/refusal text. They never
suggest execute/confirm commands and never include ``docker restart`` /
``docker compose restart`` as suggested commands (only safe read-only and
clearly-labelled plan-only commands).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Intent categories ---------------------------------------------------------
COMMAND_HELP = "command_help"
PLAN_HELP = "plan_help"
CLEANUP_REVIEW_HELP = "cleanup_review_help"
MUTATION_REQUEST = "mutation_request"
AMBIGUOUS_EXECUTE = "ambiguous_execute"
NONE = "none"

# Command-help "frames": phrasings that ask *how/what to run*, i.e. guidance.
_HELP_FRAMES: tuple[str, ...] = (
    "what command",
    "which command",
    "what commands",
    "what is the command",
    "what's the command",
    "whats the command",
    "what would i run",
    "what would you run",
    "what do i run",
    "what should i run",
    "show me the command",
    "show me the report command",
    "show me report command",
    "show me the status command",
    "show me status command",
    "show me a command",
    "show the command",
    "show me which command",
    "show me what command",
    "how would i",
    "how do i",
    "how can i safely",
    "how can i review",
    "how can i check",
    "how would you",
    "how should i",
)

# Guidance objects (ShellForgeAI-domain). Order encodes precedence below.
_CLEANUP_OBJECTS: tuple[str, ...] = ("cleanup", "clean up", "clean-up")
_ELIGIBILITY_OBJECTS: tuple[str, ...] = ("eligible", "eligibility")
_PLAN_OBJECTS: tuple[str, ...] = (
    "propose",
    "proposal",
    "remediation",
    "remediate",
    "plan",
    "restart",
    "rollback",
    "roll back",
)
_REPORT_OBJECTS: tuple[str, ...] = (
    "ops report",
    "operator report",
    "status report",
    "report history",
    "history",
    "compare reports",
    "compare report",
    "compare",
    "export the report",
    "export report",
    "export",
    "save the report",
    "save report",
    "report",
    "status",
)
_INSPECT_OBJECTS: tuple[str, ...] = (
    "inspect",
    "check",
    "look at",
    "review",
    "examine",
    "investigate",
    "triage",
    "detail",
    "status of",
)
# Domain anchors that make a bare "inspect"/"check" question ShellForgeAI-shaped
# even when no explicit target is named.
_INSPECT_DOMAIN_ANCHORS: tuple[str, ...] = (
    "container",
    "docker",
    "triage",
    "compose",
    "suspect",
    "this",
    "that",
)

# Ambiguous "just do it" phrasings. Matched against the *whole* normalized
# input (exact), never as substrings, so they do not swallow phrasings like
# "run the remediation plan" (a concrete mutation request) or PR124 read-only
# follow-up confirmations such as "do it"/"run it".
_AMBIGUOUS_EXACT: frozenset[str] = frozenset(
    {
        "run that",
        "run that now",
        "run this now",
        "do it now",
        "do that now",
        "do the thing",
        "execute it",
        "execute that",
        "execute it now",
        "execute that now",
        "apply it",
        "apply that",
        "apply it now",
        "run the command for me",
        "run the command",
        "just do it now",
    }
)

# Mutation verbs/phrases (no command-help frame) → deterministic refusal.
_MUTATION_SIGNALS: tuple[str, ...] = (
    "restart",
    "reboot",
    "delete",
    "remove",
    "prune",
    "clean up",
    "cleanup",
    "kill ",
    "stop ",
    "start ",
    "execute",
    "apply",
    "rollback",
    "roll back",
    "remediate",
    "run it",
    "run the",
    "do the remediation",
    "fix it",
    "fix this",
    "fix everything",
    "recreate",
    "rebuild",
    "compose restart",
    "compose up",
    "compose down",
    "docker restart",
    "system prune",
    "volume prune",
)

_TARGET_RE = re.compile(r"\bsfai[-_][a-z0-9][a-z0-9._-]{0,63}")


@dataclass(frozen=True)
class IntentNuance:
    """Deterministic classification of an ask/interactive line."""

    category: str
    target: str = ""
    signal: str = ""


def _normalize(text: str) -> str:
    lowered = (text or "").lower().replace("’", "'")
    return " ".join(lowered.split())


def _extract_target(low: str) -> str:
    match = _TARGET_RE.search(low)
    if match:
        return match.group(0)
    if "shellforgeai" in low:
        return "shellforgeai"
    return ""


def _has_help_frame(low: str) -> str:
    for frame in _HELP_FRAMES:
        if frame in low:
            return frame
    return ""


def _mutation_signal(low: str) -> str:
    for sig in _MUTATION_SIGNALS:
        if sig in low:
            return sig.strip()
    return ""


def _report_command_signal(low: str, frame: str = "") -> str:
    has_report_context = "report" in low or "ops" in low or "operator" in low
    has_status_report_context = "status report" in low
    helpish = bool(
        frame
        or "command" in low
        or "show me" in low
        or low.startswith(("show ", "give me "))
        or "how do i see" in low
        or "how do i view" in low
        or "how can i see" in low
        or "how can i view" in low
    )

    if "history" in low and (has_report_context or has_status_report_context):
        return "report_history"
    if "export" in low and has_report_context and helpish:
        return "report_export"
    if "save" in low and has_report_context and helpish:
        return "report_save"
    if "compare" in low and (has_report_context or "reports" in low) and helpish:
        return "report_compare"
    general_helpish = bool(frame or "command" in low or "what do i run" in low)
    if (
        has_report_context or has_status_report_context or ("status" in low and general_helpish)
    ) and general_helpish:
        return "report"
    return ""


def classify_intent_nuance(text: str) -> IntentNuance:
    """Classify a natural-language line into a PR131 intent category.

    Never executes anything. A command-help frame always wins over a mutation
    verb embedded inside it, so ``what command would restart this?`` is
    guidance, not execution.
    """

    low = _normalize(text)
    if not low:
        return IntentNuance(category=NONE)

    target = _extract_target(low)
    frame = _has_help_frame(low)
    report_signal = _report_command_signal(low, frame)
    mutation_signal = _mutation_signal(low)
    if not report_signal and mutation_signal and ("report" in low or "status" in low):
        report_signal = "report"

    if report_signal and mutation_signal:
        return IntentNuance(category=COMMAND_HELP, target=target, signal=f"{report_signal}_mixed")

    if frame:
        # Precedence: cleanup → eligibility → report → plan → inspect.
        if any(obj in low for obj in _CLEANUP_OBJECTS):
            return IntentNuance(category=CLEANUP_REVIEW_HELP, target=target, signal=frame)
        if any(obj in low for obj in _ELIGIBILITY_OBJECTS):
            return IntentNuance(category=COMMAND_HELP, target=target, signal="eligibility")
        if report_signal:
            return IntentNuance(category=COMMAND_HELP, target=target, signal=report_signal)
        if any(obj in low for obj in _PLAN_OBJECTS):
            return IntentNuance(category=PLAN_HELP, target=target, signal=frame)
        if any(obj in low for obj in _INSPECT_OBJECTS) and (
            target or any(anchor in low for anchor in _INSPECT_DOMAIN_ANCHORS)
        ):
            return IntentNuance(category=COMMAND_HELP, target=target, signal="inspect")
        # Help frame but no recognized ShellForgeAI-domain object: route normally.
        return IntentNuance(category=NONE)

    if report_signal:
        return IntentNuance(category=COMMAND_HELP, target=target, signal=report_signal)

    if low in _AMBIGUOUS_EXACT:
        return IntentNuance(category=AMBIGUOUS_EXECUTE, signal=low)

    if mutation_signal:
        return IntentNuance(category=MUTATION_REQUEST, target=target, signal=mutation_signal)

    return IntentNuance(category=NONE)


# Rendering helpers ---------------------------------------------------------
#
# All helpers return plain strings. They only ever present read-only or
# clearly-labelled plan-only commands, and always state that no action was
# taken. They never emit execute/confirm or docker (compose) restart commands.

_NO_ACTION = "No action was taken."


def _target_or_placeholder(target: str) -> str:
    return target or "<target>"


def render_command_help(nuance: IntentNuance) -> str:
    """Render read-only command guidance for an inspect/eligibility/report ask."""

    if nuance.signal == "eligibility":
        tgt = _target_or_placeholder(nuance.target)
        return (
            f"{_NO_ACTION}\n\n"
            "Safe command:\n"
            f"  shellforgeai remediation eligibility --target {tgt} --explain\n\n"
            "Why:\n"
            "- Read-only eligibility explanation.\n"
            "- Does not restart, remediate, or change Docker state."
        )

    if nuance.signal.endswith("_mixed"):
        base_signal = nuance.signal.removesuffix("_mixed")
        command = "shellforgeai ops report"
        if base_signal == "report_history":
            heading = "Report history command:"
            command = "shellforgeai ops report history --limit 5"
        elif base_signal == "report_save":
            heading = "Report save command:"
            command = "shellforgeai ops report --save"
        elif base_signal == "report_export":
            heading = "Report export command:"
            command = "shellforgeai ops report --save"
        elif base_signal == "report_compare":
            heading = "Report compare command:"
            command = "shellforgeai ops report compare-latest"
        else:
            heading = "Report command:"
        return (
            f"{heading}\n"
            f"  {command}\n\n"
            "Mutation refused:\n"
            "- I will not restart Compose, restart services, or clean up Docker "
            "from natural language.\n"
            f"- {_NO_ACTION}\n\n"
            "Safe next command:\n"
            "  shellforgeai ops report --brief"
        )
    if nuance.signal == "report_export":
        return (
            f"{_NO_ACTION}\n\n"
            "Save a report first if you need a report ID:\n"
            "  shellforgeai ops report --save\n\n"
            "Then export and validate the handoff artifact:\n"
            "  shellforgeai ops report export <report_id>\n"
            "  shellforgeai ops report export-validate <export_id>\n\n"
            "Note:\n"
            "- Save/export writes ShellForgeAI-owned artifact files only.\n"
            "- Use a real report ID from history; do not invent IDs.\n"
            "- No Docker/system mutation is performed.\n\n"
            "First safe command:\n"
            "  shellforgeai ops report --save"
        )
    if nuance.signal == "report_save":
        return (
            f"{_NO_ACTION}\n\n"
            "To save a ShellForgeAI-owned artifact:\n"
            "  shellforgeai ops report --save\n\n"
            "To validate it later:\n"
            "  shellforgeai ops report validate <report_id_or_path>\n\n"
            "Note:\n"
            "- This writes ShellForgeAI-owned artifact files only.\n"
            "- No Docker/system mutation is performed.\n\n"
            "First safe command:\n"
            "  shellforgeai ops report --save"
        )
    if nuance.signal == "report_compare":
        return (
            f"{_NO_ACTION}\n\n"
            "Use:\n"
            "  shellforgeai ops report history --limit 5\n"
            "  shellforgeai ops report compare-latest\n"
            "  shellforgeai ops report compare <before_report> <after_report>\n\n"
            "First safe command:\n"
            "  shellforgeai ops report history --limit 5"
        )
    if nuance.signal == "report_history":
        return (
            f"{_NO_ACTION}\n\n"
            "Use:\n"
            "  shellforgeai ops report history --limit 5\n\n"
            "First safe command:\n"
            "  shellforgeai ops report history --limit 5"
        )
    if nuance.signal == "report":
        return (
            f"{_NO_ACTION}\n\n"
            "Use:\n"
            "  shellforgeai ops report\n\n"
            "For machine-readable output:\n"
            "  shellforgeai ops report --json\n\n"
            "To save a handoff artifact:\n"
            "  shellforgeai ops report --save\n\n"
            "First safe command:\n"
            "  shellforgeai ops report"
        )
    # inspect (default command-help)
    if nuance.target:
        tgt = nuance.target
        return (
            f"{_NO_ACTION}\n\n"
            "Safe command:\n"
            f"  shellforgeai triage docker detail {tgt}\n\n"
            "Optionally:\n"
            f"  shellforgeai remediation eligibility --target {tgt} --explain\n\n"
            "Why:\n"
            "- Read-only inspection.\n"
            "- Does not restart, clean up, or change Docker state."
        )
    return (
        f"{_NO_ACTION}\n\n"
        "Safe commands:\n"
        "  shellforgeai triage docker\n"
        "  shellforgeai triage docker detail <target>\n\n"
        "Why:\n"
        "- Read-only inspection.\n"
        "- Does not restart, clean up, or change Docker state."
    )


def render_plan_help(nuance: IntentNuance) -> str:
    """Render plan-only guidance (clearly labelled, never executed)."""

    tgt = _target_or_placeholder(nuance.target)
    return (
        f"{_NO_ACTION}\n\n"
        "Plan-only command:\n"
        f"  shellforgeai remediation plan --target {tgt} --scenario <scenario>\n\n"
        "Note:\n"
        "- This creates a plan only.\n"
        "- Plan-only; does not execute remediation.\n"
        "- Production/unallowlisted targets may block.\n"
        "- Execution remains gated by validate, preflight, and explicit confirmation.\n\n"
        "Read-only first:\n"
        f"  shellforgeai triage docker detail {tgt}\n"
        f"  shellforgeai remediation eligibility --target {tgt} --explain"
    )


def render_cleanup_review_help(nuance: IntentNuance) -> str:
    """Render cleanup review/prepare guidance (read-only / plan-only)."""

    return (
        f"{_NO_ACTION}\n\n"
        "Safe command:\n"
        "  shellforgeai audit cleanup review\n\n"
        "Optionally (prepares a plan only):\n"
        "  shellforgeai audit cleanup prepare --category exports "
        "--max-age-days 7 --keep-latest 5\n\n"
        "Note:\n"
        "- Cleanup review and prepare are read-only / plan-only.\n"
        "- Cleanup execution remains gated and is not run from here."
    )


def render_ambiguous_execute_refusal(text: str = "") -> str:
    """Render a deterministic refusal for ambiguous 'just do it' phrasings."""

    quoted = _normalize(text)
    referent = f'"{quoted}"' if quoted else "that"
    return (
        "Refused: natural-language mutation is not allowed.\n\n"
        f"{_NO_ACTION}\n\n"
        f"I can't tell which concrete governed action {referent} refers to, and "
        "ShellForgeAI does not execute mutation from natural language.\n\n"
        "First safe command:\n"
        "  shellforgeai ops report\n\n"
        "To perform governed remediation, run the explicit CLI workflow:\n"
        "plan -> validate -> preflight -> execute with explicit confirmation."
    )


def render_intent_nuance(nuance: IntentNuance, *, text: str = "") -> str:
    """Dispatch to the right renderer for a command-help / ambiguous nuance."""

    if nuance.category == COMMAND_HELP:
        return render_command_help(nuance)
    if nuance.category == PLAN_HELP:
        return render_plan_help(nuance)
    if nuance.category == CLEANUP_REVIEW_HELP:
        return render_cleanup_review_help(nuance)
    if nuance.category == AMBIGUOUS_EXECUTE:
        return render_ambiguous_execute_refusal(text)
    return _NO_ACTION
