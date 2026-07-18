"""Pure Windows operator UX routing and deterministic guidance."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

WINDOWS_OPERATOR_INTENT_STATUS: Final = "windows_status"
WINDOWS_OPERATOR_INTENT_NEXT_CHECK: Final = "windows_next_check"
WINDOWS_OPERATOR_INTENT_PERFORMANCE: Final = "windows_performance"
WINDOWS_OPERATOR_INTENT_STRONGEST_SIGNAL: Final = "windows_strongest_signal"
WINDOWS_OPERATOR_INTENT_HANDOFF: Final = "windows_handoff"
WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL: Final = "windows_mutation_refusal"

WINDOWS_STANDARD_EVIDENCE_COMMAND: Final = "shellforgeai windows evidence --profile standard --json"
WINDOWS_STATUS_COMMAND: Final = "shellforgeai windows status --json"
WINDOWS_DOCTOR_COMMAND: Final = "shellforgeai windows doctor --json"
WINDOWS_PROCESSES_COMMAND: Final = "shellforgeai windows processes --json --limit 10"
WINDOWS_EVENTS_COMMAND: Final = "shellforgeai windows events --json --limit 50 --since-hours 24"
WINDOWS_NETWORK_COMMAND: Final = "shellforgeai windows network --json"
WINDOWS_VOLUMES_COMMAND: Final = "shellforgeai windows volumes --json --limit 32"
WINDOWS_SERVICES_COMMAND: Final = "shellforgeai windows services --json --limit 25"
WINDOWS_PLATFORM_DOCTOR_COMMAND: Final = "shellforgeai platform doctor --json"

_WINDOWS_OPERATOR_COMMANDS: Final[tuple[str, ...]] = (
    WINDOWS_STANDARD_EVIDENCE_COMMAND,
    WINDOWS_STATUS_COMMAND,
    WINDOWS_DOCTOR_COMMAND,
    WINDOWS_PROCESSES_COMMAND,
    WINDOWS_EVENTS_COMMAND,
    WINDOWS_NETWORK_COMMAND,
    WINDOWS_VOLUMES_COMMAND,
    WINDOWS_SERVICES_COMMAND,
)

_COMMANDS_BY_INTENT: Final[dict[str, tuple[str, ...]]] = {
    WINDOWS_OPERATOR_INTENT_STATUS: (
        WINDOWS_STANDARD_EVIDENCE_COMMAND,
        WINDOWS_STATUS_COMMAND,
        WINDOWS_DOCTOR_COMMAND,
    ),
    WINDOWS_OPERATOR_INTENT_NEXT_CHECK: _WINDOWS_OPERATOR_COMMANDS,
    WINDOWS_OPERATOR_INTENT_PERFORMANCE: (
        WINDOWS_STANDARD_EVIDENCE_COMMAND,
        WINDOWS_PROCESSES_COMMAND,
        WINDOWS_EVENTS_COMMAND,
        WINDOWS_NETWORK_COMMAND,
        WINDOWS_VOLUMES_COMMAND,
        WINDOWS_STATUS_COMMAND,
    ),
    WINDOWS_OPERATOR_INTENT_STRONGEST_SIGNAL: (
        WINDOWS_STANDARD_EVIDENCE_COMMAND,
        WINDOWS_STATUS_COMMAND,
        WINDOWS_PROCESSES_COMMAND,
        WINDOWS_VOLUMES_COMMAND,
    ),
    WINDOWS_OPERATOR_INTENT_HANDOFF: (
        WINDOWS_STANDARD_EVIDENCE_COMMAND,
        WINDOWS_STATUS_COMMAND,
        WINDOWS_DOCTOR_COMMAND,
    ),
    WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL: (
        WINDOWS_STANDARD_EVIDENCE_COMMAND,
        WINDOWS_STATUS_COMMAND,
        WINDOWS_DOCTOR_COMMAND,
        WINDOWS_SERVICES_COMMAND,
    ),
}

_HEADINGS: Final[dict[str, str]] = {
    WINDOWS_OPERATOR_INTENT_STATUS: "## Windows status guidance",
    WINDOWS_OPERATOR_INTENT_NEXT_CHECK: "## What to check first",
    WINDOWS_OPERATOR_INTENT_PERFORMANCE: "## Windows performance first pass",
    WINDOWS_OPERATOR_INTENT_STRONGEST_SIGNAL: "## Windows CPU/memory/disk/process comparison",
    WINDOWS_OPERATOR_INTENT_HANDOFF: "## Windows current-host handoff",
}


@dataclass(frozen=True)
class WindowsOperatorRoute:
    intent: str
    host_is_windows: bool
    explicit_windows: bool


def normalize_windows_operator_text(text: str) -> str:
    """Normalize operator text for exact phrase and word-boundary matching."""
    return re.sub(r"[^a-z0-9]+", " ", text.casefold()).strip()


def _has_word(text: str, word: str) -> bool:
    return re.search(rf"(?:^| ){re.escape(word)}(?: |$)", text) is not None


def _explicit_windows(text: str) -> bool:
    return any(
        phrase in text for phrase in ("windows", "windows server", "win2025", "win2025 sfai01")
    )


def _scoped(text: str, host_is_windows: bool, explicit_windows: bool) -> bool:
    if explicit_windows:
        return True
    if not host_is_windows:
        return False
    docker_terms = ("docker", "container", "containers", "compose")
    linux_terms = ("linux", "systemd", "journal", "iptables", "nftables")
    return not any(term in text for term in docker_terms + linux_terms)


def _status(text: str) -> bool:
    exact = {
        "show me the system status",
        "show system status",
        "system status",
        "show me the windows status",
        "windows status",
        "what is happening on this machine",
        "what is happening on this windows host",
        "is this system healthy",
        "is this windows system healthy",
        "is everything okay with this computer",
        "anything wrong with this machine",
        "machine health",
        "host health",
        "computer health",
    }
    return text in exact or any(phrase in text for phrase in exact)


def _next_check(text: str) -> bool:
    exact = {
        "what should i check first",
        "what should we check first",
        "what should i check next",
        "what should we check next",
        "what do i check first",
        "what do i check next",
        "next check",
        "next checks",
        "what next",
        "what exactly should i check next if this is a windows host",
    }
    return (
        text in exact
        or any(phrase in text for phrase in exact)
        or (
            ("what should" in text or "what do" in text)
            and ("check first" in text or "check next" in text)
        )
    )


def _performance(text: str) -> bool:
    return any(
        phrase in text
        for phrase in (
            "system feels slow",
            "system feels a bit slow",
            "feels slow",
            "weird latency",
            "latency",
            "lag",
            "laggy",
            "performance issue",
            "first pass diagnosis",
            "practical first pass diagnosis",
            "give me a first pass windows check",
        )
    )


def _strongest(text: str) -> bool:
    has_all_terms = all(_has_word(text, term) for term in ("cpu", "memory", "disk")) and (
        _has_word(text, "process") or _has_word(text, "processes")
    )
    has_ask = ("strongest" in text and "signal" in text) or any(
        phrase in text for phrase in ("strongest issue", "strongest indicator", "comparison")
    )
    return has_all_terms and has_ask


def _handoff(text: str) -> bool:
    return any(
        phrase in text
        for phrase in (
            "operator handoff",
            "current host handoff",
            "handoff for this windows host",
            "write a concise operator handoff",
            "handoff for the current host",
        )
    )


def _mutation(text: str, explicit_windows: bool) -> bool:
    actions = (
        "clean up",
        "cleanup",
        "restart",
        "start",
        "stop",
        "kill",
        "terminate",
        "fix it",
        "remediate",
        "roll back",
        "rollback",
        "recover",
        "apply",
    )
    targets = ("windows", "service", "services", "process", "processes", "cleanup", "clean up")
    return any(a in text for a in actions) and (explicit_windows or any(t in text for t in targets))


def classify_windows_operator_intent(text: str, *, host_system: str) -> WindowsOperatorRoute | None:
    normalized = normalize_windows_operator_text(text)
    host_is_windows = host_system.casefold() == "windows"
    explicit = _explicit_windows(normalized)
    if not normalized:
        return None
    if _mutation(normalized, explicit) and _scoped(normalized, host_is_windows, explicit):
        return WindowsOperatorRoute(
            WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL, host_is_windows, explicit
        )
    if not _scoped(normalized, host_is_windows, explicit):
        return None
    for intent, predicate in (
        (WINDOWS_OPERATOR_INTENT_STATUS, _status),
        (WINDOWS_OPERATOR_INTENT_NEXT_CHECK, _next_check),
        (WINDOWS_OPERATOR_INTENT_PERFORMANCE, _performance),
        (WINDOWS_OPERATOR_INTENT_STRONGEST_SIGNAL, _strongest),
        (WINDOWS_OPERATOR_INTENT_HANDOFF, _handoff),
    ):
        if predicate(normalized):
            return WindowsOperatorRoute(intent, host_is_windows, explicit)
    return None


def windows_operator_safe_commands(intent: str) -> tuple[str, ...]:
    return tuple(_COMMANDS_BY_INTENT.get(intent, (WINDOWS_STANDARD_EVIDENCE_COMMAND,)))


def render_windows_operator_safe_next_section(intent: str) -> str:
    """Render only canonical safe-next commands and no-action markers."""
    commands = windows_operator_safe_commands(intent)
    first, rest = commands[0], commands[1:]
    lines = ["Start with this bounded read-only check:", f"- {first}"]
    if rest:
        lines.extend(("", "Relevant read-only drill-downs:"))
        lines.extend(f"- {cmd}" for cmd in rest)
        lines.append("These commands are optional drill-downs after the standard profile.")
    lines.extend(
        [
            "",
            "No command was executed. No action was taken.",
            (
                "No cleanup, restart, service control, process termination, remediation, "
                "rollback, or recovery was performed."
            ),
        ]
    )
    return "\n".join(lines)


def render_windows_operator_guidance(
    route: WindowsOperatorRoute,
    *,
    assessment_lines: tuple[str, ...] = (),
    limitation_lines: tuple[str, ...] = (),
) -> str:
    commands = windows_operator_safe_commands(route.intent)
    if route.intent == WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL:
        lines = [
            "Refused: natural-language mutation is not allowed.",
            "No command was executed. No action was taken.",
            "",
            "Cleanup, restart, and service control are mutating/service-impacting actions.",
            (
                "Cleanup, restart, service control, process termination, remediation, rollback, "
                "and recovery are mutating or service-impacting actions."
            ),
            "Natural language cannot execute them.",
            (
                "Any future mutation capability must use an explicit named, reviewed, "
                "confirmed recipe."
            ),
            "This request did not select, approve, prepare, or execute a recipe.",
            "",
            "Safe Windows read-only alternatives:",
        ]
        lines.extend(f"- {cmd}" for cmd in commands)
        lines.extend(
            [
                "",
                (
                    "No cleanup, restart, service control, process termination, remediation, "
                    "rollback, or recovery was performed."
                ),
            ]
        )
        return "\n".join(lines)

    lines = [_HEADINGS.get(route.intent, "## Windows operator guidance")]
    if route.host_is_windows:
        lines.append("Context: Windows local read-only.")
        lines.append("Context/visibility: windows-local-read-only.")
    else:
        lines.extend(
            [
                "Context: Windows guidance requested from a non-Windows host.",
                "No Windows probing was performed.",
                "Windows commands below are commands to run on the Windows host.",
                "Current-host platform check:",
                f"- {WINDOWS_PLATFORM_DOCTOR_COMMAND}",
            ]
        )
    if assessment_lines:
        lines.extend(("", "Assessment:"))
        lines.extend(assessment_lines)
    if limitation_lines:
        lines.extend(("", "Limitations:"))
        lines.extend(limitation_lines)
    lines.extend(("", render_windows_operator_safe_next_section(route.intent)))
    return "\n".join(lines)
