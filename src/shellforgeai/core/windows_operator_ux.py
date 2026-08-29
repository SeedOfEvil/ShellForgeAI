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
WINDOWS_OPERATOR_INTENT_SERVICES: Final = "windows_services"
WINDOWS_OPERATOR_INTENT_DISK_CAPACITY: Final = "windows_disk_capacity"
WINDOWS_OPERATOR_INTENT_NETWORK_HEALTH: Final = "windows_network_health"
WINDOWS_OPERATOR_INTENT_FAILURE_HEALTH: Final = "windows_failure_health"
WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL: Final = "windows_mutation_refusal"
WINDOWS_OPERATOR_INTENT_RUNNING_INVENTORY: Final = "windows_running_inventory"
WINDOWS_OPERATOR_INTENT_ADVISORY_PLAN: Final = "windows_advisory_plan"

WINDOWS_INVENTORY_CONTAINER_LIMITATION: Final = (
    "Container inventory is not collected by the Windows evidence packet; container "
    "visibility is unavailable and must not be inferred from process or service names."
)

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
    WINDOWS_OPERATOR_INTENT_ADVISORY_PLAN: _WINDOWS_OPERATOR_COMMANDS,
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
    WINDOWS_OPERATOR_INTENT_SERVICES: (
        WINDOWS_SERVICES_COMMAND,
        WINDOWS_STANDARD_EVIDENCE_COMMAND,
        WINDOWS_EVENTS_COMMAND,
        WINDOWS_STATUS_COMMAND,
        WINDOWS_DOCTOR_COMMAND,
    ),
    WINDOWS_OPERATOR_INTENT_DISK_CAPACITY: (
        WINDOWS_STANDARD_EVIDENCE_COMMAND,
        WINDOWS_VOLUMES_COMMAND,
        WINDOWS_STATUS_COMMAND,
    ),
    WINDOWS_OPERATOR_INTENT_NETWORK_HEALTH: (
        WINDOWS_STANDARD_EVIDENCE_COMMAND,
        WINDOWS_NETWORK_COMMAND,
        WINDOWS_STATUS_COMMAND,
    ),
    WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL: (
        WINDOWS_STANDARD_EVIDENCE_COMMAND,
        WINDOWS_STATUS_COMMAND,
        WINDOWS_DOCTOR_COMMAND,
        WINDOWS_SERVICES_COMMAND,
    ),
    WINDOWS_OPERATOR_INTENT_RUNNING_INVENTORY: (
        WINDOWS_STANDARD_EVIDENCE_COMMAND,
        WINDOWS_PROCESSES_COMMAND,
        WINDOWS_SERVICES_COMMAND,
    ),
}

_HEADINGS: Final[dict[str, str]] = {
    WINDOWS_OPERATOR_INTENT_STATUS: "## Windows status guidance",
    WINDOWS_OPERATOR_INTENT_NEXT_CHECK: "## What to check first",
    WINDOWS_OPERATOR_INTENT_PERFORMANCE: "## Windows performance first pass",
    WINDOWS_OPERATOR_INTENT_STRONGEST_SIGNAL: "## Windows CPU/memory/disk/process comparison",
    WINDOWS_OPERATOR_INTENT_HANDOFF: "## Windows current-host handoff",
    WINDOWS_OPERATOR_INTENT_SERVICES: "## Windows services guidance",
    WINDOWS_OPERATOR_INTENT_DISK_CAPACITY: "## Windows volume capacity guidance",
    WINDOWS_OPERATOR_INTENT_NETWORK_HEALTH: "## Windows network guidance",
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
    docker_terms = ("docker", "compose")
    linux_terms = ("linux", "systemd", "journal", "iptables", "nftables")
    if any(term in text for term in docker_terms + linux_terms):
        return False
    mentions_container = _has_word(text, "container") or _has_word(text, "containers")
    host_inventory = any(
        _has_word(text, term) for term in ("process", "processes", "service", "services")
    )
    return not mentions_container or host_inventory


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
    return text in exact or (
        not _network_health(text)
        and (
            any(phrase in text for phrase in exact)
            or (
                ("what should" in text or "what do" in text)
                and ("check first" in text or "check next" in text)
            )
        )
    )


def _performance(text: str) -> bool:
    return any(
        phrase in text
        for phrase in (
            "system feels slow",
            "why does this system feel slow",
            "why is this windows host slow",
            "system feels sluggish",
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


_SERVICE_LEAD: Final = r"(?:show|list|check|get)(?: me)?(?: the)? "
_SERVICE_STATE: Final = r"(?:failed |running |stopped |all |automatic )?"
_SERVICE_NOUN: Final = r"(?:windows )?services?"
_SERVICE_ASPECT: Final = r"(?:status|health|state)"
_SERVICE_TAIL: Final = r"(?: on (?:this |the )?(?:host|machine|server|system|box))?"
_SERVICE_EXPLANATION: Final = r"(?: and explain what matters(?: to an operator(?: on call)?)?)?"

# Deliberately anchored full-string forms only. Broad substring matching on the
# word "service" would capture unrelated operator text such as "customer service
# status", "service desk", or "software as a service".
_SERVICE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern)
    for pattern in (
        rf"{_SERVICE_LEAD}{_SERVICE_STATE}{_SERVICE_NOUN}{_SERVICE_TAIL}",
        rf"{_SERVICE_LEAD}{_SERVICE_STATE}{_SERVICE_NOUN} {_SERVICE_ASPECT}{_SERVICE_TAIL}",
        rf"{_SERVICE_NOUN} {_SERVICE_ASPECT}{_SERVICE_TAIL}",
        (
            rf"(?:{_SERVICE_LEAD})?local service "
            rf"{_SERVICE_ASPECT}{_SERVICE_TAIL}{_SERVICE_EXPLANATION}"
        ),
        rf"windows services?{_SERVICE_TAIL}",
        rf"(?:are|is)(?: the)? {_SERVICE_STATE}{_SERVICE_NOUN} healthy{_SERVICE_TAIL}",
        rf"(?:what|which)(?: windows)? services? are running{_SERVICE_TAIL}",
    )
)


def _services(text: str) -> bool:
    exact = {
        "are the services healthy",
        "are any services unhealthy",
        "how do the services look",
        "any failed or unhealthy services",
    }
    return text in exact or any(pattern.fullmatch(text) for pattern in _SERVICE_PATTERNS)


_DISK_CAPACITY_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern)
    for pattern in (
        r"how is disk capacity",
        r"am i running out of disk space",
        r"are any drives low on space",
        r"how much free space is available",
        r"how does [a-z] look",
        r"are any windows volumes full",
        r"(?:windows )?(?:disk|drive|volume) (?:capacity|space|health)",
    )
)


def _disk_capacity(text: str) -> bool:
    return any(pattern.fullmatch(text) for pattern in _DISK_CAPACITY_PATTERNS)


_NETWORK_HEALTH_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern)
    for pattern in (
        r"how does the network look",
        r"is networking healthy",
        r"is networking okay",
        r"do you see a network problem",
        r"are the windows network interfaces healthy",
        r"(?:windows )?network (?:health|status)",
        (
            r"assess network health from the available evidence distinguish confirmed facts "
            r"from unknowns and give one safe read only next check"
        ),
        (
            r"evaluate network health using available evidence separate facts from unknowns "
            r"and recommend one read only check"
        ),
        (
            r"from the network observations state what is confirmed and unresolved then "
            r"provide a single safe non mutating next check"
        ),
        r"assess the network using the evidence we have and tell me what is known versus unknown",
        r"evaluate this host s network health from observed facts",
        (
            r"what can we actually confirm about network health and what read only check "
            r"should come next"
        ),
        r"review the network evidence and separate confirmed facts from unresolved questions",
        (
            r"using the available network observations assess what is known and what remains "
            r"uncertain"
        ),
        (
            r"what does the current network evidence confirm what is unknown and what should "
            r"i safely check next"
        ),
    )
)


def _network_health(text: str) -> bool:
    return any(pattern.fullmatch(text) for pattern in _NETWORK_HEALTH_PATTERNS)


_FAILURE_HEALTH_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern)
    for pattern in (
        r"is anything crashing(?: on (?:this |the )?windows host)?",
        r"are any (?:processes|services) crashing(?: on (?:this |the )?windows host)?",
        r"do you see any crash signals(?: on (?:this |the )?windows host)?",
        r"do you see any (?:failures or crashes|crashes)(?: on windows)?",
        r"is anything failing or crashing(?: on (?:this |the )?windows host)?",
        r"is anything crashing on (?:this |the )?windows host",
    )
)


def _failure_health(text: str) -> bool:
    """Match only bounded host crash-health questions, never Docker targets."""
    docker_terms = ("docker", "container", "containers", "compose")
    if any(_has_word(text, term) for term in docker_terms):
        return False
    return any(pattern.fullmatch(text) for pattern in _FAILURE_HEALTH_PATTERNS)


def _running_inventory(text: str) -> bool:
    """Recognize bounded, host-wide running-component inventory questions."""
    # Explicit Windows process analysis is still an inventory question: the
    # model is being asked to interpret the bounded process observations, not
    # to run a different collector or make a deterministic health diagnosis.
    # Keep this family deliberately narrow so generic analytical ranking and
    # explicit Docker/Linux questions retain their established routes.
    explicit_windows_process_analysis = (
        _has_word(text, "windows")
        and (_has_word(text, "process") or _has_word(text, "processes"))
        and not any(
            _has_word(text, term)
            for term in ("docker", "container", "containers", "linux", "systemd")
        )
        and (
            "working set" in text
            or "memory footprint" in text
            or (
                any(term in text for term in ("resource", "evidence"))
                and any(
                    term in text
                    for term in ("attention", "stand out", "largest", "inspect first", "rank")
                )
            )
        )
    )
    attention_question = re.fullmatch(
        r"which running (?:system )?(?:items|components) deserve attention and why", text
    )
    inventory_terms = (
        "inventory",
        "what is running",
        "what is currently running",
        "what processes services and containers",
        "running processes and services",
        "active components",
        "what is active",
        "overview of running processes and services",
    )
    evidence_terms = ("evidence", "observed", "actually see", "cannot observe", "visibility")
    component_terms = ("process", "processes", "service", "services", "component", "components")
    host_terms = ("system", "host", "machine", "windows")
    has_inventory_shape = any(term in text for term in inventory_terms)
    has_scope = (
        "inventory" in text
        or any(term in text for term in host_terms)
        or any(term in text for term in component_terms)
    )
    has_grounding = any(term in text for term in evidence_terms)
    return explicit_windows_process_analysis or attention_question is not None or (
        has_inventory_shape
        and has_scope
        and (
            has_grounding
            or "what is running" in text
            or "running processes and services" in text
            or "active components" in text
        )
    )


def _mutation(text: str, explicit_windows: bool) -> bool:
    if text in {
        "fix it",
        "fix it now",
        "apply the fix",
        "fix the network",
        "fix network",
        "fix dns",
    }:
        return True
    actions = (
        "clean up",
        "cleanup",
        "restart",
        "start",
        "stop",
        "kill",
        "terminate",
        "fix it",
        "fix anything",
        "remediate",
        "repair",
        "roll back",
        "rollback",
        "recover",
        "apply",
    )
    targets = (
        "windows",
        "service",
        "services",
        "process",
        "processes",
        "crash",
        "crashing",
        "fail",
        "failing",
        "failed",
        "cleanup",
        "clean up",
        "disk",
        "drive",
        "volume",
        "network",
        "unhealthy",
        "anything",
        "running items",
    )
    return any(a in text for a in actions) and (explicit_windows or any(t in text for t in targets))


def classify_windows_operator_intent(text: str, *, host_system: str) -> WindowsOperatorRoute | None:
    from shellforgeai.core.intent_nuance import (
        PLAN_HELP,
        classify_intent_nuance,
        has_distinct_plan_action,
    )

    normalized = normalize_windows_operator_text(text)
    host_is_windows = host_system.casefold() == "windows"
    explicit = _explicit_windows(normalized)
    if not normalized:
        return None
    scoped = _scoped(normalized, host_is_windows, explicit)
    nuance = classify_intent_nuance(text)
    if nuance.category == PLAN_HELP and scoped:
        if has_distinct_plan_action(text):
            return WindowsOperatorRoute(
                WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL, host_is_windows, explicit
            )
        return WindowsOperatorRoute(
            WINDOWS_OPERATOR_INTENT_ADVISORY_PLAN, host_is_windows, explicit
        )
    if _mutation(normalized, explicit) and scoped:
        return WindowsOperatorRoute(
            WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL, host_is_windows, explicit
        )
    if not scoped:
        return None
    for intent, predicate in (
        (WINDOWS_OPERATOR_INTENT_STATUS, _status),
        (WINDOWS_OPERATOR_INTENT_NEXT_CHECK, _next_check),
        (WINDOWS_OPERATOR_INTENT_PERFORMANCE, _performance),
        (WINDOWS_OPERATOR_INTENT_STRONGEST_SIGNAL, _strongest),
        (WINDOWS_OPERATOR_INTENT_HANDOFF, _handoff),
        (WINDOWS_OPERATOR_INTENT_RUNNING_INVENTORY, _running_inventory),
    ):
        if predicate(normalized):
            return WindowsOperatorRoute(intent, host_is_windows, explicit)
    return None


def classify_windows_interactive_intent(
    text: str, *, host_system: str
) -> WindowsOperatorRoute | None:
    """Interactive-only superset of :func:`classify_windows_operator_intent`.

    The shared classifier runs first and its route is returned unchanged, so
    mutation refusal and every existing read-only intent keep their exact
    priority and the top-level ``ask`` contract is untouched. Only text the
    shared classifier leaves unclassified is tested against the bounded
    read-only Windows service inventory/health and crash-health predicates.
    """
    shared = classify_windows_operator_intent(text, host_system=host_system)
    if shared is not None:
        return shared
    normalized = normalize_windows_operator_text(text)
    if not normalized:
        return None
    host_is_windows = host_system.casefold() == "windows"
    explicit = _explicit_windows(normalized)
    if not _scoped(normalized, host_is_windows, explicit):
        return None
    if _services(normalized):
        return WindowsOperatorRoute(WINDOWS_OPERATOR_INTENT_SERVICES, host_is_windows, explicit)
    if _disk_capacity(normalized):
        return WindowsOperatorRoute(
            WINDOWS_OPERATOR_INTENT_DISK_CAPACITY, host_is_windows, explicit
        )
    if _network_health(normalized):
        return WindowsOperatorRoute(
            WINDOWS_OPERATOR_INTENT_NETWORK_HEALTH, host_is_windows, explicit
        )
    if _failure_health(normalized):
        return WindowsOperatorRoute(
            WINDOWS_OPERATOR_INTENT_FAILURE_HEALTH, host_is_windows, explicit
        )
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
        lines.append(
            "These commands are optional drill-downs after the services command."
            if intent == WINDOWS_OPERATOR_INTENT_SERVICES
            else "These commands are optional drill-downs after the standard profile."
        )
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
