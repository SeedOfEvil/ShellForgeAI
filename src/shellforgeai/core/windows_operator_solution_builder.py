"""Pure deterministic adapter from Windows-native evidence to OperatorSolution.

The adapter consumes an already-built bounded evidence packet and an already-
classified route.  It does not collect, classify text, execute, persist, or
contact any host or provider.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import ValidationError

from shellforgeai.core.evidence import TargetType
from shellforgeai.core.operator_solution import (
    Confidence,
    OperatorProcedureStep,
    OperatorSolution,
    ProvenanceKind,
    ProvenanceReference,
    RecoveryMode,
    Risk,
    RollbackRecoveryGuidance,
    VerificationCriterion,
)
from shellforgeai.core.windows_operator_ux import (
    WINDOWS_OPERATOR_INTENT_ADVISORY_PLAN,
    WINDOWS_OPERATOR_INTENT_DISK_CAPACITY,
    WINDOWS_OPERATOR_INTENT_FAILURE_HEALTH,
    WINDOWS_OPERATOR_INTENT_HANDOFF,
    WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL,
    WINDOWS_OPERATOR_INTENT_NETWORK_HEALTH,
    WINDOWS_OPERATOR_INTENT_NEXT_CHECK,
    WINDOWS_OPERATOR_INTENT_PERFORMANCE,
    WINDOWS_OPERATOR_INTENT_RUNNING_INVENTORY,
    WINDOWS_OPERATOR_INTENT_SERVICES,
    WINDOWS_OPERATOR_INTENT_STATUS,
    WINDOWS_OPERATOR_INTENT_STRONGEST_SIGNAL,
    WindowsOperatorRoute,
    windows_operator_safe_commands,
)


class WindowsOperatorSolutionBuildError(ValueError):
    """Controlled failure to normalize incompatible Windows evidence."""


_OUTCOMES = {
    WINDOWS_OPERATOR_INTENT_ADVISORY_PLAN: (
        "Produce an evidence-backed Windows operator plan with bounded read-only "
        "investigation steps and explicit limitations."
    ),
    WINDOWS_OPERATOR_INTENT_STATUS: (
        "Assess the current Windows host status from fresh read-only evidence."
    ),
    WINDOWS_OPERATOR_INTENT_NEXT_CHECK: "Identify the next bounded read-only Windows check.",
    WINDOWS_OPERATOR_INTENT_PERFORMANCE: (
        "Assess visible Windows performance signals without inferring unavailable metrics."
    ),
    WINDOWS_OPERATOR_INTENT_STRONGEST_SIGNAL: (
        "Compare the available Windows host signals and identify the strongest observed signal."
    ),
    WINDOWS_OPERATOR_INTENT_HANDOFF: "Prepare a bounded evidence-backed Windows operator handoff.",
    WINDOWS_OPERATOR_INTENT_SERVICES: (
        "Review the observed Windows service inventory and state without treating stopped "
        "services as failures."
    ),
    WINDOWS_OPERATOR_INTENT_DISK_CAPACITY: (
        "Review observed Windows disk and volume capacity using read-only evidence."
    ),
    WINDOWS_OPERATOR_INTENT_NETWORK_HEALTH: (
        "Review available Windows network metadata without claiming end-to-end health."
    ),
    WINDOWS_OPERATOR_INTENT_FAILURE_HEALTH: (
        "Review bounded Windows event and health evidence for observed failure signals."
    ),
    WINDOWS_OPERATOR_INTENT_RUNNING_INVENTORY: (
        "Review the bounded Windows process and service inventory."
    ),
}
_COMPONENTS = ("memory", "disk", "volumes", "processes", "services", "events", "network")
_TARGET_BY_INTENT = {
    WINDOWS_OPERATOR_INTENT_SERVICES: TargetType.service,
    WINDOWS_OPERATOR_INTENT_DISK_CAPACITY: TargetType.disk,
    WINDOWS_OPERATOR_INTENT_NETWORK_HEALTH: TargetType.network,
}


def _clean_text(value: Any) -> str:
    return " ".join(str(value).split())


def _bounded_unique(values: Sequence[Any], *, limit: int = 64) -> tuple[str, ...]:
    # Limitations and gaps are semantically unordered packet sets. Sorting their
    # normalized values prevents collector insertion order from changing output.
    return tuple(sorted({_clean_text(value) for value in values if _clean_text(value)}))[:limit]


def _block(packet: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = packet.get(name)
    return value if isinstance(value, Mapping) else {}


def _observations(packet: Mapping[str, Any]) -> tuple[str, ...]:
    observations: list[str] = []
    memory = _block(packet, "memory")
    if memory.get("available") is True:
        observations.append(f"memory used_percent={memory.get('used_percent', 'unknown')}")
    disk = _block(packet, "disk")
    if disk.get("available") is True:
        observations.append(
            f"disk root_free_bytes={disk.get('root_free_bytes', 'unknown')} "
            f"visible_roots={len(disk.get('roots') or ())}"
        )
    for name in ("volumes", "events", "network"):
        component = _block(packet, name)
        if component.get("available") is True:
            summary = component.get("summary")
            keys = sorted(summary) if isinstance(summary, Mapping) else []
            observations.append(
                f"{name} metadata available" + (f" ({', '.join(keys[:8])})" if keys else "")
            )
    processes = _block(packet, "processes")
    if processes.get("available") is True:
        observations.append(
            f"processes observed total={processes.get('total_count', 'unknown')} "
            f"returned={processes.get('returned_count', 'unknown')}"
        )
    services = _block(packet, "services")
    if services.get("available") is True:
        observations.append(
            f"services observed total={services.get('total_count', 'unknown')} "
            f"running={services.get('running_count', 'unknown')} "
            f"stopped={services.get('stopped_count', 'unknown')}"
        )
    return tuple(observations)


def _validate(packet: Mapping[str, Any], route: WindowsOperatorRoute) -> None:
    if not isinstance(packet, Mapping):
        raise WindowsOperatorSolutionBuildError("evidence must be a structured mapping")
    if not isinstance(route, WindowsOperatorRoute):
        raise WindowsOperatorSolutionBuildError("route must be a WindowsOperatorRoute")
    if route.intent == WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL or route.intent not in _OUTCOMES:
        raise WindowsOperatorSolutionBuildError("route is not a supported read-only Windows intent")
    if not route.host_is_windows:
        raise WindowsOperatorSolutionBuildError("route does not represent a local Windows host")
    if str(packet.get("platform", "")).casefold() != "windows":
        raise WindowsOperatorSolutionBuildError("evidence platform must be Windows")
    if packet.get("visibility") != "windows-local-read-only":
        raise WindowsOperatorSolutionBuildError(
            "evidence visibility must be Windows local read-only"
        )
    if packet.get("read_only") is not True or packet.get("mutation_performed") is not False:
        raise WindowsOperatorSolutionBuildError("evidence safety state is incompatible")
    if not _observations(packet):
        raise WindowsOperatorSolutionBuildError("evidence has no usable observed component")
    commands = windows_operator_safe_commands(route.intent)
    packet_commands = set(packet.get("safe_next_commands") or ())
    if not commands or commands[0] not in packet_commands:
        raise WindowsOperatorSolutionBuildError("evidence has no maintained safe-next procedure")


def build_windows_operator_solution_from_evidence(
    evidence: Mapping[str, Any],
    route: WindowsOperatorRoute,
    *,
    target: str,
    target_type: TargetType,
    session_ref: str | None = None,
) -> OperatorSolution:
    """Normalize structured Windows evidence and route into the canonical solution."""
    _validate(evidence, route)
    try:
        normalized_target_type = TargetType(target_type)
    except (TypeError, ValueError) as exc:
        raise WindowsOperatorSolutionBuildError("target_type is invalid") from exc
    clean_target = _clean_text(target)
    if not clean_target:
        raise WindowsOperatorSolutionBuildError("target is required")

    observations = _observations(evidence)
    limitations = _bounded_unique(
        [
            "Evidence is a point-in-time snapshot; verification requires fresh read-only evidence.",
            *(evidence.get("limitations") or ()),
            *(evidence.get("evidence_gaps") or ()),
            *(
                f"{name} evidence is unavailable; unavailable does not mean healthy."
                for name in _COMPONENTS
                if _block(evidence, name).get("available") is not True
            ),
        ]
    )
    evidence_ref = "evidence:windows-native-packet"
    route_ref = "evidence:windows-operator-route"
    commands = windows_operator_safe_commands(route.intent)
    procedure = tuple(
        OperatorProcedureStep(
            id=f"step:{index:03d}",
            title="Collect fresh Windows read-only evidence",
            instruction=f"Run the maintained read-only command: `{command}`.",
            risk=Risk.low,
            evidence_refs=(route_ref,),
        )
        for index, command in enumerate(commands, 1)
    )
    identity = json.dumps(
        {
            "intent": route.intent,
            "observations": observations,
            "session_ref": session_ref,
            "target": clean_target,
            "target_type": normalized_target_type.value,
            "visibility_limits": limitations,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    expected_type = _TARGET_BY_INTENT.get(route.intent)
    assumptions = (
        (
            (
                f"The supplied target type is {normalized_target_type.value}; this intent "
                f"commonly addresses a {expected_type.value} target."
            ),
        )
        if expected_type is not None and normalized_target_type is not expected_type
        else ()
    )
    try:
        return OperatorSolution(
            solution_id=f"solution:{hashlib.sha256(identity.encode()).hexdigest()[:24]}",
            session_ref=session_ref,
            platform_system="windows",
            target=clean_target,
            target_type=normalized_target_type,
            desired_outcome=_OUTCOMES[route.intent],
            diagnosis_summary="Observed read-only Windows evidence: "
            + "; ".join(observations)
            + ". No root cause is proven by this packet.",
            diagnosis_confidence=Confidence.unknown,
            likely_causes=(),
            provenance_references=(
                ProvenanceReference(kind=ProvenanceKind.evidence, ref=evidence_ref),
                ProvenanceReference(kind=ProvenanceKind.evidence, ref=route_ref),
            ),
            prerequisites=(
                "Use a current Windows-local read-only session; do not treat this advisory "
                "solution as authorization.",
            ),
            expected_impact="Read-only evidence refresh only; ShellForgeAI performs no mutation.",
            blast_radius=f"Read-only observation of the Windows target: {clean_target}.",
            risk=Risk.low,
            procedure=procedure,
            alternatives=(),
            verification_criteria=(
                VerificationCriterion(
                    id="verify:001",
                    criterion=(
                        "Recollect the relevant Windows evidence read-only and compare the fresh "
                        "observed state with this point-in-time snapshot; confirm whether "
                        "previously "
                        "unavailable categories are now observable."
                    ),
                    evidence_refs=(evidence_ref, route_ref),
                ),
            ),
            rollback_recovery=RollbackRecoveryGuidance(mode=RecoveryMode.not_applicable),
            assumptions=assumptions,
            unresolved_questions=tuple(
                f"Is fresh read-only evidence available for {name}?"
                for name in _COMPONENTS
                if _block(evidence, name).get("available") is not True
            ),
            visibility_limits=limitations,
        )
    except ValidationError as exc:
        raise WindowsOperatorSolutionBuildError(
            "solution metadata or evidence is malformed"
        ) from exc


__all__ = [
    "WindowsOperatorSolutionBuildError",
    "build_windows_operator_solution_from_evidence",
]
