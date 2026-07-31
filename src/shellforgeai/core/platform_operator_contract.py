"""Pure platform metadata for generic operator responses.

This module deliberately does not classify operator text or select collectors.
The maintained routing layers make those decisions before consumers consult
this presentation/dispatch contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from shellforgeai.platform_detection import (
    PlatformInfo,
    detect_platform,
    support_status,
    unsupported_platform_payload,
)

RouteFamily = Literal["linux_primary", "windows_read_only", "unsupported"]


@dataclass(frozen=True)
class PlatformOperatorContract:
    platform_system: Literal["linux", "windows", "darwin", "unknown"]
    display_name: str
    support_lane: str
    route_family: RouteFamily
    local_evidence_available: bool
    summary_heading: str
    evidence_label: str
    fallback_heading: str
    visibility: str
    unsupported_reason: str | None
    next_safe_command: str


_PRESENTATION = {
    "linux": (
        "Linux",
        "linux_primary",
        "Linux/Docker operator summary",
        "Linux/Docker local read-only evidence",
        "Linux/Docker read-only fallback",
        "linux-docker-local-read-only",
    ),
    "windows": (
        "Windows",
        "windows_read_only",
        "Windows operator summary",
        "Windows local read-only evidence",
        "Windows read-only fallback",
        "windows-local-read-only",
    ),
    "darwin": (
        "macOS",
        "unsupported",
        "macOS operator support",
        "No supported local operational evidence lane",
        "Unsupported platform",
        "unsupported",
    ),
    "unknown": (
        "this host",
        "unsupported",
        "Operator support",
        "No supported local operational evidence lane",
        "Unsupported platform",
        "unsupported",
    ),
}


def build_platform_operator_contract(
    info: PlatformInfo | None = None,
) -> PlatformOperatorContract:
    """Build immutable operator metadata from maintained platform detection."""

    resolved = info or detect_platform()
    system = resolved.system
    display, family, summary, evidence, fallback, visibility = _PRESENTATION[system]
    lane = str(support_status(resolved)["lane"])
    available = system in {"linux", "windows"}
    reason = None
    if not available:
        reason = "No supported local operational evidence lane was selected."
    return PlatformOperatorContract(
        platform_system=system,
        display_name=display,
        support_lane=lane,
        route_family=cast(RouteFamily, family),
        local_evidence_available=available,
        summary_heading=summary,
        evidence_label=evidence,
        fallback_heading=fallback,
        visibility=visibility,
        unsupported_reason=reason,
        next_safe_command="shellforgeai platform doctor --json",
    )


def render_unsupported_platform_operator_response(
    contract: PlatformOperatorContract,
) -> str:
    """Render the bounded fallback for a contract with no operator lane."""

    if contract.route_family != "unsupported":
        raise ValueError("unsupported response requires an unsupported route family")
    payload = unsupported_platform_payload(
        platform_system=contract.platform_system,
        requested_lane=contract.support_lane,
        reason=contract.unsupported_reason or "Unsupported platform.",
        next_safe_command=contract.next_safe_command,
    )
    return (
        f"{contract.fallback_heading}\n"
        f"Detected platform: {contract.display_name}\n"
        f"Support lane: {contract.support_lane}\n"
        f"read_only={str(payload['read_only']).lower()}\n"
        f"mutation_performed={str(payload['mutation_performed']).lower()}\n"
        f"Reason: {payload['reason']}\n"
        "No local evidence was collected and no action was taken.\n"
        f"Next safe command: {payload['next_safe_command']}"
    )
