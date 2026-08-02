from __future__ import annotations

import re

_ALLOWED_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_ALLOWED_PROFILE = {"quick", "standard", "full"}


def _safe_ident(value: str, *, field: str) -> str:
    candidate = (value or "").strip()
    if not _ALLOWED_TARGET.fullmatch(candidate):
        raise ValueError(f"unsafe {field}")
    return candidate


def triage_detail_command(target: str, *, json: bool = False) -> str:
    cmd = f"shellforgeai triage docker detail {_safe_ident(target, field='target')}"
    return f"{cmd} --json" if json else cmd


def remediation_eligibility_explain_command(target: str, *, json: bool = False) -> str:
    cmd = (
        "shellforgeai remediation eligibility --target "
        f"{_safe_ident(target, field='target')} --explain"
    )
    return f"{cmd} --json" if json else cmd


def remediation_self_test_command(*, profile: str = "standard", json: bool = False) -> str:
    if profile not in _ALLOWED_PROFILE:
        raise ValueError("unsupported profile")
    cmd = f"shellforgeai remediation self-test --profile {profile}"
    return f"{cmd} --json" if json else cmd


def triage_snapshot_command(*, include_details: bool = False, json: bool = False) -> str:
    cmd = "shellforgeai triage docker snapshot"
    if include_details:
        cmd += " --include-details"
    return f"{cmd} --json" if json else cmd


def triage_timeline_command(*, include_stable: bool = False, json: bool = False) -> str:
    cmd = "shellforgeai triage docker timeline"
    if include_stable:
        cmd += " --include-stable"
    return f"{cmd} --json" if json else cmd


def remediation_audit_latest_command(*, json: bool = True) -> str:
    cmd = "shellforgeai remediation audit --latest"
    return f"{cmd} --json" if json else cmd


def remediation_plan_command(target: str, scenario: str, *, json: bool = False) -> str:
    cmd = (
        "shellforgeai remediation plan --target "
        f"{_safe_ident(target, field='target')} --scenario "
        f"{_safe_ident(scenario, field='scenario')}"
    )
    return f"{cmd} --json" if json else cmd


# Backward-compatible wrappers for the PR223 safe-command registry.  Command
# suggestion validation now lives in ``safe_commands`` so model-backed ask and
# future operator guidance share one read-only allowlist.
from shellforgeai.core.command_suggestion_validation import RouteFamily  # noqa: E402
from shellforgeai.core.safe_commands import (  # noqa: E402
    filter_or_replace_unsafe_command_suggestions,
    is_known_safe_shellforgeai_command,
    suggest_safe_next_command,
)

__all__ = [
    "filter_unsupported_command_suggestions",
    "is_known_safe_shellforgeai_command",
    "suggest_safe_next_command",
]


def filter_unsupported_command_suggestions(
    text: str,
    *,
    safe_next_command: str | None = None,
    active_platform: RouteFamily = "linux_primary",
    intended_platform: RouteFamily | None = None,
) -> tuple[str, list[str]]:
    result = filter_or_replace_unsafe_command_suggestions(
        text,
        topic="docker",
        active_platform=active_platform,
        intended_platform=intended_platform,
        fallback_command=safe_next_command,
    )
    return result.safe_text, result.removed_suggestions
