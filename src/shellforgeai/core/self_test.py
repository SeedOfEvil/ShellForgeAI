"""PR79/PR80 — Safe command coverage harness for ShellForgeAI.

Read-only operator self-test that exercises core CLI command surfaces and
reports pass/fail/warn/skip without mutating anything. No cleanup execute, no
mission execute, no apply, no docker compose restart, no proposal creation,
no archive creation, no plan creation, no shell=True, no natural-language
execution. The harness uses in-process Typer/Click invocation only; it never
shells out.

PR80 added validation profiles (``quick`` / ``standard`` / ``full``),
warn-vs-skip semantics, a ``--fail-on-warn`` mode, an expanded ``safety``
block, and a ``next_safe_commands`` hint list. The default profile remains
``standard`` so the PR79 default behavior is preserved.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from shellforgeai.core.ask_routing import (
    is_compose_mutation_request,
    is_mutation_request,
)

SCHEMA_VERSION = "1"
DEFAULT_COMPOSE_TARGET = "shellforgeai"

PROFILES: tuple[str, ...] = ("quick", "standard", "full")
DEFAULT_PROFILE = "standard"

# Mutation phrases used by the deterministic refusal-routing smoke. The harness
# checks that the natural-language router still flags these as mutation
# requests; it does NOT invoke the model. Only phrases the current router
# already catches are listed here — the harness must not broaden NL behavior.
ASK_MUTATION_PHRASES: tuple[str, ...] = (
    "docker compose restart shellforgeai",
    "can you restart nginx",
    "please delete the logs",
    "docker restart shellforgeai",
)

# Locally-routed ask prompts that never invoke the model. Each entry is
# (prompt, expected substrings in human output). These exercise the safe
# read-only and refusal handlers in the ask router. Only prompts that the
# current router fully handles locally are listed.
ASK_LOCAL_PROMPTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "show metadata hygiene",
        ("metadata hygiene", "no deletion was performed"),
    ),
    (
        "clean up now",
        ("refusing", "natural language cannot delete"),
    ),
)


@dataclass(frozen=True)
class _Check:
    name: str
    argv: tuple[str, ...]
    category: str
    profiles: frozenset[str] = field(default_factory=lambda: frozenset(PROFILES))
    expects_json: bool = False
    allow_nonzero_exit: bool = False
    # Classifiers — failures matching these treat the row as warn/skip rather
    # than fail, because the underlying environment (not the code) is the
    # cause.
    compose_target_check: bool = False  # exit=1 with no docker target → warn
    latest_runbook_check: bool = False  # exit=1 means no artifact → warn
    audit_list_check: bool = False  # no audit storage → warn
    audit_timeline_check: bool = False  # no audit storage → warn
    compose_list_check: bool = False  # no docker → warn


def _read_only_checks() -> list[_Check]:
    """All PR79/PR80 safe read-only checks the harness can run.

    Profile membership is encoded per-check. ``run_self_test_commands`` filters
    by profile. ``standard`` keeps the PR79 default coverage.
    """
    target = DEFAULT_COMPOSE_TARGET
    quick = frozenset({"quick", "standard", "full"})
    standard = frozenset({"standard", "full"})
    full_only = frozenset({"full"})
    return [
        # --- quick lane (cheap, env-independent) -----------------------------
        _Check("version", ("version",), "status", profiles=quick),
        _Check("doctor", ("doctor",), "status", profiles=quick),
        _Check(
            "doctor --json",
            ("doctor", "--json"),
            "json",
            profiles=quick,
            expects_json=True,
        ),
        _Check("model doctor", ("model", "doctor"), "status", profiles=quick),
        _Check("tools list", ("tools", "list"), "status", profiles=quick),
        _Check("ops status", ("ops", "status"), "status", profiles=quick),
        _Check(
            "ops status --json",
            ("ops", "status", "--json"),
            "json",
            profiles=quick,
            expects_json=True,
        ),
        # --- standard lane (PR79 coverage) -----------------------------------
        _Check("audit retention", ("audit", "retention"), "status", profiles=standard),
        _Check(
            "audit retention --json",
            ("audit", "retention", "--json"),
            "json",
            profiles=standard,
            expects_json=True,
        ),
        _Check(
            "audit cleanup review",
            ("audit", "cleanup", "review"),
            "cleanup",
            profiles=standard,
        ),
        _Check(
            "audit cleanup review --json",
            ("audit", "cleanup", "review", "--json"),
            "cleanup",
            profiles=standard,
            expects_json=True,
        ),
        _Check(
            "audit cleanup execute-readiness (missing-plan)",
            (
                "audit",
                "cleanup",
                "execute-readiness",
                "self_test_pr79_definitely_missing_plan",
                "--json",
            ),
            "cleanup",
            profiles=standard,
            expects_json=True,
            allow_nonzero_exit=True,
        ),
        _Check(
            "audit cleanup report (missing-receipt)",
            (
                "audit",
                "cleanup",
                "report",
                "/data/cleanup_receipts/self_test_pr79_definitely_missing/cleanup-receipt.json",
                "--json",
            ),
            "cleanup",
            profiles=standard,
            expects_json=True,
            allow_nonzero_exit=True,
        ),
        _Check(
            f"compose inspect {target}",
            ("compose", "inspect", target),
            "compose",
            profiles=standard,
            compose_target_check=True,
        ),
        _Check(
            f"compose inspect {target} --json",
            ("compose", "inspect", target, "--json"),
            "compose",
            profiles=standard,
            expects_json=True,
            compose_target_check=True,
        ),
        _Check(
            f"compose env-check --target {target} --json",
            ("compose", "env-check", "--target", target, "--json"),
            "compose",
            profiles=standard,
            expects_json=True,
        ),
        _Check(
            f"compose env-contract --target {target} --json",
            ("compose", "env-contract", "--target", target, "--json"),
            "compose",
            profiles=standard,
            expects_json=True,
        ),
        _Check(
            f"compose env-plan --target {target} --json",
            ("compose", "env-plan", "--target", target, "--json"),
            "compose",
            profiles=standard,
            expects_json=True,
        ),
        _Check(
            "validate-runbook --latest",
            ("validate-runbook", "--latest"),
            "status",
            profiles=standard,
            allow_nonzero_exit=True,
            latest_runbook_check=True,
        ),
        # --- full lane (broader read-only coverage) --------------------------
        _Check(
            "audit list",
            ("audit", "list"),
            "status",
            profiles=full_only,
            audit_list_check=True,
        ),
        _Check(
            "audit timeline --latest --json",
            ("audit", "timeline", "--latest", "--json"),
            "json",
            profiles=full_only,
            expects_json=True,
            audit_timeline_check=True,
        ),
        _Check(
            "compose list --json",
            ("compose", "list", "--json"),
            "compose",
            profiles=full_only,
            expects_json=True,
            allow_nonzero_exit=True,
            compose_list_check=True,
        ),
    ]


@dataclass
class _Result:
    name: str
    command: list[str]
    status: str  # pass | fail | skip
    category: str
    read_only: bool = True
    mutation: bool = False
    reason: str | None = None
    warn: bool = False  # true when status=skip and the cause is environmental


def _classify_compose_failure(stdout: str, stderr: str) -> tuple[str, str, bool]:
    """Classify a non-zero compose-inspect result.

    Returns ``(status, reason, warn)``. Skips with ``warn=True`` indicate an
    incomplete environment (e.g. no docker target) rather than a real failure.
    """
    blob = (stdout or "") + "\n" + (stderr or "")
    lowered = blob.lower()
    if "container not found" in lowered or "project not found" in lowered:
        return "skip", "compose target not present in container inventory", True
    if "no such" in lowered or "not available" in lowered:
        return "skip", "docker inventory unavailable", True
    if not blob.strip():
        # Typer often prints the error via err= and CliRunner separates streams.
        return "skip", "compose target unavailable", True
    return "fail", f"compose inspect failed: {blob.strip()[:160]}", False


def _runner_invoke(
    runner: Any, app: Any, argv: tuple[str, ...]
) -> tuple[int, str, str, BaseException | None]:
    result = runner.invoke(app, list(argv))
    stdout = result.stdout or ""
    try:
        stderr = result.stderr or ""
    except (ValueError, AttributeError):
        stderr = ""
    return result.exit_code, stdout, stderr, result.exception


def _normalize_profile(profile: str | None) -> str:
    if not profile:
        return DEFAULT_PROFILE
    p = profile.strip().lower()
    if p not in PROFILES:
        raise ValueError(f"unknown profile: {profile!r}; valid profiles: {', '.join(PROFILES)}")
    return p


def _run_command_checks(profile: str) -> list[_Result]:
    # Import here to avoid a circular import (cli imports core.self_test).
    from typer.testing import CliRunner

    from shellforgeai.cli import app

    runner = CliRunner()
    results: list[_Result] = []

    for check in _read_only_checks():
        if profile not in check.profiles:
            continue
        cmd = ["shellforgeai", *check.argv]
        try:
            exit_code, stdout, stderr, exc = _runner_invoke(runner, app, check.argv)
        except Exception as harness_exc:  # defensive only
            results.append(
                _Result(
                    name=check.name,
                    command=cmd,
                    status="fail",
                    category=check.category,
                    reason=(
                        f"harness invocation raised {type(harness_exc).__name__}: {harness_exc}"
                    ),
                )
            )
            continue

        if check.compose_target_check and exit_code != 0:
            status, reason, warn = _classify_compose_failure(stdout, stderr)
            results.append(
                _Result(
                    name=check.name,
                    command=cmd,
                    status=status,
                    category=check.category,
                    reason=reason,
                    warn=warn,
                )
            )
            continue

        if check.latest_runbook_check and exit_code != 0:
            results.append(
                _Result(
                    name=check.name,
                    command=cmd,
                    status="skip",
                    category=check.category,
                    reason="no latest runbook artifact found",
                    warn=True,
                )
            )
            continue

        if check.audit_list_check and exit_code == 0 and "No sessions" in stdout:
            results.append(
                _Result(
                    name=check.name,
                    command=cmd,
                    status="skip",
                    category=check.category,
                    reason="audit storage has no sessions",
                    warn=True,
                )
            )
            continue

        if check.compose_list_check and exit_code != 0:
            results.append(
                _Result(
                    name=check.name,
                    command=cmd,
                    status="skip",
                    category=check.category,
                    reason="docker inventory unavailable",
                    warn=True,
                )
            )
            continue

        if check.expects_json:
            try:
                parsed = json.loads(stdout) if stdout.strip() else None
            except (json.JSONDecodeError, ValueError) as exc:
                results.append(
                    _Result(
                        name=check.name,
                        command=cmd,
                        status="fail",
                        category=check.category,
                        reason=(f"--json output is not parseable: {type(exc).__name__}"),
                    )
                )
                continue
            if check.audit_timeline_check and (parsed in (None, [], {})):
                results.append(
                    _Result(
                        name=check.name,
                        command=cmd,
                        status="skip",
                        category=check.category,
                        reason="audit timeline empty (no events recorded)",
                        warn=True,
                    )
                )
                continue

        if exit_code != 0:
            if check.allow_nonzero_exit:
                results.append(
                    _Result(
                        name=check.name,
                        command=cmd,
                        status="pass",
                        category=check.category,
                    )
                )
                continue
            reason = f"exit_code={exit_code}"
            if exc is not None and not isinstance(exc, SystemExit):
                reason = f"{type(exc).__name__}: {exc}"
            results.append(
                _Result(
                    name=check.name,
                    command=cmd,
                    status="fail",
                    category=check.category,
                    reason=reason,
                )
            )
            continue

        results.append(
            _Result(
                name=check.name,
                command=cmd,
                status="pass",
                category=check.category,
            )
        )

    # Locally-routed ask prompts (model-free): invoke via CliRunner and check
    # for expected refusal/report substrings.
    if profile in {"standard", "full"}:
        for prompt, expected in ASK_LOCAL_PROMPTS:
            cmd = ["shellforgeai", "ask", prompt]
            try:
                exit_code, stdout, stderr, exc = _runner_invoke(runner, app, ("ask", prompt))
            except Exception as harness_exc:
                results.append(
                    _Result(
                        name=f"ask local: {prompt}",
                        command=cmd,
                        status="fail",
                        category="ask",
                        reason=(
                            f"harness invocation raised {type(harness_exc).__name__}: {harness_exc}"
                        ),
                    )
                )
                continue

            lowered = (stdout + "\n" + stderr).lower()
            if exit_code != 0 and exc is not None and not isinstance(exc, SystemExit):
                results.append(
                    _Result(
                        name=f"ask local: {prompt}",
                        command=cmd,
                        status="fail",
                        category="ask",
                        reason=f"{type(exc).__name__}: {exc}",
                    )
                )
                continue
            if not all(token.lower() in lowered for token in expected):
                results.append(
                    _Result(
                        name=f"ask local: {prompt}",
                        command=cmd,
                        status="fail",
                        category="ask",
                        reason="expected local-route output not present",
                    )
                )
                continue
            results.append(
                _Result(
                    name=f"ask local: {prompt}",
                    command=cmd,
                    status="pass",
                    category="ask",
                )
            )

    # Deterministic, model-free refusal routing check: every mutation phrase
    # must be flagged by the natural-language router. No CLI invocation, no
    # model call, no subprocess.
    unflagged: list[str] = []
    for phrase in ASK_MUTATION_PHRASES:
        if not (is_mutation_request(phrase) or is_compose_mutation_request(phrase)):
            unflagged.append(phrase)
    if unflagged:
        results.append(
            _Result(
                name="ask mutation refusal routing",
                command=["shellforgeai", "ask", "<mutation phrase>"],
                status="fail",
                category="safety",
                reason=("ask routing did not flag mutation for: " + "; ".join(unflagged[:3])),
            )
        )
    else:
        results.append(
            _Result(
                name="ask mutation refusal routing",
                command=["shellforgeai", "ask", "<mutation phrase>"],
                status="pass",
                category="safety",
            )
        )

    return results


def _disposable_mutation_lane_placeholder() -> dict[str, Any]:
    """Placeholder for the optional disposable mutation lane.

    PR79 implements only the always-safe read-only lane. The optional
    disposable mutation lane is intentionally not implemented and never
    runs anything. A future PR (with explicit gate, allowlist, receipt,
    and audit) would be required to enable it.
    """
    return {
        "implemented": False,
        "status": "manual_only",
        "executed": False,
        "note": (
            "Optional disposable mutation lane is not implemented. "
            "The safe command coverage harness never executes mutation."
        ),
    }


def _next_safe_commands(profile: str) -> list[str]:
    """Operator-friendly next-step suggestions after a self-test run."""
    suggestions = [
        "shellforgeai doctor",
        "shellforgeai ops status",
        "shellforgeai audit cleanup review",
    ]
    if profile == "quick":
        suggestions.append("shellforgeai self-test commands --profile standard")
    elif profile == "standard":
        suggestions.append("shellforgeai self-test commands --profile quick")
        suggestions.append("shellforgeai self-test commands --profile full")
    else:  # full
        suggestions.append("shellforgeai self-test commands --profile quick")
    return suggestions


def run_self_test_commands(
    profile: str | None = None,
    *,
    include_skipped: bool = False,
) -> dict[str, Any]:
    """Run the safe read-only command coverage harness.

    The payload is JSON-serializable and contains a strict schema
    (``schema_version``, ``profile``, ``status``, ``summary``, per-check rows,
    ``warnings``, ``skipped``, ``safety``, ``next_safe_commands``). The
    harness never executes cleanup, archive, plan creation, proposal creation,
    mission, apply, docker, compose mutation, or natural-language execution.

    ``include_skipped=True`` is a presentation hint for the CLI: it has no
    effect on the underlying checks, which always include every row.
    """
    chosen_profile = _normalize_profile(profile)
    results = _run_command_checks(chosen_profile)

    passed = sum(1 for r in results if r.status == "pass")
    failed = sum(1 for r in results if r.status == "fail")
    skipped = sum(1 for r in results if r.status == "skip")
    warned = sum(1 for r in results if r.warn)

    if failed:
        overall = "failed"
    elif warned:
        overall = "warn"
    else:
        overall = "ok"

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": overall,
        "profile": chosen_profile,
        "available_profiles": list(PROFILES),
        "default_profile": DEFAULT_PROFILE,
        "include_skipped": bool(include_skipped),
        "mode": {
            "read_only": True,
            "mutation_performed": False,
            "docker_compose_executed": False,
            "cleanup_executed": False,
            "mission_executed": False,
            "apply_executed": False,
            "natural_language_execution": False,
        },
        "summary": {
            "passed": passed,
            "failed": failed,
            "warned": warned,
            "skipped": skipped,
        },
        "checks": [
            {
                "name": r.name,
                "command": r.command,
                "status": r.status,
                "category": r.category,
                "read_only": r.read_only,
                "mutation": r.mutation,
                "warn": r.warn,
                "reason": r.reason,
            }
            for r in results
        ],
        "warnings": [{"name": r.name, "reason": r.reason} for r in results if r.warn and r.reason],
        "skipped": [
            {"name": r.name, "reason": r.reason} for r in results if r.status == "skip" and r.reason
        ],
        "failures": [{"name": r.name, "reason": r.reason} for r in results if r.status == "fail"],
        "safety": {
            # PR80 canonical safety invariants (aligns with the spec schema).
            "read_only": True,
            "mutation_performed": False,
            "cleanup_execute_run": False,
            "mission_execute_run": False,
            "apply_execute_run": False,
            "docker_compose_executed": False,
            "docker_compose_mutation": False,
            "natural_language_execution": False,
            "arbitrary_command_execution": False,
            # PR79 invariants retained for backward compatibility with
            # downstream consumers (Docker01 QA, prior dashboards).
            "no_cleanup_execute": True,
            "no_cleanup_archive": True,
            "no_cleanup_prepare": True,
            "no_mission_execute": True,
            "no_proposal_created": True,
            "no_mission_created": True,
            "no_apply": True,
            "no_docker_compose_restart": True,
            "no_production_mutation": True,
            "no_natural_language_execution": True,
            "no_shell_true": True,
        },
        "next_safe_commands": _next_safe_commands(chosen_profile),
        "optional_disposable_mutation_lane": _disposable_mutation_lane_placeholder(),
    }
    return payload
