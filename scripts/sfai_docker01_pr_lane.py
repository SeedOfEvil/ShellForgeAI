#!/usr/bin/env python3
"""Guarded Docker01 PR lane validation helper.

This helper wires Docker01 PR validation to the same lane planner used by
`scripts/validate_pr.py`. It is validation-only unless an operator explicitly
passes `--execute-validation`, and even then it runs only fixed argv-list
validation commands: ruff, compileall, targeted pytest, and the Lane C full
pytest runner.

The deploy/recreate railings documented for Docker01 are kept here as an
explicit checklist for the guarded deployment lane. This PR helper does not
perform Docker/Compose mutation, cleanup, rollback, remediation, pruning, or
restarts.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import validate_pr

REPO_ROOT = Path(__file__).resolve().parent.parent
FULL_PYTEST_RUNNER = validate_pr.FULL_PYTEST_RUNNER

# Documentation/checklist only: this helper must not execute these steps.
GUARDED_COMPOSE_UPDATE_RAILINGS = (
    "Proxmox snapshot before mutation",
    "compose backup before replacement",
    "write compose.yml.tmp before validation",
    "marker checks before deployment",
    "docker compose config validation against compose.yml.tmp",
    "atomic replace after validation",
    "cached build default unless --no-cache is explicit",
    "no direct compose write",
    "no destructive cleanup",
    "no volume prune",
    "no remediation/rollback/cleanup execution outside intended PR scope",
)

FORBIDDEN_RUNTIME_ACTIONS = (
    "cleanup execute",
    "remediation execute",
    "rollback execute",
    "docker volume prune",
)


def _split_changed_files(values: list[str]) -> list[str]:
    files: list[str] = []
    for value in values:
        for part in value.split(","):
            item = part.strip()
            if item:
                files.append(item)
    return files


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sfai_docker01_pr_lane.py",
        description="Plan or run the guarded Docker01 PR validation lane.",
    )
    parser.add_argument(
        "--changed-files",
        nargs="+",
        required=True,
        help="Changed files, space-separated or comma-separated.",
    )
    parser.add_argument("--pr", dest="pr_number", help="PR number for PR-specific tests.")
    parser.add_argument(
        "--profile",
        default="auto",
        choices=sorted(validate_pr.PROFILE_ALIASES),
        help="Validation profile/lane override (default: auto).",
    )
    parser.add_argument(
        "--full-validation",
        action="store_true",
        help="Force Lane C full validation for this Docker01 PR lane run.",
    )
    parser.add_argument(
        "--full-validation-reason",
        help="Required reason when --full-validation explicitly forces Lane C.",
    )
    parser.add_argument(
        "--execute-validation",
        action="store_true",
        help="Run the planned validation commands. Default is planning/dry-run only.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Plan only. This is the default and is accepted for explicitness.",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help=(
            "Record that a later guarded Docker01 build should be no-cache; "
            "validation commands are unchanged."
        ),
    )
    return parser


def plan_docker01_lane(
    *,
    changed_files: list[str],
    pr_number: str | None = None,
    profile: str = "auto",
    full_validation: bool = False,
    full_validation_reason: str | None = None,
) -> dict:
    if full_validation and not (full_validation_reason or "").strip():
        raise ValueError("--full-validation-reason is required when --full-validation is used")

    effective_profile = "full" if full_validation else profile
    plan = validate_pr.plan_validation(
        changed_files,
        pr_number=pr_number,
        profile=effective_profile,
    )
    plan["docker01_full_validation_forced"] = bool(full_validation)
    plan["docker01_full_validation_reason"] = (
        full_validation_reason.strip() if full_validation_reason else plan["lane_reason"]
    )
    return plan


def render_plan(plan: dict, *, no_cache: bool = False) -> str:
    lines = ["ShellForgeAI Docker01 PR lane"]
    lines.append(f"Selected lane: {plan['lane_letter']} ({plan['selected_lane']})")
    lines.append(f"Lane reason: {plan['lane_reason']}")
    if plan["full_pytest_required"]:
        lines.append(f"Full validation selected: {plan['docker01_full_validation_reason']}")
        lines.append(f"Full pytest runner: {FULL_PYTEST_RUNNER}")
        lines.append("duration reporting: --durations=25")
        lines.append("xdist: runner detects availability and uses parallel execution when possible")
    else:
        lines.append(f"Full validation not selected: {plan['full_pytest_reason']}")
    lines.append(
        "Docker build cache: disabled by --no-cache"
        if no_cache
        else "Docker build cache: cached build default (unchanged)"
    )
    lines.append("Commands:")
    for command in plan["recommended_commands"]:
        lines.append(f"  - {command}")
    lines.append("Guarded compose railings preserved:")
    for railing in GUARDED_COMPOSE_UPDATE_RAILINGS:
        lines.append(f"  - {railing}")
    return "\n".join(lines)


def run_validation(plan: dict, *, runner=subprocess.run) -> int:
    for command in plan["_commands"]:
        display = command["display"]
        if command["kind"] == "pytest_full_runner":
            print(f"Full pytest runner: {display}", flush=True)
            print("duration reporting: --durations=25", flush=True)
        print(f"==> {display}", flush=True)
        completed = runner(
            command["argv"],
            cwd=str(REPO_ROOT),
            check=False,
            capture_output=True,
            text=True,
        )
        stdout = getattr(completed, "stdout", "") or ""
        stderr = getattr(completed, "stderr", "") or ""
        if stdout:
            print(stdout, end="" if stdout.endswith("\n") else "\n")
        if stderr:
            print(stderr, end="" if stderr.endswith("\n") else "\n", file=sys.stderr)
        rc = int(getattr(completed, "returncode", 0))
        if rc != 0:
            print(f"Command failed ({rc}): {display}", file=sys.stderr)
            return rc
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    changed_files = _split_changed_files(args.changed_files)
    try:
        plan = plan_docker01_lane(
            changed_files=changed_files,
            pr_number=args.pr_number,
            profile=args.profile,
            full_validation=args.full_validation,
            full_validation_reason=args.full_validation_reason,
        )
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    print(render_plan(plan, no_cache=args.no_cache), flush=True)
    if not args.execute_validation or args.dry_run:
        return 0
    return run_validation(plan)


if __name__ == "__main__":
    raise SystemExit(main())
