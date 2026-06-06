#!/usr/bin/env python3
"""Bounded full pytest runner for ShellForgeAI Lane C validation.

This helper only runs the project test suite. It does not call Docker or
product runtime mutation paths. Commands are constructed as argv lists and
executed without a shell.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON_BIN = "python"
DEFAULT_DURATIONS = 25
DEFAULT_WORKERS = "auto"
DEFAULT_DIST = "loadscope"


@dataclass(frozen=True)
class FullPytestPlan:
    command: list[str]
    xdist_available: bool
    fallback: bool
    durations: int
    workers: str
    dist: str
    xdist_enabled: bool
    forced_serial: bool


def detect_xdist() -> bool:
    """Return whether pytest-xdist's import package is available."""
    return importlib.util.find_spec("xdist") is not None


def build_command(*, durations: int, workers: str, dist: str, use_xdist: bool) -> list[str]:
    command = [PYTHON_BIN, "-m", "pytest", "-q"]
    if use_xdist:
        command.extend(["-n", workers, "--dist", dist])
    command.append(f"--durations={durations}")
    return command


def plan_full_pytest(
    *,
    durations: int = DEFAULT_DURATIONS,
    workers: str = DEFAULT_WORKERS,
    dist: str = DEFAULT_DIST,
    no_xdist: bool = False,
    xdist_available: bool | None = None,
) -> FullPytestPlan:
    if durations < 0:
        raise ValueError("--durations must be zero or greater")
    detected = detect_xdist() if xdist_available is None else bool(xdist_available)
    use_xdist = detected and not no_xdist
    fallback = not detected and not no_xdist
    return FullPytestPlan(
        command=build_command(durations=durations, workers=workers, dist=dist, use_xdist=use_xdist),
        xdist_available=detected,
        fallback=fallback,
        durations=durations,
        workers=workers,
        dist=dist,
        xdist_enabled=use_xdist,
        forced_serial=no_xdist,
    )


def plan_json(plan: FullPytestPlan, *, returncode: int | None = None) -> dict:
    data = {
        "mode": "full_pytest_runner",
        "xdist_available": plan.xdist_available,
        "command": plan.command,
        "fallback": plan.fallback,
        "durations": plan.durations,
    }
    if returncode is not None:
        data["returncode"] = returncode
    return data


def render_plan(plan: FullPytestPlan, *, dry_run: bool) -> str:
    lines = ["ShellForgeAI full pytest runner (Lane C)"]
    lines.append(f"xdist_detected={str(plan.xdist_available).lower()}")
    lines.append(f"xdist_used={str(plan.xdist_enabled).lower()}")
    lines.append(f"duration_reporting=true (--durations={plan.durations})")
    if plan.fallback:
        lines.append("xdist: unavailable, falling back to serial pytest")
        lines.append("WARNING: pytest-xdist not available; falling back to serial full pytest")
    elif plan.forced_serial:
        if plan.xdist_available:
            lines.append("xdist: available but disabled by --no-xdist, using serial pytest")
        else:
            lines.append("xdist: unavailable; --no-xdist requested serial pytest")
        lines.append("xdist disabled by --no-xdist; using serial full pytest")
    else:
        lines.append(f"xdist: available, using -n {plan.workers} --dist {plan.dist}")
        lines.append("pytest-xdist available; using parallel workers when pytest starts")
    prefix = "Would run" if dry_run else "Running"
    lines.append(f"{prefix}: {' '.join(plan.command)}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_full_pytest.py",
        description="Run Lane C full pytest with xdist when available and slow-test durations.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print command metadata only.")
    parser.add_argument(
        "--no-xdist", action="store_true", help="Force serial pytest even if xdist exists."
    )
    parser.add_argument(
        "--durations",
        type=int,
        default=DEFAULT_DURATIONS,
        help="Number of slow tests to report (default: 25).",
    )
    parser.add_argument("--json", action="store_true", help="Emit strict JSON metadata.")
    parser.add_argument(
        "--workers", default=DEFAULT_WORKERS, help="xdist worker count (default: auto)."
    )
    parser.add_argument(
        "--dist", default=DEFAULT_DIST, help="xdist distribution mode (default: loadscope)."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        plan = plan_full_pytest(
            durations=args.durations,
            workers=args.workers,
            dist=args.dist,
            no_xdist=args.no_xdist,
        )
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    if args.dry_run:
        if args.json:
            print(json.dumps(plan_json(plan), sort_keys=True))
        else:
            print(render_plan(plan, dry_run=True))
        return 0

    if not args.json:
        print(render_plan(plan, dry_run=False), flush=True)
        completed = subprocess.run(plan.command, cwd=str(REPO_ROOT), check=False)
        return int(completed.returncode)

    completed = subprocess.run(
        plan.command,
        cwd=str(REPO_ROOT),
        check=False,
        capture_output=True,
        text=True,
    )
    payload = plan_json(plan, returncode=int(completed.returncode))
    payload["stdout"] = completed.stdout
    payload["stderr"] = completed.stderr
    print(json.dumps(payload, sort_keys=True))
    return int(completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
