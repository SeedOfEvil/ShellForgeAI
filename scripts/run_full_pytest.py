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
import sys
import time
from dataclasses import dataclass
from pathlib import Path

HELPER_DIR = Path(__file__).resolve().parent
REPO_ROOT = HELPER_DIR.parent

# Ensure the sibling validation_heartbeat helper is importable whether this file
# is run as a script or imported by tests via importlib.
if str(HELPER_DIR) not in sys.path:
    sys.path.insert(0, str(HELPER_DIR))

import validation_heartbeat  # noqa: E402

PYTHON_BIN = "python"
DEFAULT_DURATIONS = 25
DEFAULT_WORKERS = "auto"
DEFAULT_DIST = "loadscope"
DEFAULT_PHASE_NAME = "full_pytest"


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
    parser.add_argument(
        "--heartbeat-file",
        help=(
            "Write a validation heartbeat/status JSON here before and after the run so an "
            "interrupted run leaves clear partial evidence (never a false pass)."
        ),
    )
    parser.add_argument(
        "--status-file",
        help="Mirror the heartbeat JSON to this status path (same content).",
    )
    parser.add_argument(
        "--checkpoint-file",
        help="Append phase checkpoint events to this JSON path.",
    )
    parser.add_argument(
        "--phase-name",
        default=DEFAULT_PHASE_NAME,
        help="Heartbeat phase name for this run (default: full_pytest).",
    )
    parser.add_argument("--run-id", help="Explicit heartbeat run id.")
    parser.add_argument("--pr", help="PR number to record in the heartbeat.")
    parser.add_argument("--commit", help="Commit SHA to record in the heartbeat.")
    return parser


def _make_heartbeat(args: argparse.Namespace) -> validation_heartbeat.ValidationHeartbeat | None:
    """Build a single-phase heartbeat for this runner when requested."""
    if not (args.heartbeat_file or args.status_file or args.checkpoint_file):
        return None
    phase = args.phase_name or DEFAULT_PHASE_NAME
    target = args.heartbeat_file or args.status_file or args.checkpoint_file
    return validation_heartbeat.ValidationHeartbeat(
        target,
        checkpoint_path=args.checkpoint_file,
        status_path=args.status_file,
        run_id=args.run_id,
        pr=args.pr,
        commit=args.commit,
        phases=(phase,),
        required_phases=(phase,),
    )


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

    phase = args.phase_name or DEFAULT_PHASE_NAME
    heartbeat = _make_heartbeat(args)
    if heartbeat is not None:
        heartbeat.start()
        heartbeat.start_phase(phase)

    start = time.monotonic()
    try:
        if not args.json:
            print(render_plan(plan, dry_run=False), flush=True)
            print(
                f"Running full pytest with xdist: {'yes' if plan.xdist_enabled else 'no'}",
                flush=True,
            )
            print(f"Command: {' '.join(plan.command)}", flush=True)
            print("Pytest output streams live below.", flush=True)
            completed = subprocess.run(plan.command, cwd=str(REPO_ROOT), check=False)
            elapsed = time.monotonic() - start
            returncode = int(completed.returncode)
            if heartbeat is not None:
                heartbeat.record_full_pytest_exit(returncode, phase=phase)
                heartbeat.finalize()
            print(
                f"Full pytest finished with exit code {returncode} in {elapsed:.1f}s",
                flush=True,
            )
            return returncode

        completed = subprocess.run(
            plan.command,
            cwd=str(REPO_ROOT),
            check=False,
            capture_output=True,
            text=True,
        )
        elapsed = time.monotonic() - start
        returncode = int(completed.returncode)
        if heartbeat is not None:
            heartbeat.record_full_pytest_exit(returncode, phase=phase)
            heartbeat.finalize()
        payload = plan_json(plan, returncode=returncode)
        payload["elapsed_seconds"] = round(elapsed, 3)
        payload["stdout"] = completed.stdout
        payload["stderr"] = completed.stderr
        if heartbeat is not None:
            payload["heartbeat_path"] = str(heartbeat.path)
            payload["status"] = heartbeat.snapshot()["status"]
        print(json.dumps(payload, sort_keys=True))
        return returncode
    except KeyboardInterrupt:
        # Controlled interruption: record incomplete evidence, never a pass.
        if heartbeat is not None:
            heartbeat.mark_interrupted(signal_name="SIGINT")
        raise


if __name__ == "__main__":
    raise SystemExit(main())
