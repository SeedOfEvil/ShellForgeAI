#!/usr/bin/env python3
"""Run an explicit mainline validation baseline for ShellForgeAI.

The helper is validation-only. It writes local evidence artifacts and never
runs Docker/Compose, deployment, cleanup, remediation, rollback, restart,
prune, auto-merge, or model-driven commands. All subprocesses are fixed argv
lists constructed by this module.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = Path("/tmp/shellforgeai-validation-runs")
DEFAULT_BASELINE_NAME = "mainline"
DEFAULT_DURATIONS = 25
SCHEMA_VERSION = 1
MODE = "mainline_validation_manifest"
PYTHON_DISPLAY = "python"

SAFETY_FLAGS = {
    "deploy_performed": False,
    "compose_modified": False,
    "docker_compose_executed": False,
    "container_restarted": False,
    "cleanup_executed": False,
    "remediation_executed": False,
    "rollback_executed": False,
    "docker_prune": False,
    "volume_prune": False,
    "shell_true": False,
    "arbitrary_command_execution": False,
    "natural_language_mutation": False,
}


@dataclass(frozen=True)
class PlannedCommand:
    name: str
    command: list[str]
    log_path: Path
    required: bool = True

    def as_manifest(
        self, *, status: str = "not_run", duration_seconds: float | None = None
    ) -> dict[str, Any]:
        return {
            "name": self.name,
            "command": self.command,
            "status": status,
            "duration_seconds": duration_seconds,
            "log_path": str(self.log_path),
        }


@dataclass(frozen=True)
class MainlinePlan:
    baseline_name: str
    output_dir: Path
    run_id: str
    manifest_path: Path
    summary_path: Path
    commands: list[PlannedCommand]
    full_pytest: bool
    durations: int
    no_xdist: bool
    duration_tracking: bool
    duration_report_path: Path | None
    duration_history_path: Path | None


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_label(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "-" for ch in value.strip())
    return cleaned.strip("-.") or DEFAULT_BASELINE_NAME


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_mainline_validation.py",
        description="Run a validation-only mainline/baseline evidence manifest.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print planned commands only.")
    parser.add_argument(
        "--json", action="store_true", help="With --dry-run, emit strict JSON only."
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Directory for manifests, summaries, logs, and duration history.",
    )
    parser.add_argument(
        "--baseline-name", default=DEFAULT_BASELINE_NAME, help="Human label for this baseline."
    )
    parser.add_argument(
        "--no-full-pytest",
        action="store_true",
        help="Skip full pytest for local quick checks; recorded as skipped_by_operator.",
    )
    parser.add_argument(
        "--full-pytest",
        action="store_true",
        help="Explicitly include full pytest (the default unless --no-full-pytest is used).",
    )
    parser.add_argument(
        "--durations",
        type=int,
        default=DEFAULT_DURATIONS,
        help="Duration count passed to the full pytest runner and duration tracker.",
    )
    parser.add_argument(
        "--no-xdist", action="store_true", help="Pass --no-xdist to scripts/run_full_pytest.py."
    )
    return parser


def _display_python_command(script: str, *args: str) -> list[str]:
    return [PYTHON_DISPLAY, script, *args]


def build_plan(
    *,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    baseline_name: str = DEFAULT_BASELINE_NAME,
    full_pytest: bool = True,
    durations: int = DEFAULT_DURATIONS,
    no_xdist: bool = False,
    created_at: str | None = None,
) -> MainlinePlan:
    if durations < 0:
        raise ValueError("--durations must be zero or greater")
    label = safe_label(baseline_name)
    out = Path(output_dir)
    stamp = (created_at or utc_now()).replace(":", "").replace("-", "")
    run_id = f"{label}-{stamp}"
    manifest_path = out / f"{run_id}-manifest.json"
    summary_path = out / f"{run_id}-summary.txt"
    commands = [
        PlannedCommand("ruff", ["ruff", "check", "."], out / f"{run_id}-ruff.log"),
        PlannedCommand(
            "compileall",
            [PYTHON_DISPLAY, "-m", "compileall", "-q", "src", "tests"],
            out / f"{run_id}-compileall.log",
        ),
    ]
    v1_validate = REPO_ROOT / "scripts" / "v1_validate.sh"
    if v1_validate.is_file() and os.access(v1_validate, os.X_OK):
        commands.append(
            PlannedCommand(
                "v1_validate_quick",
                ["scripts/v1_validate.sh", "--quick"],
                out / f"{run_id}-v1-quick.log",
            )
        )
    if full_pytest:
        full_cmd = _display_python_command(
            "scripts/run_full_pytest.py", "--durations", str(durations)
        )
        if no_xdist:
            full_cmd.append("--no-xdist")
        commands.append(PlannedCommand("full_pytest", full_cmd, out / f"{run_id}-full-pytest.log"))
    duration_report_path = out / f"{run_id}-duration-report.json" if full_pytest else None
    duration_history_path = out / "pytest-duration-history.json" if full_pytest else None
    duration_tracking = (
        full_pytest and (REPO_ROOT / "scripts" / "track_pytest_durations.py").is_file()
    )
    return MainlinePlan(
        baseline_name=label,
        output_dir=out,
        run_id=run_id,
        manifest_path=manifest_path,
        summary_path=summary_path,
        commands=commands,
        full_pytest=full_pytest,
        durations=durations,
        no_xdist=no_xdist,
        duration_tracking=duration_tracking,
        duration_report_path=duration_report_path,
        duration_history_path=duration_history_path,
    )


def plan_to_dict(plan: MainlinePlan) -> dict[str, Any]:
    return {
        "mode": "mainline_validation_plan",
        "baseline_name": plan.baseline_name,
        "output_dir": str(plan.output_dir),
        "run_id": plan.run_id,
        "planned_commands": [command.command for command in plan.commands],
        "commands": [
            {"name": command.name, "command": command.command, "log_path": str(command.log_path)}
            for command in plan.commands
        ],
        "full_pytest": plan.full_pytest,
        "full_pytest_status": "planned" if plan.full_pytest else "skipped_by_operator",
        "durations": plan.durations,
        "no_xdist": plan.no_xdist,
        "duration_tracking": plan.duration_tracking,
        "manifest_path": str(plan.manifest_path),
        "summary_path": str(plan.summary_path),
        "duration_report_path": str(plan.duration_report_path)
        if plan.duration_report_path
        else None,
        "duration_history_path": str(plan.duration_history_path)
        if plan.duration_history_path
        else None,
        "safety": SAFETY_FLAGS,
    }


def render_dry_run(plan: MainlinePlan) -> str:
    lines = [
        "ShellForgeAI mainline validation baseline dry-run",
        f"Baseline: {plan.baseline_name}",
        f"Output dir: {plan.output_dir}",
        f"Full pytest: {'yes' if plan.full_pytest else 'no (skipped_by_operator)'}",
        f"Duration tracking: {'yes' if plan.duration_tracking else 'no'}",
        f"Manifest: {plan.manifest_path}",
        f"Summary: {plan.summary_path}",
        "Planned commands:",
    ]
    for command in plan.commands:
        lines.append(f"* {command.name}: {' '.join(command.command)}")
    if plan.duration_report_path:
        lines.append(f"Duration report: {plan.duration_report_path}")
    lines.extend(
        [
            "Safety: no auto-merge, no auto-deploy, no Docker/Compose mutation, ",
            "no cleanup/remediation/rollback, no restart, no prune, no shell execution expansion.",
        ]
    )
    return "\n".join(lines)


def _git_value(args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def collect_git_metadata() -> dict[str, Any]:
    dirty_text = _git_value(["status", "--porcelain"])
    return {
        "name": None,
        "source": "local_checkout",
        "git_commit": _git_value(["rev-parse", "HEAD"]),
        "branch": _git_value(["rev-parse", "--abbrev-ref", "HEAD"]),
        "dirty": None if dirty_text is None else bool(dirty_text),
    }


def initial_manifest(
    plan: MainlinePlan, *, created_at: str, git_metadata: dict[str, Any]
) -> dict[str, Any]:
    baseline = dict(git_metadata)
    baseline["name"] = plan.baseline_name
    validation = {
        "ruff": "not_run",
        "compileall": "not_run",
        "v1_validate_quick": "skipped_unavailable",
        "full_pytest": "not_run" if plan.full_pytest else "skipped_by_operator",
    }
    logs = {command.name: str(command.log_path) for command in plan.commands}
    if plan.duration_report_path:
        logs["duration_report"] = str(plan.duration_report_path)
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": "partial",
        "verdict": "unknown",
        "baseline": baseline,
        "lane": {
            "selected": "mainline_full",
            "reason": "scheduled/mainline baseline validation",
            "full_validation_required": True,
            "runner": "scripts/run_full_pytest.py" if plan.full_pytest else None,
            "duration_reporting": plan.duration_tracking,
        },
        "commands": [command.as_manifest() for command in plan.commands],
        "logs": logs,
        "validation": validation,
        "duration_tracking": {
            "enabled": plan.duration_tracking,
            "report_path": str(plan.duration_report_path) if plan.duration_report_path else None,
            "history_path": str(plan.duration_history_path) if plan.duration_history_path else None,
            "status": "not_run" if plan.duration_tracking else "disabled",
            "regressions": None,
            "warnings": [],
        },
        "safety": dict(SAFETY_FLAGS),
        "created_at": created_at,
        "artifacts": {
            "manifest_path": str(plan.manifest_path),
            "human_summary_path": str(plan.summary_path),
        },
        "non_blockers": [],
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def update_manifest_status(manifest: dict[str, Any]) -> None:
    validation = manifest.get("validation", {})
    required_failed = any(
        command.get("status") == "failed" and command.get("required", True) is not False
        for command in manifest.get("commands", [])
    )
    duration_status = (manifest.get("duration_tracking") or {}).get("status")
    if required_failed:
        manifest["status"] = "failed"
        manifest["verdict"] = "fail"
    elif duration_status in {"failed", "warning"}:
        manifest["status"] = "partial"
        manifest["verdict"] = "unknown"
    elif all(
        status in {"passed", "skipped_unavailable", "skipped_by_operator"}
        for status in validation.values()
    ):
        manifest["status"] = "passed"
        manifest["verdict"] = "pass"
    else:
        manifest["status"] = "partial"
        manifest["verdict"] = "unknown"


def render_summary(manifest: dict[str, Any]) -> str:
    result = {"pass": "PASS", "fail": "FAIL"}.get(manifest.get("verdict"), "UNKNOWN")
    validation = manifest.get("validation", {})
    duration = manifest.get("duration_tracking", {})
    lines = [
        "Mainline validation summary",
        f"Baseline: {(manifest.get('baseline') or {}).get('name')}",
        f"Commit: {(manifest.get('baseline') or {}).get('git_commit')}",
        f"Result: {result}",
        "",
        "Validation:",
        f"* ruff: {validation.get('ruff')}",
        f"* compileall: {validation.get('compileall')}",
        f"* v1 quick: {validation.get('v1_validate_quick')}",
        f"* full pytest: {validation.get('full_pytest')}",
        "",
        "Duration:",
        f"* duration report: {duration.get('report_path')}",
        f"* regressions: {duration.get('regressions')}",
        f"* status: {duration.get('status')}",
        "",
        "Safety:",
        "* deploy performed: no",
        "* compose modified: no",
        "* cleanup/remediation/rollback: not executed",
        "* Docker/Compose mutation: no",
        "",
        "Logs:",
    ]
    for name, path in sorted((manifest.get("logs") or {}).items()):
        lines.append(f"* {name}: {path}")
    if manifest.get("non_blockers"):
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"* {item}" for item in manifest["non_blockers"])
    return "\n".join(lines) + "\n"


def write_summary(path: Path, manifest: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_summary(manifest), encoding="utf-8")


def _runtime_command(display_command: list[str]) -> list[str]:
    if display_command and display_command[0] == PYTHON_DISPLAY:
        return [sys.executable, *display_command[1:]]
    return display_command


def run_planned_command(command: PlannedCommand) -> tuple[int, float]:
    start = time.monotonic()
    command.log_path.parent.mkdir(parents=True, exist_ok=True)
    with command.log_path.open("w", encoding="utf-8") as log_file:
        log_file.write(f"$ {' '.join(command.command)}\n")
        log_file.flush()
        try:
            result = subprocess.run(
                _runtime_command(command.command),
                cwd=REPO_ROOT,
                text=True,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                check=False,
            )
            return result.returncode, time.monotonic() - start
        except OSError as exc:
            log_file.write(f"command failed to start: {exc}\n")
            return 127, time.monotonic() - start


def run_duration_tracking(plan: MainlinePlan, manifest: dict[str, Any]) -> int:
    if (
        not plan.duration_tracking
        or not plan.duration_report_path
        or not plan.duration_history_path
    ):
        return 0
    full_log = next(
        (command.log_path for command in plan.commands if command.name == "full_pytest"), None
    )
    if full_log is None:
        return 0
    command = _display_python_command(
        "scripts/track_pytest_durations.py",
        "--log",
        str(full_log),
        "--json",
        "--history",
        str(plan.duration_history_path),
        "--update-history",
        "--top",
        str(plan.durations),
    )
    commit = (manifest.get("baseline") or {}).get("git_commit")
    if commit:
        command.extend(["--commit", str(commit)])
    start = time.monotonic()
    plan.duration_report_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            _runtime_command(command),
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except OSError as exc:
        report = {
            "status": "failed",
            "warnings": [f"duration tracker failed to start: {exc}"],
            "regressions": [],
        }
        plan.duration_report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        result_returncode = 127
    else:
        plan.duration_report_path.write_text(result.stdout, encoding="utf-8")
        result_returncode = result.returncode
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            report = {
                "status": "failed",
                "warnings": ["duration tracker did not emit parseable JSON"],
                "regressions": [],
            }
    duration = manifest["duration_tracking"]
    duration["command"] = command
    duration["duration_seconds"] = round(time.monotonic() - start, 3)
    report_status = report.get("status")
    if result_returncode == 0 and report_status == "ok":
        duration["status"] = "passed"
    elif result_returncode == 0:
        duration["status"] = "warning"
    else:
        duration["status"] = "failed"
    duration["report_status"] = report_status
    duration["regressions"] = len(report.get("regressions") or [])
    duration["warnings"] = list(report.get("warnings") or [])
    if duration["status"] in {"failed", "warning"}:
        note = f"duration tracking warning: {report.get('status', 'failed')}"
        if note not in manifest["non_blockers"]:
            manifest["non_blockers"].append(note)
    manifest["logs"]["duration_report"] = str(plan.duration_report_path)
    return result_returncode


def execute_plan(plan: MainlinePlan) -> int:
    created_at = utc_now()
    git_metadata = collect_git_metadata()
    manifest = initial_manifest(plan, created_at=created_at, git_metadata=git_metadata)
    write_json(plan.manifest_path, manifest)
    exit_code = 0
    for index, command in enumerate(plan.commands):
        returncode, elapsed = run_planned_command(command)
        status = "passed" if returncode == 0 else "failed"
        manifest["commands"][index] = command.as_manifest(
            status=status, duration_seconds=round(elapsed, 3)
        )
        manifest["commands"][index]["returncode"] = returncode
        manifest["validation"][command.name] = status
        update_manifest_status(manifest)
        write_json(plan.manifest_path, manifest)
        if returncode != 0:
            exit_code = returncode or 1
            break

    full_status = manifest["validation"].get("full_pytest")
    if plan.full_pytest and full_status == "passed":
        run_duration_tracking(plan, manifest)
    update_manifest_status(manifest)
    write_json(plan.manifest_path, manifest)
    write_summary(plan.summary_path, manifest)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.json and not args.dry_run:
        parser.error("--json is only supported with --dry-run")
    full_pytest = not args.no_full_pytest
    if args.full_pytest:
        full_pytest = True
    try:
        plan = build_plan(
            output_dir=args.output_dir,
            baseline_name=args.baseline_name,
            full_pytest=full_pytest,
            durations=args.durations,
            no_xdist=args.no_xdist,
        )
    except ValueError as exc:
        parser.error(str(exc))
    if args.dry_run:
        if args.json:
            print(json.dumps(plan_to_dict(plan), sort_keys=True))
        else:
            print(render_dry_run(plan))
        return 0
    return execute_plan(plan)


if __name__ == "__main__":
    raise SystemExit(main())
