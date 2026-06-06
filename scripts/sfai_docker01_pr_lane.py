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
import json
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import track_pytest_durations
import validate_pr

REPO_ROOT = Path(__file__).resolve().parent.parent
FULL_PYTEST_RUNNER = validate_pr.FULL_PYTEST_RUNNER
MANIFEST_SCHEMA_VERSION = 1
MANIFEST_MODE = "docker01_pr_validation_manifest"
DEFAULT_HOST = {"name": "lab-docker01", "target": "Docker01", "lxc_id": "106"}
DEFAULT_REPO = "SeedOfEvil/ShellForgeAI"
UNKNOWN = "unknown"

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
    parser.add_argument("--manifest-output", help="Write validation manifest JSON to this path.")
    parser.add_argument("--summary-output", help="Write human validation summary to this path.")
    parser.add_argument(
        "--print-manifest-json",
        action="store_true",
        help="Emit strict manifest JSON only; suppress human planning text.",
    )
    parser.add_argument("--head-commit", help="PR head commit SHA, if known.")
    parser.add_argument("--branch", help="PR branch name, if known.")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="Repository slug for the manifest.")
    parser.add_argument("--pr-title", help="PR title, if known.")
    parser.add_argument("--previous-image", help="Previously deployed image, if known.")
    parser.add_argument("--new-image", help="New Docker image tag, if known.")
    parser.add_argument("--image-id", help="Docker image id, if known.")
    parser.add_argument("--compose-file", help="Compose file path, if known.")
    parser.add_argument("--compose-backup", help="Compose backup path, if known.")
    parser.add_argument("--compose-final-config", help="Compose final config path, if known.")
    parser.add_argument("--snapshot", help="Snapshot identifier, if known.")
    parser.add_argument("--qa-log", help="QA log path, if known.")
    parser.add_argument("--validation-log", help="Validation log path, if known.")
    parser.add_argument("--deploy-log", help="Deploy log path, if known.")
    parser.add_argument("--runner-log", help="Full runner log path, if known.")
    parser.add_argument(
        "--duration-log", help="Full pytest log to parse for optional duration tracking."
    )
    parser.add_argument(
        "--duration-baseline",
        help="Optional duration history/baseline JSON for warning-only regression comparison.",
    )
    parser.add_argument(
        "--duration-history",
        help=(
            "Optional duration history JSON path to read as a baseline; "
            "the lane helper does not update it."
        ),
    )
    parser.add_argument("--container-name", default="shellforgeai", help="Final container name.")
    parser.add_argument("--container-image", help="Final container image, if known.")
    parser.add_argument("--container-image-id", help="Final container image id, if known.")
    parser.add_argument("--container-status", help="Final container status, if known.")
    parser.add_argument("--container-health", help="Final container health, if known.")
    parser.add_argument(
        "--container-restart-count", type=int, help="Final container restart count."
    )
    parser.add_argument("--root-used", help="Final root filesystem used space, if known.")
    parser.add_argument("--root-available", help="Final root filesystem available space, if known.")
    parser.add_argument("--root-percent", help="Final root filesystem used percent, if known.")
    parser.add_argument(
        "--non-blocker",
        action="append",
        default=[],
        help="Known non-blocker note to include in the manifest; may be repeated.",
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


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _optional(value):
    return value if value not in ("", None) else None


def _status_from_returncode(returncode: int | None) -> str:
    if returncode is None:
        return "not_run"
    return "passed" if int(returncode) == 0 else "failed"


def _default_safety(*, no_cache: bool = False) -> dict:
    return {
        "snapshot_before_mutation": True,
        "compose_atomic_update": True,
        "direct_compose_write": False,
        "cached_build": not no_cache,
        "docker_prune": False,
        "volume_prune": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "docker_compose_mutation_beyond_deploy": False,
        "production_restart_beyond_deploy": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_mutation": False,
    }


def _git_value(args: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=str(REPO_ROOT),
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value or None


def _default_artifact_path(
    *, suffix: str, pr_number: str | None, short_commit: str | None, created_at: str
) -> str:
    safe_pr = pr_number or "unknown"
    safe_sha = short_commit or "unknown"
    stamp = created_at.replace(":", "").replace("-", "").replace("Z", "")
    name = f"sfai-pr{safe_pr}-{safe_sha}-{suffix}-{stamp}"
    return str(Path(tempfile.gettempdir()) / name)


def _command_record(command: dict, *, status: str, duration: float | None, log_path: str | None):
    return {
        "name": command.get("kind") or command.get("display") or UNKNOWN,
        "command": list(command.get("argv") or []),
        "display": command.get("display"),
        "status": status,
        "duration_seconds": round(duration, 3) if duration is not None else None,
        "log_path": log_path,
    }


def planned_command_records(plan: dict, *, log_path: str | None = None) -> list[dict]:
    return [
        _command_record(command, status="not_run", duration=None, log_path=log_path)
        for command in plan.get("_commands", [])
    ]


def validation_status_from_commands(command_records: list[dict], *, full_required: bool) -> dict:
    status = {
        "ruff": UNKNOWN,
        "compileall": UNKNOWN,
        "targeted_tests": "not_required",
        "full_pytest": "not_required" if not full_required else UNKNOWN,
        "v1_quick": UNKNOWN,
        "v1_standard": UNKNOWN,
        "remediation_self_test_full": UNKNOWN,
    }
    for record in command_records:
        name = record.get("name")
        value = record.get("status") or UNKNOWN
        if name == "lint":
            status["ruff"] = value
        elif name == "compile":
            status["compileall"] = value
        elif name == "pytest_targeted":
            status["targeted_tests"] = value
        elif name == "pytest_full_runner":
            status["full_pytest"] = value
    return status


def build_validation_manifest(
    plan: dict,
    *,
    pr_number: str | None = None,
    head_commit: str | None = None,
    branch: str | None = None,
    repo: str = DEFAULT_REPO,
    title: str | None = None,
    previous_image: str | None = None,
    new_image: str | None = None,
    image_id: str | None = None,
    compose_file: str | None = None,
    compose_backup: str | None = None,
    compose_final_config: str | None = None,
    snapshot: str | None = None,
    cached_build: bool = True,
    no_cache: bool = False,
    commands: list[dict] | None = None,
    phases: list[dict] | None = None,
    logs: dict | None = None,
    final_container: dict | None = None,
    disk: dict | None = None,
    non_blockers: list[str] | None = None,
    manifest_path: str | None = None,
    human_summary_path: str | None = None,
    status: str | None = None,
    verdict: str | None = None,
    failed_phase: str | None = None,
    error_summary: str | None = None,
    created_at: str | None = None,
    duration_report: dict | None = None,
) -> dict:
    created_at = created_at or _utc_now()
    resolved_head = _optional(head_commit) or _git_value(["rev-parse", "HEAD"])
    short_commit = resolved_head[:12] if resolved_head else None
    resolved_branch = _optional(branch) or _git_value(["branch", "--show-current"])
    command_records = commands if commands is not None else planned_command_records(plan)
    phase_records = (
        phases
        if phases is not None
        else [{"name": "planning", "status": "passed", "duration_seconds": None}]
    )
    failed = failed_phase or next(
        (phase.get("name") for phase in phase_records if phase.get("status") == "failed"), None
    )
    failed = failed or next(
        (record.get("name") for record in command_records if record.get("status") == "failed"), None
    )
    if status is None:
        status = "failed" if failed else "passed"
    if verdict is None:
        verdict = "fail" if status == "failed" else "pass" if status == "passed" else "hold"
    logs = logs or {}
    container = {
        "name": "shellforgeai",
        "image": None,
        "image_id": None,
        "status": UNKNOWN,
        "health": UNKNOWN,
        "restart_count": None,
        "labels": {
            "homelab.pr": str(pr_number) if pr_number is not None else None,
            "homelab.commit": resolved_head,
        },
    }
    if final_container:
        container.update(final_container)
        labels = {
            "homelab.pr": str(pr_number) if pr_number is not None else None,
            "homelab.commit": resolved_head,
        }
        labels.update(final_container.get("labels") or {})
        container["labels"] = labels
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "mode": MANIFEST_MODE,
        "status": status,
        "verdict": verdict,
        "failed_phase": failed,
        "error_summary": error_summary,
        "pr": {
            "number": int(pr_number) if pr_number and str(pr_number).isdigit() else pr_number,
            "head_commit": resolved_head,
            "short_commit": short_commit,
            "branch": resolved_branch or UNKNOWN,
            "repo": repo,
            "title": title,
        },
        "host": dict(DEFAULT_HOST),
        "deployment": {
            "previous_image": previous_image,
            "new_image": new_image,
            "image_id": image_id,
            "compose_file": compose_file,
            "compose_backup": compose_backup,
            "compose_final_config": compose_final_config,
            "snapshot": snapshot,
            "cached_build": cached_build,
            "no_cache": no_cache,
        },
        "lane": {
            "selected": plan.get("selected_lane", UNKNOWN),
            "reason": plan.get("lane_reason", UNKNOWN),
            "full_validation_required": bool(plan.get("full_pytest_required", False)),
            "full_validation_reason": plan.get("docker01_full_validation_reason")
            or plan.get("full_pytest_reason"),
            "runner": FULL_PYTEST_RUNNER if plan.get("full_pytest_required") else None,
            "xdist_used": True if plan.get("full_pytest_required") else None,
            "duration_reporting": bool(plan.get("duration_reporting", False)),
        },
        "commands": command_records,
        "phases": phase_records,
        "logs": {
            "qa": logs.get("qa"),
            "validation": logs.get("validation"),
            "deploy": logs.get("deploy"),
            "runner": logs.get("runner"),
        },
        "final_container": container,
        "disk": disk or {"root_used": None, "root_available": None, "root_percent": None},
        "validation": validation_status_from_commands(
            command_records, full_required=bool(plan.get("full_pytest_required", False))
        ),
        "safety": _default_safety(no_cache=no_cache),
        "non_blockers": list(non_blockers or []),
        "artifacts": {
            "manifest_path": manifest_path,
            "human_summary_path": human_summary_path,
        },
        "created_at": created_at,
    }
    if duration_report is not None:
        manifest["duration_report"] = duration_report
        artifacts = manifest.get("artifacts")
        if isinstance(artifacts, dict):
            artifacts["duration_report"] = duration_report.get("log_path")
    return manifest


def render_human_summary(manifest: dict) -> str:
    pr = manifest["pr"]
    lane = manifest["lane"]
    deployment = manifest["deployment"]
    container = manifest["final_container"]
    validation = manifest["validation"]
    safety = manifest["safety"]
    logs = manifest["logs"]
    artifacts = manifest["artifacts"]
    result = str(manifest.get("verdict") or manifest.get("status") or UNKNOWN).upper()
    restart_count = container.get("restart_count")
    restart = restart_count if restart_count is not None else UNKNOWN
    lines = [
        "Docker01 PR validation summary",
        f"PR: #{pr.get('number') if pr.get('number') is not None else UNKNOWN}",
        f"Commit: {pr.get('head_commit') or UNKNOWN}",
        f"Image: {deployment.get('new_image') or container.get('image') or UNKNOWN}",
        f"Lane: {lane.get('selected') or UNKNOWN}",
        f"Reason: {lane.get('reason') or UNKNOWN}",
        "",
        f"Result: {result}",
        "Container: "
        f"{container.get('status') or UNKNOWN} / {container.get('health') or UNKNOWN} / "
        f"restart={restart}",
        "Validation:",
        f"* ruff: {validation.get('ruff', UNKNOWN)}",
        f"* compileall: {validation.get('compileall', UNKNOWN)}",
        f"* targeted tests: {validation.get('targeted_tests', UNKNOWN)}",
        f"* full pytest: {validation.get('full_pytest', UNKNOWN)}",
        "",
        "Duration tracking:",
        f"* status: {(manifest.get('duration_report') or {}).get('status', UNKNOWN)}",
        f"* slow tests recorded: {(manifest.get('duration_report') or {}).get('count', 0)}",
        f"* regressions: {len((manifest.get('duration_report') or {}).get('regressions') or [])}",
        "",
        "Safety:",
        f"* snapshot before mutation: {'yes' if safety.get('snapshot_before_mutation') else 'no'}",
        f"* compose atomic update: {'yes' if safety.get('compose_atomic_update') else 'no'}",
        "* cleanup/remediation/rollback: "
        + (
            "executed"
            if any(
                safety.get(key)
                for key in ["cleanup_executed", "remediation_executed", "rollback_executed"]
            )
            else "not executed"
        ),
        "* Docker/Compose mutation beyond deploy: "
        f"{'yes' if safety.get('docker_compose_mutation_beyond_deploy') else 'no'}",
        "* production restart beyond deploy: "
        f"{'yes' if safety.get('production_restart_beyond_deploy') else 'no'}",
        "",
        "Logs:",
        f"* QA: {logs.get('qa') or UNKNOWN}",
        f"* validation: {logs.get('validation') or UNKNOWN}",
        f"* deploy: {logs.get('deploy') or UNKNOWN}",
        f"* runner: {logs.get('runner') or UNKNOWN}",
        f"* manifest: {artifacts.get('manifest_path') or UNKNOWN}",
    ]
    if manifest.get("failed_phase"):
        lines.extend(["", f"Failed phase: {manifest['failed_phase']}"])
    if manifest.get("error_summary"):
        lines.append(f"Error: {manifest['error_summary']}")
    return "\n".join(lines) + "\n"


def write_manifest(manifest: dict, path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_human_summary(summary: str, path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(summary, encoding="utf-8")


def run_validation(
    plan: dict,
    *,
    runner=subprocess.run,
    return_records: bool = False,
    log_path: str | None = None,
):
    records: list[dict] = []
    for command in plan["_commands"]:
        display = command["display"]
        if command["kind"] == "pytest_full_runner":
            print(f"Full pytest runner: {display}", flush=True)
            print("duration reporting: --durations=25", flush=True)
        print(f"==> {display}", flush=True)
        start = time.monotonic()
        if command["kind"] == "pytest_full_runner":
            completed = runner(command["argv"], cwd=str(REPO_ROOT), check=False)
        else:
            completed = runner(
                command["argv"],
                cwd=str(REPO_ROOT),
                check=False,
                capture_output=True,
                text=True,
            )
        duration = time.monotonic() - start
        stdout = getattr(completed, "stdout", "") or ""
        stderr = getattr(completed, "stderr", "") or ""
        if stdout:
            print(stdout, end="" if stdout.endswith("\n") else "\n")
        if stderr:
            print(stderr, end="" if stderr.endswith("\n") else "\n", file=sys.stderr)
        rc = int(getattr(completed, "returncode", 0))
        records.append(
            _command_record(
                command,
                status=_status_from_returncode(rc),
                duration=duration,
                log_path=log_path,
            )
        )
        if rc != 0:
            print(f"Command failed ({rc}): {display}", file=sys.stderr)
            return (rc, records) if return_records else rc
    return (0, records) if return_records else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.print_manifest_json and args.execute_validation and not args.dry_run:
        parser.error("--print-manifest-json cannot be combined with --execute-validation")
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

    created_at = _utc_now()
    head_commit = args.head_commit or _git_value(["rev-parse", "HEAD"])
    short_commit = head_commit[:12] if head_commit else None
    manifest_path = args.manifest_output or _default_artifact_path(
        suffix="manifest.json",
        pr_number=args.pr_number,
        short_commit=short_commit,
        created_at=created_at,
    )
    summary_path = args.summary_output or _default_artifact_path(
        suffix="summary.txt",
        pr_number=args.pr_number,
        short_commit=short_commit,
        created_at=created_at,
    )
    logs = {
        "qa": args.qa_log,
        "validation": args.validation_log,
        "deploy": args.deploy_log,
        "runner": args.runner_log,
    }
    phases = [{"name": "planning", "status": "passed", "duration_seconds": None}]
    command_records = planned_command_records(plan, log_path=args.validation_log)
    return_code = 0
    error_summary = None
    duration_report = None

    duration_log = args.duration_log or args.runner_log
    if duration_log and plan.get("full_pytest_required"):
        baseline = None
        baseline_warning = None
        baseline_path = args.duration_baseline or args.duration_history
        if baseline_path:
            baseline, baseline_warning = track_pytest_durations.load_json_object(baseline_path)
        parsed = track_pytest_durations.parse_log(duration_log)
        duration_report = track_pytest_durations.build_report(
            log_path=duration_log,
            parsed=parsed,
            baseline=baseline,
            baseline_warning=baseline_warning,
        )

    if args.execute_validation and not args.dry_run:
        start = time.monotonic()
        return_code, command_records = run_validation(
            plan, return_records=True, log_path=args.validation_log
        )
        phases.append(
            {
                "name": "validation",
                "status": "passed" if return_code == 0 else "failed",
                "duration_seconds": round(time.monotonic() - start, 3),
            }
        )
        if return_code != 0:
            failed = next(
                (record for record in command_records if record.get("status") == "failed"), None
            )
            error_summary = (
                f"validation command failed: {failed.get('display') or failed.get('name')}"
                if failed
                else "validation failed"
            )

    final_container = {
        "name": args.container_name,
        "image": args.container_image or args.new_image,
        "image_id": args.container_image_id or args.image_id,
        "status": args.container_status or UNKNOWN,
        "health": args.container_health or UNKNOWN,
        "restart_count": args.container_restart_count,
    }
    disk = {
        "root_used": args.root_used,
        "root_available": args.root_available,
        "root_percent": args.root_percent,
    }
    manifest = build_validation_manifest(
        plan,
        pr_number=args.pr_number,
        head_commit=head_commit,
        branch=args.branch,
        repo=args.repo,
        title=args.pr_title,
        previous_image=args.previous_image,
        new_image=args.new_image,
        image_id=args.image_id,
        compose_file=args.compose_file,
        compose_backup=args.compose_backup,
        compose_final_config=args.compose_final_config,
        snapshot=args.snapshot,
        cached_build=not args.no_cache,
        no_cache=args.no_cache,
        commands=command_records,
        phases=phases,
        logs=logs,
        final_container=final_container,
        disk=disk,
        non_blockers=args.non_blocker,
        manifest_path=manifest_path,
        human_summary_path=summary_path,
        status="failed" if return_code != 0 else "passed",
        verdict="fail" if return_code != 0 else "pass",
        error_summary=error_summary,
        created_at=created_at,
        duration_report=duration_report,
    )
    summary = render_human_summary(manifest)
    write_manifest(manifest, manifest_path)
    write_human_summary(summary, summary_path)

    if args.print_manifest_json:
        print(json.dumps(manifest, sort_keys=True))
        return return_code

    print(render_plan(plan, no_cache=args.no_cache), flush=True)
    print()
    print(summary, end="", flush=True)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
