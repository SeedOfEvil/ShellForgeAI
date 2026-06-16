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
import contextlib
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

HELPER_DIR = Path(__file__).resolve().parent

# Ensure sibling validation helpers are importable whether this file is run as a
# script or imported by tests via importlib.
if str(HELPER_DIR) not in sys.path:
    sys.path.insert(0, str(HELPER_DIR))

import track_pytest_durations  # noqa: E402
import validate_pr  # noqa: E402
import validation_container_fallback  # noqa: E402
import validation_env_preflight  # noqa: E402
import validation_heartbeat  # noqa: E402
import validation_status as validation_status_viewer  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
FULL_PYTEST_RUNNER = validate_pr.FULL_PYTEST_RUNNER
MANIFEST_SCHEMA_VERSION = 1
MANIFEST_MODE = "docker01_pr_validation_manifest"
LANE_STATUS_MODE = "docker01_pr_lane_validation_status"
LANE_MANIFEST_MODE = "docker01_pr_lane_validation_manifest"
PR_LANE_STATUS_MODE = "docker01_pr_lane_status"
QA_BUNDLE_ROOT_ENV = "SFAI_QA_BUNDLE_ROOT"
COMPOSE_FILE_ENV = "SFAI_DOCKER01_COMPOSE_FILE"
DEFAULT_COMPOSE_FILE = Path("/srv/compose/shellforgeai/compose.yml")
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

# Conventional exit code for an interrupted validation run (128 + SIGINT).
INTERRUPTED_EXIT_CODE = 130


class _ValidationInterrupted(Exception):
    """Raised when a catchable signal interrupts validation execution."""

    def __init__(self, signal_name: str, exit_code: int = INTERRUPTED_EXIT_CODE) -> None:
        super().__init__(signal_name)
        self.signal_name = signal_name
        self.exit_code = exit_code


def _install_interrupt_handlers() -> dict:
    """Install SIGINT/SIGTERM handlers that surface a controlled interruption.

    Returns the previous handlers so they can be restored. Best-effort: signal
    handlers can only be installed in the main thread, so failures are ignored.
    """
    handlers: dict = {}

    def _handler(signum, _frame):
        name = signal.Signals(signum).name
        raise _ValidationInterrupted(name, exit_code=128 + int(signum))

    for sig in (signal.SIGINT, signal.SIGTERM):
        # Best-effort: signal handlers can only be set in the main thread.
        with contextlib.suppress(ValueError, OSError):
            handlers[sig] = signal.signal(sig, _handler)
    return handlers


def _restore_interrupt_handlers(handlers: dict) -> None:
    for sig, original in handlers.items():
        with contextlib.suppress(ValueError, OSError):
            signal.signal(sig, original)


def _required_phases_from_plan(plan: dict) -> tuple[str, ...]:
    """Derive the heartbeat required-phase set from the planned commands."""
    phases = ["ruff", "compileall"]
    kinds = {command.get("kind") for command in plan.get("_commands", [])}
    if "pytest_targeted" in kinds:
        phases.append("targeted_tests")
    if "pytest_full_runner" in kinds or plan.get("full_pytest_required"):
        phases.append("full_pytest")
    return tuple(phases)


def _phase_status_from_validation(validation: dict) -> dict:
    """Map the validation rollup to heartbeat-style phase status values."""

    def norm(value):
        if value in (None, "", UNKNOWN, "not_run"):
            return validation_heartbeat.PHASE_UNKNOWN
        return value

    return {
        "ruff": norm(validation.get("ruff")),
        "compileall": norm(validation.get("compileall")),
        "targeted_tests": norm(validation.get("targeted_tests")),
        "full_pytest": norm(validation.get("full_pytest")),
    }


def _derive_classification(status: str | None) -> str:
    return {
        "passed": validation_heartbeat.CLASS_PASSED,
        "failed": validation_heartbeat.CLASS_TEST_FAILURE,
        "incomplete": validation_heartbeat.CLASS_INTERRUPTED,
    }.get(status or "", validation_heartbeat.CLASS_UNKNOWN)


def _derive_full_pytest_result(full_pytest_exit_code, validation: dict) -> str:
    if full_pytest_exit_code is not None:
        return validation_heartbeat.full_pytest_result_from_exit(full_pytest_exit_code)
    value = (validation or {}).get("full_pytest")
    if value in ("passed", "failed", "not_required"):
        return value
    return validation_heartbeat.FULL_UNKNOWN


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
        default=[],
        help="Changed files, space-separated or comma-separated.",
    )
    parser.add_argument("--pr", dest="pr_number", help="PR number for PR-specific tests.")
    parser.add_argument("--commit", help="Requested PR head commit for read-only --status mode.")
    parser.add_argument(
        "--status",
        "--resume-status",
        action="store_true",
        help=(
            "Read-only Docker01 PR lane status/resume report; executes no deploy, "
            "build, validation, QA, or cleanup."
        ),
    )
    parser.add_argument("--json", action="store_true", help="With --status, emit strict JSON only.")
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
        "--execute",
        action="store_true",
        help="Run the planned validation commands. Default is planning/dry-run only.",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help=(
            "Run only the read-only validation environment preflight and exit. "
            "No validation phases are executed and nothing is installed."
        ),
    )
    parser.add_argument(
        "--preflight-output",
        help=(
            "Write the validation environment preflight JSON to this path "
            "(default: validation-preflight.json next to the manifest)."
        ),
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
        "--heartbeat-file",
        help=(
            "Write a validation heartbeat/status JSON updated before and after each phase so an "
            "interrupted run leaves clear partial evidence. Defaults to a path next to the "
            "manifest when executing validation."
        ),
    )
    parser.add_argument(
        "--status-file", help="Mirror the heartbeat JSON to this status path (same content)."
    )
    parser.add_argument(
        "--checkpoint-file", help="Append phase checkpoint events to this JSON path."
    )
    parser.add_argument("--run-id", help="Explicit validation run id for the heartbeat/manifest.")
    parser.add_argument(
        "--run-dir",
        help=(
            "Write Docker01 PR-lane validation evidence into this directory. "
            "Defaults to /tmp/sfai-pr<PR>-<shortsha>-validation-<timestamp>/."
        ),
    )
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


def _default_validation_run_dir(
    *, pr_number: str | None, short_commit: str | None, created_at: str
) -> Path:
    safe_pr = pr_number or "unknown"
    safe_sha = short_commit or "unknown"
    stamp = created_at.replace(":", "").replace("-", "").replace("Z", "")
    return Path(tempfile.gettempdir()) / f"sfai-pr{safe_pr}-{safe_sha}-validation-{stamp}"


def _command_record(command: dict, *, status: str, duration: float | None, log_path: str | None):
    return {
        "name": command.get("kind") or command.get("display") or UNKNOWN,
        "command": list(command.get("argv") or []),
        "display": command.get("display"),
        "status": status,
        "duration_seconds": round(duration, 3) if duration is not None else None,
        "log_path": log_path,
    }


def _command_key(record: dict) -> str:
    return {
        "lint": "ruff",
        "compile": "compileall",
        "pytest_targeted": "targeted_pytest",
        "pytest_full_runner": "full_pytest",
    }.get(str(record.get("name") or ""), str(record.get("name") or UNKNOWN))


def _log_excerpt(path: str | None, *, limit: int = 1000) -> str:
    if not path:
        return ""
    target = Path(path)
    if not target.is_file():
        return ""
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return text[-limit:]


def commands_run_records(command_records: list[dict]) -> list[dict]:
    records: list[dict] = []
    for record in command_records:
        status = record.get("status")
        records.append(
            {
                "key": _command_key(record),
                "argv": list(record.get("command") or []),
                "status": (
                    "skipped"
                    if status in ("not_run", "not_required", None)
                    else "passed"
                    if status == "passed"
                    else "failed"
                    if status == "failed"
                    else str(status)
                ),
                "exit_code": 0 if status == "passed" else 1 if status == "failed" else None,
                "duration_ms": (
                    int(float(record["duration_seconds"]) * 1000)
                    if record.get("duration_seconds") is not None
                    else 0
                ),
                "critical": True,
                "log_excerpt": _log_excerpt(record.get("log_path")),
            }
        )
    return records


def _lane_status_value(status: str | None, classification: str | None) -> str:
    if classification == "setup_failure":
        return "setup_failure"
    if classification == "interrupted_or_incomplete" or status == "incomplete":
        return "interrupted"
    if status in ("passed", "failed"):
        return status
    return "unknown"


def _lane_classification(value: str) -> str:
    return {
        "passed": "passed",
        "failed": "failed",
        "setup_failure": "setup_failure",
        "interrupted": "interrupted_or_incomplete",
        "partial": "interrupted_or_incomplete",
    }.get(value, "unknown")


def validation_evidence_safety() -> dict:
    return {
        "read_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "recovery_executed": False,
        "docker_prune_executed": False,
        "docker_image_removed": False,
        "file_deleted": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "cloud_apply_merge_push": False,
    }


def pr_lane_status_safety() -> dict:
    return {
        "read_only": True,
        "mutation_performed": False,
        "deploy_executed": False,
        "compose_written": False,
        "docker_build_executed": False,
        "validation_executed": False,
        "qa_executed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "recovery_executed": False,
        "docker_prune_executed": False,
        "docker_image_removed": False,
        "file_deleted": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "cloud_apply_merge_push": False,
    }


STATUS_ALLOWED_COMMANDS = (
    ("git", "rev-parse", "HEAD"),
    ("docker", "ps", "--filter", "name=shellforgeai"),
    ("docker", "inspect", "shellforgeai"),
)


def _status_run(argv: list[str], *, runner=None) -> subprocess.CompletedProcess:
    if tuple(argv) not in STATUS_ALLOWED_COMMANDS:
        raise ValueError(f"status command is not allowlisted: {' '.join(argv)}")
    runner = runner or subprocess.run
    return runner(argv, cwd=str(REPO_ROOT), check=False, capture_output=True, text=True)


def _status_git_head(*, runner=None) -> str | None:
    try:
        completed = _status_run(["git", "rev-parse", "HEAD"], runner=runner)
    except (OSError, ValueError):
        return None
    return (
        completed.stdout.strip() if completed.returncode == 0 and completed.stdout.strip() else None
    )


def _status_container(*, runner=None) -> dict:
    state = {
        "container_image": None,
        "container_image_id": None,
        "container_status": UNKNOWN,
        "container_health": UNKNOWN,
        "restart_count": None,
        "labels": {},
    }
    try:
        completed = _status_run(["docker", "inspect", "shellforgeai"], runner=runner)
    except (OSError, ValueError):
        return state
    if completed.returncode != 0:
        state["container_status"] = "unknown"
        return state
    try:
        payload = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError:
        return state
    item = payload[0] if isinstance(payload, list) and payload else {}
    cfg = item.get("Config") or {}
    st = item.get("State") or {}
    health = st.get("Health") or {}
    state.update(
        {
            # Config.Image is the operator-visible tag requested by compose.
            # Top-level Image is Docker's resolved image ID/digest and must not
            # override the configured tag for PR-lane status matching.
            "container_image": cfg.get("Image"),
            "container_image_id": item.get("Image"),
            "container_status": st.get("Status") or UNKNOWN,
            "container_health": health.get("Status") or ("none" if st else UNKNOWN),
            "restart_count": item.get("RestartCount"),
            "labels": cfg.get("Labels") or {},
        }
    )
    return state


def _expected_image(pr: str | int | None, commit: str | None) -> str:
    short = (commit or "")[:7] or UNKNOWN
    return f"lab/shellforgeai:pr{pr}-{short}"


def _is_digest(value: str | None) -> bool:
    text = str(value or "").strip()
    return text.startswith("sha256:") or text.startswith("sha256@")


def _image_matches(value: str | None, *, pr: int, commit: str, expected: str) -> bool:
    if not value or _is_digest(value):
        return False
    text = str(value)
    short7 = commit[:7]
    short12 = commit[:12]
    return text == expected or (f"pr{pr}-" in text and (short7 in text or short12 in text))


def _read_compose_image() -> str | None:
    raw = os.environ.get(COMPOSE_FILE_ENV)
    path = Path(raw) if raw else DEFAULT_COMPOSE_FILE
    if not path.is_file():
        return None
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if stripped.startswith("image:"):
                return stripped.split(":", 1)[1].strip().strip("\"'") or None
    except OSError:
        return None
    return None


def _validation_latest(pr: int, commit: str) -> dict:
    warnings: list[str] = []
    candidates = validation_status_viewer.discover_candidates(
        run_root=None, include_legacy=False, warnings=warnings
    )
    exact: list[dict] = []
    for candidate in candidates:
        if not validation_status_viewer._pr_matches(candidate.get("pr"), pr):
            continue
        if not validation_status_viewer._commit_matches(candidate.get("commit"), commit):
            continue
        status_path = Path(candidate["path"]) / "validation-status.json"
        if not status_path.is_file():
            continue
        try:
            doc = json.loads(status_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        doc["_candidate_path"] = candidate["path"]
        doc["_candidate_mtime"] = candidate.get("mtime") or status_path.stat().st_mtime
        exact.append(doc)
    if not exact:
        return {
            "status": "not_found",
            "classification": "not_found",
            "pass_eligible": False,
            "rerun_required": True,
            "source": {"kind": "not_found", "run_dir": None},
            "warnings": warnings,
        }

    def rank(doc: dict) -> tuple[int, float]:
        if doc.get("pass_eligible") is True:
            return (3, float(doc.get("_candidate_mtime") or 0))
        if doc.get("classification") == "passed" or doc.get("status") == "passed":
            return (2, float(doc.get("_candidate_mtime") or 0))
        return (1, float(doc.get("_candidate_mtime") or 0))

    selected = sorted(exact, key=rank, reverse=True)[0]
    selected.setdefault("source", {})
    selected["source"]["run_dir"] = selected.get("_candidate_path")
    selected["source"]["kind"] = "run_dir"
    selected["warnings"] = warnings
    return selected


def _qa_bundle_latest(pr: int, commit: str) -> dict:
    root = Path(os.environ.get(QA_BUNDLE_ROOT_ENV) or tempfile.gettempdir())
    candidates = []
    pattern = re.compile(
        r"^sfai-pr(?P<pr>\d+)-(?P<sha>[^-]+)-(?:(?:operator-)?qa-bundle)-(?P<stamp>.+)$"
    )
    if root.is_dir():
        for path in root.iterdir():
            match = pattern.match(path.name)
            if not path.is_dir() or not match:
                continue
            if str(match.group("pr")) != str(pr):
                continue
            if not validation_status_viewer._commit_matches(match.group("sha"), commit):
                continue
            qa_path = path / "qa-results.json"
            manifest_path = path / "bundle-manifest.json"
            doc_path = qa_path if qa_path.is_file() else manifest_path
            if not doc_path.is_file():
                continue
            try:
                doc = json.loads(doc_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                doc = {}
            candidates.append((path.stat().st_mtime, path, doc))
    if not candidates:
        return {
            "available": False,
            "status": "not_found",
            "bundle_path": None,
            "commands_passed": 0,
            "commands_failed": 0,
            "safety_assertions_failed": 0,
        }

    def rank(candidate: tuple[float, Path, dict]) -> tuple[int, float]:
        mtime, _path, doc = candidate
        status = doc.get("status")
        return (2 if status == "passed" else 1, mtime)

    _mtime, path, doc = sorted(candidates, key=rank, reverse=True)[0]
    summary = doc.get("summary") or {}
    return {
        "available": True,
        "status": doc.get("status") or UNKNOWN,
        "bundle_path": str(path),
        "commands_passed": int(summary.get("commands_passed") or 0),
        "commands_failed": int(summary.get("commands_failed") or 0),
        "safety_assertions_failed": int(summary.get("safety_assertions_failed") or 0),
    }


def _normalize_validation(report: dict) -> dict:
    source = report.get("source") or {}
    status = report.get("status") or "not_found"
    classification = report.get("classification") or "unknown"
    return {
        "available": status != "not_found",
        "status": status,
        "classification": classification,
        "pass_eligible": bool(report.get("pass_eligible")),
        "rerun_required": bool(report.get("rerun_required", status != "passed")),
        "run_dir": source.get("run_dir"),
        "full_validation": bool(report.get("full_validation")),
    }


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": bool(passed), "detail": detail}


def build_pr_lane_status(
    *, pr: int, commit: str, runner=None, created_at: str | None = None
) -> dict:
    created_at = created_at or _utc_now()
    short = commit[:12]
    warnings: list[str] = []
    source_head = _status_git_head(runner=runner)
    container = _status_container(runner=runner)
    labels = container.get("labels") or {}
    expected = _expected_image(pr, commit)
    configured_compose_image = _read_compose_image()
    label_compose_image = labels.get("homelab.compose_image") or labels.get(
        "com.docker.compose.image"
    )
    compose_image = configured_compose_image or label_compose_image
    validation = _normalize_validation(_validation_latest(pr, commit))
    qa_bundle = _qa_bundle_latest(pr, commit)
    if not qa_bundle["available"]:
        warnings.append("QA bundle evidence was not found for the exact PR/commit.")

    source_ok = source_head == commit
    pr_ok = str(labels.get("homelab.pr")) == str(pr)
    commit_ok = labels.get("homelab.commit") == commit
    image = container.get("container_image")
    image_ok = _image_matches(image, pr=pr, commit=commit, expected=expected) or (
        configured_compose_image is not None and image == configured_compose_image
    )
    compose_ok = (
        configured_compose_image is None
        and (label_compose_image is None or _is_digest(label_compose_image))
        or _image_matches(compose_image, pr=pr, commit=commit, expected=expected)
    )
    running = container.get("container_status") == "running"
    healthy = container.get("container_health") in ("healthy", "none")
    restart_count = container.get("restart_count")
    restart_ok = restart_count in (None, 0)
    deploy_match = source_ok and pr_ok and commit_ok and image_ok and compose_ok and running
    blocked_validation = validation["status"] == "failed" or validation["classification"] in (
        "failed",
        "test_failure",
        "setup_failure",
    )
    blocked_container = running and not healthy or (restart_count is not None and restart_count > 0)
    blocked_identity = running and not (pr_ok and commit_ok)
    checks = [
        _check("source_head_matches", source_ok, f"source HEAD is {source_head or UNKNOWN}"),
        _check(
            "compose_image_matches",
            compose_ok,
            f"compose image evidence is {compose_image or UNKNOWN}",
        ),
        _check(
            "container_running", running, f"container status is {container.get('container_status')}"
        ),
        _check(
            "container_healthy", healthy, f"container health is {container.get('container_health')}"
        ),
        _check("restart_count_acceptable", restart_ok, f"restart_count={restart_count}"),
        _check("container_labels_match", pr_ok and commit_ok, f"labels={labels}"),
        _check("container_image_matches", image_ok, f"container image is {image or UNKNOWN}"),
        _check(
            "validation_pass_eligible", validation["pass_eligible"], validation["classification"]
        ),
        _check("qa_bundle_passed", qa_bundle["status"] == "passed", qa_bundle["status"]),
    ]
    if blocked_container or blocked_validation or blocked_identity:
        status = "blocked"
    elif not deploy_match:
        status = "needs_deploy"
    elif validation["rerun_required"] or validation["status"] in ("not_found", "unknown"):
        status = "needs_validation"
    elif qa_bundle["status"] != "passed":
        status = "needs_qa"
    elif validation["pass_eligible"] and qa_bundle["status"] == "passed":
        status = "already_complete"
    else:
        status = "ready_to_continue"
    safe_next = _safe_next(status, pr, commit, validation, qa_bundle)
    return {
        "schema_version": 1,
        "mode": PR_LANE_STATUS_MODE,
        "status": status,
        "pr": pr,
        "commit": commit,
        "short_sha": short,
        "created_at": created_at,
        "read_only": True,
        "mutation_performed": False,
        "checks": checks,
        "state": {
            "source_head": source_head,
            "compose_image": compose_image,
            "container_image": image,
            "container_image_id": container.get("container_image_id"),
            "container_status": container.get("container_status"),
            "container_health": container.get("container_health"),
            "restart_count": restart_count,
            "labels": labels,
        },
        "validation": validation,
        "qa_bundle": qa_bundle,
        "safe_next": safe_next,
        "safety": pr_lane_status_safety(),
        "warnings": warnings,
    }


def _safe_next(status: str, pr: int, commit: str, validation: dict, qa_bundle: dict) -> dict:
    if status == "already_complete":
        path = qa_bundle.get("bundle_path")
        command = (
            f"cat {Path(path) / 'qa-summary.md'}"
            if path
            else (
                "python scripts/validation_status.py --latest "
                f"--pr {pr} --commit {commit} --json --explain-selection"
            )
        )
        return {
            "command": command,
            "reason": (
                "validation and QA evidence are already present; reviewer still gives "
                "final merge verdict"
            ),
        }
    if status == "needs_qa":
        return {
            "command": (
                f"python scripts/docker01_operator_qa_bundle.py --pr {pr} --commit {commit} --json"
            ),
            "reason": "validation is pass eligible but QA bundle is missing, failed, or partial",
        }
    if status == "needs_validation":
        return {
            "command": (
                "python scripts/validation_status.py --latest "
                f"--pr {pr} --commit {commit} --json --explain-selection"
            ),
            "reason": (
                "exact PR/commit validation evidence is missing or rerun is required; "
                "inspect evidence before rerunning the guarded lane"
            ),
        }
    if status == "needs_deploy":
        return {
            "command": (
                "python scripts/sfai_docker01_pr_lane.py "
                f"--pr {pr} --commit {commit} --changed-files <files> "
                "--full-validation --full-validation-reason '<reason>'"
            ),
            "reason": (
                "source, compose, container, image, or labels do not all match; "
                "use the guarded lane helper, not direct compose"
            ),
        }
    if status == "blocked":
        return {
            "command": (
                "python scripts/sfai_docker01_pr_lane.py "
                f"--pr {pr} --commit {commit} --status --json"
            ),
            "reason": (
                "blocked evidence detected; continue with read-only inspection only, "
                "not restart, cleanup, prune, or delete"
            ),
        }
    return {
        "command": (
            "python scripts/validation_status.py --latest "
            f"--pr {pr} --commit {commit} --json --explain-selection"
        ),
        "reason": "state is partially known; inspect existing evidence before any rerun",
    }


def render_pr_lane_status(doc: dict) -> str:
    return (
        "\n".join(
            [
                "Docker01 PR lane status",
                "",
                f"PR: {doc.get('pr')}",
                f"Commit: {doc.get('commit')}",
                f"Status: {doc.get('status')}",
                "",
                f"Source: {doc['state'].get('source_head') or UNKNOWN}",
                f"Compose: {doc['state'].get('compose_image') or UNKNOWN}",
                (
                    "Container: "
                    f"{doc['state'].get('container_status')} / "
                    f"{doc['state'].get('container_health')} / "
                    f"restart={doc['state'].get('restart_count')}"
                ),
                (
                    "Validation: "
                    f"{doc['validation'].get('status')} / "
                    f"{doc['validation'].get('classification')} / "
                    f"pass_eligible={doc['validation'].get('pass_eligible')}"
                ),
                (
                    "QA bundle: "
                    f"{doc['qa_bundle'].get('status')} / "
                    f"{doc['qa_bundle'].get('bundle_path') or UNKNOWN}"
                ),
                "Hygiene: available only when already captured in QA bundle evidence",
                "",
                f"Safe next command: {doc['safe_next'].get('command')}",
                f"Reason: {doc['safe_next'].get('reason')}",
                "",
                "Safety:",
                "- read-only status only",
                "- no deploy/build/compose/restart/validation executed",
                "- no cleanup/prune/delete",
                "- reviewer still gives the final merge verdict",
            ]
        )
        + "\n"
    )


def build_lane_validation_status(
    *,
    manifest: dict,
    run_dir: Path,
    commands: list[dict],
    log_path: str | None,
    created_at: str,
    completed_at: str,
) -> dict:
    pr_block = manifest.get("pr") or {}
    lane_block = manifest.get("lane") or {}
    value = _lane_status_value(manifest.get("status"), manifest.get("classification"))
    classification = _lane_classification(value)
    return {
        "schema_version": 1,
        "mode": LANE_STATUS_MODE,
        "status": value,
        "classification": classification,
        "pass_eligible": value == "passed",
        "rerun_required": value != "passed",
        "pr": pr_block.get("number"),
        "commit": pr_block.get("head_commit"),
        "short_sha": pr_block.get("short_commit"),
        "created_at": created_at,
        "completed_at": completed_at,
        "lane": "full" if lane_block.get("full_validation_required") else "targeted",
        "full_validation": bool(lane_block.get("full_validation_required")),
        "full_validation_reason": lane_block.get("full_validation_reason"),
        "commands": commands,
        "summary": {
            "commands_total": len(commands),
            "commands_passed": sum(1 for c in commands if c.get("status") == "passed"),
            "commands_failed": sum(1 for c in commands if c.get("status") == "failed"),
            "commands_skipped": sum(1 for c in commands if c.get("status") == "skipped"),
        },
        "source": {
            "kind": "docker01_pr_lane",
            "run_dir": str(run_dir),
            "log_path": log_path,
        },
        "safety": validation_evidence_safety(),
        "warnings": [],
    }


def render_lane_validation_summary(status_doc: dict) -> str:
    rows = []
    for item in status_doc.get("commands", []):
        command = " ".join(item.get("argv") or [item.get("key", UNKNOWN)])
        rows.append(f"| {command} | {item.get('status')} | {item.get('exit_code')} |")
    return "\n".join(
        [
            "# Docker01 PR Lane Validation Evidence",
            "",
            f"* PR: {status_doc.get('pr')}",
            f"* Commit: {status_doc.get('commit')}",
            f"* Lane: {status_doc.get('lane')}",
            f"* Full validation: {status_doc.get('full_validation')}",
            f"* Full validation reason: {status_doc.get('full_validation_reason')}",
            f"* Status: {status_doc.get('status')}",
            f"* Classification: {status_doc.get('classification')}",
            f"* Pass eligible: {status_doc.get('pass_eligible')}",
            f"* Rerun required: {status_doc.get('rerun_required')}",
            f"* Run dir: {status_doc.get('source', {}).get('run_dir')}",
            f"* Log path: {status_doc.get('source', {}).get('log_path')}",
            "",
            "## Commands",
            "",
            "| Command | Status | Exit code |",
            "| --- | --- | --- |",
            *rows,
            "",
            "## Safety",
            "",
            "* read-only validation evidence",
            "* no cleanup execution",
            "* no remediation execution",
            "* no rollback/recovery execution",
            "* no Docker prune/image removal/file deletion",
            "* no natural-language execution",
            "* no shell = True",
            "* no cloud apply/merge/push",
            "",
            "## Result",
            "",
            "* reviewer still gives final merge verdict",
            "",
        ]
    )


def _artifact_entry(path: Path, *, base: Path) -> dict:
    data = path.read_bytes()
    return {
        "path": str(path.relative_to(base)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def write_lane_validation_evidence(
    *,
    run_dir: Path,
    manifest: dict,
    command_records: list[dict],
    log_path: str | None,
    created_at: str,
) -> dict:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "logs").mkdir(exist_ok=True)
    commands = commands_run_records(command_records)
    completed_at = _utc_now()
    status_doc = build_lane_validation_status(
        manifest=manifest,
        run_dir=run_dir,
        commands=commands,
        log_path=log_path,
        created_at=created_at,
        completed_at=completed_at,
    )
    status_path = run_dir / "validation-status.json"
    commands_path = run_dir / "commands-run.json"
    summary_path = run_dir / "validation-summary.md"
    manifest_path = run_dir / "validation-manifest.json"
    status_path.write_text(
        json.dumps(status_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    commands_path.write_text(
        json.dumps(commands, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    summary_path.write_text(render_lane_validation_summary(status_doc), encoding="utf-8")
    log_files = []
    if log_path:
        log_files.append(log_path)
    manifest_doc = {
        "schema_version": 1,
        "mode": LANE_MANIFEST_MODE,
        "pr": status_doc.get("pr"),
        "commit": status_doc.get("commit"),
        "short_sha": status_doc.get("short_sha"),
        "created_at": created_at,
        "run_dir": str(run_dir),
        "status_file": "validation-status.json",
        "summary_file": "validation-summary.md",
        "commands_file": "commands-run.json",
        "log_files": log_files,
        "artifacts": [
            _artifact_entry(status_path, base=run_dir),
            _artifact_entry(commands_path, base=run_dir),
            _artifact_entry(summary_path, base=run_dir),
        ],
        "read_only": True,
        "mutation_performed": False,
    }
    manifest_path.write_text(
        json.dumps(manifest_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest_doc["artifacts"].append(_artifact_entry(manifest_path, base=run_dir))
    manifest_path.write_text(
        json.dumps(manifest_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest_doc


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
    classification: str | None = None,
    pass_eligible: bool | None = None,
    rerun_required: bool | None = None,
    last_completed_phase: str | None = None,
    active_phase_at_last_heartbeat: str | None = None,
    phase_status: dict | None = None,
    heartbeat_path: str | None = None,
    checkpoint_path: str | None = None,
    status_path: str | None = None,
    full_pytest_exit_code: int | None = None,
    full_pytest_result: str | None = None,
    preflight: dict | None = None,
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
    if status == "incomplete" and not failed_phase:
        failed = None
    validation_rollup = validation_status_from_commands(
        command_records, full_required=bool(plan.get("full_pytest_required", False))
    )
    # Classification / pass-eligibility evidence. A pass is only ever recorded
    # when status == "passed"; incomplete and failed runs are never pass-eligible.
    if classification is None:
        classification = _derive_classification(status)
    if pass_eligible is None:
        pass_eligible = status == "passed"
    if rerun_required is None:
        rerun_required = status != "passed"
    if full_pytest_result is None:
        full_pytest_result = _derive_full_pytest_result(full_pytest_exit_code, validation_rollup)
    if phase_status is None:
        phase_status = _phase_status_from_validation(validation_rollup)
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
        "validation": validation_rollup,
        "classification": classification,
        "pass_eligible": bool(pass_eligible),
        "rerun_required": bool(rerun_required),
        "last_completed_phase": last_completed_phase,
        "active_phase_at_last_heartbeat": active_phase_at_last_heartbeat,
        "phase_status": phase_status,
        "full_pytest_exit_code": full_pytest_exit_code,
        "full_pytest_result": full_pytest_result,
        "heartbeat_path": heartbeat_path,
        "checkpoint_path": checkpoint_path,
        "environment_preflight": preflight,
        "safety": _default_safety(no_cache=no_cache),
        "non_blockers": list(non_blockers or []),
        "artifacts": {
            "manifest_path": manifest_path,
            "human_summary_path": human_summary_path,
            "heartbeat_path": heartbeat_path,
            "checkpoint_path": checkpoint_path,
            "status_path": status_path,
            "preflight_path": (preflight or {}).get("path"),
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
    status = str(manifest.get("status") or UNKNOWN)
    classification = str(manifest.get("classification") or UNKNOWN)
    pass_eligible = bool(manifest.get("pass_eligible"))
    rerun_required = bool(manifest.get("rerun_required"))
    full_pytest_result = manifest.get("full_pytest_result") or UNKNOWN
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
        f"Validation result: {status.upper()}",
        f"Classification: {classification}",
        f"Pass eligible: {'yes' if pass_eligible else 'no'}",
        f"Rerun required: {'yes' if rerun_required else 'no'}",
        "Container: "
        f"{container.get('status') or UNKNOWN} / {container.get('health') or UNKNOWN} / "
        f"restart={restart}",
        "Validation:",
        "* environment preflight: "
        f"{(manifest.get('environment_preflight') or {}).get('status', 'not_run')}",
        f"* ruff: {validation.get('ruff', UNKNOWN)}",
        f"* compileall: {validation.get('compileall', UNKNOWN)}",
        f"* targeted tests: {validation.get('targeted_tests', UNKNOWN)}",
        f"* full pytest: {validation.get('full_pytest', UNKNOWN)} (result={full_pytest_result})",
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
        f"* heartbeat: {artifacts.get('heartbeat_path') or UNKNOWN}",
    ]
    if status == "incomplete":
        lines.extend(
            [
                "",
                "*** RERUN REQUIRED ***",
                "This run is INCOMPLETE and must not be used as merge evidence "
                "until a clean rerun passes.",
                "Last heartbeat:",
                f"* active phase: {manifest.get('active_phase_at_last_heartbeat') or UNKNOWN}",
                f"* last completed phase: {manifest.get('last_completed_phase') or UNKNOWN}",
            ]
        )
    if manifest.get("failed_phase"):
        lines.extend(["", f"Failed phase: {manifest['failed_phase']}"])
    if manifest.get("error_summary"):
        lines.append(f"Error: {manifest['error_summary']}")
    if manifest.get("failed_phase") == "environment_preflight":
        preflight = manifest.get("environment_preflight") or {}
        lines.extend(
            [
                "",
                "*** SETUP FAILURE ***",
                "Validation environment preflight failed. This is setup failure, "
                "not product test failure. Use the disposable validation container "
                "path or prepare dev dependencies, then rerun.",
            ]
        )
        for name in preflight.get("failed_checks") or []:
            lines.append(f"* Required validation dependency missing/failed: {name}")
        if preflight.get("fallback_packet_path"):
            run_dir = Path(preflight["fallback_packet_path"]).parent
            lines.extend(
                [
                    "Container fallback packet (generated; NOT executed):",
                    f"* {preflight['fallback_packet_path']}",
                    "First safe command:",
                    f"* cat {run_dir / 'validation-container-command.txt'}",
                ]
            )
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
    runner=None,
    return_records: bool = False,
    log_path: str | None = None,
    heartbeat: validation_heartbeat.ValidationHeartbeat | None = None,
    record_sink: list[dict] | None = None,
):
    # Resolve the runner at call time so the module-level ``subprocess.run`` can be
    # patched in tests; production callers get the real ``subprocess.run``.
    runner = runner or subprocess.run
    # ``record_sink`` lets the caller observe partial records even if execution is
    # interrupted mid-phase (the records list is the same object that is appended).
    records: list[dict] = record_sink if record_sink is not None else []
    seen_full_runner = False
    for command in plan["_commands"]:
        display = command["display"]
        phase = validation_heartbeat.COMMAND_KIND_TO_PHASE.get(command["kind"])
        if command["kind"] == "pytest_full_runner":
            if seen_full_runner:
                # Defence in depth: the helper never reruns full pytest in one run.
                continue
            seen_full_runner = True
            print(f"Full pytest runner: {display}", flush=True)
            print("duration reporting: --durations=25", flush=True)
        if heartbeat is not None and phase:
            heartbeat.start_phase(phase)
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
        if heartbeat is not None and phase:
            if command["kind"] == "pytest_full_runner":
                heartbeat.record_full_pytest_exit(rc, phase=phase)
            else:
                heartbeat.complete_phase(phase, status=_status_from_returncode(rc))
        if rc != 0:
            print(f"Command failed ({rc}): {display}", file=sys.stderr)
            return (rc, records) if return_records else rc
    return (0, records) if return_records else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.status:
        if args.execute_validation:
            parser.error("--status is read-only and cannot be combined with --execute")
        if args.no_cache or args.preflight_only:
            parser.error("--status cannot be combined with deploy/build/validation flags")
        if not args.pr_number or not args.commit:
            parser.error("--status requires --pr and --commit")
        doc = build_pr_lane_status(pr=int(args.pr_number), commit=args.commit)
        if args.json:
            print(json.dumps(doc, sort_keys=True))
        else:
            print(render_pr_lane_status(doc), end="")
        return 0
    if args.print_manifest_json and args.execute_validation and not args.dry_run:
        parser.error("--print-manifest-json cannot be combined with --execute-validation")
    changed_files = _split_changed_files(args.changed_files)
    if args.preflight_only:
        # Read-only environment preflight only: no planning, no validation
        # phases, no installs, no Docker/Compose.
        preflight_report = validation_env_preflight.run_preflight(
            artifact_dir=str(Path(args.preflight_output).parent) if args.preflight_output else None
        )
        if args.preflight_output:
            validation_env_preflight.write_report(preflight_report, args.preflight_output)
        print(validation_env_preflight.render_human(preflight_report), end="", flush=True)
        return validation_env_preflight.exit_code_for(preflight_report)
    if not changed_files:
        parser.error("--changed-files is required unless --preflight-only is used")
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
    validation_run_dir = (
        Path(args.run_dir)
        if args.run_dir
        else _default_validation_run_dir(
            pr_number=args.pr_number, short_commit=short_commit, created_at=created_at
        )
    )
    validation_run_dir.mkdir(parents=True, exist_ok=True)
    (validation_run_dir / "logs").mkdir(exist_ok=True)
    manifest_path = args.manifest_output or str(validation_run_dir / "docker01-lane-manifest.json")
    summary_path = args.summary_output or str(validation_run_dir / "docker01-lane-summary.txt")
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
    snapshot = None
    executed = bool(args.execute_validation and not args.dry_run)

    heartbeat_path = args.heartbeat_file
    checkpoint_path = args.checkpoint_file
    status_path = args.status_file
    if executed:
        if heartbeat_path is None:
            heartbeat_path = str(validation_run_dir / "validation-heartbeat.json")
        if checkpoint_path is None:
            checkpoint_path = str(validation_run_dir / "validation-checkpoints.json")
        if status_path is None:
            status_path = str(validation_run_dir / "validation-heartbeat-status.json")

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

    preflight_info = None
    if executed:
        required_phases = ("environment_preflight", *_required_phases_from_plan(plan))
        heartbeat = validation_heartbeat.ValidationHeartbeat(
            heartbeat_path,
            checkpoint_path=checkpoint_path,
            status_path=status_path,
            run_id=args.run_id,
            pr=args.pr_number,
            commit=head_commit,
            required_phases=required_phases,
        )
        heartbeat.start()
        # Read-only environment preflight before any ruff/compileall/pytest
        # phase. A failed preflight is a controlled setup failure: stop before
        # validation phases and leave clear setup_failure evidence instead of
        # running phases that will obviously fail. Nothing is installed and no
        # Docker/Compose fallback is executed; the container path is
        # recommendation text only.
        preflight_path = args.preflight_output or str(
            Path(manifest_path).parent / "validation-preflight.json"
        )
        heartbeat.start_phase("environment_preflight")
        preflight_report = validation_env_preflight.run_preflight(
            artifact_dir=str(Path(manifest_path).parent),
        )
        validation_env_preflight.write_report(preflight_report, preflight_path)
        preflight_info = {
            "status": preflight_report["status"],
            "classification": preflight_report["classification"],
            "failed_checks": list(preflight_report.get("failed_checks") or []),
            "warning_checks": list(preflight_report.get("warning_checks") or []),
            "path": preflight_path,
        }
        if preflight_report["status"] == validation_env_preflight.STATUS_FAILED:
            failed_names = ", ".join(preflight_info["failed_checks"]) or "unknown"
            snapshot = heartbeat.mark_setup_failure(
                reason=(
                    "validation environment preflight failed "
                    f"(missing/failed: {failed_names}); setup failure, "
                    "not product test failure"
                ),
                phase="environment_preflight",
            )
            phases.append(
                {"name": "environment_preflight", "status": "failed", "duration_seconds": None}
            )
            error_summary = (
                "validation environment preflight failed "
                f"(missing/failed: {failed_names}); this is setup failure, not "
                "product test failure; rerun in the disposable validation "
                "container or a prepared dev environment"
            )
            return_code = 1
            # PR179: write the disposable validation-container fallback packet
            # next to the manifest. Evidence files only — no Docker/Compose is
            # executed, no packages are installed, and the lane never runs the
            # generated command. Best-effort: packet failure never changes the
            # setup-failure outcome.
            try:
                packet = validation_container_fallback.generate_packet(
                    run_dir=Path(manifest_path).parent,
                    lane="full" if plan.get("full_pytest_required") else "targeted_runtime",
                    image=args.new_image,
                    pr=args.pr_number,
                    commit=head_commit,
                    preflight=preflight_report,
                )
            except OSError:
                packet = None
            if packet is not None and packet.get("status") == "created":
                preflight_info["fallback_packet_path"] = str(
                    Path(manifest_path).parent / validation_container_fallback.FALLBACK_JSON_NAME
                )
            else:
                preflight_info["fallback_packet_path"] = None
            print(
                "Validation environment preflight failed; stopping before "
                "validation phases (setup failure, not product test failure).",
                file=sys.stderr,
                flush=True,
            )
        else:
            heartbeat.complete_phase("environment_preflight")
            phases.append(
                {"name": "environment_preflight", "status": "passed", "duration_seconds": None}
            )
            # Warning-only preflight continues; preserve the warnings as
            # known non-blockers in the final evidence.
            for name in preflight_info["warning_checks"]:
                args.non_blocker.append(f"environment preflight warning: {name}")
            record_sink: list[dict] = []
            handlers = _install_interrupt_handlers()
            start = time.monotonic()
            try:
                return_code, command_records = run_validation(
                    plan,
                    return_records=True,
                    log_path=args.validation_log,
                    heartbeat=heartbeat,
                    record_sink=record_sink,
                )
                snapshot = heartbeat.finalize()
                phases.append(
                    {
                        "name": "validation",
                        "status": "passed" if return_code == 0 else "failed",
                        "duration_seconds": round(time.monotonic() - start, 3),
                    }
                )
                if return_code != 0:
                    failed = next(
                        (record for record in command_records if record.get("status") == "failed"),
                        None,
                    )
                    error_summary = (
                        f"validation command failed: {failed.get('display') or failed.get('name')}"
                        if failed
                        else "validation failed"
                    )
            except (_ValidationInterrupted, KeyboardInterrupt) as exc:
                signal_name = getattr(exc, "signal_name", None) or "SIGINT"
                return_code = int(getattr(exc, "exit_code", INTERRUPTED_EXIT_CODE))
                snapshot = heartbeat.mark_interrupted(signal_name=signal_name)
                command_records = list(record_sink)
                phases.append(
                    {
                        "name": "validation",
                        "status": "interrupted",
                        "duration_seconds": round(time.monotonic() - start, 3),
                    }
                )
                error_summary = (
                    f"validation interrupted ({signal_name}) before full pytest completion; "
                    "rerun required"
                )
                print(
                    f"Validation interrupted ({signal_name}); recorded incomplete evidence. "
                    "Rerun required.",
                    file=sys.stderr,
                    flush=True,
                )
            finally:
                _restore_interrupt_handlers(handlers)

    if snapshot is not None:
        manifest_status = snapshot["status"]
        manifest_verdict = None  # let the builder derive pass/fail/hold from status
        classification = snapshot["classification"]
        pass_eligible = snapshot["pass_eligible"]
        rerun_required = snapshot["rerun_required"]
        full_pytest_exit_code = snapshot["full_pytest_exit_code"]
        full_pytest_result = snapshot["full_pytest_result"]
        last_completed_phase = snapshot["last_completed_phase"]
        active_phase_at_last_heartbeat = snapshot["active_phase_at_last_heartbeat"]
        phase_status = snapshot["phase_status"]
        failed_phase = snapshot["failed_phase"]
    else:
        manifest_status = "failed" if return_code != 0 else "passed"
        manifest_verdict = "fail" if return_code != 0 else "pass"
        classification = None
        pass_eligible = None
        rerun_required = None
        full_pytest_exit_code = None
        full_pytest_result = None
        last_completed_phase = None
        active_phase_at_last_heartbeat = None
        phase_status = None
        failed_phase = None

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
        status=manifest_status,
        verdict=manifest_verdict,
        failed_phase=failed_phase,
        error_summary=error_summary,
        created_at=created_at,
        duration_report=duration_report,
        classification=classification,
        pass_eligible=pass_eligible,
        rerun_required=rerun_required,
        last_completed_phase=last_completed_phase,
        active_phase_at_last_heartbeat=active_phase_at_last_heartbeat,
        phase_status=phase_status,
        heartbeat_path=heartbeat_path if executed else None,
        checkpoint_path=checkpoint_path if executed else None,
        status_path=status_path if executed else None,
        full_pytest_exit_code=full_pytest_exit_code,
        full_pytest_result=full_pytest_result,
        preflight=preflight_info,
    )
    summary = render_human_summary(manifest)
    write_manifest(manifest, manifest_path)
    write_human_summary(summary, summary_path)
    write_lane_validation_evidence(
        run_dir=validation_run_dir,
        manifest=manifest,
        command_records=command_records,
        log_path=args.validation_log,
        created_at=created_at,
    )

    if args.print_manifest_json:
        print(json.dumps(manifest, sort_keys=True))
        return return_code

    print(render_plan(plan, no_cache=args.no_cache), flush=True)
    print()
    print(summary, end="", flush=True)
    # Read-only pointer to the validation evidence status viewer (PR177). The
    # viewer never executes validation; it only reads this run's evidence files.
    run_dir = str(validation_run_dir)
    print("\nValidation status viewer:")
    print(f"python scripts/validation_status.py --run-dir {run_dir} --json")
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
