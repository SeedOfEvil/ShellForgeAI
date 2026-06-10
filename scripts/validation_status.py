#!/usr/bin/env python3
"""Read-only validation evidence status viewer for ShellForgeAI.

After a long Docker01 / full-validation run (see PR176), operators need to
answer a few questions quickly without rerunning anything:

  * Did this validation run pass, fail, or end incomplete?
  * Is it merge-evidence eligible (``pass_eligible``)?
  * Is a rerun required (``rerun_required``)?
  * What phase was active when it stopped?
  * Where are the heartbeat / status / manifest / log files?

This viewer reads the PR176 heartbeat/status/checkpoint JSON plus the validation
manifest/summary written by ``sfai_docker01_pr_lane.py`` /
``run_mainline_validation.py``, then renders a human or strict-JSON status. It
classifies a run as ``passed`` / ``failed`` / ``incomplete`` / ``unknown`` using
the same conservative classifier as the heartbeat module
(:func:`validation_heartbeat.classify_run`).

Hard safety posture (this viewer is evidence-only and read-only):

  * It never executes validation, never runs ``pytest``, never runs a
    subprocess, never calls Docker/Compose, never mutates services/containers or
    the host, never runs cleanup/remediation/rollback/recovery, never restarts
    anything, never uses a shell or runs arbitrary commands, never calls a model,
    and never performs natural-language execution. It only reads ShellForgeAI
    validation evidence files and writes optional status text to stdout.

Conflict rule: if evidence sources disagree (for example a manifest says
``passed`` but a heartbeat says ``incomplete``), the viewer prefers the
conservative result and emits a warning; it never silently reports
``pass_eligible=true`` on conflicting evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HELPER_DIR = Path(__file__).resolve().parent

# Ensure the sibling validation_heartbeat helper is importable whether this file
# is run as a script or imported by tests via importlib.
if str(HELPER_DIR) not in sys.path:
    sys.path.insert(0, str(HELPER_DIR))

import validation_heartbeat as vh  # noqa: E402

SCHEMA_VERSION = 1
MODE = "validation_evidence_status"

# Overall viewer status values.
STATUS_PASSED = "passed"
STATUS_FAILED = "failed"
STATUS_INCOMPLETE = "incomplete"
STATUS_UNKNOWN = "unknown"

# Classification values surfaced by the viewer.
CLASS_PASSED = "passed"
CLASS_TEST_FAILURE = "test_failure"
CLASS_SETUP_FAILURE = "setup_failure"
CLASS_INTERRUPTED = "interrupted_or_incomplete"
CLASS_NO_EVIDENCE = "no_evidence"
CLASS_UNKNOWN = "unknown"

# Required phases shown in the human/JSON output, in display order.
REQUIRED_PHASES: tuple[str, ...] = vh.REQUIRED_PHASES

# Environment override (primarily for tests) pointing at a directory of runs.
RUNS_DIR_ENV = "SFAI_VALIDATION_RUNS_DIR"

# Known, ShellForgeAI-owned validation artifact roots scanned by ``--latest``.
# Only these directories are scanned; no arbitrary filesystem roots.
DEFAULT_SEARCH_DIRS: tuple[str, ...] = (
    "/tmp/shellforgeai-validation-runs",
    "/srv/data/shellforgeai/validation-runs",
    "/data/validation-runs",
)

# Filename suffixes used to group flat (non-subdirectory) run artifacts and to
# discover evidence files inside a run directory.
_EVIDENCE_GLOBS = {
    "manifest": ("manifest.json", "*-manifest.json", "*manifest*.json"),
    "heartbeat": ("validation-heartbeat.json", "*heartbeat*.json"),
    "status": ("validation-status.json", "*-status.json", "*status*.json"),
    "summary": ("validation-summary.txt", "*-summary.txt", "*summary*.txt"),
    "checkpoint": ("validation-checkpoints.json", "*checkpoint*.json"),
    "preflight": ("validation-preflight.json", "*preflight*.json"),
    "log": ("validation.log", "*-full-pytest.log", "*runner*.log", "*.log"),
}

# Per-phase status rank for merging phase_status across evidence sources; the
# most informative / least optimistic value wins so a partial run never reads as
# a pass.
_PHASE_RANK = {
    vh.PHASE_FAILED: 5,
    vh.PHASE_INTERRUPTED: 4,
    vh.PHASE_RUNNING: 3,
    vh.PHASE_PASSED: 2,
    vh.PHASE_NOT_STARTED: 1,
    vh.PHASE_NOT_REQUIRED: 1,
    vh.PHASE_UNKNOWN: 0,
}

# Overall status severity for the conservative cross-source merge. Higher wins,
# so any ``failed`` or ``incomplete`` source dominates a ``passed`` source and
# conflicting evidence can never report a pass.
_STATUS_SEVERITY = {
    STATUS_FAILED: 3,
    STATUS_INCOMPLETE: 2,
    STATUS_PASSED: 1,
}

FIRST_SAFE_COMMAND_TEMPLATE = "python scripts/validation_status.py --run-dir {run_dir} --json"
PREFLIGHT_SAFE_COMMAND = "python scripts/validation_env_preflight.py --json"
PREFLIGHT_MODE = "validation_environment_preflight"

# PR179 validation container fallback packet (read-only pointer; the viewer
# never generates or executes anything).
FALLBACK_PACKET_NAME = "validation-container-fallback.json"
FALLBACK_COMMAND_NAME = "validation-container-command.txt"
FALLBACK_GENERATE_TEMPLATE = (
    "python scripts/validation_container_fallback.py --run-dir {run_dir} --json"
)

SAFETY_BLOCK = {
    "read_only": True,
    "mutation_performed": False,
    "validation_executed": False,
    "pytest_executed": False,
    "cleanup_executed": False,
    "remediation_executed": False,
    "rollback_executed": False,
    "recovery_executed": False,
    "docker_compose_executed": False,
    "container_restarted": False,
    "production_restart_executed": False,
    "shell_true": False,
    "arbitrary_command_execution": False,
    "natural_language_execution": False,
    "model_called": False,
}


class ViewerError(Exception):
    """Raised for invalid arguments or unreadable explicit evidence paths."""


# --------------------------------------------------------------------------- #
# Evidence loading
# --------------------------------------------------------------------------- #
def load_json_evidence(
    path: str | os.PathLike[str] | None,
    warnings: list[str],
    *,
    label: str,
    required: bool = False,
) -> dict[str, Any] | None:
    """Load a JSON evidence file, recording warnings instead of raising.

    A ``required`` path that does not exist raises :class:`ViewerError` (a
    controlled error for an explicitly named, missing file). A present-but-broken
    file is reported as a warning and treated as absent (never a traceback).
    """
    if path is None:
        return None
    target = Path(path)
    if not target.exists():
        if required:
            raise ViewerError(f"{label} path does not exist: {target}")
        return None
    if target.is_dir():
        if required:
            raise ViewerError(f"{label} path is a directory, not a file: {target}")
        return None
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        warnings.append(f"could not read {label} evidence {target}: {exc}")
        return None
    if not isinstance(data, dict):
        warnings.append(f"{label} evidence {target} is not a JSON object; ignored")
        return None
    return data


def load_heartbeat(path, warnings, *, required=False):
    """Load a PR176 heartbeat JSON file (best-effort)."""
    return load_json_evidence(path, warnings, label="heartbeat", required=required)


def load_status(path, warnings, *, required=False):
    """Load a PR176 status JSON file (best-effort)."""
    return load_json_evidence(path, warnings, label="status", required=required)


def load_manifest(path, warnings, *, required=False):
    """Load a validation manifest JSON file (best-effort)."""
    return load_json_evidence(path, warnings, label="manifest", required=required)


# --------------------------------------------------------------------------- #
# Source discovery
# --------------------------------------------------------------------------- #
def _first_match(directory: Path, patterns: tuple[str, ...]) -> Path | None:
    """Return the newest file in ``directory`` matching one of ``patterns``."""
    for pattern in patterns:
        matches = sorted(
            (p for p in directory.glob(pattern) if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if matches:
            return matches[0]
    return None


def resolve_run_dir(run_dir: str | os.PathLike[str]) -> dict[str, Path | None]:
    """Locate heartbeat/status/manifest/summary/log files inside a run dir."""
    directory = Path(run_dir)
    if not directory.exists():
        raise ViewerError(f"run dir does not exist: {directory}")
    if not directory.is_dir():
        raise ViewerError(f"run dir is not a directory: {directory}")
    resolved: dict[str, Path | None] = {}
    for kind, patterns in _EVIDENCE_GLOBS.items():
        resolved[kind] = _first_match(directory, patterns)
    return resolved


def _run_mtime(directory: Path) -> float:
    """Return the newest evidence-file mtime under ``directory`` (0 if none)."""
    best = 0.0
    for patterns in _EVIDENCE_GLOBS.values():
        match = _first_match(directory, patterns)
        if match is not None:
            best = max(best, match.stat().st_mtime)
    return best


def candidate_run_dirs(search_dirs: list[str | os.PathLike[str]]) -> list[Path]:
    """Return candidate run directories found under the given search roots.

    A run directory is either an immediate subdirectory that contains evidence
    files, or a search root that itself directly contains evidence files (the
    flat layout used by ``run_mainline_validation.py``). Only the provided
    ShellForgeAI-owned roots are scanned; no arbitrary filesystem traversal.
    """
    candidates: list[Path] = []
    for raw in search_dirs:
        root = Path(raw)
        if not root.is_dir():
            continue
        if _run_mtime(root) > 0:
            candidates.append(root)
        for child in root.iterdir():
            if child.is_dir() and _run_mtime(child) > 0:
                candidates.append(child)
    return candidates


def default_search_dirs() -> list[str]:
    """Return the search roots for ``--latest`` (env override first)."""
    dirs: list[str] = []
    override = os.environ.get(RUNS_DIR_ENV)
    if override:
        dirs.append(override)
    dirs.extend(DEFAULT_SEARCH_DIRS)
    # Preserve order while de-duplicating.
    seen: set[str] = set()
    unique: list[str] = []
    for item in dirs:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def discover_latest(
    search_dirs: list[str | os.PathLike[str]] | None = None,
) -> Path | None:
    """Return the most recent run directory across the known search roots."""
    roots = default_search_dirs() if search_dirs is None else list(search_dirs)
    candidates = candidate_run_dirs(roots)
    if not candidates:
        return None
    return max(candidates, key=_run_mtime)


# --------------------------------------------------------------------------- #
# Per-source verdicts
# --------------------------------------------------------------------------- #
def _phase_status_from_rollup(rollup: dict[str, Any]) -> dict[str, str]:
    """Map a manifest ``validation`` rollup to heartbeat-style phase status."""

    def norm(value: Any) -> str:
        if value in (None, "", "not_run", "unknown"):
            return vh.PHASE_UNKNOWN
        if value in ("skipped_by_operator", "skipped_unavailable", "not_required"):
            return vh.PHASE_NOT_REQUIRED
        return str(value)

    return {phase: norm(rollup.get(phase)) for phase in REQUIRED_PHASES if phase in rollup}


def _normalize_stored_status(value: Any) -> str | None:
    """Map a stored evidence status onto a viewer status (or ``None``)."""
    if value in (vh.STATUS_PASSED,):
        return STATUS_PASSED
    if value in (vh.STATUS_FAILED,):
        return STATUS_FAILED
    if value in (vh.STATUS_INCOMPLETE, vh.STATUS_RUNNING, "partial", "interrupted"):
        return STATUS_INCOMPLETE
    return None


def source_verdict(data: dict[str, Any] | None, *, kind: str) -> dict[str, Any] | None:
    """Derive a conservative verdict from a single evidence document.

    Returns ``None`` when the document carries no usable status signal. The
    classifier is reused so a stored ``passed`` is cross-checked against the
    phase status and full-`pytest` exit code; the more conservative result wins.
    """
    if not isinstance(data, dict):
        return None

    phase_status = data.get("phase_status")
    if not isinstance(phase_status, dict):
        rollup = data.get("validation")
        phase_status = _phase_status_from_rollup(rollup) if isinstance(rollup, dict) else {}

    required = data.get("required_phases")
    if not isinstance(required, list) or not required:
        required = list(REQUIRED_PHASES)

    exit_code = data.get("full_pytest_exit_code")
    active = data.get("active_phase") or data.get("active_phase_at_last_heartbeat")
    last_completed = data.get("last_completed_phase")

    # When a source explicitly records full pytest as passed (phase status or
    # result) but did not carry a numeric exit code, treat that as exit 0 for the
    # classifier. A heartbeat only ever marks the full_pytest phase ``passed`` on
    # a captured exit 0, so this stays conservative and never invents a pass.
    fp_phase = (phase_status or {}).get("full_pytest") if isinstance(phase_status, dict) else None
    fp_result = data.get("full_pytest_result")
    effective_exit = exit_code if isinstance(exit_code, int) else None
    if effective_exit is None and (fp_phase == vh.PHASE_PASSED or fp_result == vh.FULL_PASSED):
        effective_exit = 0

    # An evidence document that explicitly recorded a setup failure (for
    # example a failed environment_preflight phase, which sits outside the
    # default required test phases) keeps that classification when recomputed,
    # instead of being misread as merely incomplete.
    stored_setup_failure = data.get("classification") == CLASS_SETUP_FAILURE
    stored_reason = data.get("reason") or data.get("error_summary")

    recomputed = vh.classify_run(
        phase_status if isinstance(phase_status, dict) else {},
        required_phases=[p for p in required if isinstance(p, str)] or list(REQUIRED_PHASES),
        full_pytest_exit_code=effective_exit,
        setup_failure=stored_setup_failure,
        setup_failure_reason=stored_reason if isinstance(stored_reason, str) else None,
        last_completed_phase=last_completed if isinstance(last_completed, str) else None,
        active_phase=active if isinstance(active, str) else None,
    )

    stored_status = _normalize_stored_status(data.get("status"))
    recomputed_status = recomputed["status"]

    has_phase_signal = bool(phase_status) or isinstance(exit_code, int)
    if stored_status is None and not has_phase_signal:
        # Nothing usable in this document.
        return None

    # Conservative pick between the stored status and the recomputed status.
    final_status = recomputed_status
    conflict = False
    if stored_status is not None and has_phase_signal:
        if _STATUS_SEVERITY.get(stored_status, 0) > _STATUS_SEVERITY.get(recomputed_status, 0):
            final_status = stored_status
        elif _STATUS_SEVERITY.get(stored_status, 0) < _STATUS_SEVERITY.get(recomputed_status, 0):
            final_status = recomputed_status
        conflict = stored_status != recomputed_status
    elif stored_status is not None:
        final_status = stored_status

    classification = _classification_for(final_status, data, recomputed)

    return {
        "kind": kind,
        "status": final_status,
        "classification": classification,
        "phase_status": phase_status if isinstance(phase_status, dict) else {},
        "active_phase": active if isinstance(active, str) else None,
        "last_completed_phase": last_completed if isinstance(last_completed, str) else None,
        "full_pytest_exit_code": exit_code if isinstance(exit_code, int) else None,
        "full_pytest_result": data.get("full_pytest_result") or recomputed["full_pytest_result"],
        "failed_phase": data.get("failed_phase") or recomputed["failed_phase"],
        "conflict": conflict,
        "stored_status": stored_status,
        "recomputed_status": recomputed_status,
    }


def preflight_verdict(data: dict[str, Any] | None) -> dict[str, Any] | None:
    """Derive a verdict from a PR178 environment preflight report.

    Only a *failed* preflight contributes a verdict (a controlled
    ``setup_failure`` before validation phases). A passed preflight is not run
    evidence — it only says the environment looked ready — so it never feeds
    the pass/fail merge.
    """
    if not isinstance(data, dict) or data.get("mode") != PREFLIGHT_MODE:
        return None
    if data.get("status") != STATUS_FAILED:
        return None
    return {
        "kind": "preflight",
        "status": STATUS_FAILED,
        "classification": CLASS_SETUP_FAILURE,
        "phase_status": {"environment_preflight": vh.PHASE_FAILED},
        "active_phase": None,
        "last_completed_phase": None,
        "full_pytest_exit_code": None,
        "full_pytest_result": vh.FULL_UNKNOWN,
        "failed_phase": "environment_preflight",
        "conflict": False,
        "stored_status": STATUS_FAILED,
        "recomputed_status": STATUS_FAILED,
    }


def _classification_for(status: str, data: dict[str, Any], recomputed: dict[str, Any]) -> str:
    if status == STATUS_PASSED:
        return CLASS_PASSED
    if status == STATUS_INCOMPLETE:
        return CLASS_INTERRUPTED
    if status == STATUS_FAILED:
        stored = data.get("classification")
        if stored in (CLASS_SETUP_FAILURE, CLASS_TEST_FAILURE):
            return stored
        recomputed_class = recomputed.get("classification")
        if recomputed_class in (CLASS_SETUP_FAILURE, CLASS_TEST_FAILURE):
            return recomputed_class
        return CLASS_TEST_FAILURE
    return CLASS_UNKNOWN


# --------------------------------------------------------------------------- #
# Cross-source classification / merge
# --------------------------------------------------------------------------- #
def _merge_phase_status(verdicts: list[dict[str, Any]]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for verdict in verdicts:
        for phase, value in (verdict.get("phase_status") or {}).items():
            current = merged.get(phase)
            if current is None or _PHASE_RANK.get(value, 0) > _PHASE_RANK.get(current, 0):
                merged[phase] = value
    return merged


def _full_pytest_confirmed(verdicts: list[dict[str, Any]]) -> bool:
    for verdict in verdicts:
        if verdict.get("full_pytest_exit_code") == 0:
            return True
        if verdict.get("full_pytest_result") == vh.FULL_PASSED:
            return True
        if (verdict.get("phase_status") or {}).get("full_pytest") == vh.PHASE_PASSED:
            return True
    return False


def classify_evidence(
    verdicts: list[dict[str, Any]],
    warnings: list[str],
    *,
    any_evidence_present: bool,
) -> dict[str, Any]:
    """Merge per-source verdicts into one conservative overall classification."""
    if not verdicts:
        status = STATUS_UNKNOWN
        classification = CLASS_NO_EVIDENCE if not any_evidence_present else CLASS_UNKNOWN
        return {
            "status": status,
            "classification": classification,
            "pass_eligible": False,
            "rerun_required": True,
            "phase_status": {},
            "active_phase": None,
            "last_completed_phase": None,
            "full_pytest_exit_code": None,
            "full_pytest_result": vh.FULL_UNKNOWN,
            "failed_phase": None,
        }

    # Highest severity status wins (failed > incomplete > passed). This makes any
    # disagreement collapse to the conservative result and never to a pass.
    dominant = max(verdicts, key=lambda v: _STATUS_SEVERITY.get(v["status"], 0))
    overall_status = dominant["status"]

    distinct = {v["status"] for v in verdicts}
    if STATUS_PASSED in distinct and (STATUS_FAILED in distinct or STATUS_INCOMPLETE in distinct):
        warnings.append(
            "conflicting validation evidence: at least one source reports passed "
            "while another reports a non-pass; using the conservative result and "
            "not marking pass_eligible"
        )
    for verdict in verdicts:
        if verdict.get("conflict"):
            warnings.append(
                f"{verdict['kind']} evidence stored status "
                f"'{verdict.get('stored_status')}' disagrees with recomputed "
                f"'{verdict.get('recomputed_status')}'; using the conservative result"
            )

    merged_phase = _merge_phase_status(verdicts)

    # A pass requires the overall verdict to be passed AND positive full-`pytest`
    # completion evidence. Missing that, downgrade to incomplete (never a pass).
    if overall_status == STATUS_PASSED and not _full_pytest_confirmed(verdicts):
        warnings.append(
            "evidence reports passed but no full pytest exit 0 / passed result was "
            "found; treating as incomplete (rerun required)"
        )
        overall_status = STATUS_INCOMPLETE

    classification = _overall_classification(overall_status, verdicts)
    pass_eligible = overall_status == STATUS_PASSED
    rerun_required = not pass_eligible

    active_phase = next((v.get("active_phase") for v in verdicts if v.get("active_phase")), None)
    last_completed = next(
        (v.get("last_completed_phase") for v in verdicts if v.get("last_completed_phase")),
        None,
    )
    exit_code = next(
        (
            v.get("full_pytest_exit_code")
            for v in verdicts
            if v.get("full_pytest_exit_code") is not None
        ),
        None,
    )
    full_result = vh.full_pytest_result_from_exit(exit_code)
    if exit_code is None:
        full_result = next(
            (
                v.get("full_pytest_result")
                for v in verdicts
                if v.get("full_pytest_result") not in (None, vh.FULL_UNKNOWN)
            ),
            vh.FULL_UNKNOWN,
        )
    failed_phase = next(
        (
            v.get("failed_phase")
            for v in verdicts
            if v.get("status") == STATUS_FAILED and v.get("failed_phase")
        ),
        None,
    )

    return {
        "status": overall_status,
        "classification": classification,
        "pass_eligible": pass_eligible,
        "rerun_required": rerun_required,
        "phase_status": merged_phase,
        "active_phase": active_phase,
        "last_completed_phase": last_completed,
        "full_pytest_exit_code": exit_code,
        "full_pytest_result": full_result,
        "failed_phase": failed_phase,
    }


def _overall_classification(status: str, verdicts: list[dict[str, Any]]) -> str:
    if status == STATUS_PASSED:
        return CLASS_PASSED
    if status == STATUS_INCOMPLETE:
        return CLASS_INTERRUPTED
    if status == STATUS_FAILED:
        for verdict in verdicts:
            if verdict["status"] == STATUS_FAILED and verdict["classification"] in (
                CLASS_SETUP_FAILURE,
                CLASS_TEST_FAILURE,
            ):
                return verdict["classification"]
        return CLASS_TEST_FAILURE
    return CLASS_UNKNOWN


# --------------------------------------------------------------------------- #
# Run metadata
# --------------------------------------------------------------------------- #
def _heartbeat_age_seconds(last_update: str | None) -> int | None:
    if not last_update:
        return None
    try:
        stamp = datetime.fromisoformat(str(last_update).replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    delta = datetime.now(UTC) - stamp
    return max(0, int(delta.total_seconds()))


def _run_metadata(docs: list[dict[str, Any]]) -> dict[str, Any]:
    def pick(key: str) -> Any:
        for doc in docs:
            value = doc.get(key)
            if value not in (None, ""):
                return value
        return None

    pr = pick("pr")
    if pr is None:
        for doc in docs:
            block = doc.get("pr")
            if isinstance(block, dict) and block.get("number") is not None:
                pr = block.get("number")
                break
    commit = pick("commit")
    if commit is None:
        for doc in docs:
            block = doc.get("pr")
            if isinstance(block, dict) and block.get("head_commit"):
                commit = block.get("head_commit")
                break
    last_update = pick("last_update")
    return {
        "run_id": pick("run_id"),
        "pr": pr,
        "commit": commit,
        "started_at": pick("started_at") or pick("created_at"),
        "last_update": last_update,
        "heartbeat_age_seconds": _heartbeat_age_seconds(last_update),
    }


# --------------------------------------------------------------------------- #
# Report assembly
# --------------------------------------------------------------------------- #
def _log_path_from_manifest(manifest: dict[str, Any] | None) -> str | None:
    if not isinstance(manifest, dict):
        return None
    logs = manifest.get("logs")
    if isinstance(logs, dict):
        for key in ("validation", "runner", "qa", "deploy"):
            value = logs.get(key)
            if value:
                return str(value)
        for value in logs.values():
            if value:
                return str(value)
    return None


def build_report(
    *,
    latest: bool,
    run_dir: str | None,
    heartbeat_path: str | None,
    status_path: str | None,
    manifest_path: str | None,
    summary_path: str | None,
    log_path: str | None,
    heartbeat_doc: dict[str, Any] | None,
    status_doc: dict[str, Any] | None,
    manifest_doc: dict[str, Any] | None,
    warnings: list[str],
    preflight_path: str | None = None,
    preflight_doc: dict[str, Any] | None = None,
    fallback_packet_path: str | None = None,
) -> dict[str, Any]:
    """Assemble the strict-JSON report dict from loaded evidence documents."""
    verdicts: list[dict[str, Any]] = []
    for doc, kind in (
        (status_doc, "status"),
        (heartbeat_doc, "heartbeat"),
        (manifest_doc, "manifest"),
    ):
        verdict = source_verdict(doc, kind=kind)
        if verdict is not None:
            verdicts.append(verdict)
    pf_verdict = preflight_verdict(preflight_doc)
    if pf_verdict is not None:
        verdicts.append(pf_verdict)

    any_evidence_present = any(
        p is not None
        for p in (heartbeat_path, status_path, manifest_path, summary_path, preflight_path)
    )
    merged = classify_evidence(verdicts, warnings, any_evidence_present=any_evidence_present)

    docs = [d for d in (status_doc, heartbeat_doc, manifest_doc) if isinstance(d, dict)]
    run_meta = _run_metadata(docs)

    resolved_log = log_path or _log_path_from_manifest(manifest_doc)

    run_dir_display = run_dir or "<run_dir>"

    # For a setup failure the first safe command is the read-only environment
    # preflight itself: it tells the operator whether the environment is ready
    # before any rerun, without installing or executing anything.
    setup_failure = merged["classification"] == CLASS_SETUP_FAILURE
    viewer_command = FIRST_SAFE_COMMAND_TEMPLATE.format(run_dir=run_dir_display)
    fallback_present = fallback_packet_path is not None
    if setup_failure:
        # Setup failures also point at the PR179 container fallback packet:
        # the operator either inspects an existing packet's command text or
        # generates one (both packet-only paths; nothing is executed).
        if fallback_present:
            fallback_command = f"cat {Path(fallback_packet_path).parent / FALLBACK_COMMAND_NAME}"
        else:
            fallback_command = FALLBACK_GENERATE_TEMPLATE.format(run_dir=run_dir_display)
        first_safe_command = PREFLIGHT_SAFE_COMMAND
        safe_next_commands = [PREFLIGHT_SAFE_COMMAND, fallback_command, viewer_command]
    else:
        first_safe_command = viewer_command
        safe_next_commands = [viewer_command, "python scripts/validation_status.py --latest --json"]

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": merged["status"],
        "classification": merged["classification"],
        "pass_eligible": bool(merged["pass_eligible"]),
        "rerun_required": bool(merged["rerun_required"]),
        "source": {
            "latest": bool(latest),
            "run_dir": run_dir,
            "heartbeat_path": heartbeat_path,
            "status_path": status_path,
            "manifest_path": manifest_path,
            "summary_path": summary_path,
            "log_path": resolved_log,
            "preflight_path": preflight_path,
            "fallback_packet_path": fallback_packet_path,
        },
        "fallback_packet_present": fallback_present,
        "fallback_packet_path": fallback_packet_path,
        "run": run_meta,
        "phases": {
            "active_phase": merged["active_phase"],
            "last_completed_phase": merged["last_completed_phase"],
            "phase_status": _phase_status_for_output(merged["phase_status"]),
        },
        "full_pytest": {
            "exit_code": merged["full_pytest_exit_code"],
            "result": merged["full_pytest_result"],
        },
        "failed_phase": merged["failed_phase"],
        "warnings": list(warnings),
        "first_safe_command": first_safe_command,
        "safe_next_commands": safe_next_commands,
        "safety": dict(SAFETY_BLOCK),
    }


def _phase_status_for_output(merged: dict[str, str]) -> dict[str, str]:
    """Return required phases first (defaulting to unknown), then any extras."""
    out: dict[str, str] = {}
    for phase in REQUIRED_PHASES:
        out[phase] = merged.get(phase, vh.PHASE_UNKNOWN)
    for phase, value in merged.items():
        if phase not in out:
            out[phase] = value
    return out


# --------------------------------------------------------------------------- #
# Human rendering
# --------------------------------------------------------------------------- #
def _phase_display(value: str) -> str:
    if value in (vh.PHASE_RUNNING, vh.PHASE_UNKNOWN, vh.PHASE_NOT_STARTED, vh.PHASE_INTERRUPTED):
        return "running/unknown"
    return value


def render_human(report: dict[str, Any]) -> str:
    status = report["status"]
    source = report["source"]
    phases = report["phases"]
    lines = [
        "Validation evidence status",
        "",
        f"Status: {status.upper()}",
        f"Classification: {report['classification']}",
        f"Pass eligible: {'yes' if report['pass_eligible'] else 'no'}",
        f"Rerun required: {'yes' if report['rerun_required'] else 'no'}",
    ]

    if status == STATUS_UNKNOWN and report["classification"] == CLASS_NO_EVIDENCE:
        lines.extend(
            [
                "",
                "No validation heartbeat/status/manifest evidence was found.",
            ]
        )
    else:
        lines.append("")
        lines.append("Required phases:")
        for phase in REQUIRED_PHASES:
            value = phases["phase_status"].get(phase, vh.PHASE_UNKNOWN)
            lines.append(f"* {phase}: {_phase_display(value)}")

    if status == STATUS_FAILED and report.get("failed_phase"):
        lines.extend(["", "Failed phase:", f"* {report['failed_phase']}"])

    if status == STATUS_FAILED and report["classification"] == CLASS_SETUP_FAILURE:
        lines.extend(
            [
                "",
                "This is validation environment setup failure, not evidence that "
                "product tests failed.",
                "Run validation in the disposable validation container path, or "
                "prepare the host dev environment outside ShellForgeAI, then "
                "rerun validation.",
            ]
        )
        if report.get("fallback_packet_present"):
            lines.append(f"Container fallback packet: {report.get('fallback_packet_path')}")

    if status == STATUS_INCOMPLETE:
        lines.extend(
            [
                "",
                "Last heartbeat:",
                f"* active phase: {phases.get('active_phase') or 'unknown'}",
                f"* last completed phase: {phases.get('last_completed_phase') or 'unknown'}",
                f"* last update: {report['run'].get('last_update') or 'unknown'}",
            ]
        )

    evidence_lines = []
    for label, key in (
        ("manifest", "manifest_path"),
        ("heartbeat", "heartbeat_path"),
        ("status", "status_path"),
        ("summary", "summary_path"),
        ("preflight", "preflight_path"),
        ("fallback packet", "fallback_packet_path"),
        ("log", "log_path"),
    ):
        value = source.get(key)
        if value:
            evidence_lines.append(f"* {label}: {value}")
    if evidence_lines:
        lines.append("")
        lines.append("Evidence:")
        lines.extend(evidence_lines)

    if report["warnings"]:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"* {warning}" for warning in report["warnings"])

    if status == STATUS_INCOMPLETE:
        lines.extend(
            [
                "",
                "This run must not be used as merge evidence until a clean rerun passes.",
            ]
        )
    elif status == STATUS_UNKNOWN:
        lines.extend(
            [
                "",
                "Unknown/no validation evidence is not merge evidence; rerun required.",
            ]
        )

    lines.extend(
        [
            "",
            "First safe command:",
            report["first_safe_command"],
        ]
    )
    return "\n".join(lines) + "\n"


# Backwards-friendly aliases matching the helper names suggested in the task.
render_human_status = render_human


def render_json_status(report: dict[str, Any]) -> str:
    return json.dumps(report, sort_keys=True)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="validation_status.py",
        description=(
            "Read-only validation evidence status viewer. Classifies a validation "
            "run as passed/failed/incomplete/unknown from PR176 heartbeat/status "
            "and manifest evidence. It never executes validation or pytest, never "
            "calls Docker/Compose, and never mutates anything."
        ),
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Discover the most recent run dir from known validation artifact roots.",
    )
    parser.add_argument("--run-dir", help="Run directory containing validation evidence files.")
    parser.add_argument("--heartbeat", help="Explicit heartbeat JSON path.")
    parser.add_argument("--status-file", help="Explicit status JSON path.")
    parser.add_argument("--manifest", help="Explicit manifest JSON path.")
    parser.add_argument("--summary", help="Explicit summary file path (for evidence listing).")
    parser.add_argument("--log", help="Explicit validation log path (for evidence listing).")
    parser.add_argument("--json", action="store_true", help="Emit strict JSON only.")
    return parser


def _resolve_sources(args: argparse.Namespace, warnings: list[str]) -> dict[str, Any]:
    """Resolve evidence file paths from the requested source mode."""
    run_dir = args.run_dir
    latest = bool(args.latest)
    heartbeat_path = args.heartbeat
    status_path = args.status_file
    manifest_path = args.manifest
    summary_path = args.summary
    log_path = args.log

    explicit = any((heartbeat_path, status_path, manifest_path, summary_path, log_path))

    if latest and run_dir is None and not explicit:
        discovered = discover_latest()
        if discovered is not None:
            run_dir = str(discovered)
        else:
            warnings.append("no validation runs found under known artifact roots")

    # If neither latest, run-dir, nor explicit files were requested, default to a
    # latest scan so a bare invocation is still useful.
    if not latest and run_dir is None and not explicit:
        latest = True
        discovered = discover_latest()
        if discovered is not None:
            run_dir = str(discovered)
        else:
            warnings.append("no validation runs found under known artifact roots")

    preflight_path = None
    fallback_packet_path = None
    if run_dir is not None:
        resolved = resolve_run_dir(run_dir)
        heartbeat_path = heartbeat_path or _as_str(resolved.get("heartbeat"))
        status_path = status_path or _as_str(resolved.get("status"))
        manifest_path = manifest_path or _as_str(resolved.get("manifest"))
        summary_path = summary_path or _as_str(resolved.get("summary"))
        log_path = log_path or _as_str(resolved.get("log"))
        preflight_path = _as_str(resolved.get("preflight"))
        fallback_candidate = Path(run_dir) / FALLBACK_PACKET_NAME
        if fallback_candidate.is_file():
            fallback_packet_path = str(fallback_candidate)

    return {
        "latest": latest,
        "run_dir": run_dir,
        "heartbeat_path": heartbeat_path,
        "status_path": status_path,
        "manifest_path": manifest_path,
        "summary_path": summary_path,
        "log_path": log_path,
        "preflight_path": preflight_path,
        "fallback_packet_path": fallback_packet_path,
        "explicit": explicit,
    }


def _as_str(value: Path | None) -> str | None:
    return str(value) if value is not None else None


def generate_report(args: argparse.Namespace) -> dict[str, Any]:
    warnings: list[str] = []
    sources = _resolve_sources(args, warnings)

    # Explicit paths must exist (controlled error); discovered paths are optional.
    heartbeat_doc = load_heartbeat(
        sources["heartbeat_path"], warnings, required=bool(args.heartbeat)
    )
    status_doc = load_status(sources["status_path"], warnings, required=bool(args.status_file))
    manifest_doc = load_manifest(sources["manifest_path"], warnings, required=bool(args.manifest))
    preflight_doc = load_json_evidence(sources["preflight_path"], warnings, label="preflight")

    return build_report(
        latest=sources["latest"],
        run_dir=sources["run_dir"],
        heartbeat_path=sources["heartbeat_path"],
        status_path=sources["status_path"],
        manifest_path=sources["manifest_path"],
        summary_path=sources["summary_path"],
        log_path=sources["log_path"],
        heartbeat_doc=heartbeat_doc,
        status_doc=status_doc,
        manifest_doc=manifest_doc,
        warnings=warnings,
        preflight_path=sources["preflight_path"],
        preflight_doc=preflight_doc,
        fallback_packet_path=sources["fallback_packet_path"],
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report = generate_report(args)
    except ViewerError as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(render_json_status(report))
    else:
        print(render_human(report), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
