#!/usr/bin/env python3
"""Validation-lane heartbeat / checkpoint helper for ShellForgeAI.

Long Docker01 / full-validation runs can be SIGTERM/SIGINT/timeout-interrupted
(or SIGKILLed) before the outer helper records full `pytest` completion. When
that happens the *absence* of a recorded pass must be obvious, and the partial
evidence must say "rerun required" rather than silently looking like a pass.

This module provides:

  * ``ValidationHeartbeat`` — a tiny state object that writes a strict-JSON
    heartbeat/checkpoint/status file before and after each validation phase, so
    the last on-disk heartbeat always shows the active phase and never records a
    completed PASS that did not happen.
  * ``classify_run`` — a pure, deterministic classifier that turns phase status
    plus an optional captured full-`pytest` exit code into one of
    ``passed`` / ``failed`` / ``incomplete`` with a matching classification,
    ``pass_eligible``, and ``rerun_required``.

Hard safety posture (this module is evidence-only):

  * It never runs Docker/Compose, never mutates services/containers/host, never
    runs cleanup/remediation/rollback/recovery, never restarts anything, never
    uses a shell or runs arbitrary commands, never calls a model, and never
    performs natural-language execution. It only reads/writes ShellForgeAI
    validation evidence JSON files.

SIGKILL caveat: SIGKILL cannot be caught, so a finalizing heartbeat cannot be
written on SIGKILL. That is intentional and safe — the *last* heartbeat written
before the kill still shows the active phase as ``running`` (never ``passed``),
and :func:`classify_run` reads that as ``incomplete`` / ``rerun_required``.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MODE = "validation_heartbeat"

# Phase names tracked across a full validation lane. ``summary`` is the final
# manifest/summary write; it is informational and not required for a pass.
DEFAULT_PHASES: tuple[str, ...] = (
    "ruff",
    "compileall",
    "targeted_tests",
    "full_pytest",
    "summary",
)
# Phases that must each pass for a run to be pass-eligible.
REQUIRED_PHASES: tuple[str, ...] = ("ruff", "compileall", "targeted_tests", "full_pytest")
# Pre-test phases. A failure here is classified as a setup failure.
SETUP_PHASES: tuple[str, ...] = ("ruff", "compileall")
# Test phases. A failure here is classified as a test failure.
TEST_PHASES: tuple[str, ...] = ("targeted_tests", "full_pytest")

# Per-phase status values.
PHASE_NOT_STARTED = "not_started"
PHASE_RUNNING = "running"
PHASE_PASSED = "passed"
PHASE_FAILED = "failed"
PHASE_INTERRUPTED = "interrupted"
PHASE_UNKNOWN = "unknown"
PHASE_NOT_REQUIRED = "not_required"

# Overall run status values.
STATUS_RUNNING = "running"
STATUS_PASSED = "passed"
STATUS_FAILED = "failed"
STATUS_INCOMPLETE = "incomplete"

# Run classification values.
CLASS_PASSED = "passed"
CLASS_TEST_FAILURE = "test_failure"
CLASS_SETUP_FAILURE = "setup_failure"
CLASS_INTERRUPTED = "interrupted_or_incomplete"
CLASS_UNKNOWN = "unknown"

# Full-`pytest` result values derived from a captured exit code.
FULL_PASSED = "passed"
FULL_FAILED = "failed"
FULL_UNKNOWN = "unknown"

# Map ``validate_pr`` command kinds to heartbeat phase names so the Docker01 PR
# lane helper can drive a heartbeat directly from its planned commands.
COMMAND_KIND_TO_PHASE: dict[str, str] = {
    "lint": "ruff",
    "compile": "compileall",
    "pytest_targeted": "targeted_tests",
    "pytest_full_runner": "full_pytest",
}


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp like ``2026-06-09T00:00:00Z``."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_run_id(*, pr: Any = None, commit: str | None = None, clock=None) -> str:
    """Build a readable, mostly-unique run id from pr/commit/time."""
    stamp = (clock or utc_now)().replace(":", "").replace("-", "").replace("Z", "")
    parts = ["validation"]
    if pr not in (None, ""):
        parts.append(f"pr{pr}")
    if commit:
        parts.append(str(commit)[:12])
    parts.append(stamp)
    return "-".join(parts)


def full_pytest_result_from_exit(exit_code: int | None) -> str:
    """Map a captured full-`pytest` exit code to passed/failed/unknown.

    ``None`` (no exit code captured) is always ``unknown`` — an interrupted or
    killed run must never report ``passed`` for full `pytest`.
    """
    if exit_code is None:
        return FULL_UNKNOWN
    return FULL_PASSED if int(exit_code) == 0 else FULL_FAILED


def _normalized_phase_status(
    phase_status: Mapping[str, str] | None, required_phases: Sequence[str]
) -> dict[str, str]:
    source = dict(phase_status or {})
    normalized: dict[str, str] = {}
    for phase in required_phases:
        normalized[phase] = str(source.get(phase, PHASE_NOT_STARTED) or PHASE_NOT_STARTED)
    # Preserve any extra phases (e.g. ``summary``) without affecting the verdict.
    for phase, value in source.items():
        if phase not in normalized:
            normalized[phase] = str(value or PHASE_NOT_STARTED)
    return normalized


def classify_run(
    phase_status: Mapping[str, str] | None,
    *,
    required_phases: Sequence[str] = REQUIRED_PHASES,
    full_pytest_exit_code: int | None = None,
    setup_failure: bool = False,
    setup_failure_reason: str | None = None,
    last_completed_phase: str | None = None,
    active_phase: str | None = None,
) -> dict[str, Any]:
    """Deterministically classify a validation run from phase status.

    Returns a dict with ``status`` / ``classification`` / ``pass_eligible`` /
    ``rerun_required`` plus supporting evidence fields. The classifier is
    conservative: a pass requires every required phase to be ``passed`` *and* a
    captured full-`pytest` exit code of ``0`` whenever ``full_pytest`` is
    required. Anything missing that evidence is ``incomplete`` (never a pass).
    """
    required = tuple(required_phases)
    normalized = _normalized_phase_status(phase_status, required)
    full_exit = None if full_pytest_exit_code is None else int(full_pytest_exit_code)
    full_result = full_pytest_result_from_exit(full_exit)

    setup_failed_phase = next(
        (p for p in required if p in SETUP_PHASES and normalized[p] == PHASE_FAILED), None
    )
    test_failed_phase = next(
        (p for p in required if p in TEST_PHASES and normalized[p] == PHASE_FAILED), None
    )
    other_failed_phase = next((p for p in required if normalized[p] == PHASE_FAILED), None)

    def result(status: str, classification: str, *, failed_phase: str | None, reason: str):
        pass_eligible = status == STATUS_PASSED
        return {
            "status": status,
            "classification": classification,
            "pass_eligible": pass_eligible,
            "rerun_required": not pass_eligible,
            "full_pytest_exit_code": full_exit,
            "full_pytest_result": full_result,
            "failed_phase": failed_phase,
            "last_completed_phase": last_completed_phase,
            "active_phase_at_last_heartbeat": active_phase,
            "phase_status": normalized,
            "reason": reason,
        }

    # 1. Explicit setup failure, or a pre-test (ruff/compileall) phase failed.
    if setup_failure or setup_failed_phase is not None:
        failed_phase = setup_failed_phase or active_phase
        reason = setup_failure_reason or (
            f"setup phase '{failed_phase}' failed before tests completed"
            if failed_phase
            else "helper setup failed before validation tests ran"
        )
        return result(STATUS_FAILED, CLASS_SETUP_FAILURE, failed_phase=failed_phase, reason=reason)

    # 2. Test failure: a test phase failed, or full pytest exited nonzero.
    if test_failed_phase is not None or (full_exit is not None and full_exit != 0):
        failed_phase = test_failed_phase or "full_pytest"
        return result(
            STATUS_FAILED,
            CLASS_TEST_FAILURE,
            failed_phase=failed_phase,
            reason=f"validation phase '{failed_phase}' failed",
        )

    # 3. Any other failed required phase (defensive).
    if other_failed_phase is not None:
        return result(
            STATUS_FAILED,
            CLASS_TEST_FAILURE,
            failed_phase=other_failed_phase,
            reason=f"validation phase '{other_failed_phase}' failed",
        )

    # 4. Pass: every required phase passed AND full pytest exit 0 was captured
    #    (when full pytest is required).
    all_required_passed = all(normalized[p] == PHASE_PASSED for p in required)
    full_required = "full_pytest" in required
    full_confirmed = (not full_required) or (full_exit == 0)
    if all_required_passed and full_confirmed:
        return result(
            STATUS_PASSED,
            CLASS_PASSED,
            failed_phase=None,
            reason="all required validation phases passed",
        )

    # 5. Otherwise the run did not record completion -> incomplete / rerun.
    if full_required and full_exit is None:
        reason = "full pytest completion was not recorded (exit code unknown); rerun required"
    else:
        reason = "validation run did not complete all required phases; rerun required"
    return result(STATUS_INCOMPLETE, CLASS_INTERRUPTED, failed_phase=None, reason=reason)


class ValidationHeartbeat:
    """Mutable validation-lane heartbeat that writes strict JSON evidence.

    The heartbeat is updated before and after each phase. While the run is in
    progress the on-disk ``status`` is ``running``; :meth:`finalize`,
    :meth:`mark_interrupted`, and :meth:`mark_setup_failure` classify the run and
    persist the terminal status. Writing is best-effort and never raises into the
    validation flow.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        checkpoint_path: str | os.PathLike[str] | None = None,
        status_path: str | os.PathLike[str] | None = None,
        run_id: str | None = None,
        pr: Any = None,
        commit: str | None = None,
        mode: str = MODE,
        phases: Iterable[str] = DEFAULT_PHASES,
        required_phases: Iterable[str] = REQUIRED_PHASES,
        pid: int | None = None,
        clock=None,
    ) -> None:
        self.path = Path(path)
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else None
        self.status_path = Path(status_path) if status_path else None
        self._clock = clock or utc_now
        self.run_id = run_id or default_run_id(pr=pr, commit=commit, clock=self._clock)
        self.pr = pr
        self.commit = commit
        self.mode = mode
        self.phases: tuple[str, ...] = tuple(phases)
        self.required_phases: tuple[str, ...] = tuple(required_phases)
        self.pid = int(pid) if pid is not None else os.getpid()
        self.phase_status: dict[str, str] = {phase: PHASE_NOT_STARTED for phase in self.phases}
        self.active_phase: str | None = None
        self.last_completed_phase: str | None = None
        self.full_pytest_exit_code: int | None = None
        self.signal_name: str | None = None
        self.setup_failure_reason: str | None = None
        self._setup_failure = False
        self._finalized = False
        self._snapshot: dict[str, Any] | None = None
        self.started_at = self._clock()
        self.last_update = self.started_at
        self.checkpoints: list[dict[str, Any]] = []

    # -- internal helpers --------------------------------------------------- #
    def _ensure_phase(self, phase: str) -> None:
        if phase not in self.phase_status:
            self.phase_status[phase] = PHASE_NOT_STARTED
            self.phases = (*self.phases, phase)

    def snapshot(self) -> dict[str, Any]:
        """Return the current classification snapshot (does not mutate state)."""
        return classify_run(
            self.phase_status,
            required_phases=self.required_phases,
            full_pytest_exit_code=self.full_pytest_exit_code,
            setup_failure=self._setup_failure,
            setup_failure_reason=self.setup_failure_reason,
            last_completed_phase=self.last_completed_phase,
            active_phase=self.active_phase,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the current heartbeat state as a plain dict."""
        if self._finalized and self._snapshot is not None:
            snapshot = self._snapshot
            status = snapshot["status"]
            classification = snapshot["classification"]
            pass_eligible = snapshot["pass_eligible"]
            rerun_required = snapshot["rerun_required"]
            failed_phase = snapshot["failed_phase"]
            reason = snapshot["reason"]
        else:
            status = STATUS_RUNNING
            classification = None
            pass_eligible = False
            rerun_required = True
            failed_phase = None
            reason = "validation run in progress"
        return {
            "schema_version": SCHEMA_VERSION,
            "mode": self.mode,
            "run_id": self.run_id,
            "pr": self.pr,
            "commit": self.commit,
            "status": status,
            "classification": classification,
            "active_phase": self.active_phase,
            "last_completed_phase": self.last_completed_phase,
            "phase_status": dict(self.phase_status),
            "required_phases": list(self.required_phases),
            "failed_phase": failed_phase,
            "full_pytest_exit_code": self.full_pytest_exit_code,
            "full_pytest_result": full_pytest_result_from_exit(self.full_pytest_exit_code),
            "pass_eligible": pass_eligible,
            "rerun_required": rerun_required,
            "reason": reason,
            "signal": self.signal_name,
            "finalized": self._finalized,
            "started_at": self.started_at,
            "last_update": self.last_update,
            "pid": self.pid,
        }

    def _write_json(self, path: Path, payload: Any) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except OSError:
            # Heartbeat writing is best-effort; never break the validation flow.
            pass

    def write(self, *, event: str | None = None, phase: str | None = None) -> None:
        """Persist the heartbeat (and optional status mirror / checkpoint log)."""
        self.last_update = self._clock()
        payload = self.to_dict()
        self._write_json(self.path, payload)
        if self.status_path is not None:
            self._write_json(self.status_path, payload)
        if event is not None:
            self.checkpoints.append(
                {
                    "event": event,
                    "phase": phase,
                    "phase_status": dict(self.phase_status),
                    "status": payload["status"],
                    "active_phase": self.active_phase,
                    "last_completed_phase": self.last_completed_phase,
                    "timestamp": self.last_update,
                }
            )
            if self.checkpoint_path is not None:
                self._write_json(
                    self.checkpoint_path,
                    {
                        "schema_version": SCHEMA_VERSION,
                        "mode": "validation_checkpoints",
                        "run_id": self.run_id,
                        "checkpoints": self.checkpoints,
                    },
                )

    # -- phase transitions -------------------------------------------------- #
    def start(self) -> ValidationHeartbeat:
        """Write the initial heartbeat at run start."""
        self.write(event="start")
        return self

    def start_phase(self, phase: str) -> ValidationHeartbeat:
        self._ensure_phase(phase)
        self.active_phase = phase
        self.phase_status[phase] = PHASE_RUNNING
        self.write(event="phase_start", phase=phase)
        return self

    def complete_phase(self, phase: str, *, status: str = PHASE_PASSED) -> ValidationHeartbeat:
        self._ensure_phase(phase)
        self.phase_status[phase] = status
        if status == PHASE_PASSED:
            self.last_completed_phase = phase
            if self.active_phase == phase:
                self.active_phase = None
        self.write(event="phase_complete", phase=phase)
        return self

    def record_full_pytest_exit(
        self, exit_code: int | None, *, phase: str = "full_pytest"
    ) -> ValidationHeartbeat:
        """Record the captured full-`pytest` exit code and its phase status."""
        self.full_pytest_exit_code = None if exit_code is None else int(exit_code)
        status = PHASE_PASSED if self.full_pytest_exit_code == 0 else PHASE_FAILED
        return self.complete_phase(phase, status=status)

    # -- terminal transitions ----------------------------------------------- #
    def finalize(
        self,
        *,
        full_pytest_exit_code: int | None = None,
        setup_failure: bool | None = None,
        setup_failure_reason: str | None = None,
    ) -> dict[str, Any]:
        if full_pytest_exit_code is not None:
            self.full_pytest_exit_code = int(full_pytest_exit_code)
        if setup_failure is not None:
            self._setup_failure = setup_failure
        if setup_failure_reason is not None:
            self.setup_failure_reason = setup_failure_reason
        self._snapshot = self.snapshot()
        self._finalized = True
        self.write(event="finalize")
        return self._snapshot

    def mark_interrupted(self, *, signal_name: str | None = None) -> dict[str, Any]:
        """Mark a catchable interruption (SIGTERM/SIGINT/KeyboardInterrupt)."""
        self.signal_name = signal_name
        if self.active_phase and self.phase_status.get(self.active_phase) == PHASE_RUNNING:
            self.phase_status[self.active_phase] = PHASE_INTERRUPTED
        return self.finalize()

    def mark_setup_failure(
        self, *, reason: str | None = None, phase: str | None = None
    ) -> dict[str, Any]:
        if phase is not None:
            self._ensure_phase(phase)
            self.phase_status[phase] = PHASE_FAILED
            if self.active_phase is None:
                self.active_phase = phase
        return self.finalize(setup_failure=True, setup_failure_reason=reason)


def load_and_classify(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Read a heartbeat JSON file and classify it.

    Useful for turning a last-written heartbeat (including one left behind by a
    SIGKILLed run) into an explicit ``incomplete`` verdict without rerunning
    anything. Missing/invalid files classify as ``incomplete`` (never a pass).
    """
    target = Path(path)
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return classify_run({}, last_completed_phase=None, active_phase=None)
    if not isinstance(data, dict):
        return classify_run({}, last_completed_phase=None, active_phase=None)
    required = data.get("required_phases") or REQUIRED_PHASES
    return classify_run(
        data.get("phase_status") if isinstance(data.get("phase_status"), dict) else {},
        required_phases=list(required),
        full_pytest_exit_code=data.get("full_pytest_exit_code"),
        last_completed_phase=data.get("last_completed_phase"),
        active_phase=data.get("active_phase"),
    )
