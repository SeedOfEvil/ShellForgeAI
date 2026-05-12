"""Stale evidence and drift guard (PR38).

ShellForgeAI is a Tier-3 triage tool. It never executes mutation. This
module adds deterministic *freshness* and *drift* checks for proposals,
actions, apply preflight bundles, and export packs so an operator can
tell at a glance whether a proposal/action/export is based on stale
evidence or whether source artifacts have changed after creation.

Guard checks are read-only. They read source files, compute checksums,
write a guard report under ``<data_dir>/guards/<source-id>/``, and call
existing internal validators. They never restart/reload/install/delete,
never mutate proposals/approvals/actions/exports, and never execute any
remediation command. ``execution_allowed`` is always ``false`` and
``execution_status`` is always ``not_executed``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GUARD_SCHEMA_VERSION = "1"

SOURCE_PROPOSAL = "proposal"
SOURCE_ACTIONS = "actions"
SOURCE_EXPORT = "export"
SOURCE_RUNBOOK = "runbook"

DECISION_FRESH = "fresh"
DECISION_STALE = "stale"
DECISION_DRIFT = "drift_detected"
DECISION_BLOCKED = "blocked"
DECISION_WARNING = "warning"

STATUS_PASSED = "passed"
STATUS_WARNING = "warning"
STATUS_FAILED = "failed"

AGE_FRESH = "fresh"
AGE_STALE = "stale"
AGE_UNKNOWN = "unknown"

HASH_MATCHED = "matched"
HASH_CHANGED = "changed"
HASH_MISSING = "missing"
HASH_UNKNOWN = "unknown"

EXECUTION_ALLOWED = False
EXECUTION_STATUS_NOT_EXECUTED = "not_executed"

DEFAULT_MAX_AGE_SECONDS = {
    SOURCE_PROPOSAL: 24 * 60 * 60,
    SOURCE_ACTIONS: 24 * 60 * 60,
    SOURCE_EXPORT: 7 * 24 * 60 * 60,
    SOURCE_RUNBOOK: 24 * 60 * 60,
}

SAFETY_NOTE = "ShellForgeAI ran a stale/drift guard check; no commands were executed."


# ---------------------------------------------------------------------------
# Data shapes


@dataclass
class GuardCheck:
    name: str
    status: str  # passed | warning | failed
    message: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "message": self.message}


@dataclass
class GuardAge:
    created_at: str = ""
    age_seconds: int = 0
    max_age_seconds: int = 0
    status: str = AGE_UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "created_at": self.created_at,
            "age_seconds": self.age_seconds,
            "max_age_seconds": self.max_age_seconds,
            "status": self.status,
        }


@dataclass
class GuardDrift:
    source_hash_status: str = HASH_UNKNOWN
    changed_files: list[str] = field(default_factory=list)
    missing_files: list[str] = field(default_factory=list)
    checked_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_hash_status": self.source_hash_status,
            "changed_files": list(self.changed_files),
            "missing_files": list(self.missing_files),
            "checked_files": list(self.checked_files),
        }


@dataclass
class GuardReport:
    schema_version: str = GUARD_SCHEMA_VERSION
    created_at: str = ""
    source_type: str = ""
    source_id: str = ""
    source_path: str = ""
    decision: str = DECISION_FRESH
    execution_allowed: bool = EXECUTION_ALLOWED
    execution_status: str = EXECUTION_STATUS_NOT_EXECUTED
    checks: list[GuardCheck] = field(default_factory=list)
    age: GuardAge = field(default_factory=GuardAge)
    drift: GuardDrift = field(default_factory=GuardDrift)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "source_path": self.source_path,
            "decision": self.decision,
            "execution_allowed": False,
            "execution_status": EXECUTION_STATUS_NOT_EXECUTED,
            "checks": [c.to_dict() for c in self.checks],
            "age": self.age.to_dict(),
            "drift": self.drift.to_dict(),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "safety_note": SAFETY_NOTE,
        }

    def add_check(self, name: str, status: str, message: str = "") -> None:
        self.checks.append(GuardCheck(name=name, status=status, message=message))


# ---------------------------------------------------------------------------
# Helpers


def guards_root(data_dir: Path) -> Path:
    return Path(data_dir) / "guards"


def guard_dir_for(data_dir: Path, source_id: str) -> Path:
    safe = "".join(c if (c.isalnum() or c in "._-") else "_" for c in (source_id or "unknown"))
    return guards_root(Path(data_dir)) / (safe or "unknown")


def sha256_of_path(path: Path) -> str | None:
    """Return ``sha256:<hex>`` for an existing file, else ``None``."""
    try:
        p = Path(path)
        if not p.exists() or not p.is_file():
            return None
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(64 * 1024), b""):
                h.update(chunk)
        return f"sha256:{h.hexdigest()}"
    except OSError:
        return None


def parse_created_at(text: str) -> datetime | None:
    if not text:
        return None
    raw = str(text).strip()
    if not raw:
        return None
    # datetime.fromisoformat handles "+00:00" suffixes; Python 3.11+ also
    # parses trailing "Z" but we normalize anyway for older runtimes.
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def compute_age_seconds(created_at: str, *, now: datetime | None = None) -> int | None:
    dt = parse_created_at(created_at)
    if dt is None:
        return None
    ref = now if now is not None else datetime.now(timezone.utc)
    delta = ref - dt
    return int(delta.total_seconds())


def evaluate_age(
    created_at: str,
    *,
    source_type: str,
    max_age_seconds: int | None = None,
    now: datetime | None = None,
) -> GuardAge:
    """Compute :class:`GuardAge` from a created_at ISO string."""
    max_age = (
        max_age_seconds
        if max_age_seconds is not None
        else DEFAULT_MAX_AGE_SECONDS.get(source_type, DEFAULT_MAX_AGE_SECONDS[SOURCE_PROPOSAL])
    )
    age_seconds = compute_age_seconds(created_at, now=now)
    if age_seconds is None:
        return GuardAge(
            created_at=created_at or "",
            age_seconds=0,
            max_age_seconds=int(max_age),
            status=AGE_UNKNOWN,
        )
    status = AGE_STALE if (max_age <= 0 or age_seconds > max_age) else AGE_FRESH
    return GuardAge(
        created_at=created_at or "",
        age_seconds=max(0, age_seconds),
        max_age_seconds=int(max_age),
        status=status,
    )


def max_age_from_hours(
    hours: float | None,
    *,
    source_type: str,
) -> int:
    """Convert ``--max-age-hours`` into seconds.

    Returns the source-type default when ``hours`` is ``None``. A
    non-positive value is treated as "any age is stale" (max_age=0)
    so operators can deliberately exercise the stale path; this
    differs from ``None`` which uses the default.
    """
    if hours is None:
        return DEFAULT_MAX_AGE_SECONDS.get(source_type, DEFAULT_MAX_AGE_SECONDS[SOURCE_PROPOSAL])
    if hours <= 0:
        return 0
    seconds = float(hours) * 3600.0
    # Round to nearest second; very small values still produce a strict
    # threshold rather than collapsing to default behavior.
    return max(0, int(round(seconds)))


# ---------------------------------------------------------------------------
# Source hash helpers (used by proposal/actions/export writers and the guard)


def compute_source_hashes_for_paths(paths: dict[str, str | Path]) -> dict[str, str]:
    """Return ``{name: 'sha256:<hex>'}`` for each readable file path."""
    out: dict[str, str] = {}
    for name, raw in paths.items():
        if not raw:
            continue
        digest = sha256_of_path(Path(raw))
        if digest is not None:
            out[name] = digest
    return out


def compute_proposal_source_hashes(
    *,
    evidence_path: str | Path | None,
    runbook_path: str | Path | None,
    summary_path: str | Path | None,
) -> dict[str, str]:
    """Compute the standard proposal source hash set."""
    paths = {
        "evidence.json": evidence_path or "",
        "runbook.json": runbook_path or "",
        "summary.md": summary_path or "",
    }
    return compute_source_hashes_for_paths(paths)


def compute_actions_source_hashes(
    *,
    proposal_path: str | Path | None,
    runbook_path: str | Path | None,
) -> dict[str, str]:
    paths = {
        "proposal.json": proposal_path or "",
        "runbook.json": runbook_path or "",
    }
    return compute_source_hashes_for_paths(paths)


# ---------------------------------------------------------------------------
# Drift evaluation


def evaluate_drift(
    stored_hashes: dict[str, str] | None,
    source_paths: dict[str, str | Path],
) -> GuardDrift:
    """Compare stored source hashes against the current files on disk.

    ``stored_hashes`` map ``name -> "sha256:<hex>"`` as written into the
    proposal/actions/export metadata. ``source_paths`` map ``name -> path``
    for the current location of each artifact. When ``stored_hashes`` is
    empty, the drift status is ``unknown`` (not failed) so older artifacts
    without recorded hashes still validate cleanly.
    """
    drift = GuardDrift()
    if not stored_hashes:
        drift.source_hash_status = HASH_UNKNOWN
        return drift

    overall = HASH_MATCHED
    for name, expected in stored_hashes.items():
        path_raw = source_paths.get(name, "")
        if not path_raw:
            drift.missing_files.append(name)
            overall = HASH_MISSING if overall != HASH_CHANGED else overall
            continue
        path = Path(path_raw)
        drift.checked_files.append(name)
        if not path.exists() or not path.is_file():
            drift.missing_files.append(name)
            overall = HASH_MISSING if overall != HASH_CHANGED else overall
            continue
        actual = sha256_of_path(path)
        if actual is None:
            drift.missing_files.append(name)
            overall = HASH_MISSING if overall != HASH_CHANGED else overall
            continue
        if str(actual).strip() != str(expected).strip():
            drift.changed_files.append(name)
            overall = HASH_CHANGED
    drift.source_hash_status = overall
    return drift


# ---------------------------------------------------------------------------
# Render / persist


def _safety_lines() -> list[str]:
    return [
        f"- {SAFETY_NOTE}",
        "- ShellForgeAI did not execute any command.",
        "- apply remains validation-only.",
    ]


def render_guard_md(report: GuardReport) -> str:
    lines: list[str] = []
    lines.append("# Stale/drift guard report")
    lines.append("")
    lines.append(f"- Source type: {report.source_type}")
    lines.append(f"- Source id: {report.source_id}")
    if report.source_path:
        lines.append(f"- Source path: {report.source_path}")
    lines.append(f"- Created at: {report.created_at}")
    lines.append(f"- Decision: {report.decision}")
    lines.append("- Execution allowed: false")
    lines.append("- Execution status: not_executed")
    lines.append("")
    lines.append("## Age")
    lines.append("")
    lines.append(f"- created_at: {report.age.created_at or '(unknown)'}")
    lines.append(f"- age_seconds: {report.age.age_seconds}")
    lines.append(f"- max_age_seconds: {report.age.max_age_seconds}")
    lines.append(f"- status: {report.age.status}")
    lines.append("")
    lines.append("## Drift")
    lines.append("")
    lines.append(f"- source_hash_status: {report.drift.source_hash_status}")
    if report.drift.checked_files:
        lines.append("- checked files:")
        for name in report.drift.checked_files:
            lines.append(f"  - {name}")
    if report.drift.changed_files:
        lines.append("- changed files:")
        for name in report.drift.changed_files:
            lines.append(f"  - {name}")
    if report.drift.missing_files:
        lines.append("- missing files:")
        for name in report.drift.missing_files:
            lines.append(f"  - {name}")
    lines.append("")
    lines.append("## Checks")
    lines.append("")
    if report.checks:
        for c in report.checks:
            lines.append(f"- [{c.status}] {c.name}: {c.message}")
    else:
        lines.append("- (no checks recorded)")
    lines.append("")
    if report.warnings:
        lines.append("## Warnings")
        lines.append("")
        for w in report.warnings:
            lines.append(f"- {w}")
        lines.append("")
    if report.errors:
        lines.append("## Errors")
        lines.append("")
        for e in report.errors:
            lines.append(f"- {e}")
        lines.append("")
    lines.append("## Safety")
    lines.append("")
    lines.extend(_safety_lines())
    return "\n".join(lines) + "\n"


@dataclass
class GuardWriteResult:
    report: GuardReport
    json_path: Path
    md_path: Path


def write_guard_report(
    report: GuardReport,
    *,
    data_dir: Path,
) -> GuardWriteResult:
    """Write ``guard-report.json`` and ``guard-report.md`` under data_dir."""
    out_dir = guard_dir_for(Path(data_dir), report.source_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "guard-report.json"
    md_path = out_dir / "guard-report.md"
    json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    md_path.write_text(render_guard_md(report), encoding="utf-8")
    return GuardWriteResult(report=report, json_path=json_path, md_path=md_path)


# ---------------------------------------------------------------------------
# Decision derivation


def _resolve_decision(report: GuardReport) -> str:
    """Compute the top-level decision from checks/age/drift state.

    Drift takes precedence over a generic ``blocked`` because it is the
    more specific actionable signal: source artifacts changed or were
    removed after the proposal/action/export was created.
    """
    if report.drift.source_hash_status in (HASH_CHANGED, HASH_MISSING):
        return DECISION_DRIFT
    if report.errors:
        return DECISION_BLOCKED
    if any(c.status == STATUS_FAILED for c in report.checks):
        return DECISION_BLOCKED
    if report.age.status == AGE_STALE:
        return DECISION_STALE
    if report.warnings or any(c.status == STATUS_WARNING for c in report.checks):
        return DECISION_WARNING
    return DECISION_FRESH


# ---------------------------------------------------------------------------
# Proposal guard


def _proposal_source_paths(payload: dict[str, Any]) -> dict[str, str]:
    src = payload.get("source") or {}
    return {
        "evidence.json": str(src.get("evidence") or ""),
        "runbook.json": str(src.get("runbook") or ""),
        "summary.md": str(src.get("summary") or ""),
    }


def check_proposal_payload(
    payload: dict[str, Any],
    *,
    source_path: str | Path = "",
    max_age_seconds: int | None = None,
    now: datetime | None = None,
) -> GuardReport:
    """Run guard checks against a proposal JSON payload (already parsed)."""
    from shellforgeai.core.approvals import validate_proposal_payload

    report = GuardReport(
        created_at=datetime.now(timezone.utc).isoformat(),
        source_type=SOURCE_PROPOSAL,
        source_id=str(payload.get("proposal_id") or "unknown"),
        source_path=str(source_path or ""),
    )

    schema_errors, schema_warnings = validate_proposal_payload(payload)
    if schema_errors:
        for err in schema_errors:
            report.errors.append(err)
        report.add_check("proposal_schema", STATUS_FAILED, "; ".join(schema_errors))
    else:
        report.add_check("proposal_schema", STATUS_PASSED, "proposal schema valid")
    for w in schema_warnings:
        report.warnings.append(w)

    execution = payload.get("execution") or {}
    if execution.get("allowed", False) is not False:
        report.errors.append("proposal.execution.allowed must be false")
        report.add_check(
            "execution_allowed_false", STATUS_FAILED, "proposal.execution.allowed must be false"
        )
    else:
        report.add_check(
            "execution_allowed_false", STATUS_PASSED, "proposal.execution.allowed=false"
        )
    if execution.get("status", EXECUTION_STATUS_NOT_EXECUTED) != EXECUTION_STATUS_NOT_EXECUTED:
        report.errors.append(f"proposal.execution.status must be {EXECUTION_STATUS_NOT_EXECUTED}")
        report.add_check(
            "execution_status_not_executed",
            STATUS_FAILED,
            f"proposal.execution.status must be {EXECUTION_STATUS_NOT_EXECUTED}",
        )
    else:
        report.add_check(
            "execution_status_not_executed",
            STATUS_PASSED,
            "proposal.execution.status=not_executed",
        )

    fingerprint = payload.get("fingerprint") or {}
    if isinstance(fingerprint, dict) and fingerprint.get("value"):
        report.add_check(
            "fingerprint_present",
            STATUS_PASSED,
            f"fingerprint.value={str(fingerprint.get('value'))[:8]}...",
        )
    else:
        report.add_check("fingerprint_present", STATUS_WARNING, "proposal has no fingerprint")
        report.warnings.append("proposal fingerprint missing")

    # Source paths
    source_paths = _proposal_source_paths(payload)
    for name, raw in source_paths.items():
        if not raw:
            continue
        if Path(raw).exists():
            report.add_check(f"source_exists:{name}", STATUS_PASSED, f"present: {raw}")
        else:
            report.add_check(
                f"source_exists:{name}",
                STATUS_WARNING,
                f"source path not found on filesystem: {raw}",
            )
            report.warnings.append(f"source {name} not on disk: {raw}")

    # Age
    report.age = evaluate_age(
        str(payload.get("created_at") or ""),
        source_type=SOURCE_PROPOSAL,
        max_age_seconds=max_age_seconds,
        now=now,
    )
    if report.age.status == AGE_UNKNOWN:
        report.add_check("age", STATUS_WARNING, "created_at missing or unparseable; age unknown")
        report.warnings.append("proposal created_at unknown; age unknown")
    elif report.age.status == AGE_STALE:
        report.add_check(
            "age",
            STATUS_WARNING,
            f"proposal age {report.age.age_seconds}s exceeds max {report.age.max_age_seconds}s",
        )
    else:
        report.add_check(
            "age",
            STATUS_PASSED,
            f"proposal age {report.age.age_seconds}s within max {report.age.max_age_seconds}s",
        )

    # Drift via stored source hashes (optional)
    stored = payload.get("source_hashes") or {}
    if isinstance(stored, dict) and stored:
        report.drift = evaluate_drift(
            {k: str(v) for k, v in stored.items()},
            source_paths,
        )
        if report.drift.source_hash_status == HASH_CHANGED:
            report.add_check(
                "source_hash",
                STATUS_FAILED,
                f"source hash changed: {', '.join(report.drift.changed_files)}",
            )
            report.errors.append(
                f"proposal source hash changed: {', '.join(report.drift.changed_files)}"
            )
        elif report.drift.source_hash_status == HASH_MISSING:
            report.add_check(
                "source_hash",
                STATUS_FAILED,
                f"source artifacts missing: {', '.join(report.drift.missing_files)}",
            )
            report.errors.append(
                f"proposal source artifacts missing: {', '.join(report.drift.missing_files)}"
            )
        else:
            report.add_check(
                "source_hash",
                STATUS_PASSED,
                f"stored hashes match for {len(stored)} file(s)",
            )
    else:
        report.drift = GuardDrift(source_hash_status=HASH_UNKNOWN)
        report.add_check(
            "source_hash",
            STATUS_WARNING,
            "no stored source hashes; drift unknown",
        )
        report.warnings.append("proposal has no stored source_hashes; drift unknown")

    # Surface proposal status as informational check
    status = str(payload.get("status") or "")
    if status:
        report.add_check("proposal_status", STATUS_PASSED, f"status={status}")

    report.decision = _resolve_decision(report)
    return report


def check_proposal_file(
    path: Path,
    *,
    max_age_seconds: int | None = None,
    now: datetime | None = None,
) -> GuardReport:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return _missing_report(SOURCE_PROPOSAL, str(p), f"proposal file not found: {p}")
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return _malformed_report(SOURCE_PROPOSAL, str(p), f"malformed proposal json: {exc}")
    if not isinstance(payload, dict):
        return _malformed_report(SOURCE_PROPOSAL, str(p), "proposal json must be an object")
    return check_proposal_payload(
        payload, source_path=str(p), max_age_seconds=max_age_seconds, now=now
    )


# ---------------------------------------------------------------------------
# Actions guard


def check_actions_payload(
    payload: dict[str, Any],
    *,
    source_path: str | Path = "",
    data_dir: Path | None = None,
    max_age_seconds: int | None = None,
    now: datetime | None = None,
) -> GuardReport:
    from shellforgeai.core.actions import validate_actions_payload
    from shellforgeai.core.approvals import find_proposal_path, load_proposal_from_path

    proposal_id = str(payload.get("proposal_id") or "unknown")
    report = GuardReport(
        created_at=datetime.now(timezone.utc).isoformat(),
        source_type=SOURCE_ACTIONS,
        source_id=proposal_id,
        source_path=str(source_path or ""),
    )

    result = validate_actions_payload(payload)
    if not result.ok:
        for err in result.errors:
            report.errors.append(err)
        report.add_check("actions_schema", STATUS_FAILED, "; ".join(result.errors)[:300])
    else:
        report.add_check(
            "actions_schema",
            STATUS_PASSED,
            f"actions schema valid; total={result.info.get('total_actions', 0)}",
        )

    if payload.get("execution_allowed") is True:
        report.errors.append("actions.execution_allowed must be false")
        report.add_check(
            "execution_allowed_false", STATUS_FAILED, "actions.execution_allowed must be false"
        )
    else:
        report.add_check(
            "execution_allowed_false", STATUS_PASSED, "actions.execution_allowed=false"
        )
    if payload.get("execution_status") not in (None, "", EXECUTION_STATUS_NOT_EXECUTED):
        report.errors.append("actions.execution_status must be not_executed")
        report.add_check(
            "execution_status_not_executed",
            STATUS_FAILED,
            "actions.execution_status must be not_executed",
        )
    else:
        report.add_check(
            "execution_status_not_executed",
            STATUS_PASSED,
            "actions.execution_status=not_executed",
        )

    # Compare proposal fingerprint if available
    proposal_fp = str(payload.get("proposal_fingerprint") or "")
    proposal_obj = None
    proposal_path: Path | None = None
    if data_dir is not None and proposal_id and proposal_id != "unknown":
        proposal_path, _status = find_proposal_path(Path(data_dir), proposal_id)
        if proposal_path is not None:
            try:
                proposal_obj = load_proposal_from_path(proposal_path)
            except (OSError, ValueError):
                proposal_obj = None
    if proposal_path is None:
        report.add_check(
            "source_proposal",
            STATUS_WARNING,
            f"source proposal not found: {proposal_id}",
        )
        report.warnings.append(f"source proposal not found: {proposal_id}")
    elif proposal_obj is not None:
        report.add_check(
            "source_proposal",
            STATUS_PASSED,
            f"source proposal found: {proposal_path}",
        )
        actual_fp = str((proposal_obj.fingerprint or {}).get("value") or "")
        if proposal_fp and actual_fp and proposal_fp != actual_fp:
            report.errors.append(
                f"proposal fingerprint mismatch: actions={proposal_fp[:8]}.. "
                f"proposal={actual_fp[:8]}.."
            )
            report.add_check(
                "proposal_fingerprint",
                STATUS_FAILED,
                "actions.proposal_fingerprint does not match source proposal",
            )
        elif proposal_fp and actual_fp:
            report.add_check("proposal_fingerprint", STATUS_PASSED, "proposal_fingerprint matches")
        elif not proposal_fp:
            report.add_check(
                "proposal_fingerprint",
                STATUS_WARNING,
                "actions payload has no proposal_fingerprint",
            )
            report.warnings.append("actions payload missing proposal_fingerprint")

    # Age
    report.age = evaluate_age(
        str(payload.get("created_at") or ""),
        source_type=SOURCE_ACTIONS,
        max_age_seconds=max_age_seconds,
        now=now,
    )
    if report.age.status == AGE_UNKNOWN:
        report.add_check("age", STATUS_WARNING, "actions created_at unknown")
        report.warnings.append("actions created_at unknown")
    elif report.age.status == AGE_STALE:
        report.add_check(
            "age",
            STATUS_WARNING,
            f"actions age {report.age.age_seconds}s exceeds max {report.age.max_age_seconds}s",
        )
    else:
        report.add_check(
            "age",
            STATUS_PASSED,
            f"actions age {report.age.age_seconds}s within max {report.age.max_age_seconds}s",
        )

    # Drift via stored source hashes (optional)
    stored = payload.get("source_hashes") or {}
    source_paths = {
        "proposal.json": str(proposal_path or ""),
        "runbook.json": str(payload.get("source_runbook") or ""),
    }
    if isinstance(stored, dict) and stored:
        report.drift = evaluate_drift({k: str(v) for k, v in stored.items()}, source_paths)
        if report.drift.source_hash_status == HASH_CHANGED:
            report.errors.append(
                f"actions source hash changed: {', '.join(report.drift.changed_files)}"
            )
            report.add_check(
                "source_hash",
                STATUS_FAILED,
                f"source hash changed: {', '.join(report.drift.changed_files)}",
            )
        elif report.drift.source_hash_status == HASH_MISSING:
            report.errors.append(
                f"actions source artifacts missing: {', '.join(report.drift.missing_files)}"
            )
            report.add_check(
                "source_hash",
                STATUS_FAILED,
                f"source artifacts missing: {', '.join(report.drift.missing_files)}",
            )
        else:
            report.add_check(
                "source_hash", STATUS_PASSED, f"stored hashes match for {len(stored)} file(s)"
            )
    else:
        report.drift = GuardDrift(source_hash_status=HASH_UNKNOWN)
        report.add_check("source_hash", STATUS_WARNING, "no stored source hashes; drift unknown")
        report.warnings.append("actions has no stored source_hashes; drift unknown")

    report.decision = _resolve_decision(report)
    return report


def check_actions_file(
    path: Path,
    *,
    data_dir: Path | None = None,
    max_age_seconds: int | None = None,
    now: datetime | None = None,
) -> GuardReport:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return _missing_report(SOURCE_ACTIONS, str(p), f"actions.json not found: {p}")
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return _malformed_report(SOURCE_ACTIONS, str(p), f"malformed actions json: {exc}")
    if not isinstance(payload, dict):
        return _malformed_report(SOURCE_ACTIONS, str(p), "actions json must be an object")
    return check_actions_payload(
        payload,
        source_path=str(p),
        data_dir=data_dir,
        max_age_seconds=max_age_seconds,
        now=now,
    )


# ---------------------------------------------------------------------------
# Export guard


def check_export_dir(
    export_dir: Path,
    *,
    max_age_seconds: int | None = None,
    now: datetime | None = None,
) -> GuardReport:
    from shellforgeai.core.export_pack import validate_export

    d = Path(export_dir)
    manifest_path = d / "export-manifest.json"
    if not d.exists() or not d.is_dir():
        return _missing_report(SOURCE_EXPORT, str(d), f"export dir not found: {d}")
    if not manifest_path.exists():
        return _missing_report(SOURCE_EXPORT, str(d), f"export-manifest.json not found in: {d}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return _malformed_report(SOURCE_EXPORT, str(d), f"malformed manifest: {exc}")
    if not isinstance(manifest, dict):
        return _malformed_report(SOURCE_EXPORT, str(d), "manifest is not a JSON object")

    export_id = str(manifest.get("export_id") or d.name or "unknown")
    report = GuardReport(
        created_at=datetime.now(timezone.utc).isoformat(),
        source_type=SOURCE_EXPORT,
        source_id=export_id,
        source_path=str(d),
    )

    result = validate_export(d)
    if not result.ok:
        for err in result.errors:
            report.errors.append(err)
        report.add_check("export_validate", STATUS_FAILED, "; ".join(result.errors)[:300])
    else:
        report.add_check(
            "export_validate",
            STATUS_PASSED,
            f"export valid; files={result.info.get('file_count', 0)}",
        )

    if manifest.get("execution_allowed") is True:
        report.errors.append("export manifest execution_allowed=true")
        report.add_check(
            "execution_allowed_false",
            STATUS_FAILED,
            "export manifest claims execution_allowed=true",
        )
    else:
        report.add_check(
            "execution_allowed_false", STATUS_PASSED, "export manifest execution_allowed=false"
        )
    if manifest.get("execution_status") not in (None, "", EXECUTION_STATUS_NOT_EXECUTED):
        report.errors.append("export manifest execution_status must be not_executed")
        report.add_check(
            "execution_status_not_executed",
            STATUS_FAILED,
            "export manifest execution_status must be not_executed",
        )
    else:
        report.add_check(
            "execution_status_not_executed",
            STATUS_PASSED,
            "export manifest execution_status=not_executed",
        )

    preflight_path = d / "apply-preflight.json"
    if preflight_path.exists():
        try:
            preflight = json.loads(preflight_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            report.errors.append(f"malformed apply-preflight.json: {exc}")
            report.add_check(
                "preflight_execution", STATUS_FAILED, f"malformed apply-preflight.json: {exc}"
            )
        else:
            if preflight.get("execution_allowed") is True:
                report.errors.append("export apply-preflight.json execution_allowed=true")
                report.add_check(
                    "preflight_execution",
                    STATUS_FAILED,
                    "apply-preflight.json claims execution_allowed=true",
                )
            elif preflight.get("execution_status") not in (
                None,
                "",
                EXECUTION_STATUS_NOT_EXECUTED,
            ):
                report.errors.append("export apply-preflight.json execution_status invalid")
                report.add_check(
                    "preflight_execution",
                    STATUS_FAILED,
                    "apply-preflight.json execution_status not 'not_executed'",
                )
            else:
                report.add_check(
                    "preflight_execution",
                    STATUS_PASSED,
                    "apply-preflight.json safe (execution_allowed=false)",
                )

    if manifest.get("redaction_applied"):
        report_name = str(manifest.get("redaction_report") or "redaction-report.json")
        if not (d / report_name).exists():
            report.errors.append("redacted export missing redaction-report.json")
            report.add_check(
                "redaction_consistent",
                STATUS_FAILED,
                "redacted export missing redaction-report.json",
            )
        else:
            report.add_check(
                "redaction_consistent",
                STATUS_PASSED,
                "redaction-report.json present",
            )

    # Age
    report.age = evaluate_age(
        str(manifest.get("created_at") or ""),
        source_type=SOURCE_EXPORT,
        max_age_seconds=max_age_seconds,
        now=now,
    )
    if report.age.status == AGE_UNKNOWN:
        report.add_check("age", STATUS_WARNING, "export created_at unknown")
        report.warnings.append("export created_at unknown")
    elif report.age.status == AGE_STALE:
        report.add_check(
            "age",
            STATUS_WARNING,
            f"export age {report.age.age_seconds}s exceeds max {report.age.max_age_seconds}s",
        )
    else:
        report.add_check(
            "age",
            STATUS_PASSED,
            f"export age {report.age.age_seconds}s within max {report.age.max_age_seconds}s",
        )

    # Drift: validate-export already verifies file checksums match the manifest.
    # If validate-export passed, mark drift as matched; otherwise unknown.
    if result.ok:
        report.drift = GuardDrift(
            source_hash_status=HASH_MATCHED,
            checked_files=list(manifest.get("included_files") or []),
        )
        report.add_check(
            "source_hash",
            STATUS_PASSED,
            "export checksums match manifest",
        )
    else:
        report.drift = GuardDrift(source_hash_status=HASH_UNKNOWN)

    report.decision = _resolve_decision(report)
    return report


# ---------------------------------------------------------------------------
# Failure helpers


def _missing_report(source_type: str, source_path: str, message: str) -> GuardReport:
    report = GuardReport(
        created_at=datetime.now(timezone.utc).isoformat(),
        source_type=source_type,
        source_id="unknown",
        source_path=source_path,
        decision=DECISION_BLOCKED,
    )
    report.errors.append(message)
    report.add_check("source_exists", STATUS_FAILED, message)
    return report


def _malformed_report(source_type: str, source_path: str, message: str) -> GuardReport:
    report = GuardReport(
        created_at=datetime.now(timezone.utc).isoformat(),
        source_type=source_type,
        source_id="unknown",
        source_path=source_path,
        decision=DECISION_BLOCKED,
    )
    report.errors.append(message)
    report.add_check("source_parses", STATUS_FAILED, message)
    return report


# ---------------------------------------------------------------------------
# Loading helpers


def load_guard_report(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    p = Path(path)
    if p.is_dir():
        candidate = p / "guard-report.json"
        if candidate.exists():
            p = candidate
    if not p.exists() or not p.is_file():
        return None, f"guard report not found: {p}"
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"malformed guard report: {exc}"
    if not isinstance(payload, dict):
        return None, "guard report is not a JSON object"
    return payload, None


# ---------------------------------------------------------------------------
# Ask intent matching


_GUARD_INTENT_TOKENS = (
    "is this proposal stale",
    "is the proposal stale",
    "is the approved proposal still fresh",
    "is the approved proposal stale",
    "check if approved proposal is still fresh",
    "check if the approved proposal is still fresh",
    "check the approved proposal is still fresh",
    "check if the proposal is stale",
    "check if the proposal is fresh",
    "check drift before apply",
    "check drift before applying",
    "check for drift before apply",
    "is the action plan safe to use",
    "is the actions plan safe to use",
    "is the action plan still safe",
    "verify this export pack is still valid",
    "verify the export pack is still valid",
    "is this export still valid",
    "is the export still valid",
    "is the export pack still valid",
    "check stale evidence",
    "check the freshness",
    "check freshness",
    "check stale proposal",
    "check stale actions",
    "check stale export",
    "run a drift check",
    "drift check",
    "stale check",
    "guard check",
)

_GUARD_RUN_ANYWAY_TOKENS = (
    "run it anyway",
    "apply it anyway",
    "apply anyway",
    "execute anyway",
    "do it anyway",
    "force apply",
    "force run",
    "ignore stale",
    "ignore drift",
    "bypass guard",
)


@dataclass(frozen=True)
class GuardAskIntent:
    matched: bool
    check_proposal: bool = False
    check_actions: bool = False
    check_export: bool = False
    check_drift: bool = False
    run_anyway: bool = False


def is_guard_ask_intent(text: str) -> GuardAskIntent:
    raw = (text or "").lower()
    matched = any(tok in raw for tok in _GUARD_INTENT_TOKENS)
    run_anyway = any(tok in raw for tok in _GUARD_RUN_ANYWAY_TOKENS)
    if not (matched or run_anyway):
        return GuardAskIntent(matched=False)
    check_actions = "action" in raw and ("safe" in raw or "stale" in raw or "fresh" in raw)
    check_export = "export" in raw and ("valid" in raw or "stale" in raw or "fresh" in raw)
    check_drift = "drift" in raw
    check_proposal = matched and not (check_actions or check_export)
    return GuardAskIntent(
        matched=matched or run_anyway,
        check_proposal=bool(check_proposal),
        check_actions=bool(check_actions),
        check_export=bool(check_export),
        check_drift=bool(check_drift),
        run_anyway=bool(run_anyway),
    )


__all__ = [
    "AGE_FRESH",
    "AGE_STALE",
    "AGE_UNKNOWN",
    "DECISION_BLOCKED",
    "DECISION_DRIFT",
    "DECISION_FRESH",
    "DECISION_STALE",
    "DECISION_WARNING",
    "DEFAULT_MAX_AGE_SECONDS",
    "GUARD_SCHEMA_VERSION",
    "GuardAge",
    "GuardAskIntent",
    "GuardCheck",
    "GuardDrift",
    "GuardReport",
    "GuardWriteResult",
    "HASH_CHANGED",
    "HASH_MATCHED",
    "HASH_MISSING",
    "HASH_UNKNOWN",
    "SOURCE_ACTIONS",
    "SOURCE_EXPORT",
    "SOURCE_PROPOSAL",
    "SOURCE_RUNBOOK",
    "STATUS_FAILED",
    "STATUS_PASSED",
    "STATUS_WARNING",
    "check_actions_file",
    "check_actions_payload",
    "check_export_dir",
    "check_proposal_file",
    "check_proposal_payload",
    "compute_actions_source_hashes",
    "compute_proposal_source_hashes",
    "compute_source_hashes_for_paths",
    "evaluate_age",
    "evaluate_drift",
    "guard_dir_for",
    "guards_root",
    "is_guard_ask_intent",
    "load_guard_report",
    "max_age_from_hours",
    "render_guard_md",
    "sha256_of_path",
    "write_guard_report",
]
