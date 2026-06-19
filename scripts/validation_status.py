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
``pass_eligible=true`` on conflicting evidence. The Docker01 finalizer status
packet is the exception for a completed fallback attempt: when it records a
terminal pass/fail for the exact run, it supersedes earlier host setup evidence
from the same run directory while preserving that earlier setup failure as a
warning/process note.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HELPER_DIR = Path(__file__).resolve().parent

# Ensure the sibling validation_heartbeat helper is importable whether this file
# is run as a script or imported by tests via importlib.
if str(HELPER_DIR) not in sys.path:
    sys.path.insert(0, str(HELPER_DIR))

import docker01_validation_evidence as dve  # noqa: E402
import validation_heartbeat as vh  # noqa: E402

SCHEMA_VERSION = 1
MODE = "validation_evidence_status"

# Overall viewer status values.
STATUS_PASSED = "passed"
STATUS_FAILED = "failed"
STATUS_INCOMPLETE = "incomplete"
STATUS_UNKNOWN = "unknown"
STATUS_NOT_FOUND = "not_found"

# Classification values surfaced by the viewer.
CLASS_PASSED = "passed"
CLASS_TEST_FAILURE = "test_failure"
CLASS_SETUP_FAILURE = "setup_failure"
CLASS_INTERRUPTED = "interrupted_or_incomplete"
CLASS_NO_EVIDENCE = "no_evidence"
CLASS_UNKNOWN = "unknown"
CLASS_NOT_FOUND = "not_found"

# Required phases shown in the human/JSON output, in display order.
REQUIRED_PHASES: tuple[str, ...] = vh.REQUIRED_PHASES

# Environment overrides (primarily for tests) pointing at directories of runs.
# Each maps an injected root to a deterministic candidate ``kind`` so tests can
# exercise the run-dir / persisted-manifest / legacy priority without writing to
# the real ShellForgeAI-owned locations.
RUNS_DIR_ENV = "SFAI_VALIDATION_RUNS_DIR"  # -> run_dir candidates
PERSISTED_DIR_ENV = "SFAI_VALIDATION_PERSISTED_DIR"  # -> persisted manifest
LEGACY_DIR_ENV = "SFAI_VALIDATION_LEGACY_DIR"  # -> legacy manifest

# Known, ShellForgeAI-owned validation artifact roots scanned by ``--latest``.
# Only these directories are scanned; no arbitrary filesystem roots. They are
# module-level so tests can redirect them away from the real host filesystem.
#
# Priority intent (most preferred first): recent PR-specific run directories in
# the temp dir, then mainline temp runs, then persisted validation-runs
# manifests, then (only with ``--include-legacy``) an older persisted layout.
TMP_ROOT = Path(tempfile.gettempdir())
MAINLINE_TMP_ROOT = Path("/tmp/shellforgeai-validation-runs")
PERSISTED_ROOT = Path("/srv/data/shellforgeai/validation-runs")
LEGACY_ROOT = Path("/data/validation-runs")

# Bounded glob for PR-specific temp run directories. Only entries matching this
# ShellForgeAI naming convention are considered; the temp dir is never crawled.
TMP_PR_RUN_GLOB = "sfai-pr*-validation-*"
TMP_PR_LOG_GLOB = "sfai-pr*-validation-*.log"

# Back-compat list used by the legacy ``discover_latest`` helper.
DEFAULT_SEARCH_DIRS: tuple[str, ...] = (
    "/tmp/shellforgeai-validation-runs",
    "/srv/data/shellforgeai/validation-runs",
    "/data/validation-runs",
)

# Candidate kinds for ``--latest`` discovery.
KIND_RUN_DIR = "run_dir"
KIND_MANIFEST = "manifest"
KIND_LEGACY_MANIFEST = "legacy_manifest"

# Parses a ShellForgeAI run-directory name of the form
# ``sfai-pr<PR>-<sha>-<suffix>-<stamp>`` (see sfai_docker01_pr_lane.py).
_RUN_NAME_RE = re.compile(r"^sfai-pr(?P<pr>[^-]+)-(?P<sha>[^-]+)-(?P<rest>.+)$")

# Filename suffixes used to group flat (non-subdirectory) run artifacts and to
# discover evidence files inside a run directory.
_EVIDENCE_GLOBS = {
    "manifest": ("manifest.json", "*-manifest.json", "*manifest*.json"),
    "heartbeat": ("validation-heartbeat.json", "*heartbeat*.json"),
    "status": ("validation-status.json", "*-status.json", "*status*.json"),
    "summary": (
        "validation-summary.md",
        "validation-summary.txt",
        "*-summary.md",
        "*summary*.md",
        "*summary*.txt",
    ),
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

# Lane letters for the explicit QA marker (mirrors scripts/validate_pr.py so the
# viewer can label targeted-only Lane B runs without re-deriving lane policy).
LANE_LETTER = {"fast": "A", "targeted_runtime": "B", "full": "C"}

SAFETY_BLOCK = {
    "read_only": True,
    "mutation_performed": False,
    "validation_executed": False,
    "pytest_executed": False,
    "ruff_executed": False,
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
    "artifact_repaired": False,
    "artifact_deleted": False,
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
    """Return the most recent run directory across the known search roots.

    Retained for backward compatibility. The ``--latest`` CLI path now uses the
    richer :func:`select_latest` pipeline (PR181), which adds PR/commit filters,
    deterministic kind priority, and selection explanation.
    """
    roots = default_search_dirs() if search_dirs is None else list(search_dirs)
    candidates = candidate_run_dirs(roots)
    if not candidates:
        return None
    return max(candidates, key=_run_mtime)


# --------------------------------------------------------------------------- #
# PR181: deterministic latest-artifact discovery + selection explanation
# --------------------------------------------------------------------------- #
def _parse_run_name(name: str) -> tuple[Any, str | None]:
    """Extract ``(pr, commit)`` from a ``sfai-pr<PR>-<sha>-...`` directory name.

    Returns ``(None, None)`` when the name does not follow the convention. ``pr``
    is an ``int`` when numeric, otherwise ``None``; ``commit`` is the short sha
    segment unless it is the ``unknown`` placeholder.
    """
    match = _RUN_NAME_RE.match(name)
    if not match:
        return None, None
    pr_raw = match.group("pr")
    sha_raw = match.group("sha")
    pr: Any = int(pr_raw) if pr_raw.isdigit() else None
    commit = sha_raw if sha_raw and sha_raw != "unknown" else None
    return pr, commit


def _candidate_pr_commit(path: Path) -> tuple[Any, str | None]:
    """Best-effort ``(pr, commit)`` for a candidate run directory.

    The directory name is parsed first (cheap, no I/O). When that yields nothing
    usable, the run's manifest/status/heartbeat evidence is read (read-only) and
    its recorded ``pr``/``commit`` metadata is used. Never raises.
    """
    pr, commit = _parse_run_name(path.name)
    if pr is not None and commit is not None:
        return pr, commit
    try:
        resolved = resolve_run_dir(path)
    except ViewerError:
        return pr, commit
    docs: list[dict[str, Any]] = []
    for kind in ("manifest", "status", "heartbeat"):
        candidate = resolved.get(kind)
        if candidate is not None:
            doc = load_json_evidence(candidate, [], label=kind)
            if isinstance(doc, dict):
                docs.append(doc)
    if docs:
        meta = _run_metadata(docs)
        if pr is None:
            pr = meta.get("pr")
        if commit is None:
            commit = meta.get("commit")
    return pr, commit


def _safe_run_root(raw: str, warnings: list[str]) -> Path | None:
    """Validate a user-supplied ``--run-root``; reject broad/traversal roots.

    Returns the resolved directory, or ``None`` (with a warning) when the root is
    a path-traversal attempt, the filesystem root (too broad), unresolvable, or
    not an existing directory. Only this bounded root is scanned by the caller.
    """
    if ".." in Path(raw).parts:
        warnings.append(f"run root rejected (path traversal not allowed): {raw}")
        return None
    try:
        resolved = Path(raw).expanduser().resolve()
    except OSError:
        warnings.append(f"run root rejected (unresolvable): {raw}")
        return None
    if str(resolved) == resolved.anchor:
        warnings.append(f"run root rejected (too broad to scan safely): {raw}")
        return None
    if not resolved.is_dir():
        warnings.append(f"run root does not exist or is not a directory: {raw}")
        return None
    return resolved


def _kind_rank(candidate: dict[str, Any]) -> int:
    """Deterministic preference rank for a candidate (higher is preferred)."""
    kind = candidate["kind"]
    if kind == KIND_RUN_DIR:
        return 3 if candidate.get("container") else 4
    if kind == KIND_MANIFEST:
        return 2
    return 1  # legacy_manifest


def _kind_reason(candidate: dict[str, Any]) -> str:
    """Human/JSON reason describing why this candidate kind was selected."""
    kind = candidate["kind"]
    if kind == KIND_RUN_DIR:
        if candidate.get("container"):
            return "latest matching PR-specific validation container run"
        return "latest matching PR-specific validation run"
    if kind == KIND_MANIFEST:
        return "latest persisted validation-runs manifest"
    return "latest legacy validation manifest"


def _pr_matches(candidate_pr: Any, wanted: Any) -> bool:
    return candidate_pr is not None and str(candidate_pr) == str(wanted)


def _commit_matches(candidate_commit: str | None, wanted: str) -> bool:
    """Unambiguous prefix match (either side a prefix of the other)."""
    if not candidate_commit:
        return False
    have = candidate_commit.lower()
    want = wanted.lower()
    return have.startswith(want) or want.startswith(have)


def _iso_from_mtime(mtime: float) -> str:
    return (
        datetime.fromtimestamp(mtime, UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def _add_root_candidates(
    root: Path,
    kind: str,
    *,
    container: bool,
    legacy: bool,
    seen: set[str],
    out: list[dict[str, Any]],
) -> None:
    """Append the root (flat layout) and its immediate run subdirectories."""
    if not root.is_dir():
        return
    targets = [root, *(c for c in sorted(root.iterdir()) if c.is_dir())]
    for target in targets:
        key = str(target)
        if key in seen:
            continue
        mtime = _run_mtime(target)
        if mtime <= 0:
            continue
        seen.add(key)
        pr, commit = _candidate_pr_commit(target)
        out.append(
            {
                "path": key,
                "kind": kind,
                "container": container,
                "legacy": legacy,
                "pr": pr,
                "commit": commit,
                "mtime": mtime,
            }
        )


def discover_candidates(
    *,
    run_root: str | None = None,
    include_legacy: bool = False,
    warnings: list[str] | None = None,
    include_default_roots: bool = False,
) -> list[dict[str, Any]]:
    """Discover validation evidence candidates from bounded, known locations.

    Returns a list of candidate dicts (``path``/``kind``/``container``/``legacy``/
    ``pr``/``commit``/``mtime``). When ``run_root`` is supplied, only that bounded
    root is scanned. Otherwise the env overrides and the known ShellForgeAI-owned
    roots are scanned; legacy roots are only included with ``include_legacy``.
    No arbitrary filesystem traversal is performed.
    """
    warnings = warnings if warnings is not None else []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    if run_root is not None:
        safe = _safe_run_root(run_root, warnings)
        if safe is not None:
            _add_root_candidates(
                safe, KIND_RUN_DIR, container=False, legacy=False, seen=seen, out=out
            )
        return out

    # Test/CI injection overrides (each maps to a deterministic kind).
    run_override = os.environ.get(RUNS_DIR_ENV)
    if run_override:
        _add_root_candidates(
            Path(run_override), KIND_RUN_DIR, container=False, legacy=False, seen=seen, out=out
        )
    persisted_override = os.environ.get(PERSISTED_DIR_ENV)
    if persisted_override:
        _add_root_candidates(
            Path(persisted_override),
            KIND_MANIFEST,
            container=False,
            legacy=False,
            seen=seen,
            out=out,
        )
    if include_legacy:
        legacy_override = os.environ.get(LEGACY_DIR_ENV)
        if legacy_override:
            _add_root_candidates(
                Path(legacy_override),
                KIND_LEGACY_MANIFEST,
                container=False,
                legacy=True,
                seen=seen,
                out=out,
            )

    if (
        run_override or persisted_override or (include_legacy and os.environ.get(LEGACY_DIR_ENV))
    ) and not include_default_roots:
        return out

    # Environment roots can add search locations without suppressing the built-in
    # writable/default discovery roots for exact PR/commit lookups. Docker01 may
    # set SFAI_VALIDATION_RUNS_DIR to a persisted location that is not writable by
    # the lane process; automatic lane evidence under the default temp root must
    # still be found for exact status checks.

    # Recent PR-specific temp run directories (bounded glob, never a crawl).
    if TMP_ROOT.is_dir():
        for entry in sorted(TMP_ROOT.glob(TMP_PR_RUN_GLOB)):
            if not entry.is_dir():
                continue
            key = str(entry)
            if key in seen:
                continue
            mtime = _run_mtime(entry)
            if mtime <= 0:
                continue
            seen.add(key)
            container = "-validation-container-" in entry.name
            pr, commit = _candidate_pr_commit(entry)
            out.append(
                {
                    "path": key,
                    "kind": KIND_RUN_DIR,
                    "container": container,
                    "legacy": False,
                    "pr": pr,
                    "commit": commit,
                    "mtime": mtime,
                }
            )

    if TMP_ROOT.is_dir():
        for entry in sorted(TMP_ROOT.glob(TMP_PR_LOG_GLOB)):
            if not entry.is_file():
                continue
            key = str(entry)
            if key in seen:
                continue
            mtime = entry.stat().st_mtime
            if mtime <= 0:
                continue
            seen.add(key)
            pr, commit = _candidate_pr_commit(entry)
            out.append(
                {
                    "path": key,
                    "kind": "log",
                    "container": False,
                    "legacy": False,
                    "pr": pr,
                    "commit": commit,
                    "mtime": mtime,
                }
            )

    # Mainline temp runs, then persisted manifests, then (optional) legacy.
    _add_root_candidates(
        MAINLINE_TMP_ROOT, KIND_RUN_DIR, container=False, legacy=False, seen=seen, out=out
    )
    _add_root_candidates(
        PERSISTED_ROOT, KIND_MANIFEST, container=False, legacy=False, seen=seen, out=out
    )
    if include_legacy:
        _add_root_candidates(
            LEGACY_ROOT, KIND_LEGACY_MANIFEST, container=False, legacy=True, seen=seen, out=out
        )

    return out


def _candidate_evidence_rank(candidate: dict[str, Any]) -> tuple[int, float]:
    """Rank exact PR/commit evidence by completed result before mtime.

    For exact PR/commit discovery, a newer pass-eligible artifact must beat older
    setup failures and stale partial artifacts. Non-exact discovery preserves the
    existing kind/time behavior.
    """
    status_path = Path(candidate["path"]) / "validation-status.json"
    doc = load_json_evidence(status_path, [], label="status") if status_path.is_file() else None
    if not isinstance(doc, dict):
        return (0, float(candidate.get("mtime") or 0))
    if (
        doc.get("pass_eligible") is True
        or doc.get("classification") == "passed"
        or doc.get("status") == "passed"
    ):
        return (4, float(candidate.get("mtime") or 0))
    if doc.get("status") == "failed" or doc.get("classification") in ("failed", "test_failure"):
        return (3, float(candidate.get("mtime") or 0))
    if doc.get("status") == "setup_failure" or doc.get("classification") == CLASS_SETUP_FAILURE:
        return (2, float(candidate.get("mtime") or 0))
    if (
        doc.get("status") in ("interrupted", STATUS_INCOMPLETE)
        or doc.get("classification") == CLASS_INTERRUPTED
    ):
        return (1, float(candidate.get("mtime") or 0))
    return (0, float(candidate.get("mtime") or 0))


def _selected_by(pr: Any, commit: str | None) -> str:
    if pr is not None and commit is not None:
        return "pr_commit"
    if pr is not None:
        return "pr"
    if commit is not None:
        return "commit"
    return "latest"


def _skipped_reason(candidate: dict[str, Any], selected: dict[str, Any]) -> str:
    if not candidate["eligible"]:
        return candidate["skipped_reason"]
    selected_rank = _kind_rank(selected)
    candidate_rank = _kind_rank(candidate)
    if candidate_rank < selected_rank:
        if candidate["kind"] == KIND_MANIFEST:
            return "older persisted manifest (PR-specific run preferred)"
        if candidate["kind"] == KIND_LEGACY_MANIFEST:
            return "legacy artifact (recent run preferred)"
        if candidate["kind"] == KIND_RUN_DIR and candidate.get("container"):
            return "non-preferred validation container run"
        return "lower-priority artifact"
    return "older candidate (newer selected)"


def select_latest(
    *,
    pr: Any = None,
    commit: str | None = None,
    include_legacy: bool = False,
    run_root: str | None = None,
    explain: bool = False,
    warnings: list[str],
) -> dict[str, Any]:
    """Select the most relevant validation candidate and explain the choice.

    Returns a dict with the chosen ``run_dir`` path (or ``None``), a
    ``selected_meta`` block for the report ``source``, and a ``selection`` block
    (with a candidate list when ``explain`` is set). Read-only: it never executes
    or mutates anything; it only ranks discovered evidence directories.
    """
    candidates = discover_candidates(
        run_root=run_root,
        include_legacy=include_legacy,
        warnings=warnings,
        include_default_roots=pr is not None and commit is not None,
    )

    annotated: list[dict[str, Any]] = []
    for candidate in candidates:
        eligible = True
        skip: str | None = None
        if pr is not None and not _pr_matches(candidate["pr"], pr):
            eligible = False
            skip = "PR mismatch"
        elif commit is not None and not _commit_matches(candidate["commit"], commit):
            eligible = False
            skip = "commit mismatch"
        entry = dict(candidate)
        entry["eligible"] = eligible
        entry["skipped_reason"] = skip
        annotated.append(entry)

    eligible_candidates = [c for c in annotated if c["eligible"]]
    selected: dict[str, Any] | None = None
    if eligible_candidates:
        exact_scope = pr is not None and commit is not None
        if exact_scope:
            ordered = sorted(eligible_candidates, key=_candidate_evidence_rank, reverse=True)
            selected = ordered[0]
            selected_doc_rank = _candidate_evidence_rank(selected)[0]
            if selected_doc_rank >= 4:
                ignored = [
                    c
                    for c in eligible_candidates
                    if c["path"] != selected["path"] and _candidate_evidence_rank(c)[0] in (1, 2)
                ]
                if ignored:
                    warnings.append(
                        "earlier setup_failure/interrupted evidence ignored because "
                        "newer exact pass evidence was selected"
                    )
        else:
            ordered = sorted(
                eligible_candidates, key=lambda c: (_kind_rank(c), c["mtime"]), reverse=True
            )
            selected = ordered[0]
        top_rank = _kind_rank(selected)
        ties = [c for c in eligible_candidates if _kind_rank(c) == top_rank]
        if len(ties) >= 2:
            warnings.append("multiple matching candidates, newest selected")

    selected_by = _selected_by(pr, commit)
    if run_root is not None and pr is None and commit is None:
        selected_by = "run_root"

    candidate_entries: list[dict[str, Any]] = []
    if explain:
        for candidate in annotated:
            is_selected = selected is not None and candidate["path"] == selected["path"]
            candidate_entries.append(
                {
                    "path": candidate["path"],
                    "kind": candidate["kind"],
                    "container": candidate["container"],
                    "pr": candidate["pr"],
                    "commit": candidate["commit"],
                    "timestamp": _iso_from_mtime(candidate["mtime"]),
                    "selected": is_selected,
                    "reason": (
                        (
                            f"{_kind_reason(candidate)}; exact PR/commit evidence "
                            "precedence selected latest pass/fail result"
                        )
                        if is_selected and pr is not None and commit is not None
                        else _kind_reason(candidate)
                        if is_selected
                        else None
                    ),
                    "skipped_reason": (
                        None
                        if is_selected
                        else (
                            _skipped_reason(candidate, selected)
                            if selected is not None
                            else "no candidate selected"
                        )
                    ),
                }
            )

    selection = {
        "latest": True,
        "filters": {
            "pr": pr,
            "commit": commit,
            "include_legacy": bool(include_legacy),
            "run_root": str(run_root) if run_root is not None else None,
        },
        "candidate_count": len(annotated),
        "selected_path": selected["path"] if selected else None,
        "selected_reason": _kind_reason(selected) if selected else None,
        "selected_by": selected_by,
        "candidates": candidate_entries,
    }

    selected_meta = {
        "kind": selected["kind"] if selected else KIND_RUN_DIR,
        "selected_by": selected_by,
        "selection_reason": _kind_reason(selected) if selected else None,
        "pr": selected["pr"] if selected else None,
        "commit": selected["commit"] if selected else None,
    }

    return {
        "run_dir": selected["path"] if selected else None,
        "selected_meta": selected_meta,
        "selection": selection,
    }


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
    if data.get("mode") == "docker01_pr_lane_validation_status":
        status = data.get("status")
        if status == "setup_failure":
            final_status = STATUS_FAILED
            classification = CLASS_SETUP_FAILURE
        elif status in ("interrupted", "partial"):
            final_status = STATUS_INCOMPLETE
            classification = CLASS_INTERRUPTED
        elif status == STATUS_PASSED:
            final_status = STATUS_PASSED
            classification = CLASS_PASSED
        elif status == STATUS_FAILED or data.get("classification") in (
            CLASS_TEST_FAILURE,
            "failed",
        ):
            final_status = STATUS_FAILED
            classification = data.get("classification") or "failed"
        else:
            final_status = STATUS_UNKNOWN
            classification = CLASS_UNKNOWN
        full_pytest_doc = (
            data.get("full_pytest") if isinstance(data.get("full_pytest"), dict) else {}
        )
        full_exit = full_pytest_doc.get("exit_code")
        if full_exit is None and final_status == STATUS_PASSED:
            full_exit = 0
        full_result = full_pytest_doc.get("result")
        if not full_result or full_result == vh.FULL_UNKNOWN:
            full_result = vh.FULL_PASSED if final_status == STATUS_PASSED else vh.FULL_UNKNOWN
        return {
            "kind": "docker01_pr_lane",
            "finalizer": True,
            "status": final_status,
            "classification": classification,
            "full_validation": bool(data.get("full_validation")),
            "full_validation_reason": data.get("full_validation_reason") or "",
            "duplicate_full_pytest_detected": bool(data.get("duplicate_full_pytest_detected")),
            "phase_status": {},
            "active_phase": None,
            "last_completed_phase": None,
            "full_pytest_exit_code": full_exit,
            "full_pytest_result": full_result,
            "failed_phase": None,
            "conflict": False,
            "stored_status": final_status,
            "recomputed_status": final_status,
        }

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


def _terminal_finalizer_verdict(verdicts: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Return the Docker01 finalizer verdict when it records a terminal attempt.

    The finalizer is written after the selected host/fallback validation attempt
    completes. For a run directory that also contains earlier host setup-failure
    evidence, this terminal finalizer status is the authoritative final attempt;
    read-only viewers still keep the older setup failure visible as a warning.
    """
    for verdict in verdicts:
        if verdict.get("finalizer") is True and verdict.get("status") in (
            STATUS_PASSED,
            STATUS_FAILED,
        ):
            return verdict
    return None


def _merge_from_terminal_finalizer(
    finalizer: dict[str, Any],
    verdicts: list[dict[str, Any]],
    warnings: list[str],
) -> dict[str, Any] | None:
    """Use terminal Docker01 finalizer evidence over earlier setup evidence.

    This is intentionally narrow: it only applies when the Docker01 finalizer
    status packet exists and records a terminal pass/fail. It does not convert
    interrupted/unknown finalizer evidence into a pass, and it does not make
    read-only status tools execute validation.
    """
    superseded = [
        verdict
        for verdict in verdicts
        if verdict is not finalizer
        and (
            verdict.get("classification") == CLASS_SETUP_FAILURE
            or verdict.get("failed_phase") == "environment_preflight"
            or verdict.get("classification") == CLASS_INTERRUPTED
            or verdict.get("status") == STATUS_INCOMPLETE
        )
    ]
    if not superseded:
        return None

    final_status = finalizer["status"]
    pass_eligible = final_status == STATUS_PASSED
    if pass_eligible:
        warnings.append(
            "Earlier host setup_failure evidence was superseded by later successful "
            "disposable validation fallback."
        )
        selected_reason = "latest_exact_pr_commit_completed_fallback_pass"
        failed_phase = None
    else:
        warnings.append(
            "Earlier host setup_failure evidence was superseded by later terminal "
            "disposable validation fallback failure."
        )
        selected_reason = "latest_exact_pr_commit_completed_fallback_failure"
        failed_phase = finalizer.get("failed_phase")

    for verdict in superseded:
        if verdict.get("classification") == CLASS_SETUP_FAILURE:
            warnings.append(
                "Preserved earlier setup_failure evidence as a process note; it is "
                "not the final selected validation classification."
            )
            break

    phase_status = _merge_phase_status([finalizer])
    return {
        "status": final_status,
        "classification": CLASS_PASSED
        if pass_eligible
        else finalizer.get("classification", "failed"),
        "pass_eligible": pass_eligible,
        "rerun_required": not pass_eligible,
        "phase_status": phase_status,
        "active_phase": finalizer.get("active_phase"),
        "last_completed_phase": finalizer.get("last_completed_phase"),
        "full_pytest_exit_code": finalizer.get("full_pytest_exit_code"),
        "full_pytest_result": finalizer.get("full_pytest_result") or vh.FULL_UNKNOWN,
        "failed_phase": failed_phase,
        "superseded_non_pass_evidence": True,
        "selected_reason": selected_reason,
    }


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

    terminal_finalizer = _terminal_finalizer_verdict(verdicts)
    if terminal_finalizer is not None:
        finalizer_merged = _merge_from_terminal_finalizer(terminal_finalizer, verdicts, warnings)
        if finalizer_merged is not None:
            return finalizer_merged

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
                "failed",
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


def _lane_metadata(status_doc: dict[str, Any] | None, manifest_doc: dict[str, Any] | None) -> str:
    for doc in (status_doc, manifest_doc):
        if not isinstance(doc, dict):
            continue
        lane = doc.get("lane")
        if isinstance(lane, str) and lane in {"targeted", "full", "unknown"}:
            return lane
        if isinstance(lane, dict):
            return "full" if lane.get("full_validation_required") is True else "targeted"
    return "unknown"


def _full_validation_metadata(
    status_doc: dict[str, Any] | None, manifest_doc: dict[str, Any] | None
) -> dict[str, Any]:
    """Return proven full-validation metadata from status/manifest evidence."""
    for doc in (status_doc, manifest_doc):
        if not isinstance(doc, dict):
            continue
        if doc.get("full_validation") is True:
            return {
                "full_validation": True,
                "full_validation_reason": doc.get("full_validation_reason") or "",
                "duplicate_full_pytest_detected": bool(doc.get("duplicate_full_pytest_detected")),
            }
        lane = doc.get("lane")
        if isinstance(lane, dict) and lane.get("full_validation_required") is True:
            return {
                "full_validation": True,
                "full_validation_reason": lane.get("full_validation_reason") or "",
                "duplicate_full_pytest_detected": False,
            }
    return {
        "full_validation": False,
        "full_validation_reason": "",
        "duplicate_full_pytest_detected": False,
    }


def lane_qa_marker(
    manifest_doc: dict[str, Any] | None,
    *,
    fallback_packet_present: bool,
) -> dict[str, Any]:
    """Build an explicit Lane A/B/C QA marker from manifest lane evidence.

    This makes targeted-only (Lane B) validation legible to reviewers: it records
    the selected lane, whether full ``pytest`` was run, why, and whether a
    container fallback packet is present. It is read-only summarization of
    evidence the lane helper already wrote — it never runs, schedules, or
    requests validation, and never invents a lane it cannot read.
    """
    selected = None
    full_run = False
    manifest_reason = None
    if isinstance(manifest_doc, dict):
        full_run = bool(manifest_doc.get("full_validation"))
        manifest_reason = manifest_doc.get("full_validation_reason")
        lane_block = manifest_doc.get("lane")
        if isinstance(lane_block, dict):
            selected = lane_block.get("selected")
            full_run = full_run or bool(lane_block.get("full_validation_required"))
            manifest_reason = manifest_reason or lane_block.get("full_validation_reason")

    lane_letter = LANE_LETTER.get(selected) if isinstance(selected, str) else None
    scope = "full" if full_run else "targeted"
    if full_run:
        reason = manifest_reason or "Full validation lane"
    elif lane_letter:
        reason = f"Lane {lane_letter} targeted validation"
    else:
        reason = "Targeted validation"
    return {
        "validation_lane": lane_letter,
        "validation_scope": scope,
        "full_pytest_run": full_run,
        "full_pytest_reason": reason,
        "fallback_packet_present": bool(fallback_packet_present),
    }


def _not_found_report(selection: dict[str, Any] | None, warnings: list[str]) -> dict[str, Any]:
    """Controlled report when ``--latest`` discovery finds no candidate at all.

    Never a pass, never a traceback. The first safe command suggests a read-only
    re-scan with selection explanation; nothing is executed automatically.
    """
    known_locations = ", ".join(
        str(p) for p in (TMP_ROOT, MAINLINE_TMP_ROOT, PERSISTED_ROOT, LEGACY_ROOT)
    )
    rescan = "python scripts/validation_status.py --latest --explain-selection"
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": STATUS_NOT_FOUND,
        "classification": CLASS_NOT_FOUND,
        "pass_eligible": False,
        "rerun_required": True,
        "source": {
            "latest": True,
            "run_dir": None,
            "heartbeat_path": None,
            "status_path": None,
            "manifest_path": None,
            "summary_path": None,
            "log_path": None,
            "preflight_path": None,
            "fallback_packet_path": None,
            "kind": "unknown",
            "selected_by": (selection or {}).get("selected_by"),
            "selection_reason": None,
            "pr": (selection or {}).get("filters", {}).get("pr"),
            "commit": (selection or {}).get("filters", {}).get("commit"),
        },
        "selection": selection,
        "fallback_packet_present": False,
        "fallback_packet_path": None,
        "qa_marker": lane_qa_marker(None, fallback_packet_present=False),
        "run": {
            "run_id": None,
            "pr": (selection or {}).get("filters", {}).get("pr"),
            "commit": (selection or {}).get("filters", {}).get("commit"),
            "started_at": None,
            "last_update": None,
            "heartbeat_age_seconds": None,
        },
        "phases": {
            "active_phase": None,
            "last_completed_phase": None,
            "phase_status": _phase_status_for_output({}),
        },
        "full_pytest": {"exit_code": None, "result": vh.FULL_UNKNOWN},
        "failed_phase": None,
        "warnings": list(warnings),
        "known_locations": known_locations,
        "first_safe_command": rescan,
        "safe_next_commands": [
            rescan,
            f"# check known artifact locations: {known_locations}",
        ],
        "safety": dict(SAFETY_BLOCK),
    }


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
    selection: dict[str, Any] | None = None,
    selected_meta: dict[str, Any] | None = None,
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

    meta = selected_meta or {}
    status_source = status_doc.get("source") if isinstance(status_doc, dict) else {}
    if not isinstance(status_source, dict):
        status_source = {}
    source_kind = meta.get("kind") if run_dir is not None else status_source.get("kind")
    source_pr = meta.get("pr")
    if source_pr is None:
        source_pr = run_meta.get("pr")
    source_commit = meta.get("commit")
    if source_commit is None:
        source_commit = run_meta.get("commit")

    full_meta = _full_validation_metadata(status_doc, manifest_doc)
    lane_meta = _lane_metadata(status_doc, manifest_doc)
    report_selection = dict(selection) if isinstance(selection, dict) else selection
    if (
        isinstance(report_selection, dict)
        and isinstance(status_doc, dict)
        and (status_doc.get("source") or {}).get("kind") == "legacy_docker01_validation_log"
    ):
        report_selection["legacy_log_classified"] = True
        report_selection["exact_pr_commit_matched"] = True
        if status_doc.get("classification") == CLASS_PASSED:
            report_selection["selected_reason"] = "exact_pr_commit_legacy_log_pass_markers"
    if isinstance(report_selection, dict) and merged.get("superseded_non_pass_evidence"):
        report_selection["superseded_non_pass_evidence"] = True
        report_selection["selected_final_attempt_reason"] = merged.get("selected_reason")
        if merged.get("selected_reason"):
            report_selection["selected_reason"] = merged["selected_reason"]

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": merged["status"],
        "classification": merged["classification"],
        "pass_eligible": bool(merged["pass_eligible"]),
        "rerun_required": bool(merged["rerun_required"]),
        "lane": lane_meta,
        "full_validation": full_meta["full_validation"],
        "full_validation_reason": full_meta["full_validation_reason"],
        "duplicate_full_pytest_detected": full_meta["duplicate_full_pytest_detected"],
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
            "kind": source_kind,
            "selected_by": meta.get("selected_by"),
            "selection_reason": meta.get("selection_reason"),
            "pr": source_pr,
            "commit": source_commit,
        },
        "selection": report_selection,
        "fallback_packet_present": fallback_present,
        "fallback_packet_path": fallback_packet_path,
        "qa_marker": lane_qa_marker(manifest_doc, fallback_packet_present=fallback_present),
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


def _render_selection(report: dict[str, Any], lines: list[str]) -> None:
    """Append the latest-discovery selection summary to the human output."""
    selection = report.get("selection")
    if not isinstance(selection, dict):
        return
    source = report.get("source") or {}
    selected_path = selection.get("selected_path")
    if selected_path:
        lines.append("")
        lines.append(f"Selected artifact: {selected_path}")
        lines.append("Selection reason:")
        lines.append(f"* {selection.get('selected_reason')}")
        lines.append(f"* selected by: {selection.get('selected_by')}")
        if source.get("kind"):
            lines.append(f"* artifact kind: {source.get('kind')}")
        if source.get("pr") is not None:
            lines.append(f"* matched PR: {source.get('pr')}")
        if source.get("commit"):
            lines.append(f"* matched commit: {source.get('commit')}")
    candidates = selection.get("candidates") or []
    if candidates:
        lines.append("")
        lines.append("Candidate summary:")
        for candidate in candidates:
            label = "selected" if candidate.get("selected") else "skipped"
            reason = candidate.get("reason") or candidate.get("skipped_reason")
            lines.append(f"* {label}: {candidate.get('path')} reason: {reason}")


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

    if status == STATUS_NOT_FOUND:
        lines.extend(
            [
                "",
                "No validation evidence artifact was found under the known "
                "ShellForgeAI-owned locations.",
                f"Known locations: {report.get('known_locations', '')}",
            ]
        )
        _render_selection(report, lines)
        if report["warnings"]:
            lines.append("")
            lines.append("Warnings:")
            lines.extend(f"* {warning}" for warning in report["warnings"])
        lines.extend(
            [
                "",
                "No validation evidence is not merge evidence; rerun required.",
                "",
                "First safe command:",
                report["first_safe_command"],
            ]
        )
        return "\n".join(lines) + "\n"

    _render_selection(report, lines)

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

    marker = report.get("qa_marker") or {}
    if marker:
        lines.append("")
        lines.append("QA marker:")
        lines.append(f"* validation lane: {marker.get('validation_lane') or 'unknown'}")
        lines.append(f"* validation scope: {marker.get('validation_scope')}")
        lines.append(f"* full pytest run: {'yes' if marker.get('full_pytest_run') else 'no'}")
        lines.append(f"* full pytest reason: {marker.get('full_pytest_reason')}")
        lines.append(
            f"* fallback packet present: {'yes' if marker.get('fallback_packet_present') else 'no'}"
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
        help="Discover the most relevant run dir from known validation artifact roots.",
    )
    parser.add_argument(
        "--pr",
        type=int,
        default=None,
        help="With --latest: only consider candidates for this PR number.",
    )
    parser.add_argument(
        "--commit",
        default=None,
        help="With --latest: only consider candidates whose commit prefix-matches.",
    )
    parser.add_argument(
        "--run-root",
        default=None,
        help="With --latest: scan only within this bounded run root (no host crawl).",
    )
    parser.add_argument(
        "--include-legacy",
        action="store_true",
        help="With --latest: also consider older legacy/persisted-only artifacts.",
    )
    parser.add_argument(
        "--explain-selection",
        action="store_true",
        help="With --latest: include the selected/skipped candidate list in output.",
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

    # An explicit --run-dir (or explicit evidence files) takes priority over
    # discovery. Otherwise we run the deterministic latest-selection pipeline,
    # both for an explicit --latest and for a bare invocation.
    selection: dict[str, Any] | None = None
    selected_meta: dict[str, Any] | None = None
    not_found = False
    do_latest = run_dir is None and not explicit
    if do_latest:
        latest = True
        result = select_latest(
            pr=getattr(args, "pr", None),
            commit=getattr(args, "commit", None),
            include_legacy=bool(getattr(args, "include_legacy", False)),
            run_root=getattr(args, "run_root", None),
            explain=bool(getattr(args, "explain_selection", False)),
            warnings=warnings,
        )
        selection = result["selection"]
        selected_meta = result["selected_meta"]
        if result["run_dir"] is not None:
            if selected_meta and selected_meta.get("kind") == "log":
                log_path = result["run_dir"]
                run_dir = None
            else:
                run_dir = result["run_dir"]
        else:
            not_found = True
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
        "selection": selection,
        "selected_meta": selected_meta,
        "not_found": not_found,
    }


def _as_str(value: Path | None) -> str | None:
    return str(value) if value is not None else None


def _last_match_index(patterns: tuple[str, ...], text: str) -> int:
    indexes = [
        match.start() for pattern in patterns for match in re.finditer(pattern, text, re.I | re.M)
    ]
    return max(indexes) if indexes else -1


def _legacy_log_verdict(text: str) -> tuple[str, bool, dict[str, Any], list[str]]:
    """Conservatively classify a legacy Docker01 validation log.

    This is read-only evidence classification for exact PR/commit logs selected
    by discovery.  It requires terminal success markers for pass eligibility and
    keeps ambiguous/truncated logs non-pass-eligible.
    """
    ruff_pass = (r"\bruff(?: check)? (?:passed|ok|succeeded)\b", r"\bruff passed\b")
    compile_pass = (
        r"\bcompileall (?:passed|ok|succeeded)\b",
        r"python -m compileall\b.*(?:passed|ok|succeeded)",
    )
    targeted_pass = (
        r"\btargeted (?:pr )?(?:tests|pytest) passed\b",
        r"\bpr\d+ targeted tests passed\b",
        r"\bv1 quick passed\b",
        r"\bquick validation passed\b",
    )
    full_pass = (
        r"\bfull pytest passed\b",
        r"\bfull pytest passed:?\s*100%",
        r"\bfull pytest\b.*\b100%",
        r"run_full_pytest\.py completed successfully",
        r"\bfull validation passed\b",
    )
    exit_zero = (
        r"\bfull pytest\b.*\bexit(?: code)?[ =:]?0\b",
        r"\bexit(?: code)?[ =:]?0\b",
        r"\bexit_code[=:]0\b",
        r"\bexit 0\b",
    )
    pytest_fail = (
        r"\bpytest failed\b",
        r"\bfull pytest failed\b",
        r"\bexit(?: code)?[ =:]?[1-9]\d*\b",
    )
    ruff_fail = (r"\bruff (?:check )?failed\b",)
    compile_fail = (r"\bcompileall failed\b", r"python -m compileall\b.*failed")
    setup_fail = (r"\bsetup[_ -]?failure\b", r"\bsetup failed\b", r"environment preflight failed")
    interrupted = (r"\binterrupted\b", r"\bincomplete\b", r"\btruncated\b")

    failure_last = max(
        _last_match_index(pytest_fail, text),
        _last_match_index(ruff_fail, text),
        _last_match_index(compile_fail, text),
    )
    setup_last = _last_match_index(setup_fail, text)
    interrupted_last = _last_match_index(interrupted, text)
    ruff_last = _last_match_index(ruff_pass, text)
    compile_last = _last_match_index(compile_pass, text)
    targeted_last = _last_match_index(targeted_pass, text)
    full_last = _last_match_index(full_pass, text)
    exit_last = _last_match_index(exit_zero, text)
    last_success = max(ruff_last, compile_last, targeted_last, full_last, exit_last)
    last_bad = max(failure_last, setup_last, interrupted_last)

    full_validation = full_last >= 0 or "run_full_pytest.py" in text
    full_pytest = {"result": vh.FULL_UNKNOWN, "exit_code": None}

    if setup_last > max(failure_last, interrupted_last, last_success):
        return (
            CLASS_SETUP_FAILURE,
            full_validation,
            full_pytest,
            [
                "Legacy validation log final outcome is setup_failure; "
                "evidence is not pass-eligible."
            ],
        )
    if interrupted_last > max(failure_last, setup_last, last_success):
        return (
            CLASS_INTERRUPTED,
            full_validation,
            full_pytest,
            [
                "Legacy validation log final outcome is interrupted/incomplete; "
                "evidence is not pass-eligible."
            ],
        )
    if failure_last > last_success:
        return (
            CLASS_TEST_FAILURE,
            full_validation,
            full_pytest,
            ["Legacy validation log contains a terminal validation failure marker."],
        )

    targeted_ok = ruff_last >= 0 and compile_last >= 0 and targeted_last >= 0
    full_ok = ruff_last >= 0 and compile_last >= 0 and full_last >= 0 and exit_last >= 0
    if full_ok and last_bad <= max(full_last, exit_last):
        full_pytest = {"result": vh.FULL_PASSED, "exit_code": 0}
        return (
            CLASS_PASSED,
            True,
            full_pytest,
            [
                "Classified exact legacy validation log using trusted pass markers because "
                "structured validation-status.json was unavailable."
            ],
        )
    if targeted_ok and not full_validation and last_bad <= targeted_last:
        return (
            CLASS_PASSED,
            False,
            full_pytest,
            [
                "Classified exact legacy validation log using trusted pass markers because "
                "structured validation-status.json was unavailable."
            ],
        )
    if failure_last >= 0:
        return (
            CLASS_TEST_FAILURE,
            full_validation,
            full_pytest,
            [
                "Legacy validation log contains validation failure markers; "
                "evidence is not pass-eligible."
            ],
        )
    if setup_last >= 0:
        return (
            CLASS_SETUP_FAILURE,
            full_validation,
            full_pytest,
            [
                "Legacy validation log contains setup failure markers; "
                "evidence is not pass-eligible."
            ],
        )
    return (
        CLASS_UNKNOWN,
        full_validation,
        full_pytest,
        [
            "Legacy validation log did not contain trusted terminal pass markers; "
            "leaving evidence non-pass-eligible."
        ],
    )


def _status_from_completed_log(
    log_path: str | None,
    *,
    pr: int | None,
    commit: str | None,
    selected_meta: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not log_path:
        return None
    path = Path(log_path)
    if not path.is_file():
        return None
    text = dve.read_bounded_tail(path)
    if not text.strip():
        return None
    classification, full_validation, full_pytest, warnings = _legacy_log_verdict(text)
    status = dve.status_from_classification(classification)
    pass_eligible = classification == CLASS_PASSED
    commit_value = commit or (selected_meta or {}).get("commit") or "unknown"
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "docker01_pr_lane_validation_status",
        "status": status,
        "classification": classification,
        "pass_eligible": pass_eligible,
        "rerun_required": not pass_eligible,
        "pr": pr if pr is not None else (selected_meta or {}).get("pr"),
        "commit": commit_value,
        "short_sha": str(commit_value)[:12],
        "lane": "full" if full_validation else "targeted",
        "full_validation": full_validation,
        "full_validation_reason": "trusted legacy log markers" if full_validation else "",
        "duplicate_full_pytest_detected": False,
        "full_pytest": full_pytest,
        "source": {
            "kind": "legacy_docker01_validation_log",
            "run_dir": None,
            "log_path": str(path),
        },
        "warnings": warnings,
    }


def generate_report(args: argparse.Namespace) -> dict[str, Any]:
    warnings: list[str] = []
    sources = _resolve_sources(args, warnings)

    # ``--latest`` discovery found no candidate at all: emit a controlled
    # not_found report (no traceback, never a pass) instead of loading evidence.
    if sources["not_found"]:
        return _not_found_report(sources["selection"], warnings)

    # Explicit paths must exist (controlled error); discovered paths are optional.
    heartbeat_doc = load_heartbeat(
        sources["heartbeat_path"], warnings, required=bool(args.heartbeat)
    )
    status_doc = load_status(sources["status_path"], warnings, required=bool(args.status_file))
    if status_doc is None:
        status_doc = _status_from_completed_log(
            sources["log_path"],
            pr=getattr(args, "pr", None),
            commit=getattr(args, "commit", None),
            selected_meta=sources.get("selected_meta"),
        )
    if isinstance(status_doc, dict) and isinstance(status_doc.get("warnings"), list):
        for warning in status_doc["warnings"]:
            if isinstance(warning, str) and warning not in warnings:
                warnings.append(warning)
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
        selection=sources["selection"],
        selected_meta=sources["selected_meta"],
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
