#!/usr/bin/env python3
"""Track pytest slow-test durations from full-validation logs.

This helper parses pytest ``--durations`` output and can attach the parsed
summary to explicit validation artifact paths. It does not run pytest, Docker,
Compose, cleanup, remediation, rollback, or arbitrary operator commands.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MODE = "pytest_duration_tracking"
HISTORY_MODE = "pytest_duration_history"
DEFAULT_TOP = 25
DEFAULT_REGRESSION_PERCENT = 25.0
DEFAULT_REGRESSION_SECONDS = 10.0
DEFAULT_MAX_RUNS = 50
VALID_PHASES = {"call", "setup", "teardown"}
DURATION_HEADER_RE = re.compile(r"=+\s*slowest\s+\d+\s+durations\s*=+", re.IGNORECASE)
DURATION_LINE_RE = re.compile(
    r"^\s*(?P<seconds>\d+(?:\.\d+)?)s\s+(?:(?P<phase>call|setup|teardown)\s+)?(?P<nodeid>\S.*?)(?:\s*)$",
    re.IGNORECASE,
)
TOTAL_RUNTIME_PATTERNS = (
    re.compile(
        r"Full pytest finished with exit code\s+\d+\s+in\s+(?P<seconds>\d+(?:\.\d+)?)s",
        re.IGNORECASE,
    ),
    re.compile(r"(?P<seconds>\d+(?:\.\d+)?)\s+seconds?\s*$", re.IGNORECASE),
)


def safety_contract(*, artifact_write_requested: bool = False) -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "artifact_write_requested": artifact_write_requested,
    }


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _record_from_line(line: str) -> dict[str, Any] | None:
    match = DURATION_LINE_RE.match(line)
    if not match:
        return None
    try:
        seconds = float(match.group("seconds"))
    except ValueError:
        return None
    phase = (match.group("phase") or "unknown").lower()
    if phase not in VALID_PHASES:
        phase = "unknown"
    nodeid = match.group("nodeid").strip()
    if not nodeid or nodeid.startswith("="):
        return None
    file_part = nodeid.split("::", 1)[0]
    test_name = None
    if "::" in nodeid:
        test_name = nodeid.split("::")[-1] or None
    return {
        "seconds": seconds,
        "phase": phase,
        "nodeid": nodeid,
        "file": file_part,
        "test": test_name,
        "raw_line": line.strip(),
    }


def _looks_like_duration_boundary(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith("=") or stripped.startswith("-"):
        return True
    return any(
        token in stripped.lower()
        for token in (" passed", " failed", " warnings", " errors", " short test summary")
    )


def parse_duration_text(text: str, *, top: int = DEFAULT_TOP) -> dict[str, Any]:
    warnings: list[str] = []
    lines = text.splitlines()
    header_index = next(
        (idx for idx, line in enumerate(lines) if DURATION_HEADER_RE.search(line)), None
    )
    if header_index is None:
        return {
            "status": "no_durations_found",
            "durations_found": False,
            "count": 0,
            "top": [],
            "warnings": ["no pytest slowest durations section found"],
            "total_runtime_seconds": _parse_total_runtime(text),
        }

    records: list[dict[str, Any]] = []
    malformed = 0
    for raw_line in lines[header_index + 1 :]:
        if not raw_line.strip():
            if records:
                break
            continue
        record = _record_from_line(raw_line)
        if record is not None:
            records.append(record)
            if len(records) >= top:
                break
            continue
        if _looks_like_duration_boundary(raw_line):
            if records:
                break
            continue
        malformed += 1
        warnings.append(f"ignored malformed duration line: {raw_line.strip()}")

    if not records:
        warnings.append("pytest durations section was present but no duration records were parsed")
        return {
            "status": "failed",
            "durations_found": True,
            "count": 0,
            "top": [],
            "warnings": warnings,
            "total_runtime_seconds": _parse_total_runtime(text),
        }
    if malformed:
        warnings.append(f"ignored {malformed} malformed duration line(s)")
    return {
        "status": "ok",
        "durations_found": True,
        "count": len(records),
        "top": records,
        "warnings": warnings,
        "total_runtime_seconds": _parse_total_runtime(text),
    }


def parse_log(path: str | Path, *, top: int = DEFAULT_TOP) -> dict[str, Any]:
    log_path = Path(path)
    if not log_path.exists():
        return {
            "status": "not_found",
            "durations_found": False,
            "count": 0,
            "top": [],
            "warnings": [f"log not found: {log_path}"],
            "total_runtime_seconds": None,
        }
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {
            "status": "failed",
            "durations_found": False,
            "count": 0,
            "top": [],
            "warnings": [f"unable to read log {log_path}: {exc}"],
            "total_runtime_seconds": None,
        }
    return parse_duration_text(text, top=top)


def _parse_total_runtime(text: str) -> float | None:
    for line in reversed(text.splitlines()):
        for pattern in TOTAL_RUNTIME_PATTERNS:
            match = pattern.search(line.strip())
            if match:
                try:
                    return float(match.group("seconds"))
                except ValueError:
                    return None
    return None


def load_json_object(path: str | Path) -> tuple[dict[str, Any] | None, str | None]:
    json_path = Path(path)
    if not json_path.exists():
        return None, f"baseline/history not found: {json_path}"
    try:
        loaded = json.loads(json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON in {json_path}: {exc.msg}"
    except OSError as exc:
        return None, f"unable to read {json_path}: {exc}"
    if not isinstance(loaded, dict):
        return None, f"expected object JSON in {json_path}"
    return loaded, None


def _baseline_records(baseline: dict[str, Any] | None) -> dict[str, float]:
    if not baseline:
        return {}
    candidates: list[dict[str, Any]] = []
    if isinstance(baseline.get("runs"), list):
        for run in reversed(baseline["runs"]):
            if isinstance(run, dict) and isinstance(run.get("top"), list):
                candidates.extend(item for item in run["top"] if isinstance(item, dict))
    if isinstance(baseline.get("top"), list):
        candidates.extend(item for item in baseline["top"] if isinstance(item, dict))
    duration_report = baseline.get("duration_report")
    if isinstance(duration_report, dict) and isinstance(duration_report.get("top"), list):
        candidates.extend(item for item in duration_report["top"] if isinstance(item, dict))
    by_nodeid: dict[str, float] = {}
    for item in candidates:
        nodeid = item.get("nodeid")
        seconds = item.get("seconds")
        if isinstance(nodeid, str) and isinstance(seconds, int | float) and nodeid not in by_nodeid:
            by_nodeid[nodeid] = float(seconds)
    return by_nodeid


def detect_regressions(
    current: list[dict[str, Any]],
    baseline: dict[str, Any] | None,
    *,
    threshold_percent: float = DEFAULT_REGRESSION_PERCENT,
    threshold_seconds: float = DEFAULT_REGRESSION_SECONDS,
) -> list[dict[str, Any]]:
    previous = _baseline_records(baseline)
    regressions: list[dict[str, Any]] = []
    for record in current:
        nodeid = record.get("nodeid")
        if not isinstance(nodeid, str) or nodeid not in previous:
            continue
        previous_seconds = previous[nodeid]
        current_seconds = float(record["seconds"])
        delta = current_seconds - previous_seconds
        if previous_seconds <= 0:
            delta_percent = 0.0 if delta <= 0 else 100.0
        else:
            delta_percent = (delta / previous_seconds) * 100.0
        if delta >= threshold_seconds and delta_percent >= threshold_percent:
            regressions.append(
                {
                    "nodeid": nodeid,
                    "previous_seconds": round(previous_seconds, 3),
                    "current_seconds": round(current_seconds, 3),
                    "delta_seconds": round(delta, 3),
                    "delta_percent": round(delta_percent, 3),
                    "severity": "warning",
                }
            )
    return regressions


def build_report(
    *,
    log_path: str | Path,
    parsed: dict[str, Any],
    baseline: dict[str, Any] | None = None,
    baseline_warning: str | None = None,
    threshold_percent: float = DEFAULT_REGRESSION_PERCENT,
    threshold_seconds: float = DEFAULT_REGRESSION_SECONDS,
    artifact_write_requested: bool = False,
) -> dict[str, Any]:
    warnings = list(parsed.get("warnings") or [])
    if baseline_warning:
        warnings.append(baseline_warning)
    regressions = detect_regressions(
        list(parsed.get("top") or []),
        baseline,
        threshold_percent=threshold_percent,
        threshold_seconds=threshold_seconds,
    )
    if regressions:
        warnings.append(f"duration regressions detected: {len(regressions)}")
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": parsed.get("status", "failed"),
        "log_path": str(log_path),
        "durations_found": bool(parsed.get("durations_found")),
        "count": int(parsed.get("count") or 0),
        "top": list(parsed.get("top") or []),
        "regressions": regressions,
        "warnings": warnings,
        "total_runtime_seconds": parsed.get("total_runtime_seconds"),
        "thresholds": {
            "regression_threshold_percent": threshold_percent,
            "regression_threshold_seconds": threshold_seconds,
        },
        "safety": safety_contract(artifact_write_requested=artifact_write_requested),
    }


def load_history(path: str | Path) -> tuple[dict[str, Any], str | None]:
    loaded, warning = load_json_object(path)
    if loaded is None:
        return {"schema_version": SCHEMA_VERSION, "mode": HISTORY_MODE, "runs": []}, warning
    runs = loaded.get("runs")
    if not isinstance(runs, list):
        loaded["runs"] = []
    loaded.setdefault("schema_version", SCHEMA_VERSION)
    loaded.setdefault("mode", HISTORY_MODE)
    return loaded, None


def append_history_run(
    history: dict[str, Any],
    report: dict[str, Any],
    *,
    pr: str | None = None,
    commit: str | None = None,
    max_runs: int = DEFAULT_MAX_RUNS,
) -> dict[str, Any]:
    run = {
        "created_at": _utc_now(),
        "pr": int(pr) if pr and str(pr).isdigit() else pr,
        "commit": commit,
        "log_path": report.get("log_path"),
        "total_runtime_seconds": report.get("total_runtime_seconds"),
        "top": list(report.get("top") or []),
    }
    runs = history.setdefault("runs", [])
    if not isinstance(runs, list):
        history["runs"] = runs = []
    runs.append(run)
    if max_runs > 0 and len(runs) > max_runs:
        del runs[: len(runs) - max_runs]
    return history


def write_history(path: str | Path, history: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(history, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def update_manifest(path: str | Path, report: dict[str, Any]) -> None:
    manifest_path = Path(path)
    loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("manifest JSON top-level value must be an object")
    backup_path = manifest_path.with_name(f"{manifest_path.name}.bak")
    shutil.copy2(manifest_path, backup_path)
    duration_report = {
        "log_path": report.get("log_path"),
        "status": report.get("status"),
        "durations_found": report.get("durations_found"),
        "count": report.get("count"),
        "total_runtime_seconds": report.get("total_runtime_seconds"),
        "top": report.get("top") or [],
        "regressions": report.get("regressions") or [],
        "warnings": report.get("warnings") or [],
        "updated_at": _utc_now(),
    }
    loaded["duration_report"] = duration_report
    artifacts = loaded.setdefault("artifacts", {})
    if isinstance(artifacts, dict):
        artifacts["duration_report"] = str(manifest_path)
    if report.get("status") != "ok":
        non_blockers = loaded.setdefault("non_blockers", [])
        if isinstance(non_blockers, list):
            note = f"duration tracking warning: {report.get('status')}"
            if note not in non_blockers:
                non_blockers.append(note)
    manifest_path.write_text(json.dumps(loaded, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def render_human(report: dict[str, Any]) -> str:
    lines = ["ShellForgeAI pytest duration tracking", f"status={report['status']}"]
    lines.append(f"log={report['log_path']}")
    lines.append(
        f"durations_found={str(report['durations_found']).lower()} count={report['count']}"
    )
    if report.get("total_runtime_seconds") is not None:
        lines.append(f"total_runtime_seconds={report['total_runtime_seconds']}")
    if report.get("top"):
        lines.append("Slowest tests:")
        for item in report["top"]:
            lines.append(f"  - {item['seconds']:.2f}s {item['phase']} {item['nodeid']}")
    if report.get("regressions"):
        lines.append("Regressions (warning-only):")
        for item in report["regressions"]:
            lines.append(
                "  - {nodeid}: {previous_seconds:.2f}s -> {current_seconds:.2f}s "
                "(+{delta_seconds:.2f}s, +{delta_percent:.1f}%)".format(**item)
            )
    if report.get("warnings"):
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in report["warnings"])
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="track_pytest_durations.py",
        description=(
            "Parse pytest --durations output and optionally update explicit validation artifacts."
        ),
    )
    parser.add_argument("--log", required=True, help="Pytest/full-validation log to parse.")
    parser.add_argument("--json", action="store_true", help="Emit strict JSON.")
    parser.add_argument(
        "--manifest", help="Explicit manifest JSON path to update in place with .bak copy."
    )
    parser.add_argument("--history", help="Explicit duration history JSON path to read or update.")
    parser.add_argument(
        "--update-history", action="store_true", help="Append this run to --history."
    )
    parser.add_argument(
        "--baseline", help="Explicit baseline/history JSON path for regression detection."
    )
    parser.add_argument(
        "--top", type=int, default=DEFAULT_TOP, help="Number of duration rows to keep."
    )
    parser.add_argument(
        "--regression-threshold-percent",
        type=float,
        default=DEFAULT_REGRESSION_PERCENT,
        help="Minimum percent increase for a warning regression.",
    )
    parser.add_argument(
        "--regression-threshold-seconds",
        type=float,
        default=DEFAULT_REGRESSION_SECONDS,
        help="Minimum absolute seconds increase for a warning regression.",
    )
    parser.add_argument(
        "--max-runs", type=int, default=DEFAULT_MAX_RUNS, help="History runs to keep."
    )
    parser.add_argument("--pr", help="PR number to record in history when updating.")
    parser.add_argument("--commit", help="Commit SHA to record in history when updating.")
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Return non-zero when regression warnings are detected.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.update_history and not args.history:
        parser.error("--update-history requires --history")
    if args.top < 0:
        parser.error("--top must be zero or greater")
    if args.max_runs < 0:
        parser.error("--max-runs must be zero or greater")

    parsed = parse_log(args.log, top=args.top)
    baseline = None
    baseline_warning = None
    baseline_path = args.baseline or (
        args.history if args.history and not args.update_history else None
    )
    if baseline_path:
        baseline, baseline_warning = load_json_object(baseline_path)
    report = build_report(
        log_path=args.log,
        parsed=parsed,
        baseline=baseline,
        baseline_warning=baseline_warning,
        threshold_percent=args.regression_threshold_percent,
        threshold_seconds=args.regression_threshold_seconds,
        artifact_write_requested=bool(args.manifest or args.update_history),
    )

    try:
        if args.manifest:
            update_manifest(args.manifest, report)
        if args.update_history:
            history, history_warning = load_history(args.history)
            if history_warning and Path(args.history).exists():
                report["warnings"].append(history_warning)
            history = append_history_run(
                history,
                report,
                pr=args.pr,
                commit=args.commit,
                max_runs=args.max_runs,
            )
            write_history(args.history, history)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        report["status"] = "failed"
        report["warnings"].append(f"artifact update failed: {exc}")

    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(render_human(report))

    if report["status"] == "not_found":
        return 2
    if report["status"] == "failed":
        return 1
    if args.fail_on_regression and report.get("regressions"):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
