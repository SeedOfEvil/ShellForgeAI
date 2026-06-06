#!/usr/bin/env python3
"""Finalize a Docker01 validation manifest from already-completed logs.

This helper is intentionally offline and write-only for artifacts: it reads an
existing manifest plus optional log files, conservatively imports pass/fail
signals, and writes a finalized manifest copy by default. It does not rerun
pytest, call Docker/Compose, deploy, restart, prune, remediate, roll back, or
execute arbitrary operator commands.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MANIFEST_MODE = "docker01_pr_validation_manifest"
FINALIZED_BY = "manifest_finalize_helper"
UNKNOWN_STATUSES = {None, "", "unknown", "not_run"}
VALID_STATUSES = ("passed", "failed", "partial")
VALID_VERDICTS = ("pass", "hold", "fail", "unknown")
LOG_ARGUMENTS = (
    ("validation", "validation_log"),
    ("qa", "qa_log"),
    ("runner", "runner_log"),
    ("targeted", "targeted_log"),
    ("full_pytest", "full_pytest_log"),
)
COMMAND_TO_VALIDATION = {
    "lint": "ruff",
    "ruff": "ruff",
    "compile": "compileall",
    "compileall": "compileall",
    "pytest_targeted": "targeted_tests",
    "targeted_tests": "targeted_tests",
    "targeted": "targeted_tests",
    "pytest_full_runner": "full_pytest",
    "full_pytest": "full_pytest",
    "v1_quick": "v1_quick",
    "v1_standard": "v1_standard",
    "remediation_self_test_full": "remediation_self_test_full",
}
VALIDATION_TO_COMMAND = {
    "ruff": "ruff",
    "compileall": "compileall",
    "targeted_tests": "targeted_tests",
    "full_pytest": "full_pytest",
    "v1_quick": "v1_quick",
    "v1_standard": "v1_standard",
    "remediation_self_test_full": "remediation_self_test_full",
}
PASS_PATTERNS = {
    "ruff": [r"ruff check \.\s*:\s*passed", r"\bruff\s*:\s*passed\b", r"All checks passed"],
    "compileall": [r"compileall\s+passed\b", r"compileall\s*:\s*passed\b"],
    "full_pytest": [
        r"full pytest reached 100%",
        r"full pytest\s*:\s*passed\b",
        r"pytest.*\[100%\]",
    ],
    "targeted_tests": [r"targeted tests passed", r"PR\d+ targeted tests passed"],
    "remediation_self_test_full": [r"remediation self-test --profile full:\s*status ok"],
    "v1_quick": [r"v1 quick:\s*7 passed / 0 failed"],
    "v1_standard": [r"v1 standard:\s*14 passed / 0 failed"],
}
GENERIC_PASS_PATTERNS = [
    r"\b0\s+failed\b",
    r"[\"]?failed[\"]?\s*[:=]\s*0\b",
    r"\bstatus\s*=?\s*ok\b",
    r"\bci_status\s*=\s*passed\b",
    r"\b100%\s+passed\b",
    r"\bprocess exited 0\b",
    r"\bexit code 0\b",
]
FAIL_PATTERNS = [
    r"[\"]?failed[\"]?\s*[:=]\s*[1-9]\d*\b",
    r"\b[1-9]\d*\s+failed\b",
    r"(?-i:\bFAILED\s+tests?/)",
    r"(?-i:\bFAILED\b)",
    r"\bERROR\b",
    r"Traceback",
    r"helper exit [1-9]\d*",
    r"exit code [1-9]\d*",
    r"process exited [1-9]\d*",
    r"status=failed",
    r"ci_status=failed",
    r"container unhealthy",
    r"restart_count[^\n]*(?:failure|failed|unexpectedly nonzero|nonzero)",
    r"not mergeable",
    r"assertion failed",
    r"pytest failed",
    r"\bBLOCKED\b",
    r"\bHOLD\b",
    r"\bFAIL\b",
]


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Finalize/import completed Docker01 validation evidence into an existing manifest "
            "without rerunning tests."
        )
    )
    parser.add_argument("manifest_path", help="Existing validation manifest JSON to finalize.")
    parser.add_argument("--validation-log", help="Already-completed validation log path.")
    parser.add_argument("--qa-log", help="Already-completed QA log path.")
    parser.add_argument("--runner-log", help="Already-completed validation runner log path.")
    parser.add_argument("--targeted-log", help="Already-completed targeted test log path.")
    parser.add_argument("--full-pytest-log", help="Already-completed full pytest log path.")
    parser.add_argument("--status", choices=VALID_STATUSES, help="Operator final status override.")
    parser.add_argument(
        "--verdict", choices=VALID_VERDICTS, help="Operator final verdict override."
    )
    parser.add_argument(
        "--non-blocker",
        action="append",
        default=[],
        help="Non-blocking note to append to the finalized manifest; may be repeated.",
    )
    parser.add_argument(
        "--in-place", action="store_true", help="Update the original manifest path."
    )
    parser.add_argument("--output", help="Finalized manifest output path.")
    parser.add_argument("--summary-output", help="Optional finalized human summary output path.")
    parser.add_argument("--json", action="store_true", help="Emit strict JSON only.")
    return parser


def _safe_output_path(raw_path: str | None, *, default: Path | None = None) -> Path:
    path = Path(raw_path) if raw_path is not None else default
    if path is None:
        raise ValueError("output path is required")
    if any(part == ".." for part in path.parts):
        raise ValueError(f"unsafe output path rejected: {path}")
    parent = path.parent if str(path.parent) else Path(".")
    if not parent.exists():
        raise ValueError(f"output parent does not exist: {parent}")
    if parent.is_file():
        raise ValueError(f"output parent is not a directory: {parent}")
    return path


def default_finalized_path(manifest_path: Path) -> Path:
    if manifest_path.suffix:
        return manifest_path.with_name(f"{manifest_path.stem}.finalized{manifest_path.suffix}")
    return manifest_path.with_name(f"{manifest_path.name}.finalized.json")


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid manifest JSON: {exc.msg}") from exc
    except OSError as exc:
        raise ValueError(f"unable to read manifest: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError("invalid manifest JSON: top-level value must be an object")
    return loaded


def _matches(patterns: list[str] | tuple[str, ...], text: str) -> list[str]:
    return [
        pattern for pattern in patterns if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
    ]


def parse_log_text(text: str) -> dict[str, Any]:
    passes = {
        name: matched
        for name, patterns in PASS_PATTERNS.items()
        if (matched := _matches(patterns, text))
    }
    generic_passes = _matches(GENERIC_PASS_PATTERNS, text)
    failures = _matches(FAIL_PATTERNS, text)
    has_pass = bool(passes or generic_passes)
    ambiguous = not has_pass and not failures
    return {
        "passed_commands": sorted(passes),
        "pass_patterns": passes,
        "generic_pass_patterns": generic_passes,
        "fail_patterns": failures,
        "has_pass": has_pass,
        "has_fail": bool(failures),
        "ambiguous": ambiguous,
        "conflict": bool(has_pass and failures),
    }


def _read_and_parse_log(
    log_type: str, path_text: str | None, warnings: list[str]
) -> dict[str, Any]:
    if not path_text:
        return {"type": log_type, "path": None, "exists": False, "parsed": False}
    path = Path(path_text)
    record: dict[str, Any] = {
        "type": log_type,
        "path": str(path),
        "exists": path.exists(),
        "parsed": False,
    }
    if not path.exists():
        warnings.append(f"missing {log_type} log: {path}")
        return record
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        warnings.append(f"unable to read {log_type} log {path}: {exc}")
        return record
    parsed = parse_log_text(text)
    record.update(parsed)
    record["parsed"] = True
    if parsed["ambiguous"]:
        warnings.append(f"ambiguous {log_type} log: no known pass/fail signal in {path}")
    if parsed["conflict"]:
        warnings.append(f"conflicting pass/fail evidence in {log_type} log: {path}")
    return record


def collect_evidence(args: argparse.Namespace) -> dict[str, Any]:
    warnings: list[str] = []
    logs = [
        _read_and_parse_log(log_type, getattr(args, attr), warnings)
        for log_type, attr in LOG_ARGUMENTS
    ]
    evidence = {
        "enabled": True,
        "logs": logs,
        "operator_status_override": args.status,
        "operator_verdict_override": args.verdict,
        "warnings": warnings,
    }
    return evidence


def _detected_statuses(evidence: dict[str, Any]) -> tuple[dict[str, str], bool]:
    statuses: dict[str, str] = {}
    conflict = False
    for log in evidence.get("logs", []):
        if not log.get("parsed"):
            continue
        if log.get("has_fail"):
            conflict = conflict or bool(log.get("has_pass"))
            for name in log.get("passed_commands") or []:
                statuses.setdefault(name, "passed")
            # If the failing log is command-specific, mark that command failed; otherwise
            # let the final status fail without fabricating which command failed.
            log_type = log.get("type")
            if log_type == "targeted":
                statuses["targeted_tests"] = "failed"
            elif log_type in {"full_pytest", "runner"}:
                statuses["full_pytest"] = "failed"
            else:
                statuses["imported_log_failure"] = "failed"
        else:
            for name in log.get("passed_commands") or []:
                statuses[name] = "passed"
    return statuses, conflict


def _command_validation_key(record: dict[str, Any]) -> str | None:
    name = str(record.get("name") or "")
    if name in COMMAND_TO_VALIDATION:
        return COMMAND_TO_VALIDATION[name]
    display = str(record.get("display") or "").lower()
    if "ruff" in display:
        return "ruff"
    if "compileall" in display or "compile" in display:
        return "compileall"
    if "full" in display and "pytest" in display:
        return "full_pytest"
    if "pytest" in display:
        return "targeted_tests"
    return None


def _log_path_for_key(evidence: dict[str, Any], key: str) -> str | None:
    priority = {
        "ruff": ["validation"],
        "compileall": ["validation"],
        "targeted_tests": ["targeted", "validation"],
        "full_pytest": ["full_pytest", "runner", "validation"],
    }.get(key, ["validation"])
    logs = evidence.get("logs", [])
    for wanted in priority:
        for log in logs:
            if log.get("type") == wanted and log.get("path"):
                return log.get("path")
    for log in logs:
        if log.get("path"):
            return log.get("path")
    return None


def _mark_imported(record: dict[str, Any], status: str, evidence: dict[str, Any], key: str) -> None:
    record["status"] = status
    record["evidence_source"] = "imported_log"
    record["imported"] = True
    record["executed_by_helper"] = False
    if log_path := _log_path_for_key(evidence, key):
        record["log_path"] = log_path


def update_commands(manifest: dict[str, Any], evidence: dict[str, Any]) -> None:
    statuses, conflict = _detected_statuses(evidence)
    commands = manifest.setdefault("commands", [])
    if not isinstance(commands, list):
        manifest["commands"] = commands = []
    seen: set[str] = set()
    for record in commands:
        if not isinstance(record, dict):
            continue
        key = _command_validation_key(record)
        if not key:
            continue
        seen.add(key)
        current = record.get("status")
        if key in statuses and current in UNKNOWN_STATUSES:
            _mark_imported(record, statuses[key], evidence, key)
        elif record.get("evidence_source") == "imported_log":
            record["executed_by_helper"] = False
            record["imported"] = True
    for key, status in statuses.items():
        if key == "imported_log_failure" or key in seen:
            continue
        commands.append(
            {
                "name": VALIDATION_TO_COMMAND.get(key, key),
                "status": status,
                "evidence_source": "imported_log",
                "imported": True,
                "executed_by_helper": False,
                "log_path": _log_path_for_key(evidence, key),
            }
        )
        seen.add(key)
    if evidence.get("operator_status_override") and not conflict:
        for record in commands:
            if isinstance(record, dict) and record.get("status") in UNKNOWN_STATUSES:
                record["status"] = evidence["operator_status_override"]
                record["evidence_source"] = "operator_override"
                record["imported"] = True
                record["executed_by_helper"] = False


def update_validation_rollup(manifest: dict[str, Any]) -> None:
    validation = manifest.setdefault("validation", {})
    if not isinstance(validation, dict):
        manifest["validation"] = validation = {}
    for record in manifest.get("commands", []):
        if not isinstance(record, dict):
            continue
        key = _command_validation_key(record)
        if key:
            status = record.get("status") or "unknown"
            validation[key] = "unknown" if status == "not_run" else status


def update_phase_statuses(manifest: dict[str, Any]) -> None:
    phases = manifest.setdefault("phases", [])
    if not isinstance(phases, list):
        manifest["phases"] = phases = []
    command_statuses = [
        r.get("status") for r in manifest.get("commands", []) if isinstance(r, dict)
    ]
    if any(status == "failed" for status in command_statuses):
        validation_status = "failed"
    elif command_statuses and all(status == "passed" for status in command_statuses):
        validation_status = "passed"
    elif any(status == "passed" for status in command_statuses):
        validation_status = "partial"
    else:
        validation_status = "unknown"
    existing = next(
        (p for p in phases if isinstance(p, dict) and p.get("name") == "validation"), None
    )
    if existing is None:
        phases.append({"name": "validation", "status": validation_status, "duration_seconds": None})
    elif existing.get("status") in UNKNOWN_STATUSES or validation_status == "failed":
        existing["status"] = validation_status


def final_status(manifest: dict[str, Any], evidence: dict[str, Any], *, conflict: bool) -> str:
    if evidence.get("operator_status_override"):
        return evidence["operator_status_override"]
    command_statuses = [
        r.get("status") for r in manifest.get("commands", []) if isinstance(r, dict)
    ]
    if conflict:
        return "partial"
    if any(status == "failed" for status in command_statuses):
        return "failed"
    if command_statuses and all(status == "passed" for status in command_statuses):
        return "passed"
    if any(status == "passed" for status in command_statuses):
        return "partial"
    return manifest.get("status") if manifest.get("status") in VALID_STATUSES else "partial"


def final_verdict(status: str, evidence: dict[str, Any], manifest: dict[str, Any]) -> str:
    if evidence.get("operator_verdict_override"):
        return evidence["operator_verdict_override"]
    if status == "passed":
        return "pass"
    if status == "failed":
        return "fail"
    return manifest.get("verdict") if manifest.get("verdict") in VALID_VERDICTS else "hold"


def update_logs(manifest: dict[str, Any], evidence: dict[str, Any]) -> None:
    logs = manifest.setdefault("logs", {})
    if not isinstance(logs, dict):
        manifest["logs"] = logs = {}
    for record in evidence.get("logs", []):
        path = record.get("path")
        if path:
            logs[record["type"]] = path


def _dedupe_non_blockers(items: list[Any]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, str):
            continue
        note = item.strip()
        if not note or note in seen:
            continue
        seen.add(note)
        deduped.append(note)
    return deduped


def append_non_blockers(manifest: dict[str, Any], non_blockers: list[str]) -> None:
    existing = manifest.setdefault("non_blockers", [])
    if not isinstance(existing, list):
        existing = []
    manifest["non_blockers"] = _dedupe_non_blockers([*existing, *non_blockers])


def finalize_manifest(manifest: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    finalized = deepcopy(manifest)
    evidence = collect_evidence(args)
    statuses, conflict = _detected_statuses(evidence)
    if conflict or any(status == "failed" for status in statuses.values()):
        evidence["warnings"].append(
            "imported evidence contains failure/conflict; not auto-marking pass"
        )
    update_logs(finalized, evidence)
    update_commands(finalized, evidence)
    update_validation_rollup(finalized)
    update_phase_statuses(finalized)
    append_non_blockers(finalized, args.non_blocker)
    status = final_status(finalized, evidence, conflict=conflict)
    if any(value == "failed" for value in statuses.values()) and not args.status:
        status = "failed"
    finalized.update(
        {
            "schema_version": finalized.get("schema_version", 1),
            "mode": finalized.get("mode", MANIFEST_MODE),
            "finalized": True,
            "finalized_at": utc_now(),
            "finalized_by": FINALIZED_BY,
            "status": status,
            "verdict": final_verdict(status, evidence, finalized),
            "evidence_import": evidence,
        }
    )
    if status == "failed" and not finalized.get("failed_phase"):
        finalized["failed_phase"] = "validation"
    return finalized


def render_finalized_summary(manifest: dict[str, Any], *, manifest_path: Path) -> str:
    pr = manifest.get("pr") if isinstance(manifest.get("pr"), dict) else {}
    lane = manifest.get("lane") if isinstance(manifest.get("lane"), dict) else {}
    validation = manifest.get("validation") if isinstance(manifest.get("validation"), dict) else {}
    container = (
        manifest.get("final_container") if isinstance(manifest.get("final_container"), dict) else {}
    )
    safety = manifest.get("safety") if isinstance(manifest.get("safety"), dict) else {}
    logs = manifest.get("logs") if isinstance(manifest.get("logs"), dict) else {}
    result = str(manifest.get("verdict") or manifest.get("status") or "unknown").upper()
    restart = (
        container.get("restart_count") if container.get("restart_count") is not None else "unknown"
    )
    log_lines = [f"* {name}: {path}" for name, path in sorted(logs.items()) if path]
    safety_text = "no cleanup/remediation/rollback/Docker/Compose mutation"
    if any(
        safety.get(key)
        for key in (
            "cleanup_executed",
            "remediation_executed",
            "rollback_executed",
            "docker_compose_mutation_beyond_deploy",
            "docker_prune",
            "volume_prune",
        )
    ):
        safety_text = "review safety flags in manifest"
    lines = [
        "Docker01 PR validation finalized summary",
        f"PR: #{pr.get('number') if pr.get('number') is not None else 'unknown'}",
        f"Commit: {pr.get('head_commit') or 'unknown'}",
        f"Lane: {lane.get('selected') or 'unknown'}",
        f"Result: {result}",
        "Evidence source: imported logs",
        f"Full pytest: {validation.get('full_pytest', 'unknown')}",
        f"Targeted tests: {validation.get('targeted_tests', 'unknown')}",
        "Container: "
        f"{container.get('status') or 'unknown'} / {container.get('health') or 'unknown'} / "
        f"restart={restart}",
        f"Safety: {safety_text}",
        f"Manifest: {manifest_path}",
        "Logs:",
        *(log_lines or ["* none recorded"]),
        "",
        (
            "Note: Validation statuses were imported from completed logs; "
            "tests were not rerun by the finalizer."
        ),
    ]
    warnings = (manifest.get("evidence_import") or {}).get("warnings") or []
    if warnings:
        lines.extend(["", "Warnings:", *[f"* {warning}" for warning in warnings]])
    return "\n".join(lines) + "\n"


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    manifest_path = Path(args.manifest_path)
    try:
        manifest = load_manifest(manifest_path)
        output_path = _safe_output_path(
            args.output,
            default=manifest_path if args.in_place else default_finalized_path(manifest_path),
        )
        if args.in_place and args.output:
            raise ValueError("--in-place cannot be combined with --output")
        summary_path = _safe_output_path(args.summary_output) if args.summary_output else None
        finalized = finalize_manifest(manifest, args)
        artifacts = finalized.setdefault("artifacts", {})
        if isinstance(artifacts, dict):
            artifacts["manifest_path"] = str(output_path)
            if summary_path:
                artifacts["human_summary_path"] = str(summary_path)
        write_json(output_path, finalized)
        if summary_path:
            summary_path.write_text(
                render_finalized_summary(finalized, manifest_path=output_path), encoding="utf-8"
            )
    except ValueError as exc:
        payload = {"status": "failed", "error": str(exc)}
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print(f"status=failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(
            json.dumps({"status": finalized["status"], "output": str(output_path)}, sort_keys=True)
        )
    else:
        print(f"status={finalized['status']} manifest={output_path}")
        if summary_path:
            print(f"summary={summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
