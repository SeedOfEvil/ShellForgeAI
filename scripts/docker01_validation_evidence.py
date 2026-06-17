#!/usr/bin/env python3
"""Evidence-only Docker01 validation finalizer.

This helper records structured PR/commit-scoped validation evidence from an
already completed lane log/result. It does not run validation, QA, Docker,
Compose, cleanup, remediation, rollback, recovery, or network operations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
STATUS_MODE = "docker01_pr_lane_validation_status"
MANIFEST_MODE = "docker01_pr_lane_validation_manifest"
MAX_EXCERPT_BYTES = 12000
MAX_COMMANDS = 200

SAFETY = {
    "read_only": True,
    "mutation_performed": False,
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

PASS_MARKERS = (
    "ruff passed",
    "compileall passed",
    "targeted tests passed",
    "targeted pytest passed",
    "full pytest passed",
    "full pytest passed 100%",
    "validation result: passed",
    "status: passed",
)
FAIL_MARKERS = (
    "pytest failed",
    "ruff failed",
    "compileall failed",
    "v1 validation failed",
    "command failed",
    "validation result: failed",
    "status: failed",
)
SETUP_MARKERS = (
    "setup failure",
    "environment preflight failed",
    "missing pytest",
    "missing ruff",
    "pytest: command not found",
    "ruff: command not found",
    "missing procps",
    "missing disposable container prerequisite",
    "wrapper failure",
    "permission denied",
)
INTERRUPT_MARKERS = ("interrupted", "keyboardinterrupt", "sigint", "sigterm", "aborted")


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def short_sha(commit: str) -> str:
    return str(commit)[:12]


def default_run_dir(*, pr: int | str, commit: str, created_at: str | None = None) -> Path:
    stamp = (created_at or utc_now()).replace(":", "").replace("-", "").replace("Z", "")
    return Path(tempfile.gettempdir()) / f"sfai-pr{pr}-{short_sha(commit)}-validation-{stamp}"


def read_bounded_tail(path: str | Path | None, *, limit: int = MAX_EXCERPT_BYTES) -> str:
    if not path:
        return ""
    target = Path(path)
    if not target.is_file():
        return ""
    try:
        data = target.read_bytes()
    except OSError:
        return ""
    return data[-limit:].decode("utf-8", errors="replace")


def classify_completed_log(
    log_text: str,
    *,
    status: str | None = None,
    command_records: list[dict[str, Any]] | None = None,
) -> tuple[str, list[str]]:
    """Return (classification, warnings) for completed validation evidence."""
    warnings: list[str] = []
    requested = (status or "").strip().lower()
    if requested in {"passed", "failed", "setup_failure", "interrupted", "unknown"}:
        if requested == "interrupted":
            return "interrupted_or_incomplete", warnings
        return requested, warnings

    commands = command_records or []
    if commands:
        failed = [
            c
            for c in commands
            if c.get("status") == "failed" or c.get("exit_code") not in (None, 0)
        ]
        passed = [c for c in commands if c.get("status") == "passed" or c.get("exit_code") == 0]
        if failed:
            return "failed", warnings
        if passed and all(
            c.get("status") in ("passed", "skipped", "not_required")
            or c.get("exit_code") in (0, None)
            for c in commands
        ):
            return "passed", warnings

    text = (log_text or "").lower()
    last_setup = max((text.rfind(m) for m in SETUP_MARKERS), default=-1)
    last_pass = max((text.rfind(m) for m in PASS_MARKERS), default=-1)
    last_fail = max((text.rfind(m) for m in FAIL_MARKERS), default=-1)
    last_interrupt = max((text.rfind(m) for m in INTERRUPT_MARKERS), default=-1)

    if last_pass >= 0 and last_pass > max(last_setup, last_fail, last_interrupt):
        if last_setup >= 0:
            warnings.append(
                "earlier setup_failure marker ignored because later pass marker was found"
            )
        return "passed", warnings
    if last_fail >= 0 and last_fail > max(last_setup, last_pass):
        return "failed", warnings
    if last_setup >= 0 and last_setup > last_pass:
        return "setup_failure", warnings
    if last_interrupt >= 0:
        return "interrupted_or_incomplete", warnings
    if text.strip():
        return "unknown", warnings
    return "interrupted_or_incomplete", warnings


def status_from_classification(classification: str) -> str:
    return {
        "passed": "passed",
        "failed": "failed",
        "setup_failure": "setup_failure",
        "interrupted_or_incomplete": "interrupted",
    }.get(classification, "unknown")


def normalize_commands(commands: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in list(commands or [])[:MAX_COMMANDS]:
        argv = item.get("argv") or item.get("command") or []
        if isinstance(argv, str):
            argv = [argv]
        status = item.get("status") or "unknown"
        out.append(
            {
                "key": str(item.get("key") or item.get("name") or "unknown"),
                "argv": [str(part) for part in argv],
                "status": str(status),
                "exit_code": item.get("exit_code"),
                "duration_ms": int(item.get("duration_ms") or 0),
                "critical": bool(item.get("critical", True)),
                "log_excerpt": str(item.get("log_excerpt") or "")[:1000],
            }
        )
    return out


def artifact_entry(path: Path, *, base: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": str(path.relative_to(base)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def render_summary(doc: dict[str, Any]) -> str:
    rows = []
    for item in doc.get("commands", []):
        command = " ".join(item.get("argv") or [item.get("key", "unknown")])
        rows.append(f"| {command} | {item.get('status')} | {item.get('exit_code')} |")
    return "\n".join(
        [
            "# Docker01 PR Lane Validation Evidence",
            "",
            f"PR: {doc.get('pr')}",
            f"Commit: {doc.get('commit')}",
            f"Status: {doc.get('status')}",
            f"Classification: {doc.get('classification')}",
            f"Pass eligible: {doc.get('pass_eligible')}",
            f"Rerun required: {doc.get('rerun_required')}",
            f"Lane: {doc.get('lane')}",
            f"Full validation: {doc.get('full_validation')}",
            "",
            "## Commands",
            "",
            "| Command | Status | Exit code |",
            "| --- | --- | --- |",
            *rows,
            "",
            (
                "Evidence finalization records an already-completed validation result; "
                "it does not run validation or QA."
            ),
            "",
        ]
    )


def finalize_validation_evidence(
    *,
    pr: int | str,
    commit: str,
    log_path: str | Path | None,
    run_dir: str | Path | None = None,
    status: str | None = None,
    lane: str = "unknown",
    commands: list[dict[str, Any]] | None = None,
    full_validation: bool = False,
    full_validation_reason: str = "",
    duplicate_full_pytest_detected: bool = False,
    created_at: str | None = None,
    completed_at: str | None = None,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    created = created_at or utc_now()
    completed = completed_at or utc_now()
    out_dir = (
        Path(run_dir) if run_dir else default_run_dir(pr=pr, commit=commit, created_at=created)
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "logs").mkdir(exist_ok=True)
    command_docs = normalize_commands(commands)
    excerpt = read_bounded_tail(log_path)
    classification, detected_warnings = classify_completed_log(
        excerpt, status=status, command_records=command_docs
    )
    all_warnings = list(warnings or []) + detected_warnings
    value = status_from_classification(classification)
    pass_eligible = classification == "passed"
    summary_counts = {
        "commands_total": len(command_docs),
        "commands_passed": sum(1 for c in command_docs if c.get("status") == "passed"),
        "commands_failed": sum(1 for c in command_docs if c.get("status") == "failed"),
        "commands_skipped": sum(1 for c in command_docs if c.get("status") == "skipped"),
    }
    status_doc = {
        "schema_version": SCHEMA_VERSION,
        "mode": STATUS_MODE,
        "status": value,
        "classification": classification,
        "pass_eligible": pass_eligible,
        "rerun_required": not pass_eligible,
        "pr": int(pr) if str(pr).isdigit() else pr,
        "commit": commit,
        "short_sha": short_sha(commit),
        "created_at": created,
        "completed_at": completed,
        "lane": lane if lane in {"targeted", "full", "unknown"} else "unknown",
        "full_validation": bool(full_validation),
        "full_validation_reason": full_validation_reason or "",
        "duplicate_full_pytest_detected": bool(duplicate_full_pytest_detected),
        "commands": command_docs,
        "source": {
            "kind": "docker01_validation_finalizer",
            "run_dir": str(out_dir),
            "log_path": str(log_path) if log_path else None,
        },
        "summary": summary_counts,
        "safety": dict(SAFETY),
        "warnings": all_warnings,
    }
    files: dict[str, str] = {}
    (out_dir / "validation-status.json").write_text(
        json.dumps(status_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "commands-run.json").write_text(
        json.dumps(command_docs, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "validation-summary.md").write_text(render_summary(status_doc), encoding="utf-8")
    if excerpt:
        (out_dir / "source-log-excerpt.txt").write_text(excerpt, encoding="utf-8")
        files["source_log_excerpt"] = "source-log-excerpt.txt"
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "mode": MANIFEST_MODE,
        "pr": status_doc["pr"],
        "commit": commit,
        "short_sha": short_sha(commit),
        "created_at": created,
        "completed_at": completed,
        "run_dir": str(out_dir),
        "status_file": "validation-status.json",
        "summary_file": "validation-summary.md",
        "commands_file": "commands-run.json",
        "source_log_excerpt_file": files.get("source_log_excerpt"),
        "log_files": [str(log_path)] if log_path else [],
        "read_only": True,
        "mutation_performed": False,
        "artifacts": [],
    }
    (out_dir / "validation-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    paths = [
        out_dir / "validation-status.json",
        out_dir / "commands-run.json",
        out_dir / "validation-summary.md",
        out_dir / "validation-manifest.json",
    ]
    if files.get("source_log_excerpt"):
        paths.append(out_dir / files["source_log_excerpt"])
    manifest["artifacts"] = [artifact_entry(p, base=out_dir) for p in paths]
    (out_dir / "validation-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {"run_dir": str(out_dir), "status": status_doc, "manifest": manifest}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Finalize Docker01 validation evidence from an existing log only."
    )
    parser.add_argument("--pr", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--run-dir")
    parser.add_argument(
        "--status", choices=["passed", "failed", "setup_failure", "interrupted", "unknown"]
    )
    parser.add_argument("--lane", choices=["targeted", "full", "unknown"], default="unknown")
    parser.add_argument("--full-validation", action="store_true")
    parser.add_argument("--full-validation-reason", default="")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = finalize_validation_evidence(
        pr=args.pr,
        commit=args.commit,
        log_path=args.log,
        run_dir=args.run_dir,
        status=args.status,
        lane=args.lane,
        full_validation=args.full_validation,
        full_validation_reason=args.full_validation_reason,
    )
    if args.json:
        print(
            json.dumps(
                {
                    "mode": "docker01_validation_evidence_finalizer",
                    "run_dir": result["run_dir"],
                    "status": result["status"]["status"],
                },
                sort_keys=True,
            )
        )
    else:
        print(result["run_dir"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
