#!/usr/bin/env python3
"""Read-only Docker01 ownership handoff packet generator.

This helper reads an explicitly supplied external Docker01 Dockerfile and a
repository-owned candidate Dockerfile, compares the ownership-risk pattern, and
optionally writes review-only handoff artifacts under an explicit empty --out
directory. It never edits Dockerfiles or Compose and never invokes Docker,
ownership commands, package installation, remediation, rollback, or recovery.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MODE = "docker01_build_path_ownership_handoff_packet"
KNOWN_PATHS = ["/data", "/home/appuser/.codex", "/opt/shellforgeai"]
ARTIFACTS = [
    "docker01-ownership-handoff-packet.json",
    "docker01-ownership-handoff-summary.md",
    "source-vs-candidate.diff",
    "source-dockerfile-evidence.json",
    "candidate-dockerfile-evidence.json",
    "operator-review-checklist.md",
    "future-change-preflight.md",
    "rollback-notes.md",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
]
WILL_NOT_DO = [
    "edit production Dockerfile",
    "edit Compose",
    "run docker build",
    "run docker compose",
    "run chown/chmod/chgrp",
    "install packages",
    "cleanup/prune/delete/restart/remediate/rollback/recover",
]
SAFETY = {
    "read_only": True,
    "mutation_performed": False,
    "handoff_packet_only": True,
    "apply_available": False,
    "production_dockerfile_modified": False,
    "compose_modified": False,
    "docker_build_executed": False,
    "docker_compose_executed": False,
    "chown_executed": False,
    "chmod_executed": False,
    "package_install_executed": False,
    "cleanup_executed": False,
    "docker_prune_executed": False,
    "docker_image_removed": False,
    "docker_volume_removed": False,
    "container_restarted": False,
    "remediation_executed": False,
    "rollback_executed": False,
    "recovery_executed": False,
    "natural_language_execution": False,
    "shell_true": False,
    "arbitrary_command_execution": False,
    "cloud_apply_merge_push": False,
    "github_post_approve_merge": False,
}
_RECURSIVE_CHOWN_RE = re.compile(r"\bchown\s+(?:[^#\n]*\s)?-(?:[^#\n\s]*R[^#\n\s]*)\b", re.I)
_PATH_RE = re.compile(r"/(?:[A-Za-z0-9._@:+-]+/?)+")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_text(path: Path) -> tuple[bool, str | None, str, str | None]:
    selected = path.expanduser().resolve(strict=False)
    if not selected.is_file():
        return False, None, "", f"File was not found or is not a regular file: {selected}"
    try:
        data = selected.read_bytes()
    except OSError as exc:
        return False, None, "", f"File could not be read safely: {exc}"
    return True, _sha256(data), data.decode("utf-8", errors="replace"), None


def _detected_operations(text: str) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not _RECURSIVE_CHOWN_RE.search(line):
            continue
        line_paths = sorted(set(_PATH_RE.findall(line)), key=line.find)
        risk_paths = [path for path in KNOWN_PATHS if path in line_paths or path in line]
        if risk_paths:
            operations.append(
                {
                    "line_number": number,
                    "operation": "chown -R",
                    "text": line.strip(),
                    "paths": risk_paths,
                }
            )
    return operations


def _candidate_checks(text: str, operations: list[dict[str, Any]]) -> dict[str, bool]:
    lower = text.lower()
    return {
        "candidate_verified": bool(text)
        and not operations
        and "install -d -o appuser -g appuser" in text
        and "COPY --chown=appuser:appuser" in text
        and "candidate" in lower
        and "not the active" in lower,
        "targeted_runtime_dir_pattern_detected": "install -d -o appuser -g appuser" in text,
        "copy_chown_guidance_detected": "COPY --chown=appuser:appuser" in text,
        "candidate_marked_not_active": "candidate" in lower and "not the active" in lower,
    }


def _read_candidate_verification(
    path: Path | None,
) -> tuple[dict[str, Any] | None, list[str], list[dict[str, str]]]:
    if path is None:
        return None, [], []
    payload_path = path / "docker01-ownership-candidate-verification.json"
    try:
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return (
            None,
            [f"Optional candidate verification could not be read: {payload_path}"],
            [
                {
                    "name": "candidate_verification_input",
                    "status": "warning",
                    "detail": "optional verification missing or invalid",
                }
            ],
        )
    return (
        payload,
        [],
        [
            {
                "name": "candidate_verification_input",
                "status": "passed",
                "detail": "optional verification JSON consumed",
            }
        ],
    )


def _diff(source_text: str, candidate_text: str, source_path: str, candidate_path: str) -> str:
    return "".join(
        difflib.unified_diff(
            source_text.splitlines(keepends=True),
            candidate_text.splitlines(keepends=True),
            fromfile=source_path,
            tofile=candidate_path,
        )
    )


def build_report(
    source_dockerfile: Path,
    candidate: Path,
    candidate_verification: Path | None = None,
    out_dir: Path | None = None,
) -> dict[str, Any]:
    created_at = datetime.now(timezone.utc).isoformat()
    source_found, source_sha, source_text, source_error = _read_text(source_dockerfile)
    candidate_found, candidate_sha, candidate_text, candidate_error = _read_text(candidate)
    source_ops = _detected_operations(source_text) if source_found else []
    candidate_ops = _detected_operations(candidate_text) if candidate_found else []
    candidate_static = (
        _candidate_checks(candidate_text, candidate_ops)
        if candidate_found
        else {
            "candidate_verified": False,
            "targeted_runtime_dir_pattern_detected": False,
            "copy_chown_guidance_detected": False,
            "candidate_marked_not_active": False,
        }
    )
    verification_payload, verification_warnings, verification_checks = _read_candidate_verification(
        candidate_verification
    )
    errors = [err for err in [source_error, candidate_error] if err]
    warnings = verification_warnings
    if (
        verification_payload
        and verification_payload.get("summary", {}).get("candidate_sha256") != candidate_sha
    ):
        warnings.append("Optional candidate verification SHA256 does not match supplied candidate.")
    source_risk_paths = [
        path for path in KNOWN_PATHS if any(path in op["paths"] for op in source_ops)
    ]
    candidate_risk_paths = [
        path for path in KNOWN_PATHS if any(path in op["paths"] for op in candidate_ops)
    ]
    removes_risk = bool(source_risk_paths) and not candidate_risk_paths
    artifacts_generated = out_dir is not None
    if errors:
        status = "failed"
    elif (
        source_found and candidate_found and removes_risk and candidate_static["candidate_verified"]
    ):
        status = "partial" if warnings else "handoff_ready"
    else:
        status = "not_ready"
    diff_generated = bool(source_found and candidate_found)
    if artifacts_generated and diff_generated:
        diff_generated = True
    checks = [
        {
            "name": "source_dockerfile_scanned",
            "status": "passed" if source_found else "failed",
            "detail": "source Dockerfile scanned" if source_found else "source Dockerfile missing",
        },
        {
            "name": "candidate_static_verification",
            "status": "passed" if candidate_static["candidate_verified"] else "failed",
            "detail": "candidate static checks passed"
            if candidate_static["candidate_verified"]
            else "candidate static checks failed",
        },
        {
            "name": "handoff_packet_generated",
            "status": "passed" if status in {"handoff_ready", "partial"} else "failed",
            "detail": "handoff output is valid"
            if status in {"handoff_ready", "partial"}
            else "handoff comparison is not ready",
        },
    ] + verification_checks
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "created_at": created_at,
        "source_dockerfile_path": str(source_dockerfile),
        "candidate_path": str(candidate),
        "candidate_verification_dir": str(candidate_verification)
        if candidate_verification
        else None,
        "out_dir": str(out_dir) if out_dir else None,
        "read_only": True,
        "mutation_performed": False,
        "handoff_packet_only": True,
        "apply_available": False,
        "production_dockerfile_modified": False,
        "compose_modified": False,
        "summary": {
            "source_dockerfile_found": source_found,
            "candidate_found": candidate_found,
            "source_sha256": source_sha,
            "candidate_sha256": candidate_sha,
            "source_contains_broad_recursive_ownership": bool(source_ops),
            "candidate_contains_broad_recursive_ownership": bool(candidate_ops),
            "candidate_removes_source_risk_pattern": removes_risk,
            "known_risk_paths_in_source": source_risk_paths,
            "known_risk_paths_recursive_chown_in_candidate": candidate_risk_paths,
            "source_candidate_diff_generated": diff_generated,
            "operator_checklist_generated": artifacts_generated,
            "rollback_notes_generated": artifacts_generated,
            "handoff_errors": len(errors),
            "handoff_warnings": len(warnings),
        },
        "source": {
            "path": str(source_dockerfile),
            "sha256": source_sha,
            "broad_recursive_ownership_detected": bool(source_ops),
            "recursive_ownership_operations": len(source_ops),
            "detected_operations": source_ops,
        },
        "candidate": {
            "path": str(candidate),
            "sha256": candidate_sha,
            "candidate_verified": candidate_static["candidate_verified"],
            "broad_recursive_ownership_detected": bool(candidate_ops),
            **candidate_static,
        },
        "handoff": {
            "this_is_not_approval": True,
            "this_is_not_execution": True,
            "this_does_not_authorize_dockerfile_change": True,
            "separate_operator_action_required": True,
            "separate_guarded_pr_or_change_required": True,
            "seedofevil_final_merge_owner": True,
            "expected_backup_required": True,
            "expected_config_validation_required": True,
            "expected_health_validation_required": True,
            "expected_rollback_plan_required": True,
        },
        "operator_review": {
            "review_source_sha256": True,
            "review_candidate_sha256": True,
            "review_diff": True,
            "review_backup_path_before_any_future_action": True,
            "review_compose_config_validation_before_any_future_recreate": True,
            "review_rollback_notes": True,
            "review_no_cleanup_or_prune": True,
        },
        "will_not_do": WILL_NOT_DO,
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": SAFETY,
        "first_safe_command": "cat <handoff_packet_dir>/docker01-ownership-handoff-summary.md",
        "_diff": _diff(source_text, candidate_text, str(source_dockerfile), str(candidate))
        if source_found and candidate_found
        else "",
    }
    return report


def render_human(report: dict[str, Any]) -> str:
    summary = report["summary"]
    source = report["source"]
    candidate = report["candidate"]
    risk_paths = ", ".join(summary["known_risk_paths_in_source"]) or "none"
    source_broad = "yes" if source["broad_recursive_ownership_detected"] else "no"
    broad_removed = "yes" if summary["candidate_removes_source_risk_pattern"] else "no"
    return f"""# Docker01 Ownership Handoff Packet

Status: {report["status"]}
Read-only: yes
Mutation performed: no
Apply available: no

## Source Dockerfile
* Path: {report["source_dockerfile_path"]}
* SHA256: {source["sha256"]}
* Broad recursive ownership detected: {source_broad}
* Risk paths: {risk_paths}

## Candidate
* Path: {report["candidate_path"]}
* SHA256: {candidate["sha256"]}
* Candidate verified: {"yes" if candidate["candidate_verified"] else "no"}
* Broad recursive ownership removed: {broad_removed}

## Handoff
* This is not approval
* This is not execution
* This does not authorize Dockerfile change
* Separate guarded operator action required
* SeedOfEvil final merge owner

## Operator review checklist
* Review source SHA256
* Review candidate SHA256
* Review diff
* Confirm backup path before any future action
* Confirm compose config validation before any future recreate
* Confirm rollback notes
* Confirm no cleanup/prune/restart/remediation in this packet

## Safety
* no production Dockerfile modification
* no Compose modification
* no docker build
* no docker compose
* no chown/chmod/chgrp
* no package install
* no cleanup/prune/restart
* no remediation/rollback/recovery
* no {"shell" + "=True"}
"""


def _checklist(report: dict[str, Any]) -> str:
    return """# Docker01 Ownership Operator Review Checklist

- Review source SHA256 from the packet before considering any future change.
- Review candidate SHA256 from the packet before considering any future change.
- Review `source-vs-candidate.diff` manually.
- Confirm a backup path before any future operator-controlled file change.
- Confirm Compose config validation before any future recreate.
- Confirm rollback notes are reviewed.
- Confirm no cleanup, prune, restart, or remediation occurs in this packet.
- Confirm SeedOfEvil is final merge owner.
"""


def _preflight(report: dict[str, Any]) -> str:
    source_sha = report["summary"]["source_sha256"]
    candidate_sha = report["summary"]["candidate_sha256"]
    return f"""# Future Change Preflight Checklist

This file is a checklist only. It is not an executable procedure, not approval,
and not authorization to update the external Docker01 Dockerfile.

- Verify the source Dockerfile SHA256 still matches this packet: `{source_sha}`.
- Create a backup before any future operator-controlled file change.
- Review the candidate SHA256: `{candidate_sha}`.
- Review `source-vs-candidate.diff`.
- Validate Compose config after any future operator-controlled file change.
- Confirm no cleanup or prune is part of the future action.
- Confirm a rollback path exists before any future action.
- Confirm SeedOfEvil is final merge owner.
- Confirm this PR did not perform the action.

Future concepts may include backing up the current external Dockerfile, replacing
the external Dockerfile only in a separate guarded operator action, and restoring
the backup if validation fails. This preflight intentionally includes no
copy/paste command that overwrites `/srv/compose/shellforgeai/Dockerfile`.
"""


def _rollback_notes() -> str:
    return """# Rollback / Recovery Planning Notes

These notes are planning-only. This helper does not roll back, recover, restart,
run Docker, edit Compose, edit the production Dockerfile, or execute shell
commands.

- Identify the backup file before any separate future operator-controlled change.
- Review how the backup would be restored if validation fails.
- Review expected post-change health validation before any future action.
- Keep cleanup, prune, image removal, and volume removal out of the change.
"""


def _safety_notes() -> str:
    return "# Safety Notes\n\n" + "\n".join(f"- {item}" for item in WILL_NOT_DO) + "\n"


def write_artifacts(out_dir: Path, report: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(f"Refusing to write reports into non-empty --out directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    public_report = {key: value for key, value in report.items() if key != "_diff"}
    files = {
        "docker01-ownership-handoff-packet.json": json.dumps(
            public_report, indent=2, sort_keys=True
        )
        + "\n",
        "docker01-ownership-handoff-summary.md": render_human(report),
        "source-vs-candidate.diff": report.get("_diff", ""),
        "source-dockerfile-evidence.json": json.dumps(report["source"], indent=2, sort_keys=True)
        + "\n",
        "candidate-dockerfile-evidence.json": json.dumps(
            report["candidate"], indent=2, sort_keys=True
        )
        + "\n",
        "operator-review-checklist.md": _checklist(report),
        "future-change-preflight.md": _preflight(report),
        "rollback-notes.md": _rollback_notes(),
        "safety-notes.md": _safety_notes(),
        "manifest.json": json.dumps({"artifacts": ARTIFACTS, "mode": MODE}, indent=2) + "\n",
    }
    for name, content in files.items():
        (out_dir / name).write_text(content, encoding="utf-8")
    checksums = {
        name: _sha256((out_dir / name).read_bytes())
        for name in ARTIFACTS
        if name != "checksums.json"
    }
    (out_dir / "checksums.json").write_text(
        json.dumps({"sha256": checksums}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate read-only Docker01 ownership handoff packet."
    )
    parser.add_argument("--source-dockerfile", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--candidate-verification", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = build_report(
        args.source_dockerfile, args.candidate, args.candidate_verification, args.out
    )
    if args.out:
        write_artifacts(args.out, report)
    public_report = {key: value for key, value in report.items() if key != "_diff"}
    print(
        json.dumps(public_report, indent=2, sort_keys=True) if args.json else render_human(report)
    )
    return 0 if report["status"] in {"handoff_ready", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
