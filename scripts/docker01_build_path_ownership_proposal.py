#!/usr/bin/env python3
"""Read-only Docker01 build-path ownership proposal report.

This helper inspects an explicitly supplied Dockerfile, optionally cross-checks
PR249 diagnostic artifacts, and emits review-only ownership-layer guidance for
broad recursive chown/chmod/chgrp build-path risks. It never edits Dockerfile,
runs Docker/Compose, invokes ownership commands, installs packages, or applies
any remediation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MODE = "docker01_build_path_ownership_proposal"
KNOWN_PATHS = ["/data", "/home/appuser/.codex", "/opt/shellforgeai"]
ARTIFACTS = [
    "docker01-build-path-ownership-proposal.json",
    "docker01-build-path-ownership-proposal-summary.md",
    "dockerfile-ownership-proposal-preview.json",
    "operator-review-notes.md",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
]
WILL_NOT_DO = [
    "edit Dockerfile",
    "run docker build",
    "run docker compose",
    "run chown/chmod/chgrp",
    "install packages",
    "cleanup/prune/delete/restart/remediate/rollback/recover",
]
OPERATOR_NOTES = [
    "This is a proposal report only.",
    "This helper did not edit Dockerfile.",
    "This helper did not run docker build.",
    "Any Dockerfile change must be reviewed and applied separately.",
]
SAFETY = {
    "read_only": True,
    "mutation_performed": False,
    "proposal_only": True,
    "apply_available": False,
    "dockerfile_modified": False,
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
_RECURSIVE_RE = re.compile(
    r"\b(?:chown|chmod|chgrp)\s+(?:[^#\n]*\s)?-(?:[^#\n\s]*R[^#\n\s]*)\b", re.I
)
_PATH_RE = re.compile(r"/(?:[A-Za-z0-9._@:+-]+/?)+")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _diagnostic_payload(
    diagnostic_dir: Path | None,
) -> tuple[dict[str, Any] | None, list[str], list[dict[str, str]]]:
    if diagnostic_dir is None:
        return None, [], []
    path = diagnostic_dir / "docker01-build-path-diagnostic.json"
    payload = _read_json(path)
    if payload is None:
        return (
            None,
            [f"Optional diagnostic report could not be read: {path}"],
            [
                {
                    "name": "diagnostic_cross_check",
                    "status": "warning",
                    "detail": "diagnostic JSON missing or invalid",
                }
            ],
        )
    return (
        payload,
        [],
        [
            {
                "name": "diagnostic_cross_check",
                "status": "passed",
                "detail": "diagnostic JSON consumed",
            }
        ],
    )


def _scan_dockerfile(
    path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str], list[str], list[dict[str, str]]]:
    selected = path.expanduser().resolve(strict=False)
    errors: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, str]] = []
    dockerfile: dict[str, Any] = {"path": str(selected), "exists": False, "sha256": None}
    operations: list[dict[str, Any]] = []
    if not selected.exists():
        errors.append(f"Dockerfile was not found: {selected}")
        checks.append(
            {"name": "dockerfile_scanned", "status": "failed", "detail": "Dockerfile not found."}
        )
        return dockerfile, operations, warnings, errors, checks
    if not selected.is_file():
        errors.append("Dockerfile path is not a regular file.")
        checks.append(
            {
                "name": "dockerfile_scanned",
                "status": "failed",
                "detail": "Dockerfile is not a regular file.",
            }
        )
        return dockerfile, operations, warnings, errors, checks
    try:
        data = selected.read_bytes()
    except OSError as exc:
        errors.append(f"Dockerfile could not be read safely: {exc}")
        checks.append({"name": "dockerfile_scanned", "status": "failed", "detail": str(exc)})
        return dockerfile, operations, warnings, errors, checks
    dockerfile.update({"exists": True, "sha256": _sha256(data)})
    for number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), start=1):
        if _RECURSIVE_RE.search(line):
            paths = sorted(set(_PATH_RE.findall(line)), key=line.find)
            operations.append(
                {
                    "line_number": number,
                    "operation": "chown -R"
                    if "chown" in line.lower()
                    else "recursive ownership/permission",
                    "text": line.strip(),
                    "paths": paths,
                    "risk": "broad_recursive_ownership_on_build_paths",
                }
            )
    if operations:
        warnings.append("Dockerfile contains broad recursive ownership or permission operations.")
    checks.append(
        {
            "name": "dockerfile_scanned",
            "status": "warning" if operations else "passed",
            "detail": f"{len(operations)} recursive ownership/permission operation(s) found.",
        }
    )
    return dockerfile, operations, warnings, errors, checks


def _proposal(operations: list[dict[str, Any]]) -> dict[str, Any]:
    previews = []
    for op in operations:
        previews.append(
            {
                "type": "illustrative_only",
                "applied": False,
                "before": op["text"],
                "after": [
                    "RUN install -d -o appuser -g appuser /data /home/appuser/.codex",
                    (
                        "# Prefer COPY --chown=appuser:appuser ... /opt/shellforgeai "
                        "where app source is copied"
                    ),
                ],
            }
        )
    return {
        "intent": "replace broad recursive ownership with targeted ownership setup",
        "human_review_required": True,
        "separate_pr_or_operator_change_required": True,
        "dockerfile_not_modified": True,
        "suggested_patterns": [
            {
                "name": "targeted runtime directory ownership",
                "description": (
                    "Create empty runtime directories with the desired owner instead of "
                    "recursively chowning broad paths."
                ),
            },
            {
                "name": "copy app source with ownership",
                "description": (
                    "Prefer COPY --chown=appuser:appuser for /opt/shellforgeai when applicable."
                ),
            },
            {
                "name": "avoid recursive chown over /data",
                "description": (
                    "Do not recursively chown /data during image build; handle only known "
                    "empty directories or runtime-created paths."
                ),
            },
        ],
        "candidate_patch_preview": previews,
    }


def build_report(dockerfile_path: Path, diagnostic_dir: Path | None = None) -> dict[str, Any]:
    dockerfile, operations, warnings, errors, checks = _scan_dockerfile(dockerfile_path)
    diagnostic, diag_warnings, diag_checks = _diagnostic_payload(diagnostic_dir)
    warnings.extend(diag_warnings)
    checks.extend(diag_checks)
    known = [p for p in KNOWN_PATHS if any(p in op["paths"] for op in operations)]
    if diagnostic:
        diag_file = diagnostic.get("dockerfile", {})
        if diag_file.get("path") and diag_file.get("path") != dockerfile["path"]:
            warnings.append("Diagnostic Dockerfile path differs from requested Dockerfile path.")
        if (
            diag_file.get("sha256")
            and dockerfile.get("sha256")
            and diag_file.get("sha256") != dockerfile.get("sha256")
        ):
            warnings.append(
                "Diagnostic Dockerfile SHA256 differs from requested Dockerfile SHA256."
            )
    if errors:
        status = "failed"
    elif operations:
        status = "proposal_ready"
    elif diagnostic_dir is not None and diagnostic is None:
        status = "partial"
    else:
        status = "no_issue_detected"
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dockerfile_path": dockerfile["path"],
        "diagnostic_dir": str(diagnostic_dir.resolve(strict=False)) if diagnostic_dir else None,
        "dockerfile": dockerfile,
        "read_only": True,
        "mutation_performed": False,
        "proposal_only": True,
        "apply_available": False,
        "summary": {
            "dockerfile_found": dockerfile["exists"],
            "broad_recursive_ownership_detected": bool(operations),
            "recursive_ownership_operations": len(operations),
            "known_risk_paths_detected": known,
            "proposal_items": len(_proposal(operations)["suggested_patterns"]),
            "proposal_errors": len(errors),
            "proposal_warnings": len(warnings),
        },
        "detected_operations": operations,
        "diagnostic_cross_check": {
            "provided": diagnostic_dir is not None,
            "consumed": diagnostic is not None,
        },
        "proposal": _proposal(operations),
        "operator_notes": OPERATOR_NOTES,
        "will_not_do": WILL_NOT_DO,
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": dict(SAFETY),
        "first_safe_command": (
            "cat <proposal_report_dir>/docker01-build-path-ownership-proposal-summary.md"
        ),
    }


def render_human(report: dict[str, Any]) -> str:
    summary = report["summary"]
    paths = ", ".join(summary["known_risk_paths_detected"]) or "none"
    ops = report["detected_operations"]
    op_lines = [f"* line {op['line_number']}: {op['text']}" for op in ops] or ["* none"]
    return "\n".join(
        [
            "# Docker01 Build Path Ownership Proposal",
            "",
            f"Status: {report['status']}",
            "Read-only: yes",
            "Mutation performed: no",
            "Apply available: no",
            "",
            "## Detected ownership operations",
            f"* Dockerfile: {report['dockerfile_path']}",
            (
                "* Broad recursive ownership detected: "
                f"{str(summary['broad_recursive_ownership_detected']).lower()}"
            ),
            f"* Paths: {paths}",
            *op_lines,
            "",
            "## Proposal",
            "* Replace broad recursive ownership with targeted ownership setup.",
            "* Prefer direct ownership on empty runtime dirs.",
            "* Prefer COPY --chown for app source where applicable.",
            "* Avoid recursive chown over /data.",
            "",
            "## Operator note",
            (
                "This is a proposal only. It did not edit Dockerfile, run Docker build, "
                "run Docker Compose, run chown/chmod, install packages, remediate, "
                "roll back, recover, prune, or restart anything."
            ),
            "",
            "## Safety",
            "* no Dockerfile modification",
            "* no docker build",
            "* no docker compose",
            "* no chown/chmod/chgrp",
            "* no package install",
            "* no cleanup/prune/restart",
            "* no remediation/rollback/recovery",
            "* no " + "shell=" + "True",
            "",
        ]
    )


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_artifacts(out_dir: Path, report: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(f"Refusing to write proposal reports into non-empty directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    files: dict[str, str] = {}
    payloads = {
        "docker01-build-path-ownership-proposal.json": report,
        "dockerfile-ownership-proposal-preview.json": {
            "dockerfile": report["dockerfile"],
            "detected_operations": report["detected_operations"],
            "proposal": report["proposal"],
        },
    }
    for name, payload in payloads.items():
        _write_json(out_dir / name, payload)
        files[name] = _sha256((out_dir / name).read_bytes())
    text_payloads = {
        "docker01-build-path-ownership-proposal-summary.md": render_human(report),
        "operator-review-notes.md": "# Operator Review Notes\n\n"
        + "\n".join(f"* {note}" for note in OPERATOR_NOTES)
        + "\n",
        "safety-notes.md": "# Safety Notes\n\n"
        + "\n".join(f"* {item}" for item in WILL_NOT_DO)
        + "\n",
    }
    for name, text in text_payloads.items():
        (out_dir / name).write_text(text, encoding="utf-8")
        files[name] = _sha256((out_dir / name).read_bytes())
    manifest = {"schema_version": SCHEMA_VERSION, "mode": MODE, "artifacts": ARTIFACTS}
    _write_json(out_dir / "manifest.json", manifest)
    files["manifest.json"] = _sha256((out_dir / "manifest.json").read_bytes())
    _write_json(out_dir / "checksums.json", {"sha256": files})


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Emit a read-only Docker01 build-path ownership proposal report."
    )
    parser.add_argument("--dockerfile", type=Path, required=True, help="read this Dockerfile path")
    parser.add_argument(
        "--diagnostic", type=Path, help="optional PR249 diagnostic report directory"
    )
    parser.add_argument("--out", type=Path, help="write proposal artifacts into an empty directory")
    parser.add_argument("--json", action="store_true", help="emit strict JSON instead of Markdown")
    args = parser.parse_args()
    report = build_report(args.dockerfile, args.diagnostic)
    if args.out:
        write_artifacts(args.out, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_human(report), end="")
    return 1 if report["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
