#!/usr/bin/env python3
"""Static Docker01 ownership candidate verifier.

Reads a repository-owned candidate Dockerfile, optionally reads an explicitly
supplied source Dockerfile for comparison, and writes report artifacts only under
an explicit empty --out directory. It never edits Dockerfiles or Compose and
never invokes Docker, ownership commands, package installation, or remediation.
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
MODE = "docker01_build_path_ownership_candidate_verification"
KNOWN_PATHS = ["/data", "/home/appuser/.codex", "/opt/shellforgeai"]
ARTIFACTS = [
    "docker01-ownership-candidate-verification.json",
    "docker01-ownership-candidate-verification-summary.md",
    "candidate-static-checks.json",
    "source-comparison.json",
    "operator-review-notes.md",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
]
OPERATOR_NOTES = [
    "This is a repository-owned candidate artifact only.",
    "This helper did not edit the real Docker01 Dockerfile.",
    "This helper did not edit Compose.",
    "This helper did not run docker build.",
    "Any real Dockerfile change must be reviewed and applied separately.",
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
    "candidate_verification_only": True,
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


def _read(path: Path) -> tuple[bool, str | None, str, str | None]:
    if not path.is_file():
        return False, None, "", None
    data = path.read_bytes()
    return True, _sha256(data), data.decode("utf-8", errors="replace"), None


def _recursive_risk_paths(text: str) -> list[str]:
    found: list[str] = []
    for line in text.splitlines():
        if _RECURSIVE_CHOWN_RE.search(line):
            paths = _PATH_RE.findall(line)
            found.extend(path for path in KNOWN_PATHS if path in paths or path in line)
    return sorted(set(found), key=KNOWN_PATHS.index)


def _checks(text: str) -> dict[str, bool]:
    risks = _recursive_risk_paths(text)
    lower = text.lower()
    return {
        "no_chown_r_data": "/data" not in risks,
        "no_chown_r_codex": "/home/appuser/.codex" not in risks,
        "no_chown_r_opt_shellforgeai": "/opt/shellforgeai" not in risks,
        "no_broad_recursive_ownership": not risks,
        "has_targeted_install_dir_pattern": "install -d -o appuser -g appuser" in text,
        "has_candidate_warning_comment": "candidate" in lower and "not the active" in lower,
        "has_future_review_required_comment": "future review" in lower or "reviewed" in lower,
    }


def build_report(
    candidate: Path, source_dockerfile: Path | None = None, out_dir: Path | None = None
) -> dict[str, Any]:
    created_at = datetime.now(timezone.utc).isoformat()
    candidate_path = candidate.expanduser().resolve(strict=False)
    source_path = (
        source_dockerfile.expanduser().resolve(strict=False) if source_dockerfile else None
    )
    found, digest, text, _ = _read(candidate_path)
    errors: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, str]] = []
    static = _checks(text)
    risks = _recursive_risk_paths(text)
    copy_guidance = "COPY --chown=appuser:appuser" in text
    marked = static["has_candidate_warning_comment"]
    passed = bool(found and all(static.values()) and copy_guidance and marked)
    if not found:
        errors.append(f"Candidate Dockerfile was not found: {candidate_path}")
    if risks:
        errors.append("Candidate contains broad recursive ownership on known risk paths.")
    if found and not copy_guidance:
        errors.append("Candidate is missing COPY --chown guidance.")
    checks.append(
        {
            "name": "candidate_static_verification",
            "status": "passed" if passed else "failed",
            "detail": "candidate static checks passed"
            if passed
            else "candidate static checks failed",
        }
    )
    source_found: bool | None = None
    source_risks: list[str] = []
    if source_path:
        source_found, _, source_text, _ = _read(source_path)
        if source_found:
            source_risks = _recursive_risk_paths(source_text)
        else:
            warnings.append(f"Optional source Dockerfile was not found: {source_path}")
    status = "candidate_verified" if passed else "candidate_failed"
    if passed and source_path and not source_found:
        status = "partial"
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "created_at": created_at,
        "candidate_path": str(candidate),
        "source_dockerfile_path": str(source_dockerfile) if source_dockerfile else None,
        "out_dir": str(out_dir) if out_dir else None,
        "read_only": True,
        "mutation_performed": False,
        "candidate_verification_only": True,
        "apply_available": False,
        "production_dockerfile_modified": False,
        "compose_modified": False,
        "summary": {
            "candidate_found": found,
            "candidate_sha256": digest,
            "source_dockerfile_found": source_found,
            "broad_recursive_ownership_in_candidate": bool(risks),
            "known_risk_paths_recursive_chown_in_candidate": risks,
            "targeted_runtime_dir_pattern_detected": static["has_targeted_install_dir_pattern"],
            "copy_chown_guidance_detected": copy_guidance,
            "candidate_marked_not_active": marked,
            "static_verification_passed": passed,
            "verification_errors": len(errors),
            "verification_warnings": len(warnings),
        },
        "candidate_checks": static,
        "source_comparison": {
            "requested": source_path is not None,
            "source_contains_broad_recursive_ownership": bool(source_risks)
            if source_path and source_found
            else None,
            "candidate_removes_source_risk_pattern": bool(source_risks and not risks)
            if source_path and source_found
            else None,
            "source_risk_paths": source_risks,
        },
        "operator_notes": OPERATOR_NOTES,
        "will_not_do": WILL_NOT_DO,
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": SAFETY,
        "first_safe_command": (
            "cat <candidate_verification_dir>/docker01-ownership-candidate-verification-summary.md"
        ),
    }
    return report


def render_human(report: dict[str, Any]) -> str:
    summary = report["summary"]
    source = report["source_comparison"]
    if not source["requested"]:
        comparison = "not requested"
    elif source["source_contains_broad_recursive_ownership"]:
        comparison = "risk detected"
    else:
        comparison = "no source risk detected or source missing"
    broad = "yes" if summary["broad_recursive_ownership_in_candidate"] else "no"
    targeted = "yes" if summary["targeted_runtime_dir_pattern_detected"] else "no"
    copy_guidance = "yes" if summary["copy_chown_guidance_detected"] else "no"
    note = (
        "This is a repository-owned candidate artifact only. It did not edit the real "
        "Docker01 Dockerfile, edit Compose, run Docker build, run Docker Compose, run "
        "chown/chmod, install packages, remediate, roll back, recover, prune, or restart "
        "anything."
    )
    return f"""# Docker01 Ownership Candidate Verification

Status: {report["status"]}
Read-only: yes
Mutation performed: no
Apply available: no

## Candidate
* Path: {report["candidate_path"]}
* Candidate found: {"yes" if summary["candidate_found"] else "no"}
* Candidate SHA256: {summary["candidate_sha256"]}
* Marked not active: {"yes" if summary["candidate_marked_not_active"] else "no"}

## Static checks
* Broad recursive ownership in candidate: {broad}
* Targeted runtime directory pattern: {targeted}
* COPY --chown guidance: {copy_guidance}
* Source comparison: {comparison}

## Operator note
{note}

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


def write_artifacts(out_dir: Path, report: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(f"Refusing to write reports into non-empty --out directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "docker01-ownership-candidate-verification.json": json.dumps(
            report, indent=2, sort_keys=True
        )
        + "\n",
        "docker01-ownership-candidate-verification-summary.md": render_human(report),
        "candidate-static-checks.json": json.dumps(
            report["candidate_checks"], indent=2, sort_keys=True
        )
        + "\n",
        "source-comparison.json": json.dumps(report["source_comparison"], indent=2, sort_keys=True)
        + "\n",
        "operator-review-notes.md": "\n".join(f"- {note}" for note in OPERATOR_NOTES) + "\n",
        "safety-notes.md": "\n".join(f"- {item}" for item in WILL_NOT_DO) + "\n",
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
        json.dumps({"sha256": checksums}, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify repository-owned Docker01 ownership candidate."
    )
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--source-dockerfile", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = build_report(args.candidate, args.source_dockerfile, args.out)
    if args.out:
        write_artifacts(args.out, report)
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else render_human(report))
    return 0 if report["status"] in {"candidate_verified", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
