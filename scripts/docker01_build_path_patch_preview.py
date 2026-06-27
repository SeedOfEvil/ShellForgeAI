#!/usr/bin/env python3
"""Read-only Docker01 build-path ownership patch preview.

This helper inspects an explicitly supplied Dockerfile, optionally cross-checks
PR250 ownership proposal artifacts, and emits an illustrative unified diff plus
preview Dockerfile text. It never edits the real Dockerfile, edits Compose, runs
Docker/Compose, invokes ownership commands, installs packages, or applies any
remediation.
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
MODE = "docker01_build_path_ownership_patch_preview"
KNOWN_PATHS = ["/data", "/home/appuser/.codex", "/opt/shellforgeai"]
ARTIFACTS = [
    "docker01-build-path-patch-preview.json",
    "docker01-build-path-patch-preview-summary.md",
    "dockerfile-ownership-preview.diff",
    "dockerfile-ownership-preview.Dockerfile",
    "dockerfile-ownership-static-verification.json",
    "operator-review-notes.md",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
]
WILL_NOT_DO = [
    "edit Dockerfile",
    "edit Compose",
    "run docker build",
    "run docker compose",
    "run chown/chmod/chgrp",
    "install packages",
    "cleanup/prune/delete/restart/remediate/rollback/recover",
]
OPERATOR_NOTES = [
    "This is a patch preview only.",
    "This helper did not edit Dockerfile.",
    "This helper did not run docker build.",
    "Any Dockerfile change must be reviewed and applied separately.",
]
SAFETY = {
    "read_only": True,
    "mutation_performed": False,
    "patch_preview_only": True,
    "apply_available": False,
    "dockerfile_modified": False,
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


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _proposal_payload(
    proposal_dir: Path | None,
) -> tuple[dict[str, Any] | None, list[str], list[dict[str, str]]]:
    if proposal_dir is None:
        return None, [], []
    path = proposal_dir / "docker01-build-path-ownership-proposal.json"
    payload = _read_json(path)
    if payload is None:
        return (
            None,
            [f"Optional proposal report could not be read: {path}"],
            [
                {
                    "name": "proposal_cross_check",
                    "status": "warning",
                    "detail": "proposal JSON missing or invalid",
                }
            ],
        )
    return (
        payload,
        [],
        [{"name": "proposal_cross_check", "status": "passed", "detail": "proposal JSON consumed"}],
    )


def _scan_dockerfile(
    path: Path,
) -> tuple[dict[str, Any], str, list[dict[str, Any]], list[str], list[str], list[dict[str, str]]]:
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
        return dockerfile, "", operations, warnings, errors, checks
    if not selected.is_file():
        errors.append("Dockerfile path is not a regular file.")
        checks.append(
            {
                "name": "dockerfile_scanned",
                "status": "failed",
                "detail": "Dockerfile is not a regular file.",
            }
        )
        return dockerfile, "", operations, warnings, errors, checks
    try:
        data = selected.read_bytes()
    except OSError as exc:
        errors.append(f"Dockerfile could not be read safely: {exc}")
        checks.append({"name": "dockerfile_scanned", "status": "failed", "detail": str(exc)})
        return dockerfile, "", operations, warnings, errors, checks
    text = data.decode("utf-8", errors="replace")
    dockerfile.update({"exists": True, "sha256": _sha256(data)})
    for number, line in enumerate(text.splitlines(), start=1):
        if _RECURSIVE_CHOWN_RE.search(line):
            paths = sorted(set(_PATH_RE.findall(line)), key=line.find)
            if any(p in paths for p in KNOWN_PATHS):
                operations.append(
                    {
                        "line_number": number,
                        "operation": "chown -R",
                        "text": line.strip(),
                        "paths": paths,
                        "risk": "broad_recursive_ownership_on_build_paths",
                    }
                )
    checks.append(
        {
            "name": "dockerfile_scanned",
            "status": "warning" if operations else "passed",
            "detail": f"{len(operations)} broad recursive chown operation(s) found.",
        }
    )
    return dockerfile, text, operations, warnings, errors, checks


def _preview_text(original: str, operations: list[dict[str, Any]]) -> str:
    lines = original.splitlines()
    replace_by_line = {op["line_number"] for op in operations}
    rendered: list[str] = []
    for number, line in enumerate(lines, start=1):
        if number in replace_by_line:
            rendered.extend(
                [
                    (
                        "# ShellForgeAI PR251 preview: avoid broad recursive ownership "
                        "on Docker/LXC build paths."
                    ),
                    "RUN install -d -o appuser -g appuser /data /home/appuser/.codex",
                    (
                        "# Prefer COPY --chown=appuser:appuser for application source "
                        "ownership where the Dockerfile copies /opt/shellforgeai."
                    ),
                    "# Do not recursively chown /data during image build.",
                ]
            )
        else:
            rendered.append(line)
    return "\n".join(rendered) + ("\n" if original.endswith("\n") or rendered else "")


def _diff(original: str, preview: str, dockerfile_path: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            preview.splitlines(keepends=True),
            fromfile=dockerfile_path,
            tofile="dockerfile-ownership-preview.Dockerfile",
        )
    )


def _static_verification(preview: str) -> dict[str, Any]:
    lines = preview.splitlines()
    recursive = [line for line in lines if _RECURSIVE_CHOWN_RE.search(line)]

    def has_recursive_path(path: str) -> bool:
        return any(path in line for line in recursive)

    return {
        "preview_contains_chown_r": bool(recursive),
        "preview_contains_recursive_chown_data": has_recursive_path("/data"),
        "preview_contains_recursive_chown_codex": has_recursive_path("/home/appuser/.codex"),
        "preview_contains_recursive_chown_opt_shellforgeai": has_recursive_path(
            "/opt/shellforgeai"
        ),
        "preview_mentions_targeted_runtime_dirs": (
            "install -d -o appuser -g appuser /data /home/appuser/.codex" in preview
        ),
        "preview_mentions_copy_chown_guidance": "COPY --chown=appuser:appuser" in preview,
    }


def build_report(
    dockerfile_path: Path | None = None, proposal_dir: Path | None = None
) -> dict[str, Any]:
    proposal, prop_warnings, prop_checks = _proposal_payload(proposal_dir)
    if dockerfile_path is None and proposal is not None and proposal.get("dockerfile_path"):
        dockerfile_path = Path(proposal["dockerfile_path"])
    if dockerfile_path is None:
        dockerfile_path = Path("")
    dockerfile, original, operations, warnings, errors, checks = _scan_dockerfile(dockerfile_path)
    warnings.extend(prop_warnings)
    checks.extend(prop_checks)
    if proposal:
        if (
            proposal.get("dockerfile_path")
            and proposal.get("dockerfile_path") != dockerfile["path"]
        ):
            warnings.append("Proposal Dockerfile path differs from requested Dockerfile path.")
        proposal_sha = proposal.get("dockerfile", {}).get("sha256")
        if proposal_sha and dockerfile.get("sha256") and proposal_sha != dockerfile.get("sha256"):
            warnings.append("Proposal Dockerfile SHA256 differs from requested Dockerfile SHA256.")
    preview = _preview_text(original, operations) if operations and not errors else ""
    diff = _diff(original, preview, dockerfile["path"]) if preview else ""
    static = _static_verification(preview) if preview else _static_verification(original)
    static_passed = (
        bool(preview)
        and not any(
            static[k]
            for k in [
                "preview_contains_chown_r",
                "preview_contains_recursive_chown_data",
                "preview_contains_recursive_chown_codex",
                "preview_contains_recursive_chown_opt_shellforgeai",
            ]
        )
        and static["preview_mentions_targeted_runtime_dirs"]
        and static["preview_mentions_copy_chown_guidance"]
    )
    checks.append(
        {
            "name": "patch_preview_static_verification",
            "status": "passed" if static_passed or not operations else "failed",
            "detail": "preview passed static verification"
            if static_passed
            else "no preview required"
            if not operations
            else "preview failed static verification",
        }
    )
    known = [p for p in KNOWN_PATHS if any(p in op["paths"] for op in operations)]
    if errors or (operations and not static_passed):
        status = "failed"
    elif operations:
        status = "preview_ready"
    elif proposal_dir is not None and proposal is None:
        status = "partial"
    else:
        status = "no_issue_detected"
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dockerfile_path": dockerfile["path"],
        "proposal_dir": str(proposal_dir.resolve(strict=False)) if proposal_dir else None,
        "out_dir": None,
        "dockerfile": dockerfile,
        "read_only": True,
        "mutation_performed": False,
        "patch_preview_only": True,
        "apply_available": False,
        "dockerfile_modified": False,
        "compose_modified": False,
        "summary": {
            "dockerfile_found": dockerfile["exists"],
            "broad_recursive_ownership_detected": bool(operations),
            "recursive_ownership_operations": len(operations),
            "known_risk_paths_detected": known,
            "preview_generated": bool(preview),
            "preview_removes_broad_recursive_ownership": static_passed,
            "preview_static_verification_passed": static_passed,
            "preview_items": 1 if preview else 0,
            "preview_errors": len(errors) + (1 if operations and not static_passed else 0),
            "preview_warnings": len(warnings),
        },
        "detected_operations": operations,
        "proposal_cross_check": {
            "provided": proposal_dir is not None,
            "consumed": proposal is not None,
        },
        "patch_preview": {
            "human_review_required": True,
            "separate_pr_or_operator_change_required": True,
            "applied": False,
            "dockerfile_not_modified": True,
            "preview_file": None,
            "diff_file": None,
            "strategy": (
                "replace broad recursive ownership with targeted directory ownership "
                "and COPY --chown guidance"
            ),
            "notes": [
                "Preview is illustrative and must be reviewed before any real Dockerfile change.",
                "Preview does not run Docker build.",
                "Preview does not modify the real Dockerfile.",
            ],
        },
        "static_verification": static,
        "operator_notes": OPERATOR_NOTES,
        "will_not_do": WILL_NOT_DO,
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": dict(SAFETY),
        "first_safe_command": (
            "cat <patch_preview_dir>/docker01-build-path-patch-preview-summary.md"
        ),
        "_preview_text": preview,
        "_preview_diff": diff,
    }


def render_human(report: dict[str, Any]) -> str:
    summary = report["summary"]
    paths = ", ".join(summary["known_risk_paths_detected"]) or "none"
    op_lines = [
        f"* line {op['line_number']}: {op['text']}" for op in report["detected_operations"]
    ] or ["* none"]
    return "\n".join(
        [
            "# Docker01 Build Path Ownership Patch Preview",
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
            "## Patch preview",
            f"* Preview generated: {str(summary['preview_generated']).lower()}",
            (
                "* Preview static verification: "
                f"{str(summary['preview_static_verification_passed']).lower()}"
            ),
            "* Real Dockerfile modified: no",
            "* Compose modified: no",
            "",
            "## Suggested ownership pattern",
            "* Replace broad recursive ownership with targeted ownership setup.",
            "* Prefer direct ownership on empty runtime dirs.",
            "* Prefer COPY --chown for app source where applicable.",
            "* Avoid recursive chown over /data.",
            "",
            "## Operator note",
            (
                "This is a patch preview only. It did not edit Dockerfile, run Docker "
                "build, run Docker Compose, run chown/chmod, install packages, "
                "remediate, roll back, recover, prune, or restart anything."
            ),
            "",
            "## Safety",
            "* no Dockerfile modification",
            "* no Compose modification",
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


def _public_report(report: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in report.items() if not k.startswith("_")}


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_artifacts(out_dir: Path, report: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(
            f"Refusing to write patch preview reports into non-empty directory: {out_dir}"
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    public = _public_report(report)
    public["out_dir"] = str(out_dir.resolve(strict=False))
    public["patch_preview"] = dict(public["patch_preview"])
    public["patch_preview"].update(
        {
            "preview_file": str(
                (out_dir / "dockerfile-ownership-preview.Dockerfile").resolve(strict=False)
            ),
            "diff_file": str((out_dir / "dockerfile-ownership-preview.diff").resolve(strict=False)),
        }
    )
    files: dict[str, str] = {}
    payloads = {
        "docker01-build-path-patch-preview.json": public,
        "dockerfile-ownership-static-verification.json": public["static_verification"],
    }
    for name, payload in payloads.items():
        _write_json(out_dir / name, payload)
        files[name] = _sha256((out_dir / name).read_bytes())
    text_payloads = {
        "docker01-build-path-patch-preview-summary.md": render_human(public),
        "dockerfile-ownership-preview.diff": report.get("_preview_diff", ""),
        "dockerfile-ownership-preview.Dockerfile": report.get("_preview_text", ""),
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
        description="Emit a read-only Docker01 build-path ownership patch preview."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dockerfile", type=Path, help="read this Dockerfile path")
    group.add_argument(
        "--proposal", type=Path, help="optional PR250 ownership proposal report directory"
    )
    parser.add_argument("--out", type=Path, help="write preview artifacts into an empty directory")
    parser.add_argument("--json", action="store_true", help="emit strict JSON instead of Markdown")
    args = parser.parse_args()
    report = build_report(args.dockerfile, args.proposal)
    if args.out:
        write_artifacts(args.out, report)
    public = _public_report(report)
    if args.json:
        print(json.dumps(public, indent=2, sort_keys=True))
    else:
        print(render_human(public), end="")
    return 1 if public["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
