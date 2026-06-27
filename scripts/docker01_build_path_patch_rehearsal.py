#!/usr/bin/env python3
"""Artifact-only Docker01 build-path ownership patch rehearsal.

This helper consumes an explicitly supplied original Dockerfile and a PR251
patch-preview Dockerfile artifact, then writes copied rehearsal/report artifacts
only under an explicit empty --out directory. It never edits the real Dockerfile,
edits Compose, runs Docker/Compose, invokes ownership commands, installs
packages, or applies remediation.
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
MODE = "docker01_build_path_ownership_patch_rehearsal"
KNOWN_PATHS = ["/data", "/home/appuser/.codex", "/opt/shellforgeai"]
PREVIEW_ARTIFACTS = [
    "dockerfile-ownership-preview.Dockerfile",
    "dockerfile-ownership-preview.diff",
    "docker01-build-path-patch-preview.json",
    "manifest.json",
    "checksums.json",
]
ARTIFACTS = [
    "docker01-build-path-patch-rehearsal.json",
    "docker01-build-path-patch-rehearsal-summary.md",
    "dockerfile-ownership-rehearsed.Dockerfile",
    "dockerfile-ownership-rehearsal.diff",
    "dockerfile-ownership-rehearsal-static-verification.json",
    "original-dockerfile-preservation.json",
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
    "This is a patch rehearsal only.",
    "This helper did not edit the real Dockerfile.",
    "This helper did not edit Compose.",
    "This helper did not run docker build.",
    "Any real Dockerfile change must be reviewed and applied separately.",
]
SAFETY = {
    "read_only": False,
    "mutation_performed": False,
    "fixture_or_artifact_only": True,
    "patch_rehearsal_only": True,
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


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _read_file(path: Path) -> tuple[str, str | None]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return "", str(exc)
    return data.decode("utf-8", errors="replace"), None


def _scan_recursive_paths(text: str) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if _RECURSIVE_CHOWN_RE.search(line):
            paths = sorted(set(_PATH_RE.findall(line)), key=line.find)
            if any(path in paths for path in KNOWN_PATHS):
                operations.append({"line_number": number, "text": line.strip(), "paths": paths})
    return operations


def _static_verification(text: str) -> dict[str, bool]:
    recursive_lines = [line for line in text.splitlines() if _RECURSIVE_CHOWN_RE.search(line)]

    def has_path(path: str) -> bool:
        return any(path in line for line in recursive_lines)

    return {
        "rehearsed_contains_chown_r": bool(recursive_lines),
        "rehearsed_contains_recursive_chown_data": has_path("/data"),
        "rehearsed_contains_recursive_chown_codex": has_path("/home/appuser/.codex"),
        "rehearsed_contains_recursive_chown_opt_shellforgeai": has_path("/opt/shellforgeai"),
        "rehearsed_mentions_targeted_runtime_dirs": (
            "install -d -o appuser -g appuser /data /home/appuser/.codex" in text
        ),
        "rehearsed_mentions_copy_chown_guidance": "COPY --chown=appuser:appuser" in text,
    }


def _validate_preview_dir(preview_dir: Path | None) -> tuple[bool, bool, list[str], list[str]]:
    if preview_dir is None:
        return False, False, [], []
    warnings: list[str] = []
    errors: list[str] = []
    manifest_path = preview_dir / "manifest.json"
    checksums_path = preview_dir / "checksums.json"
    manifest_ok = False
    checksums_ok = False
    manifest = _read_json(manifest_path)
    if manifest is None:
        errors.append(f"Patch preview manifest missing or invalid: {manifest_path}")
    else:
        artifacts = manifest.get("artifacts", [])
        missing = [
            name
            for name in PREVIEW_ARTIFACTS
            if name not in artifacts or not (preview_dir / name).is_file()
        ]
        if missing:
            errors.append(f"Patch preview manifest/artifacts incomplete: {', '.join(missing)}")
        else:
            manifest_ok = True
    checksums = _read_json(checksums_path)
    sha_map = checksums.get("sha256", {}) if checksums else {}
    if not isinstance(sha_map, dict):
        sha_map = {}
    if not sha_map:
        errors.append(f"Patch preview checksums missing or invalid: {checksums_path}")
    else:
        bad: list[str] = []
        for name in PREVIEW_ARTIFACTS:
            if name == "checksums.json":
                continue
            expected = sha_map.get(name)
            path = preview_dir / name
            if not expected or (path.is_file() and _sha256(path.read_bytes()) != expected):
                bad.append(name)
        if bad:
            errors.append(f"Patch preview checksum validation failed: {', '.join(bad)}")
        else:
            checksums_ok = True
    return manifest_ok, checksums_ok, warnings, errors


def _diff(original: str, rehearsed: str, dockerfile_path: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            rehearsed.splitlines(keepends=True),
            fromfile=dockerfile_path,
            tofile="dockerfile-ownership-rehearsed.Dockerfile",
        )
    )


def build_report(
    dockerfile_path: Path,
    patch_preview_dir: Path | None = None,
    preview_dockerfile_path: Path | None = None,
    out_dir: Path | None = None,
) -> dict[str, Any]:
    selected = dockerfile_path.expanduser().resolve(strict=False)
    preview_dir = (
        patch_preview_dir.expanduser().resolve(strict=False) if patch_preview_dir else None
    )
    preview_path = (
        preview_dockerfile_path.expanduser().resolve(strict=False)
        if preview_dockerfile_path
        else (preview_dir / "dockerfile-ownership-preview.Dockerfile" if preview_dir else None)
    )
    errors: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, str]] = []
    original_text = ""
    original_sha_before: str | None = None
    original_sha_after: str | None = None
    original_found = selected.is_file()
    if not original_found:
        errors.append(f"Dockerfile was not found: {selected}")
    else:
        data = selected.read_bytes()
        original_sha_before = _sha256(data)
        original_text = data.decode("utf-8", errors="replace")
    preview_found = bool(preview_path and preview_path.is_file())
    preview_text = ""
    if not preview_found:
        errors.append(f"Preview Dockerfile was not found: {preview_path}")
    else:
        preview_text, read_error = _read_file(preview_path)  # type: ignore[arg-type]
        if read_error:
            errors.append(f"Preview Dockerfile could not be read safely: {read_error}")
    manifest_ok, checksums_ok, val_warnings, val_errors = _validate_preview_dir(preview_dir)
    warnings.extend(val_warnings)
    errors.extend(val_errors)
    if original_found:
        original_sha_after = _sha256(selected.read_bytes())
    original_unchanged = bool(original_sha_before and original_sha_before == original_sha_after)
    original_ops = _scan_recursive_paths(original_text) if original_text else []
    static = _static_verification(preview_text) if preview_text else _static_verification("")
    static_passed = (
        bool(preview_text)
        and not any(
            static[key]
            for key in [
                "rehearsed_contains_chown_r",
                "rehearsed_contains_recursive_chown_data",
                "rehearsed_contains_recursive_chown_codex",
                "rehearsed_contains_recursive_chown_opt_shellforgeai",
            ]
        )
        and static["rehearsed_mentions_targeted_runtime_dirs"]
        and static["rehearsed_mentions_copy_chown_guidance"]
    )
    if not original_unchanged:
        errors.append("Original Dockerfile SHA256 changed during rehearsal scan.")
    checks.append(
        {
            "name": "original_dockerfile_preserved",
            "status": "passed" if original_unchanged else "failed",
            "detail": "original SHA256 before/after matched"
            if original_unchanged
            else "original SHA256 changed or missing",
        }
    )
    checks.append(
        {
            "name": "rehearsed_artifact_static_verification",
            "status": "passed" if static_passed else "failed",
            "detail": "rehearsed artifact passed static verification"
            if static_passed
            else "rehearsed artifact failed static verification",
        }
    )
    status = (
        "rehearsal_passed"
        if not errors and static_passed and original_unchanged
        else ("partial" if preview_text and original_unchanged else "rehearsal_failed")
    )
    mutation = bool(out_dir and status == "rehearsal_passed")
    public_out = str(out_dir.resolve(strict=False)) if out_dir else None
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dockerfile_path": str(selected),
        "patch_preview_dir": str(preview_dir) if preview_dir else None,
        "preview_dockerfile_path": str(preview_path) if preview_path else None,
        "out_dir": public_out,
        "read_only": False,
        "mutation_performed": mutation,
        "fixture_or_artifact_only": True,
        "patch_rehearsal_only": True,
        "production_dockerfile_modified": False,
        "compose_modified": False,
        "docker_build_available": False,
        "summary": {
            "original_dockerfile_found": original_found,
            "preview_dockerfile_found": preview_found,
            "patch_preview_manifest_ok": manifest_ok,
            "patch_preview_checksums_ok": checksums_ok,
            "original_sha256_before": original_sha_before,
            "original_sha256_after": original_sha_after,
            "original_unchanged": original_unchanged,
            "rehearsal_artifact_written": mutation,
            "broad_recursive_ownership_detected_in_original": bool(original_ops),
            "broad_recursive_ownership_absent_from_rehearsed_artifact": static_passed,
            "known_risk_paths_removed_from_recursive_ownership": KNOWN_PATHS
            if static_passed
            else [],
            "static_verification_passed": static_passed,
            "rehearsal_errors": len(errors),
            "rehearsal_warnings": len(warnings),
        },
        "rehearsal": {
            "source": "patch_preview_dir" if preview_dir else "preview_dockerfile",
            "applied_to_production": False,
            "rehearsed_artifact": "dockerfile-ownership-rehearsed.Dockerfile",
            "diff_artifact": "dockerfile-ownership-rehearsal.diff",
            "human_review_required": True,
            "separate_pr_or_operator_change_required": True,
        },
        "static_verification": static,
        "operator_notes": OPERATOR_NOTES,
        "will_not_do": WILL_NOT_DO,
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": dict(SAFETY, mutation_performed=mutation),
        "first_safe_command": (
            "cat <patch_rehearsal_dir>/docker01-build-path-patch-rehearsal-summary.md"
        ),
        "_original_text": original_text,
        "_rehearsed_text": preview_text,
        "_rehearsal_diff": _diff(original_text, preview_text, str(selected))
        if original_text or preview_text
        else "",
        "_preservation": {
            "dockerfile_path": str(selected),
            "sha256_before": original_sha_before,
            "sha256_after": original_sha_after,
            "unchanged": original_unchanged,
            "production_dockerfile_modified": False,
        },
    }


def _public_report(report: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in report.items() if not k.startswith("_")}


def render_human(report: dict[str, Any]) -> str:
    summary = report["summary"]
    return "\n".join(
        [
            "# Docker01 Build Path Ownership Patch Rehearsal",
            "",
            f"Status: {report['status']}",
            f"Output: {report.get('out_dir') or 'not written'}",
            "Mutation performed: yes, artifact-only"
            if report["mutation_performed"]
            else "Mutation performed: no",
            "Production Dockerfile modified: no",
            "Compose modified: no",
            "Docker build available: no",
            "",
            "## Inputs",
            f"* Original Dockerfile: {report['dockerfile_path']}",
            f"* Patch preview: {report.get('patch_preview_dir') or 'not supplied'}",
            f"* Preview Dockerfile: {report.get('preview_dockerfile_path') or 'not supplied'}",
            "",
            "## Rehearsal",
            f"* Rehearsed artifact written: {str(summary['rehearsal_artifact_written']).lower()}",
            f"* Original Dockerfile unchanged: {str(summary['original_unchanged']).lower()}",
            f"* Static verification passed: {str(summary['static_verification_passed']).lower()}",
            "* Broad recursive ownership absent from rehearsed artifact: "
            + str(summary["broad_recursive_ownership_absent_from_rehearsed_artifact"]).lower(),
            "",
            "## Operator note",
            (
                "This is a patch rehearsal only. It did not edit Dockerfile, edit Compose, "
                "run Docker build, run Docker Compose, run chown/chmod, install packages, "
                "remediate, roll back, recover, prune, or restart anything."
            ),
            "",
            "## Safety",
            "* no production Dockerfile modification",
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


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_artifacts(out_dir: Path, report: dict[str, Any]) -> None:
    if report["status"] != "rehearsal_passed":
        raise SystemExit("Refusing to write patch rehearsal artifacts for a failed rehearsal")
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(
            f"Refusing to write patch rehearsal reports into non-empty directory: {out_dir}"
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    report["out_dir"] = str(out_dir.resolve(strict=False))
    report["mutation_performed"] = True
    report["summary"]["rehearsal_artifact_written"] = True
    report["safety"]["mutation_performed"] = True
    public = _public_report(report)
    files: dict[str, str] = {}
    payloads = {
        "docker01-build-path-patch-rehearsal.json": public,
        "dockerfile-ownership-rehearsal-static-verification.json": public["static_verification"],
        "original-dockerfile-preservation.json": report["_preservation"],
    }
    for name, payload in payloads.items():
        _write_json(out_dir / name, payload)
        files[name] = _sha256((out_dir / name).read_bytes())
    text_payloads = {
        "docker01-build-path-patch-rehearsal-summary.md": render_human(public),
        "dockerfile-ownership-rehearsed.Dockerfile": report["_rehearsed_text"],
        "dockerfile-ownership-rehearsal.diff": report["_rehearsal_diff"],
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
        description="Rehearse a Docker01 ownership patch using copied artifacts only."
    )
    parser.add_argument(
        "--dockerfile", type=Path, required=True, help="read this original Dockerfile path"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--patch-preview", type=Path, help="PR251 patch preview output directory")
    source.add_argument(
        "--preview-dockerfile", type=Path, help="standalone preview Dockerfile artifact"
    )
    parser.add_argument(
        "--out", type=Path, help="write rehearsal artifacts into an empty directory"
    )
    parser.add_argument("--json", action="store_true", help="emit strict JSON instead of Markdown")
    args = parser.parse_args()
    report = build_report(args.dockerfile, args.patch_preview, args.preview_dockerfile, args.out)
    if args.out:
        write_artifacts(args.out, report)
    public = _public_report(report)
    if args.json:
        print(json.dumps(public, indent=2, sort_keys=True))
    else:
        print(render_human(public), end="")
    return 1 if public["status"] == "rehearsal_failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
