#!/usr/bin/env python3
"""Read-only governed archive plan for ShellForgeAI evidence artifacts.

This helper discovers only bounded, known ShellForgeAI-owned historical evidence
artifact paths and emits a deterministic dry-run plan. It never archives, copies,
moves, deletes, prunes, restarts, repairs, validates, or executes mutations.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MODE = "docker01_artifact_archive_plan"
VALIDATION_MODE = "docker01_artifact_archive_plan_validation"
DRY_RUN_RECEIPT_MODE = "docker01_artifact_archive_dry_run_receipt"
DRY_RUN_RECEIPT_VALIDATION_MODE = "docker01_artifact_archive_dry_run_receipt_validation"
EXECUTION_READINESS_MODE = "docker01_artifact_archive_execution_readiness"
ARCHIVE_BUNDLE_CREATE_MODE = "docker01_artifact_archive_bundle_create"
DEFAULT_ROOT = "/tmp"
DEFAULT_MAX_SCAN = 1000
DEFAULT_MAX_RETURNED = 500
DEFAULT_MAX_WARNINGS = 50
CONFIRMATION_PHRASE = "CONFIRM_SHELLFORGEAI_ARTIFACT_ARCHIVE"
FIRST_SAFE_COMMAND = "python3 scripts/docker01_artifact_archive_plan.py --root /tmp --json"
ARCHIVE_CONFIRMATION_PHRASE = CONFIRMATION_PHRASE

PLAN_ID_RE = re.compile(r"^sha256:[0-9a-f]{16}$")
MAX_PLAN_FILE_BYTES = 5 * 1024 * 1024
PLAN_MUTATION_FLAGS = (
    "mutation_performed",
    "archive_created",
    "source_deleted",
    "source_moved",
    "source_modified",
    "cleanup_executed",
    "docker_prune_executed",
    "docker_image_removed",
    "file_deleted",
    "docker_compose_executed",
    "container_restarted",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
    "natural_language_execution",
    "shell_true",
    "arbitrary_command_execution",
    "cloud_apply_merge_push",
    "github_post_approve_merge",
)
VALIDATION_OUT_FILES = (
    "artifact-archive-plan-validation.json",
    "artifact-archive-plan-validation-summary.md",
    "manifest.json",
    "checksums.json",
)

DRY_RUN_RECEIPT_VALIDATION_OUT_FILES = (
    "artifact-archive-dry-run-receipt-validation.json",
    "artifact-archive-dry-run-receipt-validation-summary.md",
    "manifest.json",
    "checksums.json",
)

ARCHIVE_BUNDLE_OUT_FILES = (
    "archive-receipt.json",
    "archive-summary.md",
    "archive-manifest.json",
    "archive-checksums.json",
    "source-candidate-manifest.json",
    "source-exclusions.json",
    "source-preservation.json",
    "future-cleanup-notes.md",
    "safety-notes.md",
)

EXECUTION_READINESS_OUT_FILES = (
    "artifact-archive-execution-readiness.json",
    "artifact-archive-execution-readiness-summary.md",
    "future-execution-checklist.md",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
)

DRY_RUN_RECEIPT_OUT_FILES = (
    "artifact-archive-dry-run-receipt.json",
    "artifact-archive-dry-run-summary.md",
    "candidate-manifest.json",
    "excluded-candidates.json",
    "future-execution-checklist.md",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
)

REQUIRED_OUT_FILES = (
    "artifact-archive-plan.json",
    "artifact-archive-plan-summary.md",
    "candidate-manifest.json",
    "excluded-candidates.json",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
)


@dataclass(frozen=True)
class CandidateClass:
    name: str
    patterns: tuple[str, ...]


CANDIDATE_CLASSES: tuple[CandidateClass, ...] = (
    CandidateClass(
        "qa_bundle_artifacts",
        ("sfai-pr*-qa-bundle-*", "sfai-pr*-operator-qa-bundle-*", "sfai-pr*-qa-*"),
    ),
    CandidateClass("validation_artifacts", ("sfai-pr*-validation-*",)),
    CandidateClass("merge_readiness_artifacts", ("sfai-pr*-merge-readiness-*",)),
    CandidateClass("v2_readiness_artifacts", ("sfai-pr*-v2-readiness-*",)),
    CandidateClass("hygiene_report_artifacts", ("sfai-pr*-hygiene-*",)),
    CandidateClass("hygiene_review_bundle_artifacts", ("sfai-docker01-hygiene-review-bundle-*",)),
    CandidateClass("model_receipt_artifacts", ("sfai-pr*-live-probe-receipt-*",)),
    CandidateClass("model_receipt_validation_artifacts", ("sfai-pr*-receipt-validation-*",)),
    CandidateClass("storage_health_report_artifacts", ("sfai-pr*-storage-health-*",)),
)

RUNTIME_NAMES = {"var", "srv", "home", "root", "proc", "sys", "dev", "run", "etc", "workspace"}
EXPLICIT_EXCLUSIONS = (
    "Docker volumes",
    "Docker images",
    "running containers",
    "current compose/source/runtime paths",
    "unmatched arbitrary files",
)


def safety_block() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "plan_only": True,
        "archive_created": False,
        "source_deleted": False,
        "source_moved": False,
        "source_modified": False,
        "cleanup_executed": False,
        "docker_prune_executed": False,
        "docker_image_removed": False,
        "file_deleted": False,
        "docker_compose_executed": False,
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


def class_for_name(name: str) -> str | None:
    for candidate_class in CANDIDATE_CLASSES:
        if any(fnmatch.fnmatchcase(name, pattern) for pattern in candidate_class.patterns):
            return candidate_class.name
    return None


def iso_mtime(path: Path) -> str:
    return (
        datetime.fromtimestamp(path.stat(follow_symlinks=False).st_mtime, UTC)
        .isoformat()
        .replace("+00:00", "Z")
    )


def item_size(path: Path) -> int:
    stat = path.stat(follow_symlinks=False)
    if path.is_file():
        return int(stat.st_size)
    return 0


def _excluded(path: Path, reason: str) -> dict[str, str]:
    return {"path": str(path), "reason": reason}


def discover_candidates(
    root: str,
    *,
    max_scan: int = DEFAULT_MAX_SCAN,
    max_returned: int = DEFAULT_MAX_RETURNED,
    max_warnings: int = DEFAULT_MAX_WARNINGS,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], list[str]]:
    root_path = Path(root).expanduser().resolve(strict=False)
    candidates: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    warnings: list[str] = []
    if not root_path.exists() or not root_path.is_dir():
        return [], [], [f"root is not a directory: {root_path}"][:max_warnings]

    scanned = 0
    for child in sorted(root_path.iterdir(), key=lambda p: p.name):
        if scanned >= max_scan:
            warnings.append(f"candidate scan limit reached at {max_scan}")
            break
        scanned += 1
        try:
            if child.is_symlink():
                excluded.append(_excluded(child, "symlink"))
                continue
            if child.name in RUNTIME_NAMES or str(child).startswith(
                ("/var/lib/docker", "/srv/compose", "/workspace")
            ):
                excluded.append(_excluded(child, "current_runtime_path"))
                continue
            candidate_class = class_for_name(child.name)
            if not candidate_class:
                excluded.append(_excluded(child, "outside_known_patterns"))
                continue
            stat = child.stat(follow_symlinks=False)
            kind = "directory" if child.is_dir() else "file" if child.is_file() else "other"
            candidates.append(
                {
                    "path": str(child),
                    "class": candidate_class,
                    "type": kind,
                    "size_bytes": item_size(child),
                    "mtime": datetime.fromtimestamp(stat.st_mtime, UTC)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "reason": "matches_known_shellforgeai_evidence_pattern",
                    "future_action": "archive_candidate_only",
                }
            )
        except OSError as exc:
            excluded.append(_excluded(child, "unknown"))
            if len(warnings) < max_warnings:
                warnings.append(f"could not stat {child}: {exc}")
    return candidates[:max_returned], excluded[:max_returned], warnings[:max_warnings]


def compute_plan_id(root: str, candidates: list[dict[str, Any]]) -> str:
    payload = {
        "root": str(Path(root).expanduser().resolve(strict=False)),
        "candidates": sorted(candidates, key=lambda c: c["path"]),
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    return f"sha256:{digest}"


def build_plan(root: str, **limits: int) -> dict[str, Any]:
    candidates, excluded, warnings = discover_candidates(root, **limits)
    classes = {c.name: {"items": 0, "bytes": 0} for c in CANDIDATE_CLASSES}
    for item in candidates:
        classes[item["class"]]["items"] += 1
        classes[item["class"]]["bytes"] += item["size_bytes"]
    status = "empty" if not candidates and not warnings else "partial" if warnings else "ok"
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "plan_id": compute_plan_id(root, candidates),
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "root": str(Path(root).expanduser().resolve(strict=False)),
        "read_only": True,
        "mutation_performed": False,
        "execution_available": False,
        "future_execution_requires_confirmation": True,
        "future_confirmation_phrase": CONFIRMATION_PHRASE,
        "summary": {
            "candidate_items": len(candidates),
            "candidate_bytes": sum(c["size_bytes"] for c in candidates),
            "classes": classes,
            "excluded_items": len(excluded),
            "warnings_count": len(warnings),
        },
        "candidates": candidates,
        "excluded": excluded,
        "future_archive_contract": {
            "archive_format": "tar.zst|tar.gz|directory_bundle_future",
            "delete_sources_by_default": False,
            "move_sources_by_default": False,
            "copy_sources_first": True,
            "verify_archive_before_any_source_change": True,
            "receipt_required": True,
            "manifest_required": True,
            "checksums_required": True,
            "rollback_instructions_required": True,
            "future_execution_requires_exact_plan_id": True,
            "future_execution_requires_bounded_candidate_classes": True,
            "future_execution_requires_validated_candidate_manifest": True,
            "future_execution_requires_archive_output_target": True,
            "future_execution_requires_receipt_output_target": True,
            "future_execution_requires_dry_run_preview_first": True,
            "future_execution_requires_operator_review": True,
            "source_deletion_is_not_part_of_this_pr": True,
        },
        "safety": safety_block(),
        "warnings": warnings,
        "first_safe_command": FIRST_SAFE_COMMAND,
    }


def render_summary(plan: dict[str, Any]) -> str:
    active_classes = [
        f"{k}: {v['items']} items / {v['bytes']} bytes"
        for k, v in plan["summary"]["classes"].items()
        if v["items"]
    ]
    classes = "; ".join(active_classes) if active_classes else "none"
    return "\n".join(
        [
            "# Docker01 ShellForgeAI Artifact Archive Plan",
            "",
            "Status:",
            f"Plan ID: {plan['plan_id']}",
            f"Root: {plan['root']}",
            "Read-only: yes",
            "Execution available: no",
            "",
            "## Candidate summary",
            f"* items: {plan['summary']['candidate_items']}",
            f"* estimated bytes: {plan['summary']['candidate_bytes']}",
            f"* classes: {classes}",
            "",
            "## Explicit exclusions",
            "* Docker volumes",
            "* Docker images",
            "* running containers",
            "* current compose/source/runtime paths",
            "* unmatched arbitrary files",
            "",
            "## Future execution contract",
            "* future execution requires exact plan id",
            "* future execution requires confirmation phrase: "
            f"{plan['future_confirmation_phrase']}",
            "* future execution must copy/archive first",
            "* future execution must verify manifest/checksums before any source change",
            "* source deletion is not part of this PR",
            "",
            "## Safety",
            "* no archive created",
            "* no source moved",
            "* no source deleted",
            "* no cleanup/prune/delete/restart",
            "* no remediation/rollback/recovery",
            "* no natural-language execution",
            "* no " + "shell=" + "True",
            "",
        ]
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_outputs(plan: dict[str, Any], out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "artifact-archive-plan.json").write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n"
    )
    (out / "artifact-archive-plan-summary.md").write_text(render_summary(plan))
    (out / "candidate-manifest.json").write_text(
        json.dumps(
            {"plan_id": plan["plan_id"], "candidates": plan["candidates"]}, indent=2, sort_keys=True
        )
        + "\n"
    )
    (out / "excluded-candidates.json").write_text(
        json.dumps(
            {"plan_id": plan["plan_id"], "excluded": plan["excluded"]}, indent=2, sort_keys=True
        )
        + "\n"
    )
    (out / "safety-notes.md").write_text(
        render_summary(plan).split("## Safety", 1)[1].join(["# Safety Notes\n\n", ""])
    )
    manifest_files = []
    for name in REQUIRED_OUT_FILES:
        if name in {"manifest.json", "checksums.json"}:
            continue
        p = out / name
        manifest_files.append({"path": str(p), "name": name, "size_bytes": p.stat().st_size})
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "plan_id": plan["plan_id"],
                "files": manifest_files,
                "archive_created": False,
                "candidate_contents_copied": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    checksum_files = [
        *manifest_files,
        {
            "path": str(out / "manifest.json"),
            "name": "manifest.json",
            "size_bytes": (out / "manifest.json").stat().st_size,
        },
    ]
    checksums = {
        item["name"]: "sha256:" + sha256_file(out / item["name"]) for item in checksum_files
    }
    (out / "checksums.json").write_text(
        json.dumps({"plan_id": plan["plan_id"], "checksums": checksums}, indent=2, sort_keys=True)
        + "\n"
    )


def validation_safety_block() -> dict[str, bool]:
    return {
        "read_only": True,
        "validation_only": True,
        "mutation_performed": False,
        "archive_created": False,
        "source_copied": False,
        "source_moved": False,
        "source_deleted": False,
        "source_modified": False,
        "cleanup_executed": False,
        "docker_prune_executed": False,
        "docker_image_removed": False,
        "file_deleted": False,
        "docker_compose_executed": False,
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


def _load_plan_json(path: Path) -> Any | None:
    """Read and parse a plan JSON file without following symlinks or over-reading."""
    try:
        if path.is_symlink() or not path.is_file():
            return None
        if path.stat().st_size > MAX_PLAN_FILE_BYTES:
            return None
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def validate_plan(plan_dir: str, *, max_candidates: int = DEFAULT_MAX_RETURNED) -> dict[str, Any]:
    """Validate an existing PR231 archive-plan directory. Strictly read-only."""
    plan_path = Path(plan_dir)
    checks: list[dict[str, str]] = []
    errors: list[str] = []
    warnings: list[str] = []

    def record(name: str, ok: bool, detail: str = "") -> bool:
        checks.append({"name": name, "status": "passed" if ok else "failed", "detail": detail})
        if not ok:
            errors.append(f"{name}: {detail}" if detail else name)
        return ok

    # 1. required files exist (and are real files, never symlinks)
    missing = [
        name
        for name in REQUIRED_OUT_FILES
        if not (plan_path / name).is_file() or (plan_path / name).is_symlink()
    ]
    record(
        "required_files_present",
        not missing,
        ("missing/invalid: " + ", ".join(missing)) if missing else "",
    )

    # 2. JSON files parse + bounded
    json_names = [n for n in REQUIRED_OUT_FILES if n.endswith(".json")]
    parsed: dict[str, Any] = {}
    unparsable: list[str] = []
    for name in json_names:
        data = _load_plan_json(plan_path / name)
        if data is None:
            unparsable.append(name)
        else:
            parsed[name] = data
    record(
        "json_parse_ok",
        not unparsable,
        ("unparsable: " + ", ".join(unparsable)) if unparsable else "",
    )

    plan = parsed.get("artifact-archive-plan.json") or {}
    candidate_manifest = parsed.get("candidate-manifest.json") or {}
    manifest = parsed.get("manifest.json") or {}
    checksums_doc = parsed.get("checksums.json") or {}
    plan_id = plan.get("plan_id") if isinstance(plan, dict) else None

    # 3. plan id present and well-formed
    record(
        "plan_id_ok",
        isinstance(plan_id, str) and bool(PLAN_ID_RE.match(plan_id)),
        f"plan_id={plan_id!r}",
    )

    # 4. manifest: every listed file exists with matching size
    manifest_files = manifest.get("files", []) if isinstance(manifest, dict) else []
    manifest_ok = isinstance(manifest_files, list) and bool(manifest_files)
    manifest_detail = ""
    if not manifest_ok:
        manifest_detail = "manifest missing files list"
    else:
        for entry in manifest_files:
            name = entry.get("name") if isinstance(entry, dict) else None
            if not name:
                manifest_ok = False
                manifest_detail = "manifest entry missing name"
                break
            target = plan_path / name
            if target.is_symlink() or not target.is_file():
                manifest_ok = False
                manifest_detail = f"manifest file missing: {name}"
                break
            if int(entry.get("size_bytes", -1)) != target.stat().st_size:
                manifest_ok = False
                manifest_detail = f"manifest size mismatch: {name}"
                break
    record("manifest_ok", manifest_ok, manifest_detail)

    # 5. checksums: sha256 + size metadata match current plan output files
    checksums = checksums_doc.get("checksums", {}) if isinstance(checksums_doc, dict) else {}
    checksums_ok = isinstance(checksums, dict) and bool(checksums)
    checksums_detail = ""
    if not checksums_ok:
        checksums_detail = "checksums missing"
    else:
        for name, recorded in checksums.items():
            target = plan_path / name
            if target.is_symlink() or not target.is_file():
                checksums_ok = False
                checksums_detail = f"checksum file missing: {name}"
                break
            actual = "sha256:" + sha256_file(target)
            if actual != recorded:
                checksums_ok = False
                checksums_detail = f"checksum mismatch: {name}"
                break
    record("checksums_ok", checksums_ok, checksums_detail)

    # 6. read_only / mutation / execution flags on the plan
    record("read_only", plan.get("read_only") is True, "read_only must be true")
    record(
        "mutation_not_performed",
        plan.get("mutation_performed") is False,
        "mutation_performed must be false",
    )
    record(
        "execution_unavailable",
        plan.get("execution_available") is False,
        "execution_available must be false",
    )

    # 7. candidate manifest bounded + only known ShellForgeAI patterns / safe paths
    cands = candidate_manifest.get("candidates", []) if isinstance(candidate_manifest, dict) else []
    candidate_ok = isinstance(cands, list) and len(cands) <= max_candidates
    candidate_detail = "" if candidate_ok else f"candidate count exceeds bound ({len(cands)})"
    symlink_ok = True
    scope_ok = True
    for cand in cands if isinstance(cands, list) else []:
        path_str = cand.get("path", "") if isinstance(cand, dict) else ""
        cand_path = Path(path_str)
        # never follow symlinks: reject by lstat-only check
        if cand_path.is_symlink():
            symlink_ok = False
            candidate_detail = candidate_detail or f"symlink candidate rejected: {path_str}"
            break
        name = cand_path.name
        if (
            name in RUNTIME_NAMES
            or str(cand_path).startswith(("/var/lib/docker", "/srv/compose", "/workspace"))
            or class_for_name(name) is None
        ):
            scope_ok = False
            candidate_detail = candidate_detail or f"out-of-scope candidate: {path_str}"
            break
        if isinstance(cand, dict) and cand.get("class") != class_for_name(name):
            scope_ok = False
            candidate_detail = candidate_detail or f"candidate class mismatch: {path_str}"
            break
    record("candidate_symlinks_rejected", symlink_ok, candidate_detail if not symlink_ok else "")
    record(
        "candidate_scope_bounded",
        candidate_ok and scope_ok,
        candidate_detail if not (candidate_ok and scope_ok) else "",
    )

    # 8. future confirmation phrase + future contract
    record(
        "confirmation_phrase_present",
        plan.get("future_confirmation_phrase") == CONFIRMATION_PHRASE,
        "missing CONFIRM_SHELLFORGEAI_ARTIFACT_ARCHIVE phrase",
    )
    contract = plan.get("future_archive_contract", {}) if isinstance(plan, dict) else {}
    record(
        "future_contract_no_execution",
        plan.get("execution_available") is False
        and contract.get("source_deletion_is_not_part_of_this_pr") is True,
        "future contract must keep execution unavailable and source deletion out of scope",
    )

    # 9. plan safety flags: no mutation of any kind
    safety = plan.get("safety", {}) if isinstance(plan, dict) else {}
    safety_ok = safety.get("read_only") is True
    safety_detail = "" if safety_ok else "safety.read_only must be true"
    if safety_ok:
        for flag in PLAN_MUTATION_FLAGS:
            if safety.get(flag) is not False:
                safety_ok = False
                safety_detail = f"safety flag must be false: {flag}"
                break
    if safety_ok and isinstance(manifest, dict):
        if manifest.get("archive_created") is not False:
            safety_ok = False
            safety_detail = "manifest.archive_created must be false"
        elif manifest.get("candidate_contents_copied") is not False:
            safety_ok = False
            safety_detail = "manifest.candidate_contents_copied must be false"
    record("safety_flags_clear", safety_ok, safety_detail)

    if isinstance(plan, dict) and plan.get("warnings"):
        warnings.append(f"plan carried {len(plan['warnings'])} discovery warning(s)")

    candidate_count = len(cands) if isinstance(cands, list) else 0
    status = "failed" if errors else ("partial" if warnings else "passed")
    passed_checks = sum(1 for c in checks if c["status"] == "passed")
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": VALIDATION_MODE,
        "status": status,
        "validated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "plan_dir": str(plan_path),
        "plan_id": plan_id,
        "read_only": True,
        "mutation_performed": False,
        "future_execution_available": False,
        "future_execution_eligible_for_review": status == "passed",
        "summary": {
            "checks_total": len(checks),
            "checks_passed": passed_checks,
            "checks_failed": len(checks) - passed_checks,
            "errors_count": len(errors),
            "warnings_count": len(warnings),
            "candidate_items": candidate_count,
        },
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": validation_safety_block(),
    }


def render_validation_summary(result: dict[str, Any]) -> str:
    failed = [c["name"] for c in result["checks"] if c["status"] == "failed"]
    lines = [
        "# Docker01 ShellForgeAI Artifact Archive Plan Validation",
        "",
        f"Plan dir: {result['plan_dir']}",
        f"Plan ID: {result['plan_id']}",
        f"Validation status: {result['status']}",
        "Read-only: yes",
        "Future execution available: no",
        "",
        "## Checks",
        f"* passed: {result['summary']['checks_passed']}/{result['summary']['checks_total']}",
        f"* failed: {', '.join(failed) if failed else 'none'}",
        f"* candidate items: {result['summary']['candidate_items']}",
    ]
    if result["errors"]:
        lines.append("")
        lines.append("## Errors")
        lines.extend(f"* {e}" for e in result["errors"])
    lines += [
        "",
        "## Safety",
        "* no archive created",
        "* no source copied",
        "* no source moved",
        "* no source deleted",
        "* no cleanup/prune/restart/remediation/rollback/recovery",
        "* validation is read-only; future execution remains unavailable",
        "* no " + "shell=" + "True",
        "",
    ]
    return "\n".join(lines)


def write_validation_outputs(result: dict[str, Any], out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "artifact-archive-plan-validation.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    (out / "artifact-archive-plan-validation-summary.md").write_text(
        render_validation_summary(result)
    )
    manifest_files = []
    for name in VALIDATION_OUT_FILES:
        if name in {"manifest.json", "checksums.json"}:
            continue
        p = out / name
        manifest_files.append({"path": str(p), "name": name, "size_bytes": p.stat().st_size})
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "plan_id": result["plan_id"],
                "mode": VALIDATION_MODE,
                "files": manifest_files,
                "archive_created": False,
                "candidate_contents_copied": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    checksum_names = [item["name"] for item in manifest_files] + ["manifest.json"]
    checksums = {name: "sha256:" + sha256_file(out / name) for name in checksum_names}
    (out / "checksums.json").write_text(
        json.dumps({"plan_id": result["plan_id"], "checksums": checksums}, indent=2, sort_keys=True)
        + "\n"
    )


def dry_run_receipt_safety_block() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "dry_run_only": True,
        "archive_created": False,
        "source_copied": False,
        "source_moved": False,
        "source_deleted": False,
        "source_modified": False,
        "cleanup_executed": False,
        "docker_prune_executed": False,
        "docker_image_removed": False,
        "docker_volume_removed": False,
        "file_deleted": False,
        "docker_compose_executed": False,
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


def _candidate_class_summary(candidates: list[Any]) -> dict[str, dict[str, int]]:
    classes = {c.name: {"items": 0, "bytes": 0} for c in CANDIDATE_CLASSES}
    for item in candidates:
        if not isinstance(item, dict):
            continue
        class_name = item.get("class")
        if class_name not in classes:
            continue
        classes[class_name]["items"] += 1
        classes[class_name]["bytes"] += int(item.get("size_bytes", 0) or 0)
    return classes


def build_dry_run_receipt(
    plan_dir: str,
    *,
    supplied_plan_id: str | None,
    max_candidates: int = DEFAULT_MAX_RETURNED,
) -> dict[str, Any]:
    """Build a read-only dry-run receipt for a validated archive plan."""
    validation = validate_plan(plan_dir, max_candidates=max_candidates)
    errors = list(validation["errors"])
    warnings = list(validation["warnings"])
    expected_plan_id = validation.get("plan_id")

    if not supplied_plan_id:
        errors.append("plan_id_required: --plan-id is required")
    elif supplied_plan_id != expected_plan_id:
        errors.append(
            f"plan_id_mismatch: expected {expected_plan_id!r}, supplied {supplied_plan_id!r}"
        )

    plan_path = Path(plan_dir)
    candidate_manifest = _load_plan_json(plan_path / "candidate-manifest.json") or {}
    excluded_doc = _load_plan_json(plan_path / "excluded-candidates.json") or {}
    candidates = (
        candidate_manifest.get("candidates", []) if isinstance(candidate_manifest, dict) else []
    )
    excluded = excluded_doc.get("excluded", []) if isinstance(excluded_doc, dict) else []
    if not isinstance(candidates, list):
        candidates = []
    if not isinstance(excluded, list):
        excluded = []

    validation_status = validation["status"]
    if validation_status != "failed" and errors:
        validation_status = "failed"
    status = "ready_for_review" if validation_status == "passed" and not errors else "failed"

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": DRY_RUN_RECEIPT_MODE,
        "status": status,
        "plan_dir": str(plan_path),
        "plan_id": expected_plan_id,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "read_only": True,
        "mutation_performed": False,
        "execution_available": False,
        "dry_run_only": True,
        "plan_validation": {
            "status": validation_status,
            "errors": errors,
            "warnings": warnings,
        },
        "summary": {
            "candidate_items": len(candidates),
            "candidate_bytes": sum(int(c.get("size_bytes", 0) or 0) for c in candidates),
            "candidate_classes": _candidate_class_summary(candidates),
            "excluded_items": len(excluded),
            "future_archive_allowed_classes": sorted(
                {c.get("class") for c in candidates if isinstance(c, dict) and c.get("class")}
            ),
            "future_archive_out_of_scope": list(EXPLICIT_EXCLUSIONS),
        },
        "future_execution_contract": {
            "future_execution_available_in_this_pr": False,
            "future_execution_requires_exact_plan_id": True,
            "future_execution_requires_confirmation": True,
            "future_confirmation_phrase": CONFIRMATION_PHRASE,
            "future_archive_must_copy_first": True,
            "future_archive_must_verify_manifest_before_source_change": True,
            "future_source_delete_default": False,
            "future_source_move_default": False,
            "receipt_required": True,
            "manifest_required": True,
            "checksums_required": True,
            "rollback_instructions_required": True,
        },
        "would_do_in_future_pr_only": [
            "create archive bundle from candidate manifest",
            "write archive manifest",
            "write archive checksums",
            "write archive receipt",
            "verify archive before any source change",
        ],
        "will_not_do": [
            "create archive in this PR",
            "copy source files in this PR",
            "move source files in this PR",
            "delete source files in this PR",
            "cleanup/prune/delete/restart/remediate/rollback/recover",
        ],
        "safety": dry_run_receipt_safety_block(),
        "warnings": warnings,
        "errors": errors,
        "first_safe_command": (
            "python3 scripts/docker01_artifact_archive_plan.py --dry-run-receipt "
            "<plan_dir> --plan-id <plan_id> --json"
        ),
    }


def render_dry_run_receipt_summary(receipt: dict[str, Any]) -> str:
    classes = receipt["summary"]["candidate_classes"]
    errors = receipt["plan_validation"]["errors"]
    warnings = receipt["plan_validation"]["warnings"]
    active = [
        f"{k}: {v['items']} items / {v['bytes']} bytes" for k, v in classes.items() if v["items"]
    ]
    return "\n".join(
        [
            "# Docker01 Artifact Archive Dry-Run Receipt",
            "",
            f"Plan: {receipt['plan_dir']}",
            f"Plan ID: {receipt['plan_id']}",
            f"Status: {receipt['status']}",
            "Read-only: yes",
            "Execution available: no",
            "",
            "## Plan validation",
            f"* status: {receipt['plan_validation']['status']}",
            f"* errors: {', '.join(errors) if errors else 'none'}",
            f"* warnings: {', '.join(warnings) if warnings else 'none'}",
            "",
            "## Future archive preview",
            f"* candidate items: {receipt['summary']['candidate_items']}",
            f"* estimated bytes: {receipt['summary']['candidate_bytes']}",
            f"* candidate classes: {'; '.join(active) if active else 'none'}",
            f"* excluded items: {receipt['summary']['excluded_items']}",
            "",
            "## Future execution contract",
            "* exact plan id required",
            "* confirmation phrase required",
            "* archive must be verified before any source change",
            "* source deletion is not part of this PR",
            "* source move is not part of this PR",
            "",
            "## Safety",
            "* dry-run only",
            "* no archive created",
            "* no source copied",
            "* no source moved",
            "* no source deleted",
            "* no cleanup/prune/delete/restart",
            "* no remediation/rollback/recovery",
            "* no natural-language execution",
            "* no " + "shell=" + "True",
            "",
        ]
    )


def render_future_execution_checklist(receipt: dict[str, Any]) -> str:
    c = receipt["future_execution_contract"]
    return "\n".join(
        [
            "# Future Execution Checklist",
            "",
            "Future PR only; execution is not implemented here.",
            f"* exact plan id required: {c['future_execution_requires_exact_plan_id']}",
            f"* confirmation phrase: {c['future_confirmation_phrase']}",
            "* copy/archive first before any source change",
            "* verify manifest and checksums before any source change",
            "* receipt, manifest, checksums, and rollback instructions required",
            "* source deletion default: false",
            "* source move default: false",
            "",
        ]
    )


def write_dry_run_receipt_outputs(receipt: dict[str, Any], out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    plan_path = Path(receipt["plan_dir"])
    (out / "artifact-archive-dry-run-receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    )
    (out / "artifact-archive-dry-run-summary.md").write_text(
        render_dry_run_receipt_summary(receipt)
    )
    for name in ("candidate-manifest.json", "excluded-candidates.json"):
        data = _load_plan_json(plan_path / name) or {}
        (out / name).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    (out / "future-execution-checklist.md").write_text(render_future_execution_checklist(receipt))
    (out / "safety-notes.md").write_text(
        "# Safety Notes\n\n"
        "* dry-run receipt only\n"
        "* no archive created\n"
        "* no source copied, moved, modified, or deleted\n"
        "* no cleanup/prune/restart/remediation/rollback/recovery\n"
        "* execution remains unavailable in this PR\n"
    )
    manifest_files = []
    for name in DRY_RUN_RECEIPT_OUT_FILES:
        if name in {"manifest.json", "checksums.json"}:
            continue
        p = out / name
        manifest_files.append({"path": str(p), "name": name, "size_bytes": p.stat().st_size})
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "plan_id": receipt["plan_id"],
                "mode": DRY_RUN_RECEIPT_MODE,
                "files": manifest_files,
                "archive_created": False,
                "candidate_contents_copied": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    checksum_names = [item["name"] for item in manifest_files] + ["manifest.json"]
    checksums = {name: "sha256:" + sha256_file(out / name) for name in checksum_names}
    (out / "checksums.json").write_text(
        json.dumps(
            {"plan_id": receipt["plan_id"], "checksums": checksums}, indent=2, sort_keys=True
        )
        + "\n"
    )


def receipt_validation_safety_block() -> dict[str, bool]:
    safety = validation_safety_block()
    safety["dry_run_only"] = True
    safety["docker_volume_removed"] = False
    return safety


def _add_check(
    checks: list[dict[str, str]],
    errors: list[str],
    warnings: list[str],
    name: str,
    status: str,
    detail: str = "",
) -> None:
    checks.append({"name": name, "status": status, "detail": detail})
    if status == "failed":
        errors.append(f"{name}: {detail}" if detail else name)
    elif status == "warning":
        warnings.append(f"{name}: {detail}" if detail else name)


def _safe_candidates(candidates: Any) -> tuple[bool, str, int, int, dict[str, dict[str, int]]]:
    if not isinstance(candidates, list):
        return False, "candidates must be a list", 0, 0, _candidate_class_summary([])
    total_bytes = 0
    for item in candidates:
        if not isinstance(item, dict):
            return False, "candidate entry must be object", 0, 0, _candidate_class_summary([])
        path_str = item.get("path", "")
        cand_path = Path(path_str)
        if cand_path.is_symlink():
            return (
                False,
                f"symlink candidate rejected: {path_str}",
                0,
                0,
                _candidate_class_summary([]),
            )
        class_name = class_for_name(cand_path.name)
        if (
            not path_str
            or cand_path.name in RUNTIME_NAMES
            or str(cand_path).startswith(("/var/lib/docker", "/srv/compose", "/workspace"))
            or class_name is None
        ):
            return False, f"out-of-scope candidate: {path_str}", 0, 0, _candidate_class_summary([])
        if item.get("class") != class_name:
            return (
                False,
                f"candidate class mismatch: {path_str}",
                0,
                0,
                _candidate_class_summary([]),
            )
        total_bytes += int(item.get("size_bytes", 0) or 0)
    return True, "", len(candidates), total_bytes, _candidate_class_summary(candidates)


def validate_dry_run_receipt(
    receipt_dir: str,
    *,
    plan_dir: str | None = None,
    max_candidates: int = DEFAULT_MAX_RETURNED,
) -> dict[str, Any]:
    """Validate a PR233 dry-run receipt directory. Strictly read-only."""
    receipt_path = Path(receipt_dir)
    checks: list[dict[str, str]] = []
    errors: list[str] = []
    warnings: list[str] = []

    missing = [
        name
        for name in DRY_RUN_RECEIPT_OUT_FILES
        if not (receipt_path / name).is_file() or (receipt_path / name).is_symlink()
    ]
    _add_check(
        checks,
        errors,
        warnings,
        "required_files_present",
        "failed" if missing else "passed",
        ", ".join(missing),
    )

    parsed: dict[str, Any] = {}
    unparsable: list[str] = []
    for name in [n for n in DRY_RUN_RECEIPT_OUT_FILES if n.endswith(".json")]:
        data = _load_plan_json(receipt_path / name)
        if data is None:
            unparsable.append(name)
        else:
            parsed[name] = data
    _add_check(
        checks,
        errors,
        warnings,
        "json_parse_ok",
        "failed" if unparsable else "passed",
        ", ".join(unparsable),
    )

    receipt = parsed.get("artifact-archive-dry-run-receipt.json") or {}
    candidate_manifest = parsed.get("candidate-manifest.json") or {}
    excluded_doc = parsed.get("excluded-candidates.json") or {}
    manifest = parsed.get("manifest.json") or {}
    checksums_doc = parsed.get("checksums.json") or {}
    plan_id = receipt.get("plan_id") if isinstance(receipt, dict) else None

    manifest_files = manifest.get("files", []) if isinstance(manifest, dict) else []
    manifest_ok = isinstance(manifest_files, list) and bool(manifest_files)
    manifest_detail = "" if manifest_ok else "manifest missing files list"
    if manifest_ok:
        for entry in manifest_files:
            name = entry.get("name") if isinstance(entry, dict) else None
            target = receipt_path / str(name)
            if not name or target.is_symlink() or not target.is_file():
                manifest_ok = False
                manifest_detail = f"manifest file missing: {name}"
                break
            if int(entry.get("size_bytes", -1)) != target.stat().st_size:
                manifest_ok = False
                manifest_detail = f"manifest size mismatch: {name}"
                break
    _add_check(
        checks,
        errors,
        warnings,
        "manifest_ok",
        "passed" if manifest_ok else "failed",
        manifest_detail,
    )

    checksums = checksums_doc.get("checksums", {}) if isinstance(checksums_doc, dict) else {}
    checksums_ok = isinstance(checksums, dict) and bool(checksums)
    checksums_detail = "" if checksums_ok else "checksums missing"
    if checksums_ok:
        for name, recorded in checksums.items():
            target = receipt_path / name
            if target.is_symlink() or not target.is_file():
                checksums_ok = False
                checksums_detail = f"checksum file missing: {name}"
                break
            if "sha256:" + sha256_file(target) != recorded:
                checksums_ok = False
                checksums_detail = f"checksum mismatch: {name}"
                break
    _add_check(
        checks,
        errors,
        warnings,
        "checksums_ok",
        "passed" if checksums_ok else "failed",
        checksums_detail,
    )

    safety = receipt.get("safety", {}) if isinstance(receipt, dict) else {}
    unsafe_flags = [
        "mutation_performed",
        "archive_created",
        "source_copied",
        "source_moved",
        "source_deleted",
        "source_modified",
        "cleanup_executed",
        "docker_prune_executed",
        "docker_image_removed",
        "docker_volume_removed",
        "file_deleted",
        "docker_compose_executed",
        "container_restarted",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
        "natural_language_execution",
        "shell_true",
        "arbitrary_command_execution",
        "cloud_apply_merge_push",
        "github_post_approve_merge",
    ]
    safety_ok = receipt.get("read_only") is True and receipt.get("mutation_performed") is False
    safety_detail = ""
    if safety_ok and receipt.get("execution_available") is not False:
        safety_ok = False
        safety_detail = "execution_available must be false"
    if safety_ok and safety.get("read_only") is not True:
        safety_ok = False
        safety_detail = "safety.read_only must be true"
    if safety_ok:
        for flag in unsafe_flags:
            if safety.get(flag) is not False:
                safety_ok = False
                safety_detail = f"safety flag must be false: {flag}"
                break
    if safety_ok and isinstance(manifest, dict):
        for flag in ("archive_created", "candidate_contents_copied"):
            if manifest.get(flag) is not False:
                safety_ok = False
                safety_detail = f"manifest.{flag} must be false"
                break
    _add_check(
        checks,
        errors,
        warnings,
        "receipt_safety_ok",
        "passed" if safety_ok else "failed",
        safety_detail,
    )

    contract = receipt.get("future_execution_contract", {}) if isinstance(receipt, dict) else {}
    future_ok = (
        isinstance(plan_id, str)
        and bool(PLAN_ID_RE.match(plan_id))
        and contract.get("future_execution_available_in_this_pr") is False
        and contract.get("future_confirmation_phrase") == CONFIRMATION_PHRASE
        and contract.get("future_execution_requires_confirmation") is True
    )
    will_not = (
        " ".join(receipt.get("will_not_do", []))
        if isinstance(receipt.get("will_not_do"), list)
        else ""
    )
    if "delete source" not in will_not and "source files" not in will_not:
        future_ok = False
    _add_check(
        checks,
        errors,
        warnings,
        "future_contract_ok",
        "passed" if future_ok else "failed",
        "confirmation/deletion/execution contract invalid" if not future_ok else "",
    )

    candidates = (
        candidate_manifest.get("candidates", []) if isinstance(candidate_manifest, dict) else []
    )
    cand_ok, cand_detail, cand_count, cand_bytes, cand_classes = _safe_candidates(candidates)
    if cand_count > max_candidates:
        cand_ok = False
        cand_detail = "candidate count exceeds bound"
    summary = receipt.get("summary", {}) if isinstance(receipt, dict) else {}
    if cand_ok and (
        summary.get("candidate_items") != cand_count or summary.get("candidate_bytes") != cand_bytes
    ):
        cand_ok = False
        cand_detail = "receipt candidate totals mismatch manifest"
    _add_check(
        checks,
        errors,
        warnings,
        "candidate_manifest_ok",
        "passed" if cand_ok else "failed",
        cand_detail,
    )

    cross_status = "not_requested"
    if plan_dir:
        plan_validation = validate_plan(plan_dir, max_candidates=max_candidates)
        if plan_validation["status"] == "failed":
            cross_status = "failed"
            _add_check(
                checks, errors, warnings, "plan_cross_check", "failed", "plan validation failed"
            )
        else:
            plan_path = Path(plan_dir)
            plan_candidate_doc = _load_plan_json(plan_path / "candidate-manifest.json") or {}
            plan_excluded_doc = _load_plan_json(plan_path / "excluded-candidates.json") or {}
            plan_candidates = (
                plan_candidate_doc.get("candidates", [])
                if isinstance(plan_candidate_doc, dict)
                else []
            )
            p_ok, _, p_count, p_bytes, p_classes = _safe_candidates(plan_candidates)
            plan_excluded = (
                plan_excluded_doc.get("excluded", []) if isinstance(plan_excluded_doc, dict) else []
            )
            excluded = excluded_doc.get("excluded", []) if isinstance(excluded_doc, dict) else []
            same_excluded = (
                len(excluded) <= len(plan_excluded)
                if isinstance(excluded, list) and isinstance(plan_excluded, list)
                else False
            )
            ok = (
                p_ok
                and plan_validation.get("plan_id") == plan_id
                and p_count == cand_count
                and p_bytes == cand_bytes
                and p_classes == cand_classes
                and same_excluded
                and contract.get("future_confirmation_phrase") == CONFIRMATION_PHRASE
            )
            cross_status = "passed" if ok else "failed"
            _add_check(
                checks,
                errors,
                warnings,
                "plan_cross_check",
                cross_status,
                "receipt does not match supplied plan" if not ok else "",
            )
    else:
        _add_check(checks, errors, warnings, "plan_cross_check", "warning", "not_requested")

    blocker_errors = [e for e in errors if not e.startswith("plan_cross_check: not_requested")]
    status = "failed" if blocker_errors else ("partial" if warnings else "passed")
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": DRY_RUN_RECEIPT_VALIDATION_MODE,
        "status": status,
        "receipt_dir": str(receipt_path),
        "plan_dir": str(Path(plan_dir)) if plan_dir else None,
        "plan_id": plan_id,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "required_files_present": not missing,
            "json_parse_ok": not unparsable,
            "manifest_ok": manifest_ok,
            "checksums_ok": checksums_ok,
            "receipt_safety_ok": safety_ok,
            "future_contract_ok": future_ok,
            "candidate_manifest_ok": cand_ok,
            "plan_cross_check_status": cross_status,
            "candidate_items": cand_count,
            "candidate_bytes": cand_bytes,
            "validation_errors": len(blocker_errors),
            "validation_warnings": len(warnings),
        },
        "checks": checks,
        "errors": blocker_errors,
        "warnings": warnings,
        "future_execution_eligible_for_review": status in {"passed", "partial"}
        and not blocker_errors,
        "future_execution_available": False,
        "safety": receipt_validation_safety_block(),
        "first_safe_command": (
            "python3 scripts/docker01_artifact_archive_plan.py "
            "--validate-dry-run-receipt <dry_run_receipt_dir> --json"
        ),
    }


def render_dry_run_receipt_validation_summary(result: dict[str, Any]) -> str:
    by_name = {c["name"]: c["status"] for c in result["checks"]}
    return "\n".join(
        [
            "# Docker01 Artifact Archive Dry-Run Receipt Validation",
            "",
            f"Receipt: {result['receipt_dir']}",
            f"Plan: {result['plan_dir']}",
            f"Plan ID: {result['plan_id']}",
            f"Status: {result['status']}",
            "Read-only: yes",
            "Execution available: no",
            "",
            "## Checks",
            f"* required files: {by_name.get('required_files_present')}",
            f"* JSON parse: {by_name.get('json_parse_ok')}",
            f"* manifest: {by_name.get('manifest_ok')}",
            f"* checksums: {by_name.get('checksums_ok')}",
            f"* receipt safety: {by_name.get('receipt_safety_ok')}",
            f"* candidate manifest: {by_name.get('candidate_manifest_ok')}",
            f"* future contract: {by_name.get('future_contract_ok')}",
            f"* plan cross-check: {result['summary']['plan_cross_check_status']}",
            "",
            "## Result",
            f"* {result['status']}",
            "",
            "## Safety",
            "* validation only",
            "* no archive created",
            "* no source copied",
            "* no source moved",
            "* no source deleted",
            "* no cleanup/prune/delete/restart",
            "* no remediation/rollback/recovery",
            "* no natural-language execution",
            "* no " + "shell=" + "True",
            "",
        ]
    )


def write_dry_run_receipt_validation_outputs(result: dict[str, Any], out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "artifact-archive-dry-run-receipt-validation.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    (out / "artifact-archive-dry-run-receipt-validation-summary.md").write_text(
        render_dry_run_receipt_validation_summary(result)
    )
    manifest_files = []
    for name in DRY_RUN_RECEIPT_VALIDATION_OUT_FILES:
        if name in {"manifest.json", "checksums.json"}:
            continue
        p = out / name
        manifest_files.append({"path": str(p), "name": name, "size_bytes": p.stat().st_size})
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "plan_id": result["plan_id"],
                "mode": DRY_RUN_RECEIPT_VALIDATION_MODE,
                "files": manifest_files,
                "archive_created": False,
                "candidate_contents_copied": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    checksum_names = [item["name"] for item in manifest_files] + ["manifest.json"]
    checksums = {name: "sha256:" + sha256_file(out / name) for name in checksum_names}
    (out / "checksums.json").write_text(
        json.dumps({"plan_id": result["plan_id"], "checksums": checksums}, indent=2, sort_keys=True)
        + "\n"
    )


def execution_readiness_safety_block() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "readiness_gate_only": True,
        "archive_created": False,
        "source_copied": False,
        "source_moved": False,
        "source_deleted": False,
        "source_modified": False,
        "cleanup_executed": False,
        "docker_prune_executed": False,
        "docker_image_removed": False,
        "docker_volume_removed": False,
        "file_deleted": False,
        "docker_compose_executed": False,
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


def _load_receipt_validation(validation_dir: str | None) -> dict[str, Any] | None:
    if not validation_dir:
        return None
    data = _load_plan_json(
        Path(validation_dir) / "artifact-archive-dry-run-receipt-validation.json"
    )
    return data if isinstance(data, dict) else None


def _same_candidates(plan_candidates: list[Any], receipt_candidates: list[Any]) -> bool:
    def key(candidate: dict[str, Any]) -> tuple[Any, ...]:
        return (
            candidate.get("path"),
            candidate.get("class"),
            candidate.get("type"),
            int(candidate.get("size_bytes", 0) or 0),
            candidate.get("future_action"),
        )

    return sorted(key(c) for c in plan_candidates if isinstance(c, dict)) == sorted(
        key(c) for c in receipt_candidates if isinstance(c, dict)
    )


def _same_exclusions(plan_excluded: Any, receipt_excluded: Any) -> bool:
    if not isinstance(plan_excluded, list) or not isinstance(receipt_excluded, list):
        return False

    def key(exclusion: dict[str, Any]) -> tuple[Any, ...]:
        return (exclusion.get("path"), exclusion.get("reason"))

    return sorted(key(e) for e in plan_excluded if isinstance(e, dict)) == sorted(
        key(e) for e in receipt_excluded if isinstance(e, dict)
    )


def build_execution_readiness(
    plan_dir: str,
    receipt_dir: str,
    *,
    receipt_validation_dir: str | None = None,
    max_candidates: int = DEFAULT_MAX_RETURNED,
) -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    errors: list[str] = []
    warnings: list[str] = []
    plan_path = Path(plan_dir)
    receipt_path = Path(receipt_dir)

    def add(name: str, ok: bool, detail: str = "", *, warning: bool = False) -> None:
        status = "warning" if warning else "passed" if ok else "failed"
        _add_check(checks, errors, warnings, name, status, detail)

    plan_validation = validate_plan(str(plan_path), max_candidates=max_candidates)
    receipt_validation = _load_receipt_validation(receipt_validation_dir)
    if receipt_validation is None:
        receipt_validation = validate_dry_run_receipt(
            str(receipt_path), plan_dir=str(plan_path), max_candidates=max_candidates
        )
        if receipt_validation_dir:
            add("receipt_validation_supplied", False, "could not parse supplied validation")
    elif receipt_validation.get("mode") != DRY_RUN_RECEIPT_VALIDATION_MODE:
        add("receipt_validation_supplied", False, "wrong receipt-validation mode")
    else:
        supplied_matches = receipt_validation.get("receipt_dir") == str(
            receipt_path
        ) and receipt_validation.get("plan_dir") == str(plan_path)
        add(
            "receipt_validation_supplied",
            supplied_matches,
            "used supplied receipt validation"
            if supplied_matches
            else "supplied validation does not match plan/receipt dirs",
        )

    add("plan_validation_passed", plan_validation["status"] == "passed", plan_validation["status"])
    add(
        "dry_run_receipt_validation_passed",
        receipt_validation.get("status") == "passed",
        str(receipt_validation.get("status")),
    )

    plan = _load_plan_json(plan_path / "artifact-archive-plan.json") or {}
    receipt = _load_plan_json(receipt_path / "artifact-archive-dry-run-receipt.json") or {}
    plan_manifest = _load_plan_json(plan_path / "candidate-manifest.json") or {}
    receipt_manifest = _load_plan_json(receipt_path / "candidate-manifest.json") or {}
    plan_excluded_doc = _load_plan_json(plan_path / "excluded-candidates.json") or {}
    receipt_excluded_doc = _load_plan_json(receipt_path / "excluded-candidates.json") or {}

    plan_id = plan.get("plan_id") if isinstance(plan, dict) else None
    receipt_plan_id = receipt.get("plan_id") if isinstance(receipt, dict) else None
    plan_id_match = isinstance(plan_id, str) and plan_id == receipt_plan_id
    add("plan_id_match", plan_id_match, f"plan={plan_id!r} receipt={receipt_plan_id!r}")

    plan_candidates = plan_manifest.get("candidates", []) if isinstance(plan_manifest, dict) else []
    receipt_candidates = (
        receipt_manifest.get("candidates", []) if isinstance(receipt_manifest, dict) else []
    )
    p_ok, p_detail, p_count, p_bytes, p_classes = _safe_candidates(plan_candidates)
    r_ok, r_detail, r_count, r_bytes, r_classes = _safe_candidates(receipt_candidates)
    add("candidate_paths_safe", p_ok and r_ok, p_detail or r_detail)
    add("candidate_count_match", p_count == r_count, f"plan={p_count} receipt={r_count}")
    add("candidate_bytes_match", p_bytes == r_bytes, f"plan={p_bytes} receipt={r_bytes}")
    add("candidate_class_match", p_classes == r_classes, "candidate class totals differ")
    candidate_manifest_match = (
        p_ok and r_ok and _same_candidates(plan_candidates, receipt_candidates)
    )
    add("candidate_manifest_match", candidate_manifest_match, "candidate manifest differs")

    exclusions_match = _same_exclusions(
        plan_excluded_doc.get("excluded", []) if isinstance(plan_excluded_doc, dict) else [],
        receipt_excluded_doc.get("excluded", []) if isinstance(receipt_excluded_doc, dict) else [],
    )
    add("exclusions_match", exclusions_match, "excluded candidate manifests differ")

    plan_contract = plan.get("future_archive_contract", {}) if isinstance(plan, dict) else {}
    receipt_contract = (
        receipt.get("future_execution_contract", {}) if isinstance(receipt, dict) else {}
    )
    future_contract_match = (
        plan.get("future_confirmation_phrase") == CONFIRMATION_PHRASE
        and receipt_contract.get("future_confirmation_phrase") == CONFIRMATION_PHRASE
        and plan_contract.get("delete_sources_by_default") is False
        and plan_contract.get("move_sources_by_default") is False
        and receipt_contract.get("future_source_delete_default") is False
        and receipt_contract.get("future_source_move_default") is False
        and receipt_contract.get("future_execution_available_in_this_pr") is False
    )
    add("future_contract_match", future_contract_match, "future execution contract mismatch")

    unsafe_seen = False
    for doc in (plan, receipt):
        if isinstance(doc, dict):
            if (
                doc.get("execution_available") is not False
                or doc.get("mutation_performed") is not False
            ):
                unsafe_seen = True
            safety = doc.get("safety", {})
            if isinstance(safety, dict):
                for flag in execution_readiness_safety_block():
                    if flag in {"read_only", "readiness_gate_only"}:
                        continue
                    if flag in safety and safety.get(flag) is not False:
                        unsafe_seen = True
    safety_contract_ok = not unsafe_seen
    add("safety_contract_ok", safety_contract_ok, "unsafe mutation/execution flag present")

    optional_missing = []
    for name in (
        "artifact-archive-plan-summary.md",
        "artifact-archive-dry-run-summary.md",
        "future-execution-checklist.md",
        "safety-notes.md",
    ):
        base = plan_path if name == "artifact-archive-plan-summary.md" else receipt_path
        if not (base / name).is_file():
            optional_missing.append(name)
    if optional_missing:
        add("optional_human_summaries_present", True, ", ".join(optional_missing), warning=True)

    core_ok = (
        plan_validation["status"] == "passed"
        and receipt_validation.get("status") == "passed"
        and plan_id_match
        and candidate_manifest_match
        and exclusions_match
        and future_contract_match
        and safety_contract_ok
        and not errors
    )
    status = (
        "ready_for_execution_review"
        if core_ok and not warnings
        else "partial"
        if core_ok
        else "not_ready"
    )
    if not isinstance(plan, dict) or not isinstance(receipt, dict):
        status = "failed"

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": EXECUTION_READINESS_MODE,
        "status": status,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "plan_dir": str(plan_path),
        "dry_run_receipt_dir": str(receipt_path),
        "receipt_validation_dir": str(Path(receipt_validation_dir))
        if receipt_validation_dir
        else None,
        "plan_id": plan_id,
        "read_only": True,
        "mutation_performed": False,
        "execution_available": False,
        "future_execution_review_only": True,
        "summary": {
            "plan_validation_status": plan_validation["status"],
            "dry_run_receipt_validation_status": receipt_validation.get("status", "failed"),
            "plan_id_match": plan_id_match,
            "candidate_manifest_match": candidate_manifest_match,
            "exclusions_match": exclusions_match,
            "future_contract_match": future_contract_match,
            "safety_contract_ok": safety_contract_ok,
            "candidate_items": p_count,
            "candidate_bytes": p_bytes,
            "candidate_classes": p_classes,
            "readiness_errors": len(errors),
            "readiness_warnings": len(warnings),
        },
        "checks": checks,
        "future_execution_requirements": {
            "separate_pr_required": True,
            "exact_plan_id_required": True,
            "exact_confirmation_phrase_required": True,
            "future_confirmation_phrase": CONFIRMATION_PHRASE,
            "archive_must_be_created_before_any_source_change": True,
            "archive_manifest_required": True,
            "archive_checksums_required": True,
            "archive_receipt_required": True,
            "archive_validation_required": True,
            "source_delete_default": False,
            "source_move_default": False,
            "operator_review_required": True,
        },
        "will_not_do": [
            "create archive in this PR",
            "copy source files in this PR",
            "move source files in this PR",
            "delete source files in this PR",
            "cleanup/prune/delete/restart/remediate/rollback/recover",
        ],
        "errors": errors,
        "warnings": warnings,
        "safety": execution_readiness_safety_block(),
        "first_safe_command": (
            "python3 scripts/docker01_artifact_archive_plan.py --execution-readiness "
            "<plan_dir> --dry-run-receipt <receipt_dir> --json"
        ),
    }


def render_execution_readiness_summary(result: dict[str, Any]) -> str:
    classes = result["summary"]["candidate_classes"]
    active = [
        f"{k}: {v['items']} items / {v['bytes']} bytes" for k, v in classes.items() if v["items"]
    ]
    return "\n".join(
        [
            "# Docker01 Artifact Archive Execution Readiness",
            "",
            f"Plan: {result['plan_dir']}",
            f"Dry-run receipt: {result['dry_run_receipt_dir']}",
            f"Plan ID: {result['plan_id']}",
            f"Status: {result['status']}",
            "Read-only: yes",
            "Execution available: no",
            "",
            "## Evidence chain",
            f"* plan validation: {result['summary']['plan_validation_status']}",
            (
                "* dry-run receipt validation: "
                f"{result['summary']['dry_run_receipt_validation_status']}"
            ),
            f"* plan id match: {result['summary']['plan_id_match']}",
            f"* candidate manifest match: {result['summary']['candidate_manifest_match']}",
            f"* exclusions match: {result['summary']['exclusions_match']}",
            f"* future contract: {result['summary']['future_contract_match']}",
            f"* safety contract: {result['summary']['safety_contract_ok']}",
            "",
            "## Candidate summary",
            f"* items: {result['summary']['candidate_items']}",
            f"* estimated bytes: {result['summary']['candidate_bytes']}",
            f"* classes: {'; '.join(active) if active else 'none'}",
            "",
            "## Future execution requirements",
            "* separate PR/lane required",
            "* exact plan id required",
            "* confirmation phrase required",
            "* archive must be created and verified before any source change",
            "* source delete default: false",
            "* source move default: false",
            "",
            "## Safety",
            "* readiness gate only",
            "* no archive created",
            "* no source copied",
            "* no source moved",
            "* no source deleted",
            "* no cleanup/prune/delete/restart",
            "* no remediation/rollback/recovery",
            "* no natural-language execution",
            "* no " + "shell=" + "True",
            "",
        ]
    )


def write_execution_readiness_outputs(result: dict[str, Any], out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "artifact-archive-execution-readiness.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    (out / "artifact-archive-execution-readiness-summary.md").write_text(
        render_execution_readiness_summary(result)
    )
    (out / "future-execution-checklist.md").write_text(
        "# Future Execution Checklist\n\n"
        "* separate PR/lane required\n"
        f"* exact plan id required: {result['plan_id']}\n"
        f"* confirmation phrase: {CONFIRMATION_PHRASE}\n"
        "* archive must be created and verified before any source change\n"
        "* source delete default: false\n"
        "* source move default: false\n"
    )
    (out / "safety-notes.md").write_text(
        "# Safety Notes\n\n"
        "* execution-readiness gate only\n"
        "* no archive created\n"
        "* no source copied, moved, modified, or deleted\n"
        "* no cleanup/prune/delete/restart/remediation/rollback/recovery\n"
        "* execution remains unavailable\n"
    )
    manifest_files = []
    for name in EXECUTION_READINESS_OUT_FILES:
        if name in {"manifest.json", "checksums.json"}:
            continue
        p = out / name
        manifest_files.append({"path": str(p), "name": name, "size_bytes": p.stat().st_size})
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "plan_id": result["plan_id"],
                "mode": EXECUTION_READINESS_MODE,
                "files": manifest_files,
                "archive_created": False,
                "candidate_contents_copied": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    checksum_names = [item["name"] for item in manifest_files] + ["manifest.json"]
    checksums = {name: "sha256:" + sha256_file(out / name) for name in checksum_names}
    (out / "checksums.json").write_text(
        json.dumps({"plan_id": result["plan_id"], "checksums": checksums}, indent=2, sort_keys=True)
        + "\n"
    )


def archive_bundle_safety_block() -> dict[str, bool]:
    return {
        "read_only": False,
        "mutation_performed": True,
        "copy_only_archive_bundle_created": True,
        "archive_created": True,
        "source_copied": True,
        "source_moved": False,
        "source_deleted": False,
        "source_modified": False,
        "cleanup_executed": False,
        "docker_prune_executed": False,
        "docker_image_removed": False,
        "docker_volume_removed": False,
        "file_deleted": False,
        "docker_compose_executed": False,
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


def _archive_failure(
    *,
    plan_dir: str,
    receipt_dir: str,
    readiness_dir: str | None,
    plan_id: str | None,
    archive_out: str | None,
    checks: list[dict[str, str]],
    errors: list[str],
    warnings: list[str] | None = None,
    created: bool = False,
    partial: bool = False,
) -> dict[str, Any]:
    warnings = warnings or []
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": ARCHIVE_BUNDLE_CREATE_MODE,
        "status": "partial" if partial else "failed",
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "plan_dir": str(Path(plan_dir)),
        "dry_run_receipt_dir": str(Path(receipt_dir)),
        "execution_readiness_dir": str(Path(readiness_dir)) if readiness_dir else None,
        "plan_id": plan_id,
        "archive_bundle_dir": str(Path(archive_out)) if archive_out else None,
        "read_only": False,
        "mutation_performed": bool(created or partial),
        "mutation_type": "copy_only_archive_bundle_create",
        "execution_available": True,
        "confirmation_phrase_matched": False,
        "summary": {
            "candidate_items": 0,
            "candidate_bytes_planned": 0,
            "candidate_bytes_copied": 0,
            "files_copied": 0,
            "directories_copied": 0,
            "source_deleted": False,
            "source_moved": False,
            "source_modified": False,
            "archive_manifest_entries": 0,
            "errors": len(errors),
            "warnings": len(warnings),
        },
        "source_preservation": {
            "source_delete_performed": False,
            "source_move_performed": False,
            "source_modify_performed": False,
            "source_paths_verified_present_after_copy": False,
        },
        "archive": {
            "format": "directory_bundle",
            "payload_dir": "payload",
            "manifest_file": "archive-manifest.json",
            "checksums_file": "archive-checksums.json",
            "receipt_file": "archive-receipt.json",
        },
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": {
            **archive_bundle_safety_block(),
            "archive_created": bool(created or partial),
            "source_copied": bool(partial),
        },
        "first_safe_command": f"cat {archive_out}/archive-summary.md" if archive_out else None,
    }


def _safe_archive_out(path_text: str | None) -> tuple[bool, str]:
    if not path_text:
        return False, "--archive-out is required"
    p = Path(path_text).expanduser().resolve(strict=False)
    if str(p) in {"/", "/tmp", "/srv", "/data", "/var", "/workspace"}:
        return False, f"unsafe archive output path: {p}"
    if p.exists() and any(p.iterdir()):
        return False, f"archive output path already exists and is non-empty: {p}"
    return True, ""


def _path_inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


def _copy_candidate(src: Path, dest: Path) -> tuple[int, int, list[dict[str, Any]]]:
    files = 0
    bytes_copied = 0
    entries: list[dict[str, Any]] = []
    if src.is_symlink():
        raise OSError(f"symlink candidate rejected: {src}")
    if src.is_file():
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest, follow_symlinks=False)
        files = 1
        bytes_copied = dest.stat().st_size
        entries.append(
            {
                "payload_path": str(dest),
                "size_bytes": bytes_copied,
                "sha256": "sha256:" + sha256_file(dest),
            }
        )
        return files, bytes_copied, entries
    if not src.is_dir():
        raise OSError(f"unsupported candidate type: {src}")
    dest.mkdir(parents=True, exist_ok=True)
    for item in sorted(src.rglob("*")):
        if item.is_symlink():
            raise OSError(f"symlink inside candidate rejected: {item}")
        rel = item.relative_to(src)
        target = dest / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if item.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target, follow_symlinks=False)
            size = target.stat().st_size
            files += 1
            bytes_copied += size
            entries.append(
                {
                    "payload_path": str(target),
                    "size_bytes": size,
                    "sha256": "sha256:" + sha256_file(target),
                }
            )
    return files, bytes_copied, entries


def build_archive_bundle(
    plan_dir: str,
    receipt_dir: str,
    *,
    supplied_plan_id: str | None,
    confirm: str | None,
    archive_out: str | None,
    readiness_dir: str | None = None,
    max_candidates: int = DEFAULT_MAX_RETURNED,
) -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    errors: list[str] = []
    warnings: list[str] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        _add_check(checks, errors, warnings, name, "passed" if ok else "failed", detail)

    add("plan_id_supplied", bool(supplied_plan_id), "--plan-id is required")
    add(
        "confirmation_phrase_matched",
        confirm == CONFIRMATION_PHRASE,
        "exact confirmation phrase required",
    )
    out_ok, out_detail = _safe_archive_out(archive_out)
    add("archive_out_safe", out_ok, out_detail)
    if errors:
        return _archive_failure(
            plan_dir=plan_dir,
            receipt_dir=receipt_dir,
            readiness_dir=readiness_dir,
            plan_id=supplied_plan_id,
            archive_out=archive_out,
            checks=checks,
            errors=errors,
            warnings=warnings,
        )

    plan_validation = validate_plan(plan_dir, max_candidates=max_candidates)
    receipt_validation = validate_dry_run_receipt(
        receipt_dir, plan_dir=plan_dir, max_candidates=max_candidates
    )
    readiness = build_execution_readiness(plan_dir, receipt_dir, max_candidates=max_candidates)
    add("plan_validation_passed", plan_validation["status"] == "passed", plan_validation["status"])
    add(
        "dry_run_receipt_validation_passed",
        receipt_validation["status"] == "passed",
        receipt_validation["status"],
    )
    add(
        "execution_readiness_passed",
        readiness["status"] in {"ready_for_execution_review", "partial"},
        readiness["status"],
    )
    expected_plan_id = plan_validation.get("plan_id")
    add("plan_id_match", supplied_plan_id == expected_plan_id, f"expected {expected_plan_id!r}")

    plan_path = Path(plan_dir)
    plan_manifest = _load_plan_json(plan_path / "candidate-manifest.json") or {}
    candidates = plan_manifest.get("candidates", []) if isinstance(plan_manifest, dict) else []
    cand_ok, cand_detail, cand_count, cand_bytes, _ = _safe_candidates(candidates)
    add("candidate_scope_safe", cand_ok, cand_detail)
    out_path = Path(str(archive_out)).expanduser().resolve(strict=False)
    for cand in candidates if isinstance(candidates, list) else []:
        src = Path(cand.get("path", "")).resolve(strict=False)
        if not src.exists():
            add("candidate_paths_present", False, f"missing candidate: {src}")
            break
        if src.is_symlink():
            add("candidate_symlinks_absent", False, f"symlink candidate: {src}")
            break
        if _path_inside(out_path, src):
            add(
                "archive_out_not_inside_candidate", False, f"archive output inside candidate: {src}"
            )
            break
        if _path_inside(src, out_path):
            add(
                "candidate_not_inside_archive_out", False, f"candidate inside archive output: {src}"
            )
            break
    if errors:
        return _archive_failure(
            plan_dir=plan_dir,
            receipt_dir=receipt_dir,
            readiness_dir=readiness_dir,
            plan_id=supplied_plan_id,
            archive_out=archive_out,
            checks=checks,
            errors=errors,
            warnings=warnings,
        )

    out_path.mkdir(parents=True, exist_ok=True)
    payload_dir = out_path / "payload"
    payload_dir.mkdir(exist_ok=True)
    manifest_entries: list[dict[str, Any]] = []
    files_copied = directories_copied = bytes_copied = 0
    status = "archive_created"
    try:
        for idx, cand in enumerate(candidates):
            src = Path(cand["path"])
            dest = payload_dir / f"{idx:04d}" / re.sub(r"[^A-Za-z0-9._-]+", "_", src.name)
            f_count, b_count, entries = _copy_candidate(src, dest)
            files_copied += f_count
            bytes_copied += b_count
            if src.is_dir():
                directories_copied += 1
            manifest_entries.append(
                {
                    "candidate_index": idx,
                    "source_path": str(src),
                    "payload_root": str(dest),
                    "entries": entries,
                }
            )
    except OSError as exc:
        status = "partial" if manifest_entries or files_copied else "failed"
        errors.append(f"copy_failed: {exc}")

    source_present = all(
        Path(c.get("path", "")).exists() for c in candidates if isinstance(c, dict)
    )
    source_preservation = {
        "source_delete_performed": False,
        "source_move_performed": False,
        "source_modify_performed": False,
        "source_paths_verified_present_after_copy": source_present,
    }
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "mode": ARCHIVE_BUNDLE_CREATE_MODE,
        "status": status,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "plan_dir": str(Path(plan_dir)),
        "dry_run_receipt_dir": str(Path(receipt_dir)),
        "execution_readiness_dir": str(Path(readiness_dir)) if readiness_dir else None,
        "plan_id": supplied_plan_id,
        "archive_bundle_dir": str(out_path),
        "read_only": False,
        "mutation_performed": True,
        "mutation_type": "copy_only_archive_bundle_create",
        "execution_available": True,
        "confirmation_phrase_matched": True,
        "summary": {
            "candidate_items": cand_count,
            "candidate_bytes_planned": cand_bytes,
            "candidate_bytes_copied": bytes_copied,
            "files_copied": files_copied,
            "directories_copied": directories_copied,
            "source_deleted": False,
            "source_moved": False,
            "source_modified": False,
            "archive_manifest_entries": len(manifest_entries),
            "errors": len(errors),
            "warnings": len(warnings),
        },
        "source_preservation": source_preservation,
        "archive": {
            "format": "directory_bundle",
            "payload_dir": "payload",
            "manifest_file": "archive-manifest.json",
            "checksums_file": "archive-checksums.json",
            "receipt_file": "archive-receipt.json",
        },
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": archive_bundle_safety_block(),
        "first_safe_command": f"cat {out_path}/archive-summary.md",
    }
    (out_path / "source-candidate-manifest.json").write_text(
        json.dumps(plan_manifest, indent=2, sort_keys=True) + "\n"
    )
    (out_path / "source-exclusions.json").write_text(
        json.dumps(
            _load_plan_json(plan_path / "excluded-candidates.json") or {}, indent=2, sort_keys=True
        )
        + "\n"
    )
    (out_path / "source-preservation.json").write_text(
        json.dumps(source_preservation, indent=2, sort_keys=True) + "\n"
    )
    (out_path / "archive-manifest.json").write_text(
        json.dumps(
            {"plan_id": supplied_plan_id, "entries": manifest_entries}, indent=2, sort_keys=True
        )
        + "\n"
    )
    checksums = {
        str(Path(e["payload_path"]).relative_to(out_path)): e["sha256"]
        for m in manifest_entries
        for e in m["entries"]
    }
    (out_path / "archive-checksums.json").write_text(
        json.dumps({"plan_id": supplied_plan_id, "checksums": checksums}, indent=2, sort_keys=True)
        + "\n"
    )
    (out_path / "future-cleanup-notes.md").write_text(
        "# Future Cleanup Notes\n\n"
        "Source deletion remains out of scope and requires a separate lane.\n"
    )
    (out_path / "safety-notes.md").write_text(
        "# Safety Notes\n\n"
        "* copy-only archive bundle creation\n"
        "* no source deletion, move, or modification\n"
        "* no cleanup/prune/restart/remediation/rollback/recovery\n"
    )
    (out_path / "archive-receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    )
    (out_path / "archive-summary.md").write_text(render_archive_bundle_summary(receipt))
    return receipt


def render_archive_bundle_summary(receipt: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Docker01 Artifact Archive Bundle Created",
            "",
            f"Plan: {receipt['plan_dir']}",
            f"Plan ID: {receipt['plan_id']}",
            f"Archive bundle: {receipt['archive_bundle_dir']}",
            f"Status: {receipt['status']}",
            "Mutation type: copy-only archive bundle creation",
            "",
            "## Summary",
            f"* candidates: {receipt['summary']['candidate_items']}",
            f"* planned bytes: {receipt['summary']['candidate_bytes_planned']}",
            f"* copied bytes: {receipt['summary']['candidate_bytes_copied']}",
            f"* files copied: {receipt['summary']['files_copied']}",
            f"* directories copied: {receipt['summary']['directories_copied']}",
            "",
            "## Source preservation",
            "* source copied: yes",
            "* source moved: no",
            "* source deleted: no",
            "* source modified: no",
            (
                "* source paths verified after copy: "
                + (
                    "yes"
                    if receipt["source_preservation"]["source_paths_verified_present_after_copy"]
                    else "no"
                )
            ),
            "",
            "## Archive contents",
            "* receipt: archive-receipt.json",
            "* manifest: archive-manifest.json",
            "* checksums: archive-checksums.json",
            "* payload: payload/",
            "",
            "## Safety",
            "* no cleanup",
            "* no source deletion",
            "* no source move",
            "* no Docker prune",
            "* no Docker image removal",
            "* no Docker/Compose mutation",
            "* no restart",
            "* no remediation/rollback/recovery",
            "* no natural-language execution",
            "* no " + "shell=" + "True",
            "",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build or validate a read-only ShellForgeAI artifact archive plan."
    )
    parser.add_argument("--root", default=DEFAULT_ROOT)
    parser.add_argument(
        "--create-archive-bundle",
        metavar="PLAN_DIR",
        help="create a governed copy-only archive bundle from a validated plan",
    )
    parser.add_argument(
        "--validate",
        metavar="PLAN_DIR",
        help="validate an existing archive-plan directory (read-only)",
    )
    parser.add_argument(
        "--dry-run-receipt",
        metavar="PLAN_DIR",
        help=(
            "build a dry-run receipt for a plan, or pair with --execution-readiness as "
            "the dry-run receipt directory"
        ),
    )
    parser.add_argument(
        "--execution-readiness",
        metavar="PLAN_DIR",
        help="read-only execution-readiness gate for a plan plus dry-run receipt",
    )
    parser.add_argument(
        "--validate-dry-run-receipt",
        metavar="RECEIPT_DIR",
        help="validate an existing dry-run receipt directory (read-only)",
    )
    parser.add_argument(
        "--plan-dir", help="optional source archive-plan directory for receipt validation"
    )
    parser.add_argument(
        "--receipt-validation",
        help="optional prior dry-run receipt validation directory for execution readiness",
    )
    parser.add_argument(
        "--plan-id", help="required exact plan id for dry-run receipt or archive bundle"
    )
    parser.add_argument("--confirm", help="exact archive bundle confirmation phrase")
    parser.add_argument("--archive-out", help="explicit archive bundle output directory")
    parser.add_argument("--json", action="store_true", help="emit strict JSON")
    parser.add_argument("--out", help="write plan or validation artifacts to this directory")
    parser.add_argument("--max-candidates-scanned", type=int, default=DEFAULT_MAX_SCAN)
    parser.add_argument("--max-candidates-returned", type=int, default=DEFAULT_MAX_RETURNED)
    parser.add_argument("--max-warnings-returned", type=int, default=DEFAULT_MAX_WARNINGS)
    args = parser.parse_args(argv)

    if args.create_archive_bundle:
        if not args.dry_run_receipt:
            parser.error("--create-archive-bundle requires --dry-run-receipt <receipt_dir>")
        result = build_archive_bundle(
            args.create_archive_bundle,
            args.dry_run_receipt,
            supplied_plan_id=args.plan_id,
            confirm=args.confirm,
            archive_out=args.archive_out,
            readiness_dir=args.execution_readiness,
            max_candidates=args.max_candidates_returned,
        )
        print(
            json.dumps(result, sort_keys=True)
            if args.json
            else render_archive_bundle_summary(result)
        )
        return 0 if result["status"] == "archive_created" else 1

    if args.validate:
        result = validate_plan(args.validate, max_candidates=args.max_candidates_returned)
        if args.out:
            write_validation_outputs(result, args.out)
        print(
            json.dumps(result, sort_keys=True) if args.json else render_validation_summary(result)
        )
        return 0 if result["status"] != "failed" else 1

    if args.validate_dry_run_receipt:
        result = validate_dry_run_receipt(
            args.validate_dry_run_receipt,
            plan_dir=args.plan_dir,
            max_candidates=args.max_candidates_returned,
        )
        if args.out:
            write_dry_run_receipt_validation_outputs(result, args.out)
        print(
            json.dumps(result, sort_keys=True)
            if args.json
            else render_dry_run_receipt_validation_summary(result)
        )
        return 0 if result["status"] != "failed" else 1

    if args.execution_readiness:
        if not args.dry_run_receipt:
            parser.error("--execution-readiness requires --dry-run-receipt <receipt_dir>")
        result = build_execution_readiness(
            args.execution_readiness,
            args.dry_run_receipt,
            receipt_validation_dir=args.receipt_validation,
            max_candidates=args.max_candidates_returned,
        )
        if args.out:
            write_execution_readiness_outputs(result, args.out)
        print(
            json.dumps(result, sort_keys=True)
            if args.json
            else render_execution_readiness_summary(result)
        )
        return 0 if result["status"] in {"ready_for_execution_review", "partial"} else 1

    if args.dry_run_receipt:
        receipt = build_dry_run_receipt(
            args.dry_run_receipt,
            supplied_plan_id=args.plan_id,
            max_candidates=args.max_candidates_returned,
        )
        if args.out:
            write_dry_run_receipt_outputs(receipt, args.out)
        print(
            json.dumps(receipt, sort_keys=True)
            if args.json
            else render_dry_run_receipt_summary(receipt)
        )
        return 0 if receipt["status"] != "failed" else 1

    plan = build_plan(
        args.root,
        max_scan=args.max_candidates_scanned,
        max_returned=args.max_candidates_returned,
        max_warnings=args.max_warnings_returned,
    )
    if args.out:
        write_outputs(plan, args.out)
    print(json.dumps(plan, sort_keys=True) if args.json else render_summary(plan))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
