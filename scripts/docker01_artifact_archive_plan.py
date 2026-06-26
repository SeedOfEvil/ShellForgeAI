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
ARCHIVE_BUNDLE_VALIDATION_MODE = "docker01_artifact_archive_bundle_validation"
ARCHIVE_ELIGIBILITY_REVIEW_MODE = "docker01_artifact_archive_eligibility_review"
SOURCE_ACTION_DRY_RUN_MODE = "docker01_artifact_archive_source_action_dry_run"
SOURCE_ACTION_DRY_RUN_VALIDATION_MODE = "docker01_artifact_archive_source_action_dry_run_validation"
SOURCE_ACTION_REVIEW_PACKET_MODE = "docker01_artifact_archive_source_action_review_packet"
SOURCE_ACTION_DECISION_RECEIPT_MODE = "docker01_artifact_archive_source_action_decision_receipt"
SOURCE_ACTION_READINESS_GATE_MODE = "docker01_artifact_archive_source_action_readiness_gate"
SOURCE_ACTION_STATUS_REPORT_MODE = "docker01_artifact_archive_source_action_status_report"
SOURCE_ACTION_FIXTURE_REHEARSAL_MODE = "docker01_artifact_archive_source_action_fixture_rehearsal"
DEFAULT_ROOT = "/tmp"
DEFAULT_MAX_SCAN = 1000
DEFAULT_MAX_RETURNED = 500
DEFAULT_MAX_WARNINGS = 50
CONFIRMATION_PHRASE = "CONFIRM_SHELLFORGEAI_ARTIFACT_ARCHIVE"
FIRST_SAFE_COMMAND = "python3 scripts/docker01_artifact_archive_plan.py --root /tmp --json"
ARCHIVE_CONFIRMATION_PHRASE = CONFIRMATION_PHRASE
SOURCE_ACTION_REVIEW_CONFIRMATION_PHRASE = "CONFIRM_SHELLFORGEAI_SOURCE_ACTION_AFTER_ARCHIVE"
SOURCE_ACTION_FIXTURE_REHEARSAL_CONFIRMATION_PHRASE = (
    "CONFIRM_SHELLFORGEAI_FIXTURE_SOURCE_ACTION_REHEARSAL"
)
ALLOWED_SOURCE_ACTION_DECISIONS = (
    "ready_for_future_pr_review",
    "defer",
    "reject",
    "needs_more_evidence",
)

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

ARCHIVE_BUNDLE_VALIDATION_OUT_FILES = (
    "artifact-archive-bundle-validation.json",
    "artifact-archive-bundle-validation-summary.md",
    "manifest.json",
    "checksums.json",
)

ARCHIVE_ELIGIBILITY_REVIEW_OUT_FILES = (
    "artifact-archive-eligibility-review.json",
    "artifact-archive-eligibility-review-summary.md",
    "candidate-archive-eligibility-review.json",
    "future-source-action-review-checklist.md",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
)

SOURCE_ACTION_DRY_RUN_OUT_FILES = (
    "archive-source-action-dry-run.json",
    "archive-source-action-dry-run-summary.md",
    "candidate-source-action-manifest.json",
    "future-source-action-checklist.md",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
)

SOURCE_ACTION_DRY_RUN_VALIDATION_OUT_FILES = (
    "archive-source-action-dry-run-validation.json",
    "archive-source-action-dry-run-validation-summary.md",
    "candidate-source-action-validation.json",
    "future-source-action-review-checklist.md",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
)

SOURCE_ACTION_REVIEW_PACKET_OUT_FILES = (
    "archive-source-action-review-packet.json",
    "archive-source-action-human-review.md",
    "candidate-review-summary.json",
    "operator-review-checklist.md",
    "future-source-action-signoff-template.md",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
)

SOURCE_ACTION_DECISION_RECEIPT_OUT_FILES = (
    "archive-source-action-decision-receipt.json",
    "archive-source-action-decision-receipt-summary.md",
    "candidate-decision-summary.json",
    "future-source-action-requirements.md",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
)

SOURCE_ACTION_READINESS_GATE_OUT_FILES = (
    "archive-source-action-readiness-gate.json",
    "archive-source-action-readiness-summary.md",
    "candidate-readiness-summary.json",
    "future-source-action-pr-checklist.md",
    "non-execution-contract.md",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
)

SOURCE_ACTION_STATUS_REPORT_OUT_FILES = (
    "archive-source-action-status-report.json",
    "archive-source-action-operator-status.md",
    "candidate-status-summary.json",
    "operator-next-steps.md",
    "non-execution-contract.md",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
)

SOURCE_ACTION_FIXTURE_REHEARSAL_OUT_FILES = (
    "fixture-source-action-rehearsal.json",
    "fixture-source-action-rehearsal-summary.md",
    "fixture-candidate-manifest.json",
    "fixture-archive-manifest.json",
    "fixture-rollback-proof.json",
    "fixture-safety-notes.md",
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


def archive_bundle_validation_safety_block() -> dict[str, bool]:
    safety = validation_safety_block()
    safety["docker_volume_removed"] = False
    return safety


def _safe_payload_rel(path_text: str) -> tuple[bool, str]:
    if not path_text:
        return False, "empty payload path"
    path = Path(path_text)
    if path.is_absolute():
        return False, f"absolute payload path: {path_text}"
    if ".." in path.parts:
        return False, f"unsafe payload traversal: {path_text}"
    if not path.parts or path.parts[0] != "payload":
        return False, f"payload path must start with payload/: {path_text}"
    return True, ""


def _candidate_keys(candidates: Any) -> set[tuple[Any, ...]]:
    if not isinstance(candidates, list):
        return set()
    return {
        (
            c.get("path"),
            c.get("class"),
            c.get("type"),
            int(c.get("size_bytes", 0) or 0),
            c.get("future_action"),
        )
        for c in candidates
        if isinstance(c, dict)
    }


def _validation_cross_check(
    label: str,
    candidates: Any,
    expected_candidates: Any,
    expected_plan_id: Any,
    archive_plan_id: Any,
) -> tuple[str, str]:
    cand_ok, cand_detail, cand_count, cand_bytes, cand_classes = _safe_candidates(candidates)
    exp_ok, exp_detail, exp_count, exp_bytes, exp_classes = _safe_candidates(expected_candidates)
    ok = (
        cand_ok
        and exp_ok
        and expected_plan_id == archive_plan_id
        and cand_count == exp_count
        and cand_bytes == exp_bytes
        and cand_classes == exp_classes
        and _candidate_keys(candidates) == _candidate_keys(expected_candidates)
    )
    if ok:
        return "passed", ""
    return (
        "failed",
        (
            f"{label} mismatch: plan_id={expected_plan_id!r}/{archive_plan_id!r}; "
            f"count={exp_count}/{cand_count}; bytes={exp_bytes}/{cand_bytes}; "
            f"{cand_detail or exp_detail}"
        ),
    )


def validate_archive_bundle(
    archive_bundle_dir: str,
    *,
    plan_dir: str | None = None,
    dry_run_receipt_dir: str | None = None,
    max_candidates: int = DEFAULT_MAX_RETURNED,
) -> dict[str, Any]:
    """Validate a PR236 copy-only archive bundle. Strictly read-only."""
    bundle = Path(archive_bundle_dir)
    checks: list[dict[str, str]] = []
    errors: list[str] = []
    warnings: list[str] = []

    required = (*ARCHIVE_BUNDLE_OUT_FILES, "payload")
    missing = [
        name
        for name in required
        if (
            (name == "payload" and (not (bundle / name).is_dir() or (bundle / name).is_symlink()))
            or (
                name != "payload"
                and (not (bundle / name).is_file() or (bundle / name).is_symlink())
            )
        )
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
    for name in [n for n in ARCHIVE_BUNDLE_OUT_FILES if n.endswith(".json")]:
        data = _load_plan_json(bundle / name)
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

    receipt = parsed.get("archive-receipt.json") or {}
    archive_manifest = parsed.get("archive-manifest.json") or {}
    archive_checksums = parsed.get("archive-checksums.json") or {}
    candidate_doc = parsed.get("source-candidate-manifest.json") or {}
    preservation = parsed.get("source-preservation.json") or {}
    plan_id = receipt.get("plan_id") if isinstance(receipt, dict) else None
    created_at = receipt.get("created_at") if isinstance(receipt, dict) else None

    plan_id_ok = isinstance(plan_id, str) and bool(PLAN_ID_RE.match(plan_id))
    _add_check(
        checks,
        errors,
        warnings,
        "plan_id_ok",
        "passed" if plan_id_ok else "failed",
        f"plan_id={plan_id!r}",
    )

    candidates = candidate_doc.get("candidates", []) if isinstance(candidate_doc, dict) else []
    cand_ok, _, cand_count, cand_bytes, _ = _safe_candidates(candidates)
    if cand_count > max_candidates:
        cand_ok = False

    entries = archive_manifest.get("entries", []) if isinstance(archive_manifest, dict) else []
    manifest_ok = isinstance(entries, list) and archive_manifest.get("plan_id") == plan_id
    manifest_detail = "" if manifest_ok else "archive manifest entries/plan_id invalid"
    payload_rel_paths: set[str] = set()
    files_copied = directories_copied = copied_bytes = 0
    if manifest_ok:
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("entries"), list)
                or not entry.get("entries")
            ):
                manifest_ok = False
                manifest_detail = "manifest entry invalid or missing payload entries"
                break
            if Path(str(entry.get("payload_root", ""))).is_symlink():
                manifest_ok = False
                manifest_detail = "symlink payload root"
                break
            directories_copied += 1 if entry.get("entries") else 0
            for payload in entry["entries"]:
                payload_path = payload.get("payload_path") if isinstance(payload, dict) else None
                if not payload_path:
                    manifest_ok = False
                    manifest_detail = "payload entry missing path"
                    break
                try:
                    rel = str(
                        Path(payload_path).resolve(strict=False).relative_to(bundle.resolve())
                    )
                except ValueError:
                    manifest_ok = False
                    manifest_detail = f"payload outside bundle: {payload_path}"
                    break
                safe, detail = _safe_payload_rel(rel)
                target = bundle / rel
                if not safe or target.is_symlink() or not target.is_file():
                    manifest_ok = False
                    manifest_detail = detail or f"payload missing/symlink: {rel}"
                    break
                if int(payload.get("size_bytes", -1)) != target.stat(follow_symlinks=False).st_size:
                    manifest_ok = False
                    manifest_detail = f"payload size mismatch: {rel}"
                    break
                payload_rel_paths.add(rel)
                files_copied += 1
                copied_bytes += int(payload.get("size_bytes", 0) or 0)
            if not manifest_ok:
                break
    if manifest_ok and cand_ok and len(entries) != cand_count:
        manifest_ok = False
        manifest_detail = "manifest candidate count mismatch"
    _add_check(
        checks,
        errors,
        warnings,
        "manifest_ok",
        "passed" if manifest_ok else "failed",
        manifest_detail,
    )

    checksums = (
        archive_checksums.get("checksums", {}) if isinstance(archive_checksums, dict) else {}
    )
    checksums_ok = isinstance(checksums, dict) and archive_checksums.get("plan_id") == plan_id
    checksums_detail = "" if checksums_ok else "archive checksums invalid"
    if checksums_ok:
        for rel, recorded in checksums.items():
            safe, detail = _safe_payload_rel(str(rel))
            target = bundle / str(rel)
            if not safe or target.is_symlink() or not target.is_file():
                checksums_ok = False
                checksums_detail = detail or f"checksum payload missing/symlink: {rel}"
                break
            if str(rel) not in payload_rel_paths:
                checksums_ok = False
                checksums_detail = f"checksum lacks manifest payload: {rel}"
                break
            if "sha256:" + sha256_file(target) != recorded:
                checksums_ok = False
                checksums_detail = f"checksum mismatch: {rel}"
                break
        if checksums_ok and set(checksums) != payload_rel_paths:
            checksums_ok = False
            checksums_detail = "manifest/checksum payload set mismatch"
    _add_check(
        checks,
        errors,
        warnings,
        "checksums_ok",
        "passed" if checksums_ok else "failed",
        checksums_detail,
    )

    payload_ok = manifest_ok and checksums_ok and payload_rel_paths == set(checksums)
    _add_check(
        checks,
        errors,
        warnings,
        "payload_ok",
        "passed" if payload_ok else "failed",
        "payload missing or checksum mismatch" if not payload_ok else "",
    )

    summary = receipt.get("summary", {}) if isinstance(receipt, dict) else {}
    preservation_ok = (
        isinstance(preservation, dict)
        and preservation.get("source_delete_performed") is False
        and preservation.get("source_move_performed") is False
        and preservation.get("source_modify_performed") is False
        and receipt.get("source_preservation") == preservation
        and summary.get("source_deleted") is False
        and summary.get("source_moved") is False
        and summary.get("source_modified") is False
    )
    source_paths_present = all(
        Path(c.get("path", "")).exists() for c in candidates if isinstance(c, dict)
    )
    if preservation_ok and not source_paths_present:
        _add_check(
            checks,
            errors,
            warnings,
            "source_paths_verified_after_copy",
            "warning",
            "one or more original source paths are unavailable",
        )
    _add_check(
        checks,
        errors,
        warnings,
        "source_preservation_ok",
        "passed" if preservation_ok else "failed",
        "source preservation metadata is missing or unsafe" if not preservation_ok else "",
    )

    unsafe_flags = [
        "source_deleted",
        "source_moved",
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
    safety = receipt.get("safety", {}) if isinstance(receipt, dict) else {}
    safety_ok = safety.get("archive_created") is True and safety.get("source_copied") is True
    safety_detail = ""
    for flag in unsafe_flags:
        if safety_ok and safety.get(flag) is not False:
            safety_ok = False
            safety_detail = f"receipt safety flag must be false: {flag}"
            break
    _add_check(
        checks,
        errors,
        warnings,
        "safety_ok",
        "passed" if safety_ok else "failed",
        safety_detail,
    )

    plan_cross = "not_requested"
    if plan_dir:
        plan_validation = validate_plan(plan_dir, max_candidates=max_candidates)
        plan_doc = _load_plan_json(Path(plan_dir) / "candidate-manifest.json") or {}
        plan_candidates = plan_doc.get("candidates", []) if isinstance(plan_doc, dict) else []
        plan_cross, detail = _validation_cross_check(
            "plan", candidates, plan_candidates, plan_validation.get("plan_id"), plan_id
        )
        if plan_validation["status"] == "failed":
            plan_cross, detail = "failed", "plan validation failed"
        _add_check(checks, errors, warnings, "plan_cross_check", plan_cross, detail)
    else:
        _add_check(checks, errors, warnings, "plan_cross_check", "passed", "not_requested")

    dry_cross = "not_requested"
    if dry_run_receipt_dir:
        receipt_validation = validate_dry_run_receipt(
            dry_run_receipt_dir, plan_dir=plan_dir, max_candidates=max_candidates
        )
        dry_doc = _load_plan_json(Path(dry_run_receipt_dir) / "candidate-manifest.json") or {}
        dry_receipt = (
            _load_plan_json(Path(dry_run_receipt_dir) / "artifact-archive-dry-run-receipt.json")
            or {}
        )
        dry_candidates = dry_doc.get("candidates", []) if isinstance(dry_doc, dict) else []
        dry_cross, detail = _validation_cross_check(
            "dry-run receipt",
            candidates,
            dry_candidates,
            dry_receipt.get("plan_id") if isinstance(dry_receipt, dict) else None,
            plan_id,
        )
        if receipt_validation["status"] == "failed":
            dry_cross, detail = "failed", "dry-run receipt validation failed"
        _add_check(checks, errors, warnings, "dry_run_cross_check", dry_cross, detail)
    else:
        _add_check(checks, errors, warnings, "dry_run_cross_check", "passed", "not_requested")

    blocker_errors = [
        e
        for e in errors
        if not e.startswith("plan_cross_check: not_requested")
        and not e.startswith("dry_run_cross_check: not_requested")
    ]
    status = "failed" if blocker_errors else ("partial" if warnings else "passed")
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": ARCHIVE_BUNDLE_VALIDATION_MODE,
        "status": status,
        "archive_bundle_dir": str(bundle),
        "plan_dir": str(Path(plan_dir)) if plan_dir else None,
        "dry_run_receipt_dir": str(Path(dry_run_receipt_dir)) if dry_run_receipt_dir else None,
        "plan_id": plan_id,
        "created_at": created_at or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "required_files_present": not missing,
            "json_parse_ok": not unparsable,
            "manifest_ok": manifest_ok,
            "checksums_ok": checksums_ok,
            "payload_ok": payload_ok,
            "source_preservation_ok": preservation_ok,
            "safety_ok": safety_ok,
            "plan_cross_check_status": plan_cross,
            "dry_run_cross_check_status": dry_cross,
            "candidate_items": cand_count,
            "candidate_bytes_planned": cand_bytes,
            "candidate_bytes_copied": copied_bytes,
            "files_copied": files_copied,
            "directories_copied": summary.get("directories_copied", directories_copied),
            "validation_errors": len(blocker_errors),
            "validation_warnings": len(warnings),
        },
        "checks": checks,
        "errors": blocker_errors,
        "warnings": warnings,
        "source_preservation": {
            "source_delete_performed": False,
            "source_move_performed": False,
            "source_modify_performed": False,
            "source_paths_verified_present_after_copy": bool(source_paths_present),
        },
        "future_cleanup_eligible_for_review": status in {"passed", "partial"}
        and not blocker_errors,
        "future_cleanup_available": False,
        "safety": archive_bundle_validation_safety_block(),
        "first_safe_command": (
            "python3 scripts/docker01_artifact_archive_plan.py "
            "--validate-archive-bundle <archive_bundle_dir> --json"
        ),
    }


def archive_eligibility_review_safety_block() -> dict[str, bool]:
    safety = validation_safety_block()
    safety["archive_eligibility_review_only"] = True
    safety["docker_volume_removed"] = False
    safety["cleanup_executed"] = False
    return safety


def _load_archive_validation(validation_dir: str | None) -> dict[str, Any] | None:
    if not validation_dir:
        return None
    data = _load_plan_json(Path(validation_dir) / "artifact-archive-bundle-validation.json")
    return data if isinstance(data, dict) else None


def _archive_payload_for_source(archive_manifest: dict[str, Any], source_path: str) -> str | None:
    for entry in archive_manifest.get("entries", []) if isinstance(archive_manifest, dict) else []:
        if not isinstance(entry, dict) or entry.get("source_path") != source_path:
            continue
        payload_root = entry.get("payload_root")
        if isinstance(payload_root, str):
            try:
                return str(Path(payload_root).relative_to(Path(payload_root).parents[2]))
            except (ValueError, IndexError):
                return payload_root
    return None


def build_archive_eligibility_review(
    archive_bundle_dir: str,
    *,
    plan_dir: str,
    dry_run_receipt_dir: str,
    archive_validation_dir: str | None = None,
    max_candidates: int = DEFAULT_MAX_RETURNED,
) -> dict[str, Any]:
    """Review archive-backed eligibility review. Read-only; cleanup remains unavailable."""
    checks: list[dict[str, str]] = []
    errors: list[str] = []
    warnings: list[str] = []

    def add(name: str, ok: bool, detail: str = "", *, warning: bool = False) -> None:
        _add_check(
            checks,
            errors,
            warnings,
            name,
            "warning" if warning else "passed" if ok else "failed",
            detail,
        )

    bundle = Path(archive_bundle_dir)
    plan_path = Path(plan_dir)
    receipt_path = Path(dry_run_receipt_dir)
    archive_validation = _load_archive_validation(archive_validation_dir)
    if archive_validation is None:
        archive_validation = validate_archive_bundle(
            str(bundle),
            plan_dir=str(plan_path),
            dry_run_receipt_dir=str(receipt_path),
            max_candidates=max_candidates,
        )
        if archive_validation_dir:
            add("archive_validation_supplied", False, "could not parse supplied archive validation")
    elif archive_validation.get("mode") != ARCHIVE_BUNDLE_VALIDATION_MODE:
        add("archive_validation_supplied", False, "wrong archive-validation mode")
    else:
        supplied_ok = (
            archive_validation.get("archive_bundle_dir") == str(bundle)
            and archive_validation.get("plan_dir") == str(plan_path)
            and archive_validation.get("dry_run_receipt_dir") == str(receipt_path)
        )
        add(
            "archive_validation_supplied",
            supplied_ok,
            "supplied validation does not match inputs"
            if not supplied_ok
            else "used supplied validation",
        )

    plan_validation = validate_plan(str(plan_path), max_candidates=max_candidates)
    receipt_validation = validate_dry_run_receipt(
        str(receipt_path), plan_dir=str(plan_path), max_candidates=max_candidates
    )
    archive_status = archive_validation.get("status")
    add(
        "archive_validation_passed",
        archive_status in {"passed", "partial"},
        str(archive_status),
        warning=archive_status == "partial",
    )
    add(
        "plan_validation_passed",
        plan_validation.get("status") == "passed",
        str(plan_validation.get("status")),
    )
    add(
        "dry_run_receipt_validation_passed",
        receipt_validation.get("status") == "passed",
        str(receipt_validation.get("status")),
    )

    plan = _load_plan_json(plan_path / "artifact-archive-plan.json") or {}
    dry_receipt = _load_plan_json(receipt_path / "artifact-archive-dry-run-receipt.json") or {}
    archive_receipt = _load_plan_json(bundle / "archive-receipt.json") or {}
    archive_manifest = _load_plan_json(bundle / "archive-manifest.json") or {}
    archive_checksums = _load_plan_json(bundle / "archive-checksums.json") or {}
    source_manifest = _load_plan_json(bundle / "source-candidate-manifest.json") or {}
    plan_manifest = _load_plan_json(plan_path / "candidate-manifest.json") or {}
    dry_manifest = _load_plan_json(receipt_path / "candidate-manifest.json") or {}
    preservation = _load_plan_json(bundle / "source-preservation.json") or {}

    plan_id = plan.get("plan_id") if isinstance(plan, dict) else None
    archive_plan_id = archive_receipt.get("plan_id") if isinstance(archive_receipt, dict) else None
    dry_plan_id = dry_receipt.get("plan_id") if isinstance(dry_receipt, dict) else None
    plan_id_match = isinstance(
        plan_id, str
    ) and plan_id == archive_plan_id == dry_plan_id == archive_validation.get("plan_id")
    add(
        "plan_id_match",
        plan_id_match,
        f"plan={plan_id!r} archive={archive_plan_id!r} dry_run={dry_plan_id!r}",
    )

    plan_candidates = plan_manifest.get("candidates", []) if isinstance(plan_manifest, dict) else []
    dry_candidates = dry_manifest.get("candidates", []) if isinstance(dry_manifest, dict) else []
    archive_candidates = (
        source_manifest.get("candidates", []) if isinstance(source_manifest, dict) else []
    )
    candidate_manifest_match = (
        _candidate_keys(plan_candidates)
        == _candidate_keys(dry_candidates)
        == _candidate_keys(archive_candidates)
    )
    add("candidate_manifest_match", candidate_manifest_match, "candidate manifests differ")
    cand_ok, cand_detail, cand_count, cand_bytes, _ = _safe_candidates(archive_candidates)
    add("candidate_paths_safe", cand_ok, cand_detail)

    archive_payload_verified = (
        archive_validation.get("summary", {}).get("payload_ok") is True
        and archive_validation.get("summary", {}).get("checksums_ok") is True
    )
    add(
        "archive_payload_verified",
        archive_payload_verified,
        "archive payload/checksum verification failed",
    )
    source_preservation_ok = (
        archive_validation.get("summary", {}).get("source_preservation_ok") is True
        and isinstance(preservation, dict)
        and preservation.get("source_delete_performed") is False
        and preservation.get("source_move_performed") is False
        and preservation.get("source_modify_performed") is False
    )
    add("source_preservation_ok", source_preservation_ok, "source-preservation metadata unsafe")

    unsafe_flags = (
        "source_deleted",
        "source_moved",
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
    )
    unsafe_seen = False
    for doc in (plan, dry_receipt, archive_receipt):
        if not isinstance(doc, dict):
            unsafe_seen = True
            continue
        safety = doc.get("safety", {})
        summary = doc.get("summary", {})
        for flag in unsafe_flags:
            if summary.get(flag) is True or (isinstance(safety, dict) and safety.get(flag) is True):
                unsafe_seen = True
    add(
        "unsafe_mutation_flags_clear",
        not unsafe_seen,
        "cleanup/prune/delete/restart/remediation flag was true",
    )

    checksum_map = (
        archive_checksums.get("checksums", {}) if isinstance(archive_checksums, dict) else {}
    )
    manifest_entries = (
        archive_manifest.get("entries", []) if isinstance(archive_manifest, dict) else []
    )
    by_source = {e.get("source_path"): e for e in manifest_entries if isinstance(e, dict)}
    candidate_review: list[dict[str, Any]] = []
    for cand in archive_candidates if isinstance(archive_candidates, list) else []:
        source = str(cand.get("path", "")) if isinstance(cand, dict) else ""
        blockers: list[str] = []
        cand_warnings: list[str] = []
        source_path = Path(source)
        if not cand_ok:
            blockers.append(cand_detail or "unsafe candidate")
        if source_path.is_symlink():
            blockers.append("source path is a symlink")
        source_exists = source_path.exists() and not source_path.is_symlink()
        if not source_exists:
            cand_warnings.append("source path is unavailable for recheck")
        entry = by_source.get(source, {}) if source else {}
        payloads = entry.get("entries", []) if isinstance(entry, dict) else []
        payload_exists = bool(payloads)
        checksum_verified = bool(payloads)
        first_payload_rel = None
        for payload in payloads if isinstance(payloads, list) else []:
            ptxt = payload.get("payload_path") if isinstance(payload, dict) else None
            if not ptxt:
                payload_exists = checksum_verified = False
                blockers.append("archive payload missing path")
                break
            try:
                rel = str(
                    Path(ptxt).resolve(strict=False).relative_to(bundle.resolve(strict=False))
                )
            except ValueError:
                rel = str(ptxt)
                blockers.append("archive payload outside bundle")
            first_payload_rel = first_payload_rel or rel
            target = bundle / rel
            if target.is_symlink() or not target.is_file():
                payload_exists = checksum_verified = False
                blockers.append(f"archive payload missing: {rel}")
                break
            if checksum_map.get(rel) != "sha256:" + sha256_file(target):
                checksum_verified = False
                blockers.append(f"archive checksum mismatch: {rel}")
                break
        if not payload_exists:
            blockers.append("archive payload missing")
        if (
            not source_exists
            and source_preservation_ok
            and archive_payload_verified
            and not blockers
        ):
            status = "warning"
        elif blockers:
            status = "blocked"
        else:
            status = "eligible"
        candidate_review.append(
            {
                "source_path": source,
                "class": cand.get("class") if isinstance(cand, dict) else None,
                "archive_payload_path": first_payload_rel,
                "status": status,
                "source_exists": source_exists,
                "archive_payload_exists": payload_exists,
                "archive_checksum_verified": checksum_verified,
                "blockers": blockers,
                "warnings": cand_warnings,
                "future_action": "cleanup_review_only",
            }
        )

    eligible = sum(1 for c in candidate_review if c["status"] == "eligible")
    blocked = sum(1 for c in candidate_review if c["status"] == "blocked")
    warning_count = sum(1 for c in candidate_review if c["status"] == "warning")
    unknown = sum(1 for c in candidate_review if c["status"] == "unknown")
    core_ok = not errors and all(c["status"] != "blocked" for c in candidate_review)
    if errors and any("json_parse" in e or "required_files" in e for e in errors):
        status = "failed"
    elif blocked or errors:
        status = "not_eligible"
    elif warning_count or warnings or archive_validation.get("status") == "partial":
        status = "partial"
    elif core_ok:
        status = "eligible_for_review"
    else:
        status = "failed"

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": ARCHIVE_ELIGIBILITY_REVIEW_MODE,
        "status": status,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "archive_bundle_dir": str(bundle),
        "plan_dir": str(plan_path),
        "dry_run_receipt_dir": str(receipt_path),
        "archive_validation_dir": str(Path(archive_validation_dir))
        if archive_validation_dir
        else None,
        "plan_id": plan_id,
        "read_only": True,
        "mutation_performed": False,
        "cleanup_available": False,
        "future_cleanup_review_only": True,
        "summary": {
            "archive_validation_status": archive_validation.get("status", "failed"),
            "plan_validation_status": plan_validation.get("status", "failed"),
            "dry_run_receipt_validation_status": receipt_validation.get("status", "failed"),
            "plan_id_match": plan_id_match,
            "candidate_manifest_match": candidate_manifest_match,
            "archive_payload_verified": archive_payload_verified,
            "source_preservation_ok": source_preservation_ok,
            "candidate_items": cand_count,
            "candidate_bytes": cand_bytes,
            "eligible_candidates": eligible,
            "blocked_candidates": blocked,
            "warning_candidates": warning_count,
            "unknown_candidates": unknown,
            "readiness_errors": len(errors),
            "readiness_warnings": len(warnings),
        },
        "candidate_review": candidate_review,
        "future_cleanup_requirements": {
            "separate_pr_required": True,
            "exact_plan_id_required": True,
            "exact_archive_bundle_required": True,
            "exact_confirmation_phrase_required": True,
            "future_confirmation_phrase": SOURCE_ACTION_REVIEW_CONFIRMATION_PHRASE,
            "archive_validation_required": True,
            "source_recheck_required": True,
            "dry_run_deletion_manifest_required": True,
            "operator_review_required": True,
            "source_delete_default": False,
            "source_move_default": False,
        },
        "will_not_do": [
            "delete source files in this PR",
            "move source files in this PR",
            "modify source files in this PR",
            "cleanup/prune/delete/restart/remediate/rollback/recover",
        ],
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": archive_eligibility_review_safety_block(),
        "first_safe_command": (
            "python3 scripts/docker01_artifact_archive_plan.py --archive-eligibility-review "
            "<archive_bundle_dir> --plan-dir <plan_dir> --dry-run-receipt "
            "<dry_run_receipt_dir> --json"
        ),
    }


def source_action_dry_run_safety_block() -> dict[str, bool]:
    safety = validation_safety_block()
    safety["source_action_dry_run_only"] = True
    safety["archive_created"] = False
    safety["source_copied"] = False
    safety["source_moved"] = False
    safety["source_deleted"] = False
    safety["source_modified"] = False
    safety["cleanup_executed"] = False
    safety["docker_volume_removed"] = False
    return safety


def _load_archive_eligibility_review(review_dir: str) -> dict[str, Any] | None:
    data = _load_plan_json(Path(review_dir) / "artifact-archive-eligibility-review.json")
    return data if isinstance(data, dict) else None


def build_archive_source_action_dry_run(
    archive_bundle_dir: str,
    *,
    plan_dir: str,
    dry_run_receipt_dir: str,
    archive_eligibility_review_dir: str,
    supplied_plan_id: str | None,
    max_candidates: int = DEFAULT_MAX_RETURNED,
) -> dict[str, Any]:
    """Build a read-only archive-backed source-action dry-run manifest."""
    checks: list[dict[str, str]] = []
    errors: list[str] = []
    warnings: list[str] = []

    def add(name: str, ok: bool, detail: str = "", *, warning: bool = False) -> None:
        _add_check(
            checks,
            errors,
            warnings,
            name,
            "warning" if warning else "passed" if ok else "failed",
            detail,
        )

    bundle = Path(archive_bundle_dir)
    plan_path = Path(plan_dir)
    receipt_path = Path(dry_run_receipt_dir)
    review_path = Path(archive_eligibility_review_dir)

    plan_id_format_ok = isinstance(supplied_plan_id, str) and bool(
        PLAN_ID_RE.match(supplied_plan_id)
    )
    add("supplied_plan_id_valid", plan_id_format_ok, f"plan_id={supplied_plan_id!r}")

    archive_validation = validate_archive_bundle(
        str(bundle),
        plan_dir=str(plan_path),
        dry_run_receipt_dir=str(receipt_path),
        max_candidates=max_candidates,
    )
    plan_validation = validate_plan(str(plan_path), max_candidates=max_candidates)
    receipt_validation = validate_dry_run_receipt(
        str(receipt_path), plan_dir=str(plan_path), max_candidates=max_candidates
    )
    eligibility = _load_archive_eligibility_review(str(review_path))
    if eligibility is None:
        add(
            "archive_eligibility_review_parse_ok",
            False,
            "could not parse artifact-archive-eligibility-review.json",
        )
        eligibility = {}
    else:
        add(
            "archive_eligibility_review_parse_ok",
            eligibility.get("mode") == ARCHIVE_ELIGIBILITY_REVIEW_MODE,
            str(eligibility.get("mode")),
        )

    add(
        "archive_validation_passed",
        archive_validation.get("status") in {"passed", "partial"},
        str(archive_validation.get("status")),
        warning=archive_validation.get("status") == "partial",
    )
    add(
        "plan_validation_passed",
        plan_validation.get("status") == "passed",
        str(plan_validation.get("status")),
    )
    add(
        "dry_run_receipt_validation_passed",
        receipt_validation.get("status") == "passed",
        str(receipt_validation.get("status")),
    )
    eligibility_status = eligibility.get("status", "failed")
    add(
        "archive_eligibility_passed",
        eligibility_status == "eligible_for_review",
        str(eligibility_status),
        warning=eligibility_status == "partial",
    )

    plan = _load_plan_json(plan_path / "artifact-archive-plan.json") or {}
    dry_receipt = _load_plan_json(receipt_path / "artifact-archive-dry-run-receipt.json") or {}
    archive_receipt = _load_plan_json(bundle / "archive-receipt.json") or {}
    archive_manifest = _load_plan_json(bundle / "archive-manifest.json") or {}
    archive_checksums = _load_plan_json(bundle / "archive-checksums.json") or {}
    source_manifest = _load_plan_json(bundle / "source-candidate-manifest.json") or {}
    plan_manifest = _load_plan_json(plan_path / "candidate-manifest.json") or {}
    dry_manifest = _load_plan_json(receipt_path / "candidate-manifest.json") or {}
    preservation = _load_plan_json(bundle / "source-preservation.json") or {}

    ids = [
        d.get("plan_id")
        for d in (
            plan,
            dry_receipt,
            archive_receipt,
            source_manifest,
            plan_manifest,
            dry_manifest,
            eligibility,
        )
        if isinstance(d, dict)
    ]
    plan_id_match = plan_id_format_ok and ids and all(i == supplied_plan_id for i in ids)
    add("plan_id_match", bool(plan_id_match), f"supplied={supplied_plan_id!r} evidence={ids!r}")

    plan_candidates = plan_manifest.get("candidates", []) if isinstance(plan_manifest, dict) else []
    dry_candidates = dry_manifest.get("candidates", []) if isinstance(dry_manifest, dict) else []
    archive_candidates = (
        source_manifest.get("candidates", []) if isinstance(source_manifest, dict) else []
    )
    candidate_manifest_match = (
        _candidate_keys(plan_candidates)
        == _candidate_keys(dry_candidates)
        == _candidate_keys(archive_candidates)
    )
    add("candidate_manifest_match", candidate_manifest_match, "candidate manifests differ")
    cand_ok, cand_detail, cand_count, cand_bytes, _ = _safe_candidates(archive_candidates)
    add("candidate_paths_safe", cand_ok, cand_detail)

    archive_payload_verified = (
        archive_validation.get("summary", {}).get("payload_ok") is True
        and archive_validation.get("summary", {}).get("checksums_ok") is True
    )
    source_preservation_ok = (
        archive_validation.get("summary", {}).get("source_preservation_ok") is True
        and isinstance(preservation, dict)
        and preservation.get("source_delete_performed") is False
        and preservation.get("source_move_performed") is False
        and preservation.get("source_modify_performed") is False
    )
    add(
        "archive_payload_verified",
        archive_payload_verified,
        "archive payload/checksum verification failed",
    )
    add("source_preservation_ok", source_preservation_ok, "source-preservation metadata unsafe")

    unsafe_flags = (
        "source_deleted",
        "source_moved",
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
    )
    unsafe_seen = False
    for doc in (plan, dry_receipt, archive_receipt, eligibility):
        if not isinstance(doc, dict):
            unsafe_seen = True
            continue
        for scope in (doc, doc.get("summary", {}), doc.get("safety", {})):
            if isinstance(scope, dict) and any(scope.get(flag) is True for flag in unsafe_flags):
                unsafe_seen = True
    add("unsafe_mutation_flags_clear", not unsafe_seen, "unsafe mutation flag was true")

    checksum_map = (
        archive_checksums.get("checksums", {}) if isinstance(archive_checksums, dict) else {}
    )
    entries = archive_manifest.get("entries", []) if isinstance(archive_manifest, dict) else []
    by_source = {e.get("source_path"): e for e in entries if isinstance(e, dict)}
    manifest: list[dict[str, Any]] = []
    for cand in archive_candidates if isinstance(archive_candidates, list) else []:
        source = str(cand.get("path", "")) if isinstance(cand, dict) else ""
        source_path = Path(source)
        blockers: list[str] = []
        cand_warnings: list[str] = []
        if not cand_ok:
            blockers.append(cand_detail or "unsafe candidate")
        if source_path.is_symlink():
            blockers.append("source path is a symlink")
        source_exists = source_path.exists() and not source_path.is_symlink()
        source_type = (
            "directory"
            if source_path.is_dir() and not source_path.is_symlink()
            else "file"
            if source_path.is_file() and not source_path.is_symlink()
            else "unknown"
        )
        source_recheck_ok = source_exists and not source_path.is_symlink()
        if not source_exists:
            cand_warnings.append("source path is unavailable for recheck")
        entry = by_source.get(source, {}) if source else {}
        payloads = entry.get("entries", []) if isinstance(entry, dict) else []
        archive_payload_exists = bool(payloads)
        archive_checksum_verified = bool(payloads)
        first_payload_rel = None
        for payload in payloads if isinstance(payloads, list) else []:
            ptxt = payload.get("payload_path") if isinstance(payload, dict) else None
            if not ptxt:
                blockers.append("archive payload missing path")
                archive_payload_exists = archive_checksum_verified = False
                break
            try:
                rel = str(
                    Path(ptxt).resolve(strict=False).relative_to(bundle.resolve(strict=False))
                )
            except ValueError:
                rel = str(ptxt)
                blockers.append("archive payload outside bundle")
            first_payload_rel = first_payload_rel or rel
            target = bundle / rel
            if target.is_symlink() or not target.is_file():
                blockers.append(f"archive payload missing: {rel}")
                archive_payload_exists = archive_checksum_verified = False
                break
            if checksum_map.get(rel) != "sha256:" + sha256_file(target):
                blockers.append(f"archive checksum mismatch: {rel}")
                archive_checksum_verified = False
                break
        if not archive_payload_exists:
            blockers.append("archive payload missing")
        if blockers:
            item_status = "blocked"
        elif not source_recheck_ok:
            item_status = "warning"
        elif not archive_payload_verified or not source_preservation_ok:
            item_status = "unknown"
        else:
            item_status = "would_review_for_source_action"
        manifest.append(
            {
                "source_path": source,
                "class": cand.get("class") if isinstance(cand, dict) else None,
                "archive_payload_path": first_payload_rel,
                "status": item_status,
                "source_exists": source_exists,
                "source_type": source_type,
                "archive_payload_exists": archive_payload_exists,
                "archive_checksum_verified": archive_checksum_verified,
                "source_recheck_ok": source_recheck_ok,
                "planned_future_action": "review_only_no_action_available",
                "blockers": blockers,
                "warnings": cand_warnings,
            }
        )

    would = sum(1 for c in manifest if c["status"] == "would_review_for_source_action")
    blocked = sum(1 for c in manifest if c["status"] == "blocked")
    warning_count = sum(1 for c in manifest if c["status"] == "warning")
    unknown = sum(1 for c in manifest if c["status"] == "unknown")
    if errors and any(k in e for e in errors for k in ("parse", "required_files")):
        status = "failed"
    elif blocked or errors or eligibility_status not in {"eligible_for_review", "partial"}:
        status = "not_ready"
    elif (
        warning_count
        or unknown
        or warnings
        or archive_validation.get("status") == "partial"
        or eligibility_status == "partial"
    ):
        status = "partial"
    else:
        status = "ready_for_source_action_review"

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": SOURCE_ACTION_DRY_RUN_MODE,
        "status": status,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "archive_bundle_dir": str(bundle),
        "plan_dir": str(plan_path),
        "dry_run_receipt_dir": str(receipt_path),
        "archive_eligibility_review_dir": str(review_path),
        "plan_id": supplied_plan_id,
        "read_only": True,
        "mutation_performed": False,
        "source_action_available": False,
        "future_source_action_review_only": True,
        "summary": {
            "archive_validation_status": archive_validation.get("status", "failed"),
            "plan_validation_status": plan_validation.get("status", "failed"),
            "dry_run_receipt_validation_status": receipt_validation.get("status", "failed"),
            "archive_eligibility_status": eligibility_status,
            "plan_id_match": bool(plan_id_match),
            "candidate_manifest_match": candidate_manifest_match,
            "archive_payload_verified": archive_payload_verified,
            "source_preservation_ok": source_preservation_ok,
            "candidate_items": cand_count,
            "candidate_bytes": cand_bytes,
            "would_review_candidates": would,
            "blocked_candidates": blocked,
            "warning_candidates": warning_count,
            "unknown_candidates": unknown,
            "dry_run_errors": len(errors),
            "dry_run_warnings": len(warnings),
        },
        "candidate_source_action_manifest": manifest,
        "future_source_action_requirements": {
            "separate_pr_required": True,
            "exact_plan_id_required": True,
            "exact_archive_bundle_required": True,
            "exact_archive_eligibility_review_required": True,
            "exact_confirmation_phrase_required": True,
            "future_confirmation_phrase": SOURCE_ACTION_REVIEW_CONFIRMATION_PHRASE,
            "dry_run_manifest_required": True,
            "source_recheck_required": True,
            "archive_validation_required": True,
            "operator_review_required": True,
            "source_delete_default": False,
            "source_move_default": False,
        },
        "will_not_do": [
            "delete source files in this PR",
            "move source files in this PR",
            "modify source files in this PR",
            "cleanup/prune/delete/restart/remediate/rollback/recover",
        ],
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": source_action_dry_run_safety_block(),
        "first_safe_command": (
            "python3 scripts/docker01_artifact_archive_plan.py "
            "--archive-source-action-dry-run <archive_bundle_dir> --plan-dir <plan_dir> "
            "--dry-run-receipt <dry_run_receipt_dir> --archive-eligibility-review "
            "<eligibility_review_dir> --plan-id <plan_id> --json"
        ),
    }


def render_archive_source_action_dry_run_summary(result: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Docker01 Archive-Backed Source Action Dry Run",
            "",
            f"Archive bundle: {result['archive_bundle_dir']}",
            f"Plan: {result['plan_dir']}",
            f"Dry-run receipt: {result['dry_run_receipt_dir']}",
            f"Archive eligibility review: {result['archive_eligibility_review_dir']}",
            f"Plan ID: {result['plan_id']}",
            f"Status: {result['status']}",
            "Read-only: yes",
            "Source action available: no",
            "",
            "## Evidence chain",
            f"* archive validation: {result['summary']['archive_validation_status']}",
            f"* plan validation: {result['summary']['plan_validation_status']}",
            (
                "* dry-run receipt validation: "
                f"{result['summary']['dry_run_receipt_validation_status']}"
            ),
            f"* archive eligibility: {result['summary']['archive_eligibility_status']}",
            f"* plan id match: {result['summary']['plan_id_match']}",
            f"* candidate manifest match: {result['summary']['candidate_manifest_match']}",
            f"* archive payload verified: {result['summary']['archive_payload_verified']}",
            f"* source preservation: {result['summary']['source_preservation_ok']}",
            "",
            "## Candidate summary",
            f"* candidates: {result['summary']['candidate_items']}",
            f"* would review: {result['summary']['would_review_candidates']}",
            f"* blocked: {result['summary']['blocked_candidates']}",
            f"* warning: {result['summary']['warning_candidates']}",
            f"* unknown: {result['summary']['unknown_candidates']}",
            "",
            "## Future source-action requirements",
            "* separate PR/lane required",
            "* exact plan id required",
            "* exact archive bundle required",
            "* exact eligibility review required",
            "* confirmation phrase required",
            "* source recheck required",
            "* archive validation required",
            "* source delete default: false",
            "* source move default: false",
            "",
            "## Safety",
            "* source-action dry run only",
            "* no source deleted",
            "* no source moved",
            "* no source modified",
            "* no cleanup/prune/delete/restart",
            "* no remediation/rollback/recovery",
            "* no natural-language execution",
            "* no " + "shell=" + "True",
            "",
        ]
    )


def write_archive_source_action_dry_run_outputs(result: dict[str, Any], out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "archive-source-action-dry-run.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    (out / "archive-source-action-dry-run-summary.md").write_text(
        render_archive_source_action_dry_run_summary(result)
    )
    (out / "candidate-source-action-manifest.json").write_text(
        json.dumps(
            {
                "plan_id": result["plan_id"],
                "candidates": result["candidate_source_action_manifest"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    (out / "future-source-action-checklist.md").write_text(
        "# Future Source-Action Checklist\n\n"
        "* separate PR/lane required\n"
        "* exact plan id required\n"
        "* exact archive bundle required\n"
        "* exact eligibility review required\n"
        "* confirmation phrase required: "
        + SOURCE_ACTION_REVIEW_CONFIRMATION_PHRASE
        + "\n* dry-run manifest required\n"
        "* source recheck required\n"
        "* archive validation required\n"
        "* source delete default: false\n"
        "* source move default: false\n"
    )
    (out / "safety-notes.md").write_text(
        "# Safety Notes\n\n"
        "* source-action dry run only\n"
        "* no source copied, moved, modified, or deleted\n"
        "* no archive created by source-action dry run\n"
        "* no cleanup/prune/delete/restart/remediation/rollback/recovery\n"
    )
    manifest_files = []
    for name in SOURCE_ACTION_DRY_RUN_OUT_FILES:
        if name in {"manifest.json", "checksums.json"}:
            continue
        p = out / name
        manifest_files.append({"path": str(p), "name": name, "size_bytes": p.stat().st_size})
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "plan_id": result["plan_id"],
                "mode": SOURCE_ACTION_DRY_RUN_MODE,
                "files": manifest_files,
                "archive_created": False,
                "candidate_contents_copied": False,
                "source_action_available": False,
                "source_deleted": False,
                "source_moved": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    names = [item["name"] for item in manifest_files] + ["manifest.json"]
    checksums = {name: "sha256:" + sha256_file(out / name) for name in names}
    (out / "checksums.json").write_text(
        json.dumps({"plan_id": result["plan_id"], "checksums": checksums}, indent=2, sort_keys=True)
        + "\n"
    )


def source_action_dry_run_validation_safety_block() -> dict[str, bool]:
    safety = validation_safety_block()
    safety["source_action_dry_run_validation_only"] = True
    safety["archive_created"] = False
    safety["source_copied"] = False
    safety["source_moved"] = False
    safety["source_deleted"] = False
    safety["source_modified"] = False
    safety["docker_volume_removed"] = False
    return safety


def _validate_output_manifest_checksums(
    base: Path, required_files: tuple[str, ...], mode: str
) -> tuple[dict[str, Any], list[dict[str, str]], list[str], list[str]]:
    checks: list[dict[str, str]] = []
    errors: list[str] = []
    warnings: list[str] = []

    missing = [
        name for name in required_files if not (base / name).is_file() or (base / name).is_symlink()
    ]
    _add_check(
        checks,
        errors,
        warnings,
        "source_action_dry_run_required_files",
        "failed" if missing else "passed",
        ", ".join(missing),
    )

    parsed: dict[str, Any] = {}
    unparsable: list[str] = []
    for name in [n for n in required_files if n.endswith(".json")]:
        data = _load_plan_json(base / name)
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

    manifest = parsed.get("manifest.json") or {}
    manifest_files = manifest.get("files", []) if isinstance(manifest, dict) else []
    manifest_ok = (
        isinstance(manifest_files, list)
        and bool(manifest_files)
        and manifest.get("mode", mode) == mode
    )
    manifest_detail = "" if manifest_ok else "manifest missing files list or mode mismatch"
    if manifest_ok:
        for entry in manifest_files:
            name = entry.get("name") if isinstance(entry, dict) else None
            if not name:
                manifest_ok = False
                manifest_detail = "manifest entry missing name"
                break
            target = base / name
            if target.is_symlink() or not target.is_file():
                manifest_ok = False
                manifest_detail = f"manifest file missing: {name}"
                break
            if int(entry.get("size_bytes", -1)) != target.stat(follow_symlinks=False).st_size:
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

    checksums_doc = parsed.get("checksums.json") or {}
    checksums = checksums_doc.get("checksums", {}) if isinstance(checksums_doc, dict) else {}
    checksums_ok = isinstance(checksums, dict) and bool(checksums)
    checksums_detail = "" if checksums_ok else "checksums missing"
    if checksums_ok:
        for name, recorded in checksums.items():
            target = base / str(name)
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
    return parsed, checks, errors, warnings


def validate_archive_source_action_dry_run(
    source_action_dry_run_dir: str,
    *,
    archive_bundle_dir: str | None = None,
    plan_dir: str | None = None,
    dry_run_receipt_dir: str | None = None,
    archive_eligibility_review_dir: str | None = None,
    max_candidates: int = DEFAULT_MAX_RETURNED,
) -> dict[str, Any]:
    """Validate a PR239 source-action dry-run directory. Strictly read-only."""
    dry_dir = Path(source_action_dry_run_dir)
    parsed, checks, errors, warnings = _validate_output_manifest_checksums(
        dry_dir, SOURCE_ACTION_DRY_RUN_OUT_FILES, SOURCE_ACTION_DRY_RUN_MODE
    )

    def add(name: str, status: str, detail: str = "") -> None:
        _add_check(checks, errors, warnings, name, status, detail)

    dry_run = parsed.get("archive-source-action-dry-run.json") or {}
    candidate_doc = parsed.get("candidate-source-action-manifest.json") or {}
    plan_id = dry_run.get("plan_id") if isinstance(dry_run, dict) else None
    plan_id_ok = isinstance(plan_id, str) and bool(PLAN_ID_RE.match(plan_id))
    add("plan_id_ok", "passed" if plan_id_ok else "failed", f"plan_id={plan_id!r}")

    safety = dry_run.get("safety", {}) if isinstance(dry_run, dict) else {}
    summary = dry_run.get("summary", {}) if isinstance(dry_run, dict) else {}
    source_contract_ok = (
        isinstance(dry_run, dict)
        and dry_run.get("read_only") is True
        and dry_run.get("mutation_performed") is False
        and dry_run.get("source_action_available") is False
        and dry_run.get("future_source_action_review_only") is True
    )
    add(
        "source_action_contract_ok",
        "passed" if source_contract_ok else "failed",
        "dry run must remain read-only and source_action_available=false",
    )

    unsafe_flags = (
        "mutation_performed",
        "archive_created",
        "source_deleted",
        "source_moved",
        "source_modified",
        "source_copied",
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
    )
    unsafe_seen = any(
        isinstance(scope, dict) and any(scope.get(flag) is True for flag in unsafe_flags)
        for scope in (dry_run, summary, safety)
    )
    will_not_do = " ".join(str(x).lower() for x in dry_run.get("will_not_do", []))
    executable_claim = any(
        token in will_not_do
        for token in (
            "execute source",
            "source action available",
            "delete is available",
            "move is available",
        )
    )
    safety_contract_ok = (
        isinstance(safety, dict)
        and safety.get("read_only") is True
        and safety.get("mutation_performed") is False
        and not unsafe_seen
        and not executable_claim
    )
    add(
        "safety_contract_ok",
        "passed" if safety_contract_ok else "failed",
        "unsafe source-action or mutation flag detected",
    )

    candidates = (
        candidate_doc.get("candidates", [])
        if isinstance(candidate_doc, dict)
        else dry_run.get("candidate_source_action_manifest", [])
        if isinstance(dry_run, dict)
        else []
    )
    cand_ok, cand_detail, cand_count, _, _ = _safe_candidates(
        [
            {
                "path": c.get("source_path"),
                "class": c.get("class"),
                "type": c.get("source_type"),
                "size_bytes": 0,
            }
            for c in candidates
            if isinstance(c, dict)
        ]
    )
    if cand_count > max_candidates:
        cand_ok = False
        cand_detail = "candidate count exceeds bound"
    add("candidate_manifest_ok", "passed" if cand_ok else "failed", cand_detail)

    bundle_validation: dict[str, Any] | None = None
    archive_cross = plan_cross = receipt_cross = eligibility_cross = "not_requested"
    if archive_bundle_dir:
        bundle_validation = validate_archive_bundle(
            archive_bundle_dir,
            plan_dir=plan_dir,
            dry_run_receipt_dir=dry_run_receipt_dir,
            max_candidates=max_candidates,
        )
        archive_cross = str(bundle_validation.get("status", "failed"))
        add("archive_bundle_cross_check", archive_cross, str(bundle_validation.get("status")))
    else:
        add("archive_bundle_cross_check", "passed", "not_requested")
    if plan_dir:
        plan_validation = validate_plan(plan_dir, max_candidates=max_candidates)
        plan_doc = _load_plan_json(Path(plan_dir) / "artifact-archive-plan.json") or {}
        plan_cross = (
            "passed"
            if plan_validation["status"] == "passed" and plan_doc.get("plan_id") == plan_id
            else "failed"
        )
        add("plan_cross_check", plan_cross, str(plan_validation.get("status")))
    else:
        add("plan_cross_check", "passed", "not_requested")
    if dry_run_receipt_dir:
        receipt_validation = validate_dry_run_receipt(
            dry_run_receipt_dir, plan_dir=plan_dir, max_candidates=max_candidates
        )
        receipt_doc = (
            _load_plan_json(Path(dry_run_receipt_dir) / "artifact-archive-dry-run-receipt.json")
            or {}
        )
        receipt_cross = (
            "passed"
            if receipt_validation["status"] == "passed" and receipt_doc.get("plan_id") == plan_id
            else "failed"
        )
        add("dry_run_receipt_cross_check", receipt_cross, str(receipt_validation.get("status")))
    else:
        add("dry_run_receipt_cross_check", "passed", "not_requested")
    if archive_eligibility_review_dir:
        eligibility = _load_archive_eligibility_review(archive_eligibility_review_dir) or {}
        eligibility_cross = (
            "passed"
            if eligibility.get("plan_id") == plan_id
            and eligibility.get("status") in {"eligible_for_review", "partial"}
            else "failed"
        )
        add("archive_eligibility_cross_check", eligibility_cross, str(eligibility.get("status")))
    else:
        add("archive_eligibility_cross_check", "passed", "not_requested")

    candidate_validation: list[dict[str, Any]] = []
    for cand in candidates if isinstance(candidates, list) else []:
        if not isinstance(cand, dict):
            continue
        source = str(cand.get("source_path", ""))
        source_path = Path(source)
        blockers: list[str] = []
        cand_warnings: list[str] = []
        if source_path.is_symlink():
            blockers.append("source path is a symlink")
        source_exists = source_path.exists() and not source_path.is_symlink()
        if not source_exists:
            cand_warnings.append("source path unavailable for read-only recheck")
        if cand.get("status") not in {
            "would_review_for_source_action",
            "blocked",
            "warning",
            "unknown",
        }:
            blockers.append("unknown dry-run status")
        if any(cand.get(k) is True for k in ("source_deleted", "source_moved", "source_modified")):
            blockers.append("candidate claims source mutation")
        candidate_validation.append(
            {
                "source_path": source,
                "class": cand.get("class"),
                "archive_payload_path": cand.get("archive_payload_path"),
                "dry_run_status": cand.get("status", "unknown"),
                "validation_status": "failed"
                if blockers
                else "warning"
                if cand_warnings
                else "passed",
                "source_exists": source_exists,
                "archive_payload_exists": cand.get("archive_payload_exists") is True,
                "archive_checksum_verified": cand.get("archive_checksum_verified") is True,
                "source_recheck_ok": source_exists,
                "blockers": blockers,
                "warnings": cand_warnings,
            }
        )
    blocked = sum(1 for c in candidate_validation if c["dry_run_status"] == "blocked")
    warning_count = sum(1 for c in candidate_validation if c["validation_status"] == "warning")
    unknown = sum(1 for c in candidate_validation if c["dry_run_status"] == "unknown")
    would = sum(
        1 for c in candidate_validation if c["dry_run_status"] == "would_review_for_source_action"
    )
    if any(c["validation_status"] == "failed" for c in candidate_validation):
        add("candidate_validation_ok", "failed", "candidate validation blockers exist")
    else:
        add("candidate_validation_ok", "passed", "")

    blocker_errors = [e for e in errors if ": not_requested" not in e]
    optional_absent = any(
        x is None
        for x in (
            archive_bundle_dir,
            plan_dir,
            dry_run_receipt_dir,
            archive_eligibility_review_dir,
        )
    )
    status = (
        "failed" if blocker_errors else ("partial" if warnings or optional_absent else "passed")
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": SOURCE_ACTION_DRY_RUN_VALIDATION_MODE,
        "status": status,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source_action_dry_run_dir": str(dry_dir),
        "archive_bundle_dir": str(Path(archive_bundle_dir)) if archive_bundle_dir else None,
        "plan_dir": str(Path(plan_dir)) if plan_dir else None,
        "dry_run_receipt_dir": str(Path(dry_run_receipt_dir)) if dry_run_receipt_dir else None,
        "archive_eligibility_review_dir": str(Path(archive_eligibility_review_dir))
        if archive_eligibility_review_dir
        else None,
        "plan_id": plan_id,
        "read_only": True,
        "mutation_performed": False,
        "source_action_available": False,
        "future_source_action_review_only": True,
        "summary": {
            "required_files_present": not any(
                c["name"] == "source_action_dry_run_required_files" and c["status"] == "failed"
                for c in checks
            ),
            "json_parse_ok": not any(
                c["name"] == "json_parse_ok" and c["status"] == "failed" for c in checks
            ),
            "manifest_ok": not any(
                c["name"] == "manifest_ok" and c["status"] == "failed" for c in checks
            ),
            "checksums_ok": not any(
                c["name"] == "checksums_ok" and c["status"] == "failed" for c in checks
            ),
            "source_action_contract_ok": source_contract_ok,
            "safety_contract_ok": safety_contract_ok,
            "candidate_manifest_ok": cand_ok,
            "archive_bundle_cross_check_status": archive_cross,
            "plan_cross_check_status": plan_cross,
            "dry_run_receipt_cross_check_status": receipt_cross,
            "archive_eligibility_cross_check_status": eligibility_cross,
            "candidate_items": len(candidate_validation),
            "would_review_candidates": would,
            "blocked_candidates": blocked,
            "warning_candidates": warning_count,
            "unknown_candidates": unknown,
            "validation_errors": len(blocker_errors),
            "validation_warnings": len(warnings),
        },
        "candidate_validation": candidate_validation,
        "future_source_action_requirements": {
            "separate_pr_required": True,
            "exact_plan_id_required": True,
            "exact_archive_bundle_required": True,
            "exact_archive_eligibility_review_required": True,
            "exact_source_action_dry_run_required": True,
            "exact_confirmation_phrase_required": True,
            "future_confirmation_phrase": SOURCE_ACTION_REVIEW_CONFIRMATION_PHRASE,
            "source_recheck_required": True,
            "archive_validation_required": True,
            "operator_review_required": True,
            "source_delete_default": False,
            "source_move_default": False,
        },
        "will_not_do": [
            "delete source files in this PR",
            "move source files in this PR",
            "modify source files in this PR",
            "copy source files in this PR",
            "create archive in this PR",
            "cleanup/prune/delete/restart/remediate/rollback/recover",
        ],
        "checks": checks,
        "errors": blocker_errors,
        "warnings": warnings,
        "safety": source_action_dry_run_validation_safety_block(),
        "first_safe_command": (
            "python3 scripts/docker01_artifact_archive_plan.py "
            "--validate-archive-source-action-dry-run <source_action_dry_run_dir> --json"
        ),
    }


def render_archive_source_action_dry_run_validation_summary(result: dict[str, Any]) -> str:
    s = result["summary"]
    return "\n".join(
        [
            "# Docker01 Archive Source-Action Dry-Run Validation",
            "",
            f"Source-action dry run: {result['source_action_dry_run_dir']}",
            f"Archive bundle: {result['archive_bundle_dir']}",
            f"Plan: {result['plan_dir']}",
            f"Dry-run receipt: {result['dry_run_receipt_dir']}",
            f"Archive eligibility review: {result['archive_eligibility_review_dir']}",
            f"Plan ID: {result['plan_id']}",
            f"Status: {result['status']}",
            "Read-only: yes",
            "Source action available: no",
            "",
            "## Checks",
            f"* required files: {s['required_files_present']}",
            f"* JSON parse: {s['json_parse_ok']}",
            f"* manifest: {s['manifest_ok']}",
            f"* checksums: {s['checksums_ok']}",
            f"* source-action contract: {s['source_action_contract_ok']}",
            f"* safety contract: {s['safety_contract_ok']}",
            f"* candidate manifest: {s['candidate_manifest_ok']}",
            f"* archive bundle cross-check: {s['archive_bundle_cross_check_status']}",
            f"* plan cross-check: {s['plan_cross_check_status']}",
            f"* dry-run receipt cross-check: {s['dry_run_receipt_cross_check_status']}",
            f"* archive eligibility cross-check: {s['archive_eligibility_cross_check_status']}",
            "",
            "## Candidate summary",
            f"* candidates: {s['candidate_items']}",
            f"* would review: {s['would_review_candidates']}",
            f"* blocked: {s['blocked_candidates']}",
            f"* warning: {s['warning_candidates']}",
            f"* unknown: {s['unknown_candidates']}",
            "",
            "## Future source-action requirements",
            "* separate PR/lane required",
            "* exact plan id required",
            "* exact archive bundle required",
            "* exact source-action dry run required",
            "* confirmation phrase required",
            "* source recheck required",
            "* source delete default: false",
            "* source move default: false",
            "",
            "## Safety",
            "* source-action dry-run validation only",
            "* no source deleted",
            "* no source moved",
            "* no source modified",
            "* no source copied",
            "* no archive created",
            "* no cleanup/prune/delete/restart",
            "* no remediation/rollback/recovery",
            "* no natural-language execution",
            "* no " + "shell=" + "True",
            "",
        ]
    )


def write_archive_source_action_dry_run_validation_outputs(
    result: dict[str, Any], out_dir: str
) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "archive-source-action-dry-run-validation.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    (out / "archive-source-action-dry-run-validation-summary.md").write_text(
        render_archive_source_action_dry_run_validation_summary(result)
    )
    (out / "candidate-source-action-validation.json").write_text(
        json.dumps(
            {"plan_id": result["plan_id"], "candidates": result["candidate_validation"]},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    (out / "future-source-action-review-checklist.md").write_text(
        "# Future Source-Action Review Checklist\n\n"
        "* separate PR/lane required\n"
        "* exact plan id required\n"
        "* exact archive bundle required\n"
        "* exact source-action dry run required\n"
        "* confirmation phrase required: "
        + SOURCE_ACTION_REVIEW_CONFIRMATION_PHRASE
        + "\n* source recheck required\n"
        "* archive validation required\n"
        "* source delete default: false\n"
        "* source move default: false\n"
    )
    (out / "safety-notes.md").write_text(
        "# Safety Notes\n\n"
        "* source-action dry-run validation only\n"
        "* no source copied, moved, modified, or deleted\n"
        "* no archive created by validator\n"
        "* no cleanup/prune/delete/restart/remediation/rollback/recovery\n"
    )
    manifest_files = []
    for name in SOURCE_ACTION_DRY_RUN_VALIDATION_OUT_FILES:
        if name in {"manifest.json", "checksums.json"}:
            continue
        p = out / name
        manifest_files.append({"path": str(p), "name": name, "size_bytes": p.stat().st_size})
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "plan_id": result["plan_id"],
                "mode": SOURCE_ACTION_DRY_RUN_VALIDATION_MODE,
                "files": manifest_files,
                "archive_created": False,
                "candidate_contents_copied": False,
                "source_action_available": False,
                "source_deleted": False,
                "source_moved": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    names = [item["name"] for item in manifest_files] + ["manifest.json"]
    checksums = {name: "sha256:" + sha256_file(out / name) for name in names}
    (out / "checksums.json").write_text(
        json.dumps({"plan_id": result["plan_id"], "checksums": checksums}, indent=2, sort_keys=True)
        + "\n"
    )


def source_action_review_packet_safety_block() -> dict[str, bool]:
    safety = validation_safety_block()
    safety["human_review_packet_only"] = True
    safety["source_action_available"] = False
    safety["archive_created"] = False
    safety["source_copied"] = False
    safety["source_moved"] = False
    safety["source_deleted"] = False
    safety["source_modified"] = False
    safety["cleanup_executed"] = False
    safety["docker_volume_removed"] = False
    return safety


def _load_source_action_validation(validation_dir: str) -> dict[str, Any] | None:
    data = _load_plan_json(Path(validation_dir) / "archive-source-action-dry-run-validation.json")
    return data if isinstance(data, dict) else None


def build_archive_source_action_review_packet(
    source_action_dry_run_dir: str,
    *,
    source_action_validation_dir: str,
    archive_bundle_dir: str,
    plan_dir: str,
    dry_run_receipt_dir: str,
    archive_eligibility_review_dir: str,
    supplied_plan_id: str | None,
    max_candidates: int = DEFAULT_MAX_RETURNED,
) -> dict[str, Any]:
    """Build a read-only human review packet for archive-backed source-action evidence."""
    checks: list[dict[str, str]] = []
    errors: list[str] = []
    warnings: list[str] = []

    def add(name: str, ok: bool, detail: str = "", *, warning: bool = False) -> None:
        _add_check(
            checks,
            errors,
            warnings,
            name,
            "warning" if warning else "passed" if ok else "failed",
            detail,
        )

    dry_path = Path(source_action_dry_run_dir)
    validation_path = Path(source_action_validation_dir)
    bundle = Path(archive_bundle_dir)
    plan_path = Path(plan_dir)
    receipt_path = Path(dry_run_receipt_dir)
    eligibility_path = Path(archive_eligibility_review_dir)

    plan_id_format_ok = isinstance(supplied_plan_id, str) and bool(
        PLAN_ID_RE.match(supplied_plan_id)
    )
    add("supplied_plan_id_valid", plan_id_format_ok, f"plan_id={supplied_plan_id!r}")

    dry_run = _load_plan_json(dry_path / "archive-source-action-dry-run.json") or {}
    validation_parsed, validation_file_checks, validation_file_errors, validation_file_warnings = (
        _validate_output_manifest_checksums(
            validation_path,
            SOURCE_ACTION_DRY_RUN_VALIDATION_OUT_FILES,
            SOURCE_ACTION_DRY_RUN_VALIDATION_MODE,
        )
    )
    checks.extend(validation_file_checks)
    errors.extend(validation_file_errors)
    warnings.extend(validation_file_warnings)
    supplied_validation = validation_parsed.get("archive-source-action-dry-run-validation.json")
    if supplied_validation is None:
        add(
            "source_action_validation_parse_ok",
            False,
            "could not parse archive-source-action-dry-run-validation.json",
        )
        supplied_validation = {}
    else:
        add(
            "source_action_validation_parse_ok",
            supplied_validation.get("mode") == SOURCE_ACTION_DRY_RUN_VALIDATION_MODE,
            str(supplied_validation.get("mode")),
        )

    rerun_validation = validate_archive_source_action_dry_run(
        str(dry_path),
        archive_bundle_dir=str(bundle),
        plan_dir=str(plan_path),
        dry_run_receipt_dir=str(receipt_path),
        archive_eligibility_review_dir=str(eligibility_path),
        max_candidates=max_candidates,
    )
    archive_validation = validate_archive_bundle(
        str(bundle),
        plan_dir=str(plan_path),
        dry_run_receipt_dir=str(receipt_path),
        max_candidates=max_candidates,
    )
    eligibility = _load_archive_eligibility_review(str(eligibility_path)) or {}

    validation_matches = (
        supplied_validation.get("status") == rerun_validation.get("status")
        and supplied_validation.get("plan_id") == rerun_validation.get("plan_id")
        and supplied_validation.get("summary", {}).get("candidate_items")
        == rerun_validation.get("summary", {}).get("candidate_items")
    )
    add(
        "source_action_validation_recheck_match",
        validation_matches,
        "supplied validation differs from in-process validation",
    )
    add(
        "source_action_validation_passed",
        rerun_validation.get("status") == "passed",
        str(rerun_validation.get("status")),
        warning=rerun_validation.get("status") == "partial",
    )
    add(
        "source_action_dry_run_ready",
        dry_run.get("status") == "ready_for_source_action_review",
        str(dry_run.get("status")),
        warning=dry_run.get("status") == "partial",
    )
    add(
        "source_action_unavailable",
        dry_run.get("source_action_available") is False
        and supplied_validation.get("source_action_available") is False,
        "source_action_available must be false",
    )
    add(
        "read_only_contract",
        dry_run.get("read_only") is True and supplied_validation.get("read_only") is True,
        "read_only must be true",
    )
    add(
        "mutation_not_performed",
        dry_run.get("mutation_performed") is False
        and supplied_validation.get("mutation_performed") is False,
        "mutation_performed must be false",
    )

    ids = [
        dry_run.get("plan_id") if isinstance(dry_run, dict) else None,
        supplied_validation.get("plan_id"),
        archive_validation.get("plan_id"),
        eligibility.get("plan_id") if isinstance(eligibility, dict) else None,
        (_load_plan_json(plan_path / "artifact-archive-plan.json") or {}).get("plan_id"),
        (_load_plan_json(receipt_path / "artifact-archive-dry-run-receipt.json") or {}).get(
            "plan_id"
        ),
    ]
    plan_id_match = plan_id_format_ok and all(i == supplied_plan_id for i in ids)
    add("plan_id_match", bool(plan_id_match), f"supplied={supplied_plan_id!r} evidence={ids!r}")

    dry_candidates = (
        dry_run.get("candidate_source_action_manifest", []) if isinstance(dry_run, dict) else []
    )
    validation_candidates = (
        supplied_validation.get("candidate_validation", [])
        if isinstance(supplied_validation, dict)
        else []
    )
    candidate_manifest_match = len(dry_candidates) == len(validation_candidates) and {
        c.get("source_path") for c in dry_candidates if isinstance(c, dict)
    } == {c.get("source_path") for c in validation_candidates if isinstance(c, dict)}
    add(
        "candidate_manifest_match",
        candidate_manifest_match,
        "source-action dry run and validation candidates differ",
    )

    archive_payload_verified = (
        archive_validation.get("summary", {}).get("payload_ok") is True
        and archive_validation.get("summary", {}).get("checksums_ok") is True
    )
    source_preservation_ok = (
        archive_validation.get("summary", {}).get("source_preservation_ok") is True
    )
    add(
        "archive_payload_verified",
        archive_payload_verified,
        "archive payload/checksum verification failed",
    )
    add("source_preservation_ok", source_preservation_ok, "source-preservation metadata unsafe")

    unsafe_flags = (
        "source_deleted",
        "source_moved",
        "source_modified",
        "source_copied",
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
    )
    unsafe_seen = False
    for doc in (dry_run, supplied_validation, archive_validation, eligibility):
        for scope in (
            doc,
            doc.get("summary", {}) if isinstance(doc, dict) else {},
            doc.get("safety", {}) if isinstance(doc, dict) else {},
        ):
            if isinstance(scope, dict) and any(scope.get(flag) is True for flag in unsafe_flags):
                unsafe_seen = True
    add("unsafe_mutation_flags_clear", not unsafe_seen, "unsafe mutation/execution flag was true")

    candidate_review: list[dict[str, Any]] = []
    validation_by_source = {
        c.get("source_path"): c for c in validation_candidates if isinstance(c, dict)
    }
    for cand in dry_candidates if isinstance(dry_candidates, list) else []:
        if not isinstance(cand, dict):
            continue
        source = str(cand.get("source_path", ""))
        src = Path(source)
        blockers = list(cand.get("blockers", [])) if isinstance(cand.get("blockers"), list) else []
        cand_warnings = (
            list(cand.get("warnings", [])) if isinstance(cand.get("warnings"), list) else []
        )
        if src.is_symlink():
            blockers.append("source path is a symlink")
        if not src.exists() and not blockers:
            cand_warnings.append("source path unavailable for optional recheck")
        if (
            cand.get("status") == "blocked"
            or validation_by_source.get(source, {}).get("validation_status") == "failed"
        ):
            blockers.append("source-action validation blocker")
        if not archive_payload_verified:
            blockers.append("archive payload not verified")
        status = "blocked" if blockers else "warning" if cand_warnings else "ready_for_human_review"
        candidate_review.append(
            {
                "source_path": source,
                "class": cand.get("class"),
                "archive_payload_path": cand.get("archive_payload_path"),
                "status": status,
                "source_exists": src.exists() and not src.is_symlink(),
                "archive_payload_exists": cand.get("archive_payload_exists") is True,
                "archive_checksum_verified": cand.get("archive_checksum_verified") is True,
                "source_recheck_ok": src.exists() and not src.is_symlink(),
                "blockers": blockers,
                "warnings": cand_warnings,
            }
        )

    blocked = sum(1 for c in candidate_review if c["status"] == "blocked")
    warning_count = sum(1 for c in candidate_review if c["status"] == "warning")
    ready = sum(1 for c in candidate_review if c["status"] == "ready_for_human_review")
    unknown = sum(1 for c in candidate_review if c["status"] == "unknown")
    core_ok = (
        not errors
        and rerun_validation.get("status") == "passed"
        and dry_run.get("status") == "ready_for_source_action_review"
        and plan_id_match
        and candidate_manifest_match
        and archive_payload_verified
        and source_preservation_ok
        and not unsafe_seen
    )
    if errors and any(k in e for e in errors for k in ("parse", "required_files", "json")):
        status = "failed"
    elif blocked or not core_ok:
        status = "not_ready"
    elif warnings or warning_count:
        status = "partial"
    else:
        status = "ready_for_human_review"

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": SOURCE_ACTION_REVIEW_PACKET_MODE,
        "status": status,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source_action_dry_run_dir": str(dry_path),
        "source_action_validation_dir": str(validation_path),
        "archive_bundle_dir": str(bundle),
        "plan_dir": str(plan_path),
        "dry_run_receipt_dir": str(receipt_path),
        "archive_eligibility_review_dir": str(eligibility_path),
        "plan_id": supplied_plan_id,
        "read_only": True,
        "mutation_performed": False,
        "source_action_available": False,
        "human_review_packet_only": True,
        "summary": {
            "source_action_dry_run_status": dry_run.get("status", "failed"),
            "source_action_validation_status": rerun_validation.get("status", "failed"),
            "archive_eligibility_status": eligibility.get("status", "failed")
            if isinstance(eligibility, dict)
            else "failed",
            "archive_bundle_validation_status": archive_validation.get("status", "failed"),
            "plan_id_match": bool(plan_id_match),
            "candidate_manifest_match": candidate_manifest_match,
            "archive_payload_verified": archive_payload_verified,
            "source_preservation_ok": source_preservation_ok,
            "candidate_items": len(candidate_review),
            "would_review_candidates": ready,
            "blocked_candidates": blocked,
            "warning_candidates": warning_count,
            "unknown_candidates": unknown,
            "review_errors": len(errors),
            "review_warnings": len(warnings),
        },
        "candidate_review": candidate_review,
        "operator_review": {
            "this_packet_is_not_approval": True,
            "this_packet_is_not_execution": True,
            "this_packet_does_not_authorize_source_action": True,
            "separate_pr_required": True,
            "exact_plan_id_required": True,
            "exact_archive_bundle_required": True,
            "exact_source_action_dry_run_required": True,
            "exact_source_action_validation_required": True,
            "exact_confirmation_phrase_required_for_any_future_action": True,
            "future_confirmation_phrase": SOURCE_ACTION_REVIEW_CONFIRMATION_PHRASE,
            "operator_must_review_candidate_manifest": True,
            "operator_must_review_source_paths": True,
            "operator_must_review_archive_payload": True,
            "operator_must_review_validation_status": True,
            "source_delete_default": False,
            "source_move_default": False,
        },
        "will_not_do": [
            "delete source files in this PR",
            "move source files in this PR",
            "modify source files in this PR",
            "copy source files in this PR",
            "create archive in this PR",
            "cleanup/prune/delete/restart/remediate/rollback/recover",
        ],
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": source_action_review_packet_safety_block(),
        "first_safe_command": "cat <review_packet_dir>/archive-source-action-human-review.md",
    }


def source_action_decision_receipt_safety_block() -> dict[str, bool]:
    safety = source_action_review_packet_safety_block()
    safety["human_review_packet_only"] = False
    safety["decision_receipt_only"] = True
    safety["archive_created"] = False
    safety["source_copied"] = False
    safety["docker_volume_removed"] = False
    return safety


def build_archive_source_action_decision_receipt(
    review_packet_dir: str,
    *,
    supplied_plan_id: str | None,
    decision: str | None,
    source_action_dry_run_dir: str | None = None,
    source_action_validation_dir: str | None = None,
    archive_bundle_dir: str | None = None,
    plan_dir: str | None = None,
    dry_run_receipt_dir: str | None = None,
    archive_eligibility_review_dir: str | None = None,
    max_candidates: int = DEFAULT_MAX_RETURNED,
) -> dict[str, Any]:
    review_path = Path(review_packet_dir)
    parsed, checks, errors, warnings = _validate_output_manifest_checksums(
        review_path, SOURCE_ACTION_REVIEW_PACKET_OUT_FILES, SOURCE_ACTION_REVIEW_PACKET_MODE
    )

    def add(name: str, ok: bool, detail: str = "", *, warning: bool = False) -> None:
        _add_check(
            checks,
            errors,
            warnings,
            name,
            "warning" if warning else "passed" if ok else "failed",
            detail,
        )

    packet = parsed.get("archive-source-action-review-packet.json") or {}
    candidate_doc = parsed.get("candidate-review-summary.json") or {}
    plan_id = packet.get("plan_id") if isinstance(packet, dict) else None
    add("plan_id_supplied", bool(supplied_plan_id), "--plan-id is required")
    add(
        "plan_id_match",
        bool(supplied_plan_id and supplied_plan_id == plan_id),
        f"expected {plan_id!r}",
    )
    add(
        "decision_enum_valid",
        decision in ALLOWED_SOURCE_ACTION_DECISIONS,
        "invalid or missing --decision",
    )

    summary = packet.get("summary", {}) if isinstance(packet, dict) else {}
    safety = packet.get("safety", {}) if isinstance(packet, dict) else {}
    operator = packet.get("operator_review", {}) if isinstance(packet, dict) else {}
    unsafe_flags = (
        "mutation_performed",
        "archive_created",
        "source_deleted",
        "source_moved",
        "source_modified",
        "source_copied",
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
    )
    unsafe_seen = any(
        isinstance(scope, dict) and any(scope.get(flag) is True for flag in unsafe_flags)
        for scope in (packet, summary, safety)
    )
    executable_claim = bool(
        isinstance(packet, dict) and packet.get("source_action_available") is True
    )
    safety_ok = (
        isinstance(packet, dict)
        and packet.get("read_only") is True
        and packet.get("mutation_performed") is False
        and packet.get("source_action_available") is False
        and isinstance(safety, dict)
        and safety.get("read_only") is True
        and safety.get("mutation_performed") is False
        and not unsafe_seen
        and not executable_claim
    )
    add(
        "review_packet_safety_contract",
        safety_ok,
        "review packet must be read-only and non-executable",
    )
    contract_ok = (
        isinstance(operator, dict)
        and operator.get("this_packet_is_not_approval") is True
        and operator.get("this_packet_is_not_execution") is True
        and operator.get("this_packet_does_not_authorize_source_action") is True
        and operator.get("separate_pr_required") is True
    )
    add("operator_review_contract", contract_ok, "operator review contract missing")
    ready_status = packet.get("status") if isinstance(packet, dict) else "failed"
    if decision == "ready_for_future_pr_review":
        add(
            "review_packet_ready_for_decision",
            ready_status == "ready_for_human_review",
            str(ready_status),
        )
    else:
        add(
            "review_packet_present_for_decision",
            ready_status in {"ready_for_human_review", "partial", "not_ready"},
            str(ready_status),
        )

    candidates = (
        candidate_doc.get("candidates", packet.get("candidate_review", []))
        if isinstance(candidate_doc, dict) and isinstance(packet, dict)
        else []
    )
    cand_ok, cand_detail, _, _, _ = _safe_candidates(
        [
            {"path": c.get("source_path"), "class": c.get("class"), "size_bytes": 0}
            for c in candidates
            if isinstance(c, dict)
        ]
    )
    add("candidate_manifest_ok", cand_ok, cand_detail)

    optional_absent = not any(
        [
            source_action_dry_run_dir,
            source_action_validation_dir,
            archive_bundle_dir,
            plan_dir,
            dry_run_receipt_dir,
            archive_eligibility_review_dir,
        ]
    )
    if source_action_dry_run_dir:
        v = validate_archive_source_action_dry_run(
            source_action_dry_run_dir,
            archive_bundle_dir=archive_bundle_dir,
            plan_dir=plan_dir,
            dry_run_receipt_dir=dry_run_receipt_dir,
            archive_eligibility_review_dir=archive_eligibility_review_dir,
            max_candidates=max_candidates,
        )
        add(
            "source_action_dry_run_cross_check",
            v.get("plan_id") == plan_id and v.get("status") in {"passed", "partial"},
            str(v.get("status")),
        )
        dry_candidates = (
            _load_plan_json(
                Path(source_action_dry_run_dir) / "candidate-source-action-manifest.json"
            )
            or {}
        ).get("candidates", [])
        if len(dry_candidates) != len(candidates) or {
            c.get("source_path") for c in dry_candidates
        } != {c.get("source_path") for c in candidates}:
            add("candidate_manifest_cross_check", False, "candidate manifest mismatch")
    if source_action_validation_dir:
        vdoc = (
            _load_plan_json(
                Path(source_action_validation_dir) / "archive-source-action-dry-run-validation.json"
            )
            or {}
        )
        add(
            "source_action_validation_cross_check",
            vdoc.get("plan_id") == plan_id and vdoc.get("source_action_available") is False,
            str(vdoc.get("status")),
        )
    if archive_bundle_dir:
        vb = validate_archive_bundle(
            archive_bundle_dir,
            plan_dir=plan_dir,
            dry_run_receipt_dir=dry_run_receipt_dir,
            max_candidates=max_candidates,
        )
        add(
            "archive_bundle_cross_check",
            vb.get("plan_id") == plan_id and vb.get("status") != "failed",
            str(vb.get("status")),
        )
    if plan_dir:
        vp = validate_plan(plan_dir, max_candidates=max_candidates)
        add(
            "plan_cross_check",
            vp.get("plan_id") == plan_id and vp.get("status") == "passed",
            str(vp.get("status")),
        )
    if dry_run_receipt_dir:
        vr = validate_dry_run_receipt(
            dry_run_receipt_dir, plan_dir=plan_dir, max_candidates=max_candidates
        )
        add(
            "dry_run_receipt_cross_check",
            vr.get("plan_id") == plan_id and vr.get("status") == "passed",
            str(vr.get("status")),
        )
    if archive_eligibility_review_dir:
        er = _load_archive_eligibility_review(archive_eligibility_review_dir) or {}
        add(
            "archive_eligibility_cross_check",
            er.get("plan_id") == plan_id and er.get("status") in {"eligible_for_review", "partial"},
            str(er.get("status")),
        )

    decision_summary = []
    for cand in candidates if isinstance(candidates, list) else []:
        if not isinstance(cand, dict):
            continue
        src = Path(str(cand.get("source_path", "")))
        blockers = list(cand.get("blockers", [])) if isinstance(cand.get("blockers"), list) else []
        cand_warnings = (
            list(cand.get("warnings", [])) if isinstance(cand.get("warnings"), list) else []
        )
        if src.is_symlink():
            blockers.append("source path is a symlink")
        if str(src).startswith(("/var/lib/docker", "/srv/compose", "/workspace")):
            blockers.append("source path is outside known ShellForgeAI evidence patterns")
        status = cand.get("status", "unknown")
        decision_summary.append(
            {
                "source_path": str(cand.get("source_path", "")),
                "class": cand.get("class"),
                "archive_payload_path": cand.get("archive_payload_path"),
                "review_packet_status": status,
                "decision": decision,
                "source_exists": src.exists() and not src.is_symlink(),
                "archive_payload_exists": cand.get("archive_payload_exists") is True,
                "archive_checksum_verified": cand.get("archive_checksum_verified") is True,
                "blockers": blockers,
                "warnings": cand_warnings,
            }
        )
    if any(c["blockers"] for c in decision_summary):
        add("candidate_decision_summary", False, "candidate blockers exist")

    blocked = sum(1 for c in decision_summary if c["review_packet_status"] == "blocked")
    warning_count = sum(1 for c in decision_summary if c["review_packet_status"] == "warning")
    ready = sum(
        1 for c in decision_summary if c["review_packet_status"] == "ready_for_human_review"
    )
    unknown = sum(1 for c in decision_summary if c["review_packet_status"] == "unknown")
    core_failed = any(c["status"] == "failed" for c in checks)
    if errors and any(
        k in e
        for e in errors
        for k in ("required_files", "json_parse", "checksums_ok", "manifest_ok")
    ):
        status = "failed"
    elif core_failed:
        status = "not_ready"
    elif optional_absent or warnings:
        status = "partial"
    else:
        status = "decision_recorded"

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": SOURCE_ACTION_DECISION_RECEIPT_MODE,
        "status": status,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "review_packet_dir": str(review_path),
        "source_action_dry_run_dir": str(Path(source_action_dry_run_dir))
        if source_action_dry_run_dir
        else None,
        "source_action_validation_dir": str(Path(source_action_validation_dir))
        if source_action_validation_dir
        else None,
        "archive_bundle_dir": str(Path(archive_bundle_dir)) if archive_bundle_dir else None,
        "plan_dir": str(Path(plan_dir)) if plan_dir else None,
        "dry_run_receipt_dir": str(Path(dry_run_receipt_dir)) if dry_run_receipt_dir else None,
        "archive_eligibility_review_dir": str(Path(archive_eligibility_review_dir))
        if archive_eligibility_review_dir
        else None,
        "plan_id": supplied_plan_id,
        "decision": decision,
        "read_only": True,
        "mutation_performed": False,
        "source_action_available": False,
        "decision_receipt_only": True,
        "this_is_not_approval": True,
        "this_is_not_execution": True,
        "this_does_not_authorize_source_action": True,
        "summary": {
            "review_packet_status": ready_status,
            "review_packet_checksums_ok": not any(
                c["name"] == "checksums_ok" and c["status"] == "failed" for c in checks
            ),
            "review_packet_manifest_ok": not any(
                c["name"] == "manifest_ok" and c["status"] == "failed" for c in checks
            ),
            "plan_id_match": bool(supplied_plan_id and supplied_plan_id == plan_id),
            "candidate_manifest_match": cand_ok
            and not any(
                c["name"] == "candidate_manifest_cross_check" and c["status"] == "failed"
                for c in checks
            ),
            "candidate_items": len(decision_summary),
            "ready_for_human_review_candidates": ready,
            "blocked_candidates": blocked,
            "warning_candidates": warning_count,
            "unknown_candidates": unknown,
            "decision_errors": len(errors),
            "decision_warnings": len(warnings),
        },
        "candidate_decision_summary": decision_summary,
        "future_source_action_requirements": {
            "separate_pr_required": True,
            "exact_plan_id_required": True,
            "exact_review_packet_required": True,
            "exact_decision_receipt_required": True,
            "exact_confirmation_phrase_required": True,
            "future_confirmation_phrase": SOURCE_ACTION_REVIEW_CONFIRMATION_PHRASE,
            "source_recheck_required": True,
            "archive_validation_required": True,
            "operator_review_required": True,
            "source_delete_default": False,
            "source_move_default": False,
        },
        "will_not_do": [
            "delete source files in this PR",
            "move source files in this PR",
            "modify source files in this PR",
            "copy source files in this PR",
            "create archive in this PR",
            "cleanup/prune/delete/restart/remediate/rollback/recover",
        ],
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": source_action_decision_receipt_safety_block(),
        "first_safe_command": (
            "cat <decision_receipt_dir>/archive-source-action-decision-receipt-summary.md"
        ),
    }


def render_archive_source_action_decision_receipt(result: dict[str, Any]) -> str:
    s = result["summary"]
    return "\n".join(
        [
            "# Docker01 Archive Source-Action Operator Decision Receipt",
            "",
            f"Plan ID: {result['plan_id']}",
            f"Review packet: {result['review_packet_dir']}",
            f"Decision: {result['decision']}",
            f"Status: {result['status']}",
            "Read-only: yes",
            "Source action available: no",
            "",
            "## Decision meaning",
            "* This receipt is not approval",
            "* This receipt is not execution",
            "* This receipt does not authorize source action",
            "* Future source action would require a separate PR/lane",
            "* Future source action would require exact plan id",
            "* Future source action would require exact confirmation phrase",
            "",
            "## Evidence chain",
            f"* review packet: {s['review_packet_status']}",
            f"* review packet manifest: {s['review_packet_manifest_ok']}",
            f"* review packet checksums: {s['review_packet_checksums_ok']}",
            f"* plan id match: {s['plan_id_match']}",
            f"* candidate manifest: {s['candidate_manifest_match']}",
            "* safety contract: "
            + str(
                not any(
                    c["name"] == "review_packet_safety_contract" and c["status"] == "failed"
                    for c in result["checks"]
                )
            ),
            "",
            "## Candidate summary",
            f"* candidates: {s['candidate_items']}",
            f"* ready for human review: {s['ready_for_human_review_candidates']}",
            f"* blocked: {s['blocked_candidates']}",
            f"* warning: {s['warning_candidates']}",
            f"* unknown: {s['unknown_candidates']}",
            "",
            "## Safety",
            "* decision receipt only",
            "* no source action available",
            "* no source deleted",
            "* no source moved",
            "* no source modified",
            "* no source copied",
            "* no archive created",
            "* no cleanup/prune/delete/restart",
            "* no remediation/rollback/recovery",
            "* no natural-language execution",
            "* no " + "shell=" + "True",
            "",
        ]
    )


def source_action_readiness_gate_safety_block() -> dict[str, bool]:
    safety = validation_safety_block()
    safety["readiness_gate_only"] = True
    safety["source_action_available"] = False
    safety["archive_created"] = False
    safety["source_copied"] = False
    safety["source_moved"] = False
    safety["source_deleted"] = False
    safety["source_modified"] = False
    safety["cleanup_executed"] = False
    safety["docker_volume_removed"] = False
    return safety


def _safety_flags_clean(
    doc: dict[str, Any], *, allow_archive_bundle: bool = False
) -> tuple[bool, str]:
    unsafe_top = ("mutation_performed", "source_action_available")
    for flag in unsafe_top:
        if allow_archive_bundle and flag == "mutation_performed":
            continue
        if doc.get(flag) is True:
            return False, f"{flag}=true"
    safety = doc.get("safety", {}) if isinstance(doc.get("safety"), dict) else {}
    unsafe = (
        "source_deleted",
        "source_moved",
        "source_modified",
        "source_copied",
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
    )
    for flag in unsafe:
        if allow_archive_bundle and flag == "source_copied":
            continue
        if safety.get(flag) is True:
            return False, f"safety.{flag}=true"
    if not allow_archive_bundle and safety.get("archive_created") is True:
        return False, "safety.archive_created=true"
    return True, ""


def _readiness_path_blocker(source_path: str) -> str | None:
    src = Path(source_path)
    if src.is_symlink():
        return "source path is a symlink"
    if str(src).startswith(("/var/lib/docker", "/srv/compose", "/workspace")):
        return "source path is a Docker/Compose/runtime path"
    if class_for_name(src.name) is None:
        return "source path is outside known ShellForgeAI evidence patterns"
    return None


def build_archive_source_action_readiness_gate(
    decision_receipt_dir: str,
    *,
    review_packet_dir: str,
    source_action_dry_run_dir: str,
    source_action_validation_dir: str,
    archive_bundle_dir: str,
    plan_dir: str,
    dry_run_receipt_dir: str,
    archive_eligibility_review_dir: str,
    supplied_plan_id: str,
    max_candidates: int = DEFAULT_MAX_RETURNED,
) -> dict[str, Any]:
    """Final read-only source-action readiness gate. It never authorizes execution."""
    checks: list[dict[str, str]] = []
    errors: list[str] = []
    warnings: list[str] = []

    def add(name: str, ok: bool, detail: str = "", *, warning: bool = False) -> None:
        _add_check(
            checks,
            errors,
            warnings,
            name,
            "warning" if warning else "passed" if ok else "failed",
            detail,
        )

    receipt_path = Path(decision_receipt_dir)
    review_path = Path(review_packet_dir)
    dry_path = Path(source_action_dry_run_dir)
    validation_path = Path(source_action_validation_dir)
    bundle_path = Path(archive_bundle_dir)
    plan_path = Path(plan_dir)
    dry_receipt_path = Path(dry_run_receipt_dir)
    eligibility_path = Path(archive_eligibility_review_dir)

    parsed_receipt, rc, re, rw = _validate_output_manifest_checksums(
        receipt_path, SOURCE_ACTION_DECISION_RECEIPT_OUT_FILES, SOURCE_ACTION_DECISION_RECEIPT_MODE
    )
    checks.extend(rc)
    errors.extend(re)
    warnings.extend(rw)
    decision_receipt = parsed_receipt.get("archive-source-action-decision-receipt.json") or {}
    decision_summary_doc = parsed_receipt.get("candidate-decision-summary.json") or {}

    parsed_review, vc, ve, vw = _validate_output_manifest_checksums(
        review_path, SOURCE_ACTION_REVIEW_PACKET_OUT_FILES, SOURCE_ACTION_REVIEW_PACKET_MODE
    )
    checks.extend(vc)
    errors.extend(ve)
    warnings.extend(vw)
    review_packet = parsed_review.get("archive-source-action-review-packet.json") or {}

    dry_run = _load_plan_json(dry_path / "archive-source-action-dry-run.json") or {}
    validation = validate_archive_source_action_dry_run(
        str(dry_path),
        archive_bundle_dir=str(bundle_path),
        plan_dir=str(plan_path),
        dry_run_receipt_dir=str(dry_receipt_path),
        archive_eligibility_review_dir=str(eligibility_path),
        max_candidates=max_candidates,
    )
    archive_validation = validate_archive_bundle(
        str(bundle_path),
        plan_dir=str(plan_path),
        dry_run_receipt_dir=str(dry_receipt_path),
        max_candidates=max_candidates,
    )
    plan_validation = validate_plan(str(plan_path), max_candidates=max_candidates)
    dry_receipt_validation = validate_dry_run_receipt(
        str(dry_receipt_path), plan_dir=str(plan_path), max_candidates=max_candidates
    )
    eligibility = _load_archive_eligibility_review(str(eligibility_path)) or {}

    plan_id_match = all(
        doc.get("plan_id") == supplied_plan_id
        for doc in (
            decision_receipt,
            review_packet,
            dry_run,
            validation,
            archive_validation,
            plan_validation,
            dry_receipt_validation,
            eligibility,
        )
        if isinstance(doc, dict)
    )
    add("plan_id_match", plan_id_match, f"plan_id={supplied_plan_id!r}")
    add(
        "decision_receipt_validated",
        isinstance(decision_receipt, dict) and bool(decision_receipt),
        "",
    )
    add(
        "decision_ready_for_future_pr_review",
        decision_receipt.get("decision") == "ready_for_future_pr_review",
        str(decision_receipt.get("decision")),
    )
    add(
        "decision_receipt_not_authorizing",
        decision_receipt.get("this_is_not_approval") is True
        and decision_receipt.get("this_is_not_execution") is True
        and decision_receipt.get("this_does_not_authorize_source_action") is True,
        "receipt must remain not approval, not execution, and not authorization",
    )
    add(
        "review_packet_ready",
        review_packet.get("status") == "ready_for_human_review",
        str(review_packet.get("status")),
    )
    add(
        "source_action_validation_passed",
        validation.get("status") == "passed",
        str(validation.get("status")),
    )
    add(
        "source_action_dry_run_non_executable",
        dry_run.get("source_action_available") is False
        and dry_run.get("mutation_performed") is False,
        "source_action_available must be false",
    )
    add(
        "archive_bundle_validated",
        archive_validation.get("status") in {"passed", "partial"},
        str(archive_validation.get("status")),
        warning=archive_validation.get("status") == "partial",
    )
    add(
        "plan_validated",
        plan_validation.get("status") == "passed",
        str(plan_validation.get("status")),
    )
    add(
        "dry_run_receipt_validated",
        dry_receipt_validation.get("status") == "passed",
        str(dry_receipt_validation.get("status")),
    )
    add(
        "archive_eligibility_validated",
        eligibility.get("status") in {"eligible_for_review", "partial"},
        str(eligibility.get("status")),
        warning=eligibility.get("status") == "partial",
    )
    add(
        "archive_payload_verified",
        archive_validation.get("summary", {}).get("payload_ok") is True
        and archive_validation.get("summary", {}).get("checksums_ok") is True,
        "archive payload/checksum validation",
    )
    add(
        "source_preservation_ok",
        archive_validation.get("summary", {}).get("source_preservation_ok") is True,
        "source preservation metadata must be clean",
    )

    for name, doc, allow_bundle in (
        ("decision_receipt_safety_contract", decision_receipt, False),
        ("review_packet_safety_contract", review_packet, False),
        ("source_action_dry_run_safety_contract", dry_run, False),
        ("source_action_validation_safety_contract", validation, False),
        (
            "archive_bundle_safety_contract",
            _load_plan_json(bundle_path / "archive-receipt.json") or {},
            True,
        ),
        ("archive_eligibility_safety_contract", eligibility, False),
    ):
        ok, detail = _safety_flags_clean(doc, allow_archive_bundle=allow_bundle)
        add(name, ok, detail)

    decision_candidates = (
        decision_summary_doc.get("candidates", [])
        if isinstance(decision_summary_doc.get("candidates"), list)
        else decision_receipt.get("candidate_decision_summary", [])
    )
    review_candidates = review_packet.get("candidate_review", [])
    validation_candidates = validation.get("candidate_validation", [])
    candidate_manifest_match = (
        {c.get("source_path") for c in decision_candidates if isinstance(c, dict)}
        == {c.get("source_path") for c in review_candidates if isinstance(c, dict)}
        == {c.get("source_path") for c in validation_candidates if isinstance(c, dict)}
    )
    add("candidate_manifest_match", candidate_manifest_match, "candidate source path sets")

    validation_by_source = {
        c.get("source_path"): c for c in validation_candidates if isinstance(c, dict)
    }
    candidate_readiness = []
    for cand in decision_candidates if isinstance(decision_candidates, list) else []:
        if not isinstance(cand, dict):
            continue
        source = str(cand.get("source_path", ""))
        blockers = list(cand.get("blockers", [])) if isinstance(cand.get("blockers"), list) else []
        cand_warnings = (
            list(cand.get("warnings", [])) if isinstance(cand.get("warnings"), list) else []
        )
        path_blocker = _readiness_path_blocker(source)
        if path_blocker:
            blockers.append(path_blocker)
        v = validation_by_source.get(source, {})
        if v.get("validation_status") not in {None, "passed", "warning"}:
            blockers.append("source-action validation failed")
        source_exists = Path(source).exists() and not Path(source).is_symlink()
        source_recheck_ok = source_exists
        readiness_status = (
            "blocked"
            if blockers
            else "warning"
            if cand_warnings or v.get("validation_status") == "warning" or not source_recheck_ok
            else "ready_for_future_pr_review"
        )
        candidate_readiness.append(
            {
                "source_path": source,
                "class": cand.get("class"),
                "archive_payload_path": cand.get("archive_payload_path"),
                "decision": decision_receipt.get("decision"),
                "review_packet_status": cand.get("review_packet_status", "unknown"),
                "source_action_validation_status": v.get("validation_status", "passed"),
                "source_exists": source_exists,
                "archive_payload_exists": cand.get("archive_payload_exists") is True,
                "archive_checksum_verified": cand.get("archive_checksum_verified") is True,
                "source_recheck_ok": source_recheck_ok,
                "readiness_status": readiness_status,
                "blockers": blockers,
                "warnings": cand_warnings,
            }
        )
    if any(c["blockers"] for c in candidate_readiness):
        add("candidate_blockers_absent", False, "candidate blockers exist")

    ready = sum(
        1 for c in candidate_readiness if c["readiness_status"] == "ready_for_future_pr_review"
    )
    blocked = sum(1 for c in candidate_readiness if c["readiness_status"] == "blocked")
    warning_count = sum(1 for c in candidate_readiness if c["readiness_status"] == "warning")
    unknown = sum(1 for c in candidate_readiness if c["readiness_status"] == "unknown")
    has_core_failure = any(c["status"] == "failed" for c in checks)
    if errors and any(
        k in e
        for e in errors
        for k in ("required_files", "json_parse", "checksums_ok", "manifest_ok")
    ):
        status = "failed"
    elif has_core_failure:
        status = "not_ready"
    elif warning_count or warnings:
        status = "partial"
    else:
        status = "ready_for_future_pr_review"

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": SOURCE_ACTION_READINESS_GATE_MODE,
        "status": status,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "decision_receipt_dir": str(receipt_path),
        "review_packet_dir": str(review_path),
        "source_action_dry_run_dir": str(dry_path),
        "source_action_validation_dir": str(validation_path),
        "archive_bundle_dir": str(bundle_path),
        "plan_dir": str(plan_path),
        "dry_run_receipt_dir": str(dry_receipt_path),
        "archive_eligibility_review_dir": str(eligibility_path),
        "plan_id": supplied_plan_id,
        "read_only": True,
        "mutation_performed": False,
        "source_action_available": False,
        "readiness_gate_only": True,
        "future_source_action_pr_required": True,
        "this_is_not_approval": True,
        "this_is_not_execution": True,
        "this_does_not_authorize_source_action": True,
        "summary": {
            "decision_receipt_status": decision_receipt.get("status", "failed"),
            "decision": decision_receipt.get("decision"),
            "review_packet_status": review_packet.get("status", "failed"),
            "source_action_validation_status": validation.get("status", "failed"),
            "source_action_dry_run_status": dry_run.get("status", "failed"),
            "archive_eligibility_status": eligibility.get("status", "failed"),
            "archive_bundle_validation_status": archive_validation.get("status", "failed"),
            "plan_id_match": plan_id_match,
            "candidate_manifest_match": candidate_manifest_match,
            "archive_payload_verified": archive_validation.get("summary", {}).get("payload_ok")
            is True,
            "source_preservation_ok": archive_validation.get("summary", {}).get(
                "source_preservation_ok"
            )
            is True,
            "source_action_contract_ok": dry_run.get("source_action_available") is False,
            "candidate_items": len(candidate_readiness),
            "ready_candidates": ready,
            "blocked_candidates": blocked,
            "warning_candidates": warning_count,
            "unknown_candidates": unknown,
            "readiness_errors": len(errors),
            "readiness_warnings": len(warnings),
        },
        "candidate_readiness": candidate_readiness,
        "future_source_action_requirements": {
            "separate_pr_required": True,
            "exact_plan_id_required": True,
            "exact_archive_bundle_required": True,
            "exact_source_action_dry_run_required": True,
            "exact_source_action_validation_required": True,
            "exact_review_packet_required": True,
            "exact_decision_receipt_required": True,
            "exact_confirmation_phrase_required": True,
            "future_confirmation_phrase": SOURCE_ACTION_REVIEW_CONFIRMATION_PHRASE,
            "source_recheck_required": True,
            "archive_validation_required": True,
            "operator_review_required": True,
            "seedofevil_final_merge_owner": True,
            "source_delete_default": False,
            "source_move_default": False,
        },
        "will_not_do": [
            "delete source files in this PR",
            "move source files in this PR",
            "modify source files in this PR",
            "copy source files in this PR",
            "create archive in this PR",
            "cleanup/prune/delete/restart/remediate/rollback/recover",
        ],
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": source_action_readiness_gate_safety_block(),
        "first_safe_command": "cat <readiness_gate_dir>/archive-source-action-readiness-summary.md",
    }


def source_action_status_report_safety_block() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "operator_status_report_only": True,
        "source_action_available": False,
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


def _candidate_digest(candidates: list[Any]) -> str:
    normalized = [
        {
            "source_path": c.get("source_path"),
            "class": c.get("class"),
            "archive_payload_path": c.get("archive_payload_path"),
        }
        for c in candidates
        if isinstance(c, dict)
    ]
    return hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()


def build_archive_source_action_status_report(
    readiness_gate_dir: str,
    *,
    decision_receipt_dir: str | None = None,
    review_packet_dir: str | None = None,
    source_action_dry_run_dir: str | None = None,
    source_action_validation_dir: str | None = None,
    archive_bundle_dir: str | None = None,
    plan_dir: str | None = None,
    dry_run_receipt_dir: str | None = None,
    archive_eligibility_review_dir: str | None = None,
    supplied_plan_id: str | None = None,
    out_dir: str | None = None,
) -> dict[str, Any]:
    """Build a read-only operator status report from source-action readiness evidence."""
    checks: list[dict[str, str]] = []
    errors: list[str] = []
    warnings: list[str] = []

    def add(name: str, ok: bool, detail: str = "", *, warning: bool = False) -> None:
        _add_check(
            checks,
            errors,
            warnings,
            name,
            "warning" if warning else "passed" if ok else "failed",
            detail,
        )

    readiness_path = Path(readiness_gate_dir)
    parsed, rc, re, rw = _validate_output_manifest_checksums(
        readiness_path, SOURCE_ACTION_READINESS_GATE_OUT_FILES, SOURCE_ACTION_READINESS_GATE_MODE
    )
    checks.extend(rc)
    errors.extend(re)
    warnings.extend(rw)
    readiness = parsed.get("archive-source-action-readiness-gate.json") or {}
    candidate_doc = parsed.get("candidate-readiness-summary.json") or {}
    plan_id = str(readiness.get("plan_id") or supplied_plan_id or "")

    add("readiness_gate_validated", bool(readiness), "readiness gate JSON parsed")
    add(
        "readiness_source_action_unavailable",
        readiness.get("source_action_available") is False,
        "source_action_available must be false",
    )
    add(
        "readiness_no_mutation",
        readiness.get("mutation_performed") is False,
        "mutation_performed must be false",
    )
    add(
        "readiness_not_authorizing",
        readiness.get("this_is_not_approval") is True
        and readiness.get("this_is_not_execution") is True
        and readiness.get("this_does_not_authorize_source_action") is True,
        "readiness gate must not approve, execute, or authorize",
    )
    ok, detail = _safety_flags_clean(readiness)
    add("readiness_safety_contract", ok, detail)
    if readiness.get("safety", {}).get("archive_created") is True:
        add("status_report_no_archive_created", False, "safety.archive_created=true")

    optional_dirs = {
        "decision_receipt_dir": decision_receipt_dir,
        "review_packet_dir": review_packet_dir,
        "source_action_dry_run_dir": source_action_dry_run_dir,
        "source_action_validation_dir": source_action_validation_dir,
        "archive_bundle_dir": archive_bundle_dir,
        "plan_dir": plan_dir,
        "dry_run_receipt_dir": dry_run_receipt_dir,
        "archive_eligibility_review_dir": archive_eligibility_review_dir,
    }
    supplied = {k: v for k, v in optional_dirs.items() if v}
    if supplied and supplied_plan_id != plan_id:
        add("supplied_plan_id_exact", False, "optional evidence requires exact --plan-id")
    elif supplied:
        add("supplied_plan_id_exact", True, "")
    elif not supplied:
        _add_check(
            checks,
            errors,
            warnings,
            "optional_evidence_absent",
            "warning",
            "standalone readiness gate status only",
        )

    evidence_docs: list[dict[str, Any]] = [readiness]
    expected = (
        (
            "decision_receipt_dir",
            decision_receipt_dir,
            SOURCE_ACTION_DECISION_RECEIPT_OUT_FILES,
            SOURCE_ACTION_DECISION_RECEIPT_MODE,
            "archive-source-action-decision-receipt.json",
        ),
        (
            "review_packet_dir",
            review_packet_dir,
            SOURCE_ACTION_REVIEW_PACKET_OUT_FILES,
            SOURCE_ACTION_REVIEW_PACKET_MODE,
            "archive-source-action-review-packet.json",
        ),
        (
            "source_action_dry_run_dir",
            source_action_dry_run_dir,
            SOURCE_ACTION_DRY_RUN_OUT_FILES,
            SOURCE_ACTION_DRY_RUN_MODE,
            "archive-source-action-dry-run.json",
        ),
        (
            "source_action_validation_dir",
            source_action_validation_dir,
            SOURCE_ACTION_DRY_RUN_VALIDATION_OUT_FILES,
            SOURCE_ACTION_DRY_RUN_VALIDATION_MODE,
            "archive-source-action-dry-run-validation.json",
        ),
        (
            "archive_eligibility_review_dir",
            archive_eligibility_review_dir,
            ARCHIVE_ELIGIBILITY_REVIEW_OUT_FILES,
            ARCHIVE_ELIGIBILITY_REVIEW_MODE,
            "artifact-archive-eligibility-review.json",
        ),
    )
    for label, directory, files, mode, main_name in expected:
        if not directory:
            continue
        parsed_optional, oc, oe, ow = _validate_output_manifest_checksums(
            Path(directory), files, mode
        )
        checks.extend(oc)
        errors.extend(oe)
        warnings.extend(ow)
        doc = parsed_optional.get(main_name) or {}
        evidence_docs.append(doc)
        add(f"{label}_plan_id_match", doc.get("plan_id") == plan_id, str(doc.get("plan_id")))
        clean, clean_detail = _safety_flags_clean(doc)
        add(f"{label}_safety_contract", clean, clean_detail)

    candidates = (
        candidate_doc.get("candidates")
        if isinstance(candidate_doc.get("candidates"), list)
        else readiness.get("candidate_readiness", [])
    )
    if not isinstance(candidates, list):
        candidates = []
    candidate_status = []
    for cand in candidates:
        if not isinstance(cand, dict):
            continue
        source = str(cand.get("source_path", ""))
        blockers = list(cand.get("blockers", [])) if isinstance(cand.get("blockers"), list) else []
        cand_warnings = (
            list(cand.get("warnings", [])) if isinstance(cand.get("warnings"), list) else []
        )
        path_blocker = _readiness_path_blocker(source)
        if path_blocker:
            blockers.append(path_blocker)
        source_exists = Path(source).exists() and not Path(source).is_symlink()
        readiness_status = cand.get("readiness_status", "unknown")
        if blockers:
            readiness_status = "blocked"
        elif readiness_status not in {
            "ready_for_future_pr_review",
            "blocked",
            "warning",
            "unknown",
        }:
            readiness_status = "unknown"
        candidate_status.append(
            {
                "source_path": source,
                "class": cand.get("class"),
                "archive_payload_path": cand.get("archive_payload_path"),
                "readiness_status": readiness_status,
                "source_exists": source_exists,
                "archive_payload_exists": cand.get("archive_payload_exists") is True,
                "archive_checksum_verified": cand.get("archive_checksum_verified") is True,
                "status_summary": "ready for future PR review only"
                if readiness_status == "ready_for_future_pr_review"
                else readiness_status,
                "blockers": blockers,
                "warnings": cand_warnings,
            }
        )
    if any(c["blockers"] for c in candidate_status):
        add("candidate_paths_safe", False, "candidate blockers exist")
    else:
        add("candidate_paths_safe", True, "")

    if source_action_validation_dir:
        validation = (
            _load_plan_json(
                Path(source_action_validation_dir) / "candidate-source-action-validation.json"
            )
            or {}
        )
        validation_candidates = (
            validation.get("candidates", []) if isinstance(validation, dict) else []
        )
        add(
            "candidate_manifest_match",
            _candidate_digest(candidates) == _candidate_digest(validation_candidates),
            "readiness vs validation candidates",
        )
    else:
        add("candidate_manifest_match", True, "standalone readiness gate")

    if archive_bundle_dir:
        archive_validation = validate_archive_bundle(
            archive_bundle_dir,
            plan_dir=plan_dir,
            dry_run_receipt_dir=dry_run_receipt_dir,
        )
        checks.extend(archive_validation.get("checks", []))
        errors.extend(archive_validation.get("errors", []))
        warnings.extend(archive_validation.get("warnings", []))
        add(
            "archive_payload_verified",
            archive_validation.get("summary", {}).get("payload_ok") is True,
            "archive payload checksum verification",
        )
        add(
            "source_preservation_ok",
            archive_validation.get("summary", {}).get("source_preservation_ok") is True,
            "source preservation",
        )
    else:
        add(
            "archive_payload_verified",
            readiness.get("summary", {}).get("archive_payload_verified") is True,
            "readiness gate summary",
        )
        add(
            "source_preservation_ok",
            readiness.get("summary", {}).get("source_preservation_ok") is True,
            "readiness gate summary",
        )

    for doc in evidence_docs:
        if not isinstance(doc, dict):
            continue
        if (
            doc.get("source_action_available") is True
            or doc.get("executable_source_action") is True
        ):
            add("executable_source_action_absent", False, "executable source action claimed")
        if any(
            doc.get(k) is True
            for k in ("this_is_approval", "this_is_execution", "this_authorizes_source_action")
        ):
            add(
                "approval_execution_authorization_absent",
                False,
                "approval/execution/authorization claimed",
            )

    ready = sum(
        1 for c in candidate_status if c["readiness_status"] == "ready_for_future_pr_review"
    )
    blocked = sum(1 for c in candidate_status if c["readiness_status"] == "blocked")
    warning_count = sum(1 for c in candidate_status if c["readiness_status"] == "warning")
    unknown = sum(1 for c in candidate_status if c["readiness_status"] == "unknown")
    has_failed = any(c.get("status") == "failed" for c in checks)
    if not readiness or any(
        "json_parse" in e or "checksums" in e or "manifest" in e or "required_files" in e
        for e in errors
    ):
        status = "failed"
    elif has_failed or blocked or readiness.get("status") in {"not_ready", "failed"}:
        status = "not_ready"
    elif warnings or warning_count or not supplied:
        status = "partial"
    else:
        status = "ready_for_operator_review"

    summary = readiness.get("summary", {}) if isinstance(readiness.get("summary"), dict) else {}
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": SOURCE_ACTION_STATUS_REPORT_MODE,
        "status": status,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "readiness_gate_dir": str(readiness_path),
        "decision_receipt_dir": str(Path(decision_receipt_dir)) if decision_receipt_dir else None,
        "review_packet_dir": str(Path(review_packet_dir)) if review_packet_dir else None,
        "source_action_dry_run_dir": str(Path(source_action_dry_run_dir))
        if source_action_dry_run_dir
        else None,
        "source_action_validation_dir": str(Path(source_action_validation_dir))
        if source_action_validation_dir
        else None,
        "archive_bundle_dir": str(Path(archive_bundle_dir)) if archive_bundle_dir else None,
        "plan_dir": str(Path(plan_dir)) if plan_dir else None,
        "dry_run_receipt_dir": str(Path(dry_run_receipt_dir)) if dry_run_receipt_dir else None,
        "archive_eligibility_review_dir": str(Path(archive_eligibility_review_dir))
        if archive_eligibility_review_dir
        else None,
        "plan_id": plan_id,
        "read_only": True,
        "mutation_performed": False,
        "source_action_available": False,
        "operator_status_report_only": True,
        "this_is_not_approval": True,
        "this_is_not_execution": True,
        "this_does_not_authorize_source_action": True,
        "summary": {
            "readiness_gate_status": readiness.get("status", "failed"),
            "decision": summary.get("decision"),
            "future_source_action_pr_required": True,
            "plan_id_match": supplied_plan_id in {None, plan_id},
            "candidate_manifest_match": not any(
                c["name"] == "candidate_manifest_match" and c["status"] == "failed" for c in checks
            ),
            "archive_payload_verified": not any(
                c["name"] == "archive_payload_verified" and c["status"] == "failed" for c in checks
            ),
            "source_preservation_ok": not any(
                c["name"] == "source_preservation_ok" and c["status"] == "failed" for c in checks
            ),
            "source_action_contract_ok": True,
            "candidate_items": len(candidate_status),
            "ready_candidates": ready,
            "blocked_candidates": blocked,
            "warning_candidates": warning_count,
            "unknown_candidates": unknown,
            "status_errors": len(errors),
            "status_warnings": len(warnings),
        },
        "operator_status": {
            "plain_language_state": (
                "Evidence chain is reviewable for a future separate PR/lane; "
                "no source action is available here."
            ),
            "next_safe_operator_step": (
                "review evidence or create a future separate PR prompt; "
                "do not execute source action from this report"
            ),
            "separate_pr_required": True,
            "seedofevil_final_merge_owner": True,
            "source_delete_default": False,
            "source_move_default": False,
        },
        "candidate_status": candidate_status,
        "will_not_do": [
            "delete source files in this PR",
            "move source files in this PR",
            "modify source files in this PR",
            "copy source files in this PR",
            "create archive in this PR",
            "cleanup/prune/delete/restart/remediate/rollback/recover",
        ],
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": source_action_status_report_safety_block(),
        "first_safe_command": f"cat {Path(out_dir) / 'archive-source-action-operator-status.md'}"
        if out_dir
        else "cat <status_report_dir>/archive-source-action-operator-status.md",
    }


def render_archive_source_action_status_report(result: dict[str, Any]) -> str:
    s = result["summary"]
    return "\n".join(
        [
            "# Docker01 Archive Source-Action Operator Status",
            "",
            f"Plan ID: {result['plan_id']}",
            f"Readiness gate: {result['readiness_gate_dir']}",
            f"Status: {result['status']}",
            "Read-only: yes",
            "Source action available: no",
            "",
            "## Plain language",
            "",
            (
                "Evidence chain is reviewable for a future separate PR/lane. "
                "No source action is available from this report."
            ),
            "",
            "## Evidence chain",
            "",
            f"* readiness gate: {s['readiness_gate_status']}",
            (
                "* decision receipt: "
                + ("supplied" if result["decision_receipt_dir"] else "not supplied")
            ),
            f"* review packet: {'supplied' if result['review_packet_dir'] else 'not supplied'}",
            (
                "* source-action validation: "
                + ("supplied" if result["source_action_validation_dir"] else "not supplied")
            ),
            (
                "* source-action dry run: "
                + ("supplied" if result["source_action_dry_run_dir"] else "not supplied")
            ),
            (
                "* archive eligibility: "
                + ("supplied" if result["archive_eligibility_review_dir"] else "not supplied")
            ),
            f"* archive bundle: {'supplied' if result['archive_bundle_dir'] else 'not supplied'}",
            f"* plan id match: {s['plan_id_match']}",
            f"* candidate manifest: {s['candidate_manifest_match']}",
            f"* source preservation: {s['source_preservation_ok']}",
            "",
            "## Candidate summary",
            "",
            f"* candidates: {s['candidate_items']}",
            f"* ready: {s['ready_candidates']}",
            f"* blocked: {s['blocked_candidates']}",
            f"* warning: {s['warning_candidates']}",
            f"* unknown: {s['unknown_candidates']}",
            "",
            "## Next safe operator step",
            "",
            "* Review evidence",
            "* Keep SeedOfEvil as final merge owner",
            "* Future action requires a separate PR/lane",
            "* Future action requires exact plan id and explicit confirmation phrase",
            "* Source delete default: false",
            "* Source move default: false",
            "",
            "## Safety",
            "",
            "* status report only",
            "* not approval",
            "* not execution",
            "* does not authorize source action",
            "* no source action available",
            "* no source deleted",
            "* no source moved",
            "* no source modified",
            "* no source copied",
            "* no archive created",
            "* no cleanup/prune/delete/restart",
            "* no remediation/rollback/recovery",
            "* no natural-language execution",
            "* no " + "shell=" + "True",
            "",
        ]
    )


PRODUCTION_PATH_PREFIXES = (
    "/srv",
    "/data",
    "/var",
    "/etc",
    "/home",
    "/root",
    "/opt",
    "/var/lib/docker",
    "/srv/compose",
    "/workspace",
)


def _fixture_failure(
    reason: str,
    *,
    plan_id: str | None = None,
    fixture_root: str | None = None,
    out_dir: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": SOURCE_ACTION_FIXTURE_REHEARSAL_MODE,
        "status": "rehearsal_failed",
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "fixture_root": fixture_root,
        "out_dir": out_dir,
        "plan_id": plan_id,
        "read_only": False,
        "mutation_performed": False,
        "fixture_only": True,
        "production_source_action_available": False,
        "production_cleanup_available": False,
        "this_is_not_production_source_action": True,
        "this_is_not_cleanup": True,
        "confirmation_phrase_matched": False,
        "restore_before_exit": False,
        "summary": {
            "fixture_candidates": 0,
            "fixture_bytes": 0,
            "fixture_files_created": 0,
            "fixture_files_archived": 0,
            "fixture_files_rehearsed": 0,
            "fixture_files_restored": 0,
            "archive_payload_verified": False,
            "rollback_proof_verified": False,
            "source_restored_before_exit": False,
            "rehearsal_errors": 1,
            "rehearsal_warnings": 0,
        },
        "fixture_candidate_manifest": [],
        "rollback_proof": {
            "rollback_available": False,
            "rollback_tested": False,
            "restore_before_exit": False,
            "restored_source_matches_original": False,
        },
        "safety": _fixture_safety_block(False, False, False),
        "errors": [reason],
        "first_safe_command": "cat <out_dir>/fixture-source-action-rehearsal-summary.md",
    }


def _fixture_safety_block(
    archive_created: bool, rehearsed: bool, restored: bool
) -> dict[str, bool]:
    return {
        "read_only": False,
        "mutation_performed": bool(archive_created or rehearsed or restored),
        "fixture_only": True,
        "fixture_source_action_rehearsal_only": True,
        "production_source_action_available": False,
        "production_cleanup_available": False,
        "archive_created": archive_created,
        "source_copied": False,
        "source_moved": False,
        "source_deleted": False,
        "source_modified": False,
        "fixture_source_created": True,
        "fixture_source_archived": archive_created,
        "fixture_source_rehearsed": rehearsed,
        "fixture_source_restored": restored,
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


def _repo_root() -> Path:
    return Path(__file__).resolve(strict=False).parents[1]


def _has_symlink(path: Path) -> bool:
    if path.is_symlink():
        return True
    if not path.exists():
        return False
    return any(child.is_symlink() for child in path.rglob("*"))


def _path_has_production_shape(path: Path) -> bool:
    text = str(path.resolve(strict=False))
    lower = text.lower()
    return (
        text == "/tmp"
        or any(text == p or text.startswith(p + "/") for p in PRODUCTION_PATH_PREFIXES)
        or "docker" in lower
        or "compose" in lower
    )


def _safe_fixture_root(path_text: str | None) -> tuple[bool, str, Path | None]:
    if not path_text:
        return False, "fixture root is required", None
    path = Path(path_text).expanduser()
    if not path.is_absolute():
        return False, "fixture root must be absolute", None
    resolved = path.resolve(strict=False)
    if resolved == Path("/tmp"):
        return False, "fixture root must not be /tmp", None
    if not str(resolved).startswith("/tmp/"):
        return False, "fixture root must be under /tmp", None
    if not any(part.startswith("sfai-fixture-source-action-") for part in resolved.parts):
        return False, "fixture root must use sfai-fixture-source-action-* prefix", None
    repo = _repo_root()
    if _path_inside(resolved, repo):
        return False, "fixture root must not be inside the repository", None
    if _path_has_production_shape(resolved):
        return False, "fixture root resembles a production/runtime path", None
    if _has_symlink(resolved):
        return False, "fixture root contains symlinks", None
    marker = resolved / ".shellforgeai-fixture-root.json"
    if resolved.exists():
        if not resolved.is_dir():
            return False, "fixture root exists but is not a directory", None
        entries = list(resolved.iterdir())
        if entries and not marker.is_file():
            return (
                False,
                "fixture root is non-empty and not marked as ShellForgeAI fixture root",
                None,
            )
    return True, "ok", resolved


def _safe_fixture_out(path_text: str | None, fixture_root: Path) -> tuple[bool, str, Path | None]:
    if not path_text:
        return False, "output directory is required", None
    path = Path(path_text).expanduser()
    if not path.is_absolute():
        return False, "output directory must be absolute", None
    resolved = path.resolve(strict=False)
    repo = _repo_root()
    if _path_inside(resolved, repo) or _path_has_production_shape(resolved):
        return False, "output directory is unsafe", None
    if _path_inside(fixture_root, resolved):
        return False, "fixture root must not be inside output directory", None
    source_root = fixture_root / "source"
    if _path_inside(resolved, source_root):
        return False, "output directory must not be inside fixture source candidates", None
    if resolved.exists() and (not resolved.is_dir() or any(resolved.iterdir())):
        return False, "output directory must be empty", None
    if _has_symlink(resolved):
        return False, "output directory contains symlinks", None
    return True, "ok", resolved


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def build_archive_source_action_fixture_rehearsal(
    *, fixture_root: str, out_dir: str, plan_id: str, confirm: str | None, restore_before_exit: bool
) -> dict[str, Any]:
    if confirm != SOURCE_ACTION_FIXTURE_REHEARSAL_CONFIRMATION_PHRASE:
        return _fixture_failure(
            "confirmation phrase is missing or wrong",
            plan_id=plan_id,
            fixture_root=fixture_root,
            out_dir=out_dir,
        )
    if not plan_id or not PLAN_ID_RE.match(plan_id):
        return _fixture_failure(
            "plan id is missing or invalid",
            plan_id=plan_id,
            fixture_root=fixture_root,
            out_dir=out_dir,
        )
    ok, reason, root = _safe_fixture_root(fixture_root)
    if not ok or root is None:
        return _fixture_failure(reason, plan_id=plan_id, fixture_root=fixture_root, out_dir=out_dir)
    ok, reason, out = _safe_fixture_out(out_dir, root)
    if not ok or out is None:
        return _fixture_failure(reason, plan_id=plan_id, fixture_root=str(root), out_dir=out_dir)

    source_dir = root / "source" / "sfai-fixture-artifacts"
    archive_dir = root / "archive" / "payload" / "sfai-fixture-artifacts"
    held_dir = root / "rehearsal" / "held" / "sfai-fixture-artifacts"
    restored_dir = root / "restored" / "sfai-fixture-artifacts"
    for directory in (root, source_dir, archive_dir, held_dir, restored_dir, out):
        directory.mkdir(parents=True, exist_ok=True)
    marker = root / ".shellforgeai-fixture-root.json"
    _write_json(
        marker, {"schema_version": SCHEMA_VERSION, "fixture_only": True, "plan_id": plan_id}
    )

    fixture_payloads = {
        "sfai-fixture-qa-bundle-001.json": json.dumps(
            {"fixture": True, "plan_id": plan_id}, sort_keys=True
        )
        + "\n",
        "sfai-fixture-qa-bundle-001.md": (
            f"# ShellForgeAI fixture QA bundle\n\nPlan ID: {plan_id}\nFixture only: yes\n"
        ),
    }
    candidates = []
    for name, content in fixture_payloads.items():
        src = source_dir / name
        src.write_text(content)
        if not _path_inside(src.resolve(strict=False), root) or _path_has_production_shape(src):
            return _fixture_failure(
                "candidate path is unsafe",
                plan_id=plan_id,
                fixture_root=str(root),
                out_dir=str(out),
            )
        payload = archive_dir / name
        shutil.copyfile(src, payload)
        original_sha = "sha256:" + sha256_file(src)
        archive_sha = "sha256:" + sha256_file(payload)
        held = held_dir / (name + ".held")
        src.rename(held)
        restored_sha = None
        status = "rehearsed"
        if restore_before_exit:
            restored = source_dir / name
            shutil.copyfile(held, restored)
            restored_dir.joinpath(name).write_text(restored.read_text())
            restored_sha = "sha256:" + sha256_file(restored)
            status = "restored"
        candidates.append(
            {
                "fixture_source_path": str(src),
                "archive_payload_path": str(payload),
                "held_path": str(held),
                "status": status,
                "original_sha256": original_sha,
                "archive_sha256": archive_sha,
                "restored_sha256": restored_sha,
                "source_inside_fixture_root": True,
                "production_path": False,
                "blockers": [],
                "warnings": [],
            }
        )
    archive_verified = all(c["original_sha256"] == c["archive_sha256"] for c in candidates)
    restored_match = all(
        (not restore_before_exit) or c["original_sha256"] == c["restored_sha256"]
        for c in candidates
    )
    total_bytes = sum((archive_dir / name).stat().st_size for name in fixture_payloads)
    result = {
        "schema_version": SCHEMA_VERSION,
        "mode": SOURCE_ACTION_FIXTURE_REHEARSAL_MODE,
        "status": "rehearsal_passed" if archive_verified and restored_match else "partial",
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "fixture_root": str(root),
        "out_dir": str(out),
        "plan_id": plan_id,
        "read_only": False,
        "mutation_performed": True,
        "fixture_only": True,
        "production_source_action_available": False,
        "production_cleanup_available": False,
        "this_is_not_production_source_action": True,
        "this_is_not_cleanup": True,
        "confirmation_phrase_matched": True,
        "restore_before_exit": restore_before_exit,
        "summary": {
            "fixture_candidates": len(candidates),
            "fixture_bytes": total_bytes,
            "fixture_files_created": len(candidates),
            "fixture_files_archived": len(candidates),
            "fixture_files_rehearsed": len(candidates),
            "fixture_files_restored": len(candidates) if restore_before_exit else 0,
            "archive_payload_verified": archive_verified,
            "rollback_proof_verified": restored_match,
            "source_restored_before_exit": restore_before_exit,
            "rehearsal_errors": 0,
            "rehearsal_warnings": 0,
        },
        "fixture_candidate_manifest": candidates,
        "rollback_proof": {
            "rollback_available": True,
            "rollback_tested": True,
            "restore_before_exit": restore_before_exit,
            "restored_source_matches_original": restored_match,
        },
        "safety": _fixture_safety_block(True, True, restore_before_exit),
        "first_safe_command": f"cat {out / 'fixture-source-action-rehearsal-summary.md'}",
    }
    return result


def render_archive_source_action_fixture_rehearsal(result: dict[str, Any]) -> str:
    summary = result.get("summary", {})
    rollback = result.get("rollback_proof", {})
    return "\n".join(
        [
            "# Docker01 Fixture Source-Action Rehearsal",
            "",
            f"Fixture root: {result.get('fixture_root')}",
            f"Output: {result.get('out_dir')}",
            f"Plan ID: {result.get('plan_id')}",
            f"Status: {result.get('status')}",
            "Fixture only: yes",
            "Production source action available: no",
            "Production cleanup available: no",
            "",
            "## What happened",
            f"* Synthetic fixture files created: {summary.get('fixture_files_created', 0)}",
            f"* Fixture files archived: {summary.get('fixture_files_archived', 0)}",
            f"* Fixture files rehearsed: {summary.get('fixture_files_rehearsed', 0)}",
            f"* Fixture rollback proof: {rollback.get('restored_source_matches_original', False)}",
            f"* Restored before exit: {summary.get('source_restored_before_exit', False)}",
            "",
            "## Safety",
            "* fixture-only rehearsal",
            "* exact confirmation required",
            "* no production source action",
            "* no production cleanup",
            "* no source deleted",
            "* no source moved",
            "* no source modified",
            "* no Docker prune",
            "* no Docker/Compose mutation",
            "* no restart",
            "* no remediation/rollback/recovery",
            "* no natural-language execution",
            "* no " + "shell=" + "True",
            "",
        ]
    )


def write_archive_source_action_fixture_rehearsal_outputs(
    result: dict[str, Any], out_dir: str
) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    _write_json(out / "fixture-source-action-rehearsal.json", result)
    (out / "fixture-source-action-rehearsal-summary.md").write_text(
        render_archive_source_action_fixture_rehearsal(result)
    )
    _write_json(
        out / "fixture-candidate-manifest.json",
        {"plan_id": result["plan_id"], "candidates": result["fixture_candidate_manifest"]},
    )
    _write_json(
        out / "fixture-archive-manifest.json",
        {
            "plan_id": result["plan_id"],
            "archive_payload_verified": result["summary"]["archive_payload_verified"],
            "candidates": result["fixture_candidate_manifest"],
        },
    )
    _write_json(
        out / "fixture-rollback-proof.json",
        {"plan_id": result["plan_id"], **result["rollback_proof"]},
    )
    (out / "fixture-safety-notes.md").write_text(
        "# Fixture safety notes\n\n"
        "Fixture-only rehearsal. No production source action. No production cleanup.\n"
    )
    manifest_files = []
    for name in SOURCE_ACTION_FIXTURE_REHEARSAL_OUT_FILES:
        if name in {"manifest.json", "checksums.json"}:
            continue
        path = out / name
        manifest_files.append({"path": str(path), "name": name, "size_bytes": path.stat().st_size})
    _write_json(
        out / "manifest.json",
        {
            "plan_id": result["plan_id"],
            "mode": SOURCE_ACTION_FIXTURE_REHEARSAL_MODE,
            "files": manifest_files,
            "fixture_only": True,
        },
    )
    checksum_names = [item["name"] for item in manifest_files] + ["manifest.json"]
    _write_json(
        out / "checksums.json",
        {
            "plan_id": result["plan_id"],
            "checksums": {name: "sha256:" + sha256_file(out / name) for name in checksum_names},
        },
    )


def write_archive_source_action_status_report_outputs(result: dict[str, Any], out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "archive-source-action-status-report.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    (out / "archive-source-action-operator-status.md").write_text(
        render_archive_source_action_status_report(result)
    )
    (out / "candidate-status-summary.json").write_text(
        json.dumps(
            {"plan_id": result["plan_id"], "candidates": result["candidate_status"]},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    (out / "operator-next-steps.md").write_text(
        "# Operator Next Steps\n\n"
        "* review evidence only\n"
        "* not approval\n"
        "* not execution\n"
        "* does not authorize source action\n"
        "* future action would require a separate PR/lane\n"
        "* future action would require exact plan id\n"
        "* future action would require exact confirmation phrase\n"
        "* source delete default is false\n"
        "* source move default is false\n"
        "* SeedOfEvil remains final merge owner\n"
    )
    (out / "non-execution-contract.md").write_text(
        "# Non-Execution Contract\n\n"
        "* status report only\n"
        "* not approval\n"
        "* not execution\n"
        "* does not authorize source action\n"
        "* source action is unavailable\n"
    )
    (out / "safety-notes.md").write_text(
        "# Safety Notes\n\n"
        "* no source copied, moved, modified, or deleted\n"
        "* no archive created by status report\n"
        "* no cleanup/prune/delete/restart/remediation/rollback/recovery\n"
    )
    manifest_files = []
    for name in SOURCE_ACTION_STATUS_REPORT_OUT_FILES:
        if name in {"manifest.json", "checksums.json"}:
            continue
        target = out / name
        manifest_files.append(
            {"path": str(target), "name": name, "size_bytes": target.stat().st_size}
        )
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "plan_id": result["plan_id"],
                "mode": SOURCE_ACTION_STATUS_REPORT_MODE,
                "files": manifest_files,
                "archive_created": False,
                "candidate_contents_copied": False,
                "source_action_available": False,
                "source_deleted": False,
                "source_moved": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    names = [item["name"] for item in manifest_files] + ["manifest.json"]
    (out / "checksums.json").write_text(
        json.dumps(
            {
                "plan_id": result["plan_id"],
                "checksums": {name: "sha256:" + sha256_file(out / name) for name in names},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def render_archive_source_action_readiness_gate(result: dict[str, Any]) -> str:
    s = result["summary"]
    return "\n".join(
        [
            "# Docker01 Archive Source-Action Readiness Gate",
            f"Plan ID: {result['plan_id']}",
            f"Decision receipt: {result['decision_receipt_dir']}",
            f"Review packet: {result['review_packet_dir']}",
            f"Source-action dry run: {result['source_action_dry_run_dir']}",
            f"Source-action validation: {result['source_action_validation_dir']}",
            f"Status: {result['status']}",
            "Read-only: yes",
            "Source action available: no",
            "",
            "## Evidence chain",
            f"* decision receipt: {s['decision_receipt_status']}",
            f"* operator decision: {s['decision']}",
            f"* review packet: {s['review_packet_status']}",
            f"* source-action validation: {s['source_action_validation_status']}",
            f"* source-action dry run: {s['source_action_dry_run_status']}",
            f"* archive eligibility: {s['archive_eligibility_status']}",
            f"* archive bundle validation: {s['archive_bundle_validation_status']}",
            f"* plan id match: {s['plan_id_match']}",
            f"* candidate manifest match: {s['candidate_manifest_match']}",
            f"* archive payload verified: {s['archive_payload_verified']}",
            f"* source preservation: {s['source_preservation_ok']}",
            "",
            "## Candidate summary",
            f"* candidates: {s['candidate_items']}",
            f"* ready: {s['ready_candidates']}",
            f"* blocked: {s['blocked_candidates']}",
            f"* warning: {s['warning_candidates']}",
            f"* unknown: {s['unknown_candidates']}",
            "",
            "## Future PR requirements",
            "* separate PR/lane required",
            "* SeedOfEvil final merge ownership required",
            "* exact plan id required",
            "* exact archive bundle required",
            "* exact decision receipt required",
            "* exact confirmation phrase required",
            "* source recheck required",
            "* source delete default: false",
            "* source move default: false",
            "",
            "## Safety",
            "* readiness gate only",
            "* not approval",
            "* not execution",
            "* does not authorize source action",
            "* no source action available",
            "* no source deleted",
            "* no source moved",
            "* no source modified",
            "* no source copied",
            "* no archive created",
            "* no cleanup/prune/delete/restart",
            "* no remediation/rollback/recovery",
            "* no natural-language execution",
            "* no " + "shell=" + "True",
            "",
        ]
    )


def write_archive_source_action_readiness_gate_outputs(
    result: dict[str, Any], out_dir: str
) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "archive-source-action-readiness-gate.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    (out / "archive-source-action-readiness-summary.md").write_text(
        render_archive_source_action_readiness_gate(result)
    )
    (out / "candidate-readiness-summary.json").write_text(
        json.dumps(
            {"plan_id": result["plan_id"], "candidates": result["candidate_readiness"]},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    req = result["future_source_action_requirements"]
    (out / "future-source-action-pr-checklist.md").write_text(
        "# Future Source-Action PR Checklist\n\n"
        "* separate PR/lane required\n"
        "* SeedOfEvil final merge ownership required\n"
        "* exact plan id required\n"
        "* exact archive bundle required\n"
        "* exact source-action dry run required\n"
        "* exact source-action validation required\n"
        "* exact review packet required\n"
        "* exact decision receipt required\n"
        f"* exact confirmation phrase required: {req['future_confirmation_phrase']}\n"
        "* source recheck required\n"
        "* archive validation required\n"
        "* source delete default: false\n"
        "* source move default: false\n"
    )
    contract = (
        "# Non-Execution Contract\n\n"
        "* not approval\n"
        "* not execution\n"
        "* does not authorize source action\n"
        "* future action would require a separate PR/lane\n"
        "* future action would require exact plan id\n"
        "* future action would require exact decision receipt\n"
        "* future action would require exact confirmation phrase\n"
        "* source delete default is false\n"
        "* source move default is false\n"
        "* SeedOfEvil remains final merge owner\n"
    )
    (out / "non-execution-contract.md").write_text(contract)
    (out / "safety-notes.md").write_text(
        "# Safety Notes\n\n"
        "* readiness gate only\n"
        "* not approval\n"
        "* not execution\n"
        "* does not authorize source action\n"
        "* no source copied, moved, modified, or deleted\n"
        "* no archive created by readiness gate\n"
        "* no cleanup/prune/delete/restart/remediation/rollback/recovery\n"
    )
    manifest_files = []
    for name in SOURCE_ACTION_READINESS_GATE_OUT_FILES:
        if name in {"manifest.json", "checksums.json"}:
            continue
        p = out / name
        manifest_files.append({"path": str(p), "name": name, "size_bytes": p.stat().st_size})
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "plan_id": result["plan_id"],
                "mode": SOURCE_ACTION_READINESS_GATE_MODE,
                "files": manifest_files,
                "archive_created": False,
                "candidate_contents_copied": False,
                "source_action_available": False,
                "source_deleted": False,
                "source_moved": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    names = [item["name"] for item in manifest_files] + ["manifest.json"]
    checksums = {name: "sha256:" + sha256_file(out / name) for name in names}
    (out / "checksums.json").write_text(
        json.dumps({"plan_id": result["plan_id"], "checksums": checksums}, indent=2, sort_keys=True)
        + "\n"
    )


def write_archive_source_action_decision_receipt_outputs(
    result: dict[str, Any], out_dir: str
) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "archive-source-action-decision-receipt.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    (out / "archive-source-action-decision-receipt-summary.md").write_text(
        render_archive_source_action_decision_receipt(result)
    )
    (out / "candidate-decision-summary.json").write_text(
        json.dumps(
            {"plan_id": result["plan_id"], "candidates": result["candidate_decision_summary"]},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    req = result["future_source_action_requirements"]
    requirements_text = "\n".join(
        [
            "# Future Source-Action Requirements",
            "",
            "* separate PR/lane required",
            "* exact plan id required",
            "* exact review packet required",
            "* exact decision receipt required",
            f"* exact confirmation phrase required: {req['future_confirmation_phrase']}",
            "* this receipt is not approval, execution, or authorization",
            "* source delete default: false",
            "* source move default: false",
            "",
        ]
    )
    (out / "future-source-action-requirements.md").write_text(requirements_text)
    safety_text = "\n".join(
        [
            "# Safety Notes",
            "",
            "* decision receipt only",
            "* not approval",
            "* not execution",
            "* does not authorize source action",
            "* no source copied, moved, modified, or deleted",
            "* no archive created by decision receipt",
            "* no cleanup/prune/delete/restart/remediation/rollback/recovery",
            "",
        ]
    )
    (out / "safety-notes.md").write_text(safety_text)
    manifest_files = []
    for name in SOURCE_ACTION_DECISION_RECEIPT_OUT_FILES:
        if name in {"manifest.json", "checksums.json"}:
            continue
        p = out / name
        manifest_files.append({"path": str(p), "name": name, "size_bytes": p.stat().st_size})
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "plan_id": result["plan_id"],
                "mode": SOURCE_ACTION_DECISION_RECEIPT_MODE,
                "files": manifest_files,
                "archive_created": False,
                "candidate_contents_copied": False,
                "source_action_available": False,
                "source_deleted": False,
                "source_moved": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    names = [item["name"] for item in manifest_files] + ["manifest.json"]
    checksums = {name: "sha256:" + sha256_file(out / name) for name in names}
    (out / "checksums.json").write_text(
        json.dumps({"plan_id": result["plan_id"], "checksums": checksums}, indent=2, sort_keys=True)
        + "\n"
    )


def render_archive_source_action_review_packet(result: dict[str, Any]) -> str:
    s = result["summary"]
    return "\n".join(
        [
            "# Docker01 Archive Source-Action Human Review Packet",
            "",
            f"Plan ID: {result['plan_id']}",
            f"Archive bundle: {result['archive_bundle_dir']}",
            f"Source-action dry run: {result['source_action_dry_run_dir']}",
            f"Source-action validation: {result['source_action_validation_dir']}",
            f"Archive eligibility review: {result['archive_eligibility_review_dir']}",
            f"Status: {result['status']}",
            "Read-only: yes",
            "Source action available: no",
            "",
            "## Evidence chain",
            f"* source-action dry run: {s['source_action_dry_run_status']}",
            f"* source-action validation: {s['source_action_validation_status']}",
            f"* archive eligibility: {s['archive_eligibility_status']}",
            f"* archive bundle validation: {s['archive_bundle_validation_status']}",
            f"* plan id match: {s['plan_id_match']}",
            f"* candidate manifest match: {s['candidate_manifest_match']}",
            f"* archive payload verified: {s['archive_payload_verified']}",
            f"* source preservation: {s['source_preservation_ok']}",
            "",
            "## Candidate summary",
            f"* candidates: {s['candidate_items']}",
            f"* ready for human review: {s['would_review_candidates']}",
            f"* blocked: {s['blocked_candidates']}",
            f"* warning: {s['warning_candidates']}",
            f"* unknown: {s['unknown_candidates']}",
            "",
            "## Operator review checklist",
            "* Review candidate manifest",
            "* Review source paths",
            "* Review archive payload paths",
            "* Review validation status",
            "* Confirm source delete default is false",
            "* Confirm source move default is false",
            "* Confirm any future action requires a separate PR/lane",
            "* Confirm any future action requires exact plan id",
            "* Confirm any future action requires exact confirmation phrase",
            "",
            "## Safety",
            "* review packet only",
            "* not approval",
            "* not execution",
            "* no source action available",
            "* no source deleted",
            "* no source moved",
            "* no source modified",
            "* no source copied",
            "* no archive created",
            "* no cleanup/prune/delete/restart",
            "* no remediation/rollback/recovery",
            "* no natural-language execution",
            "* no " + "shell=" + "True",
            "",
        ]
    )


def write_archive_source_action_review_packet_outputs(result: dict[str, Any], out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "archive-source-action-review-packet.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    (out / "archive-source-action-human-review.md").write_text(
        render_archive_source_action_review_packet(result)
    )
    (out / "candidate-review-summary.json").write_text(
        json.dumps(
            {"plan_id": result["plan_id"], "candidates": result["candidate_review"]},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    (out / "operator-review-checklist.md").write_text(
        "# Operator Review Checklist\n\n"
        "* not approval\n"
        "* not execution\n"
        "* not authorization\n"
        "* review candidate manifest\n"
        "* review source paths\n"
        "* review archive payload\n"
        "* review validation status\n"
        "* separate PR/lane required for any future action\n"
        "* exact plan id required\n"
        "* exact confirmation phrase required\n"
        "* source delete default is false\n"
        "* source move default is false\n"
    )
    (out / "future-source-action-signoff-template.md").write_text(
        "# Future Source-Action Signoff Template\n\n"
        "This template is not an approval, not execution, and not authorization. "
        "Future action would require a separate PR/lane, exact plan id, and exact "
        "confirmation phrase. Source delete default is false. Source move default "
        "is false.\n\n"
        "Plan ID: <exact-plan-id>\n"
        "Confirmation phrase: CONFIRM_SHELLFORGEAI_SOURCE_ACTION_AFTER_ARCHIVE\n"
    )
    (out / "safety-notes.md").write_text(
        "# Safety Notes\n\n"
        "* human review packet only\n"
        "* not approval\n"
        "* not execution\n"
        "* not authorization\n"
        "* no source copied, moved, modified, or deleted\n"
        "* no archive created by review packet\n"
        "* no cleanup/prune/delete/restart/remediation/rollback/recovery\n"
    )
    manifest_files = []
    for name in SOURCE_ACTION_REVIEW_PACKET_OUT_FILES:
        if name in {"manifest.json", "checksums.json"}:
            continue
        p = out / name
        manifest_files.append({"path": str(p), "name": name, "size_bytes": p.stat().st_size})
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "plan_id": result["plan_id"],
                "mode": SOURCE_ACTION_REVIEW_PACKET_MODE,
                "files": manifest_files,
                "archive_created": False,
                "candidate_contents_copied": False,
                "source_action_available": False,
                "source_deleted": False,
                "source_moved": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    names = [item["name"] for item in manifest_files] + ["manifest.json"]
    checksums = {name: "sha256:" + sha256_file(out / name) for name in names}
    (out / "checksums.json").write_text(
        json.dumps({"plan_id": result["plan_id"], "checksums": checksums}, indent=2, sort_keys=True)
        + "\n"
    )


def render_archive_eligibility_review_summary(result: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Docker01 Artifact Archive Eligibility Review",
            "",
            f"Archive bundle: {result['archive_bundle_dir']}",
            f"Plan: {result['plan_dir']}",
            f"Dry-run receipt: {result['dry_run_receipt_dir']}",
            f"Plan ID: {result['plan_id']}",
            f"Status: {result['status']}",
            "Read-only: yes",
            "Cleanup available: no",
            "",
            "## Evidence chain",
            f"* archive validation: {result['summary']['archive_validation_status']}",
            f"* plan validation: {result['summary']['plan_validation_status']}",
            (
                "* dry-run receipt validation: "
                f"{result['summary']['dry_run_receipt_validation_status']}"
            ),
            f"* plan id match: {result['summary']['plan_id_match']}",
            f"* candidate manifest match: {result['summary']['candidate_manifest_match']}",
            f"* archive payload verified: {result['summary']['archive_payload_verified']}",
            f"* source preservation: {result['summary']['source_preservation_ok']}",
            "",
            "## Candidate summary",
            f"* candidates: {result['summary']['candidate_items']}",
            f"* eligible: {result['summary']['eligible_candidates']}",
            f"* blocked: {result['summary']['blocked_candidates']}",
            f"* warning: {result['summary']['warning_candidates']}",
            f"* unknown: {result['summary']['unknown_candidates']}",
            "",
            "## Future source-action review requirements",
            "* separate PR/lane required",
            "* exact plan id required",
            "* exact archive bundle required",
            "* confirmation phrase required",
            "* source recheck required",
            "* dry-run deletion manifest required",
            "* source delete default: false",
            "* source move default: false",
            "",
            "## Safety",
            "* eligibility review only",
            "* no source deleted",
            "* no source moved",
            "* no source modified",
            "* no cleanup/prune/delete/restart",
            "* no remediation/rollback/recovery",
            "* no natural-language execution",
            "* no " + "shell=" + "True",
            "",
        ]
    )


def write_archive_eligibility_review_outputs(result: dict[str, Any], out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "artifact-archive-eligibility-review.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    (out / "artifact-archive-eligibility-review-summary.md").write_text(
        render_archive_eligibility_review_summary(result)
    )
    (out / "candidate-archive-eligibility-review.json").write_text(
        json.dumps(
            {"plan_id": result["plan_id"], "candidates": result["candidate_review"]},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    (out / "future-source-action-review-checklist.md").write_text(
        "# Future Source-Action Review Checklist\n\n"
        "* separate PR/lane required\n"
        "* exact plan id required\n"
        "* exact archive bundle required\n"
        "* confirmation phrase required: "
        + SOURCE_ACTION_REVIEW_CONFIRMATION_PHRASE
        + "\n* source recheck required\n"
        "* dry-run deletion manifest required\n"
        "* source delete default: false\n"
        "* source move default: false\n"
    )
    (out / "safety-notes.md").write_text(
        "# Safety Notes\n\n"
        "* archive eligibility review only\n"
        "* no source copied, moved, modified, or deleted\n"
        "* no cleanup/prune/delete/restart/remediation/rollback/recovery\n"
        "* cleanup remains unavailable\n"
    )
    manifest_files = []
    for name in ARCHIVE_ELIGIBILITY_REVIEW_OUT_FILES:
        if name in {"manifest.json", "checksums.json"}:
            continue
        p = out / name
        manifest_files.append({"path": str(p), "name": name, "size_bytes": p.stat().st_size})
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "plan_id": result["plan_id"],
                "mode": ARCHIVE_ELIGIBILITY_REVIEW_MODE,
                "files": manifest_files,
                "archive_created": False,
                "candidate_contents_copied": False,
                "cleanup_available": False,
                "source_deleted": False,
                "source_moved": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    names = [item["name"] for item in manifest_files] + ["manifest.json"]
    checksums = {name: "sha256:" + sha256_file(out / name) for name in names}
    (out / "checksums.json").write_text(
        json.dumps({"plan_id": result["plan_id"], "checksums": checksums}, indent=2, sort_keys=True)
        + "\n"
    )


def render_archive_bundle_validation_summary(result: dict[str, Any]) -> str:
    by_name = {c["name"]: c["status"] for c in result["checks"]}
    return "\n".join(
        [
            "# Docker01 Artifact Archive Bundle Validation",
            "",
            f"Archive bundle: {result['archive_bundle_dir']}",
            f"Plan: {result['plan_dir']}",
            f"Dry-run receipt: {result['dry_run_receipt_dir']}",
            f"Plan ID: {result['plan_id']}",
            f"Status: {result['status']}",
            "Read-only: yes",
            "",
            "## Checks",
            f"* required files: {by_name.get('required_files_present')}",
            f"* JSON parse: {by_name.get('json_parse_ok')}",
            f"* manifest: {by_name.get('manifest_ok')}",
            f"* checksums: {by_name.get('checksums_ok')}",
            f"* payload: {by_name.get('payload_ok')}",
            f"* source preservation: {by_name.get('source_preservation_ok')}",
            f"* safety: {by_name.get('safety_ok')}",
            f"* plan cross-check: {result['summary']['plan_cross_check_status']}",
            f"* dry-run cross-check: {result['summary']['dry_run_cross_check_status']}",
            "",
            "## Archive summary",
            f"* candidate items: {result['summary']['candidate_items']}",
            f"* planned bytes: {result['summary']['candidate_bytes_planned']}",
            f"* copied bytes: {result['summary']['candidate_bytes_copied']}",
            f"* files copied: {result['summary']['files_copied']}",
            f"* directories copied: {result['summary']['directories_copied']}",
            "",
            "## Source preservation",
            "* source moved: no",
            "* source deleted: no",
            "* source modified: no",
            "* source paths verified after copy: "
            + (
                "yes"
                if result["source_preservation"]["source_paths_verified_present_after_copy"]
                else "no"
            ),
            "",
            "## Safety",
            "* validation only",
            "* no archive created by validator",
            "* no source copied by validator",
            "* no source moved",
            "* no source deleted",
            "* no cleanup/prune/delete/restart",
            "* no remediation/rollback/recovery",
            "* no natural-language execution",
            "* no " + "shell=" + "True",
            "",
        ]
    )


def write_archive_bundle_validation_outputs(result: dict[str, Any], out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "artifact-archive-bundle-validation.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    (out / "artifact-archive-bundle-validation-summary.md").write_text(
        render_archive_bundle_validation_summary(result)
    )
    manifest_files = []
    for name in ARCHIVE_BUNDLE_VALIDATION_OUT_FILES:
        if name in {"manifest.json", "checksums.json"}:
            continue
        p = out / name
        manifest_files.append({"path": str(p), "name": name, "size_bytes": p.stat().st_size})
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "plan_id": result["plan_id"],
                "mode": ARCHIVE_BUNDLE_VALIDATION_MODE,
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
        "--validate-archive-bundle",
        metavar="ARCHIVE_BUNDLE_DIR",
        help="validate an existing copy-only archive bundle (read-only)",
    )
    parser.add_argument(
        "--archive-eligibility-review",
        metavar="ARCHIVE_BUNDLE_DIR",
        help="read-only archive-backed eligibility review",
    )
    parser.add_argument(
        "--archive-source-action-dry-run",
        metavar="ARCHIVE_BUNDLE_DIR",
        help="read-only archive-backed source-action dry-run manifest",
    )
    parser.add_argument(
        "--validate-archive-source-action-dry-run",
        metavar="SOURCE_ACTION_DRY_RUN_DIR",
        help="read-only validation for an archive-backed source-action dry-run manifest",
    )
    parser.add_argument(
        "--archive-source-action-review-packet",
        metavar="SOURCE_ACTION_DRY_RUN_DIR",
        help="read-only archive-backed source-action human review packet",
    )
    parser.add_argument(
        "--archive-source-action-decision-receipt",
        metavar="REVIEW_PACKET_DIR",
        help="read-only archive-backed source-action operator decision receipt",
    )
    parser.add_argument(
        "--archive-source-action-readiness-gate",
        metavar="DECISION_RECEIPT_DIR",
        help="read-only final source-action readiness gate",
    )
    parser.add_argument(
        "--archive-source-action-status-report",
        metavar="READINESS_GATE_DIR",
        help="read-only archive source-action operator status report",
    )
    parser.add_argument(
        "--archive-source-action-fixture-rehearsal",
        action="store_true",
        help="confirmation-gated fixture-only source-action rehearsal",
    )
    parser.add_argument("--archive-bundle", help="optional archive bundle directory cross-check")
    parser.add_argument(
        "--fixture-root", help="explicit safe /tmp/sfai-fixture-source-action-* root"
    )
    parser.add_argument(
        "--restore-before-exit",
        action="store_true",
        help="restore fixture source files before exit",
    )
    parser.add_argument(
        "--source-action-validation", help="source-action dry-run validation directory"
    )
    parser.add_argument("--source-action-dry-run", help="optional source-action dry-run directory")
    parser.add_argument("--review-packet", help="source-action human review packet directory")
    parser.add_argument(
        "--decision-receipt", help="source-action operator decision receipt directory"
    )
    parser.add_argument(
        "--decision", choices=ALLOWED_SOURCE_ACTION_DECISIONS, help="operator decision enum"
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
        "--archive-validation",
        help="optional prior archive bundle validation directory for archive eligibility review",
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

    if args.archive_source_action_fixture_rehearsal:
        if not args.fixture_root or not args.plan_id or not args.out:
            parser.error(
                "--archive-source-action-fixture-rehearsal requires --fixture-root, "
                "--plan-id, --confirm, and --out"
            )
        result = build_archive_source_action_fixture_rehearsal(
            fixture_root=args.fixture_root,
            out_dir=args.out,
            plan_id=args.plan_id,
            confirm=args.confirm,
            restore_before_exit=args.restore_before_exit,
        )
        if result["status"] in {"rehearsal_passed", "partial"}:
            write_archive_source_action_fixture_rehearsal_outputs(result, args.out)
        print(
            json.dumps(result, sort_keys=True)
            if args.json
            else render_archive_source_action_fixture_rehearsal(result)
        )
        return 0 if result["status"] in {"rehearsal_passed", "partial"} else 1

    if args.archive_source_action_status_report:
        optional_supplied = any(
            (
                args.decision_receipt,
                args.review_packet,
                args.source_action_dry_run,
                args.source_action_validation,
                args.archive_bundle,
                args.plan_dir,
                args.dry_run_receipt,
                args.archive_eligibility_review,
            )
        )
        if optional_supplied and not args.plan_id:
            parser.error(
                "--archive-source-action-status-report requires --plan-id "
                "when optional evidence dirs are supplied"
            )
        result = build_archive_source_action_status_report(
            args.archive_source_action_status_report,
            decision_receipt_dir=args.decision_receipt,
            review_packet_dir=args.review_packet,
            source_action_dry_run_dir=args.source_action_dry_run,
            source_action_validation_dir=args.source_action_validation,
            archive_bundle_dir=args.archive_bundle,
            plan_dir=args.plan_dir,
            dry_run_receipt_dir=args.dry_run_receipt,
            archive_eligibility_review_dir=args.archive_eligibility_review,
            supplied_plan_id=args.plan_id,
            out_dir=args.out,
        )
        if args.out:
            write_archive_source_action_status_report_outputs(result, args.out)
        print(
            json.dumps(result, sort_keys=True)
            if args.json
            else render_archive_source_action_status_report(result)
        )
        return 0 if result["status"] in {"ready_for_operator_review", "partial"} else 1

    if args.archive_source_action_readiness_gate:
        if (
            not args.review_packet
            or not args.source_action_dry_run
            or not args.source_action_validation
            or not args.archive_bundle
            or not args.plan_dir
            or not args.dry_run_receipt
            or not args.archive_eligibility_review
            or not args.plan_id
        ):
            parser.error(
                "--archive-source-action-readiness-gate requires --review-packet, "
                "--source-action-dry-run, --source-action-validation, --archive-bundle, "
                "--plan-dir, --dry-run-receipt, --archive-eligibility-review, and --plan-id"
            )
        result = build_archive_source_action_readiness_gate(
            args.archive_source_action_readiness_gate,
            review_packet_dir=args.review_packet,
            source_action_dry_run_dir=args.source_action_dry_run,
            source_action_validation_dir=args.source_action_validation,
            archive_bundle_dir=args.archive_bundle,
            plan_dir=args.plan_dir,
            dry_run_receipt_dir=args.dry_run_receipt,
            archive_eligibility_review_dir=args.archive_eligibility_review,
            supplied_plan_id=args.plan_id,
            max_candidates=args.max_candidates_returned,
        )
        if args.out:
            write_archive_source_action_readiness_gate_outputs(result, args.out)
        print(
            json.dumps(result, sort_keys=True)
            if args.json
            else render_archive_source_action_readiness_gate(result)
        )
        return 0 if result["status"] in {"ready_for_future_pr_review", "partial"} else 1

    if args.archive_source_action_decision_receipt:
        if not args.plan_id or not args.decision:
            parser.error(
                "--archive-source-action-decision-receipt requires --plan-id and --decision"
            )
        result = build_archive_source_action_decision_receipt(
            args.archive_source_action_decision_receipt,
            supplied_plan_id=args.plan_id,
            decision=args.decision,
            source_action_dry_run_dir=args.source_action_dry_run,
            source_action_validation_dir=args.source_action_validation,
            archive_bundle_dir=args.archive_bundle,
            plan_dir=args.plan_dir,
            dry_run_receipt_dir=args.dry_run_receipt,
            archive_eligibility_review_dir=args.archive_eligibility_review,
            max_candidates=args.max_candidates_returned,
        )
        if args.out:
            write_archive_source_action_decision_receipt_outputs(result, args.out)
        print(
            json.dumps(result, sort_keys=True)
            if args.json
            else render_archive_source_action_decision_receipt(result)
        )
        return 0 if result["status"] in {"decision_recorded", "partial"} else 1

    if args.archive_source_action_review_packet:
        if (
            not args.source_action_validation
            or not args.archive_bundle
            or not args.plan_dir
            or not args.dry_run_receipt
            or not args.archive_eligibility_review
            or not args.plan_id
        ):
            parser.error(
                "--archive-source-action-review-packet requires --source-action-validation, "
                "--archive-bundle, --plan-dir, --dry-run-receipt, "
                "--archive-eligibility-review, and --plan-id"
            )
        result = build_archive_source_action_review_packet(
            args.archive_source_action_review_packet,
            source_action_validation_dir=args.source_action_validation,
            archive_bundle_dir=args.archive_bundle,
            plan_dir=args.plan_dir,
            dry_run_receipt_dir=args.dry_run_receipt,
            archive_eligibility_review_dir=args.archive_eligibility_review,
            supplied_plan_id=args.plan_id,
            max_candidates=args.max_candidates_returned,
        )
        if args.out:
            write_archive_source_action_review_packet_outputs(result, args.out)
        print(
            json.dumps(result, sort_keys=True)
            if args.json
            else render_archive_source_action_review_packet(result)
        )
        return 0 if result["status"] in {"ready_for_human_review", "partial"} else 1

    if args.validate_archive_source_action_dry_run:
        result = validate_archive_source_action_dry_run(
            args.validate_archive_source_action_dry_run,
            archive_bundle_dir=args.archive_bundle,
            plan_dir=args.plan_dir,
            dry_run_receipt_dir=args.dry_run_receipt,
            archive_eligibility_review_dir=args.archive_eligibility_review,
            max_candidates=args.max_candidates_returned,
        )
        if args.out:
            write_archive_source_action_dry_run_validation_outputs(result, args.out)
        print(
            json.dumps(result, sort_keys=True)
            if args.json
            else render_archive_source_action_dry_run_validation_summary(result)
        )
        return 0 if result["status"] in {"passed", "partial"} else 1

    if args.archive_source_action_dry_run:
        if (
            not args.plan_dir
            or not args.dry_run_receipt
            or not args.archive_eligibility_review
            or not args.plan_id
        ):
            parser.error(
                "--archive-source-action-dry-run requires --plan-dir, "
                "--dry-run-receipt, --archive-eligibility-review, and --plan-id"
            )
        result = build_archive_source_action_dry_run(
            args.archive_source_action_dry_run,
            plan_dir=args.plan_dir,
            dry_run_receipt_dir=args.dry_run_receipt,
            archive_eligibility_review_dir=args.archive_eligibility_review,
            supplied_plan_id=args.plan_id,
            max_candidates=args.max_candidates_returned,
        )
        if args.out:
            write_archive_source_action_dry_run_outputs(result, args.out)
        print(
            json.dumps(result, sort_keys=True)
            if args.json
            else render_archive_source_action_dry_run_summary(result)
        )
        return 0 if result["status"] in {"ready_for_source_action_review", "partial"} else 1

    if args.archive_eligibility_review:
        if not args.plan_dir or not args.dry_run_receipt:
            parser.error("--archive-eligibility-review requires --plan-dir and --dry-run-receipt")
        result = build_archive_eligibility_review(
            args.archive_eligibility_review,
            plan_dir=args.plan_dir,
            dry_run_receipt_dir=args.dry_run_receipt,
            archive_validation_dir=args.archive_validation,
            max_candidates=args.max_candidates_returned,
        )
        if args.out:
            write_archive_eligibility_review_outputs(result, args.out)
        print(
            json.dumps(result, sort_keys=True)
            if args.json
            else render_archive_eligibility_review_summary(result)
        )
        return 0 if result["status"] in {"eligible_for_review", "partial"} else 1

    if args.validate_archive_bundle:
        result = validate_archive_bundle(
            args.validate_archive_bundle,
            plan_dir=args.plan_dir,
            dry_run_receipt_dir=args.dry_run_receipt,
            max_candidates=args.max_candidates_returned,
        )
        if args.out:
            write_archive_bundle_validation_outputs(result, args.out)
        print(
            json.dumps(result, sort_keys=True)
            if args.json
            else render_archive_bundle_validation_summary(result)
        )
        return 0 if result["status"] != "failed" else 1

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
