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
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MODE = "docker01_artifact_archive_plan"
DEFAULT_ROOT = "/tmp"
DEFAULT_MAX_SCAN = 1000
DEFAULT_MAX_RETURNED = 500
DEFAULT_MAX_WARNINGS = 50
CONFIRMATION_PHRASE = "CONFIRM_SHELLFORGEAI_ARTIFACT_ARCHIVE"
FIRST_SAFE_COMMAND = "python3 scripts/docker01_artifact_archive_plan.py --root /tmp --json"

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a read-only ShellForgeAI artifact archive plan."
    )
    parser.add_argument("--root", default=DEFAULT_ROOT)
    parser.add_argument("--json", action="store_true", help="emit strict JSON")
    parser.add_argument("--out", help="write plan artifacts to this directory")
    parser.add_argument("--max-candidates-scanned", type=int, default=DEFAULT_MAX_SCAN)
    parser.add_argument("--max-candidates-returned", type=int, default=DEFAULT_MAX_RETURNED)
    parser.add_argument("--max-warnings-returned", type=int, default=DEFAULT_MAX_WARNINGS)
    args = parser.parse_args(argv)
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
