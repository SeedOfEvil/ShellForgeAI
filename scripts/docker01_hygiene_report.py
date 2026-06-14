#!/usr/bin/env python3
"""Read-only Docker01 disk/image/artifact hygiene report helper."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MODE = "docker01_hygiene_report"
DEFAULT_TIMEOUT = 30
RAW_LIMIT = 500_000
VALIDATE_MODE = "docker01_hygiene_report_validate"
MAX_CANDIDATE_CLEANUP_ITEMS = 1_000
MAX_CANDIDATE_ITEM_LENGTH = 500
MAX_WARNINGS = 100
MAX_JSON_VALIDATE_BYTES = 5_000_000
MAX_MARKDOWN_VALIDATE_BYTES = 2_000_000
MAX_COMMANDS_RUN_BYTES = 2_000_000
MAX_RAW_VALIDATE_BYTES = 500_000
REQUIRED_REPORT_FILES = (
    "hygiene-summary.md",
    "hygiene-report.json",
    "candidate-cleanup-plan.md",
    "commands-run.json",
)
KNOWN_ROOTS = (
    "/tmp",
    "/srv/compose/shellforgeai",
    "/data",
    "/data/shellforgeai",
    "/opt/shellforgeai",
    "/var/tmp",
)


@dataclass(frozen=True)
class CommandSpec:
    key: str
    argv: tuple[str, ...]
    raw_file: str
    parse: str = "text"
    timeout: int = DEFAULT_TIMEOUT


@dataclass
class CommandResult:
    key: str
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    available: bool
    reason: str = ""


COMMAND_SPECS = [
    CommandSpec("disk", ("df", "-h", "/"), "raw/disk.txt"),
    CommandSpec(
        "docker_ps", ("docker", "ps", "--filter", "name=shellforgeai"), "raw/docker-ps.txt"
    ),
    CommandSpec(
        "docker_inspect", ("docker", "inspect", "shellforgeai"), "raw/docker-inspect.json", "json"
    ),
    CommandSpec(
        "docker_images",
        ("docker", "images", "lab/shellforgeai", "--digests", "--no-trunc"),
        "raw/docker-images.txt",
    ),
    CommandSpec(
        "docker_image_ls",
        ("docker", "image", "ls", "--format", "json"),
        "raw/docker-image-ls.jsonl",
    ),
]
ALLOWED = {spec.argv for spec in COMMAND_SPECS}


UNSAFE_COMMAND_PATTERNS = (
    re.compile(r"\bdocker\s+system\s+prune\b", re.I),
    re.compile(r"\bdocker\s+volume\s+prune\b", re.I),
    re.compile(r"\bdocker\s+image\s+rm\b", re.I),
    re.compile(r"\bdocker\s+rmi\b", re.I),
    re.compile(r"\bdocker\s+rm\b", re.I),
    re.compile(r"\bdocker\s+restart\b", re.I),
    re.compile(r"\bdocker\s+compose\s+(?:down|restart)\b", re.I),
    re.compile(r"\brm\s+-[A-Za-z]*r[A-Za-z]*f\b|\brm\s+-[A-Za-z]*f[A-Za-z]*r\b", re.I),
    re.compile(
        r"\brm\s+[^\n]*(?:/tmp/sfai|/data/shellforgeai|/srv/compose/shellforgeai|/opt/shellforgeai)",
        re.I,
    ),
    re.compile(r"\bfind\b[^\n]*\s-delete\b", re.I),
    re.compile(r"\bunlink\b", re.I),
    re.compile(r"\b(?:sh|bash)\s+-c\b", re.I),
    re.compile(r"\bcurl\b", re.I),
    re.compile(r"\bwget\b", re.I),
    re.compile(r"\bapt(?:-get)?\s+install\b", re.I),
    re.compile(r"\bpip(?:3)?\s+install\b", re.I),
    re.compile(r"\bgh\s+pr\s+merge\b", re.I),
    re.compile(r"\bcodex\s+apply\b", re.I),
)

SAFE_NEGATION_MARKERS = (
    "does not ",
    "do not ",
    "no cleanup was performed",
    "not an executable",
    "intentionally non-executable",
    "executed: false",
    "removed: false",
)

COMMAND_FAMILY_DENYLIST = {
    "rm",
    "unlink",
    "touch",
    "mkdir",
    "rmdir",
    "mv",
    "cp",
    "tee",
    "curl",
    "wget",
    "apt",
    "apt-get",
    "pip",
    "pip3",
    "sh",
    "bash",
    "gh",
    "codex",
    "find",
}


def _check(checks: list[dict[str, Any]], name: str, passed: bool, detail: str) -> bool:
    checks.append({"name": name, "passed": bool(passed), "detail": detail})
    return passed


def _read_bounded_text(path: Path, max_bytes: int) -> tuple[str, str | None]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        return "", str(exc)
    if size > max_bytes:
        return "", f"{path}: file size {size} exceeds validation cap {max_bytes}"
    try:
        return path.read_text(encoding="utf-8"), None
    except UnicodeDecodeError as exc:
        return "", f"file is not utf-8 text: {exc}"


def _parse_json_file(path: Path, max_bytes: int) -> tuple[Any, str | None]:
    text, error = _read_bounded_text(path, max_bytes)
    if error:
        return None, error
    try:
        return json.loads(text), None
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc}"


def _line_is_harmless_safety_statement(line: str) -> bool:
    stripped = line.strip().lower()
    if stripped.startswith("#"):
        return True
    return any(marker in stripped for marker in SAFE_NEGATION_MARKERS)


def _unsafe_content_hits(text: str) -> list[str]:
    hits: list[str] = []
    for line in text.splitlines():
        if _line_is_harmless_safety_statement(line):
            continue
        for pattern in UNSAFE_COMMAND_PATTERNS:
            if pattern.search(line):
                hits.append(line.strip()[:160])
                break
    return hits


def _command_argv(entry: Any) -> list[str]:
    argv = entry.get("argv") or entry.get("command") or [] if isinstance(entry, dict) else entry
    if isinstance(argv, str):
        return argv.split()
    if isinstance(argv, list) and all(isinstance(part, str) for part in argv):
        return argv
    return []


def _command_is_safe(argv: list[str]) -> tuple[bool, str]:
    if not argv:
        return False, "missing argv"
    if is_allowlisted_command(argv):
        return True, "allowlisted PR209 read-only command"
    if argv[0] in COMMAND_FAMILY_DENYLIST:
        return False, f"unsafe executable family: {argv[0]}"
    joined = " ".join(argv)
    if _unsafe_content_hits(joined):
        return False, "unsafe command pattern"
    return False, f"unknown executable family: {argv[0]}"


def validate_report(report_dir: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    warnings: list[str] = []
    report_dir = report_dir.resolve()
    required_ok = True
    for rel in REQUIRED_REPORT_FILES:
        required_ok = (
            _check(
                checks,
                f"required_file_present:{rel}",
                (report_dir / rel).is_file(),
                f"{rel} exists" if (report_dir / rel).is_file() else f"missing {rel}",
            )
            and required_ok
        )
    _check(
        checks,
        "required_files_present",
        required_ok,
        "required report files present" if required_ok else "one or more required files missing",
    )

    report: Any = None
    commands: Any = None
    if (report_dir / "hygiene-report.json").is_file():
        report, err = _parse_json_file(report_dir / "hygiene-report.json", MAX_JSON_VALIDATE_BYTES)
        _check(
            checks,
            "hygiene_report_json_object",
            err is None and isinstance(report, dict),
            err or "hygiene-report.json is a JSON object",
        )
    if (report_dir / "commands-run.json").is_file():
        commands, err = _parse_json_file(report_dir / "commands-run.json", MAX_COMMANDS_RUN_BYTES)
        _check(
            checks,
            "commands_run_json_list",
            err is None and isinstance(commands, list),
            err or "commands-run.json is a JSON list",
        )

    candidates: list[Any] = []
    if isinstance(report, dict):
        _check(
            checks,
            "mode_is_docker01_hygiene_report",
            report.get("mode") == MODE,
            f"mode={report.get('mode')!r}",
        )
        _check(
            checks,
            "top_level_read_only_true",
            report.get("read_only") is True,
            f"read_only={report.get('read_only')!r}",
        )
        _check(
            checks,
            "top_level_mutation_performed_false",
            report.get("mutation_performed") is False,
            f"mutation_performed={report.get('mutation_performed')!r}",
        )
        safety = report.get("safety")
        _check(
            checks,
            "safety_block_exists",
            isinstance(safety, dict),
            "safety block exists" if isinstance(safety, dict) else "missing safety block",
        )
        if isinstance(safety, dict):
            mutation_flags_ok = True
            for key, expected in safety_block().items():
                passed = safety.get(key) is expected
                mutation_flags_ok = mutation_flags_ok and passed
                _check(checks, f"safety_flag:{key}", passed, f"{key}={safety.get(key)!r}")
            _check(
                checks,
                "safety_mutation_flags_all_false",
                mutation_flags_ok,
                "all safety flags match read-only contract"
                if mutation_flags_ok
                else "one or more safety flags violate read-only contract",
            )
        candidates_obj = report.get("candidate_cleanup")
        _check(
            checks,
            "candidate_cleanup_is_list",
            isinstance(candidates_obj, list),
            f"type={type(candidates_obj).__name__}",
        )
        if isinstance(candidates_obj, list):
            candidates = candidates_obj
            _check(
                checks,
                "candidate_count_bounded",
                len(candidates) <= MAX_CANDIDATE_CLEANUP_ITEMS,
                f"candidate count={len(candidates)} max={MAX_CANDIDATE_CLEANUP_ITEMS}",
            )
            required = {
                "category",
                "item",
                "reason",
                "risk_note",
                "proposed_operator_review_action",
            }
            all_objects = True
            all_fields = True
            all_items_bounded = True
            for idx, cand in enumerate(candidates):
                is_obj = isinstance(cand, dict)
                all_objects = all_objects and is_obj
                if not is_obj:
                    all_fields = False
                    all_items_bounded = False
                    continue
                missing = sorted(required - set(cand))
                if missing:
                    all_fields = False
                    warnings.append(f"candidate {idx} missing fields: {', '.join(missing)}")
                item = cand.get("item")
                if not isinstance(item, str) or len(item) > MAX_CANDIDATE_ITEM_LENGTH:
                    all_items_bounded = False
            _check(
                checks,
                "every_candidate_is_object",
                all_objects,
                "all candidates are objects" if all_objects else "candidate entry is not an object",
            )
            _check(
                checks,
                "candidate_required_fields",
                all_fields,
                "all candidates include required review fields"
                if all_fields
                else "candidate missing required fields",
            )
            _check(
                checks,
                "candidate_items_bounded",
                all_items_bounded,
                f"item strings max {MAX_CANDIDATE_ITEM_LENGTH} chars",
            )

    plan_text = ""
    if (report_dir / "candidate-cleanup-plan.md").is_file():
        plan_text, err = _read_bounded_text(
            report_dir / "candidate-cleanup-plan.md", MAX_MARKDOWN_VALIDATE_BYTES
        )
        _check(checks, "candidate_plan_exists", err is None, err or "candidate cleanup plan exists")
        lower = plan_text.lower()
        has_proposal = "proposal only" in lower or "proposal-only" in lower
        has_no_cleanup = (
            "no cleanup was performed" in lower
            or "does not delete" in lower
            or "does not prune" in lower
        )
        _check(
            checks,
            "candidate_plan_proposal_only_language",
            has_proposal and has_no_cleanup,
            "proposal-only and no-cleanup language present"
            if has_proposal and has_no_cleanup
            else "missing proposal-only/no-cleanup language",
        )
        hits = _unsafe_content_hits(plan_text)
        _check(
            checks,
            "candidate_plan_no_executable_cleanup_commands",
            not hits,
            "no executable cleanup commands found" if not hits else f"unsafe lines: {hits[:3]}",
        )

    for rel in ("hygiene-summary.md", "hygiene-report.json", "commands-run.json"):
        path = report_dir / rel
        if path.is_file():
            cap = (
                MAX_JSON_VALIDATE_BYTES
                if rel == "hygiene-report.json"
                else MAX_COMMANDS_RUN_BYTES
                if rel == "commands-run.json"
                else MAX_MARKDOWN_VALIDATE_BYTES
            )
            text, err = _read_bounded_text(path, cap)
            hits = [] if err else _unsafe_content_hits(text)
            _check(
                checks,
                f"unsafe_content_absent:{rel}",
                err is None and not hits,
                err
                or ("no unsafe executable content" if not hits else f"unsafe lines: {hits[:3]}"),
            )

    if isinstance(commands, list):
        all_safe = True
        for idx, entry in enumerate(commands):
            safe, detail = _command_is_safe(_command_argv(entry))
            all_safe = all_safe and safe
            _check(checks, f"commands_run_entry_safe:{idx}", safe, detail)
        _check(
            checks,
            "commands_run_allowlisted_read_only",
            all_safe,
            "all commands are PR209 read-only allowlisted commands"
            if all_safe
            else "commands-run contains unsafe or unknown command",
        )

    raw_dir = report_dir / "raw"
    raw_failures: list[str] = []
    if raw_dir.exists():
        for path in raw_dir.iterdir():
            if path.is_file():
                size = path.stat().st_size
                if size > MAX_RAW_VALIDATE_BYTES:
                    detail = (
                        f"{path}: file size {size} exceeds validation cap {MAX_RAW_VALIDATE_BYTES}"
                    )
                    raw_failures.append(detail)
                    warnings.append(detail)
    _check(
        checks,
        "raw_outputs_bounded_if_present",
        not raw_failures,
        f"raw files are <= {MAX_RAW_VALIDATE_BYTES} bytes"
        if not raw_failures
        else "; ".join(raw_failures[:3]),
    )

    if len(warnings) > MAX_WARNINGS:
        warnings = warnings[:MAX_WARNINGS]
        warnings.append("warning list truncated")
    passed_count = sum(1 for check in checks if check["passed"])
    failed_count = len(checks) - passed_count
    status = "passed" if failed_count == 0 else "failed"
    return {
        "schema_version": 1,
        "mode": VALIDATE_MODE,
        "status": status,
        "report_dir": str(report_dir),
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "checks_total": len(checks),
            "checks_passed": passed_count,
            "checks_failed": failed_count,
            "candidate_cleanup_items": len(candidates),
        },
        "checks": checks,
        "safety": safety_block(),
        "first_safe_command": f"cat {report_dir}/hygiene-summary.md",
        "warnings": warnings,
    }


def default_report_path() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path(f"/tmp/sfai-docker01-hygiene-report-{stamp}")


def is_allowlisted_command(argv: tuple[str, ...] | list[str]) -> bool:
    return tuple(argv) in ALLOWED


def run_allowed_command(spec: CommandSpec) -> CommandResult:
    if not is_allowlisted_command(spec.argv):
        raise ValueError(f"command is not allowlisted: {spec.argv!r}")
    try:
        completed = subprocess.run(  # noqa: S603 fixed allowlist, shell=False
            list(spec.argv),
            check=False,
            capture_output=True,
            text=True,
            timeout=spec.timeout,
            shell=False,
        )
    except FileNotFoundError as exc:
        return CommandResult(
            spec.key, list(spec.argv), None, "", str(exc), False, "command unavailable"
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            spec.key,
            list(spec.argv),
            None,
            exc.stdout or "",
            exc.stderr or "",
            False,
            "command timed out",
        )
    return CommandResult(
        spec.key,
        list(spec.argv),
        completed.returncode,
        completed.stdout,
        completed.stderr,
        completed.returncode == 0,
        "" if completed.returncode == 0 else "command failed",
    )


def parse_df_root(text: str) -> dict[str, Any]:
    lines = [line.split() for line in text.splitlines() if line.strip()]
    for row in lines[1:]:
        if len(row) >= 6 and row[-1] == "/":
            return {
                "filesystem": row[0],
                "size": row[1],
                "used": row[2],
                "available": row[3],
                "use_percent": row[4],
                "mounted_on": row[5],
            }
    return {"available": False, "reason": "root df row not found"}


def parse_docker_inspect(text: str) -> dict[str, Any]:
    try:
        items = json.loads(text or "[]")
    except json.JSONDecodeError as exc:
        return {"available": False, "reason": f"invalid docker inspect JSON: {exc}"}
    if not items:
        return {"available": False, "reason": "container not found"}
    item = items[0]
    state = item.get("State") or {}
    config = item.get("Config") or {}
    health = state.get("Health") or {}
    return {
        "available": True,
        "status": state.get("Status", "unknown"),
        "health": health.get("Status", "unknown"),
        "restart_count": item.get("RestartCount", 0),
        "image": config.get("Image") or item.get("Image", ""),
        "labels": config.get("Labels") or {},
    }


def parse_image_jsonl(text: str) -> list[dict[str, Any]]:
    images: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        repo = obj.get("Repository") or obj.get("repository") or ""
        tag = obj.get("Tag") or obj.get("tag") or ""
        obj["reference"] = f"{repo}:{tag}" if repo and tag else obj.get("ID", "")
        obj["is_shellforgeai_lab"] = repo == "lab/shellforgeai"
        obj["is_pr_image"] = repo == "lab/shellforgeai" and tag.startswith("pr")
        images.append(obj)
    return images


def _safe_size(path: Path, max_entries: int = 5000) -> int:
    try:
        if path.is_file() or path.is_symlink():
            return path.stat().st_size
        total = 0
        count = 0
        for root, dirs, files in os.walk(path):
            dirs[:] = dirs[:50]
            for name in files[:200]:
                count += 1
                if count > max_entries:
                    return total
                try:
                    total += (Path(root) / name).stat().st_size
                except OSError:
                    continue
        return total
    except OSError:
        return 0


def classify_path(path: Path) -> str | None:
    name = path.name
    text = str(path)
    if re.match(r"sfai-pr\d+-.*qa-bundle-", name) or re.match(r"sfai-pr\d+-qa-bundle-", name):
        return "qa_bundles"
    if re.match(r"sfai-pr\d+-.*qa", name) or re.match(r"sfai-pr\d+-qa", name):
        return "qa_bundles"
    if re.match(r"sfai-pr\d+-.*validation", name) or re.match(r"sfai-pr\d+-validation", name):
        return "validation_artifacts"
    if re.match(r"sfai-pr\d+-.*fallback-", name):
        return "support_packets"
    if re.match(r"sfai-pr\d+-.*packet", name):
        return "support_packets"
    if re.search(r"sfai-.*(receipt|audit|handoff|release)", name):
        return "receipt_audit_handoff_release"
    if name.startswith("compose.yml.bak-pr") or "compose.yml.bak-pr" in text:
        return "compose_backups"
    if name.startswith("sfai-"):
        return "other_shellforgeai_tmp"
    return None


def inventory_filesystem(
    roots: tuple[str, ...] = KNOWN_ROOTS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    root_status: dict[str, Any] = {}
    for root_s in roots:
        root = Path(root_s)
        if not root.exists():
            root_status[root_s] = {"available": False, "reason": "root does not exist"}
            continue
        root_status[root_s] = {"available": True}
        candidates = list(root.glob("sfai-*"))
        candidates.extend(root.rglob("compose.yml.bak-pr*"))
        for path in candidates[:1000]:
            category = classify_path(path)
            if not category:
                continue
            try:
                stat = path.stat()
            except OSError as exc:
                inventory.append(
                    {
                        "path": str(path),
                        "available": False,
                        "reason": str(exc),
                        "category": category,
                    }
                )
                continue
            age_seconds = max(0, int(datetime.now(UTC).timestamp() - stat.st_mtime))
            inventory.append(
                {
                    "path": str(path),
                    "category": category,
                    "type": "dir" if path.is_dir() else "file",
                    "size_bytes": _safe_size(path),
                    "mtime": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
                    "age_seconds": age_seconds,
                }
            )
    return inventory, root_status


def group_categories(inventory: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    cats: dict[str, dict[str, Any]] = {}
    for item in inventory:
        cat = item.get("category", "unknown")
        entry = cats.setdefault(cat, {"total": 0, "size_bytes": 0, "items": []})
        entry["total"] += 1
        entry["size_bytes"] += int(item.get("size_bytes") or 0)
        entry["items"].append(item)
    return cats


def build_candidates(
    images: list[dict[str, Any]], inventory: list[dict[str, Any]], current_image: str
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    pr_images = [img for img in images if img.get("is_pr_image")]
    current_refs = {current_image, current_image.split("@", 1)[0]}
    for img in pr_images:
        ref = img.get("reference", "")
        if ref in current_refs:
            continue
        candidates.append(
            {
                "category": "old PR image",
                "item": ref,
                "estimated_size": img.get("Size", "unknown"),
                "age": img.get("CreatedSince", "unknown"),
                "reason": "ShellForgeAI lab PR image is not the currently running container image",
                "risk_note": "confirm no rollback/handoff requires this image before cleanup",
                "proposed_operator_review_action": "review in a separate cleanup PR/lane",
            }
        )
    for item in inventory:
        cat = item.get("category")
        if cat in {"validation_artifacts", "qa_bundles", "compose_backups", "support_packets"}:
            candidates.append(
                {
                    "category": cat,
                    "item": item.get("path"),
                    "estimated_size_bytes": item.get("size_bytes", 0),
                    "age_seconds": item.get("age_seconds"),
                    "reason": "historical ShellForgeAI Docker01 evidence/artifact found",
                    "risk_note": "confirm it is not needed for review, audit, rollback, or handoff",
                    "proposed_operator_review_action": "review in a separate cleanup PR/lane",
                }
            )
    return candidates


def safety_block() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
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


def build_report(
    report_path: Path,
    results: list[CommandResult],
    inventory: list[dict[str, Any]],
    roots: dict[str, Any],
) -> dict[str, Any]:
    by_key = {r.key: r for r in results}
    disk = (
        parse_df_root(by_key.get("disk", CommandResult("disk", [], None, "", "", False)).stdout)
        if by_key.get("disk") and by_key["disk"].available
        else {
            "available": False,
            "reason": by_key.get("disk").reason if by_key.get("disk") else "not run",
        }
    )
    container = (
        parse_docker_inspect(
            by_key.get(
                "docker_inspect", CommandResult("docker_inspect", [], None, "", "", False)
            ).stdout
        )
        if by_key.get("docker_inspect") and by_key["docker_inspect"].available
        else {
            "available": False,
            "reason": by_key.get("docker_inspect").reason
            if by_key.get("docker_inspect")
            else "not run",
            "status": "unavailable",
            "health": "unknown",
            "restart_count": 0,
            "image": "",
            "labels": {},
        }
    )
    images = (
        parse_image_jsonl(
            by_key.get(
                "docker_image_ls", CommandResult("docker_image_ls", [], None, "", "", False)
            ).stdout
        )
        if by_key.get("docker_image_ls") and by_key["docker_image_ls"].available
        else []
    )
    cats = group_categories(inventory)
    candidates = build_candidates(images, inventory, container.get("image", ""))
    failures = [r for r in results if not r.available]
    return {
        "schema_version": 1,
        "mode": MODE,
        "status": "partial" if failures else "ok",
        "created_at": datetime.now(UTC).isoformat(),
        "report_path": str(report_path),
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "disk_use_percent": disk.get("use_percent", "unknown"),
            "docker_images_total": len(images),
            "shellforgeai_images_total": sum(1 for i in images if i.get("is_shellforgeai_lab")),
            "compose_backups_total": cats.get("compose_backups", {}).get("total", 0),
            "validation_artifacts_total": cats.get("validation_artifacts", {}).get("total", 0),
            "qa_bundles_total": cats.get("qa_bundles", {}).get("total", 0),
            "receipt_artifacts_total": cats.get("receipt_audit_handoff_release", {}).get(
                "total", 0
            ),
            "candidate_cleanup_items_total": len(candidates),
            "candidate_cleanup_bytes_estimated": sum(
                int(c.get("estimated_size_bytes") or 0) for c in candidates
            ),
        },
        "container": container,
        "disk": disk,
        "docker_images": images,
        "filesystem_inventory": inventory,
        "filesystem_roots": roots,
        "categories": cats,
        "candidate_cleanup": candidates,
        "safety": safety_block(),
        "warnings": [f"{r.key}: {r.reason or r.stderr}" for r in failures],
        "first_safe_command": f"cat {report_path}/hygiene-summary.md",
    }


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _notable_pressure(use_percent: object) -> str:
    text = str(use_percent).rstrip("%")
    if text.isdigit() and int(text) >= 80:
        return "review recommended"
    return "none detected by helper"


def render_summary(report: dict[str, Any]) -> str:
    s = report["summary"]
    c = report["container"]
    d = report["disk"]
    lines = [
        "# Docker01 Hygiene Report",
        "",
        f"* Created: {report['created_at']}",
        f"* Report: {report['report_path']}",
        f"* Status: {report['status']}",
        "* Read-only: true",
        "",
        "## Disk",
        "",
        f"* root usage: {s['disk_use_percent']}",
        f"* available: {d.get('available', d.get('available', 'unknown'))}",
        f"* notable pressure: {_notable_pressure(s['disk_use_percent'])}",
        "",
        "## Container",
        "",
        f"* status: {c.get('status')}",
        f"* health: {c.get('health')}",
        f"* restart_count: {c.get('restart_count')}",
        f"* image: {c.get('image')}",
        f"* labels: {c.get('labels')}",
        "",
        "## Docker images",
        "",
        f"* total images: {s['docker_images_total']}",
        f"* ShellForgeAI lab images: {s['shellforgeai_images_total']}",
        "* newest PR image: review docker_images in JSON",
        "* older PR images: listed below when detected",
        "* untagged/dangling images if visible: review docker_images in JSON",
        "",
        "## Artifacts",
        "",
        f"* Compose backups: {s['compose_backups_total']}",
        f"* validation logs/evidence: {s['validation_artifacts_total']}",
        f"* QA bundles: {s['qa_bundles_total']}",
        f"* receipt/audit/handoff/release artifacts: {s['receipt_artifacts_total']}",
        "* other ShellForgeAI tmp artifacts: "
        f"{report['categories'].get('other_shellforgeai_tmp', {}).get('total', 0)}",
        "",
        "## Candidate cleanup proposal",
        "",
    ]
    for cand in report["candidate_cleanup"]:
        lines.extend(
            [
                f"* {cand.get('item')} ({cand.get('category')})",
                "  * estimated size: "
                f"{cand.get('estimated_size_bytes', cand.get('estimated_size', 'unknown'))}",
                f"  * age: {cand.get('age_seconds', cand.get('age', 'unknown'))}",
                f"  * reason: {cand.get('reason')}",
                f"  * risk note: {cand.get('risk_note')}",
                "  * proposed operator review action: "
                f"{cand.get('proposed_operator_review_action')}",
            ]
        )
    if not report["candidate_cleanup"]:
        lines.append("* No proposal-only candidates detected.")
    lines.extend(
        [
            "",
            "## Safety",
            "",
            "* cleanup executed: false",
            "* Docker prune executed: false",
            "* Docker image removed: false",
            "* file deleted: false",
            "* Docker/Compose mutation: false",
            "* container restarted: false",
            "",
            "## Result",
            "",
            "* report only",
            "* no cleanup performed",
            "* reviewer/operator decides any future cleanup lane",
            "",
        ]
    )
    return "\n".join(lines)


def render_plan(report: dict[str, Any]) -> str:
    lines = [
        "# Candidate Cleanup Plan (Proposal Only)",
        "",
        "This is not an executable cleanup script.",
        "This report does not delete files.",
        "This report does not prune Docker.",
        "This report does not remove images.",
        "This report does not restart containers.",
        "No cleanup was performed.",
        "",
        "Operator guidance: review every candidate in a separate cleanup PR/lane "
        "before any future mutation.",
        "",
    ]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for cand in report["candidate_cleanup"]:
        grouped.setdefault(cand.get("category", "unknown"), []).append(cand)
    for category, items in grouped.items():
        lines.extend([f"## {category}", ""])
        for cand in items:
            lines.extend(
                [
                    "```text",
                    f"Category: {category}",
                    f"Item: {cand.get('item')}",
                    f"Reason: {cand.get('reason')}",
                    f"Risk note: {cand.get('risk_note')}",
                    f"Suggested future action: {cand.get('proposed_operator_review_action')}",
                    "```",
                    "",
                ]
            )
    lines.extend(
        [
            "## Manual review examples",
            "",
            "All examples are comments and are intentionally non-executable.",
            "",
            "# review Docker/image candidates manually in a separate lane",
            "# review filesystem artifacts manually in a separate lane",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(
    report_path: Path, runner=run_allowed_command, roots: tuple[str, ...] = KNOWN_ROOTS
) -> dict[str, Any]:
    report_path.mkdir(parents=True, exist_ok=True)
    (report_path / "raw").mkdir(exist_ok=True)
    results = [runner(spec) for spec in COMMAND_SPECS]
    for spec, result in zip(COMMAND_SPECS, results, strict=True):
        write_text(report_path / spec.raw_file, (result.stdout or result.stderr)[:RAW_LIMIT])
    inventory, root_status = inventory_filesystem(roots)
    report = build_report(report_path, results, inventory, root_status)
    write_text(
        report_path / "hygiene-report.json", json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    commands = [
        {
            "key": r.key,
            "argv": r.argv,
            "returncode": r.returncode,
            "stdout": r.stdout,
            "stderr": r.stderr,
            "available": r.available,
            "reason": r.reason,
        }
        for r in results
    ]
    write_text(
        report_path / "commands-run.json", json.dumps(commands, indent=2, sort_keys=True) + "\n"
    )
    write_text(report_path / "hygiene-summary.md", render_summary(report))
    write_text(report_path / "candidate-cleanup-plan.md", render_plan(report))
    return report


def dry_run_payload(report_path: Path) -> dict[str, Any]:
    return {
        "status": "dry_run",
        "mode": MODE,
        "planned_commands": [list(s.argv) for s in COMMAND_SPECS],
        "planned_report_path": str(report_path),
        "commands_executed": False,
        "report_written": False,
        "mutation_performed": False,
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a read-only Docker01 hygiene inventory report."
    )
    parser.add_argument("--json", action="store_true", help="print JSON result")
    parser.add_argument("--out", type=Path, default=None, help="report output directory")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show planned read-only checks without executing or writing report",
    )
    parser.add_argument(
        "--validate", type=Path, default=None, help="validate an existing hygiene report directory"
    )
    args = parser.parse_args(argv)
    if args.validate is not None:
        payload = validate_report(args.validate)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"Docker01 hygiene validation {payload['status']}: {args.validate}")
            passed = payload["summary"]["checks_passed"]
            total = payload["summary"]["checks_total"]
            print(f"Checks: {passed}/{total} passed")
        return 0 if payload["status"] == "passed" else 1

    out = args.out or default_report_path()
    if args.dry_run:
        payload = dry_run_payload(out)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("Docker01 hygiene report dry run")
            print(f"Intended report path: {out}")
            print("Planned read-only checks:")
            for cmd in payload["planned_commands"]:
                print("- " + " ".join(cmd))
        return 0
    try:
        report = write_report(out)
    except OSError as exc:
        payload = {
            "schema_version": 1,
            "mode": MODE,
            "status": "failed",
            "report_path": str(out),
            "read_only": True,
            "mutation_performed": False,
            "error": str(exc),
            "safety": safety_block(),
        }
        print(
            json.dumps(payload, indent=2, sort_keys=True)
            if args.json
            else f"failed to create hygiene report: {exc}"
        )
        return 1
    print(
        json.dumps(report, indent=2, sort_keys=True)
        if args.json
        else (
            f"Docker01 hygiene report written: {out}\n"
            f"First safe command: cat {out}/hygiene-summary.md"
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
