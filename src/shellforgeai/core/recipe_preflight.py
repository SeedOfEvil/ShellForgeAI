"""Read-only V2 governed recipe preflight packets.

This module evaluates readiness for named, narrow recipes without enabling any
execution lane. It writes only ShellForgeAI-owned metadata when ``--save`` is
explicit and validates those packets read-only. It never restarts Docker,
executes Compose, runs cleanup/remediation/rollback, calls the model, or uses
shell execution.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shellforgeai.core.recipe_registry import (
    BROAD_TARGETS,
    PRODUCTION_TARGETS,
    REQUIRED_DISPOSABLE_RESTART_LABELS,
    get_recipe,
)

SCHEMA_VERSION = 1
PREFLIGHT_MODE = "v2_recipe_preflight"
VALIDATE_MODE = "v2_recipe_preflight_validate"
SUPPORTED_RECIPE = "docker.disposable_restart"
REQUIRED_FILES = ("recipe-preflight.json", "recipe-preflight.md", "manifest.json")
BLOCKED_COMPOSE_TARGETS = {"docker-compose", "docker-compose-down", "compose", "docker compose"}
_MUTATING_TRUE_FLAGS = (
    "mutation_performed",
    "plan_created",
    "mission_created",
    "apply_executed",
    "remediation_executed",
    "rollback_executed",
    "cleanup_executed",
    "docker_compose_executed",
    "container_restarted",
    "shell_true",
    "arbitrary_command_execution",
    "natural_language_execution",
    "model_called",
)
_SECRET_FIELD_RE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)")
_SECRET_VALUE_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*[^\s,;}]+"
)


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def recipe_preflight_root(data_dir: Path | str) -> Path:
    return Path(data_dir).expanduser() / "recipe_preflights"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _has_obvious_secret(value: Any) -> bool:
    if isinstance(value, dict):
        for key, inner in value.items():
            if _SECRET_FIELD_RE.search(str(key)):
                return True
            if _has_obvious_secret(inner):
                return True
        return False
    if isinstance(value, list):
        return any(_has_obvious_secret(inner) for inner in value)
    if isinstance(value, str):
        return bool(_SECRET_VALUE_RE.search(value))
    return False


def recipe_preflight_safety() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "plan_created": False,
        "mission_created": False,
        "apply_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "cleanup_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "model_called": False,
    }


def _safety_non_mutating(safety: dict[str, Any]) -> bool:
    return safety.get("read_only") is True and all(
        safety.get(flag) is False for flag in _MUTATING_TRUE_FLAGS if flag in safety
    )


def _normalize_labels(labels: dict[str, Any] | None) -> dict[str, str]:
    return {str(k): str(v) for k, v in (labels or {}).items()}


def _target_row(target: str, scene: dict[str, Any] | None) -> dict[str, Any] | None:
    for row in (scene or {}).get("containers") or []:
        if isinstance(row, dict) and str(row.get("name") or "") == target:
            return row
    return None


def _target_object(target: str, scene: dict[str, Any] | None) -> dict[str, Any]:
    row = _target_row(target, scene)
    labels = _normalize_labels(row.get("labels") if isinstance(row, dict) else None)
    lower = (target or "").strip().lower()
    disposable = labels.get("shellforgeai.disposable") == "true"
    allowlisted = labels.get("shellforgeai.allow_restart") == "true"
    return {
        "name": row.get("name") if row else target,
        "found": row is not None,
        "production_target": lower in PRODUCTION_TARGETS,
        "broad_target": lower in BROAD_TARGETS or lower in BLOCKED_COMPOSE_TARGETS,
        "compose_pattern": lower in BLOCKED_COMPOSE_TARGETS,
        "disposable": disposable,
        "allowlisted": allowlisted,
        "labels": labels,
        "state": row.get("state") if row else None,
        "status": row.get("status") if row else None,
    }


def _gate(name: str, status: str, reason: str = "") -> dict[str, str]:
    out = {"name": name, "status": status}
    if reason:
        out["reason"] = reason
    return out


def _first_blocker(blockers: list[str]) -> str:
    return blockers[0] if blockers else ""


def build_preflight_packet(
    recipe_id: str,
    target: str,
    *,
    scene: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a read-only recipe preflight packet. No command execution occurs."""
    recipe = get_recipe(recipe_id)
    target_name = str(target or "").strip()
    target_info = _target_object(target_name, scene)
    safety = recipe_preflight_safety()
    base: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "mode": PREFLIGHT_MODE,
        "status": "error",
        "read_only": True,
        "mutation_performed": False,
        "recipe_id": recipe_id,
        "preflight_id": None,
        "artifact_written": False,
        "execution_available": False,
        "future_confirm_required": True,
        "command_preview_only": True,
        "command_executed": False,
        "exact_target_only": True,
        "target": target_info,
        "action_preview": None,
        "gates": [],
        "blockers": [],
        "warnings": [],
        "first_safe_command": "shellforgeai recipes list",
        "safe_next_commands": [],
        "safety": safety,
    }
    if recipe is None:
        return {**base, "status": "error", "blockers": ["recipe not found"]}
    if recipe_id != SUPPORTED_RECIPE:
        return {
            **base,
            "status": "blocked",
            "blockers": ["recipe preflight is only implemented for docker.disposable_restart"],
            "first_safe_command": "shellforgeai recipes list",
            "safe_next_commands": ["shellforgeai recipes list"],
        }

    lower = target_name.lower()
    blockers: list[str] = []
    if not target_name:
        blockers.append("exact target required")
    if target_info["production_target"]:
        blockers.append("production target refused")
    if target_info["broad_target"]:
        blockers.append("broad target refused")
    if target_info["compose_pattern"]:
        blockers.append("Docker Compose service pattern refused")
    if (
        lower in {"shellforgeai", "all", "*", "docker-compose", "docker-compose-down"}
        and not blockers
    ):
        blockers.append("blocked target refused")
    if not target_info["found"]:
        blockers.append("target not found")
    labels = target_info["labels"] if isinstance(target_info.get("labels"), dict) else {}
    missing_labels = [
        f"{key}={value}"
        for key, value in REQUIRED_DISPOSABLE_RESTART_LABELS.items()
        if labels.get(key) != value
    ]
    for label in missing_labels:
        blockers.append(f"missing required label: {label}")

    status = (
        "preflight_ready"
        if not blockers
        else ("not_found" if "target not found" in blockers else "blocked")
    )
    gates = [
        _gate(
            "exact_target_required",
            "passed" if target_name and not target_info["broad_target"] else "blocked",
        ),
        _gate("target_found", "passed" if target_info["found"] else "blocked"),
        _gate("disposable_label_required", "passed" if target_info["disposable"] else "blocked"),
        _gate(
            "allow_restart_label_required", "passed" if target_info["allowlisted"] else "blocked"
        ),
        _gate(
            "production_target_refused",
            "passed" if not target_info["production_target"] else "blocked",
        ),
        _gate("explicit_confirm_required", "future_gate"),
        _gate("receipt_required", "future_gate"),
        _gate("post_verify_required", "future_gate"),
        _gate("rollback_posture_required", "future_gate"),
    ]
    action_preview = (
        {
            "argv": ["docker", "restart", target_name],
            "description": "Exact-target disposable container restart preview only",
        }
        if status == "preflight_ready"
        else None
    )
    if status == "preflight_ready":
        first_safe = "shellforgeai recipes preflight validate <preflight_id>"
        safe_next = [
            "shellforgeai recipes preflight --recipe docker.disposable_restart "
            f"--target {target_name} --save",
            "shellforgeai recipes preflight validate <preflight_id>",
        ]
    elif target_info["production_target"]:
        first_safe = "shellforgeai status --json"
        safe_next = [first_safe]
    else:
        first_safe = (
            "shellforgeai recipes eligibility --recipe docker.disposable_restart "
            f"--target {target_name} --json"
            if target_name
            else "shellforgeai triage --json"
        )
        safe_next = [first_safe, "shellforgeai triage --json"]
    return {
        **base,
        "status": status,
        "target_class": (
            "disposable allowlisted container" if status == "preflight_ready" else "blocked target"
        ),
        "action_preview": action_preview,
        "gates": gates,
        "blockers": blockers,
        "reason": _first_blocker(blockers),
        "first_safe_command": first_safe,
        "safe_next_commands": safe_next,
    }


def render_preflight_markdown(payload: dict[str, Any]) -> str:
    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    lines = ["# ShellForgeAI Recipe Preflight", ""]
    lines.append(f"- status: {payload.get('status')}")
    lines.append(f"- recipe: {payload.get('recipe_id')}")
    lines.append(f"- target: {target.get('name')}")
    lines.append(f"- preflight_id: {payload.get('preflight_id') or 'unsaved'}")
    lines.append("- read_only: true")
    lines.append("- execution_available: false")
    lines.extend(["", "## Action preview"])
    argv = (
        ((payload.get("action_preview") or {}).get("argv") or [])
        if isinstance(payload.get("action_preview"), dict)
        else []
    )
    lines.append("- " + " ".join(str(part) for part in argv))
    lines.append("- command_preview_only: true")
    lines.append("- command_executed: false")
    lines.extend(["", "## Gates"])
    for gate in payload.get("gates") or []:
        lines.append(f"- {gate.get('name')}: {gate.get('status')}")
    lines.extend(["", "## Blockers"])
    lines.extend(f"- {b}" for b in (payload.get("blockers") or ["none"]))
    lines.extend(["", "## First safe command", f"- {payload.get('first_safe_command')}"])
    lines.extend(["", "## Safety"])
    lines.append("- Read-only preflight.")
    lines.append("- No command was executed.")
    lines.append("- No container was restarted.")
    lines.append("- No remediation, rollback, cleanup, Docker Compose, or shell action occurred.")
    for key, value in (payload.get("safety") or {}).items():
        lines.append(f"- {key}: {str(value).lower()}")
    return "\n".join(lines).rstrip() + "\n"


def _resolve_preflight_dir(data_dir: Path | str, preflight_id: str) -> Path:
    root = recipe_preflight_root(data_dir).resolve()
    if not preflight_id or "/" in preflight_id or "\\" in preflight_id or ".." in preflight_id:
        raise ValueError("invalid preflight_id")
    out = (root / preflight_id).resolve()
    try:
        out.relative_to(root)
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError("refusing to write preflight outside ShellForgeAI root") from exc
    return out


def save_preflight_packet(payload: dict[str, Any], data_dir: Path | str) -> dict[str, Any]:
    safety = payload.get("safety") if isinstance(payload.get("safety"), dict) else {}
    if not _safety_non_mutating(safety):
        raise ValueError("refusing to save preflight with mutating safety metadata")
    if _has_obvious_secret(payload):
        raise ValueError("refusing to save preflight containing secret-shaped fields")
    preflight_id = f"preflight_{_now_stamp()}_{uuid.uuid4().hex[:6]}"
    out = _resolve_preflight_dir(data_dir, preflight_id)
    out.mkdir(parents=True, exist_ok=False)
    saved = dict(payload)
    created_at = _now_utc()
    saved.update(
        {
            "preflight_id": preflight_id,
            "preflight_path": str(out),
            "created_at": created_at,
            "artifact_written": True,
            "first_safe_command": f"shellforgeai recipes preflight validate {preflight_id}",
        }
    )
    json_path = out / "recipe-preflight.json"
    md_path = out / "recipe-preflight.md"
    manifest_path = out / "manifest.json"
    json_path.write_text(json.dumps(saved, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_preflight_markdown(saved), encoding="utf-8")
    files = ["recipe-preflight.json", "recipe-preflight.md"]
    checksums = {rel: _sha256_file(out / rel) for rel in files}
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "v2_recipe_preflight",
        "mode": "v2_recipe_preflight_artifact",
        "preflight_id": preflight_id,
        "recipe_id": saved.get("recipe_id"),
        "target": (saved.get("target") or {}).get("name")
        if isinstance(saved.get("target"), dict)
        else None,
        "created_at": created_at,
        "files": [*files, "manifest.json"],
        "checksums": checksums,
        "safety": dict(safety),
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksums["manifest.json"] = _sha256_file(manifest_path)
    saved.update(
        {
            "manifest_path": str(manifest_path),
            "files": [*files, "manifest.json"],
            "checksums": checksums,
            "manifest": manifest,
        }
    )
    json_path.write_text(json.dumps(saved, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksums["recipe-preflight.json"] = _sha256_file(json_path)
    manifest["checksums"] = checksums
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksums["manifest.json"] = _sha256_file(manifest_path)
    saved["checksums"] = checksums
    saved["manifest"] = manifest
    json_path.write_text(json.dumps(saved, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksums["recipe-preflight.json"] = _sha256_file(json_path)
    manifest["checksums"] = checksums
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksums["manifest.json"] = _sha256_file(manifest_path)
    saved["checksums"] = checksums
    saved["manifest"] = manifest
    return saved


def _resolve_ref(ref: str, root: Path) -> Path | None:
    raw = str(ref or "").strip()
    if not raw:
        return None
    p = Path(raw).expanduser()
    if p.is_absolute() or "/" in raw or "\\" in raw:
        resolved = p.resolve()
        if resolved.is_file():
            resolved = resolved.parent
    else:
        if ".." in raw:
            return None
        resolved = (root / raw).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return None
    return resolved


def validate_preflight_packet(preflight_ref: str, data_dir: Path | str) -> dict[str, Any]:
    root = recipe_preflight_root(data_dir)
    checks = {
        "required_files": False,
        "json_parse": False,
        "schema": False,
        "manifest": False,
        "checksums": False,
        "recipe_id": False,
        "target": False,
        "safety": False,
        "secrets": False,
    }
    base = {
        "schema_version": SCHEMA_VERSION,
        "mode": VALIDATE_MODE,
        "read_only": True,
        "mutation_performed": False,
        "safety": recipe_preflight_safety(),
    }
    d = _resolve_ref(preflight_ref, root)
    if d is None:
        return {
            **base,
            "status": "not_found",
            "preflight_id": None,
            "checks": checks,
            "warnings": ["preflight not found"],
        }
    if not d.is_dir():
        return {
            **base,
            "status": "not_found",
            "preflight_id": d.name,
            "checks": checks,
            "warnings": ["preflight not found"],
        }
    if any(not (d / rel).exists() for rel in REQUIRED_FILES):
        return {
            **base,
            "status": "failed",
            "preflight_id": d.name,
            "checks": checks,
            "warnings": ["missing required files"],
        }
    checks["required_files"] = True
    try:
        packet = json.loads((d / "recipe-preflight.json").read_text(encoding="utf-8"))
        manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    except Exception:
        return {
            **base,
            "status": "failed",
            "preflight_id": d.name,
            "checks": checks,
            "warnings": ["malformed json"],
        }
    checks["json_parse"] = True
    checks["schema"] = (
        packet.get("schema_version") == SCHEMA_VERSION and packet.get("mode") == PREFLIGHT_MODE
    )
    checks["manifest"] = manifest.get("kind") == "v2_recipe_preflight"
    manifest_checksums = (
        manifest.get("checksums") if isinstance(manifest.get("checksums"), dict) else {}
    )
    checks["checksums"] = bool(manifest_checksums)
    for rel, expected in manifest_checksums.items():
        if rel == "manifest.json":
            continue
        if not (d / rel).exists() or _sha256_file(d / rel) != expected:
            checks["checksums"] = False
            break
    checks["recipe_id"] = packet.get("recipe_id") == manifest.get("recipe_id") == SUPPORTED_RECIPE
    packet_target = (
        (packet.get("target") or {}).get("name") if isinstance(packet.get("target"), dict) else None
    )
    checks["target"] = bool(packet_target) and packet_target == manifest.get("target")
    safety = packet.get("safety") if isinstance(packet.get("safety"), dict) else {}
    checks["safety"] = (
        _safety_non_mutating(safety)
        and packet.get("read_only") is True
        and packet.get("mutation_performed") is False
        and packet.get("command_executed") is False
        and safety.get("container_restarted") is False
    )
    checks["secrets"] = not _has_obvious_secret(packet) and not _has_obvious_secret(manifest)
    warnings: list[str] = []
    if not checks["schema"]:
        warnings.append("preflight schema/mode is invalid")
    if not checks["manifest"]:
        warnings.append("manifest kind is invalid")
    if not checks["checksums"]:
        warnings.append("checksum mismatch")
    if not checks["recipe_id"]:
        warnings.append("recipe_id mismatch")
    if not checks["target"]:
        warnings.append("target mismatch")
    if not checks["safety"]:
        warnings.append("preflight safety block is not strictly read-only")
    if not checks["secrets"]:
        warnings.append("possible secret-shaped content detected")
    return {
        **base,
        "status": "ok" if all(checks.values()) else "failed",
        "preflight_id": packet.get("preflight_id") or d.name,
        "preflight_path": str(d),
        "recipe_id": packet.get("recipe_id"),
        "target": packet_target,
        "checks": checks,
        "warnings": warnings,
    }
