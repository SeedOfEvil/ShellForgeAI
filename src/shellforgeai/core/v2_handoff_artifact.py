"""Read-only V2 operator handoff artifact lifecycle.

This module saves, validates, and exports ShellForgeAI-owned handoff packets
only. Save/export write nothing outside ``<data_dir>/v2_handoffs/<handoff_id>/``
and ``<data_dir>/exports/export_<handoff_id>/`` respectively; validate and
export-validate are strictly read-only. Nothing here ever executes cleanup,
remediation, rollback, Docker/Compose, restart, shell, model, or
natural-language mutation. The lifecycle is:

    handoff --save -> handoff validate -> handoff export -> handoff export-validate
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REQUIRED_HANDOFF_FILES = ("handoff.json", "handoff.md", "manifest.json")
REQUIRED_EXPORT_FILES = (*REQUIRED_HANDOFF_FILES, "export-manifest.json")

_MUTATING_TRUE_FLAGS = (
    "mutation_performed",
    "apply_executed",
    "mission_created",
    "plan_created",
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


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _safety_non_mutating(safety: dict[str, Any]) -> bool:
    return safety.get("read_only") is True and all(
        safety.get(flag) is False for flag in _MUTATING_TRUE_FLAGS if flag in safety
    )


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


def _validate_data_dir(data_dir: Path | str) -> Path:
    """Reject obviously unsafe artifact roots before writing anything."""
    raw = str(data_dir)
    if not raw.strip():
        raise ValueError("invalid data_dir for handoff save: empty path")
    if ".." in Path(raw).parts:
        raise ValueError("invalid data_dir for handoff save: path traversal is not allowed")
    return Path(data_dir)


def resolve_handoff_dir(data_dir: Path | str, handoff_id: str) -> Path:
    """Resolve and confirm the handoff dir stays inside the ShellForgeAI root."""
    root = _validate_data_dir(data_dir).resolve() / "v2_handoffs"
    if not handoff_id or "/" in handoff_id or "\\" in handoff_id or ".." in handoff_id:
        raise ValueError("invalid handoff_id for handoff save")
    out = (root / handoff_id).resolve()
    try:
        out.relative_to(root.resolve())
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError("refusing to write handoff outside the ShellForgeAI root") from exc
    return out


def _handoff_markdown(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    golden = payload.get("golden_path") if isinstance(payload.get("golden_path"), dict) else {}
    lines = ["# ShellForgeAI V2 Operator Handoff", ""]
    lines.append(f"- status: {payload.get('status', 'unknown')}")
    lines.append(f"- handoff_id: {payload.get('handoff_id') or 'unsaved'}")
    lines.append(f"- read_only: {str(payload.get('read_only', True)).lower()}")
    lines.append(f"- mutation_performed: {str(payload.get('mutation_performed', False)).lower()}")
    lines.extend(["", "## Summary"])
    for key in (
        "current_status",
        "risk",
        "suspects_ranked",
        "proposal_status",
        "apply_preview_status",
        "verify_status",
    ):
        lines.append(f"- {key}: {summary.get(key)}")
    lines.extend(["", "## V2 golden path"])
    for stage in ("status", "triage", "propose", "apply_preview", "verify"):
        section = golden.get(stage) if isinstance(golden.get(stage), dict) else {}
        lines.append(f"- {stage}: {section.get('status', 'unknown')}")
    lines.extend(["", "## First safe command"])
    lines.append(f"- {payload.get('first_safe_command') or 'shellforgeai status --json'}")
    lines.extend(["", "## What was not done"])
    lines.append("- No applied action was detected or assumed.")
    lines.append("- This handoff is a read-only operator summary.")
    limitations = payload.get("limitations") or []
    if limitations:
        lines.extend(["", "## Limitations"])
        lines.extend(f"- {item}" for item in limitations)
    warnings = payload.get("warnings") or []
    if warnings:
        lines.extend(["", "## Warnings"])
        lines.extend(f"- {item}" for item in warnings)
    lines.extend(["", "## Safety"])
    for key, value in (payload.get("safety") or {}).items():
        lines.append(f"- {key}: {str(value).lower()}")
    return "\n".join(lines).rstrip() + "\n"


def save_v2_handoff(
    payload: dict[str, Any], data_dir: Path | str, *, source: str = "shellforgeai handoff --save"
) -> dict[str, Any]:
    """Write a read-only ShellForgeAI-owned handoff packet and return the saved payload.

    Raises ``ValueError`` for unsafe save targets or for payloads whose safety
    metadata is not strictly read-only/non-mutating.
    """
    safety = payload.get("safety") if isinstance(payload.get("safety"), dict) else {}
    if not _safety_non_mutating(safety):
        raise ValueError("refusing to save handoff with mutating safety metadata")
    if _has_obvious_secret(payload):
        raise ValueError("refusing to save handoff containing secret-shaped fields")

    handoff_id = f"handoff_{_now_stamp()}_{uuid.uuid4().hex[:6]}"
    out = resolve_handoff_dir(data_dir, handoff_id)
    out.mkdir(parents=True, exist_ok=False)

    saved = dict(payload)
    saved.update(
        {
            "schema_version": saved.get("schema_version") or 1,
            "mode": "v2_handoff",
            "read_only": True,
            "mutation_performed": False,
            "artifact_written": True,
            "handoff_id": handoff_id,
            "handoff_path": str(out),
        }
    )

    (out / "handoff.json").write_text(
        json.dumps(saved, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "handoff.md").write_text(_handoff_markdown(saved), encoding="utf-8")
    files = ["handoff.json", "handoff.md"]
    checksums = {rel: _sha256_file(out / rel) for rel in files}
    manifest = {
        "schema_version": 1,
        "kind": "v2_handoff",
        "mode": "v2_handoff_artifact",
        "handoff_id": handoff_id,
        "created_at": _now_utc(),
        "source": source,
        "files": [*files, "manifest.json"],
        "checksums": checksums,
        "mutation_performed": False,
        "artifact_written": True,
        "safety": dict(safety),
        "summary": dict(saved.get("summary") or {}),
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksums["manifest.json"] = _sha256_file(out / "manifest.json")

    return {
        **saved,
        "files": [*files, "manifest.json"],
        "checksums": checksums,
        "manifest": manifest,
    }


# --------------------------------------------------------------------------- #
# Validate / export / export-validate (read-only except owned export writes)   #
# --------------------------------------------------------------------------- #
def _validate_safety() -> dict[str, bool]:
    """Safety block asserted by the read-only validators themselves."""
    return {
        "read_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "model_called": False,
    }


def _export_safety() -> dict[str, bool]:
    """Safety block recorded by an artifact-only handoff export."""
    return {
        "read_only": True,
        "artifact_export_only": True,
        "arbitrary_path_write": False,
        "mutation_performed": False,
        "docker_compose_executed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "container_restarted": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "model_called": False,
    }


def _resolve_artifact_ref(ref: str, root: Path) -> Path | None:
    """Resolve a handoff/export ref to a path strictly inside ``root``.

    Accepts an artifact id (no separators) or a ShellForgeAI-owned directory
    path. Returns ``None`` for empty refs, traversal, or anything resolving
    outside ``root`` so callers can surface a controlled failure instead of
    touching a foreign path.
    """
    raw = str(ref or "")
    if not raw.strip():
        return None
    p = Path(raw)
    if p.is_absolute() or "/" in raw or "\\" in raw:
        resolved = p.resolve()
    else:
        if ".." in raw:
            return None
        resolved = (root / raw).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return None
    return resolved


def validate_v2_handoff(handoff_ref: str, data_dir: Path | str) -> dict[str, Any]:
    """Read-only validation of a saved ShellForgeAI handoff artifact.

    Never raises for unsafe/missing/malformed refs: it returns a controlled
    ``failed``/``not_found`` payload so the CLI can exit non-zero without a
    traceback.
    """
    root = Path(data_dir) / "v2_handoffs"
    checks = {
        "required_files": False,
        "json_parse": False,
        "schema": False,
        "manifest": False,
        "checksums": False,
        "safety": False,
        "secrets": False,
    }
    base = {
        "schema_version": 1,
        "mode": "v2_handoff_validate",
        "read_only": True,
        "mutation_performed": False,
        "safety": _validate_safety(),
    }
    d = _resolve_artifact_ref(handoff_ref, root)
    if d is None:
        return {
            **base,
            "status": "failed",
            "handoff_id": None,
            "checks": checks,
            "warnings": ["unsafe handoff reference"],
        }
    if not d.is_dir():
        return {
            **base,
            "status": "not_found",
            "handoff_id": d.name,
            "checks": checks,
            "warnings": ["handoff not found"],
        }
    if any(not (d / f).exists() for f in REQUIRED_HANDOFF_FILES):
        return {
            **base,
            "status": "failed",
            "handoff_id": d.name,
            "checks": checks,
            "warnings": ["missing required files"],
        }
    checks["required_files"] = True
    try:
        handoff = json.loads((d / "handoff.json").read_text(encoding="utf-8"))
        manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    except Exception:
        return {
            **base,
            "status": "failed",
            "handoff_id": d.name,
            "checks": checks,
            "warnings": ["malformed json"],
        }
    checks["json_parse"] = True
    checks["schema"] = bool(handoff.get("schema_version")) and handoff.get("mode") == "v2_handoff"
    checks["manifest"] = manifest.get("kind") == "v2_handoff"
    checks["checksums"] = bool(manifest.get("checksums"))
    for rel, expected in (manifest.get("checksums") or {}).items():
        if not (d / rel).exists() or _sha256_file(d / rel) != expected:
            checks["checksums"] = False
            break
    safety = handoff.get("safety") if isinstance(handoff.get("safety"), dict) else {}
    checks["safety"] = (
        _safety_non_mutating(safety)
        and handoff.get("read_only") is True
        and handoff.get("mutation_performed") is False
    )
    checks["secrets"] = not _has_obvious_secret(handoff) and not _has_obvious_secret(manifest)
    warnings: list[str] = []
    if not checks["schema"]:
        warnings.append("handoff schema/mode is not v2_handoff")
    if not checks["manifest"]:
        warnings.append("manifest kind is not v2_handoff")
    if not checks["checksums"]:
        warnings.append("checksum mismatch")
    if not checks["safety"]:
        warnings.append("handoff safety block is not strictly read-only")
    if not checks["secrets"]:
        warnings.append("possible secret-shaped content detected")
    status = "ok" if all(checks.values()) else "failed"
    return {
        **base,
        "status": status,
        "handoff_id": d.name,
        "handoff_path": str(d),
        "checks": checks,
        "warnings": warnings,
    }


def export_v2_handoff(handoff_ref: str, data_dir: Path | str) -> dict[str, Any]:
    """Copy a validated handoff into a portable ShellForgeAI-owned export.

    Writes only under ``<data_dir>/exports/export_<handoff_id>/``. Re-exporting a
    handoff whose export already exists and validates is idempotent
    (``existing: true``). Never reruns collectors, calls the model, or mutates
    anything outside the owned export path.
    """
    root = Path(data_dir) / "v2_handoffs"
    safety = _export_safety()
    v = validate_v2_handoff(handoff_ref, data_dir)
    if v.get("status") == "not_found":
        return {
            "schema_version": 1,
            "mode": "v2_handoff_export",
            "status": "not_found",
            "read_only": True,
            "mutation_performed": False,
            "source_handoff": {"id": v.get("handoff_id"), "path": None},
            "safety": safety,
            "warnings": ["handoff not found"],
        }
    if v.get("status") != "ok":
        return {
            "schema_version": 1,
            "mode": "v2_handoff_export",
            "status": "failed",
            "read_only": True,
            "mutation_performed": False,
            "source_handoff": {"id": v.get("handoff_id"), "path": None},
            "safety": safety,
            "warnings": ["source handoff validation failed", *(v.get("warnings") or [])],
        }
    src = _resolve_artifact_ref(handoff_ref, root)
    if src is None:  # pragma: no cover - validate already proved the ref is safe
        return {
            "schema_version": 1,
            "mode": "v2_handoff_export",
            "status": "failed",
            "read_only": True,
            "mutation_performed": False,
            "source_handoff": {"id": v.get("handoff_id"), "path": None},
            "safety": safety,
            "warnings": ["unsafe handoff reference"],
        }
    out = (Path(data_dir) / "exports" / f"export_{src.name}").resolve()
    if out.exists():
        vv = validate_v2_handoff_export(out.name, data_dir)
        if vv.get("status") == "ok":
            export_manifest = json.loads((out / "export-manifest.json").read_text(encoding="utf-8"))
            return {
                "schema_version": 1,
                "mode": "v2_handoff_export",
                "status": "exported",
                "existing": True,
                "read_only": True,
                "mutation_performed": False,
                "source_handoff": dict(export_manifest.get("source_handoff") or {}),
                "export": {
                    "id": out.name,
                    "path": str(out),
                    "files": list(export_manifest.get("files") or []),
                },
                "checksums": dict(export_manifest.get("checksums") or {}),
                "safety": safety,
                "next_safe_commands": [f"shellforgeai handoff export-validate {out.name}"],
                "warnings": [],
            }
        return {
            "schema_version": 1,
            "mode": "v2_handoff_export",
            "status": "already_exists",
            "read_only": True,
            "mutation_performed": False,
            "source_handoff": {"id": src.name, "path": str(src)},
            "export": {"id": out.name, "path": str(out)},
            "safety": safety,
            "warnings": ["existing export path failed validation"],
            "next_safe_commands": [f"shellforgeai handoff export-validate {out.name}"],
        }
    out.mkdir(parents=True, exist_ok=False)
    files = list(REQUIRED_HANDOFF_FILES)
    for rel in files:
        (out / rel).write_bytes((src / rel).read_bytes())
    checksums = {rel: _sha256_file(out / rel) for rel in files}
    export_manifest = {
        "schema_version": 1,
        "mode": "v2_handoff_export",
        "kind": "v2_handoff_export",
        "export_id": out.name,
        "created_at": _now_utc(),
        "source_handoff": {"id": src.name, "path": str(src), "validated": True},
        "files": [*files, "export-manifest.json"],
        "checksums": checksums,
        "safety": safety,
    }
    (out / "export-manifest.json").write_text(
        json.dumps(export_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksums["export-manifest.json"] = _sha256_file(out / "export-manifest.json")
    return {
        "schema_version": 1,
        "mode": "v2_handoff_export",
        "status": "exported",
        "existing": False,
        "read_only": True,
        "mutation_performed": False,
        "source_handoff": export_manifest["source_handoff"],
        "export": {"id": out.name, "path": str(out), "files": export_manifest["files"]},
        "checksums": checksums,
        "safety": safety,
        "next_safe_commands": [f"shellforgeai handoff export-validate {out.name}"],
        "warnings": [],
    }


def validate_v2_handoff_export(export_ref: str, data_dir: Path | str) -> dict[str, Any]:
    """Read-only validation of an exported ShellForgeAI handoff artifact."""
    root = Path(data_dir) / "exports"
    checks = {
        "required_files": False,
        "json_parse": False,
        "checksums": False,
        "source_safety": False,
        "export_safety": False,
        "secrets": False,
    }
    base = {
        "schema_version": 1,
        "mode": "v2_handoff_export_validate",
        "read_only": True,
        "mutation_performed": False,
        "safety": _validate_safety(),
    }
    d = _resolve_artifact_ref(export_ref, root)
    if d is None:
        return {
            **base,
            "status": "failed",
            "export_id": None,
            "checks": checks,
            "warnings": ["unsafe export reference"],
        }
    if not d.is_dir():
        return {
            **base,
            "status": "not_found",
            "export_id": d.name,
            "checks": checks,
            "warnings": ["export not found"],
        }
    if any(not (d / f).exists() for f in REQUIRED_EXPORT_FILES):
        return {
            **base,
            "status": "failed",
            "export_id": d.name,
            "checks": checks,
            "warnings": ["missing required files"],
        }
    checks["required_files"] = True
    try:
        handoff = json.loads((d / "handoff.json").read_text(encoding="utf-8"))
        manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
        export_manifest = json.loads((d / "export-manifest.json").read_text(encoding="utf-8"))
    except Exception:
        return {
            **base,
            "status": "failed",
            "export_id": d.name,
            "checks": checks,
            "warnings": ["malformed json"],
        }
    checks["json_parse"] = True
    checks["checksums"] = bool(export_manifest.get("checksums"))
    for rel, expected in (export_manifest.get("checksums") or {}).items():
        if not (d / rel).exists() or _sha256_file(d / rel) != expected:
            checks["checksums"] = False
            break
    src_safety = handoff.get("safety") if isinstance(handoff.get("safety"), dict) else {}
    exp_safety = (
        export_manifest.get("safety") if isinstance(export_manifest.get("safety"), dict) else {}
    )
    checks["source_safety"] = (
        _safety_non_mutating(src_safety)
        and handoff.get("read_only") is True
        and handoff.get("mutation_performed") is False
    )
    checks["export_safety"] = (
        exp_safety.get("read_only") is True
        and exp_safety.get("artifact_export_only") is True
        and exp_safety.get("arbitrary_path_write") is False
        and all(
            exp_safety.get(flag) is False for flag in _MUTATING_TRUE_FLAGS if flag in exp_safety
        )
    )
    checks["secrets"] = (
        not _has_obvious_secret(handoff)
        and not _has_obvious_secret(manifest)
        and not _has_obvious_secret(export_manifest)
    )
    warnings: list[str] = []
    if not checks["checksums"]:
        warnings.append("checksum mismatch")
    if not checks["source_safety"]:
        warnings.append("source handoff safety block is not strictly read-only")
    if not checks["export_safety"]:
        warnings.append("export safety block is not artifact-export-only")
    if not checks["secrets"]:
        warnings.append("possible secret-shaped content detected")
    status = "ok" if all(checks.values()) else "failed"
    return {
        **base,
        "status": status,
        "export_id": d.name,
        "export_path": str(d),
        "source_handoff": dict(export_manifest.get("source_handoff") or {}),
        "checks": checks,
        "warnings": warnings,
    }
