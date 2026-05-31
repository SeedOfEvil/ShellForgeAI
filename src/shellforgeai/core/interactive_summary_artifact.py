from __future__ import annotations

import hashlib
import json
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REQUIRED_SUMMARY_FILES = ("interactive-summary.json", "interactive-summary.md", "manifest.json")
REQUIRED_EXPORT_FILES = (*REQUIRED_SUMMARY_FILES, "export-manifest.json")

_MUTATING_TRUE_FLAGS = (
    "mutation_performed",
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
    "docker_compose_executed",
    "container_restarted",
    "production_restart_executed",
    "shell_true",
    "arbitrary_command_execution",
    "natural_language_execution",
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


def _summary_safety() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "production_restart_executed": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
    }


def _export_safety() -> dict[str, bool]:
    return {
        **_summary_safety(),
        "artifact_export_only": True,
        "arbitrary_path_write": False,
    }


def _resolve_ref(ref: str, root: Path) -> Path | None:
    p = Path(ref)
    if p.is_absolute() or "/" in ref:
        resolved = p.resolve()
    else:
        if ".." in ref or "\\" in ref:
            return None
        resolved = (root / ref).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return None
    return resolved


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


def _safety_non_mutating(safety: dict[str, Any]) -> bool:
    return safety.get("read_only") is True and all(
        safety.get(flag) is False for flag in _MUTATING_TRUE_FLAGS
    )


def _summary_markdown(payload: dict[str, Any]) -> str:
    session = payload.get("session") or {}
    lines = ["# ShellForgeAI Interactive Session Summary", "", "## Status"]
    lines.append(f"- status: {payload.get('status', 'ok')}")
    lines.append(f"- summary_id: {payload.get('summary_id') or 'unsaved'}")
    session_id = payload.get("session_id") or session.get("latest_session_id") or "unknown"
    lines.append(f"- session_id: {session_id}")
    lines.extend(["", "## Checked"])
    checks = payload.get("checks") or []
    lines.extend(f"- {check}" for check in checks) if checks else lines.append("- none recorded")
    lines.extend(["", "## Findings"])
    findings = payload.get("findings") or []
    lines.extend(f"- {finding}" for finding in findings) if findings else lines.append(
        "- none recorded"
    )
    lines.extend(["", "## Refusals"])
    refusals = payload.get("refusals") or []
    lines.extend(f"- {refusal}" for refusal in refusals) if refusals else lines.append(
        "- none recorded"
    )
    lines.extend(["", "## First safe command"])
    lines.append(f"- {payload.get('first_safe_command') or 'shellforgeai ops report --brief'}")
    lines.extend(["", "## Artifacts / evidence references"])
    artifacts = payload.get("latest_artifacts") or session.get("latest_artifacts") or []
    if session.get("latest_session_id"):
        lines.append(f"- latest session id: {session['latest_session_id']}")
    lines.extend(f"- {artifact}" for artifact in artifacts) if artifacts else lines.append(
        "- none recorded"
    )
    lines.extend(["", "## Safety"])
    for key, value in (payload.get("safety") or {}).items():
        lines.append(f"- {key}: {str(value).lower()}")
    return "\n".join(lines).rstrip() + "\n"


def _saved_payload(payload: dict[str, Any], summary_id: str, summary_path: Path) -> dict[str, Any]:
    saved = dict(payload)
    session = dict(saved.get("session") or {})
    saved.update(
        {
            "schema_version": saved.get("schema_version") or 1,
            "mode": "interactive_session_summary",
            "status": saved.get("status") or "ok",
            "summary_id": summary_id,
            "summary_path": str(summary_path),
            "session_id": saved.get("session_id") or session.get("latest_session_id"),
            "events_seen": saved.get("events_seen", session.get("events_seen", 0)),
            "latest_artifacts": saved.get("latest_artifacts", session.get("latest_artifacts", [])),
            "read_only": True,
            "mutation_performed": False,
            "saved": True,
            "safety": _summary_safety(),
        }
    )
    return saved


def save_interactive_summary(
    payload: dict[str, Any], data_dir: Path, *, source: str = "interactive /summary --save"
) -> dict[str, Any]:
    summary_id = f"interactive_summary_{_now_stamp()}_{uuid.uuid4().hex[:6]}"
    out = data_dir / "interactive_summaries" / summary_id
    out.mkdir(parents=True, exist_ok=False)
    saved = _saved_payload(payload, summary_id, out)
    files = ["interactive-summary.json", "interactive-summary.md"]
    (out / "interactive-summary.json").write_text(
        json.dumps(saved, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "interactive-summary.md").write_text(_summary_markdown(saved), encoding="utf-8")
    checksums = {rel: _sha256_file(out / rel) for rel in files}
    manifest = {
        "schema_version": "1",
        "kind": "interactive_session_summary",
        "mode": "interactive_session_summary_artifact",
        "summary_id": summary_id,
        "created_at": _now_utc(),
        "source": source,
        "files": [*files, "manifest.json"],
        "checksums": checksums,
        "safety": _summary_safety(),
        "session": {
            "session_id": saved.get("session_id"),
            "events_seen": saved.get("events_seen", 0),
            "latest_session_id": (saved.get("session") or {}).get("latest_session_id"),
        },
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksums["manifest.json"] = _sha256_file(out / "manifest.json")
    return {
        "schema_version": "1",
        "mode": "interactive_summary_save",
        "status": "saved",
        "saved": True,
        "summary_id": summary_id,
        "summary_path": str(out),
        "files": [*files, "manifest.json"],
        "checksums": checksums,
        "manifest": manifest,
        "safety": _summary_safety(),
        "next_safe_commands": [
            f"shellforgeai session summary validate {summary_id}",
            f"shellforgeai session summary export {summary_id}",
        ],
    }


def validate_interactive_summary(summary_ref: str, data_dir: Path) -> dict[str, Any]:
    root = data_dir / "interactive_summaries"
    d = _resolve_ref(summary_ref, root)
    checks = {
        "required_files": False,
        "json_parse": False,
        "schema": False,
        "manifest": False,
        "checksums": False,
        "safety": False,
        "secrets": False,
        "no_mutation_recorded": False,
    }
    if d is None:
        return {
            "schema_version": "1",
            "mode": "interactive_summary_validate",
            "status": "failed",
            "checks": checks,
            "warnings": ["unsafe summary reference"],
        }
    if not d.exists():
        return {
            "schema_version": "1",
            "mode": "interactive_summary_validate",
            "status": "not_found",
            "summary": {"id": d.name, "path": str(d)},
            "checks": checks,
            "warnings": ["summary not found"],
        }
    if any(not (d / rel).exists() for rel in REQUIRED_SUMMARY_FILES):
        return {
            "schema_version": "1",
            "mode": "interactive_summary_validate",
            "status": "failed",
            "summary": {"id": d.name, "path": str(d)},
            "checks": checks,
            "warnings": ["missing required files"],
        }
    checks["required_files"] = True
    try:
        summary = json.loads((d / "interactive-summary.json").read_text(encoding="utf-8"))
        manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    except Exception:
        return {
            "schema_version": "1",
            "mode": "interactive_summary_validate",
            "status": "failed",
            "summary": {"id": d.name, "path": str(d)},
            "checks": checks,
            "warnings": ["malformed json"],
        }
    checks["json_parse"] = True
    checks["schema"] = (
        bool(summary.get("schema_version")) and summary.get("mode") == "interactive_session_summary"
    )
    checks["manifest"] = (
        bool(manifest.get("schema_version"))
        and manifest.get("kind") == "interactive_session_summary"
        and manifest.get("summary_id") == summary.get("summary_id")
    )
    checks["checksums"] = True
    for rel, expected in (manifest.get("checksums") or {}).items():
        if not (d / rel).exists() or _sha256_file(d / rel) != expected:
            checks["checksums"] = False
            break
    safety = summary.get("safety") or {}
    manifest_safety = manifest.get("safety") or {}
    checks["safety"] = _safety_non_mutating(safety) and _safety_non_mutating(manifest_safety)
    checks["secrets"] = not _has_obvious_secret(summary) and not _has_obvious_secret(manifest)
    checks["no_mutation_recorded"] = summary.get("mutation_performed") is False and all(
        safety.get(flag) is False for flag in _MUTATING_TRUE_FLAGS
    )
    status = "ok" if all(checks.values()) else "failed"
    return {
        "schema_version": "1",
        "mode": "interactive_summary_validate",
        "status": status,
        "summary": {"id": d.name, "path": str(d)},
        "checks": checks,
        "safety": safety,
        "warnings": [],
    }


def export_interactive_summary(summary_ref: str, data_dir: Path) -> dict[str, Any]:
    validation = validate_interactive_summary(summary_ref, data_dir)
    safety = _export_safety()
    if validation.get("status") == "not_found":
        return {
            "schema_version": "1",
            "mode": "interactive_summary_export",
            "status": "not_found",
            "source_summary": validation.get("summary") or {},
            "safety": safety,
            "warnings": ["summary not found"],
        }
    if validation.get("status") != "ok":
        return {
            "schema_version": "1",
            "mode": "interactive_summary_export",
            "status": "failed",
            "source_summary": validation.get("summary") or {},
            "safety": safety,
            "warnings": ["source summary validation failed"],
        }
    src = Path((validation.get("summary") or {}).get("path") or "")
    out = data_dir / "exports" / f"export_interactive_summary_{src.name}"
    if out.exists():
        export_validation = validate_interactive_summary_export(out.name, data_dir)
        if export_validation.get("status") == "ok":
            manifest = json.loads((out / "export-manifest.json").read_text(encoding="utf-8"))
            return {
                "schema_version": "1",
                "mode": "interactive_summary_export",
                "status": "exported",
                "existing": True,
                "source_summary": manifest.get("source_summary") or {},
                "export": {"id": out.name, "path": str(out), "files": manifest.get("files") or []},
                "checksums": manifest.get("checksums") or {},
                "safety": safety,
                "next_safe_commands": [f"shellforgeai session summary export-validate {out}"],
            }
        return {
            "schema_version": "1",
            "mode": "interactive_summary_export",
            "status": "already_exists",
            "source_summary": validation.get("summary") or {},
            "export": {"id": out.name, "path": str(out)},
            "safety": safety,
            "warnings": ["existing export path failed validation"],
            "next_safe_commands": [f"shellforgeai session summary export-validate {out}"],
        }
    out.mkdir(parents=True, exist_ok=False)
    for rel in REQUIRED_SUMMARY_FILES:
        shutil.copyfile(src / rel, out / rel)
    checksums = {rel: _sha256_file(out / rel) for rel in REQUIRED_SUMMARY_FILES}
    export_manifest = {
        "schema_version": "1",
        "mode": "interactive_summary_export",
        "export_id": out.name,
        "created_at": _now_utc(),
        "source_summary": {"id": src.name, "path": str(src), "validated": True},
        "files": [*REQUIRED_SUMMARY_FILES, "export-manifest.json"],
        "checksums": checksums,
        "safety": safety,
    }
    (out / "export-manifest.json").write_text(
        json.dumps(export_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksums["export-manifest.json"] = _sha256_file(out / "export-manifest.json")
    return {
        "schema_version": "1",
        "mode": "interactive_summary_export",
        "status": "exported",
        "source_summary": export_manifest["source_summary"],
        "export": {"id": out.name, "path": str(out), "files": export_manifest["files"]},
        "checksums": checksums,
        "safety": safety,
        "next_safe_commands": [f"shellforgeai session summary export-validate {out}"],
    }


def validate_interactive_summary_export(export_ref: str, data_dir: Path) -> dict[str, Any]:
    root = data_dir / "exports"
    d = _resolve_ref(export_ref, root)
    checks = {
        "required_files": False,
        "json_parse": False,
        "checksums": False,
        "source_safety": False,
        "export_safety": False,
    }
    if d is None:
        return {
            "schema_version": "1",
            "mode": "interactive_summary_export_validate",
            "status": "failed",
            "checks": checks,
            "warnings": ["unsafe export reference"],
        }
    if not d.exists():
        return {
            "schema_version": "1",
            "mode": "interactive_summary_export_validate",
            "status": "not_found",
            "export": {"id": d.name, "path": str(d)},
            "checks": checks,
            "warnings": ["export not found"],
        }
    if any(not (d / rel).exists() for rel in REQUIRED_EXPORT_FILES):
        return {
            "schema_version": "1",
            "mode": "interactive_summary_export_validate",
            "status": "failed",
            "export": {"id": d.name, "path": str(d)},
            "checks": checks,
            "warnings": ["missing required files"],
        }
    checks["required_files"] = True
    try:
        summary = json.loads((d / "interactive-summary.json").read_text(encoding="utf-8"))
        manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
        export_manifest = json.loads((d / "export-manifest.json").read_text(encoding="utf-8"))
    except Exception:
        return {
            "schema_version": "1",
            "mode": "interactive_summary_export_validate",
            "status": "failed",
            "export": {"id": d.name, "path": str(d)},
            "checks": checks,
            "warnings": ["malformed json"],
        }
    checks["json_parse"] = True
    checks["checksums"] = True
    for rel, expected in (export_manifest.get("checksums") or {}).items():
        if not (d / rel).exists() or _sha256_file(d / rel) != expected:
            checks["checksums"] = False
            break
    checks["source_safety"] = _safety_non_mutating(
        summary.get("safety") or {}
    ) and _safety_non_mutating(manifest.get("safety") or {})
    checks["export_safety"] = _safety_non_mutating(export_manifest.get("safety") or {})
    status = "ok" if all(checks.values()) else "failed"
    return {
        "schema_version": "1",
        "mode": "interactive_summary_export_validate",
        "status": status,
        "export": {"id": d.name, "path": str(d)},
        "checks": checks,
        "safety": export_manifest.get("safety") or {},
        "warnings": [],
    }
