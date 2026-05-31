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


def _read_only_workflow_safety() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "summary_saved": False,
        "artifact_export_only": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "production_restart_executed": False,
        "natural_language_execution": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
    }


def _summary_root(data_dir: Path) -> Path:
    return data_dir / "interactive_summaries"


def _load_summary_artifact(summary_ref: str, data_dir: Path) -> tuple[dict[str, Any], Path | None]:
    root = _summary_root(data_dir)
    d = _resolve_ref(summary_ref, root)
    safety = _read_only_workflow_safety()
    if d is None:
        return (
            {
                "schema_version": "1",
                "mode": "interactive_summary_load",
                "status": "failed",
                "read_only": True,
                "mutation_performed": False,
                "warnings": ["unsafe summary reference"],
                "safety": safety,
            },
            None,
        )
    validation = validate_interactive_summary(str(d), data_dir)
    if validation.get("status") != "ok":
        return (
            {
                "schema_version": "1",
                "mode": "interactive_summary_load",
                "status": validation.get("status") or "failed",
                "summary": validation.get("summary") or {"id": d.name, "path": str(d)},
                "read_only": True,
                "mutation_performed": False,
                "warnings": validation.get("warnings") or ["summary validation failed"],
                "safety": safety,
            },
            None,
        )
    try:
        payload = json.loads((d / "interactive-summary.json").read_text(encoding="utf-8"))
    except Exception:
        return (
            {
                "schema_version": "1",
                "mode": "interactive_summary_load",
                "status": "failed",
                "summary": {"id": d.name, "path": str(d)},
                "read_only": True,
                "mutation_performed": False,
                "warnings": ["malformed summary json"],
                "safety": safety,
            },
            None,
        )
    return payload, d


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _stable_repr(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, default=str)
    return str(value)


def _list_diff(before: Any, after: Any) -> tuple[list[Any], list[Any], list[Any]]:
    before_items = _as_list(before)
    after_items = _as_list(after)
    before_keys = {_stable_repr(item): item for item in before_items}
    after_keys = {_stable_repr(item): item for item in after_items}
    new = [after_keys[k] for k in sorted(after_keys.keys() - before_keys.keys())]
    missing = [before_keys[k] for k in sorted(before_keys.keys() - after_keys.keys())]
    stable = [after_keys[k] for k in sorted(after_keys.keys() & before_keys.keys())]
    return new, missing, stable


def _created_at(payload: dict[str, Any], artifact_dir: Path) -> str | None:
    for key in ("created_at", "generated_at", "timestamp"):
        if payload.get(key):
            return str(payload[key])
    manifest_path = artifact_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return manifest.get("created_at")


def _summary_entry(payload: dict[str, Any], artifact_dir: Path) -> dict[str, Any]:
    checks = _as_list(payload.get("checks"))
    findings = _as_list(payload.get("findings"))
    refusals = _as_list(payload.get("refusals"))
    first_safe = payload.get("first_safe_command")
    safe_commands = _as_list(payload.get("safe_next_commands") or payload.get("next_safe_commands"))
    if not first_safe and safe_commands:
        first_safe = str(safe_commands[0])
    return {
        "summary_id": payload.get("summary_id") or artifact_dir.name,
        "session_id": payload.get("session_id"),
        "created_at": _created_at(payload, artifact_dir),
        "events_seen": payload.get("events_seen", 0),
        "checks_count": len(checks),
        "findings_count": len(findings),
        "refusals_count": len(refusals),
        "first_safe_command": first_safe,
        "path": str(artifact_dir),
        "artifact_references": _as_list(payload.get("latest_artifacts")),
        "safety": payload.get("safety") or {},
        "valid": True,
    }


def interactive_summary_history(data_dir: Path, *, limit: int = 10) -> dict[str, Any]:
    root = _summary_root(data_dir)
    warnings: list[str] = []
    entries: list[dict[str, Any]] = []
    if root.exists():
        for child in root.iterdir():
            if not child.is_dir() or not child.name.startswith("interactive_summary_"):
                continue
            payload, path = _load_summary_artifact(child.name, data_dir)
            if path is None:
                warning = "; ".join(payload.get("warnings") or ["validation failed"])
                warnings.append(f"invalid summary artifact ignored: {child.name} ({warning})")
                continue
            entries.append(_summary_entry(payload, path))
    entries.sort(
        key=lambda item: str(item.get("created_at") or item.get("summary_id") or ""), reverse=True
    )
    effective_limit = max(1, limit)
    limited = entries[:effective_limit]
    return {
        "schema_version": "1",
        "mode": "interactive_summary_history",
        "status": "ok" if entries else "empty",
        "read_only": True,
        "mutation_performed": False,
        "summaries": limited,
        "latest_summary_id": entries[0]["summary_id"] if entries else None,
        "count": len(entries),
        "limit": effective_limit,
        "warnings": warnings,
        "safe_next_commands": [
            "shellforgeai interactive",
            "/summary --save",
            "shellforgeai session summary history --limit 5",
            "shellforgeai session summary compare-latest",
        ],
        "safety": _read_only_workflow_safety(),
    }


def compare_latest_interactive_summaries(
    data_dir: Path, *, only_changed: bool = False, include_stable: bool = False
) -> dict[str, Any]:
    hist = interactive_summary_history(data_dir, limit=50)
    summaries = hist.get("summaries") or []
    if len(summaries) < 2:
        return {
            "schema_version": "1",
            "mode": "interactive_summary_compare",
            "compare_latest": True,
            "status": "empty" if not summaries else "not_enough_data",
            "read_only": True,
            "mutation_performed": False,
            "summary": {"summaries_found": len(summaries), "required_summaries": 2},
            "changes": [],
            "warnings": ["at least two saved interactive summaries are required"],
            "safe_next_commands": ["shellforgeai interactive", "/summary --save"],
            "safety": _read_only_workflow_safety(),
        }
    before = summaries[1]["summary_id"]
    after = summaries[0]["summary_id"]
    payload = compare_interactive_summaries(
        before, after, data_dir, only_changed=only_changed, include_stable=include_stable
    )
    payload["compare_latest"] = True
    return payload


def compare_interactive_summaries(
    before_ref: str,
    after_ref: str,
    data_dir: Path,
    *,
    only_changed: bool = False,
    include_stable: bool = False,
) -> dict[str, Any]:
    before, before_path = _load_summary_artifact(before_ref, data_dir)
    if before_path is None:
        return {
            "schema_version": "1",
            "mode": "interactive_summary_compare",
            "status": before.get("status") or "failed",
            "read_only": True,
            "mutation_performed": False,
            "before_summary_id": before_ref,
            "after_summary_id": after_ref,
            "changes": [],
            "warnings": ["before summary validation failed", *(before.get("warnings") or [])],
            "safety": _read_only_workflow_safety(),
        }
    after, after_path = _load_summary_artifact(after_ref, data_dir)
    if after_path is None:
        return {
            "schema_version": "1",
            "mode": "interactive_summary_compare",
            "status": after.get("status") or "failed",
            "read_only": True,
            "mutation_performed": False,
            "before_summary_id": before.get("summary_id") or before_path.name,
            "after_summary_id": after_ref,
            "changes": [],
            "warnings": ["after summary validation failed", *(after.get("warnings") or [])],
            "safety": _read_only_workflow_safety(),
        }
    return _compare_interactive_summary_payload(
        before,
        after,
        before_path,
        after_path,
        only_changed=only_changed,
        include_stable=include_stable,
    )


def _safe_commands(payload: dict[str, Any]) -> list[Any]:
    commands = []
    if payload.get("first_safe_command"):
        commands.append(payload.get("first_safe_command"))
    commands.extend(
        _as_list(payload.get("safe_next_commands") or payload.get("next_safe_commands"))
    )
    seen: set[str] = set()
    out = []
    for command in commands:
        key = _stable_repr(command)
        if key not in seen:
            seen.add(key)
            out.append(command)
    return out


def _safety_drift(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    b = before.get("safety") or {}
    a = after.get("safety") or {}
    drift = []
    for key in sorted(set(b) | set(a) | set(_read_only_workflow_safety())):
        if b.get(key) != a.get(key):
            drift.append({"flag": key, "before": b.get(key), "after": a.get(key)})
    return drift


def _compare_interactive_summary_payload(
    before: dict[str, Any],
    after: dict[str, Any],
    before_path: Path,
    after_path: Path,
    *,
    only_changed: bool,
    include_stable: bool,
) -> dict[str, Any]:
    changes: list[dict[str, Any]] = []
    stable: dict[str, Any] = {}
    fields = {
        "checks": (before.get("checks"), after.get("checks")),
        "findings": (before.get("findings"), after.get("findings")),
        "refusals": (before.get("refusals"), after.get("refusals")),
        "safe_next_commands": (_safe_commands(before), _safe_commands(after)),
        "artifact_references": (before.get("latest_artifacts"), after.get("latest_artifacts")),
    }
    diff: dict[str, dict[str, list[Any]]] = {}
    for field, (bval, aval) in fields.items():
        new, missing, same = _list_diff(bval, aval)
        diff[field] = {"new": new, "resolved_or_missing": missing, "stable": same}
        if new or missing:
            changes.append({"field": field, "new": new, "resolved_or_missing": missing})
        if same and include_stable and not only_changed:
            stable[field] = same
    scalar_fields = ("events_seen", "session_id", "summary_id")
    for field in scalar_fields:
        if before.get(field) != after.get(field):
            changes.append({"field": field, "before": before.get(field), "after": after.get(field)})
        elif include_stable and not only_changed:
            stable[field] = after.get(field)
    b_visibility = (before.get("runtime_context") or before.get("runtime") or {}).get("visibility")
    a_visibility = (after.get("runtime_context") or after.get("runtime") or {}).get("visibility")
    if b_visibility != a_visibility:
        changes.append(
            {"field": "runtime_context.visibility", "before": b_visibility, "after": a_visibility}
        )
    elif include_stable and not only_changed:
        stable["runtime_context.visibility"] = a_visibility
    drift = _safety_drift(before, after)
    if drift:
        changes.append({"field": "safety", "drift": drift})
    elif include_stable and not only_changed:
        stable["safety"] = "unchanged"
    first_safe = after.get("first_safe_command") or (
        _safe_commands(after)[0] if _safe_commands(after) else None
    )
    return {
        "schema_version": "1",
        "mode": "interactive_summary_compare",
        "status": "ok",
        "read_only": True,
        "mutation_performed": False,
        "before_summary_id": before.get("summary_id") or before_path.name,
        "after_summary_id": after.get("summary_id") or after_path.name,
        "summaries": {
            "before": {
                "id": before.get("summary_id") or before_path.name,
                "path": str(before_path),
            },
            "after": {"id": after.get("summary_id") or after_path.name, "path": str(after_path)},
        },
        "summary": {
            "events_before": before.get("events_seen", 0),
            "events_after": after.get("events_seen", 0),
            "checks_before": len(_as_list(before.get("checks"))),
            "checks_after": len(_as_list(after.get("checks"))),
            "findings_before": len(_as_list(before.get("findings"))),
            "findings_after": len(_as_list(after.get("findings"))),
            "new_findings": len(diff["findings"]["new"]),
            "resolved_or_missing_findings": len(diff["findings"]["resolved_or_missing"]),
            "new_refusals": len(diff["refusals"]["new"]),
            "safety_drift": len(drift),
            "stable": sum(len(v) if isinstance(v, list) else 1 for v in stable.values()),
        },
        "changes": changes,
        "new_checks": diff["checks"]["new"],
        "resolved_or_missing_checks": diff["checks"]["resolved_or_missing"],
        "new_findings": diff["findings"]["new"],
        "resolved_or_missing_findings": diff["findings"]["resolved_or_missing"],
        "new_refusals": diff["refusals"]["new"],
        "new_safe_next_commands": diff["safe_next_commands"]["new"],
        "artifact_reference_changes": {
            "new": diff["artifact_references"]["new"],
            "resolved_or_missing": diff["artifact_references"]["resolved_or_missing"],
        },
        "safety_drift": drift,
        "stable": {} if only_changed else stable,
        "first_safe_command": first_safe,
        "safe_next_commands": [first_safe or "shellforgeai session summary history --limit 5"],
        "warnings": [],
        "safety": _read_only_workflow_safety(),
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
