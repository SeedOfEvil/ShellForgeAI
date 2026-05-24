from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FORBIDDEN_COMMAND_FRAGMENTS = (
    "docker restart",
    "docker compose restart",
    "remediation execute",
    "rollback-execute",
    "cleanup execute",
    "--execute --confirm",
    "diagnose docker --target",
    "diagnose logs --target",
    "diagnose disk --target",
)

REQUIRED_REPORT_FILES = ("ops-report.json", "ops-report.md", "manifest.json")
REQUIRED_EXPORT_FILES = (*REQUIRED_REPORT_FILES, "export-manifest.json")


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _safety() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "plan_created": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "cleanup_executed": False,
        "proposal_created": False,
        "mission_created": False,
        "apply_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "natural_language_execution": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
    }


def _resolve_ref(ref: str, root: Path) -> Path | None:
    p = Path(ref)
    if p.is_absolute() or "/" in ref:
        resolved = p.resolve()
    else:
        if ".." in ref or "\\" in ref:
            return None
        resolved = (root / ref).resolve()
    if not str(resolved).startswith(str(root.resolve())):
        return None
    return resolved


def save_ops_report(
    report: dict[str, Any], data_dir: Path, *, source_command: str
) -> dict[str, Any]:
    rid = f"ops_report_{_now_stamp()}_{uuid.uuid4().hex[:6]}"
    d = data_dir / "ops_reports" / rid
    d.mkdir(parents=True, exist_ok=False)
    report_json = d / "ops-report.json"
    report_md = d / "ops-report.md"
    report_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = ["ShellForgeAI 2AM Operator Report", "", "Safety:"]
    for k, v in (report.get("safety") or {}).items():
        lines.append(f"- {k}: {str(v).lower()}")
    report_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    files = ["ops-report.json", "ops-report.md"]
    checksums = {f: _sha256_file(d / f) for f in files}
    manifest = {
        "schema_version": "1",
        "artifact_id": rid,
        "kind": "ops_report",
        "created_at": _now_utc(),
        "source_command": source_command,
        "files": [*files, "manifest.json"],
        "checksums": checksums,
        "safety": _safety(),
        "report": {
            "schema_version": report.get("schema_version"),
            "mode": report.get("mode"),
            "status": report.get("status"),
        },
    }
    (d / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    checksums["manifest.json"] = _sha256_file(d / "manifest.json")
    return {
        "schema_version": "1",
        "mode": "ops_report_save",
        "status": "saved",
        "report_id": rid,
        "report_path": str(d),
        "files": [*files, "manifest.json"],
        "manifest": manifest,
        "checksums": checksums,
        "safety": _safety(),
        "next_safe_commands": [
            f"shellforgeai ops report validate {rid}",
            f"shellforgeai ops report export {rid}",
        ],
    }


def validate_ops_report(report_ref: str, data_dir: Path) -> dict[str, Any]:
    root = data_dir / "ops_reports"
    d = _resolve_ref(report_ref, root)
    checks = {
        "required_files": False,
        "json_parse": False,
        "schema": False,
        "manifest": False,
        "checksums": False,
        "safety": False,
        "safe_commands": False,
    }
    if d is None:
        return {
            "schema_version": "1",
            "mode": "ops_report_validate",
            "status": "error",
            "checks": checks,
            "warnings": ["unsafe report reference"],
        }
    if not d.exists():
        return {
            "schema_version": "1",
            "mode": "ops_report_validate",
            "status": "not_found",
            "report": {"id": d.name, "path": str(d)},
            "checks": checks,
            "warnings": ["report not found"],
        }
    if any(not (d / f).exists() for f in REQUIRED_REPORT_FILES):
        return {
            "schema_version": "1",
            "mode": "ops_report_validate",
            "status": "failed",
            "report": {"id": d.name, "path": str(d)},
            "checks": checks,
            "warnings": ["missing required files"],
        }
    checks["required_files"] = True
    try:
        report = json.loads((d / "ops-report.json").read_text(encoding="utf-8"))
        manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    except Exception:
        return {
            "schema_version": "1",
            "mode": "ops_report_validate",
            "status": "error",
            "report": {"id": d.name, "path": str(d)},
            "checks": checks,
            "warnings": ["malformed json"],
        }
    checks["json_parse"] = True
    checks["schema"] = bool(report.get("schema_version")) and report.get("mode") == "ops_report"
    checks["manifest"] = manifest.get("kind") == "ops_report"
    checks["checksums"] = True
    for rel, expected in (manifest.get("checksums") or {}).items():
        if not (d / rel).exists() or _sha256_file(d / rel) != expected:
            checks["checksums"] = False
            break
    s = report.get("safety") or {}
    checks["safety"] = all((k in s and s.get(k) is v) for k, v in _safety().items())
    cmds = [str(c).lower() for c in (report.get("safe_next_commands") or [])]
    checks["safe_commands"] = not any(
        any(b in c for b in FORBIDDEN_COMMAND_FRAGMENTS) for c in cmds
    )
    status = "ok" if all(checks.values()) else "failed"
    return {
        "schema_version": "1",
        "mode": "ops_report_validate",
        "status": status,
        "report": {"id": d.name, "path": str(d)},
        "checks": checks,
        "safety": s,
        "warnings": [],
    }


def export_ops_report(report_ref: str, data_dir: Path) -> dict[str, Any]:
    v = validate_ops_report(report_ref, data_dir)
    safety = {**_safety(), "artifact_export_only": True, "arbitrary_path_write": False}
    if v.get("status") == "not_found":
        return {
            "schema_version": "1",
            "mode": "ops_report_export",
            "status": "not_found",
            "source_report": v.get("report") or {},
            "safety": safety,
        }
    if v.get("status") != "ok":
        return {
            "schema_version": "1",
            "mode": "ops_report_export",
            "status": "failed",
            "source_report": v.get("report") or {},
            "safety": safety,
            "warnings": ["source report validation failed"],
        }
    src = Path((v.get("report") or {}).get("path") or "")
    out = data_dir / "exports" / f"export_{src.name}"
    if out.exists():
        vv = validate_ops_report_export(out.name, data_dir)
        if vv.get("status") == "ok":
            manifest = json.loads((out / "export-manifest.json").read_text(encoding="utf-8"))
            return {
                "schema_version": "1",
                "mode": "ops_report_export",
                "status": "exported",
                "existing": True,
                "source_report": (manifest.get("source_report") or {}),
                "export": {
                    "id": out.name,
                    "path": str(out),
                    "files": list(manifest.get("files") or []),
                },
                "checksums": dict(manifest.get("checksums") or {}),
                "safety": safety,
                "next_safe_commands": [f"shellforgeai ops report export-validate {out}"],
            }
        return {
            "schema_version": "1",
            "mode": "ops_report_export",
            "status": "already_exists",
            "source_report": v.get("report") or {},
            "export": {"id": out.name, "path": str(out)},
            "safety": safety,
            "warnings": ["existing export path failed validation"],
            "next_safe_commands": [f"shellforgeai ops report export-validate {out}"],
        }
    out.mkdir(parents=True, exist_ok=False)
    files = list(REQUIRED_REPORT_FILES)
    for f in files:
        (out / f).write_bytes((src / f).read_bytes())
    checksums = {f: _sha256_file(out / f) for f in files}
    export_manifest = {
        "schema_version": "1",
        "mode": "ops_report_export",
        "export_id": out.name,
        "source_report": {"id": src.name, "path": str(src), "validated": True},
        "files": [*files, "export-manifest.json"],
        "checksums": checksums,
        "safety": safety,
    }
    (out / "export-manifest.json").write_text(
        json.dumps(export_manifest, indent=2) + "\n", encoding="utf-8"
    )
    checksums["export-manifest.json"] = _sha256_file(out / "export-manifest.json")
    return {
        "schema_version": "1",
        "mode": "ops_report_export",
        "status": "exported",
        "source_report": export_manifest["source_report"],
        "export": {"id": out.name, "path": str(out), "files": export_manifest["files"]},
        "checksums": checksums,
        "safety": safety,
        "next_safe_commands": [f"shellforgeai ops report export-validate {out}"],
    }


def validate_ops_report_export(export_ref: str, data_dir: Path) -> dict[str, Any]:
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
            "mode": "ops_report_export_validate",
            "status": "error",
            "checks": checks,
            "warnings": ["unsafe export reference"],
        }
    if not d.exists():
        return {
            "schema_version": "1",
            "mode": "ops_report_export_validate",
            "status": "not_found",
            "export": {"id": d.name, "path": str(d)},
            "checks": checks,
            "warnings": ["export not found"],
        }
    if any(not (d / f).exists() for f in REQUIRED_EXPORT_FILES):
        return {
            "schema_version": "1",
            "mode": "ops_report_export_validate",
            "status": "failed",
            "export": {"id": d.name, "path": str(d)},
            "checks": checks,
            "warnings": ["missing required files"],
        }
    checks["required_files"] = True
    try:
        report = json.loads((d / "ops-report.json").read_text(encoding="utf-8"))
        exp = json.loads((d / "export-manifest.json").read_text(encoding="utf-8"))
    except Exception:
        return {
            "schema_version": "1",
            "mode": "ops_report_export_validate",
            "status": "error",
            "export": {"id": d.name, "path": str(d)},
            "checks": checks,
            "warnings": ["malformed json"],
        }
    checks["json_parse"] = True
    checks["checksums"] = True
    for rel, expected in (exp.get("checksums") or {}).items():
        if not (d / rel).exists() or _sha256_file(d / rel) != expected:
            checks["checksums"] = False
            break
    base = _safety()
    rs = report.get("safety") or {}
    es = exp.get("safety") or {}
    checks["source_safety"] = all((k in rs and rs.get(k) is v) for k, v in base.items())
    checks["export_safety"] = all((k in es and es.get(k) is v) for k, v in base.items())
    status = "ok" if all(checks.values()) else "failed"
    return {
        "schema_version": "1",
        "mode": "ops_report_export_validate",
        "status": status,
        "export": {"id": d.name, "path": str(d)},
        "checks": checks,
        "warnings": [],
    }
