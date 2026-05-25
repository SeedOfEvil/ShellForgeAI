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
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


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


def _resolve_report_payload(report_ref: str, data_dir: Path) -> tuple[dict[str, Any], Path | None]:
    root = data_dir / "ops_reports"
    d = _resolve_ref(report_ref, root)
    if d is None:
        return {"status": "error"}, None
    if not d.exists():
        return {"status": "not_found"}, None
    if any(not (d / f).exists() for f in REQUIRED_REPORT_FILES):
        return {"status": "failed"}, None
    try:
        report = json.loads((d / "ops-report.json").read_text(encoding="utf-8"))
    except Exception:
        return {"status": "error"}, None
    if report.get("mode") != "ops_report":
        return {"status": "failed"}, None
    return report, d


def _resolve_export_payload(export_ref: str, data_dir: Path) -> tuple[dict[str, Any], Path | None]:
    v = validate_ops_report_export(export_ref, data_dir)
    if v.get("status") != "ok":
        return v, None
    export_path = Path((v.get("export") or {}).get("path") or "")
    report = json.loads((export_path / "ops-report.json").read_text(encoding="utf-8"))
    return report, export_path


def _suspect_index(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for suspect in report.get("suspects") or []:
        name = (suspect.get("name") or "").strip()
        if name:
            out[name] = suspect
    return out


def _safe_next_commands(target: str) -> list[str]:
    return [
        "shellforgeai ops report --json",
        f"shellforgeai ops report validate {target}",
        f"shellforgeai triage docker detail {target}",
        f"shellforgeai remediation eligibility --target {target} --explain",
        "shellforgeai remediation self-test --profile standard --json",
        "shellforgeai remediation audit --latest --json",
    ]


def _safe_history_next_commands() -> list[str]:
    return [
        "shellforgeai ops report --save",
        "shellforgeai ops report history",
        "shellforgeai ops report history --json",
        "shellforgeai ops report compare-latest",
        "shellforgeai ops report compare-latest --json",
        "shellforgeai ops report validate <report_id> --json",
        "shellforgeai ops report export <report_id> --json",
        "shellforgeai triage docker detail <target>",
        "shellforgeai remediation eligibility --target <target> --explain",
    ]


def ops_report_history(
    data_dir: Path, *, limit: int = 10, include_drift: bool = False
) -> dict[str, Any]:
    root = data_dir / "ops_reports"
    warnings: list[str] = []
    entries: list[dict[str, Any]] = []
    if root.exists():
        for child in root.iterdir():
            if not child.is_dir() or not child.name.startswith("ops_report_"):
                continue
            report_json = child / "ops-report.json"
            if not report_json.exists():
                warnings.append(
                    f"invalid report artifact ignored: {child.name} (missing ops-report.json)"
                )
                continue
            try:
                report = json.loads(report_json.read_text(encoding="utf-8"))
            except Exception:
                warnings.append(f"invalid report artifact ignored: {child.name} (malformed json)")
                continue
            if report.get("mode") != "ops_report":
                warnings.append(f"invalid report artifact ignored: {child.name} (unexpected mode)")
                continue
            suspects = report.get("suspects") or []
            summary = report.get("summary") or {}
            entries.append(
                {
                    "report_id": child.name,
                    "created_at": report.get("generated_at"),
                    "path": str(child),
                    "valid": True,
                    "suspects_ranked": summary.get("suspects_ranked", len(suspects)),
                    "critical": summary.get("critical", 0),
                    "high": summary.get("high", 0),
                    "top_suspect": (suspects[0].get("name") if suspects else None),
                }
            )
    entries.sort(key=lambda r: str(r.get("report_id") or ""), reverse=True)
    limited = entries[: max(1, limit)]
    latest_drift: dict[str, Any] = {}
    if include_drift and len(entries) >= 2:
        drift = compare_ops_reports(entries[1]["report_id"], entries[0]["report_id"], data_dir)
        latest_drift = {
            "status": drift.get("status"),
            "before_report_id": entries[1]["report_id"],
            "after_report_id": entries[0]["report_id"],
            "summary": drift.get("summary") or {},
            "warnings": drift.get("warnings") or [],
            "safe_next_commands": ["shellforgeai ops report compare-latest --json"],
        }
    payload = {
        "schema_version": "1",
        "mode": "ops_report_history",
        "status": "ok" if entries else "empty",
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "reports_found": len(entries),
            "valid_reports": len(entries),
            "invalid_reports": len(warnings),
            "limit": max(1, limit),
            "latest_report_id": (entries[0]["report_id"] if entries else None),
            "previous_report_id": (entries[1]["report_id"] if len(entries) > 1 else None),
        },
        "reports": limited,
        "latest_drift": latest_drift,
        "safe_next_commands": _safe_history_next_commands(),
        "warnings": warnings,
        "safety": _safety(),
    }
    return payload


def compare_latest_ops_reports(
    data_dir: Path, *, only_changed: bool = False, include_stable: bool = False
) -> dict[str, Any]:
    hist = ops_report_history(data_dir, limit=50, include_drift=False)
    reports = hist.get("reports") or []
    if len(reports) < 2:
        return {
            "schema_version": "1",
            "mode": "ops_report_compare_latest",
            "status": "not_enough_reports",
            "read_only": True,
            "mutation_performed": False,
            "summary": {"valid_reports": len(reports), "required_reports": 2},
            "warnings": ["at least two valid saved ops reports are required"],
            "safe_next_commands": [
                "shellforgeai ops report --save",
                "shellforgeai ops report history",
            ],
            "safety": _safety(),
        }
    before = reports[1]["report_id"]
    after = reports[0]["report_id"]
    out = compare_ops_reports(
        before, after, data_dir, only_changed=only_changed, include_stable=include_stable
    )
    out["latest"] = True
    out["before_report_id"] = before
    out["after_report_id"] = after
    out["before_path"] = reports[1]["path"]
    out["after_path"] = reports[0]["path"]
    return out


def compare_ops_reports(
    before_ref: str,
    after_ref: str,
    data_dir: Path,
    *,
    only_changed: bool = False,
    include_stable: bool = False,
) -> dict[str, Any]:
    before, before_path = _resolve_report_payload(before_ref, data_dir)
    if before_path is None:
        return {
            "schema_version": "1",
            "mode": "ops_report_compare",
            "status": before.get("status"),
            "warnings": ["before report validation failed"],
            "safety": _safety(),
            "read_only": True,
            "mutation_performed": False,
        }
    after, after_path = _resolve_report_payload(after_ref, data_dir)
    if after_path is None:
        return {
            "schema_version": "1",
            "mode": "ops_report_compare",
            "status": after.get("status"),
            "warnings": ["after report validation failed"],
            "safety": _safety(),
            "read_only": True,
            "mutation_performed": False,
        }
    return _compare_payload(
        before,
        after,
        before_path.name,
        str(before_path),
        after_path.name,
        str(after_path),
        only_changed=only_changed,
        include_stable=include_stable,
    )


def compare_ops_report_exports(
    before_ref: str,
    after_ref: str,
    data_dir: Path,
    *,
    only_changed: bool = False,
    include_stable: bool = False,
) -> dict[str, Any]:
    before, before_path = _resolve_export_payload(before_ref, data_dir)
    if before_path is None:
        return {
            "schema_version": "1",
            "mode": "ops_report_compare",
            "status": before.get("status"),
            "warnings": ["before export validation failed"],
            "safety": _safety(),
            "read_only": True,
            "mutation_performed": False,
        }
    after, after_path = _resolve_export_payload(after_ref, data_dir)
    if after_path is None:
        return {
            "schema_version": "1",
            "mode": "ops_report_compare",
            "status": after.get("status"),
            "warnings": ["after export validation failed"],
            "safety": _safety(),
            "read_only": True,
            "mutation_performed": False,
        }
    return _compare_payload(
        before,
        after,
        before_path.name,
        str(before_path),
        after_path.name,
        str(after_path),
        only_changed=only_changed,
        include_stable=include_stable,
    )


def _compare_payload(
    before: dict[str, Any],
    after: dict[str, Any],
    before_id: str,
    before_path: str,
    after_id: str,
    after_path: str,
    *,
    only_changed: bool,
    include_stable: bool,
) -> dict[str, Any]:
    bidx = _suspect_index(before)
    aidx = _suspect_index(after)
    names = sorted(set(bidx) | set(aidx))
    escalations = []
    improvements = []
    rank_changes = []
    confidence_changes = []
    class_changes = []
    stable = []
    new_suspects = []
    missing = []
    warnings = []
    for name in names:
        b = bidx.get(name)
        a = aidx.get(name)
        if b is None:
            new_suspects.append(name)
            continue
        if a is None:
            missing.append(name)
            continue
        bs, as_ = str(b.get("severity", "")), str(a.get("severity", ""))
        entry = {
            "name": name,
            "before_rank": b.get("rank"),
            "after_rank": a.get("rank"),
            "before_severity": bs,
            "after_severity": as_,
            "before_confidence": b.get("confidence"),
            "after_confidence": a.get("confidence"),
            "before_classes": b.get("classes") or [],
            "after_classes": a.get("classes") or [],
            "change_summary": [],
            "suggested_read_only_command": f"shellforgeai triage docker detail {name}",
        }
        changed = False
        if SEVERITY_ORDER.get(as_, 0) > SEVERITY_ORDER.get(bs, 0):
            escalations.append(entry)
            changed = True
        elif SEVERITY_ORDER.get(as_, 0) < SEVERITY_ORDER.get(bs, 0):
            improvements.append(entry)
            changed = True
        if b.get("rank") != a.get("rank"):
            rank_changes.append(entry)
            changed = True
        if b.get("confidence") != a.get("confidence"):
            confidence_changes.append(entry)
            changed = True
        if sorted(entry["before_classes"]) != sorted(entry["after_classes"]):
            class_changes.append(entry)
            changed = True
        if not changed:
            stable.append(name)
    bsafety = before.get("safety") or {}
    asafety = after.get("safety") or {}
    for k, v in _safety().items():
        if v is False and bsafety.get(k) is False and asafety.get(k) is True:
            warnings.append(f"critical safety drift: {k} changed false->true")
    suspect_target = (
        escalations or rank_changes or confidence_changes or class_changes or improvements
    )
    target_name = (
        suspect_target[0].get("name") if suspect_target else (names[0] if names else "target")
    )
    payload = {
        "schema_version": "1",
        "mode": "ops_report_compare",
        "status": "ok",
        "read_only": True,
        "mutation_performed": False,
        "reports": {
            "before": {"id": before_id, "path": before_path},
            "after": {"id": after_id, "path": after_path},
        },
        "summary": {
            "suspects_before": len(bidx),
            "suspects_after": len(aidx),
            "new": len(new_suspects),
            "resolved_or_missing": len(missing),
            "escalated": len(escalations),
            "improved": len(improvements),
            "rank_changed": len(rank_changes),
            "stable": len(stable),
            "remediation_lane_before": (before.get("remediation_lane") or {}).get("status"),
            "remediation_lane_after": (after.get("remediation_lane") or {}).get("status"),
        },
        "new_suspects": new_suspects,
        "resolved_or_missing_suspects": missing,
        "severity_escalations": escalations,
        "severity_improvements": improvements,
        "rank_changes": rank_changes,
        "confidence_changes": confidence_changes,
        "class_changes": class_changes,
        "stable_suspects": [] if only_changed else stable,
        "remediation_lane": {
            "changed": (
                (before.get("remediation_lane") or {}).get("status")
                != (after.get("remediation_lane") or {}).get("status")
            ),
            "before": (before.get("remediation_lane") or {}).get("status"),
            "after": (after.get("remediation_lane") or {}).get("status"),
            "notes": [],
        },
        "safety": _safety(),
        "safe_next_commands": _safe_next_commands(target_name),
        "warnings": warnings,
    }
    if include_stable and only_changed is False:
        payload["stable_suspects"] = stable
    return payload
