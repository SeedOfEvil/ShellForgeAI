"""PR54: mission post-execution export pack (read/copy/checksum only).

Bundles the full operator story of a guided restart mission into a portable
mission export directory under
``<data_dir>/mission_exports/export_<timestamp>_<shortid>/``.

This module never executes mutation. It only:
- reads existing ShellForgeAI artifacts (mission/proposal/rollback/receipt
  /inspect/audit/source-evidence),
- writes new files into an export directory it owns,
- writes checksums.sha256, an export-manifest.json, and an export-summary.md,
- optionally redacts text-like copies via the existing redactor.

Validation re-reads an export directory and checks manifest, included files,
checksums, redaction-report, and the safety invariant that the export itself
did not execute anything.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from shellforgeai.core.approvals import find_proposal_path
from shellforgeai.core.export_pack import (
    TEXT_EXTENSIONS,
    redact_text_with_report,
)
from shellforgeai.core.mission import (
    mission_dir as _mission_dir,
)
from shellforgeai.core.mission import (
    refresh_mission,
)
from shellforgeai.core.mission_report import (
    build_mission_report,
    collect_mission_audit_events,
    write_mission_report_files,
)
from shellforgeai.version import get_build_info

EXPORT_SCHEMA_VERSION = "1"
SOURCE_TYPE = "mission_restart"
SAFETY_NOTE = "ShellForgeAI exported this mission pack but did not execute any remediation."
REDACTION_WARNING = (
    "This mission export was generated with best-effort redaction, "
    "but operators should still review before sharing."
)
RAW_EVIDENCE_WARNING = (
    "Raw mission evidence files may contain environment/config details. Review before sharing."
)


@dataclass
class MissionExportResult:
    export_id: str
    export_dir: Path
    manifest_path: Path
    summary_path: Path
    checksums_path: Path
    mission_id: str
    proposal_id: str = ""
    session_id: str = ""
    included_files: list[str] = field(default_factory=list)
    missing_optional: list[str] = field(default_factory=list)
    redaction_applied: bool = False


@dataclass
class _RedactionFileResult:
    path: str
    redacted: bool
    replacements: int
    matched_kinds: list[str]


# ---------------------------------------------------------------------------
# IDs / paths


def mission_exports_root(data_dir: Path) -> Path:
    return Path(data_dir) / "mission_exports"


def make_mission_export_id() -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    return f"mission_export_{stamp}_{uuid4().hex[:6]}"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Copy helpers (with optional redaction)


def _copy_with_optional_redact(
    src: Path,
    dst: Path,
    *,
    redact: bool,
    report_files: list[_RedactionFileResult],
    warnings: list[str],
) -> bool:
    if not src.exists() or not src.is_file():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    if redact and (src.suffix.lower() in TEXT_EXTENSIONS or src.suffix == ""):
        try:
            text = src.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            warnings.append(f"binary-or-undecodable: {src.name}")
            shutil.copy2(src, dst)
            return True
        redacted, counts = redact_text_with_report(text)
        dst.write_text(redacted, encoding="utf-8")
        report_files.append(
            _RedactionFileResult(
                path=dst.name,
                redacted=bool(counts),
                replacements=sum(counts.values()),
                matched_kinds=sorted(counts.keys()),
            )
        )
        return True
    shutil.copy2(src, dst)
    return True


def _write_redacted_text(
    dst: Path,
    text: str,
    *,
    redact: bool,
    report_files: list[_RedactionFileResult],
) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if redact:
        out, counts = redact_text_with_report(text)
        dst.write_text(out, encoding="utf-8")
        report_files.append(
            _RedactionFileResult(
                path=dst.name,
                redacted=bool(counts),
                replacements=sum(counts.values()),
                matched_kinds=sorted(counts.keys()),
            )
        )
    else:
        dst.write_text(text, encoding="utf-8")


def _checksum_relative(export_dir: Path, files: list[str]) -> tuple[Path, dict[str, str]]:
    checksums: dict[str, str] = {}
    lines: list[str] = []
    for rel in sorted(set(files)):
        target = export_dir / rel
        if not target.exists() or not target.is_file():
            continue
        digest = sha256_file(target)
        checksums[rel] = digest
        lines.append(f"{digest}  {rel}")
    out = export_dir / "checksums.sha256"
    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return out, checksums


# ---------------------------------------------------------------------------
# Source resolution


def _proposal_json_path(data_dir: Path, proposal_id: str) -> Path | None:
    if not proposal_id:
        return None
    path, _status = find_proposal_path(Path(data_dir), proposal_id)
    return path


def _session_dir_for(data_dir: Path, session_id: str) -> Path | None:
    if not session_id:
        return None
    cand = Path(data_dir) / "artifacts" / session_id
    return cand if cand.is_dir() else None


# ---------------------------------------------------------------------------
# Build / write


def _ensure_mission_report_files(
    data_dir: Path,
    mission_id: str,
) -> tuple[Path, Path, dict[str, Any]]:
    """Build a fresh mission report and write source-of-truth files.

    The report files live under ``<data_dir>/mission_reports/<mission-id>/``
    so the operator can re-read them outside an export directory. The export
    pack copies them in.
    """
    report = build_mission_report(Path(data_dir), mission_id)
    json_path, md_path = write_mission_report_files(Path(data_dir), mission_id, report)
    return json_path, md_path, report


def _gather_optional_sources(
    data_dir: Path,
    mission_payload: dict[str, Any],
    *,
    mission_id: str,
    proposal_id: str,
    session_id: str,
) -> dict[str, Path]:
    """Return a mapping of export-relative-name -> source path for files we
    will try to include. Missing sources are reported in the manifest."""
    src_map: dict[str, Path] = {}

    mdir = _mission_dir(Path(data_dir), mission_id)
    src_map["mission.json"] = mdir / "mission.json"
    src_map["mission.md"] = mdir / "mission.md"

    prop_path = _proposal_json_path(Path(data_dir), proposal_id)
    if prop_path is not None:
        src_map["proposal.json"] = prop_path

    rb = str(mission_payload.get("rollback_preview_path") or "")
    if rb:
        rb_path = Path(rb)
        if rb_path.exists():
            src_map["rollback-preview.json"] = rb_path
            md_companion = rb_path.with_suffix(".md")
            if md_companion.exists():
                src_map["rollback-preview.md"] = md_companion
        if not rb_path.exists() and proposal_id:
            # Try canonical location.
            canonical = Path(data_dir) / "rollback_previews" / proposal_id / "rollback-preview.json"
            if canonical.exists():
                src_map["rollback-preview.json"] = canonical
                cmd = canonical.with_suffix(".md")
                if cmd.exists():
                    src_map["rollback-preview.md"] = cmd

    rp = str(mission_payload.get("restart_plan_path") or "")
    if rp and Path(rp).exists():
        src_map["restart-plan.json"] = Path(rp)
        cmd_md = Path(rp).with_suffix(".md")
        if cmd_md.exists():
            src_map["restart-plan.md"] = cmd_md

    phases = mission_payload.get("phases") or {}
    exec_phase = phases.get("execution") or {}
    receipt_ref = str(exec_phase.get("receipt") or "")
    if receipt_ref and Path(receipt_ref).exists():
        rj_path = Path(receipt_ref)
        src_map["apply-receipt.json"] = rj_path
        md_companion = rj_path.with_suffix(".md")
        if md_companion.exists():
            src_map["apply-receipt.md"] = md_companion
        # Inspect evidence sibling directory.
        evidence_dir = rj_path.with_suffix("")
        before = evidence_dir / "before-inspect.json"
        after = evidence_dir / "after-inspect.json"
        if before.exists():
            src_map["before-inspect.json"] = before
        if after.exists():
            src_map["after-inspect.json"] = after

    src_ev = str(mission_payload.get("source_evidence") or "")
    if src_ev and Path(src_ev).exists():
        src_map["source-evidence.json"] = Path(src_ev)

    sess_dir = _session_dir_for(Path(data_dir), session_id)
    if sess_dir is not None:
        for source_name, exported_name in (
            ("summary.md", "source-summary.md"),
            ("plan.json", "source-plan.json"),
            ("runbook.md", "source-runbook.md"),
            ("runbook.json", "source-runbook.json"),
        ):
            sp = sess_dir / source_name
            if sp.exists():
                src_map[exported_name] = sp

    return src_map


_OPTIONAL_FILE_ROSTER = (
    "mission.json",
    "mission.md",
    "proposal.json",
    "rollback-preview.json",
    "rollback-preview.md",
    "restart-plan.json",
    "restart-plan.md",
    "apply-receipt.json",
    "apply-receipt.md",
    "before-inspect.json",
    "after-inspect.json",
    "source-evidence.json",
    "source-summary.md",
    "source-plan.json",
    "source-runbook.md",
    "source-runbook.json",
)


def export_mission(
    data_dir: Path,
    mission_id: str,
    *,
    output: Path | None = None,
    redact: bool = False,
) -> MissionExportResult:
    """Bundle the mission and its referenced artifacts into an export pack.

    Read-only with respect to source artifacts. Writes only into the export
    directory plus the mission's own ``mission_reports/<mission-id>/`` for
    canonical report files. Never executes mutation.
    """
    # Refresh first so the export reflects current artifact state. The
    # refresh preserves terminal executed/refused state (PR53 invariant), so
    # it never erases an apply receipt or downgrades executed to ready.
    payload = refresh_mission(Path(data_dir), mission_id)
    proposal_id = str(payload.get("proposal_id") or "")
    session_id = str(payload.get("session_id") or "")

    export_id = make_mission_export_id()
    # Default output directory follows the PR52/PR53 mission export convention
    # (one directory per mission, keyed by mission_id so the operator can find
    # it without remembering an export id). The unique export_id still lives
    # in the manifest for audit traceability.
    export_dir = output or (mission_exports_root(Path(data_dir)) / mission_id)
    export_dir.mkdir(parents=True, exist_ok=True)

    report_files: list[_RedactionFileResult] = []
    warnings: list[str] = []
    included: list[str] = []
    missing: list[str] = []

    # 1) Build/refresh canonical mission report files (idempotent), then copy
    #    them into the export pack.
    report_json_path, report_md_path, report_payload = _ensure_mission_report_files(
        Path(data_dir), mission_id
    )

    if redact:
        # Re-render the JSON via redactor so embedded text fields are scrubbed.
        report_text = json.dumps(report_payload, indent=2)
        _write_redacted_text(
            export_dir / "mission-report.json",
            report_text,
            redact=True,
            report_files=report_files,
        )
        included.append("mission-report.json")
        try:
            md_text = report_md_path.read_text(encoding="utf-8")
        except OSError:
            md_text = ""
        if md_text:
            _write_redacted_text(
                export_dir / "mission-report.md",
                md_text,
                redact=True,
                report_files=report_files,
            )
            included.append("mission-report.md")
    else:
        if _copy_with_optional_redact(
            report_json_path,
            export_dir / "mission-report.json",
            redact=False,
            report_files=report_files,
            warnings=warnings,
        ):
            included.append("mission-report.json")
        if _copy_with_optional_redact(
            report_md_path,
            export_dir / "mission-report.md",
            redact=False,
            report_files=report_files,
            warnings=warnings,
        ):
            included.append("mission-report.md")

    # 2) Copy mission record + referenced artifacts.
    src_map = _gather_optional_sources(
        Path(data_dir),
        payload,
        mission_id=mission_id,
        proposal_id=proposal_id,
        session_id=session_id,
    )
    for rel in _OPTIONAL_FILE_ROSTER:
        src = src_map.get(rel)
        copied = (
            src is not None
            and src.exists()
            and src.is_file()
            and _copy_with_optional_redact(
                src,
                export_dir / rel,
                redact=redact,
                report_files=report_files,
                warnings=warnings,
            )
        )
        if copied:
            included.append(rel)
        else:
            missing.append(rel)

    # 3) Audit events as a compact JSON.
    audit_events = collect_mission_audit_events(
        Path(data_dir),
        mission_id=mission_id,
        proposal_id=proposal_id,
        session_id=session_id,
    )
    audit_payload = {
        "schema_version": "1",
        "mission_id": mission_id,
        "proposal_id": proposal_id,
        "session_id": session_id,
        "events": audit_events,
        "generated_at": _now(),
        "count": len(audit_events),
    }
    audit_text = json.dumps(audit_payload, indent=2)
    _write_redacted_text(
        export_dir / "audit-events.json",
        audit_text,
        redact=redact,
        report_files=report_files,
    )
    included.append("audit-events.json")

    # 4) Summary markdown (always present).
    summary_text = _render_summary(
        export_id=export_id,
        mission_id=mission_id,
        proposal_id=proposal_id,
        session_id=session_id,
        report_payload=report_payload,
        included=included,
        missing=missing,
        redact=redact,
    )
    _write_redacted_text(
        export_dir / "export-summary.md",
        summary_text,
        redact=redact,
        report_files=report_files,
    )
    included.append("export-summary.md")

    # 5) Redaction report (if applicable).
    if redact:
        redaction_payload = {
            "schema_version": "1",
            "redaction_applied": True,
            "created_at": _now(),
            "files_scanned": len(report_files),
            "files_redacted": len([f for f in report_files if f.redacted]),
            "total_replacements": sum(f.replacements for f in report_files),
            "patterns": sorted({k for f in report_files for k in f.matched_kinds}),
            "files": [f.__dict__ for f in report_files],
            "warnings": warnings,
        }
        (export_dir / "redaction-report.json").write_text(
            json.dumps(redaction_payload, indent=2), encoding="utf-8"
        )
        included.append("redaction-report.json")

    # 6) Checksums.
    checksums_path, checksums = _checksum_relative(export_dir, included)

    # 7) Manifests.
    receipt_ref = ""
    phases = payload.get("phases") or {}
    exec_phase = phases.get("execution") or {}
    if exec_phase.get("receipt"):
        receipt_ref = str(exec_phase["receipt"])

    manifest = _build_manifest(
        export_id=export_id,
        mission_id=mission_id,
        proposal_id=proposal_id,
        session_id=session_id,
        included=sorted(set(included)),
        missing=sorted(set(missing)),
        checksums=checksums,
        redact=redact,
        receipt_ref=receipt_ref,
    )
    manifest_path = export_dir / "export-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # Legacy manifest.json (PR53 contract): keep a small compat file so the
    # PR53 mission export tests continue to pass. The new export-manifest.json
    # is the canonical source going forward.
    legacy_included = sorted(
        {n for n in included if n not in ("export-summary.md", "redaction-report.json")}
    )
    if receipt_ref:
        rname = Path(receipt_ref).name
        # Also expose the receipt under its original on-disk name for legacy
        # callers that expect ``manifest.json["included_files"]`` to contain
        # the receipt's original filename.
        if rname not in legacy_included and (export_dir / rname).exists():
            legacy_included.append(rname)
    legacy_manifest = {
        "schema_version": "1",
        "mission_id": mission_id,
        "created_at": _now(),
        "included_files": legacy_included,
        "execution_receipt": receipt_ref,
        "safety": {
            "execution_allowed": False,
            "execution_status": "not_executed_by_export",
            "mutation_performed_by_export": False,
            "arbitrary_command_execution": False,
        },
    }
    if receipt_ref:
        rname = Path(receipt_ref).name
        if (export_dir / "apply-receipt.json").exists() and not (export_dir / rname).exists():
            shutil.copy2(export_dir / "apply-receipt.json", export_dir / rname)
            if rname not in legacy_manifest["included_files"]:
                legacy_manifest["included_files"].append(rname)
    (export_dir / "manifest.json").write_text(
        json.dumps(legacy_manifest, indent=2), encoding="utf-8"
    )

    return MissionExportResult(
        export_id=export_id,
        export_dir=export_dir,
        manifest_path=manifest_path,
        summary_path=export_dir / "export-summary.md",
        checksums_path=checksums_path,
        mission_id=mission_id,
        proposal_id=proposal_id,
        session_id=session_id,
        included_files=sorted(set(included)),
        missing_optional=sorted(set(missing)),
        redaction_applied=bool(redact),
    )


# ---------------------------------------------------------------------------
# Manifest / summary rendering


def _build_manifest(
    *,
    export_id: str,
    mission_id: str,
    proposal_id: str,
    session_id: str,
    included: list[str],
    missing: list[str],
    checksums: dict[str, str],
    redact: bool,
    receipt_ref: str,
) -> dict[str, Any]:
    build = get_build_info()
    manifest: dict[str, Any] = {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "export_id": export_id,
        "created_at": _now(),
        "source_type": SOURCE_TYPE,
        "mission_id": mission_id,
        "session_id": session_id,
        "proposal_id": proposal_id,
        "redaction_applied": bool(redact),
        "included_files": list(included),
        "missing_optional_files": list(missing),
        "checksums": dict(checksums),
        "execution_receipt_ref": receipt_ref,
        "safety": {
            "execution_allowed": False,
            "execution_status": "not_executed_by_export",
            "mutation_performed_by_export": False,
            "arbitrary_command_execution": False,
            "rollback_execution": False,
            "natural_language_execution": False,
        },
        "safety_note": SAFETY_NOTE,
        "raw_evidence_warning": REDACTION_WARNING if redact else RAW_EVIDENCE_WARNING,
        "shellforgeai_version": build.display_version,
    }
    if redact:
        manifest["redaction_report"] = "redaction-report.json"
    return manifest


def _render_summary(
    *,
    export_id: str,
    mission_id: str,
    proposal_id: str,
    session_id: str,
    report_payload: dict[str, Any],
    included: list[str],
    missing: list[str],
    redact: bool,
) -> str:
    target = str(report_payload.get("target") or "unknown")
    status = str(report_payload.get("status") or "")
    execution = report_payload.get("execution") or {}
    verification = report_payload.get("verification") or {}
    rollback = report_payload.get("rollback") or {}
    lines: list[str] = []
    lines.append("# ShellForgeAI mission export pack")
    lines.append("")
    lines.append(f"- export id: {export_id}")
    lines.append(f"- mission: {mission_id}")
    lines.append(f"- target: {target}")
    lines.append(f"- proposal: {proposal_id or 'missing'}")
    lines.append(f"- source session: {session_id or 'unknown'}")
    lines.append(f"- mission status: {status}")
    lines.append(f"- execution path: {execution.get('path') or 'none'}")
    lines.append(f"- redaction: {'on (best-effort; review before sharing)' if redact else 'off'}")
    lines.append("- export execution: none (this command did not execute anything)")
    lines.append("")
    lines.append("## Verification")
    lines.append(f"- status: {verification.get('status', '')}")
    lines.append(f"- running_after: {bool(verification.get('running_after', False))}")
    lines.append(f"- started_at_changed: {bool(verification.get('started_at_changed', False))}")
    lines.append(f"- health_after: {verification.get('health_after', '')}")
    lines.append("")
    lines.append("## Rollback")
    rb_status_label = rollback.get("preview_status") or rollback.get("rollback_status") or "unknown"
    lines.append(f"- preview status: {rb_status_label}")
    lines.append("- rollback execution: disabled (preview only; never executable from export)")
    lines.append("")
    lines.append("## Included files")
    if included:
        for n in sorted(set(included)):
            lines.append(f"- {n}")
    else:
        lines.append("- (no files included)")
    lines.append("")
    if missing:
        lines.append("## Missing optional files")
        for n in sorted(set(missing)):
            lines.append(f"- {n}")
        lines.append("")
    lines.append("## Safety")
    lines.append(f"- {SAFETY_NOTE}")
    if redact:
        lines.append(f"- {REDACTION_WARNING}")
    else:
        lines.append(f"- {RAW_EVIDENCE_WARNING}")
    lines.append("- export may describe a prior gated mutation but did not perform one.")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Validation


@dataclass
class MissionExportValidation:
    ok: bool
    errors: list[str] = field(default_factory=list)
    info: dict[str, Any] = field(default_factory=dict)


_REQUIRED_TOP_LEVEL_FILES = (
    "export-manifest.json",
    "export-summary.md",
    "checksums.sha256",
    "mission-report.json",
    "mission-report.md",
)


def validate_mission_export(target: Path) -> MissionExportValidation:
    target = Path(target)
    if not target.exists() or not target.is_dir():
        return MissionExportValidation(
            ok=False,
            errors=[f"export directory not found: {target}"],
        )
    manifest_path = target / "export-manifest.json"
    if not manifest_path.exists():
        return MissionExportValidation(
            ok=False,
            errors=["export-manifest.json not found"],
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return MissionExportValidation(ok=False, errors=[f"malformed export-manifest.json: {exc}"])
    if not isinstance(manifest, dict):
        return MissionExportValidation(
            ok=False, errors=["export-manifest.json is not a JSON object"]
        )

    errors: list[str] = []

    if str(manifest.get("source_type") or "") != SOURCE_TYPE:
        errors.append(f"manifest source_type must be {SOURCE_TYPE!r}")
    if not manifest.get("mission_id"):
        errors.append("manifest mission_id missing")

    safety = manifest.get("safety") or {}
    if not isinstance(safety, dict):
        errors.append("manifest safety must be an object")
        safety = {}
    if safety.get("execution_allowed") is True:
        errors.append("manifest safety.execution_allowed must be false")
    if safety.get("mutation_performed_by_export") is True:
        errors.append("manifest safety.mutation_performed_by_export must be false")
    if safety.get("arbitrary_command_execution") is True:
        errors.append("manifest safety.arbitrary_command_execution must be false")
    if safety.get("rollback_execution") is True:
        errors.append("manifest safety.rollback_execution must be false")
    exec_status = str(safety.get("execution_status") or "")
    if exec_status not in ("not_executed_by_export", "not_executed"):
        errors.append(
            f"manifest safety.execution_status must be not_executed_by_export (got {exec_status!r})"
        )

    for required in _REQUIRED_TOP_LEVEL_FILES:
        if not (target / required).exists():
            errors.append(f"required file missing: {required}")

    redaction_applied = bool(manifest.get("redaction_applied"))
    if redaction_applied:
        report_name = str(manifest.get("redaction_report") or "redaction-report.json")
        rp = target / report_name
        if not rp.exists():
            errors.append("redaction-report.json missing for redacted export")
        else:
            try:
                rpayload = json.loads(rp.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                errors.append(f"malformed redaction-report.json: {exc}")
            else:
                if rpayload.get("redaction_applied") is not True:
                    errors.append("redaction-report.json must set redaction_applied=true")

    included = list(manifest.get("included_files") or [])
    missing = list(manifest.get("missing_optional_files") or [])

    parsed_checksums: dict[str, str] = {}
    checksums_path = target / "checksums.sha256"
    if checksums_path.exists():
        for line in checksums_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                errors.append(f"malformed checksum line: {line}")
                continue
            parsed_checksums[parts[1].strip()] = parts[0].strip()
    else:
        errors.append("checksums.sha256 missing")

    for rel in included:
        path = target / rel
        if not path.exists():
            errors.append(f"missing included file: {rel}")
            continue
        expected = parsed_checksums.get(rel) or (manifest.get("checksums") or {}).get(rel)
        if expected:
            actual = sha256_file(path)
            if actual != expected:
                errors.append(f"checksum mismatch: {rel}")

    # Any extra files on disk that are neither in included nor missing are fine,
    # but explicitly missing optional files must NOT be present without being
    # listed in included.
    for rel in missing:
        if (target / rel).exists() and rel not in included:
            errors.append(f"file {rel} present on disk but listed as missing optional")

    info = {
        "export_dir": str(target),
        "export_id": str(manifest.get("export_id") or ""),
        "mission_id": str(manifest.get("mission_id") or ""),
        "file_count": len(included),
        "redaction_applied": redaction_applied,
    }
    return MissionExportValidation(ok=not errors, errors=errors, info=info)


__all__ = [
    "EXPORT_SCHEMA_VERSION",
    "MissionExportResult",
    "MissionExportValidation",
    "SOURCE_TYPE",
    "export_mission",
    "make_mission_export_id",
    "mission_exports_root",
    "validate_mission_export",
]
