"""Audit/export pack export (PR34).

Packages evidence/summary/runbook/proposal/apply-preflight artifacts into a
single portable, human-reviewable export pack on disk. **ShellForgeAI does
not execute anything.** Export only copies/reads files and writes a new
directory under ``<data_dir>/exports/``. No mutation of original artifacts,
no execution of generated scripts.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from shellforgeai.core.actions import actions_dir_for
from shellforgeai.core.apply_bundle import bundle_dir_for
from shellforgeai.core.approvals import (
    Proposal,
    find_proposal_path,
    latest_approved_proposal,
    load_proposal_from_path,
)
from shellforgeai.version import get_build_info

EXPORT_SCHEMA_VERSION = "1"

SAFETY_NOTE = "ShellForgeAI exported this audit pack but did not execute any remediation."
RAW_EVIDENCE_WARNING = (
    "Raw evidence files may contain environment/config details. Review before sharing."
)

SOURCE_SESSION = "session"
SOURCE_PROPOSAL = "proposal"
SOURCE_LATEST = "latest"
SOURCE_LATEST_APPROVED = "latest-approved"

# Files we look for in artifact session directories.
SESSION_OPTIONAL_FILES = (
    "evidence.json",
    "summary.md",
    "plan.json",
    "runbook.md",
    "runbook.json",
)

# Files we look for in apply bundle directories.
BUNDLE_OPTIONAL_FILES = (
    "apply-preview.md",
    "operator-commands.sh",
    "rollback.sh",
    "validation.md",
    "apply-preflight.json",
)

# Files we look for in compiled-actions directories (PR37).
ACTIONS_OPTIONAL_FILES = (
    "actions.json",
    "actions.md",
)

# Full optional-file roster for the export pack.
ALL_OPTIONAL_FILES = (
    SESSION_OPTIONAL_FILES + ("proposal.json",) + BUNDLE_OPTIONAL_FILES + ACTIONS_OPTIONAL_FILES
)


REDACTION_WARNING = (
    "This export was generated with best-effort redaction, "
    "but operators should still review before sharing."
)
TEXT_EXTENSIONS = {
    ".json",
    ".md",
    ".txt",
    ".log",
    ".env",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".conf",
    ".cfg",
    ".sh",
}
_KV_KEYS = (
    "password|passwd|pwd|token|access_token|refresh_token|api_key|apikey|api-key|secret|"
    "client_secret|private_key|ssh_key|bearer|authorization|cookie|set-cookie|session|"
    "connection_string|database_url|db_password|redis_url|mongo_uri|webhook_url|"
    "aws_secret_access_key|aws_access_key_id|slack_token|github_token|openai_api_key|"
    "stripe_secret_key|stripe_api_key"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9_ -]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_ -]*PRIVATE KEY-----"
)
_KV_RE = re.compile(
    rf"(?im)((?:\bexport\s+)?[\"']?(?:{_KV_KEYS})[\"']?\s*[:=]\s*)([\"']?)([^\n\"',]+)(\2)"
)
_AUTH_RE = re.compile(r"(?im)(\bauthorization\s*:\s*)(bearer\s+[^\s\"']+|[^\n]+)")
_COOKIE_RE = re.compile(r"(?im)(\b(?:set-cookie|cookie)\s*:\s*)([^\n]+)")
_GITHUB_TOKENS = re.compile(r"\b(?:ghp|github_pat|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b")
_AWS_AK = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_SLACK_TOKENS = re.compile(r"\b(?:xoxb|xoxp|xoxa|xoxr|xapp)-[A-Za-z0-9-]{20,}\b")
_WEBHOOKS = re.compile(
    r"https://(?:hooks\.slack\.com/services|discord\.com/api/webhooks)/[^\s\"']+"
)
_SK_TOKENS = re.compile(
    r"\b(?:sk-test-[A-Za-z0-9_-]{8,}|sk-live-[A-Za-z0-9_-]{8,}|"
    r"sk-proj-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{20,})\b"
)


@dataclass
class ExportResult:
    export_id: str
    export_dir: Path
    manifest_path: Path
    summary_path: Path
    checksums_path: Path
    included_files: list[str] = field(default_factory=list)
    missing_optional: list[str] = field(default_factory=list)
    source_type: str = ""
    source_session_id: str = ""
    source_proposal_id: str = ""


@dataclass
class RedactionFileResult:
    path: str
    redacted: bool
    replacements: int
    matched_kinds: list[str]


# ---------------------------------------------------------------------------
# IDs / paths


def make_export_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    short = uuid4().hex[:6]
    return f"export_{stamp}_{short}"


def exports_root(data_dir: Path) -> Path:
    return Path(data_dir) / "exports"


# ---------------------------------------------------------------------------
# Redaction


def redact_text(text: str) -> str:
    out, _stats = redact_text_with_report(text)
    return out


def redact_text_with_report(text: str) -> tuple[str, dict[str, int]]:
    counts: dict[str, int] = {}

    def _inc(kind: str, n: int = 1) -> None:
        if n > 0:
            counts[kind] = counts.get(kind, 0) + n

    out, n = _PRIVATE_KEY_BLOCK.subn("[REDACTED_PRIVATE_KEY_BLOCK]", text)
    _inc("private_key_block", n)

    def _kv_replace(m: re.Match[str]) -> str:
        key = m.group(1).split(":")[0].split("=")[0].replace("export", "").strip().lower()
        kind = key.replace("-", "_")
        _inc(kind if kind in {"database_url", "redis_url", "mongo_uri", "cookie"} else kind)
        return f"{m.group(1)}{m.group(2)}[REDACTED]{m.group(4)}"

    out = _KV_RE.sub(_kv_replace, out)
    out, n = _AUTH_RE.subn(r"\1[REDACTED]", out)
    _inc("authorization", n)
    out, n = _COOKIE_RE.subn(r"\1[REDACTED]", out)
    _inc("cookie", n)
    out, n = _GITHUB_TOKENS.subn("[REDACTED_TOKEN]", out)
    _inc("github_token", n)
    out, n = _AWS_AK.subn("[REDACTED_AWS_ACCESS_KEY]", out)
    _inc("aws_access_key", n)
    out, n = _SLACK_TOKENS.subn("[REDACTED_TOKEN]", out)
    _inc("slack_token", n)
    out, n = _WEBHOOKS.subn("[REDACTED_WEBHOOK_URL]", out)
    _inc("webhook_url", n)
    out, n = _SK_TOKENS.subn("[REDACTED_TOKEN]", out)
    _inc("bearer_token", n)
    return out, counts


# ---------------------------------------------------------------------------
# Checksums


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_checksums(export_dir: Path, relative_files: list[str]) -> tuple[Path, dict[str, str]]:
    checksums: dict[str, str] = {}
    lines: list[str] = []
    for rel in sorted(relative_files):
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


def resolve_session_dir(data_dir: Path, target: str | Path) -> Path | None:
    """Accept a session id (``sf_*``) or a session directory path."""
    p = Path(target)
    if p.is_dir():
        return p
    if p.is_file():
        return p.parent
    if str(target).startswith("sf_"):
        candidate = Path(data_dir) / "artifacts" / str(target)
        if candidate.is_dir():
            return candidate
    return None


def latest_session_dir(data_dir: Path) -> Path | None:
    root = Path(data_dir) / "artifacts"
    if not root.exists():
        return None
    candidates = [p for p in root.glob("sf_*") if p.is_dir()]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime)
    return candidates[-1]


# ---------------------------------------------------------------------------
# Copy helpers


def _copy_if_exists(
    src: Path,
    dst: Path,
    *,
    redact: bool,
    report_files: list[RedactionFileResult],
    warnings: list[str],
) -> bool:
    if not src.exists() or not src.is_file():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    if redact and (src.suffix.lower() in TEXT_EXTENSIONS or src.suffix == ""):
        try:
            text = src.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            if src.suffix == "":
                warnings.append(f"treated as binary/unsupported text decode: {src.name}")
            shutil.copy2(src, dst)
            return True
        redacted, counts = redact_text_with_report(text)
        dst.write_text(redacted, encoding="utf-8")
        report_files.append(
            RedactionFileResult(
                path=dst.name,
                redacted=bool(counts),
                replacements=sum(counts.values()),
                matched_kinds=sorted(counts.keys()),
            )
        )
        return True
    shutil.copy2(src, dst)
    return True


def _gather_session_files(
    session_dir: Path,
    export_dir: Path,
    *,
    redact: bool,
    report_files: list[RedactionFileResult],
    warnings: list[str],
) -> tuple[list[str], list[str]]:
    included: list[str] = []
    missing: list[str] = []
    for name in SESSION_OPTIONAL_FILES:
        src = session_dir / name
        if _copy_if_exists(
            src, export_dir / name, redact=redact, report_files=report_files, warnings=warnings
        ):
            included.append(name)
        else:
            missing.append(name)
    return included, missing


def _gather_bundle_files(
    bundle_dir: Path,
    export_dir: Path,
    *,
    redact: bool,
    report_files: list[RedactionFileResult],
    warnings: list[str],
) -> tuple[list[str], list[str]]:
    included: list[str] = []
    missing: list[str] = []
    for name in BUNDLE_OPTIONAL_FILES:
        src = bundle_dir / name
        if _copy_if_exists(
            src, export_dir / name, redact=redact, report_files=report_files, warnings=warnings
        ):
            included.append(name)
        else:
            missing.append(name)
    return included, missing


def _gather_actions_files(
    actions_dir: Path,
    export_dir: Path,
    *,
    redact: bool,
    report_files: list[RedactionFileResult],
    warnings: list[str],
) -> tuple[list[str], list[str]]:
    """Copy compiled action files (PR37) into the export dir if present."""
    included: list[str] = []
    missing: list[str] = []
    for name in ACTIONS_OPTIONAL_FILES:
        src = actions_dir / name
        if _copy_if_exists(
            src, export_dir / name, redact=redact, report_files=report_files, warnings=warnings
        ):
            included.append(name)
        else:
            missing.append(name)
    return included, missing


def _write_proposal_file(proposal: Proposal, export_dir: Path, *, redact: bool) -> str:
    text = proposal.model_dump_json(indent=2)
    if redact:
        text = redact_text(text)
    (export_dir / "proposal.json").write_text(text, encoding="utf-8")
    return "proposal.json"


# ---------------------------------------------------------------------------
# Summary / manifest rendering


def _render_export_summary(
    *,
    export_id: str,
    created_at: str,
    source_type: str,
    source_session_id: str,
    source_proposal_id: str,
    proposal: Proposal | None,
    session_dir: Path | None,
    bundle_dir: Path | None,
    included: list[str],
    missing: list[str],
    redact: bool,
) -> str:
    lines: list[str] = []
    lines.append("# ShellForgeAI audit/export pack")
    lines.append("")
    lines.append(f"- Export id: {export_id}")
    lines.append(f"- Created at: {created_at}")
    lines.append(f"- Source type: {source_type}")
    if source_session_id:
        lines.append(f"- Source session: {source_session_id}")
    if source_proposal_id:
        lines.append(f"- Source proposal: {source_proposal_id}")
    if session_dir is not None:
        lines.append(f"- Session dir: {session_dir}")
    if bundle_dir is not None:
        lines.append(f"- Apply bundle dir: {bundle_dir}")
    lines.append(f"- Redaction: {'on' if redact else 'off (raw copies preserved)'}")
    if redact:
        lines.append(f"- Redaction warning: {REDACTION_WARNING}")
    lines.append("- Execution status: not_executed")
    lines.append("- Execution allowed: false")
    lines.append("")
    if proposal is not None:
        lines.append("## Proposal")
        lines.append("")
        lines.append(f"- Proposal id: {proposal.proposal_id}")
        lines.append(f"- Status: {proposal.status}")
        lines.append(f"- Risk: {proposal.risk}")
        if proposal.component:
            lines.append(f"- Component: {proposal.component}")
        if proposal.title:
            title = redact_text(proposal.title) if redact else proposal.title
            lines.append(f"- Title: {title}")
        if proposal.approval and proposal.approval.reason:
            reason = redact_text(proposal.approval.reason) if redact else proposal.approval.reason
            lines.append(f"- Approval reason: {reason}")
        if proposal.approval and proposal.approval.approved_at:
            lines.append(f"- Approved at: {proposal.approval.approved_at}")
        lines.append("- Execution: not_executed (ShellForgeAI did not execute any step)")
        if bundle_dir is not None:
            lines.append(f"- Apply preflight bundle: {bundle_dir}")
        lines.append("")
        lines.append("### What was proposed")
        lines.append("")
        if proposal.proposed_steps:
            for s in proposal.proposed_steps[:20]:
                step = redact_text(s) if redact else s
                lines.append(f"- {step}")
        else:
            lines.append("- (no proposed_steps recorded)")
        lines.append("")
        lines.append("### Why it was proposed")
        lines.append("")
        impact = proposal.impact or proposal.notes or "(no impact recorded)"
        if redact:
            impact = redact_text(impact)
        lines.append(impact)
        lines.append("")

    lines.append("## Included files")
    lines.append("")
    if included:
        for name in included:
            lines.append(f"- {name}")
    else:
        lines.append("- (no files included)")
    lines.append("")

    if missing:
        lines.append("## Missing optional files")
        lines.append("")
        for name in missing:
            lines.append(f"- {name}")
        lines.append("")

    lines.append("## Safety")
    lines.append("")
    lines.append(f"- {SAFETY_NOTE}")
    lines.append(f"- {REDACTION_WARNING if redact else RAW_EVIDENCE_WARNING}")
    lines.append("- apply remains validation-only. No commands were executed.")
    return "\n".join(lines) + "\n"


def _build_manifest(
    *,
    export_id: str,
    created_at: str,
    source_type: str,
    source_session_id: str,
    source_proposal_id: str,
    included: list[str],
    missing: list[str],
    checksums: dict[str, str],
    proposal: Proposal | None,
    session_dir: Path | None,
    bundle_dir: Path | None,
    redact: bool,
) -> dict[str, Any]:
    build = get_build_info()
    manifest: dict[str, Any] = {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "export_id": export_id,
        "created_at": created_at,
        "source_type": source_type,
        "source_session_id": source_session_id,
        "source_proposal_id": source_proposal_id,
        "session_dir": str(session_dir) if session_dir is not None else "",
        "apply_bundle_dir": str(bundle_dir) if bundle_dir is not None else "",
        "included_files": list(included),
        "missing_optional_files": list(missing),
        "checksums": dict(checksums),
        "execution_allowed": False,
        "execution_status": "not_executed",
        "redaction_applied": bool(redact),
        "raw_evidence_warning": REDACTION_WARNING if redact else RAW_EVIDENCE_WARNING,
        "safety_note": SAFETY_NOTE,
        "shellforgeai_version": build.display_version,
    }
    if proposal is not None:
        manifest["proposal"] = {
            "proposal_id": proposal.proposal_id,
            "status": proposal.status,
            "risk": proposal.risk,
            "component": proposal.component,
            "title": redact_text(proposal.title) if redact else proposal.title,
            "fingerprint": str((proposal.fingerprint or {}).get("value") or ""),
            "approval_reason": (
                redact_text(proposal.approval.reason or "")
                if redact
                else (proposal.approval.reason or "")
            ),
        }
    if redact:
        manifest["redaction_report"] = "redaction-report.json"
    return manifest


# ---------------------------------------------------------------------------
# Top-level export functions


def _resolve_bundle_for_proposal(data_dir: Path, proposal_id: str) -> Path | None:
    bundle = bundle_dir_for(Path(data_dir), proposal_id)
    return bundle if bundle.exists() and bundle.is_dir() else None


def _resolve_session_dir_for_proposal(proposal: Proposal) -> Path | None:
    """Try to locate the session dir referenced by the proposal source."""
    runbook = proposal.source.runbook
    evidence = proposal.source.evidence
    summary = proposal.source.summary
    for raw in (runbook, evidence, summary):
        if not raw:
            continue
        p = Path(raw)
        if p.is_file():
            return p.parent
        if p.is_dir():
            return p
    return None


def export_from_session(
    data_dir: Path,
    session_dir: Path,
    *,
    output: Path | None = None,
    redact: bool = False,
) -> ExportResult:
    if not session_dir.exists() or not session_dir.is_dir():
        raise FileNotFoundError(f"session directory not found: {session_dir}")
    export_id = make_export_id()
    export_dir = output or (exports_root(Path(data_dir)) / export_id)
    export_dir.mkdir(parents=True, exist_ok=True)
    session_id = session_dir.name if session_dir.name.startswith("sf_") else ""
    report_files: list[RedactionFileResult] = []
    warnings: list[str] = []
    included, missing = _gather_session_files(
        session_dir, export_dir, redact=redact, report_files=report_files, warnings=warnings
    )
    return _finalize_export(
        export_dir=export_dir,
        export_id=export_id,
        source_type=SOURCE_SESSION,
        source_session_id=session_id,
        source_proposal_id="",
        proposal=None,
        session_dir=session_dir,
        bundle_dir=None,
        included=included,
        missing=missing,
        redact=redact,
        report_files=report_files,
        warnings=warnings,
    )


def export_from_proposal(
    data_dir: Path,
    proposal_id: str,
    *,
    output: Path | None = None,
    redact: bool = False,
) -> ExportResult:
    path, _status = find_proposal_path(Path(data_dir), proposal_id)
    if path is None:
        raise FileNotFoundError(f"proposal not found: {proposal_id}")
    proposal = load_proposal_from_path(path)
    return _export_proposal_object(
        data_dir=Path(data_dir),
        proposal=proposal,
        output=output,
        redact=redact,
    )


def export_latest_approved(
    data_dir: Path,
    *,
    output: Path | None = None,
    redact: bool = False,
) -> ExportResult:
    proposal = latest_approved_proposal(Path(data_dir))
    if proposal is None:
        raise FileNotFoundError("no approved proposals found")
    return _export_proposal_object(
        data_dir=Path(data_dir),
        proposal=proposal,
        output=output,
        redact=redact,
        source_type=SOURCE_LATEST_APPROVED,
    )


def export_latest_session(
    data_dir: Path,
    *,
    output: Path | None = None,
    redact: bool = False,
) -> ExportResult:
    latest = latest_session_dir(Path(data_dir))
    if latest is None:
        raise FileNotFoundError("no session artifacts found")
    res = export_from_session(Path(data_dir), latest, output=output, redact=redact)
    res.source_type = SOURCE_LATEST
    # Re-write manifest to reflect updated source_type.
    return _rewrite_source_type(res)


def _rewrite_source_type(res: ExportResult) -> ExportResult:
    manifest = json.loads(res.manifest_path.read_text(encoding="utf-8"))
    manifest["source_type"] = res.source_type
    res.manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    # Recompute checksum for manifest within checksums.sha256.
    relative_files = [f for f in res.included_files if (res.export_dir / f).exists()] + [
        "export-manifest.json",
        "export-summary.md",
    ]
    _, _ = write_checksums(res.export_dir, sorted(set(relative_files)))
    return res


def _export_proposal_object(
    *,
    data_dir: Path,
    proposal: Proposal,
    output: Path | None,
    redact: bool,
    source_type: str = SOURCE_PROPOSAL,
) -> ExportResult:
    export_id = make_export_id()
    export_dir = output or (exports_root(data_dir) / export_id)
    export_dir.mkdir(parents=True, exist_ok=True)

    included: list[str] = []
    missing: list[str] = []
    report_files: list[RedactionFileResult] = []
    warnings: list[str] = []

    session_dir = _resolve_session_dir_for_proposal(proposal)
    if session_dir is not None and session_dir.is_dir():
        sess_inc, sess_miss = _gather_session_files(
            session_dir, export_dir, redact=redact, report_files=report_files, warnings=warnings
        )
        included.extend(sess_inc)
        missing.extend(sess_miss)
    else:
        missing.extend(list(SESSION_OPTIONAL_FILES))

    included.append(_write_proposal_file(proposal, export_dir, redact=redact))

    bundle_dir = _resolve_bundle_for_proposal(data_dir, proposal.proposal_id)
    if bundle_dir is not None:
        b_inc, b_miss = _gather_bundle_files(
            bundle_dir, export_dir, redact=redact, report_files=report_files, warnings=warnings
        )
        included.extend(b_inc)
        missing.extend(b_miss)
    else:
        missing.extend(list(BUNDLE_OPTIONAL_FILES))

    # PR37: include compiled actions if present (review-only).
    actions_dir = actions_dir_for(Path(data_dir), proposal.proposal_id)
    if actions_dir.exists() and actions_dir.is_dir():
        a_inc, a_miss = _gather_actions_files(
            actions_dir, export_dir, redact=redact, report_files=report_files, warnings=warnings
        )
        included.extend(a_inc)
        missing.extend(a_miss)
    else:
        missing.extend(list(ACTIONS_OPTIONAL_FILES))

    return _finalize_export(
        export_dir=export_dir,
        export_id=export_id,
        source_type=source_type,
        source_session_id=proposal.source.session_id or "",
        source_proposal_id=proposal.proposal_id,
        proposal=proposal,
        session_dir=session_dir,
        bundle_dir=bundle_dir,
        included=included,
        missing=missing,
        redact=redact,
        report_files=report_files,
        warnings=warnings,
    )


def _finalize_export(
    *,
    export_dir: Path,
    export_id: str,
    source_type: str,
    source_session_id: str,
    source_proposal_id: str,
    proposal: Proposal | None,
    session_dir: Path | None,
    bundle_dir: Path | None,
    included: list[str],
    missing: list[str],
    redact: bool,
    report_files: list[RedactionFileResult],
    warnings: list[str],
) -> ExportResult:
    created_at = datetime.now(timezone.utc).isoformat()
    summary_text = _render_export_summary(
        export_id=export_id,
        created_at=created_at,
        source_type=source_type,
        source_session_id=source_session_id,
        source_proposal_id=source_proposal_id,
        proposal=proposal,
        session_dir=session_dir,
        bundle_dir=bundle_dir,
        included=included,
        missing=missing,
        redact=redact,
    )
    summary_path = export_dir / "export-summary.md"
    summary_path.write_text(summary_text, encoding="utf-8")

    # Compute checksums over included files + summary.md so the
    # manifest can embed them.
    if redact:
        redaction_payload = {
            "schema_version": "1",
            "redaction_applied": True,
            "created_at": created_at,
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
    rel_for_checksum = sorted(
        set(included + ["export-summary.md"] + (["redaction-report.json"] if redact else []))
    )
    checksums_path, checksums = write_checksums(export_dir, rel_for_checksum)

    manifest = _build_manifest(
        export_id=export_id,
        created_at=created_at,
        source_type=source_type,
        source_session_id=source_session_id,
        source_proposal_id=source_proposal_id,
        included=sorted(set(included)),
        missing=sorted(set(missing)),
        checksums=checksums,
        proposal=proposal,
        session_dir=session_dir,
        bundle_dir=bundle_dir,
        redact=redact,
    )
    manifest_path = export_dir / "export-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return ExportResult(
        export_id=export_id,
        export_dir=export_dir,
        manifest_path=manifest_path,
        summary_path=summary_path,
        checksums_path=checksums_path,
        included_files=sorted(set(included)),
        missing_optional=sorted(set(missing)),
        source_type=source_type,
        source_session_id=source_session_id,
        source_proposal_id=source_proposal_id,
    )


# ---------------------------------------------------------------------------
# Validation


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    info: dict[str, Any] = field(default_factory=dict)


def _resolve_validate_target(target: Path) -> tuple[Path | None, Path | None]:
    """Return (export_dir, manifest_path) or (None, None) on failure."""
    if target.is_dir():
        manifest = target / "export-manifest.json"
        if manifest.exists():
            return target, manifest
        return None, None
    if target.is_file() and target.name == "export-manifest.json":
        return target.parent, target
    if target.is_file() and target.suffix == ".json":
        return target.parent, target
    return None, None


def validate_export(target: Path) -> ValidationResult:
    target = Path(target)
    export_dir, manifest_path = _resolve_validate_target(target)
    if export_dir is None or manifest_path is None or not manifest_path.exists():
        return ValidationResult(
            ok=False,
            errors=["export-manifest.json not found"],
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return ValidationResult(ok=False, errors=[f"malformed manifest: {exc}"])
    if not isinstance(manifest, dict):
        return ValidationResult(ok=False, errors=["manifest is not a JSON object"])

    errors: list[str] = []
    info: dict[str, Any] = {
        "export_dir": str(export_dir),
        "export_id": manifest.get("export_id", ""),
        "file_count": 0,
    }

    safety_note = str(manifest.get("safety_note") or "")
    if "did not execute" not in safety_note.lower():
        errors.append("safety note missing or does not state non-execution")

    source_type = str(manifest.get("source_type") or "")
    if not source_type:
        errors.append("manifest missing source_type")
    if not (manifest.get("source_session_id") or manifest.get("source_proposal_id")):
        errors.append("manifest has no source session or proposal reference")

    if manifest.get("execution_allowed") is True:
        errors.append("manifest execution_allowed must be false")
    if manifest.get("execution_status") not in (None, "", "not_executed"):
        errors.append("manifest execution_status must be 'not_executed'")
    redaction_applied = bool(manifest.get("redaction_applied"))
    if redaction_applied:
        report_name = str(manifest.get("redaction_report") or "redaction-report.json")
        report_path = export_dir / report_name
        if not report_path.exists():
            errors.append("redaction-report.json not found for redacted export")
        else:
            try:
                report_payload = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                errors.append(f"malformed redaction-report.json: {exc}")
            else:
                if report_payload.get("redaction_applied") is not True:
                    errors.append("redaction-report.json must set redaction_applied=true")
        summary = export_dir / "export-summary.md"
        if summary.exists():
            summary_text = summary.read_text(encoding="utf-8").lower()
            if "redaction: off" in summary_text:
                errors.append("export-summary.md claims redaction off while manifest says true")

    included = list(manifest.get("included_files") or [])
    info["file_count"] = len(included)

    checksums_path = export_dir / "checksums.sha256"
    if not checksums_path.exists():
        errors.append("checksums.sha256 not found")
    parsed_checksums: dict[str, str] = {}
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

    for rel in included:
        path = export_dir / rel
        if not path.exists():
            errors.append(f"missing included file: {rel}")
            continue
        expected = parsed_checksums.get(rel) or (manifest.get("checksums") or {}).get(rel)
        if expected:
            actual = sha256_file(path)
            if actual != expected:
                errors.append(f"checksum mismatch: {rel}")

    # Apply preflight execution invariants when present.
    preflight = export_dir / "apply-preflight.json"
    if preflight.exists():
        try:
            payload = json.loads(preflight.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(f"malformed apply-preflight.json: {exc}")
        else:
            if payload.get("execution_allowed") is True:
                errors.append("apply-preflight.json claims execution_allowed=true")
            if payload.get("execution_status") not in (None, "", "not_executed"):
                errors.append("apply-preflight.json execution_status is not 'not_executed'")

    return ValidationResult(ok=not errors, errors=errors, info=info)


# ---------------------------------------------------------------------------
# Ask intent matching


_EXPORT_INTENT_TOKENS = (
    "export the latest audit pack",
    "export the audit pack",
    "create an audit pack",
    "make an audit pack",
    "package this for change review",
    "package for change review",
    "create a handoff pack",
    "make a handoff pack",
    "create change ticket evidence",
    "create change ticket evidence pack",
    "package this for external sharing",
    "export this safely",
    "create a redacted audit pack",
    "make a sanitized change-review pack",
    "export latest with secrets removed",
    "redact and export the approved proposal",
    "export the approved proposal",
    "export approved proposal",
    "export the latest approved",
    "export latest approved",
    "audit pack",
    "handoff pack",
)


_EXPORT_APPROVED_HINT_TOKENS = (
    "approved",
    "handoff",
    "change review",
    "change ticket",
)
_EXPORT_REDACT_HINT_TOKENS = (
    "redact",
    "redacted",
    "safely",
    "sanitized",
    "sharing",
    "secrets removed",
    "external",
)


@dataclass(frozen=True)
class ExportAskIntent:
    matched: bool
    prefer_approved: bool = False
    prefer_redact: bool = False


def is_export_intent(text: str) -> ExportAskIntent:
    raw = (text or "").lower()
    matched = any(tok in raw for tok in _EXPORT_INTENT_TOKENS)
    if not matched:
        return ExportAskIntent(matched=False)
    prefer = any(tok in raw for tok in _EXPORT_APPROVED_HINT_TOKENS)
    redact = any(tok in raw for tok in _EXPORT_REDACT_HINT_TOKENS)
    return ExportAskIntent(matched=True, prefer_approved=prefer, prefer_redact=redact)
