"""Audit-aware incident index and search (PR40).

Read/write a compact incident index from existing ShellForgeAI artifacts so
operators can find prior sessions, proposals, exports, refusals, guard
failures, and components from a single deterministic JSON file.

The index is search/navigation only:

- No execution.
- No mutation of artifacts (the index file itself is the only thing this
  module writes, under ``<data_dir>/audit/incident-index.json``).
- All indexed safety fields preserve
  ``execution_allowed=false``, ``execution_status=not_executed``,
  ``mutation_performed=false``.

This is intentionally simple (no DB, no embeddings, no LLM calls) and aligned
with ShellForgeAI's combat-knife product scope.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

INDEX_SCHEMA_VERSION = "1"
INDEX_FILENAME = "incident-index.json"

ITEM_TYPES = (
    "event",
    "session",
    "proposal",
    "export",
    "apply_bundle",
    "actions",
)

_SAFE_SAFETY = {
    "execution_allowed": False,
    "execution_status": "not_executed",
    "mutation_performed": False,
}

_REQUIRED_ITEM_FIELDS = (
    "item_id",
    "item_type",
    "created_at",
    "title",
    "summary",
    "paths",
    "tags",
    "safety",
)


# ---------------------------------------------------------------------------
# Data classes


@dataclass
class IndexItem:
    item_id: str
    item_type: str
    created_at: str = ""
    session_id: str = ""
    proposal_id: str = ""
    proposal_fingerprint: str = ""
    target: str = ""
    component: str = ""
    kind: str = ""
    status: str = ""
    risk: str | None = None
    title: str = ""
    summary: str = ""
    paths: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    safety: dict[str, Any] = field(default_factory=lambda: dict(_SAFE_SAFETY))

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "item_type": self.item_type,
            "created_at": self.created_at,
            "session_id": self.session_id,
            "proposal_id": self.proposal_id,
            "proposal_fingerprint": self.proposal_fingerprint,
            "target": self.target,
            "component": self.component,
            "kind": self.kind,
            "status": self.status,
            "risk": self.risk,
            "title": self.title,
            "summary": self.summary,
            "paths": list(self.paths),
            "tags": list(self.tags),
            "safety": dict(self.safety),
        }


@dataclass
class IncidentIndex:
    schema_version: str = INDEX_SCHEMA_VERSION
    created_at: str = ""
    source_counts: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    items: list[IndexItem] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "source_counts": dict(self.source_counts),
            "warnings": list(self.warnings),
            "items": [i.to_dict() for i in self.items],
        }


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str]
    item_count: int


# ---------------------------------------------------------------------------
# Paths


def audit_dir(data_dir: Path) -> Path:
    return Path(data_dir) / "audit"


def index_path(data_dir: Path) -> Path:
    return audit_dir(data_dir) / INDEX_FILENAME


def _make_item_id() -> str:
    return f"idx_{uuid4().hex[:12]}"


def _shorten(text: str, *, limit: int = 240) -> str:
    s = (text or "").strip()
    if len(s) <= limit:
        return s
    return s[: limit - 1].rstrip() + "…"


def _first_line(text: str) -> str:
    if not text:
        return ""
    for line in text.splitlines():
        s = line.strip().lstrip("#").strip()
        if s:
            return s
    return ""


def _read_json(path: Path) -> tuple[Any, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except FileNotFoundError:
        return None, f"missing: {path}"
    except (OSError, ValueError) as exc:
        return None, f"malformed JSON in {path}: {exc}"


def _safe_safety() -> dict[str, Any]:
    return dict(_SAFE_SAFETY)


# ---------------------------------------------------------------------------
# Audit-event indexing


def _index_event(payload: dict[str, Any]) -> IndexItem:
    summary = _shorten(payload.get("summary") or payload.get("action") or payload.get("kind") or "")
    details = payload.get("details") or {}
    component = ""
    if isinstance(details, dict):
        component = str(details.get("component") or "")
    return IndexItem(
        item_id=_make_item_id(),
        item_type="event",
        created_at=str(payload.get("timestamp") or ""),
        session_id=str(payload.get("session_id") or ""),
        proposal_id=str(payload.get("proposal_id") or ""),
        proposal_fingerprint=str(payload.get("proposal_fingerprint") or ""),
        target=str(payload.get("target") or ""),
        component=component,
        kind=str(payload.get("kind") or ""),
        status=str(payload.get("status") or ""),
        risk=(payload.get("risk") or None),
        title=f"event:{payload.get('kind', '')}/{payload.get('action', '')}",
        summary=summary,
        paths=[str(p) for p in (payload.get("artifacts") or []) if isinstance(p, str)],
        tags=["event", str(payload.get("kind") or ""), str(payload.get("action") or "")],
        safety=_safe_safety(),
    )


def index_audit_events(data_dir: Path, warnings: list[str]) -> list[IndexItem]:
    events_path = audit_dir(data_dir) / "events.jsonl"
    if not events_path.exists():
        return []
    items: list[IndexItem] = []
    try:
        text = events_path.read_text(encoding="utf-8")
    except OSError as exc:
        warnings.append(f"could not read audit events.jsonl: {exc}")
        return []
    for idx, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except ValueError:
            warnings.append(f"skipped malformed audit event line {idx}")
            continue
        if not isinstance(payload, dict):
            warnings.append(f"skipped non-object audit event line {idx}")
            continue
        items.append(_index_event(payload))
    return items


# ---------------------------------------------------------------------------
# Artifact session indexing


def _session_target_from_summary(summary_text: str) -> str:
    m = re.search(r"^Target:\s*([^\n]+)$", summary_text or "", flags=re.MULTILINE)
    if m:
        return m.group(1).strip()
    return ""


def _session_created_at(session_dir: Path) -> str:
    try:
        return datetime.fromtimestamp(session_dir.stat().st_mtime, tz=UTC).isoformat()
    except OSError:
        return ""


def _index_session_dir(session_dir: Path, warnings: list[str]) -> IndexItem | None:
    if not session_dir.is_dir():
        return None
    ev_path = session_dir / "evidence.json"
    summary_path = session_dir / "summary.md"
    plan_path = session_dir / "plan.json"
    runbook_md = session_dir / "runbook.md"
    runbook_json = session_dir / "runbook.json"

    target = ""
    finding_count: int | None = None
    evidence_count: int | None = None
    risk: str | None = None
    title = f"session:{session_dir.name}"
    summary = ""
    paths: list[str] = []

    if ev_path.exists():
        paths.append(str(ev_path))
        payload, err = _read_json(ev_path)
        if err is not None:
            warnings.append(err)
        elif isinstance(payload, dict):
            items = payload.get("items") or []
            if isinstance(items, list):
                evidence_count = len(items)
    if plan_path.exists():
        paths.append(str(plan_path))
    if summary_path.exists():
        paths.append(str(summary_path))
        try:
            text = summary_path.read_text(encoding="utf-8")
            target = _session_target_from_summary(text) or target
            summary = _first_line(text) or summary
        except OSError as exc:
            warnings.append(f"could not read summary.md for {session_dir.name}: {exc}")
    if runbook_md.exists():
        paths.append(str(runbook_md))
    if runbook_json.exists():
        paths.append(str(runbook_json))
        payload, err = _read_json(runbook_json)
        if err is not None:
            warnings.append(err)
        elif isinstance(payload, dict):
            risk_value = payload.get("overall_risk") or payload.get("risk_level")
            if isinstance(risk_value, str):
                risk = risk_value
            problems = payload.get("problems") or []
            if isinstance(problems, list):
                finding_count = len(problems)
            if not target:
                target = str(payload.get("target") or "")

    if not summary:
        bits = []
        if target:
            bits.append(f"target={target}")
        if evidence_count is not None:
            bits.append(f"evidence={evidence_count}")
        if finding_count is not None:
            bits.append(f"findings={finding_count}")
        summary = ", ".join(bits) or f"session {session_dir.name}"

    tags = ["session"]
    if target:
        tags.append(target)

    return IndexItem(
        item_id=_make_item_id(),
        item_type="session",
        created_at=_session_created_at(session_dir),
        session_id=session_dir.name,
        target=target,
        kind="diagnose",
        status="recorded",
        risk=risk,
        title=title,
        summary=_shorten(summary),
        paths=paths,
        tags=tags,
        safety=_safe_safety(),
    )


def index_sessions(data_dir: Path, warnings: list[str]) -> list[IndexItem]:
    root = Path(data_dir) / "artifacts"
    if not root.exists():
        return []
    items: list[IndexItem] = []
    for child in sorted(root.glob("sf_*"), key=lambda p: p.name):
        if not child.is_dir():
            continue
        try:
            item = _index_session_dir(child, warnings)
        except Exception as exc:  # never crash on a single bad source
            warnings.append(f"skipped session {child.name}: {exc}")
            continue
        if item is not None:
            items.append(item)
    return items


# ---------------------------------------------------------------------------
# Proposal indexing


def index_proposals(data_dir: Path, warnings: list[str]) -> list[IndexItem]:
    approvals_root = Path(data_dir) / "approvals"
    if not approvals_root.exists():
        return []
    items: list[IndexItem] = []
    for status_dir in sorted(approvals_root.iterdir(), key=lambda p: p.name):
        if not status_dir.is_dir():
            continue
        status = status_dir.name
        for path in sorted(status_dir.glob("*.proposal.json"), key=lambda p: p.name):
            payload, err = _read_json(path)
            if err is not None:
                warnings.append(err)
                continue
            if not isinstance(payload, dict):
                warnings.append(f"skipped non-object proposal at {path}")
                continue
            proposal_id = str(payload.get("proposal_id") or path.stem)
            risk = payload.get("risk") if isinstance(payload.get("risk"), str) else None
            fp = ""
            fingerprint_field = payload.get("fingerprint")
            if isinstance(fingerprint_field, dict):
                fp = str(fingerprint_field.get("value") or "")
            elif isinstance(fingerprint_field, str):
                fp = fingerprint_field
            approval = payload.get("approval") or {}
            approval_reason = ""
            if isinstance(approval, dict):
                approval_reason = str(approval.get("reason") or "")
            tags = ["proposal", status]
            kind = str(payload.get("kind") or "")
            if kind:
                tags.append(kind)
            component = str(payload.get("component") or "")
            target = str(payload.get("target") or "")
            if target:
                tags.append(target)
            if component:
                tags.append(component)
            summary_bits = []
            summary_bits.append(f"status={status}")
            if approval_reason:
                summary_bits.append(f"reason={approval_reason}")
            if component:
                summary_bits.append(f"component={component}")
            items.append(
                IndexItem(
                    item_id=_make_item_id(),
                    item_type="proposal",
                    created_at=str(payload.get("created_at") or ""),
                    session_id=str((payload.get("source") or {}).get("session_id") or "")
                    if isinstance(payload.get("source"), dict)
                    else "",
                    proposal_id=proposal_id,
                    proposal_fingerprint=fp,
                    target=target,
                    component=component,
                    kind=kind or "approval",
                    status=status,
                    risk=risk,
                    title=str(payload.get("title") or f"proposal:{proposal_id}"),
                    summary=_shorten(", ".join(summary_bits)),
                    paths=[str(path)],
                    tags=tags,
                    safety=_safe_safety(),
                )
            )
    return items


# ---------------------------------------------------------------------------
# Apply bundle indexing


def index_apply_bundles(data_dir: Path, warnings: list[str]) -> list[IndexItem]:
    root = Path(data_dir) / "apply_bundles"
    if not root.exists():
        return []
    items: list[IndexItem] = []
    for bundle_dir in sorted(root.iterdir(), key=lambda p: p.name):
        if not bundle_dir.is_dir():
            continue
        preflight = bundle_dir / "apply-preflight.json"
        if not preflight.exists():
            continue
        payload, err = _read_json(preflight)
        if err is not None:
            warnings.append(err)
            continue
        if not isinstance(payload, dict):
            warnings.append(f"skipped non-object apply preflight at {preflight}")
            continue
        proposal_id = str(payload.get("proposal_id") or bundle_dir.name)
        risk = payload.get("risk") if isinstance(payload.get("risk"), str) else None
        bundle_status = str(payload.get("bundle_status") or "")
        preflight_status = str(payload.get("preflight_status") or "")
        guard_status = str(payload.get("guard_status") or "")
        summary_bits = []
        if preflight_status:
            summary_bits.append(f"preflight={preflight_status}")
        if guard_status:
            summary_bits.append(f"guard={guard_status}")
        if payload.get("blocked_actions") is not None:
            summary_bits.append(f"blocked={payload.get('blocked_actions')}")
        if payload.get("manual_only_actions") is not None:
            summary_bits.append(f"manual={payload.get('manual_only_actions')}")
        paths: list[str] = [str(preflight)]
        for fname in ("apply-preview.md", "operator-commands.sh", "rollback.sh", "validation.md"):
            candidate = bundle_dir / fname
            if candidate.exists():
                paths.append(str(candidate))
        tags = ["apply_bundle"]
        if bundle_status:
            tags.append(bundle_status)
        items.append(
            IndexItem(
                item_id=_make_item_id(),
                item_type="apply_bundle",
                created_at=str(payload.get("created_at") or ""),
                proposal_id=proposal_id,
                proposal_fingerprint=str(payload.get("proposal_fingerprint") or ""),
                kind="apply_preflight",
                status=bundle_status or preflight_status or "recorded",
                risk=risk,
                title=f"apply_bundle:{proposal_id}",
                summary=_shorten(", ".join(summary_bits)),
                paths=paths,
                tags=tags,
                safety=_safe_safety(),
            )
        )
    return items


# ---------------------------------------------------------------------------
# Export indexing


def index_exports(data_dir: Path, warnings: list[str]) -> list[IndexItem]:
    root = Path(data_dir) / "exports"
    if not root.exists():
        return []
    items: list[IndexItem] = []
    for export_dir in sorted(root.iterdir(), key=lambda p: p.name):
        if not export_dir.is_dir():
            continue
        manifest = export_dir / "export-manifest.json"
        if not manifest.exists():
            continue
        payload, err = _read_json(manifest)
        if err is not None:
            warnings.append(err)
            continue
        if not isinstance(payload, dict):
            warnings.append(f"skipped non-object export manifest at {manifest}")
            continue
        export_id = str(payload.get("export_id") or export_dir.name)
        source_type = str(payload.get("source_type") or "")
        source_session = str(payload.get("source_session_id") or "")
        source_proposal = str(payload.get("source_proposal_id") or "")
        redaction = bool(payload.get("redaction_applied"))
        included = payload.get("included_files") or []
        included_count = len(included) if isinstance(included, list) else 0
        proposal_meta = payload.get("proposal") or {}
        component = ""
        risk: str | None = None
        title = f"export:{export_id}"
        if isinstance(proposal_meta, dict):
            component = str(proposal_meta.get("component") or "")
            r = proposal_meta.get("risk")
            if isinstance(r, str):
                risk = r
            t = proposal_meta.get("title")
            if isinstance(t, str) and t:
                title = f"export:{t}"
        tags = ["export", source_type] if source_type else ["export"]
        if redaction:
            tags.append("redacted")
        summary_bits = [f"source={source_type or 'unknown'}"]
        if redaction:
            summary_bits.append("redacted")
        summary_bits.append(f"files={included_count}")
        items.append(
            IndexItem(
                item_id=_make_item_id(),
                item_type="export",
                created_at=str(payload.get("created_at") or ""),
                session_id=source_session,
                proposal_id=source_proposal,
                proposal_fingerprint=(
                    str(proposal_meta.get("fingerprint") or "")
                    if isinstance(proposal_meta, dict)
                    else ""
                ),
                component=component,
                kind="export",
                status="success",
                risk=risk,
                title=title,
                summary=_shorten(", ".join(summary_bits)),
                paths=[str(manifest)],
                tags=tags,
                safety=_safe_safety(),
            )
        )
    return items


# ---------------------------------------------------------------------------
# Actions indexing


def index_actions(data_dir: Path, warnings: list[str]) -> list[IndexItem]:
    root = Path(data_dir) / "actions"
    if not root.exists():
        return []
    items: list[IndexItem] = []
    for actions_dir in sorted(root.iterdir(), key=lambda p: p.name):
        if not actions_dir.is_dir():
            continue
        path = actions_dir / "actions.json"
        if not path.exists():
            continue
        payload, err = _read_json(path)
        if err is not None:
            warnings.append(err)
            continue
        if not isinstance(payload, dict):
            warnings.append(f"skipped non-object actions.json at {path}")
            continue
        proposal_id = str(payload.get("proposal_id") or actions_dir.name)
        summary = payload.get("summary") or {}
        summary_bits = []
        if isinstance(summary, dict):
            for key in ("total_actions", "blocked", "manual_only", "read_only"):
                if key in summary:
                    summary_bits.append(f"{key}={summary[key]}")
        risk = (
            payload.get("proposal_risk") if isinstance(payload.get("proposal_risk"), str) else None
        )
        component = str(payload.get("proposal_component") or "")
        paths: list[str] = [str(path)]
        md_path = actions_dir / "actions.md"
        if md_path.exists():
            paths.append(str(md_path))
        tags = ["actions"]
        if component:
            tags.append(component)
        items.append(
            IndexItem(
                item_id=_make_item_id(),
                item_type="actions",
                created_at=str(payload.get("created_at") or ""),
                proposal_id=proposal_id,
                proposal_fingerprint=str(payload.get("proposal_fingerprint") or ""),
                component=component,
                kind="actions",
                status=str(payload.get("status") or "compiled"),
                risk=risk,
                title=f"actions:{proposal_id}",
                summary=_shorten(", ".join(summary_bits)),
                paths=paths,
                tags=tags,
                safety=_safe_safety(),
            )
        )
    return items


# ---------------------------------------------------------------------------
# Build / write / read


def build_index(data_dir: Path) -> IncidentIndex:
    """Build a deterministic incident index by reading existing artifacts.

    Never executes anything; never mutates any source artifact. Malformed
    source files are skipped with a warning instead of crashing.
    """
    warnings: list[str] = []
    events = index_audit_events(data_dir, warnings)
    sessions = index_sessions(data_dir, warnings)
    proposals = index_proposals(data_dir, warnings)
    exports = index_exports(data_dir, warnings)
    bundles = index_apply_bundles(data_dir, warnings)
    actions = index_actions(data_dir, warnings)
    items = events + sessions + proposals + exports + bundles + actions
    return IncidentIndex(
        schema_version=INDEX_SCHEMA_VERSION,
        created_at=datetime.now(UTC).isoformat(),
        source_counts={
            "events": len(events),
            "sessions": len(sessions),
            "proposals": len(proposals),
            "exports": len(exports),
            "apply_bundles": len(bundles),
            "actions": len(actions),
        },
        warnings=warnings,
        items=items,
    )


def write_index(data_dir: Path, index: IncidentIndex) -> Path:
    path = index_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(index.to_dict(), indent=2), encoding="utf-8")
    return path


def load_index(data_dir: Path) -> tuple[dict[str, Any] | None, str | None]:
    path = index_path(data_dir)
    if not path.exists():
        return None, f"index file missing: {path}"
    return _read_json(path)


# ---------------------------------------------------------------------------
# Validation


def validate_index_payload(payload: Any) -> ValidationResult:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ValidationResult(ok=False, errors=["index root must be an object"], item_count=0)
    if not payload.get("schema_version"):
        errors.append("missing schema_version")
    source_counts = payload.get("source_counts")
    if source_counts is not None:
        if not isinstance(source_counts, dict):
            errors.append("source_counts must be an object")
        else:
            for k, v in source_counts.items():
                if not isinstance(v, int):
                    errors.append(f"source_counts.{k} must be numeric")
    items = payload.get("items")
    if not isinstance(items, list):
        return ValidationResult(ok=False, errors=errors + ["items must be a list"], item_count=0)
    seen: set[str] = set()
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"item {idx}: must be an object")
            continue
        missing = [f for f in _REQUIRED_ITEM_FIELDS if f not in item]
        if missing:
            errors.append(f"item {idx}: missing fields {','.join(missing)}")
        iid = str(item.get("item_id") or "")
        if iid and iid in seen:
            errors.append(f"duplicate item_id: {iid}")
        seen.add(iid)
        itype = item.get("item_type")
        if itype is not None and itype not in ITEM_TYPES:
            errors.append(f"item {iid or idx}: unknown item_type '{itype}'")
        paths = item.get("paths")
        if paths is not None and (
            not isinstance(paths, list) or not all(isinstance(p, str) for p in paths)
        ):
            errors.append(f"item {iid or idx}: paths must be a list of strings")
        safety = item.get("safety") or {}
        if not isinstance(safety, dict):
            errors.append(f"item {iid or idx}: safety must be an object")
            continue
        if "execution_allowed" in safety and safety["execution_allowed"] is not False:
            errors.append(f"item {iid or idx}: execution_allowed must be false")
        if "mutation_performed" in safety and safety["mutation_performed"] is not False:
            errors.append(f"item {iid or idx}: mutation_performed must be false")
        if "execution_status" in safety and safety["execution_status"] != "not_executed":
            errors.append(f"item {iid or idx}: execution_status must be 'not_executed'")
    return ValidationResult(ok=not errors, errors=errors, item_count=len(items))


# ---------------------------------------------------------------------------
# Search


@dataclass
class SearchFilters:
    component: str | None = None
    target: str | None = None
    kind: str | None = None
    status: str | None = None
    risk: str | None = None
    proposal: str | None = None
    session: str | None = None
    item_type: str | None = None
    since: str | None = None


def _haystack_for(item: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "title",
        "summary",
        "component",
        "target",
        "kind",
        "status",
        "session_id",
        "proposal_id",
        "item_id",
        "item_type",
    ):
        v = item.get(key)
        if isinstance(v, str):
            parts.append(v)
    tags = item.get("tags") or []
    if isinstance(tags, list):
        parts.extend(str(t) for t in tags if isinstance(t, str))
    paths = item.get("paths") or []
    if isinstance(paths, list):
        for p in paths:
            if isinstance(p, str):
                parts.append(p)
                parts.append(os.path.basename(p))
    return " \n ".join(parts).lower()


def _field_match(item: dict[str, Any], field: str, value: str) -> bool:
    actual = item.get(field)
    if actual is None:
        return False
    return str(actual).lower() == value.lower()


def _field_contains(item: dict[str, Any], field: str, value: str) -> bool:
    actual = item.get(field)
    if actual is None:
        return False
    return value.lower() in str(actual).lower()


def search_items(
    items: list[dict[str, Any]],
    *,
    query: str | None = None,
    filters: SearchFilters | None = None,
) -> list[dict[str, Any]]:
    filters = filters or SearchFilters()
    q = (query or "").strip().lower()
    tokens = [t for t in q.split() if t]
    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if filters.component and not _field_match(item, "component", filters.component):
            continue
        if filters.target and not _field_match(item, "target", filters.target):
            continue
        if filters.kind and not _field_match(item, "kind", filters.kind):
            continue
        if filters.status and not _field_match(item, "status", filters.status):
            continue
        if filters.risk:
            risk_value = item.get("risk")
            if risk_value is None or str(risk_value).lower() != filters.risk.lower():
                continue
        if filters.proposal and not _field_contains(item, "proposal_id", filters.proposal):
            continue
        if filters.session and not _field_contains(item, "session_id", filters.session):
            continue
        if filters.item_type and not _field_match(item, "item_type", filters.item_type):
            continue
        if filters.since:
            ts = str(item.get("created_at") or "")
            if ts < filters.since:
                continue
        if tokens:
            haystack = _haystack_for(item)
            if not all(tok in haystack for tok in tokens):
                continue
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# Ask-routing helpers


_INCIDENT_SEARCH_TOKENS = (
    "search audit",
    "show audit timeline",
    "show operator trail",
    "what happened in this incident",
    "search incident",
    "search incidents",
    "search the audit",
    "audit search",
    "incident search",
    "find drift refusals",
    "find guard failures",
    "find guard refusals",
    "show recent guard failures",
    "show recent drift",
    "show recent refusals",
    "find approved proposals",
    "find pending proposals",
    "find rejected proposals",
    "find exports for this proposal",
    "find exports for proposal",
    "search incident history",
    "show recent medium risk",
    "show medium risk items",
    "find medium risk",
    "find high risk",
    "find low risk",
    "find latest docker diagnosis",
    "find docker diagnosis",
    "find bad-network",
    "find bad network",
    "search for bad-network",
    "search for bad network",
    "what happened with sfai",
    "what happened with",
)

_DID_ANYTHING_EXECUTE_TOKENS = (
    "did anything execute",
    "did anything run",
    "did shellforgeai execute",
    "did shellforge execute",
    "did shellforgeai run anything",
    "did shellforge run anything",
    "was anything executed",
    "was anything run",
    "did we execute",
)


@dataclass(frozen=True)
class IncidentSearchIntent:
    matched: bool
    query: str = ""
    risk: str | None = None
    kind: str | None = None
    status: str | None = None
    item_type: str | None = None


def is_incident_search_ask_intent(text: str) -> IncidentSearchIntent:
    raw = (text or "").strip()
    lowered = raw.lower()
    if not lowered:
        return IncidentSearchIntent(matched=False)
    matched = any(tok in lowered for tok in _INCIDENT_SEARCH_TOKENS)
    if not matched:
        return IncidentSearchIntent(matched=False)
    risk: str | None = None
    for r in ("low", "medium", "high"):
        if f" {r} risk" in lowered or lowered.startswith(f"{r} risk"):
            risk = r
            break
    kind: str | None = None
    status: str | None = None
    item_type: str | None = None
    if "drift" in lowered or "refusal" in lowered or "refused" in lowered:
        status = "refused"
    if "guard" in lowered:
        kind = "guard_check"
    if "approved" in lowered:
        status = "approved"
        item_type = "proposal"
    elif "pending" in lowered:
        status = "pending"
        item_type = "proposal"
    elif "rejected" in lowered:
        status = "rejected"
        item_type = "proposal"
    if "export" in lowered and item_type is None:
        item_type = "export"
    query = ""
    for token in (
        "find ",
        "search audit for ",
        "search for ",
        "search incident history for ",
        "what happened with ",
        "show me ",
        "show recent ",
        "show ",
    ):
        if token in lowered:
            idx = lowered.index(token) + len(token)
            query = raw[idx:].strip().rstrip("?.! ")
            break
    if query:
        descriptor_stop = {
            "drift",
            "refusal",
            "refusals",
            "refused",
            "guard",
            "failure",
            "failures",
            "approved",
            "pending",
            "rejected",
            "proposal",
            "proposals",
            "export",
            "exports",
            "medium",
            "high",
            "low",
            "risk",
            "items",
            "recent",
        }
        cleaned = [t for t in query.split() if t.lower() not in descriptor_stop]
        query = " ".join(cleaned).strip()
    return IncidentSearchIntent(
        matched=True,
        query=query,
        risk=risk,
        kind=kind,
        status=status,
        item_type=item_type,
    )


def is_did_anything_execute_intent(text: str) -> bool:
    lowered = (text or "").lower()
    return any(tok in lowered for tok in _DID_ANYTHING_EXECUTE_TOKENS)


__all__ = [
    "INDEX_SCHEMA_VERSION",
    "INDEX_FILENAME",
    "ITEM_TYPES",
    "IndexItem",
    "IncidentIndex",
    "ValidationResult",
    "SearchFilters",
    "IncidentSearchIntent",
    "audit_dir",
    "index_path",
    "build_index",
    "write_index",
    "load_index",
    "validate_index_payload",
    "search_items",
    "is_incident_search_ask_intent",
    "is_did_anything_execute_intent",
]
