from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from shellforgeai.core.approvals import find_proposal_path, list_proposals, load_proposal_from_path
from shellforgeai.core.mission import list_missions

ReferenceKind = Literal["proposal", "mission", "any"]


@dataclass(frozen=True)
class ReferenceFilters:
    restart_only: bool = False
    target: str = ""
    status_preference: str = ""
    include_archived: bool = False
    include_canceled: bool = False
    include_rejected: bool = False
    stale_after_hours: int = 24


@dataclass(frozen=True)
class ReferenceCandidate:
    kind: Literal["proposal", "mission"]
    id: str
    path: str
    created_at: str = ""
    updated_at: str = ""
    status_label: str = ""
    target: str = ""
    component: str = ""
    source_session: str = ""
    reason: str = ""
    score: tuple[int, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ReferenceResolution:
    status: Literal["resolved", "ambiguous", "not_found"]
    kind: str = ""
    id: str = ""
    path: str = ""
    created_at: str = ""
    updated_at: str = ""
    status_label: str = ""
    target: str = ""
    component: str = ""
    source_session: str = ""
    reason: str = ""
    stale: bool = False
    candidates: tuple[ReferenceCandidate, ...] = ()


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    with contextlib.suppress(ValueError):
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return None


def _id_hint(phrase: str) -> str:
    m = re.search(r"\b((?:prop|mission)[-_][a-zA-Z0-9_.-]+)\b", phrase)
    return m.group(1) if m else ""


def _needs_recency_guard(phrase: str) -> bool:
    t = phrase.lower()
    return any(tok in t for tok in ("this", "latest", "current", "most recent"))


def resolve_reference(
    kind: ReferenceKind, phrase: str, filters: ReferenceFilters, data_dir: Path
) -> ReferenceResolution:
    explicit_id = _id_hint(phrase or "")
    if explicit_id.startswith("prop"):
        pth, _ = find_proposal_path(data_dir, explicit_id)
        if pth is None:
            return ReferenceResolution(
                status="not_found", reason=f"explicit id not found: {explicit_id}"
            )
        p = load_proposal_from_path(pth)
        return ReferenceResolution(
            status="resolved",
            kind="proposal",
            id=p.proposal_id,
            path=str(pth),
            created_at=p.created_at,
            status_label=p.status,
            target=p.target,
            component=p.component,
            source_session=p.source.session_id,
        )

    missions = list_missions(data_dir)
    if explicit_id.startswith("mission"):
        for row in missions:
            if str(row.get("mission_id") or "") == explicit_id:
                return ReferenceResolution(
                    status="resolved",
                    kind="mission",
                    id=explicit_id,
                    path=str(
                        Path(data_dir) / "missions" / "restart" / explicit_id / "mission.json"
                    ),
                    created_at=str(row.get("created_at") or ""),
                    updated_at=str(row.get("updated_at") or ""),
                    status_label=str(row.get("status") or ""),
                    target=str(row.get("target") or ""),
                    source_session=str(row.get("session_id") or ""),
                    reason=str(row.get("reason") or ""),
                )
        return ReferenceResolution(
            status="not_found", reason=f"explicit id not found: {explicit_id}"
        )

    candidates: list[ReferenceCandidate] = []
    lower_phrase = (phrase or "").lower()
    target_hint = (filters.target or "").lower()

    if kind in ("proposal", "any"):
        for status, proposal in list_proposals(data_dir):
            if status == "archived" and not filters.include_archived:
                continue
            if status == "canceled" and not filters.include_canceled:
                continue
            if status == "rejected" and not filters.include_rejected:
                continue
            if filters.restart_only and proposal.kind != "docker_restart":
                continue
            blob = " ".join(
                [proposal.target, proposal.component, proposal.notes, proposal.title]
            ).lower()
            target_match = int(
                bool(target_hint and target_hint in blob)
                or (
                    not target_hint
                    and any(tok in blob for tok in ["web", "shellforgeai"] if tok in lower_phrase)
                )
            )
            status_pref = filters.status_preference.lower()
            status_match = 1 if (not status_pref or status_pref == status.lower()) else 0
            ts = _parse_ts(proposal.created_at)
            created_score = (
                int(ts.timestamp())
                if ts
                else int(
                    (find_proposal_path(data_dir, proposal.proposal_id)[0] or Path())
                    .stat()
                    .st_mtime
                )
                if find_proposal_path(data_dir, proposal.proposal_id)[0]
                else 0
            )
            score = (
                1,
                int(proposal.kind == "docker_restart"),
                target_match,
                status_match,
                created_score,
            )
            path, _ = find_proposal_path(data_dir, proposal.proposal_id)
            candidates.append(
                ReferenceCandidate(
                    kind="proposal",
                    id=proposal.proposal_id,
                    path=str(path or ""),
                    created_at=proposal.created_at,
                    status_label=status,
                    target=proposal.target,
                    component=proposal.component,
                    source_session=proposal.source.session_id,
                    reason=proposal.approval.reason,
                    score=score,
                )
            )

    if kind in ("mission", "any"):
        for row in missions:
            if filters.restart_only and str(row.get("mission_type") or "") != "docker_restart":
                continue
            status = str(row.get("status") or "")
            status_pref = filters.status_preference.lower()
            status_match = 1 if (not status_pref or status_pref == status.lower()) else 0
            target = str(row.get("target") or "")
            blob = " ".join([target, str(row.get("proposal_id") or "")]).lower()
            target_match = int(bool(target_hint and target_hint in blob))
            ts = _parse_ts(str(row.get("created_at") or ""))
            created_score = int(ts.timestamp()) if ts else 0
            mid = str(row.get("mission_id") or "")
            candidates.append(
                ReferenceCandidate(
                    kind="mission",
                    id=mid,
                    path=str(Path(data_dir) / "missions" / "restart" / mid / "mission.json"),
                    created_at=str(row.get("created_at") or ""),
                    updated_at=str(row.get("updated_at") or ""),
                    status_label=status,
                    target=target,
                    source_session=str(row.get("session_id") or ""),
                    reason=str(row.get("reason") or ""),
                    score=(1, 1, target_match, status_match, created_score),
                )
            )

    if not candidates:
        return ReferenceResolution(status="not_found", reason="no matching artifacts")
    ranked = sorted(candidates, key=lambda c: c.score, reverse=True)
    top = ranked[0]
    if len(ranked) > 1 and ranked[1].score == top.score:
        return ReferenceResolution(
            status="ambiguous", reason="multiple close candidates", candidates=tuple(ranked[:3])
        )

    stale = False
    if _needs_recency_guard(lower_phrase):
        ts = _parse_ts(top.updated_at) or _parse_ts(top.created_at)
        if ts is not None:
            stale = (datetime.now(UTC) - ts).total_seconds() > (filters.stale_after_hours * 3600)
    return ReferenceResolution(
        status="resolved",
        kind=top.kind,
        id=top.id,
        path=top.path,
        created_at=top.created_at,
        updated_at=top.updated_at,
        status_label=top.status_label,
        target=top.target,
        component=top.component,
        source_session=top.source_session,
        reason=top.reason,
        stale=stale,
        candidates=tuple(ranked[:3]) if stale else (),
    )
