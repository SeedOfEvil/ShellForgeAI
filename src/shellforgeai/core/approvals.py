"""Approval queue / mutation proposal objects (PR32).

ShellForgeAI is a Tier-3 triage tool. It never executes mutation. The
approval queue is a *paper trail*: it turns operator-run runbook options
into proposal objects that an operator can mark ``approved``, ``rejected``,
``canceled``, or ``archived``. Marking a proposal ``approved`` does NOT
execute anything; it only records that a human authorized a future
operator-run change.

PR33 consumes these proposals to generate an operator execution bundle
(``apply_bundle.py``). Generation is still inspection-only.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

PROPOSAL_SCHEMA_VERSION = "1"

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_CANCELED = "canceled"
STATUS_ARCHIVED = "archived"
APPROVAL_STATUSES = (
    STATUS_PENDING,
    STATUS_APPROVED,
    STATUS_REJECTED,
    STATUS_CANCELED,
    STATUS_ARCHIVED,
)

RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"
RISK_VALUES = (RISK_LOW, RISK_MEDIUM, RISK_HIGH)

CONFIDENCE_VALUES = ("low", "medium", "high")

EXECUTION_DISABLED_REASON = "PR32 only records proposals; apply remains validation-only."


class ProposalSource(BaseModel):
    session_id: str = ""
    runbook: str = ""
    evidence: str = ""
    summary: str = ""


class ProposalExecution(BaseModel):
    allowed: bool = False
    status: str = "not_executed"
    reason: str = EXECUTION_DISABLED_REASON


class ProposalApproval(BaseModel):
    approved_by: str | None = None
    approved_at: str | None = None
    rejected_by: str | None = None
    rejected_at: str | None = None
    canceled_by: str | None = None
    canceled_at: str | None = None
    archived_by: str | None = None
    archived_at: str | None = None
    reason: str | None = None


class Proposal(BaseModel):
    schema_version: str = PROPOSAL_SCHEMA_VERSION
    proposal_id: str
    created_at: str = ""
    status: str = STATUS_PENDING
    source: ProposalSource = Field(default_factory=ProposalSource)
    target: str = ""
    component: str = ""
    kind: str = ""
    title: str = ""
    risk: str = RISK_MEDIUM
    impact: str = ""
    confidence: str = "medium"
    evidence: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    proposed_steps: list[str] = Field(default_factory=list)
    rollback: list[str] = Field(default_factory=list)
    verification: list[str] = Field(default_factory=list)
    safety_labels: list[str] = Field(default_factory=list)
    notes: str = ""
    fingerprint: dict[str, str] = Field(default_factory=dict)
    execution: ProposalExecution = Field(default_factory=ProposalExecution)
    approval: ProposalApproval = Field(default_factory=ProposalApproval)

    def is_mutating(self) -> bool:
        return _is_mutating_steps(self.proposed_steps)


_MUTATION_TOKENS = (
    "restart",
    "recreate",
    "install",
    "apt install",
    "apt remove",
    "yum install",
    "dnf install",
    "update",
    "upgrade",
    "chmod",
    "chown",
    "edit",
    "rm ",
    "rm -",
    "delete",
    "firewall",
    "iptables",
    "ufw",
    "route add",
    "ip route",
    "dns",
    "docker compose up -d",
    "docker compose down",
    "docker restart",
    "docker rm",
    "docker stop",
    "docker kill",
    "systemctl restart",
    "systemctl start",
    "systemctl stop",
    "systemctl reload",
    "service restart",
    "service start",
    "service stop",
    "service reload",
)


_DESTRUCTIVE_BROAD_TOKENS = (
    "rm -rf /",
    "rm -rf *",
    "chmod 777",
    "chmod -r 777",
    "chown -r root",
    "docker system prune",
    "docker volume rm",
    "iptables -f",
)


def _is_mutating_steps(steps: list[str]) -> bool:
    blob = " ".join(s.lower() for s in steps)
    return any(tok in blob for tok in _MUTATION_TOKENS)


def has_broad_destructive_words(steps: list[str]) -> bool:
    blob = " ".join(s.lower() for s in steps)
    return any(tok in blob for tok in _DESTRUCTIVE_BROAD_TOKENS)


def _has_service_impacting_tokens(text: str) -> bool:
    blob = text.lower()
    return (
        "service-impacting" in blob
        or "docker compose up -d" in blob
        or "docker restart" in blob
        or "systemctl restart" in blob
        or "systemctl reload" in blob
        or "service restart" in blob
        or "service reload" in blob
    )


# ---------------------------------------------------------------------------
# Storage layout


def approvals_root(data_dir: Path) -> Path:
    return Path(data_dir) / "approvals"


def _status_dir(data_dir: Path, status: str) -> Path:
    if status not in APPROVAL_STATUSES:
        raise ValueError(f"unknown status: {status}")
    return approvals_root(data_dir) / status


def proposal_filename(proposal_id: str) -> str:
    return f"{proposal_id}.proposal.json"


def _ensure_dirs(data_dir: Path) -> None:
    for s in APPROVAL_STATUSES:
        _status_dir(data_dir, s).mkdir(parents=True, exist_ok=True)


def find_proposal_path(data_dir: Path, proposal_id: str) -> tuple[Path | None, str | None]:
    """Search every status directory for ``<id>.proposal.json``.

    Prefers ``approved`` if duplicates exist (should not happen).
    Returns ``(path, status)`` or ``(None, None)``.
    """
    name = proposal_filename(proposal_id)
    order = (STATUS_APPROVED, STATUS_PENDING, STATUS_REJECTED, STATUS_CANCELED, STATUS_ARCHIVED)
    for status in order:
        candidate = _status_dir(data_dir, status) / name
        if candidate.exists():
            return candidate, status
    return None, None


def load_proposal_from_path(path: Path) -> Proposal:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return Proposal.model_validate(payload)


def write_proposal(data_dir: Path, proposal: Proposal) -> Path:
    """Write proposal into the directory matching its status."""
    _ensure_dirs(data_dir)
    target = _status_dir(data_dir, proposal.status) / proposal_filename(proposal.proposal_id)
    target.write_text(proposal.model_dump_json(indent=2), encoding="utf-8")
    return target


def latest_approved_proposal(data_dir: Path) -> Proposal | None:
    """Return the newest approved proposal (by mtime)."""
    approved_dir = _status_dir(data_dir, STATUS_APPROVED)
    if not approved_dir.exists():
        return None
    candidates = sorted(
        (p for p in approved_dir.glob("*.proposal.json") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
    )
    if not candidates:
        return None
    return load_proposal_from_path(candidates[-1])


# ---------------------------------------------------------------------------
# Schema validation


def validate_proposal_payload(payload: dict[str, Any]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    required = (
        "schema_version",
        "proposal_id",
        "status",
        "risk",
        "title",
        "proposed_steps",
        "execution",
        "source",
    )
    for k in required:
        if k not in payload:
            errors.append(f"missing required field: {k}")
    if payload.get("status") and payload["status"] not in APPROVAL_STATUSES:
        errors.append(f"status must be one of {APPROVAL_STATUSES}")
    if payload.get("risk") and payload["risk"] not in RISK_VALUES:
        errors.append(f"risk must be one of {RISK_VALUES}")
    if payload.get("confidence") and payload["confidence"] not in CONFIDENCE_VALUES:
        errors.append(f"confidence must be one of {CONFIDENCE_VALUES}")
    steps = payload.get("proposed_steps") or []
    if not steps:
        errors.append("proposed_steps must not be empty")
    execution = payload.get("execution") or {}
    if execution.get("allowed", False) is not False:
        errors.append("execution.allowed must be false in this alpha")
    if execution.get("status", "not_executed") != "not_executed":
        errors.append("execution.status must be 'not_executed' in this alpha")
    risk = payload.get("risk")
    rollback = payload.get("rollback") or []
    if risk in (RISK_MEDIUM, RISK_HIGH) and not rollback:
        errors.append(f"{risk}-risk proposal is missing rollback")
    verification = payload.get("verification") or []
    if not verification:
        warnings.append("proposal has no verification steps")
    labels = payload.get("safety_labels") or []
    if _is_mutating_steps(steps):
        if "OPERATOR-RUN" not in labels:
            errors.append("mutating proposal must include safety_label 'OPERATOR-RUN'")
        if "REQUIRES APPROVAL" not in labels:
            errors.append("mutating proposal must include safety_label 'REQUIRES APPROVAL'")
    if risk == RISK_HIGH and "HIGH-RISK" not in labels:
        warnings.append("high-risk proposal is missing safety_label 'HIGH-RISK'")
    if has_broad_destructive_words(steps):
        warnings.append("broad destructive words detected in proposed_steps")
        if "BACKUP-REQUIRED" not in labels:
            warnings.append("destructive proposal is missing safety_label 'BACKUP-REQUIRED'")
    source = payload.get("source") or {}
    if not (source.get("runbook") or source.get("evidence") or source.get("session_id")):
        warnings.append("source has no runbook/evidence/session_id reference")
    fp = payload.get("fingerprint") or {}
    if not isinstance(fp, dict) or not fp:
        errors.append("missing required field: fingerprint")
    else:
        if fp.get("algorithm") != "sha256":
            errors.append("fingerprint.algorithm must be 'sha256'")
        value = str(fp.get("value") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            errors.append("fingerprint.value must be a 64-char sha256 hex")
    return errors, warnings


# ---------------------------------------------------------------------------
# Proposal creation from runbook


_LABEL_PATTERNS = (
    ("OPERATOR-RUN", re.compile(r"OPERATOR-RUN", re.IGNORECASE)),
    ("REQUIRES APPROVAL", re.compile(r"REQUIRES\s+APPROVAL", re.IGNORECASE)),
    ("SERVICE-IMPACTING", re.compile(r"SERVICE-IMPACTING", re.IGNORECASE)),
    ("ROLLBACK ADVISED", re.compile(r"ROLLBACK\s+ADVISED", re.IGNORECASE)),
)


_KIND_BY_PROBLEM_KIND = {
    "missing-env": "container_env_config_change",
    "bad-volume-perms": "container_mount_permission_change",
    "restart-loop": "container_startup_config_change",
    "bad-network": "container_upstream_config_change",
    "exited-nonzero": "container_config_change",
    "noisy-logs": "container_log_investigation",
}


def _derive_kind(option: dict[str, Any]) -> str:
    """Map a runbook option to a stable proposal ``kind`` string."""
    applies_to = option.get("applies_to") or []
    for a in applies_to:
        a_str = str(a)
        # Format we emit from runbook: ``problem:<component>:<problem_kind>``
        if a_str.startswith("problem:"):
            parts = a_str.split(":", 2)
            if len(parts) == 3:
                pk = parts[2]
                if pk in _KIND_BY_PROBLEM_KIND:
                    return _KIND_BY_PROBLEM_KIND[pk]
        if a_str.startswith("general:"):
            return "general_investigation"
    title = str(option.get("title") or "").lower()
    for pk, kind in _KIND_BY_PROBLEM_KIND.items():
        if pk in title:
            return kind
    if "docker" in title:
        return "container_config_change"
    return "operator_runbook_option"


def _derive_safety_labels(option: dict[str, Any], steps: list[str], risk: str) -> list[str]:
    blob = " ".join(
        [
            str(option.get("title") or ""),
            str(option.get("impact") or ""),
            " ".join(steps),
            str(option.get("safety_label") or option.get("label") or ""),
        ]
    )
    labels: list[str] = []
    for label, pattern in _LABEL_PATTERNS:
        if pattern.search(blob):
            labels.append(label)
    mutating = _is_mutating_steps(steps)
    if mutating:
        if "OPERATOR-RUN" not in labels:
            labels.insert(0, "OPERATOR-RUN")
        if "REQUIRES APPROVAL" not in labels:
            labels.append("REQUIRES APPROVAL")
    if _has_service_impacting_tokens(blob) and "SERVICE-IMPACTING" not in labels:
        labels.append("SERVICE-IMPACTING")
    if risk == RISK_HIGH and "HIGH-RISK" not in labels:
        labels.append("HIGH-RISK")
    if has_broad_destructive_words(steps) and "BACKUP-REQUIRED" not in labels:
        labels.append("BACKUP-REQUIRED")
    return labels


def _derive_risk(option: dict[str, Any], steps: list[str]) -> str:
    raw = str(option.get("risk") or RISK_MEDIUM).lower()
    if raw not in RISK_VALUES:
        raw = RISK_MEDIUM
    if has_broad_destructive_words(steps):
        return RISK_HIGH
    return raw


def _derive_confidence(option: dict[str, Any]) -> str:
    raw = str(option.get("confidence") or "medium").lower()
    if raw in CONFIDENCE_VALUES:
        return raw
    return "medium"


def _slug(value: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()
    return s[:64] or "option"


def _norm_lines(values: list[str]) -> list[str]:
    return [" ".join(str(v).split()).strip().lower() for v in values if str(v).strip()]


def compute_proposal_fingerprint_payload(
    *,
    session_id: str,
    option_id: str,
    component: str,
    kind: str,
    title: str,
    risk: str,
    steps: list[str],
    rollback: list[str],
    verification: list[str],
) -> dict[str, str]:
    fp_source = {
        "session_id": session_id,
        "runbook_option_id": option_id,
        "component": component,
        "kind": kind,
        "title": title,
        "risk": risk,
        "proposed_steps": _norm_lines(steps),
        "rollback": _norm_lines(rollback),
        "verification": _norm_lines(verification),
    }
    digest = hashlib.sha256(
        json.dumps(fp_source, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "algorithm": "sha256",
        "value": digest,
        "source_session_id": session_id,
        "runbook_option_id": option_id,
        "component": component,
        "kind": kind,
        "title": title,
    }


def make_proposal_id(*, component: str = "", option_id: str = "") -> str:
    """Stable, readable proposal id: ``prop_YYYYMMDD_HHMMSS_<short>``."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    short = uuid4().hex[:6]
    return f"prop_{stamp}_{short}"


def make_proposal_id_for(option_id: str, *, component: str = "", session_id: str = "") -> str:
    """Deterministic-ish id when a stable session/option pair is available.

    Used when migrating an existing session into proposals so re-runs do not
    duplicate. Falls back to the time-stamped form when inputs are empty.
    """
    if not option_id and not component:
        return make_proposal_id()
    base = _slug(option_id or component)
    short = uuid4().hex[:6]
    if session_id:
        return f"prop_{_slug(session_id)[:16]}_{base[:24]}_{short}"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"prop_{stamp}_{base[:24]}_{short}"


def proposals_from_runbook_payload(
    payload: dict[str, Any],
    *,
    source_runbook: str = "",
    source_evidence: str = "",
    source_summary: str = "",
    include_low: bool = False,
) -> list[Proposal]:
    """Build pending Proposal objects from a runbook JSON payload.

    Defaults skip low-risk read-only investigation-only options.
    ``include_low=True`` keeps them as low-risk, read-only proposals.
    """
    session_id = str(payload.get("session_id") or "session")
    if not source_evidence:
        source_evidence = str(payload.get("source_evidence") or "")
    target = str(payload.get("target") or "")
    now = datetime.now(timezone.utc).isoformat()
    out: list[Proposal] = []
    for option in payload.get("remediation_options") or []:
        opt_id = str(option.get("id") or option.get("title") or "option")
        applies_to = option.get("applies_to") or []
        component = ""
        for a in applies_to:
            a_str = str(a)
            if a_str and not a_str.startswith("problem:") and not a_str.startswith("general:"):
                component = a_str
                break
        if not component:
            component = "general"
        steps = [str(s) for s in (option.get("steps") or [])]
        risk = _derive_risk(option, steps)
        mutating = _is_mutating_steps(steps)
        if not mutating and risk == RISK_LOW and not include_low:
            continue
        labels = _derive_safety_labels(option, steps, risk)
        kind = _derive_kind(option)
        rollback = [str(r) for r in (option.get("rollback") or [])]
        verification = [str(v) for v in (option.get("verification") or [])]
        title = str(option.get("title") or "")
        fingerprint = compute_proposal_fingerprint_payload(
            session_id=session_id,
            option_id=opt_id,
            component=component,
            kind=kind,
            title=title,
            risk=risk,
            steps=steps,
            rollback=rollback,
            verification=verification,
        )
        proposal = Proposal(
            proposal_id=make_proposal_id_for(opt_id, component=component, session_id=session_id),
            created_at=now,
            status=STATUS_PENDING,
            source=ProposalSource(
                session_id=session_id,
                runbook=source_runbook,
                evidence=source_evidence,
                summary=source_summary,
            ),
            target=target,
            component=component,
            kind=kind,
            title=title,
            risk=risk,
            impact=str(option.get("impact") or ""),
            confidence=_derive_confidence(option),
            evidence=[str(e) for e in (option.get("evidence") or [])],
            preconditions=[str(p) for p in (option.get("preconditions") or [])],
            proposed_steps=steps,
            rollback=rollback,
            verification=verification,
            safety_labels=labels,
            notes=str(option.get("notes") or ""),
            execution=ProposalExecution(),
            fingerprint=fingerprint,
        )
        out.append(proposal)
    return out


def _resolve_runbook_target(data_dir: Path, target: str | Path) -> Path:
    """Accept a runbook.json path, a session id, or a session dir."""
    p = Path(target)
    if p.is_file():
        return p
    if p.is_dir():
        rb = p / "runbook.json"
        if rb.exists():
            return rb
        raise FileNotFoundError(f"runbook.json not found in {p}")
    if str(target).startswith("sf_"):
        sess = Path(data_dir) / "artifacts" / str(target)
        rb = sess / "runbook.json"
        if rb.exists():
            return rb
        raise FileNotFoundError(f"runbook.json not found in {sess}")
    raise FileNotFoundError(f"runbook source not found: {target}")


def latest_runbook(data_dir: Path) -> Path | None:
    root = Path(data_dir) / "artifacts"
    if not root.exists():
        return None
    candidates = sorted(
        (p for p in root.glob("sf_*/runbook.json") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
    )
    return candidates[-1] if candidates else None


def create_proposals_for_session(
    data_dir: Path,
    session_target: str | Path,
    *,
    include_low: bool = False,
) -> list[Proposal]:
    """Read ``runbook.json`` from a session and write pending proposals."""
    runbook_path = _resolve_runbook_target(data_dir, session_target)
    payload = json.loads(runbook_path.read_text(encoding="utf-8"))
    summary_path = runbook_path.parent / "summary.md"
    evidence_path = runbook_path.parent / "evidence.json"
    proposals = proposals_from_runbook_payload(
        payload,
        source_runbook=str(runbook_path),
        source_evidence=str(evidence_path) if evidence_path.exists() else "",
        source_summary=str(summary_path) if summary_path.exists() else "",
        include_low=include_low,
    )
    _ensure_dirs(data_dir)
    existing_by_fp: dict[str, tuple[str, Proposal]] = {}
    for status, existing in list_proposals(data_dir):
        value = str((existing.fingerprint or {}).get("value") or "")
        if value:
            existing_by_fp[value] = (status, existing)
    created: list[Proposal] = []
    for p in proposals:
        fp = str((p.fingerprint or {}).get("value") or "")
        if fp and fp in existing_by_fp:
            continue
        write_proposal(data_dir, p)
        created.append(p)
    return created


# ---------------------------------------------------------------------------
# Transitions


def _set_actor_fields(
    proposal: Proposal, *, status: str, reason: str, actor: str, when: str
) -> None:
    proposal.approval.reason = reason
    if status == STATUS_APPROVED:
        proposal.approval.approved_by = actor or "operator"
        proposal.approval.approved_at = when
    elif status == STATUS_REJECTED:
        proposal.approval.rejected_by = actor or "operator"
        proposal.approval.rejected_at = when
    elif status == STATUS_CANCELED:
        proposal.approval.canceled_by = actor or "operator"
        proposal.approval.canceled_at = when
    elif status == STATUS_ARCHIVED:
        proposal.approval.archived_by = actor or "operator"
        proposal.approval.archived_at = when


def _transition(
    data_dir: Path,
    proposal_id: str,
    *,
    new_status: str,
    reason: str,
    actor: str,
) -> Proposal:
    if new_status not in APPROVAL_STATUSES:
        raise ValueError(f"unknown status: {new_status}")
    src, current = find_proposal_path(data_dir, proposal_id)
    if src is None or current is None:
        raise FileNotFoundError(f"proposal not found: {proposal_id}")
    proposal = load_proposal_from_path(src)
    if current == new_status:
        return proposal
    proposal.status = new_status
    now = datetime.now(timezone.utc).isoformat()
    _set_actor_fields(proposal, status=new_status, reason=reason, actor=actor, when=now)
    dest = write_proposal(data_dir, proposal)
    if src != dest and src.exists():
        with contextlib.suppress(OSError):
            src.unlink()
    return proposal


def approve_proposal(
    data_dir: Path, proposal_id: str, *, reason: str, actor: str = "operator"
) -> Proposal:
    return _transition(
        data_dir, proposal_id, new_status=STATUS_APPROVED, reason=reason, actor=actor
    )


def reject_proposal(
    data_dir: Path, proposal_id: str, *, reason: str, actor: str = "operator"
) -> Proposal:
    return _transition(
        data_dir, proposal_id, new_status=STATUS_REJECTED, reason=reason, actor=actor
    )


def cancel_proposal(
    data_dir: Path, proposal_id: str, *, reason: str = "", actor: str = "operator"
) -> Proposal:
    return _transition(
        data_dir, proposal_id, new_status=STATUS_CANCELED, reason=reason, actor=actor
    )


def archive_proposal(
    data_dir: Path, proposal_id: str, *, reason: str = "", actor: str = "operator"
) -> Proposal:
    return _transition(
        data_dir, proposal_id, new_status=STATUS_ARCHIVED, reason=reason, actor=actor
    )


def list_proposals(data_dir: Path) -> list[tuple[str, Proposal]]:
    """Return ``(status, proposal)`` pairs across all approval directories."""
    out: list[tuple[str, Proposal]] = []
    for status in APPROVAL_STATUSES:
        d = _status_dir(data_dir, status)
        if not d.exists():
            continue
        for path in sorted(d.glob("*.proposal.json"), key=lambda p: p.name):
            try:
                out.append((status, load_proposal_from_path(path)))
            except (OSError, ValueError, json.JSONDecodeError):
                continue
    return out


def clear_proposals(data_dir: Path) -> None:
    """Remove all proposal files. Used by tests/manual cleanup."""
    root = approvals_root(data_dir)
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
