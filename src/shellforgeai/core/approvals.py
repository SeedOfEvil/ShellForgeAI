"""Approval queue / mutation proposal objects (PR32 scaffolding).

ShellForgeAI is a Tier-3 triage tool. It never executes mutation. The
approval queue is a *paper trail*: it turns operator-run runbook options
into proposal objects that an operator can mark ``approved``, ``rejected``,
or ``canceled``. Marking a proposal ``approved`` does NOT execute anything;
it only records that a human authorized a future operator-run change.

PR33 consumes these proposals to generate an operator execution bundle
(``apply_bundle.py``). Generation is still inspection-only.
"""

from __future__ import annotations

import contextlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

PROPOSAL_SCHEMA_VERSION = "1"

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_CANCELED = "canceled"
APPROVAL_STATUSES = (STATUS_PENDING, STATUS_APPROVED, STATUS_REJECTED, STATUS_CANCELED)

RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"
RISK_VALUES = (RISK_LOW, RISK_MEDIUM, RISK_HIGH)


class ProposalExecution(BaseModel):
    allowed: bool = False
    status: str = "not_executed"


class ProposalApproval(BaseModel):
    reason: str = ""
    approved_at: str = ""
    approved_by: str = ""


class Proposal(BaseModel):
    schema_version: str = PROPOSAL_SCHEMA_VERSION
    proposal_id: str
    session_id: str = ""
    created_at: str = ""
    status: str = STATUS_PENDING
    component: str = ""
    title: str = ""
    risk: str = RISK_MEDIUM
    impact: str = ""
    safety_labels: list[str] = Field(default_factory=list)
    source_evidence: str = ""
    source_runbook: str = ""
    preconditions: list[str] = Field(default_factory=list)
    proposed_steps: list[str] = Field(default_factory=list)
    rollback: list[str] = Field(default_factory=list)
    verification: list[str] = Field(default_factory=list)
    notes: str = ""
    execution: ProposalExecution = Field(default_factory=ProposalExecution)
    approval: ProposalApproval = Field(default_factory=ProposalApproval)
    rejection_reason: str = ""
    canceled_reason: str = ""

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
    order = (STATUS_APPROVED, STATUS_PENDING, STATUS_REJECTED, STATUS_CANCELED)
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
    )
    for k in required:
        if k not in payload:
            errors.append(f"missing required field: {k}")
    if payload.get("status") and payload["status"] not in APPROVAL_STATUSES:
        errors.append(f"status must be one of {APPROVAL_STATUSES}")
    if payload.get("risk") and payload["risk"] not in RISK_VALUES:
        errors.append(f"risk must be one of {RISK_VALUES}")
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
    if has_broad_destructive_words(steps):
        warnings.append("broad destructive words detected in proposed_steps")
    return errors, warnings


# ---------------------------------------------------------------------------
# Proposal creation from runbook


_LABEL_PATTERNS = (
    ("OPERATOR-RUN", re.compile(r"OPERATOR-RUN", re.IGNORECASE)),
    ("REQUIRES APPROVAL", re.compile(r"REQUIRES\s+APPROVAL", re.IGNORECASE)),
    ("SERVICE-IMPACTING", re.compile(r"SERVICE-IMPACTING", re.IGNORECASE)),
    ("ROLLBACK ADVISED", re.compile(r"ROLLBACK\s+ADVISED", re.IGNORECASE)),
)


def _derive_safety_labels(option: dict[str, Any]) -> list[str]:
    blob = " ".join(
        [
            str(option.get("title") or ""),
            str(option.get("impact") or ""),
            " ".join(str(s) for s in (option.get("steps") or [])),
            str(option.get("safety_label") or option.get("label") or ""),
        ]
    )
    labels: list[str] = []
    for label, pattern in _LABEL_PATTERNS:
        if pattern.search(blob):
            labels.append(label)
    steps = option.get("steps") or []
    if _is_mutating_steps([str(s) for s in steps]):
        if "OPERATOR-RUN" not in labels:
            labels.insert(0, "OPERATOR-RUN")
        if "REQUIRES APPROVAL" not in labels:
            labels.append("REQUIRES APPROVAL")
    return labels


def _slug(value: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()
    return s[:64] or "option"


def make_proposal_id(session_id: str, option_id: str) -> str:
    return f"prop_{session_id}_{_slug(option_id)}"


def proposals_from_runbook_payload(
    payload: dict[str, Any],
    *,
    source_runbook: str = "",
) -> list[Proposal]:
    """Build pending Proposal objects from a runbook JSON payload."""
    session_id = str(payload.get("session_id") or "session")
    source_evidence = str(payload.get("source_evidence") or "")
    now = datetime.now(timezone.utc).isoformat()
    out: list[Proposal] = []
    for option in payload.get("remediation_options") or []:
        opt_id = str(option.get("id") or option.get("title") or "option")
        applies_to = option.get("applies_to") or []
        component = ""
        for a in applies_to:
            if a and not str(a).startswith("problem:") and not str(a).startswith("general:"):
                component = str(a)
                break
        if not component:
            component = "general"
        steps = [str(s) for s in (option.get("steps") or [])]
        proposal = Proposal(
            proposal_id=make_proposal_id(session_id, opt_id),
            session_id=session_id,
            created_at=now,
            status=STATUS_PENDING,
            component=component,
            title=str(option.get("title") or ""),
            risk=str(option.get("risk") or RISK_MEDIUM),
            impact=str(option.get("impact") or ""),
            safety_labels=_derive_safety_labels(option),
            source_evidence=source_evidence,
            source_runbook=source_runbook,
            preconditions=[str(p) for p in (option.get("preconditions") or [])],
            proposed_steps=steps,
            rollback=[str(r) for r in (option.get("rollback") or [])],
            verification=[str(v) for v in (option.get("verification") or [])],
            notes=str(option.get("notes") or ""),
            execution=ProposalExecution(),
        )
        out.append(proposal)
    return out


def create_proposals_for_session(data_dir: Path, session_dir: Path) -> list[Proposal]:
    """Read ``runbook.json`` from a session directory and write pending proposals."""
    runbook_path = Path(session_dir) / "runbook.json"
    if not runbook_path.exists():
        raise FileNotFoundError(f"runbook.json not found in {session_dir}")
    payload = json.loads(runbook_path.read_text(encoding="utf-8"))
    proposals = proposals_from_runbook_payload(payload, source_runbook=str(runbook_path))
    _ensure_dirs(data_dir)
    for p in proposals:
        write_proposal(data_dir, p)
    return proposals


# ---------------------------------------------------------------------------
# Transitions


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
    if new_status == STATUS_APPROVED:
        proposal.approval = ProposalApproval(
            reason=reason, approved_at=now, approved_by=actor or "operator"
        )
    elif new_status == STATUS_REJECTED:
        proposal.rejection_reason = reason
    elif new_status == STATUS_CANCELED:
        proposal.canceled_reason = reason
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
