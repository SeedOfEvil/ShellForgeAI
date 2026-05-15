from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shellforgeai.core.approvals import (
    STATUS_APPROVED,
    STATUS_CANCELED,
    STATUS_PENDING,
    STATUS_REJECTED,
    Proposal,
    find_proposal_path,
    latest_approved_proposal,
    load_proposal_from_path,
)
from shellforgeai.core.rollback_preview import load_preview, rollback_preview_dir, validate_preview


@dataclass(frozen=True)
class RestartPlan:
    payload: dict[str, Any]


def _resolve_proposal(
    data_dir: Path,
    proposal_id: str | None,
    *,
    latest: bool,
    from_session: str | None,
    from_evidence: Path | None,
    container: str | None,
) -> tuple[Proposal | None, str]:
    if proposal_id:
        proposal_path, _ = find_proposal_path(data_dir, proposal_id)
        if proposal_path is None:
            return None, "missing"
        return load_proposal_from_path(proposal_path), "found"
    if latest:
        latest_proposal = latest_approved_proposal(data_dir)
        return (latest_proposal, "found") if latest_proposal else (None, "missing")
    target = (container or "").strip()
    if (from_session or from_evidence) and target:
        for _status, proposal in _all_proposals(data_dir):
            if proposal.component == target and (
                (from_session and proposal.source.session_id == from_session)
                or (from_evidence and proposal.source.evidence == str(from_evidence))
            ):
                return proposal, "found"
        return None, "missing"
    return None, "missing"


def _all_proposals(data_dir: Path):
    from shellforgeai.core.approvals import list_proposals

    return list_proposals(data_dir)


def _allowlist_status(proposal: Proposal | None, target: str) -> tuple[str, list[str]]:
    if proposal is None:
        return "unknown", ["proposal missing"]
    labels = set(proposal.safety_labels or [])
    if "ALLOWLISTED-LAB-TARGET" in labels or "DISPOSABLE-TARGET" in labels:
        return "passed", []
    return "failed", [f"target {target} is not allowlisted/disposable"]


def build_restart_plan(
    data_dir: Path, proposal: Proposal | None, *, target_hint: str = ""
) -> RestartPlan:
    created_at = datetime.now(UTC).isoformat()
    target = (proposal.component if proposal else target_hint) or ""
    source_evidence = proposal.source.evidence if proposal else ""
    source_session = proposal.source.session_id if proposal else ""
    proposal_status = proposal.status if proposal else "missing"
    command_preview = proposal.proposed_steps[0] if proposal and proposal.proposed_steps else ""
    allow_status, allow_reasons = _allowlist_status(proposal, target)

    rollback_status = "unknown"
    rollback_path: str | None = None
    if proposal is not None:
        preview = rollback_preview_dir(data_dir, proposal.proposal_id) / "rollback-preview.json"
        if preview.exists():
            try:
                errs = validate_preview(load_preview(preview))
                if errs:
                    rollback_status = "invalid"
                else:
                    rollback_status = "present"
                    rollback_path = str(preview)
            except Exception:
                rollback_status = "invalid"
        else:
            rollback_status = "missing"

    blockers: list[str] = []
    if proposal is None:
        blockers.append("proposal missing")
    if proposal_status != STATUS_APPROVED:
        if proposal_status == STATUS_PENDING:
            blockers.append("proposal pending approval")
        elif proposal_status in (STATUS_REJECTED, STATUS_CANCELED) or proposal_status != "missing":
            blockers.append(f"proposal status is {proposal_status}")
    if allow_status != "passed":
        blockers.extend(allow_reasons)
    if not source_evidence or not Path(source_evidence).exists():
        blockers.append("source evidence missing")
    if command_preview != (f"docker restart {target}" if target else ""):
        blockers.append("command preview mismatch")
    if rollback_status != "present":
        blockers.append(f"rollback preview {rollback_status}")

    readiness = "ready" if not blockers and proposal is not None else "blocked"
    checklist = [
        {
            "id": "evidence_exists",
            "status": "ok" if source_evidence and Path(source_evidence).exists() else "blocked",
            "summary": "Evidence exists",
        },
        {
            "id": "target_found",
            "status": "ok" if target else "blocked",
            "summary": "Container target found in evidence",
        },
        {
            "id": "allowlisted_target",
            "status": "ok" if allow_status == "passed" else "blocked",
            "summary": "Target is allowlisted/disposable",
        },
        {
            "id": "exact_command_preview",
            "status": "ok"
            if command_preview == (f"docker restart {target}" if target else "")
            else "blocked",
            "summary": f"Proposed command is exactly: docker restart {target}".strip(),
        },
        {
            "id": "approval_status",
            "status": "ok"
            if proposal_status == STATUS_APPROVED
            else ("wait" if proposal_status == STATUS_PENDING else "blocked"),
            "summary": "Proposal is approved"
            if proposal_status == STATUS_APPROVED
            else "Proposal is pending approval",
        },
        {
            "id": "rollback_preview",
            "status": "ok" if rollback_status == "present" else "blocked",
            "summary": "Rollback preview present and valid"
            if rollback_status == "present"
            else "Rollback preview missing",
        },
        {
            "id": "apply_readiness",
            "status": "ok" if readiness == "ready" else "blocked",
            "summary": "Apply execution ready"
            if readiness == "ready"
            else "Apply execution not ready",
        },
    ]

    next_commands = []
    pid = proposal.proposal_id if proposal else "<proposal-id>"
    if proposal is None:
        next_commands.append("shellforgeai approvals propose-restart --latest --container <target>")
    else:
        next_commands.append(f"shellforgeai approvals show {pid}")
        if proposal_status == STATUS_PENDING:
            next_commands.append(f'shellforgeai approvals approve {pid} --reason "..."')
        next_commands.append(f"shellforgeai rollback preview {pid}")
        next_commands.append("shellforgeai rollback validate <rollback-preview-path>")
        next_commands.append(f"shellforgeai apply {pid} --execute --confirm")

    payload = {
        "schema_version": "1",
        "created_at": created_at,
        "proposal_id": proposal.proposal_id if proposal else "",
        "session_id": source_session,
        "target": target,
        "source_evidence": source_evidence,
        "proposal_status": proposal_status,
        "allowlist": {"status": allow_status, "reasons": allow_reasons},
        "rollback": {"status": rollback_status, "path": rollback_path, "required": True},
        "apply_readiness": {"status": readiness, "blockers": blockers},
        "command_preview": command_preview,
        "checklist": checklist,
        "next_commands": next_commands,
        "safety": {
            "execution_allowed": False,
            "execution_status": "not_executed",
            "mutation_performed": False,
            "arbitrary_command_execution": False,
        },
    }
    return RestartPlan(payload=payload)


def render_restart_plan(plan: RestartPlan) -> str:
    p = plan.payload
    lines = [
        "Restart proposal plan",
        f"- Target: {p.get('target') or 'unknown'}",
        f"- Source evidence: {p.get('source_evidence') or 'missing'}",
        f"- Source session: {p.get('session_id') or 'unknown'}",
        f"- Proposal: {p.get('proposal_id') or 'missing'}",
        f"- Proposal status: {p.get('proposal_status')}",
        f"- Allowlist: {p.get('allowlist', {}).get('status')}",
        "- Policy: docker_restart / service-impacting / allowlisted lab target",
        f"- Rollback preview: {p.get('rollback', {}).get('status')}",
        f"- Apply readiness: {p.get('apply_readiness', {}).get('status')}",
        "- Execution: not executed",
        "",
        "Checklist:",
    ]
    sym = {"ok": "[OK]", "wait": "[WAIT]", "blocked": "[BLOCKED]", "unknown": "[UNKNOWN]"}
    for item in p.get("checklist", []):
        lines.append(f"{sym.get(item.get('status'), '[UNKNOWN]')} {item.get('summary')}")
    lines.append("")
    lines.append("Next safe commands:")
    for i, cmd in enumerate(p.get("next_commands", []), start=1):
        lines.append(f"{i}. {cmd}")
    lines.extend(
        [
            "",
            "Safety:",
            "- This command did not restart anything.",
            "- Natural-language restart remains refused.",
            "- ShellForgeAI can only execute the existing allowlisted restart path.",
        ]
    )
    return "\n".join(lines)


def to_json(plan: RestartPlan) -> str:
    return json.dumps(plan.payload, indent=2)
