"""Guided safe restart mission workflow (PR52).

ShellForgeAI is a Tier-3 triage tool. The mission workflow stitches the
existing diagnose/propose/approve/rollback/restart-plan/apply steps into one
operator-friendly mission record. It writes metadata only and never executes,
approves, or applies anything by default.

Mission storage layout::

    <data_dir>/missions/restart/<mission_id>/mission.json
    <data_dir>/missions/restart/<mission_id>/mission.md
"""

from __future__ import annotations

import contextlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shellforgeai.core import lab_restart as lab_restart_mod
from shellforgeai.core.approvals import (
    STATUS_APPROVED,
    STATUS_CANCELED,
    STATUS_PENDING,
    STATUS_REJECTED,
    Proposal,
    build_restart_proposal_from_evidence,
    find_proposal_path,
    list_proposals,
    load_proposal_from_path,
)
from shellforgeai.core.restart_plan import build_restart_plan
from shellforgeai.core.rollback_preview import (
    load_preview,
    rollback_preview_dir,
    validate_preview,
    write_preview,
)

SCHEMA_VERSION = "1"
MISSION_TYPE = "docker_restart"

STATUS_PREPARED = "prepared"
STATUS_WAITING_APPROVAL = "waiting_approval"
STATUS_WAITING_ROLLBACK = "waiting_rollback"
STATUS_READY = "ready"
STATUS_EXECUTED = "executed"
STATUS_BLOCKED = "blocked"
STATUS_FAILED = "failed"

KNOWN_MISSION_STATUSES = (
    STATUS_PREPARED,
    STATUS_WAITING_APPROVAL,
    STATUS_WAITING_ROLLBACK,
    STATUS_READY,
    STATUS_EXECUTED,
    STATUS_BLOCKED,
    STATUS_FAILED,
)

KNOWN_PHASE_STATUSES = {
    "evidence": ("ok", "missing", "blocked"),
    "proposal": ("pending", "approved", "missing", "blocked"),
    "approval": ("pending", "approved", "rejected", "canceled", "unknown"),
    "rollback": ("present", "missing", "invalid", "unknown"),
    "readiness": ("ready", "blocked"),
    "execution": ("not_executed", "executed", "refused"),
    "verification": ("not_run", "passed", "failed", "unknown"),
}


@dataclass(frozen=True)
class PreparedMission:
    mission_id: str
    mission_path: Path
    payload: dict[str, Any]
    status: str
    refusal: str | None = None


def missions_root(data_dir: Path) -> Path:
    return Path(data_dir) / "missions" / "restart"


def mission_dir(data_dir: Path, mission_id: str) -> Path:
    return missions_root(data_dir) / mission_id


def mission_json_path(data_dir: Path, mission_id: str) -> Path:
    return mission_dir(data_dir, mission_id) / "mission.json"


def mission_md_path(data_dir: Path, mission_id: str) -> Path:
    return mission_dir(data_dir, mission_id) / "mission.md"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _short_id() -> str:
    return uuid.uuid4().hex[:8]


def _make_mission_id() -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    return f"mission_restart_{stamp}_{_short_id()}"


def list_missions(data_dir: Path) -> list[dict[str, Any]]:
    root = missions_root(data_dir)
    if not root.exists():
        return []
    out: list[dict[str, Any]] = []
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        mp = d / "mission.json"
        if not mp.exists():
            continue
        try:
            out.append(json.loads(mp.read_text(encoding="utf-8")))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return out


def latest_mission(data_dir: Path) -> dict[str, Any] | None:
    rows = list_missions(data_dir)
    if not rows:
        return None
    rows.sort(key=lambda r: str(r.get("created_at") or ""))
    return rows[-1]


def load_mission(data_dir: Path, mission_id: str) -> dict[str, Any]:
    p = mission_json_path(data_dir, mission_id)
    return json.loads(p.read_text(encoding="utf-8"))


def find_mission_for_target(data_dir: Path, target: str) -> dict[str, Any] | None:
    for row in list_missions(data_dir):
        if str(row.get("target") or "") == target and str(row.get("status") or "") not in (
            STATUS_EXECUTED,
            STATUS_FAILED,
            STATUS_BLOCKED,
        ):
            return row
    return None


def find_mission_for_proposal(data_dir: Path, proposal_id: str) -> dict[str, Any] | None:
    for row in list_missions(data_dir):
        if str(row.get("proposal_id") or "") == proposal_id:
            return row
    return None


def _proposal_for_target(data_dir: Path, target: str) -> Proposal | None:
    """Return latest non-archived proposal for the target if any."""
    candidates: list[tuple[str, Proposal]] = []
    for status, p in list_proposals(data_dir):
        if status == "archived":
            continue
        if p.kind == "docker_restart" and p.component == target:
            candidates.append((status, p))
    if not candidates:
        return None
    # Prefer approved > pending > others; tiebreak by created_at
    rank = {STATUS_APPROVED: 0, STATUS_PENDING: 1, STATUS_REJECTED: 2, STATUS_CANCELED: 3}
    candidates.sort(key=lambda t: (rank.get(t[0], 9), str(t[1].created_at)))
    return candidates[0][1]


def _build_phases(
    data_dir: Path,
    proposal: Proposal | None,
    *,
    evidence_path: Path | None,
) -> tuple[dict[str, dict[str, Any]], str, list[str], dict[str, Any]]:
    phases: dict[str, dict[str, Any]] = {}

    if evidence_path and Path(evidence_path).exists():
        phases["evidence"] = {"status": "ok", "summary": str(evidence_path)}
    else:
        phases["evidence"] = {"status": "missing", "summary": "evidence not available"}

    if proposal is None:
        phases["proposal"] = {"status": "missing", "proposal_id": ""}
        phases["approval"] = {"status": "unknown"}
    else:
        if proposal.status == STATUS_APPROVED:
            phases["proposal"] = {"status": "approved", "proposal_id": proposal.proposal_id}
            phases["approval"] = {"status": "approved"}
        elif proposal.status == STATUS_PENDING:
            phases["proposal"] = {"status": "pending", "proposal_id": proposal.proposal_id}
            phases["approval"] = {"status": "pending"}
        elif proposal.status == STATUS_REJECTED:
            phases["proposal"] = {"status": "blocked", "proposal_id": proposal.proposal_id}
            phases["approval"] = {"status": "rejected"}
        elif proposal.status == STATUS_CANCELED:
            phases["proposal"] = {"status": "blocked", "proposal_id": proposal.proposal_id}
            phases["approval"] = {"status": "canceled"}
        else:
            phases["proposal"] = {"status": "blocked", "proposal_id": proposal.proposal_id}
            phases["approval"] = {"status": "unknown"}

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
    phases["rollback"] = {"status": rollback_status, "path": rollback_path}

    plan = build_restart_plan(data_dir, proposal)
    plan_payload = plan.payload
    readiness_status = plan_payload["apply_readiness"]["status"]
    blockers = list(plan_payload["apply_readiness"]["blockers"])
    phases["readiness"] = {"status": readiness_status, "blockers": blockers}

    phases["execution"] = {"status": "not_executed", "receipt": None}
    phases["verification"] = {"status": "not_run", "receipt": None}

    approval_status = phases["approval"]["status"]
    if (
        proposal is None
        or phases["proposal"]["status"] == "missing"
        or approval_status in ("rejected", "canceled")
    ):
        mission_status = STATUS_BLOCKED
    elif phases["approval"]["status"] == "pending":
        mission_status = STATUS_WAITING_APPROVAL
    elif phases["approval"]["status"] == "approved" and rollback_status != "present":
        mission_status = STATUS_WAITING_ROLLBACK
    elif readiness_status == "ready":
        mission_status = STATUS_READY
    else:
        mission_status = STATUS_BLOCKED

    return phases, mission_status, blockers, plan_payload


def _next_commands(
    proposal: Proposal | None,
    phases: dict[str, dict[str, Any]],
    target: str,
) -> list[str]:
    cmds: list[str] = []
    if proposal is None:
        cmds.append(
            f"shellforgeai approvals propose-restart --container {target} --latest"
            if target
            else "shellforgeai approvals propose-restart --latest --container <target>"
        )
        return cmds
    pid = proposal.proposal_id
    cmds.append(f"shellforgeai approvals show {pid}")
    if phases["approval"]["status"] == "pending":
        cmds.append(f'shellforgeai approvals approve {pid} --reason "..."')
    if phases["rollback"]["status"] != "present":
        cmds.append(f"shellforgeai rollback preview {pid}")
    cmds.append(f"shellforgeai approvals restart-plan {pid}")
    cmds.append(f"shellforgeai apply {pid} --execute --confirm")
    return cmds


def _render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Safe restart mission",
        "",
        f"- mission: {payload['mission_id']}",
        f"- target: {payload.get('target') or 'unknown'}",
        f"- proposal: {payload.get('proposal_id') or 'missing'}",
        f"- status: {payload.get('status')}",
        f"- created_at: {payload.get('created_at')}",
        f"- execution: {payload['safety']['execution_status']}",
        "",
        "## Phases",
    ]
    for key in (
        "evidence",
        "proposal",
        "approval",
        "rollback",
        "readiness",
        "execution",
        "verification",
    ):
        ph = payload["phases"].get(key) or {}
        lines.append(f"- {key}: {ph.get('status')}")
    lines.append("")
    lines.append("## Next commands")
    for i, cmd in enumerate(payload.get("next_commands") or [], start=1):
        lines.append(f"{i}. {cmd}")
    lines.extend(
        [
            "",
            "## Safety",
            "- This mission did not restart anything.",
            "- This mission did not approve or apply any proposal.",
            "- Natural-language restart remains refused.",
            "- Apply remains the only execution gate.",
        ]
    )
    return "\n".join(lines) + "\n"


def _write_mission_files(data_dir: Path, payload: dict[str, Any]) -> Path:
    mid = payload["mission_id"]
    d = mission_dir(data_dir, mid)
    d.mkdir(parents=True, exist_ok=True)
    json_path = mission_json_path(data_dir, mid)
    md_path = mission_md_path(data_dir, mid)
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_path.write_text(_render_markdown(payload), encoding="utf-8")
    return json_path


def _build_mission_payload(
    data_dir: Path,
    *,
    target: str,
    session_id: str,
    evidence_path: Path | None,
    proposal: Proposal | None,
    rollback_preview_path: str | None = None,
    restart_plan_path: str | None = None,
    existing_mission_id: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    phases, mission_status, _blockers, _plan = _build_phases(
        data_dir, proposal, evidence_path=evidence_path
    )
    if rollback_preview_path is None and phases["rollback"]["path"]:
        rollback_preview_path = phases["rollback"]["path"]

    mid = existing_mission_id or _make_mission_id()
    now = _now()
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "mission_id": mid,
        "created_at": created_at or now,
        "updated_at": now,
        "mission_type": MISSION_TYPE,
        "target": target,
        "session_id": session_id,
        "source_evidence": str(evidence_path) if evidence_path else "",
        "proposal_id": proposal.proposal_id if proposal else "",
        "rollback_preview_path": rollback_preview_path or "",
        "restart_plan_path": restart_plan_path or "",
        "command_preview": (
            (proposal.proposed_steps[0] if proposal and proposal.proposed_steps else "")
            or (f"docker restart {target}" if target else "")
        ),
        "status": mission_status,
        "phases": phases,
        "next_commands": _next_commands(proposal, phases, target),
        "safety": {
            "execution_allowed": False,
            "execution_status": "not_executed",
            "mutation_performed": False,
            "arbitrary_command_execution": False,
        },
    }
    return payload


@dataclass(frozen=True)
class PrepareResult:
    ok: bool
    mission_id: str
    mission_path: Path | None
    payload: dict[str, Any] | None
    status: str
    refusal: str
    deduped: bool = False


def prepare_mission(
    data_dir: Path,
    *,
    container: str,
    evidence_path: Path | None,
    session_id: str = "",
    with_rollback_preview: bool = False,
) -> PrepareResult:
    """Prepare a guided restart mission. Metadata only.

    Returns ``PrepareResult`` describing what happened. No mutation, no
    approval, no apply, no restart.
    """
    name = (container or "").strip()
    if not name or not lab_restart_mod.is_safe_container_name(name):
        return PrepareResult(
            ok=False,
            mission_id="",
            mission_path=None,
            payload=None,
            status="refused",
            refusal="missing or unsafe container name",
        )
    if evidence_path is None or not Path(evidence_path).exists():
        return PrepareResult(
            ok=False,
            mission_id="",
            mission_path=None,
            payload=None,
            status="refused",
            refusal=("no evidence available; run 'shellforgeai diagnose docker --save-plan' first"),
        )

    proposal = _proposal_for_target(data_dir, name)
    deduped = False
    if proposal is None:
        new_proposal, status = build_restart_proposal_from_evidence(
            data_dir,
            Path(evidence_path),
            container_name=name,
            source_session_id=session_id,
        )
        if new_proposal is None:
            return PrepareResult(
                ok=False,
                mission_id="",
                mission_path=None,
                payload=None,
                status="refused",
                refusal=str(status),
            )
        proposal = new_proposal
        if status == "deduped":
            deduped = True
    else:
        deduped = True

    if with_rollback_preview:
        with contextlib.suppress(Exception):
            write_preview(data_dir, proposal)

    existing_mission = find_mission_for_proposal(data_dir, proposal.proposal_id)
    existing_mid = str(existing_mission["mission_id"]) if existing_mission else None
    created_at = str(existing_mission["created_at"]) if existing_mission else None

    payload = _build_mission_payload(
        data_dir,
        target=name,
        session_id=session_id or (proposal.source.session_id if proposal else ""),
        evidence_path=Path(evidence_path),
        proposal=proposal,
        existing_mission_id=existing_mid,
        created_at=created_at,
    )
    json_path = _write_mission_files(data_dir, payload)
    return PrepareResult(
        ok=True,
        mission_id=payload["mission_id"],
        mission_path=json_path,
        payload=payload,
        status=payload["status"],
        refusal="",
        deduped=deduped or bool(existing_mission),
    )


def _preserve_terminal_state(
    refreshed: dict[str, Any],
    prior: dict[str, Any],
) -> dict[str, Any]:
    """Carry forward terminal execution/refusal state across a refresh.

    ``refresh_mission`` recomputes phases from current artifacts (proposal,
    rollback preview, restart plan readiness) — that view is read-only and must
    not erase an executed receipt or a recorded refusal. Once a mission has an
    execution receipt (or has reached a terminal status), the prior
    execution/verification/safety/status fields take precedence over a freshly
    computed "ready" view. Read-only derived fields (evidence, proposal,
    approval, rollback, readiness) are still refreshed.
    """
    prior_phases = prior.get("phases") or {}
    prior_exec = prior_phases.get("execution") or {}
    prior_verif = prior_phases.get("verification") or {}
    prior_status = str(prior.get("status") or "")
    prior_exec_status = str(prior_exec.get("status") or "")
    receipt = prior_exec.get("receipt")

    terminal = (
        prior_status in (STATUS_EXECUTED, STATUS_FAILED)
        or prior_exec_status in ("executed", "refused")
        or bool(receipt)
    )
    if not terminal:
        return refreshed

    phases = refreshed.setdefault("phases", {})
    phases["execution"] = dict(prior_exec)
    phases["verification"] = dict(prior_verif)

    if prior_status in (
        STATUS_EXECUTED,
        STATUS_FAILED,
        STATUS_BLOCKED,
    ):
        refreshed["status"] = prior_status

    prior_safety = prior.get("safety") or {}
    if prior_safety:
        safety = dict(prior_safety)
        safety["arbitrary_command_execution"] = False
        refreshed["safety"] = safety

    # Post-execution: drop apply-step suggestions and surface audit/export hints.
    if refreshed.get("status") in (STATUS_EXECUTED, STATUS_FAILED):
        mid = str(refreshed.get("mission_id") or "")
        receipt_str = str((phases.get("execution") or {}).get("receipt") or "")
        post_cmds: list[str] = []
        if mid:
            post_cmds.append(f"shellforgeai mission restart status {mid}")
            post_cmds.append(f"shellforgeai mission restart validate {mid}")
            post_cmds.append(f"shellforgeai mission restart export {mid}")
        post_cmds.append("shellforgeai audit timeline")
        if receipt_str:
            post_cmds.append(f"cat {receipt_str}")
        refreshed["next_commands"] = post_cmds
    return refreshed


def refresh_mission(data_dir: Path, mission_id: str) -> dict[str, Any]:
    """Reload mission and refresh phases from artifacts. Persists the update.

    Terminal execution/refusal state (existing receipt, ``status=executed`` or
    ``status=failed``) is preserved — a read-only status/checklist refresh must
    never erase a successful execution or downgrade ``executed`` back to
    ``ready``.
    """
    payload = load_mission(data_dir, mission_id)
    proposal: Proposal | None = None
    pid = str(payload.get("proposal_id") or "")
    if pid:
        path, _status = find_proposal_path(data_dir, pid)
        if path is not None:
            proposal = load_proposal_from_path(path)
    ev = payload.get("source_evidence") or ""
    evidence_path = Path(ev) if ev else None
    refreshed = _build_mission_payload(
        data_dir,
        target=str(payload.get("target") or ""),
        session_id=str(payload.get("session_id") or ""),
        evidence_path=evidence_path,
        proposal=proposal,
        existing_mission_id=mission_id,
        created_at=str(payload.get("created_at") or ""),
    )
    refreshed = _preserve_terminal_state(refreshed, payload)
    _write_mission_files(data_dir, refreshed)
    return refreshed


def render_checklist(payload: dict[str, Any]) -> str:
    sym = {
        "ok": "[OK]",
        "approved": "[OK]",
        "present": "[OK]",
        "ready": "[OK]",
        "executed": "[OK]",
        "passed": "[OK]",
        "pending": "[WAIT]",
        "missing": "[WAIT]",
        "not_run": "[WAIT]",
        "not_executed": "[WAIT]",
        "blocked": "[BLOCKED]",
        "rejected": "[BLOCKED]",
        "canceled": "[BLOCKED]",
        "invalid": "[BLOCKED]",
        "failed": "[BLOCKED]",
        "refused": "[BLOCKED]",
        "unknown": "[UNKNOWN]",
    }
    phases = payload.get("phases") or {}
    lines = [
        "Safe restart mission",
        f"- Mission: {payload.get('mission_id')}",
        f"- Target: {payload.get('target') or 'unknown'}",
        f"- Proposal: {payload.get('proposal_id') or 'missing'}",
        f"- Status: {payload.get('status')}",
        f"- Execution: {payload['safety'].get('execution_status', 'not_executed')}",
        "",
        "Checklist:",
        f"{sym.get(phases.get('evidence', {}).get('status'), '[UNKNOWN]')} Evidence captured",
        f"{sym.get(phases.get('proposal', {}).get('status'), '[UNKNOWN]')} Restart proposal exists",
        f"{sym.get(phases.get('approval', {}).get('status'), '[UNKNOWN]')} Proposal approval",
        f"{sym.get(phases.get('rollback', {}).get('status'), '[UNKNOWN]')} Rollback preview",
        f"{sym.get(phases.get('readiness', {}).get('status'), '[UNKNOWN]')} Apply readiness",
        f"{sym.get(phases.get('execution', {}).get('status'), '[UNKNOWN]')} Execution",
        f"{sym.get(phases.get('verification', {}).get('status'), '[UNKNOWN]')} Verification",
        "",
        "Next commands:",
    ]
    for i, cmd in enumerate(payload.get("next_commands") or [], start=1):
        lines.append(f"{i}. {cmd}")
    lines.extend(
        [
            "",
            "Safety:",
            "- Mission status/checklist did not restart anything.",
            "- Natural-language restart remains refused.",
            "- Apply is still the only execution gate.",
        ]
    )
    return "\n".join(lines)


_UNSAFE_TOKENS = ("&&", "||", ";", "|", "`", "$(", ">", "<", "\n")


def validate_mission_payload(payload: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if not isinstance(payload, dict):
        return ["mission payload is not a JSON object"]
    if not payload.get("schema_version"):
        errs.append("schema_version missing")
    if not payload.get("mission_id"):
        errs.append("mission_id missing")
    target = str(payload.get("target") or "")
    if not target:
        errs.append("target missing")
    phases = payload.get("phases") or {}
    if not isinstance(phases, dict):
        errs.append("phases must be an object")
        phases = {}
    safety = payload.get("safety") or {}
    if not isinstance(safety, dict):
        errs.append("safety must be an object")
        safety = {}
    if safety.get("arbitrary_command_execution") is not False:
        errs.append("arbitrary_command_execution must be false")
    exec_phase = phases.get("execution") or {}
    receipt = exec_phase.get("receipt")
    if exec_phase.get("status") == "executed":
        if not receipt:
            errs.append("execution.status=executed requires a receipt")
    else:
        if safety.get("execution_allowed") is not False:
            errs.append("execution_allowed must be false unless executed receipt exists")
        if safety.get("execution_status") not in (None, "not_executed", "refused"):
            errs.append("execution_status must be not_executed unless executed receipt exists")
        if safety.get("mutation_performed") is not False:
            errs.append("mutation_performed must be false unless executed receipt exists")
    proposal_phase = phases.get("proposal") or {}
    proposal_phase_status = proposal_phase.get("status")
    if (
        proposal_phase_status
        and proposal_phase_status != "missing"
        and not payload.get("proposal_id")
    ):
        errs.append("proposal_id missing while proposal phase is not missing")
    for key, allowed in KNOWN_PHASE_STATUSES.items():
        ph = phases.get(key)
        if ph is None:
            errs.append(f"phase {key} missing")
            continue
        st = ph.get("status")
        if st not in allowed:
            errs.append(f"phase {key} has invalid status {st!r}")
    cmd_preview = str(payload.get("command_preview") or "")
    if cmd_preview and cmd_preview != f"docker restart {target}":
        errs.append(f"command_preview must be exact 'docker restart {target}'")
    for cmd in payload.get("next_commands") or []:
        text = str(cmd)
        if any(tok in text for tok in _UNSAFE_TOKENS):
            errs.append(f"next_commands contains unsafe shell chain: {text}")
    src_ev = str(payload.get("source_evidence") or "")
    if src_ev and not Path(src_ev).exists() and phases.get("evidence", {}).get("status") == "ok":
        errs.append("evidence phase ok but source_evidence file is missing")
    rb_path = str(payload.get("rollback_preview_path") or "")
    if (
        rb_path
        and not Path(rb_path).exists()
        and (phases.get("rollback") or {}).get("status") == "present"
    ):
        errs.append("rollback phase present but rollback_preview_path is missing")
    return errs


def check_execute_readiness(
    data_dir: Path,
    mission_id: str,
) -> tuple[bool, list[str], dict[str, Any], Proposal | None]:
    """Verify a mission is ready to be handed off to the apply gate (PR53).

    Returns ``(ok, blockers, refreshed_payload, proposal)``. Refreshes the
    mission first so the answer reflects current on-disk artifact state.
    """
    blockers: list[str] = []
    try:
        payload = refresh_mission(data_dir, mission_id)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return False, [f"mission not found or invalid: {exc}"], {}, None

    if str(payload.get("mission_type") or "") != MISSION_TYPE:
        blockers.append("mission_type is not docker_restart")
    target = str(payload.get("target") or "")
    if not target:
        blockers.append("mission target missing")

    pid = str(payload.get("proposal_id") or "")
    proposal: Proposal | None = None
    if not pid:
        blockers.append("mission has no proposal_id")
    else:
        path, status = find_proposal_path(data_dir, pid)
        if path is None:
            blockers.append(f"proposal {pid} not found on disk")
        else:
            try:
                proposal = load_proposal_from_path(path)
            except (OSError, ValueError) as exc:
                blockers.append(f"proposal {pid} could not be loaded: {exc}")
            else:
                if proposal.status != STATUS_APPROVED:
                    blockers.append(f"proposal status '{proposal.status}' is not approved")
                if proposal.component and target and proposal.component != target:
                    blockers.append("proposal target does not match mission target")
                expected_preview = f"docker restart {target}" if target else ""
                preview = ""
                for step in proposal.proposed_steps or []:
                    text = str(step)
                    if "docker restart" in text:
                        idx = text.find("docker restart")
                        preview = text[idx:].split("#", 1)[0].strip().strip(";").strip()
                        break
                if not preview:
                    cmd_preview = str(payload.get("command_preview") or "")
                    preview = cmd_preview
                if expected_preview and preview != expected_preview:
                    blockers.append(
                        f"proposal command preview must be exactly '{expected_preview}'"
                    )

    phases = payload.get("phases") or {}
    rollback = phases.get("rollback") or {}
    rb_status = rollback.get("status")
    if rb_status != "present":
        blockers.append(f"rollback preview {rb_status or 'missing'}")
    else:
        rb_path_str = str(rollback.get("path") or "")
        if not rb_path_str or not Path(rb_path_str).exists():
            blockers.append("rollback preview file missing on disk")
        else:
            try:
                rb_payload = load_preview(Path(rb_path_str))
                rb_errs = validate_preview(rb_payload)
            except Exception as exc:
                blockers.append(f"rollback preview unreadable: {exc}")
            else:
                if rb_errs:
                    blockers.append("rollback preview invalid: " + "; ".join(rb_errs))
                if (rb_payload.get("safety") or {}).get("rollback_execution_allowed") is not False:
                    blockers.append("rollback_execution_allowed must be false")
                if rb_payload.get("rollback_status") != "preview_only":
                    blockers.append("rollback_status must be preview_only")

    readiness = (phases.get("readiness") or {}).get("status")
    if readiness != "ready":
        plan_blockers = (phases.get("readiness") or {}).get("blockers") or []
        if plan_blockers:
            blockers.append("restart plan readiness blocked: " + "; ".join(plan_blockers))
        else:
            blockers.append("restart plan readiness not ready")

    approval = (phases.get("approval") or {}).get("status")
    if approval in ("rejected", "canceled"):
        blockers.append(f"proposal approval is {approval}")

    if str(payload.get("status") or "") not in (STATUS_READY, STATUS_EXECUTED) and not blockers:
        blockers.append(f"mission status is {payload.get('status')}")

    return (not blockers), blockers, payload, proposal


def apply_delegation_command(payload: dict[str, Any]) -> str:
    """Return the exact `apply` invocation a mission handoff would delegate to."""
    pid = str(payload.get("proposal_id") or "<proposal-id>")
    return f"shellforgeai apply {pid} --execute --confirm"


def record_execution_result(
    data_dir: Path,
    mission_id: str,
    *,
    receipt_path: Path | None,
    verification: dict[str, Any] | None,
    execution_status: str,
    mission_status: str,
    refusal: str = "",
    blockers: list[str] | None = None,
) -> dict[str, Any]:
    """Update the mission record after a delegated apply attempt.

    ``execution_status`` is one of ``executed | failed | refused``.
    Receipt path is referenced (not duplicated). ``arbitrary_command_execution``
    remains false. ``mutation_performed`` is set only when the existing safety
    schema accepts it (i.e. when ``execution_status`` is ``executed`` and a
    receipt is present).
    """
    payload = load_mission(data_dir, mission_id)
    phases = payload.setdefault("phases", {})
    receipt_str = str(receipt_path) if receipt_path is not None else None

    if execution_status == "executed":
        phases["execution"] = {"status": "executed", "receipt": receipt_str}
        v = dict(verification or {})
        v_status = str(v.get("status") or "unknown")
        v_phase_status = (
            "passed"
            if v_status == "passed"
            else "failed"
            if v_status in ("failed", "skipped")
            else "unknown"
        )
        phases["verification"] = {
            "status": v_phase_status,
            "receipt": receipt_str,
            "summary": {
                "status": v_status,
                "running_after": bool(v.get("running_after", False)),
                "started_at_changed": bool(v.get("started_at_changed", False)),
                "health_after": str(v.get("health_after", "")),
            },
        }
    elif execution_status == "failed":
        phases["execution"] = {
            "status": "executed",
            "receipt": receipt_str,
            "result": "failed",
        }
        phases["verification"] = {
            "status": "failed",
            "receipt": receipt_str,
            "summary": {"status": "failed"},
        }
    else:  # refused
        phases["execution"] = {
            "status": "refused",
            "receipt": receipt_str,
            "refusal": refusal,
            "blockers": list(blockers or []),
        }
        phases["verification"] = {"status": "not_run", "receipt": None}

    payload["status"] = mission_status
    payload["updated_at"] = _now()

    safety = payload.setdefault("safety", {})
    # Schema invariants enforced by validate_mission_payload: when execution
    # status is `executed`, the receipt MUST be present; otherwise safety
    # mutation/exec flags MUST remain false.
    if execution_status == "executed" and receipt_str:
        safety["execution_allowed"] = True
        safety["execution_status"] = "executed"
        safety["mutation_performed"] = True
    else:
        safety["execution_allowed"] = False
        safety["execution_status"] = (
            "refused" if execution_status in ("refused", "failed") else "not_executed"
        )
        safety["mutation_performed"] = False
    safety["arbitrary_command_execution"] = False

    mission_dir(data_dir, mission_id).mkdir(parents=True, exist_ok=True)
    mission_json_path(data_dir, mission_id).write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    mission_md_path(data_dir, mission_id).write_text(_render_markdown(payload), encoding="utf-8")
    return payload


def validate_mission_path(path: Path) -> tuple[bool, list[str], dict[str, Any] | None]:
    p = Path(path)
    if not p.exists():
        return False, [f"mission file not found: {p}"], None
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return False, [f"mission JSON malformed: {exc}"], None
    errs = validate_mission_payload(payload)
    return (not errs), errs, payload
