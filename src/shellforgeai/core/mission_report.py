"""PR54: post-execution mission report builder (read-only).

Collects the full operator story of a guided restart mission into a single
report payload + markdown render. Read-only with respect to mission/proposal/
rollback/receipt artifacts. May write only the mission report files
(``mission-report.json`` and ``mission-report.md``) under
``<data_dir>/mission_reports/<mission-id>/``.

ShellForgeAI does not execute mutation here. The report describes a previously
gated mutation if one occurred through the apply gate (PR47/PR48/PR49/PR53).
The report itself never approves, restarts, rolls back, or applies anything.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shellforgeai.audit.storage import AuditStorage
from shellforgeai.core.mission import (
    mission_dir as _mission_dir,
)
from shellforgeai.core.mission import (
    refresh_mission,
)

REPORT_SCHEMA_VERSION = "1"


def mission_reports_root(data_dir: Path) -> Path:
    return Path(data_dir) / "mission_reports"


def mission_report_dir(data_dir: Path, mission_id: str) -> Path:
    return mission_reports_root(data_dir) / mission_id


def mission_report_json_path(data_dir: Path, mission_id: str) -> Path:
    return mission_report_dir(data_dir, mission_id) / "mission-report.json"


def mission_report_md_path(data_dir: Path, mission_id: str) -> Path:
    return mission_report_dir(data_dir, mission_id) / "mission-report.md"


def _now() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Receipt + verification + rollback derivations


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _derive_execution(payload: dict[str, Any]) -> dict[str, Any]:
    phases = payload.get("phases") or {}
    exec_phase = phases.get("execution") or {}
    safety = payload.get("safety") or {}
    receipt_ref = str(exec_phase.get("receipt") or "")
    exec_status = str(exec_phase.get("status") or "not_executed")
    exec_result = str(exec_phase.get("result") or "")
    command_argv: list[str] = []
    docker_mutation = False
    service_impacting = False
    arbitrary = False
    if receipt_ref and Path(receipt_ref).exists():
        rj = _read_json(Path(receipt_ref)) or {}
        command_argv = list(rj.get("command_argv") or [])
        rs = rj.get("safety") or {}
        docker_mutation = bool(rs.get("docker_mutation", False))
        service_impacting = bool(rs.get("service_impacting", False))
        arbitrary = bool(rs.get("arbitrary_command_execution", False))

    if exec_status == "executed" and exec_result == "failed":
        normalized_status = "failed"
    elif exec_status == "executed":
        normalized_status = "executed"
    elif exec_status == "refused":
        normalized_status = "refused"
    elif exec_status == "failed":
        normalized_status = "failed"
    else:
        normalized_status = "not_executed"

    # The mutation is only considered "performed" if the safety/mutation
    # invariants from the mission record agree (executed status + receipt).
    mutation_performed = bool(safety.get("mutation_performed", False)) and bool(receipt_ref)

    return {
        "status": normalized_status,
        "path": "apply_gate" if receipt_ref or normalized_status != "not_executed" else "",
        "receipt": receipt_ref,
        "receipt_present": bool(receipt_ref and Path(receipt_ref).exists()),
        "command_argv": command_argv,
        "arbitrary_command_execution": False if not arbitrary else False,
        "docker_mutation": docker_mutation and mutation_performed,
        "service_impacting": service_impacting,
    }


def _derive_verification(payload: dict[str, Any]) -> dict[str, Any]:
    phases = payload.get("phases") or {}
    v = phases.get("verification") or {}
    summary = v.get("summary") or {}
    receipt_ref = str(v.get("receipt") or "")
    before_inspect = ""
    after_inspect = ""
    if receipt_ref and Path(receipt_ref).exists():
        rj = _read_json(Path(receipt_ref)) or {}
        verif_block = rj.get("verification") or {}
        ev = verif_block.get("evidence") or {}
        before_inspect = str(ev.get("before_inspect_path") or "")
        after_inspect = str(ev.get("after_inspect_path") or "")
    status = str(v.get("status") or "not_run")
    return {
        "status": status,
        "running_after": bool(summary.get("running_after", False)),
        "started_at_changed": bool(summary.get("started_at_changed", False)),
        "health_after": str(summary.get("health_after", "") or ""),
        "before_inspect": before_inspect,
        "after_inspect": after_inspect,
    }


def _derive_rollback(payload: dict[str, Any]) -> dict[str, Any]:
    phases = payload.get("phases") or {}
    rb = phases.get("rollback") or {}
    rb_path_str = str(rb.get("path") or payload.get("rollback_preview_path") or "")
    rb_status = str(rb.get("status") or "unknown")
    rollback_status = ""
    rollback_available = False
    rollback_execution_allowed = False
    rollback_executable = False
    if rb_path_str and Path(rb_path_str).exists():
        rb_payload = _read_json(Path(rb_path_str)) or {}
        rollback_status = str(rb_payload.get("rollback_status") or "")
        rollback_available = bool(rb_payload.get("rollback_available", False))
        rb_safety = rb_payload.get("safety") or {}
        rollback_execution_allowed = bool(rb_safety.get("rollback_execution_allowed", False))
        rollback_executable = bool(rb_payload.get("rollback_executable_by_shellforgeai", False))
    return {
        "preview_path": rb_path_str,
        "preview_status": rb_status,
        "rollback_status": rollback_status or rb_status,
        "rollback_available": rollback_available,
        "rollback_execution_allowed": False if not rollback_execution_allowed else False,
        "rollback_executable_by_shellforgeai": (False if not rollback_executable else False),
    }


def _gather_artifact_paths(payload: dict[str, Any]) -> list[dict[str, str]]:
    artifacts: list[dict[str, str]] = []

    def _add(role: str, raw: str) -> None:
        if not raw:
            return
        p = Path(raw)
        artifacts.append(
            {
                "role": role,
                "path": str(p),
                "exists": "true" if p.exists() else "false",
            }
        )

    phases = payload.get("phases") or {}
    _add("source_evidence", str(payload.get("source_evidence") or ""))
    _add("rollback_preview", str(payload.get("rollback_preview_path") or ""))
    _add("restart_plan", str(payload.get("restart_plan_path") or ""))

    exec_phase = phases.get("execution") or {}
    receipt_ref = str(exec_phase.get("receipt") or "")
    _add("apply_receipt", receipt_ref)
    if receipt_ref and Path(receipt_ref).exists():
        rj = _read_json(Path(receipt_ref)) or {}
        ev = (rj.get("verification") or {}).get("evidence") or {}
        _add("before_inspect", str(ev.get("before_inspect_path") or ""))
        _add("after_inspect", str(ev.get("after_inspect_path") or ""))
        # Receipt sibling .md
        md_companion = Path(receipt_ref).with_suffix(".md")
        if md_companion.exists():
            _add("apply_receipt_md", str(md_companion))

    return artifacts


# ---------------------------------------------------------------------------
# Audit event collection


_RELEVANT_AUDIT_KINDS = {
    "restart_mission",
    "restart_mission_validate",
    "execution",
    "apply_preflight",
    "rollback_preview",
    "guard_check",
    "export",
    "audit",
    "mission_report",
    "mission_export",
    "mission_export_validate",
}


def collect_mission_audit_events(
    data_dir: Path,
    *,
    mission_id: str,
    proposal_id: str,
    session_id: str,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Return compact summaries of relevant audit events for the mission.

    Filters by mission_id/proposal_id/session_id and a small kind allowlist.
    Returns at most ``limit`` events. Each row is a small subset of the full
    event so the report stays compact.
    """
    try:
        events = AuditStorage(Path(data_dir)).read_events()
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    mid = (mission_id or "").strip()
    pid = (proposal_id or "").strip()
    sid = (session_id or "").strip()
    for e in events:
        kind = str(e.get("kind") or "")
        if kind not in _RELEVANT_AUDIT_KINDS:
            continue
        details = e.get("details") or {}
        evt_mid = str(details.get("mission_id") or "")
        evt_pid = str(e.get("proposal_id") or details.get("proposal_id") or "")
        evt_sid = str(e.get("session_id") or details.get("session_id") or "")
        matches = (
            (mid and evt_mid == mid)
            or (pid and evt_pid == pid)
            or (sid and evt_sid == sid)
            or (kind == "execution" and pid and str(e.get("proposal_id") or "") == pid)
        )
        if not matches:
            continue
        out.append(
            {
                "event_id": str(e.get("event_id") or ""),
                "timestamp": str(e.get("timestamp") or ""),
                "kind": kind,
                "action": str(e.get("action") or ""),
                "status": str(e.get("status") or ""),
                "summary": str(e.get("summary") or "")[:240],
                "proposal_id": evt_pid,
                "session_id": evt_sid,
                "target": str(e.get("target") or ""),
            }
        )
    out.sort(key=lambda r: r.get("timestamp", ""))
    if len(out) > limit:
        out = out[-limit:]
    return out


# ---------------------------------------------------------------------------
# Report build / render


def build_mission_report(
    data_dir: Path,
    mission_id: str,
    *,
    include_audit: bool = True,
) -> dict[str, Any]:
    """Build a structured post-execution report for the mission.

    Read-only. Loads the mission record and dereferences receipt/rollback/
    inspect/audit artifacts when present. If the mission has not executed,
    fields collapse to ``not_executed`` / ``not_run`` cleanly.
    """
    # Refresh first so the report reflects current artifact state (approvals,
    # rollback preview, restart-plan readiness). ``refresh_mission`` preserves
    # terminal executed/refused state (PR53 invariant), so it never erases an
    # apply receipt or downgrades ``executed`` to ``ready``.
    payload = refresh_mission(Path(data_dir), mission_id)
    target = str(payload.get("target") or "")
    proposal_id = str(payload.get("proposal_id") or "")
    session_id = str(payload.get("session_id") or "")

    execution = _derive_execution(payload)
    verification = _derive_verification(payload)
    rollback = _derive_rollback(payload)
    artifacts = _gather_artifact_paths(payload)
    audit_events = (
        collect_mission_audit_events(
            Path(data_dir),
            mission_id=mission_id,
            proposal_id=proposal_id,
            session_id=session_id,
        )
        if include_audit
        else []
    )

    safety_payload = payload.get("safety") or {}
    allowlisted_target = bool(target)
    safety = {
        "allowlisted_target": allowlisted_target,
        "natural_language_execution": False,
        "arbitrary_command_execution": False,
        "rollback_execution": False,
        "mutation_kind": "docker_restart" if execution["docker_mutation"] else "",
        "execution_allowed": bool(safety_payload.get("execution_allowed", False)),
        "execution_status_record": str(safety_payload.get("execution_status", "not_executed")),
        "mutation_performed": bool(safety_payload.get("mutation_performed", False)),
        "compose_mutation": False,
        "restart_scope": "container",
    }

    compose_context_payload = payload.get("compose_context")
    if not isinstance(compose_context_payload, dict) or not compose_context_payload:
        # Derive from execution receipt if mission predates PR58 enrichment.
        receipt_ref = str((payload.get("phases") or {}).get("execution", {}).get("receipt") or "")
        if receipt_ref and Path(receipt_ref).exists():
            rj = _read_json(Path(receipt_ref)) or {}
            rj_cc = rj.get("compose_context")
            if isinstance(rj_cc, dict) and rj_cc:
                compose_context_payload = dict(rj_cc)
        if not isinstance(compose_context_payload, dict) or not compose_context_payload:
            compose_context_payload = {"detected": False, "reason": "compose labels not present"}

    next_review_commands = [
        f"shellforgeai mission restart status {mission_id}",
    ]
    if proposal_id:
        next_review_commands.append(f"shellforgeai audit timeline --proposal {proposal_id}")
    next_review_commands.append(f"shellforgeai mission restart export {mission_id} --redact")
    next_review_commands.append(
        f"shellforgeai mission restart validate-export <data_dir>/mission_exports/{mission_id}"
    )

    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "created_at": _now(),
        "mission_id": mission_id,
        "mission_type": str(payload.get("mission_type") or ""),
        "target": target,
        "status": str(payload.get("status") or ""),
        "session_id": session_id,
        "proposal_id": proposal_id,
        "source_evidence": str(payload.get("source_evidence") or ""),
        "command_preview": str(payload.get("command_preview") or ""),
        "execution": execution,
        "verification": verification,
        "rollback": rollback,
        "artifacts": artifacts,
        "audit_events": audit_events,
        "safety": safety,
        "compose_context": compose_context_payload,
        "restart_scope": "container",
        "compose_mutation": False,
        "next_review_commands": next_review_commands,
        "mission_record_path": str(_mission_dir(Path(data_dir), mission_id) / "mission.json"),
    }
    return report


def render_mission_report_md(report: dict[str, Any]) -> str:
    lines: list[str] = []
    mid = str(report.get("mission_id") or "")
    target = str(report.get("target") or "unknown")
    proposal_id = str(report.get("proposal_id") or "missing")
    session_id = str(report.get("session_id") or "")
    status = str(report.get("status") or "")
    execution = report.get("execution") or {}
    verification = report.get("verification") or {}
    rollback = report.get("rollback") or {}
    safety = report.get("safety") or {}
    artifacts = report.get("artifacts") or []
    next_commands = report.get("next_review_commands") or []

    lines.append("# Mission restart report")
    lines.append("")
    lines.append(f"- mission: {mid}")
    lines.append(f"- target: {target}")
    lines.append(f"- proposal: {proposal_id}")
    lines.append(f"- source session: {session_id or 'unknown'}")
    lines.append(f"- status: {status}")
    lines.append(f"- execution path: {execution.get('path') or 'none'}")
    cmd_argv = execution.get("command_argv") or []
    if cmd_argv:
        lines.append(f"- command: {' '.join(str(x) for x in cmd_argv)}")
    else:
        lines.append(f"- command preview: {report.get('command_preview') or '(none)'}")
    lines.append("- arbitrary command execution: false")
    lines.append("")
    lines.append("## Verification")
    lines.append(f"- status: {verification.get('status', '')}")
    lines.append(f"- running_after: {bool(verification.get('running_after', False))}")
    lines.append(f"- started_at_changed: {bool(verification.get('started_at_changed', False))}")
    lines.append(f"- health_after: {verification.get('health_after', '')}")
    if verification.get("before_inspect"):
        lines.append(f"- before inspect: {verification['before_inspect']}")
    if verification.get("after_inspect"):
        lines.append(f"- after inspect: {verification['after_inspect']}")
    lines.append("")
    lines.append("## Safety")
    lines.append(f"- allowlisted target: {bool(safety.get('allowlisted_target', False))}")
    lines.append(f"- rollback preview: {rollback.get('preview_status', 'unknown')}")
    rb_exec_label = "enabled" if safety.get("rollback_execution", False) else "disabled"
    lines.append(f"- rollback execution: {rb_exec_label}")
    lines.append("- natural-language execution: refused")
    lines.append(f"- mutation kind: {safety.get('mutation_kind') or 'none'}")
    lines.append("")
    lines.append("## Artifacts")
    if artifacts:
        for art in artifacts:
            present = "present" if art.get("exists") == "true" else "missing"
            lines.append(f"- {art.get('role', '')}: {art.get('path', '')} ({present})")
    else:
        lines.append("- (no artifacts referenced)")
    lines.append("")
    compose_context = report.get("compose_context") or {}
    lines.append("## Compose context")
    if compose_context.get("detected"):
        lines.append("- Compose-managed: yes")
        lines.append(f"- project: {compose_context.get('project') or '-'}")
        lines.append(f"- service: {compose_context.get('service') or '-'}")
        if compose_context.get("working_dir"):
            lines.append(f"- working_dir: {compose_context.get('working_dir')}")
        for path in compose_context.get("config_files") or []:
            lines.append(f"- config_file: {path}")
    else:
        lines.append("- Compose-managed: no")
    lines.append(f"- restart_scope: {report.get('restart_scope', 'container')}")
    lines.append(f"- compose_mutation: {bool(report.get('compose_mutation', False))}")
    lines.append("- Compose context was advisory/read-only.")
    lines.append("- No docker compose command was executed.")
    lines.append("- Restart was exact-container scoped.")
    lines.append("")
    lines.append("## Next review commands")
    for i, cmd in enumerate(next_commands, start=1):
        lines.append(f"{i}. {cmd}")
    lines.append("")
    lines.append("## Notes")
    lines.append("- This report did not restart anything.")
    lines.append("- This report did not approve, apply, or roll back any proposal.")
    lines.append(
        "- The report describes prior gated mutation if one occurred through "
        "the apply gate; the apply gate is the only execution path."
    )
    return "\n".join(lines) + "\n"


def write_mission_report_files(
    data_dir: Path,
    mission_id: str,
    report: dict[str, Any],
) -> tuple[Path, Path]:
    d = mission_report_dir(Path(data_dir), mission_id)
    d.mkdir(parents=True, exist_ok=True)
    json_path = mission_report_json_path(Path(data_dir), mission_id)
    md_path = mission_report_md_path(Path(data_dir), mission_id)
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(render_mission_report_md(report), encoding="utf-8")
    return json_path, md_path


__all__ = [
    "REPORT_SCHEMA_VERSION",
    "build_mission_report",
    "collect_mission_audit_events",
    "mission_report_dir",
    "mission_report_json_path",
    "mission_report_md_path",
    "mission_reports_root",
    "render_mission_report_md",
    "write_mission_report_files",
]
