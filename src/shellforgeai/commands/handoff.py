"""``handoff`` command registration and rendering helpers.

Behavior-preserving extraction of the read-only V2 operator handoff packet and
ShellForgeAI-owned handoff artifact lifecycle from ``cli.py``. The command
surface remains unchanged: ``handoff`` plus validate/export/export-validate/
history/compare/compare-latest subcommands. This module only collects existing
read-only deterministic posture and reads/writes ShellForgeAI-owned handoff
artifacts; it does not add cleanup, remediation, rollback, recovery,
Docker/Compose mutation, restart, shell, arbitrary command, natural-language,
or model execution behavior.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from shellforgeai.core.config import load_settings


def _cli() -> Any:
    return sys.modules["shellforgeai.cli"]


def _v2_handoff_safety() -> dict[str, Any]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "apply_executed": False,
        "mission_created": False,
        "plan_created": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "cleanup_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "model_called": False,
    }


def _handoff_proposal_status(propose_payload: dict[str, Any]) -> str:
    status = str(propose_payload.get("proposal_status") or "")
    if status == "no_action_needed":
        return "none_needed"
    if status == "available":
        return "preview"
    return "blocked"


def _handoff_apply_preview_status(apply_preview_payload: dict[str, Any]) -> str:
    status = str(apply_preview_payload.get("status") or "")
    if status == "preview_ready":
        return "preview_ready"
    if status == "no_action":
        return "no_action"
    return "blocked"


def _handoff_verify_status(verify_payload: dict[str, Any]) -> str:
    status = str(verify_payload.get("status") or "")
    if status in {"ok", "degraded"}:
        return status
    return "unknown"


def _handoff_risk(*, suspects: int, critical: int, high: int, target_found: bool | None) -> str:
    if target_found is False:
        return "unknown"
    if critical:
        return "high"
    if high:
        return "medium"
    if suspects:
        return "medium"
    return "low"


def _build_v2_handoff_payload(
    *,
    target: str | None = None,
    from_status: bool = False,
    from_triage: bool = False,
    from_propose: bool = False,
    from_apply_preview: bool = False,
    from_verify: bool = False,
    top: int = 5,
) -> dict[str, Any]:
    """Collect deterministic read-only V2 golden-path posture into one handoff packet.

    This reuses only read-only evidence/status/triage/propose/apply-preview/verify
    helpers. It never executes anything and never assumes an action was applied.
    """
    cli = _cli()
    triage_payload = cli._build_v2_triage_payload(top=top)
    propose_payload = cli._build_v2_propose_payload(target=target, from_triage=True, top=top)
    apply_preview_payload = cli._build_v2_apply_preview_payload(
        target=target, from_propose=True, top=top
    )
    verify_payload = cli._build_v2_verify_payload(target=target, from_triage=True, top=top)

    suspects = list(triage_payload.get("suspects") or [])
    triage_summary = (
        triage_payload.get("summary") if isinstance(triage_payload.get("summary"), dict) else {}
    )
    critical = int(triage_summary.get("critical", 0) or 0)
    high = int(triage_summary.get("high", 0) or 0)
    top_suspect = str((suspects[0] or {}).get("name") or "") if suspects else ""

    verify_target = (
        verify_payload.get("target") if isinstance(verify_payload.get("target"), dict) else {}
    )
    target_found: bool | None = bool(verify_target.get("found")) if target else None
    production_target = bool(verify_target.get("production_target"))

    limitations = [
        "Read-only deterministic V2 handoff summary only.",
        "No applied action was detected or assumed.",
    ]
    warnings: list[str] = []
    for source in (triage_payload, verify_payload):
        for w in source.get("warnings") or []:
            if w not in warnings:
                warnings.append(str(w))

    status_section_status = "degraded" if suspects else "ok"
    if target and not target_found:
        status = "unknown"
        first_safe = "shellforgeai triage --json"
        status_section_status = "unknown"
        not_found = "target not found in current deterministic triage scene"
        if not_found not in warnings:
            warnings.append(not_found)
        limitations.append("Requested target was not found in the current deterministic scene.")
    elif suspects:
        status = "degraded"
        first_safe = "shellforgeai triage --json"
    else:
        status = "ok"
        first_safe = "shellforgeai status --json"

    if production_target:
        production_note = (
            "Production-like target: read-only handoff only; no restart or remediation "
            "is suggested."
        )
        if production_note not in warnings:
            warnings.append(production_note)
        limitations.append(
            "Production-like target caution: inspect only unless governed workflows authorize "
            "change."
        )
        first_safe = "shellforgeai status --json"

    safe_next = list(
        dict.fromkeys(
            [
                first_safe,
                "shellforgeai triage --json",
                "shellforgeai propose --json",
                "shellforgeai verify --json",
            ]
        )
    )

    golden_path = {
        "status": {
            "status": status_section_status,
            "suspects_ranked": len(suspects),
            "critical": critical,
            "high": high,
            "first_safe_command": first_safe,
            "read_only": True,
        },
        "triage": {
            "status": str(triage_payload.get("status") or "ok"),
            "suspects_ranked": len(suspects),
            "top_suspect": top_suspect or None,
            "first_safe_command": triage_payload.get("first_safe_command"),
            "read_only": True,
        },
        "propose": {
            "status": str(propose_payload.get("status") or "ok"),
            "proposal_status": _handoff_proposal_status(propose_payload),
            "target": propose_payload.get("target"),
            "first_safe_command": propose_payload.get("first_safe_command"),
            "read_only": True,
        },
        "apply_preview": {
            "status": str(apply_preview_payload.get("status") or "no_action"),
            "target": (
                apply_preview_payload.get("target", {}).get("name")
                if isinstance(apply_preview_payload.get("target"), dict)
                else None
            ),
            "first_safe_command": apply_preview_payload.get("first_safe_command"),
            "read_only": True,
        },
        "verify": {
            "status": str(verify_payload.get("status") or "ok"),
            "verification_type": "current_state",
            "applied_action_assumed": False,
            "apply_receipt_present": False,
            "first_safe_command": verify_payload.get("first_safe_command"),
            "read_only": True,
        },
    }

    summary = {
        "current_status": status_section_status,
        "risk": _handoff_risk(
            suspects=len(suspects), critical=critical, high=high, target_found=target_found
        ),
        "suspects_ranked": len(suspects),
        "proposal_status": _handoff_proposal_status(propose_payload),
        "apply_preview_status": _handoff_apply_preview_status(apply_preview_payload),
        "verify_status": _handoff_verify_status(verify_payload),
        "top_suspect": top_suspect or None,
        "target": target,
        "target_found": target_found,
        "production_target": production_target,
    }

    safety = _v2_handoff_safety()
    return {
        "schema_version": 1,
        "mode": "v2_handoff",
        "status": status,
        "read_only": True,
        "mutation_performed": False,
        "artifact_written": False,
        "handoff_id": None,
        "handoff_path": None,
        "from_status": bool(from_status),
        "from_triage": bool(from_triage),
        "from_propose": bool(from_propose),
        "from_apply_preview": bool(from_apply_preview),
        "from_verify": bool(from_verify),
        "golden_path": golden_path,
        "summary": summary,
        "first_safe_command": first_safe,
        "safe_next_commands": safe_next,
        "limitations": limitations,
        "warnings": warnings,
        "safety": safety,
        **safety,
    }


def _handoff_stage_phrase(stage: str, golden_path: dict[str, Any], summary: dict[str, Any]) -> str:
    section = golden_path.get(stage) if isinstance(golden_path.get(stage), dict) else {}
    status = str(section.get("status") or "unknown")
    if stage == "status":
        if status == "ok":
            return "OK"
        if status == "unknown":
            return "unknown (requested target not visible)"
        return "degraded"
    if stage == "triage":
        suspects = int(section.get("suspects_ranked", 0) or 0)
        if not suspects:
            return "no suspects"
        top = section.get("top_suspect")
        return f"{suspects} suspects" + (f" (top: {top})" if top else "")
    if stage == "propose":
        proposal_status = str(summary.get("proposal_status") or "")
        if proposal_status == "none_needed":
            return "no action needed"
        if proposal_status == "preview":
            return "proposal preview available"
        return "blocked"
    if stage == "apply_preview":
        apply_status = str(summary.get("apply_preview_status") or "")
        if apply_status == "no_action":
            return "no eligible action"
        if apply_status == "preview_ready":
            return "preview ready (gated, not executed)"
        return "blocked"
    if stage == "verify":
        verify_status = str(summary.get("verify_status") or "")
        if verify_status == "ok":
            return "current state OK"
        if verify_status == "degraded":
            return "current state degraded"
        return "current state unknown"
    return status


def _render_v2_handoff_human(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    golden_path = payload.get("golden_path") if isinstance(payload.get("golden_path"), dict) else {}
    status = str(payload.get("status") or "unknown")
    suspects = int(summary.get("suspects_ranked", 0) or 0)
    header = status.upper() if status == "ok" else status
    lines: list[str] = [f"Handoff: {header}"]

    if summary.get("target") and summary.get("target_found") is False:
        lines.append(f"Status: target {summary.get('target')} not found in current triage scene")
    elif suspects:
        lines.append(f"Status: {suspects} ranked Docker suspects")
    else:
        lines.append("Status: no current Docker suspects")
    lines.append(f"Risk: {summary.get('risk', 'unknown')} from current container-visible evidence")
    if summary.get("production_target"):
        lines.append("Caution: production-like target; read-only handoff only.")

    lines.extend(["", "V2 path:"])
    lines.append(f"- Status: {_handoff_stage_phrase('status', golden_path, summary)}")
    lines.append(f"- Triage: {_handoff_stage_phrase('triage', golden_path, summary)}")
    lines.append(f"- Propose: {_handoff_stage_phrase('propose', golden_path, summary)}")
    lines.append(f"- Apply-preview: {_handoff_stage_phrase('apply_preview', golden_path, summary)}")
    lines.append(f"- Verify: {_handoff_stage_phrase('verify', golden_path, summary)}")

    lines.extend(["", "First safe command:", f"  {payload.get('first_safe_command')}"])
    lines.extend(
        [
            "",
            "What was not done:",
            "- No applied action was detected or assumed.",
            "- This handoff is a read-only operator summary.",
        ]
    )
    lines.extend(
        [
            "",
            "Safety:",
            "- Read-only handoff.",
            "- No apply, remediation, rollback, cleanup, Docker, or Compose action was executed.",
            "- No action was taken.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _render_v2_handoff_brief(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    return (
        f"Handoff: {payload.get('status')}\n"
        f"Risk: {summary.get('risk', 'unknown')}\n"
        f"First safe command: {payload.get('first_safe_command')}\n"
        "Safety: read-only; no apply/remediation/rollback/cleanup/Docker/Compose action executed\n"
    )


def _render_v2_handoff_saved_human(saved: dict[str, Any]) -> str:
    lines = [
        "Handoff saved:",
        f"  {saved.get('handoff_id')}",
        "Path:",
        f"  {saved.get('handoff_path')}",
        "First safe command:",
        f"  shellforgeai handoff validate {saved.get('handoff_id')}",
        "Safety: read-only handoff; no mutation performed.",
    ]
    return "\n".join(lines).rstrip() + "\n"


def _render_v2_handoff_validate_human(payload: dict[str, Any]) -> str:
    status = str(payload.get("status") or "failed")
    lines = [f"Handoff validation: {status}"]
    if status == "ok":
        lines.append("Checks: required files, JSON, manifest, checksums, safety")
        lines.append("Safety: read-only; no mutation recorded")
    else:
        lines.append(f"Handoff: {payload.get('handoff_id') or 'unknown'}")
        for warning in payload.get("warnings") or []:
            lines.append(f"- {warning}")
        lines.append("Safety: read-only; no mutation recorded")
    return "\n".join(lines).rstrip() + "\n"


def _render_v2_handoff_export_human(payload: dict[str, Any]) -> str:
    status = str(payload.get("status") or "failed")
    if status != "exported":
        lines = [f"Handoff export: {status}"]
        for warning in payload.get("warnings") or []:
            lines.append(f"- {warning}")
        lines.append("Safety: artifact export only; no mutation recorded")
        return "\n".join(lines).rstrip() + "\n"
    export = payload.get("export") if isinstance(payload.get("export"), dict) else {}
    header = (
        "Handoff export already exists (reused)"
        if payload.get("existing")
        else "Handoff export created"
    )
    lines = [
        header,
        f"Export ID: {export.get('id')}",
        f"Path: {export.get('path')}",
        "First safe command:",
        f"  shellforgeai handoff export-validate {export.get('id')}",
        "Safety: artifact export only; no mutation recorded",
    ]
    return "\n".join(lines).rstrip() + "\n"


def _render_v2_handoff_export_validate_human(payload: dict[str, Any]) -> str:
    status = str(payload.get("status") or "failed")
    lines = [f"Handoff export validation: {status}"]
    if status != "ok":
        lines.append(f"Export: {payload.get('export_id') or 'unknown'}")
        for warning in payload.get("warnings") or []:
            lines.append(f"- {warning}")
    lines.append("Safety: artifact export only; no mutation recorded")
    return "\n".join(lines).rstrip() + "\n"


def _render_v2_handoff_history_human(payload: dict[str, Any]) -> str:
    status = str(payload.get("status") or "empty")
    lines = ["V2 handoff history", ""]
    if status != "ok":
        lines.append("No saved V2 handoff artifacts found.")
        lines.extend(["", "First safe command:", f"  {payload.get('first_safe_command')}"])
        lines.extend(["", "Safety:", "- read_only=true", "- mutation_performed=false"])
        return "\n".join(lines).rstrip() + "\n"
    lines.append(f"Saved handoffs: {payload.get('count', 0)}")
    lines.append(f"Latest handoff id: {payload.get('latest_handoff_id') or '-'}")
    lines.append("")
    for idx, handoff_entry in enumerate(payload.get("handoffs") or [], start=1):
        lines.append(f"{idx}. {handoff_entry.get('handoff_id')}")
        lines.append(f"   created: {handoff_entry.get('created_at') or '-'}")
        lines.append(f"   status: {handoff_entry.get('status') or '-'}")
        lines.append(f"   risk: {handoff_entry.get('risk') or '-'}")
        if handoff_entry.get("target"):
            lines.append(f"   target: {handoff_entry.get('target')}")
        lines.append(f"   valid: {str(handoff_entry.get('valid', False)).lower()}")
        lines.append(f"   path: {handoff_entry.get('path')}")
    lines.extend(["", "Compare-latest availability:"])
    lines.append(
        "- available"
        if int(payload.get("count", 0) or 0) >= 2
        else "- unavailable (need >=2 saved handoffs)"
    )
    if payload.get("warnings"):
        lines.extend(["", "Warnings:"])
        for warning in payload.get("warnings") or []:
            lines.append(f"- {warning}")
    lines.extend(["", "Safe next commands:"])
    for cmd in (payload.get("safe_next_commands") or [])[:5]:
        lines.append(f"- {cmd}")
    lines.extend(["", "Safety:", "- read_only=true", "- mutation_performed=false"])
    return "\n".join(lines).rstrip() + "\n"


def _render_v2_handoff_compare_human(
    payload: dict[str, Any], *, include_stable: bool = False
) -> str:
    status = str(payload.get("status") or "failed")
    before = payload.get("before") if isinstance(payload.get("before"), dict) else {}
    after = payload.get("after") if isinstance(payload.get("after"), dict) else {}
    is_latest = bool(payload.get("latest")) or payload.get("mode") == "v2_handoff_compare_latest"
    title = "V2 handoff compare-latest" if is_latest else "V2 handoff compare"
    lines = [title, ""]
    if status != "ok":
        lines.append(f"Status: {status}")
        for warning in payload.get("warnings") or []:
            lines.append(f"- {warning}")
        if payload.get("first_safe_command"):
            lines.extend(["", "First safe command:", f"  {payload.get('first_safe_command')}"])
        lines.extend(["", "Safety:", "- read_only=true", "- mutation_performed=false"])
        return "\n".join(lines).rstrip() + "\n"
    lines.append("Handoffs:")
    lines.append(f"- before: {before.get('handoff_id') or before.get('handoff_ref') or 'unknown'}")
    lines.append(f"- after:  {after.get('handoff_id') or after.get('handoff_ref') or 'unknown'}")
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    lines.extend(["", "Summary of changes:"])
    for key in ("changed", "new", "resolved_or_missing", "stable", "safety_drift"):
        lines.append(f"- {key.replace('_', ' ')}: {summary.get(key, 0)}")
    changes = payload.get("changes") or []
    drift_changes = [c for c in changes if "drift" in c]
    lines.extend(["", "Changes:"])
    if not changes:
        lines.append("- none (handoffs are equivalent)")
    for change in changes:
        field = change.get("field")
        if "drift" in change:
            lines.append(f"- {field}: drift")
        elif "new" in change or "resolved_or_missing" in change:
            new = change.get("new") or []
            missing = change.get("resolved_or_missing") or []
            lines.append(f"- {field}: +{len(new)} / -{len(missing)}")
            for item in new:
                lines.append(f"    + {item}")
            for item in missing:
                lines.append(f"    - {item}")
        else:
            lines.append(f"- {field}: {change.get('before')} -> {change.get('after')}")
    lines.extend(["", "Safety drift:"])
    if drift_changes:
        for change in drift_changes:
            for item in change.get("drift") or []:
                lines.append(
                    f"- {item.get('flag')}: {str(item.get('before')).lower()} -> "
                    f"{str(item.get('after')).lower()}"
                )
    else:
        lines.append("- none")
    if include_stable and payload.get("stable"):
        lines.extend(["", "Stable:"])
        for entry in payload.get("stable") or []:
            if "stable" in entry:
                lines.append(f"- {entry.get('field')}: {len(entry.get('stable') or [])} stable")
            else:
                lines.append(f"- {entry.get('field')}: {entry.get('value')}")
    lines.extend(
        [
            "",
            "First safe command:",
            f"  {payload.get('first_safe_command') or 'shellforgeai handoff history'}",
        ]
    )
    lines.extend(
        [
            "",
            "Safety:",
            "- Read-only handoff compare.",
            "- No collectors rerun, no model call, no shell, no mutation.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def register(handoff_app: typer.Typer) -> None:
    """Register the read-only top-level ``handoff`` command group."""

    @handoff_app.callback()
    def handoff(
        ctx: typer.Context,
        json_output: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        brief: Annotated[
            bool, typer.Option("--brief", help="Emit bounded handoff output.")
        ] = False,
        save: Annotated[
            bool,
            typer.Option("--save", help="Save a ShellForgeAI-owned read-only handoff artifact."),
        ] = False,
        target: Annotated[
            str | None, typer.Option("--target", help="Include one exact visible target's context.")
        ] = None,
        from_status: Annotated[
            bool, typer.Option("--from-status", help="Use current deterministic status context.")
        ] = False,
        from_triage: Annotated[
            bool, typer.Option("--from-triage", help="Use current deterministic triage context.")
        ] = False,
        from_propose: Annotated[
            bool, typer.Option("--from-propose", help="Use current deterministic proposal context.")
        ] = False,
        from_apply_preview: Annotated[
            bool,
            typer.Option(
                "--from-apply-preview", help="Use current deterministic apply-preview context."
            ),
        ] = False,
        from_verify: Annotated[
            bool, typer.Option("--from-verify", help="Use current deterministic verify context.")
        ] = False,
    ) -> None:
        """Read-only V2 operator handoff packet.

        Summarizes the current deterministic status/triage/propose/apply-preview/verify
        posture, the first safe next command, and what was not done. It never applies,
        creates a mission/plan/receipt, executes remediation/rollback/cleanup, runs
        Docker/Compose, restarts containers, calls the model, or assumes any action
        happened. With ``--save`` it writes only a ShellForgeAI-owned handoff artifact.
        Subcommands ``validate``/``export``/``export-validate`` cover the read-only
        handoff artifact lifecycle.
        """
        if ctx.invoked_subcommand is not None:
            return
        payload = _build_v2_handoff_payload(
            target=target,
            from_status=from_status,
            from_triage=from_triage,
            from_propose=from_propose,
            from_apply_preview=from_apply_preview,
            from_verify=from_verify,
        )
        if save:
            from shellforgeai.core.v2_handoff_artifact import save_v2_handoff

            saved = save_v2_handoff(payload, Path(load_settings().app.data_dir))
            if json_output:
                typer.echo(json.dumps(saved))
                return
            typer.echo(_render_v2_handoff_saved_human(saved), nl=False)
            return
        if json_output:
            typer.echo(json.dumps(payload))
            return
        if brief:
            typer.echo(_render_v2_handoff_brief(payload), nl=False)
            return
        typer.echo(_render_v2_handoff_human(payload), nl=False)

    @handoff_app.command("validate")
    def handoff_validate(
        handoff_ref: Annotated[
            str, typer.Argument(help="Handoff id or ShellForgeAI-owned handoff directory path")
        ],
        json_output: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Read-only validation of a saved ShellForgeAI handoff artifact."""
        from shellforgeai.core.v2_handoff_artifact import validate_v2_handoff

        payload = validate_v2_handoff(handoff_ref, Path(load_settings().app.data_dir))
        if json_output:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "ok" else 1)
        typer.echo(_render_v2_handoff_validate_human(payload), nl=False)
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    @handoff_app.command("export")
    def handoff_export(
        handoff_ref: Annotated[
            str, typer.Argument(help="Handoff id or ShellForgeAI-owned handoff directory path")
        ],
        json_output: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Copy a validated handoff into a portable ShellForgeAI-owned export."""
        from shellforgeai.core.v2_handoff_artifact import export_v2_handoff

        payload = export_v2_handoff(handoff_ref, Path(load_settings().app.data_dir))
        if json_output:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "exported" else 1)
        typer.echo(_render_v2_handoff_export_human(payload), nl=False)
        if payload.get("status") != "exported":
            raise typer.Exit(1)

    @handoff_app.command("export-validate")
    def handoff_export_validate(
        export_ref: Annotated[
            str, typer.Argument(help="Export id or ShellForgeAI-owned export directory path")
        ],
        json_output: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Read-only validation of an exported ShellForgeAI handoff artifact."""
        from shellforgeai.core.v2_handoff_artifact import validate_v2_handoff_export

        payload = validate_v2_handoff_export(export_ref, Path(load_settings().app.data_dir))
        if json_output:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "ok" else 1)
        typer.echo(_render_v2_handoff_export_validate_human(payload), nl=False)
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    @handoff_app.command("history")
    def handoff_history(
        json_output: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        limit: Annotated[
            int, typer.Option("--limit", min=1, help="Max recent handoffs to list.")
        ] = 10,
    ) -> None:
        """Read-only list of recent saved ShellForgeAI V2 handoff artifacts.

        Lists saved handoffs (latest first) with id, timestamp, status, risk, target,
        and quick local validity. It never reruns collectors, calls the model,
        executes shell, or mutates anything. An empty history returns ``empty`` with
        ``shellforgeai handoff --save`` as the first safe command.
        """
        from shellforgeai.core.v2_handoff_artifact import v2_handoff_history

        payload = v2_handoff_history(Path(load_settings().app.data_dir), limit=limit)
        if json_output:
            typer.echo(json.dumps(payload))
            return
        typer.echo(_render_v2_handoff_history_human(payload), nl=False)

    @handoff_app.command("compare")
    def handoff_compare(
        before_ref: Annotated[
            str, typer.Argument(help="Before handoff id or ShellForgeAI-owned handoff path")
        ],
        after_ref: Annotated[
            str, typer.Argument(help="After handoff id or ShellForgeAI-owned handoff path")
        ],
        json_output: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        only_changed: Annotated[
            bool, typer.Option("--only-changed", help="Suppress stable items.")
        ] = False,
        include_stable: Annotated[
            bool, typer.Option("--include-stable", help="Include stable items.")
        ] = False,
    ) -> None:
        """Read-only drift compare of two saved ShellForgeAI V2 handoff artifacts.

        Reports drift in status/risk/target/current_status, golden-path stage
        summaries, first safe command, safe-next commands, limitations, warnings, and
        safety flags. Missing/unsafe/malformed refs fail cleanly (non-zero, no
        traceback). It never reruns collectors, calls the model, executes shell, or
        mutates anything.
        """
        from shellforgeai.core.v2_handoff_artifact import compare_v2_handoffs

        payload = compare_v2_handoffs(
            before_ref,
            after_ref,
            Path(load_settings().app.data_dir),
            only_changed=only_changed,
            include_stable=include_stable,
        )
        if json_output:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "ok" else 1)
        typer.echo(
            _render_v2_handoff_compare_human(payload, include_stable=include_stable), nl=False
        )
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    @handoff_app.command("compare-latest")
    def handoff_compare_latest(
        json_output: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        only_changed: Annotated[
            bool, typer.Option("--only-changed", help="Suppress stable items.")
        ] = False,
        include_stable: Annotated[
            bool, typer.Option("--include-stable", help="Include stable items.")
        ] = False,
    ) -> None:
        """Read-only compare of the two most recent saved V2 handoff artifacts.

        Returns a controlled ``not_enough_history`` status with
        ``shellforgeai handoff --save`` as the first safe command when fewer than two
        handoffs exist. It never creates artifacts, reruns collectors, calls the
        model, or executes shell.
        """
        from shellforgeai.core.v2_handoff_artifact import compare_latest_v2_handoffs

        payload = compare_latest_v2_handoffs(
            Path(load_settings().app.data_dir),
            only_changed=only_changed,
            include_stable=include_stable,
        )
        if json_output:
            typer.echo(json.dumps(payload))
            return
        typer.echo(
            _render_v2_handoff_compare_human(payload, include_stable=include_stable), nl=False
        )
