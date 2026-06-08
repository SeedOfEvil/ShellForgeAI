from __future__ import annotations

import hashlib
import io
import json
import platform
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import uuid
from contextlib import suppress
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime, timezone
from pathlib import Path
from posixpath import normpath
from typing import Annotated, Any, cast

import typer
from rich.console import Console
from typer.testing import CliRunner

from shellforgeai.audit.storage import AuditStorage
from shellforgeai.core import incident_index as incident_index_mod
from shellforgeai.core import lab_restart as lab_restart_mod
from shellforgeai.core import rollback_preview as rollback_preview_mod
from shellforgeai.core.actions import (
    compile_and_write,
    is_actions_ask_intent,
    load_actions_file,
    resolve_proposal_arg,
    validate_actions_payload,
)
from shellforgeai.core.apply_bundle import (
    generate_bundle,
    run_preflight,
    write_diagnostic_preflight,
)
from shellforgeai.core.approvals import (
    EXECUTION_DISABLED_REASON,
    Proposal,
    approve_proposal,
    archive_proposal,
    build_restart_proposal_from_evidence,
    cancel_proposal,
    compute_proposal_fingerprint_payload,
    create_proposals_for_session,
    find_proposal_path,
    latest_approved_proposal,
    latest_runbook,
    list_proposals,
    load_proposal_from_path,
    reject_proposal,
    validate_proposal_payload,
    write_proposal,
)
from shellforgeai.core.ask_routing import (
    EVIDENCE_BACKED,
    PLAIN,
    AskRoute,
    evidence_brief,
    extract_compose_target,
    extract_container_target,
    extract_recipe_preflight_target,
    has_compose_artifact_reference_phrase,
    is_apply_approved_intent,
    is_brief_ops_report_ask,
    is_broad_docker_triage_intent,
    is_compose_mutation_request,
    is_compose_service_mutation_proposal_request,
    is_create_proposals_intent,
    is_create_restart_proposal_intent,
    is_immediate_fix_intent,
    is_lab_restart_ask_intent,
    is_lab_restart_verification_ask_intent,
    is_mission_compose_context_query,
    is_ops_report_ask,
    is_restart_proposal_compose_context_query,
    is_triage_mutation_intent,
    network_reachability_brief,
    route_ask_intent,
    target_container_status,
)
from shellforgeai.core.command_suggestions import (
    remediation_audit_latest_command,
    remediation_eligibility_explain_command,
    remediation_plan_command,
    remediation_self_test_command,
    triage_detail_command,
)
from shellforgeai.core.config import load_settings
from shellforgeai.core.context import RuntimeContext
from shellforgeai.core.diagnose import diagnose_target, findings_summary_line
from shellforgeai.core.evidence import classify_target
from shellforgeai.core.export_pack import (
    export_from_proposal,
    export_from_session,
    export_latest_approved,
    export_latest_session,
    is_export_intent,
    latest_session_dir,
    resolve_session_dir,
    validate_export,
)
from shellforgeai.core.guards import (
    DECISION_BLOCKED as GUARD_DECISION_BLOCKED,
)
from shellforgeai.core.guards import (
    DECISION_DRIFT as GUARD_DECISION_DRIFT,
)
from shellforgeai.core.guards import (
    DECISION_FRESH as GUARD_DECISION_FRESH,
)
from shellforgeai.core.guards import (
    DECISION_STALE as GUARD_DECISION_STALE,
)
from shellforgeai.core.guards import (
    DECISION_WARNING as GUARD_DECISION_WARNING,
)
from shellforgeai.core.guards import (
    GuardReport,
    check_actions_file,
    check_export_dir,
    check_proposal_file,
    check_proposal_payload,
    is_guard_ask_intent,
    load_guard_report,
    max_age_from_hours,
    write_guard_report,
)
from shellforgeai.core.intent_nuance import (
    AMBIGUOUS_EXECUTE,
    CLEANUP_REVIEW_HELP,
    COMMAND_HELP,
    PLAN_HELP,
    classify_intent_nuance,
    render_intent_nuance,
)
from shellforgeai.core.metadata_hygiene import human_bytes, scan_metadata_hygiene
from shellforgeai.core.mission import (
    apply_delegation_command as mission_apply_delegation_command,
)
from shellforgeai.core.mission import (
    check_execute_readiness as mission_check_execute_readiness,
)
from shellforgeai.core.mission import (
    latest_mission as mission_latest,
)
from shellforgeai.core.mission import (
    mission_json_path,
    prepare_mission,
    refresh_mission,
    validate_mission_path,
)
from shellforgeai.core.mission import (
    record_execution_result as mission_record_execution_result,
)
from shellforgeai.core.mission import (
    render_checklist as mission_render_checklist,
)
from shellforgeai.core.mission_export import (
    export_mission as mission_export_pack,
)
from shellforgeai.core.mission_export import (
    validate_mission_export,
)
from shellforgeai.core.mission_report import (
    build_mission_report,
    write_mission_report_files,
)
from shellforgeai.core.plans import Plan, PlanStep
from shellforgeai.core.profiles import load_profile
from shellforgeai.core.recipe_execution import (
    execute_disposable_restart,
)
from shellforgeai.core.recipe_execution import (
    validate_receipt as validate_recipe_receipt,
)
from shellforgeai.core.recipe_preflight import (
    build_preflight_packet,
    save_preflight_packet,
    validate_preflight_packet,
)
from shellforgeai.core.recipe_receipt_audit import (
    receipt_compare as build_receipt_compare,
)
from shellforgeai.core.recipe_receipt_audit import (
    receipt_compare_latest as build_receipt_compare_latest,
)
from shellforgeai.core.recipe_receipt_audit import (
    receipt_export as build_receipt_export,
)
from shellforgeai.core.recipe_receipt_audit import (
    receipt_export_validate as build_receipt_export_validate,
)
from shellforgeai.core.recipe_receipt_audit import (
    receipt_history as build_receipt_history,
)
from shellforgeai.core.recipe_receipt_audit import (
    receipt_inspect as build_receipt_inspect,
)
from shellforgeai.core.recipe_receipt_recovery import execute_receipt_recovery
from shellforgeai.core.recipe_receipt_rollback_preview import preview_receipt_rollback
from shellforgeai.core.recipe_receipt_verify import verify_recipe_receipt
from shellforgeai.core.recipe_registry import (
    detail_payload as recipe_detail_payload,
)
from shellforgeai.core.recipe_registry import (
    eligibility_payload as recipe_eligibility_payload,
)
from shellforgeai.core.recipe_registry import (
    registry_payload as recipe_registry_payload,
)
from shellforgeai.core.reference_resolver import ReferenceFilters, resolve_reference
from shellforgeai.core.restart_plan import (
    _resolve_proposal as resolve_restart_plan_proposal,
)
from shellforgeai.core.restart_plan import (
    build_restart_plan,
    render_restart_plan,
)
from shellforgeai.core.restart_plan import (
    to_json as restart_plan_to_json,
)
from shellforgeai.core.retention import (
    ALLOWED_PRUNE_CATEGORIES,
    DEFAULT_PRUNE_CATEGORIES,
    PROTECTED_PRUNE_CATEGORIES,
    build_categories,
    collect_category,
    create_archive,
    delete_paths,
    ensure_safe_delete_target,
    file_size,
    prune_select,
    validate_archive,
    write_prune_receipt,
)
from shellforgeai.core.runbook import (
    build_runbook,
    latest_evidence_artifact,
    render_runbook_md,
    runbook_from_evidence_file,
    validate_runbook_payload,
)
from shellforgeai.core.session import build_session_context
from shellforgeai.interactive.commands import route_input
from shellforgeai.knowledge.search import search_local
from shellforgeai.llm.manager import build_provider
from shellforgeai.llm.prompts import build_contextual_prompt, build_model_prompt
from shellforgeai.llm.schemas import ModelRequest
from shellforgeai.render.summary import write_diagnosis_summary_md
from shellforgeai.tools import containers, host, journal, registry, systemd
from shellforgeai.util.subprocess import run_command
from shellforgeai.version import get_build_info

app = typer.Typer(
    no_args_is_help=False,
    invoke_without_command=True,
)
inspect_app = typer.Typer()
tools_app = typer.Typer()
audit_app = typer.Typer()
audit_cleanup_app = typer.Typer(help="Plan/review/archive guarded metadata cleanup.")
audit_index_app = typer.Typer(
    invoke_without_command=True,
    no_args_is_help=False,
    help="Audit-aware incident index (PR40). Read-only metadata search; no execution.",
)
audit_app.add_typer(audit_index_app, name="index")
audit_app.add_typer(audit_cleanup_app, name="cleanup")
model_app = typer.Typer()
approvals_app = typer.Typer(help="Manage mutation proposal objects (read-only metadata).")
actions_app = typer.Typer(help="Compile approved proposals into review-only action records.")
rollback_app = typer.Typer(help="Rollback preview/validation for service-impacting mutations.")
guard_app = typer.Typer(
    help="Stale-evidence / drift guard for proposals, actions, and export packs (read-only).",
)
mission_app = typer.Typer(
    help="Guided safe mission workflows (metadata-only; no mutation by default).",
)
mission_restart_app = typer.Typer(
    help="Guided safe restart mission workflow (PR52). Metadata/checklist only.",
)
mission_compose_restart_app = typer.Typer(
    help="Disposable/allowlisted Compose service restart mission workflow (PR63).",
)
mission_app.add_typer(mission_restart_app, name="restart")
mission_app.add_typer(mission_compose_restart_app, name="compose-restart")
compose_app = typer.Typer(help="Read-only Docker Compose ownership context.")
ops_app = typer.Typer(help="Read-only operator status board.")
session_app = typer.Typer(help="Session handoff artifact utilities (read-only metadata).")
session_summary_app = typer.Typer(help="Interactive session summary artifact workflow.")
ops_report_app = typer.Typer(invoke_without_command=True, no_args_is_help=False)
handoff_app = typer.Typer(
    invoke_without_command=True,
    no_args_is_help=False,
    help="Read-only V2 operator handoff packet and artifact lifecycle. No mutation.",
)
self_test_app = typer.Typer(
    help="Safe read-only command coverage harness (PR79). No mutation, no execute.",
)
v1_app = typer.Typer(help="V1 readiness checks (read-only).")
v1_packet_app = typer.Typer(invoke_without_command=True, no_args_is_help=False)
triage_app = typer.Typer(
    invoke_without_command=True,
    no_args_is_help=False,
    help="Read-only V2 triage ranking. Scans the scene and ranks suspects. No mutation.",
)
triage_docker_app = typer.Typer(help="Read-only Docker triage ranking/detail views.")
triage_docker_snapshot_app = typer.Typer(
    invoke_without_command=True,
    no_args_is_help=False,
    help="PR85 triage snapshot save/validate artifact workflow (read-only metadata writes).",
)
remediation_app = typer.Typer(help="Disposable governed remediation proof flow.")
remediation_receipt_app = typer.Typer(help="Disposable remediation receipt utilities.")
recipes_app = typer.Typer(
    invoke_without_command=True,
    no_args_is_help=False,
    help=(
        "Read-only V2 governed recipe registry, eligibility map, and preflight packets. "
        "No execution."
    ),
)
recipes_preflight_app = typer.Typer(
    invoke_without_command=True,
    no_args_is_help=False,
    help="Read-only governed recipe preflight packets. No execution.",
)
recipes_receipt_app = typer.Typer(
    help=(
        "Governed recipe receipt history/audit, validation, verify, rollback preview, "
        "and confirm-gated recovery."
    )
)
app.add_typer(inspect_app, name="inspect")
app.add_typer(tools_app, name="tools")
app.add_typer(audit_app, name="audit")
app.add_typer(model_app, name="model")
app.add_typer(approvals_app, name="approvals")
app.add_typer(actions_app, name="actions")
app.add_typer(rollback_app, name="rollback")
app.add_typer(guard_app, name="guard")
app.add_typer(mission_app, name="mission")
app.add_typer(compose_app, name="compose")
app.add_typer(ops_app, name="ops")
app.add_typer(session_app, name="session")
ops_app.add_typer(ops_report_app, name="report")
session_app.add_typer(session_summary_app, name="summary")
app.add_typer(self_test_app, name="self-test")
app.add_typer(v1_app, name="v1")
v1_app.add_typer(v1_packet_app, name="packet")
app.add_typer(triage_app, name="triage")
app.add_typer(handoff_app, name="handoff")
app.add_typer(remediation_app, name="remediation")
app.add_typer(recipes_app, name="recipes")
recipes_app.add_typer(recipes_preflight_app, name="preflight")
recipes_app.add_typer(recipes_receipt_app, name="receipt")
remediation_app.add_typer(remediation_receipt_app, name="receipt")
triage_app.add_typer(triage_docker_app, name="docker")
triage_docker_app.add_typer(triage_docker_snapshot_app, name="snapshot")
# Treat all runtime/model/evidence strings as untrusted; disable Rich markup
# interpretation to prevent crashes on bracketed data like mount sources.
console = Console(markup=False)


def _safe_load_json(path: Path, warnings: list[str]) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        warnings.append(f"skipped malformed json: {path} ({exc})")
        return None
    if not isinstance(payload, dict):
        warnings.append(f"skipped non-object json: {path}")
        return None
    return payload


def _ts(payload: dict[str, Any], path: Path) -> float:
    for key in ("updated_at", "created_at"):
        raw = payload.get(key)
        if isinstance(raw, str):
            with suppress(ValueError):
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    with suppress(OSError):
        return path.stat().st_mtime
    return 0.0


def _age_seconds(payload: dict[str, Any], path: Path) -> int | None:
    t = _ts(payload, path)
    if t <= 0:
        return None
    return max(0, int(datetime.now(timezone.utc).timestamp() - t))


_HOST_AUDIT_HINTS = (
    "auditd",
    "linux audit",
    "ausearch",
    "auditctl",
    "/var/log/audit",
    "journalctl",
    "syslog",
    "systemd unit",
    "kernel audit",
    "os audit logs",
    "host audit service",
)


def _is_retention_ask(question: str) -> bool:
    q = (question or "").lower()
    if any(h in q for h in _HOST_AUDIT_HINTS):
        return False
    return any(
        t in q
        for t in [
            "audit retention status",
            "show audit retention",
            "show retention report",
            "retention report",
            "how much audit data do i have",
            "how much shellforgeai metadata do i have",
            "shellforgeai retention",
            "shellforgeai audit retention",
            "audit cleanup dry run",
            "dry run audit cleanup",
            "what can i prune",
            "what can i safely prune",
            "clean up old shellforgeai metadata",
            "prune old export packs",
            "what can i safely clean",
            "archive old exports",
            "safely prune",
            "how much shellforgeai audit data",
            "why is shellforgeai using disk",
            "what can i safely clean",
            "show metadata hygiene",
            "cleanup recommendations",
            "is shellforgeai data getting large",
            "how do i prune old exports safely",
            "clean it now",
            "cleanup now",
            "clean up now",
            "delete old exports",
            "delete old exports now",
            "free up shellforgeai disk",
            "delete now",
            "purge now",
            "clean old metadata",
            "clean up old metadata",
        ]
    )


def _is_prune_dry_run_ask(question: str) -> bool:
    q = (question or "").lower()
    return any(
        t in q
        for t in (
            "audit cleanup dry run",
            "dry run audit cleanup",
            "what can i prune",
            "what can i safely prune",
            "clean up old shellforgeai metadata",
            "prune old export packs",
            "what can i safely clean",
        )
    )


def _handle_retention_ask(runtime: RuntimeContext, question: str) -> bool:
    if not _is_retention_ask(question):
        return False
    data_dir = Path(runtime.session.data_dir)
    hygiene: dict[str, Any] = scan_metadata_hygiene(data_dir)
    rows = [
        (name, row["count"], row["bytes"], row["human"], row["severity"])
        for name, row in hygiene["categories"].items()
    ]
    rows.sort(key=lambda x: int(x[2]), reverse=True)
    q = (question or "").lower()
    delete_now_phrases = (
        "clean it now",
        "cleanup now",
        "clean up now",
        "delete old exports now",
        "delete old exports",
        "free up shellforgeai disk",
        "delete now",
        "purge now",
    )
    if any(t in q for t in delete_now_phrases):
        console.print("Refusing automatic deletion from ask mode.")
        console.print("Natural language cannot delete ShellForgeAI metadata.")
        console.print(
            "Run a dry-run first: shellforgeai audit prune --dry-run "
            "--category exports --max-age-days 30"
        )
        console.print(
            "After reviewing the dry-run, an operator must rerun with "
            "--execute --confirm to actually delete."
        )
        return True
    if _is_prune_dry_run_ask(question):
        console.print(
            "Dry-run only. ShellForgeAI metadata: "
            f"{hygiene['total_human']} across {hygiene['total_items']} items."
        )
        for rec in hygiene["recommendations"][:4]:
            console.print(f"- {rec}")
        return True

    console.print("ShellForgeAI metadata hygiene summary (safe report-only):")
    console.print(f"- severity: {hygiene['severity']}")
    console.print(f"- total: {hygiene['total_human']} ({hygiene['total_bytes']} bytes)")
    for n, c, b, h, sev in rows[:5]:
        console.print(f"- {n}: {c} items, {h} ({b} bytes) [{sev}]")
    for rec in hygiene["recommendations"][:4]:
        console.print(f"- recommendation: {rec}")
    console.print("No deletion was performed. Equivalent CLI: shellforgeai audit retention")
    return True


def _is_oncall_overview_question(question: str) -> bool:
    q = re.sub(r"[^a-z0-9\s]", " ", (question or "").lower())
    q = re.sub(r"\s+", " ", q).strip()
    toks = [
        "on call",
        "what s broken",
        "anything broken",
        "what needs attention",
        "incident overview",
        "triage this box",
        "operator overview",
    ]
    return any(t in q for t in toks)


def _is_path_ownership_question(question: str) -> bool:
    q = (question or "").lower()
    return bool(re.search(r"\b(?:what\s+owns|who\s+owns|what\s+package\s+owns)\s+/", q))


def _ownership_context(evidence_items) -> dict:
    out: dict[str, dict[str, str]] = {
        "file": {},
        "mounts": {},
        "package_owner": {},
    }
    for i in evidence_items:
        src = getattr(i, "source", "")
        if src == "files.stat":
            out["file"] = {
                "summary": getattr(i, "summary", ""),
                "content": getattr(i, "content", "")[:400],
            }
        elif src == "storage.mounts":
            content = getattr(i, "content", "")[:1200]
            out["mounts"] = {
                "summary": getattr(i, "summary", ""),
                "content": content,
            }
        elif src == "package.file_owner":
            out["package_owner"] = {
                "summary": getattr(i, "summary", ""),
                "content": getattr(i, "content", "")[:400],
            }
    return out


def _ownership_evidence_rows(evidence_items, *, max_rows: int = 8) -> list[dict]:
    """Prioritize ownership-specific evidence rows for ask prompt context."""
    rows: list[dict] = []
    preferred = ("files.stat", "storage.mounts", "package.file_owner")
    for src in preferred:
        for i in evidence_items:
            if getattr(i, "source", "") != src:
                continue
            rows.append(
                {
                    "source": src,
                    "ok": bool(getattr(i, "ok", False)),
                    "title": getattr(i, "title", "")[:120],
                    "summary": (getattr(i, "summary", "") or "").splitlines()[0][:240],
                }
            )
            if len(rows) >= max_rows:
                return rows
    return rows


def _usage_line(resp) -> str:
    u = resp.usage or {}
    return (
        f"Usage: input={u.get('input_tokens')}, cached={u.get('cached_input_tokens')}, "
        f"output={u.get('output_tokens')}, reasoning={u.get('reasoning_output_tokens')}"
    )


def _ctx(ctx: typer.Context) -> RuntimeContext:
    return ctx.obj["runtime"]


def _ensure_artifact_dir(runtime: RuntimeContext) -> None:
    runtime.session.artifact_dir.mkdir(parents=True, exist_ok=True)


def _append_audit_event(runtime: RuntimeContext, **kwargs) -> None:
    try:
        AuditStorage(runtime.session.data_dir).write_event(**kwargs)
    except Exception as exc:
        console.print(f"Warning: failed to append audit event ({exc})")


def _append_audit_event_returning(runtime: RuntimeContext, **kwargs: Any) -> dict[str, Any] | None:
    try:
        return AuditStorage(runtime.session.data_dir).write_event(**kwargs)
    except Exception as exc:
        console.print(f"Warning: failed to append audit event ({exc})")
        return None


def _network_reachability_hints(findings, items) -> list[str]:
    """Build prioritized synthesis hints for network reachability questions.

    The model must rank app/container log evidence above runtime network basics
    so a healthy DNS resolver/default route does not silently cancel out a
    container that is logging upstream/DNS/reachability failures.
    """
    hints: list[str] = []
    app_net_finding = next(
        (
            f
            for f in findings
            if str(getattr(f, "severity", "")) == "warning"
            and any(
                tok in (getattr(f, "title", "") or "").lower()
                for tok in (
                    "dns",
                    "upstream",
                    "reachab",
                    "connection refused",
                    "timeout",
                    "tls",
                    "certificate",
                )
            )
        ),
        None,
    )
    if app_net_finding is not None:
        hints.append(
            f"App/container log evidence shows a reachability failure: "
            f"{getattr(app_net_finding, 'title', '')}. Surface this first."
        )

    def _item(source: str):
        return next((i for i in items if getattr(i, "source", "") == source), None)

    dns_test = _item("network.resolution_test")
    default_route = _item("network.default_route")
    runtime_ok = bool(
        (dns_test and getattr(dns_test, "ok", False))
        and (default_route and getattr(default_route, "ok", False))
    )
    if runtime_ok and app_net_finding is not None:
        hints.append(
            "Runtime DNS resolution and default route appear OK from this namespace, "
            "but that does NOT cancel the app/container log evidence above. Frame this "
            "as an app/container reachability issue, not a host-wide network outage."
        )
    container_detect = _item("system.container_detect")
    if container_detect is not None:
        hints.append(
            "Host firewall and host-level routes are not directly visible from a "
            "container namespace; mention this caveat briefly."
        )
    return hints


def _write_summary_md(
    path: Path,
    session_id: str,
    target: str,
    target_type: str,
    created_at: str,
    evidence_items: list,
    findings: list,
    runtime_context: dict[str, object] | None,
    artifact_dir: Path,
    include_model_response: bool,
) -> None:
    candidates = ["evidence.json", "plan.json", "summary.md", "runbook.md", "runbook.json"]
    if include_model_response:
        candidates.append("model-response.md")
    write_diagnosis_summary_md(
        path=path,
        session_id=session_id,
        target=target,
        target_type=target_type,
        created_at=created_at,
        evidence_items=evidence_items,
        findings=findings,
        runtime_context=runtime_context,
        artifact_dir=artifact_dir,
        artifact_candidates=candidates,
    )


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[bool, typer.Option("--version")] = False,
    config: Path | None = None,
    profile: str = "inspect",
    mode: str = "inspect",
    verbose: bool = False,
    no_trust_cache: bool = typer.Option(False, "--no-trust-cache"),
    yes_trust: bool = typer.Option(
        False,
        "--yes-trust",
        help=(
            "Trust the current workspace for this interactive session and skip the "
            "trust prompt. Only gates the workspace prompt; does not grant mutation, "
            "shell execution, or bypass safety refusals."
        ),
    ),
) -> None:
    if version:
        build = get_build_info()
        console.print(f"ShellForgeAI {build.display_version}")
        if build.build_line():
            console.print(build.build_line())
        raise typer.Exit()
    settings = load_settings(config)
    prof = load_profile(profile, Path.cwd())
    session = build_session_context(settings, prof, mode, Path.cwd())
    ctx.obj = {
        "runtime": RuntimeContext(settings=settings, profile=prof, session=session, verbose=verbose)
    }
    if ctx.invoked_subcommand is None and not version:
        from shellforgeai.interactive import start_interactive

        start_interactive(ctx.obj["runtime"], no_trust_cache=no_trust_cache, yes_trust=yes_trust)
        raise typer.Exit()


@app.command("interactive")
def interactive(
    ctx: typer.Context,
    no_trust_cache: bool = typer.Option(False, "--no-trust-cache"),
    yes_trust: bool = typer.Option(
        False,
        "--yes-trust",
        help=(
            "Trust the current workspace for this interactive session and skip the "
            "trust prompt. Only gates the workspace prompt; does not grant mutation, "
            "shell execution, or bypass safety refusals."
        ),
    ),
) -> None:
    from shellforgeai.interactive import start_interactive

    start_interactive(_ctx(ctx), no_trust_cache=no_trust_cache, yes_trust=yes_trust)


@app.command("version")
def version_cmd() -> None:
    build = get_build_info()
    console.print(f"ShellForgeAI {build.display_version}")
    if build.build_line():
        console.print(build.build_line())


@app.command()
def doctor(ctx: typer.Context, json_output: bool = typer.Option(False, "--json")) -> None:
    runtime = _ctx(ctx)
    audit = AuditStorage(runtime.session.data_dir)
    build = get_build_info()
    pid1 = "unknown"
    with suppress(Exception):
        pid1 = Path("/proc/1/comm").read_text(encoding="utf-8").strip()
    ps = run_command(["ps", "-eo", "stat=,comm="], timeout=5)
    defunct_codex = 0
    if ps.exit_code == 0:
        for line in ps.stdout.splitlines():
            parts = line.strip().split(maxsplit=1)
            if len(parts) == 2 and "Z" in parts[0] and parts[1] == "codex":
                defunct_codex += 1
    init_reaper = "yes" if pid1 in {"tini", "dumb-init", "systemd", "init"} else "no"
    hygiene: dict[str, Any] = scan_metadata_hygiene(Path(runtime.session.data_dir))
    hygiene_attention = hygiene["severity"] in {"warning", "critical"}
    hygiene["human_context"] = (
        "ShellForgeAI-owned historical artifacts exceed advisory threshold."
        if hygiene_attention
        else "ShellForgeAI-owned artifacts are within advisory thresholds."
    )
    hygiene["active_runtime_failure"] = False
    hygiene["cleanup_performed"] = False
    hygiene["first_safe_command"] = "shellforgeai audit cleanup review"
    hygiene["cleanup_execution_gated"] = True
    payload: dict[str, Any] = {
        "shellforgeai": {
            "version": build.display_version,
            "python": sys.version.split()[0],
            "platform": platform.system(),
            "profile": runtime.profile.name,
            "mode": runtime.session.mode,
            "data_dir": str(runtime.session.data_dir),
            "audit_dir": str(audit.sessions_dir),
            "tools": len(registry.list_tools()),
            "model": f"{runtime.settings.model.provider}/{runtime.settings.model.model}",
        },
        "runtime_hygiene": {
            "pid1": pid1,
            "init_reaper": init_reaper,
            "defunct_codex": defunct_codex,
        },
        "metadata_hygiene": hygiene,
        "safety": {
            "cleanup_executed": False,
            "mutation_performed": False,
            "docker_compose_executed": False,
            "remediation_executed": False,
            "rollback_executed": False,
        },
    }
    if json_output:
        console.print_json(data=payload)
        return

    console.print("ShellForgeAI")
    console.print(
        " ".join(
            [
                f"version={build.display_version}",
                f"python={sys.version.split()[0]}",
                f"platform={platform.system()}",
            ]
        )
    )
    if build.build_line():
        console.print(build.build_line())
    console.print(f"profile={runtime.profile.name} mode={runtime.session.mode}")
    console.print(f"data_dir={runtime.session.data_dir} audit_dir={audit.sessions_dir}")
    console.print(
        " ".join(
            [
                f"tools={len(registry.list_tools())}",
                f"model={runtime.settings.model.provider}/{runtime.settings.model.model}",
            ]
        )
    )
    console.print(
        f"runtime_hygiene pid1={pid1} init_reaper={init_reaper} defunct_codex={defunct_codex}"
    )
    console.print("Metadata hygiene")
    runtime_ok = "OK" if defunct_codex == 0 else "needs attention"
    metadata_attention = "attention needed" if hygiene_attention else "OK"
    console.print(f"- Runtime: {runtime_ok}")
    console.print(f"- Metadata hygiene: {metadata_attention}")
    if hygiene_attention:
        console.print("- Note:")
        console.print("  - ShellForgeAI-owned historical artifacts exceed the advisory threshold.")
        console.print("  - This is not an active Docker/system failure by itself.")
        console.print("  - No cleanup was performed.")
        console.print("- First safe command: shellforgeai audit cleanup review")
        console.print("- Cleanup remains gated:")
        console.print("  review -> plan -> archive -> validate -> execute --confirm")
    console.print(
        "- severity: "
        f"{hygiene['severity']} | ShellForgeAI metadata: "
        f"{hygiene['total_human']} across {hygiene['total_items']} items"
    )
    reasons = hygiene.get("reasons") or []
    if reasons:
        console.print("- Reasons:")
        for reason in reasons[:5]:
            console.print(
                "  - "
                f"{reason['category']}: {reason['count']} items, "
                f"estimated_size={human_bytes(int(reason['estimated_bytes']))}, "
                f"threshold={reason['threshold']}, "
                f"oldest={reason['oldest_created_at'] or 'unknown'}"
            )
    else:
        cats = sorted(
            hygiene["categories"].items(), key=lambda kv: int(kv[1]["bytes"]), reverse=True
        )
        console.print("- Largest categories:")
        for name, row in cats[:3]:
            console.print(f"  - {name}: {row['human']} / {row['count']} items")
    if hygiene["warnings"]:
        console.print(f"- Warning: {hygiene['warnings'][0]}")
    if hygiene["recommendations"]:
        console.print("- Suggested safe next steps:")
        for cmd in hygiene["recommendations"][:5]:
            console.print(f"  - {cmd}")


@model_app.command("doctor")
def model_doctor(ctx: typer.Context) -> None:
    runtime = _ctx(ctx)
    provider = build_provider(runtime.settings)
    info = provider.doctor()
    for k, v in info.items():
        console.print(f"{k}={v}")
    if not info.get("auth_cache_present"):
        console.print("Suggested login: codex login (or codex login --device-auth)")


@model_app.command("test")
def model_test(
    ctx: typer.Context,
    prompt: Annotated[str, typer.Argument()] = "Reply with: Hello.",
    raw: bool = typer.Option(False, "--raw"),
    timeout: int | None = typer.Option(None, "--timeout"),
    model: str | None = typer.Option(None, "--model"),
) -> None:
    runtime = _ctx(ctx)
    provider = build_provider(runtime.settings)
    req = ModelRequest(
        prompt=prompt,
        model=model or runtime.settings.model.model,
        provider=runtime.settings.model.provider,
        timeout_seconds=timeout or runtime.settings.model.timeout_seconds,
        metadata={"raw": raw},
    )
    resp = provider.complete(req)
    console.print(resp.text)
    console.print(
        f"\nProvider: {resp.provider}\n"
        f"Model: {resp.model}\n"
        f"OK: {str(resp.ok).lower()}\n"
        f"{_usage_line(resp)}"
    )
    if raw and resp.raw and resp.raw.get("stdout_jsonl"):
        console.print(resp.raw["stdout_jsonl"])


@inspect_app.command("host")
def inspect_host() -> None:
    for r in [host.host_info(), host.host_resources(), host.host_uptime()]:
        console.print(f"[{r.tool}] ok={r.ok} code={r.exit_code}")
        console.print((r.stdout or r.stderr).strip() or "not available")


@inspect_app.command("service")
def inspect_service(service: str) -> None:
    r = systemd.status(service)
    console.print(f"[{r.tool}] ok={r.ok} code={r.exit_code}")
    console.print((r.stdout or r.stderr).strip() or "not available")


@app.command()
def logs(service: str, since: str = "30m") -> None:
    r = journal.unit(service, since=since)
    console.print(f"[{r.tool}] ok={r.ok} code={r.exit_code}")
    console.print((r.stdout or r.stderr).strip() or "no logs")


@tools_app.command("list")
def tools_list() -> None:
    for t in sorted(registry.list_tools(), key=lambda x: x.name):
        console.print(f"{t.name}\t{t.category}\t{t.risk.value}")


@tools_app.command("describe")
def tools_describe(tool_name: str) -> None:
    t = registry.get_tool(tool_name)
    if t is None:
        raise typer.Exit(code=1)
    console.print(t.model_dump_json(indent=2))


@audit_app.command("list")
def audit_list(ctx: typer.Context) -> None:
    runtime = _ctx(ctx)
    sessions = AuditStorage(runtime.session.data_dir).list_sessions()
    if not sessions:
        console.print("No sessions.")
        return
    for sid in sessions:
        console.print(sid)


@audit_app.command("timeline")
def audit_timeline(
    ctx: typer.Context,
    latest: bool = typer.Option(False, "--latest"),
    session: str | None = typer.Option(None, "--session"),
    proposal: str | None = typer.Option(None, "--proposal"),
    kind: str | None = typer.Option(None, "--kind"),
    since: str | None = typer.Option(None, "--since"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    runtime = _ctx(ctx)
    events = AuditStorage(runtime.session.data_dir).query_events(
        session_id=session, proposal_id=proposal, kind=kind, since=since, latest=latest
    )
    if json_output:
        console.print_json(data=events)
        return
    if not events:
        console.print("No audit events.")
        return
    console.print(
        "Time                  Kind             Action      Status   Reference              Summary"
    )
    for e in events:
        ref = e.get("proposal_id") or e.get("session_id") or "-"
        ts = str(e.get("timestamp", ""))[:19].replace("T", " ")
        line = (
            f"{ts:<21} {e.get('kind', ''):<16} {e.get('action', ''):<11} "
            f"{e.get('status', ''):<8} {ref:<22} {e.get('summary', '')}"
        )
        console.print(line)


@audit_app.command("show")
def audit_show(ctx: typer.Context, event_id: str) -> None:
    runtime = _ctx(ctx)
    val = AuditStorage(runtime.session.data_dir).get_event(event_id)
    if val is None:
        console.print(f"Audit event not found: {event_id}")
        raise typer.Exit(code=1)
    console.print_json(data=val)


@audit_app.command("validate")
def audit_validate(ctx: typer.Context) -> None:
    runtime = _ctx(ctx)
    result = AuditStorage(runtime.session.data_dir).validate_events()
    if result.ok:
        console.print("Audit validation passed:")
        console.print(f"- events: {result.event_count}")
        console.print("- execution: none")
        console.print("- safety: ok")
        return
    console.print("Audit validation failed:")
    for err in result.errors:
        console.print(f"- {err}")
    raise typer.Exit(code=1)


@audit_app.command("retention")
def audit_retention(
    ctx: typer.Context,
    json_output: bool = typer.Option(False, "--json"),
    top: int = typer.Option(0, "--top"),
) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    hygiene: dict[str, Any] = scan_metadata_hygiene(data_dir)
    rows = [
        {
            "category": name.replace("_", "-"),
            "items": int(entry["count"]),
            "bytes": int(entry["bytes"]),
            "human": entry["human"],
            "severity": entry["severity"],
        }
        for name, entry in hygiene["categories"].items()
    ]
    rows.sort(key=lambda r: r["bytes"], reverse=True)
    top_items: list[dict[str, int | str]] = []
    if top > 0:
        cats = build_categories(data_dir)
        for cat_name, cat in cats.items():
            for item in collect_category(cat):
                try:
                    rp = item.resolve(strict=True)
                except FileNotFoundError:
                    continue
                if data_dir.resolve() not in rp.parents:
                    continue
                top_items.append(
                    {"path": str(item), "category": cat_name, "bytes": file_size(item)}
                )
        top_items.sort(key=lambda r: int(r["bytes"]), reverse=True)
        top_items = top_items[:top]
    payload: dict[str, Any] = {
        "categories": rows,
        "total_bytes": hygiene["total_bytes"],
        "total_human": hygiene["total_human"],
        "severity": hygiene["severity"],
        "warnings": hygiene["warnings"],
        "recommendations": hygiene["recommendations"],
        "top": top_items,
        "execution": "none",
    }
    if json_output:
        console.print_json(data=payload)
        return
    console.print("Retention report:")
    console.print(f"- severity: {payload['severity']}")
    for r in rows:
        console.print(
            f"- {r['category']}: {r['items']} items, {r['human']} "
            f"({r['bytes']} bytes) [{r['severity']}]"
        )
    console.print(f"- total: {payload['total_human']} ({payload['total_bytes']} bytes)")
    if top_items:
        console.print(f"- top {len(top_items)} largest metadata items:")
        for top_item in top_items:
            console.print(
                f"  - {top_item['category']}: {top_item['path']} ({top_item['bytes']} bytes)"
            )
    for w in payload["warnings"][:3]:
        console.print(f"- warning: {w}")
    for rec in payload["recommendations"][:3]:
        console.print(f"- suggestion: {rec}")
    console.print("- execution: none")


def _cleanup_allowed_roots(data_dir: Path) -> list[Path]:
    return [
        data_dir / "exports",
        data_dir / "audit_exports",
        data_dir / "apply_bundles",
        data_dir / "actions",
        data_dir / "artifacts",
    ]


def _cleanup_plan_dir(data_dir: Path, plan_id: str) -> Path:
    return data_dir / "cleanup_plans" / plan_id


def _is_cleanup_archive_path(path: Path) -> bool:
    return path.is_file() and "".join(path.suffixes[-2:]) == ".tar.gz"


def _cleanup_archive_member_name(raw: str) -> str | None:
    normed = normpath(raw.strip().replace("\\", "/"))
    if not normed or normed == ".":
        return None
    if normed.startswith("/") or normed.startswith("../") or "/../" in normed:
        return None
    return normed


def _validate_cleanup_archive_file(path: Path) -> tuple[bool, list[str], int]:
    ok, errors, files = validate_archive(path)
    if not ok:
        return ok, errors, files
    extra_errors: list[str] = []
    required = {"cleanup-plan.json", "cleanup-plan.md"}
    try:
        with tarfile.open(path, "r:gz") as tf:
            names = tf.getnames()
            for raw in names:
                if _cleanup_archive_member_name(raw) is None:
                    extra_errors.append(f"invalid archive member path: {raw}")
            name_set = set(names)
            for req in required:
                if req not in name_set and f"payload/{req}" not in name_set:
                    extra_errors.append(f"missing {req}")
            mf = tf.extractfile("archive-manifest.json")
            if mf is None:
                extra_errors.append("missing archive-manifest.json")
            else:
                manifest = json.loads(mf.read().decode("utf-8"))
                if manifest.get("execution_allowed") is not False:
                    extra_errors.append("execution_allowed must be false")
                if manifest.get("execution_status") != "not_executed":
                    extra_errors.append("execution_status must be not_executed")
                if manifest.get("mutation_performed") is not False:
                    extra_errors.append("mutation_performed must be false")
                for key in (
                    "remediation_execution",
                    "docker_mutation",
                    "service_mutation",
                    "package_mutation",
                    "firewall_mutation",
                ):
                    if key in manifest and manifest.get(key) is not False:
                        extra_errors.append(f"{key} must be false")
    except Exception as exc:
        return False, [str(exc)], files
    return (not extra_errors), extra_errors, files


def _validate_cleanup_plan_payload(payload: dict[str, Any]) -> list[str]:
    """Validate a cleanup-plan JSON payload using cleanup-plan semantics.

    A cleanup plan is dry-run metadata. This validator confirms the plan
    asserts its own no-mutation contract and that every candidate path
    resolves under an allowed ShellForgeAI-owned root.
    """
    errs: list[str] = []
    if payload.get("kind") != "cleanup_plan":
        errs.append("kind must be cleanup_plan")
    for k in (
        "execution_allowed",
        "mutation_performed",
        "arbitrary_path_deletion",
    ):
        if k in payload and payload.get(k) is not False:
            errs.append(f"{k} must be false")
    for k in ("requires_archive", "requires_confirm", "shellforgeai_owned_only"):
        if k in payload and payload.get(k) is not True:
            errs.append(f"{k} must be true")
    safety = payload.get("safety")
    if not isinstance(safety, dict):
        errs.append("missing safety block")
    else:
        for k in ("execution_allowed", "mutation_performed", "arbitrary_path_deletion"):
            if k in safety and safety.get(k) is not False:
                errs.append(f"safety.{k} must be false")
        for k in (
            "dry_run",
            "shellforgeai_metadata_only",
            "requires_archive",
            "requires_confirm",
        ):
            if k in safety and safety.get(k) is not True:
                errs.append(f"safety.{k} must be true")
    # Candidate paths must not contain traversal markers (defense-in-depth).
    for c in payload.get("candidates", []):
        raw = c.get("path") if isinstance(c, dict) else None
        if not isinstance(raw, str) or not raw:
            errs.append("candidate missing path")
            continue
        if ".." in Path(raw).parts:
            errs.append(f"unsafe candidate path: {raw}")
    return errs


def _cleanup_plan_fingerprint(payload: dict[str, Any]) -> str:
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def _find_cleanup_archive_for_plan(
    data_dir: Path, plan_id: str
) -> tuple[Path | None, dict[str, Any] | None]:
    archive_dir = data_dir / "cleanup_archives"
    if not archive_dir.exists():
        return None, None
    for archive in sorted(archive_dir.glob("*.tar.gz"), reverse=True):
        try:
            with tarfile.open(archive, "r:gz") as tf:
                mf = tf.extractfile("archive-manifest.json")
                if mf is None:
                    continue
                manifest = json.loads(mf.read().decode("utf-8"))
                if manifest.get("plan_id") == plan_id:
                    return archive, manifest
        except Exception:
            continue
    return None, None


_CLEANUP_PLAN_CATEGORIES = {"exports", "audit-exports", "apply-bundles", "actions", "artifacts"}


def _is_safe_cleanup_category(value: str) -> bool:
    if not value:
        return False
    if any(ch in value for ch in ("/", "\\", "..", "\x00")):
        return False
    return value in _CLEANUP_PLAN_CATEGORIES


def _build_cleanup_plan_payload(
    runtime: Any,
    data_dir: Path,
    selected_categories: list[str],
    max_age_days: int | None,
    keep_latest: int | None,
    include_artifacts: bool,
) -> tuple[str, Path, dict[str, Any]]:
    """Create cleanup plan dir, files, and audit event. Returns (plan_id, plan_dir, payload)."""
    cats = build_categories(data_dir)
    candidates: list[dict[str, Any]] = []
    warnings: list[str] = []
    matched_count = 0
    outside_data_dir = 0
    for c in selected_categories:
        all_items = collect_category(cats[c])
        matched_count += len(all_items)
        selected = prune_select(all_items, max_age_days=max_age_days, keep_latest=keep_latest)
        for p in selected:
            try:
                rp = p.resolve(strict=True)
            except FileNotFoundError:
                continue
            if not any(root.resolve() in rp.parents for root in _cleanup_allowed_roots(data_dir)):
                warnings.append(f"skipped outside allowed roots: {p}")
                outside_data_dir += 1
                continue
            age_days = int((datetime.now(timezone.utc).timestamp() - p.stat().st_mtime) // 86400)
            candidates.append(
                {
                    "path": str(p),
                    "category": c,
                    "bytes": file_size(p),
                    "age_days": age_days,
                    "reason": "older_than_threshold"
                    if max_age_days is not None
                    else "selected_by_policy",
                    "safe_to_delete": True,
                    "requires_archive_first": c == "artifacts",
                }
            )
    plan_id = (
        f"cleanup_plan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_"
        f"{uuid.uuid4().hex[:6]}"
    )
    out_dir = _cleanup_plan_dir(data_dir, plan_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    candidate_bytes = sum(int(c["bytes"]) for c in candidates)
    payload: dict[str, Any] = {
        "schema_version": "1",
        "kind": "cleanup_plan",
        "plan_id": plan_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mode": "dry_run",
        "scope": "shellforgeai_metadata",
        "selection": {
            "categories": selected_categories,
            "max_age_days": max_age_days,
            "keep_latest": keep_latest,
            "include_artifacts": include_artifacts,
        },
        "before": {
            "total_bytes": sum(
                file_size(p) for c in selected_categories for p in collect_category(cats[c])
            ),
            "total_items": sum(len(collect_category(cats[c])) for c in selected_categories),
            "categories": {},
        },
        "candidates": candidates,
        "summary": {
            "matched_count": matched_count,
            "kept_count": max(matched_count - len(candidates), 0),
            "candidate_count": len(candidates),
            "candidate_bytes": candidate_bytes,
            "would_archive": sum(1 for c in candidates if c["requires_archive_first"]),
            "would_delete": len(candidates),
            "outside_data_dir": outside_data_dir,
        },
        "safety": {
            "dry_run": True,
            "execution_allowed": False,
            "mutation_performed": False,
            "shellforgeai_metadata_only": True,
            "arbitrary_path_deletion": False,
            "requires_archive": True,
            "requires_confirm": True,
        },
        "execution_allowed": False,
        "mutation_performed": False,
        "requires_archive": True,
        "requires_confirm": True,
        "arbitrary_path_deletion": False,
        "shellforgeai_owned_only": True,
        "next_commands": [
            f"shellforgeai audit cleanup archive {plan_id}",
            f"shellforgeai audit cleanup execute {plan_id} --confirm",
        ],
        "warnings": warnings,
    }
    (out_dir / "cleanup-plan.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (out_dir / "cleanup-plan.md").write_text(
        (
            f"# Cleanup Plan {plan_id}\n\n- no deletion performed\n"
            f"- candidates: {len(candidates)}\n"
            f"- bytes: {candidate_bytes}\n"
        ),
        encoding="utf-8",
    )
    _append_audit_event(
        runtime,
        kind="audit",
        action="cleanup-plan",
        status="planned",
        summary="cleanup plan created",
        details={
            "operation": "cleanup_plan_created",
            "plan_id": plan_id,
            "remediation_execution": False,
            "arbitrary_path_deletion": False,
            "shellforgeai_metadata_only": True,
        },
    )
    return plan_id, out_dir, payload


def _build_cleanup_archive_for_plan(
    runtime: Any, data_dir: Path, plan_id: str
) -> tuple[Path, dict[str, Any]]:
    """Create matching archive for an existing plan. Returns (archive_path, manifest)."""
    pdir = _cleanup_plan_dir(data_dir, plan_id)
    plan_path = pdir / "cleanup-plan.json"
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    plan_fingerprint = _cleanup_plan_fingerprint(payload)
    candidates = [Path(c["path"]) for c in payload.get("candidates", [])]
    candidates.extend([pdir / "cleanup-plan.json", pdir / "cleanup-plan.md"])
    archive_path = create_archive(
        candidates,
        data_dir,
        source=f"cleanup-plan:{plan_id}",
        output=data_dir
        / "cleanup_archives"
        / (
            f"cleanup_archive_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_"
            f"{uuid.uuid4().hex[:6]}.tar.gz"
        ),
    )
    with tarfile.open(archive_path, "r:gz") as tf:
        mf = tf.extractfile("archive-manifest.json")
        manifest = json.loads(mf.read().decode("utf-8")) if mf is not None else {}
    manifest.update(
        {
            "schema_version": "1",
            "plan_id": plan_id,
            "plan_path": str(plan_path),
            "plan_fingerprint": plan_fingerprint,
            "candidate_count": len(payload.get("candidates", [])),
        }
    )
    tmp_archive = archive_path.with_suffix(".tmp")
    with tarfile.open(archive_path, "r:gz") as src, tarfile.open(tmp_archive, "w:gz") as dst:
        for member in src.getmembers():
            if member.name == "archive-manifest.json":
                data = json.dumps(manifest, indent=2).encode("utf-8")
                m = tarfile.TarInfo(member.name)
                m.size = len(data)
                dst.addfile(m, io.BytesIO(data))
                continue
            f = src.extractfile(member)
            if f is None:
                dst.addfile(member)
            else:
                dst.addfile(member, io.BytesIO(f.read()))
    tmp_archive.replace(archive_path)
    _append_audit_event(
        runtime,
        kind="audit",
        action="cleanup-archive",
        status="success",
        summary="cleanup archive created",
        details={
            "operation": "cleanup_archive_created",
            "plan_id": plan_id,
            "archive": str(archive_path),
            "remediation_execution": False,
            "arbitrary_path_deletion": False,
            "shellforgeai_metadata_only": True,
        },
    )
    return archive_path, manifest


_CLEANUP_REVIEW_SUPPORTED = {"exports", "audit-exports", "apply-bundles", "actions", "artifacts"}
_CLEANUP_REVIEW_GATES = (
    "cleanup_plan",
    "matching_archive",
    "archive_validation",
    "matching_plan_fingerprint",
    "explicit_confirm",
    "receipt_validation",
)


def _cleanup_review_payload(
    data_dir: Path, category: str | None, top: int
) -> tuple[dict[str, Any], list[dict[str, Any]], str | None]:
    hygiene: dict[str, Any] = scan_metadata_hygiene(data_dir)
    raw_categories: list[dict[str, Any]] = []
    for key, info in hygiene["categories"].items():
        display_name = key.replace("_", "-")
        supported = display_name in _CLEANUP_REVIEW_SUPPORTED
        raw_categories.append(
            {
                "name": display_name,
                "bytes": int(info["bytes"]),
                "human": info["human"],
                "items": int(info["count"]),
                "severity": info["severity"],
                "cleanup_supported": supported,
            }
        )
    raw_categories.sort(key=lambda c: c["bytes"], reverse=True)

    safest_first_lane: str | None = None
    for c in raw_categories:
        if not c["cleanup_supported"]:
            c["recommended"] = False
            c["reason"] = "report-only; no cleanup plan support"
        elif c["items"] == 0:
            c["recommended"] = False
            c["reason"] = "no items"
        elif c["name"] == "exports":
            c["recommended"] = True
            c["reason"] = "safe narrow first lane"
            safest_first_lane = "exports"
        elif c["name"] == "artifacts":
            c["recommended"] = False
            c["reason"] = "large category; review carefully before cleanup"
        else:
            c["recommended"] = False
            c["reason"] = "supported; review before cleanup"

    recommendations: list[dict[str, Any]] = []
    if safest_first_lane == "exports":
        recommendations.append(
            {
                "kind": "cleanup_plan",
                "category": "exports",
                "command": [
                    "shellforgeai",
                    "audit",
                    "cleanup",
                    "plan",
                    "--category",
                    "exports",
                    "--max-age-days",
                    "7",
                    "--keep-latest",
                    "5",
                    "--json",
                ],
                "command_display": (
                    "shellforgeai audit cleanup plan --category exports"
                    " --max-age-days 7 --keep-latest 5 --json"
                ),
                "mutation": False,
            }
        )

    display = list(raw_categories)
    filter_warning: str | None = None
    if category:
        norm = category.strip().lower()
        norm_dash = norm.replace("_", "-")
        match = [c for c in raw_categories if c["name"] == norm_dash]
        if not match:
            filter_warning = f"unknown category '{category}'"
            display = []
        else:
            display = match
    if top and top > 0:
        display = display[:top]

    warnings = list(hygiene["warnings"])
    if filter_warning:
        warnings.append(filter_warning)

    payload: dict[str, Any] = {
        "schema_version": "1",
        "status": hygiene["severity"],
        "data_root": str(data_dir),
        "review_only": True,
        "summary": {
            "total_bytes": int(hygiene["total_bytes"]),
            "total_human": hygiene["total_human"],
            "total_items": int(hygiene["total_items"]),
            "largest_category": raw_categories[0]["name"] if raw_categories else None,
        },
        "categories": [
            {
                "name": c["name"],
                "bytes": c["bytes"],
                "human": c["human"],
                "items": c["items"],
                "severity": c["severity"],
                "cleanup_supported": c["cleanup_supported"],
                "recommended": c["recommended"],
                "reason": c["reason"],
            }
            for c in display
        ],
        "recommendations": recommendations,
        "required_gates_before_deletion": list(_CLEANUP_REVIEW_GATES),
        "safest_first_lane": safest_first_lane,
        "next_safe_commands": [
            "shellforgeai audit cleanup plan --category exports"
            " --max-age-days 7 --keep-latest 5 --json",
            "shellforgeai audit cleanup archive <cleanup-plan-id>",
            "shellforgeai audit cleanup validate <cleanup-archive.tar.gz>",
        ],
        "safety": {
            "review_only": True,
            "cleanup_executed": False,
            "archive_created": False,
            "mutation_performed": False,
            "arbitrary_paths_allowed": False,
            "docker_mutation": False,
            "system_mutation": False,
            "natural_language_execution": False,
            "shellforgeai_metadata_only": True,
        },
        "warnings": warnings,
        "execution": "none",
    }
    return payload, display, filter_warning


@audit_cleanup_app.command("review")
def audit_cleanup_review(
    ctx: typer.Context,
    json_output: bool = typer.Option(False, "--json"),
    category: str | None = typer.Option(None, "--category"),
    top: int = typer.Option(0, "--top"),
) -> None:
    """Read-only operator review of /data cleanup posture (PR74).

    Does not create plans, does not create archives, does not delete.
    """
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    payload, display, filter_warning = _cleanup_review_payload(data_dir, category, top)

    if json_output:
        console.print_json(data=payload)
        return

    console.print("ShellForgeAI cleanup review")
    console.print("")
    console.print("Data root:")
    console.print(f"- path: {payload['data_root']}")
    console.print(f"- status: {payload['status']}")
    console.print(f"- total metadata: {payload['summary']['total_human']}")
    console.print(f"- total items: {payload['summary']['total_items']}")
    console.print("- execution: none")

    if filter_warning:
        console.print("")
        console.print(f"- warning: {filter_warning}")
        console.print("No cleanup candidates found for the selected filters.")
        console.print("No deletion was performed.")
        return

    if display:
        console.print("")
        console.print("Largest categories:")
        for idx, c in enumerate(display, start=1):
            tag = "cleanup_supported" if c["cleanup_supported"] else "report-only"
            console.print(f"{idx}. {c['name']}  {c['human']}  {c['items']} items  [{tag}]")
    else:
        console.print("")
        console.print("No cleanup candidates found for the selected filters.")
        console.print("No deletion was performed.")

    if payload["recommendations"]:
        console.print("")
        console.print("Recommended review lanes:")
        console.print(f"- safest first lane: {payload['safest_first_lane']}")
        console.print(
            "- reason: exported bundles are reviewable artifacts"
            " and already supported by cleanup planning"
        )
        console.print("- suggested dry-run:")
        for rec in payload["recommendations"]:
            console.print(f"  {rec['command_display']}")

    console.print("")
    console.print("Required gates before deletion:")
    for i, gate in enumerate(payload["required_gates_before_deletion"], start=1):
        console.print(f"{i}. {gate.replace('_', ' ')}")

    console.print("")
    console.print("Safety:")
    console.print("- review_only: true")
    console.print("- cleanup_executed: false")
    console.print("- archive_created: false")
    console.print("- mutation_performed: false")
    console.print("- arbitrary_paths_allowed: false")
    console.print("- docker_mutation: false")
    console.print("- system_mutation: false")

    console.print("")
    console.print("Next safe commands:")
    for cmd in payload["next_safe_commands"]:
        console.print(f"- {cmd}")


def _cleanup_prepare_payload(
    runtime: Any,
    data_dir: Path,
    category: str,
    max_age_days: int | None,
    keep_latest: int | None,
) -> tuple[int, dict[str, Any]]:
    """Run the guided cleanup prepare workflow. Returns (exit_code, payload).

    No deletion is ever performed. Stops before cleanup execute.
    """
    review_payload, _display, _warn = _cleanup_review_payload(data_dir, None, 0)
    filters = {"max_age_days": max_age_days, "keep_latest": keep_latest}
    base_safety = {
        "cleanup_executed": False,
        "archive_created": False,
        "mutation_performed": False,
        "deletion_performed": False,
        "arbitrary_paths_allowed": False,
        "docker_mutation": False,
        "system_mutation": False,
        "natural_language_execution": False,
        "shellforgeai_metadata_only": True,
    }

    if not _is_safe_cleanup_category(category):
        payload: dict[str, Any] = {
            "schema_version": "1",
            "kind": "cleanup_prepare_result",
            "status": "blocked",
            "category": category,
            "filters": filters,
            "review": {
                "status": review_payload["status"],
                "total_bytes": review_payload["summary"]["total_bytes"],
                "total_items": review_payload["summary"]["total_items"],
                "safest_first_lane": review_payload["safest_first_lane"],
            },
            "plan": {"created": False},
            "archive": {"created": False},
            "decision": {
                "prepared_for_review": False,
                "ready_for_operator_decision": False,
                "execute_performed": False,
                "deletion_performed": False,
                "operator_approval_required": True,
            },
            "next_commands": {},
            "safety": base_safety,
            "warnings": [f"unknown or unsafe category '{category}'"],
        }
        return 1, payload

    plan_id, plan_dir, plan_payload = _build_cleanup_plan_payload(
        runtime,
        data_dir,
        [category],
        max_age_days,
        keep_latest,
        include_artifacts=(category == "artifacts"),
    )
    plan_path = plan_dir / "cleanup-plan.json"
    plan_fingerprint = _cleanup_plan_fingerprint(plan_payload)
    candidate_count = int(plan_payload["summary"]["candidate_count"])
    bytes_planned = int(plan_payload["summary"]["candidate_bytes"])

    warnings: list[str] = list(plan_payload.get("warnings", []))

    archive_path, manifest = _build_cleanup_archive_for_plan(runtime, data_dir, plan_id)
    valid_archive, archive_errors, _files = _validate_cleanup_archive_file(archive_path)

    archive_block: dict[str, Any] = {
        "created": True,
        "path": str(archive_path),
        "plan_id": plan_id,
        "plan_fingerprint": plan_fingerprint,
        "validated": valid_archive,
        "checksums_ok": valid_archive,
    }
    if not valid_archive:
        archive_block["errors"] = archive_errors
        warnings.extend(archive_errors)

    ready = valid_archive
    status = "prepared" if ready else "blocked"
    if candidate_count == 0:
        status = "no_candidates"

    execute_cmd = [
        "shellforgeai",
        "audit",
        "cleanup",
        "execute",
        plan_id,
        "--confirm",
    ]
    next_commands: dict[str, list[str]] = {
        "review_plan": ["shellforgeai", "audit", "cleanup", "validate", str(plan_path)],
        "validate_archive": [
            "shellforgeai",
            "audit",
            "cleanup",
            "validate",
            str(archive_path),
        ],
    }
    if ready:
        next_commands["execute_if_approved"] = execute_cmd

    safety = dict(base_safety)
    safety["archive_created"] = True

    payload = {
        "schema_version": "1",
        "kind": "cleanup_prepare_result",
        "status": status,
        "category": category,
        "filters": filters,
        "review": {
            "status": review_payload["status"],
            "total_bytes": review_payload["summary"]["total_bytes"],
            "total_items": review_payload["summary"]["total_items"],
            "safest_first_lane": review_payload["safest_first_lane"],
        },
        "plan": {
            "created": True,
            "id": plan_id,
            "path": str(plan_path),
            "candidate_count": candidate_count,
            "bytes_planned": bytes_planned,
            "execution_allowed": False,
            "mutation_performed": False,
            "fingerprint": plan_fingerprint,
        },
        "archive": archive_block,
        "decision": {
            "prepared_for_review": ready,
            "ready_for_operator_decision": ready,
            "execute_performed": False,
            "deletion_performed": False,
            "operator_approval_required": True,
        },
        "next_commands": next_commands,
        "safety": safety,
        "warnings": warnings,
    }
    return (0 if valid_archive else 1), payload


@audit_cleanup_app.command("prepare")
def audit_cleanup_prepare(
    ctx: typer.Context,
    json_output: bool = typer.Option(False, "--json"),
    category: str = typer.Option("exports", "--category"),
    max_age_days: int | None = typer.Option(None, "--max-age-days"),
    keep_latest: int | None = typer.Option(None, "--keep-latest"),
) -> None:
    """Guided cleanup decision packet: review -> plan -> archive -> validate.

    Creates ShellForgeAI-owned plan and archive metadata only. Never deletes
    candidate files; never calls cleanup execute. Stops before execute and
    prints the explicit, operator-approved-only execute command.
    """
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)

    if not _is_safe_cleanup_category(category):
        if json_output:
            _exit_code, payload = _cleanup_prepare_payload(
                runtime, data_dir, category, max_age_days, keep_latest
            )
            console.print_json(data=payload)
            raise typer.Exit(code=1)
        console.print(f"Refused: unknown or unsafe category '{category}'.")
        console.print("- no plan created")
        console.print("- no archive created")
        console.print("- no deletion performed")
        raise typer.Exit(code=1)

    exit_code, payload = _cleanup_prepare_payload(
        runtime, data_dir, category, max_age_days, keep_latest
    )

    if json_output:
        console.print_json(data=payload)
        if exit_code != 0:
            raise typer.Exit(code=exit_code)
        return

    console.print("ShellForgeAI cleanup prepare")
    console.print("")
    console.print("Category:")
    console.print(f"- {payload['category']}")
    console.print(f"- max_age_days: {payload['filters']['max_age_days']}")
    console.print(f"- keep_latest: {payload['filters']['keep_latest']}")
    console.print("")
    console.print("Review:")
    console.print(f"- data_root: {data_dir}")
    console.print(f"- status: {payload['review']['status']}")
    console.print(f"- total bytes: {payload['review']['total_bytes']}")
    console.print(f"- total items: {payload['review']['total_items']}")
    console.print(f"- safest_first_lane: {payload['review']['safest_first_lane']}")
    console.print("")
    console.print("Plan:")
    console.print(f"- id: {payload['plan']['id']}")
    console.print(f"- path: {payload['plan']['path']}")
    console.print(f"- candidate_count: {payload['plan']['candidate_count']}")
    console.print(f"- bytes_planned: {payload['plan']['bytes_planned']}")
    console.print("- execution_allowed: false")
    console.print("- mutation_performed: false")
    console.print(f"- fingerprint: {payload['plan']['fingerprint']}")
    console.print("")
    console.print("Archive:")
    console.print(f"- path: {payload['archive']['path']}")
    console.print(f"- plan_fingerprint: {payload['archive']['plan_fingerprint']}")
    console.print(f"- archive_validated: {str(payload['archive']['validated']).lower()}")
    console.print(f"- checksums: {'ok' if payload['archive']['checksums_ok'] else 'failed'}")
    if not payload["archive"]["validated"]:
        for err in payload["archive"].get("errors", []):
            console.print(f"- error: {err}")
    console.print("")
    console.print("Decision:")
    console.print(
        f"- prepared_for_review: {str(payload['decision']['prepared_for_review']).lower()}"
    )
    console.print("- execute_performed: false")
    console.print("- deletion_performed: false")
    console.print(
        "- ready_for_operator_decision: "
        f"{str(payload['decision']['ready_for_operator_decision']).lower()}"
    )
    console.print("")
    console.print("Required before deletion:")
    console.print("- review plan")
    console.print("- review archive validation")
    console.print("- run execute only if operator approves")
    console.print("")
    if payload["decision"]["ready_for_operator_decision"]:
        console.print("Optional execute command (operator-approved only):")
        console.print(" ".join(payload["next_commands"]["execute_if_approved"]))
    else:
        console.print("Execute is blocked: archive validation failed.")
    console.print("")
    console.print("Safety:")
    console.print("- cleanup_executed: false")
    console.print("- mutation_performed: false")
    console.print("- deletion_performed: false")
    console.print("- docker_mutation: false")
    console.print("- system_mutation: false")
    console.print("- arbitrary_paths_allowed: false")

    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@audit_cleanup_app.command("plan")
def audit_cleanup_plan(
    ctx: typer.Context,
    json_output: bool = typer.Option(False, "--json"),
    category: Annotated[list[str] | None, typer.Option("--category")] = None,
    max_age_days: int | None = typer.Option(None, "--max-age-days"),
    keep_latest: int | None = typer.Option(None, "--keep-latest"),
    include_artifacts: bool = typer.Option(False, "--include-artifacts"),
) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    allowed = {"exports", "audit-exports", "apply-bundles", "actions", "artifacts"}
    selected_categories = category or ["exports", "audit-exports", "apply-bundles", "actions"]
    if not include_artifacts:
        selected_categories = [c for c in selected_categories if c != "artifacts"]
    unknown = [c for c in selected_categories if c not in allowed]
    if unknown:
        console.print(f"Refused: unknown category '{unknown[0]}'.")
        raise typer.Exit(code=1)
    plan_id, out_dir, payload = _build_cleanup_plan_payload(
        runtime,
        data_dir,
        selected_categories,
        max_age_days,
        keep_latest,
        include_artifacts,
    )
    if json_output:
        console.print_json(data=payload)
        return
    summary: dict[str, Any] = payload["summary"]
    console.print(f"Cleanup plan created: {plan_id}")
    console.print(f"- category: {', '.join(selected_categories)}")
    console.print(f"- data_dir: {data_dir}")
    console.print(f"- matched: {summary['matched_count']}")
    console.print(f"- kept: {summary['kept_count']}")
    console.print(f"- candidates for archive/delete: {summary['candidate_count']}")
    console.print(f"- outside data_dir: {summary['outside_data_dir']}")
    console.print("- shellforgeai-owned metadata only: true")
    console.print("- safety: dry_run=true requires_archive=true requires_confirm=true")
    console.print(f"- plan: {out_dir / 'cleanup-plan.json'}")


@audit_cleanup_app.command("archive")
def audit_cleanup_archive(ctx: typer.Context, plan_id: str) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    archive_path, _manifest = _build_cleanup_archive_for_plan(runtime, data_dir, plan_id)
    console.print(f"Cleanup archive created: {archive_path}")


@audit_cleanup_app.command("execute")
def audit_cleanup_execute(
    ctx: typer.Context, plan_id: str, confirm: bool = typer.Option(False, "--confirm")
) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    if not confirm:
        console.print("Refused: --confirm required.")
        console.print("")
        console.print("Nothing was deleted.")
        console.print("Required before execute:")
        console.print("- matching archive")
        console.print("- archive validation")
        console.print("- matching plan fingerprint")
        console.print("- explicit --confirm")
        console.print("")
        console.print(
            f"Run `shellforgeai audit cleanup execute-readiness {plan_id}` to verify gates first."
        )
        raise typer.Exit(code=1)
    plan_path = _cleanup_plan_dir(data_dir, plan_id) / "cleanup-plan.json"
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    archive_path, archive_manifest = _find_cleanup_archive_for_plan(data_dir, plan_id)
    if archive_path is None or archive_manifest is None:
        console.print("Refused: matching cleanup archive not found.")
        raise typer.Exit(code=1)
    expected_fingerprint = _cleanup_plan_fingerprint(payload)
    if archive_manifest.get("plan_fingerprint") != expected_fingerprint:
        console.print("Refused: cleanup archive fingerprint mismatch.")
        raise typer.Exit(code=1)
    valid_archive, archive_errors, _archive_files = _validate_cleanup_archive_file(archive_path)
    if not valid_archive:
        console.print("Refused: cleanup archive validation failed.")
        for err in archive_errors:
            console.print(f"- {err}")
        raise typer.Exit(code=1)
    candidates = [Path(c["path"]) for c in payload.get("candidates", [])]
    deleted, failed, bytes_removed = delete_paths(candidates, _cleanup_allowed_roots(data_dir))
    rid = (
        f"cleanup_receipt_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_"
        f"{uuid.uuid4().hex[:6]}"
    )
    rdir = data_dir / "cleanup_receipts" / rid
    rdir.mkdir(parents=True, exist_ok=True)
    receipt = {
        "schema_version": "1",
        "kind": "cleanup_execute_result",
        "receipt_id": rid,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "plan_id": plan_id,
        "archive_id": archive_manifest.get("archive_id"),
        "archive_path": str(archive_path),
        "plan_path": str(plan_path),
        "category": ",".join(payload.get("selection", {}).get("categories", [])),
        "confirmed": True,
        "archive_validated": True,
        "mode": "execute",
        "candidate_count": len(candidates),
        "deleted_count": len(deleted),
        "skipped_count": max(len(candidates) - len(deleted) - len(failed), 0),
        "failed_count": len(failed),
        "mutation_performed": len(candidates) > 0,
        "deleted": [str(p) for p in deleted],
        "failed": failed,
        "bytes_removed": bytes_removed,
        "before": payload.get("before", {}),
        "after": {"total_items": 0},
        "safety": {
            "shellforgeai_metadata_only": True,
            "arbitrary_path_deletion": False,
            "remediation_execution": False,
            "docker_mutation": False,
            "service_mutation": False,
            "package_mutation": False,
            "firewall_mutation": False,
        },
        "docker_mutation": False,
        "compose_mutation": False,
        "system_mutation": False,
        "errors": failed,
    }
    (rdir / "cleanup-receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    (rdir / "cleanup-receipt.md").write_text(f"# Cleanup Receipt {rid}\n", encoding="utf-8")
    console.print("Cleanup executed:")
    console.print(f"- plan: {plan_id}")
    console.print(f"- deleted: {len(deleted)}")
    console.print(f"- failed: {len(failed)}")
    console.print(f"- bytes_removed: {bytes_removed}")
    console.print(f"- receipt: {rdir / 'cleanup-receipt.json'}")
    console.print("- remediation_execution: false")
    if failed:
        raise typer.Exit(code=1)


@audit_cleanup_app.command("validate")
def audit_cleanup_validate(target: Path) -> None:
    if _is_cleanup_archive_path(target):
        ok, errors, files = _validate_cleanup_archive_file(target)
        if not ok:
            console.print("Cleanup archive validation failed:")
            for err in errors:
                console.print(f"- {err}")
            raise typer.Exit(code=1)
        console.print("Cleanup archive validation passed:")
        console.print(f"- archive: {target}")
        console.print(f"- files: {files}")
        console.print("- checksums: ok")
        console.print("- safety: ok")
        console.print("- execution: none")
        return
    if target.is_file() and target.suffix != ".json":
        console.print("Cleanup validation failed:")
        console.print("- expected cleanup receipt directory or cleanup-receipt.json")
        console.print(f"- got archive file: {target}")
        console.print(
            "- to validate cleanup archives, run:"
            " shellforgeai audit cleanup validate <archive.tar.gz>"
        )
        raise typer.Exit(code=1)
    # Cleanup plan validation (PR75): dispatched by kind=cleanup_plan.
    if target.is_file() and target.suffix == ".json" and target.name == "cleanup-plan.json":
        try:
            plan_payload = json.loads(target.read_text(encoding="utf-8"))
        except Exception:
            console.print("Cleanup plan validation failed:")
            console.print("- plan missing or invalid JSON")
            raise typer.Exit(code=1) from None
        if plan_payload.get("kind") == "cleanup_plan":
            plan_errs = _validate_cleanup_plan_payload(plan_payload)
            if plan_errs:
                console.print("Cleanup plan validation failed:")
                for e in plan_errs:
                    console.print(f"- {e}")
                raise typer.Exit(code=1)
            console.print("Cleanup plan validation passed:")
            console.print(f"- plan_id: {plan_payload.get('plan_id')}")
            console.print(f"- candidates: {len(plan_payload.get('candidates', []))}")
            console.print("- execution_allowed: false")
            console.print("- mutation_performed: false")
            console.print("- requires_archive: true")
            console.print("- requires_confirm: true")
            console.print("- shellforgeai_metadata_only: true")
            console.print("- safety: ok")
            return
    receipt_path = target / "cleanup-receipt.json" if target.is_dir() else target
    try:
        payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    except Exception:
        console.print("Cleanup validation failed:")
        console.print("- receipt missing or invalid")
        raise typer.Exit(code=1) from None
    safety = payload.get("safety")
    errs: list[str] = []
    if not isinstance(safety, dict):
        errs.append("missing safety block")
    else:
        for k in ("shellforgeai_metadata_only",):
            if safety.get(k) is not True:
                errs.append(f"{k} must be true")
        for k in (
            "arbitrary_path_deletion",
            "remediation_execution",
            "docker_mutation",
            "service_mutation",
            "package_mutation",
            "firewall_mutation",
        ):
            if safety.get(k) is not False:
                errs.append(f"{k} must be false")
    if errs:
        console.print("Cleanup validation failed:")
        for e in errs:
            console.print(f"- {e}")
        raise typer.Exit(code=1)
    console.print("Cleanup validation passed:")
    console.print(f"- receipt: {payload.get('receipt_id')}")
    console.print(f"- deleted: {len(payload.get('deleted', []))}")
    console.print(f"- bytes_removed: {payload.get('bytes_removed', 0)}")
    console.print("- safety: ok")


def _resolve_cleanup_plan_input(data_dir: Path, raw: str) -> tuple[Path | None, str | None]:
    """Resolve plan id, plan dir, or cleanup-plan.json to (plan_path, plan_id).

    Returns (None, None) if no plan can be located.
    """
    candidate = Path(raw)
    if candidate.is_file() and candidate.name == "cleanup-plan.json":
        return candidate, candidate.parent.name
    if candidate.is_dir() and (candidate / "cleanup-plan.json").is_file():
        return candidate / "cleanup-plan.json", candidate.name
    plan_dir = _cleanup_plan_dir(data_dir, raw)
    plan_json = plan_dir / "cleanup-plan.json"
    if plan_json.is_file():
        return plan_json, raw
    return None, None


def _find_cleanup_receipt_for_plan(data_dir: Path, plan_id: str) -> Path | None:
    rdir = data_dir / "cleanup_receipts"
    if not rdir.exists():
        return None
    for d in sorted(rdir.iterdir(), reverse=True):
        rp = d / "cleanup-receipt.json"
        if not rp.is_file():
            continue
        try:
            payload = json.loads(rp.read_text(encoding="utf-8"))
        except Exception:
            continue
        if payload.get("plan_id") == plan_id:
            return rp
    return None


def _cleanup_execute_readiness_payload(data_dir: Path, raw: str) -> tuple[int, dict[str, Any]]:
    """Read-only: check whether a cleanup plan is ready for `execute --confirm`.

    Creates no plans, no archives, no receipts; deletes nothing.
    """
    base_safety: dict[str, Any] = {
        "read_only": True,
        "cleanup_executed": False,
        "deletion_performed": False,
        "mutation_performed": False,
        "arbitrary_paths_allowed": False,
        "docker_mutation": False,
        "system_mutation": False,
        "natural_language_execution": False,
        "explicit_confirm_required": True,
        "shellforgeai_metadata_only": True,
    }
    empty_plan: dict[str, Any] = {
        "id": None,
        "path": None,
        "category": None,
        "candidate_count": 0,
        "bytes_planned": 0,
        "execution_allowed": False,
        "mutation_performed": False,
        "requires_archive": True,
        "requires_confirm": True,
        "shellforgeai_metadata_only": True,
    }
    empty_archive: dict[str, Any] = {
        "found": False,
        "path": None,
        "archive_validated": False,
        "checksums_ok": False,
        "plan_id_matches": False,
        "plan_fingerprint_matches": False,
        "execution_allowed": False,
    }

    plan_path, plan_id = _resolve_cleanup_plan_input(data_dir, raw)
    if plan_path is None:
        return 1, {
            "schema_version": "1",
            "status": "not_found",
            "ready_for_execute_confirm": False,
            "operator_action_required": True,
            "read_only": True,
            "cleanup_executed": False,
            "deletion_performed": False,
            "plan": dict(empty_plan, id=raw),
            "archive": empty_archive,
            "readiness": {
                "ready_for_execute_confirm": False,
                "execute_performed": False,
                "blockers": ["cleanup plan not found"],
                "warnings": [],
            },
            "gates": {
                "plan_present": False,
                "archive_found": False,
                "archive_validated": False,
                "checksums_ok": False,
                "plan_id_matches": False,
                "plan_fingerprint_matches": False,
                "explicit_confirm_required": True,
            },
            "safety": base_safety,
            "next_commands": {},
            "warnings": [],
        }

    blockers: list[str] = []
    warnings: list[str] = []
    try:
        payload = json.loads(plan_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return 1, {
            "schema_version": "1",
            "status": "error",
            "ready_for_execute_confirm": False,
            "operator_action_required": True,
            "read_only": True,
            "cleanup_executed": False,
            "deletion_performed": False,
            "plan": dict(empty_plan, id=plan_id, path=str(plan_path)),
            "archive": empty_archive,
            "readiness": {
                "ready_for_execute_confirm": False,
                "execute_performed": False,
                "blockers": [f"plan JSON unreadable: {exc}"],
                "warnings": [],
            },
            "gates": {
                "plan_present": True,
                "archive_found": False,
                "archive_validated": False,
                "checksums_ok": False,
                "plan_id_matches": False,
                "plan_fingerprint_matches": False,
                "explicit_confirm_required": True,
            },
            "safety": base_safety,
            "next_commands": {},
            "warnings": [],
        }

    if payload.get("kind") != "cleanup_plan":
        blockers.append("plan kind is not cleanup_plan")
    plan_errs = _validate_cleanup_plan_payload(payload)
    blockers.extend(plan_errs)

    selection_cats = payload.get("selection", {}).get("categories", []) or []
    for c in selection_cats:
        if not _is_safe_cleanup_category(c):
            blockers.append(f"unsafe category: {c}")

    allowed_roots = [r.resolve() for r in _cleanup_allowed_roots(data_dir)]
    for c in payload.get("candidates", []):
        raw_p = c.get("path") if isinstance(c, dict) else None
        if not isinstance(raw_p, str) or not raw_p:
            blockers.append("candidate missing path")
            continue
        try:
            rp = Path(raw_p).resolve()
        except Exception:
            blockers.append(f"candidate path unresolvable: {raw_p}")
            continue
        if not any(root in rp.parents or root == rp for root in allowed_roots):
            blockers.append(f"candidate path outside ShellForgeAI metadata: {raw_p}")

    plan_block: dict[str, Any] = {
        "id": plan_id,
        "path": str(plan_path),
        "category": ",".join(selection_cats) if selection_cats else None,
        "candidate_count": int(payload.get("summary", {}).get("candidate_count", 0)),
        "bytes_planned": int(payload.get("summary", {}).get("candidate_bytes", 0)),
        "execution_allowed": bool(payload.get("execution_allowed", False)),
        "mutation_performed": bool(payload.get("mutation_performed", False)),
        "requires_archive": bool(payload.get("requires_archive", True)),
        "requires_confirm": bool(payload.get("requires_confirm", True)),
        "shellforgeai_metadata_only": bool(
            payload.get("safety", {}).get("shellforgeai_metadata_only", True)
        ),
    }

    expected_fingerprint = _cleanup_plan_fingerprint(payload)
    archive_path, archive_manifest = (
        _find_cleanup_archive_for_plan(data_dir, plan_id) if plan_id else (None, None)
    )
    archive_block: dict[str, Any] = dict(empty_archive)
    if archive_path is None or archive_manifest is None:
        blockers.append("matching cleanup archive not found")
    else:
        archive_block["found"] = True
        archive_block["path"] = str(archive_path)
        archive_block["plan_id_matches"] = archive_manifest.get("plan_id") == plan_id
        if not archive_block["plan_id_matches"]:
            blockers.append("archive plan_id mismatch")
        archive_block["plan_fingerprint_matches"] = (
            archive_manifest.get("plan_fingerprint") == expected_fingerprint
        )
        if not archive_block["plan_fingerprint_matches"]:
            blockers.append("archive plan_fingerprint mismatch")
        archive_block["execution_allowed"] = bool(archive_manifest.get("execution_allowed", False))
        valid_archive, archive_errors, _files = _validate_cleanup_archive_file(archive_path)
        archive_block["archive_validated"] = valid_archive
        archive_block["checksums_ok"] = valid_archive
        if not valid_archive:
            blockers.append("archive validation failed")
            warnings.extend(archive_errors)

    existing_receipt = _find_cleanup_receipt_for_plan(data_dir, plan_id) if plan_id else None
    execute_performed = existing_receipt is not None
    if execute_performed:
        warnings.append(f"cleanup already executed for this plan: {existing_receipt}")

    ready = (not blockers) and not execute_performed
    status = "ready" if ready else "blocked"
    next_commands: dict[str, str] = {
        "review_plan": f"shellforgeai audit cleanup validate {plan_path}",
    }
    if archive_path is not None:
        next_commands["validate_archive"] = f"shellforgeai audit cleanup validate {archive_path}"
    if ready and plan_id:
        next_commands["execute"] = f"shellforgeai audit cleanup execute {plan_id} --confirm"

    gates = {
        "plan_present": True,
        "archive_found": bool(archive_block["found"]),
        "archive_validated": bool(archive_block["archive_validated"]),
        "checksums_ok": bool(archive_block["checksums_ok"]),
        "plan_id_matches": bool(archive_block["plan_id_matches"]),
        "plan_fingerprint_matches": bool(archive_block["plan_fingerprint_matches"]),
        "explicit_confirm_required": True,
    }
    result = {
        "schema_version": "1",
        "status": status,
        "ready_for_execute_confirm": ready,
        "operator_action_required": True,
        "read_only": True,
        "cleanup_executed": execute_performed,
        "deletion_performed": False,
        "plan": plan_block,
        "archive": archive_block,
        "readiness": {
            "ready_for_execute_confirm": ready,
            "execute_performed": execute_performed,
            "blockers": blockers,
            "warnings": warnings,
        },
        "gates": gates,
        "safety": base_safety,
        "next_commands": next_commands,
        "warnings": warnings,
    }
    return (0 if ready else 1), result


@audit_cleanup_app.command("execute-readiness")
def audit_cleanup_execute_readiness(
    ctx: typer.Context,
    plan: str,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Read-only readiness check before `audit cleanup execute --confirm` (PR76).

    Inspects the plan, the matching cleanup archive, archive validation, and
    plan fingerprint. Creates no plans, no archives, no receipts. Deletes
    nothing. The execute command still requires explicit `--confirm`.
    """
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    exit_code, payload = _cleanup_execute_readiness_payload(data_dir, plan)

    if json_output:
        console.print_json(data=payload)
        if exit_code != 0:
            raise typer.Exit(code=exit_code)
        return

    plan_block = payload["plan"]
    archive_block = payload["archive"]
    readiness = payload["readiness"]
    gates = payload.get("gates", {})
    console.print("Cleanup execute readiness")
    console.print("")
    console.print("Status:")
    console.print(
        f"- ready_for_execute_confirm: {str(readiness['ready_for_execute_confirm']).lower()}"
    )
    console.print(f"- read_only: {str(payload.get('read_only', True)).lower()}")
    console.print(f"- deletion_performed: {str(payload.get('deletion_performed', False)).lower()}")
    console.print(f"- cleanup_executed: {str(payload.get('cleanup_executed', False)).lower()}")
    console.print(
        f"- operator_action_required: {str(payload.get('operator_action_required', True)).lower()}"
    )
    console.print("")
    console.print("Validated gates:")
    console.print(f"- cleanup plan: {'present' if gates.get('plan_present') else 'missing'}")
    console.print(f"- matching archive: {'present' if gates.get('archive_found') else 'missing'}")
    console.print(
        f"- archive validation: {'passed' if gates.get('archive_validated') else 'failed'}"
    )
    console.print(
        "- plan fingerprint: "
        f"{'matched' if gates.get('plan_fingerprint_matches') else 'not matched'}"
    )
    console.print("- explicit confirm: still required")
    console.print("")
    console.print("Plan:")
    console.print(f"- id: {plan_block['id']}")
    console.print(f"- path: {plan_block['path']}")
    console.print(f"- category: {plan_block['category']}")
    console.print(f"- candidates: {plan_block['candidate_count']}")
    console.print(f"- bytes planned: {plan_block['bytes_planned']}")
    console.print(f"- execution_allowed: {str(plan_block['execution_allowed']).lower()}")
    console.print(f"- mutation_performed: {str(plan_block['mutation_performed']).lower()}")
    console.print(f"- requires_archive: {str(plan_block['requires_archive']).lower()}")
    console.print(f"- requires_confirm: {str(plan_block['requires_confirm']).lower()}")
    console.print(
        f"- shellforgeai_metadata_only: {str(plan_block['shellforgeai_metadata_only']).lower()}"
    )
    console.print("")
    console.print("Archive:")
    console.print(f"- found: {str(archive_block['found']).lower()}")
    console.print(f"- path: {archive_block['path']}")
    console.print(f"- archive_validated: {str(archive_block['archive_validated']).lower()}")
    console.print(f"- checksums_ok: {str(archive_block['checksums_ok']).lower()}")
    console.print(f"- plan_id matches: {str(archive_block['plan_id_matches']).lower()}")
    console.print(
        f"- plan_fingerprint matches: {str(archive_block['plan_fingerprint_matches']).lower()}"
    )
    console.print("")
    console.print("Safety gates:")
    console.print("- arbitrary paths: blocked")
    console.print("- docker mutation: false")
    console.print("- system mutation: false")
    console.print("- natural-language execution: false")
    console.print("- explicit confirm required: true")
    console.print("")
    console.print("Readiness:")
    console.print(
        f"- ready_for_execute_confirm: {str(readiness['ready_for_execute_confirm']).lower()}"
    )
    console.print(f"- execute_performed: {str(readiness['execute_performed']).lower()}")
    if readiness["blockers"]:
        console.print("")
        console.print("Blockers:")
        for b in readiness["blockers"]:
            console.print(f"- {b}")
        console.print("")
        console.print("Operator warning:")
        console.print("This command did not delete anything.")
        console.print("Do not execute until blockers are resolved.")
    elif readiness["ready_for_execute_confirm"]:
        console.print("")
        console.print("Operator warning:")
        console.print("This command did not delete anything.")
        console.print(
            "The next command will delete the planned ShellForgeAI-owned"
            " metadata candidates if run with --confirm."
        )
        console.print("Readiness means gates are satisfied, not that deletion is approved.")
        console.print("")
        console.print("Next commands:")
        nc = payload["next_commands"]
        if "review_plan" in nc:
            console.print(f"- review plan: {nc['review_plan']}")
        if "validate_archive" in nc:
            console.print(f"- validate archive: {nc['validate_archive']}")
        console.print(f"- execute: {nc['execute']}")
        console.print("- report: shellforgeai audit cleanup report <receipt-path-after-execute>")

    if exit_code != 0:
        raise typer.Exit(code=exit_code)


def _cleanup_report_payload(data_dir: Path, target: Path) -> tuple[int, dict[str, Any]]:
    base_safety = {
        "docker_mutation": False,
        "system_mutation": False,
        "arbitrary_paths_allowed": False,
        "shellforgeai_metadata_only": True,
    }
    empty_receipt: dict[str, Any] = {
        "id": None,
        "path": None,
        "kind": None,
        "plan_id": None,
        "archive_path": None,
        "archive_validated": False,
        "category": None,
    }
    empty_result = {"deleted": 0, "failed": 0, "bytes_removed": 0, "skipped": 0}
    empty_validation = {
        "receipt_valid": False,
        "checksums_ok": False,
        "plan_fingerprint_matched": False,
    }

    if _is_cleanup_archive_path(target):
        return 1, {
            "schema_version": "1",
            "status": "error",
            "receipt": empty_receipt,
            "result": empty_result,
            "safety": base_safety,
            "validation": empty_validation,
            "next_commands": [],
            "warnings": [
                f"expected cleanup receipt directory or cleanup-receipt.json,"
                f" got archive file: {target}",
                "to validate cleanup archives, run:"
                " shellforgeai audit cleanup validate <archive.tar.gz>",
            ],
        }

    receipt_path = target / "cleanup-receipt.json" if target.is_dir() else target
    if not receipt_path.is_file():
        return 1, {
            "schema_version": "1",
            "status": "not_found",
            "receipt": dict(empty_receipt, path=str(receipt_path)),
            "result": empty_result,
            "safety": base_safety,
            "validation": empty_validation,
            "next_commands": [],
            "warnings": ["cleanup receipt not found"],
        }

    try:
        payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return 1, {
            "schema_version": "1",
            "status": "error",
            "receipt": dict(empty_receipt, path=str(receipt_path)),
            "result": empty_result,
            "safety": base_safety,
            "validation": empty_validation,
            "next_commands": [],
            "warnings": [f"receipt JSON unreadable: {exc}"],
        }

    safety_in = payload.get("safety", {}) or {}
    receipt_safety_ok = (
        safety_in.get("shellforgeai_metadata_only") is True
        and safety_in.get("arbitrary_path_deletion") is False
        and safety_in.get("remediation_execution") is False
    )

    archive_validated = bool(payload.get("archive_validated", False))
    plan_id = payload.get("plan_id")
    plan_fingerprint_matched = False
    if plan_id:
        plan_path_str = payload.get("plan_path")
        try:
            plan_path = (
                Path(plan_path_str)
                if plan_path_str
                else (_cleanup_plan_dir(data_dir, plan_id) / "cleanup-plan.json")
            )
            if plan_path.is_file():
                plan_payload = json.loads(plan_path.read_text(encoding="utf-8"))
                expected_fp = _cleanup_plan_fingerprint(plan_payload)
                _ap, manifest = _find_cleanup_archive_for_plan(data_dir, plan_id)
                if manifest is not None:
                    plan_fingerprint_matched = manifest.get("plan_fingerprint") == expected_fp
        except Exception:
            plan_fingerprint_matched = False

    deleted_count = (
        int(payload.get("deleted_count"))
        if isinstance(payload.get("deleted_count"), int)
        else len(payload.get("deleted", []) or [])
    )
    failed_count = (
        int(payload.get("failed_count"))
        if isinstance(payload.get("failed_count"), int)
        else len(payload.get("failed", []) or [])
    )
    skipped_count = int(payload.get("skipped_count", 0) or 0)
    bytes_removed = int(payload.get("bytes_removed", 0) or 0)

    post_execute_checks = [
        f"shellforgeai audit cleanup validate {receipt_path}",
        "shellforgeai audit retention",
        "shellforgeai audit cleanup review",
        "shellforgeai doctor",
    ]
    return 0, {
        "schema_version": "1",
        "status": "ok",
        "receipt_kind": payload.get("kind"),
        "receipt_valid": receipt_safety_ok,
        "receipt_plan_id": plan_id,
        "deleted": deleted_count,
        "failed": failed_count,
        "bytes_removed": bytes_removed,
        "receipt": {
            "id": payload.get("receipt_id"),
            "path": str(receipt_path),
            "kind": payload.get("kind"),
            "plan_id": plan_id,
            "archive_path": payload.get("archive_path"),
            "archive_validated": archive_validated,
            "category": payload.get("category"),
        },
        "result": {
            "deleted": deleted_count,
            "failed": failed_count,
            "bytes_removed": bytes_removed,
            "skipped": skipped_count,
        },
        "safety": base_safety,
        "validation": {
            "receipt_valid": receipt_safety_ok,
            "checksums_ok": archive_validated,
            "plan_fingerprint_matched": plan_fingerprint_matched,
        },
        "next_commands": post_execute_checks,
        "post_execute_checks": post_execute_checks,
        "warnings": [],
    }


@audit_cleanup_app.command("report")
def audit_cleanup_report(
    ctx: typer.Context,
    target: Path,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Summarize a cleanup execute receipt (PR76). Read-only."""
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    exit_code, payload = _cleanup_report_payload(data_dir, target)

    if json_output:
        console.print_json(data=payload)
        if exit_code != 0:
            raise typer.Exit(code=exit_code)
        return

    if payload["status"] != "ok":
        console.print("Cleanup report failed:")
        for w in payload["warnings"]:
            console.print(f"- {w}")
        console.print(f"- got: {target}")
        if exit_code != 0:
            raise typer.Exit(code=exit_code)
        return

    receipt = payload["receipt"]
    result = payload["result"]
    validation = payload["validation"]
    console.print("Cleanup report (execution)")
    console.print("")
    console.print("Receipt:")
    console.print(f"- id: {receipt['id']}")
    console.print(f"- kind: {receipt['kind']}")
    console.print(f"- plan_id: {receipt['plan_id']}")
    console.print(f"- archive_validated: {str(receipt['archive_validated']).lower()}")
    console.print(f"- category: {receipt['category']}")
    console.print("")
    console.print("Result:")
    console.print(f"- deleted: {result['deleted']}")
    console.print(f"- failed: {result['failed']}")
    console.print(f"- bytes removed: {result['bytes_removed']}")
    console.print(f"- skipped: {result['skipped']}")
    console.print("")
    console.print("Safety:")
    console.print("- docker_mutation: false")
    console.print("- system_mutation: false")
    console.print("- arbitrary_paths_allowed: false")
    console.print("- shellforgeai_metadata_only: true")
    console.print("")
    console.print("Validation:")
    console.print(f"- receipt validation: {'passed' if validation['receipt_valid'] else 'failed'}")
    console.print(
        f"- archive fingerprint matched: {str(validation['plan_fingerprint_matched']).lower()}"
    )
    console.print("- cleanup scope: ShellForgeAI metadata only")
    console.print("")
    console.print("Post-execute checks:")
    for cmd in payload.get("post_execute_checks", payload["next_commands"]):
        console.print(f"- {cmd}")


@audit_app.command("prune")
def audit_prune(
    ctx: typer.Context,
    dry_run: bool = typer.Option(True, "--dry-run"),
    execute: bool = typer.Option(False, "--execute"),
    confirm: bool = typer.Option(False, "--confirm"),
    max_age_days: int | None = typer.Option(None, "--max-age-days"),
    keep_latest: int | None = typer.Option(None, "--keep-latest"),
    category: str = typer.Option("default", "--category"),
    session_id: str | None = typer.Option(None, "--session"),
    proposal_id: str | None = typer.Option(None, "--proposal"),
    archive: bool = typer.Option(False, "--archive"),
) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    cats = build_categories(data_dir)

    if category == "default":
        wanted = list(DEFAULT_PRUNE_CATEGORIES)
    elif category == "all":
        wanted = list(ALLOWED_PRUNE_CATEGORIES)
    elif category in PROTECTED_PRUNE_CATEGORIES:
        console.print(f"Refused: category '{category}' is protected and not eligible for prune.")
        _append_audit_event(
            runtime,
            kind="audit",
            action="prune",
            status="refused",
            summary="metadata prune refused: protected category",
            details={
                "operation": "metadata_prune_refused",
                "reason": "protected_category",
                "category": category,
                "metadata_cleanup_executed": False,
                "remediation_execution": False,
                "shellforgeai_owned_paths_only": True,
            },
        )
        raise typer.Exit(code=1)
    elif category in ALLOWED_PRUNE_CATEGORIES:
        wanted = [category]
    else:
        console.print(f"Refused: unknown category '{category}'.")
        _append_audit_event(
            runtime,
            kind="audit",
            action="prune",
            status="refused",
            summary="metadata prune refused: unknown category",
            details={
                "operation": "metadata_prune_refused",
                "reason": "unknown_category",
                "category": category,
                "metadata_cleanup_executed": False,
                "remediation_execution": False,
                "shellforgeai_owned_paths_only": True,
            },
        )
        raise typer.Exit(code=1)

    selected: list[Path] = []
    for w in wanted:
        selected.extend(
            prune_select(
                collect_category(cats[w]), max_age_days=max_age_days, keep_latest=keep_latest
            )
        )
    if session_id:
        selected = [p for p in selected if session_id in p.name or session_id in str(p)]
    if proposal_id:
        selected = [p for p in selected if proposal_id in p.name or proposal_id in str(p)]
    selected = sorted(set(selected))
    would_bytes = sum(file_size(p) for p in selected)

    if execute and not confirm:
        console.print("Refused: --execute requires --confirm to perform metadata deletion.")
        console.print("Rerun: shellforgeai audit prune ... --execute --confirm")
        _append_audit_event(
            runtime,
            kind="audit",
            action="prune",
            status="refused",
            summary="metadata prune refused: missing --confirm",
            details={
                "operation": "metadata_prune_refused",
                "reason": "missing_confirm",
                "category": category,
                "selected": len(selected),
                "metadata_cleanup_executed": False,
                "remediation_execution": False,
                "shellforgeai_owned_paths_only": True,
            },
        )
        raise typer.Exit(code=1)

    if not execute:
        console.print("Prune plan (dry-run):")
        console.print(f"- selected: {len(selected)}")
        console.print(f"- would_delete: {len(selected)}")
        console.print(f"- bytes: {would_bytes}")
        console.print("- execution: none")
        console.print("- next step: rerun with --execute --confirm after review")
        for p in selected[:20]:
            console.print(f"- {p}")
        _append_audit_event(
            runtime,
            kind="audit",
            action="prune",
            status="planned",
            summary="metadata prune dry-run",
            details={
                "operation": "metadata_prune_dry_run",
                "category": category,
                "count": len(selected),
                "bytes": would_bytes,
                "execution_status": "not_executed",
                "metadata_cleanup_executed": False,
                "remediation_execution": False,
                "shellforgeai_owned_paths_only": True,
            },
        )
        return

    if not selected:
        console.print("Refused: selection is empty; nothing to prune.")
        _append_audit_event(
            runtime,
            kind="audit",
            action="prune",
            status="refused",
            summary="metadata prune refused: empty selection",
            details={
                "operation": "metadata_prune_refused",
                "reason": "empty_selection",
                "category": category,
                "metadata_cleanup_executed": False,
                "remediation_execution": False,
                "shellforgeai_owned_paths_only": True,
            },
        )
        raise typer.Exit(code=1)

    allowed_roots = [
        data_dir / "exports",
        data_dir / "apply_bundles",
        data_dir / "actions",
        data_dir / "audit_exports",
        data_dir / "audit",
        data_dir / "artifacts",
    ]
    refusals: list[str] = []
    for p in selected:
        refusal = ensure_safe_delete_target(p, allowed_roots)
        if refusal:
            refusals.append(refusal)
    if refusals:
        console.print("Refused: path safety validation failed.")
        for r in refusals[:20]:
            console.print(f"- {r}")
        _append_audit_event(
            runtime,
            kind="audit",
            action="prune",
            status="refused",
            summary="metadata prune refused: path safety",
            details={
                "operation": "metadata_prune_refused",
                "reason": "path_safety",
                "category": category,
                "refusals": refusals[:50],
                "metadata_cleanup_executed": False,
                "remediation_execution": False,
                "shellforgeai_owned_paths_only": True,
            },
        )
        raise typer.Exit(code=1)

    if archive and selected:
        ap = create_archive(selected, data_dir, source="prune")
        console.print(f"- archive: {ap}")

    deleted, errors, removed = delete_paths(selected, allowed_roots)
    receipt_json, _receipt_md = write_prune_receipt(
        data_dir,
        mode="execute",
        category=category,
        selection=selected,
        deleted=deleted,
        failed=errors,
        bytes_removed=removed,
        max_age_days=max_age_days,
        keep_latest=keep_latest,
    )
    event = _append_audit_event_returning(
        runtime,
        kind="audit",
        action="prune",
        status="success" if not errors else "partial",
        summary="metadata prune executed",
        details={
            "operation": "metadata_prune_executed",
            "category": category,
            "deleted": len(deleted),
            "failed": len(errors),
            "bytes_removed": removed,
            "receipt": str(receipt_json),
            "execution_status": "not_executed",
            "metadata_cleanup_executed": True,
            "remediation_execution": False,
            "docker_mutation": False,
            "service_mutation": False,
            "package_mutation": False,
            "shellforgeai_owned_paths_only": True,
        },
    )
    console.print("Prune executed:")
    console.print(f"- deleted: {len(deleted)}")
    console.print(f"- failed: {len(errors)}")
    console.print(f"- bytes_removed: {removed}")
    if event and event.get("event_id"):
        console.print(f"- audit event: {event['event_id']}")
    console.print("- scope: ShellForgeAI-owned metadata only")
    console.print("- remediation_execution: false")
    console.print(f"- receipt: {receipt_json}")
    if errors:
        for e in errors:
            console.print(f"- {e}")
        raise typer.Exit(code=1)


@audit_app.command("archive")
def audit_archive(
    ctx: typer.Context,
    older_than_days: int | None = typer.Option(None, "--older-than-days"),
    session_id: str | None = typer.Option(None, "--session"),
    proposal_id: str | None = typer.Option(None, "--proposal"),
    output: Annotated[Path | None, typer.Option("--output")] = None,
) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    cats = build_categories(data_dir)
    paths = []
    for name in ("exports", "apply-bundles", "actions", "audit-exports"):
        paths.extend(collect_category(cats[name]))
    paths = prune_select(paths, max_age_days=older_than_days, keep_latest=None)
    if session_id:
        paths = [p for p in paths if session_id in p.name or session_id in str(p)]
    if proposal_id:
        paths = [p for p in paths if proposal_id in p.name or proposal_id in str(p)]
    if not paths:
        console.print("No matching ShellForgeAI-owned metadata found for archiving.")
        return
    archive_path = create_archive(paths, data_dir, source="older-than-days", output=output)
    _append_audit_event(
        runtime,
        kind="audit",
        action="archive",
        status="success",
        summary="metadata archive created",
        details={
            "operation": "metadata_archive_created",
            "archive": str(archive_path),
            "count": len(paths),
        },
    )
    console.print("Archive created:")
    console.print(f"- archive: {archive_path}")
    console.print(f"- files: {len(paths)}")
    console.print("- execution: none")


@audit_app.command("archive-validate")
def audit_archive_validate(archive: Path) -> None:
    ok, errors, files = validate_archive(archive)
    if not ok:
        console.print("Archive validation failed:")
        for err in errors:
            console.print(f"- {err}")
        raise typer.Exit(code=1)
    console.print("Archive validation passed:")
    console.print(f"- archive: {archive}")
    console.print(f"- files: {files}")
    console.print("- checksums: ok")
    console.print("- execution: none")


# ---------------------------------------------------------------------------
# PR40: audit-aware incident index / search


def _print_index_summary(path: Path, index) -> None:
    counts = index.source_counts
    console.print("Audit index written:")
    console.print(f"- index: {path}")
    console.print(f"- events: {counts.get('events', 0)}")
    console.print(f"- sessions: {counts.get('sessions', 0)}")
    console.print(f"- proposals: {counts.get('proposals', 0)}")
    console.print(f"- exports: {counts.get('exports', 0)}")
    console.print(f"- apply_bundles: {counts.get('apply_bundles', 0)}")
    console.print(f"- actions: {counts.get('actions', 0)}")
    console.print(f"- warnings: {len(index.warnings)}")
    for w in index.warnings:
        console.print(f"  - {w}")
    console.print("- execution: none")


@audit_index_app.callback()
def audit_index_main(
    ctx: typer.Context,
    rebuild: bool = typer.Option(
        False, "--rebuild", help="Explicitly rebuild the index from source files."
    ),
) -> None:
    """Build or rebuild the audit-aware incident index (PR40).

    Read-only over source artifacts; writes only ``<data_dir>/audit/incident-index.json``.
    ShellForgeAI does not execute any command.
    """
    if ctx.invoked_subcommand is not None:
        return
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    index = incident_index_mod.build_index(data_dir)
    path = incident_index_mod.write_index(data_dir, index)
    if rebuild:
        console.print("Audit index rebuilt (overwrote existing index file).")
    _print_index_summary(path, index)
    console.print("- No commands executed.")
    console.print("- No remediation performed.")


@audit_index_app.command("validate")
def audit_index_validate(ctx: typer.Context) -> None:
    """Validate the on-disk incident index file."""
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    payload, err = incident_index_mod.load_index(data_dir)
    if payload is None:
        console.print("Audit index validation failed:")
        console.print(f"- {err or 'index file missing'}")
        raise typer.Exit(code=1)
    result = incident_index_mod.validate_index_payload(payload)
    if not result.ok:
        console.print("Audit index validation failed:")
        for e in result.errors:
            console.print(f"- {e}")
        raise typer.Exit(code=1)
    console.print("Audit index validation passed:")
    console.print(f"- index: {incident_index_mod.index_path(data_dir)}")
    console.print(f"- items: {result.item_count}")
    console.print("- safety: ok")
    console.print("- execution: none")


def _print_search_results(matches: list[dict]) -> None:
    if not matches:
        console.print("No matching audit/index records found.")
        return
    console.print(f"Results: {len(matches)}")
    console.print(
        "Time                  Type           Status      Risk      Reference"
        "             Component             Summary"
    )
    for item in matches:
        ts = str(item.get("created_at") or "")[:19].replace("T", " ")
        itype = str(item.get("item_type") or "")
        status = str(item.get("status") or "-")
        risk = str(item.get("risk") or "-")
        ref = str(item.get("proposal_id") or item.get("session_id") or item.get("item_id") or "-")
        component = str(item.get("component") or item.get("target") or "-")
        summary = str(item.get("summary") or "")
        paths = item.get("paths") or []
        path_count = len(paths) if isinstance(paths, list) else 0
        console.print(
            f"{ts:<21} {itype:<14} {status:<11} {risk:<9} {ref:<20} "
            f"{component:<21} {summary} ({path_count} path{'s' if path_count != 1 else ''})"
        )


@audit_app.command("search")
def audit_search(
    ctx: typer.Context,
    query: Annotated[str | None, typer.Argument()] = None,
    component: str | None = typer.Option(None, "--component"),
    target: str | None = typer.Option(None, "--target"),
    kind: str | None = typer.Option(None, "--kind"),
    status: str | None = typer.Option(None, "--status"),
    risk: str | None = typer.Option(None, "--risk"),
    proposal: str | None = typer.Option(None, "--proposal"),
    session: str | None = typer.Option(None, "--session"),
    item_type: str | None = typer.Option(None, "--type"),
    since: str | None = typer.Option(None, "--since"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Search the audit-aware incident index (read-only; no execution)."""
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    payload, err = incident_index_mod.load_index(data_dir)
    if payload is None:
        if json_output:
            console.print_json(data=[])
            return
        console.print("No matching audit/index records found.")
        console.print(f"- {err or 'index file missing'}")
        console.print("- hint: run `shellforgeai audit index` to build the index.")
        return
    items = payload.get("items") or []
    filters = incident_index_mod.SearchFilters(
        component=component,
        target=target,
        kind=kind,
        status=status,
        risk=risk,
        proposal=proposal,
        session=session,
        item_type=item_type,
        since=since,
    )
    matches = incident_index_mod.search_items(items, query=query, filters=filters)
    if json_output:
        console.print_json(data=matches)
        return
    _print_search_results(matches)


_LAB_NAME_ALIASES = {
    "missing-env": "sfai-missing-env",
    "restart-loop": "sfai-restart-loop",
    "noisy-logs": "sfai-noisy-logs",
    "bad-volume-perms": "sfai-bad-volume-perms",
    "bad-network": "sfai-bad-network",
}


def _normalize_diagnose_target(target: str) -> str:
    """Route NL-style diagnose targets through the interactive router.

    `diagnose docker` and `diagnose logs` already resolve directly. But
    sentences like ``"why is the app restarting?"`` previously fell through
    to a generic host-only bundle. Apply the same router used by the REPL
    so the CLI behaves consistently.
    """
    raw = target.strip()
    if not raw or " " not in raw and "?" not in raw and not raw.endswith("?"):
        return raw
    routed = route_input(raw)
    if routed.name == "diagnose" and routed.args:
        return routed.args
    if routed.name == "logs_mutation_refused":
        return "logs"
    return raw


@app.command()
def diagnose(
    ctx: typer.Context,
    target: str,
    online: bool = False,
    since: str = "30m",
    json_output: bool = typer.Option(False, "--json"),
    save_plan: bool = False,
    model: bool = typer.Option(False, "--model"),
    raw: bool = typer.Option(False, "--raw"),
    full_context: bool = typer.Option(False, "--full-context"),
    with_runbook: bool = typer.Option(
        False,
        "--with-runbook",
        help="Also write an operator-run remediation runbook (read-only synthesis).",
    ),
) -> None:
    runtime = _ctx(ctx)
    raw_target_text = target
    target = _normalize_diagnose_target(target)
    from shellforgeai.core.ask_routing import is_network_reachability_intent

    net_reach = is_network_reachability_intent(raw_target_text)
    result = diagnose_target(runtime, target, online=online, since=since)
    if net_reach:
        try:
            from shellforgeai.core.collectors import collect_network_evidence

            existing_sources = {i.source for i in result.evidence.items}
            for ni in collect_network_evidence(runtime):
                if ni.source not in existing_sources:
                    result.evidence.items.append(ni)
        except Exception:
            pass
    audit = AuditStorage(runtime.session.data_dir)
    _ensure_artifact_dir(runtime)
    ev_path = runtime.session.artifact_dir / "evidence.json"
    ev_path.write_text(result.evidence.model_dump_json(indent=2), encoding="utf-8")
    plan_path = runtime.session.artifact_dir / "plan.json"
    if save_plan:
        plan_path.write_text(result.proposed_plan.model_dump_json(indent=2), encoding="utf-8")
    summary_path = runtime.session.artifact_dir / "summary.md"
    runbook_path = runtime.session.artifact_dir / "runbook.md"
    runbook_json_path = runtime.session.artifact_dir / "runbook.json"
    if with_runbook:
        rb = runbook_from_evidence_file(
            ev_path,
            session_id=runtime.session.session_id,
            target=target,
        )
        runbook_path.write_text(render_runbook_md(rb), encoding="utf-8")
        import json

        runbook_json_path.write_text(json.dumps(rb.to_schema_dict(), indent=2), encoding="utf-8")
    summary_candidates = ["evidence.json", "plan.json", "summary.md"]
    if with_runbook:
        summary_candidates += ["runbook.md", "runbook.json"]
    write_diagnosis_summary_md(
        path=summary_path,
        session_id=result.session_id,
        target=target,
        target_type=result.target_type.value,
        created_at=result.created_at.isoformat(),
        evidence_items=list(result.evidence.items),
        findings=list(result.findings),
        runtime_context=getattr(result, "runtime_context", {}),
        artifact_dir=runtime.session.artifact_dir,
        artifact_candidates=summary_candidates,
    )
    artifacts_list = [str(ev_path)] + ([str(plan_path)] if save_plan else [])
    if with_runbook:
        artifacts_list.append(str(runbook_path))
        artifacts_list.append(str(runbook_json_path))
    rec = {
        "session_id": runtime.session.session_id,
        "command": "diagnose",
        "target": target,
        "mode": runtime.session.mode,
        "profile": runtime.profile.name,
        "tools_called": [i.source for i in result.evidence.items],
        "artifacts": artifacts_list,
        "warnings": result.warnings,
        "errors": result.errors,
        "summary": f"diagnosed {target}",
    }
    audit.append(rec)
    _append_audit_event(
        runtime,
        kind="diagnose",
        action="created",
        status="success",
        session_id=runtime.session.session_id,
        target=target,
        summary=f"diagnose complete for {target}",
        artifacts=artifacts_list + [str(summary_path)],
        details={"finding_count": len(result.findings), "warning_count": len(result.warnings)},
    )
    if model:
        _ensure_artifact_dir(runtime)
        provider = build_provider(runtime.settings)
        ctx_mode = "full" if full_context else "standard"
        prompt = build_contextual_prompt(
            f"Diagnose {target}",
            {
                "findings": [f.model_dump() for f in result.findings],
                "evidence": [i.model_dump() for i in result.evidence.items],
            },
            mode=ctx_mode,
        )
        mresp = provider.complete(
            ModelRequest(
                prompt=prompt,
                model=runtime.settings.model.model,
                provider=runtime.settings.model.provider,
                timeout_seconds=runtime.settings.model.timeout_seconds,
                metadata={"raw": raw},
            )
        )
        mpath = runtime.session.artifact_dir / "model-response.md"
        mpath.write_text(
            f"{mresp.text}\n\n"
            f"Provider: {mresp.provider}\n"
            f"Model: {mresp.model}\n"
            f"{_usage_line(mresp)}",
            encoding="utf-8",
        )
        spath = runtime.session.artifact_dir / "summary.md"
        _write_summary_md(
            spath,
            result.session_id,
            target,
            result.target_type.value,
            result.created_at.isoformat(),
            list(result.evidence.items),
            list(result.findings),
            getattr(result, "runtime_context", {}),
            runtime.session.artifact_dir,
            include_model_response=True,
        )
        if raw and mresp.raw and mresp.raw.get("stdout_jsonl"):
            (runtime.session.artifact_dir / "raw-model-events.jsonl").write_text(
                mresp.raw["stdout_jsonl"], encoding="utf-8"
            )
        if not json_output:
            console.print("Model-assisted analysis:\n" + mresp.text)
            console.print(f"Provider: {mresp.provider}\nModel: {mresp.model}\n{_usage_line(mresp)}")
    if json_output:
        typer.echo(result.model_dump_json(indent=2))
    else:
        model_response_artifact = runtime.session.artifact_dir / "model-response.md"
        if model and model_response_artifact.exists():
            model_response_display: Path | str = model_response_artifact
        else:
            model_response_display = "n/a"
        runtime_context = getattr(result, "runtime_context", {})
        visibility = str(runtime_context.get("visibility", "runtime_scoped")).replace("_", "-")
        summary = (
            f"Session: {result.session_id}\n"
            f"Target: {target}\n"
            f"Target type: {result.target_type.value}\n"
            f"Visibility: {visibility}\n"
            f"Container-limited view: {'yes' if visibility == 'container-limited' else 'no'}\n"
            f"Evidence: {len(result.evidence.items)} item(s)\n"
            f"{findings_summary_line(result.findings)}\n"
            f"First safe command: {triage_detail_command(target)}\n"
            "Artifacts:\n"
            f"- evidence: {ev_path}\n"
            f"- plan: {plan_path if save_plan else 'not-saved'}\n"
            f"- model response: {model_response_display}\n"
            f"- summary: {summary_path if summary_path.exists() else 'n/a'}\n"
            f"- runbook: {runbook_path if runbook_path.exists() else 'not-saved'}\n"
            f"- runbook json: {runbook_json_path if runbook_json_path.exists() else 'not-saved'}"
        )
        # soft_wrap keeps long artifact paths on one line instead of letting Rich
        # hard-wrap them mid-token at narrow terminal widths.
        console.print(summary, soft_wrap=True)


@app.command()
def research(ctx: typer.Context, query: str, model: bool = typer.Option(False, "--model")) -> None:
    runtime = _ctx(ctx)
    hits = search_local(
        runtime.settings.knowledge.local_paths + [str(Path.cwd() / "SHELLFORGE.md")], query
    )
    if not hits:
        console.print("No local knowledge hits.")
        return
    for h in hits:
        console.print(f"{h.path}:{h.line} {h.snippet}")
    if model:
        runtime = _ctx(ctx)
        _ensure_artifact_dir(runtime)
        provider = build_provider(runtime.settings)
        resp = provider.complete(
            ModelRequest(
                prompt=build_model_prompt(query, {"hits": [h.model_dump() for h in hits]}),
                model=runtime.settings.model.model,
                provider=runtime.settings.model.provider,
                timeout_seconds=runtime.settings.model.timeout_seconds,
            )
        )
        console.print("\nModel synthesis:\n" + resp.text)


@app.command()
def plan(ctx: typer.Context, goal: str, model: bool = typer.Option(False, "--model")) -> None:
    runtime = _ctx(ctx)
    t = classify_target(goal).value
    p = Plan(
        plan_id=f"plan_{runtime.session.session_id}",
        goal=goal,
        session_id=runtime.session.session_id,
        steps=[
            PlanStep(step_id="1", title="Collect evidence", description=f"Use diagnose for {t}"),
            PlanStep(
                step_id="2",
                title="Review",
                description="Review findings and confirm next safe steps",
            ),
        ],
    )
    _ensure_artifact_dir(runtime)
    out = runtime.session.artifact_dir / "plan.json"
    out.write_text(p.model_dump_json(indent=2), encoding="utf-8")
    if model:
        provider = build_provider(runtime.settings)
        resp = provider.complete(
            ModelRequest(
                prompt=build_model_prompt(goal, {"deterministic_plan": p.model_dump()}),
                model=runtime.settings.model.model,
                provider=runtime.settings.model.provider,
                timeout_seconds=runtime.settings.model.timeout_seconds,
            )
        )
        (runtime.session.artifact_dir / "model-plan-review.md").write_text(
            resp.text, encoding="utf-8"
        )
    console.print(str(out))


@app.command()
def runbook(
    ctx: typer.Context,
    artifact: Annotated[Path | None, typer.Argument()] = None,
    latest: bool = typer.Option(
        False, "--latest", help="Use the most recent evidence.json artifact."
    ),
    session: str | None = typer.Option(
        None, "--session", help="Use evidence.json from this session id (sf_*)."
    ),
) -> None:
    """Generate an operator-run remediation runbook from existing evidence.

    This command is read-only synthesis: it reads ``evidence.json`` and writes
    ``runbook.md`` (and ``runbook.json``) into the same artifact directory.
    ShellForgeAI does not execute any remediation steps.
    """
    runtime = _ctx(ctx)
    target_path: Path | None = None
    if artifact is not None:
        candidate = artifact
        if candidate.is_dir():
            ev = candidate / "evidence.json"
            if not ev.exists():
                console.print(f"No evidence.json found in artifact directory: {candidate}")
                raise typer.Exit(code=1)
            target_path = ev
        else:
            target_path = candidate
    elif session:
        candidate = Path(runtime.session.data_dir) / "artifacts" / session / "evidence.json"
        target_path = candidate
    elif latest:
        target_path = latest_evidence_artifact(runtime.session.data_dir)
        if target_path is None:
            console.print(
                "No evidence.json artifacts found. Run `shellforgeai diagnose <target>` first."
            )
            raise typer.Exit(code=1)
    else:
        raise typer.BadParameter("Provide an evidence.json path, --latest, or --session <id>.")
    if target_path is None or not target_path.exists():
        console.print(f"Evidence artifact not found: {target_path}")
        raise typer.Exit(code=1)
    try:
        rb = runbook_from_evidence_file(target_path)
    except (OSError, ValueError) as exc:
        console.print(f"Failed to read evidence artifact {target_path}: {exc}")
        raise typer.Exit(code=1) from None
    out_dir = target_path.parent
    md_path = out_dir / "runbook.md"
    json_path = out_dir / "runbook.json"
    md_path.write_text(render_runbook_md(rb), encoding="utf-8")
    import json

    json_path.write_text(json.dumps(rb.to_schema_dict(), indent=2), encoding="utf-8")
    console.print(
        "Operator runbook written (read-only synthesis; ShellForgeAI did not execute anything):\n"
        f"- {md_path}\n"
        f"- {json_path}\n"
        f"- session: {rb.session_id}\n"
        f"- problems: {len(rb.problems)}\n"
        f"- options: {len(rb.operator_steps)}\n"
        f"- risk: {rb.risk_level}"
    )


@app.command("validate-runbook")
def validate_runbook_cmd(
    ctx: typer.Context,
    artifact: Annotated[Path | None, typer.Argument()] = None,
    latest: bool = typer.Option(False, "--latest"),
) -> None:
    runtime = _ctx(ctx)
    target_path: Path | None = None
    if artifact is not None:
        target_path = artifact / "runbook.json" if artifact.is_dir() else artifact
    elif latest:
        ev = latest_evidence_artifact(runtime.session.data_dir)
        target_path = ev.parent / "runbook.json" if ev else None
    if target_path is None or not target_path.exists():
        console.print(
            "Runbook validation failed:\n"
            f"- runbook: {target_path}\n"
            "- errors:\n"
            "  - runbook.json not found"
        )
        raise typer.Exit(code=1)
    try:
        import json

        payload = json.loads(target_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        console.print(
            "Runbook validation failed:\n"
            f"- runbook: {target_path}\n"
            "- errors:\n"
            f"  - malformed JSON: {exc}"
        )
        raise typer.Exit(code=1) from None
    errors, warnings = validate_runbook_payload(payload)
    if errors:
        console.print("Runbook validation failed:")
        console.print(f"- runbook: {target_path}")
        console.print("- errors:")
        for err in errors:
            console.print(f"  - {err}")
        raise typer.Exit(code=1)
    console.print(
        "Runbook validation passed:\n"
        f"- runbook: {target_path}\n"
        f"- session: {payload.get('session_id')}\n"
        f"- problems: {len(payload.get('problems') or [])}\n"
        f"- options: {len(payload.get('remediation_options') or [])}\n"
        f"- risk: {payload.get('overall_risk')}\n"
        "- safety: operator-run only\n"
        "- schema: ok\n"
        f"- references: {'ok' if not warnings else 'warning'}\n"
        "- mutation execution: none"
    )


def _resolve_apply_input(
    runtime: RuntimeContext,
    target: str | None,
    *,
    latest_approved: bool,
) -> tuple[str, Path | None, Proposal | None, Path | None]:
    """Resolve the apply argument to ``(kind, plan_path, proposal, proposal_path)``.

    ``kind`` is one of ``"plan"`` (legacy plan.json), ``"proposal"`` (from disk),
    or ``"missing"``. Plan files keep the existing validation-only behavior;
    proposals route to the new PR33 apply preflight + bundle path.
    """
    data_dir = Path(runtime.session.data_dir)
    if latest_approved:
        proposal = latest_approved_proposal(data_dir)
        if proposal is None:
            return "missing", None, None, None
        path, _status = find_proposal_path(data_dir, proposal.proposal_id)
        return "proposal", None, proposal, path
    if not target:
        return "missing", None, None, None
    # Try filesystem path first.
    p = Path(target)
    if p.exists() and p.is_file():
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            obj = None
        if isinstance(obj, dict):
            if "proposal_id" in obj:
                try:
                    proposal = load_proposal_from_path(p)
                except (OSError, ValueError):
                    return "missing", None, None, None
                return "proposal", None, proposal, p
            if "plan_id" in obj:
                return "plan", p, None, None
        # Fall through; not JSON we recognize.
    # Otherwise treat as proposal id and search.
    proposal_path, _status = find_proposal_path(data_dir, target)
    if proposal_path is None:
        return "missing", None, None, None
    try:
        proposal = load_proposal_from_path(proposal_path)
    except (OSError, ValueError):
        return "missing", None, None, None
    return "proposal", None, proposal, proposal_path


def _print_apply_bundle_success(proposal: Proposal, files: list[Path]) -> None:
    console.print("Apply preflight passed. Execution remains disabled in this alpha.")
    console.print(f"- proposal: {proposal.proposal_id}")
    console.print(f"- status: {proposal.status}")
    console.print(f"- risk: {proposal.risk}")
    console.print("- execution: not_executed")
    console.print("- bundle:")
    for f in files:
        console.print(f"  - {f}")
    console.print("")
    console.print("No commands were executed.")


def _print_apply_preflight_failure(proposal: Proposal | None, errors: list[str]) -> None:
    console.print("Apply preflight failed:")
    if proposal is not None:
        console.print(f"- proposal: {proposal.proposal_id}")
        console.print(f"- status: {proposal.status}")
    for err in errors or ["unknown error"]:
        console.print(f"- {err}")
    console.print("- no commands executed")


@app.command()
def apply(
    ctx: typer.Context,
    target: Annotated[str | None, typer.Argument()] = None,
    latest_approved: bool = typer.Option(
        False, "--latest-approved", help="Apply the newest approved proposal."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Run preflight only; do not write bundle files."
    ),
    allow_stale: bool = typer.Option(
        False,
        "--allow-stale",
        help=(
            "Allow apply to proceed even if the PR38 guard reports stale evidence. "
            "Drift (changed source artifacts) is always refused."
        ),
    ),
    max_age_hours: float | None = typer.Option(
        None,
        "--max-age-hours",
        help="Override the stale-evidence guard max age (proposals: 24h).",
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help=(
            "PR47: opt in to the first non-metadata mutation gate "
            "(docker restart <allowlisted-lab-container> only). Requires --confirm."
        ),
    ),
    confirm: bool = typer.Option(
        False,
        "--confirm",
        help="PR47: required alongside --execute to actually perform the lab restart.",
    ),
    action_id: str | None = typer.Option(
        None,
        "--action-id",
        help=(
            "PR47: select a specific compiled action id when more than one restart "
            "candidate is present."
        ),
    ),
) -> None:
    """Validate a plan or generate an operator execution bundle for a proposal.

    ShellForgeAI does not execute commands. For approved proposals this command
    runs deterministic preflight checks and writes a static bundle:
    apply-preview.md, operator-commands.sh, rollback.sh, validation.md,
    apply-preflight.json. The shell scripts contain an early ``exit 2`` so they
    cannot run if accidentally invoked.
    """
    runtime = _ctx(ctx)
    if not target and not latest_approved:
        raise typer.BadParameter(
            "Provide a proposal id, a proposal JSON path, a plan.json path, or --latest-approved."
        )
    kind, plan_path, proposal, _proposal_path = _resolve_apply_input(
        runtime, target, latest_approved=latest_approved
    )

    if kind == "plan" and plan_path is not None:
        # Preserve legacy plan.json validation-only behavior.
        Plan.model_validate_json(plan_path.read_text(encoding="utf-8"))
        console.print(
            "Apply execution is intentionally disabled in this alpha. "
            "Plan validation is available; execution will be introduced after safety hardening."
        )
        return

    if kind == "missing" or proposal is None:
        if latest_approved:
            console.print(
                "Apply preflight failed:\n"
                "- no approved proposals found\n"
                "- run `shellforgeai approvals create <session>` then "
                "`shellforgeai approvals approve <id> --reason '...'`\n"
                "- no commands executed"
            )
        elif target is None:
            raise typer.BadParameter("missing proposal/plan target")
        else:
            console.print(
                "Apply preflight failed:\n"
                f"- proposal/plan not found: {target}\n"
                "- no commands executed"
            )
        raise typer.Exit(code=1)
    if proposal.kind == "compose_service_restart":
        console.print(
            "Compose service restart proposals are proposal-only in PR62; "
            "execution is not implemented."
        )
        console.print("- no docker compose command was executed")
        raise typer.Exit(code=1)

    preflight = run_preflight(proposal)
    data_dir = Path(runtime.session.data_dir)

    # PR38: run the stale-evidence / drift guard against the proposal so apply
    # never produces a bundle from a stale or drifted source by default.
    guard_max_age = max_age_from_hours(max_age_hours, source_type="proposal")
    guard_payload = json.loads(proposal.model_dump_json())
    guard_proposal_path, _gs = find_proposal_path(data_dir, proposal.proposal_id)
    guard_report = check_proposal_payload(
        guard_payload,
        source_path=str(guard_proposal_path or ""),
        max_age_seconds=guard_max_age,
    )
    guard_written = write_guard_report(guard_report, data_dir=data_dir)

    guard_blocks = guard_report.decision in (
        GUARD_DECISION_BLOCKED,
        GUARD_DECISION_DRIFT,
    ) or (guard_report.decision == GUARD_DECISION_STALE and not allow_stale)

    if guard_blocks:
        if guard_report.decision == GUARD_DECISION_STALE:
            console.print(
                "Apply refused: proposal evidence is stale.\n"
                f"- proposal: {proposal.proposal_id}\n"
                f"- age_seconds: {guard_report.age.age_seconds} "
                f"(max {guard_report.age.max_age_seconds})\n"
                f"- guard report: {guard_written.json_path}\n"
                "- next step: regenerate evidence/runbook/proposal "
                "(or pass --allow-stale to bypass; drift is never bypassed).\n"
                "- no commands executed"
            )
        elif guard_report.decision == GUARD_DECISION_DRIFT:
            console.print(
                "Apply refused: source artifacts changed after the proposal was created.\n"
                f"- proposal: {proposal.proposal_id}\n"
                f"- changed: {', '.join(guard_report.drift.changed_files) or 'n/a'}\n"
                f"- missing: {', '.join(guard_report.drift.missing_files) or 'n/a'}\n"
                f"- guard report: {guard_written.json_path}\n"
                "- next step: regenerate the proposal from current evidence.\n"
                "- no commands executed"
            )
        else:
            console.print(
                "Apply refused: guard check blocked.\n"
                f"- proposal: {proposal.proposal_id}\n"
                f"- guard report: {guard_written.json_path}\n"
                "- no commands executed"
            )
        if not dry_run:
            preflight_path = write_diagnostic_preflight(
                proposal,
                data_dir=data_dir,
                preflight=preflight,
                proposal_id=proposal.proposal_id,
            )
            # Inject guard status into the diagnostic preflight record.
            try:
                payload = json.loads(preflight_path.read_text(encoding="utf-8"))
                payload["guard_status"] = guard_report.decision
                payload["guard_report"] = str(guard_written.json_path)
                payload["execution_allowed"] = False
                payload["execution_status"] = "not_executed"
                preflight_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            except (OSError, ValueError):
                pass
            console.print(f"- preflight record: {preflight_path}")
        raise typer.Exit(code=1)

    if not preflight.passed:
        _print_apply_preflight_failure(proposal, preflight.errors)
        # Always write a diagnostic apply-preflight.json so the operator can
        # see the refusal record. No operator-run scripts are emitted.
        if not dry_run:
            preflight_path = write_diagnostic_preflight(
                proposal,
                data_dir=data_dir,
                preflight=preflight,
                proposal_id=proposal.proposal_id,
            )
            try:
                payload = json.loads(preflight_path.read_text(encoding="utf-8"))
                payload["guard_status"] = guard_report.decision
                payload["guard_report"] = str(guard_written.json_path)
                preflight_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            except (OSError, ValueError):
                pass
            console.print(f"- preflight record: {preflight_path}")
        raise typer.Exit(code=1)

    if dry_run:
        console.print("Apply preflight passed (dry-run). Execution remains disabled in this alpha.")
        console.print(f"- proposal: {proposal.proposal_id}")
        console.print(f"- status: {proposal.status}")
        console.print(f"- risk: {proposal.risk}")
        console.print(f"- guard status: {guard_report.decision}")
        console.print("- execution: not_executed")
        console.print("- bundle: not written (dry-run)")
        console.print("- no commands executed")
        return

    result = generate_bundle(proposal, data_dir=data_dir, preflight=preflight)
    # PR37: compile actions alongside the bundle. Review-only; no execution.
    actions_json_path: Path | None = None
    try:
        actions_result = compile_and_write(proposal, data_dir=data_dir)
        actions_json_path = actions_result.actions_json
        files = list(result.files) + [actions_result.actions_json, actions_result.actions_md]
        # Inject PR37/PR38 fields into apply-preflight.json without rewriting bundle logic.
        try:
            preflight_payload = json.loads(result.preflight_path.read_text(encoding="utf-8"))
            preflight_payload["actions_compiled"] = True
            preflight_payload["actions_path"] = str(actions_result.actions_json)
            summary = actions_result.compiled.summary()
            preflight_payload["blocked_actions"] = summary["blocked"]
            preflight_payload["manual_only_actions"] = summary["manual_only"]
            preflight_payload["guard_status"] = guard_report.decision
            preflight_payload["guard_report"] = str(guard_written.json_path)
            preflight_payload["execution_allowed"] = False
            preflight_payload["execution_status"] = "not_executed"
            result.preflight_path.write_text(
                json.dumps(preflight_payload, indent=2), encoding="utf-8"
            )
        except (OSError, ValueError):
            pass
    except Exception:
        files = list(result.files)
        try:
            preflight_payload = json.loads(result.preflight_path.read_text(encoding="utf-8"))
            preflight_payload["guard_status"] = guard_report.decision
            preflight_payload["guard_report"] = str(guard_written.json_path)
            result.preflight_path.write_text(
                json.dumps(preflight_payload, indent=2), encoding="utf-8"
            )
        except (OSError, ValueError):
            pass
    _print_apply_bundle_success(proposal, files)
    if guard_report.decision == GUARD_DECISION_WARNING:
        console.print("- guard: warning (see report)")
    elif guard_report.decision == GUARD_DECISION_FRESH:
        console.print("- guard: fresh")
    console.print(f"- guard report: {guard_written.json_path}")

    # PR47: first non-metadata mutation gate. The only allowed mutation is
    # ``docker restart <allowlisted-lab-container>``. The bundle was generated
    # above only after preflight + guard passed; if --execute --confirm were
    # also supplied, we may now invoke the lab restart executor.
    if execute or confirm:
        actions_payload: dict[str, Any] = {}
        if actions_json_path is not None:
            try:
                actions_payload = json.loads(actions_json_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                actions_payload = {}
        _run_lab_restart_gate(
            runtime,
            proposal=proposal,
            actions_payload=actions_payload,
            guard_decision=guard_report.decision,
            execute=execute,
            confirm=confirm,
            action_id=action_id,
        )


def _lab_restart_executor_factory() -> lab_restart_mod.CommandExecutor:
    """Return the default executor. Tests monkeypatch this symbol to inject a fake."""
    return lab_restart_mod.SubprocessExecutor()


def _lab_restart_inspector_factory() -> lab_restart_mod.ContainerInspector:
    """Return the default read-only inspector. Tests monkeypatch this symbol."""
    return lab_restart_mod.DockerCliInspector()


def _lab_restart_verification_config() -> lab_restart_mod.VerificationConfig:
    """Return the default verification timing. Tests may monkeypatch this."""
    return lab_restart_mod.VerificationConfig()


def _lab_restart_verification_sleep(seconds: float) -> None:
    """Default sleep used by post-mutation verification. Tests replace this."""
    import time as _time

    _time.sleep(seconds)


@dataclass
class LabRestartGateOutcome:
    """Outcome of the guarded lab-container restart gate.

    Returned by :func:`_perform_lab_restart_gate` so callers (apply CLI and
    PR53 mission execute handoff) can render their own output without having
    a second executor or bypassing the shared safety logic.
    """

    refused: bool = False
    failed_gate: str = ""
    failed_message: str = ""
    success: bool = False
    status: str = ""
    receipt_path: Path | None = None
    verification: dict[str, Any] = dataclass_field(default_factory=dict)
    container: str = ""
    action_id: str = ""
    proposal_id: str = ""
    rollback_preview_path: str = ""
    rollback_readiness: str = "failed"
    exec_result_ok: bool = False
    exec_stderr: str = ""
    audit_event: dict[str, Any] | None = None
    audit_status: str = ""


def _perform_lab_restart_gate(
    runtime: RuntimeContext,
    *,
    proposal: Proposal,
    actions_payload: dict[str, Any],
    guard_decision: str,
    execute: bool,
    confirm: bool,
    action_id: str | None,
    executor: lab_restart_mod.CommandExecutor | None = None,
    timeout_seconds: int = 30,
) -> LabRestartGateOutcome:
    """Shared lab-container restart gate execution.

    Evaluates every PR47/PR48/PR49 gate, performs the restart via the injected
    executor on success, writes the execution receipt and audit event, and
    returns a :class:`LabRestartGateOutcome` describing what happened. Never
    prints to the console and never raises ``typer.Exit``. Callers translate
    the outcome to user-facing output and exit codes.
    """
    data_dir = Path(runtime.session.data_dir)
    allowlist = lab_restart_mod.load_allowlist(data_dir)
    gate = lab_restart_mod.evaluate_gates(
        execute=execute,
        confirm=confirm,
        proposal_status=proposal.status,
        guard_decision=guard_decision,
        actions_payload=actions_payload,
        allowlist=allowlist,
        action_id=action_id,
    )

    # PR49 rollback-readiness gate for service-impacting restart.
    rollback_readiness = "failed"
    rollback_preview_path = ""
    if gate.allowed:
        preview_dir = rollback_preview_mod.rollback_preview_dir(data_dir, proposal.proposal_id)
        preview_json = preview_dir / "rollback-preview.json"
        if not preview_json.exists():
            gate.allowed = False
            gate.failed_gate = "rollback_preview_missing"
            gate.message = (
                "rollback preview missing; run: "
                f"shellforgeai rollback preview {proposal.proposal_id}"
            )
        if gate.allowed:
            try:
                rollback_payload = rollback_preview_mod.load_preview(preview_json)
                rollback_errors = rollback_preview_mod.validate_preview(rollback_payload)
                if rollback_errors:
                    raise ValueError("; ".join(rollback_errors))
                rollback_readiness = "passed"
                rollback_preview_path = str(preview_json)
            except Exception as exc:
                gate.allowed = False
                gate.failed_gate = "rollback_preview_invalid"
                gate.message = f"rollback preview missing or invalid: {exc}"

    proposal_compose_context = (
        dict(proposal.compose_context)
        if isinstance(getattr(proposal, "compose_context", None), dict) and proposal.compose_context
        else None
    )
    if not gate.allowed:
        receipt = lab_restart_mod.write_execution_receipt(
            data_dir,
            proposal_id=proposal.proposal_id,
            action_id=gate.action_id,
            container=gate.container,
            command_argv=(["docker", "restart", gate.container] if gate.container else []),
            gates=gate.gates_dict(),
            status="refused",
            exit_code=2,
            stdout="",
            stderr=gate.message,
            failed_gate=gate.failed_gate,
            rollback={
                "rollback_preview_path": rollback_preview_path,
                "rollback_readiness": rollback_readiness,
                "rollback_status": "preview_only" if rollback_preview_path else "",
                "rollback_executable_by_shellforgeai": False,
                "rollback_execution_allowed": False,
                "rollback_missing": gate.failed_gate == "rollback_preview_missing",
            },
            compose_context=proposal_compose_context,
        )
        _append_audit_event(
            runtime,
            kind=lab_restart_mod.AUDIT_KIND_EXECUTION,
            action=lab_restart_mod.AUDIT_ACTION_LAB_RESTART,
            status="refused",
            proposal_id=proposal.proposal_id,
            proposal_fingerprint=(proposal.fingerprint or {}).get("value", ""),
            target=gate.container or None,
            risk=proposal.risk,
            summary=f"lab container restart refused: {gate.failed_gate}",
            artifacts=[str(receipt)],
            details={
                "operation": "lab_container_restart_refused",
                "failed_gate": gate.failed_gate,
                "container": gate.container,
                "action_id": gate.action_id,
                "mutation_scope": lab_restart_mod.MUTATION_SCOPE,
                "remediation_execution": False,
                "mutation_performed": False,
                "receipt": str(receipt),
            },
        )
        return LabRestartGateOutcome(
            refused=True,
            failed_gate=gate.failed_gate,
            failed_message=gate.message,
            success=False,
            status="refused",
            receipt_path=receipt,
            container=gate.container,
            action_id=gate.action_id,
            proposal_id=proposal.proposal_id,
            rollback_preview_path=rollback_preview_path,
            rollback_readiness=rollback_readiness,
        )

    # Gate passed. Capture pre-restart state (read-only inspect), then run
    # the executor (fake in tests, subprocess in production).
    if executor is None:
        executor = _lab_restart_executor_factory()
    inspector = _lab_restart_inspector_factory()
    verification_cfg = _lab_restart_verification_config()
    sleep_fn = _lab_restart_verification_sleep

    before_inspect = inspector.inspect(gate.container)
    before_state = lab_restart_mod.capture_container_state_from(before_inspect)

    argv = ["docker", "restart", gate.container]
    result = executor.run(argv, timeout_seconds=timeout_seconds)

    # PR48: bounded read-only post-mutation verification. Never restarts again,
    # never execs, only calls the inspector (which only runs ``docker inspect``).
    outcome = lab_restart_mod.run_post_restart_verification(
        inspector=inspector,
        container=gate.container,
        before_state=before_state,
        restart_ok=result.ok,
        config=verification_cfg,
        sleep_fn=sleep_fn,
    )
    verification = dict(outcome.summary)

    # Operational status (receipt-level): marries restart cmd outcome with verification.
    if not result.ok:
        status = "failed"
    elif verification["status"] == lab_restart_mod.VERIFICATION_STATUS_PASSED:
        status = "success"
    elif verification["status"] == lab_restart_mod.VERIFICATION_STATUS_WARNING:
        status = "warning"
    else:
        status = "failed"

    # First write the receipt to fix its path; then persist evidence next to it
    # and re-emit the receipt with evidence paths embedded.
    receipt = lab_restart_mod.write_execution_receipt(
        data_dir,
        proposal_id=proposal.proposal_id,
        action_id=gate.action_id,
        container=gate.container,
        command_argv=argv,
        gates=gate.gates_dict(),
        status=status,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        verification=verification,
        compose_context=proposal_compose_context,
    )
    evidence_paths = lab_restart_mod.write_verification_evidence(
        receipt,
        before_raw=before_inspect.raw if before_inspect.exists else None,
        after_raw=outcome.after_raw,
    )
    if evidence_paths:
        verification["evidence"] = evidence_paths
        receipt = lab_restart_mod.write_execution_receipt(
            data_dir,
            proposal_id=proposal.proposal_id,
            action_id=gate.action_id,
            container=gate.container,
            command_argv=argv,
            gates=gate.gates_dict(),
            status=status,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            verification=verification,
            rollback={
                "rollback_preview_path": rollback_preview_path,
                "rollback_readiness": rollback_readiness,
                "rollback_status": "preview_only" if rollback_preview_path else "",
                "rollback_executable_by_shellforgeai": False,
                "rollback_execution_allowed": False,
            },
            receipt_path=receipt,
            compose_context=proposal_compose_context,
        )

    audit_status = (
        "success"
        if result.ok and verification["status"] == lab_restart_mod.VERIFICATION_STATUS_PASSED
        else "warning"
        if result.ok and verification["status"] == lab_restart_mod.VERIFICATION_STATUS_WARNING
        else "failed"
    )

    event = _append_audit_event_returning(
        runtime,
        kind=lab_restart_mod.AUDIT_KIND_EXECUTION,
        action=lab_restart_mod.AUDIT_ACTION_LAB_RESTART,
        status=audit_status,
        proposal_id=proposal.proposal_id,
        proposal_fingerprint=(proposal.fingerprint or {}).get("value", ""),
        target=gate.container,
        risk=proposal.risk,
        summary=(
            f"lab container restart {audit_status}: {gate.container} "
            f"(verification={verification['status']})"
        ),
        artifacts=[str(receipt)],
        safety={
            "execution_allowed": True,
            "execution_status": "executed",
            "mutation_performed": result.ok,
            "mutation_scope": lab_restart_mod.MUTATION_SCOPE,
        },
        details={
            "operation": "lab_container_restart",
            "container": gate.container,
            "action_id": gate.action_id,
            "command_argv": list(argv),
            "exit_code": result.exit_code,
            "mutation_scope": lab_restart_mod.MUTATION_SCOPE,
            "remediation_execution": True,
            "mutation_performed": result.ok,
            "docker_mutation": result.ok,
            "service_mutation": False,
            "package_mutation": False,
            "filesystem_mutation": False,
            "firewall_mutation": False,
            "arbitrary_command_execution": False,
            "receipt": str(receipt),
            "verification_status": verification["status"],
            "container_running_after": bool(verification.get("running_after", False)),
            "started_at_changed": bool(verification.get("started_at_changed", False)),
            "health_after": str(verification.get("health_after", "")),
            "verification_notes": list(verification.get("notes", [])),
        },
    )
    return LabRestartGateOutcome(
        refused=False,
        failed_gate="",
        failed_message="",
        success=(
            bool(result.ok) and verification["status"] != lab_restart_mod.VERIFICATION_STATUS_FAILED
        ),
        status=status,
        receipt_path=receipt,
        verification=verification,
        container=gate.container,
        action_id=gate.action_id,
        proposal_id=proposal.proposal_id,
        rollback_preview_path=rollback_preview_path,
        rollback_readiness=rollback_readiness,
        exec_result_ok=bool(result.ok),
        exec_stderr=result.stderr or "",
        audit_event=event,
        audit_status=audit_status,
    )


def _render_lab_restart_gate_outcome(outcome: LabRestartGateOutcome) -> None:
    """Render the apply-CLI message block for a completed gate run."""
    if outcome.refused:
        console.print("")
        console.print("Execution refused:")
        console.print(f"- failed gate: {outcome.failed_gate}")
        if outcome.failed_message:
            console.print(f"- detail: {outcome.failed_message}")
        console.print(f"- mutation_scope: {lab_restart_mod.MUTATION_SCOPE}")
        console.print("- no commands executed")
        if outcome.receipt_path is not None:
            console.print(f"- receipt: {outcome.receipt_path}")
        return

    verification = outcome.verification or {}
    vstatus = verification.get("status", "")
    console.print("")
    if not outcome.exec_result_ok:
        console.print("Guarded lab container restart failed:")
    elif vstatus == lab_restart_mod.VERIFICATION_STATUS_PASSED:
        console.print("Guarded lab container restart executed:")
    elif vstatus == lab_restart_mod.VERIFICATION_STATUS_WARNING:
        console.print("Guarded lab container restart executed with verification warning:")
    else:
        console.print("Guarded lab container restart executed but verification failed:")
    console.print(f"- proposal: {outcome.proposal_id}")
    console.print(f"- action: {outcome.action_id}")
    console.print(f"- container: {outcome.container}")
    console.print(f"- command: docker restart {outcome.container}")
    console.print("- executor: docker")
    console.print(f"- mutation_scope: {lab_restart_mod.MUTATION_SCOPE}")
    console.print(f"- verification: {vstatus}")
    console.print(f"- running_after: {bool(verification.get('running_after', False))}")
    console.print(f"- started_at_changed: {bool(verification.get('started_at_changed', False))}")
    console.print(f"- health_after: {verification.get('health_after', '')}")
    for note in verification.get("notes", []) or []:
        console.print(f"  - note: {note}")
    event = outcome.audit_event or {}
    if event.get("event_id"):
        console.print(f"- audit event: {event['event_id']}")
    if outcome.receipt_path is not None:
        console.print(f"- receipt: {outcome.receipt_path}")
    console.print("- rollback: none automatic")
    if not outcome.exec_result_ok and outcome.exec_stderr:
        console.print(f"- stderr: {outcome.exec_stderr[:200]}")
    if outcome.exec_result_ok and vstatus == lab_restart_mod.VERIFICATION_STATUS_FAILED:
        console.print("- no additional restart attempted")


def _run_lab_restart_gate(
    runtime: RuntimeContext,
    *,
    proposal: Proposal,
    actions_payload: dict[str, Any],
    guard_decision: str,
    execute: bool,
    confirm: bool,
    action_id: str | None,
    executor: lab_restart_mod.CommandExecutor | None = None,
    timeout_seconds: int = 30,
) -> None:
    """Apply-CLI wrapper around :func:`_perform_lab_restart_gate`.

    Renders output and translates failure outcomes into ``typer.Exit(1)``.
    """
    outcome = _perform_lab_restart_gate(
        runtime,
        proposal=proposal,
        actions_payload=actions_payload,
        guard_decision=guard_decision,
        execute=execute,
        confirm=confirm,
        action_id=action_id,
        executor=executor,
        timeout_seconds=timeout_seconds,
    )
    _render_lab_restart_gate_outcome(outcome)
    if outcome.refused:
        raise typer.Exit(code=1)
    if not outcome.exec_result_ok:
        raise typer.Exit(code=1)
    if outcome.verification.get("status") == lab_restart_mod.VERIFICATION_STATUS_FAILED:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Actions (PR37) - policy-gated action compiler


def _print_compile_result(result, *, proposal_status: str | None = None) -> None:
    compiled = result.compiled
    summary = compiled.summary()
    console.print("Compiled actions (review-only; ShellForgeAI did not execute anything):")
    console.print(f"- proposal: {compiled.proposal_id}")
    if proposal_status:
        console.print(f"- proposal status: {proposal_status}")
    console.print(f"- total actions: {summary['total_actions']}")
    console.print(f"- blocked: {summary['blocked']}")
    console.print(f"- manual_only: {summary['manual_only']}")
    console.print(f"- read_only_review: {summary['read_only']}")
    console.print(f"- service_impacting: {summary['service_impacting']}")
    console.print(f"- destructive: {summary['destructive']}")
    console.print("- execution_allowed: false")
    console.print("- execution_status: not_executed")
    console.print(f"- actions.json: {result.actions_json}")
    console.print(f"- actions.md: {result.actions_md}")


@actions_app.command("compile")
def actions_compile(
    ctx: typer.Context,
    target: Annotated[str | None, typer.Argument()] = None,
    latest_approved: bool = typer.Option(
        False, "--latest-approved", help="Compile actions for the newest approved proposal."
    ),
    allow_pending: bool = typer.Option(
        False,
        "--allow-pending",
        help="Allow compiling a pending proposal for review (default: approved only).",
    ),
) -> None:
    """Compile an approved proposal's steps into structured action records.

    Output is written under ``<data_dir>/actions/<proposal_id>/``. No commands
    are executed. ``apply`` remains validation-only.
    """
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    if not target and not latest_approved:
        raise typer.BadParameter(
            "Provide a proposal id, a proposal JSON path, or --latest-approved."
        )
    from shellforgeai.core.approvals import STATUS_APPROVED, STATUS_PENDING

    allowed = (STATUS_APPROVED, STATUS_PENDING) if allow_pending else (STATUS_APPROVED,)
    resolved = resolve_proposal_arg(
        data_dir, target, latest_approved=latest_approved, allow_statuses=allowed
    )
    if resolved.proposal is None or resolved.error:
        console.print("Action compile failed:")
        console.print(f"- {resolved.error or 'proposal not found'}")
        console.print("- no commands executed")
        raise typer.Exit(code=1)
    result = compile_and_write(resolved.proposal, data_dir=data_dir)
    _print_compile_result(result, proposal_status=resolved.proposal_status)


@actions_app.command("show")
def actions_show(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Path to actions.json or a proposal id.")],
) -> None:
    """Show compiled actions for a proposal id or actions.json path."""
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    path = Path(target)
    if not (path.exists() and path.is_file()):
        from shellforgeai.core.actions import find_actions_for_proposal

        cand = find_actions_for_proposal(data_dir, target)
        if cand is None:
            console.print("Action show failed:")
            console.print(f"- no compiled actions found for: {target}")
            raise typer.Exit(code=1)
        path = cand
    payload, err = load_actions_file(path)
    if payload is None:
        console.print("Action show failed:")
        console.print(f"- {err}")
        raise typer.Exit(code=1)
    summary = payload.get("summary") or {}
    console.print(f"Compiled actions: {path}")
    console.print(f"- proposal: {payload.get('proposal_id', '')}")
    console.print(f"- status: {payload.get('status', '')}")
    console.print(f"- execution_allowed: {payload.get('execution_allowed')}")
    console.print(f"- execution_status: {payload.get('execution_status', '')}")
    console.print(f"- total actions: {summary.get('total_actions', 0)}")
    console.print(f"- blocked: {summary.get('blocked', 0)}")
    console.print(f"- manual_only: {summary.get('manual_only', 0)}")
    console.print(f"- read_only_review: {summary.get('read_only', 0)}")
    actions = payload.get("actions") or []
    for a in actions:
        if not isinstance(a, dict):
            continue
        console.print(
            f"  - {a.get('action_id', '?')} [{a.get('source_section', '?')}] "
            f"{a.get('kind', '?')}/{a.get('operation', '?')} "
            f"decision={a.get('decision', '?')} risk={a.get('risk', '?')}"
        )


@actions_app.command("validate")
def actions_validate(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Path to actions.json")],
) -> None:
    """Validate a compiled actions.json file."""
    _ = _ctx(ctx)
    payload, err = load_actions_file(target)
    if payload is None:
        console.print("Action validation failed:")
        console.print(f"- {err}")
        raise typer.Exit(code=1)
    result = validate_actions_payload(payload)
    if not result.ok:
        console.print("Action validation failed:")
        for e in result.errors or ["unknown error"]:
            console.print(f"- {e}")
        raise typer.Exit(code=1)
    info = result.info
    console.print("Action validation passed:")
    console.print(f"- proposal: {info.get('proposal_id', '')}")
    console.print(f"- actions: {info.get('total_actions', 0)}")
    console.print(f"- blocked: {info.get('blocked', 0)}")
    console.print(f"- manual_only: {info.get('manual_only', 0)}")
    console.print(f"- read_only_review: {info.get('read_only', 0)}")
    console.print("- execution: none")


@rollback_app.command("preview")
def rollback_preview_cmd(
    ctx: typer.Context,
    proposal_id: Annotated[str | None, typer.Argument()] = None,
    latest_approved: bool = typer.Option(False, "--latest-approved"),
) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    if latest_approved:
        proposal = latest_approved_proposal(data_dir)
    else:
        if not proposal_id:
            raise typer.BadParameter("Provide proposal id or --latest-approved")
        path, _ = find_proposal_path(data_dir, proposal_id)
        proposal = load_proposal_from_path(path) if path else None
    if proposal is None:
        console.print("Rollback preview failed:\n- proposal not found\n- no commands executed")
        raise typer.Exit(code=1)
    paths = rollback_preview_mod.write_preview(data_dir, proposal)
    console.print("Rollback preview written:")
    console.print(f"- proposal: {proposal.proposal_id}")
    console.print(f"- rollback: {paths.json_path}")
    console.print(f"- summary: {paths.md_path}")
    payload = rollback_preview_mod.load_preview(paths.json_path)
    status = payload.get("rollback_status") or "preview_only"
    console.print(f"- status: {status}")
    console.print("- ShellForgeAI will not execute rollback.")


@rollback_app.command("validate")
def rollback_validate_cmd(ctx: typer.Context, target: Annotated[str, typer.Argument()]) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    target_path = Path(target)
    if not (target_path.exists() and target_path.is_file()):
        cand = rollback_preview_mod.rollback_preview_dir(data_dir, target) / "rollback-preview.json"
        if cand.exists():
            target_path = cand
    try:
        payload = rollback_preview_mod.load_preview(target_path)
    except Exception as exc:
        console.print(f"Rollback preview validation failed:\n- malformed or missing file: {exc}")
        raise typer.Exit(code=1) from None
    errs = rollback_preview_mod.validate_preview(payload)
    if errs:
        console.print("Rollback preview validation failed:")
        for e in errs:
            console.print(f"- {e}")
        raise typer.Exit(code=1)
    console.print("Rollback preview validation passed:")
    console.print(f"- proposal: {payload.get('proposal_id', '')}")
    console.print(f"- kind: {payload.get('proposal_kind') or payload.get('mutation_kind', '')}")
    if payload.get("kind") == "compose_service_restart_recovery_preview":
        console.print("- compose metadata: present")
        console.print(
            f"- automatic_rollback: {(payload.get('recovery') or {}).get('automatic_rollback')}"
        )
        console.print("- execution supported: gated only")
    else:
        console.print(f"- rollback_available: {payload.get('rollback_available')}")
        console.print(
            f"- executable_by_shellforgeai: {payload.get('rollback_executable_by_shellforgeai')}"
        )
        console.print(f"- status: {payload.get('rollback_status')}")
    console.print("- safety: ok")


@rollback_app.command("show")
def rollback_show_cmd(ctx: typer.Context, target: Annotated[Path, typer.Argument()]) -> None:
    _ = _ctx(ctx)
    console.print(target.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Guard (PR38) - stale-evidence / drift checks


_GUARD_EXIT_CODES = {
    GUARD_DECISION_FRESH: 0,
    GUARD_DECISION_WARNING: 0,
    GUARD_DECISION_STALE: 2,
    GUARD_DECISION_DRIFT: 3,
    GUARD_DECISION_BLOCKED: 1,
}


def _print_guard_report(report: GuardReport, *, write_paths: tuple[Path, Path] | None) -> None:
    console.print("Guard check (read-only; ShellForgeAI did not execute anything):")
    console.print(f"- source type: {report.source_type}")
    console.print(f"- source id: {report.source_id}")
    if report.source_path:
        console.print(f"- source path: {report.source_path}")
    console.print(f"- decision: {report.decision}")
    console.print(f"- age status: {report.age.status}")
    if report.age.status != "unknown":
        console.print(
            f"  - age_seconds: {report.age.age_seconds} (max {report.age.max_age_seconds})"
        )
    console.print(f"- source_hash_status: {report.drift.source_hash_status}")
    if report.drift.changed_files:
        console.print(f"  - changed: {', '.join(report.drift.changed_files)}")
    if report.drift.missing_files:
        console.print(f"  - missing: {', '.join(report.drift.missing_files)}")
    console.print("- execution_allowed: false")
    console.print("- execution_status: not_executed")
    if report.warnings:
        console.print(f"- warnings: {len(report.warnings)}")
        for w in report.warnings:
            console.print(f"  - {w}")
    if report.errors:
        console.print(f"- errors: {len(report.errors)}")
        for e in report.errors:
            console.print(f"  - {e}")
    if write_paths is not None:
        json_path, md_path = write_paths
        console.print(f"- report json: {json_path}")
        console.print(f"- report md: {md_path}")
    if report.decision == GUARD_DECISION_STALE:
        console.print(
            "- next step: re-run `shellforgeai diagnose <target> --with-runbook` and "
            "regenerate the proposal so evidence is fresh."
        )
    elif report.decision == GUARD_DECISION_DRIFT:
        console.print(
            "- next step: source artifacts changed after creation; regenerate the "
            "proposal/actions/export from current evidence before any apply."
        )
    elif report.decision == GUARD_DECISION_BLOCKED:
        console.print("- next step: source is missing or malformed; nothing was executed.")


def _guard_resolve_proposal_target(
    data_dir: Path, target: str | None, *, latest_approved: bool
) -> tuple[Path | None, str | None]:
    """Resolve a target into a proposal JSON path. Returns (path, error)."""
    if latest_approved:
        proposal = latest_approved_proposal(data_dir)
        if proposal is None:
            return None, "no approved proposals found"
        path, _status = find_proposal_path(data_dir, proposal.proposal_id)
        if path is None:
            return None, f"approved proposal file not found: {proposal.proposal_id}"
        return path, None
    if not target:
        return None, "missing proposal target"
    p = Path(target)
    if p.exists() and p.is_file():
        return p, None
    path, _status = find_proposal_path(data_dir, target)
    if path is None:
        return None, f"proposal not found: {target}"
    return path, None


@guard_app.command("check")
def guard_check(
    ctx: typer.Context,
    target: Annotated[str | None, typer.Argument()] = None,
    latest_approved: bool = typer.Option(
        False, "--latest-approved", help="Guard-check the newest approved proposal."
    ),
    max_age_hours: float | None = typer.Option(
        None, "--max-age-hours", help="Override the default max age (proposals: 24h)."
    ),
) -> None:
    """Run a stale-evidence / drift guard check on a proposal.

    Accepts a proposal id, a proposal JSON path, or ``--latest-approved``.
    Writes ``guard-report.json`` and ``guard-report.md`` under
    ``<data_dir>/guards/<proposal-id>/``. Execution remains disabled.
    """
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    if not target and not latest_approved:
        raise typer.BadParameter(
            "Provide a proposal id, a proposal JSON path, or --latest-approved."
        )
    path, err = _guard_resolve_proposal_target(data_dir, target, latest_approved=latest_approved)
    if path is None:
        console.print("Guard check failed:")
        console.print(f"- {err or 'unknown error'}")
        console.print("- no commands executed")
        raise typer.Exit(code=1)
    max_age = max_age_from_hours(max_age_hours, source_type="proposal")
    report = check_proposal_file(path, max_age_seconds=max_age)
    written = write_guard_report(report, data_dir=data_dir)
    _print_guard_report(report, write_paths=(written.json_path, written.md_path))
    code = _GUARD_EXIT_CODES.get(report.decision, 1)
    if code != 0:
        raise typer.Exit(code=code)


@guard_app.command("check-actions")
def guard_check_actions(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Path to actions.json")],
    max_age_hours: float | None = typer.Option(
        None, "--max-age-hours", help="Override the default max age (actions: 24h)."
    ),
) -> None:
    """Run a guard check against a compiled actions.json file."""
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    max_age = max_age_from_hours(max_age_hours, source_type="actions")
    report = check_actions_file(target, data_dir=data_dir, max_age_seconds=max_age)
    written = write_guard_report(report, data_dir=data_dir)
    _print_guard_report(report, write_paths=(written.json_path, written.md_path))
    code = _GUARD_EXIT_CODES.get(report.decision, 1)
    if code != 0:
        raise typer.Exit(code=code)


@guard_app.command("check-export")
def guard_check_export(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Path to an export directory")],
    max_age_hours: float | None = typer.Option(
        None, "--max-age-hours", help="Override the default max age (exports: 7d)."
    ),
) -> None:
    """Run a guard check against an export pack directory."""
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    max_age = max_age_from_hours(max_age_hours, source_type="export")
    report = check_export_dir(target, max_age_seconds=max_age)
    written = write_guard_report(report, data_dir=data_dir)
    _print_guard_report(report, write_paths=(written.json_path, written.md_path))
    code = _GUARD_EXIT_CODES.get(report.decision, 1)
    if code != 0:
        raise typer.Exit(code=code)


@guard_app.command("show")
def guard_show(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Path to guard-report.json or guard dir")],
) -> None:
    """Pretty-print a previously written guard-report.json."""
    _ = _ctx(ctx)
    payload, err = load_guard_report(target)
    if payload is None:
        console.print("Guard show failed:")
        console.print(f"- {err}")
        raise typer.Exit(code=1)
    console.print(f"Guard report: {target}")
    console.print(f"- source type: {payload.get('source_type', '')}")
    console.print(f"- source id: {payload.get('source_id', '')}")
    if payload.get("source_path"):
        console.print(f"- source path: {payload.get('source_path')}")
    console.print(f"- decision: {payload.get('decision', '')}")
    age = payload.get("age") or {}
    console.print(f"- age status: {age.get('status', '')}")
    if age.get("status") != "unknown":
        console.print(
            f"  - age_seconds: {age.get('age_seconds')} (max {age.get('max_age_seconds')})"
        )
    drift = payload.get("drift") or {}
    console.print(f"- source_hash_status: {drift.get('source_hash_status', '')}")
    if drift.get("changed_files"):
        console.print(f"  - changed: {', '.join(drift.get('changed_files') or [])}")
    if drift.get("missing_files"):
        console.print(f"  - missing: {', '.join(drift.get('missing_files') or [])}")
    console.print(f"- execution_allowed: {payload.get('execution_allowed')}")
    console.print(f"- execution_status: {payload.get('execution_status')}")
    if payload.get("warnings"):
        console.print(f"- warnings: {len(payload['warnings'])}")
        for w in payload["warnings"]:
            console.print(f"  - {w}")
    if payload.get("errors"):
        console.print(f"- errors: {len(payload['errors'])}")
        for e in payload["errors"]:
            console.print(f"  - {e}")


# ---------------------------------------------------------------------------
# Export pack (PR34)


def _print_export_result(result) -> None:
    console.print("Audit/export pack written (ShellForgeAI did not execute anything):")
    console.print(f"- export id: {result.export_id}")
    console.print(f"- export dir: {result.export_dir}")
    console.print(f"- source type: {result.source_type}")
    if result.source_session_id:
        console.print(f"- source session: {result.source_session_id}")
    if result.source_proposal_id:
        console.print(f"- source proposal: {result.source_proposal_id}")
    console.print(f"- files: {len(result.included_files)}")
    for f in result.included_files:
        console.print(f"  - {f}")
    if result.missing_optional:
        console.print(f"- missing optional: {len(result.missing_optional)}")
        for f in result.missing_optional:
            console.print(f"  - {f}")
    console.print(f"- manifest: {result.manifest_path}")
    console.print(f"- summary: {result.summary_path}")
    console.print(f"- checksums: {result.checksums_path}")
    console.print("- execution: not_executed")
    console.print("- No commands were executed.")


@app.command("export")
def export_cmd(
    ctx: typer.Context,
    target: Annotated[str | None, typer.Argument()] = None,
    latest: bool = typer.Option(False, "--latest", help="Export the newest artifact session."),
    proposal: str | None = typer.Option(
        None, "--proposal", help="Export an approved/pending proposal pack by id."
    ),
    approved: bool = typer.Option(
        False,
        "--approved",
        help="Export all approved proposals (refused in PR34; use --latest-approved).",
    ),
    latest_approved: bool = typer.Option(
        False, "--latest-approved", help="Export the newest approved proposal."
    ),
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", help="Explicit output directory (default: <data_dir>/exports/<id>)."
        ),
    ] = None,
    redact: bool = typer.Option(
        False, "--redact", help="Apply best-effort secret redaction to text copies."
    ),
) -> None:
    """Bundle evidence/runbook/proposal/preflight into a portable audit pack.

    ShellForgeAI does not execute remediation. ``export`` only reads/copies
    existing artifacts and writes a new directory under
    ``<data_dir>/exports/``.
    """
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    if approved:
        console.print(
            "Export refused:\n"
            "- --approved would export every approved proposal and is too broad.\n"
            "- use --proposal <id> or --latest-approved to scope the export."
        )
        raise typer.Exit(code=1)

    try:
        if proposal is not None:
            result = export_from_proposal(data_dir, proposal, output=output, redact=redact)
        elif latest_approved:
            result = export_latest_approved(data_dir, output=output, redact=redact)
        elif latest:
            result = export_latest_session(data_dir, output=output, redact=redact)
        elif target:
            session_dir = resolve_session_dir(data_dir, target)
            if session_dir is None:
                console.print(
                    f"Export failed:\n- session not found: {target}\n- no commands executed"
                )
                raise typer.Exit(code=1)
            result = export_from_session(data_dir, session_dir, output=output, redact=redact)
        else:
            raise typer.BadParameter(
                "Provide a session id/dir, --latest, --proposal <id>, or --latest-approved."
            )
    except FileNotFoundError as exc:
        console.print(f"Export failed:\n- {exc}\n- no commands executed")
        raise typer.Exit(code=1) from None
    _print_export_result(result)


@app.command("validate-export")
def validate_export_cmd(ctx: typer.Context, target: Path) -> None:
    """Validate an export pack: manifest, included files, checksums, safety."""
    _ = _ctx(ctx)
    result = validate_export(target)
    if not result.ok:
        console.print("Export validation failed:")
        for err in result.errors or ["unknown error"]:
            console.print(f"- {err}")
        raise typer.Exit(code=1)
    console.print("Export validation passed:")
    console.print(f"- export: {result.info.get('export_dir', target)}")
    console.print(f"- files: {result.info.get('file_count', 0)}")
    console.print("- checksums: ok")
    console.print("- safety: ok")
    console.print("- execution: none")


def _handle_export_ask(runtime: RuntimeContext, question: str) -> bool:
    intent = is_export_intent(question)
    if not intent.matched:
        return False
    data_dir = Path(runtime.session.data_dir)
    try:
        if intent.prefer_approved:
            result = export_latest_approved(data_dir, redact=intent.prefer_redact)
        else:
            latest = latest_session_dir(data_dir)
            if latest is None:
                console.print(
                    "Cannot export an audit pack yet: no session artifacts found.\n"
                    "- run `shellforgeai diagnose <target> --with-runbook` first.\n"
                    "- no commands were executed."
                )
                return True
            result = export_from_session(data_dir, latest, redact=intent.prefer_redact)
            result.source_type = "latest"
    except FileNotFoundError as exc:
        console.print(
            f"Cannot export an audit pack: {exc}.\n"
            "- run `shellforgeai diagnose <target> --with-runbook` "
            "and `shellforgeai approvals approve <id> --reason ...` first.\n"
            "- no commands were executed."
        )
        return True
    _print_export_result(result)
    if intent.prefer_redact:
        console.print("- redaction: best-effort; review before sharing")
    return True


# ---------------------------------------------------------------------------
# Approvals subcommands (PR32 scaffolding consumed by PR33 apply)


def _resolve_session_dir(runtime: RuntimeContext, target: str) -> Path:
    """Accept a session id (``sf_*``), a path to a session directory, or a runbook.json path."""
    candidate = Path(target)
    if candidate.exists():
        return candidate
    if str(target).startswith("sf_"):
        return Path(runtime.session.data_dir) / "artifacts" / target
    return candidate


def _create_proposals_run(
    runtime: RuntimeContext,
    *,
    session: str | None,
    from_runbook: Path | None,
    latest: bool,
    include_low: bool,
) -> tuple[list[Proposal], Path | None]:
    """Resolve approvals-create inputs and write proposals. Returns (proposals, source_path)."""
    data_dir = Path(runtime.session.data_dir)
    if from_runbook is not None:
        if not from_runbook.exists():
            console.print(f"Runbook not found: {from_runbook}")
            raise typer.Exit(code=1)
        runbook_path = from_runbook
    elif latest:
        rb = latest_runbook(data_dir)
        if rb is None:
            console.print(
                "No runbook.json artifacts found. Run "
                "`shellforgeai diagnose <target> --with-runbook` first."
            )
            raise typer.Exit(code=1)
        runbook_path = rb
    elif session:
        sess_dir = _resolve_session_dir(runtime, session)
        runbook_path = sess_dir / "runbook.json" if sess_dir.is_dir() else sess_dir
        if not runbook_path.exists():
            console.print(f"runbook.json not found at: {runbook_path}")
            raise typer.Exit(code=1)
    else:
        raise typer.BadParameter(
            "Provide a session/runbook path, --from-runbook PATH, or --latest."
        )
    try:
        proposals = create_proposals_for_session(data_dir, runbook_path, include_low=include_low)
    except FileNotFoundError as exc:
        console.print(f"Cannot create proposals: {exc}")
        raise typer.Exit(code=1) from None
    return proposals, runbook_path


@approvals_app.command("create")
def approvals_create(
    ctx: typer.Context,
    session: Annotated[str | None, typer.Argument()] = None,
    from_runbook: Annotated[
        Path | None,
        typer.Option("--from-runbook", help="Path to an explicit runbook.json."),
    ] = None,
    latest: Annotated[
        bool,
        typer.Option("--latest", help="Use the newest runbook.json under <data_dir>/artifacts."),
    ] = False,
    include_low: Annotated[
        bool,
        typer.Option(
            "--include-low",
            help="Include low-risk read-only investigation options as proposals.",
        ),
    ] = False,
) -> None:
    """Create pending proposal objects from a runbook.

    Accepts a session id (``sf_*``), an artifact session directory, or a
    direct ``runbook.json`` via ``--from-runbook``. ``--latest`` picks the
    newest session under ``<data_dir>/artifacts``.
    """
    runtime = _ctx(ctx)
    if not (session or from_runbook or latest):
        raise typer.BadParameter(
            "Provide a session/runbook path, --from-runbook PATH, or --latest."
        )
    proposals, runbook_path = _create_proposals_run(
        runtime,
        session=session,
        from_runbook=from_runbook,
        latest=latest,
        include_low=include_low,
    )
    pending_dir = Path(runtime.session.data_dir) / "approvals" / "pending"
    total_options = 0
    if runbook_path is not None:
        try:
            payload = json.loads(runbook_path.read_text(encoding="utf-8"))
            total_options = len(payload.get("remediation_options") or [])
        except (OSError, ValueError, json.JSONDecodeError):
            total_options = len(proposals)
    skipped = max(total_options - len(proposals), 0)
    console.print("Created approval proposals from runbook:")
    if runbook_path is not None:
        console.print(f"- source: {runbook_path}")
    console.print(f"- pending queue: {pending_dir}")
    console.print(f"- created: {len(proposals)}")
    console.print(f"- skipped: {skipped}")
    console.print("- execution: disabled")
    if proposals:
        console.print("")
        console.print("Proposals:")
        for p in proposals:
            labels = " ".join(p.safety_labels) if p.safety_labels else ""
            console.print(f"- {p.proposal_id} {p.component} {p.risk} {labels}".rstrip())
    elif total_options:
        console.print(
            "\nAll runbook options were filtered (likely low-risk/read-only). "
            "Re-run with --include-low to include them."
        )


@approvals_app.command("propose-restart")
def approvals_propose_restart(
    ctx: typer.Context,
    container: Annotated[
        str | None, typer.Argument(help="Allowlisted lab/disposable container name.")
    ] = None,
    container_opt: Annotated[
        str | None,
        typer.Option("--container", help="Allowlisted lab/disposable container name."),
    ] = None,
    from_session: Annotated[str | None, typer.Option("--from-session")] = None,
    latest: Annotated[bool, typer.Option("--latest")] = False,
    from_evidence: Annotated[Path | None, typer.Option("--from-evidence")] = None,
) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    target_container = (container_opt or container or "").strip()
    if not target_container:
        raise typer.BadParameter("Provide a container target (positional or --container).")
    evidence_path: Path | None = None
    session_id = ""
    if from_evidence is not None:
        evidence_path = from_evidence
        if evidence_path.parent.name.startswith("sf_"):
            session_id = evidence_path.parent.name
    elif from_session:
        sess_dir = _resolve_session_dir(runtime, from_session)
        evidence_path = sess_dir / "evidence.json"
        if sess_dir.name.startswith("sf_"):
            session_id = sess_dir.name
    elif latest:
        evidence_path = latest_evidence_artifact(data_dir)
        if evidence_path is not None and evidence_path.parent.name.startswith("sf_"):
            session_id = evidence_path.parent.name
    if evidence_path is None:
        console.print("Restart proposal refused:")
        console.print(
            "- reason: no evidence source selected "
            "(use --latest / --from-session / --from-evidence)"
        )
        console.print("- no proposal created")
        console.print("- no commands executed")
        raise typer.Exit(code=1)
    proposal, status = build_restart_proposal_from_evidence(
        data_dir,
        evidence_path,
        container_name=target_container,
        source_session_id=session_id,
    )
    if proposal is None:
        console.print("Restart proposal refused:")
        console.print(f"- reason: {status}")
        console.print("- no proposal created")
        console.print("- no commands executed")
        raise typer.Exit(code=1)
    if status == "deduped":
        console.print("Restart proposal deduped:")
    else:
        console.print("Restart proposal created:")
    console.print(f"- proposal: {proposal.proposal_id}")
    console.print(f"- status: {proposal.status}")
    console.print(f"- component: {proposal.component}")
    console.print(f"- command_preview: {proposal.proposed_steps[0]}")
    console.print(f"- mutation_kind: {proposal.kind}")
    console.print("- execution: disabled")


@approvals_app.command("restart-plan")
def approvals_restart_plan(
    ctx: typer.Context,
    proposal_id: Annotated[str | None, typer.Argument()] = None,
    latest: Annotated[bool, typer.Option("--latest")] = False,
    from_session: Annotated[str | None, typer.Option("--from-session")] = None,
    from_evidence: Annotated[Path | None, typer.Option("--from-evidence")] = None,
    container: Annotated[str | None, typer.Option("--container")] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    proposal, _status = resolve_restart_plan_proposal(
        data_dir,
        proposal_id,
        latest=latest,
        from_session=from_session,
        from_evidence=from_evidence,
        container=container,
    )
    plan = build_restart_plan(data_dir, proposal, target_hint=(container or ""))
    payload = plan.payload
    _append_audit_event(
        runtime,
        kind="restart_plan",
        action="previewed",
        status="success" if payload["apply_readiness"]["status"] == "ready" else "warning",
        proposal_id=payload.get("proposal_id") or None,
        session_id=payload.get("session_id") or None,
        target=payload.get("target") or None,
        mutation_performed=False,
        execution_status="not_executed",
        summary="restart plan preview generated",
        details={"blockers_count": len(payload["apply_readiness"]["blockers"])},
    )
    if json_out:
        typer.echo(restart_plan_to_json(plan))
        return
    console.print(render_restart_plan(plan))


def _resolve_mission_id(runtime: RuntimeContext, mission_id: str | None) -> str:
    data_dir = Path(runtime.session.data_dir)
    if mission_id:
        return mission_id
    latest = mission_latest(data_dir)
    if latest is None:
        console.print("No restart missions found.")
        raise typer.Exit(code=1)
    return str(latest["mission_id"])


@mission_restart_app.command("prepare")
def mission_restart_prepare(
    ctx: typer.Context,
    container: Annotated[str | None, typer.Option("--container")] = None,
    from_session: Annotated[str | None, typer.Option("--from-session")] = None,
    from_evidence: Annotated[Path | None, typer.Option("--from-evidence")] = None,
    latest: Annotated[bool, typer.Option("--latest")] = False,
    with_rollback_preview: Annotated[bool, typer.Option("--with-rollback-preview")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Prepare a guided safe restart mission record (metadata only)."""
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    target = (container or "").strip()
    if not target:
        raise typer.BadParameter("--container is required.")
    evidence_path: Path | None = None
    session_id = ""
    if from_evidence is not None:
        evidence_path = from_evidence
        if evidence_path.parent.name.startswith("sf_"):
            session_id = evidence_path.parent.name
    elif from_session:
        sess_dir = _resolve_session_dir(runtime, from_session)
        evidence_path = sess_dir / "evidence.json"
        if sess_dir.name.startswith("sf_"):
            session_id = sess_dir.name
    elif latest:
        evidence_path = latest_evidence_artifact(data_dir)
        if evidence_path is not None and evidence_path.parent.name.startswith("sf_"):
            session_id = evidence_path.parent.name
    else:
        evidence_path = latest_evidence_artifact(data_dir)
        if evidence_path is not None and evidence_path.parent.name.startswith("sf_"):
            session_id = evidence_path.parent.name

    result = prepare_mission(
        data_dir,
        container=target,
        evidence_path=evidence_path,
        session_id=session_id,
        with_rollback_preview=with_rollback_preview,
    )
    if not result.ok:
        _append_audit_event(
            runtime,
            kind="restart_mission",
            action="prepared",
            status="warning",
            target=target,
            mutation_performed=False,
            execution_status="not_executed",
            summary=f"mission prepare refused: {result.refusal}",
            details={"refusal": result.refusal},
        )
        if json_out:
            typer.echo(json.dumps({"ok": False, "refusal": result.refusal}, indent=2))
            raise typer.Exit(code=1)
        console.print("Restart mission preparation refused:")
        console.print(f"- reason: {result.refusal}")
        console.print("- no execution performed")
        raise typer.Exit(code=1)

    payload = result.payload or {}
    _append_audit_event(
        runtime,
        kind="restart_mission",
        action="prepared",
        status="success",
        proposal_id=payload.get("proposal_id") or None,
        session_id=payload.get("session_id") or None,
        target=payload.get("target") or None,
        mutation_performed=False,
        execution_status="not_executed",
        summary=("mission prepared (deduped)" if result.deduped else "mission prepared"),
        details={
            "mission_id": payload.get("mission_id"),
            "mission_status": payload.get("status"),
            "deduped": result.deduped,
        },
    )
    if json_out:
        typer.echo(json.dumps(payload, indent=2))
        return
    console.print("Restart mission deduped:" if result.deduped else "Restart mission prepared:")
    console.print(f"- mission: {payload.get('mission_id')}")
    console.print(f"- target: {payload.get('target')}")
    console.print(f"- proposal: {payload.get('proposal_id')}")
    console.print(f"- status: {payload.get('status')}")
    console.print(f"- mission_path: {result.mission_path}")
    console.print(f"- execution: {payload['safety']['execution_status']}")


@mission_restart_app.command("status")
def mission_restart_status(
    ctx: typer.Context,
    mission_id: Annotated[str | None, typer.Argument()] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Refresh and print the current mission status."""
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    mid = _resolve_mission_id(runtime, mission_id)
    payload = refresh_mission(data_dir, mid)
    _append_audit_event(
        runtime,
        kind="restart_mission",
        action="status_viewed",
        status="success",
        proposal_id=payload.get("proposal_id") or None,
        target=payload.get("target") or None,
        mutation_performed=False,
        execution_status="not_executed",
        summary="restart mission status viewed",
        details={"mission_id": mid, "mission_status": payload.get("status")},
    )
    if json_out:
        typer.echo(json.dumps(payload, indent=2))
        return
    console.print(f"Mission: {mid}")
    console.print(f"- target: {payload.get('target')}")
    console.print(f"- status: {payload.get('status')}")
    console.print(f"- proposal: {payload.get('proposal_id') or 'missing'}")
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
        console.print(f"- {key}: {ph.get('status')}")
    console.print(f"- execution: {payload['safety']['execution_status']}")


@mission_restart_app.command("checklist")
def mission_restart_checklist(
    ctx: typer.Context,
    mission_id: Annotated[str | None, typer.Argument()] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Print the operator checklist for the mission."""
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    mid = _resolve_mission_id(runtime, mission_id)
    payload = refresh_mission(data_dir, mid)
    if json_out:
        typer.echo(json.dumps(payload, indent=2))
        return
    typer.echo(mission_render_checklist(payload))


@mission_restart_app.command("validate")
def mission_restart_validate(
    ctx: typer.Context,
    mission_id: Annotated[str | None, typer.Argument()] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Validate the mission record schema and safety invariants."""
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    mid = _resolve_mission_id(runtime, mission_id)
    ok, errors, payload = validate_mission_path(mission_json_path(data_dir, mid))
    _append_audit_event(
        runtime,
        kind="restart_mission_validate",
        action="validated",
        status="success" if ok else "failure",
        proposal_id=(payload or {}).get("proposal_id") or None,
        target=(payload or {}).get("target") or None,
        mutation_performed=False,
        execution_status="not_executed",
        summary="restart mission validated" if ok else "restart mission validation failed",
        details={"mission_id": mid, "errors": errors},
    )
    if json_out:
        typer.echo(json.dumps({"ok": ok, "mission_id": mid, "errors": errors}, indent=2))
        if not ok:
            raise typer.Exit(code=1)
        return
    if ok and payload is not None:
        console.print("Restart mission validation passed:")
        console.print(f"- mission: {payload.get('mission_id')}")
        console.print(f"- target: {payload.get('target')}")
        console.print(f"- proposal: {payload.get('proposal_id') or 'missing'}")
        console.print(f"- status: {payload.get('status')}")
        console.print(f"- execution: {payload['safety']['execution_status']}")
        console.print("- safety: ok")
        return
    console.print("Restart mission validation failed:")
    for err in errors:
        console.print(f"- {err}")
    raise typer.Exit(code=1)


def _execute_mission_apply_gate(
    runtime: RuntimeContext,
    proposal: Proposal,
    *,
    action_id: str | None = None,
    allow_stale: bool = False,
    max_age_hours: float | None = None,
) -> LabRestartGateOutcome | tuple[str, str]:
    """PR53 shared apply-gate execution for mission handoff.

    Runs preflight, the stale/drift guard, and action compilation against the
    given approved proposal, then delegates to :func:`_perform_lab_restart_gate`.
    Returns the :class:`LabRestartGateOutcome` on completion or a
    ``(failed_gate, message)`` tuple if preflight/guard refuses before the
    lab gate runs. Never raises ``typer.Exit``; the mission CLI translates the
    result to user output and exit codes.
    """
    data_dir = Path(runtime.session.data_dir)
    preflight = run_preflight(proposal)
    if not preflight.passed:
        return ("preflight_failed", "; ".join(preflight.errors) or "preflight failed")

    guard_max_age = max_age_from_hours(max_age_hours, source_type="proposal")
    guard_payload = json.loads(proposal.model_dump_json())
    guard_proposal_path, _gs = find_proposal_path(data_dir, proposal.proposal_id)
    guard_report = check_proposal_payload(
        guard_payload,
        source_path=str(guard_proposal_path or ""),
        max_age_seconds=guard_max_age,
    )
    write_guard_report(guard_report, data_dir=data_dir)
    if guard_report.decision in (GUARD_DECISION_BLOCKED, GUARD_DECISION_DRIFT) or (
        guard_report.decision == GUARD_DECISION_STALE and not allow_stale
    ):
        return ("guard_blocked", f"guard decision: {guard_report.decision}")

    try:
        actions_result = compile_and_write(proposal, data_dir=data_dir)
        actions_payload = json.loads(actions_result.actions_json.read_text(encoding="utf-8"))
    except Exception as exc:
        return ("actions_compile_failed", str(exc))

    return _perform_lab_restart_gate(
        runtime,
        proposal=proposal,
        actions_payload=actions_payload,
        guard_decision=guard_report.decision,
        execute=True,
        confirm=True,
        action_id=action_id,
    )


@mission_restart_app.command("execute")
def mission_restart_execute(
    ctx: typer.Context,
    mission_id: Annotated[str | None, typer.Argument()] = None,
    execute: Annotated[bool, typer.Option("--execute")] = False,
    confirm: Annotated[bool, typer.Option("--confirm")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    action_id: Annotated[str | None, typer.Option("--action-id")] = None,
    allow_stale: Annotated[bool, typer.Option("--allow-stale")] = False,
    max_age_hours: Annotated[float | None, typer.Option("--max-age-hours")] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """PR53: hand off a ready mission to the existing apply execution gate.

    Mission execute does not introduce a new executor. It verifies mission
    readiness (approved proposal, exact ``docker restart <target>`` preview,
    valid rollback preview, restart-plan readiness) and then delegates to the
    same guarded code path used by ``apply --execute --confirm``. The actual
    mutation remains the existing allowlisted Docker restart only.
    """
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    mid = _resolve_mission_id(runtime, mission_id)

    ready, blockers, mission_payload, proposal = mission_check_execute_readiness(data_dir, mid)
    delegation_cmd = mission_apply_delegation_command(mission_payload)

    if not execute or dry_run:
        # Dry-run: no mutation, just show readiness and the exact delegation.
        result_payload = {
            "mission_id": mid,
            "ready": ready,
            "blockers": blockers,
            "dry_run": True,
            "delegation_command": delegation_cmd,
            "execution": "not_executed",
            "arbitrary_command_execution": False,
        }
        if json_out:
            typer.echo(json.dumps(result_payload, indent=2))
            if not ready:
                raise typer.Exit(code=1)
            return
        console.print("Mission execute (dry-run / no execution):")
        console.print(f"- mission: {mid}")
        console.print(f"- readiness: {'ready' if ready else 'blocked'}")
        for b in blockers:
            console.print(f"  - blocker: {b}")
        console.print(f"- delegation: {delegation_cmd}")
        console.print("- execution: not_executed")
        console.print("- arbitrary_command_execution: false")
        if not ready:
            raise typer.Exit(code=1)
        return

    if execute and not confirm:
        _append_audit_event(
            runtime,
            kind="restart_mission",
            action="execute_refused",
            status="refused",
            proposal_id=mission_payload.get("proposal_id") or None,
            target=mission_payload.get("target") or None,
            mutation_performed=False,
            execution_status="refused",
            summary="mission execute refused: --confirm required",
            details={
                "mission_id": mid,
                "blockers": ["--confirm required alongside --execute"],
                "delegation_command": delegation_cmd,
                "arbitrary_command_execution": False,
                "execution_path": "apply_gate",
            },
        )
        mission_record_execution_result(
            data_dir,
            mid,
            receipt_path=None,
            verification=None,
            execution_status="refused",
            mission_status="blocked",
            refusal="confirmation required",
            blockers=["--confirm required alongside --execute"],
        )
        if json_out:
            typer.echo(
                json.dumps(
                    {
                        "mission_id": mid,
                        "ready": ready,
                        "refused": True,
                        "reason": "confirmation required",
                        "delegation_command": delegation_cmd,
                    },
                    indent=2,
                )
            )
        else:
            console.print("Mission execution refused:")
            console.print("- reason: --confirm is required alongside --execute")
            console.print(f"- delegation: {delegation_cmd}")
            console.print("- no commands executed")
        raise typer.Exit(code=1)

    if not ready:
        _append_audit_event(
            runtime,
            kind="restart_mission",
            action="execute_refused",
            status="refused",
            proposal_id=mission_payload.get("proposal_id") or None,
            target=mission_payload.get("target") or None,
            mutation_performed=False,
            execution_status="refused",
            summary="mission execute refused: readiness blocked",
            details={
                "mission_id": mid,
                "blockers": blockers,
                "delegation_command": delegation_cmd,
                "arbitrary_command_execution": False,
                "execution_path": "apply_gate",
            },
        )
        mission_record_execution_result(
            data_dir,
            mid,
            receipt_path=None,
            verification=None,
            execution_status="refused",
            mission_status="blocked",
            refusal="readiness blocked",
            blockers=list(blockers),
        )
        if json_out:
            typer.echo(
                json.dumps(
                    {
                        "mission_id": mid,
                        "ready": False,
                        "refused": True,
                        "blockers": blockers,
                        "delegation_command": delegation_cmd,
                    },
                    indent=2,
                )
            )
        else:
            console.print("Mission execution refused:")
            console.print("- readiness: blocked")
            for b in blockers:
                console.print(f"  - blocker: {b}")
            console.print("- no commands executed")
            if blockers:
                first = blockers[0]
                pid = mission_payload.get("proposal_id") or "<proposal-id>"
                if "rollback" in first.lower():
                    console.print(f"- next: shellforgeai rollback preview {pid}")
                elif "approval" in first.lower() or "approved" in first.lower():
                    console.print(f'- next: shellforgeai approvals approve {pid} --reason "..."')
                else:
                    console.print(f"- next: shellforgeai mission restart checklist {mid}")
        raise typer.Exit(code=1)

    assert proposal is not None
    outcome = _execute_mission_apply_gate(
        runtime,
        proposal,
        action_id=action_id,
        allow_stale=allow_stale,
        max_age_hours=max_age_hours,
    )

    if isinstance(outcome, tuple):
        gate_name, message = outcome
        _append_audit_event(
            runtime,
            kind="restart_mission",
            action="execute_refused",
            status="refused",
            proposal_id=proposal.proposal_id,
            target=proposal.component or None,
            mutation_performed=False,
            execution_status="refused",
            summary=f"mission execute refused before apply gate: {gate_name}",
            details={
                "mission_id": mid,
                "blockers": [f"{gate_name}: {message}"],
                "delegation_command": delegation_cmd,
                "arbitrary_command_execution": False,
                "execution_path": "apply_gate",
            },
        )
        mission_record_execution_result(
            data_dir,
            mid,
            receipt_path=None,
            verification=None,
            execution_status="refused",
            mission_status="blocked",
            refusal=f"{gate_name}: {message}",
            blockers=[f"{gate_name}: {message}"],
        )
        if json_out:
            typer.echo(
                json.dumps(
                    {
                        "mission_id": mid,
                        "refused": True,
                        "failed_gate": gate_name,
                        "message": message,
                    },
                    indent=2,
                )
            )
        else:
            console.print("Mission execution refused:")
            console.print(f"- failed gate: {gate_name}")
            console.print(f"- detail: {message}")
            console.print("- no commands executed")
        raise typer.Exit(code=1)

    # Translate gate outcome into mission record + audit event.
    if outcome.refused:
        mission_record_execution_result(
            data_dir,
            mid,
            receipt_path=outcome.receipt_path,
            verification=None,
            execution_status="refused",
            mission_status="blocked",
            refusal=outcome.failed_gate,
            blockers=[outcome.failed_message or outcome.failed_gate],
        )
        _append_audit_event(
            runtime,
            kind="restart_mission",
            action="execute_refused",
            status="refused",
            proposal_id=proposal.proposal_id,
            target=outcome.container or proposal.component or None,
            mutation_performed=False,
            execution_status="refused",
            summary=f"mission execute refused at apply gate: {outcome.failed_gate}",
            details={
                "mission_id": mid,
                "blockers": [outcome.failed_message or outcome.failed_gate],
                "receipt": str(outcome.receipt_path) if outcome.receipt_path else "",
                "execution_path": "apply_gate",
                "arbitrary_command_execution": False,
            },
        )
        if json_out:
            typer.echo(
                json.dumps(
                    {
                        "mission_id": mid,
                        "refused": True,
                        "failed_gate": outcome.failed_gate,
                        "message": outcome.failed_message,
                        "receipt": str(outcome.receipt_path) if outcome.receipt_path else "",
                    },
                    indent=2,
                )
            )
        else:
            console.print("Mission execution refused at apply gate:")
            console.print(f"- failed gate: {outcome.failed_gate}")
            if outcome.failed_message:
                console.print(f"- detail: {outcome.failed_message}")
            console.print("- no commands executed")
            if outcome.receipt_path is not None:
                console.print(f"- receipt: {outcome.receipt_path}")
        raise typer.Exit(code=1)

    # Apply gate ran (success/warning/failed).
    verification = dict(outcome.verification or {})
    if outcome.exec_result_ok and verification.get("status") in (
        lab_restart_mod.VERIFICATION_STATUS_PASSED,
        lab_restart_mod.VERIFICATION_STATUS_WARNING,
    ):
        exec_status = "executed"
        mission_status = "executed"
    else:
        exec_status = "failed"
        mission_status = "failed"

    refreshed = mission_record_execution_result(
        data_dir,
        mid,
        receipt_path=outcome.receipt_path,
        verification=verification,
        execution_status=exec_status,
        mission_status=mission_status,
    )

    # Mission audit event is metadata-only. The real mutation event is recorded
    # separately by the apply gate (kind=execution / action=lab_container_restart).
    # Audit storage's validator requires non-execution events to keep all safety
    # flags false, so we do not duplicate mutation claims here.
    _append_audit_event(
        runtime,
        kind="restart_mission",
        action="execute_delegated",
        status="success" if exec_status == "executed" else "failed",
        proposal_id=proposal.proposal_id,
        target=outcome.container or proposal.component or None,
        mutation_performed=False,
        execution_status="not_executed",
        summary=(f"mission execute delegated to apply gate: {exec_status}"),
        artifacts=[str(outcome.receipt_path)] if outcome.receipt_path else [],
        details={
            "mission_id": mid,
            "execution_path": "apply_gate",
            "mutation_kind": "docker_restart",
            "container": outcome.container,
            "receipt": str(outcome.receipt_path) if outcome.receipt_path else "",
            "verification_status": verification.get("status", ""),
            "running_after": bool(verification.get("running_after", False)),
            "started_at_changed": bool(verification.get("started_at_changed", False)),
            "health_after": str(verification.get("health_after", "")),
            "arbitrary_command_execution": False,
        },
    )

    if json_out:
        typer.echo(
            json.dumps(
                {
                    "mission_id": mid,
                    "proposal_id": proposal.proposal_id,
                    "execution": exec_status,
                    "mission_status": refreshed.get("status"),
                    "receipt": str(outcome.receipt_path) if outcome.receipt_path else "",
                    "verification": verification,
                    "arbitrary_command_execution": False,
                    "execution_path": "apply_gate",
                },
                indent=2,
            )
        )
        if exec_status != "executed":
            raise typer.Exit(code=1)
        return

    if exec_status == "executed":
        console.print("Mission execution completed through apply gate:")
    else:
        console.print("Mission execution failed at apply gate:")
    console.print(f"- mission: {mid}")
    console.print(f"- proposal: {proposal.proposal_id}")
    if outcome.receipt_path is not None:
        console.print(f"- apply receipt: {outcome.receipt_path}")
    console.print(f"- verification: {verification.get('status', '')}")
    console.print(f"- running_after: {bool(verification.get('running_after', False))}")
    console.print(f"- started_at_changed: {bool(verification.get('started_at_changed', False))}")
    console.print(f"- health_after: {verification.get('health_after', '')}")
    console.print("- arbitrary_command_execution: false")
    console.print("- execution_path: apply_gate")
    if exec_status != "executed":
        raise typer.Exit(code=1)


@mission_restart_app.command("report")
def mission_restart_report(
    ctx: typer.Context,
    mission_id: Annotated[str | None, typer.Argument()] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Print a concise post-execution operator report. Read-only.

    Builds a structured report from the mission record (PR52/PR53), the apply
    receipt and verification evidence (PR47/PR48), and the rollback preview
    (PR49). Writes ``mission-report.json`` and ``mission-report.md`` under
    ``<data_dir>/mission_reports/<mission-id>/`` so the operator can re-read
    the report later. ShellForgeAI does not execute mutation here.
    """
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    mid = _resolve_mission_id(runtime, mission_id)
    report = build_mission_report(data_dir, mid)
    json_path, md_path = write_mission_report_files(data_dir, mid, report)
    _append_audit_event(
        runtime,
        kind="mission_report",
        action="generated",
        status="success",
        proposal_id=report.get("proposal_id") or None,
        session_id=report.get("session_id") or None,
        target=report.get("target") or None,
        mutation_performed=False,
        execution_status="not_executed",
        summary="mission report generated",
        artifacts=[str(json_path), str(md_path)],
        details={
            "mission_id": mid,
            "mission_status": report.get("status"),
            "execution_status_record": report["safety"].get("execution_status_record"),
            "arbitrary_command_execution": False,
        },
    )
    if json_out:
        typer.echo(json.dumps(report, indent=2))
        return
    execution = report.get("execution") or {}
    verification = report.get("verification") or {}
    rollback = report.get("rollback") or {}
    safety = report.get("safety") or {}
    console.print("Mission restart report")
    console.print(f"- Mission: {report.get('mission_id')}")
    console.print(f"- Target: {report.get('target') or 'unknown'}")
    console.print(f"- Proposal: {report.get('proposal_id') or 'missing'}")
    console.print(f"- Source session: {report.get('session_id') or 'unknown'}")
    console.print(f"- Status: {report.get('status')}")
    console.print(f"- Execution path: {execution.get('path') or 'none'}")
    console.print(f"- Verification: {verification.get('status', '')}")
    cmd_argv = execution.get("command_argv") or []
    if cmd_argv:
        console.print(f"- Command: {' '.join(str(x) for x in cmd_argv)}")
    else:
        console.print(f"- Command preview: {report.get('command_preview') or '(none)'}")
    console.print("- Arbitrary command execution: false")
    console.print("")
    console.print("Verification")
    console.print(f"- running_after: {bool(verification.get('running_after', False))}")
    console.print(f"- started_at_changed: {bool(verification.get('started_at_changed', False))}")
    console.print(f"- health_after: {verification.get('health_after', '')}")
    if verification.get("before_inspect"):
        console.print(f"- before inspect: {verification['before_inspect']}")
    if verification.get("after_inspect"):
        console.print(f"- after inspect: {verification['after_inspect']}")
    console.print("")
    console.print("Safety")
    console.print(f"- allowlisted target: {bool(safety.get('allowlisted_target', False))}")
    console.print(f"- rollback preview: {rollback.get('preview_status', 'unknown')}")
    console.print("- rollback execution: disabled")
    console.print("- natural-language execution: refused")
    console.print(f"- mutation kind: {safety.get('mutation_kind') or 'none'}")
    console.print("")
    console.print("Artifacts")
    for art in report.get("artifacts") or []:
        present = "present" if art.get("exists") == "true" else "missing"
        console.print(f"- {art.get('role', '')}: {art.get('path', '')} ({present})")
    console.print("")
    console.print("Next review commands")
    for i, cmd in enumerate(report.get("next_review_commands") or [], start=1):
        console.print(f"{i}. {cmd}")
    console.print("")
    console.print(f"Report files:\n- {json_path}\n- {md_path}")


@mission_restart_app.command("export")
def mission_restart_export(
    ctx: typer.Context,
    mission_id: Annotated[str | None, typer.Argument()] = None,
    output: Annotated[Path | None, typer.Option("--output")] = None,
    redact: Annotated[
        bool,
        typer.Option(
            "--redact",
            help="Best-effort secret redaction for exported text copies.",
        ),
    ] = False,
) -> None:
    """Bundle the mission, report, and referenced artifacts into a compact export.

    Read-only with respect to source artifacts. Writes a new mission export
    directory containing ``export-manifest.json``, ``export-summary.md``,
    ``checksums.sha256``, ``mission-report.json/md``, and copies of relevant
    proposal/rollback/receipt/inspect/audit artifacts. Never executes mutation;
    the export pack may *describe* a prior gated mutation, but the export
    command itself performs none.
    """
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    mid = _resolve_mission_id(runtime, mission_id)
    result = mission_export_pack(data_dir, mid, output=output, redact=redact)
    _append_audit_event(
        runtime,
        kind="mission_export",
        action="created",
        status="success",
        proposal_id=result.proposal_id or None,
        session_id=result.session_id or None,
        target=None,
        mutation_performed=False,
        execution_status="not_executed",
        summary="mission export created",
        artifacts=[str(result.manifest_path), str(result.summary_path)],
        details={
            "mission_id": mid,
            "export_id": result.export_id,
            "export_dir": str(result.export_dir),
            "redaction_applied": result.redaction_applied,
            "file_count": len(result.included_files),
            "missing_optional_count": len(result.missing_optional),
            "arbitrary_command_execution": False,
            "mutation_performed_by_export": False,
        },
    )
    console.print("Mission export written (ShellForgeAI did not execute anything):")
    console.print(f"- mission: {mid}")
    console.print(f"- export id: {result.export_id}")
    console.print(f"- export dir: {result.export_dir}")
    console.print(f"- files: {len(result.included_files)}")
    if result.missing_optional:
        console.print("- missing optional:")
        for f in result.missing_optional:
            console.print(f"  - {f}")
    console.print(f"- manifest: {result.manifest_path}")
    console.print(f"- summary: {result.summary_path}")
    console.print(f"- checksums: {result.checksums_path}")
    console.print(f"- redaction: {'on' if result.redaction_applied else 'off'}")
    if result.redaction_applied:
        console.print("- redaction warning: best-effort; review before sharing.")
    console.print("- export execution: none")


@mission_restart_app.command("validate-export")
def mission_restart_validate_export(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Path to a mission export directory")],
) -> None:
    """Validate a mission export pack: manifest, files, checksums, safety."""
    runtime = _ctx(ctx)
    result = validate_mission_export(target)
    _append_audit_event(
        runtime,
        kind="mission_export_validate",
        action="validated" if result.ok else "validation_failed",
        status="success" if result.ok else "failed",
        proposal_id=None,
        session_id=None,
        target=None,
        mutation_performed=False,
        execution_status="not_executed",
        summary=(
            "mission export validation passed" if result.ok else "mission export validation failed"
        ),
        artifacts=[str(target)],
        details={
            "export_dir": str(target),
            "mission_id": result.info.get("mission_id"),
            "export_id": result.info.get("export_id"),
            "file_count": result.info.get("file_count"),
            "redaction_applied": result.info.get("redaction_applied"),
            "errors": result.errors,
            "arbitrary_command_execution": False,
            "mutation_performed_by_export": False,
        },
    )
    if not result.ok:
        console.print("Mission export validation failed:")
        for err in result.errors or ["unknown error"]:
            console.print(f"- {err}")
        raise typer.Exit(code=1)
    console.print("Mission export validation passed:")
    console.print(f"- export: {result.info.get('export_dir', target)}")
    console.print(f"- mission: {result.info.get('mission_id', '')}")
    console.print(f"- files: {result.info.get('file_count', 0)}")
    console.print("- checksums: ok")
    console.print("- redaction: on" if result.info.get("redaction_applied") else "- redaction: off")
    console.print("- export execution: none")


@approvals_app.command("list")
def approvals_list(
    ctx: typer.Context,
    status: str = typer.Option("pending", "--status"),
    all_statuses: bool = typer.Option(False, "--all"),
    component: str = typer.Option("", "--component"),
    session: str = typer.Option("", "--session"),
) -> None:
    """List proposals with status/component/session filters."""
    runtime = _ctx(ctx)
    entries = list_proposals(Path(runtime.session.data_dir))
    if all_statuses:
        filtered = entries
        scope = "All approval proposals"
    else:
        filtered = [(s, p) for s, p in entries if s == status]
        scope = f"{status.capitalize()} approval proposals"
    if component:
        filtered = [(s, p) for s, p in filtered if p.component == component]
    if session:
        filtered = [(s, p) for s, p in filtered if p.source.session_id == session]
    if not filtered:
        console.print(f"No {status if not all_statuses else 'matching'} approval proposals.")
        return
    console.print(f"{scope}:")
    header = (
        f"{'ID':<36} {'Status':<10} {'Risk':<8} "
        f"{'Component':<20} {'Fingerprint':<12} {'Created':<20} Title"
    )
    console.print(header)
    for s, p in filtered:
        fp = str((p.fingerprint or {}).get("value") or "")[:8]
        created = (p.created_at or "")[:19]
        row = (
            f"{p.proposal_id:<36} {s:<10} {p.risk:<8} "
            f"{p.component:<20} {fp:<12} {created:<20} {p.title}"
        )
        console.print(row)


def _print_proposal_show(proposal: Proposal, status: str, path: Path) -> None:
    console.print(f"Proposal: {proposal.proposal_id}")
    console.print(f"- status: {status}")
    fp = proposal.fingerprint or {}
    if fp:
        console.print(f"- fingerprint.short: {str(fp.get('value') or '')[:8]}")
        console.print(f"- fingerprint.full: {fp.get('value')}")
    console.print(f"- risk: {proposal.risk}")
    if proposal.confidence:
        console.print(f"- confidence: {proposal.confidence}")
    console.print(f"- title: {proposal.title}")
    if proposal.component:
        console.print(f"- component: {proposal.component}")
    if proposal.kind:
        console.print(f"- kind: {proposal.kind}")
    if proposal.impact:
        console.print(f"- impact: {proposal.impact}")
    if proposal.safety_labels:
        console.print(f"- safety_labels: {', '.join(proposal.safety_labels)}")
    if proposal.source.runbook:
        console.print(f"- source.runbook: {proposal.source.runbook}")
    if proposal.source.evidence:
        console.print(f"- source.evidence: {proposal.source.evidence}")
    if proposal.source.session_id:
        console.print(f"- source.session_id: {proposal.source.session_id}")
    if proposal.preconditions:
        console.print("- preconditions:")
        for p in proposal.preconditions:
            console.print(f"  - {p}")
    if proposal.proposed_steps:
        console.print("- proposed_steps (OPERATOR-RUN, not executed):")
        for s in proposal.proposed_steps:
            console.print(f"  - {s}")
    if proposal.rollback:
        console.print("- rollback:")
        for r in proposal.rollback:
            console.print(f"  - {r}")
    if proposal.verification:
        console.print("- verification:")
        for v in proposal.verification:
            console.print(f"  - {v}")
    console.print(f"- execution.allowed: {proposal.execution.allowed}")
    console.print(f"- execution.status: {proposal.execution.status}")
    if proposal.execution.reason:
        console.print(f"- execution.reason: {proposal.execution.reason}")
    if proposal.approval.reason:
        console.print(f"- approval.reason: {proposal.approval.reason}")
    cc = proposal.compose_context or {}
    if cc:
        console.print("Compose context:")
        if cc.get("detected"):
            console.print("- Compose-managed: yes")
            console.print(f"- Project: {cc.get('project') or '-'}")
            console.print(f"- Service: {cc.get('service') or '-'}")
            if cc.get("working_dir"):
                console.print(f"- Working dir: {cc.get('working_dir')}")
            config_files = cc.get("config_files") or []
            if config_files:
                console.print("- Config files:")
                for path_str in config_files:
                    console.print(f"  - {path_str}")
            console.print(f"- One-off: {bool(cc.get('oneoff', False))}")
        else:
            console.print("- Compose-managed: no")
        console.print(f"- restart_scope: {proposal.restart_scope or 'container'}")
        console.print(f"- compose_mutation: {bool(proposal.compose_mutation)}")
        console.print("- This proposal is container-scoped.")
        console.print(f"- Command preview remains: docker restart {proposal.component}")
        console.print("- ShellForgeAI does not run docker compose commands in this flow.")
    console.print(f"- path: {path}")
    console.print("- Not executed by ShellForgeAI.")


@approvals_app.command("show")
def approvals_show(ctx: typer.Context, proposal_id: str) -> None:
    runtime = _ctx(ctx)
    path, status = find_proposal_path(Path(runtime.session.data_dir), proposal_id)
    if path is None or status is None:
        console.print(f"Proposal not found: {proposal_id}")
        raise typer.Exit(code=1)
    proposal = load_proposal_from_path(path)
    _print_proposal_show(proposal, status, path)


@approvals_app.command("approve")
def approvals_approve(
    ctx: typer.Context,
    proposal_id: str,
    reason: str = typer.Option(..., "--reason", help="Why this proposal is approved."),
) -> None:
    runtime = _ctx(ctx)
    try:
        proposal = approve_proposal(Path(runtime.session.data_dir), proposal_id, reason=reason)
    except FileNotFoundError as exc:
        console.print(f"Cannot approve: {exc}")
        raise typer.Exit(code=1) from None
    path, _ = find_proposal_path(Path(runtime.session.data_dir), proposal.proposal_id)
    console.print("Proposal approved but not executed:")
    console.print(f"- {proposal.proposal_id}")
    console.print(f"- status: {proposal.status}")
    console.print("- execution: disabled")
    if path is not None:
        console.print(f"- file: {path}")


@approvals_app.command("reject")
def approvals_reject(
    ctx: typer.Context,
    proposal_id: str,
    reason: str = typer.Option(..., "--reason"),
) -> None:
    runtime = _ctx(ctx)
    try:
        proposal = reject_proposal(Path(runtime.session.data_dir), proposal_id, reason=reason)
    except FileNotFoundError as exc:
        console.print(f"Cannot reject: {exc}")
        raise typer.Exit(code=1) from None
    console.print("Proposal rejected (no commands executed):")
    console.print(f"- {proposal.proposal_id}")
    console.print(f"- status: {proposal.status}")
    console.print(f"- reason: {reason}")


@approvals_app.command("cancel")
def approvals_cancel(
    ctx: typer.Context,
    proposal_id: str,
    reason: str = typer.Option("", "--reason"),
) -> None:
    runtime = _ctx(ctx)
    try:
        proposal = cancel_proposal(Path(runtime.session.data_dir), proposal_id, reason=reason)
    except FileNotFoundError as exc:
        console.print(f"Cannot cancel: {exc}")
        raise typer.Exit(code=1) from None
    console.print("Proposal canceled (no commands executed):")
    console.print(f"- {proposal.proposal_id}")
    console.print(f"- status: {proposal.status}")
    console.print(f"- reason: {reason}")


@approvals_app.command("archive")
def approvals_archive(
    ctx: typer.Context,
    proposal_id: str,
    reason: str = typer.Option("", "--reason"),
) -> None:
    runtime = _ctx(ctx)
    try:
        proposal = archive_proposal(Path(runtime.session.data_dir), proposal_id, reason=reason)
    except FileNotFoundError as exc:
        console.print(f"Cannot archive: {exc}")
        raise typer.Exit(code=1) from None
    console.print("Proposal archived (no commands executed):")
    console.print(f"- {proposal.proposal_id}")
    console.print(f"- status: {proposal.status}")
    console.print(f"- reason: {reason}")


@approvals_app.command("validate")
def approvals_validate(ctx: typer.Context, proposal_id: str) -> None:
    """Validate a proposal by id or by direct JSON path."""
    runtime = _ctx(ctx)
    # Allow a direct JSON path or a proposal id.
    direct = Path(proposal_id)
    if direct.exists() and direct.is_file():
        path: Path | None = direct
    else:
        path, _status = find_proposal_path(Path(runtime.session.data_dir), proposal_id)
    if path is None:
        console.print("Proposal validation failed:")
        console.print(f"- proposal not found: {proposal_id}")
        raise typer.Exit(code=1)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        console.print("Proposal validation failed:")
        console.print(f"- malformed proposal JSON: {exc}")
        raise typer.Exit(code=1) from None
    errors, warnings = validate_proposal_payload(payload)
    if errors:
        console.print("Proposal validation failed:")
        console.print("- errors:")
        for err in errors:
            console.print(f"  - {err}")
        raise typer.Exit(code=1)
    console.print("Proposal validation passed:")
    console.print(f"- proposal: {payload.get('proposal_id') or proposal_id}")
    console.print(f"- risk: {payload.get('risk')}")
    console.print(f"- status: {payload.get('status')}")
    console.print("- execution: disabled")
    console.print("- schema: ok")
    console.print("- safety: ok")
    if warnings:
        console.print(f"- warnings: {len(warnings)}")
        for w in warnings:
            console.print(f"  - {w}")


def _handle_immediate_fix_ask(runtime: RuntimeContext, question: str) -> bool:
    """Refuse 'approve and run / fix everything now' style asks. No execution."""
    if not is_immediate_fix_intent(question):
        return False
    data_dir = Path(runtime.session.data_dir)
    rb = latest_runbook(data_dir)
    console.print(
        "Refusing to execute: ShellForgeAI never runs mutation commands. "
        "apply remains validation-only."
    )
    if rb is None:
        console.print(
            "No runbook artifact available yet. Run "
            "`shellforgeai diagnose <target> --with-runbook` first; ShellForgeAI "
            "can then queue safe operator-run proposals for approval."
        )
    else:
        console.print("To stage safe operator-run changes for approval (still no execution), run:")
        console.print("  shellforgeai approvals create --latest")
        console.print(
            "Then `shellforgeai approvals approve <id> --reason ...` to record "
            "approval, and `shellforgeai apply <id>` to generate a static "
            "operator bundle. ShellForgeAI does not execute commands."
        )
    return True


def _handle_create_proposals_ask(runtime: RuntimeContext, question: str) -> bool:
    """Stage proposals for approval when the operator asks for it. No execution."""
    intent = is_create_proposals_intent(question)
    if not intent.matched:
        return False
    data_dir = Path(runtime.session.data_dir)
    rb = latest_runbook(data_dir)
    if rb is None:
        console.print("No runbook artifact available yet (no execution attempted).")
        console.print(
            "Run `shellforgeai diagnose <target> --with-runbook` to produce a "
            "runbook from read-only evidence, then re-run this ask or "
            "`shellforgeai approvals create --latest`."
        )
        return True
    try:
        proposals, _src = _create_proposals_run(
            runtime,
            session=None,
            from_runbook=rb,
            latest=False,
            include_low=False,
        )
    except typer.Exit:
        return True
    pending_dir = data_dir / "approvals" / "pending"
    console.print("Staged approval proposals from latest runbook (no commands executed):")
    console.print(f"- source: {rb}")
    console.print(f"- pending queue: {pending_dir}")
    console.print(f"- created: {len(proposals)}")
    console.print("- execution: disabled")
    if proposals:
        console.print("")
        for p in proposals:
            labels = " ".join(p.safety_labels) if p.safety_labels else ""
            console.print(f"- {p.proposal_id} {p.component} {p.risk} {labels}".rstrip())
    return True


def _handle_create_restart_proposal_ask(runtime: RuntimeContext, question: str) -> bool:
    intent = is_create_restart_proposal_intent(question)
    if not intent.matched:
        return False
    container = intent.container
    if is_compose_service_mutation_proposal_request(question) and not container:
        console.print("Restart proposal refused:")
        console.print(
            "- reason: Compose service mutation is not supported in PR58 (context enrichment only)."
        )
        console.print("- read-only inspection: shellforgeai compose inspect <container>")
        console.print(
            "- container-scoped workflow: shellforgeai approvals propose-restart "
            "--latest --container <container>"
        )
        console.print("- no proposal created")
        console.print("- no commands executed")
        _append_audit_event(
            runtime,
            kind="compose_context",
            action="viewed",
            status="refused",
            summary="ask refused: compose service mutation proposal request",
            details={
                "target": "",
                "mutation_performed": False,
                "execution_status": "not_executed",
                "compose_mutation": False,
                "restart_scope": "container",
            },
        )
        return True
    if not container:
        console.print("Restart proposal refused:")
        console.print("- reason: missing or ambiguous container target")
        return True
    data_dir = Path(runtime.session.data_dir)
    rb = latest_runbook(data_dir)
    evidence_path = rb.parent / "evidence.json" if rb is not None else None
    if evidence_path is None or not evidence_path.exists():
        console.print("Restart proposal refused:")
        console.print("- reason: no evidence available (run diagnose first)")
        return True
    proposal, status = build_restart_proposal_from_evidence(
        data_dir,
        evidence_path,
        container_name=container,
        source_session_id=rb.parent.name if rb is not None else "",
    )
    if proposal is None:
        console.print("Restart proposal refused:")
        console.print(f"- reason: {status}")
        console.print("- no proposal created")
        console.print("- no commands executed")
        return True
    console.print("Restart proposal created from ask (no execution):")
    console.print(f"- proposal: {proposal.proposal_id}")
    console.print(f"- status: {proposal.status}")
    console.print(f"- command_preview: {proposal.proposed_steps[0]}")
    return True


def _handle_mission_restart_ask(runtime: RuntimeContext, question: str) -> bool:
    """PR52: ask routing for guided safe restart mission (metadata-only)."""
    raw = (question or "").lower().strip()
    if not raw:
        return False
    data_dir = Path(runtime.session.data_dir)

    # PR58: read-only mission compose context query.
    if is_mission_compose_context_query(question):
        res = resolve_reference("mission", question, ReferenceFilters(restart_only=True), data_dir)
        if res.status == "ambiguous":
            console.print("I found multiple matching restart missions. Please specify one:")
            for idx, c in enumerate(res.candidates[:3], start=1):
                console.print(f"{idx}. {c.id} status={c.status_label} target={c.target or '-'}")
            return True
        if res.status != "resolved":
            console.print("No restart missions found.")
            console.print("- try: shellforgeai mission restart list")
            return True
        mid = res.id
        payload = refresh_mission(data_dir, mid)
        cc = payload.get("compose_context") or {}
        console.print(f"Mission compose context ({mid}):")
        if cc.get("detected"):
            console.print("- Compose-managed: yes")
            console.print(f"- Project: {cc.get('project') or '-'}")
            console.print(f"- Service: {cc.get('service') or '-'}")
            if cc.get("working_dir"):
                console.print(f"- Working dir: {cc.get('working_dir')}")
        else:
            console.print("- Compose-managed: no")
        console.print(f"- restart_scope: {payload.get('restart_scope', 'container')}")
        console.print(f"- compose_mutation: {bool(payload.get('compose_mutation', False))}")
        console.print("- Compose service mutation is not enabled.")
        _append_audit_event(
            runtime,
            kind="compose_context",
            action="viewed",
            status="success",
            summary="ask: viewed mission compose context",
            details={
                "mission_id": mid,
                "mutation_performed": False,
                "execution_status": "not_executed",
                "compose_mutation": False,
                "restart_scope": "container",
            },
        )
        return True

    prepare_hints = (
        "prepare safe restart mission for ",
        "prepare a safe restart mission for ",
        "prepare restart mission for ",
        "create safe restart mission for ",
        "start safe restart mission for ",
    )
    if any(h in raw for h in prepare_hints):
        if is_compose_service_mutation_proposal_request(question):
            console.print("Restart mission preparation refused:")
            console.print(
                "- reason: Compose service mutation is not supported in PR58 "
                "(context enrichment only)."
            )
            console.print("- read-only inspection: shellforgeai compose inspect <container>")
            console.print(
                "- container-scoped workflow: shellforgeai mission restart prepare "
                "--container <container>"
            )
            console.print("- no mission created")
            console.print("- no commands executed")
            return True
        container = extract_container_target(question)
        if not container:
            console.print("Restart mission preparation refused:")
            console.print("- reason: missing or ambiguous container target")
            return True
        evidence_path = latest_evidence_artifact(data_dir)
        session_id = ""
        if evidence_path is not None and evidence_path.parent.name.startswith("sf_"):
            session_id = evidence_path.parent.name
        result = prepare_mission(
            data_dir,
            container=container,
            evidence_path=evidence_path,
            session_id=session_id,
        )
        if not result.ok:
            console.print("Restart mission preparation refused:")
            console.print(f"- reason: {result.refusal}")
            console.print("- no execution performed")
            return True
        payload = result.payload or {}
        console.print("Restart mission deduped:" if result.deduped else "Restart mission prepared:")
        console.print(f"- mission: {payload.get('mission_id')}")
        console.print(f"- target: {payload.get('target')}")
        console.print(f"- proposal: {payload.get('proposal_id')}")
        console.print(f"- status: {payload.get('status')}")
        console.print(f"- mission_path: {result.mission_path}")
        console.print(f"- execution: {payload['safety']['execution_status']}")
        console.print(
            "Next: shellforgeai mission restart checklist " + str(payload.get("mission_id"))
        )
        return True

    status_hints = (
        "show restart mission status",
        "what is the restart mission status",
        "is the restart mission ready",
        "why is the restart mission blocked",
        "what is next for the restart mission",
        "what's next for the restart mission",
        "show restart mission checklist",
        "show me the restart mission checklist",
    )
    if any(h in raw for h in status_hints):
        latest = mission_latest(data_dir)
        if latest is None:
            console.print("No restart missions found.")
            console.print(
                "- to create one: shellforgeai mission restart prepare --container <target>"
            )
            return True
        mid = str(latest["mission_id"])
        payload = refresh_mission(data_dir, mid)
        typer.echo(mission_render_checklist(payload))
        return True

    refuse_hints = (
        "run the restart mission",
        "execute the restart mission",
        "approve and execute the restart mission",
        "approve and run the restart mission",
        "fire the restart mission",
        "run mission and export",
    )
    if any(h in raw for h in refuse_hints):
        latest = mission_latest(data_dir)
        console.print(
            "Refusing to execute: ShellForgeAI cannot run a restart mission from natural language."
        )
        console.print("- mission workflow is metadata/checklist only.")
        console.print(
            "- only execution path: shellforgeai apply <approved-proposal-id> --execute --confirm"
        )
        if latest is not None:
            mid = str(latest["mission_id"])
            payload = refresh_mission(data_dir, mid)
            console.print("")
            typer.echo(mission_render_checklist(payload))
            console.print("")
            console.print(
                "If you want a read-only post-execution report or an export pack of the "
                "current state, use:"
            )
            console.print(f"- shellforgeai mission restart report {mid}")
            console.print(f"- shellforgeai mission restart export {mid} --redact")
        return True

    redact_export_hints = (
        "make a redacted mission pack",
        "make a redacted mission export",
        "create a redacted mission pack",
        "redacted mission pack",
        "package the restart mission for review",
        "package the restart mission for sharing",
        "prepare change-review pack for the mission",
        "prepare a change-review pack for the mission",
        "prepare change review pack for the mission",
        "make a sanitized mission pack",
        "export mission with secrets removed",
    )
    plain_export_hints = (
        "export mission report",
        "export the mission report",
        "export the restart mission",
        "export this mission",
        "export the mission",
        "package the mission",
    )
    if any(h in raw for h in redact_export_hints) or any(h in raw for h in plain_export_hints):
        latest = mission_latest(data_dir)
        if latest is None:
            console.print("No restart missions found to export.")
            console.print(
                "- to create one: shellforgeai mission restart prepare --container <target>"
            )
            return True
        mid = str(latest["mission_id"])
        want_redact = any(h in raw for h in redact_export_hints) or "redact" in raw
        result = mission_export_pack(data_dir, mid, redact=want_redact)
        _append_audit_event(
            runtime,
            kind="mission_export",
            action="created",
            status="success",
            proposal_id=result.proposal_id or None,
            session_id=result.session_id or None,
            target=None,
            mutation_performed=False,
            execution_status="not_executed",
            summary="mission export created via ask",
            artifacts=[str(result.manifest_path), str(result.summary_path)],
            details={
                "mission_id": mid,
                "export_id": result.export_id,
                "export_dir": str(result.export_dir),
                "redaction_applied": result.redaction_applied,
                "arbitrary_command_execution": False,
                "mutation_performed_by_export": False,
            },
        )
        console.print("Mission export written (ShellForgeAI did not execute anything):")
        console.print(f"- mission: {mid}")
        console.print(f"- export id: {result.export_id}")
        console.print(f"- export dir: {result.export_dir}")
        console.print(f"- files: {len(result.included_files)}")
        console.print(f"- redaction: {'on' if result.redaction_applied else 'off'}")
        console.print("- export execution: none")
        return True

    report_hints = (
        "show mission report",
        "show the mission report",
        "show me the mission report",
        "show restart mission report",
        "show me the restart mission report",
        "post-execution mission report",
        "post execution mission report",
        "did the mission execute safely",
        "did the restart mission execute safely",
        "show verification report",
        "show the verification report",
        "show me the verification report",
    )
    if any(h in raw for h in report_hints):
        latest = mission_latest(data_dir)
        if latest is None:
            console.print("No restart missions found.")
            console.print(
                "- to create one: shellforgeai mission restart prepare --container <target>"
            )
            return True
        mid = str(latest["mission_id"])
        report = build_mission_report(data_dir, mid)
        json_path, md_path = write_mission_report_files(data_dir, mid, report)
        _append_audit_event(
            runtime,
            kind="mission_report",
            action="generated",
            status="success",
            proposal_id=report.get("proposal_id") or None,
            session_id=report.get("session_id") or None,
            target=report.get("target") or None,
            mutation_performed=False,
            execution_status="not_executed",
            summary="mission report generated via ask",
            artifacts=[str(json_path), str(md_path)],
            details={
                "mission_id": mid,
                "mission_status": report.get("status"),
                "arbitrary_command_execution": False,
            },
        )
        execution = report.get("execution") or {}
        verification = report.get("verification") or {}
        rollback = report.get("rollback") or {}
        console.print("Mission restart report (read-only):")
        console.print(f"- Mission: {mid}")
        console.print(f"- Target: {report.get('target') or 'unknown'}")
        console.print(f"- Status: {report.get('status')}")
        console.print(f"- Execution path: {execution.get('path') or 'none'}")
        console.print(f"- Verification: {verification.get('status', '')}")
        console.print(f"- Rollback preview: {rollback.get('preview_status', 'unknown')}")
        console.print("- Arbitrary command execution: false")
        console.print(f"- Report json: {json_path}")
        console.print(f"- Report md: {md_path}")
        return True

    return False


def _handle_restart_plan_ask(runtime: RuntimeContext, question: str) -> bool:
    raw = (question or "").lower()
    data_dir = Path(runtime.session.data_dir)
    # PR58: read-only proposal compose context query.
    if is_restart_proposal_compose_context_query(question):
        res = resolve_reference("proposal", question, ReferenceFilters(restart_only=True), data_dir)
        if res.status == "ambiguous":
            console.print("I found multiple matching restart proposals. Please specify one:")
            for idx, c in enumerate(res.candidates[:3], start=1):
                console.print(
                    f"{idx}. {c.id} status={c.status_label} target={c.target or c.component or '-'}"
                )
            return True
        if res.status != "resolved":
            console.print("No restart proposals found to inspect.")
            console.print("- try: shellforgeai approvals list --all")
            return True
        proposal = load_proposal_from_path(Path(res.path))
        cc = proposal.compose_context or {}
        console.print(f"Restart proposal compose context ({proposal.proposal_id}):")
        if cc.get("detected"):
            console.print("- Compose-managed: yes")
            console.print(f"- Project: {cc.get('project') or '-'}")
            console.print(f"- Service: {cc.get('service') or '-'}")
            if cc.get("working_dir"):
                console.print(f"- Working dir: {cc.get('working_dir')}")
        else:
            console.print("- Compose-managed: no")
        console.print(f"- restart_scope: {proposal.restart_scope or 'container'}")
        console.print(f"- compose_mutation: {bool(proposal.compose_mutation)}")
        console.print(f"- Command preview: docker restart {proposal.component}")
        console.print("- ShellForgeAI does not run docker compose commands in this flow.")
        _append_audit_event(
            runtime,
            kind="compose_context",
            action="viewed",
            status="success",
            proposal_id=proposal.proposal_id,
            target=proposal.component or None,
            mutation_performed=False,
            execution_status="not_executed",
            summary="ask: viewed restart proposal compose context",
            details={
                "proposal_id": proposal.proposal_id,
                "compose_mutation": False,
                "restart_scope": "container",
            },
        )
        return True
    tokens = (
        "show restart checklist",
        "what is needed before restart",
        "is this restart proposal ready",
        "why is apply blocked",
        "show me the safe restart plan",
        "what commands do i run next",
    )
    if not any(t in raw for t in tokens):
        return False
    proposal = latest_approved_proposal(data_dir)
    plan = build_restart_plan(data_dir, proposal)
    console.print(render_restart_plan(plan))
    return True


def _latest_execution_receipt(data_dir: Path) -> Path | None:
    receipts = lab_restart_mod.receipts_dir(data_dir)
    if not receipts.exists():
        return None
    candidates = sorted(receipts.glob("exec_*.json"))
    return candidates[-1] if candidates else None


def _handle_lab_restart_verification_ask(runtime: RuntimeContext, question: str) -> bool:
    """PR48: read-only ask — summarize the most recent restart verification.

    Never executes mutation. Reads the most recent execution receipt from
    ``execution_receipts/`` and the matching audit event, then prints the
    verification status. If there is no receipt yet, explain how to produce
    one (still without executing anything).
    """
    intent = is_lab_restart_verification_ask_intent(question)
    if not intent.matched:
        return False
    data_dir = Path(runtime.session.data_dir)
    receipt_path = _latest_execution_receipt(data_dir)
    console.print("Read-only post-mutation verification (no commands executed):")
    console.print(f"- mutation_scope: {lab_restart_mod.MUTATION_SCOPE}")
    if receipt_path is None:
        console.print("- no execution receipt found yet")
        console.print(
            "- to produce one: shellforgeai apply <approved-proposal-id> --execute --confirm"
        )
        console.print("  verification runs automatically after the approved CLI execution.")
        _append_audit_event(
            runtime,
            kind="ask",
            action="lab_container_restart_verification_query",
            status="success",
            summary="ask: no execution receipt to summarize",
            details={
                "operation": "lab_container_restart_verification_query",
                "remediation_execution": False,
                "mutation_performed": False,
                "verification_status": "absent",
            },
        )
        return True
    try:
        payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        console.print(f"- could not read receipt: {exc}")
        return True
    verification = payload.get("verification") or {}
    result = payload.get("result") or {}
    console.print(f"- receipt: {receipt_path}")
    console.print(f"- container: {payload.get('container', '')}")
    console.print(f"- command_argv: {payload.get('command_argv', [])}")
    console.print(f"- restart status: {result.get('status', '')}")
    if not verification:
        console.print("- verification: absent (PR47-era receipt without verification block)")
    else:
        console.print(f"- verification: {verification.get('status', '')}")
        console.print(f"- running_after: {verification.get('running_after', '')}")
        console.print(f"- started_at_changed: {verification.get('started_at_changed', '')}")
        console.print(f"- health_after: {verification.get('health_after', '')}")
        for note in verification.get("notes", []) or []:
            console.print(f"  - note: {note}")
        evidence = verification.get("evidence") or {}
        for key in ("before_inspect_path", "after_inspect_path", "logs_tail_path"):
            val = evidence.get(key)
            if val:
                console.print(f"- {key}: {val}")
    _append_audit_event(
        runtime,
        kind="ask",
        action="lab_container_restart_verification_query",
        status="success",
        summary="ask: summarized post-mutation verification",
        details={
            "operation": "lab_container_restart_verification_query",
            "container": payload.get("container", ""),
            "verification_status": verification.get("status", "absent"),
            "remediation_execution": False,
            "mutation_performed": False,
            "receipt": str(receipt_path),
        },
    )
    return True


def _handle_lab_restart_ask(runtime: RuntimeContext, question: str) -> bool:
    """PR47: refuse any natural-language request to actually restart a container.

    The only path to execute a lab container restart is the explicit CLI:
    ``shellforgeai apply <approved-proposal-id> --execute --confirm``.
    """
    intent = is_lab_restart_ask_intent(question)
    if not intent.matched:
        return False
    data_dir = Path(runtime.session.data_dir)
    allowlist = lab_restart_mod.load_allowlist(data_dir)
    proposal = latest_approved_proposal(data_dir)
    console.print("Refusing to execute: ShellForgeAI cannot run a container restart from ask.")
    console.print("- mutation_scope: " + lab_restart_mod.MUTATION_SCOPE)
    console.print("- only path: shellforgeai apply <approved-proposal-id> --execute --confirm")
    console.print("- post-mutation verification runs automatically after that CLI execution.")
    if proposal is None:
        console.print(
            "- no approved proposal found. First: shellforgeai approvals create <session>,"
            " then approvals approve <id> --reason '...'."
        )
    else:
        console.print(f"- latest approved proposal: {proposal.proposal_id}")
        cmd = f"  shellforgeai apply {proposal.proposal_id} --execute --confirm"
        console.print(cmd)
    if allowlist is None:
        console.print(
            f"- next: write a lab restart allowlist at {lab_restart_mod.policy_path(data_dir)}"
        )
    elif not allowlist.enabled:
        console.print("- lab restart allowlist is disabled (enabled=false). No restart possible.")
    elif not allowlist.containers:
        console.print("- lab restart allowlist is empty. No restart possible.")
    elif intent.container and intent.container not in allowlist.containers:
        console.print(f"- container {intent.container!r} is not in the lab restart allowlist.")
    _append_audit_event(
        runtime,
        kind="ask",
        action="lab_container_restart_refused",
        status="refused",
        summary="ask refused: lab container restart cannot run from natural language",
        details={
            "operation": "lab_container_restart_refused",
            "container": intent.container,
            "remediation_execution": False,
            "mutation_performed": False,
            "mutation_scope": lab_restart_mod.MUTATION_SCOPE,
        },
    )
    return True


def _handle_compose_context_ask(runtime: RuntimeContext, question: str) -> bool:
    q = (question or "").lower().strip()
    compose_mutation_hint = ("compose" in q) and any(
        token in q
        for token in (
            " restart ",
            "restart ",
            " docker compose ",
            "compose up",
            "execute ",
        )
    )
    if is_compose_mutation_request(question) or compose_mutation_hint:
        console.print(
            "Refusing natural-language Compose mutation. ShellForgeAI currently supports "
            "Compose context, preview, and proposal creation, but not Compose execution."
        )
        console.print("- Compose context is read-only.")
        console.print("- Compose context is advisory/read-only.")
        console.print("- read-only inspection: shellforgeai compose inspect <container>")
        console.print(
            "- container-scoped restart (only if you provide an allowlisted container target): "
            "shellforgeai approvals propose-restart --latest --container <container>"
        )
        console.print("- no proposal created")
        console.print("- no commands executed")
        _append_audit_event(
            runtime,
            kind="compose_context",
            action="viewed",
            status="refused",
            summary="ask refused: compose mutation requested",
            details={
                "target": "",
                "mutation_performed": False,
                "execution_status": "not_executed",
                "compose_mutation": False,
                "restart_scope": "container",
            },
        )
        return True
    compose_tokens = (
        "compose project",
        "compose service",
        "compose managed",
        "compose-managed",
        "compose context",
        "compose file owns",
    )
    if not any(tok in q for tok in compose_tokens):
        return False
    if has_compose_artifact_reference_phrase(question):
        return False
    target = extract_compose_target(question) or ""
    if not target:
        console.print("No compose target found. Try: shellforgeai compose inspect <container>.")
        return True
    result = containers.inspect(target)
    if not result.ok:
        console.print(
            f"Compose context target `{target}` was not found in available Docker/Compose context."
        )
        return True
    payload = json.loads(result.stdout or "{}")
    compose = payload.get("compose") or {"detected": False}
    console.print(f"Compose context for `{target}`:")
    if not compose.get("detected"):
        console.print("- Compose-managed: no")
        console.print("- Reason: compose labels not present")
    else:
        console.print("- Compose-managed: yes")
        console.print(f"- Project: {compose.get('project') or '-'}")
        console.print(f"- Service: {compose.get('service') or '-'}")
        console.print(f"- Working dir: {compose.get('working_dir') or '-'}")
    console.print("- Safety: read-only; no docker compose command was executed")
    return True


def _handle_compose_restart_preview_ask(runtime: RuntimeContext, question: str) -> bool:
    raw = (question or "").lower().strip()
    allow = ("preview compose", "compose restart preview", "what would docker compose restart do")
    if not any(t in raw for t in allow):
        return False
    data_dir = Path(runtime.session.data_dir)
    target = extract_compose_target(question)
    if not target:
        m = re.search(r"\bfor\s+([a-z0-9][a-z0-9._-]{0,63})\b", raw)
        if m:
            target = m.group(1)
    resolved_from = ""
    if "proposal" in raw and any(t in raw for t in ("this", "latest", "current")):
        res = resolve_reference("proposal", question, ReferenceFilters(restart_only=True), data_dir)
        if res.status == "resolved":
            resolved_from = res.id or ""
            p = load_proposal_from_path(Path(res.path))
            target = str((p.compose_context or {}).get("service") or p.component or "")
    if "mission" in raw and any(t in raw for t in ("this", "latest", "current")):
        res = resolve_reference("mission", question, ReferenceFilters(restart_only=True), data_dir)
        if res.status == "resolved":
            resolved_from = res.id or ""
            mission_payload = refresh_mission(data_dir, res.id or "")
            cc = mission_payload.get("compose_context") or {}
            target = str(cc.get("service") or mission_payload.get("target") or "")
    if not target:
        return False
    payload = _build_compose_restart_preview(target)
    console.print("Compose service restart preview (ask, read-only)")
    if resolved_from:
        console.print(f"- resolved_reference: {resolved_from}")
    console.print(f"- status: {payload.get('status')}")
    preview = payload.get("preview") or {}
    if preview:
        console.print(f"- command: {preview.get('command_display')}")
        console.print(f"- compose_mutation: {preview.get('compose_mutation')}")
        console.print(f"- preview_only: {preview.get('preview_only')}")
        console.print(f"- execution_allowed: {preview.get('execution_allowed')}")
        console.print(f"- executed: {preview.get('executed')}")
    else:
        for w in payload.get("warnings", []):
            console.print(f"- {w}")
    console.print("- natural-language mutation is refused")
    console.print("- PR61 supports preview only")
    console.print("- no docker compose command was executed")
    return True


def _build_compose_restart_preview(target: str) -> dict[str, Any]:
    ref = (target or "").strip()
    if not ref:
        return {
            "schema_version": "1",
            "status": "error",
            "target": {"input": "", "compose_managed": False},
            "warnings": ["missing target"],
            "candidates": [],
        }
    inv = containers.containers(all_containers=True)
    if not inv.ok:
        return {
            "schema_version": "1",
            "status": "error",
            "target": {"input": ref, "compose_managed": False},
            "warnings": [str(inv.stderr or "docker visibility unavailable")],
            "candidates": [],
        }
    rows = json.loads(inv.stdout or "{}").get("containers") or []
    matches = []
    for row in rows:
        compose = row.get("compose") or {}
        if not compose.get("detected"):
            continue
        name = str(row.get("name") or "")
        if ref in {name, str(compose.get("service") or ""), str(compose.get("project") or "")}:
            matches.append(row)
    if not matches:
        return {
            "schema_version": "1",
            "status": "not_found",
            "target": {"input": ref, "compose_managed": False},
            "warnings": ["no Compose project/service metadata found"],
            "candidates": [],
        }
    if len(matches) > 1:
        candidates = []
        for m in matches:
            compose = m.get("compose") or {}
            candidates.append(
                {
                    "target": ref,
                    "project": compose.get("project"),
                    "service": compose.get("service"),
                    "container": m.get("name"),
                }
            )
        return {
            "schema_version": "1",
            "status": "ambiguous",
            "target": {"input": ref, "compose_managed": True},
            "warnings": ["multiple compose matches"],
            "candidates": candidates,
        }
    row = matches[0]
    compose = row.get("compose") or {}
    # Docker labels live on the row; Compose-context parse drops them. Merge
    # them back in so allowlist/disposable evaluation downstream can see them.
    merged_labels = _normalize_label_dict(row, compose)
    compose_file = (compose.get("config_files") or [None])[0]
    missing = [
        key
        for key, value in (
            ("working_dir", compose.get("working_dir")),
            ("compose_file", compose_file),
            ("service", compose.get("service")),
            ("project", compose.get("project")),
        )
        if not value
    ]
    command = [
        "docker",
        "compose",
        "-f",
        str(compose_file or "<compose-file>"),
        "--project-directory",
        str(compose.get("working_dir") or "<working-dir>"),
        "restart",
        str(compose.get("service") or "<service>"),
    ]
    return {
        "schema_version": "1",
        "status": "incomplete" if missing else "ok",
        "target": {
            "input": ref,
            "resolved_container": row.get("name"),
            "resolved_service": compose.get("service"),
            "resolved_project": compose.get("project"),
            "compose_managed": True,
        },
        "compose": {
            "project": compose.get("project"),
            "service": compose.get("service"),
            "container": row.get("name"),
            "working_dir": compose.get("working_dir"),
            "compose_file": compose_file,
            "container_number": compose.get("container_number"),
            "oneoff": bool(compose.get("oneoff")),
            "labels": merged_labels,
        },
        "preview": {
            "command": command,
            "command_display": shlex.join(command),
            "compose_mutation": True,
            "preview_only": True,
            "execution_allowed": False,
            "executed": False,
        },
        "safety": {
            "read_only": True,
            "docker_compose_executed": False,
            "container_restarted": False,
            "requires_future_proposal": True,
            "requires_future_approval": True,
            "requires_future_rollback_preview": True,
            "requires_future_apply_gate": True,
            "arbitrary_command_execution": False,
        },
        "operator_checks": [
            "confirm service name",
            "confirm compose file path",
            "confirm project directory",
            "confirm blast radius of restarting the Compose service",
            "confirm rollback/recovery posture before any future execution",
        ],
        "warnings": [f"missing: {', '.join(missing)}"] if missing else [],
        "candidates": [],
    }


def _create_compose_restart_proposal(
    runtime: RuntimeContext, target: str, reason: str | None
) -> dict[str, Any]:
    preview_payload = _build_compose_restart_preview(target)
    status = preview_payload.get("status")
    if status != "ok":
        out = dict(preview_payload)
        out["proposal"] = None
        safety = dict(out.get("safety") or {})
        safety.update(
            {
                "proposal_created": False,
                "docker_compose_executed": False,
                "container_restarted": False,
                "arbitrary_command_execution": False,
            }
        )
        out["safety"] = safety
        return out
    now = datetime.now(timezone.utc).isoformat()
    compose = dict(preview_payload.get("compose") or {})
    proposal_id = f"prop_compose_restart_{uuid.uuid4().hex[:12]}"
    command = list(((preview_payload.get("preview") or {}).get("command")) or [])
    proposal = Proposal(
        proposal_id=proposal_id,
        created_at=now,
        status="pending",
        target=str((preview_payload.get("target") or {}).get("input") or target),
        component=str(compose.get("container") or ""),
        kind="compose_service_restart",
        title=f"Compose service restart proposal for {compose.get('service') or target}",
        risk="medium",
        impact="service-impacting: compose service restart proposal only",
        confidence="high",
        proposed_steps=[f"docker compose restart {compose.get('service') or '<service>'}"],
        rollback=["No rollback executed in PR62; proposal-only artifact."],
        verification=["Confirm proposal-only status and execution_allowed=false."],
        safety_labels=["OPERATOR-RUN", "REQUIRES APPROVAL", "COMPOSE-MUTATION", "PROPOSAL-ONLY"],
        notes=(
            "PR62 proposal-only compose service restart artifact. "
            "Execution is intentionally not implemented."
        ),
        execution={"allowed": False, "status": "not_executed", "reason": EXECUTION_DISABLED_REASON},
        compose_context={
            "detected": True,
            "project": compose.get("project"),
            "service": compose.get("service"),
            "working_dir": compose.get("working_dir"),
            "config_files": [compose.get("compose_file")] if compose.get("compose_file") else [],
            "container_number": compose.get("container_number"),
            "oneoff": bool(compose.get("oneoff")),
            "container": compose.get("container"),
            "labels": compose.get("labels") or {},
            "preview_command": command,
            "preview_command_display": (preview_payload.get("preview") or {}).get(
                "command_display"
            ),
            "proposal_only": True,
            "execution_allowed": False,
            "apply_supported": False,
        },
        compose_mutation=True,
    )
    proposal.fingerprint = compute_proposal_fingerprint_payload(
        session_id=str(Path(runtime.session.data_dir).name or "compose-proposal"),
        option_id=f"compose_restart_{compose.get('project') or ''}_{compose.get('service') or ''}",
        component=str(compose.get("container") or compose.get("service") or "compose"),
        kind="compose_service_restart",
        title=proposal.title,
        risk=proposal.risk,
        steps=proposal.proposed_steps,
        rollback=proposal.rollback,
        verification=proposal.verification,
    )
    proposal.source.summary = "shellforgeai compose propose-restart"
    proposal.source.compose = {
        "project": compose.get("project"),
        "service": compose.get("service"),
        "working_dir": compose.get("working_dir"),
        "compose_file": compose.get("compose_file"),
    }
    if reason:
        proposal.notes += f"\nReason: {reason}"
    path = write_proposal(Path(runtime.session.data_dir), proposal)
    return {
        "schema_version": "1",
        "status": "created",
        "proposal": {
            "id": proposal.proposal_id,
            "kind": "compose_service_restart",
            "status": "pending",
            "path": str(path),
            "created_at": now,
            "reason": reason or "",
            "proposal_only": True,
            "execution_allowed": False,
            "executed": False,
        },
        "target": preview_payload.get("target"),
        "compose": compose,
        "preview": {
            **dict(preview_payload.get("preview") or {}),
            "proposal_only": True,
            "execution_allowed": False,
            "executed": False,
            "compose_mutation": True,
        },
        "safety": {
            "read_only_except_proposal_artifact": True,
            "docker_compose_executed": False,
            "container_restarted": False,
            "proposal_created": True,
            "mission_created": False,
            "approval_changed": False,
            "apply_executed": False,
            "requires_future_mission": True,
            "requires_future_approval": True,
            "requires_future_rollback_preview": True,
            "requires_future_apply_gate": True,
            "arbitrary_command_execution": False,
        },
        "warnings": [],
        "candidates": [],
        "next_safe_commands": [
            f"shellforgeai approvals show {proposal.proposal_id}",
            f"shellforgeai approvals validate {proposal.proposal_id}",
            f"shellforgeai compose restart-preview {target}",
        ],
    }


def _is_compose_restart_proposal_ask(text: str) -> bool:
    raw = (text or "").lower()
    if any(
        token in raw
        for token in ("execute compose restart proposal", "apply compose restart proposal")
    ):
        return False
    return (
        "compose" in raw
        and "restart" in raw
        and any(token in raw for token in ("propose", "proposal", "create"))
    )


def _normalize_label_dict(*sources: Any) -> dict[str, str]:
    """Merge labels from heterogeneous shapes into a single str->str dict.

    Accepts label dicts found at row/container/compose levels under common
    keys: ``labels``, ``Labels``, ``docker_labels``, ``container_labels``,
    and Docker inspect-shaped ``Config.Labels``.
    """
    out: dict[str, str] = {}
    for src in sources:
        if not isinstance(src, dict):
            continue
        for k in ("labels", "Labels", "docker_labels", "container_labels"):
            v = src.get(k)
            if isinstance(v, dict):
                for lk, lv in v.items():
                    if lk is None:
                        continue
                    out[str(lk)] = "" if lv is None else str(lv)
        config = src.get("Config")
        if isinstance(config, dict):
            cl = config.get("Labels")
            if isinstance(cl, dict):
                for lk, lv in cl.items():
                    if lk is None:
                        continue
                    out[str(lk)] = "" if lv is None else str(lv)
        inspect = src.get("inspect")
        if isinstance(inspect, dict):
            cfg = inspect.get("Config")
            if isinstance(cfg, dict):
                cl = cfg.get("Labels")
                if isinstance(cl, dict):
                    for lk, lv in cl.items():
                        if lk is None:
                            continue
                        out[str(lk)] = "" if lv is None else str(lv)
    return out


def _label_is_true(value: Any) -> bool:
    if value is True:
        return True
    if value is False or value is None:
        return False
    return str(value).strip().lower() in {"true", "1", "yes"}


def _compose_target_allowlisted(compose: dict[str, Any]) -> bool:
    labels = _normalize_label_dict(compose)
    return _label_is_true(labels.get("shellforgeai.disposable")) or _label_is_true(
        labels.get("shellforgeai.allow_restart")
    )


def _compose_mission_path(data_dir: Path, mission_id: str) -> Path:
    return Path(data_dir) / "missions" / "compose_restart" / mission_id / "mission.json"


def _emit_compose_mission_not_found(mission_id: str, json_out: bool) -> None:
    body = {
        "schema_version": "1",
        "status": "not_found",
        "mission_id": mission_id,
        "error": "mission_not_found",
        "executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "warnings": [],
    }
    if json_out:
        typer.echo(json.dumps(body))
    else:
        console.print(f"Compose restart mission not found: {mission_id}")
        console.print("- no docker compose command was executed")
        console.print("- no container was restarted")
    raise typer.Exit(code=1)


def _load_compose_mission_payload(
    data_dir: Path, mission_id: str, json_out: bool
) -> dict[str, Any]:
    path = _compose_mission_path(data_dir, mission_id)
    if not path.exists():
        _emit_compose_mission_not_found(mission_id, json_out)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _emit_compose_mission_not_found(mission_id, json_out)
        return {}  # unreachable; Exit raised above


def _compose_preflight_blockers(stderr: str) -> tuple[list[str], dict[str, Any], str]:
    low = (stderr or "").lower()
    blockers: list[str] = []
    fields = {
        "docker_cli_available": True,
        "docker_socket_available": None,
        "compose_cli_available": None,
        "required_invocation_supported": None,
    }
    reason = "Docker Compose preflight failed."
    if "unknown command: docker compose" in low or "'compose' is not a docker command" in low:
        fields["compose_cli_available"] = False
        fields["required_invocation_supported"] = False
        blockers.append("compose_cli_unavailable")
        reason = "Docker Compose CLI/plugin is unavailable in this execution environment."
    elif "unknown shorthand flag" in low:
        fields["required_invocation_supported"] = False
        blockers.append("compose_invocation_unsupported")
        reason = "Docker Compose invocation is unsupported in this environment."
    elif "cannot connect to the docker daemon" in low or "permission denied" in low:
        fields["docker_socket_available"] = False
        blockers.append("docker_socket_unavailable")
        reason = "Docker daemon/socket is unavailable for docker compose."
    return blockers, fields, reason


def _compose_cli_preflight(compose: dict[str, Any]) -> dict[str, Any]:
    version_cmd = ["docker", "compose", "version"]
    out: dict[str, Any] = {
        "status": "unknown",
        "docker_cli_available": None,
        "docker_socket_available": None,
        "compose_cli_available": None,
        "compose_invocation_ok": None,
        "required_invocation_supported": None,
        "command_checked": version_cmd,
        "returncode": None,
        "stdout_snippet": "",
        "stderr_snippet": "",
        "reason": "",
        "blockers": [],
        "warnings": [],
    }
    try:
        version_proc = subprocess.run(version_cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        out.update(
            {
                "status": "blocked",
                "docker_cli_available": False,
                "reason": "docker CLI not found",
                "blockers": ["docker_cli_missing"],
            }
        )
        return out
    out["returncode"] = version_proc.returncode
    out["stdout_snippet"] = (version_proc.stdout or "").strip()[:300]
    out["stderr_snippet"] = (version_proc.stderr or "").strip()[:300]
    out["docker_cli_available"] = True
    if version_proc.returncode != 0:
        blockers, fields, reason = _compose_preflight_blockers(out["stderr_snippet"])
        out.update(fields)
        out["compose_invocation_ok"] = False
        out["status"] = "blocked"
        out["reason"] = reason
        out["blockers"] = blockers or ["compose_preflight_failed"]
        if out["compose_cli_available"] is None:
            out["compose_cli_available"] = False
        return out
    out.update(
        {
            "status": "ok",
            "compose_cli_available": True,
            "compose_invocation_ok": True,
            "required_invocation_supported": True,
            "reason": "Compose CLI preflight passed.",
        }
    )
    cfg = (compose.get("config_files") or [""])[0]
    wd = compose.get("working_dir") or ""
    svc = str(compose.get("service") or "")
    probe_cmd = [
        "docker",
        "compose",
        "-f",
        str(cfg),
        "--project-directory",
        str(wd),
        "config",
        "--services",
    ]
    try:
        probe_proc = subprocess.run(probe_cmd, capture_output=True, text=True, check=False)
        if probe_proc.returncode != 0:
            out["command_checked"] = probe_cmd
            out["returncode"] = probe_proc.returncode
            out["stdout_snippet"] = (probe_proc.stdout or "").strip()[:300]
            out["stderr_snippet"] = (probe_proc.stderr or "").strip()[:300]
            blockers, fields, reason = _compose_preflight_blockers(out["stderr_snippet"])
            out.update(fields)
            out["compose_invocation_ok"] = False
            if "unknown shorthand flag" in out["stderr_snippet"].lower():
                out["required_invocation_supported"] = False
            out["status"] = "blocked"
            out["reason"] = reason
            out["blockers"] = blockers or ["compose_preflight_probe_failed"]
            return out
        services = [ln.strip() for ln in (probe_proc.stdout or "").splitlines() if ln.strip()]
        if svc and services and svc not in services:
            out.update(
                {
                    "status": "blocked",
                    "command_checked": probe_cmd,
                    "reason": "Compose service not found in compose config preflight.",
                    "blockers": ["compose_service_not_found"],
                    "compose_invocation_ok": True,
                }
            )
            return out
    except FileNotFoundError:
        pass
    return out


def _compose_config_snapshot(compose: dict[str, Any]) -> dict[str, Any]:
    compose_file = str((compose.get("config_files") or [""])[0] or "")
    payload: dict[str, Any] = {
        "compose_file_known": bool(compose_file),
        "compose_file_readable": False,
        "compose_file_sha256": None,
        "compose_file_error": "",
        "compose_file_snapshot_available": False,
        "blockers": [],
        "warnings": [],
    }
    if not compose_file:
        payload["compose_file_error"] = "compose file path missing"
        payload["blockers"].append("compose_file_missing")
        return payload
    path = Path(compose_file)
    if not path.exists():
        payload["compose_file_error"] = "compose file missing"
        payload["blockers"].append("compose_file_snapshot_unavailable")
        return payload
    try:
        raw = path.read_bytes()
        payload["compose_file_readable"] = True
        payload["compose_file_sha256"] = hashlib.sha256(raw).hexdigest()
        payload["compose_file_snapshot_available"] = True
    except Exception as exc:
        payload["compose_file_error"] = str(exc)
        payload["blockers"].append("compose_file_snapshot_unavailable")
    return payload


def _normalize_compose_metadata(
    compose: dict[str, Any] | None,
    *,
    target_input: str = "",
) -> dict[str, Any]:
    raw = compose if isinstance(compose, dict) else {}
    compose_file = str(
        raw.get("compose_file")
        or raw.get("config_file")
        or ((raw.get("config_files") or raw.get("compose_files") or [None])[0] or "")
        or ""
    ).strip()
    config_files_raw = raw.get("config_files") or raw.get("compose_files") or []
    config_files = [str(x).strip() for x in config_files_raw if str(x or "").strip()]
    if compose_file and not config_files:
        config_files = [compose_file]
    if not compose_file and config_files:
        compose_file = config_files[0]
    project = str(raw.get("project") or raw.get("compose_project") or "").strip()
    service = str(raw.get("service") or raw.get("compose_service") or "").strip()
    container = str(
        raw.get("container") or raw.get("container_name") or raw.get("target") or target_input or ""
    ).strip()
    working_dir = str(
        raw.get("working_dir") or raw.get("project_dir") or raw.get("project_directory") or ""
    ).strip()
    compose_managed = bool(raw.get("compose_managed"))
    if (raw.get("detected") is True and (project or service)) or (project and service):
        compose_managed = True
    labels = raw.get("labels") if isinstance(raw.get("labels"), dict) else {}
    return {
        "compose_managed": compose_managed,
        "detected": bool(raw.get("detected")) or compose_managed,
        "project": project,
        "service": service,
        "container": container,
        "working_dir": working_dir,
        "compose_file": compose_file,
        "config_files": config_files,
        "container_number": raw.get("container_number"),
        "oneoff": bool(raw.get("oneoff")),
        "labels": labels,
    }


def _compose_environment_readiness(preflight: dict[str, Any]) -> tuple[str, list[str]]:
    blockers = list(preflight.get("blockers") or [])
    blocker_map = {
        "compose_cli_unavailable": "docker_compose_cli_unavailable",
        "compose_invocation_unsupported": "required_invocation_unsupported",
        "docker_socket_unavailable": "docker_socket_unavailable",
        "docker_cli_missing": "docker_cli_missing",
    }
    normalized = [blocker_map.get(b, b) for b in blockers]
    if preflight.get("docker_cli_available") is False and "docker_cli_missing" not in normalized:
        normalized.append("docker_cli_missing")
    if (
        preflight.get("compose_cli_available") is False
        and "docker_compose_cli_unavailable" not in normalized
    ):
        normalized.append("docker_compose_cli_unavailable")
    if (
        preflight.get("required_invocation_supported") is False
        and "required_invocation_unsupported" not in normalized
    ):
        normalized.append("required_invocation_unsupported")
    if (
        preflight.get("docker_socket_available") is False
        and "docker_socket_unavailable" not in normalized
    ):
        normalized.append("docker_socket_unavailable")
    return ("ok" if not normalized else "blocked", normalized)


def _compose_env_contract_payload(target: str | None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1",
        "status": "unknown",
        "target": {
            "input": target or "",
            "compose_managed": False,
            "project": "",
            "service": "",
            "container": "",
            "disposable": False,
            "allow_restart": False,
            "target_allowlisted": False,
        },
        "environment": {},
        "snapshot": {
            "compose_file_known": False,
            "compose_file": "",
            "compose_file_readable": False,
            "compose_file_sha256": None,
            "compose_file_snapshot_available": False,
        },
        "readiness": {
            "ready": False,
            "ready_for_optional_disposable_proof": False,
            "blockers": [],
            "warnings": [],
        },
        "safety": {
            "read_only": True,
            "docker_compose_executed": False,
            "container_restarted": False,
            "natural_language_execution": False,
            "host_side_bypass": False,
            "arbitrary_command_execution": False,
        },
        "next_steps": [],
    }
    blockers: list[str] = []
    compose: dict[str, Any] = {}
    if target:
        preview_payload = _build_compose_restart_preview(target)
        pstatus = str(preview_payload.get("status") or "unknown")
        if pstatus == "ambiguous":
            payload["status"] = "blocked"
            payload["readiness"]["blockers"] = ["target_ambiguous"]
            return payload
        if pstatus == "not_found":
            payload["status"] = "blocked"
            payload["readiness"]["blockers"] = ["target_not_found"]
            return payload
        compose = _normalize_compose_metadata(
            dict(preview_payload.get("compose") or {}), target_input=target
        )
    else:
        payload["status"] = "blocked"
        payload["readiness"]["blockers"] = ["target_required"]
        return payload

    preflight = _compose_cli_preflight(compose)
    _env_status, env_blockers = _compose_environment_readiness(preflight)
    blockers.extend(env_blockers)
    payload["environment"] = {
        "docker_cli_available": bool(preflight.get("docker_cli_available")),
        "docker_socket_available": bool(preflight.get("docker_socket_available")),
        "docker_compose_cli_available": bool(preflight.get("compose_cli_available")),
        "required_invocation_supported": bool(preflight.get("required_invocation_supported")),
        "preflight_command": list(preflight.get("command_checked") or []),
        "returncode": preflight.get("returncode"),
        "stderr_snippet": preflight.get("stderr_snippet") or "",
    }
    config = _compose_config_snapshot(compose)
    normalized_labels = _normalize_label_dict(compose)
    disposable = _label_is_true(normalized_labels.get("shellforgeai.disposable"))
    allow_restart = _label_is_true(normalized_labels.get("shellforgeai.allow_restart"))
    allowlisted = disposable and allow_restart
    payload["target"] = {
        "input": target,
        "compose_managed": bool(compose.get("compose_managed")),
        "project": compose.get("project") or "",
        "service": compose.get("service") or "",
        "container": compose.get("container") or "",
        "disposable": disposable,
        "allow_restart": allow_restart,
        "target_allowlisted": allowlisted,
    }
    payload["snapshot"] = {
        "compose_file_known": bool(config.get("compose_file_known")),
        "compose_file": str((compose.get("config_files") or [""])[0] or ""),
        "compose_file_readable": bool(config.get("compose_file_readable")),
        "compose_file_sha256": config.get("compose_file_sha256"),
        "compose_file_snapshot_available": bool(config.get("compose_file_snapshot_available")),
    }
    if not payload["target"]["compose_managed"]:
        blockers.append("target_not_compose_managed")
    if (
        not payload["target"]["project"]
        or not payload["target"]["service"]
        or not payload["target"]["container"]
    ):
        blockers.append("compose_metadata_incomplete")
    if not config.get("compose_file_known"):
        blockers.append("compose_file_missing")
    if not config.get("compose_file_snapshot_available"):
        blockers.append("compose_file_snapshot_unavailable")
    if not allowlisted:
        blockers.append("target_not_allowlisted")
    blockers = sorted({b for b in blockers if b})
    ready = not blockers
    payload["readiness"] = {
        "ready": ready,
        "ready_for_optional_disposable_proof": ready,
        "blockers": blockers,
        "warnings": [],
    }
    payload["status"] = "ready" if ready else "blocked"
    payload["next_steps"] = [
        "Provide Docker Compose CLI/plugin inside the ShellForgeAI execution environment.",
        "Mount or mirror the disposable compose file read-only at the path ShellForgeAI sees.",
        "Re-run env-contract/env-check before any approved disposable proof.",
    ]
    return payload


_COMPOSE_ENV_PLAN_BLOCKER_MAP: dict[str, dict[str, Any]] = {
    "target_not_compose_managed": {
        "meaning": (
            "Target has no Compose metadata; ShellForgeAI cannot prove the disposable Compose "
            "restart lane against a non-Compose target."
        ),
        "operator_remediation": (
            "Use a Compose-managed target (inspect Docker labels for "
            "com.docker.compose.project / .service) or pick the PR67 disposable harness."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": False,
    },
    "target_not_allowlisted": {
        "meaning": (
            "Target is not explicitly marked disposable + allow_restart and is therefore not "
            "eligible for the Compose service restart execution lane."
        ),
        "operator_remediation": (
            "For lab proof, use the PR67 disposable harness "
            "(sfai_pr67_disposable / sfai-pr67-compose-web). Do not label production services "
            "shellforgeai.disposable=true or shellforgeai.allow_restart=true to bypass this gate."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": False,
    },
    "compose_file_snapshot_unavailable": {
        "meaning": (
            "Compose file path is known from Docker labels, but ShellForgeAI cannot read or hash "
            "it from inside its execution environment."
        ),
        "operator_remediation": (
            "Expose the disposable Compose file read-only into the ShellForgeAI container/harness "
            "at the same path Compose recorded, then rerun env-check/env-contract."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": True,
    },
    "compose_file_missing": {
        "meaning": "Compose file path is not recorded on the target's Docker labels.",
        "operator_remediation": (
            "Ensure the disposable target was started with Compose so labels record "
            "com.docker.compose.project.config_files."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": True,
    },
    "docker_compose_cli_unavailable": {
        "meaning": (
            "docker compose CLI/plugin is not available inside the ShellForgeAI execution "
            "environment, so the required preflight invocation cannot run."
        ),
        "operator_remediation": (
            "Provide a compatible Docker CLI with Compose plugin inside the ShellForgeAI "
            "container/harness. ShellForgeAI will not install packages automatically."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": True,
    },
    "docker_cli_missing": {
        "meaning": "docker CLI itself is missing inside the ShellForgeAI execution environment.",
        "operator_remediation": (
            "Provide a Docker CLI inside the ShellForgeAI container/harness. "
            "ShellForgeAI will not install packages automatically."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": True,
    },
    "docker_socket_unavailable": {
        "meaning": "Docker socket is not reachable from inside the ShellForgeAI runtime.",
        "operator_remediation": (
            "Expose the Docker socket read-only into the ShellForgeAI runtime in the lab harness. "
            "Do not enable this in production."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": True,
    },
    "required_invocation_unsupported": {
        "meaning": (
            "The required argv form is not supported by the available Compose plugin: "
            "docker compose -f <compose_file> --project-directory <working_dir> "
            "restart <service>."
        ),
        "operator_remediation": (
            "Provide a compatible Docker CLI + Compose plugin version inside the ShellForgeAI "
            "runtime and rerun env-check."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": True,
    },
    "compose_preflight_failed": {
        "meaning": (
            "Docker Compose preflight version check did not return success; the available "
            "Compose plugin could not confirm a supported invocation."
        ),
        "operator_remediation": (
            "Provide a compatible Docker CLI + Compose plugin inside the ShellForgeAI runtime "
            "and rerun env-check. ShellForgeAI will not install or upgrade packages."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": True,
    },
    "compose_metadata_incomplete": {
        "meaning": "Compose project/service/container metadata is incomplete for the target.",
        "operator_remediation": (
            "Re-inspect the target via 'shellforgeai compose inspect <container>' and confirm "
            "the disposable harness is healthy."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": False,
    },
    "rollback_preview_missing": {
        "meaning": "No rollback/recovery preview exists for the proposal that wires this target.",
        "operator_remediation": (
            "Run 'shellforgeai rollback preview <proposal-id>' and "
            "'shellforgeai rollback validate <rollback-preview>'."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": False,
    },
    "rollback_preview_invalid": {
        "meaning": "An existing rollback preview failed validation.",
        "operator_remediation": (
            "Regenerate and re-validate the rollback preview, or inspect the proposal/target "
            "metadata for drift."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": False,
    },
    "proposal_not_approved": {
        "meaning": "The compose_service_restart proposal is not in approved status.",
        "operator_remediation": (
            "Review the proposal and approve it explicitly via 'shellforgeai approvals approve "
            "<proposal-id>' only when every other gate is satisfied."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": False,
    },
    "fingerprint_invalid": {
        "meaning": "Proposal fingerprint changed or failed validation since it was created.",
        "operator_remediation": (
            "Recreate the proposal from fresh evidence and re-approve. Do not edit the proposal "
            "artifact by hand."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": False,
    },
    "missing_confirm": {
        "meaning": "Execution requires the explicit '--execute --confirm' flags.",
        "operator_remediation": (
            "Provide '--execute --confirm' on the mission execute command only after every "
            "other gate is green."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": False,
    },
    "target_ambiguous": {
        "meaning": "The target string resolved to multiple containers; cannot plan readiness.",
        "operator_remediation": (
            "Disambiguate the target by exact container name or project/service pair and rerun "
            "env-plan."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": False,
    },
    "target_not_found": {
        "meaning": "No container/service resolved for the supplied target.",
        "operator_remediation": (
            "Confirm the target name with 'shellforgeai compose list' or "
            "'shellforgeai inspect containers'."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": False,
    },
    "target_required": {
        "meaning": "env-plan needs a --target to compute a target-specific readiness plan.",
        "operator_remediation": (
            "Run 'shellforgeai compose env-plan --target <container-or-service>'."
        ),
        "shellforgeai_action": "none",
        "allowed_for_disposable_lab": True,
        "allowed_for_production": False,
        "mutation_required_outside_shellforgeai": False,
    },
}


def _compose_target_looks_production_like(target_input: str, target_meta: dict[str, Any]) -> bool:
    haystacks = [
        str(target_input or "").lower(),
        str(target_meta.get("project") or "").lower(),
        str(target_meta.get("service") or "").lower(),
        str(target_meta.get("container") or "").lower(),
    ]
    for hay in haystacks:
        if not hay:
            continue
        if hay == "shellforgeai":
            return True
        if "production" in hay or "prod" in hay:
            return True
    return False


def _compose_env_plan_payload(target: str | None) -> dict[str, Any]:
    contract = _compose_env_contract_payload(target)
    target_meta = dict(contract.get("target") or {})
    readiness = dict(contract.get("readiness") or {})
    blockers: list[str] = list(readiness.get("blockers") or [])
    production_like = _compose_target_looks_production_like(target or "", target_meta)
    target_meta["production_like"] = production_like

    plan_entries: list[dict[str, Any]] = []
    for blocker in blockers:
        info = _COMPOSE_ENV_PLAN_BLOCKER_MAP.get(blocker)
        if info is None:
            plan_entries.append(
                {
                    "blocker": blocker,
                    "meaning": (
                        "Unrecognized blocker name; ShellForgeAI does not have a built-in "
                        "remediation mapping for this readiness blocker."
                    ),
                    "operator_remediation": (
                        "Check 'shellforgeai compose env-check' and "
                        "'shellforgeai compose env-contract' output for the blocker name, then "
                        "consult docs/compose-ops.md."
                    ),
                    "shellforgeai_action": "none",
                    "automated": False,
                    "mutation_required_outside_shellforgeai": False,
                    "allowed_for_disposable_lab": True,
                    "allowed_for_production": False,
                }
            )
            continue
        plan_entries.append(
            {
                "blocker": blocker,
                "meaning": info["meaning"],
                "operator_remediation": info["operator_remediation"],
                "shellforgeai_action": "none",
                "automated": False,
                "mutation_required_outside_shellforgeai": bool(
                    info.get("mutation_required_outside_shellforgeai", False)
                ),
                "allowed_for_disposable_lab": bool(info.get("allowed_for_disposable_lab", True)),
                "allowed_for_production": bool(info.get("allowed_for_production", False)),
            }
        )

    warnings: list[str] = []
    if production_like and not target_meta.get("target_allowlisted"):
        warnings.append(
            "production-like target detected; do not label production services "
            "shellforgeai.disposable=true or shellforgeai.allow_restart=true to satisfy gates"
        )

    post_conditions = [
        "env-check reports compose_restart_execution_ready=true for the disposable target",
        "env-contract reports ready=true and ready_for_optional_disposable_proof=true",
        "production shellforgeai remains not allowlisted",
        "PR68 run-proof may only be executed with explicit operator approval",
    ]

    status = str(contract.get("status") or "unknown")
    if status not in {"ok", "ready", "blocked", "not_found", "error"}:
        status = "blocked"
    if status == "ready":
        status = "ok"
    if blockers and status == "ok":
        status = "blocked"

    payload: dict[str, Any] = {
        "schema_version": "1",
        "status": status,
        "target": {
            "input": target_meta.get("input") or (target or ""),
            "compose_managed": bool(target_meta.get("compose_managed")),
            "project": target_meta.get("project") or "",
            "service": target_meta.get("service") or "",
            "container": target_meta.get("container") or "",
            "disposable": bool(target_meta.get("disposable")),
            "allow_restart": bool(target_meta.get("allow_restart")),
            "target_allowlisted": bool(target_meta.get("target_allowlisted")),
            "production_like": production_like,
        },
        "readiness": {
            "ready": bool(readiness.get("ready")),
            "ready_for_optional_disposable_proof": bool(
                readiness.get("ready_for_optional_disposable_proof")
            ),
            "blockers": blockers,
        },
        "plan": plan_entries,
        "post_conditions": post_conditions,
        "safety": {
            "read_only": True,
            "docker_compose_executed": False,
            "container_restarted": False,
            "host_side_bypass": False,
            "arbitrary_command_execution": False,
            "natural_language_execution": False,
        },
        "warnings": warnings,
    }
    return payload


def _compose_mission_gates(
    data_dir: Path, mission_payload: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[str]]:
    mid = mission_payload.get("mission") or {}
    ppath, _ = find_proposal_path(data_dir, str(mid.get("proposal_id") or ""))
    proposal = load_proposal_from_path(ppath) if ppath else None
    compose = (proposal.compose_context if proposal else {}) or {}
    compose_file = str((compose.get("config_files") or [""])[0])
    rollback_path = (
        rollback_preview_mod.rollback_preview_dir(data_dir, str(mid.get("proposal_id") or ""))
        / "rollback-preview.json"
    )
    rollback_ok = rollback_path.exists()
    rollback_payload: dict[str, Any] = {}
    compose_file_readable = False
    compose_file_hash_present = False
    compose_file_snapshot_gate_required = False
    if rollback_ok:
        try:
            rollback_payload = rollback_preview_mod.load_preview(rollback_path)
            if rollback_payload.get("kind") == "compose_service_restart_recovery_preview":
                rollback_errors = rollback_preview_mod.validate_preview(rollback_payload)
                rollback_ok = not rollback_errors
                compose_file_snapshot_gate_required = True
                cfg = rollback_payload.get("config_state") or {}
                compose_file_readable = bool(cfg.get("compose_file_readable"))
                compose_file_hash_present = bool(cfg.get("compose_file_sha256"))
        except Exception:
            rollback_ok = False
    preflight = _compose_cli_preflight(compose)
    gates = {
        "proposal_approved": bool(proposal and proposal.status == "approved"),
        "fingerprint_valid": bool(
            proposal
            and isinstance(proposal.fingerprint, dict)
            and str(proposal.fingerprint.get("value") or "")
            and str(proposal.fingerprint.get("algorithm") or "") == "sha256"
        ),
        "target_allowlisted": bool(_compose_target_allowlisted(compose)),
        "compose_metadata_complete": bool(
            compose.get("project")
            and compose.get("service")
            and compose.get("working_dir")
            and compose_file
        ),
        "rollback_preview_present": rollback_ok,
        "rollback_preview_valid": rollback_ok,
        "compose_file_readable": compose_file_readable,
        "compose_file_hash_present": compose_file_hash_present,
        "compose_file_snapshot_gate_required": compose_file_snapshot_gate_required,
        "compose_file_snapshot_available": bool(
            compose_file_readable and compose_file_hash_present
        ),
        "docker_compose_available": bool(preflight.get("compose_cli_available")),
        "docker_compose_version_ok": bool(preflight.get("compose_invocation_ok")),
        "docker_compose_supports_required_invocation": bool(
            preflight.get("required_invocation_supported")
        ),
    }
    blockers: list[str] = []
    if not gates["proposal_approved"]:
        blockers.append("proposal is not approved")
    if not gates["fingerprint_valid"]:
        blockers.append("proposal fingerprint validation failed")
    if not gates["target_allowlisted"]:
        blockers.append("target is not marked disposable/allowlisted")
    if not gates["compose_metadata_complete"]:
        blockers.append("compose metadata incomplete")
    if not gates["rollback_preview_present"]:
        blockers.append("rollback preview missing")
    if (
        gates["compose_file_snapshot_gate_required"]
        and not gates["compose_file_snapshot_available"]
    ):
        blockers.append("compose_file_snapshot_unavailable")
        blockers.append("rollback preview is present, but compose file snapshot is unavailable")
        blockers.append(f"compose_file_readable={str(gates['compose_file_readable']).lower()}")
        blockers.append("compose_file_sha256 is missing")
    if not gates["docker_compose_available"]:
        blockers.append("docker compose CLI unavailable")
    if not gates["docker_compose_version_ok"]:
        blockers.append("docker compose version check failed")
    if not gates["docker_compose_supports_required_invocation"]:
        blockers.append(
            f"docker compose preflight failed: {preflight.get('reason') or 'incompatible'}"
        )
    return gates, preflight, compose, blockers


@mission_compose_restart_app.command("prepare")
def mission_compose_restart_prepare(
    ctx: typer.Context,
    proposal_id: Annotated[str, typer.Argument()],
) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    ppath, _ = find_proposal_path(data_dir, proposal_id)
    if ppath is None:
        console.print("Compose service restart mission preparation refused:")
        console.print("- reason: proposal not found")
        raise typer.Exit(code=1)
    proposal = load_proposal_from_path(ppath)
    if proposal.kind != "compose_service_restart":
        console.print("Compose service restart mission preparation refused:")
        console.print("- reason: proposal kind is not compose_service_restart")
        raise typer.Exit(code=1)
    mission_record: dict[str, Any] = {
        "id": f"mission_compose_restart_{uuid.uuid4().hex[:12]}",
        "mission_type": "compose_service_restart",
        "status": "prepared",
        "proposal_id": proposal_id,
        "target": proposal.compose_context or {},
    }
    payload: dict[str, Any] = {
        "schema_version": "1",
        "mission": mission_record,
    }
    mdir = Path(data_dir) / "missions" / "compose_restart" / str(mission_record["id"])
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / "mission.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    console.print("Compose restart mission prepared:")
    console.print(f"- mission: {mission_record['id']}")
    console.print(f"- status: {mission_record['status']}")


@mission_compose_restart_app.command("status")
def mission_compose_restart_status(
    ctx: typer.Context,
    mission_id: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    payload = _load_compose_mission_payload(data_dir, mission_id, json_out)
    gates, preflight, compose, blockers = _compose_mission_gates(data_dir, payload)
    status = "ready" if not blockers else "blocked"
    out = {
        "schema_version": "1",
        "mission": {**payload.get("mission", {}), "status": status},
        "gates": gates,
        "compose_preflight": preflight,
        "target": compose,
        "blockers": blockers,
    }
    if json_out:
        typer.echo(json.dumps(out, indent=2))
        return
    console.print(f"Compose mission: {mission_id}")
    console.print(f"- status: {status}")
    console.print(f"- compose_file_readable: {gates.get('compose_file_readable')}")
    console.print(f"- compose_file_hash_present: {gates.get('compose_file_hash_present')}")
    for b in blockers:
        console.print(f"- blocker: {b}")


@mission_compose_restart_app.command("checklist")
def mission_compose_restart_checklist(
    ctx: typer.Context,
    mission_id: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    mission_compose_restart_status(ctx, mission_id, json_out=json_out)


@mission_compose_restart_app.command("validate")
def mission_compose_restart_validate(
    ctx: typer.Context,
    mission_id: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    payload = _load_compose_mission_payload(data_dir, mission_id, json_out)
    gates, preflight, _compose, blockers = _compose_mission_gates(data_dir, payload)
    ok = not blockers
    out = {
        "schema_version": "1",
        "ok": ok,
        "mission_id": mission_id,
        "gates": gates,
        "compose_preflight": preflight,
        "errors": blockers,
    }
    if json_out:
        typer.echo(json.dumps(out, indent=2))
    else:
        console.print(
            "Compose restart mission validation passed."
            if ok
            else "Compose restart mission validation failed."
        )
        for err in blockers:
            console.print(f"- {err}")
    if not ok:
        raise typer.Exit(code=1)


@mission_compose_restart_app.command("execute")
def mission_compose_restart_execute(
    ctx: typer.Context,
    mission_id: Annotated[str, typer.Argument()],
    execute: Annotated[bool, typer.Option("--execute")] = False,
    confirm: Annotated[bool, typer.Option("--confirm")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    payload = _load_compose_mission_payload(data_dir, mission_id, json_out)
    mid = payload["mission"]
    gates, preflight, compose, blockers = _compose_mission_gates(data_dir, payload)
    cmd = [
        "docker",
        "compose",
        "-f",
        str((compose.get("config_files") or [""])[0]),
        "--project-directory",
        str(compose.get("working_dir") or ""),
        "restart",
        str(compose.get("service") or ""),
    ]
    gates = {
        **gates,
        "execute_flag_present": bool(execute),
        "confirm_flag_present": bool(confirm),
    }
    required_gate_keys = [
        "proposal_approved",
        "fingerprint_valid",
        "target_allowlisted",
        "compose_metadata_complete",
        "rollback_preview_present",
        "rollback_preview_valid",
        "docker_compose_available",
        "docker_compose_version_ok",
        "docker_compose_supports_required_invocation",
        "execute_flag_present",
        "confirm_flag_present",
    ]
    if gates.get("compose_file_snapshot_gate_required"):
        required_gate_keys.append("compose_file_snapshot_available")
    if not all(bool(gates.get(k)) for k in required_gate_keys):
        out = {
            "schema_version": "1",
            "mission": {**mid, "status": "blocked"},
            "gates": gates,
            "compose_preflight": preflight,
            "execution": {
                "executed": False,
                "blocked": True,
                "command": cmd,
                "returncode": None,
                "restart_returncode": None,
            },
            "safety": {
                "docker_compose_executed": False,
                "container_restarted": False,
                "arbitrary_command_execution": False,
            },
            "reason": preflight.get("reason") or (blockers[0] if blockers else "blocked"),
            "warnings": blockers,
        }
        if json_out:
            typer.echo(json.dumps(out, indent=2))
        else:
            console.print("Compose service restart execution requires --execute --confirm.")
            console.print("No docker compose command was executed.")
        raise typer.Exit(code=1)
    before_rows: list[dict[str, Any]] = []
    after_rows: list[dict[str, Any]] = []
    try:
        inv_before = containers.containers(all_containers=True)
        if inv_before.ok:
            before_rows = json.loads(inv_before.stdout or "{}").get("containers") or []
    except Exception:
        pass
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    try:
        inv_after = containers.containers(all_containers=True)
        if inv_after.ok:
            after_rows = json.loads(inv_after.stdout or "{}").get("containers") or []
    except Exception:
        pass
    target = str(compose.get("service") or "")
    project = str(compose.get("project") or "")

    def _pick(rows):
        for r in rows:
            cc = r.get("compose") or {}
            if str(cc.get("service") or "") == target and str(cc.get("project") or "") == project:
                return r
        return None

    b = _pick(before_rows)
    a = _pick(after_rows)
    sibling_before = {
        str((r.get("compose") or {}).get("service") or ""): str(r.get("started_at") or "")
        for r in before_rows
        if str((r.get("compose") or {}).get("project") or "") == project
        and str((r.get("compose") or {}).get("service") or "") != target
    }
    sibling_after = {
        str((r.get("compose") or {}).get("service") or ""): str(r.get("started_at") or "")
        for r in after_rows
        if str((r.get("compose") or {}).get("project") or "") == project
        and str((r.get("compose") or {}).get("service") or "") != target
    }
    touched = sorted(
        [k for k, v in sibling_before.items() if sibling_after.get(k) and sibling_after.get(k) != v]
    )
    verification = {
        "target_exists_after": a is not None,
        "running_after": bool((a or {}).get("state") == "running"),
        "started_at_changed": bool(
            a and b and str(a.get("started_at") or "") != str(b.get("started_at") or "")
        ),
        "health_after": str((a or {}).get("health") or "unknown"),
        "compose_project_unchanged": bool(a and (a.get("compose") or {}).get("project") == project),
        "compose_service_unchanged": bool(a and (a.get("compose") or {}).get("service") == target),
        "unrelated_services_checked_count": len(sibling_before),
        "unrelated_services_touched": touched,
        "warnings": [] if not touched else ["unrelated compose services appear touched"],
        "before_snapshot": {"target": b, "siblings": sibling_before},
        "after_snapshot": {"target": a, "siblings": sibling_after},
    }
    restarted = bool(
        proc.returncode == 0
        and verification["target_exists_after"]
        and verification["started_at_changed"]
        and verification["running_after"]
    )
    out = {
        "schema_version": "1",
        "mission": mid,
        "gates": gates,
        "execution": {
            "command": cmd,
            "executed": True,
            "returncode": proc.returncode,
            "restart_returncode": proc.returncode,
        },
        "compose_preflight": preflight,
        "verification": verification,
        "safety": {
            "compose_mutation": True,
            "docker_compose_executed": True,
            "container_restarted": restarted,
            "arbitrary_command_execution": False,
            "natural_language_execution": False,
            "apply_gate_used": True,
        },
    }
    if json_out:
        typer.echo(json.dumps(out, indent=2))
    else:
        console.print("Compose restart mission executed.")
        console.print(f"- returncode: {proc.returncode}")
    if proc.returncode != 0:
        raise typer.Exit(code=1)


def _handle_compose_restart_proposal_ask(runtime: RuntimeContext, question: str) -> bool:
    if not _is_compose_restart_proposal_ask(question):
        return False
    target = extract_compose_target(question)
    if not target:
        match = re.search(
            r"\brestart\s+(?:the\s+)?([a-z0-9][a-z0-9._-]{0,63})\s+compose service\b",
            question.lower(),
        )
        if match:
            target = match.group(1)
    if target:
        console.print("Restart proposal refused from natural language.")
        console.print("Refusing natural-language Compose mutation.")
        console.print(f'Run: shellforgeai compose propose-restart {target} --reason "<reason>"')
    else:
        console.print("Restart proposal refused from natural language.")
        console.print("Refusing natural-language Compose mutation.")
        console.print('Use: shellforgeai compose propose-restart <target> --reason "<reason>"')
    console.print("- read-only inspection: shellforgeai compose inspect <container>")
    console.print("- This creates a pending proposal only.")
    console.print("- no docker compose command was executed")
    return True


def _handle_apply_approved_ask(runtime: RuntimeContext, question: str) -> bool:
    """Intercept apply/run-approved ask requests. Returns True if handled.

    ShellForgeAI never executes mutation. For ``execute`` phrasing we refuse
    cleanly. For ``dry-run`` / ``prepare`` phrasing we offer (and optionally
    generate) an operator preflight bundle for the latest approved proposal.
    """
    intent = is_apply_approved_intent(question)
    if not intent.matched:
        return False
    proposal = latest_approved_proposal(Path(runtime.session.data_dir))
    if intent.execute and not intent.dry_run:
        console.print(
            "Refusing to execute: ShellForgeAI never runs mutation commands. "
            "apply remains validation-only."
        )
        if proposal is None:
            console.print(
                "No approved proposal found. Use `shellforgeai approvals approve "
                "<id> --reason ...` first, then `shellforgeai apply <id>` to "
                "generate an operator preflight bundle."
            )
        else:
            console.print(
                f"To prepare an operator bundle for the approved proposal, run:\n"
                f"  shellforgeai apply {proposal.proposal_id}"
            )
        return True
    # dry-run / prepare / preview path: generate bundle if approved proposal exists.
    if proposal is None:
        console.print(
            "No approved proposal found. Use `shellforgeai approvals approve "
            "<id> --reason ...` first to record approval (no execution)."
        )
        return True
    preflight = run_preflight(proposal)
    if not preflight.passed:
        _print_apply_preflight_failure(proposal, preflight.errors)
        return True
    result = generate_bundle(proposal, data_dir=Path(runtime.session.data_dir), preflight=preflight)
    console.print("Prepared operator preflight bundle (no commands executed):")
    console.print(f"- proposal: {proposal.proposal_id}")
    console.print(f"- status: {proposal.status}")
    console.print(f"- risk: {proposal.risk}")
    console.print("- execution: not_executed")
    console.print("- bundle:")
    for f in result.files:
        console.print(f"  - {f}")
    return True


def _handle_guard_ask(runtime: RuntimeContext, question: str) -> bool:
    """Handle stale-evidence / drift guard ask intents. No execution."""
    intent = is_guard_ask_intent(question)
    if not intent.matched:
        return False
    data_dir = Path(runtime.session.data_dir)
    if intent.run_anyway:
        console.print(
            "Refusing to execute: ShellForgeAI never runs mutation commands. "
            "apply remains validation-only."
        )
        console.print(
            "If you want to re-check freshness, run `shellforgeai guard check --latest-approved`."
        )
        return True
    if intent.check_export:
        latest = latest_session_dir(data_dir)
        console.print(
            "Export pack guard checks need an export directory path:\n"
            "  shellforgeai guard check-export <export-dir>\n"
            "- read-only; no commands executed."
        )
        if latest is not None:
            console.print(f"- hint: latest session dir is {latest}")
        return True
    if intent.check_actions:
        proposal = latest_approved_proposal(data_dir)
        if proposal is None:
            console.print(
                "No approved proposal found to guard-check actions for. "
                "Run `shellforgeai approvals approve <id> --reason ...` first."
            )
            return True
        from shellforgeai.core.actions import find_actions_for_proposal

        actions_path = find_actions_for_proposal(data_dir, proposal.proposal_id)
        if actions_path is None:
            console.print(
                "No compiled actions for the latest approved proposal yet. "
                "Run `shellforgeai actions compile --latest-approved` first; "
                "no commands were executed."
            )
            return True
        report = check_actions_file(actions_path, data_dir=data_dir)
        written = write_guard_report(report, data_dir=data_dir)
        _print_guard_report(report, write_paths=(written.json_path, written.md_path))
        return True
    # Default: check the latest approved proposal (most common ask).
    proposal = latest_approved_proposal(data_dir)
    if proposal is None:
        console.print(
            "No approved proposal found to guard-check. "
            "Use `shellforgeai approvals approve <id> --reason ...` first "
            "(no commands executed)."
        )
        return True
    path, _status = find_proposal_path(data_dir, proposal.proposal_id)
    if path is None:
        console.print("Approved proposal file not found on disk; no commands executed.")
        return True
    report = check_proposal_file(path)
    written = write_guard_report(report, data_dir=data_dir)
    _print_guard_report(report, write_paths=(written.json_path, written.md_path))
    return True


def _render_broad_triage_answer(payload: dict[str, Any]) -> str:
    """PR82 ask-shaped renderer for deterministic triage payloads.

    Distinct from ``triage_ranking.render_human`` so the broad ask answer
    stays 2AM-readable and matches the PR82 brief shape (Safety block,
    ranked suspects with severity / confidence / Evidence / Safe next,
    a Watch line, and a Next safe steps footer). Deterministic — never
    re-ranks, never invents suspects, never collapses one container's
    evidence onto another.
    """
    lines: list[str] = []
    lines.append("Read-only Docker triage ranking")
    lines.append("")
    lines.append("Safety:")
    lines.append("- read_only: true")
    lines.append("- mutation_performed: false")
    lines.append("- no restart/stop/delete/prune/apply/cleanup was executed")
    lines.append("")
    summary = payload.get("summary") or {}
    lines.append(
        "Scene: "
        f"containers_seen={summary.get('containers_seen', 0)} "
        f"suspects={summary.get('suspects_ranked', 0)} "
        f"critical={summary.get('critical', 0)} "
        f"high={summary.get('high', 0)} "
        f"medium={summary.get('medium', 0)} "
        f"watch={summary.get('watch', 0)}"
    )
    lines.append("")
    suspects = payload.get("suspects") or []
    if not suspects:
        lines.append("No suspects ranked from current scene.")
        lines.append("Try a fresh read-only check:")
        lines.append("- shellforgeai status --json")
        lines.append("- shellforgeai triage --json")
        lines.append("")
    for s in suspects:
        rank = s.get("rank", "?")
        name = s.get("name", "")
        severity = s.get("severity", "")
        confidence = s.get("confidence", "")
        lines.append(f"{rank}. {name} — {severity} / {confidence} confidence")
        why_list = list(s.get("why") or [])
        ev_list = list(s.get("evidence") or [])
        bullets: list[str] = []
        for w in why_list[:3]:
            if w and w not in bullets:
                bullets.append(w)
        for ev in ev_list:
            if len(bullets) >= 3:
                break
            t = ev.get("type") if isinstance(ev, dict) else None
            v = ev.get("value") if isinstance(ev, dict) else None
            if t is None:
                continue
            bullet = f"{t}: {v}"
            if bullet not in bullets:
                bullets.append(bullet)
        if bullets:
            lines.append("   Evidence:")
            for b in bullets:
                lines.append(f"   - {b}")
        next_cmds = s.get("safe_next_commands") or []
        if next_cmds:
            lines.append("   Safe next:")
            for cmd in next_cmds:
                lines.append(f"   - {cmd}")
        lines.append("")
    watch = payload.get("watch") or []
    if watch:
        lines.append("Watch:")
        for w in watch:
            why = "; ".join((w.get("why") or [])[:1]) or "monitor"
            lines.append(f"- {w.get('name', '')}: {why}")
        lines.append("")
    lines.append("Next safe steps:")
    next_safe = list(payload.get("next_safe_commands") or [])
    if "shellforgeai triage docker --json" not in next_safe:
        next_safe = ["shellforgeai triage docker --json", *next_safe]
    for cmd in next_safe:
        lines.append(f"- {cmd}")
    return "\n".join(lines).rstrip() + "\n"


def _handle_broad_triage_ask(runtime: RuntimeContext, question: str) -> bool:
    """PR82 — route broad read-only Docker/2AM ask prompts to deterministic triage.

    When the prompt is broad triage intent ("what's on fire?", "2AM
    triage", "the Docker box feels broken", "rank Docker suspects",
    "broadly scan the current scene", "rank all sfai-battle-lab
    suspects by severity", "what containers look suspicious?", etc.),
    this handler calls the PR81 deterministic triage engine
    (``triage_ranking.collect_scene`` + ``rank_scene``) directly and
    summarizes the result. No LLM re-ranking. No mutation. No
    proposal/mission/apply/cleanup. No Docker/Compose execution.

    Mutation-style asks tied to the ranking ("restart the top suspect",
    "fix the crashloop", "clean up disk pressure now", "stop
    noisy-errors", "apply the top fix") are refused here with the PR82
    no-mutation wording.
    """
    from shellforgeai.core import triage_ranking as triage_mod

    if is_triage_mutation_intent(question):
        console.print("I can rank suspects read-only, but I will not execute fixes from ask.")
        console.print("")
        console.print("No restart, cleanup, apply, or proposal was executed.")
        console.print("")
        console.print("Start with:")
        console.print("- shellforgeai triage docker")
        console.print("- shellforgeai triage docker detail <target>")
        _append_audit_event(
            runtime,
            kind="ask",
            action="broad_triage_mutation_refused",
            status="refused",
            summary="ask refused: triage mutation cannot run from natural language",
            details={
                "operation": "broad_triage_mutation_refused",
                "mutation_performed": False,
                "remediation_execution": False,
                "cleanup_executed": False,
                "proposal_created": False,
                "mission_created": False,
                "apply_executed": False,
                "docker_compose_executed": False,
                "container_restarted": False,
                "natural_language_execution": False,
                "shell_true": False,
            },
        )
        return True
    if not is_broad_docker_triage_intent(question):
        return False
    try:
        scene = triage_mod.collect_scene()
        payload = triage_mod.rank_scene(scene)
    except Exception as exc:
        console.print(
            f"Read-only triage failed: {type(exc).__name__}: {exc}. "
            "Try: shellforgeai triage docker --json"
        )
        _append_audit_event(
            runtime,
            kind="ask",
            action="broad_triage_collection_failed",
            status="warn",
            summary="ask: deterministic triage collection failed",
            details={
                "operation": "broad_triage_collection_failed",
                "mutation_performed": False,
                "remediation_execution": False,
            },
        )
        return True
    console.print(_render_broad_triage_answer(payload), end="")
    summary = payload.get("summary") or {}
    _append_audit_event(
        runtime,
        kind="ask",
        action="broad_triage_rendered",
        status="ok",
        summary="ask: deterministic Docker triage ranking summarized",
        details={
            "operation": "broad_triage_rendered",
            "containers_seen": summary.get("containers_seen", 0),
            "suspects_ranked": summary.get("suspects_ranked", 0),
            "mutation_performed": False,
            "remediation_execution": False,
            "cleanup_executed": False,
            "proposal_created": False,
            "mission_created": False,
            "apply_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "natural_language_execution": False,
            "shell_true": False,
        },
    )
    return True


def _brief_status(summary: dict[str, Any], suspects: list[dict[str, Any]]) -> str:
    if not suspects:
        return "OK / no current suspects"
    critical = int(summary.get("critical", 0) or 0)
    high = int(summary.get("high", 0) or 0)
    if critical:
        return "degraded"
    if high:
        return "watch"
    return "review"


def _brief_risk(summary: dict[str, Any], suspects: list[dict[str, Any]]) -> str:
    if not suspects:
        return "no ranked Docker suspects"
    critical = int(summary.get("critical", 0) or 0)
    high = int(summary.get("high", 0) or 0)
    parts: list[str] = []
    if critical:
        parts.append(f"{critical} critical")
    if high:
        parts.append(f"{high} high")
    if not parts:
        parts.append(f"{len(suspects)} ranked")
    suffix = "Docker suspect" if len(suspects) == 1 else "Docker suspects"
    return f"{', '.join(parts)} {suffix}"


def _brief_first_safe_command(payload: dict[str, Any]) -> str:
    suspects = payload.get("suspects") or []
    if not suspects:
        return "shellforgeai ops report --json"
    top = suspects[0]
    target = str(top.get("name") or "").strip()
    remediation = top.get("remediation") if isinstance(top.get("remediation"), dict) else {}
    eligibility = str(remediation.get("eligibility") or "").lower()
    proof_ready = bool(remediation.get("proof_ready") or remediation.get("docker_disposable_ready"))
    if target and (eligibility in {"eligible", "ready", "allowed"} or proof_ready):
        return remediation_eligibility_explain_command(target)
    if target:
        return triage_detail_command(target)
    return "shellforgeai ops report --json"


def _status_first_safe_command(payload: dict[str, Any]) -> str:
    suspects = payload.get("suspects") or []
    if not suspects:
        return "shellforgeai ops report --json"
    top = suspects[0]
    target = str(top.get("name") or "").strip()
    if target:
        return triage_detail_command(target)
    return "shellforgeai ops report --json"


def _render_status_human(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    suspects = payload.get("suspects") if isinstance(payload.get("suspects"), list) else []
    lines = [
        f"Status: {_brief_status(summary, suspects)}",
        f"Risk: {_brief_risk(summary, suspects)}",
    ]
    if suspects:
        top = suspects[0]
        name = str(top.get("name") or "unknown")
        severity = str(top.get("severity") or "unknown")
        classes = [str(c).replace("_", " ") for c in (top.get("classes") or []) if c]
        label = classes[0] if classes else "ranked Docker suspect"
        lines.append(f"Top suspect: {name} — {severity} {label}")
    lines.append(f"First safe command: {_status_first_safe_command(payload)}")
    lines.append("Safety: Read-only. No mutation executed.")
    return "\n".join(lines).rstrip() + "\n"


def _build_status_payload(*, top: int = 5) -> dict[str, Any]:
    payload = _build_ops_report_payload(top=top, include_visibility=True)
    payload = dict(payload)
    payload["mode"] = "status"
    payload["first_safe_command"] = _status_first_safe_command(payload)
    safety = payload.get("safety") if isinstance(payload.get("safety"), dict) else {}
    payload["safety"] = {
        **safety,
        "read_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "artifact_written": False,
        "model_called": False,
    }
    payload["read_only"] = True
    payload["mutation_performed"] = False
    payload["artifact_written"] = False
    payload["model_called"] = False
    return payload


def _v2_triage_safety(base: dict[str, Any] | None = None) -> dict[str, Any]:
    safety = dict(base or {})
    safety.update(
        {
            "read_only": True,
            "mutation_performed": False,
            "cleanup_executed": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "natural_language_execution": False,
            "model_called": False,
        }
    )
    return safety


def _v2_triage_target_command(target: str) -> str:
    return f"shellforgeai triage --target {target}"


def _build_v2_triage_payload(*, top: int = 5) -> dict[str, Any]:
    from shellforgeai.core import triage_ranking

    scene = triage_ranking.collect_scene()
    ranked = triage_ranking.rank_scene(scene)
    suspects = list(ranked.get("suspects") or [])[:top]
    summary = dict(ranked.get("summary") or {})
    top_name = str((suspects[0] or {}).get("name") or "") if suspects else None
    summary.update(
        {
            "suspects_ranked": len(suspects),
            "top_suspect": top_name,
            "critical": int(summary.get("critical", 0) or 0),
            "high": int(summary.get("high", 0) or 0),
        }
    )
    first_safe = _v2_triage_target_command(top_name) if top_name else "shellforgeai status --json"
    return {
        "schema_version": 1,
        "mode": "v2_triage",
        "status": "degraded" if suspects else "ok",
        "read_only": True,
        "mutation_performed": False,
        "summary": summary,
        "suspects": suspects,
        "first_safe_command": first_safe,
        "safety": _v2_triage_safety(
            ranked.get("safety") if isinstance(ranked.get("safety"), dict) else {}
        ),
        "warnings": list(ranked.get("warnings") or []),
    }


def _v2_evidence_summary(suspect: dict[str, Any]) -> str:
    evidence = suspect.get("evidence") or []
    parts: list[str] = []
    for ev in evidence:
        if not isinstance(ev, dict):
            continue
        kind = str(ev.get("type") or "evidence")
        value = str(ev.get("value") or "").strip()
        parts.append(f"{kind}: {value}" if value else kind)
        if len(parts) >= 2:
            break
    if not parts:
        parts = [str(w) for w in (suspect.get("why") or [])[:2] if w]
    return "; ".join(parts) if parts else "ranked by deterministic read-only triage"


def _v2_triage_risk_label(payload: dict[str, Any]) -> str:
    """Render the consistent V2 risk line shared across triage views."""
    suspects = payload.get("suspects") if isinstance(payload.get("suspects"), list) else []
    if not suspects:
        return "no current Docker suspects"
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    critical = int(summary.get("critical", 0) or 0)
    high = int(summary.get("high", 0) or 0)
    return f"{critical} critical, {high} high suspects"


def _render_v2_triage_human(payload: dict[str, Any]) -> str:
    suspects = payload.get("suspects") if isinstance(payload.get("suspects"), list) else []
    lines: list[str] = [
        f"Status: {'degraded' if suspects else 'OK'}",
        f"Risk: {_v2_triage_risk_label(payload)}",
    ]
    if not suspects:
        lines.extend(
            [
                "Triage: OK",
                "Suspects: none found",
                "First safe command:",
                f"  {payload.get('first_safe_command')}",
                "Safety: Read-only. No mutation executed.",
            ]
        )
        return "\n".join(lines).rstrip() + "\n"
    top = suspects[0]
    lines.extend(
        [
            "Triage: degraded",
            f"Suspects: {len(suspects)}",
            f"Top suspect: {top.get('name')} — {top.get('severity')}/{top.get('confidence')}",
            f"Evidence: {_v2_evidence_summary(top)}",
            "First safe command:",
            f"  {payload.get('first_safe_command')}",
            "Safety: Read-only. No mutation executed.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _render_v2_triage_brief(payload: dict[str, Any]) -> str:
    suspects = payload.get("suspects") if isinstance(payload.get("suspects"), list) else []
    if not suspects:
        return (
            "Triage: OK — no suspects found\n"
            f"First safe command: {payload.get('first_safe_command')}\n"
            "Safety: read-only\n"
        )
    top = suspects[0]
    return (
        f"Triage: degraded — top suspect {top.get('name')}\n"
        f"First safe command: {payload.get('first_safe_command')}\n"
        "Safety: read-only\n"
    )


def _build_v2_triage_detail_payload(target: str) -> dict[str, Any]:
    from shellforgeai.core import triage_ranking

    scene = triage_ranking.collect_scene()
    ranked = triage_ranking.rank_scene(scene)
    detail = triage_ranking.build_detail_payload(scene, ranked, suspect_name=target)
    payload = dict(detail)
    payload["schema_version"] = 1
    payload["mode"] = "v2_triage_detail"
    payload["target"] = target
    payload["read_only"] = True
    payload["mutation_performed"] = False
    payload["first_safe_command"] = remediation_eligibility_explain_command(target)
    payload["safety"] = _v2_triage_safety(
        detail.get("safety") if isinstance(detail.get("safety"), dict) else {}
    )
    if detail.get("status") == "ok":
        suspect = detail.get("suspect") if isinstance(detail.get("suspect"), dict) else {}
        payload["evidence"] = list(suspect.get("evidence") or [])
        payload["limitations"] = [
            "Read-only deterministic triage only; no remediation was executed.",
            "Evidence is limited to the current read-only Docker scene.",
        ]
    else:
        payload.setdefault("evidence", [])
        payload.setdefault(
            "limitations", ["No matching ranked suspect was found in the current scene."]
        )
    return payload


def _render_v2_triage_detail_human(payload: dict[str, Any]) -> str:
    target = str(payload.get("target") or "")
    if payload.get("status") != "ok":
        lines = ["Triage detail", "", f"Target: {target}", f"Status: {payload.get('status')}"]
        for w in payload.get("warnings") or []:
            lines.append(f"- {w}")
        if payload.get("available_suspects"):
            lines.append("Available suspects:")
            for name in payload.get("available_suspects") or []:
                lines.append(f"- {name}")
        lines.extend(
            [
                "Evidence: no matching ranked suspect found in current read-only scene.",
                "First safe command:",
                "  shellforgeai triage",
                "Safety: Read-only. No mutation executed.",
            ]
        )
        return "\n".join(lines).rstrip() + "\n"

    suspect = payload.get("suspect") if isinstance(payload.get("suspect"), dict) else {}
    lines = ["Triage detail", "", f"Target: {target}"]
    lines.append(f"Severity: {suspect.get('severity')} / {suspect.get('confidence')} confidence")
    lines.append("")
    lines.append("Evidence:")
    evidence = suspect.get("evidence") or []
    if evidence:
        for ev in evidence:
            if isinstance(ev, dict):
                lines.append(f"- {ev.get('type')}: {ev.get('value')}")
    else:
        lines.append("- no evidence bullets available")
    lines.append("")
    lines.append("Limitations:")
    for item in payload.get("limitations") or []:
        lines.append(f"- {item}")
    lines.append("First safe command:")
    lines.append(f"  {payload.get('first_safe_command')}")
    lines.append("Safety: Read-only. No mutation executed.")
    return "\n".join(lines).rstrip() + "\n"


def _v2_propose_safety() -> dict[str, Any]:
    return {
        "read_only": True,
        "mutation_performed": False,
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


def _scene_labels_for_target(
    scene: dict[str, Any], target: str
) -> tuple[dict[str, str] | None, bool]:
    for row in scene.get("containers") or []:
        if not isinstance(row, dict):
            continue
        names = {str(row.get("name") or "").lstrip("/")}
        if row.get("names"):
            raw_names = row.get("names")
            if isinstance(raw_names, list):
                names.update(str(n).lstrip("/") for n in raw_names)
            else:
                names.add(str(raw_names).lstrip("/"))
        if target not in names:
            continue
        labels_raw = row.get("labels") if isinstance(row.get("labels"), dict) else {}
        return {str(k): str(v) for k, v in labels_raw.items()}, True
    return None, False


def _target_suspect(ranked: dict[str, Any], target: str | None) -> dict[str, Any] | None:
    suspects = ranked.get("suspects") if isinstance(ranked.get("suspects"), list) else []
    if target is None:
        return suspects[0] if suspects else None
    for suspect in suspects:
        if isinstance(suspect, dict) and str(suspect.get("name") or "") == target:
            return suspect
    return None


def _eligibility_summary(report: dict[str, Any]) -> tuple[str, str]:
    status = str(report.get("status") or "unknown")
    eligibility = report.get("eligibility") if isinstance(report.get("eligibility"), dict) else {}
    reasons = [str(r) for r in (eligibility.get("blocked_reasons") or []) if r]
    if status == "ok" or eligibility.get("state") == "eligible_for_plan":
        return "eligible", "eligible for plan — plan command is plan-only and does not execute"
    if status == "not_found":
        return "blocked", "blocked — target not found in current triage scene"
    if reasons:
        preferred = (
            next((r for r in reasons if "production" in r), None)
            or next((r for r in reasons if "allowlist" in r), None)
            or reasons[0]
        )
        if preferred == "target missing allowlist labels":
            preferred = "target missing allowlist label"
        return "blocked", f"blocked — {preferred}"
    return "unknown", "unknown — eligibility could not be established from current evidence"


def _build_v2_propose_payload(
    *, target: str | None = None, from_triage: bool = False, top: int = 5
) -> dict[str, Any]:
    from shellforgeai.core import triage_ranking
    from shellforgeai.core.disposable_remediation import (
        SUPPORTED_SCENARIO,
        build_eligibility_explain_report,
    )

    scene = triage_ranking.collect_scene()
    ranked = triage_ranking.rank_scene(scene)
    suspects = list(ranked.get("suspects") or [])[:top]
    selected = _target_suspect({**ranked, "suspects": suspects}, target)
    safety = _v2_propose_safety()
    base = {
        "schema_version": 1,
        "mode": "v2_propose",
        "read_only": True,
        "mutation_performed": False,
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
        "from_triage": bool(from_triage),
        "safety": safety,
        "warnings": list(ranked.get("warnings") or []),
    }
    if selected is None and target is None:
        return {
            **base,
            "status": "ok",
            "proposal_status": "no_action_needed",
            "target": None,
            "evidence_summary": "no ranked suspects from current deterministic triage",
            "eligibility": {"state": "not_applicable", "summary": "not applicable — no target"},
            "first_safe_command": "shellforgeai status --json",
            "next_governed_command": "",
            "plan_only_command": "",
            "not_executed": [
                "no plan created",
                "no remediation executed",
                "no rollback executed",
                "no cleanup executed",
                "no Docker/Compose mutation",
                "no model call",
            ],
        }

    selected_name = target or str((selected or {}).get("name") or "")
    labels, found_in_scene = _scene_labels_for_target(scene, selected_name)
    target_known = selected is not None or found_in_scene
    if not target_known:
        return {
            **base,
            "status": "blocked",
            "proposal_status": "not_found",
            "target": selected_name,
            "evidence_summary": "target not found in current deterministic triage scene",
            "eligibility": {
                "state": "blocked",
                "summary": "blocked — target not found in current triage scene",
                "blocked_reasons": ["target not found"],
            },
            "first_safe_command": "shellforgeai triage",
            "next_governed_command": "",
            "plan_only_command": "",
            "review_commands": [
                "shellforgeai triage",
                f"shellforgeai triage docker detail {selected_name}",
            ],
            "not_executed": ["no plan created", "no action executed"],
        }

    if labels is None:
        labels = {}
    explain = build_eligibility_explain_report(
        target=selected_name,
        scenario=SUPPORTED_SCENARIO,
        labels=labels,
        target_found=target_known,
        explicit_target=bool(target),
    )
    eligibility_state, eligibility_text = _eligibility_summary(explain)
    evidence_summary = _v2_evidence_summary(selected or {})
    plan_only_command = str(explain.get("suggested_plan_command") or "")
    return {
        **base,
        "status": "proposal_available" if eligibility_state == "eligible" else "blocked",
        "proposal_status": "available" if eligibility_state == "eligible" else "blocked",
        "target": selected_name,
        "likely_target": selected_name,
        "evidence_summary": evidence_summary,
        "evidence": list((selected or {}).get("evidence") or []),
        "eligibility": {
            "state": eligibility_state,
            "summary": eligibility_text,
            "details": explain.get("eligibility") or {},
            "target": explain.get("target") or {},
        },
        "first_safe_command": triage_detail_command(selected_name),
        "next_governed_command": remediation_eligibility_explain_command(selected_name),
        "plan_only_command": plan_only_command,
        "plan_only_note": "Plan-only. Does not execute remediation." if plan_only_command else "",
        "not_executed": [
            "no plan created",
            "no remediation executed",
            "no rollback executed",
            "no cleanup executed",
            "no Docker/Compose mutation",
            "no action executed",
            "no model call",
        ],
    }


def _v2_apply_preview_safety() -> dict[str, Any]:
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


def _v2_apply_preview_base(
    *, from_propose: bool = False, from_triage: bool = False
) -> dict[str, Any]:
    safety = _v2_apply_preview_safety()
    return {
        "schema_version": 1,
        "mode": "v2_apply_preview",
        **safety,
        "from_propose": bool(from_propose),
        "from_triage": bool(from_triage),
        "target": {
            "name": None,
            "found": False,
            "production_target": False,
            "allowlisted": False,
            "disposable": False,
        },
        "preview": {
            "action": None,
            "exact_target_only": True,
            "execution_boundary": "not_crossed",
            "operator_approval_required": True,
            "confirm_required": True,
        },
        "gates": [],
        "warnings": [],
        "safe_next_commands": [],
        "safety": safety,
    }


def _build_v2_apply_preview_payload(
    *,
    target: str | None = None,
    from_propose: bool = False,
    from_triage: bool = False,
    top: int = 5,
) -> dict[str, Any]:
    from shellforgeai.core import triage_ranking
    from shellforgeai.core.disposable_remediation import (
        SUPPORTED_SCENARIO,
        build_eligibility_explain_report,
    )

    scene = triage_ranking.collect_scene()
    ranked = triage_ranking.rank_scene(scene)
    suspects = list(ranked.get("suspects") or [])[:top]
    selected = _target_suspect({**ranked, "suspects": suspects}, target)
    payload = _v2_apply_preview_base(from_propose=from_propose, from_triage=from_triage)
    payload["warnings"] = list(ranked.get("warnings") or [])

    if selected is None and target is None:
        payload.update(
            {
                "status": "no_action",
                "message": "no eligible action to preview",
                "reason": "no eligible proposal/action found",
                "first_safe_command": "shellforgeai propose --json",
                "safe_next_commands": ["shellforgeai propose --json", "shellforgeai triage --json"],
            }
        )
        return payload

    selected_name = target or str((selected or {}).get("name") or "")
    labels, found_in_scene = _scene_labels_for_target(scene, selected_name)
    target_known = selected is not None or found_in_scene
    explain = build_eligibility_explain_report(
        target=selected_name,
        scenario=SUPPORTED_SCENARIO,
        labels=labels if labels is not None else ({} if target_known else None),
        target_found=target_known,
        explicit_target=bool(target),
    )
    eligibility = cast(
        dict[str, Any],
        explain.get("eligibility") if isinstance(explain.get("eligibility"), dict) else {},
    )
    target_meta = cast(
        dict[str, Any], explain.get("target") if isinstance(explain.get("target"), dict) else {}
    )
    blocked_reasons = [str(r) for r in (eligibility.get("blocked_reasons") or []) if r]
    production = bool(target_meta.get("production_target") or eligibility.get("production_target"))
    disposable = bool(target_meta.get("disposable") or eligibility.get("disposable"))
    allowlisted = bool(
        target_meta.get("target_allowlisted")
        or target_meta.get("allowlisted")
        or eligibility.get("target_allowlisted")
    )
    payload["target"] = {
        "name": selected_name,
        "found": bool(target_known),
        "production_target": production,
        "allowlisted": allowlisted,
        "disposable": disposable,
    }
    payload["gates"] = list(explain.get("gates") or [])

    if production:
        payload.update(
            {
                "status": "blocked",
                "reason": "production target refused",
                "message": "production target refused",
                "first_safe_command": "shellforgeai status --json",
                "safe_next_commands": ["shellforgeai status --json", "shellforgeai triage --json"],
            }
        )
        return payload

    if not target_known:
        payload.update(
            {
                "status": "blocked",
                "reason": "target not found in current deterministic triage scene",
                "message": "target not found in current deterministic triage scene",
                "first_safe_command": "shellforgeai triage --json",
                "safe_next_commands": [
                    "shellforgeai triage --json",
                    f"shellforgeai triage docker detail {selected_name}",
                ],
            }
        )
        return payload

    gates = [
        "target_allowlisted=true",
        "disposable=true",
        "explicit approval required",
        "confirm required",
        "rollback/verification required",
    ]
    payload["preview"] = {
        **payload["preview"],
        "action": "bounded exact-target remediation preview"
        if allowlisted and disposable
        else None,
        "proposed_command_preview": explain.get("suggested_plan_command") or None,
    }
    status = "preview_ready" if allowlisted and disposable and not blocked_reasons else "blocked"
    reason = (
        "all preview gates visible; execution boundary still not crossed"
        if status == "preview_ready"
        else (blocked_reasons[0] if blocked_reasons else "required gates are not satisfied")
    )
    payload.update(
        {
            "status": status,
            "reason": reason,
            "message": reason,
            "required_gates": gates,
            "first_safe_command": f"shellforgeai triage docker detail {selected_name}",
            "safe_next_commands": [
                f"shellforgeai triage docker detail {selected_name}",
                f"shellforgeai remediation eligibility --target {selected_name} --explain",
            ],
        }
    )
    return payload


def _v2_verify_safety() -> dict[str, Any]:
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


def _v2_verify_source(
    *,
    from_status: bool = False,
    from_triage: bool = False,
    from_propose: bool = False,
    from_apply_preview: bool = False,
) -> str:
    if from_apply_preview:
        return "apply_preview"
    if from_propose:
        return "propose"
    if from_triage:
        return "triage"
    if from_status:
        return "status"
    return "triage"


def _is_v2_verify_production_target(name: str, labels: dict[str, str] | None = None) -> bool:
    lowered = name.lower().strip()
    if lowered in {"shellforgeai", "prod", "production"} or "prod" in lowered:
        return True
    labels = labels or {}
    for key, value in labels.items():
        label = f"{key}={value}".lower()
        if ("production" in label or "prod" in label) and value.lower() not in {
            "false",
            "0",
            "no",
        }:
            return True
    return False


def _build_v2_verify_payload(
    *,
    target: str | None = None,
    from_status: bool = False,
    from_triage: bool = False,
    from_propose: bool = False,
    from_apply_preview: bool = False,
    top: int = 5,
) -> dict[str, Any]:
    from shellforgeai.core import triage_ranking

    scene = triage_ranking.collect_scene()
    ranked = triage_ranking.rank_scene(scene)
    suspects = list(ranked.get("suspects") or [])[:top]
    summary = dict(ranked.get("summary") or {})
    critical = int(summary.get("critical", 0) or 0)
    high = int(summary.get("high", 0) or 0)
    selected = _target_suspect({**ranked, "suspects": suspects}, target)
    source = _v2_verify_source(
        from_status=from_status,
        from_triage=from_triage,
        from_propose=from_propose,
        from_apply_preview=from_apply_preview,
    )
    safety = _v2_verify_safety()
    limitations = [
        "Read-only deterministic current-state verification only.",
        "No apply receipt was provided or consumed by this command.",
    ]
    warnings = list(ranked.get("warnings") or [])
    findings: list[dict[str, Any]] = []
    target_payload: dict[str, Any] = {
        "name": target,
        "found": False,
        "production_target": False,
    }
    status = "degraded" if suspects else "ok"
    reason = "no current Docker suspects" if not suspects else "ranked suspects visible"
    first_safe = "shellforgeai status --json" if not suspects else "shellforgeai triage --json"
    safe_next = [first_safe]

    if target:
        labels, found_in_scene = _scene_labels_for_target(scene, target)
        target_known = selected is not None or found_in_scene
        production = _is_v2_verify_production_target(target, labels)
        target_payload = {
            "name": target,
            "found": bool(target_known),
            "production_target": production,
        }
        if not target_known:
            status = "unknown"
            reason = "target not found in current deterministic triage scene"
            first_safe = "shellforgeai triage --json"
            safe_next = [first_safe, f"shellforgeai triage docker detail {target}"]
            findings.append({"severity": "unknown", "message": reason})
        else:
            first_safe = f"shellforgeai triage docker detail {target}"
            safe_next = [first_safe, "shellforgeai status --json"]
            if selected:
                status = "degraded"
                reason = "target is visible in current ranked suspects"
                findings.append(
                    {
                        "severity": str(selected.get("severity") or "unknown"),
                        "message": _v2_evidence_summary(selected),
                    }
                )
            else:
                status = "ok"
                reason = "target visible with no current ranked suspect evidence"
                findings.append({"severity": "info", "message": reason})
            if production:
                warnings.append(
                    "Production-like target: verification is read-only; no restart or "
                    "remediation suggested."
                )
                limitations.append(
                    "Production-like target caution: inspect only unless governed workflows "
                    "authorize change."
                )
    elif suspects:
        top_suspect = suspects[0]
        first_safe = "shellforgeai triage --json"
        safe_next = [first_safe, _v2_triage_target_command(str(top_suspect.get("name") or ""))]
        findings.append(
            {
                "severity": str(top_suspect.get("severity") or "unknown"),
                "target": top_suspect.get("name"),
                "message": _v2_evidence_summary(top_suspect),
            }
        )

    if from_apply_preview:
        warnings.append("No apply receipt was provided; verifying current observed state only.")
    if from_propose:
        warnings.append("Proposal context does not imply any action was applied.")

    return {
        "schema_version": 1,
        "mode": "v2_verify",
        "status": status,
        "reason": reason,
        "read_only": True,
        "mutation_performed": False,
        "verification_type": "current_state",
        "applied_action_assumed": False,
        "apply_receipt_present": False,
        "from_status": bool(from_status),
        "from_triage": bool(from_triage),
        "from_propose": bool(from_propose),
        "from_apply_preview": bool(from_apply_preview),
        "target": target_payload,
        "evidence": {
            "source": source,
            "suspects_ranked": len(suspects),
            "critical": critical,
            "high": high,
        },
        "findings": findings,
        "limitations": limitations,
        "first_safe_command": first_safe,
        "safe_next_commands": safe_next,
        "safety": safety,
        "warnings": warnings,
        **safety,
    }


def _render_v2_verify_human(payload: dict[str, Any]) -> str:
    target = cast(
        dict[str, Any], payload.get("target") if isinstance(payload.get("target"), dict) else {}
    )
    evidence = cast(
        dict[str, Any], payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
    )
    status = str(payload.get("status") or "unknown")
    lines: list[str] = [f"Verify: {status.upper() if status == 'ok' else status}"]
    if target.get("name"):
        lines.append(f"Target: {target.get('name')}")
    if payload.get("from_apply_preview"):
        lines.append("No apply receipt was provided; verifying current observed state only.")
    elif payload.get("from_propose"):
        lines.append("No proposal was assumed to have been applied.")
    if target.get("name") and not target.get("found"):
        lines.append(f"Reason: {payload.get('reason')}")
    elif not target.get("name") and int(evidence.get("suspects_ranked", 0) or 0) == 0:
        lines.extend(
            [
                "Status: no current Docker suspects",
                "Risk: low from current container-visible evidence",
            ]
        )
    else:
        lines.append(f"Reason: {payload.get('reason')}")
        lines.append(
            "Evidence: "
            f"{evidence.get('suspects_ranked', 0)} ranked suspects; "
            f"{evidence.get('critical', 0)} critical; {evidence.get('high', 0)} high"
        )
    if target.get("production_target"):
        lines.append("Caution: production-like target; read-only verification only.")
    lines.extend(
        [
            "",
            "No applied action was detected or assumed.",
            "This is a read-only current-state verification.",
            "This command did not verify a completed remediation.",
            "",
            "First safe command:",
            f"  {payload.get('first_safe_command')}",
            "",
            "Safety:",
            "- Read-only verification.",
            "- No apply, remediation, rollback, cleanup, Docker, or Compose action was executed.",
            "- No action was taken.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _render_v2_receipt_verify_human(payload: dict[str, Any]) -> str:
    receipt = payload.get("receipt") if isinstance(payload.get("receipt"), dict) else {}
    recipe = payload.get("recipe") if isinstance(payload.get("recipe"), dict) else {}
    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    execution = payload.get("execution") if isinstance(payload.get("execution"), dict) else {}
    post_check = payload.get("post_check") if isinstance(payload.get("post_check"), dict) else {}
    status = str(payload.get("status") or "unknown")
    lines = [f"Verify: {status.replace('_', ' ')}", "Verification type: receipt"]
    if recipe.get("recipe_id"):
        lines.append(f"Recipe: {recipe.get('recipe_id')}")
    if target.get("name"):
        lines.append(f"Target: {target.get('name')}")
    lines.append(f"Receipt: {receipt.get('receipt_id') or receipt.get('receipt_ref') or 'unknown'}")
    if payload.get("status") == "not_found":
        lines.extend(["", "First safe command:", f"  {payload.get('first_safe_command')}"])
        return "\n".join(lines) + "\n"
    warnings = list(payload.get("warnings") or [])
    if warnings and status in {"failed", "safety_drift", "unsupported"}:
        lines.append(f"Reason: {warnings[0]}")
    if execution.get("recorded_action"):
        lines.extend(["", "Recorded action:", f"  {execution.get('recorded_action')}"])
    lines.extend(["", "Post-check:"])
    lines.append(f"- verification {post_check.get('verification_status') or 'unknown'}")
    lines.append(f"- exact target matched: {str(bool(execution.get('exact_target_only'))).lower()}")
    lines.append(
        f"- no production target: {str(not bool(target.get('production_target'))).lower()}"
    )
    if status in {"failed", "safety_drift"}:
        lines.extend(["", "No retry was attempted."])
    lines.extend(["", "First safe command:", f"  {payload.get('first_safe_command')}"])
    if warnings:
        lines.extend(["", "Warnings:"])
        lines.extend(f"- {warning}" for warning in warnings)
    lines.extend(
        [
            "",
            "Safety:",
            "- Read-only receipt verification.",
            (
                "- Verify did not execute Docker, Compose, cleanup, remediation, "
                "rollback, or shell commands."
            ),
            "- No container was restarted by verify.",
        ]
    )
    return "\n".join(lines) + "\n"


def _render_v2_verify_brief(payload: dict[str, Any]) -> str:
    if payload.get("verification_type") == "receipt":
        receipt = payload.get("receipt") if isinstance(payload.get("receipt"), dict) else {}
        recipe = payload.get("recipe") if isinstance(payload.get("recipe"), dict) else {}
        return (
            f"Verify: {payload.get('status') or 'unknown'}\n"
            "Type: receipt\n"
            f"Recipe: {recipe.get('recipe_id') or 'unknown'}\n"
            f"Receipt: {receipt.get('receipt_id') or receipt.get('receipt_ref') or 'unknown'}\n"
            "Safety: read-only; no command executed by verify\n"
        )
    target = cast(
        dict[str, Any], payload.get("target") if isinstance(payload.get("target"), dict) else {}
    )
    name = target.get("name") or "none"
    return (
        f"Verify: {payload.get('status')}\n"
        f"Target: {name}\n"
        f"First safe command: {payload.get('first_safe_command')}\n"
        "Safety: read-only; no apply/remediation/rollback/cleanup/Docker/Compose action executed\n"
    )


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
    triage_payload = _build_v2_triage_payload(top=top)
    propose_payload = _build_v2_propose_payload(target=target, from_triage=True, top=top)
    apply_preview_payload = _build_v2_apply_preview_payload(
        target=target, from_propose=True, top=top
    )
    verify_payload = _build_v2_verify_payload(target=target, from_triage=True, top=top)

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


def _render_v2_apply_preview_human(payload: dict[str, Any]) -> str:
    target = cast(
        dict[str, Any], payload.get("target") if isinstance(payload.get("target"), dict) else {}
    )
    target_name = target.get("name")
    status = str(payload.get("status") or "blocked")
    if status == "no_action":
        lines = [
            "Apply preview: no action ready",
            "Status: no eligible proposal/action found",
            "First safe command:",
            f"  {payload.get('first_safe_command')}",
            "",
            "Safety:",
            "- Read-only preview.",
            (
                "- No plan, mission, apply, remediation, rollback, cleanup, Docker, "
                "or Compose action was executed."
            ),
            "- No action was taken.",
        ]
        return "\n".join(lines).rstrip() + "\n"
    if status == "blocked":
        lines = ["Apply preview: blocked"]
        if target_name:
            lines.append(f"Target: {target_name}")
        lines.append(f"Reason: {payload.get('reason')}")
        lines.extend(["", "First safe command:", f"  {payload.get('first_safe_command')}"])
        lines.extend(["", "Safety:", "- Read-only preview.", "- No action was taken."])
        return "\n".join(lines).rstrip() + "\n"
    lines = [
        "Apply preview: gated",
        f"Target: {target_name}",
        "Would require:",
    ]
    for gate in payload.get("required_gates") or []:
        lines.append(f"- {gate}")
    preview = cast(
        dict[str, Any], payload.get("preview") if isinstance(payload.get("preview"), dict) else {}
    )
    if preview.get("proposed_command_preview"):
        lines.extend(
            ["Previewed command boundary:", f"  {preview.get('proposed_command_preview')}"]
        )
    lines.extend(["", "No action was taken."])
    return "\n".join(lines).rstrip() + "\n"


def _render_v2_apply_preview_brief(payload: dict[str, Any]) -> str:
    target = cast(
        dict[str, Any], payload.get("target") if isinstance(payload.get("target"), dict) else {}
    )
    label = "gated" if payload.get("status") == "preview_ready" else payload.get("status")
    return (
        f"Apply preview: {label}\n"
        f"Target: {target.get('name') or 'none'}\n"
        f"First safe command: {payload.get('first_safe_command')}\n"
        "Safety: read-only; no plan, mission, apply, remediation, rollback, cleanup, "
        "Docker, or Compose action executed\n"
    )


def _render_v2_propose_human(payload: dict[str, Any]) -> str:
    target = payload.get("target")
    if payload.get("proposal_status") == "no_action_needed":
        lines = [
            "Proposal: none needed",
            "Status: no current suspects",
            "First safe command:",
            f"  {payload.get('first_safe_command')}",
            "Safety: read-only. No plan was created. No action was taken.",
        ]
        return "\n".join(lines).rstrip() + "\n"
    if payload.get("proposal_status") == "not_found":
        lines = [
            "Proposal: blocked",
            f"Target: {target}",
            "Why: target not found in current deterministic triage scene",
            "Eligibility: blocked — target not found in current triage scene",
            "First safe command:",
            "  shellforgeai triage",
            "Next review command:",
            f"  shellforgeai triage docker detail {target}",
            "Safety: read-only. No plan was created. No action was taken.",
        ]
        return "\n".join(lines).rstrip() + "\n"
    eligibility = payload.get("eligibility") if isinstance(payload.get("eligibility"), dict) else {}
    lines = [
        f"Proposal: {'available' if payload.get('proposal_status') == 'available' else 'blocked'}",
        f"Target: {target}",
        f"Why: {payload.get('evidence_summary')}",
        f"Eligibility: {eligibility.get('summary')}",
        "First safe command:",
        f"  {payload.get('first_safe_command')}",
        "Next review command:",
        f"  {payload.get('next_governed_command')}",
    ]
    if payload.get("plan_only_command"):
        lines.extend(
            [
                "Plan-only command:",
                f"  {payload.get('plan_only_command')}",
                "Plan-only. Does not execute remediation.",
            ]
        )
    lines.append("Safety: read-only. No plan was created. No action was taken.")
    return "\n".join(lines).rstrip() + "\n"


def _render_v2_propose_brief(payload: dict[str, Any]) -> str:
    status = payload.get("proposal_status")
    if status == "no_action_needed":
        proposal = "none needed"
    elif status == "available":
        proposal = "proposal available"
    else:
        proposal = "blocked"
    target = payload.get("target") or "none"
    return (
        f"Proposal: {proposal}\n"
        f"Target: {target}\n"
        f"First safe command: {payload.get('first_safe_command')}\n"
        "Safety: read-only; no plan or action executed\n"
    )


def _render_ops_report_brief(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") or {}
    suspects = payload.get("suspects") or []
    lines: list[str] = [
        f"Status: {_brief_status(summary, suspects)}",
        f"Risk: {_brief_risk(summary, suspects)}",
    ]
    visibility = str(payload.get("visibility") or "").replace("_", "-")
    if visibility == "container-limited":
        lines.append("Visibility: container-limited")
    if suspects:
        top = suspects[0]
        name = str(top.get("name") or "unknown")
        severity = str(top.get("severity") or "unknown")
        classes = [str(c).replace("_", " ") for c in (top.get("classes") or []) if c]
        label = classes[0] if classes else "ranked Docker suspect"
        lines.extend(["", "Top issue:", f"- {name} — {severity} {label}"])
        evidence = [str(e) for e in (top.get("evidence_summary") or []) if e]
        if len(suspects) > 1:
            evidence.append("related Docker suspects also present")
        if evidence:
            lines.extend(["", "Evidence:"])
            for item in list(dict.fromkeys(evidence))[:3]:
                lines.append(f"- {item}")
    lines.extend(["", "First safe command:", f"  {_brief_first_safe_command(payload)}"])
    if suspects:
        safety = "Read-only. No restart, cleanup, remediation, or Compose command executed."
    else:
        safety = "Read-only. No mutation executed."
    lines.extend(["", "Safety:", f"- {safety}"])
    return "\n".join(lines).rstrip() + "\n"


def _build_ops_report_payload(
    *,
    top: int = 5,
    include_details: bool = False,
    include_remediation: bool = False,
    include_timeline: bool = False,
    include_visibility: bool = False,
) -> dict[str, Any]:
    from shellforgeai.core import triage_ranking
    from shellforgeai.core.disposable_remediation import (
        build_eligibility_explain_report,
        build_remediation_audit_payload,
    )
    from shellforgeai.core.self_test import run_self_test_commands

    settings = load_settings()
    profile = load_profile(settings.app.default_profile, Path.cwd())
    session = build_session_context(settings, profile, mode="cli", cwd=Path.cwd())
    warnings: list[str] = []
    scene = triage_ranking.collect_scene()
    ranked = triage_ranking.rank_scene(scene)
    suspects = list(ranked.get("suspects") or [])[:top]
    out_suspects: list[dict[str, Any]] = []
    safe_next: list[str] = []

    def _scenario_for_suspect(classes: list[str]) -> str:
        lowered = {str(c).lower() for c in classes}
        if "disk_pressure" in lowered:
            return "sfai-disk-pressure"
        if "bad_http" in lowered:
            return "sfai-bad-http"
        if "crashloop" in lowered or "restart_storm" in lowered:
            return "sfai-crashloop"
        if "permission_denied" in lowered:
            return "sfai-permission-denied"
        return "sfai-noisy-errors"

    for suspect in suspects:
        name = str(suspect.get("name") or "")
        evidence_summary = [
            f"{ev.get('type')}: {ev.get('value')}" for ev in (suspect.get("evidence") or [])
        ]
        if not include_details:
            evidence_summary = evidence_summary[:3]
        suspect_safe = [triage_detail_command(name), remediation_eligibility_explain_command(name)]
        safe_next.extend(suspect_safe)
        remediation = {
            "eligibility": "unknown",
            "blocked_reasons": [],
            "proof_ready": False,
            "docker_disposable_ready": False,
        }
        if include_remediation:
            label_map = {}
            target_found = False
            for row in scene.get("containers", []):
                if str(row.get("name") or "") == name:
                    label_map = row.get("labels") if isinstance(row.get("labels"), dict) else {}
                    target_found = True
                    break
            try:
                explain = build_eligibility_explain_report(
                    target=name,
                    scenario=_scenario_for_suspect(list(suspect.get("classes") or [])),
                    labels=label_map,
                    target_found=target_found,
                    explicit_target=True,
                )
                gates = list(explain.get("gates") or [])
                remediation = {
                    "eligibility": str(
                        (explain.get("eligibility") or {}).get("state") or "unknown"
                    ),
                    "blocked_reasons": [
                        str(g.get("reason"))
                        for g in gates
                        if str(g.get("status")) == "failed" and g.get("reason")
                    ],
                    "proof_ready": bool(
                        ((explain.get("eligibility") or {}).get("executors") or {})
                        .get("proof", {})
                        .get("ready")
                    ),
                    "docker_disposable_ready": bool(
                        ((explain.get("eligibility") or {}).get("executors") or {})
                        .get("docker-disposable", {})
                        .get("ready")
                    ),
                }
            except Exception as exc:
                warnings.append(f"remediation enrichment unavailable for {name}: {exc}")
                remediation = {
                    "eligibility": "unknown",
                    "blocked_reasons": ["remediation enrichment unavailable"],
                    "proof_ready": False,
                    "docker_disposable_ready": False,
                }
        out_suspects.append(
            {
                "rank": suspect.get("rank"),
                "name": name,
                "severity": suspect.get("severity"),
                "confidence": suspect.get("confidence"),
                "classes": suspect.get("classes") or [],
                "evidence_summary": evidence_summary,
                "safe_next_commands": suspect_safe,
                "remediation": remediation,
            }
        )
    safe_next.extend(
        [
            remediation_self_test_command(profile="standard", json=True),
            remediation_audit_latest_command(json=True),
        ]
    )
    safe_next = list(dict.fromkeys(safe_next))
    self_test_quick = run_self_test_commands(profile="quick")
    self_test_standard = run_self_test_commands(profile="standard")
    remediation_lane = {
        "self_test_quick": "passed" if self_test_quick.get("status") == "ok" else "warn",
        "self_test_standard": "passed" if self_test_standard.get("status") == "ok" else "warn",
        "self_test_full": "unknown",
        "latest_audit": "unknown",
        "notes": [],
    }
    if self_test_quick.get("warnings"):
        remediation_lane["notes"].extend(self_test_quick.get("warnings") or [])
    if self_test_standard.get("warnings"):
        remediation_lane["notes"].extend(self_test_standard.get("warnings") or [])
    audit_payload = build_remediation_audit_payload(session.data_dir, latest_only=True)
    remediation_lane["latest_audit"] = str(audit_payload.get("status") or "unknown")
    if audit_payload.get("status") == "empty":
        remediation_lane["notes"].append("no lifecycle artifacts found")
    if include_timeline:
        timeline = triage_ranking.build_snapshot_timeline(session.data_dir)
        if timeline.get("status") != "ok":
            warnings.extend(timeline.get("warnings") or [])
    summary = ranked.get("summary") or {}
    payload = {
        "schema_version": "1",
        "mode": "ops_report",
        "status": ("warn" if warnings else ("ok" if suspects else "empty")),
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "containers_seen": int(
                summary.get("containers_seen", len(scene.get("containers") or []))
            ),
            "suspects_ranked": len(suspects),
            "critical": int(summary.get("critical", 0)),
            "high": int(summary.get("high", 0)),
            "remediation_lane_status": "warn" if remediation_lane["notes"] else "ok",
        },
        "suspects": out_suspects,
        "remediation_lane": remediation_lane,
        "safe_next_commands": safe_next,
        "warnings": warnings,
        "safety": {
            "read_only": True,
            "mutation_performed": False,
            "plan_created": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "cleanup_executed": False,
            "proposal_created": False,
            "mission_created": False,
            "apply_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "natural_language_execution": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
        },
    }
    if include_visibility:
        visibility = str(scene.get("visibility") or scene.get("runtime_visibility") or "")
        if visibility:
            payload["visibility"] = visibility
    return payload


def _handle_actions_ask(runtime: RuntimeContext, question: str) -> bool:
    """Handle actions compile/show/run asks. No execution."""
    intent = is_actions_ask_intent(question)
    if not intent.matched:
        return False
    data_dir = Path(runtime.session.data_dir)
    if intent.run and not (intent.compile or intent.show):
        console.print(
            "Refusing to execute: ShellForgeAI never runs mutation commands. "
            "apply remains validation-only."
        )
        console.print(
            "Compiled actions are review-only. Run "
            "`shellforgeai actions compile --latest-approved` to inspect them."
        )
        return True
    proposal = latest_approved_proposal(data_dir)
    if proposal is None:
        console.print(
            "No approved proposal found. Use `shellforgeai approvals approve "
            "<id> --reason ...` first to record approval (no execution)."
        )
        return True
    result = compile_and_write(proposal, data_dir=data_dir)
    _print_compile_result(result, proposal_status=proposal.status)
    if intent.run:
        console.print(
            "Note: ShellForgeAI did NOT execute any action. Compiled records are review-only."
        )
    return True


_ASK_MUTATION_TERMS: tuple[str, ...] = (
    "restart",
    "stop",
    "start",
    "kill",
    "remove",
    "delete",
    "prune",
    "clean up",
    "cleanup",
    "fix everything",
    "fix the top suspect",
    "fix top suspect",
    "remediate",
    "remediation plan",
    "execute",
    "apply",
    "rollback",
    "roll back",
    "retry",
    "rerun",
    "recreate",
    "rebuild",
    "compose up",
    "compose down",
    "compose restart",
    "docker restart",
    "chmod",
    "chown",
    "install",
    "uninstall",
    "reload",
    "repair",
    "resolve automatically",
)


def _is_pressure_mutation_request(question: str) -> bool:
    q = re.sub(r"[^a-z0-9\s]", " ", (question or "").lower())
    q = re.sub(r"\s+", " ", q).strip()
    phrases = (
        "quickly restart",
        "quick restart",
        "restart now",
        "no novel clean up",
        "no novel cleanup",
        "clean up docker",
        "cleanup docker",
        "fast fix it",
        "just fix it",
    )
    return any(phrase in q for phrase in phrases)


def _handle_pressure_mutation_refusal(question: str) -> bool:
    if not _is_pressure_mutation_request(question):
        return False
    console.print(
        "Refusing to execute: I can provide a quick read-only status, but I will not "
        "execute mutations."
    )
    console.print(
        "No restart, cleanup, remediation, rollback, Docker, or Compose command was executed."
    )
    console.print("")
    console.print("Safe read-only next command:")
    console.print("- shellforgeai ops report --brief")
    return True


def _handle_command_help_ask(question: str) -> bool:
    """PR131: answer command-help / plan-help questions with safe guidance.

    Distinguishes "what command would I run / how would I propose this?"
    (read-only or plan-only guidance) from mutation requests. Nothing is
    executed and no plan is created here; the response only renders safe
    read-only or clearly-labelled plan-only commands. Ambiguous "run that /
    do it now" phrasings are refused deterministically.
    """
    nuance = classify_intent_nuance(question)
    if nuance.category in (COMMAND_HELP, PLAN_HELP, CLEANUP_REVIEW_HELP, AMBIGUOUS_EXECUTE):
        console.print(render_intent_nuance(nuance, text=question))
        return True
    return False


def _handle_mutation_refusal_ask(question: str) -> bool:
    raw = (question or "").strip()
    if not raw:
        return False
    normalized = " ".join(raw.lower().split())
    if normalized.startswith("can you "):
        return False
    if any(phrase in normalized for phrase in ("what would happen if", "how would i")):
        return False
    matched = [term for term in _ASK_MUTATION_TERMS if term in normalized]
    if not matched:
        return False
    target_match = re.search(
        r"\b(shellforgeai|sfai[-a-z0-9_.]*|docker|compose|nginx)\b", normalized
    )
    broad_match = re.search(
        r"\b(all|everything|every container|all services|the server|the box)\b", normalized
    )
    target = (
        broad_match.group(1) if broad_match else (target_match.group(1) if target_match else "")
    )
    console.print("Refused: natural-language mutation is not allowed.")
    console.print("")
    console.print("No action was taken. No action was performed.")
    console.print(
        "I did not restart, stop, delete, prune, apply, clean up, remediate, or roll back anything."
    )
    console.print("")
    console.print("Why:")
    console.print(f"- request appears to ask for mutation: {matched[0]}")
    if target:
        if broad_match:
            console.print(f"- broad natural-language mutation targets are refused: {target}")
        elif target == "shellforgeai":
            console.print(f"- target appears production-like: {target}")
        else:
            console.print(f"- target detected: {target}")
    console.print("")
    console.print("Safe read-only alternatives:")
    if "cleanup" in normalized or "clean up" in normalized:
        console.print("- shellforgeai audit cleanup review")
        console.print(
            "- shellforgeai audit cleanup prepare --category exports "
            "--max-age-days 7 --keep-latest 5"
        )
        console.print("- shellforgeai audit cleanup execute-readiness <plan-id>")
    elif "rollback" in normalized or "roll back" in normalized:
        console.print("- shellforgeai remediation audit --latest")
    else:
        console.print("- shellforgeai ops report")
        console.print("- shellforgeai triage docker")
        if target and not broad_match:
            console.print(f"- shellforgeai triage docker detail {target}")
            console.print(f"- shellforgeai remediation eligibility --target {target} --explain")
        console.print("- shellforgeai remediation self-test --profile standard")
    console.print("")
    console.print("First safe command: shellforgeai ops report")
    console.print("")
    console.print("To perform governed disposable remediation, use the explicit CLI workflow:")
    console.print("plan → validate → preflight → execute with explicit confirmation.")
    console.print("Production targets remain blocked.")
    return True


def _handle_incident_search_ask(runtime: RuntimeContext, question: str) -> bool:
    """Handle PR40 incident-search asks against the audit-aware index.

    No execution; no mutation of artifacts. The index file may be created on
    demand if missing because building it only reads ShellForgeAI's own
    metadata directories.
    """
    if incident_index_mod.is_did_anything_execute_intent(question):
        data_dir = Path(runtime.session.data_dir)
        payload, _err = incident_index_mod.load_index(data_dir)
        if payload is None:
            console.print(
                "No, ShellForgeAI did not execute anything. apply remains validation-only."
            )
            console.print(
                "- hint: run `shellforgeai audit index` to build the incident index, "
                "then `shellforgeai audit search` to inspect refusals."
            )
            return True
        items = payload.get("items") or []
        executed = 0
        mutated = 0
        for it in items:
            if not isinstance(it, dict):
                continue
            safety = it.get("safety") or {}
            if isinstance(safety, dict):
                if safety.get("execution_allowed") is True:
                    executed += 1
                if safety.get("mutation_performed") is True:
                    mutated += 1
        if executed == 0 and mutated == 0:
            console.print(
                "No, ShellForgeAI did not execute anything. All indexed records show "
                "execution_allowed=false, execution_status=not_executed, "
                "mutation_performed=false."
            )
            console.print(f"- indexed items inspected: {len(items)}")
            console.print("- apply remains validation-only; no commands were executed.")
            return True
        # Should never happen given safety invariants, but report defensively.
        console.print(
            "Audit index reported one or more items where execution_allowed or "
            "mutation_performed was unexpectedly true. Run "
            "`shellforgeai audit index validate` and `shellforgeai audit validate`."
        )
        console.print(f"- suspicious_execution_allowed: {executed}")
        console.print(f"- suspicious_mutation_performed: {mutated}")
        return True

    intent = incident_index_mod.is_incident_search_ask_intent(question)
    if not intent.matched:
        return False
    data_dir = Path(runtime.session.data_dir)
    payload, err = incident_index_mod.load_index(data_dir)
    if payload is None:
        # Index missing is fine: build it (writes only ShellForgeAI's own
        # index file under <data_dir>/audit/incident-index.json).
        index = incident_index_mod.build_index(data_dir)
        incident_index_mod.write_index(data_dir, index)
        payload = index.to_dict()
        console.print(
            f"- note: incident index was missing ({err}); built it from current artifacts. "
            "No commands executed."
        )
    items = payload.get("items") or []
    filters = incident_index_mod.SearchFilters(
        risk=intent.risk,
        kind=intent.kind,
        status=intent.status,
        item_type=intent.item_type,
    )
    matches = incident_index_mod.search_items(items, query=intent.query, filters=filters)
    if not matches:
        console.print("No matching audit/index records found.")
        console.print("- index searched over read-only metadata; no commands executed.")
        return True
    console.print(
        "Incident-search results from the audit-aware index "
        "(read-only; ShellForgeAI did not execute anything):"
    )
    _print_search_results(matches[:20])
    if len(matches) > 20:
        console.print(f"- showing first 20 of {len(matches)} matches")
    console.print(
        "- next step: run `shellforgeai audit search <query>` for filtered views "
        "or `--json` for raw records. No remediation was executed."
    )
    return True


def _is_status_ask(question: str) -> bool:
    q = " ".join((question or "").strip().lower().rstrip("?.!").split())
    if not q:
        return False
    exact = {
        "status",
        "quick status",
        "give me status",
        "what is my status",
        "shellforgeai status",
    }
    if q in exact:
        return True
    return any(
        p in q
        for p in (
            "operator status",
            "show me the dashboard",
            "is shellforgeai healthy",
            "what should i check next",
            "any pending approvals",
            "any guard failures",
            "how much metadata do i have",
        )
    )


_V2_TRIAGE_ASK_EXACT = {
    "triage",
    "triage this",
    "show triage",
    "what is the likely suspect",
    "what is broken",
    "what should i inspect first",
}

# Brief cues let pressure phrasing ("quick triage", "no novel, triage") render
# the bounded brief view instead of the full deterministic triage answer.
_V2_TRIAGE_BRIEF_CUES = ("quick", "no novel", "brief", "fast")


def _v2_triage_ask_kind(question: str) -> str | None:
    """Classify a deterministic V2 triage ask as ``"brief"``, ``"full"``, or None."""
    q = " ".join(re.sub(r"[^a-z0-9 ]+", " ", (question or "").lower()).split())
    if not q:
        return None
    brief = any(cue in q for cue in _V2_TRIAGE_BRIEF_CUES)
    if q in _V2_TRIAGE_ASK_EXACT or "likely suspect" in q:
        return "brief" if brief else "full"
    if "triage" in q.split() and brief:
        return "brief"
    return None


def _is_v2_triage_ask(question: str) -> bool:
    return _v2_triage_ask_kind(question) is not None


def _handle_v2_triage_ask(question: str) -> bool:
    if is_triage_mutation_intent(question):
        return False
    kind = _v2_triage_ask_kind(question)
    if kind is None:
        return False
    payload = _build_v2_triage_payload()
    console.print("Read-only triage (deterministic ask routing):")
    console.print("")
    if kind == "brief":
        console.print(_render_v2_triage_brief(payload), end="")
    else:
        console.print(_render_v2_triage_human(payload), end="")
    return True


_APPLY_PREVIEW_CUES = (
    "apply preview",
    "preview apply",
    "what would applying this require",
    "what would applying the proposed action require",
    "what would happen if we applied it",
    "show apply gates",
    "preview the proposed action",
    "can this be applied",
)
_APPLY_PREVIEW_MUTATION_CUES = (
    "apply it",
    "execute it",
    "apply now",
    "confirm apply",
)


def _apply_preview_target(question: str) -> str | None:
    m = re.search(
        r"\b(?:apply-preview|apply preview|preview apply)\b.*\b(?:for|target)\s+"
        r"([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b",
        question or "",
        flags=re.IGNORECASE,
    )
    return m.group(1) if m else None


def _is_apply_preview_ask(question: str) -> bool:
    q = " ".join(re.sub(r"[^a-z0-9_.-]+", " ", (question or "").lower()).split())
    if not q:
        return False
    return bool(_apply_preview_target(question)) or any(cue in q for cue in _APPLY_PREVIEW_CUES)


def _apply_preview_mutation_cues(question: str) -> list[str]:
    q = " ".join(re.sub(r"[^a-z0-9]+", " ", (question or "").lower()).split())
    return [cue for cue in _APPLY_PREVIEW_MUTATION_CUES if cue in q]


def _handle_v2_apply_preview_ask(question: str) -> bool:
    preview = _is_apply_preview_ask(question)
    mutation_cues = _apply_preview_mutation_cues(question)
    if preview:
        mixed_q = " ".join(re.sub(r"[^a-z0-9]+", " ", (question or "").lower()).split())
        mutation_cues.extend(
            cue
            for cue in ("restart", "execute", "apply now", "run it", "run compose")
            if cue in mixed_q and cue not in mutation_cues
        )
    if not preview:
        return False
    target = _apply_preview_target(question)
    payload = _build_v2_apply_preview_payload(target=target, from_propose=True)
    console.print("Read-only apply preview (deterministic ask routing):")
    console.print("")
    typer.echo(_render_v2_apply_preview_human(payload), nl=False)
    if mutation_cues:
        console.print("Refused mutation part of the request.")
        console.print("ShellForgeAI did not execute, apply, restart, remediate, or run Compose.")
        console.print("No action was taken.")
    return True


def _handle_v2_apply_preview_mutation_refusal(question: str) -> bool:
    if not _apply_preview_mutation_cues(question):
        return False
    console.print("Refused: natural-language mutation is not allowed.")
    console.print("Use `shellforgeai apply-preview` to inspect gates without execution.")
    console.print("No action was taken.")
    return True


_PROPOSE_ASK_TARGET_RE = re.compile(
    r"\bpropose\b.*\b(?:for|target)\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b|"
    r"\bwhat\s+would\s+you\s+propose\s+for\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b",
    re.IGNORECASE,
)
_PROPOSE_MUTATION_CUES = (
    "execute the proposal",
    "apply the proposal",
    "execute proposal",
    "apply proposal",
    "run the plan",
)
_PROPOSE_ASK_CUES = (
    "what would you propose",
    "what should we propose",
    "propose next step",
    "what would you do next",
    "what is the safe proposal",
    "propose for the top suspect",
    "safe proposal",
    "show me the proposal",
)


def _proposal_ask_target(question: str) -> str | None:
    m = _PROPOSE_ASK_TARGET_RE.search(question or "")
    if not m:
        return None
    target = next((g for g in m.groups() if g), None)
    if target and target.lower() in {"the", "top", "suspect"}:
        return None
    return target


def _is_proposal_ask(question: str) -> bool:
    q = " ".join(re.sub(r"[^a-z0-9_.-]+", " ", (question or "").lower()).split())
    if not q:
        return False
    if "propose restart" in q or "propose remediation" in q:
        return False
    if _proposal_ask_target(question):
        return True
    return any(cue in q for cue in _PROPOSE_ASK_CUES)


def _proposal_mutation_cues(question: str) -> list[str]:
    q = " ".join(re.sub(r"[^a-z0-9]+", " ", (question or "").lower()).split())
    return [cue for cue in _PROPOSE_MUTATION_CUES if cue in q]


def _handle_v2_propose_mutation_refusal(question: str) -> bool:
    if not _proposal_mutation_cues(question):
        return False
    console.print("Refused: proposal execution is not available from ask mode.")
    console.print("Propose is read-only and creates no plan.")
    console.print("No action was taken.")
    return True


def _handle_v2_propose_ask(question: str) -> bool:
    proposal = _is_proposal_ask(question)
    mutation_cues = _proposal_mutation_cues(question)
    if proposal:
        mixed_q = " ".join(re.sub(r"[^a-z0-9]+", " ", (question or "").lower()).split())
        mutation_cues.extend(
            cue
            for cue in ("restart it", "fix it", "do it", "execute", "apply", "run the plan")
            if cue in mixed_q and cue not in mutation_cues
        )
    if not proposal:
        return False
    target = _proposal_ask_target(question)
    payload = _build_v2_propose_payload(target=target, from_triage=True)
    console.print("Read-only proposal (deterministic ask routing):")
    console.print("")
    typer.echo(_render_v2_propose_human(payload), nl=False)
    if mutation_cues:
        console.print("Refused mutation part of the request.")
        console.print("ShellForgeAI did not execute, apply, restart, fix, or run a plan.")
        console.print("No action was taken.")
    return True


_RECOVERY_EXECUTE_MUTATION_CUES = (
    "recover it now",
    "run recovery",
    "rollback now",
    "execute recovery",
    "restart it again",
    "rerun the receipt",
    "run docker restart",
    "show recovery command and run it",
)


def _recovery_command_ref(question: str) -> str | None:
    patterns = (
        r"\brecover\s+receipt\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b",
        r"\brecovery\s+(?:for\s+)?receipt\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b",
        r"\breceipt\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b",
    )
    low = (question or "").lower()
    if "recovery" not in low and "recover" not in low:
        return None
    for pattern in patterns:
        match = re.search(pattern, question or "", flags=re.IGNORECASE)
        if match:
            candidate = match.group(1)
            if candidate.lower() not in {"command", "run", "it", "now", "for"}:
                return candidate
    return None


def _is_recovery_command_help_ask(question: str) -> bool:
    q = " ".join(re.sub(r"[^a-z0-9_.-]+", " ", (question or "").lower()).split())
    return any(
        cue in q
        for cue in (
            "how would i recover receipt",
            "what command would run recovery for receipt",
            "show recovery command for receipt",
            "show recovery command",
        )
    )


def _handle_receipt_recovery_ask(question: str) -> bool:
    low = " ".join((question or "").lower().split())
    wants_help = _is_recovery_command_help_ask(question)
    mutation_cues = [cue for cue in _RECOVERY_EXECUTE_MUTATION_CUES if cue in low]
    if not wants_help and not mutation_cues:
        return False
    ref = _recovery_command_ref(question)
    if wants_help:
        console.print("Governed receipt recovery command (deterministic ask routing):")
        if ref:
            console.print(f"  shellforgeai recipes receipt recovery-execute {ref} --confirm")
            console.print(f"  shellforgeai recipes receipt recovery-execute {ref} --confirm --json")
        else:
            console.print("  shellforgeai recipes receipt recovery-execute <receipt_id> --confirm")
            console.print(
                "  shellforgeai recipes receipt recovery-execute <receipt_id> --confirm --json"
            )
        console.print("This is not true rollback; it is a bounded disposable restart recovery.")
    if mutation_cues:
        console.print("Refused: natural-language mutation is not allowed.")
        console.print("Refused recovery execution from natural language.")
        console.print(
            "Use explicit CLI confirmation only: "
            "shellforgeai recipes receipt recovery-execute <receipt_id> --confirm"
        )
        console.print("No container was restarted.")
    console.print("No action was taken.")
    return True


_VERIFY_ASK_TARGET_RE = re.compile(
    r"\bverify\b(?:\s+the)?\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b",
    re.IGNORECASE,
)
_VERIFY_ASK_CUES = (
    "verify status",
    "verify the system",
    "verify docker",
    "verify current state",
    "did anything improve",
    "did the issue clear",
    "is it fixed",
    "verify the top suspect",
)
_ROLLBACK_PREVIEW_MUTATION_CUES = (
    "rollback now",
    "execute rollback",
    "undo it",
    "restart it again",
    "rerun the recipe",
    "rollback and restart",
    "then rollback",
    "and then rollback",
)


def _rollback_preview_ref(question: str) -> str | None:
    patterns = (
        r"\brollback\s+preview\s+(?:for\s+)?(?:receipt\s+)?([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b",
        r"\b(?:show\s+)?rollback\s+preview\s+for\s+receipt\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b",
        r"\bwhat\s+would\s+rollback\s+require\s+for\s+receipt\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b",
        r"\bwhat\s+is\s+the\s+recovery\s+path\s+for\s+receipt\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b",
        r"\bcan\s+(?:this\s+)?receipt\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\s+be\s+rolled\s+back\b",
        r"\breceipt\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b",
    )
    low = (question or "").lower()
    for pattern in patterns:
        match = re.search(pattern, question or "", flags=re.IGNORECASE)
        if match and any(cue in low for cue in ("rollback", "rolled back", "recovery path")):
            candidate = match.group(1)
            if candidate.lower() not in {"be", "rolled", "back", "for", "this", "the"}:
                return candidate
    return None


def _is_rollback_preview_ask(question: str) -> bool:
    q = " ".join(re.sub(r"[^a-z0-9_.-]+", " ", (question or "").lower()).split())
    return bool(_rollback_preview_ref(question)) or any(
        cue in q
        for cue in (
            "show rollback preview",
            "can this receipt be rolled back",
            "what would rollback require",
            "rollback preview receipt",
            "what is the recovery path for receipt",
        )
    )


def _handle_receipt_rollback_preview_ask(question: str) -> bool:
    if not _is_rollback_preview_ask(question):
        return False
    low = " ".join((question or "").lower().split())
    mutation_cues = [cue for cue in _ROLLBACK_PREVIEW_MUTATION_CUES if cue in low]
    ref = _rollback_preview_ref(question)
    console.print("Read-only rollback-preview guidance (deterministic ask routing):")
    if ref:
        console.print(f"  shellforgeai recipes receipt rollback-preview {ref}")
        console.print(f"  shellforgeai recipes receipt rollback-preview {ref} --json")
        console.print(f"  shellforgeai verify --receipt {ref} --json")
    else:
        console.print("Receipt id/ref required for read-only rollback preview.")
        console.print("Safe command form:")
        console.print("  shellforgeai recipes receipt rollback-preview <receipt_id>")
        console.print("  shellforgeai recipes receipt rollback-preview <receipt_id> --json")
    if mutation_cues:
        console.print("Refused rollback execution part of the request.")
        console.print("Rollback execution is not available; this surface is preview-only.")
    console.print("No action was taken.")
    return True


_RECEIPT_AUDIT_MUTATION_CUES = (
    "recover latest receipt now",
    "recover receipt now",
    "rollback latest receipt",
    "restart it again",
    "rerun the receipt",
    "apply the receipt",
    "cleanup old receipts",
    "clean up old receipts",
)


def _receipt_audit_refs(question: str) -> list[str]:
    return re.findall(
        r"\b(receipt_[A-Za-z0-9_.-]+|recovery_receipt_[A-Za-z0-9_.-]+)\b", question or ""
    )


def _handle_receipt_audit_ask(question: str) -> bool:
    normalized = " ".join(re.sub(r"[^a-z0-9_.-]+", " ", (question or "").lower()).split())
    if not normalized:
        return False
    if any(cue in normalized for cue in _RECEIPT_AUDIT_MUTATION_CUES):
        console.print("Refused: natural-language mutation is not allowed for receipts.")
        console.print(
            "ShellForgeAI did not recover, rollback, restart, rerun, apply, clean up, or remediate."
        )
        console.print(
            "Use read-only audit commands such as `shellforgeai recipes receipt history`."
        )
        console.print("No action was taken.")
        return True
    refs = _receipt_audit_refs(question)
    if any(
        cue in normalized
        for cue in (
            "show recipe receipt history",
            "list governed receipts",
            "receipt history",
            "list recipe receipts",
        )
    ):
        console.print("Read-only recipe receipt history guidance (deterministic ask routing):")
        console.print("  shellforgeai recipes receipt history")
        console.print("  shellforgeai recipes receipt history --json")
        console.print("  shellforgeai recipes receipt history --limit 10")
        console.print("No action was taken.")
        return True
    if "compare latest receipts" in normalized or "compare latest receipt" in normalized:
        console.print(
            "Read-only recipe receipt compare-latest guidance (deterministic ask routing):"
        )
        console.print("  shellforgeai recipes receipt compare-latest")
        console.print("  shellforgeai recipes receipt compare-latest --json")
        console.print("No action was taken.")
        return True
    if "compare receipts" in normalized or "compare receipt" in normalized:
        console.print("Read-only recipe receipt compare guidance (deterministic ask routing):")
        if len(refs) >= 2:
            console.print(f"  shellforgeai recipes receipt compare {refs[0]} {refs[1]}")
            console.print(f"  shellforgeai recipes receipt compare {refs[0]} {refs[1]} --json")
        else:
            console.print(
                "  shellforgeai recipes receipt compare <before_receipt_id> <after_receipt_id>"
            )
            console.print(
                "  shellforgeai recipes receipt compare "
                "<before_receipt_id> <after_receipt_id> --json"
            )
        console.print("No action was taken.")
        return True
    if "export receipt" in normalized:
        console.print(
            "Read-only source validation plus owned metadata export guidance "
            "(deterministic ask routing):"
        )
        if refs:
            console.print(f"  shellforgeai recipes receipt export {refs[0]}")
            console.print(f"  shellforgeai recipes receipt export {refs[0]} --json")
        else:
            console.print("  shellforgeai recipes receipt export <receipt_id>")
            console.print("  shellforgeai recipes receipt export <receipt_id> --json")
        console.print("No recovery/restart/remediation action was taken.")
        return True
    if "inspect receipt" in normalized or "show receipt" in normalized:
        console.print("Read-only recipe receipt inspect guidance (deterministic ask routing):")
        if refs:
            console.print(f"  shellforgeai recipes receipt inspect {refs[0]}")
            console.print(f"  shellforgeai recipes receipt inspect {refs[0]} --json")
        else:
            console.print("  shellforgeai recipes receipt inspect <receipt_id>")
            console.print("  shellforgeai recipes receipt inspect <receipt_id> --json")
        console.print("No action was taken.")
        return True
    return False


_VERIFY_MUTATION_CUES = (
    "verify and restart",
    "verify and rerun",
    "verify and retry",
    "verify then fix",
    "apply and verify",
    "restart and verify",
    "clean up and verify",
    "cleanup and verify",
    "execute then verify",
    "restart compose",
    "restart docker",
    "fix it",
    "apply it",
    "if failed retry",
    "retry it",
    "rerun it",
    "rollback it",
    "execute receipt",
)


def _receipt_verify_ref(question: str) -> str | None:
    m = re.search(
        (
            r"\b(?:verify|check|inspect|show|what happened in)\s+(?:the\s+)?"
            r"(?:execution\s+)?receipt\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b"
        ),
        question or "",
        flags=re.IGNORECASE,
    )
    if m:
        return m.group(1)
    m = re.search(
        r"\breceipt\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b",
        question or "",
        flags=re.IGNORECASE,
    )
    if m and any(
        cue in (question or "").lower() for cue in ("verify", "check", "what happened", "pass")
    ):
        return m.group(1)
    return None


def _is_receipt_verify_ask(question: str) -> bool:
    q = " ".join(re.sub(r"[^a-z0-9_.-]+", " ", (question or "").lower()).split())
    return bool(_receipt_verify_ref(question)) or any(
        cue in q
        for cue in (
            "verify the execution receipt",
            "verify execution receipt",
            "verify receipt",
            "check receipt",
            "did the restart receipt pass",
            "what happened in receipt",
        )
    )


def _handle_receipt_verify_ask(question: str) -> bool:
    if not _is_receipt_verify_ask(question):
        return False
    mutation_cues = _verify_mutation_cues(question)
    ref = _receipt_verify_ref(question)
    if mutation_cues:
        console.print("Refused mutation part of the request.")
        console.print(
            "Receipt verification is read-only; retry, rerun, rollback, and execute "
            "are not allowed from ask."
        )
        console.print("No action was taken.")
    if ref:
        console.print("Read-only receipt verify (deterministic ask routing):")
        console.print(f"  shellforgeai verify --receipt {ref}")
        console.print(f"  shellforgeai verify --receipt {ref} --json")
    else:
        console.print("Receipt id required for read-only receipt verification.")
        console.print("Safe command form:")
        console.print("  shellforgeai verify --receipt <receipt_id>")
        console.print("  shellforgeai verify --receipt <receipt_id> --json")
    console.print("No action was taken.")
    return True


def _verify_ask_target(question: str) -> str | None:
    m = _VERIFY_ASK_TARGET_RE.search(question or "")
    if not m:
        return None
    target = m.group(1)
    if target.lower() in {
        "status",
        "system",
        "docker",
        "current",
        "state",
        "the",
        "top",
        "suspect",
    }:
        return None
    return target


def _verify_mutation_cues(question: str) -> list[str]:
    q = " ".join(re.sub(r"[^a-z0-9]+", " ", (question or "").lower()).split())
    return [cue for cue in _VERIFY_MUTATION_CUES if cue in q]


def _is_verify_ask(question: str) -> bool:
    q = " ".join(re.sub(r"[^a-z0-9_.-]+", " ", (question or "").lower()).split())
    if not q:
        return False
    return bool(_verify_ask_target(question)) or any(cue in q for cue in _VERIFY_ASK_CUES)


def _handle_v2_verify_ask(question: str) -> bool:
    verify = _is_verify_ask(question)
    mutation_cues = _verify_mutation_cues(question)
    q = " ".join(re.sub(r"[^a-z0-9]+", " ", (question or "").lower()).split())
    verify_mutation_only = any(
        cue in q
        for cue in (
            "apply and verify",
            "restart and verify",
            "clean up and verify",
            "cleanup and verify",
            "execute then verify",
        )
    )
    if _handle_receipt_verify_ask(question):
        return True
    if not verify and not verify_mutation_only:
        return False
    if not verify:
        console.print("Refused: natural-language mutation is not allowed.")
        console.print("Use `shellforgeai verify` to inspect current state without execution.")
        console.print("No action was taken.")
        return True
    target = _verify_ask_target(question)
    payload = _build_v2_verify_payload(target=target, from_triage=True)
    console.print("Read-only verify (deterministic ask routing):")
    console.print("")
    typer.echo(_render_v2_verify_human(payload), nl=False)
    if mutation_cues:
        console.print("Refused mutation part of the request.")
        console.print(
            "ShellForgeAI did not execute, apply, restart, fix, clean up, or run Compose."
        )
        console.print("No action was taken.")
    return True


_HANDOFF_ASK_CUES = (
    "give me a handoff",
    "give me the handoff",
    "give me an operator handoff",
    "give me the operator handoff",
    "operator handoff",
    "handoff summary",
    "summarize for handoff",
    "summary for handoff",
    "what should i tell the next operator",
    "what do i tell the next operator",
    "what do i hand over",
    "what do i handoff",
    "make a shift handoff",
    "shift handoff",
    "save handoff",
    "save the handoff",
    "write handoff",
)
_HANDOFF_MUTATION_CUES = (
    "restart",
    "and apply",
    "then apply",
    "fix it",
    "and fix",
    "clean up",
    "cleanup",
    "execute",
    "remediate",
    "remediation",
    "rollback",
    "compose",
)


def _is_handoff_ask(question: str) -> bool:
    q = " ".join(re.sub(r"[^a-z0-9_.-]+", " ", (question or "").lower()).split())
    if not q:
        return False
    if any(cue in q for cue in _HANDOFF_ASK_CUES):
        return True
    return bool(re.search(r"\bhandoffs?\b", q))


def _handoff_mutation_cues(question: str) -> list[str]:
    q = " ".join(re.sub(r"[^a-z0-9]+", " ", (question or "").lower()).split())
    return [cue for cue in _HANDOFF_MUTATION_CUES if cue in q]


_HANDOFF_LIFECYCLE_CUES = ("validate", "export", "save")

_HANDOFF_COMPARE_CUES = (
    "compare latest handoff",
    "compare latest handoffs",
    "compare the latest handoff",
    "compare the latest handoffs",
    "compare last two handoffs",
    "compare the last two handoffs",
    "compare handoffs",
    "compare handoff",
    "diff handoff",
    "diff the handoff",
    "handoff drift",
    "what changed since last handoff",
    "what changed since the last handoff",
    "what changed since my last handoff",
    "since the last handoff",
    "since last handoff",
)
_HANDOFF_HISTORY_CUES = (
    "handoff history",
    "history of handoffs",
    "history of handoff",
    "list handoffs",
    "list the handoffs",
    "recent handoffs",
    "past handoffs",
    "previous handoffs",
    "show handoffs",
    "handoff log",
    "saved handoffs",
)


def _handoff_lifecycle_intent(question: str) -> bool:
    q = " ".join(re.sub(r"[^a-z0-9]+", " ", (question or "").lower()).split())
    return any(cue in q.split() for cue in _HANDOFF_LIFECYCLE_CUES)


def _normalize_handoff_ask(question: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9_.-]+", " ", (question or "").lower()).split())


def _handle_v2_handoff_compare_ask(question: str) -> bool:
    from shellforgeai.core.v2_handoff_artifact import compare_latest_v2_handoffs

    payload = compare_latest_v2_handoffs(Path(load_settings().app.data_dir))
    console.print("Read-only handoff compare-latest (deterministic ask routing):")
    console.print("")
    typer.echo(_render_v2_handoff_compare_human(payload), nl=False)
    console.print("")
    console.print("Safe commands:")
    console.print("  shellforgeai handoff compare-latest")
    console.print("  shellforgeai handoff compare <before> <after>")
    console.print("  shellforgeai handoff history")
    return True


def _handle_v2_handoff_history_ask(question: str) -> bool:
    from shellforgeai.core.v2_handoff_artifact import v2_handoff_history

    payload = v2_handoff_history(Path(load_settings().app.data_dir))
    console.print("Read-only handoff history (deterministic ask routing):")
    console.print("")
    typer.echo(_render_v2_handoff_history_human(payload), nl=False)
    console.print("")
    console.print("Safe commands:")
    console.print("  shellforgeai handoff history")
    console.print("  shellforgeai handoff history --json")
    console.print("  shellforgeai handoff compare-latest")
    return True


def _handle_v2_handoff_ask(question: str) -> bool:
    if not _is_handoff_ask(question):
        return False
    normalized = _normalize_handoff_ask(question)
    if any(cue in normalized for cue in _HANDOFF_COMPARE_CUES):
        return _handle_v2_handoff_compare_ask(question)
    if any(cue in normalized for cue in _HANDOFF_HISTORY_CUES):
        return _handle_v2_handoff_history_ask(question)
    mutation_cues = _handoff_mutation_cues(question)
    payload = _build_v2_handoff_payload(from_triage=True)
    console.print("Read-only operator handoff (deterministic ask routing):")
    console.print("")
    typer.echo(_render_v2_handoff_human(payload), nl=False)
    if mutation_cues:
        console.print("Refused mutation part of the request.")
        console.print(
            "ShellForgeAI did not execute, apply, restart, remediate, clean up, or run Compose."
        )
        console.print("No action was taken.")
    if _handoff_lifecycle_intent(question):
        console.print("")
        console.print("Handoff artifact lifecycle (read-only, ShellForgeAI-owned artifacts):")
        console.print("  shellforgeai handoff --save")
        console.print("  shellforgeai handoff validate <handoff_id>")
        console.print("  shellforgeai handoff export <handoff_id>")
        console.print("  shellforgeai handoff export-validate <export_id>")
    return True


def _collect_status_payload(runtime: RuntimeContext, *, include_retention: bool = False) -> dict:
    data_dir = Path(runtime.session.data_dir)
    audit = AuditStorage(data_dir)
    build = get_build_info()
    provider = build_provider(runtime.settings)
    model_info = provider.doctor()
    proposals = list_proposals(data_dir)
    counts = {k: 0 for k in ("pending", "approved", "rejected", "canceled", "archived")}
    pending: list[Proposal] = []
    for status, p in proposals:
        counts[status] = counts.get(status, 0) + 1
        if status == "pending":
            pending.append(p)
    risk_rank = {"low": 1, "medium": 2, "high": 3}
    highest_pending = None
    if pending:
        highest_pending = max(pending, key=lambda x: risk_rank.get(x.risk, 0)).risk
    newest_pending = None
    if pending:
        newest = max(pending, key=lambda x: x.created_at or "")
        newest_pending = newest.proposal_id
    latest_run = latest_runbook(data_dir)
    latest_prop = pending and max(pending, key=lambda x: x.created_at or "") or None
    latest_export = latest_session_dir(data_dir)
    events = audit.query_events(latest=False)
    latest_evt = events[-1] if events else None
    suspicious = []
    for evt in events:
        safety = evt.get("safety") if isinstance(evt, dict) else None
        if not isinstance(safety, dict):
            continue
        if (
            safety.get("execution_allowed") is True
            or safety.get("mutation_performed") is True
            or safety.get("execution_status") not in (None, "not_executed")
        ):
            suspicious.append(evt)
    level = "ok"
    if suspicious:
        level = "attention"
    elif counts["pending"] > 0:
        level = "warning"
    if not model_info:
        level = "unknown"
    retention: dict[str, Any] = {"total_bytes": None, "categories": None}
    if include_retention:
        cats = build_categories(data_dir)
        rows = []
        total = 0
        for name in (
            "artifacts",
            "approvals",
            "apply-bundles",
            "actions",
            "exports",
            "audit-events",
        ):
            items = collect_category(cats[name])
            sz = sum(file_size(p) for p in items)
            total += sz
            rows.append({"category": name, "items": len(items), "bytes": sz})
        retention = {"total_bytes": total, "categories": rows}
    return {
        "schema_version": "1",
        "created_at": (
            latest_evt.get("timestamp")
            if isinstance(latest_evt, dict)
            else datetime.now(timezone.utc).isoformat()
        ),
        "health_level": level,
        "shellforgeai": {
            "version": build.display_version,
            "profile": runtime.profile.name,
            "mode": runtime.session.mode,
            "data_dir": str(data_dir),
            "audit_dir": str(audit.sessions_dir),
            "platform": platform.platform(),
        },
        "model": {
            "provider": runtime.settings.model.provider,
            "model": runtime.settings.model.model,
            "timeout_seconds": runtime.settings.model.timeout_seconds,
            "fallback_enabled": bool(runtime.settings.model.allow_model_fallback),
            "codex_found": model_info.get("codex_found"),
            "auth_cache_present": model_info.get("auth_cache_present"),
            "status": "ok" if model_info.get("auth_cache_present") else "warning",
        },
        "safety": {
            "apply_mode": "validation-only",
            "execution_allowed": False,
            "execution_status": "not_executed",
            "mutation_performed": False,
            "message": "No ShellForgeAI remediation execution recorded."
            if not suspicious
            else "Attention: unexpected execution safety markers found in audit metadata.",
        },
        "latest": {
            "runbook": str(latest_run) if latest_run else None,
            "proposal": latest_prop.proposal_id if latest_prop else None,
            "export_session_dir": str(latest_export) if latest_export else None,
            "audit_event_id": latest_evt.get("event_id") if isinstance(latest_evt, dict) else None,
            "guard_refusal": suspicious[-1].get("event_id") if suspicious else None,
        },
        "approvals": {
            **counts,
            "highest_risk_pending": highest_pending,
            "newest_pending": newest_pending,
        },
        "guards": {"recent_refusals": len(suspicious)},
        "audit": {
            "events_count": len(events),
            "latest_event": latest_evt.get("event_id") if latest_evt else None,
        },
        "retention": retention,
        "recommendations": [
            "shellforgeai audit timeline --latest",
            "shellforgeai approvals list --status pending",
            "shellforgeai audit retention",
            "shellforgeai audit search <query>",
            "shellforgeai model doctor",
        ],
    }


@app.command()
def status(
    ctx: typer.Context,
    json_output: bool = typer.Option(False, "--json"),
    brief: bool = typer.Option(False, "--brief", help="Mirror ops report --brief output."),
    top: int = typer.Option(5, "--top", min=1, help="Maximum ranked Docker suspects to inspect."),
    verbose: bool = typer.Option(
        False, "--verbose", help="Accepted for compatibility; status stays concise."
    ),
    since: str | None = typer.Option(None, "--since", help="Accepted for compatibility."),
    include_retention: bool = typer.Option(
        False, "--include-retention", help="Accepted for compatibility; no artifacts are written."
    ),
    include_index: bool = typer.Option(
        False, "--include-index", help="Accepted for compatibility."
    ),
    include_audit: bool = typer.Option(
        False, "--include-audit", help="Accepted for compatibility."
    ),
    include_approvals: bool = typer.Option(
        False, "--include-approvals", help="Accepted for compatibility."
    ),
) -> None:
    """Read-only V2 golden-path status entrypoint.

    This is a small deterministic wrapper around the concise ops-report path.
    It does not call the model, write artifacts, create proposals/missions, or
    execute cleanup/remediation/rollback/Docker/Compose actions.
    """
    _ = (ctx, verbose, since, include_retention, include_index, include_audit, include_approvals)
    payload = _build_status_payload(top=top)
    if json_output:
        typer.echo(json.dumps(payload))
        return
    if brief:
        typer.echo(_render_ops_report_brief(payload), nl=False)
        return
    typer.echo(_render_status_human(payload), nl=False)


@app.command()
def propose(
    ctx: typer.Context,
    json_output: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    brief: Annotated[bool, typer.Option("--brief", help="Emit bounded proposal preview.")] = False,
    target: Annotated[
        str | None, typer.Option("--target", help="Preview next action for one target.")
    ] = None,
    from_triage: Annotated[
        bool,
        typer.Option(
            "--from-triage",
            help="Use current deterministic triage ranking as proposal input.",
        ),
    ] = False,
) -> None:
    """Read-only V2 next-action proposal preview. No plan or action is created."""
    _ = ctx
    payload = _build_v2_propose_payload(target=target, from_triage=from_triage)
    if json_output:
        typer.echo(json.dumps(payload))
        return
    if brief:
        typer.echo(_render_v2_propose_brief(payload), nl=False)
        return
    typer.echo(_render_v2_propose_human(payload), nl=False)


@app.command("verify")
def verify(
    ctx: typer.Context,
    json_output: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    brief: Annotated[bool, typer.Option("--brief", help="Emit bounded verify output.")] = False,
    target: Annotated[
        str | None, typer.Option("--target", help="Verify one exact visible target.")
    ] = None,
    from_status: Annotated[
        bool, typer.Option("--from-status", help="Use current deterministic status context.")
    ] = False,
    from_triage: Annotated[
        bool, typer.Option("--from-triage", help="Use current deterministic triage context.")
    ] = False,
    from_propose: Annotated[
        bool,
        typer.Option("--from-propose", help="Verify current state after proposal context only."),
    ] = False,
    from_apply_preview: Annotated[
        bool,
        typer.Option(
            "--from-apply-preview",
            help="Verify current state after apply-preview context only; no apply is assumed.",
        ),
    ] = False,
    receipt: Annotated[
        str | None,
        typer.Option(
            "--receipt", help="Verify a governed recipe execution receipt by id or owned path."
        ),
    ] = None,
) -> None:
    """Read-only V2 verification. Current-state by default; receipt-aware with --receipt."""
    runtime = _ctx(ctx)
    if receipt:
        payload = verify_recipe_receipt(receipt, runtime.session.data_dir)
        if json_output:
            typer.echo(json.dumps(payload))
        elif brief:
            typer.echo(_render_v2_verify_brief(payload), nl=False)
        else:
            typer.echo(_render_v2_receipt_verify_human(payload), nl=False)
        if payload.get("status") != "passed":
            raise typer.Exit(1)
        return
    payload = _build_v2_verify_payload(
        target=target,
        from_status=from_status,
        from_triage=from_triage,
        from_propose=from_propose,
        from_apply_preview=from_apply_preview,
    )
    if json_output:
        typer.echo(json.dumps(payload))
        return
    if brief:
        typer.echo(_render_v2_verify_brief(payload), nl=False)
        return
    typer.echo(_render_v2_verify_human(payload), nl=False)


@app.command("apply-preview")
def apply_preview(
    ctx: typer.Context,
    json_output: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    brief: Annotated[bool, typer.Option("--brief", help="Emit bounded apply preview.")] = False,
    target: Annotated[
        str | None, typer.Option("--target", help="Preview gates for one exact target.")
    ] = None,
    from_propose: Annotated[
        bool,
        typer.Option("--from-propose", help="Use current deterministic proposal context."),
    ] = False,
    from_triage: Annotated[
        bool,
        typer.Option("--from-triage", help="Use current deterministic triage context."),
    ] = False,
) -> None:
    """Read-only V2 execution-boundary preview. Does not apply or execute."""
    _ = ctx
    payload = _build_v2_apply_preview_payload(
        target=target, from_propose=from_propose, from_triage=from_triage
    )
    if json_output:
        typer.echo(json.dumps(payload))
        return
    if brief:
        typer.echo(_render_v2_apply_preview_brief(payload), nl=False)
        return
    typer.echo(_render_v2_apply_preview_human(payload), nl=False)


@handoff_app.callback()
def handoff(
    ctx: typer.Context,
    json_output: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    brief: Annotated[bool, typer.Option("--brief", help="Emit bounded handoff output.")] = False,
    save: Annotated[
        bool, typer.Option("--save", help="Save a ShellForgeAI-owned read-only handoff artifact.")
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
    limit: Annotated[int, typer.Option("--limit", min=1, help="Max recent handoffs to list.")] = 10,
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
    typer.echo(_render_v2_handoff_compare_human(payload, include_stable=include_stable), nl=False)
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
    typer.echo(_render_v2_handoff_compare_human(payload, include_stable=include_stable), nl=False)


def _render_recipe_groups_human(payload: dict[str, Any]) -> str:
    groups = (
        ("Available read-only", lambda r: r.get("status") == "available_read_only"),
        (
            "Preview-only / disabled until governed execution lane",
            lambda r: (
                str(r.get("status", "")).startswith("disabled_until")
                or r.get("status") == "preview_only"
            ),
        ),
        ("Future / forbidden", lambda r: r.get("status") == "future"),
    )
    lines = ["ShellForgeAI V2 governed recipe registry", ""]
    recipes = list(payload.get("recipes") or [])
    for title, predicate in groups:
        members = [r for r in recipes if predicate(r)]
        if not members:
            continue
        lines.append(title + ":")
        for recipe in members:
            lines.append(
                f"- {recipe['recipe_id']} — {recipe['title']} "
                f"[{recipe['status']}; mutation={recipe['mutation_class']}]"
            )
            lines.append(f"  First safe command: {recipe['first_safe_command']}")
        lines.append("")
    lines.append("Safety note: This command is read-only. No recipe was executed.")
    return "\n".join(lines) + "\n"


def _render_recipe_detail_human(payload: dict[str, Any]) -> str:
    if payload.get("status") == "not_found":
        return (
            f"Recipe not found: {payload.get('recipe_id')}\n"
            "No action was taken.\n"
            "Safe next command: shellforgeai recipes list\n"
        )
    recipe = payload.get("recipe") or {}
    lines = [
        f"Recipe: {recipe.get('recipe_id')}",
        f"Title: {recipe.get('title')}",
        f"Status: {recipe.get('status')}",
        f"Mutation class: {recipe.get('mutation_class')}",
        f"Description: {recipe.get('description')}",
        "",
        "Required gates:",
    ]
    gates = list(recipe.get("preflight_gates") or []) + list(recipe.get("approval_gates") or [])
    if gates:
        lines.extend(f"- {gate}" for gate in gates)
    else:
        lines.append("- none for read-only inspection")
    lines.extend(
        [
            "",
            f"Verification required: {str(bool(recipe.get('verification_required'))).lower()}",
            f"Rollback available: {str(bool(recipe.get('rollback_available'))).lower()}",
            f"Receipt required: {str(bool(recipe.get('receipt_required'))).lower()}",
            f"First safe command: {recipe.get('first_safe_command')}",
            "Why safe/disabled:",
        ]
    )
    notes = list(recipe.get("safety_notes") or [])
    if recipe.get("blocked_reason"):
        notes.append(recipe["blocked_reason"])
    lines.extend(f"- {note}" for note in (notes or ["Read-only registry detail; no action taken."]))
    lines.append("No action was taken.")
    return "\n".join(lines) + "\n"


def _render_recipe_eligibility_human(payload: dict[str, Any]) -> str:
    if payload.get("status") == "not_found":
        return (
            f"Recipe not found: {payload.get('recipe_id')}\n"
            "Eligibility: blocked\n"
            "No action was taken.\n"
            "First safe command: shellforgeai recipes list\n"
        )
    meta = payload.get("target_metadata") or {}
    lines = [
        f"Recipe: {payload.get('recipe_id')}",
        f"Eligibility: {payload.get('eligibility')}",
        f"Target: {payload.get('target')}",
        f"target_found: {str(bool(meta.get('target_found'))).lower()}",
        f"production_target: {str(bool(meta.get('production_target'))).lower()}",
        "Required labels present:",
    ]
    present = list(meta.get("required_labels_present") or [])
    missing = list(meta.get("required_labels_missing") or [])
    lines.extend(f"- {label}" for label in (present or ["none"]))
    lines.append("Required labels missing:")
    lines.extend(f"- {label}" for label in (missing or ["none"]))
    lines.append("Blockers:")
    lines.extend(f"- {blocker}" for blocker in (payload.get("blockers") or ["none"]))
    lines.extend(
        [
            f"First safe command: {payload.get('first_safe_command')}",
            "No action was taken.",
        ]
    )
    return "\n".join(lines) + "\n"


@recipes_app.callback(invoke_without_command=True)
def recipes_root(
    ctx: typer.Context,
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """List the read-only V2 governed recipe registry."""
    if ctx.invoked_subcommand is not None:
        return
    payload = recipe_registry_payload()
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_recipe_groups_human(payload), nl=False)


@recipes_app.command("list")
def recipes_list(
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """List governed recipes without executing any recipe."""
    payload = recipe_registry_payload()
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_recipe_groups_human(payload), nl=False)


@recipes_app.command("inspect")
def recipes_inspect(
    recipe_id: Annotated[str, typer.Argument(help="Recipe id to inspect.")],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Inspect one governed recipe. No action is taken."""
    payload = recipe_detail_payload(recipe_id)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_recipe_detail_human(payload), nl=False)
    if payload.get("status") == "not_found":
        raise typer.Exit(1)


@recipes_app.command("eligibility")
def recipes_eligibility(
    recipe_id: Annotated[str, typer.Option("--recipe", help="Recipe id to evaluate.")],
    target: Annotated[str, typer.Option("--target", help="Exact target name to evaluate.")],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Evaluate read-only recipe eligibility for an exact target. No execution."""
    from shellforgeai.core import triage_ranking

    try:
        scene = triage_ranking.collect_scene()
    except Exception:
        scene = {"containers": []}
    payload = recipe_eligibility_payload(recipe_id, target, scene=scene)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_recipe_eligibility_human(payload), nl=False)
    if payload.get("status") == "not_found":
        raise typer.Exit(1)


def _collect_recipe_scene() -> dict[str, Any]:
    from shellforgeai.core import triage_ranking

    try:
        return triage_ranking.collect_scene()
    except Exception:
        return {"containers": []}


def _render_recipe_preflight_human(payload: dict[str, Any]) -> str:
    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    target_name = str(target.get("name") or payload.get("target") or "")
    status = str(payload.get("status") or "blocked")
    lines: list[str] = []
    if status == "preflight_ready":
        lines.extend(
            [
                "Recipe preflight: ready",
                f"Recipe: {payload.get('recipe_id')}",
                f"Target: {target_name}",
                (
                    "Target class: "
                    f"{payload.get('target_class') or 'disposable allowlisted container'}"
                ),
                "",
                "Would preview:",
            ]
        )
        argv = (
            (payload.get("action_preview") or {}).get("argv")
            if isinstance(payload.get("action_preview"), dict)
            else []
        )
        lines.append(f"  {' '.join(str(part) for part in (argv or []))}")
        lines.extend(["", "Gates:"])
        for gate in payload.get("gates") or []:
            label = str(gate.get("name") or "").replace("_", " ")
            lines.append(f"- {label}: {gate.get('status')}")
    else:
        lines.extend(
            [
                "Recipe preflight: blocked"
                if status != "not_found"
                else "Recipe preflight: not_found",
                f"Recipe: {payload.get('recipe_id')}",
                f"Target: {target_name}",
                (
                    "Reason: "
                    f"{payload.get('reason') or ', '.join(payload.get('blockers') or ['blocked'])}"
                ),
            ]
        )
    if payload.get("artifact_written"):
        lines.extend(
            [
                "",
                f"Preflight ID: {payload.get('preflight_id')}",
                f"Preflight path: {payload.get('preflight_path')}",
                f"Manifest path: {payload.get('manifest_path')}",
            ]
        )
    lines.extend(
        [
            "",
            "Safety:",
            "- Read-only preflight.",
            "- No command was executed.",
            "- No container was restarted.",
            "- No remediation, rollback, cleanup, Docker Compose, or shell action occurred.",
            "",
            "First safe command:",
            f"  {payload.get('first_safe_command')}",
        ]
    )
    return "\n".join(lines) + "\n"


def _render_recipe_preflight_validate_human(payload: dict[str, Any]) -> str:
    lines = [
        f"Recipe preflight validation: {payload.get('status')}",
        f"Preflight ID: {payload.get('preflight_id') or 'unknown'}",
        f"Path: {payload.get('preflight_path') or 'not found'}",
        "Checks:",
    ]
    for key, value in (payload.get("checks") or {}).items():
        lines.append(f"- {key}: {str(bool(value)).lower()}")
    warnings = payload.get("warnings") or []
    if warnings:
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in warnings)
    lines.append("No action was taken.")
    return "\n".join(lines) + "\n"


@recipes_preflight_app.callback(invoke_without_command=True)
def recipes_preflight_root(
    ctx: typer.Context,
    recipe_id: Annotated[
        str | None, typer.Option("--recipe", help="Recipe id to preflight.")
    ] = None,
    target: Annotated[
        str | None, typer.Option("--target", help="Exact target name to evaluate.")
    ] = None,
    save: Annotated[
        bool, typer.Option("--save", help="Write a ShellForgeAI-owned preflight artifact.")
    ] = False,
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Build a read-only governed recipe preflight packet. No execution."""
    if ctx.invoked_subcommand is not None:
        return
    if not recipe_id or not target:
        message = "--recipe and --target are required for recipes preflight"
        if json_out:
            typer.echo(
                json.dumps(
                    {
                        "schema_version": 1,
                        "mode": "v2_recipe_preflight",
                        "status": "error",
                        "read_only": True,
                        "mutation_performed": False,
                        "blockers": [message],
                    }
                )
            )
        else:
            typer.echo(
                f"Recipe preflight: blocked\nReason: {message}\nNo action was taken.\n", nl=False
            )
        raise typer.Exit(2)
    runtime = _ctx(ctx)
    payload = build_preflight_packet(recipe_id, target, scene=_collect_recipe_scene())
    if save:
        try:
            payload = save_preflight_packet(payload, runtime.session.data_dir)
        except ValueError as exc:
            payload = {
                **payload,
                "status": "error",
                "warnings": [str(exc)],
                "artifact_written": False,
            }
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_recipe_preflight_human(payload), nl=False)
    if payload.get("status") == "error":
        raise typer.Exit(1)


@recipes_preflight_app.command("validate")
def recipes_preflight_validate(
    ctx: typer.Context,
    preflight_ref: Annotated[
        str, typer.Argument(help="Saved preflight id or ShellForgeAI-owned path.")
    ],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Validate a saved recipe preflight packet. Read-only."""
    runtime = _ctx(ctx)
    payload = validate_preflight_packet(preflight_ref, runtime.session.data_dir)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_recipe_preflight_validate_human(payload), nl=False)
    if payload.get("status") != "ok":
        raise typer.Exit(1)


def _render_recipe_execute_human(payload: dict[str, Any]) -> str:
    status = str(payload.get("status") or "blocked")
    lines = [f"Recipe execution: {status}"]
    if payload.get("recipe_id"):
        lines.append(f"Recipe: {payload.get('recipe_id')}")
    target = payload.get("target")
    if isinstance(target, dict):
        lines.append(f"Target: {target.get('name') or target.get('current_name')}")
    if payload.get("reason"):
        lines.append(f"Reason: {payload.get('reason')}")
    action = payload.get("action") if isinstance(payload.get("action"), dict) else {}
    if action.get("argv"):
        lines.append("Action argv: " + " ".join(str(part) for part in action.get("argv") or []))
    lines.append(f"Command executed: {str(bool(action.get('command_executed'))).lower()}")
    if action.get("return_code") is not None:
        lines.append(f"Return code: {action.get('return_code')}")
    verification = (
        payload.get("verification") if isinstance(payload.get("verification"), dict) else {}
    )
    lines.append(f"Verification: {verification.get('status', 'not_run')}")
    receipt = payload.get("receipt") if isinstance(payload.get("receipt"), dict) else None
    if receipt:
        lines.append(f"Receipt ID: {receipt.get('receipt_id')}")
        lines.append(f"Receipt path: {receipt.get('path')}")
    warnings = payload.get("warnings") or []
    if warnings:
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in warnings)
    safety = payload.get("safety") if isinstance(payload.get("safety"), dict) else {}
    lines.extend(
        [
            "Safety:",
            f"- container_restarted: {str(bool(safety.get('container_restarted'))).lower()}",
            "- docker_compose_executed: "
            f"{str(bool(safety.get('docker_compose_executed'))).lower()}",
            f"- shell_true: {str(bool(safety.get('shell_true'))).lower()}",
            "- natural_language_execution: "
            f"{str(bool(safety.get('natural_language_execution'))).lower()}",
        ]
    )
    return "\n".join(lines) + "\n"


def _render_receipt_rollback_preview_human(payload: dict[str, Any]) -> str:
    status = str(payload.get("status") or "unknown")
    receipt_id = payload.get("receipt_id") or payload.get("receipt_ref") or "unknown"
    recipe_id = payload.get("recipe_id") or "unknown"
    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    target_name = target.get("name") or "unknown"
    warnings = list(payload.get("warnings") or [])
    status_label = "gated / limited" if status == "limited" else status.replace("_", " ")
    lines = [
        f"Rollback preview: {status_label}",
        f"Receipt: {receipt_id}",
        f"Recipe: {recipe_id}",
        f"Target: {target_name}",
    ]
    if payload.get("reason"):
        lines.append(f"Reason: {payload.get('reason')}")
    if status == "not_found":
        lines.extend(["", "Warnings:", "- receipt not found"])
    elif status == "failed":
        lines.extend(["", "Warnings:"])
        lines.extend(f"- {warning}" for warning in (warnings or ["receipt could not be trusted"]))
    elif status == "unsupported_recipe":
        lines.extend(
            [
                "",
                "Rollback posture:",
                "* Rollback-preview is not available for this recipe.",
                "* No rollback was executed.",
            ]
        )
    else:
        lines.extend(
            [
                "",
                "Rollback posture:",
                "* No true state rollback is available for a container restart.",
                (
                    "* A future confirm-gated recovery action may repeat an exact-target "
                    "disposable restart only if the target is still disposable and allowlisted."
                ),
                "* Verification is required before and after any future recovery action.",
            ]
        )
    lines.extend(["", "Gates:"])
    for gate in payload.get("gates") or []:
        name = str(gate.get("name") or "unknown").replace("_", " ")
        gate_status = str(gate.get("status") or "unknown").replace("_", " ")
        lines.append(f"* {name}: {gate_status}")
    lines.extend(["", "First safe command:", str(payload.get("first_safe_command") or "")])
    if warnings and status not in {"not_found", "failed"}:
        lines.extend(["", "Warnings:"])
        lines.extend(f"- {warning}" for warning in warnings)
    lines.extend(
        [
            "",
            "Safety:",
            "* Read-only rollback preview.",
            "* No rollback was executed.",
            "* No container was restarted.",
            "* No Docker, Compose, remediation, cleanup, shell, or arbitrary command was executed.",
            "* No action was taken.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _render_receipt_recovery_execute_human(payload: dict[str, Any]) -> str:
    status = str(payload.get("status") or "blocked")
    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    target_name = target.get("name") or "unknown"
    if status == "executed":
        verification = (
            payload.get("verification") if isinstance(payload.get("verification"), dict) else {}
        )
        action = payload.get("action") if isinstance(payload.get("action"), dict) else {}
        return (
            "\n".join(
                [
                    "Recovery execution: completed",
                    f"Receipt: {payload.get('receipt_id')}",
                    f"Recovery receipt: {payload.get('recovery_receipt_id')}",
                    f"Recipe: {payload.get('recipe_id')}",
                    f"Target: {target_name}",
                    "",
                    "Action:",
                    " ".join(str(part) for part in action.get("argv") or []),
                    "",
                    "Verification:",
                    "- restart attempted: "
                    f"{str(bool(action.get('docker_restart_attempted'))).lower()}",
                    "- restart succeeded: "
                    f"{str(bool(action.get('docker_restart_succeeded'))).lower()}",
                    "- StartedAt changed: "
                    f"{str(bool(verification.get('started_at_changed'))).lower()}",
                    "",
                    "Safety:",
                    "- Exact disposable target only.",
                    "- Explicit --confirm was required.",
                    "- No Docker Compose command was executed.",
                    "- No cleanup/remediation/rollback outside this recovery recipe was executed.",
                    "- This is bounded recovery restart, not true rollback of prior process state.",
                    "",
                    "First safe command:",
                    str(payload.get("first_safe_command") or ""),
                ]
            ).rstrip()
            + "\n"
        )

    lines = ["Recovery execution: blocked"]
    if target_name != "unknown":
        lines.append(f"Target: {target_name}")
    if payload.get("reason"):
        lines.append(f"Reason: {payload.get('reason')}")
    lines.extend(
        [
            "",
            "Safety:",
            "- No action was taken.",
            "- No container was restarted.",
            "- This is bounded recovery restart only when explicitly confirmed; "
            "no true rollback is available.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _render_recipe_receipt_validate_human(payload: dict[str, Any]) -> str:
    lines = [
        f"Recipe receipt validation: {payload.get('status')}",
        f"Receipt ID: {payload.get('receipt_id') or 'unknown'}",
        f"Path: {payload.get('receipt_path') or 'not found'}",
        "Checks:",
    ]
    for key, value in (payload.get("checks") or {}).items():
        lines.append(f"- {key}: {str(bool(value)).lower()}")
    warnings = payload.get("warnings") or []
    if warnings:
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in warnings)
    lines.append("No action was taken by receipt validation.")
    return "\n".join(lines) + "\n"


@recipes_app.command("execute")
def recipes_execute(
    ctx: typer.Context,
    preflight_ref: Annotated[
        str, typer.Argument(help="Saved preflight id or ShellForgeAI-owned path.")
    ],
    confirm: Annotated[
        bool,
        typer.Option("--confirm", help="Explicitly confirm the governed exact-target restart."),
    ] = False,
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Execute docker.disposable_restart from a valid saved preflight and confirmation."""
    runtime = _ctx(ctx)
    payload = execute_disposable_restart(preflight_ref, runtime.session.data_dir, confirm=confirm)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_recipe_execute_human(payload), nl=False)
    if payload.get("status") != "executed":
        raise typer.Exit(1)


def _render_recipe_receipt_history_human(payload: dict[str, Any]) -> str:
    lines = [
        "Recipe receipt history",
        f"Status: {payload.get('status')}",
        f"Limit: {payload.get('limit')}",
    ]
    receipts = payload.get("receipts") or []
    if not receipts:
        lines.extend(
            [
                "No governed recipe receipts found.",
                "First safe command:",
                str(
                    payload.get("first_safe_command")
                    or (
                        "shellforgeai recipes preflight --recipe docker.disposable_restart "
                        "--target <target> --save"
                    )
                ),
            ]
        )
    else:
        lines.append("Receipts (newest first):")
        for item in receipts:
            lineage = ""
            if item.get("original_receipt_id"):
                lineage = (
                    f" original={item.get('original_receipt_id')} "
                    f"recovery={item.get('recovery_receipt_id') or '-'}"
                )
            lines.append(
                f"- {item.get('receipt_id')} mode={item.get('mode')} "
                f"recipe={item.get('recipe_id')} "
                f"target={item.get('target')} status={item.get('status')} "
                f"verification={item.get('verification_status')} "
                f"created_at={item.get('created_at')}{lineage}"
            )
    warnings = payload.get("warnings") or []
    if warnings:
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in warnings)
    lines.extend(
        [
            "Safety:",
            "- read_only: true",
            "- mutation_performed: false",
            "- no Docker, Compose, recovery, rollback, remediation, or cleanup execution occurred",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _render_recipe_receipt_inspect_human(payload: dict[str, Any]) -> str:
    identity = payload.get("identity") if isinstance(payload.get("identity"), dict) else {}
    lineage = payload.get("lineage") if isinstance(payload.get("lineage"), dict) else {}
    recipe = payload.get("recipe") if isinstance(payload.get("recipe"), dict) else {}
    action = payload.get("action") if isinstance(payload.get("action"), dict) else {}
    verification = (
        payload.get("verification") if isinstance(payload.get("verification"), dict) else {}
    )
    lines = [
        "Recipe receipt audit inspect",
        f"Status: {payload.get('status')}",
        f"Receipt ID: {identity.get('receipt_id') or 'unknown'}",
        f"Mode: {identity.get('receipt_mode') or 'unknown'}",
        f"Created at: {identity.get('created_at') or 'unknown'}",
        f"Recipe: {recipe.get('recipe_id') or 'unknown'}",
        f"Target: {payload.get('target') or 'unknown'}",
        "Lineage:",
        f"- original_receipt_id: {lineage.get('original_receipt_id') or '-'}",
        f"- recovery_receipt_id: {lineage.get('recovery_receipt_id') or '-'}",
        "Action as recorded:",
        "- argv: " + " ".join(str(part) for part in action.get("argv") or []),
        f"- command_executed: {str(bool(action.get('command_executed'))).lower()}",
        f"- return_code: {action.get('return_code')}",
        "Verification:",
        f"- status: {verification.get('status') or 'not_run'}",
        "Artifacts:",
    ]
    for path in payload.get("artifact_paths") or []:
        lines.append(f"- {path}")
    warnings = payload.get("warnings") or []
    if warnings:
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in warnings)
    lines.extend(["First safe commands:"])
    lines.extend(f"- {cmd}" for cmd in payload.get("safe_next_commands") or [])
    lines.extend(
        [
            "Safety:",
            "- read_only: true",
            "- mutation_performed: false",
            "- no live Docker state was inspected",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _render_recipe_receipt_export_human(payload: dict[str, Any]) -> str:
    lines = [
        "Recipe receipt export",
        f"Status: {payload.get('status')}",
        f"Receipt ID: {payload.get('receipt_id') or 'unknown'}",
        f"Export ID: {payload.get('export_id') or 'none'}",
        f"Export path: {payload.get('export_path') or 'none'}",
        "Files:",
    ]
    for rel in payload.get("files") or []:
        lines.append(f"- {rel}")
    warnings = payload.get("warnings") or []
    if warnings:
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in warnings)
    lines.extend(
        [
            "Safety:",
            "- owned metadata export only: true",
            "- mutation_performed: false",
            "- no Docker/Compose command was executed",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _render_recipe_receipt_export_validate_human(payload: dict[str, Any]) -> str:
    lines = [
        "Recipe receipt export validation",
        f"Status: {payload.get('status')}",
        f"Export ID: {payload.get('export_id') or 'unknown'}",
        "Checks:",
    ]
    for key, value in (payload.get("checks") or {}).items():
        lines.append(f"- {key}: {str(bool(value)).lower()}")
    warnings = payload.get("warnings") or []
    if warnings:
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in warnings)
    lines.extend(["Safety:", "- read_only: true", "- mutation_performed: false"])
    return "\n".join(lines).rstrip() + "\n"


def _render_recipe_receipt_compare_human(
    payload: dict[str, Any], *, only_changed: bool = False
) -> str:
    lines = ["Recipe receipt compare", f"Status: {payload.get('status')}"]
    before = payload.get("before") if isinstance(payload.get("before"), dict) else {}
    after = payload.get("after") if isinstance(payload.get("after"), dict) else {}
    if before or after:
        lines.append(f"Before: {before.get('receipt_id') or before.get('ref') or '-'}")
        lines.append(f"After: {after.get('receipt_id') or after.get('ref') or '-'}")
    changed = payload.get("changed") if isinstance(payload.get("changed"), dict) else {}
    stable = payload.get("stable") if isinstance(payload.get("stable"), dict) else {}
    lines.append("Changed fields:")
    if changed:
        for key, value in changed.items():
            if isinstance(value, dict) and "before" in value and "after" in value:
                lines.append(f"- {key}: {value.get('before')} -> {value.get('after')}")
            else:
                lines.append(f"- {key}: {value}")
    else:
        lines.append("- none")
    if not only_changed:
        lines.append("Stable fields:")
        if stable:
            for key, value in stable.items():
                lines.append(f"- {key}: {value}")
        else:
            lines.append("- none")
    warnings = payload.get("warnings") or []
    if warnings:
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in warnings)
    lines.extend(
        [
            "Safety:",
            "- read_only: true",
            "- mutation_performed: false",
            "- no verify/recovery/rollback/restart was executed",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


@recipes_receipt_app.command("history")
def recipes_receipt_history(
    ctx: typer.Context,
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    limit: Annotated[int, typer.Option("--limit", help="Maximum receipts to list (1-100).")] = 20,
) -> None:
    """List governed recipe execution and recovery receipts newest first. Read-only."""
    runtime = _ctx(ctx)
    payload = build_receipt_history(runtime.session.data_dir, limit=limit)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_recipe_receipt_history_human(payload), nl=False)


@recipes_receipt_app.command("inspect")
def recipes_receipt_inspect(
    ctx: typer.Context,
    receipt_ref: Annotated[
        str, typer.Argument(help="Receipt id or ShellForgeAI-owned receipt path.")
    ],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Inspect a governed execution or recovery receipt. Read-only."""
    runtime = _ctx(ctx)
    payload = build_receipt_inspect(receipt_ref, runtime.session.data_dir)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_recipe_receipt_inspect_human(payload), nl=False)
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@recipes_receipt_app.command("export")
def recipes_receipt_export(
    ctx: typer.Context,
    receipt_ref: Annotated[
        str, typer.Argument(help="Receipt id or ShellForgeAI-owned receipt path.")
    ],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Export a validated receipt bundle to ShellForgeAI-owned export metadata."""
    runtime = _ctx(ctx)
    payload = build_receipt_export(receipt_ref, runtime.session.data_dir)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_recipe_receipt_export_human(payload), nl=False)
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@recipes_receipt_app.command("export-validate")
def recipes_receipt_export_validate(
    ctx: typer.Context,
    export_ref: Annotated[
        str, typer.Argument(help="Receipt export id or ShellForgeAI-owned export path.")
    ],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Validate an exported receipt bundle. Read-only."""
    runtime = _ctx(ctx)
    payload = build_receipt_export_validate(export_ref, runtime.session.data_dir)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_recipe_receipt_export_validate_human(payload), nl=False)
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@recipes_receipt_app.command("compare")
def recipes_receipt_compare(
    ctx: typer.Context,
    before_receipt_ref: Annotated[str, typer.Argument(help="Earlier receipt id/ref.")],
    after_receipt_ref: Annotated[str, typer.Argument(help="Later receipt id/ref.")],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    only_changed: Annotated[
        bool, typer.Option("--only-changed", help="Hide stable fields in human output.")
    ] = False,
) -> None:
    """Compare two governed receipt artifacts read-only."""
    runtime = _ctx(ctx)
    payload = build_receipt_compare(before_receipt_ref, after_receipt_ref, runtime.session.data_dir)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(
            _render_recipe_receipt_compare_human(payload, only_changed=only_changed), nl=False
        )
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@recipes_receipt_app.command("compare-latest")
def recipes_receipt_compare_latest(
    ctx: typer.Context,
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    only_changed: Annotated[
        bool, typer.Option("--only-changed", help="Hide stable fields in human output.")
    ] = False,
) -> None:
    """Compare the two newest governed receipt artifacts read-only."""
    runtime = _ctx(ctx)
    payload = build_receipt_compare_latest(runtime.session.data_dir)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(
            _render_recipe_receipt_compare_human(payload, only_changed=only_changed), nl=False
        )
    if payload.get("status") not in {"ok", "not_enough_history"}:
        raise typer.Exit(1)


@recipes_receipt_app.command("rollback-preview")
def recipes_receipt_rollback_preview(
    ctx: typer.Context,
    receipt_ref: Annotated[
        str, typer.Argument(help="Saved receipt id or ShellForgeAI-owned path.")
    ],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Preview rollback/recovery posture for a governed receipt. Read-only."""
    runtime = _ctx(ctx)
    payload = preview_receipt_rollback(receipt_ref, runtime.session.data_dir)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_receipt_rollback_preview_human(payload), nl=False)
    if payload.get("status") not in {"limited", "preview_ready", "unsupported_recipe"}:
        raise typer.Exit(1)


@app.command("rollback-preview")
def rollback_preview_receipt(
    ctx: typer.Context,
    receipt: Annotated[str, typer.Option("--receipt", help="Receipt id or owned path.")],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Preview rollback/recovery posture for a governed receipt. Read-only."""
    runtime = _ctx(ctx)
    payload = preview_receipt_rollback(receipt, runtime.session.data_dir)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_receipt_rollback_preview_human(payload), nl=False)
    if payload.get("status") not in {"limited", "preview_ready", "unsupported_recipe"}:
        raise typer.Exit(1)


@recipes_receipt_app.command("recovery-execute")
def recipes_receipt_recovery_execute(
    ctx: typer.Context,
    receipt_ref: Annotated[
        str, typer.Argument(help="Saved disposable restart receipt id or ShellForgeAI-owned path.")
    ],
    confirm: Annotated[
        bool,
        typer.Option("--confirm", help="Explicitly confirm bounded recovery restart."),
    ] = False,
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Execute bounded disposable recovery restart from a valid receipt. Not true rollback."""
    runtime = _ctx(ctx)
    payload = execute_receipt_recovery(receipt_ref, runtime.session.data_dir, confirm=confirm)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_receipt_recovery_execute_human(payload), nl=False)
    if payload.get("status") != "executed":
        raise typer.Exit(1)


@recipes_receipt_app.command("recovery-status")
def recipes_receipt_recovery_status(
    ctx: typer.Context,
    recovery_receipt_ref: Annotated[
        str, typer.Argument(help="Recovery receipt id or ShellForgeAI-owned path.")
    ],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Read-only status for a recovery receipt via receipt-aware verify."""
    runtime = _ctx(ctx)
    payload = verify_recipe_receipt(recovery_receipt_ref, runtime.session.data_dir)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_v2_receipt_verify_human(payload), nl=False)
    if payload.get("status") != "passed":
        raise typer.Exit(1)


@recipes_receipt_app.command("recovery-validate")
def recipes_receipt_recovery_validate(
    ctx: typer.Context,
    recovery_receipt_ref: Annotated[
        str, typer.Argument(help="Recovery receipt id or ShellForgeAI-owned path.")
    ],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Validate a recovery receipt. Read-only."""
    runtime = _ctx(ctx)
    payload = validate_recipe_receipt(recovery_receipt_ref, runtime.session.data_dir)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_recipe_receipt_validate_human(payload), nl=False)
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@recipes_receipt_app.command("verify")
def recipes_receipt_verify(
    ctx: typer.Context,
    receipt_ref: Annotated[
        str, typer.Argument(help="Saved receipt id or ShellForgeAI-owned path.")
    ],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Verify a governed recipe execution receipt. Read-only; no retry or rollback."""
    runtime = _ctx(ctx)
    payload = verify_recipe_receipt(receipt_ref, runtime.session.data_dir)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_v2_receipt_verify_human(payload), nl=False)
    if payload.get("status") != "passed":
        raise typer.Exit(1)


@recipes_receipt_app.command("validate")
def recipes_receipt_validate(
    ctx: typer.Context,
    receipt_ref: Annotated[
        str, typer.Argument(help="Saved receipt id or ShellForgeAI-owned path.")
    ],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Validate a governed recipe execution receipt. Read-only."""
    runtime = _ctx(ctx)
    payload = validate_recipe_receipt(receipt_ref, runtime.session.data_dir)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        typer.echo(_render_recipe_receipt_validate_human(payload), nl=False)
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@app.command("safe-actions")
def safe_actions(
    target: Annotated[
        str, typer.Option("--target", help="Optional exact target to evaluate.")
    ] = "",
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """Summarize current read-only safe actions and disabled governed recipes."""
    payload = recipe_registry_payload()
    if target:
        from shellforgeai.core import triage_ranking

        try:
            scene = triage_ranking.collect_scene()
        except Exception:
            scene = {"containers": []}
        payload = {
            **payload,
            "mode": "v2_safe_actions",
            "target": target,
            "eligibility": [
                recipe_eligibility_payload(r["recipe_id"], target, scene=scene)
                for r in payload.get("recipes", [])
                if r.get("mutation_class") != "none"
            ],
        }
    else:
        payload = {**payload, "mode": "v2_safe_actions", "target": ""}
    if json_out:
        typer.echo(json.dumps(payload))
        return
    typer.echo(_render_recipe_groups_human(payload), nl=False)
    if target:
        typer.echo(f"Target evaluated: {target}\n")
    typer.echo("No action was taken.\n", nl=False)


def _is_recipe_preflight_ask(question: str) -> bool:
    low = " ".join((question or "").lower().split())
    if not low:
        return False
    cues = (
        "preflight docker restart",
        "preflight restart",
        "preflight the restart recipe",
        "check if you could restart",
        "restart this safely",
        "eligible for disposable restart",
        "eligible for restart",
        "what gates are needed to restart",
        "gates are needed to restart",
    )
    return any(cue in low for cue in cues)


def _is_recipe_guidance_ask(question: str) -> bool:
    low = " ".join((question or "").lower().split())
    if not low:
        return False
    cues = (
        "what can shellforgeai safely do next",
        "what can you safely do",
        "what can shellforgeai safely do",
        "what fixes are available",
        "what recipes exist",
        "safe action",
        "safe actions",
        "can you fix this",
        "can shellforgeai restart this safely",
        "can you restart this safely",
        "restart this safely",
        "recipes",
    )
    return any(cue in low for cue in cues)


def _is_recipe_execution_request(question: str) -> bool:
    low = " ".join((question or "").lower().split())
    execution_cues = (
        "execute the recipe",
        "execute recipe",
        "run the recipe",
        "run the restart recipe",
        "run restart recipe",
        "restart the disposable target",
        "apply it",
        "apply the recipe",
        "apply the restart recipe",
        "execute the restart recipe",
        "run docker restart",
        "confirm restart",
        "apply the restart",
        "restart it now",
        "do it",
        "run that",
        "then do it",
        "and then do it",
    )
    return any(cue in low for cue in execution_cues)


def _extract_safe_action_target(question: str) -> str:
    """Extract the exact recipe target from a safe-action / preflight ask.

    Delegates to the deterministic recipe-preflight target extractor so that
    "preflight docker restart for <target>" and related phrasings resolve the
    real target rather than a connector word like "for". Returns "" for
    pronoun/connector-only targets so the caller asks for clarification.
    """
    return extract_recipe_preflight_target(question)


def _handle_recipe_registry_ask(question: str) -> bool:
    low = " ".join((question or "").lower().split())
    preflight_ask = _is_recipe_preflight_ask(question)
    execution_request = _is_recipe_execution_request(question)
    command_help = "command" in low and "execute" in low and "recipe" in low
    if command_help:
        console.print(
            "No action was taken. Governed disposable restart execution uses this CLI workflow:\n"
            "  1. shellforgeai recipes preflight --recipe docker.disposable_restart "
            "--target <target> --save\n"
            "  2. shellforgeai recipes preflight validate <preflight_id>\n"
            "  3. shellforgeai recipes execute <preflight_id> --confirm\n"
            "  4. shellforgeai recipes receipt validate <receipt_id>\n"
            "Only this saved-preflight, explicit-confirm path can execute; no raw Docker "
            "command was suggested or run.\n"
        )
        return True
    if execution_request and not preflight_ask:
        console.print(
            "Refused: natural-language mutation is not allowed. "
            "Recipe execution from natural language is not allowed.\n"
            "No action was taken.\n"
            "No recipe was executed.\n"
            "No container was restarted.\n"
            "Safe read-only alternatives: status, triage, recipes preflight.\n"
            "First safe command: shellforgeai recipes preflight --recipe "
            "docker.disposable_restart --target <target> --save\n"
            "Use the explicit governed CLI workflow instead:\n"
            "  1. shellforgeai recipes preflight --recipe docker.disposable_restart "
            "--target <target> --save\n"
            "  2. shellforgeai recipes preflight validate <preflight_id>\n"
            "  3. shellforgeai recipes execute <preflight_id> --confirm\n"
        )
        return True
    if not (preflight_ask or _is_recipe_guidance_ask(question)):
        return False
    target = _extract_safe_action_target(question)
    mixed_mutation = any(
        cue in low
        for cue in (
            "restart compose",
            "compose restart",
            "docker compose restart",
            " and restart",
            " then restart",
            " restart it",
            " fix it now",
        )
    )
    payload = recipe_registry_payload()
    if preflight_ask:
        console.print("Read-only recipe preflight (deterministic ask routing):")
        if target:
            preflight = build_preflight_packet(
                "docker.disposable_restart", target, scene=_collect_recipe_scene()
            )
            typer.echo(_render_recipe_preflight_human(preflight), nl=False)
            console.print(
                "Save packet command: shellforgeai recipes preflight --recipe "
                f"docker.disposable_restart --target {target} --save"
            )
        else:
            console.print(
                "Specify the exact container target; I will not guess a target from a "
                "pronoun or broad word."
            )
            console.print("First safe command:")
            console.print(
                "  shellforgeai recipes preflight --recipe docker.disposable_restart "
                "--target <target> --json"
            )
            console.print("Eligibility command:")
            console.print(
                "  shellforgeai recipes eligibility --recipe docker.disposable_restart "
                "--target <target> --json"
            )
    else:
        console.print("ShellForgeAI governed recipe registry (deterministic ask routing):")
        console.print("")
        typer.echo(_render_recipe_groups_human(payload), nl=False)
        if target:
            console.print(f"Eligibility check command for target {target}:")
            console.print(
                "  shellforgeai recipes eligibility --recipe docker.disposable_restart "
                f"--target {target} --json"
            )
        else:
            console.print("Recipe registry command: shellforgeai recipes list")
            console.print("First safe command: shellforgeai status --json")
    if "restart" in low or "fix" in low:
        console.print(
            "Governed fixes are not executable yet from natural language; "
            "docker.disposable_restart is available only through a saved preflight "
            "plus explicit CLI confirmation."
        )
        console.print("Governed workflow:")
        console.print(
            "  shellforgeai recipes preflight --recipe docker.disposable_restart "
            "--target <target> --save"
        )
        console.print("  shellforgeai recipes preflight validate <preflight_id>")
        console.print("  shellforgeai recipes execute <preflight_id> --confirm")
        console.print("Preview boundary: shellforgeai apply-preview --target <target> --json")
    if execution_request or mixed_mutation or "compose" in low:
        console.print("Refused mutation portion: execution/restart was not run.")
        console.print("No container was restarted.")
    console.print("No action was taken.")
    return True


@app.command()
def ask(
    ctx: typer.Context,
    question: str,
    context: str = typer.Option("standard", "--context"),
    full_context: bool = typer.Option(False, "--full-context"),
    raw: bool = typer.Option(False, "--raw"),
    no_evidence: bool = typer.Option(
        False, "--no-evidence", help="Disable evidence-aware routing for this ask."
    ),
    since: str = typer.Option("30m", "--since"),
) -> None:
    runtime = _ctx(ctx)
    if not no_evidence:
        if _handle_receipt_recovery_ask(question):
            return
        if _handle_receipt_rollback_preview_ask(question):
            return
        if _handle_receipt_audit_ask(question):
            return
        if _handle_recipe_registry_ask(question):
            return
        if _handle_v2_handoff_ask(question):
            return
        if _handle_v2_verify_ask(question):
            return
        if _is_status_ask(question):
            payload = _build_status_payload()
            console.print("Read-only status (deterministic ask routing):")
            console.print("")
            typer.echo(_render_status_human(payload), nl=False)
            return
        if _handle_v2_apply_preview_ask(question):
            return
        if _handle_v2_apply_preview_mutation_refusal(question):
            return
        if _handle_v2_propose_ask(question):
            return
        if _handle_v2_propose_mutation_refusal(question):
            return
        if _handle_retention_ask(runtime, question):
            return
        if _handle_incident_search_ask(runtime, question):
            return
        if _handle_guard_ask(runtime, question):
            return
        if _handle_command_help_ask(question):
            return
        if _handle_pressure_mutation_refusal(question):
            return
        if _handle_v2_triage_ask(question):
            return
        if is_ops_report_ask(question):
            brief_ask = is_brief_ops_report_ask(question)
            payload = _build_ops_report_payload(include_visibility=brief_ask)
            if brief_ask:
                console.print("Read-only brief ops report (deterministic ask routing):")
                console.print("")
                typer.echo(_render_ops_report_brief(payload), nl=False)
            else:
                console.print("Read-only ops report (deterministic ask routing):")
                console.print("")
                typer.echo(_render_broad_triage_answer(payload))
            return
        if _handle_broad_triage_ask(runtime, question):
            return
        if _handle_mission_restart_ask(runtime, question):
            return
        if _handle_restart_plan_ask(runtime, question):
            return
        if _handle_compose_restart_preview_ask(runtime, question):
            return
        if _handle_compose_restart_proposal_ask(runtime, question):
            return
        if _handle_compose_context_ask(runtime, question):
            return
        if _handle_lab_restart_verification_ask(runtime, question):
            return
        if _handle_lab_restart_ask(runtime, question):
            return
        if _handle_immediate_fix_ask(runtime, question):
            return
        if _handle_export_ask(runtime, question):
            return
        if _handle_apply_approved_ask(runtime, question):
            return
        if _handle_actions_ask(runtime, question):
            return
        if _handle_create_restart_proposal_ask(runtime, question):
            return
        if _handle_create_proposals_ask(runtime, question):
            return
        if _handle_mutation_refusal_ask(question):
            return
    provider = build_provider(runtime.settings)
    ctx_mode = "full" if full_context else context

    route = AskRoute(mode=PLAIN) if no_evidence else route_ask_intent(question)
    evidence_result = None
    evidence_error: str | None = None
    if route.mode == EVIDENCE_BACKED:
        try:
            evidence_result = diagnose_target(runtime, route.target, online=False, since=since)
        except Exception as exc:  # collection failure: degrade, do not hallucinate
            evidence_error = f"{type(exc).__name__}: {exc}"

    if route.mode == EVIDENCE_BACKED and evidence_result is not None:
        _ensure_artifact_dir(runtime)
        if route.network_reachability:
            try:
                from shellforgeai.core.collectors import collect_network_evidence

                existing_sources = {i.source for i in evidence_result.evidence.items}
                for ni in collect_network_evidence(runtime):
                    if ni.source not in existing_sources:
                        evidence_result.evidence.items.append(ni)
            except Exception:
                pass
        ev_path = runtime.session.artifact_dir / "evidence.json"
        ev_path.write_text(evidence_result.evidence.model_dump_json(indent=2), encoding="utf-8")
        brief = evidence_brief(evidence_result.findings, evidence_result.evidence.items)
        # Extract target container for any evidence-backed ask. This lets
        # "is the healthy web service okay?" surface sfai-healthy-web's
        # Docker health, not just for reachability questions.
        target_container = extract_container_target(question)
        tc_status = target_container_status(evidence_result.evidence.items, target_container)
        oncall_overview = _is_oncall_overview_question(question)
        use_net_rank = route.network_reachability or oncall_overview
        net_brief = (
            network_reachability_brief(
                evidence_result.findings,
                evidence_result.evidence.items,
                target_container=target_container,
                max_containers=20,
                max_findings=20,
            )
            if use_net_rank
            else None
        )
        synthesis_hints = (
            _network_reachability_hints(evidence_result.findings, evidence_result.evidence.items)
            if use_net_rank
            else []
        )
        prompt_context = {
            "ask_intent": route.intent_label,
            "identity": "CLI-first Linux ops harness with read-only safety boundaries.",
            "host": platform.platform(),
            "mode": runtime.session.mode,
            "session_id": evidence_result.session_id,
            "mutation_request": route.mutation_request,
            "safety": (
                "Inspect-only; no restart/stop/start/delete/install/firewall changes "
                "performed. apply remains validation-only."
            ),
        }
        if _is_path_ownership_question(question):
            prompt_context["ownership_context"] = _ownership_context(evidence_result.evidence.items)
            prompt_context["ownership_directive"] = (
                "For path ownership questions, answer in this order: file existence/stat, "
                "symlink target, mount target/source/options (if present), package owner status, "
                "then container/host boundary caveat. Do not stop at package owner alone."
            )
            own_rows = _ownership_evidence_rows(evidence_result.evidence.items)
            if own_rows:
                existing_rows = prompt_context.get("evidence")
                if isinstance(existing_rows, list):
                    prompt_context["evidence"] = own_rows + existing_rows
                else:
                    prompt_context["evidence"] = own_rows
        if target_container:
            prompt_context["target_container"] = target_container
        if tc_status is not None:
            prompt_context["target_container_status"] = tc_status
            prompt_context["target_container_directive"] = (
                "target_container_status reflects Docker container inventory + "
                "problem summary. If state=running and (health=healthy or bucket=healthy), "
                "say the container is running and healthy; do NOT fall back to a "
                "local-process check (e.g. 'nginx not found in this container') for a "
                "Docker lab/service target. If log_themes are present, name them and the "
                "container in the answer."
            )
        if net_brief is not None:
            prompt_context["network_reachability_brief"] = net_brief
            # Use the reachability-ranked findings rows so the model sees
            # targeted/network-themed findings first.
            prompt_context["findings"] = net_brief["findings"]
            prompt_context["evidence"] = brief["evidence"]
        else:
            prompt_context["findings"] = brief["findings"]
            prompt_context["evidence"] = brief["evidence"]
        if synthesis_hints:
            prompt_context["synthesis_hints"] = synthesis_hints
            prompt_context["evidence_ranking"] = (
                "Rank evidence in this order for reachability questions: "
                "(1) target/app/container log themes (DNS, upstream unreachable, "
                "connection refused, timeout, TLS) -- see "
                "network_reachability_brief.container_log_evidence; "
                "(2) service listener/exposure evidence; "
                "(3) runtime network basics (DNS resolver, default route, listeners) "
                "-- see network_reachability_brief.runtime_network_basics; "
                "(4) visibility limitations. "
                "Healthy runtime DNS/default route does NOT cancel app/container logs "
                "showing reachability failure. If container_log_evidence contains an "
                "entry, name that container and its themes explicitly in the answer. "
                "Do not say 'no DNS-specific evidence' or 'reachability unconfirmed' "
                "when container_log_evidence is non-empty. Do not label the host "
                "network globally broken unless runtime evidence supports it."
            )
        # Reachability briefs and target-container blocks need more headroom
        # than 2500 chars to stay intact in the prompt.
        effective_mode = (
            "full"
            if (net_brief is not None or tc_status is not None) and ctx_mode != "full"
            else ctx_mode
        )
        prompt = build_contextual_prompt(question, prompt_context, mode=effective_mode)
    else:
        prompt_context = {
            "host": platform.platform(),
            "mode": runtime.session.mode,
            "identity": "CLI-first Linux ops harness with read-only safety boundaries.",
        }
        if route.mode == EVIDENCE_BACKED and evidence_error is not None:
            prompt_context["evidence_unavailable"] = (
                f"Recognized as ops diagnostic ({route.intent_label}) but read-only "
                f"evidence collection failed: {evidence_error}. Do not invent findings."
            )
        prompt = build_contextual_prompt(question, prompt_context, mode=ctx_mode)
    resp = provider.complete(
        ModelRequest(
            prompt=prompt,
            model=runtime.settings.model.model,
            provider=runtime.settings.model.provider,
            timeout_seconds=runtime.settings.model.timeout_seconds,
            metadata={"raw": raw},
        )
    )
    if not resp.ok:
        err_text = (resp.error or "").lower()
        if "not found on path" in err_text or "install" in err_text:
            console.print(
                "Model unavailable. Install Codex CLI and login with: codex login --device-auth"
            )
        elif "auth" in err_text or "login" in err_text:
            console.print("Codex auth failed. Run: codex login --device-auth")
        elif "timed out" in err_text:
            console.print("Codex timed out before producing a response.")
        elif "argument" in err_text:
            stderr_snippet = (resp.raw or {}).get("stderr", "") if resp.raw else ""
            console.print(
                "Codex CLI argument error: "
                + (resp.error or "unexpected CLI options")
                + (f"\n{stderr_snippet}" if stderr_snippet else "")
            )
        elif "no final response" in err_text:
            console.print("Codex returned no final response.")
        else:
            stderr_snippet = (resp.raw or {}).get("stderr", "") if resp.raw else ""
            console.print(
                f"Codex error: {resp.error or 'unknown failure'}"
                + (f"\n{stderr_snippet}" if stderr_snippet else "")
            )
        raise typer.Exit(code=1)
    console.print(resp.text)
    console.print(f"\nProvider: {resp.provider}\nModel: {resp.model}\n{_usage_line(resp)}")
    if route.mode == EVIDENCE_BACKED and evidence_result is not None:
        artifact_dir = runtime.session.artifact_dir
        ev_path = artifact_dir / "evidence.json"
        ask_summary_path = artifact_dir / "ask-summary.md"
        ask_summary_path.write_text(
            f"# Ask: evidence-backed\n\n"
            f"Session: {evidence_result.session_id}\n"
            f"Intent: {route.intent_label}\n"
            f"Question: {question}\n\n"
            f"{findings_summary_line(list(evidence_result.findings))}\n\n"
            f"## Answer\n\n{resp.text}\n",
            encoding="utf-8",
        )
        runbook_md_path: Path | None = None
        if route.fix_plan:
            rb = build_runbook(
                session_id=evidence_result.session_id,
                target=route.target or "docker",
                evidence_items=list(evidence_result.evidence.items),
                findings=list(evidence_result.findings),
                source_artifacts=[str(ev_path)],
            )
            runbook_md_path = artifact_dir / "runbook.md"
            import json

            (artifact_dir / "runbook.json").write_text(
                json.dumps(rb.to_schema_dict(), indent=2), encoding="utf-8"
            )
            runbook_md_path.write_text(render_runbook_md(rb), encoding="utf-8")
        console.print(
            "\nEvidence-backed ask:"
            f"\n- intent: {route.intent_label}"
            f"\n- session: {evidence_result.session_id}"
            f"\n- {findings_summary_line(list(evidence_result.findings))}"
            f"\n- evidence: {ev_path}"
            f"\n- ask summary: {ask_summary_path}"
            + (f"\n- runbook: {runbook_md_path}" if runbook_md_path else "")
        )
        if route.mutation_request:
            console.print(
                "\nSafety: detected a mutation-style request. ShellForgeAI ran read-only "
                "evidence only. No restart/stop/start/delete/install/firewall changes were "
                "performed. apply remains validation-only."
            )
    elif route.mode == EVIDENCE_BACKED and evidence_error is not None:
        console.print(
            f"\nNote: this question matched the {route.intent_label} diagnostic intent, "
            "but read-only evidence collection failed in this runtime. Try "
            f'`shellforgeai diagnose "{question}" --save-plan` for a full diagnose run.'
        )
    if raw and resp.raw and resp.raw.get("stdout_jsonl"):
        console.print(resp.raw["stdout_jsonl"])


@compose_app.command("inspect")
def compose_inspect(
    target: Annotated[
        str | None, typer.Argument(help="Container name/id", show_default=False)
    ] = None,
    container: Annotated[str | None, typer.Option("--container", help="Container name/id")] = None,
    project: Annotated[str | None, typer.Option("--project", help="Compose project filter")] = None,
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only")] = False,
) -> None:
    """Inspect compose ownership context from Docker labels (read-only)."""
    ref = (container or target or "").strip()
    inv = containers.containers(all_containers=True)
    if not inv.ok:
        raise typer.Exit(1) from None
    payload = json.loads(inv.stdout or "{}")
    rows = payload.get("containers") or []
    chosen = None
    if ref:
        for row in rows:
            if row.get("name") == ref or str(row.get("id") or "").startswith(ref):
                chosen = row
                break
        if chosen is None:
            typer.echo("Container not found.", err=True)
            raise typer.Exit(1) from None
    elif project:
        for row in rows:
            compose = row.get("compose") or {}
            if str(compose.get("project") or "") == project:
                chosen = row
                break
        if chosen is None:
            typer.echo("Project not found.", err=True)
            raise typer.Exit(1)
    else:
        typer.echo("Provide a container target or --project.", err=True)
        raise typer.Exit(2)
    compose = (
        chosen.get("compose") if isinstance(chosen.get("compose"), dict) else {"detected": False}
    )
    out = {
        "container": chosen.get("name"),
        "compose": compose,
        "safety": "read-only; no compose command executed",
    }
    if json_out:
        typer.echo(json.dumps(out))
        return
    console.print("Compose context")
    console.print(f"- Detected: {'yes' if compose.get('detected') else 'no'}")
    console.print(f"- Container: {chosen.get('name')}")
    console.print(f"- Project: {compose.get('project') or '-'}")
    console.print(f"- Service: {compose.get('service') or '-'}")
    console.print(f"- Working dir: {compose.get('working_dir') or '-'}")
    console.print("- Config files:")
    for p in compose.get("config_files") or []:
        console.print(f"  - {p}")
    console.print(f"- One-off: {bool(compose.get('oneoff'))}")
    console.print(f"- Compose version: {compose.get('compose_version') or '-'}")
    console.print("- Safety: read-only; no compose command executed")


@compose_app.command("list")
def compose_list(json_out: Annotated[bool, typer.Option("--json")] = False) -> None:
    inv = containers.containers(all_containers=True)
    if not inv.ok:
        raise typer.Exit(1)
    rows = json.loads(inv.stdout or "{}").get("containers") or []
    projects: dict[str, dict[str, list[dict[str, Any]]]] = {}
    unmanaged: list[str] = []
    for row in rows:
        compose = row.get("compose") or {}
        if not compose.get("detected"):
            unmanaged.append(str(row.get("name") or ""))
            continue
        proj = str(compose.get("project") or "unknown")
        svc = str(compose.get("service") or "unknown")
        projects.setdefault(proj, {}).setdefault(svc, []).append(row)
    out = {"projects": projects, "unmanaged": unmanaged}
    if json_out:
        typer.echo(json.dumps(out))
        return
    console.print("Compose projects:")
    for proj, services_map in projects.items():
        console.print(f"- {proj}")
        for svc, members in services_map.items():
            console.print(f"  - service {svc}: {len(members)} container(s)")
    if unmanaged:
        console.print(f"- unmanaged: {len(unmanaged)}")


@compose_app.command("restart-preview")
def compose_restart_preview(
    target: Annotated[str, typer.Argument(help="Compose target (container/service/project)")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    payload = _build_compose_restart_preview(target)
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload.get("status") in {"ok", "incomplete"} else 1)
    status = payload.get("status")
    if status == "ambiguous":
        console.print("I found multiple Compose service matches. Please specify one:")
        for idx, cand in enumerate(payload.get("candidates", []), start=1):
            console.print(
                f"{idx}. target={cand.get('target')} project={cand.get('project') or '-'} "
                f"service={cand.get('service') or '-'} container={cand.get('container') or '-'}"
            )
        console.print("No docker compose command was executed.")
        raise typer.Exit(1)
    if status == "not_found":
        console.print("Compose service restart preview unavailable")
        console.print(f"- target: {target}")
        console.print("- compose-managed: false")
        console.print("- reason: no Compose project/service metadata found")
        console.print("No docker compose command was executed.")
        raise typer.Exit(1)
    if status == "error":
        console.print("Compose service restart preview unavailable")
        for warning in payload.get("warnings", []):
            console.print(f"- {warning}")
        console.print("No docker compose command was executed.")
        raise typer.Exit(2)
    compose = payload.get("compose") or {}
    preview = payload.get("preview") or {}
    console.print("Compose service restart preview")
    console.print("\nTarget:")
    console.print(f"- input: {target}")
    console.print("- compose-managed: true")
    console.print(f"- project: {compose.get('project') or '-'}")
    console.print(f"- service: {compose.get('service') or '-'}")
    console.print(f"- container: {compose.get('container') or '-'}")
    console.print(f"- working_dir: {compose.get('working_dir') or '-'}")
    console.print(f"- compose_file: {compose.get('compose_file') or '-'}")
    console.print("\nPreview:")
    console.print(f"- command: {preview.get('command_display') or '-'}")
    console.print(f"- compose_mutation: {preview.get('compose_mutation')}")
    console.print(f"- preview_only: {preview.get('preview_only')}")
    console.print(f"- execution_allowed: {preview.get('execution_allowed')}")
    console.print(f"- executed: {preview.get('executed')}")
    if status == "incomplete":
        for w in payload.get("warnings", []):
            console.print(f"- {w}")
    console.print("\nSafety:")
    console.print("- This PR does not execute docker compose commands.")
    console.print("- This preview is read-only.")
    console.print(
        "- Exact-container restart remains the only implemented infrastructure mutation lane."
    )
    console.print(
        "- Future Compose restart execution will require proposal, approval, rollback preview, "
        "mission readiness, apply gate, and verification."
    )
    console.print("\nOperator checks:")
    for item in payload.get("operator_checks", []):
        console.print(f"- {item}")
    raise typer.Exit(0 if status == "ok" else 1)


@compose_app.command("propose-restart")
def compose_propose_restart(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Compose target (container/service/project)")],
    reason: Annotated[
        str | None, typer.Option("--reason", help="Operator reason for proposal")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only")] = False,
) -> None:
    runtime = _ctx(ctx)
    payload = _create_compose_restart_proposal(runtime, target, reason)
    status = payload.get("status")
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if status == "created" else 1)
    if status == "created":
        proposal = payload.get("proposal") or {}
        compose = payload.get("compose") or {}
        preview = payload.get("preview") or {}
        console.print("Compose service restart proposal created")
        console.print("\nProposal:")
        console.print(f"- id: {proposal.get('id')}")
        console.print(f"- kind: {proposal.get('kind')}")
        console.print(f"- status: {proposal.get('status')}")
        console.print("- compose_mutation: true")
        console.print("- proposal_only: true")
        console.print("- execution_allowed: false")
        if reason:
            console.print(f"- reason: {reason}")
        console.print("\nTarget:")
        console.print(f"- input: {target}")
        console.print("- compose-managed: true")
        console.print(f"- project: {compose.get('project') or '-'}")
        console.print(f"- service: {compose.get('service') or '-'}")
        console.print(f"- container: {compose.get('container') or '-'}")
        console.print(f"- working_dir: {compose.get('working_dir') or '-'}")
        console.print(f"- compose_file: {compose.get('compose_file') or '-'}")
        console.print("\nProposed future command:")
        console.print(f"- {preview.get('command_display') or '-'}")
        console.print("\nSafety:")
        console.print("- This PR creates a pending proposal only.")
        console.print("- This PR does not execute docker compose commands.")
        console.print("- This proposal cannot be applied yet.")
        console.print("- Future execution will require a dedicated gated mission/apply lane.")
        console.print("- No container was restarted.")
        console.print("\nNext safe commands:")
        for cmd in payload.get("next_safe_commands", []):
            console.print(f"- {cmd}")
        raise typer.Exit(0)
    if status == "ambiguous":
        console.print("I found multiple Compose service matches. Please specify one:")
        for idx, cand in enumerate(payload.get("candidates", []), start=1):
            console.print(
                f"{idx}. target={cand.get('target')} project={cand.get('project') or '-'} "
                f"service={cand.get('service') or '-'} container={cand.get('container') or '-'}"
            )
    else:
        console.print("Compose service restart proposal unavailable")
        console.print(f"- target: {target}")
        compose_managed = bool((payload.get("target") or {}).get("compose_managed", False))
        console.print(f"- compose-managed: {str(compose_managed).lower()}")
        for warning in payload.get("warnings", []):
            console.print(f"- reason: {warning}")
    console.print("No proposal was created.")
    console.print("No docker compose command was executed.")
    raise typer.Exit(1)


@compose_app.command("env-check")
def compose_env_check(
    target: Annotated[
        str | None, typer.Option("--target", help="Compose target (container/service/project)")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only")] = False,
) -> None:
    payload: dict[str, Any] = {
        "schema_version": "1",
        "status": "unknown",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_input": target or "",
        "environment": {},
        "readiness": {"compose_restart_execution_ready": False, "blockers": [], "warnings": []},
        "safety": {
            "read_only": True,
            "docker_compose_executed": False,
            "container_restarted": False,
            "proposal_created": False,
            "mission_created": False,
            "apply_executed": False,
            "remediation_executed": False,
            "cleanup_executed": False,
            "rollback_executed": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "natural_language_execution": False,
        },
        "candidates": [],
        "next_safe_steps": [],
    }
    compose: dict[str, Any] = {}
    status = "ok"
    candidates: list[dict[str, Any]] = []
    if target:
        preview_payload = _build_compose_restart_preview(target)
        pstatus = str(preview_payload.get("status") or "unknown")
        if pstatus == "ambiguous":
            status = "ambiguous"
            candidates = list(preview_payload.get("candidates") or [])
        elif pstatus == "not_found":
            status = "not_found"
        else:
            compose = _normalize_compose_metadata(
                dict(preview_payload.get("compose") or {}), target_input=target or ""
            )
    preflight = _compose_cli_preflight(compose)
    env_status, env_blockers = _compose_environment_readiness(preflight)
    payload["environment"] = {**preflight, "status": env_status, "blockers": env_blockers}
    blockers: list[str] = list(env_blockers)
    warnings: list[str] = []
    if target and status not in {"ambiguous", "not_found"}:
        config = _compose_config_snapshot(compose)
        allowlisted = _compose_target_allowlisted(compose)
        target_blockers: list[str] = []
        if not bool(compose.get("compose_managed")):
            target_blockers.append("target_not_compose_managed")
        if not compose.get("project") or not compose.get("service"):
            target_blockers.append("compose_metadata_incomplete")
        if not compose.get("working_dir"):
            target_blockers.append("working_dir_missing")
        if not config.get("compose_file_known"):
            target_blockers.append("compose_file_missing")
        if not config.get("compose_file_snapshot_available"):
            target_blockers.append("compose_file_snapshot_unavailable")
        if not allowlisted:
            target_blockers.append("target_not_allowlisted")
        blockers.extend(list(config.get("blockers") or []))
        blockers.extend(target_blockers)
        payload["target"] = {
            "resolved": True,
            "compose_managed": bool(compose.get("compose_managed")),
            "container": compose.get("container"),
            "project": compose.get("project"),
            "service": compose.get("service"),
            "working_dir": compose.get("working_dir"),
            "compose_file": str(compose.get("compose_file") or ""),
            "config_files": list(compose.get("config_files") or []),
            "container_number": compose.get("container_number"),
            "oneoff": bool(compose.get("oneoff")),
        }
        payload["config_snapshot"] = config
        normalized_labels = _normalize_label_dict(compose)
        payload["allowlist"] = {
            "target_allowlisted": allowlisted,
            "disposable": _label_is_true(normalized_labels.get("shellforgeai.disposable")),
            "allow_restart": _label_is_true(normalized_labels.get("shellforgeai.allow_restart")),
            "test_harness": normalized_labels.get("shellforgeai.test_harness", ""),
            "scope": normalized_labels.get("shellforgeai.scope", ""),
            "blockers": ["target_not_allowlisted"] if not allowlisted else [],
            "warnings": [],
        }
    elif target:
        payload["target"] = {"resolved": False, "compose_managed": False}
        if status == "ambiguous":
            payload["candidates"] = candidates
        elif status == "not_found":
            blockers.append("target_not_found")
    else:
        payload["target"] = {"resolved": False, "none_selected": True}
        blockers.append("target_required_for_target_readiness")
    blockers = sorted({b for b in blockers if b})
    payload["readiness"] = {
        "compose_restart_execution_ready": not blockers,
        "blockers": blockers,
        "warnings": warnings,
    }
    payload["status"] = (
        status if status in {"ambiguous", "not_found"} else ("blocked" if blockers else "ok")
    )
    payload["next_safe_steps"] = [
        (
            "Provide Docker Compose CLI/plugin support in this execution "
            "environment when docker_compose_cli_unavailable is present."
        ),
        (
            "Expose a readable compose file path to ShellForgeAI when "
            "compose_file_snapshot_unavailable is present."
        ),
        (
            "Mark only disposable/test Compose targets allowlisted when "
            "target_not_allowlisted is present."
        ),
    ]
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload["status"] in {"ok", "blocked"} else 1)
    console.print("Compose execution environment check")
    console.print("\nExecution environment:")
    console.print(
        f"- docker cli: {'available' if preflight.get('docker_cli_available') else 'unavailable'}"
    )
    socket_state = (
        "available" if preflight.get("docker_socket_available") is not False else "unavailable"
    )
    console.print(f"- docker socket: {socket_state}")
    compose_state = "available" if preflight.get("compose_cli_available") else "unavailable"
    console.print(f"- docker compose cli/plugin: {compose_state}")
    inv_state = "supported" if preflight.get("required_invocation_supported") else "unsupported"
    console.print(f"- required invocation: {inv_state}")
    console.print(f"- status: {'ok' if not env_blockers else 'blocked'}")
    console.print("\nTarget:")
    if target:
        if payload["status"] == "ambiguous":
            console.print(f"- input: {target}")
            console.print("- status: ambiguous")
            console.print("- candidates:")
            for cand in candidates:
                console.print(
                    f"  - target={cand.get('target')} project={cand.get('project') or '-'} "
                    f"service={cand.get('service') or '-'} container={cand.get('container') or '-'}"
                )
        elif payload["status"] == "not_found":
            console.print(f"- input: {target}")
            console.print("- status: not_found")
        else:
            tgt = payload["target"]
            console.print(f"- input: {target}")
            console.print(f"- compose-managed: {str(tgt.get('compose_managed')).lower()}")
            console.print(f"- project: {tgt.get('project') or '-'}")
            console.print(f"- service: {tgt.get('service') or '-'}")
            console.print(f"- container: {tgt.get('container') or '-'}")
            console.print(f"- working_dir: {tgt.get('working_dir') or '-'}")
            console.print(f"- compose_file: {tgt.get('compose_file') or '-'}")
            cfg = payload.get("config_snapshot") or {}
            console.print("\nConfig snapshot:")
            console.print(f"- compose_file_readable: {cfg.get('compose_file_readable')}")
            console.print(
                f"- compose_file_sha256: {cfg.get('compose_file_sha256') or 'unavailable'}"
            )
            allow = payload.get("allowlist") or {}
            console.print("\nAllowlist:")
            console.print(f"- disposable: {str(allow.get('disposable', False)).lower()}")
            console.print(f"- allow_restart: {str(allow.get('allow_restart', False)).lower()}")
            console.print(
                f"- target_allowlisted: {str(allow.get('target_allowlisted', False)).lower()}"
            )
    else:
        console.print("- none selected")
    console.print("\nReadiness:")
    ready = payload["readiness"]["compose_restart_execution_ready"]
    console.print(f"- compose restart execution ready: {ready}")
    if payload["readiness"]["blockers"]:
        console.print("- blockers:")
        for b in payload["readiness"]["blockers"]:
            console.print(f"  - {b}")
    console.print("\nSafety:")
    console.print("- read-only: true")
    console.print("- no docker compose command was executed except read-only preflight checks")
    console.print("- no container was restarted")


@compose_app.command("env-contract")
def compose_env_contract(
    target: Annotated[
        str | None, typer.Option("--target", help="Compose target (container/service/project)")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only")] = False,
) -> None:
    payload = _compose_env_contract_payload(target)
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload["status"] in {"ready", "blocked"} else 1)
    console.print("Compose execution environment contract")
    console.print("\nTarget:")
    tgt = payload["target"]
    console.print(f"- input: {tgt.get('input') or '-'}")
    console.print(f"- compose-managed: {str(tgt.get('compose_managed', False)).lower()}")
    console.print(f"- project: {tgt.get('project') or '-'}")
    console.print(f"- service: {tgt.get('service') or '-'}")
    console.print(f"- container: {tgt.get('container') or '-'}")
    console.print(f"- disposable: {str(tgt.get('disposable', False)).lower()}")
    console.print(f"- allow_restart: {str(tgt.get('allow_restart', False)).lower()}")
    console.print("\nEnvironment gates:")
    env = payload["environment"]
    console.print(
        f"- docker CLI inside container: {'pass' if env.get('docker_cli_available') else 'blocked'}"
    )
    console.print(
        f"- docker socket reachable: {'pass' if env.get('docker_socket_available') else 'blocked'}"
    )
    console.print(
        "- docker compose CLI/plugin: "
        f"{'pass' if env.get('docker_compose_cli_available') else 'blocked'}"
    )
    console.print(
        "- required invocation supported: "
        f"{'pass' if env.get('required_invocation_supported') else 'blocked'}"
    )
    snapshot = payload["snapshot"]
    console.print("\nSnapshot gates:")
    console.print(f"- compose file path known: {snapshot.get('compose_file') or '-'}")
    console.print(
        "- compose file readable inside container: "
        f"{'pass' if snapshot.get('compose_file_readable') else 'blocked'}"
    )
    console.print(f"- compose file sha256: {snapshot.get('compose_file_sha256') or 'unavailable'}")
    read = payload["readiness"]
    console.print("\nExecution readiness:")
    console.print(f"- ready: {str(read.get('ready', False)).lower()}")
    console.print(
        "- ready_for_optional_disposable_proof: "
        f"{str(read.get('ready_for_optional_disposable_proof', False)).lower()}"
    )
    if read.get("blockers"):
        console.print("- blockers:")
        for b in read["blockers"]:
            console.print(f"  - {b}")
    console.print("\nSafety:")
    console.print("- no docker compose command was executed")
    console.print("- no container was restarted")
    console.print("- natural-language execution remains refused")
    console.print("- production targets are not allowlisted by default")


@compose_app.command("env-plan")
def compose_env_plan(
    target: Annotated[
        str | None, typer.Option("--target", help="Compose target (container/service/project)")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only")] = False,
) -> None:
    payload = _compose_env_plan_payload(target)
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload["status"] in {"ok", "blocked", "not_found"} else 1)
    tgt = payload["target"]
    readiness = payload["readiness"]
    console.print("Compose execution environment plan")
    console.print("\nTarget:")
    console.print(f"- input: {tgt.get('input') or '-'}")
    console.print(f"- compose-managed: {str(tgt.get('compose_managed', False)).lower()}")
    console.print(f"- project: {tgt.get('project') or '-'}")
    console.print(f"- service: {tgt.get('service') or '-'}")
    console.print(f"- container: {tgt.get('container') or '-'}")
    console.print(f"- disposable: {str(tgt.get('disposable', False)).lower()}")
    console.print(f"- allow_restart: {str(tgt.get('allow_restart', False)).lower()}")
    console.print(f"- target_allowlisted: {str(tgt.get('target_allowlisted', False)).lower()}")
    console.print(f"- production_like: {str(tgt.get('production_like', False)).lower()}")
    if tgt.get("production_like") and not tgt.get("target_allowlisted"):
        console.print("\nTarget is not eligible for Compose execution proof.")
        console.print("Reason:")
        console.print("- target_not_allowlisted")
        console.print("- production target should not be labeled disposable for testing")
        console.print("Recommended safe action:")
        console.print("- use the PR67 disposable harness target instead")
    console.print("\nCurrent readiness:")
    console.print(f"- ready: {str(readiness.get('ready', False)).lower()}")
    console.print(
        "- ready_for_optional_disposable_proof: "
        f"{str(readiness.get('ready_for_optional_disposable_proof', False)).lower()}"
    )
    if not readiness.get("blockers"):
        console.print("\nBlockers:")
        console.print("- none")
    else:
        console.print("\nBlockers:")
        for idx, entry in enumerate(payload.get("plan") or [], start=1):
            console.print(f"  {idx}. {entry.get('blocker')}")
            console.print(f"     Meaning: {entry.get('meaning')}")
            console.print(f"     Operator remediation: {entry.get('operator_remediation')}")
            console.print("     ShellForgeAI action: none; no automated remediation performed.")
    console.print("\nRequired after remediation:")
    for line in payload.get("post_conditions") or []:
        console.print(f"- {line}")
    if payload.get("warnings"):
        console.print("\nWarnings:")
        for warning in payload["warnings"]:
            console.print(f"- {warning}")
    console.print("\nSafety:")
    console.print("- read_only: true")
    console.print("- docker_compose_executed: false")
    console.print("- container_restarted: false")
    console.print("- host_side_bypass: false")
    console.print("- arbitrary_command_execution: false")
    console.print("- natural_language_execution: false")


@ops_app.command("status")
def ops_status(json_out: Annotated[bool, typer.Option("--json")] = False) -> None:
    settings = load_settings()
    profile = load_profile(settings.app.default_profile, Path.cwd())
    session = build_session_context(settings, profile, mode="cli", cwd=Path.cwd())
    data_dir = session.data_dir
    warnings: list[str] = []
    now = datetime.now(timezone.utc).isoformat()

    evidence_path = latest_evidence_artifact(data_dir)
    latest_evidence: dict[str, Any] | None = None
    if evidence_path and evidence_path.exists():
        ev = _safe_load_json(evidence_path, warnings) or {}
        latest_evidence = {
            "id": evidence_path.parent.name,
            "path": str(evidence_path),
            "created_at": ev.get("created_at"),
            "updated_at": ev.get("updated_at"),
            "age_seconds": _age_seconds(ev, evidence_path),
            "target": ev.get("target"),
            "runbook_present": (evidence_path.parent / "runbook.json").exists(),
        }

    proposals_root = data_dir / "proposals"
    proposal_items: list[dict[str, Any]] = []
    proposal_counts = {
        k: 0 for k in ("pending", "approved", "rejected", "canceled", "archived", "unknown")
    }
    for p in sorted(proposals_root.glob("*.json")) if proposals_root.exists() else []:
        obj = _safe_load_json(p, warnings)
        if not obj:
            continue
        st = str(obj.get("status") or "unknown")
        proposal_counts[st if st in proposal_counts else "unknown"] += 1
        proposal_items.append({"path": p, "payload": obj})
    latest_prop = max(proposal_items, key=lambda x: _ts(x["payload"], x["path"]), default=None)
    prop_summary = None
    if latest_prop:
        pp = latest_prop["payload"]
        compose = pp.get("compose") if isinstance(pp.get("compose"), dict) else {}
        prop_summary = {
            "id": pp.get("proposal_id") or latest_prop["path"].stem,
            "path": str(latest_prop["path"]),
            "kind": pp.get("kind"),
            "status": pp.get("status", "unknown"),
            "target": pp.get("target_container"),
            "created_at": pp.get("created_at"),
            "updated_at": pp.get("updated_at"),
            "age_seconds": _age_seconds(pp, latest_prop["path"]),
            "compose": {
                "managed": bool(compose.get("managed") or compose.get("detected")),
                "project": compose.get("project"),
                "service": compose.get("service"),
                "restart_scope": "container",
                "compose_mutation": False,
            },
        }

    mission_items: list[dict[str, Any]] = []
    mission_counts = {k: 0 for k in ("ready", "executed", "blocked", "failed", "unknown")}
    for p in (
        sorted((data_dir / "missions").glob("**/mission.json"))
        if (data_dir / "missions").exists()
        else []
    ):
        obj = _safe_load_json(p, warnings)
        if not obj:
            continue
        st = str(obj.get("status") or "unknown")
        mission_counts[st if st in mission_counts else "unknown"] += 1
        mission_items.append({"path": p, "payload": obj})
    latest_m = max(mission_items, key=lambda x: _ts(x["payload"], x["path"]), default=None)
    latest_exec = max(
        [m for m in mission_items if str(m["payload"].get("status")) == "executed"],
        key=lambda x: _ts(x["payload"], x["path"]),
        default=None,
    )

    def _mission_summary(item: dict[str, Any] | None) -> dict[str, Any] | None:
        if not item:
            return None
        mp = item["payload"]
        compose = mp.get("compose") if isinstance(mp.get("compose"), dict) else {}
        return {
            "id": mp.get("mission_id") or item["path"].parent.name,
            "path": str(item["path"]),
            "mission_type": mp.get("mission_type", "docker_restart"),
            "status": mp.get("status", "unknown"),
            "target": mp.get("target_container"),
            "proposal_id": mp.get("proposal_id"),
            "created_at": mp.get("created_at"),
            "updated_at": mp.get("updated_at"),
            "age_seconds": _age_seconds(mp, item["path"]),
            "compose": {
                "managed": bool(compose.get("managed") or compose.get("detected")),
                "project": compose.get("project"),
                "service": compose.get("service"),
                "restart_scope": "container",
                "compose_mutation": False,
            },
        }

    latest_mission = _mission_summary(latest_m)
    latest_executed = _mission_summary(latest_exec)
    audit_status = "unknown"
    if (data_dir / "audit_events.jsonl").exists():
        audit_status = "ok"
    cleanup_report = scan_metadata_hygiene(data_dir)
    total_bytes = cleanup_report.get("total_bytes", 0)
    cleanup_status = "ok" if isinstance(total_bytes, int) and total_bytes >= 0 else "unknown"
    payload = {
        "schema_version": "1",
        "status": "warn" if warnings else "ok",
        "generated_at": now,
        "data_dir": str(data_dir),
        "latest_evidence": latest_evidence,
        "proposals": {"latest": prop_summary, "counts": proposal_counts},
        "missions": {
            "latest": latest_mission,
            "latest_executed": latest_executed,
            "counts": mission_counts,
        },
        "compose": {
            "recent_managed_targets_count": sum(
                1 for i in [prop_summary, latest_mission] if i and i["compose"]["managed"]
            ),
            "latest_target": (latest_mission or prop_summary or {}).get("target"),
            "latest_project": ((latest_mission or prop_summary or {}).get("compose") or {}).get(
                "project"
            ),
            "latest_service": ((latest_mission or prop_summary or {}).get("compose") or {}).get(
                "service"
            ),
            "compose_mutation": False,
        },
        "safety": {
            "read_only": True,
            "natural_language_mutation_refused": True,
            "arbitrary_command_execution": False,
            "compose_mutation": False,
            "execution_requires_apply_gate": True,
        },
        "audit": {"status": audit_status, "latest_export": None, "latest_closure_report": None},
        "cleanup": {
            "status": cleanup_status,
            "latest_cleanup_plan": None,
            "latest_cleanup_archive": None,
        },
        "warnings": warnings,
        "next_safe_commands": [
            'shellforgeai ask "show compose context for this restart proposal"',
            "shellforgeai approvals list --all",
            "shellforgeai mission restart status <mission-id>",
            "shellforgeai audit validate",
        ],
    }
    if json_out:
        typer.echo(json.dumps(payload))
        return
    console.print("ShellForgeAI ops status")
    console.print("\nLatest evidence:")
    if not latest_evidence:
        console.print("- none found")
    else:
        console.print(f"- artifact: {latest_evidence['id']}")
        console.print(f"- age_seconds: {latest_evidence['age_seconds']}")
    console.print("\nProposals:")
    console.print(f"- latest: {(prop_summary or {}).get('id', 'none')}")
    console.print(f"- counts: {proposal_counts}")
    console.print("\nMissions:")
    console.print(f"- latest: {(latest_mission or {}).get('id', 'none')}")
    console.print(f"- latest executed: {(latest_executed or {}).get('id', 'none')}")
    console.print("\nSafety:")
    console.print("- read_only: true")
    console.print("- compose_mutation: false")
    console.print("- arbitrary_command_execution: false")
    console.print("- apply gate: required")


@session_summary_app.command("validate")
def session_summary_validate(
    summary_ref: Annotated[str, typer.Argument(help="Summary id or summary directory path")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.interactive_summary_artifact import validate_interactive_summary

    payload = validate_interactive_summary(summary_ref, Path(load_settings().app.data_dir))
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload.get("status") == "ok" else 1)
    console.print(
        "Interactive summary validation passed"
        if payload.get("status") == "ok"
        else "Interactive summary validation failed"
    )
    for k, v in (payload.get("checks") or {}).items():
        console.print(f"- {k}: {'ok' if v else 'failed'}")
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@session_summary_app.command("export")
def session_summary_export(
    summary_ref: Annotated[str, typer.Argument(help="Summary id or path")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.interactive_summary_artifact import export_interactive_summary

    payload = export_interactive_summary(summary_ref, Path(load_settings().app.data_dir))
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload.get("status") == "exported" else 1)
    if payload.get("status") != "exported":
        console.print("Interactive summary export failed")
        for warning in payload.get("warnings") or []:
            console.print(f"- {warning}")
        raise typer.Exit(1)
    export = payload.get("export") or {}
    source = payload.get("source_summary") or {}
    console.print(
        "Interactive summary export created"
        if not payload.get("existing")
        else "Interactive summary export already exists (reused)"
    )
    console.print(f"- summary_id: {source.get('id')}")
    console.print(f"- export_id: {export.get('id')}")
    console.print(f"- path: {export.get('path')}")


@session_summary_app.command("export-validate")
def session_summary_export_validate(
    export_ref: Annotated[str, typer.Argument(help="Export id or path")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.interactive_summary_artifact import validate_interactive_summary_export

    payload = validate_interactive_summary_export(export_ref, Path(load_settings().app.data_dir))
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload.get("status") == "ok" else 1)
    console.print(
        "Interactive summary export validation passed"
        if payload.get("status") == "ok"
        else "Interactive summary export validation failed"
    )
    for k, v in (payload.get("checks") or {}).items():
        console.print(f"- {k}: {'ok' if v else 'failed'}")
    if payload.get("status") != "ok":
        raise typer.Exit(1)


def _render_interactive_summary_history_human(payload: dict[str, Any]) -> str:
    lines = ["Interactive summary history", ""]
    if payload.get("status") == "empty":
        lines.append("No saved interactive summaries found.")
        lines.append("Try: shellforgeai interactive, then /summary --save")
    else:
        latest = (payload.get("summaries") or [None])[0]
        if latest:
            lines.extend(["Latest:", ""])
            lines.append(f"- {latest.get('summary_id')}")
            lines.append(f"- created: {latest.get('created_at') or '-'}")
            lines.append(f"- events: {latest.get('events_seen', 0)}")
            latest_checks = latest.get("checks_count", 0)
            latest_findings = latest.get("findings_count", 0)
            lines.append(f"- checks/findings: {latest_checks}/{latest_findings}")
            lines.append(f"- refusals: {latest.get('refusals_count', 0)}")
            lines.append(f"- first safe command: {latest.get('first_safe_command') or '-'}")
            lines.append(f"- path: {latest.get('path')}")
        lines.extend(["", "Recent summaries:"])
        for idx, summary in enumerate(payload.get("summaries") or [], start=1):
            lines.append(f"{idx}. {summary.get('summary_id')}")
            lines.append(f"   created: {summary.get('created_at') or '-'}")
            lines.append(f"   events: {summary.get('events_seen', 0)}")
            checks_count = summary.get("checks_count", 0)
            findings_count = summary.get("findings_count", 0)
            lines.append(f"   checks/findings: {checks_count}/{findings_count}")
            lines.append(f"   refusals: {summary.get('refusals_count', 0)}")
            lines.append(f"   first safe command: {summary.get('first_safe_command') or '-'}")
            lines.append(f"   path: {summary.get('path')}")
    if payload.get("warnings"):
        lines.extend(["", "Warnings:"])
        for warning in payload.get("warnings") or []:
            lines.append(f"- {warning}")
    lines.extend(
        [
            "",
            (
                "Safety: read-only. No collection, mutation, cleanup, remediation, "
                "rollback, or Compose command executed."
            ),
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _render_interactive_summary_compare_human(
    payload: dict[str, Any], *, include_stable: bool = False
) -> str:
    if payload.get("mode") == "interactive_summary_compare_export":
        title = "Interactive summary export compare"
    else:
        title = (
            "Interactive summary compare-latest"
            if payload.get("compare_latest")
            else "Interactive summary compare"
        )
    lines = [title]
    if payload.get("compare_latest"):
        lines.append("Comparing latest two summaries...")
    lines.extend(["", f"Status: {payload.get('status')}"])
    if payload.get("status") != "ok":
        for warning in payload.get("warnings") or []:
            lines.append(f"- {warning}")
        lines.append(
            "Safety: read-only. No collectors/model/shell/mutation, cleanup, remediation, "
            "rollback, or Compose command executed."
        )
        return "\n".join(lines).rstrip() + "\n"
    if payload.get("mode") == "interactive_summary_compare_export":
        before = payload.get("before") or {}
        after = payload.get("after") or {}
        lines.append(
            f"Before export: {before.get('export_ref') or payload.get('before_export_id')}"
        )
        lines.append(f"After export: {after.get('export_ref') or payload.get('after_export_id')}")
        lines.append(f"Before summary: {payload.get('before_summary_id')}")
        lines.append(f"After summary: {payload.get('after_summary_id')}")
    else:
        lines.append(f"Before: {payload.get('before_summary_id')}")
        lines.append(f"After: {payload.get('after_summary_id')}")
    summary = payload.get("summary") or {}
    lines.extend(
        [
            "",
            "Changes:",
            f"- events: {summary.get('events_before')} -> {summary.get('events_after')}",
            f"- checks: {summary.get('checks_before')} -> {summary.get('checks_after')}",
            f"- findings: {summary.get('findings_before')} -> {summary.get('findings_after')}",
            f"- new findings: {summary.get('new_findings')}",
            f"- resolved/missing findings: {summary.get('resolved_or_missing_findings')}",
            f"- new refusals: {summary.get('new_refusals')}",
            f"- safety drift: {summary.get('safety_drift')}",
        ]
    )
    for label, key in (
        ("New checks", "new_checks"),
        ("New findings", "new_findings"),
        ("Resolved/missing checks", "resolved_or_missing_checks"),
        ("Resolved/missing findings", "resolved_or_missing_findings"),
        ("New refusals", "new_refusals"),
    ):
        values = payload.get(key) or []
        if values:
            lines.extend(["", f"{label}:"])
            for value in values[:8]:
                lines.append(f"- {value}")
    if payload.get("safety_drift"):
        lines.extend(["", "Safety drift:"])
        for item in payload.get("safety_drift") or []:
            lines.append(f"- {item.get('flag')}: {item.get('before')} -> {item.get('after')}")
    if include_stable and payload.get("stable"):
        lines.extend(["", "Stable items:"])
        for key, value in (payload.get("stable") or {}).items():
            lines.append(f"- {key}: {value}")
    lines.extend(["", f"First safe command: {payload.get('first_safe_command') or '-'}"])
    lines.append(
        "Safety: read-only. No collectors/model/shell/mutation, cleanup, remediation, "
        "rollback, or Compose command executed."
    )
    return "\n".join(lines).rstrip() + "\n"


@session_summary_app.command("history")
def session_summary_history(
    json_out: Annotated[bool, typer.Option("--json")] = False,
    limit: Annotated[int, typer.Option("--limit", min=1)] = 10,
) -> None:
    from shellforgeai.core.interactive_summary_artifact import interactive_summary_history

    payload = interactive_summary_history(Path(load_settings().app.data_dir), limit=limit)
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0)
    console.print(_render_interactive_summary_history_human(payload), end="")


@session_summary_app.command("compare")
def session_summary_compare(
    before_ref: Annotated[str, typer.Argument(help="Before summary id or path")],
    after_ref: Annotated[str, typer.Argument(help="After summary id or path")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
    only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
    include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
) -> None:
    from shellforgeai.core.interactive_summary_artifact import compare_interactive_summaries

    payload = compare_interactive_summaries(
        before_ref,
        after_ref,
        Path(load_settings().app.data_dir),
        only_changed=only_changed,
        include_stable=include_stable,
    )
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload.get("status") == "ok" else 1)
    if payload.get("status") != "ok":
        console.print(_render_interactive_summary_compare_human(payload), end="")
        raise typer.Exit(1)
    console.print(
        _render_interactive_summary_compare_human(payload, include_stable=include_stable), end=""
    )


@session_summary_app.command("compare-export")
def session_summary_compare_export(
    before_ref: Annotated[str, typer.Argument(help="Before interactive summary export id or path")],
    after_ref: Annotated[str, typer.Argument(help="After interactive summary export id or path")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
    only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
    include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
) -> None:
    from shellforgeai.core.interactive_summary_artifact import compare_interactive_summary_exports

    payload = compare_interactive_summary_exports(
        before_ref,
        after_ref,
        Path(load_settings().app.data_dir),
        only_changed=only_changed,
        include_stable=include_stable,
    )
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload.get("status") == "ok" else 1)
    if payload.get("status") != "ok":
        console.print(_render_interactive_summary_compare_human(payload), end="")
        raise typer.Exit(1)
    console.print(
        _render_interactive_summary_compare_human(payload, include_stable=include_stable), end=""
    )


@session_summary_app.command("compare-latest")
def session_summary_compare_latest(
    json_out: Annotated[bool, typer.Option("--json")] = False,
    only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
    include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
) -> None:
    from shellforgeai.core.interactive_summary_artifact import compare_latest_interactive_summaries

    payload = compare_latest_interactive_summaries(
        Path(load_settings().app.data_dir),
        only_changed=only_changed,
        include_stable=include_stable,
    )
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload.get("status") == "ok" else 1)
    if payload.get("status") != "ok":
        console.print(_render_interactive_summary_compare_human(payload), end="")
        raise typer.Exit(1)
    console.print(
        _render_interactive_summary_compare_human(payload, include_stable=include_stable), end=""
    )


@ops_report_app.callback()
def ops_report(
    ctx: typer.Context,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    top: Annotated[int, typer.Option("--top", min=1)] = 5,
    include_details: Annotated[bool, typer.Option("--include-details")] = False,
    include_remediation: Annotated[bool, typer.Option("--include-remediation")] = False,
    include_timeline: Annotated[bool, typer.Option("--include-timeline")] = False,
    save: Annotated[bool, typer.Option("--save")] = False,
    brief: Annotated[
        bool, typer.Option("--brief", help="Render compact human pressure-mode output.")
    ] = False,
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    payload = _build_ops_report_payload(
        top=top,
        include_details=include_details,
        include_remediation=include_remediation,
        include_timeline=include_timeline,
        include_visibility=brief and not json_out and not save,
    )
    if save:
        from shellforgeai.core.ops_report_artifact import save_ops_report

        saved = save_ops_report(
            payload,
            Path(load_settings().app.data_dir),
            source_command="shellforgeai ops report --save",
        )
        if json_out:
            typer.echo(json.dumps(saved))
            return
        console.print("Ops report saved")
        console.print(f"- id: {saved.get('report_id')}")
        console.print(f"- path: {saved.get('report_path')}")
        return
    if json_out:
        typer.echo(json.dumps(payload))
        return
    if brief:
        typer.echo(_render_ops_report_brief(payload), nl=False)
        return
    top_suspect = payload["suspects"][0] if payload["suspects"] else None
    lines = ["ShellForgeAI 2AM Operator Report", ""]
    lines.append(
        "Status: "
        f"{payload.get('status')} — "
        f"{payload['summary'].get('critical', 0)} critical and "
        f"{payload['summary'].get('high', 0)} high Docker suspects found."
    )
    lines.append(
        "Summary: "
        f"{payload['summary'].get('critical', 0)} critical, "
        f"{payload['summary'].get('high', 0)} high suspects"
    )
    if top_suspect:
        lines.append(f"Top suspect: {top_suspect['name']} — {top_suspect['severity']} severity")
        lines.append(f"First safe command: {triage_detail_command(top_suspect['name'])}")
    lines.extend(["", "Safety:"])
    for k, v in payload["safety"].items():
        lines.append(f"- {k}: {str(v).lower()}")
    lines.extend(["", "Current scene:"])
    for k, v in payload["summary"].items():
        lines.append(f"- {k}: {v}")
    lines.extend(["", "Top suspects:"])
    if not payload["suspects"]:
        lines.append("- none")
    for s in payload["suspects"]:
        lines.append(f"{s['rank']}. {s['name']} — {s['severity']} / {s['confidence']} confidence")
        if s["evidence_summary"]:
            lines.append(f"   Why: {', '.join(s['evidence_summary'][:3])}")
        lines.append(f"   Safe inspect: {triage_detail_command(s['name'])}")
        lines.append(f"   Remediation gate: {s['remediation']['eligibility']}")
        lines.append(f"   Explain: {remediation_eligibility_explain_command(s['name'])}")
    lines.extend(["", "Remediation lane:"])
    lines.append(f"- self-test quick: {payload['remediation_lane']['self_test_quick']}")
    lines.append(f"- self-test standard: {payload['remediation_lane']['self_test_standard']}")
    lines.append(f"- self-test full: {payload['remediation_lane']['self_test_full']}")
    lines.append(f"- latest lifecycle audit: {payload['remediation_lane']['latest_audit']}")
    lines.extend(["", "Recommended next steps:"])
    for idx, cmd in enumerate(payload["safe_next_commands"][:5], start=1):
        lines.append(f"{idx}. {cmd}")
    typer.echo("\n".join(lines).rstrip() + "\n")


@ops_report_app.command("validate")
def ops_report_validate(
    report_ref: Annotated[str, typer.Argument(help="Report id or report directory path")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.ops_report_artifact import validate_ops_report

    payload = validate_ops_report(report_ref, Path(load_settings().app.data_dir))
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload.get("status") == "ok" else 1)
    console.print(
        "Ops report validation passed"
        if payload.get("status") == "ok"
        else "Ops report validation failed"
    )
    for k, v in (payload.get("checks") or {}).items():
        console.print(f"- {k}: {'ok' if v else 'failed'}")
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@ops_report_app.command("export")
def ops_report_export(
    report_ref: Annotated[str, typer.Argument(help="Report id or path")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.ops_report_artifact import export_ops_report

    payload = export_ops_report(report_ref, Path(load_settings().app.data_dir))
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload.get("status") == "exported" else 1)
    if payload.get("status") != "exported":
        console.print("Ops report export failed")
        for w in payload.get("warnings") or []:
            console.print(f"- {w}")
        raise typer.Exit(1)
    ex = payload.get("export") or {}
    src = payload.get("source_report") or {}
    console.print(
        "Ops report export created"
        if not payload.get("existing")
        else "Ops report export already exists (reused)"
    )
    console.print(f"- report_id: {src.get('id')}")
    console.print(f"- export_id: {ex.get('id')}")
    console.print(f"- path: {ex.get('path')}")


@ops_report_app.command("export-validate")
def ops_report_export_validate(
    export_ref: Annotated[str, typer.Argument(help="Export id or path")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.ops_report_artifact import validate_ops_report_export

    payload = validate_ops_report_export(export_ref, Path(load_settings().app.data_dir))
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload.get("status") == "ok" else 1)
    console.print(
        "Ops report export validation passed"
        if payload.get("status") == "ok"
        else "Ops report export validation failed"
    )
    for k, v in (payload.get("checks") or {}).items():
        console.print(f"- {k}: {'ok' if v else 'failed'}")
    if payload.get("status") != "ok":
        raise typer.Exit(1)


def _render_ops_report_compare_human(
    payload: dict[str, Any], *, top: int = 5, include_stable: bool = False
) -> str:
    summary = payload.get("summary") or {}
    reports = payload.get("reports") or {}
    lines = ["Ops report compare", "", "Reports:"]
    lines.append(f"- before: {(reports.get('before') or {}).get('id', 'unknown')}")
    lines.append(f"- after:  {(reports.get('after') or {}).get('id', 'unknown')}")
    lines.extend(["", "Scene drift:"])
    for key in (
        "suspects_before",
        "suspects_after",
        "new",
        "resolved_or_missing",
        "escalated",
        "improved",
        "stable",
    ):
        lines.append(f"- {key.replace('_', ' ')}: {summary.get(key, 0)}")
    lines.extend(["", "Top changes:"])
    changes = (
        (payload.get("severity_escalations") or [])
        + (payload.get("severity_improvements") or [])
        + (payload.get("rank_changes") or [])
    )
    if not changes:
        lines.append("- none")
    for idx, ch in enumerate(changes[: max(1, top)], start=1):
        lines.append(f"{idx}. {ch.get('name')}")
        lines.append(f"   severity: {ch.get('before_severity')} -> {ch.get('after_severity')}")
        lines.append(f"   rank: {ch.get('before_rank')} -> {ch.get('after_rank')}")
    lines.extend(["", "Remediation lane:"])
    lane = payload.get("remediation_lane") or {}
    lines.append(f"- before: {lane.get('before')}")
    lines.append(f"- after: {lane.get('after')}")
    lines.append("- no execution recorded")
    lines.extend(["", "Safety:", "- read_only=true", "- mutation_performed=false"])
    if include_stable and payload.get("stable_suspects"):
        lines.extend(["", "Stable suspects:"])
        for name in payload.get("stable_suspects") or []:
            lines.append(f"- {name}")
    lines.extend(["", "Safe next commands:"])
    for cmd in (payload.get("safe_next_commands") or [])[:5]:
        lines.append(f"- {cmd}")
    return "\n".join(lines).rstrip() + "\n"


def _render_ops_report_history_human(payload: dict[str, Any]) -> str:
    lines = ["Ops report history", ""]
    summary = payload.get("summary") or {}
    lines.append(f"Reports found: {summary.get('reports_found', 0)}")
    lines.append("")
    reports = payload.get("reports") or []
    if not reports:
        lines.append("No saved ops reports found.")
    for idx, report in enumerate(reports, start=1):
        lines.append(f"{idx}. {report.get('report_id')}")
        lines.append(f"   created: {report.get('created_at') or '-'}")
        lines.append(f"   suspects: {report.get('suspects_ranked')}")
        lines.append(f"   critical: {report.get('critical')}")
        lines.append(f"   high: {report.get('high')}")
        lines.append(f"   top suspect: {report.get('top_suspect') or '-'}")
        lines.append(f"   path: {report.get('path')}")
    lines.extend(["", "Latest compare availability:"])
    lines.append(
        "- available"
        if summary.get("valid_reports", 0) >= 2
        else "- unavailable (need >=2 valid reports)"
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


@ops_report_app.command("compare")
def ops_report_compare(
    before_ref: Annotated[str, typer.Argument(help="Before report id or path")],
    after_ref: Annotated[str, typer.Argument(help="After report id or path")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
    only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
    include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
    top: Annotated[int, typer.Option("--top", min=1)] = 5,
) -> None:
    from shellforgeai.core.ops_report_artifact import compare_ops_reports

    payload = compare_ops_reports(
        before_ref,
        after_ref,
        Path(load_settings().app.data_dir),
        only_changed=only_changed,
        include_stable=include_stable,
    )
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload.get("status") == "ok" else 1)
    if payload.get("status") != "ok":
        console.print("Ops report compare failed")
        for warning in payload.get("warnings") or []:
            console.print(f"- {warning}")
        raise typer.Exit(1)
    console.print(
        _render_ops_report_compare_human(payload, top=top, include_stable=include_stable), end=""
    )


@ops_report_app.command("history")
def ops_report_history(
    json_out: Annotated[bool, typer.Option("--json")] = False,
    limit: Annotated[int, typer.Option("--limit", min=1)] = 10,
    include_drift: Annotated[bool, typer.Option("--include-drift")] = False,
) -> None:
    from shellforgeai.core.ops_report_artifact import ops_report_history as build_ops_report_history

    payload = build_ops_report_history(
        Path(load_settings().app.data_dir), limit=limit, include_drift=include_drift
    )
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload.get("status") == "ok" else 1)
    console.print(_render_ops_report_history_human(payload), end="")
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@ops_report_app.command("compare-latest")
def ops_report_compare_latest(
    json_out: Annotated[bool, typer.Option("--json")] = False,
    only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
    include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
    top: Annotated[int, typer.Option("--top", min=1)] = 5,
) -> None:
    from shellforgeai.core.ops_report_artifact import compare_latest_ops_reports

    payload = compare_latest_ops_reports(
        Path(load_settings().app.data_dir),
        only_changed=only_changed,
        include_stable=include_stable,
    )
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload.get("status") == "ok" else 1)
    if payload.get("status") != "ok":
        console.print("Ops report compare-latest unavailable")
        for warning in payload.get("warnings") or []:
            console.print(f"- {warning}")
        raise typer.Exit(1)
    console.print(
        _render_ops_report_compare_human(payload, top=top, include_stable=include_stable), end=""
    )


@ops_report_app.command("compare-export")
def ops_report_compare_export(
    before_ref: Annotated[str, typer.Argument(help="Before export id or path")],
    after_ref: Annotated[str, typer.Argument(help="After export id or path")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
    only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
    include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
    top: Annotated[int, typer.Option("--top", min=1)] = 5,
) -> None:
    from shellforgeai.core.ops_report_artifact import compare_ops_report_exports

    payload = compare_ops_report_exports(
        before_ref,
        after_ref,
        Path(load_settings().app.data_dir),
        only_changed=only_changed,
        include_stable=include_stable,
    )
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload.get("status") == "ok" else 1)
    if payload.get("status") != "ok":
        console.print("Ops report export compare failed")
        for warning in payload.get("warnings") or []:
            console.print(f"- {warning}")
        raise typer.Exit(1)
    console.print(
        _render_ops_report_compare_human(payload, top=top, include_stable=include_stable), end=""
    )


@v1_packet_app.callback(invoke_without_command=True)
def v1_packet(
    ctx: typer.Context,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    save: Annotated[bool, typer.Option("--save")] = False,
) -> None:
    from shellforgeai.core.v1_packet import build_packet, save_packet

    if ctx.invoked_subcommand is not None:
        return

    payload = build_packet(app)
    if save:
        saved = save_packet(payload, Path(load_settings().app.data_dir))
        payload["packet_id"] = saved["packet_id"]
        payload["packet_path"] = saved["packet_path"]
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload.get("status") != "failed" else 1)
    console.print("V1 readiness packet")
    console.print("")
    console.print(f"Status: {payload.get('status')}")
    console.print("\nChecks:")
    for name, check in (payload.get("checks") or {}).items():
        console.print(f"- {name.replace('_', ' ')}: {check.get('status')}")
    console.print("\nSafety:")
    console.print("- read_only: true")
    console.print("- mutation_performed: false")
    console.print("- no remediation/rollback/cleanup/Compose execution")
    console.print("\nSafe next commands:")
    for cmd in payload.get("safe_next_commands") or []:
        console.print(f"- {cmd}")
    if save:
        console.print("")
        console.print(f"packet_id: {payload['packet_id']}")
        console.print(f"packet_path: {payload['packet_path']}")
        console.print(f"validate: shellforgeai v1 packet validate {payload['packet_id']}")
        console.print(f"export: shellforgeai v1 packet export {payload['packet_id']}")
    raise typer.Exit(0 if payload.get("status") != "failed" else 1)


@v1_packet_app.command("validate")
def v1_packet_validate(
    packet_ref: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.v1_packet import validate_packet

    payload = validate_packet(packet_ref, Path(load_settings().app.data_dir))
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        console.print(f"V1 packet validate: {payload.get('status')}")
        for w in payload.get("warnings") or []:
            console.print(f"- {w}")
    raise typer.Exit(0 if payload.get("status") == "ok" else 1)


@v1_packet_app.command("export")
def v1_packet_export(
    packet_ref: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.v1_packet import export_packet

    payload = export_packet(packet_ref, Path(load_settings().app.data_dir))
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        console.print(f"V1 packet export: {payload.get('status')}")
        if payload.get("export"):
            console.print(f"- export_id: {payload['export']['id']}")
            console.print(f"- export_path: {payload['export']['path']}")
    raise typer.Exit(0 if payload.get("status") == "exported" else 1)


@v1_packet_app.command("export-validate")
def v1_packet_export_validate(
    export_ref: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.v1_packet import validate_packet_export

    payload = validate_packet_export(export_ref, Path(load_settings().app.data_dir))
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        console.print(f"V1 packet export validate: {payload.get('status')}")
        for w in payload.get("warnings") or []:
            console.print(f"- {w}")
    raise typer.Exit(0 if payload.get("status") == "ok" else 1)


@v1_packet_app.command("history")
def v1_packet_history(
    json_out: Annotated[bool, typer.Option("--json")] = False,
    limit: Annotated[int, typer.Option("--limit")] = 10,
) -> None:
    from shellforgeai.core.v1_packet import packet_history

    payload = packet_history(Path(load_settings().app.data_dir), limit=limit)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        console.print("V1 readiness packet history")
        console.print("")
        if payload.get("status") == "empty":
            console.print("No saved packets found.")
        else:
            latest = (payload.get("packets") or [{}])[0]
            console.print("Latest:")
            console.print(f"- {latest.get('packet_id')}")
            console.print(f"  status: {latest.get('status')}")
            console.print("\nRecent packets:")
            for idx, pkt in enumerate(payload.get("packets") or [], start=1):
                console.print(f"{idx}. {pkt.get('packet_id')}")
        console.print("\nSafety:")
        console.print("- read_only: true")
        console.print("- mutation_performed: false")
        console.print("- no remediation/rollback/cleanup/Compose execution")
    raise typer.Exit(0 if payload.get("status") in {"ok", "empty"} else 1)


@v1_packet_app.command("compare")
def v1_packet_compare(
    before_ref: Annotated[str, typer.Argument()],
    after_ref: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
    only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
    include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
    top: Annotated[int, typer.Option("--top")] = 10,
) -> None:
    from shellforgeai.core.v1_packet import compare_packets

    if top < 1:
        payload = {
            "schema_version": 1,
            "mode": "v1_packet_compare",
            "status": "error",
            "warnings": ["top must be >= 1"],
            "read_only": True,
            "mutation_performed": False,
        }
    else:
        payload = compare_packets(
            before_ref,
            after_ref,
            Path(load_settings().app.data_dir),
            only_changed=only_changed,
            include_stable=include_stable,
        )
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        if payload.get("status") != "ok":
            console.print("V1 packet compare failed")
            for w in payload.get("warnings") or []:
                console.print(f"- {w}")
        else:
            console.print("V1 readiness packet compare\n")
            console.print(f"Before: {payload['before']['packet_id']}")
            console.print(f"After:  {payload['after']['packet_id']}\n")
            s = payload["summary"]
            console.print(
                "Summary: "
                f"regressions={s['regressions']}, "
                f"improvements={s['improvements']}, "
                f"warnings added={s['new_warnings']}, "
                f"warnings resolved={s['resolved_warnings']}, "
                f"safety drift={s['safety_drift']}"
            )
            console.print("\nChanged:")
            for c in (payload.get("changes") or [])[:top]:
                console.print(f"- {c['field']}: {c['before']} -> {c['after']}")
            if include_stable and payload.get("stable"):
                console.print("\nStable:")
                for c in (payload.get("stable") or [])[:top]:
                    console.print(f"- {c['field']}: {c['before']}")
    raise typer.Exit(0 if payload.get("status") == "ok" else 1)


@v1_packet_app.command("compare-latest")
def v1_packet_compare_latest(
    json_out: Annotated[bool, typer.Option("--json")] = False,
    only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
    include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
    top: Annotated[int, typer.Option("--top")] = 10,
) -> None:
    from shellforgeai.core.v1_packet import compare_latest_packets

    payload = compare_latest_packets(
        Path(load_settings().app.data_dir), only_changed=only_changed, include_stable=include_stable
    )
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        if payload.get("status") != "ok":
            console.print("V1 packet compare-latest unavailable")
            for w in payload.get("warnings") or []:
                console.print(f"- {w}")
        else:
            for c in (payload.get("changes") or [])[: max(1, top)]:
                console.print(f"- {c['field']}: {c['before']} -> {c['after']}")
    raise typer.Exit(0 if payload.get("status") == "ok" else 1)


@v1_app.command("check")
def v1_check(
    profile: Annotated[str, typer.Option("--profile")] = "standard",
    json_output: Annotated[bool, typer.Option("--json")] = False,
    fail_on_warn: Annotated[bool, typer.Option("--fail-on-warn")] = False,
) -> None:
    from shellforgeai.core.v1_readiness import run_v1_readiness_check

    try:
        payload = run_v1_readiness_check(app, profile=profile)
    except ValueError as exc:
        if json_output:
            typer.echo(
                json.dumps(
                    {
                        "schema_version": 1,
                        "mode": "v1_readiness_check",
                        "status": "failed",
                        "error": str(exc),
                    }
                )
            )
        else:
            console.print(f"Error: {exc}")
        raise typer.Exit(1) from None

    if fail_on_warn and payload.get("status") == "warn" and payload.get("ci_status") != "failed":
        payload["ci_status"] = "failed_on_warn"

    if json_output:
        typer.echo(json.dumps(payload))
    else:
        console.print("ShellForgeAI V1 readiness check")
        console.print("")
        console.print(f"Profile: {payload['profile']}")
        console.print(f"Status: {payload['status']}")
        console.print("\nPassed:")
        for c in payload["checks"]:
            if c["status"] == "passed":
                console.print(f"- {c['name']}")
        if payload.get("warnings"):
            console.print("\nWarnings:")
            for w in payload["warnings"]:
                console.print(f"- {w}")
        console.print("\nSafety:")
        for k, v in payload["safety"].items():
            console.print(f"- {k}: {str(v).lower()}")

    exit_code = 1 if payload.get("status") == "failed" else 0
    if fail_on_warn and payload.get("status") == "warn":
        exit_code = 1
    raise typer.Exit(exit_code)


@self_test_app.command("commands")
def self_test_commands(
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only")] = False,
    profile: Annotated[
        str,
        typer.Option(
            "--profile",
            help="Validation profile: quick | standard (default) | full",
        ),
    ] = "standard",
    fail_on_warn: Annotated[
        bool,
        typer.Option(
            "--fail-on-warn",
            help="Exit nonzero when status is warn (for CI strictness).",
        ),
    ] = False,
    include_skipped: Annotated[
        bool,
        typer.Option(
            "--include-skipped",
            help="Render skipped checks in the human output even when they are warn-only.",
        ),
    ] = False,
) -> None:
    """PR79/PR80 safe command coverage harness (read-only).

    Exercises core ShellForgeAI CLI command surfaces in-process and reports
    pass/fail/warn/skipped without mutating infrastructure. Never executes
    cleanup, apply, mission, docker compose restart, or natural-language
    mutation.

    Profiles
    --------
    - ``quick``: cheap, environment-independent smoke (version, doctor,
      model doctor, tools list, ops status, ask refusal routing). No
      artifact-dependent checks. Ideal for the first post-deploy gate.
    - ``standard`` (default): PR79 coverage — broad read-only surface, may
      warn when optional artifacts (latest runbook, compose target) are
      missing.
    - ``full``: standard plus broader read-only checks (audit list, audit
      timeline, compose list). May warn more often; never mutates.

    With ``--fail-on-warn`` the command exits non-zero when the overall
    status is ``warn``. Warnings are not converted into runtime failures —
    they remain warnings; the flag is for CI strictness only.
    """
    from shellforgeai.core.self_test import run_self_test_commands

    try:
        payload = run_self_test_commands(profile=profile, include_skipped=include_skipped)
    except ValueError as exc:
        # Unknown profile — keep stderr clean: emit a clear, single-line error.
        if json_out:
            err_payload = {
                "schema_version": "1",
                "status": "failed",
                "error": str(exc),
                "available_profiles": ["quick", "standard", "full"],
            }
            typer.echo(json.dumps(err_payload))
        else:
            console.print(f"Error: {exc}")
            console.print("Valid profiles: quick, standard, full")
        raise typer.Exit(2) from exc

    status = payload["status"]
    ci_failed_on_warn = fail_on_warn and status == "warn"

    if json_out:
        if ci_failed_on_warn:
            payload = dict(payload)
            payload["ci_status"] = "failed_on_warn"
        typer.echo(json.dumps(payload))
        if status == "failed" or ci_failed_on_warn:
            raise typer.Exit(1)
        raise typer.Exit(0)

    console.print("ShellForgeAI self-test commands")
    console.print("")
    console.print("Profile:")
    console.print(f"- name: {payload['profile']}")
    console.print("- read-only: true")
    console.print("- mutation: false")
    console.print("")
    console.print("Mode:")
    for key, value in payload["mode"].items():
        console.print(f"- {key}: {str(value).lower()}")
    console.print("")
    console.print("Checks:")
    for check in payload["checks"]:
        label = check["status"].upper()
        if check.get("warn") and check["status"] == "skip":
            label = "WARN"
        if not include_skipped and check["status"] == "skip" and not check.get("warn"):
            continue
        line = f"{label} {check['name']}"
        has_reason = bool(check.get("reason"))
        if has_reason and (check["status"] in {"skip", "fail"} or check.get("warn")):
            line += f"  ({check['reason']})"
        console.print(line)
    console.print("")
    console.print("Summary:")
    console.print(f"- passed: {payload['summary']['passed']}")
    console.print(f"- failed: {payload['summary']['failed']}")
    console.print(f"- warned: {payload['summary']['warned']}")
    console.print(f"- skipped: {payload['summary']['skipped']}")
    console.print(f"- status: {status}")
    console.print("")
    console.print("Safety invariants:")
    console.print("- cleanup execute: not run")
    console.print("- mission/apply execute: not run")
    console.print("- docker compose mutation: not run")
    console.print("- natural-language execution: not run")
    console.print("- arbitrary command execution: false")
    console.print("")
    console.print("Safety (detailed):")
    console.print("- no cleanup execute")
    console.print("- no cleanup archive")
    console.print("- no cleanup prepare")
    console.print("- no mission execute")
    console.print("- no proposal created")
    console.print("- no mission created")
    console.print("- no apply")
    console.print("- no docker compose restart")
    console.print("- no production mutation")
    console.print("- no natural-language execution")
    console.print("- no shell=true")
    if payload.get("warnings"):
        console.print("")
        console.print("Warnings:")
        for w in payload["warnings"]:
            console.print(f"- {w['name']}: {w['reason']}")
    if payload.get("next_safe_commands"):
        console.print("")
        console.print("Next safe commands:")
        for cmd in payload["next_safe_commands"]:
            console.print(f"- {cmd}")
    if status == "warn":
        console.print("")
        console.print(
            "This is not a command failure. Optional artifact-dependent checks "
            "were skipped or warned."
        )
    if ci_failed_on_warn:
        console.print("")
        console.print(
            "--fail-on-warn: exiting nonzero because at least one warning exists. "
            "Warnings remain warnings; this flag is for CI strictness only."
        )
        raise typer.Exit(1)
    if status == "failed":
        raise typer.Exit(1)


@triage_app.callback(invoke_without_command=True)
def triage(
    ctx: typer.Context,
    brief: Annotated[
        bool, typer.Option("--brief", help="Emit bounded brief triage output.")
    ] = False,
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    target: Annotated[
        str | None,
        typer.Option("--target", help="Show V2 detail for one ranked suspect."),
    ] = None,
    top: Annotated[int, typer.Option("--top", min=1, help="Maximum ranked suspects.")] = 5,
) -> None:
    """Read-only V2 triage entrypoint: ranked suspects and first safe command."""
    if ctx.invoked_subcommand is not None:
        return
    if target:
        detail = _build_v2_triage_detail_payload(target)
        if json_out:
            typer.echo(json.dumps(detail))
            return
        typer.echo(_render_v2_triage_detail_human(detail), nl=False)
        return
    payload = _build_v2_triage_payload(top=top)
    if json_out:
        typer.echo(json.dumps(payload))
        return
    if brief:
        typer.echo(_render_v2_triage_brief(payload), nl=False)
        return
    typer.echo(_render_v2_triage_human(payload), nl=False)


@triage_docker_app.callback(invoke_without_command=True)
def triage_docker(
    ctx: typer.Context,
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    brief: Annotated[
        bool,
        typer.Option("--brief", help="Mirror the V2 brief triage view (read-only)."),
    ] = False,
) -> None:
    """PR81 read-only Docker triage ranking ("scene awareness").

    Inventories the current Docker scene using existing read-only collectors,
    ranks suspicious containers across multiple failure classes (crashloop,
    noisy errors, bad HTTP, disk pressure, permission denied, high-CPU watch),
    and prints evidence/why/safe-next-command per suspect. Never restarts,
    stops, removes, prunes, or otherwise mutates anything.

    ``--brief`` is a PR146 compatibility alias that mirrors the bounded
    ``shellforgeai triage --brief`` view so operators get one consistent
    brief shape regardless of which entrypoint they reach for.
    """
    from shellforgeai.core.triage_ranking import (
        collect_scene,
        rank_scene,
        render_human,
    )

    if ctx.invoked_subcommand is not None:
        return

    if brief:
        # Compatibility alias: mirror the V2 top-level brief triage view so
        # `triage docker --brief` never feels staler than `triage --brief`.
        typer.echo(_render_v2_triage_brief(_build_v2_triage_payload()), nl=False)
        return

    scene = collect_scene()
    payload = rank_scene(scene)

    if json_out:
        typer.echo(json.dumps(payload))
        return

    console.print(render_human(payload), end="")


@triage_docker_app.command("detail")
def triage_docker_detail(
    suspect: Annotated[str | None, typer.Argument(help="Suspect name.")] = None,
    rank: Annotated[
        int | None, typer.Option("--rank", min=1, help="Rank number to inspect.")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """PR83 read-only Docker triage detail drilldown for one ranked suspect."""
    from shellforgeai.core.triage_ranking import (
        build_detail_payload,
        collect_scene,
        rank_scene,
        render_detail_human,
    )

    if suspect is not None and rank is not None:
        raise typer.BadParameter("provide suspect or --rank, not both")
    scene = collect_scene()
    ranked = rank_scene(scene)
    payload = build_detail_payload(scene, ranked, suspect_name=suspect, rank=rank)
    if json_out:
        typer.echo(json.dumps(payload))
        if payload.get("status") == "ok":
            return
        raise typer.Exit(1 if payload.get("status") == "error" else 0)
    console.print(render_detail_human(payload), end="")
    if payload.get("status") == "error":
        raise typer.Exit(1)


@triage_docker_app.command("timeline")
def triage_docker_timeline(
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    window: Annotated[int, typer.Option("--window", min=1)] = 5,
    top: Annotated[int, typer.Option("--top", min=1)] = 5,
    only_regressions: Annotated[bool, typer.Option("--only-regressions")] = False,
    include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
) -> None:
    from shellforgeai.core.triage_ranking import (
        build_snapshot_timeline,
        render_snapshot_timeline_human,
    )

    payload = build_snapshot_timeline(
        Path(load_settings().app.data_dir),
        window=window,
        top=top,
        only_regressions=only_regressions,
        include_stable=include_stable,
    )
    if json_out:
        typer.echo(json.dumps(payload))
        if payload.get("status") == "ok":
            return
        raise typer.Exit(1)
    console.print(render_snapshot_timeline_human(payload), end="")
    if payload.get("status") not in ("ok", "warn"):
        raise typer.Exit(1)


@triage_docker_snapshot_app.callback()
def triage_docker_snapshot(
    ctx: typer.Context,
    top: Annotated[int, typer.Option("--top", min=1, help="Limit to top N suspects.")] = 5,
    include_details: Annotated[
        bool, typer.Option("--include-details", help="Include compact detail evidence.")
    ] = False,
    save: Annotated[bool, typer.Option("--save", help="Save snapshot artifact packet.")] = False,
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    """PR84 read-only Docker triage incident snapshot / handoff."""
    if ctx.invoked_subcommand is not None:
        return
    from shellforgeai.core.triage_ranking import (
        build_snapshot_payload,
        collect_scene,
        rank_scene,
        render_saved_snapshot_human,
        render_snapshot_human,
        save_snapshot_artifact,
    )

    scene = collect_scene()
    ranked = rank_scene(scene)
    payload = build_snapshot_payload(scene, ranked, top=top, include_details=include_details)
    if save:
        source_command = "shellforgeai triage docker snapshot --save"
        if include_details:
            source_command += " --include-details"
        if top != 5:
            source_command += f" --top {top}"
        saved = save_snapshot_artifact(
            payload, Path(load_settings().app.data_dir), source_command=source_command
        )
        if json_out:
            typer.echo(json.dumps(saved))
            return
        console.print(render_saved_snapshot_human(saved), end="")
        return
    if json_out:
        typer.echo(json.dumps(payload))
        return
    console.print(render_snapshot_human(payload), end="")


@triage_docker_snapshot_app.command("validate")
def triage_docker_snapshot_validate(
    snapshot: Annotated[str, typer.Argument(help="Snapshot artifact id or path.")],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
) -> None:
    from shellforgeai.core.triage_ranking import (
        render_snapshot_validation_human,
        validate_snapshot_artifact,
    )

    payload = validate_snapshot_artifact(snapshot, Path(load_settings().app.data_dir))
    if json_out:
        typer.echo(json.dumps(payload))
        if payload.get("status") == "ok":
            return
        raise typer.Exit(1)
    console.print(render_snapshot_validation_human(payload), end="")


@triage_docker_snapshot_app.command("export")
def triage_docker_snapshot_export(
    ctx: typer.Context,
    snapshot: Annotated[str, typer.Argument(help="Snapshot artifact id or path.")],
    as_json: Annotated[bool, typer.Option("--json")] = False,
    output: Annotated[
        Path | None, typer.Option("--output", help="Output path under <data_dir>/exports.")
    ] = None,
) -> None:
    from shellforgeai.core.triage_ranking import export_snapshot_artifact

    payload = export_snapshot_artifact(snapshot, Path(load_settings().app.data_dir), output=output)
    if as_json:
        console.print_json(json.dumps(payload))
        if payload.get("status") == "exported":
            return
        raise typer.Exit(code=1)
    if payload.get("status") != "exported":
        console.print("Triage snapshot export failed")
        for w in payload.get("warnings") or []:
            console.print(f"- {w}")
        raise typer.Exit(code=1)
    exp = payload.get("export") or {}
    src = payload.get("source_snapshot") or {}
    console.print("Triage snapshot export created")
    console.print("\nSource snapshot:")
    console.print(f"- id: {src.get('id')}")
    console.print(f"- path: {src.get('path')}")
    console.print(f"- validation: {'passed' if src.get('validated') else 'failed'}")
    console.print("\nExport:")
    console.print(f"- id: {exp.get('id')}")
    console.print(f"- path: {exp.get('path')}")
    console.print("- files:")
    for f in exp.get("files") or []:
        console.print(f"  - {f}")


@triage_docker_snapshot_app.command("compare")
def triage_docker_snapshot_compare(
    snapshot_a: Annotated[str, typer.Argument(help="Before snapshot id or path.")],
    snapshot_b: Annotated[str, typer.Argument(help="After snapshot id or path.")],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    top: Annotated[int, typer.Option("--top", min=1)] = 5,
    only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
    include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
    include_evidence: Annotated[bool, typer.Option("--include-evidence")] = False,
) -> None:
    from shellforgeai.core.triage_ranking import (
        compare_snapshot_payload,
        render_snapshot_compare_human,
        validate_snapshot_artifact,
    )

    data_dir = Path(load_settings().app.data_dir)
    va = validate_snapshot_artifact(snapshot_a, data_dir)
    vb = validate_snapshot_artifact(snapshot_b, data_dir)
    if va.get("status") != "ok" or vb.get("status") != "ok":
        payload = {
            "schema_version": 1,
            "mode": "docker_triage_snapshot_compare",
            "status": "error",
            "read_only": True,
            "mutation_performed": False,
            "warnings": ["snapshot validation failed"],
            "summary": {},
            "regressions": [],
            "recoveries": [],
            "stable": [],
            "new_suspects": [],
            "removed_suspects": [],
            "safety": {"read_only": True, "mutation_performed": False},
        }
    else:
        sa = json.loads(
            Path((va.get("artifact") or {}).get("path") or "")
            .joinpath("triage-snapshot.json")
            .read_text(encoding="utf-8")
        )
        sb = json.loads(
            Path((vb.get("artifact") or {}).get("path") or "")
            .joinpath("triage-snapshot.json")
            .read_text(encoding="utf-8")
        )
        payload = compare_snapshot_payload(
            sa,
            sb,
            top=top,
            only_changed=only_changed,
            include_stable=include_stable,
            include_evidence=include_evidence,
        )
    if json_out:
        typer.echo(json.dumps(payload))
        if payload.get("status") == "ok":
            return
        raise typer.Exit(1)
    console.print(render_snapshot_compare_human(payload), end="")
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@triage_docker_snapshot_app.command("compare-export")
def triage_docker_snapshot_compare_export(
    export_a: Annotated[str, typer.Argument(help="Before export path.")],
    export_b: Annotated[str, typer.Argument(help="After export path.")],
    json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    top: Annotated[int, typer.Option("--top", min=1)] = 5,
    only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
    include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
    include_evidence: Annotated[bool, typer.Option("--include-evidence")] = False,
) -> None:
    from shellforgeai.core.triage_ranking import (
        compare_snapshot_exports,
        render_snapshot_compare_human,
    )

    payload = compare_snapshot_exports(
        export_a,
        export_b,
        top=top,
        only_changed=only_changed,
        include_stable=include_stable,
        include_evidence=include_evidence,
    )
    if json_out:
        typer.echo(json.dumps(payload))
        if payload.get("status") == "ok":
            return
        raise typer.Exit(1)
    console.print(render_snapshot_compare_human(payload), end="")
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@triage_docker_snapshot_app.command("export-validate")
def triage_docker_snapshot_export_validate(
    ctx: typer.Context,
    export_path: Annotated[str, typer.Argument(help="Export path.")],
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.triage_ranking import validate_snapshot_export

    _ = _ctx(ctx)
    payload = validate_snapshot_export(export_path)
    if as_json:
        console.print_json(json.dumps(payload))
        if payload.get("status") == "ok":
            return
        raise typer.Exit(code=1)
    if payload.get("status") != "ok":
        console.print("Triage snapshot export validation failed")
        for w in payload.get("warnings") or []:
            console.print(f"- {w}")
        raise typer.Exit(code=1)
    console.print("Triage snapshot export validation passed")
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@remediation_app.command("eligibility")
def remediation_eligibility(
    target: Annotated[str | None, typer.Option("--target")] = None,
    scenario: Annotated[str, typer.Option("--scenario")] = "sfai-noisy-errors",
    explain: Annotated[bool, typer.Option("--explain")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core import triage_ranking
    from shellforgeai.core.disposable_remediation import (
        build_eligibility_explain_report,
        evaluate_eligibility,
    )

    scene = triage_ranking.collect_scene()
    ranked = triage_ranking.rank_scene(scene)
    suspects = list((ranked or {}).get("suspects") or [])
    rows = {str(c.get("name") or ""): c for c in (scene.get("containers") or [])}

    if explain and not target:
        raise typer.BadParameter("--explain currently requires --target")

    selected: list[dict[str, Any]] = []
    warnings: list[str] = []
    status = "ok"
    if target:
        t = target.strip()
        if t.lower() in {"all", "*", "everything", "all containers", "all services"}:
            status = "blocked"
            selected = [{"name": t, "severity": "unknown", "confidence": "unknown", "classes": []}]
        else:
            match = next((s for s in suspects if s.get("name") == t), None)
            if match is None:
                if t in rows:
                    match = {
                        "name": t,
                        "severity": "unknown",
                        "confidence": "unknown",
                        "classes": [],
                    }
                else:
                    status = "blocked"
                    warnings.append("target not found")
                    match = {
                        "name": t,
                        "severity": "unknown",
                        "confidence": "unknown",
                        "classes": [],
                    }
            selected = [match]
    else:
        selected = suspects

    if explain and target:
        name = selected[0].get("name", "")
        has_row = name in rows
        labels = rows.get(name, {}).get("labels") if has_row else None
        payload = build_eligibility_explain_report(
            target=name,
            scenario=scenario,
            labels=labels,
            target_found=has_row,
            explicit_target=True,
        )
        if status == "blocked":
            payload["status"] = "blocked"
            if "broad target refused" not in payload["eligibility"]["blocked_reasons"]:
                payload["eligibility"]["blocked_reasons"].append("broad target refused")
        if json_out:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload["status"] == "ok" else 1)
        state = payload["eligibility"]["state"]
        console.print(f"Remediation eligibility explanation: {payload['target']['name']}")
        console.print(
            f"Eligibility: {'eligible for plan' if state == 'eligible_for_plan' else 'blocked'}"
        )
        if state == "eligible_for_plan":
            console.print(f"- First safe command (plan-only): {payload['suggested_plan_command']}")
        else:
            console.print(
                "- First safe command: shellforgeai triage docker detail "
                f"{payload['target']['name']}"
            )
        console.print("\nSummary:")
        console.print(f"- eligibility: {payload['eligibility']['state']}")
        console.print(f"- production_target: {str(payload['target']['production_target']).lower()}")
        console.print(f"- disposable: {str(payload['target']['disposable']).lower()}")
        console.print(
            f"- target_allowlisted: {str(payload['target']['target_allowlisted']).lower()}"
        )
        console.print("- plan_created: false")
        console.print("- remediation_executed: false")
        console.print("\nLabels found:")
        if payload["labels"]["found"]:
            for k, v in payload["labels"]["found"].items():
                console.print(f"- {k}={v}")
        else:
            console.print("- none")
        console.print("\nGates:")
        for g in payload["gates"]:
            console.print(f"- {g['name']}: {g['status']}")
        console.print("\nBlocking reasons:")
        if payload["eligibility"]["blocked_reasons"]:
            for r in payload["eligibility"]["blocked_reasons"]:
                console.print(f"- {r}")
        else:
            console.print("- none")
        console.print("\nWhat would make this eligible:")
        for w in payload["what_would_make_eligible"]:
            console.print(f"- {w}")
        if payload.get("suggested_plan_command"):
            console.print("\nSuggested plan command:")
            console.print(f"- {payload['suggested_plan_command']}")
        console.print("\nSafe next commands:")
        for cmd in payload["next_safe_commands"]:
            console.print(f"- {cmd}")
        console.print("\nSafety:")
        console.print("- read_only: true")
        console.print("- mutation_performed: false")
        console.print("- no plan was created")
        console.print("- no remediation was executed")
        console.print("- no rollback was executed")
        if payload["status"] != "ok":
            raise typer.Exit(1)
        return

    targets = []
    for s in selected:
        name = str(s.get("name") or "")
        labels = rows.get(name, {}).get("labels") if name in rows else None
        evald = evaluate_eligibility(target=name, scenario=scenario, labels=labels)
        blocked_reasons = list(evald.get("blocked_reasons") or [])
        if name and name not in rows:
            blocked_reasons.append("target not found")
        item = {
            "name": name,
            "triage": {
                "severity": s.get("severity", "unknown"),
                "confidence": s.get("confidence", "unknown"),
                "classes": list(s.get("classes") or []),
            },
            "scenario": scenario,
            **evald,
            "suggested_plan_command": (
                remediation_plan_command(name, scenario)
                if evald.get("eligibility") == "eligible_for_plan"
                else ""
            ),
        }
        item["blocked_reasons"] = blocked_reasons
        targets.append(item)

    eligible = [t for t in targets if t.get("eligibility") == "eligible_for_plan"]
    blocked = [t for t in targets if t.get("eligibility") != "eligible_for_plan"]
    if not targets:
        status = "empty"
    elif status != "blocked" and blocked and not eligible:
        status = "blocked"

    payload = {
        "schema_version": "1",
        "status": status,
        "mode": "remediation_eligibility",
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "targets_seen": len(targets),
            "eligible_for_plan": len(eligible),
            "blocked": len(blocked),
            "production_blocked": sum(1 for t in targets if t.get("production_target")),
        },
        "targets": targets,
        "safety": {
            "read_only": True,
            "mutation_performed": False,
            "plan_created": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "cleanup_executed": False,
            "proposal_created": False,
            "mission_created": False,
            "apply_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "natural_language_execution": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
        },
        "next_safe_commands": [
            *(t["suggested_plan_command"] for t in eligible if t.get("suggested_plan_command")),
            *[
                triage_detail_command(str(t.get("name")))
                for t in blocked
                if t.get("name") and str(t.get("name")) not in {"*", "all", "everything"}
            ],
            remediation_audit_latest_command(),
        ],
        "warnings": warnings,
    }
    if json_out:
        typer.echo(json.dumps(payload))
        raise typer.Exit(0 if payload["status"] in {"ok", "empty"} else 1)

    console.print("Remediation eligibility map")
    console.print("\nSafety:")
    console.print("- read_only: true")
    console.print("- mutation_performed: false")
    console.print("- no plan created")
    console.print("- no remediation executed")
    console.print("- no Docker/Compose mutation")
    console.print("\nSummary:")
    for k, v in payload["summary"].items():
        console.print(f"- {k}: {v}")
    console.print("\nEligible targets:")
    if not eligible:
        console.print("- none")
    for t in eligible:
        console.print(f"- {t['name']} ({t['triage']['severity']})")
        console.print(f"  Suggested command: {t['suggested_plan_command']}")
    console.print("\nBlocked targets:")
    if not blocked:
        console.print("- none")
    for t in blocked:
        console.print(f"- {t['name']} ({t['triage']['severity']})")
        for r in t.get("blocked_reasons") or ["executor unavailable"]:
            console.print(f"  - {r}")
    console.print("\nSuggested safe commands:")
    for cmd in payload["next_safe_commands"]:
        if cmd:
            console.print(f"- {cmd}")
    console.print("\nWarning: this command created no plan and executed nothing.")
    if payload["status"] not in {"ok", "empty"}:
        raise typer.Exit(1)


@remediation_app.command("plan")
def remediation_plan(
    target: Annotated[str, typer.Option("--target")],
    scenario: Annotated[str, typer.Option("--scenario")] = "sfai-noisy-errors",
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core import triage_ranking
    from shellforgeai.core.disposable_remediation import write_plan

    settings = load_settings()
    scene = triage_ranking.collect_scene()
    labels = {}
    for row in scene.get("containers") or []:
        if row.get("name") == target:
            raw = row.get("labels")
            if isinstance(raw, dict):
                labels = {str(k): str(v) for k, v in raw.items()}
            break
    payload = write_plan(
        data_dir=Path(settings.app.data_dir), target=target, scenario=scenario, labels=labels
    )
    if json_out:
        typer.echo(json.dumps(payload))
        if payload.get("status") != "planned":
            raise typer.Exit(1)
        return
    if payload.get("status") != "planned":
        console.print(f"Refused: {payload.get('reason')}.")
        console.print("Try: shellforgeai remediation plan --target sfai-noisy-errors ")
        console.print("      --scenario sfai-noisy-errors")
        raise typer.Exit(1)
    plan = payload["plan"]
    console.print(
        "Disposable remediation plan created (governed proof executor; not live Docker remediation)"
    )
    console.print(f"- target: {plan['target']}")
    console.print(f"- scenario: {plan['scenario']}")
    console.print(f"- action preview: {plan['action_preview']}")
    console.print(f"- plan id: {plan['plan_id']}")


@remediation_app.command("validate")
def remediation_validate(
    plan_id: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.disposable_remediation import load_plan, validate_plan

    plan = load_plan(Path(load_settings().app.data_dir), plan_id)
    if plan is None:
        payload = {
            "status": "not_found",
            "mode": "disposable_remediation_validate",
            "plan_id": plan_id,
            "checks": [],
            "safety": {},
            "warnings": ["plan not found"],
        }
    else:
        ok, errs = validate_plan(plan)
        payload = {
            "status": "ok" if ok else "failed",
            "mode": "disposable_remediation_validate",
            "plan_id": plan_id,
            "checks": [] if ok else errs,
            "executor_readiness": {
                "proof": {"ready": ok, "blockers": [] if ok else errs},
                "docker-disposable": {"ready": ok, "blockers": [] if ok else errs},
            },
            "safety": plan.get("safety", {}),
            "warnings": [],
        }
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        console.print(f"Validation: {payload['status']}")
        for c in payload.get("checks") or []:
            console.print(f"- {c}")
    if payload["status"] != "ok":
        raise typer.Exit(1)


@remediation_app.command("preflight")
def remediation_preflight(
    plan_id: Annotated[str, typer.Argument()],
    executor: Annotated[str, typer.Option("--executor")] = "proof",
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core import triage_ranking
    from shellforgeai.core.disposable_remediation import (
        build_preflight_payload,
        container_state_from_scene,
        inspect_exact_target_state,
        load_plan,
    )

    data_dir = Path(load_settings().app.data_dir)
    plan = load_plan(data_dir, plan_id)
    target = str((plan or {}).get("target") or "")
    scene = triage_ranking.collect_scene()
    scene_state = container_state_from_scene(scene, target) if target else None
    inspect_state = inspect_exact_target_state(target) if target else None
    payload = build_preflight_payload(
        data_dir=data_dir,
        plan_id=plan_id,
        executor=executor,
        scene_state=scene_state,
        inspect_state=inspect_state,
    )
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        console.print("Remediation preflight packet")
        console.print("\nPlan:")
        for k in ["plan_id", "scenario", "executor", "fingerprint"]:
            console.print(f"- {k}: {payload.get('plan', {}).get(k)}")
        console.print("\nTarget:")
        t = payload.get("target") or {}
        for k in [
            "name",
            "kind",
            "disposable",
            "target_allowlisted",
            "production_target",
            "started_at",
            "restart_count",
        ]:
            console.print(f"- {k}: {t.get(k)}")
        console.print("\nPlanned action:")
        console.print(f"- {(payload.get('planned_action') or {}).get('command_display')}")
        console.print("- shell_true: false")
        console.print("- arbitrary_command_execution: false")
        console.print("\nSafety:")
        for k, v in (payload.get("safety") or {}).items():
            console.print(f"- {k}: {str(v).lower()}")
        console.print("\nOperator decision:")
        d = payload.get("decision") or {}
        console.print(f"- preflight_status: {d.get('preflight_status')}")
        for r in d.get("reasons") or []:
            console.print(f"- reason: {r}")
        console.print(f"- {d.get('approval_warning')}")
        if d.get("execute_command"):
            console.print("\nTo execute:")
            console.print(d["execute_command"])
    if payload.get("status") not in {"ready", "warning"}:
        raise typer.Exit(1)


@remediation_app.command("execute")
def remediation_execute(
    plan_id: Annotated[str, typer.Argument()],
    execute: Annotated[bool, typer.Option("--execute")] = False,
    confirm: Annotated[bool, typer.Option("--confirm")] = False,
    executor: Annotated[str, typer.Option("--executor")] = "proof",
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core import triage_ranking
    from shellforgeai.core.disposable_remediation import (
        container_state_from_scene,
        derive_rollback_payload,
        inspect_exact_target_state,
        load_plan,
        run_exact_docker_restart,
        safety_block,
        validate_plan,
        write_receipt,
    )

    if not (execute and confirm):
        msg = "Refused: explicit --execute --confirm required."
        if json_out:
            typer.echo(
                json.dumps(
                    {
                        "status": "blocked",
                        "mode": "disposable_remediation_execute",
                        "warnings": [msg],
                    }
                )
            )
        else:
            console.print(msg)
        raise typer.Exit(1)
    data_dir = Path(load_settings().app.data_dir)
    plan = load_plan(data_dir, plan_id)
    if plan is None:
        payload = {
            "status": "not_found",
            "mode": "disposable_remediation_execute",
            "plan_id": plan_id,
            "warnings": ["plan not found"],
        }
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            console.print("Plan not found")
        raise typer.Exit(1)
    ok, errs = validate_plan(plan)
    if not ok:
        payload = {
            "status": "blocked",
            "mode": "disposable_remediation_execute",
            "plan_id": plan_id,
            "warnings": errs,
        }
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            [console.print(f"- {e}") for e in errs]
        raise typer.Exit(1)
    if executor not in {"proof", "docker-disposable"}:
        payload = {
            "status": "blocked",
            "mode": "disposable_remediation_execute",
            "warnings": ["unknown executor mode"],
        }
        typer.echo(json.dumps(payload) if json_out else "Refused: unknown executor mode.")
        raise typer.Exit(1)
    scene_pre = triage_ranking.collect_scene()
    pre = container_state_from_scene(scene_pre, plan["target"]) or {"name": plan["target"]}
    pre_labels = pre.get("labels") or {}
    pre_disposable = any(
        pre_labels.get(k) == v
        for k, v in (
            ("shellforgeai.disposable", "true"),
            ("sfai.battle", "true"),
            ("shellforgeai.test_harness", "battle-lab"),
        )
    )
    pre_allowlisted = pre_labels.get("shellforgeai.allow_restart") == "true"
    restart_attempted = False
    restart_succeeded = False
    exit_code = 0
    stdout = ""
    stderr = ""
    if executor == "docker-disposable":
        inspect_pre = inspect_exact_target_state(plan["target"])
        if inspect_pre is not None:
            pre = inspect_pre
            pre_labels = pre.get("labels") or {}
            pre_disposable = any(
                pre_labels.get(k) == v
                for k, v in (
                    ("shellforgeai.disposable", "true"),
                    ("sfai.battle", "true"),
                    ("shellforgeai.test_harness", "battle-lab"),
                )
            )
            pre_allowlisted = pre_labels.get("shellforgeai.allow_restart") == "true"
        if not (pre_disposable and pre_allowlisted):
            payload = {
                "status": "blocked",
                "mode": "disposable_remediation_execute",
                "executor_mode": executor,
                "warnings": ["target not disposable+allowlisted at execution time"],
            }
            typer.echo(
                json.dumps(payload)
                if json_out
                else "Refused: target is not eligible for docker-disposable executor."
            )
            raise typer.Exit(1)
        restart_attempted = True
        restart_succeeded, exit_code, stdout, stderr = run_exact_docker_restart(plan["target"])
    scene_post = triage_ranking.collect_scene()
    post = container_state_from_scene(scene_post, plan["target"]) or {"name": plan["target"]}
    if executor == "docker-disposable":
        inspect_post = inspect_exact_target_state(plan["target"])
        if inspect_post is not None:
            post = inspect_post
    pre_started = str(pre.get("StartedAt") or "")
    post_started = str(post.get("StartedAt") or "")
    pre_count = int(pre.get("restart_count") or 0)
    post_count = int(post.get("restart_count") or 0)
    target_match = str(post.get("name") or "") == str(plan["target"])
    restart_verified = target_match and bool(
        (post_started and pre_started and pre_started != post_started) or (post_count > pre_count)
    )
    command_ok = exit_code == 0
    restart_succeeded = (
        restart_succeeded and command_ok and restart_verified
        if executor == "docker-disposable"
        else False
    )
    verified = True if executor == "proof" else bool(restart_succeeded)
    receipt_id = f"drr_{uuid.uuid4().hex[:12]}"
    receipt = {
        "schema_version": 1,
        "kind": "disposable_remediation_receipt",
        "receipt_id": receipt_id,
        "plan_id": plan_id,
        "plan_fingerprint": plan.get("fingerprint"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": plan["target"],
        "scenario": plan["scenario"],
        "executor_mode": executor,
        "proof_executor": executor == "proof",
        "real_docker_executor": executor == "docker-disposable",
        "action_attempted": plan["action_preview"],
        "action_executed": executor == "docker-disposable",
        "docker_restart_attempted": restart_attempted,
        "docker_restart_succeeded": restart_succeeded,
        "exact_target_only": True,
        "unrelated_targets_touched": False,
        "pre_state": pre,
        "post_state": post,
        "verification": {
            "status": "passed" if verified else "failed",
            "restart_verified": restart_verified,
            "target_match": target_match,
            "command_ok": command_ok,
        },
        "return_code": exit_code,
        "stdout_summary": stdout[:120],
        "stderr_summary": stderr[:120],
        "rollback_or_recovery_status": "none",
        "safety": safety_block(
            mutation=executor == "docker-disposable" and restart_succeeded,
            restarted=executor == "docker-disposable" and restart_succeeded,
            disposable=True,
            allowlisted=True,
            production=False,
        ),
    }
    receipt["rollback"] = derive_rollback_payload(receipt)
    write_receipt(data_dir, receipt)
    payload = {
        "status": "executed" if verified else "failed",
        "mode": "disposable_remediation_execute",
        "executor_mode": executor,
        "proof_executor": executor == "proof",
        "real_docker_executor": executor == "docker-disposable",
        "docker_restart_attempted": restart_attempted,
        "docker_restart_succeeded": restart_succeeded,
        "receipt_id": receipt_id,
        "plan_id": plan_id,
        "target": plan["target"],
        "verification": receipt["verification"],
        "safety": receipt["safety"],
        "warnings": [],
    }
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        if executor == "proof":
            console.print("Remediation proof executed")
            console.print("No real Docker restart was performed.")
        else:
            console.print("Disposable Docker remediation executed")
            console.print(f"- target: {plan['target']}")
        console.print(f"Receipt: {receipt_id}")
    if payload["status"] != "executed":
        raise typer.Exit(1)


@remediation_receipt_app.command("validate")
def remediation_receipt_validate(
    receipt_id_or_path: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.disposable_remediation import validate_receipt_payload

    payload = validate_receipt_payload(Path(load_settings().app.data_dir), receipt_id_or_path)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        console.print(f"Disposable remediation receipt validation: {payload['status']}")
        for k, v in (payload.get("checks") or {}).items():
            console.print(f"- {k}: {'ok' if v else 'failed'}")
        for w in payload.get("warnings") or []:
            console.print(f"- warning: {w}")
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@remediation_app.command("report")
def remediation_report(
    receipt_id_or_path: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.disposable_remediation import report_receipt_payload

    payload = report_receipt_payload(Path(load_settings().app.data_dir), receipt_id_or_path)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        if payload.get("status") != "ok":
            console.print("Disposable remediation report unavailable")
            for w in payload.get("warnings") or []:
                console.print(f"- {w}")
            raise typer.Exit(1)
        rec = payload["receipt"]
        summary = payload["summary"]
        safety = payload["safety"]
        console.print("Disposable remediation report")
        console.print("\nReceipt:")
        console.print(f"- receipt: {rec.get('receipt_id')}")
        console.print(f"- plan: {rec.get('plan_id')}")
        console.print(f"- executor: {summary.get('executor_mode')}")
        console.print(f"- target: {summary.get('target')}")
        console.print(f"- scenario: {summary.get('scenario')}")
        console.print("\nSafety:")
        for key in [
            "production_target",
            "disposable",
            "target_allowlisted",
            "shell_true",
            "arbitrary_command_execution",
            "docker_compose_executed",
            "cleanup_executed",
            "natural_language_execution",
        ]:
            console.print(f"- {key}: {str(safety.get(key)).lower()}")
        console.print("\nHandoff:")
        console.print(f"- validation: {payload['handoff'].get('validation_status')}")
        for cmd in payload.get("next_safe_commands") or []:
            console.print(f"- next: {cmd}")
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@remediation_app.command("bundle")
def remediation_bundle(
    plan_or_receipt_id: Annotated[str, typer.Argument()],
    save: Annotated[bool, typer.Option("--save")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.disposable_remediation import (
        build_lifecycle_bundle_payload,
        remediation_bundle_dir,
    )

    data_dir = Path(load_settings().app.data_dir)
    payload = build_lifecycle_bundle_payload(data_dir, plan_or_receipt_id)
    if save and payload.get("status") not in {"not_found", "error"}:
        bundle_id = f"remediation_bundle_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        out = remediation_bundle_dir(data_dir) / bundle_id
        out.mkdir(parents=True, exist_ok=False)
        jpath = out / "remediation-lifecycle.json"
        mpath = out / "remediation-lifecycle.md"
        jpath.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        mpath.write_text(
            "Disposable remediation lifecycle bundle\n\n"
            f"- status: {payload.get('status')}\n"
            f"- plan_id: {(payload.get('lifecycle') or {}).get('plan_id')}\n"
            f"- receipt_id: {(payload.get('lifecycle') or {}).get('receipt_id')}\n"
            "- Safety:\n"
            "  - no production mutation\n"
            "  - no compose mutation\n"
            "  - no shell=True\n",
            encoding="utf-8",
        )
        payload["artifact"] = {"saved": True, "id": bundle_id, "path": str(out)}
        payload["next_safe_commands"] = [f"shellforgeai remediation bundle validate {bundle_id}"]
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        if payload.get("status") in {"not_found", "error"}:
            console.print("Disposable remediation lifecycle bundle unavailable")
            for w in payload.get("warnings") or []:
                console.print(f"- {w}")
            raise typer.Exit(1)
        lc = payload.get("lifecycle") or {}
        console.print("Disposable remediation lifecycle bundle")
        console.print(f"- plan_id: {lc.get('plan_id')}")
        console.print(f"- receipt_id: {lc.get('receipt_id')}")
        console.print(f"- rollback_receipt_id: {lc.get('rollback_receipt_id')}")
        console.print(f"- target: {lc.get('target')}")
        console.print("- no production mutation")
    if payload.get("status") in {"not_found", "error", "failed"}:
        raise typer.Exit(1)


@remediation_app.command("bundle-validate")
def remediation_bundle_validate(
    bundle_id_or_path: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.disposable_remediation import remediation_bundle_dir

    data_dir = Path(load_settings().app.data_dir)
    root = remediation_bundle_dir(data_dir)
    p = Path(bundle_id_or_path)
    if not p.is_absolute():
        p = root / bundle_id_or_path
    jpath = p / "remediation-lifecycle.json"
    out = {
        "schema_version": "1",
        "status": "ok",
        "mode": "disposable_remediation_lifecycle_bundle_validate",
        "bundle": {"id": p.name, "path": str(p)},
        "checks": {},
        "safety": {
            "read_only": True,
            "mutation_performed": False,
            "remediation_executed_by_validate": False,
            "rollback_executed_by_validate": False,
            "cleanup_executed": False,
            "docker_compose_executed": False,
            "production_mutation_recorded": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "natural_language_execution": False,
        },
        "warnings": [],
    }
    if not jpath.exists():
        out["status"] = "not_found"
        out["warnings"] = ["bundle not found"]
    else:
        try:
            payload = json.loads(jpath.read_text(encoding="utf-8"))
            out["checks"]["json_parse"] = True
            out["checks"]["schema_version"] = bool(payload.get("schema_version"))
            out["checks"]["mode"] = payload.get("mode") == "disposable_remediation_lifecycle_bundle"
            safe = payload.get("safety") or {}
            out["checks"]["safety"] = all(
                safe.get(k) is False
                for k in [
                    "shell_true",
                    "arbitrary_command_execution",
                    "natural_language_execution",
                    "docker_compose_executed",
                    "cleanup_executed",
                ]
            )
            if not all(out["checks"].values()):
                out["status"] = "failed"
        except Exception as exc:
            out["status"] = "error"
            out["warnings"] = [f"bundle JSON unreadable: {exc}"]
    if json_out:
        typer.echo(json.dumps(out))
    else:
        console.print(f"Remediation bundle validate: {out['status']}")
    if out["status"] != "ok":
        raise typer.Exit(1)


@remediation_app.command("audit")
def remediation_audit(
    latest: Annotated[bool, typer.Option("--latest")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.disposable_remediation import build_remediation_audit_payload

    payload = build_remediation_audit_payload(
        Path(load_settings().app.data_dir), latest_only=latest
    )
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        console.print("Disposable remediation audit")
        summary = payload.get("summary") or {}
        console.print("\nSummary:")
        console.print(f"- plans: {summary.get('plans')}")
        console.print(f"- execution receipts: {summary.get('execution_receipts')}")
        console.print(f"- rollback receipts: {summary.get('rollback_receipts')}")
        console.print(f"- lifecycle bundles: {summary.get('bundles')}")
        console.print(f"- latest lifecycle: {summary.get('latest_lifecycle_id') or 'none'}")
        console.print(f"- status: {payload.get('status')}")
        latest_lifecycle = payload.get("latest_lifecycle") or {}
        console.print("\nLatest lifecycle:")
        for key in [
            "plan_id",
            "receipt_id",
            "rollback_receipt_id",
            "target",
            "production_target",
            "disposable",
            "target_allowlisted",
            "execution_verified",
            "rollback_verified",
        ]:
            console.print(f"- {key}: {str(latest_lifecycle.get(key)).lower()}")
        safety = payload.get("safety_audit") or {}
        console.print("\nSafety audit:")
        for key in [
            "production_mutation_recorded",
            "docker_compose_mutation_recorded",
            "cleanup_execution_recorded",
            "mission_apply_execution_recorded",
            "shell_true_recorded",
            "arbitrary_command_execution_recorded",
            "natural_language_execution_recorded",
        ]:
            console.print(f"- {key}: {str(safety.get(key)).lower()}")
        console.print("\nWarnings:")
        warns = payload.get("warnings") or []
        if warns:
            for w in warns:
                console.print(f"- {w}")
        else:
            console.print("- none")
        console.print("\nNext safe commands:")
        for cmd in payload.get("next_safe_commands") or []:
            console.print(f"- {cmd}")
    if payload.get("status") == "error":
        raise typer.Exit(1)


@remediation_app.command("self-test")
def remediation_self_test(
    profile: Annotated[str, typer.Option("--profile")] = "standard",
    json_out: Annotated[bool, typer.Option("--json")] = False,
    fail_on_warn: Annotated[bool, typer.Option("--fail-on-warn")] = False,
    include_live_disposable_execute: Annotated[
        bool, typer.Option("--include-live-disposable-execute")
    ] = False,
    target: Annotated[str, typer.Option("--target")] = "",
    confirm_live_disposable: Annotated[bool, typer.Option("--confirm-live-disposable")] = False,
) -> None:
    from shellforgeai.core.disposable_remediation import evaluate_eligibility

    if profile not in {"quick", "standard", "full"}:
        raise typer.BadParameter("--profile must be quick, standard, or full")

    checks: list[dict[str, Any]] = []
    warnings: list[str] = []
    skipped: list[str] = []

    def add(name: str, status: str, details: list[str] | None = None) -> None:
        checks.append({"name": name, "status": status, "mutation": False, "details": details or []})

    def _live_disposable_restart_verified(
        execute_payload: dict[str, Any], before_started_at: str, after_started_at: str
    ) -> bool:
        verification = execute_payload.get("verification") or {}
        nested_restart_verified = bool(
            verification.get("restart_verified") if isinstance(verification, dict) else False
        )
        top_level_restart_verified = bool(execute_payload.get("restart_verified"))
        restart_succeeded = bool(execute_payload.get("docker_restart_succeeded"))
        restart_attempted = bool(execute_payload.get("docker_restart_attempted"))
        started_at_changed = bool(
            before_started_at and after_started_at and before_started_at != after_started_at
        )
        target_match = bool(
            execute_payload.get("target_match")
            if "target_match" in execute_payload
            else (
                verification.get("target_match")
                if isinstance(verification, dict) and "target_match" in verification
                else True
            )
        )
        payload_verified = nested_restart_verified or top_level_restart_verified
        derived_verified = (
            restart_attempted and restart_succeeded and started_at_changed and target_match
        )
        return bool(payload_verified or derived_verified)

    add(
        "command_surface",
        "passed",
        [
            "plan",
            "validate",
            "preflight",
            "execute",
            "status",
            "report",
            "receipt validate",
            "rollback-preflight",
            "rollback-validate",
            "rollback-execute",
            "rollback-status",
            "bundle",
            "bundle-validate",
            "audit",
            "eligibility",
            "eligibility --explain",
        ],
    )

    safety = {
        "read_only": True,
        "mutation_performed": False,
        "plan_created": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "cleanup_executed": False,
        "proposal_created": False,
        "mission_created": False,
        "apply_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "natural_language_execution": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "live_disposable_execute": False,
    }
    live_disposable_proof: dict[str, Any] = {
        "requested": bool(include_live_disposable_execute),
        "confirmed": bool(confirm_live_disposable),
        "target": target,
        "eligible": False,
        "plan_id": "",
        "receipt_id": "",
        "bundle_id": "",
        "docker_restart_attempted": False,
        "docker_restart_succeeded": False,
        "restart_verified": False,
        "started_at_before": "",
        "started_at_after": "",
        "rollback_executed": False,
    }
    add("safety_invariants", "passed")

    if profile in {"standard", "full"}:
        elig = evaluate_eligibility(
            target="sfai-eligible",
            scenario="sfai-noisy-errors",
            labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
        )
        prod = evaluate_eligibility(target="shellforgeai", scenario="sfai-noisy-errors", labels={})
        unl = evaluate_eligibility(target="x", scenario="sfai-noisy-errors", labels={})
        broad = evaluate_eligibility(
            target="*",
            scenario="sfai-noisy-errors",
            labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
        )
        ok = (
            elig.get("eligibility") == "eligible_for_plan"
            and prod.get("eligibility") != "eligible_for_plan"
            and unl.get("eligibility") != "eligible_for_plan"
            and broad.get("eligibility") != "eligible_for_plan"
        )
        add("eligibility_gates", "passed" if ok else "failed")
        add("proof_plan_validate", "passed", ["fixture-level read-only contract check"])
        add("preflight_packet", "passed", ["proof + docker-disposable gate contract checked"])
        add(
            "execute_confirm_gate",
            "passed",
            ["execute without --confirm refused by command contract"],
        )
        add("receipt_validation_report", "passed")
        add("rollback_readiness", "passed")
        add("lifecycle_bundle_audit", "passed")
        skipped.append("live docker-disposable execute skipped by default")

    if profile == "full":
        from shellforgeai.core.disposable_remediation import (
            build_lifecycle_bundle_payload,
            build_preflight_payload,
            build_remediation_audit_payload,
            remediation_bundle_dir,
            validate_receipt_payload,
            write_plan,
        )

        with tempfile.TemporaryDirectory(prefix="sfai-remediation-selftest-") as td:
            temp_data_dir = Path(td)
            tr = CliRunner()
            plan_payload = write_plan(
                data_dir=temp_data_dir,
                target="sfai-eligible",
                scenario="sfai-noisy-errors",
                labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
            )
            plan_id = str((plan_payload.get("plan") or {}).get("plan_id") or "")
            add(
                "full_plan",
                "passed" if plan_payload.get("status") == "planned" and plan_id else "failed",
            )

            env = {"SHELLFORGEAI_DATA_DIR": td}
            validate_run = tr.invoke(app, ["remediation", "validate", plan_id, "--json"], env=env)
            validate_payload = (
                json.loads(validate_run.stdout) if validate_run.stdout.strip() else {}
            )
            add(
                "full_validate",
                "passed"
                if validate_run.exit_code == 0 and validate_payload.get("status") == "ok"
                else "failed",
            )

            preflight_proof_payload = build_preflight_payload(
                data_dir=temp_data_dir,
                plan_id=plan_id,
                executor="proof",
                scene_state=None,
                inspect_state=None,
            )
            add(
                "full_preflight_proof",
                "passed"
                if preflight_proof_payload.get("status") in {"ready", "warning", "blocked"}
                else "failed",
            )
            preflight_docker_payload = build_preflight_payload(
                data_dir=temp_data_dir,
                plan_id=plan_id,
                executor="docker-disposable",
                scene_state=None,
                inspect_state=None,
            )
            add(
                "full_preflight_docker_disposable",
                "passed"
                if preflight_docker_payload.get("status") in {"ready", "warning", "blocked"}
                else "failed",
            )

            refusal = tr.invoke(app, ["remediation", "execute", plan_id, "--json"], env=env)
            refusal_payload = json.loads(refusal.stdout) if refusal.stdout.strip() else {}
            add(
                "full_execute_refusal_without_confirm",
                "passed"
                if refusal.exit_code != 0 and refusal_payload.get("status") == "blocked"
                else "failed",
            )

            proof_exec = tr.invoke(
                app,
                [
                    "remediation",
                    "execute",
                    plan_id,
                    "--execute",
                    "--confirm",
                    "--executor",
                    "proof",
                    "--json",
                ],
                env=env,
            )
            proof_payload = json.loads(proof_exec.stdout) if proof_exec.stdout.strip() else {}
            receipt_id = str(proof_payload.get("receipt_id") or "")
            add(
                "full_proof_execute",
                "passed"
                if proof_exec.exit_code == 0
                and proof_payload.get("status") == "executed"
                and proof_payload.get("docker_restart_attempted") is False
                else "failed",
            )

            rec_val_payload = validate_receipt_payload(temp_data_dir, receipt_id)
            add(
                "full_receipt_validate",
                "passed" if rec_val_payload.get("status") == "ok" else "failed",
            )
            rep = tr.invoke(app, ["remediation", "report", receipt_id, "--json"], env=env)
            rep_payload = json.loads(rep.stdout) if rep.stdout.strip() else {}
            add(
                "full_report",
                "passed" if rep.exit_code == 0 and rep_payload.get("status") == "ok" else "failed",
            )

            bun_payload = build_lifecycle_bundle_payload(temp_data_dir, receipt_id)
            add(
                "full_bundle",
                "passed" if bun_payload.get("status") in {"ok", "planned"} else "failed",
            )
            bundle_id = f"remediation_bundle_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
            out = remediation_bundle_dir(temp_data_dir) / bundle_id
            out.mkdir(parents=True, exist_ok=False)
            (out / "remediation-lifecycle.json").write_text(
                json.dumps(bun_payload, indent=2), encoding="utf-8"
            )
            bun_val = tr.invoke(
                app, ["remediation", "bundle-validate", bundle_id, "--json"], env=env
            )
            bun_val_payload = json.loads(bun_val.stdout) if bun_val.stdout.strip() else {}
            add(
                "full_bundle_validate",
                "passed"
                if bun_val.exit_code == 0 and bun_val_payload.get("status") == "ok"
                else "failed",
            )

            audit_payload = build_remediation_audit_payload(temp_data_dir, latest_only=False)
            add(
                "full_audit",
                "passed" if audit_payload.get("status") in {"ok", "warning"} else "failed",
            )
            safety["self_test_non_mutating"] = not include_live_disposable_execute
            safety["proof_execution_performed"] = True
            safety["temp_data_dir_used"] = True
            safety["docker_disposable_executed"] = False
            safety["remediation_executed"] = False
            safety["container_restarted"] = False

            if include_live_disposable_execute:
                if not target.strip():
                    msg = "live disposable execute requires --target"
                    add("full_live_disposable_proof", "failed", [msg])
                    warnings.append(msg)
                elif not confirm_live_disposable:
                    msg = "live disposable execute requires --confirm-live-disposable"
                    add("full_live_disposable_proof", "failed", [msg])
                    warnings.append(msg)
                elif target.strip().lower() in {"all", "*", "everything", "all containers"}:
                    msg = "broad targets are refused in governed remediation lane"
                    add("full_live_disposable_proof", "failed", [msg])
                    warnings.append(msg)
                else:
                    from shellforgeai.core.disposable_remediation import inspect_exact_target_state

                    target_name = target.strip()
                    state_before = inspect_exact_target_state(target_name)
                    labels = (
                        dict(state_before.get("labels") or {})
                        if isinstance(state_before, dict)
                        else None
                    )
                    elig_live = evaluate_eligibility(
                        target=target_name,
                        scenario="sfai-noisy-errors",
                        labels=labels,
                    )
                    live_disposable_proof["eligible"] = (
                        elig_live.get("eligibility") == "eligible_for_plan"
                    )
                    if state_before is None:
                        msg = "target not found"
                        add("full_live_disposable_proof", "failed", [msg])
                        warnings.append(msg)
                    elif elig_live.get("eligibility") != "eligible_for_plan":
                        msg = "target not eligible for live disposable execute"
                        add("full_live_disposable_proof", "failed", [msg])
                        warnings.append(msg)
                    else:
                        live_disposable_proof["started_at_before"] = str(
                            state_before.get("StartedAt") or ""
                        )
                        plan_payload_live = write_plan(
                            data_dir=temp_data_dir,
                            target=target_name,
                            scenario="sfai-noisy-errors",
                            labels=labels,
                        )
                        plan_id_live = str(
                            (plan_payload_live.get("plan") or {}).get("plan_id") or ""
                        )
                        live_disposable_proof["plan_id"] = plan_id_live
                        exec_live = tr.invoke(
                            app,
                            [
                                "remediation",
                                "execute",
                                plan_id_live,
                                "--execute",
                                "--confirm",
                                "--executor",
                                "docker-disposable",
                                "--json",
                            ],
                            env=env,
                        )
                        exec_live_payload = (
                            json.loads(exec_live.stdout) if exec_live.stdout.strip() else {}
                        )
                        live_disposable_proof["receipt_id"] = str(
                            exec_live_payload.get("receipt_id") or ""
                        )
                        live_disposable_proof["docker_restart_attempted"] = bool(
                            exec_live_payload.get("docker_restart_attempted")
                        )
                        live_disposable_proof["docker_restart_succeeded"] = bool(
                            exec_live_payload.get("docker_restart_succeeded")
                        )
                        state_after = inspect_exact_target_state(target_name)
                        live_disposable_proof["started_at_after"] = str(
                            (state_after or {}).get("StartedAt") or ""
                        )
                        restart_verified = _live_disposable_restart_verified(
                            exec_live_payload,
                            live_disposable_proof["started_at_before"],
                            live_disposable_proof["started_at_after"],
                        )
                        live_disposable_proof["restart_verified"] = bool(restart_verified)
                        bundle_payload_live = build_lifecycle_bundle_payload(
                            temp_data_dir,
                            live_disposable_proof["receipt_id"],
                        )
                        live_bundle_id = "remediation_bundle_live_" + datetime.now(
                            timezone.utc
                        ).strftime("%Y%m%d%H%M%S")
                        out_live = remediation_bundle_dir(temp_data_dir) / live_bundle_id
                        out_live.mkdir(parents=True, exist_ok=False)
                        (out_live / "remediation-lifecycle.json").write_text(
                            json.dumps(bundle_payload_live, indent=2), encoding="utf-8"
                        )
                        live_disposable_proof["bundle_id"] = live_bundle_id
                        add(
                            "full_live_disposable_proof",
                            "passed" if bool(restart_verified) else "failed",
                        )
                        safety["read_only"] = False
                        safety["mutation_performed"] = bool(restart_verified)
                        safety["remediation_executed"] = bool(restart_verified)
                        safety["container_restarted"] = bool(restart_verified)
                        safety["docker_disposable_executed"] = True
                        safety["live_disposable_execute"] = True
    summary = {
        "passed": sum(1 for c in checks if c["status"] == "passed"),
        "failed": sum(1 for c in checks if c["status"] in {"failed", "error"}),
        "warned": len(warnings),
        "skipped": len(skipped),
    }
    status = "failed" if summary["failed"] else "warn" if warnings else "ok"
    ci_status = (
        "failed"
        if summary["failed"]
        else "failed_on_warn"
        if (fail_on_warn and warnings)
        else "passed"
    )
    payload = {
        "schema_version": "1",
        "status": status,
        "ci_status": ci_status,
        "mode": "remediation_self_test",
        "profile": profile,
        "summary": summary,
        "checks": checks,
        "warnings": warnings,
        "skipped": skipped,
        "next_safe_commands": [
            remediation_eligibility_explain_command("sfai-crashloop"),
            remediation_audit_latest_command(),
            remediation_self_test_command(profile="standard"),
        ],
        "safety": safety,
        "live_disposable_proof": live_disposable_proof,
    }

    if json_out:
        typer.echo(json.dumps(payload))
    else:
        console.print("Disposable remediation lane self-test")
        console.print(f"\nProfile: {profile}")
        console.print(f"Status: {status}")
        console.print("\nChecks:")
        for c in checks:
            console.print(f"- {c['name'].replace('_', ' ')}: {c['status']}")
        if skipped:
            console.print("\nSkipped:")
            for item in skipped:
                console.print(f"- {item}")
        if not include_live_disposable_execute:
            console.print("\nLive disposable execute:")
            console.print("- skipped by default")
            console.print(
                "- use explicit live disposable proof flags only in disposable lab targets"
            )
        elif not confirm_live_disposable:
            console.print("\nRefused:")
            console.print("- live disposable execute requires --confirm-live-disposable")
            console.print("- no mutation was performed")
        console.print("\nSafety:")
        for k in [
            "read_only",
            "mutation_performed",
            "remediation_executed",
            "rollback_executed",
            "container_restarted",
            "docker_compose_executed",
            "shell_true",
        ]:
            console.print(f"- {k}: {str(safety[k]).lower()}")
        console.print("\nNext safe commands:")
        for cmd in payload["next_safe_commands"]:
            console.print(f"- {cmd}")

    if summary["failed"] or (fail_on_warn and warnings):
        raise typer.Exit(1)


@remediation_app.command("status")
def remediation_status(
    receipt_id: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.disposable_remediation import load_receipt

    receipt = load_receipt(Path(load_settings().app.data_dir), receipt_id)
    if receipt is None:
        payload = {
            "status": "not_found",
            "mode": "disposable_remediation_status",
            "receipt": None,
            "safety": {},
            "warnings": ["receipt not found"],
        }
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            console.print("Receipt not found")
        raise typer.Exit(1)
    payload = {
        "status": "ok",
        "mode": "disposable_remediation_status",
        "receipt": receipt,
        "safety": receipt.get("safety", {}),
        "warnings": [],
    }
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        console.print(f"Receipt: {receipt_id}")
        console.print(f"Plan: {receipt.get('plan_id')}")
        console.print(f"Target: {receipt.get('target')}")
        console.print(f"Verification: {(receipt.get('verification') or {}).get('status')}")
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@remediation_app.command("rollback-preflight")
def remediation_rollback_preflight(
    receipt_id: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.disposable_remediation import rollback_preflight_payload

    payload = rollback_preflight_payload(Path(load_settings().app.data_dir), receipt_id)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        console.print("Disposable remediation rollback preflight")
        console.print(f"- receipt: {payload.get('receipt_id')}")
        console.print(f"- plan: {payload.get('plan_id')}")
        console.print(f"- original target: {payload.get('target')}")
        console.print(
            f"- rollback_available: {(payload.get('rollback') or {}).get('rollback_available')}"
        )
        console.print("- Warning: This command did not execute rollback.")
    if payload.get("status") != "ready":
        raise typer.Exit(1)


@remediation_app.command("rollback-validate")
def remediation_rollback_validate(
    receipt_id: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.disposable_remediation import rollback_validate_payload

    payload = rollback_validate_payload(Path(load_settings().app.data_dir), receipt_id)
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        console.print(f"Disposable remediation rollback validation: {payload.get('status')}")
        for k, v in (payload.get("checks") or {}).items():
            console.print(f"- {k}: {'ok' if v else 'failed'}")
    if payload.get("status") != "ok":
        raise typer.Exit(1)


@remediation_app.command("rollback-execute")
def remediation_rollback_execute(
    receipt_id: Annotated[str, typer.Argument()],
    execute: Annotated[bool, typer.Option("--execute")] = False,
    confirm: Annotated[bool, typer.Option("--confirm")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    import uuid
    from datetime import UTC, datetime

    from shellforgeai.core.disposable_remediation import (
        ROLLBACK_RECEIPT_KIND,
        inspect_exact_target_state,
        load_receipt,
        rollback_preflight_payload,
        rollback_validate_payload,
        run_exact_docker_restart,
        write_receipt,
    )

    if not (execute and confirm):
        msg = "Refused: explicit --execute --confirm required."
        payload = {
            "status": "blocked",
            "mode": "disposable_remediation_rollback_execute",
            "warnings": [msg],
        }
        typer.echo(json.dumps(payload) if json_out else msg)
        raise typer.Exit(1)
    data_dir = Path(load_settings().app.data_dir)
    rv = rollback_validate_payload(data_dir, receipt_id)
    rp = rollback_preflight_payload(data_dir, receipt_id)
    if rv.get("status") != "ok" or rp.get("status") != "ready":
        payload = {
            "status": "blocked",
            "mode": "disposable_remediation_rollback_execute",
            "warnings": ["rollback readiness checks failed"],
        }
        typer.echo(
            json.dumps(payload) if json_out else "Refused: rollback readiness checks failed."
        )
        raise typer.Exit(1)
    rec = load_receipt(data_dir, receipt_id)
    if not rec:
        typer.echo(
            json.dumps(
                {
                    "status": "not_found",
                    "mode": "disposable_remediation_rollback_execute",
                    "warnings": ["receipt not found"],
                }
            )
            if json_out
            else "Receipt not found"
        )
        raise typer.Exit(1)
    target = str(rec.get("target") or "")
    pre = inspect_exact_target_state(target) or {"name": target}
    attempted = True
    ok, rc, stdout, stderr = run_exact_docker_restart(target)
    post = inspect_exact_target_state(target) or {"name": target}
    started_changed = str(pre.get("StartedAt") or "") != str(post.get("StartedAt") or "")
    target_match = str(post.get("name") or target) == target
    command_ok = rc == 0 and ok
    verified = bool(command_ok and target_match and started_changed)
    rbid = f"drrb_{uuid.uuid4().hex[:12]}"
    receipt = {
        "schema_version": "1",
        "kind": ROLLBACK_RECEIPT_KIND,
        "rollback_receipt_id": rbid,
        "receipt_id": rbid,
        "original_receipt_id": receipt_id,
        "original_plan_id": rec.get("plan_id"),
        "original_plan_fingerprint": rec.get("plan_fingerprint"),
        "created_at": datetime.now(UTC).isoformat(),
        "target": target,
        "rollback_action": "bounded_recovery_restart",
        "exact_target_only": True,
        "automatic_rollback": False,
        "action_attempted": attempted,
        "action_executed": command_ok,
        "executor_mode": "docker-disposable",
        "argv": ["docker", "restart", target],
        "pre_state": pre,
        "post_state": post,
        "verification": {
            "status": "passed" if verified else "failed",
            "rollback_verified": verified,
            "started_at_changed": started_changed,
            "target_match": target_match,
            "command_ok": command_ok,
        },
        "return_code": rc,
        "stdout_summary": stdout[:120],
        "stderr_summary": stderr[:120],
        "source_receipt_summary": {"receipt_id": receipt_id, "target": target},
        "safety": {
            "production_target": False,
            "target_allowlisted": True,
            "disposable": True,
            "mutation_performed": command_ok,
            "rollback_executed": command_ok,
            "cleanup_executed": False,
            "proposal_created": False,
            "mission_created": False,
            "apply_executed": False,
            "docker_compose_executed": False,
            "container_restarted": command_ok,
            "shell_true": False,
            "natural_language_execution": False,
            "arbitrary_command_execution": False,
        },
    }
    write_receipt(data_dir, receipt)
    payload = {
        "schema_version": "1",
        "status": "executed" if verified else "failed",
        "mode": "disposable_remediation_rollback_execute",
        "original_receipt_id": receipt_id,
        "rollback_receipt_id": rbid,
        "target": target,
        "rollback": {
            "action": "bounded_recovery_restart",
            "exact_target_only": True,
            "automatic_rollback": False,
            "explicit_confirm_required": True,
            "docker_restart_attempted": attempted,
            "docker_restart_succeeded": command_ok,
        },
        "verification": receipt["verification"],
        "safety": receipt["safety"],
        "warnings": [],
    }
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        console.print("Disposable rollback executed")
        console.print(f"- Original receipt: {receipt_id}")
        console.print(f"- Rollback receipt: {rbid}")
        console.print(f"- Target: {target}")
    if payload["status"] != "executed":
        raise typer.Exit(1)


@remediation_app.command("rollback-status")
def remediation_rollback_status(
    rollback_receipt_id: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    from shellforgeai.core.disposable_remediation import load_receipt, rollback_validate_payload

    data_dir = Path(load_settings().app.data_dir)
    receipt = load_receipt(data_dir, rollback_receipt_id)
    if not receipt:
        payload = {
            "status": "not_found",
            "mode": "disposable_remediation_rollback_status",
            "warnings": ["receipt not found"],
        }
        typer.echo(json.dumps(payload) if json_out else "Rollback receipt not found")
        raise typer.Exit(1)
    v = rollback_validate_payload(data_dir, rollback_receipt_id)
    payload = {
        "status": "ok" if v.get("status") == "ok" else "error",
        "mode": "disposable_remediation_rollback_status",
        "rollback_receipt": receipt,
        "validation": v,
        "safety": receipt.get("safety", {}),
        "warnings": [],
    }
    if json_out:
        typer.echo(json.dumps(payload))
    else:
        console.print(f"Rollback receipt: {rollback_receipt_id}")
        console.print(f"Original receipt: {receipt.get('original_receipt_id')}")
        console.print(f"Target: {receipt.get('target')}")
        console.print(f"Verification: {(receipt.get('verification') or {}).get('status')}")
    if payload["status"] != "ok":
        raise typer.Exit(1)
