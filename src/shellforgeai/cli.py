from __future__ import annotations

import json
import platform
import re
import shlex
import sys
import tarfile
import uuid
from contextlib import suppress
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime, timezone
from pathlib import Path
from posixpath import normpath
from typing import Annotated, Any

import typer
from rich.console import Console

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
    has_compose_artifact_reference_phrase,
    is_apply_approved_intent,
    is_compose_mutation_request,
    is_compose_service_mutation_proposal_request,
    is_create_proposals_intent,
    is_create_restart_proposal_intent,
    is_immediate_fix_intent,
    is_lab_restart_ask_intent,
    is_lab_restart_verification_ask_intent,
    is_mission_compose_context_query,
    is_restart_proposal_compose_context_query,
    network_reachability_brief,
    route_ask_intent,
    target_container_status,
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
from shellforgeai.core.metadata_hygiene import scan_metadata_hygiene
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
mission_app.add_typer(mission_restart_app, name="restart")
compose_app = typer.Typer(help="Read-only Docker Compose ownership context.")
ops_app = typer.Typer(help="Read-only operator status board.")
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

        start_interactive(ctx.obj["runtime"], no_trust_cache=no_trust_cache)
        raise typer.Exit()


@app.command("interactive")
def interactive(
    ctx: typer.Context, no_trust_cache: bool = typer.Option(False, "--no-trust-cache")
) -> None:
    from shellforgeai.interactive import start_interactive

    start_interactive(_ctx(ctx), no_trust_cache=no_trust_cache)


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
    console.print(
        "- severity: "
        f"{hygiene['severity']} | ShellForgeAI metadata: "
        f"{hygiene['total_human']} across {hygiene['total_items']} items"
    )
    cats = sorted(hygiene["categories"].items(), key=lambda kv: int(kv[1]["bytes"]), reverse=True)
    console.print("- Largest categories:")
    for name, row in cats[:3]:
        console.print(f"  - {name}: {row['human']} / {row['count']} items")
    if hygiene["warnings"]:
        console.print(f"- Warning: {hygiene['warnings'][0]}")
    if hygiene["recommendations"]:
        console.print(f"- Suggested next step: {hygiene['recommendations'][0]}")
        if len(hygiene["recommendations"]) > 1:
            console.print(f"- Dry-run cleanup: {hygiene['recommendations'][1]}")


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
    payload = {
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
    cats = build_categories(data_dir)
    candidates: list[dict[str, Any]] = []
    warnings: list[str] = []
    for c in selected_categories:
        selected = prune_select(
            collect_category(cats[c]), max_age_days=max_age_days, keep_latest=keep_latest
        )
        for p in selected:
            try:
                rp = p.resolve(strict=True)
            except FileNotFoundError:
                continue
            if not any(root.resolve() in rp.parents for root in _cleanup_allowed_roots(data_dir)):
                warnings.append(f"skipped outside allowed roots: {p}")
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
    payload = {
        "schema_version": "1",
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
            "candidate_count": len(candidates),
            "candidate_bytes": candidate_bytes,
            "would_archive": sum(1 for c in candidates if c["requires_archive_first"]),
            "would_delete": len(candidates),
        },
        "safety": {
            "dry_run": True,
            "execution_allowed": False,
            "mutation_performed": False,
            "shellforgeai_metadata_only": True,
            "arbitrary_path_deletion": False,
        },
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
    if json_output:
        console.print_json(data=payload)
        return
    console.print(f"Cleanup plan created: {plan_id}")
    console.print(f"- plan: {out_dir / 'cleanup-plan.json'}")


@audit_cleanup_app.command("archive")
def audit_cleanup_archive(ctx: typer.Context, plan_id: str) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    pdir = _cleanup_plan_dir(data_dir, plan_id)
    payload = json.loads((pdir / "cleanup-plan.json").read_text(encoding="utf-8"))
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
    console.print(f"Cleanup archive created: {archive_path}")


@audit_cleanup_app.command("execute")
def audit_cleanup_execute(
    ctx: typer.Context, plan_id: str, confirm: bool = typer.Option(False, "--confirm")
) -> None:
    runtime = _ctx(ctx)
    data_dir = Path(runtime.session.data_dir)
    if not confirm:
        console.print("Refused: --confirm required.")
        raise typer.Exit(code=1)
    payload = json.loads(
        (_cleanup_plan_dir(data_dir, plan_id) / "cleanup-plan.json").read_text(encoding="utf-8")
    )
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
        "receipt_id": rid,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "plan_id": plan_id,
        "archive_id": None,
        "mode": "execute",
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


@audit_cleanup_app.command("report")
def audit_cleanup_report(target: Path) -> None:
    if _is_cleanup_archive_path(target):
        console.print("Cleanup report failed:")
        console.print("- expected cleanup receipt directory or cleanup-receipt.json")
        console.print(f"- got archive file: {target}")
        console.print(
            "- to validate cleanup archives, run:"
            " shellforgeai audit cleanup validate <archive.tar.gz>"
        )
        raise typer.Exit(code=1)
    receipt_path = target / "cleanup-receipt.json" if target.is_dir() else target
    try:
        payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    except Exception:
        console.print("Cleanup report failed:")
        console.print("- expected cleanup receipt directory or cleanup-receipt.json")
        console.print(f"- got: {target}")
        raise typer.Exit(code=1) from None
    console.print("Cleanup report:")
    console.print(f"- receipt: {receipt_path}")
    console.print(f"- plan_id: {payload.get('plan_id')}")
    console.print(f"- deleted: {len(payload.get('deleted', []))}")
    console.print(f"- failed: {len(payload.get('failed', []))}")
    console.print(f"- bytes_removed: {payload.get('bytes_removed', 0)}")
    console.print("- safety: shellforgeai_metadata_only=true")


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
        summary = (
            f"Session: {result.session_id}\n"
            f"Target: {target}\n"
            f"Type: {result.target_type.value}\n"
            f"Evidence: {len(result.evidence.items)} item(s)\n"
            f"{findings_summary_line(result.findings)}\n"
            "Artifacts:\n"
            f"- evidence: {ev_path}\n"
            f"- plan: {plan_path if save_plan else 'not-saved'}\n"
            f"- model response: {model_response_display}\n"
            f"- summary: {summary_path if summary_path.exists() else 'n/a'}\n"
            f"- runbook: {runbook_path if runbook_path.exists() else 'not-saved'}\n"
            f"- runbook json: {runbook_json_path if runbook_json_path.exists() else 'not-saved'}"
        )
        console.print(summary)


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
    console.print("- status: preview_only")
    console.print("- ShellForgeAI will not execute rollback.")


@rollback_app.command("validate")
def rollback_validate_cmd(ctx: typer.Context, target: Annotated[Path, typer.Argument()]) -> None:
    _ = _ctx(ctx)
    try:
        payload = rollback_preview_mod.load_preview(target)
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
        "restart it now",
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
    if is_compose_mutation_request(question):
        console.print(
            "Refusing natural-language Compose mutation. PR58 only enriches Compose context. "
            "Compose context is read-only; ShellForgeAI does not run docker compose commands."
        )
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
    q = (question or "").strip().lower()
    return any(
        p in q
        for p in (
            "shellforgeai status",
            "operator status",
            "show me the dashboard",
            "is shellforgeai healthy",
            "what should i check next",
            "any pending approvals",
            "any guard failures",
            "how much metadata do i have",
        )
    )


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
    verbose: bool = typer.Option(False, "--verbose"),
    since: str | None = typer.Option(None, "--since"),
    include_retention: bool = typer.Option(False, "--include-retention"),
    include_index: bool = typer.Option(False, "--include-index"),
    include_audit: bool = typer.Option(False, "--include-audit"),
    include_approvals: bool = typer.Option(False, "--include-approvals"),
) -> None:
    _ = (verbose, since, include_index, include_audit, include_approvals)
    runtime = _ctx(ctx)
    payload = _collect_status_payload(runtime, include_retention=include_retention)
    if json_output:
        console.print_json(data=payload)
        return
    console.print("ShellForgeAI")
    for k, v in payload["shellforgeai"].items():
        console.print(f"- {k}: {v}")
    console.print("Model")
    for k, v in payload["model"].items():
        console.print(f"- {k}: {v}")
    console.print("Safety")
    for k, v in payload["safety"].items():
        console.print(f"- {k}: {v}")
    console.print("Latest activity")
    for k, v in payload["latest"].items():
        console.print(f"- {k}: {v}")
    console.print("Approvals")
    for k, v in payload["approvals"].items():
        console.print(f"- {k}: {v}")
    console.print("Guards / drift")
    for k, v in payload["guards"].items():
        console.print(f"- {k}: {v}")
    console.print("Audit / index")
    for k, v in payload["audit"].items():
        console.print(f"- {k}: {v}")
    if include_retention:
        console.print("Retention")
        console.print(f"- total_bytes: {payload['retention']['total_bytes']}")
    console.print("Next suggested read-only actions")
    for r in payload["recommendations"][:6]:
        console.print(f"- {r}")


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
        if _is_status_ask(question):
            p = _collect_status_payload(runtime, include_retention=True)
            console.print("ShellForgeAI status dashboard (read-only):")
            console.print(f"- health_level: {p.get('health_level')}")
            console.print(f"- execution: {p['safety']['message']}")
            console.print(f"- pending approvals: {p['approvals'].get('pending', 0)}")
            console.print(f"- recent guard refusals: {p['guards'].get('recent_refusals', 0)}")
            console.print("- next: shellforgeai status --json")
            return
        if _handle_retention_ask(runtime, question):
            return
        if _handle_incident_search_ask(runtime, question):
            return
        if _handle_guard_ask(runtime, question):
            return
        if _handle_mission_restart_ask(runtime, question):
            return
        if _handle_restart_plan_ask(runtime, question):
            return
        if _handle_compose_restart_preview_ask(runtime, question):
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
            console.print("Model unavailable. Install Codex CLI and login with: codex login")
        elif "auth" in err_text or "login" in err_text:
            console.print("Codex auth failed. Run: codex login")
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
        raise typer.Exit(1)
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
            raise typer.Exit(1)
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
