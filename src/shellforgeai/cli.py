from __future__ import annotations

import json
import platform
import re
import sys
from contextlib import suppress
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from shellforgeai.audit.storage import AuditStorage
from shellforgeai.core.apply_bundle import (
    generate_bundle,
    run_preflight,
    write_diagnostic_preflight,
)
from shellforgeai.core.approvals import (
    Proposal,
    approve_proposal,
    archive_proposal,
    cancel_proposal,
    create_proposals_for_session,
    find_proposal_path,
    latest_approved_proposal,
    latest_runbook,
    list_proposals,
    load_proposal_from_path,
    reject_proposal,
    validate_proposal_payload,
)
from shellforgeai.core.ask_routing import (
    EVIDENCE_BACKED,
    PLAIN,
    AskRoute,
    evidence_brief,
    extract_container_target,
    is_apply_approved_intent,
    is_create_proposals_intent,
    is_immediate_fix_intent,
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
from shellforgeai.core.plans import Plan, PlanStep
from shellforgeai.core.profiles import load_profile
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
from shellforgeai.tools import host, journal, registry, systemd
from shellforgeai.util.subprocess import run_command
from shellforgeai.version import get_build_info

app = typer.Typer(
    no_args_is_help=False,
    invoke_without_command=True,
)
inspect_app = typer.Typer()
tools_app = typer.Typer()
audit_app = typer.Typer()
model_app = typer.Typer()
approvals_app = typer.Typer(help="Manage mutation proposal objects (read-only metadata).")
app.add_typer(inspect_app, name="inspect")
app.add_typer(tools_app, name="tools")
app.add_typer(audit_app, name="audit")
app.add_typer(model_app, name="model")
app.add_typer(approvals_app, name="approvals")
# Treat all runtime/model/evidence strings as untrusted; disable Rich markup
# interpretation to prevent crashes on bracketed data like mount sources.
console = Console(markup=False)


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
def doctor(ctx: typer.Context) -> None:
    runtime = _ctx(ctx)
    audit = AuditStorage(runtime.session.data_dir)
    console.print("ShellForgeAI")
    build = get_build_info()
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
    console.print(
        f"runtime_hygiene pid1={pid1} init_reaper={init_reaper} defunct_codex={defunct_codex}"
    )


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


@audit_app.command("show")
def audit_show(ctx: typer.Context, session_id: str) -> None:
    runtime = _ctx(ctx)
    val = AuditStorage(runtime.session.data_dir).show(session_id)
    if val is None:
        raise typer.Exit(code=1)
    console.print(val)


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

    preflight = run_preflight(proposal)
    data_dir = Path(runtime.session.data_dir)

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
            console.print(f"- preflight record: {preflight_path}")
        raise typer.Exit(code=1)

    if dry_run:
        console.print("Apply preflight passed (dry-run). Execution remains disabled in this alpha.")
        console.print(f"- proposal: {proposal.proposal_id}")
        console.print(f"- status: {proposal.status}")
        console.print(f"- risk: {proposal.risk}")
        console.print("- execution: not_executed")
        console.print("- bundle: not written (dry-run)")
        console.print("- no commands executed")
        return

    result = generate_bundle(proposal, data_dir=data_dir, preflight=preflight)
    _print_apply_bundle_success(proposal, result.files)


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
            result = export_latest_approved(data_dir, redact=intent.use_redaction)
        else:
            latest = latest_session_dir(data_dir)
            if latest is None:
                console.print(
                    "Cannot export an audit pack yet: no session artifacts found.\n"
                    "- run `shellforgeai diagnose <target> --with-runbook` first.\n"
                    "- no commands were executed."
                )
                return True
            result = export_from_session(data_dir, latest, redact=intent.use_redaction)
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
    if intent.use_redaction:
        console.print("- redaction: best-effort only; review the export before external sharing.")
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
        if _handle_immediate_fix_ask(runtime, question):
            return
        if _handle_export_ask(runtime, question):
            return
        if _handle_apply_approved_ask(runtime, question):
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
