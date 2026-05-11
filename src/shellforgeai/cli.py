from __future__ import annotations

import platform
import re
import sys
from contextlib import suppress
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from shellforgeai.audit.storage import AuditStorage
from shellforgeai.core.ask_routing import (
    EVIDENCE_BACKED,
    PLAIN,
    AskRoute,
    evidence_brief,
    extract_container_target,
    network_reachability_brief,
    route_ask_intent,
    target_container_status,
)
from shellforgeai.core.config import load_settings
from shellforgeai.core.context import RuntimeContext
from shellforgeai.core.diagnose import diagnose_target, findings_summary_line
from shellforgeai.core.evidence import classify_target
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
app.add_typer(inspect_app, name="inspect")
app.add_typer(tools_app, name="tools")
app.add_typer(audit_app, name="audit")
app.add_typer(model_app, name="model")
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


@app.command()
def apply(plan_file: Path) -> None:
    if not plan_file.exists():
        raise typer.BadParameter("plan file missing")
    Plan.model_validate_json(plan_file.read_text(encoding="utf-8"))
    console.print(
        "Apply execution is intentionally disabled in this alpha. "
        "Plan validation is available; execution will be introduced after safety hardening."
    )


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
