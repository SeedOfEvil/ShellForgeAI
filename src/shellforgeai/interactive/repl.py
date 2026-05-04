from __future__ import annotations

import os
import platform
from ast import literal_eval
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from shellforgeai.audit.storage import AuditStorage
from shellforgeai.core.context import RuntimeContext
from shellforgeai.core.diagnose import diagnose_target
from shellforgeai.core.evidence import classify_target
from shellforgeai.core.plans import Plan, PlanStep
from shellforgeai.interactive.banner import build_banner
from shellforgeai.knowledge.search import search_local
from shellforgeai.llm.manager import build_provider
from shellforgeai.llm.prompts import build_contextual_prompt
from shellforgeai.llm.schemas import ModelRequest
from shellforgeai.tools import disk, host, network, process, registry, systemd
from shellforgeai.version import get_build_info

from .commands import route_input
from .guards import is_multiline_shell_fragment, is_shell_fragment_line, looks_like_shell_command
from .streaming import StreamRenderer
from .workspace import WorkspaceTrustStore


def _ensure_artifact_dir(runtime: RuntimeContext) -> None:
    runtime.session.artifact_dir.mkdir(parents=True, exist_ok=True)


def _is_machine_health_question(text: str) -> bool:
    t = text.lower()
    return any(
        n in t
        for n in [
            "issue on this machine",
            "machine healthy",
            "what's wrong with this box",
            "check this system",
            "machine look",
            "anything broken",
            "firewall is on or off",
            "firewall status",
            "firewall enabled",
            "check firewall",
            "anything wrong with my computer",
            "anything wrong with this machine",
            "is my computer okay",
            "do you see any issues",
            "host health",
            "computer health",
            "machine health",
        ]
    )


def _is_firewall_question(text: str) -> bool:
    t = text.lower()
    return any(
        p in t
        for p in [
            "firewall on or off",
            "firewall is on or off",
            "is firewall on",
            "is firewall off",
            "is the firewall enabled",
            "firewall status",
            "firewall state",
            "firewall enabled",
            "check firewall",
            "iptables status",
            "nftables status",
            "pve firewall",
        ]
    )


def _sanitize_provider_error(text: str) -> str:
    if "bwrap: No permissions to create a new namespace" in text:
        return (
            "Codex sandbox could not create a namespace in this container. "
            "This is a provider/container sandbox limitation, not evidence of host failure."
        )
    return text


def _evidence_table(console: Console, checks: list[dict[str, str]]) -> None:
    t = Table("Tool", "Status", "Summary")
    for c in checks:
        t.add_row(c["tool"], c["status"], c["summary"])
    console.print(t)


def _evidence_highlights(checks: list[dict[str, str]]) -> list[str]:
    by_tool = {c["tool"]: c for c in checks}
    out = []
    if "system.cpu_memory" in by_tool:
        out.append(f"- CPU/memory: {by_tool['system.cpu_memory']['summary']}.")
    if "host.resources" in by_tool:
        out.append(f"- Load: {by_tool['host.resources']['summary']}.")
    if "disk.usage" in by_tool or "disk.inodes" in by_tool:
        disk_sum = by_tool.get("disk.usage", {}).get("summary", "unknown")
        inode_sum = by_tool.get("disk.inodes", {}).get("summary", "unknown")
        out.append(f"- Disk/inodes: {disk_sum}; {inode_sum}.")
    if "storage.pressure" in by_tool:
        out.append(f"- Storage/I/O: {by_tool['storage.pressure']['summary']}.")
    if "system.container_detect" in by_tool:
        out.append(f"- Context: {by_tool['system.container_detect']['summary']}.")
    if "process.top" in by_tool:
        out.append(f"- Process: {by_tool['process.top']['summary']}.")
    return out[:7]


def _run_model_synthesis(
    console: Console, provider, request: ModelRequest, raw: bool
) -> tuple[str, bool]:
    streaming_enabled = os.getenv("SHELLFORGEAI_EXPERIMENTAL_STREAMING", "0") == "1"
    final_text = ""
    if streaming_enabled and hasattr(provider, "stream_complete"):
        with console.status("Synthesizing operator summary..."):
            pass
        for event in provider.stream_complete(request):
            etype = event.get("type")
            if etype == "text":
                console.print(event.get("text", ""), end="")
            elif etype == "raw" and raw:
                console.print(event.get("raw", ""))
            elif etype == "final":
                resp = event.get("response")
                if resp is not None:
                    final_text = resp.text
                break
        console.print("")
        return final_text, True
    with console.status("Asking model..."):
        resp = provider.complete(request)
    return resp.text, False


def _has_substantive_response(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    lowered = stripped.lower()
    banned = [
        "please collect these",
        "please run disk.usage",
        "please run host.resources",
        "i only have host/mode context",
        "i don’t have evidence yet",
        "i don't have evidence yet",
    ]
    if any(b in lowered for b in banned):
        return False
    return lowered not in {"## assessment", "# assessment"}


def _confirm_workspace(console: Console, runtime: RuntimeContext, no_trust_cache: bool) -> bool:
    store = WorkspaceTrustStore(runtime.session.data_dir)
    workspace = Path.cwd()
    if not no_trust_cache and store.is_trusted(workspace):
        return True
    console.print("Trust this workspace?\n")
    console.print(f"Path:\n  {workspace}\n")
    trust = typer.confirm(f"Trust {workspace}?", default=False)
    if not trust:
        console.print("Workspace not trusted. Exiting interactive mode.")
        return False
    if not no_trust_cache:
        store.trust(workspace, get_build_info().version)
    return True


def _summary_for_check(c) -> str:
    first = (c.stderr or c.stdout or "").splitlines()[0] if (c.stderr or c.stdout) else ""
    if c.tool == "host.info" and "hostname" in c.stdout:
        payload = literal_eval(c.stdout)
        return (
            f"hostname={payload.get('hostname', 'unknown')} "
            f"kernel={payload.get('kernel', 'unknown')} "
            f"arch={payload.get('arch', 'unknown')}"
        )
    if c.tool == "host.resources":
        return (c.stdout or "").replace("{'loadavg': ", "loadavg=").replace("}", "")
    if c.tool == "host.uptime":
        return first or "uptime unavailable"
    if c.tool in {"disk.usage", "disk.inodes"}:
        lines = (c.stdout or "").splitlines()[1:3]
        vals = []
        for ln in lines:
            parts = ln.split()
            if len(parts) >= 6:
                vals.append(f"{parts[5]} {parts[4]} used")
        return ", ".join(vals) if vals else (first or "disk summary unavailable")
    if c.tool == "network.dns" and "nameserver" in (c.stdout or ""):
        ns = [ln.split()[1] for ln in c.stdout.splitlines() if ln.startswith("nameserver")]
        return f"docker resolver {ns[0]}" if ns else "dns configured"
    if c.tool == "network.routes":
        return first or "route summary unavailable"
    if c.tool == "process.top":
        return (
            "top process summary available"
            if c.ok
            else f"unavailable — {first or 'command failed'}"
        )
    if c.tool.startswith("systemd") and not c.ok:
        return f"unavailable — {first or 'systemctl not found'}"
    return first[:120] if first else ("ok" if c.ok else "unavailable")


def _collect_machine_health() -> list[dict[str, str]]:
    health_checks = [
        host.host_info(),
        host.host_resources(),
        host.host_uptime(),
        disk.usage(),
        disk.inodes(),
        network.dns(),
        network.routes(),
        process.top(),
        systemd.list_failed(),
    ]
    return [
        {
            "tool": c.tool,
            "status": "ok" if c.ok else "unavailable",
            "summary": _summary_for_check(c),
        }
        for c in health_checks
    ]


def _deterministic_operator_summary(intent: str, checks: list[dict[str, str]]) -> str:
    def _find(tool: str) -> dict[str, str] | None:
        return next((c for c in checks if c["tool"] == tool), None)

    disk_row = _find("disk.usage")
    inode_row = _find("disk.inodes")
    container_row = _find("system.container_detect")
    load_row = _find("host.resources")
    systemd_row = _find("systemd.list_failed")
    assessment = "No critical issue seen from current read-only context."
    clues = []
    facts = []
    os_row = _find("system.os_release")
    cpu_mem_row = _find("system.cpu_memory")
    route_row = _find("network.routes")
    dns_row = _find("network.dns")
    process_row = _find("process.snapshot")
    if os_row:
        facts.append(f"- Host context: {os_row['summary']}.")
    if cpu_mem_row:
        facts.append(f"- CPU/memory: {cpu_mem_row['summary']}.")
    if load_row:
        facts.append(f"- Load: {load_row['summary']}.")
    if disk_row:
        facts.append(f"- Disk: {disk_row['summary']}.")
    if inode_row:
        facts.append(f"- Inodes: {inode_row['summary']}.")
    if route_row:
        facts.append(f"- Network route: {route_row['summary']}.")
    if dns_row:
        facts.append(f"- DNS: {dns_row['summary']}.")
    if process_row:
        facts.append(f"- Process view: {process_row['summary']}.")
    if disk_row and "% used" in disk_row["summary"]:
        if " 9" in disk_row["summary"] or "100%" in disk_row["summary"]:
            assessment = "Filesystem pressure looks critical."
            clues.append("- High confidence: filesystem usage is critically high.")
        elif " 8" in disk_row["summary"]:
            assessment = "Mostly okay, but filesystem usage is getting high."
            clues.append(
                "- Medium confidence: disk usage is elevated and worth drilling into first."
            )
    if container_row and "docker" in container_row["summary"].lower():
        clues.append("- High confidence: container context limits host-level visibility.")
    if systemd_row and systemd_row["status"] != "ok":
        clues.append("- High confidence: systemd checks are unavailable in this environment.")
    if load_row:
        clues.append(f"- Low confidence: load snapshot is {load_row['summary']}.")
    if inode_row and "% used" in inode_row["summary"]:
        clues.append(f"- Medium confidence: inode usage snapshot is {inode_row['summary']}.")
    return (
        "## Assessment\n"
        f"{assessment}\n\n"
        "## Facts found\n"
        + ("\n".join(facts) if facts else "- No evidence rows were collected.")
        + "\n\n## Clues / likely causes\n"
        + (
            "\n".join(clues)
            if clues
            else "- No strong clues yet; continue with read-only evidence."
        )
        + "\n\n## What I can check next\n"
        "- I can continue with a deeper read-only pass over process activity and error clues.\n\n"
        "## Safety\n"
        "Next steps are read-only. No restart, install, cleanup, or file changes.\n"
    )


_FOLLOWUP_CONFIRM = {
    "yes",
    "y",
    "proceed",
    "continue",
    "go ahead",
    "dig deeper",
    "do it",
    "make it so",
    "check deeper",
    "investigate more",
    "run it",
    "please continue",
    "sure",
}


def _operator_followup_text(label: str, description: str) -> str:
    return f"I can dig deeper into {label} next — {description}. Proceed?"


def select_followup_investigation(
    intent: str, checks: list[dict[str, str]], question: str
) -> dict[str, str] | None:
    q = question.lower()
    is_disk_capacity_intent = any(
        k in q
        for k in (
            "disk full",
            "disk getting full",
            "running out of space",
            "disk space",
            "inodes",
        )
    ) or intent in {"disk"}
    if any(w in q for w in ("service", "services", "nginx", "ssh", "docker", "port")):
        return {
            "intent": "service_health_deep_dive",
            "label": "service health",
            "description": "listening ports, service detectors, and recent service clues",
            "bundle": "services",
        }
    if any(w in q for w in ("network", "dns", "route", "firewall")):
        return {
            "intent": "network_dns_firewall_deep_dive",
            "label": "network/DNS",
            "description": "routes, DNS, listeners, and firewall context",
            "bundle": "network",
        }
    disk_summary = next((c.get("summary", "") for c in checks if c.get("tool") == "disk.usage"), "")
    inode_summary = next(
        (c.get("summary", "") for c in checks if c.get("tool") == "disk.inodes"), ""
    )
    if is_disk_capacity_intent:
        joined = f"{disk_summary} {inode_summary}"
        if not joined.strip() or "unavailable" in joined.lower():
            return {
                "intent": "disk_capacity_deep_dive",
                "label": "disk capacity angle",
                "description": "disk growth and inode pressure details",
                "bundle": "disk",
                "reason": "disk/inode evidence is unavailable or incomplete",
            }
        if any(x in joined for x in (" 8", " 9", "100%")):
            return {
                "intent": "disk_capacity_deep_dive",
                "label": "disk capacity angle",
                "description": "disk growth and inode pressure details",
                "bundle": "disk",
                "reason": "disk or inode usage is elevated",
            }
        return None
    for c in checks:
        tool = c.get("tool", "")
        summary = c.get("summary", "").lower()
        if tool == "storage.pressure" and ("io_some" in summary or "non-zero" in summary):
            return {
                "intent": "storage_io_deep_dive",
                "label": "storage/I/O",
                "description": "process activity, storage pressure, and recent error clues",
                "bundle": "performance",
            }
    return {
        "intent": "general_missing_context_deep_dive",
        "label": "broader read-only health pass",
        "description": "missing context, pressure signals, and recent error clues",
        "bundle": "health",
        "reason": "no single stronger angle was detected",
    }


def _contains_internal_collector_language(text: str) -> bool:
    low = text.lower()
    blocked = [
        "please run",
        "please collect",
        "useful next shellforgeai read-only checks",
        "shellforgeai collectors",
        "collector:",
        "process.top",
        "logs.search_errors",
        "disk.usage",
        "disk.inodes",
        "firewall.detect",
        "network.listeners",
        "host.info:",
        "host.resources:",
        "system.cpu_memory:",
        "process.top:",
        "shellforgeai should first collect",
    ]
    return any(b in low for b in blocked)


def start_interactive(runtime: RuntimeContext, no_trust_cache: bool = False) -> None:
    console = Console()
    trusted = WorkspaceTrustStore(runtime.session.data_dir).is_trusted(Path.cwd())
    console.print(build_banner(runtime, trusted))
    if not _confirm_workspace(console, runtime, no_trust_cache=no_trust_cache):
        return
    renderer = StreamRenderer(console)
    paste_guard_active = False
    paste_guard_remaining_lines = 0
    paste_guard_non_shell_lines = 0
    paste_guard_first_notice = False
    pending_followup: dict[str, str] | None = None
    completed_followups: list[str] = []
    evidence_mode = "compact"
    while True:
        user_input = input("sfai> ").strip()
        routed = route_input(user_input)
        if routed.name == "noop":
            continue
        if user_input.strip().lower() in _FOLLOWUP_CONFIRM:
            if not pending_followup:
                console.print(
                    "I don’t have a pending investigation. Tell me what symptom to check, "
                    "such as slow system, disk issue, network issue, or service issue."
                )
                continue
            with console.status("Running deeper read-only investigation..."):
                res = diagnose_target(
                    runtime, pending_followup["bundle"], online=False, since="30m"
                )
            checks = [
                {
                    "tool": i.source,
                    "status": str(i.metadata.get("status", "ok" if i.ok else "unavailable")),
                    "summary": i.summary,
                }
                for i in res.evidence.items
            ]
            console.print(
                f"Deeper investigation complete: {len(checks)} read-only evidence item(s)."
            )
            if evidence_mode == "full":
                _evidence_table(console, checks)
            else:
                console.print("Highlights:")
                for line in _evidence_highlights(checks):
                    console.print(line)
            console.print(_deterministic_operator_summary(pending_followup["intent"], checks))
            completed_followups.append(pending_followup["intent"])
            pending_followup = None
            continue
        if routed.name in {"/exit", "/quit"}:
            console.print("Goodbye.")
            return
        if routed.name == "/clear":
            os.system("clear")
            paste_guard_active = False
            continue
        if routed.name == "/help":
            console.print("""Session:
  /help              Show this help
  /exit, /quit       Exit ShellForgeAI
  /clear             Clear the screen

Status:
  /status            Show runtime summary
  /doctor            Show ShellForgeAI health
  /health            Run machine health checks
  /model             Show model provider status
  /workspace         Show workspace trust/status
  /mode              Show current mode
  /profile           Show active profile

Ops:
  diagnose <target>  Collect evidence and diagnose targets
  research <query>   Search local knowledge first
  plan <goal>        Create a conservative read-only plan
  ask <question>     Ask the configured model

Debug:
  /raw on|off        Toggle raw provider events
  /context <mode>    Set context mode: minimal, standard, full

Examples:
  diagnose disk
  research nginx address already in use
  plan investigate high disk usage
  ask explain this command: systemctl status nginx --no-pager

Shell paste guard:
  ShellForgeAI is not a shell. Run host/container commands outside sfai>.
  To review a command, prefix it with:
  ask explain this command: ...""")
            continue
        if routed.name == "/examples":
            console.print("""Diagnostics:
  diagnose disk
  diagnose network
  diagnose nginx
Research:
  research nginx address already in use
  research docker dns resolution
Planning:
  plan investigate high disk usage
  plan troubleshoot nginx 502 errors
Ask:
  ask what can you inspect here?
  ask explain this command: systemctl status nginx --no-pager
  ask review this shell snippet: df -h && du -xhd1 /var
Safety:
  Can you restart nginx for me?
  What would you check before restarting nginx?
Commands:
  /health
  /audit latest
  /pending
  /evidence compact|full""")
            continue
        if routed.name == "/evidence":
            arg = routed.args.strip().lower()
            if arg in {"compact", "full"}:
                evidence_mode = arg
                console.print(f"Evidence view set to: {evidence_mode}")
            else:
                console.print(f"Evidence view: {evidence_mode}")
            continue
        if routed.name == "/pending":
            if not pending_followup:
                console.print("No pending investigation.")
            else:
                console.print(
                    f"Pending investigation: {pending_followup['label']}\n"
                    f"Reason: {pending_followup.get('reason', 'not specified')}\n"
                    f"From: {pending_followup.get('created_from_question', 'unknown')}\n"
                    f"Session: {pending_followup.get('created_from_session', 'unknown')}"
                )
            continue
        if routed.name in {"/doctor", "/status", "/health"}:
            b = get_build_info()
            if routed.name == "/health":
                checks = _collect_machine_health()
                console.print("Collected evidence:")
                _evidence_table(console, checks)
                console.print(
                    "Health summary:\n"
                    "Read-only checks completed. Review unavailable rows "
                    "and investigate as needed."
                )
            else:
                console.print(
                    f"version={b.display_version} "
                    f"profile={runtime.profile.name} "
                    f"mode={runtime.session.mode}"
                )
            continue
        if routed.name == "/model":
            info = build_provider(runtime.settings).doctor()
            for k, v in info.items():
                console.print(f"{k}={v}")
            continue
        if routed.name == "/profile":
            p = runtime.profile
            console.print(
                f"Profile: {p.name}\n"
                f"Online allowed: {p.online_allowed}\n"
                f"Raw shell allowed: {getattr(p, 'allow_shell_raw', False)}\n"
                f"Mode: {runtime.session.mode}\n"
                "Apply: validation-only"
            )
            continue
        if routed.name == "/mode":
            console.print(
                f"Mode: {runtime.session.mode}\n"
                "Execution: no destructive actions\n"
                "Apply: validation-only"
            )
            continue
        if routed.name == "/audit":
            sessions = AuditStorage(runtime.session.data_dir).list_sessions()
            if routed.args.strip().lower() == "latest":
                if not sessions:
                    console.print("No audit sessions found.")
                else:
                    latest = sessions[-1]
                    console.print(
                        f"Latest audit session: {latest}\n"
                        f"Session file: "
                        f"{runtime.session.data_dir / 'sessions' / (latest + '.json')}\n"
                        f"Artifacts dir: {runtime.session.data_dir / 'artifacts'}"
                    )
                continue
            console.print(
                "No audit sessions found."
                if not sessions
                else "Recent audit sessions:\n" + "\n".join(sessions[:10])
            )
            continue
        if routed.name == "/workspace":
            trusted_now = WorkspaceTrustStore(runtime.session.data_dir).is_trusted(Path.cwd())
            console.print(
                f"Workspace: {Path.cwd()}\n"
                f"Trusted: {'yes' if trusted_now else 'no'}\n"
                f"Data dir: {runtime.session.data_dir}\n"
                f"Artifacts dir: {runtime.session.data_dir / 'artifacts'}\n"
                f"Sessions dir: {runtime.session.data_dir / 'sessions'}\n"
                f"Mode/Profile: {runtime.session.mode}/{runtime.profile.name}\n"
                "Safety: workspace trust allows bounded read context only."
            )
            continue
        if routed.name == "/tools":
            t = Table("Name", "Category", "Risk", "Description")
            for tool in sorted(registry.list_tools(), key=lambda x: x.name):
                t.add_row(tool.name, tool.category, tool.risk.value, tool.description)
            console.print(t)
            continue
        if routed.name == "research":
            with console.status("Searching local knowledge..."):
                hits = search_local(
                    runtime.settings.knowledge.local_paths + [str(Path.cwd() / "SHELLFORGE.md")],
                    routed.args,
                )
            if not hits:
                console.print(
                    f"No local knowledge hits for: {routed.args}\n"
                    "Suggestions:\n"
                    "- Add SHELLFORGE.md guidance in this workspace.\n"
                    "- Add local runbooks under configured knowledge paths.\n"
                    "- Use ask for model-backed general reasoning.\n"
                    "- Use diagnose nginx to collect live service evidence."
                )
            else:
                for h in hits[:5]:
                    console.print(f"{h.path}:{h.line} {h.snippet}")
            continue
        if routed.name in {"diagnose"}:
            with console.status("Collecting evidence..."):
                res = diagnose_target(runtime, routed.args, online=False, since="30m")
            checks = [
                {
                    "tool": i.source,
                    "status": str(i.metadata.get("status", "ok" if i.ok else "unavailable")),
                    "summary": i.summary,
                }
                for i in res.evidence.items
            ]
            console.print(f"Collected {len(checks)} read-only evidence item(s).")
            show_full = user_input.lower().startswith("diagnose ") or evidence_mode == "full"
            if show_full:
                _evidence_table(console, checks)
            else:
                console.print("Highlights:")
                for line in _evidence_highlights(checks):
                    console.print(line)
            natural_language_diagnose = not user_input.lower().startswith("diagnose ")
            with console.status("Building findings..."):
                pass
            with console.status("Writing artifacts..."):
                _ensure_artifact_dir(runtime)
                ep = runtime.session.artifact_dir / "evidence.json"
                ep.write_text(res.evidence.model_dump_json(indent=2), encoding="utf-8")
                pp = runtime.session.artifact_dir / "plan.json"
                pp.write_text(res.proposed_plan.model_dump_json(indent=2), encoding="utf-8")
                sp = runtime.session.artifact_dir / "summary.md"
                sp.write_text(
                    f"Session: {res.session_id}\n"
                    f"Target: {routed.args}\n"
                    f"Type: {res.target_type.value}\n"
                    f"Mode: {runtime.session.mode}\n"
                    f"Profile: {runtime.profile.name}\n"
                    "Collectors:\n"
                    + "\n".join([f"- {c['tool']}: {c['status']} ({c['summary']})" for c in checks])
                    + "\nDeterministic findings:\n"
                    + "\n".join([f"- {f.title}" for f in res.findings])
                    + (
                        f"\nArtifacts:\n- evidence: {ep}\n"
                        f"- plan: {pp}\n- summary: {sp}\n"
                        "Safety: apply remains validation-only."
                    ),
                    encoding="utf-8",
                )
            console.print(
                f"Diagnose {routed.args}\n"
                f"Session: {res.session_id}\nTarget: {routed.args}\n"
                f"Type: {res.target_type.value}\n"
                f"Evidence: {len(res.evidence.items)} item(s)\n"
                f"Findings: {len(res.findings)}\n"
                f"Artifacts:\n- evidence: {ep}\n- plan: {pp}\n- summary: {sp}"
            )
            if natural_language_diagnose:
                pending_followup = None
                pending_followup = select_followup_investigation(routed.args, checks, user_input)
                if pending_followup:
                    pending_followup["created_from_session"] = runtime.session.session_id
                    pending_followup["created_from_question"] = user_input
                    pending_followup["created_from_intent"] = routed.args
                provider_error = None
                try:
                    provider = build_provider(runtime.settings)
                    prompt = build_contextual_prompt(
                        user_input,
                        {
                            "intent": routed.args,
                            "evidence_label": f"{routed.args} evidence",
                            "evidence": checks,
                            "findings": [f.model_dump() for f in res.findings],
                            "artifacts": {"evidence": str(ep), "plan": str(pp), "summary": str(sp)},
                        },
                        mode="standard",
                    )
                    mresp_text, mresp_streamed = _run_model_synthesis(
                        console,
                        provider,
                        ModelRequest(
                            prompt=prompt,
                            model=runtime.settings.model.model,
                            provider=runtime.settings.model.provider,
                            timeout_seconds=runtime.settings.model.timeout_seconds,
                            metadata={"command_kind": "diagnose", "intent": routed.args},
                        ),
                        raw=False,
                    )
                    (runtime.session.artifact_dir / "model-response.md").write_text(
                        mresp_text, encoding="utf-8"
                    )
                    console.print("\n## Assessment")
                    if (
                        not _has_substantive_response(mresp_text)
                    ) or _contains_internal_collector_language(mresp_text):
                        console.print(_deterministic_operator_summary(routed.args, checks))
                    elif not mresp_streamed:
                        renderer.render(_sanitize_provider_error(mresp_text), None)
                    if pending_followup and pending_followup["intent"] not in completed_followups:
                        console.print(
                            _operator_followup_text(
                                pending_followup["label"], pending_followup["description"]
                            )
                        )
                    elif not pending_followup and (
                        routed.args == "disk"
                        and any(
                            k in user_input.lower()
                            for k in ("disk full", "disk getting full", "running out of space")
                        )
                    ):
                        console.print(
                            "Disk capacity looks healthy from this context. I don’t see a "
                            "disk-capacity reason to dig deeper. If the concern is slowness "
                            "rather than fullness, I can investigate performance/I/O next."
                        )
                except Exception as exc:
                    provider_error = str(exc)
                if provider_error:
                    console.print(
                        _deterministic_operator_summary(routed.args, checks)
                        + "\n## Artifacts\n"
                        + f"- evidence: {ep}\n- plan: {pp}\n- summary: {sp}\n"
                        + (
                            "\nNote: model synthesis unavailable "
                            f"({_sanitize_provider_error(provider_error)})."
                        )
                    )
                if (not pending_followup) and "proceed?" in mresp_text.lower():
                    console.print(
                        "I do not see a specific deeper read-only investigation to queue "
                        "from this evidence."
                    )
            continue
        if routed.name in {"plan", "/plan"}:
            with console.status("Building plan..."):
                t = classify_target(routed.args).value
                p = Plan(
                    plan_id=f"plan_{runtime.session.session_id}",
                    goal=routed.args,
                    session_id=runtime.session.session_id,
                    steps=[
                        PlanStep(
                            step_id="1",
                            title="Collect evidence",
                            description=f"Use diagnose for {t}",
                        ),
                        PlanStep(
                            step_id="2",
                            title="Review findings",
                            description="Review evidence and prioritize safe checks",
                        ),
                    ],
                )
            with console.status("Writing plan artifact..."):
                _ensure_artifact_dir(runtime)
                pp = runtime.session.artifact_dir / "plan.json"
                pp.write_text(p.model_dump_json(indent=2), encoding="utf-8")
                (runtime.session.artifact_dir / "summary.md").write_text(
                    f"Session: {runtime.session.session_id}\n"
                    f"Goal: {routed.args}\nPlan: {pp}\n"
                    "Safety: apply remains validation-only.",
                    encoding="utf-8",
                )
            console.print(
                f"Plan created\nGoal: {routed.args}\nRisk: read\n"
                f"Steps: {len(p.steps)}\nPlan: {pp}\n"
                "Apply: validation-only in this alpha"
            )
            continue

        if user_input.startswith("/"):
            console.print(f"Unknown command: {routed.name}")
            console.print("Type /help for available commands.")
            continue
        if _is_firewall_question(user_input):
            paste_guard_active = False
            with console.status("Collecting firewall evidence..."):
                res = diagnose_target(runtime, "firewall", online=False, since="30m")
            checks = [
                {
                    "tool": i.source,
                    "status": str(i.metadata.get("status", "ok" if i.ok else "unavailable")),
                    "summary": i.summary,
                }
                for i in res.evidence.items
            ]
            console.print(f"Collected {len(checks)} read-only evidence item(s).")
            show_full = user_input.lower().startswith("diagnose ") or evidence_mode == "full"
            if show_full:
                _evidence_table(console, checks)
            else:
                console.print("Highlights:")
                for line in _evidence_highlights(checks):
                    console.print(line)
            missing = [
                c
                for c in checks
                if c["tool"].startswith("command.exists") and c["status"] == "not_found"
            ]
            if len(missing) >= 5:
                console.print(
                    "Firewall summary:\n"
                    "ShellForgeAI checked common firewall tools in this environment and "
                    "none were found. Firewall state cannot be confirmed from this "
                    "container context. Run ShellForgeAI from the host context to "
                    "inspect host firewall state."
                )
            continue

        is_explicit_ask = routed.name == "ask" and routed.args.lower().startswith(
            ("explain this command:", "review this shell snippet:", "what does this command do?")
        )
        raw_for_guard = routed.args if routed.name == "ask" else user_input
        shell_like = is_multiline_shell_fragment(raw_for_guard) or looks_like_shell_command(
            raw_for_guard
        )
        if paste_guard_active and not is_explicit_ask:
            if shell_like or is_shell_fragment_line(raw_for_guard):
                if not paste_guard_first_notice:
                    console.print("""Multiline shell paste detected.

ShellForgeAI interactive mode does not execute shell snippets.

Run it in your shell, or ask me to review it with:

ask review this shell snippet: ...

No command was executed.""")
                    paste_guard_first_notice = True
                else:
                    console.print("Blocked shell paste fragment. No command was executed.")
                paste_guard_remaining_lines -= 1
                if raw_for_guard.strip().lower() in {"done", "fi", "esac", "'"}:
                    paste_guard_active = False
                if paste_guard_remaining_lines <= 0:
                    paste_guard_active = False
                continue
            paste_guard_non_shell_lines += 1
            if paste_guard_non_shell_lines >= 3:
                paste_guard_active = False
            else:
                paste_guard_remaining_lines -= 1
                if paste_guard_remaining_lines <= 0:
                    paste_guard_active = False
        if not is_explicit_ask and shell_like:
            paste_guard_active = True
            paste_guard_remaining_lines = 20
            paste_guard_non_shell_lines = 0
            paste_guard_first_notice = False
            console.print("""Multiline shell paste detected.

ShellForgeAI interactive mode does not execute shell snippets.

Run it in your shell, or ask me to review it with:

ask review this shell snippet: ...

No command was executed.""")
            paste_guard_first_notice = True
            continue
        if not is_explicit_ask and is_shell_fragment_line(raw_for_guard):
            console.print(
                "This looks like a shell command pasted into ShellForgeAI interactive mode.\n\n"
                "ShellForgeAI is not a shell and will not execute it.\n\n"
                "Run this in your host/container shell instead, or ask ShellForgeAI to "
                "explain/review it with:\n\nask explain this command: <command>\n\n"
                "No command was executed."
            )
            continue

        if user_input.strip().lower() in {"what did you check?", "what did you check"}:
            console.print(
                "I checked host/resources, storage, network, and process signals "
                "in read-only mode.\n"
                "Technical details are in artifacts (evidence.json / summary.md)."
            )
            continue
        provider = build_provider(runtime.settings)
        kind = "ask"
        context = {
            "host": platform.platform(),
            "mode": runtime.session.mode,
            "workspace_trusted": True,
        }
        if _is_machine_health_question(user_input):
            with console.status("Collecting evidence..."):
                checks = _collect_machine_health()
            console.print(f"Collected {len(checks)} read-only evidence item(s).")
            show_full = user_input.lower().startswith("diagnose ") or evidence_mode == "full"
            if show_full:
                _evidence_table(console, checks)
            else:
                console.print("Highlights:")
                for line in _evidence_highlights(checks):
                    console.print(line)
            context["machine_health"] = checks
            context["evidence_label"] = "general health evidence"
            kind = "diagnose"
        with console.status("Preparing context..."):
            prompt = build_contextual_prompt(
                user_input if routed.name != "ask" else routed.args, context, mode="standard"
            )
        try:
            resp_text, resp_streamed = _run_model_synthesis(
                console,
                provider,
                ModelRequest(
                    prompt=prompt,
                    model=runtime.settings.model.model,
                    provider=runtime.settings.model.provider,
                    timeout_seconds=runtime.settings.model.timeout_seconds,
                    metadata={
                        "command_kind": kind,
                        "profile": runtime.profile.name,
                        "mode": runtime.session.mode,
                    },
                ),
                raw=False,
            )
        except Exception as exc:
            console.print(_sanitize_provider_error(str(exc)))
            continue
        with console.status("Writing artifacts..."):
            _ensure_artifact_dir(runtime)
            (runtime.session.artifact_dir / "model-response.md").write_text(
                resp_text, encoding="utf-8"
            )
        if not _has_substantive_response(resp_text) and kind == "diagnose":
            console.print(
                _deterministic_operator_summary("health", context.get("machine_health", []))
            )
        elif not _has_substantive_response(resp_text):
            console.print(
                "ShellForgeAI did not produce a response for that input. No action was taken."
            )
        elif not resp_streamed:
            renderer.render(_sanitize_provider_error(resp_text), None)
