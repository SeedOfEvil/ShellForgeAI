from __future__ import annotations

import json
import os
import platform
import re
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from shellforgeai.audit.storage import AuditStorage
from shellforgeai.core.collectors import (
    LINUX_ONLY_COLLECTOR_SKIP_STATUS,
    WINDOWS_METRIC_UNAVAILABLE_STATUS,
    WINDOWS_PERFORMANCE_NEXT_SAFE_COMMANDS,
    parse_collector_payload,
)
from shellforgeai.core.collectors import _to_item as _evidence_item_from_result
from shellforgeai.core.context import RuntimeContext
from shellforgeai.core.diagnose import diagnose_target, findings_summary_line
from shellforgeai.core.evidence import EvidenceCategory, classify_target
from shellforgeai.core.followup_grounding import (
    FollowupGroundingState,
    render_grounded_resolution,
    resolve_followup_reference,
    update_grounding_from_latest_context,
    update_grounding_from_ops_report_text,
    update_grounding_from_triage_detail_text,
)
from shellforgeai.core.intent_nuance import (
    AMBIGUOUS_EXECUTE,
    CLEANUP_REVIEW_HELP,
    COMMAND_HELP,
    MUTATION_REQUEST,
    PLAN_HELP,
    classify_intent_nuance,
    render_intent_nuance,
)
from shellforgeai.core.latest_context import (
    LatestDiagnosisContext,
    answer_from_latest_context,
    build_latest_diagnosis_context,
    detect_latest_context_intent,
    is_mutation_followup,
    no_latest_context_reply,
    render_latest_context_pending,
)
from shellforgeai.core.plans import Plan, PlanStep
from shellforgeai.interactive.banner import build_banner
from shellforgeai.knowledge.search import search_local
from shellforgeai.llm.codex import CodexProvider, classify_model_failure
from shellforgeai.llm.manager import build_provider
from shellforgeai.llm.prompts import build_contextual_prompt
from shellforgeai.llm.schemas import ModelRequest
from shellforgeai.render.summary import write_diagnosis_summary_md
from shellforgeai.tools import disk, host, network, process, registry, storage, systemd
from shellforgeai.version import get_build_info

from .commands import route_input
from .guards import is_multiline_shell_fragment, is_shell_fragment_line, looks_like_shell_command
from .streaming import StreamRenderer
from .workspace import WorkspaceTrustStore

_REFUSED_DOCKER_RESTART = "docker" + " restart <container>"
_REFUSED_COMPOSE_RESTART = "docker compose" + " restart <service>"
_REFUSED_CLEANUP_EXECUTE = "cleanup" + " execute"
_REFUSED_REMEDIATION_EXECUTE = "remediation" + " execute --confirm"
_REFUSED_ROLLBACK_EXECUTE = "rollback-" + "execute --confirm"

INTERACTIVE_HELP_TEXT = f"""ShellForgeAI interactive help

Session:
  help / /help / ? / commands
  pending / /pending / summary / /summary / summary --json / exit / /exit

Fast status:
  status [--brief|--json]
  ops report / ops report --brief / ops report --json
  v1 check quick / v1 check --profile quick --json
  doctor / model doctor
V2 golden path:
  status / triage / propose [--brief|--json]
  recipes [--json] / recipes inspect <id> / safe-actions [--target <target>]
  recipes eligibility --recipe docker.disposable_restart --target <target>
  recipes preflight --recipe docker.disposable_restart --target <target> [--json|--save]
  recipes preflight validate <id> / recipes execute <id> --confirm [--json]
  recipes receipt validate <id> [--json] / recipes receipt verify <id> [--json]
  recipes receipt explain/integrity/audit/history/inspect/export/export-validate/compare [--json]
  recipes receipt rollback-preview <id> / recovery-execute <id> --confirm / recovery-status <id>
  apply-preview [--brief|--json] / verify [--brief|--json]
  verify --receipt <id> [--json] / handoff [--brief|--json|--save]
  triage/propose/verify/handoff --target <target> [--json] / handoff summary
  full path: status -> triage -> propose -> apply-preview -> verify -> handoff

Triage/detail:
  triage [--brief|--json] / triage --target <target>
  triage docker [--brief|--json]
  triage docker detail <target> --json
  diagnose <target>

Reports/artifacts:
  ops report --save
  ops report history --limit 5
  ops report compare-latest [--json]
  handoff --save / handoff validate / handoff export / handoff export-validate
  handoff history / handoff compare / handoff compare-latest

V1/readiness:
  remediation self-test quick / remediation self-test --profile quick --json
  remediation eligibility --target <target> --explain
  remediation eligibility --target <target> --explain --json
Follow-ups/session:
  /summary
  what happened in this session?
  what did you find? / get that info / dig deeper / proceed
  pending / /pending
  exit / /exit

Pressure mode: no novel, what is on fire? / quick status only

Refused here (not run):
  {_REFUSED_DOCKER_RESTART}
  {_REFUSED_COMPOSE_RESTART}
  {_REFUSED_CLEANUP_EXECUTE}
  {_REFUSED_REMEDIATION_EXECUTE}
  {_REFUSED_ROLLBACK_EXECUTE}
  rm -rf /

Safety:
  Interactive mode is not a shell.
  No Docker/Compose/remediation/cleanup command runs from natural language.
  Mutation requires governed explicit workflows. Natural language cannot execute recipes."""


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
            "is my computer having any issue",
            "is everything okay with my computer",
            "so is everything okay with my computer",
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


_SAFE_DEFAULT_DNS_DOMAIN = "example.com"


def _extract_reachability_target(text: str) -> tuple[str, int] | None:
    low = text.lower()
    m = re.search(r"([a-z0-9][a-z0-9\.\-]*\.[a-z0-9\.\-]+):(\d{1,5})", low)
    if m:
        return m.group(1), int(m.group(2))
    m2 = re.search(r"port\s+(\d{1,5})\s+(?:on|to|at|of|for)\s+([a-z0-9][a-z0-9\.\-]+)", low)
    if m2:
        return m2.group(2), int(m2.group(1))
    m3 = re.search(
        r"(?:reach|conenct|connect|reachable|test|tcp\s*connect)[a-z\s]*?"
        r"\s([a-z0-9][a-z0-9\.\-]*\.[a-z0-9\.\-]+)\s+(\d{1,5})",
        low,
    )
    if m3:
        return m3.group(1), int(m3.group(2))
    m4 = re.search(r"([a-z0-9][a-z0-9\.\-]*\.[a-z0-9\.\-]+)\s+(?:port\s+)?(\d{1,5})\b", low)
    if m4:
        return m4.group(1), int(m4.group(2))
    return None


def _extract_port_target(text: str) -> int | None:
    low = text.lower()
    m = re.search(r"port\s+(\d{1,5})", low)
    if m:
        return int(m.group(1))
    m2 = re.search(r":(\d{1,5})\b", low)
    if m2:
        return int(m2.group(1))
    return None


def _extract_dns_target(text: str) -> str | None:
    low = text.lower()
    for pat in (
        r"(?:dns|resolve|resolution|lookup|dig|nslookup)\s+(?:for|of|on)?\s*"
        r"([a-z0-9][a-z0-9\.\-]*\.[a-z0-9\.\-]+)",
        r"(?:dns|resolve|resolution|lookup)\s+([a-z0-9][a-z0-9\.\-]*\.[a-z0-9\.\-]+)",
        r"check\s+dns\s+for\s+([a-z0-9][a-z0-9\.\-]*\.[a-z0-9\.\-]+)",
    ):
        m = re.search(pat, low)
        if m:
            return m.group(1)
    return None


def _detect_network_subtype(text: str) -> str:
    low = text.lower()
    if "open port" in low or "allow port" in low or "publish port" in low:
        return "port-open"
    if "dns" in low or "resolve" in low or "resolution" in low or "nslookup" in low:
        return "dns"
    if (
        "firewall" in low
        or "firwall" in low
        or "iptables" in low
        or "nftables" in low
        or "ufw" in low
    ):
        return "firewall"
    if (
        "reach" in low
        or "reachable" in low
        or "connect to" in low
        or "conenct to" in low
        or "test port" in low
        or "tcp connect" in low
    ):
        return "reachability"
    if "is port" in low or "port " in low or "listening" in low or "listerning" in low:
        return "listener"
    return "connectivity"


def _network_subtype_label(subtype: str) -> str:
    return {
        "reachability": "network reachability",
        "port-open": "network port-open",
        "dns": "network DNS",
        "listener": "network listener",
        "firewall": "network firewall",
        "connectivity": "network/DNS",
    }.get(subtype, "network/DNS")


def _network_followup_description(subtype: str) -> str:
    return {
        "reachability": (
            "namespace context, default route, DNS, target resolution, and bounded TCP connect"
        ),
        "port-open": (
            "listener inventory, listener ownership, firewall context, and container/route view"
        ),
        "dns": "DNS resolver config, target resolution test, default route, and namespace context",
        "listener": "listener inventory, ownership, and container/firewall context",
        "firewall": "firewall tooling visibility, container context, and listener view",
        "connectivity": (
            "routes, DNS, listeners, firewall context, and bounded target reachability"
        ),
    }.get(subtype, "routes, DNS, listeners, firewall context, and bounded target reachability")


def _pending_target_phrase(p: dict[str, Any]) -> str | None:
    host_t = p.get("target_host")
    port_t = p.get("target_port")
    dom_t = p.get("target_domain")
    if host_t and port_t:
        return f"{host_t}:{port_t}"
    if host_t:
        return str(host_t)
    if dom_t:
        return str(dom_t)
    if port_t:
        return f"port {port_t}"
    return None


def _model_dump_json_safe(value: Any, *, indent: int = 2) -> str:
    dumper = getattr(value, "model_dump_json", None)
    if callable(dumper):
        return str(dumper(indent=indent))
    return "{}"


def _model_dump_safe(value: Any) -> dict[str, Any]:
    dumper = getattr(value, "model_dump", None)
    if callable(dumper):
        dumped = dumper()
        return dumped if isinstance(dumped, dict) else {}
    return {}


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


def _is_windows_platform_checks(checks: list[dict[str, str]]) -> bool:
    return any(
        c.get("tool") == "platform.detect" and "windows" in c.get("summary", "").lower()
        for c in checks
    )


def _windows_evidence_highlights(checks: list[dict[str, str]]) -> list[str]:
    out = []
    unavailable = [c for c in checks if c.get("status") == WINDOWS_METRIC_UNAVAILABLE_STATUS]
    for c in checks:
        if c.get("tool", "").startswith(("platform.", "windows.")) and c not in unavailable:
            out.append(f"- {c.get('summary', 'unavailable')}.")
    for c in unavailable[:3]:
        out.append(f"- {c.get('summary', 'metric unavailable on Windows')}.")
    skipped = sum(1 for c in checks if c.get("status") == LINUX_ONLY_COLLECTOR_SKIP_STATUS)
    if skipped:
        out.append(f"- Linux-only collectors skipped on Windows: {skipped} (not applicable).")
    return out[:7]


def _evidence_highlights(checks: list[dict[str, str]]) -> list[str]:
    if _is_windows_platform_checks(checks):
        return _windows_evidence_highlights(checks)
    by_tool = {c["tool"]: c for c in checks}
    out = []
    if "system.cpu_memory" in by_tool:
        out.append(f"- CPU/memory: {_human_cpu_mem(by_tool['system.cpu_memory']['summary'])}.")
    if "host.resources" in by_tool:
        out.append(f"- Load: {_human_load(by_tool['host.resources']['summary'])}.")
    if "disk.usage" in by_tool or "disk.inodes" in by_tool:
        disk_sum = by_tool.get("disk.usage", {}).get("summary", "unknown")
        inode_sum = by_tool.get("disk.inodes", {}).get("summary", "unknown")
        out.append(f"- Disk/inodes: {disk_sum}; {inode_sum}.")
    if "storage.pressure" in by_tool:
        out.append(
            f"- Storage/I/O: {_human_storage_pressure(by_tool['storage.pressure']['summary'])}."
        )
    if "system.container_detect" in by_tool:
        out.append(f"- Context: {_human_container(by_tool['system.container_detect']['summary'])}.")
    if "process.top" in by_tool:
        out.append(f"- Process: {by_tool['process.top']['summary']}.")
    return out[:7]


def _human_load(raw: str) -> str:
    nums = re.findall(r"\d+\.\d+|\d+", raw)
    if len(nums) >= 3:
        a, b, c = [float(n) for n in nums[:3]]
        return f"{a:.2f} / {b:.2f} / {c:.2f}"
    return "unavailable from this context"


def _human_container(raw: str) -> str:
    low = raw.lower()
    if "docker" in low:
        return "Docker/container view"
    if "container=no" in low:
        return "container=no"
    return "container=unknown"


def _human_cpu_mem(raw: str) -> str:
    m = re.search(r"cpus=(\d+).*mem=(\d+\.\d+)GiB/(\d+\.\d+)GiB.*swap=([^ ]+)", raw)
    if not m:
        return raw
    cpus, used, total, swap = m.groups()
    swap_txt = "swap unused" if swap.startswith("0B/") else f"{swap} swap used"
    return f"{cpus} CPUs visible, {used} GiB / {total} GiB used, {swap_txt}"


def _human_storage_pressure(raw: str) -> str:
    vals = _parse_storage_pressure(raw)
    if not vals:
        return "no pressure reported" if "unavailable" not in raw.lower() else raw
    a10, a60, a300 = vals
    if a10 == 0 and a60 == 0 and a300 == 0:
        return "no pressure reported"
    return f"non-zero pressure, avg10 {a10:g} / avg60 {a60:g} / avg300 {a300:g}"


def _parse_storage_pressure(raw: str) -> tuple[float, float, float] | None:
    vals = dict(
        re.findall(
            r"(io_some_avg10|io_some_avg60|io_some_avg300|avg10|avg60|avg300)=([0-9.]+)", raw
        )
    )
    a10 = vals.get("avg10") or vals.get("io_some_avg10")
    a60 = vals.get("avg60") or vals.get("io_some_avg60")
    a300 = vals.get("avg300") or vals.get("io_some_avg300")
    if a10 is None or a60 is None or a300 is None:
        return None
    return (float(a10), float(a60), float(a300))


def _parse_load_values(raw: str) -> tuple[float, float, float] | None:
    nums = re.findall(r"\d+\.\d+|\d+", raw)
    if len(nums) < 3:
        return None
    return (float(nums[0]), float(nums[1]), float(nums[2]))


def _parse_cpu_mem(raw: str) -> dict[str, Any] | None:
    m = re.search(r"cpus=(\d+).*mem=(\d+\.\d+)GiB/(\d+\.\d+)GiB.*swap=([^ ]+)", raw)
    if not m:
        return None
    cpus, used, total, swap = m.groups()
    return {
        "cpus": int(cpus),
        "mem_used_gib": float(used),
        "mem_total_gib": float(total),
        "swap_unused": swap.startswith("0B/"),
        "swap_raw": swap,
    }


def _parse_disk_pct(raw: str) -> int:
    pcts = [int(n) for n in re.findall(r"(\d+)%", raw)]
    return max(pcts) if pcts else 0


def _is_container_context(raw: str) -> bool:
    return "docker" in raw.lower() or "overlay" in raw.lower() or "container=yes" in raw.lower()


def _summarize_facts(checks: list[dict[str, str]]) -> dict[str, Any]:
    by_tool = {c["tool"]: c.get("summary", "") for c in checks}
    facts: dict[str, Any] = {}
    if "host.resources" in by_tool:
        facts["load"] = _parse_load_values(by_tool["host.resources"])
    if "system.cpu_memory" in by_tool:
        facts["cpu_mem"] = _parse_cpu_mem(by_tool["system.cpu_memory"])
    if "disk.usage" in by_tool:
        facts["disk_pct"] = _parse_disk_pct(by_tool["disk.usage"])
        facts["disk_summary"] = by_tool["disk.usage"]
    if "disk.inodes" in by_tool:
        facts["inode_pct"] = _parse_disk_pct(by_tool["disk.inodes"])
        facts["inode_summary"] = by_tool["disk.inodes"]
    if "storage.pressure" in by_tool:
        facts["storage_pressure"] = _parse_storage_pressure(by_tool["storage.pressure"])
        facts["storage_pressure_raw"] = by_tool["storage.pressure"]
    if "system.container_detect" in by_tool:
        facts["container"] = _is_container_context(by_tool["system.container_detect"])
        facts["container_label"] = _human_container(by_tool["system.container_detect"])
    if "process.top" in by_tool:
        facts["top_process"] = by_tool["process.top"]
    if "storage.error_summary" in by_tool:
        facts["storage_errors"] = by_tool["storage.error_summary"]
    return facts


def _run_model_synthesis(
    console: Console, provider, request: ModelRequest, raw: bool
) -> tuple[str, bool]:
    streaming_enabled = os.getenv("SHELLFORGEAI_EXPERIMENTAL_STREAMING", "0") == "1"
    final_text = ""
    if (streaming_enabled or not hasattr(provider, "complete")) and hasattr(
        provider, "stream_complete"
    ):
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
    if not getattr(resp, "ok", True):
        raw = getattr(resp, "raw", None) or {}
        failure = classify_model_failure(
            stdout=str(raw.get("stdout_jsonl") or raw.get("stdout") or getattr(resp, "text", "")),
            stderr=str(raw.get("stderr") or getattr(resp, "error", "") or ""),
        )
        clean = str(failure["user_message"])
        next_step = str(failure.get("next_step") or "")
        if next_step:
            clean = f"{clean} Next step: {next_step}."
        return clean, False
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


def _confirm_workspace(
    console: Console,
    runtime: RuntimeContext,
    no_trust_cache: bool,
    yes_trust: bool = False,
) -> bool:
    """Establish interactive workspace trust without eating the first command.

    Trust here only gates the interactive workspace confirmation; it never grants
    shell execution, mutation, remediation, cleanup, rollback, or Docker/Compose
    mutation powers. Those remain refused regardless of trust state.

    Resolution order:
      1. Already-trusted workspaces proceed straight to the command loop (no prompt),
         so a scripted first command such as ``doctor`` is never consumed as a trust
         response.
      2. ``--yes-trust`` trusts the current workspace for this session and proceeds
         directly to command input.
      3. Otherwise prompt once. Only ``y``/``yes`` grant trust; ``n``/``no``/empty
         decline safely. Any other input is treated as an invalid trust response: it
         is never executed as a command and never silently discarded -- the user gets
         clear guidance and is reprompted.
    """
    store = WorkspaceTrustStore(runtime.session.data_dir)
    workspace = Path.cwd()
    already_trusted = (not no_trust_cache) and store.is_trusted(workspace)

    if already_trusted:
        console.print(f"Workspace already trusted: {workspace}\nCommands accepted.")
        return True

    if yes_trust:
        if not no_trust_cache:
            store.trust(workspace, get_build_info().version)
        console.print(
            f"Workspace trusted for this session: {workspace}\n"
            "Trust only gates the workspace prompt; mutation and shell execution stay refused."
        )
        return True

    console.print("Trust this workspace?\n")
    console.print(f"Path:\n  {workspace}\n")
    while True:
        try:
            answer = input("Trust this workspace for this session? [y/N] ").strip().lower()
        except EOFError:
            console.print("Workspace not trusted. Exiting interactive mode.")
            return False
        if answer in {"y", "yes"}:
            if not no_trust_cache:
                store.trust(workspace, get_build_info().version)
            return True
        if answer in {"", "n", "no"}:
            console.print("Workspace not trusted. Exiting interactive mode.")
            return False
        console.print("Please answer y or n. Commands are accepted after trust is set.")


def _summary_for_check(c) -> str:
    first = (c.stderr or c.stdout or "").splitlines()[0] if (c.stderr or c.stdout) else ""
    if c.tool == "host.info" and "hostname" in c.stdout:
        payload = parse_collector_payload(c.stdout, default=None)
        if not isinstance(payload, dict):
            payload = {}
        return (
            f"hostname={payload.get('hostname') or 'unknown'} "
            f"kernel={payload.get('kernel') or 'unknown'} "
            f"arch={payload.get('arch') or 'unknown'}"
        )
    if c.tool == "host.resources":
        human = _human_load(c.stdout or c.stderr or first)
        if "unavailable" in human:
            return "load average unavailable from this collector"
        return f"loadavg={human.replace(' / ', ',')}"
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
        return first or "process details unavailable from this context"
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


def _format_load(load: tuple[float, float, float] | None) -> str:
    if not load:
        return "unavailable from this context"
    return f"{load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}"


def _format_storage_pressure(sp: tuple[float, float, float] | None) -> str:
    if sp is None:
        return "unavailable from this context"
    a10, a60, a300 = sp
    if a10 == 0 and a60 == 0 and a300 == 0:
        return "no pressure reported"
    return f"non-zero pressure (avg10 {a10:g} / avg60 {a60:g} / avg300 {a300:g})"


def _format_cpu_mem(cpu_mem: dict[str, Any] | None) -> str:
    if not cpu_mem:
        return "unavailable from this context"
    swap_txt = "swap unused" if cpu_mem.get("swap_unused") else "swap in use"
    return (
        f"{cpu_mem['cpus']} CPUs visible, "
        f"{cpu_mem['mem_used_gib']:.1f} GiB / {cpu_mem['mem_total_gib']:.1f} GiB used, "
        f"{swap_txt}"
    )


def _format_disk(facts: dict[str, Any]) -> str:
    summary = facts.get("disk_summary", "")
    return str(summary) if summary else "unavailable from this context"


def _format_inode(facts: dict[str, Any]) -> str:
    summary = facts.get("inode_summary", "")
    return str(summary) if summary else "unavailable from this context"


def _compare_storage_pressure(
    before: tuple[float, float, float] | None,
    after: tuple[float, float, float] | None,
) -> str:
    if before is None or after is None:
        if after is not None:
            return f"second pass: {_format_storage_pressure(after)}"
        return "storage pressure unavailable in either pass"
    if before == after:
        return f"unchanged ({_format_storage_pressure(after)})"
    return (
        f"first pass {_format_storage_pressure(before)}; "
        f"second pass {_format_storage_pressure(after)}"
    )


def _storage_io_deep_dive_synthesis(
    first_pass: list[dict[str, str]] | None, second_pass: list[dict[str, str]]
) -> str:
    f1 = _summarize_facts(first_pass or [])
    f2 = _summarize_facts(second_pass)
    sp1 = f1.get("storage_pressure")
    sp2 = f2.get("storage_pressure")
    load1 = f1.get("load")
    load2 = f2.get("load")
    cpus2 = (f2.get("cpu_mem") or {}).get("cpus") or 0
    if sp2 is None or all(v == 0 for v in sp2):
        if sp1 and any(v > 0 for v in sp1):
            assessment = (
                "The deeper pass weakens the first-pass storage/I/O suspicion: "
                "pressure is no longer non-zero."
            )
        else:
            assessment = (
                "The deeper pass did not strengthen the storage/I/O suspicion. "
                "No pressure reported in either pass."
            )
    elif sp1 and sp2 and sp2[0] > sp1[0]:
        assessment = "The deeper pass confirms and slightly strengthens the storage/I/O suspicion."
    else:
        assessment = (
            "The deeper pass confirms the first-pass storage/I/O suspicion at similar levels."
        )
    top_proc1 = (f1.get("top_process") or "").strip() or "unavailable"
    top_proc2 = (f2.get("top_process") or "").strip() or "unavailable"
    storage_errors = (f2.get("storage_errors") or "").strip()
    cpu_mem_line = _format_cpu_mem(f2.get("cpu_mem"))
    load_line = f"about {_format_load(load2)}" + (
        f", low for {cpus2} visible CPUs" if cpus2 and load2 and load2[0] < cpus2 else ""
    )
    swap_healthy = bool((f2.get("cpu_mem") or {}).get("swap_unused"))
    mem_healthy = (f2.get("cpu_mem") or {}).get("mem_total_gib", 0) > 0 and (
        (
            (f2["cpu_mem"]["mem_total_gib"] - f2["cpu_mem"]["mem_used_gib"])
            / f2["cpu_mem"]["mem_total_gib"]
        )
        > 0.15
    )
    disk_pct2 = f2.get("disk_pct", 0)
    inode_pct2 = f2.get("inode_pct", 0)
    disk_healthy = disk_pct2 < 80 and inode_pct2 < 80
    storage_errors_present = (
        bool(storage_errors) and "no recent storage error patterns" not in storage_errors.lower()
    )
    container_ctx = bool(f2.get("container"))
    blind_spot = (
        "Host-level backing-storage latency and per-process I/O attribution "
        "remain limited from inside this container."
        if container_ctx
        else "Host-level backing storage latency is partly opaque from this context."
    )
    likely_angle = (
        "Mild container storage/I/O pressure is the strongest remaining angle from this view."
        if container_ctx
        else "Storage/I/O pressure remains the strongest remaining angle from this view."
    )
    return (
        "## Assessment\n"
        f"{assessment}\n\n"
        "## What changed / deeper clues\n"
        f"- Storage pressure: {_compare_storage_pressure(sp1, sp2)}.\n"
        f"- Top CPU process: first pass {top_proc1}; second pass {top_proc2}.\n"
        f"- Load: first pass {_format_load(load1)}; second pass {load_line}.\n"
        f"- Memory/swap: still {'healthy' if mem_healthy and swap_healthy else 'noted'} "
        f"({cpu_mem_line}).\n"
        f"- Disk/inodes: still {'healthy' if disk_healthy else 'elevated'} "
        f"({_format_disk(f2)}; {_format_inode(f2)}).\n"
        f"- Storage errors: {('present — ' + storage_errors) if storage_errors_present else 'none in scanned logs'}.\n\n"  # noqa: E501
        "## Likely angle\n"
        f"{likely_angle}\n\n"
        "## Remaining blind spots\n"
        f"{blind_spot}\n\n"
        "## Safe conclusion\n"
        "No restart, cleanup, repair, install, delete, or service change is "
        "indicated by this evidence.\n"
        "The remaining blind spot is host-level backing-storage visibility "
        "outside this container.\n"
    )


def _windows_operator_summary(checks: list[dict[str, str]]) -> str:
    """Bounded Windows-aware read-only summary for slow-system/performance asks."""
    facts = []
    unavailable = [c for c in checks if c.get("status") == WINDOWS_METRIC_UNAVAILABLE_STATUS]
    skipped = [c for c in checks if c.get("status") == LINUX_ONLY_COLLECTOR_SKIP_STATUS]
    for c in checks:
        if c in unavailable:
            continue
        if c.get("tool", "").startswith(("platform.", "windows.")) or c.get("tool") == "host.info":
            facts.append(f"- {c.get('summary', 'unavailable')}.")
    limitations = [f"- {c.get('summary', 'metric unavailable on Windows')}." for c in unavailable]
    if skipped:
        skipped_names = ", ".join(c.get("tool", "collector") for c in skipped[:8])
        more = "" if len(skipped) <= 8 else f" (+{len(skipped) - 8} more)"
        limitations.append(
            f"- Linux-only collectors skipped on Windows (not applicable): {skipped_names}{more}."
        )
    next_commands = "\n".join(f"- {cmd}" for cmd in WINDOWS_PERFORMANCE_NEXT_SAFE_COMMANDS)
    return (
        "## Assessment\n"
        "Windows host: bounded read-only diagnostics completed. Linux-only collectors "
        "were skipped instead of executed, so their absence is expected and not a failure.\n\n"
        "## Facts found\n"
        + ("\n".join(facts) if facts else "- Windows platform evidence collected.")
        + "\n\n## Platform limitations\n"
        + (
            "\n".join(limitations)
            if limitations
            else "- No additional platform limitations recorded."
        )
        + "\n\n## Next safe read-only commands\n"
        + next_commands
        + "\n\n## Safety\n"
        "Read-only checks only. No shell or remoting execution, no service restart, "
        "no process termination, no cleanup, and no file changes were performed.\n"
    )


def _deterministic_operator_summary(
    intent: str, checks: list[dict[str, str]], target: str | None = None
) -> str:
    if _is_windows_platform_checks(checks):
        return _windows_operator_summary(checks)

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
    listeners_row = _find("network.listeners")
    iface_row = _find("network.interfaces")
    default_route_row = _find("network.default_route")
    dns_test_row = _find("network.resolution_test")
    ns_row = _find("network.namespace_context")
    fw_row = _find("network.firewall_context")
    listener_attr_row = _find("network.listener_attribution")
    tcp_row = _find("network.tcp_connect_test")
    manager_row = _find("service.manager_detect")
    if intent == "logs_deep_dive":
        common = _find("logs.common_paths")
        recent = _find("logs.recent_errors")
        auth = _find("logs.auth_errors")
        kern = _find("logs.kernel_errors")
        themes = _find("logs.error_themes")
        svc_errs = _find("logs.service_errors")
        docker_s = _find("docker.problem_summary")
        common_s = common["summary"] if common else "common log paths unavailable"
        recent_s = recent["summary"] if recent else "recent error scan unavailable"
        auth_s = auth["summary"] if auth else "auth scan unavailable"
        kern_s = kern["summary"] if kern else "kernel scan unavailable"
        themes_s = themes["summary"] if themes else "no theme summary"
        svc_line = f"- Service-specific log errors: {svc_errs['summary']}.\n" if svc_errs else ""
        docker_line = f"- Container problem summary: {docker_s['summary']}.\n" if docker_s else ""
        return (
            "## Assessment\n"
            "Deeper read-only log/error triage completed from current runtime view.\n\n"
            "## What I found\n"
            f"- Visible log sources: {common_s}.\n"
            f"- Recent error scan: {recent_s}.\n"
            f"- Auth log scan: {auth_s}.\n"
            f"- Kernel log scan: {kern_s}.\n"
            f"- Error themes: {themes_s}.\n"
            f"{svc_line}{docker_line}\n"
            "## Best read\n"
            "Visible logs were inspected with bounded reads only. Host-level journal/syslog "
            "may be outside this view if running inside a container.\n\n"
            "## Safety\n"
            "Read-only checks only. No log deletion, truncation, rotation, restart, or "
            "install actions were performed.\n"
        )
    if intent == "service_health_deep_dive":
        svc = (target or "service").lower()
        svc_proc = _find("service.processes")
        svc_ports = _find("service.ports")
        svc_cfg = _find("service.config_hints")
        svc_logs = _find("service.logs")
        mgr = manager_row["summary"] if manager_row else "service manager context unavailable"
        proc = svc_proc["summary"] if svc_proc else "process evidence unavailable"
        ports = svc_ports["summary"] if svc_ports else "listener evidence unavailable"
        cfg = svc_cfg["summary"] if svc_cfg else "config hints unavailable"
        logs = svc_logs["summary"] if svc_logs else "logs unavailable"
        return (
            "## Assessment\n"
            f"Deeper {svc} service check completed from current runtime view.\n\n"
            "## What I found\n"
            f"- Service manager context: {mgr}.\n"
            f"- {svc} process status: {proc}.\n"
            f"- {svc} listener status: {ports}.\n"
            f"- {svc} config hints: {cfg}.\n"
            f"- {svc} log visibility: {logs}.\n\n"
            "## Best read\n"
            "This remains a read-only container/runtime view. If the service is expected "
            "elsewhere, confirm host vs sibling-container ownership before restart decisions.\n\n"
            "## Safety\n"
            "Read-only checks only. No restart/reload/start/stop/install/delete "
            "actions were performed.\n"
        )
    if intent == "service_inventory_deep_dive":
        listener_line = "listener evidence unavailable"
        if listeners_row:
            lsum = listeners_row["summary"]
            if "ports=" in lsum:
                listener_line = f"listening ports: {lsum.split('ports=', 1)[-1].strip()}"
            elif "no listening sockets" in lsum.lower():
                listener_line = "no listeners found"
            else:
                listener_line = lsum
        mgr = manager_row["summary"] if manager_row else "service manager context unavailable"
        proc = process_row["summary"] if process_row else "process evidence unavailable"
        return (
            "## Assessment\n"
            "Deeper service inventory completed from current runtime view.\n\n"
            "## What I found\n"
            f"- Service manager context: {mgr}.\n"
            f"- Listener view: {listener_line}.\n"
            f"- Process view: {proc}.\n\n"
            "## Best read\n"
            "This reflects container-visible services/listeners only; "
            "host-level service managers may be out of scope here.\n\n"
            "## Safety\n"
            "Read-only checks only. No restart/reload/start/stop/install/delete "
            "actions were performed.\n"
        )
    if intent in {"network_dns_firewall_deep_dive", "network"}:
        interface_summary = iface_row["summary"] if iface_row else "interface view unavailable"
        route_summary = (
            default_route_row["summary"]
            if default_route_row
            else (route_row["summary"] if route_row else "default route unavailable")
        )
        dns_summary = dns_row["summary"] if dns_row else "dns config unavailable"
        dns_test_summary = (
            dns_test_row["summary"] if dns_test_row else "dns resolution test unavailable"
        )
        listener_summary = (
            listeners_row["summary"] if listeners_row else "listener view unavailable"
        )
        listener_attr = (
            listener_attr_row["summary"] if listener_attr_row else "listener ownership unavailable"
        )
        fw_summary = fw_row["summary"] if fw_row else "firewall context unavailable"
        ns_summary = ns_row["summary"] if ns_row else "namespace context unavailable"
        tcp_summary = f"- Target reachability: {tcp_row['summary']}.\n" if tcp_row else ""
        return (
            "## Assessment\n"
            "Deeper network check completed from this runtime context.\n\n"
            "## What I found\n"
            f"- Namespace/container context: {ns_summary}.\n"
            f"- Interfaces: {interface_summary}.\n"
            f"- Route/default gateway: {route_summary}.\n"
            f"- DNS resolver config: {dns_summary}.\n"
            f"- DNS resolution: {dns_test_summary}.\n"
            f"{tcp_summary}"
            f"- Listeners: {listener_summary}.\n"
            f"- Listener ownership: {listener_attr}.\n"
            f"- Firewall context: {fw_summary}.\n\n"
            "## Best read\n"
            "Network basics are evaluated from this container/runtime view; "
            "host firewall and host routing may differ.\n\n"
            "## Safety\n"
            "Read-only checks only. No firewall/route/interface/service changes were performed.\n"
        )
    if os_row:
        facts.append(f"- Host context: {os_row['summary']}.")
    if cpu_mem_row:
        facts.append(f"- CPU/memory: {_human_cpu_mem(cpu_mem_row['summary'])}.")
    if load_row:
        facts.append(f"- Load: about {_human_load(load_row['summary'])}.")
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
        clues.append(f"- Low confidence: load snapshot is {_human_load(load_row['summary'])}.")
    if inode_row and "% used" in inode_row["summary"]:
        clues.append(f"- Medium confidence: inode usage snapshot is {inode_row['summary']}.")
    if intent == "storage_io_deep_dive":
        return _storage_io_deep_dive_synthesis(None, checks)
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
        + (
            "\n\n## What I can check next\n"
            "- The remaining blind spot is host-level storage visibility "
            "outside this container.\n\n"
            if intent == "storage_io_deep_dive"
            else "\n\n"
        )
        + "## Safety\n"
        + "Next steps are read-only. No restart, install, cleanup, or file changes.\n"
    )


def _findings_to_strings(findings: list) -> list[str]:
    out: list[str] = []
    for f in findings or []:
        title = getattr(f, "title", None)
        if title:
            out.append(str(title))
    return out


def _checks_from_results(results: list) -> list[dict[str, str]]:
    items = [_evidence_item_from_result(r, EvidenceCategory.network, r.tool) for r in results]
    return [
        {
            "tool": i.source,
            "status": str(i.metadata.get("status", "ok" if i.ok else "unavailable")),
            "summary": i.summary,
        }
        for i in items
    ]


def _run_network_followup(
    pending: dict[str, Any],
) -> tuple[list[dict[str, str]], str]:
    subtype = pending.get("subtype", "connectivity")
    host_t = pending.get("target_host")
    port_t = pending.get("target_port")
    domain_t = pending.get("target_domain")
    results: list = []
    if subtype == "reachability":
        results.append(network.namespace_context())
        results.append(network.default_route())
        results.append(network.dns())
        if host_t:
            results.append(network.resolution_test(host_t))
            if port_t:
                results.append(network.tcp_connect_test(host_t, int(port_t)))
        results.append(network.firewall_context())
    elif subtype == "port-open" or subtype == "listener":
        results.append(network.listeners())
        results.append(network.listener_attribution())
        results.append(network.firewall_context())
        results.append(network.namespace_context())
        results.append(network.default_route())
    elif subtype == "dns":
        target = domain_t or host_t or _SAFE_DEFAULT_DNS_DOMAIN
        results.append(network.dns())
        results.append(network.resolution_test(target))
        results.append(network.default_route())
        results.append(network.namespace_context())
        results.append(network.firewall_context())
    elif subtype == "firewall":
        results.append(network.firewall_context())
        results.append(network.namespace_context())
        results.append(network.listeners())
        results.append(network.default_route())
    else:
        results.append(network.namespace_context())
        results.append(network.interfaces())
        results.append(network.default_route())
        results.append(network.dns())
        results.append(network.listeners())
        results.append(network.firewall_context())
    checks = _checks_from_results(results)
    text = _network_followup_synthesis(pending, checks)
    return checks, text


def _network_followup_synthesis(pending: dict[str, Any], checks: list[dict[str, str]]) -> str:
    subtype = pending.get("subtype", "connectivity")
    host_t = pending.get("target_host")
    port_t = pending.get("target_port")
    domain_t = pending.get("target_domain")
    by = {c["tool"]: c.get("summary", "") for c in checks}
    ns = by.get("network.namespace_context", "namespace context unavailable")
    route = by.get("network.default_route", "default route unavailable")
    dns_cfg = by.get("network.dns", "dns config unavailable")
    dns_test = by.get("network.resolution_test", "")
    tcp = by.get("network.tcp_connect_test", "")
    listeners_s = by.get("network.listeners", "listener view unavailable")
    listener_attr = by.get("network.listener_attribution", "")
    fw = by.get("network.firewall_context", "firewall context unavailable")
    if subtype == "reachability" and host_t and port_t:
        tcp_line = tcp or f"bounded TCP connect to {host_t}:{port_t} not run"
        dns_line = dns_test or f"DNS resolution test for {host_t} not run"
        return (
            "## Assessment\n"
            f"Deeper reachability check for {host_t}:{port_t} completed.\n\n"
            "## What I found\n"
            f"- Namespace/container context: {ns}.\n"
            f"- Default route: {route}.\n"
            f"- DNS resolver config: {dns_cfg}.\n"
            f"- DNS resolution: {dns_line}.\n"
            f"- TCP connect: {tcp_line}.\n"
            f"- Firewall context: {fw}.\n\n"
            "## Best read\n"
            f"This reachability view is taken from the current container/runtime namespace; "
            f"host routing and host firewall may differ for {host_t}:{port_t}.\n\n"
            "## Safety\n"
            "Read-only checks only. No firewall/route/interface/service changes were performed.\n"
        )
    if subtype in {"port-open", "listener"} and port_t is not None:
        port_str = str(port_t)
        listening_line = (
            f"port {port_str} is listening"
            if f":{port_str}" in listeners_s
            else f"port {port_str} is not listening from this container view"
        )
        return (
            "## Assessment\n"
            f"Deeper port {port_str} check completed.\n\n"
            "## What I found\n"
            f"- Listener status: {listening_line}.\n"
            f"- Visible listeners: {listeners_s}.\n"
            f"- Listener ownership: {listener_attr or 'ownership unavailable'}.\n"
            f"- Firewall context: {fw}.\n"
            f"- Namespace/container context: {ns}.\n"
            f"- Default route: {route}.\n\n"
            "## Best read\n"
            f"Host firewall and Docker port publishing are not visible from this container. "
            f"Opening port {port_str} would require an operator-approved change such as "
            f"starting a service listener, publishing the Docker port, "
            f"and/or allowing host firewall policy.\n\n"
            "## Safety\n"
            "Read-only checks only. No mutation was performed; "
            "no unconditional firewall commands are issued from here.\n"
        )
    if subtype == "dns":
        target = domain_t or host_t or _SAFE_DEFAULT_DNS_DOMAIN
        used_default_note = (
            ""
            if (domain_t or host_t)
            else f" No domain was specified, so the safe default {target} was used."
        )
        return (
            "## Assessment\n"
            f"DNS follow-up for {target} completed.{used_default_note}\n\n"
            "## What I found\n"
            f"- DNS resolver config: {dns_cfg}.\n"
            f"- Resolution test: {dns_test or 'resolution test unavailable'}.\n"
            f"- Default route: {route}.\n"
            f"- Namespace/container context: {ns}.\n"
            f"- Firewall context: {fw}.\n\n"
            "## Safety\n"
            "Read-only DNS lookups only. No resolver/firewall/route changes were performed.\n"
        )
    return _deterministic_operator_summary("network_dns_firewall_deep_dive", checks)


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

_FOLLOWUP_PHRASES = {
    "get that info",
    "get the info",
    "then get that info",
    "collect that info",
    "get those checks",
    "collect those checks",
    "do that",
    "do those checks",
    "run those checks",
    "proceed",
    "continue",
    "go ahead",
    "dig deeper",
    "check those",
    "check that",
    "yes do that",
    "ok do that",
    "yeah run the read-only checks",
}


def _is_followup_phrase(text: str) -> bool:
    normalized = " ".join((text or "").strip().lower().replace(",", "").split())
    return normalized in _FOLLOWUP_PHRASES


def is_pending_followup_confirmation(text: str) -> bool:
    normalized = " ".join(
        (text or "").strip().lower().strip(" .!?;,").replace(",", " ").replace("  ", " ").split()
    )
    if not normalized:
        return False
    soft_prefixes = ("then ", "ok ", "okay ", "please ", "yes ", "yeah ", "yep ")
    collapsed = normalized
    for pfx in soft_prefixes:
        if collapsed.startswith(pfx):
            collapsed = collapsed[len(pfx) :].strip()
            break
    return (
        normalized in _FOLLOWUP_CONFIRM
        or collapsed in _FOLLOWUP_CONFIRM
        or _is_followup_phrase(normalized)
        or _is_followup_phrase(collapsed)
    )


def _operator_followup_text(label: str, description: str) -> str:
    label = label.replace("broader read-only ", "").replace(" pass pass", " pass")
    label = label.replace("read-only read-only", "read-only")
    label = label.removesuffix(" pass").strip()
    return (
        f"I can dig into the {label} angle next — {description}. "
        "Say `proceed` or `dig deeper` and I’ll keep it read-only."
    )


def _is_disk_usage_breakdown_intent(question: str) -> bool:
    q = question.lower()
    phrases = (
        "what is using disk space",
        "what is taking disk space",
        "what is taking up space",
        "what is filling my disk",
        "where is my disk space going",
        "largest folders",
        "biggest directories",
        "disk hogs",
        "what is eating space",
        "why is my disk filling",
    )
    return any(p in q for p in phrases)


def _extract_service_target(question: str) -> str:
    q = question.lower()
    aliases = [
        "nginx",
        "ssh",
        "sshd",
        "docker",
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "redis",
        "caddy",
    ]
    for a in aliases:
        if a in q:
            return a
    return "service-discovery"


def select_followup_investigation(
    intent: str, checks: list[dict[str, str]], question: str
) -> dict[str, Any] | None:
    if _is_windows_platform_checks(checks):
        # Windows route stays bounded: deeper follow-up bundles are
        # Linux-oriented, so no pending investigation is queued.
        return None
    q = question.lower()
    if intent == "docker" or any(
        p in q
        for p in (
            "container restart",
            "restart loop",
            "crash loop",
            "container exit",
            "container crash",
            "container failing",
            "anything crashing",
            "any container errors",
        )
    ):
        target_container: str | None = None
        for tok in q.split():
            if tok.startswith("sfai-"):
                target_container = tok.strip(".,?!")
                break
        subtype = "container-errors"
        if "restart" in q or "restaring" in q or "restart loop" in q:
            subtype = "restart-loop"
        elif "exit" in q:
            subtype = "exited-containers"
        elif "noisy" in q:
            subtype = "noisy-logs"
        elif any(t in q for t in ("dns", "reachability", "network")):
            subtype = "network-log-errors"
        followup_d: dict[str, Any] = {
            "intent": "logs_deep_dive",
            "label": "container/log deep dive",
            "description": (
                "container inventory, restart counts, exit codes, and bounded logs for "
                "failing/restarting containers"
            ),
            "bundle": "docker",
            "type": "logs",
            "subtype": subtype,
            "target": "docker",
        }
        if target_container:
            followup_d["target_container"] = target_container
        return followup_d
    if intent in {"logs", "errors", "auth", "log", "error"} or intent.startswith("logs:"):
        subtype = "general"
        target_service: str | None = None
        if intent == "auth" or any(
            p in q for p in ("auth", "login fail", "ssh fail", "sudo fail", "permission denied")
        ):
            subtype = "auth"
        elif intent.startswith("logs:"):
            subtype = "service"
            target_service = intent.split(":", 1)[1].strip() or None
        elif any(
            p in q for p in ("kernel", "oom", "killed process", "i/o error", "io error", "panic")
        ):
            subtype = "kernel"
        elif any(p in q for p in ("connection refused", "timeout", "tls", "certificate", "dns")):
            subtype = "network-errors"
        elif any(p in q for p in ("no space left", "disk full", "read-only", "filesystem")):
            subtype = "storage-errors"
        if not target_service:
            for svc in (
                "nginx",
                "ssh",
                "sshd",
                "docker",
                "postgres",
                "postgresql",
                "mysql",
                "mariadb",
                "redis",
                "caddy",
                "shellforgeai",
            ):
                if svc in q:
                    target_service = svc
                    if subtype == "general":
                        subtype = "service"
                    break
        followup: dict[str, Any] = {
            "intent": "logs_deep_dive",
            "label": "log/error deep dive",
            "description": (
                "broader bounded error scan, auth/kernel clues, and service-specific themes"
            ),
            "bundle": "logs_deep_dive",
            "type": "logs",
            "subtype": subtype,
            "target": "logs_deep_dive",
        }
        if target_service:
            followup["target_service"] = target_service
            followup["target"] = f"logs:{target_service}"
        return followup
    if intent == "network" or any(
        w in q
        for w in (
            "network",
            "netwrok",
            "dns",
            "dns statsu",
            "route",
            "firewall",
            "firwall",
            "conenctivity",
            "listerning",
            "reachable",
            "reach ",
            "connect to",
            "conenct to",
            "test port",
            "tcp connect",
            "open port",
            "allow port",
            "is port ",
            "port ",
            "listening",
        )
    ):
        subtype = _detect_network_subtype(question)
        reach = _extract_reachability_target(question)
        port_only = _extract_port_target(question) if not reach else None
        dom = _extract_dns_target(question)
        label = _network_subtype_label(subtype)
        description = _network_followup_description(subtype)
        followup = {
            "intent": "network_dns_firewall_deep_dive",
            "label": label,
            "description": description,
            "bundle": "network",
            "type": "network",
            "subtype": subtype,
        }
        if reach:
            followup["target_host"] = reach[0]
            followup["target_port"] = reach[1]
        elif port_only is not None:
            followup["target_port"] = port_only
        if dom:
            followup["target_domain"] = dom
        elif reach:
            followup["target_domain"] = reach[0]
        return followup
    is_disk_capacity_intent = (
        any(
            k in q
            for k in (
                "disk full",
                "disk getting full",
                "running out of space",
                "disk space",
                "inodes",
            )
        )
        or intent in {"disk"}
        or _is_disk_usage_breakdown_intent(q)
    )
    if intent in {"nginx", "ssh", "sshd", "docker", "service", "services"} or any(
        w in q
        for w in (
            "service",
            "services",
            "nginx",
            "ssh",
            "docker",
            "port",
            "restart",
            "restarat",
            "reeestart",
            "ngnix",
        )
    ):
        return {
            "intent": (
                "service_inventory_deep_dive"
                if any(w in q for w in ("what services", "services are running", "what ports"))
                else "service_health_deep_dive"
            ),
            "label": "service health",
            "description": "listening ports, service detectors, and recent service clues",
            "bundle": "services",
            "target": _extract_service_target(question),
        }
    disk_summary = next((c.get("summary", "") for c in checks if c.get("tool") == "disk.usage"), "")
    inode_summary = next(
        (c.get("summary", "") for c in checks if c.get("tool") == "disk.inodes"), ""
    )
    if is_disk_capacity_intent:
        if _is_disk_usage_breakdown_intent(q):
            return {
                "intent": "disk_capacity_deep_dive",
                "label": "disk usage breakdown",
                "description": "bounded top-level directory usage plus disk/inode context",
                "bundle": "disk",
                "reason": "user asked what is consuming disk space",
            }
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
    facts = _summarize_facts(checks)
    sp = facts.get("storage_pressure")
    storage_pressure_nonzero = bool(sp and any(v > 0 for v in sp))
    cpu_mem = facts.get("cpu_mem") or {}
    load = facts.get("load")
    cpus = cpu_mem.get("cpus") or 0
    cpu_saturated = bool(load and cpus and load[0] > cpus * 1.5)
    mem_total = cpu_mem.get("mem_total_gib") or 0.0
    mem_used = cpu_mem.get("mem_used_gib") or 0.0
    mem_headroom = mem_total > 0 and (mem_total - mem_used) / mem_total > 0.15
    swap_unused = bool(cpu_mem.get("swap_unused", True))
    disk_healthy = facts.get("disk_pct", 0) < 80
    inode_healthy = facts.get("inode_pct", 0) < 80
    container_ctx = bool(facts.get("container"))
    is_perf_intent = intent in {
        "performance",
        "host",
        "slow",
        "slowness",
        "storage_performance",
    } or any(
        p in q for p in ("slow", "sluggish", "laggy", "performance", "feels slow", "high load")
    )
    if (
        is_perf_intent
        and storage_pressure_nonzero
        and not cpu_saturated
        and mem_headroom
        and swap_unused
        and disk_healthy
        and inode_healthy
        and container_ctx
    ):
        return {
            "intent": "storage_io_deep_dive",
            "label": "storage/I/O",
            "description": (
                "storage pressure, active processes, recent error clues, "
                "and container storage context"
            ),
            "bundle": "performance",
            "reason": "storage pressure is non-zero with healthy CPU/memory/disk",
        }
    if is_perf_intent and storage_pressure_nonzero:
        return {
            "intent": "storage_io_deep_dive",
            "label": "storage/I/O",
            "description": (
                "storage pressure, active processes, recent error clues, "
                "and container storage context"
            ),
            "bundle": "performance",
            "reason": "storage pressure is non-zero",
        }
    for c in checks:
        tool = c.get("tool", "")
        summary = c.get("summary", "").lower()
        if tool == "storage.pressure" and ("io_some" in summary or "non-zero" in summary):
            return {
                "intent": "storage_io_deep_dive",
                "label": "storage/I/O",
                "description": (
                    "storage pressure, active processes, recent error clues, "
                    "and container storage context"
                ),
                "bundle": "performance",
                "reason": "storage pressure is non-zero",
            }
    return {
        "intent": "general_missing_context_deep_dive",
        "label": "broader read-only health pass",
        "description": "missing context, pressure signals, and recent error clues",
        "bundle": "health",
        "reason": "no single stronger angle was detected",
    }


_ACTION_VERBS = (
    "restart",
    "reload",
    "stop",
    "start",
    "kill",
    "install",
    "uninstall",
    "remove",
    "delete",
    "purge",
    "upgrade",
    "downgrade",
    "reboot",
    "shutdown",
    "format",
    "wipe",
    "drop",
)


def _detect_action_request(text: str) -> str | None:
    low = text.lower().strip()
    if not low:
        return None
    request_modal = any(
        p in low
        for p in (
            "can you ",
            "could you ",
            "please ",
            "would you ",
            "will you ",
            "go ahead and ",
            "i need you to ",
        )
    )
    starts_imperative = any(re.match(rf"^{re.escape(v)}\b", low) for v in _ACTION_VERBS)
    if not (request_modal or starts_imperative):
        return None
    if not any(re.search(rf"\b{re.escape(v)}\b", low) for v in _ACTION_VERBS):
        return None
    if any(
        phrase in low
        for phrase in (
            "what would you check before",
            "before restarting",
            "explain",
            "review",
            "describe",
            "what does",
        )
    ):
        return None
    target_match = re.search(
        r"\b(?:restart|reload|stop|start|kill|install|uninstall|remove|delete|"
        r"purge|upgrade|downgrade|reboot|shutdown|format|wipe|drop)\b\s+([\w\-./]+)",
        low,
    )
    target = target_match.group(1) if target_match else None
    target_phrase = f" {target}" if target else ""
    return (
        f"I can't run that action from inspect mode — apply remains validation-only "
        f"in this alpha, and changes like this need explicit operator approval.\n"
        f"If you'd like, I can take a read-only look at{target_phrase or ' the relevant service'} "
        "first (process state, listeners, recent log clues) so you have evidence in hand "
        "before deciding."
    )


def _extract_service_action_target(text: str) -> str | None:
    low = text.lower().strip()
    m = re.search(
        r"\b(?:restart|reload|stop|start|bounce)\b\s+([\w\-./]+)",
        low,
    )
    if not m:
        return None
    target = m.group(1).strip("?.!,")
    return target or None


_INTERACTIVE_DISPATCH_LABELS: dict[tuple[str, ...], str] = {
    ("version",): "Running version...",
    ("doctor",): "Running doctor...",
    ("model", "doctor"): "Running model doctor...",
    ("status",): "Running read-only status...",
    ("ops", "report"): "Running read-only ops report...",
    ("ops", "report", "history"): "Running read-only ops report history...",
    ("ops", "report", "compare-latest"): "Running read-only ops report compare-latest...",
    ("triage", "docker"): "Running read-only Docker triage...",
    ("triage", "docker", "detail"): "Running read-only Docker triage detail...",
    ("handoff",): "Running read-only operator handoff...",
    ("handoff", "validate"): "Running read-only handoff validation...",
    ("handoff", "export"): "Running read-only handoff export...",
    ("handoff", "export-validate"): "Running read-only handoff export validation...",
    ("handoff", "history"): "Running read-only handoff history...",
    ("handoff", "compare"): "Running read-only handoff compare...",
    ("handoff", "compare-latest"): "Running read-only handoff compare-latest...",
    ("diagnose",): "Running read-only diagnose...",
    ("v1", "check"): "Running V1 readiness check...",
    ("remediation", "self-test"): "Running read-only remediation self-test...",
    ("remediation", "eligibility"): "Running read-only remediation eligibility explain...",
    ("recipes",): "Running read-only recipe registry...",
    ("recipes", "list"): "Running read-only recipe registry...",
    ("recipes", "inspect"): "Running read-only recipe inspection...",
    ("recipes", "eligibility"): "Running read-only recipe eligibility...",
    ("recipes", "receipt", "audit"): "Running read-only receipt audit...",
    ("recipes", "receipt", "explain"): "Running read-only receipt finding explanation...",
    ("recipes", "receipt", "integrity"): "Running read-only receipt integrity scan...",
    ("recipes", "receipt", "audit-bundle"): "Running read-only receipt audit bundle...",
    (
        "recipes",
        "receipt",
        "audit-bundle-validate",
    ): "Running read-only receipt audit bundle validation...",
    ("safe-actions",): "Running read-only safe-actions summary...",
}


def _dispatch_label(argv: tuple[str, ...]) -> str:
    for prefix, label in sorted(
        _INTERACTIVE_DISPATCH_LABELS.items(), key=lambda item: len(item[0]), reverse=True
    ):
        if argv[: len(prefix)] == prefix:
            return label
    return "Running read-only ShellForgeAI command..."


def _interactive_unknown_command_guidance(text: str, suggestions: tuple[str, ...]) -> str:
    lines = [
        f"Unknown command: {text}",
        "No action was taken.",
    ]
    if suggestions:
        lines.extend(["", "Did you mean:"])
        lines.extend(f"  {suggestion}" for suggestion in suggestions)
    lines.extend(["", "Type help for supported commands."])
    return "\n".join(lines)


def _run_interactive_cli_dispatch(console: Console, argv: tuple[str, ...]) -> str:
    if not argv:
        console.print("No command was dispatched.")
        return ""
    json_output = "--json" in argv
    if not json_output:
        console.print(_dispatch_label(argv))
    try:
        from typer.testing import CliRunner

        from shellforgeai.cli import app

        result = CliRunner().invoke(app, list(argv))
    except Exception as exc:
        console.print(
            f"ShellForgeAI command dispatch failed safely. No action was taken. Error: {exc}"
        )
        return ""
    output = result.output or ""
    if output:
        console.print(output.rstrip())
    if result.exit_code != 0 and not json_output:
        console.print(
            f"ShellForgeAI command exited with status {result.exit_code}. "
            "No action was taken by the interactive dispatcher."
        )
    return output


def _interactive_mutation_refusal(text: str) -> str:
    return (
        "Refused: natural-language mutation is not allowed.\n"
        "Refused: interactive mode is not a shell.\n"
        "No command was executed.\n"
        "No action was taken.\n"
        "I can't run that command from ShellForgeAI interactive mode.\n"
        "ShellForgeAI interactive mode does not execute shell snippets. "
        "ShellForgeAI interactive mode does not execute Docker/Compose, cleanup, "
        "remediation, rollback, apply, or restart commands.\n"
        "Safe read-only alternatives:\n"
        "- status\n"
        "- ops report\n"
        "- triage docker\n"
        "- triage docker detail <target>\n"
        "- remediation eligibility --target <target> --explain\n"
        "- recipes list\n"
        "- recipes receipt audit\n"
        "- recipes eligibility --recipe docker.disposable_restart --target <target>"
    )


def _interactive_not_a_shell_refusal(text: str) -> str:
    """Refusal for shell-shaped input (commands/metacharacters/file reads).

    Interactive mode is not a shell: no shell command, file read, network call,
    package install, or Docker/Compose mutation is executed from typed text. The
    wording is explicit (not a shell / no command was executed / no action was
    taken) and offers safe read-only ShellForgeAI alternatives.
    """
    return (
        "Refused: interactive mode is not a shell.\n"
        "No command was executed.\n"
        "No action was taken.\n"
        "ShellForgeAI interactive mode does not execute shell commands, shell "
        "snippets, arbitrary file reads, network or download commands, package "
        "installs, or Docker/Compose, cleanup, remediation, rollback, recovery, "
        "apply, merge, push, or restart commands. Real fixes only run through "
        "governed, named recipes with explicit confirmation.\n"
        "Safe read-only alternatives:\n"
        "  shellforgeai ops report --json\n"
        "  shellforgeai triage docker --json\n"
        "- status\n"
        "- doctor\n"
        "- recipes list\n"
        "- recipes receipt audit"
    )


@dataclass
class InteractiveSessionSummaryState:
    """Compact read-only metadata for deterministic REPL handoff summaries."""

    session_id: str
    started_at: float = field(default_factory=time.time)
    events_seen: int = 0
    checks: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    refusals: list[str] = field(default_factory=list)
    latest_artifacts: list[str] = field(default_factory=list)
    latest_target: str = ""
    latest_session_id: str = ""
    top_suspect: str = ""
    visibility_notes: list[str] = field(default_factory=list)
    safe_next_commands: list[str] = field(default_factory=list)

    def _append_unique(self, field_name: str, value: str, *, limit: int = 8) -> None:
        clean = _sanitize_session_summary_text(value)
        if not clean:
            return
        values = getattr(self, field_name)
        if clean not in values:
            values.append(clean)
        del values[limit:]

    def note_check(self, check: str) -> None:
        self.events_seen += 1
        self._append_unique("checks", check)

    def note_finding(self, finding: str) -> None:
        self._append_unique("findings", finding, limit=6)

    def note_refusal(self, category: str) -> None:
        self.events_seen += 1
        self._append_unique("refusals", category, limit=6)

    def note_artifact(self, path: str) -> None:
        self._append_unique("latest_artifacts", path, limit=8)

    def note_visibility(self, note: str) -> None:
        self._append_unique("visibility_notes", note, limit=4)

    def note_safe_command(self, command: str) -> None:
        self._append_unique("safe_next_commands", command, limit=6)


def _sanitize_session_summary_text(value: str) -> str:
    text = " ".join(str(value or "").split())[:240]
    low = text.lower()
    dangerous_markers = (
        "rm -rf",
        "mkfs",
        "dd if=",
        "docker compose" + " restart",
        "docker" + " restart",
        "sudo reboot",
        "shutdown",
    )
    if any(marker in low for marker in dangerous_markers):
        return "destructive shell-like input refused"
    return text


def _session_summary_from_grounding(
    state: InteractiveSessionSummaryState, grounding: FollowupGroundingState
) -> None:
    if grounding.last_target:
        state.latest_target = grounding.last_target
    if grounding.last_top_suspect:
        state.top_suspect = grounding.last_top_suspect
    if grounding.last_evidence_summary:
        state.note_finding(grounding.last_evidence_summary)
    for artifact in grounding.last_artifact_paths:
        state.note_artifact(artifact)
    if grounding.last_safe_next_command:
        state.note_safe_command(grounding.last_safe_next_command)


def _parse_artifact_lines_for_summary(state: InteractiveSessionSummaryState, text: str) -> None:
    for line in (text or "").splitlines():
        if any(label in line.lower() for label in ("artifact", "evidence:", "summary:", "packet")):
            path_match = re.search(r"(/[^\s]+|[A-Za-z0-9_.-]+/[^\s]+)", line)
            if path_match:
                state.note_artifact(path_match.group(1).rstrip(",."))
        if "metadata hygiene" in line.lower():
            state.note_finding("metadata hygiene advisory observed")


def _record_cli_dispatch_in_session_summary(
    state: InteractiveSessionSummaryState,
    argv: tuple[str, ...],
    output: str,
    grounding: FollowupGroundingState,
) -> None:
    if argv[:1] == ("status",):
        state.note_check("status")
        if "--brief" in argv:
            state.note_finding("brief status reviewed")
    elif argv[:2] == ("ops", "report"):
        state.note_check("ops report")
        if "--brief" in argv:
            state.note_finding("brief ops report reviewed")
    elif argv[:3] == ("triage", "docker", "detail") and len(argv) >= 4:
        state.latest_target = argv[3]
        state.note_check(f"triage docker detail {argv[3]}")
        state.note_safe_command(
            f"shellforgeai remediation eligibility --target {argv[3]} --explain"
        )
    elif argv[:2] == ("triage", "docker"):
        state.note_check("triage docker")
    elif argv[:1] == ("recipes",):
        state.note_check("recipes")
        if len(argv) >= 3 and argv[1] == "inspect":
            state.note_check(f"recipes inspect {argv[2]}")
        elif len(argv) >= 6 and argv[1] == "eligibility":
            state.note_check("recipes eligibility")
            state.latest_target = argv[5]
    elif argv[:1] == ("safe-actions",):
        state.note_check("safe-actions")
    elif argv[:2] == ("remediation", "eligibility"):
        target = argv[3] if len(argv) >= 4 and argv[2] == "--target" else ""
        if target:
            state.latest_target = target
            state.note_check(f"remediation eligibility {target}")
        else:
            state.note_check("remediation eligibility")
        low_output = (output or "").lower()
        if "blocked" in low_output:
            state.note_finding("remediation eligibility: blocked")
        elif "eligible" in low_output:
            state.note_finding("remediation eligibility: eligible")
        elif output:
            state.note_finding("remediation eligibility reviewed")
    elif argv[:2] == ("handoff", "validate"):
        state.note_check("handoff validate")
    elif argv[:2] == ("handoff", "export-validate"):
        state.note_check("handoff export-validate")
    elif argv[:2] == ("handoff", "export"):
        state.note_check("handoff export")
        state.note_finding("read-only handoff artifact exported")
    elif argv[:2] == ("handoff", "history"):
        state.note_check("handoff history")
    elif argv[:2] == ("handoff", "compare-latest"):
        state.note_check("handoff compare-latest")
    elif argv[:2] == ("handoff", "compare"):
        state.note_check("handoff compare")
    elif argv[:1] == ("handoff",):
        state.note_check("handoff")
        if "--save" in argv:
            state.note_finding("read-only handoff artifact saved")
    elif argv[:2] == ("v1", "check"):
        state.note_check("v1 check")
    elif argv[:2] == ("remediation", "self-test"):
        state.note_check("remediation self-test")
    elif argv[:1] == ("diagnose",):
        target = argv[1] if len(argv) > 1 else "target"
        state.latest_target = target
        state.note_check(f"diagnose {target}")
    _parse_artifact_lines_for_summary(state, output)
    _session_summary_from_grounding(state, grounding)


def _record_latest_context_in_session_summary(
    state: InteractiveSessionSummaryState, ctx: LatestDiagnosisContext | None
) -> None:
    if ctx is None:
        return
    state.latest_session_id = ctx.session_id or state.latest_session_id
    state.latest_target = ctx.target or state.latest_target
    state.note_check(ctx.diagnosis_kind or ctx.target or "diagnosis")
    if ctx.diagnosis_kind in {"system role/health", "machine health", "health"}:
        state.note_visibility("container-limited/runtime-scoped visibility may apply")
    for path in (ctx.evidence_path, ctx.summary_path, ctx.plan_path, ctx.artifact_dir):
        if path:
            state.note_artifact(path)
    for highlight in ctx.evidence_highlights[:3]:
        state.note_finding(highlight)
    for finding in ctx.findings[:3]:
        state.note_finding(finding)
    for limitation in ctx.limitations[:2]:
        state.note_visibility(limitation)
    for command in ctx.safe_next_commands[:3]:
        state.note_safe_command(command)


def _first_safe_summary_command(state: InteractiveSessionSummaryState) -> str:
    if any("metadata hygiene" in finding.lower() for finding in state.findings):
        return "shellforgeai audit cleanup review"
    if state.top_suspect:
        return f"shellforgeai triage docker detail {state.top_suspect}"
    if state.latest_target and state.latest_target not in {
        "health",
        "machine health",
        "firewall",
        "performance",
        "storage_performance",
    }:
        return f"shellforgeai remediation eligibility --target {state.latest_target} --explain"
    if any(check == "status" for check in state.checks):
        return "shellforgeai status --json"
    if any(check == "ops report" for check in state.checks):
        return "shellforgeai ops report --json"
    return "shellforgeai ops report --brief"


def _session_summary_payload(state: InteractiveSessionSummaryState) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "interactive_session_summary",
        "status": "ok",
        "read_only": True,
        "mutation_performed": False,
        "session": {
            "events_seen": state.events_seen,
            "latest_target": state.latest_target or None,
            "latest_session_id": state.latest_session_id or state.session_id,
            "latest_artifacts": list(state.latest_artifacts),
        },
        "checks": list(state.checks),
        "findings": list(state.findings + state.visibility_notes),
        "refusals": list(state.refusals),
        "first_safe_command": _first_safe_summary_command(state),
        "safety": {
            "cleanup_executed": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "production_restart_executed": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "natural_language_execution": False,
        },
    }


def render_interactive_session_summary(
    state: InteractiveSessionSummaryState, *, json_output: bool = False
) -> str:
    payload = _session_summary_payload(state)
    if json_output:
        return json.dumps(payload, indent=2, sort_keys=True)

    if state.events_seen == 0 and not state.checks and not state.findings and not state.refusals:
        return (
            "Session summary: read-only inspection session.\n"
            "No diagnostic evidence has been collected in this interactive session yet. "
            "I don't have any collected evidence to summarize.\n\n"
            "First safe next command:\n"
            "  shellforgeai ops report --brief\n\n"
            "Safety:\n"
            "- No cleanup/remediation/rollback/Compose mutation executed.\n"
            "- No arbitrary shell executed.\n"
            "- Natural-language mutation remained blocked."
        )

    lines = ["Session summary: read-only inspection session."]
    if state.latest_target and state.checks:
        lines.append(f"\nUsing latest {state.checks[-1]} diagnosis context.")
    if state.checks:
        lines.append("\nWhat was checked:")
        lines.extend(f"- {check}" for check in state.checks[:8])
    if state.latest_session_id or state.latest_artifacts:
        lines.append("\nLatest evidence / artifacts:")
        lines.append(f"- latest session id: {state.latest_session_id or state.session_id}")
        for artifact in state.latest_artifacts[:6]:
            lines.append(f"- {artifact}")
    findings = list(state.findings)
    if state.top_suspect:
        findings.insert(0, f"top Docker suspect: {state.top_suspect}")
    findings.extend(state.visibility_notes)
    if findings:
        lines.append("\nFindings:")
        lines.extend(f"- {finding}" for finding in findings[:8])
    if state.refusals:
        lines.append("\nRefusals / blocked actions:")
        lines.extend(f"- {refusal}" for refusal in state.refusals[:6])
        lines.append("- No action was taken.")
    lines.append("\nFirst safe next command:")
    lines.append(f"  {payload['first_safe_command']}")
    lines.append("\nSafety:")
    lines.append("- No cleanup/remediation/rollback/Compose mutation executed.")
    lines.append("- No arbitrary shell executed.")
    lines.append("- Natural-language mutation remained blocked.")
    return "\n".join(lines)


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
        'container={"is_container"',
        "loadavg=(",
        "mem_used=",
        "'=",
    ]
    return any(b in low for b in blocked)


def _grounded_mutation_has_concrete_ops_target(res) -> bool:  # noqa: ANN001
    return bool(
        res.target
        and (
            res.target.startswith("sfai-")
            or res.target_kind in {"container", "docker_container", "suspect"}
            or res.intent == "mutation_refusal"
            and res.safe_command.endswith(res.target)
            and res.target != "performance"
        )
    )


def start_interactive(
    runtime: RuntimeContext, no_trust_cache: bool = False, yes_trust: bool = False
) -> None:
    console = Console()
    trusted = WorkspaceTrustStore(runtime.session.data_dir).is_trusted(Path.cwd())
    console.print(build_banner(runtime, trusted or yes_trust))
    if not _confirm_workspace(console, runtime, no_trust_cache=no_trust_cache, yes_trust=yes_trust):
        return
    renderer = StreamRenderer(console)
    paste_guard_active = False
    paste_guard_remaining_lines = 0
    paste_guard_non_shell_lines = 0
    paste_guard_first_notice = False
    pending_followup: dict[str, Any] | None = None
    completed_followups: list[str] = []
    evidence_mode = "compact"
    latest_context: LatestDiagnosisContext | None = None
    grounding = FollowupGroundingState()
    session_summary = InteractiveSessionSummaryState(session_id=runtime.session.session_id)
    while True:
        try:
            user_input = input("sfai> ").strip()
        except EOFError:
            CodexProvider.cleanup_active_processes()
            console.print("Goodbye.")
            return
        except KeyboardInterrupt:
            CodexProvider.cleanup_active_processes()
            console.print("\nInterrupted safely. REPL is still healthy.")
            continue
        routed = route_input(user_input)
        if routed.name == "noop":
            continue
        if routed.name == "unknown_command":
            console.print(
                _interactive_unknown_command_guidance(routed.args or user_input, routed.argv)
            )
            continue
        if routed.name == "/summary":
            raw_args = routed.argv or tuple(routed.args.strip().lower().split())
            args = set(raw_args)
            allowed_args = {"--json", "--save"}
            if len(raw_args) != len(args) or args - allowed_args:
                console.print("Usage: /summary [--save] [--json]")
            elif "--save" in args:
                from shellforgeai.core.interactive_summary_artifact import (
                    save_interactive_summary,
                )

                saved = save_interactive_summary(
                    _session_summary_payload(session_summary),
                    Path(runtime.session.data_dir),
                    source="interactive /summary --save",
                )
                if "--json" in args:
                    console.print(json.dumps(saved, sort_keys=True))
                else:
                    console.print("Session summary saved:")
                    console.print(f"  id: {saved.get('summary_id')}")
                    console.print(f"  path: {saved.get('summary_path')}")
                    console.print("\nNext safe commands:")
                    console.print(
                        f"  shellforgeai session summary validate {saved.get('summary_id')}"
                    )
                    console.print(
                        f"  shellforgeai session summary export {saved.get('summary_id')}"
                    )
            else:
                console.print(
                    render_interactive_session_summary(
                        session_summary, json_output=("--json" in args)
                    )
                )
            continue
        pre_nuance_grounded = resolve_followup_reference(user_input, grounding)
        if (
            routed.name != "mutation_refused"
            and pre_nuance_grounded.kind == "mutation_refusal"
            and _grounded_mutation_has_concrete_ops_target(pre_nuance_grounded)
        ):
            session_summary.note_refusal("mutation follow-up refused")
            console.print(render_grounded_resolution(grounding, pre_nuance_grounded))
            continue
        # PR131: command-help / plan-help guidance and ambiguous-execute refusal.
        # Command-help frames ("what command would I run?", "how would I propose?")
        # are answered with safe read-only / plan-only guidance and never execute.
        # Mutation requests still fall through to the existing deterministic
        # refusal paths (route_input mutation_refused, _detect_action_request, ...).
        if routed.name not in {
            "cli_dispatch",
            "mutation_refused",
            "logs_mutation_refused",
            "shell_refused",
        }:
            nuance = classify_intent_nuance(user_input)
            if nuance.category in (COMMAND_HELP, PLAN_HELP, CLEANUP_REVIEW_HELP):
                console.print(render_intent_nuance(nuance, text=user_input))
                continue
            if nuance.category == AMBIGUOUS_EXECUTE and not is_pending_followup_confirmation(
                user_input
            ):
                console.print(render_intent_nuance(nuance, text=user_input))
                continue
            if nuance.category == MUTATION_REQUEST and any(
                term in user_input.lower() for term in ("report", "status")
            ):
                session_summary.note_refusal("mutation request refused")
                console.print(_interactive_mutation_refusal(user_input))
                continue
        is_followup_phrase = _is_followup_phrase(user_input)
        early_grounded = resolve_followup_reference(user_input, grounding)
        if (
            routed.name != "mutation_refused"
            and early_grounded.kind == "mutation_refusal"
            and _grounded_mutation_has_concrete_ops_target(early_grounded)
        ):
            session_summary.note_refusal("mutation follow-up refused")
            console.print(render_grounded_resolution(grounding, early_grounded))
            continue
        if is_pending_followup_confirmation(user_input):
            if not pending_followup:
                if _is_followup_phrase(user_input):
                    console.print(
                        "There is no prior requested read-only info to continue.\n"
                        "Try one of:\n"
                        "- shellforgeai ops report\n"
                        "- shellforgeai triage docker\n"
                        "- shellforgeai v1 check --profile quick"
                    )
                else:
                    console.print(
                        "I don’t have a pending investigation. Tell me what symptom to check, "
                        "such as slow system, disk issue, network issue, or service issue."
                    )
                continue
            console.print(
                f'I’ll treat "{user_input}" as a read-only follow-up to the pending checks. '
                "No mutation will be performed."
            )
            pending_snapshot = dict(pending_followup)
            followup_target = pending_snapshot.get("target") or pending_snapshot.get("bundle")
            if pending_snapshot.get("intent") == "service_health_deep_dive" and not followup_target:
                pending_followup["last_error"] = "missing target"
                console.print(
                    "I had a pending service follow-up, but the target was missing. "
                    "Please ask the service question again."
                )
                continue
            network_followup_text: str | None = None
            proceed_res: Any = None
            try:
                with console.status("Running deeper read-only investigation..."):
                    if pending_snapshot.get("type") == "network":
                        with ThreadPoolExecutor(max_workers=1) as ex:
                            fut_net = ex.submit(_run_network_followup, pending_snapshot)
                            checks, network_followup_text = fut_net.result(timeout=45)
                    else:
                        if (
                            pending_snapshot.get("intent") == "service_health_deep_dive"
                            and followup_target == "service-discovery"
                        ):
                            followup_target = "services"
                        with ThreadPoolExecutor(max_workers=1) as ex:
                            fut_diag = ex.submit(
                                diagnose_target, runtime, followup_target, False, "30m"
                            )
                            proceed_res = fut_diag.result(timeout=45)
            except (TimeoutError, FutureTimeout):
                pending_followup["last_error"] = "timeout"
                console.print(
                    "The deeper service check timed out safely. No changes were made, "
                    "and the REPL is still healthy."
                )
                continue
            except KeyboardInterrupt:
                pending_followup["last_error"] = "interrupted"
                CodexProvider.cleanup_active_processes()
                console.print(
                    "The deeper check was interrupted safely. No changes were made, "
                    "and the REPL is still healthy."
                )
                continue
            except Exception as exc:
                pending_followup["last_error"] = str(exc)
                console.print(
                    "The deeper follow-up failed safely, but the REPL is still healthy. "
                    "No changes were made."
                )
                continue
            if proceed_res is not None:
                checks = [
                    {
                        "tool": i.source,
                        "status": str(i.metadata.get("status", "ok" if i.ok else "unavailable")),
                        "summary": i.summary,
                    }
                    for i in proceed_res.evidence.items
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
            if network_followup_text is not None:
                console.print(network_followup_text)
            elif pending_snapshot["intent"] == "storage_io_deep_dive":
                console.print(
                    _storage_io_deep_dive_synthesis(
                        pending_snapshot.get("first_pass_checks"), checks
                    )
                )
            else:
                console.print(
                    _deterministic_operator_summary(
                        pending_snapshot["intent"], checks, pending_snapshot.get("target")
                    )
                )
            completed_followups.append(
                f"{pending_snapshot['intent']}:{pending_snapshot.get('subtype', 'generic')}"
            )
            pending_followup = None
            continue
        if routed.name in {"/exit", "/quit"}:
            CodexProvider.cleanup_active_processes()
            console.print("Goodbye.")
            return
        if routed.name == "/clear":
            console.clear()
            paste_guard_active = False
            continue
        if routed.name == "/help":
            console.print(INTERACTIVE_HELP_TEXT)
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
                if latest_context is not None:
                    console.print(render_latest_context_pending(latest_context))
                else:
                    console.print("No pending investigation.")
            elif "label" not in pending_followup:
                console.print(
                    "Pending investigation state is invalid. Please ask the service question again."
                )
            else:
                target_phrase = _pending_target_phrase(pending_followup)
                target_line = f"Target: {target_phrase}\n" if target_phrase else ""
                console.print(
                    f"Pending investigation: {pending_followup['label']}\n"
                    + target_line
                    + f"Reason: {pending_followup.get('reason', 'not specified')}\n"
                    f"From: {pending_followup.get('created_from_question', 'unknown')}\n"
                    f"Session: {pending_followup.get('created_from_session', 'unknown')}\n"
                    f"Last error: {pending_followup.get('last_error', 'none')}"
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
        if routed.name == "cli_dispatch":
            dispatch_output = _run_interactive_cli_dispatch(console, routed.argv)
            if routed.argv[:2] == ("ops", "report"):
                update_grounding_from_ops_report_text(grounding, dispatch_output)
            elif routed.argv[:3] == ("triage", "docker", "detail") and len(routed.argv) >= 4:
                update_grounding_from_triage_detail_text(grounding, routed.argv[3], dispatch_output)
            _record_cli_dispatch_in_session_summary(
                session_summary, routed.argv, dispatch_output, grounding
            )
            continue
        if routed.name == "mutation_refused":
            session_summary.note_refusal("mutation request refused")
            resolved_mutation = resolve_followup_reference(routed.args or user_input, grounding)
            if resolved_mutation.kind == "mutation_refusal" and resolved_mutation.target:
                console.print(render_grounded_resolution(grounding, resolved_mutation))
            else:
                console.print(_interactive_mutation_refusal(routed.args or user_input))
            continue
        if routed.name == "logs_mutation_refused":
            session_summary.note_refusal("log deletion/truncation request refused")
            console.print(
                "Log deletion, truncation, or rotation is not performed by ShellForgeAI. "
                "Collecting read-only log evidence instead so you can decide safely."
            )
            try:
                with (
                    console.status("Running read-only log triage..."),
                    ThreadPoolExecutor(max_workers=1) as ex,
                ):
                    fut = ex.submit(diagnose_target, runtime, "logs", False, "30m")
                    res = fut.result(timeout=45)
                checks = [
                    {
                        "tool": i.source,
                        "status": str(i.metadata.get("status", "ok" if i.ok else "unavailable")),
                        "summary": i.summary,
                    }
                    for i in res.evidence.items
                ]
                console.print(
                    f"Read-only log evidence collected: {len(checks)} item(s). "
                    "No logs were modified."
                )
                console.print("Highlights:")
                for line in _evidence_highlights(checks):
                    console.print(line)
            except Exception:
                console.print(
                    "Log triage failed safely; no logs were modified and the REPL is healthy."
                )
            continue
        if routed.name == "shell_refused" and not paste_guard_active:
            # Interactive is not a shell: shell-shaped commands / metacharacters
            # are refused with clear wording and never executed. While a paste
            # quarantine is active, defer to the paste-fragment guard below.
            session_summary.note_refusal("not-a-shell command refused")
            console.print(_interactive_not_a_shell_refusal(routed.args or user_input))
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
        is_explicit_ask = routed.name == "ask" and routed.args.lower().startswith(
            ("explain this command:", "review this shell snippet:", "what does this command do?")
        )
        raw_for_guard = routed.args if routed.name == "ask" else user_input
        shell_like = is_multiline_shell_fragment(raw_for_guard) or looks_like_shell_command(
            raw_for_guard
        )
        if (
            paste_guard_active
            and not is_explicit_ask
            and (shell_like or is_shell_fragment_line(raw_for_guard))
        ):
            session_summary.note_refusal("shell/paste fragment blocked")
            console.print("Blocked shell paste fragment. No command was executed.")
            paste_guard_remaining_lines -= 1
            if raw_for_guard.strip().lower() in {"done", "fi", "esac", "'"}:
                paste_guard_active = False
            if paste_guard_remaining_lines <= 0:
                paste_guard_active = False
            continue
        if not is_explicit_ask and shell_like:
            if is_followup_phrase:
                shell_like = False
            else:
                paste_guard_active = True
                paste_guard_remaining_lines = 20
                paste_guard_non_shell_lines = 0
                paste_guard_first_notice = True
                session_summary.note_refusal("shell/paste fragment blocked")
                console.print("""Multiline shell paste detected.

ShellForgeAI interactive mode does not execute shell snippets.

Run it in your shell, or ask me to review it with:

ask review this shell snippet: ...

No command was executed.""")
                continue

        grounded = resolve_followup_reference(user_input, grounding)
        if grounded.kind == "mutation_refusal" and _grounded_mutation_has_concrete_ops_target(
            grounded
        ):
            session_summary.note_refusal("mutation follow-up refused")
            console.print(render_grounded_resolution(grounding, grounded))
            continue
        if grounded.kind in {"target", "evidence", "ambiguous"} and (
            grounded.kind != "target" or _grounded_mutation_has_concrete_ops_target(grounded)
        ):
            console.print(render_grounded_resolution(grounding, grounded))
            continue

        # Grounded follow-ups reuse the latest session evidence instead of
        # re-running collectors. Mutation phrases are never answered here.
        if latest_context is not None and not is_mutation_followup(user_input):
            _followup_intent = detect_latest_context_intent(user_input)
            if _followup_intent is not None:
                console.print(answer_from_latest_context(latest_context, _followup_intent))
                continue
        if is_followup_phrase and not pending_followup and latest_context is None:
            console.print(
                "There is no prior requested read-only info to continue.\n"
                "Try one of:\n"
                "- what does this system do?\n"
                "- is it running normally?\n"
                "- shellforgeai ops report"
            )
            continue

        if routed.name in {"diagnose"}:
            with console.status("Collecting evidence..."):
                res = diagnose_target(runtime, routed.args, online=False, since="30m")
            if routed.args == "network":
                res.evidence.items.append(
                    _evidence_item_from_result(
                        network.listener_attribution(),
                        EvidenceCategory.network,
                        "Listener attribution",
                    )
                )
                target = _extract_reachability_target(user_input)
                if target:
                    host_target, port_target = target
                    res.evidence.items.append(
                        _evidence_item_from_result(
                            network.resolution_test(host_target),
                            EvidenceCategory.network,
                            "Target DNS resolution test",
                        )
                    )
                    res.evidence.items.append(
                        _evidence_item_from_result(
                            network.tcp_connect_test(host_target, port_target),
                            EvidenceCategory.network,
                            "Target TCP connect test",
                        )
                    )
            if _is_disk_usage_breakdown_intent(user_input):
                top_dirs = disk.top_dirs("/")
                res.evidence.items.append(
                    _evidence_item_from_result(
                        top_dirs, EvidenceCategory.files, "Top-level directory usage"
                    )
                )
                mounts = storage.mounts()
                res.evidence.items.append(
                    _evidence_item_from_result(mounts, EvidenceCategory.files, "Mount layout")
                )
            checks = [
                {
                    "tool": i.source,
                    "status": str(i.metadata.get("status", "ok" if i.ok else "unavailable")),
                    "summary": i.summary,
                }
                for i in res.evidence.items
            ]
            evidence_count = len(res.evidence.items)
            console.print(f"Collected {evidence_count} read-only evidence item(s).")
            show_full = user_input.lower().startswith("diagnose ") or evidence_mode == "full"
            if show_full:
                _evidence_table(console, checks)
            else:
                console.print("Highlights:")
                for line in _evidence_highlights(checks):
                    console.print(line)
            natural_language_diagnose = not user_input.lower().startswith("diagnose ")
            with console.status("Writing artifacts..."):
                _ensure_artifact_dir(runtime)
                ep = runtime.session.artifact_dir / "evidence.json"
                ep.write_text(_model_dump_json_safe(res.evidence, indent=2), encoding="utf-8")
                pp = runtime.session.artifact_dir / "plan.json"
                pp.write_text(_model_dump_json_safe(res.proposed_plan, indent=2), encoding="utf-8")
                sp = runtime.session.artifact_dir / "summary.md"
                created_at_obj: Any = getattr(res, "created_at", None)
                created_at_str = (
                    created_at_obj.isoformat() if hasattr(created_at_obj, "isoformat") else ""
                )
                runtime_context = getattr(res, "runtime_context", {})
                write_diagnosis_summary_md(
                    path=sp,
                    session_id=res.session_id,
                    target=routed.args,
                    target_type=res.target_type.value,
                    created_at=created_at_str,
                    evidence_items=list(res.evidence.items),
                    findings=list(res.findings),
                    runtime_context=runtime_context,
                    artifact_dir=runtime.session.artifact_dir,
                )
            visibility = str(runtime_context.get("visibility", "runtime_scoped")).replace("_", "-")
            console.print(
                f"Diagnose {routed.args}\n"
                f"Session: {res.session_id}\nTarget: {routed.args}\n"
                f"Target type: {res.target_type.value}\n"
                f"Visibility: {visibility}\n"
                f"Evidence: {evidence_count} item(s)\n"
                f"{findings_summary_line(res.findings)}\n"
                f"Artifacts:\n- evidence: {ep}\n- plan: {pp}\n- summary: {sp}"
            )
            summary_diagnosis_kind = (
                "system role/health"
                if routed.args == "health"
                and detect_latest_context_intent(user_input) == "system_role"
                else routed.args
            )
            latest_context = build_latest_diagnosis_context(
                session_id=res.session_id,
                target=routed.args,
                diagnosis_kind=summary_diagnosis_kind,
                checks=checks,
                facts=_summarize_facts(checks),
                evidence_highlights=_evidence_highlights(checks),
                findings=_findings_to_strings(res.findings),
                artifact_dir=str(runtime.session.artifact_dir),
                evidence_path=str(ep),
                summary_path=str(sp),
                plan_path=str(pp),
                source_command=user_input,
            )
            update_grounding_from_latest_context(grounding, latest_context)
            _record_latest_context_in_session_summary(session_summary, latest_context)
            immediate_followup_intent = detect_latest_context_intent(user_input)
            if immediate_followup_intent in {"system_role", "health_status", "next_steps"}:
                console.print(answer_from_latest_context(latest_context, immediate_followup_intent))
            if natural_language_diagnose:
                pending_followup = None
                pending_followup = select_followup_investigation(routed.args, checks, user_input)
                followup_key = (
                    f"{pending_followup['intent']}:{pending_followup.get('subtype', 'generic')}"
                    if pending_followup
                    else ""
                )
                if pending_followup and followup_key in completed_followups:
                    pending_followup = None
                if pending_followup:
                    reach_target = _extract_reachability_target(user_input)
                    if reach_target:
                        pending_followup["target_host"] = reach_target[0]
                        pending_followup["target_port"] = reach_target[1]
                    if pending_followup.get("type") == "network":
                        port_only = _extract_port_target(user_input)
                        if port_only is not None and pending_followup.get("target_port") is None:
                            pending_followup["target_port"] = port_only
                        dns_target = _extract_dns_target(user_input)
                        if dns_target and not pending_followup.get("target_domain"):
                            pending_followup["target_domain"] = dns_target
                    pending_followup["created_from_session"] = runtime.session.session_id
                    pending_followup["created_from_question"] = user_input
                    pending_followup["created_from_intent"] = routed.args
                    pending_followup["session_id"] = runtime.session.session_id
                    pending_followup["source_user_message"] = user_input
                    pending_followup["created_at"] = time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                    )
                    pending_followup["first_pass_checks"] = list(checks)
                provider_error = None
                mresp_text = ""
                try:
                    provider = build_provider(runtime.settings)
                    prompt = build_contextual_prompt(
                        user_input,
                        {
                            "intent": routed.args,
                            "evidence_label": f"{routed.args} evidence",
                            "evidence": checks,
                            "findings": [_model_dump_safe(f) for f in res.findings],
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
                    write_diagnosis_summary_md(
                        path=sp,
                        session_id=res.session_id,
                        target=routed.args,
                        target_type=res.target_type.value,
                        created_at=created_at_str,
                        evidence_items=list(res.evidence.items),
                        findings=list(res.findings),
                        runtime_context=runtime_context,
                        artifact_dir=runtime.session.artifact_dir,
                    )
                    console.print("\n## Assessment")
                    if (
                        not _has_substantive_response(mresp_text)
                    ) or _contains_internal_collector_language(mresp_text):
                        console.print(_deterministic_operator_summary(routed.args, checks))
                    elif not mresp_streamed:
                        renderer.render(_sanitize_provider_error(mresp_text), None)
                    followup_key = (
                        f"{pending_followup['intent']}:{pending_followup.get('subtype', 'generic')}"
                        if pending_followup
                        else ""
                    )
                    if pending_followup and followup_key not in completed_followups:
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

        is_explicit_ask = routed.name == "ask" and routed.args.lower().startswith(
            ("explain this command:", "review this shell snippet:", "what does this command do?")
        )
        raw_for_guard = routed.args if routed.name == "ask" else user_input
        shell_like = is_multiline_shell_fragment(raw_for_guard) or looks_like_shell_command(
            raw_for_guard
        )
        if (
            paste_guard_active
            and not is_explicit_ask
            and (shell_like or is_shell_fragment_line(raw_for_guard))
        ):
            session_summary.note_refusal("shell/paste fragment blocked")
            console.print("Blocked shell paste fragment. No command was executed.")
            paste_guard_remaining_lines -= 1
            if raw_for_guard.strip().lower() in {"done", "fi", "esac", "'"}:
                paste_guard_active = False
            if paste_guard_remaining_lines <= 0:
                paste_guard_active = False
            continue
        if not is_explicit_ask and shell_like:
            session_summary.note_refusal("shell/paste fragment blocked")
            paste_guard_active = True
            paste_guard_remaining_lines = 20
            paste_guard_non_shell_lines = 0
            paste_guard_first_notice = True
            console.print("""Multiline shell paste detected.

ShellForgeAI interactive mode does not execute shell snippets.

Run it in your shell, or ask me to review it with:

ask review this shell snippet: ...

No command was executed.""")
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
            latest_context = build_latest_diagnosis_context(
                session_id=res.session_id,
                target="firewall",
                diagnosis_kind="firewall",
                checks=checks,
                facts=_summarize_facts(checks),
                evidence_highlights=_evidence_highlights(checks),
                findings=_findings_to_strings(res.findings),
                source_command=user_input,
            )
            update_grounding_from_latest_context(grounding, latest_context)
            _record_latest_context_in_session_summary(session_summary, latest_context)
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
                    session_summary.note_refusal("shell/paste fragment blocked")
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
            session_summary.note_refusal("shell/paste fragment blocked")
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
            session_summary.note_refusal("shell/paste fragment blocked")
            console.print(
                "This looks like a shell command pasted into ShellForgeAI interactive mode.\n\n"
                "ShellForgeAI is not a shell and will not execute it.\n\n"
                "Run this in your host/container shell instead, or ask ShellForgeAI to "
                "explain/review it with:\n\nask explain this command: <command>\n\n"
                "No command was executed."
            )
            continue

        if user_input.strip().lower() in {"what did you check?", "what did you check"}:
            artifact_dir = runtime.session.artifact_dir
            files = [
                name
                for name in ("evidence.json", "plan.json", "summary.md", "model-response.md")
                if (artifact_dir / name).exists()
            ]
            pass_kind = (
                "deeper follow-up pass" if completed_followups else "first-pass read-only check"
            )
            console.print(
                f"That was a {pass_kind}. I looked at CPU/memory/load, disk and inode usage, "
                "storage pressure, process activity, container and mount context, recent "
                "trend clues, and network/DNS context.\n"
                "Saved artifacts for this session: "
                f"{', '.join(files) if files else 'none yet'}."
            )
            continue
        if user_input.strip().lower() in {"what tools did you use?", "what tools did you use"}:
            artifact_dir = runtime.session.artifact_dir
            ev_path = artifact_dir / "evidence.json"
            tool_names: list[str] = []
            if ev_path.exists():
                import json as _json

                try:
                    data = _json.loads(ev_path.read_text(encoding="utf-8"))
                    seen_tools: set[str] = set()
                    for it in data.get("items", []):
                        src = (it or {}).get("source")
                        if src and src not in seen_tools:
                            seen_tools.add(src)
                            tool_names.append(src)
                except Exception:
                    tool_names = []
            console.print(
                "Collectors used in the most recent run: "
                f"{', '.join(tool_names) if tool_names else 'none recorded yet'}."
            )
            continue
        service_action_target = _extract_service_action_target(user_input)
        if service_action_target:
            with console.status("Collecting read-only service evidence..."):
                res = diagnose_target(runtime, service_action_target, online=False, since="30m")
            checks = [
                {
                    "tool": i.source,
                    "status": str(i.metadata.get("status", "ok" if i.ok else "unavailable")),
                    "summary": i.summary,
                }
                for i in res.evidence.items
            ]
            console.print(f"Collected {len(checks)} read-only evidence item(s).")
            if evidence_mode == "full":
                _evidence_table(console, checks)
            else:
                console.print("Highlights:")
                for line in _evidence_highlights(checks):
                    console.print(line)
            pending_followup = {
                "intent": "service_health_deep_dive",
                "label": "service health",
                "description": "service manager context, processes, listeners, and logs",
                "bundle": "services",
                "target": service_action_target,
                "created_from_session": runtime.session.session_id,
                "created_from_question": user_input,
                "created_from_intent": service_action_target,
                "first_pass_checks": list(checks),
            }
            console.print(
                f"I can’t execute restart/reload/start/stop from inspect mode. "
                f"I checked {service_action_target} first with read-only evidence. "
                "Service-impacting actions remain operator-run, and apply stays validation-only."
            )
            console.print(
                _operator_followup_text(pending_followup["label"], pending_followup["description"])
            )
            latest_context = build_latest_diagnosis_context(
                session_id=runtime.session.session_id,
                target=service_action_target,
                diagnosis_kind="service health",
                checks=checks,
                facts=_summarize_facts(checks),
                evidence_highlights=_evidence_highlights(checks),
                source_command=user_input,
            )
            update_grounding_from_latest_context(grounding, latest_context)
            _record_latest_context_in_session_summary(session_summary, latest_context)
            session_summary.note_refusal("service restart/start/stop request refused")
            continue
        action_response = _detect_action_request(user_input)
        if action_response is not None:
            session_summary.note_refusal("mutation request refused")
            console.print(action_response)
            continue
        if is_mutation_followup(user_input):
            session_summary.note_refusal("natural-language mutation refused")
            console.print(
                "I can't run fixes or mutations from interactive inspect mode. "
                "Apply stays validation-only and changes need explicit operator approval. "
                "No action was taken."
            )
            if latest_context is not None and latest_context.safe_next_commands:
                console.print("Safe read-only next commands:")
                for c in latest_context.safe_next_commands:
                    console.print(f"- {c}")
            continue
        followup_intent = detect_latest_context_intent(user_input)
        if (
            followup_intent in {"system_role", "health_status", "next_steps"}
            and latest_context is None
        ):
            with console.status("Collecting evidence..."):
                res = diagnose_target(runtime, "health", online=False, since="30m")
            checks = [
                {
                    "tool": i.source,
                    "status": str(i.metadata.get("status", "ok" if i.ok else "unavailable")),
                    "summary": i.summary,
                }
                for i in res.evidence.items
            ]
            console.print(f"Collected {len(checks)} read-only evidence item(s).")
            console.print(_deterministic_operator_summary("health", checks))
            latest_context = build_latest_diagnosis_context(
                session_id=runtime.session.session_id,
                target="health",
                diagnosis_kind="system role/health",
                checks=checks,
                facts=_summarize_facts(checks),
                evidence_highlights=_evidence_highlights(checks),
                findings=[f.title for f in res.findings],
                source_command=user_input,
            )
            update_grounding_from_latest_context(grounding, latest_context)
            _record_latest_context_in_session_summary(session_summary, latest_context)
            if followup_intent is not None:
                console.print(answer_from_latest_context(latest_context, followup_intent))
            continue
        if followup_intent is not None and latest_context is None:
            console.print(no_latest_context_reply())
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
            latest_context = build_latest_diagnosis_context(
                session_id=runtime.session.session_id,
                target="machine health",
                diagnosis_kind="machine health",
                checks=checks,
                facts=_summarize_facts(checks),
                evidence_highlights=_evidence_highlights(checks),
                source_command=user_input,
            )
            update_grounding_from_latest_context(grounding, latest_context)
            _record_latest_context_in_session_summary(session_summary, latest_context)
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
