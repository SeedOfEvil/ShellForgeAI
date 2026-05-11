"""Routing for `shellforgeai ask`.

`ask` is conversational by default. For ops-shaped questions, this
module decides whether to upgrade the call into an evidence-backed
ask that reuses the same read-only routing/evidence collection used
by `diagnose` and the interactive REPL.

There is exactly one source of truth for natural-language intent
matching: ``shellforgeai.interactive.commands.route_input``. This
module is a thin adapter on top of it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from shellforgeai.interactive.commands import _normalize_intent_text, route_input

PLAIN = "plain_model_ask"
EVIDENCE_BACKED = "evidence_backed_ask"


# Surface labels used in prompt briefs. Internal classifier theme keys
# (see tools/containers.py _PROBLEM_PATTERNS) are mapped to these
# operator-facing labels so the model sees consistent vocabulary.
NETWORK_THEME_LABEL = {
    "dns_failure": "dns_resolution",
    "upstream_unreachable": "upstream_unreachable",
    "connection_refused": "connection_refused",
    "timeout": "timeout",
    "tls_certificate": "tls_certificate",
    "unknown_network_error": "unknown_network_error",
}
NETWORK_THEME_KEYS = tuple(NETWORK_THEME_LABEL.keys())


_MUTATION_PHRASES = (
    "restart ",
    "reboot",
    "stop the ",
    "stop service",
    "stop nginx",
    "stop docker",
    "stop ssh",
    "start the ",
    "start service",
    "start nginx",
    "start docker",
    "start ssh",
    "kill ",
    "delete ",
    "remove ",
    "uninstall ",
    "install ",
    "open port",
    "allow port",
    "add firewall",
    "drop firewall",
    "block port",
    "fix the network",
    "fix network",
    "fix dns",
    "change dns",
    "change the dns",
    "edit dns",
    "modify dns",
    "set dns",
    "flush dns",
    "fix firewall",
    "modify firewall",
    "clear logs",
    "delete logs",
    "wipe logs",
    "truncate logs",
    "rotate logs",
    "rm -rf",
    "prune ",
    "docker prune",
    "docker rm",
    "docker stop",
    "docker kill",
    "docker restart",
    "can you restart",
    "can you reboot",
    "can you stop",
    "can you start",
    "can you delete",
    "can you remove",
    "can you install",
    "please restart",
    "please reboot",
)


_FIX_PLAN_TOKENS = (
    "fix plan",
    "safe fix plan",
    "safe fix paln",
    "give me a fix plan",
    "give me a safe fix plan",
    "fix-plan",
    "runbook",
    "run book",
    "runbok",
    "runboook",
    "operator runbook",
    "remediation",
    "remeditation",
    "remdiation",
    "rollback plan",
    "repair plan",
    "safe operator",
    "safe operator steps",
    "post-fix validation",
    "post fix validation",
    "prechecks before",
    "fix failed containers safely",
    "fix bad-network safely",
    "fix bad network safely",
    "fix write permissions safely",
    "fix missing env safely",
    "fix missing-env safely",
    "what should i do next",
    "what shoud i do next",
    "how do i fix this safely",
    "how do i fix this",
    "fix this safely",
)


_NETWORK_REACH_TOKENS = (
    "reachab",
    "reechab",
    "upstream",
    "upstram",
    "dns error",
    "dns erro",
    "dns erorr",
    "connection refused",
    "coneccion refused",
    "timeout",
    "timout",
    "cant reach",
    "cannot reach",
    "can not reach",
    "reach the server",
    "reach upstream",
    "reach the upstream",
    "container network",
    "network errors",
    "network reachability",
    "netwrok reachab",
    "service dependency unreach",
    "bad network",
    "bad-network",
)


@dataclass(frozen=True)
class AskRoute:
    """Decision returned by :func:`route_ask_intent`."""

    mode: str
    target: str = ""
    intent_label: str = ""
    mutation_request: bool = False
    network_reachability: bool = False
    fix_plan: bool = False


def is_mutation_request(text: str) -> bool:
    lowered = _normalize_intent_text(text or "")
    return any(p in lowered for p in _MUTATION_PHRASES)


def is_fix_plan_intent(text: str) -> bool:
    """Detect questions asking for an operator-run fix plan / runbook."""
    lowered = _normalize_intent_text(text or "")
    raw_lower = (text or "").lower()
    return any(t in lowered for t in _FIX_PLAN_TOKENS) or any(
        t in raw_lower for t in _FIX_PLAN_TOKENS
    )


_APPLY_APPROVED_TOKENS = (
    "apply the approved proposal",
    "apply approved proposal",
    "apply the approved fix",
    "apply approved fix",
    "run the approved proposal",
    "run the approved fix",
    "run approved fix",
    "can you run the approved",
    "can you apply the approved",
    "can you apply the proposal",
    "execute the approved",
    "execute approved",
    "prepare the approved fix bundle",
    "prepare the approved bundle",
    "prepare approved bundle",
    "prepare the operator bundle",
    "prepare the apply bundle",
    "generate operator script for approved",
    "generate the operator script for approved",
    "generate operator bundle",
    "build operator bundle",
    "dry run the approved proposal",
    "dry-run the approved proposal",
    "dry run the approved fix",
    "dry-run the approved fix",
)


@dataclass(frozen=True)
class ApplyApprovedIntent:
    matched: bool
    dry_run: bool = False
    execute: bool = False


def is_apply_approved_intent(text: str) -> ApplyApprovedIntent:
    """Detect ask requests about applying/running an approved proposal.

    ShellForgeAI never executes mutation. The CLI uses this to refuse run
    requests politely and to offer the preflight bundle when appropriate.
    """
    raw = (text or "").lower()
    if not any(tok in raw for tok in _APPLY_APPROVED_TOKENS):
        return ApplyApprovedIntent(matched=False)
    dry_run = any(
        tok in raw
        for tok in (
            "dry run",
            "dry-run",
            "prepare",
            "preview",
            "generate operator",
            "generate the operator",
            "build operator",
        )
    )
    execute = any(
        tok in raw
        for tok in (
            "run the approved",
            "run approved",
            "execute the approved",
            "execute approved",
            "apply the approved",
            "apply approved",
            "can you run",
            "can you apply",
        )
    )
    return ApplyApprovedIntent(matched=True, dry_run=dry_run, execute=execute)


def is_network_reachability_intent(text: str) -> bool:
    """Detect questions that focus on app/network reachability or upstream failures."""
    lowered = _normalize_intent_text(text or "")
    raw_lower = (text or "").lower()
    if any(tok in lowered for tok in _NETWORK_REACH_TOKENS):
        return True
    return any(tok in raw_lower for tok in _NETWORK_REACH_TOKENS)


def route_ask_intent(text: str) -> AskRoute:
    """Decide whether an ``ask`` question should collect read-only evidence.

    Returns ``plain_model_ask`` for generic Q&A and ``evidence_backed_ask``
    when the natural-language router maps the question to a known diagnose
    target. The third runtime mode (``evidence_required_but_unavailable``)
    is decided at evidence-collection time, not here, since this routing
    layer cannot know whether collectors will succeed.
    """

    raw = (text or "").strip()
    if not raw:
        return AskRoute(mode=PLAIN)

    mutation = is_mutation_request(raw)
    routed = route_input(raw)
    net_reach = is_network_reachability_intent(raw)
    fix_plan = is_fix_plan_intent(raw)

    if routed.name == "diagnose" and routed.args:
        target = routed.args
        if fix_plan:
            intent = "fix_plan"
        elif net_reach:
            intent = "network_reachability"
        else:
            intent = target
        return AskRoute(
            mode=EVIDENCE_BACKED,
            target=target,
            intent_label=intent,
            mutation_request=mutation,
            network_reachability=net_reach,
            fix_plan=fix_plan,
        )
    if routed.name == "logs_mutation_refused":
        return AskRoute(
            mode=EVIDENCE_BACKED,
            target="logs",
            intent_label="logs",
            mutation_request=True,
            network_reachability=net_reach,
            fix_plan=fix_plan,
        )
    if fix_plan:
        # Fix-plan requests should always collect docker evidence as a sane
        # default when the underlying NL router does not pick a target.
        return AskRoute(
            mode=EVIDENCE_BACKED,
            target="docker",
            intent_label="fix_plan",
            mutation_request=mutation,
            network_reachability=net_reach,
            fix_plan=True,
        )
    return AskRoute(
        mode=PLAIN,
        mutation_request=mutation,
        network_reachability=net_reach,
        fix_plan=fix_plan,
    )


_LAB_CONTAINER_HINTS = {
    "bad-network": "sfai-bad-network",
    "bad network": "sfai-bad-network",
    "missing-env": "sfai-missing-env",
    "missing env": "sfai-missing-env",
    "restart-loop": "sfai-restart-loop",
    "restart loop": "sfai-restart-loop",
    "noisy-logs": "sfai-noisy-logs",
    "noisy logs": "sfai-noisy-logs",
    "bad-volume-perms": "sfai-bad-volume-perms",
    "bad volume perms": "sfai-bad-volume-perms",
    "healthy-web": "sfai-healthy-web",
    "healthy web": "sfai-healthy-web",
    "healthy webservice": "sfai-healthy-web",
    "the healthy web service": "sfai-healthy-web",
}


def extract_container_target(text: str) -> str:
    """Return a likely sfai-* container name when the question names a lab case.

    Used so reachability questions like "why is bad-network failing?" pin the
    answer to ``sfai-bad-network`` and are not buried under generic Docker
    aggregates.
    """
    raw = (text or "").lower()
    for hint, container in _LAB_CONTAINER_HINTS.items():
        if hint in raw:
            return container
    m = re.search(r"\bsfai-[a-z0-9][a-z0-9._-]{1,40}", raw)
    if m:
        return m.group(0)
    return ""


def network_reachability_brief(
    findings,
    evidence_items,
    *,
    target_container: str = "",
    max_containers: int = 10,
    max_findings: int = 12,
):
    """Build a network-reachability-focused evidence brief.

    The compact ``evidence_brief`` used for general ops asks does not surface
    per-container log themes — `docker.problem_summary` is reduced to a single
    one-line summary and runtime network basics dominate. For reachability
    questions that loses the most important signal: a running container that
    is logging DNS/upstream failures.

    This brief separates evidence into two clearly labelled blocks so the
    model can rank them correctly:

    - ``container_log_evidence``: every visible container with any network
      log theme (running or failing), with theme labels and a bounded log
      sample. Targeted containers (e.g. ``sfai-bad-network`` when the user
      asked about ``bad-network``) are pinned to the front and never
      truncated out.
    - ``runtime_network_basics``: DNS resolver, default route, listeners,
      firewall context — labelled so the model knows these are namespace-
      local checks, not proof of host-wide reachability.
    """

    payload: dict = {}
    summary_item = next(
        (i for i in evidence_items if getattr(i, "source", "") == "docker.problem_summary"),
        None,
    )
    if summary_item is not None and getattr(summary_item, "ok", False):
        try:
            payload = json.loads(getattr(summary_item, "content", "") or "{}")
        except (ValueError, json.JSONDecodeError):
            payload = {}

    def _row(entry: dict, bucket: str) -> dict | None:
        themes = entry.get("log_themes") or {}
        labels = [NETWORK_THEME_LABEL[k] for k in NETWORK_THEME_KEYS if themes.get(k)]
        if not labels:
            return None
        sample = [str(line)[:200] for line in (entry.get("log_sample") or [])][-3:]
        return {
            "container": entry.get("name") or "",
            "state": entry.get("state") or "",
            "bucket": bucket,
            "themes": labels,
            "exit_code": entry.get("exit_code"),
            "log_sample": sample,
        }

    container_rows: list[dict] = []
    for entry in payload.get("failing", []) or []:
        r = _row(entry, "failing")
        if r:
            container_rows.append(r)
    for entry in payload.get("noisy", []) or []:
        r = _row(entry, "noisy")
        if r:
            container_rows.append(r)

    if target_container:
        container_rows.sort(key=lambda r: 0 if r.get("container") == target_container else 1)

    if len(container_rows) > max_containers:
        # Always keep the targeted container even if many entries exist.
        kept = []
        if target_container:
            kept.extend([r for r in container_rows if r.get("container") == target_container])
        for r in container_rows:
            if r in kept:
                continue
            if len(kept) >= max_containers:
                break
            kept.append(r)
        container_rows = kept

    runtime_rows: list[dict] = []
    runtime_sources = (
        "network.resolution_test",
        "network.default_route",
        "network.dns",
        "network.listeners",
        "network.firewall_context",
        "system.container_detect",
    )
    for src in runtime_sources:
        item = next(
            (i for i in evidence_items if getattr(i, "source", "") == src),
            None,
        )
        if item is None:
            continue
        runtime_rows.append(
            {
                "source": src,
                "ok": bool(getattr(item, "ok", False)),
                "summary": (getattr(item, "summary", "") or "").splitlines()[0][:200],
            }
        )

    f_rows: list[dict] = []
    network_kw = (
        "dns",
        "upstream",
        "reachab",
        "connection refused",
        "timeout",
        "tls",
        "certificate",
    )
    # Pin findings whose title mentions the target container or network themes.
    sorted_findings = sorted(
        list(findings),
        key=lambda f: (
            0
            if target_container and target_container in (getattr(f, "title", "") or "")
            else (1 if any(k in (getattr(f, "title", "") or "").lower() for k in network_kw) else 2)
        ),
    )
    for f in sorted_findings[:max_findings]:
        f_rows.append(
            {
                "severity": getattr(f, "severity", "info"),
                "title": getattr(f, "title", ""),
                "detail": (getattr(f, "detail", "") or "")[:400],
            }
        )

    return {
        "target_container": target_container,
        "container_log_evidence": container_rows,
        "runtime_network_basics": runtime_rows,
        "findings": f_rows,
        "note": (
            "container_log_evidence is application/container-level proof of "
            "reachability failure. runtime_network_basics are namespace-local "
            "checks and do NOT cancel container_log_evidence. Rank "
            "container_log_evidence first; treat reachability as an app/"
            "container dependency issue unless runtime evidence proves a "
            "host-wide outage."
        ),
    }


def target_container_status(evidence_items, target_container: str):
    """Return a compact status dict for the named container, if visible.

    Looks at ``docker.containers`` (full inventory, includes healthy
    containers) and ``docker.problem_summary`` (failing/noisy buckets with
    log themes). Returns ``None`` if Docker is not visible or the container
    is not present. Used so the model can confidently say e.g.
    ``sfai-healthy-web is running and healthy`` instead of falling back to
    a local-process check that fails inside the ShellForgeAI container.
    """

    if not target_container:
        return None
    inv_item = next(
        (i for i in evidence_items if getattr(i, "source", "") == "docker.containers"),
        None,
    )
    if inv_item is None or not getattr(inv_item, "ok", False):
        return None
    try:
        inv_payload = json.loads(getattr(inv_item, "content", "") or "{}")
    except (ValueError, json.JSONDecodeError):
        inv_payload = {}
    row = next(
        (
            r
            for r in (inv_payload.get("containers") or [])
            if (r.get("name") or "") == target_container
        ),
        None,
    )
    if row is None:
        return None

    summary_item = next(
        (i for i in evidence_items if getattr(i, "source", "") == "docker.problem_summary"),
        None,
    )
    health = None
    log_themes: dict = {}
    log_sample: list = []
    bucket = "healthy"
    if summary_item is not None and getattr(summary_item, "ok", False):
        try:
            payload = json.loads(getattr(summary_item, "content", "") or "{}")
        except (ValueError, json.JSONDecodeError):
            payload = {}
        for entry in payload.get("failing", []) or []:
            if entry.get("name") == target_container:
                bucket = "failing"
                health = entry.get("health")
                log_themes = entry.get("log_themes") or {}
                log_sample = [str(s)[:200] for s in (entry.get("log_sample") or [])][-3:]
                break
        else:
            for entry in payload.get("noisy", []) or []:
                if entry.get("name") == target_container:
                    bucket = "noisy"
                    health = entry.get("health")
                    log_themes = entry.get("log_themes") or {}
                    log_sample = [str(s)[:200] for s in (entry.get("log_sample") or [])][-3:]
                    break
    status = (row.get("status") or "").lower()
    if health is None:
        if "healthy" in status:
            health = "healthy"
        elif "unhealthy" in status:
            health = "unhealthy"
    return {
        "name": target_container,
        "image": row.get("image") or "",
        "state": row.get("state") or "",
        "status": row.get("status") or "",
        "health": health,
        "bucket": bucket,
        "log_themes": [NETWORK_THEME_LABEL.get(k, k) for k in log_themes if log_themes.get(k)],
        "log_sample": log_sample,
    }


def _docker_problem_rows(evidence_items, max_rows: int = 8) -> list[dict]:
    summary_item = next(
        (i for i in evidence_items if getattr(i, "source", "") == "docker.problem_summary"), None
    )
    if summary_item is None or not getattr(summary_item, "ok", False):
        return []
    try:
        payload = json.loads(getattr(summary_item, "content", "") or "{}")
    except (ValueError, json.JSONDecodeError):
        return []
    rows: list[dict] = []
    for bucket in ("failing", "noisy", "healthy"):
        for entry in payload.get(bucket, []) or []:
            rows.append(
                {
                    "bucket": bucket,
                    "name": entry.get("name"),
                    "state": entry.get("state"),
                    "exit_code": entry.get("exit_code"),
                    "themes": [k for k, v in (entry.get("log_themes") or {}).items() if v],
                }
            )
            if len(rows) >= max_rows:
                return rows
    return rows


def evidence_brief(findings, evidence_items, *, max_findings: int = 8, max_evidence: int = 12):
    """Produce a compact dict suitable for prompt context.

    Keeps the evidence brief small so the model focuses on signal, not noise.
    """

    f_rows = []
    for f in list(findings)[:max_findings]:
        f_rows.append(
            {
                "severity": getattr(f, "severity", "info"),
                "title": getattr(f, "title", ""),
                "detail": getattr(f, "detail", "")[:400],
            }
        )
    e_rows = []
    for i in list(evidence_items)[:max_evidence]:
        e_rows.append(
            {
                "source": getattr(i, "source", "unknown"),
                "ok": bool(getattr(i, "ok", False)),
                "title": getattr(i, "title", "")[:120],
                "summary": (getattr(i, "summary", "") or "").splitlines()[0][:240],
            }
        )
    brief = {"findings": f_rows, "evidence": e_rows}
    drows = _docker_problem_rows(evidence_items)
    if drows:
        brief["docker_problem_rows"] = drows
    return brief
