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


# PR82 — broad read-only Docker/2AM triage ask intent.
#
# Detect ops-shaped natural-language prompts that mean "rank the Docker
# scene" rather than naming a specific container. These route to the
# deterministic PR81 ``triage docker`` engine and never to a model-only
# rephrase or to mutation. The phrase list stays narrow and read-only —
# mutation intent (``restart …``, ``fix …``, ``clean up …``) continues
# to refuse via the existing PR47/PR74-PR80 paths.
_BROAD_DOCKER_TRIAGE_PHRASES: tuple[str, ...] = (
    "what's on fire",
    "whats on fire",
    "what is on fire",
    "2am triage",
    "2 am triage",
    "2am docker",
    "docker box feels broken",
    "the docker box feels broken",
    "docker feels broken",
    "docker is broken",
    "broadly scan the current scene",
    "broadly scan the scene",
    "broad scan of the scene",
    "broad scan of docker",
    "rank docker suspects",
    "rank the docker suspects",
    "rank all docker suspects",
    "rank docker containers",
    "rank the docker containers",
    "rank all sfai-battle-lab suspects",
    "rank all battle-lab suspects",
    "rank all battle lab suspects",
    "rank sfai-battle-lab suspects",
    "rank battle-lab suspects",
    "rank battle lab suspects",
    "what should i inspect first",
    "what should i look at first",
    "show current docker suspects",
    "show docker suspects",
    "show me docker suspects",
    "what containers look suspicious",
    "which containers look suspicious",
    "what docker containers look suspicious",
    "which docker containers look suspicious",
    "scan the scene",
    "scan the current scene",
    "scan docker scene",
    "scan the docker scene",
    "triage the docker box",
    "triage docker box",
    "triage docker scene",
    "rank the suspects",
)


_BROAD_TRIAGE_TOKEN_HINTS: tuple[tuple[str, ...], ...] = (
    # "rank … docker … suspects" style phrasings that survive paraphrase.
    ("rank", "docker", "suspect"),
    ("rank", "docker", "container"),
    ("rank", "battle-lab", "suspect"),
    ("rank", "battle lab", "suspect"),
    ("rank", "sfai-battle-lab", "suspect"),
    ("scan", "docker", "scene"),
    ("scan", "current", "scene"),
    ("triage", "docker", "scene"),
)

_BRIEF_OPS_REPORT_ASK_PHRASES: tuple[str, ...] = (
    "no novel",
    "give me the short version",
    "short version",
    "i have five minutes",
    "i'm half awake",
    "im half awake",
    "half awake",
    "quick status",
    "2am quick status",
    "2 am quick status",
    "what is on fire keep it short",
    "what is on fire, keep it short",
    "keep it short",
)

_OPS_REPORT_ASK_PHRASES: tuple[str, ...] = (
    "operator report",
    "ops report",
    "2am report",
    "2 am report",
    "summarize current docker incidents",
    "summarize docker incidents",
    "what should i check first",
    "what should i look at first",
    "rank current suspects",
    "rank suspects and tell me what to inspect",
    "what is on fire in docker",
    "2am what is on fire",
    "2 am what is on fire",
    "2am, what is on fire",
    "2 am, what is on fire",
    *_BRIEF_OPS_REPORT_ASK_PHRASES,
)


def is_broad_docker_triage_intent(text: str) -> bool:
    """Detect a broad read-only Docker triage ask intent.

    True when the prompt asks for a broad scene-level ranking of Docker
    suspects ("what's on fire?", "2AM triage", "the Docker box feels
    broken", "rank Docker suspects", "broadly scan the current scene",
    "rank all sfai-battle-lab suspects", "what containers look
    suspicious?", etc.). Always returns False if the prompt also
    matches a mutation phrase — mutation refusal is handled by the
    existing PR47/PR74-PR80 paths and the triage-mutation helper.
    """
    raw = (text or "").strip()
    if not raw:
        return False
    if is_mutation_request(raw):
        return False
    if is_triage_mutation_intent(raw):
        return False
    lowered = _normalize_intent_text(raw)
    raw_lower = raw.lower()
    if any(phrase in lowered or phrase in raw_lower for phrase in _BROAD_DOCKER_TRIAGE_PHRASES):
        return True
    return any(all(tok in lowered for tok in tokens) for tokens in _BROAD_TRIAGE_TOKEN_HINTS)


def is_brief_ops_report_ask(text: str) -> bool:
    """Detect pressure-mode ask prompts that should render brief ops report output."""
    raw = (text or "").strip()
    if not raw:
        return False
    if is_mutation_request(raw) or is_triage_mutation_intent(raw):
        return False
    lowered = _normalize_intent_text(raw)
    raw_lower = raw.lower()
    return any(phrase in lowered or phrase in raw_lower for phrase in _BRIEF_OPS_REPORT_ASK_PHRASES)


def is_ops_report_ask(text: str) -> bool:
    """Detect ask prompts that should route to deterministic ``ops report``."""
    raw = (text or "").strip()
    if not raw:
        return False
    if is_mutation_request(raw) or is_triage_mutation_intent(raw):
        return False
    lowered = _normalize_intent_text(raw)
    raw_lower = raw.lower()
    return any(phrase in lowered or phrase in raw_lower for phrase in _OPS_REPORT_ASK_PHRASES)


# PR82 — natural-language mutation phrasings tied to triage rankings.
#
# These prompts mean "ShellForgeAI, please go fix the top suspect"
# rather than "rank them". They must refuse from ask: the broad ask
# triage route never executes restart/cleanup/apply/proposal/mission
# work, and the existing CLI gates remain the only path.
_TRIAGE_MUTATION_PHRASES: tuple[str, ...] = (
    "restart the top suspect",
    "restart top suspect",
    "restart the top",
    "fix the top suspect",
    "fix the crashloop",
    "fix crashloop",
    "fix the crash loop",
    "fix crash loop",
    "fix the noisy errors",
    "fix the noisy-errors",
    "fix the bad-http",
    "fix the bad http",
    "fix the disk pressure",
    "fix the disk-pressure",
    "fix permission denied",
    "fix the permission denied",
    "fix the permission-denied",
    "clean up disk pressure",
    "clean up disk-pressure",
    "clean up disk pressure now",
    "clean up disk space",
    "stop noisy-errors",
    "stop noisy errors",
    "stop the noisy-errors",
    "stop the noisy errors",
    "stop the noisy",
    "apply the top fix",
    "apply top fix",
    "apply the fix",
    "create a restart proposal for the top suspect",
    "create restart proposal for the top suspect",
    "create restart proposal for top suspect",
    "docker compose restart the top",
    "docker compose restart the top one",
    "compose restart the top",
    "delete old files causing disk pressure",
    "delete files causing disk pressure",
)


def is_triage_mutation_intent(text: str) -> bool:
    """Detect mutation phrasings that follow a triage ranking.

    Used by the broad-triage ask handler so prompts like ``restart the
    top suspect`` / ``fix the crashloop`` / ``clean up disk pressure
    now`` refuse cleanly from ask. This helper never triggers a
    deterministic triage render and never executes mutation.
    """
    raw = (text or "").strip()
    if not raw:
        return False
    lowered = _normalize_intent_text(raw)
    raw_lower = raw.lower()
    return any(phrase in lowered or phrase in raw_lower for phrase in _TRIAGE_MUTATION_PHRASES)


_LAB_RESTART_ASK_TOKENS = (
    "restart the container",
    "restart container",
    "restart that container",
    "restart this container",
    "restart the lab container",
    "restart lab container",
    "run the approved restart",
    "run approved restart",
    "apply the approved restart",
    "apply approved restart",
    "execute the approved restart",
    "execute approved restart",
    "perform the restart",
    "perform restart",
    "do the restart",
    "kick the container",
    "bounce the container",
    "bounce container",
)


@dataclass(frozen=True)
class LabRestartAskIntent:
    matched: bool
    container: str = ""


_LAB_RESTART_VERIFICATION_TOKENS = (
    "did the restart work",
    "did restart work",
    "did the lab restart work",
    "did the container restart work",
    "show restart verification",
    "show post-mutation verification",
    "show post mutation verification",
    "show verification",
    "show last execution receipt",
    "show last receipt",
    "show last restart receipt",
    "was the container running after restart",
    "was the container running after the restart",
    "is the container running after restart",
    "post-restart verification",
    "post restart verification",
    "verify the restart",
    "verify restart",
    "verification status",
    "restart verification",
)

_RESTART_AND_VERIFY_TOKENS = (
    "restart it and verify",
    "restart and verify",
    "restart then verify",
    "kick it and verify",
    "bounce and verify",
    "restart the container and verify",
)


def is_lab_restart_ask_intent(text: str) -> LabRestartAskIntent:
    """Detect natural-language requests to actually run a (lab) container restart.

    PR47 lab restart can only happen through explicit CLI gates
    (``apply --execute --confirm``). Ask must refuse and direct the operator
    to the CLI.
    """
    raw = (text or "").lower()
    if not raw:
        return LabRestartAskIntent(matched=False)
    # PR48: "restart it and verify" still asks ShellForgeAI to mutate from ask.
    # That falls under restart-execute refusal (verification runs automatically
    # only after the CLI gate).
    if any(tok in raw for tok in _RESTART_AND_VERIFY_TOKENS):
        return LabRestartAskIntent(matched=True, container=extract_container_target(text))
    if any(tok in raw for tok in _LAB_RESTART_ASK_TOKENS):
        return LabRestartAskIntent(matched=True, container=extract_container_target(text))
    # Also catch "restart sfai-<name>" / "docker restart sfai-<name>" phrasings.
    # Scoped to the ShellForgeAI lab container prefix so we do not hijack
    # generic phrasings like "can you restart nginx?" which should fall
    # through to evidence-backed diagnose routing.
    m = re.search(r"\brestart\s+(sfai[-_][a-zA-Z0-9_.\-]{1,127})\b", raw)
    if m:
        return LabRestartAskIntent(matched=True, container=m.group(1).strip())
    return LabRestartAskIntent(matched=False)


@dataclass(frozen=True)
class LabRestartVerificationAskIntent:
    """PR48: read-only ask intent — show the most recent restart verification."""

    matched: bool


def is_lab_restart_verification_ask_intent(text: str) -> LabRestartVerificationAskIntent:
    """Detect read-only questions about the last restart verification.

    These never execute mutation; they read the most recent execution receipt
    and audit event and summarize verification status. ``"restart it and
    verify"`` is *not* matched here — that is mutation intent and is routed
    to :func:`is_lab_restart_ask_intent` for refusal.
    """
    raw = (text or "").lower().strip()
    if not raw:
        return LabRestartVerificationAskIntent(matched=False)
    # Mutation phrasings ("restart and verify") must not match here.
    if any(tok in raw for tok in _RESTART_AND_VERIFY_TOKENS):
        return LabRestartVerificationAskIntent(matched=False)
    if any(tok in raw for tok in _LAB_RESTART_VERIFICATION_TOKENS):
        return LabRestartVerificationAskIntent(matched=True)
    return LabRestartVerificationAskIntent(matched=False)


def is_fix_plan_intent(text: str) -> bool:
    """Detect questions asking for an operator-run fix plan / runbook."""
    lowered = _normalize_intent_text(text or "")
    raw_lower = (text or "").lower()
    return any(t in lowered for t in _FIX_PLAN_TOKENS) or any(
        t in raw_lower for t in _FIX_PLAN_TOKENS
    )


_CREATE_PROPOSALS_TOKENS = (
    "create approval proposals",
    "create approval proposal",
    "approval proposals from latest runbook",
    "approval proposals from the latest runbook",
    "approval proposals from latest",
    "queue the safe fixes for approval",
    "queue the safe fixes",
    "queue safe fixes",
    "make approval proposals",
    "make an approval proposal",
    "prepare changes for approval",
    "prepare the changes for approval",
    "stage the remediation plan for approval",
    "stage the remediation plan",
    "stage remediation for approval",
    "create pending fixes",
    "put those fixes in the approval queue",
    "put these fixes in the approval queue",
    "put the fixes in the approval queue",
    "queue these fixes for approval",
    "queue those fixes for approval",
)


_IMMEDIATE_FIX_TOKENS = (
    "approve and run the fix",
    "approve and run the fixes",
    "approve and apply",
    "approve and execute",
    "fix everything now",
    "fix it now",
    "fix this now",
    "just fix it",
    "just fix everything",
    "apply the fix now",
    "apply the fixes now",
    "run the fix now",
    "run the fixes now",
)


@dataclass(frozen=True)
class CreateProposalsIntent:
    matched: bool


def is_create_proposals_intent(text: str) -> CreateProposalsIntent:
    """Detect ask phrasing that asks ShellForgeAI to queue proposals."""
    raw = (text or "").lower()
    if any(tok in raw for tok in _CREATE_PROPOSALS_TOKENS):
        return CreateProposalsIntent(matched=True)
    return CreateProposalsIntent(matched=False)


@dataclass(frozen=True)
class CreateRestartProposalIntent:
    matched: bool
    container: str = ""


def is_create_restart_proposal_intent(text: str) -> CreateRestartProposalIntent:
    raw = (text or "").lower()
    hints = (
        "propose restart for ",
        "create restart proposal for ",
        "prepare safe restart proposal for ",
        "build a restart approval for ",
        "can shellforgeai restart ",
    )
    if not any(h in raw for h in hints):
        return CreateRestartProposalIntent(matched=False)
    return CreateRestartProposalIntent(matched=True, container=extract_container_target(text))


def is_immediate_fix_intent(text: str) -> bool:
    """Detect 'approve and run / fix everything now' style asks."""
    raw = (text or "").lower()
    return any(tok in raw for tok in _IMMEDIATE_FIX_TOKENS)


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


_COMPOSE_MUTATION_PHRASES = (
    "docker compose restart",
    "restart compose service",
    "restart the compose service",
    "compose restart",
    "compose up",
    "docker compose up",
    "compose down",
    "docker compose down",
    "recreate compose service",
    "fix compose service now",
    "propose restart for compose service",
    "create compose restart proposal",
    "prepare compose restart proposal",
    "build a compose restart proposal",
    "build compose restart proposal",
    "make a compose restart proposal",
    "convert this to compose restart",
    "run docker compose restart",
    "execute compose restart preview",
    "apply compose restart",
)


_COMPOSE_SERVICE_MUTATION_PROPOSAL_PHRASES = (
    "propose restart for compose service",
    "create compose restart proposal for",
    "compose restart proposal for",
    "restart proposal for compose service",
    "build a compose restart proposal",
    "make a compose restart proposal",
    "prepare a compose restart proposal",
    "convert this to compose restart",
)


def is_compose_service_mutation_proposal_request(text: str) -> bool:
    """Detect a request to create a Compose service-level restart mutation.

    PR58 only enriches Compose context. ShellForgeAI does not build proposals
    for ``docker compose restart <service>``; this helper lets the CLI refuse
    such requests cleanly.
    """
    raw = (text or "").lower()
    if any(p in raw for p in _COMPOSE_SERVICE_MUTATION_PROPOSAL_PHRASES):
        return True
    return is_compose_mutation_request(text)


_COMPOSE_TARGET_PATTERNS = (
    r"\bcompose\s+context\s+for\s+['\"]?([a-z0-9][a-z0-9._-]{0,63})['\"]?",
    r"\bcompose\s+inspect\s+['\"]?([a-z0-9][a-z0-9._-]{0,63})['\"]?",
    r"\bcompose\s+project\s+owns\s+['\"]?([a-z0-9][a-z0-9._-]{0,63})['\"]?",
    r"\bcompose\s+service\s+is\s+['\"]?([a-z0-9][a-z0-9._-]{0,63})['\"]?",
    r"\bis\s+['\"]?([a-z0-9][a-z0-9._-]{0,63})['\"]?\s+compose\s+managed\b",
    r"\bcompose\s+file\s+owns\s+['\"]?([a-z0-9][a-z0-9._-]{0,63})['\"]?",
    r"\bcompose\s+labels\s+for\s+['\"]?([a-z0-9][a-z0-9._-]{0,63})['\"]?",
    r"\bcontainer\s+['\"]?([a-z0-9][a-z0-9._-]{0,63})['\"]?",
    r":\s*['\"]?([a-z0-9][a-z0-9._-]{0,63})['\"]?\s*$",
)


def is_compose_mutation_request(text: str) -> bool:
    lowered = _normalize_intent_text(text or "")
    return any(p in lowered for p in _COMPOSE_MUTATION_PHRASES)


_RESTART_PROPOSAL_COMPOSE_CONTEXT_PHRASES = (
    "show compose context for this restart proposal",
    "show compose context for the restart proposal",
    "show restart proposal compose context",
    "is this restart proposal compose managed",
    "is this restart proposal compose-managed",
    "what compose service owns the restart target",
    "what compose project owns the restart target",
    "is the restart scope container or compose service",
    "is the restart scope container or compose",
    "compose context for this restart proposal",
)

_MISSION_COMPOSE_CONTEXT_PHRASES = (
    "is this mission targeting a compose service",
    "is the mission targeting a compose service",
    "is this mission compose managed",
    "is this mission compose-managed",
    "show compose context for this mission",
    "show compose context for this restart mission",
    "show compose context for latest restart mission",
    "show compose context for the latest restart mission",
    "show compose context for current restart mission",
    "show compose context for most recent restart mission",
    "show mission compose context",
)


def is_restart_proposal_compose_context_query(text: str) -> bool:
    raw = (text or "").lower()
    return any(p in raw for p in _RESTART_PROPOSAL_COMPOSE_CONTEXT_PHRASES)


def is_mission_compose_context_query(text: str) -> bool:
    raw = (text or "").lower()
    return any(p in raw for p in _MISSION_COMPOSE_CONTEXT_PHRASES)


def has_compose_artifact_reference_phrase(text: str) -> bool:
    """Return True when compose ask references implicit proposal/mission artifacts.

    These phrases should be handled by proposal/mission reference routes before
    generic compose target extraction.
    """
    raw = (text or "").lower()
    if "compose" not in raw or "context" not in raw:
        return False
    if ("proposal" not in raw) and ("mission" not in raw):
        return False
    return any(tok in raw for tok in ("this", "latest", "current", "most recent"))


def extract_compose_target(text: str) -> str:
    raw = (text or "").strip()
    if any(ch in raw for ch in (";", "&", "|", "$", "`", ">", "<", "\n", "\r", "\t")):
        return ""
    lowered = _normalize_intent_text(raw)
    for pattern in _COMPOSE_TARGET_PATTERNS:
        m = re.search(pattern, lowered)
        if m:
            target = (m.group(1) or "").strip("'\"")
            return target if _is_valid_compose_target(target) else ""
    return ""


def _is_valid_compose_target(target: str) -> bool:
    if not target:
        return False
    if any(ch.isspace() for ch in target):
        return False
    if any(ch in target for ch in (";", "&", "|", "$", "`", ">", "<", "(", ")")):
        return False
    if "/" in target or "\\" in target:
        return False
    if target.startswith("-"):
        return False
    return re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", target) is not None


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
