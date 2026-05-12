"""Policy-gated action compiler (PR37).

Turns an approved :class:`Proposal`'s operator-run steps into structured,
review-only action records on disk. **ShellForgeAI does not execute
anything.** Every compiled action carries ``execution_allowed=false`` and
the top-level record carries ``execution_status=not_executed``.

The compiler uses deterministic string/regex matching only. There is no
LLM call, no shell execution, no Docker/network mutation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shellforgeai.core.approvals import (
    STATUS_APPROVED,
    STATUS_CANCELED,
    STATUS_PENDING,
    STATUS_REJECTED,
    Proposal,
    find_proposal_path,
    latest_approved_proposal,
    load_proposal_from_path,
)

ACTIONS_SCHEMA_VERSION = "1"

EXECUTION_ALLOWED = False
EXECUTION_STATUS_NOT_EXECUTED = "not_executed"
COMPILED_STATUS = "compiled"

SAFETY_LINE = "ShellForgeAI compiled this action plan but did not execute anything."

ACTIONS_FILES = ("actions.json", "actions.md")


# Decisions
DECISION_READ_ONLY = "read_only_review"
DECISION_MANUAL_ONLY = "manual_only"
DECISION_BLOCKED = "blocked"

# Risk
RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"

# Kinds / operations
KIND_DOCKER = "docker"
KIND_FILESYSTEM = "filesystem"
KIND_PACKAGE = "package"
KIND_SERVICE = "service"
KIND_NETWORK = "network"
KIND_FIREWALL = "firewall"
KIND_MANUAL = "manual"
KIND_UNKNOWN = "unknown"

OP_INSPECT = "inspect"
OP_LOGS = "logs"
OP_EDIT_CONFIG = "edit_config"
OP_RESTART = "restart"
OP_RECREATE = "recreate"
OP_CHMOD = "chmod"
OP_CHOWN = "chown"
OP_INSTALL = "install"
OP_DELETE = "delete"
OP_MANUAL_REVIEW = "manual_review"
OP_UNKNOWN = "unknown"


# Labels we strip from the beginning of operator-run lines for normalization.
LEADING_LABELS = (
    "OPERATOR-RUN",
    "PRECHECK",
    "VERIFY",
    "ROLLBACK",
    "REQUIRES APPROVAL",
    "SERVICE-IMPACTING",
    "FILESYSTEM-MUTATION",
    "PACKAGE-MUTATION",
    "NETWORK-MUTATION",
    "FIREWALL-MUTATION",
)

_LABEL_PREFIX_RE = re.compile(
    r"^\s*(?:{names})\s*[:\-]\s*".format(names="|".join(re.escape(lbl) for lbl in LEADING_LABELS)),
    re.IGNORECASE,
)


def _strip_leading_labels(text: str) -> tuple[str, list[str]]:
    """Strip leading label prefixes and return ``(stripped, labels_found)``."""
    labels: list[str] = []
    out = (text or "").strip()
    changed = True
    while changed:
        changed = False
        m = _LABEL_PREFIX_RE.match(out)
        if m:
            matched = m.group(0).strip().rstrip(":-").strip()
            # Recover the canonical label text from LEADING_LABELS.
            for lbl in LEADING_LABELS:
                if matched.upper() == lbl.upper():
                    if lbl not in labels:
                        labels.append(lbl)
                    break
            out = out[m.end() :].lstrip()
            changed = True
    return out, labels


def _strip_inline_label_suffix(text: str) -> tuple[str, list[str]]:
    """Strip trailing ``# SERVICE-IMPACTING`` style inline labels.

    Preserves arbitrary inline comments that are not known labels.
    Returns ``(stripped, labels_found)``.
    """
    labels: list[str] = []
    out = text
    # Match "  # LABEL" or "# LABEL" only when LABEL is one of our known labels.
    pattern = re.compile(
        r"\s*#\s*({names})\s*$".format(names="|".join(re.escape(lbl) for lbl in LEADING_LABELS)),
        re.IGNORECASE,
    )
    changed = True
    while changed:
        changed = False
        m = pattern.search(out)
        if m:
            matched = m.group(1).strip()
            for lbl in LEADING_LABELS:
                if matched.upper() == lbl.upper():
                    if lbl not in labels:
                        labels.append(lbl)
                    break
            out = out[: m.start()].rstrip()
            changed = True
    return out, labels


# ---------------------------------------------------------------------------
# Policy classification


@dataclass(frozen=True)
class Classification:
    kind: str
    operation: str
    decision: str
    risk: str
    reason: str
    safety_labels: tuple[str, ...] = ()


def _has_word(text: str, *words: str) -> bool:
    blob = " " + text.lower() + " "
    return any((" " + w + " ") in blob or text.lower().startswith(w + " ") for w in words)


# Service-impacting (docker/systemctl/service mutation)
_SVC_RESTART_PATTERNS = (
    re.compile(r"\bdocker\s+compose\s+(up\s+-d|down|restart|stop|start|kill)\b", re.IGNORECASE),
    re.compile(r"\bdocker-compose\s+(up\s+-d|down|restart|stop|start|kill)\b", re.IGNORECASE),
    re.compile(r"\bdocker\s+(restart|stop|start|kill|rm)\b", re.IGNORECASE),
    re.compile(r"\bsystemctl\s+(restart|reload|start|stop|disable|enable)\b", re.IGNORECASE),
    re.compile(r"\bservice\s+\S+\s+(restart|reload|start|stop)\b", re.IGNORECASE),
)

# Docker read-only
_DOCKER_RO_PATTERNS = (
    re.compile(
        r"\bdocker\s+(logs|inspect|ps|stats|top|images|version|info|events)\b", re.IGNORECASE
    ),
    re.compile(r"\bdocker\s+compose\s+(logs|ps|config|top)\b", re.IGNORECASE),
)

# Filesystem mutation
_FS_MUTATION_PATTERNS = (
    re.compile(r"\bchmod\b", re.IGNORECASE),
    re.compile(r"\bchown\b", re.IGNORECASE),
    re.compile(r"(^|\s)rm\s+(-[rRf]+\s+)?\S", re.IGNORECASE),
    re.compile(r"(^|\s)mv\s+\S+\s+\S", re.IGNORECASE),
    re.compile(r"(^|\s)cp\s+\S+\s+\S", re.IGNORECASE),
    re.compile(r"\btruncate\b", re.IGNORECASE),
)

# Package mutation
_PKG_MUTATION_PATTERNS = (
    re.compile(r"\bapt(?:-get)?\s+(install|remove|purge|upgrade|update)\b", re.IGNORECASE),
    re.compile(r"\b(?:yum|dnf)\s+(install|remove|erase|update|upgrade)\b", re.IGNORECASE),
    re.compile(r"\bapk\s+(add|del)\b", re.IGNORECASE),
    re.compile(r"\bpip3?\s+(install|uninstall)\b", re.IGNORECASE),
    re.compile(r"\bnpm\s+(install|uninstall|update)\b", re.IGNORECASE),
)

# Network mutation
_NET_MUTATION_PATTERNS = (
    re.compile(r"\bip\s+route\s+(add|del|delete|change|replace)\b", re.IGNORECASE),
    re.compile(r"\bip\s+addr\s+(add|del)\b", re.IGNORECASE),
    re.compile(r"\bresolvectl\s+(dns|domain|reset)\b", re.IGNORECASE),
)

# Firewall mutation
_FW_MUTATION_PATTERNS = (
    re.compile(r"\biptables\b", re.IGNORECASE),
    re.compile(r"\bnft\b", re.IGNORECASE),
    re.compile(r"\bufw\s+(allow|deny|delete|enable|disable|reset)\b", re.IGNORECASE),
    re.compile(r"\bfirewall-cmd\b", re.IGNORECASE),
)

# Read-only host
_RO_HOST_PATTERNS = (
    re.compile(r"^(cat|less|head|tail|grep|egrep|fgrep|awk|sed\s+-n)\b", re.IGNORECASE),
    re.compile(r"^(stat|ls|file|wc|du|df|find\b[^#]*?(?!.*-delete))", re.IGNORECASE),
    re.compile(
        r"^(getent|dig|host|nslookup|ss|netstat|ip\s+(?:a|addr|route)\s*$|ip\s+-?\S*\s*$)",
        re.IGNORECASE,
    ),
    re.compile(r"^(ps|top|uptime|free|uname|env|printenv|id|whoami|date)\b", re.IGNORECASE),
    re.compile(r"\bsystemctl\s+(status|is-active|is-enabled|show|cat|list-units)\b", re.IGNORECASE),
    re.compile(r"\bjournalctl\b", re.IGNORECASE),
)

# Manual edit / review tokens (case-insensitive)
_MANUAL_TOKENS = (
    "edit ",
    "review ",
    "confirm ",
    "verify ",
    "correct ",
    "compare ",
    "inspect the ",
    "open ",
    "check ",
    "ensure ",
    "validate ",
    "update the compose",
    "update compose",
    "fix the upstream",
    "set the correct",
    "set correct",
)


def _looks_like_manual(text: str) -> bool:
    low = " " + text.lower()
    return any(tok in low for tok in _MANUAL_TOKENS)


def classify_step(text: str) -> Classification:
    """Classify normalized operator step text deterministically."""
    t = (text or "").strip()
    if not t:
        return Classification(
            kind=KIND_UNKNOWN,
            operation=OP_UNKNOWN,
            decision=DECISION_MANUAL_ONLY,
            risk=RISK_LOW,
            reason="empty step",
        )

    # Service-impacting / restart / recreate
    for pat in _SVC_RESTART_PATTERNS:
        m = pat.search(t)
        if m:
            verb = (m.group(1) if m.groups() else "").lower()
            op = OP_RESTART
            if verb in ("up -d", "recreate"):
                op = OP_RECREATE
            elif verb in ("rm", "stop", "kill", "down"):
                op = OP_RESTART
            kind = KIND_DOCKER if ("docker" in t.lower()) else KIND_SERVICE
            return Classification(
                kind=kind,
                operation=op,
                decision=DECISION_BLOCKED,
                risk=RISK_HIGH,
                reason="service-impacting mutation (restart/recreate/down/stop)",
                safety_labels=("SERVICE-IMPACTING",),
            )

    # Package mutation
    for pat in _PKG_MUTATION_PATTERNS:
        if pat.search(t):
            return Classification(
                kind=KIND_PACKAGE,
                operation=OP_INSTALL,
                decision=DECISION_BLOCKED,
                risk=RISK_HIGH,
                reason="package install/remove/update mutation",
                safety_labels=("PACKAGE-MUTATION",),
            )

    # Firewall mutation (check before generic network)
    for pat in _FW_MUTATION_PATTERNS:
        if pat.search(t):
            return Classification(
                kind=KIND_FIREWALL,
                operation=OP_EDIT_CONFIG,
                decision=DECISION_BLOCKED,
                risk=RISK_HIGH,
                reason="firewall rule mutation",
                safety_labels=("FIREWALL-MUTATION",),
            )

    # Network mutation
    for pat in _NET_MUTATION_PATTERNS:
        if pat.search(t):
            return Classification(
                kind=KIND_NETWORK,
                operation=OP_EDIT_CONFIG,
                decision=DECISION_BLOCKED,
                risk=RISK_HIGH,
                reason="network/routing/DNS mutation",
                safety_labels=("NETWORK-MUTATION",),
            )

    # Filesystem mutation
    for pat in _FS_MUTATION_PATTERNS:
        if pat.search(t):
            op = (
                OP_DELETE
                if re.search(r"\brm\b", t, re.IGNORECASE)
                else (
                    OP_CHMOD
                    if re.search(r"\bchmod\b", t, re.IGNORECASE)
                    else (OP_CHOWN if re.search(r"\bchown\b", t, re.IGNORECASE) else OP_EDIT_CONFIG)
                )
            )
            return Classification(
                kind=KIND_FILESYSTEM,
                operation=op,
                decision=DECISION_BLOCKED,
                risk=RISK_HIGH,
                reason="filesystem mutation (chmod/chown/rm/mv/cp)",
                safety_labels=("FILESYSTEM-MUTATION",),
            )

    # Docker read-only
    for pat in _DOCKER_RO_PATTERNS:
        m = pat.search(t)
        if m:
            verb = (m.group(1) if m.groups() else "").lower()
            op = OP_LOGS if "logs" in verb else OP_INSPECT
            return Classification(
                kind=KIND_DOCKER,
                operation=op,
                decision=DECISION_READ_ONLY,
                risk=RISK_LOW,
                reason="docker read-only inspection",
            )

    # Read-only host
    for pat in _RO_HOST_PATTERNS:
        if pat.search(t):
            return Classification(
                kind=KIND_MANUAL
                if t.lower().startswith(("cat", "grep", "stat", "ls"))
                else KIND_SERVICE,
                operation=OP_INSPECT,
                decision=DECISION_READ_ONLY,
                risk=RISK_LOW,
                reason="read-only host inspection",
            )

    # Manual edit / review
    if _looks_like_manual(t):
        return Classification(
            kind=KIND_MANUAL,
            operation=OP_EDIT_CONFIG
            if "edit" in t.lower() or "update" in t.lower()
            else OP_MANUAL_REVIEW,
            decision=DECISION_MANUAL_ONLY,
            risk=RISK_MEDIUM if "edit" in t.lower() or "update" in t.lower() else RISK_LOW,
            reason="manual operator step (edit/review/confirm)",
        )

    # Unknown -> safest: manual_only
    return Classification(
        kind=KIND_UNKNOWN,
        operation=OP_UNKNOWN,
        decision=DECISION_MANUAL_ONLY,
        risk=RISK_MEDIUM,
        reason="unrecognized step; manual operator review required",
    )


# ---------------------------------------------------------------------------
# Action records


@dataclass
class Action:
    action_id: str
    source_section: str
    raw_text: str
    normalized_text: str
    kind: str
    operation: str
    risk: str
    decision: str
    reason: str
    safety_labels: list[str] = field(default_factory=list)
    command_preview: str = ""
    execution_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "source_section": self.source_section,
            "raw_text": self.raw_text,
            "normalized_text": self.normalized_text,
            "kind": self.kind,
            "operation": self.operation,
            "risk": self.risk,
            "decision": self.decision,
            "reason": self.reason,
            "safety_labels": list(self.safety_labels),
            "command_preview": self.command_preview,
            "execution_allowed": False,
        }


@dataclass
class CompiledActions:
    proposal_id: str
    proposal_fingerprint: str
    source_proposal: str
    source_runbook: str
    actions: list[Action]
    created_at: str
    proposal_title: str = ""
    proposal_component: str = ""
    proposal_risk: str = ""
    proposal_status: str = ""

    def summary(self) -> dict[str, int]:
        total = len(self.actions)
        blocked = sum(1 for a in self.actions if a.decision == DECISION_BLOCKED)
        manual = sum(1 for a in self.actions if a.decision == DECISION_MANUAL_ONLY)
        read_only = sum(1 for a in self.actions if a.decision == DECISION_READ_ONLY)
        svc = sum(1 for a in self.actions if "SERVICE-IMPACTING" in a.safety_labels)
        destructive = sum(
            1
            for a in self.actions
            if any(
                lbl in a.safety_labels
                for lbl in (
                    "FILESYSTEM-MUTATION",
                    "PACKAGE-MUTATION",
                    "NETWORK-MUTATION",
                    "FIREWALL-MUTATION",
                )
            )
        )
        return {
            "total_actions": total,
            "allowed_for_future_execution": 0,
            "blocked": blocked,
            "manual_only": manual,
            "read_only": read_only,
            "service_impacting": svc,
            "destructive": destructive,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ACTIONS_SCHEMA_VERSION,
            "created_at": self.created_at,
            "proposal_id": self.proposal_id,
            "proposal_fingerprint": self.proposal_fingerprint,
            "proposal_title": self.proposal_title,
            "proposal_component": self.proposal_component,
            "proposal_risk": self.proposal_risk,
            "proposal_status": self.proposal_status,
            "source_proposal": self.source_proposal,
            "source_runbook": self.source_runbook,
            "status": COMPILED_STATUS,
            "execution_allowed": EXECUTION_ALLOWED,
            "execution_status": EXECUTION_STATUS_NOT_EXECUTED,
            "policy": {
                "mode": "review_only",
                "default_decision": "deny",
                "mutation_execution": "disabled",
            },
            "summary": self.summary(),
            "actions": [a.to_dict() for a in self.actions],
        }


# ---------------------------------------------------------------------------
# Compilation


def _normalize_one(raw: str) -> tuple[str, list[str]]:
    """Strip leading and inline label prefixes/suffixes; return normalized text + labels."""
    out = (raw or "").strip()
    stripped, leading = _strip_leading_labels(out)
    final, trailing = _strip_inline_label_suffix(stripped)
    labels: list[str] = []
    for lbl in leading + trailing:
        if lbl not in labels:
            labels.append(lbl)
    return final.strip(), labels


def _compile_section(
    proposal_id_seq: list[int],
    section: str,
    raw_steps: list[str],
) -> list[Action]:
    out: list[Action] = []
    for raw in raw_steps or []:
        raw_text = str(raw)
        normalized, source_labels = _normalize_one(raw_text)
        cls = classify_step(normalized)
        labels = list(cls.safety_labels)
        for lbl in source_labels:
            if (
                lbl
                in (
                    "SERVICE-IMPACTING",
                    "FILESYSTEM-MUTATION",
                    "PACKAGE-MUTATION",
                    "NETWORK-MUTATION",
                    "FIREWALL-MUTATION",
                )
                and lbl not in labels
            ):
                labels.append(lbl)
        if section in ("precondition", "verification") and cls.decision == DECISION_BLOCKED:
            # Should not happen for proper runbooks, but be safe and keep blocked
            pass
        proposal_id_seq[0] += 1
        out.append(
            Action(
                action_id=f"act_{proposal_id_seq[0]:03d}",
                source_section=section,
                raw_text=raw_text,
                normalized_text=normalized,
                kind=cls.kind,
                operation=cls.operation,
                risk=cls.risk,
                decision=cls.decision,
                reason=cls.reason,
                safety_labels=labels,
                command_preview=normalized,
                execution_allowed=False,
            )
        )
    return out


def compile_actions(proposal: Proposal) -> CompiledActions:
    """Compile a proposal's steps into structured action records."""
    seq = [0]
    actions: list[Action] = []
    actions.extend(_compile_section(seq, "precondition", list(proposal.preconditions or [])))
    actions.extend(_compile_section(seq, "proposed_step", list(proposal.proposed_steps or [])))
    actions.extend(_compile_section(seq, "rollback", list(proposal.rollback or [])))
    actions.extend(_compile_section(seq, "verification", list(proposal.verification or [])))
    fingerprint = ""
    if isinstance(proposal.fingerprint, dict):
        fingerprint = str(proposal.fingerprint.get("value", ""))
    return CompiledActions(
        proposal_id=proposal.proposal_id,
        proposal_fingerprint=fingerprint,
        source_proposal=proposal.source.runbook or proposal.source.evidence or "",
        source_runbook=proposal.source.runbook or "",
        actions=actions,
        created_at=datetime.now(timezone.utc).isoformat(),
        proposal_title=proposal.title or "",
        proposal_component=proposal.component or "",
        proposal_risk=proposal.risk or "",
        proposal_status=proposal.status or "",
    )


# ---------------------------------------------------------------------------
# Rendering & I/O


def actions_dir_for(data_dir: Path, proposal_id: str) -> Path:
    return Path(data_dir) / "actions" / proposal_id


def render_actions_md(compiled: CompiledActions) -> str:
    summary = compiled.summary()
    lines: list[str] = []
    lines.append("# Compiled actions (review-only)")
    lines.append("")
    lines.append(f"- Proposal: {compiled.proposal_id}")
    if compiled.proposal_title:
        lines.append(f"- Title: {compiled.proposal_title}")
    if compiled.proposal_component:
        lines.append(f"- Component: {compiled.proposal_component}")
    if compiled.proposal_risk:
        lines.append(f"- Proposal risk: {compiled.proposal_risk}")
    if compiled.proposal_status:
        lines.append(f"- Proposal status: {compiled.proposal_status}")
    lines.append(f"- Created at: {compiled.created_at}")
    lines.append("- Policy mode: review_only")
    lines.append("- Execution: disabled / not_executed")
    if compiled.source_runbook:
        lines.append(f"- Source runbook: {compiled.source_runbook}")
    if compiled.source_proposal and compiled.source_proposal != compiled.source_runbook:
        lines.append(f"- Source proposal: {compiled.source_proposal}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total actions: {summary['total_actions']}")
    lines.append(f"- Blocked: {summary['blocked']}")
    lines.append(f"- Manual-only: {summary['manual_only']}")
    lines.append(f"- Read-only review: {summary['read_only']}")
    lines.append(f"- Service-impacting: {summary['service_impacting']}")
    lines.append(f"- Destructive: {summary['destructive']}")
    lines.append(f"- Allowed for future execution: {summary['allowed_for_future_execution']}")
    lines.append("")
    lines.append("## Actions")
    lines.append("")
    if compiled.actions:
        lines.append("| id | section | kind | operation | decision | risk | reason |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for a in compiled.actions:
            reason = a.reason.replace("|", "\\|")
            lines.append(
                f"| {a.action_id} | {a.source_section} | {a.kind} | {a.operation} | "
                f"{a.decision} | {a.risk} | {reason} |"
            )
    else:
        lines.append("- (no actions compiled)")
    lines.append("")

    def _section(title: str, decision: str | None, predicate=None) -> None:
        lines.append(f"## {title}")
        lines.append("")
        rows = [
            a
            for a in compiled.actions
            if (decision is None and (predicate(a) if predicate else True))
            or (decision is not None and a.decision == decision)
        ]
        if not rows:
            lines.append("- (none)")
        else:
            for a in rows:
                labels = (" [" + ", ".join(a.safety_labels) + "]") if a.safety_labels else ""
                lines.append(f"- {a.action_id} ({a.source_section}) `{a.normalized_text}`{labels}")
        lines.append("")

    _section("Read-only review actions", DECISION_READ_ONLY)
    _section("Manual-only actions", DECISION_MANUAL_ONLY)
    _section("Blocked mutation actions", DECISION_BLOCKED)
    _section(
        "Unknown / manual review actions",
        None,
        predicate=lambda a: a.kind == KIND_UNKNOWN,
    )
    lines.append("## Safety")
    lines.append("")
    lines.append(f"- {SAFETY_LINE}")
    lines.append("- Every blocked or manual-only action requires human operator review.")
    lines.append("- apply remains validation-only. No commands are executed by ShellForgeAI.")
    return "\n".join(lines) + "\n"


@dataclass
class CompileResult:
    actions_dir: Path
    actions_json: Path
    actions_md: Path
    compiled: CompiledActions


def write_compiled_actions(
    compiled: CompiledActions,
    *,
    data_dir: Path,
) -> CompileResult:
    out_dir = actions_dir_for(Path(data_dir), compiled.proposal_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    actions_json = out_dir / "actions.json"
    actions_md = out_dir / "actions.md"
    actions_json.write_text(json.dumps(compiled.to_dict(), indent=2), encoding="utf-8")
    actions_md.write_text(render_actions_md(compiled), encoding="utf-8")
    return CompileResult(
        actions_dir=out_dir,
        actions_json=actions_json,
        actions_md=actions_md,
        compiled=compiled,
    )


def compile_and_write(proposal: Proposal, *, data_dir: Path) -> CompileResult:
    compiled = compile_actions(proposal)
    return write_compiled_actions(compiled, data_dir=Path(data_dir))


# ---------------------------------------------------------------------------
# Resolution helpers (for CLI/ask)


@dataclass
class ResolveResult:
    proposal: Proposal | None
    proposal_path: Path | None
    proposal_status: str | None
    error: str | None = None


def resolve_proposal_arg(
    data_dir: Path,
    target: str | None,
    *,
    latest_approved: bool = False,
    allow_statuses: tuple[str, ...] = (STATUS_APPROVED,),
) -> ResolveResult:
    """Resolve a proposal target into a Proposal object, enforcing status policy."""
    data_dir = Path(data_dir)
    if latest_approved:
        p = latest_approved_proposal(data_dir)
        if p is None:
            return ResolveResult(None, None, None, "no approved proposals found")
        path, status = find_proposal_path(data_dir, p.proposal_id)
        return ResolveResult(p, path, status)
    if not target:
        return ResolveResult(None, None, None, "missing proposal target")
    # Try filesystem path first
    p_path = Path(target)
    if p_path.exists() and p_path.is_file():
        try:
            proposal = load_proposal_from_path(p_path)
        except (OSError, ValueError) as exc:
            return ResolveResult(None, None, None, f"failed to load proposal: {exc}")
        # status is whatever the file says
        status = proposal.status
        if status not in allow_statuses:
            return ResolveResult(
                proposal,
                p_path,
                status,
                f"proposal status '{status}' is not allowed (allowed: {', '.join(allow_statuses)})",
            )
        return ResolveResult(proposal, p_path, status)
    # Treat as id
    path, status = find_proposal_path(data_dir, target)
    if path is None:
        return ResolveResult(None, None, None, f"proposal not found: {target}")
    try:
        proposal = load_proposal_from_path(path)
    except (OSError, ValueError) as exc:
        return ResolveResult(None, path, status, f"failed to load proposal: {exc}")
    if status not in allow_statuses:
        return ResolveResult(
            proposal,
            path,
            status,
            f"proposal status '{status}' is not allowed (allowed: {', '.join(allow_statuses)})",
        )
    return ResolveResult(proposal, path, status)


# ---------------------------------------------------------------------------
# Validation


@dataclass
class ActionValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    info: dict[str, Any] = field(default_factory=dict)


REQUIRED_ACTION_FIELDS = (
    "action_id",
    "source_section",
    "raw_text",
    "normalized_text",
    "kind",
    "operation",
    "risk",
    "decision",
    "reason",
    "execution_allowed",
)

ALLOWED_DECISIONS = (DECISION_READ_ONLY, DECISION_MANUAL_ONLY, DECISION_BLOCKED)
ALLOWED_RISKS = (RISK_LOW, RISK_MEDIUM, RISK_HIGH)

_SVC_IMPACTING_OPS = {OP_RESTART, OP_RECREATE}


def validate_actions_payload(payload: Any) -> ActionValidationResult:
    errors: list[str] = []
    info: dict[str, Any] = {}
    if not isinstance(payload, dict):
        return ActionValidationResult(ok=False, errors=["actions.json must be a JSON object"])

    if not payload.get("schema_version"):
        errors.append("missing schema_version")
    proposal_id = payload.get("proposal_id")
    if not isinstance(proposal_id, str) or not proposal_id:
        errors.append("missing proposal_id")
    if payload.get("execution_allowed") is not False:
        errors.append("execution_allowed must be false")
    if payload.get("execution_status") != EXECUTION_STATUS_NOT_EXECUTED:
        errors.append(f"execution_status must be '{EXECUTION_STATUS_NOT_EXECUTED}'")

    actions = payload.get("actions")
    if not isinstance(actions, list):
        return ActionValidationResult(ok=False, errors=errors + ["actions must be a JSON array"])

    blocked_count = 0
    manual_count = 0
    read_only_count = 0
    svc_impacting_count = 0
    destructive_count = 0

    for idx, action in enumerate(actions):
        if not isinstance(action, dict):
            errors.append(f"action[{idx}] is not a JSON object")
            continue
        for field_name in REQUIRED_ACTION_FIELDS:
            if field_name not in action:
                errors.append(f"action[{idx}] missing required field: {field_name}")
        action_id = action.get("action_id", f"action[{idx}]")
        if action.get("execution_allowed") is not False:
            errors.append(f"action {action_id} execution_allowed must be false")
        decision = action.get("decision")
        if decision not in ALLOWED_DECISIONS:
            errors.append(
                f"action {action_id} decision must be one of {ALLOWED_DECISIONS}, got {decision!r}"
            )
        if action.get("risk") not in ALLOWED_RISKS:
            errors.append(
                f"action {action_id} risk must be one of {ALLOWED_RISKS}, "
                f"got {action.get('risk')!r}"
            )
        # Forbid blocked mutations claimed as read-only.
        kind = action.get("kind")
        op = action.get("operation")
        labels = action.get("safety_labels") or []
        mutation_labels = {
            "SERVICE-IMPACTING",
            "FILESYSTEM-MUTATION",
            "PACKAGE-MUTATION",
            "NETWORK-MUTATION",
            "FIREWALL-MUTATION",
        }
        mutating_kinds = {KIND_PACKAGE, KIND_FIREWALL, KIND_NETWORK}
        mutating_ops = {OP_RESTART, OP_RECREATE, OP_CHMOD, OP_CHOWN, OP_DELETE, OP_INSTALL}
        looks_mutating = (
            any(lbl in mutation_labels for lbl in labels)
            or op in mutating_ops
            or kind in mutating_kinds
        )
        if looks_mutating and decision == DECISION_READ_ONLY:
            errors.append(
                f"action {action_id} is mutating ({kind}/{op}) but marked read_only_review"
            )

        # Service-impacting label expected for restart/recreate ops
        if op in _SVC_IMPACTING_OPS and not any(
            lbl.upper() in ("SERVICE-IMPACTING", "OPERATOR-RUN") for lbl in labels
        ):
            errors.append(
                f"action {action_id} is service-impacting (op={op}) "
                "but lacks SERVICE-IMPACTING label"
            )

        # Forbid claimed execution
        for forbidden in ("executed", "running", "succeeded"):
            if action.get("status") == forbidden:
                errors.append(f"action {action_id} status must not be '{forbidden}'")

        if decision == DECISION_BLOCKED:
            blocked_count += 1
        elif decision == DECISION_MANUAL_ONLY:
            manual_count += 1
        elif decision == DECISION_READ_ONLY:
            read_only_count += 1
        if "SERVICE-IMPACTING" in labels:
            svc_impacting_count += 1
        if any(
            lbl in labels
            for lbl in (
                "FILESYSTEM-MUTATION",
                "PACKAGE-MUTATION",
                "NETWORK-MUTATION",
                "FIREWALL-MUTATION",
            )
        ):
            destructive_count += 1

    # Summary count cross-check
    summary = payload.get("summary") or {}
    if isinstance(summary, dict):
        checks = {
            "total_actions": len(actions),
            "blocked": blocked_count,
            "manual_only": manual_count,
            "read_only": read_only_count,
            "service_impacting": svc_impacting_count,
            "destructive": destructive_count,
        }
        for key, expected in checks.items():
            if key in summary and summary[key] != expected:
                errors.append(f"summary.{key} mismatch: declared {summary[key]}, actual {expected}")
        if summary.get("allowed_for_future_execution", 0) != 0:
            errors.append("summary.allowed_for_future_execution must be 0")
    else:
        errors.append("summary must be a JSON object")

    info.update(
        {
            "proposal_id": proposal_id if isinstance(proposal_id, str) else "",
            "total_actions": len(actions),
            "blocked": blocked_count,
            "manual_only": manual_count,
            "read_only": read_only_count,
            "service_impacting": svc_impacting_count,
            "destructive": destructive_count,
        }
    )
    return ActionValidationResult(ok=not errors, errors=errors, info=info)


def load_actions_file(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return None, f"actions file not found: {p}"
    try:
        return json.loads(p.read_text(encoding="utf-8")), None
    except (OSError, ValueError) as exc:
        return None, f"malformed actions json: {exc}"


def find_actions_for_proposal(data_dir: Path, proposal_id: str) -> Path | None:
    p = actions_dir_for(Path(data_dir), proposal_id) / "actions.json"
    return p if p.exists() else None


# ---------------------------------------------------------------------------
# Ask intent


_ACTIONS_COMPILE_TOKENS = (
    "compile actions",
    "compile the actions",
    "compile the approved actions",
    "compile actions for approved",
    "compile actions for the approved",
    "compile the approved proposal",
    "compile policy actions",
    "policy review of the approved",
    "policy review of approved",
    "prepare a policy review",
    "prepare policy review",
    "classify the approved fix",
    "classify the approved steps",
    "classify approved fix",
    "classify approved steps",
)
_ACTIONS_SHOW_TOKENS = (
    "what actions are blocked",
    "what would be executed",
    "show me what would be executed",
    "show what would be executed",
    "show me the actions",
    "show the compiled actions",
    "show compiled actions",
    "list compiled actions",
    "list the compiled actions",
)
_ACTIONS_RUN_TOKENS = (
    "run the actions",
    "run actions",
    "execute the actions",
    "execute actions",
    "run the compiled actions",
)


@dataclass(frozen=True)
class ActionsAskIntent:
    matched: bool
    compile: bool = False
    show: bool = False
    run: bool = False


def is_actions_ask_intent(text: str) -> ActionsAskIntent:
    raw = (text or "").lower()
    run = any(tok in raw for tok in _ACTIONS_RUN_TOKENS)
    compile_ = any(tok in raw for tok in _ACTIONS_COMPILE_TOKENS)
    show = any(tok in raw for tok in _ACTIONS_SHOW_TOKENS)
    if not (run or compile_ or show):
        return ActionsAskIntent(matched=False)
    return ActionsAskIntent(matched=True, compile=compile_, show=show, run=run)


__all__ = [
    "ACTIONS_FILES",
    "ACTIONS_SCHEMA_VERSION",
    "Action",
    "ActionValidationResult",
    "CompileResult",
    "CompiledActions",
    "Classification",
    "DECISION_BLOCKED",
    "DECISION_MANUAL_ONLY",
    "DECISION_READ_ONLY",
    "EXECUTION_ALLOWED",
    "EXECUTION_STATUS_NOT_EXECUTED",
    "STATUS_APPROVED",
    "STATUS_CANCELED",
    "STATUS_PENDING",
    "STATUS_REJECTED",
    "actions_dir_for",
    "classify_step",
    "compile_actions",
    "compile_and_write",
    "ActionsAskIntent",
    "find_actions_for_proposal",
    "is_actions_ask_intent",
    "load_actions_file",
    "render_actions_md",
    "resolve_proposal_arg",
    "validate_actions_payload",
    "write_compiled_actions",
]
