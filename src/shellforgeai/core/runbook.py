"""Evidence-backed operator runbook / safe-fix-plan synthesis.

ShellForgeAI is a Tier-3 triage tool. It does not execute changes.
This module turns existing read-only evidence into an operator-run
remediation plan. Every mutating step is labelled as OPERATOR-RUN and
the runbook is explicit that ShellForgeAI did not execute anything.

The runbook is intentionally deterministic and built from already-collected
evidence (``EvidenceItem`` records, typically loaded from ``evidence.json``)
plus the ``Finding`` list. There is no model call, no shell execution, and
no mutation. It is safe to render at any time.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from shellforgeai.core.evidence import EvidenceBundle, EvidenceItem

SAFETY_LINE = "ShellForgeAI did not execute these steps. This is an operator-run plan."

RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"
SCHEMA_VERSION = "1"


class RunbookProblem(BaseModel):
    id: str = ""
    name: str
    component: str = ""
    kind: str = ""
    severity: str = "warning"
    evidence: list[str] = Field(default_factory=list)
    likely_cause: str = ""
    confidence: str = "medium"


class RunbookOption(BaseModel):
    id: str = ""
    title: str
    applies_to: list[str] = Field(default_factory=list)
    risk: str = RISK_MEDIUM
    impact: str = ""
    preconditions: list[str] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
    rollback: list[str] = Field(default_factory=list)
    verification: list[str] = Field(default_factory=list)
    notes: str = ""
    label: str = "OPERATOR-RUN"


class Runbook(BaseModel):
    session_id: str
    target: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_artifacts: list[str] = Field(default_factory=list)
    problems: list[RunbookProblem] = Field(default_factory=list)
    risk_level: str = RISK_LOW
    prechecks: list[str] = Field(default_factory=list)
    operator_steps: list[RunbookOption] = Field(default_factory=list)
    rollback: list[str] = Field(default_factory=list)
    validation: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=lambda: [SAFETY_LINE])
    executive_summary: str = ""

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "session_id": self.session_id,
            "target": self.target,
            "generated_at": self.generated_at.isoformat(),
            "source_evidence": self.source_artifacts[0] if self.source_artifacts else "",
            "safety_mode": "read-only / operator-run only",
            "overall_risk": self.risk_level,
            "problems": [
                p.model_dump(
                    include={
                        "id",
                        "component",
                        "kind",
                        "severity",
                        "confidence",
                        "likely_cause",
                        "evidence",
                    }
                )
                for p in self.problems
            ],
            "remediation_options": [
                {
                    "id": o.id,
                    "title": o.title,
                    "applies_to": o.applies_to,
                    "risk": o.risk,
                    "impact": o.impact,
                    "preconditions": o.preconditions,
                    "steps": o.steps,
                    "rollback": o.rollback,
                    "verification": o.verification,
                    "safety_label": o.label,
                }
                for o in self.operator_steps
            ],
            "recommended_order": [o.id or o.title for o in self.operator_steps],
            "post_fix_validation": self.validation,
            "rollback_notes": self.rollback,
            "safety_notes": self.safety_notes,
            "executive_summary": self.executive_summary,
        }


# ---------------------------------------------------------------------------
# Evidence helpers


def _by_source(items: list[EvidenceItem]) -> dict[str, EvidenceItem]:
    out: dict[str, EvidenceItem] = {}
    for it in items:
        out.setdefault(it.source, it)
    return out


def _docker_buckets(items: list[EvidenceItem]) -> dict[str, list[dict[str, Any]]]:
    item = next((i for i in items if i.source == "docker.problem_summary"), None)
    if item is None or not item.ok:
        return {"failing": [], "noisy": [], "healthy": []}
    try:
        payload = json.loads(item.content or "{}")
    except (ValueError, json.JSONDecodeError):
        return {"failing": [], "noisy": [], "healthy": []}
    return {
        "failing": payload.get("failing", []) or [],
        "noisy": payload.get("noisy", []) or [],
        "healthy": payload.get("healthy", []) or [],
    }


def _docker_inventory(items: list[EvidenceItem]) -> list[dict[str, Any]]:
    item = next((i for i in items if i.source == "docker.containers"), None)
    if item is None or not item.ok:
        return []
    try:
        payload = json.loads(item.content or "{}")
    except (ValueError, json.JSONDecodeError):
        return []
    return payload.get("containers", []) or []


def _container_problem_kind(entry: dict[str, Any]) -> str:
    """Classify a problem-summary entry into a runbook problem kind."""
    themes = entry.get("log_themes") or {}
    state = (entry.get("state") or "").lower()
    exit_code = entry.get("exit_code")
    if themes.get("missing_required_setting"):
        return "missing-env"
    if themes.get("read_only_fs") or themes.get("permission_denied"):
        return "bad-volume-perms"
    if state == "restarting" or themes.get("simulated_crash"):
        return "restart-loop"
    if (
        themes.get("dns_failure")
        or themes.get("upstream_unreachable")
        or themes.get("connection_refused")
        or themes.get("timeout")
        or themes.get("tls_certificate")
        or themes.get("unknown_network_error")
    ):
        return "bad-network"
    if state == "exited" and isinstance(exit_code, int) and exit_code != 0:
        return "exited-nonzero"
    if state == "running" and (themes.get("error_line") or themes.get("warn_line")):
        return "noisy-logs"
    return "unknown"


# ---------------------------------------------------------------------------
# Per-problem option builders


def _opt_missing_env(name: str, sample: list[str]) -> RunbookOption:
    snippet = "; ".join(sample[-2:]) if sample else ""
    return RunbookOption(
        title=f"Provide REQUIRED_SETTING (or missing config) for {name}",
        risk=RISK_MEDIUM,
        impact=f"Recreates {name} after config change. Brief downtime for that container.",
        preconditions=[
            "Confirm the required variable name from the application's documentation.",
            "Locate the compose file or env file that owns this service.",
            f"Read-only inspect: docker inspect {name}",
        ],
        steps=[
            "OPERATOR-RUN: edit the service's compose / env file and add the required variable.",
            f"OPERATOR-RUN: docker compose up -d {name}   # SERVICE-IMPACTING",
        ],
        rollback=[
            "Revert the compose/env file change from version control or backup.",
            f"OPERATOR-RUN: docker compose up -d {name}   # restore previous config",
        ],
        verification=[
            f"docker inspect -f '{{{{.State.Status}}}} {{{{.State.ExitCode}}}}' {name}",
            f"docker logs --tail 50 {name}   # should no longer mention REQUIRED_SETTING",
        ],
        notes=f"Triggered by log evidence: {snippet}" if snippet else "",
    )


def _opt_bad_volume_perms(name: str, sample: list[str]) -> RunbookOption:
    snippet = "; ".join(sample[-2:]) if sample else ""
    return RunbookOption(
        title=f"Fix volume permissions / writable mount for {name}",
        risk=RISK_MEDIUM,
        impact=(
            "Changes mount flags or host directory ownership. "
            "May affect other consumers of the same path."
        ),
        preconditions=[
            f"docker inspect -f '{{{{json .Mounts}}}}' {name}",
            "Confirm intended writable path and intended owning UID/GID.",
            "Check whether the host directory is shared with other services.",
        ],
        steps=[
            "OPERATOR-RUN: edit compose volume entry to remove ':ro' if write is intended.",
            (
                "OPERATOR-RUN: chown / chmod the host path to the intended UID/GID"
                "   # REQUIRES APPROVAL"
            ),
            f"OPERATOR-RUN: docker compose up -d {name}   # SERVICE-IMPACTING",
        ],
        rollback=[
            "Restore previous compose volume flags from version control.",
            "Restore previous ownership/mode using values captured in pre-checks.",
            f"OPERATOR-RUN: docker compose up -d {name}",
        ],
        verification=[
            f"docker logs --tail 50 {name}   # should no longer mention 'read-only file system'",
            f"docker inspect -f '{{{{.State.Status}}}} {{{{.State.ExitCode}}}}' {name}",
        ],
        notes=f"Triggered by log evidence: {snippet}" if snippet else "",
    )


def _opt_restart_loop(name: str, sample: list[str]) -> RunbookOption:
    snippet = "; ".join(sample[-2:]) if sample else ""
    return RunbookOption(
        title=f"Stabilize restart loop for {name}",
        risk=RISK_MEDIUM,
        impact=f"Modifies {name} startup. Brief downtime while debugging.",
        preconditions=[
            f"docker logs --tail 200 {name}",
            f"docker inspect -f '{{{{json .Config.Cmd}}}} {{{{json .Config.Entrypoint}}}}' {name}",
            f"docker inspect -f '{{{{.RestartCount}}}}' {name}",
        ],
        steps=[
            "OPERATOR-RUN: identify the failing entrypoint/command and fix the underlying defect.",
            (
                "OPERATOR-RUN: optionally set restart policy to 'no' temporarily for "
                "debugging   # REQUIRES APPROVAL"
            ),
            f"OPERATOR-RUN: docker compose up -d {name}   # SERVICE-IMPACTING",
        ],
        rollback=[
            "Revert startup/config changes from version control.",
            "Restore the previous restart policy.",
        ],
        verification=[
            f"docker inspect -f '{{{{.RestartCount}}}}' {name}   # should stop incrementing",
            f"docker logs --tail 50 {name}   # should show normal startup",
        ],
        notes=f"Triggered by log evidence: {snippet}" if snippet else "",
    )


def _opt_bad_network(name: str, sample: list[str]) -> RunbookOption:
    snippet = "; ".join(sample[-2:]) if sample else ""
    return RunbookOption(
        title=f"Correct upstream / DNS configuration for {name}",
        risk=RISK_MEDIUM,
        impact=f"Recreates {name} after dependency config change.",
        preconditions=[
            f"docker inspect -f '{{{{json .Config.Env}}}}' {name}",
            "Confirm the intended upstream service name / DNS / URL.",
            (
                f"docker exec {name} getent hosts <upstream>"
                "   # read-only DNS check from same namespace"
            ),
        ],
        steps=[
            "OPERATOR-RUN: correct the upstream hostname / URL in the compose or env file.",
            f"OPERATOR-RUN: docker compose up -d {name}   # SERVICE-IMPACTING",
        ],
        rollback=[
            "Restore previous upstream configuration from version control.",
            f"OPERATOR-RUN: docker compose up -d {name}",
        ],
        verification=[
            f"docker logs --tail 50 {name}   # should no longer show DNS / upstream errors",
            f"docker exec {name} getent hosts <upstream>   # should resolve",
        ],
        notes=f"Triggered by log evidence: {snippet}" if snippet else "",
    )


def _opt_noisy_logs(name: str, sample: list[str]) -> RunbookOption:
    snippet = "; ".join(sample[-2:]) if sample else ""
    return RunbookOption(
        title=f"Investigate (do not mutate) noisy logs for {name}",
        risk=RISK_LOW,
        impact="No mutation recommended yet. Read-only investigation only.",
        preconditions=[
            f"docker logs --tail 200 {name}",
            f"docker inspect -f '{{{{.State.Health.Status}}}} {{{{.State.Status}}}}' {name}",
            "Compare error frequency to a known-good baseline if available.",
        ],
        steps=[
            "Decide whether the WARN/ERROR lines correlate with user-visible impact.",
            "If they are expected app chatter, no action is required.",
            (
                "OPERATOR-RUN: only after approval, tune the application's log level"
                "   # REQUIRES APPROVAL"
            ),
        ],
        rollback=[
            "Revert any log-level change to the previous value.",
        ],
        verification=[
            f"docker inspect -f '{{{{.State.Status}}}}' {name}   # should remain running",
            f"docker logs --tail 50 {name}",
        ],
        notes=f"Sample log lines: {snippet}" if snippet else "",
    )


def _opt_exited_nonzero(name: str, exit_code: Any, sample: list[str]) -> RunbookOption:
    snippet = "; ".join(sample[-2:]) if sample else ""
    return RunbookOption(
        title=f"Diagnose non-zero exit ({exit_code}) for {name}",
        risk=RISK_MEDIUM,
        impact=f"Recreates {name}. Brief downtime.",
        preconditions=[
            f"docker logs --tail 200 {name}",
            f"docker inspect -f '{{{{json .State}}}}' {name}",
        ],
        steps=[
            "OPERATOR-RUN: address the root cause indicated by the logs.",
            f"OPERATOR-RUN: docker compose up -d {name}   # SERVICE-IMPACTING",
        ],
        rollback=[
            "Revert any code/config change from version control.",
        ],
        verification=[
            f"docker inspect -f '{{{{.State.Status}}}} {{{{.State.ExitCode}}}}' {name}",
            f"docker logs --tail 50 {name}",
        ],
        notes=f"Recent log lines: {snippet}" if snippet else "",
    )


# ---------------------------------------------------------------------------
# Problem detection


def _problems_from_docker(
    items: list[EvidenceItem],
) -> tuple[
    list[RunbookProblem],
    list[RunbookOption],
]:
    buckets = _docker_buckets(items)
    problems: list[RunbookProblem] = []
    options: list[RunbookOption] = []
    seen: set[tuple[str, str]] = set()

    def _add(entry: dict[str, Any], bucket: str) -> None:
        name = entry.get("name") or "(unnamed)"
        kind = _container_problem_kind(entry)
        if kind == "unknown":
            return
        key = (name, kind)
        if key in seen:
            return
        seen.add(key)
        themes = entry.get("log_themes") or {}
        sample = [str(s) for s in (entry.get("log_sample") or [])]
        ev: list[str] = []
        if entry.get("state"):
            ev.append(f"state={entry.get('state')}")
        if entry.get("exit_code") is not None:
            ev.append(f"exit_code={entry.get('exit_code')}")
        if themes:
            ev.append("log_themes=" + ",".join(sorted(k for k, v in themes.items() if v)))
        if sample:
            ev.append("log_sample=" + " | ".join(s[:160] for s in sample[-2:]))
        sev = "critical" if (kind == "restart-loop" or bucket == "failing") else "warning"
        if kind == "noisy-logs":
            sev = "info"
        confidence = "high" if themes else "medium"
        cause_map = {
            "missing-env": (
                "Required environment/config variable not set; container exits at startup."
            ),
            "bad-volume-perms": (
                "Container cannot write to its mount: read-only flag or wrong owner/perms."
            ),
            "restart-loop": "Application crashes during startup and is being restarted by Docker.",
            "bad-network": "Upstream hostname/URL is wrong or unreachable from this container.",
            "noisy-logs": "Application is logging WARN/ERROR but is running. May be benign.",
            "exited-nonzero": "Container terminated with a non-zero exit code.",
        }
        problems.append(
            RunbookProblem(
                id=f"problem:{name}:{kind}",
                name=f"{name}: {kind}",
                component=name,
                kind=kind,
                severity=sev,
                evidence=ev,
                likely_cause=cause_map.get(kind, ""),
                confidence=confidence,
            )
        )
        if kind == "missing-env":
            opt = _opt_missing_env(name, sample)
            opt.id = f"option:{name}:{kind}"
            opt.applies_to = [f"problem:{name}:{kind}", name]
            options.append(opt)
        elif kind == "bad-volume-perms":
            opt = _opt_bad_volume_perms(name, sample)
            opt.id = f"option:{name}:{kind}"
            opt.applies_to = [f"problem:{name}:{kind}", name]
            options.append(opt)
        elif kind == "restart-loop":
            opt = _opt_restart_loop(name, sample)
            opt.id = f"option:{name}:{kind}"
            opt.applies_to = [f"problem:{name}:{kind}", name]
            options.append(opt)
        elif kind == "bad-network":
            opt = _opt_bad_network(name, sample)
            opt.id = f"option:{name}:{kind}"
            opt.applies_to = [f"problem:{name}:{kind}", name]
            options.append(opt)
        elif kind == "noisy-logs":
            opt = _opt_noisy_logs(name, sample)
            opt.id = f"option:{name}:{kind}"
            opt.applies_to = [f"problem:{name}:{kind}", name]
            options.append(opt)
        elif kind == "exited-nonzero":
            opt = _opt_exited_nonzero(name, entry.get("exit_code"), sample)
            opt.id = f"option:{name}:{kind}"
            opt.applies_to = [f"problem:{name}:{kind}", name]
            options.append(opt)

    for entry in buckets["failing"]:
        _add(entry, "failing")
    for entry in buckets["noisy"]:
        _add(entry, "noisy")
    return problems, options


def _problems_from_packages(items: list[EvidenceItem]) -> list[RunbookOption]:
    out: list[RunbookOption] = []
    for it in items:
        if it.source != "package.query" or not it.ok:
            continue
        try:
            payload = json.loads(it.content or "{}")
        except (ValueError, json.JSONDecodeError):
            continue
        installed = payload.get("installed")
        name = payload.get("query") or "the package"
        if installed is False:
            out.append(
                RunbookOption(
                    title=f"Confirm whether {name} is supposed to run on this host",
                    risk=RISK_LOW,
                    impact="Read-only confirmation only. No install is recommended yet.",
                    preconditions=[
                        f"Confirm whether {name} is expected on this host or in another "
                        "container/namespace.",
                        "Check service inventory / runbooks for the intended deployment target.",
                    ],
                    steps=[
                        f"OPERATOR-RUN: only after confirmation, apt install {name}   "
                        "# REQUIRES APPROVAL, SERVICE-IMPACTING",
                    ],
                    rollback=[
                        f"OPERATOR-RUN: apt remove {name}   # REQUIRES APPROVAL",
                    ],
                    verification=[
                        f"dpkg -s {name} 2>/dev/null | head -n 5",
                        "shellforgeai diagnose packages --json",
                    ],
                    notes=(
                        f"{name} is not installed. Do NOT install as a first step without "
                        "confirming the architecture; it may be intentionally absent."
                    ),
                )
            )
    return out


def _problems_from_file_owner(items: list[EvidenceItem]) -> list[RunbookOption]:
    out: list[RunbookOption] = []
    by = _by_source(items)
    fo = by.get("package.file_owner")
    mounts = by.get("storage.mounts")
    if fo is None:
        return out
    try:
        payload = json.loads(fo.content or "{}")
    except (ValueError, json.JSONDecodeError):
        return out
    path = payload.get("path") or ""
    if path == "/usr/local/bin/docker" and (
        payload.get("owner_status") in {"not_owned", "path_missing"}
    ):
        mount_summary = (mounts.summary if mounts else "") or ""
        out.append(
            RunbookOption(
                title="Document host-mounted Docker CLI (no fix needed if intentional)",
                risk=RISK_LOW,
                impact="Read-only documentation. No mutation.",
                preconditions=[
                    "Confirm whether /usr/local/bin/docker is mounted from the host.",
                    "Inspect the compose file's bind mounts for /usr/bin/docker.",
                ],
                steps=[
                    "Document the mount as host-provided Docker CLI in the runbook.",
                    "OPERATOR-RUN: only if unexpected, edit the compose mounts and recreate "
                    "the container   # REQUIRES APPROVAL",
                ],
                rollback=[
                    "Restore previous compose mount entry.",
                ],
                verification=[
                    "shellforgeai ask 'what owns /usr/local/bin/docker?'",
                ],
                notes=(
                    "/usr/local/bin/docker is not dpkg-owned because it is provided by a "
                    "host bind-mount (see storage.mounts). "
                    + (f"Mount summary: {mount_summary[:200]}" if mount_summary else "")
                ).strip(),
            )
        )
    return out


def _problems_from_config_changes(items: list[EvidenceItem]) -> list[RunbookOption]:
    cc = next((i for i in items if i.source == "config.recent_changes"), None)
    if cc is None or not cc.ok or not (cc.content or "").strip():
        return []
    return [
        RunbookOption(
            title="Review recent config changes before any restart",
            risk=RISK_LOW,
            impact="Read-only review. Mutations only after explicit operator approval.",
            preconditions=[
                "List recently modified config files (config.recent_changes).",
                "Compare modification times with the incident window.",
                "Backup any file before editing it.",
            ],
            steps=[
                (
                    "OPERATOR-RUN: back up the file "
                    "(cp <file> <file>.bak.$(date +%s))   # REQUIRES APPROVAL"
                ),
                "OPERATOR-RUN: edit the file and run the service's config-validate command "
                "before reload   # REQUIRES APPROVAL",
                "OPERATOR-RUN: reload (not restart, when supported) the affected service "
                "  # SERVICE-IMPACTING, ROLLBACK ADVISED",
            ],
            rollback=[
                "Restore the backup file and reload the service.",
            ],
            verification=[
                "Service status returns to running/healthy.",
                "shellforgeai diagnose <service> --json",
            ],
            notes="Recent config changes detected — investigate before any restart/reload.",
        )
    ]


# ---------------------------------------------------------------------------
# Aggregation / ordering


def _executive_summary(problems: list[RunbookProblem]) -> str:
    if not problems:
        return (
            "No actionable problems were identified from the evidence. "
            "ShellForgeAI did not execute anything."
        )
    by_kind: dict[str, list[str]] = {}
    for p in problems:
        kind = p.name.split(":", 1)[1].strip() if ":" in p.name else p.name
        by_kind.setdefault(kind, []).append(p.component or p.name)
    parts = [f"{kind} ({', '.join(sorted(set(names)))})" for kind, names in sorted(by_kind.items())]
    return "Identified problems: " + "; ".join(parts) + ". " + SAFETY_LINE


def _risk_level(options: list[RunbookOption]) -> str:
    if any(o.risk == RISK_HIGH for o in options):
        return RISK_HIGH
    if any(o.risk == RISK_MEDIUM for o in options):
        return RISK_MEDIUM
    return RISK_LOW


_MUTATION_TOKENS = (
    "restart",
    "recreate",
    "install",
    "update",
    "chmod",
    "chown",
    "edit",
    "delete",
    "firewall",
    "route",
    "dns",
    "docker compose up -d",
)


def option_risk_from_text(option: RunbookOption) -> str:
    blob = " ".join([option.title, option.impact, *option.steps]).lower()
    if "document host-mounted docker cli" in blob:
        return RISK_LOW
    if any(
        tok in blob
        for tok in (
            "chmod 777",
            "package update all",
            "docker daemon restart",
            "broad chown",
            "broad chmod",
            "volume deletion",
            "firewall",
            "route",
            "dns changes",
        )
    ):
        return RISK_HIGH
    if any(tok in blob for tok in ("docker compose up -d", "restart", "recreate")):
        return RISK_MEDIUM
    return RISK_LOW


def validate_runbook_payload(payload: dict[str, Any]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    required_top = [
        "schema_version",
        "session_id",
        "target",
        "generated_at",
        "source_evidence",
        "safety_mode",
        "overall_risk",
        "problems",
        "remediation_options",
        "recommended_order",
        "post_fix_validation",
        "safety_notes",
    ]
    for key in required_top:
        if key not in payload:
            errors.append(f"missing required field: {key}")
    safety_mode = str(payload.get("safety_mode", "")).lower()
    if "read-only" not in safety_mode and "operator-run" not in safety_mode:
        errors.append("safety_mode must mention read-only or operator-run")
    notes = " ".join(str(x) for x in (payload.get("safety_notes") or []))
    if "did not execute" not in notes.lower():
        errors.append("runbook missing safety note")
    problems = payload.get("problems") or []
    for i, p in enumerate(problems):
        for key in (
            "id",
            "component",
            "kind",
            "severity",
            "confidence",
            "likely_cause",
            "evidence",
        ):
            if key not in p:
                errors.append(f"problem[{i}] missing {key}")
        if p.get("severity") not in {"critical", "warning", "info"}:
            errors.append(f"problem[{i}].severity must be one of critical|warning|info")
        if p.get("confidence") not in {"high", "medium", "low"}:
            errors.append(f"problem[{i}].confidence must be one of high|medium|low")
    options = payload.get("remediation_options") or []
    known_problem_refs = {p.get("id") for p in problems} | {p.get("component") for p in problems}
    for i, o in enumerate(options):
        for key in (
            "id",
            "title",
            "applies_to",
            "risk",
            "impact",
            "preconditions",
            "steps",
            "rollback",
            "verification",
            "safety_label",
        ):
            if key not in o:
                errors.append(f"option[{i}] missing {key}")
        if o.get("risk") not in {RISK_LOW, RISK_MEDIUM, RISK_HIGH}:
            errors.append(f"option[{i}].risk must be one of low|medium|high")
        if o.get("risk") in {RISK_MEDIUM, RISK_HIGH} and not o.get("rollback"):
            errors.append(f"option[{i}] is missing rollback")
        if not o.get("verification"):
            errors.append(f"option[{i}] is missing verification")
        steps = " ".join(str(s) for s in (o.get("steps") or [])).lower()
        mutating = any(tok in steps for tok in _MUTATION_TOKENS)
        if mutating and "OPERATOR-RUN" not in str(o.get("safety_label", "")):
            errors.append("mutating step is not labeled OPERATOR-RUN")
        if mutating and not any(
            lbl in str(o.get("steps", "")) for lbl in ("REQUIRES APPROVAL", "SERVICE-IMPACTING")
        ):
            errors.append("mutating step missing REQUIRES APPROVAL or SERVICE-IMPACTING")
        applies_to = o.get("applies_to") or []
        if applies_to and not all(
            (a in known_problem_refs or str(a).startswith("general:")) for a in applies_to
        ):
            warnings.append(f"option[{i}] applies_to does not match known problem ids/components")
    max_risk = (
        _risk_level(
            [
                RunbookOption.model_validate(
                    {"title": str(o.get("title", "")), "risk": o.get("risk", RISK_LOW)}
                )
                for o in options
            ]
        )
        if options
        else RISK_LOW
    )
    if payload.get("overall_risk") != max_risk:
        errors.append(f"overall_risk must be {max_risk} based on remediation_options")
    return errors, warnings


# Order: high-confidence + low-risk first; restart-loop is critical and should
# bubble up; noisy-logs is always last.
_KIND_ORDER = {
    "missing-env": 1,
    "bad-volume-perms": 2,
    "bad-network": 3,
    "exited-nonzero": 4,
    "restart-loop": 0,  # surface critical restart loops first
    "noisy-logs": 99,
}


def _sort_options(options: list[RunbookOption]) -> list[RunbookOption]:
    def key(o: RunbookOption) -> tuple[int, int]:
        kind_score = 50
        for k, v in _KIND_ORDER.items():
            if k in o.title.lower():
                kind_score = v
                break
        risk_score = {RISK_LOW: 0, RISK_MEDIUM: 1, RISK_HIGH: 2}.get(o.risk, 1)
        return (kind_score, risk_score)

    return sorted(options, key=key)


# ---------------------------------------------------------------------------
# Public API


def build_runbook(
    *,
    session_id: str,
    target: str,
    evidence_items: list[EvidenceItem],
    findings: list[Any] | None = None,
    source_artifacts: list[str] | None = None,
) -> Runbook:
    """Build a deterministic operator runbook from existing read-only evidence."""
    problems, docker_options = _problems_from_docker(evidence_items)
    pkg_options = _problems_from_packages(evidence_items)
    fo_options = _problems_from_file_owner(evidence_items)
    cc_options = _problems_from_config_changes(evidence_items)
    options = _sort_options(docker_options + pkg_options + fo_options + cc_options)
    for idx, opt in enumerate(options, 1):
        if not opt.id:
            opt.id = f"option:general:{idx}"
            opt.applies_to = ["general:investigation"]
        derived = option_risk_from_text(opt)
        if {RISK_LOW: 0, RISK_MEDIUM: 1, RISK_HIGH: 2}[derived] > {
            RISK_LOW: 0,
            RISK_MEDIUM: 1,
            RISK_HIGH: 2,
        }[opt.risk]:
            opt.risk = derived

    inv = _docker_inventory(evidence_items)
    healthy_names = []
    failing_names = {p.component for p in problems}
    for row in inv:
        name = row.get("name") or ""
        state = (row.get("state") or "").lower()
        if name and state == "running" and name not in failing_names:
            healthy_names.append(name)

    prechecks = [
        "Confirm the change window and incident scope before touching anything.",
        "Review evidence.json and summary.md from this session.",
    ]
    if any(i.source == "docker.problem_summary" for i in evidence_items):
        prechecks.append("Read-only: docker compose ps   # see container state at the time of fix")
    if any(i.source == "config.recent_changes" for i in evidence_items):
        prechecks.append("Read-only: review recently modified config files (config.recent_changes)")

    validation = [
        "shellforgeai diagnose <target> --json   # rerun read-only diagnose after the fix",
    ]
    if any(i.source == "docker.problem_summary" for i in evidence_items):
        validation.append(
            "docker compose ps   # confirm previously-failing containers are now running/healthy"
        )

    safety_notes = [
        SAFETY_LINE,
        (
            "All steps marked OPERATOR-RUN must be executed by a human operator with "
            "approval. ShellForgeAI's apply remains validation-only in this alpha."
        ),
    ]
    if healthy_names:
        safety_notes.append(
            "Known-good baseline (no remediation needed): " + ", ".join(sorted(healthy_names))
        )

    rb = Runbook(
        session_id=session_id,
        target=target,
        source_artifacts=list(source_artifacts or []),
        problems=problems,
        risk_level=_risk_level(options),
        prechecks=prechecks,
        operator_steps=options,
        rollback=[
            "Each operator-run option above includes a per-option rollback. Always capture "
            "current state before editing files or recreating containers.",
        ],
        validation=validation,
        safety_notes=safety_notes,
        executive_summary=_executive_summary(problems),
    )
    return rb


def render_runbook_md(rb: Runbook) -> str:
    """Render a :class:`Runbook` as operator-friendly Markdown."""
    lines: list[str] = []
    lines.append("# ShellForgeAI Operator Runbook")
    lines.append("")
    lines.append(f"- Session: {rb.session_id}")
    lines.append(f"- Target: {rb.target}")
    lines.append(f"- Generated: {rb.generated_at.isoformat()}")
    if rb.source_artifacts:
        lines.append("- Source evidence: " + ", ".join(rb.source_artifacts))
    lines.append("- Safety mode: read-only / operator-run only")
    lines.append(f"- Overall risk: {rb.risk_level}")
    lines.append("")
    lines.append("## Executive summary")
    lines.append("")
    lines.append(rb.executive_summary or "No actionable problems were identified.")
    lines.append("")

    lines.append("## Problems found")
    lines.append("")
    if not rb.problems:
        lines.append("- None identified from the available evidence.")
    else:
        for p in rb.problems:
            lines.append(f"### {p.name}")
            lines.append(f"- Severity: {p.severity}")
            lines.append(f"- Confidence: {p.confidence}")
            if p.likely_cause:
                lines.append(f"- Likely cause: {p.likely_cause}")
            if p.evidence:
                lines.append("- Evidence:")
                for e in p.evidence:
                    lines.append(f"  - {e}")
            lines.append("")

    lines.append("## Pre-checks before changing anything")
    lines.append("")
    for c in rb.prechecks:
        lines.append(f"- {c}")
    lines.append("")

    lines.append("## Operator-run remediation options")
    lines.append("")
    if not rb.operator_steps:
        lines.append(
            "- No remediation options were generated. ShellForgeAI did not execute anything."
        )
    else:
        for i, opt in enumerate(rb.operator_steps, 1):
            lines.append(f"### Option {i}: {opt.title}")
            lines.append(f"- Label: {opt.label}")
            lines.append(f"- Risk: {opt.risk}")
            if opt.impact:
                lines.append(f"- Impact: {opt.impact}")
            if opt.preconditions:
                lines.append("- Preconditions:")
                for pc in opt.preconditions:
                    lines.append(f"  - {pc}")
            if opt.steps:
                lines.append("- Steps (OPERATOR-RUN, ShellForgeAI did not execute these):")
                lines.append("")
                lines.append("```sh")
                for s in opt.steps:
                    lines.append(s)
                lines.append("```")
            if opt.rollback:
                lines.append("- Rollback:")
                for r in opt.rollback:
                    lines.append(f"  - {r}")
            if opt.verification:
                lines.append("- Verification:")
                for v in opt.verification:
                    lines.append(f"  - {v}")
            if opt.notes:
                lines.append(f"- Notes: {opt.notes}")
            lines.append("")

    lines.append("## Recommended order")
    lines.append("")
    if rb.operator_steps:
        for i, opt in enumerate(rb.operator_steps, 1):
            lines.append(f"{i}. ({opt.risk}) {opt.title}")
    else:
        lines.append("- N/A")
    lines.append("")

    lines.append("## Post-fix validation")
    lines.append("")
    for v in rb.validation:
        lines.append(f"- {v}")
    lines.append("")

    lines.append("## Rollback notes")
    lines.append("")
    for r in rb.rollback:
        lines.append(f"- {r}")
    lines.append("")

    lines.append("## Safety note")
    lines.append("")
    for s in rb.safety_notes:
        lines.append(f"- {s}")
    lines.append("")

    return "\n".join(lines)


def runbook_from_evidence_file(
    path: Path, *, session_id: str | None = None, target: str | None = None
) -> Runbook:
    """Build a runbook by loading an ``evidence.json`` artifact from disk."""
    bundle = EvidenceBundle.model_validate_json(path.read_text(encoding="utf-8"))
    sid = session_id or path.parent.name
    tgt = target or bundle.target
    return build_runbook(
        session_id=sid,
        target=tgt,
        evidence_items=list(bundle.items),
        source_artifacts=[str(path)],
    )


def latest_evidence_artifact(data_dir: Path) -> Path | None:
    """Return the most recent ``evidence.json`` under ``<data_dir>/artifacts``."""
    root = Path(data_dir) / "artifacts"
    if not root.exists():
        return None
    candidates = sorted(
        (p for p in root.glob("sf_*/evidence.json") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
    )
    return candidates[-1] if candidates else None
