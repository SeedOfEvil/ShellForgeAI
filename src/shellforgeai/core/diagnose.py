from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field

from shellforgeai.core.collectors import (
    collect_disk_evidence,
    collect_docker_evidence,
    collect_firewall_evidence,
    collect_health_evidence,
    collect_host_evidence,
    collect_local_knowledge_evidence,
    collect_network_evidence,
    collect_nginx_evidence,
    collect_performance_evidence,
    collect_service_evidence,
    collect_ssh_evidence,
)
from shellforgeai.core.evidence import EvidenceBundle, TargetType, classify_target
from shellforgeai.core.plans import Plan, PlanStep
from shellforgeai.util.text import extract_lines_matching


class Finding(BaseModel):
    severity: str
    title: str
    detail: str
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: str = "medium"


class DiagnosisResult(BaseModel):
    session_id: str
    target: str
    target_type: TargetType
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: EvidenceBundle
    findings: list[Finding]
    proposed_plan: Plan
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    audit_path: str | None = None


def finding_severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "warning": 0, "info": 0, "limitation": 0}
    for f in findings:
        sev = str(getattr(f, "severity", "warning"))
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def findings_summary_line(findings: list[Finding]) -> str:
    counts = finding_severity_counts(findings)
    parts = [f"{counts['critical']} critical", f"{counts['warning']} warning"]
    tail = counts["info"] + counts["limitation"]
    if tail:
        parts.append(f"{tail} info/limitations")
    return "Findings: " + ", ".join(parts)


def _is_container(items) -> bool:
    for i in items:
        if i.source == "system.container_detect":
            text = f"{i.summary} {i.content}".lower()
            if "docker" in text or "container" in text:
                return True
    return False


def _is_benign_storage_error_summary(item) -> bool:
    if item.source != "storage.error_summary":
        return False
    txt = f"{item.summary} {item.content}".lower()
    return any(s in txt for s in ["no recent storage error patterns found", "0 hits", "none found"])


def _dedupe(items):
    seen = set()
    out = []
    for i in items:
        key = (i.source, i.path or "", " ".join(i.command or []), i.summary)
        if key in seen:
            continue
        seen.add(key)
        out.append(i)
    return out


def diagnose_target(
    context, target: str, online: bool = False, since: str = "30m"
) -> DiagnosisResult:
    ttype = classify_target(target)
    items = collect_host_evidence(context)
    findings: list[Finding] = []
    warnings: list[str] = []
    if online and not context.session.online_enabled:
        warnings.append("Online research requested but blocked by active profile/policy.")
    canonical_target = target.lower().strip()
    if canonical_target in {
        "services",
        "service-discovery",
        "listening",
        "ports",
        "service_deep_dive",
    }:
        canonical_target = "service-discovery"
        target = "service-discovery"
    if canonical_target in {"storage_performance", "disk-performance", "io", "iowait"}:
        canonical_target = "storage-performance"
        target = "storage-performance"
    if canonical_target in {"performance", "slow", "slowness", "host", "performance_deep_dive"}:
        canonical_target = "host"
    if target in {"health"} or canonical_target == "host":
        items.extend(collect_health_evidence(context))
    if any(
        k in target.lower() for k in ["slow", "performance", "high cpu", "high memory", "high load"]
    ):
        items.extend(collect_performance_evidence(context))
        items.extend(collect_disk_evidence(context))
        items.extend(collect_network_evidence(context))
        items.extend(collect_local_knowledge_evidence(context, "performance"))
    if canonical_target in {"storage-performance", "disk_storage_deep_dive"}:
        items.extend(collect_health_evidence(context))
        items.extend(collect_performance_evidence(context))
        items.extend(collect_disk_evidence(context))
        items.extend(collect_local_knowledge_evidence(context, "disk"))
    elif ttype == TargetType.service or canonical_target == "service-discovery":
        items.extend(collect_service_evidence(context, target, since=since))
        if target.lower() == "nginx":
            items.extend(collect_nginx_evidence(context))
        if target.lower() in {"ssh", "sshd"}:
            items.extend(collect_ssh_evidence(context))
        if target.lower() == "docker":
            items.extend(collect_docker_evidence(context))
        items.extend(collect_local_knowledge_evidence(context, target))
    elif ttype == TargetType.disk:
        items.extend(collect_disk_evidence(context))
    elif ttype == TargetType.network or canonical_target == "network_deep_dive":
        items.extend(collect_network_evidence(context))
        if "firewall" in target.lower():
            items.extend(collect_firewall_evidence(context))
    else:
        if "firewall" in target.lower():
            items.extend(collect_firewall_evidence(context))
        else:
            items.extend(collect_local_knowledge_evidence(context, target))
    items = _dedupe(items)
    in_container = _is_container(items)
    for i in items:
        if not i.ok:
            txt = f"{i.summary} {i.content}".lower()
            if i.source.startswith("systemd.") and "not found" in txt and in_container:
                findings.append(
                    Finding(
                        severity="limitation",
                        title="systemd is unavailable in this container",
                        detail=(
                            "Host-level systemd service state could not be checked "
                            "from this environment."
                        ),
                        evidence_refs=[i.source],
                        confidence="high",
                    )
                )
                continue
            if i.source.startswith("journal.") and "not found" in txt and in_container:
                findings.append(
                    Finding(
                        severity="limitation",
                        title="journalctl is unavailable in this container",
                        detail="Host-level journal logs are not visible from this environment.",
                        evidence_refs=[i.source],
                        confidence="high",
                    )
                )
                continue
            findings.append(
                Finding(
                    severity="limitation",
                    title=f"{i.source} reported error",
                    detail=i.summary,
                    evidence_refs=[i.source],
                    confidence="high",
                )
            )
            continue
        if _is_benign_storage_error_summary(i):
            continue
        matches = extract_lines_matching(
            i.content,
            [
                "error",
                "failed",
                "permission denied",
                "address already in use",
                "no such file",
                "connection refused",
            ],
            5,
        )
        if matches:
            if i.source == "storage.error_summary":
                severity = "warning"
                title = "Storage error patterns were detected"
            else:
                severity = "warning"
                title = f"Potential issues in {i.source}"
            findings.append(
                Finding(
                    severity=severity,
                    title=title,
                    detail="; ".join(matches),
                    evidence_refs=[i.source],
                    confidence="medium",
                )
            )
    if ttype == TargetType.service and target.lower() in {"nginx", "ssh", "sshd", "docker"}:
        for i in items:
            txt = f"{i.summary} {i.content}".lower()
            if i.source.endswith(".status") and any(
                s in txt for s in ["not found", "no such file", "no matching process"]
            ):
                findings.append(
                    Finding(
                        severity="warning",
                        title=f"{target.lower()} was not found in this environment",
                        detail=(
                            f"{target.lower()} was not found in this container; "
                            f"if {target.lower()} is expected, verify the correct host/container."
                        ),
                        evidence_refs=[i.source],
                        confidence="medium",
                    )
                )
                break
    if ttype == TargetType.disk:
        steps = [
            PlanStep(
                step_id="1",
                title="Review disk usage evidence",
                description="Review filesystem capacity from df output.",
            ),
            PlanStep(
                step_id="2",
                title="Check inode usage",
                description="Confirm inode pressure from inode evidence.",
            ),
            PlanStep(
                step_id="3",
                title="Check mount layout",
                description=(
                    "Review mount points and identify heavy paths for future "
                    "read-only du collection."
                ),
            ),
        ]
    elif ttype == TargetType.network or canonical_target == "network_deep_dive":
        steps = [
            PlanStep(
                step_id="1", title="Review routes", description="Validate routing table evidence."
            ),
            PlanStep(
                step_id="2",
                title="Review DNS config",
                description="Check resolver configuration and name resolution risks.",
            ),
            PlanStep(
                step_id="3",
                title="Review listeners",
                description=(
                    "Determine whether issue maps to DNS, routing, local listener, "
                    "or external path."
                ),
            ),
        ]
    elif ttype == TargetType.service:
        steps = [
            PlanStep(
                step_id="1",
                title="Check service manager availability",
                description=(
                    "Confirm systemd/journalctl availability and note container fallback mode."
                ),
            ),
            PlanStep(
                step_id="2",
                title="Check process and listeners",
                description="Verify process existence and expected ports.",
            ),
            PlanStep(
                step_id="3",
                title="Check config and logs",
                description="Inspect known config/log paths with read-only checks.",
            ),
        ]
    else:
        steps = [
            PlanStep(
                step_id="1",
                title="Review collected evidence",
                description="Inspect host/service signals and prioritize likely root cause.",
            ),
            PlanStep(
                step_id="2",
                title="Validate configuration manually",
                description="Check target-specific config files and syntax before any change.",
            ),
            PlanStep(
                step_id="3",
                title="Prepare operator-approved remediation",
                description=(
                    "Document exact change/reload steps for explicit approval in later phase."
                ),
            ),
        ]
    plan = Plan(
        plan_id=f"plan_{uuid4().hex[:8]}",
        goal=f"Diagnose {target}",
        session_id=context.session.session_id,
        steps=steps,
        notes=["Restart/reload actions are deferred and require operator approval."],
    )
    bundle = EvidenceBundle(target=target, target_type=ttype, items=items, warnings=warnings)
    return DiagnosisResult(
        session_id=context.session.session_id,
        target=target,
        target_type=ttype,
        evidence=bundle,
        findings=findings,
        proposed_plan=plan,
        warnings=warnings,
    )
