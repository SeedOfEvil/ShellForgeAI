from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field

from shellforgeai.core.collectors import (
    WINDOWS_PERFORMANCE_NEXT_SAFE_COMMANDS,
    collect_config_evidence,
    collect_disk_evidence,
    collect_docker_evidence,
    collect_firewall_evidence,
    collect_health_evidence,
    collect_host_evidence,
    collect_local_knowledge_evidence,
    collect_logs_auth_evidence,
    collect_logs_basic_evidence,
    collect_logs_deep_dive_evidence,
    collect_logs_service_evidence,
    collect_network_evidence,
    collect_nginx_evidence,
    collect_package_evidence,
    collect_path_ownership_evidence,
    collect_performance_evidence,
    collect_service_evidence,
    collect_ssh_evidence,
    collect_windows_performance_evidence,
)
from shellforgeai.core.command_suggestions import (
    remediation_eligibility_explain_command,
    triage_detail_command,
)
from shellforgeai.core.evidence import EvidenceBundle, TargetType, classify_target
from shellforgeai.core.plans import Plan, PlanStep
from shellforgeai.core.triage_ranking import collect_scene, rank_scene
from shellforgeai.platform_detection import detect_platform
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
    triage_context: dict[str, object] = Field(default_factory=dict)
    container_scope: dict[str, object] = Field(default_factory=dict)
    runtime_context: dict[str, object] = Field(default_factory=dict)
    safe_next_commands: list[str] = Field(default_factory=list)
    safety: dict[str, bool] = Field(default_factory=dict)


def _docker_triage_context(
    items, target: str
) -> tuple[dict[str, object], dict[str, object], list[str]]:
    import json as _json

    summary = next((i for i in items if i.source == "docker.problem_summary" and i.ok), None)
    if summary is None:
        try:
            ranked = rank_scene(collect_scene())
        except Exception:
            return {}, {}, []
        hit = next(
            (s for s in ranked.get("suspects") or [] if str(s.get("name") or "") == target), None
        )
        if hit is None:
            return {}, {}, []
        detail = triage_detail_command(target)
        eligibility = remediation_eligibility_explain_command(target)
        return (
            {
                "detected": True,
                "target": target,
                "kind": "docker_container",
                "rank": hit.get("rank"),
                "severity": hit.get("severity"),
                "confidence": hit.get("confidence"),
                "classes": list(hit.get("classes") or []),
                "evidence_summary": list(hit.get("why") or []),
                "detail_command": detail,
                "eligibility_command": eligibility,
            },
            {
                "detected": True,
                "host_checks_demoted": True,
                "notes": [
                    "Host service checks are not primary for this target.",
                    "Use triage docker detail for container scenario evidence.",
                ],
            },
            [
                detail,
                triage_detail_command(target, json=True),
                eligibility,
                remediation_eligibility_explain_command(target, json=True),
            ],
        )
    try:
        payload = _json.loads(summary.content or summary.summary or "{}")
    except (ValueError, _json.JSONDecodeError):
        return {}, {}, []
    scene = {"containers": (payload.get("failing") or []) + (payload.get("noisy") or [])}
    ranked = rank_scene(scene)
    hit = next(
        (s for s in ranked.get("suspects") or [] if str(s.get("name") or "") == target), None
    )
    if hit is None:
        return {}, {}, []
    detail = triage_detail_command(target)
    eligibility = remediation_eligibility_explain_command(target)
    return (
        {
            "detected": True,
            "target": target,
            "kind": "docker_container",
            "rank": hit.get("rank"),
            "severity": hit.get("severity"),
            "confidence": hit.get("confidence"),
            "classes": list(hit.get("classes") or []),
            "evidence_summary": list(hit.get("why") or []),
            "detail_command": detail,
            "eligibility_command": eligibility,
        },
        {
            "detected": True,
            "host_checks_demoted": True,
            "notes": [
                "Host service checks are not primary for this target.",
                "Use triage docker detail for container scenario evidence.",
            ],
        },
        [
            detail,
            triage_detail_command(target, json=True),
            eligibility,
            remediation_eligibility_explain_command(target, json=True),
        ],
    )


def finding_severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "warning": 0, "info": 0, "limitation": 0}
    for f in findings:
        sev = str(getattr(f, "severity", "warning"))
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def findings_summary_line(findings: list[Finding]) -> str:
    counts = displayed_finding_severity_counts(findings)
    parts = [f"{counts['critical']} critical", f"{counts['warning']} warning"]
    tail = counts["info"] + counts["limitation"]
    if tail:
        parts.append(f"{tail} info/limitations")
    return "Findings: " + ", ".join(parts)


def displayed_finding_severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "warning": 0, "info": 0, "limitation": 0}
    has_system_lim = any(
        any(
            tok in str(getattr(f, "title", "")).lower()
            for tok in (
                "systemd.",
                "journal.",
                "systemd is unavailable",
                "journalctl is unavailable",
            )
        )
        for f in findings
    )
    if has_system_lim:
        counts["limitation"] += 1
    for f in findings:
        sev = str(getattr(f, "severity", "warning"))
        title = str(getattr(f, "title", "")).lower()
        if has_system_lim and ("systemd" in title or "journalctl" in title or "journal." in title):
            continue
        if "process.find" in title or "logs.file_tail reported error" in title:
            continue
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _is_container(items) -> bool:
    for i in items:
        if i.source == "system.container_detect":
            text = f"{i.summary} {i.content}".lower()
            if "docker" in text or "container" in text:
                return True
    return False


def _runtime_context(items) -> dict[str, object]:
    inside_container = _is_container(items)
    if not inside_container:
        return {
            "inside_container": False,
            "visibility": "runtime_scoped",
            "view": "runtime-local diagnosis",
            "limitations": [],
        }
    return {
        "inside_container": True,
        "visibility": "container_limited",
        "view": "host_oriented_from_container_namespace",
        "limitations": [
            "systemd/journal may not be visible",
            "host firewall state may not be visible",
            "host process/listener view may be incomplete",
        ],
    }


def _is_benign_storage_error_summary(item) -> bool:
    if item.source != "storage.error_summary":
        return False
    txt = f"{item.summary} {item.content}".lower()
    return any(s in txt for s in ["no recent storage error patterns found", "0 hits", "none found"])


def _looks_like_not_found(text: str) -> bool:
    return any(s in text for s in ["not found", "no such file", "no matching process"])


def _findings_from_docker(items) -> list[Finding]:
    import json as _json

    findings: list[Finding] = []
    inv = next((i for i in items if i.source == "docker.containers"), None)
    summary = next((i for i in items if i.source == "docker.problem_summary"), None)
    if summary is not None and not summary.ok:
        if (
            "not available" in (summary.summary or "").lower()
            or "unavailable" in (summary.summary or "").lower()
        ):
            findings.append(
                Finding(
                    severity="limitation",
                    title="Docker visibility is unavailable from this runtime",
                    detail=(
                        "Docker CLI/daemon was not reachable; container failures cannot be "
                        "diagnosed from this view."
                    ),
                    evidence_refs=["docker.problem_summary"],
                    confidence="high",
                )
            )
        return findings
    if summary is None or not summary.ok:
        return findings
    try:
        payload = _json.loads(summary.content or summary.summary or "{}")
    except (ValueError, _json.JSONDecodeError):
        payload = {}
    for entry in payload.get("failing", []) or []:
        name = entry.get("name") or "container"
        state = (entry.get("state") or "").lower()
        themes = entry.get("log_themes") or {}
        ec = entry.get("exit_code")
        rc = entry.get("restart_count") or 0
        if state == "restarting" or rc and int(rc) >= 3:
            sev = "critical"
            title = f"{name} appears to be in a restart loop"
        elif state == "exited":
            sev = "warning"
            title = f"{name} exited with code {ec}"
        elif entry.get("oom_killed"):
            sev = "critical"
            title = f"{name} was OOM-killed"
        else:
            sev = "warning"
            title = f"{name} is in an unhealthy state ({state})"
        if themes.get("missing_required_setting"):
            title += " (missing required setting)"
        elif themes.get("read_only_fs") or themes.get("permission_denied"):
            title += " (write/permission failure)"
        elif themes.get("dns_failure") or themes.get("upstream_unreachable"):
            title += " (network/DNS failure in logs)"
        elif themes.get("connection_refused"):
            title += " (connection refused in logs)"
        elif themes.get("timeout"):
            title += " (timeout in logs)"
        elif themes.get("tls_certificate"):
            title += " (TLS/certificate failure in logs)"
        elif themes.get("simulated_crash") or themes.get("traceback"):
            title += " (repeated crash)"
        findings.append(
            Finding(
                severity=sev,
                title=title,
                detail=(
                    f"state={state} exit_code={ec} restart_count={rc} "
                    f"themes={','.join(themes.keys()) or 'none'}"
                ),
                evidence_refs=["docker.problem_summary"],
                confidence="high",
            )
        )
    for entry in payload.get("noisy", []) or []:
        name = entry.get("name") or "container"
        themes = entry.get("log_themes") or {}
        net_themes = [
            t
            for t in (
                "dns_failure",
                "upstream_unreachable",
                "connection_refused",
                "timeout",
                "tls_certificate",
            )
            if themes.get(t)
        ]
        if net_themes:
            sev = "warning"
            theme_label = "/".join(t.replace("_", " ") for t in net_themes)
            title = f"{name} is running but logs show {theme_label} (app/container reachability)"
        else:
            sev = "info"
            title = f"{name} is running but logs contain WARN/ERROR noise (not a crash)"
        findings.append(
            Finding(
                severity=sev,
                title=title,
                detail=f"themes={','.join(themes.keys()) or 'none'}",
                evidence_refs=["docker.problem_summary"],
                confidence="medium",
            )
        )
    if inv is None and summary.ok:
        # ok but no inventory item; nothing to add
        pass
    return findings


def _findings_from_logs(items) -> list[Finding]:
    findings: list[Finding] = []
    in_container = _is_container(items)
    common_paths_item = next((i for i in items if i.source == "logs.common_paths"), None)
    recent_item = next((i for i in items if i.source == "logs.recent_errors"), None)
    auth_item = next((i for i in items if i.source == "logs.auth_errors"), None)
    kernel_item = next((i for i in items if i.source == "logs.kernel_errors"), None)
    themes_item = next((i for i in items if i.source == "logs.error_themes"), None)
    no_visible_logs = False
    if common_paths_item and "readable_logs=0" in (common_paths_item.summary or ""):
        no_visible_logs = True
        findings.append(
            Finding(
                severity="limitation",
                title="No common readable log files were visible",
                detail=(
                    "No common log files were readable from this runtime context"
                    + (" (container view)" if in_container else "")
                    + "."
                ),
                evidence_refs=["logs.common_paths"],
                confidence="high",
            )
        )
    if (
        recent_item
        and recent_item.ok
        and "no recent error-like patterns found" in (recent_item.summary or "").lower()
        and not no_visible_logs
    ):
        findings.append(
            Finding(
                severity="info",
                title="Visible logs did not contain recent error patterns",
                detail="Bounded scan found no recent error-like lines.",
                evidence_refs=["logs.recent_errors"],
                confidence="medium",
            )
        )
    if recent_item and recent_item.ok and "total=" in (recent_item.summary or ""):
        try:
            total = int((recent_item.summary or "").split("total=", 1)[1].split()[0])
        except (ValueError, IndexError):
            total = 0
        if total > 0:
            findings.append(
                Finding(
                    severity="warning",
                    title="Recent error-like log patterns were found",
                    detail=recent_item.summary,
                    evidence_refs=["logs.recent_errors"],
                    confidence="medium",
                )
            )
    if auth_item and auth_item.ok and "auth_errors total=" in (auth_item.summary or ""):
        try:
            total = int(auth_item.summary.split("total=", 1)[1].split()[0])
        except (ValueError, IndexError):
            total = 0
        if total > 0:
            findings.append(
                Finding(
                    severity="warning",
                    title="Auth log failures detected",
                    detail=auth_item.summary,
                    evidence_refs=["logs.auth_errors"],
                    confidence="medium",
                )
            )
    if kernel_item and kernel_item.ok:
        summ = kernel_item.summary or ""
        if "files_total=" in summ:
            try:
                ftotal = int(summ.split("files_total=", 1)[1].split()[0])
            except (ValueError, IndexError):
                ftotal = 0
            try:
                dtotal = int(summ.split("dmesg_matches=", 1)[1].split()[0])
            except (ValueError, IndexError):
                dtotal = 0
            if ftotal + dtotal > 0:
                findings.append(
                    Finding(
                        severity="critical",
                        title="Kernel/system error patterns were found",
                        detail=summ,
                        evidence_refs=["logs.kernel_errors"],
                        confidence="medium",
                    )
                )
    if themes_item and themes_item.ok and "themes:" in (themes_item.summary or "").lower():
        findings.append(
            Finding(
                severity="info",
                title="Error theme summary",
                detail=themes_item.summary,
                evidence_refs=["logs.error_themes"],
                confidence="medium",
            )
        )
    return findings


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


_PERFORMANCE_FAMILY_KEYWORDS = (
    "slow",
    "sluggish",
    "laggy",
    "performance",
    "high cpu",
    "high memory",
    "high load",
)


def _is_performance_family_target(canonical_target: str, target: str) -> bool:
    if canonical_target in {"host", "health", "storage-performance", "disk_storage_deep_dive"}:
        return True
    low = target.lower()
    return any(k in low for k in _PERFORMANCE_FAMILY_KEYWORDS)


def _windows_performance_diagnosis(
    context, target: str, ttype: TargetType, warnings: list[str], platform_info
) -> DiagnosisResult:
    """Bounded read-only Windows diagnosis for slow-system/performance asks.

    Runs no Linux-only collectors, no shell execution, no remoting, and no
    mutation; missing metrics are marked unavailable instead of rendered as
    fake zero values.
    """
    items = collect_windows_performance_evidence(context, platform_info)
    memory_item = next((item for item in items if item.source == "system.cpu_memory"), None)
    memory_available = bool(memory_item) and memory_item.metadata.get("status") == "ok"
    if memory_available:
        memory_finding = Finding(
            severity="info",
            title="Windows memory summary collected (read-only)",
            detail=(
                "Windows physical memory posture was collected read-only via "
                f"GlobalMemoryStatusEx: {memory_item.summary}."
            ),
            evidence_refs=["system.cpu_memory"],
            confidence="high",
        )
    else:
        memory_finding = Finding(
            severity="limitation",
            title="Memory summary unavailable from this collector",
            detail=(
                "Windows physical memory totals could not be collected here; missing "
                "values are marked unavailable rather than rendered as 0.0GiB/0.0GiB."
            ),
            evidence_refs=["system.cpu_memory"],
            confidence="high",
        )
    findings = [
        Finding(
            severity="info",
            title="Windows host: Linux-only collectors were skipped",
            detail=(
                "This host runs Windows, so Linux-oriented collectors (uptime, df, ip, "
                "ss, ps, systemctl, /proc, /etc/resolv.conf) were skipped instead of "
                "executed or reported as failures."
            ),
            evidence_refs=["platform.detect"],
            confidence="high",
        ),
        Finding(
            severity="limitation",
            title="Load average is not available on Windows",
            detail="Windows does not expose a Linux-style load average from this collector.",
            evidence_refs=["host.resources"],
            confidence="high",
        ),
        memory_finding,
    ]
    plan = Plan(
        plan_id=f"plan_{uuid4().hex[:8]}",
        goal=f"Diagnose {target}",
        session_id=context.session.session_id,
        steps=[
            PlanStep(
                step_id="1",
                title="Review Windows platform evidence",
                description=(
                    "Review the read-only Windows status and disk capacity evidence "
                    "collected without shelling out."
                ),
            ),
            PlanStep(
                step_id="2",
                title="Run bounded Windows read-only commands",
                description=(
                    "Use shellforgeai windows status --json and "
                    "shellforgeai windows processes --json --limit 10 for local evidence."
                ),
            ),
            PlanStep(
                step_id="3",
                title="Decide operator follow-up",
                description=(
                    "Deeper Windows performance metrics remain future work; any "
                    "remediation stays operator-run."
                ),
            ),
        ],
        notes=[
            "Read-only Windows diagnostics only; no shell execution, no remoting, and no mutation.",
        ],
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
        runtime_context={
            "inside_container": False,
            "visibility": "windows_local_read_only",
            "view": "windows read-only diagnostics",
            "limitations": [
                "Linux-only collectors are skipped on Windows",
                (
                    "load average is not available on Windows; memory summary collected read-only"
                    if memory_available
                    else "load average and memory metrics are unavailable on Windows"
                ),
            ],
        },
        safe_next_commands=list(WINDOWS_PERFORMANCE_NEXT_SAFE_COMMANDS),
        safety={
            "read_only": True,
            "mutation_performed": False,
            "plan_created": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "cleanup_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "natural_language_execution": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
        },
    )


def diagnose_target(
    context, target: str, online: bool = False, since: str = "30m"
) -> DiagnosisResult:
    ttype = classify_target(target)
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
    platform_info = detect_platform()
    if platform_info.system == "windows" and _is_performance_family_target(
        canonical_target, target
    ):
        # Windows slow-system/performance route: never execute Linux-only
        # collectors; return bounded read-only Windows evidence instead.
        return _windows_performance_diagnosis(context, target, ttype, warnings, platform_info)
    items = collect_host_evidence(context)
    log_targets = {
        "logs",
        "errors",
        "log",
        "error",
        "logs_basic",
        "logs_deep_dive",
        "log_deep_dive",
    }
    log_auth_targets = {"auth", "auth-logs", "logs_auth", "login", "logins"}
    log_service_prefix = "logs:"
    if canonical_target in log_targets:
        items.extend(collect_logs_basic_evidence(context))
        if canonical_target in {"logs_deep_dive", "log_deep_dive"}:
            items.extend(collect_logs_deep_dive_evidence(context))
        items = _dedupe(items)
        bundle = EvidenceBundle(
            target=target, target_type=TargetType.generic, items=items, warnings=warnings
        )
        plan = Plan(
            plan_id=f"plan_{uuid4().hex[:8]}",
            goal=f"Diagnose {target}",
            session_id=context.session.session_id,
            steps=[
                PlanStep(
                    step_id="1",
                    title="Review visible log sources",
                    description="Check which common logs are readable from this runtime.",
                ),
                PlanStep(
                    step_id="2",
                    title="Review recent error themes",
                    description="Inspect bounded error samples grouped by theme.",
                ),
                PlanStep(
                    step_id="3",
                    title="Decide on targeted follow-up",
                    description=(
                        "Pick service-specific log triage if a theme points at a service."
                    ),
                ),
            ],
            notes=["Read-only log triage only; no log mutation is performed."],
        )
        for i in items:
            if not i.ok:
                continue
        return DiagnosisResult(
            session_id=context.session.session_id,
            target=target,
            target_type=TargetType.generic,
            evidence=bundle,
            findings=_findings_from_logs(items) + _findings_from_docker(items),
            proposed_plan=plan,
            warnings=warnings,
        )
    if canonical_target in log_auth_targets:
        items.extend(collect_logs_auth_evidence(context))
        items = _dedupe(items)
        bundle = EvidenceBundle(
            target=target, target_type=TargetType.generic, items=items, warnings=warnings
        )
        plan = Plan(
            plan_id=f"plan_{uuid4().hex[:8]}",
            goal=f"Diagnose {target}",
            session_id=context.session.session_id,
            steps=[
                PlanStep(
                    step_id="1",
                    title="Review auth log visibility",
                    description="Check which auth/secure logs are readable.",
                ),
                PlanStep(
                    step_id="2",
                    title="Review failed auth themes",
                    description=(
                        "Look for failed passwords, invalid users, sudo failures, PAM errors."
                    ),
                ),
                PlanStep(
                    step_id="3",
                    title="Plan operator follow-up",
                    description="No mutation; recommend operator-run remediation steps.",
                ),
            ],
            notes=["Read-only auth log triage only."],
        )
        return DiagnosisResult(
            session_id=context.session.session_id,
            target=target,
            target_type=TargetType.generic,
            evidence=bundle,
            findings=_findings_from_logs(items) + _findings_from_docker(items),
            proposed_plan=plan,
            warnings=warnings,
        )
    if target.lower().startswith(log_service_prefix):
        svc = target.split(":", 1)[1].strip() or "service-discovery"
        items.extend(collect_logs_service_evidence(context, svc, since=since))
        items = _dedupe(items)
        bundle = EvidenceBundle(
            target=target, target_type=TargetType.service, items=items, warnings=warnings
        )
        plan = Plan(
            plan_id=f"plan_{uuid4().hex[:8]}",
            goal=f"Diagnose {target}",
            session_id=context.session.session_id,
            steps=[
                PlanStep(
                    step_id="1",
                    title="Review service log visibility",
                    description=f"Check what is visible for {svc}.",
                ),
                PlanStep(
                    step_id="2",
                    title="Review recent error themes",
                    description="Inspect bounded error samples grouped by theme.",
                ),
                PlanStep(
                    step_id="3",
                    title="Plan operator follow-up",
                    description="Read-only triage; no mutation is performed.",
                ),
            ],
            notes=["Read-only service log triage only."],
        )
        return DiagnosisResult(
            session_id=context.session.session_id,
            target=target,
            target_type=TargetType.service,
            evidence=bundle,
            findings=_findings_from_logs(items) + _findings_from_docker(items),
            proposed_plan=plan,
            warnings=warnings,
        )

    if canonical_target.startswith("packages:"):
        pkg = canonical_target.split(":", 1)[1].strip()
        items.extend(collect_package_evidence(context, target=pkg))
    elif canonical_target.startswith("package-owner:"):
        owner_path = target.split(":", 1)[1].strip() if ":" in target else ""
        items.extend(collect_path_ownership_evidence(context, owner_path))
        items.extend(collect_package_evidence(context, owner_path=owner_path))
    elif canonical_target in {"packages", "package", "changes", "change", "config"}:
        if canonical_target in {"packages", "package"}:
            items.extend(collect_package_evidence(context))
        elif canonical_target == "config":
            items.extend(collect_config_evidence(context))
        else:
            items.extend(collect_package_evidence(context))
            items.extend(collect_config_evidence(context))
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
    elif (
        ttype == TargetType.service or canonical_target == "service-discovery"
    ) and not canonical_target.startswith("package-owner:"):
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
    service_missing_signal = False
    if ttype == TargetType.service and target.lower() in {"nginx", "ssh", "sshd", "docker"}:
        service_missing_signal = any(
            _looks_like_not_found(f"{i.summary} {i.content}".lower()) for i in items
        )

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
            if service_missing_signal and (
                i.source.startswith("process.find") or i.source == "logs.file_tail"
            ):
                continue
            if i.source == "logs.file_tail" and target.lower() == "nginx":
                findings.append(
                    Finding(
                        severity="limitation",
                        title="nginx log files were not available from this environment",
                        detail="Nginx log paths could not be read from this environment.",
                        evidence_refs=[i.source],
                        confidence="medium",
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
    if ttype == TargetType.service and target.lower() == "nginx":
        proc_missing = any(
            i.source == "service.processes" and ("not found" in i.summary.lower() or not i.ok)
            for i in items
        )
        listener_missing = any(
            i.source == "service.ports" and "listeners=none" in i.summary.lower() for i in items
        )
        if proc_missing and listener_missing:
            findings.append(
                Finding(
                    severity="warning",
                    title="nginx was not found running in this environment",
                    detail=(
                        "No nginx process or expected listener was visible from this runtime; "
                        "confirm whether nginx should run on the host or another container."
                    ),
                    evidence_refs=["service.processes", "service.ports"],
                    confidence="high",
                )
            )
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
    findings.extend(_findings_from_docker(items))
    triage_context, container_scope, safe_next_commands = _docker_triage_context(items, target)
    runtime_context = _runtime_context(items)
    if triage_context.get("detected"):
        demoted_refs: list[str] = []
        kept: list[Finding] = []
        for f in findings:
            lower = f.title.lower()
            if "systemd" in lower or "journalctl" in lower or "service manager" in lower:
                demoted_refs.extend(f.evidence_refs)
                continue
            kept.append(f)
        findings = kept
        if demoted_refs:
            findings.append(
                Finding(
                    severity="info",
                    title="Container-scope note",
                    detail=(
                        "Host service checks are not primary for this container target; "
                        "use triage docker detail for scenario-specific evidence."
                    ),
                    evidence_refs=demoted_refs,
                    confidence="high",
                )
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
        triage_context=triage_context,
        container_scope=container_scope,
        runtime_context=runtime_context,
        safe_next_commands=safe_next_commands,
        safety={
            "read_only": True,
            "mutation_performed": False,
            "plan_created": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "cleanup_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "natural_language_execution": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
        },
    )
