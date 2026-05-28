"""Friendly diagnosis mini-report writer.

Produces a compact human-readable summary.md that is consistent with
evidence.json (same evidence count) and only references artifact files
that actually exist on disk.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from shellforgeai.core.diagnose import displayed_finding_severity_counts, finding_severity_counts

_ARTIFACT_LABELS = {
    "evidence.json": "evidence.json",
    "plan.json": "plan.json",
    "summary.md": "summary.md",
    "model-response.md": "model-response.md",
}


def _by_source(items: Iterable) -> dict[str, object]:
    by: dict[str, object] = {}
    for it in items:
        by.setdefault(getattr(it, "source", ""), it)
    return by


def _short_summary(item) -> str:
    s = (getattr(item, "summary", "") or "").strip()
    return s.splitlines()[0] if s else ""


def _human_load(raw: str) -> str:
    nums = re.findall(r"\d+\.\d+|\d+", raw)
    if len(nums) >= 3:
        a, b, c = (float(n) for n in nums[:3])
        return f"{a:.2f} / {b:.2f} / {c:.2f}"
    return raw or "unavailable"


def _human_cpu_mem(raw: str) -> str:
    m = re.search(r"cpus=(\d+).*mem=(\d+\.\d+)GiB/(\d+\.\d+)GiB.*swap=([^ ]+)", raw)
    if not m:
        return raw or "unavailable"
    cpus, used, total, swap = m.groups()
    swap_txt = "swap unused" if swap.startswith("0B/") else f"swap {swap}"
    return f"{cpus} CPUs visible, {used} GiB / {total} GiB used, {swap_txt}"


def _human_container(raw: str) -> str:
    low = (raw or "").lower()
    if "docker" in low:
        return "Docker / container view"
    if "container=no" in low:
        return "no container detected"
    return "container context unknown"


def _human_storage_pressure(raw: str) -> str:
    nums = dict(
        re.findall(
            r"(io_some_avg10|io_some_avg60|io_some_avg300|avg10|avg60|avg300)=([0-9.]+)",
            raw or "",
        )
    )
    a10 = nums.get("avg10") or nums.get("io_some_avg10")
    a60 = nums.get("avg60") or nums.get("io_some_avg60")
    a300 = nums.get("avg300") or nums.get("io_some_avg300")
    if not (a10 and a60 and a300):
        return raw or "no pressure data"
    if float(a10) == 0 and float(a60) == 0 and float(a300) == 0:
        return "no pressure reported"
    return f"non-zero pressure (avg10 {a10} / avg60 {a60} / avg300 {a300})"


def _key_evidence_lines(items: Iterable) -> list[str]:
    by = _by_source(items)
    lines: list[str] = []
    if "system.cpu_memory" in by:
        lines.append(f"- CPU/memory: {_human_cpu_mem(_short_summary(by['system.cpu_memory']))}.")
    if "host.resources" in by:
        lines.append(f"- Load: {_human_load(_short_summary(by['host.resources']))}.")
    if "disk.usage" in by or "disk.inodes" in by:
        d = _short_summary(by.get("disk.usage")) if by.get("disk.usage") else "unknown"
        i = _short_summary(by.get("disk.inodes")) if by.get("disk.inodes") else "unknown"
        lines.append(f"- Disk / inodes: {d}; {i}.")
    if "storage.pressure" in by:
        lines.append(
            f"- Storage / I/O: {_human_storage_pressure(_short_summary(by['storage.pressure']))}."
        )
    if "process.top" in by:
        s = _short_summary(by["process.top"])
        if s:
            lines.append(f"- Top process: {s}.")
    if "system.container_detect" in by:
        lines.append(
            f"- Context: {_human_container(_short_summary(by['system.container_detect']))}."
        )
    if "systemd.list_failed" in by:
        s = _short_summary(by["systemd.list_failed"]) or "unavailable in this context"
        lines.append(f"- Service manager: {s}.")
    return lines[:8]


def _short_assessment(items: Iterable, displayed_sev: dict[str, int]) -> str:
    sev = displayed_sev
    actionable = sev.get("critical", 0) + sev.get("warning", 0)
    if actionable == 0 and (sev.get("info", 0) + sev.get("limitation", 0)) > 0:
        return (
            "Read-only checks found no actionable issue, but some host-level checks "
            "are limited from this container."
        )
    if actionable == 0:
        return "No actionable findings were raised by deterministic checks."
    by = _by_source(items)
    if sev.get("critical", 0) == 0:
        lim = sev.get("limitation", 0)
        lim_word = "limitation" if lim == 1 else "limitations"
        return (
            "Read-only checks found "
            f"{sev.get('warning', 0)} warning and {lim} context {lim_word}. "
            "No critical issues were found."
        )
    high_disk = False
    disk_item = by.get("disk.usage")
    if disk_item:
        for n in re.findall(r"(\d+)%", _short_summary(disk_item)):
            if int(n) >= 90:
                high_disk = True
    if high_disk:
        return "Filesystem usage looks critical and should be reviewed first."
    return "Read-only checks found critical issues that should be reviewed immediately."


def _humanize_findings(findings: list) -> list[str]:
    out: list[str] = []
    system_tokens = ("systemd.", "journal.", "systemd is unavailable", "journalctl is unavailable")
    has_system_lim = any(
        any(tok in getattr(f, "title", "").lower() for tok in system_tokens) for f in findings
    )
    if has_system_lim:
        out.append(
            "- Limitation: systemd and journal checks are unavailable in this container, so "
            "host-level service state could not be inspected from here."
        )
    for f in findings:
        sev = str(getattr(f, "severity", "warning")).title()
        title = str(getattr(f, "title", "finding"))
        if has_system_lim and (
            "systemd" in title.lower()
            or "journalctl" in title.lower()
            or "journal." in title.lower()
        ):
            continue
        if "process.find" in title or "logs.file_tail reported error" in title:
            continue
        out.append(f"- {sev}: {title}")
    return out


def _existing_artifacts(
    artifact_dir: Path, candidates: Iterable[str], assume_present: Iterable[str] = ()
) -> list[str]:
    assume = set(assume_present)
    out: list[str] = []
    for name in candidates:
        if name in assume or (artifact_dir / name).exists():
            out.append(_ARTIFACT_LABELS.get(name, name))
    return out


def write_diagnosis_summary_md(
    *,
    path: Path,
    session_id: str,
    target: str,
    target_type: str,
    created_at: str,
    evidence_items: list,
    findings: list,
    runtime_context: dict[str, object] | None = None,
    artifact_dir: Path,
    artifact_candidates: Iterable[str] = (
        "evidence.json",
        "plan.json",
        "summary.md",
        "model-response.md",
    ),
) -> None:
    """Write a friendly mini-report to summary.md.

    The evidence count is taken from ``evidence_items`` so it always matches
    ``evidence.json``. Only artifact files that exist on disk are listed.
    """
    evidence_count = len(evidence_items)
    findings_count = len(findings)
    sev = finding_severity_counts(findings)
    displayed_sev = displayed_finding_severity_counts(findings)
    assessment = _short_assessment(evidence_items, displayed_sev)
    key_lines = _key_evidence_lines(evidence_items)
    artifacts = _existing_artifacts(artifact_dir, artifact_candidates, assume_present={path.name})
    findings_block: list[str]
    actionable = sev.get("critical", 0) + sev.get("warning", 0)
    if (
        actionable == 0
        and (displayed_sev.get("critical", 0) + displayed_sev.get("warning", 0)) == 0
    ):
        findings_block = ["No actionable findings were raised by deterministic checks."]
        displayed_count = 0
        displayed_sev = {"critical": 0, "warning": 0, "info": 0, "limitation": 0}
    else:
        findings_block = _humanize_findings(findings[:8])
        if findings_count > 8:
            findings_block.append(f"- ...and {findings_count - 8} more.")
        # Summary severity is the source of truth for the whole findings list.
        displayed_count = sum(displayed_sev.values())

    lines: list[str] = [
        "# ShellForgeAI Diagnosis Summary",
        "",
        f"- Session: {session_id}",
        f"- Target: {target}",
        f"- Target type: {target_type}",
        f"- Created: {created_at}",
        f"- Evidence count: {evidence_count}",
        f"- Findings count: {displayed_count}",
        (
            "- Findings severity: "
            f"{displayed_sev.get('critical', 0)} critical, "
            f"{displayed_sev.get('warning', 0)} warning, "
            f"{displayed_sev.get('info', 0) + displayed_sev.get('limitation', 0)} info/limitations"
        ),
        "",
        "## Assessment",
        assessment,
        "",
        "## Key evidence",
    ]
    if runtime_context:
        inside_container = bool(runtime_context.get("inside_container"))
        visibility = str(runtime_context.get("visibility", "runtime_scoped")).replace("_", "-")
        view = str(runtime_context.get("view", "runtime-local diagnosis")).replace("_", " ")
        lines.extend(
            [
                "- Runtime context:",
                f"  - inside_container: {'true' if inside_container else 'false'}",
                f"  - visibility: {visibility}",
                f"  - view: {view}",
            ]
        )
    if key_lines:
        lines.extend(key_lines)
    else:
        lines.append("- No structured highlights from this run.")
    lines.extend(["", "## Findings"])
    lines.extend(findings_block)
    lines.extend(["", "## Artifacts"])
    if artifacts:
        lines.extend(f"- {a}" for a in artifacts)
    else:
        lines.append("- (no artifact files written)")
    lines.extend(
        [
            "",
            "## Safety note",
            "No changes were applied; this diagnosis used read-only evidence.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")
