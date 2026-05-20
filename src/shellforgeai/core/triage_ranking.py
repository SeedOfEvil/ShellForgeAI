"""PR81 — Read-only Docker triage ranking ("scene awareness").

Given a Docker scene snapshot (container inventory + log themes + bounded
metrics), deterministically rank multiple suspects with severity, confidence,
evidence, and a safe next read-only command per suspect. No LLM, no mutation,
no natural-language execution.

The scoring runs on a plain dict scene payload so tests can drive it from
fixtures without a live Docker daemon. The collector ``collect_scene`` adapts
the existing read-only ``docker.containers`` / ``docker.problem_summary``
collectors into that shape.

Forbidden in this module:
- container start/stop/restart/remove
- docker compose mutation
- cleanup execute / mission execute / apply
- proposal/mission creation
- chmod/chown/host writes
- arbitrary command execution / shell=true
- natural-language mutation routing
"""

from __future__ import annotations

import json
from typing import Any

SCHEMA_VERSION = "1"
MODE = "docker_triage_ranking"

# --- scoring classes -------------------------------------------------------

CLASS_CRASHLOOP = "crashloop"
CLASS_RESTART_STORM = "restart_storm"
CLASS_NOISY_ERRORS = "noisy_errors"
CLASS_BAD_HTTP = "bad_http"
CLASS_DISK_PRESSURE = "disk_pressure"
CLASS_PERMISSION_DENIED = "permission_denied"
CLASS_HIGH_CPU_WATCH = "high_cpu_watch"

SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"
SEV_WATCH = "watch"

_SEV_RANK = {
    SEV_CRITICAL: 4,
    SEV_HIGH: 3,
    SEV_MEDIUM: 2,
    SEV_LOW: 1,
    SEV_WATCH: 0,
}

# Log theme keys produced by tools/containers._classify_log
_BAD_HTTP_THEMES = (
    "connection_refused",
    "upstream_unreachable",
    "timeout",
)
_DNS_THEMES = ("dns_failure",)
_NOISY_THEMES = ("error_line", "traceback", "config_error")
_DISK_THEMES = ("read_only_fs",)
_PERM_THEMES = ("permission_denied",)


def _safe_next_logs(name: str) -> str:
    return f"shellforgeai diagnose logs --target {name} --json"


def _safe_next_docker(name: str) -> str:
    return f"shellforgeai diagnose docker --container {name} --json"


def _safe_next_disk() -> str:
    return "shellforgeai diagnose disk --json"


def _max_sev(a: str, b: str) -> str:
    return a if _SEV_RANK[a] >= _SEV_RANK[b] else b


# --- per-class scorers -----------------------------------------------------


def _score_crashloop(c: dict[str, Any]) -> dict[str, Any] | None:
    state = (c.get("state") or "").lower()
    restart_count = int(c.get("restart_count") or 0)
    exit_code = c.get("exit_code")
    oom = bool(c.get("oom_killed"))
    log_themes = c.get("log_themes") or {}
    triggered = False
    classes: list[str] = []
    evidence: list[dict[str, Any]] = []
    why: list[str] = []
    severity = SEV_LOW
    score = 0

    if state in {"restarting", "dead"}:
        triggered = True
        classes.append(CLASS_CRASHLOOP)
        evidence.append({"type": "state", "value": state, "weight": 35})
        why.append(f"container state is {state}")
        severity = _max_sev(severity, SEV_CRITICAL)
        score += 60
    if restart_count >= 3:
        triggered = True
        if CLASS_RESTART_STORM not in classes:
            classes.append(CLASS_RESTART_STORM)
        evidence.append({"type": "restart_count", "value": restart_count, "weight": 30})
        why.append("restart storm detected")
        severity = _max_sev(severity, SEV_CRITICAL if restart_count >= 5 else SEV_HIGH)
        score += 30 + min(restart_count, 12)
    if state == "exited" and exit_code is not None and exit_code != 0:
        triggered = True
        if CLASS_CRASHLOOP not in classes:
            classes.append(CLASS_CRASHLOOP)
        evidence.append({"type": "exit_code", "value": exit_code, "weight": 25})
        why.append(f"last exit code is {exit_code} (nonzero)")
        severity = _max_sev(severity, SEV_HIGH)
        score += 25
    if oom:
        triggered = True
        if CLASS_CRASHLOOP not in classes:
            classes.append(CLASS_CRASHLOOP)
        evidence.append({"type": "oom_killed", "value": True, "weight": 25})
        why.append("OOM killed")
        severity = _max_sev(severity, SEV_HIGH)
        score += 25
    # Repeated startup/failure pattern in logs reinforces crashloop signal.
    if triggered and (log_themes.get("traceback", 0) or log_themes.get("error_line", 0) >= 2):
        evidence.append(
            {
                "type": "repeated_startup_failure",
                "value": True,
                "weight": 10,
            }
        )
        score += 10

    if not triggered:
        return None
    return {
        "classes": classes,
        "severity": severity,
        "score": min(score, 100),
        "evidence": evidence,
        "why": why,
    }


def _score_bad_http(c: dict[str, Any]) -> dict[str, Any] | None:
    log_themes = c.get("log_themes") or {}
    hits = {k: int(log_themes.get(k, 0) or 0) for k in _BAD_HTTP_THEMES + _DNS_THEMES}
    total = sum(hits.values())
    if total <= 0:
        return None
    evidence: list[dict[str, Any]] = []
    why: list[str] = []
    for theme, count in hits.items():
        if count > 0:
            evidence.append({"type": f"log_theme:{theme}", "value": count, "weight": 15})
            why.append(f"log evidence: {theme} x{count}")
    severity = SEV_HIGH if total >= 3 else SEV_MEDIUM
    score = 55 + min(total * 5, 25)
    why.insert(0, "HTTP/upstream failure evidence")
    return {
        "classes": [CLASS_BAD_HTTP],
        "severity": severity,
        "score": score,
        "evidence": evidence,
        "why": why,
    }


def _score_noisy_errors(c: dict[str, Any]) -> dict[str, Any] | None:
    state = (c.get("state") or "").lower()
    if state != "running":
        return None
    log_themes = c.get("log_themes") or {}
    err = int(log_themes.get("error_line", 0) or 0)
    tb = int(log_themes.get("traceback", 0) or 0)
    cfg = int(log_themes.get("config_error", 0) or 0)
    total = err + tb + cfg
    if total < 2:
        return None
    evidence = [
        {"type": "log_theme:error_line", "value": err, "weight": 10},
        {"type": "log_theme:traceback", "value": tb, "weight": 10},
    ]
    if cfg:
        evidence.append({"type": "log_theme:config_error", "value": cfg, "weight": 5})
    severity = SEV_HIGH if total >= 6 else SEV_MEDIUM
    score = 40 + min(total * 3, 25)
    why = [
        "repeated error lines while container is still running",
        f"error density: error_line={err} traceback={tb} config_error={cfg}",
    ]
    return {
        "classes": [CLASS_NOISY_ERRORS],
        "severity": severity,
        "score": score,
        "evidence": evidence,
        "why": why,
    }


def _score_disk_pressure(c: dict[str, Any]) -> dict[str, Any] | None:
    log_themes = c.get("log_themes") or {}
    ro = int(log_themes.get("read_only_fs", 0) or 0)
    no_space = bool(c.get("log_no_space_left"))
    disk_free_pct = c.get("disk_free_pct")
    triggered = ro > 0 or no_space
    evidence: list[dict[str, Any]] = []
    why: list[str] = []
    score = 0
    severity = SEV_LOW
    if ro:
        evidence.append({"type": "log_theme:read_only_fs", "value": ro, "weight": 20})
        why.append("read-only filesystem evidence in logs")
        severity = _max_sev(severity, SEV_HIGH)
        score += 50
    if no_space:
        evidence.append({"type": "log_no_space_left", "value": True, "weight": 25})
        why.append("logs mention 'no space left'")
        severity = _max_sev(severity, SEV_HIGH)
        score += 55
    if isinstance(disk_free_pct, (int, float)) and disk_free_pct <= 10:
        triggered = True
        evidence.append({"type": "disk_free_pct", "value": disk_free_pct, "weight": 20})
        why.append(f"low free disk: {disk_free_pct}%")
        severity = _max_sev(severity, SEV_HIGH if disk_free_pct <= 5 else SEV_MEDIUM)
        score += 45
    if not triggered:
        return None
    return {
        "classes": [CLASS_DISK_PRESSURE],
        "severity": severity,
        "score": min(score, 95),
        "evidence": evidence,
        "why": why,
    }


def _score_permission_denied(c: dict[str, Any]) -> dict[str, Any] | None:
    log_themes = c.get("log_themes") or {}
    perm = int(log_themes.get("permission_denied", 0) or 0)
    ro = int(log_themes.get("read_only_fs", 0) or 0)
    if perm <= 0 and ro <= 0:
        return None
    evidence: list[dict[str, Any]] = []
    why: list[str] = []
    score = 0
    severity = SEV_MEDIUM
    if perm:
        evidence.append({"type": "log_theme:permission_denied", "value": perm, "weight": 20})
        why.append(f"permission denied evidence x{perm}")
        score += 50 + min(perm * 3, 15)
        if perm >= 3:
            severity = SEV_HIGH
    if ro and not perm:
        # Read-only FS without permission_denied still implies access failure.
        evidence.append({"type": "log_theme:read_only_fs", "value": ro, "weight": 15})
        why.append("read-only filesystem evidence")
        score += 40
    return {
        "classes": [CLASS_PERMISSION_DENIED],
        "severity": severity,
        "score": min(score, 90),
        "evidence": evidence,
        "why": why,
    }


def _score_high_cpu_watch(c: dict[str, Any]) -> dict[str, Any] | None:
    state = (c.get("state") or "").lower()
    cpu = c.get("cpu_percent")
    if state != "running" or not isinstance(cpu, (int, float)):
        return None
    if cpu < 80:
        return None
    log_themes = c.get("log_themes") or {}
    error_total = (
        int(log_themes.get("error_line", 0) or 0)
        + int(log_themes.get("traceback", 0) or 0)
        + sum(int(log_themes.get(k, 0) or 0) for k in _BAD_HTTP_THEMES)
    )
    if error_total >= 2:
        # Errors present — do not classify as quiet watch case.
        return None
    health = (c.get("health") or "").lower()
    if health in {"unhealthy", "starting"}:
        return None
    return {
        "classes": [CLASS_HIGH_CPU_WATCH],
        "severity": SEV_WATCH,
        "score": 20 + min(int(cpu) - 80, 20),
        "evidence": [{"type": "cpu_percent", "value": cpu, "weight": 15}],
        "why": [
            f"high CPU ({cpu}%) but currently running/healthy",
            "monitor and inspect before action",
        ],
    }


_SCORERS = (
    _score_crashloop,
    _score_bad_http,
    _score_noisy_errors,
    _score_disk_pressure,
    _score_permission_denied,
    _score_high_cpu_watch,
)


# --- ranking ---------------------------------------------------------------


def _confidence_from_score(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _safe_next_for(name: str, classes: list[str]) -> list[str]:
    if CLASS_DISK_PRESSURE in classes:
        return [_safe_next_disk(), _safe_next_docker(name)]
    if CLASS_CRASHLOOP in classes or CLASS_RESTART_STORM in classes:
        return [_safe_next_docker(name)]
    return [_safe_next_logs(name)]


def _rank_one(container: dict[str, Any]) -> dict[str, Any] | None:
    name = container.get("name") or ""
    if not name:
        return None
    classes: list[str] = []
    evidence: list[dict[str, Any]] = []
    why: list[str] = []
    severity = SEV_LOW
    score = 0
    watch_only = True
    for scorer in _SCORERS:
        out = scorer(container)
        if not out:
            continue
        for cls in out["classes"]:
            if cls not in classes:
                classes.append(cls)
        evidence.extend(out["evidence"])
        why.extend(out["why"])
        severity = _max_sev(severity, out["severity"])
        score = max(score, int(out["score"]))
        if out["severity"] != SEV_WATCH:
            watch_only = False
    if not classes:
        return None
    return {
        "name": name,
        "kind": "container",
        "severity": severity,
        "confidence": _confidence_from_score(score),
        "score": score,
        "classes": classes,
        "evidence": evidence,
        "why": why,
        "safe_next_commands": _safe_next_for(name, classes),
        "_watch_only": watch_only,
    }


def rank_scene(scene: dict[str, Any]) -> dict[str, Any]:
    """Rank a Docker scene payload.

    Input shape::
        {
          "containers": [
            {
              "name": "...",
              "state": "running|exited|restarting|dead|...",
              "exit_code": int|None,
              "restart_count": int,
              "oom_killed": bool,
              "health": "healthy|unhealthy|...",
              "log_themes": {"error_line": 3, ...},
              "cpu_percent": float|None,
              "disk_free_pct": float|None,
              "log_no_space_left": bool,
            },
            ...
          ]
        }

    Returns the full strict JSON-shaped report dict.
    """
    containers = scene.get("containers") or []
    suspects: list[dict[str, Any]] = []
    watch: list[dict[str, Any]] = []
    warnings: list[str] = []
    for c in containers:
        ranked = _rank_one(c)
        if ranked is None:
            continue
        if ranked.pop("_watch_only"):
            watch.append(
                {
                    "name": ranked["name"],
                    "severity": SEV_WATCH,
                    "confidence": ranked["confidence"],
                    "classes": ranked["classes"],
                    "why": ranked["why"],
                    "safe_next_commands": ranked["safe_next_commands"],
                }
            )
        else:
            suspects.append(ranked)
    # Stable deterministic ordering: severity desc, score desc, name asc.
    suspects.sort(key=lambda s: (-_SEV_RANK[s["severity"]], -int(s["score"]), s["name"]))
    for i, s in enumerate(suspects, start=1):
        s["rank"] = i
        # Move rank to front for human-friendliness.
        s_keys = ["rank"] + [k for k in s if k != "rank"]
        s.update({k: s[k] for k in s_keys})
    watch.sort(key=lambda w: w["name"])

    counts = {SEV_CRITICAL: 0, SEV_HIGH: 0, SEV_MEDIUM: 0, SEV_LOW: 0, SEV_WATCH: 0}
    for s in suspects:
        counts[s["severity"]] += 1
    counts[SEV_WATCH] += len(watch)

    if not suspects and not watch:
        warnings.append("no suspects ranked from provided scene")

    next_safe_commands = [
        "shellforgeai diagnose docker --save-plan --with-runbook",
        "shellforgeai self-test commands --profile quick",
    ]

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "ok" if suspects or watch else "warn",
        "mode": MODE,
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "containers_seen": len(containers),
            "suspects_ranked": len(suspects),
            "critical": counts[SEV_CRITICAL],
            "high": counts[SEV_HIGH],
            "medium": counts[SEV_MEDIUM],
            "low": counts[SEV_LOW],
            "watch": counts[SEV_WATCH],
        },
        "suspects": suspects,
        "watch": watch,
        "safety": {
            "read_only": True,
            "mutation_performed": False,
            "cleanup_executed": False,
            "proposal_created": False,
            "mission_created": False,
            "apply_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "natural_language_execution": False,
            "shell_true": False,
        },
        "warnings": warnings,
        "next_safe_commands": next_safe_commands,
    }
    return payload


# --- scene collection from read-only Docker evidence -----------------------


def _scene_from_problem_summary(
    inventory_payload: dict[str, Any], summary_payload: dict[str, Any]
) -> dict[str, Any]:
    """Adapt existing docker.problem_summary output into a scoring scene.

    All inputs come from existing read-only collectors. No subprocess work
    happens here; this is a pure transformation for testability.
    """
    by_name: dict[str, dict[str, Any]] = {}
    for row in inventory_payload.get("containers") or []:
        name = row.get("name") or ""
        if not name:
            continue
        by_name[name] = {
            "name": name,
            "state": (row.get("state") or "").lower(),
            "image": row.get("image"),
            "status": row.get("status"),
        }
    for bucket in ("failing", "noisy"):
        for entry in summary_payload.get(bucket) or []:
            name = entry.get("name") or ""
            if not name:
                continue
            row = by_name.setdefault(
                name,
                {"name": name, "state": (entry.get("state") or "").lower()},
            )
            row["exit_code"] = entry.get("exit_code")
            row["restart_count"] = entry.get("restart_count") or 0
            row["oom_killed"] = bool(entry.get("oom_killed"))
            row["health"] = entry.get("health")
            row["log_themes"] = entry.get("log_themes") or {}
            sample = entry.get("log_sample") or []
            if sample and any("no space left" in (s or "").lower() for s in sample):
                row["log_no_space_left"] = True
    return {"containers": list(by_name.values())}


def collect_scene(context: Any = None) -> dict[str, Any]:
    """Build a triage scene from live read-only Docker collectors.

    Returns ``{"containers": []}`` (empty) when the daemon is unavailable;
    that becomes a "no suspects" report rather than an error.
    """
    from shellforgeai.tools import containers as containers_tool

    inv = containers_tool.containers(all_containers=True)
    if not inv.ok or not (inv.stdout or "").strip():
        return {"containers": []}
    try:
        inv_payload = json.loads(inv.stdout)
    except (ValueError, json.JSONDecodeError):
        return {"containers": []}
    summary = containers_tool.problem_summary()
    summary_payload: dict[str, Any] = {}
    if summary.ok and (summary.stdout or "").strip():
        try:
            summary_payload = json.loads(summary.stdout)
        except (ValueError, json.JSONDecodeError):
            summary_payload = {}
    return _scene_from_problem_summary(inv_payload, summary_payload)


# --- human rendering -------------------------------------------------------


def render_human(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("Docker triage suspects")
    lines.append("")
    lines.append("Safety:")
    lines.append("- read_only: true")
    lines.append("- mutation_performed: false")
    lines.append("- no restart/stop/delete/prune was executed")
    lines.append("")
    summary = payload.get("summary", {})
    lines.append(
        "Scene: "
        f"containers_seen={summary.get('containers_seen', 0)} "
        f"suspects={summary.get('suspects_ranked', 0)} "
        f"critical={summary.get('critical', 0)} "
        f"high={summary.get('high', 0)} "
        f"medium={summary.get('medium', 0)} "
        f"watch={summary.get('watch', 0)}"
    )
    lines.append("")
    suspects = payload.get("suspects") or []
    if not suspects:
        lines.append("No ranked suspects from current scene.")
    for s in suspects:
        lines.append(f"{s['rank']}. {s['name']}")
        lines.append(f"   Severity: {s['severity']}")
        lines.append(f"   Confidence: {s['confidence']}")
        lines.append(f"   Classes: {', '.join(s['classes'])}")
        lines.append("   Why ranked here:")
        for w in s.get("why") or []:
            lines.append(f"   - {w}")
        lines.append("   Safe next command:")
        for cmd in s.get("safe_next_commands") or []:
            lines.append(f"   - {cmd}")
        lines.append("")
    watch = payload.get("watch") or []
    if watch:
        lines.append("Watch:")
        for w in watch:
            why = "; ".join(w.get("why") or [])
            lines.append(f"- {w['name']}: {why}")
        lines.append("")
    lines.append("Next safe steps:")
    for cmd in payload.get("next_safe_commands") or []:
        lines.append(f"- {cmd}")
    return "\n".join(lines).rstrip() + "\n"
