"""PR81 — Read-only Docker triage ranking ("scene awareness").

Given a Docker scene snapshot (container inventory + per-container logs +
bounded metrics), deterministically rank multiple suspects with severity,
confidence, evidence, and a safe next read-only command per suspect. No LLM,
no mutation, no natural-language execution.

PR81-followup: triage owns its own per-container log classifier (rather than
relying on ``docker.problem_summary``'s narrower line-anchored patterns), so
running-but-noisy containers, disk-pressure scenarios, and ``ERROR ...`` lines
prefixed by timestamps are detected per-container. ``collect_scene`` independently
inspects + tails logs + classifies for each container in the inventory and
optionally pulls ``docker stats`` for the high-CPU watch lane. Evidence is
scoped per container; cross-attribution between containers does not occur.

The scoring runs on a plain scene dict so tests drive it from fixtures
without a live Docker daemon.

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

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
MODE = "docker_triage_ranking"
SNAPSHOT_MODE = "docker_triage_snapshot"
SNAPSHOT_EXPORT_MODE = "docker_triage_snapshot_export"

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

# --- per-container log classifier -----------------------------------------
#
# These patterns are intentionally line-anchor-free (no ``^``) so they fire on
# timestamp-prefixed lines like ``2024-05-20 14:50:01 ERROR payment-worker
# timeout``. Each pattern produces a semantic theme key consumed directly by
# the scorers below. Classification runs per container; the resulting theme
# dict is local to that container and is never copied to peers.

_TRIAGE_LOG_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # noisy errors: ERROR/FATAL/Exception/Traceback/queue-depth markers
    (
        "noisy_error",
        re.compile(
            r"(?i)\b(?:ERROR|FATAL|Exception|Traceback|queue depth high|"
            r"repeated startup failure)\b"
        ),
    ),
    ("warn_signal", re.compile(r"(?i)\bWARN(?:ING)?\b")),
    # disk pressure: lab + production phrasings
    (
        "disk_pressure",
        re.compile(
            r"(?i)("
            r"simulated disk pressure|write failed|no space left|"
            r"disk pressure|filler\s*=|ENOSPC|low free|"
            r"low\s+(?:disk|free)\s+space|out of disk"
            r")"
        ),
    ),
    # bad HTTP / upstream / refused endpoint
    (
        "bad_http",
        re.compile(
            r"(?i)("
            r"\b50[23]\b|bad gateway|connection refused|connect\(\)\s+failed|"
            r"upstream (?:refused|unreachable|host|connect(?:ion)?|down|"
            r"timeout|prematurely closed|server temporarily disabled)|"
            r"econnrefused|127\.0\.0\.1:9999"
            r")"
        ),
    ),
    # DNS resolution failure
    (
        "dns_failure",
        re.compile(
            r"(?i)(temporary failure in name resolution|name or service not known|"
            r"could not resolve host|no such host|getaddrinfo|nxdomain|servfail)"
        ),
    ),
    # generic timeout (separate from bad_http on purpose)
    (
        "timeout",
        re.compile(
            r"(?i)(connection timed out|i/o timeout|read timed out|"
            r"timeout connecting|upstream timeout|deadline exceeded|\btimed out\b)"
        ),
    ),
    # permission / access failures
    (
        "permission_denied",
        re.compile(
            r"(?i)("
            r"permission denied|\bEACCES\b|access denied|"
            r"operation not permitted|read[- ]only file ?system"
            r")"
        ),
    ),
    # explicit crashloop boot marker
    (
        "crashloop_boot",
        re.compile(
            r"(?i)(CRITICAL boot failure|panic:\s|fatal error:|abort:|"
            r"unrecoverable startup error)"
        ),
    ),
)

# Legacy theme keys (from ``tools/containers._classify_log``) that scorers
# also accept so existing collectors and fixtures keep working.
_LEGACY_THEME_ALIASES: dict[str, str] = {
    "error_line": "noisy_error",
    "traceback": "noisy_error",
    "config_error": "noisy_error",
    "warn_line": "warn_signal",
    "connection_refused": "bad_http",
    "upstream_unreachable": "bad_http",
    "read_only_fs": "permission_denied",
}


def classify_logs(text: str) -> dict[str, int]:
    """Per-container log classifier producing semantic theme counts.

    Returns ``{}`` for empty/None input. Counts are clamped at 0 minimum.
    Each pattern is scoped to the text passed in — never shared across
    containers.
    """
    out: dict[str, int] = {}
    if not text:
        return out
    for name, pat in _TRIAGE_LOG_PATTERNS:
        n = len(pat.findall(text))
        if n:
            out[name] = n
    return out


def _themes(c: dict[str, Any]) -> dict[str, int]:
    """Return semantic theme counts for a container, merging legacy keys.

    If ``log_text`` is present we classify it directly (most accurate).
    Otherwise we read ``log_themes`` and translate legacy aliases.
    """
    text = c.get("log_text")
    themes = classify_logs(text) if isinstance(text, str) and text else {}
    raw = c.get("log_themes") or {}
    for k, v in raw.items():
        try:
            n = int(v or 0)
        except (TypeError, ValueError):
            continue
        if n <= 0:
            continue
        key = _LEGACY_THEME_ALIASES.get(k, k)
        themes[key] = themes.get(key, 0) + n
    return themes


# --- helpers ---------------------------------------------------------------


def _safe_next_logs(name: str) -> str:
    return f"shellforgeai diagnose logs --target {name} --json"


def _safe_next_docker(name: str) -> str:
    return f"shellforgeai diagnose docker --container {name} --json"


def _safe_next_disk() -> str:
    return "shellforgeai diagnose disk --json"


def _max_sev(a: str, b: str) -> str:
    return a if _SEV_RANK[a] >= _SEV_RANK[b] else b


# --- per-class scorers -----------------------------------------------------
#
# Every scorer receives a single container snapshot. Each scorer only reads
# fields scoped to that container; no scorer reaches into a shared scene or
# peer container. Theme attribution is bounded by thresholds so a single
# stray nginx errno line (``connect() failed (13: Permission denied)``) does
# not pin the ``permission_denied`` class onto a clear bad-http suspect.


def _score_crashloop(c: dict[str, Any], themes: dict[str, int]) -> dict[str, Any] | None:
    state = (c.get("state") or "").lower()
    restart_count = int(c.get("restart_count") or 0)
    exit_code = c.get("exit_code")
    oom = bool(c.get("oom_killed"))
    boot = int(themes.get("crashloop_boot", 0) or 0)
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
        why.append(f"restart storm detected (restart_count={restart_count})")
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
    if boot:
        triggered = True
        if CLASS_CRASHLOOP not in classes:
            classes.append(CLASS_CRASHLOOP)
        evidence.append({"type": "log_theme:crashloop_boot", "value": boot, "weight": 15})
        why.append(f"explicit crashloop boot marker x{boot}")
        severity = _max_sev(severity, SEV_HIGH)
        score += 15

    if not triggered:
        return None
    return {
        "classes": classes,
        "severity": severity,
        "score": min(score, 100),
        "evidence": evidence,
        "why": why,
    }


def _score_bad_http(c: dict[str, Any], themes: dict[str, int]) -> dict[str, Any] | None:
    http = int(themes.get("bad_http", 0) or 0)
    dns = int(themes.get("dns_failure", 0) or 0)
    # timeout alone does not classify as bad_http; only count it when accompanied
    # by direct upstream/refused evidence to keep noisy-errors and bad_http
    # distinct.
    timeout = int(themes.get("timeout", 0) or 0) if http >= 1 else 0
    total = http + dns + timeout
    if http <= 0 and dns <= 0:
        return None
    evidence: list[dict[str, Any]] = []
    why: list[str] = ["HTTP/upstream failure evidence"]
    if http:
        evidence.append({"type": "log_theme:bad_http", "value": http, "weight": 20})
        why.append(f"log evidence: bad_http x{http}")
    if dns:
        evidence.append({"type": "log_theme:dns_failure", "value": dns, "weight": 15})
        why.append(f"log evidence: dns_failure x{dns}")
    if timeout:
        evidence.append({"type": "log_theme:timeout", "value": timeout, "weight": 10})
        why.append(f"log evidence: timeout x{timeout}")
    severity = SEV_HIGH if total >= 3 else SEV_MEDIUM
    score = 55 + min(total * 5, 25)
    return {
        "classes": [CLASS_BAD_HTTP],
        "severity": severity,
        "score": score,
        "evidence": evidence,
        "why": why,
    }


def _score_noisy_errors(c: dict[str, Any], themes: dict[str, int]) -> dict[str, Any] | None:
    state = (c.get("state") or "").lower()
    if state not in {"running", ""}:
        # Crashloop scorer already captures exited/restarting/dead cases.
        return None
    err = int(themes.get("noisy_error", 0) or 0)
    warn = int(themes.get("warn_signal", 0) or 0)
    if err < 2 and warn < 2:
        return None
    # Anti-attribution guard: if those ERROR/WARN lines are already explained
    # by a specific category (disk pressure, bad HTTP, permission denied,
    # crashloop boot), do NOT also pin "noisy_errors" on this container — the
    # signal is already accounted for elsewhere with its own evidence.
    specific = (
        int(themes.get("bad_http", 0) or 0)
        + int(themes.get("disk_pressure", 0) or 0)
        + int(themes.get("permission_denied", 0) or 0)
        + int(themes.get("crashloop_boot", 0) or 0)
    )
    if specific >= max(err, 1):
        return None
    total = err + warn
    evidence = [
        {"type": "log_theme:noisy_error", "value": err, "weight": 12},
    ]
    if warn:
        evidence.append({"type": "log_theme:warn_signal", "value": warn, "weight": 6})
    severity = SEV_HIGH if total >= 8 else SEV_MEDIUM
    score = 45 + min(total * 3, 30)
    why = [
        "repeated error/warn lines while container is running",
        f"error density: noisy_error={err} warn_signal={warn}",
    ]
    return {
        "classes": [CLASS_NOISY_ERRORS],
        "severity": severity,
        "score": score,
        "evidence": evidence,
        "why": why,
    }


def _score_disk_pressure(c: dict[str, Any], themes: dict[str, int]) -> dict[str, Any] | None:
    disk = int(themes.get("disk_pressure", 0) or 0)
    no_space = bool(c.get("log_no_space_left"))
    disk_free_pct = c.get("disk_free_pct")
    if (
        disk <= 0
        and not no_space
        and not (isinstance(disk_free_pct, (int, float)) and disk_free_pct <= 10)
    ):
        return None
    evidence: list[dict[str, Any]] = []
    why: list[str] = []
    score = 0
    severity = SEV_LOW
    if disk:
        evidence.append({"type": "log_theme:disk_pressure", "value": disk, "weight": 25})
        why.append(f"disk-pressure log evidence x{disk}")
        severity = _max_sev(severity, SEV_HIGH if disk >= 3 else SEV_MEDIUM)
        score += 55 + min(disk * 3, 20)
    if no_space:
        evidence.append({"type": "log_no_space_left", "value": True, "weight": 25})
        why.append("logs mention 'no space left'")
        severity = _max_sev(severity, SEV_HIGH)
        score += 50
    if isinstance(disk_free_pct, (int, float)) and disk_free_pct <= 10:
        evidence.append({"type": "disk_free_pct", "value": disk_free_pct, "weight": 20})
        why.append(f"low free disk: {disk_free_pct}%")
        severity = _max_sev(severity, SEV_HIGH if disk_free_pct <= 5 else SEV_MEDIUM)
        score += 45
    return {
        "classes": [CLASS_DISK_PRESSURE],
        "severity": severity,
        "score": min(score, 95),
        "evidence": evidence,
        "why": why,
    }


def _score_permission_denied(c: dict[str, Any], themes: dict[str, int]) -> dict[str, Any] | None:
    perm = int(themes.get("permission_denied", 0) or 0)
    if perm <= 0:
        return None
    # Anti-attribution guard: nginx and other HTTP servers occasionally log
    # ``connect() failed (13: Permission denied)`` as part of an upstream
    # failure. When the dominant signal is bad_http and the permission_denied
    # count is weak (1), suppress to avoid pinning the wrong class on a clear
    # bad-http suspect.
    http = int(themes.get("bad_http", 0) or 0)
    if http >= 3 and perm < 2:
        return None
    # Require at least 2 hits to call this its own class (single mentions
    # are common collateral in mixed log streams).
    if perm < 2:
        return None
    evidence: list[dict[str, Any]] = [
        {"type": "log_theme:permission_denied", "value": perm, "weight": 20},
    ]
    why = [f"permission denied evidence x{perm}"]
    score = 50 + min(perm * 3, 20)
    severity = SEV_HIGH if perm >= 4 else SEV_MEDIUM
    return {
        "classes": [CLASS_PERMISSION_DENIED],
        "severity": severity,
        "score": min(score, 90),
        "evidence": evidence,
        "why": why,
    }


def _score_high_cpu_watch(c: dict[str, Any], themes: dict[str, int]) -> dict[str, Any] | None:
    state = (c.get("state") or "").lower()
    cpu = c.get("cpu_percent")
    if state != "running" or not isinstance(cpu, (int, float)):
        return None
    if cpu < 80:
        return None
    # If the container has any meaningful error/disk/permission signal it is
    # already covered by a higher-severity lane — keep watch a quiet bucket.
    suppress = (
        int(themes.get("noisy_error", 0) or 0) >= 2
        or int(themes.get("bad_http", 0) or 0) >= 2
        or int(themes.get("disk_pressure", 0) or 0) >= 1
        or int(themes.get("permission_denied", 0) or 0) >= 2
    )
    if suppress:
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
    themes = _themes(container)
    classes: list[str] = []
    evidence: list[dict[str, Any]] = []
    why: list[str] = []
    severity = SEV_LOW
    score = 0
    watch_only = True
    for scorer in _SCORERS:
        out = scorer(container, themes)
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

    Each container is scored independently. Themes/evidence/classes/why are
    scoped to that container only and are never copied to peer containers.
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
                    "evidence": ranked["evidence"],
                    "why": ranked["why"],
                    "safe_next_commands": ranked["safe_next_commands"],
                }
            )
        else:
            suspects.append(ranked)
    suspects.sort(key=lambda s: (-_SEV_RANK[s["severity"]], -int(s["score"]), s["name"]))
    for i, s in enumerate(suspects, start=1):
        s["rank"] = i
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


def _collect_cpu_stats() -> dict[str, float]:
    """Read bounded ``docker stats --no-stream`` for the watch lane.

    Returns ``{name: cpu_percent}``. Empty when stats are unavailable. Never
    runs in shell mode; failures are silently swallowed because the watch
    lane is a "nice to have" — the main ranking does not depend on it.
    """
    from shellforgeai.tools import host
    from shellforgeai.util.subprocess import run_command

    if not (host.command_exists("docker").ok or False):
        return {}
    cmd = [
        "docker",
        "stats",
        "--no-stream",
        "--format",
        "{{.Name}}\t{{.CPUPerc}}",
    ]
    try:
        r = run_command(cmd, timeout=8)
    except Exception:
        return {}
    if r.exit_code != 0 or not (r.stdout or "").strip():
        return {}
    out: dict[str, float] = {}
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name = parts[0].strip()
        cpu_raw = parts[1].strip().rstrip("%")
        if not name:
            continue
        try:
            out[name] = float(cpu_raw)
        except ValueError:
            continue
    return out


def collect_scene(context: Any = None) -> dict[str, Any]:
    """Build a triage scene from live read-only Docker collectors.

    Per-container, this function:
    - reads the inventory via ``docker.containers``,
    - runs ``docker.inspect`` for state/restart/exit/health,
    - tails ``docker.container_logs`` and classifies them with the
      triage-owned per-container classifier above,
    - optionally pulls ``docker stats`` for the watch lane.

    Each container's evidence is scoped to that container — log text is never
    shared across peers. Returns ``{"containers": []}`` if the Docker CLI is
    unavailable; that becomes a "no suspects" report rather than an error.
    """
    from shellforgeai.tools import containers as containers_tool

    inv = containers_tool.containers(all_containers=True)
    if not inv.ok or not (inv.stdout or "").strip():
        return {"containers": []}
    try:
        inv_payload = json.loads(inv.stdout)
    except (ValueError, json.JSONDecodeError):
        return {"containers": []}

    cpu_by_name = _collect_cpu_stats()

    out_rows: list[dict[str, Any]] = []
    for row in inv_payload.get("containers") or []:
        name = row.get("name") or ""
        if not name:
            continue
        state = (row.get("state") or "").lower()
        info: dict[str, Any] = {}
        ins = containers_tool.inspect(name)
        if ins.ok and (ins.stdout or "").strip():
            try:
                info = json.loads(ins.stdout)
            except (ValueError, json.JSONDecodeError):
                info = {}
        # Per-container log read — scoped to this container only.
        log_text = ""
        if state in {"running", "restarting", "exited", "dead"}:
            lr = containers_tool.container_logs(name, tail=200)
            if lr.ok:
                log_text = lr.stdout or ""
        log_no_space = bool(log_text and "no space left" in log_text.lower())
        out_rows.append(
            {
                "name": name,
                "state": state,
                "image": row.get("image"),
                "status": row.get("status"),
                "exit_code": info.get("exit_code"),
                "restart_count": info.get("restart_count") or 0,
                "oom_killed": bool(info.get("oom_killed")),
                "health": info.get("health"),
                "log_text": log_text,
                "log_no_space_left": log_no_space,
                "cpu_percent": cpu_by_name.get(name),
                "labels": row.get("labels") if isinstance(row.get("labels"), dict) else {},
            }
        )
    return {"containers": out_rows}


# --- human rendering -------------------------------------------------------


def build_detail_payload(
    scene: dict[str, Any],
    ranked: dict[str, Any],
    *,
    suspect_name: str | None = None,
    rank: int | None = None,
) -> dict[str, Any]:
    target_input = (
        suspect_name if suspect_name is not None else (f"rank:{rank}" if rank is not None else "")
    )
    suspects = ranked.get("suspects") or []
    base = {
        "schema_version": SCHEMA_VERSION,
        "mode": "docker_triage_detail",
        "target": {"input": target_input, "name": None, "rank": None, "rank_total": len(suspects)},
        "safety": ranked.get("safety", {}),
        "warnings": [],
    }
    if rank is not None and rank <= 0:
        return {**base, "status": "error", "warnings": ["rank must be >= 1"]}

    selected = None
    if suspect_name is not None:
        for s in suspects:
            if s.get("name") == suspect_name:
                selected = s
                break
        if selected is None:
            return {
                **base,
                "status": "not_found",
                "target": {**base["target"], "name": suspect_name},
                "available_suspects": [s.get("name") for s in suspects],
                "warnings": ["suspect not found"],
            }
    elif rank is not None:
        if rank > len(suspects):
            return {
                **base,
                "status": "error",
                "warnings": [f"rank out of range: {rank} (suspects={len(suspects)})"],
            }
        selected = suspects[rank - 1]
    else:
        return {**base, "status": "error", "warnings": ["suspect name or --rank is required"]}

    rank_val = int(selected.get("rank", 0))
    higher = [s.get("name") for s in suspects if int(s.get("rank", 0)) < rank_val]
    lower = [s.get("name") for s in suspects if int(s.get("rank", 0)) > rank_val]
    return {
        **base,
        "status": "ok",
        "target": {
            "input": target_input,
            "name": selected.get("name"),
            "rank": rank_val,
            "rank_total": len(suspects),
        },
        "suspect": selected,
        "scene_context": {
            "containers_seen": int(
                (ranked.get("summary") or {}).get(
                    "containers_seen", len(scene.get("containers") or [])
                )
            ),
            "suspects_ranked": len(suspects),
            "higher_ranked": higher,
            "lower_ranked": lower,
        },
    }


def render_detail_human(payload: dict[str, Any]) -> str:
    if payload.get("status") != "ok":
        lines = ["Docker triage detail", "", f"Status: {payload.get('status')}"]
        tgt = payload.get("target") or {}
        lines.append(f"Target: {tgt.get('input')}")
        for w in payload.get("warnings") or []:
            lines.append(f"- {w}")
        if payload.get("available_suspects"):
            lines.append("Available suspects:")
            for name in payload["available_suspects"]:
                lines.append(f"- {name}")
        lines.append("Try: shellforgeai triage docker")
        return "\n".join(lines).rstrip() + "\n"

    s = payload["suspect"]
    tgt = payload["target"]
    lines = [f"Docker triage detail: {s['name']}", "", "Rank:"]
    lines.append(f"- rank: {tgt['rank']} of {tgt['rank_total']}")
    lines.append(f"- severity: {s['severity']}")
    lines.append(f"- confidence: {s['confidence']}")
    lines.append(f"- score: {s['score']}")
    lines.append(f"- classes: {', '.join(s.get('classes') or [])}")
    lines.append("")
    lines.append("Why ranked here:")
    for w in s.get("why") or []:
        lines.append(f"- {w}")
    lines.append("")
    lines.append("Evidence:")
    for ev in s.get("evidence") or []:
        lines.append(f"- {ev.get('type')}: {ev.get('value')}")
    lines.append("")
    lines.append("Safe next commands:")
    for cmd in s.get("safe_next_commands") or []:
        lines.append(f"- {cmd}")
    lines.append("- shellforgeai triage docker --json")
    lines.append("")
    lines.append("Safety:")
    lines.append("- read_only: true")
    lines.append("- mutation_performed: false")
    lines.append("- no restart/stop/delete/prune/apply/cleanup executed")
    return "\n".join(lines).rstrip() + "\n"


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
        lines.append("   Evidence:")
        for ev in s.get("evidence") or []:
            lines.append(f"   - {ev.get('type')}: {ev.get('value')}")
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


def build_snapshot_payload(
    scene: dict[str, Any],
    ranked: dict[str, Any],
    *,
    top: int = 5,
    include_details: bool = False,
) -> dict[str, Any]:
    suspects = list(ranked.get("suspects") or [])
    if top < 1:
        top = 1
    selected = suspects[:top]
    status = "ok" if suspects else "warn"
    details: list[dict[str, Any]] = []
    if include_details:
        for s in selected:
            details.append(
                {
                    "name": s.get("name"),
                    "evidence": (s.get("evidence") or [])[:6],
                }
            )
    next_safe = [
        "shellforgeai triage docker detail --rank 1",
        "shellforgeai diagnose docker --save-plan --with-runbook",
        "shellforgeai self-test commands --profile quick",
    ]
    warnings = list(ranked.get("warnings") or [])
    if not suspects:
        warnings.append("no suspects found")
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "mode": SNAPSHOT_MODE,
        "generated_at": _now_utc(),
        "read_only": True,
        "summary": dict(
            ranked.get("summary") or {"containers_seen": len(scene.get("containers") or [])}
        ),
        "suspects": [
            {
                "rank": s.get("rank"),
                "name": s.get("name"),
                "kind": s.get("kind"),
                "severity": s.get("severity"),
                "confidence": s.get("confidence"),
                "score": s.get("score"),
                "classes": s.get("classes") or [],
                "why": s.get("why") or [],
                "detail_command": f"shellforgeai triage docker detail {s.get('name')}",
            }
            for s in selected
        ],
        "details": details,
        "next_safe_commands": next_safe,
        "safety": dict(ranked.get("safety") or {}),
        "warnings": warnings,
    }


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def render_snapshot_human(payload: dict[str, Any]) -> str:
    lines = ["Docker triage snapshot", "", "Scene:"]
    summary = payload.get("summary") or {}
    lines.append(f"- containers seen: {summary.get('containers_seen', 0)}")
    lines.append(f"- suspects ranked: {summary.get('suspects_ranked', 0)}")
    lines.append(f"- critical: {summary.get('critical', 0)}")
    lines.append(f"- high: {summary.get('high', 0)}")
    lines.append(f"- generated_at: {payload.get('generated_at')}")
    lines.append("- mode: read-only")
    lines.append("")
    lines.append("Ranked suspects:")
    suspects = payload.get("suspects") or []
    if not suspects:
        lines.append("- no suspects found")
    for s in suspects:
        lines.append(f"{s['rank']}. {s['name']}")
        lines.append(f"   Severity: {s['severity']}")
        lines.append(f"   Confidence: {s['confidence']}")
        lines.append(f"   Classes: {', '.join(s.get('classes') or [])}")
        lines.append("   Why:")
        for why in s.get("why") or []:
            lines.append(f"   - {why}")
        lines.append("   Detail:")
        lines.append(f"   - {s.get('detail_command')}")
    if payload.get("details"):
        lines.append("")
        lines.append("Detail evidence:")
        for d in payload["details"]:
            lines.append(f"- {d.get('name')}:")
            for ev in d.get("evidence") or []:
                lines.append(f"  - {ev.get('type')}: {ev.get('value')}")
    lines.append("")
    lines.append("Safe next commands:")
    for cmd in payload.get("next_safe_commands") or []:
        lines.append(f"- {cmd}")
    lines.append("")
    lines.append("Safety:")
    lines.append("- read_only: true")
    lines.append("- mutation_performed: false")
    lines.append("- no restart/stop/delete/prune/apply/cleanup executed")
    return "\n".join(lines).rstrip() + "\n"


def _snapshot_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"triage_snapshot_{stamp}_{uuid.uuid4().hex[:6]}"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def save_snapshot_artifact(
    snapshot: dict[str, Any], data_dir: Path, *, source_command: str
) -> dict[str, Any]:
    artifact_id = _snapshot_id()
    artifact_dir = data_dir / "artifacts" / artifact_id
    artifact_dir.mkdir(parents=True, exist_ok=False)
    json_path = artifact_dir / "triage-snapshot.json"
    md_path = artifact_dir / "triage-snapshot.md"
    details_path = artifact_dir / "triage-details.json"
    json_path.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_snapshot_human(snapshot), encoding="utf-8")
    files = ["triage-snapshot.json", "triage-snapshot.md"]
    if snapshot.get("details"):
        details_path.write_text(
            json.dumps(snapshot.get("details") or [], indent=2) + "\n", encoding="utf-8"
        )
        files.append("triage-details.json")
    manifest = {
        "schema_version": "1",
        "mode": "docker_triage_snapshot_artifact",
        "artifact_id": artifact_id,
        "generated_at": _now_utc(),
        "source_command": source_command,
        "files": files,
        "checksums": {name: _sha256_file(artifact_dir / name) for name in files},
    }
    (artifact_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    files.append("manifest.json")
    return {
        "schema_version": "1",
        "status": "saved",
        "mode": "docker_triage_snapshot_save",
        "artifact": {"id": artifact_id, "path": str(artifact_dir), "files": files, "written": True},
        "snapshot": snapshot,
        "safety": {**(snapshot.get("safety") or {}), "arbitrary_path_write": False},
        "next_safe_commands": [
            f"shellforgeai triage docker snapshot validate {artifact_id}",
            "shellforgeai triage docker detail --rank 1",
            f"shellforgeai export {artifact_dir}",
        ],
        "warnings": [],
    }


def validate_snapshot_artifact(snapshot_ref: str, data_dir: Path) -> dict[str, Any]:
    candidate = Path(snapshot_ref)
    if candidate.is_absolute() or "/" in snapshot_ref:
        artifact_dir = candidate
    else:
        if ".." in snapshot_ref or "\\" in snapshot_ref:
            return {
                "schema_version": "1",
                "status": "error",
                "mode": "docker_triage_snapshot_validate",
                "warnings": ["unsafe snapshot id"],
                "checks": {},
            }
        artifact_dir = data_dir / "artifacts" / snapshot_ref
    checks = {
        "required_files": False,
        "json_parse": False,
        "schema_version": False,
        "mode": False,
        "safety": False,
        "checksums": False,
    }
    if not artifact_dir.exists():
        return {
            "schema_version": "1",
            "status": "not_found",
            "mode": "docker_triage_snapshot_validate",
            "artifact": {"id": artifact_dir.name, "path": str(artifact_dir)},
            "checks": checks,
            "warnings": ["snapshot not found"],
        }
    json_path = artifact_dir / "triage-snapshot.json"
    md_path = artifact_dir / "triage-snapshot.md"
    if not json_path.exists() or not md_path.exists():
        return {
            "schema_version": "1",
            "status": "failed",
            "mode": "docker_triage_snapshot_validate",
            "artifact": {"id": artifact_dir.name, "path": str(artifact_dir)},
            "checks": checks,
            "warnings": ["missing required files"],
        }
    checks["required_files"] = True
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception:
        return {
            "schema_version": "1",
            "status": "error",
            "mode": "docker_triage_snapshot_validate",
            "artifact": {"id": artifact_dir.name, "path": str(artifact_dir)},
            "checks": checks,
            "warnings": ["triage-snapshot.json unreadable"],
        }
    checks["json_parse"] = True
    checks["schema_version"] = payload.get("schema_version") == "1"
    checks["mode"] = payload.get("mode") == SNAPSHOT_MODE
    s = payload.get("safety") or {}
    blocked = any(
        bool(s.get(k))
        for k in (
            "mutation_performed",
            "cleanup_executed",
            "proposal_created",
            "mission_created",
            "apply_executed",
            "docker_compose_executed",
            "container_restarted",
            "natural_language_execution",
            "shell_true",
        )
    )
    checks["safety"] = not blocked and bool(s.get("read_only") is True)
    manifest_path = artifact_dir / "manifest.json"
    checks["checksums"] = True
    if manifest_path.exists():
        mf = json.loads(manifest_path.read_text(encoding="utf-8"))
        for rel, expected in (mf.get("checksums") or {}).items():
            if not (artifact_dir / rel).exists() or _sha256_file(artifact_dir / rel) != expected:
                checks["checksums"] = False
                break
    status = "ok" if all(checks.values()) else "failed"
    return {
        "schema_version": "1",
        "status": status,
        "mode": "docker_triage_snapshot_validate",
        "artifact": {"id": artifact_dir.name, "path": str(artifact_dir)},
        "checks": checks,
        "summary": {
            "containers_seen": (payload.get("summary") or {}).get("containers_seen", 0),
            "suspects_ranked": (payload.get("summary") or {}).get("suspects_ranked", 0),
        },
        "safety": s,
        "warnings": [],
    }


def render_saved_snapshot_human(payload: dict[str, Any]) -> str:
    art = payload.get("artifact") or {}
    snap = payload.get("snapshot") or {}
    summary = snap.get("summary") or {}
    lines = ["Docker triage snapshot saved", "", "Snapshot:"]
    lines.append(f"- id: {art.get('id')}")
    lines.append(f"- path: {art.get('path')}")
    lines.append("- files:")
    for name in art.get("files") or []:
        lines.append(f"  - {name}")
    lines += [
        "",
        "Summary:",
        f"- containers seen: {summary.get('containers_seen', 0)}",
        f"- suspects ranked: {summary.get('suspects_ranked', 0)}",
        f"- critical: {summary.get('critical', 0)}",
        f"- high: {summary.get('high', 0)}",
        "",
        "Safety:",
        "- read_only: true",
        "- mutation_performed: false",
        "- no restart/stop/delete/prune/apply/cleanup executed",
        "",
        "Next safe commands:",
    ]
    for cmd in payload.get("next_safe_commands") or []:
        lines.append(f"- {cmd}")
    return "\n".join(lines).rstrip() + "\n"


def render_snapshot_validation_human(payload: dict[str, Any]) -> str:
    lines = [
        "Triage snapshot validation passed"
        if payload.get("status") == "ok"
        else "Triage snapshot validation failed",
        "",
        f"Status: {payload.get('status')}",
    ]
    art = payload.get("artifact") or {}
    if art:
        lines += ["", "Snapshot:", f"- id: {art.get('id')}", f"- path: {art.get('path')}"]
    if payload.get("checks"):
        lines += ["", "Checks:"]
        for k, v in (payload.get("checks") or {}).items():
            lines.append(f"- {k.replace('_', ' ')}: {'ok' if v else 'failed'}")
    for w in payload.get("warnings") or []:
        lines.append(f"- warning: {w}")
    return "\n".join(lines).rstrip() + "\n"


def export_snapshot_artifact(
    snapshot_ref: str, data_dir: Path, *, output: Path | None = None
) -> dict[str, Any]:
    validation = validate_snapshot_artifact(snapshot_ref, data_dir)
    base_safety = {
        "read_only": True,
        "artifact_export_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
        "proposal_created": False,
        "mission_created": False,
        "apply_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "natural_language_execution": False,
        "shell_true": False,
        "arbitrary_path_write": False,
    }
    if validation.get("status") == "not_found":
        return {
            "schema_version": "1",
            "status": "not_found",
            "mode": "docker_triage_snapshot_export",
            "source_snapshot": validation.get("artifact") or {},
            "safety": base_safety,
            "warnings": ["snapshot not found"],
        }
    if validation.get("status") != "ok":
        return {
            "schema_version": "1",
            "status": "failed",
            "mode": "docker_triage_snapshot_export",
            "source_snapshot": validation.get("artifact") or {},
            "safety": base_safety,
            "warnings": ["source snapshot validation failed"],
        }
    source = Path((validation.get("artifact") or {}).get("path") or "")
    if not source.exists():
        return {
            "schema_version": "1",
            "status": "not_found",
            "mode": "docker_triage_snapshot_export",
            "source_snapshot": validation.get("artifact") or {},
            "safety": base_safety,
            "warnings": ["snapshot not found"],
        }
    export_id = f"export_{source.name}"
    out_root = data_dir / "exports"
    export_dir = output or (out_root / export_id)
    if output is not None and (output.is_absolute() or ".." in output.parts):
        return {
            "schema_version": "1",
            "status": "error",
            "mode": "docker_triage_snapshot_export",
            "source_snapshot": validation.get("artifact") or {},
            "safety": base_safety,
            "warnings": ["unsafe output path"],
        }
    export_dir = export_dir.resolve()
    if not str(export_dir).startswith(str(out_root.resolve())):
        return {
            "schema_version": "1",
            "status": "error",
            "mode": "docker_triage_snapshot_export",
            "source_snapshot": validation.get("artifact") or {},
            "safety": base_safety,
            "warnings": ["unsafe output path"],
        }
    export_dir.mkdir(parents=True, exist_ok=False)
    files = ["triage-snapshot.json", "triage-snapshot.md", "manifest.json"]
    if (source / "triage-details.json").exists():
        files.append("triage-details.json")
    for name in files:
        (export_dir / name).write_bytes((source / name).read_bytes())
    checksums = {name: _sha256_file(export_dir / name) for name in files}
    (export_dir / "checksums.sha256").write_text(
        "".join(f"{v}  {k}\n" for k, v in checksums.items()), encoding="utf-8"
    )
    export_manifest = {
        "schema_version": "1",
        "mode": SNAPSHOT_EXPORT_MODE,
        "export_id": export_dir.name,
        "source_snapshot": {"id": source.name, "path": str(source), "validated": True},
        "files": files,
        "checksums": checksums,
        "safety": base_safety,
    }
    (export_dir / "export-manifest.json").write_text(
        json.dumps(export_manifest, indent=2) + "\n", encoding="utf-8"
    )
    return {
        "schema_version": "1",
        "status": "exported",
        "mode": "docker_triage_snapshot_export",
        "source_snapshot": {"id": source.name, "path": str(source), "validated": True},
        "export": {
            "id": export_dir.name,
            "path": str(export_dir),
            "files": files + ["export-manifest.json"],
            "written": True,
        },
        "checksums": {"enabled": True, "algorithm": "sha256"},
        "safety": base_safety,
        "next_safe_commands": [
            f"shellforgeai triage docker snapshot export-validate {export_dir}",
            f"shellforgeai validate-export {export_dir}",
        ],
        "warnings": [],
    }


def validate_snapshot_export(export_ref: str) -> dict[str, Any]:
    export_dir = Path(export_ref)
    checks = {
        "required_files": False,
        "json_parse": False,
        "manifest": False,
        "checksums": False,
        "source_snapshot_safety": False,
        "export_safety": False,
    }
    if not export_dir.exists():
        return {
            "schema_version": "1",
            "status": "not_found",
            "mode": "docker_triage_snapshot_export_validate",
            "export": {"path": str(export_dir)},
            "checks": checks,
            "warnings": ["export not found"],
        }
    req = ["triage-snapshot.json", "triage-snapshot.md", "manifest.json", "export-manifest.json"]
    if not all((export_dir / r).exists() for r in req):
        return {
            "schema_version": "1",
            "status": "failed",
            "mode": "docker_triage_snapshot_export_validate",
            "export": {"path": str(export_dir)},
            "checks": checks,
            "warnings": ["missing required file"],
        }
    checks["required_files"] = True
    try:
        snap = json.loads((export_dir / "triage-snapshot.json").read_text(encoding="utf-8"))
        em = json.loads((export_dir / "export-manifest.json").read_text(encoding="utf-8"))
    except Exception:
        return {
            "schema_version": "1",
            "status": "error",
            "mode": "docker_triage_snapshot_export_validate",
            "export": {"path": str(export_dir)},
            "checks": checks,
            "warnings": ["malformed json"],
        }
    checks["json_parse"] = True
    checks["manifest"] = em.get("mode") == SNAPSHOT_EXPORT_MODE
    checks["checksums"] = True
    for rel, expected in (em.get("checksums") or {}).items():
        if not (export_dir / rel).exists() or _sha256_file(export_dir / rel) != expected:
            checks["checksums"] = False
            break
    ss = snap.get("safety") or {}
    checks["source_snapshot_safety"] = bool(ss.get("read_only") is True) and not any(
        bool(ss.get(k))
        for k in (
            "mutation_performed",
            "cleanup_executed",
            "proposal_created",
            "mission_created",
            "apply_executed",
            "docker_compose_executed",
            "container_restarted",
            "natural_language_execution",
            "shell_true",
        )
    )
    exs = em.get("safety") or {}
    checks["export_safety"] = bool(exs.get("read_only") is True) and not bool(
        exs.get("mutation_performed")
    )
    status = "ok" if all(checks.values()) else "failed"
    return {
        "schema_version": "1",
        "status": status,
        "mode": "docker_triage_snapshot_export_validate",
        "export": {"path": str(export_dir)},
        "checks": checks,
        "summary": {
            "containers_seen": (snap.get("summary") or {}).get("containers_seen", 0),
            "suspects_ranked": (snap.get("summary") or {}).get("suspects_ranked", 0),
        },
        "safety": exs,
        "warnings": [],
    }


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _suspect_index(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    idx = {}
    for s in snapshot.get("suspects") or []:
        name = (s.get("name") or "").strip()
        if name:
            idx[name] = s
    return idx


def _evidence_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, int]:
    b = {
        str(e.get("type")): int(e.get("value") or 0)
        for e in (before.get("evidence") or [])
        if str(e.get("type") or "") and str(e.get("value") or "").lstrip("-").isdigit()
    }
    a = {
        str(e.get("type")): int(e.get("value") or 0)
        for e in (after.get("evidence") or [])
        if str(e.get("type") or "") and str(e.get("value") or "").lstrip("-").isdigit()
    }
    keys = set(b) | set(a)
    return {k: a.get(k, 0) - b.get(k, 0) for k in sorted(keys) if a.get(k, 0) - b.get(k, 0) != 0}


def compare_snapshot_payload(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    top: int = 5,
    only_changed: bool = False,
    include_stable: bool = False,
    include_evidence: bool = False,
) -> dict[str, Any]:
    bidx = _suspect_index(before)
    aidx = _suspect_index(after)
    names = sorted(set(bidx) | set(aidx))
    regressions = []
    recoveries = []
    stable = []
    new_suspects = []
    removed_suspects = []
    for name in names:
        b = bidx.get(name)
        a = aidx.get(name)
        if b is None:
            new_suspects.append(name)
            continue
        if a is None:
            removed_suspects.append(name)
            continue
        drift = []
        bsev, asev = b.get("severity"), a.get("severity")
        if bsev != asev:
            drift.append(f"severity: {bsev} -> {asev}")
        bconf, aconf = b.get("confidence"), a.get("confidence")
        if bconf != aconf:
            drift.append(f"confidence: {bconf} -> {aconf}")
        if b.get("rank") != a.get("rank"):
            drift.append(f"rank: {b.get('rank')} -> {a.get('rank')}")
        if (b.get("classes") or []) != (a.get("classes") or []):
            drift.append("classes changed")
        ev_delta = _evidence_delta(b, a) if include_evidence else {}
        for k, v in ev_delta.items():
            drift.append(f"{k}: {v:+d}")
        entry = {
            "name": name,
            "before_rank": b.get("rank"),
            "after_rank": a.get("rank"),
            "before_severity": bsev,
            "after_severity": asev,
            "before_confidence": bconf,
            "after_confidence": aconf,
            "before_classes": b.get("classes") or [],
            "after_classes": a.get("classes") or [],
            "evidence_delta": ev_delta,
            "drift_summary": drift,
            "recommended_safe_next_command": f"shellforgeai triage docker detail {name}",
        }
        sev_up = SEVERITY_ORDER.get(str(asev), 0) > SEVERITY_ORDER.get(str(bsev), 0)
        if drift:
            if sev_up or (a.get("rank") or 999) < (b.get("rank") or 999):
                regressions.append(entry)
            else:
                recoveries.append(entry)
        else:
            stable.append(entry)
    regressions.sort(
        key=lambda x: (
            (SEVERITY_ORDER.get(str(x.get("after_severity")), 0)) * -1,
            x.get("after_rank") or 999,
            x["name"],
        )
    )
    recoveries.sort(key=lambda x: (x.get("after_rank") or 999, x["name"]))
    stable.sort(key=lambda x: (x.get("after_rank") or 999, x["name"]))
    if top < 1:
        top = 1
    regressions = regressions[:top]
    if only_changed or not include_stable:
        stable = []
    scene_before = before.get("summary") or {}
    scene_after = after.get("summary") or {}
    return {
        "schema_version": 1,
        "mode": "docker_triage_snapshot_compare",
        "status": "ok",
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "suspects_before": len(bidx),
            "suspects_after": len(aidx),
            "new": len(new_suspects),
            "recovered": len(removed_suspects),
            "escalated": len(regressions),
            "scene_before": scene_before,
            "scene_after": scene_after,
        },
        "regressions": regressions,
        "recoveries": recoveries,
        "stable": stable,
        "new_suspects": new_suspects,
        "removed_suspects": removed_suspects,
        "warnings": [],
        "safety": {"read_only": True, "mutation_performed": False},
    }


def render_snapshot_compare_human(payload: dict[str, Any]) -> str:
    s = payload.get("summary") or {}
    lines = ["Scene drift summary:"]
    for k in ("suspects_before", "suspects_after", "new", "recovered", "escalated"):
        lines.append(f"- {k}: {s.get(k, 0)}")
    lines += ["", "Top regressions:"]
    regs = payload.get("regressions") or []
    if not regs:
        lines.append("- none")
    for i, r in enumerate(regs, 1):
        lines.append(f"{i}. {r.get('name')}")
        for d in r.get("drift_summary") or []:
            lines.append(f"   {d}")
    if payload.get("recoveries"):
        lines += ["", "Recovered:"]
        for r in payload.get("recoveries") or []:
            lines.append(f"- {r.get('name') if isinstance(r, dict) else r}")
    if payload.get("stable"):
        lines += ["", "Stable:"]
        for r in payload.get("stable"):
            lines.append(f"- {r.get('name')}")
    lines += ["", "Safety:", "- read_only=true", "- mutation_performed=false"]
    return "\n".join(lines).rstrip() + "\n"


def compare_snapshot_exports(export_a: str, export_b: str, **kwargs: Any) -> dict[str, Any]:
    va = validate_snapshot_export(export_a)
    vb = validate_snapshot_export(export_b)
    if va.get("status") != "ok" or vb.get("status") != "ok":
        return {
            "schema_version": 1,
            "mode": "docker_triage_snapshot_compare",
            "status": "error",
            "read_only": True,
            "mutation_performed": False,
            "warnings": ["export validation failed"],
            "summary": {},
            "regressions": [],
            "recoveries": [],
            "stable": [],
            "new_suspects": [],
            "removed_suspects": [],
            "safety": {"read_only": True, "mutation_performed": False},
        }
    sa = json.loads((Path(export_a) / "triage-snapshot.json").read_text(encoding="utf-8"))
    sb = json.loads((Path(export_b) / "triage-snapshot.json").read_text(encoding="utf-8"))
    return compare_snapshot_payload(sa, sb, **kwargs)


def build_snapshot_timeline(
    data_dir: Path,
    *,
    window: int = 5,
    top: int = 5,
    only_regressions: bool = False,
    include_stable: bool = False,
) -> dict[str, Any]:
    artifacts_root = data_dir / "artifacts"
    safety = {
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
    }
    if not artifacts_root.exists():
        return {
            "schema_version": "1",
            "status": "not_found",
            "mode": "docker_triage_timeline",
            "window": {"snapshots_analyzed": 0},
            "summary": {},
            "escalating": [],
            "recovering": [],
            "flapping": [],
            "recurring": [],
            "stable": [],
            "new_suspects": [],
            "resolved_suspects": [],
            "safety": safety,
            "warnings": ["no snapshots found"],
        }
    entries: list[tuple[str, dict[str, Any]]] = []
    warnings: list[str] = []
    dirs = sorted([p for p in artifacts_root.iterdir() if p.is_dir()], key=lambda p: p.name)
    for d in dirs:
        v = validate_snapshot_artifact(d.name, data_dir)
        if v.get("status") != "ok":
            warnings.append(f"skipped invalid snapshot: {d.name}")
            continue
        snap = json.loads((d / "triage-snapshot.json").read_text(encoding="utf-8"))
        entries.append((d.name, snap))
    if window > 0:
        entries = entries[-window:]
    if len(entries) < 2:
        return {
            "schema_version": "1",
            "status": "warn",
            "mode": "docker_triage_timeline",
            "window": {"snapshots_analyzed": len(entries)},
            "summary": {},
            "escalating": [],
            "recovering": [],
            "flapping": [],
            "recurring": [],
            "stable": [],
            "new_suspects": [],
            "resolved_suspects": [],
            "safety": safety,
            "warnings": warnings + ["at least 2 valid snapshots required"],
        }
    snapshot_names = [x[0] for x in entries]
    latest_idx = len(entries) - 1
    hist: dict[str, dict[str, Any]] = {}
    for i, (_sid, snap) in enumerate(entries):
        for s in snap.get("suspects") or []:
            name = (s.get("name") or "").strip()
            if not name:
                continue
            h = hist.setdefault(
                name,
                {
                    "name": name,
                    "seen": [],
                    "rank_history": [],
                    "severity_history": [],
                    "confidence_history": [],
                    "class_history": [],
                    "evidence_count_history": [],
                },
            )
            h["seen"].append(i)
            h["rank_history"].append(s.get("rank"))
            h["severity_history"].append(s.get("severity"))
            h["confidence_history"].append(s.get("confidence"))
            h["class_history"].append(s.get("classes") or [])
            h["evidence_count_history"].append(len(s.get("why") or []))
    sev = SEVERITY_ORDER
    escalating = []
    recovering = []
    flapping = []
    recurring = []
    stable = []
    new_s = []
    resolved = []
    for name, h in hist.items():
        seen = h["seen"]
        present_latest = latest_idx in seen
        rank_hist = [r for r in h["rank_history"] if isinstance(r, int)]
        sev_hist = [str(x) for x in h["severity_history"]]
        evidence = h["evidence_count_history"]
        miss = len(entries) - len(seen)
        is_flap = any((b - a) > 1 for a, b in zip(seen, seen[1:], strict=False))
        sev_first = sev.get(sev_hist[0], 0)
        sev_last = sev.get(sev_hist[-1], 0)
        rank_first = rank_hist[0] if rank_hist else None
        rank_last = rank_hist[-1] if rank_hist else None
        is_escalating = present_latest and (
            (sev_last > sev_first)
            or (rank_first is not None and rank_last is not None and rank_last < rank_first)
            or (evidence and evidence[-1] > evidence[0])
        )
        is_recovering = (
            present_latest
            and (
                (sev_last < sev_first)
                or (rank_first is not None and rank_last is not None and rank_last > rank_first)
                or (evidence and evidence[-1] < evidence[0])
            )
        ) or (not present_latest)
        is_stable = (
            miss == 0
            and len(set(sev_hist)) == 1
            and len(set(rank_hist or [None])) == 1
            and not is_flap
        )
        trend = "stable"
        if present_latest and len(seen) == 1:
            trend = "new"
            new_s.append(name)
        elif not present_latest:
            trend = "resolved"
            resolved.append(name)
        elif is_flap:
            trend = "flapping"
            flapping.append(name)
        elif is_escalating:
            trend = "escalating"
            escalating.append(name)
        elif is_recovering:
            trend = "recovering"
            recovering.append(name)
        elif len(seen) > 1:
            trend = "recurring"
            recurring.append(name)
        if is_stable:
            stable.append(name)
        item = {
            "name": name,
            "first_seen": snapshot_names[seen[0]],
            "last_seen": snapshot_names[seen[-1]],
            "snapshots_seen": len(seen),
            "snapshots_missing": miss,
            "latest_rank": rank_last,
            "rank_history": rank_hist,
            "latest_severity": sev_hist[-1] if sev_hist else None,
            "severity_history": sev_hist,
            "latest_confidence": h["confidence_history"][-1] if h["confidence_history"] else None,
            "confidence_history": h["confidence_history"],
            "class_history": h["class_history"],
            "evidence_count_history": evidence,
            "highest_severity": max(sev_hist, key=lambda x: sev.get(x, 0)) if sev_hist else None,
            "worst_rank": max(rank_hist) if rank_hist else None,
            "best_rank": min(rank_hist) if rank_hist else None,
            "latest_status": trend,
            "recommended_safe_next_command": f"shellforgeai triage docker detail {name}",
        }
        if trend == "escalating":
            escalating[-1] = item
        elif trend == "recovering":
            recovering[-1] = item
        elif trend == "flapping":
            flapping[-1] = item
        elif trend == "recurring":
            recurring[-1] = item
        elif trend == "stable":
            stable[-1] = item
    if top < 1:
        top = 1
    escalating = escalating[:top]
    recovering = recovering[:top]
    flapping = flapping[:top]
    recurring = recurring[:top]
    shown_stable = stable[:top] if include_stable and not only_regressions else []
    if only_regressions:
        recovering = []
        recurring = []
        shown_stable = []
    return {
        "schema_version": "1",
        "status": "ok",
        "mode": "docker_triage_timeline",
        "read_only": True,
        "mutation_performed": False,
        "window": {
            "snapshots_analyzed": len(entries),
            "first_snapshot": snapshot_names[0],
            "latest_snapshot": snapshot_names[-1],
        },
        "summary": {
            "suspects_seen": len(hist),
            "escalating": len(escalating),
            "recovering": len(recovering),
            "flapping": len(flapping),
            "recurring": len(recurring),
            "stable": len(stable),
            "new": len(new_s),
            "resolved": len(resolved),
        },
        "escalating": escalating,
        "recovering": recovering,
        "flapping": flapping,
        "recurring": recurring,
        "stable": shown_stable,
        "new_suspects": new_s,
        "resolved_suspects": resolved,
        "next_safe_commands": [
            "shellforgeai triage docker snapshot",
            "shellforgeai triage docker detail --rank 1",
        ],
        "safety": safety,
        "warnings": warnings,
    }


def render_snapshot_timeline_human(payload: dict[str, Any]) -> str:
    def _timeline_item_name(item: Any) -> str:
        if isinstance(item, dict):
            return str(item.get("name") or item.get("suspect") or "unknown")
        if isinstance(item, str):
            return item
        return str(item)

    def _timeline_item_dict(item: Any) -> dict[str, Any]:
        if isinstance(item, dict):
            return item
        if isinstance(item, str):
            return {"name": item}
        return {"name": _timeline_item_name(item)}

    lines = ["Docker triage timeline", "", "Window:"]
    w = payload.get("window") or {}
    lines.append(f"- snapshots analyzed: {w.get('snapshots_analyzed', 0)}")
    if w.get("first_snapshot"):
        lines.append(f"- first snapshot: {w.get('first_snapshot')}")
        lines.append(f"- latest snapshot: {w.get('latest_snapshot')}")
    lines.append("- mode: read-only")
    lines += ["", "Summary:"]
    s = payload.get("summary") or {}
    for k in ("escalating", "recovering", "flapping", "recurring", "stable", "new", "resolved"):
        lines.append(f"- {k}: {s.get(k, 0)}")
    for section in ("escalating", "flapping", "recovering", "stable"):
        vals = payload.get(section) or []
        if not vals:
            continue
        lines += ["", f"{section.capitalize()}:"]
        for i, item in enumerate(vals, 1):
            parsed = _timeline_item_dict(item)
            lines.append(f"{i}. {_timeline_item_name(item)}")
            sev_hist = parsed.get("severity_history") or []
            if sev_hist or parsed.get("latest_severity") is not None:
                first_sev = sev_hist[0] if sev_hist else parsed.get("latest_severity")
                lines.append(f"   severity: {first_sev} -> {parsed.get('latest_severity')}")
            rank_hist = parsed.get("rank_history") or []
            if rank_hist or parsed.get("latest_rank") is not None:
                first_rank = rank_hist[0] if rank_hist else parsed.get("latest_rank")
                lines.append(f"   rank: {first_rank} -> {parsed.get('latest_rank')}")
            if parsed.get("snapshots_seen") is not None:
                lines.append(f"   seen: {parsed.get('snapshots_seen')} snapshots")
            if parsed.get("latest_status"):
                lines.append(f"   trend: {parsed.get('latest_status')}")
    lines += [
        "",
        "Safety:",
        "- read_only: true",
        "- mutation_performed: false",
        "- no restart/stop/delete/prune/apply/cleanup executed",
    ]
    return "\n".join(lines).rstrip() + "\n"
