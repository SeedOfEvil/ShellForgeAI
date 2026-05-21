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

import json
import re
from typing import Any

SCHEMA_VERSION = "1"
MODE = "docker_triage_ranking"
SNAPSHOT_MODE = "docker_triage_snapshot"

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
    from datetime import datetime, timezone

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
