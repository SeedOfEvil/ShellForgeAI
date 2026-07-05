#!/usr/bin/env python3
"""Read-only Docker01 ownership-fix readiness packet helper.

This helper reads local Dockerfile, recipe, and optional health-report JSON files
only. It never executes the recipe, Docker, Compose, cleanup, remediation,
rollback, recovery, restarts, process kills, or arbitrary shell commands.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MODE = "docker01_ownership_fix_readiness"
BROAD_CHOWN_PATTERN = "chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai"
DEFAULT_RECIPE = (
    Path(__file__).resolve().parent / "docker01_external_dockerfile_ownership_update.py"
)
NEXT_OPERATOR_STEP = (
    "Review readiness packet, then execute the guarded ownership update recipe only in an "
    "approved maintenance window with the recipe confirmation phrase."
)


def safety_block() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "recipe_executed": False,
        "dockerfile_modified": False,
        "docker_build_executed": False,
        "docker_compose_mutation_executed": False,
        "docker_prune_executed": False,
        "process_kill_executed": False,
        "service_restart_executed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "recovery_executed": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
    }


def read_text(path: Path) -> tuple[bool, str | None, str]:
    try:
        return True, None, path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return False, str(exc), ""


def dockerfile_block(path: Path) -> dict[str, Any]:
    exists = path.exists()
    block: dict[str, Any] = {
        "path": str(path),
        "exists": exists,
        "readable": False,
        "broad_recursive_ownership_layer": {
            "detected": False,
            "pattern": BROAD_CHOWN_PATTERN,
        },
    }
    if not exists:
        block["status"] = "not_found"
        return block
    ok, err, text = read_text(path)
    block["readable"] = ok
    if not ok:
        block["status"] = "unreadable"
        block["reason"] = err
        return block
    block["status"] = "found"
    block["broad_recursive_ownership_layer"]["detected"] = BROAD_CHOWN_PATTERN in text
    return block


def recipe_path(explicit: Path | None) -> tuple[Path, bool]:
    if explicit is not None:
        return explicit, True
    return DEFAULT_RECIPE, False


def _commandish_lines(text: str) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        if any(
            token in line
            for token in ("subprocess", "os.system", "check_call", "check_output", "popen")
        ):
            lines.append(line)
            continue
    return lines


def static_recipe_checks(text: str) -> dict[str, bool]:
    lower = text.lower()
    command_text = "\n".join(_commandish_lines(text))
    return {
        "confirmation_required": bool(
            re.search(r"confirm|confirmation|confirmation_phrase", lower)
        ),
        "apply_flag_present": bool(
            re.search(r"--(?:apply|write|execute)|write_available|write_external", lower)
        ),
        "backup_or_receipt_present": "backup" in lower or "receipt" in lower,
        "docker_build_absent": not bool(
            re.search(r"docker[^\n]*(?:build|buildx)|\bbuildx\b", command_text)
        ),
        "docker_compose_mutation_absent": not bool(
            re.search(
                r"docker[^\n]*compose[^\n]*(?:up|down|restart|rm|kill|stop|start)", command_text
            )
            or re.search(r"compose[^\n]*(?:up|down|restart|rm|kill|stop|start)", command_text)
        ),
        "docker_prune_absent": not bool(re.search(r"docker[^\n]*prune|\bprune\b", command_text)),
        "docker_remove_absent": not bool(
            re.search(r"docker[^\n]*(?:\brm\b|\brmi\b|volume[^\n]*rm)", command_text)
        ),
        "service_restart_absent": not bool(
            re.search(r"\b(systemctl|service)\b[^\n]*\brestart\b", command_text)
        ),
        "process_kill_absent": not bool(re.search(r"\b(kill|pkill|killall)\b", command_text)),
        "shell_true_absent": "shell=true" not in lower.replace(" ", ""),
        "arbitrary_subprocess_shell_absent": not bool(
            re.search(r"subprocess\.[a-z_]+\([^\)]*shell\s*=\s*true", lower, re.S)
        ),
    }


def recipe_block(path: Path, explicit: bool) -> dict[str, Any]:
    block: dict[str, Any] = {"path": str(path), "status": "not_found", "explicit": explicit}
    if not path.exists():
        if explicit:
            block["reason"] = "explicit_recipe_script_not_found"
        return block
    ok, err, text = read_text(path)
    if not ok:
        block.update({"status": "unreadable", "reason": err})
        return block
    checks = static_recipe_checks(text)
    block.update({"status": "present", "static_checks": checks})
    return block


def health_block(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"provided": False, "status": "not_provided"}
    block: dict[str, Any] = {"provided": True, "path": str(path), "status": "invalid"}
    try:
        text = path.read_text(encoding="utf-8-sig")
        data = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        block["reason"] = str(exc)
        return block
    readiness = data.get("readiness", {}) if isinstance(data.get("readiness"), dict) else {}
    risk = (
        data.get("known_risks", {}).get("broad_recursive_ownership_layer", {})
        if isinstance(data.get("known_risks"), dict)
        else {}
    )
    dockerfile = data.get("dockerfile", {}) if isinstance(data.get("dockerfile"), dict) else {}
    block.update(
        {
            "status": "valid",
            "mode": data.get("mode"),
            "reported_status": data.get("status"),
            "readiness_status": readiness.get("status") or data.get("readiness"),
            "reasons": readiness.get("reasons", data.get("reasons", [])),
            "broad_chown_risk": risk,
            "dockerfile_path": dockerfile.get("selected_path") or dockerfile.get("path"),
        }
    )
    return block


def compute_readiness(
    dockerfile: dict[str, Any], recipe: dict[str, Any], health: dict[str, Any]
) -> dict[str, Any]:
    reasons: list[str] = []
    status = "unknown"
    if not dockerfile["exists"]:
        status = "blocked"
        reasons.append("dockerfile_not_found")
    elif not dockerfile["readable"]:
        status = "blocked"
        reasons.append("dockerfile_unreadable")
    else:
        risk = dockerfile["broad_recursive_ownership_layer"]["detected"]
        if not risk:
            status = "attention"
            reasons.append("no_broad_chown_detected")
        elif recipe["status"] != "present":
            status = "blocked"
            reasons.append(
                "recipe_not_found" if recipe["status"] == "not_found" else "recipe_unreadable"
            )
        else:
            checks = recipe.get("static_checks", {})
            missing = [k for k, v in checks.items() if not v]
            if missing:
                status = "blocked"
                reasons.extend(f"recipe_static_check_failed:{m}" for m in missing)
            else:
                status = "ready"
    hstatus = health.get("readiness_status")
    if hstatus in {"attention", "blocked"}:
        reasons.append(f"health_readiness_{hstatus}")
        if hstatus == "blocked":
            status = "blocked"
        elif status == "ready":
            status = "attention"
    if health.get("status") == "invalid":
        reasons.append("health_json_invalid")
        if status == "ready":
            status = "attention"
    return {"status": status, "reasons": reasons, "next_operator_step": NEXT_OPERATOR_STEP}


def build_report(
    dockerfile: Path, health_json: Path | None = None, recipe_script: Path | None = None
) -> dict[str, Any]:
    df = dockerfile_block(dockerfile)
    rp, explicit = recipe_path(recipe_script)
    rec = recipe_block(rp, explicit)
    health = health_block(health_json)
    readiness = compute_readiness(df, rec, health)
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": readiness["status"] if readiness["status"] != "ready" else "attention",
        "read_only": True,
        "mutation_performed": False,
        "dockerfile": df,
        "recipe": rec,
        "health_report": health,
        "readiness": readiness,
        "safety": safety_block(),
    }


def to_markdown(report: dict[str, Any]) -> str:
    checks = report["recipe"].get("static_checks", {})
    broad_detected = str(
        report["dockerfile"]["broad_recursive_ownership_layer"]["detected"]
    ).lower()
    lines = [
        "# Docker01 Ownership-Fix Readiness Packet",
        "",
        f"- Readiness status: `{report['readiness']['status']}`",
        f"- Dockerfile path: `{report['dockerfile']['path']}`",
        f"- Broad chown risk detected: `{broad_detected}`",
        f"- Recipe path: `{report['recipe']['path']}`",
        f"- Recipe status: `{report['recipe']['status']}`",
        f"- Health report status: `{report['health_report']['status']}`",
        "",
        "## Static recipe safety checks",
    ]
    if checks:
        for key in sorted(checks):
            lines.append(f"- {key}: `{str(checks[key]).lower()}`")
    else:
        lines.append("- not_available: `true`")
    lines.extend(
        [
            "",
            "## Reasons",
        ]
    )
    for reason in report["readiness"]["reasons"] or ["none"]:
        lines.append(f"- {reason}")
    lines.extend(
        [
            "",
            "## Safety summary",
            "- read_only: `true`",
            "- mutation_performed: `false`",
            "- recipe_executed: `false`",
            "- dockerfile_modified: `false`",
            "- docker_build_executed: `false`",
            "- docker_compose_mutation_executed: `false`",
            "- docker_prune_executed: `false`",
            "- process_kill_executed: `false`",
            "- service_restart_executed: `false`",
            "",
            "This helper did not modify the Dockerfile and did not execute the recipe.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Emit a read-only Docker01 ownership-fix readiness packet."
    )
    p.add_argument("--dockerfile", required=True, type=Path)
    p.add_argument("--health-json", type=Path)
    p.add_argument("--recipe-script", type=Path)
    p.add_argument("--json", action="store_true")
    p.add_argument("--markdown", action="store_true")
    p.add_argument("--out-json", type=Path)
    p.add_argument("--out-markdown", type=Path)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not (args.json or args.markdown or args.out_json or args.out_markdown):
        print(
            "error: select at least one output mode: "
            "--json, --markdown, --out-json, or --out-markdown",
            file=sys.stderr,
        )
        return 2
    report = build_report(args.dockerfile, args.health_json, args.recipe_script)
    json_text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    md_text = to_markdown(report)
    if args.out_json:
        args.out_json.write_text(json_text, encoding="utf-8")
    if args.out_markdown:
        args.out_markdown.write_text(md_text, encoding="utf-8")
    if args.json:
        print(json_text, end="")
    if args.markdown:
        print(md_text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
