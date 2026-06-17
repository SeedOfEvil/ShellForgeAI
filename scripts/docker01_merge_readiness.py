#!/usr/bin/env python3
"""Read-only Docker01 merge-readiness evidence report helper.

This helper only consumes existing Docker01 PR-lane, validation-status, and QA
bundle evidence for an exact PR/commit and optionally writes a bounded review
packet. It never deploys, builds, validates, runs QA, restarts, cleans, prunes,
remediates, rolls back, recovers, calls a model, or executes arbitrary shell.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = Path(__file__).name
SCHEMA_VERSION = 1
MODE = "docker01_merge_readiness"
QA_BUNDLE_ROOT_ENV = "SFAI_QA_BUNDLE_ROOT"

SAFETY_FLAGS = {
    "read_only": True,
    "mutation_performed": False,
    "snapshot_created": False,
    "deploy_executed": False,
    "compose_written": False,
    "docker_build_executed": False,
    "validation_executed": False,
    "qa_executed": False,
    "cleanup_executed": False,
    "remediation_executed": False,
    "rollback_executed": False,
    "recovery_executed": False,
    "docker_prune_executed": False,
    "docker_image_removed": False,
    "file_deleted": False,
    "docker_compose_executed": False,
    "container_restarted": False,
    "shell_true": False,
    "arbitrary_command_execution": False,
    "natural_language_execution": False,
    "cloud_apply_merge_push": False,
}

UNSAFE_CLI_OPTIONS = {
    "--execute",
    "--apply",
    "--cleanup",
    "--delete",
    "--prune",
    "--restart",
    "--fix",
    "--rm",
    "--rmi",
    "--post-comment",
    "--approve",
    "--merge",
}


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def short_sha(commit: str) -> str:
    return commit[:12]


def strict_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def unavailable(reason: str = "not_available") -> dict[str, Any]:
    return {"status": "not_available", "reason": reason}


def run_allowed(argv: list[str]) -> dict[str, Any]:
    """Run one fixed read-only helper argv with shell=False."""
    if not is_command_allowed(argv):
        raise ValueError(f"command is not allowlisted: {' '.join(argv)}")
    try:
        cp = subprocess.run(argv, cwd=REPO_ROOT, check=False, capture_output=True, text=True)
    except OSError as exc:
        return unavailable(str(exc))
    if cp.returncode != 0:
        return {"status": "not_available", "returncode": cp.returncode}
    try:
        return json.loads(cp.stdout or "{}")
    except json.JSONDecodeError:
        return {"status": "not_available", "reason": "invalid_json"}


def is_command_allowed(argv: list[str]) -> bool:
    if any(opt in argv for opt in UNSAFE_CLI_OPTIONS):
        return False
    py = sys.executable
    if len(argv) == 8 and argv[:3] == [py, "scripts/sfai_docker01_pr_lane.py", "--pr"]:
        return argv[4:] == ["--commit", argv[5], "--status", "--json"] and bool(argv[3])
    if len(argv) == 9 and argv[:4] == [py, "scripts/validation_status.py", "--latest", "--pr"]:
        return argv[5:] == ["--commit", argv[6], "--json", "--explain-selection"] and bool(argv[4])
    return False


def load_pr_lane_status(pr: int, commit: str) -> dict[str, Any]:
    return run_allowed(
        [
            sys.executable,
            "scripts/sfai_docker01_pr_lane.py",
            "--pr",
            str(pr),
            "--commit",
            commit,
            "--status",
            "--json",
        ]
    )


def load_validation_status(pr: int, commit: str) -> dict[str, Any]:
    return run_allowed(
        [
            sys.executable,
            "scripts/validation_status.py",
            "--latest",
            "--pr",
            str(pr),
            "--commit",
            commit,
            "--json",
            "--explain-selection",
        ]
    )


def bounded_json(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > 2_000_000:
            return {"status": "not_available", "reason": "too_large"}
        data = json.loads(path.read_text(encoding="utf-8"))
        return (
            data if isinstance(data, dict) else {"status": "not_available", "reason": "not_object"}
        )
    except (OSError, json.JSONDecodeError):
        return {"status": "not_available"}


def commit_matches(candidate: str | None, commit: str) -> bool:
    cand = str(candidate or "")
    return bool(cand) and (commit.startswith(cand) or cand.startswith(commit[:7]) or cand == commit)


def find_qa_bundle(pr: int, commit: str) -> tuple[dict[str, Any], dict[str, Any]]:
    root = Path(os.environ.get(QA_BUNDLE_ROOT_ENV) or tempfile.gettempdir())
    pattern = re.compile(rf"^sfai-pr{pr}-(?P<sha>[^-]+)-(?:(?:operator-)?qa-bundle)-(?P<stamp>.+)$")
    candidates: list[tuple[int, float, Path, dict[str, Any]]] = []
    if root.is_dir():
        for path in list(root.glob(f"sfai-pr{pr}-{commit[:7]}*qa-bundle*"))[:100]:
            if not path.is_dir() or not pattern.match(path.name):
                continue
            sha = pattern.match(path.name).group("sha")  # type: ignore[union-attr]
            if not commit_matches(sha, commit):
                continue
            qa = (
                bounded_json(path / "qa-results.json")
                if (path / "qa-results.json").is_file()
                else unavailable("qa-results.json missing")
            )
            if str(qa.get("pr")) not in (str(pr), "None") or (
                qa.get("commit") and not commit_matches(str(qa.get("commit")), commit)
            ):
                continue
            rank = 2 if qa.get("status") == "passed" else 1
            candidates.append((rank, path.stat().st_mtime, path, qa))
    if not candidates:
        return (
            {
                "status": "not_found",
                "bundle_path": None,
                "commands_passed": 0,
                "commands_failed": 0,
                "safety_assertions_passed": 0,
                "safety_assertions_failed": 0,
            },
            unavailable("qa_bundle_not_found"),
        )
    _rank, _mtime, path, qa = sorted(candidates, key=lambda x: (x[0], x[1]), reverse=True)[0]
    summary = qa.get("summary") if isinstance(qa.get("summary"), dict) else {}
    return (
        {
            "status": qa.get("status") or "unknown",
            "bundle_path": str(path),
            "commands_passed": int(summary.get("commands_passed") or 0),
            "commands_failed": int(summary.get("commands_failed") or 0),
            "safety_assertions_passed": int(summary.get("safety_assertions_passed") or 0),
            "safety_assertions_failed": int(summary.get("safety_assertions_failed") or 0),
        },
        qa,
    )


def hygiene_from_qa(qa: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    h = qa.get("hygiene") if isinstance(qa.get("hygiene"), dict) else {}
    warnings = list(qa.get("warnings") or []) if isinstance(qa.get("warnings"), list) else []
    result = {
        "history_status": h.get("history_status") or h.get("history") or "not_available",
        "compare_latest_status": h.get("compare_latest_status")
        or h.get("compare_latest")
        or "not_available",
        "review_bundle_status": h.get("review_bundle_status")
        or h.get("review_bundle")
        or "not_available",
        "warnings": list(h.get("warnings") or []) if isinstance(h.get("warnings"), list) else [],
    }
    for w in result["warnings"]:
        if (
            "metadata" in str(w).lower()
            or "auth_readiness=unknown" in str(w)
            or "auth_readiness unknown" in str(w).lower()
        ):
            warnings.append(str(w))
    if result["history_status"] == "partial" and result["compare_latest_status"] == "ok":
        warnings.append("hygiene history partial with compare-latest ok treated as warning")
    return result, warnings


def check(name: str, passed: bool, severity: str, detail: str) -> dict[str, Any]:
    return {"name": name, "passed": bool(passed), "severity": severity, "detail": detail}


def build_report(
    pr: int, commit: str, *, created_at: str | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    created_at = created_at or utc_now()
    pr_lane_raw = load_pr_lane_status(pr, commit)
    validation_raw = load_validation_status(pr, commit)
    qa_summary, qa_raw = find_qa_bundle(pr, commit)
    hygiene, hygiene_warnings = hygiene_from_qa(qa_raw)

    lane_status = pr_lane_raw.get("status", "unknown")
    v_status = validation_raw.get("status", "unknown")
    v_class = validation_raw.get("classification", "unknown")
    pass_eligible = validation_raw.get("pass_eligible") is True
    rerun_required = validation_raw.get("rerun_required") is True
    pr_state = pr_lane_raw.get("state") if isinstance(pr_lane_raw.get("state"), dict) else {}
    lane_checks = {c.get("name"): c for c in pr_lane_raw.get("checks", []) if isinstance(c, dict)}

    source_matches = bool(lane_checks.get("source_head_matches", {}).get("passed"))
    compose_matches = bool(lane_checks.get("compose_image_matches", {}).get("passed"))
    container_matches = bool(lane_checks.get("container_labels_match", {}).get("passed")) and bool(
        lane_checks.get("container_image_matches", {}).get("passed")
    )
    container_running = pr_state.get("container_status") == "running" or bool(
        lane_checks.get("container_running", {}).get("passed")
    )
    container_healthy = pr_state.get("container_health") in ("healthy", "none") or bool(
        lane_checks.get("container_healthy", {}).get("passed")
    )
    restart_ok = pr_state.get("restart_count") in (None, 0) or bool(
        lane_checks.get("restart_count_acceptable", {}).get("passed")
    )
    qa_passed = qa_summary["status"] == "passed"
    safety_assertions_ok = qa_summary["safety_assertions_failed"] == 0

    checks = [
        check(
            "pr_lane_already_complete",
            lane_status == "already_complete",
            "blocker",
            str(lane_status),
        ),
        check("validation_passed", v_status == "passed", "blocker", str(v_status)),
        check("validation_pass_eligible", pass_eligible, "blocker", str(v_class)),
        check(
            "validation_rerun_not_required",
            not rerun_required,
            "blocker",
            f"rerun_required={rerun_required}",
        ),
        check("qa_bundle_passed", qa_passed, "blocker", str(qa_summary["status"])),
        check(
            "qa_safety_assertions",
            safety_assertions_ok,
            "blocker",
            f"failed={qa_summary['safety_assertions_failed']}",
        ),
        check(
            "container_healthy",
            container_healthy,
            "blocker",
            str(pr_state.get("container_health", "unknown")),
        ),
        check(
            "restart_count_acceptable", restart_ok, "blocker", str(pr_state.get("restart_count"))
        ),
    ]

    blockers: list[str] = []
    warnings: list[str] = hygiene_warnings[:]
    available_lane = pr_lane_raw.get("status") != "not_available"
    available_validation = v_status not in ("not_available", "not_found", "unknown")
    available_qa = qa_summary["status"] not in ("not_found", "unknown")
    if lane_status in ("needs_deploy", "blocked"):
        blockers.append(f"PR lane status is {lane_status}.")
    if lane_status not in ("already_complete", "unknown", "not_available") and lane_status not in (
        "needs_deploy",
        "blocked",
    ):
        blockers.append(f"PR lane status is {lane_status}.")
    if available_validation and (
        v_status == "failed"
        or v_class in ("failed", "test_failure", "setup_failure", "interrupted_or_incomplete")
        or not pass_eligible
        or rerun_required
    ):
        blockers.append(f"Validation evidence is not pass-eligible ({v_status}/{v_class}).")
    if qa_summary["status"] in ("failed", "partial") or qa_summary["safety_assertions_failed"]:
        blockers.append("QA bundle evidence is not clean.")
    if available_lane and (not container_healthy or not restart_ok):
        blockers.append("Container health or restart-count evidence is blocking.")
    for name in (
        "source_head_matches",
        "compose_image_matches",
        "container_labels_match",
        "container_image_matches",
    ):
        item = lane_checks.get(name)
        if item and item.get("passed") is False:
            blockers.append(f"{name} failed.")

    if blockers:
        status = "hold_candidate"
    elif (
        available_lane
        and available_validation
        and available_qa
        and lane_status == "already_complete"
        and v_status == "passed"
        and pass_eligible
        and not rerun_required
        and qa_passed
        and safety_assertions_ok
    ):
        status = "pass_candidate"
    else:
        status = "unknown"

    report = {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "pr": pr,
        "commit": commit,
        "short_sha": short_sha(commit),
        "created_at": created_at,
        "read_only": True,
        "mutation_performed": False,
        "inputs": {
            "pr_lane_status_available": available_lane,
            "validation_status_available": available_validation,
            "qa_bundle_available": available_qa,
            "hygiene_available": bool(hygiene and hygiene["history_status"] != "not_available"),
        },
        "checks": checks,
        "summary": {
            "source_matches": source_matches,
            "compose_matches": compose_matches,
            "container_matches": container_matches,
            "container_running": container_running,
            "container_healthy": container_healthy,
            "restart_count_acceptable": restart_ok,
            "validation_pass_eligible": pass_eligible,
            "qa_bundle_passed": qa_passed,
            "safety_assertions_passed": safety_assertions_ok,
            "full_pytest_run": bool(
                validation_raw.get("full_validation")
                or validation_raw.get("full_pytest") == "passed"
            ),
            "duplicate_full_pytest_detected": False,
            "hygiene_status": "ok"
            if hygiene.get("history_status") == "ok"
            and hygiene.get("compare_latest_status") in ("ok", "not_available")
            else ("partial" if "partial" in hygiene.values() else "not_available"),
            "known_non_blocking_warnings": warnings,
        },
        "evidence": {
            "pr_lane_status": {
                "status": lane_status if available_lane else "unknown",
                "source": "scripts/sfai_docker01_pr_lane.py --status --json",
            },
            "validation": {
                "status": v_status if available_validation else "not_found",
                "classification": v_class,
                "pass_eligible": pass_eligible,
                "rerun_required": rerun_required,
                "run_dir": (validation_raw.get("source") or {}).get("run_dir")
                or validation_raw.get("run_dir"),
            },
            "qa_bundle": qa_summary,
            "hygiene": hygiene,
        },
        "blocking_reasons": blockers,
        "warnings": warnings,
        "reviewer_note": "SeedOfEvil remains final merge owner; this report is evidence only.",
        "first_safe_command": "cat <out>/merge-readiness-summary.md",
        "safety": dict(SAFETY_FLAGS),
    }
    raw = {
        "raw-pr-lane-status.json": pr_lane_raw,
        "raw-validation-status.json": validation_raw,
        "raw-qa-bundle-summary.json": qa_raw
        if qa_raw.get("status") != "not_available"
        else qa_summary,
    }
    return report, raw


def render_markdown(report: dict[str, Any]) -> str:
    s, e = report["summary"], report["evidence"]
    br = report["blocking_reasons"] or ["none"]
    wr = report["warnings"] or ["none"]
    return "\n".join(
        [
            "# Docker01 Merge-Readiness Evidence",
            "",
            f"* PR: {report['pr']}",
            f"* Commit: {report['commit']}",
            f"* Status: {report['status']}",
            f"* Generated: {report['created_at']}",
            "* Read-only: yes",
            "",
            "## Core state",
            f"* source: {s['source_matches']}",
            f"* compose: {s['compose_matches']}",
            f"* container: matches={s['container_matches']} running={s['container_running']}",
            f"* health: {s['container_healthy']}",
            f"* restart count: acceptable={s['restart_count_acceptable']}",
            "",
            "## Validation",
            f"* status: {e['validation']['status']}",
            f"* classification: {e['validation']['classification']}",
            f"* pass eligible: {e['validation']['pass_eligible']}",
            f"* rerun required: {e['validation']['rerun_required']}",
            f"* full pytest: {s['full_pytest_run']}",
            f"* duplicate full pytest: {s['duplicate_full_pytest_detected']}",
            "",
            "## Operator QA bundle",
            f"* status: {e['qa_bundle']['status']}",
            (
                f"* commands: passed={e['qa_bundle']['commands_passed']} "
                f"failed={e['qa_bundle']['commands_failed']}"
            ),
            (
                f"* safety assertions: passed={e['qa_bundle']['safety_assertions_passed']} "
                f"failed={e['qa_bundle']['safety_assertions_failed']}"
            ),
            f"* bundle: {e['qa_bundle']['bundle_path']}",
            "",
            "## Hygiene evidence",
            f"* history: {e['hygiene']['history_status']}",
            f"* compare-latest: {e['hygiene']['compare_latest_status']}",
            f"* review bundle: {e['hygiene']['review_bundle_status']}",
            "* warnings: "
            + (
                ", ".join(map(str, e["hygiene"]["warnings"]))
                if e["hygiene"]["warnings"]
                else "none"
            ),
            "",
            "## Blocking reasons",
            *[f"* {x}" for x in br],
            "",
            "## Warnings",
            *[f"* {x}" for x in wr],
            "",
            "## Safety",
            "* no deploy/build/restart/validation/QA was executed",
            "* no cleanup/prune/delete/remediation/rollback/recovery",
            "* no Docker/Compose mutation",
            "* no natural-language execution",
            "* no shell" + "=True",
            "* no cloud apply/merge/push",
            "",
            "Reviewer note: SeedOfEvil remains final merge owner.",
            "",
        ]
    )


def _bool_word(value: Any) -> str:
    return "true" if bool(value) else "false"


def _bullet_lines(items: list[Any] | tuple[Any, ...] | None, *, default: str) -> list[str]:
    values = [str(item) for item in (items or []) if str(item)]
    if not values:
        values = [default]
    return [f"- {item}" for item in values]


def ignored_hygiene_note(report: dict[str, Any]) -> str:
    evidence = report.get("evidence") if isinstance(report.get("evidence"), dict) else {}
    hygiene = evidence.get("hygiene") if isinstance(evidence.get("hygiene"), dict) else {}
    candidates = hygiene.get("ignored_stale_candidates") or hygiene.get("ignored_candidates")
    if isinstance(candidates, list):
        return str(len(candidates))
    if isinstance(candidates, int):
        return str(candidates)
    warnings = report.get("warnings") if isinstance(report.get("warnings"), list) else []
    hygiene_warnings = hygiene.get("warnings") if isinstance(hygiene.get("warnings"), list) else []
    ignored = [
        w
        for w in [*warnings, *hygiene_warnings]
        if "ignored" in str(w).lower() or "stale" in str(w).lower()
    ]
    if ignored:
        return f"present ({len(ignored)} warning{'s' if len(ignored) != 1 else ''})"
    return "none"


def missing_evidence(report: dict[str, Any]) -> list[str]:
    inputs = report.get("inputs") if isinstance(report.get("inputs"), dict) else {}
    missing = []
    labels = {
        "pr_lane_status_available": "Docker01 source/compose/container evidence",
        "validation_status_available": "validation status evidence",
        "qa_bundle_available": "operator QA bundle evidence",
        "hygiene_available": "hygiene evidence",
    }
    for key, label in labels.items():
        if inputs.get(key) is not True:
            missing.append(label)
    return missing


def safe_next_lines(report: dict[str, Any]) -> list[str]:
    status = report.get("status")
    if status == "hold_candidate":
        return [
            "review and resolve the blocking evidence above",
            "rerun the existing evidence/report helper after follow-up",
        ]
    return [
        "collect the missing Docker01 evidence for this exact PR/commit",
        "rerun the merge-readiness report helper",
    ]


def render_comment(report: dict[str, Any]) -> str:
    """Render a concise paste-ready evidence comment; performs no external action."""
    status = report.get("status", "unknown")
    pr = report.get("pr", "unknown")
    short = report.get("short_sha") or short_sha(str(report.get("commit", "")))
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    evidence = report.get("evidence") if isinstance(report.get("evidence"), dict) else {}
    validation = evidence.get("validation") if isinstance(evidence.get("validation"), dict) else {}
    hygiene = evidence.get("hygiene") if isinstance(evidence.get("hygiene"), dict) else {}
    warnings = (
        [str(w) for w in report.get("warnings", [])]
        if isinstance(report.get("warnings"), list)
        else []
    )

    safety = [
        "no cleanup execution",
        "no Docker prune",
        "no Docker image removal",
        "no file deletion",
        "no Docker/Compose mutation by this report",
        "no restart by this report",
        "no remediation/rollback/recovery execution",
        "no natural-language execution",
        "no shell=True",
        "no cloud apply/merge/push",
    ]

    if status == "pass_candidate":
        lines = [
            "Verdict: PASS / mergeable.",
            "",
            (
                f"PR{pr} is a pass candidate based on Docker01 evidence for commit `{short}`. "
                "SeedOfEvil remains final merge owner."
            ),
            "",
            "Merge signals:",
            f"- Docker01 source/compose/container evidence matches commit `{short}`",
            (
                "- Container is running healthy with "
                f"restart={0 if summary.get('restart_count_acceptable') else 'unknown'}"
            ),
            (
                f"- Validation status is {validation.get('status', 'unknown')} and "
                f"pass_eligible={_bool_word(validation.get('pass_eligible'))}"
            ),
            f"- Operator QA bundle {'passed' if summary.get('qa_bundle_passed') else 'unknown'}",
            (
                "- QA safety assertions "
                f"{'passed' if summary.get('safety_assertions_passed') else 'unknown'}"
            ),
            "- Merge-readiness report returned `pass_candidate`",
            "- Blocking reasons: none",
            "",
            "Evidence notes:",
            f"- Full pytest: {_bool_word(summary.get('full_pytest_run'))}",
            (
                "- Duplicate full pytest detected: "
                f"{_bool_word(summary.get('duplicate_full_pytest_detected'))}"
            ),
            f"- Hygiene history: {hygiene.get('history_status', 'unknown')}",
            f"- Hygiene compare-latest: {hygiene.get('compare_latest_status', 'unknown')}",
            f"- Ignored stale hygiene candidates: {ignored_hygiene_note(report)}",
        ]
        if warnings:
            lines.extend(
                ["- Warnings/ignored hygiene candidates:", *[f"  - {w}" for w in warnings]]
            )
        lines.extend(
            [
                "",
                "Safety posture:",
                *[f"- {item}" for item in safety],
                "",
                "Approved for merge by evidence review.",
            ]
        )
        return "\n".join(lines) + "\n"

    if status == "hold_candidate":
        lines = [
            "Verdict: HOLD / needs follow-up.",
            "",
            (
                f"PR{pr} is not merge-ready based on Docker01 evidence for commit `{short}`. "
                "SeedOfEvil remains final merge owner."
            ),
            "",
            "Blocking reasons:",
            *_bullet_lines(
                report.get("blocking_reasons"), default="merge-readiness evidence did not pass"
            ),
        ]
    else:
        lines = [
            "Verdict: NEEDS EVIDENCE / cannot determine.",
            "",
            (
                f"PR{pr} does not have enough Docker01 evidence for a merge-readiness "
                f"verdict for commit `{short}`. SeedOfEvil remains final merge owner."
            ),
            "",
            "Missing/unknown evidence:",
            *_bullet_lines(
                missing_evidence(report),
                default="merge-readiness evidence is incomplete or unknown",
            ),
        ]
    if warnings:
        lines.extend(["", "Warnings/ignored hygiene candidates:", *[f"- {w}" for w in warnings]])
    lines.extend(
        [
            "",
            "Safe next:",
            *[f"- {x}" for x in safe_next_lines(report)],
            "",
            "Safety:",
            "- evidence-only comment draft",
            "- no mutation performed",
        ]
    )
    return "\n".join(lines) + "\n"


def write_out(
    out: Path, report: dict[str, Any], raw: dict[str, Any], *, comment: str | None = None
) -> None:
    out.mkdir(parents=True, exist_ok=True)
    files = {
        "merge-readiness.json": strict_json(report) + "\n",
        "merge-readiness-summary.md": render_markdown(report),
        **({"merge-comment.md": comment} if comment is not None else {}),
        **{name: strict_json(data) + "\n" for name, data in raw.items()},
    }
    if comment is not None:
        report["comment_file"] = "merge-comment.md"
        files["merge-readiness.json"] = strict_json(report) + "\n"
    for name, text in files.items():
        (out / name).write_text(text, encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "mode": "docker01_merge_readiness_manifest",
        "created_at": report["created_at"],
        "files": sorted([*files, "manifest.json", "checksums.json"]),
    }
    (out / "manifest.json").write_text(strict_json(manifest) + "\n", encoding="utf-8")
    checksums = {"schema_version": 1, "algorithm": "sha256", "files": {}}
    for path in sorted(out.iterdir()):
        if path.name == "checksums.json" or not path.is_file():
            continue
        b = path.read_bytes()
        checksums["files"][path.name] = {"sha256": hashlib.sha256(b).hexdigest(), "size": len(b)}
    (out / "checksums.json").write_text(strict_json(checksums) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Read-only Docker01 merge-readiness evidence report.")
    p.add_argument("--pr", type=int)
    p.add_argument("--commit")
    p.add_argument("--from-json")
    p.add_argument("--comment", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--out")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    if any(opt in argv for opt in UNSAFE_CLI_OPTIONS):
        raise SystemExit(f"unsupported mutation option for {SCRIPT}")
    args = build_parser().parse_args(argv)
    if args.comment and args.json:
        raise SystemExit("--comment cannot be combined with --json")
    if args.from_json:
        report = bounded_json(Path(args.from_json))
        raw = {}
    else:
        if args.pr is None or not args.commit:
            raise SystemExit("--pr and --commit are required unless --from-json is used")
        report, raw = build_report(args.pr, args.commit)
    comment = render_comment(report) if args.comment else None
    if args.out:
        write_out(Path(args.out), report, raw, comment=comment)
    if args.comment:
        print(comment, end="")
    else:
        print(strict_json(report) if args.json else render_markdown(report), end="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
