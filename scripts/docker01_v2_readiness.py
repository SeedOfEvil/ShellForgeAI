#!/usr/bin/env python3
"""Read-only Docker01 V2-readiness evidence snapshot helper.

Consumes only existing Docker01 evidence for an exact PR/commit and optionally
writes a bounded report packet. It never deploys, builds, validates, runs QA,
runs pytest, restarts, cleans, prunes, remediates, rolls back, recovers, posts to
GitHub, calls a model, or executes arbitrary shell.
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
MODE = "docker01_v2_readiness"
QA_BUNDLE_ROOT_ENV = "SFAI_QA_BUNDLE_ROOT"

SAFETY_FLAGS = {
    "read_only": True,
    "mutation_performed": False,
    "snapshot_created": False,
    "deploy_executed": False,
    "compose_written": False,
    "docker_build_executed": False,
    "validation_executed": False,
    "pytest_executed": False,
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
    "natural_language_execution": False,
    "shell_true": False,
    "cloud_apply_merge_push": False,
    "github_post_approve_merge": False,
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


def is_command_allowed(argv: list[str]) -> bool:
    if any(opt in argv for opt in UNSAFE_CLI_OPTIONS):
        return False
    py = sys.executable
    if len(argv) == 8 and argv[:3] == [py, "scripts/sfai_docker01_pr_lane.py", "--pr"]:
        return argv[4:] == ["--commit", argv[5], "--status", "--json"] and bool(argv[3])
    if len(argv) == 9 and argv[:4] == [py, "scripts/validation_status.py", "--latest", "--pr"]:
        return argv[5:] == ["--commit", argv[6], "--json", "--explain-selection"] and bool(argv[4])
    if len(argv) == 7 and argv[:3] == [py, "scripts/docker01_merge_readiness.py", "--pr"]:
        return argv[4:] == ["--commit", argv[5], "--json"] and bool(argv[3])
    return False


def run_allowed(argv: list[str]) -> dict[str, Any]:
    if not is_command_allowed(argv):
        raise ValueError(f"command is not allowlisted: {' '.join(argv)}")
    try:
        cp = subprocess.run(argv, cwd=REPO_ROOT, check=False, capture_output=True, text=True)
    except OSError as exc:
        return unavailable(str(exc))
    if cp.returncode != 0:
        return {"status": "not_available", "returncode": cp.returncode}
    try:
        data = json.loads(cp.stdout or "{}")
    except json.JSONDecodeError:
        return unavailable("invalid_json")
    return data if isinstance(data, dict) else unavailable("not_object")


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


def load_merge_readiness(pr: int, commit: str) -> dict[str, Any]:
    return run_allowed(
        [
            sys.executable,
            "scripts/docker01_merge_readiness.py",
            "--pr",
            str(pr),
            "--commit",
            commit,
            "--json",
        ]
    )


def bounded_json(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > 2_000_000:
            return unavailable("too_large")
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else unavailable("not_object")
    except (OSError, json.JSONDecodeError):
        return unavailable()


def commit_matches(candidate: str | None, commit: str) -> bool:
    cand = str(candidate or "")
    return bool(cand) and (cand == commit or commit.startswith(cand) or cand.startswith(commit[:7]))


def _candidate_qa_dirs(root: Path, pr: int, commit: str) -> list[Path]:
    """Return bounded exact PR/commit QA bundle directory candidates.

    Supports both the original flat bundle names and the Docker01 convergence
    layout:
    ``sfai-pr<PR>-<short>-convergence-<stamp>/operator-qa``.
    """
    direct = list(root.glob(f"sfai-pr{pr}-{commit[:7]}*qa-bundle*"))[:100]
    nested = list(root.glob(f"sfai-pr{pr}-{commit[:7]}*convergence*/operator-qa"))[:100]
    return [path for path in [*direct, *nested] if path.is_dir()]


def _qa_dir_matches(path: Path, pr: int, commit: str) -> bool:
    direct = re.compile(rf"^sfai-pr{pr}-(?P<sha>[^-]+)-(?:(?:operator-)?qa-bundle)-(?P<stamp>.+)$")
    convergence = re.compile(rf"^sfai-pr{pr}-(?P<sha>[^-]+)-convergence-(?P<stamp>.+)$")
    if path.name == "operator-qa":
        match = convergence.match(path.parent.name)
    else:
        match = direct.match(path.name)
    return bool(match and commit_matches(match.group("sha"), commit))


def find_qa_bundle(pr: int, commit: str) -> tuple[dict[str, Any], dict[str, Any]]:
    root = Path(os.environ.get(QA_BUNDLE_ROOT_ENV) or tempfile.gettempdir())
    candidates: list[tuple[int, float, Path, dict[str, Any]]] = []
    if root.is_dir():
        for path in _candidate_qa_dirs(root, pr, commit):
            if not _qa_dir_matches(path, pr, commit):
                continue
            qa = (
                bounded_json(path / "qa-results.json")
                if (path / "qa-results.json").is_file()
                else unavailable("qa-results.json missing")
            )
            if str(qa.get("pr")) not in (str(pr), "None"):
                continue
            if qa.get("commit") and not commit_matches(str(qa.get("commit")), commit):
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
                "failing_commands": [],
            },
            unavailable("qa_bundle_not_found"),
        )
    _rank, _mtime, path, qa = sorted(candidates, key=lambda x: (x[0], x[1]), reverse=True)[0]
    summary = qa.get("summary") if isinstance(qa.get("summary"), dict) else {}
    commands = qa.get("commands") if isinstance(qa.get("commands"), list) else []
    failing_commands = [
        str(item.get("key") or item.get("label") or item.get("raw_file"))
        for item in commands
        if isinstance(item, dict) and item.get("status") == "failed"
    ]
    return (
        {
            "status": qa.get("status") or "unknown",
            "bundle_path": str(path),
            "commands_passed": int(summary.get("commands_passed") or 0),
            "commands_failed": int(summary.get("commands_failed") or 0),
            "safety_assertions_passed": int(summary.get("safety_assertions_passed") or 0),
            "safety_assertions_failed": int(summary.get("safety_assertions_failed") or 0),
            "failing_commands": failing_commands,
        },
        qa,
    )


def _hygiene_source(qa: dict[str, Any], merge: dict[str, Any]) -> dict[str, Any]:
    qh = qa.get("hygiene") if isinstance(qa.get("hygiene"), dict) else {}
    me = merge.get("evidence") if isinstance(merge.get("evidence"), dict) else {}
    mh = me.get("hygiene") if isinstance(me.get("hygiene"), dict) else {}
    return qh or mh


def hygiene_summary(qa: dict[str, Any], merge: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    h = _hygiene_source(qa, merge)
    warnings = []
    for source in (qa, h, merge):
        values = source.get("warnings") if isinstance(source, dict) else None
        if isinstance(values, list):
            warnings.extend(str(v) for v in values if str(v))
    for key in ("ignored_stale_candidates", "ignored_candidates"):
        if h.get(key):
            warnings.append("hygiene ignored stale/non-report candidates")
    return (
        {
            "history_status": str(h.get("history_status") or h.get("history") or "not_available"),
            "compare_latest_status": str(
                h.get("compare_latest_status") or h.get("compare_latest") or "not_available"
            ),
        },
        warnings,
    )


def check(name: str, passed: bool, severity: str, detail: str) -> dict[str, Any]:
    return {"name": name, "passed": bool(passed), "severity": severity, "detail": detail}


def _lane_check(lane: dict[str, Any], name: str) -> Any:
    for c in lane.get("checks", []):
        if isinstance(c, dict) and c.get("name") == name:
            return c.get("passed")
    return None


def build_report(
    pr: int, commit: str, *, created_at: str | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    created_at = created_at or utc_now()
    lane = load_pr_lane_status(pr, commit)
    validation = load_validation_status(pr, commit)
    merge = load_merge_readiness(pr, commit)
    qa_summary, qa_raw = find_qa_bundle(pr, commit)
    hygiene, hygiene_warnings = hygiene_summary(qa_raw, merge)

    state = lane.get("state") if isinstance(lane.get("state"), dict) else {}
    source_matches = _lane_check(lane, "source_head_matches") is True
    compose_matches = _lane_check(lane, "compose_image_matches") is True
    container_matches = (
        _lane_check(lane, "container_labels_match") is True
        and _lane_check(lane, "container_image_matches") is True
    )
    container_running = (
        state.get("container_status") == "running" or _lane_check(lane, "container_running") is True
    )
    container_healthy = (
        state.get("container_health") in ("healthy", "none")
        or _lane_check(lane, "container_healthy") is True
    )
    restart_ok = (
        state.get("restart_count") in (None, 0)
        or _lane_check(lane, "restart_count_acceptable") is True
    )
    pass_eligible = validation.get("pass_eligible") is True
    rerun_required = validation.get("rerun_required") is True
    v_status = str(validation.get("status") or "unknown")
    v_class = str(validation.get("classification") or "unknown")
    qa_passed = qa_summary["status"] == "passed"
    qa_safety_ok = qa_summary["safety_assertions_failed"] == 0
    merge_status = str(merge.get("status") or "unknown")
    full_pytest = bool(
        validation.get("full_validation")
        or validation.get("full_pytest") == "passed"
        or (validation.get("qa_marker") or {}).get("full_pytest_run") is True
    )
    duplicate_full = bool(
        validation.get("duplicate_full_pytest_detected")
        or (merge.get("summary") or {}).get("duplicate_full_pytest_detected")
    )

    summary = {
        "source_matches": source_matches,
        "compose_matches": compose_matches,
        "container_matches": container_matches,
        "container_running": container_running,
        "container_healthy": container_healthy,
        "restart_count_acceptable": restart_ok,
        "validation_pass_eligible": pass_eligible,
        "validation_rerun_required": rerun_required,
        "qa_bundle_passed": qa_passed,
        "qa_safety_assertions_passed": qa_safety_ok,
        "merge_readiness_status": merge_status
        if merge_status in ("pass_candidate", "hold_candidate")
        else "unknown",
        "full_pytest_run": full_pytest,
        "duplicate_full_pytest_detected": duplicate_full,
        "hygiene_history_status": hygiene["history_status"],
        "hygiene_compare_latest_status": hygiene["compare_latest_status"],
        "known_non_blocking_warnings": hygiene_warnings,
    }
    checks = [
        check(
            "docker01_state_matches_commit",
            source_matches and compose_matches and container_matches,
            "blocker",
            "source/compose/container must match requested commit",
        ),
        check(
            "container_running",
            container_running,
            "blocker",
            str(state.get("container_status", "unknown")),
        ),
        check(
            "container_healthy",
            container_healthy,
            "blocker",
            str(state.get("container_health", "unknown")),
        ),
        check("restart_count_acceptable", restart_ok, "blocker", str(state.get("restart_count"))),
        check("validation_passed", v_status == "passed", "blocker", v_status),
        check("validation_pass_eligible", pass_eligible, "blocker", v_class),
        check(
            "validation_rerun_not_required",
            not rerun_required,
            "blocker",
            f"rerun_required={rerun_required}",
        ),
        check("qa_bundle_passed", qa_passed, "blocker", str(qa_summary["status"])),
        check(
            "qa_safety_assertions_passed",
            qa_safety_ok,
            "blocker",
            f"failed={qa_summary['safety_assertions_failed']}",
        ),
        check(
            "merge_readiness_pass_candidate",
            merge_status == "pass_candidate",
            "blocker",
            merge_status,
        ),
    ]
    blockers: list[str] = []
    missing: list[str] = []
    explicit_fail = False
    if lane.get("status") == "not_available":
        missing.append("Docker01 PR-lane evidence is unavailable.")
    if v_status in ("not_available", "not_found", "unknown"):
        missing.append("Exact PR/commit validation evidence is unavailable.")
        missing.append(
            "V2 readiness cannot be determined until validation evidence is discoverable."
        )
    if qa_summary["status"] in ("not_found", "unknown"):
        missing.append("Operator QA bundle evidence is unavailable for the exact PR/commit.")
    if merge_status in ("not_available", "unknown"):
        missing.append("Merge-readiness evidence is unavailable for the exact PR/commit.")
    for _name, ok, text in [
        ("source", source_matches, "Source evidence does not match requested commit."),
        ("compose", compose_matches, "Compose evidence does not match requested commit."),
        (
            "container",
            container_matches,
            "Container image/label evidence does not match requested commit.",
        ),
        ("running", container_running, "Container is not running."),
        ("healthy", container_healthy, "Container is unhealthy."),
        ("restart", restart_ok, "Restart count is not acceptable."),
    ]:
        if lane.get("status") != "not_available" and not ok:
            explicit_fail = True
            blockers.append(text)
    if (
        v_status == "failed"
        or v_class in ("failed", "test_failure", "setup_failure", "interrupted_or_incomplete")
        or (
            v_status not in ("not_available", "not_found", "unknown")
            and (not pass_eligible or rerun_required)
        )
    ):
        explicit_fail = True
        blockers.append(f"Validation evidence is not pass-eligible ({v_status}/{v_class}).")
    if qa_summary["status"] in ("failed", "partial") or qa_summary["safety_assertions_failed"]:
        explicit_fail = True
        failing = qa_summary.get("failing_commands") or []
        suffix = f" Failing commands: {', '.join(map(str, failing))}." if failing else ""
        blockers.append(f"Operator QA bundle or safety assertions failed.{suffix}")
    if merge_status == "hold_candidate":
        if missing:
            missing.append(
                "Merge-readiness is hold_candidate because required evidence is incomplete."
            )
        else:
            explicit_fail = True
            blockers.append("Merge-readiness is hold_candidate.")
    if any(
        report_flag is True for key, report_flag in SAFETY_FLAGS.items() if key not in {"read_only"}
    ):
        explicit_fail = True
        blockers.append("Mutation safety drift detected.")

    if blockers:
        status = "v2_not_ready"
    elif not missing and all(c["passed"] for c in checks):
        status = "v2_candidate"
    elif explicit_fail:
        status = "v2_not_ready"
    else:
        status = "v2_unknown"

    if not blockers and status == "v2_unknown":
        blockers = []
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
        "summary": summary,
        "evidence": {
            "validation": {
                "status": v_status,
                "classification": v_class,
                "pass_eligible": pass_eligible,
                "rerun_required": rerun_required,
                "full_validation": bool(validation.get("full_validation")),
                "full_pytest": validation.get("full_pytest"),
                "duplicate_full_pytest_detected": bool(
                    validation.get("duplicate_full_pytest_detected")
                ),
                "run_dir": (validation.get("source") or {}).get("run_dir")
                if isinstance(validation.get("source"), dict)
                else validation.get("run_dir"),
            },
            "qa_bundle": qa_summary,
            "merge_readiness": {
                "status": summary["merge_readiness_status"],
                "blocking_reasons": list(merge.get("blocking_reasons") or [])
                if isinstance(merge.get("blocking_reasons"), list)
                else [],
            },
        },
        "v2_checks": checks,
        "blocking_reasons": blockers,
        "warnings": hygiene_warnings + missing,
        "reviewer_note": "SeedOfEvil remains final merge owner; this report is evidence only.",
        "first_safe_command": "cat <out>/v2-readiness-summary.md",
        "safety": dict(SAFETY_FLAGS),
    }
    return report, {
        "raw-validation-status.json": validation,
        "raw-pr-lane-status.json": lane,
        "raw-merge-readiness.json": merge,
        "raw-qa-bundle-summary.json": qa_raw
        if qa_raw.get("status") != "not_available"
        else qa_summary,
    }


def render_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    blockers = report["blocking_reasons"] or ["none"]
    warnings = report["warnings"] or ["none"]
    return "\n".join(
        [
            "# Docker01 V2 Readiness Evidence",
            "",
            f"* PR: {report['pr']}",
            f"* Commit: {report['commit']}",
            f"* Status: {report['status']}",
            f"* Generated: {report['created_at']}",
            "* Read-only: yes",
            "",
            "## Core Docker01 state",
            f"* source: {s['source_matches']}",
            f"* compose: {s['compose_matches']}",
            f"* container image: matches={s['container_matches']}",
            f"* labels: matches={s['container_matches']}",
            f"* health: running={s['container_running']} healthy={s['container_healthy']}",
            f"* restart count: acceptable={s['restart_count_acceptable']}",
            "",
            "## Evidence chain",
            (
                f"* validation: pass_eligible={s['validation_pass_eligible']} "
                f"rerun_required={s['validation_rerun_required']} "
                f"full_pytest={s['full_pytest_run']}"
            ),
            "* PR lane status: consumed",
            (
                f"* operator QA bundle: passed={s['qa_bundle_passed']} "
                f"safety={s['qa_safety_assertions_passed']}"
            ),
            f"* merge-readiness: {s['merge_readiness_status']}",
            f"* hygiene history: {s['hygiene_history_status']}",
            f"* hygiene compare-latest: {s['hygiene_compare_latest_status']}",
            "",
            "## V2 blockers",
            *[f"* {x}" for x in blockers],
            "",
            "## V2 warnings",
            *[f"* {x}" for x in warnings],
            "",
            "## Safety",
            "* no deploy/build/restart/validation/QA was executed by this report",
            "* no cleanup/prune/delete/remediation/rollback/recovery",
            "* no Docker/Compose mutation",
            "* no natural-language execution",
            "* no shell" + "=True",
            "* no GitHub post/approve/merge",
            "* no cloud apply/merge/push",
            "",
            "Reviewer note: SeedOfEvil remains final merge owner.",
            "",
        ]
    )


def write_out(out: Path, report: dict[str, Any], raw: dict[str, Any]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    files = {
        "v2-readiness.json": strict_json(report) + "\n",
        "v2-readiness-summary.md": render_markdown(report),
        **{name: strict_json(data) + "\n" for name, data in raw.items()},
    }
    for name, text in files.items():
        (out / name).write_text(text, encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "mode": "docker01_v2_readiness_manifest",
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
    p = argparse.ArgumentParser(description="Read-only Docker01 V2 readiness evidence snapshot.")
    p.add_argument("--pr", type=int, required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--json", action="store_true")
    p.add_argument("--out")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    if any(opt in argv for opt in UNSAFE_CLI_OPTIONS):
        raise SystemExit(f"unsupported mutation option for {SCRIPT}")
    args = build_parser().parse_args(argv)
    report, raw = build_report(args.pr, args.commit)
    if args.out:
        write_out(Path(args.out), report, raw)
    print(strict_json(report) if args.json else render_markdown(report), end="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
