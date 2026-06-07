#!/usr/bin/env python3
"""ShellForgeAI validation lane optimizer (PR157).

Read-only planning helper. Given a set of changed files, recommend a
validation *lane* (fast / targeted_runtime / full), the regression tests that
should run, the exact commands to run, and an explicit answer to the question
"is full pytest required, and why?".

The goal is faster validation with explicit confidence, not weaker safety:
targeted validation becomes the default and full pytest becomes exceptional,
while safety/execution-boundary changes still escalate to full.

Safety posture (hard rules):
  * This helper NEVER mutates anything. It does not run Docker, Compose,
    cleanup, remediation, rollback, restart, prune, or any production action.
  * By default it only PLANS (dry-run). It does not run any tests.
  * It only runs commands when the operator explicitly passes --execute, and
    even then it only runs the recommended read-only validation commands
    (ruff / compileall / pytest) from a fixed allowlist. It never uses a shell
    and never runs arbitrary commands.

Examples:
  python scripts/validate_pr.py --changed-files docs/cli.md
  python scripts/validate_pr.py --changed-files src/shellforgeai/core/ask_routing.py --pr 156
  python scripts/validate_pr.py --base main --head HEAD --json
  python scripts/validate_pr.py --profile full --pr 157
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

HELPER_DIR = Path(__file__).resolve().parent
REPO_ROOT = HELPER_DIR.parent
DEFAULT_MATRIX = HELPER_DIR / "validation_matrix.json"
FULL_PYTEST_RUNNER = "python scripts/run_full_pytest.py"

LANE_ORDER = {"fast": 0, "targeted_runtime": 1, "full": 2}
LANE_LETTER = {"fast": "A", "targeted_runtime": "B", "full": "C"}
RUNTIME_CLASS = {"fast": "short", "targeted_runtime": "medium", "full": "long"}

# Profile aliases the operator may pass on the CLI.
PROFILE_ALIASES = {
    "auto": "auto",
    "fast": "fast",
    "targeted": "targeted_runtime",
    "targeted_runtime": "targeted_runtime",
    "full": "full",
}

# Command display strings use the canonical short forms from the runbook
# (e.g. "python -m compileall ..."); argv uses the current interpreter so
# --execute stays robust in minimal containers.
PY_EXEC = sys.executable or "python3"

# --execute will only ever launch these binaries (defence in depth; argv is
# always constructed by this module, never taken from user input).
ALLOWED_EXEC_BASENAMES = {
    "python",
    "python3",
    "ruff",
    "pytest",
    os.path.basename(PY_EXEC),
}

_GLOB_CHARS = set("*?[]")


# --------------------------------------------------------------------------- #
# Glob matching (supports ** across path separators)
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1024)
def _compile_glob(pattern: str) -> re.Pattern[str]:
    out = ["^"]
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                i += 2
                if i < n and pattern[i] == "/":
                    out.append("(?:.*/)?")  # **/ -> zero or more path segments
                    i += 1
                else:
                    out.append(".*")  # ** -> anything, including separators
            else:
                out.append("[^/]*")  # * -> anything within one path segment
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    out.append("$")
    return re.compile("".join(out))


def _glob_match(pattern: str, path: str) -> bool:
    return _compile_glob(pattern).match(path) is not None


def _norm(path: str) -> str:
    if not path:
        return path
    p = path.replace(os.sep, "/")
    while p.startswith("./"):  # strip a leading ./ prefix without touching dotfiles
        p = p[2:]
    return p


# --------------------------------------------------------------------------- #
# Matrix loading
# --------------------------------------------------------------------------- #
def load_matrix(path: str | os.PathLike[str] | None = None) -> dict:
    matrix_path = Path(path) if path else DEFAULT_MATRIX
    with open(matrix_path, encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# Classification helpers
# --------------------------------------------------------------------------- #
def _is_documentation(path: str) -> bool:
    p = _norm(path)
    return p.endswith(".md") or p.endswith(".rst") or p.startswith("docs/") or p == "LICENSE"


def _classify_file(path: str, matrix: dict) -> tuple[dict, str]:
    """Return (rule, source) where source is matched|source_fallback|unmatched."""
    norm = _norm(path)
    for rule in matrix.get("rules", []):
        if _glob_match(rule["pattern"], norm):
            return rule, "matched"
    fallback = matrix.get("source_fallback")
    if fallback and _glob_match(fallback["pattern"], norm):
        return fallback, "source_fallback"
    return matrix.get("unmatched", {"lane": "full", "reason": "unrecognized path"}), "unmatched"


def _resolve_tests(specs: list[str], repo_root: Path) -> tuple[list[str], list[str]]:
    """Resolve literal/glob test specs against the filesystem.

    Returns (resolved_existing_paths, unresolved_specs). Order preserved.
    """
    resolved: list[str] = []
    missing: list[str] = []
    for spec in specs:
        if any(ch in spec for ch in _GLOB_CHARS):
            matches = sorted(
                p.relative_to(repo_root).as_posix() for p in repo_root.glob(spec) if p.is_file()
            )
            if matches:
                resolved.extend(matches)
            else:
                missing.append(spec)
        else:
            if (repo_root / spec).is_file():
                resolved.append(spec)
            else:
                missing.append(spec)
    return resolved, missing


def _dedup(seq: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _scan_safety(
    changed_files: list[str],
    contents: dict[str, str] | None,
    matrix: dict,
    repo_root: Path,
    scan_disk: bool,
) -> list[dict]:
    """Scan non-documentation changed content for safety/execution keywords.

    Documentation that merely *describes* these keywords (docs/, *.md) is
    skipped on purpose so that docs/wording PRs stay in the fast lane.
    """
    keywords = matrix.get("safety_escalation", {}).get("keywords", [])
    hits: list[dict] = []
    for raw in changed_files:
        f = _norm(raw)
        if _is_documentation(f):
            continue
        text: str | None = None
        if contents and raw in contents:
            text = contents[raw]
        elif contents and f in contents:
            text = contents[f]
        elif scan_disk:
            disk = repo_root / f
            if disk.is_file():
                try:
                    text = disk.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    text = None
        if not text:
            continue
        for kw in keywords:
            if kw in text:
                hits.append({"file": f, "keyword": kw})
    return hits


def _max_lane(a: str, b: str) -> str:
    return a if LANE_ORDER.get(a, 0) >= LANE_ORDER.get(b, 0) else b


# --------------------------------------------------------------------------- #
# Command construction
# --------------------------------------------------------------------------- #
def _cmd(display: str, argv: list[str], kind: str) -> dict:
    return {"display": display, "argv": argv, "kind": kind}


def _build_commands(lane: str, tests: list[str]) -> list[dict]:
    commands: list[dict] = [
        _cmd("ruff check .", [PY_EXEC, "-m", "ruff", "check", "."], "lint"),
        _cmd(
            "python -m compileall -q src tests",
            [PY_EXEC, "-m", "compileall", "-q", "src", "tests"],
            "compile",
        ),
    ]
    if tests:
        display = "pytest -q " + " ".join(tests)
        commands.append(_cmd(display, [PY_EXEC, "-m", "pytest", "-q", *tests], "pytest_targeted"))
    if lane == "full":
        commands.append(
            _cmd(
                FULL_PYTEST_RUNNER,
                [PY_EXEC, "scripts/run_full_pytest.py"],
                "pytest_full_runner",
            )
        )
    return commands


# --------------------------------------------------------------------------- #
# Planning
# --------------------------------------------------------------------------- #
def plan_validation(
    changed_files: list[str],
    *,
    pr_number: int | str | None = None,
    profile: str = "auto",
    contents: dict[str, str] | None = None,
    scan_disk: bool = False,
    matrix: dict | None = None,
    repo_root: Path | None = None,
) -> dict:
    """Compute a validation plan for a set of changed files.

    This function is pure planning: it reads the matrix and (optionally) file
    content, but never executes anything.
    """
    matrix = matrix or load_matrix()
    repo_root = repo_root or REPO_ROOT
    changed_files = [_norm(f) for f in changed_files]
    profile_key = PROFILE_ALIASES.get(profile, profile)

    per_file: list[dict] = []
    matrix_test_specs: list[str] = []
    warnings: list[str] = []
    natural_lane = "fast"

    for f in changed_files:
        rule, source = _classify_file(f, matrix)
        lane = rule.get("lane", "full")
        reason = rule.get("reason", "unspecified")
        specs = list(rule.get("tests", []) or [])
        resolved, _missing = _resolve_tests(specs, repo_root)
        matrix_test_specs.extend(specs)
        per_file.append(
            {
                "file": f,
                "lane": lane,
                "reason": reason,
                "source": source,
                "pattern": rule.get("pattern"),
                "mapped_tests": resolved,
            }
        )
        natural_lane = _max_lane(natural_lane, lane)

        if source == "source_fallback" and not resolved and not _is_test_file(f):
            default_warn = "no mapped tests; consider --pr or --profile full"
            warnings.append(f"{f}: {rule.get('warn_if_no_tests', default_warn)}")
        elif source == "unmatched":
            warnings.append(
                f"{f}: unrecognized path; using full lane as a safe default "
                "(add a matrix rule if this is routine)"
            )

    # Safety / execution-boundary content escalation.
    safety_hits = _scan_safety(changed_files, contents, matrix, repo_root, scan_disk)
    natural_pre_safety = natural_lane
    if safety_hits:
        natural_lane = "full"

    # Profile resolution: --profile may escalate freely, but may not de-escalate
    # below a safety-required full lane (safety gate cannot be weakened).
    safety_required = "full" if safety_hits else None
    if profile_key == "auto":
        selected_lane = natural_lane
    elif profile_key in LANE_ORDER:
        forced = profile_key
        if safety_required and LANE_ORDER[forced] < LANE_ORDER["full"]:
            selected_lane = "full"
            warnings.append(
                f"profile override '{profile}' raised to full: safety/execution-boundary "
                f"keyword present (cannot weaken safety gate)"
            )
        else:
            selected_lane = forced
            if LANE_ORDER[forced] < LANE_ORDER[natural_lane]:
                warnings.append(
                    f"profile override de-escalates from natural '{natural_lane}' to "
                    f"'{forced}'; ensure this is justified by a reviewer"
                )
    else:
        selected_lane = natural_lane
        warnings.append(f"unknown profile '{profile}'; falling back to auto ({natural_lane})")

    # Recommended tests: PR-specific first, then changed test files, then matrix.
    recommended_tests: list[str] = []
    if pr_number is not None and str(pr_number).strip():
        pr_spec = f"tests/test_pr{str(pr_number).strip()}_*"
        pr_resolved, _ = _resolve_tests([pr_spec], repo_root)
        recommended_tests.extend(pr_resolved)
    for f in changed_files:
        if _is_test_file(f) and (repo_root / f).is_file():
            recommended_tests.append(f)
    matrix_resolved, _ = _resolve_tests(matrix_test_specs, repo_root)
    recommended_tests.extend(matrix_resolved)
    recommended_tests = _dedup(recommended_tests)

    if not recommended_tests and selected_lane != "full":
        warnings.append(
            "no targeted tests resolved for this change; pass --pr <n>, map tests in "
            "validation_matrix.json, or use --profile full"
        )

    commands = _build_commands(selected_lane, recommended_tests)
    full_pytest_required = selected_lane == "full"

    lane_reason = _compose_lane_reason(
        per_file, selected_lane, natural_pre_safety, safety_hits, profile_key, profile
    )
    full_pytest_reason = _compose_full_pytest_reason(selected_lane, safety_hits, lane_reason)
    runtime_class = RUNTIME_CLASS[selected_lane]
    summary = (
        f"Lane {LANE_LETTER[selected_lane]} ({selected_lane}) for "
        f"{len(changed_files)} changed file(s); full pytest "
        f"{'required' if full_pytest_required else 'not required'}; "
        f"estimated runtime: {runtime_class}."
    )

    plan = {
        "changed_files": changed_files,
        "pr_number": str(pr_number).strip() if pr_number is not None else None,
        "profile": profile,
        "selected_lane": selected_lane,
        "lane_letter": LANE_LETTER[selected_lane],
        "lane_reason": lane_reason,
        "natural_lane": natural_pre_safety,
        "safety_escalations": safety_hits,
        "recommended_tests": recommended_tests,
        "recommended_commands": [c["display"] for c in commands],
        "full_pytest_required": full_pytest_required,
        "full_pytest_runner": FULL_PYTEST_RUNNER if full_pytest_required else None,
        "duration_reporting": full_pytest_required,
        "xdist_used_if_available": full_pytest_required,
        "full_pytest_reason": full_pytest_reason,
        "estimated_runtime_class": runtime_class,
        "warnings": warnings,
        "per_file": per_file,
        "final_summary": summary,
        # Internal: full command objects (with argv) for --execute. Keys with a
        # leading underscore are stripped from --json output.
        "_commands": commands,
    }
    return plan


def _is_test_file(path: str) -> bool:
    p = _norm(path)
    return p.startswith("tests/") and os.path.basename(p).startswith("test_") and p.endswith(".py")


def _compose_lane_reason(
    per_file: list[dict],
    selected_lane: str,
    natural_pre_safety: str,
    safety_hits: list[dict],
    profile_key: str,
    profile_raw: str,
) -> str:
    parts: list[str] = []
    contributing = _dedup([pf["reason"] for pf in per_file if pf["lane"] == natural_pre_safety])
    if contributing:
        parts.append("; ".join(contributing))
    if safety_hits:
        kws = _dedup([h["keyword"] for h in safety_hits])
        example = safety_hits[0]["file"]
        parts.append(
            f"safety/execution-boundary keyword(s) in changed content "
            f"[{', '.join(kws)}] (e.g. {example})"
        )
    if profile_key in LANE_ORDER and profile_key != natural_pre_safety:
        parts.append(f"profile override requested '{profile_raw}'")
    return " | ".join(parts) if parts else "no specific change class detected"


def _compose_full_pytest_reason(
    selected_lane: str, safety_hits: list[dict], lane_reason: str
) -> str:
    if selected_lane == "full":
        if safety_hits:
            return (
                "Full pytest required: safety/execution-boundary content changed. Full "
                "validation provides broad regression confidence for execution/safety/"
                "packaging boundaries and must not be skipped."
            )
        return (
            "Full pytest required: Lane C change (execution/safety/packaging or "
            "validation-infrastructure boundary). Full validation provides broad "
            "regression confidence and must not be skipped."
        )
    return (
        f"Full pytest not required: Lane {LANE_LETTER[selected_lane]} change is covered "
        "by targeted regression tests. Full pytest is reserved for Lane C "
        "(execution/safety/packaging boundaries), failing or suspicious targeted "
        "results, or an explicit reviewer request."
    )


# --------------------------------------------------------------------------- #
# Optional, bounded execution mode
# --------------------------------------------------------------------------- #
def execute_plan(plan: dict, runner=None) -> list[dict]:
    """Run ONLY the recommended commands from the plan.

    `runner` defaults to subprocess.run and can be injected for testing. Each
    command's argv is constructed by this module and additionally checked
    against an allowlist of validation binaries. No shell is used; nothing
    outside the recommended commands is ever run.
    """
    runner = runner or (lambda argv: subprocess.run(argv, cwd=str(REPO_ROOT), check=False))
    results: list[dict] = []
    for command in plan.get("_commands", []):
        argv = command["argv"]
        basename = os.path.basename(argv[0])
        if basename not in ALLOWED_EXEC_BASENAMES:
            raise SystemExit(f"refusing to execute non-allowlisted command: {argv}")
        completed = runner(argv)
        returncode = int(getattr(completed, "returncode", 0) or 0)
        results.append({"display": command["display"], "returncode": returncode})
        if returncode != 0:
            break
    return results


# --------------------------------------------------------------------------- #
# Git changed-file / diff discovery (read-only)
# --------------------------------------------------------------------------- #
def _git(args: list[str], repo_root: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout if completed.returncode == 0 else ""


def _git_changed_files(base: str, head: str, repo_root: Path) -> list[str]:
    out = _git(["diff", "--name-only", f"{base}...{head}"], repo_root)
    return [line.strip() for line in out.splitlines() if line.strip()]


def _git_added_content(base: str, head: str, repo_root: Path, file: str) -> str:
    out = _git(["diff", "--unified=0", f"{base}...{head}", "--", file], repo_root)
    added = [
        line[1:] for line in out.splitlines() if line.startswith("+") and not line.startswith("+++")
    ]
    return "\n".join(added)


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _public_plan(plan: dict) -> dict:
    return {k: v for k, v in plan.items() if not k.startswith("_")}


def render_human(plan: dict) -> str:
    lines: list[str] = []
    lines.append("ShellForgeAI validation lane plan (PR157)")
    lines.append("")
    lines.append(f"Validation lane: {plan['selected_lane']} (Lane {plan['lane_letter']})")
    lines.append(f"Reason: {plan['lane_reason']}")
    lines.append(f"Estimated runtime: {plan['estimated_runtime_class']}")
    lines.append(f"Full pytest required: {'yes' if plan['full_pytest_required'] else 'no'}")
    lines.append(f"Full pytest reason: {plan['full_pytest_reason']}")
    lines.append(f"selected_lane={plan['selected_lane']}")
    lines.append(f"full_pytest_required={str(plan['full_pytest_required']).lower()}")
    if plan["full_pytest_required"]:
        lines.append(f"full_pytest_runner={plan['full_pytest_runner']}")
        lines.append(f"duration_reporting={str(plan['duration_reporting']).lower()}")
        lines.append(f"xdist_used_if_available={str(plan['xdist_used_if_available']).lower()}")
        lines.append(
            "Lane C runner uses pytest-xdist when available and falls back to serial pytest "
            "when unavailable."
        )
        lines.append(
            "Recommended preflight: python scripts/check_validation_env.py --profile docker01"
        )

    hits = plan["safety_escalations"]
    if hits:
        lines.append("Safety escalations:")
        for h in hits:
            lines.append(f"  - {h['file']}: {h['keyword']}")
    else:
        lines.append("Safety escalations: none")

    lines.append("")
    lines.append("Changed files:")
    for pf in plan["per_file"]:
        lines.append(f"  - {pf['file']} -> {pf['lane']} ({pf['reason']})")

    lines.append("")
    lines.append("Recommended tests:")
    if plan["recommended_tests"]:
        for t in plan["recommended_tests"]:
            lines.append(f"  - {t}")
    else:
        lines.append("  (none resolved)")

    lines.append("")
    lines.append("Recommended commands:")
    for c in plan["recommended_commands"]:
        lines.append(f"  {c}")

    if plan["warnings"]:
        lines.append("")
        lines.append("Warnings:")
        for w in plan["warnings"]:
            lines.append(f"  ! {w}")

    lines.append("")
    lines.append(f"Summary: {plan['final_summary']}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="validate_pr.py",
        description=(
            "Recommend a ShellForgeAI validation lane (fast / targeted_runtime / full) "
            "from changed files. Planning/dry-run only by default; never mutates."
        ),
    )
    parser.add_argument(
        "--changed-files",
        nargs="+",
        metavar="PATH",
        help="Explicit list of changed files to plan for.",
    )
    parser.add_argument("--base", help="Base git ref (used with --head to derive changed files).")
    parser.add_argument("--head", default="HEAD", help="Head git ref (default: HEAD).")
    parser.add_argument(
        "--pr", dest="pr_number", help="PR number; adds tests/test_pr<N>_* targets."
    )
    parser.add_argument(
        "--profile",
        default="auto",
        choices=sorted(PROFILE_ALIASES.keys()),
        help="Lane selection profile (default: auto). May escalate but not weaken safety.",
    )
    parser.add_argument(
        "--full-validation",
        action="store_true",
        help="Force Lane C (full) validation. Equivalent to --profile full.",
    )
    parser.add_argument(
        "--scan-content",
        action="store_true",
        help="Scan changed non-doc files on disk for safety keywords (off by default).",
    )
    parser.add_argument("--matrix", help="Path to a validation_matrix.json override.")
    parser.add_argument("--json", action="store_true", help="Emit strict JSON instead of text.")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Run ONLY the recommended commands (ruff/compileall/pytest). Off by default.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    matrix = load_matrix(args.matrix)
    repo_root = REPO_ROOT
    contents: dict[str, str] | None = None

    if args.changed_files:
        changed_files = list(args.changed_files)
    elif args.base:
        changed_files = _git_changed_files(args.base, args.head, repo_root)
        # Diff mode: scan only added lines for non-doc files (low-noise, high-signal).
        contents = {}
        for f in changed_files:
            if not _is_documentation(f):
                contents[f] = _git_added_content(args.base, args.head, repo_root, f)
    else:
        parser.error("provide --changed-files <paths> or --base <ref> [--head <ref>]")
        return 2  # pragma: no cover

    if not changed_files:
        print("No changed files detected; nothing to validate.", file=sys.stderr)
        return 0

    profile = "full" if args.full_validation else args.profile

    plan = plan_validation(
        changed_files,
        pr_number=args.pr_number,
        profile=profile,
        contents=contents,
        scan_disk=args.scan_content,
        matrix=matrix,
        repo_root=repo_root,
    )

    if args.json:
        print(json.dumps(_public_plan(plan), indent=2, sort_keys=True))
    else:
        print(render_human(plan))

    if args.execute:
        if not args.json:
            print("")
            print("Executing recommended commands (read-only validation only):")
        results = execute_plan(plan)
        failed = [r for r in results if r["returncode"] != 0]
        if args.json:
            print(json.dumps({"execution": results}, indent=2, sort_keys=True))
        else:
            for r in results:
                status = "ok" if r["returncode"] == 0 else f"FAILED (rc={r['returncode']})"
                print(f"  {status}: {r['display']}")
        return 1 if failed else 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
