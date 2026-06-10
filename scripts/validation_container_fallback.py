#!/usr/bin/env python3
"""Validation container fallback packet generator for ShellForgeAI.

PR178 added a read-only validation environment preflight so a host without dev
tools (``ruff``/``pytest``/...) stops *before* validation phases run and leaves
controlled ``setup_failure`` evidence. PR178 Docker01 QA showed the useful next
step: when that happens, the operator needs a clear, copy-pasteable path to run
validation in a **disposable validation container** without mutating the host
package set.

This generator reads the validation evidence in a run directory
(``validation-preflight.json`` / ``validation-status.json`` / manifest), and —
when the run stopped on a ``setup_failure`` — writes a fallback packet into the
same run directory:

  * ``validation-container-fallback.json`` — strict-JSON packet evidence
  * ``validation-container-fallback.md``   — operator-facing explanation
  * ``validation-container-command.txt``   — exact copy-paste command + notes
  * ``validation-container-command.argv.json`` — the same command as argv list

Hard safety posture (packet generation only):

  * It never runs Docker or Docker Compose, never restarts containers, never
    runs ``pytest`` or ``ruff``, never installs host packages, never runs a
    subprocess, never uses a shell, never executes the
    generated command, never mutates anything outside the run directory, never
    runs cleanup/remediation/rollback/recovery, never calls a model, and never
    performs natural-language execution. The operator must run the generated
    container command explicitly and separately if they choose to.

A setup-failure run — with or without this packet — is **not merge evidence**.
Only a clean validation rerun (in the container or a prepared environment) can
be used as a pass.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

SCHEMA_VERSION = 1
MODE = "validation_container_fallback_packet"

STATUS_CREATED = "created"
STATUS_NOT_NEEDED = "not_needed"
STATUS_NOT_FOUND = "not_found"
STATUS_FAILED = "failed"

CLASS_SETUP_FAILURE = "setup_failure"

LANE_TARGETED = "targeted_runtime"
LANE_FULL = "full"
LANE_UNKNOWN = "unknown"
LANES = (LANE_TARGETED, LANE_FULL, LANE_UNKNOWN)

FALLBACK_JSON_NAME = "validation-container-fallback.json"
FALLBACK_MD_NAME = "validation-container-fallback.md"
FALLBACK_COMMAND_NAME = "validation-container-command.txt"
FALLBACK_ARGV_NAME = "validation-container-command.argv.json"
PACKET_FILES = (FALLBACK_JSON_NAME, FALLBACK_MD_NAME, FALLBACK_COMMAND_NAME, FALLBACK_ARGV_NAME)

# Disposable validation container default. Dev dependencies are installed
# *inside* the disposable container only; the host package set is unchanged.
DEFAULT_IMAGE = "python:3.12-slim"

RECOMMENDED_ENVIRONMENT = "disposable_validation_container"

# Evidence files read from the run directory (same shapes as validation_status).
_EVIDENCE_GLOBS = {
    "preflight": ("validation-preflight.json", "*preflight*.json"),
    "status": ("validation-status.json", "*-status.json"),
    "manifest": ("validation-manifest.json", "*manifest*.json"),
}

# Preflight check names that map to installable dev tools.
_CHECK_TO_TOOL = {
    "ruff": "ruff",
    "pytest": "pytest",
    "pytest_xdist": "pytest-xdist",
    "python": "python",
}

EXPECTED_PHASES = ("environment_preflight", "ruff", "compileall", "pytest")

SAFETY_BLOCK = {
    "read_only": True,
    "mutation_performed": False,
    "packages_installed": False,
    "validation_executed": False,
    "pytest_executed": False,
    "ruff_executed": False,
    "docker_executed": False,
    "docker_compose_executed": False,
    "container_restarted": False,
    "cleanup_executed": False,
    "remediation_executed": False,
    "rollback_executed": False,
    "recovery_executed": False,
    "shell_true": False,
    "arbitrary_command_execution": False,
    "natural_language_execution": False,
    "model_called": False,
}


# --------------------------------------------------------------------------- #
# Evidence loading
# --------------------------------------------------------------------------- #
def _first_match(directory: Path, patterns: tuple[str, ...]) -> Path | None:
    for pattern in patterns:
        matches = sorted(
            (p for p in directory.glob(pattern) if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if matches:
            # Never read a previously generated fallback packet as evidence.
            for match in matches:
                if match.name not in PACKET_FILES:
                    return match
    return None


def load_evidence(run_dir: Path, warnings: list[str]) -> dict[str, dict[str, Any] | None]:
    """Load preflight/status/manifest evidence, recording controlled warnings."""
    docs: dict[str, dict[str, Any] | None] = {}
    for kind, patterns in _EVIDENCE_GLOBS.items():
        path = _first_match(run_dir, patterns)
        docs[kind] = None
        if path is None:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            warnings.append(f"could not read {kind} evidence {path}: {exc}")
            continue
        if not isinstance(data, dict):
            warnings.append(f"{kind} evidence {path} is not a JSON object; ignored")
            continue
        docs[kind] = data
    return docs


def detect_setup_failure(docs: dict[str, dict[str, Any] | None]) -> dict[str, Any] | None:
    """Return a source summary when the evidence records a setup failure."""
    preflight = docs.get("preflight")
    missing: list[str] = []
    if isinstance(preflight, dict):
        for name in preflight.get("failed_checks") or []:
            tool = _CHECK_TO_TOOL.get(str(name))
            if tool and tool not in missing:
                missing.append(tool)

    setup_failed = False
    failed_phase = None
    if isinstance(preflight, dict) and (
        preflight.get("status") == "failed"
        or preflight.get("classification") == CLASS_SETUP_FAILURE
    ):
        setup_failed = True
        failed_phase = "environment_preflight"
    for kind in ("status", "manifest"):
        doc = docs.get(kind)
        if isinstance(doc, dict) and doc.get("classification") == CLASS_SETUP_FAILURE:
            setup_failed = True
            failed_phase = failed_phase or doc.get("failed_phase") or "environment_preflight"

    if not setup_failed:
        return None
    return {
        "status": "failed",
        "classification": CLASS_SETUP_FAILURE,
        "failed_phase": failed_phase or "environment_preflight",
        "missing_required_tools": missing,
    }


def _run_metadata(docs: dict[str, dict[str, Any] | None]) -> dict[str, Any]:
    pr = None
    commit = None
    for doc in (docs.get("status"), docs.get("manifest")):
        if not isinstance(doc, dict):
            continue
        if pr is None:
            value = doc.get("pr")
            if isinstance(value, dict):
                pr = value.get("number")
            elif value not in (None, ""):
                pr = value
        if commit is None:
            value = doc.get("commit")
            if value in (None, ""):
                block = doc.get("pr")
                if isinstance(block, dict):
                    value = block.get("head_commit")
            if value not in (None, ""):
                commit = value
    return {"pr": pr, "commit": commit}


# --------------------------------------------------------------------------- #
# Fallback command generation (text only; never executed)
# --------------------------------------------------------------------------- #
def build_container_command(
    *,
    run_dir: Path,
    lane: str = LANE_UNKNOWN,
    image: str | None = None,
    pr: str | None = None,
    commit: str | None = None,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Build the operator-run disposable container validation command.

    Returns the command as an argv list plus a safely quoted copy-paste string.
    The command is conservative: read-only source mount, run-dir artifact mount,
    dev dependencies installed inside the disposable container only, and no
    Compose/restart/prune/cleanup of any kind. Nothing here is executed.
    """
    repo_root = repo_root or REPO_ROOT
    resolved_image = image or DEFAULT_IMAGE

    if lane == LANE_TARGETED and pr:
        pytest_step = f"python -m pytest -q tests/test_pr{pr}*"
    else:
        pytest_step = "python scripts/run_full_pytest.py"

    inner = " && ".join(
        [
            "cp -a /src/. /tmp/sfai-validation",
            "cd /tmp/sfai-validation",
            "python -m pip install -q -e '.[dev]'",
            "ruff check .",
            "python -m compileall -q src tests scripts",
            pytest_step,
        ]
    )

    name_pr = pr or "unknown"
    name_sha = (commit or "unknown")[:12]
    argv = [
        "docker",
        "run",
        "--rm",
        "--name",
        f"sfai-validation-fallback-pr{name_pr}-{name_sha}",
        "-v",
        f"{repo_root}:/src:ro",
        "-v",
        f"{run_dir}:/artifacts",
        "-w",
        "/tmp/sfai-validation",
        resolved_image,
        "bash",
        "-lc",
        inner,
    ]
    return {
        "argv": argv,
        "copy_paste": shlex.join(argv),
        "image": resolved_image,
        "lane": lane if lane in LANES else LANE_UNKNOWN,
        "pytest_step": pytest_step,
    }


def render_command_text(command: dict[str, Any], run_dir: Path) -> str:
    """Render the operator-facing command text file (copy-paste + notes)."""
    lines = [
        "# ShellForgeAI disposable validation container fallback command",
        "# Generated because host validation stopped on a setup_failure.",
        "# This command was NOT executed by the generator. Review it, then run",
        "# it yourself if you choose the disposable container path.",
        "#",
        "# What it does:",
        "#   - starts a disposable container (removed when it exits)",
        "#   - mounts the repo read-only at /src and copies it to a temp workdir",
        f"#   - mounts this run dir at /artifacts: {run_dir}",
        "#   - installs dev dependencies INSIDE the container only",
        "#     (the host package set is unchanged; network access is needed",
        "#     for the in-container dependency install)",
        f"#   - runs the validation phases: ruff check, compileall, {command['pytest_step']}",
        "#",
        "# This run is not a pass until a clean validation rerun completes.",
        "",
        command["copy_paste"],
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Packet assembly
# --------------------------------------------------------------------------- #
def build_packet_report(
    *,
    run_dir: Path,
    source: dict[str, Any],
    command: dict[str, Any],
    warnings: list[str],
    forced: bool = False,
) -> dict[str, Any]:
    """Assemble the strict-JSON fallback packet report."""
    command_txt = str(run_dir / FALLBACK_COMMAND_NAME)
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": STATUS_CREATED,
        "read_only": True,
        "mutation_performed": False,
        "forced": bool(forced),
        "run_dir": str(run_dir),
        "source": dict(source),
        "packet": {
            "created": True,
            "files": list(PACKET_FILES),
        },
        "container_validation": {
            "auto_execute": False,
            "operator_invoked": True,
            "host_package_install_required": False,
            "recommended_environment": RECOMMENDED_ENVIRONMENT,
            "lane": command["lane"],
            "image": command["image"],
            "command_preview": command["copy_paste"],
            "command_argv": list(command["argv"]),
            "expected_phases": list(EXPECTED_PHASES),
        },
        "first_safe_command": f"cat {command_txt}",
        "safe_next_commands": [
            f"cat {command_txt}",
            f"python scripts/validation_status.py --run-dir {run_dir} --json",
        ],
        "no_pass_until_rerun": (
            "This setup-failure run is not merge evidence; only a clean "
            "validation rerun (container or prepared environment) can pass."
        ),
        "warnings": list(warnings),
        "safety": dict(SAFETY_BLOCK),
    }


def render_markdown(report: dict[str, Any]) -> str:
    source = report["source"]
    container = report["container_validation"]
    missing = source.get("missing_required_tools") or []
    lines = [
        "# Validation container fallback packet",
        "",
        "## Why host validation stopped",
        "",
        f"- Status: `{source.get('status')}`",
        f"- Classification: `{source.get('classification')}`",
        f"- Failed phase: `{source.get('failed_phase')}`",
        "",
        "This is **validation environment setup failure, not product test "
        "failure**. The host is missing dev tools that the validation phases "
        "need; no product test was run or failed.",
        "",
        "## Missing dependencies",
        "",
    ]
    if missing:
        lines.extend(f"- `{tool}`" for tool in missing)
    else:
        lines.append("- (not recorded in the preflight evidence)")
    lines.extend(
        [
            "",
            "## Recommended path",
            "",
            "Use a disposable validation container (or a separately prepared dev "
            "environment). Do not change the host package set just to satisfy "
            "this run unless you choose to prepare a dev environment yourself.",
            "",
            f"- Recommended environment: `{container['recommended_environment']}`",
            f"- Lane: `{container['lane']}`",
            f"- Image: `{container['image']}`",
            "- Dev dependencies are installed inside the disposable container "
            "only; the host package set is unchanged.",
            "",
            "## Operator-run command",
            "",
            "The generator did **not** run this command. Review it, then run it "
            "yourself if you choose the container path:",
            "",
            "```bash",
            container["command_preview"],
            "```",
            "",
            f"The same command as an argv list is in `{FALLBACK_ARGV_NAME}`.",
            "",
            "## Expected validation phases",
            "",
        ]
    )
    lines.extend(f"- {phase}" for phase in container["expected_phases"])
    lines.extend(
        [
            "",
            "## Safety",
            "",
            "- Packet generation only: no Docker or Docker Compose command was "
            "executed, no container was started or restarted.",
            "- No validation, pytest, or ruff command was executed by the generator.",
            "- No host packages were installed.",
            "- Nothing outside this run directory was written.",
            "",
            "## First safe command",
            "",
            "```bash",
            report["first_safe_command"],
            "```",
            "",
            "## Not a pass",
            "",
            report["no_pass_until_rerun"],
            "",
        ]
    )
    return "\n".join(lines)


def write_packet(run_dir: Path, report: dict[str, Any], command: dict[str, Any]) -> None:
    """Write the four packet files into the run directory (and nowhere else)."""
    (run_dir / FALLBACK_JSON_NAME).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (run_dir / FALLBACK_MD_NAME).write_text(render_markdown(report), encoding="utf-8")
    (run_dir / FALLBACK_COMMAND_NAME).write_text(
        render_command_text(command, run_dir), encoding="utf-8"
    )
    (run_dir / FALLBACK_ARGV_NAME).write_text(
        json.dumps(list(command["argv"]), indent=2) + "\n", encoding="utf-8"
    )


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def generate_packet(
    *,
    run_dir: str | os.PathLike[str],
    lane: str = LANE_UNKNOWN,
    image: str | None = None,
    pr: str | None = None,
    commit: str | None = None,
    force: bool = False,
    preflight: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate (or decline to generate) the fallback packet for a run dir.

    Returns the strict-JSON report dict; ``status`` is one of ``created`` /
    ``not_needed`` / ``not_found`` / ``failed``. ``preflight`` lets a caller
    (the Docker01 PR lane helper) pass an in-memory preflight report instead of
    re-reading it from disk. Nothing is executed; only packet files inside the
    run directory are written, and only on ``created``.
    """
    directory = Path(run_dir)
    if not directory.is_dir():
        return _terminal_report(
            STATUS_NOT_FOUND,
            run_dir=directory,
            warnings=[f"run dir does not exist: {directory}"],
        )

    warnings: list[str] = []
    docs = load_evidence(directory, warnings)
    if preflight is not None:
        docs["preflight"] = preflight

    source = detect_setup_failure(docs)
    if source is None:
        if warnings:
            # Evidence was present but unreadable/malformed: controlled failure,
            # never a guess and never a traceback.
            return _terminal_report(STATUS_FAILED, run_dir=directory, warnings=warnings)
        if not force:
            return _terminal_report(
                STATUS_NOT_NEEDED,
                run_dir=directory,
                warnings=warnings,
                detail=(
                    "no setup_failure evidence found in this run dir; the "
                    "container fallback is not required (use --force to write "
                    "a packet anyway)"
                ),
            )
        source = {
            "status": "unknown",
            "classification": "none",
            "failed_phase": None,
            "missing_required_tools": [],
        }

    meta = _run_metadata(docs)
    resolved_pr = pr if pr is not None else _as_optional_str(meta.get("pr"))
    resolved_commit = commit if commit is not None else _as_optional_str(meta.get("commit"))

    command = build_container_command(
        run_dir=directory,
        lane=lane,
        image=image,
        pr=resolved_pr,
        commit=resolved_commit,
    )
    report = build_packet_report(
        run_dir=directory,
        source=source,
        command=command,
        warnings=warnings,
        forced=force and source.get("classification") != CLASS_SETUP_FAILURE,
    )
    write_packet(directory, report, command)
    return report


def _as_optional_str(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def _terminal_report(
    status: str,
    *,
    run_dir: Path,
    warnings: list[str],
    detail: str | None = None,
) -> dict[str, Any]:
    """Build a non-created report (not_needed / not_found / failed)."""
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "read_only": True,
        "mutation_performed": False,
        "run_dir": str(run_dir),
        "detail": detail,
        "source": None,
        "packet": {"created": False, "files": []},
        "first_safe_command": (f"python scripts/validation_status.py --run-dir {run_dir} --json"),
        "safe_next_commands": [
            f"python scripts/validation_status.py --run-dir {run_dir} --json",
        ],
        "warnings": list(warnings),
        "safety": dict(SAFETY_BLOCK),
    }


def exit_code_for(report: dict[str, Any]) -> int:
    status = report.get("status")
    if status in (STATUS_CREATED, STATUS_NOT_NEEDED):
        return 0
    if status == STATUS_NOT_FOUND:
        return 2
    return 1


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render_human(report: dict[str, Any]) -> str:
    status = report["status"]
    lines = [f"Validation container fallback packet: {status}", ""]
    lines.append(f"Run: {report['run_dir']}")
    if status == STATUS_CREATED:
        source = report["source"]
        lines.append(f"Reason: host validation environment {source.get('classification')}")
        missing = source.get("missing_required_tools") or []
        if missing:
            lines.append("Missing tools:")
            lines.extend(f"* {tool}" for tool in missing)
        lines.extend(
            [
                "",
                "Recommended path:",
                "* Use a disposable validation container or prepared dev environment.",
                "* Do not install packages on the host just to satisfy this run "
                "unless the operator chooses to prepare a dev environment separately.",
                "",
                "Packet files:",
            ]
        )
        lines.extend(f"* {name}" for name in report["packet"]["files"])
    elif status == STATUS_NOT_NEEDED:
        lines.extend(
            [
                "",
                "No setup_failure evidence was found in this run dir, so the "
                "container fallback is not required.",
                "Use --force to write a packet anyway.",
            ]
        )
    elif status == STATUS_NOT_FOUND:
        lines.extend(["", "The run directory does not exist."])
    else:
        lines.extend(["", "The run evidence could not be read (controlled failure)."])
    if report.get("warnings"):
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"* {warning}" for warning in report["warnings"])
    lines.extend(
        [
            "",
            "First safe command:",
            report["first_safe_command"],
            "",
            "Safety:",
            "* Packet generation only.",
            "* No Docker/Compose command was executed.",
            "* No validation command was executed.",
            "* No host packages were installed.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, sort_keys=True)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="validation_container_fallback.py",
        description=(
            "Generate a disposable validation-container fallback packet for a "
            "validation run that stopped on an environment setup_failure. The "
            "generator only reads run evidence and writes packet files into the "
            "run directory: it never runs Docker/Compose, never runs pytest or "
            "ruff, never installs packages, and never executes the generated "
            "command."
        ),
    )
    parser.add_argument(
        "--run-dir", required=True, help="Validation run directory containing evidence files."
    )
    parser.add_argument("--json", action="store_true", help="Emit strict JSON only.")
    parser.add_argument(
        "--lane",
        default=LANE_UNKNOWN,
        choices=LANES,
        help="Validation lane for the generated command (default: unknown → full pytest).",
    )
    parser.add_argument("--pr", help="PR number (default: read from run evidence if present).")
    parser.add_argument("--commit", help="Head commit SHA (default: read from run evidence).")
    parser.add_argument(
        "--image",
        help=f"Disposable validation container image (default: {DEFAULT_IMAGE}).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Write a packet even when no setup_failure evidence is present.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = generate_packet(
        run_dir=args.run_dir,
        lane=args.lane,
        image=args.image,
        pr=args.pr,
        commit=args.commit,
        force=args.force,
    )
    if args.json:
        print(render_json(report))
    else:
        print(render_human(report), end="")
    return exit_code_for(report)


if __name__ == "__main__":
    raise SystemExit(main())
