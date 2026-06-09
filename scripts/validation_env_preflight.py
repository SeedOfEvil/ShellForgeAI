#!/usr/bin/env python3
"""Read-only validation environment preflight for ShellForgeAI.

Before an expensive Docker01 / full-validation run starts ruff/compileall/
pytest, the host validation environment must actually have the dev tools those
phases need. PR177 QA showed what happens otherwise: a host without dev deps
produces a real ruff setup-failure artifact that is correctly classified as
``setup_failure`` — but only *after* the run started. This preflight detects
the missing tools *before* any validation phase runs and classifies the result
as a controlled ``setup_failure`` outcome, so setup noise is never confused
with product/test failure.

The preflight checks (availability/presence only, nothing is executed):

  * Python executable and version
  * ``ruff`` availability (module spec or CLI on PATH; never runs ``ruff check``)
  * ``pytest`` availability (module spec only; never runs pytest)
  * ``pytest-xdist`` availability (warning unless explicitly required)
  * importability of the ``shellforgeai`` package (spec lookup only)
  * presence of the validation helper scripts (run_full_pytest / heartbeat /
    status viewer)
  * write access to the intended validation artifact directory
  * ability to create a heartbeat/status-style JSON probe file

Hard safety posture (this preflight is read-only apart from one tiny probe
file written and removed inside the validation artifact directory):

  * It never installs packages, never modifies venvs or host Python, never
    runs pytest or ``ruff check``, never runs a subprocess, never calls
    Docker/Compose, never mutates ShellForgeAI data or services/containers or
    the host, never runs cleanup/remediation/rollback/recovery, never uses a
    shell or arbitrary commands, never calls a model, and never performs
    natural-language execution.

A failed preflight means the *environment* is not ready: ``status=failed``,
``classification=setup_failure``, ``pass_eligible=false``,
``rerun_required=true``. The recommended fix is to use the disposable
validation container path or prepare dev dependencies outside ShellForgeAI,
then rerun — this preflight never installs anything itself.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"

SCHEMA_VERSION = 1
MODE = "validation_environment_preflight"

# Overall preflight status values.
STATUS_PASSED = "passed"
STATUS_PASSED_WITH_WARNINGS = "passed_with_warnings"
STATUS_FAILED = "failed"

# Per-check status values.
CHECK_PASSED = "passed"
CHECK_FAILED = "failed"
CHECK_WARNING = "warning"

# Classification values (matches validation_heartbeat / validation_status).
CLASS_PASSED = "passed"
CLASS_SETUP_FAILURE = "setup_failure"

# Minimum Python version required by the project (pyproject requires-python).
MIN_PYTHON = (3, 12)

# Validation helper scripts whose presence is checked. ``validation_status.py``
# is the read-only viewer (PR177); missing it degrades evidence inspection but
# does not block validation, so it is a warning rather than a failure.
HELPER_RUN_FULL_PYTEST = "scripts/run_full_pytest.py"
HELPER_HEARTBEAT = "scripts/validation_heartbeat.py"
HELPER_STATUS_VIEWER = "scripts/validation_status.py"

RECOMMENDATION_FAILED = (
    "Use the disposable validation container path or install dev dependencies outside ShellForgeAI."
)
RECOMMENDATION_PASSED = "Validation environment preflight passed; validation can continue."

FIRST_SAFE_COMMAND = "python scripts/validation_env_preflight.py --json"
SAFE_NEXT_COMMANDS = (
    "python scripts/validation_env_preflight.py --json",
    "python scripts/validation_status.py --run-dir <validation_run_dir> --json",
)

SAFETY_BLOCK = {
    "read_only": True,
    "mutation_performed": False,
    "packages_installed": False,
    "validation_executed": False,
    "pytest_executed": False,
    "ruff_executed": False,
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
# Check seams (kept as tiny module-level functions so tests can fake them)
# --------------------------------------------------------------------------- #
def _module_available(name: str) -> bool:
    """Return True when ``name`` is importable (spec lookup; nothing imported)."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _tool_path(name: str) -> str | None:
    return shutil.which(name)


def _helper_exists(rel_path: str) -> bool:
    return (REPO_ROOT / rel_path).is_file()


def _dir_writable(directory: Path) -> tuple[bool, str]:
    """Check the artifact directory exists/can be created and is writable."""
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return False, f"cannot create artifact dir {directory}: {exc}"
    if not os.access(directory, os.W_OK):
        return False, f"artifact dir is not writable: {directory}"
    return True, str(directory)


def _heartbeat_probe(directory: Path) -> tuple[bool, str]:
    """Write and remove one tiny JSON probe file (heartbeat/status shape)."""
    probe = directory / f".sfai-preflight-probe-{os.getpid()}.json"
    try:
        probe.write_text(
            json.dumps({"mode": "preflight_probe", "probe": True}) + "\n", encoding="utf-8"
        )
        json.loads(probe.read_text(encoding="utf-8"))
        probe.unlink()
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"cannot create heartbeat/status probe file in {directory}: {exc}"
    return True, f"heartbeat/status probe write OK in {directory}"


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def _check(name: str, status: str, detail: str, *, required: bool) -> dict[str, Any]:
    return {"name": name, "status": status, "detail": detail, "required": required}


def run_preflight(
    *,
    artifact_dir: str | os.PathLike[str] | None = None,
    require_xdist: bool = False,
    module_available=None,
    tool_path=None,
    helper_exists=None,
) -> dict[str, Any]:
    """Run all preflight checks and return the strict-JSON report dict.

    ``module_available`` / ``tool_path`` / ``helper_exists`` are injectable for
    tests; production callers use the real spec/PATH/filesystem lookups. The
    only write performed is the heartbeat probe file inside ``artifact_dir``.
    """
    module_available = module_available or _module_available
    tool_path = tool_path or _tool_path
    helper_exists = helper_exists or _helper_exists
    target_dir = Path(artifact_dir) if artifact_dir is not None else Path(tempfile.gettempdir())

    checks: list[dict[str, Any]] = []

    # Python executable / version.
    version = ".".join(str(part) for part in sys.version_info[:3])
    executable = sys.executable or tool_path("python3")
    if executable and sys.version_info[:2] >= MIN_PYTHON:
        checks.append(_check("python", CHECK_PASSED, f"{executable}, {version}", required=True))
    elif executable:
        checks.append(
            _check(
                "python",
                CHECK_FAILED,
                f"{executable}, {version} (requires >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})",
                required=True,
            )
        )
    else:
        checks.append(_check("python", CHECK_FAILED, "python executable not found", required=True))

    # ruff availability (module spec or CLI on PATH; never executed).
    if module_available("ruff") or tool_path("ruff"):
        checks.append(_check("ruff", CHECK_PASSED, "ruff available", required=True))
    else:
        checks.append(_check("ruff", CHECK_FAILED, "ruff module not available", required=True))

    # pytest availability (module spec only; never executed).
    if module_available("pytest"):
        checks.append(_check("pytest", CHECK_PASSED, "pytest available", required=True))
    else:
        checks.append(_check("pytest", CHECK_FAILED, "pytest module not available", required=True))

    # pytest-xdist availability (warning unless the lane explicitly requires it).
    if module_available("xdist"):
        checks.append(
            _check("pytest_xdist", CHECK_PASSED, "pytest-xdist available", required=require_xdist)
        )
    elif require_xdist:
        checks.append(
            _check(
                "pytest_xdist",
                CHECK_FAILED,
                "pytest-xdist module not available and required for this lane",
                required=True,
            )
        )
    else:
        checks.append(
            _check(
                "pytest_xdist",
                CHECK_WARNING,
                "not_available; serial full pytest fallback will be used",
                required=False,
            )
        )

    # Project package importability (spec lookup only; nothing imported/run).
    if SRC_ROOT.is_dir() and str(SRC_ROOT) not in sys.path:
        sys.path.insert(0, str(SRC_ROOT))
    if module_available("shellforgeai"):
        checks.append(
            _check("project_import", CHECK_PASSED, "shellforgeai package importable", required=True)
        )
    else:
        checks.append(
            _check(
                "project_import",
                CHECK_FAILED,
                "shellforgeai package spec not found (source/editable install missing)",
                required=True,
            )
        )

    # Validation helper presence.
    for name, rel_path, required in (
        ("run_full_pytest_present", HELPER_RUN_FULL_PYTEST, True),
        ("validation_heartbeat_present", HELPER_HEARTBEAT, True),
        ("validation_status_present", HELPER_STATUS_VIEWER, False),
    ):
        if helper_exists(rel_path):
            checks.append(_check(name, CHECK_PASSED, rel_path, required=required))
        elif required:
            checks.append(_check(name, CHECK_FAILED, f"{rel_path} missing", required=True))
        else:
            checks.append(
                _check(
                    name,
                    CHECK_WARNING,
                    f"{rel_path} missing; evidence viewing degraded",
                    required=False,
                )
            )

    # Artifact directory write access + heartbeat/status probe write.
    writable, writable_detail = _dir_writable(target_dir)
    checks.append(
        _check(
            "artifact_dir_writable",
            CHECK_PASSED if writable else CHECK_FAILED,
            writable_detail,
            required=True,
        )
    )
    if writable:
        probe_ok, probe_detail = _heartbeat_probe(target_dir)
    else:
        probe_ok, probe_detail = False, "skipped: artifact dir not writable"
    checks.append(
        _check(
            "heartbeat_write",
            CHECK_PASSED if probe_ok else CHECK_FAILED,
            probe_detail,
            required=True,
        )
    )

    return build_report(checks)


def build_report(checks: list[dict[str, Any]]) -> dict[str, Any]:
    """Assemble the strict-JSON preflight report from check results."""
    required_failed = sum(
        1 for check in checks if check["required"] and check["status"] == CHECK_FAILED
    )
    required_passed = sum(
        1 for check in checks if check["required"] and check["status"] == CHECK_PASSED
    )
    warnings = sum(1 for check in checks if check["status"] == CHECK_WARNING)

    if required_failed:
        status = STATUS_FAILED
    elif warnings:
        status = STATUS_PASSED_WITH_WARNINGS
    else:
        status = STATUS_PASSED
    failed = status == STATUS_FAILED

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "classification": CLASS_SETUP_FAILURE if failed else CLASS_PASSED,
        "pass_eligible": not failed,
        "rerun_required": failed,
        "checks": checks,
        "summary": {
            "required_passed": required_passed,
            "required_failed": required_failed,
            "warnings": warnings,
        },
        "failed_checks": [
            check["name"]
            for check in checks
            if check["required"] and check["status"] == CHECK_FAILED
        ],
        "warning_checks": [check["name"] for check in checks if check["status"] == CHECK_WARNING],
        "first_safe_command": FIRST_SAFE_COMMAND,
        "safe_next_commands": list(SAFE_NEXT_COMMANDS),
        "recommendation": RECOMMENDATION_FAILED if failed else RECOMMENDATION_PASSED,
        "safety": dict(SAFETY_BLOCK),
    }


# --------------------------------------------------------------------------- #
# Rendering / persistence
# --------------------------------------------------------------------------- #
def render_human(report: dict[str, Any]) -> str:
    failed = report["status"] == STATUS_FAILED
    lines = [
        "Validation environment preflight",
        "",
        f"Status: {report['status']}",
        f"Classification: {report['classification']}",
        f"Pass eligible: {'yes' if report['pass_eligible'] else 'no'}",
        f"Rerun required: {'yes' if report['rerun_required'] else 'no'}",
        "",
        "Checks:",
    ]
    for check in report["checks"]:
        lines.append(f"* {check['name']}: {check['status']} ({check['detail']})")
    if failed:
        lines.extend(
            [
                "",
                "This is validation environment setup failure, not evidence that "
                "product tests failed.",
            ]
        )
    lines.extend(
        [
            "",
            "Recommended next step:",
            report["recommendation"],
            "",
            "Safety:",
            "* Preflight only.",
            "* No packages were installed.",
            "* No validation tests were run.",
            "* No Docker, Compose, cleanup, remediation, rollback, or recovery "
            "command was executed.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, sort_keys=True)


def write_report(report: dict[str, Any], path: str | os.PathLike[str]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def exit_code_for(report: dict[str, Any]) -> int:
    return 0 if report["status"] in (STATUS_PASSED, STATUS_PASSED_WITH_WARNINGS) else 1


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="validation_env_preflight.py",
        description=(
            "Read-only validation environment preflight. Checks whether the "
            "current environment has the dev tools required before "
            "ruff/compileall/pytest validation phases begin. It never installs "
            "packages, never runs pytest or ruff, never runs a subprocess, and "
            "never calls Docker/Compose or mutates anything."
        ),
    )
    parser.add_argument("--json", action="store_true", help="Emit strict JSON only.")
    parser.add_argument(
        "--artifact-dir",
        help=(
            "Intended validation artifact/output directory to check for write "
            "access (default: the system temp directory)."
        ),
    )
    parser.add_argument(
        "--require-xdist",
        action="store_true",
        help="Treat missing pytest-xdist as a failure instead of a warning.",
    )
    parser.add_argument("--output", help="Also write the preflight JSON report to this path.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = run_preflight(artifact_dir=args.artifact_dir, require_xdist=args.require_xdist)
    if args.output:
        write_report(report, args.output)
    if args.json:
        print(render_json(report))
    else:
        print(render_human(report), end="")
    return exit_code_for(report)


if __name__ == "__main__":
    raise SystemExit(main())
