#!/usr/bin/env python3
"""Read-only validation environment doctor for ShellForgeAI.

The doctor inspects developer/Docker01 validation prerequisites before expensive
validation runs. It never installs, deletes, chmods/chowns, contacts the Docker
daemon, restarts services, or executes arbitrary operator commands.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
SUPPORTED_PROFILES = ("docker01", "local")
REQUIRED_HELPERS = (
    "scripts/run_full_pytest.py",
    "scripts/validate_pr.py",
    "scripts/v1_validate.sh",
    "scripts/finalize_validation_manifest.py",
    "scripts/track_pytest_durations.py",
    "scripts/run_mainline_validation.py",
)
HYGIENE_ROOTS = ("src", "tests", "scripts")
CACHE_NAMES = ("__pycache__", ".pytest_cache", ".ruff_cache")


def _check(status: str, **data: Any) -> dict[str, Any]:
    return {"status": status, **data}


def _find_spec(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


def _version_tuple() -> tuple[int, int, int]:
    return sys.version_info[:3]


def _is_root_owned(path: Path) -> bool:
    try:
        return path.stat().st_uid == 0
    except OSError:
        return False


def _is_writable(path: Path) -> bool:
    return os.access(path, os.W_OK)


def _safe_relative(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def check_python() -> dict[str, Any]:
    version = ".".join(str(part) for part in _version_tuple())
    path = sys.executable or shutil.which("python")
    python3_path = shutil.which("python3")
    usr_bin_python3 = Path("/usr/bin/python3")
    status = "ok" if path and _version_tuple() >= (3, 12, 0) else "failed"
    warnings: list[str] = []
    if not usr_bin_python3.exists():
        warnings.append("/usr/bin/python3 is missing; not required unless tests hardcode it")
    if not python3_path:
        warnings.append("python3 was not found on PATH")
    return _check(
        status,
        path=path,
        version=version,
        python3_path=python3_path,
        usr_bin_python3_exists=usr_bin_python3.exists(),
        warnings=warnings,
        required=True,
    )


def check_import(module: str, *, required: bool = True) -> dict[str, Any]:
    available = _find_spec(module)
    return _check("ok" if available else "failed", available=available, required=required)


def check_shellforgeai_import() -> dict[str, Any]:
    added_source_context = False
    if SRC_ROOT.is_dir() and str(SRC_ROOT) not in sys.path:
        sys.path.insert(0, str(SRC_ROOT))
        added_source_context = True
    available = _find_spec("shellforgeai")
    return _check(
        "ok" if available else "failed",
        available=available,
        required=True,
        detail="import shellforgeai",
        source_context_added=added_source_context,
    )


def check_compileall() -> dict[str, Any]:
    available = _find_spec("compileall")
    return _check("ok" if available else "failed", available=available, required=True)


def check_package_metadata() -> dict[str, Any]:
    names = ("shellforgeai", "ShellForgeAI")
    for name in names:
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
        return _check("ok", available=True, distribution=name, version=version, required=False)
    return _check(
        "warn",
        available=False,
        required=False,
        detail=(
            "project package metadata not installed; editable/source-context import "
            "may still be valid"
        ),
    )


def check_tool(name: str, *, required: bool = True, label: str | None = None) -> dict[str, Any]:
    path = shutil.which(name)
    status = "ok" if path else ("failed" if required else "warn")
    return _check(status, path=path, available=bool(path), required=required, label=label or name)


def check_xdist(*, strict: bool, profile: str) -> dict[str, Any]:
    available = _find_spec("xdist")
    fail_when_missing = strict and profile == "docker01"
    status = "ok" if available else ("failed" if fail_when_missing else "warn")
    detail = "pytest-xdist available" if available else "serial full pytest fallback will be used"
    return _check(status, available=available, required=fail_when_missing, detail=detail)


def check_helpers() -> dict[str, Any]:
    entries: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    for rel in REQUIRED_HELPERS:
        exists = (REPO_ROOT / rel).is_file()
        entries[rel] = {"status": "ok" if exists else "failed", "exists": exists}
        if not exists:
            missing.append(rel)
    return _check("ok" if not missing else "failed", required=True, missing=missing, files=entries)


def check_hygiene() -> dict[str, Any]:
    root_owned_pycache: list[str] = []
    cache_counts = {name: 0 for name in CACHE_NAMES}
    warnings: list[str] = []
    for rel_root in HYGIENE_ROOTS:
        root = REPO_ROOT / rel_root
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.name not in CACHE_NAMES:
                continue
            cache_counts[path.name] += 1
            if path.name == "__pycache__" and _is_root_owned(path):
                root_owned_pycache.append(_safe_relative(path))
    if root_owned_pycache:
        warnings.append(
            "root-owned __pycache__ found; remove generated cache files before source sync"
        )
    if any(cache_counts.values()):
        warnings.append(
            "generated cache directories present; cleanup is operator-owned and not automatic"
        )
    writable = _is_writable(REPO_ROOT)
    if not writable:
        warnings.append("source tree is not writable by current user")
    return {
        "source_tree_writable": writable,
        "root_owned_pycache_count": len(root_owned_pycache),
        "root_owned_pycache_paths": root_owned_pycache[:20],
        "cache_counts": cache_counts,
        "warnings": warnings,
    }


def safety_block() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "package_install_executed": False,
        "file_delete_executed": False,
        "chmod_chown_executed": False,
        "docker_daemon_contacted": False,
    }


def recommendations_for(
    checks: dict[str, Any], hygiene: dict[str, Any], *, fix_hints: bool
) -> list[str]:
    recs: list[str] = []
    if checks["pytest"]["status"] == "failed" or checks["ruff"]["status"] == "failed":
        recs.append(
            "Use/install the project dev validation environment with pytest and ruff "
            "before running validation."
        )
    if checks["rsync"]["status"] == "failed" or checks["procps"]["status"] == "failed":
        recs.append(
            "Use a validation container/image that includes required OS tools such as "
            "rsync and procps/ps."
        )
    if checks["xdist"]["status"] in {"warn", "failed"}:
        recs.append(
            "Install/use pytest-xdist in the validation environment for faster Lane C runs; "
            "serial fallback is valid by default."
        )
    if not checks["python"].get("usr_bin_python3_exists", False):
        recs.append(
            "Prefer tests and helpers that use PATH/env python; /usr/bin/python3 is "
            "optional and may be absent in slim images."
        )
    if hygiene["root_owned_pycache_count"] or hygiene["warnings"]:
        recs.append(
            "Review generated cache ownership before source sync; the doctor reports "
            "hints only and does not delete or chmod/chown."
        )
    if fix_hints:
        recs.append(
            "Fix hints are advisory only: choose any installs, cache deletion, or "
            "permission repair explicitly outside this doctor."
        )
    return recs


def run_doctor(
    *, profile: str = "docker01", strict: bool = False, fix_hints: bool = False
) -> dict[str, Any]:
    checks: dict[str, Any] = {
        "python": check_python(),
        "shellforgeai_import": check_shellforgeai_import(),
        "pytest": check_import("pytest"),
        "ruff": check_import("ruff"),
        "compileall": check_compileall(),
        "package_metadata": check_package_metadata(),
        "git": check_tool("git"),
        "rsync": check_tool("rsync"),
        "procps": check_tool("ps", label="ps/procps"),
        "timeout": check_tool("timeout"),
        "helpers": check_helpers(),
        "xdist": check_xdist(strict=strict, profile=profile),
    }
    if profile == "docker01":
        docker = check_tool("docker", required=False)
        compose_plugin = shutil.which("docker-compose") or shutil.which("docker")
        checks["docker"] = docker
        checks["docker_compose"] = _check(
            "ok" if compose_plugin else "warn",
            path=compose_plugin,
            available=bool(compose_plugin),
            required=False,
            detail="CLI presence only; Docker daemon not contacted",
        )
    hygiene = check_hygiene()
    required_passed = all(
        check.get("status") != "failed" for check in checks.values() if check.get("required")
    )
    warning_present = any(check.get("status") == "warn" for check in checks.values()) or bool(
        hygiene["warnings"]
    )
    status = "failed" if not required_passed else ("warn" if warning_present else "ok")
    return {
        "schema_version": 1,
        "mode": "validation_environment_doctor",
        "status": status,
        "profile": profile,
        "strict": strict,
        "required_passed": required_passed,
        "checks": checks,
        "hygiene": hygiene,
        "recommendations": recommendations_for(checks, hygiene, fix_hints=fix_hints),
        "safety": safety_block(),
    }


def render_human(result: dict[str, Any]) -> str:
    checks = result["checks"]
    lines = ["ShellForgeAI validation environment doctor", "", f"Profile: {result['profile']}"]
    lines.append("")
    lines.append("Required:")
    required_order = (
        "python",
        "shellforgeai_import",
        "pytest",
        "ruff",
        "compileall",
        "git",
        "rsync",
        "procps",
        "timeout",
        "helpers",
    )
    for key in required_order:
        check = checks[key]
        label = check.get("label") or key.replace("_", " ")
        detail = check.get("path") or check.get("version") or check.get("detail")
        suffix = f" ({detail})" if detail else ""
        lines.append(f"* {label}: {check['status']}{suffix}")
    lines.append("")
    lines.append("Optional:")
    xdist = checks["xdist"]
    xdist_label = "ok" if xdist["available"] else "missing"
    lines.append(f"* pytest-xdist: {xdist_label} ({xdist['detail']})")
    py = checks["python"]
    if py.get("usr_bin_python3_exists"):
        lines.append("* /usr/bin/python3: ok")
    else:
        lines.append("* /usr/bin/python3: missing (not required unless tests hardcode it)")
    if "docker" in checks:
        lines.append(f"* docker CLI: {checks['docker']['status']} (daemon not contacted)")
        lines.append(
            f"* docker compose CLI: {checks['docker_compose']['status']} (daemon not contacted)"
        )
    metadata = checks["package_metadata"]
    lines.append(f"* package metadata: {metadata['status']}")
    lines.append("")
    lines.append("Hygiene:")
    hygiene = result["hygiene"]
    lines.append(f"* source tree writable: {'yes' if hygiene['source_tree_writable'] else 'no'}")
    lines.append(f"* root-owned __pycache__: found {hygiene['root_owned_pycache_count']}")
    for warning in hygiene["warnings"]:
        lines.append(f"  Hint: {warning}")
    lines.append("")
    if result["recommendations"]:
        lines.append("Recommendations:")
        for rec in result["recommendations"]:
            lines.append(f"* {rec}")
        lines.append("")
    lines.append(f"Result: {result['status']}")
    if result["required_passed"]:
        if result["status"] == "warn":
            lines.append("Required checks passed. Optional checks have warnings.")
        else:
            lines.append("Required checks passed.")
    else:
        lines.append(
            "Required checks failed. Fix the validation environment before expensive validation."
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only ShellForgeAI validation environment doctor."
    )
    parser.add_argument("--json", action="store_true", help="Emit strict JSON only.")
    parser.add_argument(
        "--strict", action="store_true", help="Fail Docker01 when recommended xdist is missing."
    )
    parser.add_argument("--profile", choices=SUPPORTED_PROFILES, default="docker01")
    parser.add_argument(
        "--fix-hints",
        action="store_true",
        help="Include advisory fix hints; no fixes are executed.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_doctor(profile=args.profile, strict=args.strict, fix_hints=args.fix_hints)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_human(result))
    return 0 if result["required_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
