#!/usr/bin/env python3
"""Read-only Docker01 build-path diagnostic report.

This helper scans the repository Dockerfile for broad recursive ownership or
permission operations and records small, bounded filesystem/tooling evidence.
It never runs Docker, Compose, chown/chmod/chgrp, package installation, pytest,
or remediation commands.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MODE = "docker01_build_path_diagnostic_report"
SCHEMA_VERSION = 1
KNOWN_PATHS = ["/data", "/home/appuser/.codex", "/opt/shellforgeai"]
TOOLS = ["python3", "ps", "git", "rsync"]
ARTIFACTS = [
    "docker01-build-path-diagnostic.json",
    "docker01-build-path-diagnostic-summary.md",
    "dockerfile-ownership-scan.json",
    "path-stat-report.json",
    "tooling-baseline-report.json",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
]
WILL_NOT_DO = [
    "run docker build",
    "run docker compose",
    "run chown/chmod/chgrp",
    "install packages",
    "cleanup/prune/delete/restart/remediate/rollback/recover",
]
OPERATOR_NOTES = [
    "This report is diagnostic only.",
    "This report does not build, restart, prune, chown, chmod, remediate, rollback, or recover.",
]
SAFETY = {
    "read_only": True,
    "mutation_performed": False,
    "diagnostic_report_only": True,
    "docker_build_executed": False,
    "docker_compose_executed": False,
    "chown_executed": False,
    "chmod_executed": False,
    "package_install_executed": False,
    "cleanup_executed": False,
    "docker_prune_executed": False,
    "docker_image_removed": False,
    "docker_volume_removed": False,
    "container_restarted": False,
    "remediation_executed": False,
    "rollback_executed": False,
    "recovery_executed": False,
    "natural_language_execution": False,
    "shell_true": False,
    "arbitrary_command_execution": False,
    "cloud_apply_merge_push": False,
    "github_post_approve_merge": False,
}

_RECURSIVE_RE = re.compile(
    r"\b(?:chown|chmod|chgrp)\s+(?:[^#\n]*\s)?-(?:[^#\n\s]*R[^#\n\s]*)\b", re.I
)
_PATH_RE = re.compile(r"/(?:[A-Za-z0-9._@:+-]+/?)+")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _scan_dockerfile(
    path: Path,
    source: str,
) -> tuple[dict[str, Any], list[str], list[str], list[dict[str, str]]]:
    path = path.expanduser().resolve(strict=False)
    warnings: list[str] = []
    errors: list[str] = []
    checks: list[dict[str, str]] = []
    result: dict[str, Any] = {
        "path": str(path),
        "source": source,
        "exists": False,
        "sha256": None,
        "recursive_ownership_lines": [],
    }
    if not path.exists():
        errors.append(f"Dockerfile was not found: {path}")
        checks.append(
            {"name": "dockerfile_scanned", "status": "failed", "detail": "Dockerfile not found."}
        )
        return result, warnings, errors, checks
    if not path.is_file():
        errors.append("Dockerfile path is not a regular file.")
        checks.append(
            {
                "name": "dockerfile_scanned",
                "status": "failed",
                "detail": "Dockerfile is not a regular file.",
            }
        )
        return result, warnings, errors, checks
    try:
        data = path.read_bytes()
        text = data.decode("utf-8", errors="replace")
        result["exists"] = True
    except OSError as exc:
        errors.append(f"Dockerfile could not be read safely: {exc}")
        checks.append({"name": "dockerfile_scanned", "status": "failed", "detail": str(exc)})
        return result, warnings, errors, checks
    result["sha256"] = _sha256(data)
    for number, line in enumerate(text.splitlines(), start=1):
        if _RECURSIVE_RE.search(line):
            paths = sorted(set(_PATH_RE.findall(line)), key=line.find)
            result["recursive_ownership_lines"].append(
                {"line_number": number, "text": line.strip(), "paths": paths}
            )
    status = "warning" if result["recursive_ownership_lines"] else "passed"
    detail = (
        f"{len(result['recursive_ownership_lines'])} recursive ownership/permission line(s) found."
    )
    if status == "warning":
        warnings.append("Dockerfile contains recursive ownership or permission operations.")
    checks.append({"name": "dockerfile_scanned", "status": status, "detail": detail})
    return result, warnings, errors, checks


def _path_report(paths: list[str]) -> list[dict[str, Any]]:
    reports = []
    for item in paths:
        entry: dict[str, Any] = {
            "path": item,
            "exists": False,
            "is_dir": False,
            "is_symlink": False,
            "device": None,
            "owner_uid": None,
            "group_gid": None,
            "mode": None,
            "stat_error": None,
        }
        try:
            p = Path(item)
            st = os.lstat(p)
            entry.update(
                {
                    "exists": True,
                    "is_dir": p.is_dir(),
                    "is_symlink": p.is_symlink(),
                    "device": st.st_dev,
                    "owner_uid": st.st_uid,
                    "group_gid": st.st_gid,
                    "mode": oct(st.st_mode & 0o7777),
                }
            )
        except FileNotFoundError:
            pass
        except OSError as exc:
            entry["stat_error"] = str(exc)
        reports.append(entry)
    return reports


def _tool_report() -> tuple[dict[str, bool], list[str], list[dict[str, str]]]:
    tools = {tool: shutil.which(tool) is not None for tool in TOOLS}
    warnings = []
    checks = []
    for tool, present in tools.items():
        status = "passed" if present else "warning"
        detail = "present" if present else "missing"
        if tool == "ps" and not present:
            detail = (
                "missing; install procps in disposable/manual fallback validation "
                "containers before rerunning the narrow process snapshot test"
            )
        if not present:
            warnings.append(f"Optional investigation tool missing: {tool}.")
        checks.append({"name": f"tool_{tool}", "status": status, "detail": detail})
    return tools, warnings, checks


def build_report(
    repo_root: Path | None = None, dockerfile_path: Path | None = None
) -> dict[str, Any]:
    root = repo_root or _repo_root()
    selected_dockerfile = dockerfile_path or (root / "Dockerfile")
    source = "explicit_argument" if dockerfile_path is not None else "repo_default"
    dockerfile, warnings, errors, checks = _scan_dockerfile(selected_dockerfile, source)
    tools, tool_warnings, tool_checks = _tool_report()
    warnings.extend(tool_warnings)
    checks.extend(tool_checks)
    paths_in_lines: set[str] = set()
    for line in dockerfile["recursive_ownership_lines"]:
        paths_in_lines.update(line["paths"])
    known_detected = [p for p in KNOWN_PATHS if p in paths_in_lines]
    broad = bool(dockerfile["recursive_ownership_lines"])
    status = "failed" if errors else "warning" if warnings or broad else "ok"
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "dockerfile_found": dockerfile["exists"],
            "broad_chown_detected": broad,
            "recursive_ownership_operations": len(dockerfile["recursive_ownership_lines"]),
            "known_chown_paths_detected": known_detected,
            "tooling_baseline_ok": all(tools.values()),
            "report_warnings": len(warnings),
            "report_errors": len(errors),
        },
        "dockerfile": dockerfile,
        "paths": _path_report(KNOWN_PATHS),
        "tools": tools,
        "operator_notes": OPERATOR_NOTES,
        "will_not_do": WILL_NOT_DO,
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": dict(SAFETY),
        "first_safe_command": (
            "cat <diagnostic_report_dir>/docker01-build-path-diagnostic-summary.md"
        ),
    }


def render_human(report: dict[str, Any]) -> str:
    summary = report["summary"]
    known = ", ".join(summary["known_chown_paths_detected"]) or "none"
    path_lines = []
    for p in report["paths"]:
        detail = "exists" if p["exists"] else "missing"
        if p["exists"]:
            detail += (
                f", dir={p['is_dir']}, uid={p['owner_uid']}, "
                f"gid={p['group_gid']}, mode={p['mode']}, device={p['device']}"
            )
        elif p["stat_error"]:
            detail += f", stat_error={p['stat_error']}"
        path_lines.append(f"* {p['path']}: {detail}")
    tool_lines = [
        f"* {name}: {'present' if present else 'missing'}"
        for name, present in report["tools"].items()
        if name != "python3"
    ]
    return "\n".join(
        [
            "# Docker01 Build Path Diagnostic Report",
            "",
            f"Dockerfile: {report['dockerfile']['path']}",
            f"Source: {report['dockerfile']['source'].replace('_', ' ')}",
            f"Status: {report['status']}",
            "Read-only: yes",
            "Mutation performed: no",
            "",
            "## Dockerfile ownership scan",
            f"* Dockerfile found: {str(summary['dockerfile_found']).lower()}",
            f"* Broad recursive chown detected: {str(summary['broad_chown_detected']).lower()}",
            f"* Recursive ownership lines: {summary['recursive_ownership_operations']}",
            f"* Known paths: {known}",
            "",
            "## Relevant paths",
            *path_lines,
            "",
            "## Tools",
            *tool_lines,
            "",
            "## Operator note",
            (
                "This is a diagnostic report only. It does not build, restart, chown, "
                "chmod, prune, remediate, roll back, recover, or mutate Docker/Compose."
            ),
            "",
            "## Safety",
            "* no docker build",
            "* no docker compose",
            "* no chown/chmod/chgrp",
            "* no package install",
            "* no cleanup/prune/restart",
            "* no remediation/rollback/recovery",
            "* no " + "shell=" + "True",
            "",
        ]
    )


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_artifacts(out_dir: Path, report: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(f"Refusing to write reports into non-empty directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    files: dict[str, str] = {}
    payloads = {
        "docker01-build-path-diagnostic.json": report,
        "dockerfile-ownership-scan.json": report["dockerfile"],
        "path-stat-report.json": {"paths": report["paths"]},
        "tooling-baseline-report.json": {
            "tools": report["tools"],
            "warnings": [w for w in report["warnings"] if "tool" in w.lower()],
        },
    }
    for name, payload in payloads.items():
        target = out_dir / name
        _write_json(target, payload)
        files[name] = _sha256(target.read_bytes())
    (out_dir / "docker01-build-path-diagnostic-summary.md").write_text(
        render_human(report), encoding="utf-8"
    )
    (out_dir / "safety-notes.md").write_text(
        "\n".join(["# Safety Notes", "", *[f"* {item}" for item in WILL_NOT_DO], ""]),
        encoding="utf-8",
    )
    manifest = {"schema_version": 1, "mode": MODE, "artifacts": ARTIFACTS}
    _write_json(out_dir / "manifest.json", manifest)
    for name in ["docker01-build-path-diagnostic-summary.md", "safety-notes.md", "manifest.json"]:
        files[name] = _sha256((out_dir / name).read_bytes())
    _write_json(out_dir / "checksums.json", {"sha256": files})


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Emit a read-only Docker01 build-path diagnostic report."
    )
    parser.add_argument("--json", action="store_true", help="emit strict JSON instead of Markdown")
    parser.add_argument(
        "--dockerfile",
        type=Path,
        help="read this Dockerfile path instead of the repository-root default",
    )
    parser.add_argument("--out", type=Path, help="write report artifacts into an empty directory")
    args = parser.parse_args()
    report = build_report(dockerfile_path=args.dockerfile)
    if args.out:
        write_artifacts(args.out, report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_human(report), end="")
    return 1 if report["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
