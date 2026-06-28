#!/usr/bin/env python3
"""Guarded Docker01 external Dockerfile ownership update recipe.

Default mode is read-only preflight. The only write mode backs up and atomically
replaces the exact external Dockerfile with the verified repository candidate
after exact SHA checks and an exact confirmation phrase. This helper never runs
Docker, Docker Compose, ownership commands, package installation, cleanup,
restart, remediation, rollback, recovery, process spawning or shell commands.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
PRODUCTION_SOURCE = Path("/srv/compose/shellforgeai/Dockerfile")
PRODUCTION_ROOT = Path("/srv/compose/shellforgeai")
CONFIRMATION = "CONFIRM_SHELLFORGEAI_DOCKER01_OWNERSHIP_DOCKERFILE_UPDATE"
KNOWN_PATHS = ["/data", "/home/appuser/.codex", "/opt/shellforgeai"]
RISK_TEXT = "chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai"
PRE_ARTIFACTS = [
    "docker01-external-dockerfile-update-preflight.json",
    "docker01-external-dockerfile-update-preflight-summary.md",
    "source-evidence.json",
    "candidate-evidence.json",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
]
WRITE_ARTIFACTS = [
    "docker01-external-dockerfile-update-receipt.json",
    "docker01-external-dockerfile-update-summary.md",
    "source-before-evidence.json",
    "candidate-evidence.json",
    "backup-evidence.json",
    "source-after-evidence.json",
    "post-write-next-steps.md",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
]
WILL_NOT_DO = [
    "edit Dockerfile during preflight",
    "edit Compose",
    "run docker build",
    "run docker compose",
    "run chown/chmod/chgrp",
    "install packages",
    "cleanup/prune/delete/restart/remediate/rollback/recover",
]
WRITE_WILL_NOT_DO = [
    "run docker build",
    "run docker compose",
    "restart container",
    "run chown/chmod/chgrp",
    "install packages",
    "cleanup/prune/delete/restart/remediate/rollback/recover",
]
_RECURSIVE_CHOWN_RE = re.compile(r"\bchown\s+(?:[^#\n]*\s)?-(?:[^#\n\s]*R[^#\n\s]*)\b", re.I)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: Path) -> tuple[bool, str | None, str]:
    if path.is_symlink() or not path.is_file():
        return False, None, ""
    data = path.read_bytes()
    return True, _sha256(data), data.decode("utf-8", errors="replace")


def _resolve(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _has_risk(text: str) -> bool:
    if RISK_TEXT in text:
        return True
    for line in text.splitlines():
        if _RECURSIVE_CHOWN_RE.search(line) and all(p in line for p in KNOWN_PATHS):
            return True
    return False


def _candidate_marked(text: str) -> bool:
    lower = text.lower()
    return "candidate" in lower and ("not the active" in lower or "candidate only" in lower)


def _safety(read_only: bool, mutation: bool, production_modified: bool) -> dict[str, bool]:
    base = {
        "read_only": read_only,
        "mutation_performed": mutation,
        "production_dockerfile_modified": production_modified,
        "compose_modified": False,
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
    if read_only:
        base.update({"preflight_only": True, "write_available": False})
    else:
        base.update({"write_external_dockerfile_only": True})
    return base


def _evidence(path: Path, found: bool, digest: str | None, text: str) -> dict[str, Any]:
    return {
        "path": str(path),
        "found": found,
        "sha256": digest,
        "is_symlink": path.is_symlink(),
        "contains_broad_recursive_ownership": _has_risk(text) if found else False,
        "candidate_marked_not_active": _candidate_marked(text) if found else False,
    }


def _path_errors(
    source: Path, candidate: Path, out: Path | None, backup: Path | None, fixture: Path | None
) -> list[str]:
    errors: list[str] = []
    repo = Path(__file__).resolve().parents[1]
    source_r, candidate_r = _resolve(source), _resolve(candidate)
    out_r = _resolve(out) if out else None
    backup_r = _resolve(backup) if backup else None
    if source.is_symlink() or source_r.is_symlink():
        errors.append("source Dockerfile must not be a symlink")
    if candidate.is_symlink() or candidate_r.is_symlink():
        errors.append("candidate Dockerfile must not be a symlink")
    if fixture:
        fixture_r = _resolve(fixture)
        forbidden = [
            Path("/tmp"),
            Path("/srv"),
            Path("/data"),
            Path("/var"),
            Path("/etc"),
            Path("/home"),
            Path("/root"),
            Path("/opt"),
            repo,
        ]
        if fixture_r in forbidden or any(fixture_r == p for p in forbidden):
            errors.append("fixture root is not safe")
        for label, p in (
            ("source", source_r),
            ("candidate", candidate_r),
            ("out", out_r),
            ("backup", backup_r),
        ):
            if p is not None and not _under(p, fixture_r):
                errors.append(f"{label} path must be under fixture root")
    else:
        if source_r != PRODUCTION_SOURCE:
            errors.append(
                "production source Dockerfile must resolve exactly to "
                "/srv/compose/shellforgeai/Dockerfile"
            )
        if backup_r and not (backup_r == PRODUCTION_ROOT or _under(backup_r, PRODUCTION_ROOT)):
            errors.append(
                "production backup dir must be /srv/compose/shellforgeai or "
                "a safe subdirectory under it"
            )
        if not _under(candidate_r, repo):
            errors.append("candidate path must be inside repository checkout")
    for label, p in (("out", out_r), ("backup", backup_r)):
        if p is not None and p in {source_r, candidate_r}:
            errors.append(f"{label} path must not equal source or candidate path")
    if out_r is not None and backup_r is not None and out_r == backup_r:
        errors.append("out dir must not equal backup dir")
    if out and out.exists() and any(out.iterdir()):
        errors.append("out dir must not be non-empty")
    return errors


def _preflight(args: argparse.Namespace) -> dict[str, Any]:
    source = _resolve(args.source_dockerfile)
    candidate = _resolve(args.candidate)
    errors = _path_errors(args.source_dockerfile, args.candidate, args.out, None, args.fixture_root)
    sf, ss, st = _read(source)
    cf, cs, ct = _read(candidate)
    if not sf:
        errors.append(f"source Dockerfile not found or unsafe: {source}")
    if not cf:
        errors.append(f"candidate Dockerfile not found or unsafe: {candidate}")
    if ss != args.expected_source_sha256:
        errors.append("source sha256 did not match expected value")
    if cs != args.expected_candidate_sha256:
        errors.append("candidate sha256 did not match expected value")
    if sf and not _has_risk(st):
        errors.append("source no longer contains expected broad recursive ownership risk")
    if cf and _has_risk(ct):
        errors.append("candidate contains broad recursive ownership risk")
    if cf and not _candidate_marked(ct):
        errors.append("candidate is not marked as not active production candidate")
    ok = not errors
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "docker01_external_dockerfile_ownership_update_preflight",
        "status": "preflight_passed" if ok else "preflight_failed",
        "created_at": _now(),
        "source_dockerfile_path": str(args.source_dockerfile),
        "candidate_path": str(args.candidate),
        "backup_dir": None,
        "out_dir": str(args.out) if args.out else None,
        "read_only": True,
        "mutation_performed": False,
        "preflight_only": True,
        "write_available": False,
        "production_dockerfile_modified": False,
        "compose_modified": False,
        "summary": {
            "source_found": sf,
            "candidate_found": cf,
            "source_sha256_actual": ss,
            "source_sha256_expected": args.expected_source_sha256,
            "source_sha256_match": ss == args.expected_source_sha256,
            "candidate_sha256_actual": cs,
            "candidate_sha256_expected": args.expected_candidate_sha256,
            "candidate_sha256_match": cs == args.expected_candidate_sha256,
            "source_contains_broad_recursive_ownership": _has_risk(st) if sf else False,
            "candidate_contains_broad_recursive_ownership": _has_risk(ct) if cf else False,
            "candidate_removes_source_risk_pattern": bool(
                sf and cf and _has_risk(st) and not _has_risk(ct)
            ),
            "candidate_marked_not_active": _candidate_marked(ct) if cf else False,
            "preflight_errors": len(errors),
            "preflight_warnings": 0,
        },
        "will_not_do": WILL_NOT_DO,
        "errors": errors,
        "warnings": [],
        "safety": _safety(True, False, False),
        "_source_evidence": _evidence(source, sf, ss, st),
        "_candidate_evidence": _evidence(candidate, cf, cs, ct),
    }


def _write(args: argparse.Namespace) -> dict[str, Any]:
    report = _preflight(args)
    errors = list(report["errors"])
    errors.extend(
        _path_errors(
            args.source_dockerfile,
            args.candidate,
            args.out,
            args.backup_dir,
            args.fixture_root,
        )
    )
    if args.confirm != CONFIRMATION:
        errors.append("confirmation phrase missing or incorrect")
    if not args.backup_dir:
        errors.append("write mode requires explicit backup dir")
    if errors:
        report.update(
            {
                "mode": "docker01_external_dockerfile_ownership_update",
                "status": "update_failed",
                "read_only": False,
                "mutation_performed": False,
                "write_external_dockerfile_only": True,
                "confirmation_phrase_matched": args.confirm == CONFIRMATION,
                "docker_build_available": False,
                "compose_validation_available": False,
                "container_recreate_available": False,
                "errors": errors,
                "safety": _safety(False, False, False),
            }
        )
        return report
    source = _resolve(args.source_dockerfile)
    candidate = _resolve(args.candidate)
    backup_dir = _resolve(args.backup_dir)
    source_before = source.read_bytes()
    candidate_bytes = candidate.read_bytes()
    before_sha = _sha256(source_before)
    cand_sha = _sha256(candidate_bytes)
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"Dockerfile.bak-{stamp}-{before_sha[:12]}.Dockerfile"
    backup_path.write_bytes(source_before)
    tmp = source.with_name(f".{source.name}.tmp-{os.getpid()}")
    try:
        tmp.write_bytes(candidate_bytes)
        os.replace(tmp, source)
    finally:
        if tmp.exists():
            tmp.unlink()
    after = source.read_bytes()
    after_sha = _sha256(after)
    backup_sha = _sha256(backup_path.read_bytes())
    ok = after_sha == cand_sha and backup_sha == before_sha
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "docker01_external_dockerfile_ownership_update",
        "status": "update_written" if ok else "partial",
        "created_at": _now(),
        "source_dockerfile_path": str(args.source_dockerfile),
        "candidate_path": str(args.candidate),
        "backup_dir": str(args.backup_dir),
        "backup_path": str(backup_path),
        "out_dir": str(args.out) if args.out else None,
        "read_only": False,
        "mutation_performed": True,
        "write_external_dockerfile_only": True,
        "confirmation_phrase_matched": True,
        "docker_build_available": False,
        "compose_validation_available": False,
        "container_recreate_available": False,
        "summary": {
            "source_sha256_before": before_sha,
            "candidate_sha256": cand_sha,
            "source_sha256_after": after_sha,
            "backup_sha256": backup_sha,
            "backup_created": backup_path.is_file(),
            "source_replaced_with_candidate": ok,
            "source_after_matches_candidate": after_sha == cand_sha,
            "source_before_matches_backup": backup_sha == before_sha,
            "candidate_removes_source_risk_pattern": True,
            "write_errors": 0 if ok else 1,
            "write_warnings": 0,
        },
        "next_operator_steps": [
            "Review receipt and backup path.",
            "Run Docker/Compose validation only in a separate guarded operator lane.",
            "Do not build or recreate from this helper.",
        ],
        "will_not_do": WRITE_WILL_NOT_DO,
        "errors": [] if ok else ["post-write checksum validation failed"],
        "warnings": [],
        "safety": _safety(False, True, args.fixture_root is None),
        "first_safe_command": "cat <out_dir>/docker01-external-dockerfile-update-summary.md",
        "_source_before_evidence": _evidence(
            source, True, before_sha, source_before.decode("utf-8", errors="replace")
        ),
        "_candidate_evidence": _evidence(
            candidate, True, cand_sha, candidate_bytes.decode("utf-8", errors="replace")
        ),
        "_backup_evidence": _evidence(
            backup_path, True, backup_sha, source_before.decode("utf-8", errors="replace")
        ),
        "_source_after_evidence": _evidence(
            source, True, after_sha, after.decode("utf-8", errors="replace")
        ),
    }


def render_human(report: dict[str, Any]) -> str:
    s = report["summary"]
    return f"""# Docker01 External Dockerfile Ownership Update

Status: {report["status"]}
Mode: {report["mode"]}
Read-only: {"yes" if report["read_only"] else "no"}
Mutation performed: {"yes" if report["mutation_performed"] else "no"}
Docker build available: {"yes" if report.get("docker_build_available") else "no"}
Compose validation available: {"yes" if report.get("compose_validation_available") else "no"}
Container recreate available: {"yes" if report.get("container_recreate_available") else "no"}

## SHA guards
* Source match: {s.get("source_sha256_match", "n/a")}
* Candidate match: {s.get("candidate_sha256_match", "n/a")}
* Candidate removes source risk: {s.get("candidate_removes_source_risk_pattern")}

## Safety
* stops before docker build
* stops before docker compose
* stops before recreate/restart
* no chown/chmod/chgrp
* no package install
* no {"shell" + "=True"}
"""


def _public(report: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in report.items() if not k.startswith("_")}


def write_artifacts(out: Path, report: dict[str, Any]) -> None:
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"Refusing to write artifacts into non-empty --out directory: {out}")
    out.mkdir(parents=True, exist_ok=True)
    pre = report["mode"].endswith("preflight")
    artifacts = PRE_ARTIFACTS if pre else WRITE_ARTIFACTS
    files: dict[str, str] = {}
    if pre:
        files[artifacts[0]] = json.dumps(_public(report), indent=2, sort_keys=True) + "\n"
        files[artifacts[1]] = render_human(report)
        files["source-evidence.json"] = (
            json.dumps(report["_source_evidence"], indent=2, sort_keys=True) + "\n"
        )
        files["candidate-evidence.json"] = (
            json.dumps(report["_candidate_evidence"], indent=2, sort_keys=True) + "\n"
        )
    else:
        files[artifacts[0]] = json.dumps(_public(report), indent=2, sort_keys=True) + "\n"
        files[artifacts[1]] = render_human(report)
        for name, key in (
            ("source-before-evidence.json", "_source_before_evidence"),
            ("candidate-evidence.json", "_candidate_evidence"),
            ("backup-evidence.json", "_backup_evidence"),
            ("source-after-evidence.json", "_source_after_evidence"),
        ):
            if key in report:
                files[name] = json.dumps(report[key], indent=2, sort_keys=True) + "\n"
        files["post-write-next-steps.md"] = (
            "\n".join(f"- {x}" for x in report.get("next_operator_steps", [])) + "\n"
        )
    files["safety-notes.md"] = "\n".join(f"- {x}" for x in report["will_not_do"]) + "\n"
    files["manifest.json"] = (
        json.dumps(
            {"schema_version": 1, "mode": report["mode"], "artifacts": artifacts},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    for n, c in files.items():
        (out / n).write_text(c, encoding="utf-8")
    checksums = {
        n: _sha256((out / n).read_bytes())
        for n in artifacts
        if n != "checksums.json" and (out / n).exists()
    }
    (out / "checksums.json").write_text(
        json.dumps({"sha256": checksums}, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    p = argparse.ArgumentParser(
        description="Guarded Docker01 external Dockerfile ownership update recipe."
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument("--preflight", action="store_true")
    g.add_argument("--write-external-dockerfile", action="store_true")
    p.add_argument("--source-dockerfile", required=True, type=Path)
    p.add_argument("--candidate", required=True, type=Path)
    p.add_argument("--expected-source-sha256", required=True)
    p.add_argument("--expected-candidate-sha256", required=True)
    p.add_argument("--backup-dir", type=Path)
    p.add_argument("--fixture-root", type=Path)
    p.add_argument("--confirm")
    p.add_argument("--out", type=Path)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    report = _write(args) if args.write_external_dockerfile else _preflight(args)
    if args.out:
        write_artifacts(args.out, report)
    print(
        json.dumps(_public(report), indent=2, sort_keys=True) if args.json else render_human(report)
    )
    return 0 if report["status"] in {"preflight_passed", "update_written"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
