#!/usr/bin/env python3
"""Read-only validator for Docker01 external Dockerfile ownership update receipts.

This helper statically inspects an explicit target Dockerfile and optional PR255
receipt directory. It never executes the ownership update recipe, Docker,
Compose, ownership commands, package installs, cleanup, restart, remediation,
rollback, recovery, process spawning, or shell commands. The only writes are report
artifacts under an explicit --out directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MODE = "docker01_external_dockerfile_ownership_update_validation"
RISK_PATHS = ["/data", "/home/appuser/.codex", "/opt/shellforgeai"]
EXACT_RISK = "chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai"
ARTIFACTS = [
    "docker01-ownership-update-validation.json",
    "docker01-ownership-update-validation-summary.md",
    "target-dockerfile-analysis.json",
    "receipt-validation.json",
    "safety-notes.md",
    "manifest.json",
    "checksums.json",
]
WILL_NOT_DO = [
    "execute ownership update recipe",
    "edit Dockerfile",
    "edit Compose",
    "run docker build",
    "run docker compose",
    "run chown/chmod/chgrp",
    "install packages",
    "cleanup/prune/delete/restart/remediate/rollback/recover",
]
_RECURSIVE_CHOWN_RE = re.compile(r"\bchown\s+(?:[^#\n]*\s)?-(?:[^#\n\s]*R[^#\n\s]*)\b", re.I)
TARGETED_INSTALL_RE = re.compile(r"\binstall\s+-d\b[^\n#]*(?:-o\s+appuser|-g\s+appuser)", re.I)
COPY_CHOWN_RE = re.compile(r"\bCOPY\s+--chown=appuser:appuser\b", re.I)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_text(path: Path) -> tuple[bool, str | None, str, str | None]:
    try:
        if path.is_symlink() or not path.is_file():
            return False, None, "", "not found or unsafe"
        data = path.read_bytes()
        return True, _sha256(data), data.decode("utf-8", errors="replace"), None
    except OSError as exc:
        return False, None, "", str(exc)


def analyze_target(path: Path) -> dict[str, Any]:
    found, digest, text, error = _read_text(path)
    risk_matches: list[str] = []
    risk_paths: list[str] = []
    targeted_install = False
    copy_chown = False
    if found:
        for line in text.splitlines():
            if EXACT_RISK in line or _RECURSIVE_CHOWN_RE.search(line):
                matched = [p for p in RISK_PATHS if p in line]
                if EXACT_RISK in line or matched:
                    risk_matches.append(line.strip())
                    risk_paths.extend(p for p in matched if p not in risk_paths)
        targeted_install = bool(TARGETED_INSTALL_RE.search(text)) and any(
            p in text for p in RISK_PATHS
        )
        copy_chown = bool(COPY_CHOWN_RE.search(text)) or "--chown=appuser:appuser" in text
    targeted = targeted_install or copy_chown
    return {
        "path": str(path),
        "dockerfile_found": found,
        "target_sha256": digest,
        "read_error": error,
        "broad_chown_risk_detected": bool(risk_matches),
        "risk_line_matches": risk_matches,
        "known_risk_paths_detected_in_recursive_ownership": risk_paths,
        "targeted_install_dir_pattern_detected": targeted_install,
        "copy_chown_guidance_or_pattern_detected": copy_chown,
        "targeted_ownership_pattern_present": targeted,
        "ownership_update_appears_applied": bool(found and not risk_matches and targeted),
    }


def _json_file(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, json.JSONDecodeError) as exc:
        return None, str(exc)


def _bool_claim(obj: dict[str, Any], key: str) -> bool:
    if key in obj:
        return bool(obj[key])
    safety = obj.get("safety") if isinstance(obj.get("safety"), dict) else {}
    if key in safety:
        return bool(safety[key])
    return False


def validate_receipt(receipt: Path | None, target: Path) -> dict[str, Any]:
    base: dict[str, Any] = {
        "requested": receipt is not None,
        "status": "not_requested" if receipt is None else "failed",
        "receipt_mode": None,
        "backup_path": None,
        "backup_sha256": None,
        "target_before_sha256": None,
        "target_after_sha256": None,
        "atomic_replace_claimed": None,
        "docker_build_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "recovery_executed": False,
        "manifest_ok": None,
        "checksums_ok": None,
        "backup_verified": None,
        "allowed_scope_ok": True,
        "safety_contract_ok": True,
        "errors": [],
        "warnings": [],
    }
    if receipt is None:
        return base
    if receipt.is_symlink() or not receipt.is_dir():
        base["errors"].append("receipt directory not found or unsafe")
        return base
    receipt_json = receipt / "docker01-external-dockerfile-update-receipt.json"
    data, err = _json_file(receipt_json)
    if data is None:
        base["errors"].append(f"receipt JSON cannot parse: {err}")
        return base
    base["receipt_mode"] = data.get("mode")
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    base["backup_path"] = data.get("backup_path")
    base["backup_sha256"] = summary.get("backup_sha256")
    base["target_before_sha256"] = summary.get("source_sha256_before")
    base["target_after_sha256"] = summary.get("source_sha256_after")
    base["atomic_replace_claimed"] = bool(summary.get("source_replaced_with_candidate"))
    if data.get("mode") != "docker01_external_dockerfile_ownership_update":
        base["errors"].append("receipt mode is not the PR255 update receipt mode")
    if data.get("source_dockerfile_path") and str(data.get("source_dockerfile_path")) != str(
        target
    ):
        base["errors"].append("receipt target path does not match requested target")
    if not data.get("write_external_dockerfile_only", False):
        base["allowed_scope_ok"] = False
        base["errors"].append("receipt does not claim the narrow external Dockerfile-only scope")
    forbidden = [
        "docker_build_executed",
        "docker_compose_executed",
        "container_restarted",
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
    ]
    for key in forbidden:
        base[key] = _bool_claim(data, key)
        if base[key]:
            base["safety_contract_ok"] = False
            base["errors"].append(f"receipt claims disallowed action: {key}")
    manifest, merr = _json_file(receipt / "manifest.json")
    if manifest is None:
        base["manifest_ok"] = False
        base["errors"].append(f"manifest JSON cannot parse: {merr}")
    else:
        artifacts = manifest.get("artifacts")
        base["manifest_ok"] = isinstance(artifacts, list) and receipt_json.name in artifacts
        if not base["manifest_ok"]:
            base["errors"].append("manifest does not include receipt artifact")
    checksums, cerr = _json_file(receipt / "checksums.json")
    if checksums is None:
        base["checksums_ok"] = False
        base["errors"].append(f"checksums JSON cannot parse: {cerr}")
    else:
        sums = checksums.get("sha256") if isinstance(checksums.get("sha256"), dict) else {}
        mismatches = []
        for name, expected in sums.items():
            p = receipt / name
            if not p.is_file() or p.is_symlink() or _sha256(p.read_bytes()) != expected:
                mismatches.append(name)
        base["checksums_ok"] = not mismatches
        if mismatches:
            base["errors"].append("checksum mismatch: " + ", ".join(mismatches))
    if base["backup_path"]:
        bp = Path(str(base["backup_path"]))
        found, digest, _text, _err = _read_text(bp)
        base["backup_verified"] = bool(
            found and (not base["backup_sha256"] or digest == base["backup_sha256"])
        )
        if not base["backup_verified"]:
            base["errors"].append("backup metadata could not be verified")
    else:
        base["backup_verified"] = None
        base["warnings"].append("receipt did not include backup_path")
    base["status"] = "validated" if not base["errors"] else "failed"
    return base


def _safety() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "validation_only": True,
        "update_executed_by_validator": False,
        "dockerfile_modified_by_validator": False,
        "compose_modified_by_validator": False,
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


def build_report(target: Path, receipt: Path | None, out: Path | None) -> dict[str, Any]:
    target_analysis = analyze_target(target)
    receipt_validation = validate_receipt(receipt, target)
    errors: list[str] = []
    warnings: list[str] = []
    if not target_analysis["dockerfile_found"]:
        errors.append("target Dockerfile not found or unsafe")
    errors.extend(receipt_validation["errors"])
    warnings.extend(receipt_validation["warnings"])
    if out and out.exists() and any(out.iterdir()):
        errors.append("out dir must not be non-empty")
    target_ok = target_analysis["ownership_update_appears_applied"]
    receipt_ok = receipt_validation["status"] in {"not_requested", "validated"}
    if errors:
        status = "failed"
    elif target_ok and receipt_ok:
        status = "validated"
    elif target_analysis["dockerfile_found"] and not target_ok:
        status = "not_updated"
    else:
        status = "partial"
    checks = [
        {
            "name": "target_dockerfile_scanned",
            "status": "passed" if target_analysis["dockerfile_found"] else "failed",
            "detail": str(target),
        },
        {
            "name": "safety_contract_validated",
            "status": "passed" if receipt_validation["safety_contract_ok"] else "failed",
            "detail": "validator remained read-only",
        },
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "created_at": _now(),
        "target": str(target),
        "receipt_dir": str(receipt) if receipt else None,
        "out_dir": str(out) if out else None,
        "read_only": True,
        "mutation_performed": False,
        "validation_only": True,
        "update_executed_by_validator": False,
        "dockerfile_modified_by_validator": False,
        "compose_modified_by_validator": False,
        "summary": {
            "target_found": target_analysis["dockerfile_found"],
            "receipt_found": bool(receipt and receipt.is_dir()),
            "receipt_manifest_ok": receipt_validation["manifest_ok"],
            "receipt_checksums_ok": receipt_validation["checksums_ok"],
            "backup_verified": receipt_validation["backup_verified"],
            "target_sha256": target_analysis["target_sha256"],
            "broad_recursive_ownership_present": target_analysis["broad_chown_risk_detected"],
            "targeted_ownership_pattern_present": target_analysis[
                "targeted_ownership_pattern_present"
            ],
            "ownership_update_appears_applied": target_analysis["ownership_update_appears_applied"],
            "allowed_scope_ok": receipt_validation["allowed_scope_ok"],
            "safety_contract_ok": receipt_validation["safety_contract_ok"],
            "validation_errors": len(errors),
            "validation_warnings": len(warnings),
        },
        "target_analysis": target_analysis,
        "receipt_validation": receipt_validation,
        "will_not_do": WILL_NOT_DO,
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "safety": _safety(),
        "first_safe_command": (
            "cat <validation_report_dir>/docker01-ownership-update-validation-summary.md"
        ),
    }


def render_human(report: dict[str, Any]) -> str:
    s, r = report["summary"], report["receipt_validation"]
    return f"""# Docker01 External Dockerfile Ownership Update Validation

Status: {report["status"]}
Read-only: yes
Mutation performed: no
Target: {report["target"]}
Receipt: {report["receipt_dir"] or "not supplied"}

## Target Dockerfile
* Target found: {s["target_found"]}
* Broad recursive ownership present: {s["broad_recursive_ownership_present"]}
* Targeted ownership pattern present: {s["targeted_ownership_pattern_present"]}
* Appears updated: {s["ownership_update_appears_applied"]}

## Receipt
* Receipt supplied: {r["requested"]}
* Manifest: {r["manifest_ok"]}
* Checksums: {r["checksums_ok"]}
* Backup: {r["backup_verified"]}
* Allowed scope: {r["allowed_scope_ok"]}

## Safety
* validation only
* no Dockerfile modification by validator
* no Compose modification by validator
* no docker build
* no docker compose
* no chown/chmod/chgrp
* no package install
* no cleanup/prune/restart
* no remediation/rollback/recovery
* no {"shell" + "=True"}
"""


def write_artifacts(out: Path, report: dict[str, Any]) -> None:
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"Refusing to write artifacts into non-empty --out directory: {out}")
    out.mkdir(parents=True, exist_ok=True)
    files = {
        "docker01-ownership-update-validation.json": json.dumps(report, indent=2, sort_keys=True)
        + "\n",
        "docker01-ownership-update-validation-summary.md": render_human(report),
        "target-dockerfile-analysis.json": json.dumps(
            report["target_analysis"], indent=2, sort_keys=True
        )
        + "\n",
        "receipt-validation.json": json.dumps(
            report["receipt_validation"], indent=2, sort_keys=True
        )
        + "\n",
        "safety-notes.md": "\n".join(f"- {x}" for x in report["will_not_do"]) + "\n",
        "manifest.json": json.dumps(
            {"schema_version": 1, "mode": MODE, "artifacts": ARTIFACTS}, indent=2, sort_keys=True
        )
        + "\n",
    }
    for name, content in files.items():
        (out / name).write_text(content, encoding="utf-8")
    checksums = {
        name: _sha256((out / name).read_bytes()) for name in ARTIFACTS if name != "checksums.json"
    }
    (out / "checksums.json").write_text(
        json.dumps({"sha256": checksums}, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    p = argparse.ArgumentParser(description="Read-only PR255 Docker01 ownership update validator.")
    p.add_argument("--target", required=True, type=Path)
    p.add_argument("--receipt", type=Path)
    p.add_argument("--out", type=Path)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    report = build_report(args.target, args.receipt, args.out)
    if args.out and not report["errors"]:
        write_artifacts(args.out, report)
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else render_human(report))
    return 0 if report["status"] in {"validated", "not_updated", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
