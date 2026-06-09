"""Read-only governed recipe receipt history/audit/export/compare helpers."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shellforgeai.core.recipe_execution import (
    RECEIPT_MODE,
    RECOVERY_RECEIPT_MODE,
    SCHEMA_VERSION,
    _resolve_receipt_ref,
    recipe_receipt_root,
    validate_receipt,
)
from shellforgeai.core.recipe_preflight import SUPPORTED_RECIPE

HISTORY_MODE = "v2_recipe_receipt_history"
INSPECT_MODE = "v2_recipe_receipt_inspect"
EXPORT_MODE = "v2_recipe_receipt_export"
EXPORT_VALIDATE_MODE = "v2_recipe_receipt_export_validate"
COMPARE_MODE = "v2_recipe_receipt_compare"
AUDIT_MODE = "v2_recipe_receipt_audit"
AUDIT_BUNDLE_MODE = "v2_recipe_receipt_audit_bundle"
AUDIT_BUNDLE_VALIDATE_MODE = "v2_recipe_receipt_audit_bundle_validate"
INTEGRITY_MODE = "v2_recipe_receipt_integrity"
AUDIT_BUNDLE_MANIFEST_KIND = "v2_recipe_receipt_audit_bundle"
EXPORT_MANIFEST_KIND = "v2_recipe_receipt_export"
DEFAULT_HISTORY_LIMIT = 20
MAX_HISTORY_LIMIT = 100
_SECRET_RE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+")
_SUPPORTED_MODES = {RECEIPT_MODE, RECOVERY_RECEIPT_MODE}


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def receipt_export_root(data_dir: Path | str) -> Path:
    return Path(data_dir).expanduser() / "exports" / "receipt_exports"


def receipt_audit_bundle_root(data_dir: Path | str) -> Path:
    return Path(data_dir).expanduser() / "exports" / "receipt-audit-bundles"


def audit_safety() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "production_restart_executed": False,
        "recovery_executed": False,
        "rollback_executed": False,
        "remediation_executed": False,
        "cleanup_executed": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "model_called": False,
    }


def _coerce_limit(limit: int) -> tuple[int, list[str]]:
    warnings: list[str] = []
    if limit < 1:
        warnings.append("limit below 1; using 1")
        return 1, warnings
    if limit > MAX_HISTORY_LIMIT:
        warnings.append(f"limit above {MAX_HISTORY_LIMIT}; using {MAX_HISTORY_LIMIT}")
        return MAX_HISTORY_LIMIT, warnings
    return limit, warnings


def _read_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, "missing json file"
    except json.JSONDecodeError as exc:
        return None, f"malformed json: {exc}"
    except OSError as exc:
        return None, f"could not read json: {exc}"
    if not isinstance(payload, dict):
        return None, "malformed json: top-level value is not an object"
    return payload, None


def _receipt_dirs(data_dir: Path | str) -> list[Path]:
    root = recipe_receipt_root(data_dir)
    if not root.exists():
        return []
    return [p for p in root.iterdir() if p.is_dir() and (p / "recipe-receipt.json").exists()]


def _created_sort_key(item: dict[str, Any], path: Path) -> tuple[str, float, str]:
    return (
        str(item.get("created_at") or item.get("updated_at") or ""),
        path.stat().st_mtime,
        path.name,
    )


def _verification_status(receipt: dict[str, Any]) -> str:
    verification = (
        receipt.get("verification") if isinstance(receipt.get("verification"), dict) else {}
    )
    return str(verification.get("status") or "not_run")


def _lineage(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "receipt_id": receipt.get("receipt_id"),
        "original_receipt_id": receipt.get("original_receipt_id"),
        "recovery_receipt_id": receipt.get("recovery_receipt_id"),
    }


def _receipt_summary(receipt: dict[str, Any], path: Path) -> dict[str, Any]:
    safety = receipt.get("safety") if isinstance(receipt.get("safety"), dict) else {}
    return {
        "receipt_id": str(receipt.get("receipt_id") or path.name),
        "mode": str(receipt.get("mode") or "unknown"),
        "type": "recovery" if receipt.get("mode") == RECOVERY_RECEIPT_MODE else "execution",
        "recipe_id": receipt.get("recipe_id"),
        "target": receipt.get("target"),
        "status": receipt.get("status") or "unknown",
        "created_at": receipt.get("created_at"),
        "original_receipt_id": receipt.get("original_receipt_id"),
        "recovery_receipt_id": receipt.get("recovery_receipt_id"),
        "verification_status": _verification_status(receipt),
        "path": str(path),
        "safety_highlights": {
            "docker_compose_executed": safety.get("docker_compose_executed") is True,
            "shell_true": safety.get("shell_true") is True,
            "arbitrary_command_execution": safety.get("arbitrary_command_execution") is True,
            "natural_language_execution": safety.get("natural_language_execution") is True,
            "production_restart_executed": safety.get("production_restart_executed") is True,
        },
    }


def receipt_history(data_dir: Path | str, *, limit: int = DEFAULT_HISTORY_LIMIT) -> dict[str, Any]:
    bounded_limit, warnings = _coerce_limit(int(limit))
    rows: list[tuple[dict[str, Any], Path]] = []
    for d in _receipt_dirs(data_dir):
        receipt, err = _read_json(d / "recipe-receipt.json")
        if err or not receipt:
            warnings.append(f"skipped malformed receipt at {d.name}: {err}")
            continue
        if receipt.get("mode") not in _SUPPORTED_MODES:
            warnings.append(f"skipped unsupported receipt at {d.name}")
            continue
        rows.append((receipt, d))
    rows.sort(key=lambda pair: _created_sort_key(pair[0], pair[1]), reverse=True)
    receipts = [_receipt_summary(receipt, path) for receipt, path in rows[:bounded_limit]]
    status = "ok" if receipts else "empty"
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": HISTORY_MODE,
        "status": status,
        "read_only": True,
        "mutation_performed": False,
        "limit": bounded_limit,
        "count": len(receipts),
        "receipts": receipts,
        "first_safe_command": (
            "shellforgeai recipes preflight --recipe docker.disposable_restart "
            "--target <target> --save"
        ),
        "safe_next_commands": [
            (
                "shellforgeai recipes preflight --recipe docker.disposable_restart "
                "--target <target> --save"
            ),
            "shellforgeai recipes receipt inspect <receipt_id>",
        ],
        "safety": audit_safety(),
        "warnings": warnings,
    }


_AUDIT_SAFETY_FLAG_KEYS = (
    "container_restarted",
    "production_restart_executed",
    "docker_compose_executed",
    "shell_true",
    "arbitrary_command_execution",
    "natural_language_execution",
)


def _status_for_audit(receipt: dict[str, Any]) -> str:
    status = str(receipt.get("status") or "unknown")
    if status == "verification_failed":
        return "failed"
    if status in {"executed", "failed", "blocked"}:
        return status
    return status or "unknown"


def _receipt_type(receipt: dict[str, Any]) -> str:
    return "recovery" if receipt.get("mode") == RECOVERY_RECEIPT_MODE else "execution"


def _safety_flag(receipt: dict[str, Any], key: str) -> bool:
    safety = receipt.get("safety") if isinstance(receipt.get("safety"), dict) else {}
    return safety.get(key) is True or receipt.get(key) is True


def _audit_receipt_entry(receipt: dict[str, Any], path: Path) -> dict[str, Any]:
    return {
        "receipt_id": str(receipt.get("receipt_id") or path.name),
        "receipt_type": _receipt_type(receipt),
        "status": _status_for_audit(receipt),
        "verification_status": _verification_status(receipt),
        "created_at": receipt.get("created_at"),
        "path": str(path),
        "safety_summary": {key: _safety_flag(receipt, key) for key in _AUDIT_SAFETY_FLAG_KEYS},
    }


def _known_exports(data_dir: Path | str, receipt_id: str) -> list[dict[str, Any]]:
    root = receipt_export_root(data_dir)
    if not root.exists():
        return []
    exports: list[dict[str, Any]] = []
    for d in root.iterdir():
        if not d.is_dir():
            continue
        manifest, err = _read_json(d / "export-manifest.json")
        if err or not manifest or manifest.get("source_receipt_id") != receipt_id:
            continue
        exports.append(
            {
                "export_id": manifest.get("export_id") or d.name,
                "path": str(d),
                "created_at": manifest.get("created_at"),
            }
        )
    exports.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return exports


def _audit_finding(kind: str, message: str, *, receipt_id: str | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {"kind": kind, "message": message}
    if receipt_id:
        item["receipt_id"] = receipt_id
    return item


def receipt_audit(
    data_dir: Path | str,
    *,
    target: str | None = None,
    recipe_id: str | None = None,
    limit: int = DEFAULT_HISTORY_LIMIT,
    include_exports: bool = False,
    include_compare_summary: bool = False,
) -> dict[str, Any]:
    """Summarize governed execution/recovery receipt chains without executing anything."""
    bounded_limit, limit_warnings = _coerce_limit(int(limit))
    warnings: list[str] = [*limit_warnings]
    findings: list[dict[str, Any]] = []
    all_rows: list[tuple[dict[str, Any], Path, dict[str, Any]]] = []

    root = recipe_receipt_root(data_dir)
    if root.exists():
        for d in root.iterdir():
            if not d.is_dir():
                continue
            receipt_path = d / "recipe-receipt.json"
            if not receipt_path.exists():
                continue
            receipt, err = _read_json(receipt_path)
            if err or receipt is None:
                msg = f"malformed receipt at {d.name}: {err or 'could not read receipt'}"
                warnings.append(msg)
                findings.append(_audit_finding("malformed_receipt", msg))
                continue
            validation = validate_receipt(str(receipt.get("receipt_id") or d.name), data_dir)
            if validation.get("status") != "ok":
                warnings.extend(str(w) for w in validation.get("warnings") or [])
                findings.append(
                    _audit_finding(
                        "receipt_validation_warning",
                        f"receipt validation status is {validation.get('status')}",
                        receipt_id=str(receipt.get("receipt_id") or d.name),
                    )
                )
            all_rows.append((receipt, d, validation))

    all_rows.sort(key=lambda pair: _created_sort_key(pair[0], pair[1]), reverse=True)
    inspected_rows = all_rows[:bounded_limit]
    known_ids = {str(receipt.get("receipt_id") or path.name) for receipt, path, _ in all_rows}

    chains_map: dict[str, dict[str, Any]] = {}
    for receipt, path, validation in inspected_rows:
        rid = str(receipt.get("receipt_id") or path.name)
        rec_recipe = str(receipt.get("recipe_id") or "unknown")
        rec_target = str(receipt.get("target") or "unknown")
        if target and rec_target != target:
            continue
        if recipe_id and rec_recipe != recipe_id:
            continue
        original_id = str(receipt.get("original_receipt_id") or rid)
        chain = chains_map.setdefault(
            original_id,
            {
                "target": rec_target,
                "recipe_id": rec_recipe,
                "original_receipt_id": original_id,
                "latest_receipt_id": rid,
                "receipts": [],
                "findings": [],
                "warnings": [],
            },
        )
        if str(receipt.get("created_at") or "") >= str(chain.get("latest_created_at") or ""):
            chain["latest_receipt_id"] = rid
            chain["latest_created_at"] = receipt.get("created_at") or ""
        if chain.get("target") in {"unknown", ""} and rec_target:
            chain["target"] = rec_target
        if chain.get("recipe_id") in {"unknown", ""} and rec_recipe:
            chain["recipe_id"] = rec_recipe
        entry = _audit_receipt_entry(receipt, path)
        if include_exports:
            entry["exports"] = _known_exports(data_dir, rid)
        chain["receipts"].append(entry)

        if receipt.get("mode") not in _SUPPORTED_MODES:
            msg = f"unsupported receipt mode: {receipt.get('mode') or 'unknown'}"
            chain["warnings"].append(msg)
            chain["findings"].append(_audit_finding("unsupported_receipt", msg, receipt_id=rid))
        if rec_recipe != SUPPORTED_RECIPE:
            msg = f"unsupported recipe id: {rec_recipe}"
            chain["warnings"].append(msg)
            chain["findings"].append(_audit_finding("unsupported_recipe", msg, receipt_id=rid))
        if validation.get("status") != "ok":
            msg = f"validation status is {validation.get('status')}"
            chain["warnings"].append(msg)
        if _verification_status(receipt) == "failed":
            chain["findings"].append(
                _audit_finding("verification_failed", "receipt verification failed", receipt_id=rid)
            )
        for key in _AUDIT_SAFETY_FLAG_KEYS:
            if key == "container_restarted":
                continue
            if _safety_flag(receipt, key):
                msg = f"safety flag recorded true: {key}"
                chain["warnings"].append(msg)
                chain["findings"].append(_audit_finding("safety_drift", msg, receipt_id=rid))
        if receipt.get("mode") == RECOVERY_RECEIPT_MODE:
            if original_id not in known_ids:
                msg = f"recovery receipt links to missing original receipt: {original_id}"
                chain["warnings"].append(msg)
                chain["findings"].append(
                    _audit_finding("missing_original_receipt", msg, receipt_id=rid)
                )
            else:
                chain["findings"].append(
                    _audit_finding(
                        "recovery_links_original",
                        "Recovery receipt links to original execution receipt.",
                        receipt_id=rid,
                    )
                )

    chains = list(chains_map.values())
    for chain in chains:
        chain["receipts"].sort(key=lambda item: str(item.get("created_at") or ""))
        chain.pop("latest_created_at", None)
    chains.sort(
        key=lambda chain: max(str(item.get("created_at") or "") for item in chain["receipts"]),
        reverse=True,
    )

    for chain in chains:
        findings.extend(chain.get("findings") or [])
        warnings.extend(str(w) for w in chain.get("warnings") or [])

    receipt_entries = [entry for chain in chains for entry in chain["receipts"]]
    summary = {
        "receipts_found": len(receipt_entries),
        "execution_receipts": sum(
            1 for item in receipt_entries if item.get("receipt_type") == "execution"
        ),
        "recovery_receipts": sum(
            1 for item in receipt_entries if item.get("receipt_type") == "recovery"
        ),
        "failed_receipts": sum(1 for item in receipt_entries if item.get("status") == "failed"),
        "verification_failed": sum(
            1 for item in receipt_entries if item.get("verification_status") == "failed"
        ),
        "safety_drift": sum(
            1
            for item in receipt_entries
            if any(
                item.get("safety_summary", {}).get(key) is True
                for key in (
                    "production_restart_executed",
                    "docker_compose_executed",
                    "shell_true",
                    "arbitrary_command_execution",
                    "natural_language_execution",
                )
            )
        ),
        "missing_original_receipts": sum(
            1 for item in findings if item.get("kind") == "missing_original_receipt"
        ),
        "production_restart_recorded": sum(
            1
            for item in receipt_entries
            if item.get("safety_summary", {}).get("production_restart_executed") is True
        ),
    }

    if not all_rows and not warnings:
        status = "empty"
    elif all_rows and not receipt_entries:
        status = "no_matches"
    else:
        status = "ok" if receipt_entries or warnings else "empty"

    if receipt_entries and summary["safety_drift"] == 0:
        findings.append(_audit_finding("no_safety_drift", "No safety drift detected."))
    if receipt_entries and summary["production_restart_recorded"] == 0:
        findings.append(
            _audit_finding("no_production_restart", "No production target restart recorded.")
        )

    safe_next = ["shellforgeai recipes receipt history --json"]
    if receipt_entries:
        safe_next = [
            "shellforgeai recipes receipt inspect <receipt_id> --json",
            "shellforgeai recipes receipt history --json",
            "shellforgeai recipes receipt compare <before_receipt_id> <after_receipt_id> --json",
        ]
    compare_summary: dict[str, Any] | None = None
    if include_compare_summary:
        compare_summary = {
            "available": len(receipt_entries) >= 2,
            "command": (
                "shellforgeai recipes receipt compare <before_receipt_id> <after_receipt_id> --json"
            ),
            "note": (
                "Receipt audit does not run compare automatically; use the explicit "
                "read-only compare command."
            ),
        }
        if len(receipt_entries) < 2:
            warnings.append(
                "compare summary requested but fewer than two matching receipts are present"
            )

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "mode": AUDIT_MODE,
        "status": status,
        "read_only": True,
        "mutation_performed": False,
        "filters": {
            "target": target or None,
            "recipe_id": recipe_id or None,
            "limit": bounded_limit,
            "include_exports": bool(include_exports),
            "include_compare_summary": bool(include_compare_summary),
        },
        "summary": summary,
        "chains": chains,
        "findings": findings,
        "warnings": list(dict.fromkeys(warnings)),
        "first_safe_command": safe_next[0],
        "safe_next_commands": safe_next,
        "safety": audit_safety(),
    }
    if compare_summary is not None:
        payload["compare_summary"] = compare_summary
    return payload


_INTEGRITY_SAFETY_FLAG_KEYS = (
    "docker_compose_executed",
    "shell_true",
    "arbitrary_command_execution",
    "natural_language_execution",
    "production_restart_executed",
)


def _integrity_summary() -> dict[str, int]:
    return {
        "receipts_scanned": 0,
        "exports_scanned": 0,
        "audit_bundles_scanned": 0,
        "valid_artifacts": 0,
        "failed_artifacts": 0,
        "warnings": 0,
        "checksum_failures": 0,
        "missing_required_files": 0,
        "malformed_json": 0,
        "missing_original_receipts": 0,
        "unsupported_artifacts": 0,
        "safety_drift": 0,
        "production_restart_recorded": 0,
    }


def _integrity_finding(
    severity: str,
    artifact_type: str,
    path: Path,
    check: str,
    message: str,
    *,
    artifact_ref: str | None = None,
    first_safe_command: str | None = None,
) -> dict[str, Any]:
    return {
        "severity": severity,
        "artifact_type": artifact_type,
        "artifact_ref": artifact_ref or path.name,
        "path": str(path),
        "check": check,
        "message": message,
        "first_safe_command": first_safe_command or "shellforgeai recipes receipt audit --json",
    }


def _safe_rel_path(base: Path, rel: str) -> Path | None:
    rel_path = Path(str(rel))
    if rel_path.is_absolute() or ".." in rel_path.parts:
        return None
    path = (base / rel_path).resolve()
    try:
        path.relative_to(base.resolve())
    except ValueError:
        return None
    return path


def _check_manifest_checksums(
    base: Path,
    checksums: dict[str, Any],
    *,
    artifact_type: str,
    artifact_ref: str,
    skip: set[str] | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    skip = skip or set()
    for rel, expected in checksums.items():
        rel_s = str(rel)
        if rel_s in skip:
            continue
        path = _safe_rel_path(base, rel_s)
        if path is None:
            findings.append(
                _integrity_finding(
                    "failed",
                    artifact_type,
                    base,
                    "checksum",
                    f"unsafe checksum path: {rel_s}",
                    artifact_ref=artifact_ref,
                )
            )
            continue
        if not path.is_file():
            findings.append(
                _integrity_finding(
                    "warning",
                    artifact_type,
                    path,
                    "required_file",
                    f"checksum references missing file: {rel_s}",
                    artifact_ref=artifact_ref,
                )
            )
            continue
        try:
            actual = _sha256_file(path)
        except OSError as exc:
            findings.append(
                _integrity_finding(
                    "warning",
                    artifact_type,
                    path,
                    "checksum",
                    f"could not hash {rel_s}: {exc}",
                    artifact_ref=artifact_ref,
                )
            )
            continue
        if actual != str(expected):
            findings.append(
                _integrity_finding(
                    "failed",
                    artifact_type,
                    path,
                    "checksum",
                    f"checksum mismatch for {rel_s}",
                    artifact_ref=artifact_ref,
                )
            )
    return findings


def _integrity_checks(summary: dict[str, int]) -> list[dict[str, str]]:
    return [
        {
            "name": "receipt_json_parse",
            "status": "failed" if summary["malformed_json"] else "passed",
        },
        {
            "name": "manifest_checksum_consistency",
            "status": "failed" if summary["checksum_failures"] else "passed",
        },
        {
            "name": "recovery_original_links",
            "status": "failed" if summary["missing_original_receipts"] else "passed",
        },
        {"name": "safety_flags", "status": "failed" if summary["safety_drift"] else "passed"},
        {
            "name": "production_restart_records",
            "status": "failed" if summary["production_restart_recorded"] else "passed",
        },
    ]


def _scan_receipt_integrity(
    d: Path,
    data_dir: Path | str,
    known_ids: set[str],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], bool]:
    findings: list[dict[str, Any]] = []
    required = ("recipe-receipt.json", "recipe-receipt.md", "manifest.json")
    for rel in required:
        if not (d / rel).exists():
            findings.append(
                _integrity_finding(
                    "warning",
                    "receipt",
                    d / rel,
                    "required_file",
                    f"missing required receipt file: {rel}",
                    artifact_ref=d.name,
                    first_safe_command=f"shellforgeai recipes receipt inspect {d.name} --json",
                )
            )
    receipt, err = _read_json(d / "recipe-receipt.json")
    if err or receipt is None:
        findings.append(
            _integrity_finding(
                "warning",
                "receipt",
                d / "recipe-receipt.json",
                "json_parse",
                err or "receipt JSON could not be parsed",
                artifact_ref=d.name,
                first_safe_command=f"shellforgeai recipes receipt inspect {d.name} --json",
            )
        )
        return None, findings, False
    rid = str(receipt.get("receipt_id") or d.name)
    for field in ("recipe_id", "target", "created_at"):
        if not receipt.get(field):
            findings.append(
                _integrity_finding(
                    "warning",
                    "receipt",
                    d / "recipe-receipt.json",
                    "required_file",
                    f"receipt missing expected field: {field}",
                    artifact_ref=rid,
                    first_safe_command=f"shellforgeai recipes receipt inspect {rid} --json",
                )
            )
    if receipt.get("mode") not in _SUPPORTED_MODES:
        findings.append(
            _integrity_finding(
                "warning",
                "receipt",
                d / "recipe-receipt.json",
                "required_file",
                f"unsupported receipt mode: {receipt.get('mode') or 'unknown'}",
                artifact_ref=rid,
                first_safe_command=f"shellforgeai recipes receipt inspect {rid} --json",
            )
        )
    safety = receipt.get("safety") if isinstance(receipt.get("safety"), dict) else {}
    if not safety:
        findings.append(
            _integrity_finding(
                "warning",
                "receipt",
                d / "recipe-receipt.json",
                "safety_flag",
                "receipt missing safety block",
                artifact_ref=rid,
                first_safe_command=f"shellforgeai recipes receipt inspect {rid} --json",
            )
        )
    for key in _INTEGRITY_SAFETY_FLAG_KEYS:
        if safety.get(key) is True or receipt.get(key) is True:
            findings.append(
                _integrity_finding(
                    "failed",
                    "receipt",
                    d / "recipe-receipt.json",
                    "safety_flag",
                    f"unsafe safety flag recorded true: {key}",
                    artifact_ref=rid,
                    first_safe_command=f"shellforgeai recipes receipt inspect {rid} --json",
                )
            )
    if receipt.get("mode") == RECOVERY_RECEIPT_MODE and receipt.get("original_receipt_id"):
        original = str(receipt.get("original_receipt_id"))
        if original not in known_ids:
            findings.append(
                _integrity_finding(
                    "warning",
                    "receipt",
                    d / "recipe-receipt.json",
                    "linkage",
                    f"recovery receipt links to missing original receipt: {original}",
                    artifact_ref=rid,
                    first_safe_command=f"shellforgeai recipes receipt inspect {rid} --json",
                )
            )
    manifest, manifest_err = _read_json(d / "manifest.json")
    if manifest_err or manifest is None:
        findings.append(
            _integrity_finding(
                "warning",
                "receipt",
                d / "manifest.json",
                "json_parse",
                manifest_err or "manifest JSON could not be parsed",
                artifact_ref=rid,
                first_safe_command=f"shellforgeai recipes receipt inspect {rid} --json",
            )
        )
    else:
        checksums = manifest.get("checksums") if isinstance(manifest.get("checksums"), dict) else {}
        if checksums:
            findings.extend(
                _check_manifest_checksums(
                    d,
                    checksums,
                    artifact_type="receipt",
                    artifact_ref=rid,
                    skip={"manifest.json"},
                )
            )
    return receipt, findings, not findings


def receipt_integrity(
    data_dir: Path | str,
    *,
    target: str | None = None,
    recipe_id: str | None = None,
    limit: int = DEFAULT_HISTORY_LIMIT,
    include_exports: bool = False,
    include_audit_bundles: bool = False,
) -> dict[str, Any]:
    """Scan owned receipt/export/audit-bundle artifacts for drift without executing anything."""
    bounded_limit, limit_warnings = _coerce_limit(int(limit))
    summary = _integrity_summary()
    findings: list[dict[str, Any]] = []
    warnings: list[str] = [*limit_warnings]
    root = recipe_receipt_root(data_dir)
    try:
        receipt_dirs = [p for p in root.iterdir() if p.is_dir()] if root.exists() else []
    except OSError as exc:
        warnings.append(f"could not read receipt data directory: {exc}")
        summary["warnings"] = len(warnings)
        return {
            "schema_version": SCHEMA_VERSION,
            "mode": INTEGRITY_MODE,
            "status": "failed",
            "read_only": True,
            "mutation_performed": False,
            "filters": {
                "target": target or None,
                "recipe_id": recipe_id or None,
                "limit": bounded_limit,
                "include_exports": bool(include_exports),
                "include_audit_bundles": bool(include_audit_bundles),
            },
            "summary": summary,
            "checks": _integrity_checks(summary),
            "findings": findings,
            "warnings": warnings,
            "first_safe_command": "shellforgeai recipes receipt history --json",
            "safe_next_commands": [
                "shellforgeai recipes receipt history --json",
                "shellforgeai recipes receipt audit --json",
            ],
            "safety": audit_safety(),
        }

    known_ids: set[str] = set()
    sortable: list[tuple[str, float, str, Path, dict[str, Any] | None]] = []
    for d in receipt_dirs:
        receipt, _ = _read_json(d / "recipe-receipt.json")
        if receipt:
            known_ids.add(str(receipt.get("receipt_id") or d.name))
        sortable.append(
            (
                str((receipt or {}).get("created_at") or (receipt or {}).get("updated_at") or ""),
                d.stat().st_mtime,
                d.name,
                d,
                receipt,
            )
        )
    sortable.sort(reverse=True)

    selected: list[Path] = []
    for _, _, _, d, cached in sortable:
        rec = cached
        if rec is None:
            rec, _ = _read_json(d / "recipe-receipt.json")
        if rec is not None:
            if target and str(rec.get("target") or "") != target:
                continue
            if recipe_id and str(rec.get("recipe_id") or "") != recipe_id:
                continue
        selected.append(d)
        if len(selected) >= bounded_limit:
            break

    for d in selected:
        receipt, item_findings, ok = _scan_receipt_integrity(d, data_dir, known_ids)
        summary["receipts_scanned"] += 1
        findings.extend(item_findings)
        if ok:
            summary["valid_artifacts"] += 1
        else:
            summary["failed_artifacts"] += 1
        if receipt:
            safety = receipt.get("safety") if isinstance(receipt.get("safety"), dict) else {}
            if (
                safety.get("production_restart_executed") is True
                or receipt.get("production_restart_executed") is True
            ):
                summary["production_restart_recorded"] += 1

    if include_exports:
        export_root = receipt_export_root(data_dir)
        try:
            export_dirs = (
                [p for p in export_root.iterdir() if p.is_dir()] if export_root.exists() else []
            )
        except OSError as exc:
            export_dirs = []
            warnings.append(f"could not read receipt export directory: {exc}")
        for d in export_dirs:
            validation = receipt_export_validate(str(d), data_dir)
            manifest, _ = _read_json(d / "export-manifest.json")
            if target and str((manifest or {}).get("target") or "") != target:
                continue
            if recipe_id and str((manifest or {}).get("recipe_id") or "") != recipe_id:
                continue
            summary["exports_scanned"] += 1
            if validation.get("status") == "ok":
                summary["valid_artifacts"] += 1
            else:
                summary["failed_artifacts"] += 1
                for warning in validation.get("warnings") or ["receipt export validation failed"]:
                    findings.append(
                        _integrity_finding(
                            "warning",
                            "receipt_export",
                            d,
                            "checksum" if "checksum" in str(warning) else "required_file",
                            str(warning),
                            artifact_ref=str(validation.get("export_id") or d.name),
                            first_safe_command=(
                                f"shellforgeai recipes receipt export-validate {d.name} --json"
                            ),
                        )
                    )

    if include_audit_bundles:
        bundle_root = receipt_audit_bundle_root(data_dir)
        try:
            bundle_dirs = (
                [p for p in bundle_root.iterdir() if p.is_dir()] if bundle_root.exists() else []
            )
        except OSError as exc:
            bundle_dirs = []
            warnings.append(f"could not read audit bundle directory: {exc}")
        for d in bundle_dirs:
            validation = receipt_audit_bundle_validate(str(d), data_dir)
            manifest, _ = _read_json(d / "manifest.json")
            filters = (
                (manifest or {}).get("filters")
                if isinstance((manifest or {}).get("filters"), dict)
                else {}
            )
            if target and str(filters.get("target") or "") != target:
                continue
            if recipe_id and str(filters.get("recipe_id") or "") != recipe_id:
                continue
            summary["audit_bundles_scanned"] += 1
            if validation.get("status") == "ok":
                summary["valid_artifacts"] += 1
            else:
                summary["failed_artifacts"] += 1
                for warning in validation.get("warnings") or ["audit bundle validation failed"]:
                    findings.append(
                        _integrity_finding(
                            "warning",
                            "audit_bundle",
                            d,
                            "checksum" if "checksum" in str(warning) else "required_file",
                            str(warning),
                            artifact_ref=str(validation.get("bundle_id") or d.name),
                            first_safe_command=(
                                "shellforgeai recipes receipt audit-bundle-validate "
                                f"{d.name} --json"
                            ),
                        )
                    )

    for finding in findings:
        check = str(finding.get("check") or "")
        msg = str(finding.get("message") or "")
        if check == "checksum" or "checksum" in msg:
            summary["checksum_failures"] += 1
        if check == "required_file" or "missing required" in msg or "missing file" in msg:
            summary["missing_required_files"] += 1
        if check == "json_parse" or "malformed" in msg:
            summary["malformed_json"] += 1
        if check == "linkage" or "missing original" in msg:
            summary["missing_original_receipts"] += 1
        if "unsupported" in msg:
            summary["unsupported_artifacts"] += 1
        if check == "safety_flag":
            summary["safety_drift"] += 1
    warnings.extend(
        str(f.get("message")) for f in findings if f.get("severity") in {"warning", "failed"}
    )
    warnings = list(dict.fromkeys(warnings))
    summary["warnings"] = len(warnings)

    scanned = (
        summary["receipts_scanned"] + summary["exports_scanned"] + summary["audit_bundles_scanned"]
    )
    status = "empty" if scanned == 0 else ("ok_with_warnings" if findings or warnings else "ok")
    first_safe = (
        "shellforgeai recipes receipt history --json"
        if status == "empty"
        else "shellforgeai recipes receipt audit --json"
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": INTEGRITY_MODE,
        "status": status,
        "read_only": True,
        "mutation_performed": False,
        "filters": {
            "target": target or None,
            "recipe_id": recipe_id or None,
            "limit": bounded_limit,
            "include_exports": bool(include_exports),
            "include_audit_bundles": bool(include_audit_bundles),
        },
        "summary": summary,
        "checks": _integrity_checks(summary),
        "findings": findings,
        "warnings": warnings,
        "first_safe_command": first_safe,
        "safe_next_commands": [
            "shellforgeai recipes receipt audit --json",
            "shellforgeai recipes receipt history --json",
            "shellforgeai recipes receipt audit-bundle --json",
        ],
        "safety": audit_safety(),
    }


def _receipt_audit_bundle_summary(audit_payload: dict[str, Any]) -> dict[str, Any]:
    summary = audit_payload.get("summary") if isinstance(audit_payload.get("summary"), dict) else {}
    warnings = (
        audit_payload.get("warnings") if isinstance(audit_payload.get("warnings"), list) else []
    )
    return {
        "receipts_summarized": int(summary.get("receipts_found") or 0),
        "chains_summarized": len(audit_payload.get("chains") or []),
        "warnings": len(warnings),
        "safety_drift": int(summary.get("safety_drift") or 0),
        "production_restart_recorded": int(summary.get("production_restart_recorded") or 0),
    }


def _render_audit_bundle_markdown(payload: dict[str, Any]) -> str:
    filters = payload.get("filters") if isinstance(payload.get("filters"), dict) else {}
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    warnings = payload.get("warnings") if isinstance(payload.get("warnings"), list) else []
    lines = [
        "# Governed Recipe Receipt Audit Bundle",
        "",
        f"Created at: {payload.get('created_at')}",
        f"Bundle ID: {payload.get('bundle_id')}",
        "",
        "## Filters",
        "",
        f"- target: {filters.get('target') or '-'}",
        f"- recipe_id: {filters.get('recipe_id') or '-'}",
        f"- limit: {filters.get('limit')}",
        f"- include_exports: {str(bool(filters.get('include_exports'))).lower()}",
        f"- include_compare_summary: {str(bool(filters.get('include_compare_summary'))).lower()}",
        "",
        "## Summary",
        "",
        f"- receipts summarized: {summary.get('receipts_summarized', 0)}",
        f"- chains summarized: {summary.get('chains_summarized', 0)}",
        f"- warnings: {summary.get('warnings', 0)}",
        f"- safety drift: {summary.get('safety_drift', 0)}",
        f"- production restart recorded: {summary.get('production_restart_recorded', 0)}",
        "",
        "## Findings / Warnings",
        "",
    ]
    if warnings:
        lines.extend(f"- {warning}" for warning in warnings[:20])
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Safety",
            "",
            "Artifact export only. No execution was performed.",
            "No recipe, recovery, rollback, cleanup, Docker, or Compose command was executed.",
            "No container restart, production restart, arbitrary command execution, "
            "natural-language execution, or model call occurred.",
            "",
            "## First safe command",
            "",
            f"`{payload.get('first_safe_command')}`",
            "",
        ]
    )
    return "\n".join(lines)


def _write_json_file(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _audit_bundle_required_files() -> list[str]:
    return [
        "audit-bundle.json",
        "audit-bundle.md",
        "receipt-audit.json",
        "receipt-history.json",
        "manifest.json",
        "checksums.json",
    ]


def receipt_audit_bundle(
    data_dir: Path | str,
    *,
    target: str | None = None,
    recipe_id: str | None = None,
    limit: int = DEFAULT_HISTORY_LIMIT,
    include_exports: bool = False,
    include_compare_summary: bool = False,
) -> dict[str, Any]:
    """Package existing local receipt audit/history evidence into an owned support bundle."""
    bounded_limit, limit_warnings = _coerce_limit(int(limit))
    created_at = _now_utc()
    bundle_id = f"audit_bundle_{_now_stamp()}_{uuid.uuid4().hex[:6]}"
    root = receipt_audit_bundle_root(data_dir).resolve()
    out = (root / bundle_id).resolve()
    try:
        out.relative_to(root)
    except ValueError:
        return {
            "schema_version": SCHEMA_VERSION,
            "mode": AUDIT_BUNDLE_MODE,
            "status": "failed",
            "read_only": True,
            "mutation_performed": False,
            "artifact_export_only": True,
            "bundle": {"bundle_id": bundle_id, "path": None, "files": []},
            "filters": {},
            "summary": {},
            "first_safe_command": (
                "shellforgeai recipes receipt audit-bundle-validate <bundle_id> --json"
            ),
            "safe_next_commands": [],
            "warnings": ["refused unsafe bundle path"],
            "safety": {**audit_safety(), "artifact_export_only": True},
        }
    out.mkdir(parents=True, exist_ok=False)

    audit_payload = receipt_audit(
        data_dir,
        target=target,
        recipe_id=recipe_id,
        limit=bounded_limit,
        include_exports=include_exports,
        include_compare_summary=include_compare_summary,
    )
    history_payload = receipt_history(data_dir, limit=bounded_limit)
    filters = {
        "target": target or None,
        "recipe_id": recipe_id or None,
        "limit": bounded_limit,
        "include_exports": bool(include_exports),
        "include_compare_summary": bool(include_compare_summary),
    }
    summary = _receipt_audit_bundle_summary(audit_payload)
    warnings = list(dict.fromkeys([*limit_warnings, *(audit_payload.get("warnings") or [])]))
    first_safe = f"shellforgeai recipes receipt audit-bundle-validate {bundle_id} --json"
    safe_next = [
        first_safe,
        "shellforgeai recipes receipt audit --json",
        "shellforgeai recipes receipt history --json",
    ]
    files = [*_audit_bundle_required_files()]
    optional_files: list[str] = []
    if include_compare_summary:
        optional_files.append("receipt-compare-summary.json")
    if include_exports:
        optional_files.append("receipt-export-index.json")
    files = [*files, *optional_files]

    _write_json_file(out / "receipt-audit.json", audit_payload)
    _write_json_file(out / "receipt-history.json", history_payload)
    if include_compare_summary:
        _write_json_file(
            out / "receipt-compare-summary.json",
            audit_payload.get("compare_summary")
            if isinstance(audit_payload.get("compare_summary"), dict)
            else {
                "available": False,
                "command": (
                    "shellforgeai recipes receipt compare "
                    "<before_receipt_id> <after_receipt_id> --json"
                ),
            },
        )
    if include_exports:
        exports: list[dict[str, Any]] = []
        for chain in audit_payload.get("chains") or []:
            for receipt in chain.get("receipts") or []:
                for item in receipt.get("exports") or []:
                    if isinstance(item, dict):
                        exports.append(item)
        _write_json_file(out / "receipt-export-index.json", {"exports": exports})

    bundle_payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "mode": AUDIT_BUNDLE_MODE,
        "status": "created",
        "read_only": True,
        "mutation_performed": False,
        "artifact_export_only": True,
        "bundle_id": bundle_id,
        "created_at": created_at,
        "bundle": {"bundle_id": bundle_id, "path": str(out), "files": files},
        "path": str(out),
        "files": files,
        "filters": filters,
        "receipt_audit_summary": audit_payload.get("summary") or {},
        "receipt_history_summary": {
            "count": history_payload.get("count", 0),
            "status": history_payload.get("status"),
        },
        "summary": summary,
        "findings": audit_payload.get("findings") or [],
        "warnings": warnings,
        "checksum_file": "checksums.json",
        "first_safe_command": first_safe,
        "safe_next_commands": safe_next,
        "safety": {**audit_safety(), "artifact_export_only": True},
    }
    _write_json_file(out / "audit-bundle.json", bundle_payload)
    (out / "audit-bundle.md").write_text(
        _render_audit_bundle_markdown(bundle_payload), encoding="utf-8"
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": AUDIT_BUNDLE_MANIFEST_KIND,
        "mode": "v2_recipe_receipt_audit_bundle_manifest",
        "bundle_id": bundle_id,
        "created_at": created_at,
        "generated_by": "shellforgeai recipes receipt audit-bundle",
        "source_command": "shellforgeai recipes receipt audit-bundle",
        "files": files,
        "checksums": {
            "stored_in": "checksums.json",
            "covers": [f for f in files if f != "checksums.json"],
        },
        "filters": filters,
        "safety": {**audit_safety(), "artifact_export_only": True},
    }
    _write_json_file(out / "manifest.json", manifest)
    checksums = {
        rel: _sha256_file(out / rel)
        for rel in files
        if rel != "checksums.json" and (out / rel).is_file()
    }
    _write_json_file(out / "checksums.json", {"algorithm": "sha256", "checksums": checksums})
    bundle_payload["checksums"] = {"stored_in": "checksums.json"}
    # Update audit-bundle after checksum generation without changing the checksum contract.
    # checksums.json verifies the support packet files and excludes itself.
    _write_json_file(out / "audit-bundle.json", bundle_payload)
    checksums["audit-bundle.json"] = _sha256_file(out / "audit-bundle.json")
    _write_json_file(out / "checksums.json", {"algorithm": "sha256", "checksums": checksums})
    return bundle_payload


def _resolve_audit_bundle_ref(ref: str, data_dir: Path | str) -> Path | None:
    raw = str(ref or "").strip()
    if not raw or ".." in Path(raw).parts:
        return None
    root = receipt_audit_bundle_root(data_dir).resolve()
    p = Path(raw).expanduser()
    resolved = (
        p.resolve() if p.is_absolute() or "/" in raw or "\\" in raw else (root / raw).resolve()
    )
    if resolved.is_file():
        resolved = resolved.parent
    try:
        resolved.relative_to(root)
    except ValueError:
        return None
    return resolved


def receipt_audit_bundle_validate(ref: str, data_dir: Path | str) -> dict[str, Any]:
    d = _resolve_audit_bundle_ref(ref, data_dir)
    required = [{"name": name, "status": "missing"} for name in _audit_bundle_required_files()]
    base = {
        "schema_version": SCHEMA_VERSION,
        "mode": AUDIT_BUNDLE_VALIDATE_MODE,
        "status": "failed",
        "read_only": True,
        "mutation_performed": False,
        "bundle_id": d.name if d else str(ref or ""),
        "path": str(d) if d else None,
        "required_files": required,
        "checksum_status": "not_checked",
        "warnings": [],
        "safety": audit_safety(),
    }
    warnings: list[str] = []
    if d is None or not d.is_dir():
        return {
            **base,
            "status": "not_found",
            "warnings": ["audit bundle not found or not ShellForgeAI-owned"],
        }
    json_ok = True
    for item in required:
        path = d / str(item["name"])
        if not path.is_file():
            item["status"] = "missing"
            warnings.append(f"missing required file: {item['name']}")
            json_ok = False
            continue
        item["status"] = "ok"
        if str(item["name"]).endswith(".json"):
            parsed, err = _read_json(path)
            if err or parsed is None:
                item["status"] = "malformed"
                warnings.append(f"malformed JSON in {item['name']}: {err}")
                json_ok = False
    manifest, manifest_err = _read_json(d / "manifest.json")
    if manifest_err or manifest is None:
        warnings.append(manifest_err or "malformed manifest")
        manifest = {}
    if manifest and manifest.get("kind") != AUDIT_BUNDLE_MANIFEST_KIND:
        warnings.append("manifest kind mismatch")
    if manifest and manifest.get("bundle_id") not in {None, d.name}:
        warnings.append("manifest bundle id mismatch")
    manifest_files = manifest.get("files") if isinstance(manifest.get("files"), list) else []
    missing_from_manifest = [
        name for name in _audit_bundle_required_files() if name not in set(map(str, manifest_files))
    ]
    if manifest and missing_from_manifest:
        warnings.append(
            "manifest files missing required entries: " + ", ".join(missing_from_manifest)
        )
    checksums_payload, checksums_err = _read_json(d / "checksums.json")
    checksum_status = "not_checked"
    if checksums_err or checksums_payload is None:
        warnings.append(checksums_err or "malformed checksums")
        checksum_status = "failed"
    else:
        checksum_status = "ok"
        checksums = (
            checksums_payload.get("checksums")
            if isinstance(checksums_payload.get("checksums"), dict)
            else {}
        )
        if not checksums:
            checksum_status = "failed"
            warnings.append("checksums missing")
        for rel, expected in checksums.items():
            rel_path = Path(str(rel))
            if rel_path.is_absolute() or ".." in rel_path.parts:
                checksum_status = "failed"
                warnings.append(f"unsafe path in checksums: {rel}")
                break
            path = (d / rel_path).resolve()
            try:
                path.relative_to(d.resolve())
            except ValueError:
                checksum_status = "failed"
                warnings.append(f"external path in checksums: {rel}")
                break
            if not path.is_file() or _sha256_file(path) != str(expected):
                checksum_status = "failed"
                warnings.append(f"checksum failed for {rel}")
                break
    status = "ok" if json_ok and not warnings and checksum_status == "ok" else "failed"
    return {
        **base,
        "status": status,
        "bundle_id": (manifest or {}).get("bundle_id") or d.name,
        "path": str(d),
        "required_files": required,
        "checksum_status": checksum_status,
        "warnings": warnings,
    }


def _resolve_and_validate_receipt(
    ref: str, data_dir: Path | str
) -> tuple[dict[str, Any] | None, Path | None, dict[str, Any], list[str]]:
    root = recipe_receipt_root(data_dir)
    d = _resolve_receipt_ref(ref, root)
    validation = validate_receipt(ref, data_dir)
    warnings = list(validation.get("warnings") or [])
    if d is None or not d.is_dir():
        return None, d, validation, warnings or ["receipt not found"]
    receipt, err = _read_json(d / "recipe-receipt.json")
    if err or receipt is None:
        warnings.append(err or "receipt could not be read")
        return None, d, {**validation, "status": "failed"}, warnings
    mode = receipt.get("mode")
    if mode not in _SUPPORTED_MODES:
        warnings.append(f"unsupported receipt mode: {mode or 'unknown'}")
    if validation.get("status") != "ok":
        warnings.append("receipt validation failed")
    return receipt, d, validation, warnings


def _artifact_paths(receipt_dir: Path, manifest: dict[str, Any] | None = None) -> list[str]:
    files = (
        manifest.get("files")
        if isinstance(manifest, dict) and isinstance(manifest.get("files"), list)
        else []
    )
    names = (
        [str(f) for f in files]
        if files
        else ["recipe-receipt.json", "recipe-receipt.md", "manifest.json"]
    )
    return [str(receipt_dir / name) for name in names if (receipt_dir / name).exists()]


def receipt_inspect(ref: str, data_dir: Path | str) -> dict[str, Any]:
    receipt, d, validation, warnings = _resolve_and_validate_receipt(ref, data_dir)
    status = "ok"
    if receipt is None:
        status = "not_found" if validation.get("status") == "not_found" else "failed"
    elif receipt.get("mode") not in _SUPPORTED_MODES:
        status = "unsupported"
    elif validation.get("status") != "ok":
        status = "failed"
    manifest: dict[str, Any] | None = None
    if d and (d / "manifest.json").exists():
        manifest, _ = _read_json(d / "manifest.json")
    safe_next = [
        "shellforgeai recipes receipt history",
        "shellforgeai recipes receipt compare-latest",
    ]
    if receipt:
        rid = str(receipt.get("receipt_id") or ref)
        safe_next = [
            f"shellforgeai recipes receipt verify {rid} --json",
            f"shellforgeai recipes receipt export {rid}",
            "shellforgeai recipes receipt history",
        ]
    verification = (
        receipt.get("verification")
        if receipt and isinstance(receipt.get("verification"), dict)
        else {}
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "mode": INSPECT_MODE,
        "status": status,
        "read_only": True,
        "mutation_performed": False,
        "identity": {
            "receipt_ref": ref,
            "receipt_id": receipt.get("receipt_id") if receipt else (d.name if d else None),
            "receipt_mode": receipt.get("mode") if receipt else None,
            "created_at": receipt.get("created_at") if receipt else None,
            "path": str(d) if d else None,
        },
        "lineage": _lineage(receipt or {}),
        "recipe": {
            "recipe_id": (receipt or {}).get("recipe_id"),
            "supported": (receipt or {}).get("recipe_id") == SUPPORTED_RECIPE,
        },
        "target": (receipt or {}).get("target"),
        "action": {
            "argv": list((receipt or {}).get("argv") or []),
            "command_executed": bool((receipt or {}).get("command_executed")),
            "return_code": (receipt or {}).get("return_code"),
            "status": (receipt or {}).get("status"),
        },
        "verification": verification or {"status": "not_run"},
        "safety_flags": (receipt or {}).get("safety")
        if isinstance((receipt or {}).get("safety"), dict)
        else {},
        "artifact_paths": _artifact_paths(d, manifest) if d else [],
        "validation": validation,
        "first_safe_command": safe_next[0],
        "safe_next_commands": safe_next,
        "safety": audit_safety(),
        "warnings": warnings,
    }
    return payload


def _contains_secret(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return False
    except OSError:
        return True
    return bool(_SECRET_RE.search(text))


def _copy_owned_bundle(
    src: Path, dst: Path, manifest: dict[str, Any]
) -> tuple[list[str], dict[str, str], list[str]]:
    warnings: list[str] = []
    copied: list[str] = []
    checksums: dict[str, str] = {}
    files = manifest.get("files") if isinstance(manifest.get("files"), list) else []
    rels = (
        [str(rel) for rel in files]
        if files
        else ["recipe-receipt.json", "recipe-receipt.md", "manifest.json"]
    )
    for rel in rels:
        rel_path = Path(rel)
        if rel_path.is_absolute() or ".." in rel_path.parts:
            warnings.append(f"refused unsafe artifact path in manifest: {rel}")
            continue
        source = (src / rel_path).resolve()
        try:
            source.relative_to(src.resolve())
        except ValueError:
            warnings.append(f"refused external artifact path in manifest: {rel}")
            continue
        if not source.is_file():
            warnings.append(f"missing artifact skipped: {rel}")
            continue
        if _contains_secret(source):
            warnings.append(f"refused export because secret-like token appeared in {rel}")
            return [], {}, warnings
        target = dst / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        copied.append(rel)
        checksums[rel] = _sha256_file(target)
    return copied, checksums, warnings


def receipt_export(ref: str, data_dir: Path | str) -> dict[str, Any]:
    receipt, d, validation, warnings = _resolve_and_validate_receipt(ref, data_dir)
    base = {
        "schema_version": SCHEMA_VERSION,
        "mode": EXPORT_MODE,
        "read_only": False,
        "mutation_performed": False,
        "metadata_write_only": True,
        "safety": audit_safety(),
    }
    if (
        receipt is None
        or d is None
        or validation.get("status") != "ok"
        or receipt.get("mode") not in _SUPPORTED_MODES
    ):
        return {
            **base,
            "status": "failed" if validation.get("status") != "not_found" else "not_found",
            "export_id": None,
            "export_path": None,
            "receipt_id": (receipt or {}).get("receipt_id"),
            "warnings": warnings or ["receipt validation failed"],
        }
    manifest, err = _read_json(d / "manifest.json")
    if err or manifest is None:
        return {
            **base,
            "status": "failed",
            "export_id": None,
            "export_path": None,
            "receipt_id": receipt.get("receipt_id"),
            "warnings": [*warnings, err or "manifest missing"],
        }
    export_id = f"receipt_export_{_now_stamp()}_{uuid.uuid4().hex[:6]}"
    out = (receipt_export_root(data_dir) / export_id).resolve()
    out.mkdir(parents=True, exist_ok=False)
    copied, checksums, copy_warnings = _copy_owned_bundle(d, out, manifest)
    warnings.extend(copy_warnings)
    if copy_warnings and not copied:
        shutil.rmtree(out, ignore_errors=True)
        return {
            **base,
            "status": "failed",
            "export_id": None,
            "export_path": None,
            "receipt_id": receipt.get("receipt_id"),
            "warnings": warnings,
        }
    export_manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": EXPORT_MANIFEST_KIND,
        "mode": "v2_recipe_receipt_export_manifest",
        "export_id": export_id,
        "created_at": _now_utc(),
        "source_receipt_id": receipt.get("receipt_id"),
        "source_receipt_mode": receipt.get("mode"),
        "original_receipt_id": receipt.get("original_receipt_id"),
        "recovery_receipt_id": receipt.get("recovery_receipt_id"),
        "recipe_id": receipt.get("recipe_id"),
        "target": receipt.get("target"),
        "files": [*copied, "export-manifest.json"],
        "checksums": checksums,
        "safety": audit_safety(),
    }
    (out / "export-manifest.json").write_text(
        json.dumps(export_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksums["export-manifest.json"] = _sha256_file(out / "export-manifest.json")
    export_manifest["checksums"] = checksums
    (out / "export-manifest.json").write_text(
        json.dumps(export_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        **base,
        "status": "ok",
        "export_id": export_id,
        "export_path": str(out),
        "receipt_id": receipt.get("receipt_id"),
        "checksums": checksums,
        "files": list(export_manifest["files"]),
        "warnings": warnings,
    }


def _resolve_export_ref(ref: str, data_dir: Path | str) -> Path | None:
    raw = str(ref or "").strip()
    if not raw:
        return None
    root = receipt_export_root(data_dir).resolve()
    p = Path(raw).expanduser()
    resolved = (
        p.resolve() if p.is_absolute() or "/" in raw or "\\" in raw else (root / raw).resolve()
    )
    if resolved.is_file():
        resolved = resolved.parent
    try:
        resolved.relative_to(root)
    except ValueError:
        return None
    return resolved


def receipt_export_validate(ref: str, data_dir: Path | str) -> dict[str, Any]:
    d = _resolve_export_ref(ref, data_dir)
    checks = {
        "required_files": False,
        "json_parse": False,
        "manifest": False,
        "checksums": False,
        "schema": False,
        "safety": False,
    }
    warnings: list[str] = []
    base = {
        "schema_version": SCHEMA_VERSION,
        "mode": EXPORT_VALIDATE_MODE,
        "status": "failed",
        "read_only": True,
        "mutation_performed": False,
        "export_id": d.name if d else None,
        "export_path": str(d) if d else None,
        "checks": checks,
        "safety": audit_safety(),
        "warnings": warnings,
    }
    if d is None or not d.is_dir():
        return {**base, "status": "not_found", "warnings": ["export not found"]}
    manifest_path = d / "export-manifest.json"
    if not manifest_path.exists():
        return {**base, "warnings": ["missing export manifest"]}
    checks["required_files"] = True
    manifest, err = _read_json(manifest_path)
    if err or manifest is None:
        return {**base, "warnings": [err or "malformed export manifest"]}
    checks["json_parse"] = True
    checks["schema"] = manifest.get("schema_version") == SCHEMA_VERSION
    checks["manifest"] = manifest.get("kind") == EXPORT_MANIFEST_KIND and bool(
        manifest.get("source_receipt_id")
    )
    safety = manifest.get("safety") if isinstance(manifest.get("safety"), dict) else {}
    checks["safety"] = (
        safety.get("docker_compose_executed") is False
        and safety.get("shell_true") is False
        and safety.get("arbitrary_command_execution") is False
    )
    manifest_checksums = (
        manifest.get("checksums") if isinstance(manifest.get("checksums"), dict) else {}
    )
    checks["checksums"] = bool(manifest_checksums)
    for rel, expected in manifest_checksums.items():
        if str(rel) == "export-manifest.json":
            continue
        rel_path = Path(str(rel))
        if rel_path.is_absolute() or ".." in rel_path.parts:
            checks["checksums"] = False
            warnings.append(f"unsafe path in export manifest: {rel}")
            break
        path = (d / rel_path).resolve()
        try:
            path.relative_to(d.resolve())
        except ValueError:
            checks["checksums"] = False
            warnings.append(f"external path in export manifest: {rel}")
            break
        if not path.is_file() or _sha256_file(path) != expected:
            checks["checksums"] = False
            warnings.append(f"checksum failed for {rel}")
            break
    warnings.extend(
        f"{key} check failed"
        for key, ok in checks.items()
        if not ok and f"{key} check failed" not in warnings
    )
    return {
        **base,
        "status": "ok" if all(checks.values()) else "failed",
        "export_id": manifest.get("export_id") or d.name,
        "receipt_id": manifest.get("source_receipt_id"),
        "recipe_id": manifest.get("recipe_id"),
        "target": manifest.get("target"),
        "checks": checks,
        "warnings": warnings,
    }


def _compare_fields(receipt: dict[str, Any]) -> dict[str, Any]:
    verification = (
        receipt.get("verification") if isinstance(receipt.get("verification"), dict) else {}
    )
    safety = receipt.get("safety") if isinstance(receipt.get("safety"), dict) else {}
    return {
        "receipt_id": receipt.get("receipt_id"),
        "mode": receipt.get("mode"),
        "recipe_id": receipt.get("recipe_id"),
        "target": receipt.get("target"),
        "status": receipt.get("status"),
        "created_at": receipt.get("created_at"),
        "action_argv": list(receipt.get("argv") or []),
        "verification_status": verification.get("status") or "not_run",
        "started_at_before": verification.get("started_at_before"),
        "started_at_after": verification.get("started_at_after"),
        "original_receipt_id": receipt.get("original_receipt_id"),
        "recovery_receipt_id": receipt.get("recovery_receipt_id"),
        "warnings": list(receipt.get("warnings") or []),
        "safety_flags": {key: safety.get(key) for key in sorted(safety)},
    }


def receipt_compare(before_ref: str, after_ref: str, data_dir: Path | str) -> dict[str, Any]:
    before, before_dir, before_validation, before_warnings = _resolve_and_validate_receipt(
        before_ref, data_dir
    )
    after, after_dir, after_validation, after_warnings = _resolve_and_validate_receipt(
        after_ref, data_dir
    )
    warnings = [*before_warnings, *after_warnings]
    base = {
        "schema_version": SCHEMA_VERSION,
        "mode": COMPARE_MODE,
        "read_only": True,
        "mutation_performed": False,
        "safety": audit_safety(),
        "warnings": warnings,
    }
    if (
        before is None
        or after is None
        or before_validation.get("status") != "ok"
        or after_validation.get("status") != "ok"
    ):
        return {
            **base,
            "status": "failed",
            "before": {"ref": before_ref, "path": str(before_dir) if before_dir else None},
            "after": {"ref": after_ref, "path": str(after_dir) if after_dir else None},
            "stable": {},
            "changed": {},
        }
    before_fields = _compare_fields(before)
    after_fields = _compare_fields(after)
    stable: dict[str, Any] = {}
    changed: dict[str, Any] = {}
    for key in sorted(set(before_fields) | set(after_fields)):
        if before_fields.get(key) == after_fields.get(key):
            stable[key] = before_fields.get(key)
        else:
            changed[key] = {"before": before_fields.get(key), "after": after_fields.get(key)}
    return {
        **base,
        "status": "ok",
        "before": {
            "ref": before_ref,
            "receipt_id": before.get("receipt_id"),
            "path": str(before_dir),
        },
        "after": {"ref": after_ref, "receipt_id": after.get("receipt_id"), "path": str(after_dir)},
        "stable": stable,
        "changed": changed,
    }


def receipt_compare_latest(data_dir: Path | str) -> dict[str, Any]:
    hist = receipt_history(data_dir, limit=2)
    if hist.get("count", 0) < 2:
        return {
            "schema_version": SCHEMA_VERSION,
            "mode": COMPARE_MODE,
            "status": "not_enough_history",
            "read_only": True,
            "mutation_performed": False,
            "stable": {},
            "changed": {},
            "safety": audit_safety(),
            "warnings": ["need at least two receipts to compare"],
        }
    receipts = hist["receipts"]
    # History is newest first: compare older before newer.
    return receipt_compare(str(receipts[1]["receipt_id"]), str(receipts[0]["receipt_id"]), data_dir)
