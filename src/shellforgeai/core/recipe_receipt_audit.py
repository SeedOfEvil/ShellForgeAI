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


def audit_safety() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
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
