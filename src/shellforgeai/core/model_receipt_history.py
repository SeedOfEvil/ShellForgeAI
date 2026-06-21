"""Read-only history and compare helpers for Model Doctor live-probe receipts."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shellforgeai.core.model_receipt_validation import (
    REQUIRED_RECEIPT_FILES,
    validate_model_doctor_receipt,
)
from shellforgeai.core.read_only_safety import read_only_safety_metadata

MAX_CANDIDATES_SCANNED = 200
MAX_RETURNED_RECEIPTS = 50
MAX_INVALID_CANDIDATES = 20


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safety(extra_key: str) -> dict[str, bool]:
    data = read_only_safety_metadata(model_call_performed=False)
    data["live_probe_performed"] = False
    data[extra_key] = True
    data["github_post_approve_merge"] = False
    return data


def _looks_named(path: Path) -> bool:
    name = path.name.lower()
    return (
        (name.startswith("sfai-pr") and "live-probe-receipt" in name)
        or (name.startswith("sfai-") and "model-doctor-live-probe" in name)
        or ("model" in name and "doctor" in name and "receipt" in name)
    )


def _looks_receipt_shaped(path: Path) -> bool:
    return any((path / filename).exists() for filename in REQUIRED_RECEIPT_FILES)


def _reason(validation: dict[str, Any]) -> str:
    errors = " ".join(str(item).lower() for item in validation.get("errors", []))
    if "missing required" in errors or "does not exist" in errors:
        return "missing_required_files"
    if "secret marker" in errors:
        return "secret_marker_detected"
    if "checksum" in errors:
        return "checksum_mismatch"
    if "invalid json" in errors:
        return "invalid_json"
    return "unknown"


def _read_payload(path: Path) -> dict[str, Any]:
    try:
        value = json.loads((path / "model-doctor-live-probe.json").read_text(encoding="utf-8"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _created_at(path: Path, payload: dict[str, Any]) -> str:
    value = payload.get("created_at") or payload.get("timestamp")
    if isinstance(value, str) and value.strip():
        return value
    try:
        return (
            datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except OSError:
        return ""


def _metadata(path: Path, validation: dict[str, Any]) -> dict[str, Any]:
    payload = _read_payload(path)
    probe = payload.get("probe") if isinstance(payload.get("probe"), dict) else {}
    return {
        "path": str(path),
        "status": "valid" if validation.get("status") in {"passed", "partial"} else "invalid",
        "created_at": _created_at(path, payload),
        "probe_status": str(
            probe.get("status") or validation.get("summary", {}).get("probe_status") or "unknown"
        ),
        "auth_readiness": str(payload.get("auth_readiness") or "unknown"),
        "model_called": payload.get("model_called") is True,
        "live_probe_performed": payload.get("live_probe_performed") is True,
        "timeout_seconds": probe.get("timeout_seconds"),
        "latency_ms": probe.get("latency_ms"),
        "provider": probe.get("provider") or payload.get("provider"),
        "model": probe.get("model") or payload.get("model"),
        "validation_status": str(validation.get("status") or "failed"),
        "validation_errors": list(validation.get("errors") or []),
    }


def build_model_receipt_history(root: Path) -> dict[str, Any]:
    root = root.expanduser()
    warnings: list[str] = []
    valid: list[dict[str, Any]] = []
    invalid: list[dict[str, str]] = []
    ignored = 0
    scanned = 0
    candidates: list[Path] = []
    if root.exists() and root.is_dir():
        try:
            children = sorted((p for p in root.iterdir() if p.is_dir()), key=lambda p: p.name)[
                :MAX_CANDIDATES_SCANNED
            ]
        except OSError as exc:
            children = []
            warnings.append(f"unable to scan root: {exc}")
        for child in children:
            named = _looks_named(child)
            shaped = _looks_receipt_shaped(child)
            if named or shaped:
                candidates.append(child)
            else:
                ignored += 1
    else:
        warnings.append("root is missing or is not a directory")
    for candidate in candidates:
        scanned += 1
        validation = validate_model_doctor_receipt(candidate)
        if validation.get("status") in {"passed", "partial"}:
            valid.append(_metadata(candidate, validation))
        elif len(invalid) < MAX_INVALID_CANDIDATES:
            invalid.append({"path": str(candidate), "reason": _reason(validation)})
    valid.sort(
        key=lambda item: (str(item.get("created_at") or ""), str(item.get("path") or "")),
        reverse=True,
    )
    returned = valid[:MAX_RETURNED_RECEIPTS]
    latest = returned[0] if returned else {}
    status = "empty" if not candidates and not valid else "partial" if invalid else "ok"
    if warnings and status != "empty":
        status = "partial"
    return {
        "schema_version": 1,
        "mode": "model_doctor_receipt_history",
        "status": status,
        "root": str(root),
        "created_at": _now_iso(),
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "candidates_scanned": scanned,
            "valid_receipts": len(valid),
            "invalid_receipts": len(invalid),
            "ignored_candidates": ignored,
            "latest_valid_receipt": latest.get("path"),
            "latest_probe_status": latest.get("probe_status", "unknown"),
            "latest_auth_readiness": latest.get("auth_readiness", "unknown"),
            "latest_model_called": latest.get("model_called"),
            "latest_live_probe_performed": latest.get("live_probe_performed"),
        },
        "receipts": returned,
        "invalid_candidates": invalid,
        "warnings": warnings,
        "safety": _safety("history_only"),
        "first_safe_command": f"shellforgeai model receipt history --root {root} --json",
    }


def render_model_receipt_history_markdown(result: dict[str, Any]) -> str:
    s = result["summary"]
    latest = result.get("receipts", [{}])[0] if result.get("receipts") else {}
    warnings = result.get("warnings") or ["none"]
    return (
        "# Model Doctor Receipt History\n\n"
        f"Root: {result['root']}\n"
        f"Status: {result['status']}\n"
        f"Valid receipts: {s['valid_receipts']}\n"
        f"Invalid receipts: {s['invalid_receipts']}\n"
        f"Latest valid receipt: {s.get('latest_valid_receipt') or 'none'}\n\n"
        "## Latest receipt\n"
        f"* probe status: {latest.get('probe_status', 'unknown')}\n"
        f"* auth readiness: {latest.get('auth_readiness', 'unknown')}\n"
        f"* live probe performed: {latest.get('live_probe_performed', False)}\n"
        f"* model called: {latest.get('model_called', False)}\n"
        f"* latency: {latest.get('latency_ms', 'unknown')}\n"
        f"* timeout: {latest.get('timeout_seconds', 'unknown')}\n\n"
        "## Warnings\n" + "".join(f"* {w}\n" for w in warnings) + "\n## Safety\n"
        "* history only\n* no live probe performed\n* no model call performed\n"
        "* no cleanup/prune/delete/restart\n* no remediation/rollback/recovery\n"
        "* no natural-language execution\n* no shell="
        "True\n"
    )


def build_model_receipt_compare(old: Path, new: Path) -> dict[str, Any]:
    old_v = validate_model_doctor_receipt(old)
    new_v = validate_model_doctor_receipt(new)
    old_m = _metadata(old.expanduser(), old_v)
    new_m = _metadata(new.expanduser(), new_v)
    blocking = {_reason(old_v), _reason(new_v)} & {
        "checksum_mismatch",
        "invalid_json",
        "secret_marker_detected",
        "missing_required_files",
    }
    if blocking:
        status = "failed"
    elif old_v.get("status") == "partial" or new_v.get("status") == "partial":
        status = "partial"
    else:
        status = "ok"
    delta = {
        "probe_status_changed": old_m["probe_status"] != new_m["probe_status"],
        "auth_readiness_changed": old_m["auth_readiness"] != new_m["auth_readiness"],
        "latency_ms_delta": (new_m.get("latency_ms") or 0) - (old_m.get("latency_ms") or 0),
        "timeout_seconds_delta": (new_m.get("timeout_seconds") or 0)
        - (old_m.get("timeout_seconds") or 0),
        "model_changed": old_m.get("model") != new_m.get("model"),
        "provider_changed": old_m.get("provider") != new_m.get("provider"),
    }
    notable = [
        key
        for key, value in delta.items()
        if (isinstance(value, bool) and value) or (isinstance(value, int) and value != 0)
    ]

    def slim(item: dict[str, Any]) -> dict[str, Any]:
        return {
            k: item.get(k)
            for k in (
                "path",
                "validation_status",
                "probe_status",
                "auth_readiness",
                "latency_ms",
                "timeout_seconds",
            )
        }

    return {
        "schema_version": 1,
        "mode": "model_doctor_receipt_compare",
        "status": status,
        "created_at": _now_iso(),
        "read_only": True,
        "mutation_performed": False,
        "old_receipt": slim(old_m),
        "new_receipt": slim(new_m),
        "delta": delta,
        "notable_changes": notable,
        "warnings": [],
        "safety": _safety("compare_only"),
        "first_safe_command": "shellforgeai model receipt compare <old> <new> --json",
    }


def render_model_receipt_compare_markdown(result: dict[str, Any]) -> str:
    old = result["old_receipt"]
    new = result["new_receipt"]
    delta = result["delta"]
    notable = result.get("notable_changes") or ["none"]
    return (
        "# Model Doctor Receipt Compare\n\n"
        f"Old receipt: {old['path']}\nNew receipt: {new['path']}\nStatus: {result['status']}\n\n"
        "## Probe result\n"
        f"* old: {old.get('probe_status', 'unknown')}\n"
        f"* new: {new.get('probe_status', 'unknown')}\n"
        f"* changed: {delta['probe_status_changed']}\n\n"
        "## Auth readiness\n"
        f"* old: {old.get('auth_readiness', 'unknown')}\n"
        f"* new: {new.get('auth_readiness', 'unknown')}\n"
        f"* changed: {delta['auth_readiness_changed']}\n\n"
        "## Latency\n"
        f"* old: {old.get('latency_ms')}\n"
        f"* new: {new.get('latency_ms')}\n"
        f"* delta: {delta['latency_ms_delta']}\n\n"
        "## Notable changes\n" + "".join(f"* {item}\n" for item in notable) + "\n## Safety\n"
        "* compare only\n* no live probe performed\n* no model call performed\n"
        "* no cleanup/prune/delete/restart\n* no remediation/rollback/recovery\n"
        "* no natural-language execution\n* no shell="
        "True\n"
    )
