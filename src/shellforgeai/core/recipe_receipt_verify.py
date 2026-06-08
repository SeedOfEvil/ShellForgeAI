"""Read-only V2 receipt-aware verification for governed recipe receipts.

This module verifies what an existing governed execution receipt records.  It
never re-executes a recipe, calls Docker/Compose, retries, rolls back, or writes
new artifacts.
"""

from __future__ import annotations

import json
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

VERIFY_RECEIPT_MODE = "v2_verify"


def _verify_safety() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "verify_executed_command": False,
        "apply_executed": False,
        "mission_created": False,
        "plan_created": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "cleanup_executed": False,
        "docker_compose_executed": False,
        "container_restarted_by_verify": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "model_called": False,
    }


def _base_payload(
    receipt_ref: str, *, status: str, receipt_path: Path | None = None
) -> dict[str, Any]:
    safety = _verify_safety()
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": VERIFY_RECEIPT_MODE,
        "verification_type": "receipt",
        "status": status,
        "read_only": True,
        "mutation_performed": False,
        "receipt": {
            "receipt_ref": receipt_ref,
            "receipt_id": receipt_path.name if receipt_path else None,
            "found": bool(receipt_path and receipt_path.is_dir()),
            "valid": False,
            "path": str(receipt_path) if receipt_path else None,
        },
        "recipe": {"recipe_id": None, "supported": False},
        "target": {
            "name": None,
            "found": False,
            "production_target": False,
            "disposable": False,
            "allowlisted": False,
        },
        "execution": {
            "action_recorded": False,
            "action_result": "unknown",
            "command_preview_only": False,
            "command_executed": False,
            "exact_target_only": False,
            "argv": [],
            "recorded_action": "",
        },
        "post_check": {
            "verification_status": "unknown",
            "signals": [],
            "limitations": ["Receipt could not be verified as a supported governed receipt."],
        },
        "first_safe_command": "shellforgeai recipes list --json",
        "safe_next_commands": ["shellforgeai recipes list --json"],
        "warnings": [],
        "safety": safety,
        **safety,
    }


def _read_receipt(
    receipt_ref: str, data_dir: Path | str
) -> tuple[dict[str, Any] | None, Path | None, str | None]:
    root = recipe_receipt_root(data_dir)
    d = _resolve_receipt_ref(receipt_ref, root)
    if d is None or not d.is_dir():
        return None, d, "receipt not found"
    try:
        receipt = json.loads((d / "recipe-receipt.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, d, "receipt JSON not found"
    except Exception as exc:
        return None, d, f"malformed receipt JSON: {exc}"
    if not isinstance(receipt, dict):
        return None, d, "malformed receipt JSON: top-level value is not an object"
    return receipt, d, None


def _target_from_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    post_state = receipt.get("post_state") if isinstance(receipt.get("post_state"), dict) else {}
    return {
        "name": str(receipt.get("target") or post_state.get("name") or "") or None,
        "found": bool(post_state.get("found")),
        "production_target": bool(post_state.get("production_target")),
        "disposable": bool(post_state.get("disposable")),
        "allowlisted": bool(post_state.get("allowlisted")),
    }


def _action_result(receipt_status: str) -> str:
    if receipt_status == "executed":
        return "executed"
    if receipt_status in {"failed", "verification_failed"}:
        return "failed"
    if receipt_status == "blocked":
        return "blocked"
    return "unknown"


def _status_from_receipt(
    *,
    receipt: dict[str, Any],
    validation: dict[str, Any],
    warnings: list[str],
) -> str:
    recipe_id = str(receipt.get("recipe_id") or "")
    if recipe_id != SUPPORTED_RECIPE:
        return "unsupported"
    safety = receipt.get("safety") if isinstance(receipt.get("safety"), dict) else {}
    validation_checks = (
        validation.get("checks") if isinstance(validation.get("checks"), dict) else {}
    )
    if safety.get("docker_compose_executed") is not False or safety.get("shell_true") is not False:
        warnings.append("receipt safety flags drifted from governed recipe constraints")
        return "safety_drift"
    if (
        safety.get("arbitrary_command_execution") is not False
        or safety.get("natural_language_execution") is not False
    ):
        warnings.append("receipt safety flags drifted from governed recipe constraints")
        return "safety_drift"
    if validation_checks and validation_checks.get("safety") is False:
        warnings.append("receipt safety validation failed")
        return "safety_drift"
    receipt_status = str(receipt.get("status") or "")
    verification = (
        receipt.get("verification") if isinstance(receipt.get("verification"), dict) else {}
    )
    verification_status = str(verification.get("status") or "unknown")
    if (
        receipt_status == "executed"
        and verification_status == "passed"
        and validation.get("status") == "ok"
    ):
        return "passed"
    if receipt_status in {"failed", "verification_failed", "blocked"}:
        return "failed"
    if validation.get("status") != "ok":
        return "failed"
    return "unknown"


def verify_recipe_receipt(receipt_ref: str, data_dir: Path | str) -> dict[str, Any]:
    """Verify a governed recipe execution receipt without executing anything."""

    receipt, receipt_dir, read_error = _read_receipt(receipt_ref, data_dir)
    if receipt is None:
        status = "not_found" if read_error == "receipt not found" else "failed"
        payload = _base_payload(receipt_ref, status=status, receipt_path=receipt_dir)
        payload["warnings"] = [read_error or "receipt could not be read"]
        return payload

    validation = validate_receipt(receipt_ref, data_dir)
    validation_warnings = list(validation.get("warnings") or [])
    warnings = validation_warnings.copy()
    recipe_id = str(receipt.get("recipe_id") or "")
    target = _target_from_receipt(receipt)
    safety = receipt.get("safety") if isinstance(receipt.get("safety"), dict) else {}
    verification = (
        receipt.get("verification") if isinstance(receipt.get("verification"), dict) else {}
    )
    argv = [str(part) for part in (receipt.get("argv") or [])]
    receipt_status = str(receipt.get("status") or "unknown")
    status = _status_from_receipt(receipt=receipt, validation=validation, warnings=warnings)
    if status == "unsupported":
        first_safe = "shellforgeai recipes list --json"
        safe_next = [first_safe]
    else:
        first_safe = "shellforgeai handoff --json"
        preflight_id = str(receipt.get("preflight_id") or "")
        safe_next = [first_safe]
        if status in {"failed", "safety_drift"} and preflight_id:
            safe_next.append(f"shellforgeai recipes preflight validate {preflight_id} --json")

    payload = _base_payload(receipt_ref, status=status, receipt_path=receipt_dir)
    payload.update(
        {
            "receipt": {
                "receipt_ref": receipt_ref,
                "receipt_id": str(
                    receipt.get("receipt_id") or (receipt_dir.name if receipt_dir else "")
                ),
                "found": True,
                "valid": validation.get("status") == "ok",
                "path": str(receipt_dir) if receipt_dir else None,
                "receipt_status": receipt_status,
                "preflight_id": receipt.get("preflight_id"),
                "original_receipt_id": receipt.get("original_receipt_id"),
                "recovery_receipt_id": receipt.get("recovery_receipt_id"),
            },
            "recipe": {"recipe_id": recipe_id or None, "supported": recipe_id == SUPPORTED_RECIPE},
            "target": target,
            "execution": {
                "action_recorded": bool(receipt.get("action_attempted") or argv),
                "action_result": _action_result(receipt_status),
                "command_preview_only": False,
                "command_executed": bool(receipt.get("command_executed")),
                "exact_target_only": bool(safety.get("exact_target_only")),
                "argv": argv,
                "recorded_action": " ".join(argv),
                "return_code": receipt.get("return_code"),
            },
            "post_check": {
                "verification_status": str(verification.get("status") or "unknown"),
                "signals": [
                    {"name": key, "value": value}
                    for key, value in verification.items()
                    if key != "status"
                ],
                "limitations": [
                    "Receipt-aware verify uses evidence recorded in the receipt.",
                    "Verify did not re-run Docker inspection or restart the target.",
                ],
            },
            "first_safe_command": first_safe,
            "safe_next_commands": safe_next,
            "warnings": warnings,
        }
    )
    if (
        receipt.get("mode") not in {RECEIPT_MODE, RECOVERY_RECEIPT_MODE}
        or receipt.get("schema_version") != SCHEMA_VERSION
    ):
        payload["status"] = "failed"
        payload["warnings"] = [*warnings, "receipt schema or mode is invalid"]
    return payload
