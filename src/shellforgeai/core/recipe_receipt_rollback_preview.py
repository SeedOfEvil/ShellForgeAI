"""Read-only rollback posture preview for governed recipe execution receipts.

This module only reads ShellForgeAI-owned receipt artifacts and explains future
rollback/recovery gates. It never executes rollback, Docker, Compose, shell, or
model calls, and it never writes rollback receipts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shellforgeai.core.recipe_execution import (
    RECEIPT_MODE,
    SCHEMA_VERSION,
    _resolve_receipt_ref,
    recipe_receipt_root,
    validate_receipt,
)
from shellforgeai.core.recipe_preflight import SUPPORTED_RECIPE

ROLLBACK_PREVIEW_MODE = "v2_receipt_rollback_preview"


def rollback_preview_safety() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "rollback_executed": False,
        "remediation_executed": False,
        "cleanup_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "model_called": False,
    }


def _base_payload(
    receipt_ref: str,
    *,
    status: str,
    receipt_path: Path | None = None,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    safety = rollback_preview_safety()
    receipt_id = receipt_path.name if receipt_path else None
    first_safe = (
        f"shellforgeai recipes receipt verify {receipt_ref} --json"
        if status in {"unsupported_recipe", "failed", "not_found"}
        else f"shellforgeai verify --receipt {receipt_id or receipt_ref} --json"
    )
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "mode": ROLLBACK_PREVIEW_MODE,
        "status": status,
        "read_only": True,
        "mutation_performed": False,
        "receipt_ref": receipt_ref,
        "receipt_id": receipt_id,
        "recipe_id": None,
        "target": {
            "name": None,
            "production_target": False,
            "found_in_receipt": False,
        },
        "rollback": {
            "true_rollback_available": False,
            "recovery_action_available_future": False,
            "recovery_action": None,
            "execution_available": False,
            "confirm_required": True,
            "receipt_required": True,
            "verification_required": True,
        },
        "gates": [
            {"name": "receipt_valid", "status": "failed"},
            {"name": "exact_target_required", "status": "required"},
            {"name": "production_target_refused", "status": "required"},
            {"name": "disposable_label_required", "status": "required_at_execution_time"},
            {"name": "allow_restart_label_required", "status": "required_at_execution_time"},
            {"name": "explicit_confirm_required", "status": "future_gate"},
            {"name": "rollback_receipt_required", "status": "future_gate"},
            {"name": "post_rollback_verify_required", "status": "future_gate"},
        ],
        "warnings": warnings or [],
        "first_safe_command": first_safe,
        "safe_next_commands": [first_safe],
        "safety": safety,
        **safety,
    }
    return payload


def _read_receipt(
    receipt_ref: str, data_dir: Path | str
) -> tuple[dict[str, Any] | None, Path | None, str | None]:
    root = recipe_receipt_root(data_dir)
    receipt_dir = _resolve_receipt_ref(receipt_ref, root)
    if receipt_dir is None or not receipt_dir.is_dir():
        return None, receipt_dir, "receipt not found"
    try:
        receipt = json.loads((receipt_dir / "recipe-receipt.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, receipt_dir, "receipt JSON not found"
    except Exception as exc:
        return None, receipt_dir, f"malformed receipt JSON: {exc}"
    if not isinstance(receipt, dict):
        return None, receipt_dir, "malformed receipt JSON: top-level value is not an object"
    return receipt, receipt_dir, None


def _target_from_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    post_state = receipt.get("post_state") if isinstance(receipt.get("post_state"), dict) else {}
    name = str(receipt.get("target") or post_state.get("name") or "").strip()
    return {
        "name": name or None,
        "production_target": bool(post_state.get("production_target")),
        "found_in_receipt": bool(name),
    }


def _limited_gates(*, receipt_valid: bool, exact_target: bool) -> list[dict[str, str]]:
    return [
        {"name": "receipt_valid", "status": "passed" if receipt_valid else "failed"},
        {"name": "exact_target_required", "status": "passed" if exact_target else "failed"},
        {"name": "production_target_refused", "status": "required"},
        {"name": "disposable_label_required", "status": "required_at_execution_time"},
        {"name": "allow_restart_label_required", "status": "required_at_execution_time"},
        {"name": "explicit_confirm_required", "status": "future_gate"},
        {"name": "rollback_receipt_required", "status": "future_gate"},
        {"name": "post_rollback_verify_required", "status": "future_gate"},
    ]


def _docker_disposable_rollback() -> dict[str, Any]:
    return {
        "true_rollback_available": False,
        "recovery_action_available_future": True,
        "recovery_action": "exact_target_disposable_restart",
        "execution_available": False,
        "confirm_required": True,
        "receipt_required": True,
        "verification_required": True,
    }


def preview_receipt_rollback(receipt_ref: str, data_dir: Path | str) -> dict[str, Any]:
    """Return a read-only rollback posture preview for a governed receipt."""

    receipt, receipt_dir, read_error = _read_receipt(receipt_ref, data_dir)
    if receipt is None:
        status = "not_found" if read_error == "receipt not found" else "failed"
        return _base_payload(
            receipt_ref, status=status, receipt_path=receipt_dir, warnings=[read_error or status]
        )

    receipt_id = str(
        receipt.get("receipt_id") or (receipt_dir.name if receipt_dir else receipt_ref)
    )
    recipe_id = str(receipt.get("recipe_id") or "")
    target = _target_from_receipt(receipt)
    validation = validate_receipt(receipt_ref, data_dir)
    validation_warnings = list(validation.get("warnings") or [])
    schema_valid = (
        receipt.get("schema_version") == SCHEMA_VERSION and receipt.get("mode") == RECEIPT_MODE
    )
    target_valid = bool(target.get("name"))
    safety = receipt.get("safety") if isinstance(receipt.get("safety"), dict) else {}
    safety_valid = (
        safety.get("docker_compose_executed") is False
        and safety.get("shell_true") is False
        and safety.get("arbitrary_command_execution") is False
        and safety.get("natural_language_execution") is False
    )
    if not schema_valid or not target_valid or not safety_valid:
        warnings = validation_warnings or ["receipt schema, target, or safety metadata is invalid"]
        payload = _base_payload(
            receipt_ref, status="failed", receipt_path=receipt_dir, warnings=warnings
        )
        payload.update(
            {
                "receipt_id": receipt_id,
                "recipe_id": recipe_id or None,
                "target": target,
                "gates": _limited_gates(receipt_valid=False, exact_target=target_valid),
            }
        )
        return payload

    if recipe_id != SUPPORTED_RECIPE:
        payload = _base_payload(
            receipt_ref,
            status="unsupported_recipe",
            receipt_path=receipt_dir,
            warnings=[f"unsupported recipe for rollback-preview: {recipe_id or 'unknown'}"],
        )
        payload.update(
            {
                "receipt_id": receipt_id,
                "recipe_id": recipe_id or None,
                "target": target,
                "gates": _limited_gates(receipt_valid=True, exact_target=target_valid),
                "first_safe_command": f"shellforgeai recipes receipt verify {receipt_id} --json",
                "safe_next_commands": [f"shellforgeai recipes receipt verify {receipt_id} --json"],
            }
        )
        return payload

    first_safe = f"shellforgeai verify --receipt {receipt_id} --json"
    safe_next = [first_safe, f"shellforgeai recipes receipt verify {receipt_id} --json"]
    status = "blocked" if target.get("production_target") else "limited"
    warnings = [] if validation.get("status") == "ok" else validation_warnings
    if target.get("production_target"):
        warnings = ["production target refused for rollback/recovery", *warnings]
    payload = _base_payload(receipt_ref, status=status, receipt_path=receipt_dir, warnings=warnings)
    payload.update(
        {
            "receipt_id": receipt_id,
            "recipe_id": recipe_id,
            "target": target,
            "rollback": _docker_disposable_rollback(),
            "gates": _limited_gates(
                receipt_valid=validation.get("status") == "ok", exact_target=target_valid
            ),
            "first_safe_command": first_safe,
            "safe_next_commands": safe_next,
        }
    )
    if target.get("production_target"):
        payload["reason"] = "production target refused for rollback/recovery"
        payload["rollback"]["recovery_action_available_future"] = False
    return payload
