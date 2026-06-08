"""Confirm-gated recovery execution for disposable restart receipts.

This is not true rollback.  For ``docker.disposable_restart`` the only
supported recovery action is one repeat exact-target disposable restart from a
valid governed execution receipt, after the target is re-gated at execution
time and the operator passes explicit CLI confirmation.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shellforgeai.core.recipe_execution import (
    SCHEMA_VERSION,
    CommandResult,
    DockerContainerState,
    DockerExactTargetClient,
    _current_gate_blockers,
    _is_exact_target,
    _resolve_receipt_ref,
    _sha256_file,
    _summary,
    _target_payload,
    recipe_receipt_root,
    validate_receipt,
)
from shellforgeai.core.recipe_preflight import SUPPORTED_RECIPE
from shellforgeai.core.recipe_registry import BROAD_TARGETS, PRODUCTION_TARGETS

RECOVERY_EXECUTE_MODE = "v2_receipt_recovery_execute"
RECOVERY_RECEIPT_MODE = "v2_recipe_recovery_receipt"
RECOVERY_MANIFEST_KIND = "v2_recipe_recovery_receipt"


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _base_safety(*, attempted: bool = False, success: bool = False) -> dict[str, bool]:
    return {
        "read_only": False,
        "mutation_performed": bool(success),
        "recovery_executed": bool(success),
        "rollback_executed": False,
        "remediation_executed": False,
        "cleanup_executed": False,
        "docker_compose_executed": False,
        "container_restarted": bool(success),
        "production_restart_executed": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "model_called": False,
        "exact_target_only": True,
        "command_executed": bool(attempted),
    }


def _blocked_safety() -> dict[str, bool]:
    safety = _base_safety(attempted=False, success=False)
    safety["read_only"] = True
    return safety


def _blocked_payload(
    receipt_ref: str,
    *,
    status: str = "blocked",
    reason: str,
    receipt_id: str | None = None,
    recipe_id: str | None = None,
    target: dict[str, Any] | None = None,
    confirm_provided: bool = False,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    safety = _blocked_safety()
    action = {
        "argv": [],
        "docker_restart_attempted": False,
        "docker_restart_succeeded": False,
        "docker_compose_executed": False,
        "shell_true": False,
    }
    payload = {
        "schema_version": SCHEMA_VERSION,
        "mode": RECOVERY_EXECUTE_MODE,
        "status": status,
        "reason": reason,
        "receipt_ref": receipt_ref,
        "receipt_id": receipt_id,
        "recovery_receipt_id": None,
        "recipe_id": recipe_id,
        "target": target,
        "confirm_required": True,
        "confirm_provided": bool(confirm_provided),
        "exact_target_only": True,
        "mutation_performed": False,
        "action": action,
        "verification": {"status": "not_run", "restart_verified": False},
        "safety": safety,
        "warnings": warnings or [reason],
        **safety,
    }
    return payload


def _read_receipt(
    receipt_ref: str, data_dir: Path | str
) -> tuple[dict[str, Any] | None, Path | None, str | None]:
    root = recipe_receipt_root(data_dir)
    d = _resolve_receipt_ref(receipt_ref, root)
    if d is None or not d.is_dir():
        return None, d, "receipt not found"
    try:
        payload = json.loads((d / "recipe-receipt.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        try:
            payload = json.loads((d / "receipt.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None, d, "receipt JSON not found"
        except Exception as exc:
            return None, d, f"malformed receipt JSON: {exc}"
    except Exception as exc:
        return None, d, f"malformed receipt JSON: {exc}"
    if not isinstance(payload, dict):
        return None, d, "malformed receipt JSON: top-level value is not an object"
    return payload, d, None


def _receipt_target(receipt: dict[str, Any]) -> str:
    post_state = receipt.get("post_state") if isinstance(receipt.get("post_state"), dict) else {}
    return str(receipt.get("target") or post_state.get("name") or "").strip()


def _current_target_blocker(target: str, state: DockerContainerState) -> str | None:
    if target.strip().lower() in BROAD_TARGETS or target.strip().lower().startswith(
        "docker-compose"
    ):
        return "broad target refused"
    if any(token in target.strip().lower() for token in ("*", " ", "/")):
        return "broad or invalid target refused"
    if not _is_exact_target(target):
        return "broad or invalid target refused"
    if target.lower() in PRODUCTION_TARGETS or state.name.lower() in PRODUCTION_TARGETS:
        return "production target refused"
    blockers = _current_gate_blockers(target, state)
    if blockers:
        return blockers[0]
    return None


def _verification(
    pre: DockerContainerState, post: DockerContainerState, target: str, command_ok: bool
) -> dict[str, Any]:
    target_match = post.found and post.name == target
    started_changed = bool(pre.started_at and post.started_at and pre.started_at != post.started_at)
    labels_ok = not _current_gate_blockers(target, post)
    restart_verified = command_ok and target_match and started_changed and labels_ok
    return {
        "status": "passed" if restart_verified else "failed",
        "restart_verified": restart_verified,
        "started_at_before": pre.started_at,
        "started_at_after": post.started_at,
        "started_at_changed": started_changed,
        "container_id_before": pre.container_id,
        "container_id_after": post.container_id,
        "target_match": target_match,
        "command_ok": command_ok,
        "current_labels_match": labels_ok,
    }


def _render_markdown(receipt: dict[str, Any]) -> str:
    lines = [
        "# ShellForgeAI Recipe Recovery Receipt",
        "",
        f"- status: {receipt.get('status')}",
        f"- recipe: {receipt.get('recipe_id')}",
        f"- target: {receipt.get('target')}",
        f"- recovery_receipt_id: {receipt.get('recovery_receipt_id')}",
        f"- original_receipt_id: {receipt.get('original_receipt_id')}",
        "",
        "## Recovery action",
        "- note: bounded recovery restart; not true rollback of prior process state",
        "- argv: " + " ".join(str(part) for part in receipt.get("argv") or []),
        f"- command_executed: {str(bool(receipt.get('command_executed'))).lower()}",
        f"- return_code: {receipt.get('return_code')}",
        "",
        "## Verification",
    ]
    for key, value in (receipt.get("verification") or {}).items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Safety"])
    for key, value in (receipt.get("safety") or {}).items():
        lines.append(f"- {key}: {str(value).lower()}")
    warnings = receipt.get("warnings") or []
    if warnings:
        lines.extend(["", "## Warnings"])
        lines.extend(f"- {warning}" for warning in warnings)
    return "\n".join(lines).rstrip() + "\n"


def _write_recovery_receipt(
    data_dir: Path | str,
    *,
    original_receipt_id: str,
    recipe_id: str,
    target: str,
    status: str,
    pre_state: DockerContainerState,
    post_state: DockerContainerState,
    action: CommandResult,
    verification: dict[str, Any],
    safety: dict[str, bool],
    warnings: list[str],
) -> dict[str, Any]:
    rid = f"recovery_receipt_{_now_stamp()}_{uuid.uuid4().hex[:6]}"
    out = (recipe_receipt_root(data_dir) / rid).resolve()
    out.mkdir(parents=True, exist_ok=False)
    created_at = _now_utc()
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "mode": RECOVERY_RECEIPT_MODE,
        "status": status,
        "receipt_id": rid,
        "recovery_receipt_id": rid,
        "original_receipt_id": original_receipt_id,
        "recipe_id": recipe_id,
        "target": target,
        "action_attempted": action.argv == ["docker", "restart", target],
        "argv": list(action.argv),
        "command_executed": bool(safety.get("command_executed")),
        "operator_confirmation": True,
        "return_code": action.return_code,
        "stdout_summary": _summary(action.stdout),
        "stderr_summary": _summary(action.stderr),
        "pre_state": pre_state.to_dict(),
        "post_state": post_state.to_dict(),
        "verification": verification,
        "recovery_posture": {
            "true_rollback_available": False,
            "bounded_recovery_restart": True,
            "note": (
                "Docker restart cannot restore the prior process state; "
                "this repeated the exact disposable restart target only."
            ),
        },
        "safety": safety,
        "warnings": warnings,
        "created_at": created_at,
    }
    json_path = out / "recipe-receipt.json"
    alias_json_path = out / "receipt.json"
    md_path = out / "receipt.md"
    legacy_md_path = out / "recipe-receipt.md"
    manifest_path = out / "manifest.json"
    body = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    json_path.write_text(body, encoding="utf-8")
    alias_json_path.write_text(body, encoding="utf-8")
    md = _render_markdown(receipt)
    md_path.write_text(md, encoding="utf-8")
    legacy_md_path.write_text(md, encoding="utf-8")
    files = ["recipe-receipt.json", "receipt.json", "recipe-receipt.md", "receipt.md"]
    checksums = {rel: _sha256_file(out / rel) for rel in files}
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": RECOVERY_MANIFEST_KIND,
        "mode": "v2_recipe_receipt_manifest",
        "receipt_id": rid,
        "recovery_receipt_id": rid,
        "original_receipt_id": original_receipt_id,
        "created_at": created_at,
        "recipe_id": recipe_id,
        "target": target,
        "files": [*files, "manifest.json"],
        "checksums": checksums,
        "safety": safety,
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksums["manifest.json"] = _sha256_file(manifest_path)
    manifest["checksums"] = checksums
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    receipt["receipt_path"] = str(out)
    receipt["manifest_path"] = str(manifest_path)
    receipt["files"] = list(manifest["files"])
    receipt["checksums"] = checksums
    body = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    json_path.write_text(body, encoding="utf-8")
    alias_json_path.write_text(body, encoding="utf-8")
    checksums["recipe-receipt.json"] = _sha256_file(json_path)
    checksums["receipt.json"] = _sha256_file(alias_json_path)
    manifest["checksums"] = checksums
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return receipt


def execute_receipt_recovery(
    receipt_ref: str,
    data_dir: Path | str,
    *,
    confirm: bool,
    docker: Any | None = None,
) -> dict[str, Any]:
    if not confirm:
        return _blocked_payload(
            receipt_ref,
            reason="explicit --confirm required",
            confirm_provided=False,
        )

    receipt, _receipt_dir, read_error = _read_receipt(receipt_ref, data_dir)
    if receipt is None:
        status = "not_found" if read_error == "receipt not found" else "failed"
        return _blocked_payload(
            receipt_ref,
            status=status,
            reason=read_error or "receipt could not be read",
            confirm_provided=True,
        )

    original_receipt_id = str(
        receipt.get("receipt_id") or (_receipt_dir.name if _receipt_dir else receipt_ref)
    )
    recipe_id = str(receipt.get("recipe_id") or "")
    if recipe_id != SUPPORTED_RECIPE:
        return _blocked_payload(
            receipt_ref,
            status="unsupported_recipe",
            reason=f"unsupported recipe for recovery: {recipe_id or 'unknown'}",
            receipt_id=original_receipt_id,
            recipe_id=recipe_id or None,
            confirm_provided=True,
        )

    validation = validate_receipt(receipt_ref, data_dir)
    if validation.get("status") != "ok":
        return _blocked_payload(
            receipt_ref,
            status="failed",
            reason="receipt validation failed",
            receipt_id=original_receipt_id,
            recipe_id=recipe_id,
            confirm_provided=True,
            warnings=list(validation.get("warnings") or ["receipt validation failed"]),
        )

    target = _receipt_target(receipt)
    if not target:
        return _blocked_payload(
            receipt_ref,
            reason="receipt target missing",
            receipt_id=original_receipt_id,
            recipe_id=recipe_id,
            confirm_provided=True,
        )
    if target.lower() in BROAD_TARGETS or not _is_exact_target(target):
        return _blocked_payload(
            receipt_ref,
            reason="broad or invalid target refused",
            receipt_id=original_receipt_id,
            recipe_id=recipe_id,
            target={
                "name": target,
                "found": False,
                "production_target": False,
                "disposable": False,
                "allowlisted": False,
            },
            confirm_provided=True,
        )

    docker_client = docker or DockerExactTargetClient()
    pre_state = docker_client.inspect(target)
    target_payload = _target_payload(pre_state, target)
    blocker = _current_target_blocker(target, pre_state)
    if blocker:
        return _blocked_payload(
            receipt_ref,
            reason=blocker,
            receipt_id=original_receipt_id,
            recipe_id=recipe_id,
            target=target_payload,
            confirm_provided=True,
        )

    expected_argv = ["docker", "restart", target]
    command_result = docker_client.restart(target)
    attempted = list(command_result.argv) == expected_argv
    if not attempted:
        return _blocked_payload(
            receipt_ref,
            reason="executor returned non-governed argv; command refused",
            receipt_id=original_receipt_id,
            recipe_id=recipe_id,
            target=target_payload,
            confirm_provided=True,
        )

    post_state = docker_client.inspect(target)
    command_ok = command_result.return_code == 0
    verification = _verification(pre_state, post_state, target, command_ok)
    if not command_ok:
        status = "failed"
        warnings = ["docker restart returned nonzero"]
    elif verification["status"] != "passed":
        status = "verification_failed"
        warnings = ["docker restart returned success but recovery verification failed"]
    else:
        status = "executed"
        warnings = []
    success = status == "executed"
    safety = _base_safety(attempted=True, success=success)
    recovery_receipt = _write_recovery_receipt(
        data_dir,
        original_receipt_id=original_receipt_id,
        recipe_id=recipe_id,
        target=target,
        status=status,
        pre_state=pre_state,
        post_state=post_state,
        action=command_result,
        verification=verification,
        safety=safety,
        warnings=warnings,
    )
    action = {
        "argv": expected_argv,
        "docker_restart_attempted": True,
        "docker_restart_succeeded": command_ok,
        "docker_compose_executed": False,
        "shell_true": False,
        "return_code": command_result.return_code,
        "stdout_summary": _summary(command_result.stdout),
        "stderr_summary": _summary(command_result.stderr),
    }
    payload = {
        "schema_version": SCHEMA_VERSION,
        "mode": RECOVERY_EXECUTE_MODE,
        "status": status,
        "receipt_ref": receipt_ref,
        "receipt_id": original_receipt_id,
        "recovery_receipt_id": recovery_receipt["recovery_receipt_id"],
        "recipe_id": recipe_id,
        "target": _target_payload(post_state, target),
        "confirm_required": True,
        "confirm_provided": True,
        "exact_target_only": True,
        "action": action,
        "verification": verification,
        "safety": safety,
        "warnings": warnings,
        "first_safe_command": (
            f"shellforgeai verify --receipt {recovery_receipt['recovery_receipt_id']} --json"
        ),
        **safety,
    }
    return payload
