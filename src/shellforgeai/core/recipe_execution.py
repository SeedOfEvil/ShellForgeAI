"""Governed V2 recipe execution for the disposable restart recipe.

This module intentionally supports exactly one mutating action:
``["docker", "restart", <exact disposable allowlisted target>]``.  It never
uses a shell, never executes Docker Compose, and never accepts natural language
as an execution source.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shellforgeai.core.recipe_preflight import (
    PREFLIGHT_MODE,
    SUPPORTED_RECIPE,
    _resolve_ref,
    recipe_preflight_root,
    validate_preflight_packet,
)
from shellforgeai.core.recipe_registry import (
    BROAD_TARGETS,
    PRODUCTION_TARGETS,
    REQUIRED_DISPOSABLE_RESTART_LABELS,
)

SCHEMA_VERSION = 1
EXECUTE_MODE = "v2_recipe_execute"
RECEIPT_MODE = "v2_recipe_execution_receipt"
RECEIPT_VALIDATE_MODE = "v2_recipe_receipt_validate"
RECEIPT_REQUIRED_FILES = ("recipe-receipt.json", "recipe-receipt.md", "manifest.json")
RECOVERY_RECEIPT_MODE = "v2_recipe_recovery_receipt"
RECOVERY_MANIFEST_KIND = "v2_recipe_recovery_receipt"
_EXACT_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


@dataclass(frozen=True)
class CommandResult:
    argv: list[str]
    return_code: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class DockerContainerState:
    found: bool
    name: str
    container_id: str = ""
    started_at: str = ""
    labels: dict[str, str] | None = None
    raw_state: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        labels = dict(self.labels or {})
        return {
            "found": self.found,
            "name": self.name,
            "container_id": self.container_id,
            "started_at": self.started_at,
            "labels": labels,
            "disposable": labels.get("shellforgeai.disposable") == "true",
            "allowlisted": labels.get("shellforgeai.allow_restart") == "true",
            "production_target": self.name.lower() in PRODUCTION_TARGETS,
        }


class DockerExactTargetClient:
    """Tiny exact-target Docker client using argv lists only."""

    def inspect(self, target: str) -> DockerContainerState:
        try:
            proc = subprocess.run(  # noqa: S603 - governed exact argv, shell=False by default.
                ["docker", "inspect", target],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (FileNotFoundError, subprocess.SubprocessError, OSError):
            return DockerContainerState(found=False, name=target, labels={})
        if proc.returncode != 0:
            return DockerContainerState(found=False, name=target, labels={})
        try:
            rows = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            return DockerContainerState(found=False, name=target, labels={})
        if not rows or not isinstance(rows[0], dict):
            return DockerContainerState(found=False, name=target, labels={})
        row = rows[0]
        raw_name = str(row.get("Name") or "").lstrip("/")
        labels = row.get("Config", {}).get("Labels") if isinstance(row.get("Config"), dict) else {}
        state = row.get("State") if isinstance(row.get("State"), dict) else {}
        return DockerContainerState(
            found=True,
            name=raw_name or target,
            container_id=str(row.get("Id") or ""),
            started_at=str(state.get("StartedAt") or ""),
            labels={str(k): str(v) for k, v in (labels or {}).items()},
            raw_state=state,
        )

    def restart(self, target: str) -> CommandResult:
        argv = ["docker", "restart", target]
        try:
            proc = subprocess.run(  # noqa: S603 - only exact governed argv; shell=False by default.
                argv,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except FileNotFoundError as exc:
            return CommandResult(argv=argv, return_code=127, stdout="", stderr=str(exc))
        except subprocess.SubprocessError as exc:
            return CommandResult(argv=argv, return_code=124, stdout="", stderr=str(exc))
        return CommandResult(
            argv=argv, return_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr
        )


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def recipe_receipt_root(data_dir: Path | str) -> Path:
    return Path(data_dir).expanduser() / "recipe_receipts"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _summary(text: str, *, limit: int = 400) -> str:
    redacted = re.sub(
        r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+", r"\1=<redacted>", text or ""
    )
    redacted = "\n".join(line.rstrip() for line in redacted.splitlines()[:8]).strip()
    return redacted[:limit]


def _execution_safety(*, command_executed: bool, success: bool) -> dict[str, bool]:
    return {
        "read_only": False,
        "mutation_performed": bool(success),
        "container_restarted": bool(success),
        "docker_compose_executed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "production_restart_executed": False,
        "exact_target_only": True,
        "command_executed": bool(command_executed),
    }


def _blocked_safety() -> dict[str, bool]:
    safety = _execution_safety(command_executed=False, success=False)
    safety["read_only"] = True
    return safety


def _target_payload(state: DockerContainerState, target: str) -> dict[str, Any]:
    labels = dict(state.labels or {})
    return {
        "name": target,
        "current_name": state.name,
        "found": state.found,
        "production_target": target.lower() in PRODUCTION_TARGETS
        or state.name.lower() in PRODUCTION_TARGETS,
        "disposable": labels.get("shellforgeai.disposable") == "true",
        "allowlisted": labels.get("shellforgeai.allow_restart") == "true",
        "broad_target": target.lower() in BROAD_TARGETS,
    }


def _is_exact_target(target: str) -> bool:
    lower = target.strip().lower()
    return (
        bool(_EXACT_TARGET_RE.match(target))
        and lower not in BROAD_TARGETS
        and lower not in {"docker", "compose"}
    )


def _current_gate_blockers(target: str, state: DockerContainerState) -> list[str]:
    labels = dict(state.labels or {})
    blockers: list[str] = []
    if not _is_exact_target(target):
        blockers.append("broad or invalid target refused")
    if target.lower() in PRODUCTION_TARGETS or state.name.lower() in PRODUCTION_TARGETS:
        blockers.append("production target refused")
    if not state.found:
        blockers.append("target not found")
    if state.found and state.name != target:
        blockers.append("target exact match failed")
    for key, value in REQUIRED_DISPOSABLE_RESTART_LABELS.items():
        if labels.get(key) != value:
            blockers.append("current target labels no longer satisfy gates")
            break
    return blockers


def _load_saved_preflight(
    preflight_ref: str, data_dir: Path | str
) -> tuple[dict[str, Any] | None, Path | None]:
    root = recipe_preflight_root(data_dir)
    d = _resolve_ref(preflight_ref, root)
    if d is None or not d.is_dir():
        return None, d
    try:
        packet = json.loads((d / "recipe-preflight.json").read_text(encoding="utf-8"))
    except Exception:
        return None, d
    return packet, d


def _blocked_result(
    reason: str, *, preflight_ref: str, validation: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": EXECUTE_MODE,
        "status": "blocked" if reason != "preflight not found" else "not_found",
        "reason": reason,
        "preflight_ref": preflight_ref,
        "preflight_id": (validation or {}).get("preflight_id"),
        "recipe_id": (validation or {}).get("recipe_id"),
        "target": None,
        "action": {
            "argv": [],
            "command_executed": False,
            "return_code": None,
            "stdout_summary": "",
            "stderr_summary": "",
        },
        "verification": {"status": "not_run", "restart_verified": False},
        "receipt": None,
        "rollback_posture": rollback_posture(),
        "safety": _blocked_safety(),
        "warnings": [reason],
    }


def rollback_posture() -> dict[str, bool | str]:
    return {
        "automatic_rollback": False,
        "bounded_recovery_restart_available": True,
        "rollback_is_repeat_exact_target_restart_only": True,
        "future_rollback_requires_explicit_confirm": True,
        "rollback_executed": False,
        "note": "No automatic undo exists for docker restart; no rollback was executed.",
    }


def execute_disposable_restart(
    preflight_ref: str,
    data_dir: Path | str,
    *,
    confirm: bool,
    docker: Any | None = None,
) -> dict[str, Any]:
    if not confirm:
        return _blocked_result("explicit confirmation required", preflight_ref=preflight_ref)

    validation = validate_preflight_packet(preflight_ref, data_dir)
    if validation.get("status") == "not_found":
        return _blocked_result(
            "preflight not found", preflight_ref=preflight_ref, validation=validation
        )
    if validation.get("status") != "ok":
        return _blocked_result(
            "preflight validation failed", preflight_ref=preflight_ref, validation=validation
        )

    packet, preflight_dir = _load_saved_preflight(preflight_ref, data_dir)
    if not packet or not preflight_dir:
        return _blocked_result(
            "malformed preflight packet", preflight_ref=preflight_ref, validation=validation
        )
    if packet.get("mode") != PREFLIGHT_MODE or packet.get("recipe_id") != SUPPORTED_RECIPE:
        return _blocked_result(
            "unsupported recipe preflight", preflight_ref=preflight_ref, validation=validation
        )
    if packet.get("status") != "preflight_ready":
        return _blocked_result(
            "preflight not ready", preflight_ref=preflight_ref, validation=validation
        )

    target_obj = packet.get("target") if isinstance(packet.get("target"), dict) else {}
    target = str(target_obj.get("name") or "").strip()
    if not _is_exact_target(target):
        return _blocked_result(
            "broad or invalid target refused", preflight_ref=preflight_ref, validation=validation
        )

    docker_client = docker or DockerExactTargetClient()
    pre_state = docker_client.inspect(target)
    blockers = _current_gate_blockers(target, pre_state)
    if blockers:
        result = _blocked_result(blockers[0], preflight_ref=preflight_ref, validation=validation)
        result["target"] = _target_payload(pre_state, target)
        return result

    argv = ["docker", "restart", target]
    command_result = docker_client.restart(target)
    if list(command_result.argv) != argv:
        receipt = _write_receipt(
            data_dir,
            preflight_id=str(packet.get("preflight_id") or validation.get("preflight_id") or ""),
            recipe_id=SUPPORTED_RECIPE,
            target=target,
            status="blocked",
            pre_state=pre_state,
            post_state=pre_state,
            action=CommandResult(argv=list(command_result.argv), return_code=127),
            verification={"status": "failed", "restart_verified": False, "target_match": False},
            safety=_execution_safety(command_executed=False, success=False),
            warnings=["executor returned non-governed argv; command refused"],
        )
        return _result_from_receipt(receipt, "blocked")

    post_state = docker_client.inspect(target)
    target_payload = _target_payload(post_state, target)
    command_ok = command_result.return_code == 0
    target_match = post_state.found and post_state.name == target
    started_changed = bool(
        pre_state.started_at
        and post_state.started_at
        and pre_state.started_at != post_state.started_at
    )
    label_blockers_after = _current_gate_blockers(target, post_state)
    restart_verified = command_ok and target_match and started_changed and not label_blockers_after
    verification_status = "passed" if restart_verified else "failed"
    verification = {
        "status": verification_status,
        "restart_verified": restart_verified,
        "started_at_before": pre_state.started_at,
        "started_at_after": post_state.started_at,
        "container_id_before": pre_state.container_id,
        "container_id_after": post_state.container_id,
        "target_match": target_match,
        "command_ok": command_ok,
        "stdout_contains_target": target in (command_result.stdout or ""),
        "current_labels_match": not label_blockers_after,
    }
    if command_ok and not restart_verified:
        status = "verification_failed"
        warnings = ["docker restart returned success but post-restart verification failed"]
    elif not command_ok:
        status = "failed"
        warnings = ["docker restart returned nonzero"]
    else:
        status = "executed"
        warnings = []
    success = status == "executed"
    safety = _execution_safety(command_executed=True, success=success)
    receipt = _write_receipt(
        data_dir,
        preflight_id=str(packet.get("preflight_id") or validation.get("preflight_id") or ""),
        recipe_id=SUPPORTED_RECIPE,
        target=target,
        status=status,
        pre_state=pre_state,
        post_state=post_state,
        action=command_result,
        verification=verification,
        safety=safety,
        warnings=warnings,
    )
    result = _result_from_receipt(receipt, status)
    result["target"] = target_payload
    return result


def _write_receipt(
    data_dir: Path | str,
    *,
    preflight_id: str,
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
    receipt_id = f"receipt_{_now_stamp()}_{uuid.uuid4().hex[:6]}"
    out = (recipe_receipt_root(data_dir) / receipt_id).resolve()
    out.mkdir(parents=True, exist_ok=False)
    created_at = _now_utc()
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "mode": RECEIPT_MODE,
        "status": status,
        "receipt_id": receipt_id,
        "preflight_id": preflight_id,
        "recipe_id": recipe_id,
        "target": target,
        "target_labels_before": dict(pre_state.labels or {}),
        "target_labels_after": dict(post_state.labels or {}),
        "action_attempted": action.argv == ["docker", "restart", target],
        "argv": list(action.argv),
        "command_executed": bool(safety.get("command_executed")),
        "return_code": action.return_code,
        "stdout_summary": _summary(action.stdout),
        "stderr_summary": _summary(action.stderr),
        "pre_state": pre_state.to_dict(),
        "post_state": post_state.to_dict(),
        "verification": verification,
        "rollback_posture": rollback_posture(),
        "safety": safety,
        "warnings": warnings,
        "created_at": created_at,
    }
    json_path = out / "recipe-receipt.json"
    md_path = out / "recipe-receipt.md"
    manifest_path = out / "manifest.json"
    json_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(_render_receipt_markdown(receipt), encoding="utf-8")
    files = ["recipe-receipt.json", "recipe-receipt.md"]
    checksums = {rel: _sha256_file(out / rel) for rel in files}
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "v2_recipe_execution_receipt",
        "mode": "v2_recipe_receipt_manifest",
        "receipt_id": receipt_id,
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
    json_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksums["recipe-receipt.json"] = _sha256_file(json_path)
    manifest["checksums"] = checksums
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return receipt


def _render_receipt_markdown(receipt: dict[str, Any]) -> str:
    lines = [
        "# ShellForgeAI Recipe Execution Receipt",
        "",
        f"- status: {receipt.get('status')}",
        f"- recipe: {receipt.get('recipe_id')}",
        f"- target: {receipt.get('target')}",
        f"- receipt_id: {receipt.get('receipt_id')}",
        f"- preflight_id: {receipt.get('preflight_id')}",
        "",
        "## Action",
        "- argv: " + " ".join(str(part) for part in receipt.get("argv") or []),
        f"- command_executed: {str(bool(receipt.get('command_executed'))).lower()}",
        f"- return_code: {receipt.get('return_code')}",
        "",
        "## Verification",
    ]
    for key, value in (receipt.get("verification") or {}).items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Rollback posture"])
    for key, value in (receipt.get("rollback_posture") or {}).items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Safety"])
    for key, value in (receipt.get("safety") or {}).items():
        lines.append(f"- {key}: {str(value).lower()}")
    warnings = receipt.get("warnings") or []
    if warnings:
        lines.extend(["", "## Warnings"])
        lines.extend(f"- {warning}" for warning in warnings)
    return "\n".join(lines).rstrip() + "\n"


def _result_from_receipt(receipt: dict[str, Any], status: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": EXECUTE_MODE,
        "status": status,
        "recipe_id": receipt.get("recipe_id"),
        "preflight_id": receipt.get("preflight_id"),
        "receipt_id": receipt.get("receipt_id"),
        "target": {
            "name": receipt.get("target"),
            "production_target": (receipt.get("post_state") or {}).get("production_target", False),
            "disposable": (receipt.get("post_state") or {}).get("disposable", False),
            "allowlisted": (receipt.get("post_state") or {}).get("allowlisted", False),
        },
        "action": {
            "argv": receipt.get("argv") or [],
            "command_executed": receipt.get("command_executed") is True,
            "return_code": receipt.get("return_code"),
            "stdout_summary": receipt.get("stdout_summary") or "",
            "stderr_summary": receipt.get("stderr_summary") or "",
        },
        "verification": receipt.get("verification") or {},
        "receipt": {"receipt_id": receipt.get("receipt_id"), "path": receipt.get("receipt_path")},
        "rollback_posture": receipt.get("rollback_posture") or rollback_posture(),
        "safety": receipt.get("safety") or {},
        "warnings": receipt.get("warnings") or [],
    }


def _resolve_receipt_ref(ref: str, root: Path) -> Path | None:
    raw = str(ref or "").strip()
    if not raw:
        return None
    p = Path(raw).expanduser()
    if p.is_absolute() or "/" in raw or "\\" in raw:
        resolved = p.resolve()
        if resolved.is_file():
            resolved = resolved.parent
    else:
        if ".." in raw:
            return None
        resolved = (root / raw).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return None
    return resolved


def validate_receipt(receipt_ref: str, data_dir: Path | str) -> dict[str, Any]:
    root = recipe_receipt_root(data_dir)
    checks = {
        "required_files": False,
        "json_parse": False,
        "schema": False,
        "manifest": False,
        "checksums": False,
        "recipe_id": False,
        "target": False,
        "safety": False,
        "verification": False,
    }
    d = _resolve_receipt_ref(receipt_ref, root)
    base = {
        "schema_version": SCHEMA_VERSION,
        "mode": RECEIPT_VALIDATE_MODE,
        "read_only": True,
        "mutation_performed": False,
        "receipt_id": d.name if d is not None else None,
        "receipt_path": str(d) if d is not None else None,
        "checks": checks,
        "warnings": [],
    }
    if d is None or not d.is_dir():
        return {**base, "status": "not_found", "warnings": ["receipt not found"]}
    if any(not (d / rel).exists() for rel in RECEIPT_REQUIRED_FILES):
        return {**base, "status": "failed", "warnings": ["missing required files"]}
    checks["required_files"] = True
    try:
        receipt = json.loads((d / "recipe-receipt.json").read_text(encoding="utf-8"))
        manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    except Exception:
        return {**base, "status": "failed", "warnings": ["malformed json"]}
    checks["json_parse"] = True
    receipt_mode = receipt.get("mode")
    manifest_kind = manifest.get("kind")
    checks["schema"] = receipt.get("schema_version") == SCHEMA_VERSION and receipt_mode in {
        RECEIPT_MODE,
        RECOVERY_RECEIPT_MODE,
    }
    checks["manifest"] = manifest_kind in {"v2_recipe_execution_receipt", RECOVERY_MANIFEST_KIND}
    checks["recipe_id"] = receipt.get("recipe_id") == manifest.get("recipe_id") == SUPPORTED_RECIPE
    checks["target"] = bool(receipt.get("target")) and receipt.get("target") == manifest.get(
        "target"
    )
    safety = receipt.get("safety") if isinstance(receipt.get("safety"), dict) else {}
    checks["safety"] = (
        safety.get("docker_compose_executed") is False
        and safety.get("shell_true") is False
        and safety.get("arbitrary_command_execution") is False
        and safety.get("natural_language_execution") is False
        and safety.get("production_restart_executed") is False
        and safety.get("exact_target_only") is True
    )
    verification = (
        receipt.get("verification") if isinstance(receipt.get("verification"), dict) else {}
    )
    checks["verification"] = bool(verification.get("status"))
    manifest_checksums = (
        manifest.get("checksums") if isinstance(manifest.get("checksums"), dict) else {}
    )
    checks["checksums"] = bool(manifest_checksums)
    for rel, expected in manifest_checksums.items():
        if rel == "manifest.json":
            continue
        if not (d / rel).exists() or _sha256_file(d / rel) != expected:
            checks["checksums"] = False
            break
    warnings = [f"{key} check failed" for key, ok in checks.items() if not ok]
    return {
        **base,
        "status": "ok" if all(checks.values()) else "failed",
        "receipt_id": receipt.get("receipt_id") or d.name,
        "recipe_id": receipt.get("recipe_id"),
        "target": receipt.get("target"),
        "checks": checks,
        "warnings": warnings,
        "receipt_status": receipt.get("status"),
        "receipt_mode": receipt.get("mode"),
        "original_receipt_id": receipt.get("original_receipt_id"),
        "recovery_receipt_id": receipt.get("recovery_receipt_id"),
        "verification": verification,
        "safety": safety,
    }
