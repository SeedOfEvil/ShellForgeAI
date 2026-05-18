from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shellforgeai.core.approvals import Proposal

SCHEMA_VERSION = "1"
STATUS_PREVIEW_ONLY = "preview_only"


@dataclass(frozen=True)
class RollbackPreviewPaths:
    json_path: Path
    md_path: Path


def rollback_preview_dir(data_dir: Path, proposal_id: str) -> Path:
    return Path(data_dir) / "rollback_previews" / proposal_id


def build_preview(proposal: Proposal) -> dict[str, Any]:
    if proposal.kind == "compose_service_restart":
        return _build_compose_service_restart_preview(proposal)
    component = ""
    if proposal.proposed_steps:
        for line in proposal.proposed_steps:
            text = str(line)
            if "docker restart" in text:
                parts = text.strip().split()
                component = parts[-1] if parts else ""
                break
    if not component:
        component = "unknown"
    return {
        "schema_version": SCHEMA_VERSION,
        "proposal_id": proposal.proposal_id,
        "created_at": datetime.now(UTC).isoformat(),
        "mutation_kind": "docker_restart",
        "component": component,
        "rollback_available": True,
        "rollback_executable_by_shellforgeai": False,
        "rollback_status": STATUS_PREVIEW_ONLY,
        "rollback_risk": "medium",
        "preconditions": ["operator has proposal receipt/evidence path"],
        "rollback_steps": [
            "Inspect current container state with docker inspect.",
            "If health is degraded, operator may run a manual restart "
            "of the same allowlisted target.",
            "If verification still fails, stop escalation and use "
            "evidence path for manual recovery.",
            "Docker restart cannot restore previous process memory/state; "
            "rollback is recovery guidance, not state reversal.",
        ],
        "verification_steps": [
            "Confirm container running_after=true.",
            "Confirm started_at_changed=true when possible.",
            "Confirm health_after is healthy (or explain warning evidence).",
        ],
        "refusal_reasons": [],
        "safety": {
            "execution_allowed": False,
            "rollback_execution_allowed": False,
            "arbitrary_command_execution": False,
            "service_impacting": True,
        },
    }


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_compose_service_restart_preview(proposal: Proposal) -> dict[str, Any]:
    compose = proposal.compose_context or {}
    labels_any = compose.get("labels")
    labels: dict[str, Any] = labels_any if isinstance(labels_any, dict) else {}
    compose_file = str((compose.get("config_files") or [""])[0] or "")
    working_dir = str(compose.get("working_dir") or "")
    command = list(compose.get("preview_command") or [])
    command_display = str(compose.get("preview_command_display") or "")
    target_service = str(compose.get("service") or "")
    warnings: list[dict[str, str]] = []

    compose_file_sha256 = ""
    compose_file_readable = False
    compose_file_error = ""
    if compose_file:
        p = Path(compose_file)
        if p.is_file():
            try:
                compose_file_sha256 = _sha256_file(p)
                compose_file_readable = True
            except OSError as exc:
                compose_file_error = str(exc)
                warnings.append(
                    {
                        "code": "compose_file_unreadable",
                        "message": (
                            "compose file path is not readable from this execution environment"
                        ),
                    }
                )
        else:
            compose_file_error = "compose_file missing"
            warnings.append(
                {
                    "code": "compose_file_snapshot_unavailable",
                    "message": "compose file snapshot unavailable in this execution environment",
                }
            )
    else:
        warnings.append(
            {
                "code": "compose_file_snapshot_unavailable",
                "message": "compose file path missing from proposal metadata",
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "id": f"rb_compose_{proposal.proposal_id}",
        "kind": "compose_service_restart_recovery_preview",
        "proposal_id": proposal.proposal_id,
        "proposal_kind": "compose_service_restart",
        "proposal_fingerprint": str((proposal.fingerprint or {}).get("value") or ""),
        "proposal_status": proposal.status,
        "created_at": datetime.now(UTC).isoformat(),
        "target": {
            "project": str(compose.get("project") or ""),
            "service": target_service,
            "container": str(compose.get("container") or proposal.component or ""),
            "working_dir": working_dir,
            "compose_file": compose_file,
        },
        "proposed_operation": {
            "command": command,
            "command_display": command_display,
            "compose_mutation": True,
            "execution_allowed": False,
            "gated_only": True,
        },
        "before_state": {
            "container_id": "",
            "container_name": str(compose.get("container") or proposal.component or ""),
            "image": "",
            "image_digest": "",
            "started_at": "",
            "running": None,
            "health": "unknown",
            "compose_project_label": str(labels.get("com.docker.compose.project") or ""),
            "compose_service_label": str(labels.get("com.docker.compose.service") or ""),
            "compose_container_number": str(compose.get("container_number") or ""),
            "labels": labels,
        },
        "config_state": {
            "compose_file_sha256": compose_file_sha256,
            "compose_file_readable": compose_file_readable,
            "compose_file_error": compose_file_error,
            "compose_file_snapshot_available": bool(compose_file_readable and compose_file_sha256),
            "env_files": [],
            "config_hash_warnings": [],
        },
        "sibling_state": {
            "project": str(compose.get("project") or ""),
            "services": [],
            "count": 0,
            "warnings": [],
        },
        "recovery": {
            "automatic_rollback": False,
            "rollback_command_generated": False,
            "operator_recovery_required": True,
            "confidence": "limited",
            "notes": [
                "Inspect service logs and health after restart.",
                "Verify compose file and config hashes have not drifted.",
                "If restart worsens state, operator must perform manual recovery "
                "from known image/config.",
                "Restore changed config from source control/backups when needed.",
                "Review sibling services in the same compose project.",
            ],
        },
        "safety": {
            "read_only": True,
            "docker_compose_executed": False,
            "container_restarted": False,
            "files_changed": False,
            "arbitrary_command_execution": False,
            "natural_language_execution": False,
            "rollback_execution_allowed": False,
        },
        "warnings": warnings,
    }


def write_preview(data_dir: Path, proposal: Proposal) -> RollbackPreviewPaths:
    d = rollback_preview_dir(data_dir, proposal.proposal_id)
    d.mkdir(parents=True, exist_ok=True)
    payload = build_preview(proposal)
    json_path = d / "rollback-preview.json"
    md_path = d / "rollback-preview.md"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_path.write_text(
        "\n".join(
            [
                "# Rollback preview",
                f"- proposal: {proposal.proposal_id}",
                f"- status: {payload.get('rollback_status', 'preview_only')}",
                "- rollback executable by ShellForgeAI: false",
                "- note: rollback is recovery guidance and verification, not state reversal.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return RollbackPreviewPaths(json_path=json_path, md_path=md_path)


def load_preview(path: Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_preview(payload: dict[str, Any]) -> list[str]:
    if payload.get("kind") == "compose_service_restart_recovery_preview":
        return _validate_compose_restart_preview(payload)
    errs: list[str] = []
    if payload.get("rollback_status") != STATUS_PREVIEW_ONLY:
        errs.append("rollback_status must be preview_only")
    if payload.get("rollback_executable_by_shellforgeai") is not False:
        errs.append("rollback_executable_by_shellforgeai must be false")
    if (payload.get("safety") or {}).get("rollback_execution_allowed") is not False:
        errs.append("safety.rollback_execution_allowed must be false")
    if not payload.get("rollback_steps"):
        errs.append("rollback_steps must be non-empty")
    if not payload.get("verification_steps"):
        errs.append("verification_steps must be non-empty")
    if payload.get("rollback_available") is not True:
        errs.append("rollback_available must be true for service-impacting mutation")
    return errs


def _validate_compose_restart_preview(payload: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if not payload.get("schema_version"):
        errs.append("schema_version required")
    if payload.get("proposal_kind") != "compose_service_restart":
        errs.append("proposal_kind must be compose_service_restart")
    if not payload.get("proposal_id"):
        errs.append("proposal_id required")
    if not payload.get("proposal_fingerprint"):
        errs.append("proposal_fingerprint required")
    target = payload.get("target") or {}
    if not target.get("project"):
        errs.append("target.project required")
    if not target.get("service"):
        errs.append("target.service required")
    if not target.get("working_dir"):
        errs.append("target.working_dir required")
    if not target.get("compose_file"):
        errs.append("target.compose_file required")
    op = payload.get("proposed_operation") or {}
    cmd = op.get("command")
    if not isinstance(cmd, list) or not cmd:
        errs.append("proposed_operation.command argv/list required")
    else:
        blob = " ".join(str(x).lower() for x in cmd)
        if " up" in f" {blob}" or " down" in f" {blob}" or "recreate" in blob:
            errs.append("compose command must not include up/down/recreate")
        if "restart" not in cmd:
            errs.append("command must be docker compose ... restart <service>")
    if op.get("compose_mutation") is not True:
        errs.append("proposed_operation.compose_mutation must be true")
    rec = payload.get("recovery") or {}
    if rec.get("automatic_rollback") is not False:
        errs.append("recovery.automatic_rollback must be false")
    if rec.get("rollback_command_generated") is not False:
        errs.append("recovery.rollback_command_generated must be false")
    if not rec.get("notes"):
        errs.append("recovery.notes must be present")
    cfg = payload.get("config_state") or {}
    if cfg.get("compose_file_readable") is False and cfg.get("compose_file_sha256"):
        errs.append(
            "config_state.compose_file_sha256 must be empty when compose_file_readable=false"
        )
    safety = payload.get("safety") or {}
    for k in ("docker_compose_executed", "container_restarted", "arbitrary_command_execution"):
        if safety.get(k) is not False:
            errs.append(f"safety.{k} must be false")
    return errs
