from __future__ import annotations

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
                f"- status: {payload['rollback_status']}",
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
