"""Read-only V2 operator handoff artifact writer.

This module saves ShellForgeAI-owned handoff packets only. It writes nothing
outside ``<data_dir>/v2_handoffs/<handoff_id>/`` and never executes cleanup,
remediation, rollback, Docker/Compose, restart, shell, or natural-language
mutation. Validation/export of saved handoffs is intentionally out of scope for
PR150 and left for a later PR.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REQUIRED_HANDOFF_FILES = ("handoff.json", "handoff.md", "manifest.json")

_MUTATING_TRUE_FLAGS = (
    "mutation_performed",
    "apply_executed",
    "mission_created",
    "plan_created",
    "remediation_executed",
    "rollback_executed",
    "cleanup_executed",
    "docker_compose_executed",
    "container_restarted",
    "shell_true",
    "arbitrary_command_execution",
    "natural_language_execution",
    "model_called",
)
_SECRET_FIELD_RE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)")
_SECRET_VALUE_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*[^\s,;}]+"
)


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _safety_non_mutating(safety: dict[str, Any]) -> bool:
    return safety.get("read_only") is True and all(
        safety.get(flag) is False for flag in _MUTATING_TRUE_FLAGS if flag in safety
    )


def _has_obvious_secret(value: Any) -> bool:
    if isinstance(value, dict):
        for key, inner in value.items():
            if _SECRET_FIELD_RE.search(str(key)):
                return True
            if _has_obvious_secret(inner):
                return True
        return False
    if isinstance(value, list):
        return any(_has_obvious_secret(inner) for inner in value)
    if isinstance(value, str):
        return bool(_SECRET_VALUE_RE.search(value))
    return False


def _validate_data_dir(data_dir: Path | str) -> Path:
    """Reject obviously unsafe artifact roots before writing anything."""
    raw = str(data_dir)
    if not raw.strip():
        raise ValueError("invalid data_dir for handoff save: empty path")
    if ".." in Path(raw).parts:
        raise ValueError("invalid data_dir for handoff save: path traversal is not allowed")
    return Path(data_dir)


def resolve_handoff_dir(data_dir: Path | str, handoff_id: str) -> Path:
    """Resolve and confirm the handoff dir stays inside the ShellForgeAI root."""
    root = _validate_data_dir(data_dir).resolve() / "v2_handoffs"
    if not handoff_id or "/" in handoff_id or "\\" in handoff_id or ".." in handoff_id:
        raise ValueError("invalid handoff_id for handoff save")
    out = (root / handoff_id).resolve()
    try:
        out.relative_to(root.resolve())
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError("refusing to write handoff outside the ShellForgeAI root") from exc
    return out


def _handoff_markdown(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    golden = payload.get("golden_path") if isinstance(payload.get("golden_path"), dict) else {}
    lines = ["# ShellForgeAI V2 Operator Handoff", ""]
    lines.append(f"- status: {payload.get('status', 'unknown')}")
    lines.append(f"- handoff_id: {payload.get('handoff_id') or 'unsaved'}")
    lines.append(f"- read_only: {str(payload.get('read_only', True)).lower()}")
    lines.append(f"- mutation_performed: {str(payload.get('mutation_performed', False)).lower()}")
    lines.extend(["", "## Summary"])
    for key in (
        "current_status",
        "risk",
        "suspects_ranked",
        "proposal_status",
        "apply_preview_status",
        "verify_status",
    ):
        lines.append(f"- {key}: {summary.get(key)}")
    lines.extend(["", "## V2 golden path"])
    for stage in ("status", "triage", "propose", "apply_preview", "verify"):
        section = golden.get(stage) if isinstance(golden.get(stage), dict) else {}
        lines.append(f"- {stage}: {section.get('status', 'unknown')}")
    lines.extend(["", "## First safe command"])
    lines.append(f"- {payload.get('first_safe_command') or 'shellforgeai status --json'}")
    lines.extend(["", "## What was not done"])
    lines.append("- No applied action was detected or assumed.")
    lines.append("- This handoff is a read-only operator summary.")
    limitations = payload.get("limitations") or []
    if limitations:
        lines.extend(["", "## Limitations"])
        lines.extend(f"- {item}" for item in limitations)
    warnings = payload.get("warnings") or []
    if warnings:
        lines.extend(["", "## Warnings"])
        lines.extend(f"- {item}" for item in warnings)
    lines.extend(["", "## Safety"])
    for key, value in (payload.get("safety") or {}).items():
        lines.append(f"- {key}: {str(value).lower()}")
    return "\n".join(lines).rstrip() + "\n"


def save_v2_handoff(
    payload: dict[str, Any], data_dir: Path | str, *, source: str = "shellforgeai handoff --save"
) -> dict[str, Any]:
    """Write a read-only ShellForgeAI-owned handoff packet and return the saved payload.

    Raises ``ValueError`` for unsafe save targets or for payloads whose safety
    metadata is not strictly read-only/non-mutating.
    """
    safety = payload.get("safety") if isinstance(payload.get("safety"), dict) else {}
    if not _safety_non_mutating(safety):
        raise ValueError("refusing to save handoff with mutating safety metadata")
    if _has_obvious_secret(payload):
        raise ValueError("refusing to save handoff containing secret-shaped fields")

    handoff_id = f"handoff_{_now_stamp()}_{uuid.uuid4().hex[:6]}"
    out = resolve_handoff_dir(data_dir, handoff_id)
    out.mkdir(parents=True, exist_ok=False)

    saved = dict(payload)
    saved.update(
        {
            "schema_version": saved.get("schema_version") or 1,
            "mode": "v2_handoff",
            "read_only": True,
            "mutation_performed": False,
            "artifact_written": True,
            "handoff_id": handoff_id,
            "handoff_path": str(out),
        }
    )

    (out / "handoff.json").write_text(
        json.dumps(saved, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "handoff.md").write_text(_handoff_markdown(saved), encoding="utf-8")
    files = ["handoff.json", "handoff.md"]
    checksums = {rel: _sha256_file(out / rel) for rel in files}
    manifest = {
        "schema_version": 1,
        "kind": "v2_handoff",
        "mode": "v2_handoff_artifact",
        "handoff_id": handoff_id,
        "created_at": _now_utc(),
        "source": source,
        "files": [*files, "manifest.json"],
        "checksums": checksums,
        "mutation_performed": False,
        "artifact_written": True,
        "safety": dict(safety),
        "summary": dict(saved.get("summary") or {}),
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksums["manifest.json"] = _sha256_file(out / "manifest.json")

    return {
        **saved,
        "files": [*files, "manifest.json"],
        "checksums": checksums,
        "manifest": manifest,
    }
