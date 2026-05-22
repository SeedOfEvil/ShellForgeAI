from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
PLAN_KIND = "disposable_remediation_plan"
RECEIPT_KIND = "disposable_remediation_receipt"
SUPPORTED_SCENARIO = "sfai-noisy-errors"
BROAD_TARGETS = {"all", "*", "everything", "all containers", "all services"}
SAFE_TARGET_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$")
DISPOSABLE_LABELS = (
    ("shellforgeai.disposable", "true"),
    ("sfai.battle", "true"),
    ("shellforgeai.test_harness", "battle-lab"),
)
ALLOWLIST_LABELS = (("shellforgeai.allow_restart", "true"),)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _fingerprint(payload: dict[str, Any]) -> str:
    basis = {
        "schema_version": payload.get("schema_version"),
        "kind": payload.get("kind"),
        "scenario": payload.get("scenario"),
        "target": payload.get("target"),
        "target_labels": payload.get("target_labels"),
        "proposed_action": payload.get("proposed_action"),
        "pre_checks": payload.get("pre_checks"),
        "post_checks": payload.get("post_checks"),
    }
    return hashlib.sha256(json.dumps(basis, sort_keys=True).encode()).hexdigest()


def _is_broad_target(target: str) -> bool:
    return target.strip().lower() in BROAD_TARGETS


def _safe_target(target: str) -> bool:
    return bool(
        target and SAFE_TARGET_RE.fullmatch(target) and ".." not in target and "/" not in target
    )


def _is_production_target(target: str) -> bool:
    return target.strip().lower() == "shellforgeai"


def _has_any_label(labels: dict[str, str], required: tuple[tuple[str, str], ...]) -> bool:
    return any(labels.get(k) == v for k, v in required)


def safety_block(
    *, mutation: bool, restarted: bool, disposable: bool, allowlisted: bool, production: bool
) -> dict[str, Any]:
    return {
        "read_only": not mutation,
        "mutation_performed": mutation,
        "production_target": production,
        "target_allowlisted": allowlisted,
        "disposable": disposable,
        "cleanup_executed": False,
        "proposal_created": False,
        "mission_created": False,
        "apply_executed": False,
        "docker_compose_executed": False,
        "container_restarted": restarted,
        "shell_true": False,
        "natural_language_execution": False,
        "arbitrary_command_execution": False,
    }


def plan_artifacts_dir(data_dir: Path) -> Path:
    return data_dir / "artifacts" / "remediation-plans"


def receipt_artifacts_dir(data_dir: Path) -> Path:
    return data_dir / "artifacts" / "remediation-receipts"


def write_plan(
    *, data_dir: Path, target: str, scenario: str, labels: dict[str, str]
) -> dict[str, Any]:
    if _is_broad_target(target):
        return {"status": "blocked", "reason": "broad target refused"}
    if not _safe_target(target):
        return {"status": "blocked", "reason": "suspicious target refused"}
    if _is_production_target(target):
        return {"status": "blocked", "reason": "production target refused"}
    if scenario != SUPPORTED_SCENARIO:
        return {"status": "blocked", "reason": "unsupported scenario"}
    disposable = _has_any_label(labels, DISPOSABLE_LABELS)
    allowlisted = _has_any_label(labels, ALLOWLIST_LABELS)
    if not disposable:
        return {"status": "blocked", "reason": "target missing disposable labels"}
    if not allowlisted:
        return {"status": "blocked", "reason": "target missing allowlist labels"}

    plan_id = f"drp_{uuid.uuid4().hex[:12]}"
    plan = {
        "schema_version": SCHEMA_VERSION,
        "kind": PLAN_KIND,
        "plan_id": plan_id,
        "created_at": _now(),
        "scenario": scenario,
        "target": target,
        "target_kind": "container",
        "target_labels": labels,
        "target_allowlisted": True,
        "disposable": True,
        "production_target": False,
        "proposed_action": "docker restart <target>",
        "action_preview": f"docker restart {target}",
        "pre_checks": ["target exists", "target labels still eligible"],
        "post_checks": ["container running", "restart_count changed or started_at changed"],
        "rollback_or_recovery_note": "If verification fails, stop and return to read-only triage.",
        "verification_criteria": "container running and restart indicator changed",
        "execution_allowed": False,
        "mutation_performed": False,
    }
    plan["safety"] = safety_block(
        mutation=False, restarted=False, disposable=True, allowlisted=True, production=False
    )
    plan["fingerprint"] = _fingerprint(plan)
    out = plan_artifacts_dir(data_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{plan_id}.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    return {
        "status": "planned",
        "mode": "disposable_remediation_plan",
        "plan_id": plan_id,
        "plan": plan,
    }


def load_plan(data_dir: Path, plan_id: str) -> dict[str, Any] | None:
    p = plan_artifacts_dir(data_dir) / f"{plan_id}.json"
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def validate_plan(plan: dict[str, Any]) -> tuple[bool, list[str]]:
    errs: list[str] = []
    if plan.get("kind") != PLAN_KIND:
        errs.append("invalid kind")
    if plan.get("fingerprint") != _fingerprint(plan):
        errs.append("fingerprint mismatch")
    if not plan.get("post_checks"):
        errs.append("missing post checks")
    if not plan.get("rollback_or_recovery_note"):
        errs.append("missing rollback/recovery note")
    s = plan.get("safety") or {}
    for k in ("shell_true", "arbitrary_command_execution", "natural_language_execution"):
        if s.get(k) is not False:
            errs.append(f"unsafe safety flag: {k}")
    if plan.get("production_target"):
        errs.append("production target refused")
    if not plan.get("disposable"):
        errs.append("target must be disposable")
    if not plan.get("target_allowlisted"):
        errs.append("target must be allowlisted")
    return (len(errs) == 0, errs)


def write_receipt(data_dir: Path, receipt: dict[str, Any]) -> None:
    d = receipt_artifacts_dir(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{receipt['receipt_id']}.json").write_text(
        json.dumps(receipt, indent=2), encoding="utf-8"
    )


def load_receipt(data_dir: Path, receipt_id: str) -> dict[str, Any] | None:
    p = receipt_artifacts_dir(data_dir) / f"{receipt_id}.json"
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))
