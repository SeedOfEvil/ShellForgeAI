from __future__ import annotations

import hashlib
import json
import re
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
PLAN_KIND = "disposable_remediation_plan"
RECEIPT_KIND = "disposable_remediation_receipt"
ROLLBACK_RECEIPT_KIND = "disposable_remediation_rollback_receipt"
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


def evaluate_eligibility(
    *, target: str, scenario: str, labels: dict[str, str] | None
) -> dict[str, Any]:
    normalized_labels = {str(k): str(v) for k, v in (labels or {}).items()}
    blocked: list[str] = []
    if _is_broad_target(target):
        blocked.append("broad target refused")
    if not _safe_target(target):
        blocked.append("suspicious target refused")
    production = _is_production_target(target)
    if production:
        blocked.append("production target refused")
    if scenario != SUPPORTED_SCENARIO:
        blocked.append("unsupported scenario")
    if labels is None:
        blocked.append("labels unavailable")
    disposable = _has_any_label(normalized_labels, DISPOSABLE_LABELS)
    allowlisted = _has_any_label(normalized_labels, ALLOWLIST_LABELS)
    if labels is not None and not disposable:
        blocked.append("target missing disposable labels")
    if labels is not None and not allowlisted:
        blocked.append("target missing allowlist labels")

    proof_ready = (
        not production
        and scenario == SUPPORTED_SCENARIO
        and disposable
        and not _is_broad_target(target)
    )
    docker_ready = proof_ready and allowlisted

    proof_reason = "" if proof_ready else "executor unavailable"
    docker_reason = "" if docker_ready else "executor unavailable"

    eligibility = "eligible_for_plan" if proof_ready and docker_ready else "blocked"
    return {
        "eligibility": eligibility,
        "production_target": production,
        "disposable": disposable,
        "target_allowlisted": allowlisted,
        "labels": normalized_labels,
        "executors": {
            "proof": {"ready": proof_ready, "reason": proof_reason},
            "docker-disposable": {"ready": docker_ready, "reason": docker_reason},
        },
        "blocked_reasons": blocked,
    }


def derive_rollback_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    target = str(receipt.get("target") or "")
    mode = str(receipt.get("executor_mode") or "")
    safety = receipt.get("safety") if isinstance(receipt.get("safety"), dict) else {}
    proof_only = mode == "proof"
    available = (
        mode in {"proof", "docker-disposable"}
        and bool(target)
        and not _is_broad_target(target)
        and _safe_target(target)
        and safety.get("production_target") is False
        and safety.get("disposable") is True
        and safety.get("target_allowlisted") is True
    )
    return {
        "rollback_available": available and not proof_only,
        "proof_only": proof_only,
        "automatic_rollback": False,
        "rollback_kind": "bounded_recovery_restart",
        "rollback_strategy": "repeat_exact_target_restart",
        "rollback_target": target,
        "rollback_scope_exact_target_only": True,
        "rollback_requires_explicit_confirm": True,
        "rollback_executor_modes_supported": ["proof", "docker-disposable"],
        "rollback_verification_signal": "started_at_changed",
        "rollback_preconditions": [
            "receipt validates",
            "target remains disposable",
            "target remains allowlisted",
            "target is not production shellforgeai",
        ],
        "rollback_risk_level": "low_disposable_only",
        "rollback_note": (
            "This is a bounded disposable recovery restart, not full state restoration."
        ),
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
        "executor_modes_supported": ["proof", "docker-disposable"],
        "default_executor": "proof",
        "real_execution_requires_explicit_executor": True,
        "docker_disposable_eligible": True,
        "why_real_execution_blocked": [],
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


def resolve_receipt_path(data_dir: Path, receipt_id_or_path: str) -> tuple[Path | None, str | None]:
    receipts_root = receipt_artifacts_dir(data_dir).resolve()
    token = (receipt_id_or_path or "").strip()
    if not token:
        return (None, "malformed receipt id")
    if "/" in token or "\\" in token:
        candidate = Path(token)
        if not candidate.is_absolute():
            return (None, "unsafe receipt path")
        if not candidate.exists():
            return (None, "receipt not found")
        rp = candidate.resolve()
        if not str(rp).startswith(str(receipts_root) + "/"):
            return (None, "unsafe receipt path")
        return (rp, None)
    if not re.fullmatch(r"drr[b]?_[a-f0-9]{12}", token):
        return (None, "malformed receipt id")
    rp = (receipts_root / f"{token}.json").resolve()
    if not str(rp).startswith(str(receipts_root) + "/"):
        return (None, "unsafe receipt path")
    if not rp.exists():
        return (None, "receipt not found")
    return (rp, None)


def validate_receipt_payload(data_dir: Path, receipt_id_or_path: str) -> dict[str, Any]:
    path, err = resolve_receipt_path(data_dir, receipt_id_or_path)
    base = {
        "schema_version": "1",
        "mode": "disposable_remediation_receipt_validate",
        "status": "error",
        "receipt": {},
        "checks": {},
        "safety": {},
        "warnings": [],
    }
    if path is None:
        base["status"] = "not_found" if err == "receipt not found" else "error"
        base["warnings"] = [err or "receipt not found"]
        return base
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        base["warnings"] = [f"receipt JSON unreadable: {exc}"]
        return base
    checks: dict[str, bool] = {}
    safety = receipt.get("safety") if isinstance(receipt.get("safety"), dict) else {}
    plan = (
        load_plan(data_dir, str(receipt.get("plan_id") or "")) if receipt.get("plan_id") else None
    )
    checks["receipt_exists"] = True
    checks["json_parse"] = True
    checks["kind"] = receipt.get("kind") == RECEIPT_KIND
    checks["plan_id_present"] = bool(receipt.get("plan_id"))
    checks["plan_fingerprint_present"] = bool(receipt.get("plan_fingerprint"))
    checks["plan_fingerprint_matches"] = plan is None or receipt.get(
        "plan_fingerprint"
    ) == plan.get("fingerprint")
    tgt = str(receipt.get("target") or "")
    checks["target_explicit"] = bool(tgt) and not _is_broad_target(tgt) and _safe_target(tgt)
    checks["production_target_false"] = safety.get("production_target") is False
    checks["disposable_true"] = safety.get("disposable") is True
    checks["target_allowlisted_true"] = safety.get("target_allowlisted") is True
    checks["executor_mode_known"] = receipt.get("executor_mode") in {"proof", "docker-disposable"}
    checks["pre_state_present"] = isinstance(receipt.get("pre_state"), dict)
    checks["post_state_present"] = isinstance(receipt.get("post_state"), dict)
    checks["verification_present"] = isinstance(receipt.get("verification"), dict)
    checks["restart_verified"] = (
        True
        if receipt.get("executor_mode") == "proof"
        else bool((receipt.get("verification") or {}).get("restart_verified"))
    )
    checks["safety"] = isinstance(receipt.get("safety"), dict)
    failed_reason = bool(receipt.get("failure_reason") or receipt.get("stderr_summary"))
    mode = receipt.get("executor_mode")
    if mode == "proof":
        checks["proof_invariants"] = (
            receipt.get("real_docker_executor") is False
            and receipt.get("docker_restart_attempted") is False
            and safety.get("mutation_performed") is False
            and safety.get("container_restarted") is False
        )
    if mode == "docker-disposable":
        rc0 = int(receipt.get("return_code") or 0) == 0
        if receipt.get("verification", {}).get("status") == "failed":
            checks["failure_reason_present"] = failed_reason
        else:
            checks["docker_disposable_invariants"] = (
                receipt.get("real_docker_executor") is True
                and receipt.get("docker_restart_attempted") is True
                and (receipt.get("action_executed") is True if rc0 else True)
                and checks["restart_verified"] is True
                and receipt.get("docker_restart_succeeded") is True
                and safety.get("container_restarted") is True
            )
    for k in [
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_execution",
        "cleanup_executed",
        "apply_executed",
        "docker_compose_executed",
    ]:
        checks[f"{k}_false"] = safety.get(k) is False
    all_ok = (
        all(bool(v) for v in checks.values())
        and bool(receipt.get("schema_version"))
        and bool(receipt.get("receipt_id"))
    )
    base["status"] = "ok" if all_ok else "failed"
    base["receipt"] = {
        "receipt_id": receipt.get("receipt_id"),
        "plan_id": receipt.get("plan_id"),
        "executor_mode": receipt.get("executor_mode"),
        "target": receipt.get("target"),
        "scenario": receipt.get("scenario"),
    }
    base["checks"] = checks
    base["safety"] = safety
    return base


def report_receipt_payload(data_dir: Path, receipt_id_or_path: str) -> dict[str, Any]:
    v = validate_receipt_payload(data_dir, receipt_id_or_path)
    if v["status"] in {"not_found", "error"}:
        return {
            "schema_version": "1",
            "status": v["status"],
            "mode": "disposable_remediation_report",
            "receipt": {},
            "summary": {},
            "handoff": {},
            "next_safe_commands": [],
            "safety": {},
            "warnings": v.get("warnings") or [],
        }
    rid = v["receipt"].get("receipt_id") or "<receipt-id>"
    return {
        "schema_version": "1",
        "status": "ok" if v["status"] == "ok" else "error",
        "mode": "disposable_remediation_report",
        "receipt": v["receipt"],
        "summary": {
            "executor_mode": v["receipt"].get("executor_mode"),
            "target": v["receipt"].get("target"),
            "scenario": v["receipt"].get("scenario"),
            "action_executed": bool(v["safety"].get("mutation_performed")),
            "restart_verified": bool(v["checks"].get("restart_verified")),
            "production_target": v["safety"].get("production_target"),
            "disposable": v["safety"].get("disposable"),
            "target_allowlisted": v["safety"].get("target_allowlisted"),
        },
        "handoff": {
            "validation_status": v["status"],
            "production_mutation_recorded": bool(v["safety"].get("production_target")),
            "compose_mutation_recorded": bool(v["safety"].get("docker_compose_executed")),
            "cleanup_execution_recorded": bool(v["safety"].get("cleanup_executed")),
        },
        "next_safe_commands": [
            f"shellforgeai remediation receipt validate {rid}",
            f"shellforgeai remediation status {rid} --json",
            "shellforgeai triage docker snapshot --save --include-details",
        ],
        "safety": v["safety"],
        "warnings": v.get("warnings") or [],
    }


def rollback_validate_payload(data_dir: Path, receipt_id_or_path: str) -> dict[str, Any]:
    base = {
        "schema_version": "1",
        "status": "error",
        "mode": "disposable_remediation_rollback_validate",
        "receipt_id": receipt_id_or_path,
        "checks": {},
        "safety": {
            "read_only": True,
            "rollback_executed": False,
            "mutation_performed": False,
            "automatic_rollback": False,
            "natural_language_execution": False,
            "shell_true": False,
        },
        "warnings": [],
    }
    path, err = resolve_receipt_path(data_dir, receipt_id_or_path)
    if path is None:
        base["status"] = "not_found" if err == "receipt not found" else "error"
        base["warnings"] = [err or "receipt not found"]
        return base
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        base["status"] = "error"
        base["warnings"] = [f"receipt JSON unreadable: {exc}"]
        return base
    if not receipt:
        base["status"] = "not_found"
        base["warnings"] = ["receipt not found"]
        return base
    if receipt.get("kind") == ROLLBACK_RECEIPT_KIND:
        safety = receipt.get("safety") if isinstance(receipt.get("safety"), dict) else {}
        verification = (
            receipt.get("verification") if isinstance(receipt.get("verification"), dict) else {}
        )
        checks = {
            "kind": True,
            "original_receipt_id_present": bool(receipt.get("original_receipt_id")),
            "target_present": bool(receipt.get("target")),
            "production_target_refused": safety.get("production_target") is False,
            "allowlisted": safety.get("target_allowlisted") is True,
            "disposable": safety.get("disposable") is True,
            "exact_target_only": bool(receipt.get("exact_target_only")) is True,
            "automatic_rollback_disabled": bool(receipt.get("automatic_rollback")) is False,
            "shell_true_false": safety.get("shell_true") is False,
            "arbitrary_command_execution_false": safety.get("arbitrary_command_execution") is False,
            "docker_compose_executed_false": safety.get("docker_compose_executed") is False,
            "cleanup_executed_false": safety.get("cleanup_executed") is False,
            "verification_present": bool(verification),
            "target_match": verification.get("target_match") is True,
            "command_ok": verification.get("command_ok") is True,
            "started_at_changed": verification.get("started_at_changed") is True,
            "rollback_verified": verification.get("rollback_verified") is True,
        }
        base["status"] = "ok" if all(checks.values()) else "failed"
        base["receipt_id"] = str(receipt.get("rollback_receipt_id") or receipt_id_or_path)
        base["checks"] = checks
        base["safety"] = safety
        return base
    v = validate_receipt_payload(data_dir, receipt_id_or_path)
    if v["status"] in {"not_found", "error"}:
        base["status"] = v["status"]
        base["warnings"] = list(v.get("warnings") or [])
        return base
    rb = (
        receipt.get("rollback")
        if isinstance(receipt.get("rollback"), dict)
        else derive_rollback_payload(receipt)
    )
    safety = receipt.get("safety") if isinstance(receipt.get("safety"), dict) else {}
    checks = {
        "receipt_exists": True,
        "receipt_json_parse": True,
        "receipt_valid": v["status"] == "ok",
        "rollback_strategy": bool(rb.get("rollback_strategy")),
        "exact_target_only": rb.get("rollback_scope_exact_target_only") is True,
        "production_target_refused": safety.get("production_target") is False,
        "disposable": safety.get("disposable") is True,
        "allowlisted": safety.get("target_allowlisted") is True,
        "automatic_rollback_disabled": rb.get("automatic_rollback") is False,
        "explicit_confirm_required": rb.get("rollback_requires_explicit_confirm") is True,
        "shell_true_false": safety.get("shell_true") is False,
        "arbitrary_command_execution_false": safety.get("arbitrary_command_execution") is False,
    }
    ok = all(checks.values())
    base["status"] = "ok" if ok else "blocked"
    base["receipt_id"] = str(receipt.get("receipt_id") or receipt_id_or_path)
    base["checks"] = checks
    if "rollback" not in receipt:
        base["warnings"].append("rollback metadata missing; derived from receipt")
    return base


def rollback_preflight_payload(data_dir: Path, receipt_id_or_path: str) -> dict[str, Any]:
    rv = rollback_validate_payload(data_dir, receipt_id_or_path)
    payload = {
        "schema_version": "1",
        "status": "error",
        "mode": "disposable_remediation_rollback_preflight",
        "receipt_id": receipt_id_or_path,
        "plan_id": None,
        "target": None,
        "rollback": {},
        "action_preview": {"argv": [], "shell_true": False, "arbitrary_command_execution": False},
        "checks": {
            "receipt_valid": False,
            "target_disposable": False,
            "target_allowlisted": False,
            "production_target": True,
            "exact_target_only": False,
        },
        "safety": {
            "read_only": True,
            "rollback_executed": False,
            "mutation_performed": False,
            "automatic_rollback": False,
            "cleanup_executed": False,
            "proposal_created": False,
            "mission_created": False,
            "apply_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "natural_language_execution": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
        },
        "warnings": list(rv.get("warnings") or []),
    }
    if rv["status"] in {"not_found", "error"}:
        payload["status"] = rv["status"]
        return payload
    receipt = load_receipt(data_dir, str(rv.get("receipt_id") or ""))
    if not receipt:
        payload["status"] = "not_found"
        return payload
    rb = (
        receipt.get("rollback")
        if isinstance(receipt.get("rollback"), dict)
        else derive_rollback_payload(receipt)
    )
    target = str(receipt.get("target") or "")
    payload["receipt_id"] = str(receipt.get("receipt_id") or receipt_id_or_path)
    payload["plan_id"] = receipt.get("plan_id")
    payload["target"] = target
    payload["rollback"] = rb
    payload["action_preview"] = {
        "argv": ["docker", "restart", target],
        "shell_true": False,
        "arbitrary_command_execution": False,
    }
    payload["checks"] = {
        "receipt_valid": rv["checks"].get("receipt_valid") is True,
        "target_disposable": rv["checks"].get("disposable") is True,
        "target_allowlisted": rv["checks"].get("allowlisted") is True,
        "production_target": not rv["checks"].get("production_target_refused"),
        "exact_target_only": rv["checks"].get("exact_target_only") is True,
    }
    payload["status"] = "ready" if rv["status"] == "ok" else "blocked"
    return payload


def build_preflight_payload(
    *,
    data_dir: Path,
    plan_id: str,
    executor: str,
    scene_state: dict[str, Any] | None,
    inspect_state: dict[str, Any] | None,
) -> dict[str, Any]:
    base_safety = {
        "read_only": True,
        "mutation_performed": False,
        "execution_performed": False,
        "cleanup_executed": False,
        "proposal_created": False,
        "mission_created": False,
        "apply_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "natural_language_execution": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
    }
    packet = {
        "schema_version": "1",
        "mode": "disposable_remediation_preflight",
        "status": "error",
        "plan": {"plan_id": plan_id},
        "target": {},
        "planned_action": {},
        "verification_expectation": {},
        "recovery": {},
        "decision": {"preflight_status": "error", "reasons": []},
        "safety": base_safety,
        "warnings": [],
    }
    plan = load_plan(data_dir, plan_id)
    if plan is None:
        packet["status"] = "not_found"
        packet["decision"]["preflight_status"] = "blocked"
        packet["decision"]["reasons"] = ["plan not found"]
        packet["warnings"] = ["plan not found"]
        return packet
    if executor not in {"proof", "docker-disposable"}:
        packet["status"] = "blocked"
        packet["decision"]["preflight_status"] = "blocked"
        packet["decision"]["reasons"] = ["unknown executor mode"]
        return packet
    ok, errs = validate_plan(plan)
    state = inspect_state or scene_state or {"name": plan.get("target")}
    labels = state.get("labels") if isinstance(state.get("labels"), dict) else {}
    labels = {str(k): str(v) for k, v in labels.items()}
    disposable = _has_any_label(labels, DISPOSABLE_LABELS)
    allowlisted = _has_any_label(labels, ALLOWLIST_LABELS)
    production = _is_production_target(str(plan.get("target") or ""))
    reasons = list(errs)
    if _is_broad_target(str(plan.get("target") or "")):
        reasons.append("broad target refused")
    if production:
        reasons.append("production target refused")
    if not disposable:
        reasons.append("target missing disposable labels")
    if not allowlisted:
        reasons.append("target missing allowlist labels")
    if executor not in (plan.get("executor_modes_supported") or []):
        reasons.append("executor mode unsupported by plan")
    reasons = sorted(set(reasons))
    ready = ok and not reasons
    packet["status"] = "ready" if ready else "blocked"
    packet["plan"] = {
        "plan_id": plan_id,
        "fingerprint": plan.get("fingerprint"),
        "scenario": plan.get("scenario"),
        "executor": executor,
        "default_executor": plan.get("default_executor", "proof"),
        "executor_modes_supported": plan.get("executor_modes_supported") or ["proof"],
    }
    packet["target"] = {
        "name": plan.get("target"),
        "kind": plan.get("target_kind", "container"),
        "container_id": state.get("id"),
        "image": state.get("image"),
        "running": state.get("running"),
        "health": state.get("health") or "",
        "started_at": state.get("StartedAt"),
        "restart_count": state.get("restart_count"),
        "compose_project": ((state.get("compose") or {}).get("project")),
        "compose_service": ((state.get("compose") or {}).get("service")),
        "labels": labels,
        "disposable": disposable,
        "target_allowlisted": allowlisted,
        "production_target": production,
    }
    packet["planned_action"] = {
        "action_preview": plan.get("action_preview"),
        "command_display": plan.get("action_preview"),
        "argv": ["docker", "restart", str(plan.get("target"))],
        "exact_target_only": True,
        "shell_true": False,
        "arbitrary_command_execution": False,
    }
    packet["verification_expectation"] = {
        "expected_signal": "proof_receipt_only" if executor == "proof" else "started_at_changed",
        "pre_state_required": True,
        "post_state_required": True,
        "receipt_required": True,
        "post_check_criteria": plan.get("post_checks") or [],
    }
    packet["recovery"] = {
        "automatic_rollback": False,
        "recovery_available": False,
        "recovery_validated": False,
        "note": plan.get("rollback_or_recovery_note"),
        "human_recovery_command": "",
    }
    packet["decision"] = {
        "preflight_status": "ready" if ready else "blocked",
        "reasons": reasons,
        "operator_approval_required": True,
        "approval_warning": (
            "Ready means gates are satisfied. It does not mean you approved execution."
        ),
    }
    if ready:
        packet["decision"]["execute_command"] = (
            f"shellforgeai remediation execute {plan_id} --executor {executor} --execute --confirm"
        )
    return packet


def container_state_from_scene(scene: dict[str, Any], target: str) -> dict[str, Any] | None:
    for row in scene.get("containers") or []:
        if row.get("name") == target:
            labels_raw = row.get("labels") if isinstance(row.get("labels"), dict) else {}
            labels = {str(k): str(v) for k, v in labels_raw.items()}
            return {
                "id": row.get("id"),
                "name": row.get("name"),
                "labels": labels,
                "status": row.get("status") or row.get("state"),
                "StartedAt": row.get("StartedAt") or row.get("started_at"),
                "restart_count": row.get("restart_count"),
                "image": row.get("image"),
                "compose": {
                    "project": labels.get("com.docker.compose.project"),
                    "service": labels.get("com.docker.compose.service"),
                },
            }
    return None


def run_exact_docker_restart(target: str) -> tuple[bool, int, str, str]:
    try:
        cp = subprocess.run(
            ["docker", "restart", target],
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )
    except OSError as exc:
        return (False, 127, "", str(exc))
    return (cp.returncode == 0, cp.returncode, cp.stdout, cp.stderr)


def inspect_exact_target_state(target: str) -> dict[str, Any] | None:
    try:
        cp = subprocess.run(
            ["docker", "inspect", target],
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )
    except OSError:
        return None
    if cp.returncode != 0:
        return None
    try:
        payload = json.loads(cp.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, list) or not payload:
        return None
    row = payload[0] if isinstance(payload[0], dict) else {}
    state = row.get("State") if isinstance(row.get("State"), dict) else {}
    cfg = row.get("Config") if isinstance(row.get("Config"), dict) else {}
    labels_raw = cfg.get("Labels") if isinstance(cfg.get("Labels"), dict) else {}
    labels = {str(k): str(v) for k, v in labels_raw.items()}
    name = str(row.get("Name") or "").lstrip("/")
    return {
        "id": row.get("Id"),
        "name": name or target,
        "labels": labels,
        "status": state.get("Status"),
        "running": state.get("Running"),
        "StartedAt": state.get("StartedAt"),
        "restart_count": state.get("RestartCount"),
        "image": row.get("Image"),
        "compose": {
            "project": labels.get("com.docker.compose.project"),
            "service": labels.get("com.docker.compose.service"),
        },
    }


def remediation_bundle_dir(data_dir: Path) -> Path:
    return data_dir / "artifacts" / "remediation-bundles"


def build_remediation_audit_payload(data_dir: Path, *, latest_only: bool = False) -> dict[str, Any]:
    plans_dir = plan_artifacts_dir(data_dir)
    receipts_dir = receipt_artifacts_dir(data_dir)
    bundles_dir = remediation_bundle_dir(data_dir)
    artifacts: list[dict[str, Any]] = []
    warnings: list[str] = []
    invalid_artifacts = 0

    plans: dict[str, dict[str, Any]] = {}
    exec_receipts: dict[str, dict[str, Any]] = {}
    rollback_receipts: dict[str, dict[str, Any]] = {}
    bundles: list[tuple[float, str, dict[str, Any]]] = []

    def _load_json(path: Path, kind: str) -> dict[str, Any] | None:
        nonlocal invalid_artifacts
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            artifacts.append({"kind": kind, "id": path.stem, "path": str(path), "valid_json": True})
            return payload if isinstance(payload, dict) else {}
        except Exception as exc:
            invalid_artifacts += 1
            warnings.append(f"{kind} unreadable: {path.name}: {exc}")
            artifacts.append(
                {
                    "kind": kind,
                    "id": path.stem,
                    "path": str(path),
                    "valid_json": False,
                    "warning": str(exc),
                }
            )
            return None

    for p in sorted(plans_dir.glob("drp_*.json")) if plans_dir.exists() else []:
        payload = _load_json(p, "plan")
        if payload is not None:
            plans[str(payload.get("plan_id") or p.stem)] = payload
    for p in sorted(receipts_dir.glob("drr_*.json")) if receipts_dir.exists() else []:
        payload = _load_json(p, "execution_receipt")
        if payload is not None:
            exec_receipts[str(payload.get("receipt_id") or p.stem)] = payload
    for p in sorted(receipts_dir.glob("drrb_*.json")) if receipts_dir.exists() else []:
        payload = _load_json(p, "rollback_receipt")
        if payload is not None:
            rollback_receipts[str(payload.get("rollback_receipt_id") or p.stem)] = payload
    for p in (
        sorted(bundles_dir.glob("*/remediation-lifecycle.json")) if bundles_dir.exists() else []
    ):
        payload = _load_json(p, "lifecycle_bundle")
        if payload is not None:
            bundles.append((p.stat().st_mtime, p.parent.name, payload))

    latest_bundle_id = ""
    latest_lifecycle = {
        "bundle_id": "",
        "plan_id": "",
        "receipt_id": "",
        "rollback_receipt_id": "",
        "target": "",
        "production_target": False,
        "disposable": True,
        "target_allowlisted": True,
        "execution_verified": False,
        "rollback_verified": False,
    }
    if bundles:
        _, latest_bundle_id, latest_bundle = max(bundles, key=lambda row: row[0])
        lc = latest_bundle.get("lifecycle") or {}
        latest_lifecycle.update(
            {
                "bundle_id": latest_bundle_id,
                "plan_id": str(lc.get("plan_id") or ""),
                "receipt_id": str(lc.get("receipt_id") or ""),
                "rollback_receipt_id": str(lc.get("rollback_receipt_id") or ""),
                "target": str(lc.get("target") or ""),
                "production_target": bool(lc.get("production_target")),
                "disposable": bool(lc.get("disposable", True)),
                "target_allowlisted": bool(lc.get("target_allowlisted", True)),
                "execution_verified": bool(
                    (latest_bundle.get("execution") or {}).get("restart_verified")
                ),
                "rollback_verified": bool(
                    (latest_bundle.get("rollback") or {}).get("rollback_verified")
                ),
            }
        )
    elif exec_receipts:
        rid = sorted(exec_receipts.keys())[-1]
        rec = exec_receipts[rid]
        safe = rec.get("safety") if isinstance(rec.get("safety"), dict) else {}
        latest_lifecycle.update(
            {
                "receipt_id": rid,
                "plan_id": str(rec.get("plan_id") or ""),
                "target": str(rec.get("target") or ""),
                "production_target": bool(safe.get("production_target")),
                "disposable": bool(safe.get("disposable", True)),
                "target_allowlisted": bool(safe.get("target_allowlisted", True)),
                "execution_verified": bool((rec.get("verification") or {}).get("restart_verified")),
            }
        )
        for rb in rollback_receipts.values():
            if rb.get("original_receipt_id") == rid:
                latest_lifecycle["rollback_receipt_id"] = str(rb.get("rollback_receipt_id") or "")
                latest_lifecycle["rollback_verified"] = bool(
                    (rb.get("verification") or {}).get("rollback_verified")
                )
                break

    safety_flags = {
        "production_mutation_recorded": False,
        "docker_compose_mutation_recorded": False,
        "cleanup_execution_recorded": False,
        "mission_apply_execution_recorded": False,
        "shell_true_recorded": False,
        "arbitrary_command_execution_recorded": False,
        "natural_language_execution_recorded": False,
    }
    for payload in [*plans.values(), *exec_receipts.values(), *rollback_receipts.values()]:
        safety = payload.get("safety") if isinstance(payload.get("safety"), dict) else {}
        safety_flags["production_mutation_recorded"] |= bool(safety.get("production_target"))
        safety_flags["docker_compose_mutation_recorded"] |= bool(
            safety.get("docker_compose_executed")
        )
        safety_flags["cleanup_execution_recorded"] |= bool(safety.get("cleanup_executed"))
        safety_flags["mission_apply_execution_recorded"] |= bool(
            safety.get("apply_executed") or safety.get("mission_created")
        )
        safety_flags["shell_true_recorded"] |= bool(safety.get("shell_true"))
        safety_flags["arbitrary_command_execution_recorded"] |= bool(
            safety.get("arbitrary_command_execution")
        )
        safety_flags["natural_language_execution_recorded"] |= bool(
            safety.get("natural_language_execution")
        )

    for key, flagged in safety_flags.items():
        if flagged:
            warnings.append(f"unsafe historical artifact: {key}=true")
    if latest_lifecycle.get("receipt_id") and not exec_receipts.get(
        str(latest_lifecycle["receipt_id"])
    ):
        warnings.append("latest lifecycle links missing execution receipt")
        invalid_artifacts += 1

    if latest_only and latest_bundle_id:
        artifacts = [a for a in artifacts if f"/{latest_bundle_id}/" in a.get("path", "")]
    status = "ok"
    if not plans and not exec_receipts and not rollback_receipts and not bundles:
        status = "empty"
        warnings.append("no disposable remediation lifecycle artifacts found")
    elif warnings or invalid_artifacts > 0:
        status = "warn"
    payload = {
        "schema_version": "1",
        "mode": "disposable_remediation_audit",
        "status": status,
        "summary": {
            "plans": len(plans),
            "execution_receipts": len(exec_receipts),
            "rollback_receipts": len(rollback_receipts),
            "bundles": len(bundles),
            "invalid_artifacts": invalid_artifacts,
            "latest_lifecycle_id": latest_bundle_id,
        },
        "latest_lifecycle": latest_lifecycle,
        "safety_audit": {
            "read_only": True,
            "mutation_performed": False,
            **safety_flags,
        },
        "artifacts": artifacts,
        "warnings": warnings,
        "next_safe_commands": [
            "shellforgeai remediation bundle-validate <bundle-id>",
            "shellforgeai remediation receipt validate <receipt-id>",
            "shellforgeai remediation rollback-status <rollback-receipt-id>",
        ],
    }
    return payload


def build_lifecycle_bundle_payload(data_dir: Path, token: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1",
        "status": "planned",
        "mode": "disposable_remediation_lifecycle_bundle",
        "lifecycle": {},
        "plan": {"present": False},
        "preflight": {},
        "execution": {"present": False},
        "rollback": {"executed": False},
        "artifact": {"saved": False, "id": "", "path": ""},
        "safety": {
            "read_only": True,
            "bundle_only": True,
            "mutation_performed": False,
            "remediation_executed_by_bundle": False,
            "rollback_executed_by_bundle": False,
            "cleanup_executed": False,
            "proposal_created": False,
            "mission_created": False,
            "apply_executed": False,
            "docker_compose_executed": False,
            "production_mutation_recorded": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "natural_language_execution": False,
            "arbitrary_path_write": False,
        },
        "next_safe_commands": [],
        "warnings": [],
    }
    plan = load_plan(data_dir, token)
    receipt: dict[str, Any] | None = None
    rollback_receipt: dict[str, Any] | None = None
    if plan is None:
        receipt = load_receipt(data_dir, token)
    if receipt and receipt.get("kind") == ROLLBACK_RECEIPT_KIND:
        rollback_receipt = receipt
        receipt = load_receipt(data_dir, str(rollback_receipt.get("original_receipt_id") or ""))
    if receipt and not plan:
        plan = load_plan(data_dir, str(receipt.get("plan_id") or ""))
    if receipt and not rollback_receipt:
        for p in receipt_artifacts_dir(data_dir).glob("drrb_*.json"):
            try:
                rb = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if rb.get("original_receipt_id") == receipt.get("receipt_id"):
                rollback_receipt = rb
                break
    if not plan and not receipt and not rollback_receipt:
        payload["status"] = "not_found"
        payload["warnings"] = ["plan/receipt not found"]
        return payload
    lifecycle = {
        "plan_id": (plan or {}).get("plan_id"),
        "receipt_id": (receipt or {}).get("receipt_id"),
        "rollback_receipt_id": (rollback_receipt or {}).get("rollback_receipt_id"),
        "target": (receipt or plan or {}).get("target"),
        "scenario": (receipt or plan or {}).get("scenario"),
        "executor": (receipt or {}).get("executor_mode"),
        "production_target": bool(((receipt or {}).get("safety") or {}).get("production_target")),
        "disposable": bool(((receipt or plan or {}).get("safety") or {}).get("disposable", True)),
        "target_allowlisted": bool(
            ((receipt or plan or {}).get("safety") or {}).get("target_allowlisted", True)
        ),
    }
    payload["lifecycle"] = lifecycle
    if plan:
        ok, errs = validate_plan(plan)
        payload["plan"] = {
            "present": True,
            "validation_status": "ok" if ok else "failed",
            "fingerprint": plan.get("fingerprint"),
            "fingerprint_matches_receipt": receipt is None
            or receipt.get("plan_fingerprint") == plan.get("fingerprint"),
            "warnings": errs,
        }
    if plan:
        payload["preflight"] = {
            "status": "ready" if payload["plan"]["validation_status"] == "ok" else "blocked",
            "argv": ["docker", "restart", str(plan.get("target") or "")],
            "shell_true": False,
            "arbitrary_command_execution": False,
            "approval_required": True,
        }
    if receipt:
        rv = validate_receipt_payload(data_dir, str(receipt.get("receipt_id") or ""))
        payload["execution"] = {
            "present": True,
            "status": "executed"
            if (receipt.get("verification") or {}).get("status") == "passed"
            else "failed",
            "receipt_valid": rv.get("status") == "ok",
            "restart_verified": bool((receipt.get("verification") or {}).get("restart_verified")),
            "docker_restart_succeeded": bool(receipt.get("docker_restart_succeeded")),
        }
    if receipt:
        rbv = rollback_validate_payload(data_dir, str(receipt.get("receipt_id") or ""))
        payload["rollback"]["validate_status"] = rbv.get("status")
    if rollback_receipt:
        rbvv = rollback_validate_payload(
            data_dir, str(rollback_receipt.get("rollback_receipt_id") or "")
        )
        payload["rollback"].update(
            {
                "executed": True,
                "receipt_valid": rbvv.get("status") == "ok",
                "rollback_verified": bool(
                    (rollback_receipt.get("verification") or {}).get("rollback_verified")
                ),
                "automatic_rollback": bool(rollback_receipt.get("automatic_rollback")),
            }
        )
    payload["status"] = "ok" if receipt else "planned"
    return payload
