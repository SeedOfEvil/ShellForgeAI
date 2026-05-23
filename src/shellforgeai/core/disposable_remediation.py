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
    if not re.fullmatch(r"drr_[a-f0-9]{12}", token):
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
