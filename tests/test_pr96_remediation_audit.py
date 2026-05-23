from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.disposable_remediation import (
    remediation_bundle_dir,
    write_plan,
    write_receipt,
)


def _env(tmp_path: Path) -> dict[str, str]:
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


def _seed_bundle(data: Path, plan_id: str, receipt_id: str) -> str:
    bid = "remediation_bundle_20260523141411"
    out = remediation_bundle_dir(data) / bid
    out.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "1",
        "mode": "disposable_remediation_lifecycle_bundle",
        "lifecycle": {
            "plan_id": plan_id,
            "receipt_id": receipt_id,
            "rollback_receipt_id": "drrb_cccccccccccc",
            "target": "sfai-pr95-user-sim",
            "production_target": False,
            "disposable": True,
            "target_allowlisted": True,
        },
        "execution": {"restart_verified": True},
        "rollback": {"rollback_verified": True},
    }
    (out / "remediation-lifecycle.json").write_text(json.dumps(payload), encoding="utf-8")
    return bid


def test_remediation_audit_empty_json(tmp_path: Path):
    r = CliRunner().invoke(app, ["remediation", "audit", "--json"], env=_env(tmp_path))
    assert r.exit_code == 0
    j = json.loads(r.stdout)
    assert j["status"] == "empty"
    assert j["safety_audit"]["read_only"] is True


def test_remediation_audit_reports_lifecycle_and_safety(tmp_path: Path):
    data = tmp_path / "data"
    plan = write_plan(
        data_dir=data,
        target="sfai-pr95-user-sim",
        scenario="sfai-noisy-errors",
        labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
    )["plan"]
    write_receipt(
        data,
        {
            "schema_version": 1,
            "kind": "disposable_remediation_receipt",
            "receipt_id": "drr_aaaaaaaaaaaa",
            "plan_id": plan["plan_id"],
            "plan_fingerprint": plan["fingerprint"],
            "target": plan["target"],
            "scenario": plan["scenario"],
            "executor_mode": "docker-disposable",
            "verification": {"status": "passed", "restart_verified": True},
            "docker_restart_succeeded": True,
            "safety": {
                "production_target": False,
                "disposable": True,
                "target_allowlisted": True,
                "shell_true": False,
                "arbitrary_command_execution": False,
                "natural_language_execution": False,
                "cleanup_executed": False,
                "docker_compose_executed": False,
                "apply_executed": False,
            },
        },
    )
    rollback_receipt = {
        "schema_version": 1,
        "kind": "disposable_remediation_rollback_receipt",
        "rollback_receipt_id": "drrb_cccccccccccc",
        "original_receipt_id": "drr_aaaaaaaaaaaa",
        "verification": {"rollback_verified": True},
        "safety": {"shell_true": False, "docker_compose_executed": False},
    }
    receipt_dir = data / "artifacts" / "remediation-receipts"
    receipt_dir.mkdir(parents=True, exist_ok=True)
    (receipt_dir / "drrb_cccccccccccc.json").write_text(
        json.dumps(rollback_receipt), encoding="utf-8"
    )
    bundle_id = _seed_bundle(data, plan["plan_id"], "drr_aaaaaaaaaaaa")

    rj = CliRunner().invoke(app, ["remediation", "audit", "--latest", "--json"], env=_env(tmp_path))
    assert rj.exit_code == 0
    j = json.loads(rj.stdout)
    assert j["status"] == "ok"
    assert j["summary"]["latest_lifecycle_id"] == bundle_id
    assert j["latest_lifecycle"]["execution_verified"] is True
    assert j["latest_lifecycle"]["rollback_verified"] is True
    assert j["safety_audit"]["production_mutation_recorded"] is False

    rh = CliRunner().invoke(app, ["remediation", "audit"], env=_env(tmp_path))
    assert rh.exit_code == 0
    assert "Summary:" in rh.stdout
    assert "Safety audit:" in rh.stdout
    assert "Next safe commands:" in rh.stdout


def test_remediation_audit_warns_unsafe_and_malformed(tmp_path: Path):
    data = tmp_path / "data"
    receipt_dir = data / "artifacts" / "remediation-receipts"
    receipt_dir.mkdir(parents=True, exist_ok=True)
    (receipt_dir / "drr_badbadbadbad.json").write_text("{bad", encoding="utf-8")
    write_receipt(
        data,
        {
            "schema_version": 1,
            "kind": "disposable_remediation_receipt",
            "receipt_id": "drr_unsafeunsafe",
            "safety": {
                "production_target": True,
                "shell_true": True,
                "docker_compose_executed": True,
                "arbitrary_command_execution": False,
                "natural_language_execution": False,
                "cleanup_executed": False,
            },
        },
    )
    r = CliRunner().invoke(app, ["remediation", "audit", "--json"], env=_env(tmp_path))
    assert r.exit_code == 0
    j = json.loads(r.stdout)
    assert j["status"] == "warn"
    assert j["summary"]["invalid_artifacts"] > 0
    assert j["safety_audit"]["production_mutation_recorded"] is True
    assert j["safety_audit"]["shell_true_recorded"] is True
    assert j["safety_audit"]["docker_compose_mutation_recorded"] is True
