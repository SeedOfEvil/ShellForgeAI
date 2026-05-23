from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.disposable_remediation import (
    derive_rollback_payload,
    write_plan,
    write_receipt,
)


def _mk_receipt(
    rid: str,
    *,
    mode: str = "docker-disposable",
    production: bool = False,
    disposable: bool = True,
    allowlisted: bool = True,
) -> dict:
    receipt = {
        "schema_version": 1,
        "kind": "disposable_remediation_receipt",
        "receipt_id": rid,
        "plan_id": "drp_aaaaaaaaaaaa",
        "plan_fingerprint": "abc",
        "target": "sfai-pr92-user-sim",
        "scenario": "sfai-noisy-errors",
        "executor_mode": mode,
        "pre_state": {},
        "post_state": {},
        "verification": {"status": "passed", "restart_verified": True},
        "safety": {
            "production_target": production,
            "disposable": disposable,
            "target_allowlisted": allowlisted,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "natural_language_execution": False,
            "cleanup_executed": False,
            "apply_executed": False,
            "docker_compose_executed": False,
            "container_restarted": mode == "docker-disposable",
            "mutation_performed": mode == "docker-disposable",
        },
        "real_docker_executor": mode == "docker-disposable",
        "docker_restart_attempted": mode == "docker-disposable",
        "docker_restart_succeeded": mode == "docker-disposable",
        "action_executed": mode == "docker-disposable",
        "return_code": 0,
    }
    receipt["rollback"] = derive_rollback_payload(receipt)
    return receipt


def test_rollback_metadata_in_receipt_modes():
    d = _mk_receipt("drr_aaaaaaaaaaaa", mode="docker-disposable")
    p = _mk_receipt("drr_bbbbbbbbbbbb", mode="proof")
    assert d["rollback"]["rollback_available"] is True
    assert p["rollback"]["proof_only"] is True


def test_rollback_preflight_and_validate_json(tmp_path: Path, monkeypatch):
    data = tmp_path / "data"
    plan = write_plan(
        data_dir=data,
        target="sfai-pr92-user-sim",
        scenario="sfai-noisy-errors",
        labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
    )["plan"]
    receipt = _mk_receipt("drr_cccccccccccc")
    receipt["plan_id"] = plan["plan_id"]
    receipt["plan_fingerprint"] = plan["fingerprint"]
    write_receipt(data, receipt)
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(data))
    runner = CliRunner()

    r1 = runner.invoke(app, ["remediation", "rollback-preflight", "drr_cccccccccccc", "--json"])
    assert r1.exit_code == 0
    j1 = json.loads(r1.stdout)
    assert j1["status"] == "ready"
    assert j1["action_preview"]["argv"] == ["docker", "restart", "sfai-pr92-user-sim"]
    assert j1["action_preview"]["shell_true"] is False

    r2 = runner.invoke(app, ["remediation", "rollback-validate", "drr_cccccccccccc", "--json"])
    assert r2.exit_code == 0
    j2 = json.loads(r2.stdout)
    assert j2["status"] == "ok"


def test_rollback_preflight_blocks_production(tmp_path: Path, monkeypatch):
    data = tmp_path / "data"
    write_receipt(data, _mk_receipt("drr_dddddddddddd", production=True))
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(data))
    runner = CliRunner()

    r = runner.invoke(app, ["remediation", "rollback-preflight", "drr_dddddddddddd", "--json"])
    assert r.exit_code != 0
    assert json.loads(r.stdout)["status"] == "blocked"
