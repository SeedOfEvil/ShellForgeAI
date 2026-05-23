from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.disposable_remediation import write_plan, write_receipt


def _env(tmp_path: Path) -> dict[str, str]:
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


def _plan(data: Path) -> dict:
    return write_plan(
        data_dir=data,
        target="sfai-pr94-user-sim",
        scenario="sfai-noisy-errors",
        labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
    )["plan"]


def test_bundle_from_plan_planned(tmp_path: Path):
    data = tmp_path / "data"
    plan = _plan(data)
    r = CliRunner().invoke(
        app, ["remediation", "bundle", plan["plan_id"], "--json"], env=_env(tmp_path)
    )
    assert r.exit_code == 0
    j = json.loads(r.stdout)
    assert j["status"] == "planned"


def test_bundle_save_and_validate(tmp_path: Path):
    data = tmp_path / "data"
    plan = _plan(data)
    receipt = {
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
        },
    }
    write_receipt(data, receipt)
    runner = CliRunner()
    b = runner.invoke(
        app,
        ["remediation", "bundle", "drr_aaaaaaaaaaaa", "--save", "--json"],
        env=_env(tmp_path),
    )
    assert b.exit_code == 0
    bj = json.loads(b.stdout)
    assert bj["artifact"]["saved"] is True
    vid = bj["artifact"]["id"]
    v = runner.invoke(app, ["remediation", "bundle-validate", vid, "--json"], env=_env(tmp_path))
    assert v.exit_code == 0
    assert json.loads(v.stdout)["status"] == "ok"
