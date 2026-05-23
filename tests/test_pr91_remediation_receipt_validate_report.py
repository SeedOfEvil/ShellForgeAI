import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.disposable_remediation import write_plan, write_receipt

runner = CliRunner()


def _env(tmp_path):
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


def _mk_receipt(tmp_path, executor_mode="proof", status="executed"):
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    p = write_plan(
        data_dir=data,
        target="x",
        scenario="sfai-noisy-errors",
        labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
    )
    rec = {
        "schema_version": 1,
        "kind": "disposable_remediation_receipt",
        "receipt_id": "drr_aaaaaaaaaaaa",
        "plan_id": p["plan_id"],
        "plan_fingerprint": p["plan"]["fingerprint"],
        "target": "x",
        "scenario": "sfai-noisy-errors",
        "executor_mode": executor_mode,
        "real_docker_executor": executor_mode == "docker-disposable",
        "action_executed": executor_mode == "docker-disposable",
        "docker_restart_attempted": executor_mode == "docker-disposable",
        "docker_restart_succeeded": executor_mode == "docker-disposable",
        "return_code": 0,
        "pre_state": {"StartedAt": "a", "restart_count": 0},
        "post_state": {"StartedAt": "b", "restart_count": 1, "name": "x"},
        "verification": {
            "status": "passed" if status == "executed" else "failed",
            "restart_verified": executor_mode == "docker-disposable",
        },
        "safety": {
            "read_only": executor_mode == "proof",
            "mutation_performed": executor_mode == "docker-disposable",
            "production_target": False,
            "target_allowlisted": True,
            "disposable": True,
            "cleanup_executed": False,
            "proposal_created": False,
            "mission_created": False,
            "apply_executed": False,
            "docker_compose_executed": False,
            "container_restarted": executor_mode == "docker-disposable",
            "shell_true": False,
            "natural_language_execution": False,
            "arbitrary_command_execution": False,
        },
    }
    write_receipt(data, rec)
    return rec


def test_validate_proof_and_report_json(tmp_path):
    rec = _mk_receipt(tmp_path, "proof")
    rv = runner.invoke(
        app, ["remediation", "receipt", "validate", rec["receipt_id"], "--json"], env=_env(tmp_path)
    )
    assert rv.exit_code == 0
    pv = json.loads(rv.stdout)
    assert pv["status"] == "ok"

    rr = runner.invoke(
        app, ["remediation", "report", rec["receipt_id"], "--json"], env=_env(tmp_path)
    )
    assert rr.exit_code == 0
    pr = json.loads(rr.stdout)
    assert pr["status"] == "ok"
    assert pr["summary"]["action_executed"] is False


def test_validate_docker_disposable_success(tmp_path):
    rec = _mk_receipt(tmp_path, "docker-disposable")
    rv = runner.invoke(
        app, ["remediation", "receipt", "validate", rec["receipt_id"], "--json"], env=_env(tmp_path)
    )
    assert rv.exit_code == 0
    assert json.loads(rv.stdout)["checks"]["restart_verified"] is True


def test_missing_and_malformed_receipt(tmp_path):
    miss = runner.invoke(
        app,
        ["remediation", "receipt", "validate", "drr_bbbbbbbbbbbb", "--json"],
        env=_env(tmp_path),
    )
    assert miss.exit_code != 0
    assert json.loads(miss.stdout)["status"] == "not_found"

    data = tmp_path / "data" / "artifacts" / "remediation-receipts"
    data.mkdir(parents=True, exist_ok=True)
    (data / "drr_cccccccccccc.json").write_text("{", encoding="utf-8")
    bad = runner.invoke(
        app,
        ["remediation", "receipt", "validate", "drr_cccccccccccc", "--json"],
        env=_env(tmp_path),
    )
    assert bad.exit_code != 0
    assert json.loads(bad.stdout)["status"] == "error"


def test_path_traversal_refused(tmp_path):
    rv = runner.invoke(
        app, ["remediation", "receipt", "validate", "../etc/passwd", "--json"], env=_env(tmp_path)
    )
    assert rv.exit_code != 0
    assert json.loads(rv.stdout)["status"] == "error"


def test_failure_flags_fail_validation(tmp_path):
    rec = _mk_receipt(tmp_path, "proof")
    rp = Path(
        tmp_path / "data" / "artifacts" / "remediation-receipts" / f"{rec['receipt_id']}.json"
    )
    payload = json.loads(rp.read_text())
    payload["safety"]["shell_true"] = True
    rp.write_text(json.dumps(payload), encoding="utf-8")
    rv = runner.invoke(
        app, ["remediation", "receipt", "validate", rec["receipt_id"], "--json"], env=_env(tmp_path)
    )
    assert rv.exit_code != 0
    assert json.loads(rv.stdout)["status"] == "failed"
