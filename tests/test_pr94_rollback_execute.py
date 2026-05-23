from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.disposable_remediation import derive_rollback_payload, write_receipt


def _env(tmp_path: Path) -> dict[str, str]:
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


def _receipt(rid: str = "drr_aaaaaaaaaaaa") -> dict:
    rec = {
        "schema_version": 1,
        "kind": "disposable_remediation_receipt",
        "receipt_id": rid,
        "plan_id": "drp_aaaaaaaaaaaa",
        "plan_fingerprint": "abc",
        "target": "sfai-pr94-user-sim",
        "scenario": "sfai-noisy-errors",
        "executor_mode": "docker-disposable",
        "pre_state": {},
        "post_state": {},
        "verification": {"status": "passed", "restart_verified": True},
        "safety": {
            "production_target": False,
            "disposable": True,
            "target_allowlisted": True,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "natural_language_execution": False,
            "cleanup_executed": False,
            "apply_executed": False,
            "docker_compose_executed": False,
            "container_restarted": True,
            "mutation_performed": True,
        },
        "real_docker_executor": True,
        "docker_restart_attempted": True,
        "docker_restart_succeeded": True,
        "action_executed": True,
        "return_code": 0,
    }
    rec["rollback"] = derive_rollback_payload(rec)
    return rec


def test_rollback_execute_requires_flags(tmp_path: Path):
    data = tmp_path / "data"
    write_receipt(data, _receipt())
    runner = CliRunner()
    r = runner.invoke(
        app, ["remediation", "rollback-execute", "drr_aaaaaaaaaaaa", "--json"], env=_env(tmp_path)
    )
    assert r.exit_code != 0
    assert json.loads(r.stdout)["status"] == "blocked"


def test_rollback_execute_success_fixture(tmp_path: Path, monkeypatch):
    data = tmp_path / "data"
    write_receipt(data, _receipt())
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.inspect_exact_target_state",
        lambda t: {
            "name": t,
            "StartedAt": "b" if getattr(test_rollback_execute_success_fixture, "n", 0) else "a",
        },
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.run_exact_docker_restart",
        lambda t: (True, 0, "ok", ""),
    )
    test_rollback_execute_success_fixture.n = 0

    def _inspect(t):
        test_rollback_execute_success_fixture.n += 1
        return {
            "name": t,
            "StartedAt": "a" if test_rollback_execute_success_fixture.n == 1 else "b",
            "labels": {"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
        }

    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.inspect_exact_target_state", _inspect
    )

    runner = CliRunner()
    r = runner.invoke(
        app,
        ["remediation", "rollback-execute", "drr_aaaaaaaaaaaa", "--execute", "--confirm", "--json"],
        env=_env(tmp_path),
    )
    assert r.exit_code == 0
    j = json.loads(r.stdout)
    assert j["status"] == "executed"

    s = runner.invoke(
        app,
        ["remediation", "rollback-status", j["rollback_receipt_id"], "--json"],
        env=_env(tmp_path),
    )
    assert s.exit_code == 0
    assert json.loads(s.stdout)["status"] == "ok"
