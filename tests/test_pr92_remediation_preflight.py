import json

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.disposable_remediation import write_plan

runner = CliRunner()


def _env(tmp_path):
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


def _scene_row(name, labels):
    return {
        "containers": [
            {
                "id": "abc123",
                "name": name,
                "labels": labels,
                "status": "running",
                "running": True,
                "StartedAt": "2026-01-01T00:00:00Z",
                "restart_count": 0,
                "image": "img:latest",
            }
        ]
    }


def test_preflight_ready_proof_json(tmp_path, monkeypatch):
    data = tmp_path / "data"
    p = write_plan(
        data_dir=data,
        target="x",
        scenario="sfai-noisy-errors",
        labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: _scene_row(
            "x", {"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"}
        ),
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.inspect_exact_target_state", lambda t: None
    )
    r = runner.invoke(app, ["remediation", "preflight", p["plan_id"], "--json"], env=_env(tmp_path))
    assert r.exit_code == 0
    payload = json.loads(r.stdout)
    assert payload["status"] == "ready"
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False
    assert payload["decision"]["execute_command"].endswith("--executor proof --execute --confirm")


def test_preflight_ready_docker_disposable_json(tmp_path, monkeypatch):
    data = tmp_path / "data"
    p = write_plan(
        data_dir=data,
        target="x",
        scenario="sfai-noisy-errors",
        labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
    )
    state = {
        "id": "abc",
        "name": "x",
        "labels": {"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
        "StartedAt": "2026-01-01T00:00:00Z",
        "restart_count": 0,
        "image": "img:latest",
        "running": True,
        "compose": {"project": "p", "service": "s"},
    }
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene", lambda: _scene_row("x", state["labels"])
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.inspect_exact_target_state", lambda t: state
    )
    r = runner.invoke(
        app,
        ["remediation", "preflight", p["plan_id"], "--executor", "docker-disposable", "--json"],
        env=_env(tmp_path),
    )
    assert r.exit_code == 0
    payload = json.loads(r.stdout)
    assert payload["planned_action"]["argv"] == ["docker", "restart", "x"]
    assert payload["target"]["compose_project"] == "p"
    assert payload["target"]["disposable"] is True


def test_preflight_blocked_no_execute_command(tmp_path, monkeypatch):
    data = tmp_path / "data"
    p = write_plan(
        data_dir=data,
        target="x",
        scenario="sfai-noisy-errors",
        labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene", lambda: _scene_row("x", {})
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.inspect_exact_target_state", lambda t: None
    )
    r = runner.invoke(app, ["remediation", "preflight", p["plan_id"], "--json"], env=_env(tmp_path))
    assert r.exit_code == 1
    payload = json.loads(r.stdout)
    assert payload["status"] == "blocked"
    assert "execute_command" not in payload["decision"]


def test_preflight_not_found_json_nonzero(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene", lambda: {"containers": []}
    )
    r = runner.invoke(
        app, ["remediation", "preflight", "drp_missing", "--json"], env=_env(tmp_path)
    )
    assert r.exit_code == 1
    payload = json.loads(r.stdout)
    assert payload["status"] == "not_found"


def test_preflight_read_only_no_receipt_created(tmp_path, monkeypatch):
    data = tmp_path / "data"
    p = write_plan(
        data_dir=data,
        target="x",
        scenario="sfai-noisy-errors",
        labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: _scene_row(
            "x", {"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"}
        ),
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.inspect_exact_target_state", lambda t: None
    )
    r = runner.invoke(app, ["remediation", "preflight", p["plan_id"], "--json"], env=_env(tmp_path))
    assert r.exit_code == 0
    receipts_dir = tmp_path / "data" / "artifacts" / "remediation-receipts"
    assert not receipts_dir.exists()
