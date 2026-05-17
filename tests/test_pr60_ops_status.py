from __future__ import annotations

import json

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def test_ops_status_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    r = runner.invoke(app, ["ops", "status"])
    assert r.exit_code == 0
    assert "ShellForgeAI ops status" in r.stdout
    assert "none found" in r.stdout


def test_ops_status_json_strict_and_safety(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    (tmp_path / "proposals").mkdir()
    (tmp_path / "proposals" / "prop_1.json").write_text(
        json.dumps({"proposal_id": "prop_1", "status": "pending", "kind": "docker_restart"}),
        encoding="utf-8",
    )
    r = runner.invoke(app, ["ops", "status", "--json"])
    assert r.exit_code == 0
    out = json.loads(r.stdout)
    assert out["schema_version"] == "1"
    assert out["safety"]["read_only"] is True
    assert out["safety"]["compose_mutation"] is False
    assert out["safety"]["arbitrary_command_execution"] is False
    assert out["proposals"]["counts"]["pending"] == 1


def test_ops_status_malformed_warning(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    (tmp_path / "proposals").mkdir()
    (tmp_path / "proposals" / "bad.json").write_text("{", encoding="utf-8")
    r = runner.invoke(app, ["ops", "status", "--json"])
    assert r.exit_code == 0
    out = json.loads(r.stdout)
    assert out["status"] == "warn"
    assert out["warnings"]
