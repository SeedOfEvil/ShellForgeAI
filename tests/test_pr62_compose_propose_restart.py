from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _containers_payload(rows):
    class _Res:
        ok = True
        stdout = json.dumps({"containers": rows})

    return _Res()


def _runtime_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path / "data"))


def test_compose_propose_restart_human_and_artifact(monkeypatch, tmp_path: Path) -> None:
    _runtime_env(monkeypatch, tmp_path)
    rows = [
        {
            "name": "shellforgeai",
            "compose": {
                "detected": True,
                "project": "p",
                "service": "s",
                "working_dir": "/w",
                "config_files": ["/w/c.yml"],
                "oneoff": False,
            },
        }
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    res = runner.invoke(
        app, ["compose", "propose-restart", "shellforgeai", "--reason", "planned maintenance"]
    )
    assert res.exit_code == 0
    assert "Compose service restart proposal created" in res.stdout
    assert "kind: compose_service_restart" in res.stdout
    assert "proposal_only: true" in res.stdout
    pid = [
        line.split(":", 1)[1].strip()
        for line in res.stdout.splitlines()
        if line.strip().startswith("- id:")
    ][0]
    proposal_path = tmp_path / "data" / "approvals" / "pending" / f"{pid}.proposal.json"
    assert proposal_path.exists()
    payload = json.loads(proposal_path.read_text(encoding="utf-8"))
    assert payload["kind"] == "compose_service_restart"
    assert payload["status"] == "pending"
    assert payload["compose_mutation"] is True
    assert payload["execution"]["allowed"] is False
    assert payload["fingerprint"]["algorithm"] == "sha256"
    assert len(payload["fingerprint"]["value"]) == 64


def test_compose_propose_restart_json(monkeypatch, tmp_path: Path) -> None:
    _runtime_env(monkeypatch, tmp_path)
    rows = [
        {
            "name": "shellforgeai",
            "compose": {
                "detected": True,
                "project": "p",
                "service": "s",
                "working_dir": "/w",
                "config_files": ["/w/c.yml"],
                "oneoff": False,
            },
        }
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    res = runner.invoke(app, ["compose", "propose-restart", "shellforgeai", "--json"])
    body = json.loads(res.stdout)
    assert body["schema_version"] == "1"
    assert body["status"] == "created"
    assert body["proposal"]["kind"] == "compose_service_restart"
    assert body["preview"]["command"][-2:] == ["restart", "s"]
    assert body["preview"]["execution_allowed"] is False
    assert body["safety"]["docker_compose_executed"] is False
    proposal_id = body["proposal"]["id"]
    validate = runner.invoke(app, ["approvals", "validate", proposal_id])
    assert validate.exit_code == 0
    assert "Proposal validation passed" in validate.stdout


def test_compose_propose_restart_not_found(monkeypatch, tmp_path: Path) -> None:
    _runtime_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload([]),
    )
    res = runner.invoke(app, ["compose", "propose-restart", "unknown"])
    assert res.exit_code == 1
    assert "No proposal was created." in res.stdout


def test_apply_refuses_compose_restart_proposal(monkeypatch, tmp_path: Path) -> None:
    _runtime_env(monkeypatch, tmp_path)
    rows = [
        {
            "name": "shellforgeai",
            "compose": {
                "detected": True,
                "project": "p",
                "service": "s",
                "working_dir": "/w",
                "config_files": ["/w/c.yml"],
                "oneoff": False,
            },
        }
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    create = runner.invoke(app, ["compose", "propose-restart", "shellforgeai", "--json"])
    pid = json.loads(create.stdout)["proposal"]["id"]
    approve = runner.invoke(app, ["approvals", "approve", pid, "--reason", "ok"])
    assert approve.exit_code == 0
    applied = runner.invoke(app, ["apply", pid])
    assert applied.exit_code == 1
    assert "proposal-only in PR62" in applied.stdout


def test_ask_compose_proposal_intent_suggests_cli_not_no_target(
    monkeypatch, tmp_path: Path
) -> None:
    _runtime_env(monkeypatch, tmp_path)
    res = runner.invoke(
        app,
        [
            "ask",
            (
                "create a proposal to restart the shellforgeai compose service, "
                "but do not execute anything"
            ),
        ],
    )
    assert res.exit_code == 0
    assert "shellforgeai compose propose-restart shellforgeai --reason" in res.stdout
    assert "No compose target found" not in res.stdout
    assert "no docker compose command was executed" in res.stdout


def test_ask_compose_mutation_refusal_version_neutral(monkeypatch, tmp_path: Path) -> None:
    _runtime_env(monkeypatch, tmp_path)
    for phrase in (
        "restart the shellforgeai compose service",
        "docker compose restart shellforgeai",
        "execute compose restart proposal",
    ):
        res = runner.invoke(app, ["ask", phrase])
        assert res.exit_code == 0
        assert "Refusing natural-language Compose mutation" in res.stdout
        assert "PR58 only enriches Compose context" not in res.stdout
