from __future__ import annotations

import json

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _containers_payload(rows):
    class _Res:
        ok = True
        stdout = json.dumps({"containers": rows})

    return _Res()


def test_compose_restart_preview_human_ok(monkeypatch) -> None:
    rows = [
        {
            "name": "shellforgeai",
            "compose": {
                "detected": True,
                "project": "shellforgeai",
                "service": "shellforgeai",
                "working_dir": "/srv/compose/shellforgeai",
                "config_files": ["/srv/compose/shellforgeai/compose.yml"],
                "oneoff": False,
            },
        }
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    res = runner.invoke(app, ["compose", "restart-preview", "shellforgeai"])
    assert "Compose service restart preview" in res.stdout
    assert "compose_mutation: True" in res.stdout
    assert "preview_only: True" in res.stdout
    assert "execution_allowed: False" in res.stdout
    assert "executed: False" in res.stdout


def test_compose_restart_preview_json(monkeypatch) -> None:
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
    res = runner.invoke(app, ["compose", "restart-preview", "shellforgeai", "--json"])
    body = json.loads(res.stdout)
    assert body["schema_version"] == "1"
    assert body["preview"]["command"][-2:] == ["restart", "s"]
    assert body["preview"]["compose_mutation"] is True
    assert body["preview"]["preview_only"] is True
    assert body["preview"]["execution_allowed"] is False
    assert body["preview"]["executed"] is False
    assert body["safety"]["read_only"] is True
    assert body["safety"]["docker_compose_executed"] is False
    assert body["safety"]["arbitrary_command_execution"] is False


def test_compose_restart_preview_ambiguous(monkeypatch) -> None:
    rows = [
        {"name": "c1", "compose": {"detected": True, "project": "p1", "service": "shellforgeai"}},
        {"name": "c2", "compose": {"detected": True, "project": "p2", "service": "shellforgeai"}},
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    res = runner.invoke(app, ["compose", "restart-preview", "shellforgeai"])
    assert "multiple Compose service matches" in res.stdout
    assert "No docker compose command was executed." in res.stdout


def test_ask_compose_restart_preview_and_refusal(monkeypatch) -> None:
    rows = [
        {
            "name": "shellforgeai",
            "compose": {
                "detected": True,
                "project": "p",
                "service": "shellforgeai",
                "working_dir": "/w",
                "config_files": ["/w/c.yml"],
            },
        }
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    res = runner.invoke(app, ["ask", "show compose restart preview for shellforgeai"])
    assert "preview_only: True" in res.stdout
    res2 = runner.invoke(app, ["ask", "docker compose restart shellforgeai"])
    assert "Refusing natural-language Compose mutation" in res2.stdout
