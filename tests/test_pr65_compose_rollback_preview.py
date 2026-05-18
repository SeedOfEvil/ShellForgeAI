from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _runtime(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path / "data"))


def _containers_payload(rows):
    class _Res:
        ok = True
        stdout = json.dumps({"containers": rows})

    return _Res()


def _make_proposal(monkeypatch, tmp_path: Path) -> str:
    compose_dir = tmp_path / "compose"
    compose_dir.mkdir()
    compose_file = compose_dir / "compose.yml"
    compose_file.write_text("services:\n  web:\n    image: nginx:alpine\n", encoding="utf-8")
    rows = [
        {
            "name": "web-1",
            "compose": {
                "detected": True,
                "project": "p",
                "service": "web",
                "working_dir": str(compose_dir),
                "config_files": [str(compose_file)],
                "labels": {"com.docker.compose.project": "p", "com.docker.compose.service": "web"},
            },
        }
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    out = json.loads(runner.invoke(app, ["compose", "propose-restart", "web-1", "--json"]).stdout)
    return out["proposal"]["id"]


def test_compose_rollback_preview_schema_and_safety(monkeypatch, tmp_path: Path) -> None:
    _runtime(monkeypatch, tmp_path)
    pid = _make_proposal(monkeypatch, tmp_path)

    res = runner.invoke(app, ["rollback", "preview", pid])
    assert res.exit_code == 0

    preview_path = tmp_path / "data" / "rollback_previews" / pid / "rollback-preview.json"
    payload = json.loads(preview_path.read_text(encoding="utf-8"))
    assert payload["kind"] == "compose_service_restart_recovery_preview"
    assert payload["proposal_id"] == pid
    assert payload["proposal_kind"] == "compose_service_restart"
    assert payload["proposed_operation"]["compose_mutation"] is True
    assert payload["recovery"]["automatic_rollback"] is False
    assert payload["recovery"]["rollback_command_generated"] is False
    assert payload["safety"]["docker_compose_executed"] is False
    assert payload["safety"]["container_restarted"] is False
    assert payload["safety"]["arbitrary_command_execution"] is False
    assert payload["config_state"]["compose_file_sha256"]


def test_compose_rollback_validate_rejects_up_command(monkeypatch, tmp_path: Path) -> None:
    _runtime(monkeypatch, tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "kind": "compose_service_restart_recovery_preview",
                "proposal_id": "p",
                "proposal_kind": "compose_service_restart",
                "proposal_fingerprint": "a" * 64,
                "target": {
                    "project": "p",
                    "service": "web",
                    "working_dir": "/w",
                    "compose_file": "/w/c.yml",
                },
                "proposed_operation": {
                    "command": ["docker", "compose", "up", "web"],
                    "compose_mutation": True,
                },
                "recovery": {
                    "automatic_rollback": False,
                    "rollback_command_generated": False,
                    "notes": ["n"],
                },
                "safety": {
                    "docker_compose_executed": False,
                    "container_restarted": False,
                    "arbitrary_command_execution": False,
                },
            }
        ),
        encoding="utf-8",
    )
    res = runner.invoke(app, ["rollback", "validate", str(bad)])
    assert res.exit_code == 1
    assert "up/down/recreate" in res.stdout


def test_compose_mission_checklist_uses_compose_preview(monkeypatch, tmp_path: Path) -> None:
    _runtime(monkeypatch, tmp_path)
    pid = _make_proposal(monkeypatch, tmp_path)
    runner.invoke(app, ["approvals", "approve", pid, "--reason", "ok"])

    pre = runner.invoke(app, ["mission", "compose-restart", "prepare", pid])
    mid = [
        ln.split(":", 1)[1].strip()
        for ln in pre.stdout.splitlines()
        if ln.strip().startswith("- mission:")
    ][0]
    c1 = runner.invoke(app, ["mission", "compose-restart", "checklist", mid])
    assert "rollback preview missing" in c1.stdout

    runner.invoke(app, ["rollback", "preview", pid])
    c2 = runner.invoke(app, ["mission", "compose-restart", "checklist", mid])
    assert "rollback preview missing" not in c2.stdout
