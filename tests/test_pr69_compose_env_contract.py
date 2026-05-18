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


def test_env_contract_blocked_json(monkeypatch) -> None:
    rows = [
        {
            "name": "shellforgeai",
            "compose": {
                "detected": True,
                "project": "shellforgeai",
                "service": "shellforgeai",
                "container": "shellforgeai",
                "working_dir": "/srv/compose/shellforgeai",
                "config_files": ["/srv/compose/shellforgeai/compose.yml"],
                "labels": {},
            },
        }
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr(
        "shellforgeai.cli.subprocess.run",
        lambda *a, **k: type(
            "R", (), {"returncode": 1, "stdout": "", "stderr": "unknown command: docker compose"}
        )(),
    )
    res = runner.invoke(app, ["compose", "env-contract", "--target", "shellforgeai", "--json"])
    body = json.loads(res.stdout)
    assert body["schema_version"] == "1"
    assert body["status"] == "blocked"
    assert body["safety"]["read_only"] is True
    assert body["safety"]["docker_compose_executed"] is False
    assert body["safety"]["container_restarted"] is False
    assert body["safety"]["host_side_bypass"] is False
    assert body["safety"]["arbitrary_command_execution"] is False
    assert "docker_compose_cli_unavailable" in body["readiness"]["blockers"]


def test_env_contract_ready_fixture(monkeypatch, tmp_path) -> None:
    compose_file = tmp_path / "compose.yml"
    compose_file.write_text("services:\n  web: {}\n", encoding="utf-8")
    rows = [
        {
            "name": "sfai-pr67-compose-web",
            "compose": {
                "detected": True,
                "project": "sfai_pr67_disposable",
                "service": "web",
                "container": "sfai-pr67-compose-web",
                "working_dir": str(tmp_path),
                "config_files": [str(compose_file)],
                "labels": {
                    "shellforgeai.disposable": "true",
                    "shellforgeai.allow_restart": "true",
                },
            },
        }
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )

    def _run(*a, **k):
        cmd = a[0]
        if cmd[:3] == ["docker", "compose", "version"]:
            return type("R", (), {"returncode": 0, "stdout": "Docker Compose v2", "stderr": ""})()
        return type("R", (), {"returncode": 0, "stdout": "web\n", "stderr": ""})()

    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _run)
    res = runner.invoke(
        app,
        ["compose", "env-contract", "--target", "sfai-pr67-compose-web", "--json"],
    )
    body = json.loads(res.stdout)
    assert body["status"] == "ready"
    assert body["readiness"]["ready"] is True
    assert body["readiness"]["ready_for_optional_disposable_proof"] is True
    assert body["snapshot"]["compose_file_sha256"]


def test_env_contract_human_output(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.cli.subprocess.run",
        lambda *a, **k: type(
            "R", (), {"returncode": 1, "stdout": "", "stderr": "unknown command: docker compose"}
        )(),
    )
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload([]),
    )
    res = runner.invoke(app, ["compose", "env-contract", "--target", "missing"])
    assert "Compose execution environment contract" in res.stdout
    assert "Execution readiness:" in res.stdout
    assert "no docker compose command was executed" in res.stdout
