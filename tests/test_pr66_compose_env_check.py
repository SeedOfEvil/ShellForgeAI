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


def test_compose_env_check_no_target(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.cli.subprocess.run",
        lambda *a, **k: type(
            "R", (), {"returncode": 1, "stdout": "", "stderr": "unknown command: docker compose"}
        )(),
    )
    res = runner.invoke(app, ["compose", "env-check"])
    assert "Compose execution environment check" in res.stdout
    assert "none selected" in res.stdout
    assert "read-only preflight checks" in res.stdout


def test_compose_env_check_target_json_blockers(monkeypatch) -> None:
    rows = [
        {
            "name": "shellforgeai",
            "compose": {
                "detected": True,
                "project": "shellforgeai",
                "service": "shellforgeai",
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
    res = runner.invoke(app, ["compose", "env-check", "--target", "shellforgeai", "--json"])
    body = json.loads(res.stdout)
    assert body["schema_version"] == "1"
    assert body["safety"]["read_only"] is True
    assert body["safety"]["docker_compose_executed"] is False
    assert "docker_compose_cli_unavailable" in body["readiness"]["blockers"]
    assert "compose_file_snapshot_unavailable" in body["readiness"]["blockers"]
    assert "target_not_allowlisted" in body["readiness"]["blockers"]


def test_compose_env_check_ambiguous(monkeypatch) -> None:
    rows = [
        {"name": "c1", "compose": {"detected": True, "project": "p1", "service": "shellforgeai"}},
        {"name": "c2", "compose": {"detected": True, "project": "p2", "service": "shellforgeai"}},
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr(
        "shellforgeai.cli.subprocess.run",
        lambda *a, **k: type(
            "R", (), {"returncode": 0, "stdout": "Docker Compose v2", "stderr": ""}
        )(),
    )
    res = runner.invoke(app, ["compose", "env-check", "--target", "shellforgeai", "--json"])
    body = json.loads(res.stdout)
    assert body["status"] == "ambiguous"
    assert isinstance(body["candidates"], list)


def test_env_check_normalizes_detected_config_files_shape(monkeypatch) -> None:
    rows = [
        {
            "name": "shellforgeai",
            "compose": {
                "detected": True,
                "project": "shellforgeai",
                "service": "shellforgeai",
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
            "R", (), {"returncode": 0, "stdout": "Docker Compose v2", "stderr": ""}
        )(),
    )
    res = runner.invoke(app, ["compose", "env-check", "--target", "shellforgeai", "--json"])
    body = json.loads(res.stdout)
    assert body["target"]["compose_managed"] is True
    assert body["target"]["project"] == "shellforgeai"
    assert body["target"]["service"] == "shellforgeai"
    assert body["target"]["compose_file"] == "/srv/compose/shellforgeai/compose.yml"
    assert body["target"]["config_files"] == ["/srv/compose/shellforgeai/compose.yml"]
    assert "target_not_compose_managed" not in body["readiness"]["blockers"]


def test_env_check_normalizes_compose_file_to_config_files(monkeypatch, tmp_path) -> None:
    compose_file = tmp_path / "compose.yml"
    compose_file.write_text("services: {}\n", encoding="utf-8")
    rows = [
        {
            "name": "shellforgeai",
            "compose": {
                "detected": True,
                "project": "shellforgeai",
                "service": "shellforgeai",
                "working_dir": str(tmp_path),
                "config_files": [str(compose_file)],
                "labels": {"shellforgeai.disposable": "true"},
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
            "R", (), {"returncode": 0, "stdout": "Docker Compose v2", "stderr": ""}
        )(),
    )
    res = runner.invoke(app, ["compose", "env-check", "--target", "shellforgeai", "--json"])
    body = json.loads(res.stdout)
    assert body["target"]["compose_managed"] is True
    assert body["target"]["compose_file"] == str(compose_file)
    assert body["target"]["config_files"] == [str(compose_file)]


def test_env_check_unreadable_known_compose_file_not_target_not_compose(monkeypatch) -> None:
    rows = [
        {
            "name": "shellforgeai",
            "compose": {
                "detected": True,
                "project": "shellforgeai",
                "service": "shellforgeai",
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
    res = runner.invoke(app, ["compose", "env-check", "--target", "shellforgeai", "--json"])
    body = json.loads(res.stdout)
    assert body["target"]["compose_managed"] is True
    assert body["target"]["compose_file"] == "/srv/compose/shellforgeai/compose.yml"
    assert "compose_file_snapshot_unavailable" in body["readiness"]["blockers"]
    assert "target_not_compose_managed" not in body["readiness"]["blockers"]


def test_env_check_human_detected_target_shows_compose_managed(monkeypatch) -> None:
    rows = [
        {
            "name": "shellforgeai",
            "compose": {
                "detected": True,
                "project": "shellforgeai",
                "service": "shellforgeai",
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
    res = runner.invoke(app, ["compose", "env-check", "--target", "shellforgeai"])
    assert "- compose-managed: true" in res.stdout
    assert "- compose_file: /srv/compose/shellforgeai/compose.yml" in res.stdout
    assert "docker compose cli/plugin: unavailable" in res.stdout
