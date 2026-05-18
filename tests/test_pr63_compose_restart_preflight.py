from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _runtime_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path / "data"))


def _containers_payload(rows):
    class _Res:
        ok = True
        stdout = json.dumps({"containers": rows})

    return _Res()


def _setup_mission(monkeypatch, tmp_path: Path) -> str:
    rows = [
        {
            "name": "shellforgeai",
            "compose": {
                "detected": True,
                "project": "p",
                "service": "s",
                "working_dir": "/w",
                "config_files": ["/w/c.yml"],
                "labels": {"shellforgeai.disposable": "true"},
            },
        }
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    pid = json.loads(
        runner.invoke(app, ["compose", "propose-restart", "shellforgeai", "--json"]).stdout
    )["proposal"]["id"]
    runner.invoke(app, ["approvals", "approve", pid, "--reason", "ok"])
    (tmp_path / "data" / "rollback_previews" / pid).mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "rollback_previews" / pid / "rollback-preview.json").write_text(
        json.dumps(
            {
                "rollback_status": "preview_only",
                "safety": {"rollback_execution_allowed": False},
                "schema_version": "1",
            }
        )
    )
    prep = runner.invoke(app, ["mission", "compose-restart", "prepare", pid])
    return [
        ln.split(":", 1)[1].strip()
        for ln in prep.stdout.splitlines()
        if ln.strip().startswith("- mission:")
    ][0]


def test_preflight_unknown_shorthand_blocks_execute(monkeypatch, tmp_path: Path) -> None:
    _runtime_env(monkeypatch, tmp_path)
    mid = _setup_mission(monkeypatch, tmp_path)

    class P:
        def __init__(self, rc, out="", err=""):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    calls = []

    def _run(cmd, capture_output, text, check):
        calls.append(cmd)
        if cmd[:3] == ["docker", "compose", "version"]:
            return P(0, "Docker Compose version v2.0.0")
        return P(125, "", "unknown shorthand flag: 'f' in -f")

    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _run)
    r = runner.invoke(
        app, ["mission", "compose-restart", "execute", mid, "--execute", "--confirm", "--json"]
    )
    assert r.exit_code == 1
    body = json.loads(r.stdout)
    assert body["safety"]["docker_compose_executed"] is False
    assert body["safety"]["container_restarted"] is False
    assert body["gates"]["docker_compose_supports_required_invocation"] is False
    assert calls[-1][-2:] != ["restart", "s"]


def test_preflight_file_not_found_blocks_status(monkeypatch, tmp_path: Path) -> None:
    _runtime_env(monkeypatch, tmp_path)
    mid = _setup_mission(monkeypatch, tmp_path)

    def _run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _run)
    r = runner.invoke(app, ["mission", "compose-restart", "status", mid, "--json"])
    assert r.exit_code == 0
    body = json.loads(r.stdout)
    assert body["mission"]["status"] == "blocked"
    assert body["gates"]["docker_compose_available"] is False


def test_preflight_ok_allows_execute(monkeypatch, tmp_path: Path) -> None:
    _runtime_env(monkeypatch, tmp_path)
    mid = _setup_mission(monkeypatch, tmp_path)

    class P:
        def __init__(self, rc, out="", err=""):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    seen = []

    def _run(cmd, capture_output, text, check):
        seen.append((cmd, check))
        if cmd[:3] == ["docker", "compose", "version"]:
            return P(0, "Docker Compose version v2.0.0")
        if cmd[-2:] == ["config", "--services"]:
            return P(0, "s")
        return P(0, "")

    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _run)
    r = runner.invoke(
        app, ["mission", "compose-restart", "execute", mid, "--execute", "--confirm", "--json"]
    )
    assert r.exit_code == 0
    body = json.loads(r.stdout)
    assert body["execution"]["executed"] is True
    assert body["safety"]["docker_compose_executed"] is True
    assert any(cmd[-2:] == ["restart", "s"] for cmd, _ in seen)
    assert all(chk is False for _, chk in seen)
