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


def _make_proposal(monkeypatch, tmp_path: Path, approved: bool = True) -> str:
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
    create = runner.invoke(app, ["compose", "propose-restart", "shellforgeai", "--json"])
    pid = json.loads(create.stdout)["proposal"]["id"]
    if approved:
        runner.invoke(app, ["approvals", "approve", pid, "--reason", "ok"])
    return pid


def test_compose_mission_execute_requires_confirm(monkeypatch, tmp_path: Path) -> None:
    _runtime_env(monkeypatch, tmp_path)
    pid = _make_proposal(monkeypatch, tmp_path)
    prep = runner.invoke(app, ["mission", "compose-restart", "prepare", pid])
    mid = [
        ln.split(":", 1)[1].strip()
        for ln in prep.stdout.splitlines()
        if ln.strip().startswith("- mission:")
    ][0]
    r = runner.invoke(app, ["mission", "compose-restart", "execute", mid, "--execute"])
    assert r.exit_code == 1
    assert "requires --execute --confirm" in r.stdout


def test_compose_mission_execute_runs_expected_argv(monkeypatch, tmp_path: Path) -> None:
    _runtime_env(monkeypatch, tmp_path)
    pid = _make_proposal(monkeypatch, tmp_path)
    prep = runner.invoke(app, ["mission", "compose-restart", "prepare", pid])
    mid = [
        ln.split(":", 1)[1].strip()
        for ln in prep.stdout.splitlines()
        if ln.strip().startswith("- mission:")
    ][0]
    seen = {}

    class P:
        returncode = 0
        stdout = ""
        stderr = ""

    def _run(cmd, capture_output, text, check):
        seen["cmd"] = cmd
        seen["check"] = check
        return P()

    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _run)
    r = runner.invoke(
        app, ["mission", "compose-restart", "execute", mid, "--execute", "--confirm", "--json"]
    )
    assert r.exit_code == 0
    body = json.loads(r.stdout)
    assert body["execution"]["executed"] is True
    assert seen["cmd"] == [
        "docker",
        "compose",
        "-f",
        "/w/c.yml",
        "--project-directory",
        "/w",
        "restart",
        "s",
    ]
    assert seen["check"] is False
