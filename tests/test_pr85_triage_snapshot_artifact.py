from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core import triage_ranking as triage_mod

runner = CliRunner()


def _scene() -> dict:
    return {
        "containers": [
            {
                "name": "a",
                "state": "restarting",
                "restart_count": 5,
                "exit_code": 1,
                "oom_killed": False,
                "log_themes": {"error_line": 3},
            },
            {
                "name": "b",
                "state": "running",
                "restart_count": 0,
                "exit_code": 0,
                "oom_killed": False,
                "log_themes": {"connection_refused": 3},
            },
            {
                "name": "c",
                "state": "running",
                "restart_count": 0,
                "exit_code": 0,
                "oom_killed": False,
                "log_themes": {"disk_pressure": 4},
            },
        ]
    }


def _invoke(monkeypatch, tmp_path: Path, args: list[str]):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _scene())
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    return runner.invoke(app, ["triage", "docker", "snapshot", *args])


def test_snapshot_save_writes_artifact(monkeypatch, tmp_path: Path):
    out = _invoke(monkeypatch, tmp_path, ["--save", "--json"])
    p = json.loads(out.stdout)
    art = Path(p["artifact"]["path"])
    assert art.parent == tmp_path / "artifacts"
    assert (art / "triage-snapshot.json").exists()
    assert (art / "triage-snapshot.md").exists()
    assert p["snapshot"]["mode"] == "docker_triage_snapshot"
    assert "shellforgeai triage docker snapshot validate" in "\n".join(p["next_safe_commands"])


def test_snapshot_save_include_details(monkeypatch, tmp_path: Path):
    out = _invoke(monkeypatch, tmp_path, ["--save", "--include-details", "--json"])
    p = json.loads(out.stdout)
    art = Path(p["artifact"]["path"])
    assert (art / "triage-details.json").exists()


def test_snapshot_validate_ok_id_and_path(monkeypatch, tmp_path: Path):
    save = _invoke(monkeypatch, tmp_path, ["--save", "--json"])
    sp = json.loads(save.stdout)
    sid = sp["artifact"]["id"]
    out_id = runner.invoke(app, ["triage", "docker", "snapshot", "validate", sid, "--json"])
    assert json.loads(out_id.stdout)["status"] == "ok"
    out_path = runner.invoke(
        app, ["triage", "docker", "snapshot", "validate", sp["artifact"]["path"], "--json"]
    )
    assert json.loads(out_path.stdout)["status"] == "ok"


def test_snapshot_validate_not_found_and_malformed(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    nf = runner.invoke(app, ["triage", "docker", "snapshot", "validate", "missing", "--json"])
    assert json.loads(nf.stdout)["status"] == "not_found"
    d = tmp_path / "artifacts" / "bad"
    d.mkdir(parents=True)
    (d / "triage-snapshot.json").write_text("{", encoding="utf-8")
    (d / "triage-snapshot.md").write_text("x", encoding="utf-8")
    bad = runner.invoke(app, ["triage", "docker", "snapshot", "validate", "bad", "--json"])
    assert json.loads(bad.stdout)["status"] == "error"
