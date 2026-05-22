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
                "restart_count": 2,
                "exit_code": 1,
                "oom_killed": False,
                "log_themes": {"error_line": 2},
            }
        ]
    }


def _save(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _scene())
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(
        app, ["triage", "docker", "snapshot", "--save", "--include-details", "--json"]
    )
    return json.loads(out.stdout)


def test_snapshot_export_and_validate_json(monkeypatch, tmp_path: Path):
    saved = _save(monkeypatch, tmp_path)
    sid = saved["artifact"]["id"]
    out = runner.invoke(app, ["triage", "docker", "snapshot", "export", sid, "--json"])
    payload = json.loads(out.stdout)
    assert payload["status"] == "exported"
    assert payload["schema_version"] == "1"
    exp_dir = Path(payload["export"]["path"])
    assert exp_dir.parent == tmp_path / "exports"
    assert (exp_dir / "export-manifest.json").exists()

    val = runner.invoke(
        app, ["triage", "docker", "snapshot", "export-validate", str(exp_dir), "--json"]
    )
    vp = json.loads(val.stdout)
    assert vp["status"] == "ok"
    assert vp["checks"]["checksums"] is True
    assert val.exit_code == 0
    assert val.stdout.strip().startswith("{")
    assert val.stdout.strip().endswith("}")


def test_snapshot_export_path_safety(monkeypatch, tmp_path: Path):
    saved = _save(monkeypatch, tmp_path)
    sid = saved["artifact"]["id"]
    out = runner.invoke(
        app,
        ["triage", "docker", "snapshot", "export", sid, "--output", "/tmp/escape", "--json"],
    )
    p = json.loads(out.stdout)
    assert out.exit_code != 0
    assert p["status"] in {"failed", "error", "not_found"}
    assert out.stdout.strip().startswith("{")
    assert out.stdout.strip().endswith("}")

    out2 = runner.invoke(
        app,
        ["triage", "docker", "snapshot", "export", sid, "--output", "../escape", "--json"],
    )
    p2 = json.loads(out2.stdout)
    assert out2.exit_code != 0
    assert p2["status"] in {"failed", "error", "not_found"}


def test_snapshot_export_missing_snapshot_json_exit_nonzero(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["triage", "docker", "snapshot", "export", "missing", "--json"])
    payload = json.loads(out.stdout)
    assert out.exit_code != 0
    assert payload["status"] == "not_found"


def test_snapshot_export_validate_malformed(monkeypatch, tmp_path: Path):
    saved = _save(monkeypatch, tmp_path)
    sid = saved["artifact"]["id"]
    out = runner.invoke(app, ["triage", "docker", "snapshot", "export", sid, "--json"])
    exp = Path(json.loads(out.stdout)["export"]["path"])
    (exp / "triage-snapshot.json").write_text("{", encoding="utf-8")
    bad = runner.invoke(
        app, ["triage", "docker", "snapshot", "export-validate", str(exp), "--json"]
    )
    assert bad.exit_code != 0
    assert json.loads(bad.stdout)["status"] == "error"


def test_snapshot_export_validate_missing_json_exit_nonzero(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(
        app,
        ["triage", "docker", "snapshot", "export-validate", str(tmp_path / "missing"), "--json"],
    )
    payload = json.loads(out.stdout)
    assert out.exit_code != 0
    assert payload["status"] == "not_found"


def test_snapshot_export_validate_checksum_mismatch_json_exit_nonzero(monkeypatch, tmp_path: Path):
    saved = _save(monkeypatch, tmp_path)
    sid = saved["artifact"]["id"]
    out = runner.invoke(app, ["triage", "docker", "snapshot", "export", sid, "--json"])
    exp = Path(json.loads(out.stdout)["export"]["path"])
    (exp / "triage-snapshot.md").write_text("tampered\n", encoding="utf-8")
    bad = runner.invoke(
        app, ["triage", "docker", "snapshot", "export-validate", str(exp), "--json"]
    )
    payload = json.loads(bad.stdout)
    assert bad.exit_code != 0
    assert payload["status"] == "failed"
