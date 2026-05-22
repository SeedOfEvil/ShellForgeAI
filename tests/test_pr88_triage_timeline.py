from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _write_snapshot(root: Path, sid: str, suspects: list[dict]) -> Path:
    art = root / "artifacts" / sid
    art.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "1",
        "mode": "docker_triage_snapshot",
        "read_only": True,
        "summary": {"containers_seen": 8, "suspects_ranked": len(suspects)},
        "safety": {"read_only": True, "mutation_performed": False},
        "suspects": suspects,
    }
    (art / "triage-snapshot.json").write_text(json.dumps(payload), encoding="utf-8")
    (art / "triage-snapshot.md").write_text("ok\n", encoding="utf-8")
    (art / "manifest.json").write_text(json.dumps({"checksums": {}}), encoding="utf-8")
    return art


def _sus(name: str, rank: int, severity: str, confidence: str = "medium") -> dict:
    return {
        "name": name,
        "rank": rank,
        "severity": severity,
        "confidence": confidence,
        "classes": [severity],
        "why": ["e1"],
    }


def test_timeline_detects_trends(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _write_snapshot(
        tmp_path,
        "triage_snapshot_20260521_000001_a",
        [
            _sus("sfai-crashloop", 4, "high"),
            _sus("sfai-disk-pressure", 1, "critical"),
            _sus("sfai-noisy-errors", 2, "high"),
        ],
    )
    _write_snapshot(
        tmp_path,
        "triage_snapshot_20260521_000002_b",
        [
            _sus("sfai-crashloop", 2, "high"),
            _sus("sfai-disk-pressure", 2, "high"),
            _sus("sfai-noisy-errors", 2, "high"),
            _sus("sfai-bad-http", 3, "high"),
        ],
    )
    _write_snapshot(
        tmp_path,
        "triage_snapshot_20260521_000003_c",
        [
            _sus("sfai-crashloop", 1, "critical"),
            _sus("sfai-disk-pressure", 4, "medium"),
            _sus("sfai-noisy-errors", 2, "high"),
            _sus("sfai-new", 5, "medium"),
        ],
    )
    out = runner.invoke(app, ["triage", "docker", "timeline", "--json"])
    p = json.loads(out.stdout)
    assert out.exit_code == 0
    assert p["mode"] == "docker_triage_timeline"
    assert p["schema_version"] == "1"
    assert p["window"]["snapshots_analyzed"] == 3
    assert any(x["name"] == "sfai-crashloop" for x in p["escalating"])
    assert any(x["name"] == "sfai-disk-pressure" for x in p["recovering"])
    assert "sfai-bad-http" in p["resolved_suspects"]
    assert "sfai-new" in p["new_suspects"]
    assert "sfai-disk-pressure" not in p["resolved_suspects"]
    assert p["safety"]["read_only"] is True
    assert p["safety"]["mutation_performed"] is False


def test_timeline_window_top_and_filters(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    for i in range(6):
        _write_snapshot(
            tmp_path,
            f"triage_snapshot_20260521_00000{i}_x",
            [
                _sus("sfai-crashloop", max(1, 5 - i), "high" if i < 5 else "critical"),
                _sus("sfai-noisy-errors", 3, "high"),
            ],
        )
    h = runner.invoke(
        app, ["triage", "docker", "timeline", "--window", "5", "--top", "1", "--only-regressions"]
    )
    assert h.exit_code == 0
    assert "Stable:" not in h.stdout
    out = runner.invoke(
        app,
        [
            "triage",
            "docker",
            "timeline",
            "--window",
            "5",
            "--top",
            "1",
            "--include-stable",
            "--json",
        ],
    )
    p = json.loads(out.stdout)
    assert p["window"]["snapshots_analyzed"] == 5


def test_timeline_insufficient_and_invalid(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _write_snapshot(tmp_path, "triage_snapshot_20260521_000001_a", [_sus("one", 1, "high")])
    out = runner.invoke(app, ["triage", "docker", "timeline", "--json"])
    assert out.exit_code != 0
    p = json.loads(out.stdout)
    assert p["status"] == "warn"
    bad = tmp_path / "artifacts" / "triage_snapshot_20260521_000002_b"
    bad.mkdir(parents=True)
    (bad / "triage-snapshot.json").write_text("{bad", encoding="utf-8")
    (bad / "triage-snapshot.md").write_text("ok", encoding="utf-8")
    out2 = runner.invoke(app, ["triage", "docker", "timeline", "--json"])
    p2 = json.loads(out2.stdout)
    assert any("skipped invalid snapshot" in w for w in p2["warnings"])
