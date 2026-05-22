from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _write_snapshot(
    root: Path, sid: str, suspects: list[dict], summary: dict | None = None
) -> Path:
    art = root / "artifacts" / sid
    art.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "1",
        "mode": "docker_triage_snapshot",
        "read_only": True,
        "summary": summary or {"containers_seen": 5, "suspects_ranked": len(suspects)},
        "safety": {"read_only": True, "mutation_performed": False},
        "suspects": suspects,
    }
    (art / "triage-snapshot.json").write_text(json.dumps(payload), encoding="utf-8")
    (art / "triage-snapshot.md").write_text("ok\n", encoding="utf-8")
    (art / "manifest.json").write_text(json.dumps({"checksums": {}}), encoding="utf-8")
    return art


def _sus(name: str, rank: int, severity: str, confidence: str, classes: list[str]) -> dict:
    return {
        "name": name,
        "rank": rank,
        "severity": severity,
        "confidence": confidence,
        "classes": classes,
    }


def test_compare_identical_stable(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    suspects = [_sus("sfai-noisy-errors", 1, "medium", "medium", ["noisy_errors"])]
    _write_snapshot(tmp_path, "a", suspects)
    _write_snapshot(tmp_path, "b", suspects)
    out = runner.invoke(
        app, ["triage", "docker", "snapshot", "compare", "a", "b", "--include-stable", "--json"]
    )
    p = json.loads(out.stdout)
    assert out.exit_code == 0
    assert p["status"] == "ok"
    assert len(p["stable"]) == 1
    assert p["read_only"] is True and p["mutation_performed"] is False


def test_compare_drift_and_filters(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _write_snapshot(
        tmp_path,
        "a",
        [
            _sus("sfai-crashloop", 3, "high", "medium", ["restart_storm"]),
            _sus("sfai-bad-http", 1, "high", "high", ["http_failures"]),
            _sus("sfai-noisy-errors", 2, "medium", "medium", ["noisy_errors"]),
        ],
    )
    _write_snapshot(
        tmp_path,
        "b",
        [
            _sus("sfai-crashloop", 1, "critical", "high", ["restart_storm"]),
            _sus("sfai-noisy-errors", 2, "medium", "medium", ["noisy_errors"]),
            _sus("sfai-permission-denied", 3, "high", "medium", ["permission_denied"]),
        ],
    )
    out = runner.invoke(
        app,
        [
            "triage",
            "docker",
            "snapshot",
            "compare",
            "a",
            "b",
            "--top",
            "1",
            "--only-changed",
            "--json",
        ],
    )
    p = json.loads(out.stdout)
    assert out.exit_code == 0
    assert p["summary"]["new"] == 1
    assert p["summary"]["recovered"] == 1
    assert len(p["regressions"]) == 1
    assert p["regressions"][0]["name"] == "sfai-crashloop"
    assert p["stable"] == []


def test_compare_export_success_and_refusals(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    a = _write_snapshot(
        tmp_path, "a", [_sus("sfai-disk-pressure", 1, "high", "high", ["disk_pressure"])]
    )
    b = _write_snapshot(
        tmp_path, "b", [_sus("sfai-disk-pressure", 1, "medium", "medium", ["disk_pressure"])]
    )
    ea = tmp_path / "exports" / "ea"
    eb = tmp_path / "exports" / "eb"
    ea.mkdir(parents=True)
    eb.mkdir(parents=True)
    for src, dst in [(a, ea), (b, eb)]:
        for name in ["triage-snapshot.json", "triage-snapshot.md", "manifest.json"]:
            (dst / name).write_bytes((src / name).read_bytes())
        checks = {
            name: __import__("hashlib").sha256((dst / name).read_bytes()).hexdigest()
            for name in ["triage-snapshot.json", "triage-snapshot.md", "manifest.json"]
        }
        (dst / "export-manifest.json").write_text(
            json.dumps(
                {
                    "mode": "docker_triage_snapshot_export",
                    "checksums": checks,
                    "safety": {"read_only": True, "mutation_performed": False},
                }
            ),
            encoding="utf-8",
        )
    ok = runner.invoke(
        app, ["triage", "docker", "snapshot", "compare-export", str(ea), str(eb), "--json"]
    )
    assert ok.exit_code == 0
    assert json.loads(ok.stdout)["status"] == "ok"
    (eb / "triage-snapshot.md").write_text("tamper\n", encoding="utf-8")
    bad = runner.invoke(
        app, ["triage", "docker", "snapshot", "compare-export", str(ea), str(eb), "--json"]
    )
    assert bad.exit_code != 0
    assert json.loads(bad.stdout)["status"] == "error"
