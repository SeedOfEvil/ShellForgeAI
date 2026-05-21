from __future__ import annotations

import json

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core import triage_ranking as triage_mod

runner = CliRunner()


def _battle_lab_scene() -> dict:
    return {
        "containers": [
            {
                "name": "sfai-crashloop",
                "state": "restarting",
                "exit_code": 42,
                "restart_count": 12,
                "oom_killed": False,
                "health": None,
                "log_themes": {"error_line": 4, "traceback": 1},
            },
            {
                "name": "sfai-bad-http",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "unhealthy",
                "log_themes": {"connection_refused": 5, "upstream_unreachable": 2},
            },
            {
                "name": "sfai-noisy-errors",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "log_themes": {"error_line": 8, "traceback": 1},
            },
            {
                "name": "sfai-disk-pressure",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "log_themes": {"disk_pressure": 6},
                "log_no_space_left": True,
                "disk_free_pct": 3,
            },
            {
                "name": "sfai-permission-denied",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "log_themes": {"permission_denied": 5},
            },
        ]
    }


def _invoke(monkeypatch, args: list[str]):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _battle_lab_scene())
    return runner.invoke(app, ["triage", "docker", "snapshot", *args])


def test_snapshot_human_sections(monkeypatch):
    out = _invoke(monkeypatch, [])
    body = out.stdout
    assert "Docker triage snapshot" in body
    assert "Scene:" in body
    assert "Ranked suspects:" in body
    assert "Safe next commands:" in body
    assert "Safety:" in body
    for name in [
        "sfai-crashloop",
        "sfai-bad-http",
        "sfai-disk-pressure",
        "sfai-noisy-errors",
        "sfai-permission-denied",
    ]:
        assert name in body


def test_snapshot_top_3(monkeypatch):
    out = _invoke(monkeypatch, ["--top", "3", "--json"])
    p = json.loads(out.stdout)
    assert len(p["suspects"]) == 3
    assert p["summary"]["suspects_ranked"] == 5


def test_snapshot_include_details(monkeypatch):
    out = _invoke(monkeypatch, ["--include-details", "--json"])
    p = json.loads(out.stdout)
    assert p["details"]
    assert all("evidence" in d for d in p["details"])


def test_snapshot_json_contract(monkeypatch):
    out = _invoke(monkeypatch, ["--json"])
    assert out.stdout.endswith("\n")
    assert out.stdout.count("\n") == 1
    p = json.loads(out.stdout)
    assert p["schema_version"] == "1"
    assert p["mode"] == "docker_triage_snapshot"
    assert p["generated_at"]
    assert isinstance(p["summary"], dict)
    assert isinstance(p["suspects"], list)
    assert isinstance(p["next_safe_commands"], list)
    s = p["safety"]
    assert s["read_only"] is True
    assert s["mutation_performed"] is False
    assert s["cleanup_executed"] is False
    assert s["proposal_created"] is False
    assert s["mission_created"] is False
    assert s["apply_executed"] is False
    assert s["docker_compose_executed"] is False
    assert s["container_restarted"] is False
    assert s["natural_language_execution"] is False
    assert s["shell_true"] is False


def test_snapshot_no_suspects(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: {"containers": []})
    out = runner.invoke(app, ["triage", "docker", "snapshot", "--json"])
    p = json.loads(out.stdout)
    assert p["status"] == "warn"
    assert p["suspects"] == []
    assert p["safety"]["read_only"] is True
