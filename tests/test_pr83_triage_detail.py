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
    return runner.invoke(app, ["triage", "docker", "detail", *args])


def test_detail_by_name_each_core_suspect(monkeypatch):
    for name in [
        "sfai-crashloop",
        "sfai-bad-http",
        "sfai-disk-pressure",
        "sfai-noisy-errors",
        "sfai-permission-denied",
    ]:
        out = _invoke(monkeypatch, [name, "--json"])
        assert out.exit_code == 0
        p = json.loads(out.stdout)
        assert p["status"] == "ok"
        assert p["suspect"]["name"] == name


def test_detail_by_rank(monkeypatch):
    out1 = _invoke(monkeypatch, ["--rank", "1", "--json"])
    p1 = json.loads(out1.stdout)
    assert p1["suspect"]["name"] == "sfai-crashloop"

    expected_rank3 = triage_mod.rank_scene(_battle_lab_scene())["suspects"][2]["name"]
    out3 = _invoke(monkeypatch, ["--rank", "3", "--json"])
    p3 = json.loads(out3.stdout)
    assert p3["suspect"]["name"] == expected_rank3


def test_detail_not_found(monkeypatch):
    out = _invoke(monkeypatch, ["missing-suspect", "--json"])
    assert out.exit_code == 0
    p = json.loads(out.stdout)
    assert p["status"] == "not_found"
    assert p["available_suspects"]


def test_detail_invalid_rank(monkeypatch):
    out = _invoke(monkeypatch, ["--rank", "99", "--json"])
    assert out.exit_code == 1
    p = json.loads(out.stdout)
    assert p["status"] == "error"


def test_detail_human_sections(monkeypatch):
    out = _invoke(monkeypatch, ["sfai-disk-pressure"])
    body = out.stdout
    assert "Docker triage detail:" in body
    assert "Rank:" in body
    assert "Why ranked here:" in body
    assert "Evidence:" in body
    assert "Safe next commands:" in body
    assert "Safety:" in body


def test_detail_json_contract(monkeypatch):
    out = _invoke(monkeypatch, ["sfai-bad-http", "--json"])
    assert out.stdout.endswith("\n")
    assert out.stdout.count("\n") == 1
    p = json.loads(out.stdout)
    assert p["schema_version"] == "1"
    assert p["mode"] == "docker_triage_detail"
    assert p["suspect"]["severity"]
    assert p["suspect"]["confidence"]
    assert isinstance(p["suspect"]["evidence"], list) and p["suspect"]["evidence"]
    assert isinstance(p["suspect"]["why"], list) and p["suspect"]["why"]
    for cmd in p["suspect"]["safe_next_commands"]:
        low = cmd.lower()
        assert low.startswith("shellforgeai triage ") or low.startswith("shellforgeai remediation ")
        assert "restart" not in low
        assert "apply" not in low
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
