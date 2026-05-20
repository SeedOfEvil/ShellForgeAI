"""PR81 — Read-only Docker triage ranking tests.

Drives the scoring engine from synthetic battle-lab fixtures (no live Docker,
no daemon, no subprocess). Verifies scoring, ranking, JSON shape, human
output, and the safety invariants required by the PR81 brief.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core import triage_ranking as triage_mod
from shellforgeai.core.triage_ranking import (
    MODE,
    SCHEMA_VERSION,
    rank_scene,
)

runner = CliRunner()


# --- fixture: noisy battle-lab scene ---------------------------------------


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
                "log_themes": {
                    "connection_refused": 5,
                    "upstream_unreachable": 2,
                },
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
                "log_themes": {"read_only_fs": 2},
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
            {
                "name": "sfai-high-cpu",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "cpu_percent": 92.0,
                "log_themes": {},
            },
            {
                "name": "sfai-quiet",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "log_themes": {},
            },
        ]
    }


def _by_name(suspects: list) -> dict:
    return {s["name"]: s for s in suspects}


# --- scoring / ranking ----------------------------------------------------


def test_crashloop_ranks_critical_or_high():
    payload = rank_scene(_battle_lab_scene())
    s = _by_name(payload["suspects"])
    assert "sfai-crashloop" in s
    assert s["sfai-crashloop"]["severity"] in {"critical", "high"}


def test_crashloop_ranks_above_noisy_and_high_cpu():
    payload = rank_scene(_battle_lab_scene())
    suspects = payload["suspects"]
    names = [x["name"] for x in suspects]
    assert "sfai-crashloop" in names
    # Crashloop must outrank noisy-errors and must not be tied with watch cases.
    crashloop_rank = names.index("sfai-crashloop")
    assert "sfai-noisy-errors" in names
    assert crashloop_rank < names.index("sfai-noisy-errors")
    # High-CPU healthy should be in watch list, not in suspects.
    assert "sfai-high-cpu" not in names


def test_bad_http_suspect_present():
    payload = rank_scene(_battle_lab_scene())
    s = _by_name(payload["suspects"])
    assert "sfai-bad-http" in s
    assert "bad_http" in s["sfai-bad-http"]["classes"]


def test_noisy_errors_suspect_present():
    payload = rank_scene(_battle_lab_scene())
    s = _by_name(payload["suspects"])
    assert "sfai-noisy-errors" in s
    assert "noisy_errors" in s["sfai-noisy-errors"]["classes"]


def test_disk_pressure_suspect_present():
    payload = rank_scene(_battle_lab_scene())
    s = _by_name(payload["suspects"])
    assert "sfai-disk-pressure" in s
    assert "disk_pressure" in s["sfai-disk-pressure"]["classes"]


def test_permission_denied_suspect_present():
    payload = rank_scene(_battle_lab_scene())
    s = _by_name(payload["suspects"])
    assert "sfai-permission-denied" in s
    assert "permission_denied" in s["sfai-permission-denied"]["classes"]


def test_high_cpu_healthy_is_watch_only():
    payload = rank_scene(_battle_lab_scene())
    watch_names = {w["name"] for w in payload["watch"]}
    assert "sfai-high-cpu" in watch_names
    # And severity is watch, never critical.
    w = next(w for w in payload["watch"] if w["name"] == "sfai-high-cpu")
    assert w["severity"] == "watch"


def test_multiple_active_scenarios_listed():
    payload = rank_scene(_battle_lab_scene())
    names = {s["name"] for s in payload["suspects"]}
    expected = {
        "sfai-crashloop",
        "sfai-bad-http",
        "sfai-noisy-errors",
        "sfai-disk-pressure",
        "sfai-permission-denied",
    }
    assert expected.issubset(names)


def test_every_suspect_has_evidence_why_and_safe_next():
    payload = rank_scene(_battle_lab_scene())
    for s in payload["suspects"]:
        assert s.get("evidence"), s
        assert s.get("why"), s
        assert s.get("safe_next_commands"), s


def test_safe_next_commands_are_read_only():
    payload = rank_scene(_battle_lab_scene())
    for s in payload["suspects"]:
        for cmd in s["safe_next_commands"]:
            lowered = cmd.lower()
            # Read-only verbs only.
            assert lowered.startswith("shellforgeai diagnose ") or lowered.startswith(
                "shellforgeai ask "
            ), cmd
            for forbidden in (
                "restart",
                "stop ",
                " rm ",
                "remove",
                "prune",
                "apply",
                "mission ",
                "cleanup execute",
                "compose up",
                "compose down",
                "compose restart",
            ):
                assert forbidden not in lowered, cmd
    for cmd in payload["next_safe_commands"]:
        lowered = cmd.lower()
        for forbidden in (
            "restart",
            "prune",
            "apply",
            " rm ",
            "compose up",
            "compose down",
        ):
            assert forbidden not in lowered, cmd


# --- JSON output contract --------------------------------------------------


def _invoke_json(monkeypatch, scene):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: scene)
    out = runner.invoke(app, ["triage", "docker", "--json"])
    assert out.exit_code == 0, out.stdout
    return out


def test_triage_json_strict_parseable(monkeypatch):
    out = _invoke_json(monkeypatch, _battle_lab_scene())
    # No text before/after JSON.
    body = out.stdout.strip()
    payload = json.loads(body)
    assert isinstance(payload, dict)
    # Ensure single-line / parseable: stdout should be the JSON only (plus
    # optional trailing newline from typer.echo).
    assert out.stdout.endswith("\n")
    assert out.stdout.count("\n") == 1


def test_triage_json_schema_version_and_mode(monkeypatch):
    out = _invoke_json(monkeypatch, _battle_lab_scene())
    p = json.loads(out.stdout)
    assert p["schema_version"] == SCHEMA_VERSION
    assert p["mode"] == MODE


def test_triage_json_includes_suspects_and_summary(monkeypatch):
    out = _invoke_json(monkeypatch, _battle_lab_scene())
    p = json.loads(out.stdout)
    assert isinstance(p["suspects"], list) and p["suspects"]
    assert isinstance(p["summary"], dict)
    for key in ("containers_seen", "suspects_ranked", "critical", "high", "medium", "watch"):
        assert key in p["summary"]


def test_triage_json_safety_flags(monkeypatch):
    out = _invoke_json(monkeypatch, _battle_lab_scene())
    p = json.loads(out.stdout)
    safety = p["safety"]
    assert safety["read_only"] is True
    for k in (
        "mutation_performed",
        "cleanup_executed",
        "proposal_created",
        "mission_created",
        "apply_executed",
        "docker_compose_executed",
        "container_restarted",
        "natural_language_execution",
        "shell_true",
    ):
        assert safety[k] is False, k
    assert p["read_only"] is True
    assert p["mutation_performed"] is False


def test_triage_json_required_keys(monkeypatch):
    out = _invoke_json(monkeypatch, _battle_lab_scene())
    p = json.loads(out.stdout)
    for k in (
        "schema_version",
        "mode",
        "summary",
        "suspects",
        "safety",
        "warnings",
        "next_safe_commands",
    ):
        assert k in p


def test_triage_json_empty_scene_is_warn(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: {"containers": []})
    out = runner.invoke(app, ["triage", "docker", "--json"])
    assert out.exit_code == 0
    p = json.loads(out.stdout)
    assert p["status"] == "warn"
    assert p["suspects"] == []
    assert p["safety"]["read_only"] is True


# --- human output contract -------------------------------------------------


def test_human_ranks_suspects(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _battle_lab_scene())
    out = runner.invoke(app, ["triage", "docker"])
    assert out.exit_code == 0, out.stdout
    text = out.stdout
    assert "Docker triage suspects" in text
    assert "sfai-crashloop" in text
    # Severity / confidence / why / safe next must be rendered.
    assert "Severity:" in text
    assert "Confidence:" in text
    assert "Why ranked here:" in text
    assert "Safe next command:" in text


def test_human_includes_safety_statement(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _battle_lab_scene())
    out = runner.invoke(app, ["triage", "docker"])
    assert "read_only: true" in out.stdout
    assert "mutation_performed: false" in out.stdout
    assert "no restart/stop/delete/prune was executed" in out.stdout


def test_human_includes_next_safe_steps(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _battle_lab_scene())
    out = runner.invoke(app, ["triage", "docker"])
    assert "Next safe steps:" in out.stdout


def test_human_includes_watch_line(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _battle_lab_scene())
    out = runner.invoke(app, ["triage", "docker"])
    assert "Watch:" in out.stdout
    assert "sfai-high-cpu" in out.stdout


# --- safety regression -----------------------------------------------------


def _module_text() -> str:
    return Path(inspect.getfile(triage_mod)).read_text(encoding="utf-8")


def test_no_shell_true_in_triage_module():
    text = _module_text()
    assert "shell=True" not in text


def test_triage_does_not_import_mutation_helpers():
    text = _module_text()
    forbidden = [
        "from shellforgeai.core.apply_bundle",
        "from shellforgeai.core.mission",
        "from shellforgeai.core.actions",
        "subprocess.run",
        "subprocess.Popen",
        "os.system",
    ]
    for f in forbidden:
        assert f not in text, f


def test_triage_does_not_call_mutation_methods(monkeypatch):
    # Stand up a real run, ensure no plan/proposal/mission/apply files written.
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _battle_lab_scene())
    out = runner.invoke(app, ["triage", "docker", "--json"])
    assert out.exit_code == 0
    p = json.loads(out.stdout)
    assert p["safety"]["proposal_created"] is False
    assert p["safety"]["mission_created"] is False
    assert p["safety"]["apply_executed"] is False
    assert p["safety"]["cleanup_executed"] is False
    assert p["safety"]["docker_compose_executed"] is False
    assert p["safety"]["container_restarted"] is False
