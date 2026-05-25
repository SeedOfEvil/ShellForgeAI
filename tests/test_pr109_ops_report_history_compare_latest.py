from __future__ import annotations

import json

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.ops_report_artifact import save_ops_report

runner = CliRunner()


def _report(name: str = "sfai-a", severity: str = "high"):
    return {
        "schema_version": "1",
        "mode": "ops_report",
        "status": "ok",
        "generated_at": "2026-05-24T22:07:46Z",
        "summary": {"containers_seen": 1, "suspects_ranked": 1, "critical": 0, "high": 1},
        "suspects": [
            {
                "name": name,
                "rank": 1,
                "severity": severity,
                "confidence": "high",
                "classes": ["crashloop"],
            }
        ],
        "remediation_lane": {"status": "warn"},
        "safe_next_commands": ["shellforgeai ops report --json"],
        "safety": {
            "read_only": True,
            "mutation_performed": False,
            "plan_created": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "cleanup_executed": False,
            "proposal_created": False,
            "mission_created": False,
            "apply_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "natural_language_execution": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
        },
    }


def _save(tmp_path, payload):
    return save_ops_report(payload, tmp_path, source_command="test")["report_id"]


def test_history_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    r = runner.invoke(app, ["ops", "report", "history", "--json"])
    assert r.exit_code == 1
    out = json.loads(r.stdout)
    assert out["status"] == "empty"


def test_history_lists_sorted_and_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    a = _save(tmp_path, _report(name="a"))
    b = _save(tmp_path, _report(name="b"))
    out = json.loads(
        runner.invoke(app, ["ops", "report", "history", "--limit", "1", "--json"]).stdout
    )
    assert out["summary"]["reports_found"] == 2
    assert len(out["reports"]) == 1
    assert out["reports"][0]["report_id"] in {a, b}


def test_history_ignores_invalid_and_human_safety(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _save(tmp_path, _report())
    bad = tmp_path / "ops_reports" / "ops_report_bad"
    bad.mkdir(parents=True)
    (bad / "manifest.json").write_text("{}", encoding="utf-8")
    human = runner.invoke(app, ["ops", "report", "history"])
    assert "Safety:" in human.stdout
    out = json.loads(runner.invoke(app, ["ops", "report", "history", "--json"]).stdout)
    assert out["summary"]["invalid_reports"] >= 1


def test_compare_latest_not_enough(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _save(tmp_path, _report())
    r = runner.invoke(app, ["ops", "report", "compare-latest", "--json"])
    assert r.exit_code == 1
    out = json.loads(r.stdout)
    assert out["status"] == "not_enough_reports"


def test_compare_latest_ok_and_flags(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _save(tmp_path, _report(name="sfai-a", severity="high"))
    _save(tmp_path, _report(name="sfai-a", severity="critical"))
    out = json.loads(
        runner.invoke(
            app,
            [
                "ops",
                "report",
                "compare-latest",
                "--json",
                "--only-changed",
                "--include-stable",
                "--top",
                "3",
            ],
        ).stdout
    )
    assert out["status"] == "ok"
    assert out["latest"] is True
    assert out["before_report_id"]
    assert out["after_report_id"]


def test_history_include_drift_json(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _save(tmp_path, _report(severity="high"))
    _save(tmp_path, _report(severity="critical"))
    out = json.loads(
        runner.invoke(app, ["ops", "report", "history", "--include-drift", "--json"]).stdout
    )
    assert out["status"] == "ok"
    assert out["latest_drift"]["status"] == "ok"


def test_history_safe_next_commands_no_forbidden(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _save(tmp_path, _report())
    out = json.loads(runner.invoke(app, ["ops", "report", "history", "--json"]).stdout)
    joined = "\n".join(out["safe_next_commands"]).lower()
    for bad in [
        "remediation execute",
        "rollback-execute",
        "cleanup execute",
        "docker restart",
        "docker compose restart",
        "--execute --confirm",
    ]:
        assert bad not in joined
