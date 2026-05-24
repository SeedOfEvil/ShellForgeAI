from __future__ import annotations

import json

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.ops_report_artifact import save_ops_report

runner = CliRunner()


def _report(
    *,
    severity: str = "high",
    rank: int = 1,
    confidence: str = "high",
    classes=None,
    lane: str = "warn",
    safety_override=None,
):
    safety = {
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
    }
    if safety_override:
        safety.update(safety_override)
    return {
        "schema_version": "1",
        "mode": "ops_report",
        "status": "ok",
        "summary": {"containers_seen": 1, "suspects_ranked": 1, "critical": 0, "high": 1},
        "suspects": [
            {
                "name": "sfai-a",
                "rank": rank,
                "severity": severity,
                "confidence": confidence,
                "classes": classes or ["crashloop"],
            }
        ],
        "remediation_lane": {"status": lane},
        "safe_next_commands": ["shellforgeai ops report --json"],
        "safety": safety,
    }


def _save(tmp_path, payload):
    out = save_ops_report(payload, tmp_path, source_command="test")
    return out["report_id"]


def test_compare_identical_ok(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    a = _save(tmp_path, _report())
    b = _save(tmp_path, _report())
    r = runner.invoke(app, ["ops", "report", "compare", a, b, "--json"])
    assert r.exit_code == 0
    out = json.loads(r.stdout)
    assert out["status"] == "ok"
    assert out["summary"]["stable"] == 1


def test_compare_detects_escalation_and_lane_change(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    a = _save(tmp_path, _report(severity="high", lane="warn"))
    b = _save(tmp_path, _report(severity="critical", lane="blocked"))
    out = json.loads(runner.invoke(app, ["ops", "report", "compare", a, b, "--json"]).stdout)
    assert out["summary"]["escalated"] == 1
    assert out["remediation_lane"]["changed"] is True


def test_compare_safety_drift_warning(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    a = _save(tmp_path, _report())
    b = _save(tmp_path, _report(safety_override={"remediation_executed": True}))
    out = json.loads(runner.invoke(app, ["ops", "report", "compare", a, b, "--json"]).stdout)
    assert any("critical safety drift" in w for w in out["warnings"])


def test_compare_only_changed_and_include_stable_human(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    a = _save(tmp_path, _report())
    b = _save(tmp_path, _report())
    human = runner.invoke(app, ["ops", "report", "compare", a, b, "--only-changed"])
    assert human.exit_code == 0
    assert "Stable suspects:" not in human.stdout
    human2 = runner.invoke(app, ["ops", "report", "compare", a, b, "--include-stable"])
    assert "Stable suspects:" in human2.stdout


def test_compare_missing_not_found_nonzero_json(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    r = runner.invoke(app, ["ops", "report", "compare", "missing-a", "missing-b", "--json"])
    assert r.exit_code == 1
    out = json.loads(r.stdout)
    assert out["status"] in {"not_found", "failed", "error"}


def test_compare_export_valid(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    a = _save(tmp_path, _report(severity="high"))
    b = _save(tmp_path, _report(severity="critical"))
    ea = json.loads(runner.invoke(app, ["ops", "report", "export", a, "--json"]).stdout)["export"][
        "id"
    ]
    eb = json.loads(runner.invoke(app, ["ops", "report", "export", b, "--json"]).stdout)["export"][
        "id"
    ]
    r = runner.invoke(app, ["ops", "report", "compare-export", ea, eb, "--json"])
    assert r.exit_code == 0
    assert json.loads(r.stdout)["mode"] == "ops_report_compare"
