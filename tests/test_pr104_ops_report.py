from __future__ import annotations

import json

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _fake_scene():
    return {
        "containers": [
            {"name": "sfai-crashloop", "labels": {}},
            {"name": "sfai-bad-http", "labels": {}},
        ]
    }


def _fake_ranked():
    return {
        "summary": {"containers_seen": 2, "critical": 1, "high": 1},
        "suspects": [
            {
                "rank": 1,
                "name": "sfai-crashloop",
                "severity": "critical",
                "confidence": "high",
                "classes": ["crashloop"],
                "evidence": [{"type": "restart_count", "value": 8}],
            },
            {
                "rank": 2,
                "name": "sfai-bad-http",
                "severity": "high",
                "confidence": "high",
                "classes": ["bad_http"],
                "evidence": [{"type": "bad_http", "value": 502}],
            },
        ],
    }


def test_ops_report_human_contains_safety_and_suspects(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.core.triage_ranking.collect_scene", lambda: _fake_scene())
    monkeypatch.setattr("shellforgeai.core.triage_ranking.rank_scene", lambda scene: _fake_ranked())
    monkeypatch.setattr(
        "shellforgeai.core.self_test.run_self_test_commands",
        lambda profile, include_skipped=False: {"status": "ok", "warnings": []},
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.build_remediation_audit_payload",
        lambda data_dir, latest_only=True: {"status": "empty"},
    )

    r = runner.invoke(app, ["ops", "report"])
    assert r.exit_code == 0
    assert "ShellForgeAI 2AM Operator Report" in r.stdout
    assert "Safety:" in r.stdout
    assert "sfai-crashloop" in r.stdout
    assert "Recommended next steps" in r.stdout


def test_ops_report_json_strict_contract(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.core.triage_ranking.collect_scene", lambda: _fake_scene())
    monkeypatch.setattr("shellforgeai.core.triage_ranking.rank_scene", lambda scene: _fake_ranked())
    monkeypatch.setattr(
        "shellforgeai.core.self_test.run_self_test_commands",
        lambda profile, include_skipped=False: {"status": "warn", "warnings": ["w"]},
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.build_remediation_audit_payload",
        lambda data_dir, latest_only=True: {"status": "ok"},
    )

    r = runner.invoke(app, ["ops", "report", "--json"])
    assert r.exit_code == 0
    out = json.loads(r.stdout)
    assert out["mode"] == "ops_report"
    assert out["read_only"] is True
    assert out["safety"]["mutation_performed"] is False
    assert out["safety"]["remediation_executed"] is False
    assert out["safety"]["rollback_executed"] is False


def test_ops_report_top_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.core.triage_ranking.collect_scene", lambda: _fake_scene())
    monkeypatch.setattr("shellforgeai.core.triage_ranking.rank_scene", lambda scene: _fake_ranked())
    monkeypatch.setattr(
        "shellforgeai.core.self_test.run_self_test_commands",
        lambda profile, include_skipped=False: {"status": "ok", "warnings": []},
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.build_remediation_audit_payload",
        lambda data_dir, latest_only=True: {"status": "ok"},
    )

    out = json.loads(runner.invoke(app, ["ops", "report", "--json", "--top", "1"]).stdout)
    assert len(out["suspects"]) == 1


def test_ops_report_include_remediation(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.core.triage_ranking.collect_scene", lambda: _fake_scene())
    monkeypatch.setattr("shellforgeai.core.triage_ranking.rank_scene", lambda scene: _fake_ranked())
    monkeypatch.setattr(
        "shellforgeai.core.self_test.run_self_test_commands",
        lambda profile, include_skipped=False: {"status": "ok", "warnings": []},
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.build_remediation_audit_payload",
        lambda data_dir, latest_only=True: {"status": "ok"},
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.build_eligibility_explain_report",
        lambda *, target, scenario, labels=None, target_found=True, explicit_target=True: {
            "eligibility": {
                "state": "blocked",
                "executors": {
                    "proof": {"ready": False},
                    "docker-disposable": {"ready": False},
                },
            },
            "gates": [{"status": "failed", "reason": "missing label"}],
        },
    )
    out = json.loads(
        runner.invoke(app, ["ops", "report", "--json", "--include-remediation"]).stdout
    )
    assert out["suspects"][0]["remediation"]["eligibility"] == "blocked"
    assert "missing label" in out["suspects"][0]["remediation"]["blocked_reasons"]


def test_ops_report_include_timeline_warning(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.core.triage_ranking.collect_scene", lambda: _fake_scene())
    monkeypatch.setattr("shellforgeai.core.triage_ranking.rank_scene", lambda scene: _fake_ranked())
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.build_snapshot_timeline",
        lambda data_dir: {"status": "warn", "warnings": ["no snapshots"]},
    )
    monkeypatch.setattr(
        "shellforgeai.core.self_test.run_self_test_commands",
        lambda profile, include_skipped=False: {"status": "ok", "warnings": []},
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.build_remediation_audit_payload",
        lambda data_dir, latest_only=True: {"status": "ok"},
    )

    out = json.loads(runner.invoke(app, ["ops", "report", "--json", "--include-timeline"]).stdout)
    assert "no snapshots" in out["warnings"]


def test_ops_report_safe_commands_no_mutation_keywords(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.core.triage_ranking.collect_scene", lambda: _fake_scene())
    monkeypatch.setattr("shellforgeai.core.triage_ranking.rank_scene", lambda scene: _fake_ranked())
    monkeypatch.setattr(
        "shellforgeai.core.self_test.run_self_test_commands",
        lambda profile, include_skipped=False: {"status": "ok", "warnings": []},
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.build_remediation_audit_payload",
        lambda data_dir, latest_only=True: {"status": "ok"},
    )

    out = json.loads(runner.invoke(app, ["ops", "report", "--json"]).stdout)
    cmds = "\n".join(out["safe_next_commands"]).lower()
    assert "triage docker detail" in cmds
    assert "remediation eligibility --target" in cmds
    assert "docker restart" not in cmds
    assert "docker compose restart" not in cmds
    assert "remediation execute" not in cmds
    assert "rollback-execute" not in cmds
    assert "cleanup execute" not in cmds
    assert "--execute --confirm" not in cmds
