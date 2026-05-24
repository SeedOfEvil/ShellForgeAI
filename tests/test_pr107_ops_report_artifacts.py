from __future__ import annotations

import json

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _patch_ops(monkeypatch):
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: {"containers": [{"name": "sfai-crashloop", "labels": {}}]},
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene",
        lambda scene: {
            "summary": {"containers_seen": 1, "critical": 1, "high": 0},
            "suspects": [
                {
                    "rank": 1,
                    "name": "sfai-crashloop",
                    "severity": "critical",
                    "confidence": "high",
                    "classes": ["crashloop"],
                    "evidence": [{"type": "restart_count", "value": 8}],
                }
            ],
        },
    )
    monkeypatch.setattr(
        "shellforgeai.core.self_test.run_self_test_commands",
        lambda profile, include_skipped=False: {"status": "ok", "warnings": []},
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.build_remediation_audit_payload",
        lambda data_dir, latest_only=True: {"status": "ok"},
    )


def test_ops_report_save_validate_export_flow(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _patch_ops(monkeypatch)
    saved = json.loads(runner.invoke(app, ["ops", "report", "--save", "--json"]).stdout)
    assert saved["status"] == "saved"
    rid = saved["report_id"]
    v = runner.invoke(app, ["ops", "report", "validate", rid, "--json"])
    assert v.exit_code == 0
    assert json.loads(v.stdout)["status"] == "ok"
    exp = runner.invoke(app, ["ops", "report", "export", rid, "--json"])
    assert exp.exit_code == 0
    exp_out = json.loads(exp.stdout)
    assert exp_out["status"] == "exported"
    ev = runner.invoke(app, ["ops", "report", "export-validate", exp_out["export"]["id"], "--json"])
    assert ev.exit_code == 0
    assert json.loads(ev.stdout)["status"] == "ok"


def test_ops_report_validate_fails_for_forbidden_command(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _patch_ops(monkeypatch)
    saved = json.loads(runner.invoke(app, ["ops", "report", "--save", "--json"]).stdout)
    report_path = tmp_path / "ops_reports" / saved["report_id"] / "ops-report.json"
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    payload["safe_next_commands"] = ["docker restart sfai-crashloop"]
    report_path.write_text(json.dumps(payload), encoding="utf-8")
    bad = runner.invoke(app, ["ops", "report", "validate", saved["report_id"], "--json"])
    assert bad.exit_code == 1
    assert json.loads(bad.stdout)["checks"]["safe_commands"] is False
