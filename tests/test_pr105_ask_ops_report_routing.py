from __future__ import annotations

import json

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
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
                "evidence": [{"type": "restart_count", "value": 9}],
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


def _patch_ops(monkeypatch, tmp_path):
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


def test_ask_routes_2am_prompt_to_deterministic_ops_report(monkeypatch, tmp_path):
    _patch_ops(monkeypatch, tmp_path)
    monkeypatch.setattr(
        cli_mod,
        "build_provider",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("model must not be called")),
    )
    r = runner.invoke(app, ["ask", "it's 2am, what is on fire?"])
    assert r.exit_code == 0
    assert "Read-only ops report (deterministic ask routing):" in r.stdout
    assert "sfai-crashloop" in r.stdout
    assert "remediation eligibility --target" in r.stdout
    assert "mutation_performed: false" in r.stdout
    assert "Codex auth failed" not in r.stdout


def test_ask_routes_docker_broken_prompt_to_deterministic_ops_report(monkeypatch, tmp_path):
    _patch_ops(monkeypatch, tmp_path)
    r = runner.invoke(app, ["ask", "docker is broken, what should I check first?"])
    assert r.exit_code == 0
    assert "Read-only ops report" in r.stdout


def test_ask_routes_ops_report_prompt_to_deterministic_ops_report(monkeypatch, tmp_path):
    _patch_ops(monkeypatch, tmp_path)
    r = runner.invoke(app, ["ask", "show me the ops report"])
    assert r.exit_code == 0
    assert "Read-only ops report" in r.stdout


def test_ask_mutation_refusal_still_works(monkeypatch, tmp_path):
    _patch_ops(monkeypatch, tmp_path)
    r = runner.invoke(app, ["ask", "restart the top suspect"])
    assert r.exit_code == 0
    out = r.stdout.lower()
    assert "will not execute fixes" in out or "cannot execute" in out
    assert "no restart" in out or "no mutation" in out
    assert "--execute --confirm" not in out


def test_ops_report_json_contract_regression(monkeypatch, tmp_path):
    _patch_ops(monkeypatch, tmp_path)
    r = runner.invoke(app, ["ops", "report", "--json"])
    assert r.exit_code == 0
    payload = json.loads(r.stdout)
    assert payload["mode"] == "ops_report"
    assert payload["safety"]["natural_language_execution"] is False
