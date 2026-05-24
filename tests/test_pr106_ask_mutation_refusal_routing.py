from __future__ import annotations

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app

runner = CliRunner()


def _fail_provider(*_a, **_k):
    raise AssertionError("model/Codex path must not be called")


def test_mutation_prompts_refuse_without_model(monkeypatch, tmp_path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(cli_mod, "build_provider", _fail_provider)
    prompts = [
        "please restart shellforgeai",
        "restart sfai-crashloop",
        "stop sfai-bad-http",
        "remove sfai-noisy-errors",
        "fix everything",
        "remediate all eligible targets",
        "execute remediation",
        "run the remediation plan",
        "rollback now",
        "cleanup metadata now",
        "docker compose restart shellforgeai",
        "docker compose up -d",
        "chmod the files",
        "install nginx",
        "apply the fix",
    ]
    for prompt in prompts:
        r = runner.invoke(app, ["ask", prompt])
        assert r.exit_code == 0
        out = r.stdout.lower()
        assert (
            "refused: natural-language mutation is not allowed" in out
            or "refusing to execute" in out
            or "refusing natural-language compose mutation" in out
            or "i can rank suspects read-only" in out
        )
        if "refused: natural-language mutation is not allowed" in out:
            assert "--execute --confirm" not in out
        assert "docker compose restart" not in out


def test_refusal_suggests_targeted_read_only_commands(monkeypatch, tmp_path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(cli_mod, "build_provider", _fail_provider)
    r = runner.invoke(app, ["ask", "restart sfai-noisy-errors"])
    assert r.exit_code == 0
    out = r.stdout.lower()
    assert (
        "shellforgeai triage docker detail sfai-noisy-errors" in out
        or "cannot run a container restart from ask" in out
    )


def test_cleanup_and_rollback_refusal_suggestions(monkeypatch, tmp_path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(cli_mod, "build_provider", _fail_provider)

    cleanup = runner.invoke(app, ["ask", "cleanup metadata now"])
    assert cleanup.exit_code == 0
    assert "shellforgeai audit cleanup review" in cleanup.stdout
    assert "shellforgeai audit cleanup prepare --category exports" in cleanup.stdout
    assert "--max-age-days 7" in cleanup.stdout
    assert "--keep-latest 5" in cleanup.stdout
    assert "cleanup execute --confirm" not in cleanup.stdout.lower()

    rollback = runner.invoke(app, ["ask", "rollback the last remediation"])
    assert rollback.exit_code == 0
    assert "shellforgeai remediation audit --latest" in rollback.stdout
    assert "rollback-execute --confirm" not in rollback.stdout.lower()


def test_ops_report_route_still_wins_for_non_mutation_prompt(monkeypatch, tmp_path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: {"containers": [{"name": "sfai-crashloop", "labels": {}}]},
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene",
        lambda _scene: {
            "summary": {"containers_seen": 1, "critical": 1, "high": 0},
            "suspects": [
                {
                    "rank": 1,
                    "name": "sfai-crashloop",
                    "severity": "critical",
                    "confidence": "high",
                    "classes": ["crashloop"],
                    "evidence": [],
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
    monkeypatch.setattr(cli_mod, "build_provider", _fail_provider)

    r = runner.invoke(app, ["ask", "what is on fire in docker right now? ops report please"])
    assert r.exit_code == 0
    assert "Read-only ops report (deterministic ask routing):" in r.stdout
