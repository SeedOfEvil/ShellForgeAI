from __future__ import annotations

import importlib
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app

runner = CliRunner()


def _fake_scene() -> dict:
    return {
        "containers": [
            {"name": "sfai-crashloop", "labels": {}, "State": "running"},
            {"name": "sfai-bad-http", "labels": {}, "State": "running"},
        ]
    }


def _fake_ranked() -> dict:
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


def _patch_read_only_scene(monkeypatch, tmp_path: Path) -> None:
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
        cli_mod,
        "build_provider",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("model must not be called")),
    )


def test_ops_and_triage_modules_exist_and_import_cleanly() -> None:
    assert Path("src/shellforgeai/commands/ops.py").exists()
    assert Path("src/shellforgeai/commands/triage.py").exists()

    cli_source = Path("src/shellforgeai/cli.py").read_text(encoding="utf-8")
    assert "from shellforgeai.commands import ops as ops_commands" in cli_source
    assert "from shellforgeai.commands import triage as triage_commands" in cli_source
    assert "ops_commands.register(ops_app, ops_report_app)" in cli_source
    assert (
        "triage_commands.register(triage_app, triage_docker_app, triage_docker_snapshot_app)"
        in cli_source
    )

    importlib.import_module("shellforgeai.cli")
    importlib.import_module("shellforgeai.commands.ops")
    importlib.import_module("shellforgeai.commands.triage")


def test_command_surface_help_stays_registered() -> None:
    for args in (
        ["--help"],
        ["ops", "--help"],
        ["ops", "report", "--help"],
        ["triage", "--help"],
        ["triage", "docker", "--help"],
    ):
        result = runner.invoke(app, args)
        assert result.exit_code == 0, result.stdout


def test_ops_report_json_and_human_outputs_preserve_safety(monkeypatch, tmp_path: Path) -> None:
    _patch_read_only_scene(monkeypatch, tmp_path)

    json_result = runner.invoke(app, ["ops", "report", "--json"])
    assert json_result.exit_code == 0, json_result.stdout
    payload = json.loads(json_result.stdout)
    assert payload["mode"] == "ops_report"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False
    assert payload["safety"]["docker_compose_executed"] is False
    assert payload["safety"]["container_restarted"] is False
    assert payload["safety"].get("arbitrary_command_execution", False) is False
    assert payload["safety"].get("natural_language_execution", False) is False

    human_result = runner.invoke(app, ["ops", "report"])
    assert human_result.exit_code == 0, human_result.stdout
    assert "ShellForgeAI 2AM Operator Report" in human_result.stdout
    assert "Safety" in human_result.stdout
    assert "mutation_performed: false" in human_result.stdout

    brief_result = runner.invoke(app, ["ops", "report", "--brief"])
    assert brief_result.exit_code == 0, brief_result.stdout
    assert "Status:" in brief_result.stdout
    assert "Safety:" in brief_result.stdout
    assert "Read-only" in brief_result.stdout


def test_triage_json_and_human_outputs_preserve_safety(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        cli_mod,
        "build_provider",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("model must not be called")),
    )

    json_result = runner.invoke(app, ["triage", "docker", "--json"])
    assert json_result.exit_code == 0, json_result.stdout
    payload = json.loads(json_result.stdout)
    assert payload["mode"] == "docker_triage_ranking"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False
    assert payload["safety"]["docker_compose_executed"] is False
    assert payload["safety"]["container_restarted"] is False
    assert payload["safety"].get("arbitrary_command_execution", False) is False
    assert payload["safety"].get("natural_language_execution", False) is False

    human_result = runner.invoke(app, ["triage", "docker"])
    assert human_result.exit_code == 0, human_result.stdout
    assert "Docker triage" in human_result.stdout
    assert "no ranked Docker suspects" in human_result.stdout
    assert "mutation_performed: false" in human_result.stdout

    v2_result = runner.invoke(app, ["triage", "--json"])
    assert v2_result.exit_code == 0, v2_result.stdout
    v2_payload = json.loads(v2_result.stdout)
    assert v2_payload["read_only"] is True
    assert v2_payload["mutation_performed"] is False


def test_ask_routing_and_mutation_refusal_remain_deterministic(monkeypatch, tmp_path: Path) -> None:
    _patch_read_only_scene(monkeypatch, tmp_path)

    triage_result = runner.invoke(app, ["ask", "triage docker, what should I inspect first?"])
    assert triage_result.exit_code == 0, triage_result.stdout
    triage_out = triage_result.stdout.lower()
    assert "read-only" in triage_out
    assert "triage" in triage_out or "status" in triage_out
    assert "shellforgeai triage" in triage_out or "shellforgeai status" in triage_out

    report_result = runner.invoke(app, ["ask", "show me the ops report"])
    assert report_result.exit_code == 0, report_result.stdout
    report_out = report_result.stdout.lower()
    assert "read-only ops report" in report_out
    assert "deterministic ask routing" in report_out
    assert "mutation_performed: false" in report_out

    cleanup_restart_result = runner.invoke(app, ["ask", "cleanup docker and restart the app"])
    assert cleanup_restart_result.exit_code == 0, cleanup_restart_result.stdout
    cleanup_out = cleanup_restart_result.stdout.lower()
    assert "execute mutations" in cleanup_out or "cannot execute" in cleanup_out
    assert "no restart" in cleanup_out or "no mutation" in cleanup_out
    assert "--execute --confirm" not in cleanup_out

    recovery_result = runner.invoke(
        app,
        ["ask", "recover the service, roll back the bad change, and remediate it now"],
    )
    assert recovery_result.exit_code == 0, recovery_result.stdout
    recovery_out = recovery_result.stdout.lower()
    assert (
        "natural-language mutation is not allowed" in recovery_out
        or "cannot execute" in recovery_out
    )
    assert (
        "rollback" in recovery_out or "remediation" in recovery_out or "no mutation" in recovery_out
    )
    assert "--execute --confirm" not in recovery_out


def test_extracted_modules_do_not_introduce_execution_surfaces() -> None:
    combined = "\n".join(
        [
            Path("src/shellforgeai/commands/ops.py").read_text(encoding="utf-8"),
            Path("src/shellforgeai/commands/triage.py").read_text(encoding="utf-8"),
        ]
    )
    forbidden_snippets = (
        "shell=True",
        "build_provider(",
        "subprocess.run",
        "docker compose up",
        "docker compose down",
        "docker compose restart",
        "docker restart",
        "execute_receipt_recovery(",
        "preview_receipt_rollback(",
        "run_exact_docker_restart(",
    )
    for snippet in forbidden_snippets:
        assert snippet not in combined
