from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.interactive import repl
from shellforgeai.interactive.commands import route_input

runner = CliRunner()


def _fake_scene(*, empty: bool = False) -> dict:
    return {"containers": [] if empty else [{"name": "sfai-crashloop", "labels": {}}]}


def _fake_ranked(*, empty: bool = False) -> dict:
    if empty:
        return {
            "summary": {"containers_seen": 0, "suspects_ranked": 0, "critical": 0, "high": 0},
            "suspects": [],
        }
    return {
        "summary": {"containers_seen": 1, "suspects_ranked": 1, "critical": 1, "high": 0},
        "suspects": [
            {
                "rank": 1,
                "name": "sfai-crashloop",
                "severity": "critical",
                "confidence": "high",
                "classes": ["restart_storm"],
                "evidence": [{"type": "restart_count", "value": 9}],
            }
        ],
    }


def _patch_status(monkeypatch, tmp_path: Path, *, empty: bool = False) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene", lambda: _fake_scene(empty=empty)
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene", lambda scene: _fake_ranked(empty=empty)
    )
    monkeypatch.setattr(
        "shellforgeai.core.self_test.run_self_test_commands",
        lambda profile, include_skipped=False: {"status": "ok", "warnings": []},
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.build_remediation_audit_payload",
        lambda data_dir, latest_only=True: {"status": "ok"},
    )


def test_status_human_exits_zero_and_is_concise_safe(monkeypatch, tmp_path: Path) -> None:
    _patch_status(monkeypatch, tmp_path)
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "Status:" in result.stdout
    assert "Risk:" in result.stdout
    assert "First safe command:" in result.stdout
    assert "Safety: Read-only. No mutation executed." in result.stdout
    assert "shellforgeai triage docker detail sfai-crashloop" in result.stdout
    assert "docker restart" not in result.stdout.lower()
    assert "docker compose" not in result.stdout.lower()


def test_status_brief_exits_zero_and_mirrors_ops_report_brief(monkeypatch, tmp_path: Path) -> None:
    _patch_status(monkeypatch, tmp_path)
    status_result = runner.invoke(app, ["status", "--brief"])
    ops_result = runner.invoke(app, ["ops", "report", "--brief"])
    assert status_result.exit_code == 0
    assert ops_result.exit_code == 0
    assert "Status:" in status_result.stdout
    assert "First safe command:" in status_result.stdout
    assert status_result.stdout == ops_result.stdout


def test_status_json_is_strict_read_only_contract(monkeypatch, tmp_path: Path) -> None:
    _patch_status(monkeypatch, tmp_path)
    result = runner.invoke(app, ["status", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")
    assert payload["mode"] == "status"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False
    assert payload["safety"]["artifact_written"] is False
    assert payload["safety"]["model_called"] is False
    assert payload["first_safe_command"] == "shellforgeai triage docker detail sfai-crashloop"


def test_status_no_suspects_points_to_read_only_report_json(monkeypatch, tmp_path: Path) -> None:
    _patch_status(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "Risk: no ranked Docker suspects" in result.stdout
    assert "First safe command: shellforgeai ops report --json" in result.stdout


def test_status_does_not_write_artifacts_or_create_execution_objects(
    monkeypatch, tmp_path: Path
) -> None:
    _patch_status(monkeypatch, tmp_path)
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    forbidden_roots = [
        "ops_reports",
        "proposals",
        "missions",
        "apply-bundles",
        "actions",
        "cleanup",
        "remediation_receipts",
    ]
    assert [name for name in forbidden_roots if (tmp_path / name).exists()] == []


def test_status_does_not_call_model_codex(monkeypatch, tmp_path: Path) -> None:
    _patch_status(monkeypatch, tmp_path)

    def fail_build_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("status must not build or call a model provider")

    monkeypatch.setattr(cli_mod, "build_provider", fail_build_provider)
    result = runner.invoke(app, ["status", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["model_called"] is False


def test_status_does_not_run_cleanup_remediation_rollback_or_docker_mutation(
    monkeypatch, tmp_path: Path
) -> None:
    _patch_status(monkeypatch, tmp_path)
    calls: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        calls.append([str(part) for part in (cmd if isinstance(cmd, (list, tuple)) else [cmd])])
        raise AssertionError(f"status must not execute subprocesses: {cmd!r}")

    monkeypatch.setattr(cli_mod.subprocess, "run", fake_run)
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert calls == []
    low = result.stdout.lower()
    for forbidden in (
        "cleanup execute",
        "remediation execute",
        "rollback execute",
        "docker restart",
        "docker compose restart",
        "docker compose up",
        "docker compose down",
        "production restart",
    ):
        assert forbidden not in low


def test_interactive_status_routes_to_same_safe_entrypoint(monkeypatch, tmp_path: Path) -> None:
    _patch_status(monkeypatch, tmp_path)
    assert route_input("status").argv == ("status",)
    assert route_input("status --brief").argv == ("status", "--brief")
    assert route_input("status --json").argv == ("status", "--json")
    stream = StringIO()
    output = repl._run_interactive_cli_dispatch(Console(file=stream), ("status", "--json"))
    payload = json.loads(output)
    assert payload["mode"] == "status"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False


def test_ask_quick_status_routes_deterministically_and_mutation_ask_refuses(
    monkeypatch, tmp_path: Path
) -> None:
    _patch_status(monkeypatch, tmp_path)
    quick = runner.invoke(app, ["ask", "quick status"])
    assert quick.exit_code == 0
    assert "Read-only status (deterministic ask routing):" in quick.stdout
    assert "Safety: Read-only. No mutation executed." in quick.stdout

    mutation = runner.invoke(app, ["ask", "run the status fix"])
    assert mutation.exit_code == 0
    assert "Refusing" in mutation.stdout or "refus" in mutation.stdout.lower()
    assert "No command was executed" in mutation.stdout or "No action was taken" in mutation.stdout
