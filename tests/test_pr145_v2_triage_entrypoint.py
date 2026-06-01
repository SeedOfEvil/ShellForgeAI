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


def _scene(*, empty: bool = False) -> dict:
    return {"containers": [] if empty else [{"name": "sfai-crashloop", "labels": {}}]}


def _ranked(*, empty: bool = False) -> dict:
    safety = {
        "read_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "model_called": False,
    }
    if empty:
        return {
            "status": "warn",
            "summary": {"containers_seen": 0, "suspects_ranked": 0, "critical": 0, "high": 0},
            "suspects": [],
            "warnings": ["no suspects ranked from provided scene"],
            "safety": safety,
        }
    return {
        "status": "ok",
        "summary": {"containers_seen": 1, "suspects_ranked": 1, "critical": 1, "high": 0},
        "suspects": [
            {
                "rank": 1,
                "name": "sfai-crashloop",
                "kind": "container",
                "severity": "critical",
                "confidence": "high",
                "score": 100,
                "classes": ["crashloop", "restart_storm"],
                "why": ["container is restart-looping"],
                "evidence": [{"type": "restart_count", "value": 9}],
                "safe_next_commands": ["shellforgeai triage docker detail sfai-crashloop"],
            }
        ],
        "warnings": [],
        "safety": safety,
    }


def _patch_triage(monkeypatch, tmp_path: Path, *, empty: bool = False) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene", lambda: _scene(empty=empty)
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene", lambda scene: _ranked(empty=empty)
    )


def test_triage_human_returns_ranked_suspect_and_safe_command(monkeypatch, tmp_path: Path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["triage"])
    assert result.exit_code == 0
    assert "Triage: degraded" in result.stdout
    assert "Suspects: 1" in result.stdout
    assert "Top suspect: sfai-crashloop" in result.stdout
    assert "Evidence:" in result.stdout
    assert "First safe command:" in result.stdout
    assert "shellforgeai triage --target sfai-crashloop" in result.stdout
    assert "Safety: Read-only. No mutation executed." in result.stdout


def test_triage_brief_is_bounded(monkeypatch, tmp_path: Path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["triage", "--brief"])
    assert result.exit_code == 0
    assert result.stdout.count("\n") <= 3
    assert "Triage: degraded — top suspect sfai-crashloop" in result.stdout
    assert "Safety: read-only" in result.stdout


def test_triage_json_is_strict_and_non_mutating(monkeypatch, tmp_path: Path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["triage", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")
    assert payload["mode"] == "v2_triage"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["first_safe_command"] == "shellforgeai triage --target sfai-crashloop"
    safety = payload["safety"]
    for key in (
        "mutation_performed",
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "docker_compose_executed",
        "container_restarted",
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_execution",
        "model_called",
    ):
        assert safety[key] is False


def test_triage_target_human_and_json_detail(monkeypatch, tmp_path: Path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    human = runner.invoke(app, ["triage", "--target", "sfai-crashloop"])
    assert human.exit_code == 0
    assert "Triage detail" in human.stdout
    assert "Target: sfai-crashloop" in human.stdout
    assert "Severity: critical / high confidence" in human.stdout
    assert "First safe command:" in human.stdout
    assert "shellforgeai remediation eligibility --target sfai-crashloop --explain" in human.stdout
    assert "Safety: Read-only. No mutation executed." in human.stdout

    raw = runner.invoke(app, ["triage", "--target", "sfai-crashloop", "--json"])
    assert raw.exit_code == 0
    payload = json.loads(raw.stdout)
    assert payload["mode"] == "v2_triage_detail"
    assert payload["target"] == "sfai-crashloop"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["first_safe_command"].endswith("--explain")


def test_triage_no_suspects_is_ok_with_status_json_next_command(
    monkeypatch, tmp_path: Path
) -> None:
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["triage"])
    assert result.exit_code == 0
    assert "Triage: OK" in result.stdout
    assert "Suspects: none found" in result.stdout
    assert "shellforgeai status --json" in result.stdout


def test_triage_target_not_found_is_controlled(monkeypatch, tmp_path: Path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["triage", "--target", "missing"])
    assert result.exit_code == 0
    assert "Status: not_found" in result.stdout
    assert "no matching ranked suspect" in result.stdout
    assert "Traceback" not in result.stdout


def test_existing_triage_docker_subcommands_still_work(monkeypatch, tmp_path: Path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    listing = runner.invoke(app, ["triage", "docker"])
    assert listing.exit_code == 0
    assert "Docker triage suspects" in listing.stdout
    detail = runner.invoke(app, ["triage", "docker", "detail", "sfai-crashloop"])
    assert detail.exit_code == 0
    assert "Docker triage detail: sfai-crashloop" in detail.stdout


def test_ask_likely_suspect_routes_to_v2_triage_and_mutation_refuses(
    monkeypatch, tmp_path: Path
) -> None:
    _patch_triage(monkeypatch, tmp_path)
    for prompt in ("what is the likely suspect?", "what should I inspect first?"):
        result = runner.invoke(app, ["ask", prompt])
        assert result.exit_code == 0
        assert "Read-only triage (deterministic ask routing):" in result.stdout
        assert "shellforgeai triage --target sfai-crashloop" in result.stdout
        assert "No mutation executed" in result.stdout
    refused = runner.invoke(app, ["ask", "docker compose restart"])
    assert refused.exit_code == 0
    assert "refus" in refused.stdout.lower() or "cannot" in refused.stdout.lower()


def test_interactive_triage_dispatches_v2_commands(monkeypatch, tmp_path: Path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    assert route_input("triage").argv == ("triage",)
    assert route_input("triage --brief").argv == ("triage", "--brief")
    assert route_input("triage --json").argv == ("triage", "--json")
    assert route_input("triage --target sfai-crashloop").argv == (
        "triage",
        "--target",
        "sfai-crashloop",
    )
    stream = StringIO()
    output = repl._run_interactive_cli_dispatch(Console(file=stream), ("triage", "--json"))
    assert json.loads(output)["mode"] == "v2_triage"
    detail = repl._run_interactive_cli_dispatch(
        Console(file=StringIO()), ("triage", "--target", "sfai-crashloop")
    )
    assert "Triage detail" in detail
    assert route_input("docker compose restart").name == "mutation_refused"


def test_v2_triage_safety_does_not_execute_or_call_model(monkeypatch, tmp_path: Path) -> None:
    _patch_triage(monkeypatch, tmp_path)

    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"triage must not run subprocesses: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("triage must not call model provider")

    monkeypatch.setattr(cli_mod.subprocess, "run", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)
    result = runner.invoke(app, ["triage", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["safety"]["cleanup_executed"] is False
    assert payload["safety"]["remediation_executed"] is False
    assert payload["safety"]["rollback_executed"] is False
    assert payload["safety"]["docker_compose_executed"] is False
    assert payload["safety"]["shell_true"] is False
    assert payload["safety"]["arbitrary_command_execution"] is False
    assert payload["safety"]["model_called"] is False
    low = result.stdout.lower()
    for forbidden in (
        "cleanup execute",
        "remediation execute --confirm",
        "rollback execute --confirm",
        "docker restart",
        "docker compose restart",
        "docker system prune",
    ):
        assert forbidden not in low
