"""PR146: triage UX polish and command consistency.

These tests pin the V2 triage command family to one consistent, read-only
operator shape: top-level ``triage`` / ``triage --brief`` / ``triage --json``,
the Docker compatibility path ``triage docker`` (now including a
``--brief`` alias), deterministic ask routing, and interactive dispatch.

Everything here must stay strictly read-only. No mutation, no cleanup
execution, no remediation execution, no rollback execution, no Docker or
Compose mutation, no ``shell=True``, no arbitrary command execution, and no
natural-language mutation may be introduced by triage UX polish.
"""

from __future__ import annotations

import ast
import json
from io import StringIO
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.interactive import repl
from shellforgeai.interactive.commands import route_input

runner = CliRunner()

# Read-only first-safe-command allowlist for the no-suspect state.
APPROVED_NO_SUSPECT_COMMANDS = {
    "shellforgeai status --json",
    "shellforgeai ops report --json",
    "shellforgeai triage --json",
}

# Commands that triage UX must never suggest as a first safe step.
FORBIDDEN_COMMANDS = (
    "docker restart",
    "docker compose restart",
    "docker compose up",
    "docker compose down",
    "docker system prune",
    "docker volume prune",
    "cleanup execute",
    "remediation execute",
    "rollback-execute",
    "rollback execute",
    "execute --confirm",
)


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


def _assert_no_forbidden(text: str) -> None:
    low = text.lower()
    for forbidden in FORBIDDEN_COMMANDS:
        assert forbidden not in low, f"forbidden command surfaced: {forbidden!r}"


# 1. Top-level triage human output is status-consistent.
def test_triage_human_has_consistent_status_risk_and_safety(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["triage"])
    assert result.exit_code == 0
    out = result.stdout
    assert "Status:" in out
    assert "Risk:" in out
    assert "First safe command:" in out
    assert "Safety:" in out
    assert "Safety: Read-only. No mutation executed." in out
    _assert_no_forbidden(out)


# 2. Brief is bounded and still names the first safe command.
def test_triage_brief_is_bounded_with_first_safe_command(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["triage", "--brief"])
    assert result.exit_code == 0
    assert result.stdout.count("\n") <= 3
    assert "First safe command:" in result.stdout
    assert "Safety: read-only" in result.stdout
    _assert_no_forbidden(result.stdout)


# 3. JSON stays strict and read-only.
def test_triage_json_is_strict(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["triage", "--json"])
    assert result.exit_code == 0
    body = result.stdout.strip()
    assert body.startswith("{") and body.endswith("}")
    payload = json.loads(body)
    assert payload["mode"] == "v2_triage"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    _assert_no_forbidden(result.stdout)


# 4. No-suspect JSON must not point at a detail command for a missing suspect.
def test_triage_json_no_suspects_does_not_suggest_detail(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["triage", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    first = payload["first_safe_command"]
    assert "detail" not in first
    assert "--target" not in first


# 5. No-suspect first safe command is an approved read-only status/report command.
def test_triage_no_suspects_first_safe_command_is_approved(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["triage", "--json"]).stdout)
    assert payload["first_safe_command"] in APPROVED_NO_SUSPECT_COMMANDS
    human = runner.invoke(app, ["triage"]).stdout
    assert "shellforgeai status --json" in human
    assert "Suspects: none found" in human


# 6. With suspects, the Docker compatibility path leads with triage docker detail.
def test_suspect_first_safe_command_is_triage_docker_detail(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["triage", "docker"])
    assert result.exit_code == 0
    assert "First safe command: shellforgeai triage docker detail sfai-crashloop" in result.stdout


# 7. triage docker carries V2 read-only safety wording and no forbidden commands.
def test_triage_docker_safety_wording_is_consistent(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["triage", "docker"])
    assert result.exit_code == 0
    out = result.stdout
    assert "read_only: true" in out
    assert "mutation_performed: false" in out
    _assert_no_forbidden(out)


# 8. triage docker --brief is a safe compatibility alias mirroring triage --brief.
def test_triage_docker_brief_mirrors_top_level_brief(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    docker_brief = runner.invoke(app, ["triage", "docker", "--brief"])
    assert docker_brief.exit_code == 0
    top_brief = runner.invoke(app, ["triage", "--brief"])
    assert docker_brief.stdout == top_brief.stdout
    assert "First safe command:" in docker_brief.stdout
    assert "Safety: read-only" in docker_brief.stdout
    _assert_no_forbidden(docker_brief.stdout)


# 9. triage docker --json remains backwards-compatible.
def test_triage_docker_json_remains_backwards_compatible(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["triage", "docker", "--json"])
    assert result.exit_code == 0
    body = result.stdout.strip()
    assert body.startswith("{") and body.endswith("}")
    payload = json.loads(body)
    # Backwards-compatible Docker ranking contract: suspects list + read-only safety.
    assert "suspects" in payload
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False


# 10. Interactive triage --brief routes and dispatches.
def test_interactive_triage_brief(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    assert route_input("triage --brief").argv == ("triage", "--brief")
    output = repl._run_interactive_cli_dispatch(Console(file=StringIO()), ("triage", "--brief"))
    assert "Triage: degraded — top suspect sfai-crashloop" in output
    _assert_no_forbidden(output)


# 11. Interactive triage docker --brief routes and dispatches as the alias.
def test_interactive_triage_docker_brief(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    assert route_input("triage docker --brief").argv == ("triage", "docker", "--brief")
    output = repl._run_interactive_cli_dispatch(
        Console(file=StringIO()), ("triage", "docker", "--brief")
    )
    assert "First safe command:" in output
    assert "Safety: read-only" in output
    _assert_no_forbidden(output)


# 12. Interactive triage --json emits strict JSON.
def test_interactive_triage_json_is_strict(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    assert route_input("triage --json").argv == ("triage", "--json")
    output = repl._run_interactive_cli_dispatch(Console(file=StringIO()), ("triage", "--json"))
    payload = json.loads(output)
    assert payload["mode"] == "v2_triage"
    assert payload["read_only"] is True


# 13. Ask "quick triage" routes to brief read-only triage.
def test_ask_quick_triage_routes_to_brief(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["ask", "quick triage"])
    assert result.exit_code == 0
    out = result.stdout
    assert "Read-only triage (deterministic ask routing):" in out
    assert "Triage: degraded — top suspect sfai-crashloop" in out
    assert "Safety: read-only" in out
    _assert_no_forbidden(out)


# 14. Ask "no novel, triage" routes to brief read-only triage.
def test_ask_no_novel_triage_routes_to_brief(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["ask", "no novel, triage"])
    assert result.exit_code == 0
    out = result.stdout
    assert "Read-only triage (deterministic ask routing):" in out
    assert "Triage: degraded — top suspect sfai-crashloop" in out
    _assert_no_forbidden(out)


# 15. Ask "restart the top suspect" refuses without mutation.
def test_ask_restart_top_suspect_refuses(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["ask", "restart the top suspect"])
    assert result.exit_code == 0
    low = result.stdout.lower()
    assert "will not execute" in low or "refus" in low
    assert "was executed" in low or "no restart" in low
    _assert_no_forbidden(result.stdout)


# 16. None of the triage surfaces suggest forbidden mutation commands.
def test_triage_surfaces_have_no_forbidden_commands(monkeypatch, tmp_path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    for argv in (
        ["triage"],
        ["triage", "--brief"],
        ["triage", "--json"],
        ["triage", "docker"],
        ["triage", "docker", "--brief"],
        ["triage", "docker", "--json"],
    ):
        result = runner.invoke(app, argv)
        assert result.exit_code == 0
        _assert_no_forbidden(result.stdout)


# 17-23. Safety regression: triage UX changes introduce no execution primitives.
def test_triage_sources_stay_read_only_and_shell_free() -> None:
    touched = [
        Path("src/shellforgeai/cli.py"),
        Path("src/shellforgeai/core/ask_routing.py"),
        Path("src/shellforgeai/interactive/commands.py"),
        Path("src/shellforgeai/interactive/repl.py"),
    ]
    for path in touched:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    assert not (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ), f"shell=True introduced in {path}"


def test_interactive_triage_mutation_still_refuses() -> None:
    # Natural-language and command-style mutation tied to triage must refuse.
    assert route_input("docker compose restart").name == "mutation_refused"
    assert route_input("restart the top suspect").name in {"mutation_refused", "ask"}
    assert route_input("docker restart sfai-crashloop").name == "mutation_refused"
