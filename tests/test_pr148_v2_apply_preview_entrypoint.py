from __future__ import annotations

import ast
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


def _safety() -> dict:
    return {
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


def _scene(
    *, empty: bool = False, labels: dict | None = None, target: str = "sfai-crashloop"
) -> dict:
    if empty:
        return {"containers": []}
    return {"containers": [{"name": target, "labels": labels or {}}]}


def _ranked(*, empty: bool = False, target: str = "sfai-crashloop") -> dict:
    if empty:
        return {
            "status": "warn",
            "summary": {"containers_seen": 0, "suspects_ranked": 0, "critical": 0, "high": 0},
            "suspects": [],
            "warnings": ["no suspects ranked from provided scene"],
            "safety": _safety(),
        }
    return {
        "status": "ok",
        "summary": {"containers_seen": 1, "suspects_ranked": 1, "critical": 1, "high": 0},
        "suspects": [
            {
                "rank": 1,
                "name": target,
                "kind": "container",
                "severity": "critical",
                "confidence": "high",
                "score": 100,
                "classes": ["crashloop"],
                "why": ["critical restart storm evidence from Docker triage"],
                "evidence": [{"type": "restart_count", "value": 9}],
                "safe_next_commands": [f"shellforgeai triage docker detail {target}"],
            }
        ],
        "warnings": [],
        "safety": _safety(),
    }


def _patch_triage(
    monkeypatch,
    tmp_path: Path,
    *,
    empty: bool = False,
    labels: dict | None = None,
    target: str = "sfai-crashloop",
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: _scene(empty=empty, labels=labels, target=target),
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene",
        lambda scene: _ranked(empty=empty, target=target),
    )


def _assert_forbidden_absent(text: str) -> None:
    low = text.lower()
    for forbidden in (
        "remediation execute --confirm",
        "rollback-execute --confirm",
        "cleanup execute --confirm",
        "docker restart",
        "docker compose restart",
    ):
        assert forbidden not in low


def test_apply_preview_no_suspect_human_no_action_safe_and_read_only(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["apply-preview"])
    assert result.exit_code == 0
    assert "Apply preview: no action ready" in result.stdout
    assert "no eligible proposal/action found" in result.stdout
    assert "shellforgeai propose --json" in result.stdout
    assert "Read-only preview" in result.stdout
    assert "No action was taken" in result.stdout
    _assert_forbidden_absent(result.stdout)


def test_apply_preview_brief_is_bounded_and_read_only(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["apply-preview", "--brief"])
    assert result.exit_code == 0
    assert result.stdout.count("\n") <= 4
    assert "Apply preview: no_action" in result.stdout
    assert "Target: none" in result.stdout
    assert "Safety: read-only" in result.stdout


def test_apply_preview_blocks_production_target(monkeypatch, tmp_path):
    _patch_triage(
        monkeypatch,
        tmp_path,
        target="shellforgeai",
        labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
    )
    result = runner.invoke(app, ["apply-preview", "--target", "shellforgeai"])
    assert result.exit_code == 0
    assert "Apply preview: blocked" in result.stdout
    assert "Target: shellforgeai" in result.stdout
    assert "production target refused" in result.stdout
    assert "shellforgeai status --json" in result.stdout
    assert "No action was taken" in result.stdout


def test_apply_preview_target_not_found_blocks(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["apply-preview", "--target", "missing"])
    assert result.exit_code == 0
    assert "Apply preview: blocked" in result.stdout
    assert "Target: missing" in result.stdout
    assert "target not found in current deterministic triage scene" in result.stdout
    assert "shellforgeai triage --json" in result.stdout
    assert "No action was taken" in result.stdout


def test_apply_preview_eligible_disposable_target_shows_gates_only(monkeypatch, tmp_path):
    _patch_triage(
        monkeypatch,
        tmp_path,
        labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
    )
    result = runner.invoke(app, ["apply-preview", "--from-propose"])
    assert result.exit_code == 0
    assert "Apply preview: gated" in result.stdout
    assert "Target: sfai-crashloop" in result.stdout
    assert "explicit approval required" in result.stdout
    assert "confirm required" in result.stdout
    assert "rollback/verification required" in result.stdout
    assert "No action was taken" in result.stdout
    _assert_forbidden_absent(result.stdout)


def test_apply_preview_json_strict_and_safety_complete(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["apply-preview", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")
    assert payload["schema_version"] == 1
    assert payload["mode"] == "v2_apply_preview"
    assert payload["status"] == "no_action"
    assert payload["read_only"] is True
    for key in (
        "mutation_performed",
        "apply_executed",
        "mission_created",
        "plan_created",
        "remediation_executed",
        "rollback_executed",
        "cleanup_executed",
        "docker_compose_executed",
        "container_restarted",
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_execution",
        "model_called",
    ):
        assert payload[key] is False
        assert payload["safety"][key] is False
    assert payload["target"]["found"] is False
    assert payload["preview"]["execution_boundary"] == "not_crossed"


def test_ask_apply_preview_routes_and_mutation_phrases_refuse(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path)
    for prompt in (
        "apply preview",
        "what would applying this require?",
        "show apply gates",
    ):
        result = runner.invoke(app, ["ask", prompt])
        assert result.exit_code == 0
        assert "Read-only apply preview (deterministic ask routing):" in result.stdout
        assert "No action was taken" in result.stdout
        assert "Provider:" not in result.stdout
    for prompt in ("apply it", "execute it"):
        refused = runner.invoke(app, ["ask", prompt])
        assert refused.exit_code == 0
        assert "Refused" in refused.stdout
        assert "No action was taken" in refused.stdout
    mixed = runner.invoke(app, ["ask", "show me apply preview and restart compose"])
    assert mixed.exit_code == 0
    assert "Read-only apply preview" in mixed.stdout
    assert "Refused mutation part" in mixed.stdout
    assert "No action was taken" in mixed.stdout


def test_interactive_apply_preview_dispatch_json_target_help_and_refusal(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, target="shellforgeai")
    assert route_input("apply-preview").argv == ("apply-preview",)
    assert route_input("apply-preview --json").argv == ("apply-preview", "--json")
    assert route_input("apply-preview --target shellforgeai").argv == (
        "apply-preview",
        "--target",
        "shellforgeai",
    )
    out = repl._run_interactive_cli_dispatch(Console(file=StringIO()), ("apply-preview",))
    assert "Apply preview:" in out
    raw = repl._run_interactive_cli_dispatch(Console(file=StringIO()), ("apply-preview", "--json"))
    assert json.loads(raw)["mode"] == "v2_apply_preview"
    blocked = repl._run_interactive_cli_dispatch(
        Console(file=StringIO()), ("apply-preview", "--target", "shellforgeai")
    )
    assert "production target refused" in blocked
    assert "apply-preview [--brief|--json]" in repl.INTERACTIVE_HELP_TEXT
    assert route_input("apply it").name == "mutation_refused"


def test_apply_preview_forbidden_execution_primitives_not_used(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path)

    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"apply-preview must not run subprocesses: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("apply-preview must not call model provider")

    monkeypatch.setattr(cli_mod.subprocess, "run", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)
    before = {p.relative_to(tmp_path) for p in tmp_path.rglob("*")}
    result = runner.invoke(app, ["apply-preview", "--json"])
    after = {p.relative_to(tmp_path) for p in tmp_path.rglob("*")}
    assert result.exit_code == 0
    assert before == after
    payload = json.loads(result.stdout)
    for key in (
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
        assert payload[key] is False
    _assert_forbidden_absent(result.stdout)


def test_apply_preview_sources_contain_no_shell_true() -> None:
    for path in [
        Path("src/shellforgeai/cli.py"),
        Path("src/shellforgeai/interactive/commands.py"),
        Path("src/shellforgeai/interactive/repl.py"),
    ]:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    assert not (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ), path
