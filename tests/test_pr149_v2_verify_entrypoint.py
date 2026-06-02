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
            "status": "ok",
            "summary": {"containers_seen": 0, "suspects_ranked": 0, "critical": 0, "high": 0},
            "suspects": [],
            "warnings": [],
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
        "compose restart",
        "production restart",
    ):
        assert forbidden not in low


def test_verify_human_current_state_read_only_no_suspects(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["verify"])
    assert result.exit_code == 0
    assert "Verify: OK" in result.stdout
    assert "Status: no current Docker suspects" in result.stdout
    assert "First safe command:" in result.stdout
    assert "shellforgeai status --json" in result.stdout
    assert "No applied action was detected or assumed" in result.stdout
    assert "Read-only verification" in result.stdout
    assert "No action was taken" in result.stdout
    _assert_forbidden_absent(result.stdout)


def test_verify_brief_is_bounded_and_read_only(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["verify", "--brief"])
    assert result.exit_code == 0
    assert result.stdout.count("\n") <= 4
    assert "Verify: ok" in result.stdout
    assert "Safety: read-only" in result.stdout


def test_verify_target_missing_unknown_or_blocked_cleanly(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["verify", "--target", "missing"])
    assert result.exit_code == 0
    assert "Verify: unknown" in result.stdout
    assert "Target: missing" in result.stdout
    assert "target not found in current deterministic triage scene" in result.stdout
    assert "shellforgeai triage --json" in result.stdout
    assert "No action was taken" in result.stdout


def test_verify_production_target_read_only_and_no_mutation_suggestion(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, target="shellforgeai")
    result = runner.invoke(app, ["verify", "--target", "shellforgeai"])
    assert result.exit_code == 0
    assert "Target: shellforgeai" in result.stdout
    assert "production-like target" in result.stdout.lower()
    assert "read-only verification" in result.stdout.lower()
    _assert_forbidden_absent(result.stdout)


def test_verify_json_strict_and_safety_complete(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["verify", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")
    assert payload["schema_version"] == 1
    assert payload["mode"] == "v2_verify"
    assert payload["read_only"] is True
    assert payload["verification_type"] == "current_state"
    assert payload["applied_action_assumed"] is False
    assert payload["apply_receipt_present"] is False
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
    assert payload["evidence"]["suspects_ranked"] == 0


def test_verify_from_flags_do_not_assume_apply_or_proposal(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    for flag in ("--from-status", "--from-triage", "--from-propose", "--from-apply-preview"):
        result = runner.invoke(app, ["verify", flag])
        assert result.exit_code == 0
        assert "Verify:" in result.stdout
        assert "No applied action was detected or assumed" in result.stdout
        if flag == "--from-propose":
            assert "No proposal was assumed to have been applied" in result.stdout
        if flag == "--from-apply-preview":
            assert "No apply receipt was provided" in result.stdout
            assert "current observed state only" in result.stdout


def test_ask_verify_routes_and_does_not_claim_fixed(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    for prompt in ("verify status", "verify the system", "did anything improve?"):
        result = runner.invoke(app, ["ask", prompt])
        assert result.exit_code == 0
        assert "Read-only verify (deterministic ask routing):" in result.stdout
        assert "current-state verification" in result.stdout
        assert "No action was taken" in result.stdout
        assert "Provider:" not in result.stdout
    fixed = runner.invoke(app, ["ask", "is it fixed?"])
    assert fixed.exit_code == 0
    assert "Read-only verify" in fixed.stdout
    assert "No applied action was detected or assumed" in fixed.stdout
    assert "This command did not verify a completed remediation" in fixed.stdout


def test_ask_verify_mutation_phrases_refuse(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path)
    for prompt in ("verify and restart compose", "apply and verify"):
        result = runner.invoke(app, ["ask", prompt])
        assert result.exit_code == 0
        assert "Refused" in result.stdout
        assert "No action was taken" in result.stdout
        assert "did not execute" in result.stdout or "natural-language mutation" in result.stdout


def test_interactive_verify_dispatch_json_target_help_and_refusal(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, target="shellforgeai")
    assert route_input("verify").argv == ("verify",)
    assert route_input("verify --json").argv == ("verify", "--json")
    assert route_input("verify --target shellforgeai").argv == (
        "verify",
        "--target",
        "shellforgeai",
    )
    out = repl._run_interactive_cli_dispatch(Console(file=StringIO()), ("verify",))
    assert "Verify:" in out
    raw = repl._run_interactive_cli_dispatch(Console(file=StringIO()), ("verify", "--json"))
    assert json.loads(raw)["mode"] == "v2_verify"
    targeted = repl._run_interactive_cli_dispatch(
        Console(file=StringIO()), ("verify", "--target", "shellforgeai")
    )
    assert "read-only verification" in targeted.lower()
    assert "verify [--brief|--json]" in repl.INTERACTIVE_HELP_TEXT
    assert route_input("verify and restart").name == "mutation_refused"


def test_verify_forbidden_execution_primitives_not_used(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path)

    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"verify must not run subprocesses: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("verify must not call model provider")

    monkeypatch.setattr(cli_mod.subprocess, "run", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)
    before = {p.relative_to(tmp_path) for p in tmp_path.rglob("*")}
    result = runner.invoke(app, ["verify", "--json"])
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


def test_verify_sources_contain_no_shell_true() -> None:
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
