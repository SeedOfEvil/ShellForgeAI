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
                "classes": ["crashloop", "restart_storm"],
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


def test_propose_no_suspect_human_output_no_proposal_status_command_and_safety(
    monkeypatch, tmp_path: Path
) -> None:
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["propose"])
    assert result.exit_code == 0
    assert "Proposal: none needed" in result.stdout
    assert "Status: no current suspects" in result.stdout
    assert "shellforgeai status --json" in result.stdout
    assert "No plan was created" in result.stdout
    assert "No action was taken" in result.stdout


def test_propose_brief_is_bounded_and_read_only(monkeypatch, tmp_path: Path) -> None:
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["propose", "--brief"])
    assert result.exit_code == 0
    assert result.stdout.count("\n") <= 4
    assert "Proposal: none needed" in result.stdout
    assert "Target: none" in result.stdout
    assert "Safety: read-only; no plan or action executed" in result.stdout


def test_propose_json_is_strict_and_contains_required_safety(monkeypatch, tmp_path: Path) -> None:
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["propose", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")
    assert payload["mode"] == "v2_propose"
    assert payload["status"] == "ok"
    assert payload["proposal_status"] == "no_action_needed"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["plan_created"] is False
    assert payload["remediation_executed"] is False
    assert payload["first_safe_command"] == "shellforgeai status --json"
    for key in (
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


def test_propose_top_suspect_includes_target_evidence_eligibility_and_safe_command(
    monkeypatch, tmp_path: Path
) -> None:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["propose", "--from-triage"])
    assert result.exit_code == 0
    assert "Proposal: blocked" in result.stdout
    assert "Target: sfai-crashloop" in result.stdout
    assert "restart_count: 9" in result.stdout
    assert "Eligibility: blocked" in result.stdout
    assert "shellforgeai triage docker detail sfai-crashloop" in result.stdout
    assert "shellforgeai remediation eligibility --target sfai-crashloop --explain" in result.stdout
    assert "No action was taken" in result.stdout


def test_propose_target_known_and_unknown_are_controlled(monkeypatch, tmp_path: Path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    known = runner.invoke(app, ["propose", "--target", "sfai-crashloop"])
    assert known.exit_code == 0
    assert "Target: sfai-crashloop" in known.stdout
    assert "Eligibility:" in known.stdout

    unknown = runner.invoke(app, ["propose", "--target", "missing"])
    assert unknown.exit_code == 0
    assert "Proposal: blocked" in unknown.stdout
    assert "Target: missing" in unknown.stdout
    assert "target not found" in unknown.stdout.lower()
    assert "shellforgeai triage" in unknown.stdout
    assert "shellforgeai triage docker detail missing" in unknown.stdout


def test_propose_eligible_disposable_target_shows_plan_only_not_execute(
    monkeypatch, tmp_path: Path
) -> None:
    _patch_triage(
        monkeypatch,
        tmp_path,
        labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
    )
    result = runner.invoke(app, ["propose"])
    assert result.exit_code == 0
    assert "Proposal: available" in result.stdout
    assert "eligible for plan" in result.stdout
    assert (
        "shellforgeai remediation plan --target sfai-crashloop --scenario sfai-noisy-errors"
        in result.stdout
    )
    assert "Plan-only. Does not execute remediation." in result.stdout
    _assert_forbidden_absent(result.stdout)


def test_propose_production_target_blocks(monkeypatch, tmp_path: Path) -> None:
    _patch_triage(
        monkeypatch,
        tmp_path,
        target="shellforgeai",
        labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
    )
    result = runner.invoke(app, ["propose", "--target", "shellforgeai"])
    assert result.exit_code == 0
    assert "Proposal: blocked" in result.stdout
    assert "production target refused" in result.stdout


def test_ask_proposal_prompts_route_deterministically_and_include_no_action(
    monkeypatch, tmp_path: Path
) -> None:
    _patch_triage(monkeypatch, tmp_path)
    prompts = (
        "what would you propose?",
        "propose next step",
        "propose for the top suspect",
        "what would you propose for sfai-crashloop?",
    )
    for prompt in prompts:
        result = runner.invoke(app, ["ask", prompt])
        assert result.exit_code == 0
        assert "Read-only proposal (deterministic ask routing):" in result.stdout
        assert "Target: sfai-crashloop" in result.stdout
        assert "No action was taken" in result.stdout
        assert "Provider:" not in result.stdout


def test_ask_proposal_mutations_refuse_and_mixed_prompt_refuses_mutation_part(
    monkeypatch, tmp_path: Path
) -> None:
    _patch_triage(monkeypatch, tmp_path)
    for prompt in ("execute the proposal", "run the plan"):
        result = runner.invoke(app, ["ask", prompt])
        assert result.exit_code == 0
        assert "Refused" in result.stdout
        assert "No action was taken" in result.stdout
    mixed = runner.invoke(app, ["ask", "show me the proposal and restart it"])
    assert mixed.exit_code == 0
    assert "Read-only proposal" in mixed.stdout
    assert "Refused mutation part" in mixed.stdout
    assert "No action was taken" in mixed.stdout


def test_interactive_propose_dispatch_help_and_refusals(monkeypatch, tmp_path: Path) -> None:
    _patch_triage(monkeypatch, tmp_path)
    assert route_input("propose").argv == ("propose",)
    assert route_input("propose --json").argv == ("propose", "--json")
    assert route_input("propose --target sfai-crashloop").argv == (
        "propose",
        "--target",
        "sfai-crashloop",
    )
    out = repl._run_interactive_cli_dispatch(Console(file=StringIO()), ("propose",))
    assert "Target: sfai-crashloop" in out
    raw = repl._run_interactive_cli_dispatch(Console(file=StringIO()), ("propose", "--json"))
    assert json.loads(raw)["mode"] == "v2_propose"
    detail = repl._run_interactive_cli_dispatch(
        Console(file=StringIO()), ("propose", "--target", "sfai-crashloop")
    )
    assert "Target: sfai-crashloop" in detail
    assert "propose [--brief|--json]" in repl.INTERACTIVE_HELP_TEXT
    assert route_input("execute proposal").name == "mutation_refused"
    assert route_input("run the plan").name == "mutation_refused"


def test_propose_forbidden_outputs_and_safety_no_execution_or_model(
    monkeypatch, tmp_path: Path
) -> None:
    _patch_triage(monkeypatch, tmp_path)

    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"propose must not run subprocesses: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("propose must not call model provider")

    monkeypatch.setattr(cli_mod.subprocess, "run", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)
    before = {p.relative_to(tmp_path) for p in tmp_path.rglob("*")}
    result = runner.invoke(app, ["propose", "--json"])
    after = {p.relative_to(tmp_path) for p in tmp_path.rglob("*")}
    assert result.exit_code == 0
    assert before == after
    payload = json.loads(result.stdout)
    for key in (
        "plan_created",
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
