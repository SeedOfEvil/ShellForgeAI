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
            "safety": {},
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
            }
        ],
        "warnings": [],
        "safety": {},
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


_FORBIDDEN = (
    "remediation execute --confirm",
    "rollback-execute --confirm",
    "cleanup execute --confirm",
    "docker restart",
    "docker compose restart",
)


def _assert_forbidden_absent(text: str) -> None:
    low = text.lower()
    for forbidden in _FORBIDDEN:
        assert forbidden not in low


_SAFETY_FALSE_KEYS = (
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
)


# --------------------------------------------------------------------------- #
# CLI / human
# --------------------------------------------------------------------------- #
def test_verify_returns_current_state_verification(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["verify"])
    assert result.exit_code == 0
    assert "Verify: OK" in result.stdout
    assert "no current Docker suspects" in result.stdout
    assert "Read-only verification." in result.stdout
    _assert_forbidden_absent(result.stdout)


def test_verify_brief_is_bounded_and_read_only(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["verify", "--brief"])
    assert result.exit_code == 0
    assert result.stdout.count("\n") <= 5
    assert "Verify: OK" in result.stdout
    assert "Safety: read-only" in result.stdout
    _assert_forbidden_absent(result.stdout)


def test_verify_target_missing_returns_unknown_cleanly(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["verify", "--target", "sfai-crashloop-missing"])
    assert result.exit_code == 0
    assert "Verify: unknown" in result.stdout
    assert "Target: sfai-crashloop-missing" in result.stdout
    assert "target not found in current deterministic triage scene" in result.stdout
    assert "shellforgeai triage --json" in result.stdout
    _assert_forbidden_absent(result.stdout)


def test_verify_target_production_does_not_suggest_mutation(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, target="shellforgeai", labels={})
    result = runner.invoke(app, ["verify", "--target", "shellforgeai"])
    assert result.exit_code == 0
    assert "Target: shellforgeai" in result.stdout
    assert "restart" not in result.stdout.lower().replace("no restart", "")
    _assert_forbidden_absent(result.stdout)


def test_verify_human_includes_first_safe_command(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["verify"])
    assert "First safe command:" in result.stdout
    assert "shellforgeai status --json" in result.stdout


def test_verify_human_says_no_action_taken(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["verify"])
    assert "Read-only verification." in result.stdout
    assert "No apply, remediation, rollback, cleanup, Docker, or Compose action was executed." in (
        result.stdout
    )


# --------------------------------------------------------------------------- #
# CLI / JSON
# --------------------------------------------------------------------------- #
def test_verify_json_is_strict(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["verify", "--json"])
    assert result.exit_code == 0
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1


def test_verify_json_mode_is_v2_verify(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["verify", "--json"]).stdout)
    assert payload["mode"] == "v2_verify"
    assert payload["verification_type"] == "current_state"


def test_verify_json_read_only_true(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["verify", "--json"]).stdout)
    assert payload["read_only"] is True
    assert payload["safety"]["read_only"] is True


def test_verify_json_applied_action_assumed_false(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["verify", "--json"]).stdout)
    assert payload["applied_action_assumed"] is False
    assert payload["apply_receipt_present"] is False


def test_verify_json_safety_flags_all_false(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["verify", "--json"]).stdout)
    for key in _SAFETY_FALSE_KEYS:
        assert payload[key] is False, key
        assert payload["safety"][key] is False, key


def test_verify_json_with_suspects_is_degraded(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path)
    payload = json.loads(runner.invoke(app, ["verify", "--json"]).stdout)
    assert payload["status"] == "degraded"
    assert payload["evidence"]["suspects_ranked"] == 1
    assert payload["evidence"]["critical"] == 1
    for key in _SAFETY_FALSE_KEYS:
        assert payload[key] is False, key


# --------------------------------------------------------------------------- #
# From flags
# --------------------------------------------------------------------------- #
def test_verify_from_status_works(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["verify", "--from-status", "--json"]).stdout)
    assert payload["mode"] == "v2_verify"
    assert payload["evidence"]["source"] == "status"
    assert payload["applied_action_assumed"] is False


def test_verify_from_triage_works(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["verify", "--from-triage", "--json"]).stdout)
    assert payload["mode"] == "v2_verify"
    assert payload["evidence"]["source"] == "triage"


def test_verify_from_propose_does_not_assume_applied(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["verify", "--from-propose", "--json"])
    payload = json.loads(result.stdout)
    assert payload["applied_action_assumed"] is False
    assert payload["apply_receipt_present"] is False
    assert any("no proposal was applied" in f.lower() for f in payload["findings"])


def test_verify_from_apply_preview_does_not_assume_apply(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["verify", "--from-apply-preview"])
    assert result.exit_code == 0
    assert "No applied action was detected or assumed." in result.stdout
    assert "This command did not verify a completed remediation." in result.stdout
    payload = json.loads(runner.invoke(app, ["verify", "--from-apply-preview", "--json"]).stdout)
    assert payload["applied_action_assumed"] is False
    assert payload["apply_receipt_present"] is False
    assert any("apply receipt" in f.lower() for f in payload["findings"])


# --------------------------------------------------------------------------- #
# Ask routing
# --------------------------------------------------------------------------- #
def test_ask_verify_status_routes_to_verify(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["ask", "verify status"])
    assert result.exit_code == 0
    assert "Read-only verification (deterministic ask routing):" in result.stdout
    assert "Verify:" in result.stdout
    assert "Provider:" not in result.stdout


def test_ask_verify_the_system_routes_to_verify(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["ask", "verify the system"])
    assert result.exit_code == 0
    assert "Read-only verification (deterministic ask routing):" in result.stdout


def test_ask_did_anything_improve_routes_to_current_state_verify(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["ask", "did anything improve?"])
    assert result.exit_code == 0
    assert "Read-only verification (deterministic ask routing):" in result.stdout
    assert "Verify: OK" in result.stdout


def test_ask_is_it_fixed_does_not_claim_fixed_without_evidence(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["ask", "is it fixed?"])
    assert result.exit_code == 0
    assert "Read-only verification (deterministic ask routing):" in result.stdout
    # Active suspects present -> must not claim resolution.
    assert "fixed" not in result.stdout.lower()
    assert "Verify: degraded" in result.stdout


def test_ask_verify_and_restart_compose_refuses_mutation(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["ask", "verify status and restart compose"])
    assert result.exit_code == 0
    low = result.stdout.lower()
    assert "refus" in low
    assert "no action was taken" in low
    _assert_forbidden_absent(result.stdout)


def test_ask_apply_and_verify_refuses_mutation(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["ask", "apply and verify"])
    assert result.exit_code == 0
    low = result.stdout.lower()
    assert "refus" in low
    assert "no action was taken" in low
    _assert_forbidden_absent(result.stdout)


# --------------------------------------------------------------------------- #
# Interactive
# --------------------------------------------------------------------------- #
def test_interactive_verify_dispatch(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    assert route_input("verify").argv == ("verify",)
    assert route_input("verify --brief").argv == ("verify", "--brief")
    assert route_input("verify --from-apply-preview").argv == (
        "verify",
        "--from-apply-preview",
    )
    out = repl._run_interactive_cli_dispatch(Console(file=StringIO()), ("verify",))
    assert "Verify:" in out


def test_interactive_verify_json_emits_strict_json(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, empty=True)
    assert route_input("verify --json").argv == ("verify", "--json")
    raw = repl._run_interactive_cli_dispatch(Console(file=StringIO()), ("verify", "--json"))
    payload = json.loads(raw)
    assert payload["mode"] == "v2_verify"
    assert payload["read_only"] is True


def test_interactive_verify_target_remains_read_only(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path, target="shellforgeai", labels={})
    assert route_input("verify --target shellforgeai").argv == (
        "verify",
        "--target",
        "shellforgeai",
    )
    out = repl._run_interactive_cli_dispatch(
        Console(file=StringIO()), ("verify", "--target", "shellforgeai")
    )
    assert "Target: shellforgeai" in out
    _assert_forbidden_absent(out)


def test_interactive_verify_and_restart_refuses(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path)
    assert route_input("verify and restart").name == "mutation_refused"
    assert route_input("apply and verify").name == "mutation_refused"


def test_interactive_help_includes_verify():
    assert "verify [--brief|--json]" in repl.INTERACTIVE_HELP_TEXT


# --------------------------------------------------------------------------- #
# Safety
# --------------------------------------------------------------------------- #
def test_verify_does_not_run_subprocess_or_model(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path)

    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"verify must not run subprocesses: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("verify must not call model provider")

    monkeypatch.setattr(cli_mod.subprocess, "run", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)
    before = {p.relative_to(tmp_path) for p in tmp_path.rglob("*")}
    for argv in (["verify"], ["verify", "--json"], ["verify", "--from-apply-preview"]):
        result = runner.invoke(app, argv)
        assert result.exit_code == 0
    after = {p.relative_to(tmp_path) for p in tmp_path.rglob("*")}
    assert before == after


def test_verify_json_never_marks_execution(monkeypatch, tmp_path):
    _patch_triage(monkeypatch, tmp_path)
    for argv in (
        ["verify", "--json"],
        ["verify", "--target", "sfai-crashloop", "--json"],
        ["verify", "--from-apply-preview", "--json"],
    ):
        payload = json.loads(runner.invoke(app, argv).stdout)
        for key in _SAFETY_FALSE_KEYS:
            assert payload[key] is False, (argv, key)
            assert payload["safety"][key] is False, (argv, key)


def test_verify_sources_contain_no_shell_true():
    for path in (
        Path("src/shellforgeai/cli.py"),
        Path("src/shellforgeai/interactive/commands.py"),
        Path("src/shellforgeai/interactive/repl.py"),
    ):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    assert not (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ), path
