"""PR190 top-level ``ask`` command-module extraction guardrails.

These tests prove the deterministic ``ask`` command is wired from
``shellforgeai.commands.ask`` while preserving the exact command surface,
deterministic read-only routing, mutation/freeform refusal wording,
no-action-taken output, and the no-execution safety boundary. The
deterministic ``_handle_*`` routing/refusal helpers stay in
``shellforgeai.cli`` (interactive mode and other surfaces share them), and
governed recipe execution, recovery execution, and interactive mode must not
move in this PR.

Safety posture enforced here: no cleanup, remediation, rollback, recovery,
Docker/Compose mutation, container/production restart, shell=True,
arbitrary/natural-language execution, or model call for deterministic routes.
No Docker daemon is required and real ``/data`` is never touched.
"""

from __future__ import annotations

import ast
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app

runner = CliRunner()

MODULE_PATH = Path("src/shellforgeai/commands/ask.py")
CLI_PATH = Path("src/shellforgeai/cli.py")

READ_ONLY_PHRASES = (
    "quick status",
    "show docker triage",
    "show ops report",
    "audit recipe receipts",
    "check receipt integrity",
    "explain receipt integrity findings",
    "create receipt audit bundle",
)

REFUSAL_PHRASES = (
    "Clean up docker and restart compose to fix it",
    "restart compose",
    "run docker restart",
    "rollback now",
    "recover it again",
    "rerun receipt",
    "fix corrupt receipts",
    "delete bad artifacts",
    "repair checksum mismatch",
    "restart from the receipt",
    "execute the restart recipe",
    "apply the fix",
)

MIXED_PHRASES = (
    "show rollback preview and then rollback",
    "show recovery command and run it",
    "bundle audit then restart it",
    "explain safety drift and recover now",
)

FORBIDDEN_OUTPUT_TOKENS = (
    "cleanup executed",
    "remediation executed",
    "rollback executed",
    "recovery executed",
    "container restarted successfully",
    "compose restarted",
    "production restart executed",
)


def _fake_scene() -> dict:
    return {"containers": [{"name": "sfai-crashloop", "labels": {}}]}


def _fake_ranked(scene: dict) -> dict:
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


def _patch_deterministic(monkeypatch, tmp_path: Path) -> None:
    """Deterministic scene/self-test fixtures; no Docker daemon required."""

    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.core.triage_ranking.collect_scene", _fake_scene)
    monkeypatch.setattr("shellforgeai.core.triage_ranking.rank_scene", _fake_ranked)
    monkeypatch.setattr(
        "shellforgeai.core.self_test.run_self_test_commands",
        lambda profile, include_skipped=False: {"status": "ok", "warnings": []},
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.build_remediation_audit_payload",
        lambda data_dir, latest_only=True: {"status": "ok"},
    )


def _forbid_execution(monkeypatch) -> None:
    """Fail loudly if ask runs any subprocess, model call, or governed execution."""

    import subprocess as subprocess_mod

    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"deterministic ask must not run subprocesses: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("deterministic ask must not build or call a model provider")

    def fail_execute(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("ask must never invoke governed execution")

    monkeypatch.setattr(subprocess_mod, "run", fail_run)
    monkeypatch.setattr(subprocess_mod, "Popen", fail_run)
    monkeypatch.setattr(subprocess_mod, "check_output", fail_run)
    monkeypatch.setattr(subprocess_mod, "call", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)
    monkeypatch.setattr(cli_mod, "execute_disposable_restart", fail_execute, raising=False)
    monkeypatch.setattr(cli_mod, "execute_receipt_recovery", fail_execute, raising=False)
    from shellforgeai.commands import receipt_recovery_execute as recovery_execute_commands
    from shellforgeai.core import recipe_execution, recipe_receipt_recovery

    monkeypatch.setattr(recipe_execution, "execute_disposable_restart", fail_execute)
    monkeypatch.setattr(recipe_receipt_recovery, "execute_receipt_recovery", fail_execute)
    monkeypatch.setattr(recovery_execute_commands, "execute_receipt_recovery", fail_execute)


def _deterministic_ask(monkeypatch, tmp_path: Path, phrase: str):
    _patch_deterministic(monkeypatch, tmp_path)
    _forbid_execution(monkeypatch)
    return runner.invoke(app, ["ask", phrase])


def _assert_no_mutation_claims(stdout: str) -> None:
    low = stdout.lower()
    for token in FORBIDDEN_OUTPUT_TOKENS:
        assert token not in low, token


# ---------------------------------------------------------------------------
# Module split / registration
# ---------------------------------------------------------------------------


def test_ask_module_exists_and_cli_wires_registration() -> None:
    assert MODULE_PATH.exists()
    module_source = MODULE_PATH.read_text(encoding="utf-8")
    cli_source = CLI_PATH.read_text(encoding="utf-8")
    assert "def register(app: typer.Typer)" in module_source
    assert "def ask(" in module_source
    assert "from shellforgeai.commands import ask as ask_commands" in cli_source
    assert "ask_commands.register(app)" in cli_source


def test_cli_no_longer_owns_ask_command_body() -> None:
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    assert "ask" not in function_names


def test_deterministic_routing_helpers_remain_in_cli() -> None:
    """The shared deterministic routing/refusal helpers must NOT move in PR190."""

    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    for kept in (
        "_handle_mutation_refusal_ask",
        "_handle_receipt_recovery_ask",
        "_handle_receipt_rollback_preview_ask",
        "_handle_receipt_audit_ask",
        "_handle_recipe_registry_ask",
        "_handle_v2_triage_ask",
        "_handle_command_help_ask",
        "_is_status_ask",
        "interactive",
        "recipes_execute",
    ):
        assert kept in function_names, kept


def test_ask_module_does_not_import_execution_surfaces() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    forbidden = (
        "execute_disposable_restart",
        "execute_receipt_recovery",
        "subprocess",
        "shell=True",
        "os.system",
        "docker compose restart",
        "docker restart ",
    )
    for token in forbidden:
        assert token not in source, token


def test_ask_help_exits_zero_and_preserves_existing_options() -> None:
    result = runner.invoke(app, ["ask", "--help"])
    assert result.exit_code == 0, result.output
    for token in ("question", "--context", "--full-context", "--raw", "--no-evidence", "--since"):
        assert token in result.stdout, token


# ---------------------------------------------------------------------------
# Deterministic read-only ask routing
# ---------------------------------------------------------------------------


def test_status_ask_routes_read_only_without_model(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "quick status")
    assert result.exit_code == 0, result.output
    assert "Read-only status (deterministic ask routing):" in result.stdout
    assert "Safety: Read-only. No mutation executed." in result.stdout
    assert "First safe command:" in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_triage_ask_routes_read_only_without_model(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "show docker triage")
    assert result.exit_code == 0, result.output
    assert "Read-only Docker triage ranking" in result.stdout
    assert "mutation_performed: false" in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_ops_report_ask_routes_read_only_without_model(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "show ops report")
    assert result.exit_code == 0, result.output
    assert "Read-only ops report (deterministic ask routing):" in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_receipt_audit_ask_routes_read_only_without_model(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "audit recipe receipts")
    assert result.exit_code == 0, result.output
    assert "Read-only recipe receipt audit guidance (deterministic ask routing):" in result.stdout
    assert "shellforgeai recipes receipt audit" in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_receipt_integrity_ask_routes_read_only_without_model(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "check receipt integrity")
    assert result.exit_code == 0, result.output
    assert "deterministic ask routing" in result.stdout
    assert "shellforgeai recipes receipt integrity" in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_receipt_explain_ask_routes_read_only_without_model(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "explain receipt integrity findings")
    assert result.exit_code == 0, result.output
    assert "deterministic ask routing" in result.stdout
    assert "shellforgeai recipes receipt explain" in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_audit_bundle_ask_routes_read_only_without_model(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "create receipt audit bundle")
    assert result.exit_code == 0, result.output
    assert "deterministic ask routing" in result.stdout
    assert "shellforgeai recipes receipt audit-bundle" in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_all_read_only_phrases_route_without_any_execution(monkeypatch, tmp_path: Path) -> None:
    _patch_deterministic(monkeypatch, tmp_path)
    _forbid_execution(monkeypatch)
    for phrase in READ_ONLY_PHRASES:
        result = runner.invoke(app, ["ask", phrase])
        assert result.exit_code == 0, (phrase, result.output)
        _assert_no_mutation_claims(result.stdout)


# ---------------------------------------------------------------------------
# Mutation / freeform refusal
# ---------------------------------------------------------------------------


def test_cleanup_restart_compose_ask_is_refused(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(
        monkeypatch, tmp_path, "Clean up docker and restart compose to fix it"
    )
    assert result.exit_code == 0, result.output
    assert "Refus" in result.stdout
    assert "No restart" in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_restart_compose_ask_is_refused(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "restart compose")
    assert result.exit_code == 0, result.output
    assert "Refusing natural-language Compose mutation" in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_run_docker_restart_ask_is_refused(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "run docker restart")
    assert result.exit_code == 0, result.output
    assert "Refused: natural-language mutation is not allowed." in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_rollback_now_ask_is_refused(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "rollback now")
    assert result.exit_code == 0, result.output
    assert "Refused" in result.stdout
    assert "--confirm" in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_recover_again_ask_is_refused(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "recover it again")
    assert result.exit_code == 0, result.output
    assert "Refused" in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_rerun_receipt_ask_is_refused_with_no_action_taken(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "rerun receipt")
    assert result.exit_code == 0, result.output
    assert "Refused" in result.stdout
    assert "No action was taken." in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_fix_corrupt_receipts_ask_is_refused(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "fix corrupt receipts")
    assert result.exit_code == 0, result.output
    assert "Refused: natural-language mutation is not allowed for receipts." in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_delete_bad_artifacts_ask_is_refused(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "delete bad artifacts")
    assert result.exit_code == 0, result.output
    assert "Refused: natural-language mutation is not allowed for receipts." in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_execute_restart_recipe_ask_refuses_natural_language_execution(
    monkeypatch, tmp_path: Path
) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "execute the restart recipe")
    assert result.exit_code == 0, result.output
    assert "Recipe execution from natural" in result.stdout
    assert "No action was taken." in result.stdout
    assert "No recipe was executed." in result.stdout
    assert "No container was restarted." in result.stdout


def test_mixed_recovery_phrase_refuses_execution_part(monkeypatch, tmp_path: Path) -> None:
    result = _deterministic_ask(monkeypatch, tmp_path, "show recovery command and run it")
    assert result.exit_code == 0, result.output
    assert "deterministic ask routing" in result.stdout
    assert "recovery-execute <receipt_id> --confirm" in result.stdout
    _assert_no_mutation_claims(result.stdout)


def test_all_refusal_and_mixed_phrases_refuse_without_any_execution(
    monkeypatch, tmp_path: Path
) -> None:
    _patch_deterministic(monkeypatch, tmp_path)
    _forbid_execution(monkeypatch)
    for phrase in REFUSAL_PHRASES + MIXED_PHRASES:
        result = runner.invoke(app, ["ask", phrase])
        assert result.exit_code == 0, (phrase, result.output)
        _assert_no_mutation_claims(result.stdout)


# ---------------------------------------------------------------------------
# Safety: no execution of any kind, no artifact mutation
# ---------------------------------------------------------------------------


def test_deterministic_ask_does_not_use_model_subprocess_or_shell(
    monkeypatch, tmp_path: Path
) -> None:
    """Every deterministic phrase must complete with subprocess, shell, model,
    and governed execution all blocked — proving no cleanup, remediation,
    rollback, recovery, Docker/Compose, restart, or arbitrary execution."""

    _patch_deterministic(monkeypatch, tmp_path)
    _forbid_execution(monkeypatch)
    for phrase in READ_ONLY_PHRASES + REFUSAL_PHRASES + MIXED_PHRASES:
        result = runner.invoke(app, ["ask", phrase])
        assert result.exit_code == 0, (phrase, result.output)


def test_deterministic_ask_does_not_create_execution_artifacts(monkeypatch, tmp_path: Path) -> None:
    _patch_deterministic(monkeypatch, tmp_path)
    _forbid_execution(monkeypatch)
    for phrase in ("rollback now", "execute the restart recipe", "fix corrupt receipts"):
        result = runner.invoke(app, ["ask", phrase])
        assert result.exit_code == 0, (phrase, result.output)
    for forbidden_root in ("cleanup", "remediation_receipts", "recipe_receipts", "missions"):
        assert not (tmp_path / forbidden_root).exists(), forbidden_root


def test_evidence_backed_ask_path_remains_read_only(monkeypatch, tmp_path: Path) -> None:
    """'what is the docker status?' is evidence-backed (model path) today; the
    extraction must keep it read-only: cli-level diagnose/provider hooks are
    used (monkeypatch-compatible) and no subprocess/mutation happens."""

    import platform as platform_mod
    import subprocess as subprocess_mod

    platform_mod.platform()  # warm the stdlib cache (first call may exec uname)
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))

    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"ask must not run subprocesses: {cmd!r}")

    monkeypatch.setattr(subprocess_mod, "run", fail_run)
    monkeypatch.setattr(subprocess_mod, "Popen", fail_run)

    diagnose_calls: list[str] = []

    def fake_diagnose(runtime, target, online=False, since="30m"):  # noqa: ANN001
        diagnose_calls.append(str(target))
        raise RuntimeError("evidence collection unavailable in test")

    class _Resp:
        ok = True
        text = "deterministic test answer"
        provider = "test"
        model = "test-model"
        raw: dict = {}
        usage: dict = {}

    class _Provider:
        def complete(self, request):  # noqa: ANN001
            return _Resp()

    monkeypatch.setattr(cli_mod, "diagnose_target", fake_diagnose)
    monkeypatch.setattr(cli_mod, "build_provider", lambda settings: _Provider())

    result = runner.invoke(app, ["ask", "what is the docker status?"])
    assert result.exit_code == 0, result.output
    assert diagnose_calls, "evidence-backed route must use cli.diagnose_target"
    assert "deterministic test answer" in result.stdout
    _assert_no_mutation_claims(result.stdout)
