"""PR135: deterministic report command-help routing.

Generic report/status command-help prompts should return copy/paste-correct
``shellforgeai ops report`` guidance without calling the model, executing
commands, or suggesting stale/mutating commands.
"""

from __future__ import annotations

import builtins
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.interactive import repl

runner = CliRunner()

_FORBIDDEN_SUGGESTIONS = (
    "/report",
    "shellforgeai diagnose",
    "shellforgeai diagnose docker --target",
    "shellforgeai diagnose logs --target",
    "docker restart",
    "docker compose restart",
    "docker compose up",
    "docker compose down",
    "docker system prune",
    "docker volume prune",
    "cleanup execute",
    "remediation execute --confirm",
    "rollback-execute --confirm",
)


def _fail_provider(*_args, **_kwargs):  # noqa: ANN002, ANN003
    raise AssertionError("model/Codex path must not be called for report command-help")


def _ask(prompt: str, monkeypatch, tmp_path: Path) -> str:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(cli_mod, "build_provider", _fail_provider)
    result = runner.invoke(app, ["ask", prompt])
    assert result.exit_code == 0, result.stdout
    return result.stdout


def _assert_common_report_guidance(out: str) -> None:
    assert "No action was taken." in out
    assert "shellforgeai ops report" in out
    assert "First safe command:" in out


def _assert_no_forbidden_suggestions(out: str) -> None:
    low = out.lower()
    for forbidden in _FORBIDDEN_SUGGESTIONS:
        assert forbidden not in low, f"forbidden suggestion leaked: {forbidden}"


def test_generic_report_command_help_uses_canonical_ops_report(monkeypatch, tmp_path) -> None:
    out = _ask("what command would show the report?", monkeypatch, tmp_path)
    _assert_common_report_guidance(out)
    assert "Use:" in out
    assert "shellforgeai ops report --json" in out
    assert "shellforgeai ops report --save" in out
    _assert_no_forbidden_suggestions(out)


def test_report_command_phrase_routes_deterministically(monkeypatch, tmp_path) -> None:
    out = _ask("show me the report command", monkeypatch, tmp_path)
    _assert_common_report_guidance(out)
    _assert_no_forbidden_suggestions(out)


def test_status_command_phrase_routes_to_ops_report(monkeypatch, tmp_path) -> None:
    out = _ask("what command shows status?", monkeypatch, tmp_path)
    _assert_common_report_guidance(out)
    assert "shellforgeai ops report" in out or "shellforgeai ops report --brief" in out
    _assert_no_forbidden_suggestions(out)


def test_save_report_help_suggests_save_and_artifact_boundary(monkeypatch, tmp_path) -> None:
    out = _ask("how do I save the report?", monkeypatch, tmp_path)
    assert "No action was taken." in out
    assert "shellforgeai ops report --save" in out
    assert "shellforgeai ops report validate <report_id_or_path>" in out
    assert "ShellForgeAI-owned artifact" in out
    assert "No Docker/system mutation" in out
    assert "First safe command:" in out
    _assert_no_forbidden_suggestions(out)


def test_export_report_help_suggests_save_export_validate_flow(monkeypatch, tmp_path) -> None:
    out = _ask("how do I export the report?", monkeypatch, tmp_path)
    assert "No action was taken." in out
    assert "Save a report first" in out
    assert "shellforgeai ops report --save" in out
    assert "shellforgeai ops report export <report_id>" in out
    assert "shellforgeai ops report export-validate <export_id>" in out
    assert "ShellForgeAI-owned artifact" in out
    assert "No Docker/system mutation" in out
    _assert_no_forbidden_suggestions(out)


def test_compare_report_help_suggests_history_and_compare(monkeypatch, tmp_path) -> None:
    out = _ask("how do I compare reports?", monkeypatch, tmp_path)
    assert "No action was taken." in out
    assert "shellforgeai ops report history --limit 5" in out
    assert "shellforgeai ops report compare-latest" in out
    assert "shellforgeai ops report compare <before_report> <after_report>" in out
    assert "First safe command:" in out
    _assert_no_forbidden_suggestions(out)


def test_report_history_help_suggests_history_limit(monkeypatch, tmp_path) -> None:
    out = _ask("what command shows report history?", monkeypatch, tmp_path)
    assert "No action was taken." in out
    assert "shellforgeai ops report history --limit 5" in out
    assert "First safe command:" in out
    _assert_no_forbidden_suggestions(out)


def test_show_me_report_history_does_not_use_model_or_shell_history(monkeypatch, tmp_path) -> None:
    out = _ask("show me report history", monkeypatch, tmp_path)
    assert "No action was taken." in out
    assert "shellforgeai ops report history --limit 5" in out
    assert "Provider:" not in out
    assert "Model:" not in out
    assert "history | tail" not in out
    assert "  history\n" not in out
    _assert_no_forbidden_suggestions(out)


def test_report_history_command_does_not_suggest_shell_history(monkeypatch, tmp_path) -> None:
    out = _ask("report history command", monkeypatch, tmp_path)
    assert "No action was taken." in out
    assert "shellforgeai ops report history --limit 5" in out
    assert "Provider:" not in out
    assert "Model:" not in out
    assert "history | tail" not in out
    assert "  history\n" not in out
    _assert_no_forbidden_suggestions(out)


def test_report_help_outputs_never_suggest_stale_or_mutating_commands(
    monkeypatch, tmp_path
) -> None:
    prompts = (
        "what command would show the report?",
        "show me the report command",
        "what command shows status?",
        "how do I save the report?",
        "how do I export the report?",
        "how do I compare reports?",
        "what command shows report history?",
    )
    for prompt in prompts:
        _assert_no_forbidden_suggestions(_ask(prompt, monkeypatch, tmp_path))


def test_mutation_plus_report_restart_refuses(monkeypatch, tmp_path) -> None:
    out = _ask("restart and show me the report", monkeypatch, tmp_path).lower()
    assert "refus" in out
    assert "no action was taken" in out or "no restart" in out
    assert "shellforgeai ops report" in out
    assert "docker restart" not in out


def test_status_report_and_restart_compose_splits_report_and_refusal(monkeypatch, tmp_path) -> None:
    out = _ask("status report and restart compose", monkeypatch, tmp_path)
    low = out.lower()
    assert "shellforgeai ops report" in out
    assert "No action was taken." in out
    assert "refus" in low
    assert "Provider:" not in out
    assert "Model:" not in out
    assert "docker compose restart" not in low


def test_command_help_report_and_restart_compose_is_not_plan_guidance(
    monkeypatch, tmp_path
) -> None:
    out = _ask("what command would show report and restart compose?", monkeypatch, tmp_path)
    low = out.lower()
    assert "shellforgeai ops report" in out
    assert "No action was taken." in out
    assert "refus" in low
    assert "remediation plan" not in low
    assert "--execute --confirm" not in low
    assert "docker compose restart" not in low


def test_mutation_plus_report_cleanup_refuses(monkeypatch, tmp_path) -> None:
    out = _ask("clean up docker and generate a report", monkeypatch, tmp_path).lower()
    assert "refus" in out
    assert "no action was taken" in out or "no restart" in out or "will not execute" in out
    assert "shellforgeai ops report" in out
    assert "cleanup execute" not in out


class _FakeProviderRepl:
    def complete(self, request):  # noqa: ANN001
        raise AssertionError("model must not be called for report command-help/refusal")

    def doctor(self):
        return {"provider": "fake", "ready": "yes", "auth_cache_present": False}


def _drive_repl(monkeypatch, tmp_path: Path, inputs: list[str]) -> str:  # noqa: ANN001
    printed: list[str] = []

    class _Cap:
        def print(self, *args, **kwargs):  # noqa: ANN002, ANN003
            printed.append(" ".join(str(a) for a in args))

        def print_json(self, *args, **kwargs):  # noqa: ANN002, ANN003
            printed.append(str(kwargs.get("data", args)))

        def clear(self):
            printed.append("<clear>")

        def status(self, *args, **kwargs):  # noqa: ANN002, ANN003
            class _Ctx:
                def __enter__(self_inner):
                    return self_inner

                def __exit__(self_inner, *exc):
                    return False

            return _Ctx()

    monkeypatch.setattr(repl, "Console", lambda *a, **k: _Cap())
    monkeypatch.setattr(repl, "_confirm_workspace", lambda *a, **k: True)
    monkeypatch.setattr(repl, "build_provider", lambda *a, **k: _FakeProviderRepl())
    monkeypatch.setattr(repl.WorkspaceTrustStore, "is_trusted", lambda self, p: True)
    monkeypatch.setattr(
        repl,
        "StreamRenderer",
        lambda *a, **k: SimpleNamespace(render=lambda text, *_: printed.append(str(text))),
    )

    seq = iter(inputs)

    def _fake_input(prompt: str = "") -> str:
        try:
            return next(seq)
        except StopIteration as exc:
            raise EOFError from exc

    monkeypatch.setattr(builtins, "input", _fake_input)

    runtime = SimpleNamespace(
        session=SimpleNamespace(
            session_id="sf_pr135_fixture",
            data_dir=tmp_path / "data",
            artifact_dir=tmp_path / "data" / "artifacts" / "sf_pr135_fixture",
            mode="inspect",
        ),
        profile=SimpleNamespace(name="standard", online_allowed=False, allow_shell_raw=False),
        settings=SimpleNamespace(
            model=SimpleNamespace(provider="fake", model="fake", timeout_seconds=30),
        ),
    )
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    repl.start_interactive(runtime, no_trust_cache=True)
    return "\n".join(printed)


def test_interactive_report_command_help_is_deterministic(monkeypatch, tmp_path) -> None:
    out = _drive_repl(monkeypatch, tmp_path, ["what command would show the report?", "/exit"])
    _assert_common_report_guidance(out)
    _assert_no_forbidden_suggestions(out)


def test_interactive_status_command_help_is_deterministic(monkeypatch, tmp_path) -> None:
    out = _drive_repl(monkeypatch, tmp_path, ["show me the status command", "/exit"])
    _assert_common_report_guidance(out)
    _assert_no_forbidden_suggestions(out)


def test_interactive_show_me_report_history_is_deterministic(monkeypatch, tmp_path) -> None:
    out = _drive_repl(monkeypatch, tmp_path, ["show me report history", "/exit"])
    assert "No action was taken." in out
    assert "shellforgeai ops report history --limit 5" in out
    _assert_no_forbidden_suggestions(out)


def test_interactive_report_history_command_is_deterministic(monkeypatch, tmp_path) -> None:
    out = _drive_repl(monkeypatch, tmp_path, ["report history command", "/exit"])
    assert "No action was taken." in out
    assert "shellforgeai ops report history --limit 5" in out
    assert "history | tail" not in out
    _assert_no_forbidden_suggestions(out)


def test_interactive_mutation_plus_report_refuses(monkeypatch, tmp_path) -> None:
    out = _drive_repl(monkeypatch, tmp_path, ["restart and show me the report", "/exit"]).lower()
    assert "refus" in out or "no command was executed" in out
    assert "no action was taken" in out or "no command was executed" in out


def test_interactive_report_command_and_restart_compose_splits_intent(
    monkeypatch, tmp_path
) -> None:
    out = _drive_repl(
        monkeypatch, tmp_path, ["what command would show report and restart compose?", "/exit"]
    ).lower()
    assert "shellforgeai ops report" in out
    assert "refus" in out
    assert "no action was taken" in out
    assert "remediation plan" not in out
    assert "docker compose restart" not in out
