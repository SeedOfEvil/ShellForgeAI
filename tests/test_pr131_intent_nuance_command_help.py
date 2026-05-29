"""PR131: intent nuance for command-help vs mutation requests.

ShellForgeAI must distinguish "what command would I run / how would I propose
this?" (read-only or plan-only guidance) from "do it / execute / restart"
(mutation, refused). These tests cover the deterministic classifier, the
``ask`` command-help/refusal rendering, and interactive-mode parity. They stay
offline and non-mutating: the model provider is stubbed to fail loudly so a
command-help path that accidentally calls the model is caught.
"""

from __future__ import annotations

import builtins
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.core.intent_nuance import (
    AMBIGUOUS_EXECUTE,
    CLEANUP_REVIEW_HELP,
    COMMAND_HELP,
    MUTATION_REQUEST,
    NONE,
    PLAN_HELP,
    classify_intent_nuance,
)
from shellforgeai.interactive import repl

runner = CliRunner()

# Strings that must never appear as *suggested* commands in command-help output.
_FORBIDDEN_SUGGESTIONS = (
    "remediation execute --execute --confirm",
    "rollback execute --execute --confirm",
    "rollback-execute --confirm",
    "cleanup execute --confirm",
    "audit cleanup execute",
    "docker restart",
    "docker compose restart",
    "docker system prune",
    "docker volume prune",
    "--execute --confirm",
)


def _fail_provider(*_a, **_k):
    raise AssertionError("model/Codex path must not be called for command-help/refusal")


def _ask(prompt: str, monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(cli_mod, "build_provider", _fail_provider)
    result = runner.invoke(app, ["ask", prompt])
    assert result.exit_code == 0, result.stdout
    return result.stdout


# --------------------------------------------------------------------------
# Classifier unit coverage
# --------------------------------------------------------------------------
def test_command_help_frame_overrides_embedded_mutation_verb() -> None:
    assert classify_intent_nuance("what command would restart this?").category == PLAN_HELP
    assert classify_intent_nuance("restart this").category == MUTATION_REQUEST


def test_classifier_categories() -> None:
    assert classify_intent_nuance("show me the command to inspect sfai-crashloop").category == (
        COMMAND_HELP
    )
    assert classify_intent_nuance("how do I review cleanup safely?").category == CLEANUP_REVIEW_HELP
    assert classify_intent_nuance("how do I check if sfai-crashloop is eligible?").category == (
        COMMAND_HELP
    )
    assert classify_intent_nuance("run that").category == AMBIGUOUS_EXECUTE
    assert classify_intent_nuance("do it now").category == AMBIGUOUS_EXECUTE
    assert classify_intent_nuance("execute the remediation plan").category == MUTATION_REQUEST
    # General non-domain guidance and read-only status phrasings route normally.
    assert classify_intent_nuance("how do I check disk space?").category == NONE
    assert classify_intent_nuance("show me the ops report").category == NONE
    # PR124 follow-up confirmations are not ambiguous-execute mutations.
    assert classify_intent_nuance("do it").category == NONE
    assert classify_intent_nuance("run the remediation plan").category == MUTATION_REQUEST


# --------------------------------------------------------------------------
# ask: command-help allowed (tests 1-6)
# --------------------------------------------------------------------------
def test_command_help_restart_returns_guidance_not_refusal_only(monkeypatch, tmp_path) -> None:
    out = _ask("what command would restart sfai-crashloop?", monkeypatch, tmp_path)
    assert "No action was taken." in out
    assert "shellforgeai remediation plan --target sfai-crashloop" in out
    assert "Plan-only; does not execute remediation." in out


def test_command_help_inspect_returns_triage_detail(monkeypatch, tmp_path) -> None:
    out = _ask("show me the command to inspect sfai-crashloop", monkeypatch, tmp_path)
    assert "shellforgeai triage docker detail sfai-crashloop" in out
    assert "No action was taken." in out


def test_command_help_propose_remediation_returns_plan_only(monkeypatch, tmp_path) -> None:
    out = _ask("how would I propose remediation for sfai-crashloop?", monkeypatch, tmp_path)
    assert "shellforgeai remediation plan --target sfai-crashloop --scenario" in out
    assert "Plan-only; does not execute remediation." in out
    assert "validate, preflight, and explicit confirmation" in out


def test_command_help_cleanup_returns_review(monkeypatch, tmp_path) -> None:
    out = _ask("how do I review cleanup safely?", monkeypatch, tmp_path)
    assert "shellforgeai audit cleanup review" in out
    # cleanup execute must not be the first/any suggested command
    assert "cleanup execute" not in out.lower()


def test_command_help_eligibility_and_report(monkeypatch, tmp_path) -> None:
    elig = _ask("how do I check if sfai-crashloop is eligible?", monkeypatch, tmp_path)
    assert "shellforgeai remediation eligibility --target sfai-crashloop --explain" in elig
    report = _ask("what command would export the latest ops report?", monkeypatch, tmp_path)
    assert "shellforgeai ops report" in report
    # console line-wrapping can split "IDs"; assert the stable fragment.
    assert "do not invent" in report


def test_command_help_says_no_action_taken(monkeypatch, tmp_path) -> None:
    for prompt in (
        "show me the command to inspect sfai-crashloop",
        "what command would propose a restart for sfai-crashloop?",
        "how do I review cleanup safely?",
    ):
        out = _ask(prompt, monkeypatch, tmp_path)
        assert "No action was taken." in out


# --------------------------------------------------------------------------
# ask: mutation refused (tests 7-13)
# --------------------------------------------------------------------------
def test_mutation_requests_refuse(monkeypatch, tmp_path) -> None:
    prompts = [
        "restart sfai-crashloop",
        "restart shellforgeai",
        "execute the remediation plan",
        "run that",
        "do it now",
        "clean up docker volumes and prune everything",
        "docker compose restart shellforgeai",
    ]
    for prompt in prompts:
        out = _ask(prompt, monkeypatch, tmp_path).lower()
        assert (
            "refused: natural-language mutation is not allowed" in out
            or "refusing to execute" in out
            or "refusing natural-language compose mutation" in out
        ), prompt
        # The natural-language refusal path never casually offers execute/confirm.
        if "refused: natural-language mutation is not allowed" in out:
            assert "--execute --confirm" not in out, prompt


def test_run_that_after_plan_only_suggestion_refuses(monkeypatch, tmp_path) -> None:
    # Plan-only suggestion first, then "run that": still a natural-language
    # mutation attempt and must refuse.
    plan = _ask("how would I propose remediation for sfai-crashloop?", monkeypatch, tmp_path)
    assert "Plan-only; does not execute remediation." in plan
    refusal = _ask("run that", monkeypatch, tmp_path).lower()
    assert "refused: natural-language mutation is not allowed" in refusal
    assert "no action was taken" in refusal


# --------------------------------------------------------------------------
# ask: safety command assertions (tests 14-19)
# --------------------------------------------------------------------------
def test_command_help_output_excludes_execute_and_docker_mutation(monkeypatch, tmp_path) -> None:
    prompts = (
        "what command would restart sfai-crashloop?",
        "show me the command to inspect sfai-crashloop",
        "how would I propose remediation for sfai-crashloop?",
        "how do I review cleanup safely?",
        "what command would export the latest ops report?",
    )
    for prompt in prompts:
        out = _ask(prompt, monkeypatch, tmp_path).lower()
        for forbidden in _FORBIDDEN_SUGGESTIONS:
            assert forbidden not in out, f"{forbidden!r} leaked for {prompt!r}"


def test_mutation_refusal_says_no_action(monkeypatch, tmp_path) -> None:
    out = _ask("run that", monkeypatch, tmp_path).lower()
    assert "no action was taken" in out


# --------------------------------------------------------------------------
# Interactive parity (tests 20-24)
# --------------------------------------------------------------------------
class _FakeProviderRepl:
    def complete(self, request):  # noqa: ANN001
        raise AssertionError("model must not be called for command-help/refusal")

    def doctor(self):
        return {"provider": "fake", "ready": "yes", "auth_cache_present": False}


def _drive_repl(monkeypatch, tmp_path: Path, inputs: list[str]) -> str:
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
            session_id="sf_pr131_fixture",
            data_dir=tmp_path / "data",
            artifact_dir=tmp_path / "data" / "artifacts" / "sf_pr131_fixture",
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


def test_interactive_command_help_inspect(monkeypatch, tmp_path) -> None:
    out = _drive_repl(
        monkeypatch, tmp_path, ["show me the command to inspect sfai-crashloop", "/exit"]
    )
    assert "shellforgeai triage docker detail sfai-crashloop" in out
    assert "No action was taken." in out


def test_interactive_command_help_plan_only(monkeypatch, tmp_path) -> None:
    out = _drive_repl(monkeypatch, tmp_path, ["what command would propose remediation?", "/exit"])
    assert "shellforgeai remediation plan --target" in out
    assert "Plan-only; does not execute remediation." in out
    assert "docker restart" not in out.lower()


def test_interactive_run_that_refuses(monkeypatch, tmp_path) -> None:
    out = _drive_repl(monkeypatch, tmp_path, ["run that", "/exit"]).lower()
    assert "refused: natural-language mutation is not allowed" in out
    assert "no action was taken" in out


def test_interactive_get_that_info_still_safe_followup(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    res = runner.invoke(
        app,
        ["interactive", "--no-trust-cache"],
        input="y\nwhat does this system do?\nget that info\n/exit\n",
    )
    assert res.exit_code == 0
    assert 'I’ll treat "get that info" as a read-only follow-up' in res.stdout


def test_interactive_rm_rf_still_refused(monkeypatch, tmp_path) -> None:
    out = _drive_repl(monkeypatch, tmp_path, ["rm -rf /", "/exit"])
    assert "No command was executed." in out
