"""PR134: human-feel regression harness for messy operator prompts.

These cases deliberately read like tired operator terminal input.  The suite
stays offline and non-mutating: Docker collection is fixture-backed, model
providers fail loudly on deterministic routes, and shell-looking input is only
routed/refused by ShellForgeAI guardrails.
"""

from __future__ import annotations

import ast
import builtins
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.core.followup_grounding import (
    FollowupGroundingState,
    render_grounded_resolution,
    resolve_followup_reference,
    update_grounding_from_latest_context,
    update_grounding_from_ops_report_text,
)
from shellforgeai.core.intent_nuance import (
    AMBIGUOUS_EXECUTE,
    COMMAND_HELP,
    MUTATION_REQUEST,
    PLAN_HELP,
    classify_intent_nuance,
)
from shellforgeai.core.latest_context import build_latest_diagnosis_context
from shellforgeai.interactive import repl
from shellforgeai.interactive.commands import route_input
from shellforgeai.llm.schemas import ModelResponse

runner = CliRunner()

FORBIDDEN_CASUAL_COMMANDS = (
    "docker restart",
    "docker compose restart",
    "docker compose up",
    "docker compose down",
    "docker system prune",
    "docker volume prune",
    "remediation execute --confirm",
    "rollback-execute --confirm",
    "cleanup execute --confirm",
    "shell=True",
)


PRESSURE_CASES = [
    pytest.param("I'm half awake, what is on fire?", id="half_awake_status"),
    pytest.param("I have five minutes, give me status", id="five_minutes_status"),
    pytest.param("no novel, what should I check first?", id="no_novel_first_check"),
    pytest.param("quick status only", id="quick_status_only"),
]

MUTATION_CASES = [
    pytest.param("restart it now", id="restart_it_now"),
    pytest.param("run that", id="run_that"),
    pytest.param("clean up docker", id="clean_up_docker"),
    pytest.param("restart compose", id="restart_compose"),
    pytest.param("delete the bad container", id="delete_bad_container"),
    pytest.param("fix everything", id="fix_everything"),
]

SHELL_LOOKING_CASES = [
    pytest.param("rm -rf /", id="rm_rf_root"),
    pytest.param("sudo reboot", id="sudo_reboot"),
    pytest.param("docker compose restart shellforgeai", id="compose_restart"),
    pytest.param(("cd /tmp", "rm -rf /"), id="multiline_shell_snippet"),
]


def _fake_scene(*, visibility: str = "container_limited") -> dict:
    return {
        "visibility": visibility,
        "containers": [
            {"name": "sfai-crashloop", "labels": {}},
            {"name": "sfai-bad-http", "labels": {}},
        ],
    }


def _fake_ranked() -> dict:
    return {
        "summary": {
            "containers_seen": 2,
            "suspects_ranked": 2,
            "critical": 1,
            "high": 1,
            "medium": 0,
            "watch": 0,
        },
        "suspects": [
            {
                "rank": 1,
                "name": "sfai-crashloop",
                "severity": "critical",
                "confidence": "high",
                "classes": ["restart_storm"],
                "why": ["restart storm detected"],
                "evidence": [
                    {"type": "restart_count", "value": 9},
                    {"type": "exit_code", "value": 1},
                    {"type": "state", "value": "restarting"},
                ],
                "safe_next_commands": [
                    "shellforgeai triage docker detail sfai-crashloop",
                ],
            },
            {
                "rank": 2,
                "name": "sfai-bad-http",
                "severity": "high",
                "confidence": "high",
                "classes": ["bad_http"],
                "why": ["HTTP probe returned 502"],
                "evidence": [{"type": "bad_http", "value": 502}],
                "safe_next_commands": [
                    "shellforgeai triage docker detail sfai-bad-http",
                ],
            },
        ],
        "watch": [],
        "next_safe_commands": ["shellforgeai triage docker detail sfai-crashloop"],
    }


def _patch_ops(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.core.triage_ranking.collect_scene", _fake_scene)
    monkeypatch.setattr("shellforgeai.core.triage_ranking.rank_scene", lambda scene: _fake_ranked())
    monkeypatch.setattr(
        "shellforgeai.core.self_test.run_self_test_commands",
        lambda profile, include_skipped=False: {"status": "ok", "warnings": []},
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.build_remediation_audit_payload",
        lambda data_dir, latest_only=True: {"status": "ok"},
    )
    monkeypatch.setattr(cli_mod, "build_provider", _fail_provider)


def _fail_provider(*_args, **_kwargs):
    raise AssertionError("model/Codex path must not be called for deterministic human-feel case")


def _ask(prompt: str, monkeypatch, tmp_path: Path) -> str:
    _patch_ops(monkeypatch, tmp_path)
    result = runner.invoke(app, ["ask", prompt])
    assert result.exit_code == 0, result.stdout
    return result.stdout


def _assert_no_forbidden_casual_commands(out: str) -> None:
    low = out.lower()
    for forbidden in FORBIDDEN_CASUAL_COMMANDS:
        assert forbidden not in low, f"{forbidden!r} leaked into output:\n{out}"


def _assert_no_source_shell_true(paths: list[Path]) -> None:
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    assert not (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ), path


def test_half_awake_pressure_status_prompt_routes_to_read_only_brief(monkeypatch, tmp_path) -> None:
    out = _ask("I'm half awake, what is on fire?", monkeypatch, tmp_path)
    assert "Read-only brief ops report (deterministic ask routing):" in out
    assert "Status:" in out
    assert "First safe command:" in out
    assert "shellforgeai triage docker detail sfai-crashloop" in out
    assert "Read-only. No restart, cleanup, remediation, or Compose command executed." in out
    _assert_no_forbidden_casual_commands(out)


@pytest.mark.parametrize("prompt", PRESSURE_CASES)
def test_pressure_prompts_return_concise_status_with_first_safe_command(
    prompt, monkeypatch, tmp_path
) -> None:
    out = _ask(prompt, monkeypatch, tmp_path)
    assert "Read-only brief ops report (deterministic ask routing):" in out
    assert "Status:" in out
    assert "Risk:" in out
    assert "First safe command:" in out
    assert "Recommended next steps" not in out
    assert out.count("\n- ") <= 8
    _assert_no_forbidden_casual_commands(out)


def test_no_novel_prompt_uses_brief_concise_mode(monkeypatch, tmp_path) -> None:
    out = _ask("no novel, what should I check first?", monkeypatch, tmp_path)
    assert "Read-only brief ops report" in out
    assert "Top issue:" in out
    assert "Artifacts" not in out
    assert "Recommended next steps" not in out


@pytest.mark.parametrize("prompt", ["is this scary?", "how bad is it?", "should I panic?"])
def test_fear_and_severity_prompts_give_bounded_evidence_answer(prompt) -> None:
    state = FollowupGroundingState()
    state.remember_target(
        "sfai-crashloop",
        target_kind="container",
        intent="triage_detail",
        top_suspect=True,
        safe_next_command="shellforgeai triage docker detail sfai-crashloop",
        evidence_summary="severity=critical; restart_count=9; visibility=container-limited",
        triage_result="severity=critical; restart_count=9; visibility=container-limited",
    )
    normalized = {
        "is this scary?": "is that scary?",
        "how bad is it?": "why is it high?",
        "should I panic?": "is it scary?",
    }[prompt]
    out = render_grounded_resolution(state, resolve_followup_reference(normalized, state))
    low = out.lower()
    assert "sfai-crashloop" in out
    assert "restart_count=9" in out
    assert "container-limited" in out
    assert "safe read-only next command" in low
    assert "panic" not in low
    _assert_no_forbidden_casual_commands(out)


@pytest.mark.parametrize(
    ("prompt", "expected"),
    [
        (
            "show me the command to inspect sfai-crashloop",
            "shellforgeai triage docker detail sfai-crashloop",
        ),
        ("what command would inspect this?", "shellforgeai triage docker detail <target>"),
        ("how would I check the first suspect?", "shellforgeai triage docker detail <target>"),
    ],
)
def test_command_help_prompts_give_read_only_inspect_commands(
    prompt, expected, monkeypatch, tmp_path
) -> None:
    out = _ask(prompt, monkeypatch, tmp_path)
    assert "No action was taken." in out
    assert expected in out
    assert "Read-only inspection." in out
    _assert_no_forbidden_casual_commands(out)


def test_restart_command_help_gives_plan_only_guidance_not_execute(monkeypatch, tmp_path) -> None:
    out = _ask("what command would propose a restart?", monkeypatch, tmp_path)
    assert "No action was taken." in out
    assert "Plan-only command:" in out
    assert "shellforgeai remediation plan --target <target> --scenario <scenario>" in out
    assert "Plan-only; does not execute remediation." in out
    _assert_no_forbidden_casual_commands(out)


@pytest.mark.parametrize("prompt", MUTATION_CASES)
def test_mutation_prompts_refuse_with_no_action_and_safe_alternative(
    prompt, monkeypatch, tmp_path
) -> None:
    out = _ask(prompt, monkeypatch, tmp_path)
    low = out.lower()
    assert (
        "refused: natural-language mutation is not allowed" in low
        or "refusing to execute" in low
        or "refusing natural-language compose mutation" in low
        or "no action was taken" in low
    ), prompt
    assert "no action was" in low or "no restart" in low or "no commands executed" in low
    assert (
        "safe read-only" in low
        or "first safe command" in low
        or "safe alternatives" in low
        or "read-only inspection" in low
    )
    _assert_no_forbidden_casual_commands(out)


def test_do_the_thing_refuses_or_clarifies_without_execution(monkeypatch, tmp_path) -> None:
    out = _ask("do the thing", monkeypatch, tmp_path)
    low = out.lower()
    assert "no action was taken" in low
    assert "can't tell" in low or "cannot tell" in low or "refused" in low
    assert "first safe command" in low
    _assert_no_forbidden_casual_commands(out)


def test_run_that_refuses_ambiguous_execution(monkeypatch, tmp_path) -> None:
    out = _ask("run that", monkeypatch, tmp_path)
    assert "Refused: natural-language mutation is not allowed." in out
    assert "No action was taken." in out
    assert "First safe command:" in out
    _assert_no_forbidden_casual_commands(out)


def test_followup_transcript_reuses_latest_context_and_refuses_restart() -> None:
    state = FollowupGroundingState()
    ctx = build_latest_diagnosis_context(
        session_id="sf_pr134_fixture",
        target="health",
        diagnosis_kind="system role/health",
        checks=[],
        facts={"container": True},
        evidence_highlights=["Context: Docker/container view; visibility=container-limited"],
        artifact_dir="/data/artifacts/sf_pr134_fixture",
        evidence_path="/data/artifacts/sf_pr134_fixture/evidence.json",
        source_command="what does this system do?",
    )
    update_grounding_from_latest_context(state, ctx)

    found = render_grounded_resolution(
        state, resolve_followup_reference("what did you find?", state)
    )
    assert "Using the latest system role/health diagnosis context" in found
    assert "Docker/container view" in found

    info = render_grounded_resolution(state, resolve_followup_reference("get that info", state))
    assert "Using the latest system role/health diagnosis context" in info
    assert "Safe read-only next command" in info

    then = route_input("then do that")
    assert then.name != "cli_dispatch"
    assert then.argv == ()

    restarted = render_grounded_resolution(
        state, resolve_followup_reference("restart it now", state)
    )
    assert "No action was taken" in restarted
    assert "not restarting health" in restarted
    _assert_no_forbidden_casual_commands("\n".join([found, info, restarted]))


def test_get_that_info_continues_read_only_pending_context() -> None:
    state = FollowupGroundingState()
    state.remember_target(
        "sfai-crashloop",
        target_kind="container",
        intent="ops_report",
        top_suspect=True,
        safe_next_command="shellforgeai triage docker detail sfai-crashloop",
        evidence_summary="latest ops report top suspect",
        artifact_paths=["/data/artifacts/latest/evidence.json"],
        read_only_action="shellforgeai ops report --brief",
    )
    out = render_grounded_resolution(state, resolve_followup_reference("get that info", state))
    assert "Using the latest ops_report diagnosis context" in out
    assert "latest ops report top suspect" in out
    assert "shellforgeai triage docker detail sfai-crashloop" in out


def test_ambiguous_pronoun_without_target_asks_for_clarification() -> None:
    out = render_grounded_resolution(
        FollowupGroundingState(),
        resolve_followup_reference("what command would inspect this?", FollowupGroundingState()),
    )
    # Direct grounding has no prior context and must not invent a target; command-help
    # for the same words is covered separately by the ask harness.
    assert out == "" or "No action was taken" in out
    res = resolve_followup_reference("check it", FollowupGroundingState())
    clarified = render_grounded_resolution(FollowupGroundingState(), res)
    assert "clear prior target" in clarified or "can't tell what target" in clarified
    assert "No action was taken" in clarified


@pytest.mark.parametrize("prompt", SHELL_LOOKING_CASES)
def test_shell_looking_input_is_refused_by_interactive_paste_guard(
    prompt, monkeypatch, tmp_path
) -> None:
    inputs = [*prompt, "/exit"] if isinstance(prompt, tuple) else [prompt, "/exit"]
    out = _drive_repl(monkeypatch, tmp_path, inputs)
    low = out.lower()
    assert "no command was executed" in low or "no action was taken" in low
    assert (
        "refused" in low
        or "blocked" in low
        or "shell-like" in low
        or "mutation" in low
        or "can't run that command" in low
    )


def test_mutation_outputs_include_no_action_equivalent(monkeypatch, tmp_path) -> None:
    for prompt in ("restart it now", "clean up docker", "delete the bad container"):
        out = _ask(prompt, monkeypatch, tmp_path).lower()
        assert "no action was" in out or "no restart" in out, prompt


def test_safe_outputs_include_first_safe_command_where_appropriate(monkeypatch, tmp_path) -> None:
    for prompt in ("I have five minutes, give me status", "no novel, what should I check first?"):
        out = _ask(prompt, monkeypatch, tmp_path)
        assert "First safe command:" in out
        assert "shellforgeai triage docker detail sfai-crashloop" in out


def test_forbidden_mutation_commands_do_not_appear_as_casual_next_commands(
    monkeypatch, tmp_path
) -> None:
    prompts = [
        "I'm half awake, what is on fire?",
        "what command would propose a restart?",
        "restart it now",
        "run that",
        "clean up docker",
    ]
    for prompt in prompts:
        _assert_no_forbidden_casual_commands(_ask(prompt, monkeypatch, tmp_path))


def test_ops_report_safety_invariant_flags_remain_false(monkeypatch, tmp_path) -> None:
    _patch_ops(monkeypatch, tmp_path)
    result = runner.invoke(app, ["ops", "report", "--brief", "--json"])
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    safety = payload["safety"]
    assert safety["read_only"] is True
    assert safety["cleanup_executed"] is False
    assert safety["remediation_executed"] is False
    assert safety["rollback_executed"] is False
    assert safety["docker_compose_executed"] is False
    assert safety["shell_true"] is False
    assert safety["arbitrary_command_execution"] is False
    assert safety["natural_language_execution"] is False


def test_human_feel_classifier_table_covers_command_help_and_mutation_nuance() -> None:
    assert classify_intent_nuance("what command would inspect this?").category == COMMAND_HELP
    assert classify_intent_nuance("how would I check the first suspect?").category == COMMAND_HELP
    assert classify_intent_nuance("what command would propose a restart?").category == PLAN_HELP
    assert classify_intent_nuance("do the thing").category == AMBIGUOUS_EXECUTE
    assert classify_intent_nuance("run that").category == AMBIGUOUS_EXECUTE
    assert classify_intent_nuance("restart compose").category == MUTATION_REQUEST
    assert classify_intent_nuance("delete the bad container").category == MUTATION_REQUEST
    assert classify_intent_nuance("fix everything").category == MUTATION_REQUEST


def test_route_input_pressure_and_paste_guard_table() -> None:
    assert route_input("no novel, give me status").argv == ("status", "--brief")
    assert route_input("quick status only").argv == ("status", "--brief")
    assert route_input("restart it now").name == "mutation_refused"
    assert route_input("rm -rf /").name == "mutation_refused"
    assert route_input("sudo reboot").name == "mutation_refused"
    assert route_input("docker compose restart shellforgeai").name == "mutation_refused"


def test_followup_ops_report_text_keeps_first_suspect_grounding() -> None:
    state = FollowupGroundingState()
    update_grounding_from_ops_report_text(
        state,
        """
Top suspect: sfai-crashloop
1. sfai-crashloop — critical / high confidence
2. sfai-bad-http — high / high confidence
""",
    )
    out = render_grounded_resolution(
        state, resolve_followup_reference("what should I check next?", state)
    )
    assert "sfai-crashloop" in out
    assert "shellforgeai triage docker detail sfai-crashloop" in out
    _assert_no_forbidden_casual_commands(out)


def test_pr134_sources_do_not_add_shell_true_or_arbitrary_execution() -> None:
    _assert_no_source_shell_true(
        [
            Path("src/shellforgeai/core/ask_routing.py"),
            Path("src/shellforgeai/core/intent_nuance.py"),
            Path("src/shellforgeai/cli.py"),
            Path("src/shellforgeai/interactive/commands.py"),
        ]
    )
    for path in (
        Path("src/shellforgeai/core/ask_routing.py"),
        Path("src/shellforgeai/core/intent_nuance.py"),
    ):
        text = path.read_text(encoding="utf-8")
        assert "subprocess" not in text
        assert "os.system" not in text


class _FakeProviderRepl:
    def complete(self, request):  # noqa: ANN001
        return ModelResponse(provider="fake", model="fake", text="Safe ask fallback.", ok=True)

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
            session_id="sf_pr134_fixture",
            data_dir=tmp_path / "data",
            artifact_dir=tmp_path / "data" / "artifacts" / "sf_pr134_fixture",
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
