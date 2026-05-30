from __future__ import annotations

import builtins
from pathlib import Path
from types import SimpleNamespace

from shellforgeai.core.followup_grounding import (
    FollowupGroundingState,
    render_grounded_resolution,
    resolve_followup_reference,
    update_grounding_from_latest_context,
    update_grounding_from_ops_report_text,
    update_grounding_from_triage_detail_text,
)
from shellforgeai.core.latest_context import build_latest_diagnosis_context
from shellforgeai.interactive import repl

OPS_REPORT = """ShellForgeAI 2AM Operator Report

Top suspect: sfai-crashloop — critical severity
First safe command: shellforgeai triage docker detail sfai-crashloop

Top suspects:
1. sfai-crashloop — critical / high confidence
2. sfai-bad-http — high / medium confidence
"""

DETAIL = """Triage detail: sfai-bad-http
Severity: high
Confidence: high
Evidence:
- bad_http: HTTP probe failed
Why: health endpoint returned 500
"""


def _ops_state() -> FollowupGroundingState:
    st = FollowupGroundingState()
    update_grounding_from_ops_report_text(st, OPS_REPORT)
    return st


def _detail_state() -> FollowupGroundingState:
    st = FollowupGroundingState()
    update_grounding_from_triage_detail_text(st, "sfai-bad-http", DETAIL)
    return st


# Required grounding cases -------------------------------------------------


def test_ops_report_top_suspect_resolves_to_crashloop() -> None:
    res = resolve_followup_reference("top suspect", _ops_state())
    assert res.target == "sfai-crashloop"
    assert res.safe_command == "shellforgeai triage docker detail sfai-crashloop"


def test_the_first_one_resolves_to_latest_top_suspect() -> None:
    assert resolve_followup_reference("the first one", _ops_state()).target == "sfai-crashloop"


def test_that_one_resolves_to_latest_target_when_unambiguous() -> None:
    assert resolve_followup_reference("that one", _ops_state()).target == "sfai-crashloop"


def test_that_container_resolves_to_latest_target_when_unambiguous() -> None:
    assert resolve_followup_reference("that container", _ops_state()).target == "sfai-crashloop"


def test_what_about_it_uses_latest_target() -> None:
    assert resolve_followup_reference("what about it?", _ops_state()).target == "sfai-crashloop"


def test_show_me_details_after_ops_report_routes_to_triage_detail() -> None:
    res = resolve_followup_reference("show me details", _ops_state())
    assert res.target == "sfai-crashloop"
    assert res.intent == "triage_detail"
    assert res.safe_command.endswith("sfai-crashloop")


def test_is_that_scary_references_triage_detail_target() -> None:
    res = resolve_followup_reference("is that scary?", _detail_state())
    out = render_grounded_resolution(_detail_state(), res)
    assert res.target == "sfai-bad-http"
    assert "sfai-bad-http" in out
    assert "high" in out.lower()


def test_why_is_it_high_references_triage_detail_target() -> None:
    res = resolve_followup_reference("why is it high?", _detail_state())
    assert res.target == "sfai-bad-http"
    assert res.intent == "triage_explain"


def test_what_did_you_find_uses_latest_evidence_context() -> None:
    ctx = build_latest_diagnosis_context(
        session_id="s1",
        target="health",
        diagnosis_kind="system role/health",
        checks=[],
        facts={"container": True},
        evidence_highlights=["- Context: Docker/container view."],
        artifact_dir="/data/artifacts/s1",
        evidence_path="/data/artifacts/s1/evidence.json",
        source_command="what does this system do?",
    )
    st = FollowupGroundingState()
    update_grounding_from_latest_context(st, ctx)
    res = resolve_followup_reference("what did you find?", st)
    out = render_grounded_resolution(st, res)
    assert res.kind == "evidence"
    assert "/data/artifacts/s1" in out
    assert "Docker/container view" in out


def test_dig_deeper_uses_latest_pending_or_evidence_context() -> None:
    st = _ops_state()
    res = resolve_followup_reference("dig deeper", st)
    assert res.kind == "evidence"
    assert render_grounded_resolution(st, res)


def test_ambiguous_check_it_with_no_latest_target_asks_clarification() -> None:
    res = resolve_followup_reference("check it", FollowupGroundingState())
    out = render_grounded_resolution(FollowupGroundingState(), res)
    assert res.kind in {"ambiguous", "no_context"}
    assert "No action was taken" in out


def test_no_context_what_about_it_does_not_invent_target() -> None:
    res = resolve_followup_reference("what about it?", FollowupGroundingState())
    assert not res.target
    assert res.kind == "no_context"


def test_restart_it_after_latest_target_resolves_but_refuses() -> None:
    st = _ops_state()
    res = resolve_followup_reference("restart it", st)
    out = render_grounded_resolution(st, res)
    assert res.kind == "mutation_refusal"
    assert res.target == "sfai-crashloop"
    assert "not restarting sfai-crashloop" in out
    assert "No action was taken" in out


def test_fix_that_after_latest_target_refuses_and_says_no_action() -> None:
    st = _ops_state()
    out = render_grounded_resolution(st, resolve_followup_reference("fix that", st))
    assert "not fixing sfai-crashloop" in out
    assert "No action was taken" in out


def test_run_that_remains_refused_for_target_reference() -> None:
    st = _ops_state()
    out = render_grounded_resolution(st, resolve_followup_reference("run that", st))
    assert "not running sfai-crashloop" in out
    assert "shellforgeai triage docker detail sfai-crashloop" in out


def test_resolved_output_keeps_target_name_not_generic_it() -> None:
    st = _ops_state()
    out = render_grounded_resolution(st, resolve_followup_reference("that one", st))
    assert "sfai-crashloop" in out
    assert "as it" not in out.lower()


# Safety source checks -----------------------------------------------------


def test_followup_grounding_does_not_call_shell_true() -> None:
    src = Path("src/shellforgeai/core/followup_grounding.py").read_text(encoding="utf-8")
    assert "shell=True" not in src


def test_followup_grounding_does_not_call_remediation_execute() -> None:
    src = Path("src/shellforgeai/core/followup_grounding.py").read_text(encoding="utf-8")
    assert "remediation execute" not in src
    assert ".execute(" not in src


def test_followup_grounding_does_not_call_cleanup_execute() -> None:
    src = Path("src/shellforgeai/core/followup_grounding.py").read_text(encoding="utf-8")
    assert "cleanup execute" not in src


def test_followup_grounding_does_not_call_docker_or_compose_mutation() -> None:
    src = Path("src/shellforgeai/core/followup_grounding.py").read_text(encoding="utf-8").lower()
    for bad in ("docker restart", "compose restart", "compose up", "compose down"):
        assert bad not in src


# Transcript-inspired REPL checks ----------------------------------------


def _drive(inputs: list[str], monkeypatch, tmp_path, dispatch_output: str = OPS_REPORT) -> str:
    monkeypatch.setattr(repl, "_confirm_workspace", lambda *a, **k: True)
    monkeypatch.setattr(repl.WorkspaceTrustStore, "is_trusted", lambda self, p: True)

    printed: list[str] = []

    class _Cap:
        def print(self, *args, **kwargs):  # noqa: ANN002, ANN003
            printed.append(" ".join(str(a) for a in args))

        def status(self, *args, **kwargs):  # noqa: ANN002, ANN003
            class _Ctx:
                def __enter__(self_inner):
                    return self_inner

                def __exit__(self_inner, *exc):
                    return False

            return _Ctx()

        def clear(self):
            pass

    monkeypatch.setattr(repl, "Console", lambda *a, **k: _Cap())
    monkeypatch.setattr(
        repl, "StreamRenderer", lambda *a, **k: SimpleNamespace(render=lambda *x: None)
    )
    monkeypatch.setattr(
        repl, "_run_interactive_cli_dispatch", lambda console, argv: dispatch_output
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
            session_id="s132",
            data_dir=tmp_path / "data",
            artifact_dir=tmp_path / "data" / "artifacts" / "s132",
            mode="inspect",
        ),
        profile=SimpleNamespace(name="standard", online_allowed=False),
        settings=SimpleNamespace(
            model=SimpleNamespace(provider="fake", model="fake", timeout_seconds=1)
        ),
    )
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    repl.start_interactive(runtime, no_trust_cache=True)
    return "\n".join(printed)


def test_transcript_docker_ops_first_one_scary_restart(monkeypatch, tmp_path) -> None:
    out = _drive(
        ["ops report", "the first one", "is that scary?", "restart it", "/exit"],
        monkeypatch,
        tmp_path,
    )
    assert "sfai-crashloop" in out
    assert "not restarting sfai-crashloop" in out
    assert "No action was taken" in out


def test_transcript_system_health_find_deeper_fix(monkeypatch, tmp_path) -> None:
    ctx = build_latest_diagnosis_context(
        session_id="s132",
        target="health",
        diagnosis_kind="system role/health",
        checks=[],
        facts={"container": True},
        evidence_highlights=["- Context: Docker/container view."],
        artifact_dir="/data/artifacts/s132",
        source_command="system health",
    )
    st = FollowupGroundingState()
    update_grounding_from_latest_context(st, ctx)
    assert render_grounded_resolution(st, resolve_followup_reference("what did you find?", st))
    assert render_grounded_resolution(st, resolve_followup_reference("dig deeper", st))
    out = render_grounded_resolution(st, resolve_followup_reference("fix it", st))
    assert "No action was taken" in out


def test_transcript_triage_detail_next_run_that(monkeypatch, tmp_path) -> None:
    out = _drive(
        ["triage docker detail sfai-bad-http", "what should I check next?", "run that", "/exit"],
        monkeypatch,
        tmp_path,
        dispatch_output=DETAIL,
    )
    assert "sfai-bad-http" in out
    assert "not running sfai-bad-http" in out
