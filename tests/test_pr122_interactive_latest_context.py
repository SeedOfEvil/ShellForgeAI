"""PR122: interactive latest-evidence memory and follow-up continuity.

These tests are fully offline: no live Docker, no internet, no real Codex,
no real /data, and no host mutation.
"""

from __future__ import annotations

import builtins
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from shellforgeai.core.evidence import EvidenceBundle, EvidenceCategory, EvidenceItem, TargetType
from shellforgeai.core.latest_context import (
    LatestDiagnosisContext,
    answer_from_latest_context,
    build_latest_diagnosis_context,
    detect_latest_context_intent,
    is_mutation_followup,
    no_latest_context_reply,
    render_latest_context_pending,
)
from shellforgeai.interactive.repl import _evidence_highlights, _summarize_facts

PERF_CHECKS = [
    {
        "tool": "system.cpu_memory",
        "status": "ok",
        "summary": "cpus=4 mem=2.0GiB/8.0GiB swap=0B/2.0GiB",
    },
    {"tool": "host.resources", "status": "ok", "summary": "loadavg 3.10 2.50 1.90"},
    {
        "tool": "storage.pressure",
        "status": "ok",
        "summary": "io_some_avg10=1.7 io_some_avg60=1.2 io_some_avg300=0.5",
    },
    {"tool": "system.container_detect", "status": "ok", "summary": "docker container=yes"},
    {"tool": "process.top", "status": "ok", "summary": "top: pid 1 codex using 92% cpu"},
    {"tool": "disk.usage", "status": "ok", "summary": "/ 42% used"},
]


def _perf_context() -> LatestDiagnosisContext:
    return build_latest_diagnosis_context(
        session_id="sf_test_001",
        target="performance",
        diagnosis_kind="performance",
        checks=PERF_CHECKS,
        facts=_summarize_facts(PERF_CHECKS),
        evidence_highlights=_evidence_highlights(PERF_CHECKS),
        findings=["Elevated I/O pressure observed"],
        artifact_dir="/data/artifacts/sf_test_001",
        evidence_path="/data/artifacts/sf_test_001/evidence.json",
        summary_path="/data/artifacts/sf_test_001/summary.md",
        plan_path="/data/artifacts/sf_test_001/plan.json",
        source_command="this system is feeling a bit slow",
    )


# --- 1-4: context is built and complete -----------------------------------


def test_performance_diagnosis_builds_latest_context() -> None:
    ctx = _perf_context()
    assert isinstance(ctx, LatestDiagnosisContext)
    assert ctx.diagnosis_kind == "performance"
    assert ctx.deterministic_only is True


def test_context_includes_target_kind_and_artifact_paths() -> None:
    ctx = _perf_context()
    assert ctx.target == "performance"
    assert ctx.diagnosis_kind == "performance"
    assert ctx.artifact_dir == "/data/artifacts/sf_test_001"
    assert ctx.evidence_path.endswith("evidence.json")
    assert ctx.summary_path.endswith("summary.md")
    assert ctx.plan_path.endswith("plan.json")


def test_context_includes_evidence_highlights() -> None:
    ctx = _perf_context()
    assert ctx.evidence_highlights
    joined = " ".join(ctx.evidence_highlights).lower()
    assert "cpu" in joined or "load" in joined


def test_context_includes_limitations() -> None:
    ctx = _perf_context()
    assert ctx.limitations
    assert any("container" in limit.lower() for limit in ctx.limitations)


# --- 5-10: follow-ups use latest context ----------------------------------


def test_followup_what_did_you_find_uses_context() -> None:
    assert detect_latest_context_intent("what did you find?") == "summary"
    ctx = _perf_context()
    answer = answer_from_latest_context(ctx, "summary")
    assert "performance" in answer.lower()
    assert any(h.split(":")[0].strip("- ") in answer for h in ctx.evidence_highlights)


def test_followup_why_is_it_slow_uses_performance_evidence() -> None:
    assert detect_latest_context_intent("why is it slow?") == "performance"
    answer = answer_from_latest_context(_perf_context(), "performance")
    low = answer.lower()
    assert "load average" in low or "cpu/memory" in low
    assert "3.10" in answer or "top process" in low


def test_followup_is_it_running_normally_has_confidence_and_caveats() -> None:
    assert detect_latest_context_intent("is it running normally?") == "health_status"
    answer = answer_from_latest_context(_perf_context(), "health_status")
    low = answer.lower()
    assert "confidence" in low
    assert "cannot" in low or "bounded" in low or "limitation" in low


def test_followup_what_does_system_do_does_not_invent_role() -> None:
    assert detect_latest_context_intent("what does this system do?") == "system_role"
    answer = answer_from_latest_context(_perf_context(), "system_role")
    low = answer.lower()
    assert "container-limited view" in low
    assert "will not invent" in low or "cannot fully infer" in low


def test_followup_includes_artifact_references() -> None:
    answer = answer_from_latest_context(_perf_context(), "summary")
    assert "evidence.json" in answer
    assert "summary.md" in answer


def test_followup_includes_safe_next_commands() -> None:
    answer = answer_from_latest_context(_perf_context(), "performance")
    assert "shellforgeai ops report" in answer
    assert "Safe next commands" in answer


# --- 11-12 & safety: read-only, no mutation -------------------------------


def test_safe_next_commands_are_read_only_only() -> None:
    ctx = _perf_context()
    forbidden = (
        "remediation plan",
        "remediation execute",
        "execute",
        "cleanup execute",
        "compose up",
        "compose down",
        "compose restart",
        "docker restart",
        "prune",
        "rollback",
        "--apply",
    )
    for cmd in ctx.safe_next_commands:
        low = cmd.lower()
        assert all(bad not in low for bad in forbidden), cmd


def test_followup_answer_emits_no_mutation_directives() -> None:
    for intent in (
        "summary",
        "performance",
        "health_status",
        "system_role",
        "next_steps",
        "artifacts",
        "limitations",
    ):
        answer = answer_from_latest_context(_perf_context(), intent).lower()
        for bad in ("docker restart", "compose up", "compose down", "rm -rf", "prune -f"):
            assert bad not in answer


# --- 13-15: /pending behavior ---------------------------------------------


def test_pending_renders_latest_context_when_no_formal_pending() -> None:
    out = render_latest_context_pending(_perf_context())
    assert "latest diagnosis context" in out.lower()
    assert "performance" in out
    assert "evidence.json" in out
    assert "shellforgeai ops report" in out


def test_pending_render_is_distinct_from_formal_pending() -> None:
    # The latest-context render is only used when no formal pending exists;
    # it must clearly label itself so formal pending output is preserved.
    out = render_latest_context_pending(_perf_context())
    assert "No formal pending investigation" in out


def test_no_context_reply_when_neither_exists() -> None:
    reply = no_latest_context_reply()
    assert "don't have any collected evidence" in reply.lower()
    assert "diagnose" in reply.lower()


# --- 16-17: no-context behavior -------------------------------------------


def test_no_context_followup_suggests_read_only_commands() -> None:
    reply = no_latest_context_reply()
    assert "ops report" in reply.lower()
    assert "diagnose" in reply.lower()


def test_no_context_reply_does_not_hallucinate_evidence() -> None:
    reply = no_latest_context_reply().lower()
    # must not assert any concrete findings/metrics
    for fabricated in ("cpu", "load average", "top process", "disk usage", "% used"):
        assert fabricated not in reply


# --- 18-23: mutation refusals & no remediation calls ----------------------


def test_mutation_followup_restart_is_not_a_context_intent() -> None:
    assert detect_latest_context_intent("restart it") is None


def test_mutation_followup_fix_is_recognized_and_refused() -> None:
    assert is_mutation_followup("fix it") is True
    assert is_mutation_followup("just fix it") is True
    assert detect_latest_context_intent("fix it") is None


def test_latest_context_module_has_no_remediation_or_docker_execution() -> None:
    src = Path("src/shellforgeai/core/latest_context.py").read_text(encoding="utf-8")
    for forbidden in (
        "remediation_plan_command",
        "remediation_execute",
        "subprocess",
        "os.system",
        "docker restart",
        "compose up",
        "cleanup execute",
    ):
        assert forbidden not in src


def test_no_shell_true_introduced() -> None:
    for rel in (
        "src/shellforgeai/core/latest_context.py",
        "src/shellforgeai/interactive/repl.py",
    ):
        src = Path(rel).read_text(encoding="utf-8")
        assert "shell=True" not in src


# --- REPL integration: transcript-inspired flow ---------------------------


def _fake_perf_result() -> SimpleNamespace:
    items = [
        EvidenceItem(
            source=c["tool"],
            category=EvidenceCategory.host,
            ok=True,
            title=c["tool"],
            summary=c["summary"],
            content=c["summary"],
            metadata={"status": c["status"]},
        )
        for c in PERF_CHECKS
    ]
    bundle = EvidenceBundle(
        target="performance",
        target_type=TargetType.host,
        created_at=datetime.now(timezone.utc),
        items=items,
    )
    plan = SimpleNamespace(model_dump_json=lambda indent=2: "{}")
    finding = SimpleNamespace(title="Elevated I/O pressure", model_dump=lambda: {})
    return SimpleNamespace(
        session_id="sf_test_001",
        target="performance",
        target_type=TargetType.host,
        created_at=datetime.now(timezone.utc),
        evidence=bundle,
        proposed_plan=plan,
        findings=[finding],
    )


class _FakeProvider:
    def complete(self, request):  # noqa: ANN001
        return SimpleNamespace(text="Read-only performance assessment from evidence.")

    def doctor(self):
        return {"provider": "fake", "ready": "yes"}


def _drive_repl(monkeypatch, tmp_path: Path, inputs: list[str]) -> str:
    from shellforgeai.interactive import repl

    monkeypatch.setattr(repl, "_confirm_workspace", lambda *a, **k: True)
    monkeypatch.setattr(repl, "build_provider", lambda *a, **k: _FakeProvider())
    monkeypatch.setattr(repl, "diagnose_target", lambda *a, **k: _fake_perf_result())
    monkeypatch.setattr(repl, "build_contextual_prompt", lambda *a, **k: "prompt", raising=True)

    printed: list[str] = []

    class _Cap:
        def print(self, *args, **kwargs):  # noqa: ANN002, ANN003
            printed.append(" ".join(str(a) for a in args))

        def print_json(self, *args, **kwargs):  # noqa: ANN002, ANN003
            printed.append(str(kwargs.get("data", args)))

        def status(self, *args, **kwargs):  # noqa: ANN002, ANN003
            class _Ctx:
                def __enter__(self_inner):
                    return self_inner

                def __exit__(self_inner, *exc):
                    return False

            return _Ctx()

    monkeypatch.setattr(repl, "Console", lambda *a, **k: _Cap())
    monkeypatch.setattr(
        repl, "StreamRenderer", lambda *a, **k: SimpleNamespace(render=lambda *x: None)
    )
    monkeypatch.setattr(repl.WorkspaceTrustStore, "is_trusted", lambda self, p: True)

    seq = iter(inputs)

    def _fake_input(prompt: str = "") -> str:
        try:
            return next(seq)
        except StopIteration as exc:
            raise EOFError from exc

    monkeypatch.setattr(builtins, "input", _fake_input)

    runtime = SimpleNamespace(
        session=SimpleNamespace(
            session_id="sf_test_001",
            data_dir=tmp_path / "data",
            artifact_dir=tmp_path / "data" / "artifacts" / "sf_test_001",
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


def test_repl_flow_diagnose_then_followup_uses_latest_context(monkeypatch, tmp_path) -> None:
    out = _drive_repl(
        monkeypatch,
        tmp_path,
        ["this system is feeling a bit slow", "what did you find?", "/exit"],
    )
    assert "Collected" in out
    # follow-up grounded in latest context
    assert "latest performance diagnosis" in out.lower()
    assert "shellforgeai ops report" in out


def test_repl_pending_shows_latest_context_after_diagnose(monkeypatch, tmp_path) -> None:
    # explicit `diagnose` leaves no formal pending follow-up, so /pending
    # should surface the latest diagnosis context instead.
    out = _drive_repl(
        monkeypatch,
        tmp_path,
        ["diagnose performance", "/pending", "/exit"],
    )
    assert "latest diagnosis context" in out.lower()
    assert "performance" in out


def test_repl_pending_no_context_shows_no_pending(monkeypatch, tmp_path) -> None:
    out = _drive_repl(monkeypatch, tmp_path, ["/pending", "/exit"])
    assert "No pending investigation." in out


def test_repl_followup_with_no_context_suggests_commands(monkeypatch, tmp_path) -> None:
    # "what did you find?" routes to a question (not a fresh collection), so
    # with no prior evidence it should cleanly say so and suggest read-only steps.
    out = _drive_repl(monkeypatch, tmp_path, ["what did you find?", "/exit"])
    assert "don't have any collected evidence" in out.lower()
    assert "ops report" in out.lower()


def test_repl_fix_followup_refuses_mutation(monkeypatch, tmp_path) -> None:
    out = _drive_repl(
        monkeypatch,
        tmp_path,
        ["this system is feeling a bit slow", "fix it", "/exit"],
    )
    assert "can't run fixes or mutations" in out.lower()
    assert "no action was taken" in out.lower()
