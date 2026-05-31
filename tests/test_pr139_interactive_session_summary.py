"""PR139: deterministic interactive session handoff summaries."""

from __future__ import annotations

import ast
import builtins
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from shellforgeai.core.diagnose import DiagnosisResult, Finding
from shellforgeai.core.evidence import EvidenceBundle, EvidenceCategory, EvidenceItem, TargetType
from shellforgeai.core.plans import Plan, PlanStep
from shellforgeai.interactive import repl
from shellforgeai.interactive.commands import route_input


class _NoModelProvider:
    complete_calls = 0

    def complete(self, request):  # noqa: ANN001
        type(self).complete_calls += 1
        raise AssertionError("session summary must not call the model")

    def doctor(self):
        return {"provider": "none", "ready": "no"}


def _fake_health_result() -> DiagnosisResult:
    items = [
        EvidenceItem(
            source="system.container_detect",
            category=EvidenceCategory.host,
            ok=True,
            title="Container context",
            summary="docker container=yes",
            content="container=docker",
            metadata={"status": "ok"},
        ),
        EvidenceItem(
            source="host.resources",
            category=EvidenceCategory.host,
            ok=True,
            title="Host resources",
            summary="loadavg 0.10 0.05 0.01",
            content="loadavg 0.10 0.05 0.01",
            metadata={"status": "ok"},
        ),
    ]
    return DiagnosisResult(
        session_id="sf_pr139_diag",
        target="health",
        target_type=TargetType.host,
        created_at=datetime.now(timezone.utc),
        evidence=EvidenceBundle(target="health", target_type=TargetType.host, items=items),
        findings=[
            Finding(
                severity="info",
                title="Container-limited runtime view",
                detail="Host-level visibility may be limited.",
            )
        ],
        proposed_plan=Plan(
            plan_id="plan_pr139",
            goal="health",
            session_id="sf_pr139_diag",
            steps=[PlanStep(step_id="1", title="Review", description="Review evidence")],
        ),
        runtime_context={"visibility": "container_limited"},
    )


def _drive_repl(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    inputs: list[str],
    *,
    dispatch_output: str = "",
    patch_diagnose: bool = True,
    patch_dispatch: bool = True,
) -> tuple[str, list[tuple[str, ...]], type[_NoModelProvider]]:
    printed: list[str] = []
    dispatched: list[tuple[str, ...]] = []

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

    class _Provider(_NoModelProvider):
        complete_calls = 0

    def _fake_dispatch(console, argv):  # noqa: ANN001
        dispatched.append(tuple(argv))
        console.print(f"DISPATCH {' '.join(argv)}")
        if dispatch_output:
            console.print(dispatch_output)
            return dispatch_output
        return f"DISPATCH {' '.join(argv)}"

    monkeypatch.setattr(repl, "Console", lambda *a, **k: _Cap())
    monkeypatch.setattr(repl, "_confirm_workspace", lambda *a, **k: True)
    monkeypatch.setattr(repl, "build_provider", lambda *a, **k: _Provider())
    if patch_diagnose:
        monkeypatch.setattr(repl, "diagnose_target", lambda *a, **k: _fake_health_result())
    if patch_dispatch:
        monkeypatch.setattr(repl, "_run_interactive_cli_dispatch", _fake_dispatch)
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
            session_id="sf_pr139_fixture",
            data_dir=tmp_path / "data",
            artifact_dir=tmp_path / "data" / "artifacts" / "sf_pr139_fixture",
            mode="inspect",
        ),
        profile=SimpleNamespace(name="standard", online_allowed=False, allow_shell_raw=False),
        settings=SimpleNamespace(
            model=SimpleNamespace(provider="fake", model="fake", timeout_seconds=30),
        ),
    )
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    repl.start_interactive(runtime, no_trust_cache=True)
    return "\n".join(printed), dispatched, _Provider


def test_summary_with_no_prior_activity_returns_no_evidence_and_safe_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out, dispatched, provider = _drive_repl(
        monkeypatch, tmp_path, ["/summary", "/exit"], patch_diagnose=False, patch_dispatch=False
    )
    assert "No diagnostic evidence has been collected in this interactive session yet." in out
    assert "shellforgeai ops report --brief" in out
    assert "No cleanup/remediation/rollback/Compose mutation executed." in out
    assert dispatched == []
    assert provider.complete_calls == 0


def test_summary_aliases_and_natural_language_route_to_summary() -> None:
    for text in [
        "summary",
        "/summary",
        "session summary",
        "what happened in this session?",
        "what did you check?",
        "what did you find?",
        "what did you refuse?",
        "what should I hand off?",
    ]:
        assert route_input(text).name == "/summary"


def test_summary_alias_prints_same_handoff(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    out, dispatched, provider = _drive_repl(monkeypatch, tmp_path, ["summary", "/exit"])
    assert "Session summary: read-only inspection session." in out
    assert "shellforgeai ops report --brief" in out
    assert dispatched == []
    assert provider.complete_calls == 0


def test_after_ops_report_summary_mentions_ops_report_and_read_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ops_output = "Ops report\nTop suspect: sfai-crashloop\nArtifacts:\n- /data/ops/sf_pr139.json"
    out, dispatched, provider = _drive_repl(
        monkeypatch,
        tmp_path,
        ["ops report --brief", "/summary", "/exit"],
        dispatch_output=ops_output,
    )
    assert dispatched == [("ops", "report", "--brief")]
    assert "ops report" in out.lower()
    assert "top Docker suspect: sfai-crashloop" in out
    assert "shellforgeai triage docker detail sfai-crashloop" in out
    assert "No arbitrary shell executed." in out
    assert provider.complete_calls == 0


def test_after_system_role_summary_mentions_diagnosis_and_container_visibility(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out, _dispatched, provider = _drive_repl(
        monkeypatch, tmp_path, ["what does this system do?", "/summary", "/exit"]
    )
    assert "system role/health" in out
    assert "Container-limited" in out or "container-limited" in out
    assert "sf_pr139_diag" in out or "sf_pr139_fixture" in out
    assert "No cleanup/remediation/rollback/Compose mutation executed." in out
    # The prior natural-language diagnosis may synthesize, but /summary itself must not add a call.
    assert provider.complete_calls <= 1


def test_after_mutation_refusal_summary_mentions_refusal_and_no_action(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out, dispatched, provider = _drive_repl(
        monkeypatch, tmp_path, ["restart compose", "/summary", "/exit"]
    )
    assert "mutation request refused" in out or "service restart/start/stop request refused" in out
    assert "No action was taken." in out
    assert "shellforgeai ops report --brief" in out
    assert dispatched == []
    assert provider.complete_calls == 0


def test_mixed_triage_detail_eligibility_summary_tracks_target_and_safe_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out, dispatched, provider = _drive_repl(
        monkeypatch,
        tmp_path,
        [
            "triage docker detail sfai-crashloop",
            "remediation eligibility --target sfai-crashloop --explain",
            "restart it now",
            "/summary",
            "/exit",
        ],
        dispatch_output="Eligibility: blocked\nSeverity: critical\nEvidence: restart loop",
    )
    assert ("triage", "docker", "detail", "sfai-crashloop") in dispatched
    assert ("remediation", "eligibility", "--target", "sfai-crashloop", "--explain") in dispatched
    assert "triage docker detail sfai-crashloop" in out
    assert "remediation eligibility sfai-crashloop" in out
    assert "remediation eligibility: blocked" in out
    assert "natural-language mutation refused" in out or "mutation request refused" in out
    assert "shellforgeai remediation eligibility --target sfai-crashloop --explain" in out
    assert provider.complete_calls == 0


def test_summary_json_is_strict_json_and_safety_block_present(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out, _dispatched, provider = _drive_repl(monkeypatch, tmp_path, ["summary --json", "/exit"])
    json_text = out[out.index("{") : out.rindex("}") + 1]
    payload = json.loads(json_text)
    assert payload["mode"] == "interactive_session_summary"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["first_safe_command"] == "shellforgeai ops report --brief"
    assert payload["safety"] == {
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "production_restart_executed": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
    }
    assert provider.complete_calls == 0


def test_summary_does_not_rerun_collectors_or_execute_shell_or_subprocess(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("summary must not collect or dispatch")

    monkeypatch.setattr(repl, "diagnose_target", _boom)
    monkeypatch.setattr(repl, "_collect_machine_health", _boom)
    monkeypatch.setattr(repl, "_run_interactive_cli_dispatch", _boom)
    out, dispatched, provider = _drive_repl(
        monkeypatch, tmp_path, ["/summary", "/exit"], patch_diagnose=False, patch_dispatch=False
    )
    assert "No diagnostic evidence" in out
    assert dispatched == []
    assert provider.complete_calls == 0


def test_summary_redacts_raw_destructive_shell_snippets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out, _dispatched, provider = _drive_repl(
        monkeypatch, tmp_path, ["rm -rf /", "/summary", "/exit"]
    )
    summary_part = out.split("Session summary: read-only inspection session.")[-1]
    assert "rm -rf /" not in summary_part
    assert "mutation request refused" in summary_part
    assert "No arbitrary shell executed." in summary_part
    assert provider.complete_calls == 0


def test_summary_static_safety_invariants() -> None:
    sources = [
        Path("src/shellforgeai/interactive/repl.py"),
        Path("src/shellforgeai/interactive/commands.py"),
    ]
    joined = "\n".join(path.read_text(encoding="utf-8") for path in sources)
    assert "shell=True" not in joined
    assert "os.system" not in joined
    for path in sources:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert not (
                    getattr(node.func.value, "id", "") == "subprocess"
                    and node.func.attr in {"run", "Popen", "call", "check_call", "check_output"}
                )
    assert "cleanup execute" not in joined
    assert "remediation execute --confirm" not in joined
    assert "rollback-execute --confirm" not in joined
    assert "docker compose restart" not in joined
    assert "docker restart" not in joined
    assert "production restart" not in joined
