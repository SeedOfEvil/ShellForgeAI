"""PR128: V1 interactive transcript regression harness.

These transcript-style tests stay offline and non-mutating: no live Docker,
no real Codex auth, no internet, no root, no production container access, and
no real /data dependency.
"""

from __future__ import annotations

import ast
import builtins
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.evidence import EvidenceBundle, EvidenceCategory, EvidenceItem, TargetType
from shellforgeai.interactive import repl
from shellforgeai.llm.schemas import ModelResponse

runner = CliRunner()

FIXTURE_CHECKS = [
    {
        "tool": "system.cpu_memory",
        "status": "ok",
        "summary": "cpus=4 mem=2.0GiB/8.0GiB swap=0B/2.0GiB",
    },
    {"tool": "host.resources", "status": "ok", "summary": "loadavg 3.10 2.50 1.90"},
    {"tool": "disk.usage", "status": "ok", "summary": "/ 42% used"},
    {"tool": "disk.inodes", "status": "ok", "summary": "/ 8% used"},
    {
        "tool": "storage.pressure",
        "status": "ok",
        "summary": "io_some_avg10=1.7 io_some_avg60=1.2 io_some_avg300=0.5",
    },
    {"tool": "system.container_detect", "status": "ok", "summary": "docker container=yes"},
    {"tool": "process.top", "status": "ok", "summary": "top: pid 42 postgres using 31% cpu"},
]

FORBIDDEN_OUTPUT = (
    "cleanup execute",
    "remediation execute",
    "rollback execute",
    "docker compose restart",
    "compose restart",
    "production restart",
    "shell=True",
    "thread.started",
    "turn.started",
    "turn.failed",
    "refresh token already used",
)


def _fake_result(target: str = "performance") -> SimpleNamespace:
    items = [
        EvidenceItem(
            source=c["tool"],
            category=EvidenceCategory.host,
            ok=c["status"] == "ok",
            title=c["tool"],
            summary=c["summary"],
            content=c["summary"],
            metadata={"status": c["status"]},
        )
        for c in FIXTURE_CHECKS
    ]
    bundle = EvidenceBundle(
        target=target,
        target_type=TargetType.host,
        created_at=datetime.now(timezone.utc),
        items=items,
    )
    plan = SimpleNamespace(model_dump_json=lambda indent=2: "{}")
    finding = SimpleNamespace(
        title="Fixture evidence shows mild storage/I/O pressure with CPU and memory headroom",
        model_dump=lambda: {"title": "Fixture finding"},
    )
    return SimpleNamespace(
        session_id="sf_pr128_fixture",
        target=target,
        target_type=TargetType.host,
        created_at=datetime.now(timezone.utc),
        evidence=bundle,
        proposed_plan=plan,
        findings=[finding],
        runtime_context={"visibility": "container_limited", "container": True},
    )


class _FakeProvider:
    def complete(self, request):  # noqa: ANN001
        return ModelResponse(
            provider="fake",
            model="fake",
            text="Read-only model summary from fixture evidence.",
            ok=True,
        )

    def doctor(self):
        return {"provider": "fake", "ready": "yes"}


class _AuthFailureProvider:
    def complete(self, request):  # noqa: ANN001
        jsonl = "\n".join(
            [
                '{"type":"thread.started"}',
                '{"type":"turn.started"}',
                '{"type":"error", "message":"refresh token already used"}',
                '{"type":"turn.failed"}',
            ]
        )
        return ModelResponse(
            provider="codex",
            model="gpt-test",
            text=jsonl,
            ok=False,
            error="codex auth failed; run: codex login --device-auth",
            raw={"stdout_jsonl": jsonl, "stderr": ""},
        )


def _drive_repl(monkeypatch, tmp_path: Path, inputs: list[str], provider=None) -> str:
    monkeypatch.setattr(repl, "_confirm_workspace", lambda *a, **k: True)
    monkeypatch.setattr(repl, "build_provider", lambda *a, **k: provider or _FakeProvider())
    monkeypatch.setattr(
        repl, "diagnose_target", lambda runtime, target, *a, **k: _fake_result(target)
    )
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
        repl,
        "StreamRenderer",
        lambda *a, **k: SimpleNamespace(render=lambda text, *_: printed.append(str(text))),
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
            session_id="sf_pr128_fixture",
            data_dir=tmp_path / "data",
            artifact_dir=tmp_path / "data" / "artifacts" / "sf_pr128_fixture",
            mode="inspect",
        ),
        profile=SimpleNamespace(name="standard", online_allowed=False, allow_shell_raw=False),
        settings=SimpleNamespace(
            model=SimpleNamespace(provider="fake", model="fake", timeout_seconds=30),
        ),
    )
    runtime.session.data_dir.mkdir(parents=True, exist_ok=True)
    repl.start_interactive(runtime, no_trust_cache=True)
    return "\n".join(printed)


def _assert_no_forbidden(text: str) -> None:
    low = text.lower()
    for forbidden in FORBIDDEN_OUTPUT:
        assert forbidden.lower() not in low


def test_slow_system_transcript_stores_and_reuses_latest_context(monkeypatch, tmp_path) -> None:
    out = _drive_repl(
        monkeypatch,
        tmp_path,
        [
            "this system is feeling a bit slow",
            "what did you find?",
            "why is it slow?",
            "/exit",
        ],
    )
    low = out.lower()
    assert "collected" in low and "read-only evidence" in low
    assert "artifacts" in low and "evidence.json" in low and "summary.md" in low
    assert "latest performance diagnosis" in low
    assert "load" in low and "3.10" in out
    assert "cpu" in low and "memory" in low
    assert "disk" in low and "42%" in out
    assert "storage/i/o" in low or "storage" in low
    assert "top process" in low or "postgres" in low
    assert "limitation" in low or "container-limited" in low
    assert "no context" not in low
    _assert_no_forbidden(out)


def test_system_role_health_transcript_auto_collects_then_reuses_context(
    monkeypatch, tmp_path
) -> None:
    out = _drive_repl(
        monkeypatch,
        tmp_path,
        ["what does this system do?", "is it running normally?", "/exit"],
    )
    low = out.lower()
    assert "collected" in low and "read-only evidence" in low
    assert "visibility: container-limited" in low
    assert "container-limited view" in low or "container/runtime" in low
    assert "cannot fully infer" in low or "host-level" in low or "may not be visible" in low
    assert "confidence" in low
    assert "full host" not in low
    assert "complete host" not in low
    _assert_no_forbidden(out)


def test_pending_followup_phrases_resolve_to_same_read_only_path(monkeypatch, tmp_path) -> None:
    for phrase in ("get that info", "then get that info", "do that", "proceed", "dig deeper"):
        out = _drive_repl(
            monkeypatch,
            tmp_path,
            ["this system is feeling a bit slow", phrase, "/exit"],
        )
        low = out.lower()
        assert f'i’ll treat "{phrase}" as a read-only follow-up'.lower() in low
        assert "deeper investigation complete" in low
        assert "no mutation will be performed" in low
        assert "no command was executed" not in low
        assert "do not know what that refers to" not in low
        _assert_no_forbidden(out)


def test_no_context_followup_phrases_give_safe_guidance(monkeypatch, tmp_path) -> None:
    for phrase in ("get that info", "then get that info", "do that"):
        out = _drive_repl(monkeypatch, tmp_path, [phrase, "/exit"])
        low = out.lower()
        assert "no prior requested read-only info" in low
        assert "shellforgeai ops report" in low
        assert "shellforgeai triage docker" in low or "what does this system do" in low
        assert "collected" not in low
        _assert_no_forbidden(out)


def test_interactive_paste_guard_and_mutation_refusals(monkeypatch, tmp_path) -> None:
    for user_input in ("rm -rf /", "docker compose restart shellforgeai", "fix it"):
        out = _drive_repl(monkeypatch, tmp_path, [user_input, "/exit"])
        low = out.lower()
        assert (
            "no command was executed" in low
            or "no action was taken" in low
            or "can't run fixes or mutations" in low
        )
        assert "proposal" not in low
        _assert_no_forbidden(out.replace("No command was executed.", ""))


def test_clean_up_and_restart_compose_refused_by_ask_without_execution(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        "shellforgeai.cli.build_provider",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("model should not be called")),
    )
    res = runner.invoke(app, ["ask", "clean up docker and restart compose"])
    assert res.exit_code == 0
    low = res.stdout.lower()
    assert "refus" in low or "cannot" in low or "not allowed" in low
    assert "cleanup execute" not in low
    assert "remediation execute" not in low
    assert "rollback execute" not in low
    assert "docker compose restart" not in low


def test_codex_jsonl_auth_failure_is_suppressed_in_assessment(monkeypatch, tmp_path) -> None:
    out = _drive_repl(
        monkeypatch,
        tmp_path,
        ["this system is feeling a bit slow", "/exit"],
        provider=_AuthFailureProvider(),
    )
    low = out.lower()
    assert "model-assisted assessment unavailable" in low
    assert "codex login --device-auth" in low
    assert "deterministic" in low or "assessment" in low
    assert "collected" in low and "read-only evidence" in low
    assert "thread.started" not in out
    assert "turn.started" not in out
    assert "turn.failed" not in out
    assert "refresh token already used" not in low


def test_container_limited_truthfulness_for_system_role(monkeypatch, tmp_path) -> None:
    out = _drive_repl(monkeypatch, tmp_path, ["what does this system do?", "/exit"])
    low = out.lower()
    assert "container-limited" in low or "container/runtime" in low
    assert "may not be visible" in low or "cannot fully infer" in low or "host-level" in low
    assert "full host view" not in low
    assert "complete host visibility" not in low


def test_no_shell_true_or_mutating_subprocess_patterns_introduced() -> None:
    source_paths = list(Path("src").rglob("*.py")) + [Path(__file__)]
    for path in source_paths:
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    assert not (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ), path
    changed_text = Path(__file__).read_text(encoding="utf-8").lower()
    assert "subprocess" + ".run" not in changed_text
    assert "subprocess" + ".popen" not in changed_text
