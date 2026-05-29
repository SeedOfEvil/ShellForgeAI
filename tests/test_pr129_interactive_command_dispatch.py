"""PR129: interactive command dispatch polish.

Transcript-style coverage for safe ShellForgeAI command dispatch from the
interactive REPL. Tests stay offline and non-mutating by stubbing the in-process
CLI dispatcher; they assert argv routing, refusal behavior, and session helpers.
"""

from __future__ import annotations

import ast
import builtins
from pathlib import Path
from types import SimpleNamespace

from shellforgeai.interactive import repl
from shellforgeai.interactive.commands import route_input
from shellforgeai.llm.schemas import ModelResponse


class _FakeProvider:
    def complete(self, request):  # noqa: ANN001
        return ModelResponse(provider="fake", model="fake", text="Safe ask fallback.", ok=True)

    def doctor(self):
        return {"provider": "fake", "ready": "yes", "auth_cache_present": False}


def _drive_repl(
    monkeypatch, tmp_path: Path, inputs: list[str]
) -> tuple[str, list[tuple[str, ...]]]:
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

    def _fake_dispatch(console, argv):  # noqa: ANN001
        dispatched.append(tuple(argv))
        console.print(f"DISPATCH {' '.join(argv)}")

    monkeypatch.setattr(repl, "Console", lambda *a, **k: _Cap())
    monkeypatch.setattr(repl, "_confirm_workspace", lambda *a, **k: True)
    monkeypatch.setattr(repl, "build_provider", lambda *a, **k: _FakeProvider())
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
            session_id="sf_pr129_fixture",
            data_dir=tmp_path / "data",
            artifact_dir=tmp_path / "data" / "artifacts" / "sf_pr129_fixture",
            mode="inspect",
        ),
        profile=SimpleNamespace(name="standard", online_allowed=False, allow_shell_raw=False),
        settings=SimpleNamespace(
            model=SimpleNamespace(provider="fake", model="fake", timeout_seconds=30),
        ),
    )
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    repl.start_interactive(runtime, no_trust_cache=True)
    return "\n".join(printed), dispatched


def test_interactive_core_safe_commands_dispatch(monkeypatch, tmp_path) -> None:
    commands = [
        "doctor",
        "model doctor",
        "ops report",
        "triage docker",
        "triage docker detail sfai-crashloop",
        "v1 check quick",
        "v1 check standard",
        "remediation self-test quick",
        "remediation eligibility --target sfai-crashloop --explain",
        "/exit",
    ]
    out, dispatched = _drive_repl(monkeypatch, tmp_path, commands)
    assert dispatched == [
        ("doctor",),
        ("model", "doctor"),
        ("ops", "report"),
        ("triage", "docker"),
        ("triage", "docker", "detail", "sfai-crashloop"),
        ("v1", "check", "--profile", "quick"),
        ("v1", "check", "--profile", "standard"),
        ("remediation", "self-test", "--profile", "quick"),
        ("remediation", "eligibility", "--target", "sfai-crashloop", "--explain"),
    ]
    assert "DISPATCH doctor" in out
    assert "Goodbye." in out


def test_interactive_additional_safe_commands_and_aliases_dispatch(monkeypatch, tmp_path) -> None:
    commands = [
        "version",
        "status",
        "ops report --json",
        "ops report history",
        "ops report compare-latest",
        "v1 check full",
        "remediation self-test standard",
        "remediation self-test full",
        "exit",
    ]
    _, dispatched = _drive_repl(monkeypatch, tmp_path, commands)
    assert dispatched == [
        ("version",),
        ("ops", "report"),
        ("ops", "report", "--json"),
        ("ops", "report", "history"),
        ("ops", "report", "compare-latest"),
        ("v1", "check", "--profile", "full"),
        ("remediation", "self-test", "--profile", "standard"),
        ("remediation", "self-test", "--profile", "full"),
    ]


def test_unknown_command_falls_back_safely_without_dispatch(monkeypatch, tmp_path) -> None:
    out, dispatched = _drive_repl(monkeypatch, tmp_path, ["frobnicate subsystem", "/exit"])
    assert dispatched == []
    assert "Safe ask fallback." in out or "model-assisted answer unavailable" in out.lower()


def test_dangerous_command_like_inputs_are_refused(monkeypatch, tmp_path) -> None:
    dangerous = [
        "docker compose restart shellforgeai",
        "docker restart sfai-crashloop",
        "rm -rf /",
        "cleanup execute",
        "remediation execute --confirm",
    ]
    out, dispatched = _drive_repl(monkeypatch, tmp_path, [*dangerous, "/exit"])
    low = out.lower()
    assert dispatched == []
    assert low.count("no action was taken") >= len(dangerous)
    assert "safe read-only alternatives" in low
    assert "does not execute shell" in low


def test_pending_and_exit_plain_and_slash_forms(monkeypatch, tmp_path) -> None:
    out, dispatched = _drive_repl(monkeypatch, tmp_path, ["pending", "/pending", "exit"])
    assert dispatched == []
    assert out.count("No pending investigation.") == 2
    assert "Goodbye." in out

    out, dispatched = _drive_repl(monkeypatch, tmp_path, ["/exit"])
    assert dispatched == []
    assert "Goodbye." in out


def test_route_input_command_dispatch_contract() -> None:
    assert route_input("doctor").argv == ("doctor",)
    assert route_input("model doctor").argv == ("model", "doctor")
    assert route_input("triage docker detail sfai-crashloop").argv == (
        "triage",
        "docker",
        "detail",
        "sfai-crashloop",
    )
    assert route_input("remediation execute --confirm").name == "mutation_refused"
    assert route_input("docker restart sfai-crashloop").name == "mutation_refused"


def test_dispatch_source_has_no_shell_true_or_arbitrary_subprocess() -> None:
    source_paths = [
        Path("src/shellforgeai/interactive/commands.py"),
        Path("src/shellforgeai/interactive/repl.py"),
    ]
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
    repl_src = Path("src/shellforgeai/interactive/repl.py").read_text(encoding="utf-8")
    assert "subprocess" not in repl_src
    assert "os.system" not in repl_src
