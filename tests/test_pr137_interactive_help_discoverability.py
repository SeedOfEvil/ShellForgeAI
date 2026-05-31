"""PR137: interactive help and safe-command discoverability.

The REPL help is deterministic local text. These tests keep it aligned with the
safe command-style allowlist while proving help aliases do not call the model,
dispatch CLI work, or expand mutation execution paths.
"""

from __future__ import annotations

import builtins
from pathlib import Path
from types import SimpleNamespace

import pytest

from shellforgeai.interactive import repl
from shellforgeai.interactive.commands import route_input
from shellforgeai.llm.schemas import ModelResponse


class _FakeProvider:
    complete_calls = 0

    def complete(self, request):  # noqa: ANN001
        type(self).complete_calls += 1
        return ModelResponse(provider="fake", model="fake", text="Safe ask fallback.", ok=True)

    def doctor(self):
        return {"provider": "fake", "ready": "yes", "auth_cache_present": False}


def _drive_repl(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, inputs: list[str]
) -> tuple[str, list[tuple[str, ...]], type[_FakeProvider]]:
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

    class _Provider(_FakeProvider):
        complete_calls = 0

    def _fake_dispatch(console, argv):  # noqa: ANN001
        dispatched.append(tuple(argv))
        console.print(f"DISPATCH {' '.join(argv)}")
        return f"DISPATCH {' '.join(argv)}"

    monkeypatch.setattr(repl, "Console", lambda *a, **k: _Cap())
    monkeypatch.setattr(repl, "_confirm_workspace", lambda *a, **k: True)
    monkeypatch.setattr(repl, "build_provider", lambda *a, **k: _Provider())
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
            session_id="sf_pr137_fixture",
            data_dir=tmp_path / "data",
            artifact_dir=tmp_path / "data" / "artifacts" / "sf_pr137_fixture",
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


def _help_for(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, alias: str) -> str:
    out, dispatched, provider = _drive_repl(monkeypatch, tmp_path, [alias, "/exit"])
    assert dispatched == []
    assert provider.complete_calls == 0
    return out


@pytest.mark.parametrize("alias", ["help", "/help", "?", "commands", "what can I do?"])
def test_interactive_help_aliases_render_without_dispatch_or_model(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, alias: str
) -> None:
    out = _help_for(monkeypatch, tmp_path, alias)
    assert "ShellForgeAI interactive help" in out
    assert "Fast status:" in out
    assert "Safety:" in out


@pytest.mark.parametrize("alias", ["help", "/help", "?", "commands", "what can I do?"])
def test_help_aliases_route_to_slash_help(alias: str) -> None:
    routed = route_input(alias)
    assert routed.name == "/help"


def test_help_lists_supported_safe_interactive_forms(monkeypatch, tmp_path) -> None:
    out = _help_for(monkeypatch, tmp_path, "help")
    for expected in [
        "ops report --brief",
        "ops report",
        "ops report --json",
        "v1 check quick",
        "v1 check --profile quick --json",
        "doctor",
        "model doctor",
        "triage docker detail <target>",
        "triage docker detail <target> --json",
        "diagnose <target>",
        "ops report --save",
        "ops report history --limit 5",
        "ops report compare-latest",
        "remediation self-test quick",
        "remediation eligibility --target <target> --explain",
        "remediation eligibility --target <target> --explain --json",
        "what did you find?",
        "get that info",
        "dig deeper",
        "no novel, what is on fire?",
        "quick status only",
    ]:
        assert expected in out


def test_help_includes_safety_note_and_refused_examples_only(monkeypatch, tmp_path) -> None:
    out = _help_for(monkeypatch, tmp_path, "commands")
    assert "Interactive mode is not a shell." in out
    assert "No Docker/Compose/remediation/cleanup command runs from natural language." in out
    assert "Mutation requires governed explicit workflows." in out
    assert "Refused here (not run):" in out

    refused_section = out.split("Refused here (not run):", maxsplit=1)[1].split(
        "Safety:", maxsplit=1
    )[0]
    available_section = out.split("Refused here (not run):", maxsplit=1)[0]

    for refused in [
        "docker restart <container>",
        "docker compose restart <service>",
        "cleanup execute",
        "remediation execute --confirm",
        "rollback-execute --confirm",
        "rm -rf /",
    ]:
        assert refused in refused_section

    for forbidden_normal in [
        "docker restart",
        "docker compose restart",
        "cleanup execute --confirm",
        "remediation execute --confirm",
    ]:
        assert forbidden_normal not in available_section


def test_help_output_is_bounded_and_local_non_mutating(monkeypatch, tmp_path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    before_paths = {path.relative_to(data_dir) for path in data_dir.rglob("*")}
    out = _help_for(monkeypatch, tmp_path, "?")
    after_paths = {path.relative_to(data_dir) for path in data_dir.rglob("*")}
    assert len(out.splitlines()) <= 65
    assert "DISPATCH" not in out
    assert after_paths == before_paths


def test_unknown_command_behavior_remains_safe(monkeypatch, tmp_path) -> None:
    out, dispatched, provider = _drive_repl(monkeypatch, tmp_path, ["/definitely-unknown", "/exit"])
    assert dispatched == []
    assert provider.complete_calls == 0
    assert "Unknown command: /definitely-unknown" in out
    assert "Type /help for available commands." in out


@pytest.mark.parametrize(
    "text",
    [
        "docker restart sfai-crashloop",
        "docker compose restart shellforgeai",
        "cleanup execute --confirm",
        "remediation execute --confirm",
        "rollback-execute --confirm",
        "rm -rf /",
    ],
)
def test_mutation_refusal_routes_still_win(text: str) -> None:
    assert route_input(text).name == "mutation_refused"
