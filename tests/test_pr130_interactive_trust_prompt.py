"""PR130: interactive trust prompt UX and scripted-session safety.

These transcript-style tests prove the interactive workspace trust prompt no
longer eats the first real command, that ``--yes-trust`` provides a safe
script-friendly way to skip the prompt, and that trust never weakens mutation
refusal or shell-execution safety.

Tests stay offline and non-mutating: no live Docker, no real Codex auth, no
internet, no root, no production container access, and no real /data dependency.
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


def _build_runtime(tmp_path: Path) -> SimpleNamespace:
    runtime = SimpleNamespace(
        session=SimpleNamespace(
            session_id="sf_pr130_fixture",
            data_dir=tmp_path / "data",
            artifact_dir=tmp_path / "data" / "artifacts" / "sf_pr130_fixture",
            mode="inspect",
        ),
        profile=SimpleNamespace(name="standard", online_allowed=False, allow_shell_raw=False),
        settings=SimpleNamespace(
            model=SimpleNamespace(provider="fake", model="fake", timeout_seconds=30),
        ),
    )
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    return runtime


def _drive_repl(
    monkeypatch,
    tmp_path: Path,
    inputs: list[str],
    *,
    yes_trust: bool = False,
    no_trust_cache: bool = False,
    trusted: bool = False,
) -> tuple[str, list[tuple[str, ...]], list[str]]:
    """Drive the REAL trust prompt + command loop with scripted stdin.

    Unlike the PR128/PR129 harnesses, this does NOT monkeypatch
    ``_confirm_workspace`` -- the point of PR130 is to exercise the real prompt
    behavior. The workspace trust store is stubbed in-memory.
    """
    printed: list[str] = []
    dispatched: list[tuple[str, ...]] = []
    prompts_seen: list[str] = []

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

    trust_records: dict[str, bool] = {}

    monkeypatch.setattr(repl, "Console", lambda *a, **k: _Cap())
    monkeypatch.setattr(repl, "build_provider", lambda *a, **k: _FakeProvider())
    monkeypatch.setattr(repl, "_run_interactive_cli_dispatch", _fake_dispatch)
    monkeypatch.setattr(
        repl.WorkspaceTrustStore,
        "is_trusted",
        lambda self, p: trusted or trust_records.get(str(Path(p).resolve()), False),
    )
    monkeypatch.setattr(
        repl.WorkspaceTrustStore,
        "trust",
        lambda self, p, v: trust_records.__setitem__(str(Path(p).resolve()), True),
    )
    monkeypatch.setattr(
        repl,
        "StreamRenderer",
        lambda *a, **k: SimpleNamespace(render=lambda text, *_: printed.append(str(text))),
    )

    seq = iter(inputs)

    def _fake_input(prompt: str = "") -> str:
        prompts_seen.append(prompt)
        try:
            return next(seq)
        except StopIteration as exc:
            raise EOFError from exc

    monkeypatch.setattr(builtins, "input", _fake_input)

    runtime = _build_runtime(tmp_path)
    repl.start_interactive(runtime, no_trust_cache=no_trust_cache, yes_trust=yes_trust)
    return "\n".join(printed), dispatched, prompts_seen


# --- A. Already trusted workspace ------------------------------------------------


def test_already_trusted_does_not_prompt_again(monkeypatch, tmp_path) -> None:
    out, _, prompts = _drive_repl(monkeypatch, tmp_path, ["doctor", "/exit"], trusted=True)
    # No trust prompt should ever be shown.
    assert not any("Trust this workspace for this session?" in p for p in prompts)
    assert "Trust this workspace?" not in out
    assert "already trusted" in out.lower()


def test_already_trusted_runs_first_command_doctor(monkeypatch, tmp_path) -> None:
    out, dispatched, _ = _drive_repl(monkeypatch, tmp_path, ["doctor", "/exit"], trusted=True)
    assert ("doctor",) in dispatched
    assert "DISPATCH doctor" in out
    assert "Goodbye." in out


def test_first_command_not_swallowed_in_trusted_scripted_mode(monkeypatch, tmp_path) -> None:
    # First scripted line must reach dispatch, not be consumed as trust input.
    _, dispatched, _ = _drive_repl(
        monkeypatch, tmp_path, ["doctor", "ops report", "/exit"], trusted=True
    )
    assert dispatched[0] == ("doctor",)
    assert ("ops", "report") in dispatched


# --- B. Explicit trust flag ------------------------------------------------------


def test_yes_trust_skips_trust_prompt(monkeypatch, tmp_path) -> None:
    out, _, prompts = _drive_repl(monkeypatch, tmp_path, ["doctor", "/exit"], yes_trust=True)
    assert not any("Trust this workspace for this session?" in p for p in prompts)
    assert "trusted for this session" in out.lower()


def test_yes_trust_runs_first_command_doctor(monkeypatch, tmp_path) -> None:
    _, dispatched, _ = _drive_repl(monkeypatch, tmp_path, ["doctor", "/exit"], yes_trust=True)
    assert dispatched[0] == ("doctor",)


def test_yes_trust_runs_ops_report(monkeypatch, tmp_path) -> None:
    _, dispatched, _ = _drive_repl(
        monkeypatch, tmp_path, ["doctor", "ops report", "/exit"], yes_trust=True
    )
    assert ("doctor",) in dispatched
    assert ("ops", "report") in dispatched


# --- C/D. Trust prompt without flag, declined, invalid ---------------------------


def test_trust_declined_exits_safely(monkeypatch, tmp_path) -> None:
    out, dispatched, _ = _drive_repl(monkeypatch, tmp_path, ["no"])
    assert dispatched == []
    assert "not trusted" in out.lower()
    assert "exiting interactive mode" in out.lower()


def test_trust_empty_response_declines_safely(monkeypatch, tmp_path) -> None:
    out, dispatched, _ = _drive_repl(monkeypatch, tmp_path, [""])
    assert dispatched == []
    assert "not trusted" in out.lower()


def test_invalid_trust_response_shows_clear_guidance(monkeypatch, tmp_path) -> None:
    # "doctor" arrives as the trust answer when untrusted and no flag passed.
    out, dispatched, _ = _drive_repl(monkeypatch, tmp_path, ["doctor"])
    # Not treated as yes -> no command dispatched.
    assert dispatched == []
    # Not silently swallowed -> clear guidance shown.
    assert "please answer y or n" in out.lower()
    assert "commands are accepted after trust is set" in out.lower()


def test_invalid_then_valid_trust_then_command(monkeypatch, tmp_path) -> None:
    # Invalid answer reprompts; a following "y" grants trust; then command runs.
    out, dispatched, _ = _drive_repl(monkeypatch, tmp_path, ["maybe", "y", "doctor", "/exit"])
    assert "please answer y or n" in out.lower()
    assert dispatched == [("doctor",)]


def test_yes_response_grants_trust_and_runs_command(monkeypatch, tmp_path) -> None:
    _, dispatched, _ = _drive_repl(monkeypatch, tmp_path, ["yes", "doctor", "/exit"])
    assert dispatched == [("doctor",)]


# --- E. Safety: trust must not grant mutation ------------------------------------


def test_yes_trust_does_not_bypass_mutation_refusal(monkeypatch, tmp_path) -> None:
    out, dispatched, _ = _drive_repl(
        monkeypatch,
        tmp_path,
        ["remediation execute --confirm", "/exit"],
        yes_trust=True,
    )
    assert dispatched == []
    assert "no action was taken" in out.lower()


def test_compose_restart_still_refused_under_yes_trust(monkeypatch, tmp_path) -> None:
    out, dispatched, _ = _drive_repl(
        monkeypatch,
        tmp_path,
        ["docker compose restart shellforgeai", "/exit"],
        yes_trust=True,
    )
    assert dispatched == []
    assert "no action was taken" in out.lower()
    assert "docker compose restart" not in out.lower()


def test_rm_rf_still_refused_under_yes_trust(monkeypatch, tmp_path) -> None:
    out, dispatched, _ = _drive_repl(monkeypatch, tmp_path, ["rm -rf /", "/exit"], yes_trust=True)
    assert dispatched == []
    assert "no action was taken" in out.lower()


# --- Exit forms ------------------------------------------------------------------


def test_slash_exit_and_plain_exit_work_under_trust(monkeypatch, tmp_path) -> None:
    out, _, _ = _drive_repl(monkeypatch, tmp_path, ["/exit"], yes_trust=True)
    assert "Goodbye." in out

    out, _, _ = _drive_repl(monkeypatch, tmp_path, ["exit"], trusted=True)
    assert "Goodbye." in out


# --- Routing contract sanity (mutation refusal unchanged) ------------------------


def test_route_input_still_refuses_mutation() -> None:
    assert route_input("remediation execute --confirm").name == "mutation_refused"
    assert route_input("docker compose restart shellforgeai").name == "mutation_refused"
    assert route_input("docker restart sfai-crashloop").name == "mutation_refused"


# --- Safety: no shell=True / arbitrary execution introduced ----------------------


def test_no_shell_true_in_touched_sources() -> None:
    source_paths = [
        Path("src/shellforgeai/interactive/repl.py"),
        Path("src/shellforgeai/interactive/workspace.py"),
        Path("src/shellforgeai/cli.py"),
        Path(__file__),
    ]
    for path in source_paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    assert not (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ), path


def test_repl_has_no_arbitrary_execution_primitives() -> None:
    repl_src = Path("src/shellforgeai/interactive/repl.py").read_text(encoding="utf-8")
    assert "subprocess" not in repl_src
    assert "os.system" not in repl_src
    # Trust flag must not introduce any cleanup/remediation/rollback execution.
    low = repl_src.lower()
    assert "cleanup execute" not in low
    assert "remediation execute" not in low
    assert "rollback execute" not in low
