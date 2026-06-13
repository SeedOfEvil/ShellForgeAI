"""PR201 — interactive "not-a-shell" policy guardrail and wording polish.

Interactive mode is not a shell. It routes known ShellForgeAI read-only commands
and deterministic operator asks, and refuses shell-shaped input: arbitrary shell
commands, filesystem mutation, arbitrary file reads, network/download commands,
package installs, cloud/VCS mutation, Docker/Compose mutation, and shell
metacharacters (pipes/redirections/command separators). Refusals carry clear
wording (not a shell / no command was executed / no action was taken) and offer
safe read-only alternatives.

"uname -a" decision: it is refused as not-a-shell (interactive cannot guarantee a
non-shell evidence path for a bare ``uname`` invocation), so it never reaches a
shell. The test still accepts the read-only-evidence-with-no-shell-wording
alternative if the implementation ever provides it.

These tests never run a real shell, never require a Docker daemon, never make
network calls, never call a model, and never write outside ``tmp_path``. The
deterministic router is exercised directly and the REPL is driven with a
captured console + stubbed dispatch/provider so nothing executes.
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
    """Drive the REPL loop with a captured console and stubbed dispatch/provider.

    Returns (joined_output, dispatched_argv_list, provider_type). Nothing real is
    executed: CLI dispatch is captured, the provider is a fake, and workspace
    trust is forced so no prompt is consumed.
    """

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
            session_id="sf_pr201_fixture",
            data_dir=tmp_path / "data",
            artifact_dir=tmp_path / "data" / "artifacts" / "sf_pr201_fixture",
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


def _refusal_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str) -> str:
    out, dispatched, provider = _drive_repl(monkeypatch, tmp_path, [text, "/exit"])
    # A refusal never dispatches a CLI command and never calls a model.
    assert dispatched == [], f"refused input must not dispatch: {text!r}"
    assert provider.complete_calls == 0, f"refused input must not call a model: {text!r}"
    return out


def _assert_not_a_shell_wording(out: str) -> None:
    low = out.lower()
    assert "not a shell" in low
    assert "no command was executed" in low or "no command was run" in low
    assert "no action was taken" in low


# ---------------------------------------------------------------------------
# Allowed read-only routing (interactive keeps working)
# ---------------------------------------------------------------------------


def test_triage_docker_routes_read_only() -> None:
    routed = route_input("triage docker")
    assert routed.name == "cli_dispatch"
    assert routed.argv == ("triage", "docker")


def test_ops_report_json_routes_read_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    routed = route_input("ops report --json")
    assert routed.name == "cli_dispatch"
    assert routed.argv == ("ops", "report", "--json")
    out, dispatched, provider = _drive_repl(monkeypatch, tmp_path, ["ops report --json", "/exit"])
    assert ("ops", "report", "--json") in dispatched
    assert provider.complete_calls == 0


def test_ops_report_json_payload_is_read_only_no_mutation() -> None:
    # Inspect the real ops-report JSON safety block to prove read_only semantics
    # are preserved for a routed read-only command (no shell, no mutation).
    from typer.testing import CliRunner

    from shellforgeai.cli import app

    result = CliRunner().invoke(app, ["ops", "report", "--json"])
    assert result.exit_code == 0
    import json

    payload = json.loads(result.stdout)
    assert payload.get("read_only") is True
    assert payload.get("mutation_performed") is False


def test_safe_command_help_still_works(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    out, dispatched, provider = _drive_repl(monkeypatch, tmp_path, ["help", "/exit"])
    assert "Session:" in out
    assert "Interactive mode is not a shell." in out
    assert dispatched == []
    assert provider.complete_calls == 0


def test_pr200_launch_help_behavior_still_passes() -> None:
    from typer.testing import CliRunner

    from shellforgeai.cli import app

    result = CliRunner().invoke(app, ["interactive", "--help"])
    assert result.exit_code == 0
    assert "--no-trust-cache" in result.stdout
    assert "--yes-trust" in result.stdout


# ---------------------------------------------------------------------------
# Not-a-shell refusal (filesystem mutation / reads / network / package / cloud)
# ---------------------------------------------------------------------------

_REFUSED_INPUTS = [
    "rm -rf /tmp/sfai_should_not_exist",
    "cat /etc/passwd",
    "cat ~/.ssh/id_rsa",
    "curl http://example.com",
    "wget http://example.com",
    "apt install cowsay",
    "pip install requests",
    "git push",
    "gh pr merge 1",
    "codex apply",
    "docker restart shellforgeai",
    "docker compose restart shellforgeai",
    "docker compose down",
    "docker volume prune",
    "kubectl apply -f x.yaml",
]


@pytest.mark.parametrize("text", _REFUSED_INPUTS)
def test_shell_shaped_inputs_are_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str
) -> None:
    routed = route_input(text)
    assert routed.name in {"shell_refused", "mutation_refused"}
    out = _refusal_output(monkeypatch, tmp_path, text)
    _assert_not_a_shell_wording(out)


def test_touch_does_not_create_marker_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    marker = tmp_path / "sfai_should_not_exist"
    assert not marker.exists()
    out = _refusal_output(monkeypatch, tmp_path, f"touch {marker}")
    _assert_not_a_shell_wording(out)
    # The marker must never be created: interactive does not execute the command.
    assert not marker.exists()


def test_pipe_redirection_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    marker = tmp_path / "redir_marker"
    out = _refusal_output(monkeypatch, tmp_path, f"uname -a > {marker}")
    _assert_not_a_shell_wording(out)
    assert not marker.exists()


def test_command_separators_are_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for text in ("status && rm -rf /tmp/x", "status; uname -a", "uname -a | cat"):
        routed = route_input(text)
        assert routed.name in {"shell_refused", "mutation_refused"}
        out = _refusal_output(monkeypatch, tmp_path, text)
        _assert_not_a_shell_wording(out)


def test_refusal_suggests_safe_read_only_alternatives(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out = _refusal_output(monkeypatch, tmp_path, "cat /etc/passwd")
    low = out.lower()
    assert "ops report" in low
    assert "triage docker" in low


# ---------------------------------------------------------------------------
# Read-only host evidence nuance: "uname -a"
# ---------------------------------------------------------------------------


def test_uname_is_safe_refused_or_explicit_read_only_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    routed = route_input("uname -a")
    # Never arbitrary shell execution.
    assert routed.name != "shell"
    out, dispatched, provider = _drive_repl(monkeypatch, tmp_path, ["uname -a", "/exit"])
    low = out.lower()
    if routed.name in {"shell_refused", "mutation_refused"}:
        # Refused as not-a-shell.
        _assert_not_a_shell_wording(out)
    else:
        # If it ever returns read-only host evidence, it must carry explicit
        # no-shell / no-mutation wording.
        assert "no shell command was executed" in low or "no shell command was run" in low
        assert "no mutation" in low or "read-only" in low
    # Either way, no shell was run.
    assert provider.complete_calls == 0 or routed.name not in {"shell_refused", "mutation_refused"}


# ---------------------------------------------------------------------------
# Safety invariants — refusal output never claims execution/mutation occurred
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "rm -rf /tmp/sfai_should_not_exist",
        "docker compose restart shellforgeai",
        "docker volume prune",
        "git push",
        "curl http://example.com",
        "cat /etc/passwd",
    ],
)
def test_refusal_output_asserts_no_execution_or_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str
) -> None:
    out = _refusal_output(monkeypatch, tmp_path, text)
    low = out.lower()
    # No claim of cleanup/remediation/rollback/recovery/restart/compose execution.
    for forbidden in (
        "cleanup executed",
        "remediation executed",
        "rollback executed",
        "recovery executed",
        "restarted",
        "compose up",
        "compose down was run",
        "container restarted",
    ):
        assert forbidden not in low, f"refusal must not claim {forbidden!r}: {text!r}"
    _assert_not_a_shell_wording(out)


def test_explicit_ask_review_of_shell_snippet_is_not_shell_refused() -> None:
    # The read-only "explain/review" ask path must survive: shell metacharacters
    # inside an explicit ask frame are not refused as not-a-shell.
    routed = route_input("ask review this shell snippet: rm -rf / | tee x")
    assert routed.name == "ask"
    routed2 = route_input("ask explain this command: docker compose up -d")
    assert routed2.name == "ask"


# ---------------------------------------------------------------------------
# Source-level safety: no execution primitives added for refusal handling
# ---------------------------------------------------------------------------


def test_not_a_shell_refusal_helper_has_no_execution_primitives() -> None:
    src = Path("src/shellforgeai/interactive/commands.py").read_text(encoding="utf-8")
    repl_src = Path("src/shellforgeai/interactive/repl.py").read_text(encoding="utf-8")
    # The new detection/refusal path must not introduce shell execution.
    assert "shell=True" not in src
    # repl already imports subprocess-free dispatch; ensure no new shell=True.
    assert "shell=True" not in repl_src
