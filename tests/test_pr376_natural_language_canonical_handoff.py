from __future__ import annotations

import builtins
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.commands import ask as ask_module
from shellforgeai.core import linux_advisory_planning, windows_advisory_planning
from shellforgeai.core.windows_operator_ux import WINDOWS_OPERATOR_INTENT_HANDOFF
from shellforgeai.interactive import repl
from shellforgeai.interactive.commands import route_input


@pytest.mark.parametrize(
    ("prompt", "name", "argv"),
    (
        ("Give me an operator handoff", "cli_dispatch", ("handoff",)),
        ("Summarize for handoff", "cli_dispatch", ("handoff",)),
        ("What should I tell the next operator?", "cli_dispatch", ("handoff",)),
        ("save handoff", "cli_dispatch", ("handoff", "--save")),
        ("save the handoff", "cli_dispatch", ("handoff", "--save")),
        ("Give me a handoff and restart it", "mutation_refused", ()),
        ("Summarize for handoff then apply the fix", "mutation_refused", ()),
    ),
)
def test_maintained_final_routes_are_preserved(
    prompt: str, name: str, argv: tuple[str, ...]
) -> None:
    route = route_input(prompt)
    assert (route.name, route.argv) == (name, argv)


@pytest.mark.parametrize("system", ("Linux", "Windows"))
def test_ask_pure_handoff_uses_platform_canonical_orchestration(
    monkeypatch: pytest.MonkeyPatch, system: str
) -> None:
    calls = {"linux": 0, "windows": 0}
    monkeypatch.setattr(ask_module.platform, "system", lambda: system)

    def linux(_runtime: Any, target: str, **_kwargs: Any) -> str:
        calls["linux"] += 1
        assert target == "host"
        return "# Canonical Linux OperatorSolution\n"

    def windows(route: Any) -> str:
        calls["windows"] += 1
        assert route.intent == WINDOWS_OPERATOR_INTENT_HANDOFF
        return "# Canonical Windows OperatorSolution\n"

    monkeypatch.setattr(linux_advisory_planning, "render_linux_advisory_plan", linux)
    monkeypatch.setattr(windows_advisory_planning, "render_windows_advisory_plan", windows)
    result = CliRunner().invoke(app, ["ask", "Summarize for handoff"])
    assert result.exit_code == 0
    assert result.stdout == f"# Canonical {system} OperatorSolution\n"
    assert calls == (
        {"linux": 1, "windows": 0} if system == "Linux" else {"linux": 0, "windows": 1}
    )


def _runtime(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        session=SimpleNamespace(session_id="pr376", data_dir=tmp_path, mode="inspect"),
        profile=SimpleNamespace(name="standard", online_allowed=False, allow_shell_raw=False),
        settings=SimpleNamespace(model=SimpleNamespace(provider="none", model="none")),
    )


@pytest.mark.parametrize("system", ("Linux", "Windows"))
def test_interactive_pure_handoff_uses_platform_canonical_orchestration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, system: str
) -> None:
    printed: list[str] = []
    calls = {"linux": 0, "windows": 0, "parity": 0}

    class Console:
        def print(self, *args: Any, **_kwargs: Any) -> None:
            printed.append(" ".join(str(arg) for arg in args))

    inputs = iter(("Summarize for handoff", "/exit"))
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(inputs))
    monkeypatch.setattr(repl, "Console", Console)
    monkeypatch.setattr(repl, "_confirm_workspace", lambda *_a, **_k: True)
    monkeypatch.setattr(repl.WorkspaceTrustStore, "is_trusted", lambda *_a: True)
    monkeypatch.setattr(repl.platform, "system", lambda: system)
    monkeypatch.setattr(
        repl,
        "_render_windows_parity_prompt",
        lambda *_a, **_k: calls.__setitem__("parity", calls["parity"] + 1),
    )
    monkeypatch.setattr(
        linux_advisory_planning,
        "render_linux_advisory_plan",
        lambda *_a, **_k: calls.__setitem__("linux", calls["linux"] + 1) or "linux canonical",
    )
    monkeypatch.setattr(
        windows_advisory_planning,
        "render_windows_advisory_plan",
        lambda route: (
            calls.__setitem__("windows", calls["windows"] + 1)
            or ("windows canonical" if route.intent == WINDOWS_OPERATOR_INTENT_HANDOFF else "wrong")
        ),
    )
    repl.start_interactive(_runtime(tmp_path), yes_trust=True)
    assert calls == (
        {"linux": 1, "windows": 0, "parity": 0}
        if system == "Linux"
        else {"linux": 0, "windows": 1, "parity": 0}
    )
    assert any(f"{system.casefold()} canonical" in line for line in printed)


def test_save_and_no_evidence_do_not_use_canonical_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("canonical natural-language handoff must be bypassed")

    monkeypatch.setattr(linux_advisory_planning, "render_linux_advisory_plan", forbidden)
    monkeypatch.setattr(windows_advisory_planning, "render_windows_advisory_plan", forbidden)
    saved = CliRunner().invoke(app, ["ask", "save handoff"])
    assert saved.exit_code == 0
    assert "Read-only operator handoff (deterministic ask routing):" in saved.stdout
    no_evidence = CliRunner().invoke(app, ["ask", "give me an operator handoff", "--no-evidence"])
    assert no_evidence.exit_code == 1


@pytest.mark.parametrize(
    ("prompt", "marker"),
    (
        ("show handoff history", "Read-only handoff history"),
        ("what changed since last handoff", "Read-only handoff compare-latest"),
        ("compare latest handoffs", "Read-only handoff compare-latest"),
        ("export handoff", "Handoff artifact lifecycle"),
        ("validate handoff", "Handoff artifact lifecycle"),
        ("create receipt audit bundle for support handoff", "receipt audit bundle guidance"),
        ("make a support packet for receipt audit", "receipt audit bundle guidance"),
    ),
)
def test_specialized_handoff_authorities_precede_canonical_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt: str, marker: str
) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("generic canonical handoff must not steal a specialized route")

    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(linux_advisory_planning, "render_linux_advisory_plan", forbidden)
    monkeypatch.setattr(windows_advisory_planning, "render_windows_advisory_plan", forbidden)
    result = CliRunner().invoke(app, ["ask", prompt])
    assert result.exit_code == 0
    assert marker in result.stdout
    assert "# ShellForgeAI Operator Solution" not in result.stdout


def test_windows_orchestration_failure_is_bounded_for_handoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        windows_advisory_planning,
        "build_windows_evidence_context",
        lambda: (_ for _ in ()).throw(RuntimeError("secret/path")),
    )
    route = SimpleNamespace(intent=WINDOWS_OPERATOR_INTENT_HANDOFF, host_is_windows=True)
    rendered = windows_advisory_planning.render_windows_advisory_plan(route)
    assert rendered.startswith("Windows operator handoff unavailable.")
    assert "No model was called and no action was taken." in rendered
    assert "secret/path" not in rendered
