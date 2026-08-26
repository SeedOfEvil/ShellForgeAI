from __future__ import annotations

import ast
import builtins
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core import linux_advisory_planning
from shellforgeai.core.ask_routing import select_linux_plan_help_target
from shellforgeai.core.linux_advisory_planning import LINUX_ADVISORY_FAILURE
from shellforgeai.interactive import repl


def _runtime(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        session=SimpleNamespace(
            session_id="sf_pr375",
            data_dir=tmp_path,
            artifact_dir=tmp_path / "artifacts",
            mode="inspect",
        ),
        profile=SimpleNamespace(name="standard", online_allowed=False, allow_shell_raw=False),
        settings=SimpleNamespace(
            model=SimpleNamespace(provider="forbidden", model="forbidden", timeout_seconds=1)
        ),
    )


def test_helper_collects_builds_and_renders_exactly_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, Any]] = []
    diagnosis = object()
    solution = object()

    def diagnose(runtime: Any, target: str, *, online: bool, since: str) -> object:
        calls.append(("diagnose", (runtime, target, online, since)))
        return diagnosis

    def build(value: object) -> object:
        calls.append(("build", value))
        assert value is diagnosis
        return solution

    def render(value: object) -> str:
        calls.append(("render", value))
        assert value is solution
        return "# Operator solution\n"

    monkeypatch.setattr(linux_advisory_planning, "diagnose_target", diagnose)
    monkeypatch.setattr(
        linux_advisory_planning, "build_linux_operator_solution_from_diagnosis", build
    )
    monkeypatch.setattr(linux_advisory_planning, "render_operator_solution_markdown", render)

    runtime = object()
    assert linux_advisory_planning.render_linux_advisory_plan(runtime, "sfai-restart-loop") == (
        "# Operator solution\n"
    )
    assert calls == [
        ("diagnose", (runtime, "sfai-restart-loop", False, "30m")),
        ("build", diagnosis),
        ("render", solution),
    ]


@pytest.mark.parametrize("stage", ("diagnose", "build", "render"))
def test_helper_fails_closed_without_fallback(monkeypatch: pytest.MonkeyPatch, stage: str) -> None:
    def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("sensitive unbounded detail")

    monkeypatch.setattr(
        linux_advisory_planning,
        "diagnose_target",
        fail if stage == "diagnose" else lambda *_a, **_k: object(),
    )
    monkeypatch.setattr(
        linux_advisory_planning,
        "build_linux_operator_solution_from_diagnosis",
        fail if stage == "build" else lambda _value: object(),
    )
    monkeypatch.setattr(
        linux_advisory_planning,
        "render_operator_solution_markdown",
        fail if stage == "render" else lambda _value: "ok",
    )
    assert (
        linux_advisory_planning.render_linux_advisory_plan(object(), "docker")
        == LINUX_ADVISORY_FAILURE
    )


@pytest.mark.parametrize(
    ("nuance_target", "route_name", "route_target", "expected"),
    (
        ("sfai-restart-loop", "diagnose", "docker", "sfai-restart-loop"),
        ("", "diagnose", "docker", "docker"),
        ("", "diagnose", "services", None),
        ("", "ask", "ambiguous prose", None),
    ),
)
def test_selector_consumes_only_maintained_outputs(
    nuance_target: str, route_name: str, route_target: str, expected: str | None
) -> None:
    assert (
        select_linux_plan_help_target(
            nuance_signal="what plan should i",
            nuance_target=nuance_target,
            routed_name=route_name,
            routed_target=route_target,
        )
        == expected
    )


def test_ask_resolved_target_uses_shared_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []
    monkeypatch.setattr(
        linux_advisory_planning,
        "render_linux_advisory_plan",
        lambda _runtime, target, **_kwargs: seen.append(target) or "# Canonical\n",
    )
    result = CliRunner().invoke(app, ["ask", "What plan should I follow for sfai-restart-loop?"])
    assert result.exit_code == 0
    assert result.stdout == "# Canonical\n"
    assert seen == ["sfai-restart-loop"]
    assert "Plan-only command:" not in result.stdout


def test_ask_ambiguous_and_no_evidence_bypass_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("PR375 helper must not run")

    monkeypatch.setattr(linux_advisory_planning, "render_linux_advisory_plan", forbidden)
    ambiguous = CliRunner().invoke(app, ["ask", "How would you remediate this problem?"])
    assert ambiguous.exit_code == 0
    assert "Plan-only command:" in ambiguous.stdout

    no_evidence = CliRunner().invoke(
        app, ["ask", "What plan should I follow for Docker?", "--no-evidence"]
    )
    # The configured model is unavailable in this unit environment; the
    # pre-PR375 plain/model route therefore keeps its existing failure exit.
    assert no_evidence.exit_code == 1


def test_mixed_action_refuses_before_linux_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("PR375 helper must not run")

    monkeypatch.setattr(linux_advisory_planning, "render_linux_advisory_plan", forbidden)
    result = CliRunner().invoke(
        app, ["ask", "What plan should I follow for Docker? Restart it now."]
    )
    assert result.exit_code == 0
    assert "Refused: natural-language mutation is not allowed." in result.stdout


def test_interactive_resolved_target_uses_shared_helper(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    printed: list[str] = []
    seen: list[str] = []

    class Console:
        def print(self, *args: Any, **_kwargs: Any) -> None:
            printed.append(" ".join(str(arg) for arg in args))

    inputs = iter(("What plan should I follow for Docker?", "/exit"))
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(inputs))
    monkeypatch.setattr(repl, "Console", Console)
    monkeypatch.setattr(repl, "_confirm_workspace", lambda *_a, **_k: True)
    monkeypatch.setattr(repl.WorkspaceTrustStore, "is_trusted", lambda *_a: True)
    monkeypatch.setattr(
        linux_advisory_planning,
        "render_linux_advisory_plan",
        lambda _runtime, target: seen.append(target) or "# Canonical",
    )
    repl.start_interactive(_runtime(tmp_path), no_trust_cache=True)
    assert seen == ["docker"]
    assert "# Canonical" in "\n".join(printed)


def test_interactive_unresolved_target_keeps_safe_guidance(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    printed: list[str] = []

    class Console:
        def print(self, *args: Any, **_kwargs: Any) -> None:
            printed.append(" ".join(str(arg) for arg in args))

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("unresolved PLAN_HELP must not enter PR375")

    inputs = iter(("How would you remediate this problem?", "/exit"))
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(inputs))
    monkeypatch.setattr(repl, "Console", Console)
    monkeypatch.setattr(repl, "_confirm_workspace", lambda *_a, **_k: True)
    monkeypatch.setattr(repl.WorkspaceTrustStore, "is_trusted", lambda *_a: True)
    monkeypatch.setattr(linux_advisory_planning, "render_linux_advisory_plan", forbidden)

    repl.start_interactive(_runtime(tmp_path), no_trust_cache=True)

    assert "Plan-only command:" in "\n".join(printed)


def test_windows_plan_never_enters_linux_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("Windows PLAN_HELP must not enter PR375")

    monkeypatch.setattr(linux_advisory_planning, "render_linux_advisory_plan", forbidden)
    result = CliRunner().invoke(app, ["ask", "How would you investigate this Windows host?"])
    assert result.exit_code == 0
    assert "## Windows operator guidance" in result.stdout


def test_linux_helper_has_bounded_import_surface() -> None:
    source = Path(linux_advisory_planning.__file__).read_text(encoding="utf-8")
    imported = {
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    forbidden_fragments = {
        "model",
        "provider",
        "persist",
        "publish",
        "approval",
        "recipe",
        "preflight",
        "receipt",
        "recovery",
        "execution",
        "remediation",
        "subprocess",
        "windows",
    }
    assert not {name for name in imported if any(part in name for part in forbidden_fragments)}
