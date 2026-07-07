"""PR286 Docker read-only natural-language routing in interactive mode."""

from __future__ import annotations

from typing import Any

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.interactive.commands import route_input

runner = CliRunner()


def test_interactive_docker_feels_broken_routes_to_read_only_triage(
    monkeypatch: Any, tmp_path: Any
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    dispatched: list[tuple[str, ...]] = []

    def _fake_dispatch(console: Any, argv: tuple[str, ...]) -> str:
        dispatched.append(argv)
        text = (
            "Read-only Docker triage guidance\n"
            "Safe next commands:\n"
            "- shellforgeai triage docker --json\n"
            "- shellforgeai ops report --json\n"
            "No mutation was performed."
        )
        console.print(text)
        return text

    def _fail_provider(*_: Any) -> Any:
        raise AssertionError("read-only Docker triage prompt must not call the model provider")

    monkeypatch.setattr(
        "shellforgeai.interactive.repl._run_interactive_cli_dispatch", _fake_dispatch
    )
    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", _fail_provider)
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="docker feels broken what should I check first\n/exit\n",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert dispatched == [("triage", "docker")]
    assert "Read-only Docker triage guidance" in out
    assert "shellforgeai triage docker --json" in out
    assert "No mutation was performed" in out
    assert "Refused:" not in out


def test_docker_feels_broken_route_input_is_safe_cli_dispatch() -> None:
    routed = route_input("docker feels broken what should I check first")
    assert routed.name == "cli_dispatch"
    assert routed.argv == ("triage", "docker")


def test_interactive_still_refuses_docker_shell_or_mutation_inputs() -> None:
    for text in (
        "docker ps",
        "docker compose restart",
        "docker restart shellforgeai",
        "clean up docker and restart compose to fix it",
        "prune docker",
        "restart compose",
    ):
        routed = route_input(text)
        assert routed.name in {"mutation_refused", "shell_refused"}
