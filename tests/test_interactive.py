from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.workspace import WorkspaceTrustStore

runner = CliRunner()


def test_no_args_enters_interactive_and_exit() -> None:
    result = runner.invoke(app, input="n\n")
    assert result.exit_code == 0
    assert "ShellForgeAI" in result.stdout
    assert "CLI-first AI Ops for Linux" in result.stdout
    assert "Trust " in result.stdout
    assert "Workspace not trusted" in result.stdout
    assert "Missing command" not in result.stdout


def test_help_still_works() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0


def test_route_input() -> None:
    assert route_input("diagnose disk").name == "diagnose"
    assert route_input("research nginx").name == "research"
    assert route_input("plan fix disk").name == "plan"
    assert route_input("what is happening").name == "ask"
    assert route_input("my machine is running slow").args == "performance"
    assert route_input("high cpu").name == "diagnose"


def test_trust_store(tmp_path: Path) -> None:
    store = WorkspaceTrustStore(tmp_path)
    w = tmp_path / "wk"
    w.mkdir()
    assert not store.is_trusted(w)
    store.trust(w, "0.1.0")
    assert store.is_trusted(w)


def test_interactive_command_alias() -> None:
    result = runner.invoke(app, ["interactive"], input="n\n")
    assert result.exit_code == 0
    assert "Trust " in result.stdout
