from __future__ import annotations

from typer.testing import CliRunner

from shellforgeai.cli import app


def test_windows_memory_help_and_command_registration() -> None:
    windows_help = CliRunner().invoke(app, ["windows", "--help"])
    assert windows_help.exit_code == 0
    assert "memory" in windows_help.stdout
    command_help = CliRunner().invoke(app, ["windows", "memory", "--help"])
    assert command_help.exit_code == 0
    assert "--json" in command_help.stdout
