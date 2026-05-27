from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.interactive.guards import looks_like_shell_command
from shellforgeai.interactive.repl import _is_followup_phrase

runner = CliRunner()


def test_followup_phrase_detection_supported_examples() -> None:
    assert _is_followup_phrase("get that info")
    assert _is_followup_phrase("then get that info")
    assert _is_followup_phrase("do that")
    assert _is_followup_phrase("proceed")
    assert _is_followup_phrase("check those")


def test_short_followups_not_classified_as_shell() -> None:
    assert not looks_like_shell_command("get that info")
    assert not looks_like_shell_command("then get that info")
    assert not looks_like_shell_command("do that")


def test_followup_phrase_with_no_context_returns_safe_guidance(monkeypatch, tmp_path) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("model should not be called")

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", boom)
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    res = runner.invoke(app, ["interactive", "--no-trust-cache"], input="y\nget that info\n/exit\n")
    assert res.exit_code == 0
    assert "no prior requested read-only info" in res.stdout.lower()
    assert "ops report" in res.stdout.lower()


def test_mutating_shell_commands_remain_blocked(monkeypatch, tmp_path) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("model should not be called")

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", boom)
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    res = runner.invoke(
        app,
        ["interactive", "--no-trust-cache"],
        input="y\ndocker restart sfai-healthy-web\n/exit\n",
    )
    assert res.exit_code == 0
    assert "No command was executed." in res.stdout
