from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.interactive.guards import is_shell_fragment_line, looks_like_shell_command

runner = CliRunner()


def test_shell_guard_detects_examples() -> None:
    assert looks_like_shell_command("sudo docker exec -it shellforgeai sh -lc 'echo hi'")
    assert looks_like_shell_command("docker compose up -d")
    assert looks_like_shell_command("for d in $(ls -td /data/artifacts/sf_*); do")
    assert looks_like_shell_command("done")
    assert is_shell_fragment_line("found=0")
    assert is_shell_fragment_line('[ -d "$d" ] || continue')
    assert is_shell_fragment_line('c=$(find "$d" -maxdepth 1 -type f | wc -l)')
    assert is_shell_fragment_line('echo "$d"')
    assert is_shell_fragment_line('[ "$found" -eq 0 ] && echo "none"')


def test_blocked_shell_input_no_model_call(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("model should not be called")

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", boom)
    res = runner.invoke(
        app,
        ["interactive", "--no-trust-cache"],
        input="y\nsudo docker exec -it shellforgeai sh\n/help\n/exit\n",
    )
    assert res.exit_code == 0
    assert "ShellForgeAI interactive mode does not execute shell snippets." in res.stdout
    assert "Session:" in res.stdout


def test_explicit_ask_shell_explain_calls_model(monkeypatch) -> None:
    called = {"v": False}

    class P:
        def complete(self, req):
            called["v"] = True

            class R:
                text = "ok"

            return R()

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", lambda *_: P())
    res = runner.invoke(
        app,
        ["interactive", "--no-trust-cache"],
        input="y\nask explain this command: sudo docker exec -it x y\n/exit\n",
    )
    assert res.exit_code == 0
    assert called["v"]


def test_audit_latest_no_model(monkeypatch, tmp_path) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("model should not be called")

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", boom)
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    res = runner.invoke(app, ["interactive", "--no-trust-cache"], input="y\n/audit latest\n/exit\n")
    assert res.exit_code == 0
    assert "No audit sessions found." in res.stdout


def test_multiline_paste_quarantine_blocks_fragments_and_allows_exit(monkeypatch, tmp_path) -> None:
    called = {"v": 0}

    class P:
        def complete(self, req):
            called["v"] += 1
            raise AssertionError("model should not be called for blocked paste fragments")

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", lambda *_: P())
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    payload = (
        "y\n"
        "sudo docker exec -it shellforgeai sh -lc '\n"
        "found=0\n"
        '[ -d "$d" ] || continue\n'
        'c=$(find "$d" -maxdepth 1 -type f | wc -l)\n'
        'echo "$d"\n'
        '[ "$found" -eq 0 ] && echo "none"\n'
        "done\n"
        "/help\n"
        "/exit\n"
    )
    res = runner.invoke(app, ["interactive", "--no-trust-cache"], input=payload)
    assert res.exit_code == 0
    assert "Multiline shell paste detected." in res.stdout
    assert "Blocked shell paste fragment. No command was executed." in res.stdout
    assert "Session:" in res.stdout
    assert "Goodbye." in res.stdout
    assert called["v"] == 0
    assert not (tmp_path / "artifacts").exists()


def test_firewall_status_routes_without_paste_guard(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("model should not be called for deterministic firewall summary")

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", boom)
    res = runner.invoke(
        app,
        ["interactive", "--no-trust-cache"],
        input="y\nfirewall status\n/exit\n",
    )
    assert res.exit_code == 0
    assert "Collected" in res.stdout
    assert "Multiline shell paste detected" not in res.stdout
