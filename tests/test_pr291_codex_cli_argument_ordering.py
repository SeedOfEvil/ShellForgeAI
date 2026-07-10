"""PR291 fix: Codex CLI global/subcommand argument-ordering tests.

Fake subprocess only: no network, no real model calls, no auth-cache reads.
The installed Codex CLIs (0.130.0 Linux/Docker, 0.137.0 Windows QA lane)
reject global options placed after the ``exec`` subcommand
(``error: unexpected argument '--ask-for-approval' found``). These tests pin
the one canonical builder shape on every platform:

``codex --model <m> --sandbox read-only --ask-for-approval never exec
--skip-git-repo-check [--json] [--output-last-message <path>] <prompt|->``
"""

from __future__ import annotations

from pathlib import Path

from shellforgeai.llm.codex import CodexProvider, classify_model_failure
from shellforgeai.llm.schemas import ModelRequest

GLOBAL_FLAGS = ("--model", "--sandbox", "--ask-for-approval")
EXEC_FLAGS = ("--skip-git-repo-check", "--json", "--output-last-message")

CLI_PARSE_STDERR = (
    "error: unexpected argument '--ask-for-approval' found\n"
    "\n"
    "  tip: to pass '--ask-for-approval' as a value, use '-- --ask-for-approval'\n"
    "\n"
    "Usage: codex exec [OPTIONS] [PROMPT]\n"
    "       codex exec [OPTIONS] <COMMAND> [ARGS]...\n"
)


def _provider(monkeypatch, *, windows_lane: bool) -> CodexProvider:
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: windows_lane)
    provider = CodexProvider(skip_git_repo_check=True)
    provider._resolved_binary = (
        "C:\\Tools\\ShellForgeAI\\tools\\codex-cli\\codex.CMD" if windows_lane else "/usr/bin/codex"
    )
    return provider


def _build(monkeypatch, *, windows_lane: bool, last_message: Path | None = None) -> list[str]:
    provider = _provider(monkeypatch, windows_lane=windows_lane)
    prompt = "-" if windows_lane else "Say only OK"
    return provider._build_cmd(prompt, "gpt-5.5", last_message)


def test_canonical_ordering_global_flags_before_exec(monkeypatch, tmp_path: Path) -> None:
    out_file = tmp_path / "last_message.txt"
    for windows_lane in (False, True):
        cmd = _build(monkeypatch, windows_lane=windows_lane, last_message=out_file)
        exec_idx = cmd.index("exec")
        assert cmd[1:3] == ["--model", "gpt-5.5"]
        assert cmd[cmd.index("--sandbox") + 1] == "read-only"
        assert cmd[cmd.index("--ask-for-approval") + 1] == "never"
        for flag in GLOBAL_FLAGS:
            assert cmd.index(flag) < exec_idx, f"{flag} must precede exec"
        for flag in EXEC_FLAGS:
            assert cmd.index(flag) > exec_idx, f"{flag} must follow exec"
        assert cmd[cmd.index("--output-last-message") + 1] == str(out_file)
        assert cmd[-1] == ("-" if windows_lane else "Say only OK")


def test_invalid_order_regression_no_global_flags_after_exec(monkeypatch) -> None:
    # The previously invalid shape (`exec --model ... --sandbox ...
    # --ask-for-approval never --skip-git-repo-check`) must be impossible to
    # generate: nothing global ever lands in the post-exec section.
    for windows_lane in (False, True):
        cmd = _build(monkeypatch, windows_lane=windows_lane)
        post_exec = cmd[cmd.index("exec") + 1 :]
        for flag in GLOBAL_FLAGS:
            assert flag not in post_exec, f"{flag} leaked after exec"
        assert "-m" not in post_exec
        assert "-s" not in post_exec
        assert "-a" not in post_exec


def test_builder_sections_are_explicit(monkeypatch) -> None:
    provider = _provider(monkeypatch, windows_lane=False)
    assert provider._global_options("gpt-5.5") == [
        "--model",
        "gpt-5.5",
        "--sandbox",
        "read-only",
        "--ask-for-approval",
        "never",
    ]
    exec_opts = provider._exec_options(None)
    assert exec_opts[0] == "--skip-git-repo-check"
    assert "--output-last-message" not in exec_opts
    with_capture = provider._exec_options(Path("/tmp/out.txt"))
    assert with_capture[-2:] == ["--output-last-message", "/tmp/out.txt"]


def test_read_only_sandbox_and_never_approval_always_present(monkeypatch) -> None:
    for windows_lane in (False, True):
        cmd = _build(monkeypatch, windows_lane=windows_lane)
        assert cmd[cmd.index("--sandbox") + 1] == "read-only"
        assert cmd[cmd.index("--ask-for-approval") + 1] == "never"
        assert "--yolo" not in cmd
        assert "--dangerously-bypass-approvals-and-sandbox" not in cmd


def test_unexpected_argument_stderr_classifies_as_cli_argument_order() -> None:
    failure = classify_model_failure(stdout="", stderr=CLI_PARSE_STDERR, returncode=2)
    assert failure["category"] == "cli_argument_order"
    assert failure["reason"] == "cli_argument_order"
    assert "argument" in str(failure["user_message"]).lower()
    # A parse failure is not an auth failure and not a model failure.
    assert "login" not in str(failure["user_message"]).lower()
    assert "model command failed" not in str(failure["user_message"]).lower()


def test_provider_reports_cli_parse_failure_with_bounded_stderr(monkeypatch) -> None:
    class _ParseFailPopen:
        def __init__(self, cmd, **kwargs):
            self.returncode = 2

        def communicate(self, input=None, timeout=None):
            return ("", CLI_PARSE_STDERR)

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr("subprocess.Popen", _ParseFailPopen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: False)
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: False)
    provider = CodexProvider(allow_fallback=False)
    resp = provider.complete(
        ModelRequest(prompt="Say only OK", model="gpt-5.5", provider="openai-codex")
    )
    assert not resp.ok
    assert "argument" in (resp.error or "").lower()
    assert "precede the exec subcommand" in (resp.error or "")
    assert resp.metadata["codex_exec_error_class"] == "cli_argument_order"
    assert resp.metadata["codex_command_started"] is True
    assert resp.metadata["model_response_captured"] is False
    assert "unexpected argument" in resp.metadata["codex_exec_stderr_excerpt"]
    assert len(resp.metadata["codex_exec_stderr_excerpt"]) <= 400


def test_ordering_is_protected_in_source_docstring() -> None:
    # The ordering contract is load-bearing: keep it stated at the builder.
    source = (
        Path(__file__).resolve().parents[1] / "src" / "shellforgeai" / "llm" / "codex.py"
    ).read_text(encoding="utf-8")
    assert "MUST precede the ``exec`` subcommand" in source
    assert "unexpected argument '--ask-for-approval' found" in source
