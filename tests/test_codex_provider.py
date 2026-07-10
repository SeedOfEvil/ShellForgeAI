import contextlib

from shellforgeai.llm.codex import CodexProvider
from shellforgeai.llm.schemas import ModelRequest


def _fake_popen_factory(returncode=0, stdout="ok", stderr="", last_message=None):
    captured = {}

    class FakePopen:
        def __init__(self, cmd, **kwargs):
            captured["cmd"] = cmd
            captured["stdin"] = kwargs.get("stdin")
            self.returncode = returncode
            self._kwargs = kwargs
            # Find the --output-last-message tmp path and write last_message
            if last_message is not None:
                from pathlib import Path

                for i, tok in enumerate(cmd):
                    if tok == "--output-last-message" and i + 1 < len(cmd):
                        with contextlib.suppress(OSError):
                            Path(cmd[i + 1]).write_text(last_message)

        def communicate(self, timeout=None):
            return (stdout, stderr)

        def poll(self):
            return self.returncode

        def terminate(self):
            pass

        def kill(self):
            pass

    return FakePopen, captured


def test_command_global_options_before_exec(monkeypatch):
    Fake, captured = _fake_popen_factory(stdout="", last_message="ok")
    monkeypatch.setattr("subprocess.Popen", Fake)
    # POSIX/Docker lane shape: pin the non-Windows form and the explicit
    # configured trust-bypass option (build_provider passes the config value;
    # the bare constructor default is False since PR291).
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: False)
    p = CodexProvider(skip_git_repo_check=True)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    p.complete(ModelRequest(prompt="hi", model="gpt-5.5", provider="openai-codex"))
    cmd = captured["cmd"]
    exec_idx = cmd.index("exec")
    # Global options must come before exec.
    for flag in ("--sandbox", "read-only", "--ask-for-approval", "never", "-m", "gpt-5.5"):
        assert flag in cmd
        assert cmd.index(flag) < exec_idx, f"{flag} must precede exec"
    # Exec-only options after exec.
    assert "--skip-git-repo-check" in cmd
    assert cmd.index("--skip-git-repo-check") > exec_idx
    assert "--output-last-message" in cmd
    assert cmd.index("--output-last-message") > exec_idx
    # Approval/sandbox not duplicated post-exec.
    post = cmd[exec_idx + 1 :]
    assert "--ask-for-approval" not in post
    assert "--sandbox" not in post
    # No yolo / dangerous flags.
    assert "--yolo" not in cmd
    assert "--dangerously-bypass-approvals-and-sandbox" not in cmd


def test_provider_uses_devnull_stdin(monkeypatch):
    import subprocess as _subprocess

    Fake, captured = _fake_popen_factory(stdout="", last_message="ok")
    monkeypatch.setattr("subprocess.Popen", Fake)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    p = CodexProvider()
    p.complete(ModelRequest(prompt="hi", model="gpt-5.5", provider="openai-codex"))
    assert captured["stdin"] == _subprocess.DEVNULL


def test_provider_returns_last_message_text(monkeypatch):
    Fake, _ = _fake_popen_factory(stdout="", last_message="ok\n")
    monkeypatch.setattr("subprocess.Popen", Fake)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    p = CodexProvider()
    r = p.complete(ModelRequest(prompt="hi", model="gpt-5.5", provider="openai-codex"))
    assert r.ok
    assert r.text == "ok"


def test_provider_missing_binary_returns_install_message(monkeypatch):
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: None)
    p = CodexProvider()
    r = p.complete(ModelRequest(prompt="hi", model="gpt-5.5", provider="openai-codex"))
    assert not r.ok
    assert "not found" in (r.error or "")


def test_provider_cli_argument_error_not_login(monkeypatch):
    err = "error: unexpected argument '--ask-for-approval' found"
    Fake, _ = _fake_popen_factory(returncode=2, stdout="", stderr=err)
    monkeypatch.setattr("subprocess.Popen", Fake)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    p = CodexProvider()
    r = p.complete(ModelRequest(prompt="hi", model="gpt-5.5", provider="openai-codex"))
    assert not r.ok
    assert "argument" in (r.error or "").lower()
    assert "login" not in (r.error or "").lower()


def test_provider_timeout(monkeypatch):
    import subprocess as _sp

    class TimeoutPopen:
        def __init__(self, cmd, **kwargs):
            self.returncode = None
            self._kwargs = kwargs

        def communicate(self, timeout=None):
            raise _sp.TimeoutExpired(cmd="codex", timeout=timeout)

        def poll(self):
            return None

        def terminate(self):
            self.returncode = -15

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr("subprocess.Popen", TimeoutPopen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    p = CodexProvider(timeout_seconds=1)
    r = p.complete(
        ModelRequest(prompt="hi", model="gpt-5.5", provider="openai-codex", timeout_seconds=1)
    )
    assert not r.ok
    assert "timed out" in (r.error or "").lower()


def test_provider_empty_response(monkeypatch):
    Fake, _ = _fake_popen_factory(returncode=0, stdout="", stderr="", last_message="")
    monkeypatch.setattr("subprocess.Popen", Fake)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    p = CodexProvider()
    r = p.complete(ModelRequest(prompt="hi", model="gpt-5.5", provider="openai-codex"))
    assert not r.ok
    assert "no final response" in (r.error or "").lower()


def test_stream_complete_reuses_complete_for_safe_cleanup(monkeypatch):
    p = CodexProvider()
    monkeypatch.setattr(
        p,
        "complete",
        lambda _req: type(
            "Resp",
            (),
            {
                "text": "hello",
                "provider": "openai-codex",
                "model": "gpt-5.5",
                "ok": True,
                "error": None,
            },
        )(),
    )
    evs = list(
        p.stream_complete(ModelRequest(prompt="hi", model="gpt-5.5", provider="openai-codex"))
    )
    assert evs[0]["type"] == "text"
    assert evs[-1]["type"] == "final"
