"""PR291: scoped Windows Codex repository-trust bypass tests.

Fake subprocess only: no network, no real model calls, no auth-cache reads.
These tests pin the scoped authenticated Windows Codex invocation form proven
live on the QGA/SYSTEM QA lane (``codex exec -s read-only
--skip-git-repo-check ...``) while keeping the mandatory read-only sandbox,
the inherited tester-scoped CODEX_HOME environment, and the POSIX/Docker
invocation shape unchanged.
"""

from __future__ import annotations

import contextlib
import os
import subprocess as subprocess_mod
from pathlib import Path
from typing import Any

from shellforgeai.llm.codex import CodexProvider
from shellforgeai.llm.schemas import ModelRequest

FAKE_WINDOWS_BINARY = "C:\\Tools\\ShellForgeAI\\tools\\codex-cli\\codex.CMD"
# Generic tester-scoped value: the real lab path is supplied externally by the
# QA lane and must never be hardcoded in product code or pinned here.
FAKE_CODEX_HOME = "C:\\Users\\tester\\.codex"


class _RecordingPopen:
    instances: list[_RecordingPopen] = []

    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        self.cmd = list(cmd)
        self.kwargs = dict(kwargs)
        self.communicate_input: Any = "unset"
        self.returncode = 0
        type(self).instances.append(self)
        for i, tok in enumerate(cmd):
            if tok == "--output-last-message" and i + 1 < len(cmd):
                with contextlib.suppress(OSError):
                    Path(cmd[i + 1]).write_text("windows model answer", encoding="utf-8")

    def communicate(self, input: Any = None, timeout: Any = None) -> tuple[str, str]:
        self.communicate_input = input
        return ("", "")

    def poll(self) -> int:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


def _windows_provider(monkeypatch, **kwargs: Any) -> CodexProvider:
    _RecordingPopen.instances = []
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: True)
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: True)
    monkeypatch.setattr("subprocess.Popen", _RecordingPopen)
    provider = CodexProvider(binary=FAKE_WINDOWS_BINARY, **kwargs)
    provider._resolved_binary = FAKE_WINDOWS_BINARY
    return provider


def _request(prompt: str = "What is running on this system?") -> ModelRequest:
    return ModelRequest(prompt=prompt, model="gpt-5.5", provider="openai-codex")


def test_windows_scoped_invocation_uses_read_only_and_trust_bypass(monkeypatch) -> None:
    monkeypatch.setenv("CODEX_HOME", FAKE_CODEX_HOME)
    provider = _windows_provider(monkeypatch, skip_git_repo_check=True)
    resp = provider.complete(_request())
    assert resp.ok
    assert resp.text == "windows model answer"
    proc = _RecordingPopen.instances[0]
    cmd = proc.cmd
    for token in ("--sandbox", "read-only", "--ask-for-approval", "never", "exec"):
        assert token in cmd, f"{token} missing from scoped Windows invocation"
    # Ordering verified on the installed Windows Codex CLI (v0.137.0):
    # codex --model <m> --sandbox read-only --ask-for-approval never exec
    #   --skip-git-repo-check ... -
    assert cmd[0] == FAKE_WINDOWS_BINARY
    exec_idx = cmd.index("exec")
    for global_flag in ("--model", "--sandbox", "--ask-for-approval"):
        assert cmd.index(global_flag) < exec_idx, f"{global_flag} must precede exec"
    assert cmd[cmd.index("--sandbox") + 1] == "read-only"
    assert cmd[cmd.index("--ask-for-approval") + 1] == "never"
    assert cmd.index("--skip-git-repo-check") > exec_idx
    assert cmd[-1] == "-"  # prompt travels over stdin, never cmd.exe argv


def test_windows_scoped_invocation_preserves_read_only_sandbox(monkeypatch) -> None:
    provider = _windows_provider(monkeypatch, skip_git_repo_check=True)
    provider.complete(_request())
    cmd = _RecordingPopen.instances[0].cmd
    assert provider.sandbox == "read-only"
    assert "read-only" in cmd
    # The trust bypass never weakens sandboxing or enables broad execution.
    assert "--yolo" not in cmd
    assert "--dangerously-bypass-approvals-and-sandbox" not in cmd
    assert "--full-auto" not in cmd


def test_windows_scope_enables_bypass_even_for_bare_provider(monkeypatch) -> None:
    # The scoped Windows Codex lane explicitly enables the bypass: staged
    # QGA/SYSTEM source directories are never trusted git repositories.
    provider = _windows_provider(monkeypatch)
    assert provider.skip_git_repo_check is False
    assert provider.skip_git_repo_check_used() is True
    provider.complete(_request())
    assert "--skip-git-repo-check" in _RecordingPopen.instances[0].cmd


def test_windows_invocation_inherits_caller_environment_no_shell(monkeypatch) -> None:
    monkeypatch.setenv("CODEX_HOME", FAKE_CODEX_HOME)
    provider = _windows_provider(monkeypatch, skip_git_repo_check=True)
    provider.complete(_request())
    proc = _RecordingPopen.instances[0]
    # Same-process context: no env override, so tester-scoped CODEX_HOME flows
    # to the codex CLI child untouched. Never shell=True; argv list only.
    assert "env" not in proc.kwargs
    assert "shell" not in proc.kwargs
    assert os.environ["CODEX_HOME"] == FAKE_CODEX_HOME
    assert proc.kwargs["stdin"] == subprocess_mod.PIPE
    assert proc.communicate_input == _request().prompt
    joined = " ".join(proc.cmd).lower()
    assert "powershell" not in joined
    assert "winrm" not in joined


def test_windows_successful_bypass_reports_diagnostics(monkeypatch) -> None:
    provider = _windows_provider(monkeypatch, skip_git_repo_check=True)
    resp = provider.complete(_request())
    assert resp.ok
    assert resp.metadata["codex_exec_attempted"] is True
    assert resp.metadata["codex_exec_exit_code"] == 0
    assert resp.metadata["codex_exec_timed_out"] is False
    assert resp.metadata["codex_exec_error_class"] is None
    assert resp.metadata["sandbox_mode"] == "read-only"
    assert resp.metadata["approval_policy"] == "never"
    assert resp.metadata["skip_git_repo_check_used"] is True
    assert resp.metadata["codex_binary"] == FAKE_WINDOWS_BINARY
    assert resp.metadata["codex_command_built"] is True
    assert resp.metadata["codex_command_started"] is True
    assert resp.metadata["model_response_captured"] is True
    assert resp.metadata["model_response_nonempty"] is True


def test_default_trust_bypass_false_outside_scoped_path(monkeypatch) -> None:
    _RecordingPopen.instances = []
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: False)
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: False)
    monkeypatch.setattr("subprocess.Popen", _RecordingPopen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    provider = CodexProvider()
    assert provider.skip_git_repo_check is False
    assert provider.skip_git_repo_check_used() is False
    provider.complete(_request(prompt="hi"))
    assert "--skip-git-repo-check" not in _RecordingPopen.instances[0].cmd


def test_configured_linux_docker_invocation_canonical_shape(monkeypatch) -> None:
    # With the explicit configured option (build_provider passes the config
    # value, which defaults to true), the POSIX/Docker command keeps the one
    # canonical shape: global options before exec, exec options after.
    _RecordingPopen.instances = []
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: False)
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: False)
    monkeypatch.setattr("subprocess.Popen", _RecordingPopen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    provider = CodexProvider(skip_git_repo_check=True)
    provider.complete(_request(prompt="hi"))
    cmd = _RecordingPopen.instances[0].cmd
    last_message_path = cmd[cmd.index("--output-last-message") + 1]
    assert cmd == [
        "/usr/bin/codex",
        "--model",
        "gpt-5.5",
        "--sandbox",
        "read-only",
        "--ask-for-approval",
        "never",
        "exec",
        "--skip-git-repo-check",
        "--json",
        "--output-last-message",
        last_message_path,
        "hi",
    ]


def test_build_provider_passes_configured_trust_bypass_option() -> None:
    from shellforgeai.core.config import load_settings
    from shellforgeai.llm.manager import build_provider

    settings = load_settings()
    provider = build_provider(settings)
    assert provider.skip_git_repo_check == settings.model.codex_skip_git_repo_check


def test_model_doctor_surfaces_trust_bypass_diagnostics(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: True)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    provider = CodexProvider(binary=FAKE_WINDOWS_BINARY, skip_git_repo_check=True)
    provider._resolved_binary = FAKE_WINDOWS_BINARY
    monkeypatch.setattr(
        "shellforgeai.llm.codex.subprocess.run",
        lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "codex 0.130.0", "stderr": ""})(),
    )
    info = provider.doctor()
    assert info["sandbox_mode"] == "read-only"
    assert info["skip_git_repo_check_used"] is True
    assert info["auth_cache_contents_inspected"] is False
