from __future__ import annotations

import subprocess as subprocess_mod
from pathlib import Path
from typing import Any

from shellforgeai.llm.codex import CodexProvider
from shellforgeai.llm.schemas import ModelRequest

PARTIAL_WINDOWS_EVIDENCE_PROMPT = (
    "Windows evidence packet — read_only=true mutation_performed=false\n"
    "memory used 23%; C:\\ free 57.5 GiB; D:\\ and E:\\ unavailable; "
    "process preview │ service preview; Español: análisis; 한국어: 확인"
)


class _SuccessfulOperatorPopen:
    last: Any = None

    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        self.cmd = list(cmd)
        self.kwargs = dict(kwargs)
        self.communicate_input: Any = None
        self.communicate_timeout: Any = None
        self.returncode = 0
        type(self).last = self
        for i, tok in enumerate(cmd):
            if tok == "--output-last-message" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text(
                    "Model-assisted Windows answer — grounded in memory, disk, "
                    "process, and service evidence.",
                    encoding="utf-8",
                )

    def communicate(self, input: Any = None, timeout: Any = None) -> tuple[str, str]:
        self.communicate_input = input
        self.communicate_timeout = timeout
        return ('{"type":"turn.completed"}\n', "")

    def poll(self) -> int:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


class _TimeoutPopen:
    last: Any = None

    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        self.cmd = list(cmd)
        self.kwargs = dict(kwargs)
        self.returncode = None
        self.terminate_called = False
        self.kill_called = False
        self._timed_out_once = False
        type(self).last = self
        for i, tok in enumerate(cmd):
            if tok == "--output-last-message" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text("partial answer must not pass", encoding="utf-8")

    def communicate(self, input: Any = None, timeout: Any = None) -> tuple[str, str]:
        if not self._timed_out_once:
            self._timed_out_once = True
            raise subprocess_mod.TimeoutExpired(cmd=self.cmd, timeout=timeout)
        return "", ""

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminate_called = True
        self.returncode = -15

    def kill(self) -> None:
        self.kill_called = True
        self.returncode = -9


def _install_provider_fakes(monkeypatch, popen: type) -> None:
    monkeypatch.delenv("PYTHONUTF8", raising=False)
    monkeypatch.delenv("PYTHONIOENCODING", raising=False)
    monkeypatch.setattr("subprocess.Popen", popen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: True)
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: True)


def test_operator_unicode_prompt_succeeds_without_python_utf8_env(monkeypatch) -> None:
    _install_provider_fakes(monkeypatch, _SuccessfulOperatorPopen)

    resp = CodexProvider(allow_fallback=False).complete(
        ModelRequest(
            prompt=PARTIAL_WINDOWS_EVIDENCE_PROMPT,
            model="gpt-5.5",
            provider="openai-codex",
            timeout_seconds=11,
        )
    )

    child = _SuccessfulOperatorPopen.last
    assert resp.ok
    assert resp.text.startswith("Model-assisted Windows answer")
    assert resp.metadata["model_response_captured"] is True
    assert resp.metadata["model_response_nonempty"] is True
    assert resp.metadata["codex_exec_exit_code"] == 0
    assert resp.metadata["codex_exec_timed_out"] is False
    assert resp.metadata["stdin_encoding"] == "utf-8"
    assert child.kwargs["encoding"] == "utf-8"
    assert child.communicate_input == PARTIAL_WINDOWS_EVIDENCE_PROMPT
    assert "PYTHONUTF8" not in __import__("os").environ
    assert "PYTHONIOENCODING" not in __import__("os").environ


def test_timeout_still_fails_even_when_partial_utf8_file_exists(monkeypatch) -> None:
    _install_provider_fakes(monkeypatch, _TimeoutPopen)

    resp = CodexProvider(allow_fallback=False).complete(
        ModelRequest(
            prompt=PARTIAL_WINDOWS_EVIDENCE_PROMPT,
            model="gpt-5.5",
            provider="openai-codex",
            timeout_seconds=1,
        )
    )

    child = _TimeoutPopen.last
    assert not resp.ok
    assert resp.metadata["codex_exec_error_class"] == "timeout"
    assert resp.metadata["codex_exec_timed_out"] is True
    assert resp.metadata["codex_process_completed"] is False
    assert resp.metadata["model_response_captured"] is True
    assert "timed out" in (resp.error or "").lower()
    assert child.terminate_called
