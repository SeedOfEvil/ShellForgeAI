"""PR291 fix: process completion vs output capture semantics.

Fake subprocess fixtures only: no network, no real model calls. A timed-out
Codex invocation previously discarded the ``--output-last-message`` file with
the temp directory before it could be inspected, so a run whose response file
existed still reported that nothing was captured. The provider now reads the
capture during timeout cleanup and reports process completion, child cleanup,
output-file creation, and the stdin lifecycle separately — without ever
converting a timeout into success.
"""

from __future__ import annotations

import contextlib
import subprocess as subprocess_mod
from pathlib import Path
from typing import Any

from shellforgeai.llm.codex import CodexProvider
from shellforgeai.llm.schemas import ModelRequest


def _popen_factory(*, last_message: str | None, times_out: bool):
    class _FakePopen:
        last: Any = None

        def __init__(self, cmd: list[str], **kwargs: Any) -> None:
            self.cmd = list(cmd)
            self.kwargs = dict(kwargs)
            self.communicate_input: Any = "unset"
            self.communicate_timeout: Any = "unset"
            self.terminate_called = False
            self.kill_called = False
            self._timed_out_once = False
            self.returncode = None if times_out else 0
            type(self).last = self
            if last_message is not None:
                for i, tok in enumerate(cmd):
                    if tok == "--output-last-message" and i + 1 < len(cmd):
                        with contextlib.suppress(OSError):
                            Path(cmd[i + 1]).write_text(last_message, encoding="utf-8")

        def communicate(self, input: Any = None, timeout: Any = None) -> tuple[str, str]:
            if self.communicate_input == "unset":
                self.communicate_input = input
                self.communicate_timeout = timeout
            if times_out and not self._timed_out_once:
                self._timed_out_once = True
                raise subprocess_mod.TimeoutExpired(cmd=self.cmd, timeout=timeout)
            return ("", "")

        def poll(self):
            return self.returncode

        def terminate(self) -> None:
            self.terminate_called = True
            self.returncode = -15

        def kill(self) -> None:
            self.kill_called = True
            self.returncode = -9

    return _FakePopen


def _provider(monkeypatch, popen, *, stdin_mode: bool = False) -> CodexProvider:
    monkeypatch.setattr("subprocess.Popen", popen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: False)
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: stdin_mode)
    return CodexProvider(allow_fallback=False)


def _request(timeout_seconds: int = 5) -> ModelRequest:
    return ModelRequest(
        prompt="What is running on this system?",
        model="gpt-5.5",
        provider="openai-codex",
        timeout_seconds=timeout_seconds,
    )


# --- 5. successful run --------------------------------------------------------------


def test_successful_run_reports_completion_and_capture(monkeypatch) -> None:
    popen = _popen_factory(last_message="Grounded Windows answer.", times_out=False)
    resp = _provider(monkeypatch, popen).complete(_request())
    assert resp.ok
    meta = resp.metadata
    assert meta["codex_exec_exit_code"] == 0
    assert meta["codex_exec_timed_out"] is False
    assert meta["codex_process_completed"] is True
    assert meta["codex_child_cleanup_performed"] is False
    assert meta["output_last_message_requested"] is True
    assert meta["output_file_created"] is True
    assert meta["output_last_message_path"]
    assert meta["model_response_captured"] is True
    assert meta["model_response_nonempty"] is True
    assert meta["stdin_closed"] is True


# --- 6. genuine timeout -------------------------------------------------------------


def test_genuine_timeout_reports_cleanup_and_no_capture(monkeypatch) -> None:
    popen = _popen_factory(last_message=None, times_out=True)
    resp = _provider(monkeypatch, popen).complete(_request(timeout_seconds=1))
    assert not resp.ok
    meta = resp.metadata
    assert meta["codex_exec_timed_out"] is True
    assert meta["codex_process_completed"] is False
    assert meta["codex_child_cleanup_performed"] is True
    assert meta["output_file_created"] is False
    assert meta["model_response_captured"] is False
    assert meta["codex_exec_error_class"] == "timeout"
    child = popen.last
    assert child.terminate_called  # no lingering child
    assert child.returncode is not None


# --- 7. output created before timeout ------------------------------------------------


def test_output_created_before_timeout_is_reported_but_stays_a_failure(monkeypatch) -> None:
    popen = _popen_factory(last_message="Partial final answer.", times_out=True)
    resp = _provider(monkeypatch, popen).complete(_request(timeout_seconds=1))
    # The capture is reported honestly...
    meta = resp.metadata
    assert meta["output_file_created"] is True
    assert meta["model_response_captured"] is True
    assert meta["model_response_nonempty"] is True
    assert "Partial final answer." in meta["model_response_excerpt"]
    # ...but the timeout is never hidden and never converted into success.
    assert not resp.ok
    assert meta["codex_exec_timed_out"] is True
    assert meta["codex_process_completed"] is False
    assert meta["codex_exec_error_class"] == "timeout"
    assert "timed out" in (resp.error or "")
    assert meta["codex_child_cleanup_performed"] is True


# --- 8/9. missing and empty output ---------------------------------------------------


def test_exit_zero_with_missing_output_classifies_missing(monkeypatch) -> None:
    popen = _popen_factory(last_message=None, times_out=False)
    resp = _provider(monkeypatch, popen).complete(_request())
    assert not resp.ok
    assert resp.metadata["codex_process_completed"] is True
    assert resp.metadata["output_file_created"] is False
    assert resp.metadata["model_response_captured"] is False
    assert resp.metadata["codex_exec_error_class"] == "output_capture_missing"


def test_exit_zero_with_empty_output_classifies_empty(monkeypatch) -> None:
    popen = _popen_factory(last_message="", times_out=False)
    resp = _provider(monkeypatch, popen).complete(_request())
    assert not resp.ok
    assert resp.metadata["output_file_created"] is True
    assert resp.metadata["model_response_captured"] is False
    assert resp.metadata["codex_exec_error_class"] == "empty_response"


# --- 10. stdin lifecycle --------------------------------------------------------------


def test_stdin_lifecycle_in_stdin_mode(monkeypatch) -> None:
    import subprocess as sp

    popen = _popen_factory(last_message="OK", times_out=False)
    resp = _provider(monkeypatch, popen, stdin_mode=True).complete(_request(timeout_seconds=7))
    assert resp.ok
    child = popen.last
    # Prompt travels through communicate(input=...), never argv; stdin is a
    # pipe that communicate() closes; the bounded timeout is passed through.
    assert child.communicate_input == "What is running on this system?"
    assert child.communicate_timeout == 7
    assert child.kwargs["stdin"] == sp.PIPE
    assert child.cmd[-1] == "-"
    assert "What is running on this system?" not in child.cmd
    assert "shell" not in child.kwargs
    assert resp.metadata["stdin_prompt_sent"] is True
    assert resp.metadata["stdin_closed"] is True


def test_stdin_flags_false_in_argv_mode(monkeypatch) -> None:
    popen = _popen_factory(last_message="OK", times_out=False)
    resp = _provider(monkeypatch, popen, stdin_mode=False).complete(_request())
    assert resp.ok
    assert resp.metadata["stdin_prompt_sent"] is False
    assert resp.metadata["stdin_closed"] is True
    assert popen.last.communicate_input is None
