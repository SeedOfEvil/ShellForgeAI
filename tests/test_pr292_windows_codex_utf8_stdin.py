from __future__ import annotations

import locale
import subprocess
from pathlib import Path
from typing import Any

from shellforgeai.llm.codex import CodexProvider
from shellforgeai.llm.schemas import ModelRequest

UNICODE_PROMPT = (
    "Windows host — read-only assessment:\n"
    "Memory: 23%\n"
    "C:\\ free: 57.5 GiB\n"
    "D:\\ and E:\\ unavailable\n"
    "Process preview │ service preview\n"
    "“Do not restart or clean up.”\n"
    "Español: análisis\n"
    "한국어: 확인\n"
)


class _Utf8RecordingPopen:
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
                Path(cmd[i + 1]).write_text("UTF-8 answer — listo │ 확인", encoding="utf-8")

    def communicate(self, input: Any = None, timeout: Any = None) -> tuple[str, str]:
        self.communicate_input = input
        self.communicate_timeout = timeout
        # This is the regression assertion: the text Python hands to Popen can
        # be encoded as UTF-8 regardless of the host preferred encoding.
        assert isinstance(input, str)
        input.encode("utf-8")
        return ('{"type":"turn.completed"}\n', "")

    def poll(self) -> int:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


def _provider(monkeypatch) -> CodexProvider:
    monkeypatch.setattr("subprocess.Popen", _Utf8RecordingPopen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: True)
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: True)
    return CodexProvider(allow_fallback=False)


def test_codex_subprocess_uses_explicit_utf8_text_mode(monkeypatch) -> None:
    resp = _provider(monkeypatch).complete(
        ModelRequest(
            prompt=UNICODE_PROMPT,
            model="gpt-5.5",
            provider="openai-codex",
            timeout_seconds=9,
        )
    )

    child = _Utf8RecordingPopen.last
    assert resp.ok
    assert child.kwargs["stdin"] == subprocess.PIPE
    assert child.kwargs["stdout"] == subprocess.PIPE
    assert child.kwargs["stderr"] == subprocess.PIPE
    assert child.kwargs["text"] is True
    assert child.kwargs["encoding"] == "utf-8"
    assert child.kwargs["errors"] == "replace"
    assert child.communicate_input == UNICODE_PROMPT
    assert child.communicate_timeout == 9
    assert UNICODE_PROMPT not in child.cmd
    assert child.cmd[-1] == "-"
    assert resp.metadata["stdin_encoding"] == "utf-8"
    assert resp.metadata["stdout_encoding"] == "utf-8"
    assert resp.metadata["stderr_encoding"] == "utf-8"
    assert resp.metadata["prompt_character_count"] == len(UNICODE_PROMPT)
    assert resp.metadata["prompt_utf8_byte_count"] == len(UNICODE_PROMPT.encode("utf-8"))


def test_codex_stdin_utf8_is_locale_independent(monkeypatch) -> None:
    monkeypatch.setattr(locale, "getpreferredencoding", lambda do_setlocale=True: "cp1252")

    resp = _provider(monkeypatch).complete(
        ModelRequest(prompt=UNICODE_PROMPT, model="gpt-5.5", provider="openai-codex")
    )

    assert resp.ok
    assert _Utf8RecordingPopen.last.kwargs["encoding"] == "utf-8"
    assert _Utf8RecordingPopen.last.communicate_input == UNICODE_PROMPT
