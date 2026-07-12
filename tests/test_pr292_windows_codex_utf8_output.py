from __future__ import annotations

from pathlib import Path
from typing import Any

from shellforgeai.llm.codex import CodexProvider
from shellforgeai.llm.schemas import ModelRequest

UNICODE_ANSWER = "Assessment — “memory” │ Español: análisis │ 한국어: 확인"


class _UnicodeOutputPopen:
    last: Any = None

    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        self.cmd = list(cmd)
        self.kwargs = dict(kwargs)
        self.returncode = 0
        type(self).last = self
        for i, tok in enumerate(cmd):
            if tok == "--output-last-message" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text(UNICODE_ANSWER, encoding="utf-8")

    def communicate(self, input: Any = None, timeout: Any = None) -> tuple[str, str]:
        return ('{"type":"turn.completed"}\n', "")

    def poll(self) -> int:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


def test_output_last_message_is_read_as_utf8(monkeypatch) -> None:
    monkeypatch.setattr("subprocess.Popen", _UnicodeOutputPopen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: True)

    resp = CodexProvider(allow_fallback=False).complete(
        ModelRequest(prompt="unicode prompt — 확인", model="gpt-5.5", provider="openai-codex")
    )

    assert resp.ok
    assert resp.text == UNICODE_ANSWER
    assert resp.metadata["model_response_captured"] is True
    assert resp.metadata["model_response_nonempty"] is True
    assert resp.metadata["output_file_encoding"] == "utf-8"
    assert "�" not in resp.text


class _UnicodeStderrPopen:
    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        self.returncode = 1

    def communicate(self, input: Any = None, timeout: Any = None) -> tuple[str, str]:
        return "", "provider said — ошибка │ línea\x00 with control"

    def poll(self) -> int:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


def test_unicode_stderr_diagnostics_are_bounded_and_sanitized(monkeypatch) -> None:
    monkeypatch.setattr("subprocess.Popen", _UnicodeStderrPopen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: True)

    resp = CodexProvider(allow_fallback=False).complete(
        ModelRequest(
            prompt="do not leak this prompt — 확인", model="gpt-5.5", provider="openai-codex"
        )
    )

    assert not resp.ok
    excerpt = str(resp.metadata["codex_exec_stderr_excerpt"])
    assert "provider said — ошибка │ línea" in excerpt
    assert "\x00" not in excerpt
    assert "do not leak this prompt" not in excerpt
    assert resp.metadata["stderr_encoding"] == "utf-8"
