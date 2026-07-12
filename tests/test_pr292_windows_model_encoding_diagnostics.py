from __future__ import annotations

from typing import Any

from shellforgeai.llm.codex import CodexProvider, classify_model_failure
from shellforgeai.llm.schemas import ModelRequest

UTF8_ERROR = (
    "Failed to read prompt from stdin: input is not valid UTF-8 "
    "(invalid byte at offset 2504). Convert it to UTF-8 and retry."
)


class _InvalidUtf8ProviderInputPopen:
    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        self.kwargs = dict(kwargs)
        self.returncode = 1

    def communicate(self, input: Any = None, timeout: Any = None) -> tuple[str, str]:
        return "", UTF8_ERROR

    def poll(self) -> int:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


def test_invalid_utf8_stdin_signature_gets_precise_failure_class() -> None:
    failure = classify_model_failure(stdout="", stderr=UTF8_ERROR, returncode=1)

    assert failure["category"] == "stdin_encoding"
    assert failure["reason"] == "provider_stdin_not_utf8"
    assert "auth" not in str(failure["user_message"]).lower()
    assert "repository" not in str(failure["user_message"]).lower()
    assert "utf-8" in str(failure["next_step"]).lower()


def test_provider_surfaces_stdin_encoding_diagnostics(monkeypatch) -> None:
    monkeypatch.setattr("subprocess.Popen", _InvalidUtf8ProviderInputPopen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: True)

    resp = CodexProvider(allow_fallback=False).complete(
        ModelRequest(
            prompt="Windows host — análisis 확인", model="gpt-5.5", provider="openai-codex"
        )
    )

    assert not resp.ok
    assert resp.metadata["codex_exec_error_class"] == "stdin_encoding"
    assert resp.metadata["stdin_encoding"] == "utf-8"
    assert resp.metadata["stdin_prompt_sent"] is True
    assert resp.metadata["stdin_closed"] is True
    assert "input is not valid UTF-8" in str(resp.metadata["codex_exec_stderr_excerpt"])
    assert "auth" not in (resp.error or "").lower()
