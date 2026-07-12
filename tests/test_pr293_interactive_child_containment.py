from __future__ import annotations

from pathlib import Path
from typing import Any

from shellforgeai.llm.codex import CodexProvider
from shellforgeai.llm.schemas import ModelRequest


class _SuccessPopen:
    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        self.returncode = 0
        self.pid = 29301
        idx = cmd.index("--output-last-message") + 1
        Path(cmd[idx]).write_text("PR293_OK", encoding="utf-8")

    def communicate(self, input: str | None = None, timeout: int | None = None) -> tuple[str, str]:
        return "", ""

    def poll(self) -> int | None:
        return self.returncode


def test_shared_lifecycle_suitable_for_interactive_exit_cleanup(monkeypatch: Any) -> None:
    monkeypatch.setattr("subprocess.Popen", _SuccessPopen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    resp = CodexProvider().complete(
        ModelRequest(prompt="interactive", model="gpt-5.5", provider="openai-codex")
    )
    assert resp.ok
    assert resp.metadata["child_cleanup_verified"] is True
    assert resp.metadata["remaining_owned_child_pids"] == []
