from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from shellforgeai.llm.codex import CodexProvider
from shellforgeai.llm.schemas import ModelRequest


class _TimeoutPopen:
    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        self.cmd = cmd
        self.returncode: int | None = None
        self.pid = 29302
        idx = cmd.index("--output-last-message") + 1
        Path(cmd[idx]).write_text("partial", encoding="utf-8")

    def communicate(self, input: str | None = None, timeout: int | None = None) -> tuple[str, str]:
        if self.returncode is None:
            raise subprocess.TimeoutExpired(self.cmd, timeout or 1, output="partial", stderr="")
        return "partial", ""

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


def test_owned_process_cleanup_reports_exact_tracked_pid(monkeypatch: Any) -> None:
    monkeypatch.setattr("subprocess.Popen", _TimeoutPopen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    resp = CodexProvider(allow_fallback=False).complete(
        ModelRequest(prompt="hi", model="gpt-5.5", provider="openai-codex", timeout_seconds=1)
    )
    assert resp.metadata["owned_child_pids"] == [29302]
    assert resp.metadata["remaining_owned_child_pids"] == []
