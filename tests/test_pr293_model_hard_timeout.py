from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from shellforgeai.llm.codex import CodexProvider
from shellforgeai.llm.schemas import ModelRequest


class _TimeoutPopen:
    last: _TimeoutPopen | None = None

    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        self.cmd = cmd
        self.kwargs = kwargs
        self.returncode: int | None = None
        self.pid = 29302
        self.terminated = False
        self.killed = False
        _TimeoutPopen.last = self
        idx = cmd.index("--output-last-message") + 1
        Path(cmd[idx]).write_text("partial", encoding="utf-8")

    def communicate(self, input: str | None = None, timeout: int | None = None) -> tuple[str, str]:
        if not self.terminated and not self.killed:
            raise subprocess.TimeoutExpired(
                self.cmd, timeout or 1, output="partial stdout", stderr=""
            )
        self.returncode = -15 if self.terminated else -9
        return "partial stdout", ""

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


def test_timeout_records_terminal_phase_and_owned_cleanup(monkeypatch: Any) -> None:
    monkeypatch.setattr("subprocess.Popen", _TimeoutPopen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    resp = CodexProvider(allow_fallback=False).complete(
        ModelRequest(prompt="hi", model="gpt-5.5", provider="openai-codex", timeout_seconds=1)
    )
    assert not resp.ok
    assert resp.metadata["model_phase"] == "timed_out"
    assert resp.metadata["codex_exec_timed_out"] is True
    assert resp.metadata["timeout_phase"] in {"waiting_for_response", "sending_prompt"}
    assert resp.metadata["partial_output_detected"] is True
    assert resp.metadata["partial_output_nonempty"] is True
    assert resp.metadata["child_cleanup_requested"] is True
    assert resp.metadata["child_cleanup_verified"] is True
    assert resp.metadata["remaining_owned_child_pids"] == []
    assert _TimeoutPopen.last is not None and _TimeoutPopen.last.terminated
