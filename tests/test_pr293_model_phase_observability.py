from __future__ import annotations

from pathlib import Path
from typing import Any

from shellforgeai.llm.codex import CodexProvider
from shellforgeai.llm.schemas import ModelRequest


class _SuccessPopen:
    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        self.cmd = cmd
        self.kwargs = kwargs
        self.returncode = 0
        self.pid = 29301
        idx = cmd.index("--output-last-message") + 1
        Path(cmd[idx]).write_text("PR293_OK", encoding="utf-8")

    def communicate(self, input: str | None = None, timeout: int | None = None) -> tuple[str, str]:
        return '{"type":"message","content":"PR293_OK"}\n', ""

    def poll(self) -> int | None:
        return self.returncode


def test_phase_ordering_on_success(monkeypatch: Any) -> None:
    monkeypatch.setattr("subprocess.Popen", _SuccessPopen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    seen: list[str] = []
    resp = CodexProvider().complete(
        ModelRequest(
            prompt="hi",
            model="gpt-5.5",
            provider="openai-codex",
            metadata={"progress_callback": seen.append},
        )
    )
    assert resp.ok
    phases = [entry["phase"] for entry in resp.metadata["model_phase_history"]]
    for phase in [
        "preparing_context",
        "building_prompt",
        "starting_provider",
        "sending_prompt",
        "waiting_for_response",
        "capturing_response",
        "provider_exited",
        "completed",
    ]:
        assert phase in phases
    assert (
        phases.index("starting_provider")
        < phases.index("sending_prompt")
        < phases.index("waiting_for_response")
    )
    assert resp.metadata["model_phase"] == "completed"
    assert resp.metadata["model_total_ms"] >= 0
    assert "hi" not in str(resp.metadata["model_phase_history"])
    assert "waiting_for_response" in seen
