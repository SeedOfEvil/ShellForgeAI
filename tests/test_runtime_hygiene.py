import subprocess

from shellforgeai.llm.codex import CodexProvider
from shellforgeai.llm.schemas import ModelRequest


def test_codex_timeout_returns_structured_error(monkeypatch):
    class FakePopen:
        returncode = 124

        def __init__(self, *a, **k):
            self._terminated = False

        def communicate(self, timeout=None):
            if not self._terminated:
                raise subprocess.TimeoutExpired(cmd=["codex"], timeout=timeout)
            return ("partial-out", "partial-err")

        def terminate(self):
            self._terminated = True

        def kill(self):
            self._terminated = True

        def poll(self):
            return None

    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    p = CodexProvider()
    resp = p.complete(
        ModelRequest(prompt="x", model="gpt-5.5", provider="openai-codex", timeout_seconds=1)
    )
    assert not resp.ok
    assert resp.error == "timeout"


def test_cleanup_active_processes_terminates_children():
    class P:
        terminated = False

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

        def communicate(self, timeout=None):
            return ("", "")

    child = P()
    CodexProvider._active_procs = {child}  # type: ignore[arg-type]
    CodexProvider.cleanup_active_processes()
    assert child.terminated
