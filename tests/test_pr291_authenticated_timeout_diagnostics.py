"""PR291 fix: authenticated acceptance timeout diagnostics.

Offline fixtures only: no network, no real model calls, no auth-cache reads.
The live Windows run held with ``sfai ask`` exit 0 but a fallback transcript
carrying a timeout marker — the inner Codex invocation timed out and the
product fell back to the evidence answer. These tests pin that a timed-out
authenticated run stays HOLD with an explicit, bounded, explainable timeout
classification, and that PASS requires a captured non-empty non-fallback
answer with no timeout.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "windows_authenticated_model_acceptance.py"
)


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "windows_authenticated_model_acceptance_pr291_timeout", SCRIPT
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


wama = _load_module()

PACKET = {
    "platform": "windows",
    "processes": {"available": True, "total_count": 74, "returned_count": 10, "entries": []},
    "services": {
        "available": True,
        "total_count": 131,
        "running_count": 53,
        "stopped_count": 78,
        "entries": [],
    },
}

GROUNDED_ANSWER = (
    "This Windows host has 74 processes visible (10 shown) and 131 services: "
    "53 running and 78 stopped."
)

# The exact live failure shape: sfai ask exits 0 but prints the deterministic
# Windows evidence fallback because the inner Codex invocation timed out.
TIMEOUT_FALLBACK_TRANSCRIPT = (
    "## Windows evidence summary\n"
    "Processes total=74 (10 shown). Services total=131 (53 running, 78 stopped).\n"
    "\n"
    "Model assistance is unavailable, so the read-only Windows evidence above "
    "is the answer.\n"
    "Model failure class: timeout\n"
    "Check model auth with: shellforgeai model doctor --json\n"
)


def _summary(answer: str | None, *, ask_exit_code: int | None = 0) -> dict[str, Any]:
    return wama.build_summary(
        codex_login_checked=True,
        codex_logged_in=True,
        codex_home_configured=True,
        same_process_context=True,
        packet=PACKET,
        answer=answer,
        model_assisted_answer_ran=True,
        targeted_tests_exit_code=0,
        targeted_tests_output="........ [100%]\n",
        ask_exit_code=ask_exit_code,
    )


def test_inner_timeout_with_ask_exit_zero_holds_with_explicit_class() -> None:
    # sfai ask exit 0 is NOT authenticated success when the transcript is the
    # timeout fallback: the summary must say precisely why it held.
    summary = _summary(TIMEOUT_FALLBACK_TRANSCRIPT, ask_exit_code=0)
    assert summary["codex_exec_exit_code"] == 0  # the ask child exited 0
    assert summary["codex_exec_timed_out"] is True  # the inner model call did not
    assert summary["codex_exec_error_class"] == "timeout"
    assert summary["fallback_used"] is True
    assert summary["model_assisted_answer_ran"] is False
    assert summary["model_response_captured"] is False
    assert summary["validation_status"] == "HOLD"


def test_grounded_answer_without_timeout_passes() -> None:
    summary = _summary(GROUNDED_ANSWER)
    assert summary["codex_exec_timed_out"] is False
    assert summary["codex_exec_error_class"] is None
    assert summary["model_response_captured"] is True
    assert summary["model_response_nonempty"] is True
    assert summary["model_assisted_answer_ran"] is True
    assert summary["fallback_used"] is False
    assert summary["process_grounding_detected"] is True
    assert summary["service_grounding_detected"] is True
    assert summary["answer_uses_process_or_service_evidence"] is True
    assert summary["validation_status"] == "PASS"


def test_timeout_diagnostics_are_bounded_and_sanitized() -> None:
    noisy = TIMEOUT_FALLBACK_TRANSCRIPT + "\x07" + ("z" * 5000)
    summary = _summary(noisy)
    excerpt = summary["codex_exec_stderr_excerpt"]
    assert len(excerpt) <= 400
    assert "\x07" not in excerpt
    assert summary["validation_status"] == "HOLD"


def test_live_lane_timeout_fallback_holds_end_to_end() -> None:
    def login_runner(argv, env):
        return wama.CommandResult(exit_code=0, stdout="Logged in using ChatGPT", stderr="")

    def ask_runner(argv, env):
        return wama.CommandResult(exit_code=0, stdout=TIMEOUT_FALLBACK_TRANSCRIPT, stderr="")

    summary = wama.run_authenticated_acceptance(
        codex_binary="codex",
        sfai_binary="sfai.cmd",
        codex_home="C:\\Users\\tester\\.codex",
        login_runner=login_runner,
        ask_runner=ask_runner,
        packet_builder=lambda: dict(PACKET),
        targeted_tests_exit_code=0,
        targeted_tests_output="........ [100%]\n",
    )
    assert summary["codex_logged_in"] is True
    assert summary["codex_exec_timed_out"] is True
    assert summary["fallback_used"] is True
    assert summary["model_assisted_answer_ran"] is False
    assert summary["validation_status"] == "HOLD"


def test_provider_metadata_distinguishes_capture_from_completion() -> None:
    # The provider-side contract the acceptance lane relies on: a timeout with
    # a produced output file is explainable (captured=true) but never a
    # completed process, so PASS still requires codex_exec_timed_out=false.
    import contextlib
    import subprocess as sp

    from shellforgeai.llm.codex import CodexProvider
    from shellforgeai.llm.schemas import ModelRequest

    class _TimeoutAfterWritePopen:
        def __init__(self, cmd, **kwargs):
            self.cmd = list(cmd)
            self._timed_out_once = False
            self.returncode = None
            for i, tok in enumerate(cmd):
                if tok == "--output-last-message" and i + 1 < len(cmd):
                    with contextlib.suppress(OSError):
                        Path(cmd[i + 1]).write_text("Late final answer.", encoding="utf-8")

        def communicate(self, input=None, timeout=None):
            if not self._timed_out_once:
                self._timed_out_once = True
                raise sp.TimeoutExpired(cmd=self.cmd, timeout=timeout)
            return ("", "")

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def kill(self):
            self.returncode = -9

    import pytest

    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr("subprocess.Popen", _TimeoutAfterWritePopen)
        monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
        monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: False)
        monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: False)
        resp = CodexProvider(allow_fallback=False).complete(
            ModelRequest(prompt="hi", model="gpt-5.5", provider="openai-codex", timeout_seconds=1)
        )
    finally:
        monkeypatch.undo()
    assert not resp.ok
    assert resp.metadata["codex_exec_timed_out"] is True
    assert resp.metadata["codex_process_completed"] is False
    assert resp.metadata["output_file_created"] is True
    assert resp.metadata["model_response_captured"] is True
