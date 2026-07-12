"""PR291 fix: deterministic Codex final-response capture tests.

Fake subprocess/provider fixtures only: no network, no real model calls, no
auth-cache reads. Command start / process exit 0 alone is never proof of a
model response: the ``--output-last-message`` capture must exist and hold a
non-empty final response. Missing and empty captures are classified
explicitly and keep authenticated acceptance HOLD.
"""

from __future__ import annotations

import contextlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from shellforgeai.llm.codex import CodexProvider
from shellforgeai.llm.schemas import ModelRequest

SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "windows_authenticated_model_acceptance.py"
)


def _load_acceptance_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "windows_authenticated_model_acceptance_pr291_capture", SCRIPT
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


wama = _load_acceptance_module()

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


def _capture_popen(last_message: str | None):
    """Fake Popen: exit 0; writes the --output-last-message file when not None."""

    class _CapturePopen:
        instances: list[Any] = []

        def __init__(self, cmd: list[str], **kwargs: Any) -> None:
            self.cmd = list(cmd)
            self.kwargs = dict(kwargs)
            self.returncode = 0
            type(self).instances.append(self)
            if last_message is not None:
                for i, tok in enumerate(cmd):
                    if tok == "--output-last-message" and i + 1 < len(cmd):
                        with contextlib.suppress(OSError):
                            Path(cmd[i + 1]).write_text(last_message, encoding="utf-8")

        def communicate(self, input: Any = None, timeout: Any = None) -> tuple[str, str]:
            return ("", "")

        def poll(self):
            return self.returncode

        def terminate(self) -> None:
            self.returncode = -15

        def kill(self) -> None:
            self.returncode = -9

    return _CapturePopen


def _provider(monkeypatch, popen) -> CodexProvider:
    monkeypatch.setattr("subprocess.Popen", popen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: False)
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: False)
    return CodexProvider(allow_fallback=False)


def _request() -> ModelRequest:
    return ModelRequest(
        prompt="Say only OK", model="gpt-5.5", provider="openai-codex", timeout_seconds=5
    )


# --- provider capture -------------------------------------------------------------


def test_successful_invocation_reports_captured_nonempty_response(monkeypatch) -> None:
    provider = _provider(monkeypatch, _capture_popen("OK"))
    resp = provider.complete(_request())
    assert resp.ok
    assert resp.text == "OK"
    meta = resp.metadata
    assert meta["codex_command_built"] is True
    assert meta["codex_command_started"] is True
    assert meta["output_last_message_requested"] is True
    assert meta["model_response_captured"] is True
    assert meta["model_response_nonempty"] is True
    assert meta["model_response_excerpt"] == "OK"
    assert meta["codex_exec_exit_code"] == 0
    assert meta["codex_exec_error_class"] is None


def test_exit_zero_with_missing_output_file_is_not_success(monkeypatch) -> None:
    # Command start success is not model-response success: exit 0 with no
    # --output-last-message file and no other output must fail explicitly.
    provider = _provider(monkeypatch, _capture_popen(None))
    resp = provider.complete(_request())
    assert not resp.ok
    assert resp.metadata["codex_command_started"] is True
    assert resp.metadata["model_response_captured"] is False
    assert resp.metadata["model_response_nonempty"] is False
    assert resp.metadata["codex_exec_error_class"] == "output_capture_missing"
    assert "no final response" in (resp.error or "")


def test_exit_zero_with_empty_output_file_classifies_empty_response(monkeypatch) -> None:
    provider = _provider(monkeypatch, _capture_popen(""))
    resp = provider.complete(_request())
    assert not resp.ok
    assert resp.metadata["model_response_captured"] is False
    assert resp.metadata["codex_exec_error_class"] == "empty_response"
    assert "no final response" in (resp.error or "")


def test_response_excerpt_is_bounded_and_sanitized(monkeypatch) -> None:
    provider = _provider(monkeypatch, _capture_popen("OK\x07" + ("y" * 5000)))
    resp = provider.complete(_request())
    assert resp.ok
    excerpt = resp.metadata["model_response_excerpt"]
    assert len(excerpt) <= 240
    assert "\x07" not in excerpt
    assert all(ch == "\n" or ch.isprintable() for ch in excerpt)


# --- acceptance summary ------------------------------------------------------------


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


def test_grounded_answer_reports_captured_response_and_pass() -> None:
    answer = (
        "This Windows host has 74 processes visible (10 shown) and 131 services: "
        "53 running and 78 stopped."
    )
    summary = _summary(answer)
    assert summary["model_response_captured"] is True
    assert summary["model_response_nonempty"] is True
    assert summary["validation_status"] == "PASS"


def test_exit_zero_with_empty_answer_holds() -> None:
    # Process exit 0 alone is not enough: an empty captured answer HOLDs.
    summary = _summary("", ask_exit_code=0)
    assert summary["model_response_captured"] is False
    assert summary["model_response_nonempty"] is False
    assert summary["model_assisted_answer_ran"] is False
    assert summary["validation_status"] == "HOLD"


def test_fallback_answer_is_not_a_captured_model_response() -> None:
    summary = _summary(
        "## Windows evidence summary\n"
        "Model assistance is unavailable, so the read-only Windows evidence "
        "above is the answer.\n"
        "Model failure class: repository_trust\n"
    )
    assert summary["model_response_captured"] is False
    assert summary["fallback_used"] is True
    assert summary["validation_status"] == "HOLD"


def test_cli_parse_failure_transcript_holds_with_explicit_class() -> None:
    summary = _summary(
        "Codex CLI argument error: error: unexpected argument '--ask-for-approval' found\n"
    )
    assert summary["codex_exec_error_class"] == "cli_argument_order"
    assert summary["fallback_used"] is True
    assert summary["model_assisted_answer_ran"] is False
    assert summary["validation_status"] == "HOLD"
    assert "unexpected argument" in summary["codex_exec_stderr_excerpt"]


def test_live_lane_requires_captured_response_not_just_exit_zero() -> None:
    calls: list[list[str]] = []

    def login_runner(argv, env):
        calls.append(argv)
        return wama.CommandResult(exit_code=0, stdout="Logged in using ChatGPT", stderr="")

    def ask_runner(argv, env):
        calls.append(argv)
        return wama.CommandResult(exit_code=0, stdout="", stderr="")

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
    assert summary["model_response_captured"] is False
    assert summary["validation_status"] == "HOLD"
