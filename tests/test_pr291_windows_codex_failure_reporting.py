"""PR291: bounded sanitized Codex failure reporting tests.

Fake subprocess/provider fixtures only: no network, no real model calls, no
auth-cache reads. These tests pin the precise ``repository_trust`` failure
class for Codex's git/repository trust gate, the bounded sanitized stderr
excerpt in provider diagnostics, the bounded timeout with child cleanup, and
the acceptance-summary HOLD semantics when the model-assisted answer did not
really run.
"""

from __future__ import annotations

import contextlib
import importlib.util
import subprocess as subprocess_mod
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from shellforgeai.llm.codex import (
    CODEX_STDERR_EXCERPT_MAX_CHARS,
    CodexProvider,
    _sanitize_stderr_excerpt,
    classify_model_failure,
)
from shellforgeai.llm.schemas import ModelRequest

TRUST_GATE_STDERR = "Not inside a trusted directory and --skip-git-repo-check was not specified."

SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "windows_authenticated_model_acceptance.py"
)


def _load_acceptance_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "windows_authenticated_model_acceptance_pr291", SCRIPT
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


class _FailingPopen:
    instances: list[_FailingPopen] = []

    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        self.cmd = list(cmd)
        self.kwargs = dict(kwargs)
        self.returncode = 1
        type(self).instances.append(self)

    def communicate(self, input: Any = None, timeout: Any = None) -> tuple[str, str]:
        return ("", TRUST_GATE_STDERR)

    def poll(self) -> int:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


def _provider(monkeypatch, popen) -> CodexProvider:
    monkeypatch.setattr("subprocess.Popen", popen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: False)
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: False)
    return CodexProvider(allow_fallback=False)


def _request() -> ModelRequest:
    return ModelRequest(
        prompt="What is running on this system?",
        model="gpt-5.5",
        provider="openai-codex",
        timeout_seconds=5,
    )


# --- classification -------------------------------------------------------------


def test_trust_gate_stderr_classifies_as_repository_trust() -> None:
    failure = classify_model_failure(stdout="", stderr=TRUST_GATE_STDERR, returncode=1)
    assert failure["category"] == "repository_trust"
    assert failure["reason"] == "repository_trust"
    assert "repository trust" in str(failure["user_message"]).lower()
    # Repository trust is NOT an authentication failure: never point at login.
    assert "login" not in str(failure["user_message"]).lower()
    assert "auth" not in str(failure["user_message"]).lower()


def test_trust_gate_is_not_collapsed_into_unknown_model_failure() -> None:
    failure = classify_model_failure(stdout="", stderr=TRUST_GATE_STDERR, returncode=1)
    assert failure["reason"] != "unknown_model_failure"
    assert "model command failed" not in str(failure["user_message"]).lower()


def test_other_failures_keep_existing_classes() -> None:
    assert classify_model_failure("", "", returncode=124)["category"] == "timeout"
    assert classify_model_failure("", "please run codex login", returncode=1)["category"] == "auth"
    assert classify_model_failure("", "boom", returncode=1)["category"] == "model"


# --- provider diagnostics --------------------------------------------------------


def test_provider_reports_repository_trust_failure_with_bounded_excerpt(monkeypatch) -> None:
    _FailingPopen.instances = []
    provider = _provider(monkeypatch, _FailingPopen)
    resp = provider.complete(_request())
    assert not resp.ok
    assert "repository trust" in (resp.error or "").lower()
    meta = resp.metadata
    assert meta["codex_exec_attempted"] is True
    assert meta["codex_exec_exit_code"] == 1
    assert meta["codex_exec_timed_out"] is False
    assert meta["codex_exec_error_class"] == "repository_trust"
    assert "trusted directory" in meta["codex_exec_stderr_excerpt"]
    assert len(meta["codex_exec_stderr_excerpt"]) <= CODEX_STDERR_EXCERPT_MAX_CHARS
    assert meta["sandbox_mode"] == "read-only"
    assert "skip_git_repo_check_used" in meta


def test_missing_binary_reports_binary_resolution_class(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: None)
    resp = CodexProvider().complete(_request())
    assert not resp.ok
    assert resp.metadata["codex_exec_attempted"] is False
    assert resp.metadata["codex_exec_error_class"] == "binary_resolution"


def test_timeout_reports_timeout_class_and_cleans_up_child(monkeypatch) -> None:
    class _HangingPopen:
        last: Any = None

        def __init__(self, cmd: list[str], **kwargs: Any) -> None:
            self.terminate_called = False
            self.kill_called = False
            self._timed_out_once = False
            self.returncode = None
            type(self).last = self

        def communicate(self, input: Any = None, timeout: Any = None) -> tuple[str, str]:
            if not self._timed_out_once:
                self._timed_out_once = True
                raise subprocess_mod.TimeoutExpired(cmd=["codex"], timeout=timeout)
            return ("", "")

        def poll(self):
            return self.returncode

        def terminate(self) -> None:
            self.terminate_called = True
            self.returncode = -15

        def kill(self) -> None:
            self.kill_called = True
            self.returncode = -9

    provider = _provider(monkeypatch, _HangingPopen)
    resp = provider.complete(_request())
    assert not resp.ok
    assert "timed out" in (resp.error or "").lower()
    assert "bounded timeout" in (resp.error or "")
    assert resp.metadata["codex_exec_timed_out"] is True
    assert resp.metadata["codex_exec_error_class"] == "timeout"
    child = _HangingPopen.last
    assert child.terminate_called  # no lingering child after the bounded timeout
    assert child.returncode is not None


# --- sanitization ----------------------------------------------------------------


def test_stderr_excerpt_is_bounded_and_sanitized() -> None:
    noisy = (
        "\x1b[31m" + TRUST_GATE_STDERR + "\x1b[0m\n"
        "Authorization: Bearer fake-credential-value\n" + ("x" * 5000)
    )
    excerpt = _sanitize_stderr_excerpt(noisy)
    assert len(excerpt) <= CODEX_STDERR_EXCERPT_MAX_CHARS
    assert "trusted directory" in excerpt
    assert "\x1b" not in excerpt
    assert all(ch == "\n" or ch.isprintable() for ch in excerpt)
    assert "fake-credential-value" not in excerpt
    assert "[REDACTED]" in excerpt


def test_diagnostics_never_record_the_environment(monkeypatch) -> None:
    _FailingPopen.instances = []
    monkeypatch.setenv("CODEX_HOME", "C:\\Users\\tester\\.codex")
    provider = _provider(monkeypatch, _FailingPopen)
    resp = provider.complete(_request())
    assert set(resp.metadata) == {
        "codex_command_built",
        "codex_command_started",
        "codex_exec_attempted",
        "model_call_attempted",
        "codex_exec_exit_code",
        "codex_exec_timed_out",
        "codex_process_completed",
        "codex_child_cleanup_performed",
        "codex_exec_error_class",
        "codex_exec_error_message",
        "codex_exec_stderr_excerpt",
        "output_last_message_requested",
        "output_last_message_path",
        "output_file_created",
        "model_response_captured",
        "model_response_nonempty",
        "model_response_excerpt",
        "stdin_prompt_sent",
        "stdin_closed",
        "codex_binary",
        "codex_resolved_binary",
        "sandbox_mode",
        "approval_policy",
        "skip_git_repo_check_used",
    }
    assert "CODEX_HOME" not in str(resp.metadata)


def test_provider_never_opens_auth_cache_on_failure(monkeypatch, tmp_path) -> None:
    opened: list[str] = []
    real_open = Path.open

    def _spy_open(self, *args: Any, **kwargs: Any):
        opened.append(str(self))
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _spy_open)
    with contextlib.suppress(Exception):
        _provider(monkeypatch, _FailingPopen).complete(_request())
    assert not [p for p in opened if "auth.json" in p or ".codex" in p]


# --- acceptance summary ----------------------------------------------------------


FALLBACK_WITH_TRUST_FAILURE = (
    "## Windows evidence summary\n"
    "Processes total=74 (10 shown). Services total=131 (53 running, 78 stopped).\n"
    "\n"
    "Model assistance is unavailable, so the read-only Windows evidence above "
    "is the answer.\n"
    "Model failure class: repository_trust\n"
    "Check model auth with: shellforgeai model doctor --json\n"
)


def _summary(answer: str, *, ask_exit_code: int | None = 0) -> dict[str, Any]:
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


def test_trust_gate_fallback_holds_with_repository_trust_class() -> None:
    summary = _summary(FALLBACK_WITH_TRUST_FAILURE)
    assert summary["fallback_used"] is True
    assert summary["model_assisted_answer_ran"] is False
    assert summary["validation_status"] == "HOLD"
    assert summary["codex_exec_error_class"] == "repository_trust"
    assert summary["codex_exec_timed_out"] is False
    assert len(summary["codex_exec_stderr_excerpt"]) <= 400


def test_timeout_fallback_holds_with_timeout_class() -> None:
    summary = _summary("Codex timed out before producing a response.")
    assert summary["fallback_used"] is True
    assert summary["validation_status"] == "HOLD"
    assert summary["codex_exec_error_class"] == "timeout"
    assert summary["codex_exec_timed_out"] is True


def test_successful_grounded_answer_reports_no_failure_class() -> None:
    answer = (
        "This Windows host has 74 processes visible (10 shown) and 131 services: "
        "53 running and 78 stopped."
    )
    summary = _summary(answer)
    assert summary["validation_status"] == "PASS"
    assert summary["fallback_used"] is False
    assert summary["codex_exec_error_class"] is None
    assert summary["codex_exec_attempted"] is True
    assert summary["codex_exec_exit_code"] == 0


def test_extract_diagnostics_detects_raw_trust_error_text() -> None:
    diag = wama.extract_model_failure_diagnostics(
        "Model-assisted assessment unavailable: Codex repository trust check "
        "blocked execution from this directory.",
        ask_exit_code=1,
    )
    assert diag["codex_exec_error_class"] == "repository_trust"
    assert diag["codex_exec_exit_code"] == 1
    assert "repository trust" in diag["codex_exec_stderr_excerpt"].lower()


def test_extract_diagnostics_sanitizes_and_bounds_excerpt() -> None:
    line = "Model failure class: repository_trust \x07" + ("y" * 5000)
    diag = wama.extract_model_failure_diagnostics(line)
    excerpt = diag["codex_exec_stderr_excerpt"]
    assert len(excerpt) <= 400
    assert "\x07" not in excerpt
