"""PR291: Codex invocation scope, live-probe diagnostics, and safety guards.

Fake provider/subprocess fixtures only: no network, no real model calls, no
auth-cache reads. These tests prove the trust bypass stays scoped (default
false outside the Windows Codex lane; POSIX/Docker construction unchanged),
the model doctor live probe surfaces the trust-bypass diagnostic and precise
failure classes, and no new execution surface was introduced.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from typer.testing import CliRunner

import shellforgeai.cli as cli
from shellforgeai.cli import app
from shellforgeai.llm.codex import CodexProvider, _windows_codex_lane
from shellforgeai.llm.schemas import ModelResponse

runner = CliRunner()

REPO = Path(__file__).resolve().parents[1]


class FakeProvider:
    def __init__(self, *, response: ModelResponse) -> None:
        self.calls: list[object] = []
        self.response = response

    def doctor(self) -> dict:
        return {
            "provider": "openai-codex",
            "model": "gpt-5.5",
            "auth_cache_present": True,
            "auth_cache_contents_inspected": False,
            "auth_readiness": "not_verified",
            "auth_reason": "auth_cache_present_live_probe_not_run",
            "sandbox": "read-only",
            "sandbox_mode": "read-only",
            "skip_git_repo_check_used": True,
        }

    def complete(self, request) -> ModelResponse:
        self.calls.append(request)
        return self.response


def _install(monkeypatch, provider: FakeProvider) -> FakeProvider:
    monkeypatch.setattr(cli, "build_provider", lambda _settings: provider)
    return provider


def _success_metadata() -> dict:
    return {
        "codex_command_built": True,
        "codex_command_started": True,
        "codex_exec_attempted": True,
        "model_call_attempted": True,
        "codex_exec_exit_code": 0,
        "codex_exec_timed_out": False,
        "codex_exec_error_class": None,
        "codex_exec_error_message": None,
        "codex_exec_stderr_excerpt": "",
        "output_last_message_requested": True,
        "model_response_captured": True,
        "model_response_nonempty": True,
        "model_response_excerpt": "SFAI_MODEL_DOCTOR_READY",
        "codex_binary": "codex",
        "codex_resolved_binary": "/usr/bin/codex",
        "sandbox_mode": "read-only",
        "approval_policy": "never",
        "skip_git_repo_check_used": True,
    }


# --- scope ----------------------------------------------------------------------


def test_windows_codex_lane_matches_platform() -> None:
    assert _windows_codex_lane() == (os.name == "nt")


def test_trust_bypass_defaults_false_and_stays_scoped(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: False)
    provider = CodexProvider()
    assert provider.skip_git_repo_check is False
    assert provider.skip_git_repo_check_used() is False
    explicit = CodexProvider(skip_git_repo_check=True)
    assert explicit.skip_git_repo_check_used() is True


def test_windows_lane_uses_canonical_global_form_with_scoped_bypass(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: True)
    provider = CodexProvider(binary="codex")
    provider._resolved_binary = "C:\\Tools\\ShellForgeAI\\tools\\codex-cli\\codex.CMD"
    cmd = provider._build_cmd("-", "gpt-5.5", None)
    # Verified on codex 0.137.0: global options (--model/--sandbox/
    # --ask-for-approval) MUST precede exec; the scoped trust bypass is the
    # only Windows-specific behavior and stays exec-scoped.
    exec_idx = cmd.index("exec")
    assert cmd[1:3] == ["--model", "gpt-5.5"]
    assert cmd.index("--sandbox") < exec_idx
    assert cmd[cmd.index("--sandbox") + 1] == "read-only"
    assert cmd.index("--ask-for-approval") < exec_idx
    assert cmd[cmd.index("--ask-for-approval") + 1] == "never"
    assert cmd[exec_idx + 1] == "--skip-git-repo-check"


def test_posix_lane_keeps_global_option_form(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: False)
    provider = CodexProvider(skip_git_repo_check=True)
    provider._resolved_binary = "/usr/bin/codex"
    cmd = provider._build_cmd("hi", "gpt-5.5", None)
    exec_idx = cmd.index("exec")
    assert cmd.index("--sandbox") < exec_idx
    assert cmd.index("--ask-for-approval") < exec_idx
    assert cmd.index("--skip-git-repo-check") > exec_idx
    unconfigured = CodexProvider()
    unconfigured._resolved_binary = "/usr/bin/codex"
    assert "--skip-git-repo-check" not in unconfigured._build_cmd("hi", "gpt-5.5", None)


def test_read_only_sandbox_is_present_in_both_forms(monkeypatch) -> None:
    for lane in (True, False):
        monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda lane=lane: lane)
        provider = CodexProvider(skip_git_repo_check=True)
        provider._resolved_binary = "/usr/bin/codex"
        cmd = provider._build_cmd("hi", "gpt-5.5", None)
        assert "read-only" in cmd


# --- model doctor live probe ------------------------------------------------------


def test_live_probe_success_reports_trust_bypass_diagnostics(monkeypatch) -> None:
    provider = _install(
        monkeypatch,
        FakeProvider(
            response=ModelResponse(
                provider="openai-codex",
                model="gpt-5.5",
                text="SFAI_MODEL_DOCTOR_READY",
                ok=True,
                metadata=_success_metadata(),
            )
        ),
    )
    result = runner.invoke(app, ["model", "doctor", "--live-probe", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["live_probe_requested"] is True
    assert payload["live_probe_performed"] is True
    assert payload["model_called"] is True
    assert payload["probe"]["status"] == "passed"
    assert payload["auth_cache_contents_inspected"] is False
    assert payload["sandbox_mode"] == "read-only"
    assert payload["skip_git_repo_check_used"] is True
    assert payload["probe"]["sandbox_mode"] == "read-only"
    assert payload["probe"]["skip_git_repo_check_used"] is True
    assert len(provider.calls) == 1


def test_live_probe_repository_trust_failure_is_precise_not_auth(monkeypatch) -> None:
    failure_metadata = dict(_success_metadata())
    failure_metadata.update(
        {
            "codex_exec_exit_code": 1,
            "codex_exec_error_class": "repository_trust",
            "codex_exec_error_message": "codex repository trust check blocked execution",
            "codex_exec_stderr_excerpt": (
                "Not inside a trusted directory and --skip-git-repo-check was not specified."
            ),
            "skip_git_repo_check_used": False,
        }
    )
    _install(
        monkeypatch,
        FakeProvider(
            response=ModelResponse(
                provider="openai-codex",
                model="gpt-5.5",
                text="",
                ok=False,
                error="codex repository trust check blocked execution",
                metadata=failure_metadata,
            )
        ),
    )
    result = runner.invoke(app, ["model", "doctor", "--live-probe", "--json"])
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["live_probe_performed"] is True
    assert payload["probe"]["status"] == "failed"
    assert payload["probe"]["error_class"] == "repository_trust"
    assert "trusted directory" in payload["probe"]["codex_exec_stderr_excerpt"]
    assert payload["probe"]["skip_git_repo_check_used"] is False
    # A repository-trust failure must never masquerade as missing auth.
    assert payload["probe"]["error_class"] != "provider_error"
    assert "login" not in str(payload["probe"]["error_message"]).lower()


def test_live_probe_timeout_failure_stays_bounded_and_explicit(monkeypatch) -> None:
    timeout_metadata = dict(_success_metadata())
    timeout_metadata.update(
        {
            "codex_exec_exit_code": None,
            "codex_exec_timed_out": True,
            "codex_exec_error_class": "timeout",
            "model_response_captured": False,
            "model_response_nonempty": False,
            "model_response_excerpt": "",
        }
    )
    _install(
        monkeypatch,
        FakeProvider(
            response=ModelResponse(
                provider="openai-codex",
                model="gpt-5.5",
                text="",
                ok=False,
                error="codex timed out after 60s (bounded timeout; no indefinite wait)",
                metadata=timeout_metadata,
            )
        ),
    )
    result = runner.invoke(app, ["model", "doctor", "--live-probe", "--json"])
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["status"] == "warning"
    assert payload["probe"]["error_class"] == "model_probe_timeout"
    assert payload["live_probe_timed_out"] is True
    assert payload["live_probe_error_class"] == "model_probe_timeout"
    assert payload["model_response_captured"] is False
    assert "bounded timeout" in payload["probe"]["error_message"]


# --- mutation refusal stays intact -------------------------------------------------


def test_windows_mutation_phrase_still_refused() -> None:
    from shellforgeai.interactive.repl import _is_windows_service_mutation_phrase

    assert _is_windows_service_mutation_phrase("Clean up Windows and restart services to fix it")


# --- safety/source guards ----------------------------------------------------------


def test_no_new_execution_surface_in_pr291_paths() -> None:
    codex_source = (REPO / "src/shellforgeai/llm/codex.py").read_text(encoding="utf-8")
    assert "shell=True" not in codex_source
    assert "powershell" not in codex_source.lower()
    assert "winrm" not in codex_source.lower()
    ask_source = (REPO / "src/shellforgeai/commands/ask.py").read_text(encoding="utf-8")
    assert "shell=True" not in ask_source
    pr291_slice = ask_source.split("PR291", 1)[1]
    assert "os.environ" not in pr291_slice
    assert "auth.json" not in ask_source
    model_source = (REPO / "src/shellforgeai/commands/model.py").read_text(encoding="utf-8")
    assert "shell=True" not in model_source
    assert "auth.json" not in model_source


def test_provider_diagnostics_do_not_read_auth_cache_source_guard() -> None:
    codex_source = (REPO / "src/shellforgeai/llm/codex.py").read_text(encoding="utf-8")
    diagnostics_slice = codex_source.split("def _exec_diagnostics", 1)[1].split(
        "def stream_complete", 1
    )[0]
    assert "auth.json" not in diagnostics_slice
    assert "os.environ" not in diagnostics_slice
    assert "read_text" not in diagnostics_slice
    assert ".open(" not in diagnostics_slice
