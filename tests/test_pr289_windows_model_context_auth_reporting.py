"""PR289 fix: Windows model-context auth + reporting semantics.

Unit coverage for the authenticated Windows acceptance helper:

* Codex login parsing accepts ``Logged in using ChatGPT`` on stdout OR stderr
  only with exit code 0, and never touches auth-cache/token files;
* ``CODEX_HOME`` is tester-scoped/configurable: a pre-existing environment
  value is preserved, an explicit override wins, and no user-specific path is
  hardcoded in product or harness code;
* ``targeted_tests_ok`` is based on the pytest exit code plus reliable
  completion evidence — quiet dot-progress/[100%] output passes without the
  literal word "passed", while nonzero exits and failure summaries never pass;
* ``answer_uses_process_or_service_evidence`` stays strict: it requires a real
  process/service evidence reference or an explicit missing-evidence
  acknowledgement plus BOTH safe gap commands;
* summary status is HOLD unless auth, evidence, context, grounding, and tests
  are all proven, and fallback/preamble output never counts as a pass.

Everything here is offline: no network, no real model calls, no subprocess
execution, no secret/auth-cache reads.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "windows_authenticated_model_acceptance.py"
)


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("windows_authenticated_model_acceptance", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


wama = _load_module()

LOGIN_PHRASE = "Logged in using ChatGPT"

GROUNDED_ANSWER = (
    "On this Windows host the read-only evidence packet shows 182 visible "
    "processes and 98 services with 61 running. Process/service evidence is "
    "read-only. Next: sfai.cmd windows processes --json --limit 10."
)

MISSING_EVIDENCE_ANSWER = (
    "From the evidence currently loaded, I can see host and memory facts. "
    "I do not have process/service detail in this evidence packet. "
    "Run these read-only commands to fill the gap: "
    "sfai.cmd windows processes --json --limit 10 and "
    "sfai.cmd windows services --json."
)

BAD_PREAMBLE_ANSWER = (
    "Understood. I’ll operate within the ShellForgeAI invariants: read-only "
    "evidence first, no arbitrary/destructive execution, preserve CLI "
    "behavior, and keep user-facing UX/docs consistent."
)

PACKET_WITH_PROCESS_SERVICE = {
    "platform": "windows",
    "read_only": True,
    "mutation_performed": False,
    "processes": {"available": True, "total_count": 182},
    "services": {"available": True, "total_count": 98, "running_count": 61},
}

PACKET_THIN = {
    "platform": "windows",
    "read_only": True,
    "mutation_performed": False,
    "processes": {"available": False},
    "services": {"available": False},
}


# --- 1. Codex login parsing ---------------------------------------------------


def test_login_phrase_on_stdout_with_exit_zero_passes() -> None:
    assert wama.parse_codex_login_status(0, f"{LOGIN_PHRASE}\n", "")


def test_login_phrase_on_stderr_with_exit_zero_passes() -> None:
    assert wama.parse_codex_login_status(0, "", f"info: {LOGIN_PHRASE}\n")


def test_login_nonzero_exit_fails_even_with_phrase() -> None:
    assert not wama.parse_codex_login_status(1, LOGIN_PHRASE, LOGIN_PHRASE)


def test_login_missing_phrase_fails() -> None:
    assert not wama.parse_codex_login_status(0, "Not logged in\n", "")
    assert not wama.parse_codex_login_status(0, "", "")


# --- 2. configurable CODEX_HOME -----------------------------------------------


def test_existing_codex_home_is_preserved() -> None:
    env = wama.build_process_env(None, base_env={"CODEX_HOME": "X:\\preexisting", "PATH": "p"})
    assert env["CODEX_HOME"] == "X:\\preexisting"


def test_codex_home_override_wins() -> None:
    env = wama.build_process_env(
        "C:\\Users\\labuser\\.codex", base_env={"CODEX_HOME": "X:\\preexisting"}
    )
    assert env["CODEX_HOME"] == "C:\\Users\\labuser\\.codex"


def test_no_codex_home_when_absent() -> None:
    env = wama.build_process_env(None, base_env={"PATH": "p"})
    assert "CODEX_HOME" not in env


def test_no_user_specific_codex_home_hardcoded_anywhere() -> None:
    # The QGA/SYSTEM lab value is supplied by the tester lane, never baked in.
    repo = Path(__file__).resolve().parents[1]
    for path in (
        SCRIPT,
        repo / "src" / "shellforgeai" / "core" / "windows_evidence_context.py",
        repo / "src" / "shellforgeai" / "commands" / "ask.py",
        repo / "src" / "shellforgeai" / "interactive" / "repl.py",
        repo / "src" / "shellforgeai" / "llm" / "codex.py",
    ):
        source = path.read_text(encoding="utf-8").lower()
        assert "newtwo" not in source, f"user-specific CODEX_HOME path leaked into {path}"


def test_product_codex_provider_inherits_environment() -> None:
    # CODEX_HOME pass-through: the provider must not override the child env,
    # so a tester-scoped CODEX_HOME set in the process flows to the codex CLI.
    source = (
        Path(__file__).resolve().parents[1] / "src" / "shellforgeai" / "llm" / "codex.py"
    ).read_text(encoding="utf-8")
    run_slice = source.split("def _run", 1)[1].split("def stream_complete", 1)[0]
    assert "env=" not in run_slice
    assert "shell=True" not in source


# --- 3. targeted_tests_ok parser ----------------------------------------------


def test_targeted_tests_ok_with_passed_summary() -> None:
    assert wama.targeted_tests_ok(0, "....\n168 passed in 12.3s\n")


def test_targeted_tests_ok_quiet_dot_progress_without_literal_passed() -> None:
    assert wama.targeted_tests_ok(0, "...........................    [100%]\n")


def test_targeted_tests_ok_dot_lines_only() -> None:
    assert wama.targeted_tests_ok(0, "........\n....s...\n")


def test_targeted_tests_ok_handles_carriage_returns_and_ansi() -> None:
    assert wama.targeted_tests_ok(0, "\x1b[32m........ [100%]\x1b[0m\r\n")


def test_targeted_tests_not_ok_on_nonzero_exit_even_with_passed() -> None:
    assert not wama.targeted_tests_ok(1, "167 passed, 1 failed\n")


def test_targeted_tests_not_ok_on_failure_summary() -> None:
    assert not wama.targeted_tests_ok(0, "1 failed, 167 passed\n")


def test_targeted_tests_not_ok_when_no_tests_ran() -> None:
    assert not wama.targeted_tests_ok(0, "no tests ran in 0.01s\n")


def test_targeted_tests_not_ok_on_empty_or_missing_output() -> None:
    assert not wama.targeted_tests_ok(0, "")
    assert not wama.targeted_tests_ok(0, None)
    assert not wama.targeted_tests_ok(None, "168 passed\n")


# --- 4. strict answer grounding -----------------------------------------------


def test_grounded_answer_with_counts_passes() -> None:
    assert wama.answer_uses_process_or_service_evidence(GROUNDED_ANSWER)


def test_missing_evidence_ack_with_both_gap_commands_passes() -> None:
    assert wama.answer_uses_process_or_service_evidence(MISSING_EVIDENCE_ANSWER)


def test_generic_answer_without_evidence_fails() -> None:
    assert not wama.answer_uses_process_or_service_evidence(
        "The system looks fine. Processes and services are running normally."
    )


def test_missing_evidence_ack_without_gap_commands_fails() -> None:
    assert not wama.answer_uses_process_or_service_evidence(
        "I do not have process/service detail in this evidence packet."
    )


def test_bad_preamble_never_counts_as_grounded() -> None:
    assert not wama.answer_uses_process_or_service_evidence(BAD_PREAMBLE_ANSWER)
    assert wama.bad_preamble_detected(BAD_PREAMBLE_ANSWER)


def test_fallback_marker_detection() -> None:
    assert wama.fallback_used("## Windows evidence summary\nFrom the evidence currently loaded")
    assert wama.fallback_used("Model assistance is unavailable, so the evidence is the answer.")
    assert not wama.fallback_used(GROUNDED_ANSWER)


# --- 5. summary semantics -----------------------------------------------------


def _summary(**overrides: object) -> dict:
    kwargs = {
        "codex_login_checked": True,
        "codex_logged_in": True,
        "codex_home_configured": True,
        "same_process_context": True,
        "packet": PACKET_WITH_PROCESS_SERVICE,
        "answer": GROUNDED_ANSWER,
        "model_assisted_answer_ran": True,
        "targeted_tests_exit_code": 0,
        "targeted_tests_output": "........ [100%]\n",
    }
    kwargs.update(overrides)
    return wama.build_summary(**kwargs)


def test_summary_pass_when_everything_proven() -> None:
    summary = _summary()
    assert summary["validation_status"] == "PASS"
    assert summary["codex_login_checked"] is True
    assert summary["codex_logged_in"] is True
    assert summary["codex_home_configured"] is True
    assert summary["evidence_collected"] is True
    assert summary["evidence_context_contains_process_service"] is True
    assert summary["model_assisted_answer_ran"] is True
    assert summary["answer_uses_process_or_service_evidence"] is True
    assert summary["bad_preamble_detected"] is False
    assert summary["fallback_used"] is False
    assert summary["targeted_tests_ok"] is True
    assert summary["read_only"] is True
    assert summary["mutation_performed"] is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"codex_logged_in": False},
        {"codex_home_configured": False},
        {"packet": None},
        {"packet": PACKET_THIN},
        {"model_assisted_answer_ran": False},
        {"answer": "All good."},
        {"answer": BAD_PREAMBLE_ANSWER},
        {"answer": "## Windows evidence summary\nprocesses total=182"},
        {"targeted_tests_exit_code": 1},
        {"targeted_tests_output": ""},
    ],
)
def test_summary_holds_when_any_proof_is_missing(overrides: dict) -> None:
    assert _summary(**overrides)["validation_status"] == "HOLD"


def test_summary_fallback_answer_never_counts_as_model_assisted_pass() -> None:
    fallback_answer = (
        "## Windows evidence summary\n"
        "From the evidence currently loaded, I can see:\n"
        "- Processes total=182 returned=10 (bounded read-only preview).\n"
        "- Services total=98 running=61 stopped=37 (read-only state summary).\n"
        "Safe next read-only commands:\n"
        "- sfai.cmd windows processes --json --limit 10\n"
        "- sfai.cmd windows services --json\n"
    )
    summary = _summary(answer=fallback_answer)
    assert summary["fallback_used"] is True
    assert summary["validation_status"] == "HOLD"


def test_summary_thin_packet_with_honest_answer_still_holds_context_field() -> None:
    summary = _summary(packet=PACKET_THIN, answer=MISSING_EVIDENCE_ANSWER)
    assert summary["evidence_context_contains_process_service"] is False
    assert summary["answer_uses_process_or_service_evidence"] is True
    assert summary["validation_status"] == "HOLD"


# --- 6. safety/source ----------------------------------------------------------


def test_script_source_safety() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    # Scan executable code only; the module docstring may name the forbidden
    # mechanisms in its safety negations ("no WinRM", "No PowerShell").
    docstring = ast.get_docstring(tree) or ""
    code_only = source.replace(docstring, "")
    assert "shell=True" not in code_only
    assert "Power" + "Shell" not in code_only
    assert "Win" + "RM" not in code_only
    assert "os.system" not in code_only
    assert "eval(" not in code_only
    assert "exec(" not in code_only.replace("exec_module", "")
    # No auth-cache/token reads: CODEX_HOME is only exported, never opened.
    assert "auth.json" not in code_only
    assert "auth_cache" not in code_only.replace('"auth_cache_read": False', "")
    top_level_imports = [
        alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names
    ]
    top_level_imports += [
        node.module or "" for node in tree.body if isinstance(node, ast.ImportFrom)
    ]
    # subprocess stays confined to the opt-in --live runner, never module level.
    assert "subprocess" not in top_level_imports


def test_script_never_opens_codex_home_contents() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    for pattern in ('CODEX_HOME"]).read', "codex_home).read", "codex_home / ", "listdir"):
        assert pattern not in source


# --- 7. product model doctor / provider honors tester-scoped CODEX_HOME --------


import json as _json  # noqa: E402
from typing import Any  # noqa: E402

from typer.testing import CliRunner  # noqa: E402

from shellforgeai.cli import app  # noqa: E402
from shellforgeai.llm.codex import CodexProvider  # noqa: E402

_cli_runner = CliRunner()


class _FakeCompleted:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_codex_cli(login_result: _FakeCompleted) -> tuple[Any, list[dict[str, Any]]]:
    """Fake subprocess.run for the codex CLI: --version and login status only."""
    calls: list[dict[str, Any]] = []

    def _run(argv: list[str], **kwargs: Any) -> _FakeCompleted:
        calls.append({"argv": list(argv), "kwargs": dict(kwargs)})
        if argv[1:] == ["login", "status"]:
            return login_result
        if argv[1:] == ["--version"]:
            return _FakeCompleted(0, stdout="codex 0.130.0")
        raise AssertionError(f"unexpected codex CLI invocation: {argv}")

    return _run, calls


def _provider_with_fake_binary() -> CodexProvider:
    provider = CodexProvider()
    provider._resolved_binary = "C:\\fake\\codex-cli\\codex.CMD"
    return provider


def test_provider_login_status_accepts_stdout_phrase(monkeypatch: Any) -> None:
    fake_run, calls = _fake_codex_cli(_FakeCompleted(0, stdout=f"{LOGIN_PHRASE}\n"))
    monkeypatch.setattr("shellforgeai.llm.codex.subprocess.run", fake_run)
    provider = _provider_with_fake_binary()
    status = provider.login_status()
    assert status == {"checked": True, "ok": True, "reason": "codex_login_status_ok"}
    login_call = calls[-1]
    assert login_call["argv"][1:] == ["login", "status"]
    # Same-process context: the login-status child inherits the provider
    # process environment (no env override), so CODEX_HOME governs it.
    assert "env" not in login_call["kwargs"]
    assert "shell" not in login_call["kwargs"]


def test_provider_login_status_accepts_stderr_phrase(monkeypatch: Any) -> None:
    fake_run, _ = _fake_codex_cli(_FakeCompleted(0, stderr=f"info: {LOGIN_PHRASE}\n"))
    monkeypatch.setattr("shellforgeai.llm.codex.subprocess.run", fake_run)
    assert _provider_with_fake_binary().login_status()["ok"] is True


def test_provider_login_status_rejects_nonzero_exit(monkeypatch: Any) -> None:
    fake_run, _ = _fake_codex_cli(_FakeCompleted(1, stdout=LOGIN_PHRASE))
    monkeypatch.setattr("shellforgeai.llm.codex.subprocess.run", fake_run)
    assert _provider_with_fake_binary().login_status()["ok"] is False


def test_provider_login_status_rejects_missing_phrase(monkeypatch: Any) -> None:
    fake_run, _ = _fake_codex_cli(_FakeCompleted(0, stdout="Not logged in\n"))
    monkeypatch.setattr("shellforgeai.llm.codex.subprocess.run", fake_run)
    assert _provider_with_fake_binary().login_status()["ok"] is False


def _pin_codex_home(monkeypatch: Any, tmp_path: Path, *, configured: bool) -> None:
    if configured:
        monkeypatch.setenv("CODEX_HOME", "C:\\Users\\labuser\\.codex")
    else:
        monkeypatch.delenv("CODEX_HOME", raising=False)
    # Empty fake home: the profile-default auth cache does not exist, exactly
    # like the QGA/SYSTEM profile on the lab host.
    monkeypatch.setattr("shellforgeai.llm.codex.Path.home", staticmethod(lambda: tmp_path))


def test_doctor_honors_codex_home_with_proven_login(monkeypatch: Any, tmp_path: Path) -> None:
    _pin_codex_home(monkeypatch, tmp_path, configured=True)
    fake_run, _ = _fake_codex_cli(_FakeCompleted(0, stdout=f"{LOGIN_PHRASE}\n"))
    monkeypatch.setattr("shellforgeai.llm.codex.subprocess.run", fake_run)
    provider = _provider_with_fake_binary()
    info = provider.doctor()
    assert info["codex_home_configured"] is True
    assert info["login_status_checked"] is True
    assert info["login_status_ok"] is True
    assert info["login_status_source"] == "codex_login_status"
    assert info["auth_cache_contents_inspected"] is False
    assert info["auth_readiness"] == "verified_login_status"
    assert info["auth_reason"] == "codex_login_status_ok"
    assert "missing_auth_cache" not in str(info["auth_readiness"])
    assert info["codex_resolved_binary"] == "C:\\fake\\codex-cli\\codex.CMD"
    assert provider.available() == (True, "ok")


def test_doctor_codex_home_login_not_proven_holds_readiness(
    monkeypatch: Any, tmp_path: Path
) -> None:
    _pin_codex_home(monkeypatch, tmp_path, configured=True)
    fake_run, _ = _fake_codex_cli(_FakeCompleted(1, stderr="not logged in"))
    monkeypatch.setattr("shellforgeai.llm.codex.subprocess.run", fake_run)
    provider = _provider_with_fake_binary()
    info = provider.doctor()
    assert info["auth_readiness"] == "login_status_not_proven"
    assert info["login_status_ok"] is False
    ok, reason = provider.available()
    assert ok is False
    assert "login status not proven" in reason


def test_doctor_without_codex_home_keeps_legacy_auth_cache_contract(
    monkeypatch: Any, tmp_path: Path
) -> None:
    _pin_codex_home(monkeypatch, tmp_path, configured=False)

    def _no_login_calls(argv: list[str], **kwargs: Any) -> _FakeCompleted:
        assert argv[1:] != ["login", "status"], "login status must not run without CODEX_HOME"
        return _FakeCompleted(0, stdout="codex 0.130.0")

    monkeypatch.setattr("shellforgeai.llm.codex.subprocess.run", _no_login_calls)
    info = _provider_with_fake_binary().doctor()
    assert info["codex_home_configured"] is False
    assert info["login_status_checked"] is False
    assert info["auth_readiness"] == "missing_auth_cache"


class _DoctorOnlyProvider:
    def __init__(self, info: dict[str, Any], response_ok: bool = True) -> None:
        self._info = info
        self._response_ok = response_ok
        self.complete_calls: list[Any] = []

    def doctor(self) -> dict[str, Any]:
        return dict(self._info)

    def complete(self, req: Any) -> Any:
        self.complete_calls.append(req)
        return type(
            "R",
            (),
            {
                "ok": self._response_ok,
                "text": "SFAI_MODEL_DOCTOR_READY",
                "provider": "openai-codex",
                "model": "gpt-5.5",
                "error": None if self._response_ok else "probe failed",
                "duration_ms": 12,
                "metadata": {},
                "raw": {},
            },
        )()


_CODEX_HOME_DOCTOR_INFO: dict[str, Any] = {
    "provider": "openai-codex",
    "model": "gpt-5.5",
    "codex_binary": "codex",
    "codex_resolved_binary": "C:\\fake\\codex-cli\\codex.CMD",
    "codex_found": True,
    "codex_version": "codex 0.130.0",
    "auth_cache_present": False,
    "auth_cache_contents_inspected": False,
    "codex_home_configured": True,
    "login_status_checked": True,
    "login_status_ok": True,
    "login_status_source": "codex_login_status",
    "auth_readiness": "verified_login_status",
    "auth_reason": "codex_login_status_ok",
    "live_probe_available": False,
    "live_probe_performed": False,
    "safe_next_command": "shellforgeai model doctor --json",
}


def test_model_doctor_json_reports_readiness_from_login_status(monkeypatch: Any) -> None:
    import shellforgeai.cli as cli_mod

    provider = _DoctorOnlyProvider(_CODEX_HOME_DOCTOR_INFO)
    monkeypatch.setattr(cli_mod, "build_provider", lambda *a, **k: provider)
    res = _cli_runner.invoke(app, ["model", "doctor", "--json"])
    assert res.exit_code == 0
    payload = _json.loads(res.stdout)
    assert payload["ok"] is True
    assert payload["status"] == "ok"
    assert payload["auth_readiness"] == "verified_login_status"
    assert payload["auth_readiness"] != "missing_auth_cache"
    assert payload["codex_home_configured"] is True
    assert payload["login_status_checked"] is True
    assert payload["login_status_ok"] is True
    assert payload["login_status_source"] == "codex_login_status"
    assert payload["auth_cache_contents_inspected"] is False
    assert payload["codex_resolved_binary"] == "C:\\fake\\codex-cli\\codex.CMD"
    assert provider.complete_calls == []  # default doctor never calls the model


def test_model_doctor_live_probe_runs_when_login_status_proven(monkeypatch: Any) -> None:
    # The QGA/SYSTEM regression: auth_cache_present=false must not skip the
    # live probe as not_configured when login status is proven via CODEX_HOME.
    import shellforgeai.cli as cli_mod

    provider = _DoctorOnlyProvider(_CODEX_HOME_DOCTOR_INFO)
    monkeypatch.setattr(cli_mod, "build_provider", lambda *a, **k: provider)
    res = _cli_runner.invoke(app, ["model", "doctor", "--live-probe", "--json"])
    assert res.exit_code == 0
    payload = _json.loads(res.stdout)
    assert len(provider.complete_calls) == 1
    assert payload["model_called"] is True
    assert payload["live_probe_performed"] is True
    assert payload["auth_readiness"] == "verified"
    assert payload["probe"]["status"] == "passed"
    assert payload["auth_readiness"] != "not_configured"


def test_model_doctor_live_probe_still_skips_when_login_not_proven(monkeypatch: Any) -> None:
    import shellforgeai.cli as cli_mod

    info = dict(_CODEX_HOME_DOCTOR_INFO)
    info.update(
        {
            "login_status_ok": False,
            "auth_readiness": "login_status_not_proven",
            "auth_reason": "login_status_not_proven",
        }
    )
    provider = _DoctorOnlyProvider(info)
    monkeypatch.setattr(cli_mod, "build_provider", lambda *a, **k: provider)
    res = _cli_runner.invoke(app, ["model", "doctor", "--live-probe", "--json"])
    assert res.exit_code == 0
    payload = _json.loads(res.stdout)
    assert provider.complete_calls == []
    assert payload["model_called"] is False
    assert payload["auth_readiness"] == "not_configured"
    assert payload["probe"]["status"] == "skipped"


def test_model_doctor_human_output_notes_login_status_and_no_cache_inspection(
    monkeypatch: Any,
) -> None:
    import shellforgeai.cli as cli_mod

    provider = _DoctorOnlyProvider(_CODEX_HOME_DOCTOR_INFO)
    monkeypatch.setattr(cli_mod, "build_provider", lambda *a, **k: provider)
    res = _cli_runner.invoke(app, ["model", "doctor"])
    assert res.exit_code == 0
    assert "Codex login status: proven (Logged in using ChatGPT)" in res.stdout
    assert "Auth cache contents were not inspected." in res.stdout
    assert "Suggested login:" not in res.stdout


def test_summary_model_assisted_answer_ran_false_when_fallback_used() -> None:
    summary = _summary(answer="## Windows evidence summary\nprocesses total=182")
    assert summary["fallback_used"] is True
    assert summary["model_assisted_answer_ran"] is False
    assert summary["validation_status"] == "HOLD"


# --- 8. Windows model invocation: prompt transport + bounded timeout -----------


import subprocess as _subprocess_mod  # noqa: E402

from shellforgeai.commands.model import MODEL_DOCTOR_PROBE_TIMEOUT_SECONDS  # noqa: E402

MULTILINE_EVIDENCE_PROMPT = (
    "Question: What is running on this system?\n"
    'Context:\n{\n  "windows_evidence": {"processes": {"total_count": 182}},\n'
    '  "services": "total=98 running=61",\n'
    '  "cmd_hazards": "100%% !delayed! ^caret & ampersand <redir>"\n}\n'
) * 8


class _RecordingPopen:
    """Fake Popen capturing argv, kwargs, and the communicate() stdin input."""

    instances: list[_RecordingPopen] = []

    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        self.cmd = list(cmd)
        self.kwargs = dict(kwargs)
        self.communicate_input: Any = "unset"
        self.returncode = 0
        type(self).instances.append(self)
        for i, tok in enumerate(cmd):
            if tok == "--output-last-message" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text("grounded windows answer", encoding="utf-8")

    def communicate(self, input: Any = None, timeout: Any = None) -> tuple[str, str]:
        self.communicate_input = input
        return ("", "")

    def poll(self) -> int:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


def _reset_recording_popen() -> None:
    _RecordingPopen.instances = []


def test_windows_codex_prompt_goes_via_stdin_not_cmd_argv(monkeypatch: Any) -> None:
    # Windows .CMD wrappers route through cmd.exe: multi-KB prompts in argv hit
    # the 8191-char limit and %/! expansion. The prompt must travel over stdin.
    _reset_recording_popen()
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: True)
    monkeypatch.setattr("subprocess.Popen", _RecordingPopen)
    provider = _provider_with_fake_binary()
    from shellforgeai.llm.schemas import ModelRequest

    resp = provider.complete(
        ModelRequest(prompt=MULTILINE_EVIDENCE_PROMPT, model="gpt-5.5", provider="openai-codex")
    )
    assert resp.ok
    proc = _RecordingPopen.instances[0]
    assert MULTILINE_EVIDENCE_PROMPT not in proc.cmd
    assert proc.cmd[-1] == "-"
    assert proc.kwargs["stdin"] == _subprocess_mod.PIPE
    assert proc.communicate_input == MULTILINE_EVIDENCE_PROMPT
    assert len(" ".join(proc.cmd)) < 512  # command line stays tiny for cmd.exe


def test_posix_codex_prompt_stays_in_argv(monkeypatch: Any) -> None:
    _reset_recording_popen()
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: False)
    monkeypatch.setattr("subprocess.Popen", _RecordingPopen)
    provider = _provider_with_fake_binary()
    from shellforgeai.llm.schemas import ModelRequest

    resp = provider.complete(
        ModelRequest(prompt="hi there", model="gpt-5.5", provider="openai-codex")
    )
    assert resp.ok
    proc = _RecordingPopen.instances[0]
    assert proc.cmd[-1] == "hi there"
    assert proc.kwargs["stdin"] == _subprocess_mod.DEVNULL
    assert proc.communicate_input is None


class _HangingPopen:
    """Fake Popen whose first communicate() times out; records shutdown calls."""

    last: _HangingPopen | None = None

    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        self.cmd = list(cmd)
        self.kwargs = dict(kwargs)
        self.terminate_called = False
        self.kill_called = False
        self.signals: list[Any] = []
        self._timed_out_once = False
        self.returncode = None
        type(self).last = self

    def communicate(self, input: Any = None, timeout: Any = None) -> tuple[str, str]:
        if not self._timed_out_once:
            self._timed_out_once = True
            raise _subprocess_mod.TimeoutExpired(cmd=self.cmd, timeout=timeout)
        self.returncode = -15
        return ("", "")

    def poll(self) -> Any:
        return self.returncode

    def send_signal(self, sig: Any) -> None:
        self.signals.append(sig)

    def terminate(self) -> None:
        self.terminate_called = True

    def kill(self) -> None:
        self.kill_called = True


def test_codex_timeout_is_bounded_precise_and_stops_children(monkeypatch: Any) -> None:
    monkeypatch.setattr("subprocess.Popen", _HangingPopen)
    provider = _provider_with_fake_binary()
    from shellforgeai.llm.codex import CodexProvider
    from shellforgeai.llm.schemas import ModelRequest

    resp = provider.complete(
        ModelRequest(prompt="hi", model="gpt-5.5", provider="openai-codex", timeout_seconds=7)
    )
    assert not resp.ok
    assert "timed out after 7s" in (resp.error or "")
    assert "bounded timeout" in (resp.error or "")
    proc = _HangingPopen.last
    assert proc is not None
    assert proc.terminate_called  # shutdown attempted, no indefinite wait
    assert not CodexProvider._active_procs  # no lingering tracked child


def test_probe_timeout_is_realistic_but_still_bounded() -> None:
    # A real codex roundtrip regularly exceeds the old 10s, which misreported
    # healthy auth as timeout; the probe stays bounded, never indefinite.
    assert 30 <= MODEL_DOCTOR_PROBE_TIMEOUT_SECONDS <= 120


def test_live_probe_timeout_reports_failed_and_never_passes(monkeypatch: Any) -> None:
    import shellforgeai.cli as cli_mod

    class _TimeoutProbeProvider(_DoctorOnlyProvider):
        def complete(self, req: Any) -> Any:
            self.complete_calls.append(req)
            return type(
                "R",
                (),
                {
                    "ok": False,
                    "text": "",
                    "provider": "openai-codex",
                    "model": "gpt-5.5",
                    "error": "codex timed out after 60s (bounded timeout; no indefinite wait)",
                    "duration_ms": 60000,
                    "metadata": {},
                    "raw": {},
                },
            )()

    provider = _TimeoutProbeProvider(_CODEX_HOME_DOCTOR_INFO)
    monkeypatch.setattr(cli_mod, "build_provider", lambda *a, **k: provider)
    res = _cli_runner.invoke(app, ["model", "doctor", "--live-probe", "--json"])
    assert res.exit_code == 0
    payload = _json.loads(res.stdout)
    assert len(provider.complete_calls) == 1
    assert payload["ok"] is False
    assert payload["auth_readiness"] == "failed"
    assert payload["probe"]["status"] == "failed"
    assert payload["probe"]["error_class"] == "timeout"
    assert "timed out" in payload["probe"]["error_message"]
    assert payload["model_called"] is True  # the attempt is represented honestly


def test_timeout_wording_counts_as_fallback_and_holds_acceptance() -> None:
    timed_out_answer = (
        "## Windows evidence summary\nFrom the evidence currently loaded, I can "
        "see host facts.\nNote: model synthesis unavailable (codex timed out "
        "after 180s); the Windows read-only evidence above is the answer."
    )
    assert wama.fallback_used(timed_out_answer)
    summary = _summary(answer=timed_out_answer)
    assert summary["fallback_used"] is True
    assert summary["model_assisted_answer_ran"] is False
    assert summary["validation_status"] == "HOLD"
    assert wama.fallback_used("Codex timed out before producing a response.")
