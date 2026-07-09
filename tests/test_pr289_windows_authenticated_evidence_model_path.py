"""PR289 fix: authenticated Windows evidence-to-model path orchestration.

Proves, with fake runners and fake providers only (no network, no real model
calls, no auth-cache reads):

* the acceptance lane checks Codex login status BEFORE the model-assisted
  step, in the SAME process environment (tester-scoped ``CODEX_HOME``
  included) used for the model-assisted run;
* the model-assisted step never runs when login is not proven, and a
  fallback/model-unavailable answer never counts as a model-assisted pass;
* the saved-artifact mode reproduces the same verdicts end-to-end;
* the product interactive/ask Windows paths persist the exact evidence packet
  passed into model context (``windows-evidence-context.json``) inside the
  established artifact flow, so the QA lane can verify grounding.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo


def _load_by_path(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_sibling = _load_by_path(
    "pr289_windows_interactive_evidence_context_fixtures",
    Path(__file__).resolve().parent / "test_pr289_windows_interactive_evidence_context.py",
)
GOOD_EVIDENCE_ANSWER = _sibling.GOOD_EVIDENCE_ANSWER
OBSERVED_BAD_PREAMBLE = _sibling.OBSERVED_BAD_PREAMBLE
_GoodEvidenceProvider = _sibling._GoodEvidenceProvider
_pin_context_builders = _sibling._pin_context_builders

runner = CliRunner()

SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "windows_authenticated_model_acceptance.py"
)

WINDOWS_INFO = PlatformInfo(
    system="windows",
    python_platform="Windows-2025Server-10.0.26100",
    os_name="nt",
    release="2025Server",
    machine="AMD64",
)

LOGIN_OK = "Logged in using ChatGPT\n"

FAKE_PACKET = {
    "platform": "windows",
    "read_only": True,
    "mutation_performed": False,
    "processes": {"available": True, "total_count": 182, "returned_count": 10},
    "services": {"available": True, "total_count": 98, "running_count": 61},
}


wama = _load_by_path("windows_authenticated_model_acceptance_path", SCRIPT)


class _RunnerLog:
    """Records every fake child invocation: argv, env identity, order."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict[str, str]]] = []

    def runner(self, result: Any) -> Any:
        def _run(argv: list[str], env: dict[str, str]) -> Any:
            self.calls.append((list(argv), env))
            return result

        return _run


def _result(exit_code: int, stdout: str = "", stderr: str = "") -> Any:
    return wama.CommandResult(exit_code=exit_code, stdout=stdout, stderr=stderr)


# --- live orchestration with injected runners ----------------------------------


def test_login_is_checked_before_model_assisted_step_with_same_env() -> None:
    log = _RunnerLog()
    summary = wama.run_authenticated_acceptance(
        codex_binary="C:\\Tools\\ShellForgeAI\\tools\\codex-cli\\codex.CMD",
        sfai_binary="C:\\Tools\\ShellForgeAI\\bin\\sfai.cmd",
        codex_home="C:\\Users\\labuser\\.codex",
        login_runner=log.runner(_result(0, stdout=LOGIN_OK)),
        ask_runner=log.runner(_result(0, stdout=GOOD_EVIDENCE_ANSWER)),
        packet_builder=lambda: dict(FAKE_PACKET),
        targeted_tests_exit_code=0,
        targeted_tests_output="........ [100%]\n",
        base_env={"PATH": "p"},
    )
    assert [argv[-2:] if len(argv) > 2 else argv[1:] for argv, _ in log.calls][0] == [
        "login",
        "status",
    ]
    assert log.calls[1][0][1] == "ask"
    assert log.calls[1][0][2] == "What is running on this system?"
    # Same process context: both children received the identical env mapping,
    # carrying the tester-scoped CODEX_HOME.
    login_env, ask_env = log.calls[0][1], log.calls[1][1]
    assert login_env is ask_env
    assert ask_env["CODEX_HOME"] == "C:\\Users\\labuser\\.codex"
    assert summary["codex_login_checked"] is True
    assert summary["codex_logged_in"] is True
    assert summary["codex_home_configured"] is True
    assert summary["same_process_context"] is True
    assert summary["model_assisted_answer_ran"] is True
    assert summary["answer_uses_process_or_service_evidence"] is True
    assert summary["validation_status"] == "PASS"


def test_model_assisted_step_never_runs_when_login_not_proven() -> None:
    log = _RunnerLog()

    def _ask_must_not_run(argv: list[str], env: dict[str, str]) -> Any:
        raise AssertionError("model-assisted step must not run without proven login")

    summary = wama.run_authenticated_acceptance(
        codex_binary="codex",
        sfai_binary="sfai.cmd",
        login_runner=log.runner(_result(1, stderr="error: not logged in")),
        ask_runner=_ask_must_not_run,
        packet_builder=lambda: dict(FAKE_PACKET),
        base_env={"PATH": "p"},
    )
    assert summary["codex_logged_in"] is False
    assert summary["model_assisted_answer_ran"] is False
    assert summary["evidence_collected"] is False
    assert summary["validation_status"] == "HOLD"


def test_login_phrase_on_stderr_is_accepted_in_orchestration() -> None:
    log = _RunnerLog()
    summary = wama.run_authenticated_acceptance(
        codex_binary="codex",
        sfai_binary="sfai.cmd",
        codex_home="C:\\Users\\labuser\\.codex",
        login_runner=log.runner(_result(0, stdout="", stderr=LOGIN_OK)),
        ask_runner=log.runner(_result(0, stdout=GOOD_EVIDENCE_ANSWER)),
        packet_builder=lambda: dict(FAKE_PACKET),
        targeted_tests_exit_code=0,
        targeted_tests_output="1 passed\n",
        base_env={},
    )
    assert summary["codex_logged_in"] is True
    assert summary["validation_status"] == "PASS"


def test_bad_preamble_answer_holds_and_is_flagged() -> None:
    log = _RunnerLog()
    summary = wama.run_authenticated_acceptance(
        codex_binary="codex",
        sfai_binary="sfai.cmd",
        codex_home="C:\\Users\\labuser\\.codex",
        login_runner=log.runner(_result(0, stdout=LOGIN_OK)),
        ask_runner=log.runner(_result(0, stdout=OBSERVED_BAD_PREAMBLE)),
        packet_builder=lambda: dict(FAKE_PACKET),
        targeted_tests_exit_code=0,
        targeted_tests_output="1 passed\n",
        base_env={},
    )
    assert summary["bad_preamble_detected"] is True
    assert summary["answer_uses_process_or_service_evidence"] is False
    assert summary["validation_status"] == "HOLD"


def test_fallback_answer_is_not_a_model_assisted_pass() -> None:
    log = _RunnerLog()
    fallback = (
        "## Windows evidence summary\n"
        "- Processes total=182 returned=10 (bounded read-only preview).\n"
        "- sfai.cmd windows processes --json --limit 10\n"
    )
    summary = wama.run_authenticated_acceptance(
        codex_binary="codex",
        sfai_binary="sfai.cmd",
        codex_home="C:\\Users\\labuser\\.codex",
        login_runner=log.runner(_result(0, stdout=LOGIN_OK)),
        ask_runner=log.runner(_result(0, stdout=fallback)),
        packet_builder=lambda: dict(FAKE_PACKET),
        targeted_tests_exit_code=0,
        targeted_tests_output="1 passed\n",
        base_env={},
    )
    assert summary["fallback_used"] is True
    assert summary["validation_status"] == "HOLD"


# --- saved-artifact mode end-to-end --------------------------------------------


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_saved_mode_pass_report(tmp_path: Path, capsys: Any) -> None:
    login_out = _write(tmp_path / "login.txt", LOGIN_OK)
    answer = _write(tmp_path / "answer.txt", GOOD_EVIDENCE_ANSWER)
    evidence = _write(tmp_path / "windows-evidence-context.json", json.dumps(FAKE_PACKET))
    tests_out = _write(tmp_path / "pytest.txt", "...........................    [100%]\n")
    code = wama.main(
        [
            "--codex-home",
            "C:\\Users\\labuser\\.codex",
            "--login-status-exit-code",
            "0",
            "--login-status-stdout",
            str(login_out),
            "--answer-transcript",
            str(answer),
            "--evidence-context-json",
            str(evidence),
            "--targeted-tests-exit-code",
            "0",
            "--targeted-tests-output",
            str(tests_out),
            "--json",
        ]
    )
    result = json.loads(capsys.readouterr().out)
    summary = result["summary"]
    assert code == 0
    assert summary["validation_status"] == "PASS"
    assert summary["targeted_tests_ok"] is True
    assert summary["evidence_context_contains_process_service"] is True
    assert result["safety"]["auth_cache_read"] is False
    assert result["safety"]["token_contents_displayed"] is False


def test_saved_mode_holds_on_bad_preamble_transcript(tmp_path: Path, capsys: Any) -> None:
    login_out = _write(tmp_path / "login.txt", LOGIN_OK)
    answer = _write(tmp_path / "answer.txt", OBSERVED_BAD_PREAMBLE)
    evidence = _write(tmp_path / "windows-evidence-context.json", json.dumps(FAKE_PACKET))
    code = wama.main(
        [
            "--codex-home",
            "C:\\Users\\labuser\\.codex",
            "--login-status-exit-code",
            "0",
            "--login-status-stdout",
            str(login_out),
            "--answer-transcript",
            str(answer),
            "--evidence-context-json",
            str(evidence),
            "--targeted-tests-exit-code",
            "0",
            "--json",
        ]
    )
    summary = json.loads(capsys.readouterr().out)["summary"]
    assert code == 1
    assert summary["bad_preamble_detected"] is True
    assert summary["validation_status"] == "HOLD"


def test_saved_mode_holds_without_login_proof(tmp_path: Path, capsys: Any) -> None:
    answer = _write(tmp_path / "answer.txt", GOOD_EVIDENCE_ANSWER)
    code = wama.main(
        [
            "--login-status-exit-code",
            "1",
            "--answer-transcript",
            str(answer),
            "--targeted-tests-exit-code",
            "0",
            "--json",
        ]
    )
    summary = json.loads(capsys.readouterr().out)["summary"]
    assert code == 1
    assert summary["codex_logged_in"] is False
    assert summary["model_assisted_answer_ran"] is False
    assert summary["validation_status"] == "HOLD"


def test_saved_mode_markdown_reports_all_fields(tmp_path: Path, capsys: Any) -> None:
    login_out = _write(tmp_path / "login.txt", LOGIN_OK)
    answer = _write(tmp_path / "answer.txt", GOOD_EVIDENCE_ANSWER)
    evidence = _write(tmp_path / "windows-evidence-context.json", json.dumps(FAKE_PACKET))
    wama.main(
        [
            "--codex-home",
            "C:\\Users\\labuser\\.codex",
            "--login-status-exit-code",
            "0",
            "--login-status-stdout",
            str(login_out),
            "--answer-transcript",
            str(answer),
            "--evidence-context-json",
            str(evidence),
            "--targeted-tests-exit-code",
            "0",
            "--targeted-tests-output",
            str(_write(tmp_path / "pytest.txt", "1 passed\n")),
            "--markdown",
        ]
    )
    out = capsys.readouterr().out
    for field in (
        "codex_login_checked",
        "codex_logged_in",
        "codex_home_configured",
        "evidence_collected",
        "evidence_context_contains_process_service",
        "model_assisted_answer_ran",
        "answer_uses_process_or_service_evidence",
        "bad_preamble_detected",
        "fallback_used",
        "targeted_tests_ok",
        "validation_status",
    ):
        assert field in out
    assert "no auth-cache/token contents" in out


# --- product artifact flow: evidence packet visible to the QA lane -------------


def test_interactive_windows_path_persists_evidence_context_artifact(
    monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "shellforgeai.core.windows_evidence_context.detect_platform", lambda: WINDOWS_INFO
    )
    _pin_context_builders(monkeypatch)
    _GoodEvidenceProvider.prompts = []
    monkeypatch.setattr(
        "shellforgeai.interactive.repl.build_provider", lambda *_: _GoodEvidenceProvider()
    )
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="What is running on this system?\n/exit\n",
    )
    assert res.exit_code == 0
    artifacts = list(tmp_path.rglob("windows-evidence-context.json"))
    assert artifacts
    packet = json.loads(artifacts[0].read_text(encoding="utf-8"))
    assert packet["read_only"] is True
    assert packet["mutation_performed"] is False
    assert packet["processes"]["available"] is True
    assert packet["processes"]["total_count"] == 182
    assert packet["services"]["total_count"] == 98
    assert packet["services"]["running_count"] == 61
    assert wama.evidence_context_contains_process_service(packet)


def test_ask_windows_path_persists_evidence_context_artifact(
    monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "shellforgeai.core.windows_evidence_context.detect_platform", lambda: WINDOWS_INFO
    )
    _pin_context_builders(monkeypatch)
    _GoodEvidenceProvider.prompts = []
    monkeypatch.setattr("shellforgeai.cli.build_provider", lambda *_: _GoodEvidenceProvider())
    res = runner.invoke(app, ["ask", "What is running on this system?"])
    assert res.exit_code == 0
    artifacts = list(tmp_path.rglob("windows-evidence-context.json"))
    assert artifacts
    packet = json.loads(artifacts[0].read_text(encoding="utf-8"))
    assert packet["processes"]["available"] is True
    assert packet["services"]["available"] is True
    assert wama.evidence_context_contains_process_service(packet)
