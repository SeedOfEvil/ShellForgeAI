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
