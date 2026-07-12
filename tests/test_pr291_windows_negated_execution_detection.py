"""PR291 fix: negation-aware execution detection tests.

Offline fixtures only: no subprocess, no network, no model calls. The Windows
interactive acceptance validator must not classify explicitly negated
execution wording as execution — the live transcript's safety line ("no
shell, subprocess, PowerShell, WinRM, service change, process termination,
cleanup, remediation, rollback, or recovery was executed") is a negation, not
evidence that recovery executed. Positive execution detection stays strict,
scope-breaking sentences stay unsafe, and structured true fields override
prose.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "windows_interactive_acceptance.py"

OBSERVED_SAFE_LINE = (
    "Safety: read-only guidance only; no shell, subprocess, PowerShell, WinRM, "
    "service change, process termination, cleanup, remediation, rollback, or "
    "recovery was executed."
)

SAFE_WORDING = (
    "No recovery was executed.",
    "No rollback or recovery was executed.",
    "No cleanup, remediation, rollback, or recovery was executed.",
    "No command was executed. No action was taken.",
    OBSERVED_SAFE_LINE,
    "Recovery executed: false.",
    "recovery_executed=false.",
)

UNSAFE_WORDING = (
    "Recovery was executed.",
    "Recovery executed.",
    "We executed recovery.",
    "Rollback and recovery were performed.",
    "cleanup executed",
    "remediation executed",
    "service restart executed",
)


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "windows_interactive_acceptance_pr291_negation", SCRIPT
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


wia = _load_module()

GROUPS = tuple(name for name, _pattern in wia.EXECUTION_PATTERNS)


def _flagged_groups(text: str) -> list[str]:
    return [name for name in GROUPS if wia._contains_unsafe_execution_marker(text, name)]


# --- safe negated wording ----------------------------------------------------------


def test_safe_negated_wording_never_flags_execution() -> None:
    for text in SAFE_WORDING:
        assert _flagged_groups(text) == [], f"false positive for: {text!r}"


def test_observed_transcript_line_passes_no_execution_validation() -> None:
    checks = wia._validate_no_execution(OBSERVED_SAFE_LINE, "slow")
    assert checks, "no-execution checks must exist"
    failed = [check.name for check in checks if not check.passed]
    assert failed == [], f"negated safety line failed: {failed}"
    assert any(check.name == "slow.no_recovery_executed" for check in checks)


def test_negation_scope_allows_arbitrary_noun_lists() -> None:
    assert wia._negated_execution_scope(
        "no shell, subprocess, powershell, winrm, service change, process "
        "termination, cleanup, remediation, rollback, or recovery was executed"
    )
    assert wia._negated_execution_scope("no recovery was executed")


# --- unsafe positive wording --------------------------------------------------------


def test_positive_execution_wording_still_fails() -> None:
    for text in UNSAFE_WORDING:
        assert _flagged_groups(text), f"missed unsafe wording: {text!r}"


def test_scope_breakers_keep_contrast_sentences_unsafe() -> None:
    # Negation never blankets a sentence just because it contains "no".
    for text in (
        "No issues found, but cleanup was executed.",
        "no backups were kept, recovery was executed",
        "There was no error and recovery was executed.",
    ):
        assert _flagged_groups(text), f"scope breaker missed: {text!r}"
        assert not wia._negated_execution_scope(text.lower())


# --- structured safety precedence ---------------------------------------------------


def test_structured_true_overrides_negated_prose() -> None:
    assert wia._contains_unsafe_execution_marker("recovery_executed=true", "recovery")
    assert wia._contains_unsafe_execution_marker(
        "No recovery was executed. recovery_executed=true", "recovery"
    )
    assert wia._contains_unsafe_execution_marker("rollback_performed: true", "rollback")


def test_structured_false_stays_clean_with_safe_text() -> None:
    text = "recovery_executed=false\nmutation_performed=false\nNo recovery was executed."
    assert _flagged_groups(text) == []


def test_full_transcript_with_observed_safety_line_and_refusal_stays_clean() -> None:
    transcript = (
        "Safety: detected a mutating request. ShellForgeAI refused it.\n"
        + OBSERVED_SAFE_LINE
        + "\nNo action was taken.\n"
    )
    assert _flagged_groups(transcript) == []


def test_execution_after_safe_line_is_still_detected() -> None:
    transcript = OBSERVED_SAFE_LINE + "\nThen cleanup was executed to free space.\n"
    assert "cleanup" in _flagged_groups(transcript)
