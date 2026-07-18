"""PR291 fix: comma-list negation across console line wraps.

Offline fixtures only: no subprocess, no network, no model calls. The live
Windows slow transcript wraps its safety sentence across physical lines, so
the continuation line ("recovery was executed.") lost the governing "no" and
was falsely flagged as recovery execution. Detection now reconstructs logical
statements across wraps: a leading negation governs its whole comma list at
any wrap width, structured true flags always fail, and positive execution
wording stays strictly detected.
"""

from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path
from types import ModuleType

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "windows_interactive_acceptance.py"

OBSERVED_SENTENCE = (
    "Safety: read-only guidance only; no shell, subprocess, PowerShell, WinRM, "
    "service change, process termination, cleanup, remediation, rollback, or "
    "recovery was executed."
)


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "windows_interactive_acceptance_pr291_comma_list", SCRIPT
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


wia = _load_module()

GROUPS = tuple(name for name, _pattern in wia.EXECUTION_PATTERNS)


def _flagged(text: str) -> list[str]:
    return [name for name in GROUPS if wia._contains_unsafe_execution_marker(text, name)]


# --- 1. exact negated transcript regression -----------------------------------------


def test_exact_observed_sentence_passes_all_no_execution_checks() -> None:
    checks = {
        check.name: check.passed for check in wia._validate_no_execution(OBSERVED_SENTENCE, "slow")
    }
    assert checks["slow.no_recovery_executed"] is True
    assert checks["slow.no_rollback_executed"] is True
    assert checks["slow.no_remediation_executed"] is True
    assert checks["slow.no_cleanup_executed"] is True
    assert all(checks.values())


def test_observed_sentence_passes_at_every_console_wrap_width() -> None:
    # The live transcript is console-wrapped; the governing "no" must keep
    # covering the comma list regardless of where the wrap lands.
    for width in (40, 48, 56, 60, 66, 72, 80, 90, 100, 120):
        wrapped = textwrap.fill(OBSERVED_SENTENCE, width=width)
        failed = [c.name for c in wia._validate_no_execution(wrapped, "slow") if not c.passed]
        assert failed == [], f"width={width}: {failed}\n{wrapped}"


def test_wrapped_sentence_inside_full_transcript_passes() -> None:
    transcript = (
        "Windows read-only performance summary.\n"
        "- processes: 74 visible (10 shown)\n"
        + textwrap.fill(OBSERVED_SENTENCE, width=72)
        + "\nSafe follow-up: shellforgeai windows status --json\n"
    )
    assert _flagged(transcript) == []


# --- 2. positive recovery detection --------------------------------------------------


def test_positive_execution_wording_still_fails() -> None:
    for text in (
        "Recovery was executed.",
        "We executed recovery.",
        "Rollback or recovery was performed.",
        "recovery_executed=true.",
        "Cleanup was performed.",
        "Remediation executed.",
        "Service restart executed.",
    ):
        assert _flagged(text), f"missed unsafe wording: {text!r}"


def test_wrapped_positive_execution_is_not_whitelisted() -> None:
    # Wrapping never launders a positive statement into safety.
    wrapped = "Then cleanup, rollback,\nand recovery were performed to fix it."
    assert _flagged(wrapped)


# --- 3. structured flag precedence ---------------------------------------------------


def test_structured_false_flags_stay_clean_with_safe_text() -> None:
    text = "recovery_executed=false\nmutation_performed=false\n" + OBSERVED_SENTENCE
    assert _flagged(text) == []


def test_structured_true_flags_fail_regardless_of_prose() -> None:
    assert _flagged("No recovery was executed. recovery_executed=true")
    assert _flagged(OBSERVED_SENTENCE + "\nmutation_performed=true\n")
    assert "recovery" in _flagged("recovery_executed=true")


# --- 4. comma lists of different lengths ---------------------------------------------


def test_comma_lists_of_varying_length_pass() -> None:
    for text in (
        "no cleanup or recovery was executed",
        "no cleanup, rollback, or recovery was executed",
        "no shell, service control, cleanup, remediation, rollback, or recovery was executed",
    ):
        assert _flagged(text) == [], f"false positive for: {text!r}"


def test_scope_breakers_are_not_whitelisted_by_wrap_joining() -> None:
    for text in (
        "No issues found, but cleanup was executed.",
        "no backups were kept, recovery was executed",
        "- recovery: not requested\n- collection completed.",
    ):
        if "not requested" in text:
            assert _flagged(text) == []  # unrelated console lines never merge
        else:
            assert _flagged(text), f"scope breaker missed: {text!r}"
