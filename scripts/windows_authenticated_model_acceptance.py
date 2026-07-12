#!/usr/bin/env python3
"""Authenticated Windows evidence-to-model acceptance helper (PR289 fix).

QA/harness-only. This helper proves the Windows model-assisted evidence path
end-to-end for the exact target behavior:

1. Codex login status is verified in the SAME process environment that the
   model-assisted answer uses (tester-scoped ``CODEX_HOME`` supported via
   ``--codex-home`` or the pre-existing environment variable; never hardcoded
   into product code).
2. The bounded read-only Windows evidence packet is collected/loaded and
   checked for process/service facts.
3. The model-assisted answer for ``What is running on this system?`` is
   validated strictly: it must reference real process/service evidence or
   explicitly acknowledge the missing evidence with the safe read-only gap
   commands; project/policy preamble, metadata-primary answers,
   Docker/container framing, and deterministic-fallback output never count as
   a model-assisted pass.
4. Summary fields reflect real results: ``targeted_tests_ok`` is based on the
   pytest exit code plus reliable completion evidence (quiet dot progress and
   ``[100%]`` markers count), not a brittle literal ``passed`` substring;
   Codex login detection accepts ``Logged in using ChatGPT`` on stdout or
   stderr when the exit code is 0.

Safety: the helper never reads, copies, prints, archives, or parses
auth-cache/token contents — it only sets the ``CODEX_HOME`` environment
variable for its child processes and checks ``codex login status`` output.
The default mode validates saved artifacts only and runs nothing. The opt-in
``--live`` mode runs exactly two fixed argv commands (``<codex> login
status`` and ``<sfai> ask <prompt>``) without any shell, and refuses to run
the model-assisted step when login is not proven. No PowerShell, no
WinRM/remoting, no QGA/Proxmox integration, no mutation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HELPER_DIR = Path(__file__).resolve().parent
REPO_ROOT = HELPER_DIR.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from shellforgeai.core.windows_evidence_context import (  # noqa: E402
    build_windows_evidence_context,
    contains_project_policy_preamble,
    is_container_primary_framing,
    is_metadata_primary_answer,
)

CODEX_LOGIN_PHRASE = "Logged in using ChatGPT"
DEFAULT_PROMPT = "What is running on this system?"

SAFE_GAP_COMMANDS = (
    "sfai.cmd windows processes --json --limit 10",
    "sfai.cmd windows services --json",
)

# Markers that identify the deterministic gated/model-unavailable fallback.
# A fallback answer is safe operator output but is never a model-assisted
# pass; a timed-out model invocation keeps the lane HOLD the same way.
FALLBACK_MARKERS = (
    "## windows evidence summary",
    "model assistance is unavailable",
    "model synthesis unavailable",
    "model-assisted assessment unavailable",
    "repository trust check blocked",
    "model failure class:",
    "codex cli argument error",
    "unexpected argument",
    "codex timed out",
    "timed out before producing a response",
)

# Bounded excerpt cap for sanitized failure lines kept in the summary.
FAILURE_EXCERPT_MAX_CHARS = 400

# PR291 fix — deterministic Windows-targeted pytest selection. The maintained
# Windows runner launches processes without a shell (ProcessStartInfo), so a
# literal ``tests/test_pr291_*.py`` wildcard reaches pytest unexpanded and
# pytest exits 4 ("file or directory not found"). The targeted set is
# therefore resolved HERE with Python filesystem APIs (sorted, explicit file
# paths; never shell glob expansion, never any shell).
TARGETED_TEST_GLOBS = ("test_pr291_*.py",)
TARGETED_TEST_EXPLICIT_FILES = ("test_codex_provider.py",)
TARGETED_TEST_OUTPUT_EXCERPT_MAX_CHARS = 2000

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_PYTEST_FAILURE_RE = re.compile(r"\b\d+\s+(failed|errors?)\b|\bno tests ran\b", re.I)
_PYTEST_COMPLETION_RE = re.compile(r"\b\d+\s+passed\b|\[\s*100%\s*\]|^[.sxX]{3,}\s*$", re.M)

# Missing-evidence language must name the specific missing category; generic
# "check processes/services" wording is intentionally insufficient.
_MISSING_EVIDENCE_MARKERS = (
    "not present in this evidence packet",
    "not in this evidence packet",
    "missing from the current evidence packet",
    "do not have",
    "don't have",
    "unavailable",
    "not available",
    "lacks",
)


@dataclass(frozen=True)
class GroundingFacts:
    """Normalized process/service facts extracted from one evidence packet."""

    process_available: bool = False
    service_available: bool = False
    process_total: int | None = None
    process_returned: int | None = None
    process_names: tuple[str, ...] = ()
    process_collection: str | None = None
    process_limitation: str | None = None
    service_total: int | None = None
    service_running: int | None = None
    service_stopped: int | None = None
    service_returned: int | None = None
    service_names: tuple[str, ...] = ()
    service_collection: str | None = None
    service_limitation: str | None = None


@dataclass(frozen=True)
class GroundingResult:
    """Explainable authenticated answer-grounding decision."""

    process_evidence_available: bool
    service_evidence_available: bool
    process_grounding_detected: bool
    service_grounding_detected: bool
    matched_process_facts: list[str] = field(default_factory=list)
    matched_service_facts: list[str] = field(default_factory=list)
    missing_required_grounding: list[str] = field(default_factory=list)
    answer_uses_process_or_service_evidence: bool = False
    grounding_reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "process_evidence_available": self.process_evidence_available,
            "service_evidence_available": self.service_evidence_available,
            "process_grounding_detected": self.process_grounding_detected,
            "service_grounding_detected": self.service_grounding_detected,
            "matched_process_facts": self.matched_process_facts,
            "matched_service_facts": self.matched_service_facts,
            "missing_required_grounding": self.missing_required_grounding,
            "answer_uses_process_or_service_evidence": self.answer_uses_process_or_service_evidence,
            "grounding_reason": self.grounding_reason,
        }


@dataclass(frozen=True)
class CommandResult:
    """Captured child-process result (no shell, argv-list execution only)."""

    exit_code: int
    stdout: str
    stderr: str


Runner = Callable[[list[str], dict[str, str]], CommandResult]


def build_process_env(
    codex_home: str | None, base_env: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Environment for BOTH the login check and the model-assisted run.

    Respects a pre-existing ``CODEX_HOME`` when no override is supplied. Never
    reads anything inside the directory — the value is only exported to child
    processes.
    """
    env = dict(os.environ if base_env is None else base_env)
    if codex_home:
        env["CODEX_HOME"] = codex_home
    return env


def parse_codex_login_status(exit_code: int, stdout: str, stderr: str) -> bool:
    """Login is proven only by exit 0 plus the phrase on stdout OR stderr."""
    if exit_code != 0:
        return False
    return CODEX_LOGIN_PHRASE in (stdout or "") or CODEX_LOGIN_PHRASE in (stderr or "")


def targeted_tests_ok(exit_code: int | None, output: str | None) -> bool:
    """Exit-code-first pytest verdict with reliable completion evidence.

    Quiet ``-q`` runs whose output shows dot progress or ``[100%]`` count as
    completed even without the literal word ``passed``; a nonzero exit code or
    failure/no-tests summary always fails.
    """
    if exit_code != 0:
        return False
    text = _ANSI_RE.sub("", (output or "").replace("\r\n", "\n").replace("\r", "\n"))
    if _PYTEST_FAILURE_RE.search(text):
        return False
    return bool(_PYTEST_COMPLETION_RE.search(text))


def _int_value(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _entry_names(entries: Any) -> tuple[str, ...]:
    if not isinstance(entries, list):
        return ()
    names: list[str] = []
    for entry in entries:
        if isinstance(entry, Mapping) and entry.get("name"):
            names.append(str(entry["name"]))
    return tuple(names)


def extract_grounding_facts(packet: Mapping[str, Any] | None) -> GroundingFacts:
    """Extract comparable process/service facts from the run's evidence packet."""
    if not packet:
        return GroundingFacts()
    processes = packet.get("processes") or {}
    services = packet.get("services") or {}
    if not isinstance(processes, Mapping):
        processes = {}
    if not isinstance(services, Mapping):
        services = {}
    return GroundingFacts(
        process_available=bool(processes.get("available")),
        service_available=bool(services.get("available")),
        process_total=_int_value(processes.get("total_count")),
        process_returned=_int_value(processes.get("returned_count")),
        process_names=_entry_names(processes.get("entries")),
        process_collection=str(processes.get("collection") or "") or None,
        process_limitation=(
            str(processes.get("limitation") or "")
            or ("Process detail is not present in this evidence packet" if processes else "")
            or None
        ),
        service_total=_int_value(services.get("total_count")),
        service_running=_int_value(services.get("running_count")),
        service_stopped=_int_value(services.get("stopped_count")),
        service_returned=_int_value(services.get("returned_count")),
        service_names=_entry_names(services.get("entries")),
        service_collection=str(services.get("collection") or "") or None,
        service_limitation=(
            str(services.get("limitation") or "")
            or ("Service detail is not present in this evidence packet" if services else "")
            or None
        ),
    )


def _normalized_text(answer: str) -> str:
    return re.sub(r"\s+", " ", (answer or "").lower().replace(",", ""))


def _number_near_term(text: str, number: int, terms: tuple[str, ...]) -> bool:
    n = str(number)
    term_alt = "|".join(re.escape(term) for term in terms)
    return bool(
        re.search(rf"\b{re.escape(n)}\b\D{{0,36}}\b({term_alt})\b", text)
        or re.search(rf"\b({term_alt})\b\D{{0,36}}\b{re.escape(n)}\b", text)
    )


def _name_mentioned(text: str, name: str) -> bool:
    low = name.lower()
    if not low:
        return False
    if re.search(r"[\W_]", low):
        return low in text
    return bool(re.search(rf"(?<![a-z0-9]){re.escape(low)}(?![a-z0-9])", text))


def _gap_acknowledged(text: str, category: str) -> bool:
    command = (
        "sfai.cmd windows processes --json --limit 10"
        if category == "process"
        else "sfai.cmd windows services --json"
    )
    status_command = "sfai.cmd windows status --json"
    if command not in text and status_command not in text:
        return False
    if category not in text and f"{category}es" not in text and f"{category}s" not in text:
        return False
    return any(marker in text for marker in _MISSING_EVIDENCE_MARKERS)


def _detect_process_grounding(text: str, facts: GroundingFacts) -> tuple[bool, list[str]]:
    matches: list[str] = []
    if facts.process_available:
        if facts.process_total is not None and _number_near_term(
            text, facts.process_total, ("process", "processes", "process total", "total processes")
        ):
            matches.append(f"process_total={facts.process_total}")
        if facts.process_returned is not None and (
            _number_near_term(
                text, facts.process_returned, ("returned", "preview", "bounded", "included")
            )
            or re.search(
                rf"showing\s+{facts.process_returned}\s+of\s+{facts.process_total}\s+process",
                text,
            )
        ):
            matches.append(f"process_returned={facts.process_returned}")
        for name in facts.process_names:
            if _name_mentioned(text, name):
                matches.append(f"process_name={name}")
        if "bounded" in text and "process" in text and facts.process_returned is not None:
            matches.append("process_bounded_visibility")
        if facts.process_collection and facts.process_collection.replace("_", "-") in text:
            matches.append(f"process_collection={facts.process_collection}")
        return bool(matches), matches
    if facts.process_limitation and _gap_acknowledged(text, "process"):
        return True, ["process_limitation_acknowledged"]
    return False, matches


def _detect_service_grounding(text: str, facts: GroundingFacts) -> tuple[bool, list[str]]:
    matches: list[str] = []
    if facts.service_available:
        if facts.service_total is not None and _number_near_term(
            text, facts.service_total, ("service", "services", "service total", "total services")
        ):
            matches.append(f"service_total={facts.service_total}")
        if facts.service_running is not None and _number_near_term(
            text, facts.service_running, ("running", "running services", "services running")
        ):
            matches.append(f"service_running={facts.service_running}")
        if facts.service_stopped is not None and _number_near_term(
            text, facts.service_stopped, ("stopped", "stopped services", "services stopped")
        ):
            matches.append(f"service_stopped={facts.service_stopped}")
        if facts.service_returned is not None and _number_near_term(
            text, facts.service_returned, ("returned", "preview", "bounded", "included")
        ):
            matches.append(f"service_returned={facts.service_returned}")
        for name in facts.service_names:
            if _name_mentioned(text, name):
                matches.append(f"service_name={name}")
        if facts.service_collection and facts.service_collection.replace("_", "-") in text:
            matches.append(f"service_collection={facts.service_collection}")
        return bool(matches), matches
    if facts.service_limitation and _gap_acknowledged(text, "service"):
        return True, ["service_limitation_acknowledged"]
    return False, matches


def evaluate_answer_grounding(answer: str, packet: Mapping[str, Any] | None) -> GroundingResult:
    facts = extract_grounding_facts(packet)
    text = _normalized_text(answer)
    process_ok, process_matches = _detect_process_grounding(text, facts)
    service_ok, service_matches = _detect_service_grounding(text, facts)
    missing: list[str] = []
    if (facts.process_available or facts.process_limitation) and not process_ok:
        missing.append("process")
    if (facts.service_available or facts.service_limitation) and not service_ok:
        missing.append("service")
    passed = not missing and (process_ok or service_ok)
    reason = (
        "grounded in available process and service evidence"
        if passed and facts.process_available and facts.service_available
        else "grounded in available evidence with explicit gap acknowledgement"
        if passed
        else "missing required grounding: " + ", ".join(missing)
        if missing
        else "no process/service evidence or explicit gap facts were available to validate"
    )
    return GroundingResult(
        process_evidence_available=facts.process_available,
        service_evidence_available=facts.service_available,
        process_grounding_detected=process_ok,
        service_grounding_detected=service_ok,
        matched_process_facts=process_matches,
        matched_service_facts=service_matches,
        missing_required_grounding=missing,
        answer_uses_process_or_service_evidence=passed,
        grounding_reason=reason,
    )


def answer_references_process_service_evidence(
    answer: str, packet: Mapping[str, Any] | None = None
) -> bool:
    if packet is not None:
        return evaluate_answer_grounding(answer, packet).answer_uses_process_or_service_evidence
    return bool(
        re.search(r"\b\d+\s+(visible\s+|running\s+)?(process(es)?|services?)\b", answer or "", re.I)
    )


def answer_acknowledges_missing_evidence(answer: str) -> bool:
    """Backward-compatible thin-evidence check: both categories and commands."""
    low = _normalized_text(answer)
    return _gap_acknowledged(low, "process") and _gap_acknowledged(low, "service")


def answer_uses_process_or_service_evidence(
    answer: str, packet: Mapping[str, Any] | None = None
) -> bool:
    """Strict grounding verdict; generic process/service mentions never pass."""
    if packet is not None:
        return evaluate_answer_grounding(answer, packet).answer_uses_process_or_service_evidence
    return answer_references_process_service_evidence(
        answer
    ) or answer_acknowledges_missing_evidence(answer)


def bad_preamble_detected(answer: str) -> bool:
    text = answer or ""
    return (
        contains_project_policy_preamble(text)
        or is_metadata_primary_answer(text)
        or is_container_primary_framing(text)
    )


def fallback_used(answer: str) -> bool:
    low = (answer or "").lower()
    return any(marker in low for marker in FALLBACK_MARKERS)


def _sanitize_failure_excerpt(line: str) -> str:
    """Bounded, control-character-free excerpt; token-like lines are redacted."""
    lowered = line.lower()
    if any(
        key in lowered
        for key in ("token", "secret", "password", "api_key", "authorization", "bearer")
    ):
        return "[REDACTED]"
    cleaned = "".join(ch if ch.isprintable() else " " for ch in line)
    return cleaned.strip()[:FAILURE_EXCERPT_MAX_CHARS]


def extract_model_failure_diagnostics(
    answer: str | None, ask_exit_code: int | None = None
) -> dict[str, Any]:
    """PR291 — bounded, sanitized Codex failure diagnostics from the transcript.

    Classifies the known failure modes precisely (``cli_argument_order``,
    ``repository_trust``, ``timeout``, ``model``) so a HOLD explains WHY the
    model-assisted answer did not run. Only the answer transcript is
    inspected: no auth-cache read, no environment capture, no token output.
    """
    text = answer or ""
    low = re.sub(r"\s+", " ", text.lower())
    error_class: str | None = None
    match = re.search(r"model failure class:\s*([a-z_]+)", low)
    if match and match.group(1) != "unknown":
        error_class = match.group(1)
    elif "unexpected argument" in low:
        error_class = "cli_argument_order"
    elif "repository trust check blocked" in low or "not inside a trusted directory" in low:
        error_class = "repository_trust"
    elif "timed out" in low:
        error_class = "timeout"
    elif fallback_used(text):
        error_class = "model"
    excerpt = ""
    for line in text.splitlines():
        lowered = line.lower()
        if "model failure class:" in lowered or any(
            marker in lowered
            for marker in FALLBACK_MARKERS
            if marker != "## windows evidence summary"
        ):
            excerpt = _sanitize_failure_excerpt(line)
            break
    return {
        "codex_exec_attempted": bool(text),
        "codex_exec_exit_code": ask_exit_code,
        "codex_exec_timed_out": error_class == "timeout",
        "codex_exec_error_class": error_class,
        "codex_exec_stderr_excerpt": excerpt,
    }


def evidence_context_contains_process_service(packet: Mapping[str, Any] | None) -> bool:
    if not packet:
        return False
    processes = packet.get("processes") or {}
    services = packet.get("services") or {}
    return bool(processes.get("available")) or bool(services.get("available"))


def build_summary(
    *,
    codex_login_checked: bool,
    codex_logged_in: bool,
    codex_home_configured: bool,
    same_process_context: bool,
    packet: Mapping[str, Any] | None,
    answer: str | None,
    model_assisted_answer_ran: bool,
    targeted_tests_exit_code: int | None,
    targeted_tests_output: str | None,
    ask_exit_code: int | None = None,
    targeted_selection: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the acceptance summary with real, unloosened semantics."""
    answer_text = answer or ""
    tests_ok = targeted_tests_ok(targeted_tests_exit_code, targeted_tests_output)
    grounding = evaluate_answer_grounding(answer_text, packet)
    grounded = bool(answer_text) and grounding.answer_uses_process_or_service_evidence
    preamble = bool(answer_text) and bad_preamble_detected(answer_text)
    fell_back = bool(answer_text) and fallback_used(answer_text)
    failure_diagnostics = extract_model_failure_diagnostics(answer_text, ask_exit_code)
    # PR291 fix — deterministic response capture: command start / process
    # exit 0 alone is never proof of a model response. The captured answer
    # must be non-empty and must not be the deterministic fallback.
    model_response_nonempty = bool(answer_text.strip())
    model_response_captured = model_response_nonempty and not fell_back
    # A fallback/model-unavailable or empty answer means the model-assisted
    # answer did NOT run, regardless of how the child process exited.
    model_assisted_answer_ran = model_assisted_answer_ran and model_response_captured
    summary: dict[str, Any] = {
        "codex_login_checked": codex_login_checked,
        "codex_logged_in": codex_logged_in,
        "codex_home_configured": codex_home_configured,
        "same_process_context": same_process_context,
        "evidence_collected": bool(packet),
        "evidence_context_contains_process_service": evidence_context_contains_process_service(
            packet
        ),
        "model_assisted_answer_ran": model_assisted_answer_ran,
        "model_response_nonempty": model_response_nonempty,
        "model_response_captured": model_response_captured,
        **grounding.as_dict(),
        "answer_uses_process_or_service_evidence": grounded,
        "bad_preamble_detected": preamble,
        "fallback_used": fell_back,
        # PR291 — bounded, sanitized failure diagnostics so a HOLD explains
        # whether a CLI argument-ordering failure, repository trust, a
        # timeout, or a model command failure blocked the model-assisted
        # answer. Diagnostics never loosen PASS.
        **failure_diagnostics,
        "targeted_tests_ok": tests_ok,
        "read_only": True,
        "mutation_performed": False,
    }
    # PR291 fix — deterministic test-selection reporting: surface the resolved
    # explicit file list (or the precise selection error). A saved output that
    # shows pytest's exit-4 signature for a literal unexpanded wildcard is
    # classified as a selection error so the lane sees WHY the targeted run
    # never executed (targeted_tests_ok stays honest either way).
    if targeted_selection is None and _looks_like_unexpanded_wildcard_failure(
        targeted_tests_output
    ):
        targeted_selection = {
            "targeted_test_selection_error": (
                "literal wildcard passed unexpanded to pytest (no shell glob "
                "expansion); resolve explicit files with "
                "resolve_targeted_test_files/--run-targeted-tests instead"
            )
        }
    if targeted_selection is not None:
        for key in (
            "targeted_test_files_resolved",
            "targeted_test_file_count",
            "targeted_pytest_exit_code",
            "targeted_test_selection_error",
        ):
            if key in targeted_selection:
                summary[key] = targeted_selection[key]
    required = (
        summary["codex_login_checked"]
        and summary["codex_logged_in"]
        and summary["codex_home_configured"]
        and summary["same_process_context"]
        and summary["evidence_collected"]
        and summary["evidence_context_contains_process_service"]
        and summary["model_assisted_answer_ran"]
        and summary["model_response_captured"]
        and summary["answer_uses_process_or_service_evidence"]
        and summary["targeted_tests_ok"]
        and not summary["bad_preamble_detected"]
        and not summary["fallback_used"]
    )
    summary["validation_status"] = "PASS" if required else "HOLD"
    return summary


def _default_runner(argv: list[str], env: dict[str, str]) -> CommandResult:
    """Opt-in live runner: fixed argv, no shell, bounded timeout."""
    import subprocess  # noqa: PLC0415 — live mode only; never used in saved mode

    proc = subprocess.run(  # noqa: S603 — fixed argv list, shell never used
        argv,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        stdin=subprocess.DEVNULL,
    )
    return CommandResult(exit_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


def resolve_targeted_test_files(tests_dir: Path | None = None) -> list[str]:
    """Deterministic, shell-free resolution of the targeted Windows test set.

    Expands ``test_pr291_*.py`` with :meth:`pathlib.Path.glob` and adds the
    explicit provider-compatibility file, returning a sorted list of explicit
    file paths so no wildcard ever reaches pytest through a no-shell process
    launcher.
    """
    base = tests_dir if tests_dir is not None else REPO_ROOT / "tests"
    resolved: set[Path] = set()
    for pattern in TARGETED_TEST_GLOBS:
        resolved.update(path for path in base.glob(pattern) if path.is_file())
    for name in TARGETED_TEST_EXPLICIT_FILES:
        candidate = base / name
        if candidate.is_file():
            resolved.add(candidate)
    return sorted(str(path) for path in resolved)


def _bounded_test_output_excerpt(output: str) -> str:
    """Bounded, ANSI/control-sanitized tail of the targeted pytest output."""
    plain = _ANSI_RE.sub("", output or "")
    cleaned = "".join(ch if ch == "\n" or ch.isprintable() else " " for ch in plain)
    return cleaned[-TARGETED_TEST_OUTPUT_EXCERPT_MAX_CHARS:]


def run_targeted_tests(
    tests_dir: Path | None = None,
    *,
    runner: Runner | None = None,
    base_env: Mapping[str, str] | None = None,
    python_executable: str | None = None,
) -> dict[str, Any]:
    """Run the resolved targeted set with explicit file paths (no shell).

    An empty resolution is a clear selection error: pytest is never launched
    and ``targeted_tests_ok`` is never reported true. ``targeted_tests_ok``
    stays exit-code-first with completion evidence, so it can never be false
    merely because a literal wildcard was passed unexpanded — wildcards are
    expanded here, in Python, before pytest starts.
    """
    files = resolve_targeted_test_files(tests_dir)
    result: dict[str, Any] = {
        "targeted_test_files_resolved": files,
        "targeted_test_file_count": len(files),
        "targeted_pytest_exit_code": None,
        "targeted_tests_ok": False,
        "targeted_test_selection_error": None,
        "targeted_pytest_output_excerpt": "",
    }
    if not files:
        result["targeted_test_selection_error"] = (
            "no targeted test files resolved (expected test_pr291_*.py and "
            "test_codex_provider.py under the tests directory)"
        )
        return result
    runner = runner or _default_runner
    env = dict(os.environ if base_env is None else base_env)
    argv = [python_executable or sys.executable, "-m", "pytest", "-q", *files]
    run = runner(argv, env)
    output = f"{run.stdout}\n{run.stderr}"
    result["targeted_pytest_exit_code"] = run.exit_code
    result["targeted_tests_ok"] = targeted_tests_ok(run.exit_code, output)
    result["targeted_pytest_output_excerpt"] = _bounded_test_output_excerpt(output)
    return result


def _looks_like_unexpanded_wildcard_failure(output: str | None) -> bool:
    """Detect pytest's exit-4 signature for a literal unexpanded wildcard."""
    if not output:
        return False
    low = output.lower()
    return "file or directory not found" in low and "*" in output


def run_authenticated_acceptance(
    *,
    codex_binary: str,
    sfai_binary: str,
    prompt: str = DEFAULT_PROMPT,
    codex_home: str | None = None,
    login_runner: Runner | None = None,
    ask_runner: Runner | None = None,
    packet_builder: Callable[[], dict[str, Any]] = build_windows_evidence_context,
    targeted_tests_exit_code: int | None = None,
    targeted_tests_output: str | None = None,
    base_env: Mapping[str, str] | None = None,
    targeted_selection: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Live orchestration: login proof FIRST, then the model-assisted answer.

    Both child commands receive the SAME environment mapping (including any
    tester-scoped ``CODEX_HOME``), so login status is proven in the process
    context actually used for the model-assisted run. When login is not
    proven, the model-assisted step never runs and the summary is HOLD.
    """
    login_runner = login_runner or _default_runner
    ask_runner = ask_runner or _default_runner
    env = build_process_env(codex_home, base_env=base_env)
    login = login_runner([codex_binary, "login", "status"], env)
    logged_in = parse_codex_login_status(login.exit_code, login.stdout, login.stderr)
    packet: dict[str, Any] | None = None
    answer: str | None = None
    ran = False
    ask_exit_code: int | None = None
    if logged_in:
        packet = packet_builder()
        ask = ask_runner([sfai_binary, "ask", prompt], env)
        answer = ask.stdout
        ask_exit_code = ask.exit_code
        ran = ask.exit_code == 0
    return build_summary(
        codex_login_checked=True,
        codex_logged_in=logged_in,
        codex_home_configured="CODEX_HOME" in env,
        same_process_context=True,
        packet=packet,
        answer=answer,
        model_assisted_answer_ran=ran,
        targeted_tests_exit_code=targeted_tests_exit_code,
        targeted_tests_output=targeted_tests_output,
        ask_exit_code=ask_exit_code,
        targeted_selection=targeted_selection,
    )


def _read_text(path: Path | None) -> str | None:
    if path is None:
        return None
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig", errors="replace")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Prove the authenticated Windows evidence-to-model path for PR289 "
            "(saved-artifact mode by default; --live is opt-in)."
        )
    )
    parser.add_argument(
        "--codex-home",
        default=None,
        help=(
            "Tester-scoped CODEX_HOME for the login check and model-assisted "
            "run (defaults to the pre-existing environment variable)."
        ),
    )
    parser.add_argument("--live", action="store_true", help="Run the opt-in live lane.")
    parser.add_argument("--codex-binary", default="codex", help="Codex CLI path (live mode).")
    parser.add_argument("--sfai-binary", default="sfai.cmd", help="sfai wrapper path (live mode).")
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--login-status-exit-code", type=int, default=None)
    parser.add_argument("--login-status-stdout", type=Path, default=None)
    parser.add_argument("--login-status-stderr", type=Path, default=None)
    parser.add_argument("--answer-transcript", type=Path, default=None)
    parser.add_argument(
        "--evidence-context-json",
        type=Path,
        default=None,
        help="Saved windows-evidence-context.json artifact from the product run.",
    )
    parser.add_argument("--targeted-tests-exit-code", type=int, default=None)
    parser.add_argument("--targeted-tests-output", type=Path, default=None)
    parser.add_argument(
        "--tests-dir",
        type=Path,
        default=None,
        help="Tests directory for deterministic targeted-test resolution.",
    )
    parser.add_argument(
        "--print-targeted-tests",
        action="store_true",
        help=(
            "Print the deterministically resolved targeted test files (one "
            "per line) and exit; exit 4 when none resolve. No shell glob "
            "expansion is ever required."
        ),
    )
    parser.add_argument(
        "--run-targeted-tests",
        action="store_true",
        help=(
            "Resolve the targeted test files in Python and run pytest with "
            "explicit file paths (argv list, no shell); overrides "
            "--targeted-tests-exit-code/--targeted-tests-output."
        ),
    )
    parser.add_argument("--json", action="store_true", dest="emit_json")
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-markdown", type=Path)
    args = parser.parse_args(argv)
    if args.print_targeted_tests:
        return args
    if not (args.emit_json or args.markdown or args.out_json or args.out_markdown):
        parser.error(
            "select at least one output mode: --json, --markdown, --out-json, or --out-markdown"
        )
    if not args.live and args.login_status_exit_code is None:
        parser.error("saved mode requires --login-status-exit-code (or use --live)")
    if not args.live and args.answer_transcript is None:
        parser.error("saved mode requires --answer-transcript (or use --live)")
    return args


def build_result(args: argparse.Namespace) -> dict[str, Any]:
    targeted_output = _read_text(args.targeted_tests_output)
    targeted_exit_code = args.targeted_tests_exit_code
    targeted_selection: dict[str, Any] | None = None
    if getattr(args, "run_targeted_tests", False):
        # PR291 fix — deterministic selection + explicit file paths; the
        # resolved list and any selection error are reported in the summary.
        targeted_selection = run_targeted_tests(args.tests_dir)
        targeted_exit_code = targeted_selection["targeted_pytest_exit_code"]
        targeted_output = targeted_selection["targeted_pytest_output_excerpt"]
    if args.live:
        summary = run_authenticated_acceptance(
            codex_binary=args.codex_binary,
            sfai_binary=args.sfai_binary,
            prompt=args.prompt,
            codex_home=args.codex_home,
            targeted_tests_exit_code=targeted_exit_code,
            targeted_tests_output=targeted_output,
            targeted_selection=targeted_selection,
        )
    else:
        login_stdout = _read_text(args.login_status_stdout) or ""
        login_stderr = _read_text(args.login_status_stderr) or ""
        logged_in = parse_codex_login_status(
            args.login_status_exit_code, login_stdout, login_stderr
        )
        answer = _read_text(args.answer_transcript)
        packet: dict[str, Any] | None = None
        if args.evidence_context_json is not None:
            loaded = json.loads(args.evidence_context_json.read_text(encoding="utf-8-sig"))
            packet = loaded if isinstance(loaded, dict) else None
        env = build_process_env(args.codex_home)
        summary = build_summary(
            codex_login_checked=True,
            codex_logged_in=logged_in,
            codex_home_configured="CODEX_HOME" in env,
            # Saved mode trusts the lane to have used one process context; the
            # live lane proves it directly.
            same_process_context=True,
            packet=packet,
            answer=answer,
            model_assisted_answer_ran=bool(answer) and logged_in,
            targeted_tests_exit_code=targeted_exit_code,
            targeted_tests_output=targeted_output,
            targeted_selection=targeted_selection,
        )
    return {
        "schema_version": 1,
        "mode": "windows_authenticated_model_acceptance",
        "prompt": args.prompt,
        "summary": summary,
        "safety": {
            "read_only": True,
            "mutation_performed": False,
            "auth_cache_read": False,
            "token_contents_displayed": False,
            "shell_used": False,
            "remote_execution": False,
        },
    }


def render_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# Windows authenticated evidence-to-model acceptance",
        "",
        f"Prompt: {result['prompt']}",
        f"Validation status: {summary['validation_status']}",
        "",
        "| field | value |",
        "| --- | --- |",
    ]
    lines.extend(
        f"| {key} | {str(value).lower() if isinstance(value, bool) else value} |"
        for key, value in summary.items()
    )
    lines.append("")
    lines.append(
        "Safety: read-only validation only; no auth-cache/token contents were "
        "read or displayed; no shell, remoting, or mutation was used."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.print_targeted_tests:
        files = resolve_targeted_test_files(args.tests_dir)
        for path in files:
            print(path)
        if not files:
            print(
                "targeted_test_selection_error: no targeted test files resolved",
                file=sys.stderr,
            )
            return 4
        return 0
    result = build_result(args)
    payload = json.dumps(result, indent=2, sort_keys=True)
    if args.emit_json:
        print(payload)
    if args.markdown:
        print(render_markdown(result))
    if args.out_json:
        args.out_json.write_text(payload + "\n", encoding="utf-8")
    if args.out_markdown:
        args.out_markdown.write_text(render_markdown(result) + "\n", encoding="utf-8")
    return 0 if result["summary"]["validation_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
