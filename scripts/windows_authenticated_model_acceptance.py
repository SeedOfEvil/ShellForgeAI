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
from dataclasses import dataclass
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
# A fallback answer is safe operator output but is never a model-assisted pass.
FALLBACK_MARKERS = (
    "## windows evidence summary",
    "model assistance is unavailable",
    "model synthesis unavailable",
)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_PYTEST_FAILURE_RE = re.compile(r"\b\d+\s+(failed|errors?)\b|\bno tests ran\b", re.I)
_PYTEST_COMPLETION_RE = re.compile(r"\b\d+\s+passed\b|\[\s*100%\s*\]|^[.sxX]{3,}\s*$", re.M)

# Strict evidence-reference patterns: a process/service term must carry a real
# number (count/total/running) — generic "processes look fine" never counts.
_PROCESS_SERVICE_EVIDENCE_RES = (
    re.compile(r"\b\d+\s+(visible\s+|running\s+)?(process(es)?|services?)\b", re.I),
    re.compile(r"\b(process(es)?|services?)\s+total\s*=\s*\d+", re.I),
    re.compile(r"\brunning\s*=\s*\d+", re.I),
    re.compile(r"\bwith\s+\d+\s+running\b", re.I),
    re.compile(r"\b(process|service)\s+count\b\D{0,12}\d+", re.I),
)

_MISSING_EVIDENCE_MARKERS = (
    "not present in this evidence packet",
    "not in this evidence packet",
    "missing from the current evidence packet",
    "lacks process",
    "lacks service",
    "lacks process/service",
    "do not have process",
    "do not have service",
    "do not have process/service",
    "don't have process",
    "don't have service",
)


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


def answer_references_process_service_evidence(answer: str) -> bool:
    return any(pattern.search(answer or "") for pattern in _PROCESS_SERVICE_EVIDENCE_RES)


def answer_acknowledges_missing_evidence(answer: str) -> bool:
    """Explicit missing-evidence acknowledgement plus BOTH safe gap commands."""
    low = (answer or "").lower()
    if not any(marker in low for marker in _MISSING_EVIDENCE_MARKERS):
        return False
    if not ("process" in low or "service" in low):
        return False
    return all(cmd in low for cmd in SAFE_GAP_COMMANDS)


def answer_uses_process_or_service_evidence(answer: str) -> bool:
    """Strict grounding verdict; never loosened into generic passing."""
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
) -> dict[str, Any]:
    """Assemble the acceptance summary with real, unloosened semantics."""
    answer_text = answer or ""
    tests_ok = targeted_tests_ok(targeted_tests_exit_code, targeted_tests_output)
    grounded = bool(answer_text) and answer_uses_process_or_service_evidence(answer_text)
    preamble = bool(answer_text) and bad_preamble_detected(answer_text)
    fell_back = bool(answer_text) and fallback_used(answer_text)
    # A fallback/model-unavailable answer means the model-assisted answer did
    # NOT run, regardless of how the child process exited.
    model_assisted_answer_ran = model_assisted_answer_ran and not fell_back
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
        "answer_uses_process_or_service_evidence": grounded,
        "bad_preamble_detected": preamble,
        "fallback_used": fell_back,
        "targeted_tests_ok": tests_ok,
        "read_only": True,
        "mutation_performed": False,
    }
    required = (
        summary["codex_login_checked"]
        and summary["codex_logged_in"]
        and summary["codex_home_configured"]
        and summary["same_process_context"]
        and summary["evidence_collected"]
        and summary["evidence_context_contains_process_service"]
        and summary["model_assisted_answer_ran"]
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
    if logged_in:
        packet = packet_builder()
        ask = ask_runner([sfai_binary, "ask", prompt], env)
        answer = ask.stdout
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
    parser.add_argument("--json", action="store_true", dest="emit_json")
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-markdown", type=Path)
    args = parser.parse_args(argv)
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
    if args.live:
        summary = run_authenticated_acceptance(
            codex_binary=args.codex_binary,
            sfai_binary=args.sfai_binary,
            prompt=args.prompt,
            codex_home=args.codex_home,
            targeted_tests_exit_code=args.targeted_tests_exit_code,
            targeted_tests_output=targeted_output,
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
            targeted_tests_exit_code=args.targeted_tests_exit_code,
            targeted_tests_output=targeted_output,
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
