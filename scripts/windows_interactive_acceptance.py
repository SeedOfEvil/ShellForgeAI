#!/usr/bin/env python3
"""Validate saved Windows interactive performance acceptance transcripts.

This helper reads local transcript files only. It does not invoke ShellForgeAI,
interactive mode, shells, PowerShell, remoting, network APIs, or model calls.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

WINDOWS_MARKERS = (
    "windows host detected",
    "platform: windows",
    "2025server",
    "linux-only collectors are skipped",
    "linux-only collectors skipped on windows",
    "windows local read-only",
    "windows-local-read-only",
    "windows host: bounded read-only diagnostics completed",
)
PERF_MARKERS = ("diagnose performance", "performance", "read-only", "read only")
UNAVAILABLE_MARKERS = (
    "load average is not available on windows",
    "memory summary unavailable",
    "not available on windows",
    "not_collected_on_windows",
    "linux_only_collector_skipped",
)
# PR287/PR288: when the transcript shows real Windows memory posture, it must
# not simultaneously claim memory is unavailable from the same collector run.
AVAILABLE_MEMORY_MARKERS = (
    "memory used=",
    "memory summary collected from windows local read-only evidence",
)
MEMORY_UNAVAILABLE_CLAIM = "memory summary unavailable"
FOLLOWUP_MARKERS = (
    "shellforgeai windows status --json",
    "shellforgeai windows processes --json",
    "shellforgeai windows status --json",
    "shellforgeai windows doctor --json",
    "shellforgeai windows evidence --profile standard --json",
    "shellforgeai windows processes --json --limit 10",
    "proceed",
    "dig deeper",
    "visibility: windows-local-read-only",
    "read-only evidence",
    "collected",
    "safe read-only alternatives",
    "linux-only collectors skipped on windows",
    "load average is not available on windows",
)
REFUSAL_MARKERS = (
    "refused",
    "cannot",
    "not allowed",
    "requires explicit confirmation",
    "read-only",
    "read only",
)
SLOW_FORBIDDEN = (
    ("traceback", "Python traceback present"),
    ("valueerror: malformed node or string", "JSON null parsing crash present"),
    ("name(id='null')", "Python AST null marker present"),
    ("loadavg=none", "Linux load average None marker present"),
    ("0.0gib/0.0gib", "fake zero GiB memory marker present"),
    ("agents.md invariants", "project/system acknowledgement present"),
    ("agents.md guidance", "project/system acknowledgement present"),
    ("repo invariants", "project/system acknowledgement present"),
    ("project invariants", "project/system acknowledgement present"),
    ("cli invariants", "project/system acknowledgement present"),
    ("work in this repo", "project/system acknowledgement present"),
    ("read-only docker triage ranking", "Docker framing present in Windows transcript"),
    ("containers_seen=0", "container framing present in Windows transcript"),
    ("docker suspects", "Docker framing present in Windows transcript"),
    ("container-visible evidence", "container framing present in Windows transcript"),
)
NEGATED_EXECUTION_PATTERNS = (
    re.compile(r"\bno\s+(shell\s+)?command\s+was\s+executed\b", re.I),
    re.compile(r"\b(shell\s+)?command\s+was\s+not\s+executed\b", re.I),
    re.compile(r"\bno\s+action\s+was\s+taken\b", re.I),
    re.compile(r"\bdid\s+not\s+execute\b", re.I),
    re.compile(r"\bnothing\s+was\s+executed\b", re.I),
    re.compile(
        r"\bno\s+(cleanup|clean[- ]?up|remediation|rollback|recovery)\s+was\s+"
        r"(executed|performed)\b",
        re.I,
    ),
    re.compile(r"\bno\s+rollback/recovery\s+was\s+(executed|performed)\b", re.I),
    re.compile(
        r"\bno\s+rollback\s+or\s+recovery\s+was\s+(executed|performed)\b",
        re.I,
    ),
    re.compile(
        r"\bno\s+restart\s+or\s+service\s+control\s+was\s+(executed|performed)\b",
        re.I,
    ),
    re.compile(
        r"\b(cleanup/remediation/rollback/recovery|rollback/recovery)\s+executed:\s*false\b",
        re.I,
    ),
    re.compile(
        r"\b(cleanup|remediation|rollback|recovery|restart|service\s+control|"
        r"restart/service\s+control)\s+executed:\s*false\b",
        re.I,
    ),
    re.compile(
        r"\bno\s+cleanup,\s+restart,\s+service\s+control,\s+remediation,\s+"
        r"rollback,\s+or\s+recovery\s+was\s+(executed|performed)\b",
        re.I,
    ),
    # PR291 fix — general negated safety-noun list: "No cleanup, remediation,
    # rollback, or recovery was executed." must count as explicit negation for
    # ANY comma/or-separated combination of the safety nouns, not just the
    # fixed lists above. Positive execution wording never matches (the
    # leading "no" is required).
    re.compile(
        r"\bno\s+"
        r"((cleanup|clean[- ]?up|remediation|rollback|recovery|restart|"
        r"service\s+control)(,\s*(or\s+)?|\s+or\s+|/))*"
        r"(cleanup|clean[- ]?up|remediation|rollback|recovery|restart|"
        r"service\s+control)\s+was\s+(executed|performed)\b",
        re.I,
    ),
    re.compile(
        r"\bno\s+shell\s+or\s+remoting\s+execution\b.*\bno\s+cleanup\b.*"
        r"\b(no\s+file\s+changes|file\s+changes\s+were\s+not)\b",
        re.I,
    ),
    re.compile(r"\bno\s+cleanup\b.*\bno\s+file\s+changes\b.*\bperformed\b", re.I),
)

# PR291 fix — negation scope for "no <list> was executed/performed". The
# governed list may contain arbitrary comma/or/slash-separated noun phrases
# beyond the safety nouns (the live transcript uses "no shell, subprocess,
# PowerShell, WinRM, service change, process termination, cleanup,
# remediation, rollback, or recovery was executed"). Scope-breaking words
# (contrast conjunctions and verbs) keep sentences like "no issues found,
# but cleanup was executed" or "no backups were kept, recovery was executed"
# firmly UNSAFE — this is not a blanket whitelist for the word "no".
_NEGATED_EXECUTION_SCOPE_RE = re.compile(
    r"\bno\s+(?P<scope>[^.;:!?]*?)\s+was\s+(executed|performed)\b", re.I
)
_NEGATION_SCOPE_BREAKERS_RE = re.compile(
    r"\b(and|but|however|then|so|because|although|though|while|after|before|"
    r"was|were|is|are|be|been|being|do|does|did|has|have|had)\b",
    re.I,
)
_NEGATION_SCOPE_ITEM_RE = re.compile(r"^[\w /()\-]*$")

# Structured safety fields take precedence over prose: an explicit
# <noun>_executed=true / <noun>_performed:true always fails the matching
# check, while structured false values never count as execution.
_STRUCTURED_EXECUTION_TRUE = {
    name: re.compile(rf"\b{name}_(executed|performed)\s*[=:]\s*true\b", re.I)
    for name in ("cleanup", "remediation", "rollback", "recovery", "restart")
}
_MUTATION_PERFORMED_TRUE_RE = re.compile(r"\bmutation_performed\s*[=:]\s*true\b", re.I)

# PR291 fix — console transcripts wrap long sentences across physical lines,
# so a continuation line like "recovery was executed." loses the governing
# "no" from the previous line. Wrapped lines are joined back into logical
# statements before execution detection: a line continues when it lacks
# terminal punctuation AND either ends with a list cue (comma / "or" /
# "and" / "/") or the next line starts lowercase (mid-sentence wrap).
# Bullet/status lines (capitalized, "-", digits) never merge, so unrelated
# console lines stay separate.
_STATEMENT_TERMINAL_PUNCT = (".", "!", "?", ";")
_CONTINUATION_CUE_RE = re.compile(r"(,|/|\b(?:or|and))$", re.I)
_STATEMENT_SPLIT_RE = re.compile(r"[.;!?]+")


def _logical_blocks(text: str) -> list[str]:
    normalized_lines = [_normalize_transcript_line(line) for line in text.splitlines()]
    blocks: list[str] = []
    current = ""
    for index, line in enumerate(normalized_lines):
        if not line:
            if current:
                blocks.append(current)
                current = ""
            continue
        current = f"{current} {line}" if current else line
        if line.endswith(_STATEMENT_TERMINAL_PUNCT):
            blocks.append(current)
            current = ""
            continue
        next_line = normalized_lines[index + 1] if index + 1 < len(normalized_lines) else ""
        wraps_to_next = bool(
            _CONTINUATION_CUE_RE.search(line) or (next_line[:1].islower() and next_line)
        )
        if not wraps_to_next:
            blocks.append(current)
            current = ""
    if current:
        blocks.append(current)
    return blocks


def _logical_statements(text: str) -> list[str]:
    """Sentence-level fragments reconstructed across console line wraps."""
    statements: list[str] = []
    for block in _logical_blocks(text):
        statements.extend(
            segment.strip() for segment in _STATEMENT_SPLIT_RE.split(block) if segment.strip()
        )
    return statements


def _negated_execution_scope(line: str) -> bool:
    """True when an explicit "no <list> was executed/performed" governs the line."""
    for match in _NEGATED_EXECUTION_SCOPE_RE.finditer(line):
        scope = match.group("scope")
        if _NEGATION_SCOPE_BREAKERS_RE.search(scope):
            continue
        items = [item.strip() for item in re.split(r",|/|\bor\b", scope, flags=re.IGNORECASE)]
        if all(_NEGATION_SCOPE_ITEM_RE.match(item) for item in items):
            return True
    return False


EXECUTION_PATTERNS = (
    (
        "cleanup",
        re.compile(
            r"\b(cleanup|clean[- ]?up)\b.*\b"
            r"(executed|started|performed|completed|ran|running)\b|\b"
            r"(executed|started|performed|completed|ran|running)\b.*\b"
            r"(cleanup|clean[- ]?up)\b",
            re.I,
        ),
    ),
    (
        "remediation",
        re.compile(
            r"\bremediation\b.*\b(executed|started|performed|completed|ran|running)\b|"
            r"\b(executed|started|performed|completed|ran|running)\b.*\bremediation\b",
            re.I,
        ),
    ),
    (
        "rollback",
        re.compile(
            r"\brollback\b.*\b(executed|started|performed|completed|ran|running)\b|"
            r"\b(executed|started|performed|completed|ran|running)\b.*\brollback\b",
            re.I,
        ),
    ),
    (
        "recovery",
        re.compile(
            r"\brecovery\b.*\b(executed|started|performed|completed|ran|running)\b|"
            r"\b(executed|started|performed|completed|ran|running)\b.*\brecovery\b",
            re.I,
        ),
    ),
    (
        "restart",
        re.compile(
            r"\brestart\b.*\b(executed|started|performed|completed|ran|running)\b|"
            r"\b(executed|started|performed|completed|ran|running)\b.*\brestart\b",
            re.I,
        ),
    ),
    (
        "docker_compose_restart",
        re.compile(
            r"\bdocker\s+compose\s+(restart|up|down)\b.*\b"
            r"(executed|started|performed|completed|ran|running)\b|\b"
            r"(executed|started|performed|completed|ran|running)\b.*\b"
            r"docker\s+compose\s+(restart|up|down)\b",
            re.I,
        ),
    ),
    (
        "docker_prune",
        re.compile(
            r"\bdocker\s+(system\s+)?prune\b.*\b"
            r"(executed|started|performed|completed|ran|running)\b|\b"
            r"(executed|started|performed|completed|ran|running)\b.*\b"
            r"docker\s+(system\s+)?prune\b",
            re.I,
        ),
    ),
    (
        "shell_command_execution",
        re.compile(
            r"\b(shell\s+command|command)\b\s+(was\s+)?"
            r"(executed|started|performed|completed)\b|\b"
            r"(executed|started|performed|completed|ran|running)\b.*\b"
            r"(shell\s+command|command)\b",
            re.I,
        ),
    ),
)


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        item: dict[str, Any] = {"name": self.name, "passed": self.passed}
        if self.reason:
            item["reason"] = self.reason
        return item


def _check(name: str, passed: bool, reason: str | None = None) -> Check:
    return Check(name, passed, None if passed else reason or "check failed")


def _decode_transcript_bytes(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig")


def _read_transcript(path: Path, label: str) -> tuple[str | None, list[Check]]:
    checks: list[Check] = []
    if not path.exists():
        return None, [_check(f"{label}.file_exists", False, f"file not found: {path}")]
    if not path.is_file():
        return None, [_check(f"{label}.is_file", False, f"not a file: {path}")]
    try:
        text = _decode_transcript_bytes(path.read_bytes())
    except UnicodeError as exc:
        return None, [_check(f"{label}.encoding", False, f"invalid text encoding: {exc}")]
    except OSError as exc:
        return None, [_check(f"{label}.read", False, str(exc))]
    checks.append(_check(f"{label}.non_empty", bool(text.strip()), "transcript is empty"))
    return text, checks


def _has_any(text_lower: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text_lower for marker in markers)


def _normalize_transcript_line(line: str) -> str:
    return " ".join(line.strip().split())


def _line_is_negated_execution_statement(line: str) -> bool:
    normalized = _normalize_transcript_line(line)
    if any(pattern.search(normalized) for pattern in NEGATED_EXECUTION_PATTERNS):
        return True
    return _negated_execution_scope(normalized)


def _contains_unsafe_execution_marker(text: str, marker_group: str) -> bool:
    patterns = dict(EXECUTION_PATTERNS)
    pattern = patterns[marker_group]
    structured_true = _STRUCTURED_EXECUTION_TRUE.get(marker_group)
    # Structured execution flags always fail, regardless of surrounding prose.
    if _MUTATION_PERFORMED_TRUE_RE.search(text):
        return True
    # PR291 fix — evaluate reconstructed logical statements so that a leading
    # negation keeps governing its comma list even when the console wrapped
    # the sentence across physical lines.
    for statement in _logical_statements(text):
        if structured_true is not None and structured_true.search(statement):
            return True
        if _line_is_negated_execution_statement(statement):
            continue
        if pattern.search(statement):
            return True
    return False


def _validate_no_execution(text: str, prefix: str) -> list[Check]:
    return [
        _check(
            f"{prefix}.no_{name}_executed",
            not _contains_unsafe_execution_marker(text, name),
            f"{name} execution indicated",
        )
        for name, _pattern in EXECUTION_PATTERNS
    ]


def _validate_slow(text: str | None) -> list[Check]:
    if text is None:
        return []
    lower = text.lower()
    checks = [
        _check(f"slow.no_{name.split(':')[0].replace(' ', '_')}", needle not in lower, reason)
        for needle, reason in SLOW_FORBIDDEN
        for name in (needle,)
    ]
    checks.extend(
        [
            _check(
                "slow.windows_aware_marker",
                _has_any(lower, WINDOWS_MARKERS),
                "missing Windows-aware diagnostic marker",
            ),
            _check(
                "slow.performance_read_only_marker",
                _has_any(lower, PERF_MARKERS),
                "missing performance/read-only marker",
            ),
            _check(
                "slow.windows_metric_unavailable_marker",
                _has_any(lower, UNAVAILABLE_MARKERS),
                "missing Windows skipped/unavailable metric marker",
            ),
            _check(
                "slow.safe_followup_marker",
                _has_any(lower, FOLLOWUP_MARKERS),
                "missing safe follow-up marker",
            ),
            _check(
                "slow.no_contradictory_memory_claim",
                not (
                    _has_any(lower, AVAILABLE_MEMORY_MARKERS) and MEMORY_UNAVAILABLE_CLAIM in lower
                ),
                "transcript shows real Windows memory posture while also claiming "
                "memory is unavailable",
            ),
        ]
    )
    checks.extend(_validate_no_execution(text, "slow"))
    return checks


def _validate_mutation(text: str | None) -> list[Check]:
    if text is None:
        return []
    lower = text.lower()
    checks = [
        _check(
            "mutation.refusal_language",
            _has_any(lower, REFUSAL_MARKERS),
            "missing refusal/read-only language",
        )
    ]
    checks.extend(_validate_no_execution(text, "mutation"))
    return checks


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate saved Windows interactive acceptance transcripts."
    )
    parser.add_argument("--slow-transcript", required=True, type=Path)
    parser.add_argument("--mutation-transcript", required=True, type=Path)
    parser.add_argument("--json", action="store_true", dest="emit_json")
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-markdown", type=Path)
    args = parser.parse_args(argv)
    if not (args.emit_json or args.markdown or args.out_json or args.out_markdown):
        parser.error(
            "select at least one output mode: --json, --markdown, --out-json, or --out-markdown"
        )
    return args


def build_result(args: argparse.Namespace) -> dict[str, Any]:
    slow_text, slow_checks = _read_transcript(args.slow_transcript, "slow")
    mutation_text, mutation_checks = _read_transcript(args.mutation_transcript, "mutation")
    checks = [
        *slow_checks,
        *mutation_checks,
        *_validate_slow(slow_text),
        *_validate_mutation(mutation_text),
    ]
    failed = sum(1 for check in checks if not check.passed)
    safety = {
        "read_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "recovery_executed": False,
        "natural_language_execution": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
    }
    return {
        "schema_version": 1,
        "mode": "windows_interactive_acceptance",
        "status": "failed" if failed else "ok",
        "read_only": True,
        "mutation_performed": False,
        "inputs": {
            "slow_transcript": str(args.slow_transcript),
            "mutation_transcript": str(args.mutation_transcript),
        },
        "checks": [check.to_dict() for check in checks],
        "summary": {"passed": len(checks) - failed, "failed": failed},
        "safety": safety,
    }


def render_markdown(result: dict[str, Any]) -> str:
    failed = [check for check in result["checks"] if not check["passed"]]
    slow_status = "failed" if any(c["name"].startswith("slow.") for c in failed) else "ok"
    mutation_status = "failed" if any(c["name"].startswith("mutation.") for c in failed) else "ok"
    lines = [
        "# Windows Interactive Acceptance",
        "",
        f"Status: {result['status']}",
        f"Slow transcript: {slow_status}",
        f"Mutation/refusal transcript: {mutation_status}",
        "",
        "## Failed checks",
    ]
    lines.extend(
        [f"- {check['name']}: {check.get('reason', 'check failed')}" for check in failed]
        or ["- None"]
    )
    lines.extend(
        [
            "",
            "## Safety summary",
            "- Read-only: true",
            "- Mutation performed: false",
            "- Cleanup/remediation/rollback/recovery executed: false",
            "- Natural-language, shell, arbitrary command execution: false",
            "",
            "Note: this helper validates saved transcript files only and did not run "
            "ShellForgeAI commands, PowerShell, WinRM, QGA, Proxmox, model calls, "
            "or mutation.",
        ]
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = build_result(args)
    json_text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    markdown_text = render_markdown(result)
    if args.out_json:
        args.out_json.write_text(json_text, encoding="utf-8")
    if args.out_markdown:
        args.out_markdown.write_text(markdown_text, encoding="utf-8")
    if args.emit_json:
        sys.stdout.write(json_text)
    if args.markdown:
        sys.stdout.write(markdown_text)
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
