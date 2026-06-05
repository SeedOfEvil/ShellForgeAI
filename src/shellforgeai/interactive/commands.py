from __future__ import annotations

import difflib
import re
import shlex
from dataclasses import dataclass


@dataclass(frozen=True)
class RoutedCommand:
    name: str
    args: str = ""
    argv: tuple[str, ...] = ()


_SAFE_PROFILES = ("quick", "standard", "full")

_SAFE_SUGGESTION_COMMANDS = (
    "version",
    "doctor",
    "model doctor",
    "status",
    "status --brief",
    "status --json",
    "ops report",
    "ops report --brief",
    "ops report --json",
    "ops report history --limit 5",
    "ops report compare-latest",
    "v1 check quick",
    "v1 check standard",
    "v1 check --profile quick --json",
    "v1 check --profile standard --json",
    "triage",
    "triage --brief",
    "triage --json",
    "triage --target <target>",
    "propose",
    "propose --brief",
    "propose --json",
    "propose --target <target>",
    "apply-preview",
    "apply-preview --brief",
    "apply-preview --json",
    "apply-preview --target <target>",
    "verify",
    "verify --brief",
    "verify --json",
    "verify --target <target>",
    "handoff",
    "handoff --brief",
    "handoff --json",
    "handoff --save",
    "handoff validate <handoff_id>",
    "handoff export <handoff_id>",
    "handoff export-validate <export_id>",
    "handoff history",
    "handoff history --limit 5",
    "handoff compare-latest",
    "handoff compare <before> <after>",
    "triage docker",
    "triage docker --brief",
    "triage docker --json",
    "triage docker detail <target>",
    "remediation self-test quick",
    "remediation self-test --profile quick --json",
    "remediation eligibility --target <target> --explain",
    "recipes",
    "recipes --json",
    "recipes list",
    "recipes inspect docker.disposable_restart",
    "recipes eligibility --recipe docker.disposable_restart --target <target>",
    "recipes preflight --recipe docker.disposable_restart --target <target>",
    "recipes preflight --recipe docker.disposable_restart --target <target> --json",
    "recipes preflight --recipe docker.disposable_restart --target <target> --save",
    "recipes preflight validate <preflight_id>",
    "safe-actions",
    "help",
    "pending",
    "summary",
    "/summary",
    "exit",
)

_COMMAND_LIKE_STARTS = (
    "ops",
    "op",
    "status",
    "report",
    "triage",
    "trage",
    "propose",
    "apply-preview",
    "verify",
    "handoff",
    "v1",
    "doctor",
    "model",
    "remediation",
    "remediaton",
    "recipes",
    "safe-actions",
    "audit",
)

_COMMAND_LIKE_FLAGS = ("--json", "--profile", "--target", "--brief", "--limit")

_ALLOWED_CLI_DISPATCH: dict[tuple[str, ...], tuple[str, ...]] = {
    ("version",): ("version",),
    ("doctor",): ("doctor",),
    ("model", "doctor"): ("model", "doctor"),
    ("ops", "report"): ("ops", "report"),
    ("ops", "report", "--brief"): ("ops", "report", "--brief"),
    ("ops", "report", "--json"): ("ops", "report", "--json"),
    ("ops", "report", "--save"): ("ops", "report", "--save"),
    ("ops", "report", "history"): ("ops", "report", "history"),
    ("ops", "report", "history", "--limit", "5"): (
        "ops",
        "report",
        "history",
        "--limit",
        "5",
    ),
    ("ops", "report", "compare-latest"): ("ops", "report", "compare-latest"),
    ("ops", "report", "compare-latest", "--json"): (
        "ops",
        "report",
        "compare-latest",
        "--json",
    ),
    ("triage",): ("triage",),
    ("triage", "--brief"): ("triage", "--brief"),
    ("triage", "--json"): ("triage", "--json"),
    ("propose",): ("propose",),
    ("propose", "--brief"): ("propose", "--brief"),
    ("propose", "--json"): ("propose", "--json"),
    ("propose", "--from-triage"): ("propose", "--from-triage"),
    ("propose", "--from-triage", "--json"): ("propose", "--from-triage", "--json"),
    ("apply-preview",): ("apply-preview",),
    ("apply-preview", "--brief"): ("apply-preview", "--brief"),
    ("apply-preview", "--json"): ("apply-preview", "--json"),
    ("apply-preview", "--from-propose"): ("apply-preview", "--from-propose"),
    ("apply-preview", "--from-propose", "--json"): (
        "apply-preview",
        "--from-propose",
        "--json",
    ),
    ("apply-preview", "--from-triage"): ("apply-preview", "--from-triage"),
    ("apply-preview", "--from-triage", "--json"): (
        "apply-preview",
        "--from-triage",
        "--json",
    ),
    ("verify",): ("verify",),
    ("verify", "--brief"): ("verify", "--brief"),
    ("verify", "--json"): ("verify", "--json"),
    ("verify", "--from-status"): ("verify", "--from-status"),
    ("verify", "--from-status", "--json"): ("verify", "--from-status", "--json"),
    ("verify", "--from-triage"): ("verify", "--from-triage"),
    ("verify", "--from-triage", "--json"): ("verify", "--from-triage", "--json"),
    ("verify", "--from-propose"): ("verify", "--from-propose"),
    ("verify", "--from-propose", "--json"): ("verify", "--from-propose", "--json"),
    ("verify", "--from-apply-preview"): ("verify", "--from-apply-preview"),
    ("verify", "--from-apply-preview", "--json"): (
        "verify",
        "--from-apply-preview",
        "--json",
    ),
    ("handoff",): ("handoff",),
    ("handoff", "--brief"): ("handoff", "--brief"),
    ("handoff", "--json"): ("handoff", "--json"),
    ("handoff", "--save"): ("handoff", "--save"),
    ("handoff", "--save", "--json"): ("handoff", "--save", "--json"),
    ("handoff", "summary"): ("handoff",),
    ("handoff", "--from-status"): ("handoff", "--from-status"),
    ("handoff", "--from-triage"): ("handoff", "--from-triage"),
    ("handoff", "--from-propose"): ("handoff", "--from-propose"),
    ("handoff", "--from-apply-preview"): ("handoff", "--from-apply-preview"),
    ("handoff", "--from-verify"): ("handoff", "--from-verify"),
    ("handoff", "history"): ("handoff", "history"),
    ("handoff", "history", "--json"): ("handoff", "history", "--json"),
    ("handoff", "history", "--limit", "5"): ("handoff", "history", "--limit", "5"),
    ("handoff", "compare-latest"): ("handoff", "compare-latest"),
    ("handoff", "compare-latest", "--json"): ("handoff", "compare-latest", "--json"),
    ("handoff", "compare-latest", "--only-changed"): (
        "handoff",
        "compare-latest",
        "--only-changed",
    ),
    ("handoff", "compare-latest", "--include-stable"): (
        "handoff",
        "compare-latest",
        "--include-stable",
    ),
    ("triage", "docker"): ("triage", "docker"),
    ("triage", "docker", "--brief"): ("triage", "docker", "--brief"),
    ("triage", "docker", "--json"): ("triage", "docker", "--json"),
    ("status",): ("status",),
    ("status", "--brief"): ("status", "--brief"),
    ("status", "--json"): ("status", "--json"),
}

for _profile in _SAFE_PROFILES:
    _ALLOWED_CLI_DISPATCH[("v1", "check", _profile)] = (
        "v1",
        "check",
        "--profile",
        _profile,
    )
    _ALLOWED_CLI_DISPATCH[("v1", "check", "--profile", _profile)] = (
        "v1",
        "check",
        "--profile",
        _profile,
    )
    _ALLOWED_CLI_DISPATCH[("v1", "check", "--profile", _profile, "--json")] = (
        "v1",
        "check",
        "--profile",
        _profile,
        "--json",
    )
    _ALLOWED_CLI_DISPATCH[("remediation", "self-test", _profile)] = (
        "remediation",
        "self-test",
        "--profile",
        _profile,
    )
    _ALLOWED_CLI_DISPATCH[("remediation", "self-test", "--profile", _profile)] = (
        "remediation",
        "self-test",
        "--profile",
        _profile,
    )
    _ALLOWED_CLI_DISPATCH[("remediation", "self-test", "--profile", _profile, "--json")] = (
        "remediation",
        "self-test",
        "--profile",
        _profile,
        "--json",
    )

_ALLOWED_CLI_DISPATCH.update(
    {
        ("recipes",): ("recipes",),
        ("recipes", "--json"): ("recipes", "--json"),
        ("recipes", "list"): ("recipes", "list"),
        ("recipes", "list", "--json"): ("recipes", "list", "--json"),
        ("safe-actions",): ("safe-actions",),
        ("safe-actions", "--json"): ("safe-actions", "--json"),
    }
)

_BRIEF_OPS_REPORT_PHRASES = (
    "no novel",
    "give me the short version",
    "short version",
    "i have five minutes",
    "quick status",
    "2am quick status",
    "2 am quick status",
    "what is on fire keep it short",
    "what is on fire, keep it short",
)

_QUICK_MUTATION_PHRASES = (
    "quickly restart",
    "quick restart",
    "restart it now",
    "restart now",
    "no novel clean up",
    "no novel cleanup",
    "clean up docker",
    "cleanup docker",
    "fast fix it",
    "fix it now",
    "just fix it",
    "execute proposal",
    "execute the proposal",
    "apply proposal",
    "apply the proposal",
    "run the plan",
    "execute recipe",
    "execute the recipe",
    "run restart recipe",
    "run the restart recipe",
    "execute the restart recipe",
    "run " + "docker" + " restart",
    "confirm restart",
    "apply the restart",
)

_DANGEROUS_COMMAND_PREFIXES = (
    ("docker",),
    ("sudo",),
    ("sh",),
    ("bash",),
    ("rm",),
    ("reboot",),
    ("systemctl",),
    ("apply",),
    ("chmod",),
    ("chown",),
    ("curl",),
)

_DANGEROUS_COMMAND_PATTERNS = (
    ("cleanup", "execute"),
    ("audit", "cleanup", "execute"),
    ("remediation", "execute"),
    ("remediation", "rollback-execute"),
    ("recipes", "execute"),
    ("rollback", "execute"),
    ("rollback-execute",),
    ("mission", "execute"),
)


def _split_command_style(raw: str) -> tuple[str, ...] | None:
    try:
        parts = shlex.split(raw)
    except ValueError:
        return None
    return tuple(parts)


def _tokenize_command_style(raw: str) -> tuple[str, ...] | None:
    parts = _split_command_style(raw)
    if parts is None:
        return None
    return tuple(part.lower() for part in parts)


def _dispatch_safe_cli_command(raw: str) -> RoutedCommand | None:
    original_tokens = _split_command_style(raw)
    if original_tokens is None:
        return None
    tokens = tuple(part.lower() for part in original_tokens)
    if tokens in _ALLOWED_CLI_DISPATCH:
        return RoutedCommand(name="cli_dispatch", args=raw, argv=_ALLOWED_CLI_DISPATCH[tokens])
    if len(tokens) in {3, 4} and tokens[:2] == ("propose", "--target") and tokens[2]:
        json_flag = len(tokens) == 4 and tokens[3] == "--json"
        if len(tokens) == 3 or json_flag:
            argv = ("propose", "--target", original_tokens[2])
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if len(tokens) in {3, 4} and tokens[:2] == ("apply-preview", "--target") and tokens[2]:
        json_flag = len(tokens) == 4 and tokens[3] == "--json"
        if len(tokens) == 3 or json_flag:
            argv = ("apply-preview", "--target", original_tokens[2])
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if len(tokens) in {3, 4} and tokens[:2] == ("verify", "--target") and tokens[2]:
        json_flag = len(tokens) == 4 and tokens[3] == "--json"
        if len(tokens) == 3 or json_flag:
            argv = ("verify", "--target", original_tokens[2])
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if len(tokens) in {3, 4} and tokens[:2] == ("handoff", "--target") and tokens[2]:
        json_flag = len(tokens) == 4 and tokens[3] == "--json"
        if len(tokens) == 3 or json_flag:
            argv = ("handoff", "--target", original_tokens[2])
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if (
        len(tokens) in {3, 4}
        and tokens[0] == "handoff"
        and tokens[1] in {"validate", "export", "export-validate"}
        and tokens[2]
    ):
        json_flag = len(tokens) == 4 and tokens[3] == "--json"
        if len(tokens) == 3 or json_flag:
            argv = ("handoff", original_tokens[1], original_tokens[2])
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if (
        len(tokens) in {4, 5}
        and tokens[0] == "handoff"
        and tokens[1] == "compare"
        and tokens[2]
        and tokens[3]
    ):
        json_flag = len(tokens) == 5 and tokens[4] == "--json"
        if len(tokens) == 4 or json_flag:
            argv = ("handoff", "compare", original_tokens[2], original_tokens[3])
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if (
        len(tokens) in {4, 5}
        and tokens[:3] == ("handoff", "history", "--limit")
        and tokens[3].isdigit()
    ):
        json_flag = len(tokens) == 5 and tokens[4] == "--json"
        if len(tokens) == 4 or json_flag:
            argv = ("handoff", "history", "--limit", original_tokens[3])
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if len(tokens) in {3, 4} and tokens[:2] == ("triage", "--target") and tokens[2]:
        json_flag = len(tokens) == 4 and tokens[3] == "--json"
        if len(tokens) == 3 or json_flag:
            argv = ("triage", "--target", original_tokens[2])
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if len(tokens) in {4, 5} and tokens[:3] == ("triage", "docker", "detail") and tokens[3]:
        json_flag = len(tokens) == 5 and tokens[4] == "--json"
        if len(tokens) == 4 or json_flag:
            argv = ("triage", "docker", "detail", original_tokens[3])
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if (
        len(tokens) in {5, 6}
        and tokens[:2] == ("remediation", "eligibility")
        and tokens[2] == "--target"
        and tokens[3]
        and tokens[4] == "--explain"
    ):
        json_flag = len(tokens) == 6 and tokens[5] == "--json"
        if len(tokens) == 5 or json_flag:
            argv = (
                "remediation",
                "eligibility",
                "--target",
                original_tokens[3],
                "--explain",
            )
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if len(tokens) in {3, 4} and tokens[:2] == ("recipes", "inspect") and tokens[2]:
        json_flag = len(tokens) == 4 and tokens[3] == "--json"
        if len(tokens) == 3 or json_flag:
            argv = ("recipes", "inspect", original_tokens[2])
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if (
        len(tokens) in {6, 7, 8}
        and tokens[:2] == ("recipes", "preflight")
        and tokens[2] == "--recipe"
        and tokens[3]
        and tokens[4] == "--target"
        and tokens[5]
    ):
        flags = set(tokens[6:])
        if len(tokens) == 6 or flags in ({"--json"}, {"--save"}, {"--save", "--json"}):
            argv = (
                "recipes",
                "preflight",
                "--recipe",
                original_tokens[3],
                "--target",
                original_tokens[5],
            )
            for flag in original_tokens[6:]:
                if flag.lower() in {"--save", "--json"}:
                    argv = (*argv, flag)
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if len(tokens) in {4, 5} and tokens[:3] == ("recipes", "preflight", "validate") and tokens[3]:
        json_flag = len(tokens) == 5 and tokens[4] == "--json"
        if len(tokens) == 4 or json_flag:
            argv = ("recipes", "preflight", "validate", original_tokens[3])
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if len(tokens) in {3, 4} and tokens[:2] == ("preflight", "restart") and tokens[2]:
        json_flag = len(tokens) == 4 and tokens[3] == "--json"
        if len(tokens) == 3 or json_flag:
            argv = (
                "recipes",
                "preflight",
                "--recipe",
                "docker.disposable_restart",
                "--target",
                original_tokens[2],
            )
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if len(tokens) in {4, 5} and tokens[:3] == ("preflight", "docker", "restart") and tokens[3]:
        json_flag = len(tokens) == 5 and tokens[4] == "--json"
        if len(tokens) == 4 or json_flag:
            argv = (
                "recipes",
                "preflight",
                "--recipe",
                "docker.disposable_restart",
                "--target",
                original_tokens[3],
            )
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if (
        len(tokens) in {6, 7}
        and tokens[:2] == ("recipes", "eligibility")
        and tokens[2] == "--recipe"
        and tokens[3]
        and tokens[4] == "--target"
        and tokens[5]
    ):
        json_flag = len(tokens) == 7 and tokens[6] == "--json"
        if len(tokens) == 6 or json_flag:
            argv = (
                "recipes",
                "eligibility",
                "--recipe",
                original_tokens[3],
                "--target",
                original_tokens[5],
            )
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    if len(tokens) in {3, 4} and tokens[:2] == ("safe-actions", "--target") and tokens[2]:
        json_flag = len(tokens) == 4 and tokens[3] == "--json"
        if len(tokens) == 3 or json_flag:
            argv = ("safe-actions", "--target", original_tokens[2])
            if json_flag:
                argv = (*argv, "--json")
            return RoutedCommand(name="cli_dispatch", args=raw, argv=argv)
    return None


def _normalize_suggestion_text(text: str) -> str:
    lowered = " ".join(text.lower().strip().split())
    return lowered.replace("selftest", "self test").replace("self-test", "self test")


def suggest_safe_commands(raw: str, *, limit: int = 3) -> tuple[str, ...]:
    """Return conservative suggestions from the safe interactive allowlist only."""
    normalized_raw = _normalize_suggestion_text(raw)
    if not normalized_raw:
        return ()

    scored: list[tuple[float, int, str]] = []
    for index, command in enumerate(_SAFE_SUGGESTION_COMMANDS):
        candidate = _normalize_suggestion_text(command)
        ratio = difflib.SequenceMatcher(None, normalized_raw, candidate).ratio()
        raw_words = normalized_raw.split()
        candidate_words = candidate.split()
        raw_tokens = set(raw_words)
        candidate_tokens = set(candidate_words)
        overlap = len(raw_tokens & candidate_tokens) / max(len(raw_tokens | candidate_tokens), 1)
        token_ratio = sum(
            max(
                difflib.SequenceMatcher(None, raw_word, candidate_word).ratio()
                for candidate_word in candidate_words
            )
            for raw_word in raw_words
        ) / max(len(raw_words), 1)
        score = max(ratio, (ratio * 0.75) + (overlap * 0.25), (ratio * 0.6) + (token_ratio * 0.4))
        if "--json" in candidate_words and "--json" not in raw_words:
            score -= 0.06
        if "compare-latest" in candidate_words and "compare-latest" not in raw_words:
            score -= 0.08
        if score >= 0.62:
            scored.append((score, index, command))

    scored.sort(key=lambda item: (-item[0], item[1]))
    suggestions: list[str] = []
    for _score, _index, command in scored:
        if command not in suggestions:
            suggestions.append(command)
        if len(suggestions) >= limit:
            break
    return tuple(suggestions)


def _is_command_like_unknown(raw: str) -> bool:
    tokens = _tokenize_command_style(raw)
    if not tokens:
        return False
    if tokens[0] in {"show", "what", "how", "is", "why"}:
        return False
    if "command" in tokens or "commands" in tokens:
        return False
    return tokens[0] in _COMMAND_LIKE_STARTS or any(
        token.startswith(_COMMAND_LIKE_FLAGS) for token in tokens
    )


def _dispatch_dangerous_command(raw: str) -> RoutedCommand | None:
    tokens = _tokenize_command_style(raw)
    if not tokens:
        return None
    if "|" in tokens and tokens[0] in {"curl", "wget"}:
        return RoutedCommand(name="mutation_refused", args=raw)
    if tokens[0] == "service" and any(
        token in {"restart", "start", "stop", "reload", "enable", "disable"} for token in tokens[1:]
    ):
        return RoutedCommand(name="mutation_refused", args=raw)
    if any(tokens[: len(prefix)] == prefix for prefix in _DANGEROUS_COMMAND_PREFIXES):
        return RoutedCommand(name="mutation_refused", args=raw)
    if any(tokens[: len(pattern)] == pattern for pattern in _DANGEROUS_COMMAND_PATTERNS):
        return RoutedCommand(name="mutation_refused", args=raw)
    return None


def _normalize_intent_text(text: str) -> str:
    lowered = re.sub(r"[^a-z0-9/\s]", " ", text.lower())
    lowered = re.sub(r"\s+", " ", lowered).strip()
    fillers = (
        "hey ",
        "hi ",
        "hello ",
        "yo ",
        "please ",
        "can you ",
        "could you ",
        "i think ",
        "so ",
        "uh ",
        "um ",
    )
    changed = True
    while changed:
        changed = False
        for prefix in fillers:
            if lowered.startswith(prefix):
                lowered = lowered[len(prefix) :].strip()
                changed = True
    return lowered


def route_input(text: str) -> RoutedCommand:
    raw = text.strip()
    if not raw:
        return RoutedCommand(name="noop")
    if raw.startswith("/"):
        head, _, tail = raw.partition(" ")
        return RoutedCommand(name=head.lower(), args=tail.strip())

    normalized_session_summary = _normalize_intent_text(raw)
    if normalized_session_summary in {
        "summary",
        "session summary",
        "summarize this session",
        "what happened in this session",
        "what did you check",
        "what did you find",
        "what did you refuse",
        "what should i hand off",
    }:
        return RoutedCommand(name="/summary")
    summary_tokens = _split_command_style(raw)
    if summary_tokens and summary_tokens[0].lower() == "summary":
        flags = tuple(token.lower() for token in summary_tokens[1:])
        if flags and all(flag in {"--json", "--save"} for flag in flags):
            return RoutedCommand(name="/summary", args=" ".join(flags), argv=flags)
    if normalized_session_summary == "summary json" or raw.lower().strip() == "summary --json":
        return RoutedCommand(name="/summary", args="--json", argv=("--json",))

    exact_session = raw.lower()
    if exact_session in {"exit", "quit"}:
        return RoutedCommand(name="/exit")
    if exact_session in {"help", "?", "commands", "what can i do?"}:
        return RoutedCommand(name="/help")
    if exact_session == "pending":
        return RoutedCommand(name="/pending")
    if exact_session in {"restart compose", "compose restart"}:
        return RoutedCommand(name="mutation_refused", args=raw)

    verify_mutation_phrases = (
        "verify and restart",
        "verify then fix",
        "apply and verify",
        "restart and verify",
        "clean up and verify",
        "cleanup and verify",
        "execute then verify",
    )
    if any(phrase in exact_session for phrase in verify_mutation_phrases):
        return RoutedCommand(name="mutation_refused", args=raw)

    handoff_mutation_phrases = (
        "handoff and restart",
        "handoff then restart",
        "handoff and apply",
        "handoff then apply",
        "handoff and fix",
        "handoff and clean up",
        "handoff and cleanup",
        "handoff and execute",
        "handoff and remediate",
        "handoff and rollback",
        "summarize and fix",
        "summarise and fix",
        "write handoff and clean up",
        "write handoff and cleanup",
    )
    if any(phrase in exact_session for phrase in handoff_mutation_phrases):
        return RoutedCommand(name="mutation_refused", args=raw)

    safe_dispatch = _dispatch_safe_cli_command(raw)
    if safe_dispatch is not None:
        return safe_dispatch
    dangerous_dispatch = _dispatch_dangerous_command(raw)
    if dangerous_dispatch is not None:
        return dangerous_dispatch
    if _is_command_like_unknown(raw):
        return RoutedCommand(name="unknown_command", args=raw, argv=suggest_safe_commands(raw))

    lowered = _normalize_intent_text(raw)
    raw_lower = raw.lower()
    if any(
        cue in lowered
        for cue in (
            "what can shellforgeai safely do next",
            "what can you safely do",
            "what fixes are available",
            "what recipes exist",
            "safe actions",
            "safe action",
        )
    ):
        target_match = re.search(
            r"\b(?:for|target)\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b", raw, flags=re.IGNORECASE
        )
        if target_match:
            return RoutedCommand(
                name="cli_dispatch",
                args=raw,
                argv=("safe-actions", "--target", target_match.group(1)),
            )
        return RoutedCommand(name="cli_dispatch", args=raw, argv=("safe-actions",))

    preflight_cues = (
        "preflight " + "docker" + " restart",
        "preflight restart",
        "preflight the restart recipe",
        "check if you could restart",
        "restart this safely",
        "eligible for disposable restart",
        "what gates are needed to restart",
    )
    if any(cue in lowered for cue in preflight_cues):
        target_match = re.search(
            r"\b(?:for|target|restart)\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b",
            raw,
            flags=re.IGNORECASE,
        )
        target = target_match.group(1).strip("?.!,") if target_match else ""
        if target.lower() in {"this", "safely", "it", "docker"}:
            target = ""
        if target:
            return RoutedCommand(
                name="cli_dispatch",
                args=raw,
                argv=(
                    "recipes",
                    "preflight",
                    "--recipe",
                    "docker.disposable_restart",
                    "--target",
                    target,
                ),
            )
        return RoutedCommand(
            name="cli_dispatch",
            args=raw,
            argv=(
                "recipes",
                "eligibility",
                "--recipe",
                "docker.disposable_restart",
                "--target",
                "<target>",
            ),
        )

    proposal_cues = (
        "what would you propose",
        "what should we propose",
        "propose next step",
        "what would you do next",
        "what is the safe proposal",
        "propose for the top suspect",
        "show me the proposal",
    )
    if any(cue in lowered for cue in proposal_cues):
        if any(
            mut in lowered
            for mut in ("restart it", "execute", "apply", "run the plan", "fix it", "do it")
        ):
            return RoutedCommand(name="ask", args=raw)
        return RoutedCommand(name="cli_dispatch", args=raw, argv=("propose", "--from-triage"))
    target_proposal = None
    if "propose restart" not in lowered and "propose remediation" not in lowered:
        target_proposal = re.search(
            r"\bwhat\s+would\s+you\s+propose\s+for\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b|"
            r"\bpropose\b.*\b(?:for|target)\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b",
            raw,
            flags=re.IGNORECASE,
        )
    if target_proposal:
        target = next((g for g in target_proposal.groups() if g), "")
        if target.lower() in {"the", "top", "suspect"}:
            return RoutedCommand(name="cli_dispatch", args=raw, argv=("propose", "--from-triage"))
        return RoutedCommand(name="cli_dispatch", args=raw, argv=("propose", "--target", target))
    apply_preview_cues = (
        "apply preview",
        "preview apply",
        "what would applying this require",
        "what would applying the proposed action require",
        "what would happen if we applied it",
        "show apply gates",
        "preview the proposed action",
        "can this be applied",
    )
    if any(cue in lowered for cue in apply_preview_cues):
        if any(
            mut in lowered for mut in ("restart", "execute", "apply now", "confirm apply", "run it")
        ):
            return RoutedCommand(name="ask", args=raw)
        return RoutedCommand(
            name="cli_dispatch", args=raw, argv=("apply-preview", "--from-propose")
        )
    verify_cues = (
        "verify status",
        "verify the system",
        "verify docker",
        "verify current state",
        "did anything improve",
        "did the issue clear",
        "is it fixed",
        "verify the top suspect",
    )
    verify_mutations = (
        "verify and restart",
        "verify then fix",
        "apply and verify",
        "restart and verify",
        "clean up and verify",
        "cleanup and verify",
        "execute then verify",
        "restart compose",
    )
    if any(cue in lowered for cue in verify_cues) or re.search(
        r"\bverify\s+[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\b", raw, flags=re.IGNORECASE
    ):
        if any(mut in lowered for mut in verify_mutations):
            return RoutedCommand(name="mutation_refused", args=raw)
        m = re.search(r"\bverify\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\b", raw, flags=re.IGNORECASE)
        if m and m.group(1).lower() not in {"status", "the", "docker", "current", "system"}:
            return RoutedCommand(
                name="cli_dispatch", args=raw, argv=("verify", "--target", m.group(1))
            )
        return RoutedCommand(name="cli_dispatch", args=raw, argv=("verify", "--from-triage"))
    handoff_cues = (
        "give me a handoff",
        "give me the handoff",
        "give me an operator handoff",
        "give me the operator handoff",
        "operator handoff",
        "handoff summary",
        "summarize for handoff",
        "summary for handoff",
        "what should i tell the next operator",
        "what do i tell the next operator",
        "what do i hand over",
        "make a shift handoff",
        "shift handoff",
        "save handoff",
        "save the handoff",
    )
    handoff_mutations = (
        "restart",
        "and apply",
        "then apply",
        "fix it",
        "and fix",
        "clean up",
        "cleanup",
        "execute",
        "remediate",
        "rollback",
        "compose",
    )
    if any(cue in lowered for cue in handoff_cues) or re.search(r"\bhandoff\b", lowered):
        if any(mut in lowered for mut in handoff_mutations):
            return RoutedCommand(name="mutation_refused", args=raw)
        if "save handoff" in lowered or "save the handoff" in lowered:
            return RoutedCommand(name="cli_dispatch", args=raw, argv=("handoff", "--save"))
        return RoutedCommand(name="cli_dispatch", args=raw, argv=("handoff",))
    if any(phrase in lowered or phrase in raw_lower for phrase in _QUICK_MUTATION_PHRASES):
        return RoutedCommand(name="mutation_refused", args=raw)
    if any(phrase in lowered or phrase in raw_lower for phrase in _BRIEF_OPS_REPORT_PHRASES):
        return RoutedCommand(name="cli_dispatch", args=raw, argv=("status", "--brief"))
    storage_perf_intents = [
        "i think my disk is slow",
        "disk is slow",
        "disk feels slow",
        "storage is slow",
        "drive is slow",
        "filesystem is slow",
        "io is slow",
        "i/o is slow",
        "high io",
        "high disk io",
        "disk performance",
        "storage performance",
        "disk latency",
        "disk lag",
        "writes are slow",
        "reads are slow",
        "disk is dying",
        "drive is dying",
        "disk failing",
        "drive failing",
        "disk health",
        "storage health",
        "nvme issue",
        "ssd issue",
        "hard drive issue",
        "filesystem issue",
        "storage issue",
        "disk slow",
        "disk dying",
    ]
    if any(p in lowered for p in storage_perf_intents):
        return RoutedCommand(name="diagnose", args="storage_performance")
    log_service_aliases = [
        "nginx",
        "apache",
        "httpd",
        "caddy",
        "ssh",
        "sshd",
        "docker",
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "redis",
        "shellforgeai",
    ]
    auth_phrases = [
        "auth failing",
        "auth fail",
        "login failing",
        "logins failing",
        "ssh login failing",
        "ssh failed",
        "ssh failing",
        "sudo failing",
        "sudo failed",
        "permission denied",
        "permision denied",
        "failed password",
        "invalid user",
        "pam error",
        "pam errors",
        "auth log",
        "auth logs",
        "login failed",
    ]
    lab_container_aliases = (
        "missing env",
        "missing-env",
        "restart loop",
        "restart-loop",
        "noisy logs",
        "noisy-logs",
        "bad volume perms",
        "bad-volume-perms",
        "bad network",
        "bad-network",
        "healthy web",
        "healthy-web",
        "healthy web service",
        "the healthy web service",
        "is the healthy web service",
        "sfai-missing-env",
        "sfai missing env",
        "sfai-restart-loop",
        "sfai restart loop",
        "sfai-noisy-logs",
        "sfai noisy logs",
        "sfai-bad-volume-perms",
        "sfai bad volume perms",
        "sfai-bad-network",
        "sfai bad network",
        "sfai-healthy-web",
        "sfai healthy web",
    )
    if any(alias in lowered for alias in lab_container_aliases) or any(
        alias in raw.lower() for alias in lab_container_aliases
    ):
        return RoutedCommand(name="diagnose", args="docker")
    failed_container_phrases = [
        "find failed containers",
        "find failed container",
        "failed containers",
        "failed docker containers",
        "any failed containers",
        "container failures",
        "explain container failures",
        "show failing containers",
        "explain likely cause",
    ]
    if any(p in lowered for p in failed_container_phrases):
        return RoutedCommand(name="diagnose", args="docker")
    write_failure_phrases = [
        "service cannot write to disk",
        "service can not write",
        "service cant write",
        "app cannot write to disk",
        "app cant write",
        "cannot write file",
        "cannot write to disk",
        "cant write to disk",
        "cannot create file",
        "write failed",
        "read-only filesystem",
        "read only filesystem",
        "filesystem read-only",
        "filesystem read only",
        "disk write permission",
        "volume permission",
        "why can the service not write",
        "why cant the service write",
        "why can not the service write",
        "why can the app not write",
        "why cant the app write",
    ]
    if any(p in lowered for p in write_failure_phrases):
        return RoutedCommand(name="diagnose", args="logs")
    network_log_failure_phrases = [
        "network reachability is broken",
        "network reachabilty is broken",
        "network reechability",
        "netwrok reachability",
        "netwrok reachabilty",
        "reachability is broken",
        "reechability is broken",
        "upstream is unreachable",
        "upstream unreachable",
        "upstram unreachable",
        "upstram is unreachable",
        "app cannot reach upstream",
        "app cant reach upstream",
        "app can not reach upstream",
        "app cannot reach the server",
        "app cant reach the server",
        "app cannot reach upstram",
        "service cannot reach upstream",
        "service cant reach upstream",
        "service can not reach upstream",
        "service dependency unreachable",
        "service dependency is unreachable",
        "container network broken",
        "container network is broken",
        "dns errors in logs",
        "dns errors in log",
        "dns erorrs in logs",
        "dns erors in logs",
        "connection refused errors",
        "coneccion refused errors",
        "coneccion refused",
        "timeout errors",
        "timout errors",
        "network errors",
        "why cant the app reach the server",
        "why can the app not reach the server",
        "why cant the app reach upstream",
        "why can the app not reach upstream",
    ]
    if any(p in lowered for p in network_log_failure_phrases):
        return RoutedCommand(name="diagnose", args="docker")
    container_failure_phrases = [
        "why is the app restarting",
        "why is my app restarting",
        "why is the container restarting",
        "why is the container restaring",
        "container restarting",
        "container restaring",
        "why did the container exit",
        "why did the contianer exit",
        "exited container",
        "exited containers",
        "what containers are failing",
        "what containers failing",
        "any container errors",
        "container errors",
        "container error",
        "container is crashing",
        "container is crashng",
        "containers are crashing",
        "is the container healthy",
        "container unhealthy",
        "restart loop",
        "crash loop",
        "crashloop",
        "container crashing",
        "is anything crashing",
        "anything crashing",
        "is anything crasing",
        "is the app crashing",
        "is the app restarting",
        "show container logs",
        "show docker logs",
    ]
    if any(p in lowered for p in container_failure_phrases):
        return RoutedCommand(name="diagnose", args="docker")
    log_phrases = [
        "any errors",
        "any erorrs",
        "any erors",
        "any error",
        "any warnings",
        "any critical errors",
        "check logs",
        "check loggs",
        "show logs",
        "show recent errors",
        "recent errors",
        "recent failures",
        "anything failing",
        "anything crashing",
        "is anything crashing",
        "what do the logs say",
        "look for errors",
        "summarize errors",
        "summarize the errors",
        "summarise errors",
        "check recent failures",
        "why did it fail",
        "why is it failing",
        "is it failng",
        "is it crasing",
        "loggs",
        "log errors",
        "find recent logs",
        "find recent errors",
        "find recent logs and errors",
        "recent logs and errors",
        "show recent logs",
        "find logs",
    ]
    log_storage_phrases = [
        "disk errors",
        "i/o errors",
        "io errors",
        "no space left",
        "filesystem read-only",
        "read-only filesystem",
        "oom killed",
        "oom kill",
    ]
    log_network_error_phrases = [
        "connection refused errors",
        "timeout errors",
        "tls errors",
        "certificate errors",
        "dns errors",
    ]
    delete_log_phrases = [
        "delete logs",
        "clear logs",
        "truncate logs",
        "rotate logs",
        "wipe logs",
        "remove logs",
    ]
    if any(p in lowered for p in delete_log_phrases):
        return RoutedCommand(name="logs_mutation_refused", args=raw)
    if any(p in lowered for p in auth_phrases):
        return RoutedCommand(name="diagnose", args="auth")
    for svc in log_service_aliases:
        if (
            (f"check {svc} logs" in lowered)
            or (f"{svc} logs" in lowered)
            or (f"{svc} errors" in lowered)
            or (f"why is {svc} failing" in lowered)
            or (f"why is {svc} broken" in lowered)
        ):
            return RoutedCommand(name="diagnose", args=f"logs:{svc}")
    oncall_phrases = [
        "i m on call what s broken",
        "what s broken",
        "anything broken",
        "what needs attention",
        "incident overview",
        "triage this box",
        "operator overview",
    ]
    if any(p in lowered for p in oncall_phrases):
        return RoutedCommand(name="diagnose", args="docker")
    if any(p in lowered for p in log_phrases):
        return RoutedCommand(name="diagnose", args="logs")
    if any(p in lowered for p in log_storage_phrases):
        return RoutedCommand(name="diagnose", args="logs")
    if any(p in lowered for p in log_network_error_phrases):
        return RoutedCommand(name="diagnose", args="logs")
    perf_intents = [
        "my machine is running slow",
        "my computer is slow",
        "my computer feels slow",
        "computer feels slow",
        "my pc is slow",
        "my pc feels slow",
        "pc feels slow",
        "system feels slow",
        "system feels sluggish",
        "the system feels sluggish",
        "my system feels slow",
        "server feels sluggish",
        "server feels a bit slow",
        "server feels a bit sluggish",
        "this server feels slow",
        "the server feels a bit slow",
        "computer feels sluggish",
        "it feels sluggish",
        "system is sluggish",
        "server is sluggish",
        "machine is laggy",
        "system is laggy",
        "feels slow",
        "feels laggy",
        "things feel slow",
        "things are slow",
        "the box feels slow",
        "machine feels sluggish",
        "machine feels slow",
        "this machine feels slow",
        "this computer feels slow",
        "server is slow",
        "server feels slow",
        "host is slow",
        "host feels slow",
        "the host feels slow",
        "why is this machine slow",
        "why is my server slow",
        "high cpu",
        "high memory",
        "high load",
        "performance issue",
        "laggy",
        "hanging",
        "system is crawling",
        "everything is slow",
        "device feels slow",
        "device feels sluggish",
        "device feels a bit sluggish",
        "device is slow",
        "device is sluggish",
        "device is laggy",
        "device feels laggy",
        "device feels a bit slow",
        "the device feels a bit slow",
        "device feels a bit laggy",
    ]
    if any(p in lowered for p in perf_intents):
        return RoutedCommand(name="diagnose", args="performance")
    disk_intents = [
        "how much disk space do we have left",
        "disk space left",
        "free disk space",
        "are we running out of disk",
        "is disk full",
        "disk usage",
        "storage left",
        "how full is the disk",
        "out of space",
        "inode usage",
        "are inodes full",
        "disk is dying",
        "drive is dying",
        "disk failing",
        "drive failing",
        "disk health",
        "storage health",
        "disk errors",
        "hard drive issue",
        "nvme issue",
        "ssd issue",
    ]
    if any(p in lowered for p in disk_intents):
        return RoutedCommand(name="diagnose", args="disk")
    health_intents = [
        "my system is glitchy",
        "computer is acting weird",
        "machine is acting weird",
        "something is wrong with this machine",
        "system health",
        "check this machine",
        "any issue on this machine",
        "any issues on this machine",
        "anything wrong with my computer",
        "anything wrong with this computer",
        "anything wrong with my machine",
        "anything wrong with this machine",
        "anything wrong with my pc",
        "anything wrong with this pc",
        "anything wrong with my server",
        "anything wrong with this server",
        "is my computer having any issue",
        "so is everything okay with my computer",
        "is everything okay with my computer",
        "is anything wrong",
        "is anything wrong with this system",
        "is my computer okay",
        "is my machine okay",
        "is this host okay",
        "is this system healthy",
        "is it running normally",
        "does this look normal",
        "give me a quick health check",
        "what should i check first",
        "is the system ok",
        "is the system okay",
        "is system ok",
        "is system okay",
        "system ok",
        "system okay",
        "is the host ok",
        "is the host okay",
        "is everything ok",
        "is everything okay",
        "check my computer",
        "check my machine",
        "check this host",
        "check this system",
        "what does this system do",
        "what is this box",
        "what is this machine for",
        "what role is this server playing",
        "host health",
        "computer health",
        "machine health",
        "do you see any issues",
        "do you see anything wrong",
        "what’s wrong with my computer",
        "what is wrong with my computer",
        "is this host healthy",
        "things are unstable",
        "weird behavior",
        "glitches",
    ]
    if any(p in lowered for p in health_intents):
        return RoutedCommand(name="diagnose", args="health")
    network_intents = [
        "network status",
        "check network",
        "is networking okay",
        "is this server online",
        "check dns",
        "dns status",
        "dns broken",
        "cannot resolve",
        "resolver issue",
        "firewall status",
        "is port ",
        "can it reach ",
        "can this server reach ",
        "server reach ",
        "sever reach ",
        "box reach ",
        "host reach ",
        "machine reach ",
        "can it connect to ",
        "can it conenct to ",
        "conenct to ",
        "reachable",
        "test port ",
        "tcp connect ",
        "open port ",
        "allow port ",
        "add firewall rule",
        "netwrok status",
        "dns statsu",
        "firwall status",
        "listerning ports",
    ]
    if any(p in lowered for p in network_intents):
        return RoutedCommand(name="diagnose", args="network")
    service_intents = [
        "what services this computer is running",
        "what services are running",
        "what is running on this machine",
        "what is this host running",
        "what services are listening",
        "what ports are open",
        "what daemons are running",
        "show running services",
        "list services",
        "list listening services",
        "what apps are running",
        "what is exposed",
        "what is listening on ports",
        "which services are active",
    ]
    if any(p in lowered for p in service_intents):
        return RoutedCommand(name="diagnose", args="services")
    if "is nginx running" in lowered:
        return RoutedCommand(name="diagnose", args="nginx")
    if "is ssh running" in lowered:
        return RoutedCommand(name="diagnose", args="ssh")
    if "is docker running" in lowered:
        return RoutedCommand(name="diagnose", args="docker")
    pkg_install_match = re.search(r"\bis\s+([a-z0-9.+_-]+)\s+installed\b", lowered)
    if pkg_install_match:
        return RoutedCommand(name="diagnose", args=f"packages:{pkg_install_match.group(1)}")
    owner_match = re.search(
        r"\b(?:what\s+package\s+owns|what\s+owns|who\s+owns)\s+(/[^\s]+)", lowered
    )
    if owner_match:
        return RoutedCommand(name="diagnose", args=f"package-owner:{owner_match.group(1)}")
    package_config_intents = [
        ("what packages changed recently", "packages"),
        ("package history", "packages"),
        ("is nginx installed", "packages"),
        ("what version of nginx", "packages"),
        ("what package owns", "packages"),
        ("what config changed recently", "config"),
        ("check nginx config", "config"),
        ("ngnix config", "config"),
        ("confg", "config"),
        ("cnfig", "config"),
        ("what changed before this broke", "changes"),
        ("recent chagnes", "changes"),
    ]
    for tok, tgt in package_config_intents:
        if tok in lowered:
            return RoutedCommand(name="diagnose", args=tgt)
    for prefix, cmd in [
        ("diagnose ", "diagnose"),
        ("research ", "research"),
        ("plan ", "plan"),
        ("inspect host", "inspect_host"),
        ("inspect service ", "inspect_service"),
        ("ask ", "ask"),
    ]:
        if lowered.startswith(prefix):
            return RoutedCommand(name=cmd, args=raw[len(prefix) :].strip())
    tool_first_ops_hints = [
        ("cpu", "performance"),
        ("memory", "performance"),
        ("load", "performance"),
        ("slow", "performance"),
        ("disk", "disk"),
        ("storage", "disk"),
        ("inode", "disk"),
        ("firewall", "firewall"),
        ("service", "services"),
        ("ports", "services"),
        ("exposed", "services"),
        ("nginx", "nginx"),
        ("docker", "docker"),
        ("ssh", "ssh"),
        ("host health", "health"),
        ("machine health", "health"),
        ("system ok", "health"),
        ("system okay", "health"),
        ("host ok", "health"),
        ("host okay", "health"),
        ("everything ok", "health"),
        ("everything okay", "health"),
    ]
    for token, target in tool_first_ops_hints:
        if token in lowered:
            return RoutedCommand(name="diagnose", args=target)
    return RoutedCommand(name="ask", args=raw)
