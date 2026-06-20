"""Safe ShellForgeAI command suggestion registry.

The registry is suggestion-only: helpers in this module validate and rewrite
operator-facing command text, but never execute commands or perform cleanup,
restart, remediation, rollback, recovery, Docker/Compose mutation, shell
passthrough, or natural-language execution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SafeCommand:
    id: str
    command: str
    category: str
    read_only: bool
    mutation: bool
    description: str
    suggest: bool = True
    placeholders: tuple[str, ...] = ()


@dataclass(frozen=True)
class SafeCommandFilterResult:
    safe_text: str
    removed_suggestions: list[str]
    replacement_commands: list[str]
    read_only: bool = True
    mutation_performed: bool = False


_ALLOWED_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_UNSAFE_SHELL_RE = re.compile(
    r"(?:\|\||&&|[;|`$\\]|\$\(|\n|\r|>>?|<\(|\bsh\s+-c\b|\bbash\s+-c\b)", re.I
)
_TOOL_RE = re.compile(r"\b(shellforgeai|sfai|docker)\b", re.IGNORECASE)
_WS_RE = re.compile(r"[ \t]+")
_NONSPACE_RE = re.compile(r"\S+")
_ARG_TOKEN_RE = re.compile(r"^(?:--?[A-Za-z0-9][\w-]*|<[A-Za-z0-9_-]+>|[A-Za-z0-9][\w./:=@-]*)$")

_CMD_STOPWORDS = frozenset(
    {
        "to",
        "and",
        "or",
        "then",
        "so",
        "for",
        "the",
        "a",
        "an",
        "if",
        "when",
        "please",
        "with",
        "that",
        "this",
        "your",
        "you",
        "it",
        "into",
        "on",
        "in",
        "of",
        "will",
        "can",
        "could",
        "should",
        "would",
        "run",
        "running",
        "use",
        "using",
        "try",
        "instead",
        "first",
        "next",
        "also",
        "but",
        "because",
        "while",
        "via",
        "per",
        "as",
        "is",
        "are",
        "be",
        "which",
        "what",
        "see",
        "check",
        "review",
        "from",
        "after",
        "before",
        "once",
        "here",
        "there",
        "now",
        "they",
        "we",
        "i",
        "do",
        "does",
    }
)

_DOCKER_MUTATION_VERBS = frozenset(
    {
        "prune",
        "rm",
        "rmi",
        "stop",
        "start",
        "restart",
        "kill",
        "pause",
        "unpause",
        "run",
        "create",
        "exec",
        "update",
        "rename",
        "commit",
        "build",
        "push",
        "load",
        "import",
        "tag",
    }
)
_DOCKER_MUTATION_NOUN_VERBS = {
    "image": frozenset({"rm", "rmi", "prune", "load", "import", "build", "push", "tag"}),
    "container": frozenset(
        {"rm", "prune", "stop", "kill", "start", "restart", "create", "run", "exec"}
    ),
    "volume": frozenset({"rm", "prune", "create"}),
    "network": frozenset({"rm", "prune", "create", "connect", "disconnect"}),
    "system": frozenset({"prune"}),
    "builder": frozenset({"prune"}),
    "compose": frozenset(
        {"up", "down", "restart", "stop", "start", "rm", "kill", "run", "build", "create"}
    ),
}

SAFE_COMMANDS: tuple[SafeCommand, ...] = (
    SafeCommand(
        "status",
        "shellforgeai status --json",
        "status",
        True,
        False,
        "Show read-only ShellForgeAI status.",
    ),
    SafeCommand(
        "doctor",
        "shellforgeai doctor --json",
        "doctor",
        True,
        False,
        "Run read-only environment doctor checks.",
    ),
    SafeCommand(
        "model_doctor",
        "shellforgeai model doctor --json",
        "model",
        True,
        False,
        "Check model provider configuration without inference.",
    ),
    SafeCommand(
        "ops_report",
        "shellforgeai ops report --json",
        "ops",
        True,
        False,
        "Build a read-only operator report.",
    ),
    SafeCommand(
        "ops_report_brief",
        "shellforgeai ops report --brief",
        "ops",
        True,
        False,
        "Build a concise read-only operator report.",
    ),
    SafeCommand(
        "ops_status",
        "shellforgeai ops status --json",
        "ops",
        True,
        False,
        "Show read-only ops status.",
    ),
    SafeCommand(
        "triage_docker",
        "shellforgeai triage docker --json",
        "docker_triage",
        True,
        False,
        "Run deterministic Docker triage.",
    ),
    SafeCommand(
        "triage_docker_detail",
        "shellforgeai triage docker detail <suspect> --json",
        "docker_triage",
        True,
        False,
        "Inspect deterministic triage evidence for one suspect.",
        placeholders=("suspect",),
    ),
    SafeCommand(
        "triage_docker_snapshot",
        "shellforgeai triage docker snapshot --json",
        "docker_triage",
        True,
        False,
        "Show read-only Docker triage snapshot.",
    ),
    SafeCommand(
        "triage_docker_timeline",
        "shellforgeai triage docker timeline --json",
        "docker_triage",
        True,
        False,
        "Show read-only Docker triage timeline.",
    ),
    SafeCommand(
        "propose_docker",
        "shellforgeai propose docker --json",
        "v2_preview",
        True,
        False,
        "Create/read a governed Docker proposal without applying it.",
    ),
    SafeCommand(
        "apply_preview_docker",
        "shellforgeai apply-preview docker --json",
        "v2_preview",
        True,
        False,
        "Preview a Docker apply path without applying it.",
    ),
    SafeCommand(
        "verify_docker",
        "shellforgeai verify docker --json",
        "v2_preview",
        True,
        False,
        "Run read-only Docker verification.",
    ),
    SafeCommand(
        "handoff_docker",
        "shellforgeai handoff docker --json",
        "v2_preview",
        True,
        False,
        "Prepare read-only Docker handoff guidance.",
    ),
)

_COMMAND_BY_ID = {entry.id: entry for entry in SAFE_COMMANDS}


def _safe_identifier(value: str | None) -> str | None:
    candidate = (value or "").strip()
    return candidate if _ALLOWED_IDENTIFIER_RE.fullmatch(candidate) else None


def _render(entry: SafeCommand, *, suspect: str | None = None) -> str | None:
    if "suspect" in entry.placeholders:
        safe = _safe_identifier(suspect)
        if not safe:
            return None
        return entry.command.replace("<suspect>", safe)
    return entry.command


def registered_safe_commands() -> tuple[SafeCommand, ...]:
    return SAFE_COMMANDS


def suggest_safe_next_command(topic: str | None = None, suspect: str | None = None) -> str:
    topic_l = (topic or "").lower()
    if topic_l in {"docker", "docker_triage"}:
        detail = _render(_COMMAND_BY_ID["triage_docker_detail"], suspect=suspect)
        return detail or _COMMAND_BY_ID["triage_docker"].command
    if topic_l in {"model", "auth"}:
        return _COMMAND_BY_ID["model_doctor"].command
    if topic_l in {"status"}:
        return _COMMAND_BY_ID["status"].command
    if topic_l in {"ops", "mutation_refusal"}:
        return _COMMAND_BY_ID["ops_report_brief"].command
    return _COMMAND_BY_ID["ops_report"].command


def _tokens(text: str, start: int) -> tuple[list[str], int]:
    tokens: list[str] = []
    pos = start
    last_end = start
    while len(tokens) < 10:
        ws = _WS_RE.match(text, pos)
        if not ws:
            break
        tm = _NONSPACE_RE.match(text, ws.end())
        if not tm:
            break
        raw = tm.group(0)
        core = raw.strip("`*_(),.;:!?\"'")
        if not core or core.lower() in _CMD_STOPWORDS or not _ARG_TOKEN_RE.match(core):
            break
        tokens.append(core)
        last_end = ws.end() + len(raw)
        pos = last_end
    return tokens, last_end


def _docker_mutation(tokens: list[str]) -> bool:
    nonflag = [t.lower() for t in tokens if not t.startswith("-")]
    if not nonflag:
        return False
    if nonflag[0] in _DOCKER_MUTATION_VERBS:
        return True
    verbs = _DOCKER_MUTATION_NOUN_VERBS.get(nonflag[0])
    return verbs is not None and len(nonflag) > 1 and nonflag[1] in verbs


def _matches_registry(tokens: list[str]) -> bool:
    if _UNSAFE_SHELL_RE.search(" ".join(tokens)):
        return False
    nonflag = [t for t in tokens if not t.startswith("-")]
    for entry in SAFE_COMMANDS:
        etokens = entry.command.split()[1:]
        enonflag = [t for t in etokens if not t.startswith("-")]
        if len(nonflag) != len(enonflag):
            continue
        ok = True
        for got, expected in zip(nonflag, enonflag, strict=True):
            if expected == "<suspect>":
                ok = _safe_identifier(got) is not None
            else:
                ok = got.lower() == expected.lower()
            if not ok:
                break
        if ok and set(t.lower() for t in tokens if t.startswith("-")) <= set(
            t.lower() for t in etokens if t.startswith("-")
        ):
            return True
    return False


def is_known_safe_shellforgeai_command(text: str) -> bool:
    candidate = " ".join((text or "").strip().split())
    if not candidate or _UNSAFE_SHELL_RE.search(candidate):
        return False
    parts = candidate.split()
    if not parts or parts[0].lower() not in {"shellforgeai", "sfai"}:
        return False
    return _matches_registry(parts[1:])


def _contains_only_safe_command(text: str) -> bool:
    candidate = (text or "").strip()
    if candidate.lower().startswith(("shellforgeai ", "sfai ")):
        return is_known_safe_shellforgeai_command(candidate)
    if candidate.lower().startswith("docker "):
        return not _docker_mutation(candidate.split()[1:]) and not _UNSAFE_SHELL_RE.search(
            candidate
        )
    return not _UNSAFE_SHELL_RE.search(candidate)


def filter_or_replace_unsafe_command_suggestions(
    text: str, topic: str | None = None, suspect: str | None = None
) -> SafeCommandFilterResult:
    if not text:
        return SafeCommandFilterResult(
            safe_text=text, removed_suggestions=[], replacement_commands=[]
        )
    fallback = suggest_safe_next_command(topic, suspect=suspect)
    spans: list[tuple[int, int, str, bool]] = []
    for m in _TOOL_RE.finditer(text):
        tool = m.group(1).lower()
        tokens, end = _tokens(text, m.end())
        if not tokens:
            continue
        original = text[m.start() : end]
        if tool == "docker":
            unsafe = _docker_mutation(tokens) or _UNSAFE_SHELL_RE.search(original) is not None
        else:
            unsafe = not is_known_safe_shellforgeai_command("shellforgeai " + " ".join(tokens))
        spans.append((m.start(), end, original, unsafe))
    if not spans:
        return SafeCommandFilterResult(
            safe_text=text, removed_suggestions=[], replacement_commands=[]
        )
    out: list[str] = []
    removed: list[str] = []
    replacements: list[str] = []
    cursor = 0
    for start, end, original, unsafe in sorted(spans, key=lambda s: s[0]):
        if start < cursor:
            continue
        out.append(text[cursor:start])
        if unsafe:
            cleaned = " ".join(original.split())
            removed.append(cleaned)
            if fallback:
                out.append(fallback)
                replacements.append(fallback)
            else:
                out.append("no supported safe command is available")
        else:
            out.append(original)
        cursor = end
    out.append(text[cursor:])
    return SafeCommandFilterResult(
        safe_text="".join(out),
        removed_suggestions=removed,
        replacement_commands=replacements,
    )
