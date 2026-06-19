from __future__ import annotations

import re

_ALLOWED_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_ALLOWED_PROFILE = {"quick", "standard", "full"}


def _safe_ident(value: str, *, field: str) -> str:
    candidate = (value or "").strip()
    if not _ALLOWED_TARGET.fullmatch(candidate):
        raise ValueError(f"unsafe {field}")
    return candidate


def triage_detail_command(target: str, *, json: bool = False) -> str:
    cmd = f"shellforgeai triage docker detail {_safe_ident(target, field='target')}"
    return f"{cmd} --json" if json else cmd


def remediation_eligibility_explain_command(target: str, *, json: bool = False) -> str:
    cmd = (
        "shellforgeai remediation eligibility --target "
        f"{_safe_ident(target, field='target')} --explain"
    )
    return f"{cmd} --json" if json else cmd


def remediation_self_test_command(*, profile: str = "standard", json: bool = False) -> str:
    if profile not in _ALLOWED_PROFILE:
        raise ValueError("unsupported profile")
    cmd = f"shellforgeai remediation self-test --profile {profile}"
    return f"{cmd} --json" if json else cmd


def triage_snapshot_command(*, include_details: bool = False, json: bool = False) -> str:
    cmd = "shellforgeai triage docker snapshot"
    if include_details:
        cmd += " --include-details"
    return f"{cmd} --json" if json else cmd


def triage_timeline_command(*, include_stable: bool = False, json: bool = False) -> str:
    cmd = "shellforgeai triage docker timeline"
    if include_stable:
        cmd += " --include-stable"
    return f"{cmd} --json" if json else cmd


def remediation_audit_latest_command(*, json: bool = True) -> str:
    cmd = "shellforgeai remediation audit --latest"
    return f"{cmd} --json" if json else cmd


def remediation_plan_command(target: str, scenario: str, *, json: bool = False) -> str:
    cmd = (
        "shellforgeai remediation plan --target "
        f"{_safe_ident(target, field='target')} --scenario "
        f"{_safe_ident(scenario, field='scenario')}"
    )
    return f"{cmd} --json" if json else cmd


# PR222 — ask-output safe-command suggestion guard.
#
# Model-backed ``ask`` answers must not suggest unsupported or mutation-style
# commands. This is a *tiny local allowlist* (not a full command registry) of
# the real, read-only, currently-supported ShellForgeAI command families that
# an ask answer may route to. Anything else (``shellforgeai diagnose
# <container>``, ``shellforgeai fix docker``, ``shellforgeai restart compose``,
# bare ``docker prune`` / ``docker image rm`` ...) is stripped from the final
# answer and reported, so the model can explain evidence but never invents a
# command surface. Read-only only: this function inspects/edits text, it never
# executes anything.

# Each tuple is the leading non-flag token signature of a supported read-only
# command. A suggested command is allowed when one of these signatures is a
# prefix of its leading tokens.
_ALLOWED_ASK_COMMAND_SIGNATURES: tuple[tuple[str, ...], ...] = (
    ("status",),
    ("doctor",),
    ("model", "doctor"),
    ("ops", "report"),
    ("ops", "status"),
    ("triage",),
    ("triage", "docker"),
    ("triage", "docker", "detail"),
    ("triage", "docker", "snapshot"),
    ("triage", "docker", "timeline"),
    ("propose",),
    ("propose", "docker"),
    ("apply-preview",),
    ("apply-preview", "docker"),
    ("verify",),
    ("verify", "docker"),
    ("handoff",),
    ("handoff", "docker"),
    ("remediation", "eligibility"),
    ("remediation", "self-test"),
    ("remediation", "audit"),
    ("safe-actions",),
    ("compose",),
    ("inspect",),
    ("self-test",),
    ("v1",),
)

# Docker subcommands (and ``docker <noun> <verb>`` pairs) that mutate state.
# A bare ``docker ...`` suggestion using any of these is stripped/replaced.
_DOCKER_MUTATION_VERBS: frozenset[str] = frozenset(
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
_DOCKER_MUTATION_NOUN_VERBS: dict[str, frozenset[str]] = {
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

# Connector / prose words that terminate a command token run so trailing
# sentence text ("... to investigate the issue") is not swallowed into a
# command span.
_CMD_STOPWORDS: frozenset[str] = frozenset(
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

_TOOL_RE = re.compile(r"\b(shellforgeai|sfai|docker)\b", re.IGNORECASE)
_WS_RE = re.compile(r"[ \t]+")
_NONSPACE_RE = re.compile(r"\S+")
_ARG_TOKEN_RE = re.compile(r"^(?:--?[A-Za-z0-9][\w-]*|<[A-Za-z0-9_-]+>|[A-Za-z0-9][\w./:=@-]*)$")

_UNSUPPORTED_REPLACEMENT = "a supported read-only ShellForgeAI command"


def _command_tokens(text: str, start: int) -> tuple[list[str], int]:
    """Collect command argument tokens starting at ``start``.

    Returns ``(tokens, end)`` where ``end`` is the offset just past the last
    consumed token. Token collection stops at the first stopword, non-arg-shaped
    token, newline, or after a safety bound.
    """
    tokens: list[str] = []
    pos = start
    last_end = start
    while len(tokens) < 8:
        ws = _WS_RE.match(text, pos)
        if not ws:
            break
        tstart = ws.end()
        tm = _NONSPACE_RE.match(text, tstart)
        if not tm:
            break
        raw_tok = tm.group(0)
        core = raw_tok.strip("`*_(),.;:!?\"'")
        if not core or core.lower() in _CMD_STOPWORDS or not _ARG_TOKEN_RE.match(core):
            break
        tokens.append(core)
        last_end = tstart + len(raw_tok)
        pos = last_end
    return tokens, last_end


def _is_docker_mutation(tokens: list[str]) -> bool:
    nonflag = [t for t in tokens if not t.startswith("-")]
    if not nonflag:
        return False
    first = nonflag[0].lower()
    if first in _DOCKER_MUTATION_VERBS:
        return True
    noun_verbs = _DOCKER_MUTATION_NOUN_VERBS.get(first)
    return noun_verbs is not None and len(nonflag) >= 2 and nonflag[1].lower() in noun_verbs


def _shellforgeai_allowed(tokens: list[str]) -> bool:
    sig = tuple(
        t.lower()
        for t in tokens
        if not t.startswith("-") and not (t.startswith("<") and t.endswith(">"))
    )[:3]
    if not sig:
        return False
    return any(sig[: len(allowed)] == allowed for allowed in _ALLOWED_ASK_COMMAND_SIGNATURES)


def filter_unsupported_command_suggestions(
    text: str, *, safe_next_command: str | None = None
) -> tuple[str, list[str]]:
    """Strip unsupported/mutation command suggestions from ask answer ``text``.

    Returns ``(cleaned_text, removed)`` where ``removed`` lists the original
    command strings that were stripped. Unsupported ``shellforgeai``/``sfai``
    commands and mutation-style bare ``docker`` commands are replaced with
    ``safe_next_command`` (a real supported read-only command) when provided,
    otherwise with a neutral phrase. Supported read-only command suggestions
    are preserved verbatim. Purely read-only and side-effect free.
    """
    if not text:
        return text, []

    replacement = (safe_next_command or "").strip() or _UNSUPPORTED_REPLACEMENT

    spans: list[tuple[int, int, str, bool]] = []  # (start, end, original, drop)
    for m in _TOOL_RE.finditer(text):
        tool = m.group(1).lower()
        tokens, end = _command_tokens(text, m.end())
        if not tokens:
            continue
        if tool == "docker":
            drop = _is_docker_mutation(tokens)
        else:  # shellforgeai / sfai
            drop = not _shellforgeai_allowed(tokens)
        spans.append((m.start(), end, text[m.start() : end], drop))

    if not spans:
        return text, []

    spans.sort(key=lambda s: s[0])
    out: list[str] = []
    removed: list[str] = []
    cursor = 0
    for start, end, original, drop in spans:
        if start < cursor:
            continue  # overlapped by a previously consumed command span
        out.append(text[cursor:start])
        if drop:
            removed.append(" ".join(original.split()))
            out.append(replacement)
        else:
            out.append(original)
        cursor = end
    out.append(text[cursor:])
    return "".join(out), removed
