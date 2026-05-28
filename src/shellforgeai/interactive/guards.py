from __future__ import annotations

import re

_SHELL_PREFIXES = (
    "sudo ",
    "docker ",
    "kubectl ",
    "systemctl ",
    "journalctl ",
    "apt ",
    "apt-get ",
    "dnf ",
    "yum ",
    "apk ",
    "pacman ",
    "rm ",
    "mv ",
    "cp ",
    "chmod ",
    "chown ",
    "cat ",
    "grep ",
    "find ",
    "sed ",
    "awk ",
    "tail ",
    "head ",
    "ps ",
    "ss ",
    "ip ",
    "nft ",
    "iptables ",
    "bash -lc",
    "sh -lc",
    "for ",
    "while ",
    "if ",
)


def _has_unmatched_quote(text: str, quote: str) -> bool:
    return text.count(quote) % 2 == 1


def is_multiline_shell_fragment(text: str) -> bool:
    raw = text.strip()
    if not raw:
        return False
    lowered = raw.lower()
    if raw.endswith("\\"):
        return True
    if _has_unmatched_quote(raw, "'") or _has_unmatched_quote(raw, '"'):
        return True
    if lowered in {"for", "if", "while", "do", "done", "then", "fi"}:
        return True
    return ("$(" in raw or "`" in raw) and any(
        x in lowered for x in ("for ", "do", "done", "ls", "find", "echo")
    )


def looks_like_shell_command(text: str) -> bool:
    raw = text.strip()
    if not raw:
        return False
    if is_multiline_shell_fragment(raw):
        return True
    lowered = raw.lower()
    if lowered.startswith(_SHELL_PREFIXES):
        return True
    return (
        " docker exec " in lowered or " docker compose " in lowered or is_shell_fragment_line(raw)
    )


def is_shell_fragment_line(text: str) -> bool:
    raw = text.strip()
    if not raw:
        return False
    lowered = raw.lower()
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", raw):
        return True
    if lowered.startswith("test "):
        return True
    if raw.startswith("[") and "]" in raw:
        return True
    if lowered in {"break", "then", "else", "fi", "do", "done", "esac"}:
        return True
    if lowered.startswith(("echo ", "printf ", "read ")):
        return True
    if "$(" in raw or "`" in raw:
        return True
    return any(op in raw for op in ("|", "||", "&&", ";", "2>/dev/null", ">/dev/null"))
