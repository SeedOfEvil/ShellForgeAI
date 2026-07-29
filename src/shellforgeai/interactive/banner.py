from __future__ import annotations

import platform
import random
from pathlib import Path

from rich.panel import Panel

from shellforgeai.version import get_build_info

QUOTES = [
    "CLI just do it.",
    "Read-only today, root cause tomorrow.",
    "In logs we trust.",
    "No YAML was harmed in the making of this diagnosis.",
    "sudo? Not without a plan.",
    "Grep first, panic later.",
    "Your shell has entered the chat.",
    "Trust, but verify with journalctl.",
    "Works on my container.",
    "The prompt is mightier than the outage.",
]

# Platform-neutral subset of QUOTES (same relative order) for hosts that are not
# Linux. Linux-only banner language (journalctl/sudo/grep/container) must never
# be shown on a Windows or macOS banner.
NEUTRAL_QUOTES = [
    "CLI just do it.",
    "Read-only today, root cause tomorrow.",
    "In logs we trust.",
    "No YAML was harmed in the making of this diagnosis.",
    "Your shell has entered the chat.",
    "The prompt is mightier than the outage.",
]

PLATFORM_LABELS = {
    "linux": "Linux",
    "windows": "Windows",
    "darwin": "macOS",
}

GENERIC_PLATFORM_LABEL = "this host"


def _normalize_host_system(host_system: str | None) -> str:
    """Normalize a local platform identity to a recognized key.

    ``host_system`` is a test/injection seam only. In production it is ``None``
    and the local read-only ``platform.system()`` value is used. An empty or
    unrecognized value normalizes to ``""``.
    """
    raw = platform.system() if host_system is None else host_system
    key = (raw or "").strip().lower()
    return key if key in PLATFORM_LABELS else ""


def platform_label(host_system: str | None = None) -> str:
    """Return the banner platform label for the local host."""
    return PLATFORM_LABELS.get(_normalize_host_system(host_system), GENERIC_PLATFORM_LABEL)


def quotes_for_platform(host_system: str | None = None) -> list[str]:
    """Return the banner quote pool that is safe for the local host."""
    return QUOTES if _normalize_host_system(host_system) == "linux" else NEUTRAL_QUOTES


def build_banner(
    runtime,
    trusted: bool,
    chooser=random.choice,
    *,
    host_system: str | None = None,
) -> Panel:
    build = get_build_info()
    key = _normalize_host_system(host_system)
    label = PLATFORM_LABELS.get(key, GENERIC_PLATFORM_LABEL)
    quote = chooser(QUOTES if key == "linux" else NEUTRAL_QUOTES)
    body = (
        "[bold cyan]ShellForgeAI[/bold cyan]\n"
        f"CLI-first AI Ops for {label}\n"
        f"Version: {build.display_version}\n"
        f"Mode/Profile: {runtime.session.mode}/{runtime.profile.name}\n"
        f"Model: {runtime.settings.model.provider}/{runtime.settings.model.model}\n"
        f"Workspace: {Path.cwd()}\n"
        f"Trust status: {'trusted' if trusted else 'untrusted'}\n"
        f"Quote: {quote}"
    )
    if build.build_line():
        body += f"\n{build.build_line()}"
    return Panel.fit(body)
