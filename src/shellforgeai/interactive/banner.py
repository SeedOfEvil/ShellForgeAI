from __future__ import annotations

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


def build_banner(runtime, trusted: bool, chooser=random.choice) -> Panel:
    build = get_build_info()
    quote = chooser(QUOTES)
    body = (
        "[bold cyan]ShellForgeAI[/bold cyan]\n"
        "CLI-first AI Ops for Linux\n"
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
