"""Interactive entrypoint helpers with lazy REPL import."""

from __future__ import annotations

from typing import Any


def start_interactive(*args: Any, **kwargs: Any) -> Any:
    """Start the interactive REPL without importing Unix-heavy collectors at CLI import time."""

    from .repl import start_interactive as _start_interactive

    return _start_interactive(*args, **kwargs)


__all__ = ["start_interactive"]
