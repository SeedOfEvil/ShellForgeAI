from __future__ import annotations

import json
from pathlib import Path

from .base import ToolResult


def recent(limit: int = 10) -> ToolResult:
    base = Path("/data/sessions")
    if not base.exists():
        return ToolResult(
            tool="audit.recent", ok=False, exit_code=1, stderr="no recent audit trend available"
        )
    sessions = sorted([p.name for p in base.iterdir() if p.is_dir()], reverse=True)[:limit]
    return ToolResult(
        tool="audit.recent",
        stdout=json.dumps({"sessions": sessions}),
        stderr=f"recent={len(sessions)} sessions",
        ok=True,
    )
