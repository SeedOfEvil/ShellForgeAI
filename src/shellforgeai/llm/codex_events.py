from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CodexUsage:
    input_tokens: int | None = None
    cached_input_tokens: int | None = None
    output_tokens: int | None = None
    reasoning_output_tokens: int | None = None


@dataclass
class CodexEventParseResult:
    thread_id: str | None = None
    agent_messages: list[str] = field(default_factory=list)
    final_text: str = ""
    usage: CodexUsage = field(default_factory=CodexUsage)
    warnings: list[str] = field(default_factory=list)
    effective_model: str | None = None
    raw_events: list[dict[str, Any]] = field(default_factory=list)


def parse_codex_jsonl(raw_jsonl: str, keep_raw: bool = False) -> CodexEventParseResult:
    result = CodexEventParseResult()
    for idx, line in enumerate(raw_jsonl.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            result.warnings.append(f"malformed JSONL line {idx}")
            continue
        if keep_raw:
            result.raw_events.append(event)
        if not isinstance(event, dict):
            continue
        etype = event.get("type")
        explicit_model = event.get("effective_model")
        if isinstance(explicit_model, str) and explicit_model.strip():
            result.effective_model = explicit_model.strip()
        if etype == "thread.started":
            result.thread_id = event.get("thread_id")
        if etype == "item.completed":
            item = event.get("item", {})
            if isinstance(item, dict) and item.get("type") == "agent_message":
                text = item.get("text")
                if isinstance(text, str) and text.strip():
                    result.agent_messages.append(text.strip())
        if etype == "turn.completed":
            usage = event.get("usage", {})
            if isinstance(usage, dict):
                result.usage = CodexUsage(
                    input_tokens=usage.get("input_tokens"),
                    cached_input_tokens=usage.get("cached_input_tokens"),
                    output_tokens=usage.get("output_tokens"),
                    reasoning_output_tokens=usage.get("reasoning_output_tokens"),
                )
    if result.agent_messages:
        result.final_text = result.agent_messages[-1]
    return result
