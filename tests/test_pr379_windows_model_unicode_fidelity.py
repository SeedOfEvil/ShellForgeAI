"""PR379 diagnostic contract for native-Windows model-response Unicode.

These repository-local tests pin each ShellForgeAI-owned seam.  The fake
Codex process writes the same UTF-8 bytes as ``--output-last-message``; no
repair, normalization, real provider call, or auth-cache access is involved.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai import cli as cli_module
from shellforgeai.cli import app
from shellforgeai.core.evidence_first_response import render_model_assessment
from shellforgeai.llm.codex import CodexProvider
from shellforgeai.llm.codex_events import parse_codex_jsonl
from shellforgeai.llm.schemas import ModelRequest

UNICODE_TEXT = "server’s expected virtualization tooling — “memory” — análisis — 확인"
MOJIBAKE = "serverÃ¢â¬â¢s"


class _Utf8CapturePopen:
    """Write an exact deterministic final-response artifact like Codex CLI."""

    artifact_bytes: bytes = b""

    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        self.returncode = 0
        for index, token in enumerate(cmd):
            if token == "--output-last-message":
                path = Path(cmd[index + 1])
                self.artifact_bytes = UNICODE_TEXT.encode("utf-8")
                type(self).artifact_bytes = self.artifact_bytes
                path.write_bytes(self.artifact_bytes)

    def communicate(self, input: Any = None, timeout: Any = None) -> tuple[str, str]:
        return json.dumps(
            {"type": "item.completed", "item": {"type": "agent_message", "text": UNICODE_TEXT}},
            ensure_ascii=False,
        ) + "\n", ""

    def poll(self) -> int:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


def _assert_exact_unicode(text: str) -> None:
    assert text == UNICODE_TEXT
    assert "’" in text
    assert MOJIBAKE not in text
    assert "�" not in text


def test_utf8_artifact_read_jsonl_and_model_response_preserve_exact_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Pin stages A-D: artifact bytes, decode, JSONL parse, and response."""
    artifact = tmp_path / "last-message.txt"
    artifact.write_bytes(UNICODE_TEXT.encode("utf-8"))
    assert artifact.read_bytes() == UNICODE_TEXT.encode("utf-8")
    _assert_exact_unicode(CodexProvider._read_last_message(artifact) or "")

    raw_jsonl = json.dumps(
        {"type": "item.completed", "item": {"type": "agent_message", "text": UNICODE_TEXT}},
        ensure_ascii=False,
    )
    _assert_exact_unicode(parse_codex_jsonl(raw_jsonl).final_text)

    monkeypatch.setattr("subprocess.Popen", _Utf8CapturePopen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: True)
    response = CodexProvider(allow_fallback=False).complete(
        ModelRequest(prompt="bounded prompt", model="gpt-5.5", provider="openai-codex")
    )

    assert _Utf8CapturePopen.artifact_bytes == UNICODE_TEXT.encode("utf-8")
    assert response.ok
    _assert_exact_unicode(response.text)
    _assert_exact_unicode(str(response.metadata["model_response_excerpt"]))
    assert response.metadata["output_file_encoding"] == "utf-8"
    assert response.metadata["sandbox_mode"] == "read-only"
    assert response.metadata["approval_policy"] == "never"


@pytest.mark.parametrize("text", [UNICODE_TEXT, "plain ASCII response"])
def test_immediate_model_assessment_does_not_recode(text: str) -> None:
    """Pin stage E without making the deterministic UI CP1252-dependent."""
    rendered = render_model_assessment(text)
    assert text in rendered
    assert MOJIBAKE not in rendered
    assert "�" not in rendered


def test_native_windows_ask_stdout_preserves_exact_model_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Pin stage F at the maintained native-Windows ``ask`` renderer."""
    packet = {
        "platform": "windows",
        "visibility": "windows-local-read-only",
        "read_only": True,
        "mutation_performed": False,
        "host": {},
        "platform_detail": {},
        "memory": {"available": False},
        "disk": {"available": False},
        "processes": {"available": False},
        "services": {"available": False},
        "events": {"available": False},
        "network": {"available": False},
        "volumes": {"available": False},
        "limitations": ["bounded"],
        "evidence_gaps": [],
        "safe_next_commands": [],
    }
    provider = SimpleNamespace(
        complete=lambda _request: SimpleNamespace(
            ok=True,
            text=UNICODE_TEXT,
            provider="test-provider",
            model="test-model",
            raw={},
            error=None,
            usage=None,
        )
    )
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "shellforgeai.core.windows_evidence_context.build_windows_evidence_context",
        lambda: packet,
    )
    monkeypatch.setattr(cli_module, "build_provider", lambda *_args: provider)

    result = CliRunner().invoke(app, ["ask", "Which running items deserve attention and why?"])

    assert result.exit_code == 0, result.stdout
    assert UNICODE_TEXT in result.stdout
    assert "Intent: Windows running-system inventory" in result.stdout
    assert MOJIBAKE not in result.stdout
    assert "�" not in result.stdout
    assert packet["read_only"] is True
    assert packet["mutation_performed"] is False


def test_linux_provider_pipeline_preserves_unicode_and_ascii(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The shared provider has no Windows-only recoding and leaves ASCII alone."""
    monkeypatch.setattr("subprocess.Popen", _Utf8CapturePopen)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr("shellforgeai.llm.codex._prompt_via_stdin", lambda: False)
    monkeypatch.setattr("shellforgeai.llm.codex._windows_codex_lane", lambda: False)

    response = CodexProvider(allow_fallback=False).complete(
        ModelRequest(prompt="ASCII prompt", model="gpt-5.5", provider="openai-codex")
    )

    _assert_exact_unicode(response.text)
    assert render_model_assessment("plain ASCII response").endswith("plain ASCII response")
