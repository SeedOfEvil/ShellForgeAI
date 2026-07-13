from __future__ import annotations

import subprocess
from typing import Any

from shellforgeai.llm.codex import CodexProvider


def test_doctor_reports_codex_cli_version_stdout(monkeypatch: Any) -> None:
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda b: "/usr/bin/codex")

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args[0], 0, stdout="codex-cli 0.144.1\n", stderr="")

    monkeypatch.setattr("shellforgeai.llm.codex.subprocess.run", fake_run)
    info = CodexProvider().doctor()
    assert info["codex_cli_version"] == "codex-cli 0.144.1"
    assert info["codex_resolved_binary"] == "/usr/bin/codex"
