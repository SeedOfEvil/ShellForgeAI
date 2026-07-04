from __future__ import annotations

import contextlib
import subprocess
from pathlib import Path

from shellforgeai.llm.codex import CodexProvider, _format_human_value
from shellforgeai.llm.schemas import ModelRequest


def _request() -> ModelRequest:
    return ModelRequest(prompt="hi", model="gpt-5.5", provider="openai-codex")


def _fake_popen(captured: dict, returncode: int = 0, stdout: str = "", stderr: str = ""):
    class FakePopen:
        def __init__(self, cmd, **kwargs):
            captured.setdefault("cmds", []).append(cmd)
            captured.setdefault("kwargs", []).append(kwargs)
            assert kwargs.get("shell") is not True
            assert "powershell" not in str(cmd).lower()
            self.returncode = returncode
            if "--output-last-message" in cmd:
                idx = cmd.index("--output-last-message")
                with contextlib.suppress(OSError):
                    Path(cmd[idx + 1]).write_text("ready")

        def communicate(self, timeout=None):
            return stdout, stderr

        def poll(self):
            return self.returncode

        def terminate(self):
            pass

        def kill(self):
            pass

    return FakePopen


def test_human_value_formatting_does_not_repr_escape_windows_paths():
    resolved = r"C:\Tools\ShellForgeAI\bin\codex.cmd"

    formatted = _format_human_value(resolved)

    assert formatted == f"'{resolved}'"
    assert "\\\\" not in formatted
    assert _format_human_value(None) == "'<unresolved>'"


def test_plain_codex_resolves_mixed_case_cmd_for_doctor_and_complete(monkeypatch, tmp_path):
    resolved = str(tmp_path / "codex.CMD")
    captured: dict = {"run_cmds": []}
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda binary: resolved)

    def fake_run(cmd, **kwargs):
        captured["run_cmds"].append(cmd)
        assert kwargs.get("shell") is not True
        assert "powershell" not in str(cmd).lower()
        return subprocess.CompletedProcess(cmd, 0, stdout="codex 0.130.0\n", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("subprocess.Popen", _fake_popen(captured))

    provider = CodexProvider(binary="codex")
    info = provider.doctor()
    response = provider.complete(_request())

    assert info["codex_binary"] == "codex"
    assert info["codex_resolved_binary"] == resolved
    assert captured["run_cmds"][0][0] == resolved
    assert captured["cmds"][0][0] == resolved
    assert response.ok


def test_configured_codex_cmd_and_absolute_path_work(monkeypatch, tmp_path):
    resolved_cmd = str(tmp_path / "codex.cmd")
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda binary: resolved_cmd)
    provider = CodexProvider(binary="codex.cmd")
    assert provider._build_cmd("hi", "gpt-5.5", None)[0] == resolved_cmd

    abs_cmd = tmp_path / "bin" / "codex.cmd"
    abs_cmd.parent.mkdir()
    abs_cmd.write_text("fake")

    def fail_which(binary):
        raise AssertionError("absolute usable paths should not need PATH lookup")

    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", fail_which)
    provider = CodexProvider(binary=str(abs_cmd))
    assert provider._build_cmd("hi", "gpt-5.5", None)[0] == str(abs_cmd)


def test_missing_binary_is_clean_and_does_not_attempt_subprocess(monkeypatch):
    calls = {"popen": 0}
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda binary: None)

    def fail_popen(*args, **kwargs):
        calls["popen"] += 1
        raise AssertionError("subprocess should not be attempted")

    monkeypatch.setattr("subprocess.Popen", fail_popen)
    response = CodexProvider(binary="codex").complete(_request())

    assert not response.ok
    assert "configured_binary='codex'" in (response.error or "")
    assert "resolved_binary='<unresolved>'" in (response.error or "")
    assert "shellforgeai model doctor --json" in (response.error or "")
    assert "Traceback" not in (response.error or "")
    assert calls["popen"] == 0


def test_filenotfound_and_oserror_from_launch_are_bounded(monkeypatch):
    resolved = (
        r"C:\Windows\Temp\pytest-of-WIN2025-SFAI01$"
        r"\pytest-0\test_filenotfound_and_oserror_0\codex.CMD"
    )
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda binary: resolved)

    for exc_type in (FileNotFoundError, OSError):

        def raising_popen(*args, _exc_type=exc_type, **kwargs):
            raise _exc_type("[WinError 2] The system cannot find the file specified")

        monkeypatch.setattr("subprocess.Popen", raising_popen)
        response = CodexProvider(binary="codex").complete(_request())
        error = response.error or ""
        expected_resolved = f"resolved_binary='{resolved}'"
        repr_style_resolved = expected_resolved.replace("\\", "\\\\")

        assert not response.ok
        assert f"reason={exc_type.__name__}" in error
        assert expected_resolved in error
        assert repr_style_resolved not in error
        assert "configured_binary='codex'" in error
        assert "shellforgeai model doctor --json" in error
        assert "Traceback" not in error
        assert "WinError 2" not in error


def test_doctor_version_oserror_is_bounded(monkeypatch, tmp_path):
    resolved = str(tmp_path / "codex.CMD")
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda binary: resolved)

    def raising_run(*args, **kwargs):
        raise FileNotFoundError("[WinError 2] The system cannot find the file specified")

    monkeypatch.setattr("subprocess.run", raising_run)
    info = CodexProvider(binary="codex").doctor()
    assert info["codex_found"] is True
    assert info["codex_resolved_binary"] == resolved
    assert info["codex_version"] == "unknown"


def test_linux_style_resolution_still_uses_shutil_which_path(monkeypatch, tmp_path):
    resolved = "/usr/local/bin/codex"
    captured: dict = {}
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda binary: resolved)
    monkeypatch.setattr("subprocess.Popen", _fake_popen(captured))

    response = CodexProvider(binary="codex").complete(_request())

    assert response.ok
    assert captured["cmds"][0][0] == resolved
    assert all(kwargs.get("shell") is not True for kwargs in captured["kwargs"])


def test_resolution_is_cached_between_doctor_and_complete(monkeypatch, tmp_path):
    first = str(tmp_path / "codex.CMD")
    second = str(tmp_path / "other.cmd")
    calls = {"which": 0, "run_cmds": []}
    captured: dict = {}

    def fake_which(binary):
        calls["which"] += 1
        return first if calls["which"] == 1 else second

    def fake_run(cmd, **kwargs):
        calls["run_cmds"].append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="codex 0.130.0\n", stderr="")

    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", fake_which)
    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("subprocess.Popen", _fake_popen(captured))

    provider = CodexProvider(binary="codex")
    info = provider.doctor()
    response = provider.complete(_request())

    assert info["codex_resolved_binary"] == first
    assert calls["run_cmds"][0][0] == first
    assert captured["cmds"][0][0] == first
    assert calls["which"] == 1
    assert response.ok


def test_missing_binary_doctor_does_not_launch_or_read_auth_cache_contents(monkeypatch):
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda binary: None)

    def fail_run(*args, **kwargs):
        raise AssertionError("doctor should not launch subprocess when binary is missing")

    def fail_read_text(self, *args, **kwargs):
        raise AssertionError("provider must not read auth-cache contents")

    monkeypatch.setattr("subprocess.run", fail_run)
    monkeypatch.setattr(Path, "read_text", fail_read_text)

    info = CodexProvider(binary="codex").doctor()

    assert info["codex_found"] is False
    assert info["auth_readiness"] == "missing_binary"
    assert info["codex_resolved_binary"] == ""
