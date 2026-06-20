from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.llm.codex import CodexProvider

runner = CliRunner()


class FakeProvider:
    def __init__(self, info: dict[str, object]):
        self.info = info

    def doctor(self) -> dict[str, object]:
        return dict(self.info)

    def complete(self, _request):  # pragma: no cover - safety assertion
        raise AssertionError("default model doctor must not call model inference")


def _patch_provider(monkeypatch, info: dict[str, object]) -> None:
    import shellforgeai.cli as cli

    monkeypatch.setattr(cli, "build_provider", lambda _settings: FakeProvider(info))


def test_default_json_cache_present_is_not_verified_not_broken(monkeypatch) -> None:
    _patch_provider(
        monkeypatch,
        {
            "provider": "openai-codex",
            "model": "gpt-5.5",
            "codex_binary": "/usr/local/bin/codex",
            "codex_found": True,
            "codex_version": "codex-cli 0.135.0",
            "auth_cache_present": True,
            "auth_readiness": "not_verified",
            "auth_reason": "auth_cache_present_live_probe_not_run",
        },
    )

    result = runner.invoke(app, ["model", "doctor", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["model_called"] is False
    assert payload["live_probe_performed"] is False
    assert payload["live_probe_available"] is False
    assert payload["auth_cache_present"] is True
    assert payload["auth_readiness"] == "not_verified"
    assert payload["auth_reason"] == "auth_cache_present_live_probe_not_run"
    assert payload["warnings"] == []
    assert payload["safe_next_command"] == "shellforgeai model doctor --json"


def test_human_output_says_live_readiness_not_verified(monkeypatch) -> None:
    _patch_provider(
        monkeypatch,
        {
            "provider": "openai-codex",
            "model": "gpt-5.5",
            "auth_cache_present": True,
            "auth_readiness": "not_verified",
            "auth_reason": "auth_cache_present_live_probe_not_run",
        },
    )

    result = runner.invoke(app, ["model", "doctor"])

    assert result.exit_code == 0
    assert "Auth cache: present" in result.stdout
    assert "Live auth readiness: not verified" in result.stdout
    assert "Reason: default model doctor does not call the model" in result.stdout
    assert "Safe next step: shellforgeai model doctor --json" in result.stdout


def test_missing_binary_and_missing_auth_are_classified(monkeypatch) -> None:
    _patch_provider(
        monkeypatch,
        {
            "provider": "openai-codex",
            "model": "gpt-5.5",
            "codex_found": False,
            "codex_binary": "codex",
            "auth_cache_present": False,
            "auth_readiness": "missing_binary",
            "auth_reason": "codex_binary_missing",
        },
    )

    result = runner.invoke(app, ["model", "doctor", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "warning"
    assert payload["auth_readiness"] == "missing_binary"
    assert payload["auth_reason"] == "codex_binary_missing"
    assert "token" not in result.stdout.lower()
    assert "secret" not in result.stdout.lower()


def test_real_provider_local_semantics_without_network_or_model_call(
    monkeypatch, tmp_path: Path
) -> None:
    auth_dir = tmp_path / ".codex"
    auth_dir.mkdir()
    (auth_dir / "auth.json").write_text("{}")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr("shutil.which", lambda _binary: "/usr/local/bin/codex")

    def fake_run(cmd, **kwargs):
        assert cmd == ["codex", "--version"]
        assert kwargs.get("timeout") == 10

        class Result:
            stdout = "codex-cli 0.135.0\n"
            stderr = ""

        return Result()

    monkeypatch.setattr("subprocess.run", fake_run)

    info = CodexProvider(default_model="gpt-5.5").doctor()

    assert info["auth_cache_present"] is True
    assert info["auth_readiness"] == "not_verified"
    assert info["auth_reason"] == "auth_cache_present_live_probe_not_run"
    assert info["live_probe_performed"] is False
    assert info["model_called"] is False
