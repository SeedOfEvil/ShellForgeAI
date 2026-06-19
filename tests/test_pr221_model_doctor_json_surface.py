import json

from typer.testing import CliRunner

import shellforgeai.cli as cli
from shellforgeai.cli import app

runner = CliRunner()


class Provider:
    def __init__(self, auth_readiness="unknown"):
        self.auth_readiness = auth_readiness
        self.complete_called = False

    def doctor(self):
        return {
            "provider": "openai-codex",
            "model": "gpt-5.5",
            "fallback_model": "gpt-5.4",
            "codex_found": True,
            "auth_cache_present": False,
            "auth_readiness": self.auth_readiness,
            "auth_reason": "login_required"
            if self.auth_readiness == "failed"
            else "status_unknown",
            "sandbox": "read-only",
            "approval": "never",
        }

    def complete(self, _request):  # pragma: no cover - failure path only
        raise AssertionError("model doctor must not call model completion")


def test_model_doctor_json_is_accepted_and_strict_json(monkeypatch):
    monkeypatch.setattr(cli, "build_provider", lambda _settings: Provider("unknown"))

    result = runner.invoke(app, ["model", "doctor", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["mode"] == "model_doctor"
    assert payload["status"] == "ok"
    assert payload["ok"] is True
    assert payload["auth_readiness"] == "unknown"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["model_called"] is False
    assert isinstance(payload["warnings"], list)
    assert payload["safety"]["read_only"] is True
    assert all(value is False for key, value in payload["safety"].items() if key != "read_only")


def test_model_doctor_help_exposes_json_option():
    result = runner.invoke(app, ["model", "doctor", "--help"])

    assert result.exit_code == 0
    assert "--json" in result.stdout


def test_model_doctor_json_structures_failed_or_unavailable_auth(monkeypatch):
    monkeypatch.setattr(cli, "build_provider", lambda _settings: Provider("failed"))

    result = runner.invoke(app, ["model", "doctor", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "warning"
    assert payload["ok"] is False
    assert payload["auth_readiness"] == "failed"
    assert payload["mutation_performed"] is False


def test_model_doctor_json_handles_provider_doctor_exception(monkeypatch):
    def boom(_settings):
        raise RuntimeError("codex auth unavailable")

    monkeypatch.setattr(cli, "build_provider", boom)

    result = runner.invoke(app, ["model", "doctor", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["auth_readiness"] == "unknown"
    assert payload["read_only"] is True
    assert payload["warnings"]
    assert "codex auth unavailable" in payload["warnings"][0]
