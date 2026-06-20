from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

import shellforgeai.cli as cli
from shellforgeai.cli import app
from shellforgeai.llm.schemas import ModelResponse

runner = CliRunner()


class FakeProvider:
    def __init__(self, *, auth_cache_present=True, response=None, exc=None):
        self.calls = []
        self.auth_cache_present = auth_cache_present
        self.response = response or ModelResponse(
            provider="fake", model="fake-model", text="ok", ok=True
        )
        self.exc = exc

    def doctor(self):
        return {
            "provider": "fake",
            "model": "fake-model",
            "auth_cache_present": self.auth_cache_present,
            "auth_readiness": "not_verified" if self.auth_cache_present else "missing_auth_cache",
            "auth_reason": "auth_cache_present_live_probe_not_run"
            if self.auth_cache_present
            else "auth_cache_missing",
        }

    def complete(self, request):
        self.calls.append(request)
        if self.exc:
            raise self.exc
        return self.response


def _install(monkeypatch, provider):
    monkeypatch.setattr(cli, "build_provider", lambda _settings: provider)
    return provider


def test_model_module_static_guard_tokens_absent():
    source = Path("src/shellforgeai/commands/model.py").read_text().lower()
    for token in (
        "shell=true",
        "subprocess.run",
        "subprocess.popen",
        "os.system",
        "docker restart",
        "docker compose",
        "compose restart",
        "production restart",
        "cleanup_execute",
        "execute_remediation",
        "execute_receipt_recovery(",
        "preview_receipt_rollback(",
        "run_exact_docker_restart(",
        "route_input(",
        "codex exec",
    ):
        assert token not in source


def _assert_read_only_safety(safety):
    assert safety["read_only"] is True
    for key, value in safety.items():
        if key != "read_only":
            assert value is False


def test_default_no_probe_json_and_human_do_not_call_model(monkeypatch):
    provider = _install(monkeypatch, FakeProvider())
    result = runner.invoke(app, ["model", "doctor", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["live_probe_requested"] is False
    assert payload["live_probe_performed"] is False
    assert payload["auth_readiness"] == "not_verified"
    assert payload["reason"] == "Live auth probe was not requested."
    assert payload["safety"]["model_call_performed"] is False
    _assert_read_only_safety(payload["safety"])
    assert provider.calls == []

    human = runner.invoke(app, ["model", "doctor"])
    assert human.exit_code == 0, human.output
    assert "Auth readiness: not verified" in human.stdout
    assert "Reason: live auth probe was not requested." in human.stdout
    assert "No model call was made." in human.stdout
    assert provider.calls == []


def test_live_probe_success_calls_once_and_suppresses_secrets(monkeypatch):
    provider = _install(
        monkeypatch,
        FakeProvider(
            response=ModelResponse(
                provider="fake",
                model="fake-model",
                text="ready",
                ok=True,
                metadata={"request_id": "req-1"},
            )
        ),
    )
    result = runner.invoke(app, ["model", "doctor", "--live-probe", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert len(provider.calls) == 1
    req = provider.calls[0]
    assert req.timeout_seconds == 10
    assert req.metadata["tools_allowed"] is False
    assert req.metadata["operator_prompt_included"] is False
    assert payload["auth_readiness"] == "verified"
    assert payload["probe"]["status"] == "passed"
    assert payload["safety"]["model_call_performed"] is True
    assert payload["safety"]["tools_executed"] is False
    assert all(
        value is False
        for key, value in payload["safety"].items()
        if key not in {"read_only", "model_call_performed", "model_called"}
    )
    assert "secret" not in result.stdout.lower()
    assert "token" not in result.stdout.lower()


def test_live_probe_missing_credentials_skips_without_model_call(monkeypatch):
    provider = _install(monkeypatch, FakeProvider(auth_cache_present=False))
    result = runner.invoke(app, ["model", "doctor", "--live-probe", "--json"])
    payload = json.loads(result.stdout)
    assert payload["auth_readiness"] == "not_configured"
    assert payload["probe"]["status"] == "skipped"
    assert provider.calls == []


def test_live_probe_failures_are_bounded(monkeypatch):
    for response in [
        ModelResponse(
            provider="fake",
            model="fake-model",
            text="",
            ok=False,
            error="unauthorized bearer SECRET_TOKEN",
        ),
        ModelResponse(
            provider="fake", model="fake-model", text="", ok=False, error="probe timed out"
        ),
        ModelResponse(
            provider="fake", model="fake-model", text="", ok=False, error="network unreachable"
        ),
    ]:
        provider = _install(monkeypatch, FakeProvider(response=response))
        result = runner.invoke(app, ["model", "doctor", "--live-probe", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert len(provider.calls) == 1
        assert payload["auth_readiness"] == "failed"
        assert payload["probe"]["status"] == "failed"
        assert "Traceback" not in result.stdout
        assert "SECRET_TOKEN" not in result.stdout
        assert "bearer" not in result.stdout.lower()


def test_live_probe_receipt_writes_bounded_files(monkeypatch, tmp_path: Path):
    _install(monkeypatch, FakeProvider())
    out_dir = tmp_path / "receipt"
    result = runner.invoke(app, ["model", "doctor", "--live-probe", "--receipt-out", str(out_dir)])
    assert result.exit_code == 0, result.output
    for name in [
        "model-doctor-live-probe.json",
        "model-doctor-live-probe-summary.md",
        "manifest.json",
        "checksums.json",
    ]:
        assert (out_dir / name).exists()
    payload = json.loads((out_dir / "model-doctor-live-probe.json").read_text())
    assert payload["live_probe_performed"] is True
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False
    assert payload["safety"]["tools_executed"] is False
    checksums = json.loads((out_dir / "checksums.json").read_text())
    for meta in checksums["files"].values():
        assert len(meta["sha256"]) == 64
        assert meta["size_bytes"] > 0
    summary = (out_dir / "model-doctor-live-probe-summary.md").read_text()
    assert "No tools were executed." in summary
    assert "No mutation was performed." in summary
    joined = "\n".join(path.read_text() for path in out_dir.iterdir())
    secret_markers = [
        "OPENAI_API_KEY",
        "Authorization:",
        "Bearer",
        "sk-",
        "ghp_",
        "BEGIN PRIVATE KEY",
    ]
    for marker in secret_markers:
        assert marker.lower() not in joined.lower()
    assert "token" not in joined.lower()
    assert "secret" not in joined.lower()


def test_probe_surface_rejects_freeform_and_unknown_flags_and_source_guardrails():
    prompt = runner.invoke(app, ["model", "doctor", "--live-probe", "operator prompt"])
    assert prompt.exit_code != 0
    unknown = runner.invoke(app, ["model", "doctor", "--probe-prompt", "hello"])
    assert unknown.exit_code != 0
    help_text = runner.invoke(app, ["model", "doctor", "--help"]).stdout
    assert "--live-probe" in help_text
    assert "--receipt-out" in help_text
    for forbidden in [
        "--execute",
        "--apply",
        "--cleanup",
        "--delete",
        "--prune",
        "--restart",
        "--fix",
        "--rm",
        "--rmi",
    ]:
        assert forbidden not in help_text
    source = Path("src/shellforgeai/commands/model.py").read_text()
    assert "shell=True" not in source
