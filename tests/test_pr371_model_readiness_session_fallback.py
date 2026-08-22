from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from shellforgeai.core.model_session import complete_for_session
from shellforgeai.llm.codex import CodexProvider, classify_model_failure
from shellforgeai.llm.codex_events import parse_codex_jsonl
from shellforgeai.llm.schemas import ModelRequest, ModelResponse


def _request(**metadata) -> ModelRequest:
    return ModelRequest(
        prompt="bounded evidence",
        model="configured-model",
        provider="openai-codex",
        timeout_seconds=3,
        metadata=metadata,
    )


def test_default_doctor_checks_login_once_without_inference(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda _: "/bin/codex")
    monkeypatch.setattr("shellforgeai.llm.codex.Path.home", lambda: tmp_path)

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[-1] == "--version":
            return SimpleNamespace(returncode=0, stdout="codex 1", stderr="")
        assert argv == ["/bin/codex", "login", "status"]
        assert kwargs["timeout"] == 30
        return SimpleNamespace(returncode=0, stdout="Logged in using ChatGPT", stderr="")

    monkeypatch.setattr("shellforgeai.llm.codex.subprocess.run", run)
    provider = CodexProvider()
    monkeypatch.setattr(provider, "complete", lambda _: pytest.fail("inference called"))
    info = provider.doctor()
    assert sum(argv[-2:] == ["login", "status"] for argv, _ in calls) == 1
    assert info["auth_readiness"] == "verified_login_status"
    assert info["login_status_ok"] is True
    assert info["auth_cache_contents_inspected"] is False


def test_cache_presence_cannot_prove_readiness(monkeypatch, tmp_path):
    cache = tmp_path / ".codex" / "auth.json"
    cache.parent.mkdir()
    cache.touch()
    monkeypatch.setattr("shellforgeai.llm.codex.Path.home", lambda: tmp_path)
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda _: "/bin/codex")
    monkeypatch.setattr(
        "shellforgeai.llm.codex.subprocess.run",
        lambda argv, **_: SimpleNamespace(
            returncode=0 if argv[-1] == "--version" else 1, stdout="codex 1", stderr=""
        ),
    )
    info = CodexProvider().doctor()
    assert info["auth_cache_present"] is True
    assert info["auth_readiness"] == "login_status_not_proven"


@pytest.mark.parametrize(
    "message, eligible",
    [
        ("model is not available", True),
        ("authentication failed for model request", False),
        ("not inside a trusted directory", False),
        ("unexpected argument --model", False),
        ("input is not valid UTF-8", False),
        ("request timed out", False),
    ],
)
def test_fallback_eligibility_is_classification_driven(message, eligible):
    result = classify_model_failure("", message, returncode=1)
    assert (result.get("fallback_eligible") is True) is eligible


def test_one_eligible_fallback_and_truthful_identity(monkeypatch):
    provider = CodexProvider(default_model="configured-model", fallback_model="fallback-model")
    monkeypatch.setattr(provider, "_resolve_binary", lambda: "/bin/codex")
    attempts = []

    def run(prompt, model, timeout, lifecycle):
        attempts.append(model)
        if len(attempts) == 1:
            return 1, "", "model is not available", None, ["codex"], {}
        return 0, '{"type":"turn.completed","usage":{}}', "", "answer", ["codex"], {}

    monkeypatch.setattr(provider, "_run", run)
    response = provider.complete(_request())
    assert response.ok is True
    assert attempts == ["configured-model", "fallback-model"]
    assert response.model == "fallback-model"
    assert response.metadata["configured_model"] == "configured-model"
    assert response.metadata["requested_model"] == "configured-model"
    assert response.metadata["response_reported_model"] == "fallback-model"
    assert response.metadata["provider_attempt_count"] == 2
    assert response.metadata["effective_model"] is None
    assert response.metadata["effective_model_observed"] is False


def test_live_probe_metadata_disables_fallback(monkeypatch):
    provider = CodexProvider(default_model="configured-model", fallback_model="fallback-model")
    monkeypatch.setattr(provider, "_resolve_binary", lambda: "/bin/codex")
    attempts = []
    monkeypatch.setattr(
        provider,
        "_run",
        lambda prompt, model, timeout, lifecycle: (
            attempts.append(model) or 1,
            "",
            "model unavailable",
            None,
            ["codex"],
            {},
        ),
    )
    response = provider.complete(_request(disable_fallback=True, tools_allowed=False))
    assert response.ok is False
    assert attempts == ["configured-model"]


def test_fallback_timeout_stops_at_two_and_reports_owned_cleanup(monkeypatch):
    provider = CodexProvider(default_model="configured-model", fallback_model="fallback-model")
    monkeypatch.setattr(provider, "_resolve_binary", lambda: "/bin/codex")
    attempts = []

    def run(prompt, model, timeout, lifecycle):
        attempts.append(model)
        if len(attempts) == 1:
            return 1, "", "model unavailable", None, ["codex"], {}
        exc = subprocess.TimeoutExpired(["codex"], timeout)
        exc.child_cleanup_performed = True
        raise exc

    monkeypatch.setattr(provider, "_run", run)
    response = provider.complete(_request())
    assert response.ok is False
    assert attempts == ["configured-model", "fallback-model"]
    assert response.metadata["provider_attempt_count"] == 2
    assert response.metadata["codex_child_cleanup_performed"] is True


def test_effective_model_only_from_explicit_structured_field():
    absent = parse_codex_jsonl('{"type":"thread.started","thread_id":"gpt-claimed"}')
    present = parse_codex_jsonl('{"type":"turn.completed","effective_model":"backend-model"}')
    assert absent.effective_model is None
    assert present.effective_model == "backend-model"


def test_terminal_failure_suppresses_only_same_session():
    class Provider:
        calls = 0

        def complete(self, request):
            self.calls += 1
            return ModelResponse(
                provider=request.provider,
                model=request.model,
                text="",
                ok=False,
                error="timeout",
                metadata={"codex_exec_error_class": "timeout", "provider_attempt_count": 1},
            )

    provider = Provider()
    first_session = SimpleNamespace(provider_failure=None)
    first = complete_for_session(first_session, provider, _request())
    second = complete_for_session(first_session, provider, _request())
    assert first.ok is False and provider.calls == 1
    assert second.metadata["provider_call_suppressed"] is True
    assert "suppressed for this session" in second.error
    assert provider.calls == 1
    assert set(first_session.provider_failure) == {"category", "attempt_count", "suppressed"}

    new_session = SimpleNamespace(provider_failure=None)
    complete_for_session(new_session, provider, _request())
    assert provider.calls == 2
