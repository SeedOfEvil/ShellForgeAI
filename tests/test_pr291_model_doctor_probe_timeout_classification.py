"""PR291 fix: model-doctor live-probe timeout classification tests.

Fake provider fixtures only: no network, no real model calls, no auth-cache
reads. A bounded model-response timeout is a live-probe outcome — when Codex
login was already proven (``login_status_ok``) and CODEX_HOME is configured,
auth readiness must stay verified instead of degrading to ``failed`` /
``missing_auth_cache`` / ``not_configured``. The warning is expressed through
the probe fields (``live_probe_timed_out``, ``model_probe_timeout``) and the
overall doctor status.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

import shellforgeai.cli as cli
from shellforgeai.cli import app
from shellforgeai.llm.schemas import ModelResponse

runner = CliRunner()

TIMEOUT_ERROR = "codex timed out after 60s (bounded timeout; no indefinite wait)"


class FakeProvider:
    def __init__(self, *, doctor: dict, response: ModelResponse | None = None, exc=None) -> None:
        self.calls: list[object] = []
        self._doctor = doctor
        self.response = response
        self.exc = exc

    def doctor(self) -> dict:
        return dict(self._doctor)

    def complete(self, request) -> ModelResponse:
        self.calls.append(request)
        if self.exc is not None:
            raise self.exc
        assert self.response is not None
        return self.response


def _proven_login_doctor() -> dict:
    return {
        "provider": "openai-codex",
        "model": "gpt-5.5",
        "auth_cache_present": False,
        "auth_cache_contents_inspected": False,
        "codex_home_configured": True,
        "login_status_checked": True,
        "login_status_ok": True,
        "login_status_source": "codex_login_status",
        "auth_readiness": "verified_login_status",
        "auth_reason": "codex_login_status_ok",
        "sandbox": "read-only",
        "sandbox_mode": "read-only",
        "skip_git_repo_check_used": True,
    }


def _timeout_response() -> ModelResponse:
    return ModelResponse(
        provider="openai-codex",
        model="gpt-5.5",
        text="",
        ok=False,
        error=TIMEOUT_ERROR,
        metadata={
            "codex_exec_timed_out": True,
            "codex_exec_error_class": "timeout",
            "model_response_captured": False,
            "sandbox_mode": "read-only",
            "skip_git_repo_check_used": True,
        },
    )


def _invoke(monkeypatch, provider: FakeProvider) -> dict:
    monkeypatch.setattr(cli, "build_provider", lambda _settings: provider)
    result = runner.invoke(app, ["model", "doctor", "--live-probe", "--json"])
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


def test_probe_timeout_with_proven_login_keeps_auth_ready(monkeypatch) -> None:
    payload = _invoke(
        monkeypatch, FakeProvider(doctor=_proven_login_doctor(), response=_timeout_response())
    )
    # Auth/configuration readiness stays proven — the timeout is a probe
    # outcome, not an authentication failure.
    assert payload["auth_readiness"] == "verified_login_status"
    assert payload["auth_verification_status"] == "verified_login_status"
    assert payload["login_status_checked"] is True
    assert payload["login_status_ok"] is True
    assert payload["codex_home_configured"] is True
    assert payload["auth_cache_contents_inspected"] is False
    assert payload["auth_readiness"] not in {"failed", "missing_auth_cache", "not_configured"}
    # The probe outcome carries the timeout, explicitly classified.
    assert payload["live_probe_requested"] is True
    assert payload["model_call_attempted"] is True
    assert payload["live_probe_completed"] is False
    assert payload["live_probe_timed_out"] is True
    assert payload["live_probe_error_class"] == "model_probe_timeout"
    assert payload["live_probe_status"] == "failed"
    assert payload["model_response_captured"] is False
    assert payload["probe"]["error_class"] == "model_probe_timeout"
    assert payload["probe"]["model_response_captured"] is False
    # Overall doctor is a warning, never an auth-failure claim.
    assert payload["status"] == "warning"
    assert payload["ok"] is False
    assert payload["auth_reason"] == "live_probe_timed_out"


def test_provider_timeout_exception_with_proven_login_keeps_auth_ready(monkeypatch) -> None:
    payload = _invoke(
        monkeypatch,
        FakeProvider(doctor=_proven_login_doctor(), exc=TimeoutError("probe timed out")),
    )
    assert payload["auth_readiness"] == "verified_login_status"
    assert payload["live_probe_timed_out"] is True
    assert payload["live_probe_error_class"] == "model_probe_timeout"
    assert payload["probe"]["error_class"] == "model_probe_timeout"
    assert payload["status"] == "warning"


def test_probe_timeout_without_proven_login_still_reports_failed(monkeypatch) -> None:
    doctor = _proven_login_doctor()
    doctor.update(
        {
            "login_status_ok": False,
            "login_status_checked": False,
            "codex_home_configured": False,
            "auth_cache_present": True,
            "auth_readiness": "not_verified",
            "auth_reason": "auth_cache_present_live_probe_not_run",
        }
    )
    payload = _invoke(monkeypatch, FakeProvider(doctor=doctor, response=_timeout_response()))
    # Without proven login a timeout proves nothing about auth either way;
    # the pre-existing conservative classification is kept.
    assert payload["auth_readiness"] == "failed"
    assert payload["live_probe_timed_out"] is True
    assert payload["live_probe_error_class"] == "model_probe_timeout"


def test_non_timeout_auth_failure_still_downgrades_readiness(monkeypatch) -> None:
    response = ModelResponse(
        provider="openai-codex",
        model="gpt-5.5",
        text="",
        ok=False,
        error="codex auth failed; run: codex login --device-auth",
        metadata={"codex_exec_error_class": "auth", "codex_exec_timed_out": False},
    )
    payload = _invoke(monkeypatch, FakeProvider(doctor=_proven_login_doctor(), response=response))
    assert payload["auth_readiness"] == "failed"
    assert payload["live_probe_timed_out"] is False
    assert payload["probe"]["error_class"] == "auth"


def test_successful_probe_reports_captured_response_and_ok(monkeypatch) -> None:
    response = ModelResponse(
        provider="openai-codex",
        model="gpt-5.5",
        text="SFAI_MODEL_DOCTOR_READY",
        ok=True,
        metadata={
            "model_response_captured": True,
            "model_response_nonempty": True,
            "sandbox_mode": "read-only",
            "skip_git_repo_check_used": True,
        },
    )
    payload = _invoke(monkeypatch, FakeProvider(doctor=_proven_login_doctor(), response=response))
    assert payload["ok"] is True
    assert payload["status"] == "ok"
    assert payload["auth_readiness"] == "verified"
    assert payload["live_probe_performed"] is True
    assert payload["live_probe_completed"] is True
    assert payload["live_probe_status"] == "passed"
    assert payload["live_probe_timed_out"] is False
    assert payload["model_called"] is True
    assert payload["model_response_captured"] is True
    assert payload["probe"]["status"] == "passed"
    assert payload["probe"]["model_response_captured"] is True


def test_probe_status_stays_in_receipt_validator_allowed_set(monkeypatch) -> None:
    from shellforgeai.core.model_receipt_validation import ALLOWED_PROBE_STATUSES

    for provider in (
        FakeProvider(doctor=_proven_login_doctor(), response=_timeout_response()),
        FakeProvider(
            doctor=_proven_login_doctor(),
            response=ModelResponse(provider="openai-codex", model="gpt-5.5", text="ready", ok=True),
        ),
    ):
        payload = _invoke(monkeypatch, provider)
        assert payload["probe"]["status"] in ALLOWED_PROBE_STATUSES
