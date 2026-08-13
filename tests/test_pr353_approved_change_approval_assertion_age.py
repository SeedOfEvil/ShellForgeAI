"""Focused tests for exact persisted approval-assertion chronology."""

from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from shellforgeai.core import approved_change_approval_assertion_age as age

ARTIFACT_ID = "aca_" + "a" * 64
ARTIFACT_SHA = "a" * 64
SUBJECT_SHA = "b" * 64
ASSERTED = datetime(2026, 8, 13, 12, 0, 0, 123456, tzinfo=UTC)


def loaded(*, asserted=ASSERTED, artifact_id=ARTIFACT_ID, identity=ARTIFACT_SHA):
    approval = SimpleNamespace(approved_at=asserted, approved_by="must-not-leak")
    artifact = SimpleNamespace(contract=SimpleNamespace(approval=approval))
    return SimpleNamespace(
        status="persisted_approval_artifact_loaded",
        artifact=artifact,
        approval_artifact_id=artifact_id,
        approval_artifact_identity_sha256=identity,
        subject_sha256=SUBJECT_SHA,
        errors=(),
    )


def evaluate(monkeypatch, reference, **loader_kwargs):
    calls = []
    monkeypatch.setattr(
        age,
        "load_persisted_approved_change_approval_artifact",
        lambda artifact_id, *, data_dir: (
            calls.append(("load", artifact_id, data_dir)) or loaded(**loader_kwargs)
        ),
    )
    monkeypatch.setattr(age, "_utc_now", lambda: calls.append(("clock",)) or reference)
    result = age.measure_persisted_approval_assertion_age(
        ARTIFACT_ID,
        data_dir=Path("/not-accessed-by-mock"),
        confirm_approval_artifact_identity_sha256=ARTIFACT_SHA,
    )
    return result, calls


@pytest.mark.parametrize(
    ("artifact_id", "confirmation"),
    [
        ("aca_bad", ARTIFACT_SHA),
        ("ACA_" + "a" * 64, ARTIFACT_SHA),
        (ARTIFACT_ID, "A" * 64),
        (ARTIFACT_ID, "a" * 63),
    ],
)
def test_malformed_pure_inputs_never_load_or_read_clock(monkeypatch, artifact_id, confirmation):
    monkeypatch.setattr(
        age,
        "load_persisted_approved_change_approval_artifact",
        lambda *args, **kwargs: pytest.fail("loader called"),
    )
    monkeypatch.setattr(age, "_utc_now", lambda: pytest.fail("clock read"))
    result = age.measure_persisted_approval_assertion_age(
        artifact_id,
        data_dir="relative-is-loader-owned",
        confirm_approval_artifact_identity_sha256=confirmation,
    )
    assert result.status == "invalid_approval_assertion_age_input"
    assert not result.approval_artifact_load_evaluated


@pytest.mark.parametrize(
    "load_result",
    [
        SimpleNamespace(
            status="persisted_approval_artifact_not_found", artifact=None, errors=("missing",)
        ),
        SimpleNamespace(
            status="persisted_approval_artifact_invalid", artifact=None, errors=("tampered",)
        ),
    ],
)
def test_missing_or_invalid_exact_artifact_fails_before_clock(monkeypatch, load_result):
    monkeypatch.setattr(
        age, "load_persisted_approved_change_approval_artifact", lambda *a, **k: load_result
    )
    monkeypatch.setattr(age, "_utc_now", lambda: pytest.fail("clock read"))
    result = age.measure_persisted_approval_assertion_age(
        ARTIFACT_ID, data_dir="x", confirm_approval_artifact_identity_sha256=ARTIFACT_SHA
    )
    assert result.status == "approval_artifact_not_available"
    assert result.approval_artifact_load_evaluated and not result.approval_artifact_loaded


@pytest.mark.parametrize(
    "loader_kwargs", [{"artifact_id": "aca_" + "c" * 64}, {"identity": "c" * 64}]
)
def test_loaded_id_and_constant_time_identity_confirmation_precede_clock(
    monkeypatch, loader_kwargs
):
    result, calls = evaluate(monkeypatch, ASSERTED, **loader_kwargs)
    assert result.status == "approval_artifact_confirmation_mismatch"
    assert calls == [("load", ARTIFACT_ID, Path("/not-accessed-by-mock"))]
    assert not result.approval_artifact_identity_confirmed


def test_timestamp_comes_only_from_loaded_model_and_clock_is_read_once_after_loader(monkeypatch):
    reference = ASSERTED + timedelta(seconds=2)
    result, calls = evaluate(monkeypatch, reference)
    assert calls == [
        ("load", ARTIFACT_ID, Path("/not-accessed-by-mock")),
        ("clock",),
    ]
    assert result.approval_asserted_at_utc == "2026-08-13T12:00:00.123456Z"
    assert (
        "approved_at"
        not in inspect.signature(age.measure_persisted_approval_assertion_age).parameters
    )


def test_naive_loaded_assertion_fails_before_clock(monkeypatch):
    result, calls = evaluate(
        monkeypatch, ASSERTED.replace(tzinfo=None), asserted=ASSERTED.replace(tzinfo=None)
    )
    assert result.status == "approval_assertion_time_invalid"
    assert calls == [("load", ARTIFACT_ID, Path("/not-accessed-by-mock"))]


def test_naive_evaluator_clock_fails_closed(monkeypatch):
    result, calls = evaluate(monkeypatch, ASSERTED.replace(tzinfo=None))
    assert result.status == "approval_assertion_age_evaluation_failed"
    assert calls[-1] == ("clock",)
    assert result.evaluator_clock_evaluated and not result.clock_consistency_evaluated


@pytest.mark.parametrize(
    ("delta_us", "expected_ms"), [(0, 0), (1, 1), (999, 1), (1000, 1), (1001, 2)]
)
def test_exact_integer_microseconds_and_ceiling_milliseconds(monkeypatch, delta_us, expected_ms):
    result, _ = evaluate(monkeypatch, ASSERTED + timedelta(microseconds=delta_us))
    assert result.status == "approval_assertion_age_evaluated"
    assert result.age_microseconds == delta_us
    assert result.age_milliseconds_ceiling == expected_ms
    assert result.clock_consistent and result.approval_assertion_age_evaluated


def test_timezone_offsets_normalize_to_canonical_utc(monkeypatch):
    offset_assertion = ASSERTED.astimezone(timezone(timedelta(hours=5, minutes=30)))
    result, _ = evaluate(
        monkeypatch, ASSERTED + timedelta(microseconds=1), asserted=offset_assertion
    )
    assert result.approval_asserted_at_utc == "2026-08-13T12:00:00.123456Z"
    assert result.evaluator_reference_utc == "2026-08-13T12:00:00.123457Z"


def test_future_assertion_is_clock_inconsistent_without_negative_clamp_or_absolute_value(
    monkeypatch,
):
    result, _ = evaluate(monkeypatch, ASSERTED - timedelta(microseconds=1))
    assert result.status == "approval_assertion_clock_inconsistent"
    assert not result.clock_consistent
    assert result.age_microseconds is None and result.age_milliseconds_ceiling is None
    assert not result.approval_assertion_age_evaluated
    assert result.evaluation.chronology_outcome == "approval_assertion_clock_inconsistent"


def test_canonical_identity_is_non_circular_deterministic_and_fact_sensitive(monkeypatch):
    first, _ = evaluate(monkeypatch, ASSERTED + timedelta(seconds=1))
    second, _ = evaluate(monkeypatch, ASSERTED + timedelta(seconds=1))
    later, _ = evaluate(monkeypatch, ASSERTED + timedelta(seconds=2))
    canonical = age.canonical_approval_assertion_age_evaluation_json(first.evaluation)
    assert first.evaluation_identity_sha256 == second.evaluation_identity_sha256
    assert first.evaluation_identity_sha256 != later.evaluation_identity_sha256
    assert "evaluation_identity_sha256" not in json.loads(canonical)
    assert "must-not-leak" not in canonical


def test_models_are_frozen_forbid_extra_and_safety_ledger_is_non_authoritative(monkeypatch):
    result, _ = evaluate(monkeypatch, ASSERTED)
    with pytest.raises(ValidationError):
        age.ApprovedChangeApprovalAssertionAgeEvaluation.model_validate(
            {**result.evaluation.model_dump(), "extra": True}
        )
    with pytest.raises(ValidationError):
        result.status = "changed"
    assert result.read_only and not result.mutation_performed
    assert not result.approval_time_authenticated
    assert not result.approval_freshness_evaluated
    assert not result.windows_identity_binding_evaluated
    assert not result.authorization_evaluated and not result.preflight_evaluated
    assert not result.receipt_created and not result.persistence_performed
    assert not result.execution_allowed and not result.execution_available
    assert result.execution_status == "not_executed"
    assert all(
        "fresh" not in value and "stale" not in value for value in (result.status, result.reason)
    )


def test_source_has_no_inventory_alias_filesystem_time_or_freshness_policy():
    source = Path(age.__file__).read_text(encoding="utf-8")
    signature = inspect.signature(age.measure_persisted_approval_assertion_age)
    assert list(signature.parameters) == [
        "approval_artifact_id",
        "data_dir",
        "confirm_approval_artifact_identity_sha256",
    ]
    for forbidden in ("getmtime", "st_mtime", "ctime", "inventory", "latest", "current alias"):
        assert forbidden not in source
    for forbidden in (
        "max_age",
        "ttl",
        "expiration_duration",
        "approval_fresh:",
        "approval_stale:",
    ):
        assert forbidden not in source.lower()
