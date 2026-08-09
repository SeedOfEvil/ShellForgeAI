"""Focused deterministic tests for the PR304 temporal freshness authority."""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from shellforgeai.core import approved_change_pr304_evidence_freshness as freshness
from shellforgeai.core.windows_runtime_integrity_contract import (
    Pr304EvidenceObservation,
    Pr304RuntimeIntegrityEvidenceSet,
    compute_evidence_set_identity_sha256,
)


def evidence(start: str, completed: str, *, status="attention", timed=True):
    def observation(role):
        return Pr304EvidenceObservation(
            role=role,
            packet_identity_sha256=("a" if role.startswith("source") else "b") * 64,
            packet_status=status,
            platform_system="windows",
            capture_chronology_available=timed,
            capture_chronology_valid=timed,
            capture_started_at_utc=start if timed else "",
            capture_completed_at_utc=completed if timed else "",
            capture_duration_ms=0 if timed else None,
        )

    return Pr304RuntimeIntegrityEvidenceSet(
        source_root_observation=observation("source_root_observation"),
        system32_observation=observation("system32_observation"),
        stable_fields_consistent=True,
        capture_chronology_available=timed,
        capture_chronology_valid=timed,
        earliest_capture_started_at_utc=start if timed else "",
        latest_capture_completed_at_utc=completed if timed else "",
        combined_capture_span_ms=0 if timed else None,
    )


def evaluate(monkeypatch, item, now):
    calls = []
    monkeypatch.setattr(freshness, "_utc_now", lambda: calls.append(1) or now)
    policy_id = freshness.compute_pr304_evidence_freshness_policy_identity_sha256(
        freshness.maintained_pr304_evidence_freshness_policy()
    )
    result = freshness.evaluate_pr304_evidence_set_freshness(
        item,
        confirm_evidence_set_identity_sha256=compute_evidence_set_identity_sha256(item),
        confirm_freshness_policy_identity_sha256=policy_id,
    )
    return result, calls


def test_policy_is_fixed_canonical_and_immutable():
    policy = freshness.maintained_pr304_evidence_freshness_policy()
    assert policy.max_oldest_evidence_age_ms == 300_000
    assert freshness.canonical_pr304_evidence_freshness_policy_json(
        policy
    ) == freshness.canonical_pr304_evidence_freshness_policy_json(
        dict(reversed(list(policy.model_dump().items())))
    )
    assert len(freshness.compute_pr304_evidence_freshness_policy_identity_sha256(policy)) == 64
    with pytest.raises(ValidationError):
        freshness.Pr304EvidenceFreshnessPolicy(max_oldest_evidence_age_ms=1)


@pytest.mark.parametrize(
    ("microseconds", "expected"),
    [
        (0, "evidence_fresh"),
        (299_999_000, "evidence_fresh"),
        (300_000_000, "evidence_fresh"),
        (300_000_001, "evidence_stale"),
        (300_001_000, "evidence_stale"),
    ],
)
def test_exact_and_submillisecond_boundaries(monkeypatch, microseconds, expected):
    start = "2026-08-08T12:00:00.000000Z"
    item = evidence(start, start)
    result, calls = evaluate(
        monkeypatch,
        item,
        datetime(2026, 8, 8, 12, 0, tzinfo=UTC).replace(microsecond=0)
        + __import__("datetime").timedelta(microseconds=microseconds),
    )
    assert result.status == expected
    assert len(calls) == 1
    assert result.oldest_evidence_age_ms == (microseconds + 999) // 1000
    assert result.evidence_fresh is (expected == "evidence_fresh")
    assert result.authorization_evaluated is False and result.execution_allowed is False
    assert result.approval_freshness_evaluated is False


def test_confirmations_precede_clock(monkeypatch):
    item = evidence("2026-08-08T12:00:00.000000Z", "2026-08-08T12:00:00.000000Z")
    monkeypatch.setattr(freshness, "_utc_now", lambda: pytest.fail("clock read"))
    result = freshness.evaluate_pr304_evidence_set_freshness(
        item,
        confirm_evidence_set_identity_sha256="0" * 64,
        confirm_freshness_policy_identity_sha256="0" * 64,
    )
    assert result.status == "evidence_set_confirmation_mismatch"
    result = freshness.evaluate_pr304_evidence_set_freshness(
        item,
        confirm_evidence_set_identity_sha256=compute_evidence_set_identity_sha256(item),
        confirm_freshness_policy_identity_sha256="0" * 64,
    )
    assert result.status == "freshness_policy_confirmation_mismatch"


def test_legacy_unavailable_without_clock(monkeypatch):
    item = evidence("", "", timed=False)
    result, calls = evaluate(monkeypatch, item, datetime.now(UTC))
    assert result.status == "freshness_unavailable" and calls == []
    assert (
        not result.freshness_evaluated and not result.evidence_fresh and not result.evidence_stale
    )
    assert result.reference_time_utc == ""


def test_clock_inconsistent_and_status_orthogonal(monkeypatch):
    item = evidence("2026-08-08T12:00:00.000000Z", "2026-08-08T12:00:01.000000Z", status="blocked")
    result, calls = evaluate(monkeypatch, item, datetime(2026, 8, 8, 12, 0, 0, tzinfo=UTC))
    assert result.status == "freshness_clock_inconsistent" and calls == [1]
    assert (
        result.oldest_evidence_age_ms is None
        and not result.evidence_fresh
        and not result.evidence_stale
    )
    assert item.source_root_observation.packet_status == "blocked"


def test_evaluation_identity_is_deterministic(monkeypatch):
    item = evidence("2026-08-08T12:00:00.000000Z", "2026-08-08T12:00:00.000000Z")
    now = datetime(2026, 8, 8, 12, 1, tzinfo=UTC)
    first, _ = evaluate(monkeypatch, item, now)
    second, _ = evaluate(monkeypatch, item, now)
    assert first.freshness_evaluation_identity_sha256 == second.freshness_evaluation_identity_sha256
    later, _ = evaluate(monkeypatch, item, datetime(2026, 8, 8, 12, 2, tzinfo=UTC))
    assert first.freshness_evaluation_identity_sha256 != later.freshness_evaluation_identity_sha256


def test_module_has_no_forbidden_runtime_dependencies():
    source = Path(freshness.__file__).read_text(encoding="utf-8")
    imports = " ".join(
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    )
    for forbidden in (
        "subprocess",
        "windows_runtime_reconcile_execution",
        "approved_change_plan_current_state",
        "shellforgeai.cli",
        "provider",
    ):
        assert forbidden not in imports
