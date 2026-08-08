"""Focused capture chronology contract tests for PR304 evidence."""

from __future__ import annotations

import argparse
import copy
import importlib.util
from pathlib import Path

import pytest

from shellforgeai.core import windows_runtime_integrity_contract as contract


def _load_collector():
    path = Path("scripts/windows_runtime_integrity.py")
    spec = importlib.util.spec_from_file_location("pr340_collector", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _args() -> argparse.Namespace:
    return argparse.Namespace(
        expected_source_root=None,
        runtime_root=None,
        wrapper_path=None,
        canonical_wrapper_path=None,
        entrypoint_path=None,
        profile="inspect",
        json=True,
        out_json=None,
    )


def _legacy_packet() -> dict:
    safety = {key: False for key in contract.FALSE_KEYS}
    safety.update(read_only=True, mutation_performed=False)
    return {
        "schema_version": 1,
        "mode": contract.MODE,
        "status": "unsupported",
        "platform": {"system": "linux"},
        "checks": [{"id": "platform.windows", "status": "unsupported"}],
        "summary": {
            key: int(key == "unsupported")
            for key in ("pass", "attention", "blocked", "not_requested", "unsupported")
        },
        "read_only": True,
        "mutation_performed": False,
        "safety": safety,
        "first_safe_command": "python scripts/windows_runtime_integrity.py --json",
    }


def _timed_packet(
    start="2026-08-08T18:45:30.123456Z", end="2026-08-08T18:45:31.123456Z", duration=1000
):
    packet = _legacy_packet()
    packet["observation"] = {
        "capture_started_at_utc": start,
        "capture_completed_at_utc": end,
        "capture_duration_ms": duration,
        "clock_source": contract.CLOCK_SOURCE,
    }
    return packet


def test_collector_brackets_unsupported_observation_with_wall_and_monotonic_clocks(monkeypatch):
    collector = _load_collector()
    events = []
    utc = iter(("2026-08-08T18:45:30.123456Z", "2026-08-08T18:45:31.123456Z"))
    mono = iter((10_000_000_000, 10_025_999_999))
    monkeypatch.setattr(collector, "_utc_now", lambda: events.append("utc") or next(utc))
    monkeypatch.setattr(collector, "_monotonic_ns", lambda: events.append("mono") or next(mono))
    monkeypatch.setattr(
        collector, "_platform_block", lambda: events.append("observe") or {"system": "linux"}
    )
    monkeypatch.setattr(collector.platform, "system", lambda: "Linux")
    packet = collector.build_packet(_args())
    assert events == ["utc", "mono", "observe", "mono", "utc"]
    assert packet["status"] == "unsupported"
    assert packet["observation"] == {
        "capture_started_at_utc": "2026-08-08T18:45:30.123456Z",
        "capture_completed_at_utc": "2026-08-08T18:45:31.123456Z",
        "capture_duration_ms": 25,
        "clock_source": "local_system_utc_plus_monotonic",
    }
    assert packet["read_only"] is True and packet["mutation_performed"] is False


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("capture_started_at_utc", "2026-08-08T18:45:30", "canonical UTC"),
        ("capture_started_at_utc", "2026-08-08T19:45:30.000000+01:00", "canonical UTC"),
        ("capture_started_at_utc", "2026-02-30T18:45:30.000000Z", "canonical UTC"),
        ("capture_duration_ms", -1, "between 0"),
        ("capture_duration_ms", 1.5, "must be an integer"),
        ("capture_duration_ms", True, "must be an integer"),
        ("capture_duration_ms", contract.MAX_CAPTURE_DURATION_MS + 1, "between 0"),
        ("clock_source", "trusted_ntp", "clock_source"),
    ],
)
def test_observation_rejects_malformed_values(field, value, error):
    packet = _timed_packet()
    packet["observation"][field] = value
    assert any(error in item for item in contract.packet_validation_errors(packet))


def test_observation_exact_shape_order_and_identity():
    packet = _timed_packet(duration=0)
    assert contract.validate_windows_runtime_integrity_packet(packet).packet_valid
    backwards = _timed_packet(
        start="2026-08-08T18:45:31.123456Z", end="2026-08-08T18:45:30.123456Z"
    )
    assert "capture completion must not precede capture start" in contract.packet_validation_errors(
        backwards
    )
    extra = _timed_packet()
    extra["observation"]["fresh"] = True
    assert (
        "observation must contain exactly the required fields"
        in contract.packet_validation_errors(extra)
    )
    missing = _timed_packet()
    del missing["observation"]["clock_source"]
    assert contract.packet_validation_errors(missing)
    reordered = dict(reversed(list(packet.items())))
    assert contract.compute_packet_identity_sha256(
        packet
    ) == contract.compute_packet_identity_sha256(reordered)
    changed = copy.deepcopy(packet)
    changed["observation"]["capture_duration_ms"] = 1
    assert contract.compute_packet_identity_sha256(
        packet
    ) != contract.compute_packet_identity_sha256(changed)


def test_legacy_is_explicitly_untimed_and_pair_chronology_is_bounded():
    legacy = contract.validate_windows_runtime_integrity_packet(_legacy_packet())
    assert legacy.packet_valid
    assert legacy.capture_chronology_available is False
    assert legacy.capture_chronology_valid is False
    source = _timed_packet(end="2026-08-08T18:45:31.123456Z", duration=1000)
    system32 = _timed_packet(
        start="2026-08-08T18:45:32.123456Z",
        end="2026-08-08T18:45:34.123456Z",
        duration=2000,
    )
    result = contract.prepare_pr304_runtime_integrity_evidence_set(source, system32)
    assert result.status == "evidence_set_prepared"
    assert result.evidence_set.capture_chronology_available is True
    assert result.evidence_set.capture_chronology_valid is True
    assert (
        result.evidence_set.earliest_capture_started_at_utc
        == source["observation"]["capture_started_at_utc"]
    )
    assert (
        result.evidence_set.latest_capture_completed_at_utc
        == system32["observation"]["capture_completed_at_utc"]
    )
    assert result.evidence_set.combined_capture_span_ms == 4000
    assert result.evidence_freshness_evaluated is False
