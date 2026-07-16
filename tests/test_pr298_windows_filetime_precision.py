from __future__ import annotations

import importlib.util
import inspect
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_events import (
    EventMetadataContractError,
    RawEventMetadata,
    WindowsFileTime,
    format_windows_filetime,
    normalize_timestamp,
    render_windows_events_text,
    windows_events_payload,
)

WINDOWS = PlatformInfo("windows", "Windows", "nt", "2025", "AMD64")
FILETIME_TICKS_PER_SECOND = 10_000_000


def _ticks(iso_second: str, fraction: int = 0) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=UTC)
    dt = datetime.strptime(iso_second, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    delta = dt - epoch
    return (
        delta.days * 24 * 60 * 60 * FILETIME_TICKS_PER_SECOND
        + delta.seconds * FILETIME_TICKS_PER_SECOND
        + delta.microseconds * 10
        + fraction
    )


class Native:
    def __init__(self, records: list[RawEventMetadata]):
        self.records = list(records)

    def query(self, query_text):
        return "query"

    def create_render_context(self, property_paths):
        return "context"

    def next(self, query_handle, count):
        if not self.records:
            return []
        return [self.records.pop(0)]

    def render_metadata(self, render_context, event_handle):
        return event_handle

    def close(self, handle):
        pass


def _event(record_id: int, fraction: int, provider: str = "disk", event_id: int = 153):
    return RawEventMetadata(
        provider,
        event_id,
        3,
        WindowsFileTime(_ticks("2026-07-15T23:41:10", fraction)),
        record_id,
    )


@pytest.mark.parametrize(
    ("fraction", "suffix"),
    [
        (0, ".0000000Z"),
        (1, ".0000001Z"),
        (9_999_999, ".9999999Z"),
        (7_402_876, ".7402876Z"),
        (7_088_783, ".7088783Z"),
        (5_559_538, ".5559538Z"),
        (2_997_836, ".2997836Z"),
        (8_083_558, ".8083558Z"),
        (1_234_567, ".1234567Z"),
    ],
)
def test_filetime_fractional_ticks_are_preserved(fraction: int, suffix: str) -> None:
    rendered = format_windows_filetime(WindowsFileTime(_ticks("2026-07-15T23:41:10", fraction)))
    assert rendered == f"2026-07-15T23:41:10{suffix}"


def test_second_and_year_boundary_carry() -> None:
    one_tick_past_second = WindowsFileTime(_ticks("2026-07-15T23:41:10", 9_999_999) + 1)
    assert format_windows_filetime(one_tick_past_second) == "2026-07-15T23:41:11.0000000Z"

    one_tick_past_year = WindowsFileTime(_ticks("2026-12-31T23:59:59", 9_999_999) + 1)
    assert format_windows_filetime(one_tick_past_year) == "2027-01-01T00:00:00.0000000Z"


def test_no_floating_point_timestamp_conversion_in_native_formatter() -> None:
    source = inspect.getsource(format_windows_filetime)
    assert "fromtimestamp" not in source
    assert " / " not in source
    assert "isoformat" not in source
    assert format_windows_filetime(WindowsFileTime(_ticks("2026-07-15T23:41:10", 1))) == (
        "2026-07-15T23:41:10.0000001Z"
    )


def test_datetime_and_string_fixture_compatibility_canonicalizes_to_seven_digits() -> None:
    assert normalize_timestamp(datetime(2026, 7, 15, 23, 41, 10, 123456, tzinfo=UTC)) == (
        "2026-07-15T23:41:10.1234560Z"
    )
    assert normalize_timestamp("2026-07-15T23:41:10Z") == "2026-07-15T23:41:10.0000000Z"
    assert normalize_timestamp("2026-07-15T23:41:10.7402876Z") == ("2026-07-15T23:41:10.7402876Z")
    assert normalize_timestamp("2026-07-15T23:41:10.12345678Z") is None
    assert normalize_timestamp("2026-07-15T23:41:10+00:00") is None


def test_same_second_fractional_ordering_and_equal_timestamp_tie() -> None:
    payload = windows_events_payload(
        WINDOWS,
        native=Native([_event(30, 3_000_000), _event(70, 7_000_000), _event(10, 1_000_000)]),
    )
    assert [event["time_created_utc"] for event in payload["events"]] == [
        "2026-07-15T23:41:10.7000000Z",
        "2026-07-15T23:41:10.3000000Z",
        "2026-07-15T23:41:10.1000000Z",
    ]

    tied = windows_events_payload(WINDOWS, native=Native([_event(1, 5), _event(2, 5)]))
    assert [event["record_id"] for event in tied["events"]] == [2, 1]


def test_aggregation_most_recent_preserves_fractional_precision() -> None:
    payload = windows_events_payload(
        WINDOWS,
        native=Native([_event(1, 1_000_000), _event(2, 7_000_000), _event(3, 3_000_000)]),
    )
    assert payload["top_provider_event_pairs"][0]["most_recent_utc"] == (
        "2026-07-15T23:41:10.7000000Z"
    )


def test_invalid_filetime_is_bounded_and_not_fabricated() -> None:
    with pytest.raises(EventMetadataContractError):
        WindowsFileTime(-1)
    payload = windows_events_payload(
        WINDOWS,
        native=Native([RawEventMetadata("disk", 153, 3, WindowsFileTime(2**63), 53672)]),
    )
    assert payload["status"] == "partial"
    assert payload["events"] == []
    assert payload["errors"]
    assert "Traceback" not in str(payload)


def test_json_determinism_and_text_output_keep_seven_digits() -> None:
    records = [_event(1, 7_402_876), _event(2, 7_088_783, provider="disk", event_id=153)]
    first = windows_events_payload(WINDOWS, native=Native(records.copy()))
    second = windows_events_payload(WINDOWS, native=Native(records.copy()))
    assert first["events"] == second["events"]
    assert first["top_provider_event_pairs"] == second["top_provider_event_pairs"]
    text = render_windows_events_text(first)
    assert "2026-07-15T23:41:10.7402876Z" in text
    assert "2026-07-15T23:41:10Z" not in text


def _acceptance_validator():
    script = Path(__file__).parents[1] / "scripts" / "windows_smoke_acceptance.py"
    spec = importlib.util.spec_from_file_location("windows_smoke_acceptance_precision", script)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module._validate_events_artifact


def _artifact(timestamp: str, *, most_recent: str | None = None, reverse: bool = False) -> dict:
    events = [
        {
            "provider": "disk",
            "event_id": 153,
            "level": "warning",
            "time_created_utc": timestamp,
            "record_id": 53672,
        },
        {
            "provider": "disk",
            "event_id": 153,
            "level": "warning",
            "time_created_utc": "2026-07-15T23:41:10.7000000Z",
            "record_id": 53671,
        },
    ]
    if reverse:
        events = list(reversed(events))
    return {
        "mode": "windows_events",
        "status": "ok",
        "platform": {"system": "windows"},
        "read_only": True,
        "mutation_performed": False,
        "collection": {
            "channel": "System",
            "levels": ["critical", "error", "warning"],
            "limit": 50,
            "since_hours": 24,
        },
        "summary": {"events_returned": len(events), "unknown": 0},
        "top_provider_event_pairs": [
            {
                "provider": "disk",
                "event_id": 153,
                "level": "warning",
                "count": len(events),
                "most_recent_utc": most_recent if most_recent is not None else timestamp,
            }
        ],
        "events": events,
        "warnings": [],
        "safety": {
            "powershell_executed": False,
            "winrm_used": False,
            "remote_execution": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "model_called": False,
            "network_call": False,
            "event_log_write_performed": False,
            "event_log_clear_performed": False,
            "event_log_export_performed": False,
            "event_subscription_created": False,
        },
    }


def test_acceptance_timestamp_precision_checks() -> None:
    validate = _acceptance_validator()
    valid = _artifact("2026-07-15T23:41:10.7402876Z")
    assert all(check.passed for check in validate(valid))

    cases = [
        _artifact("2026-07-15T23:41:10Z"),
        _artifact("2026-07-15T23:41:10.740287Z"),
        _artifact("2026-07-15T23:41:10.74028761Z"),
        _artifact("2026-07-15T23:41:10.7402876z"),
        _artifact("2026-07-15T23:41:10.7402876+00:00"),
        _artifact("2026-07-15T23:41:10.7402876Z", most_recent="2026-07-15T23:41:10Z"),
        _artifact("2026-07-15T23:41:10.7402876Z", reverse=True),
    ]
    for payload in cases:
        assert any(not check.passed for check in validate(payload))
