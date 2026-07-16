from __future__ import annotations

import json
from datetime import UTC, datetime

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_events import (
    DEFAULT_EVENTS_LIMIT,
    DEFAULT_SINCE_HOURS,
    MAX_EVENTS_LIMIT,
    MAX_SINCE_HOURS,
    MIN_EVENTS_LIMIT,
    MIN_SINCE_HOURS,
    SYSTEM_PROPERTY_PATHS,
    RawEventMetadata,
    build_system_events_query,
    render_windows_events_text,
    validate_events_limit,
    validate_since_hours,
    windows_events_payload,
)

WINDOWS = PlatformInfo("windows", "Windows", "nt", "2025", "AMD64")
LINUX = PlatformInfo("linux", "Linux", "posix", "6.8", "x86_64")


class FakeNative:
    def __init__(self, records=None, fail=None):
        self.records = list(records or [])
        self.fail = fail
        self.closed = []
        self.query_text = None
        self.paths = None
        self.query_handle = "query"
        self.context = "context"
        self.next_calls = 0

    def query(self, query_text):
        if self.fail == "query":
            raise OSError(5, "access denied")
        self.query_text = query_text
        return self.query_handle

    def create_render_context(self, property_paths):
        if self.fail == "context":
            raise OSError(1, "context failed")
        self.paths = property_paths
        return self.context

    def next(self, query_handle, count):
        if self.fail == "next":
            raise OSError(2, "next failed")
        self.next_calls += 1
        if not self.records:
            return []
        return [self.records.pop(0)[0]]

    def render_metadata(self, render_context, event_handle):
        if event_handle == "bad":
            raise ValueError("bad render")
        return event_handle

    def close(self, handle):
        self.closed.append(handle)


def rec(
    provider="Provider", event_id=1001, level=3, ts="2026-07-15T05:30:00.0000000Z", rid=10, **kw
):
    return RawEventMetadata(provider, event_id, level, ts, rid, **kw)


def test_cli_registration_help_and_unrelated_commands() -> None:
    result = CliRunner().invoke(app, ["windows", "events", "--help"])
    assert result.exit_code == 0
    assert "--json" in result.stdout
    assert "--limit" in result.stdout
    assert "--since-hours" in result.stdout
    top = CliRunner().invoke(app, ["windows", "--help"])
    assert top.exit_code == 0
    for command in ("memory", "network", "disks", "volumes", "processes", "services", "events"):
        assert command in top.stdout


def test_argument_validation_bounds_and_cli_errors() -> None:
    assert validate_events_limit(MIN_EVENTS_LIMIT) == 1
    assert validate_events_limit(MAX_EVENTS_LIMIT) == 200
    assert validate_since_hours(MIN_SINCE_HOURS) == 1
    assert validate_since_hours(MAX_SINCE_HOURS) == 168
    for argv in (
        ["windows", "events", "--limit", "0"],
        ["windows", "events", "--limit", "201"],
        ["windows", "events", "--limit", "abc"],
        ["windows", "events", "--since-hours", "0"],
        ["windows", "events", "--since-hours", "169"],
        ["windows", "events", "--since-hours", "abc"],
    ):
        result = CliRunner().invoke(app, argv)
        assert result.exit_code != 0
        assert "Invalid value" in result.output


def test_fixed_query_and_selected_property_context() -> None:
    query = build_system_events_query(24, now=datetime(2026, 7, 15, tzinfo=UTC))
    assert "Level=1" in query and "Level=2" in query and "Level=3" in query
    assert "SystemTime" in query and "2026-07-14" in query
    assert "Security" not in query and "Application" not in query
    paths = set(SYSTEM_PROPERTY_PATHS)
    assert paths == {
        "Event/System/Provider/@Name",
        "Event/System/EventID",
        "Event/System/Level",
        "Event/System/TimeCreated/@SystemTime",
        "Event/System/EventRecordID",
        "Event/System/Task",
        "Event/System/Opcode",
        "Event/System/Keywords",
    }
    assert not any("EventData" in p or "UserData" in p or "Computer" in p for p in paths)


def test_success_normalization_summary_order_aggregation_and_privacy() -> None:
    native = FakeNative(
        [
            (
                rec(
                    "B\x00ad", 2, 1, "2026-07-15T05:00:00.0000000Z", 5, task=1, opcode=2, keywords=3
                ),
            ),
            (rec("Provider", 1001, 3, "2026-07-15T05:30:00.0000000Z", 10),),
            (rec("Provider", 1001, 3, "2026-07-15T05:31:00.0000000Z", 11),),
        ]
    )
    payload = windows_events_payload(WINDOWS, native=native, limit=10, since_hours=24)
    assert payload["status"] == "ok"
    assert payload["collection"]["channel"] == "System"
    assert payload["events"][0]["time_created_utc"] == "2026-07-15T05:31:00.0000000Z"
    assert payload["summary"]["critical"] == 1
    assert payload["summary"]["warning"] == 2
    assert payload["summary"]["unknown"] == 0
    assert payload["top_provider_event_pairs"][0]["provider"] == "Provider"
    assert payload["top_provider_event_pairs"][0]["count"] == 2
    event_keys = set().union(*(event.keys() for event in payload["events"]))
    assert event_keys <= {
        "provider",
        "event_id",
        "level",
        "time_created_utc",
        "record_id",
        "task",
        "opcode",
        "keywords",
    }
    dumped = json.dumps(payload["events"]).lower()
    for forbidden in (
        "event_data",
        "user_data",
        "username",
        "computer",
        "activity_id",
        "process_id",
        "thread_id",
        "command_line",
    ):
        assert forbidden not in dumped


def test_empty_truncation_and_handle_cleanup() -> None:
    empty = FakeNative([])
    payload = windows_events_payload(WINDOWS, native=empty)
    assert payload["status"] == "ok"
    assert payload["events"] == []
    assert payload["summary"]["events_returned"] == 0
    assert empty.closed == ["context", "query"]
    many = FakeNative([(rec(rid=i + 1),) for i in range(5)])
    limited = windows_events_payload(WINDOWS, native=many, limit=2)
    assert len(limited["events"]) == 2
    assert limited["collection"]["truncated"] is True
    assert many.next_calls == 3
    assert many.closed.count("context") == 1 and many.closed.count("query") == 1


def test_render_failure_and_query_failure_are_bounded() -> None:
    native = FakeNative([(rec(rid=1),), ("bad",), (rec(rid=3),)])
    payload = windows_events_payload(WINDOWS, native=native, limit=5)
    assert payload["status"] == "ok"
    assert len(payload["events"]) == 2
    assert payload["warnings"]
    failed = windows_events_payload(WINDOWS, native=FakeNative(fail="query"))
    assert failed["status"] == "error"
    assert failed["errors"][0]["message"] == "Windows Event Log metadata collection failed."
    assert "Traceback" not in json.dumps(failed)


def test_unsupported_platform_does_not_initialize_native_and_text_is_bounded() -> None:
    payload = windows_events_payload(
        LINUX, native=None, limit=DEFAULT_EVENTS_LIMIT, since_hours=DEFAULT_SINCE_HOURS
    )
    assert payload["status"] == "unsupported"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["collection"]["method"] == "wevtapi_system_metadata"
    text = render_windows_events_text(
        {
            **payload,
            "status": "ok",
            "events": [
                rec.__dict__
                if False
                else {
                    "provider": "P",
                    "event_id": i,
                    "level": "warning",
                    "time_created_utc": "2026-07-15T00:00:00.0000000Z",
                    "record_id": i,
                }
                for i in range(12)
            ],
            "summary": {"events_returned": 12, "critical": 0, "error": 0, "warning": 12},
            "top_provider_event_pairs": [
                {"provider": "P", "event_id": i, "level": "warning", "count": 1} for i in range(12)
            ],
        }
    )
    assert text.count("event_id=") == 10
    assert "additional events omitted" in text
    assert "messages" in text and "payload data" in text
