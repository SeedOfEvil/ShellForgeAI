from __future__ import annotations

import json

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_events import DEFAULT_EVENTS_LIMIT, DEFAULT_SINCE_HOURS
from shellforgeai.windows_evidence import (
    render_windows_evidence_text,
    validate_evidence_events_limit,
    validate_evidence_events_since_hours,
    windows_evidence_payload,
)

WINDOWS = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
LINUX = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")


def doctor(_info):
    return {"status": "ok"}


def status(_info):
    return {"status": "ok"}


def evidence(**kwargs):
    return windows_evidence_payload(WINDOWS, doctor_builder=doctor, status_builder=status, **kwargs)


def event_payload(*, status="ok", limit=50, since_hours=24, truncated=True):
    events = [
        {
            "provider": "ProviderA",
            "event_id": 100,
            "level": "warning",
            "time_created_utc": "2026-07-16T00:00:00.1234567Z",
            "record_id": 10,
        }
    ]
    return {
        "schema_version": 1,
        "mode": "windows_events",
        "status": status,
        "platform": {"system": "windows"},
        "read_only": True,
        "mutation_performed": False,
        "collection": {
            "method": "wevtapi_system_metadata",
            "channel": "System",
            "levels": ["critical", "error", "warning"],
            "since_hours": since_hours,
            "limit": limit,
            "truncated": truncated,
            "rendered_messages_collected": False,
            "event_xml_collected": False,
            "event_data_collected": False,
            "user_data_collected": False,
            "remote_session_used": False,
        },
        "summary": {
            "events_returned": len(events),
            "critical": 0,
            "error": 0,
            "warning": len(events),
            "unknown": 0,
            "truncated": truncated,
            "since_hours": since_hours,
            "limit": limit,
        },
        "events": events,
        "top_provider_event_pairs": [
            {
                "provider": "ProviderA",
                "event_id": 100,
                "level": "warning",
                "count": 1,
                "most_recent_utc": "2026-07-16T00:00:00.1234567Z",
            }
        ],
        "warnings": [],
        "errors": [],
        "limitations": ["metadata only"],
        "safety": {
            "read_only": True,
            "mutation_performed": False,
            "event_log_clear_performed": False,
        },
    }


def test_default_evidence_excludes_events_and_does_not_call_builder() -> None:
    def builder(*_args, **_kwargs):
        raise AssertionError("events builder must not be called")

    payload = evidence(events_builder=builder)
    assert list(payload["components"]) == ["doctor", "status"]
    assert "events" not in payload["components"]
    assert "embedded_events" not in payload
    assert (
        payload["not_collected_in_pr264"]["event_logs"]
        == "planned for later read-only Windows evidence PR"
    )
    assert payload["next_safe_command"] == "shellforgeai windows status --json"
    assert "Events component:" not in render_windows_evidence_text(payload)
    assert "event logs" in render_windows_evidence_text(payload)


def test_linux_unsupported_does_not_call_events_builder() -> None:
    def builder(*_args, **_kwargs):
        raise AssertionError("events builder must not be called on unsupported platforms")

    payload = windows_evidence_payload(LINUX, include_events=True, events_builder=builder)
    assert payload["status"] == "unsupported"
    assert "components" not in payload


def test_include_events_uses_defaults_and_embeds_component_once() -> None:
    calls = []

    def builder(info, limit, since_hours):
        calls.append((info.system, limit, since_hours))
        return event_payload(limit=limit, since_hours=since_hours)

    payload = evidence(include_events=True, events_builder=builder)
    assert calls == [("windows", DEFAULT_EVENTS_LIMIT, DEFAULT_SINCE_HOURS)]
    assert payload["components"]["events"]["mode"] == "windows_events"
    assert payload["embedded_events"] == {
        "included": True,
        "status": "ok",
        "limit": 50,
        "since_hours": 24,
        "returned_count": 1,
        "truncated": True,
        "critical": 0,
        "error": 0,
        "warning": 1,
        "unknown": 0,
    }
    assert (
        payload["next_safe_command"]
        == "shellforgeai windows events --json --limit 50 --since-hours 24"
    )
    text = render_windows_evidence_text(payload)
    assert (
        "Events component: status=ok; returned=1; limit=50; since_hours=24; "
        "truncated=true; critical=0; error=0; warning=1; unknown=0"
    ) in text
    assert "event logs" not in text
    assert "ProviderA" not in text


def test_include_events_forwards_custom_bounds_and_combines_components() -> None:
    def builder(_info, limit, since_hours):
        return event_payload(limit=limit, since_hours=since_hours, truncated=False)

    payload = evidence(
        include_services=True,
        services_builder=lambda _info, _limit: {
            "status": "ok",
            "services": {"items": [], "collection_limits": {"truncated": False}, "total_count": 0},
        },
        include_processes=True,
        processes_builder=lambda _info, _limit: {
            "status": "ok",
            "returned_count": 0,
            "total_count": 0,
            "truncated": False,
        },
        include_events=True,
        events_limit=10,
        events_since_hours=12,
        events_builder=builder,
    )
    assert list(payload["components"]) == ["doctor", "status", "services", "processes", "events"]
    assert payload["components"]["events"]["collection"]["limit"] == 10
    assert payload["components"]["events"]["collection"]["since_hours"] == 12
    assert payload["summary"]["failed_components"] == []


def test_bounds_and_flag_dependency_validation() -> None:
    for value in (1, 200):
        assert validate_evidence_events_limit(value) == value
    for value in (0, 201, True):
        try:
            validate_evidence_events_limit(value)
        except ValueError:
            pass
        else:  # pragma: no cover
            raise AssertionError(value)
    for value in (1, 168):
        assert validate_evidence_events_since_hours(value) == value
    for value in (0, 169, False):
        try:
            validate_evidence_events_since_hours(value)
        except ValueError:
            pass
        else:  # pragma: no cover
            raise AssertionError(value)
    for kwargs in (
        {"events_limit": 10},
        {"events_since_hours": 24},
        {"events_limit": 10, "events_since_hours": 24},
    ):
        try:
            evidence(**kwargs)
        except ValueError as exc:
            assert "requires include_events=True" in str(exc)
        else:  # pragma: no cover
            raise AssertionError(kwargs)


def test_events_failure_is_isolated_and_sanitized() -> None:
    payload = evidence(
        include_events=True,
        events_builder=lambda *_args: (_ for _ in ()).throw(RuntimeError("secret path C:/x")),
    )
    assert payload["status"] == "component_failure"
    assert payload["summary"]["ok_components"] == ["doctor", "status"]
    assert payload["summary"]["failed_components"] == ["events"]
    assert payload["components"]["events"]["status"] == "error"
    dumped = json.dumps(payload)
    assert "secret path" not in dumped
    assert "Traceback" not in dumped


def test_cli_help_and_dependency_errors() -> None:
    runner = CliRunner()
    help_result = runner.invoke(app, ["windows", "evidence", "--help"])
    assert help_result.exit_code == 0
    assert "--include-events" in help_result.output
    assert "--events-limit" in help_result.output
    assert "1-200" in help_result.output
    assert "--events-since-hours" in help_result.output
    assert "1-168" in help_result.output

    standalone_help = runner.invoke(app, ["windows", "events", "--help"])
    assert standalone_help.exit_code == 0
    assert "--limit" in standalone_help.output
    assert "--since-hours" in standalone_help.output

    for args in (["--events-limit", "10"], ["--events-since-hours", "24"]):
        result = runner.invoke(app, ["windows", "evidence", *args, "--json"])
        assert result.exit_code != 0
        assert args[0] in (result.output + (result.stderr or ""))


def test_cli_json_include_events_on_linux_is_structured_unsupported() -> None:
    result = CliRunner().invoke(app, ["windows", "evidence", "--include-events", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "unsupported"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
