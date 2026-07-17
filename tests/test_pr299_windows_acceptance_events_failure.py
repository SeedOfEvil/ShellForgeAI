from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_ACCEPTANCE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "windows_smoke_acceptance.py"
_SPEC = importlib.util.spec_from_file_location("windows_smoke_acceptance", _ACCEPTANCE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_acceptance = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _acceptance
_SPEC.loader.exec_module(_acceptance)

SAFETY_FALSE_KEYS = _acceptance.SAFETY_FALSE_KEYS
_validate_evidence = _acceptance._validate_evidence
_validate_events_artifact = _acceptance._validate_events_artifact


def _common(mode: str, scope: str) -> dict:
    return {
        "schema_version": 1,
        "mode": mode,
        "status": "ok",
        "platform": {"system": "windows"},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": scope,
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "safety": {key: False for key in SAFETY_FALSE_KEYS},
        "host": {"hostname": "WIN2025-SFAI01", "python": "3.14"},
        "python_runtime": {"version": "3.14", "executable": "python"},
        "filesystem": {"cwd": "C:/Tools/ShellForgeAI", "home": "C:/Users/Operator"},
    }


def _event_component(status: str = "ok") -> dict:
    payload = {
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
            "since_hours": 24,
            "limit": 50,
            "truncated": False,
            "rendered_messages_collected": False,
            "event_xml_collected": False,
            "event_data_collected": False,
            "user_data_collected": False,
            "remote_session_used": False,
        },
        "summary": {
            "events_returned": 1,
            "critical": 0,
            "error": 0,
            "warning": 1,
            "unknown": 0,
            "providers_observed": 1,
            "provider_event_pairs_observed": 1,
            "truncated": False,
            "since_hours": 24,
            "limit": 50,
        },
        "events": [
            {
                "provider": "ProviderA",
                "event_id": 100,
                "level": "warning",
                "time_created_utc": "2026-07-16T00:00:00.1234567Z",
                "record_id": 1000,
            }
        ],
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
        "limitations": [],
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
            "secret_read": False,
            "auth_cache_read": False,
        },
    }
    if status == "error":
        payload["summary"].update(
            {
                "events_returned": 0,
                "critical": 0,
                "error": 0,
                "warning": 0,
                "unknown": 0,
                "providers_observed": 0,
                "provider_event_pairs_observed": 0,
            }
        )
        payload["events"] = []
        payload["top_provider_event_pairs"] = []
        payload["errors"] = [
            {
                "type": "events_component_failed",
                "message": "Windows Event Log metadata component failed.",
            }
        ]
    return payload


def _evidence(events_status: str | None = None) -> dict:
    doctor = _common("windows_doctor", "local_read_only_doctor")
    status = _common("windows_status", "local_read_only_status")
    components = {"doctor": doctor, "status": status}
    failed: list[str] = []
    if events_status:
        events = _event_component(events_status)
        components["events"] = events
        if events_status != "ok":
            failed.append("events")
    payload = _common("windows_evidence_bundle", "local_read_only_evidence_bundle")
    payload["components"] = components
    payload["summary"] = {
        "component_count": len(components),
        "ok_components": [name for name in components if name not in failed],
        "failed_components": failed,
    }
    payload["status"] = "component_failure" if failed else "ok"
    payload["not_collected_in_pr264"] = {
        "powershell_version": "not collected",
        "execution_policy": "not collected",
        "services": "not collected",
        "processes": "not collected",
        "event_logs": "not collected",
        "firewall": "not collected",
        "windows_update": "not collected",
    }
    if events_status:
        summary = components["events"]["summary"]
        payload["embedded_events"] = {
            "included": True,
            "status": components["events"]["status"],
            "limit": summary["limit"],
            "since_hours": summary["since_hours"],
            "returned_count": summary["events_returned"],
            "truncated": summary["truncated"],
            "critical": summary["critical"],
            "error": summary["error"],
            "warning": summary["warning"],
            "unknown": summary["unknown"],
        }
    return payload


def _passes(checks) -> bool:
    return all(check.passed for check in checks)


def test_acceptance_status_consistency_allows_healthy_and_isolated_failure() -> None:
    assert _passes(_validate_evidence(_evidence("ok"), None, None))
    assert _passes(_validate_evidence(_evidence("error"), None, None))


def test_acceptance_status_consistency_rejects_contradictions() -> None:
    failed_but_ok = _evidence("error")
    failed_but_ok["status"] = "ok"
    assert not _passes(_validate_evidence(failed_but_ok, None, None))

    healthy_but_failed = _evidence("ok")
    healthy_but_failed["status"] = "component_failure"
    assert not _passes(_validate_evidence(healthy_but_failed, None, None))

    arbitrary = _evidence("ok")
    arbitrary["status"] = "surprising"
    assert not _passes(_validate_evidence(arbitrary, None, None))


def test_acceptance_allows_generic_fallback_message_and_safety_secret_keys() -> None:
    payload = _evidence("error")
    assert payload["components"]["events"]["safety"]["secret_read"] is False
    assert payload["components"]["events"]["safety"]["auth_cache_read"] is False
    assert _passes(_validate_evidence(payload, None, None))


def test_acceptance_rejects_event_record_message_xml_and_payload_fields() -> None:
    for key, value in (
        ("message", "rendered event text"),
        ("rendered_message", "rendered event text"),
        ("xml", "<Event />"),
        ("event_data", {"name": "value"}),
        ("UserData", {"name": "value"}),
    ):
        component = _event_component("ok")
        component["events"][0][key] = value
        assert not _passes(_validate_events_artifact(component)), key


def test_acceptance_rejects_unapproved_fallback_error_shapes_and_leaks() -> None:
    cases = []
    extra_key = _event_component("error")
    extra_key["errors"][0]["traceback"] = "Traceback ..."
    cases.append(extra_key)

    arbitrary_message = _event_component("error")
    arbitrary_message["errors"][0]["message"] = "different message"
    cases.append(arbitrary_message)

    secret_marker = _event_component("error")
    secret_marker["errors"][0]["message"] = "secret-marker-123"
    cases.append(secret_marker)

    windows_path = _event_component("error")
    windows_path["errors"][0]["message"] = r"C:\sensitive\value"
    cases.append(windows_path)

    traceback = _event_component("error")
    traceback["errors"][0]["message"] = "Traceback line"
    cases.append(traceback)

    exception_class = _event_component("error")
    exception_class["errors"][0]["message"] = "OSError: bad"
    cases.append(exception_class)

    for component in cases:
        assert not _passes(_validate_events_artifact(component))


def test_acceptance_embedded_parity_mismatches_fail() -> None:
    fields = (
        ("critical", 1),
        ("error", 1),
        ("warning", 1),
        ("unknown", 1),
        ("returned_count", 1),
        ("limit", 49),
        ("since_hours", 23),
        ("status", "ok"),
        ("truncated", True),
    )
    for key, bad_value in fields:
        payload = _evidence("error")
        payload["embedded_events"][key] = bad_value
        assert not _passes(_validate_evidence(payload, None, None)), key


def test_acceptance_preserves_pr298_event_artifact_error_contract() -> None:
    healthy = _event_component("ok")
    assert _passes(_validate_events_artifact(healthy))

    collection_error = _event_component("error")
    collection_error["errors"] = [
        {
            "type": "OSError",
            "message": "Windows Event Log metadata collection failed.",
            "winerror": None,
        }
    ]
    assert _passes(_validate_events_artifact(collection_error))
