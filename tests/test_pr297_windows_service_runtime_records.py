from __future__ import annotations

import json
from pathlib import Path

import pytest

from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_services import (
    RawServiceRecord,
    normalize_controls,
    render_windows_services_text,
    runtime_signals,
    windows_services_payload,
)

WINDOWS_INFO = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
LINUX_INFO = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")


def rec(name="Svc", state=4, **kw):
    return RawServiceRecord(name, f"{name} Display", state, 0x10, **kw)


def payload(records, limit=500):
    return windows_services_payload(
        WINDOWS_INFO, enumerator=lambda: list(records), max_services=limit
    )


def test_raw_record_capture_and_existing_fields_compatibility():
    r = rec(
        process_id=123,
        controls_accepted_mask=0x3,
        win32_exit_code=5,
        service_specific_exit_code=7,
        checkpoint=9,
        wait_hint_ms=11,
        service_flags=1,
    )
    item = payload([r])["services"]["items"][0]
    assert item["name"] == "Svc"
    assert item["display_name"] == "Svc Display"
    assert item["state"] == "running"
    assert item["service_type"] == "win32_own_process"
    assert item["process_id"] == 123
    assert item["controls_accepted"] == ["stop", "pause_continue"]
    assert item["controls_accepted_unknown_mask"] == 0
    assert item["win32_exit_code"] == 5
    assert item["service_specific_exit_code"] == 7
    assert item["checkpoint"] == 9
    assert item["wait_hint_ms"] == 11
    assert item["runs_in_system_process"] is True


@pytest.mark.parametrize(("pid", "expected"), [(456, 456), (0, None)])
def test_process_id_normalization(pid, expected):
    assert payload([rec(process_id=pid)])["services"]["items"][0]["process_id"] == expected


def test_controls_normalization_canonical_order_unknown_mask():
    assert normalize_controls(0) == ([], 0)
    assert normalize_controls(0x1) == (["stop"], 0)
    labels, unknown = normalize_controls(0x80000000 | 0x400 | 0x1 | 0x2)
    assert labels == ["stop", "pause_continue", "trigger_event"]
    assert len(labels) == len(set(labels))
    assert unknown == 0x80000000
    all_labels, all_unknown = normalize_controls(0xFFF)
    assert all_labels == [
        "stop",
        "pause_continue",
        "shutdown",
        "param_change",
        "netbind_change",
        "hardware_profile_change",
        "power_event",
        "session_change",
        "preshutdown",
        "time_change",
        "trigger_event",
        "user_logoff",
    ]
    assert all_unknown == 0


def test_pending_state_classification_only_four_pending_labels():
    cases = {2: True, 3: True, 5: True, 6: True, 4: False, 1: False, 7: False, 99: False}
    for state, expected in cases.items():
        assert ("pending" in runtime_signals(rec(state=state))) is expected


def test_exit_code_checkpoint_wait_hint_and_flags_are_observational():
    item = payload(
        [
            rec(
                win32_exit_code=1,
                service_specific_exit_code=2,
                checkpoint=3,
                wait_hint_ms=4,
                service_flags=0x80000001,
            )
        ]
    )["services"]["items"][0]
    assert item["runtime_signals"] == [
        "nonzero_win32_exit_code",
        "nonzero_service_specific_exit_code",
        "checkpoint_present",
        "wait_hint_present",
        "runs_in_system_process",
    ]
    text = render_windows_services_text(payload([rec(win32_exit_code=1)]))
    forbidden = ("failed", "unhealthy", "restart recommendation", "remediate")
    assert not any(word in text.lower() for word in forbidden)


def test_runtime_summary_full_set_before_truncation_and_limit_compatibility():
    records = [
        rec("a", process_id=1, controls_accepted_mask=0x3),
        rec("b", process_id=0),
        rec("c", state=2, checkpoint=1, wait_hint_ms=2),
        rec("d", state=1, win32_exit_code=5),
        rec("e", state=1, service_specific_exit_code=6, service_flags=1),
    ]
    p = payload(records, limit=2)
    assert p["services"]["total_count"] == 5
    assert len(p["services"]["items"]) == 2
    assert p["services"]["collection_limits"]["truncated"] is True
    assert p["services"]["runtime_summary"] == {
        "running_with_process_id": 1,
        "running_without_process_id": 1,
        "pending_services": 1,
        "services_with_nonzero_win32_exit_code": 1,
        "services_with_nonzero_service_specific_exit_code": 1,
        "services_with_checkpoint": 1,
        "services_with_wait_hint": 1,
        "services_accepting_stop": 1,
        "services_accepting_pause_continue": 1,
        "services_running_in_system_process": 1,
        "runtime_signal_services": 4,
    }


def test_text_runtime_preview_is_bounded_deterministic_and_safe():
    records = [rec(f"z{i:02d}", state=2, checkpoint=i) for i in range(12)] + [rec("ordinary")]
    text = render_windows_services_text(payload(records))
    assert "Runtime:" in text
    assert "Runtime signals are point-in-time observations, not failure diagnoses." in text
    assert text.count("- z") == 10
    assert "Runtime signal preview truncated: 2 additional services not shown." in text
    assert "ordinary" not in text


def test_enumeration_failure_and_unsupported_platform_preserve_safety():
    err = windows_services_payload(
        WINDOWS_INFO, enumerator=lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    assert err["status"] == "error"
    assert "Traceback" not in json.dumps(err)
    assert err["safety"]["read_only"] is True
    assert err["safety"]["service_control_executed"] is False
    unsupported = windows_services_payload(
        LINUX_INFO, enumerator=lambda: pytest.fail("should not enumerate")
    )
    assert unsupported["status"] == "unsupported"
    assert unsupported["windows_v1"]["available"] is False


def test_json_determinism_and_integer_types():
    p1 = payload([rec("b", controls_accepted_mask=0x3), rec("a", process_id=2)])
    p2 = payload([rec("b", controls_accepted_mask=0x3), rec("a", process_id=2)])
    assert json.dumps(p1, sort_keys=True) == json.dumps(p2, sort_keys=True)
    item = p1["services"]["items"][0]
    assert isinstance(item["win32_exit_code"], int)
    assert item["controls_accepted"] == []


def test_no_forbidden_process_or_service_config_apis_in_source():
    src = Path("src/shellforgeai/windows_services.py").read_text()
    forbidden = [
        "psutil.Process",
        "OpenProcess",
        "QueryFullProcessImageName",
        "OpenServiceW",
        "QueryServiceConfigW",
        "QueryServiceConfig2W",
        "StartServiceW",
        "ControlService",
        "ChangeServiceConfigW",
        "ChangeServiceConfig2W",
        "DeleteService",
        "EnumDependentServicesW",
        "shell=True",
        "PowerShell",
        "WinRM",
        "subprocess",
    ]
    for token in forbidden:
        assert token not in src
