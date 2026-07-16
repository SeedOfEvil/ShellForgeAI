from __future__ import annotations

import ctypes
from datetime import UTC, datetime

import pytest

from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_events import (
    EVT_VAR_TYPE_BYTE,
    EVT_VAR_TYPE_FILETIME,
    EVT_VAR_TYPE_HEX_INT32,
    EVT_VAR_TYPE_HEX_INT64,
    EVT_VAR_TYPE_INT16,
    EVT_VAR_TYPE_INT32,
    EVT_VAR_TYPE_INT64,
    EVT_VAR_TYPE_NULL,
    EVT_VAR_TYPE_SBYTE,
    EVT_VAR_TYPE_STRING,
    EVT_VAR_TYPE_UINT16,
    EVT_VAR_TYPE_UINT32,
    EVT_VAR_TYPE_UINT64,
    EVT_VARIANT,
    EVT_VARIANT_TYPE_ARRAY,
    EventMetadataContractError,
    EvtVariantValue,
    RawEventMetadata,
    WindowsFileTime,
    decode_evt_variant,
    decode_selected_event_metadata,
    windows_events_payload,
)

WINDOWS = PlatformInfo("windows", "Windows", "nt", "2025", "AMD64")


def _variant(
    type_code: int, member: str | None = None, value=0, *, dirty: int = 0xAB
) -> EVT_VARIANT:
    variant = EVT_VARIANT()
    ctypes.memset(ctypes.byref(variant.value), dirty, ctypes.sizeof(EvtVariantValue))
    variant.Count = 0
    variant.Type = type_code
    if member is not None:
        setattr(variant.value, member, value)
    return variant


def _filetime(dt: datetime, fractional_ticks: int = 0) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=UTC)
    delta = dt.astimezone(UTC) - epoch
    return (
        delta.days * 24 * 60 * 60 * 10_000_000
        + delta.seconds * 10_000_000
        + delta.microseconds * 10
        + fractional_ticks
    )


def test_evt_variant_abi_layout_matches_windows_x64_contract() -> None:
    assert EVT_VARIANT.value.offset == 0
    assert EVT_VARIANT.Count.offset == ctypes.sizeof(EvtVariantValue)
    assert EVT_VARIANT.Type.offset == ctypes.sizeof(EvtVariantValue) + 4
    assert ctypes.sizeof(EvtVariantValue) == 8
    assert ctypes.alignment(EvtVariantValue) == ctypes.alignment(ctypes.c_void_p)
    assert ctypes.sizeof(EVT_VARIANT) == 16
    assert ctypes.alignment(EVT_VARIANT) == ctypes.alignment(ctypes.c_void_p)


@pytest.mark.parametrize(
    ("type_code", "member", "value", "expected"),
    [
        (EVT_VAR_TYPE_BYTE, "ByteVal", 3, 3),
        (EVT_VAR_TYPE_UINT16, "UInt16Val", 153, 153),
        (EVT_VAR_TYPE_UINT32, "UInt32Val", 123456789, 123456789),
        (EVT_VAR_TYPE_SBYTE, "SByteVal", -5, -5),
        (EVT_VAR_TYPE_INT16, "Int16Val", -1234, -1234),
        (EVT_VAR_TYPE_INT32, "Int32Val", -123456, -123456),
        (EVT_VAR_TYPE_UINT64, "UInt64Val", 53672, 53672),
        (EVT_VAR_TYPE_INT64, "Int64Val", -53672, -53672),
        (EVT_VAR_TYPE_HEX_INT32, "HexInt32Val", 0xDEADBEEF, 0xDEADBEEF),
        (EVT_VAR_TYPE_HEX_INT64, "HexInt64Val", 0x0123456789ABCDEF, 0x0123456789ABCDEF),
    ],
)
def test_dirty_upper_bytes_do_not_corrupt_exact_scalar_members(
    type_code: int, member: str, value: int, expected: int
) -> None:
    variant = _variant(type_code, member, value, dirty=0xCD)
    assert decode_evt_variant(variant) == expected


def test_uint16_153_regression_does_not_decode_as_live_corrupt_value() -> None:
    variant = _variant(EVT_VAR_TYPE_UINT16, "UInt16Val", 153, dirty=0xAB)
    corrupt_live_value = 737179140249
    assert corrupt_live_value != 153
    assert decode_evt_variant(variant) == 153


def test_null_string_filetime_array_and_unsupported_variant_behavior() -> None:
    assert decode_evt_variant(_variant(EVT_VAR_TYPE_NULL)) is None
    backing = ctypes.create_unicode_buffer("disk")
    assert (
        decode_evt_variant(
            _variant(EVT_VAR_TYPE_STRING, "StringVal", ctypes.cast(backing, ctypes.c_wchar_p))
        )
        == "disk"
    )
    dt = datetime(2026, 7, 15, 5, 30, tzinfo=UTC)
    assert decode_evt_variant(
        _variant(EVT_VAR_TYPE_FILETIME, "FileTimeVal", _filetime(dt, 7))
    ) == WindowsFileTime(_filetime(dt, 7))
    with pytest.raises(EventMetadataContractError, match="array_variant_unsupported"):
        decode_evt_variant(_variant(EVT_VAR_TYPE_BYTE | EVT_VARIANT_TYPE_ARRAY, "ByteVal", 3))
    with pytest.raises(EventMetadataContractError, match="unsupported_variant_type"):
        decode_evt_variant(_variant(99))


def _eight_property_variants(**overrides) -> tuple[ctypes.Array, datetime]:
    dt = datetime(2026, 7, 15, 5, 30, tzinfo=UTC)
    provider = ctypes.create_unicode_buffer(overrides.get("provider", "disk"))
    variants = (EVT_VARIANT * 8)()
    values = [
        _variant(EVT_VAR_TYPE_STRING, "StringVal", ctypes.cast(provider, ctypes.c_wchar_p)),
        _variant(EVT_VAR_TYPE_UINT16, "UInt16Val", overrides.get("event_id", 153)),
        _variant(EVT_VAR_TYPE_BYTE, "ByteVal", overrides.get("level", 3)),
        _variant(EVT_VAR_TYPE_FILETIME, "FileTimeVal", _filetime(dt, 7)),
        _variant(EVT_VAR_TYPE_UINT64, "UInt64Val", overrides.get("record_id", 53672)),
        _variant(EVT_VAR_TYPE_UINT16, "UInt16Val", overrides.get("task", 7)),
        _variant(EVT_VAR_TYPE_BYTE, "ByteVal", overrides.get("opcode", 0)),
        _variant(
            EVT_VAR_TYPE_HEX_INT64, "HexInt64Val", overrides.get("keywords", 0x80000000000000)
        ),
    ]
    for index, value in enumerate(values):
        variants[index] = value
    variants._provider = provider  # keep backing string alive for the fixture
    return variants, dt


def test_full_eight_property_dirty_storage_fixture_decodes_and_normalizes() -> None:
    variants, dt = _eight_property_variants()
    raw = decode_selected_event_metadata(variants, 8)
    assert raw == RawEventMetadata(
        "disk", 153, 3, WindowsFileTime(_filetime(dt, 7)), 53672, 7, 0, 0x80000000000000
    )

    class Native:
        def query(self, query_text):
            return "query"

        def create_render_context(self, property_paths):
            return "context"

        def next(self, query_handle, count):
            if hasattr(self, "done"):
                return []
            self.done = True
            return ["event"]

        def render_metadata(self, render_context, event_handle):
            return raw

        def close(self, handle):
            pass

    payload = windows_events_payload(WINDOWS, native=Native())
    assert payload["status"] == "ok"
    assert payload["events"] == [
        {
            "provider": "disk",
            "event_id": 153,
            "level": "warning",
            "time_created_utc": "2026-07-15T05:30:00.0000007Z",
            "record_id": 53672,
            "task": 7,
            "opcode": 0,
            "keywords": 0x80000000000000,
        }
    ]
    assert payload["summary"]["unknown"] == 0


@pytest.mark.parametrize(
    ("index", "variant"),
    [
        (0, _variant(EVT_VAR_TYPE_NULL)),
        (1, _variant(EVT_VAR_TYPE_UINT32, "UInt32Val", 153)),
        (2, _variant(EVT_VAR_TYPE_UINT16, "UInt16Val", 3)),
        (3, _variant(EVT_VAR_TYPE_STRING, "StringVal", None)),
        (4, _variant(EVT_VAR_TYPE_UINT16, "UInt16Val", 1)),
    ],
)
def test_wrong_native_type_for_required_selected_properties_is_invalid(index: int, variant) -> None:
    variants, _ = _eight_property_variants()
    variants[index] = variant
    with pytest.raises(EventMetadataContractError):
        decode_selected_event_metadata(variants, 8)


@pytest.mark.parametrize(
    "raw",
    [
        RawEventMetadata("disk", -1, 3, "2026-07-15T05:30:00.0000000Z", 1),
        RawEventMetadata("disk", 65536, 3, "2026-07-15T05:30:00.0000000Z", 1),
        RawEventMetadata("disk", 153, 4, "2026-07-15T05:30:00.0000000Z", 1),
        RawEventMetadata("disk", 153, 3, None, 1),
        RawEventMetadata("disk", 153, 3, "2026-07-15T05:30:00.0000000Z", 0),
    ],
)
def test_required_property_out_of_range_or_missing_omits_event(raw: RawEventMetadata) -> None:
    class Native:
        def query(self, query_text):
            return "query"

        def create_render_context(self, property_paths):
            return "context"

        def next(self, query_handle, count):
            if hasattr(self, "done"):
                return []
            self.done = True
            return ["event"]

        def render_metadata(self, render_context, event_handle):
            return raw

        def close(self, handle):
            pass

    payload = windows_events_payload(WINDOWS, native=Native())
    assert payload["status"] == "partial"
    assert payload["events"] == []
    assert payload["summary"]["events_returned"] == 0
    assert payload["warnings"]


def test_optional_property_wrong_type_or_out_of_range_is_omitted_with_bounded_warning() -> None:
    class Native:
        def __init__(self):
            self.done = False

        def query(self, query_text):
            return "query"

        def create_render_context(self, property_paths):
            return "context"

        def next(self, query_handle, count):
            if self.done:
                return []
            self.done = True
            return ["event"]

        def render_metadata(self, render_context, event_handle):
            return RawEventMetadata(
                "disk", 153, 3, "2026-07-15T05:30:00.0000000Z", 53672, task="bad", opcode=999
            )

        def close(self, handle):
            pass

    payload = windows_events_payload(WINDOWS, native=Native())
    assert payload["status"] == "ok"
    assert payload["events"][0] == {
        "provider": "disk",
        "event_id": 153,
        "level": "warning",
        "time_created_utc": "2026-07-15T05:30:00.0000000Z",
        "record_id": 53672,
    }
    assert {w["category"] for w in payload["warnings"]} == {
        "optional_opcode_omitted",
        "optional_task_omitted",
    }


def test_acceptance_rejects_live_corruption_artifact() -> None:
    import importlib.util
    import sys
    from pathlib import Path

    script = Path(__file__).parents[1] / "scripts" / "windows_smoke_acceptance.py"
    spec = importlib.util.spec_from_file_location("windows_smoke_acceptance", script)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _validate_events_artifact = module._validate_events_artifact

    payload = {
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
        "summary": {"events_returned": 1, "unknown": 1},
        "top_provider_event_pairs": [
            {"provider": "disk", "event_id": 737179140249, "level": "unknown", "count": 1}
        ],
        "events": [
            {
                "provider": "disk",
                "event_id": 737179140249,
                "level": "unknown",
                "time_created_utc": "2026-07-15T05:30:00.0000000Z",
                "record_id": 53672,
                "task": 737179140096,
                "opcode": 737179185408,
            }
        ],
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
    failed = {check.name for check in _validate_events_artifact(payload) if not check.passed}
    assert "events.item_0.event_id" in failed
    assert "events.item_0.level" in failed
    assert "events.item_0.task" in failed
    assert "events.item_0.opcode" in failed
    assert "events.summary_unknown_zero" in failed
