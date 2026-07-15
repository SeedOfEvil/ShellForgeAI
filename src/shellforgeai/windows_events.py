"""Bounded read-only Windows System Event Log metadata collector.

This module intentionally collects only selected System-channel metadata through
local wevtapi calls. It never renders messages or XML, reads payload data,
opens remote sessions, subscribes, exports, clears, writes, invokes shells, or
calls models/network services.
"""

from __future__ import annotations

import ctypes
import os
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from shellforgeai.platform_detection import PlatformInfo, detect_platform

DEFAULT_EVENTS_LIMIT = 50
MIN_EVENTS_LIMIT = 1
MAX_EVENTS_LIMIT = 200
DEFAULT_SINCE_HOURS = 24
MIN_SINCE_HOURS = 1
MAX_SINCE_HOURS = 168
PROVIDER_MAX_LENGTH = 256
METHOD = "wevtapi_system_metadata"
SYSTEM_CHANNEL = "System"
LEVELS = ["critical", "error", "warning"]
SYSTEM_PROPERTY_PATHS = (
    "Event/System/Provider/@Name",
    "Event/System/EventID",
    "Event/System/Level",
    "Event/System/TimeCreated/@SystemTime",
    "Event/System/EventRecordID",
    "Event/System/Task",
    "Event/System/Opcode",
    "Event/System/Keywords",
)

EVT_VAR_TYPE_NULL = 0
EVT_VAR_TYPE_STRING = 1
EVT_VAR_TYPE_ANSI_STRING = 2
EVT_VAR_TYPE_SBYTE = 3
EVT_VAR_TYPE_BYTE = 4
EVT_VAR_TYPE_INT16 = 5
EVT_VAR_TYPE_UINT16 = 6
EVT_VAR_TYPE_INT32 = 7
EVT_VAR_TYPE_UINT32 = 8
EVT_VAR_TYPE_INT64 = 9
EVT_VAR_TYPE_UINT64 = 10
EVT_VAR_TYPE_SINGLE = 11
EVT_VAR_TYPE_DOUBLE = 12
EVT_VAR_TYPE_BOOLEAN = 13
EVT_VAR_TYPE_BINARY = 14
EVT_VAR_TYPE_GUID = 15
EVT_VAR_TYPE_SIZE_T = 16
EVT_VAR_TYPE_FILETIME = 17
EVT_VAR_TYPE_SYS_TIME = 18
EVT_VAR_TYPE_SID = 19
EVT_VAR_TYPE_HEX_INT32 = 20
EVT_VAR_TYPE_HEX_INT64 = 21
EVT_VARIANT_TYPE_ARRAY = 0x80
EVT_VARIANT_TYPE_MASK = 0x7F
_WINDOWS_FILETIME_EPOCH_OFFSET = 116444736000000000


class EvtVariantValue(ctypes.Union):
    _fields_ = [
        ("StringVal", ctypes.c_wchar_p),
        ("AnsiStringVal", ctypes.c_char_p),
        ("SByteVal", ctypes.c_int8),
        ("ByteVal", ctypes.c_uint8),
        ("Int16Val", ctypes.c_int16),
        ("UInt16Val", ctypes.c_uint16),
        ("Int32Val", ctypes.c_int32),
        ("UInt32Val", ctypes.c_uint32),
        ("Int64Val", ctypes.c_int64),
        ("UInt64Val", ctypes.c_uint64),
        ("SingleVal", ctypes.c_float),
        ("DoubleVal", ctypes.c_double),
        ("BooleanVal", ctypes.c_int32),
        ("BinaryVal", ctypes.c_void_p),
        ("GuidVal", ctypes.c_void_p),
        ("SizeTVal", ctypes.c_size_t),
        ("FileTimeVal", ctypes.c_uint64),
        ("SysTimeVal", ctypes.c_void_p),
        ("SidVal", ctypes.c_void_p),
        ("HexInt32Val", ctypes.c_uint32),
        ("HexInt64Val", ctypes.c_uint64),
    ]


class EVT_VARIANT(ctypes.Structure):
    _fields_ = [
        ("value", EvtVariantValue),
        ("Count", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
    ]


class EventMetadataContractError(ValueError):
    """Selected Event Log metadata did not match the PR298 scalar contract."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


_EVENT_SAFETY = {
    "read_only": True,
    "mutation_performed": False,
    "powershell_executed": False,
    "winrm_used": False,
    "remote_execution": False,
    "shell_true": False,
    "arbitrary_command_execution": False,
    "event_log_write_performed": False,
    "event_log_clear_performed": False,
    "event_log_export_performed": False,
    "event_subscription_created": False,
    "registry_modified": False,
    "service_control_executed": False,
    "process_termination_executed": False,
    "cleanup_executed": False,
    "remediation_executed": False,
    "rollback_executed": False,
    "recovery_executed": False,
    "secret_read": False,
    "auth_cache_read": False,
    "model_called": False,
    "network_call": False,
}
_LIMITATIONS = [
    "Only local System-channel Critical, Error, and Warning metadata was queried.",
    (
        "No rendered messages, EventData, UserData, XML, identities, remote logs, "
        "or Event Log changes were performed."
    ),
]


@dataclass(frozen=True)
class RawEventMetadata:
    provider: Any = None
    event_id: Any = None
    level: Any = None
    time_created_utc: Any = None
    record_id: Any = None
    task: Any = None
    opcode: Any = None
    keywords: Any = None


class WindowsEventNative(Protocol):
    def query(self, query_text: str) -> Any: ...
    def create_render_context(self, property_paths: tuple[str, ...]) -> Any: ...
    def next(self, query_handle: Any, count: int) -> list[Any]: ...
    def render_metadata(self, render_context: Any, event_handle: Any) -> RawEventMetadata: ...
    def close(self, handle: Any) -> None: ...


def validate_events_limit(value: int) -> int:
    try:
        numeric = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"--limit must be an integer, got {value!r}") from exc
    if isinstance(value, bool) or numeric < MIN_EVENTS_LIMIT or numeric > MAX_EVENTS_LIMIT:
        raise ValueError(
            f"--limit must be between {MIN_EVENTS_LIMIT} and {MAX_EVENTS_LIMIT}, got {value!r}"
        )
    return numeric


def validate_since_hours(value: int) -> int:
    try:
        numeric = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"--since-hours must be an integer, got {value!r}") from exc
    if isinstance(value, bool) or numeric < MIN_SINCE_HOURS or numeric > MAX_SINCE_HOURS:
        raise ValueError(
            f"--since-hours must be between {MIN_SINCE_HOURS} and {MAX_SINCE_HOURS}, got {value!r}"
        )
    return numeric


def build_system_events_query(since_hours: int, now: datetime | None = None) -> str:
    since_hours = validate_since_hours(since_hours)
    now = now.astimezone(UTC) if now else datetime.now(UTC)
    since = now - timedelta(hours=since_hours)
    since_text = since.isoformat(timespec="seconds").replace("+00:00", "Z")
    return (
        f"*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[@SystemTime >= '{since_text}']]]"
    )


def _sanitize_provider(value: Any) -> str:
    text = "unknown" if value in (None, "") else str(value)
    text = re.sub(r"[\x00-\x1f\x7f]+", "?", text).strip() or "unknown"
    return text[:PROVIDER_MAX_LENGTH]


def _int_or_none(value: Any, *, minimum: int | None = None) -> int | None:
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        return None
    if minimum is not None and numeric < minimum:
        return None
    return numeric


def normalize_level(value: Any) -> str:
    return {1: "critical", 2: "error", 3: "warning"}.get(_int_or_none(value), "unknown")


def normalize_timestamp(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=UTC)
    else:
        text = str(value).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _require_int_range(value: Any, *, field: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise EventMetadataContractError(f"invalid_required_{field}")
    if value < minimum or value > maximum:
        raise EventMetadataContractError(f"invalid_required_{field}")
    return value


def _optional_int_range(
    value: Any, *, field: str, minimum: int, maximum: int
) -> tuple[int | None, str | None]:
    if value is None:
        return None, None
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum or value > maximum:
        return None, f"optional_{field}_omitted"
    return value, None


def _normalize_event(raw: RawEventMetadata) -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    if not isinstance(raw.provider, str) or raw.provider == "":
        raise EventMetadataContractError("invalid_required_provider")
    event_id = _require_int_range(raw.event_id, field="event_id", minimum=0, maximum=65535)
    numeric_level = _require_int_range(raw.level, field="level", minimum=1, maximum=3)
    level = normalize_level(numeric_level)
    if level == "unknown":
        raise EventMetadataContractError("invalid_required_level")
    time_created_utc = normalize_timestamp(raw.time_created_utc)
    if time_created_utc is None:
        raise EventMetadataContractError("invalid_required_time_created_utc")
    record_id = _require_int_range(raw.record_id, field="record_id", minimum=1, maximum=(2**64) - 1)
    item: dict[str, Any] = {
        "provider": _sanitize_provider(raw.provider),
        "event_id": event_id,
        "level": level,
        "time_created_utc": time_created_utc,
        "record_id": record_id,
    }
    for key, maximum in (("task", 65535), ("opcode", 255), ("keywords", (2**64) - 1)):
        numeric, warning = _optional_int_range(
            getattr(raw, key), field=key, minimum=0, maximum=maximum
        )
        if numeric is not None:
            item[key] = numeric
        if warning:
            warnings.append(warning)
    return item, warnings


def _bounded_warning(category: str, count: int) -> dict[str, Any]:
    return {"category": category, "count": count}


def _sort_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(e: dict[str, Any]) -> tuple[str, int, str, int]:
        return (
            str(e.get("time_created_utc") or ""),
            int(e.get("record_id") or 0),
            str(e.get("provider") or "").casefold(),
            int(e.get("event_id") or 0),
        )

    return sorted(events, key=key, reverse=True)


def _summary(
    events: list[dict[str, Any]], truncated: bool, since_hours: int, limit: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    counts = Counter(str(e.get("level", "unknown")) for e in events)
    pairs: dict[tuple[str, int, str], dict[str, Any]] = {}
    for e in events:
        k = (str(e["provider"]), int(e["event_id"]), str(e["level"]))
        row = pairs.setdefault(
            k,
            {
                "provider": k[0],
                "event_id": k[1],
                "level": k[2],
                "count": 0,
                "most_recent_utc": None,
            },
        )
        row["count"] += 1
        ts = e.get("time_created_utc")
        if ts and (row["most_recent_utc"] is None or ts > row["most_recent_utc"]):
            row["most_recent_utc"] = ts
    top = sorted(
        pairs.values(),
        key=lambda r: (
            -int(r["count"]),
            str(r.get("most_recent_utc") or ""),
            str(r["provider"]).casefold(),
            int(r["event_id"]),
        ),
        reverse=False,
    )[:10]
    return {
        "events_returned": len(events),
        "critical": counts.get("critical", 0),
        "error": counts.get("error", 0),
        "warning": counts.get("warning", 0),
        "unknown": counts.get("unknown", 0),
        "providers_observed": len({e["provider"] for e in events}),
        "provider_event_pairs_observed": len(pairs),
        "truncated": truncated,
        "since_hours": since_hours,
        "limit": limit,
    }, top


def _base_payload(info: PlatformInfo, since_hours: int, limit: int) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "windows_events",
        "platform": {"system": info.system},
        "read_only": True,
        "mutation_performed": False,
        "collection": {
            "method": METHOD,
            "channel": SYSTEM_CHANNEL,
            "levels": list(LEVELS),
            "since_hours": since_hours,
            "limit": limit,
            "truncated": False,
            "rendered_messages_collected": False,
            "event_xml_collected": False,
            "event_data_collected": False,
            "user_data_collected": False,
            "remote_session_used": False,
        },
        "limitations": list(_LIMITATIONS),
        "warnings": [],
        "errors": [],
        "safety": dict(_EVENT_SAFETY),
    }


def windows_events_unsupported_payload(
    info: PlatformInfo | None = None,
    *,
    since_hours: int = DEFAULT_SINCE_HOURS,
    limit: int = DEFAULT_EVENTS_LIMIT,
) -> dict[str, Any]:
    info = info or detect_platform()
    payload = _base_payload(info, validate_since_hours(since_hours), validate_events_limit(limit))
    payload.update(
        {
            "status": "unsupported",
            "reason": "Windows System Event metadata is only available on Windows hosts.",
        }
    )
    return payload


def windows_events_payload(
    info: PlatformInfo | None = None,
    *,
    native: WindowsEventNative | None = None,
    limit: int = DEFAULT_EVENTS_LIMIT,
    since_hours: int = DEFAULT_SINCE_HOURS,
    now: datetime | None = None,
) -> dict[str, Any]:
    info = info or detect_platform()
    limit = validate_events_limit(limit)
    since_hours = validate_since_hours(since_hours)
    if info.system != "windows":
        return windows_events_unsupported_payload(info, since_hours=since_hours, limit=limit)
    payload = _base_payload(info, since_hours, limit)
    query_text = build_system_events_query(since_hours, now=now)
    native = native or CtypesWevtapi()
    query_handle = render_context = None
    events: list[dict[str, Any]] = []
    warning_counts: Counter[str] = Counter()
    truncated = False
    try:
        query_handle = native.query(query_text)
        render_context = native.create_render_context(SYSTEM_PROPERTY_PATHS)
        while len(events) <= limit:
            handles = native.next(query_handle, 1)
            if not handles:
                break
            for event_handle in handles:
                try:
                    if len(events) >= limit:
                        truncated = True
                        break
                    item, item_warnings = _normalize_event(
                        native.render_metadata(render_context, event_handle)
                    )
                    events.append(item)
                    warning_counts.update(item_warnings)
                except EventMetadataContractError as exc:
                    warning_counts.update([exc.category])
                except Exception:
                    warning_counts.update(["render_metadata_failed"])
                finally:
                    native.close(event_handle)
            if truncated:
                break
    except Exception as exc:
        payload["status"] = "error"
        payload["errors"].append(
            {
                "type": type(exc).__name__,
                "message": "Windows Event Log metadata collection failed.",
                "winerror": getattr(exc, "winerror", None),
            }
        )
        events = []
    finally:
        if render_context is not None:
            native.close(render_context)
        if query_handle is not None:
            native.close(query_handle)
    events = _sort_events(events)[:limit]
    payload["collection"]["truncated"] = truncated
    payload["warnings"] = [
        _bounded_warning(category, warning_counts[category]) for category in sorted(warning_counts)
    ]
    summary, top = _summary(events, truncated, since_hours, limit)
    if payload.get("status") != "error" and not events and warning_counts:
        payload["status"] = "partial"
        payload["errors"].append(
            {
                "type": "metadata_contract",
                "message": (
                    "Windows Event Log metadata was present but failed "
                    "the selected metadata contract."
                ),
                "winerror": None,
            }
        )
    payload.setdefault("status", "ok")
    payload["summary"] = summary
    payload["top_provider_event_pairs"] = top
    payload["events"] = events
    return payload


def decode_evt_variant(variant: EVT_VARIANT) -> Any:
    raw_type = int(variant.Type)
    if raw_type & EVT_VARIANT_TYPE_ARRAY:
        raise EventMetadataContractError("array_variant_unsupported")
    base_type = raw_type & EVT_VARIANT_TYPE_MASK
    value = variant.value
    if base_type == EVT_VAR_TYPE_NULL:
        return None
    if base_type == EVT_VAR_TYPE_STRING:
        return ctypes.wstring_at(value.StringVal) if value.StringVal else None
    if base_type == EVT_VAR_TYPE_ANSI_STRING:
        return value.AnsiStringVal.decode("utf-8", "replace") if value.AnsiStringVal else None
    if base_type == EVT_VAR_TYPE_SBYTE:
        return int(value.SByteVal)
    if base_type == EVT_VAR_TYPE_BYTE:
        return int(value.ByteVal)
    if base_type == EVT_VAR_TYPE_INT16:
        return int(value.Int16Val)
    if base_type == EVT_VAR_TYPE_UINT16:
        return int(value.UInt16Val)
    if base_type == EVT_VAR_TYPE_INT32:
        return int(value.Int32Val)
    if base_type == EVT_VAR_TYPE_UINT32:
        return int(value.UInt32Val)
    if base_type == EVT_VAR_TYPE_INT64:
        return int(value.Int64Val)
    if base_type == EVT_VAR_TYPE_UINT64:
        return int(value.UInt64Val)
    if base_type == EVT_VAR_TYPE_SINGLE:
        return float(value.SingleVal)
    if base_type == EVT_VAR_TYPE_DOUBLE:
        return float(value.DoubleVal)
    if base_type == EVT_VAR_TYPE_BOOLEAN:
        return bool(value.BooleanVal)
    if base_type == EVT_VAR_TYPE_SIZE_T:
        return int(value.SizeTVal)
    if base_type == EVT_VAR_TYPE_FILETIME:
        filetime = int(value.FileTimeVal)
        try:
            seconds = (filetime - _WINDOWS_FILETIME_EPOCH_OFFSET) / 10_000_000
            return datetime.fromtimestamp(seconds, UTC)
        except (OSError, OverflowError, ValueError) as exc:
            raise EventMetadataContractError("invalid_filetime") from exc
    if base_type == EVT_VAR_TYPE_HEX_INT32:
        return int(value.HexInt32Val)
    if base_type == EVT_VAR_TYPE_HEX_INT64:
        return int(value.HexInt64Val)
    raise EventMetadataContractError("unsupported_variant_type")


def _decode_expected_variant(
    variant: EVT_VARIANT, *, expected: int | tuple[int, ...], required: bool, field: str
) -> Any:
    raw_type = int(variant.Type)
    if raw_type & EVT_VARIANT_TYPE_ARRAY:
        raise EventMetadataContractError(f"array_{field}")
    base_type = raw_type & EVT_VARIANT_TYPE_MASK
    if base_type == EVT_VAR_TYPE_NULL:
        if required:
            raise EventMetadataContractError(f"invalid_required_{field}")
        return None
    expected_types = expected if isinstance(expected, tuple) else (expected,)
    if base_type not in expected_types:
        if required:
            raise EventMetadataContractError(f"invalid_required_{field}")
        raise EventMetadataContractError(f"optional_{field}_omitted")
    return decode_evt_variant(variant)


def _decode_optional_variant(
    variants: Any, index: int, *, expected: int | tuple[int, ...], field: str
) -> Any:
    try:
        return _decode_expected_variant(
            variants[index], expected=expected, required=False, field=field
        )
    except EventMetadataContractError as exc:
        if exc.category.startswith(f"optional_{field}_"):
            return None
        raise


def decode_selected_event_metadata(variants: Any, property_count: int) -> RawEventMetadata:
    if property_count < len(SYSTEM_PROPERTY_PATHS):
        raise EventMetadataContractError("missing_required_property")
    return RawEventMetadata(
        provider=_decode_expected_variant(
            variants[0], expected=EVT_VAR_TYPE_STRING, required=True, field="provider"
        ),
        event_id=_decode_expected_variant(
            variants[1], expected=EVT_VAR_TYPE_UINT16, required=True, field="event_id"
        ),
        level=_decode_expected_variant(
            variants[2], expected=EVT_VAR_TYPE_BYTE, required=True, field="level"
        ),
        time_created_utc=_decode_expected_variant(
            variants[3], expected=EVT_VAR_TYPE_FILETIME, required=True, field="time_created_utc"
        ),
        record_id=_decode_expected_variant(
            variants[4], expected=EVT_VAR_TYPE_UINT64, required=True, field="record_id"
        ),
        task=_decode_optional_variant(variants, 5, expected=EVT_VAR_TYPE_UINT16, field="task"),
        opcode=_decode_optional_variant(variants, 6, expected=EVT_VAR_TYPE_BYTE, field="opcode"),
        keywords=_decode_optional_variant(
            variants,
            7,
            expected=(EVT_VAR_TYPE_UINT64, EVT_VAR_TYPE_HEX_INT64),
            field="keywords",
        ),
    )


class CtypesWevtapi:
    """Tiny local wevtapi wrapper; initialized only after Windows platform check."""

    def __init__(self) -> None:
        self._wevtapi = ctypes.WinDLL("wevtapi", use_last_error=True)
        self._wevtapi.EvtQuery.restype = ctypes.c_void_p
        self._wevtapi.EvtNext.restype = ctypes.c_int
        self._wevtapi.EvtCreateRenderContext.restype = ctypes.c_void_p
        self._wevtapi.EvtRender.restype = ctypes.c_int
        self._wevtapi.EvtClose.restype = ctypes.c_int

    def query(self, query_text: str) -> Any:
        # EvtQueryChannelPath | EvtQueryReverseDirection
        handle = self._wevtapi.EvtQuery(None, SYSTEM_CHANNEL, query_text, 0x1 | 0x200)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def create_render_context(self, property_paths: tuple[str, ...]) -> Any:
        arr = (ctypes.c_wchar_p * len(property_paths))(*property_paths)
        # EvtRenderContextValues: selected System property paths only.
        handle = self._wevtapi.EvtCreateRenderContext(len(property_paths), arr, 0)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def next(self, query_handle: Any, count: int) -> list[Any]:
        arr = (ctypes.c_void_p * count)()
        returned = ctypes.c_ulong(0)
        ok = self._wevtapi.EvtNext(query_handle, count, arr, 0, 0, ctypes.byref(returned))
        if not ok:
            err = ctypes.get_last_error()
            if err == 259:  # ERROR_NO_MORE_ITEMS
                return []
            raise ctypes.WinError(err)
        return [arr[i] for i in range(returned.value)]

    def render_metadata(self, render_context: Any, event_handle: Any) -> RawEventMetadata:
        buffer_used = ctypes.c_ulong(0)
        property_count = ctypes.c_ulong(0)
        # EvtRenderEventValues renders only the selected property-path context.
        ok = self._wevtapi.EvtRender(
            render_context,
            event_handle,
            0,
            0,
            None,
            ctypes.byref(buffer_used),
            ctypes.byref(property_count),
        )
        if ok:
            raise RuntimeError("unexpected empty Event Log metadata render")
        err = ctypes.get_last_error()
        if err != 122:  # ERROR_INSUFFICIENT_BUFFER
            raise ctypes.WinError(err)
        raw = ctypes.create_string_buffer(buffer_used.value)
        ok = self._wevtapi.EvtRender(
            render_context,
            event_handle,
            0,
            buffer_used,
            raw,
            ctypes.byref(buffer_used),
            ctypes.byref(property_count),
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

        variants = ctypes.cast(raw, ctypes.POINTER(EVT_VARIANT))
        return decode_selected_event_metadata(variants, int(property_count.value))

    def close(self, handle: Any) -> None:
        if handle:
            self._wevtapi.EvtClose(handle)


def render_windows_events_text(payload: dict[str, Any]) -> str:
    lines = ["ShellForgeAI Windows System events", f"Status: {payload.get('status', 'unknown')}"]
    if payload.get("status") == "unsupported":
        lines.append(str(payload.get("reason")))
    s = payload.get("summary", {})
    c = payload.get("collection", {})
    lines.append(f"Window: last {c.get('since_hours', DEFAULT_SINCE_HOURS)} hours")
    lines.append(
        f"Events: {s.get('events_returned', 0)} returned; "
        f"critical={s.get('critical', 0)}; error={s.get('error', 0)}; "
        f"warning={s.get('warning', 0)}"
    )
    lines.append(f"Truncated: {str(c.get('truncated', False)).lower()}")
    events = payload.get("events", [])
    if events:
        lines.append("")
        lines.append("Recent metadata:")
        for e in events[:10]:
            lines.append(
                f"  {e.get('time_created_utc') or 'unavailable'}  {e.get('level')}  "
                f"{e.get('provider')}  event_id={e.get('event_id')}  "
                f"record_id={e.get('record_id')}"
            )
        if len(events) > 10:
            lines.append(f"  ... {len(events) - 10} additional events omitted")
    elif payload.get("status") == "ok":
        lines.append(
            "No matching System Critical/Error/Warning metadata was found in the requested window."
        )
    top = payload.get("top_provider_event_pairs", [])
    if top:
        lines.append("")
        lines.append("Top provider/Event ID pairs:")
        for row in top[:10]:
            lines.append(
                f"  {row.get('provider')} / {row.get('event_id')} / "
                f"{row.get('level')}: {row.get('count')}"
            )
        if len(top) > 10:
            lines.append(f"  ... {len(top) - 10} additional pairs omitted")
    lines.append("Read-only: true")
    lines.append(
        "Limitations: local System metadata only; no messages, payload data, XML, "
        "identities, remote logs, subscriptions, export, clear, or mutation."
    )
    if payload.get("warnings"):
        lines.append(f"Warnings: {len(payload['warnings'])}")
    if payload.get("errors"):
        lines.append("Errors: Windows Event Log metadata collection failed.")
    return os.linesep.join(lines)
