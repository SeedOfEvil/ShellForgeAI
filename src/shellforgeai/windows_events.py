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


def _normalize_event(raw: RawEventMetadata) -> tuple[dict[str, Any], str | None]:
    event_id = _int_or_none(raw.event_id, minimum=0)
    if event_id is None:
        event_id = 0
    item: dict[str, Any] = {
        "provider": _sanitize_provider(raw.provider),
        "event_id": event_id,
        "level": normalize_level(raw.level),
        "time_created_utc": normalize_timestamp(raw.time_created_utc),
        "record_id": _int_or_none(raw.record_id, minimum=1),
    }
    for key in ("task", "opcode", "keywords"):
        numeric = _int_or_none(getattr(raw, key), minimum=0)
        if numeric is not None:
            item[key] = numeric
    warning = (
        None
        if item["level"] in LEVELS
        else "An event had an unexpected level and was normalized as unknown."
    )
    return item, warning


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
                    item, warning = _normalize_event(
                        native.render_metadata(render_context, event_handle)
                    )
                    events.append(item)
                    if warning and warning not in payload["warnings"]:
                        payload["warnings"].append(warning)
                except Exception as exc:
                    msg = (
                        "One event could not be rendered as selected metadata: "
                        f"{type(exc).__name__}."
                    )
                    if msg not in payload["warnings"]:
                        payload["warnings"].append(msg)
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
    summary, top = _summary(events, truncated, since_hours, limit)
    payload.setdefault("status", "ok")
    payload["summary"] = summary
    payload["top_provider_event_pairs"] = top
    payload["events"] = events
    return payload


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

        class EVT_VARIANT(ctypes.Structure):
            _fields_ = [
                ("value", ctypes.c_ulonglong),
                ("count", ctypes.c_ulong),
                ("type", ctypes.c_ulong),
            ]

        variants = ctypes.cast(raw, ctypes.POINTER(EVT_VARIANT))
        values = [
            self._variant_value(variants[i])
            for i in range(min(property_count.value, len(SYSTEM_PROPERTY_PATHS)))
        ]
        values.extend([None] * (len(SYSTEM_PROPERTY_PATHS) - len(values)))
        return RawEventMetadata(*values[:8])

    @staticmethod
    def _variant_value(variant: Any) -> Any:
        variant_type = int(variant.type) & 0x7F
        if variant_type == 0:
            return None
        if variant_type == 1:  # EvtVarTypeString
            return ctypes.wstring_at(variant.value) if variant.value else None
        if variant_type in {4, 5, 6, 7, 8, 9, 10}:
            return int(variant.value)
        if variant_type == 17:  # EvtVarTypeFileTime
            windows_epoch_offset = 116444736000000000
            seconds = (int(variant.value) - windows_epoch_offset) / 10_000_000
            return datetime.fromtimestamp(seconds, UTC)
        return None

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
