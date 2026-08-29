"""Focused coverage for bounded native Windows working-set evidence."""

from __future__ import annotations

import ctypes

import pytest

from shellforgeai.core import windows_evidence_context as evidence_context
from shellforgeai.core.windows_evidence_context import _processes_context
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_processes import (
    _query_process_working_set_bytes,
    render_windows_processes_text,
    windows_processes_payload,
)

WINDOWS = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
LINUX = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")


def rows(count: int = 3) -> list[dict[str, object]]:
    return [
        {"pid": n + 10, "parent_pid": 4, "name": f"p{n}.exe", "thread_count": n + 1}
        for n in range(count)
    ]


def test_success_zero_and_unavailable_are_distinct_and_collection_continues() -> None:
    def observe(pid: int) -> int:
        if pid == 10:
            return 4096
        if pid == 11:
            return 0
        raise PermissionError("protected process")

    payload = windows_processes_payload(
        WINDOWS, process_enumerator=rows, working_set_observer=observe
    )
    first, zero, unavailable = payload["processes"]
    assert first["working_set_available"] is True
    assert first["working_set_bytes"] == 4096
    assert zero["working_set_available"] is True and zero["working_set_bytes"] == 0
    assert unavailable["working_set_available"] is False
    assert unavailable["working_set_bytes"] is None
    assert payload["returned_count"] == 3


@pytest.mark.parametrize("error", [ProcessLookupError("exited"), OSError("query failed")])
def test_race_and_other_row_errors_are_unknown_without_traceback(error: Exception) -> None:
    payload = windows_processes_payload(
        WINDOWS,
        process_enumerator=lambda: rows(1),
        working_set_observer=lambda _pid: (_ for _ in ()).throw(error),
    )
    assert payload["status"] == "ok"
    assert payload["processes"][0]["working_set_bytes"] is None
    assert "Traceback" not in render_windows_processes_text(payload)


def test_enrichment_is_after_selection_and_bounded_by_returned_limit() -> None:
    calls: list[int] = []
    payload = windows_processes_payload(
        WINDOWS,
        process_enumerator=lambda: rows(20),
        working_set_observer=lambda pid: calls.append(pid) or pid,
        limit=4,
    )
    assert len(calls) == payload["returned_count"] == payload["limit"] == 4


def test_enumeration_failure_and_non_windows_never_query_resource_counter() -> None:
    def forbidden(_pid: int) -> int:
        pytest.fail("no row exists to enrich")

    failed = windows_processes_payload(
        WINDOWS,
        process_enumerator=lambda: (_ for _ in ()).throw(OSError("snapshot failed")),
        working_set_observer=forbidden,
    )
    assert failed["state"]["enumeration_failed"] and failed["processes"] == []
    unsupported = windows_processes_payload(
        LINUX,
        process_enumerator=lambda: pytest.fail("no enumeration"),
        working_set_observer=forbidden,
    )
    assert unsupported["status"] == "unsupported"


class _Function:
    def __init__(self, implementation):
        object.__setattr__(self, "implementation", implementation)

    def __call__(self, *args):
        return self.implementation(*args)


def test_native_query_uses_limited_right_and_closes_handle_on_success_and_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opens: list[tuple[int, bool, int]] = []
    closes: list[int] = []
    query_ok = [True]
    kernel32 = type("Kernel", (), {})()
    kernel32.OpenProcess = _Function(
        lambda right, inherit, pid: opens.append((right, inherit, pid)) or 99
    )
    kernel32.CloseHandle = _Function(lambda handle: closes.append(handle) or 1)

    def get_memory(_handle, pointer, _size):
        pointer._obj.WorkingSetSize = 8192
        return int(query_ok[0])

    psapi = type("Psapi", (), {})()
    psapi.GetProcessMemoryInfo = _Function(get_memory)
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda name, **_kwargs: kernel32 if name == "kernel32" else psapi,
        raising=False,
    )
    assert _query_process_working_set_bytes(44) == 8192
    assert opens == [(0x1000, False, 44)] and closes == [99]
    query_ok[0] = False
    with pytest.raises(OSError):
        _query_process_working_set_bytes(45)
    assert closes == [99, 99]


def test_human_and_evidence_projection_preserve_identity_zero_and_unknown() -> None:
    payload = windows_processes_payload(
        WINDOWS,
        process_enumerator=lambda: rows(2),
        working_set_observer=lambda pid: 0 if pid == 10 else (_ for _ in ()).throw(OSError()),
    )
    output = render_windows_processes_text(payload)
    assert "working_set_bytes=0" in output
    assert "working_set_bytes=unavailable" in output
    output.encode("cp1252", errors="strict")
    context = _processes_context(payload, 2)
    assert context["entries"][0] == {
        "pid": 10,
        "parent_pid": 4,
        "name": "p0.exe",
        "thread_count": 1,
        "working_set_bytes": 0,
    }
    assert context["entries"][1]["working_set_bytes"] is None


def test_safety_metadata_distinguishes_counter_query_from_memory_content_reads() -> None:
    safety = windows_processes_payload(
        WINDOWS, process_enumerator=lambda: rows(1), working_set_observer=lambda _pid: 1
    )["safety"]
    assert safety["read_only"] is True and safety["mutation_performed"] is False
    assert safety["process_working_set_queried"] is True
    assert safety["process_query_handles_opened"] is True
    assert safety["process_memory_read"] is False


def test_packet_states_point_in_time_cpu_and_no_diagnosis_limitations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_payload = windows_processes_payload(
        WINDOWS, process_enumerator=lambda: rows(1), working_set_observer=lambda _pid: 7
    )
    monkeypatch.setattr(evidence_context, "detect_platform", lambda: WINDOWS)
    monkeypatch.setattr(
        evidence_context,
        "windows_status_payload",
        lambda _info: {"host": {}, "platform": {}, "python_runtime": {}},
    )
    monkeypatch.setattr(
        evidence_context, "windows_processes_payload", lambda *_args, **_kw: process_payload
    )
    for name in (
        "windows_memory_payload",
        "windows_disks_payload",
        "windows_services_payload",
        "windows_events_payload",
        "windows_network_payload",
        "windows_volumes_payload",
    ):
        monkeypatch.setattr(evidence_context, name, lambda *_args, **_kwargs: {})

    packet = evidence_context.build_windows_evidence_context()
    limitations = " ".join(packet["limitations"])
    assert "point-in-time" in limitations
    assert "unavailable means unknown, not zero" in limitations
    assert "per-process CPU attribution are not collected" in limitations
    assert "does not prove unhealthy" in limitations
    assert "no automatic threshold, ranking, or diagnosis" in limitations
