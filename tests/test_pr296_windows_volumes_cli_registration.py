from __future__ import annotations

from types import SimpleNamespace

import pytest

from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_volumes import (
    classify_access,
    classify_volume_kind,
    validate_volumes_limit,
    windows_volumes_payload,
)

WINDOWS = PlatformInfo(
    system="windows", python_platform="Windows", os_name="nt", release="2025", machine="AMD64"
)
LINUX = PlatformInfo(
    system="linux", python_platform="Linux", os_name="posix", release="", machine=""
)


def part(device, mountpoint, fstype="NTFS", opts="fixed,rw"):
    return SimpleNamespace(device=device, mountpoint=mountpoint, fstype=fstype, opts=opts)


def usage(total, used, free):
    return SimpleNamespace(total=total, used=used, free=free)


def test_successful_local_volume_collection_sorting_summary_and_safety():
    calls = []
    parts = [part("D:\\", "D:\\", "ReFS"), part("C:\\", "C:\\", "NTFS")]

    def disk_usage(mount):
        calls.append(mount)
        return {"C:\\": usage(100, 25, 75), "D:\\": usage(200, 50, 150)}[mount]

    payload = windows_volumes_payload(
        WINDOWS, partition_source=lambda: parts, disk_usage=disk_usage
    )
    assert payload["mode"] == "windows_volumes"
    assert [v["drive"] for v in payload["volumes"]] == ["C:", "D:"]
    assert calls == ["C:\\", "D:\\"]
    assert payload["volumes"][0]["filesystem"] == "NTFS"
    assert payload["volumes"][0]["kind"] == "fixed"
    assert payload["volumes"][0]["access"] == "read_write"
    assert payload["volumes"][0]["total_bytes"] == 100
    assert payload["volumes"][0]["used_percent"] == 25.0
    assert payload["summary"]["partitions_observed"] == 2
    assert payload["summary"]["returned_volumes"] == 2
    assert payload["summary"]["available_volumes"] == 2
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["safety"]["model_called"] is False
    assert payload["safety"]["shell_true"] is False


@pytest.mark.parametrize(
    ("opts", "kind"),
    [
        ("fixed", "fixed"),
        ("removable", "removable"),
        ("cdrom", "cdrom"),
        ("ramdisk", "ramdisk"),
        ("", "unknown"),
    ],
)
def test_kind_classification(opts, kind):
    assert classify_volume_kind({opts} if opts else set()) == kind


@pytest.mark.parametrize(
    ("opts", "access"),
    [("rw", "read_write"), ("ro", "read_only"), ("", "unknown")],
)
def test_access_classification(opts, access):
    assert classify_access({opts} if opts else set()) == access


def test_usage_failure_keeps_metadata_and_sanitizes_error():
    payload = windows_volumes_payload(
        WINDOWS,
        partition_source=lambda: [part("E:\\", "E:\\", "UDF", "cdrom,ro")],
        disk_usage=lambda _mount: (_ for _ in ()).throw(OSError("E:\\ secret path")),
    )
    volume = payload["volumes"][0]
    assert volume["drive"] == "E:"
    assert volume["kind"] == "cdrom"
    assert volume["access"] == "read_only"
    assert volume["status"] == "unavailable"
    assert volume["error"] == "disk_usage_failed"
    assert "secret path" not in str(payload).lower()


def test_remote_guid_and_folder_mounts_skipped_before_usage_and_not_emitted():
    calls = []
    parts = [
        part("Z:\\", "Z:\\", opts="remote,rw"),
        part("\\\\server\\share", "\\\\server\\share", opts="remote"),
        part(
            "\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\",
            "\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\",
        ),
        part("C:\\mounts\\data", "C:\\mounts\\data"),
        part("C:\\", "C:\\"),
    ]

    def disk_usage(mount):
        calls.append(mount)
        return usage(10, 1, 9)

    payload = windows_volumes_payload(
        WINDOWS, partition_source=lambda: parts, disk_usage=disk_usage
    )
    assert calls == ["C:\\"]
    assert payload["summary"]["skipped_remote"] == 2
    assert payload["summary"]["skipped_unsafe_identifier"] == 1
    assert payload["summary"]["skipped_non_drive_root"] == 1
    emitted = str(payload).lower()
    assert "server" not in emitted
    assert "volume{" not in emitted
    assert "mounts" not in emitted


def test_deduplication_limit_truncation_capacity_edges():
    parts = [part("c:\\", "c:\\"), part("C:\\", "C:\\"), part("D:\\", "D:\\"), part("E:\\", "E:\\")]
    payload = windows_volumes_payload(
        WINDOWS,
        partition_source=lambda: parts,
        disk_usage=lambda mount: usage(0, 0, 0) if mount == "C:\\" else usage(100, 100, 0),
        limit=2,
    )
    assert [v["drive"] for v in payload["volumes"]] == ["C:", "D:"]
    assert payload["collection"]["truncated"] is True
    assert payload["volumes"][0]["used_percent"] is None
    assert payload["volumes"][1]["used_percent"] == 100.0


@pytest.mark.parametrize("bad", [0, 65, True, "abc"])
def test_invalid_limits_fail_clearly(bad):
    with pytest.raises(ValueError):
        validate_volumes_limit(bad)


def test_unsupported_platform_does_not_call_collector():
    def boom():
        raise AssertionError("collector called")

    payload = windows_volumes_payload(
        LINUX, partition_source=boom, disk_usage=lambda _: usage(1, 0, 1)
    )
    assert payload["status"] == "unsupported"
    assert payload["read_only"] is True
    assert payload["summary"]["returned_volumes"] == 0
