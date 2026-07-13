from __future__ import annotations

from types import SimpleNamespace

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_volumes import render_windows_volumes_text, windows_volumes_payload

WINDOWS = PlatformInfo(
    system="windows", python_platform="Windows", os_name="nt", release="2025", machine="AMD64"
)


def part(device, mountpoint, fstype="NTFS", opts="fixed,rw"):
    return SimpleNamespace(device=device, mountpoint=mountpoint, fstype=fstype, opts=opts)


def usage(total, used, free):
    return SimpleNamespace(total=total, used=used, free=free)


def test_cli_registration_help_and_prior_commands_available():
    result = CliRunner().invoke(app, ["windows", "--help"])
    assert result.exit_code == 0
    out = result.output.lower()
    assert "volumes" in out
    assert "disks" in out and "memory" in out and "network" in out
    help_result = CliRunner().invoke(app, ["windows", "volumes", "--help"])
    assert help_result.exit_code == 0
    assert "--json" in help_result.output
    assert "--limit" in help_result.output


def test_text_output_is_safe():
    payload = windows_volumes_payload(
        WINDOWS,
        partition_source=lambda: [part("C:\\", "C:\\", "NTFS", "fixed,rw")],
        disk_usage=lambda _: usage(1024**3, 0, 1024**3),
    )
    text = render_windows_volumes_text(payload).lower()
    assert "c:\\" in text and "ntfs" in text and "fixed" in text and "read-write" in text
    assert "format" not in text and "repair" not in text and "volume{" not in text
