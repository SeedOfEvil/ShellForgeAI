from __future__ import annotations

import json
import socket
from collections import namedtuple
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_network import (
    MAX_ADDRESSES_PER_INTERFACE,
    MAX_INTERFACES,
    classify_ip_address,
    render_windows_network_text,
    windows_network_payload,
)

WINDOWS_INFO = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
LINUX_INFO = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")
Addr = namedtuple("Addr", "family address netmask broadcast ptp")
Stat = namedtuple("Stat", "isup duplex speed mtu flags")
Counter = namedtuple(
    "Counter", "bytes_sent bytes_recv packets_sent packets_recv errin errout dropin dropout"
)


def _sources(addrs=None, stats=None, counters=None):
    return (lambda: addrs or {}, lambda: stats or {}, lambda: counters or {})


def test_pr_specific_test_file_exists() -> None:
    assert Path("tests/test_pr295_windows_network_collector.py").exists()


def test_windows_network_cli_help_registered_and_prior_commands_remain() -> None:
    result = CliRunner().invoke(app, ["windows", "--help"])
    assert result.exit_code == 0
    for command in (
        "evidence",
        "status",
        "doctor",
        "memory",
        "disks",
        "processes",
        "services",
        "network",
    ):
        assert command in result.stdout
    network_help = CliRunner().invoke(app, ["windows", "network", "--help"])
    assert network_help.exit_code == 0
    assert "Inspect local Windows network interfaces" in network_help.stdout


def test_successful_collector_result_sorted_bounded_and_read_only() -> None:
    addrs = {
        "zeta": [Addr(socket.AF_INET6, "fe80::1234%12", "ffff:ffff::", None, None)],
        "Ethernet": [
            Addr(
                socket.AF_PACKET if hasattr(socket, "AF_PACKET") else 17,
                "aa:bb:cc:dd:ee:ff",
                None,
                None,
                None,
            ),
            Addr(socket.AF_INET, "192.168.1.100", "255.255.255.0", None, None),
        ],
    }
    stats = {"zeta": Stat(False, 0, 0, 1500, ""), "Ethernet": Stat(True, 1, 1000, 1500, "")}
    counters = {
        "Ethernet": Counter(1000, 2000, 10, 20, 0, 0, 0, 0),
        "zeta": Counter(1, 2, 3, 4, 1, 0, 0, 0),
    }
    payload = windows_network_payload(WINDOWS_INFO, sources=_sources(addrs, stats, counters))
    assert payload["mode"] == "windows_network"
    assert payload["status"] == "ok"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert [i["name"] for i in payload["interfaces"]] == ["Ethernet", "zeta"]
    assert payload["summary"]["interfaces_up"] == 1
    assert payload["summary"]["interfaces_down"] == 1
    assert payload["summary"]["ipv4_addresses"] == 1
    assert payload["summary"]["ipv6_addresses"] == 1
    assert payload["summary"]["interfaces_with_errors"] == 1
    assert payload["interfaces"][0]["addresses"][0]["family"] == "ipv4"
    dumped = json.dumps(payload).lower()
    assert "aa:bb:cc:dd:ee:ff" not in dumped
    assert "mac" not in dumped
    assert "guid" not in dumped


def test_address_classification_no_dns_and_ipv6_zone_suffix() -> None:
    assert classify_ip_address("127.0.0.1")[0] == "loopback"
    assert classify_ip_address("192.168.1.10")[0] == "private"
    assert classify_ip_address("169.254.1.1")[0] == "link_local"
    assert classify_ip_address("8.8.8.8")[0] == "global"
    assert classify_ip_address("::1")[0] == "loopback"
    assert classify_ip_address("fe80::1234:5678:abcd:ef01%12")[0] == "link_local"
    assert classify_ip_address("fc00::1")[0] == "private"
    assert classify_ip_address("2001:4860:4860::8888")[0] == "global"
    assert classify_ip_address("ff02::1")[0] == "multicast"
    assert classify_ip_address("not an ip")[0] == "unknown"


def test_missing_stats_and_counters_do_not_crash_or_fabricate_zeroes() -> None:
    payload = windows_network_payload(
        WINDOWS_INFO,
        sources=_sources({"orphan": [Addr(socket.AF_INET, "10.0.0.5", None, None, None)]}, {}, {}),
    )
    iface = payload["interfaces"][0]
    assert iface["name"] == "orphan"
    assert iface["is_up"] is None
    assert iface["mtu"] is None
    assert iface["speed_mbps"] is None
    assert iface["counters"] is None
    assert "interface stats unavailable" in iface["warnings"]


def test_interface_and_address_caps_are_deterministic() -> None:
    addrs = {
        f"if{i:02d}": [Addr(socket.AF_INET, f"10.0.0.{i}", None, None, None)]
        for i in range(MAX_INTERFACES + 2)
    }
    payload = windows_network_payload(WINDOWS_INFO, sources=_sources(addrs, {}, {}))
    assert payload["summary"]["interfaces_total"] == MAX_INTERFACES + 2
    assert payload["summary"]["interfaces_returned"] == MAX_INTERFACES
    assert payload["summary"]["truncated"] is True
    many = {
        "eth": [
            Addr(socket.AF_INET, f"10.0.0.{i}", None, None, None)
            for i in range(MAX_ADDRESSES_PER_INTERFACE + 3)
        ]
    }
    capped = windows_network_payload(
        WINDOWS_INFO, sources=_sources(many, {"eth": Stat(True, 1, 1, 1500, "")}, {})
    )
    iface = capped["interfaces"][0]
    assert iface["addresses_total"] == MAX_ADDRESSES_PER_INTERFACE + 3
    assert iface["addresses_returned"] == MAX_ADDRESSES_PER_INTERFACE
    assert iface["addresses_truncated"] is True


def test_json_and_text_outputs_are_safe_and_concise(monkeypatch) -> None:
    addrs = {"Ethernet": [Addr(socket.AF_INET, "192.168.1.100", "255.255.255.0", None, None)]}
    stats = {"Ethernet": Stat(True, 1, 1000, 1500, "")}
    counters = {"Ethernet": Counter(1000, 2000, 10, 20, 0, 0, 0, 0)}
    monkeypatch.setattr("shellforgeai.windows_network.detect_platform", lambda: WINDOWS_INFO)
    monkeypatch.setattr(
        "shellforgeai.windows_network._psutil_sources", lambda: _sources(addrs, stats, counters)
    )
    result = CliRunner().invoke(app, ["windows", "network", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["interfaces"][0]["counters"]["bytes_received"] == 2000
    text_result = CliRunner().invoke(app, ["windows", "network"])
    assert text_result.exit_code == 0
    out = text_result.stdout
    assert "Windows network" in out
    assert "Interfaces: 1 total, 1 up, 0 down" in out
    assert "IPV4: 192.168.1.100/255.255.255.0" in out
    assert "Limitations:" in out
    assert "internet" not in out.lower()
    assert '"interfaces"' not in out


def test_unsupported_platform_does_not_call_collector_or_linux_substitute(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_network.detect_platform", lambda: LINUX_INFO)
    monkeypatch.setattr(
        "shellforgeai.windows_network._psutil_sources",
        lambda: (_ for _ in ()).throw(AssertionError("must not collect")),
    )
    result = CliRunner().invoke(app, ["windows", "network", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "unsupported"
    assert payload["platform"] == {"system": "linux"}
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["interfaces"] == []


def test_main_collector_failure_is_bounded_json(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_network.detect_platform", lambda: WINDOWS_INFO)
    monkeypatch.setattr(
        "shellforgeai.windows_network._psutil_sources",
        lambda: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    result = CliRunner().invoke(app, ["windows", "network", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert payload["errors"] == ["boom"]
    assert "Traceback" not in result.stdout


def test_render_omits_raw_link_layer_identifiers() -> None:
    payload = windows_network_payload(
        WINDOWS_INFO,
        sources=_sources({"eth": [Addr(socket.AF_INET, "10.0.0.1", None, None, None)]}, {}, {}),
    )
    text = render_windows_network_text(payload).lower()
    assert "mac" not in text
    assert "guid" not in text
