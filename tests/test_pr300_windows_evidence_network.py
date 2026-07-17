from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_evidence import (
    EVIDENCE_NETWORK_DEFAULT_ADDRESS_LIMIT,
    EVIDENCE_NETWORK_DEFAULT_INTERFACE_LIMIT,
    render_windows_evidence_text,
    validate_evidence_network_address_limit,
    validate_evidence_network_interface_limit,
    windows_evidence_payload,
)

WINDOWS = PlatformInfo("windows", "WIN", "nt", "2025", "AMD64")
LINUX = PlatformInfo("linux", "linux", "posix", "6.8", "x86_64")


def _common(mode, scope):
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
        "safety": {
            "powershell_executed": False,
            "winrm_used": False,
            "remote_execution": False,
            "service_restart_executed": False,
            "process_termination_executed": False,
            "registry_modified": False,
            "execution_policy_modified": False,
            "software_install_executed": False,
            "cleanup_executed": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "recovery_executed": False,
            "natural_language_execution": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "secret_read": False,
            "auth_cache_read": False,
            "model_called": False,
            "network_call": False,
        },
        "host": {"hostname": "WIN", "python": "3.14"},
        "python_runtime": {"version": "3.14", "executable": "python"},
        "filesystem": {"cwd": "C:/Tools/ShellForgeAI", "home": "C:/Users/Operator"},
    }


def doctor(_info):
    return _common("windows_doctor", "local_read_only_doctor")


def status(_info):
    return _common("windows_status", "local_read_only_status")


def net_payload(interface_limit=32, address_limit=16, *, status_value="ok", empty=False):
    interfaces = (
        []
        if empty
        else [
            {
                "name": "Ethernet0",
                "is_up": True,
                "mtu": 1500,
                "speed_mbps": 1000,
                "duplex": "full",
                "addresses": [
                    {
                        "family": "ipv4",
                        "address": "192.0.2.10",
                        "netmask": "255.255.255.0",
                        "broadcast": None,
                        "scope": "private",
                        "is_loopback": False,
                        "is_link_local": False,
                    },
                    {
                        "family": "ipv6",
                        "address": "fe80::1%1",
                        "netmask": "ffff:ffff::",
                        "broadcast": None,
                        "scope": "link_local",
                        "is_loopback": False,
                        "is_link_local": True,
                    },
                ][:address_limit],
                "addresses_total": 2,
                "addresses_returned": min(2, address_limit),
                "addresses_truncated": address_limit < 2,
                "counters": {
                    "bytes_sent": 1,
                    "bytes_received": 2,
                    "packets_sent": 3,
                    "packets_received": 4,
                    "input_errors": 0,
                    "output_errors": 0,
                    "input_drops": 0,
                    "output_drops": 0,
                },
                "warnings": [],
            }
        ]
    )
    return {
        "schema_version": 1,
        "mode": "windows_network",
        "status": status_value,
        "platform": {"system": "windows"},
        "read_only": True,
        "mutation_performed": False,
        "method": "psutil_net_if_addrs_stats_counters",
        "caps": {"max_interfaces": interface_limit, "max_addresses_per_interface": address_limit},
        "summary": {
            "interfaces_total": 0 if empty else 1,
            "interfaces_returned": 0 if empty else 1,
            "interfaces_up": 0 if empty else 1,
            "interfaces_down": 0,
            "ipv4_addresses": 0 if empty else min(1, address_limit),
            "ipv6_addresses": 0 if empty or address_limit < 2 else 1,
            "interfaces_with_errors": 0,
            "truncated": False,
        },
        "interfaces": interfaces,
        "limitations": [
            (
                "No packet capture, socket inventory, route-table lookup, DNS lookup, "
                "remote probing, or network mutation was performed. Counters are "
                "cumulative snapshots when available."
            )
        ],
        "warnings": [],
        "errors": [] if status_value == "ok" else [{"type": "raw", "message": "C:/secret marker"}],
        "safety": {
            k: False
            for k in (
                "powershell_executed",
                "winrm_used",
                "remote_execution",
                "packet_capture",
                "socket_inventory",
                "dns_lookup",
                "route_table_lookup",
                "network_mutation",
                "shell_true",
                "arbitrary_command_execution",
                "secret_read",
                "auth_cache_read",
                "model_called",
                "network_call",
            )
        }
        | {"read_only": True, "mutation_performed": False},
    }


def evidence(**kwargs):
    return windows_evidence_payload(WINDOWS, doctor_builder=doctor, status_builder=status, **kwargs)


def test_cli_help_registration_and_windows_network_unchanged():
    result = CliRunner().invoke(app, ["windows", "evidence", "--help"])
    assert result.exit_code == 0
    assert "--include-network" in result.stdout
    assert (
        "--network-interface-limit" in result.stdout
        and "1-32" in result.stdout
        and "default 32" in result.stdout
    )
    assert (
        "--network-address-limit" in result.stdout
        and "1-16" in result.stdout
        and "default 16" in result.stdout
    )
    network_help = CliRunner().invoke(app, ["windows", "network", "--help"])
    assert network_help.exit_code == 0
    assert "network-interface-limit" not in network_help.stdout


def test_default_omits_network_and_builder_not_called():
    default_payload = evidence()

    def boom(*_args):
        raise AssertionError("network builder called")

    injected = evidence(network_builder=boom)
    assert injected == default_payload
    assert list(injected["components"]) == ["doctor", "status"]
    assert "network" not in injected["components"]
    assert "embedded_network" not in injected
    assert injected["next_safe_command"] == "shellforgeai windows status --json"
    assert render_windows_evidence_text(injected) == render_windows_evidence_text(default_payload)


def test_opt_in_defaults_forwards_and_embeds_once():
    calls = []

    def builder(info, interface_limit, address_limit):
        calls.append((info.system, interface_limit, address_limit))
        return net_payload(interface_limit, address_limit)

    payload = evidence(include_network=True, network_builder=builder)
    assert calls == [("windows", 32, 16)]
    assert payload["components"]["network"]["caps"] == {
        "max_interfaces": 32,
        "max_addresses_per_interface": 16,
    }
    assert payload["embedded_network"] == {
        "included": True,
        "status": "ok",
        "max_interfaces": 32,
        "max_addresses_per_interface": 16,
        "interfaces_total": 1,
        "interfaces_returned": 1,
        "interfaces_up": 1,
        "interfaces_down": 0,
        "ipv4_addresses": 1,
        "ipv6_addresses": 1,
        "interfaces_with_errors": 0,
        "truncated": False,
    }
    assert payload["next_safe_command"] == "shellforgeai windows network --json"


def test_bounds_validators_and_cli_dependencies():
    assert EVIDENCE_NETWORK_DEFAULT_INTERFACE_LIMIT == 32
    assert EVIDENCE_NETWORK_DEFAULT_ADDRESS_LIMIT == 16
    for value in (1, 32):
        assert validate_evidence_network_interface_limit(value) == value
    for value in (0, 33, True):
        try:
            validate_evidence_network_interface_limit(value)
        except ValueError:
            pass
        else:
            raise AssertionError(value)
    for value in (1, 16):
        assert validate_evidence_network_address_limit(value) == value
    for value in (0, 17, False):
        try:
            validate_evidence_network_address_limit(value)
        except ValueError:
            pass
        else:
            raise AssertionError(value)
    for args in (
        ["--network-interface-limit", "8"],
        ["--network-address-limit", "4"],
        ["--network-interface-limit", "8", "--network-address-limit", "4"],
    ):
        result = CliRunner().invoke(app, ["windows", "evidence", *args])
        assert result.exit_code != 0
        assert "include-network" in result.output


def test_custom_bounds_healthy_schema_order_and_text_privacy():
    payload = evidence(
        include_services=True,
        services_builder=lambda _i, _l: {
            "status": "ok",
            "services": {"items": [], "collection_limits": {"truncated": False}, "total_count": 0},
        },
        include_processes=True,
        processes_builder=lambda _i, _l: {
            "status": "ok",
            "returned_count": 0,
            "total_count": 0,
            "truncated": False,
        },
        include_events=True,
        events_builder=lambda _i, _l, _h: {
            "status": "ok",
            "summary": {
                "events_returned": 0,
                "critical": 0,
                "error": 0,
                "warning": 0,
                "unknown": 0,
                "truncated": False,
                "limit": _l,
                "since_hours": _h,
            },
            "collection": {"limit": _l, "since_hours": _h},
        },
        include_network=True,
        network_interface_limit=8,
        network_address_limit=1,
        network_builder=lambda _i, il, al: net_payload(il, al),
    )
    assert list(payload["components"]) == [
        "doctor",
        "status",
        "services",
        "processes",
        "events",
        "network",
    ]
    component = payload["components"]["network"]
    assert (
        component["mode"] == "windows_network"
        and component["method"] == "psutil_net_if_addrs_stats_counters"
    )
    assert len(component["interfaces"]) <= 8
    assert all(len(i["addresses"]) <= 1 for i in component["interfaces"])
    text = render_windows_evidence_text(payload)
    assert (
        "Network component: status=ok; returned=1/1; up=1; down=0; "
        "ipv4=1; ipv6=0; errors=0; interface_limit=8; "
        "address_limit=1; truncated=false" in text
    )
    assert "Ethernet0" not in text and "192.0.2.10" not in text and "bytes_received" not in text


def test_unsupported_linux_does_not_call_network_builder(monkeypatch):
    monkeypatch.setattr("shellforgeai.windows_evidence.detect_platform", lambda: LINUX)
    monkeypatch.setattr(
        "shellforgeai.windows_evidence._default_network_builder",
        lambda *_: (_ for _ in ()).throw(AssertionError("called")),
    )
    result = CliRunner().invoke(app, ["windows", "evidence", "--include-network", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "unsupported"
    assert payload["platform"] == {"system": "linux"}
    assert "components" not in payload and "embedded_network" not in payload


def test_failure_normalization_for_exception_returned_error_and_malformed():
    def raised(*_args):
        raise RuntimeError("RAW_MARKER /home/operator/secret")

    for builder in (raised, lambda *_: net_payload(status_value="error"), lambda *_: ["bad"]):
        payload = evidence(
            include_network=True,
            network_interface_limit=4,
            network_address_limit=2,
            network_builder=builder,
        )
        dumped = json.dumps(payload)
        net = payload["components"]["network"]
        assert payload["status"] == "component_failure"
        assert payload["summary"]["failed_components"] == ["network"]
        assert (
            "doctor" in payload["summary"]["ok_components"]
            and "status" in payload["summary"]["ok_components"]
        )
        assert net["status"] == "error" and net["caps"] == {
            "max_interfaces": 4,
            "max_addresses_per_interface": 2,
        }
        assert net["summary"]["interfaces_returned"] == 0 and net["interfaces"] == []
        assert net["errors"] == [
            {
                "type": "network_component_failed",
                "message": "Windows network interface metadata component failed.",
            }
        ]
        assert (
            payload["embedded_network"]["status"] == "error"
            and payload["embedded_network"]["interfaces_returned"] == 0
        )
        assert (
            "RAW_MARKER" not in dumped
            and "/home/operator" not in dumped
            and "RuntimeError" not in dumped
            and "Traceback" not in dumped
        )


def test_healthy_empty_result_remains_ok():
    payload = evidence(
        include_network=True, network_builder=lambda _i, il, al: net_payload(il, al, empty=True)
    )
    assert payload["status"] == "ok"
    assert "network" in payload["summary"]["ok_components"]
    assert payload["embedded_network"]["interfaces_total"] == 0
    assert payload["embedded_network"]["truncated"] is False


def test_acceptance_network_fixtures_and_rejections(tmp_path):
    path = Path(__file__).resolve().parents[1] / "scripts" / "windows_smoke_acceptance.py"
    spec = importlib.util.spec_from_file_location("windows_smoke_acceptance_pr300", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    healthy = evidence(include_network=True, network_builder=lambda _i, il, al: net_payload(il, al))
    empty = evidence(
        include_network=True, network_builder=lambda _i, il, al: net_payload(il, al, empty=True)
    )
    failed = evidence(
        include_network=True,
        network_builder=lambda *_: (_ for _ in ()).throw(RuntimeError("C:/raw secret")),
    )
    default = evidence()
    for artifact in (healthy, empty, failed, default):
        checks = mod._validate_evidence(artifact, None, None)
        assert all(c.passed for c in checks), [c.to_dict() for c in checks if not c.passed]
    bad = json.loads(json.dumps(healthy))
    bad["embedded_network"]["interfaces_returned"] = 99
    assert not all(c.passed for c in mod._validate_evidence(bad, None, None))
    bad = json.loads(json.dumps(healthy))
    bad["components"]["network"]["interfaces"][0]["mac_address"] = "aa:bb"
    assert not all(c.passed for c in mod._validate_evidence(bad, None, None))
    bad = json.loads(json.dumps(healthy))
    bad["components"]["network"]["interfaces"][0]["addresses"] *= 20
    assert not all(c.passed for c in mod._validate_evidence(bad, None, None))


def test_pr300_source_guardrails():
    import subprocess

    added = subprocess.check_output(
        [
            "git",
            "diff",
            "--",
            "src/shellforgeai/windows_evidence.py",
            "src/shellforgeai/commands/windows.py",
        ],
        text=True,
    ).lower()
    for forbidden in (
        "get-netadapter",
        "get-netipaddress",
        "ipconfig",
        "netsh",
        "winrm",
        "qga",
        "subprocess.",
        "shell=true",
        "packet_capture = true",
        "socket_inventory = true",
        "route_table_lookup = true",
        "dns_lookup = true",
        "network_mutation = true",
        "registry_modified = true",
        "model_called = true",
        "network_call = true",
    ):
        assert forbidden not in added
