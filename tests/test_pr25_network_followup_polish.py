"""PR25: targeted network follow-up polish tests."""

from __future__ import annotations

from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.repl import (
    _detect_network_subtype,
    _extract_dns_target,
    _extract_port_target,
    _extract_reachability_target,
    _network_followup_synthesis,
    _pending_target_phrase,
    _run_network_followup,
    select_followup_investigation,
)
from shellforgeai.tools import network
from shellforgeai.tools.base import ToolResult

# ---------------------------------------------------------------------------
# Pending context preservation
# ---------------------------------------------------------------------------


def test_reachability_pending_stores_host_and_port():
    sel = select_followup_investigation("network", [], "can this server reach example.com:443?")
    assert sel
    assert sel["type"] == "network"
    assert sel["subtype"] == "reachability"
    assert sel["target_host"] == "example.com"
    assert sel["target_port"] == 443


def test_open_port_pending_stores_port_target():
    sel = select_followup_investigation("network", [], "can you open port 443?")
    assert sel
    assert sel["subtype"] == "port-open"
    assert sel["target_port"] == 443


def test_listener_pending_stores_port_target():
    sel = select_followup_investigation("network", [], "is port 443 open?")
    assert sel
    assert sel["subtype"] in {"listener", "port-open"}
    assert sel["target_port"] == 443


def test_dns_pending_stores_target_domain():
    sel = select_followup_investigation("network", [], "check DNS for internal.example.local")
    assert sel
    assert sel["subtype"] == "dns"
    assert sel["target_domain"] == "internal.example.local"


def test_pending_target_phrase_reachability():
    p = {"target_host": "example.com", "target_port": 443}
    assert _pending_target_phrase(p) == "example.com:443"


def test_pending_target_phrase_port_only():
    assert _pending_target_phrase({"target_port": 443}) == "port 443"


def test_pending_target_phrase_domain_only():
    assert _pending_target_phrase({"target_domain": "example.com"}) == "example.com"


def test_pending_label_reflects_subtype():
    sel = select_followup_investigation("network", [], "can this server reach example.com:443?")
    assert sel and sel["label"] == "network reachability"
    sel2 = select_followup_investigation("network", [], "can you open port 443?")
    assert sel2 and sel2["label"] == "network port-open"
    sel3 = select_followup_investigation("network", [], "check DNS for example.com")
    assert sel3 and sel3["label"] == "network DNS"


# ---------------------------------------------------------------------------
# Typo tolerance for reachability
# ---------------------------------------------------------------------------


def test_reachability_typo_thiis_routes_to_network():
    assert route_input("can thiis server reach example.com:443?").args == "network"


def test_reachability_typo_sever_routes_to_network():
    assert route_input("can this sever reach example.com:443?").args == "network"


def test_reachability_box_no_colon_routes_to_network():
    assert route_input("can this box reach example.com 443").args == "network"


def test_reachability_typo_conenct_routes_to_network():
    assert route_input("can it conenct to example.com:443?").args == "network"


def test_reachability_passive_phrasing_routes_to_network():
    assert route_input("is example.com:443 reachable?").args == "network"


def test_test_port_phrasing_routes_to_network():
    assert route_input("test port 443 on example.com").args == "network"


def test_extract_target_test_port_phrasing():
    assert _extract_reachability_target("test port 443 on example.com") == (
        "example.com",
        443,
    )


def test_extract_target_box_no_colon():
    assert _extract_reachability_target("can this box reach example.com 443") == (
        "example.com",
        443,
    )


def test_extract_target_typo_thiis():
    assert _extract_reachability_target("can thiis server reach example.com:443?") == (
        "example.com",
        443,
    )


# ---------------------------------------------------------------------------
# Subtype detection helpers
# ---------------------------------------------------------------------------


def test_detect_network_subtype_reachability():
    assert _detect_network_subtype("can it reach example.com:443") == "reachability"
    assert _detect_network_subtype("test port 443 on example.com") == "reachability"
    assert _detect_network_subtype("is example.com:443 reachable?") == "reachability"


def test_detect_network_subtype_port_open():
    assert _detect_network_subtype("can you open port 443?") == "port-open"


def test_detect_network_subtype_dns():
    assert _detect_network_subtype("check DNS for example.com") == "dns"


def test_detect_network_subtype_firewall():
    assert _detect_network_subtype("firewall status") == "firewall"


def test_extract_port_target_open_port():
    assert _extract_port_target("can you open port 443?") == 443


def test_extract_dns_target_for_phrase():
    assert _extract_dns_target("check dns for internal.example.local") == ("internal.example.local")


# ---------------------------------------------------------------------------
# Reachability follow-up: target-specific deep dive
# ---------------------------------------------------------------------------


def _stub_network(monkeypatch, *, tcp_ok: bool = True, dns_ok: bool = True) -> None:
    monkeypatch.setattr(
        network,
        "namespace_context",
        lambda: ToolResult(
            tool="network.namespace_context",
            stdout="container_view=yes runtime_hint=docker",
        ),
    )
    monkeypatch.setattr(
        network,
        "default_route",
        lambda: ToolResult(tool="network.default_route", stdout="default via 172.18.0.1 dev eth0"),
    )
    monkeypatch.setattr(
        network,
        "dns",
        lambda: ToolResult(tool="network.dns", stdout="nameserver 127.0.0.11"),
    )
    monkeypatch.setattr(
        network,
        "resolution_test",
        lambda h, timeout_seconds=3.0: ToolResult(
            tool="network.resolution_test",
            stdout=f"{h} resolved to 1 addresses: 93.184.216.34" if dns_ok else "",
            ok=dns_ok,
            exit_code=0 if dns_ok else 1,
            stderr="" if dns_ok else "DNS resolution failed",
        ),
    )
    monkeypatch.setattr(
        network,
        "tcp_connect_test",
        lambda h, p, timeout_seconds=3.0: ToolResult(
            tool="network.tcp_connect_test",
            stdout=f"tcp connect {h}:{p} ok in 12ms" if tcp_ok else "",
            ok=tcp_ok,
            exit_code=0 if tcp_ok else 1,
            stderr="" if tcp_ok else f"tcp connect {h}:{p} failed",
        ),
    )
    monkeypatch.setattr(
        network,
        "firewall_context",
        lambda: ToolResult(
            tool="network.firewall_context",
            stdout="no firewall tools found; host firewall state not visible from container",
        ),
    )
    monkeypatch.setattr(
        network,
        "listeners",
        lambda: ToolResult(
            tool="network.listeners",
            stdout="Netid State Local Address:Port\ntcp LISTEN 0.0.0.0:22",
        ),
    )
    monkeypatch.setattr(
        network,
        "listener_attribution",
        lambda: ToolResult(
            tool="network.listener_attribution", stdout="tcp 0.0.0.0:22 process=sshd"
        ),
    )
    monkeypatch.setattr(
        network,
        "interfaces",
        lambda: ToolResult(tool="network.interfaces", stdout="eth0 UP"),
    )


def test_reachability_followup_runs_target_specific(monkeypatch):
    _stub_network(monkeypatch)
    pending = {
        "type": "network",
        "subtype": "reachability",
        "target_host": "example.com",
        "target_port": 443,
    }
    checks, text = _run_network_followup(pending)
    tool_names = {c["tool"] for c in checks}
    assert "network.resolution_test" in tool_names
    assert "network.tcp_connect_test" in tool_names
    assert "network.default_route" in tool_names
    assert "network.dns" in tool_names
    assert "Deeper reachability check for example.com:443" in text
    assert "tcp connect example.com:443 ok" in text
    assert "Read-only checks only" in text


def test_reachability_followup_no_extra_port_scan(monkeypatch):
    _stub_network(monkeypatch)
    pending = {
        "type": "network",
        "subtype": "reachability",
        "target_host": "example.com",
        "target_port": 443,
    }
    checks, _ = _run_network_followup(pending)
    tcp_rows = [c for c in checks if c["tool"] == "network.tcp_connect_test"]
    assert len(tcp_rows) == 1
    assert "443" in tcp_rows[0]["summary"]


# ---------------------------------------------------------------------------
# Port-open follow-up
# ---------------------------------------------------------------------------


def test_port_open_followup_focuses_on_port(monkeypatch):
    _stub_network(monkeypatch)
    pending = {"type": "network", "subtype": "port-open", "target_port": 443}
    checks, text = _run_network_followup(pending)
    tool_names = {c["tool"] for c in checks}
    assert "network.listeners" in tool_names
    assert "network.listener_attribution" in tool_names
    assert "network.firewall_context" in tool_names
    assert "Deeper port 443 check completed" in text
    assert "no mutation" in text.lower()
    assert "operator-approved change" in text


def test_port_open_followup_does_not_assert_open_when_not_listening(monkeypatch):
    _stub_network(monkeypatch)
    pending = {"type": "network", "subtype": "port-open", "target_port": 443}
    _, text = _run_network_followup(pending)
    assert "port 443 is not listening" in text


def test_port_open_followup_does_not_emit_unconditional_firewall_commands(monkeypatch):
    _stub_network(monkeypatch)
    pending = {"type": "network", "subtype": "port-open", "target_port": 443}
    _, text = _run_network_followup(pending)
    for forbidden in ("ufw allow", "iptables -A", "nft add rule", "firewall-cmd --add"):
        assert forbidden not in text


# ---------------------------------------------------------------------------
# DNS follow-up
# ---------------------------------------------------------------------------


def test_dns_followup_uses_target_domain(monkeypatch):
    _stub_network(monkeypatch)
    pending = {"type": "network", "subtype": "dns", "target_domain": "example.com"}
    checks, text = _run_network_followup(pending)
    tool_names = {c["tool"] for c in checks}
    assert "network.dns" in tool_names
    assert "network.resolution_test" in tool_names
    assert "DNS follow-up for example.com" in text


def test_dns_followup_no_domain_uses_safe_default(monkeypatch):
    _stub_network(monkeypatch)
    pending = {"type": "network", "subtype": "dns"}
    _, text = _run_network_followup(pending)
    assert "example.com" in text
    assert "safe default" in text


# ---------------------------------------------------------------------------
# Synthesis structural assertions
# ---------------------------------------------------------------------------


def test_reachability_synthesis_safety_clause():
    pending = {
        "type": "network",
        "subtype": "reachability",
        "target_host": "example.com",
        "target_port": 443,
    }
    checks = [
        {"tool": "network.namespace_context", "status": "ok", "summary": "container_view=yes"},
        {"tool": "network.default_route", "status": "ok", "summary": "default via 172.18.0.1"},
        {"tool": "network.dns", "status": "ok", "summary": "nameserver 127.0.0.11"},
        {
            "tool": "network.resolution_test",
            "status": "ok",
            "summary": "example.com resolved to 1 addresses",
        },
        {
            "tool": "network.tcp_connect_test",
            "status": "ok",
            "summary": "tcp connect example.com:443 ok in 12ms",
        },
        {
            "tool": "network.firewall_context",
            "status": "ok",
            "summary": "no firewall tools",
        },
    ]
    text = _network_followup_synthesis(pending, checks)
    assert "Deeper reachability check for example.com:443" in text
    assert "host routing and host firewall may differ" in text
