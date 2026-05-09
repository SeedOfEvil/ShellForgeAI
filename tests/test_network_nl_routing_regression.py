from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.repl import (
    _extract_reachability_target,
    select_followup_investigation,
)


def test_network_status_routes_to_diagnose_network():
    assert route_input("network status").args == "network"


def test_check_dns_routes_to_diagnose_network():
    assert route_input("check dns").args == "network"


def test_reachability_routes_to_diagnose_network():
    assert route_input("can this server reach example.com:443?").args == "network"


def test_open_port_routes_to_diagnose_network_not_services():
    assert route_input("can you open port 443?").args == "network"


def test_extract_reachability_target():
    assert _extract_reachability_target("can it reach example.com:443") == ("example.com", 443)


def test_network_followup_has_subtype_and_target():
    follow = select_followup_investigation("network", [], "can it reach example.com:443")
    assert follow
    assert follow["bundle"] == "network"
    assert follow["type"] == "network"
    assert follow["subtype"] == "reachability"
