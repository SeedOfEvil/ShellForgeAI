from shellforgeai.interactive.repl import select_followup_investigation


def test_network_status_routes_to_network_bundle():
    r = select_followup_investigation("host", [], "network status")
    assert r and r["bundle"] == "network"


def test_firewall_typo_routes():
    r = select_followup_investigation("host", [], "firwall status")
    assert r and r["bundle"] == "network"
