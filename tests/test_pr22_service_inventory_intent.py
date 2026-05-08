from shellforgeai.interactive.repl import select_followup_investigation


def test_services_running_queues_service_inventory_deep_dive() -> None:
    sel = select_followup_investigation("services", [], "what services are running?")
    assert sel is not None
    assert sel["intent"] == "service_inventory_deep_dive"
