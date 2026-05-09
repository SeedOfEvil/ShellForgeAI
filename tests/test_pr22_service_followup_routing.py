from shellforgeai.interactive.repl import select_followup_investigation


def test_restart_nginx_queues_service_health_with_target() -> None:
    sel = select_followup_investigation("nginx", [], "can you restart nginx for me?")
    assert sel is not None
    assert sel["intent"] == "service_health_deep_dive"
    assert sel["target"] == "nginx"


def test_typo_restart_still_service_health() -> None:
    sel = select_followup_investigation("nginx", [], "restarat ngnix please")
    assert sel is not None
    assert sel["intent"] == "service_health_deep_dive"
