from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.repl import _extract_service_action_target


def test_restart_shellforgeai_target_extracted() -> None:
    assert _extract_service_action_target("can you restart shellforgeai?") == "shellforgeai"


def test_restart_unknown_service_target_extracted() -> None:
    assert _extract_service_action_target("restart frobnicator") == "frobnicator"


def test_reload_caddy_target_extracted() -> None:
    assert _extract_service_action_target("reload caddy") == "caddy"


def test_nginx_routing_still_diagnose() -> None:
    assert route_input("can you restart nginx for me?").name == "diagnose"
