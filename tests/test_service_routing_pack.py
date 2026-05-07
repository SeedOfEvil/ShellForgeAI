from shellforgeai.interactive.commands import route_input


def test_restart_nginx_routes_to_service_diagnose() -> None:
    assert route_input("can you restart nginx").name == "diagnose"


def test_is_nginx_running_routes() -> None:
    r = route_input("is nginx running?")
    assert r.name == "diagnose" and r.args == "nginx"


def test_what_services_running_routes() -> None:
    r = route_input("what services are running")
    assert r.name == "diagnose" and r.args == "services"
