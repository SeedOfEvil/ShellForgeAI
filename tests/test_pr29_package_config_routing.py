from shellforgeai.interactive.commands import route_input


def test_package_and_config_routing_intents() -> None:
    assert route_input("what packages changed recently?").args == "packages"
    assert route_input("is nginx installed?").args == "packages:nginx"
    assert route_input("what package owns /usr/sbin/nginx?").args == "package-owner:/usr/sbin/nginx"
    assert (
        route_input("what owns /usr/local/bin/docker?").args
        == "package-owner:/usr/local/bin/docker"
    )
    assert route_input("what config changed recently?").args == "config"
    assert route_input("check ngnix config").args == "config"
    assert route_input("what changed before this broke?").args == "changes"


def test_oncall_overview_routes_to_docker_triage() -> None:
    assert route_input("I'm on call, what's broken?").args == "docker"
    assert route_input("anything broken?").args == "docker"
