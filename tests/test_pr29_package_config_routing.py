from shellforgeai.interactive.commands import route_input


def test_package_and_config_routing_intents() -> None:
    assert route_input("what packages changed recently?").args == "packages"
    assert route_input("what package owns /usr/sbin/nginx?").args == "packages"
    assert route_input("is nginx installed?").args == "packages"
    assert route_input("what config changed recently?").args == "config"
    assert route_input("check ngnix config").args == "config"
    assert route_input("what changed before this broke?").args == "changes"
