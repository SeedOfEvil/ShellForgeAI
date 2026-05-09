from shellforgeai.tools import network
from shellforgeai.tools.base import ToolResult


def test_network_interfaces_ip_missing_fallback(monkeypatch):
    monkeypatch.setattr(
        network,
        "run_command",
        lambda cmd: ToolResult(tool="x", command=cmd, ok=False, exit_code=127, stderr="not found"),
    )
    res = network.interfaces()
    assert res.tool == "network.interfaces"


def test_network_default_route_no_default(monkeypatch):
    calls = iter(
        [
            ToolResult(tool="x", command=["ip"], exit_code=0, stdout=""),
            ToolResult(tool="x", command=["ip"], exit_code=0, stdout="10.0.0.0/8 dev eth0"),
        ]
    )
    monkeypatch.setattr(network, "run_command", lambda cmd: next(calls))
    res = network.default_route()
    assert "no default route" in res.stdout


def test_network_resolution_failure(monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("temporary failure")

    monkeypatch.setattr(network.socket, "getaddrinfo", boom)
    res = network.resolution_test("example.com")
    assert not res.ok


def test_network_tcp_connect_timeout(monkeypatch):
    def boom(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(network.socket, "create_connection", boom)
    res = network.tcp_connect_test("example.com", 443)
    assert not res.ok
    assert "failed" in (res.stderr or "")


def test_network_namespace_context_docker(monkeypatch):
    monkeypatch.setattr(
        network.system,
        "container_detect",
        lambda: ToolResult(tool="system.container_detect", stdout="docker"),
    )
    monkeypatch.setattr(
        network, "dns", lambda: ToolResult(tool="network.dns", stdout="nameserver 127.0.0.11")
    )
    monkeypatch.setattr(
        network,
        "default_route",
        lambda: ToolResult(tool="network.default_route", stdout="default via 172.18.0.1 dev eth0"),
    )
    res = network.namespace_context()
    assert "container_view=yes" in res.stdout
