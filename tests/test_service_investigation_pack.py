from shellforgeai.tools import services
from shellforgeai.tools.base import ToolResult


def test_service_manager_detect_container_none(monkeypatch):
    monkeypatch.setattr(
        services.host, "command_exists", lambda _: ToolResult(tool="command.exists", stdout="")
    )
    monkeypatch.setattr(
        services.system,
        "container_detect",
        lambda: ToolResult(tool="system.container_detect", stdout="docker"),
    )
    monkeypatch.setattr(services, "_pid1_comm", lambda: "sleep")
    r = services.manager_detect()
    assert '"manager": "container-none"' in r.stdout


def test_service_status_systemctl_unavailable(monkeypatch):
    monkeypatch.setattr(
        services,
        "manager_detect",
        lambda: ToolResult(tool="service.manager_detect", stdout='{"systemctl_available": false}'),
    )
    r = services.status("nginx")
    assert not r.ok
    assert "systemd unavailable" in r.stderr


def test_service_processes_excludes_shellforgeai_self(monkeypatch):
    monkeypatch.setattr(
        services.process,
        "find",
        lambda name: ToolResult(
            tool=f"process.find {name}", stdout="", stderr="not found", ok=False, exit_code=0
        ),
    )
    r = services.processes("nginx")
    assert not r.ok


def test_service_ports_detect_expected_listener(monkeypatch):
    monkeypatch.setattr(
        services.network,
        "listeners",
        lambda: ToolResult(
            tool="network.listeners", stdout="tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*"
        ),
    )
    r = services.ports("nginx")
    assert "443" in r.stdout


def test_service_logs_handles_no_journal_and_no_paths(monkeypatch):
    monkeypatch.setattr(
        services.host, "command_exists", lambda _: ToolResult(tool="command.exists", stdout="")
    )
    monkeypatch.setattr(
        services.logs, "find_common", lambda _: ToolResult(tool="logs.find_common", stdout="none")
    )
    r = services.service_logs("nginx")
    assert not r.ok
    assert "journal unavailable" in r.stderr
