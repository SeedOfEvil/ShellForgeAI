from types import SimpleNamespace

from shellforgeai.core.collectors import collect_service_evidence
from shellforgeai.tools.base import ToolResult


def _ctx():
    return SimpleNamespace(session=SimpleNamespace(data_dir="."))


def test_service_discovery_collects_listener_and_process_evidence(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.core.collectors.system.container_detect",
        lambda: ToolResult(tool="system.container_detect", stdout="docker"),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.services.manager_detect",
        lambda: ToolResult(tool="service.manager_detect", stdout="{}"),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.network.listeners",
        lambda: ToolResult(tool="network.listeners", stdout=""),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.process.snapshot",
        lambda: ToolResult(tool="process.snapshot", stdout="processes=1"),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.process.top",
        lambda: ToolResult(tool="process.top", stdout="PID CMD\n1 init"),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.services.processes",
        lambda daemon: ToolResult(tool="service.processes", stdout=daemon),
    )
    items = collect_service_evidence(_ctx(), "services")
    sources = {i.source for i in items}
    assert "network.listeners" in sources
    assert "process.snapshot" in sources
    assert "service.manager_detect" in sources


def test_service_deep_dive_collectors_present(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.core.collectors.system.container_detect",
        lambda: ToolResult(tool="system.container_detect", stdout="docker"),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.services.manager_detect",
        lambda: ToolResult(tool="service.manager_detect", stdout="{}"),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.network.listeners",
        lambda: ToolResult(tool="network.listeners", stdout=""),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.process.snapshot",
        lambda: ToolResult(tool="process.snapshot", stdout=""),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.process.top",
        lambda: ToolResult(tool="process.top", stdout=""),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.services.status",
        lambda _: ToolResult(tool="service.status", stdout=""),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.services.unit_file",
        lambda _: ToolResult(tool="service.unit_file", stdout=""),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.services.processes",
        lambda _: ToolResult(tool="service.processes", stdout=""),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.services.ports",
        lambda _: ToolResult(tool="service.ports", stdout=""),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.services.config_hints",
        lambda _: ToolResult(tool="service.config_hints", stdout=""),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.services.service_logs",
        lambda *_a, **_k: ToolResult(tool="service.logs", stdout=""),
    )
    items = collect_service_evidence(_ctx(), "nginx")
    sources = {i.source for i in items}
    for req in {
        "service.manager_detect",
        "service.status",
        "service.processes",
        "service.ports",
        "service.config_hints",
        "service.logs",
    }:
        assert req in sources
