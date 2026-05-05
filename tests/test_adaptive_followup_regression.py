from __future__ import annotations

from typing import Any

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.interactive.commands import route_input

runner = CliRunner()


class _Item:
    def __init__(self, source: str, summary: str, status: str = "ok") -> None:
        self.source = source
        self.summary = summary
        self.ok = status == "ok"
        self.metadata = {"status": status}


class _Evidence:
    def __init__(self, items: list[_Item]) -> None:
        self.items = items

    def model_dump_json(self, indent: int = 2) -> str:
        return "{}"


class _Plan:
    def model_dump_json(self, indent: int = 2) -> str:
        return "{}"


class _TargetType:
    value = "host"


class _Result:
    session_id = "s1"
    target_type = _TargetType()
    findings: list[Any] = []
    proposed_plan = _Plan()

    def __init__(self, items: list[_Item]) -> None:
        self.evidence = _Evidence(items)


class _Provider:
    def complete(self, req: Any) -> Any:
        return type("R", (), {"text": "## Assessment\n"})()


def _first_pass() -> list[_Item]:
    return [
        _Item("system.cpu_memory", "cpus=32 mem=78.1GiB/220.3GiB swap=0B/8.0GiB"),
        _Item("host.resources", "loadavg=4.61,5.96,4.88"),
        _Item("disk.usage", "/ 39% used"),
        _Item("disk.inodes", "/ 28% used"),
        _Item("storage.pressure", "some avg10=1.83 avg60=0.99 avg300=1.42 total=7022"),
        _Item(
            "system.container_detect", 'container={"is_container": "yes", "runtime_hint": "docker"}'
        ),
        _Item("process.top", "top CPU process shellforgeai pid=123 cpu=4.5%"),
    ]


def _second_pass() -> list[_Item]:
    return [
        _Item("system.cpu_memory", "cpus=32 mem=78.1GiB/220.3GiB swap=0B/8.0GiB"),
        _Item("host.resources", "loadavg=4.70,5.90,4.80"),
        _Item("disk.usage", "/ 39% used"),
        _Item("disk.inodes", "/ 28% used"),
        _Item("storage.pressure", "some avg10=2.10 avg60=1.40 avg300=1.60 total=8000"),
        _Item(
            "system.container_detect", 'container={"is_container": "yes", "runtime_hint": "docker"}'
        ),
        _Item("process.top", "top CPU process shellforgeai pid=123 cpu=4.7%"),
    ]


def test_validated_slowness_phrases_route_to_performance() -> None:
    for phrase in [
        "the device feels a bit slow today",
        "my device feels a bit sluggish today",
        "this device feels slow",
        "this device is sluggish",
        "the server feels a bit slow",
        "this server feels slow",
        "system feels sluggish",
        "things feel slow",
        "host feels slow",
        "machine is laggy",
    ]:
        routed = route_input(phrase)
        assert routed.name == "diagnose", phrase
        assert routed.args == "performance", phrase


def test_validated_storage_io_followup_flow(monkeypatch: Any, tmp_path: Any) -> None:
    calls = {"count": 0}

    def fake_diagnose(*args: Any, **kwargs: Any) -> _Result:
        calls["count"] += 1
        return _Result(_first_pass() if calls["count"] == 1 else _second_pass())

    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.interactive.repl.diagnose_target", fake_diagnose)
    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", lambda *_: _Provider())

    res = runner.invoke(
        app,
        ["interactive", "--no-trust-cache"],
        input="y\nthe device feels a bit slow today\n/pending\ndig deeper\n/pending\n/exit\n",
    )

    assert res.exit_code == 0
    out = res.stdout
    assert calls["count"] == 2
    assert "Collected 7 read-only evidence item(s)." in out
    assert "Highlights:" in out
    assert "32 CPUs visible" in out
    assert "78.1 GiB / 220.3 GiB used" in out
    assert "swap unused" in out
    assert "Load: 4.61 / 5.96 / 4.88" in out
    assert "Docker/container view" in out
    assert "Storage/I/O: non-zero pressure" in out
    assert "top CPU process shellforgeai" in out
    assert "Pending investigation: storage/I/O" in out
    assert "deeper read-only storage/I/O pass" in out
    assert "Deeper investigation complete: 7 read-only evidence item(s)." in out
    assert "## What changed / deeper clues" in out
    assert "first pass non-zero pressure (avg10 1.83" in out
    assert "second pass non-zero pressure (avg10 2.1" in out
    assert "first pass top CPU process shellforgeai" in out
    assert "second pass top CPU process shellforgeai" in out
    assert "Load: first pass 4.61 / 5.96 / 4.88" in out
    assert "Disk/inodes: still healthy" in out
    assert "Memory/swap: still healthy" in out
    assert "Storage errors: none" in out
    assert "No pending investigation." in out
    assert out.count("deeper read-only storage/I/O pass") == 1
    for leaked in [
        '{"name":',
        'container={"is_container":',
        "mem_used=",
        "loadavg=(",
        "'=",
        "host.info:",
        "system.cpu_memory:",
        "process.top:",
        "top process summary available",
    ]:
        assert leaked not in out
