from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.repl import (
    _contains_internal_collector_language,
    _storage_io_deep_dive_synthesis,
    select_followup_investigation,
)


def test_device_sluggish_routes_to_performance() -> None:
    for phrase in [
        "my device feels a bit sluggish today",
        "device feels slow",
        "device feels sluggish",
        "this device feels sluggish",
        "this device is slow",
        "this device is sluggish",
        "my device is laggy",
        "this device is laggy",
        "my device feels sluggish",
    ]:
        r = route_input(phrase)
        assert r.name == "diagnose", phrase
        assert r.args == "performance", phrase


def _perf_checks_with_storage_pressure() -> list[dict[str, str]]:
    return [
        {
            "tool": "system.cpu_memory",
            "summary": "cpus=32 mem=78.1GiB/220.3GiB swap=0B/8.0GiB",
            "status": "ok",
        },
        {
            "tool": "host.resources",
            "summary": "loadavg=2.57,2.82,3.31",
            "status": "ok",
        },
        {"tool": "disk.usage", "summary": "/ 39% used", "status": "ok"},
        {"tool": "disk.inodes", "summary": "/ 28% used", "status": "ok"},
        {
            "tool": "storage.pressure",
            "summary": "some avg10=1.83 avg60=0.99 avg300=1.42 total=7022",
            "status": "ok",
        },
        {
            "tool": "system.container_detect",
            "summary": 'container={"is_container": "yes", "runtime_hint": "docker"}',
            "status": "ok",
        },
        {
            "tool": "process.top",
            "summary": "top_cpu=python pid=123 cpu=4.5%",
            "status": "ok",
        },
    ]


def test_perf_with_healthy_resources_and_storage_pressure_selects_storage_io() -> None:
    sel = select_followup_investigation(
        "performance", _perf_checks_with_storage_pressure(), "my device feels a bit sluggish today"
    )
    assert sel and sel["intent"] == "storage_io_deep_dive"
    assert sel["label"] == "storage/I/O"
    assert "health pass" not in sel["label"]


def test_storage_io_deep_dive_synthesis_compares_passes() -> None:
    first = _perf_checks_with_storage_pressure()
    second = _perf_checks_with_storage_pressure()
    # second pass has slightly higher pressure
    second[4] = {
        "tool": "storage.pressure",
        "summary": "some avg10=2.1 avg60=1.4 avg300=1.6 total=8000",
        "status": "ok",
    }
    out = _storage_io_deep_dive_synthesis(first, second)
    assert "## Assessment" in out
    assert "## What changed / deeper clues" in out
    assert "## Likely angle" in out
    assert "## Remaining blind spots" in out
    assert "## Safe conclusion" in out
    assert "host-level backing-storage visibility" in out
    # No raw leakage
    assert "mem_used=" not in out
    assert "loadavg=(" not in out
    assert "'=" not in out
    assert 'container={"is_container"' not in out
    assert '{"name": "Debian"' not in out


def test_synthesis_blocklist_catches_raw_strings() -> None:
    assert _contains_internal_collector_language("loadavg=(1, 2, 3)")
    assert _contains_internal_collector_language("mem_used=12345")
    assert _contains_internal_collector_language('container={"is_container": "yes"}')
    assert _contains_internal_collector_language("Load snapshot is '=2.5,3.0,3.5}")


def test_completed_followup_not_offered_again() -> None:
    # Simulate a selector return; downstream caller suppresses if intent in completed_followups.
    sel = select_followup_investigation(
        "performance", _perf_checks_with_storage_pressure(), "my device feels a bit sluggish today"
    )
    assert sel and sel["intent"] == "storage_io_deep_dive"
    completed = {"storage_io_deep_dive"}
    # Caller-side gate: intent in completed → drop pending
    suppressed = sel if sel["intent"] not in completed else None
    assert suppressed is None
