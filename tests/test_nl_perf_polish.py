from shellforgeai.interactive.repl import (
    _human_container,
    _human_load,
    select_followup_investigation,
)


def test_human_load_formats_cleanly() -> None:
    assert (
        _human_load("{'loadavg': (1.9521484375, 3.02294921875, 3.9150390625)}")
        == "1.95 / 3.02 / 3.92"
    )


def test_human_container_docker() -> None:
    assert (
        _human_container('container={"is_container": "yes", "runtime_hint": "docker"}')
        == "Docker/container view"
    )


def test_perf_storage_pressure_selects_storage_followup() -> None:
    checks = [
        {
            "tool": "storage.pressure",
            "summary": "io_some_avg10=0.99 io_some_avg60=1.07 io_some_avg300=3.72",
            "status": "ok",
        },
        {"tool": "disk.usage", "summary": "/ 39% used", "status": "ok"},
        {"tool": "disk.inodes", "summary": "/ 28% used", "status": "ok"},
    ]
    s = select_followup_investigation("performance", checks, "I feel my system is a bit slow")
    assert s and s["intent"] == "storage_io_deep_dive"
    assert "broader read-only health pass" not in s["label"]
