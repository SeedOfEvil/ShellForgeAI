from shellforgeai.tools import process, system


def test_cpu_memory_has_expected_fields():
    r = system.cpu_memory()
    assert r.ok
    assert "mem_total_mb" in r.stdout
    assert "swap_percent" in r.stdout


def test_system_pressure_graceful():
    r = system.pressure()
    assert r.ok or "unavailable" in (r.stderr or "")


def test_process_snapshot_shape():
    r = process.snapshot()
    assert r.ok
    assert "processes=" in r.stdout
    assert "zombies=" in r.stdout
