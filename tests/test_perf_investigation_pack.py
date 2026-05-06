from pathlib import Path

from shellforgeai.tools import audit_recent, disk, process, storage, system


def test_process_io_graceful(tmp_path: Path):
    r = process.io(proc_root=tmp_path)
    assert (not r.ok) or ("top_io_write" in (r.stderr or ""))


def test_system_pressure_graceful_new():
    r = system.pressure()
    assert r.ok or "pressure metrics unavailable" in (r.stderr or "")


def test_cgroup_limits_graceful():
    r = system.cgroup_limits()
    assert r.ok or "unavailable" in (r.stderr or "")


def test_storage_mounts_graceful():
    r = storage.mounts()
    assert r.ok or "unavailable" in (r.stderr or "")


def test_disk_top_dirs_graceful():
    r = disk.top_dirs("/")
    assert r.ok or "unavailable" in (r.stderr or "") or "timed out" in (r.stderr or "")


def test_audit_recent_graceful():
    r = audit_recent.recent()
    assert r.ok or "no recent audit trend available" in (r.stderr or "")
