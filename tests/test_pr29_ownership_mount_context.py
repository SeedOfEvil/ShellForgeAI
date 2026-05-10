from shellforgeai.core.collectors import collect_path_ownership_evidence
from shellforgeai.tools.base import ToolResult


class _DummySession:
    data_dir = "/tmp"


class _DummyCtx:
    session = _DummySession()


def test_collect_path_ownership_includes_stat_mount_and_owner(monkeypatch) -> None:
    from shellforgeai.core import collectors

    monkeypatch.setattr(
        collectors.files,
        "stat",
        lambda p: ToolResult(
            tool="files.stat",
            stdout=str(
                {
                    "path": p,
                    "exists": True,
                    "owner": "root",
                    "group": "root",
                    "mode": "0o755",
                    "executable": True,
                    "type": "file",
                    "symlink_target": None,
                }
            ),
        ),
    )
    monkeypatch.setattr(
        collectors.storage,
        "mounts",
        lambda p: ToolResult(
            tool="storage.mounts",
            stdout=f"{p} /dev/mapper/disk[/usr/bin/docker] ext4 ro,relatime",
        ),
    )
    items = collect_path_ownership_evidence(_DummyCtx(), "/usr/local/bin/docker")
    sources = [i.source for i in items]
    assert "files.stat" in sources
    assert "storage.mounts" in sources
