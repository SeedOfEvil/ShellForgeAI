from shellforgeai.core.diagnose import diagnose_target


class _S:
    session_id = "s"
    online_enabled = False
    data_dir = "/tmp"


class _C:
    session = _S()
    settings = type("X", (), {"knowledge": type("K", (), {"local_paths": []})()})()


def test_package_owner_bundle_contains_storage_mounts() -> None:
    res = diagnose_target(_C(), "package-owner:/usr/local/bin/docker", online=False, since="30m")
    sources = [i.source for i in res.evidence.items]
    assert "storage.mounts" in sources
