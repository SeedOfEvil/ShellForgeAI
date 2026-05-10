from shellforgeai.tools import packages
from shellforgeai.util.subprocess import CommandResult


def test_query_unavailable_when_no_manager(monkeypatch) -> None:
    monkeypatch.setattr(
        packages,
        "manager_detect",
        lambda: packages.ToolResult(tool="x", stdout='{"primary":"unknown"}'),
    )
    r = packages.query("nginx")
    assert not r.ok
    assert "unavailable" in (r.stderr or "")


def test_file_owner_unavailable_when_no_manager(monkeypatch) -> None:
    monkeypatch.setattr(
        packages,
        "manager_detect",
        lambda: packages.ToolResult(tool="x", stdout='{"primary":"unknown"}'),
    )
    r = packages.file_owner("/usr/sbin/nginx")
    assert not r.ok


def test_query_returns_version(monkeypatch) -> None:
    monkeypatch.setattr(
        packages,
        "manager_detect",
        lambda: packages.ToolResult(tool="x", stdout='{"primary":"apt/dpkg"}'),
    )
    monkeypatch.setattr(
        packages,
        "run_command",
        lambda cmd: CommandResult(
            command=cmd,
            exit_code=0,
            stdout="Package: nginx\nVersion: 1.2.3\n",
            stderr="",
            duration_ms=1,
        ),
    )
    r = packages.query("nginx")
    assert r.ok
    assert "Version" in (r.stdout or "")


def test_file_owner_returns_owner(monkeypatch) -> None:
    monkeypatch.setattr(
        packages,
        "manager_detect",
        lambda: packages.ToolResult(tool="x", stdout='{"primary":"apt/dpkg"}'),
    )
    monkeypatch.setattr(
        packages,
        "run_command",
        lambda cmd: CommandResult(
            command=cmd, exit_code=0, stdout="nginx: /usr/sbin/nginx\n", stderr="", duration_ms=1
        ),
    )
    r = packages.file_owner("/usr/sbin/nginx")
    assert r.ok
    assert "nginx" in (r.stdout or "")
