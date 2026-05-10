import json

from shellforgeai.tools import packages
from shellforgeai.util.subprocess import CommandResult


def test_query_unavailable_when_no_manager(monkeypatch) -> None:
    monkeypatch.setattr(
        packages,
        "manager_detect",
        lambda: packages.ToolResult(tool="x", stdout='{"primary":"unknown"}'),
    )
    r = packages.query("nginx")
    payload = json.loads(r.stdout)
    assert payload["installed"] == "unknown"
    assert payload["limitation"]


def test_query_not_installed_when_missing(monkeypatch) -> None:
    monkeypatch.setattr(
        packages,
        "manager_detect",
        lambda: packages.ToolResult(tool="x", stdout='{"primary":"apt/dpkg"}'),
    )
    monkeypatch.setattr(
        packages,
        "run_command",
        lambda cmd: CommandResult(command=cmd, exit_code=1, stdout="", stderr="", duration_ms=1),
    )
    payload = json.loads(packages.query("nginx").stdout)
    assert payload["installed"] is False


def test_file_owner_path_missing(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        packages,
        "manager_detect",
        lambda: packages.ToolResult(tool="x", stdout='{"primary":"apt/dpkg"}'),
    )
    payload = json.loads(packages.file_owner(str(tmp_path / "missing")).stdout)
    assert payload["owner_status"] == "path_missing"


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
            stdout="install ok installed|nginx|1.2.3|amd64",
            stderr="",
            duration_ms=1,
        ),
    )
    payload = json.loads(packages.query("nginx").stdout)
    assert payload["installed"] is True
    assert payload["version"] == "1.2.3"


def test_file_owner_returns_owner(monkeypatch, tmp_path) -> None:
    p = tmp_path / "owned"
    p.write_text("x")
    monkeypatch.setattr(
        packages,
        "manager_detect",
        lambda: packages.ToolResult(tool="x", stdout='{"primary":"apt/dpkg"}'),
    )
    monkeypatch.setattr(
        packages,
        "run_command",
        lambda cmd: CommandResult(
            command=cmd, exit_code=0, stdout="dash: /bin/sh\n", stderr="", duration_ms=1
        ),
    )
    payload = json.loads(packages.file_owner(str(p)).stdout)
    assert payload["owner_status"] == "owned"
    assert payload["owner_package"] == "dash"
