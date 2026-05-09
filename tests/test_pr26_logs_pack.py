from __future__ import annotations

import contextlib
import json
from pathlib import Path
from types import SimpleNamespace

from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.repl import select_followup_investigation
from shellforgeai.tools import logs
from shellforgeai.tools.base import ToolResult


def _patch_no_dmesg(monkeypatch) -> None:
    monkeypatch.setattr(
        logs.host,
        "command_exists",
        lambda c: ToolResult(tool="command.exists", ok=False, exit_code=1, stdout=""),
    )


def test_common_paths_finds_readable_files(tmp_path, monkeypatch) -> None:
    fixture_a = tmp_path / "syslog"
    fixture_a.write_text("ok\n")
    res = logs.common_paths(extra_paths=[str(fixture_a)])
    payload = json.loads(res.stdout)
    assert any(r["path"] == str(fixture_a) for r in payload["readable"])
    assert "readable_logs" in res.stderr


def test_common_paths_handles_no_logs(monkeypatch) -> None:
    monkeypatch.setattr(logs, "COMMON_LOG_PATHS", ["/nonexistent/log_path/__nope__"])
    res = logs.common_paths()
    payload = json.loads(res.stdout)
    assert payload["readable"] == []
    assert payload["missing_count"] >= 1


def test_recent_errors_finds_patterns_and_dedupes(tmp_path) -> None:
    f = tmp_path / "app.log"
    f.write_text(
        "starting\n"
        "ERROR connection refused to 127.0.0.1:8080\n"
        "ERROR connection refused to 127.0.0.1:8080\n"
        "info ok\n"
        "permission denied accessing /tmp\n"
    )
    res = logs.recent_errors(paths=[str(f)])
    payload = json.loads(res.stdout)
    assert payload["total_matches"] >= 3
    samples = payload["samples"]
    refused = [s for s in samples if "refused" in s["line"].lower()]
    assert refused and refused[0]["count"] >= 2


def test_recent_errors_redacts_secrets(tmp_path) -> None:
    f = tmp_path / "secret.log"
    f.write_text("ERROR token=abc123secretvalue failed\n")
    res = logs.recent_errors(paths=[str(f)])
    payload = json.loads(res.stdout)
    samples_text = " ".join(s["line"] for s in payload["samples"])
    assert "abc123secretvalue" not in samples_text
    assert "REDACTED" in samples_text.upper()


def test_recent_errors_respects_max_files(tmp_path) -> None:
    files = []
    for i in range(5):
        p = tmp_path / f"l{i}.log"
        p.write_text("ERROR boom\n")
        files.append(str(p))
    res = logs.recent_errors(paths=files, max_files=2)
    payload = json.loads(res.stdout)
    assert payload["files_scanned"] <= 2


def test_recent_errors_empty(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(logs, "COMMON_LOG_PATHS", [str(tmp_path / "nope")])
    res = logs.recent_errors()
    payload = json.loads(res.stdout)
    assert payload["total_matches"] == 0
    assert "no recent error-like patterns" in res.stderr


def test_service_errors_uses_files_when_no_journal(tmp_path, monkeypatch) -> None:
    _patch_no_dmesg(monkeypatch)
    f = tmp_path / "nginx_error.log"
    f.write_text("ERROR upstream connection refused\n")
    monkeypatch.setattr(logs, "COMMON", {"nginx": [str(f)]})
    res = logs.service_errors("nginx")
    payload = json.loads(res.stdout)
    assert payload["service"] == "nginx"
    assert payload["files"]["total_matches"] >= 1


def test_auth_errors_finds_failed_password(tmp_path, monkeypatch) -> None:
    _patch_no_dmesg(monkeypatch)
    f = tmp_path / "auth.log"
    f.write_text(
        "Jan 1 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "Jan 1 sudo[2]: pam_unix(sudo:auth): authentication failure\n"
    )

    real_recent = logs.recent_errors

    def fake_recent(*args, **kwargs):
        kwargs["paths"] = [str(f)]
        return real_recent(*args, **kwargs)

    monkeypatch.setattr(logs, "recent_errors", fake_recent)
    res = logs.auth_errors()
    payload = json.loads(res.stdout)
    assert payload["total_matches"] >= 2
    assert payload["category"] == "auth"


def test_kernel_errors_finds_oom(tmp_path, monkeypatch) -> None:
    _patch_no_dmesg(monkeypatch)
    f = tmp_path / "kern.log"
    f.write_text(
        "Jan 1 kernel: Out of memory: Killed process 1234 (python)\n"
        "Jan 1 kernel: I/O error, dev sda, sector 12345\n"
    )

    real_recent = logs.recent_errors

    def fake_recent(*args, **kwargs):
        kwargs["paths"] = [str(f)]
        return real_recent(*args, **kwargs)

    monkeypatch.setattr(logs, "recent_errors", fake_recent)
    res = logs.kernel_errors()
    payload = json.loads(res.stdout)
    assert payload["total_matches"] >= 1


def test_kernel_errors_none_visible(monkeypatch, tmp_path) -> None:
    _patch_no_dmesg(monkeypatch)

    def fake_recent(*args, **kwargs):
        return ToolResult(
            tool="logs.recent_errors",
            stdout=json.dumps(
                {"files_scanned": 0, "sources": [], "samples": [], "total_matches": 0}
            ),
            stderr="no recent error-like patterns found in visible logs",
        )

    monkeypatch.setattr(logs, "recent_errors", fake_recent)
    res = logs.kernel_errors()
    assert "no visible kernel" in res.stderr


def test_error_themes_groups_patterns() -> None:
    samples = [
        "connection refused to 127.0.0.1:8080",
        "connection refused to 127.0.0.1:8080",
        "permission denied for /var/run/nginx.pid",
        "Out of memory: Killed process",
    ]
    res = logs.error_themes(samples=samples)
    payload = json.loads(res.stdout)
    names = [t["name"] for t in payload["themes"]]
    assert "connection refused" in names
    assert "permission denied" in names
    assert "oom killed" in names


def test_safe_tail_bounded(tmp_path) -> None:
    p = Path("/var/log/__sfai_test.log")
    # safe_tail only allows known roots; use /var/log
    try:
        p.write_text("\n".join(f"line {i}" for i in range(500)))
    except (OSError, PermissionError):
        return
    try:
        res = logs.safe_tail(str(p), lines=10)
        assert res.ok
        assert len(res.stdout.splitlines()) <= 10
    finally:
        with contextlib.suppress(OSError):
            p.unlink()


def test_safe_tail_rejects_outside_paths(tmp_path) -> None:
    f = tmp_path / "x.log"
    f.write_text("hi\n")
    res = logs.safe_tail(str(f))
    assert not res.ok
    assert "permitted" in (res.stderr or "")


def test_safe_tail_rejects_glob() -> None:
    res = logs.safe_tail("/var/log/*.log")
    assert not res.ok


def test_safe_tail_rejects_binary(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(logs, "COMMON_LOG_PATHS", logs.COMMON_LOG_PATHS + [str(tmp_path)])
    f = tmp_path / "blob.log"
    f.write_bytes(b"\x00\x01binary")
    res = logs.safe_tail(str(f))
    assert not res.ok


# ---------- Routing ----------


def test_routing_any_errors() -> None:
    cmd = route_input("any errors?")
    assert cmd.name == "diagnose" and cmd.args == "logs"


def test_routing_check_logs() -> None:
    cmd = route_input("check logs")
    assert cmd.name == "diagnose" and cmd.args == "logs"


def test_routing_typo_erorrs() -> None:
    cmd = route_input("any erorrs?")
    assert cmd.name == "diagnose" and cmd.args == "logs"


def test_routing_nginx_logs() -> None:
    cmd = route_input("why is nginx failing?")
    assert cmd.name == "diagnose" and cmd.args == "logs:nginx"


def test_routing_check_nginx_logs() -> None:
    cmd = route_input("check nginx logs")
    assert cmd.name == "diagnose" and cmd.args == "logs:nginx"


def test_routing_ssh_login_failing() -> None:
    cmd = route_input("ssh login failing")
    assert cmd.name == "diagnose" and cmd.args == "auth"


def test_routing_permission_denied() -> None:
    cmd = route_input("permission denied")
    assert cmd.name == "diagnose" and cmd.args == "auth"


def test_routing_delete_logs_does_not_mutate() -> None:
    cmd = route_input("delete logs")
    assert cmd.name == "logs_mutation_refused"


def test_routing_truncate_logs_refused() -> None:
    cmd = route_input("truncate logs")
    assert cmd.name == "logs_mutation_refused"


def test_followup_logs_general() -> None:
    sel = select_followup_investigation("logs", [], "any errors?")
    assert sel is not None
    assert sel["intent"] == "logs_deep_dive"
    assert sel["type"] == "logs"
    assert sel["subtype"] == "general"


def test_followup_logs_service_target_preserved() -> None:
    sel = select_followup_investigation("logs:nginx", [], "why is nginx failing?")
    assert sel is not None
    assert sel["intent"] == "logs_deep_dive"
    assert sel["target_service"] == "nginx"
    assert sel["target"] == "logs:nginx"


def test_followup_logs_auth_subtype() -> None:
    sel = select_followup_investigation("auth", [], "ssh login failing")
    assert sel is not None
    assert sel["intent"] == "logs_deep_dive"
    assert sel["subtype"] == "auth"


def test_followup_logs_kernel_subtype() -> None:
    sel = select_followup_investigation("logs", [], "any kernel oom errors")
    assert sel is not None
    assert sel["subtype"] == "kernel"


# ---------- diagnose target wiring ----------


def test_diagnose_logs_target(monkeypatch) -> None:
    from shellforgeai.core.diagnose import diagnose_target

    class _S:
        session_id = "s1"
        data_dir = "."
        online_enabled = False

    class _Settings:
        class knowledge:
            local_paths: list[str] = []

    ctx = SimpleNamespace(session=_S(), settings=_Settings())
    monkeypatch.setattr(
        "shellforgeai.core.collectors.logs.common_paths",
        lambda extra_paths=None: ToolResult(
            tool="logs.common_paths",
            stdout=json.dumps(
                {"readable": [], "unreadable_count": 0, "missing_count": 5, "total_checked": 5}
            ),
            stderr="readable_logs=0 unreadable=0 missing=5 samples=none",
        ),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.logs.recent_errors",
        lambda **_: ToolResult(
            tool="logs.recent_errors",
            stdout=json.dumps(
                {"files_scanned": 0, "sources": [], "samples": [], "total_matches": 0}
            ),
            stderr="no recent error-like patterns found in visible logs",
        ),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.logs.kernel_errors",
        lambda **_: ToolResult(
            tool="logs.kernel_errors",
            stdout=json.dumps(
                {
                    "files_scanned": 0,
                    "sources": [],
                    "samples": [],
                    "total_matches": 0,
                    "category": "kernel",
                    "dmesg": {"available": False},
                }
            ),
            stderr="no visible kernel storage/network/OOM errors found",
        ),
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.logs.auth_errors",
        lambda **_: ToolResult(
            tool="logs.auth_errors",
            stdout=json.dumps(
                {
                    "files_scanned": 0,
                    "sources": [],
                    "samples": [],
                    "total_matches": 0,
                    "category": "auth",
                }
            ),
            stderr="no auth logs visible or no recent auth failures",
        ),
    )
    res = diagnose_target(ctx, "logs", online=False, since="30m")
    sources = {i.source for i in res.evidence.items}
    assert "logs.common_paths" in sources
    assert "logs.recent_errors" in sources
    # No mutation finding; should have at least one limitation/info finding
    severities = {f.severity for f in res.findings}
    assert severities  # not empty
