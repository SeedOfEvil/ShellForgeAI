from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from shellforgeai.core.diagnose import (
    _findings_from_docker,
    _findings_from_logs,
)
from shellforgeai.core.evidence import EvidenceCategory, EvidenceItem
from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.repl import select_followup_investigation
from shellforgeai.tools import containers
from shellforgeai.tools.base import ToolResult
from shellforgeai.util.subprocess import CommandResult


def _run_factory(responses: dict[str, CommandResult]):
    """Return a fake run_command that matches by command-tail key."""

    def fake(cmd, timeout=15):
        key = " ".join(cmd[:3])
        if key in responses:
            return responses[key]
        for k, v in responses.items():
            if " ".join(cmd).startswith(k):
                return v
        return CommandResult(cmd, 1, "", f"unmatched: {cmd}", 0)

    return fake


@pytest.fixture
def docker_available(monkeypatch):
    monkeypatch.setattr(
        containers.host,
        "command_exists",
        lambda c: ToolResult(tool="command.exists", ok=True, exit_code=0, stdout="/usr/bin/docker"),
    )


def test_containers_unavailable_when_docker_missing(monkeypatch):
    monkeypatch.setattr(
        containers.host,
        "command_exists",
        lambda c: ToolResult(tool="command.exists", ok=False, exit_code=1, stdout=""),
    )
    res = containers.containers()
    assert not res.ok
    assert "not available" in res.stderr


def test_containers_parses_ps_output(monkeypatch, docker_available):
    out = (
        "abc123\tsfai-missing-env\timg:1\tExited (42) 1 minute ago\texited\t1 minute ago\t\n"
        "def456\tsfai-restart-loop\timg:1\tRestarting (1)\trestarting\t10 sec\t\n"
        "ghi789\tsfai-noisy-logs\timg:1\tUp 2 minutes\trunning\t2 minutes\t\n"
    )
    responses = {
        "docker ps --no-trunc": CommandResult(["docker", "ps"], 0, out, "", 0),
    }
    monkeypatch.setattr(containers, "run_command", _run_factory(responses))
    res = containers.containers()
    assert res.ok
    payload = json.loads(res.stdout)
    names = [c["name"] for c in payload["containers"]]
    assert "sfai-missing-env" in names
    assert "sfai-restart-loop" in names
    assert "exited=" in res.stderr


def test_inspect_parses_exit_and_restart(monkeypatch, docker_available):
    inspect_payload = json.dumps(
        [
            {
                "Name": "/sfai-missing-env",
                "Id": "abc1234567890",
                "Config": {"Image": "img:1"},
                "RestartCount": 0,
                "State": {
                    "Status": "exited",
                    "Running": False,
                    "ExitCode": 42,
                    "StartedAt": "now",
                    "FinishedAt": "now",
                    "Error": "",
                    "OOMKilled": False,
                    "Health": None,
                },
            }
        ]
    )
    responses = {"docker inspect": CommandResult(["docker", "inspect"], 0, inspect_payload, "", 0)}
    monkeypatch.setattr(containers, "run_command", _run_factory(responses))
    res = containers.inspect("sfai-missing-env")
    assert res.ok
    p = json.loads(res.stdout)
    assert p["exit_code"] == 42
    assert p["restart_count"] == 0
    assert p["status"] == "exited"


def test_container_logs_bounded_and_redacted(monkeypatch, docker_available):
    log_lines = "\n".join(
        ["INFO start", "ERROR token=abc123secretvalue failed", "ERROR REQUIRED_SETTING is missing"]
    )
    responses = {"docker logs": CommandResult(["docker", "logs"], 0, log_lines, "", 0)}
    monkeypatch.setattr(containers, "run_command", _run_factory(responses))
    res = containers.container_logs("sfai-missing-env", tail=10)
    assert res.ok
    assert "abc123secretvalue" not in res.stdout
    assert "REDACTED" in res.stdout.upper()


def test_container_logs_rejects_invalid_name(docker_available):
    res = containers.container_logs("../etc/passwd")
    assert not res.ok


def _stub_docker(monkeypatch, ps_out: str, inspects: dict, logs_map: dict):
    monkeypatch.setattr(
        containers.host,
        "command_exists",
        lambda c: ToolResult(tool="command.exists", ok=True, stdout="/usr/bin/docker"),
    )

    def fake_run(cmd, timeout=15):
        if cmd[:2] == ["docker", "ps"]:
            return CommandResult(cmd, 0, ps_out, "", 0)
        if cmd[:2] == ["docker", "inspect"]:
            name = cmd[2]
            data = inspects.get(name)
            if data is None:
                return CommandResult(cmd, 1, "", f"inspect failed for {name}", 0)
            return CommandResult(cmd, 0, json.dumps([data]), "", 0)
        if cmd[:2] == ["docker", "logs"]:
            name = cmd[-1]
            return CommandResult(cmd, 0, logs_map.get(name, ""), "", 0)
        return CommandResult(cmd, 1, "", "unmatched", 0)

    monkeypatch.setattr(containers, "run_command", fake_run)


def _lab_ps_output() -> str:
    return (
        "id1\tsfai-missing-env\timg\tExited (42)\texited\t1 minute ago\t\n"
        "id2\tsfai-restart-loop\timg\tRestarting\trestarting\t5 seconds\t\n"
        "id3\tsfai-noisy-logs\timg\tUp\trunning\t2 minutes\t\n"
        "id4\tsfai-bad-volume-perms\timg\tExited (1)\texited\t1 minute\t\n"
        "id5\tsfai-bad-network\timg\tUp\trunning\t2 minutes\t\n"
    )


def _lab_inspects() -> dict:
    def base(name, status, running, exit_code, restarts):
        return {
            "Name": f"/{name}",
            "Id": "x" * 12,
            "Config": {"Image": "img"},
            "RestartCount": restarts,
            "State": {
                "Status": status,
                "Running": running,
                "ExitCode": exit_code,
                "Error": "",
                "OOMKilled": False,
                "Health": None,
            },
        }

    return {
        "sfai-missing-env": base("sfai-missing-env", "exited", False, 42, 0),
        "sfai-restart-loop": base("sfai-restart-loop", "restarting", True, 1, 5),
        "sfai-noisy-logs": base("sfai-noisy-logs", "running", True, 0, 0),
        "sfai-bad-volume-perms": base("sfai-bad-volume-perms", "exited", False, 1, 0),
        "sfai-bad-network": base("sfai-bad-network", "running", True, 0, 0),
    }


def _lab_logs() -> dict:
    return {
        "sfai-missing-env": "ERROR REQUIRED_SETTING is missing\n" * 3,
        "sfai-restart-loop": "Simulated crash before startup\n" * 6,
        "sfai-noisy-logs": "INFO ok\nWARN slow\nERROR something noisy\n",
        "sfai-bad-volume-perms": (
            "ERROR cannot create /data/out.txt: read-only file system\n"
            "permission denied opening /data/out.txt\n"
        ),
        "sfai-bad-network": (
            "Could not resolve host upstream.invalid\n"
            "temporary failure in name resolution upstream.invalid\n"
        ),
    }


def test_problem_summary_detects_lab_failures(monkeypatch):
    _stub_docker(monkeypatch, _lab_ps_output(), _lab_inspects(), _lab_logs())
    res = containers.problem_summary()
    assert res.ok
    payload = json.loads(res.stdout)
    failing_names = [f["name"] for f in payload["failing"]]
    assert "sfai-missing-env" in failing_names
    assert "sfai-restart-loop" in failing_names
    assert "sfai-bad-volume-perms" in failing_names
    # noisy-logs is running with errors but exit_code=0 -> noisy bucket
    noisy_names = [n["name"] for n in payload["noisy"]]
    assert "sfai-noisy-logs" in noisy_names or "sfai-bad-network" in noisy_names


def test_findings_from_docker_lab_signals(monkeypatch):
    _stub_docker(monkeypatch, _lab_ps_output(), _lab_inspects(), _lab_logs())
    summary = containers.problem_summary()
    item = EvidenceItem(
        source="docker.problem_summary",
        category=EvidenceCategory.logs,
        ok=True,
        title="Container problem summary",
        summary=summary.stderr,
        content=summary.stdout,
    )
    findings = _findings_from_docker([item])
    titles = " | ".join(f.title for f in findings)
    severities = {f.severity for f in findings}
    assert "sfai-missing-env" in titles
    assert "sfai-restart-loop" in titles
    assert "sfai-bad-volume-perms" in titles
    assert "warning" in severities or "critical" in severities
    assert any("missing required setting" in f.title for f in findings)
    assert any("restart loop" in f.title.lower() for f in findings)
    assert any("permission" in f.title.lower() or "write" in f.title.lower() for f in findings)


def test_findings_when_docker_unavailable():
    item = EvidenceItem(
        source="docker.problem_summary",
        category=EvidenceCategory.logs,
        ok=False,
        title="Container problem summary",
        summary="docker visibility unavailable",
        content="",
    )
    findings = _findings_from_docker([item])
    assert any(f.severity == "limitation" for f in findings)
    # do not falsely claim healthy
    assert all("healthy" not in f.title.lower() for f in findings)


def test_findings_no_false_positive_when_no_failing(monkeypatch):
    ps = "id\tsfai-ok\timg\tUp\trunning\t1 minute\t\n"
    inspects = {
        "sfai-ok": {
            "Name": "/sfai-ok",
            "Id": "x" * 12,
            "Config": {"Image": "img"},
            "RestartCount": 0,
            "State": {
                "Status": "running",
                "Running": True,
                "ExitCode": 0,
                "Error": "",
                "OOMKilled": False,
                "Health": None,
            },
        }
    }
    _stub_docker(monkeypatch, ps, inspects, {"sfai-ok": "INFO ok\n"})
    summary = containers.problem_summary()
    item = EvidenceItem(
        source="docker.problem_summary",
        category=EvidenceCategory.logs,
        ok=True,
        title="Container problem summary",
        summary=summary.stderr,
        content=summary.stdout,
    )
    findings = _findings_from_docker([item])
    assert findings == []


# ---------- Routing ----------


def test_routing_why_app_restarting():
    cmd = route_input("why is the app restarting?")
    assert cmd.name == "diagnose" and cmd.args == "docker"


def test_routing_why_container_exit():
    cmd = route_input("why did the container exit?")
    assert cmd.name == "diagnose" and cmd.args == "docker"


def test_routing_anything_crashing():
    cmd = route_input("is anything crashing?")
    assert cmd.name == "diagnose" and cmd.args == "docker"


def test_routing_find_recent_logs_and_errors():
    cmd = route_input("find recent logs and errors")
    assert cmd.name == "diagnose" and cmd.args == "logs"


def test_routing_typo_restart():
    cmd = route_input("why is the container restaring?")
    assert cmd.name == "diagnose" and cmd.args == "docker"


def test_routing_typo_crashng():
    cmd = route_input("is anything crasing?")
    assert cmd.name == "diagnose" and cmd.args == "docker"


def test_followup_docker_restart_loop():
    sel = select_followup_investigation("docker", [], "why is the app restarting?")
    assert sel is not None
    assert sel["intent"] == "logs_deep_dive"
    assert sel["subtype"] == "restart-loop"


def test_followup_docker_target_container():
    sel = select_followup_investigation("docker", [], "why did sfai-missing-env fail?")
    assert sel is not None
    assert sel.get("target_container") == "sfai-missing-env"


def test_followup_exited_container_subtype():
    sel = select_followup_investigation("docker", [], "why did the container exit?")
    assert sel is not None
    assert sel["subtype"] == "exited-containers"


# ---------- Regression: logs findings still work ----------


def test_logs_findings_unchanged_for_no_logs():
    item = EvidenceItem(
        source="logs.common_paths",
        category=EvidenceCategory.logs,
        ok=True,
        title="Common log paths",
        summary="readable_logs=0 unreadable=0 missing=5 samples=none",
        content="",
    )
    findings = _findings_from_logs([item])
    assert any(f.severity == "limitation" for f in findings)


# ---------- Bundle includes docker problem ----------


def test_logs_basic_includes_docker_problem(monkeypatch):
    from shellforgeai.core import collectors as col

    monkeypatch.setattr(col.host, "host_info", lambda: ToolResult(tool="host.info", stdout="{}"))
    monkeypatch.setattr(
        col.host, "host_resources", lambda: ToolResult(tool="host.resources", stdout="")
    )
    monkeypatch.setattr(
        col.system,
        "container_detect",
        lambda: ToolResult(tool="system.container_detect", stdout="docker"),
    )
    monkeypatch.setattr(
        col.services,
        "manager_detect",
        lambda: ToolResult(tool="service.manager_detect", stdout="{}"),
    )
    monkeypatch.setattr(
        col.logs,
        "common_paths",
        lambda extra_paths=None: ToolResult(
            tool="logs.common_paths",
            stdout='{"readable":[],"unreadable_count":0,"missing_count":0,"total_checked":0}',
            stderr="readable_logs=0 unreadable=0 missing=0 samples=none",
        ),
    )
    monkeypatch.setattr(
        col.logs,
        "recent_errors",
        lambda **_: ToolResult(
            tool="logs.recent_errors",
            stdout='{"files_scanned":0,"sources":[],"samples":[],"total_matches":0}',
            stderr="no recent error-like patterns found in visible logs",
        ),
    )
    monkeypatch.setattr(
        col.logs,
        "kernel_errors",
        lambda **_: ToolResult(
            tool="logs.kernel_errors",
            stdout='{"files_scanned":0,"sources":[],"samples":[],"total_matches":0,"category":"kernel","dmesg":{"available":false}}',
            stderr="no visible kernel storage/network/OOM errors found",
        ),
    )
    monkeypatch.setattr(
        col.logs,
        "auth_errors",
        lambda **_: ToolResult(
            tool="logs.auth_errors",
            stdout='{"files_scanned":0,"sources":[],"samples":[],"total_matches":0,"category":"auth"}',
            stderr="no auth logs visible or no recent auth failures",
        ),
    )
    monkeypatch.setattr(
        col.audit_recent,
        "recent",
        lambda: ToolResult(tool="audit.recent", stdout=""),
    )
    monkeypatch.setattr(
        col.containers,
        "containers",
        lambda all_containers=True: ToolResult(
            tool="docker.containers",
            stdout='{"containers":[],"total":0}',
            stderr="docker containers=0 running=0 exited=0 restarting=0",
        ),
    )
    monkeypatch.setattr(
        col.containers,
        "problem_summary",
        lambda log_tail=80: ToolResult(
            tool="docker.problem_summary",
            stdout='{"available":true,"total":0,"failing":[],"noisy":[]}',
            stderr="docker_total=0 failing=0 noisy=0",
        ),
    )
    ctx = SimpleNamespace(session=SimpleNamespace(data_dir="."))
    items = col.collect_logs_basic_evidence(ctx)
    sources = {i.source for i in items}
    assert "docker.containers" in sources
    assert "docker.problem_summary" in sources
