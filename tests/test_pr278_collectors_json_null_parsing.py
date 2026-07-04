"""PR278: collector payload parsing must accept JSON null/true/false.

Manual Windows testing crashed interactive slow-system diagnostics:
``system.cpu_memory`` emits ``json.dumps(...)`` payloads which may contain
``null`` (e.g. ``mem_percent`` when memory totals are unavailable), and the
evidence summary path parsed them with ``ast.literal_eval``, raising
``ValueError: malformed node or string ... Name(id='null')``.

The fix parses collector payloads with ``json.loads`` first, keeps
``ast.literal_eval`` only as a fallback for legacy ``str(dict)`` payloads
(such as ``host.info``), and degrades to a safe summary when neither parser
accepts the payload.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.collectors import (
    PARSE_FAILED,
    _summarize,
    _to_item,
    parse_collector_payload,
)
from shellforgeai.core.evidence import EvidenceCategory
from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.repl import _summary_for_check
from shellforgeai.tools.base import ToolResult

runner = CliRunner()

ROOT = Path(__file__).resolve().parents[1]
COLLECTORS_PATH = ROOT / "src" / "shellforgeai" / "core" / "collectors.py"
REPL_PATH = ROOT / "src" / "shellforgeai" / "interactive" / "repl.py"

# A Windows-like system.cpu_memory payload: /proc/meminfo is unavailable, so
# totals are zero and ratio fields serialize as JSON null.
WINDOWS_CPU_MEMORY_PAYLOAD = json.dumps(
    {
        "cpus": 8,
        "effective_cpus": None,
        "loadavg": [],
        "mem_total_mb": 0.0,
        "mem_available_mb": 0.0,
        "mem_used_mb": 0.0,
        "mem_percent": None,
        "swap_total_mb": 0.0,
        "swap_used_mb": 0.0,
        "swap_percent": None,
    }
)


# ---------------------------------------------------------------------------
# parse_collector_payload: JSON values
# ---------------------------------------------------------------------------


def test_parse_json_object_with_null() -> None:
    data = parse_collector_payload('{"mem_percent": null, "cpus": 8}')
    assert data == {"mem_percent": None, "cpus": 8}


def test_parse_json_object_with_true() -> None:
    data = parse_collector_payload('{"installed": true}')
    assert data == {"installed": True}


def test_parse_json_object_with_false() -> None:
    data = parse_collector_payload('{"installed": false}')
    assert data == {"installed": False}


def test_parse_nested_json_with_null() -> None:
    data = parse_collector_payload('{"outer": {"inner": [null, 1, "x"], "flag": true}}')
    assert data == {"outer": {"inner": [None, 1, "x"], "flag": True}}


def test_parse_json_scalars_arrays_objects() -> None:
    assert parse_collector_payload('"text"') == "text"
    assert parse_collector_payload("3.5") == 3.5
    assert parse_collector_payload("[1, null, false]") == [1, None, False]
    assert parse_collector_payload("{}") == {}
    assert parse_collector_payload("null") is None
    assert parse_collector_payload("true") is True
    assert parse_collector_payload("false") is False


def test_parse_windows_cpu_memory_payload() -> None:
    data = parse_collector_payload(WINDOWS_CPU_MEMORY_PAYLOAD)
    assert isinstance(data, dict)
    assert data["cpus"] == 8
    assert data["mem_percent"] is None
    assert data["effective_cpus"] is None


# ---------------------------------------------------------------------------
# parse_collector_payload: legacy Python-literal fallback + safe failure
# ---------------------------------------------------------------------------


def test_parse_python_literal_fallback_still_works() -> None:
    payload = "{'hostname': 'win2025', 'kernel': None, 'cpus': (1, 2)}"
    data = parse_collector_payload(payload)
    assert data == {"hostname": "win2025", "kernel": None, "cpus": (1, 2)}


def test_parse_invalid_payload_does_not_raise() -> None:
    for garbage in ["not json at all ][", "{'unterminated': ", "Name(id='null')", ""]:
        assert parse_collector_payload(garbage) is PARSE_FAILED


def test_parse_invalid_payload_honors_default_override() -> None:
    assert parse_collector_payload("bad ][", default={}) == {}
    assert parse_collector_payload(None, default={}) == {}


# ---------------------------------------------------------------------------
# Summary rendering with JSON null payloads
# ---------------------------------------------------------------------------


def test_summarize_cpu_memory_json_null_does_not_crash() -> None:
    r = ToolResult(tool="system.cpu_memory", stdout=WINDOWS_CPU_MEMORY_PAYLOAD)
    summary = _summarize(r)
    assert "cpus=8" in summary
    assert "malformed" not in summary


def test_summarize_cpu_memory_garbage_payload_degrades_safely() -> None:
    r = ToolResult(tool="system.cpu_memory", stdout="{not valid json or literal")
    assert _summarize(r) == "cpu/memory summary unavailable"


def test_summarize_os_release_json_null_does_not_crash() -> None:
    r = ToolResult(
        tool="system.os_release",
        stdout='{"name": null, "version": null, "id": null, "pretty_name": null}',
    )
    summary = _summarize(r)
    assert summary  # non-empty, no exception
    assert "None" not in summary


def test_summarize_files_stat_garbage_payload_degrades_safely() -> None:
    r = ToolResult(tool="files.stat", stdout="{broken payload")
    summary = _summarize(r)
    assert "missing" in summary


def test_to_item_cpu_memory_json_null_yields_safe_evidence() -> None:
    r = ToolResult(tool="system.cpu_memory", stdout=WINDOWS_CPU_MEMORY_PAYLOAD)
    item = _to_item(r, EvidenceCategory.host, "CPU/memory")
    assert "cpus=8" in item.summary
    assert item.metadata["status"] == "ok"


def test_repl_summary_for_check_host_info_json_null() -> None:
    c = ToolResult(
        tool="host.info",
        stdout='{"hostname": null, "kernel": null, "arch": null}',
    )
    assert _summary_for_check(c) == "hostname=unknown kernel=unknown arch=unknown"


def test_repl_summary_for_check_host_info_literal_still_works() -> None:
    c = ToolResult(
        tool="host.info",
        stdout="{'hostname': 'w1', 'kernel': '10.0', 'arch': 'AMD64'}",
    )
    assert _summary_for_check(c) == "hostname=w1 kernel=10.0 arch=AMD64"


# ---------------------------------------------------------------------------
# Interactive slow-system route regression
# ---------------------------------------------------------------------------


class _Provider:
    def complete(self, req: Any) -> Any:
        return type("R", (), {"text": "## Assessment\nRead-only summary."})()


def test_slow_phrase_routes_to_readonly_diagnose_not_execution() -> None:
    routed = route_input("Hey this system feels a bit slow")
    assert routed.name == "diagnose"
    assert routed.args == "performance"


def test_interactive_slow_system_with_json_null_completes(monkeypatch: Any, tmp_path: Any) -> None:
    def fake_cpu_memory() -> ToolResult:
        return ToolResult(tool="system.cpu_memory", stdout=WINDOWS_CPU_MEMORY_PAYLOAD)

    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.tools.system.cpu_memory", fake_cpu_memory)
    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", lambda *_: _Provider())

    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="Hey this system feels a bit slow\n/exit\n",
    )

    out = res.stdout
    assert res.exit_code == 0
    # No traceback / no literal_eval crash on JSON null.
    assert "Traceback" not in out
    assert "malformed node or string" not in out
    assert "ValueError" not in out
    # The route completed with a safe read-only summary.
    assert "read-only evidence item(s)." in out
    # No cleanup/remediation/rollback/recovery execution was triggered.
    for forbidden in [
        "remediation executed",
        "rollback executed",
        "recovery executed",
        "cleanup executed",
        "Restarting",
        "Executing command",
    ]:
        assert forbidden not in out
    # No natural-language command execution: interactive is not a shell.
    assert "shell=True" not in out


# ---------------------------------------------------------------------------
# Source safety
# ---------------------------------------------------------------------------


def test_collectors_source_has_no_eval() -> None:
    source = COLLECTORS_PATH.read_text(encoding="utf-8")
    assert "eval(" not in source.replace("literal_eval(", "")
    assert "exec(" not in source


def test_collectors_source_has_no_shell_true() -> None:
    source = COLLECTORS_PATH.read_text(encoding="utf-8")
    assert "shell=True" not in source


def test_fix_introduces_no_powershell_or_winrm() -> None:
    collectors_src = COLLECTORS_PATH.read_text(encoding="utf-8").lower()
    repl_src = REPL_PATH.read_text(encoding="utf-8").lower()
    for banned in ["powershell", "winrm", "invoke-command", "pwsh"]:
        assert banned not in collectors_src
        assert banned not in repl_src
    assert "shell=True" not in REPL_PATH.read_text(encoding="utf-8")
