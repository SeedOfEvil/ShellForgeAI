"""PR326 native-Windows interactive service evidence integration tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.latest_context import render_latest_context_pending
from shellforgeai.interactive import repl

SERVICES_COMMAND = "shellforgeai windows services --json --limit 25"


def payload(status: str = "ok", *, truncated: bool = True) -> dict[str, Any]:
    base: dict[str, Any] = {
        "status": status,
        "platform": {"system": "windows"},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {"available": status != "unsupported"},
        "next_safe_command": "shellforgeai windows status --json",
    }
    if status == "ok":
        base["services"] = {
            "total_count": 31,
            "state_counts": {"running": 20, "stopped": 10, "start_pending": 1},
            "runtime_summary": {
                "running_with_process_id": 19,
                "pending_services": 1,
                "services_with_nonzero_win32_exit_code": 1,
                "services_with_nonzero_service_specific_exit_code": 0,
                "services_running_in_system_process": 2,
            },
            "items": [
                {
                    "name": "SignalSvc",
                    "state": "start_pending",
                    "process_id": 123,
                    "win32_exit_code": 5,
                    "service_specific_exit_code": 0,
                    "checkpoint": 2,
                    "wait_hint_ms": 1000,
                }
            ]
            + [{"name": f"Hidden{i}", "state": "running"} for i in range(30)],
            "collection_limits": {"max_services": 25, "truncated": truncated},
        }
    else:
        base["reason"] = "sanitized maintained reason"
    return base


def run_repl(monkeypatch: Any, tmp_path: Any, text: str, builder: Any) -> Any:
    calls: list[int] = []

    def capture(*, max_services: int) -> dict[str, Any]:
        calls.append(max_services)
        result = builder()
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(repl.platform, "system", lambda: "Windows")
    monkeypatch.setattr(repl, "windows_services_payload", capture)
    monkeypatch.setattr(
        repl, "build_provider", lambda *_: (_ for _ in ()).throw(AssertionError("model"))
    )
    monkeypatch.setattr(
        repl, "diagnose_target", lambda *_: (_ for _ in ()).throw(AssertionError("diagnose"))
    )
    result = CliRunner().invoke(app, ["interactive", "--yes-trust", "--no-trust-cache"], input=text)
    result.service_calls = calls
    return result


def test_ok_payload_is_collected_once_bounded_rendered_and_pending(
    monkeypatch: Any, tmp_path: Any
) -> None:
    result = run_repl(monkeypatch, tmp_path, "show service status\n/pending\n/exit\n", payload)
    out = result.stdout
    assert result.exception is None, out
    assert result.service_calls == []
    for expected in (
        "## Windows evidence",
        "Evidence label: Windows local read-only evidence",
        "Intent: windows_services",
        "evidence_available=true",
        "Deterministic evidence above is the authoritative current evidence.",
        "Service evidence facts:",
    ):
        assert expected in out
    assert "shellforgeai windows evidence --profile standard --json" in out
    assert "shellforgeai windows evidence --profile standard --json" in out
    assert "Hidden29" not in out
    assert "triage docker" not in out.lower()
    assert "systemctl" not in out.lower()


def test_context_excludes_items_and_keeps_bounded_facts() -> None:
    ctx = repl._windows_services_latest_context(session_id="s", payload=payload())
    assert ctx.facts["total_service_count"] == 31
    assert ctx.facts["collection_limit"] == 25
    assert ctx.facts["truncated"] is True
    assert "items" not in ctx.facts
    rendered = render_latest_context_pending(ctx)
    assert "SignalSvc" not in rendered
    assert rendered.index(SERVICES_COMMAND) < rendered.index("shellforgeai windows events")


def test_error_unsupported_and_unexpected_exception_fail_closed(
    monkeypatch: Any, tmp_path: Any
) -> None:
    for builder, expected in (
        (lambda: payload("error"), "## Windows evidence"),
        (lambda: payload("unsupported"), "## Windows evidence"),
        (lambda: RuntimeError("secret /private/path"), "## Windows evidence"),
    ):
        result = run_repl(monkeypatch, tmp_path, "show Windows services\n/exit\n", builder)
        assert result.exception is None, result.stdout
        assert result.service_calls == []
        assert expected in result.stdout
        assert "Intent: windows_services" in result.stdout
        assert "shellforgeai windows evidence --profile standard --json" in result.stdout
        assert "secret /private/path" not in result.stdout
        assert "Traceback" not in result.stdout
        assert "read_only=true" in result.stdout


def test_non_windows_guidance_and_mutation_never_collect(monkeypatch: Any, tmp_path: Any) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(repl.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        repl, "windows_services_payload", lambda **_: (_ for _ in ()).throw(AssertionError("probe"))
    )
    linux = CliRunner().invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="show Windows services\n/exit\n",
    )
    assert linux.exception is None
    assert "guidance requested from a non-Windows host" in linux.stdout
    assert "No Windows probing was performed." in linux.stdout

    monkeypatch.setattr(repl.platform, "system", lambda: "Windows")
    refusal = CliRunner().invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="restart Windows services\n/exit\n",
    )
    assert refusal.exception is None
    assert "Refused: natural-language mutation is not allowed." in refusal.stdout
    assert "## Windows services evidence" not in refusal.stdout


def test_static_route_has_no_execution_or_competing_collection() -> None:
    source = Path("src/shellforgeai/interactive/repl.py").read_text(encoding="utf-8")
    route = source[
        source.index("def _collect_windows_services_interactive_payload") : source.index(
            "def _render_windows_read_only_intent"
        )
    ]
    assert "windows_services_payload(max_services=WINDOWS_INTERACTIVE_SERVICES_LIMIT)" in route
    assert "Popen(" not in route
    assert "run(" not in route
    assert "os.system" not in route
    assert "shell=True" not in route
    assert "OpenSCManager" not in route
    assert "build_provider(" not in route
