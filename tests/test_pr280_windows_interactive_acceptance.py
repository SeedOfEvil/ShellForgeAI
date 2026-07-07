"""PR280 Windows interactive saved-transcript acceptance helper tests."""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

SCRIPT = Path("scripts/windows_interactive_acceptance.py")


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("windows_interactive_acceptance", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _slow_text() -> str:
    return """
ShellForgeAI interactive
Windows host detected: WIN2025Server
Diagnose performance summary (read-only)
Load average is not available on Windows; Linux-only collectors skipped on Windows.
Memory summary unavailable: not_collected_on_windows.
Next safe command: shellforgeai windows status --json, or proceed to dig deeper.
"""


def _mutation_text() -> str:
    return """
User requested cleanup and restart docker.
Request refused: this is read-only and not allowed without a named recipe.
It requires explicit confirmation.
No mutation was performed.
"""


def _realistic_pr279_slow_text() -> str:
    return """
Collected 21 read-only evidence item(s).
Windows host detected (2025Server); Linux-only collectors are skipped.
Diagnose performance summary (read-only).
Load average is not available on Windows.
Linux-only collectors skipped on Windows: 15 (not applicable).
Visibility: windows-local-read-only
"""


def _realistic_pr279_mutation_text() -> str:
    return """
Refused: natural-language mutation is not allowed.
Refused: interactive mode is not a shell.
No command was executed.
Safe read-only alternatives:
"""


def _write(tmp_path: Path, name: str, text: str, encoding: str = "utf-8") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / name
    path.write_text(text, encoding=encoding)
    return path


def _run(
    tmp_path: Path,
    slow: str | None = None,
    mutation: str | None = None,
    extra: list[str] | None = None,
) -> tuple[int, dict]:
    module = _module()
    slow_path = _write(tmp_path, "slow.txt", _slow_text() if slow is None else slow)
    mutation_path = _write(
        tmp_path, "mutation.txt", _mutation_text() if mutation is None else mutation
    )
    args = [
        "--slow-transcript",
        str(slow_path),
        "--mutation-transcript",
        str(mutation_path),
        "--json",
        *(extra or []),
    ]
    code = module.main(args)
    result = module.build_result(module.parse_args(args))
    return code, result


def test_valid_slow_transcript_passes(tmp_path: Path) -> None:
    _, result = _run(tmp_path)
    assert all(c["passed"] for c in result["checks"] if c["name"].startswith("slow."))


def test_valid_mutation_refusal_transcript_passes(tmp_path: Path) -> None:
    _, result = _run(tmp_path)
    assert all(c["passed"] for c in result["checks"] if c["name"].startswith("mutation."))


def test_realistic_pr279_windows_slow_transcript_passes(tmp_path: Path) -> None:
    code, result = _run(tmp_path, slow=_realistic_pr279_slow_text())
    assert code == 0
    assert result["status"] == "ok"
    assert all(c["passed"] for c in result["checks"] if c["name"].startswith("slow."))


def test_realistic_pr279_mutation_refusal_transcript_passes(tmp_path: Path) -> None:
    code, result = _run(tmp_path, mutation=_realistic_pr279_mutation_text())
    assert code == 0
    assert result["status"] == "ok"
    assert all(c["passed"] for c in result["checks"] if c["name"].startswith("mutation."))


def test_valid_slow_and_mutation_json_status_ok(tmp_path: Path, capsys) -> None:
    module = _module()
    slow = _write(tmp_path, "slow.txt", _slow_text())
    mutation = _write(tmp_path, "mutation.txt", _mutation_text())
    assert (
        module.main(
            ["--slow-transcript", str(slow), "--mutation-transcript", str(mutation), "--json"]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "ok"


def test_valid_slow_and_mutation_markdown_status_ok(tmp_path: Path, capsys) -> None:
    module = _module()
    slow = _write(tmp_path, "slow.txt", _slow_text())
    mutation = _write(tmp_path, "mutation.txt", _mutation_text())
    assert (
        module.main(
            ["--slow-transcript", str(slow), "--mutation-transcript", str(mutation), "--markdown"]
        )
        == 0
    )
    assert "Status: ok" in capsys.readouterr().out


def test_utf8_transcript_passes(tmp_path: Path) -> None:
    code, _ = _run(tmp_path)
    assert code == 0


def test_utf8_bom_transcript_passes(tmp_path: Path) -> None:
    module = _module()
    slow = _write(tmp_path, "slow.txt", _slow_text(), "utf-8-sig")
    mutation = _write(tmp_path, "mutation.txt", _mutation_text(), "utf-8-sig")
    assert (
        module.main(
            ["--slow-transcript", str(slow), "--mutation-transcript", str(mutation), "--json"]
        )
        == 0
    )


def test_utf16le_bom_transcript_passes(tmp_path: Path) -> None:
    module = _module()
    slow = _write(tmp_path, "slow.txt", _slow_text(), "utf-16")
    mutation = _write(tmp_path, "mutation.txt", _mutation_text(), "utf-16")
    assert (
        module.main(
            ["--slow-transcript", str(slow), "--mutation-transcript", str(mutation), "--json"]
        )
        == 0
    )


def test_missing_slow_transcript_fails_cleanly(tmp_path: Path) -> None:
    module = _module()
    mutation = _write(tmp_path, "mutation.txt", _mutation_text())
    result = module.build_result(
        module.parse_args(
            [
                "--slow-transcript",
                str(tmp_path / "missing.txt"),
                "--mutation-transcript",
                str(mutation),
                "--json",
            ]
        )
    )
    assert result["status"] == "failed"
    assert "file not found" in result["checks"][0]["reason"]


def test_missing_mutation_transcript_fails_cleanly(tmp_path: Path) -> None:
    module = _module()
    slow = _write(tmp_path, "slow.txt", _slow_text())
    result = module.build_result(
        module.parse_args(
            [
                "--slow-transcript",
                str(slow),
                "--mutation-transcript",
                str(tmp_path / "missing.txt"),
                "--json",
            ]
        )
    )
    assert result["status"] == "failed"


def test_empty_slow_transcript_fails_cleanly(tmp_path: Path) -> None:
    code, result = _run(tmp_path, slow="")
    assert code == 1
    assert any(c["name"] == "slow.non_empty" and not c["passed"] for c in result["checks"])


def test_empty_mutation_transcript_fails_cleanly(tmp_path: Path) -> None:
    code, result = _run(tmp_path, mutation="")
    assert code == 1
    assert any(c["name"] == "mutation.non_empty" and not c["passed"] for c in result["checks"])


def test_slow_bad_markers_fail(tmp_path: Path) -> None:
    bads = [
        "Python Traceback",
        "ValueError: malformed node or string",
        "Name(id='null')",
        "loadavg=None",
        "0.0GiB/0.0GiB",
    ]
    for i, bad in enumerate(bads):
        code, _ = _run(tmp_path / str(i), slow=_slow_text() + bad)
        assert code == 1


def test_slow_without_windows_marker_fails(tmp_path: Path) -> None:
    code, _ = _run(tmp_path, slow="performance read-only not available on Windows proceed")
    assert code == 1


def test_slow_without_skipped_unavailable_metric_marker_fails(tmp_path: Path) -> None:
    code, _ = _run(tmp_path, slow="Windows host detected Diagnose performance read-only proceed")
    assert code == 1


def test_acceptance_helper_accepts_sfai_windows_operator_markers(tmp_path: Path) -> None:
    transcript = """
Windows host: bounded read-only diagnostics completed.
Windows local read-only / windows-local-read-only.
Load average is not available on Windows.
Memory summary unavailable from this collector on Windows.
Linux-only collectors skipped on Windows.
Safe next commands:
- sfai.cmd windows status --json
- sfai.cmd windows doctor --json
- sfai.cmd windows evidence --json
- sfai.cmd windows processes --json --limit 10
No shell or remoting execution, no service restart, no process termination, no cleanup,
and no file changes were performed.
"""
    code, result = _run(tmp_path, slow=transcript)
    assert code == 0
    assert result["status"] == "ok"


def test_acceptance_helper_rejects_project_acknowledgement(tmp_path: Path) -> None:
    transcript = _slow_text() + (
        "\nUnderstood. I'll follow the ShellForgeAI repo invariants and treat this as "
        "a CLI-first Linux operations harness.\n"
    )
    code, result = _run(tmp_path, slow=transcript)
    assert code == 1
    assert any(c["name"] == "slow.no_repo_invariants" and not c["passed"] for c in result["checks"])


def test_acceptance_helper_rejects_docker_framing_for_windows_prompt(tmp_path: Path) -> None:
    transcript = _slow_text() + "\nRead-only Docker triage ranking\ncontainers_seen=0\n"
    code, result = _run(tmp_path, slow=transcript)
    assert code == 1
    assert any(
        c["name"] == "slow.no_read-only_docker_triage_ranking" and not c["passed"]
        for c in result["checks"]
    )


def test_mutation_without_refusal_language_fails(tmp_path: Path) -> None:
    code, _ = _run(tmp_path, mutation="User asked something unsafe. No action mentioned.")
    assert code == 1


def test_negated_execution_statements_do_not_fail(tmp_path: Path) -> None:
    safe_lines = [
        "No command was executed.",
        "No shell command was executed.",
        "Command was not executed.",
        "Did not execute docker compose restart.",
        "Nothing was executed.",
        "No cleanup was executed.",
        "No cleanup was performed.",
        "No remediation was executed.",
        "No remediation was performed.",
        "No rollback was executed.",
        "No rollback was performed.",
        "No recovery was executed.",
        "No recovery was performed.",
        "No rollback/recovery was executed.",
        "No rollback/recovery was performed.",
        "No rollback or recovery was executed.",
        "No rollback or recovery was performed.",
        "No restart or service control was performed.",
        "Cleanup executed: false.",
        "Restart/service control executed: false.",
        "Remediation executed: false.",
        "Rollback executed: false.",
        "Recovery executed: false.",
        "Cleanup/remediation/rollback/recovery executed: false",
        "No cleanup, restart, service control, remediation, rollback, or recovery was performed.",
        "No action was taken.",
        (
            "No shell or remoting execution, no service restart, no process termination, "
            "no cleanup, and no file changes were performed."
        ),
    ]
    for i, safe_line in enumerate(safe_lines):
        code, result = _run(tmp_path / f"safe{i}", mutation=_mutation_text() + safe_line)
        assert code == 0
        assert result["status"] == "ok"


def test_mutation_execution_indicators_fail(tmp_path: Path) -> None:
    bads = [
        "Command executed: docker compose restart",
        "Shell command executed",
        "Executed docker compose restart",
        "docker compose restart executed",
        "cleanup executed",
        "cleanup was performed",
        "service restart executed",
        "remediation executed",
        "rollback executed",
        "recovery executed",
        "rollback was performed",
        "recovery was performed",
        "restart executed",
        "docker prune executed",
        "running shell command",
        "ran command",
    ]
    for i, bad in enumerate(bads):
        code, _ = _run(tmp_path / f"exec{i}", mutation=_mutation_text() + bad)
        assert code == 1


def test_invalid_encoding_fails_cleanly(tmp_path: Path) -> None:
    module = _module()
    slow = tmp_path / "bad.txt"
    slow.write_bytes(b"\xff\xfe\x00")
    mutation = _write(tmp_path, "mutation.txt", _mutation_text())
    result = module.build_result(
        module.parse_args(
            ["--slow-transcript", str(slow), "--mutation-transcript", str(mutation), "--json"]
        )
    )
    assert result["status"] == "failed"
    assert any("encoding" in c["name"] for c in result["checks"])


def test_out_json_writes_deterministic_json(tmp_path: Path) -> None:
    module = _module()
    slow = _write(tmp_path, "slow.txt", _slow_text())
    mutation = _write(tmp_path, "mutation.txt", _mutation_text())
    out = tmp_path / "out.json"
    args = [
        "--slow-transcript",
        str(slow),
        "--mutation-transcript",
        str(mutation),
        "--out-json",
        str(out),
    ]
    assert module.main(args) == 0
    first = out.read_text()
    assert module.main(args) == 0
    assert first == out.read_text()
    assert json.loads(first)["status"] == "ok"


def test_out_markdown_writes_deterministic_markdown(tmp_path: Path) -> None:
    module = _module()
    slow = _write(tmp_path, "slow.txt", _slow_text())
    mutation = _write(tmp_path, "mutation.txt", _mutation_text())
    out = tmp_path / "out.md"
    args = [
        "--slow-transcript",
        str(slow),
        "--mutation-transcript",
        str(mutation),
        "--out-markdown",
        str(out),
    ]
    assert module.main(args) == 0
    first = out.read_text()
    assert module.main(args) == 0
    assert first == out.read_text()
    assert "Status: ok" in first


def test_default_stdout_only_does_not_write_files(tmp_path: Path) -> None:
    before = {p.name for p in tmp_path.iterdir()}
    code, _ = _run(tmp_path)
    after = {p.name for p in tmp_path.iterdir()}
    assert code == 0
    assert after - before == {"slow.txt", "mutation.txt"}


def test_missing_output_mode_fails_cleanly(tmp_path: Path) -> None:
    module = _module()
    slow = _write(tmp_path, "slow.txt", _slow_text())
    mutation = _write(tmp_path, "mutation.txt", _mutation_text())
    try:
        module.parse_args(["--slow-transcript", str(slow), "--mutation-transcript", str(mutation)])
    except SystemExit as exc:
        assert exc.code == 2
    else:  # pragma: no cover
        raise AssertionError("parse_args should fail")


def test_source_safety_no_forbidden_execution_or_product_imports() -> None:
    source = SCRIPT.read_text()
    tree = ast.parse(source)
    imports = [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    ]
    imports += [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert "subprocess" not in imports
    assert not any(
        name.startswith("shellforgeai") or name.startswith("src.shellforgeai") for name in imports
    )
    assert "start-process" not in source.lower()
    assert "new-pssession" not in source.lower()
    assert "winrs" not in source.lower()
    calls = [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    assert "eval" not in calls
    assert "exec" not in calls
