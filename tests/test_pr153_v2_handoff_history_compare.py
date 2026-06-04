"""PR153: V2 handoff artifact history and compare workflow.

Read-only history/compare for saved ShellForgeAI V2 handoff artifacts:

    handoff history [--limit N] [--json]
    handoff compare <before> <after> [--only-changed] [--include-stable] [--json]
    handoff compare-latest [--only-changed] [--include-stable] [--json]

History/compare are strictly read-only: they never write new artifacts, rerun
collectors, call the model/Codex, execute shell/subprocess, or mutate
Docker/Compose/containers/host state. Missing/malformed refs fail cleanly with a
controlled status and no traceback.
"""

from __future__ import annotations

import ast
import json
from io import StringIO
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

import shellforgeai.cli as cli_mod
import shellforgeai.core.v2_handoff_artifact as artifact_mod
from shellforgeai.cli import app
from shellforgeai.core.v2_handoff_artifact import (
    compare_latest_v2_handoffs,
    compare_v2_handoffs,
    save_v2_handoff,
    v2_handoff_history,
)
from shellforgeai.interactive import repl
from shellforgeai.interactive.commands import route_input

runner = CliRunner()

_MUTATION_SAFETY_FLAGS = (
    "mutation_performed",
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
    "docker_compose_executed",
    "container_restarted",
    "shell_true",
    "arbitrary_command_execution",
    "natural_language_execution",
    "model_called",
)


def _safety(**over) -> dict:
    base = {
        "read_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "model_called": False,
    }
    base.update(over)
    return base


def _payload(
    *,
    status: str = "ok",
    risk: str = "low",
    current_status: str = "ok",
    target: str | None = None,
    first_safe_command: str = "shellforgeai status --json",
    warnings: list | None = None,
    limitations: list | None = None,
    safe_next: list | None = None,
    safety: dict | None = None,
    golden_status: str = "ok",
    triage_status: str = "ok",
) -> dict:
    return {
        "schema_version": 1,
        "mode": "v2_handoff",
        "status": status,
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "current_status": current_status,
            "risk": risk,
            "target": target,
            "proposal_status": "none_needed",
            "apply_preview_status": "no_action",
            "verify_status": "ok",
        },
        "golden_path": {
            "status": {"status": golden_status},
            "triage": {"status": triage_status},
            "propose": {"status": "ok"},
            "apply_preview": {"status": "no_action"},
            "verify": {"status": "ok"},
        },
        "first_safe_command": first_safe_command,
        "safe_next_commands": safe_next or ["shellforgeai status --json"],
        "limitations": limitations or ["Read-only deterministic V2 handoff summary only."],
        "warnings": warnings or [],
        "safety": safety or _safety(),
    }


def _sequence_stamps(monkeypatch) -> None:
    """Force monotonically increasing handoff ids so ordering is deterministic."""
    counter = {"n": 0}

    def _stamp() -> str:
        counter["n"] += 1
        return f"20260604_{counter['n']:06d}"

    monkeypatch.setattr(artifact_mod, "_now_stamp", _stamp)


def _save_all(monkeypatch, data_dir: Path, payloads: list[dict]) -> list[dict]:
    _sequence_stamps(monkeypatch)
    return [save_v2_handoff(p, data_dir) for p in payloads]


def _assert_strict_json(stdout: str) -> dict:
    stripped = stdout.strip()
    assert stripped.startswith("{"), stripped[:80]
    assert stripped.endswith("}"), stripped[-80:]
    return json.loads(stripped)


def _assert_no_traceback(result) -> None:
    assert "Traceback" not in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


def _arm_no_collectors_no_model_no_shell(monkeypatch) -> None:
    """Make any collector/model/subprocess use explode so read-only paths are proven."""

    def boom_scene(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("history/compare must not rerun collectors")

    def boom_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("history/compare must not call the model/Codex")

    def boom_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"history/compare must not run subprocesses: {cmd!r}")

    monkeypatch.setattr("shellforgeai.core.triage_ranking.collect_scene", boom_scene)
    monkeypatch.setattr("shellforgeai.core.triage_ranking.rank_scene", boom_scene)
    monkeypatch.setattr(cli_mod, "build_provider", boom_provider)
    monkeypatch.setattr(cli_mod.subprocess, "run", boom_run)


# --------------------------------------------------------------------------- #
# History                                                                      #
# --------------------------------------------------------------------------- #
def test_history_empty_is_status_empty(monkeypatch, tmp_path):  # 1
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, ["handoff", "history", "--json"])
    assert result.exit_code == 0
    payload = _assert_strict_json(result.stdout)
    assert payload["mode"] == "v2_handoff_history"
    assert payload["status"] == "empty"
    assert payload["count"] == 0
    assert payload["first_safe_command"] == "shellforgeai handoff --save"
    _assert_no_traceback(result)


def test_history_human_empty_has_no_traceback(monkeypatch, tmp_path):  # 1
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, ["handoff", "history"])
    assert result.exit_code == 0
    assert "No saved V2 handoff artifacts found." in result.stdout
    assert "shellforgeai handoff --save" in result.stdout
    _assert_no_traceback(result)


def test_history_with_artifacts_is_ok(monkeypatch, tmp_path):  # 2
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload(), _payload(risk="high")])
    result = runner.invoke(app, ["handoff", "history", "--json"])
    assert result.exit_code == 0
    payload = _assert_strict_json(result.stdout)
    assert payload["status"] == "ok"
    assert payload["count"] == 2
    # Newest first; the second save is the latest id.
    assert payload["latest_handoff_id"] == saved[1]["handoff_id"]
    assert payload["handoffs"][0]["handoff_id"] == saved[1]["handoff_id"]
    assert payload["handoffs"][0]["valid"] is True


def test_history_json_is_strict(monkeypatch, tmp_path):  # 3
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _save_all(monkeypatch, tmp_path, [_payload()])
    result = runner.invoke(app, ["handoff", "history", "--json"])
    payload = _assert_strict_json(result.stdout)
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    for flag in _MUTATION_SAFETY_FLAGS:
        assert payload["safety"][flag] is False, flag


def test_history_limit_respected(monkeypatch, tmp_path):  # 4
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(
        monkeypatch, tmp_path, [_payload(), _payload(risk="high"), _payload(risk="medium")]
    )
    result = runner.invoke(app, ["handoff", "history", "--limit", "1", "--json"])
    payload = _assert_strict_json(result.stdout)
    # Count reflects all saved; the rendered list honors the limit.
    assert payload["count"] == 3
    assert len(payload["handoffs"]) == 1
    assert payload["handoffs"][0]["handoff_id"] == saved[-1]["handoff_id"]


def test_history_is_read_only_no_collectors_model_shell(monkeypatch, tmp_path):  # 5
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _save_all(monkeypatch, tmp_path, [_payload(), _payload(risk="high")])
    _arm_no_collectors_no_model_no_shell(monkeypatch)
    before = {p.relative_to(tmp_path): p.stat().st_mtime for p in tmp_path.rglob("*")}
    result = runner.invoke(app, ["handoff", "history", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "ok"
    after = {p.relative_to(tmp_path): p.stat().st_mtime for p in tmp_path.rglob("*")}
    assert before == after  # no writes/creates/deletes


# --------------------------------------------------------------------------- #
# Compare                                                                      #
# --------------------------------------------------------------------------- #
def test_compare_valid_refs_is_ok(monkeypatch, tmp_path):  # 6
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload(), _payload(risk="high")])
    result = runner.invoke(
        app, ["handoff", "compare", saved[0]["handoff_id"], saved[1]["handoff_id"], "--json"]
    )
    assert result.exit_code == 0
    payload = _assert_strict_json(result.stdout)
    assert payload["mode"] == "v2_handoff_compare"
    assert payload["status"] == "ok"
    assert payload["before"]["handoff_id"] == saved[0]["handoff_id"]
    assert payload["after"]["handoff_id"] == saved[1]["handoff_id"]


def test_compare_json_is_strict(monkeypatch, tmp_path):  # 7
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload(), _payload(risk="high")])
    result = runner.invoke(
        app, ["handoff", "compare", saved[0]["handoff_id"], saved[1]["handoff_id"], "--json"]
    )
    payload = _assert_strict_json(result.stdout)
    assert set(payload["summary"]) == {
        "new",
        "resolved_or_missing",
        "changed",
        "stable",
        "safety_drift",
    }
    for flag in _MUTATION_SAFETY_FLAGS:
        assert payload["safety"][flag] is False, flag


def test_compare_human_includes_before_after_refs(monkeypatch, tmp_path):  # 8
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload(), _payload(risk="high")])
    result = runner.invoke(
        app, ["handoff", "compare", saved[0]["handoff_id"], saved[1]["handoff_id"]]
    )
    assert result.exit_code == 0
    assert "V2 handoff compare" in result.stdout
    assert f"before: {saved[0]['handoff_id']}" in result.stdout
    assert f"after:  {saved[1]['handoff_id']}" in result.stdout
    assert "Read-only handoff compare." in result.stdout


def test_compare_detects_changed_current_status_and_risk(monkeypatch, tmp_path):  # 9
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(
        monkeypatch,
        tmp_path,
        [
            _payload(current_status="ok", risk="low"),
            _payload(current_status="degraded", risk="high"),
        ],
    )
    payload = compare_v2_handoffs(saved[0]["handoff_id"], saved[1]["handoff_id"], tmp_path)
    fields = {c["field"]: c for c in payload["changes"]}
    assert "current_status" in fields
    assert fields["current_status"]["before"] == "ok"
    assert fields["current_status"]["after"] == "degraded"
    assert "risk" in fields
    assert fields["risk"]["after"] == "high"


def test_compare_detects_changed_first_safe_command(monkeypatch, tmp_path):  # 10
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(
        monkeypatch,
        tmp_path,
        [
            _payload(first_safe_command="shellforgeai status --json"),
            _payload(first_safe_command="shellforgeai triage --json"),
        ],
    )
    payload = compare_v2_handoffs(saved[0]["handoff_id"], saved[1]["handoff_id"], tmp_path)
    fields = {c["field"]: c for c in payload["changes"]}
    assert "first_safe_command" in fields
    assert fields["first_safe_command"]["after"] == "shellforgeai triage --json"


def test_compare_detects_changed_warnings_and_limitations(monkeypatch, tmp_path):  # 11
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(
        monkeypatch,
        tmp_path,
        [
            _payload(warnings=[], limitations=["base limitation"]),
            _payload(warnings=["new warning"], limitations=["base limitation", "extra limitation"]),
        ],
    )
    payload = compare_v2_handoffs(saved[0]["handoff_id"], saved[1]["handoff_id"], tmp_path)
    fields = {c["field"]: c for c in payload["changes"]}
    assert "warnings" in fields
    assert "new warning" in fields["warnings"]["new"]
    assert "limitations" in fields
    assert "extra limitation" in fields["limitations"]["new"]
    assert payload["summary"]["new"] >= 2


def test_compare_include_stable_lists_stable_items(monkeypatch, tmp_path):  # 12
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload(risk="low"), _payload(risk="high")])
    payload = compare_v2_handoffs(
        saved[0]["handoff_id"], saved[1]["handoff_id"], tmp_path, include_stable=True
    )
    assert payload["summary"]["stable"] > 0
    stable_fields = {entry["field"] for entry in payload["stable"]}
    # status/current_status are identical across the two payloads here.
    assert "current_status" in stable_fields


def test_compare_only_changed_suppresses_stable(monkeypatch, tmp_path):  # 13
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload(risk="low"), _payload(risk="high")])
    payload = compare_v2_handoffs(
        saved[0]["handoff_id"],
        saved[1]["handoff_id"],
        tmp_path,
        only_changed=True,
        include_stable=True,
    )
    assert payload["summary"]["stable"] == 0
    assert payload["stable"] == []


def test_same_handoff_compare_has_no_changes(monkeypatch, tmp_path):  # 14
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload()])
    result = runner.invoke(
        app, ["handoff", "compare", saved[0]["handoff_id"], saved[0]["handoff_id"], "--json"]
    )
    assert result.exit_code == 0
    payload = _assert_strict_json(result.stdout)
    assert payload["status"] == "ok"
    assert payload["changes"] == []
    assert payload["summary"]["changed"] == 0
    assert payload["summary"]["new"] == 0
    assert payload["summary"]["safety_drift"] == 0


def test_compare_missing_before_ref_is_controlled(monkeypatch, tmp_path):  # 15
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload()])
    result = runner.invoke(
        app, ["handoff", "compare", "handoff_missing", saved[0]["handoff_id"], "--json"]
    )
    assert result.exit_code != 0
    payload = _assert_strict_json(result.stdout)
    assert payload["status"] == "not_found"
    _assert_no_traceback(result)
    for flag in _MUTATION_SAFETY_FLAGS:
        assert payload["safety"][flag] is False, flag


def test_compare_missing_after_ref_is_controlled(monkeypatch, tmp_path):  # 16
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload()])
    result = runner.invoke(
        app, ["handoff", "compare", saved[0]["handoff_id"], "handoff_missing", "--json"]
    )
    assert result.exit_code != 0
    payload = _assert_strict_json(result.stdout)
    assert payload["status"] == "not_found"
    assert payload["before"]["handoff_id"] == saved[0]["handoff_id"]
    _assert_no_traceback(result)


def test_compare_malformed_handoff_is_controlled_failure(monkeypatch, tmp_path):  # 17
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload(), _payload(risk="high")])
    (Path(saved[0]["handoff_path"]) / "handoff.json").write_text("{ broken", encoding="utf-8")
    result = runner.invoke(
        app, ["handoff", "compare", saved[0]["handoff_id"], saved[1]["handoff_id"], "--json"]
    )
    assert result.exit_code != 0
    payload = _assert_strict_json(result.stdout)
    assert payload["status"] == "failed"
    _assert_no_traceback(result)


def test_compare_unsafe_ref_is_controlled(monkeypatch, tmp_path):  # 17 (path traversal)
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload()])
    result = runner.invoke(
        app, ["handoff", "compare", "../../etc/passwd", saved[0]["handoff_id"], "--json"]
    )
    assert result.exit_code != 0
    payload = _assert_strict_json(result.stdout)
    assert payload["status"] in {"failed", "not_found"}
    _assert_no_traceback(result)


def test_compare_detects_safety_drift(monkeypatch, tmp_path):  # 18
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload(), _payload()])
    # Tamper the after handoff so a previously-false mutating flag reads true.
    after_json = Path(saved[1]["handoff_path"]) / "handoff.json"
    data = json.loads(after_json.read_text())
    data["safety"]["cleanup_executed"] = True
    after_json.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    payload = compare_v2_handoffs(saved[0]["handoff_id"], saved[1]["handoff_id"], tmp_path)
    assert payload["summary"]["safety_drift"] == 1
    drift = [c for c in payload["changes"] if c.get("field") == "safety"]
    assert drift and drift[0]["drift"][0]["flag"] == "cleanup_executed"
    assert any("critical safety drift" in w for w in payload["warnings"])


def test_compare_never_reruns_collectors(monkeypatch, tmp_path):  # 19
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload(), _payload(risk="high")])
    _arm_no_collectors_no_model_no_shell(monkeypatch)
    result = runner.invoke(
        app, ["handoff", "compare", saved[0]["handoff_id"], saved[1]["handoff_id"], "--json"]
    )
    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "ok"


def test_compare_never_calls_model(monkeypatch, tmp_path):  # 20
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload(), _payload(risk="high")])

    def boom_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("compare must not call the model/Codex")

    monkeypatch.setattr(cli_mod, "build_provider", boom_provider)
    result = runner.invoke(
        app, ["handoff", "compare", saved[0]["handoff_id"], saved[1]["handoff_id"]]
    )
    assert result.exit_code == 0
    payload = json.loads(
        runner.invoke(
            app, ["handoff", "compare", saved[0]["handoff_id"], saved[1]["handoff_id"], "--json"]
        ).stdout
    )
    assert payload["safety"]["model_called"] is False


def test_compare_never_executes_shell(monkeypatch, tmp_path):  # 21
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload(), _payload(risk="high")])

    def boom_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"compare must not run subprocesses: {cmd!r}")

    monkeypatch.setattr(cli_mod.subprocess, "run", boom_run)
    result = runner.invoke(
        app, ["handoff", "compare", saved[0]["handoff_id"], saved[1]["handoff_id"], "--json"]
    )
    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "ok"


def test_compare_never_mutates_files(monkeypatch, tmp_path):  # 22
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload(), _payload(risk="high")])
    before = {p.relative_to(tmp_path): p.stat().st_mtime for p in tmp_path.rglob("*")}
    runner.invoke(
        app, ["handoff", "compare", saved[0]["handoff_id"], saved[1]["handoff_id"], "--json"]
    )
    runner.invoke(
        app,
        [
            "handoff",
            "compare",
            saved[0]["handoff_id"],
            saved[1]["handoff_id"],
            "--include-stable",
            "--json",
        ],
    )
    after = {p.relative_to(tmp_path): p.stat().st_mtime for p in tmp_path.rglob("*")}
    assert before == after


# --------------------------------------------------------------------------- #
# Compare-latest                                                               #
# --------------------------------------------------------------------------- #
def test_compare_latest_not_enough_history(monkeypatch, tmp_path):  # 23
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _save_all(monkeypatch, tmp_path, [_payload()])  # only one saved
    result = runner.invoke(app, ["handoff", "compare-latest", "--json"])
    assert result.exit_code == 0
    payload = _assert_strict_json(result.stdout)
    assert payload["status"] == "not_enough_history"
    assert payload["first_safe_command"] == "shellforgeai handoff --save"
    _assert_no_traceback(result)


def test_compare_latest_empty_not_enough_history(monkeypatch, tmp_path):  # 23
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    payload = compare_latest_v2_handoffs(tmp_path)
    assert payload["status"] == "not_enough_history"
    assert payload["available"] == 0


def test_compare_latest_two_handoffs_is_ok(monkeypatch, tmp_path):  # 24
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload(risk="low"), _payload(risk="high")])
    result = runner.invoke(app, ["handoff", "compare-latest"])
    assert result.exit_code == 0
    assert "V2 handoff compare-latest" in result.stdout
    payload = compare_latest_v2_handoffs(tmp_path)
    assert payload["status"] == "ok"
    assert payload["latest"] is True
    # Latest two: before is the older, after is the newest.
    assert payload["before"]["handoff_id"] == saved[0]["handoff_id"]
    assert payload["after"]["handoff_id"] == saved[1]["handoff_id"]


def test_compare_latest_json_is_strict(monkeypatch, tmp_path):  # 25
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _save_all(monkeypatch, tmp_path, [_payload(), _payload(risk="high")])
    result = runner.invoke(app, ["handoff", "compare-latest", "--json"])
    payload = _assert_strict_json(result.stdout)
    assert payload["mode"] == "v2_handoff_compare_latest"
    assert payload["status"] == "ok"


# --------------------------------------------------------------------------- #
# Ask / interactive routing                                                    #
# --------------------------------------------------------------------------- #
def test_ask_show_handoff_history_routes(monkeypatch, tmp_path):  # 26
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))

    def boom_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("handoff-history ask must not fall back to the model")

    monkeypatch.setattr(cli_mod, "build_provider", boom_provider)
    result = runner.invoke(app, ["ask", "show handoff history"])
    assert result.exit_code == 0
    assert "Read-only handoff history (deterministic ask routing)" in result.stdout
    assert "shellforgeai handoff history" in result.stdout


def test_ask_compare_latest_handoffs_routes(monkeypatch, tmp_path):  # 27
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))

    def boom_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("handoff-compare ask must not fall back to the model")

    monkeypatch.setattr(cli_mod, "build_provider", boom_provider)
    result = runner.invoke(app, ["ask", "compare latest handoffs"])
    assert result.exit_code == 0
    assert "Read-only handoff compare-latest (deterministic ask routing)" in result.stdout
    assert "shellforgeai handoff compare-latest" in result.stdout


def test_ask_what_changed_since_last_handoff_routes(monkeypatch, tmp_path):  # 27
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))

    def boom_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("handoff-compare ask must not fall back to the model")

    monkeypatch.setattr(cli_mod, "build_provider", boom_provider)
    result = runner.invoke(app, ["ask", "what changed since last handoff?"])
    assert result.exit_code == 0
    assert "compare-latest" in result.stdout


def test_interactive_handoff_history_routes_and_dispatches(monkeypatch, tmp_path):  # 28
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _save_all(monkeypatch, tmp_path, [_payload()])
    assert route_input("handoff history").argv == ("handoff", "history")
    assert route_input("handoff history --json").argv == ("handoff", "history", "--json")
    assert route_input("handoff history --limit 3").argv == (
        "handoff",
        "history",
        "--limit",
        "3",
    )
    out = repl._run_interactive_cli_dispatch(Console(file=StringIO()), ("handoff", "history"))
    assert "V2 handoff history" in out


def test_interactive_handoff_compare_latest_routes_and_dispatches(monkeypatch, tmp_path):  # 29
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload(), _payload(risk="high")])
    assert route_input("handoff compare-latest").argv == ("handoff", "compare-latest")
    assert route_input("handoff compare-latest --json").argv == (
        "handoff",
        "compare-latest",
        "--json",
    )
    assert route_input(
        f"handoff compare {saved[0]['handoff_id']} {saved[1]['handoff_id']}"
    ).argv == ("handoff", "compare", saved[0]["handoff_id"], saved[1]["handoff_id"])
    out = repl._run_interactive_cli_dispatch(
        Console(file=StringIO()), ("handoff", "compare-latest")
    )
    assert "V2 handoff compare-latest" in out


def test_interactive_help_mentions_history_compare() -> None:  # 29
    text = repl.INTERACTIVE_HELP_TEXT
    assert "handoff history" in text
    assert "handoff compare" in text
    assert "compare-latest" in text


# --------------------------------------------------------------------------- #
# Safety guarantees                                                            #
# --------------------------------------------------------------------------- #
def test_history_compare_modules_have_no_execution_primitives() -> None:
    source = Path("src/shellforgeai/core/v2_handoff_artifact.py").read_text(encoding="utf-8")
    for banned in (
        "import subprocess",
        "subprocess.",
        "os.system",
        "Popen",
        "shell=True",
        "build_provider",
        "docker restart",
        "docker compose",
    ):
        assert banned not in source, banned


def test_no_shell_true_in_new_cli_paths() -> None:
    for path in (
        Path("src/shellforgeai/cli.py"),
        Path("src/shellforgeai/core/v2_handoff_artifact.py"),
        Path("src/shellforgeai/interactive/commands.py"),
    ):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    assert not (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ), path


def test_compare_safety_block_is_read_only(monkeypatch, tmp_path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    saved = _save_all(monkeypatch, tmp_path, [_payload(), _payload(risk="high")])
    payload = compare_v2_handoffs(saved[0]["handoff_id"], saved[1]["handoff_id"], tmp_path)
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    for flag in _MUTATION_SAFETY_FLAGS:
        assert payload["safety"][flag] is False, flag


def test_history_core_helper_round_trip(monkeypatch, tmp_path):
    saved = _save_all(monkeypatch, tmp_path, [_payload(), _payload(risk="high")])
    history = v2_handoff_history(tmp_path)
    assert history["count"] == 2
    assert history["latest_handoff_id"] == saved[1]["handoff_id"]
    ids = {h["handoff_id"] for h in history["handoffs"]}
    assert ids == {saved[0]["handoff_id"], saved[1]["handoff_id"]}
