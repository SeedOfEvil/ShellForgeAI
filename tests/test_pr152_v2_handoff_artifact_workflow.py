"""PR152: V2 handoff artifact validate/export lifecycle.

Covers the read-only lifecycle:

    handoff --save -> handoff validate -> handoff export -> handoff export-validate

Save/export write only ShellForgeAI-owned artifacts; validate/export-validate are
strictly read-only. Nothing here executes cleanup/remediation/rollback, mutates
Docker/Compose/containers, uses shell=True, runs arbitrary commands, or calls the
model.
"""

from __future__ import annotations

import ast
import json
from io import StringIO
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.core.v2_handoff_artifact import (
    REQUIRED_EXPORT_FILES,
    REQUIRED_HANDOFF_FILES,
    export_v2_handoff,
    validate_v2_handoff,
    validate_v2_handoff_export,
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


def _safety() -> dict:
    return {
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


def _scene(*, empty: bool = False, target: str = "sfai-crashloop") -> dict:
    if empty:
        return {"containers": []}
    return {"containers": [{"name": target, "labels": {}}]}


def _ranked(*, empty: bool = False, target: str = "sfai-crashloop") -> dict:
    if empty:
        return {
            "status": "ok",
            "summary": {"containers_seen": 0, "suspects_ranked": 0, "critical": 0, "high": 0},
            "suspects": [],
            "warnings": [],
            "safety": _safety(),
        }
    return {
        "status": "ok",
        "summary": {"containers_seen": 1, "suspects_ranked": 1, "critical": 1, "high": 0},
        "suspects": [
            {
                "rank": 1,
                "name": target,
                "kind": "container",
                "severity": "critical",
                "confidence": "high",
                "score": 100,
                "classes": ["crashloop"],
                "why": ["critical restart storm evidence from Docker triage"],
                "evidence": [{"type": "restart_count", "value": 9}],
                "safe_next_commands": [f"shellforgeai triage docker detail {target}"],
            }
        ],
        "warnings": [],
        "safety": _safety(),
    }


def _patch_triage(monkeypatch, tmp_path: Path, *, empty: bool = True) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: _scene(empty=empty),
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene",
        lambda scene: _ranked(empty=empty),
    )


def _save_handoff(monkeypatch, tmp_path: Path) -> dict:
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["handoff", "--save", "--json"])
    assert result.exit_code == 0, result.stdout
    return json.loads(result.stdout)


def _assert_strict_json(stdout: str) -> dict:
    stripped = stdout.strip()
    assert stripped.startswith("{"), stripped[:80]
    assert stripped.endswith("}"), stripped[-80:]
    return json.loads(stripped)


def _assert_no_traceback(result) -> None:
    assert "Traceback" not in result.output
    # A controlled non-zero exit is a SystemExit (typer.Exit), never a raw crash.
    assert result.exception is None or isinstance(result.exception, SystemExit)


# --------------------------------------------------------------------------- #
# Save                                                                         #
# --------------------------------------------------------------------------- #
def test_save_creates_handoff_artifact(monkeypatch, tmp_path):  # 1
    saved = _save_handoff(monkeypatch, tmp_path)
    out = Path(saved["handoff_path"])
    assert out.is_dir()
    assert out.resolve().is_relative_to((tmp_path / "v2_handoffs").resolve())
    assert saved["handoff_id"].startswith("handoff_")


def test_save_json_is_strict(monkeypatch, tmp_path):  # 2
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["handoff", "--save", "--json"])
    payload = _assert_strict_json(result.stdout)
    assert payload["mode"] == "v2_handoff"
    assert payload["artifact_written"] is True


def test_saved_artifact_has_required_files(monkeypatch, tmp_path):  # 3
    saved = _save_handoff(monkeypatch, tmp_path)
    out = Path(saved["handoff_path"])
    for name in REQUIRED_HANDOFF_FILES:
        assert (out / name).exists(), name


def test_saved_artifact_safety_is_read_only(monkeypatch, tmp_path):  # 4
    saved = _save_handoff(monkeypatch, tmp_path)
    assert saved["read_only"] is True
    for flag in _MUTATION_SAFETY_FLAGS:
        assert saved["safety"][flag] is False, flag
    manifest = json.loads((Path(saved["handoff_path"]) / "manifest.json").read_text())
    assert manifest["mutation_performed"] is False
    assert manifest["safety"]["read_only"] is True


# --------------------------------------------------------------------------- #
# Validate                                                                     #
# --------------------------------------------------------------------------- #
def test_validate_by_id_returns_ok(monkeypatch, tmp_path):  # 5
    saved = _save_handoff(monkeypatch, tmp_path)
    result = runner.invoke(app, ["handoff", "validate", saved["handoff_id"], "--json"])
    assert result.exit_code == 0
    payload = _assert_strict_json(result.stdout)
    assert payload["mode"] == "v2_handoff_validate"
    assert payload["status"] == "ok"
    assert all(payload["checks"].values())
    assert payload["read_only"] is True


def test_validate_by_path_returns_ok(monkeypatch, tmp_path):  # 6
    saved = _save_handoff(monkeypatch, tmp_path)
    result = runner.invoke(app, ["handoff", "validate", saved["handoff_path"], "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "ok"


def test_validate_missing_ref_is_not_found(monkeypatch, tmp_path):  # 7
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["handoff", "validate", "handoff_does_not_exist", "--json"])
    assert result.exit_code != 0
    assert json.loads(result.stdout)["status"] == "not_found"
    _assert_no_traceback(result)


def test_validate_malformed_artifact_fails(monkeypatch, tmp_path):  # 8
    saved = _save_handoff(monkeypatch, tmp_path)
    (Path(saved["handoff_path"]) / "handoff.json").write_text("{ not valid json", encoding="utf-8")
    result = runner.invoke(app, ["handoff", "validate", saved["handoff_id"], "--json"])
    assert result.exit_code != 0
    assert json.loads(result.stdout)["status"] == "failed"
    _assert_no_traceback(result)


def test_validate_does_not_traceback_on_unsafe_ref(monkeypatch, tmp_path):  # 9
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["handoff", "validate", "../../etc/passwd", "--json"])
    assert result.exit_code != 0
    _assert_no_traceback(result)
    assert json.loads(result.stdout)["status"] in {"failed", "not_found"}


def test_validate_checksum_mismatch_fails(monkeypatch, tmp_path):  # validate integrity
    saved = _save_handoff(monkeypatch, tmp_path)
    (Path(saved["handoff_path"]) / "handoff.md").write_text("tampered\n", encoding="utf-8")
    payload = validate_v2_handoff(saved["handoff_id"], tmp_path)
    assert payload["status"] == "failed"
    assert payload["checks"]["checksums"] is False


# --------------------------------------------------------------------------- #
# Export                                                                       #
# --------------------------------------------------------------------------- #
def test_export_creates_export_artifact(monkeypatch, tmp_path):  # 10
    saved = _save_handoff(monkeypatch, tmp_path)
    result = runner.invoke(app, ["handoff", "export", saved["handoff_id"], "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "exported"
    out = Path(payload["export"]["path"])
    assert out.is_dir()
    assert out.name == f"export_{saved['handoff_id']}"


def test_export_json_is_strict(monkeypatch, tmp_path):  # 11
    saved = _save_handoff(monkeypatch, tmp_path)
    result = runner.invoke(app, ["handoff", "export", saved["handoff_id"], "--json"])
    payload = _assert_strict_json(result.stdout)
    assert payload["mode"] == "v2_handoff_export"


def test_export_has_export_manifest(monkeypatch, tmp_path):  # 12
    saved = _save_handoff(monkeypatch, tmp_path)
    payload = json.loads(
        runner.invoke(app, ["handoff", "export", saved["handoff_id"], "--json"]).stdout
    )
    out = Path(payload["export"]["path"])
    for name in REQUIRED_EXPORT_FILES:
        assert (out / name).exists(), name
    export_manifest = json.loads((out / "export-manifest.json").read_text())
    assert export_manifest["source_handoff"]["id"] == saved["handoff_id"]
    assert export_manifest["checksums"]


def test_repeated_export_is_idempotent(monkeypatch, tmp_path):  # 13
    saved = _save_handoff(monkeypatch, tmp_path)
    first = json.loads(
        runner.invoke(app, ["handoff", "export", saved["handoff_id"], "--json"]).stdout
    )
    second = runner.invoke(app, ["handoff", "export", saved["handoff_id"], "--json"])
    assert second.exit_code == 0
    second_payload = json.loads(second.stdout)
    assert second_payload["status"] == "exported"
    assert second_payload["existing"] is True
    assert second_payload["export"]["id"] == first["export"]["id"]


def test_export_refuses_unsafe_ref(monkeypatch, tmp_path):  # 14
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["handoff", "export", "../../tmp/evil", "--json"])
    assert result.exit_code != 0
    payload = json.loads(result.stdout)
    assert payload["status"] in {"failed", "not_found"}
    _assert_no_traceback(result)
    # No export tree leaked outside the owned exports path.
    assert not (tmp_path / "exports").exists() or not any((tmp_path / "exports").iterdir())


# --------------------------------------------------------------------------- #
# Export-validate                                                              #
# --------------------------------------------------------------------------- #
def _export(monkeypatch, tmp_path: Path) -> dict:
    saved = _save_handoff(monkeypatch, tmp_path)
    exported = json.loads(
        runner.invoke(app, ["handoff", "export", saved["handoff_id"], "--json"]).stdout
    )
    return exported


def test_export_validate_by_id_returns_ok(monkeypatch, tmp_path):  # 15
    exported = _export(monkeypatch, tmp_path)
    result = runner.invoke(app, ["handoff", "export-validate", exported["export"]["id"], "--json"])
    assert result.exit_code == 0
    payload = _assert_strict_json(result.stdout)
    assert payload["mode"] == "v2_handoff_export_validate"
    assert payload["status"] == "ok"
    assert all(payload["checks"].values())


def test_export_validate_by_path_returns_ok(monkeypatch, tmp_path):  # 16
    exported = _export(monkeypatch, tmp_path)
    result = runner.invoke(
        app, ["handoff", "export-validate", exported["export"]["path"], "--json"]
    )
    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "ok"


def test_export_validate_missing_ref_is_not_found(monkeypatch, tmp_path):  # 17
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["handoff", "export-validate", "export_missing", "--json"])
    assert result.exit_code != 0
    assert json.loads(result.stdout)["status"] == "not_found"
    _assert_no_traceback(result)


def test_export_validate_malformed_fails(monkeypatch, tmp_path):  # 18
    exported = _export(monkeypatch, tmp_path)
    out = Path(exported["export"]["path"])
    (out / "export-manifest.json").write_text("{ broken", encoding="utf-8")
    result = runner.invoke(app, ["handoff", "export-validate", exported["export"]["id"], "--json"])
    assert result.exit_code != 0
    assert json.loads(result.stdout)["status"] == "failed"
    _assert_no_traceback(result)


def test_export_validate_does_not_traceback(monkeypatch, tmp_path):  # 19
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["handoff", "export-validate", "../../etc", "--json"])
    assert result.exit_code != 0
    _assert_no_traceback(result)


# --------------------------------------------------------------------------- #
# Safety                                                                       #
# --------------------------------------------------------------------------- #
def test_lifecycle_runs_no_subprocess_or_model(monkeypatch, tmp_path):  # 20-26
    _patch_triage(monkeypatch, tmp_path)

    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"handoff lifecycle must not run subprocesses: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("handoff lifecycle must not call the model provider")

    monkeypatch.setattr(cli_mod.subprocess, "run", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)

    saved = json.loads(runner.invoke(app, ["handoff", "--save", "--json"]).stdout)
    hid = saved["handoff_id"]
    assert runner.invoke(app, ["handoff", "validate", hid, "--json"]).exit_code == 0
    exported = json.loads(runner.invoke(app, ["handoff", "export", hid, "--json"]).stdout)
    eid = exported["export"]["id"]
    assert runner.invoke(app, ["handoff", "export-validate", eid, "--json"]).exit_code == 0

    # Every recorded safety flag stays false for mutation/execution.
    for payload in (saved, exported):
        for flag in _MUTATION_SAFETY_FLAGS:
            assert payload["safety"].get(flag) is False, flag
    assert exported["safety"]["artifact_export_only"] is True
    assert exported["safety"]["arbitrary_path_write"] is False


def test_export_writes_only_owned_export_path(monkeypatch, tmp_path):  # 27
    saved = _save_handoff(monkeypatch, tmp_path)
    payload = json.loads(
        runner.invoke(app, ["handoff", "export", saved["handoff_id"], "--json"]).stdout
    )
    out = Path(payload["export"]["path"])
    assert out.resolve().is_relative_to((tmp_path / "exports").resolve())
    # Only the two ShellForgeAI-owned artifact trees exist under the data dir.
    top_level = {p.name for p in tmp_path.iterdir() if p.is_dir()}
    assert top_level <= {"v2_handoffs", "exports"}


def test_validate_and_export_validate_are_read_only(monkeypatch, tmp_path):  # 28
    exported = _export(monkeypatch, tmp_path)
    hid = exported["source_handoff"]["id"]
    eid = exported["export"]["id"]
    before = {p.relative_to(tmp_path): p.stat().st_mtime for p in tmp_path.rglob("*")}
    runner.invoke(app, ["handoff", "validate", hid, "--json"])
    runner.invoke(app, ["handoff", "export-validate", eid, "--json"])
    after = {p.relative_to(tmp_path): p.stat().st_mtime for p in tmp_path.rglob("*")}
    assert before == after  # no creates, deletes, or rewrites


def test_lifecycle_module_has_no_execution_primitives() -> None:  # 24, 25
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


def test_lifecycle_cli_handlers_no_shell_true() -> None:  # 24
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


def test_export_safety_block_is_artifact_export_only(monkeypatch, tmp_path):  # safety contract
    exported = _export(monkeypatch, tmp_path)
    out = Path(exported["export"]["path"])
    export_manifest = json.loads((out / "export-manifest.json").read_text())
    safety = export_manifest["safety"]
    assert safety["artifact_export_only"] is True
    assert safety["arbitrary_path_write"] is False
    for flag in _MUTATION_SAFETY_FLAGS:
        assert safety.get(flag) is False, flag


# --------------------------------------------------------------------------- #
# Ask / interactive                                                            #
# --------------------------------------------------------------------------- #
def test_interactive_handoff_save_works(monkeypatch, tmp_path):  # 29
    _patch_triage(monkeypatch, tmp_path)
    assert route_input("handoff --save").argv == ("handoff", "--save")
    out = repl._run_interactive_cli_dispatch(Console(file=StringIO()), ("handoff", "--save"))
    assert "Handoff saved:" in out
    assert list((tmp_path / "v2_handoffs").glob("handoff_*"))


def test_interactive_handoff_lifecycle_dispatch_supported(monkeypatch, tmp_path):  # 30
    saved = _save_handoff(monkeypatch, tmp_path)
    hid = saved["handoff_id"]
    # routing
    assert route_input(f"handoff validate {hid}").argv == ("handoff", "validate", hid)
    assert route_input(f"handoff export {hid} --json").argv == (
        "handoff",
        "export",
        hid,
        "--json",
    )
    assert route_input("handoff export-validate eid").argv == (
        "handoff",
        "export-validate",
        "eid",
    )
    # dispatch end to end
    console = Console(file=StringIO())
    v_out = repl._run_interactive_cli_dispatch(console, ("handoff", "validate", hid))
    assert "Handoff validation: ok" in v_out
    e_out = repl._run_interactive_cli_dispatch(console, ("handoff", "export", hid, "--json"))
    eid = json.loads(e_out)["export"]["id"]
    ev_out = repl._run_interactive_cli_dispatch(console, ("handoff", "export-validate", eid))
    assert "Handoff export validation: ok" in ev_out


def test_interactive_help_mentions_handoff_lifecycle() -> None:  # 30
    text = repl.INTERACTIVE_HELP_TEXT
    assert "handoff validate" in text
    assert "handoff export" in text
    assert "handoff export-validate" in text
    assert "handoff --save" in text


def test_ask_export_handoff_gives_safe_guidance_no_ref(monkeypatch, tmp_path):  # 31
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["ask", "export handoff"])
    assert result.exit_code == 0
    assert "Handoff artifact lifecycle" in result.stdout
    assert "shellforgeai handoff validate" in result.stdout
    assert "shellforgeai handoff export" in result.stdout
    low = result.stdout.lower()
    for forbidden in ("docker restart", "docker compose", "--execute", "--confirm"):
        assert forbidden not in low


def test_ask_validate_handoff_gives_safe_guidance(monkeypatch, tmp_path):  # 31
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["ask", "validate handoff"])
    assert result.exit_code == 0
    assert "Handoff artifact lifecycle" in result.stdout


# --------------------------------------------------------------------------- #
# JSON contract: all four modes present and strict                             #
# --------------------------------------------------------------------------- #
def test_all_four_json_modes_strict(monkeypatch, tmp_path):  # JSON contract
    _patch_triage(monkeypatch, tmp_path)
    saved = _assert_strict_json(runner.invoke(app, ["handoff", "--save", "--json"]).stdout)
    hid = saved["handoff_id"]
    validate = _assert_strict_json(
        runner.invoke(app, ["handoff", "validate", hid, "--json"]).stdout
    )
    export = _assert_strict_json(runner.invoke(app, ["handoff", "export", hid, "--json"]).stdout)
    eid = export["export"]["id"]
    export_validate = _assert_strict_json(
        runner.invoke(app, ["handoff", "export-validate", eid, "--json"]).stdout
    )
    assert saved["mode"] == "v2_handoff"
    assert validate["mode"] == "v2_handoff_validate"
    assert export["mode"] == "v2_handoff_export"
    assert export_validate["mode"] == "v2_handoff_export_validate"


# --------------------------------------------------------------------------- #
# Core helpers behave for direct callers                                       #
# --------------------------------------------------------------------------- #
def test_core_helpers_round_trip(monkeypatch, tmp_path):  # core contract
    saved = _save_handoff(monkeypatch, tmp_path)
    hid = saved["handoff_id"]
    assert validate_v2_handoff(hid, tmp_path)["status"] == "ok"
    exported = export_v2_handoff(hid, tmp_path)
    assert exported["status"] == "exported"
    assert validate_v2_handoff_export(exported["export"]["id"], tmp_path)["status"] == "ok"
