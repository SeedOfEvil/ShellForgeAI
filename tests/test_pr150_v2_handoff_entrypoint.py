from __future__ import annotations

import ast
import json
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.core.v2_handoff_artifact import resolve_handoff_dir, save_v2_handoff
from shellforgeai.interactive import repl
from shellforgeai.interactive.commands import route_input

runner = CliRunner()

_SAFETY_FLAGS = (
    "mutation_performed",
    "apply_executed",
    "mission_created",
    "plan_created",
    "remediation_executed",
    "rollback_executed",
    "cleanup_executed",
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


def _scene(
    *, empty: bool = False, labels: dict | None = None, target: str = "sfai-crashloop"
) -> dict:
    if empty:
        return {"containers": []}
    return {"containers": [{"name": target, "labels": labels or {}}]}


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


def _patch_triage(
    monkeypatch,
    tmp_path: Path,
    *,
    empty: bool = False,
    labels: dict | None = None,
    target: str = "sfai-crashloop",
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: _scene(empty=empty, labels=labels, target=target),
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene",
        lambda scene: _ranked(empty=empty, target=target),
    )


def _assert_forbidden_absent(text: str) -> None:
    low = text.lower()
    for forbidden in (
        "remediation execute --confirm",
        "rollback-execute --confirm",
        "cleanup execute --confirm",
        "docker restart",
        "docker compose restart",
        "compose restart",
        "production restart",
        "--confirm",
        "--execute",
    ):
        assert forbidden not in low


# --------------------------------------------------------------------------- #
# CLI / human                                                                  #
# --------------------------------------------------------------------------- #
def test_handoff_human_read_only_operator_handoff(monkeypatch, tmp_path):  # 1
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["handoff"])
    assert result.exit_code == 0
    assert "Handoff: OK" in result.stdout
    assert "Status: no current Docker suspects" in result.stdout
    assert "Risk: low" in result.stdout
    _assert_forbidden_absent(result.stdout)


def test_handoff_brief_is_bounded_and_read_only(monkeypatch, tmp_path):  # 2
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["handoff", "--brief"])
    assert result.exit_code == 0
    assert result.stdout.count("\n") <= 5
    assert "Handoff: ok" in result.stdout
    assert "Safety: read-only" in result.stdout
    _assert_forbidden_absent(result.stdout)


def test_handoff_human_includes_v2_path_sections(monkeypatch, tmp_path):  # 3
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["handoff"])
    assert result.exit_code == 0
    assert "V2 path:" in result.stdout
    for stage in ("- Status:", "- Triage:", "- Propose:", "- Apply-preview:", "- Verify:"):
        assert stage in result.stdout


def test_handoff_human_includes_first_safe_command(monkeypatch, tmp_path):  # 4
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["handoff"])
    assert result.exit_code == 0
    assert "First safe command:" in result.stdout
    assert "shellforgeai status --json" in result.stdout


def test_handoff_human_says_no_action_taken_read_only(monkeypatch, tmp_path):  # 5
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["handoff"])
    assert result.exit_code == 0
    assert "No applied action was detected or assumed." in result.stdout
    assert "This handoff is a read-only operator summary." in result.stdout
    assert "Read-only handoff." in result.stdout
    assert "No action was taken." in result.stdout


def test_handoff_human_does_not_suggest_execute_or_confirm(monkeypatch, tmp_path):  # 6
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["handoff"])
    assert result.exit_code == 0
    _assert_forbidden_absent(result.stdout)
    low = result.stdout.lower()
    # No execute/confirm-style commands are suggested anywhere in the handoff.
    assert "execute --confirm" not in low
    assert "--execute" not in low
    assert "--confirm" not in low
    # Every suggested command is a read-only `shellforgeai ... ` inspection command.
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("shellforgeai "):
            assert "--execute" not in stripped and "--confirm" not in stripped


# --------------------------------------------------------------------------- #
# CLI / JSON                                                                   #
# --------------------------------------------------------------------------- #
def test_handoff_json_strict(monkeypatch, tmp_path):  # 7
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["handoff", "--json"])
    assert result.exit_code == 0
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1


def test_handoff_json_mode_is_v2_handoff(monkeypatch, tmp_path):  # 8
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["handoff", "--json"]).stdout)
    assert payload["mode"] == "v2_handoff"


def test_handoff_json_read_only_true(monkeypatch, tmp_path):  # 9
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["handoff", "--json"]).stdout)
    assert payload["read_only"] is True
    assert payload["safety"]["read_only"] is True


def test_handoff_json_mutation_performed_false(monkeypatch, tmp_path):  # 10
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["handoff", "--json"]).stdout)
    assert payload["mutation_performed"] is False
    assert payload["safety"]["mutation_performed"] is False


def test_handoff_json_artifact_written_false_without_save(monkeypatch, tmp_path):  # 11
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["handoff", "--json"]).stdout)
    assert payload["artifact_written"] is False
    assert payload["handoff_id"] is None
    assert payload["handoff_path"] is None


def test_handoff_json_includes_golden_path_sections(monkeypatch, tmp_path):  # 12
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["handoff", "--json"]).stdout)
    golden = payload["golden_path"]
    for stage in ("status", "triage", "propose", "apply_preview", "verify"):
        assert stage in golden
    summary = payload["summary"]
    for key in (
        "current_status",
        "risk",
        "suspects_ranked",
        "proposal_status",
        "apply_preview_status",
        "verify_status",
    ):
        assert key in summary


def test_handoff_json_safety_flags_all_false(monkeypatch, tmp_path):  # 13-23
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["handoff", "--json"]).stdout)
    for key in _SAFETY_FLAGS:
        assert payload[key] is False, key
        assert payload["safety"][key] is False, key


# --------------------------------------------------------------------------- #
# Save                                                                         #
# --------------------------------------------------------------------------- #
def test_handoff_save_json_writes_owned_artifact(monkeypatch, tmp_path):  # 24
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["handoff", "--save", "--json"]).stdout)
    assert payload["artifact_written"] is True
    assert payload["handoff_id"].startswith("handoff_")
    out = Path(payload["handoff_path"])
    assert out.exists()
    # Owned: lives strictly under the ShellForgeAI data dir.
    assert out.resolve().is_relative_to((tmp_path / "v2_handoffs").resolve())


def test_handoff_save_required_files(monkeypatch, tmp_path):  # 25
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["handoff", "--save", "--json"]).stdout)
    out = Path(payload["handoff_path"])
    for name in ("handoff.json", "handoff.md", "manifest.json"):
        assert (out / name).exists(), name


def test_handoff_save_manifest_and_checksums(monkeypatch, tmp_path):  # 26
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["handoff", "--save", "--json"]).stdout)
    out = Path(payload["handoff_path"])
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["handoff_id"] == payload["handoff_id"]
    assert manifest["checksums"]
    assert "handoff.json" in manifest["checksums"]
    assert payload["checksums"]["handoff.json"]


def test_handoff_save_safety_flags_remain_false(monkeypatch, tmp_path):  # 27
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["handoff", "--save", "--json"]).stdout)
    for key in _SAFETY_FLAGS:
        assert payload[key] is False, key
        assert payload["safety"][key] is False, key
    manifest = json.loads((Path(payload["handoff_path"]) / "manifest.json").read_text())
    assert manifest["mutation_performed"] is False
    assert manifest["artifact_written"] is True


def test_handoff_save_contains_no_secrets(monkeypatch, tmp_path):  # 28
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["handoff", "--save", "--json"]).stdout)
    out = Path(payload["handoff_path"])
    blob = (out / "handoff.json").read_text(encoding="utf-8").lower()
    blob += (out / "manifest.json").read_text(encoding="utf-8").lower()
    for marker in ("password", "secret", "token", "api_key", "api-key", "private_key"):
        assert marker not in blob


def test_handoff_save_invalid_path_is_rejected(monkeypatch, tmp_path):  # 29
    _patch_triage(monkeypatch, tmp_path, empty=True)
    payload = json.loads(runner.invoke(app, ["handoff", "--json"]).stdout)
    # Path traversal in handoff_id is refused.
    with pytest.raises(ValueError):
        resolve_handoff_dir(tmp_path, "../evil")
    # Traversal in the data dir root is refused.
    with pytest.raises(ValueError):
        save_v2_handoff(payload, tmp_path / ".." / "evil")
    # A payload carrying mutating safety metadata is never persisted.
    unsafe = dict(payload)
    unsafe["safety"] = {**payload["safety"], "mutation_performed": True}
    with pytest.raises(ValueError):
        save_v2_handoff(unsafe, tmp_path)


def test_handoff_save_human_points_to_validate(monkeypatch, tmp_path):  # save human contract
    # PR152 implements the handoff artifact lifecycle, so --save now points to the
    # first safe lifecycle step (validate) instead of deferring it. It must still
    # never suggest an execute/apply/confirm command.
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["handoff", "--save"])
    assert result.exit_code == 0
    assert "Handoff saved:" in result.stdout
    assert "shellforgeai handoff validate" in result.stdout
    low = result.stdout.lower()
    assert "--execute" not in low
    assert "--confirm" not in low
    _assert_forbidden_absent(result.stdout)


# --------------------------------------------------------------------------- #
# Ask routing                                                                  #
# --------------------------------------------------------------------------- #
def test_ask_give_me_a_handoff_routes(monkeypatch, tmp_path):  # 30
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["ask", "give me a handoff"])
    assert result.exit_code == 0
    assert "Read-only operator handoff (deterministic ask routing):" in result.stdout
    assert "Handoff: OK" in result.stdout
    assert "No action was taken." in result.stdout
    assert "Provider:" not in result.stdout


def test_ask_what_should_i_tell_next_operator_routes(monkeypatch, tmp_path):  # 31
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["ask", "what should I tell the next operator?"])
    assert result.exit_code == 0
    assert "Read-only operator handoff (deterministic ask routing):" in result.stdout
    assert "V2 path:" in result.stdout


def test_ask_handoff_summary_routes(monkeypatch, tmp_path):  # 32
    _patch_triage(monkeypatch, tmp_path, empty=True)
    result = runner.invoke(app, ["ask", "handoff summary"])
    assert result.exit_code == 0
    assert "Read-only operator handoff (deterministic ask routing):" in result.stdout


def test_ask_handoff_with_mutation_refuses_and_no_action(monkeypatch, tmp_path):  # 33
    _patch_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["ask", "give me a handoff and restart compose"])
    assert result.exit_code == 0
    assert "Read-only operator handoff (deterministic ask routing):" in result.stdout
    assert "Refused mutation part of the request." in result.stdout
    assert "No action was taken." in result.stdout
    _assert_forbidden_absent(result.stdout)


# --------------------------------------------------------------------------- #
# Interactive                                                                  #
# --------------------------------------------------------------------------- #
def test_interactive_handoff_works(monkeypatch, tmp_path):  # 34
    _patch_triage(monkeypatch, tmp_path, empty=True)
    assert route_input("handoff").argv == ("handoff",)
    out = repl._run_interactive_cli_dispatch(Console(file=StringIO()), ("handoff",))
    assert "Handoff:" in out
    assert "V2 path:" in out


def test_interactive_handoff_json_strict(monkeypatch, tmp_path):  # 35
    _patch_triage(monkeypatch, tmp_path, empty=True)
    assert route_input("handoff --json").argv == ("handoff", "--json")
    raw = repl._run_interactive_cli_dispatch(Console(file=StringIO()), ("handoff", "--json"))
    assert json.loads(raw)["mode"] == "v2_handoff"


def test_interactive_handoff_save_works(monkeypatch, tmp_path):  # 36
    _patch_triage(monkeypatch, tmp_path, empty=True)
    assert route_input("handoff --save").argv == ("handoff", "--save")
    out = repl._run_interactive_cli_dispatch(Console(file=StringIO()), ("handoff", "--save"))
    assert "Handoff saved:" in out
    saved_dirs = list((tmp_path / "v2_handoffs").glob("handoff_*"))
    assert saved_dirs


def test_interactive_next_operator_routes_to_handoff():  # 37
    assert route_input("what should I tell the next operator?").argv == ("handoff",)
    assert route_input("give me a handoff").argv == ("handoff",)
    assert "handoff [--brief|--json|--save]" in repl.INTERACTIVE_HELP_TEXT
    assert (
        "status -> triage -> propose -> apply-preview -> verify -> handoff"
        in repl.INTERACTIVE_HELP_TEXT
    )


def test_interactive_handoff_and_restart_refuses():  # 38
    assert route_input("handoff and restart").name == "mutation_refused"
    assert route_input("handoff then apply").name == "mutation_refused"
    assert route_input("summarize and fix it").name == "mutation_refused"


# --------------------------------------------------------------------------- #
# Safety                                                                       #
# --------------------------------------------------------------------------- #
def test_handoff_no_subprocess_or_model_and_no_stray_writes(monkeypatch, tmp_path):  # 39-45
    _patch_triage(monkeypatch, tmp_path)

    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"handoff must not run subprocesses: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("handoff must not call model provider")

    monkeypatch.setattr(cli_mod.subprocess, "run", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)
    before = {p.relative_to(tmp_path) for p in tmp_path.rglob("*")}
    result = runner.invoke(app, ["handoff", "--json"])
    after = {p.relative_to(tmp_path) for p in tmp_path.rglob("*")}
    assert result.exit_code == 0
    assert before == after  # non-save handoff writes nothing
    payload = json.loads(result.stdout)
    for key in _SAFETY_FLAGS:
        assert payload[key] is False
    _assert_forbidden_absent(result.stdout)


def test_handoff_save_only_writes_owned_artifact(monkeypatch, tmp_path):  # 39-45 (save lane)
    _patch_triage(monkeypatch, tmp_path)

    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"handoff --save must not run subprocesses: {cmd!r}")

    monkeypatch.setattr(cli_mod.subprocess, "run", fail_run)
    result = runner.invoke(app, ["handoff", "--save", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    written = sorted(p.relative_to(tmp_path).parts[0] for p in tmp_path.rglob("*") if p.is_file())
    # Only the ShellForgeAI-owned handoff artifact tree was written.
    assert set(written) == {"v2_handoffs"}
    assert payload["mutation_performed"] is False


def test_handoff_sources_contain_no_shell_true() -> None:  # 43
    for path in [
        Path("src/shellforgeai/cli.py"),
        Path("src/shellforgeai/core/v2_handoff_artifact.py"),
        Path("src/shellforgeai/interactive/commands.py"),
        Path("src/shellforgeai/interactive/repl.py"),
    ]:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    assert not (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ), path


def test_handoff_artifact_module_has_no_execution_primitives() -> None:  # 39-42, 44
    # The safety-flag keys legitimately contain words like "docker"/"compose";
    # assert against real execution primitives instead of flag-name substrings.
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
