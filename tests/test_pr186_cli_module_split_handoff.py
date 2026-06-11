from __future__ import annotations

import ast
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app

runner = CliRunner()


def _safety() -> dict[str, bool]:
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


def _patch_empty_triage(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene", lambda: {"containers": []}
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene",
        lambda scene: {
            "status": "ok",
            "summary": {
                "containers_seen": 0,
                "suspects_ranked": 0,
                "critical": 0,
                "high": 0,
            },
            "suspects": [],
            "warnings": [],
            "safety": _safety(),
        },
    )


def test_handoff_module_exists_and_cli_wires_registration() -> None:
    module = Path("src/shellforgeai/commands/handoff.py")
    cli = Path("src/shellforgeai/cli.py")
    assert module.exists()
    module_source = module.read_text(encoding="utf-8")
    cli_source = cli.read_text(encoding="utf-8")
    assert "def register(handoff_app: typer.Typer)" in module_source
    assert "from shellforgeai.commands import handoff as handoff_commands" in cli_source
    assert "handoff_commands.register(handoff_app)" in cli_source


def test_handoff_help_preserves_options_and_artifact_subcommands() -> None:
    result = runner.invoke(app, ["handoff", "--help"])
    assert result.exit_code == 0
    for expected in (
        "--json",
        "--brief",
        "--save",
        "--target",
        "--from-status",
        "--from-triage",
        "--from-propose",
        "--from-apply-preview",
        "--from-verify",
        "validate",
        "export",
        "export-validate",
        "history",
        "compare",
        "compare-latest",
    ):
        assert expected in result.stdout


def test_cli_no_longer_owns_handoff_handler_body() -> None:
    cli_source = Path("src/shellforgeai/cli.py").read_text(encoding="utf-8")
    assert "def _build_v2_handoff_payload" not in cli_source
    assert "def _render_v2_handoff_human" not in cli_source
    assert "def handoff(" not in cli_source
    assert "@handoff_app.callback" not in cli_source
    assert "@handoff_app.command" not in cli_source


def test_handoff_default_and_json_behaviour_preserved(monkeypatch, tmp_path) -> None:
    _patch_empty_triage(monkeypatch, tmp_path)
    human = runner.invoke(app, ["handoff"])
    assert human.exit_code == 0
    assert "Handoff: OK" in human.stdout
    assert "First safe command:" in human.stdout
    assert "No action was taken." in human.stdout

    result = runner.invoke(app, ["handoff", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["mode"] == "v2_handoff"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["safety"]["read_only"] is True
    for key in (
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "docker_compose_executed",
        "container_restarted",
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_execution",
        "model_called",
    ):
        assert payload[key] is False
        assert payload["safety"][key] is False
    assert payload["first_safe_command"] == "shellforgeai status --json"
    assert "shellforgeai verify --json" in payload["safe_next_commands"]


def test_handoff_brief_still_works(monkeypatch, tmp_path) -> None:
    _patch_empty_triage(monkeypatch, tmp_path)
    result = runner.invoke(app, ["handoff", "--brief"])
    assert result.exit_code == 0
    assert "Handoff: ok" in result.stdout
    assert "Safety: read-only" in result.stdout
    assert result.stdout.count("\n") <= 5


def test_handoff_artifact_save_validate_export_history_compare(monkeypatch, tmp_path) -> None:
    _patch_empty_triage(monkeypatch, tmp_path)
    first = runner.invoke(app, ["handoff", "--save", "--json"])
    second = runner.invoke(app, ["handoff", "--save", "--json"])
    assert first.exit_code == 0
    assert second.exit_code == 0
    first_payload = json.loads(first.stdout)
    second_payload = json.loads(second.stdout)
    assert first_payload["mode"] == "v2_handoff"
    assert first_payload["artifact_written"] is True
    assert first_payload["mutation_performed"] is False

    validate = runner.invoke(app, ["handoff", "validate", first_payload["handoff_id"], "--json"])
    assert validate.exit_code == 0
    assert json.loads(validate.stdout)["status"] == "ok"

    export = runner.invoke(app, ["handoff", "export", first_payload["handoff_id"], "--json"])
    assert export.exit_code == 0
    export_payload = json.loads(export.stdout)
    assert export_payload["status"] == "exported"

    export_validate = runner.invoke(
        app, ["handoff", "export-validate", export_payload["export"]["id"], "--json"]
    )
    assert export_validate.exit_code == 0
    assert json.loads(export_validate.stdout)["status"] == "ok"

    history = runner.invoke(app, ["handoff", "history", "--json"])
    assert history.exit_code == 0
    history_payload = json.loads(history.stdout)
    assert history_payload["mode"] == "v2_handoff_history"
    assert history_payload["count"] >= 2

    compare = runner.invoke(
        app,
        ["handoff", "compare", first_payload["handoff_id"], second_payload["handoff_id"], "--json"],
    )
    assert compare.exit_code == 0
    assert json.loads(compare.stdout)["mode"] == "v2_handoff_compare"

    latest = runner.invoke(app, ["handoff", "compare-latest", "--json"])
    assert latest.exit_code == 0
    assert json.loads(latest.stdout)["mode"] == "v2_handoff_compare_latest"


def test_handoff_missing_and_malformed_artifact_fail_cleanly(monkeypatch, tmp_path) -> None:
    _patch_empty_triage(monkeypatch, tmp_path)
    missing = runner.invoke(app, ["handoff", "validate", "handoff_missing", "--json"])
    assert missing.exit_code == 1
    missing_payload = json.loads(missing.stdout)
    assert missing_payload["status"] != "ok"
    assert "Traceback" not in missing.stdout

    malformed_dir = tmp_path / "v2_handoffs" / "handoff_bad"
    malformed_dir.mkdir(parents=True)
    (malformed_dir / "handoff.json").write_text("{not-json", encoding="utf-8")
    malformed = runner.invoke(app, ["handoff", "validate", str(malformed_dir), "--json"])
    assert malformed.exit_code == 1
    malformed_payload = json.loads(malformed.stdout)
    assert malformed_payload["status"] != "ok"
    assert "Traceback" not in malformed.stdout


def test_handoff_safety_no_execution_primitives_or_model_calls(monkeypatch, tmp_path) -> None:
    _patch_empty_triage(monkeypatch, tmp_path)

    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"handoff must not run subprocesses: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("handoff must not call model provider")

    monkeypatch.setattr(cli_mod.subprocess, "run", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)
    result = runner.invoke(app, ["handoff", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["safety"]["cleanup_executed"] is False
    assert payload["safety"]["remediation_executed"] is False
    assert payload["safety"]["rollback_executed"] is False
    assert payload["safety"]["docker_compose_executed"] is False
    assert payload["safety"]["container_restarted"] is False
    assert payload["safety"]["model_called"] is False


def test_handoff_command_module_has_no_forbidden_execution_primitives() -> None:
    source = Path("src/shellforgeai/commands/handoff.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                assert not (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                )
    for banned in (
        "import subprocess",
        "subprocess.",
        "os.system",
        "Popen",
        "shell=True",
        "build_provider",
        "docker compose",
        "docker restart",
        "cleanup execute --confirm",
        "remediation execute --confirm",
        "rollback-execute --confirm",
        "recovery execute --confirm",
    ):
        assert banned not in source, banned
