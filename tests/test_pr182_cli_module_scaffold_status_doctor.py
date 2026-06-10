"""PR182 — CLI command-module scaffold + status/doctor extraction.

These tests prove the behavior-preserving extraction of the ``status`` and
``doctor``/``model doctor`` command glue out of the monolithic
``shellforgeai.cli`` module into the new ``shellforgeai.commands`` package.

Scope is intentionally narrow:

* the new command package and modules exist and import cleanly,
* importing the command modules has no side effects,
* the moved commands keep their exact public surface, output, exit codes,
  strict JSON behavior, advisory wording, and read-only safety, and
* no new execution / mutation / model call is introduced.
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app

runner = CliRunner()

SRC = Path(__file__).resolve().parents[1] / "src" / "shellforgeai"
COMMANDS = SRC / "commands"


# --------------------------------------------------------------------------
# 1-6: structure / import hygiene
# --------------------------------------------------------------------------


def test_commands_package_init_exists() -> None:
    assert (COMMANDS / "__init__.py").exists()


def test_commands_status_module_exists() -> None:
    assert (COMMANDS / "status.py").exists()


def test_commands_doctor_module_exists() -> None:
    assert (COMMANDS / "doctor.py").exists()


def test_cli_imports_cleanly() -> None:
    mod = importlib.import_module("shellforgeai.cli")
    assert mod.app is app


def test_importing_command_modules_has_no_side_effects(monkeypatch) -> None:
    # Importing the command modules must not spawn subprocesses, build a model
    # provider, or create their own Typer app at module import time.
    def _boom_run(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("importing command modules must not run subprocesses")

    monkeypatch.setattr(subprocess, "run", _boom_run)
    for name in ("shellforgeai.commands.status", "shellforgeai.commands.doctor"):
        sys.modules.pop(name, None)
        mod = importlib.import_module(name)
        # No module-level Typer app should be constructed in the command slices.
        assert not hasattr(mod, "app")


def test_command_modules_expose_simple_registration_surface() -> None:
    status_mod = importlib.import_module("shellforgeai.commands.status")
    doctor_mod = importlib.import_module("shellforgeai.commands.doctor")
    assert callable(status_mod.register)
    assert callable(doctor_mod.register)


# --------------------------------------------------------------------------
# 7-14: command surface
# --------------------------------------------------------------------------


def test_root_help_works_and_lists_moved_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    out = result.stdout
    for name in ("status", "doctor", "version", "model"):
        assert name in out


def test_version_command_works() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "ShellForgeAI" in result.stdout


def test_doctor_help_works() -> None:
    result = runner.invoke(app, ["doctor", "--help"])
    assert result.exit_code == 0
    assert "--json" in result.stdout


def test_doctor_works(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "ShellForgeAI" in result.stdout
    assert "Metadata hygiene" in result.stdout


def test_model_doctor_help_works() -> None:
    result = runner.invoke(app, ["model", "doctor", "--help"])
    assert result.exit_code == 0


def test_model_doctor_works(monkeypatch) -> None:
    class _Provider:
        def doctor(self) -> dict[str, object]:
            return {"provider": "fake", "auth_cache_present": True}

    monkeypatch.setattr(cli_mod, "build_provider", lambda *a, **k: _Provider())
    result = runner.invoke(app, ["model", "doctor"])
    assert result.exit_code == 0
    assert "provider=fake" in result.stdout


def test_ops_report_json_is_strict(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene", lambda: {"containers": []}
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene",
        lambda scene: {
            "summary": {"containers_seen": 0, "suspects_ranked": 0, "critical": 0, "high": 0},
            "suspects": [],
        },
    )
    result = runner.invoke(app, ["ops", "report", "--json"])
    assert result.exit_code == 0
    text = result.stdout.strip()
    payload = json.loads(text)
    assert text.startswith("{") and text.endswith("}")
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False


def test_status_help_works() -> None:
    result = runner.invoke(app, ["status", "--help"])
    assert result.exit_code == 0
    assert "--json" in result.stdout


# --------------------------------------------------------------------------
# 15-20: behavior preservation
# --------------------------------------------------------------------------


def _patch_status_empty(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene", lambda: {"containers": []}
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene",
        lambda scene: {
            "summary": {"containers_seen": 0, "suspects_ranked": 0, "critical": 0, "high": 0},
            "suspects": [],
        },
    )
    monkeypatch.setattr(
        "shellforgeai.core.self_test.run_self_test_commands",
        lambda profile, include_skipped=False: {"status": "ok", "warnings": []},
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.build_remediation_audit_payload",
        lambda data_dir, latest_only=True: {"status": "ok"},
    )


def test_status_json_read_only_preserved(monkeypatch, tmp_path: Path) -> None:
    _patch_status_empty(monkeypatch, tmp_path)
    result = runner.invoke(app, ["status", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["mode"] == "status"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False


def test_doctor_json_safety_and_mutation_flags_preserved(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["safety"]["mutation_performed"] is False
    assert payload["safety"]["cleanup_executed"] is False
    assert payload["safety"]["docker_compose_executed"] is False
    assert payload["safety"]["remediation_executed"] is False
    assert payload["safety"]["rollback_executed"] is False


def test_doctor_and_model_doctor_have_no_traceback(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))

    class _Provider:
        def doctor(self) -> dict[str, object]:
            return {"provider": "fake", "auth_cache_present": False}

    monkeypatch.setattr(cli_mod, "build_provider", lambda *a, **k: _Provider())
    doctor_out = runner.invoke(app, ["doctor"])
    model_out = runner.invoke(app, ["model", "doctor"])
    for out in (doctor_out, model_out):
        assert out.exit_code == 0
        assert "Traceback" not in out.stdout
    assert "Suggested login: codex login" in model_out.stdout


def test_strict_json_has_no_human_text_around_payload(monkeypatch, tmp_path: Path) -> None:
    _patch_status_empty(monkeypatch, tmp_path)
    status_text = runner.invoke(app, ["status", "--json"]).stdout.strip()
    assert status_text.startswith("{") and status_text.endswith("}")
    # doctor --json emits a pretty JSON object only.
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    doctor_text = runner.invoke(app, ["doctor", "--json"]).stdout.strip()
    assert doctor_text.startswith("{") and doctor_text.endswith("}")
    json.loads(doctor_text)


def test_exit_codes_for_success_paths_are_zero(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    assert runner.invoke(app, ["doctor"]).exit_code == 0
    assert runner.invoke(app, ["doctor", "--json"]).exit_code == 0
    assert runner.invoke(app, ["version"]).exit_code == 0


def test_doctor_advisory_behavior_preserved(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHELLFORGEAI_METADATA_WARN_BYTES", "1")
    exports = tmp_path / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    for i in range(3):
        (exports / f"e{i}.bin").write_text("x" * 64, encoding="utf-8")
    out = runner.invoke(app, ["doctor"])
    assert out.exit_code == 0
    assert "First safe command: shellforgeai audit cleanup review" in out.stdout
    assert "No cleanup was performed." in out.stdout
    assert "review -> plan -> archive -> validate -> execute --confirm" in out.stdout


# --------------------------------------------------------------------------
# 21-31: safety
# --------------------------------------------------------------------------


def test_status_and_doctor_do_not_mutate_data_dir(tmp_path: Path, monkeypatch) -> None:
    _patch_status_empty(monkeypatch, tmp_path)
    before = {p.name for p in tmp_path.iterdir()}
    runner.invoke(app, ["status"])
    runner.invoke(app, ["status", "--json"])
    runner.invoke(app, ["doctor"])
    runner.invoke(app, ["doctor", "--json"])
    after = {p.name for p in tmp_path.iterdir()}
    forbidden = {
        "cleanup_plans",
        "cleanup_archives",
        "cleanup_receipts",
        "remediation_receipts",
        "proposals",
        "missions",
        "apply-bundles",
        "actions",
        "execution_receipts",
        "prune_receipts",
    }
    assert (after - before).isdisjoint(forbidden)


def test_status_does_not_execute_subprocess(monkeypatch, tmp_path: Path) -> None:
    _patch_status_empty(monkeypatch, tmp_path)

    def _boom(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"status must not execute subprocesses: {cmd!r}")

    monkeypatch.setattr(cli_mod.subprocess, "run", _boom)
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0


def test_status_does_not_build_model_provider(monkeypatch, tmp_path: Path) -> None:
    _patch_status_empty(monkeypatch, tmp_path)

    def _fail_build_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("status must not build or call a model provider")

    monkeypatch.setattr(cli_mod, "build_provider", _fail_build_provider)
    result = runner.invoke(app, ["status", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["model_called"] is False


def test_command_modules_contain_no_unsafe_execution_tokens() -> None:
    # Static guard: the extracted command modules must not introduce any
    # cleanup/remediation/rollback/recovery/Docker/Compose/shell execution.
    sources = {
        name: (COMMANDS / f"{name}.py").read_text(encoding="utf-8") for name in ("status", "doctor")
    }
    # Note: the doctor JSON payload legitimately contains read-only *_executed
    # safety flags set to False (e.g. "cleanup_executed": false); those are
    # status fields, not execution, so they are intentionally not matched here.
    forbidden_tokens = (
        "shell=True",
        "subprocess.run",
        "subprocess.Popen",
        "os.system",
        "docker restart",
        "docker compose",
        "compose restart",
        "production restart",
    )
    for name, text in sources.items():
        low = text.lower()
        for token in forbidden_tokens:
            assert token.lower() not in low, f"{name}.py contains forbidden token: {token}"


def test_doctor_human_never_suggests_mutation_terms(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHELLFORGEAI_METADATA_WARN_BYTES", "1")
    exports = tmp_path / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    (exports / "e0.bin").write_text("x" * 64, encoding="utf-8")
    text = runner.invoke(app, ["doctor"]).stdout.lower()
    for forbidden in (
        "docker compose restart",
        "docker compose up",
        "docker compose down",
        "docker system prune",
        "rm -rf",
    ):
        assert forbidden not in text


# --------------------------------------------------------------------------
# 32-35: regression anchors (lightweight; full suites run separately)
# --------------------------------------------------------------------------


def test_model_test_command_still_registered_in_cli() -> None:
    # model test intentionally stays in cli.py; only model doctor was moved.
    result = runner.invoke(app, ["model", "--help"])
    assert result.exit_code == 0
    assert "doctor" in result.stdout
    assert "test" in result.stdout


def test_status_command_owned_by_commands_module() -> None:
    # The moved handler functions live in the commands package, not cli.py.
    status_cmd = next(c for c in app.registered_commands if c.callback.__name__ == "status")
    assert status_cmd.callback.__module__ == "shellforgeai.commands.status"
    doctor_cmd = next(c for c in app.registered_commands if c.callback.__name__ == "doctor")
    assert doctor_cmd.callback.__module__ == "shellforgeai.commands.doctor"
