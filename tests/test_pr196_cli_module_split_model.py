"""PR196 — CLI command-module split: the ``model`` command group.

Behavior-preserving extraction proof for ``model doctor`` (moved from
``shellforgeai.commands.doctor``, where it had lived since PR182) and
``model test`` (moved from ``cli.py``) into ``shellforgeai.commands.model``.

Scope is intentionally narrow:

* the new command module exists, imports cleanly, and has no import side
  effects,
* ``cli.py`` keeps Typer wiring only and no longer owns the model command
  bodies,
* the ``model`` command surface (help, options, output shape, readiness/auth
  fields, suggested-login recovery hint) is unchanged,
* ``model doctor`` stays read-only: no model inference, no Codex task
  execution, no subprocess/shell execution from the handler, no mutation, and
* the PR184 golden command-surface guardrail still covers the group.

Note on JSON/brief: ``model doctor`` intentionally has no ``--json`` or
``--brief`` flag in the current surface (see the PR184 fixture notes); this
extraction preserves that surface exactly rather than inventing new flags.
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.llm.schemas import ModelResponse

runner = CliRunner()

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "shellforgeai"
MODULE_PATH = SRC / "commands" / "model.py"
CLI_PATH = SRC / "cli.py"
DOCTOR_PATH = SRC / "commands" / "doctor.py"

_DOCTOR_INFO: dict[str, Any] = {
    "provider": "openai-codex",
    "model": "gpt-5.5",
    "fallback_model": "gpt-5.4",
    "codex_binary": "/usr/bin/codex",
    "codex_found": True,
    "codex_version": "codex 1.0.0",
    "auth_cache_present": True,
    "auth_readiness": "unknown",
    "auth_reason": "status_unknown",
    "auth_next_step": "codex login --device-auth",
    "sandbox": "read-only",
    "approval": "never",
    "timeout_seconds": "180",
    "fallback_enabled": True,
}


class _FakeProvider:
    """Provider stub: readiness metadata only; any inference call fails loudly."""

    def __init__(self, info: dict[str, Any] | None = None) -> None:
        self._info = dict(_DOCTOR_INFO if info is None else info)

    def doctor(self) -> dict[str, Any]:
        return dict(self._info)

    def complete(self, req: Any) -> Any:
        raise AssertionError("model doctor must not call model inference")


def _use_fake_provider(monkeypatch, info: dict[str, Any] | None = None) -> None:
    monkeypatch.setattr(cli_mod, "build_provider", lambda *a, **k: _FakeProvider(info))


def _callback_name(cmd: Any) -> str:
    assert cmd.callback is not None
    return cmd.callback.__name__


# --------------------------------------------------------------------------
# Module split / registration
# --------------------------------------------------------------------------


def test_commands_model_module_exists() -> None:
    assert MODULE_PATH.exists()


def test_cli_wires_model_registration_and_no_longer_owns_bodies() -> None:
    module_source = MODULE_PATH.read_text(encoding="utf-8")
    cli_source = CLI_PATH.read_text(encoding="utf-8")
    doctor_source = DOCTOR_PATH.read_text(encoding="utf-8")

    assert "def register(model_app: typer.Typer)" in module_source
    assert '@model_app.command("doctor")' in module_source
    assert '@model_app.command("test")' in module_source

    assert "from shellforgeai.commands import model as model_commands" in cli_source
    assert "model_commands.register(model_app)" in cli_source
    assert "@model_app.command(" not in cli_source
    assert "def model_test(" not in cli_source
    assert "def model_doctor(" not in cli_source

    # model doctor moved out of the PR182 doctor module unchanged.
    assert "@model_app.command(" not in doctor_source
    assert "def model_doctor(" not in doctor_source


def test_model_handlers_are_owned_by_commands_model_module() -> None:
    by_name = {_callback_name(c): c for c in cli_mod.model_app.registered_commands}
    assert set(by_name) == {"model_doctor", "model_test"}
    for cmd in by_name.values():
        assert cmd.callback is not None
        assert cmd.callback.__module__ == "shellforgeai.commands.model"


def test_importing_model_module_has_no_side_effects(monkeypatch) -> None:
    def _boom_run(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("importing the model command module must not run subprocesses")

    monkeypatch.setattr(subprocess, "run", _boom_run)
    sys.modules.pop("shellforgeai.commands.model", None)
    mod = importlib.import_module("shellforgeai.commands.model")
    assert not hasattr(mod, "app")
    assert callable(mod.register)


def test_model_help_lists_doctor_and_test() -> None:
    result = runner.invoke(app, ["model", "--help"])
    assert result.exit_code == 0
    assert "doctor" in result.stdout
    assert "test" in result.stdout


def test_model_doctor_help_works_and_surface_is_unchanged() -> None:
    result = runner.invoke(app, ["model", "doctor", "--help"])
    assert result.exit_code == 0
    assert "--json" in result.stdout
    assert "--brief" not in result.stdout


def test_model_test_help_preserves_options() -> None:
    result = runner.invoke(app, ["model", "test", "--help"])
    assert result.exit_code == 0
    for opt in ("--raw", "--timeout", "--model"):
        assert opt in result.stdout


# --------------------------------------------------------------------------
# model doctor behavior
# --------------------------------------------------------------------------


def test_model_doctor_reports_provider_model_fallback_fields(monkeypatch) -> None:
    _use_fake_provider(monkeypatch)
    result = runner.invoke(app, ["model", "doctor"])
    assert result.exit_code == 0
    out = result.stdout
    assert "provider=openai-codex" in out
    assert "model=gpt-5.5" in out
    assert "fallback_model=gpt-5.4" in out
    assert "fallback_enabled=True" in out


def test_model_doctor_reports_codex_binary_auth_sandbox_approval_fields(monkeypatch) -> None:
    _use_fake_provider(monkeypatch)
    result = runner.invoke(app, ["model", "doctor"])
    assert result.exit_code == 0
    out = result.stdout
    assert "codex_binary=/usr/bin/codex" in out
    assert "codex_found=True" in out
    assert "codex_version=codex 1.0.0" in out
    assert "auth_cache_present=True" in out
    assert "auth_readiness=unknown" in out
    assert "auth_reason=status_unknown" in out
    assert "sandbox=read-only" in out
    assert "approval=never" in out


def test_model_doctor_auth_cache_present_keeps_status_unknown_without_login_hint(
    monkeypatch,
) -> None:
    _use_fake_provider(monkeypatch)
    result = runner.invoke(app, ["model", "doctor"])
    assert result.exit_code == 0
    # Auth cache present means readiness stays status_unknown (no live auth
    # probe) and no login suggestion is printed.
    assert "auth_reason=status_unknown" in result.stdout
    assert "Suggested login" not in result.stdout


def test_model_doctor_missing_auth_cache_suggests_login(monkeypatch) -> None:
    info = dict(_DOCTOR_INFO)
    info.update(
        {"auth_cache_present": False, "auth_readiness": "failed", "auth_reason": "login_required"}
    )
    _use_fake_provider(monkeypatch, info)
    result = runner.invoke(app, ["model", "doctor"])
    assert result.exit_code == 0
    assert "auth_readiness=failed" in result.stdout
    assert "auth_reason=login_required" in result.stdout
    assert "Suggested login: codex login (or codex login --device-auth)" in result.stdout


def test_model_doctor_real_provider_path_without_codex_binary(monkeypatch, tmp_path: Path) -> None:
    # End-to-end through the real provider doctor with the codex binary absent
    # and an isolated HOME: detection must stay shutil.which-based (no codex
    # subprocess runs when the binary is missing) and readiness must degrade
    # to the controlled login_required hint — no traceback, exit 0.
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("shellforgeai.llm.codex.shutil.which", lambda _b: None)

    def _boom_run(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("model doctor must not spawn codex when the binary is missing")

    monkeypatch.setattr("shellforgeai.llm.codex.subprocess.run", _boom_run)
    result = runner.invoke(app, ["model", "doctor"])
    assert result.exit_code == 0
    assert "Traceback" not in result.stdout
    assert "codex_found=False" in result.stdout
    assert "auth_cache_present=False" in result.stdout
    assert "auth_readiness=failed" in result.stdout
    assert "auth_reason=login_required" in result.stdout
    assert "Suggested login: codex login" in result.stdout


def test_model_test_behavior_preserved(monkeypatch) -> None:
    seen: dict[str, Any] = {}

    class _TestProvider(_FakeProvider):
        def complete(self, req: Any) -> ModelResponse:
            seen["prompt"] = req.prompt
            return ModelResponse(
                provider="openai-codex",
                model="gpt-5.5",
                text="ShellForgeAI Codex provider online.",
                ok=True,
                usage={
                    "input_tokens": 1,
                    "cached_input_tokens": 0,
                    "output_tokens": 1,
                    "reasoning_output_tokens": 0,
                },
            )

    monkeypatch.setattr(cli_mod, "build_provider", lambda *a, **k: _TestProvider())
    result = runner.invoke(app, ["model", "test", "Reply exactly: ping"])
    assert result.exit_code == 0
    assert seen["prompt"] == "Reply exactly: ping"
    assert "ShellForgeAI Codex provider online." in result.stdout
    assert "Provider: openai-codex" in result.stdout
    assert "Model: gpt-5.5" in result.stdout
    assert "OK: true" in result.stdout
    assert "Usage: input=1" in result.stdout


# --------------------------------------------------------------------------
# Safety: read-only, no inference, no execution, no mutation
# --------------------------------------------------------------------------


def test_model_doctor_does_not_call_model_inference(monkeypatch) -> None:
    # _FakeProvider.complete raises AssertionError on any inference attempt.
    _use_fake_provider(monkeypatch)
    result = runner.invoke(app, ["model", "doctor"])
    assert result.exit_code == 0


def test_model_doctor_handler_does_not_execute_subprocess(monkeypatch) -> None:
    _use_fake_provider(monkeypatch)

    def _boom(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"model doctor handler must not execute subprocesses: {cmd!r}")

    monkeypatch.setattr(cli_mod.subprocess, "run", _boom)
    monkeypatch.setattr(subprocess, "run", _boom)
    result = runner.invoke(app, ["model", "doctor"])
    assert result.exit_code == 0


def test_model_doctor_does_not_mutate_data_dir(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _use_fake_provider(monkeypatch)
    runner.invoke(app, ["model", "doctor"])
    before = {p.name for p in tmp_path.iterdir()}
    runner.invoke(app, ["model", "doctor"])
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
        "recovery_receipts",
        "prune_receipts",
    }
    assert (after - before).isdisjoint(forbidden)
    assert before.isdisjoint(forbidden)


def test_model_module_contains_no_execution_or_mutation_tokens() -> None:
    # Static guard: the extracted model command module must not introduce
    # cleanup/remediation/rollback/recovery/Docker/Compose/shell execution,
    # Codex task execution, or natural-language execution paths.
    source = MODULE_PATH.read_text(encoding="utf-8")
    low = source.lower()
    forbidden_tokens = (
        "shell=true",
        "subprocess.run",
        "subprocess.popen",
        "os.system",
        "docker restart",
        "docker compose",
        "compose restart",
        "production restart",
        "cleanup_execute",
        "execute_remediation",
        "execute_receipt_recovery(",
        "preview_receipt_rollback(",
        "run_exact_docker_restart(",
        "route_input(",
        "codex exec",
    )
    for token in forbidden_tokens:
        assert token not in low, f"model.py contains forbidden token: {token}"


def test_no_new_model_commands_added() -> None:
    names = {
        c.name or _callback_name(c).replace("model_", "")
        for c in cli_mod.model_app.registered_commands
    }
    assert names == {"doctor", "test"}


# --------------------------------------------------------------------------
# Regression anchors (full suites run separately)
# --------------------------------------------------------------------------


def test_pr184_guardrail_still_covers_model_doctor_help() -> None:
    fixture_path = REPO / "tests" / "golden" / "cli_command_surface_pr184.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    by_name = {entry["name"]: entry for entry in fixture["commands"]}
    assert "model_doctor_help" in by_name
    assert by_name["model_doctor_help"]["argv"] == ["model", "doctor", "--help"]


def test_prior_module_split_tests_present() -> None:
    base = Path(__file__).resolve().parent
    for name in (
        "test_pr182_cli_module_scaffold_status_doctor.py",
        "test_pr184_cli_command_surface_golden.py",
        "test_pr195_cli_module_split_v1.py",
        "test_pr106_ask_mutation_refusal_routing.py",
    ):
        assert (base / name).exists(), name


def test_root_doctor_still_registered_from_doctor_module() -> None:
    doctor_cmd = next(c for c in app.registered_commands if _callback_name(c) == "doctor")
    assert doctor_cmd.callback is not None
    assert doctor_cmd.callback.__module__ == "shellforgeai.commands.doctor"
