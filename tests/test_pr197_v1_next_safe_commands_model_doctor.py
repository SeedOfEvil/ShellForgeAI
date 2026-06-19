"""V1 safe-next-command guidance must only suggest valid commands.

``shellforgeai model doctor --json`` is now a valid read-only readiness surface.
These regression checks keep V1 next-safe guidance resolvable and prove the
model doctor JSON path remains structured and non-mutating.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app

runner = CliRunner()

REPO = Path(__file__).resolve().parents[1]

JSON_MODEL_COMMAND = "shellforgeai model doctor --json"
VALID_MODEL_COMMAND = "shellforgeai model doctor"
PROFILES = ("quick", "standard", "full")


@pytest.fixture(scope="module")
def readiness_payloads(tmp_path_factory) -> dict[str, dict[str, Any]]:
    """Run ``v1 check --profile <p> --json`` once per profile and cache it."""
    data_dir = tmp_path_factory.mktemp("pr197-data")
    payloads: dict[str, dict[str, Any]] = {}
    for profile in PROFILES:
        result = runner.invoke(
            app,
            ["v1", "check", "--profile", profile, "--json"],
            env={"SHELLFORGEAI_DATA_DIR": str(data_dir / "data")},
        )
        assert result.exit_code in {0, 1}, result.stdout
        payloads[profile] = json.loads(result.stdout)
    return payloads


# --------------------------------------------------------------------------
# V1 readiness guidance: JSON model doctor command is valid
# --------------------------------------------------------------------------


@pytest.mark.parametrize("profile", PROFILES)
def test_profile_json_suggests_model_doctor_json(readiness_payloads, profile) -> None:
    commands = readiness_payloads[profile]["next_safe_commands"]
    assert JSON_MODEL_COMMAND in commands


@pytest.mark.parametrize("profile", PROFILES)
def test_profile_json_keeps_model_doctor_command_valid(readiness_payloads, profile) -> None:
    commands = readiness_payloads[profile]["next_safe_commands"]
    assert any(cmd.startswith(VALID_MODEL_COMMAND) for cmd in commands)


@pytest.mark.parametrize("profile", PROFILES)
def test_profile_next_safe_commands_are_registered_commands(readiness_payloads, profile) -> None:
    # Each suggested command must resolve to a real registered ShellForgeAI
    # command with options that all exist. Appending --help keeps this
    # read-only: Click rejects unknown options with exit code 2 before the
    # eager --help short-circuits with exit code 0, so a valid command path
    # plus valid options is exactly what exit code 0 proves.
    for cmd in readiness_payloads[profile]["next_safe_commands"]:
        words = cmd.split()
        assert words[0] == "shellforgeai", cmd
        result = runner.invoke(app, [*words[1:], "--help"])
        assert result.exit_code == 0, f"invalid next_safe_command suggested: {cmd!r}"


@pytest.mark.parametrize("profile", PROFILES)
def test_profile_readiness_semantics_unchanged(readiness_payloads, profile) -> None:
    payload = readiness_payloads[profile]
    assert payload["schema_version"] == 1
    assert payload["mode"] == "v1_readiness_check"
    assert payload["profile"] == profile
    assert payload["status"] in {"ok", "warn", "failed"}
    assert payload["ci_status"] in {"passed", "failed", "failed_on_warn"}
    if payload["status"] == "ok":
        assert payload["ci_status"] == "passed"


# --------------------------------------------------------------------------
# Safety fields remain non-mutating
# --------------------------------------------------------------------------


@pytest.mark.parametrize("profile", PROFILES)
def test_profile_safety_flags_remain_non_mutating(readiness_payloads, profile) -> None:
    safety = readiness_payloads[profile]["safety"]
    assert safety["read_only"] is True
    for flag in (
        "mutation_performed",
        "remediation_executed",
        "rollback_executed",
        "cleanup_executed",
        "apply_executed",
        "docker_compose_executed",
        "container_restarted",
        "natural_language_execution",
        "shell_true",
        "arbitrary_command_execution",
    ):
        assert safety[flag] is False, flag


# --------------------------------------------------------------------------
# model doctor contract: human and JSON output
# --------------------------------------------------------------------------


def test_model_doctor_help_shows_json_but_not_brief() -> None:
    result = runner.invoke(app, ["model", "doctor", "--help"])
    assert result.exit_code == 0
    assert "--json" in result.stdout
    assert "--brief" not in result.stdout


def test_model_doctor_json_is_structured_read_only(monkeypatch) -> None:
    class _FakeProvider:
        def doctor(self) -> dict[str, Any]:
            return {"provider": "openai-codex", "auth_readiness": "unknown"}

    monkeypatch.setattr(cli_mod, "build_provider", lambda *_: _FakeProvider())
    result = runner.invoke(app, ["model", "doctor", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["mode"] == "model_doctor"
    assert payload["auth_readiness"] == "unknown"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False


def test_model_doctor_still_exits_cleanly(monkeypatch) -> None:
    class _FakeProvider:
        def doctor(self) -> dict[str, Any]:
            return {"provider": "openai-codex", "auth_cache_present": True}

        def complete(self, req: Any) -> Any:
            raise AssertionError("model doctor must not call model inference")

    monkeypatch.setattr(cli_mod, "build_provider", lambda *a, **k: _FakeProvider())
    result = runner.invoke(app, ["model", "doctor"])
    assert result.exit_code == 0
    assert "provider=openai-codex" in result.stdout


def test_doctor_json_replacement_guidance_exits_cleanly(tmp_path) -> None:
    # Machine-readable general health stays "shellforgeai doctor --json".
    result = runner.invoke(
        app, ["doctor", "--json"], env={"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["safety"]["mutation_performed"] is False


# --------------------------------------------------------------------------
# Docs / source / fixtures encode the restored JSON surface
# --------------------------------------------------------------------------


def test_readiness_core_emits_model_doctor_json() -> None:
    source = (REPO / "src" / "shellforgeai" / "core" / "v1_readiness.py").read_text(
        encoding="utf-8"
    )
    assert JSON_MODEL_COMMAND in source


def test_docs_document_model_doctor_json() -> None:
    docs_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [REPO / "README.md", REPO / "OPS.md", *sorted((REPO / "docs").rglob("*.md"))]
    )
    assert JSON_MODEL_COMMAND in docs_text
