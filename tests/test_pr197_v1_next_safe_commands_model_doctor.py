"""PR197 — V1 safe-next-command guidance must only suggest valid commands.

Pre-existing drift (found during PR196 Docker01 QA, present on main before
PR196): the V1 readiness JSON ``next_safe_commands`` suggested
``shellforgeai model doctor --json``, which is invalid because ``model
doctor`` is human-output only and intentionally has no ``--json`` (or
``--brief``) flag in the current surface.

PR197 corrects the guidance string only:

* V1 quick/standard/full readiness JSON never suggests
  ``shellforgeai model doctor --json``; it suggests
  ``shellforgeai model doctor`` instead,
* every ``next_safe_commands`` entry is a registered ShellForgeAI command
  whose options all exist (validated via ``--help``),
* the ``model doctor`` contract is unchanged: human output only, ``--json``
  still rejected cleanly with exit code 2, no new flags added,
* machine-readable general health remains ``shellforgeai doctor --json``,
* docs and tests no longer encode the invalid command (except where they
  explicitly document that it is invalid), and
* V1 readiness semantics (status/ci_status/safety flags) are unchanged.

No execution/mutation behavior is touched: no cleanup, remediation,
rollback, recovery, Docker/Compose mutation, restart, ``shell=True``,
arbitrary command execution, natural-language execution, or model call.
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

INVALID_COMMAND = "shellforgeai model doctor --json"
VALID_MODEL_COMMAND = "shellforgeai model doctor"
PROFILES = ("quick", "standard", "full")

# Markers that make a doc/test mention of the invalid command acceptable:
# the surrounding line must be documenting that the command is invalid (or
# recording the drift fix), not suggesting it.
_INVALIDITY_MARKERS = ("invalid", "no longer", "not ", "drift", "rejected", "absent")


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
# V1 readiness guidance: invalid command absent, valid guidance present
# --------------------------------------------------------------------------


@pytest.mark.parametrize("profile", PROFILES)
def test_profile_json_does_not_suggest_model_doctor_json(readiness_payloads, profile) -> None:
    commands = readiness_payloads[profile]["next_safe_commands"]
    assert INVALID_COMMAND not in commands


@pytest.mark.parametrize("profile", PROFILES)
def test_profile_json_suggests_valid_model_doctor(readiness_payloads, profile) -> None:
    commands = readiness_payloads[profile]["next_safe_commands"]
    assert VALID_MODEL_COMMAND in commands
    # No entry may smuggle a --json flag onto model doctor.
    for cmd in commands:
        if cmd.startswith(VALID_MODEL_COMMAND):
            assert cmd == VALID_MODEL_COMMAND


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
# model doctor contract: human output only, --json still rejected
# --------------------------------------------------------------------------


def test_model_doctor_help_still_has_no_json_or_brief() -> None:
    result = runner.invoke(app, ["model", "doctor", "--help"])
    assert result.exit_code == 0
    assert "--json" not in result.stdout
    assert "--brief" not in result.stdout


def test_model_doctor_json_still_rejected_cleanly(monkeypatch) -> None:
    # The fix must not hide the drift by adding a --json flag: the invalid
    # invocation keeps failing with a clean Typer usage error (exit code 2)
    # and never reaches the handler (no provider is built).
    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("rejected model doctor --json must not build a provider")

    monkeypatch.setattr(cli_mod, "build_provider", _boom)
    result = runner.invoke(app, ["model", "doctor", "--json"])
    assert result.exit_code == 2
    output = result.stdout + (result.stderr or "")
    assert "no such option" in output.lower()
    assert "Traceback" not in output


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
# Docs / source / fixtures no longer encode the invalid command
# --------------------------------------------------------------------------


def _offending_lines(text: str) -> list[str]:
    lines = []
    for line in text.splitlines():
        if INVALID_COMMAND in line:
            low = line.lower()
            if not any(marker in low for marker in _INVALIDITY_MARKERS):
                lines.append(line.strip())
    return lines


def test_readiness_core_does_not_emit_invalid_command() -> None:
    source = (REPO / "src" / "shellforgeai" / "core" / "v1_readiness.py").read_text(
        encoding="utf-8"
    )
    assert INVALID_COMMAND not in source


def test_docs_do_not_suggest_invalid_command() -> None:
    doc_paths = [REPO / "README.md", REPO / "OPS.md", *sorted((REPO / "docs").rglob("*.md"))]
    offending: dict[str, list[str]] = {}
    for path in doc_paths:
        lines = _offending_lines(path.read_text(encoding="utf-8"))
        if lines:
            offending[str(path.relative_to(REPO))] = lines
    assert not offending, f"docs suggest invalid command: {offending}"


def test_tests_and_fixtures_do_not_require_invalid_command() -> None:
    this_file = Path(__file__).resolve()
    offending: dict[str, list[str]] = {}
    for path in sorted((REPO / "tests").rglob("*")):
        if path.resolve() == this_file or path.suffix not in {".py", ".json", ".md", ".txt"}:
            continue
        lines = _offending_lines(path.read_text(encoding="utf-8"))
        if lines:
            offending[str(path.relative_to(REPO))] = lines
    assert not offending, f"tests/fixtures require invalid command: {offending}"
