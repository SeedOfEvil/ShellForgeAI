"""PR80 — Self-test command coverage profiles and QA handoff polish.

PR80 adds validation profiles (``quick`` / ``standard`` / ``full``), an
explicit warn-vs-skip distinction, a ``--fail-on-warn`` flag for CI
strictness, an ``--include-skipped`` rendering hint, and an expanded
JSON schema (``profile``, ``summary.warned``, expanded ``safety`` block,
``warnings`` / ``skipped`` arrays, ``next_safe_commands``).

These tests confirm the new behaviors while leaving the PR79 invariants
intact (covered by ``test_pr79_self_test_commands.py``):
- harness remains read-only and never executes mutation,
- no profile uses ``shell=True`` or shells out,
- JSON output is strict (no preamble / no trailing text),
- skipped vs warn semantics are deterministic and documented.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.core import self_test as self_test_mod
from shellforgeai.llm.manager import build_provider as _real_build_provider

runner = CliRunner()


@pytest.fixture(autouse=True)
def _restore_build_provider(monkeypatch):
    """Restore ``cli.build_provider`` so model-doctor stays deterministic.

    Mirrors the PR79 autouse fixture: a few sibling tests replace
    ``cli.build_provider`` with a lambda directly (not via monkeypatch)
    which can leak across tests when the suite runs out of order.
    """
    monkeypatch.setattr(cli_mod, "build_provider", _real_build_provider)
    yield


# --- profile selection ----------------------------------------------------


def test_default_profile_is_standard(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--json"])
    assert out.exit_code == 0
    payload = json.loads(out.stdout)
    assert payload["profile"] == "standard"
    assert payload["default_profile"] == "standard"
    assert payload["available_profiles"] == ["quick", "standard", "full"]


def test_profile_quick_runs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--profile", "quick", "--json"])
    assert out.exit_code == 0, out.stdout
    payload = json.loads(out.stdout)
    assert payload["profile"] == "quick"
    names = {row["name"] for row in payload["checks"]}
    # quick lane essentials
    for required in {"version", "doctor", "model doctor", "ops status", "tools list"}:
        assert required in names
    # quick lane must exclude artifact-dependent checks
    assert "validate-runbook --latest" not in names
    assert "audit cleanup review" not in names


def test_profile_standard_runs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--profile", "standard", "--json"])
    assert out.exit_code == 0, out.stdout
    payload = json.loads(out.stdout)
    assert payload["profile"] == "standard"
    names = {row["name"] for row in payload["checks"]}
    assert "validate-runbook --latest" in names
    assert "audit cleanup review" in names
    assert "ask mutation refusal routing" in names


def test_profile_full_runs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--profile", "full", "--json"])
    assert out.exit_code == 0, out.stdout
    payload = json.loads(out.stdout)
    assert payload["profile"] == "full"
    names = {row["name"] for row in payload["checks"]}
    # full lane is a superset of standard
    for required in {
        "version",
        "doctor",
        "ops status",
        "audit cleanup review",
        "validate-runbook --latest",
        "audit list",
        "audit timeline --latest --json",
        "compose list --json",
    }:
        assert required in names, f"full lane missing: {required}"


def test_profile_unknown_returns_clean_error(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--profile", "bogus"])
    assert out.exit_code == 2
    assert "unknown profile" in out.stdout.lower() or "valid profiles" in out.stdout.lower()


def test_profile_unknown_json_remains_strict(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--profile", "bogus", "--json"])
    assert out.exit_code == 2
    stripped = out.stdout.strip()
    assert stripped.startswith("{") and stripped.endswith("}")
    payload = json.loads(stripped)
    assert payload["status"] == "failed"
    assert "available_profiles" in payload


# --- quick profile avoids common warnings ---------------------------------


def test_quick_profile_avoids_artifact_warn(tmp_path: Path, monkeypatch) -> None:
    """``quick`` should be reliable on a fresh container: no artifact warns."""
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--profile", "quick", "--json"])
    payload = json.loads(out.stdout)
    # validate-runbook (the common artifact warn) is not in quick
    names = {row["name"] for row in payload["checks"]}
    assert "validate-runbook --latest" not in names
    # No compose env-checks either — they often warn or skip in a fresh env
    assert not any(name.startswith("compose ") for name in names)


def test_standard_and_full_can_report_warn(tmp_path: Path, monkeypatch) -> None:
    """In a fresh env, standard/full report ``warn`` (not failed)."""
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    for profile in ("standard", "full"):
        out = runner.invoke(app, ["self-test", "commands", "--profile", profile, "--json"])
        assert out.exit_code == 0, f"{profile}: {out.stdout}"
        payload = json.loads(out.stdout)
        assert payload["summary"]["failed"] == 0
        assert payload["status"] in {"ok", "warn"}


# --- read-only / mutation invariants per profile --------------------------


@pytest.mark.parametrize("profile", ["quick", "standard", "full"])
def test_every_profile_is_read_only(tmp_path: Path, monkeypatch, profile: str) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--profile", profile, "--json"])
    payload = json.loads(out.stdout)
    assert payload["mode"]["read_only"] is True
    assert payload["mode"]["mutation_performed"] is False
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False
    for row in payload["checks"]:
        assert row["read_only"] is True
        assert row["mutation"] is False


# --- JSON schema fields ---------------------------------------------------


@pytest.mark.parametrize("profile", ["quick", "standard", "full"])
def test_json_strict_for_each_profile(tmp_path: Path, monkeypatch, profile: str) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--profile", profile, "--json"])
    assert out.exit_code == 0, out.stdout
    stripped = out.stdout.strip()
    assert stripped.startswith("{") and stripped.endswith("}")
    payload = json.loads(stripped)
    assert payload["schema_version"] == "1"
    assert payload["profile"] == profile
    assert "summary" in payload
    assert "checks" in payload
    assert "safety" in payload
    assert "warnings" in payload and isinstance(payload["warnings"], list)
    assert "skipped" in payload and isinstance(payload["skipped"], list)
    assert "next_safe_commands" in payload and isinstance(payload["next_safe_commands"], list)


def test_json_summary_has_warned_field(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--json"])
    payload = json.loads(out.stdout)
    summary = payload["summary"]
    for key in ("passed", "failed", "warned", "skipped"):
        assert key in summary, f"summary missing {key}"
    # PR79 invariant preserved.
    assert summary["passed"] + summary["failed"] + summary["skipped"] == len(payload["checks"])


def test_json_safety_block_has_canonical_pr80_keys(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--json"])
    payload = json.loads(out.stdout)
    safety = payload["safety"]
    for key in (
        "read_only",
        "mutation_performed",
        "cleanup_execute_run",
        "mission_execute_run",
        "apply_execute_run",
        "docker_compose_executed",
        "docker_compose_mutation",
        "natural_language_execution",
        "arbitrary_command_execution",
    ):
        assert key in safety, f"safety missing {key}"
    assert safety["read_only"] is True
    assert safety["mutation_performed"] is False
    assert safety["cleanup_execute_run"] is False
    assert safety["mission_execute_run"] is False
    assert safety["apply_execute_run"] is False
    assert safety["docker_compose_executed"] is False
    assert safety["docker_compose_mutation"] is False
    assert safety["natural_language_execution"] is False
    assert safety["arbitrary_command_execution"] is False


# --- safety: no profile contains mutating argv tokens ---------------------


@pytest.mark.parametrize("profile", ["quick", "standard", "full"])
def test_no_profile_includes_mutating_argv(profile: str) -> None:
    forbidden_tokens = {
        "execute",  # cleanup execute, mission execute, restart-execute
        "prepare",
        "archive",
        "apply",
        "approve",
        "reject",
        "propose-restart",
        "restart-execute",
        "compose-restart",
        "--execute",
        "--confirm",
        "restart",
        "up",
        "down",
        "recreate",
    }
    # ``execute-readiness`` is a read-only readiness check, allowlisted.
    for check in self_test_mod._read_only_checks():
        if profile not in check.profiles:
            continue
        for token in check.argv:
            if token == "execute-readiness":
                continue
            assert token not in forbidden_tokens, (
                f"profile {profile!r} check {check.name!r} contains forbidden token {token!r}"
            )


def test_no_profile_creates_mutation_artifacts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    for profile in ("quick", "standard", "full"):
        out = runner.invoke(app, ["self-test", "commands", "--profile", profile])
        assert out.exit_code == 0, out.stdout
    for forbidden in (
        "cleanup_plans",
        "cleanup_archives",
        "cleanup_receipts",
        "proposals",
        "approvals",
        "missions",
        "apply_bundles",
        "exports",
        "actions",
    ):
        assert not (tmp_path / forbidden).exists(), f"{forbidden} must not be created"


def test_self_test_module_has_no_shell_invocation() -> None:
    import inspect

    src = inspect.getsource(self_test_mod)
    # Strip docstrings/comments (best-effort).
    code_lines = [
        line for line in src.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    code_blob = "\n".join(code_lines)
    for marker in ('"""', "'''"):
        while marker in code_blob:
            start = code_blob.index(marker)
            end = code_blob.find(marker, start + len(marker))
            if end == -1:
                break
            code_blob = code_blob[:start] + code_blob[end + len(marker) :]
    assert "shell=True" not in code_blob
    assert "shell = True" not in code_blob
    assert "subprocess" not in code_blob
    assert "os.system" not in code_blob
    assert "popen" not in code_blob.lower()


# --- warn / skip / fail semantics -----------------------------------------


def test_missing_runbook_yields_warn_not_failed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--profile", "standard", "--json"])
    payload = json.loads(out.stdout)
    runbook_rows = [c for c in payload["checks"] if c["name"] == "validate-runbook --latest"]
    assert runbook_rows, "validate-runbook --latest must be present in standard"
    row = runbook_rows[0]
    assert row["status"] == "skip"
    assert row["warn"] is True
    assert row["reason"]
    # Aggregated warn count > 0; not a failure.
    assert payload["summary"]["warned"] >= 1
    assert payload["summary"]["failed"] == 0
    assert payload["status"] == "warn"


def test_warnings_array_lists_warn_rows(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--json"])
    payload = json.loads(out.stdout)
    assert payload["warnings"], "warnings array expected when artifact missing"
    for w in payload["warnings"]:
        assert "name" in w and "reason" in w
        assert w["reason"]


def test_fail_on_warn_returns_nonzero(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--fail-on-warn"])
    # In a fresh container, the standard profile warns on validate-runbook.
    # --fail-on-warn must surface a non-zero exit code.
    assert out.exit_code == 1
    assert "fail-on-warn" in out.stdout.lower()


def test_fail_on_warn_still_emits_strict_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--fail-on-warn", "--json"])
    assert out.exit_code == 1
    stripped = out.stdout.strip()
    assert stripped.startswith("{") and stripped.endswith("}")
    payload = json.loads(stripped)
    assert payload["status"] == "warn"
    assert payload["ci_status"] == "failed_on_warn"
    # Underlying status reporting must not lie: mutation_performed remains false.
    assert payload["mode"]["mutation_performed"] is False
    assert payload["safety"]["mutation_performed"] is False


def test_fail_on_warn_with_quick_profile_is_clean(tmp_path: Path, monkeypatch) -> None:
    """quick profile should not warn on an empty env → --fail-on-warn passes."""
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(
        app, ["self-test", "commands", "--profile", "quick", "--fail-on-warn", "--json"]
    )
    assert out.exit_code == 0, out.stdout
    payload = json.loads(out.stdout)
    assert payload["status"] == "ok"
    assert payload["summary"]["warned"] == 0


# --- human output: profile / warnings / next steps ------------------------


def test_human_output_shows_profile_block(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands"])
    assert out.exit_code == 0
    text = out.stdout
    assert "Profile:" in text
    assert "name: standard" in text
    assert "read-only: true" in text
    assert "mutation: false" in text


def test_human_output_shows_warned_count(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands"])
    assert "warned:" in out.stdout
    assert "Safety invariants:" in out.stdout
    assert "cleanup execute: not run" in out.stdout


def test_human_output_warn_status_explains_artifact(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands"])
    # standard profile warns on validate-runbook in a fresh env.
    assert "This is not a command failure" in out.stdout
    assert "Warnings:" in out.stdout


def test_human_output_lists_next_safe_commands(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands"])
    assert "Next safe commands:" in out.stdout
    assert "shellforgeai doctor" in out.stdout
    assert "shellforgeai ops status" in out.stdout


def test_include_skipped_renders_extra_rows(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--include-skipped"])
    assert out.exit_code == 0


# --- regression: ask-routing smoke remains deterministic ------------------


def test_ask_mutation_refusal_routing_present_in_each_profile(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    for profile in ("quick", "standard", "full"):
        out = runner.invoke(app, ["self-test", "commands", "--profile", profile, "--json"])
        payload = json.loads(out.stdout)
        rows = [c for c in payload["checks"] if c["name"] == "ask mutation refusal routing"]
        assert rows, f"ask refusal smoke must run in profile={profile}"
        assert rows[0]["status"] == "pass"
        assert rows[0]["category"] == "safety"
