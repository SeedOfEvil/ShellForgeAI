"""PR79 — Safe command coverage harness tests.

The self-test command exercises core ShellForgeAI CLI command surfaces in
read-only mode and reports pass/fail/skipped without mutating infrastructure.

These tests confirm:
- the command exists and emits both human and strict JSON output,
- the JSON shape is stable and includes safety/mode invariants,
- skipped checks include a reason,
- no cleanup/apply/mission/docker mutation is performed,
- no proposals/missions/plans/archives are created by default,
- subprocess shell=True is never used,
- the mutation-refusal smoke depends only on local routing helpers.
"""

from __future__ import annotations

import inspect
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
    """Restore `cli.build_provider` to the real implementation.

    A few other tests in this suite (e.g. test_pr5_model_ux) replace
    ``cli.build_provider`` with a lambda directly (not via monkeypatch),
    which can leak across tests. The self-test harness exercises
    ``model doctor`` and needs the real provider builder so behavior is
    deterministic regardless of test order.
    """
    monkeypatch.setattr(cli_mod, "build_provider", _real_build_provider)
    yield


# --- command exists / human output ----------------------------------------


def test_self_test_commands_exists(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands"])
    assert out.exit_code == 0, out.stdout
    assert "ShellForgeAI self-test commands" in out.stdout


def test_self_test_commands_human_marks_read_only_true(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands"])
    assert out.exit_code == 0
    assert "read_only: true" in out.stdout
    assert "mutation_performed: false" in out.stdout


def test_self_test_commands_human_has_safety_block(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands"])
    assert out.exit_code == 0
    assert "no cleanup execute" in out.stdout
    assert "no mission execute" in out.stdout
    assert "no apply" in out.stdout
    assert "no docker compose restart" in out.stdout
    assert "no production mutation" in out.stdout


def test_self_test_commands_human_lists_checks(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands"])
    assert out.exit_code == 0
    # Must enumerate concrete check names so the operator can read them.
    assert "version" in out.stdout
    assert "ops status --json" in out.stdout
    assert "audit retention" in out.stdout
    assert "ask mutation refusal routing" in out.stdout


# --- JSON output ----------------------------------------------------------


def test_self_test_commands_json_strict(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--json"])
    assert out.exit_code == 0, out.stdout
    payload = json.loads(out.stdout)
    assert payload["schema_version"] == "1"


def test_self_test_commands_json_no_text_around(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--json"])
    assert out.exit_code == 0
    stripped = out.stdout.strip()
    assert stripped.startswith("{") and stripped.endswith("}")
    json.loads(stripped)


def test_self_test_commands_json_mode_invariants(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--json"])
    payload = json.loads(out.stdout)
    mode = payload["mode"]
    assert mode["read_only"] is True
    assert mode["mutation_performed"] is False
    assert mode["docker_compose_executed"] is False
    assert mode["cleanup_executed"] is False
    assert mode["mission_executed"] is False
    assert mode["apply_executed"] is False
    assert mode["natural_language_execution"] is False


def test_self_test_commands_json_summary_counts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--json"])
    payload = json.loads(out.stdout)
    summary = payload["summary"]
    assert summary["passed"] + summary["failed"] + summary["skipped"] == len(payload["checks"])
    assert summary["failed"] == 0


def test_self_test_commands_json_check_rows(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--json"])
    payload = json.loads(out.stdout)
    assert payload["checks"], "expected at least one check"
    for row in payload["checks"]:
        # PR80: per-row status remains in {pass, fail, skip}; the warn
        # severity is carried as a per-row boolean (``warn``).
        assert row["status"] in {"pass", "fail", "skip"}
        assert row["category"] in {"status", "json", "compose", "cleanup", "ask", "safety"}
        assert row["read_only"] is True
        assert row["mutation"] is False
        assert "warn" in row
        assert isinstance(row["warn"], bool)
        assert isinstance(row["command"], list) and row["command"][0] == "shellforgeai"


def test_self_test_commands_skipped_checks_include_reason(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--json"])
    payload = json.loads(out.stdout)
    skipped = [r for r in payload["checks"] if r["status"] == "skip"]
    # With an empty data dir and no docker, at minimum validate-runbook --latest skips.
    assert skipped, "expected at least one skipped check in an empty environment"
    for row in skipped:
        assert row["reason"], "skipped checks must include a non-empty reason"


def test_self_test_commands_status_is_ok_or_warn_when_failed_zero(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--json"])
    payload = json.loads(out.stdout)
    assert payload["summary"]["failed"] == 0
    assert payload["status"] in {"ok", "warn"}


# --- safety invariants ----------------------------------------------------


def test_self_test_commands_safety_block(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--json"])
    payload = json.loads(out.stdout)
    safety = payload["safety"]
    assert safety["no_cleanup_execute"] is True
    assert safety["no_cleanup_archive"] is True
    assert safety["no_cleanup_prepare"] is True
    assert safety["no_mission_execute"] is True
    assert safety["no_proposal_created"] is True
    assert safety["no_mission_created"] is True
    assert safety["no_apply"] is True
    assert safety["no_docker_compose_restart"] is True
    assert safety["no_production_mutation"] is True
    assert safety["no_natural_language_execution"] is True
    assert safety["no_shell_true"] is True


def test_self_test_commands_does_not_create_metadata(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands"])
    assert out.exit_code == 0
    # The harness must not create any of these mutation artifacts.
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


def test_self_test_commands_does_not_invoke_dangerous_argv() -> None:
    # Cross-check: the static list of commands the harness invokes contains no
    # mutation-side argv tokens. This is a guardrail against future churn.
    forbidden_tokens = {
        "execute",
        "execute-readiness",  # allowed in cleanup readiness check ONLY
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
    }
    # execute-readiness is allowed and read-only by design; whitelist it.
    allowed_with_execute_readiness = True
    for check in self_test_mod._read_only_checks():
        argv = check.argv
        for token in argv:
            if token == "execute-readiness" and allowed_with_execute_readiness:
                continue
            assert token not in forbidden_tokens, (
                f"harness argv must not contain {token!r}; offending check: {check.name}"
            )


def test_self_test_module_does_not_use_shell_true() -> None:
    src = inspect.getsource(self_test_mod)
    # Strip docstrings/comments by tokenizing code lines only.
    code_lines = [
        line for line in src.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    code_blob = "\n".join(code_lines)
    # Strip simple triple-quoted docstrings (best-effort).
    code_blob_no_docstrings = code_blob
    for marker in ('"""', "'''"):
        while marker in code_blob_no_docstrings:
            start = code_blob_no_docstrings.index(marker)
            end = code_blob_no_docstrings.find(marker, start + len(marker))
            if end == -1:
                break
            code_blob_no_docstrings = (
                code_blob_no_docstrings[:start] + code_blob_no_docstrings[end + len(marker) :]
            )
    assert "shell=True" not in code_blob_no_docstrings
    assert "shell = True" not in code_blob_no_docstrings
    # The harness should not shell out at all.
    assert "subprocess" not in code_blob_no_docstrings
    assert "os.system" not in code_blob_no_docstrings
    assert "popen" not in code_blob_no_docstrings.lower()


# --- JSON parse semantics -------------------------------------------------


def test_self_test_marks_invalid_json_command_as_fail(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))

    # Patch typer.testing.CliRunner.invoke to emit garbage stdout for one
    # specific argv so we exercise the JSON-failure branch.
    real_run = self_test_mod._runner_invoke
    target_argv = ("ops", "status", "--json")

    def stub_invoke(runner_obj, app_obj, argv):
        if tuple(argv) == target_argv:
            return 0, "this is not JSON {", "", None
        return real_run(runner_obj, app_obj, argv)

    monkeypatch.setattr(self_test_mod, "_runner_invoke", stub_invoke)
    payload = self_test_mod.run_self_test_commands()
    ops_status_json = [c for c in payload["checks"] if c["name"] == "ops status --json"]
    assert ops_status_json, "ops status --json check must exist"
    row = ops_status_json[0]
    assert row["status"] == "fail"
    assert row["reason"] and "json" in row["reason"].lower()


def test_self_test_marks_valid_json_command_as_pass(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    payload = self_test_mod.run_self_test_commands()
    ops_status_json = [c for c in payload["checks"] if c["name"] == "ops status --json"]
    assert ops_status_json and ops_status_json[0]["status"] == "pass"


# --- ask refusal smoke ----------------------------------------------------


def test_ask_mutation_refusal_routing_passes_by_default(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--json"])
    payload = json.loads(out.stdout)
    rows = [c for c in payload["checks"] if c["name"] == "ask mutation refusal routing"]
    assert rows and rows[0]["status"] == "pass"
    assert rows[0]["category"] == "safety"


def test_self_test_mutation_phrases_are_actually_flagged() -> None:
    from shellforgeai.core.ask_routing import (
        is_compose_mutation_request,
        is_mutation_request,
    )

    for phrase in self_test_mod.ASK_MUTATION_PHRASES:
        assert is_mutation_request(phrase) or is_compose_mutation_request(phrase), (
            f"PR79 self-test mutation phrase {phrase!r} is not flagged by router; "
            "the harness only smoke-tests refusal for phrases the router actually "
            "catches (no NL broadening is performed)."
        )


def test_self_test_ask_local_prompts_are_safe(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    # Run ask directly on each local prompt and confirm the output never
    # includes a Codex error (i.e. it was handled locally, not via model).
    for prompt, _expected in self_test_mod.ASK_LOCAL_PROMPTS:
        out = runner.invoke(app, ["ask", prompt])
        joined = out.stdout.lower()
        assert "model unavailable" not in joined, (
            f"ask {prompt!r} fell through to the model; expected local handler"
        )


# --- regression: harness counts ------------------------------------------


def test_self_test_passes_with_clean_environment(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--json"])
    assert out.exit_code == 0
    payload = json.loads(out.stdout)
    assert payload["summary"]["failed"] == 0


def test_optional_disposable_mutation_lane_not_implemented(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["self-test", "commands", "--json"])
    payload = json.loads(out.stdout)
    lane = payload["optional_disposable_mutation_lane"]
    assert lane["implemented"] is False
    assert lane["executed"] is False
    assert lane["status"] == "manual_only"
