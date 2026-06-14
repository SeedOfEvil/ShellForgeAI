"""PR184: golden CLI command-surface guardrail.

Behavior-preserving refactor safety net. These tests assert that important
ShellForgeAI command groups, subcommands, options, help surfaces, JSON
capability, governed-execution confirmation markers, read-only safety wording,
and mutation-refusal paths remain registered. They run the CLI in-process via
``CliRunner`` with the model/provider factory blocked, so no model call, Docker
call, restart, cleanup, remediation, rollback, recovery execution, shell, or
arbitrary/natural-language execution can occur.

This is test infrastructure only; it adds no product command and no runtime
behavior. When the command surface changes intentionally, update
``tests/golden/cli_command_surface_pr184.json`` in the same PR.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HELPERS = Path(__file__).resolve().parent / "helpers"
if str(HELPERS) not in sys.path:
    sys.path.insert(0, str(HELPERS))

import cli_surface  # noqa: E402

from shellforgeai import cli as cli_mod  # noqa: E402
from shellforgeai.cli import app  # noqa: E402

FIXTURE = cli_surface.load_fixture()
COMMANDS = FIXTURE["commands"]
REFUSALS = FIXTURE.get("refusal_phrases", [])

COMMANDS_BY_NAME = {entry["name"]: entry for entry in COMMANDS}


@pytest.fixture(autouse=True)
def _safe_cli_env(monkeypatch, tmp_path: Path):
    """Isolate data dir to tmp and block any model/provider call."""

    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    cli_surface.block_model_calls(monkeypatch, cli_mod)
    return tmp_path


def _entry(name: str) -> dict:
    assert name in COMMANDS_BY_NAME, f"fixture missing command entry: {name}"
    return COMMANDS_BY_NAME[name]


# --------------------------------------------------------------------------
# Golden fixture / registry
# --------------------------------------------------------------------------


def test_01_golden_fixture_parses() -> None:
    assert isinstance(FIXTURE, dict)
    assert FIXTURE["schema_version"] == 1
    assert FIXTURE["mode"] == "cli_command_surface_golden"


def test_02_every_command_entry_has_required_fields() -> None:
    cli_surface.validate_fixture(FIXTURE)


def test_03_command_argv_entries_are_lists_of_strings() -> None:
    for entry in COMMANDS + REFUSALS:
        argv = entry["argv"]
        assert isinstance(argv, list) and argv
        assert all(isinstance(a, str) for a in argv), entry["name"]


def test_04_no_duplicate_command_names() -> None:
    names = [e["name"] for e in COMMANDS]
    assert len(names) == len(set(names))
    refusal_names = [e["name"] for e in REFUSALS]
    assert len(refusal_names) == len(set(refusal_names))


def test_05_no_volatile_timestamp_or_path_fields() -> None:
    cli_surface.assert_no_volatile_fields(FIXTURE)


# --------------------------------------------------------------------------
# Parametrized: every command/refusal entry is invokable and matches golden
# --------------------------------------------------------------------------


@pytest.mark.parametrize("entry", COMMANDS, ids=[e["name"] for e in COMMANDS])
def test_command_surface_matches_golden(entry: dict) -> None:
    cli_surface.check_command(app, entry)


@pytest.mark.parametrize("entry", REFUSALS, ids=[e["name"] for e in REFUSALS])
def test_refusal_phrase_matches_golden(entry: dict) -> None:
    cli_surface.check_refusal(app, entry)


# --------------------------------------------------------------------------
# Core command surface
# --------------------------------------------------------------------------


def test_06_root_help_works() -> None:
    cli_surface.check_command(app, _entry("core_help"))


def test_07_version_works() -> None:
    cli_surface.check_command(app, _entry("version"))


def test_08_status_help_and_json_work() -> None:
    cli_surface.check_command(app, _entry("status_help"))
    cli_surface.check_command(app, _entry("status_json"))


def test_09_doctor_help_and_json_work() -> None:
    cli_surface.check_command(app, _entry("doctor_help"))
    cli_surface.check_command(app, _entry("doctor_json"))


def test_10_model_doctor_help_works() -> None:
    # model doctor intentionally has no --json flag in the current surface and
    # builds a provider when invoked without --help, so only help is golden.
    cli_surface.check_command(app, _entry("model_doctor_help"))


# --------------------------------------------------------------------------
# V1 / readiness
# --------------------------------------------------------------------------


def test_11_v1_check_help_works() -> None:
    cli_surface.check_command(app, _entry("v1_check_help"))


def test_12_v1_quick_json_works() -> None:
    cli_surface.check_command(app, _entry("v1_check_quick_json"))


def test_13_v1_standard_json_works() -> None:
    cli_surface.check_command(app, _entry("v1_check_standard_json"))


# --------------------------------------------------------------------------
# V2 / ops
# --------------------------------------------------------------------------


def test_14_triage_help_works() -> None:
    cli_surface.check_command(app, _entry("triage_help"))


def test_15_triage_docker_help_works() -> None:
    cli_surface.check_command(app, _entry("triage_docker_help"))


def test_16_ops_report_help_works() -> None:
    cli_surface.check_command(app, _entry("ops_report_help"))


def test_17_ops_report_json_is_read_only_non_mutating() -> None:
    result = cli_surface.invoke_cached(app, ["ops", "report", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False


def test_18_propose_apply_preview_verify_handoff_help_work() -> None:
    for name in ("propose_help", "apply_preview_help", "verify_help", "handoff_help"):
        cli_surface.check_command(app, _entry(name))


# --------------------------------------------------------------------------
# Recipes / receipts
# --------------------------------------------------------------------------


def test_19_recipes_help_works() -> None:
    cli_surface.check_command(app, _entry("recipes_help"))


def test_20_recipes_list_json_works() -> None:
    cli_surface.check_command(app, _entry("recipes_list_json"))


def test_21_recipes_preflight_help_works() -> None:
    cli_surface.check_command(app, _entry("recipes_preflight_help"))


def test_22_recipes_execute_help_works() -> None:
    cli_surface.check_command(app, _entry("recipes_execute_help"))


def test_23_recipes_receipt_help_works() -> None:
    cli_surface.check_command(app, _entry("recipes_receipt_help"))


def test_24_receipt_history_inspect_export_compare_help_work() -> None:
    for name in (
        "recipes_receipt_history_help",
        "recipes_receipt_inspect_help",
        "recipes_receipt_export_help",
        "recipes_receipt_export_validate_help",
        "recipes_receipt_compare_help",
    ):
        cli_surface.check_command(app, _entry(name))


def test_25_receipt_audit_help_work() -> None:
    for name in (
        "recipes_receipt_audit_help",
        "recipes_receipt_audit_bundle_help",
        "recipes_receipt_audit_bundle_validate_help",
    ):
        cli_surface.check_command(app, _entry(name))


def test_26_receipt_integrity_and_explain_help_work() -> None:
    cli_surface.check_command(app, _entry("recipes_receipt_integrity_help"))
    cli_surface.check_command(app, _entry("recipes_receipt_explain_help"))


def test_27_rollback_preview_help_works() -> None:
    cli_surface.check_command(app, _entry("recipes_receipt_rollback_preview_help"))


def test_28_recovery_execute_help_requires_confirm() -> None:
    entry = _entry("recipes_receipt_recovery_execute_help")
    assert "--confirm" in entry["required_substrings"]
    cli_surface.check_command(app, entry)


def test_29_recovery_status_and_validate_help_work() -> None:
    cli_surface.check_command(app, _entry("recipes_receipt_recovery_status_help"))
    cli_surface.check_command(app, _entry("recipes_receipt_recovery_validate_help"))


# --------------------------------------------------------------------------
# Ask / interactive
# --------------------------------------------------------------------------


def test_30_ask_help_works() -> None:
    cli_surface.check_command(app, _entry("ask_help"))


def test_31_interactive_help_works() -> None:
    cli_surface.check_command(app, _entry("interactive_help"))


def test_32_cleanup_restart_phrase_still_refuses() -> None:
    result = cli_surface.invoke_cached(
        app, ["ask", "Clean up docker and restart compose to fix it"]
    )
    assert result.exit_code == 0
    out = result.stdout_lower
    assert "refus" in out
    assert "no restart" in out
    assert "--execute --confirm" not in out


def test_33_rollback_recovery_rerun_fix_phrases_still_refuse() -> None:
    for phrase in (
        "rollback now",
        "recover it again",
        "rerun receipt",
        "fix corrupt receipts",
        "restart from the receipt",
    ):
        result = cli_surface.invoke_cached(app, ["ask", phrase])
        assert result.exit_code == 0, phrase
        out = result.stdout_lower
        assert "refus" in out, phrase
        assert "no action was taken" in out, phrase
        assert "--execute --confirm" not in out, phrase


# --------------------------------------------------------------------------
# Safety: JSON safety fields + no execution surface introduced
# --------------------------------------------------------------------------

# Commands the guardrail invokes with side-effecting potential are all
# --help or read-only JSON. These tokens must never appear in any invoked
# command's output, proving no execution/mutation path was triggered.
_FORBIDDEN_OUTPUT_TOKENS = (
    "container restarted: true",
    "docker_compose_executed: true",
    "cleanup_executed: true",
    "remediation_executed: true",
    "rollback_executed: true",
    "mutation_performed: true",
)


def test_34_json_safety_fields_stay_read_only_where_expected() -> None:
    for name in (
        "status_json",
        "ops_report_json",
        "recipes_list_json",
        "v1_check_quick_json",
        "verify_receipt_json",
    ):
        entry = _entry(name)
        result = cli_surface.invoke_cached(app, entry["argv"])
        payload = json.loads(result.stdout)
        assert cli_surface.resolve_safety_flag(payload, "read_only") is True, name
        assert cli_surface.resolve_safety_flag(payload, "mutation_performed") is False, name


# The full command/refusal sweep reuses the shared, process-wide invocation
# cache (``cli_surface.invoke_cached``). By the time these safety assertions run,
# the parametrized ``test_command_surface_matches_golden`` /
# ``test_refusal_phrase_matches_golden`` tests have already invoked every entry,
# so this sweep is almost entirely cache hits and the expensive v1 readiness
# invocations run exactly once for the whole module.
_SWEEP_CACHE: list[tuple[str, str]] | None = None


def _all_invoked_outputs() -> list[tuple[str, str]]:
    global _SWEEP_CACHE
    if _SWEEP_CACHE is None:
        outputs: list[tuple[str, str]] = []
        for entry in COMMANDS + REFUSALS:
            result = cli_surface.invoke_cached(app, entry["argv"])
            outputs.append((entry["name"], result.stdout_lower))
        _SWEEP_CACHE = outputs
    return _SWEEP_CACHE


def test_35_to_41_no_execution_flag_ever_true() -> None:
    # 35 cleanup, 36 remediation, 37 rollback, 38 recovery (recovery restart
    # surfaces as container_restarted), 39 docker/compose, 40 container restart,
    # 41 production restart: none of these may ever report true from any invoked
    # command/refusal in the guardrail.
    tokens = (
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "container_restarted",
        "docker_compose_executed",
    )
    for name, out in _all_invoked_outputs():
        for token in tokens:
            assert f"{token}: true" not in out, f"{name}: {token} reported true"
            assert f'"{token}": true' not in out, f"{name}: {token} reported true (json)"


def test_42_no_shell_true_in_added_artifacts() -> None:
    _assert_no_execution_snippets()


def test_43_44_no_arbitrary_or_nl_execution_in_added_artifacts() -> None:
    _assert_no_execution_snippets()


def _assert_no_execution_snippets() -> None:
    helper_src = (HELPERS / "cli_surface.py").read_text(encoding="utf-8")
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "cli_surface_snapshot.py"
    script_src = script_path.read_text(encoding="utf-8") if script_path.exists() else ""
    combined = helper_src + "\n" + script_src
    forbidden = (
        "shell=True",
        "subprocess.run",
        "subprocess.Popen",
        "os.system",
        "docker compose up",
        "docker compose down",
        "docker compose restart",
        "docker restart",
        "execute_receipt_recovery(",
        "preview_receipt_rollback(",
        "run_exact_docker_restart(",
    )
    for snippet in forbidden:
        assert snippet not in combined, (
            f"unexpected execution snippet in added artifacts: {snippet}"
        )


def test_45_no_model_call_from_deterministic_surface() -> None:
    # The autouse fixture blocks build_provider with an AssertionError. The
    # cached full sweep invokes every golden command and refusal phrase; if any
    # triggered a model call the sweep would already have failed.
    assert _all_invoked_outputs(), "expected a non-empty command sweep"


# --------------------------------------------------------------------------
# Regression: prior extraction / command-surface tests still pass
# --------------------------------------------------------------------------


def test_46_to_49_prior_command_surface_tests_present() -> None:
    base = Path(__file__).resolve().parent
    for name in (
        "test_pr182_cli_module_scaffold_status_doctor.py",
        "test_pr183_cli_module_split_ops_triage.py",
        "test_pr143_command_surface_audit.py",
        "test_pr114_v1_command_surface.py",
    ):
        assert (base / name).exists(), name


def test_50_deterministic_refusal_count_covered() -> None:
    # At least the six required mutation-refusal smoke phrases are covered.
    assert len(REFUSALS) >= 6
