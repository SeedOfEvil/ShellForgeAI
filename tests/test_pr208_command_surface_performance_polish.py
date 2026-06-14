"""PR208 — command-surface golden / import guardrail performance polish.

This is validation-performance work only: it adds no product command and changes
no ShellForgeAI runtime behavior. It proves that the PR184 golden command-surface
guardrail and the PR205 import side-effect guardrail keep exactly the same safety
coverage while running the expensive, repeated, read-only CLI invocations far
fewer times.

The polish is a shared, process-wide invocation cache in
``tests/helpers/cli_surface.py`` (``invoke_cached``) plus a deterministic
duration report (``invocation_duration_report`` / ``format_duration_report``).
The PR184 suite previously invoked the slow commands (``v1 check`` readiness,
``status --json``, ``ops report``) two or three times each across the
parametrized sweep, the explicit numbered tests, and the whole-surface safety
sweep; with the cache each unique argv runs at most once per test process.

These tests assert:

* the golden fixture still covers the same expected commands and refusals,
* cached invocation returns a result identical to an uncached invocation,
* repeated invocation does not re-run the expensive CliRunner path,
* failure output still names the offending command and missing/unexpected token,
* the PR184 / PR204 / PR205 guardrail suites remain present and collectible,
* no ``shell=True`` / subprocess / Docker / network / model / artifact mutation
  is introduced by the cached path, and
* the duration report is deterministic enough to assert on its structure.

The tests run the CLI in-process via the model-blocked ``CliRunner`` helper and,
where they exercise the sibling guardrail suites, only *collect* them in a fresh
subprocess (no Docker daemon, no network, no host mutation).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
HELPERS = REPO / "tests" / "helpers"
if str(HELPERS) not in sys.path:
    sys.path.insert(0, str(HELPERS))

import cli_surface  # noqa: E402

from shellforgeai import cli as cli_mod  # noqa: E402
from shellforgeai.cli import app  # noqa: E402

FIXTURE = cli_surface.load_fixture()
COMMANDS = FIXTURE["commands"]
REFUSALS = FIXTURE.get("refusal_phrases", [])
COMMAND_NAMES = {entry["name"] for entry in COMMANDS}

# A representative slice of the command surface that must never silently vanish.
# These span every safety-relevant lane (read-only inspection, governed-recipe
# confirmation, ask/interactive). Keeping this list here gives PR208 an explicit,
# independent coverage assertion in addition to PR184's golden snapshot.
REQUIRED_COMMAND_NAMES = frozenset(
    {
        "core_help",
        "version",
        "status_json",
        "doctor_json",
        "v1_check_quick_json",
        "v1_check_standard_json",
        "triage_help",
        "ops_report_json",
        "propose_help",
        "apply_preview_help",
        "verify_help",
        "handoff_help",
        "recipes_list_json",
        "recipes_execute_help",
        "recipes_receipt_recovery_execute_help",
        "ask_help",
        "interactive_help",
    }
)


@pytest.fixture(autouse=True)
def _safe_cli_env(monkeypatch, tmp_path: Path):
    """Isolate the data dir to tmp and block any model/provider call."""

    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    cli_surface.block_model_calls(monkeypatch, cli_mod)
    return tmp_path


def _collect_only(target: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(SRC), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    return subprocess.run(  # noqa: S603 - collects a local guardrail suite only.
        [sys.executable, "-m", "pytest", "-q", "-p", "no:xdist", "--collect-only", target],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


# --------------------------------------------------------------------------
# 1: golden coverage preserved
# --------------------------------------------------------------------------


def test_01_golden_fixture_still_covers_expected_commands() -> None:
    cli_surface.validate_fixture(FIXTURE)
    missing = REQUIRED_COMMAND_NAMES - COMMAND_NAMES
    assert not missing, f"command-surface coverage shrank; missing: {sorted(missing)}"
    # The governed recovery-execute command must still advertise --confirm.
    recovery = next(e for e in COMMANDS if e["name"] == "recipes_receipt_recovery_execute_help")
    assert "--confirm" in recovery.get("required_substrings", [])
    # Mutation-refusal coverage is unchanged.
    assert len(REFUSALS) >= 6


def test_02_every_golden_command_is_still_invokable() -> None:
    # Drives the full golden surface through the cache exactly as PR184 does, and
    # confirms each unique argv is invoked at most once (misses == unique argvs).
    cli_surface.clear_invoke_cache()
    for entry in COMMANDS:
        cli_surface.check_command(app, entry)
    for entry in REFUSALS:
        cli_surface.check_refusal(app, entry)
    stats = cli_surface.invoke_cache_stats()
    unique_argvs = {tuple(e["argv"]) for e in COMMANDS + REFUSALS}
    assert stats["unique"] == len(unique_argvs)
    assert stats["misses"] == len(unique_argvs)


# --------------------------------------------------------------------------
# 2: cached discovery == uncached discovery
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [["--help"], ["status", "--help"], ["recipes", "list", "--json"]],
    ids=["root_help", "status_help", "recipes_list_json"],
)
def test_03_cached_invocation_matches_uncached(argv: list[str]) -> None:
    cli_surface.clear_invoke_cache()
    fresh = cli_surface.invoke(app, argv)
    cached = cli_surface.invoke_cached(app, argv)
    assert cached.exit_code == fresh.exit_code
    assert cached.stdout == fresh.stdout


def test_04_repeated_cached_invocation_returns_same_object() -> None:
    cli_surface.clear_invoke_cache()
    first = cli_surface.invoke_cached(app, ["--help"])
    second = cli_surface.invoke_cached(app, ["--help"])
    assert first is second  # identity, not just equality


# --------------------------------------------------------------------------
# 3: repeated discovery does not re-run the expensive CliRunner path
# --------------------------------------------------------------------------


def test_05_cache_hit_does_not_reinvoke_clirunner(monkeypatch) -> None:
    cli_surface.clear_invoke_cache()
    calls: list[tuple[str, ...]] = []
    real_invoke = cli_surface.invoke

    def _counting_invoke(app_, argv):
        calls.append(tuple(argv))
        return real_invoke(app_, argv)

    monkeypatch.setattr(cli_surface, "invoke", _counting_invoke)

    cli_surface.invoke_cached(app, ["--help"])
    cli_surface.invoke_cached(app, ["--help"])
    cli_surface.invoke_cached(app, ["--help"])

    assert calls == [("--help",)], "cache hit must not re-run the underlying invocation"
    stats = cli_surface.invoke_cache_stats()
    assert stats["misses"] == 1
    assert stats["hits"] == 2


# --------------------------------------------------------------------------
# 4: failure output still names the offending command/token
# --------------------------------------------------------------------------


def test_06_missing_substring_failure_is_precise() -> None:
    cli_surface.clear_invoke_cache()
    bogus = {
        "name": "synthetic_help",
        "argv": ["--help"],
        "required_substrings": ["this_token_will_never_appear_in_help"],
    }
    with pytest.raises(AssertionError) as excinfo:
        cli_surface.check_command(app, bogus)
    message = str(excinfo.value)
    assert "synthetic_help" in message
    assert "this_token_will_never_appear_in_help" in message


def test_07_unexpected_exit_code_failure_is_precise() -> None:
    cli_surface.clear_invoke_cache()
    bogus = {
        "name": "synthetic_exit",
        "argv": ["--help"],
        "required_substrings": [],
        "expect_exit_code": 42,
    }
    with pytest.raises(AssertionError) as excinfo:
        cli_surface.check_command(app, bogus)
    message = str(excinfo.value)
    assert "synthetic_exit" in message
    assert "42" in message


# --------------------------------------------------------------------------
# 5–7: sibling guardrail suites remain present and collectible
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "tests/test_pr184_cli_command_surface_golden.py",
        "tests/test_pr204_cli_wiring_only_enforcement.py",
        "tests/test_pr205_command_module_import_side_effects.py",
    ],
)
def test_08_guardrail_suites_present_and_collectible(target: str) -> None:
    assert (REPO / target).exists(), target
    result = _collect_only(target)
    assert result.returncode == 0, result.stdout + result.stderr


# --------------------------------------------------------------------------
# 8–9: no execution / mutation introduced by the cached helper path
# --------------------------------------------------------------------------


def test_09_no_execution_snippets_in_perf_artifacts() -> None:
    # Scan the actual cached-invocation helper -- the only added artifact that
    # *runs* commands. (The PR184/PR208 test modules legitimately list these
    # tokens as forbidden strings, so scanning their source would self-trip.)
    helper_src = (HELPERS / "cli_surface.py").read_text(encoding="utf-8")
    combined = helper_src
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
        "build_provider(",
    )
    for snippet in forbidden:
        assert snippet not in combined, f"unexpected execution snippet in perf artifacts: {snippet}"


def test_10_cached_path_uses_only_in_process_clirunner() -> None:
    # The cache must never reach for Docker/network/model/subprocess execution: it
    # wraps the existing in-process CliRunner invocation and a perf-counter clock.
    helper_src = (HELPERS / "cli_surface.py").read_text(encoding="utf-8")
    for forbidden in ("import subprocess", "import socket", "import httpx", "import docker"):
        assert forbidden not in helper_src, forbidden
    assert "from typer.testing import CliRunner" in helper_src


# --------------------------------------------------------------------------
# 10: deterministic duration / reporting
# --------------------------------------------------------------------------


def test_11_duration_report_structure_is_deterministic() -> None:
    cli_surface.clear_invoke_cache()
    cli_surface.invoke_cached(app, ["--help"])
    cli_surface.invoke_cached(app, ["status", "--help"])
    cli_surface.invoke_cached(app, ["--help"])  # cache hit, no new timing

    report = cli_surface.invocation_duration_report()
    assert set(report) == {"unique_commands", "cache_hits", "cache_misses", "slowest"}
    assert report["unique_commands"] == 2
    assert report["cache_misses"] == 2
    assert report["cache_hits"] == 1

    seconds = [item["seconds"] for item in report["slowest"]]
    assert all(isinstance(s, float) and s >= 0.0 for s in seconds)
    # Deterministic ordering: slowest first.
    assert seconds == sorted(seconds, reverse=True)
    for item in report["slowest"]:
        assert isinstance(item["argv"], list)
        assert all(isinstance(a, str) for a in item["argv"])


def test_12_duration_report_top_limit_is_respected() -> None:
    cli_surface.clear_invoke_cache()
    for argv in (["--help"], ["status", "--help"], ["doctor", "--help"]):
        cli_surface.invoke_cached(app, argv)
    assert len(cli_surface.invocation_duration_report(top=1)["slowest"]) == 1
    assert len(cli_surface.invocation_duration_report(top=0)["slowest"]) == 0
    assert len(cli_surface.invocation_duration_report(top=10)["slowest"]) == 3


def test_13_format_duration_report_is_readable_text() -> None:
    cli_surface.clear_invoke_cache()
    cli_surface.invoke_cached(app, ["--help"])
    text = cli_surface.format_duration_report()
    assert "command-surface invocation report:" in text
    assert "unique commands invoked: 1" in text
    assert "cache hits / misses: 0 / 1" in text
