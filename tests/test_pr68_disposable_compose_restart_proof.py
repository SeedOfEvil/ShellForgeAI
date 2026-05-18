"""PR68 optional live disposable Compose restart proof helper tests.

Verifies the lab-only orchestrator script:
- exists and is executable
- defaults to dry-run/readiness only
- never auto-executes the gated mission
- refuses production target names
- pins the exact disposable target invariants
- carries the explicit dangerous flag name
- prints the gated ShellForgeAI command sequence in dry-run/print mode
- does not run docker system prune, does not remove arbitrary paths,
  does not edit production compose files, does not install packages,
  does not pass --execute --confirm by default
"""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROOF_SCRIPT = REPO_ROOT / "scripts" / "pr68_disposable_compose_restart_proof.sh"
HARNESS_SCRIPT = REPO_ROOT / "scripts" / "pr67_disposable_compose_harness.sh"

DISPOSABLE_PROJECT = "sfai_pr67_disposable"
DISPOSABLE_SERVICE = "web"
DISPOSABLE_CONTAINER = "sfai-pr67-compose-web"
DANGEROUS_FLAG = "--execute-approved-disposable-restart"


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(PROOF_SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _script_text() -> str:
    return PROOF_SCRIPT.read_text(encoding="utf-8")


def _script_text_no_comments() -> str:
    lines = []
    for ln in _script_text().splitlines():
        if ln.lstrip().startswith("#"):
            continue
        lines.append(ln)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# script presence and shape
# ---------------------------------------------------------------------------


def test_proof_script_exists_and_executable() -> None:
    assert PROOF_SCRIPT.is_file(), "PR68 proof script missing"
    mode = PROOF_SCRIPT.stat().st_mode
    assert mode & stat.S_IXUSR, "PR68 proof script must be executable"


def test_proof_script_pins_disposable_target_names() -> None:
    raw = _script_text()
    assert DISPOSABLE_PROJECT in raw
    assert DISPOSABLE_SERVICE in raw
    assert DISPOSABLE_CONTAINER in raw


def test_proof_script_declares_dangerous_flag() -> None:
    assert DANGEROUS_FLAG in _script_text()


def test_proof_script_references_pr67_harness() -> None:
    assert "pr67_disposable_compose_harness.sh" in _script_text()


# ---------------------------------------------------------------------------
# safety: no destructive operations baked in
# ---------------------------------------------------------------------------


def test_proof_script_does_not_prune() -> None:
    assert "docker system prune" not in _script_text_no_comments()


def test_proof_script_does_not_remove_arbitrary_paths() -> None:
    code = _script_text_no_comments()
    assert "rm -rf /" not in code
    assert "rm -rf ~" not in code
    assert "rm -rf $HOME" not in code


def test_proof_script_does_not_install_packages() -> None:
    code = _script_text_no_comments()
    for forbidden in (
        "apt-get install",
        "apt install",
        "apk add",
        "yum install",
        "dnf install",
        "pip install",
        "pip3 install",
    ):
        assert forbidden not in code, f"unexpected installer in script: {forbidden}"


def test_proof_script_does_not_edit_production_compose_files() -> None:
    code = _script_text_no_comments()
    # We must not target the production project name with docker compose
    assert "--project-name shellforgeai" not in code
    assert "--project-name shellforgeai\n" not in code
    # We must not invoke docker compose up/down/recreate against arbitrary
    # compose files. The script may only refer to the disposable harness.
    for verb in ("up", "down", "recreate"):
        line = f'docker compose -f "$COMPOSE_FILE" --project-name "$EXPECTED_PROJECT" {verb}'
        # script must not bring up/down the disposable project itself - that
        # is the PR67 harness's job, not this orchestrator's.
        assert line not in code


def test_proof_script_uses_no_shell_true_pattern() -> None:
    # No eval, no constructing commands from unquoted strings.
    code = _script_text_no_comments()
    assert "eval " not in code
    assert "eval\t" not in code
    assert "/bin/sh -c" not in code
    assert "bash -c $" not in code


# ---------------------------------------------------------------------------
# default behavior: dry-run / print-only / readiness-only
# ---------------------------------------------------------------------------


def test_print_commands_does_not_auto_execute() -> None:
    res = _run("print-commands")
    assert res.returncode == 0
    out = res.stdout
    # Must show the gated ShellForgeAI mission execute command as a manual
    # step, never auto-run it.
    assert "shellforgeai mission compose-restart execute" in out
    assert "--execute --confirm" in out
    # Must mention that this is print-only / never auto-executes.
    assert "print-only" in out.lower() or "never auto-execute" in out.lower()
    # Must explicitly mention the disposable target.
    assert DISPOSABLE_CONTAINER in out


def test_dry_run_alias_matches_print_commands() -> None:
    a = _run("print-commands")
    b = _run("dry-run")
    assert a.returncode == 0 and b.returncode == 0
    assert b.stdout == a.stdout


def test_run_proof_without_dangerous_flag_refuses_execution() -> None:
    res = _run("run-proof")
    assert res.returncode == 0
    out = res.stdout.lower()
    # Must refuse to execute without explicit dangerous flag.
    assert "refusing to execute" in out or "default mode" in out
    assert DANGEROUS_FLAG in res.stdout
    # Must not appear to have called the gated execute command for the user.
    # (Since this is print/refuse, no execute output is expected here.)


def test_run_proof_default_does_not_pass_execute_confirm() -> None:
    res = _run("run-proof")
    assert res.returncode == 0
    # Default output is print-only; the only place --execute --confirm
    # appears is in the printed manual command sequence, not as an action.
    # Ensure the script does not claim to have executed.
    assert "executed" not in res.stdout.lower() or "never auto-execute" in res.stdout.lower()


# ---------------------------------------------------------------------------
# refusals
# ---------------------------------------------------------------------------


def test_unknown_subcommand_refuses() -> None:
    res = _run("self-destruct")
    assert res.returncode != 0


def test_no_args_shows_usage_and_refuses() -> None:
    res = _run()
    assert res.returncode != 0
    assert "Usage" in res.stdout or "Usage" in res.stderr


# ---------------------------------------------------------------------------
# script text invariants for production refusal
# ---------------------------------------------------------------------------


def test_proof_script_explicitly_refuses_production_targets() -> None:
    code = _script_text()
    # Refusal pattern for production-looking names must appear.
    assert "shellforgeai" in code
    assert "Refusing" in code
    # Production-looking project / container guards must exist.
    assert "production-looking" in code.lower() or "production" in code.lower()


def test_proof_script_pins_dangerous_flag_name_exactly() -> None:
    # The dangerous flag name must be exactly the documented one.
    code = _script_text()
    assert DANGEROUS_FLAG in code
    # No alternative bypass flags.
    for bad in ("--yes", "--force-execute", "--bypass-gates", "--skip-confirm"):
        assert bad not in code


def test_proof_script_does_not_invoke_natural_language_ask() -> None:
    code = _script_text_no_comments()
    # Must not pipe natural-language asks at the CLI.
    assert "shellforgeai ask" not in code


def test_proof_script_uses_explicit_argv_for_shellforgeai_calls() -> None:
    code = _script_text_no_comments()
    # The gated mission execute command is documented in printed output
    # but must not appear as an actual command invocation in the script
    # body (i.e. there is no `$SHELLFORGEAI_BIN mission compose-restart
    # execute ... --execute --confirm` line outside the heredoc).
    for line in code.splitlines():
        stripped = line.strip()
        if "mission compose-restart execute" in stripped and "--execute" in stripped:
            # Allow only inside heredoc-ish prefix (the print block uses
            # indentation but no `$SHELLFORGEAI_BIN` invocation in this
            # PR68 helper).
            assert not stripped.startswith("$SHELLFORGEAI_BIN"), stripped
            assert not stripped.startswith('"$SHELLFORGEAI_BIN"'), stripped
