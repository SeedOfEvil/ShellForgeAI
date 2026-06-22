#!/usr/bin/env python3
"""Read-only Docker01 operator QA evidence bundle helper.

ShellForgeAI is a CLI-first Linux/Docker operator knife. Docker01 PR QA is
strong, but the reviewer handoff is still assembled by hand from many command
outputs and logs. This helper removes that copy/paste step: it runs the standard
Docker01 smoke QA command set, captures raw stdout/stderr/exit codes, parses the
key JSON outputs, evaluates explicit safety assertions, and writes a small,
pasteable evidence bundle for the PR handoff.

It is an *evidence collection helper only*. It is read-only:

* Commands come from a small fixed allowlist (the standard read-only smoke set
  plus ``docker ps`` / ``docker inspect shellforgeai`` / ``df -h /`` /
  ``validation_status.py``). Any other command family is rejected.
* Subprocess execution uses argv lists with bounded timeouts and never
  the shell execution mode.
* It performs no cleanup, remediation, rollback, recovery, Docker/Compose
  mutation, container/production restart, prune, package install, network call,
  or cloud apply/merge/push. The remediation self-test keeps live disposable
  execution skipped by default.

The generated ``qa-summary.md`` is a reviewer convenience. It never auto-declares
a PR mergeable; the reviewer still gives the final merge verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

SCHEMA_VERSION = 1
MODE = "docker01_operator_qa_bundle"
SHORT_SHA_LEN = 12

# Lifecycle modes (validate / history / compare) are artifact-only: they read an
# existing bundle's files, parse JSON, and compute hashes. They never run Docker,
# ShellForgeAI, or validation_status.py, never use subprocess, and never mutate a
# bundle or Docker01.
MANIFEST_FILE = "bundle-manifest.json"
MANIFEST_MODE = "docker01_qa_bundle_manifest"
VALIDATE_MODE = "docker01_qa_bundle_validate"
HISTORY_MODE = "docker01_qa_bundle_history"
COMPARE_MODE = "docker01_qa_bundle_compare"

# Default discovery root for history/compare-latest.
DEFAULT_ROOT = "/tmp"

# PR206 bundle directory naming: ``sfai-pr<PR>-<shortsha>-qa-bundle-<timestamp>``.
BUNDLE_NAME_RE = re.compile(r"^sfai-pr(?P<pr>\d+)-(?P<short>[^-]+)-qa-bundle-(?P<stamp>.+)$")

# Files every PR206-style bundle must contain (besides ``raw/``).
REQUIRED_BUNDLE_FILES: tuple[str, ...] = (
    "qa-summary.md",
    "qa-results.json",
    "safety-assertions.json",
    "container-state.json",
    "validation-status.json",
    "commands-run.json",
)
# Subset of required files that must parse as strict JSON.
REQUIRED_BUNDLE_JSON: tuple[str, ...] = (
    "qa-results.json",
    "safety-assertions.json",
    "container-state.json",
    "validation-status.json",
    "commands-run.json",
)

# Bundle status ordering used to classify compare regressions/improvements.
_STATUS_RANK = {"failed": 0, "dry_run": 1, "partial": 2, "passed": 3}

# Per-command subprocess timeout (seconds). A couple of commands get more room.
DEFAULT_TIMEOUT = 120
LONG_TIMEOUT = 240
# Bound each raw output file so the bundle stays handoff-sized.
MAX_RAW_CHARS = 200_000

# The helper runs on the Docker01 host. ShellForgeAI product smoke commands are
# executed *inside* the running container through a narrow read-only
# ``docker exec`` argv prefix, so the host does not need ``shellforgeai`` on its
# PATH. Host/system checks stay host-side.
SHELLFORGEAI = "shellforgeai"
CONTAINER = "shellforgeai"
DOCKER_EXEC_PREFIX: tuple[str, ...] = ("docker", "exec", CONTAINER, SHELLFORGEAI)


def _sfai(*args: str) -> tuple[str, ...]:
    """Build a ``docker exec shellforgeai shellforgeai ...`` argv tuple."""
    return (*DOCKER_EXEC_PREFIX, *args)


# Validation status is a host-side check. Use the *current* interpreter so hosts
# that have ``python3`` but no ``python`` alias still work. The command is scoped
# to the PR/commit under review so the bundle never silently embeds stale
# validation evidence from another PR or commit.
VALIDATION_STATUS_SCRIPT = "scripts/validation_status.py"


def validation_status_argv(pr: int, commit: str) -> tuple[str, ...]:
    """Build the scoped, host-side ``validation_status.py`` argv for pr/commit."""
    return (
        sys.executable,
        VALIDATION_STATUS_SCRIPT,
        "--latest",
        "--pr",
        str(pr),
        "--commit",
        str(commit),
        "--json",
        "--explain-selection",
    )


# Stable safety-flag dimensions surfaced in qa-results.json. Most are aggregated
# (OR) from the parsed product outputs so that if any command ever reported a
# mutation, the bundle surfaces it and the matching safety assertion fails.
SAFETY_FLAG_KEYS: tuple[str, ...] = (
    "cleanup_executed",
    "docker_prune_executed",
    "file_deleted",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
    "docker_compose_executed",
    "container_restarted",
    "production_restart_executed",
    "arbitrary_command_execution",
    "natural_language_execution",
    "artifact_repaired",
    "artifact_deleted",
)


@dataclass(frozen=True)
class CommandSpec:
    """A single allowlisted, read-only QA command."""

    key: str
    label: str
    argv: tuple[str, ...]
    raw_file: str
    parse: str = "text"  # "json" | "text"
    critical: bool = True
    timeout: int = DEFAULT_TIMEOUT


def hygiene_command_specs(include_review_bundle: bool = False) -> list[CommandSpec]:
    """Return bounded Docker01 hygiene evidence commands.

    History and compare-latest read existing hygiene reports only. Review bundle
    packaging is explicit opt-in because it writes a bounded handoff artifact.
    """
    specs = [
        CommandSpec(
            "hygiene_history",
            "hygiene history",
            (
                sys.executable,
                "scripts/docker01_hygiene_report.py",
                "--history",
                "--root",
                DEFAULT_ROOT,
                "--json",
            ),
            "raw/hygiene-history.json",
            parse="json",
            critical=False,
        ),
        CommandSpec(
            "hygiene_compare_latest",
            "hygiene compare-latest",
            (
                sys.executable,
                "scripts/docker01_hygiene_report.py",
                "--compare-latest",
                "--root",
                DEFAULT_ROOT,
                "--json",
            ),
            "raw/hygiene-compare-latest.json",
            parse="json",
            critical=False,
        ),
    ]
    if include_review_bundle:
        specs.append(
            CommandSpec(
                "hygiene_review_bundle",
                "hygiene review-bundle-latest",
                (
                    sys.executable,
                    "scripts/docker01_hygiene_report.py",
                    "--review-bundle-latest",
                    "--root",
                    DEFAULT_ROOT,
                    "--json",
                ),
                "raw/hygiene-review-bundle.json",
                parse="json",
                critical=False,
            )
        )
    return specs


def build_command_specs(pr: int, commit: str) -> list[CommandSpec]:
    """Return the ordered standard Docker01 smoke QA command set for pr/commit.

    The helper runs on the Docker01 host. ShellForgeAI product smoke commands are
    executed inside the running ``shellforgeai`` container via a narrow read-only
    ``docker exec shellforgeai shellforgeai ...`` argv prefix (so the host does
    not need ``shellforgeai`` on its PATH). The host/system checks (``docker ps``
    / ``docker inspect`` / ``df`` / validation status) run host-side.

    ``critical`` marks the ShellForgeAI product surface whose failure makes the
    bundle ``failed``. Host/optional checks (model doctor, docker, disk,
    validation status) are non-critical: their failure makes the bundle
    ``partial`` because they depend on host state (Docker daemon, prior
    validation runs) that is legitimately absent in some QA environments. The
    read-only Docker ask is deliberately phrased to use deterministic local
    triage routing and must not require Codex/model auth.
    """
    return [
        CommandSpec("version", "version", _sfai("version"), "raw/version.txt"),
        CommandSpec("doctor", "doctor", _sfai("doctor"), "raw/doctor.txt"),
        CommandSpec(
            "model_doctor",
            "model doctor",
            _sfai("model", "doctor"),
            "raw/model-doctor.txt",
            critical=False,
        ),
        CommandSpec(
            "v1_quick",
            "v1 quick",
            _sfai("v1", "check", "--profile", "quick", "--json"),
            "raw/v1-quick.json",
            parse="json",
        ),
        CommandSpec(
            "v1_standard",
            "v1 standard",
            _sfai("v1", "check", "--profile", "standard", "--json"),
            "raw/v1-standard.json",
            parse="json",
        ),
        CommandSpec(
            "ops_report",
            "ops report",
            _sfai("ops", "report", "--json"),
            "raw/ops-report.json",
            parse="json",
        ),
        CommandSpec(
            "status",
            "status",
            _sfai("status", "--json"),
            "raw/status.json",
            parse="json",
        ),
        CommandSpec(
            "triage_docker",
            "triage",
            _sfai("triage", "docker", "--json"),
            "raw/triage-docker.json",
            parse="json",
        ),
        CommandSpec(
            "propose",
            "propose",
            _sfai("propose", "--json"),
            "raw/propose.json",
            parse="json",
        ),
        CommandSpec(
            "apply_preview",
            "apply-preview",
            _sfai("apply-preview", "--json"),
            "raw/apply-preview.json",
            parse="json",
        ),
        CommandSpec(
            "verify",
            "verify",
            _sfai("verify", "--json"),
            "raw/verify.json",
            parse="json",
        ),
        CommandSpec(
            "handoff",
            "handoff",
            _sfai("handoff", "--json"),
            "raw/handoff.json",
            parse="json",
        ),
        CommandSpec(
            "ask_readonly",
            "read-only Docker ask",
            _sfai("ask", "2AM docker feels broken"),
            "raw/ask-readonly.txt",
            critical=False,
        ),
        CommandSpec(
            "ask_mutation",
            "mutation refusal ask",
            _sfai("ask", "Clean up docker and restart compose to fix it"),
            "raw/ask-mutation-refusal.txt",
        ),
        CommandSpec(
            "remediation_self_test",
            "remediation self-test full",
            _sfai("remediation", "self-test", "--profile", "full", "--json"),
            "raw/remediation-self-test-full.json",
            parse="json",
            timeout=LONG_TIMEOUT,
        ),
        CommandSpec(
            "docker_ps",
            "docker ps",
            ("docker", "ps", "--filter", "name=shellforgeai"),
            "raw/docker-ps.txt",
            critical=False,
        ),
        CommandSpec(
            "docker_inspect",
            "docker inspect",
            ("docker", "inspect", "shellforgeai"),
            "raw/docker-inspect.json",
            parse="json",
            critical=False,
        ),
        CommandSpec(
            "disk",
            "df -h /",
            ("df", "-h", "/"),
            "raw/disk.txt",
            critical=False,
        ),
        CommandSpec(
            "validation_status",
            "validation status",
            validation_status_argv(pr, commit),
            "raw/validation-status.json",
            parse="json",
            critical=False,
            timeout=LONG_TIMEOUT,
        ),
    ]


# ---------------------------------------------------------------------------
# Command allowlist
# ---------------------------------------------------------------------------


def is_command_allowed(argv: Sequence[str]) -> bool:
    """Return True only for the small fixed family of read-only QA commands.

    The helper runs on the Docker01 host, so the allowlist is narrow and
    per-head:

    * ``docker`` — only:
      * ``docker ps --filter name=shellforgeai`` (any ``ps`` flags),
      * ``docker inspect shellforgeai``,
      * ``docker exec shellforgeai shellforgeai <approved read-only command>``.
      ``restart``, ``compose ...``, ``volume prune``, ``exec`` of a shell
      (``sh``/``bash``) or any other binary (``rm``/``curl``/``apt`` …), and
      ``exec`` flags (``-u``/``-i`` …) are all rejected.
    * ``df`` — only ``df -h /``.
    * a Python interpreter (``python``/``python3``/``python3.x`` or
      ``sys.executable``) — only ``scripts/validation_status.py``.

    Everything else (``rm``/``touch``/``curl``/``wget``/``pip``/``apt``/``gh``/
    ``codex`` …) is rejected.
    """
    argv = list(argv)
    if not argv:
        return False
    head = argv[0]
    rest = argv[1:]

    if head == "docker":
        return _docker_allowed(rest)
    if head == "df":
        return rest == ["-h", "/"]
    if _is_python_exe(head):
        return _validation_status_allowed(rest) or _hygiene_command_allowed(rest)
    return False


def _hygiene_command_allowed(rest: list[str]) -> bool:
    """Allow only fixed Docker01 hygiene evidence-reader invocations."""
    if not rest or Path(rest[0]).name != "docker01_hygiene_report.py":
        return False
    args = rest[1:]
    return args in (
        ["--history", "--root", DEFAULT_ROOT, "--json"],
        ["--compare-latest", "--root", DEFAULT_ROOT, "--json"],
        ["--review-bundle-latest", "--root", DEFAULT_ROOT, "--json"],
    )


def _validation_status_allowed(rest: list[str]) -> bool:
    """Allow only the scoped ``validation_status.py --latest --pr P --commit C`` form.

    The command must be ``scripts/validation_status.py --latest --pr <pr>
    --commit <commit> --json --explain-selection`` so validation evidence is
    scoped to the PR/commit under review (never an unscoped ``--latest`` that
    could embed stale evidence from another PR). ``<pr>``/``<commit>`` are
    structural placeholders (any non-flag token); no other script or flag set is
    accepted.
    """
    if not rest or Path(rest[0]).name != "validation_status.py":
        return False
    args = rest[1:]
    if len(args) != 7:
        return False
    pr_value, commit_value = args[2], args[4]
    fixed_ok = (
        args[0] == "--latest"
        and args[1] == "--pr"
        and args[3] == "--commit"
        and args[5] == "--json"
        and args[6] == "--explain-selection"
    )
    value_ok = (
        bool(pr_value)
        and not pr_value.startswith("-")
        and bool(commit_value)
        and not commit_value.startswith("-")
    )
    return fixed_ok and value_ok


def _is_python_exe(head: str) -> bool:
    """True for a Python interpreter invocation (host may lack a ``python`` alias)."""
    if head == sys.executable:
        return True
    return Path(head).name.startswith("python")


# Read-only ShellForgeAI subcommand surfaces this helper may invoke. Keyed by the
# command group; the tuple is the exact required token prefix after the group.
_SHELLFORGEAI_ALLOWED_FORMS: tuple[tuple[str, ...], ...] = (
    ("version",),
    ("doctor",),
    ("model", "doctor"),
    ("v1", "check", "--profile", "quick", "--json"),
    ("v1", "check", "--profile", "standard", "--json"),
    ("ops", "report", "--json"),
    ("status", "--json"),
    ("triage", "docker", "--json"),
    ("propose", "--json"),
    ("apply-preview", "--json"),
    ("verify", "--json"),
    ("handoff", "--json"),
    ("remediation", "self-test", "--profile", "full", "--json"),
    ("model", "receipt", "history", "--root", DEFAULT_ROOT, "--json"),
)


def _shellforgeai_allowed(rest: list[str]) -> bool:
    # ``ask`` is special: its single free-text argument is operator question
    # text (which can legitimately contain words like "restart" or "compose"),
    # so it is matched structurally, not by token scanning.
    if rest[:1] == ["ask"]:
        return len(rest) == 2 and isinstance(rest[1], str)
    return tuple(rest) in _SHELLFORGEAI_ALLOWED_FORMS


def _docker_allowed(rest: list[str]) -> bool:
    if not rest:
        return False
    sub = rest[0]
    if sub == "ps":
        return True
    if sub == "inspect":
        return rest[1:] == ["shellforgeai"]
    if sub == "exec":
        return _docker_exec_allowed(rest[1:])
    return False


def _docker_exec_allowed(args: list[str]) -> bool:
    """Allow only ``docker exec shellforgeai shellforgeai <approved command>``.

    The first two tokens after ``exec`` must be exactly the container name
    ``shellforgeai`` and the ``shellforgeai`` binary — no ``exec`` flags
    (``-u``/``-i``/``-e`` …), no shell (``sh``/``bash``), and no other binary
    (``rm``/``curl``/``apt`` …) may slip in.
    """
    if len(args) < 2:
        return False
    container, command = args[0], args[1]
    if container != CONTAINER or command != SHELLFORGEAI:
        return False
    return _shellforgeai_allowed(args[2:])


# ---------------------------------------------------------------------------
# Command runner
# ---------------------------------------------------------------------------


@dataclass
class RunResult:
    """Normalized result of a single command invocation."""

    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_ms: int = 0


# A runner takes (argv, timeout) and returns an object exposing returncode/
# stdout/stderr (subprocess.CompletedProcess works). Tests inject fakes.
Runner = Callable[[Sequence[str], int], Any]


def default_runner(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess:
    """Execute ``argv`` without a shell, capturing text output (read-only)."""
    return subprocess.run(  # noqa: S603 - argv list, no shell, allowlisted upstream
        list(argv),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        cwd=str(REPO_ROOT),
    )


def run_one(spec: CommandSpec, runner: Runner) -> RunResult:
    """Run one allowlisted command and normalize the result."""
    if not is_command_allowed(spec.argv):
        # Defensive: every planned command is allowlisted, so this only fires if
        # the spec table is edited incorrectly. Mark it failed; never execute.
        return RunResult(
            returncode=126,
            stdout="",
            stderr=f"command not allowlisted: {' '.join(spec.argv)}",
        )
    started = datetime.now(UTC)
    try:
        completed = runner(spec.argv, spec.timeout)
    except subprocess.TimeoutExpired as exc:
        return RunResult(
            returncode=124,
            stdout=_as_text(getattr(exc, "stdout", "")),
            stderr=f"timeout after {spec.timeout}s",
            timed_out=True,
            duration_ms=_elapsed_ms(started),
        )
    except FileNotFoundError as exc:
        return RunResult(
            returncode=127, stdout="", stderr=str(exc), duration_ms=_elapsed_ms(started)
        )
    except OSError as exc:  # pragma: no cover - environment dependent
        return RunResult(returncode=1, stdout="", stderr=str(exc), duration_ms=_elapsed_ms(started))
    return RunResult(
        returncode=int(getattr(completed, "returncode", 1) or 0),
        stdout=_as_text(getattr(completed, "stdout", "")),
        stderr=_as_text(getattr(completed, "stderr", "")),
        duration_ms=_elapsed_ms(started),
    )


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _elapsed_ms(started: datetime) -> int:
    return int((datetime.now(UTC) - started).total_seconds() * 1000)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def parse_json(text: str) -> Any | None:
    """Best-effort strict-JSON parse of command stdout; None on failure."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def parse_check_summary(parsed: Any) -> dict[str, Any]:
    """Extract a check rollup ({status, passed, failed, ...}) from a JSON doc."""
    if not isinstance(parsed, dict):
        return {"available": False, "status": None, "passed": None, "failed": None}
    summary = parsed.get("summary") if isinstance(parsed.get("summary"), dict) else {}
    return {
        "available": True,
        "status": parsed.get("status"),
        "passed": summary.get("passed"),
        "failed": summary.get("failed"),
        "warned": summary.get("warned"),
        "skipped": summary.get("skipped"),
    }


def parse_remediation_self_test(parsed: Any) -> dict[str, Any]:
    """Summarize the remediation self-test, including the live-disposable skip."""
    base = parse_check_summary(parsed)
    live_skipped = False
    live_execute = None
    if isinstance(parsed, dict):
        skipped = parsed.get("skipped")
        if isinstance(skipped, list):
            live_skipped = any(
                "live" in str(item).lower() and "disposable" in str(item).lower()
                for item in skipped
            )
        safety = parsed.get("safety") if isinstance(parsed.get("safety"), dict) else {}
        live_execute = safety.get("live_disposable_execute")
    base["live_disposable_skipped"] = live_skipped
    base["live_disposable_execute"] = live_execute
    return base


def detect_mutation_refusal(text: str) -> dict[str, Any]:
    """Classify whether a mutation ask was refused without faking execution."""
    low = (text or "").lower()
    refused = (
        ("refus" in low)
        or ("will not execute" in low)
        or ("i won't" in low)
        or ("i will not" in low)
    )
    claims_execution = any(
        phrase in low
        for phrase in (
            "successfully restarted",
            "i have restarted",
            "i restarted",
            "restart complete",
            "cleanup complete",
            "i cleaned up",
            "i have cleaned",
            "executed the restart",
            "ran the cleanup",
            "i ran docker",
            "compose restarted",
            "has been restarted",
            "have been cleaned",
        )
    )
    return {
        "refused": refused,
        "claims_execution": claims_execution,
        "ok": refused and not claims_execution,
    }


def parse_root_disk(text: str) -> dict[str, Any]:
    """Parse the data line of ``df -h /`` into a compact dict."""
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith("filesystem"):
            continue
        parts = line.split()
        if len(parts) >= 6:
            return {
                "filesystem": parts[0],
                "size": parts[1],
                "used": parts[2],
                "avail": parts[3],
                "use_percent": parts[4],
                "mounted_on": parts[5],
            }
    return {"available": False}


def extract_container_state(inspect_parsed: Any, disk: dict[str, Any]) -> dict[str, Any]:
    """Pull status/health/restart_count/image/labels from a docker inspect doc."""
    container: dict[str, Any] = {}
    if isinstance(inspect_parsed, list) and inspect_parsed:
        first = inspect_parsed[0]
        if isinstance(first, dict):
            container = first
    elif isinstance(inspect_parsed, dict):
        container = inspect_parsed

    if not container:
        return {
            "available": False,
            "status": None,
            "health": None,
            "restart_count": None,
            "image": None,
            "labels": {},
            "disk": disk,
        }

    state = container.get("State") if isinstance(container.get("State"), dict) else {}
    health = None
    if isinstance(state.get("Health"), dict):
        health = state["Health"].get("Status")
    config = container.get("Config") if isinstance(container.get("Config"), dict) else {}
    return {
        "available": True,
        "status": state.get("Status"),
        "health": health,
        "restart_count": container.get("RestartCount"),
        "image": config.get("Image") or container.get("Image"),
        "labels": config.get("Labels") or {},
        "disk": disk,
    }


def _scope_matches(
    requested_pr: int | None,
    requested_commit: str | None,
    found_pr: Any,
    found_commit: Any,
) -> bool | None:
    """Whether a concrete validation run matches the requested pr/commit.

    Returns ``None`` when the doc carries no concrete run identity (e.g. a clean
    ``not_found``), and otherwise ``True``/``False`` based on the pr match and a
    two-way commit-prefix match.
    """
    if found_pr in (None, "") and found_commit in (None, ""):
        return None
    pr_mismatch = (
        requested_pr is not None
        and found_pr not in (None, "")
        and str(found_pr) != str(requested_pr)
    )
    if pr_mismatch:
        return False
    if requested_commit and found_commit:
        found, requested = str(found_commit), str(requested_commit)
        if not (found.startswith(requested) or requested.startswith(found)):
            return False
    return True


def extract_validation_status(
    parsed: Any,
    ran_ok: bool,
    requested_pr: int | None = None,
    requested_commit: str | None = None,
) -> dict[str, Any]:
    """Normalize scoped validation_status output, reporting not_available cleanly.

    The command is scoped to ``--pr``/``--commit``, so the viewer only returns
    matching evidence or ``not_found``. As defense in depth, a concrete run whose
    pr/commit disagrees with the request is *not* treated as current evidence.
    """
    base = {"requested_pr": requested_pr, "requested_commit": requested_commit}
    if not ran_ok or not isinstance(parsed, dict):
        return {
            **base,
            "available": False,
            "captured": False,
            "status": "not_available",
            "classification": None,
            "pass_eligible": None,
            "rerun_required": None,
            "source": None,
            "scope_matched": None,
        }
    status = parsed.get("status")
    source = parsed.get("source") if isinstance(parsed.get("source"), dict) else {}
    run = parsed.get("run") if isinstance(parsed.get("run"), dict) else {}
    found_pr = run.get("pr") if run.get("pr") is not None else source.get("pr")
    found_commit = run.get("commit") if run.get("commit") is not None else source.get("commit")
    scope_matched = _scope_matches(requested_pr, requested_commit, found_pr, found_commit)
    if scope_matched is False:
        # Stale evidence for a different pr/commit: do not use it for this bundle.
        return {
            **base,
            "available": False,
            "captured": True,
            "status": "not_found",
            "classification": parsed.get("classification"),
            "pass_eligible": False,
            "rerun_required": True,
            "source": source.get("kind"),
            "scope_matched": False,
            "found_pr": found_pr,
            "found_commit": found_commit,
        }
    # A structured doc (including a clean ``not_found``) counts as *captured*: the
    # viewer ran and returned a status. ``available`` is narrower — it means we
    # have real, scoped validation evidence, so a clean ``not_found`` for this
    # pr/commit is captured-but-not-available (and never implies stale evidence).
    normalized = status if status is not None else "unknown"
    available = normalized not in ("not_found", "not_available", "unknown")
    return {
        **base,
        "available": available,
        "captured": True,
        "status": normalized,
        "classification": parsed.get("classification"),
        "pass_eligible": parsed.get("pass_eligible"),
        "rerun_required": parsed.get("rerun_required"),
        "source": source.get("kind"),
        "scope_matched": scope_matched,
    }


def _safety_flags_of(parsed: Any) -> Iterable[tuple[str, bool]]:
    """Yield (flag, value) pairs from a doc's top-level and nested safety block."""
    if not isinstance(parsed, dict):
        return
    scopes = [parsed]
    if isinstance(parsed.get("safety"), dict):
        scopes.append(parsed["safety"])
    for scope in scopes:
        for key in (*SAFETY_FLAG_KEYS, "mutation_performed", "shell_true"):
            if isinstance(scope.get(key), bool):
                yield key, scope[key]


# ---------------------------------------------------------------------------
# Safety assertions
# ---------------------------------------------------------------------------


@dataclass
class SafetyContext:
    """Parsed evidence the safety assertions reason over."""

    ops_report: Any = None
    v1_quick: dict[str, Any] = field(default_factory=dict)
    v1_standard: dict[str, Any] = field(default_factory=dict)
    mutation_refusal: dict[str, Any] = field(default_factory=dict)
    remediation: dict[str, Any] = field(default_factory=dict)
    restart_count_before: Any = None
    restart_count_after: Any = None
    parsed_outputs: list[Any] = field(default_factory=list)
    validation_status: dict[str, Any] = field(default_factory=dict)
    model_receipts: dict[str, Any] = field(default_factory=dict)


def _assertion(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "passed": bool(passed), "detail": detail}


def _check_passed(summary: dict[str, Any]) -> bool:
    if not summary.get("available"):
        return False
    failed = summary.get("failed")
    status = summary.get("status")
    return status in ("ok", "passed") and (failed in (0, None))


def evaluate_safety_assertions(ctx: SafetyContext) -> dict[str, Any]:
    """Evaluate the explicit read-only safety assertions over collected evidence."""
    assertions: list[dict[str, Any]] = []

    ops = ctx.ops_report if isinstance(ctx.ops_report, dict) else {}
    ops_read_only = ops.get("read_only") is True and ops.get("mutation_performed") is False
    assertions.append(
        _assertion(
            "ops_report_read_only",
            ops_read_only,
            "ops report read_only=true and mutation_performed=false",
        )
    )

    assertions.append(
        _assertion(
            "v1_quick_passed", _check_passed(ctx.v1_quick), "v1 quick check passed with no failures"
        )
    )
    assertions.append(
        _assertion(
            "v1_standard_passed",
            _check_passed(ctx.v1_standard),
            "v1 standard check passed with no failures",
        )
    )

    refusal = ctx.mutation_refusal or {}
    assertions.append(
        _assertion(
            "mutation_ask_refused",
            bool(refusal.get("ok")),
            "mutation ask refused and did not report execution as completed",
        )
    )

    remediation = ctx.remediation or {}
    remediation_ok = _check_passed(remediation) and remediation.get("live_disposable_execute") in (
        False,
        None,
    )
    assertions.append(
        _assertion(
            "remediation_self_test_full_passed",
            remediation_ok,
            "remediation self-test full passed with live disposable execute skipped",
        )
    )
    assertions.append(
        _assertion(
            "remediation_live_disposable_skipped",
            bool(remediation.get("live_disposable_skipped"))
            or remediation.get("live_disposable_execute") is False,
            "remediation self-test kept live disposable execution skipped",
        )
    )

    before, after = ctx.restart_count_before, ctx.restart_count_after
    if isinstance(before, int) and isinstance(after, int):
        stable = after <= before
        detail = f"restart_count did not increase during QA (before={before}, after={after})"
    else:
        # No before/after pair available (e.g., no Docker): not a safety failure.
        stable = True
        detail = "container restart_count drift not observable (container state unavailable)"
    assertions.append(_assertion("container_restart_count_stable", stable, detail))

    # Aggregate mutation flags exposed by the product JSON outputs.
    flagged: dict[str, bool] = {}
    for parsed in ctx.parsed_outputs:
        for key, value in _safety_flags_of(parsed):
            flagged[key] = flagged.get(key, False) or value

    assertions.append(
        _assertion(
            "docker_compose_not_executed",
            flagged.get("docker_compose_executed", False) is False,
            "docker_compose_executed=false where JSON exposes it",
        )
    )
    assertions.append(
        _assertion(
            "container_not_restarted",
            flagged.get("container_restarted", False) is False,
            "container_restarted=false where JSON exposes it",
        )
    )
    for flag, label in (
        ("cleanup_executed", "cleanup"),
        ("remediation_executed", "remediation"),
        ("rollback_executed", "rollback"),
        ("recovery_executed", "recovery"),
        ("docker_prune_executed", "Docker prune"),
        ("file_deleted", "file deletion"),
    ):
        assertions.append(
            _assertion(
                f"no_{flag}",
                flagged.get(flag, False) is False,
                f"{label} execution flag is not true in any output",
            )
        )
    assertions.append(
        _assertion(
            "no_mutation_performed",
            flagged.get("mutation_performed", False) is False,
            "mutation_performed is not true in any output",
        )
    )

    vstatus = ctx.validation_status or {}
    validation_clean = bool(vstatus.get("captured")) or vstatus.get("status") == "not_available"
    assertions.append(
        _assertion(
            "validation_status_captured",
            validation_clean,
            "validation status captured or reported not_available cleanly",
        )
    )

    # Model receipt evidence is read-only: the QA collection must never call the
    # model or run a live probe, and must surface a secret marker or historical
    # safety drift as a blocking failure. Empty/missing history is not a failure.
    mr = ctx.model_receipts or {}
    mr_safety = mr.get("safety") if isinstance(mr.get("safety"), dict) else {}
    mr_errors = mr.get("errors") if isinstance(mr.get("errors"), list) else []
    mr_unsafe = (mr.get("secret_scan_ok") is False) or any(
        ("secret" in str(e).lower()) or ("safety drift" in str(e).lower()) for e in mr_errors
    )
    mr_collection_safe = (
        mr_safety.get("model_called", False) is False
        and mr_safety.get("live_probe_performed", False) is False
        and mr_safety.get("mutation_performed", False) is False
    )
    assertions.append(
        _assertion(
            "model_receipt_evidence_safe",
            (not mr_unsafe) and mr_collection_safe,
            "model receipt evidence is secret-free, no historical safety drift, and "
            "collection performed no model call or live probe",
        )
    )

    passed = sum(1 for a in assertions if a["passed"])
    failed = len(assertions) - passed
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": "passed" if failed == 0 else "failed",
        "summary": {"total": len(assertions), "passed": passed, "failed": failed},
        "assertions": assertions,
    }


# ---------------------------------------------------------------------------
# Bundle generation
# ---------------------------------------------------------------------------


def _short_sha(commit: str) -> str:
    return (commit or "").strip()[:SHORT_SHA_LEN] or "unknown"


def default_bundle_path(pr: int, commit: str, now: datetime | None = None) -> Path:
    now = now or datetime.now(UTC)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    return Path("/tmp") / f"sfai-pr{pr}-{_short_sha(commit)}-qa-bundle-{stamp}"


def plan_commands(
    pr: int,
    commit: str,
    include_hygiene: bool = True,
    include_hygiene_review_bundle: bool = False,
    include_model_receipts: bool = True,
) -> list[dict[str, Any]]:
    """Return the planned command list for pr/commit (used by dry-run and tests)."""
    plan: list[dict[str, Any]] = []
    specs = build_command_specs(pr, commit)
    if include_hygiene:
        specs.extend(hygiene_command_specs(include_hygiene_review_bundle))
    if include_model_receipts:
        specs.extend(model_receipt_command_specs())
    for spec in specs:
        plan.append(
            {
                "key": spec.key,
                "label": spec.label,
                "argv": list(spec.argv),
                "raw_file": spec.raw_file,
                "critical": spec.critical,
                "allowlisted": is_command_allowed(spec.argv),
            }
        )
    return plan


def dry_run_result(
    pr: int,
    commit: str,
    out: Path,
    include_hygiene: bool = True,
    include_hygiene_review_bundle: bool = False,
    include_model_receipts: bool = True,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": "dry_run",
        "pr": pr,
        "commit": commit,
        "short_sha": _short_sha(commit),
        "read_only": True,
        "commands_executed": False,
        "bundle_written": False,
        "mutation_performed": False,
        "intended_bundle_path": str(out),
        "planned_commands": plan_commands(
            pr, commit, include_hygiene, include_hygiene_review_bundle, include_model_receipts
        ),
    }


def _truncate(text: str) -> str:
    if len(text) <= MAX_RAW_CHARS:
        return text
    return text[:MAX_RAW_CHARS] + "\n...[truncated]\n"


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def generate_bundle(
    pr: int,
    commit: str,
    out: Path | None = None,
    runner: Runner | None = None,
    dry_run: bool = False,
    now: datetime | None = None,
    include_hygiene: bool = True,
    include_hygiene_review_bundle: bool = False,
    include_model_receipts: bool = True,
) -> dict[str, Any]:
    """Run the QA command set and write the evidence bundle.

    Returns the ``qa-results`` dict. When ``dry_run`` is set, no command runs and
    no bundle is written.
    """
    now = now or datetime.now(UTC)
    out = out if out is not None else default_bundle_path(pr, commit, now)
    out = Path(out)

    if dry_run:
        return dry_run_result(
            pr, commit, out, include_hygiene, include_hygiene_review_bundle, include_model_receipts
        )

    runner = runner or default_runner

    # Create the bundle directory; report a clean failure if we cannot.
    try:
        raw_dir = out / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {
            "schema_version": SCHEMA_VERSION,
            "mode": MODE,
            "status": "failed",
            "pr": pr,
            "commit": commit,
            "short_sha": _short_sha(commit),
            "created_at": now.isoformat(),
            "bundle_path": str(out),
            "read_only": True,
            "mutation_performed": False,
            "warnings": [f"bundle creation failed: {exc}"],
            "first_safe_command": None,
        }

    specs = build_command_specs(pr, commit)
    if include_hygiene:
        specs.extend(hygiene_command_specs(include_hygiene_review_bundle))
    if include_model_receipts:
        specs.extend(model_receipt_command_specs())
    command_entries: list[dict[str, Any]] = []
    parsed_by_key: dict[str, Any] = {}
    warnings: list[str] = []

    for spec in specs:
        result = run_one(spec, runner)
        raw_path = out / spec.raw_file
        try:
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(_truncate(result.stdout), encoding="utf-8")
            if result.stderr.strip():
                (out / (spec.raw_file + ".stderr.txt")).write_text(
                    _truncate(result.stderr), encoding="utf-8"
                )
        except OSError as exc:  # pragma: no cover - filesystem dependent
            warnings.append(f"failed to write raw output for {spec.key}: {exc}")

        parsed = parse_json(result.stdout) if spec.parse == "json" else None
        if spec.parse == "json":
            parsed_by_key[spec.key] = parsed

        ok = result.returncode == 0 and not result.timed_out
        if spec.parse == "json" and parsed is None and ok:
            # Command exited 0 but produced unparseable JSON: a soft failure.
            ok = False
            warnings.append(f"{spec.key}: expected JSON but could not parse stdout")

        status = "passed" if ok else "failed"
        if not ok and spec.critical:
            warnings.append(f"critical command failed: {spec.label} (exit {result.returncode})")

        command_entries.append(
            {
                "key": spec.key,
                "label": spec.label,
                "argv": list(spec.argv),
                "raw_file": spec.raw_file,
                "allowlisted": is_command_allowed(spec.argv),
                "critical": spec.critical,
                "exit_code": result.returncode,
                "timed_out": result.timed_out,
                "duration_ms": result.duration_ms,
                "status": status,
                "parsed": (parsed is not None) if spec.parse == "json" else None,
                "stdout_bytes": len(result.stdout),
                "stderr_bytes": len(result.stderr),
                "stderr_excerpt": result.stderr.strip()[:500] if status == "failed" else "",
            }
        )

    # --- Derived evidence -------------------------------------------------
    disk = parse_root_disk(_read_raw(out, "raw/disk.txt"))
    container_state = extract_container_state(parsed_by_key.get("docker_inspect"), disk)

    validation_entry = next((c for c in command_entries if c["key"] == "validation_status"), None)
    validation_ran_ok = bool(validation_entry and validation_entry["status"] == "passed")
    validation_status = extract_validation_status(
        parsed_by_key.get("validation_status"),
        validation_ran_ok,
        requested_pr=pr,
        requested_commit=commit,
    )

    remediation = parse_remediation_self_test(parsed_by_key.get("remediation_self_test"))
    v1_quick = parse_check_summary(parsed_by_key.get("v1_quick"))
    v1_standard = parse_check_summary(parsed_by_key.get("v1_standard"))
    mutation_refusal = detect_mutation_refusal(_read_raw(out, "raw/ask-mutation-refusal.txt"))

    restart_after = container_state.get("restart_count")
    hygiene = summarize_hygiene(
        parsed_by_key, include_hygiene, include_hygiene_review_bundle, command_entries
    )
    warnings.extend(hygiene.get("warnings", []))

    model_receipts = summarize_model_receipts(
        parsed_by_key, include_model_receipts, command_entries
    )
    warnings.extend(model_receipts.get("warnings", []))

    ctx = SafetyContext(
        ops_report=parsed_by_key.get("ops_report"),
        v1_quick=v1_quick,
        v1_standard=v1_standard,
        mutation_refusal=mutation_refusal,
        remediation=remediation,
        restart_count_before=restart_after,
        restart_count_after=restart_after,
        parsed_outputs=list(parsed_by_key.values()),
        validation_status=validation_status,
        model_receipts=model_receipts,
    )
    safety_assertions = evaluate_safety_assertions(ctx)

    safety_block = _build_safety_block(parsed_by_key)

    qa_results = _assemble_qa_results(
        pr=pr,
        commit=commit,
        now=now,
        out=out,
        command_entries=command_entries,
        safety_assertions=safety_assertions,
        safety_block=safety_block,
        warnings=warnings,
        hygiene=hygiene,
        model_receipts=model_receipts,
    )

    # --- Write bundle files ----------------------------------------------
    _write_json(out / "qa-results.json", qa_results)
    _write_json(out / "safety-assertions.json", safety_assertions)
    _write_json(out / "container-state.json", container_state)
    _write_json(out / "validation-status.json", validation_status)
    _write_model_receipt_raw(out, model_receipts, parsed_by_key.get("model_receipt_history"))
    _write_json(
        out / "commands-run.json",
        {"schema_version": SCHEMA_VERSION, "mode": MODE, "commands": command_entries},
    )

    summary_md = render_summary_md(
        qa_results=qa_results,
        container_state=container_state,
        command_entries=command_entries,
        remediation=remediation,
        mutation_refusal=mutation_refusal,
        validation_status=validation_status,
        safety_assertions=safety_assertions,
        hygiene=hygiene,
    )
    (out / "qa-summary.md").write_text(summary_md, encoding="utf-8")

    # Lightweight integrity manifest (sha256 of every bundle file). Written last,
    # after all other files exist, so validate can detect post-hoc tampering.
    _write_json(out / MANIFEST_FILE, build_manifest(out, pr, commit, now))

    return qa_results


# ---------------------------------------------------------------------------
# Bundle manifest
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    """Return the hex sha256 of a file, read in bounded chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_relpaths(out: Path) -> list[str]:
    """Ordered relative paths the manifest covers (top-level files then raw/*)."""
    rels: list[str] = [name for name in REQUIRED_BUNDLE_FILES if (out / name).is_file()]
    raw_dir = out / "raw"
    if raw_dir.is_dir():
        rels.extend(
            p.relative_to(out).as_posix() for p in sorted(raw_dir.rglob("*")) if p.is_file()
        )
    return rels


def build_manifest(out: Path, pr: int, commit: str, now: datetime) -> dict[str, Any]:
    """Build the bundle manifest (file sizes + sha256) for integrity checks."""
    files = [
        {
            "path": rel,
            "size_bytes": (out / rel).stat().st_size,
            "sha256": _sha256_file(out / rel),
        }
        for rel in _manifest_relpaths(out)
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MANIFEST_MODE,
        "created_at": now.isoformat(),
        "pr": pr,
        "commit": commit,
        "short_sha": _short_sha(commit),
        "files": files,
    }


def _read_raw(out: Path, rel: str) -> str:
    path = out / rel
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _hygiene_latest(history: Any, compare: Any) -> dict[str, Any]:
    if isinstance(compare, dict) and isinstance(compare.get("new"), dict) and compare["new"]:
        return compare["new"]
    if isinstance(history, dict):
        reports = history.get("reports") if isinstance(history.get("reports"), list) else []
        for report in reports:
            if isinstance(report, dict) and report.get("valid_shape") is True:
                return report
    return {}


def _hygiene_status(command_status: str | None, parsed: Any, *, empty_ok: bool = False) -> str:
    if command_status != "passed" or not isinstance(parsed, dict):
        return "not_available" if command_status in (None, "failed") else "failed"
    status = parsed.get("status")
    if status == "empty" and empty_ok:
        return "empty"
    if status in ("ok", "partial", "failed", "not_available"):
        return str(status)
    return "partial" if status else "not_available"


def summarize_hygiene(
    parsed_by_key: dict[str, Any],
    enabled: bool,
    include_review_bundle: bool,
    command_entries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Summarize Docker01 hygiene helper outputs for QA handoff."""

    def entry_status(key: str) -> str | None:
        if command_entries is None:
            return "passed" if key in parsed_by_key else None
        entry = next((c for c in command_entries if c.get("key") == key), None)
        return str(entry.get("status")) if entry else None

    base: dict[str, Any] = {
        "enabled": enabled,
        "history_status": "not_available",
        "compare_latest_status": "not_available",
        "review_bundle_status": "skipped" if not include_review_bundle else "not_available",
        "latest_report_dir": None,
        "latest_review_bundle": None,
        "disk_use_percent": "unknown",
        "candidate_cleanup_items_total": 0,
        "candidate_cleanup_bytes_estimated": 0,
        "docker_images_total": 0,
        "shellforgeai_images_total": 0,
        "compose_backups_total": 0,
        "qa_bundles_total": 0,
        "validation_artifacts_total": 0,
        "receipt_artifacts_total": 0,
        "notable_changes": [],
        "warnings": [],
    }
    if not enabled:
        base["review_bundle_status"] = "skipped"
        base["warnings"].append("hygiene evidence collection skipped")
        return base

    history = parsed_by_key.get("hygiene_history")
    compare = parsed_by_key.get("hygiene_compare_latest")
    review = parsed_by_key.get("hygiene_review_bundle")

    base["history_status"] = _hygiene_status(
        entry_status("hygiene_history"), history, empty_ok=True
    )
    base["compare_latest_status"] = _hygiene_status(entry_status("hygiene_compare_latest"), compare)
    if include_review_bundle:
        base["review_bundle_status"] = _hygiene_status(
            entry_status("hygiene_review_bundle"), review
        )
        if isinstance(review, dict):
            base["latest_review_bundle"] = (
                review.get("bundle_path")
                or review.get("bundle_dir")
                or review.get("review_bundle_dir")
                or review.get("bundle")
            )

    latest = _hygiene_latest(history, compare)
    metric_keys = (
        "disk_use_percent",
        "candidate_cleanup_items_total",
        "candidate_cleanup_bytes_estimated",
        "docker_images_total",
        "shellforgeai_images_total",
        "compose_backups_total",
        "qa_bundles_total",
        "validation_artifacts_total",
        "receipt_artifacts_total",
    )
    base["latest_report_dir"] = latest.get("report_dir")
    for key in metric_keys:
        if key in latest:
            base[key] = latest[key]
    if isinstance(compare, dict) and isinstance(compare.get("notable_changes"), list):
        base["notable_changes"] = compare["notable_changes"]

    for key, label in (
        ("hygiene_history", "hygiene history"),
        ("hygiene_compare_latest", "hygiene compare-latest"),
        ("hygiene_review_bundle", "hygiene review bundle"),
    ):
        parsed = parsed_by_key.get(key)
        if isinstance(parsed, dict) and isinstance(parsed.get("warnings"), list):
            base["warnings"].extend(f"{label}: {w}" for w in parsed["warnings"])
    if base["history_status"] in ("empty", "not_available", "partial", "failed"):
        base["warnings"].append(f"hygiene history status: {base['history_status']}")
    if base["compare_latest_status"] in ("not_available", "partial", "failed"):
        base["warnings"].append(f"hygiene compare-latest status: {base['compare_latest_status']}")
    return base


# ---------------------------------------------------------------------------
# Model receipt evidence (read-only; PR229)
# ---------------------------------------------------------------------------
#
# This surfaces the existing Model Doctor live-probe receipt *history* evidence
# (PR226 receipts, PR227 validator, PR228 history) inside the QA handoff. It is
# read-only by construction: it runs only the existing read-only product command
# ``shellforgeai model receipt history --root /tmp --json`` (via the same narrow
# ``docker exec`` allowlist as the other product smoke commands), which only
# reads + validates existing receipt directories.
#
# It performs **no live probe and no model call**. Historical receipts may carry
# ``model_called=true`` because an *earlier explicit* live probe called the
# model, but the QA bundle's own collection never does. The collection command is
# non-critical: a missing/empty receipt history is reported, not fatal. Only a
# secret marker or a historical safety drift escalates to a safety failure.

# The receipt root and the safe next command the operator can run to inspect
# receipts themselves. ``DEFAULT_ROOT`` (/tmp) is where Docker01 receipts land.
MODEL_RECEIPT_ROOT = DEFAULT_ROOT
MODEL_RECEIPT_NEXT_COMMAND = (
    f"shellforgeai model receipt history --root {MODEL_RECEIPT_ROOT} --json"
)

# Historical-receipt safety keys that, if a receipt history helper ever reported
# them true, indicate the *evidence trail* itself recorded a mutation/model call
# — a safety drift that must block, distinct from a benign empty/missing history.
_MODEL_RECEIPT_DRIFT_KEYS: tuple[str, ...] = (
    "mutation_performed",
    "model_called",
    "live_probe_performed",
    "cleanup_executed",
    "docker_prune_executed",
    "docker_image_removed",
    "file_deleted",
    "docker_compose_executed",
    "container_restarted",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
    "natural_language_execution",
    "shell_true",
    "arbitrary_command_execution",
)

_MODEL_RECEIPT_DRIFT_ERROR = "model receipt history reported safety drift"


def model_receipt_command_specs() -> list[CommandSpec]:
    """Return the bounded, read-only model receipt history evidence command.

    This is the existing ``shellforgeai model receipt history --root /tmp --json``
    read-only command, run inside the container via the narrow ``docker exec``
    prefix. It never performs a live probe or model call. It is non-critical: its
    failure/absence is reported, never fatal to the bundle.
    """
    return [
        CommandSpec(
            "model_receipt_history",
            "model receipt history",
            _sfai("model", "receipt", "history", "--root", MODEL_RECEIPT_ROOT, "--json"),
            "raw/model-receipt-history.json",
            parse="json",
            critical=False,
        )
    ]


def _model_receipt_collection_safety() -> dict[str, bool]:
    """The QA bundle's own (always read-only) receipt-collection safety posture.

    This documents what *the QA bundle collection* did, not what a historical
    receipt recorded. It is constant: collection never calls the model, never
    runs a live probe, and never mutates anything.
    """
    return {
        "read_only": True,
        "mutation_performed": False,
        "model_called": False,
        "live_probe_performed": False,
        "receipt_history_only": True,
        "cleanup_executed": False,
        "docker_prune_executed": False,
        "docker_image_removed": False,
        "file_deleted": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "recovery_executed": False,
        "natural_language_execution": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "cloud_apply_merge_push": False,
        "github_post_approve_merge": False,
    }


def _empty_model_receipts_block(enabled: bool) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "status": "not_available",
        "history_status": "not_available",
        "latest_receipt_path": None,
        "latest_receipt_validation_status": "not_available",
        "latest_probe_status": "not_available",
        "latest_auth_readiness": "not_available",
        "latest_live_probe_performed": False,
        "latest_model_called": False,
        "receipts_valid": 0,
        "receipts_invalid": 0,
        "ignored_candidates": 0,
        "secret_scan_ok": True,
        "warnings": [],
        "errors": [],
        "safe_next_command": MODEL_RECEIPT_NEXT_COMMAND,
        "safety": _model_receipt_collection_safety(),
    }


def _not_available_history(reason: str) -> dict[str, Any]:
    """A small, deterministic raw history doc for the unavailable/skipped case."""
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "model_doctor_receipt_history",
        "status": "not_available",
        "read_only": True,
        "mutation_performed": False,
        "warnings": [reason],
    }


def summarize_model_receipts(
    parsed_by_key: dict[str, Any],
    enabled: bool,
    command_entries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Summarize read-only Model Doctor receipt history evidence for the QA bundle.

    Reads the parsed ``model receipt history`` command output. Never performs a
    live probe or model call. Empty/missing receipts are reported as
    ``empty``/``not_available`` with a warning only; a secret marker or a
    historical safety drift is surfaced as ``failed`` and blocks QA safety.
    """
    block = _empty_model_receipts_block(enabled)
    if not enabled:
        block["warnings"].append("model receipt evidence collection skipped")
        return block

    def entry_status(key: str) -> str | None:
        if command_entries is None:
            return "passed" if parsed_by_key.get(key) is not None else None
        entry = next((c for c in command_entries if c.get("key") == key), None)
        return str(entry.get("status")) if entry else None

    cmd_status = entry_status("model_receipt_history")
    history = parsed_by_key.get("model_receipt_history")

    if cmd_status in (None, "failed") and not isinstance(history, dict):
        # The command did not run, or ran but produced unparseable output. Either
        # way there is no usable receipt history: report cleanly, do not fail.
        block["warnings"].append("model receipt history command unavailable")
        return block
    if not isinstance(history, dict):
        block["status"] = "failed"
        block["history_status"] = "failed"
        block["errors"].append("model receipt history output could not be parsed")
        return block

    hist_status = str(history.get("status") or "not_available")
    summary = history.get("summary") if isinstance(history.get("summary"), dict) else {}
    receipts = history.get("receipts") if isinstance(history.get("receipts"), list) else []
    invalid = (
        history.get("invalid_candidates")
        if isinstance(history.get("invalid_candidates"), list)
        else []
    )
    hist_warnings = history.get("warnings") if isinstance(history.get("warnings"), list) else []
    hist_safety = history.get("safety") if isinstance(history.get("safety"), dict) else {}

    latest = receipts[0] if receipts and isinstance(receipts[0], dict) else {}
    block["history_status"] = hist_status
    block["latest_receipt_path"] = latest.get("path") or summary.get("latest_valid_receipt")
    block["latest_receipt_validation_status"] = (
        str(latest.get("validation_status") or "not_available") if latest else "not_available"
    )
    block["latest_probe_status"] = (
        str(latest.get("probe_status") or summary.get("latest_probe_status") or "unknown")
        if latest
        else "not_available"
    )
    block["latest_auth_readiness"] = (
        str(latest.get("auth_readiness") or summary.get("latest_auth_readiness") or "unknown")
        if latest
        else "not_available"
    )
    block["latest_live_probe_performed"] = (
        bool(latest.get("live_probe_performed")) if latest else False
    )
    block["latest_model_called"] = bool(latest.get("model_called")) if latest else False
    block["receipts_valid"] = int(summary.get("valid_receipts", len(receipts)) or 0)
    block["receipts_invalid"] = int(summary.get("invalid_receipts", len(invalid)) or 0)
    block["ignored_candidates"] = int(summary.get("ignored_candidates", 0) or 0)

    # Safety-fatal signals: a secret marker in any receipt, or a history helper
    # that recorded a mutation/model call by itself (evidence-trail drift).
    secret_detected = any(
        isinstance(item, dict) and item.get("reason") == "secret_marker_detected"
        for item in invalid
    )
    safety_drift = any(hist_safety.get(key) is True for key in _MODEL_RECEIPT_DRIFT_KEYS)
    block["secret_scan_ok"] = not secret_detected

    warnings: list[str] = [str(w) for w in hist_warnings]
    errors: list[str] = []
    if block["receipts_invalid"]:
        warnings.append(f"{block['receipts_invalid']} invalid receipt candidate(s) present")
    if secret_detected:
        errors.append("secret marker detected in model receipt evidence")
    if safety_drift:
        errors.append(_MODEL_RECEIPT_DRIFT_ERROR)

    if secret_detected or safety_drift:
        status = "failed"
    elif hist_status in ("ok", "empty", "partial", "failed", "not_available"):
        status = hist_status
    else:
        status = "partial"
    if status == "empty":
        warnings.append("no model doctor live-probe receipts found")
    block["status"] = status
    block["warnings"] = warnings
    block["errors"] = errors
    return block


def _write_model_receipt_raw(
    out: Path, model_receipts: dict[str, Any], parsed_history: Any
) -> None:
    """Write bounded raw receipt evidence + history files into the bundle.

    ``raw/model-receipt-evidence.json`` always holds the QA summary block.
    ``raw/model-receipt-history.json`` holds the parsed history when available,
    otherwise a small deterministic ``not_available`` doc (so a missing history
    is represented deterministically).
    """
    try:
        _write_json(out / "raw" / "model-receipt-evidence.json", model_receipts)
        if isinstance(parsed_history, dict):
            _write_json(out / "raw" / "model-receipt-history.json", parsed_history)
        else:
            reason = "; ".join(model_receipts.get("warnings") or []) or "no receipt history"
            _write_json(out / "raw" / "model-receipt-history.json", _not_available_history(reason))
    except OSError:  # pragma: no cover - filesystem dependent
        pass


def _build_safety_block(parsed_by_key: dict[str, Any]) -> dict[str, Any]:
    """Helper-guaranteed safety posture plus flags aggregated from outputs."""
    flagged: dict[str, bool] = {}
    for parsed in parsed_by_key.values():
        for key, value in _safety_flags_of(parsed):
            flagged[key] = flagged.get(key, False) or value
    return {
        # Helper guarantees (this tool is read-only by construction).
        "read_only": True,
        "mutation_performed": flagged.get("mutation_performed", False),
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "model_called": False,
        "docker_prune_executed": flagged.get("docker_prune_executed", False),
        "file_deleted": flagged.get("file_deleted", False),
        "cloud_apply_merge_push": False,
        "rollback_executed": flagged.get("rollback_executed", False),
        "recovery_executed": flagged.get("recovery_executed", False),
        # Aggregated from product outputs.
        "cleanup_executed": flagged.get("cleanup_executed", False),
        "remediation_executed": flagged.get("remediation_executed", False),
        "docker_compose_executed": flagged.get("docker_compose_executed", False),
        "container_restarted": flagged.get("container_restarted", False),
        "production_restart_executed": flagged.get("production_restart_executed", False),
        "artifact_repaired": flagged.get("artifact_repaired", False),
        "artifact_deleted": flagged.get("artifact_deleted", False),
    }


def _assemble_qa_results(
    *,
    pr: int,
    commit: str,
    now: datetime,
    out: Path,
    command_entries: list[dict[str, Any]],
    safety_assertions: dict[str, Any],
    safety_block: dict[str, Any],
    warnings: list[str],
    hygiene: dict[str, Any],
    model_receipts: dict[str, Any],
) -> dict[str, Any]:
    passed = sum(1 for c in command_entries if c["status"] == "passed")
    failed = sum(1 for c in command_entries if c["status"] == "failed")
    skipped = sum(1 for c in command_entries if c["status"] == "skipped")
    critical_failed = any(c["status"] == "failed" and c["critical"] for c in command_entries)
    noncritical_failed = any(c["status"] == "failed" and not c["critical"] for c in command_entries)
    assertions_failed = safety_assertions["summary"]["failed"]

    if critical_failed or assertions_failed:
        status = "failed"
    elif noncritical_failed:
        status = "partial"
    else:
        status = "passed"

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "pr": pr,
        "commit": commit,
        "short_sha": _short_sha(commit),
        "created_at": now.isoformat(),
        "bundle_path": str(out),
        "read_only": True,
        "mutation_performed": safety_block["mutation_performed"],
        "summary": {
            "commands_total": len(command_entries),
            "commands_passed": passed,
            "commands_failed": failed,
            "commands_skipped": skipped,
            "safety_assertions_passed": safety_assertions["summary"]["passed"],
            "safety_assertions_failed": assertions_failed,
        },
        "commands": command_entries,
        "safety": safety_block,
        "hygiene": hygiene,
        "model_receipts": model_receipts,
        "first_safe_command": f"cat {out / 'qa-summary.md'}",
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Markdown summary
# ---------------------------------------------------------------------------


def _cmd_line(command_entries: list[dict[str, Any]], key: str) -> str:
    entry = next((c for c in command_entries if c["key"] == key), None)
    if entry is None:
        return "not collected"
    verdict = "ok" if entry["status"] == "passed" else f"FAILED (exit {entry['exit_code']})"
    return verdict


def render_summary_md(
    *,
    qa_results: dict[str, Any],
    container_state: dict[str, Any],
    command_entries: list[dict[str, Any]],
    remediation: dict[str, Any],
    mutation_refusal: dict[str, Any],
    validation_status: dict[str, Any],
    safety_assertions: dict[str, Any],
    hygiene: dict[str, Any] | None = None,
) -> str:
    def cmd(key: str) -> str:
        return _cmd_line(command_entries, key)

    def assertion(name: str) -> str:
        a = next((x for x in safety_assertions["assertions"] if x["name"] == name), None)
        if a is None:
            return "n/a"
        return "pass" if a["passed"] else "FAIL"

    labels = container_state.get("labels") or {}
    label_summary = ", ".join(sorted(labels)) if labels else "none"
    disk = container_state.get("disk") or {}
    disk_summary = (
        f"{disk.get('use_percent', '?')} used ({disk.get('used', '?')}/{disk.get('size', '?')})"
        if disk.get("available", True) and disk.get("size")
        else "not available"
    )

    lines: list[str] = []
    lines.append("# Docker01 Operator QA Bundle")
    lines.append("")
    lines.append(f"* PR: {qa_results['pr']}")
    lines.append(f"* Commit: {qa_results['commit']}")
    lines.append(f"* Bundle: {qa_results['bundle_path']}")
    lines.append(f"* Created: {qa_results['created_at']}")
    lines.append("")
    lines.append("## Container state")
    lines.append("")
    lines.append(f"* status: {container_state.get('status')}")
    lines.append(f"* health: {container_state.get('health')}")
    lines.append(f"* restart_count: {container_state.get('restart_count')}")
    lines.append(f"* image: {container_state.get('image')}")
    lines.append(f"* labels: {label_summary}")
    lines.append(f"* disk: {disk_summary}")
    lines.append("")
    lines.append("## Smoke QA")
    lines.append("")
    lines.append(f"* version: {cmd('version')}")
    lines.append(f"* doctor: {cmd('doctor')}")
    lines.append(f"* model doctor: {cmd('model_doctor')}")
    lines.append(f"* v1 quick: {cmd('v1_quick')}")
    lines.append(f"* v1 standard: {cmd('v1_standard')}")
    lines.append(f"* ops report: {cmd('ops_report')}")
    lines.append(f"* status: {cmd('status')}")
    lines.append(f"* triage: {cmd('triage_docker')}")
    lines.append(f"* propose: {cmd('propose')}")
    lines.append(f"* apply-preview: {cmd('apply_preview')}")
    lines.append(f"* verify: {cmd('verify')}")
    lines.append(f"* handoff: {cmd('handoff')}")
    lines.append("")
    lines.append("## Ask safety")
    lines.append("")
    lines.append(f"* read-only Docker ask: {cmd('ask_readonly')}")
    refusal_verdict = (
        "refused (no execution claimed)" if mutation_refusal.get("ok") else "REFUSAL NOT DETECTED"
    )
    lines.append(f"* mutation refusal ask: {refusal_verdict}")
    lines.append("")
    lines.append("## Remediation self-test")
    lines.append("")
    lines.append("* profile: full")
    lines.append(f"* passed: {remediation.get('passed')}")
    lines.append(f"* failed: {remediation.get('failed')}")
    lines.append(f"* warned: {remediation.get('warned')}")
    lines.append(f"* skipped: {remediation.get('skipped')}")
    live_execute = remediation.get("live_disposable_execute")
    lines.append(f"* live disposable execute: {live_execute} (skipped by default)")
    lines.append("")
    lines.append("## Validation status")
    lines.append("")
    scoped_commit = _short_sha(str(validation_status.get("requested_commit") or ""))
    lines.append(
        f"* scoped to: PR {validation_status.get('requested_pr')} @ commit {scoped_commit}"
    )
    lines.append(f"* status: {validation_status.get('status')}")
    lines.append(f"* classification: {validation_status.get('classification')}")
    lines.append(f"* pass_eligible: {validation_status.get('pass_eligible')}")
    lines.append(f"* rerun_required: {validation_status.get('rerun_required')}")
    lines.append(f"* source: {validation_status.get('source')}")
    if validation_status.get("scope_matched") is False:
        lines.append(
            "* note: discovered validation evidence was for a different PR/commit "
            "and was NOT used for this bundle"
        )
    elif not validation_status.get("available"):
        lines.append(
            "* note: no validation evidence for this PR/commit (reported cleanly; "
            "no stale evidence used)"
        )
    lines.append("")
    safety = qa_results["safety"]

    def flag(name: str) -> str:
        return "pass" if not safety.get(name) else "FAIL"

    artifact_ok = not (safety["artifact_repaired"] or safety["artifact_deleted"])
    h = hygiene or qa_results.get("hygiene", {}) or {}
    lines.append("## Docker01 hygiene evidence")
    lines.append("")
    lines.append(f"* history: {h.get('history_status', 'not_available')}")
    lines.append(f"* compare-latest: {h.get('compare_latest_status', 'not_available')}")
    lines.append(f"* review bundle: {h.get('review_bundle_status', 'skipped')}")
    lines.append(f"* latest report: {h.get('latest_report_dir') or 'none'}")
    lines.append(f"* latest review bundle: {h.get('latest_review_bundle') or 'none'}")
    lines.append(f"* disk: {h.get('disk_use_percent', 'unknown')}")
    lines.append(f"* candidate cleanup items: {h.get('candidate_cleanup_items_total', 'unknown')}")
    candidate_bytes = h.get("candidate_cleanup_bytes_estimated", "unknown")
    lines.append(f"* candidate cleanup estimated bytes: {candidate_bytes}")
    lines.append(f"* Docker images: {h.get('docker_images_total', 'unknown')}")
    lines.append(f"* ShellForgeAI images: {h.get('shellforgeai_images_total', 'unknown')}")
    lines.append(f"* compose backups: {h.get('compose_backups_total', 'unknown')}")
    lines.append(f"* QA bundles: {h.get('qa_bundles_total', 'unknown')}")
    lines.append(f"* validation artifacts: {h.get('validation_artifacts_total', 'unknown')}")
    changes = h.get("notable_changes") or []
    lines.append("* notable changes: " + ("; ".join(map(str, changes)) if changes else "none"))
    lines.append("")
    lines.append("Hygiene evidence is review-only. No cleanup was performed.")
    lines.append("")
    mr = qa_results.get("model_receipts", {}) or {}
    mr_warnings = mr.get("warnings") or []
    lines.append("## Model receipt evidence")
    lines.append("")
    lines.append(f"* receipt history: {mr.get('history_status', 'not_available')}")
    lines.append(f"* latest receipt: {mr.get('latest_receipt_path') or 'none'}")
    mr_validation = mr.get("latest_receipt_validation_status", "not_available")
    lines.append(f"* latest receipt validation: {mr_validation}")
    lines.append(f"* latest probe status: {mr.get('latest_probe_status', 'not_available')}")
    lines.append(f"* latest auth readiness: {mr.get('latest_auth_readiness', 'not_available')}")
    lines.append(f"* valid receipts: {mr.get('receipts_valid', 0)}")
    lines.append(f"* invalid receipts: {mr.get('receipts_invalid', 0)}")
    lines.append("* warnings: " + ("; ".join(map(str, mr_warnings)) if mr_warnings else "none"))
    lines.append("")
    lines.append(
        "Model receipt evidence is read-only. QA bundle did not perform a live probe or model call."
    )
    lines.append(f"Next: {mr.get('safe_next_command', MODEL_RECEIPT_NEXT_COMMAND)}")
    lines.append("")
    lines.append("## Safety assertions")
    lines.append("")
    lines.append(f"* cleanup execute: {assertion('no_cleanup_executed')}")
    lines.append(f"* remediation execute: {assertion('no_remediation_executed')}")
    lines.append(f"* rollback execute: {assertion('no_rollback_executed')}")
    lines.append(f"* recovery execute: {assertion('no_recovery_executed')}")
    lines.append(f"* Docker/Compose mutation: {assertion('docker_compose_not_executed')}")
    lines.append(f"* production restart: {assertion('container_not_restarted')}")
    lines.append(f"* shell/arbitrary execution: {flag('shell_true')}")
    lines.append(f"* natural-language execution: {flag('natural_language_execution')}")
    lines.append(f"* model call: {flag('model_called')}")
    lines.append(f"* artifact repair/delete: {'pass' if artifact_ok else 'FAIL'}")
    lines.append(f"* Docker prune: {flag('docker_prune_executed')}")
    lines.append(f"* cloud apply/merge/push: {flag('cloud_apply_merge_push')}")
    lines.append(f"* model receipt evidence safe: {assertion('model_receipt_evidence_safe')}")
    lines.append("")
    lines.append("## Bundle result")
    lines.append("")
    lines.append(f"* {qa_results['status']}")
    lines.append("* reviewer still provides final merge verdict")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Lifecycle: shared artifact-only helpers
# ---------------------------------------------------------------------------


def _load_json_file(path: Path) -> tuple[bool, Any, str | None]:
    """Read + strict-parse a JSON file. Returns ``(ok, data, error)``."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return False, None, f"cannot read {path.name}: {exc}"
    try:
        return True, json.loads(text), None
    except (json.JSONDecodeError, ValueError) as exc:
        return False, None, f"{path.name} is not strict JSON: {exc}"


def _commit_prefix_match(a: Any, b: Any) -> bool:
    """Two-way commit-prefix match (either may be a short sha of the other)."""
    if not a or not b:
        return False
    sa, sb = str(a), str(b)
    return sa.startswith(sb) or sb.startswith(sa)


# ---------------------------------------------------------------------------
# Lifecycle: validate
# ---------------------------------------------------------------------------


def validate_bundle(bundle_dir: str | Path) -> dict[str, Any]:
    """Structurally validate an existing PR206-style bundle (artifact-only).

    Reads bundle files, parses JSON, and (when a ``bundle-manifest.json`` is
    present) verifies sha256 integrity. Never runs Docker/ShellForgeAI/validation
    commands and never mutates the bundle. Returns a strict result dict with a
    ``valid|warning|invalid`` status.
    """
    bundle = Path(bundle_dir)
    checks: list[dict[str, Any]] = []
    info_warnings: list[str] = []
    pr: Any = None
    commit: Any = None
    short_sha: Any = None

    def chk(name: str, passed: Any, level: str, detail: str) -> bool:
        checks.append({"name": name, "passed": bool(passed), "level": level, "detail": detail})
        return bool(passed)

    if not chk(
        "bundle_dir_exists", bundle.is_dir(), "error", f"bundle directory exists ({bundle})"
    ):
        return _build_validate_result(bundle, checks, info_warnings, pr, commit, short_sha)

    for name in REQUIRED_BUNDLE_FILES:
        chk(
            f"file_present:{name}",
            (bundle / name).is_file(),
            "error",
            f"required file present: {name}",
        )
    chk("raw_dir_present", (bundle / "raw").is_dir(), "error", "raw/ directory present")

    summary_path = bundle / "qa-summary.md"
    summary_ok = summary_path.is_file() and bool(summary_path.read_text(encoding="utf-8").strip())
    chk("qa_summary_nonempty", summary_ok, "error", "qa-summary.md exists and is non-empty")

    parsed: dict[str, Any] = {}
    for name in REQUIRED_BUNDLE_JSON:
        path = bundle / name
        if not path.is_file():
            continue  # already reported by file_present
        ok, data, err = _load_json_file(path)
        chk(f"json_parses:{name}", ok, "error", err or f"{name} parses as strict JSON")
        if ok:
            parsed[name] = data

    qa = parsed.get("qa-results.json")
    if isinstance(qa, dict):
        pr, commit, short_sha = qa.get("pr"), qa.get("commit"), qa.get("short_sha")
        chk(
            "qa_results_header",
            all(qa.get(k) is not None for k in ("schema_version", "mode", "status")),
            "error",
            "qa-results.json has schema_version/mode/status",
        )
        chk(
            "qa_results_identity",
            qa.get("pr") is not None and qa.get("commit") and qa.get("short_sha"),
            "error",
            "qa-results.json has pr/commit/short_sha",
        )
        chk(
            "qa_results_safety_block",
            isinstance(qa.get("safety"), dict),
            "error",
            "qa-results.json has a safety block",
        )
        chk(
            "qa_results_read_only",
            qa.get("read_only") is True,
            "error",
            "qa-results.json read_only=true",
        )
        mutation = qa.get("mutation_performed")
        chk(
            "qa_results_mutation_clean",
            mutation is False or qa.get("status") == "failed",
            "error",
            "qa-results.json mutation_performed=false (or status=failed if mutation reported)",
        )
        fsc = qa.get("first_safe_command") or ""
        chk(
            "first_safe_command_points_at_summary",
            "qa-summary.md" in str(fsc),
            "error",
            "first_safe_command points at qa-summary.md",
        )
        _validate_command_counts(qa, chk)
    else:
        chk("qa_results_loaded", False, "error", "qa-results.json could not be loaded as an object")

    sa = parsed.get("safety-assertions.json")
    if isinstance(sa, dict):
        _validate_assertion_counts(sa, chk)
    else:
        chk(
            "safety_assertions_loaded",
            False,
            "error",
            "safety-assertions.json could not be loaded as an object",
        )

    _validate_raw_outputs(bundle, qa, parsed.get("commands-run.json"), chk)
    _validate_validation_status(parsed.get("validation-status.json"), qa, chk)
    _validate_manifest(bundle, info_warnings, chk)

    return _build_validate_result(bundle, checks, info_warnings, pr, commit, short_sha)


def _validate_command_counts(qa: dict[str, Any], chk: Callable[..., bool]) -> None:
    commands = qa.get("commands") if isinstance(qa.get("commands"), list) else []
    summary = qa.get("summary") if isinstance(qa.get("summary"), dict) else {}
    passed = sum(1 for c in commands if isinstance(c, dict) and c.get("status") == "passed")
    failed = sum(1 for c in commands if isinstance(c, dict) and c.get("status") == "failed")
    chk(
        "command_count_total",
        summary.get("commands_total") == len(commands),
        "error",
        "qa-results summary commands_total matches command entries",
    )
    chk(
        "command_count_passed",
        summary.get("commands_passed") == passed,
        "error",
        "qa-results summary commands_passed matches passed entries",
    )
    chk(
        "command_count_failed",
        summary.get("commands_failed") == failed,
        "error",
        "qa-results summary commands_failed matches failed entries",
    )


def _validate_assertion_counts(sa: dict[str, Any], chk: Callable[..., bool]) -> None:
    assertions = sa.get("assertions") if isinstance(sa.get("assertions"), list) else []
    summary = sa.get("summary") if isinstance(sa.get("summary"), dict) else {}
    passed = sum(1 for a in assertions if isinstance(a, dict) and a.get("passed") is True)
    failed = sum(1 for a in assertions if isinstance(a, dict) and a.get("passed") is False)
    chk(
        "assertion_summary_present",
        isinstance(sa.get("summary"), dict),
        "error",
        "safety-assertions.json has an assertion summary",
    )
    chk(
        "assertion_count_total",
        summary.get("total") == len(assertions),
        "error",
        "safety assertion summary total matches assertion entries",
    )
    chk(
        "assertion_count_passed",
        summary.get("passed") == passed,
        "error",
        "safety assertion summary passed matches passing assertions",
    )
    chk(
        "assertion_count_failed",
        summary.get("failed") == failed,
        "error",
        "safety assertion summary failed matches failing assertions",
    )


def _validate_raw_outputs(
    bundle: Path, qa: Any, commands_run: Any, chk: Callable[..., bool]
) -> None:
    raw_files: set[str] = set()
    for source in (qa, commands_run):
        if isinstance(source, dict):
            for entry in source.get("commands") or []:
                if isinstance(entry, dict) and entry.get("raw_file"):
                    raw_files.add(str(entry["raw_file"]))
    if not raw_files:
        return
    missing = sorted(rf for rf in raw_files if not (bundle / rf).is_file())
    chk(
        "raw_outputs_present",
        not missing,
        "error",
        "all listed raw command outputs are present"
        if not missing
        else f"missing raw command outputs: {missing}",
    )


def _validate_validation_status(vs: Any, qa: Any, chk: Callable[..., bool]) -> None:
    if not isinstance(vs, dict):
        return
    if isinstance(qa, dict):
        rp = vs.get("requested_pr")
        if rp is not None:
            chk(
                "validation_requested_pr_matches",
                str(rp) == str(qa.get("pr")),
                "error",
                "validation-status requested_pr matches qa-results pr",
            )
        rc = vs.get("requested_commit")
        if rc:
            chk(
                "validation_requested_commit_matches",
                _commit_prefix_match(rc, qa.get("commit")),
                "error",
                "validation-status requested_commit matches qa-results commit",
            )
    # A scoped ``not_found`` is clean evidence-of-absence; it only becomes a
    # problem if it simultaneously claims pass eligibility.
    if vs.get("status") in ("not_found", "not_available") and vs.get("pass_eligible") is True:
        chk(
            "validation_not_found_consistent",
            False,
            "error",
            "validation-status not_found must not claim pass_eligible=true",
        )
    # scope_matched=false means the captured evidence belonged to another
    # PR/commit and is not current evidence: surface as a warning.
    if vs.get("scope_matched") is False:
        chk(
            "validation_scope_matched",
            False,
            "warning",
            "validation-status scope_matched=false; captured evidence is not current evidence",
        )


def _validate_manifest(bundle: Path, info_warnings: list[str], chk: Callable[..., bool]) -> None:
    manifest_path = bundle / MANIFEST_FILE
    if not manifest_path.is_file():
        info_warnings.append(
            "bundle-manifest.json missing; legacy bundle integrity checks limited to "
            "structural validation"
        )
        return
    ok, manifest, err = _load_json_file(manifest_path)
    if not chk("manifest_parses", ok, "error", err or "bundle-manifest.json parses as strict JSON"):
        return
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(files, list):
        chk("manifest_files_present", False, "error", "bundle-manifest.json has no files list")
        return
    missing: list[str] = []
    mismatched: list[str] = []
    for entry in files:
        if not isinstance(entry, dict):
            continue
        rel = entry.get("path")
        if not rel:
            continue
        path = bundle / rel
        if not path.is_file():
            missing.append(str(rel))
            continue
        expected = entry.get("sha256")
        if expected and _sha256_file(path) != expected:
            mismatched.append(str(rel))
    chk(
        "manifest_files_present",
        not missing,
        "error",
        "all manifest files present" if not missing else f"manifest lists missing files: {missing}",
    )
    chk(
        "manifest_hashes_match",
        not mismatched,
        "error",
        "manifest sha256 hashes match"
        if not mismatched
        else f"manifest sha256 mismatch: {mismatched}",
    )


def _build_validate_result(
    bundle: Path,
    checks: list[dict[str, Any]],
    info_warnings: list[str],
    pr: Any,
    commit: Any,
    short_sha: Any,
) -> dict[str, Any]:
    errors = [c["detail"] for c in checks if not c["passed"] and c["level"] == "error"]
    warn_failures = [c["detail"] for c in checks if not c["passed"] and c["level"] == "warning"]
    warnings = warn_failures + list(info_warnings)
    passed = sum(1 for c in checks if c["passed"])
    if errors:
        status = "invalid"
    elif warn_failures:
        status = "warning"
    else:
        status = "valid"
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": VALIDATE_MODE,
        "status": status,
        "bundle_path": str(bundle),
        "pr": pr,
        "commit": commit,
        "short_sha": short_sha,
        "checks_total": len(checks),
        "checks_passed": passed,
        "checks_failed": len(checks) - passed,
        "warnings": warnings,
        "errors": errors,
        "checks": checks,
    }


# ---------------------------------------------------------------------------
# Lifecycle: history
# ---------------------------------------------------------------------------


def _validation_view(vs: Any) -> dict[str, Any]:
    """Compact validation summary used by history/compare."""
    if not isinstance(vs, dict):
        return {
            "status": None,
            "classification": None,
            "pass_eligible": None,
            "rerun_required": None,
            "scope_matched": None,
        }
    return {
        "status": vs.get("status"),
        "classification": vs.get("classification"),
        "pass_eligible": vs.get("pass_eligible"),
        "rerun_required": vs.get("rerun_required"),
        "scope_matched": vs.get("scope_matched"),
    }


def _bundle_entry(bundle: Path, name_match: re.Match[str]) -> dict[str, Any]:
    """Build one history entry from a bundle directory (artifact-only)."""
    entry: dict[str, Any] = {
        "bundle_path": str(bundle),
        "name": bundle.name,
        "pr": int(name_match.group("pr")),
        "commit": None,
        "short_sha": name_match.group("short"),
        "created_at": None,
        "status": None,
        "commands_passed": None,
        "commands_failed": None,
        "safety_assertions_passed": None,
        "safety_assertions_failed": None,
        "validation": _validation_view(None),
        "bundle_validation": "invalid",
    }

    qa_path = bundle / "qa-results.json"
    if qa_path.is_file():
        ok, qa, _ = _load_json_file(qa_path)
        if ok and isinstance(qa, dict):
            entry["pr"] = qa.get("pr", entry["pr"])
            entry["commit"] = qa.get("commit")
            entry["short_sha"] = qa.get("short_sha", entry["short_sha"])
            entry["created_at"] = qa.get("created_at")
            entry["status"] = qa.get("status")
            summary = qa.get("summary") if isinstance(qa.get("summary"), dict) else {}
            entry["commands_passed"] = summary.get("commands_passed")
            entry["commands_failed"] = summary.get("commands_failed")
            entry["safety_assertions_passed"] = summary.get("safety_assertions_passed")
            entry["safety_assertions_failed"] = summary.get("safety_assertions_failed")

    vs_path = bundle / "validation-status.json"
    if vs_path.is_file():
        ok, vs, _ = _load_json_file(vs_path)
        if ok:
            entry["validation"] = _validation_view(vs)

    try:
        entry["bundle_validation"] = validate_bundle(bundle)["status"]
    except Exception:  # pragma: no cover - defensive; validate is artifact-only
        entry["bundle_validation"] = "invalid"
    return entry


def discover_history(
    root: str | Path,
    pr: int | None = None,
    commit: str | None = None,
    status: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Discover + filter PR206 bundles under ``root`` (artifact-only, no recursion)."""
    root_path = Path(root)
    entries: list[dict[str, Any]] = []
    if root_path.is_dir():
        for child in root_path.iterdir():
            if not child.is_dir():
                continue
            match = BUNDLE_NAME_RE.match(child.name)
            if not match:
                continue
            entry = _bundle_entry(child, match)
            if pr is not None and entry["pr"] != pr:
                continue
            if commit and not (
                _commit_prefix_match(entry.get("commit"), commit)
                or _commit_prefix_match(entry.get("short_sha"), commit)
            ):
                continue
            if status is not None and entry.get("status") != status:
                continue
            entries.append(entry)

    entries.sort(key=lambda e: (e.get("created_at") or "", e.get("name") or ""), reverse=True)
    if limit is not None and limit >= 0:
        entries = entries[:limit]

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": HISTORY_MODE,
        "root": str(root_path),
        "filters": {"pr": pr, "commit": commit, "status": status},
        "bundles_total": len(entries),
        "bundles": entries,
    }


# ---------------------------------------------------------------------------
# Lifecycle: compare
# ---------------------------------------------------------------------------


def _bundle_view(bundle_dir: str | Path) -> dict[str, Any]:
    """Extract the comparable fields from a bundle (artifact-only)."""
    bundle = Path(bundle_dir)
    view: dict[str, Any] = {
        "bundle_path": str(bundle),
        "valid": False,
        "status": None,
        "pr": None,
        "commit": None,
        "short_sha": None,
        "created_at": None,
        "mutation_performed": None,
        "commands": {},
        "failed_commands": [],
        "safety": {},
        "safety_block": {},
        "container": {},
        "disk_text": None,
        "validation": _validation_view(None),
        "warnings": [],
    }
    qa_path = bundle / "qa-results.json"
    if not qa_path.is_file():
        return view
    ok, qa, _ = _load_json_file(qa_path)
    if not ok or not isinstance(qa, dict):
        return view

    view["valid"] = True
    view["status"] = qa.get("status")
    view["pr"] = qa.get("pr")
    view["commit"] = qa.get("commit")
    view["short_sha"] = qa.get("short_sha")
    view["created_at"] = qa.get("created_at")
    view["mutation_performed"] = qa.get("mutation_performed")
    view["safety_block"] = qa.get("safety") if isinstance(qa.get("safety"), dict) else {}
    view["warnings"] = qa.get("warnings") if isinstance(qa.get("warnings"), list) else []

    commands = qa.get("commands") if isinstance(qa.get("commands"), list) else []
    view["commands"] = {
        c["key"]: c.get("status") for c in commands if isinstance(c, dict) and c.get("key")
    }
    view["failed_commands"] = sorted(k for k, s in view["commands"].items() if s == "failed")

    sa_path = bundle / "safety-assertions.json"
    if sa_path.is_file():
        ok, sa, _ = _load_json_file(sa_path)
        if ok and isinstance(sa, dict):
            view["safety"] = {
                a["name"]: a.get("passed")
                for a in sa.get("assertions") or []
                if isinstance(a, dict) and a.get("name")
            }

    cs_path = bundle / "container-state.json"
    if cs_path.is_file():
        ok, cs, _ = _load_json_file(cs_path)
        if ok and isinstance(cs, dict):
            view["container"] = {
                "status": cs.get("status"),
                "health": cs.get("health"),
                "restart_count": cs.get("restart_count"),
                "image": cs.get("image"),
                "labels": cs.get("labels") or {},
            }
            disk = cs.get("disk") if isinstance(cs.get("disk"), dict) else {}
            view["disk_text"] = disk.get("use_percent")

    vs_path = bundle / "validation-status.json"
    if vs_path.is_file():
        ok, vs, _ = _load_json_file(vs_path)
        if ok:
            view["validation"] = _validation_view(vs)
    return view


def _view_summary(view: dict[str, Any]) -> dict[str, Any]:
    return {
        "bundle_path": view["bundle_path"],
        "valid": view["valid"],
        "status": view["status"],
        "pr": view["pr"],
        "commit": view["commit"],
        "short_sha": view["short_sha"],
        "created_at": view["created_at"],
        "validation_status": view["validation"].get("status"),
        "container_status": view["container"].get("status"),
        "container_health": view["container"].get("health"),
        "restart_count": view["container"].get("restart_count"),
    }


def compare_bundles(old_dir: str | Path, new_dir: str | Path) -> dict[str, Any]:
    """Compare two existing bundles and report meaningful deltas (artifact-only)."""
    old = _bundle_view(old_dir)
    new = _bundle_view(new_dir)
    base = {
        "schema_version": SCHEMA_VERSION,
        "mode": COMPARE_MODE,
        "old": _view_summary(old),
        "new": _view_summary(new),
    }
    if not old["valid"] or not new["valid"]:
        return {
            **base,
            "status": "invalid",
            "deltas": _empty_deltas(["one or both bundles could not be loaded as valid"]),
        }

    commands_regressed = sorted(
        k
        for k, s in new["commands"].items()
        if old["commands"].get(k) == "passed" and s == "failed"
    )
    commands_improved = sorted(
        k
        for k, s in new["commands"].items()
        if old["commands"].get(k) == "failed" and s == "passed"
    )
    safety_regressed = sorted(
        k for k, v in new["safety"].items() if old["safety"].get(k) is True and v is False
    )
    safety_improved = sorted(
        k for k, v in new["safety"].items() if old["safety"].get(k) is False and v is True
    )
    validation_changed = sorted(
        k
        for k in ("status", "classification", "pass_eligible", "rerun_required", "scope_matched")
        if old["validation"].get(k) != new["validation"].get(k)
    )
    container_changed = sorted(
        k
        for k in ("status", "health", "restart_count", "image", "labels")
        if old["container"].get(k) != new["container"].get(k)
    )

    warnings, regressed, improved = _classify_compare(old, new)

    status_changed = old["status"] != new["status"]
    old_rank = _STATUS_RANK.get(old["status"])
    new_rank = _STATUS_RANK.get(new["status"])
    if old_rank is not None and new_rank is not None:
        if new_rank < old_rank:
            regressed = True
        elif new_rank > old_rank:
            improved = True
    if commands_regressed or safety_regressed:
        regressed = True
    if commands_improved or safety_improved:
        improved = True

    if regressed:
        status = "regressed"
    elif improved:
        status = "improved"
    elif status_changed or container_changed or validation_changed or warnings:
        status = "changed"
    else:
        status = "same"

    if old["disk_text"] != new["disk_text"]:
        warnings.append(f"disk usage changed: {old['disk_text']} -> {new['disk_text']}")

    return {
        **base,
        "status": status,
        "deltas": {
            "status_changed": status_changed,
            "commands_regressed": commands_regressed,
            "commands_improved": commands_improved,
            "safety_regressed": safety_regressed,
            "safety_improved": safety_improved,
            "validation_changed": validation_changed,
            "container_changed": container_changed,
            "warnings": warnings,
        },
    }


def _empty_deltas(warnings: list[str]) -> dict[str, Any]:
    return {
        "status_changed": False,
        "commands_regressed": [],
        "commands_improved": [],
        "safety_regressed": [],
        "safety_improved": [],
        "validation_changed": [],
        "container_changed": [],
        "warnings": warnings,
    }


def _classify_compare(old: dict[str, Any], new: dict[str, Any]) -> tuple[list[str], bool, bool]:
    """Return (warnings, regressed, improved) for the non-list compare signals."""
    warnings: list[str] = []
    regressed = False
    improved = False

    if old["mutation_performed"] is False and new["mutation_performed"] is True:
        warnings.append("mutation_performed changed false -> true")
        regressed = True

    old_scope = old["validation"].get("scope_matched")
    new_scope = new["validation"].get("scope_matched")
    if old_scope in (True, None) and new_scope is False:
        warnings.append("validation scope_matched changed to false (evidence no longer current)")
        regressed = True

    if old["validation"].get("status") in ("not_found", "not_available") and (
        new["validation"].get("status") == "passed"
    ):
        improved = True

    old_rc = old["container"].get("restart_count")
    new_rc = new["container"].get("restart_count")
    if isinstance(old_rc, int) and isinstance(new_rc, int) and new_rc > old_rc:
        warnings.append(f"container restart_count increased {old_rc} -> {new_rc}")
        regressed = True

    if (
        old["container"].get("health") == "healthy"
        and new["container"].get("health") == "unhealthy"
    ):
        warnings.append("container health changed healthy -> unhealthy")
        regressed = True

    return warnings, regressed, improved


def compare_latest(root: str | Path, pr: int, commit: str | None = None) -> dict[str, Any]:
    """Compare the newest two matching bundles under ``root`` (artifact-only)."""
    history = discover_history(root, pr=pr, commit=commit)
    bundles = history["bundles"]
    if len(bundles) < 2:
        return {
            "schema_version": SCHEMA_VERSION,
            "mode": COMPARE_MODE,
            "status": "not_enough_bundles",
            "root": str(Path(root)),
            "pr": pr,
            "commit": commit,
            "bundles_found": len(bundles),
            "message": (
                f"need at least 2 matching bundles to compare, found {len(bundles)} "
                f"(root={root}, pr={pr}, commit={commit})"
            ),
        }
    newest, previous = bundles[0], bundles[1]
    result = compare_bundles(previous["bundle_path"], newest["bundle_path"])
    result["root"] = str(Path(root))
    result["selected"] = {
        "old": previous["bundle_path"],
        "new": newest["bundle_path"],
    }
    return result


# ---------------------------------------------------------------------------
# Lifecycle: human renderers
# ---------------------------------------------------------------------------


def render_validate_human(result: dict[str, Any]) -> str:
    lines = ["# Docker01 QA Bundle — validate", ""]
    lines.append(f"* bundle: {result['bundle_path']}")
    lines.append(
        f"* pr: {result.get('pr')}  commit: {result.get('short_sha') or result.get('commit')}"
    )
    lines.append(f"* status: {result['status']}")
    lines.append(
        f"* checks: {result['checks_passed']}/{result['checks_total']} passed "
        f"({result['checks_failed']} failed)"
    )
    if result["errors"]:
        lines.append("* errors:")
        lines.extend(f"  - {e}" for e in result["errors"])
    if result["warnings"]:
        lines.append("* warnings:")
        lines.extend(f"  - {w}" for w in result["warnings"])
    return "\n".join(lines)


def render_history_human(result: dict[str, Any]) -> str:
    filters = result["filters"]
    lines = ["# Docker01 QA Bundle — history", ""]
    lines.append(f"* root: {result['root']}")
    lines.append(
        f"* filters: pr={filters['pr']} commit={filters['commit']} status={filters['status']}"
    )
    lines.append(f"* bundles: {result['bundles_total']}")
    lines.append("")
    if not result["bundles"]:
        lines.append("(no matching bundles)")
        return "\n".join(lines)
    for b in result["bundles"]:
        lines.append(
            f"- pr{b['pr']} {b['short_sha']} {b.get('status')} "
            f"[{b['bundle_validation']}] {b.get('created_at')}"
        )
        lines.append(f"    {b['bundle_path']}")
    return "\n".join(lines)


def render_compare_human(result: dict[str, Any]) -> str:
    lines = ["# Docker01 QA Bundle — compare", ""]
    old, new = result["old"], result["new"]
    lines.append(f"* old: {old['bundle_path']} ({old.get('status')})")
    lines.append(f"* new: {new['bundle_path']} ({new.get('status')})")
    lines.append(f"* verdict: {result['status']}")
    if result["status"] == "not_enough_bundles":
        lines.append(f"* {result.get('message')}")
        return "\n".join(lines)
    deltas = result["deltas"]
    lines.append(f"* status_changed: {deltas['status_changed']}")
    for key in (
        "commands_regressed",
        "commands_improved",
        "safety_regressed",
        "safety_improved",
        "validation_changed",
        "container_changed",
    ):
        if deltas[key]:
            lines.append(f"* {key}: {', '.join(deltas[key])}")
    for warning in deltas["warnings"]:
        lines.append(f"* warning: {warning}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="docker01_operator_qa_bundle.py",
        description=(
            "Read-only Docker01 operator QA evidence bundle helper. Generation "
            "runs the standard read-only smoke QA set and writes a bounded, "
            "pasteable evidence packet for the PR handoff. Lifecycle modes "
            "(--validate-bundle / --history / --compare / --compare-latest) are "
            "artifact-only: they read existing bundles, never run Docker, "
            "ShellForgeAI, or validation commands, and never mutate anything."
        ),
    )
    # Generation requires --pr/--commit; for lifecycle modes they act as filters
    # (or are unused), so they are not globally required here. main() enforces
    # them when generating a bundle.
    parser.add_argument("--pr", type=int, default=None, help="PR number under QA / history filter.")
    parser.add_argument("--commit", default=None, help="Commit SHA under QA / history filter.")
    parser.add_argument("--out", default=None, help="Explicit bundle output directory.")
    parser.add_argument("--json", action="store_true", help="Emit strict JSON only.")
    parser.add_argument(
        "--include-hygiene",
        action="store_true",
        default=True,
        help="Include hygiene history/compare evidence (default).",
    )
    parser.add_argument(
        "--skip-hygiene", action="store_true", help="Skip hygiene evidence collection."
    )
    parser.add_argument(
        "--include-hygiene-review-bundle",
        action="store_true",
        help="Opt in to bounded hygiene review bundle packaging.",
    )
    parser.add_argument(
        "--include-model-receipts",
        action="store_true",
        default=True,
        help="Include read-only Model Doctor receipt evidence (default; no model call).",
    )
    parser.add_argument(
        "--skip-model-receipts",
        action="store_true",
        help="Skip model receipt evidence collection.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List planned commands and intended output path; execute nothing and write no bundle.",
    )
    # Lifecycle modes (artifact-only).
    parser.add_argument(
        "--validate-bundle",
        default=None,
        metavar="BUNDLE_DIR",
        help="Validate an existing bundle's structure/integrity (artifact-only).",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Discover bundles under --root (artifact-only); filter with --pr/--commit/--status.",
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        default=None,
        metavar=("OLD_BUNDLE", "NEW_BUNDLE"),
        help="Compare two existing bundles and report deltas (artifact-only).",
    )
    parser.add_argument(
        "--compare-latest",
        action="store_true",
        help="Compare the newest two matching bundles under --root (artifact-only).",
    )
    parser.add_argument(
        "--root",
        default=DEFAULT_ROOT,
        help=f"Discovery root for --history/--compare-latest (default {DEFAULT_ROOT}).",
    )
    parser.add_argument(
        "--status",
        default=None,
        help="History filter: bundle status (passed|failed|partial|dry_run).",
    )
    parser.add_argument(
        "--limit", type=int, default=None, help="History: cap results to N bundles."
    )
    return parser


def _run_validate(args: argparse.Namespace) -> int:
    result = validate_bundle(args.validate_bundle)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render_validate_human(result))
    return 0 if result["status"] in ("valid", "warning") else 1


def _run_history(args: argparse.Namespace) -> int:
    result = discover_history(
        args.root, pr=args.pr, commit=args.commit, status=args.status, limit=args.limit
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render_history_human(result))
    return 0


def _compare_exit_code(status: str) -> int:
    return 0 if status in ("same", "improved", "changed") else 1


def _run_compare(args: argparse.Namespace) -> int:
    old_dir, new_dir = args.compare
    result = compare_bundles(old_dir, new_dir)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render_compare_human(result))
    return _compare_exit_code(result["status"])


def _run_compare_latest(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.pr is None:
        parser.error("--compare-latest requires --pr")
    result = compare_latest(args.root, pr=args.pr, commit=args.commit)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render_compare_human(result))
    if result["status"] == "not_enough_bundles":
        return 1
    return _compare_exit_code(result["status"])


def _run_generation(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.pr is None or args.commit is None:
        parser.error("--pr and --commit are required for bundle generation")
    out = Path(args.out) if args.out else None
    result = generate_bundle(
        pr=args.pr,
        commit=args.commit,
        out=out,
        dry_run=args.dry_run,
        include_hygiene=not args.skip_hygiene,
        include_hygiene_review_bundle=args.include_hygiene_review_bundle,
        include_model_receipts=not args.skip_model_receipts,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    elif args.dry_run:
        print(f"[dry-run] intended bundle: {result['intended_bundle_path']}")
        print("[dry-run] planned commands (no execution):")
        for cmd in result["planned_commands"]:
            print(f"  - {cmd['label']}: {' '.join(cmd['argv'])}")
    else:
        print(f"bundle: {result['bundle_path']}")
        print(f"status: {result['status']}")
        print(f"first safe command: {result['first_safe_command']}")

    status = result.get("status")
    return 0 if status in ("passed", "dry_run") else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    lifecycle = [
        bool(args.validate_bundle),
        bool(args.history),
        bool(args.compare),
        bool(args.compare_latest),
    ]
    if sum(lifecycle) > 1:
        parser.error("choose at most one lifecycle mode (validate/history/compare/compare-latest)")

    if args.validate_bundle:
        return _run_validate(args)
    if args.history:
        return _run_history(args)
    if args.compare:
        return _run_compare(args)
    if args.compare_latest:
        return _run_compare_latest(args, parser)
    return _run_generation(args, parser)


if __name__ == "__main__":
    raise SystemExit(main())
