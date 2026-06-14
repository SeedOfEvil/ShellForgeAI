"""Read-only helpers for the PR184 golden CLI command-surface guardrail.

This module is test-support only. It loads the golden command-surface fixture,
validates its shape, and provides a deterministic, model-free way to invoke the
ShellForgeAI Typer app via ``CliRunner`` so refactors cannot silently drop
commands, JSON flags, help text, governed-execution confirmation markers, or
mutation-refusal paths.

Strict safety posture (enforced by the guardrail itself):

* No Docker/Compose call, container/production restart, cleanup, remediation,
  rollback, or recovery execution is performed.
* No shell execution, subprocess use, or arbitrary/natural-language execution
  is introduced.
* No model/provider call is made: callers block ``cli.build_provider`` so any
  accidental model call fails loudly.

The helper only reads the fixture and runs the in-process CLI. It never writes
artifacts and never mutates real ``/data``.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

# tests/helpers/cli_surface.py -> repo root is parents[2].
REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REPO_ROOT / "tests" / "golden" / "cli_command_surface_pr184.json"

# Fields that would make the golden fixture volatile/environment-specific. The
# guardrail refuses to store any of these so the snapshot stays stable.
FORBIDDEN_FIXTURE_FIELD_TOKENS = (
    "timestamp",
    "created_at",
    "generated_at",
    "duration",
    "/data",
    "/srv",
    "/tmp",
    "/home",
    "/proc",
    "elapsed",
)

_MISSING = object()


@dataclass(frozen=True)
class CommandResult:
    """Bounded view of a CliRunner invocation result."""

    exit_code: int
    stdout: str

    @property
    def stdout_lower(self) -> str:
        return self.stdout.lower()


def load_fixture(path: Path | None = None) -> dict[str, Any]:
    """Load and JSON-parse the golden command-surface fixture."""

    fixture_path = path or FIXTURE_PATH
    raw = fixture_path.read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise AssertionError("command-surface fixture must be a JSON object")
    return data


def validate_fixture(fixture: dict[str, Any]) -> None:
    """Validate the top-level fixture contract, raising a clear error on drift."""

    for field in ("schema_version", "mode", "commands"):
        if field not in fixture:
            raise AssertionError(f"fixture missing required top-level field: {field}")
    if fixture["mode"] != "cli_command_surface_golden":
        raise AssertionError(
            f"unexpected fixture mode: {fixture['mode']!r} (expected cli_command_surface_golden)"
        )
    commands = fixture["commands"]
    if not isinstance(commands, list) or not commands:
        raise AssertionError("fixture 'commands' must be a non-empty list")

    seen: set[str] = set()
    for entry in commands:
        _validate_command_entry(entry, seen)

    refusals = fixture.get("refusal_phrases", [])
    if not isinstance(refusals, list):
        raise AssertionError("fixture 'refusal_phrases' must be a list when present")
    refusal_seen: set[str] = set()
    for entry in refusals:
        _validate_refusal_entry(entry, refusal_seen)


def _validate_command_entry(entry: Any, seen: set[str]) -> None:
    if not isinstance(entry, dict):
        raise AssertionError("each command entry must be an object")
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        raise AssertionError(f"command entry has invalid 'name': {name!r}")
    if name in seen:
        raise AssertionError(f"duplicate command name in fixture: {name}")
    seen.add(name)

    argv = entry.get("argv")
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise AssertionError(f"command {name!r} argv must be a list of strings")
    if not argv:
        raise AssertionError(f"command {name!r} argv must not be empty")

    has_substrings = isinstance(entry.get("required_substrings"), list)
    has_json = bool(entry.get("expect_json"))
    if not (has_substrings or has_json):
        raise AssertionError(f"command {name!r} must declare required_substrings OR expect_json")
    if "expect_exit_code" in entry and not isinstance(entry["expect_exit_code"], int):
        raise AssertionError(f"command {name!r} expect_exit_code must be an int when present")
    if has_substrings and not all(isinstance(s, str) for s in entry["required_substrings"]):
        raise AssertionError(f"command {name!r} required_substrings must be strings")
    if "required_json_fields" in entry and not all(
        isinstance(s, str) for s in entry["required_json_fields"]
    ):
        raise AssertionError(f"command {name!r} required_json_fields must be strings")
    if "safety_expectations" in entry and not isinstance(entry["safety_expectations"], dict):
        raise AssertionError(f"command {name!r} safety_expectations must be an object")


def _validate_refusal_entry(entry: Any, seen: set[str]) -> None:
    if not isinstance(entry, dict):
        raise AssertionError("each refusal entry must be an object")
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        raise AssertionError(f"refusal entry has invalid 'name': {name!r}")
    if name in seen:
        raise AssertionError(f"duplicate refusal name in fixture: {name}")
    seen.add(name)
    argv = entry.get("argv")
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise AssertionError(f"refusal {name!r} argv must be a list of strings")
    if not argv or argv[0] != "ask":
        raise AssertionError(f"refusal {name!r} argv must start with 'ask'")
    if not isinstance(entry.get("required_substrings"), list):
        raise AssertionError(f"refusal {name!r} must declare required_substrings")


def _strip_documentation(value: Any) -> Any:
    """Recursively drop free-text documentation fields before volatility scan.

    The guardrail intentionally documents its own no-volatile-data policy in
    prose (``description`` / ``notes``), so those human-facing fields are
    excluded from the volatility scan; structural data (argv, expectations,
    json fields) is still checked for embedded timestamps/paths.
    """

    if isinstance(value, dict):
        return {
            k: _strip_documentation(v)
            for k, v in value.items()
            if k not in {"description", "notes"}
        }
    if isinstance(value, list):
        return [_strip_documentation(v) for v in value]
    return value


def assert_no_volatile_fields(fixture: dict[str, Any]) -> None:
    """Fail if the fixture stores volatile/environment-specific values."""

    blob = json.dumps(_strip_documentation(fixture)).lower()
    for token in FORBIDDEN_FIXTURE_FIELD_TOKENS:
        if token in blob:
            raise AssertionError(
                f"command-surface fixture must not store volatile token: {token!r}"
            )


def make_runner() -> CliRunner:
    return CliRunner()


def block_model_calls(monkeypatch, cli_module) -> None:
    """Patch the provider factory so any model call fails the test loudly."""

    def _no_model(*_args, **_kwargs):
        raise AssertionError("model/provider must not be called by command-surface tests")

    monkeypatch.setattr(cli_module, "build_provider", _no_model)


def invoke(app, argv: list[str]) -> CommandResult:
    """Invoke the CLI in-process and return a bounded result view (uncached)."""

    result = make_runner().invoke(app, argv)
    return CommandResult(exit_code=result.exit_code, stdout=result.stdout or "")


# --------------------------------------------------------------------------
# Shared, in-process invocation cache + deterministic duration reporting
# --------------------------------------------------------------------------
#
# The golden command-surface guardrail invokes the same read-only commands many
# times: once in the parametrized sweep, again in the explicit numbered tests,
# and again in the whole-surface safety sweep (``test_35_*``). The expensive
# ones -- ``v1 check`` readiness, ``status --json``, ``ops report`` -- each cost
# seconds of real, read-only host inspection, so re-running them 2-3x dominates
# the suite (and the PR205 ``test_23`` subprocess that runs this whole suite).
#
# This cache makes each *unique* argv run at most once per test process. It is
# correctness-neutral: every command the guardrail invokes is read-only and
# deterministic with respect to its argv -- help text is static, and the JSON
# inspection commands probe the host read-only against an always-empty tmp data
# dir -- so a cached result is identical to a fresh invocation. Coverage is
# unchanged: if a command regresses, the (single) cached result reflects the
# regression and every test reading it still fails.

_INVOKE_CACHE: dict[tuple[str, ...], CommandResult] = {}
_INVOKE_DURATIONS: dict[tuple[str, ...], float] = {}
_INVOKE_HITS = 0
_INVOKE_MISSES = 0


def invoke_cached(app, argv: list[str]) -> CommandResult:
    """Invoke the CLI once per unique argv and reuse the result thereafter.

    Returns the *same* :class:`CommandResult` object for repeated argv so callers
    can rely on identity as well as equality. The first (uncached) invocation is
    timed for the duration report; cache hits do no work.
    """

    global _INVOKE_HITS, _INVOKE_MISSES
    key = tuple(argv)
    cached = _INVOKE_CACHE.get(key)
    if cached is not None:
        _INVOKE_HITS += 1
        return cached
    _INVOKE_MISSES += 1
    start = time.perf_counter()
    result = invoke(app, argv)
    _INVOKE_DURATIONS[key] = time.perf_counter() - start
    _INVOKE_CACHE[key] = result
    return result


def clear_invoke_cache() -> None:
    """Reset the shared invocation cache, stats, and timings (test isolation)."""

    global _INVOKE_HITS, _INVOKE_MISSES
    _INVOKE_CACHE.clear()
    _INVOKE_DURATIONS.clear()
    _INVOKE_HITS = 0
    _INVOKE_MISSES = 0


def invoke_cache_stats() -> dict[str, int]:
    """Return deterministic counters describing cache usage in this process."""

    return {
        "unique": len(_INVOKE_CACHE),
        "hits": _INVOKE_HITS,
        "misses": _INVOKE_MISSES,
    }


def invocation_duration_report(top: int = 10) -> dict[str, Any]:
    """Return a deterministic summary of per-argv invocation cost.

    The shape is stable and ordering is deterministic (slowest first, argv as a
    tiebreaker), so tests can assert on structure without depending on machine
    timing. Absolute durations are reported for observability only and must not
    be turned into assertions.
    """

    items = sorted(_INVOKE_DURATIONS.items(), key=lambda kv: (-kv[1], kv[0]))
    return {
        "unique_commands": len(_INVOKE_DURATIONS),
        "cache_hits": _INVOKE_HITS,
        "cache_misses": _INVOKE_MISSES,
        "slowest": [
            {"argv": list(argv), "seconds": round(seconds, 4)}
            for argv, seconds in items[: max(0, top)]
        ],
    }


def format_duration_report(report: dict[str, Any] | None = None) -> str:
    """Render the duration report as a short, deterministic text block."""

    report = report or invocation_duration_report()
    lines = [
        "command-surface invocation report:",
        f"  unique commands invoked: {report['unique_commands']}",
        f"  cache hits / misses: {report['cache_hits']} / {report['cache_misses']}",
    ]
    for item in report["slowest"]:
        lines.append(f"  {item['seconds']:.4f}s  {' '.join(item['argv'])}")
    return "\n".join(lines)


def resolve_safety_flag(payload: dict[str, Any], key: str) -> Any:
    """Resolve a safety flag from the top level first, then the ``safety`` block.

    ShellForgeAI JSON payloads expose safety flags either at the top level,
    inside a nested ``safety`` object, or both. This resolver checks both so the
    guardrail is robust to which location a given command uses.
    """

    if key in payload:
        return payload[key]
    safety = payload.get("safety")
    if isinstance(safety, dict) and key in safety:
        return safety[key]
    return _MISSING


def check_substrings(result: CommandResult, required: list[str], *, label: str) -> None:
    haystack = result.stdout_lower
    for needle in required:
        if needle.lower() not in haystack:
            raise AssertionError(
                f"{label}: missing required substring {needle!r}\n--- stdout ---\n{result.stdout}"
            )


def check_command(app, entry: dict[str, Any]) -> None:
    """Assert a single command-surface fixture entry against the live CLI."""

    name = entry["name"]
    result = invoke_cached(app, entry["argv"])

    if "expect_exit_code" in entry and result.exit_code != entry["expect_exit_code"]:
        raise AssertionError(
            f"{name}: exit code {result.exit_code} != expected "
            f"{entry['expect_exit_code']}\n--- stdout ---\n{result.stdout}"
        )

    if entry.get("required_substrings"):
        check_substrings(result, entry["required_substrings"], label=name)

    if entry.get("expect_json"):
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"{name}: expected strict JSON but parsing failed: {exc}\n"
                f"--- stdout ---\n{result.stdout}"
            ) from exc
        if not isinstance(payload, dict):
            raise AssertionError(f"{name}: JSON payload must be an object")

        for field in entry.get("required_json_fields", []):
            if field not in payload:
                raise AssertionError(
                    f"{name}: missing required JSON field {field!r}; keys={list(payload)}"
                )
        for field, expected in entry.get("required_json_values", {}).items():
            if payload.get(field) != expected:
                raise AssertionError(
                    f"{name}: JSON field {field!r} = {payload.get(field)!r} != {expected!r}"
                )
        for flag, expected in entry.get("safety_expectations", {}).items():
            actual = resolve_safety_flag(payload, flag)
            if actual is _MISSING:
                raise AssertionError(
                    f"{name}: safety flag {flag!r} not present at top level or in safety block"
                )
            if actual != expected:
                raise AssertionError(
                    f"{name}: safety flag {flag!r} = {actual!r} != expected {expected!r}"
                )


def check_refusal(app, entry: dict[str, Any]) -> None:
    """Assert a mutation-refusal phrase still refuses without any execution flag."""

    name = entry["name"]
    result = invoke_cached(app, entry["argv"])
    if result.exit_code != entry.get("expect_exit_code", 0):
        raise AssertionError(
            f"{name}: refusal exit code {result.exit_code} unexpected\n"
            f"--- stdout ---\n{result.stdout}"
        )
    check_substrings(result, entry["required_substrings"], label=name)
    for forbidden in entry.get("forbidden_substrings", []):
        if forbidden.lower() in result.stdout_lower:
            raise AssertionError(
                f"{name}: refusal output must not contain {forbidden!r}\n"
                f"--- stdout ---\n{result.stdout}"
            )
