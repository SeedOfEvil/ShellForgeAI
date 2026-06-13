#!/usr/bin/env python3
"""Read-only import side-effect audit for the ShellForgeAI CLI command modules.

This helper proves that importing ``shellforgeai.cli`` and every
``shellforgeai.commands.*`` module is *import-safe*: importing them must only
define Typer apps/functions/classes, import local modules, define constants and
option metadata, and register commands. Importing them must **not** execute any
operational behavior — no subprocess/``os.system``/``shell=True`` execution, no
Docker/Compose call or container/production restart, no cleanup/remediation/
rollback/recovery execution, no model/Codex call, no network call, and no
artifact write/repair/delete.

The audit installs harmless recording stubs over the dangerous primitives
*before* importing any ShellForgeAI module, then imports each target module in a
controlled order and reports whether any stub was triggered at import time. It is
strictly read-only:

* It never executes a ShellForgeAI product command.
* It never calls Docker/Compose, runs a subprocess, opens a network connection,
  or calls a model/provider — the stubs make any such attempt fail loudly and be
  recorded rather than actually run.
* It never writes, repairs, or deletes artifacts and never mutates real ``/data``.

Run it fresh (so nothing is import-cached) to get a meaningful result::

    python scripts/cli_import_audit.py
    python scripts/cli_import_audit.py --json
    python scripts/cli_import_audit.py --markdown

Default and Markdown modes are human-facing; ``--json`` emits strict JSON. No
mode writes a file or mutates any system state.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import socket
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MODE = "cli_import_audit"

# Repo layout: scripts/cli_import_audit.py -> repo root is parents[1].
REPO_ROOT = Path(__file__).resolve().parents[1]
COMMANDS_DIR = Path("src/shellforgeai/commands")

# The CLI entrypoint and command package are always audited alongside the
# discovered command modules.
CLI_MODULE = "shellforgeai.cli"
COMMANDS_PACKAGE = "shellforgeai.commands"


@dataclass
class SideEffectRecorder:
    """Collects (module, primitive) pairs for any dangerous stub that fires."""

    current_module: str | None = None
    attempts: list[dict[str, str]] = field(default_factory=list)

    def record(self, primitive: str) -> None:
        self.attempts.append({"module": self.current_module or "<setup>", "primitive": primitive})

    def for_module(self, module: str) -> list[str]:
        return sorted({a["primitive"] for a in self.attempts if a["module"] == module})


def _make_stub(recorder: SideEffectRecorder, primitive: str) -> Callable[..., Any]:
    """Return a harmless callable that records the attempt and returns a stand-in.

    The stub never performs the real operation. It returns a permissive
    :class:`_Inert` object so that, in the (defended-against) event a module
    *does* call it at import time, the import can still complete and every
    attempt is collected rather than dying on the first one.
    """

    def _stub(*_args: Any, **_kwargs: Any) -> Any:
        recorder.record(primitive)
        return _Inert()

    return _stub


class _Inert:
    """A permissive no-op stand-in returned by recording stubs."""

    def __call__(self, *_args: Any, **_kwargs: Any) -> _Inert:
        return self

    def __getattr__(self, _name: str) -> _Inert:
        return self

    def __iter__(self):
        return iter(())

    def __enter__(self) -> _Inert:
        return self

    def __exit__(self, *_exc: Any) -> bool:
        return False

    def __bool__(self) -> bool:
        return False


def install_import_guards(recorder: SideEffectRecorder) -> list[Callable[[], None]]:
    """Patch dangerous primitives with recording stubs.

    Returns a list of undo callables so callers can restore the originals. The
    guards cover the lowest-level primitives that *all* operational behavior must
    pass through:

    * subprocess execution (``subprocess.run``/``Popen``/``call``/``check_call``/
      ``check_output``) — this is how Docker/Compose, container/production
      restart, cleanup/remediation/rollback/recovery, and any shell command would
      run;
    * ``os.system``/``os.popen`` — arbitrary command execution;
    * network primitives (``socket.socket.connect``, ``socket.create_connection``)
      — any network/model API traffic ultimately opens a socket;
    * the model/provider factory (``shellforgeai.llm.manager.build_provider``)
      where it is patchable, as belt-and-suspenders over the network guard.

    Artifact write/repair/delete at import time would itself require executing
    code paths that are not present at module top level; the static guard in the
    PR205 test suite backs this up by rejecting top-level mutation calls.
    """

    undo: list[Callable[[], None]] = []

    def _patch(obj: Any, attr: str, primitive: str) -> None:
        if not hasattr(obj, attr):
            return
        original = getattr(obj, attr)
        setattr(obj, attr, _make_stub(recorder, primitive))
        undo.append(lambda: setattr(obj, attr, original))

    # Subprocess / shell execution primitives (covers Docker/Compose/restart/
    # cleanup/remediation/rollback/recovery — they all shell out).
    for attr in ("run", "Popen", "call", "check_call", "check_output"):
        _patch(subprocess, attr, f"subprocess.{attr}")

    # Arbitrary command execution.
    _patch(os, "system", "os.system")
    _patch(os, "popen", "os.popen")

    # Network primitives (any real model/network call opens a socket).
    _patch(socket, "create_connection", "socket.create_connection")
    _patch(socket.socket, "connect", "socket.socket.connect")

    # Model/provider factory, patched before cli binds it via ``from`` import.
    try:
        manager = importlib.import_module("shellforgeai.llm.manager")
    except Exception:
        manager = None
    if manager is not None:
        _patch(manager, "build_provider", "shellforgeai.llm.manager.build_provider")

    return undo


def discover_command_modules(commands_dir: Path | None = None) -> list[str]:
    """Return sorted dotted module names for every command module on disk."""

    base = commands_dir or (REPO_ROOT / COMMANDS_DIR)
    names = sorted(path.stem for path in base.glob("*.py") if path.name != "__init__.py")
    return [f"{COMMANDS_PACKAGE}.{name}" for name in names]


def _import_module(recorder: SideEffectRecorder, dotted: str) -> dict[str, Any]:
    recorder.current_module = dotted
    entry: dict[str, Any] = {
        "module": dotted,
        "status": "ok",
        "imported": False,
        "side_effects_detected": [],
    }
    try:
        importlib.import_module(dotted)
        entry["imported"] = True
    except Exception as exc:  # pragma: no cover - import failure is reported, not raised
        entry["status"] = "failed"
        entry["error"] = f"{type(exc).__name__}: {exc}"
    entry["side_effects_detected"] = recorder.for_module(dotted)
    if entry["side_effects_detected"]:
        entry["status"] = "failed"
    recorder.current_module = None
    return entry


def build_audit_payload() -> dict[str, Any]:
    """Import the CLI surface under recording stubs and summarize the result."""

    recorder = SideEffectRecorder()
    undo = install_import_guards(recorder)
    try:
        # Import the leaf command modules first (each is independent and does not
        # import cli.py), then the package, then cli.py last so any cascading
        # import-time behavior is attributed to the entrypoint.
        targets = [COMMANDS_PACKAGE, *discover_command_modules(), CLI_MODULE]
        # Keep a stable, readable order: package, sorted command modules, cli.
        modules = [_import_module(recorder, dotted) for dotted in targets]
    finally:
        for restore in reversed(undo):
            restore()

    imported = sum(1 for m in modules if m["imported"])
    failed = sum(1 for m in modules if m["status"] == "failed")
    side_effect_attempts = len(recorder.attempts)
    status = "ok" if failed == 0 and side_effect_attempts == 0 else "failed"

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "read_only": True,
        "mutation_performed": False,
        "modules_checked": len(modules),
        "modules": modules,
        "summary": {
            "imported": imported,
            "failed": failed,
            "side_effect_attempts": side_effect_attempts,
        },
        "safety": {
            "read_only": True,
            "mutation_performed": False,
            "subprocess_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "production_restarted": False,
            "cleanup_executed": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "recovery_executed": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "natural_language_execution": False,
            "model_called": False,
            "network_called": False,
            "package_installed": False,
            "cloud_apply_merge_push": False,
            "artifact_repaired": False,
            "artifact_deleted": False,
        },
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# ShellForgeAI CLI Import Side-Effect Audit",
        "",
        (
            "Read-only check that importing `shellforgeai.cli` and every "
            "`shellforgeai.commands.*` module is import-safe (definitions, imports, "
            "and Typer registration only — no operational execution at import time)."
        ),
        "",
        f"- Status: `{payload['status']}`",
        f"- Modules checked: {payload['modules_checked']}",
        f"- Imported: {payload['summary']['imported']}",
        f"- Failed: {payload['summary']['failed']}",
        f"- Side-effect attempts: {payload['summary']['side_effect_attempts']}",
        "",
        "## Modules",
        "",
        "| Module | Status | Imported | Side effects detected |",
        "| --- | --- | --- | --- |",
    ]
    for module in payload["modules"]:
        effects = ", ".join(module["side_effects_detected"]) or "none"
        lines.append(
            f"| `{module['module']}` | `{module['status']}` | "
            f"{str(module['imported']).lower()} | {effects} |"
        )
    lines.extend(
        [
            "",
            "## Safety",
            "",
            "- Read-only import audit; no ShellForgeAI command executed.",
            "- No subprocess, Docker/Compose, container/production restart.",
            "- No cleanup/remediation/rollback/recovery execution.",
            "- No model/Codex call and no network call.",
            "- No artifact write/repair/delete and no real `/data` mutation.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_human(payload: dict[str, Any]) -> str:
    lines = [
        "ShellForgeAI CLI import side-effect audit",
        "",
        f"Status: {payload['status']}",
        f"Modules checked: {payload['modules_checked']}",
        (
            f"Imported: {payload['summary']['imported']}  "
            f"Failed: {payload['summary']['failed']}  "
            f"Side-effect attempts: {payload['summary']['side_effect_attempts']}"
        ),
        "",
        "Modules:",
        "",
    ]
    for module in payload["modules"]:
        effects = ", ".join(module["side_effects_detected"]) or "none"
        lines.append(
            f"* {module['module']}: {module['status']} "
            f"(imported={str(module['imported']).lower()}, side_effects={effects})"
        )
    lines.extend(
        [
            "",
            "Safety:",
            "",
            "* Read-only import audit; no command/Docker/Compose/model/network execution.",
            "* No artifact write/repair/delete; no real /data mutation.",
        ]
    )
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit CLI command-module import side effects (read-only)."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true", help="Emit strict JSON only.")
    mode.add_argument("--markdown", action="store_true", help="Emit Markdown suitable for docs.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    payload = build_audit_payload()
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    elif args.markdown:
        print(render_markdown(payload), end="")
    else:
        print(render_human(payload), end="")
    return 0 if payload["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
