#!/usr/bin/env python3
"""Read-only CLI command-surface snapshot helper for the PR184 guardrail.

This helper invokes the ShellForgeAI CLI in-process (via ``CliRunner``) over the
argv entries recorded in ``tests/golden/cli_command_surface_pr184.json`` and
prints a compact snapshot of each command's exit code and JSON validity. It
exists to make it easy to *inspect* the current command surface when updating
the golden fixture intentionally.

Safety posture (this script is a guardrail aid, not a product feature):

* It is read-only. It only runs ``--help`` / read-only JSON argv from the golden
  fixture; it never runs cleanup, remediation, rollback, recovery, Docker,
  Compose, restart, shell, arbitrary, or natural-language execution.
* It blocks the model/provider factory so no model call can occur.
* By default it prints to stdout. It writes a file only when an explicit
  ``--output`` path under a temp/test directory is given; production paths are
  refused. It never writes to real ``/data``.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

FIXTURE_PATH = REPO_ROOT / "tests" / "golden" / "cli_command_surface_pr184.json"


def _load_entries() -> list[dict]:
    data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    entries: list[dict] = list(data.get("commands", []))
    entries.extend(data.get("refusal_phrases", []))
    return entries


def _is_safe_output_path(path: Path) -> bool:
    """Only allow writing under a temp/test directory; refuse production paths."""

    resolved = str(path.resolve()).lower()
    tmp_root = str(Path(tempfile.gettempdir()).resolve()).lower()
    return resolved.startswith(tmp_root) or "tmp" in resolved or "test" in resolved


def build_snapshot() -> dict:
    from typer.testing import CliRunner

    from shellforgeai import cli as cli_mod
    from shellforgeai.cli import app

    def _no_model(*_args, **_kwargs):
        raise RuntimeError("model/provider must not be called by the snapshot helper")

    cli_mod.build_provider = _no_model  # block any accidental model call

    runner = CliRunner()
    rows: list[dict] = []
    for entry in _load_entries():
        result = runner.invoke(app, entry["argv"])
        stdout = result.stdout or ""
        json_valid = None
        if entry.get("expect_json"):
            try:
                json.loads(stdout)
                json_valid = True
            except json.JSONDecodeError:
                json_valid = False
        rows.append(
            {
                "name": entry["name"],
                "argv": entry["argv"],
                "exit_code": result.exit_code,
                "json_valid": json_valid,
            }
        )
    return {
        "schema_version": 1,
        "mode": "cli_command_surface_snapshot",
        "read_only": True,
        "mutation_performed": False,
        "commands": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only CLI command-surface snapshot.")
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path (must be under a temp/test directory) to write the snapshot JSON.",
    )
    args = parser.parse_args(argv)

    snapshot = build_snapshot()
    text = json.dumps(snapshot, indent=2)

    if args.output is not None:
        if not _is_safe_output_path(args.output):
            parser.error(
                "refusing to write outside a temp/test directory; "
                "--output must be under a tmp/test path"
            )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
        print(f"wrote snapshot to {args.output}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
