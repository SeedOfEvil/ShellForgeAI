#!/usr/bin/env python3
"""Read-only post-change verification for the PR313 Windows reconciliation lane.

It consumes one validated execution receipt plus two fresh PR304 artifacts (one
from the staged source context and one produced with the process CWD set to
``C:\\Windows\\System32``) and re-checks the durable runtime.  It never repairs,
restores, rolls back, prunes, or mutates anything.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _bootstrap() -> None:
    """Support direct invocation from an exact source checkout."""
    try:
        import shellforgeai  # noqa: F401
    except ModuleNotFoundError:
        src = Path(__file__).resolve().parent.parent / "src"
        if src.is_dir():
            sys.path.insert(0, str(src))


_bootstrap()

from shellforgeai.core.windows_runtime_reconcile_execution import (  # noqa: E402
    VERIFY_STATUS_UNSUPPORTED,
    VERIFY_STATUS_VERIFIED,
    load_validators,
    verify_windows_runtime_reconcile,
)


def render_text(result: dict) -> str:
    lines = [
        "ShellForgeAI Windows runtime reconciliation verification",
        f"Status: {result.get('status')}",
        f"Reason: {result.get('reason')}",
        f"Receipt: {result.get('receipt_id')}",
        "Read-only: true; mutation performed: false; repair executed: false.",
    ]
    for item in result.get("operations") or []:
        lines.append(f"- {item.get('relative_destination')}: {item.get('result')}")
    for failure in result.get("failures") or []:
        lines.append(f"! {failure}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", help="receipt id, receipt directory, or receipt JSON path")
    parser.add_argument("--staged-pr304", required=True)
    parser.add_argument("--system32-pr304", required=True)
    parser.add_argument("--staged-source-root", required=True)
    parser.add_argument("--durable-runtime-root", required=True)
    parser.add_argument("--data-dir", required=True, help="ShellForgeAI-owned receipt/data root")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out-json", help="optionally save a ShellForgeAI-owned packet")
    args = parser.parse_args(argv)

    result = verify_windows_runtime_reconcile(
        args.receipt,
        staged_pr304=args.staged_pr304,
        system32_pr304=args.system32_pr304,
        staged_source_root=args.staged_source_root,
        durable_runtime_root=args.durable_runtime_root,
        data_dir=args.data_dir,
        validators=load_validators(Path(__file__).resolve().parent),
    )
    text = json.dumps(result, sort_keys=True, separators=(",", ":"))
    if args.out_json:
        out = Path(args.out_json)
        if out.exists():
            parser.error(f"refusing to overwrite existing artifact: {out}")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
    print(text if args.json else render_text(result))
    if result.get("status") in {VERIFY_STATUS_VERIFIED, VERIFY_STATUS_UNSUPPORTED}:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
