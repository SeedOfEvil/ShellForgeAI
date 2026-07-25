#!/usr/bin/env python3
"""Execute the governed two-file Windows durable-runtime reconciliation (PR313).

This is the authoritative direct entry point.  It is invoked with an exact Python
interpreter and an exact source checkout and never depends on the durable
``sfai.cmd`` wrapper it may be repairing.
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
    ALLOWLIST,
    STATUS_BLOCKED,
    STATUS_EXECUTED,
    STATUS_NO_CHANGE,
    STATUS_PARTIAL_EXECUTED,
    STATUS_UNSUPPORTED,
    execute_windows_runtime_reconcile,
    load_validators,
)

_OK_STATUSES = {STATUS_EXECUTED, STATUS_PARTIAL_EXECUTED, STATUS_NO_CHANGE, STATUS_UNSUPPORTED}


def render_text(result: dict) -> str:
    lines = [
        "ShellForgeAI Windows runtime reconciliation execute",
        f"Status: {result.get('status')}",
        f"Reason: {result.get('reason')}",
        f"Receipt: {result.get('receipt_id')}",
        f"Mutation performed: {str(bool(result.get('mutation_performed'))).lower()}",
        "Allowlist: " + "; ".join(f"{a} -> {b}" for a, b in ALLOWLIST),
    ]
    for item in result.get("operations") or []:
        lines.append(
            f"- {item.get('relative_source')} -> {item.get('relative_destination')}: "
            f"saved={item.get('saved_operation')} "
            f"revalidated={item.get('revalidated_operation')} "
            f"mutated={str(bool(item.get('mutation_performed'))).lower()}"
        )
    for blocker in result.get("blockers") or []:
        lines.append(f"! {blocker}")
    for warning in result.get("warnings") or []:
        lines.append(f"~ {warning}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", help="saved PR305 windows_runtime_reconcile packet")
    parser.add_argument(
        "artifacts", nargs="+", help="one or two fresh PR304 runtime-integrity artifacts"
    )
    parser.add_argument("--staged-source-root", required=True)
    parser.add_argument("--durable-runtime-root", required=True)
    parser.add_argument(
        "--confirm-plan-sha256",
        required=True,
        help="exact canonical SHA-256 of the accepted PR305 packet (64 lowercase hex)",
    )
    parser.add_argument("--data-dir", required=True, help="ShellForgeAI-owned receipt/data root")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    result = execute_windows_runtime_reconcile(
        args.packet,
        args.artifacts,
        staged_source_root=args.staged_source_root,
        durable_runtime_root=args.durable_runtime_root,
        confirm_plan_sha256=args.confirm_plan_sha256,
        data_dir=args.data_dir,
        validators=load_validators(Path(__file__).resolve().parent),
    )
    print(
        json.dumps(result, sort_keys=True, separators=(",", ":"))
        if args.json
        else render_text(result)
    )
    if result.get("status") in _OK_STATUSES:
        return 0
    return 1 if result.get("status") == STATUS_BLOCKED else 2


if __name__ == "__main__":
    raise SystemExit(main())
