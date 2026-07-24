#!/usr/bin/env python3
"""Validate a saved PR313 Windows runtime reconciliation execution receipt bundle.

Read-only saved-artifact validation only.  It never reconciles, repairs, restores,
prunes backups, or mutates anything.
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
    validate_saved_receipt,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", help="receipt id, receipt directory, or receipt JSON path")
    parser.add_argument("--data-dir", required=True, help="ShellForgeAI-owned receipt/data root")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    result = validate_saved_receipt(args.receipt, args.data_dir)
    accepted = result.get("status") == "ok"
    payload = {"accepted": accepted, **result}
    if args.json:
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    else:
        print("accepted" if accepted else f"rejected ({result.get('status')})")
        for failure in result.get("failures") or []:
            print(f"- {failure}")
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
