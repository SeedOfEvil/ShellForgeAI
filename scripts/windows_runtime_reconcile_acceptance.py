#!/usr/bin/env python3
"""Validate saved Windows runtime reconcile preflight packets.

The acceptance rules themselves live in exactly one place,
``shellforgeai.core.windows_runtime_reconcile_plan_contract``, so this
standalone entry point, the PR313 execution lane, and the PR323 plan-link layer
can never drift from one another. This file keeps the operator CLI shape and
delegates every rule.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _bootstrap() -> None:
    """Support direct invocation from an exact source checkout."""
    try:
        import shellforgeai  # noqa: F401
    except ModuleNotFoundError:
        src = Path(__file__).resolve().parent.parent / "src"
        if src.is_dir():
            sys.path.insert(0, str(src))


_bootstrap()

from shellforgeai.core.windows_runtime_reconcile_plan_contract import (  # noqa: E402
    ALLOWLIST,
    AUTHORIZED_PARENT_DIRECTORIES,
    PARENT_CONTRACT_VERSION,
    PARENT_CREATION_ALLOWED,
    PARENT_RELATIVE,
    PARENT_STATES,
    PLAN_MODE,
    PLAN_OPERATIONS,
    PLAN_STATUSES,
    RECIPE_ID,
    REQUIRED_FUTURE_GATES,
    UNSAFE_SAFETY_FALSE_KEYS,
    destination_parent_contract_errors,
    saved_plan_packet_acceptance_errors,
)

# Maintained names kept for the operator-facing surface and existing consumers.
MODE = PLAN_MODE
RECIPE = RECIPE_ID
STAT = set(PLAN_STATUSES)
OPS = PLAN_OPERATIONS
ALLOW = list(ALLOWLIST)
FUT = set(REQUIRED_FUTURE_GATES)
FALSE = UNSAFE_SAFETY_FALSE_KEYS

__all__ = [
    "ALLOW",
    "AUTHORIZED_PARENT_DIRECTORIES",
    "FALSE",
    "FUT",
    "MODE",
    "OPS",
    "PARENT_CONTRACT_VERSION",
    "PARENT_CREATION_ALLOWED",
    "PARENT_RELATIVE",
    "PARENT_STATES",
    "RECIPE",
    "STAT",
    "errs",
    "main",
    "parent_errs",
    "read",
]


def parent_errs(op: dict[str, Any]) -> list[str]:
    """Validate the exact fixed destination-parent contract for one operation."""
    return destination_parent_contract_errors(op)


def errs(p: dict[str, Any]) -> list[str]:
    """Return every maintained acceptance failure for one saved packet."""
    return saved_plan_packet_acceptance_errors(p)


def read(path: Path):
    try:
        p = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(p, dict):
            return None, ["JSON must be object"]
        return p, []
    except Exception as ex:
        return None, [f"invalid JSON: {ex.__class__.__name__}: {str(ex)[:160]}"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("packet")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    p, e = read(Path(a.packet))
    e = e + (errs(p) if p else [])
    r = {"accepted": not e, "failures": e}
    print(
        json.dumps(r, sort_keys=True, separators=(",", ":"))
        if a.json
        else ("accepted" if not e else "rejected\n- " + "\n- ".join(e))
    )
    return 0 if not e else 1


if __name__ == "__main__":
    raise SystemExit(main())
