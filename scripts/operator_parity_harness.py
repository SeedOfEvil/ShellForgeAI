#!/usr/bin/env python3
"""Evaluate normalized parity observations without live collection or providers."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from shellforgeai.core.operator_parity_contract import evaluate, load_contract, render_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", default="config/operator_parity_v1.json")
    parser.add_argument(
        "--observations", default="tests/fixtures/operator_parity/august_9_baseline.json"
    )
    parser.add_argument("--mode", choices=("baseline_guard", "strict_parity"), required=True)
    args = parser.parse_args()
    report = evaluate(
        load_contract(args.contract),
        json.loads(Path(args.observations).read_text(encoding="utf-8"))["observations"],
        args.mode,
    )
    print(render_json(report), end="")
    return (
        0
        if args.mode == "strict_parity"
        and report["totals"]["strict_failures"] == 0
        or args.mode == "baseline_guard"
        and report["totals"]["baseline_guard_passed"]
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
