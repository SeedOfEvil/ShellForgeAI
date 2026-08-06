#!/usr/bin/env python3
"""Validate saved Windows runtime integrity JSON artifacts only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from shellforgeai.core.windows_runtime_integrity_contract import (
    ALLOWED_STATUS,
    compare_stable_fields,
    packet_validation_errors,
)


def validate(payload: dict[str, Any], expect_status: str | None = None) -> list[str]:
    return packet_validation_errors(payload, expect_status)


def read_artifact(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, [f"{path}: invalid JSON: {exc}"]
    if not isinstance(payload, dict):
        return None, [f"{path}: JSON must be an object"]
    return payload, []


def compare(payloads: list[dict[str, Any]]) -> list[str]:
    return compare_stable_fields(payloads)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="+")
    parser.add_argument("--expect-status", choices=sorted(ALLOWED_STATUS))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    payloads: list[dict[str, Any]] = []
    failures: list[str] = []
    for value in args.artifacts:
        payload, errs = read_artifact(Path(value))
        failures.extend(errs)
        if payload is not None:
            payloads.append(payload)
            failures.extend(f"{value}: {err}" for err in validate(payload, args.expect_status))
    failures.extend(compare(payloads))
    result = {"accepted": not failures, "artifact_count": len(args.artifacts), "failures": failures}
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print("accepted" if not failures else "rejected")
        for failure in failures:
            print(f"- {failure}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
