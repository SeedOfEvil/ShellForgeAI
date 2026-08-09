"""Pure V1 Linux/Windows operator-parity contract validation and audit.

This module never collects evidence or routes text. Runtime observation uses the
maintained routing authorities exposed by :func:`observe_maintained_routes`;
fixture evaluation remains deterministic and side-effect free.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CONTRACT_ID = "linux_windows_operator_parity_v1"
HARNESS_VERSION = 1
MODES = ("baseline_guard", "strict_parity")
_TARGET_KEYS = {
    "semantic_intent",
    "safety_decision",
    "mutation_request",
    "natural_language_execution",
    "mutation_performed",
    "evidence_policy",
    "model_policy",
    "response_structure",
    "encoding",
    "timing_policy",
    "platforms",
}
_ENUMS = {
    "semantic_intent": {
        "read_only_inventory",
        "read_only_analysis",
        "read_only_health_assessment",
        "read_only_troubleshooting_plan",
        "mutation_request",
    },
    "safety_decision": {"allow_read_only_analysis", "refuse_natural_language_mutation"},
    "evidence_policy": {"required_platform_native", "optional", "unavailable"},
    "model_policy": {"model_after_evidence", "deterministic_no_model", "no_model"},
}


class ContractError(ValueError):
    """The parity contract or observation corpus is malformed."""


def load_contract(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_contract(data)
    return data


def validate_contract(data: dict[str, Any]) -> None:
    if set(data) != {
        "schema_version",
        "contract_id",
        "encoding_target",
        "timing_policy",
        "known_gaps",
        "scenarios",
    }:
        raise ContractError("unknown or missing top-level fields")
    if data["schema_version"] != 1 or data["contract_id"] != CONTRACT_ID:
        raise ContractError("unsupported V1 contract identity")
    if data["encoding_target"] != "utf-8" or data["timing_policy"] != {
        "record_total_elapsed": True,
        "budget_ms": None,
    }:
        raise ContractError("invalid encoding or timing policy")
    gaps = data["known_gaps"]
    if not isinstance(gaps, dict) or not gaps or "*" in gaps:
        raise ContractError("known gaps must be explicit")
    scenario_ids: set[str] = set()
    variant_ids: set[str] = set()
    for scenario in data["scenarios"]:
        if set(scenario) != {"id", "variants", "target", "known_gap_ids"}:
            raise ContractError("unknown or missing scenario fields")
        if scenario["id"] in scenario_ids:
            raise ContractError("duplicate scenario id")
        scenario_ids.add(scenario["id"])
        variants = scenario["variants"]
        canonical = [v for v in variants if v.get("kind") == "canonical"]
        if len(canonical) != 1 or sum(v.get("kind") == "paraphrase" for v in variants) < 2:
            raise ContractError("one canonical and two paraphrases required")
        prompts: set[str] = set()
        for variant in variants:
            if set(variant) != {"id", "kind", "prompt"} or variant["kind"] not in {
                "canonical",
                "paraphrase",
            }:
                raise ContractError("invalid variant")
            qualified = f"{scenario['id']}:{variant['id']}"
            if qualified in variant_ids or variant["prompt"] in prompts:
                raise ContractError("duplicate variant id or prompt")
            variant_ids.add(qualified)
            prompts.add(variant["prompt"])
        target = scenario["target"]
        if set(target) != _TARGET_KEYS:
            raise ContractError("invalid target dimensions")
        for key, allowed in _ENUMS.items():
            if target[key] not in allowed:
                raise ContractError(f"invalid {key}")
        if (
            target["encoding"] != "utf-8"
            or target["timing_policy"] != "record_total_elapsed_no_budget"
        ):
            raise ContractError("invalid scenario encoding or timing policy")
        if target["platforms"] != ["linux", "windows"]:
            raise ContractError("V1 applies to Linux and Windows")
        if any(gap not in gaps or gap == "*" for gap in scenario["known_gap_ids"]):
            raise ContractError("unresolved known-gap reference")


def observe_maintained_routes(prompt: str) -> dict[str, Any]:
    """Instrument maintained product authorities; never infer from prompt text here."""
    from shellforgeai.core.ask_routing import route_ask_intent
    from shellforgeai.interactive.commands import route_input

    routed = route_input(prompt)
    ask = route_ask_intent(prompt)
    return {
        "interactive_route": routed.name,
        "ask_mode": ask.mode,
        "mutation_request": ask.mutation_request,
    }


def evaluate(
    contract: dict[str, Any], observations: list[dict[str, Any]], mode: str
) -> dict[str, Any]:
    validate_contract(contract)
    if mode not in MODES:
        raise ContractError("unknown evaluation mode")
    scenarios = {s["id"]: s for s in contract["scenarios"]}
    cases = []
    for observed in sorted(
        observations, key=lambda x: (x["scenario_id"], x["variant_id"], x["platform"])
    ):
        scenario = scenarios.get(observed["scenario_id"])
        if scenario is None or observed["platform"] not in scenario["target"]["platforms"]:
            raise ContractError("unknown scenario or platform")
        if observed["variant_id"] not in {v["id"] for v in scenario["variants"]}:
            raise ContractError("unknown variant")
        elapsed = observed.get("total_elapsed_ms")
        if elapsed is not None and (
            not isinstance(elapsed, (int, float)) or isinstance(elapsed, bool) or elapsed < 0
        ):
            raise ContractError("elapsed time must be nonnegative numeric or null")
        actual = observed["actual"]
        compared = {
            key: actual.get(key) == value
            for key, value in scenario["target"].items()
            if key != "platforms"
        }
        failures = sorted(key for key, matched in compared.items() if not matched)
        allowances = observed.get("gap_allowances", {})
        if set(allowances) - set(failures) or any(
            g not in scenario["known_gap_ids"] for g in allowances.values()
        ):
            raise ContractError(
                "gap allowance must name a failing dimension and declared scenario gap"
            )
        active = sorted(set(allowances.values()))
        undeclared = sorted(key for key in failures if key not in allowances)
        passed = not failures if mode == "strict_parity" else not undeclared
        cases.append(
            {
                "scenario_id": observed["scenario_id"],
                "variant_id": observed["variant_id"],
                "platform": observed["platform"],
                "target": scenario["target"],
                "observed": actual,
                "target_matched": compared,
                "declared_known_gap_ids": scenario["known_gap_ids"],
                "active_gap_ids": active,
                "undeclared_regressions": undeclared,
                "total_elapsed_ms": elapsed,
                "passed": passed,
            }
        )
    strict_failures = sum(bool(c["active_gap_ids"] or c["undeclared_regressions"]) for c in cases)
    return {
        "schema_version": 1,
        "contract_id": CONTRACT_ID,
        "harness_version": HARNESS_VERSION,
        "evaluation_mode": mode,
        "cases": cases,
        "totals": {
            "total_cases": len(cases),
            "target_passed": sum(all(c["target_matched"].values()) for c in cases),
            "known_gap_cases": sum(bool(c["active_gap_ids"]) for c in cases),
            "new_regressions": sum(bool(c["undeclared_regressions"]) for c in cases),
            "strict_failures": strict_failures,
            "baseline_guard_passed": not any(c["undeclared_regressions"] for c in cases),
        },
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
