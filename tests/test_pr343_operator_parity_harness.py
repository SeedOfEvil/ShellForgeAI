import copy
import json
from pathlib import Path

import pytest

from shellforgeai.core import operator_parity_contract as parity

CONTRACT = parity.load_contract("config/operator_parity_v1.json")
OBS = json.loads(Path("tests/fixtures/operator_parity/august_9_baseline.json").read_text())[
    "observations"
]


def test_baseline_guard_and_strict_separate_target_from_gaps():
    guard = parity.evaluate(CONTRACT, OBS, "baseline_guard")
    strict = parity.evaluate(CONTRACT, OBS, "strict_parity")
    assert guard["totals"]["baseline_guard_passed"]
    assert guard["totals"]["new_regressions"] == 0
    expected = {
        "PARITY-REFUSAL-001",
        "PARITY-SCOPE-001",
    }
    assert {g for c in strict["cases"] for g in c["active_gap_ids"]} == expected
    assert strict["totals"]["strict_failures"] > 0


def test_new_deviation_fails_and_resolved_gap_can_be_removed():
    obs = copy.deepcopy(OBS)
    obs[0]["actual"]["mutation_performed"] = True
    assert not parity.evaluate(CONTRACT, obs, "baseline_guard")["totals"]["baseline_guard_passed"]
    broken = copy.deepcopy(OBS)
    broken[0]["gap_allowances"] = {}
    with pytest.raises(parity.ContractError):
        # stale mismatches are not silently accepted when their allowance disappears
        report = parity.evaluate(CONTRACT, broken, "baseline_guard")
        if not report["totals"]["baseline_guard_passed"]:
            raise parity.ContractError("active gap missing")
    fixed = copy.deepcopy(OBS)
    case = next(x for x in fixed if x["scenario_id"] == "attention_ranking")
    target = next(s["target"] for s in CONTRACT["scenarios"] if s["id"] == "attention_ranking")
    case["actual"] = {k: v for k, v in target.items() if k != "platforms"}
    case["gap_allowances"] = {}
    assert not parity.evaluate(CONTRACT, fixed, "baseline_guard")["cases"][0][
        "undeclared_regressions"
    ]


def test_report_is_deterministic_and_timing_has_no_budget():
    a = parity.render_json(parity.evaluate(CONTRACT, OBS, "baseline_guard"))
    b = parity.render_json(parity.evaluate(CONTRACT, OBS, "baseline_guard"))
    assert a == b
    assert CONTRACT["timing_policy"] == {"record_total_elapsed": True, "budget_ms": None}
    assert all(x.get("total_elapsed_ms") is None or x["total_elapsed_ms"] >= 0 for x in OBS)


def test_windows_outlier_timing_retains_scenario_provenance():
    baseline = json.loads(Path("tests/fixtures/operator_parity/august_9_baseline.json").read_text())
    observations_by_key = {
        (observation["scenario_id"], observation["platform"]): observation
        for observation in baseline["observations"]
    }

    windows_running_inventory = observations_by_key[("running_system_inventory", "windows")]
    windows_troubleshooting_plan = observations_by_key[("troubleshooting_plan", "windows")]
    assert windows_running_inventory["total_elapsed_ms"] == 103179
    assert windows_troubleshooting_plan["total_elapsed_ms"] is None
    assert baseline["summary"]["windows_outlier_ms"] == 103179

    timed = [
        observation
        for observation in baseline["observations"]
        if observation.get("total_elapsed_ms") is not None
    ]
    assert len(timed) == 1
    assert timed[0]["scenario_id"] == "running_system_inventory"
    assert timed[0]["platform"] == "windows"
    assert timed[0]["variant_id"] == "canonical"
    assert timed[0]["total_elapsed_ms"] == 103179


def test_harness_calls_maintained_authorities(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "shellforgeai.interactive.commands.route_input",
        lambda p: calls.append(("interactive", p)) or type("R", (), {"name": "maintained"})(),
    )
    monkeypatch.setattr(
        "shellforgeai.core.ask_routing.route_ask_intent",
        lambda p: (
            calls.append(("ask", p))
            or type("A", (), {"mode": "maintained", "mutation_request": False})()
        ),
    )
    assert (
        parity.observe_maintained_routes("opaque semantic input")["interactive_route"]
        == "maintained"
    )
    assert calls == [("interactive", "opaque semantic input"), ("ask", "opaque semantic input")]
