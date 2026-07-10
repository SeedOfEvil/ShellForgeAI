"""PR290: evidence-aware Windows authenticated answer grounding tests.

Offline fixtures only: no network, no real model calls, no auth-cache reads, and
no subprocess execution. These tests pin the QA helper to compare answers with
the structured Windows evidence packet from the same run instead of accepting
(or rejecting) brittle fixed phrases.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "windows_authenticated_model_acceptance.py"
)


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("windows_authenticated_model_acceptance", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


wama = _load_module()

PACKET = {
    "platform": "windows",
    "read_only": True,
    "mutation_performed": False,
    "processes": {
        "available": True,
        "total_count": 74,
        "returned_count": 10,
        "limit": 10,
        "truncated": True,
        "collection": "read_only",
        "entries": [
            {"pid": 4, "name": "System", "thread_count": 150},
            {"pid": 888, "name": "svchost.exe", "thread_count": 13},
            {"pid": 1200, "name": "lsass.exe", "thread_count": 8},
        ],
    },
    "services": {
        "available": True,
        "total_count": 131,
        "running_count": 53,
        "stopped_count": 78,
        "returned_count": 10,
        "limit": 10,
        "collection": "read_only",
        "entries": [
            {"name": "BalloonService", "state": "running"},
            {"name": "beszel-agent", "state": "running"},
            {"name": "BFE", "state": "running"},
        ],
    },
}


def _summary(answer: str, packet: dict = PACKET) -> dict:
    return wama.build_summary(
        codex_login_checked=True,
        codex_logged_in=True,
        codex_home_configured=True,
        same_process_context=True,
        packet=packet,
        answer=answer,
        model_assisted_answer_ran=True,
        targeted_tests_exit_code=0,
        targeted_tests_output="........ [100%]\n",
    )


def test_positive_grounded_answer_matches_structured_process_and_service_facts() -> None:
    answer = (
        "This Windows host has 74 processes visible, with 10 included in the bounded "
        "preview. The host reports 131 services: 53 running and 78 stopped; examples "
        "include BalloonService, beszel-agent, and BFE."
    )
    result = wama.evaluate_answer_grounding(answer, PACKET)
    assert result.process_grounding_detected is True
    assert result.service_grounding_detected is True
    assert result.answer_uses_process_or_service_evidence is True
    assert "process_total=74" in result.matched_process_facts
    assert "process_returned=10" in result.matched_process_facts
    assert "service_total=131" in result.matched_service_facts
    assert "service_running=53" in result.matched_service_facts
    summary = _summary(answer)
    assert summary["validation_status"] == "PASS"
    assert summary["fallback_used"] is False


def test_natural_name_only_variants_match_only_names_from_fixture() -> None:
    answer = (
        "The bounded process list includes System and other Windows core processes. "
        "Examples of visible services include BalloonService, beszel-agent, and BFE."
    )
    result = wama.evaluate_answer_grounding(answer, PACKET)
    assert result.answer_uses_process_or_service_evidence is True
    assert "process_name=System" in result.matched_process_facts
    assert "service_name=BalloonService" in result.matched_service_facts


def test_memory_disk_only_answer_rejected_when_process_service_available() -> None:
    summary = _summary("Memory usage is moderate and the C: disk has free space.")
    assert summary["process_grounding_detected"] is False
    assert summary["service_grounding_detected"] is False
    assert summary["missing_required_grounding"] == ["process", "service"]
    assert summary["answer_uses_process_or_service_evidence"] is False
    assert summary["validation_status"] == "HOLD"


def test_generic_language_and_safe_commands_only_are_rejected() -> None:
    for answer in (
        "Processes and services look normal.",
        "Check what is running. Review processes and services.",
        "sfai.cmd windows processes --json --limit 10 and sfai.cmd windows services --json",
    ):
        assert _summary(answer)["validation_status"] == "HOLD"
        assert _summary(answer)["answer_uses_process_or_service_evidence"] is False


def test_one_category_only_rejected_and_reports_missing_category() -> None:
    process_only = _summary("There are 74 processes visible, showing 10 of 74 processes.")
    assert process_only["process_grounding_detected"] is True
    assert process_only["service_grounding_detected"] is False
    assert process_only["missing_required_grounding"] == ["service"]
    assert process_only["validation_status"] == "HOLD"

    service_only = _summary("The host reports 131 services, with 53 running and 78 stopped.")
    assert service_only["service_grounding_detected"] is True
    assert service_only["process_grounding_detected"] is False
    assert service_only["missing_required_grounding"] == ["process"]
    assert service_only["validation_status"] == "HOLD"


def test_missing_process_evidence_gap_plus_available_service_grounding_passes() -> None:
    packet = dict(PACKET)
    packet["processes"] = {
        "available": False,
        "limitation": "Process detail is not present in this evidence packet",
    }
    answer = (
        "I do not have process detail in this evidence packet. To fill that gap, run "
        "sfai.cmd windows processes --json --limit 10. The service evidence reports "
        "131 services, with 53 running and 78 stopped."
    )
    summary = _summary(answer, packet)
    assert summary["process_grounding_detected"] is True
    assert summary["service_grounding_detected"] is True
    assert summary["answer_uses_process_or_service_evidence"] is True
    assert summary["validation_status"] == "PASS"


def test_missing_service_evidence_gap_plus_available_process_grounding_passes() -> None:
    packet = dict(PACKET)
    packet["services"] = {
        "available": False,
        "limitation": "Service detail is not present in this evidence packet",
    }
    answer = (
        "There are 74 processes visible, with 10 in the bounded preview. I do not "
        "have service detail in this evidence packet; run sfai.cmd windows services --json."
    )
    summary = _summary(answer, packet)
    assert summary["process_grounding_detected"] is True
    assert summary["service_grounding_detected"] is True
    assert summary["validation_status"] == "PASS"


def test_fallback_and_bad_preamble_rejections_still_hold() -> None:
    fallback = _summary("Model assistance is unavailable. Processes total=74 services total=131.")
    assert fallback["fallback_used"] is True
    assert fallback["model_assisted_answer_ran"] is False
    assert fallback["validation_status"] == "HOLD"

    preamble = _summary("Understood. I’ll follow the project constraints and repo invariants.")
    assert preamble["bad_preamble_detected"] is True
    assert preamble["validation_status"] == "HOLD"


def test_invented_counts_or_names_do_not_match_fixture() -> None:
    summary = _summary("There are 99 processes and 222 services. Examples include FakeSvc.")
    assert summary["matched_process_facts"] == []
    assert summary["matched_service_facts"] == []
    assert summary["validation_status"] == "HOLD"


def test_report_includes_explainable_grounding_fields() -> None:
    summary = _summary("There are 74 processes visible, including System.")
    for key in (
        "process_evidence_available",
        "service_evidence_available",
        "process_grounding_detected",
        "service_grounding_detected",
        "matched_process_facts",
        "matched_service_facts",
        "missing_required_grounding",
        "grounding_reason",
    ):
        assert key in summary
    assert summary["matched_process_facts"]
    assert summary["missing_required_grounding"] == ["service"]
    assert "missing required grounding" in summary["grounding_reason"]


def test_safety_source_regression() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    docstring = ast.get_docstring(tree) or ""
    code_only = source.replace(docstring, "")
    forbidden = (
        "shell=True",
        "Power" + "Shell",
        "Win" + "RM",
        "os.system",
        "auth.json",
        "requests.",
        "urllib.",
    )
    for token in forbidden:
        assert token not in code_only
