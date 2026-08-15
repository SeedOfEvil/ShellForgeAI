from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from shellforgeai.core.diagnose import DiagnosisResult, Finding
from shellforgeai.core.evidence import EvidenceBundle, EvidenceCategory, EvidenceItem, TargetType
from shellforgeai.core.operator_solution import (
    canonical_operator_solution_json,
    compute_operator_solution_sha256,
    render_operator_solution_markdown,
    validate_operator_solution,
)
from shellforgeai.core.operator_solution_builder import (
    OperatorSolutionBuildError,
    build_linux_operator_solution_from_diagnosis,
)
from shellforgeai.core.plans import Plan, PlanStep


def _diagnosis(
    *,
    created_at: datetime | None = None,
    plan_id: str = "plan-random-one",
    windows: bool = False,
    safety: dict[str, bool] | None = None,
    findings: list[Finding] | None = None,
    docker: bool = True,
) -> DiagnosisResult:
    items = [
        EvidenceItem(
            source="platform.detect" if windows else "host.resources",
            category=EvidenceCategory.host,
            title="Platform" if windows else "Host resources",
            summary="Structured platform record" if windows else "Capacity pressure observed",
            content=json.dumps({"system": "windows"}) if windows else "bounded sample",
            metadata={"platform": "windows"} if windows else {},
        )
    ]
    if docker:
        items.append(
            EvidenceItem(
                source="docker.problem_summary",
                category=EvidenceCategory.service,
                title="Docker problem summary",
                summary="One container is restarting",
                content=json.dumps(
                    {
                        "failing": [
                            {
                                "name": "api",
                                "state": "restarting",
                                "exit_code": 1,
                                "log_themes": {"simulated_crash": True},
                            }
                        ]
                    }
                ),
            )
        )
    finding_values = findings or [
        Finding(
            severity="critical",
            title="API container restart loop",
            detail="The bounded container state shows repeated restarts.",
            evidence_refs=["docker.problem_summary"],
            confidence="high",
        ),
        Finding(
            severity="limitation",
            title="Host journal unavailable",
            detail="The container namespace cannot see the host journal.",
            confidence="high",
        ),
        Finding(severity="info", title="Inventory captured", detail="Inventory is point-in-time."),
    ]
    plan = Plan(
        plan_id=plan_id,
        goal="Stabilize the diagnosed target",
        created_at=created_at or datetime(2025, 1, 1, tzinfo=timezone.utc),
        session_id="session-359",
        steps=[
            PlanStep(
                step_id="random-step-id",
                title="Review evidence",
                description="Review the bounded diagnosis before operator action.",
            )
        ],
    )
    return DiagnosisResult(
        session_id="session-359",
        target="api",
        target_type=TargetType.service,
        created_at=created_at or datetime(2025, 1, 1, tzinfo=timezone.utc),
        evidence=EvidenceBundle(target="api", target_type=TargetType.service, items=items),
        findings=finding_values,
        proposed_plan=plan,
        runtime_context={
            "visibility": "windows_local_read_only" if windows else "container_limited",
            "limitations": ["Host process visibility may be incomplete."],
        },
        safety=safety
        or {
            "read_only": True,
            "mutation_performed": False,
            "remediation_executed": False,
            "natural_language_execution": False,
        },
    )


def test_linux_docker_diagnosis_builds_valid_advisory_solution_with_provenance() -> None:
    solution = build_linux_operator_solution_from_diagnosis(_diagnosis())
    assert validate_operator_solution(solution).valid
    assert solution.platform_system == "linux"
    assert solution.advisory_only and solution.read_only
    assert not solution.mutation_performed
    assert not solution.execution_allowed and not solution.execution_available
    assert solution.execution_status == "not_executed"
    declared = {ref.ref for ref in solution.provenance_references}
    for item in (*solution.likely_causes, *solution.procedure, *solution.verification_criteria):
        assert item.evidence_refs
        assert set(item.evidence_refs) <= declared
    assert any(
        ref.startswith("runbook:") for step in solution.procedure for ref in step.evidence_refs
    )
    assert solution.alternatives == ()
    assert solution.risk.value == "medium"
    assert "Brief downtime" in solution.expected_impact
    assert solution.rollback_recovery.mode.value == "rollback"


def test_only_actionable_findings_become_causes_and_limits_remain_visible() -> None:
    solution = build_linux_operator_solution_from_diagnosis(_diagnosis())
    assert [cause.inference for cause in solution.likely_causes] == ["API container restart loop"]
    assert any("host journal" in limit.lower() for limit in solution.visibility_limits)


def test_plan_is_safe_fallback_when_runbook_has_no_corrective_option() -> None:
    solution = build_linux_operator_solution_from_diagnosis(_diagnosis(docker=False))
    assert [step.title for step in solution.procedure] == ["Review evidence"]
    assert solution.procedure[0].evidence_refs == ("plan:diagnosis-proposed",)
    assert solution.rollback_recovery.mode.value == "not_applicable"
    assert solution.rollback_recovery.guidance == ()


@pytest.mark.parametrize(
    "safety_key",
    [
        "mutation_performed",
        "natural_language_execution",
        "arbitrary_command_execution",
        "shell_true",
        "remediation_executed",
        "rollback_executed",
        "cleanup_executed",
        "docker_compose_executed",
        "container_restarted",
    ],
)
def test_unsafe_diagnosis_state_fails_closed(safety_key: str) -> None:
    with pytest.raises(OperatorSolutionBuildError, match="incompatible"):
        build_linux_operator_solution_from_diagnosis(_diagnosis(safety={safety_key: True}))


def test_windows_and_insufficient_evidence_fail_closed() -> None:
    with pytest.raises(OperatorSolutionBuildError, match="Windows"):
        build_linux_operator_solution_from_diagnosis(_diagnosis(windows=True))
    diagnosis = _diagnosis()
    diagnosis.evidence.items = []
    with pytest.raises(OperatorSolutionBuildError, match="insufficient"):
        build_linux_operator_solution_from_diagnosis(diagnosis)


def test_nondeterministic_upstream_fields_do_not_affect_any_canonical_form(monkeypatch) -> None:
    first = _diagnosis(created_at=datetime(2025, 1, 1, tzinfo=timezone.utc), plan_id="random-a")
    second = _diagnosis(created_at=datetime(2035, 2, 2, tzinfo=timezone.utc), plan_id="random-b")
    import shellforgeai.core.operator_solution_builder as builder

    real_build = builder.build_runbook
    times = iter(
        [datetime(2020, 1, 1, tzinfo=timezone.utc), datetime(2040, 1, 1, tzinfo=timezone.utc)]
    )

    def build_with_different_time(**kwargs):
        runbook = real_build(**kwargs)
        runbook.generated_at = next(times)
        return runbook

    monkeypatch.setattr(builder, "build_runbook", build_with_different_time)
    one = build_linux_operator_solution_from_diagnosis(first)
    two = build_linux_operator_solution_from_diagnosis(second)
    assert one.solution_id == two.solution_id
    assert canonical_operator_solution_json(one) == canonical_operator_solution_json(two)
    assert render_operator_solution_markdown(one) == render_operator_solution_markdown(two)
    assert compute_operator_solution_sha256(one) == compute_operator_solution_sha256(two)


def test_material_represented_change_changes_solution_sha() -> None:
    first = build_linux_operator_solution_from_diagnosis(_diagnosis())
    changed = _diagnosis()
    changed.findings[0].detail = "A materially different restart pattern was observed."
    second = build_linux_operator_solution_from_diagnosis(changed)
    assert compute_operator_solution_sha256(first) != compute_operator_solution_sha256(second)


def test_duplicate_content_is_deduplicated_without_reordering() -> None:
    diagnosis = _diagnosis(docker=False)
    diagnosis.proposed_plan.steps.extend(
        [
            diagnosis.proposed_plan.steps[0].model_copy(),
            PlanStep(step_id="2", title="Next", description="Then inspect state."),
        ]
    )
    solution = build_linux_operator_solution_from_diagnosis(diagnosis)
    assert [step.instruction for step in solution.procedure] == [
        "Review the bounded diagnosis before operator action.",
        "Then inspect state.",
    ]
    # Shared runbook list fields are also safely deduped.
    assert len(solution.prerequisites) == len(set(solution.prerequisites))
    assert len(solution.verification_criteria) == len(
        {criterion.criterion for criterion in solution.verification_criteria}
    )


def test_solution_contains_no_raw_or_whole_upstream_payload() -> None:
    diagnosis = _diagnosis()
    raw_marker = "RAW-EVIDENCE-MUST-NOT-LEAK"
    diagnosis.evidence.items[0].content = raw_marker
    solution = build_linux_operator_solution_from_diagnosis(diagnosis)
    payload = canonical_operator_solution_json(solution)
    assert raw_marker not in payload
    assert not {"evidence", "diagnosis_result", "plan", "runbook"} & solution.model_fields_set


def test_builder_has_no_nondeterministic_execution_or_runtime_dependencies() -> None:
    source = Path("src/shellforgeai/core/operator_solution_builder.py").read_text(encoding="utf-8")
    forbidden = (
        "datetime",
        "uuid",
        "random",
        "os.environ",
        "socket",
        "subprocess",
        "shell=True",
        "httpx",
        "requests",
        "shellforgeai.llm",
        "detect_platform",
        "diagnose_target(",
        "collect_",
    )
    assert all(term not in source for term in forbidden)
    assert not dataclasses.is_dataclass(build_linux_operator_solution_from_diagnosis(_diagnosis()))
