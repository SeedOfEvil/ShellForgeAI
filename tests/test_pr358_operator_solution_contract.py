from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from shellforgeai.core.evidence import EvidenceBundle, TargetType
from shellforgeai.core.operator_solution import (
    OperatorSolution,
    ProvenanceReference,
    RollbackRecoveryGuidance,
    canonical_operator_solution_json,
    compute_operator_solution_sha256,
    render_operator_solution_markdown,
    validate_operator_solution,
)


def solution_data(*, platform_system: str = "linux") -> dict[str, object]:
    return {
        "solution_id": "solution:disk-pressure",
        "session_ref": "session:123",
        "platform_system": platform_system,
        "target": "root filesystem",
        "target_type": "disk",
        "desired_outcome": "Restore sufficient free capacity without service interruption.",
        "diagnosis_summary": "Observed utilization is above the operator threshold.",
        "diagnosis_confidence": "high",
        "likely_causes": [
            {
                "id": "cause:logs",
                "inference": "Application logs are likely the main contributor.",
                "rationale": "The declared disk finding attributes most visible growth to logs.",
                "uncertainty": "Files hidden from the collector may contribute additional usage.",
                "evidence_refs": ["evidence:disk", "finding:usage"],
            }
        ],
        "provenance_references": [
            {"kind": "evidence", "ref": "evidence:disk"},
            {"kind": "finding", "ref": "finding:usage", "sha256": "a" * 64},
        ],
        "prerequisites": ["Obtain an operator maintenance window."],
        "expected_impact": "Free space should increase; log history may be reduced.",
        "blast_radius": "Limited to application log retention on the target host.",
        "risk": "medium",
        "procedure": [
            {
                "id": "step:inspect",
                "title": "Confirm candidates",
                "instruction": "As the operator, review log retention and exact file ownership.",
                "risk": "low",
                "evidence_refs": ["evidence:disk"],
            },
            {
                "id": "step:adjust",
                "title": "Adjust retention",
                "instruction": "As the operator, apply the approved retention change.",
                "risk": "medium",
                "evidence_refs": ["finding:usage"],
            },
        ],
        "alternatives": [
            {
                "id": "alternative:expand",
                "title": "Expand storage",
                "rationale": "Preserves all current log history.",
                "trade_offs": ["Requires additional capacity and cost."],
                "conditions": ["Use when retention cannot be reduced."],
            }
        ],
        "verification_criteria": [
            {
                "id": "verify:capacity",
                "criterion": "Operator confirms utilization is below the agreed threshold.",
                "evidence_refs": ["evidence:disk"],
            }
        ],
        "rollback_recovery": {
            "mode": "rollback",
            "guidance": ["Restore the previous retention configuration if errors appear."],
        },
        "assumptions": ["The evidence refers to the intended host."],
        "unresolved_questions": ["Is longer off-host retention required?"],
        "visibility_limits": ["No inaccessible or deleted-open files were observed."],
    }


def make_solution(**changes: object) -> OperatorSolution:
    data = solution_data()
    data.update(changes)
    return OperatorSolution.model_validate(data)


def test_v1_linux_contract_is_frozen_extra_forbidden_and_semantically_valid() -> None:
    solution = make_solution()
    assert solution.schema_version == "v1"
    assert solution.artifact_type == "operator_solution"
    assert solution.platform_system == "linux"
    assert solution.target_type is TargetType.disk
    assert validate_operator_solution(solution).valid is True
    with pytest.raises(ValidationError):
        OperatorSolution.model_validate({**solution_data(), "unknown": True})
    with pytest.raises(ValidationError):
        solution.target = "other"  # type: ignore[misc]


def test_valid_windows_instance_and_permanent_non_execution_posture() -> None:
    solution = make_solution(platform_system="windows")
    assert solution.platform_system == "windows"
    assert (solution.advisory_only, solution.read_only) == (True, True)
    assert not solution.mutation_performed
    assert not solution.execution_allowed
    assert not solution.execution_available
    assert solution.execution_status == "not_executed"
    for field, unsafe in (
        ("advisory_only", False),
        ("read_only", False),
        ("mutation_performed", True),
        ("execution_allowed", True),
        ("execution_available", True),
        ("execution_status", "executed"),
    ):
        with pytest.raises(ValidationError):
            make_solution(**{field: unsafe})


def test_canonical_json_markdown_and_sha_are_repeatable_and_non_circular() -> None:
    first = make_solution()
    second = OperatorSolution.model_validate(json.loads(first.model_dump_json()))
    canonical = canonical_operator_solution_json(first)
    assert canonical == canonical_operator_solution_json(second)
    assert canonical == canonical.strip() and not canonical.startswith("\ufeff")
    assert render_operator_solution_markdown(first) == render_operator_solution_markdown(second)
    digest = compute_operator_solution_sha256(first)
    assert digest == compute_operator_solution_sha256(second)
    assert digest == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert digest not in canonical


def test_semantic_order_is_preserved_and_material_change_changes_sha() -> None:
    solution = make_solution()
    assert [step.id for step in solution.procedure] == ["step:inspect", "step:adjust"]
    assert canonical_operator_solution_json(solution).index(
        "step:inspect"
    ) < canonical_operator_solution_json(solution).index("step:adjust")
    changed = make_solution(expected_impact="A materially different expected impact.")
    assert compute_operator_solution_sha256(solution) != compute_operator_solution_sha256(changed)


@pytest.mark.parametrize(
    "group", ["procedure", "alternatives", "verification_criteria", "likely_causes"]
)
def test_duplicate_ids_are_rejected(group: str) -> None:
    data = solution_data()
    data[group] = [data[group][0], data[group][0]]  # type: ignore[index]
    with pytest.raises(ValidationError, match="duplicate"):
        OperatorSolution.model_validate(data)


def test_duplicate_and_undeclared_provenance_refs_are_rejected() -> None:
    data = solution_data()
    data["provenance_references"] = [data["provenance_references"][0]] * 2  # type: ignore[index]
    with pytest.raises(ValidationError, match="duplicate provenance"):
        OperatorSolution.model_validate(data)
    data = solution_data()
    data["procedure"][0]["evidence_refs"] = ["evidence:missing"]  # type: ignore[index]
    with pytest.raises(ValidationError, match="undeclared provenance"):
        OperatorSolution.model_validate(data)


@pytest.mark.parametrize(
    "ref", ["/tmp/evidence", "../evidence", "folder/evidence", r"folder\evidence"]
)
def test_path_like_provenance_references_are_rejected(ref: str) -> None:
    with pytest.raises(ValidationError):
        ProvenanceReference(kind="evidence", ref=ref)


def test_malformed_optional_sha_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ProvenanceReference(kind="report", ref="report:one", sha256="ABC")


@pytest.mark.parametrize("field", ["procedure", "verification_criteria"])
def test_actionable_solution_requires_procedure_and_verification(field: str) -> None:
    with pytest.raises(ValidationError):
        make_solution(**{field: []})


def test_recovery_mode_and_guidance_cannot_contradict() -> None:
    with pytest.raises(ValidationError):
        RollbackRecoveryGuidance(mode="not_applicable", guidance=("Do something.",))
    with pytest.raises(ValidationError):
        RollbackRecoveryGuidance(mode="recovery", guidance=())
    assert RollbackRecoveryGuidance(mode="not_applicable").guidance == ()


def test_models_do_not_accept_raw_evidence_or_whole_upstream_artifacts() -> None:
    raw = EvidenceBundle(target="disk", target_type=TargetType.disk)
    with pytest.raises(ValidationError):
        make_solution(evidence=raw)
    fields = OperatorSolution.model_fields
    assert (
        not {"evidence", "diagnosis_result", "plan", "runbook", "report", "handoff"} & fields.keys()
    )


def test_contract_module_has_no_nondeterministic_or_execution_dependencies() -> None:
    source = Path("src/shellforgeai/core/operator_solution.py").read_text(encoding="utf-8")
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
        "shellforgeai.core.diagnose",
        "shellforgeai.core.runbook",
    )
    assert all(term not in source for term in forbidden)
    assert not dataclasses.is_dataclass(make_solution())
