"""Focused contract tests for canonical PR338 current-state evidence."""

from __future__ import annotations

import inspect
import json

import pytest
from pydantic import ValidationError

from shellforgeai.core import approved_change_persisted_plan_link_current_state_evidence as evidence
from shellforgeai.core import approved_change_plan_current_state as pr338

SHA = "1" * 64
ARTIFACT_ID = "acpl_" + "2" * 64


def confirmed(**changes):
    values = dict(
        status="current_state_confirmed",
        requested_plan_link_artifact_id=ARTIFACT_ID,
        plan_link_artifact_identity_sha256="2" * 64,
        plan_link_identity_sha256="3" * 64,
        approval_artifact_id="aca_" + "4" * 64,
        approval_artifact_identity_sha256="4" * 64,
        subject_sha256="5" * 64,
        capability_binding_identity_sha256="6" * 64,
        capability_catalog_identity_sha256="7" * 64,
        lane_declaration_identity_sha256="8" * 64,
        capability_id="windows.runtime_reconcile",
        lane_id="pr313.windows_runtime_reconcile",
        plan_sha256=SHA,
        confirmed_plan_sha256=SHA,
        plan_mode="apply",
        recipe_id="windows_runtime_reconcile",
        plan_status="ready",
        staged_source_root_fingerprint="9" * 64,
        durable_runtime_root_fingerprint="a" * 64,
        mappings=(
            pr338.CurrentStateMapping(
                relative_source="config/profiles/inspect.yaml",
                relative_destination="config/profiles/inspect.yaml",
                planned_operation="replace",
                current_operation="replace",
                source_exists=True,
                destination_exists=True,
                source_hash_matches=True,
                destination_hash_matches=True,
                parent_state="existing_directory",
                current_state_matched=True,
            ),
            pr338.CurrentStateMapping(
                relative_source="scripts/windows/sfai.cmd",
                relative_destination="bin/sfai.cmd",
                planned_operation="create",
                current_operation="create",
                source_exists=True,
                destination_exists=False,
                source_hash_matches=True,
                destination_hash_matches=True,
                parent_state="existing_directory",
                current_state_matched=True,
            ),
        ),
        plan_validated=True,
        plan_identity_confirmed=True,
        plan_link_artifact_load_evaluated=True,
        plan_link_artifact_loaded=True,
        plan_link_artifact_identity_confirmed=True,
        plan_link_validated=True,
        plan_link_plan_comparison_evaluated=True,
        plan_link_plan_matched=True,
        current_state_revalidation_evaluated=True,
        current_state_matched=True,
    )
    values.update(changes)
    return pr338.PersistedPlanLinkCurrentStateResult(**values)


def invoke(monkeypatch, result=None):
    calls = []
    monkeypatch.setattr(
        evidence.pr338,
        "revalidate_persisted_plan_link_artifact_current_state",
        lambda *args, **kwargs: calls.append((args, kwargs)) or (result or confirmed()),
    )
    output = evidence.construct_persisted_plan_link_current_state_evidence(
        ARTIFACT_ID,
        {"exact": "packet"},
        data_dir="data",
        staged_source_root="/private/source",
        durable_runtime_root="/private/runtime",
        confirm_plan_link_artifact_identity_sha256="2" * 64,
        confirm_plan_sha256=SHA,
    )
    return output, calls


def test_public_boundary_and_exact_single_pr338_call(monkeypatch):
    signature = inspect.signature(evidence.construct_persisted_plan_link_current_state_evidence)
    assert tuple(signature.parameters) == (
        "plan_link_artifact_id",
        "plan_packet",
        "data_dir",
        "staged_source_root",
        "durable_runtime_root",
        "confirm_plan_link_artifact_identity_sha256",
        "confirm_plan_sha256",
    )
    assert not any(
        "result" in name or "clock" in name or "path" in name for name in signature.parameters
    )
    result, calls = invoke(monkeypatch)
    assert result.status == "current_state_evidence_constructed"
    assert len(calls) == 1
    assert calls[0][0] == (ARTIFACT_ID, {"exact": "packet"})
    assert calls[0][1]["staged_source_root"] == "/private/source"


def test_success_is_bounded_deterministic_non_circular_and_frozen(monkeypatch):
    first, _ = invoke(monkeypatch)
    second, _ = invoke(monkeypatch)
    assert first.evidence is not None
    assert first.evidence == second.evidence
    assert first.evidence_identity_sha256 == second.evidence_identity_sha256
    assert first.evidence_identity_sha256 == (
        "1b46b5b6d359f2f2ceff46fcfae1bea5786ba9b83c4f580d43c0193162f01957"
    )
    canonical = evidence.canonical_persisted_plan_link_current_state_evidence_json(first.evidence)
    assert (
        evidence.compute_persisted_plan_link_current_state_evidence_sha256(first.evidence)
        == first.evidence_identity_sha256
    )
    assert first.evidence_identity_sha256 not in canonical
    assert "/private/" not in canonical
    assert "inspect.yaml" in canonical and "root_fingerprint" in canonical
    assert "raw source content" not in canonical and "secret" not in canonical
    with pytest.raises(ValidationError):
        evidence.ApprovedChangePersistedPlanLinkCurrentStateEvidence.model_validate(
            {**first.evidence.model_dump(), "extra": True}
        )
    with pytest.raises(ValidationError):
        first.evidence.plan_sha256 = "0" * 64


def test_result_contract_has_no_generic_filesystem_telemetry(monkeypatch):
    result, _ = invoke(monkeypatch)

    assert (
        "filesystem_accessed"
        not in evidence.ApprovedChangePersistedPlanLinkCurrentStateEvidenceResult.model_fields
    )
    assert "filesystem_accessed" not in result.model_dump()


@pytest.mark.parametrize(
    ("status", "updates", "expected_status"),
    [
        (
            "plan_link_artifact_confirmation_mismatch",
            {
                "plan_link_artifact_load_evaluated": True,
                "plan_link_artifact_loaded": True,
                "plan_link_artifact_identity_confirmed": False,
                "plan_link_validated": False,
                "plan_link_plan_comparison_evaluated": False,
                "plan_link_plan_matched": False,
            },
            "current_state_evidence_not_confirmed",
        ),
        (
            "persisted_link_plan_mismatch",
            {
                "plan_link_artifact_load_evaluated": True,
                "plan_link_artifact_loaded": True,
                "plan_link_artifact_identity_confirmed": True,
                "plan_link_validated": True,
                "plan_link_plan_comparison_evaluated": True,
                "plan_link_plan_matched": False,
            },
            "current_state_evidence_not_confirmed",
        ),
        (
            "plan_link_artifact_not_available",
            {
                "plan_link_artifact_load_evaluated": True,
                "plan_link_artifact_loaded": False,
                "plan_link_artifact_identity_confirmed": False,
                "plan_link_validated": False,
                "plan_link_plan_comparison_evaluated": False,
                "plan_link_plan_matched": False,
            },
            "current_state_evidence_not_confirmed",
        ),
        (
            "unsupported",
            {
                "plan_link_artifact_load_evaluated": True,
                "plan_link_artifact_loaded": True,
                "plan_link_artifact_identity_confirmed": True,
                "plan_link_validated": True,
                "plan_link_plan_comparison_evaluated": True,
                "plan_link_plan_matched": True,
            },
            "current_state_evidence_unavailable",
        ),
    ],
)
def test_loader_phase_early_outcomes_expose_no_generic_filesystem_claim(
    monkeypatch, status, updates, expected_status
):
    upstream = confirmed(
        status=status,
        current_state_revalidation_evaluated=False,
        current_state_matched=False,
        mappings=(),
        **updates,
    )

    result, calls = invoke(monkeypatch, upstream)

    assert len(calls) == 1
    assert result.status == expected_status
    assert not result.current_state_revalidation_evaluated
    assert result.evidence is None
    assert result.evidence_identity_sha256 == ""
    assert "filesystem_accessed" not in result.model_dump()


@pytest.mark.parametrize(
    "status",
    [
        "current_state_changed",
        "current_state_blocked",
        "unsupported",
        "invalid_current_state_input",
        "plan_link_artifact_not_available",
        "plan_link_artifact_confirmation_mismatch",
        "persisted_link_plan_mismatch",
        "current_state_validation_failed",
    ],
)
def test_non_success_never_constructs_evidence(monkeypatch, status):
    result, calls = invoke(monkeypatch, confirmed(status=status))
    assert len(calls) == 1
    assert result.evidence is None
    assert result.evidence_identity_sha256 == ""
    assert not result.current_state_evidence_constructed


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("current_state_revalidation_evaluated", False),
        ("current_state_matched", False),
        ("plan_validated", False),
        ("plan_identity_confirmed", False),
        ("plan_link_artifact_load_evaluated", False),
        ("plan_link_artifact_loaded", False),
        ("plan_link_artifact_identity_confirmed", False),
        ("plan_link_validated", False),
        ("plan_link_plan_comparison_evaluated", False),
        ("plan_link_plan_matched", False),
    ],
)
def test_contradictory_success_prerequisite_fails_closed(monkeypatch, field, value):
    result, _ = invoke(monkeypatch, confirmed(**{field: value}))
    assert result.status == "current_state_evidence_validation_failed"
    assert result.evidence is None and result.evidence_identity_sha256 == ""


def test_mapping_contradictions_fail_closed(monkeypatch):
    base = confirmed()
    variants = (
        base.model_copy(update={"mappings": base.mappings[:1]}),
        base.model_copy(update={"mappings": (base.mappings[0], base.mappings[0])}),
        base.model_copy(update={"mappings": tuple(reversed(base.mappings))}),
        base.model_copy(
            update={
                "mappings": (
                    base.mappings[0].model_copy(update={"current_state_matched": False}),
                    base.mappings[1],
                )
            }
        ),
        base.model_copy(
            update={
                "mappings": (
                    base.mappings[0].model_copy(update={"current_operation": "create"}),
                    base.mappings[1],
                )
            }
        ),
    )
    for variant in variants:
        result, _ = invoke(monkeypatch, variant)
        assert result.evidence is None and result.evidence_identity_sha256 == ""


@pytest.mark.parametrize(
    "path",
    [
        "plan_link_artifact_identity_sha256",
        "plan_link_identity_sha256",
        "approval_artifact_identity_sha256",
        "subject_sha256",
        "capability_binding_identity_sha256",
        "capability_catalog_identity_sha256",
        "lane_declaration_identity_sha256",
        "plan_sha256",
        "staged_source_root_fingerprint",
        "durable_runtime_root_fingerprint",
    ],
)
def test_material_top_level_fact_changes_identity(path):
    original = confirmed()
    changed = original.model_copy(
        update={
            path: "b" * 64,
            **({"confirmed_plan_sha256": "b" * 64} if path == "plan_sha256" else {}),
        }
    )
    one = evidence.ApprovedChangePersistedPlanLinkCurrentStateEvidence.model_validate(
        _evidence_dict(original)
    )
    two = evidence.ApprovedChangePersistedPlanLinkCurrentStateEvidence.model_validate(
        _evidence_dict(changed)
    )
    assert evidence.compute_persisted_plan_link_current_state_evidence_sha256(
        one
    ) != evidence.compute_persisted_plan_link_current_state_evidence_sha256(two)


def _evidence_dict(result):
    return dict(
        plan_link_artifact_id=result.requested_plan_link_artifact_id,
        **{
            name: getattr(result, name)
            for name in (
                "plan_link_artifact_identity_sha256",
                "plan_link_identity_sha256",
                "approval_artifact_id",
                "approval_artifact_identity_sha256",
                "subject_sha256",
                "capability_binding_identity_sha256",
                "capability_catalog_identity_sha256",
                "lane_declaration_identity_sha256",
                "capability_id",
                "lane_id",
                "plan_sha256",
                "plan_mode",
                "recipe_id",
                "plan_status",
                "current_state_scope",
                "staged_source_root_fingerprint",
                "durable_runtime_root_fingerprint",
            )
        },
        mappings=tuple(m.model_dump() for m in result.mappings),
    )


def test_mapping_facts_and_safety_ledger(monkeypatch):
    result, _ = invoke(monkeypatch)
    assert result.evidence is not None
    original = result.evidence
    for update in (
        {"planned_operation": "copy", "current_operation": "copy"},
        {"source_exists": False},
        {"destination_exists": False},
        {"source_hash_matches": False},
        {"destination_hash_matches": False},
        {"parent_state": "missing"},
        {"reason_codes": ("bounded_reason",)},
    ):
        mapping = original.mappings[0].model_copy(update=update)
        changed = original.model_copy(update={"mappings": (mapping, original.mappings[1])})
        assert (
            evidence.compute_persisted_plan_link_current_state_evidence_sha256(changed)
            != result.evidence_identity_sha256
        )
    assert (
        json.loads(evidence.canonical_persisted_plan_link_current_state_evidence_json(original))[
            "source_status"
        ]
        == "current_state_confirmed"
    )
    for name, value in result.model_dump().items():
        if name.endswith(
            (
                "evaluated",
                "performed",
                "persisted",
                "executed",
                "created",
                "linked",
                "allowed",
                "available",
            )
        ) and name not in {
            "current_state_revalidation_evaluated",
            "current_state_evidence_constructed",
        }:
            assert value is False, name
    assert result.read_only and result.execution_status == "not_executed"


def test_module_has_no_direct_filesystem_clock_random_or_environment_authority():
    source = inspect.getsource(evidence)
    for prohibited in (
        "read_text(",
        "read_bytes(",
        "os.stat",
        "os.listdir",
        ".glob(",
        ".rglob(",
        "datetime",
        "time.time",
        "uuid",
        "random",
        "getenv",
        "environ",
    ):
        assert prohibited not in source
