"""Focused PR339 evidence identity and persisted-provenance binding tests."""

from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError
from test_pr323_approved_change_plan_link import plan_packet

from shellforgeai.core import approved_change_pr304_evidence_binding as binding_module
from shellforgeai.core import windows_runtime_integrity_contract as contract
from shellforgeai.core.windows_runtime_reconcile_plan_contract import canonical_plan_sha256


def packet(*, cwd: str = "C:/source", status: str = "ok") -> dict:
    safety = {key: False for key in contract.FALSE_KEYS}
    safety.update(read_only=True, mutation_performed=False)
    check_status = "pass" if status == "ok" else status
    return {
        "schema_version": 1,
        "mode": contract.MODE,
        "status": status,
        "platform": {"system": "windows"},
        "checks": [{"id": "runtime", "status": check_status}],
        "summary": {
            key: int(key == check_status)
            for key in ("pass", "attention", "blocked", "not_requested", "unsupported")
        },
        "read_only": True,
        "mutation_performed": False,
        "safety": safety,
        "first_safe_command": "python scripts/windows_runtime_integrity_acceptance.py packet.json",
        "invocation": {"cwd": cwd},
    }


def test_packet_validation_and_canonical_identity_are_pure_and_deterministic():
    original = packet()
    reordered = dict(reversed(list(original.items())))
    snapshot = copy.deepcopy(original)
    first = contract.validate_windows_runtime_integrity_packet(original)
    second = contract.validate_windows_runtime_integrity_packet(reordered)
    assert first.packet_valid
    assert first.packet_identity_sha256 == second.packet_identity_sha256
    assert original == snapshot
    changed = copy.deepcopy(original)
    changed["invocation"]["cwd"] = "C:/Windows/System32"
    assert contract.compute_packet_identity_sha256(changed) != first.packet_identity_sha256


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("schema_version", 2, "schema_version must be 1"),
        ("mode", "other", "mode must be windows_runtime_integrity"),
        ("status", "fresh", "invalid top-level status"),
        ("checks", "bad", "checks must be a list of objects"),
        ("first_safe_command", "", "first_safe_command is missing"),
    ],
)
def test_packet_contract_rejects_corruption(field, value, error):
    value_packet = packet()
    value_packet[field] = value
    assert error in contract.packet_validation_errors(value_packet)


def test_exact_ordered_pair_has_distinct_deterministic_identity_and_no_raw_packets():
    source = packet(cwd="C:/source")
    system32 = packet(cwd="C:/Windows/System32")
    first = contract.prepare_pr304_runtime_integrity_evidence_set(source, system32)
    second = contract.prepare_pr304_runtime_integrity_evidence_set(source, system32)
    assert first.status == "evidence_set_prepared"
    assert first.evidence_set_identity_sha256 == second.evidence_set_identity_sha256
    assert first.evidence_set_identity_sha256 not in {
        first.source_root_packet_identity_sha256,
        first.system32_packet_identity_sha256,
    }
    dumped = first.model_dump(mode="json")
    assert "checks" not in str(dumped)
    assert "C:/" not in str(dumped)
    swapped = contract.prepare_pr304_runtime_integrity_evidence_set(system32, source)
    assert swapped.evidence_set_identity_sha256 != first.evidence_set_identity_sha256


def test_stable_field_mismatch_is_inconsistent_but_attention_is_valid_evidence():
    source = packet(status="attention")
    system32 = packet(status="attention", cwd="C:/Windows/System32")
    assert contract.prepare_pr304_runtime_integrity_evidence_set(source, system32).status == (
        "evidence_set_prepared"
    )
    system32["status"] = "blocked"
    system32["checks"][0]["status"] = "blocked"
    system32["summary"]["attention"] = 0
    system32["summary"]["blocked"] = 1
    result = contract.prepare_pr304_runtime_integrity_evidence_set(source, system32)
    assert result.status == "evidence_set_inconsistent"
    assert result.stable_field_comparison_evaluated


def test_confirmation_failures_occur_before_exact_artifact_load(monkeypatch, tmp_path):
    calls = 0

    def forbidden(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("loader reached")

    monkeypatch.setattr(
        binding_module, "load_persisted_approved_change_plan_link_artifact", forbidden
    )
    plan = plan_packet()
    source = packet()
    system32 = packet(cwd="C:/Windows/System32")
    evidence = contract.prepare_pr304_runtime_integrity_evidence_set(source, system32)
    result = binding_module.bind_persisted_plan_link_to_pr304_evidence_set(
        "acpl_" + "a" * 64,
        plan,
        source,
        system32,
        data_dir=tmp_path,
        confirm_plan_link_artifact_identity_sha256="b" * 64,
        confirm_plan_sha256="0" * 64,
        confirm_evidence_set_identity_sha256=evidence.evidence_set_identity_sha256,
    )
    assert result.status == "invalid_evidence_binding_input"
    assert calls == 0
    result = binding_module.bind_persisted_plan_link_to_pr304_evidence_set(
        "acpl_" + "a" * 64,
        plan,
        source,
        system32,
        data_dir=tmp_path,
        confirm_plan_link_artifact_identity_sha256="b" * 64,
        confirm_plan_sha256=canonical_plan_sha256(plan),
        confirm_evidence_set_identity_sha256="0" * 64,
    )
    assert result.status == "evidence_set_confirmation_mismatch"
    assert calls == 0
    assert result.execution_allowed is False
    assert result.current_state_revalidation_evaluated is False


def test_models_are_frozen_and_forbid_extra_fields():
    result = contract.prepare_pr304_runtime_integrity_evidence_set(
        packet(), packet(cwd="C:/Windows/System32")
    )
    with pytest.raises(ValidationError):
        result.__class__.model_validate({**result.model_dump(), "surprise": True})
    with pytest.raises(ValidationError):
        result.evidence_set.stable_fields_consistent = False
