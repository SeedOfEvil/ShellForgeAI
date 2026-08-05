"""Focused tests for PR338 persisted plan-link current-state revalidation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from test_pr323_approved_change_plan_link import (
    catalog_identity,
    lane_identity,
    no_change_packet,
    ready_packet,
    supported_artifact,
)

from shellforgeai.core import approved_change_plan_current_state as current
from shellforgeai.core import approved_change_plan_link as link_module
from shellforgeai.core.approved_change_plan_link_artifact_persistence import (
    construct_approved_change_plan_link_artifact,
    publish_approved_change_plan_link_artifact,
)
from shellforgeai.core.windows_runtime_reconcile_plan_contract import canonical_plan_sha256


def persisted_fixture(tmp_path):
    approval = supported_artifact(tmp_path)
    packet = ready_packet()
    link = link_module.link_persisted_approved_change_to_windows_runtime_reconcile_plan(
        approval.approval_artifact_id,
        packet,
        data_dir=tmp_path,
        confirm_capability_catalog_identity_sha256=catalog_identity(),
        confirm_lane_declaration_identity_sha256=lane_identity(),
        confirm_plan_sha256=canonical_plan_sha256(packet),
    )
    artifact = construct_approved_change_plan_link_artifact(link)
    assert artifact.status == "plan_link_artifact_constructed"
    published = publish_approved_change_plan_link_artifact(
        approval.approval_artifact_id,
        packet,
        data_dir=tmp_path,
        confirm_capability_catalog_identity_sha256=catalog_identity(),
        confirm_lane_declaration_identity_sha256=lane_identity(),
        confirm_plan_sha256=canonical_plan_sha256(packet),
        confirm_plan_link_artifact_identity_sha256=artifact.artifact_identity_sha256,
    )
    assert published.status in {
        "plan_link_artifact_published",
        "plan_link_artifact_already_present",
    }
    return packet, artifact


def call(tmp_path, packet, artifact, **overrides):
    kwargs = dict(
        data_dir=tmp_path,
        staged_source_root=tmp_path / "source",
        durable_runtime_root=tmp_path / "runtime",
        confirm_plan_link_artifact_identity_sha256=artifact.artifact_identity_sha256,
        confirm_plan_sha256=canonical_plan_sha256(packet),
    )
    kwargs.update(overrides)
    return current.revalidate_persisted_plan_link_artifact_current_state(
        artifact.artifact_id, packet, **kwargs
    )


def forbid_roots(monkeypatch):
    monkeypatch.setattr(current, "root_fingerprint", lambda root: pytest.fail("root reached"))
    monkeypatch.setattr(current, "load_validators", lambda: pytest.fail("validators reached"))


@pytest.mark.parametrize(
    "bad_id",
    [
        "",
        "aca_" + "0" * 64,
        "acpl_" + "A" * 64,
        "acpl_" + "0" * 63,
        "acpl_" + "0" * 65,
        "../acpl_" + "0" * 64,
    ],
)
def test_invalid_exact_acpl_id_stops_before_loader_and_roots(monkeypatch, tmp_path, bad_id):
    packet, artifact = persisted_fixture(tmp_path)
    monkeypatch.setattr(
        current,
        "load_persisted_approved_change_plan_link_artifact",
        lambda *a, **k: pytest.fail("loader reached"),
    )
    forbid_roots(monkeypatch)

    result = current.revalidate_persisted_plan_link_artifact_current_state(
        bad_id,
        packet,
        data_dir=tmp_path,
        staged_source_root=tmp_path / "source",
        durable_runtime_root=tmp_path / "runtime",
        confirm_plan_link_artifact_identity_sha256=artifact.artifact_identity_sha256,
        confirm_plan_sha256=canonical_plan_sha256(packet),
    )

    assert result.status == "invalid_current_state_input"
    assert not result.plan_link_artifact_load_evaluated


@pytest.mark.parametrize(
    "field", ["confirm_plan_sha256", "confirm_plan_link_artifact_identity_sha256"]
)
def test_bad_confirmation_format_stops_before_loader_and_roots(monkeypatch, tmp_path, field):
    packet, artifact = persisted_fixture(tmp_path)
    monkeypatch.setattr(
        current,
        "load_persisted_approved_change_plan_link_artifact",
        lambda *a, **k: pytest.fail("loader reached"),
    )
    forbid_roots(monkeypatch)

    result = call(tmp_path, packet, artifact, **{field: "A" * 64})

    assert result.status == "invalid_current_state_input"
    assert not result.plan_link_artifact_load_evaluated


def test_plan_confirmation_mismatch_stops_before_loader_and_roots(monkeypatch, tmp_path):
    packet, artifact = persisted_fixture(tmp_path)
    monkeypatch.setattr(
        current,
        "load_persisted_approved_change_plan_link_artifact",
        lambda *a, **k: pytest.fail("loader reached"),
    )
    forbid_roots(monkeypatch)

    result = call(tmp_path, packet, artifact, confirm_plan_sha256="0" * 64)

    assert result.status == "invalid_current_state_input"
    assert result.plan_validated
    assert not result.plan_identity_confirmed


def test_artifact_confirmation_mismatch_reads_only_exact_artifact(monkeypatch, tmp_path):
    packet, artifact = persisted_fixture(tmp_path)
    calls = []
    real_loader = current.load_persisted_approved_change_plan_link_artifact
    monkeypatch.setattr(
        current,
        "load_persisted_approved_change_plan_link_artifact",
        lambda *a, **k: calls.append(a) or real_loader(*a, **k),
    )
    forbid_roots(monkeypatch)

    result = call(tmp_path, packet, artifact, confirm_plan_link_artifact_identity_sha256="0" * 64)

    assert result.status == "plan_link_artifact_confirmation_mismatch"
    assert len(calls) == 1
    assert calls[0][1] == artifact.artifact_id
    assert result.plan_link_artifact_loaded
    assert not result.current_state_revalidation_evaluated


def test_missing_artifact_stops_before_governed_roots(monkeypatch, tmp_path):
    packet, artifact = persisted_fixture(tmp_path)
    forbid_roots(monkeypatch)

    result = current.revalidate_persisted_plan_link_artifact_current_state(
        "acpl_" + "0" * 64,
        packet,
        data_dir=tmp_path,
        staged_source_root=tmp_path / "source",
        durable_runtime_root=tmp_path / "runtime",
        confirm_plan_link_artifact_identity_sha256="0" * 64,
        confirm_plan_sha256=canonical_plan_sha256(packet),
    )

    assert result.status == "plan_link_artifact_not_available"
    assert result.plan_link_artifact_load_evaluated


def test_persisted_link_plan_mismatch_stops_before_roots(monkeypatch, tmp_path):
    packet, artifact = persisted_fixture(tmp_path)
    changed = no_change_packet()
    forbid_roots(monkeypatch)

    result = call(tmp_path, changed, artifact, confirm_plan_sha256=canonical_plan_sha256(changed))

    assert result.status == "persisted_link_plan_mismatch"
    assert result.plan_link_plan_comparison_evaluated
    assert not result.plan_link_plan_matched


def test_non_windows_unsupported_after_all_provenance_gates_without_roots(monkeypatch, tmp_path):
    packet, artifact = persisted_fixture(tmp_path)
    forbid_roots(monkeypatch)
    monkeypatch.setattr(current.platform, "system", lambda: "Linux")

    result = call(tmp_path, packet, artifact)

    assert result.status == "unsupported"
    assert result.plan_identity_confirmed
    assert result.plan_link_artifact_identity_confirmed
    assert result.plan_link_plan_matched
    assert not result.current_state_revalidation_evaluated


def test_result_is_frozen_extra_forbidden_and_ledger_is_fixed_false(tmp_path):
    packet, artifact = persisted_fixture(tmp_path)
    result = call(tmp_path, packet, artifact, confirm_plan_link_artifact_identity_sha256="0" * 64)

    with pytest.raises(ValidationError):
        current.PersistedPlanLinkCurrentStateResult(status="unsupported", extra=True)
    with pytest.raises(ValidationError):
        result.status = "current_state_confirmed"
    for field in (
        "mutation_performed",
        "artifact_write_performed",
        "publication_performed",
        "persistence_performed",
        "plan_packet_persisted",
        "current_state_persisted",
        "authorization_evaluated",
        "preflight_evaluated",
        "receipt_created",
        "receipt_linked",
        "file_create_executed",
        "file_replace_executed",
        "backup_created",
        "atomic_runtime_replace_executed",
        "parent_directory_create_executed",
        "compensation_executed",
        "service_control_executed",
        "process_termination_executed",
        "registry_modified",
        "powershell_executed",
        "winrm_used",
        "qga_used",
        "remote_execution",
        "subprocess_executed",
        "shell_executed",
        "natural_language_execution",
        "network_call",
        "model_called",
        "secret_read",
        "auth_cache_read",
        "execution_allowed",
        "execution_available",
    ):
        assert getattr(result, field) is False, field
    assert result.execution_status == "not_executed"
