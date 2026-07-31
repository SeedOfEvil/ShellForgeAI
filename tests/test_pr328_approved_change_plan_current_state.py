"""Focused tests for PR328 linked-plan current-state revalidation."""

from __future__ import annotations

import copy
import os
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from test_pr323_approved_change_plan_link import plan_packet

from shellforgeai.core import approved_change_plan_current_state as current
from shellforgeai.core.approved_change_capability_binding import (
    compute_capability_lane_declaration_sha256,
    maintained_windows_runtime_reconcile_lane_declaration,
)
from shellforgeai.core.approved_change_capability_support import (
    compute_approved_change_capability_support_catalog_sha256,
    maintained_approved_change_capability_support_catalog,
)
from shellforgeai.core.approved_change_plan_link import (
    ApprovedChangeWindowsRuntimeReconcilePlanLink,
    compute_approved_change_plan_link_sha256,
)
from shellforgeai.core.windows_runtime_reconcile_plan_contract import canonical_plan_sha256


def confirmations(packet):
    catalog = compute_approved_change_capability_support_catalog_sha256(
        maintained_approved_change_capability_support_catalog()
    )
    lane = compute_capability_lane_declaration_sha256(
        maintained_windows_runtime_reconcile_lane_declaration()
    )
    link = ApprovedChangeWindowsRuntimeReconcilePlanLink(
        approval_artifact_id="aca_" + "1" * 64,
        approval_artifact_identity_sha256="2" * 64,
        subject_sha256="3" * 64,
        capability_binding_identity_sha256="4" * 64,
        capability_catalog_identity_sha256=catalog,
        capability_id="windows.runtime_reconcile",
        lane_declaration_identity_sha256=lane,
        lane_id="windows.runtime_reconcile.pr313.fixed_two_file_local_windows",
        plan_mode="windows_runtime_reconcile",
        plan_recipe_id="windows.runtime_reconcile",
        plan_sha256=canonical_plan_sha256(packet),
        plan_status=packet["status"],
        destination_parent_contract_version=1,
    )
    return catalog, lane, link


def call(tmp_path, packet, catalog, lane, link, **overrides):
    values = dict(
        data_dir=tmp_path / "data",
        staged_source_root=tmp_path / "source",
        durable_runtime_root=tmp_path / "runtime",
        confirm_capability_catalog_identity_sha256=catalog,
        confirm_lane_declaration_identity_sha256=lane,
        confirm_plan_sha256=canonical_plan_sha256(packet),
        confirm_plan_link_identity_sha256=compute_approved_change_plan_link_sha256(link),
    )
    values.update(overrides)
    return current.revalidate_linked_windows_runtime_reconcile_plan_current_state(
        link.approval_artifact_id, packet, **values
    )


def exact_link_result(link):
    return SimpleNamespace(
        link_complete=True,
        plan_link=link,
        capability_support_evaluated=True,
        capability_supported=True,
        capability_binding_evaluated=True,
        capability_bound=True,
        plan_linked=True,
        errors=(),
    )


def guard_inspection(monkeypatch):
    monkeypatch.setattr(current, "load_validators", lambda: pytest.fail("validators reached"))
    monkeypatch.setattr(current, "_evaluate_file", lambda *a, **k: pytest.fail("file reached"))


def assert_fail_closed_safety(result):
    assert result.read_only
    assert result.execution_status == "not_executed"
    assert not result.current_state_revalidation_evaluated
    assert not result.current_state_matched
    false_fields = (
        "mutation_performed",
        "artifact_write_performed",
        "publication_performed",
        "persistence_performed",
        "authorization_evaluated",
        "preflight_evaluated",
        "receipt_created",
        "receipt_linked",
        "host_configuration_mutation_performed",
        "file_create_executed",
        "file_replace_executed",
        "backup_created",
        "atomic_replace_executed",
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
    )
    assert all(getattr(result, field) is False for field in false_fields)


class InvalidRoot(os.PathLike[str]):
    def __fspath__(self) -> str:
        raise RuntimeError("private failure at C:/not-for-results")


@pytest.mark.parametrize("root_name", ["staged_source_root", "durable_runtime_root"])
def test_path_construction_failure_is_sanitized_before_inspection(monkeypatch, tmp_path, root_name):
    packet = plan_packet()
    catalog, lane, link = confirmations(packet)
    link_calls = []
    monkeypatch.setattr(
        current,
        "link_persisted_approved_change_to_windows_runtime_reconcile_plan",
        lambda *a, **k: link_calls.append(1) or exact_link_result(link),
    )
    monkeypatch.setattr(current.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        current, "root_fingerprint", lambda root: pytest.fail("fingerprint reached")
    )
    guard_inspection(monkeypatch)

    result = call(tmp_path, packet, catalog, lane, link, **{root_name: InvalidRoot()})

    assert result.status == "invalid_current_state_input"
    assert result.reason == "governed root input is invalid"
    assert result.errors == ("governed root preparation failed safely",)
    assert link_calls == [1]
    assert "C:/" not in result.model_dump_json()
    assert "RuntimeError" not in result.model_dump_json()
    assert "Traceback" not in result.model_dump_json()
    assert_fail_closed_safety(result)


@pytest.mark.parametrize("failure_call", [1, 2])
def test_root_fingerprint_failure_is_sanitized_before_inspection(
    monkeypatch, tmp_path, failure_call
):
    packet = plan_packet()
    catalog, lane, link = confirmations(packet)
    calls = []
    monkeypatch.setattr(
        current,
        "link_persisted_approved_change_to_windows_runtime_reconcile_plan",
        lambda *a, **k: exact_link_result(link),
    )
    monkeypatch.setattr(current.platform, "system", lambda: "Windows")

    def fail_fingerprint(root):
        calls.append(root)
        if len(calls) == failure_call:
            raise OSError("private failure at C:/not-for-results")
        return "a" * 64

    monkeypatch.setattr(current, "root_fingerprint", fail_fingerprint)
    guard_inspection(monkeypatch)

    result = call(tmp_path, packet, catalog, lane, link)

    assert result.status == "current_state_blocked"
    assert result.reason == "complete current-state inspection was not possible"
    assert result.errors == ("governed root preparation failed safely",)
    assert len(calls) == failure_call
    assert "C:/" not in result.model_dump_json()
    assert "OSError" not in result.model_dump_json()
    assert "Traceback" not in result.model_dump_json()
    assert_fail_closed_safety(result)


@pytest.mark.parametrize("bad", ["", "A" * 64, "sha256:" + "a" * 64, "a" * 63, " a" * 32])
def test_bad_link_confirmation_stops_before_link_and_roots(monkeypatch, tmp_path, bad):
    packet = plan_packet()
    catalog, lane, link = confirmations(packet)
    monkeypatch.setattr(
        current,
        "link_persisted_approved_change_to_windows_runtime_reconcile_plan",
        lambda *a, **k: pytest.fail("link reached"),
    )
    monkeypatch.setattr(current.Path, "is_dir", lambda self: pytest.fail("root reached"))
    result = call(tmp_path, packet, catalog, lane, link, confirm_plan_link_identity_sha256=bad)
    assert result.status == "invalid_current_state_input"
    assert not result.current_state_revalidation_evaluated


def test_link_mismatch_stops_before_root_inspection(monkeypatch, tmp_path):
    packet = plan_packet()
    catalog, lane, link = confirmations(packet)
    calls = []
    monkeypatch.setattr(
        current,
        "link_persisted_approved_change_to_windows_runtime_reconcile_plan",
        lambda *a, **k: (
            calls.append(1)
            or SimpleNamespace(
                link_complete=True,
                plan_link=link,
                capability_support_evaluated=True,
                capability_supported=True,
                capability_binding_evaluated=True,
                capability_bound=True,
                plan_linked=True,
                errors=(),
            )
        ),
    )
    monkeypatch.setattr(current.Path, "is_dir", lambda self: pytest.fail("root reached"))
    result = call(tmp_path, packet, catalog, lane, link, confirm_plan_link_identity_sha256="f" * 64)
    assert result.status == "invalid_current_state_input"
    assert calls == [1]


def test_non_windows_is_unsupported_after_exact_link(monkeypatch, tmp_path):
    packet = plan_packet()
    original = copy.deepcopy(packet)
    catalog, lane, link = confirmations(packet)
    monkeypatch.setattr(
        current,
        "link_persisted_approved_change_to_windows_runtime_reconcile_plan",
        lambda *a, **k: SimpleNamespace(
            link_complete=True,
            plan_link=link,
            capability_support_evaluated=True,
            capability_supported=True,
            capability_binding_evaluated=True,
            capability_bound=True,
            plan_linked=True,
            errors=(),
        ),
    )
    monkeypatch.setattr(current.platform, "system", lambda: "Linux")
    result = call(tmp_path, packet, catalog, lane, link)
    assert result.status == "unsupported"
    assert packet == original
    assert result.execution_status == "not_executed"
    assert not result.authorization_evaluated
    assert not result.persistence_performed


def test_result_models_are_immutable_and_forbid_extra_fields():
    result = current.ApprovedChangePlanCurrentStateResult(status="current_state_blocked")
    with pytest.raises(ValidationError):
        result.status = "current_state_confirmed"
    with pytest.raises(ValidationError):
        current.ApprovedChangePlanCurrentStateResult(
            status="current_state_blocked", absolute_path="C:/secret"
        )
