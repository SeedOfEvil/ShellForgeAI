"""Focused deterministic tests for PR337 plan-link artifact persistence."""

from __future__ import annotations

import json

from test_pr323_approved_change_plan_link import (
    catalog_identity,
    lane_identity,
    link,
    ready_packet,
    supported_artifact,
)

from shellforgeai.core.approved_change_plan_link_artifact_persistence import (
    APPROVED_CHANGE_PLAN_LINK_FILENAME,
    APPROVED_CHANGE_PLAN_LINKS_DIRNAME,
    PLAN_LINK_ARTIFACT_ID_PREFIX,
    canonical_approved_change_plan_link_artifact_bytes,
    construct_approved_change_plan_link_artifact,
    load_persisted_approved_change_plan_link_artifact,
    publish_approved_change_plan_link_artifact,
    validate_approved_change_plan_link_artifact,
)
from shellforgeai.core.windows_runtime_reconcile_plan_contract import canonical_plan_sha256


def prepared(tmp_path):
    approval = supported_artifact(tmp_path)
    result = link(approval.approval_artifact_id, tmp_path)
    construction = construct_approved_change_plan_link_artifact(result)
    assert construction.status == "plan_link_artifact_constructed"
    return approval, construction


def test_canonical_identity_is_deterministic_distinct_and_non_circular(tmp_path):
    _, first = prepared(tmp_path)
    second = construct_approved_change_plan_link_artifact(first.artifact.plan_link)
    assert first.canonical_bytes == second.canonical_bytes
    assert first.artifact_identity_sha256 == second.artifact_identity_sha256
    assert first.artifact_id == PLAN_LINK_ARTIFACT_ID_PREFIX + first.artifact_identity_sha256
    assert first.artifact_identity_sha256 != first.artifact.plan_link_identity_sha256
    payload = json.loads(first.canonical_bytes)
    assert "artifact_id" not in payload
    assert "artifact_identity_sha256" not in payload


def test_mapping_order_is_irrelevant_and_extra_fields_are_rejected(tmp_path):
    _, construction = prepared(tmp_path)
    payload = json.loads(construction.canonical_bytes)
    reversed_payload = dict(reversed(tuple(payload.items())))
    assert (
        canonical_approved_change_plan_link_artifact_bytes(reversed_payload)
        == construction.canonical_bytes
    )
    payload["extra"] = True
    result = validate_approved_change_plan_link_artifact(payload)
    assert result.status == "plan_link_artifact_invalid"


def test_publish_load_and_existing_identical_noop(tmp_path):
    approval, construction = prepared(tmp_path)
    kwargs = dict(
        data_dir=tmp_path,
        confirm_capability_catalog_identity_sha256=catalog_identity(),
        confirm_lane_declaration_identity_sha256=lane_identity(),
        confirm_plan_sha256=canonical_plan_sha256(ready_packet()),
        confirm_plan_link_artifact_identity_sha256=construction.artifact_identity_sha256,
    )
    first = publish_approved_change_plan_link_artifact(
        approval.approval_artifact_id, ready_packet(), **kwargs
    )
    assert first.status == "plan_link_artifact_published", first.errors
    path = (
        tmp_path
        / APPROVED_CHANGE_PLAN_LINKS_DIRNAME
        / construction.artifact_id
        / APPROVED_CHANGE_PLAN_LINK_FILENAME
    )
    assert path.read_bytes() == construction.canonical_bytes
    before = (path.stat().st_mtime_ns, path.parent.stat().st_mtime_ns)
    loaded = load_persisted_approved_change_plan_link_artifact(tmp_path, construction.artifact_id)
    assert loaded.status == "plan_link_artifact_loaded"
    second = publish_approved_change_plan_link_artifact(
        approval.approval_artifact_id, ready_packet(), **kwargs
    )
    assert second.status == "plan_link_artifact_already_present"
    assert before == (path.stat().st_mtime_ns, path.parent.stat().st_mtime_ns)


def test_bad_artifact_confirmation_writes_no_plan_link_root(tmp_path):
    approval, _ = prepared(tmp_path)
    result = publish_approved_change_plan_link_artifact(
        approval.approval_artifact_id,
        ready_packet(),
        data_dir=tmp_path,
        confirm_capability_catalog_identity_sha256=catalog_identity(),
        confirm_lane_declaration_identity_sha256=lane_identity(),
        confirm_plan_sha256=canonical_plan_sha256(ready_packet()),
        confirm_plan_link_artifact_identity_sha256="0" * 64,
    )
    assert result.status == "artifact_confirmation_mismatch"
    assert not (tmp_path / APPROVED_CHANGE_PLAN_LINKS_DIRNAME).exists()


def test_loader_rejects_invalid_ids_without_filesystem_access(tmp_path):
    for artifact_id in ("latest", "acpl_deadbeef", "acpl_" + "A" * 64, "../acpl_" + "0" * 64):
        result = load_persisted_approved_change_plan_link_artifact(tmp_path, artifact_id)
        assert result.status == "invalid_plan_link_artifact_id"
        assert result.filesystem_accessed is False
