"""Focused deterministic tests for PR337 plan-link artifact persistence."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import pytest
from test_pr323_approved_change_plan_link import (
    catalog_identity,
    lane_identity,
    link,
    ready_packet,
    supported_artifact,
)

from shellforgeai.core import approved_change_plan_link_artifact_persistence as persistence
from shellforgeai.core.approved_change_approval_persistence import AtomicNoReplaceOutcome
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


def _publisher_kwargs(tmp_path: Path, construction):
    return dict(
        data_dir=tmp_path,
        confirm_capability_catalog_identity_sha256=catalog_identity(),
        confirm_lane_declaration_identity_sha256=lane_identity(),
        confirm_plan_sha256=canonical_plan_sha256(ready_packet()),
        confirm_plan_link_artifact_identity_sha256=construction.artifact_identity_sha256,
    )


def _artifact_path(tmp_path: Path, artifact_id: str) -> Path:
    return (
        tmp_path
        / APPROVED_CHANGE_PLAN_LINKS_DIRNAME
        / artifact_id
        / APPROVED_CHANGE_PLAN_LINK_FILENAME
    )


def _assert_fixed_false_ledger(result):
    for field in (
        "plan_packet_persisted",
        "plan_packet_freshly_revalidated",
        "authenticated_identity_evaluated",
        "approval_freshness_evaluated",
        "authorization_evaluated",
        "preflight_evaluated",
        "current_state_revalidation_evaluated",
        "pr304_evidence_freshness_evaluated",
        "receipt_created",
        "receipt_linked",
        "execution_allowed",
        "execution_available",
        "host_configuration_mutation_performed",
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
    ):
        assert getattr(result, field) is False, field
    assert result.execution_status == "not_executed"


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


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("confirm_capability_catalog_identity_sha256", "", "plan_link_not_available"),
        ("confirm_capability_catalog_identity_sha256", "0" * 63, "plan_link_not_available"),
        ("confirm_capability_catalog_identity_sha256", "A" * 64, "plan_link_not_available"),
        (
            "confirm_capability_catalog_identity_sha256",
            "cat_" + "0" * 64,
            "plan_link_not_available",
        ),
        ("confirm_capability_catalog_identity_sha256", "g" * 64, "plan_link_not_available"),
        ("confirm_capability_catalog_identity_sha256", "0" * 64, "plan_link_not_available"),
        ("confirm_lane_declaration_identity_sha256", "", "plan_link_not_available"),
        ("confirm_lane_declaration_identity_sha256", "0" * 63, "plan_link_not_available"),
        ("confirm_lane_declaration_identity_sha256", "A" * 64, "plan_link_not_available"),
        ("confirm_lane_declaration_identity_sha256", "lane_" + "0" * 64, "plan_link_not_available"),
        ("confirm_lane_declaration_identity_sha256", "g" * 64, "plan_link_not_available"),
        ("confirm_lane_declaration_identity_sha256", "0" * 64, "plan_link_not_available"),
        ("confirm_plan_sha256", "", "plan_link_not_available"),
        ("confirm_plan_sha256", "0" * 63, "plan_link_not_available"),
        ("confirm_plan_sha256", "A" * 64, "plan_link_not_available"),
        ("confirm_plan_sha256", "sha_" + "0" * 64, "plan_link_not_available"),
        ("confirm_plan_sha256", "g" * 64, "plan_link_not_available"),
        ("confirm_plan_sha256", "0" * 64, "plan_link_not_available"),
        ("confirm_plan_link_artifact_identity_sha256", "", "invalid_plan_link_artifact_input"),
        (
            "confirm_plan_link_artifact_identity_sha256",
            "0" * 63,
            "invalid_plan_link_artifact_input",
        ),
        (
            "confirm_plan_link_artifact_identity_sha256",
            "A" * 64,
            "invalid_plan_link_artifact_input",
        ),
        (
            "confirm_plan_link_artifact_identity_sha256",
            "acpl_" + "0" * 64,
            "invalid_plan_link_artifact_input",
        ),
        (
            "confirm_plan_link_artifact_identity_sha256",
            "g" * 64,
            "invalid_plan_link_artifact_input",
        ),
        ("confirm_plan_link_artifact_identity_sha256", "0" * 64, "artifact_confirmation_mismatch"),
    ],
)
def test_confirmation_failures_write_no_pr337_artifact_root(tmp_path, field, value, expected):
    approval, construction = prepared(tmp_path)
    kwargs = _publisher_kwargs(tmp_path, construction)
    kwargs[field] = value
    result = publish_approved_change_plan_link_artifact(
        approval.approval_artifact_id, ready_packet(), **kwargs
    )
    assert result.status == expected
    assert not (tmp_path / APPROVED_CHANGE_PLAN_LINKS_DIRNAME).exists()
    assert result.artifact_write_performed is False
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.temporary_directory_created is False
    _assert_fixed_false_ledger(result)


@pytest.mark.parametrize(
    ("mutator", "identity", "artifact_id"),
    [
        (lambda p: {**p, "schema_version": "2"}, None, None),
        (lambda p: {**p, "artifact_type": "wrong"}, None, None),
        (lambda p: {k: v for k, v in p.items() if k != "plan_sha256"}, None, None),
        (lambda p: {**p, "extra": True}, None, None),
        (lambda p: {**p, "plan_sha256": 1}, None, None),
        (lambda p: {**p, "approval_artifact_id": "bad"}, None, None),
        (lambda p: {**p, "approval_artifact_identity_sha256": "0" * 64}, None, None),
        (lambda p: {**p, "subject_sha256": "0" * 64}, None, None),
        (lambda p: {**p, "capability_binding_identity_sha256": "0" * 64}, None, None),
        (lambda p: {**p, "capability_catalog_identity_sha256": "0" * 64}, None, None),
        (lambda p: {**p, "lane_declaration_identity_sha256": "0" * 64}, None, None),
        (lambda p: {**p, "capability_id": "wrong.capability"}, None, None),
        (lambda p: {**p, "lane_id": "wrong.lane"}, None, None),
        (lambda p: {**p, "plan_sha256": "0" * 64}, None, None),
        (lambda p: {**p, "plan_link_identity_sha256": "0" * 64}, None, None),
        (lambda p: {**p, "plan_link": {**p["plan_link"], "plan_sha256": "0" * 64}}, None, None),
        (lambda p: p, "0" * 64, None),
        (lambda p: p, None, "acpl_" + "0" * 64),
        (lambda p: p, "0" * 64, "acpl_" + "1" * 64),
    ],
)
def test_validator_corruption_matrix_fails_closed(tmp_path, mutator, identity, artifact_id):
    _, construction = prepared(tmp_path)
    payload = json.loads(construction.canonical_bytes)
    result = validate_approved_change_plan_link_artifact(
        mutator(payload), artifact_identity_sha256=identity, artifact_id=artifact_id
    )
    assert result.status == "plan_link_artifact_invalid"
    assert result.errors == tuple(sorted(set(result.errors)))
    assert b"operations" not in json.dumps(result.model_dump(mode="json")).encode()
    _assert_fixed_false_ledger(result)


@pytest.mark.parametrize(
    "bad_id",
    [
        "",
        "latest",
        "current",
        "acpl_" + "0" * 63,
        "acpl_" + "0" * 65,
        "acpl_" + "A" * 64,
        "aca_" + "0" * 64,
        " acpl_" + "0" * 64,
        "acpl_" + "0" * 64 + " ",
        "acpl/" + "0" * 64,
        "../acpl_" + "0" * 64,
        "/tmp/acpl_" + "0" * 64,
        "acpl_" + "0" * 64 + ".json",
    ],
)
def test_exact_id_references_reject_before_filesystem(tmp_path, bad_id):
    result = load_persisted_approved_change_plan_link_artifact(tmp_path, bad_id)
    assert result.status == "invalid_plan_link_artifact_id"
    assert result.filesystem_accessed is False
    assert not tmp_path.exists() or list(tmp_path.iterdir()) == []
    _assert_fixed_false_ledger(result)


@pytest.mark.parametrize(
    "writer",
    [
        lambda b: b.replace(b'","artifact_type"', b', "artifact_type"', 1),
        lambda b: b + b"\n",
        lambda b: b"\xef\xbb\xbf" + b,
        lambda b: b"\xff",
        lambda b: b"",
        lambda b: b"{",
        lambda b: b'{"schema_version":"1","schema_version":"1"}',
        lambda b: b.replace(b'"schema_version":"1"', b'"schema_version":"2"', 1),
        lambda b: b.replace(
            b'"artifact_type":"approved_change_plan_link_artifact"', b'"artifact_type":"wrong"', 1
        ),
        lambda b: b.replace(b'"plan_sha256"', b'"extra"', 1),
        lambda b: b.replace(b'"plan_link_identity_sha256"', b'"bad_plan_link_identity_sha256"', 1),
    ],
)
def test_loader_rejects_persisted_byte_corruption_without_repair(tmp_path, writer):
    _, construction = prepared(tmp_path)
    path = _artifact_path(tmp_path, construction.artifact_id)
    path.parent.mkdir(parents=True)
    raw = writer(construction.canonical_bytes)
    path.write_bytes(raw)
    before = path.read_bytes()
    result = load_persisted_approved_change_plan_link_artifact(tmp_path, construction.artifact_id)
    assert result.status == "plan_link_artifact_invalid"
    assert path.read_bytes() == before
    assert result.read_only is True
    assert result.mutation_performed is False
    _assert_fixed_false_ledger(result)


def test_loader_rejects_oversized_file(tmp_path):
    _, construction = prepared(tmp_path)
    path = _artifact_path(tmp_path, construction.artifact_id)
    path.parent.mkdir(parents=True)
    path.write_bytes(b"{" + b" " * persistence.MAX_PERSISTED_PLAN_LINK_ARTIFACT_BYTES)
    result = load_persisted_approved_change_plan_link_artifact(tmp_path, construction.artifact_id)
    assert result.status == "plan_link_artifact_invalid"


@pytest.mark.parametrize("extra_name", ["extra.txt", "subdir"])
def test_existing_destination_with_extra_entry_blocks_and_preserves(tmp_path, extra_name):
    approval, construction = prepared(tmp_path)
    path = _artifact_path(tmp_path, construction.artifact_id)
    path.parent.mkdir(parents=True)
    path.write_bytes(construction.canonical_bytes)
    extra = path.parent / extra_name
    if extra_name == "subdir":
        extra.mkdir()
    else:
        extra.write_text("preserve", encoding="utf-8")
    before = sorted(p.name for p in path.parent.iterdir())
    result = publish_approved_change_plan_link_artifact(
        approval.approval_artifact_id, ready_packet(), **_publisher_kwargs(tmp_path, construction)
    )
    assert result.status == "plan_link_artifact_conflict"
    assert sorted(p.name for p in path.parent.iterdir()) == before
    assert extra.exists()


def test_symlink_root_directory_and_file_are_refused(tmp_path):
    _, construction = prepared(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    root = tmp_path / APPROVED_CHANGE_PLAN_LINKS_DIRNAME
    os.symlink(target, root)
    assert (
        load_persisted_approved_change_plan_link_artifact(tmp_path, construction.artifact_id).status
        == "plan_link_artifact_load_blocked"
    )
    root.unlink()
    artifact_dir = root / construction.artifact_id
    root.mkdir()
    os.symlink(target, artifact_dir)
    assert load_persisted_approved_change_plan_link_artifact(
        tmp_path, construction.artifact_id
    ).status in {"plan_link_artifact_invalid", "plan_link_artifact_load_blocked"}
    artifact_dir.unlink()
    artifact_dir.mkdir()
    os.symlink(target, artifact_dir / APPROVED_CHANGE_PLAN_LINK_FILENAME)
    assert (
        load_persisted_approved_change_plan_link_artifact(tmp_path, construction.artifact_id).status
        == "plan_link_artifact_invalid"
    )


@pytest.mark.parametrize("outcome", ["destination_exists", "rejected", "unsupported", "failed"])
def test_atomic_race_and_failures_clean_only_invocation_pending(tmp_path, monkeypatch, outcome):
    approval, construction = prepared(tmp_path)
    other_pending = tmp_path / APPROVED_CHANGE_PLAN_LINKS_DIRNAME / ".pending-other"

    def fake_publish(source, destination):
        other_pending.mkdir(exist_ok=True)
        if outcome == "destination_exists":
            destination.mkdir(parents=True, exist_ok=True)
            (destination / APPROVED_CHANGE_PLAN_LINK_FILENAME).write_bytes(
                construction.canonical_bytes
            )
        return AtomicNoReplaceOutcome(outcome, "test", "injected")

    monkeypatch.setattr(persistence, "atomic_no_replace_approval_directory_publish", fake_publish)
    result = publish_approved_change_plan_link_artifact(
        approval.approval_artifact_id, ready_packet(), **_publisher_kwargs(tmp_path, construction)
    )
    if outcome == "destination_exists":
        assert result.status == "plan_link_artifact_already_present"
    else:
        assert result.status == "plan_link_artifact_publication_blocked"
    root = tmp_path / APPROVED_CHANGE_PLAN_LINKS_DIRNAME
    assert not [p for p in root.glob(".pending-*") if p.name != ".pending-other"]
    assert other_pending.exists()
    assert result.temporary_directory_created is True
    assert result.cleanup_status == "completed"
    assert result.temporary_directory_cleaned is True


def test_atomic_conflicting_race_cleans_pending_and_preserves_competitor(tmp_path, monkeypatch):
    approval, construction = prepared(tmp_path)
    competitor = b"not canonical"

    def fake_publish(source, destination):
        destination.mkdir(parents=True, exist_ok=True)
        (destination / APPROVED_CHANGE_PLAN_LINK_FILENAME).write_bytes(competitor)
        return AtomicNoReplaceOutcome("destination_exists", "test", "injected")

    monkeypatch.setattr(persistence, "atomic_no_replace_approval_directory_publish", fake_publish)
    result = publish_approved_change_plan_link_artifact(
        approval.approval_artifact_id, ready_packet(), **_publisher_kwargs(tmp_path, construction)
    )
    assert result.status == "plan_link_artifact_conflict"
    assert _artifact_path(tmp_path, construction.artifact_id).read_bytes() == competitor
    root = tmp_path / APPROVED_CHANGE_PLAN_LINKS_DIRNAME
    assert not list(root.glob(".pending-*"))
    assert result.cleanup_status == "completed"


def test_cleanup_failure_is_reported_without_deleting_competitor(tmp_path, monkeypatch):
    approval, construction = prepared(tmp_path)

    def fake_publish(source, destination):
        destination.mkdir(parents=True, exist_ok=True)
        (destination / APPROVED_CHANGE_PLAN_LINK_FILENAME).write_bytes(b"competitor")
        return AtomicNoReplaceOutcome("destination_exists", "test", "injected")

    monkeypatch.setattr(persistence, "atomic_no_replace_approval_directory_publish", fake_publish)
    monkeypatch.setattr(persistence.os, "rmdir", lambda path: (_ for _ in ()).throw(OSError("no")))
    result = publish_approved_change_plan_link_artifact(
        approval.approval_artifact_id, ready_packet(), **_publisher_kwargs(tmp_path, construction)
    )
    assert result.status == "plan_link_artifact_publication_blocked"
    assert result.cleanup_status == "incomplete"
    assert _artifact_path(tmp_path, construction.artifact_id).read_bytes() == b"competitor"


def test_static_dependency_boundary_excludes_execution_current_state_and_external_surfaces():
    source = Path(
        "src/shellforgeai/core/approved_change_plan_link_artifact_persistence.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    forbidden = (
        "approved_change_plan_current_state",
        "windows_runtime_reconcile_execution",
        "subprocess",
        "requests",
        "urllib",
        "socket",
        "openai",
        "receipt",
        "preflight",
        "authorization",
        "interactive",
        "cli",
    )
    for needle in forbidden:
        assert all(needle not in name for name in imported)


def test_public_results_carry_complete_fixed_safety_ledgers(tmp_path):
    _, construction = prepared(tmp_path)
    validation = validate_approved_change_plan_link_artifact(construction.artifact)
    loaded = load_persisted_approved_change_plan_link_artifact(tmp_path, construction.artifact_id)
    for result in (validation, construction, loaded):
        _assert_fixed_false_ledger(result)
