"""Focused PR318 tests: explicit approval binding for persisted bundles.

PR309 owns the subject schema, the subject identity, the attestation, the
contract, and approval-binding verification. PR316 owns the four-file bundle,
its canonical bytes, and the bundle identity. PR317 owns the governed publisher
and the exact-ID read-only loader.

These tests prove PR318 adds exactly one read-only operation on top of those
maintained contracts: it loads one exact persisted bundle through PR317,
requires two independent explicit confirmations, sources the subject only from
the fixed PR316 subject file, creates exactly one in-memory
``ApprovalAttestation`` and one in-memory ``ApprovedChangeContract``, verifies
the exact binding through PR309, and persists, publishes, authorizes,
capability-evaluates, preflights, receipts, and executes nothing at all.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
import random
import socket
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

# The PR316 focused suite owns the maintained reviewed-context fixtures. They
# are reused verbatim so PR318 never invents its own bundle or subject schema.
from test_pr316_approved_change_artifact_bundle import (  # noqa: E402
    FIXTURE_A_BUNDLE_IDENTITY_SHA256,
    FIXTURE_A_CONTEXT_SHA256,
    FIXTURE_A_EVIDENCE_SHA256,
    FIXTURE_A_SUBJECT_SHA256,
    build,
    context_alt_provenance,
    context_b,
)

from shellforgeai.core import approved_change_approval_workflow as workflow
from shellforgeai.core.approvals import Proposal
from shellforgeai.core.approved_change_approval_workflow import (
    APPROVAL_DECISION_APPROVE,
    APPROVAL_WORKFLOW_STATUSES,
    PERMANENT_APPROVAL_WORKFLOW_WARNINGS,
    ApprovedChangeApprovalWorkflowResult,
    construct_approved_change_contract_from_persisted_bundle,
)
from shellforgeai.core.approved_change_artifact_bundle import (
    APPROVED_CHANGE_SUBJECT_FILENAME,
    BUNDLE_FILENAMES,
    BUNDLE_ID_PREFIX,
    CONSTRUCTION_EVIDENCE_FILENAME,
    MANIFEST_FILENAME,
    SUPPLEMENTAL_CONTEXT_FILENAME,
    validate_approved_change_artifact_bundle,
)
from shellforgeai.core.approved_change_artifact_persistence import (
    APPROVED_CHANGE_ARTIFACTS_DIRNAME,
    ApprovedChangeArtifactBundleLoadResult,
    publish_approved_change_artifact_bundle,
)
from shellforgeai.core.approved_change_contract import (
    APPROVAL_SCOPE_EXACT_SUBJECT_ONLY,
    ApprovalAttestation,
    ApprovedChangeContract,
    canonical_subject_json,
    compute_subject_sha256,
)

NOT_A_HASH = "0" * 64

# --------------------------------------------------------------------------
# Fixed explicit approval metadata
#
# Every value is committed here. Nothing is defaulted, inferred, generated,
# read from a clock, or derived from reviewer provenance.
# --------------------------------------------------------------------------

APPROVED_BY = "operator-approver"
APPROVED_AT = datetime(2026, 7, 27, 9, 0, 0, tzinfo=timezone.utc)
#: The exact same instant spelled with a +02:00 offset instead of UTC.
ALT_ZONE_APPROVED_AT = datetime(2026, 7, 27, 11, 0, 0, tzinfo=timezone(timedelta(hours=2)))
NAIVE_APPROVED_AT = datetime(2026, 7, 27, 9, 0, 0)
REASON = "reviewed the exact persisted reviewed-change subject"
#: Every PR314 reviewer in the maintained fixtures. None of them is the approver.
FIXTURE_REVIEWERS = ("operator-a", "operator-b", "operator-z")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def bundle_a():
    result = build()
    assert result.status == "bundle_constructed"
    return result.bundle


def bundle_b():
    result = build(context_b())
    assert result.status == "bundle_constructed"
    return result.bundle


def bundle_same_subject():
    """Fixture A's exact subject values reviewed by a different actor."""
    result = build(context_alt_provenance())
    assert result.status == "bundle_constructed"
    return result.bundle


def data_dir(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    root.mkdir()
    return root


def publish(bundle, root: Path):
    result = publish_approved_change_artifact_bundle(
        bundle,
        data_dir=root,
        confirm_bundle_identity_sha256=bundle.bundle_identity_sha256,
    )
    assert result.status == "bundle_published"
    return result


def subject_sha256_of(bundle) -> str:
    return stored_file(bundle, APPROVED_CHANGE_SUBJECT_FILENAME).sha256


def stored_file(bundle, filename: str):
    return next(item for item in bundle.files if item.relative_path == filename)


_EXACT = object()


def approve(
    bundle,
    root: Path,
    *,
    bundle_id=_EXACT,
    decision=APPROVAL_DECISION_APPROVE,
    confirm_bundle=_EXACT,
    confirm_subject=_EXACT,
    approved_by=APPROVED_BY,
    approved_at=APPROVED_AT,
    reason=REASON,
):
    """Invoke PR318 with fixed explicit inputs and per-test overrides."""
    return construct_approved_change_contract_from_persisted_bundle(
        bundle.bundle_id if bundle_id is _EXACT else bundle_id,
        data_dir=root,
        approval_decision=decision,
        confirm_bundle_identity_sha256=(
            bundle.bundle_identity_sha256 if confirm_bundle is _EXACT else confirm_bundle
        ),
        confirm_subject_sha256=(
            subject_sha256_of(bundle) if confirm_subject is _EXACT else confirm_subject
        ),
        approved_by=approved_by,
        approved_at=approved_at,
        reason=reason,
    )


def publication_root(root: Path) -> Path:
    return root / APPROVED_CHANGE_ARTIFACTS_DIRNAME


def bundle_directory(root: Path, bundle) -> Path:
    return publication_root(root) / bundle.bundle_id


def write_bundle_directory(root: Path, bundle, *, mutate=None, name=None) -> Path:
    """Materialise a bundle directory directly, bypassing the publisher."""
    directory = publication_root(root) / (bundle.bundle_id if name is None else name)
    directory.mkdir(parents=True)
    payload = {item.relative_path: item.content_utf8.encode("utf-8") for item in bundle.files}
    if mutate is not None:
        payload = mutate(dict(payload))
    for filename, data in payload.items():
        (directory / filename).write_bytes(data)
    return directory


def snapshot(root: Path) -> dict[str, tuple[bytes, int, int]]:
    """Record every persisted byte, size, and modification time under ``root``."""
    recorded: dict[str, tuple[bytes, int, int]] = {}
    for path in sorted(root.rglob("*")):
        key = str(path.relative_to(root))
        if path.is_dir():
            recorded[key] = (b"", -1, path.stat().st_mtime_ns)
        else:
            info = path.stat()
            recorded[key] = (path.read_bytes(), info.st_size, info.st_mtime_ns)
    return recorded


def assert_no_approval(result) -> None:
    """A failure must never carry an approval, a contract, or a partial claim."""
    assert isinstance(result, ApprovedChangeApprovalWorkflowResult)
    assert result.status in APPROVAL_WORKFLOW_STATUSES
    assert result.status != "approval_contract_constructed"
    assert result.approval_succeeded is False
    assert result.approval is None
    assert result.contract is None
    assert result.approval_scope == ""
    assert result.approval_binding_valid is False
    assert result.approval_created is False
    assert result.contract_created is False
    assert result.errors
    assert isinstance(result.errors, tuple)
    assert all(isinstance(error, str) for error in result.errors)
    assert "Traceback" not in " ".join(result.errors)
    assert list(result.errors) == sorted(set(result.errors))
    assert_permanent_safety(result)


def assert_permanent_safety(result) -> None:
    """The fields PR318 may never claim, on success or on failure."""
    assert result.read_only is True
    assert result.mutation_performed is False
    assert result.artifact_write_performed is False
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.approval_persisted is False
    assert result.contract_persisted is False
    assert result.authorization_evaluated is False
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert result.preflight_evaluated is False
    assert result.receipt_created is False
    assert result.receipt_linked is False
    assert result.host_configuration_mutation_performed is False
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"
    assert result.warnings == PERMANENT_APPROVAL_WORKFLOW_WARNINGS


def assert_inert(result) -> None:
    """The ledger for a rejection that never reached the filesystem."""
    assert result.filesystem_accessed is False
    assert_no_approval(result)


@pytest.fixture
def published_a(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish(bundle, root)
    return root, bundle


# --------------------------------------------------------------------------
# Successful explicit approval
# --------------------------------------------------------------------------


def test_explicit_approval_binds_one_contract_to_the_exact_persisted_subject(published_a):
    root, bundle = published_a
    before = snapshot(root)

    result = approve(bundle, root)

    assert isinstance(result, ApprovedChangeApprovalWorkflowResult)
    assert result.status == "approval_contract_constructed"
    assert result.errors == ()
    assert result.approval_succeeded is True
    assert result.approval_decision == "approve"
    assert result.requested_bundle_id == bundle.bundle_id
    assert result.loaded_bundle_id == bundle.bundle_id
    assert result.confirmed_bundle_identity_sha256 == bundle.bundle_identity_sha256
    assert result.computed_bundle_identity_sha256 == bundle.bundle_identity_sha256
    assert result.confirmed_subject_sha256 == subject_sha256_of(bundle)
    assert result.computed_subject_sha256 == subject_sha256_of(bundle)
    assert result.source_bundle_loaded is True
    assert result.source_bundle_valid is True
    assert result.approval_binding_valid is True
    assert result.approval_scope == APPROVAL_SCOPE_EXACT_SUBJECT_ONLY

    # Exactly one attestation with the exact explicit metadata.
    assert isinstance(result.approval, ApprovalAttestation)
    assert result.approval.approved_by == APPROVED_BY
    assert result.approval.approved_at == APPROVED_AT
    assert result.approval.approved_at.tzinfo is not None
    assert result.approval.reason == REASON
    assert result.approval.subject_sha256 == subject_sha256_of(bundle)
    assert result.approval.scope == APPROVAL_SCOPE_EXACT_SUBJECT_ONLY

    # Exactly one contract carrying that exact subject and that exact approval.
    assert isinstance(result.contract, ApprovedChangeContract)
    assert result.contract.approval is result.approval
    assert compute_subject_sha256(result.contract.subject) == subject_sha256_of(bundle)

    # PR309 verified the binding.
    assert result.binding_validation is not None
    assert result.binding_validation.status == "contract_valid"
    assert result.binding_validation.approval_binding_valid is True
    assert result.binding_validation.computed_subject_sha256 == subject_sha256_of(bundle)
    # ... and it evaluated no capability support.
    assert result.binding_validation.capability_supported is False
    assert result.capability_support_evaluated is False
    assert result.execution_allowed is False
    assert result.execution_status == "not_executed"

    assert snapshot(root) == before


def test_successful_approval_reports_the_accurate_safety_ledger(published_a):
    root, bundle = published_a
    result = approve(bundle, root)

    assert result.read_only is True
    assert result.mutation_performed is False
    assert result.filesystem_accessed is True
    assert result.artifact_write_performed is False
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.approval_input_evaluated is True
    assert result.approval_created is True
    assert result.approval_persisted is False
    assert result.contract_created is True
    assert result.contract_persisted is False
    assert result.approval_binding_valid is True
    assert result.authorization_evaluated is False
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert result.preflight_evaluated is False
    assert result.receipt_created is False
    assert result.receipt_linked is False
    assert result.host_configuration_mutation_performed is False
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"


def test_successful_approval_creates_no_file_and_no_new_directory(published_a):
    root, bundle = published_a
    before = snapshot(root)
    approve(bundle, root)
    after = snapshot(root)
    assert after == before
    assert sorted(publication_root(root).iterdir()) == [bundle_directory(root, bundle)]
    assert sorted(item.name for item in bundle_directory(root, bundle).iterdir()) == sorted(
        BUNDLE_FILENAMES
    )


def test_permanent_warnings_are_stated_on_every_result(published_a):
    root, bundle = published_a
    outcomes = [
        approve(bundle, root),
        approve(bundle, root, decision="yes"),
        approve(bundle, root, confirm_subject=NOT_A_HASH),
        approve(bundle, root, bundle_id=f"{BUNDLE_ID_PREFIX}{'a' * 64}"),
    ]
    for result in outcomes:
        assert result.warnings == PERMANENT_APPROVAL_WORKFLOW_WARNINGS
    joined = " ".join(PERMANENT_APPROVAL_WORKFLOW_WARNINGS)
    for phrase in (
        "self-asserted metadata",
        "reviewer provenance is not approval",
        "exact confirmed PR309 subject SHA-256",
        "does not expand attestation scope",
        "not persisted approval",
        "not authorization",
        "not capability support",
        "no capability registry",
        "no current-state preflight",
        "no receipt",
        "no execution eligibility",
        "reviewed before sharing",
        "no redaction",
    ):
        assert phrase in joined, phrase


# --------------------------------------------------------------------------
# Explicit approval decision
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "decision",
    [
        None,
        True,
        False,
        1,
        0,
        "",
        " ",
        "approve ",
        " approve",
        "approve\n",
        "APPROVE",
        "Approve",
        "approved",
        "approval",
        "yes",
        "y",
        "true",
        "ok",
        "confirm",
        "reject",
    ],
)
def test_only_the_exact_approve_literal_is_accepted(published_a, decision):
    root, bundle = published_a
    result = approve(bundle, root, decision=decision)
    assert result.status == "invalid_approval_input"
    assert result.approval_decision == ""
    assert_inert(result)


def test_an_invalid_decision_reaches_no_filesystem_primitive(published_a, monkeypatch):
    root, bundle = published_a

    def boom(*args, **kwargs):
        raise AssertionError("the persisted-bundle loader was reached")

    monkeypatch.setattr(workflow, "load_persisted_approved_change_artifact_bundle", boom)
    result = approve(bundle, root, decision="approved")
    assert result.status == "invalid_approval_input"
    assert result.filesystem_accessed is False


def test_no_decision_default_exists():
    signature = inspect.signature(construct_approved_change_contract_from_persisted_bundle)
    for name in (
        "approval_decision",
        "confirm_bundle_identity_sha256",
        "confirm_subject_sha256",
        "approved_by",
        "approved_at",
        "reason",
        "data_dir",
    ):
        parameter = signature.parameters[name]
        assert parameter.default is inspect.Parameter.empty, name
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY, name
    assert signature.parameters["bundle_id"].default is inspect.Parameter.empty


def test_no_rejection_or_state_transition_surface_exists():
    for name in (
        "reject",
        "revoke",
        "cancel",
        "expire",
        "supersede",
        "approval_status",
        "transition_approval",
    ):
        assert not hasattr(workflow, name), name
    assert set(APPROVAL_WORKFLOW_STATUSES) == {
        "approval_contract_constructed",
        "approval_blocked",
        "invalid_approval_input",
        "persisted_bundle_not_available",
        "persisted_bundle_invalid",
        "approval_binding_failed",
    }


# --------------------------------------------------------------------------
# Exact bundle reference
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reference",
    [
        None,
        "",
        "latest",
        "current",
        "most recent",
        FIXTURE_A_BUNDLE_IDENTITY_SHA256,
        f"{BUNDLE_ID_PREFIX}{FIXTURE_A_BUNDLE_IDENTITY_SHA256.upper()}",
        f"{BUNDLE_ID_PREFIX}{FIXTURE_A_BUNDLE_IDENTITY_SHA256[:32]}",
        f" {BUNDLE_ID_PREFIX}{FIXTURE_A_BUNDLE_IDENTITY_SHA256}",
        f"{BUNDLE_ID_PREFIX}{FIXTURE_A_BUNDLE_IDENTITY_SHA256} ",
        f"acb/{FIXTURE_A_BUNDLE_IDENTITY_SHA256}",
        f"../{BUNDLE_ID_PREFIX}{FIXTURE_A_BUNDLE_IDENTITY_SHA256}",
        f"{APPROVED_CHANGE_ARTIFACTS_DIRNAME}/{BUNDLE_ID_PREFIX}{FIXTURE_A_BUNDLE_IDENTITY_SHA256}",
    ],
)
def test_only_one_exact_full_bundle_id_is_accepted(published_a, reference):
    root, bundle = published_a
    result = approve(bundle, root, bundle_id=reference)
    assert result.status == "invalid_approval_input"
    assert result.requested_bundle_id == ""
    assert_inert(result)


def test_an_absolute_persisted_path_is_not_a_bundle_reference(published_a):
    root, bundle = published_a
    result = approve(bundle, root, bundle_id=str(bundle_directory(root, bundle)))
    assert result.status == "invalid_approval_input"
    assert_inert(result)


# --------------------------------------------------------------------------
# Bundle-identity confirmation gate
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "confirmation",
    [
        None,
        "",
        "not-a-hash",
        FIXTURE_A_BUNDLE_IDENTITY_SHA256[:32],
        FIXTURE_A_BUNDLE_IDENTITY_SHA256.upper(),
        f"{BUNDLE_ID_PREFIX}{FIXTURE_A_BUNDLE_IDENTITY_SHA256}",
        f" {FIXTURE_A_BUNDLE_IDENTITY_SHA256}",
    ],
)
def test_malformed_bundle_identity_confirmations_are_invalid_input(published_a, confirmation):
    root, bundle = published_a
    result = approve(bundle, root, confirm_bundle=confirmation)
    assert result.status == "invalid_approval_input"
    assert result.confirmed_bundle_identity_sha256 == ""
    assert_inert(result)


@pytest.mark.parametrize("confirmation_of", ["subject", "context", "evidence", "stale"])
def test_a_wrong_bundle_identity_confirmation_blocks_approval(published_a, confirmation_of):
    root, bundle = published_a
    confirmation = {
        "subject": FIXTURE_A_SUBJECT_SHA256,
        "context": FIXTURE_A_CONTEXT_SHA256,
        "evidence": FIXTURE_A_EVIDENCE_SHA256,
        "stale": NOT_A_HASH,
    }[confirmation_of]
    result = approve(bundle, root, confirm_bundle=confirmation)
    assert result.status == "approval_blocked"
    assert result.filesystem_accessed is True
    assert result.source_bundle_loaded is True
    assert result.computed_bundle_identity_sha256 == bundle.bundle_identity_sha256
    assert_no_approval(result)


def test_another_bundles_identity_cannot_confirm_this_bundle(tmp_path):
    root = data_dir(tmp_path)
    first, second = bundle_a(), bundle_b()
    publish(first, root)
    publish(second, root)
    before = snapshot(root)

    result = approve(first, root, confirm_bundle=second.bundle_identity_sha256)
    assert result.status == "approval_blocked"
    assert result.loaded_bundle_id == first.bundle_id
    assert_no_approval(result)
    assert snapshot(root) == before


def test_the_exact_bundle_identity_confirmation_is_accepted(published_a):
    root, bundle = published_a
    result = approve(bundle, root, confirm_bundle=bundle.bundle_identity_sha256)
    assert result.status == "approval_contract_constructed"
    assert result.confirmed_bundle_identity_sha256 == FIXTURE_A_BUNDLE_IDENTITY_SHA256


# --------------------------------------------------------------------------
# Subject confirmation gate
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "confirmation",
    [
        None,
        "",
        "not-a-hash",
        FIXTURE_A_SUBJECT_SHA256[:32],
        FIXTURE_A_SUBJECT_SHA256.upper(),
        f"{BUNDLE_ID_PREFIX}{FIXTURE_A_SUBJECT_SHA256}",
        f"{FIXTURE_A_SUBJECT_SHA256} ",
    ],
)
def test_malformed_subject_confirmations_are_invalid_input(published_a, confirmation):
    root, bundle = published_a
    result = approve(bundle, root, confirm_subject=confirmation)
    assert result.status == "invalid_approval_input"
    assert result.confirmed_subject_sha256 == ""
    assert_inert(result)


@pytest.mark.parametrize("confirmation_of", ["bundle_identity", "context", "evidence", "stale"])
def test_a_wrong_subject_confirmation_blocks_approval(published_a, confirmation_of):
    root, bundle = published_a
    confirmation = {
        "bundle_identity": FIXTURE_A_BUNDLE_IDENTITY_SHA256,
        "context": FIXTURE_A_CONTEXT_SHA256,
        "evidence": FIXTURE_A_EVIDENCE_SHA256,
        "stale": NOT_A_HASH,
    }[confirmation_of]
    result = approve(bundle, root, confirm_subject=confirmation)
    assert result.status == "approval_blocked"
    assert result.filesystem_accessed is True
    assert result.computed_subject_sha256 == FIXTURE_A_SUBJECT_SHA256
    assert_no_approval(result)


def test_a_legacy_proposal_fingerprint_is_not_a_subject_confirmation(published_a):
    root, bundle = published_a
    fingerprint = hashlib.sha256(b"legacy proposal schema v1 fingerprint").hexdigest()
    assert fingerprint != FIXTURE_A_SUBJECT_SHA256
    result = approve(bundle, root, confirm_subject=fingerprint)
    assert result.status == "approval_blocked"
    assert_no_approval(result)


def test_the_exact_subject_confirmation_is_accepted(published_a):
    root, bundle = published_a
    result = approve(bundle, root, confirm_subject=FIXTURE_A_SUBJECT_SHA256)
    assert result.status == "approval_contract_constructed"
    assert result.approval.subject_sha256 == FIXTURE_A_SUBJECT_SHA256


# --------------------------------------------------------------------------
# Explicit approval metadata
# --------------------------------------------------------------------------


@pytest.mark.parametrize("actor", [None, 1, "", "   ", "\t\n", "*", "all", "any", "ANY", "All"])
def test_unacceptable_actors_are_rejected_before_any_filesystem_access(published_a, actor):
    root, bundle = published_a
    result = approve(bundle, root, approved_by=actor)
    assert result.status == "invalid_approval_input"
    assert_inert(result)


@pytest.mark.parametrize("reason", [None, 1, "", "   ", "*", "all", "any"])
def test_unacceptable_reasons_are_rejected_before_any_filesystem_access(published_a, reason):
    root, bundle = published_a
    result = approve(bundle, root, reason=reason)
    assert result.status == "invalid_approval_input"
    assert_inert(result)


@pytest.mark.parametrize(
    "moment",
    [None, "2026-07-27T09:00:00Z", 1769504400, NAIVE_APPROVED_AT],
)
def test_a_naive_or_non_datetime_timestamp_is_rejected(published_a, moment):
    root, bundle = published_a
    result = approve(bundle, root, approved_at=moment)
    assert result.status == "invalid_approval_input"
    assert any("timezone-aware" in error for error in result.errors)
    assert_inert(result)


def test_an_equivalent_offset_timestamp_is_accepted_and_preserved(published_a):
    root, bundle = published_a
    assert ALT_ZONE_APPROVED_AT == APPROVED_AT

    utc = approve(bundle, root)
    offset = approve(bundle, root, approved_at=ALT_ZONE_APPROVED_AT)

    assert offset.status == "approval_contract_constructed"
    assert offset.approval.approved_at == APPROVED_AT
    assert offset.approval.approved_at == utc.approval.approved_at
    assert offset.approval.subject_sha256 == utc.approval.subject_sha256
    # The approval timestamp is approval metadata, never subject identity.
    assert offset.computed_subject_sha256 == utc.computed_subject_sha256


def test_unicode_actor_and_reason_are_preserved_exactly(published_a):
    root, bundle = published_a
    actor = "revisor-ñ"
    reason = "revisión explícita del asunto exacto"
    result = approve(bundle, root, approved_by=actor, reason=reason)
    assert result.status == "approval_contract_constructed"
    assert result.approval.approved_by == actor
    assert result.approval.reason == reason


def test_the_approver_is_never_a_reviewer_and_is_never_inferred(published_a):
    root, bundle = published_a
    result = approve(bundle, root)
    assert result.approval.approved_by == APPROVED_BY
    assert result.approval.approved_by not in FIXTURE_REVIEWERS
    stored_context = stored_file(bundle, SUPPLEMENTAL_CONTEXT_FILENAME).content_utf8
    for reviewer in FIXTURE_REVIEWERS:
        if reviewer in stored_context:
            assert result.approval.approved_by != reviewer
    # Reviewer provenance is still present in the reviewed artifact and is not approval.
    assert "operator-a" in stored_context
    assert "reviewed_by" in stored_context
    assert "reviewed_by" not in result.approval.model_dump(mode="json")


def test_approval_metadata_is_never_defaulted_from_the_environment(published_a, monkeypatch):
    root, bundle = published_a
    monkeypatch.setenv("USER", "environment-operator")
    monkeypatch.setenv("USERNAME", "environment-operator")
    result = approve(bundle, root)
    assert result.approval.approved_by == APPROVED_BY
    assert "environment-operator" not in result.approval.model_dump_json()


# --------------------------------------------------------------------------
# Persisted-source failures
# --------------------------------------------------------------------------


def test_a_missing_persisted_bundle_is_not_available(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    result = approve(bundle, root)
    assert result.status == "persisted_bundle_not_available"
    assert result.filesystem_accessed is True
    assert result.source_bundle_loaded is False
    assert_no_approval(result)


def test_a_different_persisted_bundle_id_is_not_available(tmp_path):
    root = data_dir(tmp_path)
    publish(bundle_a(), root)
    result = approve(bundle_b(), root)
    assert result.status == "persisted_bundle_not_available"
    assert_no_approval(result)


@pytest.mark.parametrize("unsafe", ["relative", "missing", "file"])
def test_an_unsafe_data_root_is_refused(tmp_path, unsafe):
    bundle = bundle_a()
    if unsafe == "relative":
        root = Path("relative-data-dir")
    elif unsafe == "missing":
        root = tmp_path / "absent"
    else:
        root = tmp_path / "not-a-directory"
        root.write_text("data", encoding="utf-8")
    result = approve(bundle, root)
    assert result.status == "persisted_bundle_not_available"
    assert result.filesystem_accessed is (unsafe != "relative")
    assert_no_approval(result)


@pytest.mark.parametrize("missing", list(BUNDLE_FILENAMES))
def test_a_missing_persisted_file_blocks_approval(tmp_path, missing):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    write_bundle_directory(
        root, bundle, mutate=lambda p: {k: v for k, v in p.items() if k != missing}
    )
    result = approve(bundle, root)
    assert result.status == "persisted_bundle_invalid"
    assert result.filesystem_accessed is True
    assert_no_approval(result)


def test_an_extra_persisted_file_blocks_approval(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    directory = write_bundle_directory(root, bundle)
    (directory / "extra.json").write_text("{}", encoding="utf-8")
    result = approve(bundle, root)
    assert result.status == "persisted_bundle_invalid"
    assert_no_approval(result)


def test_a_tampered_persisted_subject_blocks_approval(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()

    def tamper(payload):
        parsed = json.loads(payload[APPROVED_CHANGE_SUBJECT_FILENAME])
        parsed["blast_radius"] = "every host"
        payload[APPROVED_CHANGE_SUBJECT_FILENAME] = json.dumps(
            parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return payload

    write_bundle_directory(root, bundle, mutate=tamper)
    result = approve(bundle, root)
    assert result.status == "persisted_bundle_invalid"
    assert_no_approval(result)


def test_a_tampered_persisted_manifest_blocks_approval(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()

    def tamper(payload):
        parsed = json.loads(payload[MANIFEST_FILENAME])
        parsed["subject_sha256"] = NOT_A_HASH
        payload[MANIFEST_FILENAME] = json.dumps(
            parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return payload

    write_bundle_directory(root, bundle, mutate=tamper)
    result = approve(bundle, root)
    assert result.status == "persisted_bundle_invalid"
    assert_no_approval(result)


def test_a_mixed_persisted_bundle_blocks_approval(tmp_path):
    root = data_dir(tmp_path)
    first, second = bundle_a(), bundle_b()
    other = {item.relative_path: item.content_utf8.encode("utf-8") for item in second.files}

    def mix(payload):
        payload[CONSTRUCTION_EVIDENCE_FILENAME] = other[CONSTRUCTION_EVIDENCE_FILENAME]
        return payload

    write_bundle_directory(root, first, mutate=mix)
    result = approve(first, root)
    assert result.status == "persisted_bundle_invalid"
    assert_no_approval(result)


def test_a_bundle_stored_under_another_bundle_id_blocks_approval(tmp_path):
    root = data_dir(tmp_path)
    first, second = bundle_a(), bundle_b()
    write_bundle_directory(root, second, name=first.bundle_id)
    result = approve(first, root)
    assert result.status == "persisted_bundle_invalid"
    assert_no_approval(result)


def test_noncanonical_persisted_json_blocks_approval(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()

    def prettify(payload):
        parsed = json.loads(payload[APPROVED_CHANGE_SUBJECT_FILENAME])
        payload[APPROVED_CHANGE_SUBJECT_FILENAME] = json.dumps(
            parsed, indent=2, sort_keys=True, ensure_ascii=False
        ).encode("utf-8")
        return payload

    write_bundle_directory(root, bundle, mutate=prettify)
    result = approve(bundle, root)
    assert result.status == "persisted_bundle_invalid"
    assert_no_approval(result)


def test_persisted_bytes_are_never_repaired_or_republished(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()

    def prettify(payload):
        parsed = json.loads(payload[APPROVED_CHANGE_SUBJECT_FILENAME])
        payload[APPROVED_CHANGE_SUBJECT_FILENAME] = json.dumps(
            parsed, indent=2, sort_keys=True, ensure_ascii=False
        ).encode("utf-8")
        return payload

    write_bundle_directory(root, bundle, mutate=prettify)
    before = snapshot(root)
    approve(bundle, root)
    assert snapshot(root) == before


def test_a_loader_validation_failure_blocks_approval(published_a, monkeypatch):
    root, bundle = published_a
    broken = validate_approved_change_artifact_bundle("not a bundle")
    assert broken.bundle_valid is False

    def loader(bundle_id, *, data_dir):
        return ApprovedChangeArtifactBundleLoadResult(
            status="persisted_bundle_loaded",
            bundle_id=bundle_id,
            bundle_identity_sha256=bundle.bundle_identity_sha256,
            bundle=bundle,
            bundle_validation=broken,
            filesystem_accessed=True,
        )

    monkeypatch.setattr(workflow, "load_persisted_approved_change_artifact_bundle", loader)
    result = approve(bundle, root)
    assert result.status == "persisted_bundle_invalid"
    assert result.source_bundle_loaded is True
    assert result.source_bundle_valid is False
    assert_no_approval(result)


def test_a_missing_loader_validation_blocks_approval(published_a, monkeypatch):
    root, bundle = published_a

    def loader(bundle_id, *, data_dir):
        return ApprovedChangeArtifactBundleLoadResult(
            status="persisted_bundle_loaded",
            bundle_id=bundle_id,
            bundle_identity_sha256=bundle.bundle_identity_sha256,
            bundle=bundle,
            bundle_validation=None,
            filesystem_accessed=True,
        )

    monkeypatch.setattr(workflow, "load_persisted_approved_change_artifact_bundle", loader)
    result = approve(bundle, root)
    assert result.status == "persisted_bundle_invalid"
    assert_no_approval(result)


def test_a_loader_bundle_id_mismatch_blocks_approval(published_a, monkeypatch):
    root, bundle = published_a
    other = bundle_b()
    real = workflow.load_persisted_approved_change_artifact_bundle

    def loader(bundle_id, *, data_dir):
        loaded = real(bundle_id, data_dir=data_dir)
        return loaded.model_copy(update={"bundle_id": other.bundle_id})

    monkeypatch.setattr(workflow, "load_persisted_approved_change_artifact_bundle", loader)
    result = approve(bundle, root)
    assert result.status == "persisted_bundle_invalid"
    assert_no_approval(result)


def test_the_maintained_pr317_loader_is_the_only_persisted_source(published_a, monkeypatch):
    root, bundle = published_a
    calls: list[tuple[str, Path]] = []
    real = workflow.load_persisted_approved_change_artifact_bundle

    def loader(bundle_id, *, data_dir):
        calls.append((bundle_id, data_dir))
        return real(bundle_id, data_dir=data_dir)

    monkeypatch.setattr(workflow, "load_persisted_approved_change_artifact_bundle", loader)
    result = approve(bundle, root)
    assert result.status == "approval_contract_constructed"
    assert calls == [(bundle.bundle_id, root)]


# --------------------------------------------------------------------------
# Exact subject sourcing
# --------------------------------------------------------------------------


def test_the_subject_comes_only_from_the_fixed_pr316_subject_file(published_a):
    root, bundle = published_a
    result = approve(bundle, root)
    stored = stored_file(bundle, APPROVED_CHANGE_SUBJECT_FILENAME)
    assert canonical_subject_json(result.contract.subject) == stored.content_utf8
    assert hashlib.sha256(stored.content_utf8.encode("utf-8")).hexdigest() == stored.sha256
    assert result.approval.subject_sha256 == stored.sha256
    assert result.computed_subject_sha256 == compute_subject_sha256(result.contract.subject)


def test_no_caller_supplied_subject_contract_or_attestation_is_accepted():
    signature = inspect.signature(construct_approved_change_contract_from_persisted_bundle)
    assert set(signature.parameters) == {
        "bundle_id",
        "data_dir",
        "approval_decision",
        "confirm_bundle_identity_sha256",
        "confirm_subject_sha256",
        "approved_by",
        "approved_at",
        "reason",
    }
    rendered = str(signature)
    for token in (
        "ApprovedChangeSubject",
        "ApprovalAttestation",
        "ApprovedChangeContract",
        "ApprovedChangeArtifactBundle",
        "Proposal",
        "supported_capability",
        "token",
        "output_path",
        "receipt",
    ):
        assert token not in rendered, token


def test_the_persisted_subject_bytes_are_not_rewritten(published_a):
    root, bundle = published_a
    stored_path = bundle_directory(root, bundle) / APPROVED_CHANGE_SUBJECT_FILENAME
    before = stored_path.read_bytes()
    before_mtime = stored_path.stat().st_mtime_ns
    approve(bundle, root)
    assert stored_path.read_bytes() == before
    assert stored_path.stat().st_mtime_ns == before_mtime


# --------------------------------------------------------------------------
# Same subject, different bundle provenance
# --------------------------------------------------------------------------


def test_identical_subjects_with_different_provenance_stay_separately_confirmed(tmp_path):
    root = data_dir(tmp_path)
    first, second = bundle_a(), bundle_same_subject()

    # The two bundles share one subject identity but not one bundle identity.
    assert subject_sha256_of(first) == subject_sha256_of(second) == FIXTURE_A_SUBJECT_SHA256
    assert first.bundle_identity_sha256 != second.bundle_identity_sha256
    assert first.bundle_id != second.bundle_id

    publish(first, root)
    publish(second, root)
    before = snapshot(root)

    # Bundle A's confirmation cannot authorize loading bundle B.
    substituted = approve(second, root, confirm_bundle=first.bundle_identity_sha256)
    assert substituted.status == "approval_blocked"
    assert substituted.loaded_bundle_id == second.bundle_id
    assert_no_approval(substituted)

    # Each bundle still approves under its own exact confirmation.
    for bundle in (first, second):
        result = approve(bundle, root)
        assert result.status == "approval_contract_constructed"
        assert result.loaded_bundle_id == bundle.bundle_id
        assert result.computed_bundle_identity_sha256 == bundle.bundle_identity_sha256
        # The attestation is scoped to the subject only, never to the source bundle.
        assert result.approval.scope == APPROVAL_SCOPE_EXACT_SUBJECT_ONLY
        assert result.approval.subject_sha256 == FIXTURE_A_SUBJECT_SHA256
        assert "bundle" not in result.approval.model_dump(mode="json")

    assert snapshot(root) == before


def test_reviewer_provenance_never_becomes_approval_identity(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_same_subject()
    publish(bundle, root)
    result = approve(bundle, root)
    assert result.status == "approval_contract_constructed"
    assert "operator-z" in stored_file(bundle, SUPPLEMENTAL_CONTEXT_FILENAME).content_utf8
    assert result.approval.approved_by == APPROVED_BY


# --------------------------------------------------------------------------
# Binding failure
# --------------------------------------------------------------------------


def test_a_binding_mismatch_after_construction_fails_closed(published_a, monkeypatch):
    root, bundle = published_a
    real = workflow.verify_approval_binding

    def mismatched(contract):
        broken = contract.model_copy(
            update={"approval": contract.approval.model_copy(update={"subject_sha256": NOT_A_HASH})}
        )
        return real(broken)

    monkeypatch.setattr(workflow, "verify_approval_binding", mismatched)
    before = snapshot(root)
    result = approve(bundle, root)

    assert result.status == "approval_binding_failed"
    assert result.binding_validation is not None
    assert result.binding_validation.approval_binding_valid is False
    assert_no_approval(result)
    assert snapshot(root) == before


def test_the_maintained_pr309_binding_verifier_is_used(published_a, monkeypatch):
    root, bundle = published_a
    calls: list[ApprovedChangeContract] = []
    real = workflow.verify_approval_binding

    def recorded(contract):
        calls.append(contract)
        return real(contract)

    monkeypatch.setattr(workflow, "verify_approval_binding", recorded)
    result = approve(bundle, root)
    assert result.status == "approval_contract_constructed"
    assert len(calls) == 1
    assert calls[0].approval.subject_sha256 == FIXTURE_A_SUBJECT_SHA256


# --------------------------------------------------------------------------
# Capability, receipt, preflight, and execution separation
# --------------------------------------------------------------------------


def test_successful_approval_never_evaluates_capability_support(published_a, monkeypatch):
    root, bundle = published_a

    def boom(*args, **kwargs):
        raise AssertionError("a capability-support path was reached")

    monkeypatch.setattr(
        "shellforgeai.core.approved_change_contract.validate_approved_change_contract", boom
    )
    result = approve(bundle, root)
    assert result.status == "approval_contract_constructed"
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert result.preflight_evaluated is False
    assert result.receipt_created is False
    assert result.receipt_linked is False
    assert result.execution_allowed is False
    assert result.execution_available is False


def test_no_capability_registry_or_pr313_symbol_is_reachable():
    for name in (
        "validate_approved_change_contract",
        "supported_capability_ids",
        "capability_registry",
        "CAPABILITY_REGISTRY",
        "bind_capability",
        "resolve_capability_support",
        "windows_runtime_reconcile",
        "preflight",
        "create_receipt",
        "link_receipt",
        "execute",
    ):
        assert not hasattr(workflow, name), name


# --------------------------------------------------------------------------
# No filesystem mutation
# --------------------------------------------------------------------------


def install_write_guards(monkeypatch):
    """Fail loudly if any write-capable filesystem primitive is reached.

    This is a helper rather than a fixture on purpose: the persisted fixture
    must be published *before* the guards are installed.
    """

    def raiser(label):
        def boom(*args, **kwargs):
            raise AssertionError(f"{label} was reached during a read-only approval binding")

        return boom

    for name in ("mkdir", "makedirs", "rename", "replace", "rmdir", "unlink", "remove", "truncate"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, raiser(f"os.{name}"))
    monkeypatch.setattr(os, "write", raiser("os.write"))
    monkeypatch.setattr(Path, "mkdir", raiser("Path.mkdir"))
    monkeypatch.setattr(Path, "write_bytes", raiser("Path.write_bytes"))
    monkeypatch.setattr(Path, "write_text", raiser("Path.write_text"))
    monkeypatch.setattr(Path, "rename", raiser("Path.rename"))
    monkeypatch.setattr(Path, "replace", raiser("Path.replace"))
    monkeypatch.setattr(Path, "unlink", raiser("Path.unlink"))
    monkeypatch.setattr(tempfile, "mkdtemp", raiser("tempfile.mkdtemp"))
    monkeypatch.setattr(tempfile, "mkstemp", raiser("tempfile.mkstemp"))
    monkeypatch.setattr(tempfile, "TemporaryDirectory", raiser("tempfile.TemporaryDirectory"))

    real_open = os.open

    def guarded_open(path, flags, *args, **kwargs):
        if flags & (os.O_CREAT | os.O_WRONLY | os.O_RDWR | getattr(os, "O_APPEND", 0)):
            raise AssertionError("a write-capable os.open was reached")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded_open)
    return True


def test_approval_binding_works_through_read_only_loading_only(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    # The fixture is published before the write guards are installed.
    publish(bundle, root)
    before = snapshot(root)

    install_write_guards(monkeypatch)
    result = approve(bundle, root)

    assert result.status == "approval_contract_constructed"
    assert result.artifact_write_performed is False
    assert result.persistence_performed is False
    assert snapshot(root) == before


@pytest.mark.parametrize("published_first", [True, False])
def test_no_persisted_byte_or_mtime_changes(tmp_path, published_first):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    if published_first:
        publish(bundle, root)
    else:
        write_bundle_directory(root, bundle)
    before = snapshot(root)
    for _ in range(3):
        approve(bundle, root)
        approve(bundle, root, confirm_subject=NOT_A_HASH)
    assert snapshot(root) == before


# --------------------------------------------------------------------------
# No hidden time, identity, randomness, authorization, or network lookup
# --------------------------------------------------------------------------


class _GuardedEnvironment(dict):
    def __getitem__(self, key):
        raise AssertionError("an environment variable was read")

    def get(self, *args, **kwargs):
        raise AssertionError("an environment variable was read")


def install_ambient_guards(monkeypatch):
    """Fail loudly on any clock, identity, randomness, or network lookup."""

    def raiser(label):
        def boom(*args, **kwargs):
            raise AssertionError(f"{label} was reached")

        return boom

    monkeypatch.setattr(time, "time", raiser("time.time"))
    monkeypatch.setattr(time, "time_ns", raiser("time.time_ns"))
    monkeypatch.setattr(time, "monotonic", raiser("time.monotonic"))
    monkeypatch.setattr(random, "random", raiser("random.random"))
    monkeypatch.setattr(random, "randint", raiser("random.randint"))
    monkeypatch.setattr(uuid, "uuid4", raiser("uuid.uuid4"))
    monkeypatch.setattr(uuid, "uuid1", raiser("uuid.uuid1"))
    monkeypatch.setattr(socket, "socket", raiser("socket.socket"))
    monkeypatch.setattr(socket, "gethostname", raiser("socket.gethostname"))
    monkeypatch.setattr(os, "getenv", raiser("os.getenv"))
    monkeypatch.setattr(os, "environ", _GuardedEnvironment())
    if hasattr(os, "getlogin"):
        monkeypatch.setattr(os, "getlogin", raiser("os.getlogin"))
    return True


def test_successful_construction_uses_only_explicit_inputs(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish(bundle, root)

    install_ambient_guards(monkeypatch)
    result = approve(bundle, root)

    assert result.status == "approval_contract_constructed"
    assert result.approval.approved_by == APPROVED_BY
    assert result.approval.approved_at == APPROVED_AT
    assert result.approval.reason == REASON


def test_the_module_never_binds_a_clock_or_a_path_constructor_at_runtime():
    assert not hasattr(workflow, "datetime")
    assert not hasattr(workflow, "Path")
    assert not hasattr(workflow, "time")
    assert not hasattr(workflow, "random")
    assert not hasattr(workflow, "secrets")
    assert not hasattr(workflow, "uuid")
    assert not hasattr(workflow, "os")


# --------------------------------------------------------------------------
# Legacy approval separation
# --------------------------------------------------------------------------


def test_no_legacy_proposal_type_is_named_or_imported():
    tree = module_tree_without_docstrings()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.module != "shellforgeai.core.approvals"
            assert "Proposal" not in {alias.name for alias in node.names}
        if isinstance(node, ast.Name):
            assert node.id != "Proposal"
        if isinstance(node, ast.Attribute):
            assert node.attr != "Proposal"


def test_no_legacy_approval_symbol_or_queue_path_appears():
    source = module_code_without_strings()
    for token in (
        "Proposal",
        "core.approvals",
        "approvals",
        "proposals",
        "approve_proposal",
        "set_status",
        "fingerprint",
    ):
        assert token not in source, token


def test_signatures_never_take_or_return_legacy_approval_types():
    for _, obj in inspect.getmembers(workflow, inspect.isfunction):
        signature = inspect.signature(obj)
        assert all(param.annotation is not Proposal for param in signature.parameters.values())
        assert "Proposal" not in str(signature)


def test_approval_binding_creates_no_legacy_queue_directory(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish(bundle, root)
    before = snapshot(root)
    result = approve(bundle, root)
    assert result.status == "approval_contract_constructed"
    assert snapshot(root) == before
    for name in ("proposals", "approvals", "approved", "queue"):
        assert not (root / name).exists()


# --------------------------------------------------------------------------
# Structured failures and immutability
# --------------------------------------------------------------------------


def test_every_public_object_is_frozen(published_a):
    root, bundle = published_a
    result = approve(bundle, root)
    for model, field, value in (
        (result, "status", "approval_blocked"),
        (result.approval, "approved_by", "someone-else"),
        (result.contract, "approval", result.approval),
        (result.binding_validation, "approval_binding_valid", False),
    ):
        with pytest.raises(ValidationError):
            setattr(model, field, value)


def test_result_collections_are_immutable_tuples(published_a):
    root, bundle = published_a
    result = approve(bundle, root)
    assert isinstance(result.errors, tuple)
    assert isinstance(result.warnings, tuple)
    with pytest.raises(TypeError):
        result.warnings[0] = "rewritten"


def test_failure_errors_are_sorted_and_deduplicated(published_a):
    root, bundle = published_a
    result = approve(
        bundle,
        root,
        decision="yes",
        confirm_bundle="nope",
        confirm_subject="nope",
        approved_by="",
        reason="",
        approved_at=NAIVE_APPROVED_AT,
        bundle_id="latest",
    )
    assert result.status == "invalid_approval_input"
    assert list(result.errors) == sorted(set(result.errors))
    assert len(result.errors) == len(set(result.errors))
    assert_inert(result)


def test_no_failure_leaks_a_traceback_or_a_host_path(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    write_bundle_directory(root, bundle, mutate=lambda p: {MANIFEST_FILENAME: p[MANIFEST_FILENAME]})
    outcomes = [
        approve(bundle, root),
        approve(bundle, root, decision="approved"),
        approve(bundle, tmp_path / "absent"),
    ]
    for result in outcomes:
        payload = result.model_dump(mode="json")
        payload.pop("approval", None)
        payload.pop("contract", None)
        payload.pop("binding_validation", None)
        rendered = json.dumps(payload)
        assert "Traceback" not in rendered
        assert str(tmp_path) not in rendered
        assert_no_approval(result)


def test_a_result_carries_at_most_one_approval_and_one_contract(published_a):
    root, bundle = published_a
    result = approve(bundle, root)
    assert isinstance(result.approval, ApprovalAttestation)
    assert isinstance(result.contract, ApprovedChangeContract)
    assert result.contract.approval == result.approval
    assert len([result.approval]) == 1


# --------------------------------------------------------------------------
# Cross-platform deterministic acceptance
# --------------------------------------------------------------------------


def test_fixed_fixture_approval_is_deterministic_on_every_platform(published_a):
    root, bundle = published_a
    result = approve(bundle, root)

    assert result.computed_bundle_identity_sha256 == FIXTURE_A_BUNDLE_IDENTITY_SHA256
    assert result.loaded_bundle_id == f"{BUNDLE_ID_PREFIX}{FIXTURE_A_BUNDLE_IDENTITY_SHA256}"
    assert result.computed_subject_sha256 == FIXTURE_A_SUBJECT_SHA256
    assert result.approval.subject_sha256 == FIXTURE_A_SUBJECT_SHA256
    assert result.approval.scope == "exact_subject_only"
    assert result.approval.approved_by == APPROVED_BY
    assert result.approval.approved_at == APPROVED_AT
    assert result.approval.approved_at.utcoffset() == timedelta(0)
    assert result.approval.reason == REASON
    assert compute_subject_sha256(result.contract.subject) == FIXTURE_A_SUBJECT_SHA256
    assert result.binding_validation.status == "contract_valid"
    assert result.read_only is True
    assert result.filesystem_accessed is True
    assert result.approval_created is True
    assert result.contract_created is True


def test_repeated_invocations_are_identical(published_a):
    root, bundle = published_a
    first = approve(bundle, root)
    second = approve(bundle, root)
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


# --------------------------------------------------------------------------
# Static source guards
# --------------------------------------------------------------------------


def module_tree_without_docstrings():
    tree = ast.parse(Path(workflow.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef):
            continue
        first = node.body[0] if node.body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            node.body.pop(0)
            if not node.body:
                node.body.append(ast.Pass())
    return tree


def module_code_without_strings():
    tree = module_tree_without_docstrings()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            node.value = ""
    return ast.unparse(tree)


def test_static_no_filesystem_execution_network_or_model_surface():
    source = module_code_without_strings()
    for token in (
        "open(",
        "os.",
        "mkdir",
        "makedirs",
        "write_bytes",
        "write_text",
        "tempfile",
        "mkdtemp",
        "shutil",
        "rmtree",
        "unlink",
        "remove(",
        "rename",
        "replace(",
        "subprocess",
        "system(",
        "popen",
        "socket",
        "docker",
        "compose",
        "powershell",
        "winrm",
        "qga",
        "requests",
        "httpx",
        "urllib",
        "provider",
        "environ",
        "getenv",
        "getlogin",
        "getuser",
        "gethostname",
        "random",
        "secrets",
        "uuid",
        "now(",
        "utcnow",
        "today",
        "time(",
        "monotonic",
        "glob",
        "walk",
    ):
        assert token not in source, token


def test_static_no_capability_receipt_preflight_or_cli_surface():
    source = module_code_without_strings()
    for token in (
        "validate_approved_change_contract",
        "supported_capability",
        "capability_registry",
        "CAPABILITY_REGISTRY",
        "bind_capability",
        "evaluate_capability",
        "run_preflight",
        "evaluate_preflight",
        "create_receipt",
        "link_receipt",
        "recipe",
        "RECIPE",
        "typer",
        "app.command",
        "add_typer",
        "windows_runtime_reconcile",
        "ask_routing",
        "intent",
        "publish_approved_change_artifact_bundle",
    ):
        assert token not in source, token


def test_static_import_set_is_exactly_the_maintained_dependencies():
    tree = ast.parse(Path(workflow.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    assert imported == {
        "__future__",
        "datetime",
        "hmac",
        "json",
        "pathlib",
        "pydantic",
        "shellforgeai.core.approved_change_artifact_bundle",
        "shellforgeai.core.approved_change_artifact_persistence",
        "shellforgeai.core.approved_change_contract",
        "typing",
    }


def test_static_datetime_and_pathlib_are_annotation_only():
    tree = ast.parse(Path(workflow.__file__).read_text(encoding="utf-8"))
    runtime_modules = set()
    guarded_modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and ast.unparse(node.test) == "TYPE_CHECKING":
            for inner in ast.walk(node):
                if isinstance(inner, ast.ImportFrom) and inner.module:
                    guarded_modules.add(inner.module)
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            runtime_modules.add(node.module)
    assert {"datetime", "pathlib"} <= guarded_modules
    assert "datetime" not in runtime_modules
    assert "pathlib" not in runtime_modules


def test_public_surface_is_exactly_one_operation():
    public = sorted(
        name
        for name, obj in inspect.getmembers(workflow, inspect.isfunction)
        if not name.startswith("_") and obj.__module__ == workflow.__name__
    )
    assert public == ["construct_approved_change_contract_from_persisted_bundle"]


def test_module_exposes_no_cli_persistence_or_registry_surface():
    for name in (
        "app",
        "cli",
        "main",
        "register",
        "REGISTRY",
        "persist_approval",
        "save_approval",
        "write_approval",
        "load_approval",
        "delete_approval",
        "publish_approval",
        "approval_artifact",
    ):
        assert not hasattr(workflow, name), name


def test_module_is_not_imported_by_cli_approvals_recipes_or_execution():
    # PR319's pure approval-artifact module is the one governed consumer of this
    # result type; it is named here explicitly so no CLI, approvals, recipe, or
    # execution module can quietly reach the approval-binding operation instead.
    permitted = {
        "approved_change_approval_workflow.py",
        "approved_change_approval_artifact.py",
    }
    roots = [Path("src/shellforgeai/cli"), Path("src/shellforgeai/core")]
    offenders = []
    for base in roots:
        for path in base.rglob("*.py"):
            if path.name in permitted:
                continue
            if "approved_change_approval_workflow" in path.read_text(encoding="utf-8"):
                offenders.append(str(path))
    assert offenders == []


def test_the_pr319_consumer_only_consumes_the_maintained_result():
    # PR319 consumes one fully successful PR318 result. It never reimplements
    # the approval-binding operation and never creates an approval of its own.
    source = Path("src/shellforgeai/core/approved_change_approval_artifact.py").read_text(
        encoding="utf-8"
    )
    assert "ApprovedChangeApprovalWorkflowResult" in source
    assert "construct_approved_change_contract_from_persisted_bundle" not in source
    assert "ApprovalAttestation(" not in source
    assert "ApprovedChangeContract(" not in source


def test_fixed_identifiers_are_taken_from_the_maintained_modules():
    assert workflow.BUNDLE_ID_PREFIX is BUNDLE_ID_PREFIX
    assert workflow.APPROVED_CHANGE_SUBJECT_FILENAME is APPROVED_CHANGE_SUBJECT_FILENAME
    assert workflow.MANIFEST_FILENAME is MANIFEST_FILENAME
    assert workflow.APPROVAL_SCOPE_EXACT_SUBJECT_ONLY is APPROVAL_SCOPE_EXACT_SUBJECT_ONLY
    source = ast.unparse(module_tree_without_docstrings())
    assert "'acb_'" not in source
    assert "'exact_subject_only'" not in source
    assert f"'{APPROVED_CHANGE_SUBJECT_FILENAME}'" not in source


# --------------------------------------------------------------------------
# Documentation and validation-matrix contract
# --------------------------------------------------------------------------


def test_approval_workflow_documentation_records_the_fixed_contract():
    document = Path("docs/APPROVED_CHANGE_APPROVAL_WORKFLOW.md").read_text(encoding="utf-8")
    for phrase in (
        "construct_approved_change_contract_from_persisted_bundle",
        "approval_decision",
        "confirm_bundle_identity_sha256",
        "confirm_subject_sha256",
        "approval_contract_constructed",
        "approval_binding_failed",
        "persisted_bundle_not_available",
        "exact_subject_only",
        "self-asserted",
        "no approval persistence",
        "no execution eligibility",
        "PR319",
    ):
        assert phrase in document, phrase


def test_validation_matrix_maps_the_approval_workflow_module_to_this_suite():
    matrix = json.loads(Path("scripts/validation_matrix.json").read_text(encoding="utf-8"))
    rules = [
        rule
        for rule in matrix["rules"]
        if rule["pattern"].endswith("approved_change_approval_workflow.py")
    ]
    assert len(rules) == 1
    assert "tests/test_pr318_approved_change_approval_workflow.py" in rules[0]["tests"]
    document = Path("docs/VALIDATION_MATRIX.md").read_text(encoding="utf-8")
    assert "approved_change_approval_workflow.py" in document
    assert "test_pr318_approved_change_approval_workflow" in document


def test_roadmap_and_safety_record_the_pr318_boundary():
    roadmap = Path("docs/roadmap.md").read_text(encoding="utf-8")
    assert "PR318" in roadmap
    assert "APPROVED_CHANGE_APPROVAL_WORKFLOW.md" in roadmap
    safety = Path("docs/safety.md").read_text(encoding="utf-8")
    assert "PR318" in safety
    architecture = Path("docs/architecture.md").read_text(encoding="utf-8")
    assert "approved_change_approval_workflow.py" in architecture
