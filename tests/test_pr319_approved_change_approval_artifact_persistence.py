"""Focused PR319 tests: approved-change approval artifact persistence.

PR309 owns the subject schema, the subject identity, the attestation, the
contract, and approval-binding verification. PR316 owns the four-file reviewed
bundle, its canonical bytes, and the bundle identity. PR317 owns the governed
bundle publisher and the exact-ID read-only bundle loader. PR318 owns the one
read-only approval-binding operation and the in-memory approval and contract.

These tests prove PR319 adds exactly two things on top of those maintained
contracts: one canonical, immutable, checksum-protected approval artifact built
from one fully successful PR318 result, and one governed atomic no-replace
filesystem boundary for it beneath the fixed
``<data_dir>/approved_change_approvals/`` subtree, plus an exact-ID read-only
loader that revalidates the artifact, its PR309 approval binding, and its exact
PR317 source bundle.

PR319 persists approval evidence only. It authenticates nobody, creates no new
approval, permits no overwrite, adds no revocation or mutable approval state,
evaluates no capability, runs no preflight, creates or links no receipt, and
grants no execution eligibility.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
import random
import socket
import stat as stat_module
import subprocess
import sys
import tempfile
import time
import types
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

# The PR316 focused suite owns the maintained reviewed-context fixtures. They
# are reused verbatim so PR319 never invents its own bundle or subject schema.
from test_pr316_approved_change_artifact_bundle import (  # noqa: E402
    FIXTURE_A_BUNDLE_IDENTITY_SHA256,
    FIXTURE_A_SUBJECT_SHA256,
    build,
    context_alt_provenance,
    context_b,
)

from shellforgeai.core import approved_change_approval_artifact as artifact_module
from shellforgeai.core import approved_change_approval_persistence as persistence
from shellforgeai.core.approvals import Proposal
from shellforgeai.core.approved_change_approval_artifact import (
    APPROVAL_ARTIFACT_ID_PREFIX,
    APPROVAL_ARTIFACT_PAYLOAD_FIELDS,
    APPROVAL_ARTIFACT_SCHEMA_VERSION,
    APPROVAL_ARTIFACT_TYPE,
    APPROVED_CHANGE_APPROVAL_FILENAME,
    BUILD_STATUSES,
    PERMANENT_APPROVAL_ARTIFACT_WARNINGS,
    REQUIRED_APPROVAL_WORKFLOW_STATUS,
    VALIDATION_STATUSES,
    ApprovedChangeApprovalArtifact,
    ApprovedChangeApprovalArtifactBuildResult,
    build_approved_change_approval_artifact,
    canonical_approval_artifact_json,
    canonical_approval_artifact_payload,
    compute_approval_artifact_identity_sha256,
    derive_approval_artifact_id,
    validate_approved_change_approval_artifact,
)
from shellforgeai.core.approved_change_approval_persistence import (
    APPROVED_CHANGE_APPROVALS_DIRNAME,
    LOAD_STATUSES,
    PUBLICATION_STATUSES,
    TEMPORARY_DIRECTORY_NAME_LENGTH,
    TEMPORARY_DIRECTORY_PREFIX,
    AtomicNoReplaceOutcome,
    load_persisted_approved_change_approval_artifact,
    publish_approved_change_approval_artifact,
)
from shellforgeai.core.approved_change_approval_workflow import (
    APPROVAL_WORKFLOW_STATUSES,
    construct_approved_change_contract_from_persisted_bundle,
)
from shellforgeai.core.approved_change_artifact_bundle import (
    APPROVED_CHANGE_SUBJECT_FILENAME,
    BUNDLE_ID_PREFIX,
    derive_bundle_id,
)
from shellforgeai.core.approved_change_artifact_persistence import (
    APPROVED_CHANGE_ARTIFACTS_DIRNAME,
    publish_approved_change_artifact_bundle,
)
from shellforgeai.core.approved_change_contract import (
    APPROVAL_SCOPE_EXACT_SUBJECT_ONLY,
    canonical_subject_json,
    compute_subject_sha256,
)

NOT_A_HASH = "0" * 64
WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="Windows-only native behaviour")
LINUX_ONLY = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux-only native behaviour"
)

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
REASON = "reviewed the exact persisted reviewed-change subject"

# --------------------------------------------------------------------------
# Committed fixed-fixture reference values
#
# These are the exact expected Linux and Windows canonical bytes for the fixed
# fixture-A approval. They are recorded here so any canonicalization, ordering,
# encoding, schema, or payload drift fails loudly instead of silently changing
# persisted approval identity.
# --------------------------------------------------------------------------

FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256 = (
    "c907fe026b378ae2576f4ee8a384ff1f11e24b9cda59c988722240c2abde34d8"
)
FIXTURE_A_APPROVAL_ARTIFACT_ID = (
    f"{APPROVAL_ARTIFACT_ID_PREFIX}{FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256}"
)
FIXTURE_A_APPROVAL_ARTIFACT_BYTE_LENGTH = 2652


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def data_dir(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    root.mkdir(parents=True)
    return root


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


def publish_bundle(bundle, root: Path):
    result = publish_approved_change_artifact_bundle(
        bundle,
        data_dir=root,
        confirm_bundle_identity_sha256=bundle.bundle_identity_sha256,
    )
    assert result.status == "bundle_published"
    return result


def subject_sha256_of(bundle) -> str:
    return next(
        item.sha256
        for item in bundle.files
        if item.relative_path == APPROVED_CHANGE_SUBJECT_FILENAME
    )


def approve(bundle, root: Path, *, approved_by=APPROVED_BY, approved_at=APPROVED_AT, reason=REASON):
    """Run the maintained PR318 operation with fixed explicit inputs."""
    result = construct_approved_change_contract_from_persisted_bundle(
        bundle.bundle_id,
        data_dir=root,
        approval_decision="approve",
        confirm_bundle_identity_sha256=bundle.bundle_identity_sha256,
        confirm_subject_sha256=subject_sha256_of(bundle),
        approved_by=approved_by,
        approved_at=approved_at,
        reason=reason,
    )
    assert result.status == REQUIRED_APPROVAL_WORKFLOW_STATUS
    return result


def workflow_for(bundle, root: Path, **kwargs):
    publish_bundle(bundle, root)
    return approve(bundle, root, **kwargs)


def artifact_for(bundle, root: Path, **kwargs):
    built = build_approved_change_approval_artifact(workflow_for(bundle, root, **kwargs))
    assert built.status == "approval_artifact_constructed", built.errors
    return built.artifact


def publication_root(root: Path) -> Path:
    return root / APPROVED_CHANGE_APPROVALS_DIRNAME


def artifact_directory(root: Path, artifact) -> Path:
    return publication_root(root) / artifact.approval_artifact_id


def artifact_file(root: Path, artifact) -> Path:
    return artifact_directory(root, artifact) / APPROVED_CHANGE_APPROVAL_FILENAME


_EXACT = object()


def publish_artifact(artifact, root: Path, confirmation=_EXACT):
    return publish_approved_change_approval_artifact(
        artifact,
        data_dir=root,
        confirm_approval_artifact_identity_sha256=(
            artifact.approval_artifact_identity_sha256 if confirmation is _EXACT else confirmation
        ),
    )


def write_artifact_directory(root: Path, artifact, *, mutate=None, name=None) -> Path:
    """Materialise an approval-artifact directory directly, bypassing the publisher."""
    directory = publication_root(root) / (artifact.approval_artifact_id if name is None else name)
    directory.mkdir(parents=True)
    payload = {APPROVED_CHANGE_APPROVAL_FILENAME: artifact.canonical_content_utf8.encode("utf-8")}
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


def pending_entries(root: Path) -> list[Path]:
    base = publication_root(root)
    if not base.exists():
        return []
    return [item for item in base.iterdir() if item.name.startswith(TEMPORARY_DIRECTORY_PREFIX)]


def inject_failure(monkeypatch, target: str, exc: Exception | None = None):
    """Fail deterministically at one named internal publication stage."""
    failure = exc or OSError("injected failure")

    def failpoint(name: str) -> None:
        if name == target:
            raise failure

    monkeypatch.setattr(persistence, "_failpoint", failpoint)


def run_at(monkeypatch, target: str, action):
    """Run ``action`` exactly when one named internal stage is reached."""
    seen: list[str] = []

    def failpoint(name: str) -> None:
        if name == target and target not in seen:
            seen.append(target)
            action()

    monkeypatch.setattr(persistence, "_failpoint", failpoint)
    return seen


class FsRecorder:
    """Record every filesystem primitive this module can reach."""

    NAMES = (
        "mkdir",
        "makedirs",
        "open",
        "scandir",
        "listdir",
        "lstat",
        "stat",
        "rmdir",
        "unlink",
        "remove",
        "rename",
        "replace",
        "fsync",
        "write",
        "read",
    )
    WRITE_NAMES = frozenset({"mkdir", "makedirs", "rmdir", "unlink", "remove", "rename", "replace"})

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def touched(self, root: Path) -> list[tuple[str, str]]:
        marker = str(root)
        return [entry for entry in self.calls if marker in entry[1]]

    def write_paths(self) -> list[str]:
        return [path for name, path in self.calls if name in self.WRITE_NAMES]

    def creations(self, root: Path) -> list[tuple[str, str]]:
        marker = str(root)
        return [
            entry
            for entry in self.calls
            if marker in entry[1] and entry[0] in {"mkdir", "makedirs", "rename", "replace"}
        ]


@pytest.fixture
def fs_recorder(monkeypatch):
    recorder = FsRecorder()

    def wrap(name):
        original = getattr(os, name)

        def recorded(*args, **kwargs):
            first = args[0] if args else ""
            recorder.calls.append((name, str(first)))
            return original(*args, **kwargs)

        return recorded

    for name in FsRecorder.NAMES:
        if hasattr(os, name):
            monkeypatch.setattr(os, name, wrap(name))
    return recorder


@pytest.fixture
def no_filesystem_mutation(monkeypatch):
    """Return an installer that fails loudly on any filesystem-creating primitive.

    It is installed explicitly inside the test, after the fixtures it needs have
    legitimately published their PR317 source bundle, so only the operation
    under test is guarded.
    """

    def install():
        def raiser(name):
            def boom(*args, **kwargs):
                raise AssertionError(f"os.{name} was reached during a structural rejection")

            return boom

        for name in ("mkdir", "makedirs", "rename", "replace", "rmdir", "unlink", "remove"):
            if hasattr(os, name):
                monkeypatch.setattr(os, name, raiser(name))

        real_open = os.open

        def guarded_open(path, flags, *args, **kwargs):
            if flags & (os.O_CREAT | os.O_WRONLY | os.O_RDWR):
                raise AssertionError("a write-capable os.open was reached")
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", guarded_open)

    return install


@pytest.fixture
def no_replace_primitives(monkeypatch):
    """Prove no replace-capable primitive is ever reachable during publication."""

    def boom(*args, **kwargs):
        raise AssertionError("a replace-capable primitive was used")

    monkeypatch.setattr(os, "replace", boom)
    monkeypatch.setattr(os, "rename", boom)
    monkeypatch.setattr(Path, "replace", boom)
    monkeypatch.setattr(Path, "rename", boom)
    return True


@pytest.fixture
def published_a(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    artifact = artifact_for(bundle, root)
    result = publish_artifact(artifact, root)
    assert result.status == "approval_artifact_published"
    return root, bundle, artifact


def assert_never_expands(result) -> None:
    """The fields PR319 may never claim, on success or on failure."""
    assert result.approval_created is False
    assert result.contract_created is False
    assert result.overwrite_performed is False
    assert result.source_bundle_mutation_performed is False
    assert result.host_configuration_mutation_performed is False
    assert result.authorization_evaluated is False
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert result.preflight_evaluated is False
    assert result.receipt_created is False
    assert result.receipt_linked is False
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"
    assert result.warnings == PERMANENT_APPROVAL_ARTIFACT_WARNINGS
    assert "Traceback" not in " ".join(result.errors)
    assert list(result.errors) == sorted(set(result.errors))


def assert_inert_build(result) -> None:
    assert result.read_only is True
    assert result.mutation_performed is False
    assert result.filesystem_accessed is False
    assert result.artifact_write_performed is False
    assert result.approval_persisted is False
    assert result.contract_persisted is False
    assert result.approval_created is False
    assert result.contract_created is False
    assert result.authorization_evaluated is False
    assert result.capability_support_evaluated is False
    assert result.preflight_evaluated is False
    assert result.receipt_created is False
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"
    assert result.warnings == PERMANENT_APPROVAL_ARTIFACT_WARNINGS


def assert_no_artifact(result) -> None:
    assert isinstance(result, ApprovedChangeApprovalArtifactBuildResult)
    assert result.status in BUILD_STATUSES
    assert result.status != "approval_artifact_constructed"
    assert result.build_succeeded is False
    assert result.artifact is None
    assert result.artifact_validation is None
    assert result.approval_artifact_id == ""
    assert result.approval_artifact_identity_sha256 == ""
    assert result.byte_length == 0
    assert result.errors
    assert list(result.errors) == sorted(set(result.errors))
    assert "Traceback" not in " ".join(result.errors)
    assert_inert_build(result)


# --------------------------------------------------------------------------
# Deterministic artifact construction
# --------------------------------------------------------------------------


def test_the_fixed_fixture_artifact_is_exactly_the_committed_bytes(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    built = build_approved_change_approval_artifact(workflow_for(bundle, root))

    assert built.status == "approval_artifact_constructed"
    assert built.build_succeeded is True
    artifact = built.artifact
    assert artifact.byte_length == FIXTURE_A_APPROVAL_ARTIFACT_BYTE_LENGTH
    assert artifact.approval_artifact_identity_sha256 == FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256
    assert artifact.approval_artifact_id == FIXTURE_A_APPROVAL_ARTIFACT_ID
    assert artifact.source_bundle_identity_sha256 == FIXTURE_A_BUNDLE_IDENTITY_SHA256
    assert artifact.source_bundle_id == f"{BUNDLE_ID_PREFIX}{FIXTURE_A_BUNDLE_IDENTITY_SHA256}"
    assert artifact.subject_sha256 == FIXTURE_A_SUBJECT_SHA256
    assert built.byte_length == artifact.byte_length
    assert built.approval_artifact_id == artifact.approval_artifact_id
    assert_inert_build(built)
    assert_never_expands(built)


def test_the_canonical_payload_shape_is_exact(published_a):
    _, _, artifact = published_a
    payload = json.loads(artifact.canonical_content_utf8)
    assert sorted(payload) == sorted(APPROVAL_ARTIFACT_PAYLOAD_FIELDS)
    assert payload["schema_version"] == APPROVAL_ARTIFACT_SCHEMA_VERSION
    assert payload["artifact_type"] == APPROVAL_ARTIFACT_TYPE
    assert sorted(payload["contract"]) == ["approval", "schema_version", "subject"]
    assert payload["contract"]["approval"]["scope"] == APPROVAL_SCOPE_EXACT_SUBJECT_ONLY
    assert payload["contract"]["approval"]["approved_by"] == APPROVED_BY
    assert payload["contract"]["approval"]["approved_at"] == "2026-07-27T09:00:00Z"
    assert payload["contract"]["approval"]["reason"] == REASON
    assert payload["contract"]["approval"]["subject_sha256"] == FIXTURE_A_SUBJECT_SHA256
    # The derived identity fields are never inside the payload.
    for excluded in artifact_module.APPROVAL_ARTIFACT_IDENTITY_EXCLUDED_FIELDS:
        assert excluded not in payload
    for forbidden in (
        "status",
        "revoked",
        "revocation",
        "expires",
        "expiration",
        "superseded",
        "latest",
        "current",
        "hostname",
        "environment",
        "receipt",
        "preflight",
        "reviewed_by",
        "capability_supported",
        "capability_support_evaluated",
        "authorization",
        "execution_allowed",
    ):
        assert forbidden not in payload
        assert forbidden not in payload["contract"]
        assert forbidden not in payload["contract"]["approval"]
    # `capability_id` is a maintained PR309 subject field; capability *support*
    # is never recorded anywhere in the artifact.
    assert "capability_id" in payload["contract"]["subject"]
    for forbidden in ("capability_supported", "capability_support", "supported_capability"):
        assert forbidden not in artifact.canonical_content_utf8


def test_the_canonical_filename_and_bytes_are_exact(published_a):
    root, _, artifact = published_a
    assert APPROVED_CHANGE_APPROVAL_FILENAME == "approved-change-approval.json"
    raw = artifact_file(root, artifact).read_bytes()
    assert raw == artifact.canonical_content_utf8.encode("utf-8")
    assert len(raw) == artifact.byte_length
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert not raw.endswith(b"\n")
    assert b"\r\n" not in raw
    assert b", " not in raw
    assert b'": ' not in raw
    # ensure_ascii=False: reviewed Unicode survives exactly.
    assert "corrección descriptiva acotada" in artifact.canonical_content_utf8


def test_the_artifact_identity_is_the_exact_byte_sha256(published_a):
    _, _, artifact = published_a
    encoded = artifact.canonical_content_utf8.encode("utf-8")
    assert artifact.approval_artifact_identity_sha256 == hashlib.sha256(encoded).hexdigest()
    assert artifact.approval_artifact_id == (
        f"{APPROVAL_ARTIFACT_ID_PREFIX}{artifact.approval_artifact_identity_sha256}"
    )
    assert derive_approval_artifact_id(artifact.approval_artifact_identity_sha256) == (
        artifact.approval_artifact_id
    )
    assert compute_approval_artifact_identity_sha256(artifact) == (
        artifact.approval_artifact_identity_sha256
    )
    assert canonical_approval_artifact_json(artifact) == artifact.canonical_content_utf8


def test_repeated_builds_are_byte_identical(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish_bundle(bundle, root)
    first = build_approved_change_approval_artifact(approve(bundle, root))
    second = build_approved_change_approval_artifact(approve(bundle, root))
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.artifact.canonical_content_utf8 == second.artifact.canonical_content_utf8


def test_equivalent_timezone_offsets_canonicalize_identically(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish_bundle(bundle, root)
    utc = build_approved_change_approval_artifact(approve(bundle, root)).artifact
    offset = build_approved_change_approval_artifact(
        approve(bundle, root, approved_at=ALT_ZONE_APPROVED_AT)
    ).artifact
    assert utc.canonical_content_utf8 == offset.canonical_content_utf8
    assert utc.approval_artifact_identity_sha256 == offset.approval_artifact_identity_sha256
    assert utc.approval_artifact_id == offset.approval_artifact_id


@pytest.mark.parametrize(
    "override",
    [
        {"approved_by": "another-approver"},
        {"approved_at": datetime(2026, 7, 27, 9, 0, 1, tzinfo=timezone.utc)},
        {"reason": "a different stated approval reason"},
    ],
)
def test_changed_approval_metadata_changes_the_artifact_identity(tmp_path, override):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish_bundle(bundle, root)
    baseline = build_approved_change_approval_artifact(approve(bundle, root)).artifact
    changed = build_approved_change_approval_artifact(approve(bundle, root, **override)).artifact
    assert changed.approval_artifact_identity_sha256 != (baseline.approval_artifact_identity_sha256)
    assert changed.approval_artifact_id != baseline.approval_artifact_id
    assert changed.subject_sha256 == baseline.subject_sha256


def test_a_changed_subject_or_source_bundle_changes_the_artifact_identity(tmp_path):
    root = data_dir(tmp_path)
    baseline = artifact_for(bundle_a(), root)
    other_subject = artifact_for(bundle_b(), root)
    other_provenance = artifact_for(bundle_same_subject(), root)

    assert other_subject.subject_sha256 != baseline.subject_sha256
    assert other_subject.approval_artifact_identity_sha256 != (
        baseline.approval_artifact_identity_sha256
    )
    # Same subject values, different reviewed provenance and bundle identity.
    assert other_provenance.subject_sha256 == baseline.subject_sha256
    assert other_provenance.source_bundle_id != baseline.source_bundle_id
    assert other_provenance.approval_artifact_identity_sha256 != (
        baseline.approval_artifact_identity_sha256
    )


def test_the_artifact_identity_is_permanently_distinct(published_a):
    _, bundle, artifact = published_a
    distinct = {
        artifact.approval_artifact_identity_sha256,
        artifact.source_bundle_identity_sha256,
        artifact.subject_sha256,
        *(item.sha256 for item in bundle.files),
    }
    assert len(distinct) == 2 + 1 + len(bundle.files) - 1  # subject file == subject identity
    assert artifact.approval_artifact_identity_sha256 not in {
        artifact.source_bundle_identity_sha256,
        artifact.subject_sha256,
        artifact.contract.approval.subject_sha256,
    }
    assert not artifact.approval_artifact_id.startswith(BUNDLE_ID_PREFIX)
    assert APPROVAL_ARTIFACT_ID_PREFIX != BUNDLE_ID_PREFIX


def test_the_identity_is_never_embedded_inside_the_payload(published_a):
    _, _, artifact = published_a
    assert artifact.approval_artifact_identity_sha256 not in artifact.canonical_content_utf8
    assert artifact.approval_artifact_id not in artifact.canonical_content_utf8
    assert str(artifact.byte_length) not in json.dumps(
        canonical_approval_artifact_payload(artifact)
    )


# --------------------------------------------------------------------------
# Builder refusal
# --------------------------------------------------------------------------


def test_a_failed_workflow_result_is_refused(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish_bundle(bundle, root)
    failed = construct_approved_change_contract_from_persisted_bundle(
        bundle.bundle_id,
        data_dir=root,
        approval_decision="approved",
        confirm_bundle_identity_sha256=bundle.bundle_identity_sha256,
        confirm_subject_sha256=subject_sha256_of(bundle),
        approved_by=APPROVED_BY,
        approved_at=APPROVED_AT,
        reason=REASON,
    )
    assert failed.status == "invalid_approval_input"
    assert_no_artifact(build_approved_change_approval_artifact(failed))


@pytest.mark.parametrize(
    "update",
    [
        {"status": "approval_blocked"},
        {"approval_succeeded": False},
        {"approval": None},
        {"contract": None},
        {"binding_validation": None},
        {"source_bundle_loaded": False},
        {"source_bundle_valid": False},
        {"approval_binding_valid": False},
        {"approval_scope": "any_subject"},
        {"loaded_bundle_id": f"{BUNDLE_ID_PREFIX}{NOT_A_HASH}"},
        {"requested_bundle_id": f"{BUNDLE_ID_PREFIX}{NOT_A_HASH}"},
        {"confirmed_bundle_identity_sha256": NOT_A_HASH},
        {"confirmed_subject_sha256": NOT_A_HASH},
        {"computed_subject_sha256": NOT_A_HASH},
        {"computed_bundle_identity_sha256": NOT_A_HASH},
    ],
)
def test_every_workflow_success_gate_is_required(tmp_path, update):
    root = data_dir(tmp_path)
    result = workflow_for(bundle_a(), root)
    assert_no_artifact(build_approved_change_approval_artifact(result.model_copy(update=update)))


@pytest.mark.parametrize(
    "field",
    [
        "authorization_evaluated",
        "capability_support_evaluated",
        "capability_supported",
        "preflight_evaluated",
        "receipt_created",
        "receipt_linked",
        "execution_allowed",
        "execution_available",
        "approval_persisted",
        "contract_persisted",
    ],
)
def test_a_capability_preflight_receipt_or_execution_claim_is_refused(tmp_path, field):
    root = data_dir(tmp_path)
    result = workflow_for(bundle_a(), root)
    blocked = build_approved_change_approval_artifact(result.model_copy(update={field: True}))
    assert_no_artifact(blocked)
    assert any(field in error for error in blocked.errors)


def test_an_executed_workflow_status_is_refused(tmp_path):
    root = data_dir(tmp_path)
    result = workflow_for(bundle_a(), root)
    blocked = build_approved_change_approval_artifact(
        result.model_copy(update={"execution_status": "executed"})
    )
    assert_no_artifact(blocked)


def test_an_invalid_binding_validation_is_refused(tmp_path):
    root = data_dir(tmp_path)
    result = workflow_for(bundle_a(), root)
    broken = result.binding_validation.model_copy(update={"approval_binding_valid": False})
    assert_no_artifact(
        build_approved_change_approval_artifact(
            result.model_copy(update={"binding_validation": broken})
        )
    )


def test_a_contract_that_is_not_the_approved_subject_is_refused(tmp_path):
    root = data_dir(tmp_path)
    result = workflow_for(bundle_a(), root)
    other = workflow_for(bundle_b(), data_dir(tmp_path / "second"))
    blocked = build_approved_change_approval_artifact(
        result.model_copy(update={"contract": other.contract})
    )
    assert_no_artifact(blocked)


def test_a_contract_whose_approval_is_not_the_result_approval_is_refused(tmp_path):
    root = data_dir(tmp_path)
    result = workflow_for(bundle_a(), root)
    other_approval = result.approval.model_copy(update={"approved_by": "someone-else"})
    swapped = result.contract.model_copy(update={"approval": other_approval})
    blocked = build_approved_change_approval_artifact(
        result.model_copy(update={"contract": swapped})
    )
    assert_no_artifact(blocked)
    assert any("contract approval" in error for error in blocked.errors)


def test_a_non_exact_subject_scope_is_refused(tmp_path):
    root = data_dir(tmp_path)
    result = workflow_for(bundle_a(), root)
    widened = result.approval.model_copy(update={"scope": "any_subject"})
    blocked = build_approved_change_approval_artifact(
        result.model_copy(
            update={
                "approval": widened,
                "contract": result.contract.model_copy(update={"approval": widened}),
            }
        )
    )
    assert_no_artifact(blocked)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"status": "approval_contract_constructed"},
        {"approved_by": "operator", "approved_at": "2026-07-27T09:00:00Z"},
        {"status": "approval_contract_constructed", "unexpected_field": True},
        "approval_contract_constructed",
        None,
        42,
        ["approve"],
    ],
)
def test_an_arbitrary_caller_payload_is_refused(payload):
    assert_no_artifact(build_approved_change_approval_artifact(payload))


def test_the_builder_takes_no_separately_supplied_approval_data():
    signature = inspect.signature(build_approved_change_approval_artifact)
    assert list(signature.parameters) == ["workflow_result"]
    for forbidden in (
        "approval",
        "contract",
        "subject",
        "bundle_id",
        "bundle_identity",
        "subject_sha256",
        "approved_by",
        "output_path",
        "data_dir",
        "confirm",
    ):
        assert forbidden not in signature.parameters


def test_a_mapping_equivalent_of_the_maintained_result_is_accepted(tmp_path):
    root = data_dir(tmp_path)
    result = workflow_for(bundle_a(), root)
    from_model = build_approved_change_approval_artifact(result)
    from_mapping = build_approved_change_approval_artifact(result.model_dump(mode="json"))
    assert from_mapping.status == "approval_artifact_constructed"
    assert (
        from_mapping.artifact.approval_artifact_identity_sha256
        == from_model.artifact.approval_artifact_identity_sha256
    )


# --------------------------------------------------------------------------
# Artifact validation
# --------------------------------------------------------------------------


def test_an_exact_artifact_validates(published_a):
    _, _, artifact = published_a
    validation = validate_approved_change_approval_artifact(artifact)
    assert validation.status == "approval_artifact_valid"
    assert validation.artifact_valid is True
    assert validation.approval_binding_valid is True
    assert validation.approval_scope == APPROVAL_SCOPE_EXACT_SUBJECT_ONLY
    assert validation.computed_subject_sha256 == FIXTURE_A_SUBJECT_SHA256
    assert validation.computed_approval_artifact_id == artifact.approval_artifact_id
    assert validation.computed_byte_length == artifact.byte_length
    assert validation.errors == ()
    assert validation.binding_validation.status == "contract_valid"
    assert_inert_build(validation)
    assert_never_expands(validation)


def test_a_json_round_trip_of_the_artifact_validates(published_a):
    _, _, artifact = published_a
    reparsed = ApprovedChangeApprovalArtifact.model_validate(artifact.model_dump(mode="json"))
    assert reparsed == artifact
    assert (
        validate_approved_change_approval_artifact(artifact.model_dump(mode="json")).status
        == "approval_artifact_valid"
    )


@pytest.mark.parametrize(
    "update",
    [
        {"canonical_content_utf8": "{}"},
        {"byte_length": 1},
        {"approval_artifact_identity_sha256": NOT_A_HASH},
        {"approval_artifact_id": f"{APPROVAL_ARTIFACT_ID_PREFIX}{NOT_A_HASH}"},
        {"source_bundle_id": f"{BUNDLE_ID_PREFIX}{NOT_A_HASH}"},
        {"source_bundle_identity_sha256": NOT_A_HASH},
        {"subject_sha256": NOT_A_HASH},
        {"schema_version": "2"},
        {"artifact_type": "something_else"},
    ],
)
def test_every_tampered_artifact_field_is_rejected(published_a, update):
    _, _, artifact = published_a
    tampered = artifact.model_copy(update=update)
    validation = validate_approved_change_approval_artifact(tampered)
    assert validation.status == "approval_artifact_invalid"
    assert validation.artifact_valid is False
    assert validation.errors
    assert_never_expands(validation)


def test_a_tampered_subject_or_approval_is_rejected(published_a):
    _, _, artifact = published_a
    other_subject = artifact.contract.subject.model_copy(update={"risk": "high"})
    with_subject = artifact.model_copy(
        update={"contract": artifact.contract.model_copy(update={"subject": other_subject})}
    )
    assert validate_approved_change_approval_artifact(with_subject).status == (
        "approval_artifact_invalid"
    )

    other_approval = artifact.contract.approval.model_copy(update={"approved_by": "impostor"})
    with_approval = artifact.model_copy(
        update={"contract": artifact.contract.model_copy(update={"approval": other_approval})}
    )
    assert validate_approved_change_approval_artifact(with_approval).status == (
        "approval_artifact_invalid"
    )

    later = artifact.contract.approval.model_copy(
        update={"approved_at": datetime(2027, 1, 1, tzinfo=timezone.utc)}
    )
    with_timestamp = artifact.model_copy(
        update={"contract": artifact.contract.model_copy(update={"approval": later})}
    )
    assert validate_approved_change_approval_artifact(with_timestamp).status == (
        "approval_artifact_invalid"
    )


def test_a_mismatched_approval_subject_hash_and_invalid_binding_are_rejected(published_a):
    _, _, artifact = published_a
    mismatched = artifact.contract.approval.model_copy(update={"subject_sha256": NOT_A_HASH})
    broken = artifact.model_copy(
        update={"contract": artifact.contract.model_copy(update={"approval": mismatched})}
    )
    validation = validate_approved_change_approval_artifact(broken)
    assert validation.status == "approval_artifact_invalid"
    assert validation.approval_binding_valid is False
    assert any("binding" in error for error in validation.errors)


def test_a_widened_approval_scope_is_rejected(published_a):
    _, _, artifact = published_a
    widened = artifact.contract.approval.model_copy(update={"scope": "any_subject"})
    broken = artifact.model_copy(
        update={"contract": artifact.contract.model_copy(update={"approval": widened})}
    )
    validation = validate_approved_change_approval_artifact(broken)
    assert validation.status == "approval_artifact_invalid"
    assert any("scope" in error for error in validation.errors)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda content: content + "\n",
        lambda content: " " + content,
        lambda content: content.replace('{"artifact_type"', '{ "artifact_type"'),
        lambda content: json.dumps(json.loads(content), sort_keys=False, indent=2),
        lambda content: json.dumps(json.loads(content), ensure_ascii=True, separators=(",", ":")),
    ],
)
def test_noncanonical_content_is_rejected(published_a, mutate):
    _, _, artifact = published_a
    broken = artifact.model_copy(
        update={"canonical_content_utf8": mutate(artifact.canonical_content_utf8)}
    )
    assert validate_approved_change_approval_artifact(broken).status == (
        "approval_artifact_invalid"
    )


def test_extra_and_malformed_payloads_are_rejected(published_a):
    _, _, artifact = published_a
    data = artifact.model_dump(mode="json")
    data["unexpected"] = "extra"
    assert validate_approved_change_approval_artifact(data).status == "approval_artifact_invalid"

    incomplete = artifact.model_dump(mode="json")
    incomplete.pop("contract")
    assert validate_approved_change_approval_artifact(incomplete).status == (
        "approval_artifact_invalid"
    )
    for payload in ("{}", 7, None, ["approval"]):
        result = validate_approved_change_approval_artifact(payload)
        assert result.status in VALIDATION_STATUSES
        assert result.artifact_valid is False


def test_a_missing_or_extra_canonical_payload_field_is_rejected(published_a):
    _, _, artifact = published_a
    payload = json.loads(artifact.canonical_content_utf8)
    payload["extra"] = 1
    rebuilt, errors = artifact_module._artifact_from_canonical_payload(payload)
    assert rebuilt is None
    assert any("unexpected field" in error for error in errors)

    payload = json.loads(artifact.canonical_content_utf8)
    payload.pop("subject_sha256")
    rebuilt, errors = artifact_module._artifact_from_canonical_payload(payload)
    assert rebuilt is None
    assert any("missing the required field" in error for error in errors)


# --------------------------------------------------------------------------
# Source-provenance binding
# --------------------------------------------------------------------------


def test_the_artifact_records_the_exact_source_bundle(published_a):
    root, bundle, artifact = published_a
    assert artifact.source_bundle_id == bundle.bundle_id
    assert artifact.source_bundle_identity_sha256 == bundle.bundle_identity_sha256
    assert artifact.source_bundle_id == derive_bundle_id(bundle.bundle_identity_sha256)
    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    assert loaded.status == "persisted_approval_artifact_loaded"
    assert loaded.source_bundle_id == bundle.bundle_id
    assert loaded.source_bundle_revalidated is True


def test_an_identical_subject_never_substitutes_another_source_bundle(tmp_path):
    """Two bundles share one subject identity but never one approval artifact."""
    root = data_dir(tmp_path)
    first = bundle_a()
    second = bundle_same_subject()
    assert subject_sha256_of(first) == subject_sha256_of(second)
    assert first.bundle_id != second.bundle_id

    artifact_first = artifact_for(first, root)
    artifact_second = artifact_for(second, root)
    assert artifact_first.subject_sha256 == artifact_second.subject_sha256
    assert artifact_first.source_bundle_id != artifact_second.source_bundle_id
    assert artifact_first.approval_artifact_id != artifact_second.approval_artifact_id

    # Swapping the recorded provenance never validates.
    swapped = artifact_first.model_copy(
        update={
            "source_bundle_id": artifact_second.source_bundle_id,
            "source_bundle_identity_sha256": artifact_second.source_bundle_identity_sha256,
        }
    )
    assert validate_approved_change_approval_artifact(swapped).status == (
        "approval_artifact_invalid"
    )


def test_the_loader_requires_the_exact_source_bundle_to_be_present(tmp_path):
    origin = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), origin)

    # A second data root that holds only a different reviewed bundle.
    elsewhere = data_dir(tmp_path / "elsewhere")
    publish_bundle(bundle_same_subject(), elsewhere)
    write_artifact_directory(elsewhere, artifact)

    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=elsewhere
    )
    assert loaded.status == "persisted_approval_artifact_invalid"
    assert loaded.source_bundle_revalidated is False
    assert loaded.source_bundle_load_status == "persisted_bundle_not_found"
    assert any("source bundle" in error for error in loaded.errors)
    assert_never_expands(loaded)


def _stub_bundle(bundle, *, bundle_id=None, identity=None, subject_content=None):
    files = []
    for item in bundle.files:
        content = item.content_utf8
        sha = item.sha256
        if subject_content is not None and item.relative_path == APPROVED_CHANGE_SUBJECT_FILENAME:
            content = subject_content
            sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        files.append(
            types.SimpleNamespace(
                relative_path=item.relative_path,
                role=item.role,
                content_utf8=content,
                sha256=sha,
            )
        )
    return types.SimpleNamespace(
        bundle_id=bundle_id or bundle.bundle_id,
        bundle_identity_sha256=identity or bundle.bundle_identity_sha256,
        files=tuple(files),
    )


def _stub_loader(stub):
    def loader(bundle_id, *, data_dir):
        return types.SimpleNamespace(
            status="persisted_bundle_loaded", bundle=stub, errors=(), filesystem_accessed=True
        )

    return loader


def test_a_source_bundle_identity_mismatch_blocks_the_loader(published_a, monkeypatch):
    root, bundle, artifact = published_a
    stub = _stub_bundle(bundle, identity=NOT_A_HASH)
    monkeypatch.setattr(
        persistence, "load_persisted_approved_change_artifact_bundle", _stub_loader(stub)
    )
    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    assert loaded.status == "persisted_approval_artifact_invalid"
    assert any("another bundle identity" in error for error in loaded.errors)


def test_a_source_bundle_id_mismatch_blocks_the_loader(published_a, monkeypatch):
    root, bundle, artifact = published_a
    stub = _stub_bundle(bundle, bundle_id=f"{BUNDLE_ID_PREFIX}{NOT_A_HASH}")
    monkeypatch.setattr(
        persistence, "load_persisted_approved_change_artifact_bundle", _stub_loader(stub)
    )
    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    assert loaded.status == "persisted_approval_artifact_invalid"
    assert any("another bundle ID" in error for error in loaded.errors)


def test_a_source_subject_byte_mismatch_blocks_the_loader(published_a, monkeypatch):
    root, bundle, artifact = published_a
    other = canonical_subject_json(
        build_approved_change_approval_artifact(
            workflow_for(bundle_b(), data_dir(root.parent / "second"))
        ).artifact.contract.subject
    )
    stub = _stub_bundle(bundle, subject_content=other)
    monkeypatch.setattr(
        persistence, "load_persisted_approved_change_artifact_bundle", _stub_loader(stub)
    )
    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    assert loaded.status == "persisted_approval_artifact_invalid"
    assert any("subject" in error for error in loaded.errors)


def test_the_contract_subject_bytes_equal_the_source_bundle_subject_file(published_a):
    root, bundle, artifact = published_a
    stored = next(
        item.content_utf8
        for item in bundle.files
        if item.relative_path == APPROVED_CHANGE_SUBJECT_FILENAME
    )
    assert canonical_subject_json(artifact.contract.subject) == stored
    assert compute_subject_sha256(artifact.contract.subject) == artifact.subject_sha256


def test_reviewer_provenance_never_becomes_the_approver(published_a):
    _, _, artifact = published_a
    assert artifact.contract.approval.approved_by == APPROVED_BY
    for reviewer in ("operator-a", "operator-b", "operator-z"):
        assert artifact.contract.approval.approved_by != reviewer
    payload = json.loads(artifact.canonical_content_utf8)
    assert "reviewed_by" not in json.dumps(payload["contract"]["approval"])


# --------------------------------------------------------------------------
# Publication success
# --------------------------------------------------------------------------


def test_one_exact_publication_writes_exactly_one_fixed_file(
    tmp_path, no_replace_primitives, fs_recorder
):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    artifact = artifact_for(bundle, root)
    bundle_tree = snapshot(root / APPROVED_CHANGE_ARTIFACTS_DIRNAME)
    fs_recorder.calls.clear()

    result = publish_artifact(artifact, root)
    assert result.status == "approval_artifact_published"
    assert result.confirmation_matched is True
    assert result.atomic_publish_attempted is True
    assert result.atomic_publish_succeeded is True
    assert result.atomic_publish_outcome == "published"
    assert result.file_flush_status == "passed"
    assert result.temporary_directory_flush_status in {"passed", "unsupported"}
    assert result.all_files_prepared_before_publish is True
    assert result.prepared_file_count == 1
    assert result.post_validation_status == "passed"
    assert result.temporary_cleanup == "not_required"
    assert result.residual_temporary_directory == ""
    assert result.errors == ()

    assert result.read_only is False
    assert result.mutation_performed is True
    assert result.filesystem_accessed is True
    assert result.artifact_write_performed is True
    assert result.publication_performed is True
    assert result.persistence_performed is True
    assert result.persisted_approval_artifact_present is True
    assert result.approval_persisted is True
    assert result.contract_persisted is True
    assert_never_expands(result)

    directory = artifact_directory(root, artifact)
    assert directory.is_dir()
    assert sorted(item.name for item in directory.iterdir()) == [APPROVED_CHANGE_APPROVAL_FILENAME]
    assert artifact_file(root, artifact).read_bytes() == (
        artifact.canonical_content_utf8.encode("utf-8")
    )
    assert pending_entries(root) == []
    assert result.relative_artifact_directory == (
        f"{APPROVED_CHANGE_APPROVALS_DIRNAME}/{artifact.approval_artifact_id}"
    )
    # The PR317 source bundle survives byte- and mtime-identical.
    assert snapshot(root / APPROVED_CHANGE_ARTIFACTS_DIRNAME) == bundle_tree
    assert not [
        entry
        for entry in fs_recorder.write_paths()
        if str(root / APPROVED_CHANGE_ARTIFACTS_DIRNAME) in entry
    ]


def test_a_published_artifact_loads_back_exactly(published_a):
    root, bundle, artifact = published_a
    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    assert loaded.status == "persisted_approval_artifact_loaded"
    assert loaded.artifact == artifact
    assert loaded.artifact_validation.status == "approval_artifact_valid"
    assert loaded.approval_loaded is True
    assert loaded.contract_loaded is True
    assert loaded.approval_binding_valid is True
    assert loaded.persisted_approval_artifact_present is True
    assert loaded.read_only is True
    assert loaded.mutation_performed is False
    assert loaded.filesystem_accessed is True
    assert loaded.artifact_write_performed is False
    assert loaded.total_bytes_read == artifact.byte_length
    assert loaded.subject_sha256 == FIXTURE_A_SUBJECT_SHA256
    assert loaded.artifact.contract.approval.approved_by == APPROVED_BY
    assert loaded.artifact.contract.approval.approved_at == APPROVED_AT
    assert loaded.artifact.contract.approval.reason == REASON
    assert loaded.artifact.contract.approval.scope == APPROVAL_SCOPE_EXACT_SUBJECT_ONLY
    assert_never_expands(loaded)


def test_the_final_directory_is_the_exact_full_artifact_id(published_a):
    root, _, artifact = published_a
    directory = artifact_directory(root, artifact)
    assert directory.name == artifact.approval_artifact_id
    assert directory.name == (
        f"{APPROVAL_ARTIFACT_ID_PREFIX}{artifact.approval_artifact_identity_sha256}"
    )
    assert len(directory.name) == len(APPROVAL_ARTIFACT_ID_PREFIX) + 64
    assert sorted(item.name for item in publication_root(root).iterdir()) == [directory.name]


def test_persisted_modes_are_restrictive_where_supported(published_a):
    root, _, artifact = published_a
    if os.name == "nt":  # pragma: no cover - Windows lane
        pytest.skip("POSIX mode bits are not meaningful on Windows")
    directory = artifact_directory(root, artifact)
    assert stat_module.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat_module.S_IMODE(artifact_file(root, artifact).stat().st_mode) == 0o600


def test_publication_adds_no_sidecar_marker_or_pointer(published_a):
    root, _, artifact = published_a
    assert sorted(item.name for item in artifact_directory(root, artifact).iterdir()) == [
        APPROVED_CHANGE_APPROVAL_FILENAME
    ]
    for forbidden in ("latest", "current", "index.json", "status.json", ".complete", "pointer"):
        assert not (publication_root(root) / forbidden).exists()
        assert not (artifact_directory(root, artifact) / forbidden).exists()


# --------------------------------------------------------------------------
# Invalid confirmation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "confirmation",
    [
        "",
        None,
        42,
        "   ",
        NOT_A_HASH,
        "abc",
        FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256.upper(),
        f" {FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256}",
        FIXTURE_A_APPROVAL_ARTIFACT_ID,
        FIXTURE_A_BUNDLE_IDENTITY_SHA256,
        FIXTURE_A_SUBJECT_SHA256,
    ],
)
def test_an_invalid_confirmation_reaches_no_filesystem_object(
    tmp_path, confirmation, no_filesystem_mutation
):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    before = snapshot(root)
    no_filesystem_mutation()

    result = publish_artifact(artifact, root, confirmation=confirmation)
    assert result.status == "invalid_publication_input"
    assert result.confirmation_matched is False
    assert result.read_only is True
    assert result.mutation_performed is False
    assert result.filesystem_accessed is False
    assert result.artifact_write_performed is False
    assert result.approval_persisted is False
    assert result.contract_persisted is False
    assert result.publication_root_created is False
    assert result.temporary_directory_created is False
    assert_never_expands(result)
    assert not publication_root(root).exists()
    assert snapshot(root) == before


def test_the_zero_filesystem_access_proof_is_not_vacuous(tmp_path, no_filesystem_mutation):
    """The guard used by the confirmation tests above really is installed.

    Under the exact same guard a *valid* confirmation reaches the filesystem and
    fails closed, so `filesystem_accessed=False` on a rejected confirmation is a
    real measurement rather than an accident of the fixture.
    """
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    no_filesystem_mutation()
    result = publish_artifact(artifact, root)
    assert result.status == "publication_failed_precommit"
    assert result.filesystem_accessed is True
    assert result.publication_root_created is False
    assert not publication_root(root).exists()


def test_a_stale_or_foreign_identity_confirmation_is_refused(tmp_path, no_filesystem_mutation):
    root = data_dir(tmp_path)
    first = artifact_for(bundle_a(), root)
    second = artifact_for(bundle_b(), root)
    no_filesystem_mutation()
    result = publish_artifact(first, root, confirmation=second.approval_artifact_identity_sha256)
    assert result.status == "invalid_publication_input"
    assert result.confirmation_matched is False
    assert not publication_root(root).exists()


def test_the_confirmation_scope_is_publication_only(published_a):
    _, _, artifact = published_a
    result = publish_artifact(artifact, published_a[0])
    assert result.confirmation_scope == (persistence.APPROVAL_PUBLICATION_CONFIRMATION_SCOPE)
    assert "publish" in result.confirmation_scope
    for forbidden in ("execute", "authorize", "capability", "overwrite", "approve_"):
        assert forbidden not in result.confirmation_scope


def test_an_invalid_artifact_is_refused_before_any_filesystem_access(
    tmp_path, no_filesystem_mutation
):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    tampered = artifact.model_copy(update={"byte_length": 3})
    no_filesystem_mutation()
    result = publish_artifact(tampered, root, confirmation=NOT_A_HASH)
    assert result.status == "invalid_publication_input"
    assert result.filesystem_accessed is False
    assert not publication_root(root).exists()


# --------------------------------------------------------------------------
# Idempotency
# --------------------------------------------------------------------------


def test_a_second_publication_is_already_present_and_writes_nothing(published_a, fs_recorder):
    root, _, artifact = published_a
    before = snapshot(root)
    fs_recorder.calls.clear()

    result = publish_artifact(artifact, root)
    assert result.status == "approval_artifact_already_present"
    assert result.persisted_approval_artifact_present is True
    assert result.post_validation_status == "passed"
    assert result.read_only is True
    assert result.mutation_performed is False
    assert result.artifact_write_performed is False
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.approval_persisted is False
    assert result.contract_persisted is False
    assert result.temporary_directory_created is False
    assert result.atomic_publish_attempted is False
    assert result.temporary_cleanup == "not_required"
    assert result.errors == ()
    assert_never_expands(result)

    assert snapshot(root) == before
    assert pending_entries(root) == []
    assert fs_recorder.creations(root) == []
    assert not [entry for entry in fs_recorder.touched(root) if entry[0] in {"write", "unlink"}]


def test_repeated_publications_never_change_a_byte_or_an_mtime(published_a):
    root, _, artifact = published_a
    before = snapshot(root)
    for _ in range(3):
        assert publish_artifact(artifact, root).status == "approval_artifact_already_present"
    assert snapshot(root) == before


# --------------------------------------------------------------------------
# Conflict and race
# --------------------------------------------------------------------------


def test_conflicting_existing_bytes_block_and_are_never_overwritten(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    write_artifact_directory(
        root, artifact, mutate=lambda payload: {APPROVED_CHANGE_APPROVAL_FILENAME: b"{}"}
    )
    before = snapshot(root)

    result = publish_artifact(artifact, root)
    assert result.status == "approval_artifact_publication_blocked"
    assert result.overwrite_performed is False
    assert result.post_validation_status == "failed"
    assert result.temporary_directory_created is False
    assert_never_expands(result)
    assert snapshot(root) == before


def test_another_valid_artifact_at_the_same_destination_blocks(tmp_path):
    root = data_dir(tmp_path)
    first = artifact_for(bundle_a(), root)
    second = artifact_for(bundle_b(), root)
    # Force a seam: the second artifact's bytes stored under the first ID.
    write_artifact_directory(
        root,
        second,
        name=first.approval_artifact_id,
    )
    before = snapshot(root)
    result = publish_artifact(first, root)
    assert result.status == "approval_artifact_publication_blocked"
    assert result.overwrite_performed is False
    assert snapshot(root) == before


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: {},
        lambda payload: {**payload, "extra.json": b"{}"},
    ],
)
def test_a_missing_or_extra_destination_file_blocks(tmp_path, mutate):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    write_artifact_directory(root, artifact, mutate=mutate)
    before = snapshot(root)
    result = publish_artifact(artifact, root)
    assert result.status == "approval_artifact_publication_blocked"
    assert result.overwrite_performed is False
    assert snapshot(root) == before


def test_a_directory_in_place_of_the_fixed_file_blocks(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    directory = publication_root(root) / artifact.approval_artifact_id
    directory.mkdir(parents=True)
    (directory / APPROVED_CHANGE_APPROVAL_FILENAME).mkdir()
    before = snapshot(root)
    result = publish_artifact(artifact, root)
    assert result.status == "approval_artifact_publication_blocked"
    assert snapshot(root) == before


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_a_symlinked_destination_blocks(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    real = tmp_path / "outside"
    real.mkdir()
    publication_root(root).mkdir(parents=True)
    (publication_root(root) / artifact.approval_artifact_id).symlink_to(real)
    before = snapshot(root)
    result = publish_artifact(artifact, root)
    assert result.status in {
        "approval_artifact_publication_blocked",
        "publication_failed_precommit",
    }
    assert result.overwrite_performed is False
    assert snapshot(root) == before
    assert list(real.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_a_symlinked_persisted_file_blocks_the_loader(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    directory = publication_root(root) / artifact.approval_artifact_id
    directory.mkdir(parents=True)
    target = tmp_path / "elsewhere.json"
    target.write_text(artifact.canonical_content_utf8, encoding="utf-8")
    (directory / APPROVED_CHANGE_APPROVAL_FILENAME).symlink_to(target)
    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    assert loaded.status == "persisted_approval_artifact_invalid"


def test_a_destination_appearing_before_the_commit_is_never_replaced(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    other = artifact_for(bundle_b(), root)

    seen = run_at(
        monkeypatch,
        "temporary_directory_flush",
        lambda: write_artifact_directory(root, other, name=artifact.approval_artifact_id),
    )
    result = publish_artifact(artifact, root)
    assert seen == ["temporary_directory_flush"]
    assert result.status == "approval_artifact_publication_blocked"
    assert result.atomic_publish_attempted is False
    assert result.overwrite_performed is False
    assert result.temporary_cleanup == "completed"
    assert pending_entries(root) == []
    assert artifact_file(root, artifact).read_bytes() == (
        other.canonical_content_utf8.encode("utf-8")
    )


def test_an_identical_destination_appearing_before_the_commit_is_already_present(
    tmp_path, monkeypatch
):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    seen = run_at(
        monkeypatch,
        "temporary_directory_flush",
        lambda: write_artifact_directory(root, artifact),
    )
    result = publish_artifact(artifact, root)
    assert seen == ["temporary_directory_flush"]
    assert result.status == "approval_artifact_already_present"
    assert result.overwrite_performed is False
    assert result.temporary_cleanup == "completed"
    assert result.artifact_write_performed is True
    assert pending_entries(root) == []


def test_the_native_primitive_refuses_a_destination_that_appears_at_the_commit_seam(
    tmp_path, monkeypatch, no_replace_primitives
):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    other = artifact_for(bundle_b(), root)
    seen = run_at(
        monkeypatch,
        "atomic_publish",
        lambda: write_artifact_directory(root, other, name=artifact.approval_artifact_id),
    )
    result = publish_artifact(artifact, root)
    assert seen == ["atomic_publish"]
    assert result.status == "approval_artifact_publication_blocked"
    assert result.atomic_publish_attempted is True
    assert result.atomic_publish_outcome == "destination_exists"
    assert result.atomic_publish_succeeded is False
    assert result.overwrite_performed is False
    assert artifact_file(root, artifact).read_bytes() == (
        other.canonical_content_utf8.encode("utf-8")
    )
    assert pending_entries(root) == []


# --------------------------------------------------------------------------
# Flush, atomic, and cleanup failures
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "stage,expected_flush",
    [
        ("write", "not_attempted"),
        ("file_flush", "failed"),
        ("file_hash_verify", "passed"),
        ("prepared_artifact_reconstruct", "passed"),
        ("prepared_artifact_validate", "passed"),
    ],
)
def test_an_injected_precommit_failure_publishes_nothing(
    tmp_path, monkeypatch, stage, expected_flush
):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    before = snapshot(root)

    inject_failure(monkeypatch, stage)
    result = publish_artifact(artifact, root)
    assert result.status == "publication_failed_precommit"
    assert result.file_flush_status == expected_flush
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.approval_persisted is False
    assert result.contract_persisted is False
    assert result.temporary_cleanup == "completed"
    assert result.temporary_cleanup_performed is True
    assert result.residual_temporary_directory == ""
    assert result.mutation_performed is True
    assert_never_expands(result)
    assert not artifact_directory(root, artifact).exists()
    assert pending_entries(root) == []
    assert snapshot(root) == before


def test_a_temporary_directory_flush_failure_blocks_publication(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    monkeypatch.setattr(persistence, "_fsync_directory", lambda path: ("failed", "flush failed"))
    result = publish_artifact(artifact, root)
    assert result.status == "publication_failed_precommit"
    assert result.temporary_directory_flush_status == "failed"
    assert not artifact_directory(root, artifact).exists()
    assert pending_entries(root) == []


def test_a_root_creation_failure_fails_closed(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    # Remove the root created by the bundle publication path.
    inject_failure(monkeypatch, "publication_root_create")
    result = publish_artifact(artifact, root)
    assert result.status == "publication_failed_precommit"
    assert result.publication_root_created is False
    assert not publication_root(root).exists()


def test_a_temporary_directory_creation_failure_fails_closed(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    inject_failure(monkeypatch, "temporary_directory_create")
    result = publish_artifact(artifact, root)
    assert result.status == "publication_failed_precommit"
    assert result.temporary_directory_created is False
    assert result.publication_root_removed is True
    assert not publication_root(root).exists()


def test_an_unsupported_atomic_primitive_fails_closed(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    monkeypatch.setattr(
        persistence,
        "atomic_no_replace_approval_directory_publish",
        lambda source, destination: AtomicNoReplaceOutcome("unsupported", "none", "no primitive"),
    )
    result = publish_artifact(artifact, root)
    assert result.status == "atomic_publication_unsupported"
    assert result.atomic_publish_attempted is True
    assert result.atomic_publish_succeeded is False
    assert result.publication_performed is False
    assert result.approval_persisted is False
    assert result.temporary_cleanup == "completed"
    assert not artifact_directory(root, artifact).exists()
    assert pending_entries(root) == []


def test_a_failed_atomic_primitive_fails_closed(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    monkeypatch.setattr(
        persistence,
        "atomic_no_replace_approval_directory_publish",
        lambda source, destination: AtomicNoReplaceOutcome("failed", "none", "injected"),
    )
    result = publish_artifact(artifact, root)
    assert result.status == "publication_failed_precommit"
    assert result.publication_performed is False
    assert not artifact_directory(root, artifact).exists()
    assert pending_entries(root) == []


def test_an_unknown_temporary_entry_is_preserved_and_reported(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)

    def add_unknown_entry_then_fail(name: str) -> None:
        if name != "file_hash_verify":
            return
        pending = pending_entries(root)
        assert pending
        (pending[0] / "unknown-entry.txt").write_bytes(b"not mine")
        raise OSError("injected failure")

    monkeypatch.setattr(persistence, "_failpoint", add_unknown_entry_then_fail)
    result = publish_artifact(artifact, root)
    assert result.status == "publication_failed_cleanup_incomplete"
    assert result.temporary_cleanup == "incomplete"
    assert result.temporary_cleanup_performed is False
    assert result.residual_temporary_directory.startswith(TEMPORARY_DIRECTORY_PREFIX)
    assert any("preserved" in error for error in result.errors)
    residual = publication_root(root) / result.residual_temporary_directory
    assert (residual / "unknown-entry.txt").read_bytes() == b"not mine"
    assert not artifact_directory(root, artifact).exists()


def test_a_cleanup_file_removal_failure_is_reported(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    inject_failure(monkeypatch, "file_hash_verify")

    def boom(path, *args, **kwargs):
        raise OSError("unlink refused")

    monkeypatch.setattr(persistence.os, "unlink", boom)
    result = publish_artifact(artifact, root)
    assert result.status == "publication_failed_cleanup_incomplete"
    assert result.temporary_cleanup == "incomplete"
    assert result.residual_temporary_directory.startswith(TEMPORARY_DIRECTORY_PREFIX)
    assert not artifact_directory(root, artifact).exists()


def test_a_cleanup_directory_removal_failure_is_reported(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    inject_failure(monkeypatch, "file_hash_verify")

    def boom(path, *args, **kwargs):
        raise OSError("rmdir refused")

    monkeypatch.setattr(persistence.os, "rmdir", boom)
    result = publish_artifact(artifact, root)
    assert result.status == "publication_failed_cleanup_incomplete"
    assert result.temporary_cleanup == "incomplete"
    assert not artifact_directory(root, artifact).exists()


def test_a_post_publication_verification_failure_never_deletes_the_artifact(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)

    real_loader = persistence.load_persisted_approved_change_approval_artifact
    calls: list[str] = []

    def broken_loader(artifact_id, *, data_dir):
        calls.append(artifact_id)
        result = real_loader(artifact_id, data_dir=data_dir)
        return result.model_copy(
            update={"status": "persisted_approval_artifact_invalid", "artifact": None}
        )

    monkeypatch.setattr(
        persistence, "load_persisted_approved_change_approval_artifact", broken_loader
    )
    result = publish_artifact(artifact, root)
    assert calls
    assert result.status == "published_verification_failed"
    assert result.publication_performed is True
    assert result.persistence_performed is True
    assert result.approval_persisted is True
    assert result.contract_persisted is True
    assert result.persisted_approval_artifact_present is True
    assert result.post_validation_status == "failed"
    assert result.overwrite_performed is False
    assert_never_expands(result)
    # The published artifact was retained: no automatic removal or rollback.
    assert artifact_file(root, artifact).read_bytes() == (
        artifact.canonical_content_utf8.encode("utf-8")
    )
    monkeypatch.undo()
    assert (
        load_persisted_approved_change_approval_artifact(
            artifact.approval_artifact_id, data_dir=root
        ).status
        == "persisted_approval_artifact_loaded"
    )


def test_a_published_artifact_is_never_deleted_by_a_later_failure(published_a, monkeypatch):
    root, _, artifact = published_a
    before = snapshot(root)
    inject_failure(monkeypatch, "atomic_publish")
    result = publish_artifact(artifact, root)
    assert result.status == "approval_artifact_already_present"
    assert snapshot(root) == before


# --------------------------------------------------------------------------
# Path and platform safety
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "make_root",
    [
        lambda tmp_path: "relative/data",
        lambda tmp_path: Path("relative/data"),
        lambda tmp_path: "",
        lambda tmp_path: 42,
        lambda tmp_path: Path(tmp_path.anchor),
    ],
)
def test_a_structurally_unsafe_data_root_reaches_no_filesystem_object(
    tmp_path, make_root, no_filesystem_mutation
):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    no_filesystem_mutation()
    result = publish_artifact(artifact, make_root(tmp_path))
    assert result.status == "approval_artifact_publication_blocked"
    assert result.filesystem_accessed is False
    assert result.mutation_performed is False
    assert_never_expands(result)


def test_a_missing_or_non_directory_data_root_blocks(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    missing = publish_artifact(artifact, tmp_path / "absent")
    assert missing.status == "approval_artifact_publication_blocked"
    assert any("exist" in error for error in missing.errors)

    file_root = tmp_path / "a-file"
    file_root.write_text("not a directory", encoding="utf-8")
    as_file = publish_artifact(artifact, file_root)
    assert as_file.status == "approval_artifact_publication_blocked"
    assert any("directory" in error for error in as_file.errors)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_a_symlinked_data_root_or_publication_root_blocks(tmp_path):
    real = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), real)

    linked = tmp_path / "linked-data"
    linked.symlink_to(real)
    result = publish_artifact(artifact, linked)
    assert result.status == "approval_artifact_publication_blocked"
    assert any("symlink" in error for error in result.errors)

    other = data_dir(tmp_path / "second")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (other / APPROVED_CHANGE_APPROVALS_DIRNAME).symlink_to(elsewhere)
    unsafe = publish_artifact(artifact, other)
    assert unsafe.status == "approval_artifact_publication_blocked"
    assert list(elsewhere.iterdir()) == []


def test_an_unaddressable_final_path_fails_closed_before_anything_is_created(
    tmp_path, monkeypatch, fs_recorder
):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    longest = len(str(artifact_directory(root, artifact) / APPROVED_CHANGE_APPROVAL_FILENAME))
    monkeypatch.setattr(persistence, "MAX_PUBLICATION_PATH_CHARS", longest - 1)
    fs_recorder.calls.clear()

    result = publish_artifact(artifact, root)
    assert result.status == "approval_artifact_publication_blocked"
    assert any("too long" in error for error in result.errors)
    assert result.publication_root_created is False
    assert result.temporary_directory_created is False
    assert result.artifact_write_performed is False
    assert not publication_root(root).exists()
    assert fs_recorder.creations(root) == []
    assert str(tmp_path) not in json.dumps(result.model_dump(mode="json"))


def test_the_publication_path_limit_matches_the_platform():
    if os.name == "nt":  # pragma: no cover - Windows lane
        assert persistence.MAX_PUBLICATION_PATH_CHARS == 259
    else:
        assert persistence.MAX_PUBLICATION_PATH_CHARS == 4095
    source = module_code_without_strings(persistence)
    assert "GetLongPathName" not in source
    assert "GetShortPathName" not in source


def test_the_pending_name_is_short_and_shorter_than_the_final_path(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    captured: list[str] = []

    def capture(name: str) -> None:
        if name == "file_hash_verify":
            captured.extend(item.name for item in pending_entries(root))

    monkeypatch.setattr(persistence, "_failpoint", capture)
    assert publish_artifact(artifact, root).status == "approval_artifact_published"

    assert len(captured) == 1
    pending = captured[0]
    assert pending.startswith(TEMPORARY_DIRECTORY_PREFIX)
    assert len(pending) == TEMPORARY_DIRECTORY_NAME_LENGTH == 25
    assert len(pending) < len(artifact.approval_artifact_id)
    assert artifact.approval_artifact_id not in pending
    assert artifact.approval_artifact_identity_sha256 not in pending
    assert artifact.subject_sha256 not in pending


def test_the_pending_token_never_reaches_a_durable_artifact(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    monkeypatch.setattr(persistence, "_temporary_nonce", lambda: "abcdef0123456789")
    result = publish_artifact(artifact, root)
    assert result.status == "approval_artifact_published"
    assert "abcdef0123456789" not in json.dumps(result.model_dump(mode="json"))
    assert b"abcdef0123456789" not in artifact_file(root, artifact).read_bytes()
    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    assert "abcdef0123456789" not in json.dumps(loaded.model_dump(mode="json"))
    # A large sample of tokens stays unique.
    monkeypatch.undo()
    assert len({persistence._temporary_nonce() for _ in range(256)}) == 256


@LINUX_ONLY
def test_linux_uses_the_native_no_replace_primitive(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    destination = tmp_path / "destination"
    outcome = persistence.atomic_no_replace_approval_directory_publish(source, destination)
    assert outcome.outcome == "published"
    assert outcome.platform_primitive == "linux_renameat2_no_replace"
    assert destination.is_dir()

    again = tmp_path / "again"
    again.mkdir()
    blocked = persistence.atomic_no_replace_approval_directory_publish(again, destination)
    assert blocked.outcome == "destination_exists"
    assert again.is_dir()


@WINDOWS_ONLY
def test_windows_uses_the_native_move_file_primitive(tmp_path):  # pragma: no cover - Windows
    source = tmp_path / "source"
    source.mkdir()
    destination = tmp_path / "destination"
    outcome = persistence.atomic_no_replace_approval_directory_publish(source, destination)
    assert outcome.outcome == "published"
    assert outcome.platform_primitive == "windows_movefileexw_no_replace"
    again = tmp_path / "again"
    again.mkdir()
    blocked = persistence.atomic_no_replace_approval_directory_publish(again, destination)
    assert blocked.outcome == "destination_exists"


@WINDOWS_ONLY
def test_windows_normal_test_root_geometry_fits_max_path(tmp_path):  # pragma: no cover - Windows
    """A normal Windows test root must address the fixed final approval path."""
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    result = publish_artifact(artifact, root)
    assert result.status == "approval_artifact_published"
    assert result.file_flush_status == "passed"
    assert result.temporary_directory_flush_status == "unsupported"
    final = artifact_file(root, artifact)
    assert len(str(final)) <= persistence.MAX_PUBLICATION_PATH_CHARS
    assert final.is_file()


@WINDOWS_ONLY
def test_windows_directory_flush_reports_unsupported(tmp_path):  # pragma: no cover - Windows
    status, detail = persistence._fsync_directory(tmp_path)
    assert status == "unsupported"
    assert detail


def test_an_unsupported_platform_fails_closed(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(persistence.sys, "platform", "sunos5")
    monkeypatch.setattr(persistence.os, "name", "posix")
    outcome = persistence.atomic_no_replace_approval_directory_publish(
        source, tmp_path / "destination"
    )
    assert outcome.outcome == "unsupported"


@pytest.mark.parametrize(
    "make_paths",
    [
        lambda tmp_path: ("relative", tmp_path / "destination"),
        lambda tmp_path: (tmp_path / "a" / "source", tmp_path / "b" / "destination"),
        lambda tmp_path: (tmp_path / "same", tmp_path / "same"),
    ],
)
def test_the_atomic_primitive_rejects_unsafe_requests(tmp_path, make_paths):
    source, destination = make_paths(tmp_path)
    if isinstance(source, Path):
        source.parent.mkdir(parents=True, exist_ok=True)
        source.mkdir(exist_ok=True)
    outcome = persistence.atomic_no_replace_approval_directory_publish(
        Path(source) if isinstance(source, str) else source, destination
    )
    assert outcome.outcome == "rejected"


# --------------------------------------------------------------------------
# Loader
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reference",
    [
        "",
        None,
        42,
        "latest",
        "current",
        "most recent",
        "aca_",
        FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256,
        FIXTURE_A_APPROVAL_ARTIFACT_ID[:20],
        FIXTURE_A_APPROVAL_ARTIFACT_ID.upper(),
        f" {FIXTURE_A_APPROVAL_ARTIFACT_ID}",
        f"{FIXTURE_A_APPROVAL_ARTIFACT_ID}\n",
        f"../{FIXTURE_A_APPROVAL_ARTIFACT_ID}",
        f"/{FIXTURE_A_APPROVAL_ARTIFACT_ID}",
        f"C:\\{FIXTURE_A_APPROVAL_ARTIFACT_ID}",
        f"\\\\server\\share\\{FIXTURE_A_APPROVAL_ARTIFACT_ID}",
        "aca_*",
        f"{APPROVAL_ARTIFACT_ID_PREFIX}{'g' * 64}",
        f"{BUNDLE_ID_PREFIX}{FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256}",
    ],
)
def test_the_loader_accepts_only_one_exact_full_artifact_id(published_a, reference):
    root, _, _ = published_a
    loaded = load_persisted_approved_change_approval_artifact(reference, data_dir=root)
    assert loaded.status == "invalid_approval_artifact_reference"
    assert loaded.artifact is None
    assert loaded.filesystem_accessed is False
    assert loaded.approval_loaded is False
    assert loaded.contract_loaded is False
    assert_never_expands(loaded)


def test_the_loader_reports_not_found_for_an_absent_artifact(tmp_path):
    root = data_dir(tmp_path)
    absent = f"{APPROVAL_ARTIFACT_ID_PREFIX}{'a' * 64}"
    empty = load_persisted_approved_change_approval_artifact(absent, data_dir=root)
    assert empty.status == "persisted_approval_artifact_not_found"
    assert empty.artifact is None

    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    missing = load_persisted_approved_change_approval_artifact(absent, data_dir=root)
    assert missing.status == "persisted_approval_artifact_not_found"
    assert missing.artifact is None
    assert_never_expands(missing)


def test_the_loader_rejects_an_unsafe_data_root(tmp_path, no_filesystem_mutation):
    no_filesystem_mutation()
    loaded = load_persisted_approved_change_approval_artifact(
        FIXTURE_A_APPROVAL_ARTIFACT_ID, data_dir="relative/data"
    )
    assert loaded.status == "unsafe_approval_persistence_root"
    assert loaded.filesystem_accessed is False


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: {},
        lambda payload: {**payload, "extra.json": b"{}"},
        lambda payload: {APPROVED_CHANGE_APPROVAL_FILENAME: b"{"},
        lambda payload: {APPROVED_CHANGE_APPROVAL_FILENAME: b'{"schema_version":"1"}'},
        lambda payload: {
            APPROVED_CHANGE_APPROVAL_FILENAME: payload[APPROVED_CHANGE_APPROVAL_FILENAME] + b"\n"
        },
        lambda payload: {
            APPROVED_CHANGE_APPROVAL_FILENAME: json.dumps(
                json.loads(payload[APPROVED_CHANGE_APPROVAL_FILENAME]), indent=2
            ).encode("utf-8")
        },
    ],
)
def test_the_loader_rejects_a_missing_extra_or_noncanonical_persisted_file(tmp_path, mutate):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    write_artifact_directory(root, artifact, mutate=mutate)
    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    assert loaded.status == "persisted_approval_artifact_invalid"
    assert loaded.artifact is None
    assert_never_expands(loaded)


def test_the_loader_rejects_a_tampered_contract_and_an_invalid_binding(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    payload = json.loads(artifact.canonical_content_utf8)
    payload["contract"]["approval"]["approved_by"] = "impostor"
    write_artifact_directory(
        root,
        artifact,
        mutate=lambda _: {
            APPROVED_CHANGE_APPROVAL_FILENAME: json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        },
    )
    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    # The tampered bytes hash to another identity than the directory name.
    assert loaded.status == "persisted_approval_artifact_invalid"

    broken = json.loads(artifact.canonical_content_utf8)
    broken["contract"]["approval"]["subject_sha256"] = NOT_A_HASH
    directory = publication_root(root) / artifact.approval_artifact_id
    content = json.dumps(broken, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    (directory / APPROVED_CHANGE_APPROVAL_FILENAME).write_bytes(content.encode("utf-8"))
    invalid = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    assert invalid.status == "persisted_approval_artifact_invalid"
    assert invalid.approval_binding_valid is False


def test_the_loader_rejects_an_artifact_stored_under_another_id(tmp_path):
    root = data_dir(tmp_path)
    first = artifact_for(bundle_a(), root)
    second = artifact_for(bundle_b(), root)
    write_artifact_directory(root, second, name=first.approval_artifact_id)
    loaded = load_persisted_approved_change_approval_artifact(
        first.approval_artifact_id, data_dir=root
    )
    assert loaded.status == "persisted_approval_artifact_invalid"
    assert any("directory" in error for error in loaded.errors)


def test_the_loader_enforces_a_conservative_size_bound(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    monkeypatch.setattr(persistence, "MAX_PERSISTED_APPROVAL_FILE_BYTES", artifact.byte_length - 1)
    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    assert loaded.status == "persisted_approval_artifact_invalid"
    assert any("per-file limit" in error for error in loaded.errors)


def test_the_loader_detects_size_drift(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    path = artifact_file(root, artifact)

    real_read = persistence._read_bounded

    def growing(target, expected_size):
        path.chmod(0o600)
        with open(target, "ab") as handle:
            handle.write(b"x")
        return real_read(target, expected_size)

    monkeypatch.setattr(persistence, "_read_bounded", growing)
    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    assert loaded.status == "persisted_approval_artifact_invalid"


def test_the_loader_rejects_a_non_utf8_persisted_file(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    write_artifact_directory(
        root, artifact, mutate=lambda _: {APPROVED_CHANGE_APPROVAL_FILENAME: b"\xff\xfe\x00"}
    )
    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    assert loaded.status == "persisted_approval_artifact_invalid"


def test_the_loader_never_writes_repairs_or_republishes(published_a, fs_recorder):
    root, _, artifact = published_a
    before = snapshot(root)
    fs_recorder.calls.clear()
    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    assert loaded.status == "persisted_approval_artifact_loaded"
    assert snapshot(root) == before
    assert fs_recorder.write_paths() == []


# --------------------------------------------------------------------------
# No hidden expansion
# --------------------------------------------------------------------------


class _GuardedEnvironment(dict):
    def __getitem__(self, key):
        raise AssertionError("an environment variable was read")

    def get(self, *args, **kwargs):
        raise AssertionError("an environment variable was read")


def install_ambient_guards(monkeypatch, *, allow_randomness=False):
    """Fail loudly on any clock, identity, network, or model lookup."""

    def raiser(label):
        def boom(*args, **kwargs):
            raise AssertionError(f"{label} was reached")

        return boom

    monkeypatch.setattr(time, "time", raiser("time.time"))
    monkeypatch.setattr(time, "time_ns", raiser("time.time_ns"))
    monkeypatch.setattr(time, "monotonic", raiser("time.monotonic"))
    monkeypatch.setattr(uuid, "uuid4", raiser("uuid.uuid4"))
    monkeypatch.setattr(uuid, "uuid1", raiser("uuid.uuid1"))
    monkeypatch.setattr(socket, "socket", raiser("socket.socket"))
    monkeypatch.setattr(socket, "gethostname", raiser("socket.gethostname"))
    monkeypatch.setattr(subprocess, "run", raiser("subprocess.run"))
    monkeypatch.setattr(subprocess, "Popen", raiser("subprocess.Popen"))
    monkeypatch.setattr(os, "system", raiser("os.system"))
    monkeypatch.setattr(os, "getenv", raiser("os.getenv"))
    monkeypatch.setattr(os, "environ", _GuardedEnvironment())
    if hasattr(os, "getlogin"):
        monkeypatch.setattr(os, "getlogin", raiser("os.getlogin"))
    if not allow_randomness:
        monkeypatch.setattr(random, "random", raiser("random.random"))
        monkeypatch.setattr(random, "randint", raiser("random.randint"))
    return True


def test_the_builder_reaches_no_clock_identity_network_or_shell(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    result = workflow_for(bundle_a(), root)
    install_ambient_guards(monkeypatch)

    def boom(*args, **kwargs):
        raise AssertionError("a filesystem primitive was reached")

    for name in ("mkdir", "makedirs", "rename", "replace", "rmdir", "unlink", "remove", "open"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, boom)
    monkeypatch.setattr(Path, "mkdir", boom)
    monkeypatch.setattr(Path, "write_bytes", boom)
    monkeypatch.setattr(Path, "write_text", boom)
    monkeypatch.setattr(Path, "read_bytes", boom)
    monkeypatch.setattr(tempfile, "mkdtemp", boom)
    monkeypatch.setattr(tempfile, "mkstemp", boom)

    built = build_approved_change_approval_artifact(result)
    assert built.status == "approval_artifact_constructed"
    assert validate_approved_change_approval_artifact(built.artifact).status == (
        "approval_artifact_valid"
    )


def test_publication_reaches_no_clock_identity_network_or_shell(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    install_ambient_guards(monkeypatch, allow_randomness=True)
    result = publish_artifact(artifact, root)
    assert result.status == "approval_artifact_published"
    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    assert loaded.status == "persisted_approval_artifact_loaded"


def test_no_capability_preflight_receipt_or_execution_module_is_reached(tmp_path, monkeypatch):
    from shellforgeai.core import approvals as legacy_approvals
    from shellforgeai.core import approved_change_contract as contract_module
    from shellforgeai.core import recipe_registry

    def boom(label):
        def raiser(*args, **kwargs):
            raise AssertionError(f"{label} was reached")

        return raiser

    monkeypatch.setattr(
        contract_module,
        "validate_approved_change_contract",
        boom("validate_approved_change_contract"),
    )
    for name in dir(recipe_registry):
        candidate = getattr(recipe_registry, name)
        if callable(candidate) and not name.startswith("_") and not isinstance(candidate, type):
            monkeypatch.setattr(
                recipe_registry, name, boom(f"recipe_registry.{name}"), raising=False
            )
    for name in ("approve_proposal", "load_proposal", "save_proposal", "set_status"):
        if hasattr(legacy_approvals, name):
            monkeypatch.setattr(legacy_approvals, name, boom(f"approvals.{name}"))

    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    assert publish_artifact(artifact, root).status == "approval_artifact_published"
    assert (
        load_persisted_approved_change_approval_artifact(
            artifact.approval_artifact_id, data_dir=root
        ).status
        == "persisted_approval_artifact_loaded"
    )


def test_no_legacy_approval_queue_directory_is_created(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    load_persisted_approved_change_approval_artifact(artifact.approval_artifact_id, data_dir=root)
    assert sorted(item.name for item in root.iterdir()) == sorted(
        [APPROVED_CHANGE_ARTIFACTS_DIRNAME, APPROVED_CHANGE_APPROVALS_DIRNAME]
    )
    for name in ("proposals", "approvals", "approved", "pending", "rejected", "queue"):
        assert not (root / name).exists()


# --------------------------------------------------------------------------
# No writes outside the fixed subtree
# --------------------------------------------------------------------------


def test_every_write_stays_inside_the_fixed_approval_subtree(tmp_path, fs_recorder):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    approvals_root = publication_root(root)
    fs_recorder.calls.clear()

    result = publish_artifact(artifact, root)
    assert result.status == "approval_artifact_published"

    writes = fs_recorder.write_paths()
    assert writes
    for path in writes:
        assert path.startswith(str(approvals_root)), path
    created = {Path(path) for name, path in fs_recorder.calls if name == "mkdir"}
    assert approvals_root in created
    pending = [item for item in created if item.name.startswith(TEMPORARY_DIRECTORY_PREFIX)]
    assert len(pending) == 1
    assert pending[0].parent == approvals_root
    # Exactly one final directory and exactly one fixed file.
    assert sorted(item.name for item in approvals_root.iterdir()) == [artifact.approval_artifact_id]
    assert sorted(item.name for item in artifact_directory(root, artifact).iterdir()) == [
        APPROVED_CHANGE_APPROVAL_FILENAME
    ]


def test_the_source_bundle_is_never_written_renamed_or_refreshed(tmp_path, fs_recorder):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    artifact = artifact_for(bundle, root)
    bundle_root = root / APPROVED_CHANGE_ARTIFACTS_DIRNAME
    before = snapshot(bundle_root)
    fs_recorder.calls.clear()

    publish_artifact(artifact, root)
    load_persisted_approved_change_approval_artifact(artifact.approval_artifact_id, data_dir=root)
    assert snapshot(bundle_root) == before
    assert not [path for path in fs_recorder.write_paths() if str(bundle_root) in path]


# --------------------------------------------------------------------------
# Immutability and structured failures
# --------------------------------------------------------------------------


def test_every_public_object_is_frozen(published_a):
    root, _, artifact = published_a
    built = build_approved_change_approval_artifact(workflow_for(bundle_b(), root))
    validation = validate_approved_change_approval_artifact(artifact)
    publication = publish_artifact(artifact, root)
    loaded = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    for model, field, value in (
        (artifact, "subject_sha256", NOT_A_HASH),
        (built, "status", "approval_artifact_construction_blocked"),
        (validation, "artifact_valid", False),
        (publication, "overwrite_performed", True),
        (loaded, "status", "persisted_approval_artifact_invalid"),
    ):
        with pytest.raises(ValidationError):
            setattr(model, field, value)


def test_result_collections_are_immutable_tuples(published_a):
    root, _, artifact = published_a
    result = publish_artifact(artifact, root)
    assert isinstance(result.errors, tuple)
    assert isinstance(result.warnings, tuple)
    with pytest.raises(TypeError):
        result.warnings[0] = "rewritten"


def test_failure_errors_are_sorted_deduplicated_and_leak_nothing(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    outcomes = [
        publish_artifact(artifact, root, confirmation="nope"),
        publish_artifact(artifact, tmp_path / "absent"),
        load_persisted_approved_change_approval_artifact("latest", data_dir=root),
        load_persisted_approved_change_approval_artifact(
            artifact.approval_artifact_id, data_dir=root
        ),
    ]
    for result in outcomes:
        assert list(result.errors) == sorted(set(result.errors))
        payload = result.model_dump(mode="json")
        payload.pop("artifact", None)
        payload.pop("artifact_validation", None)
        rendered = json.dumps(payload)
        assert "Traceback" not in rendered
        assert str(tmp_path) not in rendered


def test_statuses_are_the_maintained_sets(published_a):
    root, _, artifact = published_a
    assert publish_artifact(artifact, root).status in PUBLICATION_STATUSES
    assert (
        load_persisted_approved_change_approval_artifact(
            artifact.approval_artifact_id, data_dir=root
        ).status
        in LOAD_STATUSES
    )
    assert REQUIRED_APPROVAL_WORKFLOW_STATUS in APPROVAL_WORKFLOW_STATUSES
    assert set(BUILD_STATUSES) & set(VALIDATION_STATUSES) == set()


# --------------------------------------------------------------------------
# Static source guards
# --------------------------------------------------------------------------


def module_tree_without_docstrings(module):
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
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


def module_code_without_strings(module):
    tree = module_tree_without_docstrings(module)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            node.value = ""
    return ast.unparse(tree)


def test_static_the_artifact_module_reaches_no_boundary_at_all():
    source = module_code_without_strings(artifact_module)
    for token in (
        "open(",
        "os.",
        "pathlib",
        "Path(",
        "mkdir",
        "makedirs",
        "write_bytes",
        "write_text",
        "read_bytes",
        "read_text",
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


def test_static_the_artifact_module_adds_no_capability_receipt_preflight_or_cli_surface():
    for module in (artifact_module, persistence):
        source = module_code_without_strings(module)
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
            "publish_approved_change_artifact_bundle",
        ):
            assert token not in source, (module.__name__, token)


def test_static_the_persistence_module_reaches_no_shell_network_or_model_surface():
    source = module_code_without_strings(persistence)
    for token in (
        "subprocess",
        "system(",
        "popen",
        "socket",
        "shutil",
        "rmtree",
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
        "now(",
        "utcnow",
        "today",
        "monotonic",
        "glob",
        "walk(",
        "rmtree",
    ):
        assert token not in source, token


def test_static_no_replace_capable_primitive_appears():
    source = module_code_without_strings(persistence)
    for token in (
        "os.replace",
        "os.rename",
        "Path.replace",
        "Path.rename",
        "shutil.move",
        ".replace(",
        ".rename(",
    ):
        assert token not in source, token


def test_static_the_artifact_module_import_set_is_exactly_the_maintained_dependencies():
    tree = ast.parse(Path(artifact_module.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    assert imported == {
        "__future__",
        "hashlib",
        "hmac",
        "json",
        "pydantic",
        "shellforgeai.core.approved_change_approval_workflow",
        "shellforgeai.core.approved_change_artifact_bundle",
        "shellforgeai.core.approved_change_contract",
        "typing",
    }


def test_static_the_persistence_module_import_set_is_narrow():
    tree = ast.parse(Path(persistence.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    assert imported == {
        "__future__",
        "ctypes",
        "dataclasses",
        "hashlib",
        "hmac",
        "json",
        "os",
        "pathlib",
        "platform",
        "pydantic",
        "re",
        "secrets",
        "shellforgeai.core.approved_change_approval_artifact",
        "shellforgeai.core.approved_change_artifact_bundle",
        "shellforgeai.core.approved_change_artifact_persistence",
        "shellforgeai.core.approved_change_contract",
        "stat",
        "sys",
        "typing",
    }


def test_no_legacy_proposal_type_is_named_or_imported():
    for module in (artifact_module, persistence):
        tree = module_tree_without_docstrings(module)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module != "shellforgeai.core.approvals"
                assert "Proposal" not in {alias.name for alias in node.names}
            if isinstance(node, ast.Name):
                assert node.id != "Proposal"
        source = module_code_without_strings(module)
        for token in ("Proposal", "core.approvals", "approve_proposal", "fingerprint"):
            assert token not in source, (module.__name__, token)


def test_signatures_never_take_or_return_legacy_approval_types():
    for module in (artifact_module, persistence):
        for _, obj in inspect.getmembers(module, inspect.isfunction):
            signature = inspect.signature(obj)
            assert all(param.annotation is not Proposal for param in signature.parameters.values())
            assert "Proposal" not in str(signature)


def test_public_surfaces_are_exactly_the_maintained_operations():
    artifact_public = sorted(
        name
        for name, obj in inspect.getmembers(artifact_module, inspect.isfunction)
        if not name.startswith("_") and obj.__module__ == artifact_module.__name__
    )
    assert artifact_public == [
        "build_approved_change_approval_artifact",
        "canonical_approval_artifact_json",
        "canonical_approval_artifact_payload",
        "compute_approval_artifact_identity_sha256",
        "derive_approval_artifact_id",
        "validate_approved_change_approval_artifact",
    ]
    persistence_public = sorted(
        name
        for name, obj in inspect.getmembers(persistence, inspect.isfunction)
        if not name.startswith("_") and obj.__module__ == persistence.__name__
    )
    assert persistence_public == [
        "atomic_no_replace_approval_directory_publish",
        "load_persisted_approved_change_approval_artifact",
        "publish_approved_change_approval_artifact",
    ]


def test_the_modules_expose_no_cli_registry_or_mutable_state_surface():
    for module in (artifact_module, persistence):
        for name in (
            "app",
            "cli",
            "main",
            "register",
            "REGISTRY",
            "revoke_approval",
            "cancel_approval",
            "expire_approval",
            "supersede_approval",
            "delete_approval",
            "update_approval",
            "set_approval_status",
            "list_approvals",
            "find_latest_approval",
        ):
            assert not hasattr(module, name), (module.__name__, name)


def test_the_modules_are_not_imported_by_cli_approvals_recipes_or_execution():
    permitted = {
        "approved_change_approval_artifact.py",
        "approved_change_approval_persistence.py",
    }
    roots = [Path("src/shellforgeai/cli"), Path("src/shellforgeai/core")]
    for target in ("approved_change_approval_artifact", "approved_change_approval_persistence"):
        offenders = []
        for base in roots:
            for path in base.rglob("*.py"):
                if path.name in permitted:
                    continue
                if target in path.read_text(encoding="utf-8"):
                    offenders.append(str(path))
        assert offenders == [], (target, offenders)


def test_fixed_layout_literals_are_module_constants():
    source = ast.unparse(module_tree_without_docstrings(persistence))
    assert "'approved_change_approvals'" in source
    assert "'.pending-'" in source
    assert APPROVED_CHANGE_APPROVALS_DIRNAME == "approved_change_approvals"
    assert TEMPORARY_DIRECTORY_PREFIX == ".pending-"
    # The filename and the artifact-ID prefix stay in the pure artifact module.
    assert f"'{APPROVED_CHANGE_APPROVAL_FILENAME}'" not in source
    assert f"'{APPROVAL_ARTIFACT_ID_PREFIX}'" not in source
    assert persistence.APPROVED_CHANGE_APPROVAL_FILENAME is APPROVED_CHANGE_APPROVAL_FILENAME
    assert persistence.APPROVAL_ARTIFACT_ID_PREFIX is APPROVAL_ARTIFACT_ID_PREFIX


def test_maintained_identifiers_are_taken_from_the_upstream_modules():
    assert artifact_module.BUNDLE_ID_PREFIX is BUNDLE_ID_PREFIX
    assert artifact_module.APPROVAL_SCOPE_EXACT_SUBJECT_ONLY is APPROVAL_SCOPE_EXACT_SUBJECT_ONLY
    source = ast.unparse(module_tree_without_docstrings(artifact_module))
    assert "'acb_'" not in source
    assert "'exact_subject_only'" not in source
    assert persistence._ARTIFACT_ID_RE.pattern == (
        rf"^{APPROVAL_ARTIFACT_ID_PREFIX}[0-9a-f]{{64}}$"
    )


# --------------------------------------------------------------------------
# Documentation and validation-matrix contract
# --------------------------------------------------------------------------


def test_the_persistence_documentation_records_the_fixed_contract():
    document = Path("docs/APPROVED_CHANGE_APPROVAL_ARTIFACT_PERSISTENCE.md").read_text(
        encoding="utf-8"
    )
    for phrase in (
        "approved_change_approvals",
        APPROVED_CHANGE_APPROVAL_FILENAME,
        "aca_",
        "confirm_approval_artifact_identity_sha256",
        "build_approved_change_approval_artifact",
        "validate_approved_change_approval_artifact",
        "publish_approved_change_approval_artifact",
        "load_persisted_approved_change_approval_artifact",
        "approval_artifact_published",
        "approval_artifact_already_present",
        "published_verification_failed",
        "atomic_publication_unsupported",
        "persisted_approval_artifact_loaded",
        "RENAME_NOREPLACE",
        "MoveFileExW",
        str(persistence.MAX_PERSISTED_APPROVAL_FILE_BYTES),
        "self-asserted",
        "no overwrite",
        "no revocation",
        "no execution eligibility",
        "PR320",
    ):
        assert phrase in document, phrase


def test_the_validation_matrix_maps_both_modules_to_this_suite():
    matrix = json.loads(Path("scripts/validation_matrix.json").read_text(encoding="utf-8"))
    for module_path in (
        "src/shellforgeai/core/approved_change_approval_artifact.py",
        "src/shellforgeai/core/approved_change_approval_persistence.py",
    ):
        rules = [rule for rule in matrix["rules"] if rule["pattern"] == module_path]
        assert len(rules) == 1, module_path
        assert (
            "tests/test_pr319_approved_change_approval_artifact_persistence.py" in rules[0]["tests"]
        )
    document = Path("docs/VALIDATION_MATRIX.md").read_text(encoding="utf-8")
    assert "approved_change_approval_artifact.py" in document
    assert "approved_change_approval_persistence.py" in document
    assert "test_pr319_approved_change_approval_artifact_persistence" in document


def test_roadmap_safety_architecture_and_data_layout_record_the_pr319_boundary():
    roadmap = Path("docs/roadmap.md").read_text(encoding="utf-8")
    assert "PR319" in roadmap
    assert "APPROVED_CHANGE_APPROVAL_ARTIFACT_PERSISTENCE.md" in roadmap
    assert "Stage B is not complete" in roadmap

    safety = Path("docs/safety.md").read_text(encoding="utf-8")
    assert "PR319" in safety
    assert "approved_change_approvals" in safety

    architecture = Path("docs/architecture.md").read_text(encoding="utf-8")
    assert "approved_change_approval_artifact.py" in architecture
    assert "approved_change_approval_persistence.py" in architecture

    layout = Path("docs/data-layout.md").read_text(encoding="utf-8")
    assert "approved_change_approvals/aca_" in layout
    assert APPROVED_CHANGE_APPROVAL_FILENAME in layout


def test_no_cli_surface_was_added():
    cli = Path("docs/cli.md").read_text(encoding="utf-8")
    assert "approved_change_approvals" not in cli
    assert "approval-artifact" not in cli
    offenders = [
        str(path)
        for path in Path("src/shellforgeai/cli").rglob("*.py")
        if "approved_change_approval" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []
