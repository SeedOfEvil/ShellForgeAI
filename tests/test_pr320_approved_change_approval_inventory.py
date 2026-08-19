"""Focused PR320 tests: bounded read-only approved-change approval inventory.

PR309 owns the subject schema, the subject identity, the attestation, the
contract, and approval-binding verification. PR316 owns the reviewed bundle and
its identity. PR317 owns the governed bundle publisher and the exact-ID bundle
loader. PR318 owns the one read-only approval-binding operation. PR319 owns the
canonical approval-artifact bytes, the ``aca_`` artifact identity, the fixed
``approved_change_approvals`` subtree, atomic publication, and the exact-ID
approval-artifact loader.

These tests prove PR320 adds exactly one thing on top of those maintained
contracts: one bounded, deterministic, read-only inventory of the *direct*
children of that fixed root, which validates exact ``aca_`` candidates only
through the maintained PR319 loader, returns immutable summaries sorted only by
exact artifact ID, and reports every other direct child as an explicit anomaly.

Inventory is discovery, not selection. It resolves no ``latest``, ``current``,
or "most recent" approval, orders by nothing but the artifact ID, writes
nothing, repairs nothing, creates no index or pointer, authenticates nobody,
evaluates and binds no capability, runs no preflight, creates or links no
receipt, and grants no execution eligibility.
"""

from __future__ import annotations

import ast
import builtins
import inspect
import json
import os
import platform
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

# The PR319 focused suite owns the maintained approval-artifact fixtures and
# publication helpers. They are reused verbatim so PR320 never invents its own
# bundle, subject, approval, or artifact schema.
from test_pr319_approved_change_approval_artifact_persistence import (  # noqa: E402
    APPROVED_AT,
    APPROVED_BY,
    FIXTURE_A_APPROVAL_ARTIFACT_BYTE_LENGTH,
    FIXTURE_A_APPROVAL_ARTIFACT_ID,
    FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256,
    approve,
    artifact_for,
    bundle_a,
    bundle_b,
    data_dir,
    publication_root,
    publish_artifact,
    publish_bundle,
    snapshot,
    workflow_for,
    write_artifact_directory,
)

from shellforgeai.core import approved_change_approval_inventory as inventory_module
from shellforgeai.core.approvals import Proposal
from shellforgeai.core.approved_change_approval_artifact import (
    APPROVAL_ARTIFACT_ID_PREFIX,
    APPROVED_CHANGE_APPROVAL_FILENAME,
    PERMANENT_APPROVAL_ARTIFACT_WARNINGS,
    build_approved_change_approval_artifact,
    canonical_approval_artifact_json,
)
from shellforgeai.core.approved_change_approval_inventory import (
    INVENTORY_ANOMALY_CATEGORIES,
    INVENTORY_STATUSES,
    MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES,
    PERMANENT_APPROVAL_INVENTORY_WARNINGS,
    REQUIRED_APPROVAL_ARTIFACT_LOAD_STATUS,
    ApprovedChangeApprovalArtifactInventoryAnomaly,
    ApprovedChangeApprovalArtifactInventoryEntry,
    ApprovedChangeApprovalArtifactInventoryResult,
    inventory_persisted_approved_change_approval_artifacts,
)
from shellforgeai.core.approved_change_approval_persistence import (
    APPROVED_CHANGE_APPROVALS_DIRNAME,
    LOAD_STATUSES,
    load_persisted_approved_change_approval_artifact,
)
from shellforgeai.core.approved_change_artifact_persistence import (
    APPROVED_CHANGE_ARTIFACTS_DIRNAME,
)
from shellforgeai.core.approved_change_contract import APPROVAL_SCOPE_EXACT_SUBJECT_ONLY

WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="Windows-only native behaviour")
POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX-only native behaviour")

HEX64 = "0123456789abcdef" * 4
OTHER_HEX64 = "fedcba9876543210" * 4
EXACT_UNPUBLISHED_ID = f"{APPROVAL_ARTIFACT_ID_PREFIX}{HEX64}"

# --------------------------------------------------------------------------
# Committed fixed-fixture inventory values
#
# These are the exact expected inventory summaries for the two maintained
# fixtures. They are recorded here so any ordering, canonicalization, schema,
# or metadata drift fails loudly on either platform instead of silently
# changing what discovery reports.
# --------------------------------------------------------------------------

FIXTURE_B_APPROVAL_ARTIFACT_IDENTITY_SHA256 = (
    "4825749622d0dbf3bfbd705f2203b895f1c03c60adf45b659f922781c6722c8e"
)
FIXTURE_B_APPROVAL_ARTIFACT_ID = (
    f"{APPROVAL_ARTIFACT_ID_PREFIX}{FIXTURE_B_APPROVAL_ARTIFACT_IDENTITY_SHA256}"
)
FIXTURE_B_APPROVAL_ARTIFACT_BYTE_LENGTH = 2617

#: The one expected order: lexicographic by exact artifact ID. Fixture B is
#: published *second* below and still sorts first, so creation order, mtime
#: order, and approval order can never be what is being reported.
EXPECTED_FIXTURE_ORDER = (FIXTURE_B_APPROVAL_ARTIFACT_ID, FIXTURE_A_APPROVAL_ARTIFACT_ID)

EXPECTED_APPROVED_AT = "2026-07-27T09:00:00Z"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def inventory(root):
    return inventory_persisted_approved_change_approval_artifacts(data_dir=root)


def require_symlinks(tmp_path: Path) -> None:
    probe = tmp_path / "symlink-probe"
    target = tmp_path / "symlink-target"
    target.mkdir()
    try:
        probe.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("this platform does not permit unprivileged symlink creation")
    probe.unlink()
    target.rmdir()


def published_pair(tmp_path):
    """Publish fixture B *after* fixture A even though B sorts first."""
    root = data_dir(tmp_path)
    artifact_a = artifact_for(bundle_a(), root)
    assert publish_artifact(artifact_a, root).status == "approval_artifact_published"
    artifact_b = artifact_for(bundle_b(), root)
    assert publish_artifact(artifact_b, root).status == "approval_artifact_published"
    return root, artifact_a, artifact_b


def orphan_artifact(tmp_path, *, bundle=None, label="staging"):
    """Build one valid artifact whose PR317 source bundle lives somewhere else.

    The bundle must exist for the maintained PR318 operation to run at all, so
    it is published into a throwaway data root. The resulting artifact is
    therefore an orphan wherever else it is materialised.
    """
    staging = tmp_path / label
    staging.mkdir()
    built = build_approved_change_approval_artifact(workflow_for(bundle or bundle_a(), staging))
    assert built.status == "approval_artifact_constructed", built.errors
    return built.artifact


def artifact_with_present_bundle(root, bundle):
    """Build one valid artifact whose exact source bundle is present in ``root``."""
    built = build_approved_change_approval_artifact(workflow_for(bundle, root))
    assert built.status == "approval_artifact_constructed", built.errors
    return built.artifact


def entry_names(result) -> list[str]:
    return [entry.approval_artifact_id for entry in result.entries]


def anomaly_pairs(result) -> list[tuple[str, str]]:
    return [(item.entry_name, item.category) for item in result.anomalies]


def assert_never_expands(result) -> None:
    """The fields PR320 may never claim, on any status whatsoever."""
    assert result.read_only is True
    assert result.mutation_performed is False
    assert result.artifact_write_performed is False
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.inventory_index_written is False
    assert result.approval_selected is False
    assert result.approval_created is False
    assert result.approval_persisted is False
    assert result.contract_created is False
    assert result.contract_persisted is False
    assert result.source_bundle_mutation_performed is False
    assert result.overwrite_performed is False
    assert result.authorization_evaluated is False
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert result.capability_bound is False
    assert result.preflight_evaluated is False
    assert result.receipt_created is False
    assert result.receipt_linked is False
    assert result.host_configuration_mutation_performed is False
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"
    assert result.warnings == PERMANENT_APPROVAL_INVENTORY_WARNINGS
    assert result.status in INVENTORY_STATUSES
    assert list(result.errors) == sorted(set(result.errors))
    assert "Traceback" not in " ".join(result.errors)
    for anomaly in result.anomalies:
        assert anomaly.category in INVENTORY_ANOMALY_CATEGORIES
        assert list(anomaly.errors) == sorted(set(anomaly.errors))
        assert "Traceback" not in " ".join(anomaly.errors)


def path_spellings(value) -> set[str]:
    """Every spelling one absolute path can take in reported text.

    ``OSError.__str__`` embeds ``repr(filename)``, which doubles backslashes;
    Windows also accepts ``/`` separators, extended-length prefixes, and
    case-varied spellings. All of them must be absent from public output.
    """
    base = str(value)
    forms = {base, base.replace("\\", "/"), base.replace("/", "\\")}
    for form in tuple(forms):
        forms.add(form.replace("\\", "\\\\"))
        forms.add("\\\\?\\" + form)
        forms.add(form.upper())
        forms.add(form.lower())
    return {form for form in forms if form}


def assert_no_host_paths(result, root: Path) -> None:
    markers = {str(root), str(root.parent), str(Path(root).resolve())}
    blob = result.model_dump_json()
    for marker in markers:
        assert marker not in blob, marker


def assert_path_free(result, root: Path, *extra) -> None:
    """Prove no spelling of any host absolute path survives into the result."""
    blob = result.model_dump_json()
    candidates = [root, root.parent, Path(root).resolve(), *extra]
    for candidate in candidates:
        for spelling in path_spellings(candidate):
            assert spelling not in blob, spelling


def assert_blocked(result, root: Path | None = None) -> None:
    assert result.status in {
        "approval_artifact_inventory_blocked",
        "approval_artifact_inventory_limit_exceeded",
        "invalid_inventory_input",
    }
    assert result.inventory_complete is False
    assert result.entries == ()
    assert result.valid_entry_count == 0
    assert result.errors
    assert_never_expands(result)
    if root is not None:
        assert_no_host_paths(result, root)


# --------------------------------------------------------------------------
# Empty inventory
# --------------------------------------------------------------------------


def test_an_absent_approval_root_is_one_complete_empty_inventory(tmp_path):
    root = data_dir(tmp_path)
    before = snapshot(root)
    result = inventory(root)
    assert result.status == "approval_artifact_inventory_empty"
    assert result.inventory_complete is True
    assert result.inventory_root_present is False
    assert result.scanned_entry_count == 0
    assert result.valid_entry_count == 0
    assert result.anomaly_count == 0
    assert result.entries == ()
    assert result.anomalies == ()
    assert result.errors == ()
    # The explicit data root was inspected, so the ledger says so truthfully.
    assert result.filesystem_accessed is True
    assert result.inventory_performed is True
    assert_never_expands(result)
    # The missing root is never created.
    assert not publication_root(root).exists()
    assert snapshot(root) == before


def test_an_empty_approval_root_is_one_complete_empty_inventory(tmp_path):
    root = data_dir(tmp_path)
    publication_root(root).mkdir()
    before = snapshot(root)
    result = inventory(root)
    assert result.status == "approval_artifact_inventory_empty"
    assert result.inventory_complete is True
    assert result.inventory_root_present is True
    assert result.scanned_entry_count == 0
    assert result.entries == ()
    assert result.anomalies == ()
    assert result.filesystem_accessed is True
    assert result.inventory_performed is True
    assert_never_expands(result)
    assert snapshot(root) == before


def test_an_empty_inventory_creates_no_subtree_at_all(tmp_path):
    root = data_dir(tmp_path)
    inventory(root)
    assert sorted(item.name for item in root.iterdir()) == []


# --------------------------------------------------------------------------
# One valid artifact
# --------------------------------------------------------------------------


def test_one_published_artifact_is_summarised_exactly(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    assert publish_artifact(artifact, root).status == "approval_artifact_published"
    before = snapshot(root)

    result = inventory(root)
    assert result.status == "approval_artifact_inventory_loaded"
    assert result.inventory_complete is True
    assert result.inventory_root_present is True
    assert result.scanned_entry_count == 1
    assert result.valid_entry_count == 1
    assert result.anomaly_count == 0
    assert result.anomalies == ()
    assert result.relative_inventory_root == APPROVED_CHANGE_APPROVALS_DIRNAME
    assert result.max_inventory_entries == MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES
    assert_never_expands(result)
    assert_no_host_paths(result, root)

    (entry,) = result.entries
    assert entry.approval_artifact_id == FIXTURE_A_APPROVAL_ARTIFACT_ID
    assert entry.approval_artifact_identity_sha256 == FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256
    assert entry.artifact_byte_length == FIXTURE_A_APPROVAL_ARTIFACT_BYTE_LENGTH
    assert entry.source_bundle_id == artifact.source_bundle_id
    assert entry.source_bundle_identity_sha256 == artifact.source_bundle_identity_sha256
    assert entry.subject_sha256 == artifact.subject_sha256
    assert entry.approved_by == APPROVED_BY
    assert entry.approved_at == EXPECTED_APPROVED_AT
    assert entry.approval_scope == APPROVAL_SCOPE_EXACT_SUBJECT_ONLY
    assert entry.approval_binding_valid is True

    # Nothing was touched.
    assert snapshot(root) == before


def test_the_summary_never_carries_the_approval_reason_or_the_contract(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    (entry,) = inventory(root).entries

    reason = artifact.contract.approval.reason
    assert reason
    payload = entry.model_dump()
    assert reason not in json.dumps(payload)
    assert "reason" not in payload
    assert "contract" not in payload
    assert "canonical_content_utf8" not in payload
    for forbidden in ("path", "mtime", "modified", "status", "capability", "receipt", "preflight"):
        assert not [key for key in payload if forbidden in key], forbidden


def test_the_summary_carries_no_filesystem_timestamp(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    directory = publication_root(root) / artifact.approval_artifact_id
    mtimes = {str(directory.stat().st_mtime_ns), str(directory.stat().st_mtime)}

    (entry,) = inventory(root).entries
    blob = entry.model_dump_json()
    for value in mtimes:
        assert value not in blob


# --------------------------------------------------------------------------
# Multiple valid artifacts and deterministic ordering
# --------------------------------------------------------------------------


def test_entries_are_sorted_lexicographically_by_exact_artifact_id(tmp_path):
    root, artifact_a, artifact_b = published_pair(tmp_path)
    result = inventory(root)
    assert result.status == "approval_artifact_inventory_loaded"
    assert result.inventory_complete is True
    assert entry_names(result) == list(EXPECTED_FIXTURE_ORDER)
    assert entry_names(result) == sorted(entry_names(result))
    # Fixture B was published second and still sorts first.
    assert artifact_b.approval_artifact_id == EXPECTED_FIXTURE_ORDER[0]
    assert artifact_a.approval_artifact_id == EXPECTED_FIXTURE_ORDER[1]


def test_the_order_is_independent_of_creation_and_mtime_order(tmp_path):
    forward = tmp_path / "forward"
    reverse = tmp_path / "reverse"
    forward.mkdir()
    reverse.mkdir()

    root_forward = data_dir(forward)
    for maker in (bundle_a, bundle_b):
        publish_artifact(artifact_for(maker(), root_forward), root_forward)

    root_reverse = data_dir(reverse)
    for maker in (bundle_b, bundle_a):
        publish_artifact(artifact_for(maker(), root_reverse), root_reverse)

    # Push the lexicographically-first artifact to the newest mtime everywhere.
    for root in (root_forward, root_reverse):
        directory = publication_root(root) / EXPECTED_FIXTURE_ORDER[0]
        os.utime(directory, (time.time() + 5_000, time.time() + 5_000))

    assert entry_names(inventory(root_forward)) == list(EXPECTED_FIXTURE_ORDER)
    assert entry_names(inventory(root_reverse)) == list(EXPECTED_FIXTURE_ORDER)


def test_the_order_is_independent_of_filesystem_enumeration_order(tmp_path, monkeypatch):
    root, _, _ = published_pair(tmp_path)
    real_listdir = os.listdir

    def shuffled(path, *args, **kwargs):
        names = real_listdir(path, *args, **kwargs)
        return list(reversed(sorted(names)))

    monkeypatch.setattr(os, "listdir", shuffled)
    assert entry_names(inventory(root)) == list(EXPECTED_FIXTURE_ORDER)


def test_repeated_inventories_are_model_dump_identical(tmp_path):
    root, _, _ = published_pair(tmp_path)
    first = inventory(root)
    second = inventory(root)
    assert first.model_dump_json() == second.model_dump_json()
    assert first.model_dump() == second.model_dump()


#: Fixed candidate approval instants. One of these pairs necessarily orders by
#: approval time differently from how it orders by artifact ID, because the
#: artifact identity is a hash of the whole approval payload.
CANDIDATE_APPROVAL_TIMES = tuple(
    datetime(2026, 7, 27, 9, 0, second, tzinfo=APPROVED_AT.tzinfo) for second in range(1, 9)
)


def test_approval_time_is_never_the_ordering_key(tmp_path):
    """Two artifacts whose ID order disagrees with their approval-time order."""
    chosen = None
    for index, later in enumerate(CANDIDATE_APPROVAL_TIMES):
        probe = tmp_path / f"probe-{index}"
        probe.mkdir()
        root = data_dir(probe)
        bundle = bundle_a()
        publish_bundle(bundle, root)
        early = build_approved_change_approval_artifact(
            approve(bundle, root, approved_at=APPROVED_AT)
        ).artifact
        late = build_approved_change_approval_artifact(
            approve(bundle, root, approved_at=later)
        ).artifact
        if late.approval_artifact_id < early.approval_artifact_id:
            chosen = (root, early, late)
            break
    assert chosen is not None, "no candidate approval instant inverted the ID order"

    root, early, late = chosen
    assert publish_artifact(early, root).status == "approval_artifact_published"
    assert publish_artifact(late, root).status == "approval_artifact_published"

    result = inventory(root)
    assert result.status == "approval_artifact_inventory_loaded"
    # The later-approved artifact is reported first purely because its exact
    # artifact ID sorts first. Nothing chronological is happening.
    assert entry_names(result) == [late.approval_artifact_id, early.approval_artifact_id]
    assert entry_names(result) == sorted(entry_names(result))
    assert result.entries[0].approved_at > result.entries[1].approved_at


# --------------------------------------------------------------------------
# Cross-platform deterministic inventory
# --------------------------------------------------------------------------


def test_the_fixed_fixture_inventory_is_exactly_the_committed_summaries(tmp_path):
    """Identical persisted artifacts must inventory identically everywhere."""
    root, _, _ = published_pair(tmp_path)
    result = inventory(root)

    assert result.status == "approval_artifact_inventory_loaded"
    assert result.inventory_complete is True
    assert result.inventory_root_present is True
    assert result.scanned_entry_count == 2
    assert result.valid_entry_count == 2
    assert result.anomaly_count == 0
    assert result.errors == ()
    assert result.warnings == PERMANENT_APPROVAL_INVENTORY_WARNINGS

    first, second = result.entries
    assert first.approval_artifact_id == FIXTURE_B_APPROVAL_ARTIFACT_ID
    assert first.approval_artifact_identity_sha256 == FIXTURE_B_APPROVAL_ARTIFACT_IDENTITY_SHA256
    assert first.artifact_byte_length == FIXTURE_B_APPROVAL_ARTIFACT_BYTE_LENGTH
    assert second.approval_artifact_id == FIXTURE_A_APPROVAL_ARTIFACT_ID
    assert second.approval_artifact_identity_sha256 == FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256
    assert second.artifact_byte_length == FIXTURE_A_APPROVAL_ARTIFACT_BYTE_LENGTH

    for entry in result.entries:
        assert entry.approved_by == APPROVED_BY
        assert entry.approved_at == EXPECTED_APPROVED_AT
        assert entry.approval_scope == APPROVAL_SCOPE_EXACT_SUBJECT_ONLY
        assert entry.approval_binding_valid is True
        assert entry.source_bundle_id.startswith("acb_")
        assert len(entry.source_bundle_identity_sha256) == 64
        assert len(entry.subject_sha256) == 64

    assert {entry.source_bundle_id for entry in result.entries} == {
        f"acb_{first.source_bundle_identity_sha256}",
        f"acb_{second.source_bundle_identity_sha256}",
    }
    # No platform-dependent path spelling reaches any reported entry.
    for entry in result.entries:
        assert "\\" not in entry.model_dump_json()
        assert "/" not in entry.model_dump_json()


def test_the_approval_timestamp_is_the_maintained_canonical_utc_spelling(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    (entry,) = inventory(root).entries
    canonical = json.loads(canonical_approval_artifact_json(artifact))
    assert entry.approved_at == canonical["contract"]["approval"]["approved_at"]
    assert entry.approved_at.endswith("Z")


# --------------------------------------------------------------------------
# Unexpected names
# --------------------------------------------------------------------------

#: Every semantic unexpected-name case PR320 must report. Two of these differ
#: only by case, which is a genuine product case on POSIX but a single directory
#: entry on Windows, so the tuple is never materialised as-is: it is partitioned
#: below into groups that are unique under the active filesystem's own
#: case-normalization rules, and every name is additionally exercised alone.
UNEXPECTED_NAMES = (
    "latest",
    "current",
    "most-recent",
    "aca_short",
    f"ACA_{OTHER_HEX64}",
    f"{APPROVAL_ARTIFACT_ID_PREFIX}{OTHER_HEX64.upper()}",
    f"{APPROVAL_ARTIFACT_ID_PREFIX}{HEX64}extra",
    "random",
    ".pending-deadbeefdeadbeef",
    "index.json",
)


def partition_case_safe(names):
    """Split ``names`` into groups co-creatable in one directory on this platform.

    ``os.path.normcase`` is identity on POSIX and case-folding on Windows, so a
    POSIX run gets exactly one group holding every name while a Windows run
    splits case-only collisions into separate groups. No name is ever dropped.
    """
    groups: list[list[str]] = []
    for name in names:
        key = os.path.normcase(name)
        for group in groups:
            if key not in {os.path.normcase(item) for item in group}:
                group.append(name)
                break
        else:
            groups.append([name])
    return tuple(tuple(group) for group in groups)


UNEXPECTED_NAME_GROUPS = partition_case_safe(UNEXPECTED_NAMES)
GROUP_IDS = [f"group{index}" for index in range(len(UNEXPECTED_NAME_GROUPS))]
NAME_IDS = [f"name{index}" for index in range(len(UNEXPECTED_NAMES))]


def test_the_case_safe_partition_preserves_every_unexpected_name():
    flattened = [name for group in UNEXPECTED_NAME_GROUPS for name in group]
    assert sorted(flattened) == sorted(UNEXPECTED_NAMES)
    assert len(flattened) == len(set(flattened))
    # No group can collide with itself on this platform's filesystem.
    for group in UNEXPECTED_NAME_GROUPS:
        keys = [os.path.normcase(name) for name in group]
        assert len(keys) == len(set(keys)), group
    # The case-only variants are real, distinct product cases either way.
    assert f"ACA_{OTHER_HEX64}" in flattened
    assert f"{APPROVAL_ARTIFACT_ID_PREFIX}{OTHER_HEX64.upper()}" in flattened
    if os.path.normcase("A") != "A":
        assert len(UNEXPECTED_NAME_GROUPS) > 1
    else:
        assert len(UNEXPECTED_NAME_GROUPS) == 1


@pytest.mark.parametrize("names", UNEXPECTED_NAME_GROUPS, ids=GROUP_IDS)
def test_every_unexpected_direct_child_is_an_explicit_anomaly(tmp_path, names):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    base = publication_root(root)
    for name in names:
        (base / name).mkdir()
        (base / name / "payload.json").write_text("{}", encoding="utf-8")
    before = snapshot(root)

    result = inventory(root)
    assert result.status == "approval_artifact_inventory_loaded_with_anomalies"
    assert result.inventory_complete is False
    assert result.scanned_entry_count == 1 + len(names)
    assert result.valid_entry_count == 1
    assert result.anomaly_count == len(names)
    assert entry_names(result) == [FIXTURE_A_APPROVAL_ARTIFACT_ID]
    assert anomaly_pairs(result) == sorted((name, "unexpected_name") for name in names)
    for anomaly in result.anomalies:
        assert anomaly.entry_name in names
        assert "/" not in anomaly.entry_name and "\\" not in anomaly.entry_name
        assert anomaly.loader_status == ""
    assert_never_expands(result)
    assert_no_host_paths(result, root)
    assert snapshot(root) == before


@pytest.mark.parametrize("name", UNEXPECTED_NAMES, ids=NAME_IDS)
def test_each_unexpected_name_is_individually_reported(tmp_path, monkeypatch, name):
    """Each name alone in its own data root, so no case collision is possible."""
    root = data_dir(tmp_path)
    base = publication_root(root)
    base.mkdir()
    (base / name).mkdir()
    (base / name / "payload.json").write_text("{}", encoding="utf-8")

    seen: list[str] = []
    real_listdir = os.listdir

    def recorded(path, *args, **kwargs):
        seen.append(str(path))
        return real_listdir(path, *args, **kwargs)

    def refusing_loader(artifact_id, *, data_dir):
        raise AssertionError("the loader must never see a malformed name")

    monkeypatch.setattr(os, "listdir", recorded)
    monkeypatch.setattr(
        inventory_module, "load_persisted_approved_change_approval_artifact", refusing_loader
    )
    result = inventory(root)

    assert anomaly_pairs(result) == [(name, "unexpected_name")]
    assert result.entries == ()
    assert result.valid_entry_count == 0
    assert result.inventory_complete is False
    # Never followed and never recursed into: only the fixed root is enumerated.
    assert seen == [str(base)]
    assert_never_expands(result)


def test_an_unexpected_child_is_never_recursed_into(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    base = publication_root(root)
    nest = base / "latest" / "aca_nested" / "deeper"
    nest.mkdir(parents=True)
    seen: list[str] = []
    real_listdir = os.listdir

    def recorded(path, *args, **kwargs):
        seen.append(str(path))
        return real_listdir(path, *args, **kwargs)

    monkeypatch.setattr(os, "listdir", recorded)
    result = inventory(root)
    assert anomaly_pairs(result) == [("latest", "unexpected_name")]
    assert seen == [str(base)]


@pytest.mark.parametrize("names", UNEXPECTED_NAME_GROUPS, ids=GROUP_IDS)
def test_a_malformed_name_is_never_offered_to_the_loader(tmp_path, monkeypatch, names):
    root = data_dir(tmp_path)
    base = publication_root(root)
    base.mkdir()
    for name in names:
        (base / name).mkdir()

    calls: list[str] = []

    def recording_loader(artifact_id, *, data_dir):
        calls.append(artifact_id)
        raise AssertionError("the loader must never see a malformed name")

    monkeypatch.setattr(
        inventory_module, "load_persisted_approved_change_approval_artifact", recording_loader
    )
    result = inventory(root)
    assert calls == []
    assert result.anomaly_count == len(names)


# --------------------------------------------------------------------------
# Unsafe direct children
# --------------------------------------------------------------------------


def test_a_symlinked_exact_id_child_is_reported_and_never_followed(tmp_path):
    require_symlinks(tmp_path)
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    target = publication_root(root) / artifact.approval_artifact_id
    link = publication_root(root) / EXACT_UNPUBLISHED_ID
    link.symlink_to(target, target_is_directory=True)

    result = inventory(root)
    assert result.status == "approval_artifact_inventory_loaded_with_anomalies"
    assert result.inventory_complete is False
    assert entry_names(result) == [FIXTURE_A_APPROVAL_ARTIFACT_ID]
    assert anomaly_pairs(result) == [(EXACT_UNPUBLISHED_ID, "symlink_or_reparse_entry")]
    assert_never_expands(result)


def test_a_dangling_symlink_child_is_reported_and_never_followed(tmp_path):
    require_symlinks(tmp_path)
    root = data_dir(tmp_path)
    base = publication_root(root)
    base.mkdir()
    (base / EXACT_UNPUBLISHED_ID).symlink_to(tmp_path / "nowhere", target_is_directory=True)
    result = inventory(root)
    assert anomaly_pairs(result) == [(EXACT_UNPUBLISHED_ID, "symlink_or_reparse_entry")]
    assert result.entries == ()
    assert result.inventory_complete is False


def test_a_regular_file_with_an_exact_artifact_name_is_a_non_directory_anomaly(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    (publication_root(root) / EXACT_UNPUBLISHED_ID).write_text("{}", encoding="utf-8")

    result = inventory(root)
    assert anomaly_pairs(result) == [(EXACT_UNPUBLISHED_ID, "non_directory_entry")]
    assert entry_names(result) == [FIXTURE_A_APPROVAL_ARTIFACT_ID]
    assert result.inventory_complete is False


@POSIX_ONLY
def test_a_fifo_with_an_exact_artifact_name_is_a_non_directory_anomaly(tmp_path):
    root = data_dir(tmp_path)
    base = publication_root(root)
    base.mkdir()
    try:
        os.mkfifo(base / EXACT_UNPUBLISHED_ID)
    except (AttributeError, OSError):  # pragma: no cover - platform dependent
        pytest.skip("this platform does not support FIFO creation")
    result = inventory(root)
    assert anomaly_pairs(result) == [(EXACT_UNPUBLISHED_ID, "non_directory_entry")]
    assert result.entries == ()


def test_an_uninspectable_child_is_an_explicit_anomaly(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    base = publication_root(root)
    base.mkdir()
    (base / EXACT_UNPUBLISHED_ID).mkdir()
    real_lstat = os.lstat

    def guarded(path, *args, **kwargs):
        if str(path).endswith(EXACT_UNPUBLISHED_ID):
            raise PermissionError(13, "permission denied", str(path))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", guarded)
    result = inventory(root)
    assert anomaly_pairs(result) == [(EXACT_UNPUBLISHED_ID, "entry_not_inspectable")]
    (anomaly,) = result.anomalies
    assert anomaly.errors
    # The injected OSError names an absolute path. PR320 never reports raw
    # exception text, so only the deterministic path-free classification is
    # public — on every platform, whatever the separator spelling.
    reported = " ".join(anomaly.errors)
    assert "PermissionError" in reported
    assert "errno=13" in reported
    assert "permission denied" not in reported
    assert_path_free(result, root, publication_root(root) / EXACT_UNPUBLISHED_ID)


def test_an_exact_id_child_that_disappears_during_validation_is_reported(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    directory = publication_root(root) / artifact.approval_artifact_id
    real_loader = load_persisted_approved_change_approval_artifact

    def vanishing_loader(artifact_id, *, data_dir):
        shutil.rmtree(directory)
        return real_loader(artifact_id, data_dir=data_dir)

    monkeypatch.setattr(
        inventory_module, "load_persisted_approved_change_approval_artifact", vanishing_loader
    )
    result = inventory(root)
    assert result.entries == ()
    assert anomaly_pairs(result) == [(artifact.approval_artifact_id, "entry_disappeared")]
    assert result.inventory_complete is False


def test_an_exact_id_child_that_changes_identity_during_validation_is_reported(
    tmp_path, monkeypatch
):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    directory = publication_root(root) / artifact.approval_artifact_id
    real_loader = load_persisted_approved_change_approval_artifact

    def swapping_loader(artifact_id, *, data_dir):
        loaded = real_loader(artifact_id, data_dir=data_dir)
        moved = directory.parent / "moved-aside"
        os.rename(directory, moved)
        directory.mkdir()
        return loaded

    monkeypatch.setattr(
        inventory_module, "load_persisted_approved_change_approval_artifact", swapping_loader
    )
    result = inventory(root)
    assert result.entries == ()
    assert (artifact.approval_artifact_id, "entry_changed_during_inventory") in anomaly_pairs(
        result
    )
    assert result.inventory_complete is False


def test_an_unsafe_child_is_never_repaired_renamed_or_removed(tmp_path):
    root = data_dir(tmp_path)
    base = publication_root(root)
    base.mkdir()
    (base / "latest").mkdir()
    (base / EXACT_UNPUBLISHED_ID).write_text("{}", encoding="utf-8")
    before = snapshot(root)
    inventory(root)
    assert snapshot(root) == before


# --------------------------------------------------------------------------
# Invalid exact-ID artifacts
# --------------------------------------------------------------------------


def _oversized(payload):
    payload[APPROVED_CHANGE_APPROVAL_FILENAME] = b"{" + b" " * 2_000_000 + b"}"
    return payload


def _tamper(field, value):
    def mutate(payload):
        document = json.loads(payload[APPROVED_CHANGE_APPROVAL_FILENAME])
        node = document
        parts = field.split(".")
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = value
        payload[APPROVED_CHANGE_APPROVAL_FILENAME] = json.dumps(
            document, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return payload

    return mutate


INVALID_ARTIFACT_MUTATIONS = {
    "missing_file": lambda payload: {},
    "extra_file": lambda payload: {**payload, "extra.json": b"{}"},
    "oversized_file": _oversized,
    "malformed_json": lambda payload: {APPROVED_CHANGE_APPROVAL_FILENAME: b"{not json"},
    "noncanonical_json": lambda payload: {
        APPROVED_CHANGE_APPROVAL_FILENAME: json.dumps(
            json.loads(payload[APPROVED_CHANGE_APPROVAL_FILENAME]), indent=2
        ).encode("utf-8")
    },
    "tampered_contract": _tamper("contract.approval.approved_by", "someone-else"),
    "invalid_binding": _tamper("contract.approval.subject_sha256", "0" * 64),
    "source_identity_mismatch": _tamper("source_bundle_identity_sha256", "1" * 64),
    "subject_mismatch": _tamper("subject_sha256", "2" * 64),
}


@pytest.mark.parametrize("label", sorted(INVALID_ARTIFACT_MUTATIONS))
def test_every_invalid_exact_id_artifact_is_an_explicit_anomaly(tmp_path, label):
    root = data_dir(tmp_path)
    good = artifact_for(bundle_a(), root)
    publish_artifact(good, root)
    bad = artifact_with_present_bundle(root, bundle_b())
    write_artifact_directory(root, bad, mutate=INVALID_ARTIFACT_MUTATIONS[label])
    before = snapshot(root)

    result = inventory(root)
    assert result.status == "approval_artifact_inventory_loaded_with_anomalies"
    assert result.inventory_complete is False
    assert entry_names(result) == [good.approval_artifact_id]
    (anomaly,) = result.anomalies
    assert anomaly.entry_name == bad.approval_artifact_id
    assert anomaly.category == "invalid_approval_artifact"
    assert anomaly.loader_status in LOAD_STATUSES
    assert anomaly.loader_status != REQUIRED_APPROVAL_ARTIFACT_LOAD_STATUS
    assert_never_expands(result)
    assert_no_host_paths(result, root)
    assert snapshot(root) == before


def test_a_missing_source_bundle_blocks_the_entry_without_repair(tmp_path):
    root = data_dir(tmp_path)
    good = artifact_for(bundle_a(), root)
    publish_artifact(good, root)
    orphan = orphan_artifact(tmp_path, bundle=bundle_b())
    write_artifact_directory(root, orphan)

    result = inventory(root)
    assert entry_names(result) == [good.approval_artifact_id]
    (anomaly,) = result.anomalies
    assert anomaly.entry_name == orphan.approval_artifact_id
    assert anomaly.category == "invalid_approval_artifact"
    assert anomaly.loader_status != REQUIRED_APPROVAL_ARTIFACT_LOAD_STATUS
    assert result.inventory_complete is False


def test_an_invalid_source_bundle_blocks_the_entry(tmp_path):
    root = data_dir(tmp_path)
    good = artifact_for(bundle_a(), root)
    publish_artifact(good, root)
    other = artifact_for(bundle_b(), root)
    publish_artifact(other, root)
    # Corrupt the second artifact's persisted PR317 source bundle.
    bundle_root = root / APPROVED_CHANGE_ARTIFACTS_DIRNAME / other.source_bundle_id
    victim = sorted(item for item in bundle_root.iterdir() if item.is_file())[0]
    victim.write_bytes(b"corrupted")

    result = inventory(root)
    assert entry_names(result) == [good.approval_artifact_id]
    (anomaly,) = result.anomalies
    assert anomaly.entry_name == other.approval_artifact_id
    assert anomaly.category == "invalid_approval_artifact"
    assert result.inventory_complete is False


def test_valid_neighbours_survive_every_invalid_artifact(tmp_path):
    root, artifact_a, artifact_b = published_pair(tmp_path)
    broken = orphan_artifact(tmp_path, bundle=bundle_a())
    write_artifact_directory(root, broken, name=f"{APPROVAL_ARTIFACT_ID_PREFIX}{OTHER_HEX64}")
    result = inventory(root)
    assert entry_names(result) == list(EXPECTED_FIXTURE_ORDER)
    assert result.valid_entry_count == 2
    assert result.anomaly_count == 1
    assert result.inventory_complete is False


# --------------------------------------------------------------------------
# Root safety
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "candidate",
    ["", "   ", "relative/data", Path("relative/data"), 5, None, b"/data"],
)
def test_a_structurally_invalid_data_root_never_touches_the_filesystem(candidate):
    result = inventory_persisted_approved_change_approval_artifacts(data_dir=candidate)
    assert result.status == "invalid_inventory_input"
    assert result.filesystem_accessed is False
    assert result.inventory_performed is False
    assert result.inventory_root_present is False
    assert_blocked(result)


def test_the_filesystem_root_is_refused():
    result = inventory_persisted_approved_change_approval_artifacts(data_dir=Path(os.sep))
    assert result.status == "invalid_inventory_input"
    assert result.filesystem_accessed is False
    assert_blocked(result)


@WINDOWS_ONLY
def test_a_windows_drive_root_is_refused():  # pragma: no cover - platform dependent
    result = inventory_persisted_approved_change_approval_artifacts(data_dir=Path("C:\\"))
    assert result.status == "invalid_inventory_input"
    assert result.filesystem_accessed is False


def test_a_missing_data_root_is_blocked(tmp_path):
    result = inventory(tmp_path / "absent")
    assert result.status == "approval_artifact_inventory_blocked"
    assert result.filesystem_accessed is True
    assert result.inventory_performed is False
    assert_blocked(result, tmp_path)


def test_a_file_data_root_is_blocked(tmp_path):
    target = tmp_path / "data-file"
    target.write_text("{}", encoding="utf-8")
    result = inventory(target)
    assert result.status == "approval_artifact_inventory_blocked"
    assert_blocked(result, tmp_path)


def test_a_symlinked_data_root_is_blocked(tmp_path):
    require_symlinks(tmp_path)
    real = data_dir(tmp_path)
    link = tmp_path / "linked-data"
    link.symlink_to(real, target_is_directory=True)
    result = inventory(link)
    assert result.status == "approval_artifact_inventory_blocked"
    assert_blocked(result, tmp_path)


def test_a_file_approval_root_is_blocked(tmp_path):
    root = data_dir(tmp_path)
    publication_root(root).write_text("{}", encoding="utf-8")
    result = inventory(root)
    assert result.status == "approval_artifact_inventory_blocked"
    assert_blocked(result, root)


def test_a_symlinked_approval_root_is_blocked(tmp_path):
    require_symlinks(tmp_path)
    root = data_dir(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    publication_root(root).symlink_to(elsewhere, target_is_directory=True)
    result = inventory(root)
    assert result.status == "approval_artifact_inventory_blocked"
    assert_blocked(result, root)


def test_an_uninspectable_approval_root_is_blocked(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    base = publication_root(root)
    base.mkdir()

    def boom(path, *args, **kwargs):
        raise PermissionError(13, "permission denied", str(path))

    monkeypatch.setattr(inventory_module, "_filesystem_identity", boom)
    result = inventory(root)
    assert result.status == "approval_artifact_inventory_blocked"
    assert result.inventory_root_present is True
    assert_blocked(result, root)


def test_a_failed_enumeration_is_blocked(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    publication_root(root).mkdir()

    def boom(path, *args, **kwargs):
        raise PermissionError(13, "permission denied", str(path))

    monkeypatch.setattr(os, "listdir", boom)
    result = inventory(root)
    assert result.status == "approval_artifact_inventory_blocked"
    assert result.inventory_root_present is True
    assert_blocked(result, root)


def test_a_replaced_approval_root_during_the_scan_is_blocked(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    base = publication_root(root)

    def stage(name):
        if name == "entries_enumerated":
            os.rename(base, base.parent / "moved-root")
            base.mkdir()

    monkeypatch.setattr(inventory_module, "_inventory_stage", stage)
    result = inventory(root)
    assert result.status == "approval_artifact_inventory_blocked"
    assert result.entries == ()
    assert_blocked(result, root)


def test_a_removed_approval_root_during_the_scan_is_blocked(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    base = publication_root(root)

    def stage(name):
        if name == "entries_enumerated":
            os.rename(base, base.parent / "moved-root")

    monkeypatch.setattr(inventory_module, "_inventory_stage", stage)
    result = inventory(root)
    assert result.status == "approval_artifact_inventory_blocked"
    assert result.entries == ()
    assert_blocked(result, root)


def test_the_blocking_paths_return_no_partial_entries(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    publish_artifact(artifact_for(bundle_a(), root), root)
    base = publication_root(root)

    def stage(name):
        if name == "root_identity_captured":
            os.rename(base, base.parent / "moved-root")
            base.mkdir()

    monkeypatch.setattr(inventory_module, "_inventory_stage", stage)
    result = inventory(root)
    assert result.entries == ()
    assert result.valid_entry_count == 0
    assert result.inventory_complete is False


# --------------------------------------------------------------------------
# The fixed entry-count bound
# --------------------------------------------------------------------------


def test_the_bound_is_a_fixed_maintained_constant():
    assert MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES == 1024
    signature = inspect.signature(inventory_persisted_approved_change_approval_artifacts)
    assert list(signature.parameters) == ["data_dir"]
    assert signature.parameters["data_dir"].kind is inspect.Parameter.KEYWORD_ONLY


def _fill(base: Path, count: int, *, start: int = 0) -> None:
    for index in range(start, start + count):
        (base / f"filler-{index:06d}").mkdir()


def test_exactly_the_maximum_number_of_direct_children_completes(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    base = publication_root(root)
    _fill(base, MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES - 1)

    calls: list[str] = []
    real_loader = load_persisted_approved_change_approval_artifact

    def counting(artifact_id, *, data_dir):
        calls.append(artifact_id)
        return real_loader(artifact_id, data_dir=data_dir)

    monkeypatch.setattr(
        inventory_module, "load_persisted_approved_change_approval_artifact", counting
    )
    result = inventory(root)
    assert result.status == "approval_artifact_inventory_loaded_with_anomalies"
    assert result.scanned_entry_count == MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES
    assert result.valid_entry_count == 1
    assert result.anomaly_count == MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES - 1
    assert calls == [artifact.approval_artifact_id]


def test_one_more_than_the_maximum_fails_closed(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    base = publication_root(root)
    _fill(base, MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES)
    before = snapshot(root)

    calls: list[str] = []

    def counting(artifact_id, *, data_dir):
        calls.append(artifact_id)
        raise AssertionError("the loader must not run once the bound is exceeded")

    monkeypatch.setattr(
        inventory_module, "load_persisted_approved_change_approval_artifact", counting
    )
    result = inventory(root)
    assert result.status == "approval_artifact_inventory_limit_exceeded"
    assert result.inventory_complete is False
    assert result.entries == ()
    assert result.anomalies == ()
    assert result.valid_entry_count == 0
    assert result.anomaly_count == 0
    assert result.scanned_entry_count == MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES + 1
    assert result.max_inventory_entries == MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES
    assert calls == []
    assert_blocked(result, root)
    assert snapshot(root) == before


def test_the_bound_counts_every_direct_child_including_malformed_names(tmp_path):
    root = data_dir(tmp_path)
    base = publication_root(root)
    base.mkdir()
    _fill(base, MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES + 1)
    result = inventory(root)
    assert result.status == "approval_artifact_inventory_limit_exceeded"
    assert result.scanned_entry_count == MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES + 1
    assert str(MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES) in " ".join(result.errors)


# --------------------------------------------------------------------------
# Loader-only validation
# --------------------------------------------------------------------------


def test_every_exact_candidate_is_validated_through_the_maintained_loader(tmp_path, monkeypatch):
    root, artifact_a, artifact_b = published_pair(tmp_path)
    (publication_root(root) / "latest").mkdir()
    seen: list[tuple[str, str]] = []
    real_loader = load_persisted_approved_change_approval_artifact

    def recording(artifact_id, *, data_dir):
        seen.append((artifact_id, str(data_dir)))
        return real_loader(artifact_id, data_dir=data_dir)

    monkeypatch.setattr(
        inventory_module, "load_persisted_approved_change_approval_artifact", recording
    )
    result = inventory(root)
    assert [item[0] for item in seen] == sorted(
        [artifact_a.approval_artifact_id, artifact_b.approval_artifact_id]
    )
    assert {item[1] for item in seen} == {str(root)}
    assert entry_names(result) == list(EXPECTED_FIXTURE_ORDER)


def test_a_loader_that_returns_nothing_valid_yields_no_entries(tmp_path, monkeypatch):
    root, artifact_a, _ = published_pair(tmp_path)
    real_loader = load_persisted_approved_change_approval_artifact

    def degraded(artifact_id, *, data_dir):
        loaded = real_loader(artifact_id, data_dir=data_dir)
        return loaded.model_copy(update={"approval_binding_valid": False})

    monkeypatch.setattr(
        inventory_module, "load_persisted_approved_change_approval_artifact", degraded
    )
    result = inventory(root)
    assert result.entries == ()
    assert result.anomaly_count == 2
    assert {item.category for item in result.anomalies} == {"invalid_approval_artifact"}
    assert result.inventory_complete is False


def test_the_inventory_module_owns_no_parser_loader_or_binding_recomputation():
    source = Path(inventory_module.__file__).read_text(encoding="utf-8")
    for token in (
        "json.loads",
        "json.dumps",
        "read_text",
        "read_bytes",
        "verify_approval_binding",
        "compute_subject_sha256",
        "canonical_subject_json",
        "validate_approved_change_approval_artifact",
        "load_persisted_approved_change_artifact_bundle",
        "hashlib",
        "sha256(",
    ):
        assert token not in source, token


# --------------------------------------------------------------------------
# Path-safe public error reporting
#
# ``OSError.__str__`` embeds ``repr(filename)``, which doubles every backslash,
# so a Windows host path inside a raw exception string can never be matched by
# literal-prefix redaction. PR320 therefore reports deterministic, path-free
# classification for its own exception boundaries, and hardens the redaction of
# inherited maintained PR319 strings against every spelling of the data root.
# --------------------------------------------------------------------------


def test_the_public_os_error_detail_is_deterministic_and_path_free():
    detail = inventory_module._public_os_error_detail
    leaked = "/srv/sfai/data/approved_change_approvals/aca_x"

    plain = PermissionError(13, "permission denied", leaked)
    assert detail(plain) == "PermissionError errno=13"

    # ``OSError`` auto-selects a concrete subclass from errno; the reported
    # type name is whatever that subclass is, and never any filename.
    two_paths = OSError(2, "no such file", leaked, None, leaked + "-2")
    rendered = detail(two_paths)
    assert rendered == f"{type(two_paths).__name__} errno=2"
    assert two_paths.filename == leaked
    assert leaked not in rendered
    assert str(two_paths) not in rendered
    assert repr(two_paths) not in rendered

    # Repeated formatting is byte-identical, and nothing is read from filename.
    assert detail(plain) == detail(PermissionError(13, "different text", "/other/path"))

    class _WinLike(OSError):
        pass

    win = _WinLike(13, "access is denied", leaked)
    win.winerror = 5
    assert detail(win) == "_WinLike errno=13 winerror=5"
    assert leaked not in detail(win)

    assert detail(OSError()) == "OSError"


def test_the_redactor_collapses_every_spelling_of_the_data_root(tmp_path):
    root = data_dir(tmp_path)
    redact = inventory_module._redactor(root)
    base = str(root)
    spellings = [
        base,
        base.replace("\\", "\\\\"),  # repr-escaped, exactly as OSError renders it
        base.replace("\\", "/"),
        "\\\\?\\" + base,
    ]
    if inventory_module._CASE_INSENSITIVE_PATHS:
        spellings.append(base.upper())
    for spelling in spellings:
        cleaned = redact(f"persisted approval directory is not inspectable: '{spelling}'")
        assert "<data_dir>" in cleaned, spelling
        assert spelling not in cleaned, spelling
        assert base not in cleaned, spelling


def test_the_root_spelling_set_is_deterministic_and_longest_first(tmp_path):
    root = data_dir(tmp_path)
    spellings = inventory_module._root_spellings(root)
    assert spellings == inventory_module._root_spellings(root)
    assert all(spellings)
    assert list(spellings) == sorted(spellings, key=lambda item: (-len(item), item))
    assert str(root) in spellings
    assert inventory_module._EXTENDED_LENGTH_PREFIX + str(root) in spellings
    assert str(root).replace("\\", "/") in spellings
    assert str(root).replace("\\", "\\\\") in spellings


def test_a_root_inspection_error_never_leaks_a_host_path(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    base = publication_root(root)
    base.mkdir()

    def boom(path, *args, **kwargs):
        raise PermissionError(13, "permission denied", str(path))

    monkeypatch.setattr(inventory_module, "_filesystem_identity", boom)
    result = inventory(root)
    assert result.status == "approval_artifact_inventory_blocked"
    reported = " ".join(result.errors)
    assert "PermissionError" in reported
    assert "errno=13" in reported
    assert "permission denied" not in reported
    assert "[Errno" not in reported
    assert_path_free(result, root, base)


def test_an_enumeration_error_never_leaks_a_host_path(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    base = publication_root(root)
    base.mkdir()

    def boom(path, *args, **kwargs):
        raise PermissionError(13, "permission denied", str(path))

    monkeypatch.setattr(os, "listdir", boom)
    result = inventory(root)
    assert result.status == "approval_artifact_inventory_blocked"
    reported = " ".join(result.errors)
    assert "PermissionError" in reported
    assert "errno=13" in reported
    assert "permission denied" not in reported
    assert "[Errno" not in reported
    assert_path_free(result, root, base)


def test_a_child_inspection_error_never_leaks_a_windows_shaped_host_path(tmp_path, monkeypatch):
    """The exact regression: a repr-escaped absolute path must not survive."""
    root = data_dir(tmp_path)
    base = publication_root(root)
    base.mkdir()
    (base / EXACT_UNPUBLISHED_ID).mkdir()
    child = base / EXACT_UNPUBLISHED_ID
    real_lstat = os.lstat

    windows_shaped = r"C:\Users\runner\AppData\Local\Temp\data\aca_child"

    def guarded(path, *args, **kwargs):
        if str(path).endswith(EXACT_UNPUBLISHED_ID):
            raise PermissionError(13, "Access is denied", windows_shaped)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", guarded)
    result = inventory(root)

    assert anomaly_pairs(result) == [(EXACT_UNPUBLISHED_ID, "entry_not_inspectable")]
    blob = result.model_dump_json()
    for spelling in path_spellings(windows_shaped):
        assert spelling not in blob, spelling
    assert "Access is denied" not in blob
    assert "[Errno" not in blob
    assert_path_free(result, root, child)
    # The anomaly still names the direct child by its single safe name only.
    assert result.anomalies[0].entry_name == EXACT_UNPUBLISHED_ID


def test_an_inherited_loader_error_carrying_a_path_is_redacted(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    directory = publication_root(root) / artifact.approval_artifact_id
    real_loader = load_persisted_approved_change_approval_artifact

    def leaking_loader(artifact_id, *, data_dir):
        loaded = real_loader(artifact_id, data_dir=data_dir)
        escaped = str(directory).replace("\\", "\\\\")
        return loaded.model_copy(
            update={
                "status": "persisted_approval_artifact_invalid",
                "errors": (
                    f"persisted approval directory is not inspectable: '{directory}'",
                    f"persisted approval file is not readable: '{escaped}'",
                ),
            }
        )

    monkeypatch.setattr(
        inventory_module, "load_persisted_approved_change_approval_artifact", leaking_loader
    )
    result = inventory(root)

    (anomaly,) = result.anomalies
    assert anomaly.category == "invalid_approval_artifact"
    assert anomaly.errors
    assert all("<data_dir>" in item for item in anomaly.errors)
    assert_path_free(result, root, directory)


def test_no_public_error_field_ever_carries_raw_exception_text():
    source = Path(inventory_module.__file__).read_text(encoding="utf-8")
    for token in ("str(exc)", "repr(exc)", "exc.filename", "exc.filename2", "format_exc"):
        assert token not in source, token
    # Every OSError handler that reports detail must route through the helper.
    tree = ast.parse(source)
    reporting = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_public_os_error_detail":
            reporting += 1
    assert reporting == 3


# --------------------------------------------------------------------------
# No writes
# --------------------------------------------------------------------------


@pytest.fixture
def no_filesystem_writes(monkeypatch):
    """Install a guard that fails loudly on any write-capable primitive."""

    def install():
        def raiser(label):
            def boom(*args, **kwargs):
                raise AssertionError(f"{label} was reached by a read-only inventory")

            return boom

        for name in (
            "mkdir",
            "makedirs",
            "rename",
            "replace",
            "rmdir",
            "unlink",
            "remove",
            "truncate",
            "link",
            "symlink",
            "utime",
            "chmod",
        ):
            if hasattr(os, name):
                monkeypatch.setattr(os, name, raiser(f"os.{name}"))

        real_os_open = os.open

        def guarded_os_open(path, flags, *args, **kwargs):
            if flags & (os.O_CREAT | os.O_WRONLY | os.O_RDWR | getattr(os, "O_TRUNC", 0)):
                raise AssertionError("a write-capable os.open was reached")
            return real_os_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", guarded_os_open)

        real_open = builtins.open

        def guarded_open(file, mode="r", *args, **kwargs):
            if set(mode) & {"w", "a", "x", "+"}:
                raise AssertionError("a write-capable open() was reached")
            return real_open(file, mode, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", guarded_open)
        monkeypatch.setattr(Path, "mkdir", raiser("Path.mkdir"))
        monkeypatch.setattr(Path, "write_text", raiser("Path.write_text"))
        monkeypatch.setattr(Path, "write_bytes", raiser("Path.write_bytes"))
        monkeypatch.setattr(Path, "rename", raiser("Path.rename"))
        monkeypatch.setattr(Path, "replace", raiser("Path.replace"))
        monkeypatch.setattr(Path, "unlink", raiser("Path.unlink"))
        monkeypatch.setattr(Path, "rmdir", raiser("Path.rmdir"))
        monkeypatch.setattr(Path, "touch", raiser("Path.touch"))
        monkeypatch.setattr(Path, "symlink_to", raiser("Path.symlink_to"))
        monkeypatch.setattr(tempfile, "mkdtemp", raiser("tempfile.mkdtemp"))
        monkeypatch.setattr(tempfile, "mkstemp", raiser("tempfile.mkstemp"))
        monkeypatch.setattr(tempfile, "TemporaryDirectory", raiser("tempfile.TemporaryDirectory"))
        monkeypatch.setattr(shutil, "rmtree", raiser("shutil.rmtree"))
        monkeypatch.setattr(shutil, "move", raiser("shutil.move"))
        monkeypatch.setattr(shutil, "copy2", raiser("shutil.copy2"))

    return install


def test_no_write_primitive_is_reached_on_any_inventory_path(tmp_path, no_filesystem_writes):
    empty_root = data_dir(tmp_path / "empty-case")
    present_root = data_dir(tmp_path / "present-case")
    publication_root(present_root).mkdir()
    loaded_root, _, _ = published_pair(tmp_path / "loaded-case")
    anomalous_root, _, _ = published_pair(tmp_path / "anomalous-case")
    (publication_root(anomalous_root) / "latest").mkdir()
    blocked_root = data_dir(tmp_path / "blocked-case")
    publication_root(blocked_root).write_text("{}", encoding="utf-8")

    before = {
        root: snapshot(root)
        for root in (empty_root, present_root, loaded_root, anomalous_root, blocked_root)
    }

    no_filesystem_writes()

    assert inventory(empty_root).status == "approval_artifact_inventory_empty"
    assert inventory(present_root).status == "approval_artifact_inventory_empty"
    assert inventory(loaded_root).status == "approval_artifact_inventory_loaded"
    assert inventory(anomalous_root).status == "approval_artifact_inventory_loaded_with_anomalies"
    assert inventory(blocked_root).status == "approval_artifact_inventory_blocked"
    assert (
        inventory_persisted_approved_change_approval_artifacts(data_dir="").status
        == "invalid_inventory_input"
    )

    for root, recorded in before.items():
        assert snapshot(root) == recorded


def test_the_no_write_proof_is_not_vacuous(tmp_path, no_filesystem_writes):
    root = data_dir(tmp_path)
    no_filesystem_writes()
    with pytest.raises(AssertionError):
        (root / "proof").mkdir()


# --------------------------------------------------------------------------
# No hidden ordering or selection
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


def test_static_no_time_based_or_preferred_ordering_exists():
    source = module_code_without_strings(inventory_module)
    for token in (
        "st_mtime",
        "st_ctime",
        "st_atime",
        "st_birthtime",
        "getmtime",
        "getctime",
        "st_mtime_ns",
        "max(",
        "min(",
        "reverse=True",
        "newest",
        "oldest",
        "latest",
        "current_",
        "most_recent",
        "preferred",
        "select(",
        "select_",
        "selection",
        "resolve_approval",
        "sort_key",
        "descending",
        "approved_at)",
    ):
        assert token not in source, token


def test_static_the_only_sort_keys_are_the_artifact_id_and_the_entry_name():
    tree = module_tree_without_docstrings(inventory_module)
    keys: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "sorted":
            for keyword in node.keywords:
                keys.append(ast.unparse(keyword.value))
    assert keys == [
        "lambda item: (-len(item), item)",
        "lambda item: item.approval_artifact_id",
        "lambda item: (item.entry_name, item.category)",
    ], keys


def test_the_result_exposes_no_selection_surface():
    fields = set(ApprovedChangeApprovalArtifactInventoryResult.model_fields)
    for forbidden in (
        "selected_approval_artifact_id",
        "selected_entry",
        "latest",
        "latest_approval_artifact_id",
        "current",
        "current_approval_artifact_id",
        "most_recent",
        "preferred_entry",
        "recommended_entry",
        "index_path",
        "pointer_path",
    ):
        assert forbidden not in fields, forbidden
    empty = ApprovedChangeApprovalArtifactInventoryResult(
        status="approval_artifact_inventory_empty"
    )
    assert empty.approval_selected is False
    assert empty.inventory_index_written is False


def test_the_module_exposes_no_selection_or_search_operation():
    for name in (
        "latest_approval",
        "current_approval",
        "most_recent_approval",
        "resolve_latest_approval",
        "select_approval_artifact",
        "find_approval_artifact",
        "search_approval_artifacts",
        "filter_approval_artifacts",
        "rank_approval_artifacts",
        "write_approval_inventory_index",
        "app",
        "cli",
        "main",
        "REGISTRY",
    ):
        assert not hasattr(inventory_module, name), name


# --------------------------------------------------------------------------
# No hidden expansion
# --------------------------------------------------------------------------


@pytest.fixture
def no_hidden_expansion(monkeypatch):
    def install():
        def raiser(label):
            def boom(*args, **kwargs):
                raise AssertionError(f"{label} was reached by a read-only inventory")

            return boom

        monkeypatch.setattr(subprocess, "run", raiser("subprocess.run"))
        monkeypatch.setattr(subprocess, "Popen", raiser("subprocess.Popen"))
        monkeypatch.setattr(subprocess, "check_output", raiser("subprocess.check_output"))
        monkeypatch.setattr(socket, "socket", raiser("socket.socket"))
        monkeypatch.setattr(socket, "create_connection", raiser("socket.create_connection"))
        monkeypatch.setattr(socket, "gethostname", raiser("socket.gethostname"))
        monkeypatch.setattr(os, "system", raiser("os.system"))
        monkeypatch.setattr(os, "popen", raiser("os.popen"))
        monkeypatch.setattr(time, "time", raiser("time.time"))
        monkeypatch.setattr(time, "monotonic", raiser("time.monotonic"))
        monkeypatch.setattr(uuid, "uuid4", raiser("uuid.uuid4"))
        monkeypatch.setattr(random, "random", raiser("random.random"))
        monkeypatch.setattr(random, "choice", raiser("random.choice"))
        monkeypatch.setattr(platform, "node", raiser("platform.node"))
        monkeypatch.setattr(platform, "system", raiser("platform.system"))
        if hasattr(os, "getlogin"):
            monkeypatch.setattr(os, "getlogin", raiser("os.getlogin"))
        monkeypatch.setattr(os, "getenv", raiser("os.getenv"))

    return install


def test_no_shell_network_clock_identity_or_randomness_surface_is_reached(
    tmp_path, no_hidden_expansion
):
    root, _, _ = published_pair(tmp_path)
    (publication_root(root) / "latest").mkdir()
    no_hidden_expansion()
    result = inventory(root)
    assert result.status == "approval_artifact_inventory_loaded_with_anomalies"
    assert result.valid_entry_count == 2


def test_static_the_import_set_is_exactly_the_maintained_dependencies():
    tree = ast.parse(Path(inventory_module.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    assert imported == {
        "__future__",
        "os",
        "pathlib",
        "pydantic",
        "re",
        "shellforgeai.core.approved_change_approval_artifact",
        "shellforgeai.core.approved_change_approval_persistence",
        "shellforgeai.core.approved_change_artifact_bundle",
        "stat",
        "typing",
    }


def test_static_no_capability_preflight_receipt_execution_or_cli_surface_exists():
    source = module_code_without_strings(inventory_module)
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
        "publish_approved_change_approval_artifact",
        "publish_approved_change_artifact_bundle",
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
        "random",
        "secrets",
        "uuid",
        "glob",
        "walk(",
        "rglob",
        "iterdir",
        "mkdir",
        "makedirs",
        "write_text",
        "write_bytes",
        "unlink",
        "rmdir",
        "tempfile",
        "mkdtemp",
    ):
        assert token not in source, token


def test_no_legacy_proposal_type_is_named_or_imported():
    tree = module_tree_without_docstrings(inventory_module)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.module != "shellforgeai.core.approvals"
            assert "Proposal" not in {alias.name for alias in node.names}
        if isinstance(node, ast.Name):
            assert node.id != "Proposal"
    source = module_code_without_strings(inventory_module)
    for token in ("Proposal", "core.approvals", "approve_proposal", "fingerprint"):
        assert token not in source, token


def test_signatures_never_take_or_return_legacy_approval_types():
    for _, obj in inspect.getmembers(inventory_module, inspect.isfunction):
        signature = inspect.signature(obj)
        assert all(param.annotation is not Proposal for param in signature.parameters.values())
        assert "Proposal" not in str(signature)


def test_the_legacy_approval_queue_is_never_scanned(tmp_path, monkeypatch):
    root, _, _ = published_pair(tmp_path)
    legacy = root / "approvals"
    legacy.mkdir()
    (legacy / "proposal.json").write_text("{}", encoding="utf-8")
    seen: list[str] = []
    real_listdir = os.listdir

    def recorded(path, *args, **kwargs):
        seen.append(str(path))
        return real_listdir(path, *args, **kwargs)

    monkeypatch.setattr(os, "listdir", recorded)
    result = inventory(root)
    assert seen == [str(publication_root(root))]
    assert result.valid_entry_count == 2
    assert "proposal" not in result.model_dump_json()


def test_the_public_surface_is_exactly_one_operation():
    public = sorted(
        name
        for name, obj in inspect.getmembers(inventory_module, inspect.isfunction)
        if not name.startswith("_") and obj.__module__ == inventory_module.__name__
    )
    assert public == ["inventory_persisted_approved_change_approval_artifacts"]


def test_the_inventory_module_is_not_imported_by_cli_approvals_recipes_or_execution():
    roots = [Path("src/shellforgeai/cli"), Path("src/shellforgeai/core")]
    offenders = [
        str(path)
        for base in roots
        for path in base.rglob("*.py")
        if path.name != "approved_change_approval_inventory.py"
        and "approved_change_approval_inventory" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_no_cli_surface_was_added():
    cli = Path("docs/cli.md").read_text(encoding="utf-8")
    assert "approval-inventory" not in cli
    assert "approved_change_approvals" not in cli
    offenders = [
        str(path)
        for path in Path("src/shellforgeai/cli").rglob("*.py")
        if "approved_change_approval" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


# --------------------------------------------------------------------------
# Immutability and structured failures
# --------------------------------------------------------------------------


def test_every_result_model_is_frozen(tmp_path):
    root, _, _ = published_pair(tmp_path)
    (publication_root(root) / "latest").mkdir()
    result = inventory(root)
    entry = result.entries[0]
    anomaly = result.anomalies[0]

    for model, field, value in (
        (result, "status", "approval_artifact_inventory_loaded"),
        (result, "inventory_complete", True),
        (entry, "approval_artifact_id", "aca_other"),
        (anomaly, "category", "unexpected_name"),
    ):
        with pytest.raises(ValidationError):
            setattr(model, field, value)

    assert isinstance(result.entries, tuple)
    assert isinstance(result.anomalies, tuple)
    assert isinstance(result.errors, tuple)
    assert isinstance(result.warnings, tuple)
    assert isinstance(anomaly.errors, tuple)


def test_the_models_reject_unknown_fields():
    for model in (
        ApprovedChangeApprovalArtifactInventoryResult,
        ApprovedChangeApprovalArtifactInventoryEntry,
        ApprovedChangeApprovalArtifactInventoryAnomaly,
    ):
        with pytest.raises(ValidationError):
            model(surprise=True)


def test_errors_are_deterministic_sorted_and_deduplicated(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bad = artifact_with_present_bundle(root, bundle_a())
    write_artifact_directory(root, bad, mutate=lambda payload: {})
    result = inventory(root)
    (anomaly,) = result.anomalies
    assert list(anomaly.errors) == sorted(set(anomaly.errors))
    assert anomaly.errors


def test_no_host_absolute_path_reaches_any_result(tmp_path):
    root = data_dir(tmp_path)
    good = artifact_for(bundle_a(), root)
    publish_artifact(good, root)
    bad = artifact_with_present_bundle(root, bundle_b())
    write_artifact_directory(root, bad, mutate=lambda payload: {})
    (publication_root(root) / "latest").mkdir()

    result = inventory(root)
    blob = result.model_dump_json()
    assert str(root) not in blob
    assert str(tmp_path) not in blob
    assert str(Path(root).resolve()) not in blob
    assert str(Path(tempfile.gettempdir())) not in blob
    assert result.anomaly_count == 2
    for anomaly in result.anomalies:
        assert os.sep not in anomaly.entry_name
        assert "/" not in anomaly.entry_name


def test_every_status_is_a_maintained_literal():
    assert set(INVENTORY_STATUSES) == {
        "approval_artifact_inventory_loaded",
        "approval_artifact_inventory_empty",
        "approval_artifact_inventory_loaded_with_anomalies",
        "approval_artifact_inventory_blocked",
        "approval_artifact_inventory_limit_exceeded",
        "invalid_inventory_input",
    }
    assert set(INVENTORY_ANOMALY_CATEGORIES) == {
        "entry_changed_during_inventory",
        "entry_disappeared",
        "entry_not_inspectable",
        "invalid_approval_artifact",
        "non_directory_entry",
        "symlink_or_reparse_entry",
        "unexpected_name",
    }
    assert REQUIRED_APPROVAL_ARTIFACT_LOAD_STATUS in LOAD_STATUSES


def test_the_permanent_warnings_state_the_whole_posture():
    joined = " ".join(PERMANENT_APPROVAL_INVENTORY_WARNINGS)
    for phrase in (
        "discovery only and selects no approval",
        "lexicographic by exact approval-artifact ID only",
        "not chronological",
        "most recent approval",
        "exact aca_ approval-artifact ID remains required",
        "explicitly incomplete",
        "no persisted index, pointer, or cache",
        "repaired, overwritten, renamed, quarantined, or deleted",
        "self-asserted metadata, not authenticated identity",
        "reviewer provenance is not approval",
        "persistence is not authorization",
        "not capability support",
        "no capability registry has been consulted",
        "no current-state preflight has run",
        "no receipt has been created or linked",
        "no execution eligibility is granted",
        "reviewed before sharing",
    ):
        assert phrase in joined, phrase
    for warning in PERMANENT_APPROVAL_ARTIFACT_WARNINGS:
        assert warning in PERMANENT_APPROVAL_INVENTORY_WARNINGS


# --------------------------------------------------------------------------
# Exact-ID downstream boundary
# --------------------------------------------------------------------------


def test_the_complete_artifact_still_requires_the_exact_id_loader(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root)
    publish_artifact(artifact, root)
    (entry,) = inventory(root).entries

    assert not hasattr(entry, "artifact")
    assert not hasattr(entry, "contract")
    assert entry.model_dump().get("canonical_content_utf8") is None

    loaded = load_persisted_approved_change_approval_artifact(
        entry.approval_artifact_id, data_dir=root
    )
    assert loaded.status == REQUIRED_APPROVAL_ARTIFACT_LOAD_STATUS
    assert loaded.artifact.approval_artifact_id == entry.approval_artifact_id
    assert loaded.artifact.contract.approval.reason


def test_an_inventory_entry_is_never_capability_authorization_or_execution(tmp_path):
    root, _, _ = published_pair(tmp_path)
    result = inventory(root)
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert result.capability_bound is False
    assert result.authorization_evaluated is False
    assert result.preflight_evaluated is False
    assert result.receipt_created is False
    assert result.receipt_linked is False
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"
    fields = set(ApprovedChangeApprovalArtifactInventoryEntry.model_fields)
    for forbidden in ("capability_id", "capability_supported", "preflight", "receipt", "execution"):
        assert not [name for name in fields if forbidden in name], forbidden


def test_inventory_never_reaches_the_publisher(tmp_path, monkeypatch):
    from shellforgeai.core import approved_change_approval_persistence as persistence

    def boom(*args, **kwargs):
        raise AssertionError("the PR319 publisher must never be reached")

    monkeypatch.setattr(persistence, "publish_approved_change_approval_artifact", boom)
    root, _, _ = published_pair(tmp_path)
    assert inventory(root).status == "approval_artifact_inventory_loaded"


# --------------------------------------------------------------------------
# Documentation and validation-matrix contract
# --------------------------------------------------------------------------


def test_the_inventory_documentation_records_the_fixed_contract():
    document = Path("docs/APPROVED_CHANGE_APPROVAL_INVENTORY.md").read_text(encoding="utf-8")
    for phrase in (
        "PR320",
        "PR319",
        "inventory_persisted_approved_change_approval_artifacts",
        "load_persisted_approved_change_approval_artifact",
        APPROVED_CHANGE_APPROVALS_DIRNAME,
        "aca_",
        str(MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES),
        "approval_artifact_inventory_loaded",
        "approval_artifact_inventory_empty",
        "approval_artifact_inventory_loaded_with_anomalies",
        "approval_artifact_inventory_blocked",
        "approval_artifact_inventory_limit_exceeded",
        "invalid_inventory_input",
        "inventory_complete",
        "unexpected_name",
        "symlink_or_reparse_entry",
        "non_directory_entry",
        "invalid_approval_artifact",
        "entry_disappeared",
        "entry_changed_during_inventory",
        "direct children",
        "lexicograph",
        "self-asserted",
        "no execution eligibility",
        "PR321",
    ):
        assert phrase in document, phrase
    assert "discovery only and selects no approval" in document
    assert "inventory_complete=false" in document
    assert "MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES" in document


def test_the_validation_matrix_maps_the_inventory_module_to_this_suite():
    matrix = json.loads(Path("scripts/validation_matrix.json").read_text(encoding="utf-8"))
    rules = [
        rule
        for rule in matrix["rules"]
        if rule["pattern"] == "src/shellforgeai/core/approved_change_approval_inventory.py"
    ]
    assert len(rules) == 1
    assert "tests/test_pr320_approved_change_approval_inventory.py" in rules[0]["tests"]
    for required in (
        "tests/test_pr319_approved_change_approval_artifact_persistence.py",
        "tests/test_pr318_approved_change_approval_workflow.py",
        "tests/test_pr317_approved_change_artifact_persistence.py",
        "tests/test_pr316_approved_change_artifact_bundle.py",
        "tests/test_pr309_approved_change_contract.py",
    ):
        assert required in rules[0]["tests"], required

    for pattern in (
        "src/shellforgeai/core/approved_change_approval_artifact.py",
        "src/shellforgeai/core/approved_change_approval_persistence.py",
    ):
        rule = next(rule for rule in matrix["rules"] if rule["pattern"] == pattern)
        assert "tests/test_pr320_approved_change_approval_inventory.py" in rule["tests"]

    document = Path("docs/VALIDATION_MATRIX.md").read_text(encoding="utf-8")
    assert "approved_change_approval_inventory.py" in document
    assert "test_pr320_approved_change_approval_inventory" in document


def test_roadmap_safety_and_architecture_record_the_pr320_boundary():
    history = Path("docs/archive/PROJECT_HISTORY.md").read_text(encoding="utf-8")
    assert "PR320" in history
    assert "APPROVED_CHANGE_APPROVAL_INVENTORY.md" in history
    assert "discovery, not selection or authorization" in history
    assert "no persisted index" in history

    safety = Path("docs/safety.md").read_text(encoding="utf-8")
    assert "PR320" in safety
    assert "inventory" in safety

    architecture = Path("docs/architecture.md").read_text(encoding="utf-8")
    assert "approved_change_approval_inventory.py" in architecture


def test_no_new_persisted_subtree_was_documented():
    layout = Path("docs/data-layout.md").read_text(encoding="utf-8")
    assert "inventory" not in layout.lower().replace("there is no inventory", "")


def test_the_module_docstring_states_the_read_only_discovery_posture():
    doc = inventory_module.__doc__ or ""
    for phrase in ("read-only", "direct", "PR319", "selection"):
        assert phrase in doc, phrase
    assert sys.modules[inventory_module.__name__] is inventory_module
