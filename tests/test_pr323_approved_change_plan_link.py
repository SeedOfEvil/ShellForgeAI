"""Focused PR323 tests: approved-change plan link.

PR309 owns the subject schema, the subject identity, the contract, and the
capability-ID syntax. PR316 owns the reviewed bundle. PR317 owns the governed
bundle publisher and its exact-ID loader. PR318 owns the one read-only
approval-binding operation. PR319 owns the canonical approval artifact, the
``aca_`` identity, and the exact-ID approval-artifact loader. PR320 owns bounded
read-only discovery. PR321 owns the capability-support catalog and the support
decision. PR322 owns the lane declaration and the capability binding. PR305 and
PR313 own saved-plan acceptance, the executable-plan contract, and the canonical
plan identity.

These tests prove PR323 adds exactly one thing on top of those maintained
contracts: one immutable, deterministic, in-memory association between one exact
PR322 binding identity and the exact canonical identity of one
maintained-validator-approved saved Windows runtime-reconcile plan packet.

A plan link is an identity association only. It is not target semantics,
procedure semantics, free-text intent equivalence, PR304 evidence freshness,
staged-source inspection, durable-runtime inspection, ``System32`` inspection,
current-state readiness, preflight, authorization, receipt linkage, or
execution.
"""

from __future__ import annotations

import ast
import builtins
import hashlib
import json
import os
import platform
import random
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest
from pydantic import ValidationError

# The PR319 focused suite owns the maintained publication helpers and the PR321
# focused suite owns the maintained capability fixtures. Both are reused
# verbatim so PR323 never invents its own context, subject, bundle, approval,
# artifact, or catalog schema.
from test_pr319_approved_change_approval_artifact_persistence import (  # noqa: E402
    data_dir,
    module_code_without_strings,
    publication_root,
    snapshot,
)
from test_pr321_approved_change_capability_support import (  # noqa: E402
    NEAR_MISS_CAPABILITY_IDS,
    UNKNOWN_CAPABILITY_ID,
    FsWatch,
    alternate_supported_bundle,
    capability_bundle,
    catalog_identity,
    publish_for,
)

from shellforgeai.core import approved_change_plan_link as link_module
from shellforgeai.core.approved_change_approval_artifact import (
    APPROVAL_ARTIFACT_ID_PREFIX,
)
from shellforgeai.core.approved_change_capability_binding import (
    WINDOWS_RUNTIME_RECONCILE_LANE_ID,
    compute_approved_change_capability_binding_sha256,
    compute_capability_lane_declaration_sha256,
    construct_persisted_approved_change_capability_binding,
    maintained_windows_runtime_reconcile_lane_declaration,
    validate_approved_change_capability_binding,
)
from shellforgeai.core.approved_change_capability_support import (
    WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
)
from shellforgeai.core.approved_change_plan_link import (
    PERMANENT_PLAN_LINK_WARNINGS,
    PLAN_LINK_COMPARISON_SCOPE,
    PLAN_LINK_SCHEMA_VERSION,
    PLAN_LINK_STATUSES,
    PLAN_LINK_TYPE,
    PLAN_LINK_VALIDATION_STATUSES,
    ApprovedChangePlanLinkResult,
    ApprovedChangePlanLinkValidationResult,
    ApprovedChangeWindowsRuntimeReconcilePlanLink,
    canonical_approved_change_plan_link_json,
    canonical_approved_change_plan_link_payload,
    compute_approved_change_plan_link_sha256,
    link_persisted_approved_change_to_windows_runtime_reconcile_plan,
    validate_approved_change_plan_link,
)
from shellforgeai.core.windows_runtime_reconcile_plan_contract import (
    ALLOWLIST,
    PARENT_CONTRACT_VERSION,
    PLAN_MODE,
    RECIPE_ID,
    REQUIRED_FUTURE_GATES,
    UNSAFE_SAFETY_FALSE_KEYS,
    canonical_plan_sha256,
    validate_saved_windows_runtime_reconcile_plan_packet,
)

# --------------------------------------------------------------------------
# Committed fixed-fixture values
#
# The plan fixtures below are byte-fixed source constants: they contain no
# tmp_path, no host name, no user name, and no clock value, so the canonical
# plan SHA-256, the canonical link bytes, the link byte length, and the link
# identity are the same on Linux and on Windows. Any drift in the plan schema,
# the link payload, the ordering, or the encoding fails loudly here instead of
# silently changing what ShellForgeAI links.
# --------------------------------------------------------------------------

READY_PLAN_SHA256 = "fc5807dcd27d96f1c9b5cec56c5e26f6025a51ced7bcbbb34ddabd2c6602182c"
NO_CHANGE_PLAN_SHA256 = "acb2f611afe3530e898a4326072537c698b9fa470ecfbc5e781182a7f3e24742"

#: The exact link produced for the maintained supported fixture and the exact
#: ready plan. Every field is deterministic, so the whole payload, its canonical
#: byte length, and its identity are fixed fixtures.
SUPPORTED_LINK_APPROVAL_ARTIFACT_ID = (
    "aca_c6ba9c51e9efa77c9df355cb87e0c5ceebd580a81c327a7a4806ce0ee7240f9f"
)
SUPPORTED_LINK_SUBJECT_SHA256 = "f643bdcf2d5674a8d9b1771e5e60af7f962e2b0ee73c24833113f973102fcc96"
SUPPORTED_BINDING_IDENTITY_SHA256 = (
    "08a396a106aad7fdedf6491137631456ab9d8a1722d9582f69ddd44b15ab3c81"
)
READY_LINK_BYTE_LENGTH = 1069
READY_LINK_IDENTITY_SHA256 = "088c18e7a5bc4ccecbe9496ed841c6fa8830d2ebe9528e1c85c4b940079c80b6"
NO_CHANGE_LINK_IDENTITY_SHA256 = "496104380eba15526432543a4fda1d647cfd876c37b92dc6507c8ec3255f633c"

HEX64 = "0123456789abcdef" * 4
OTHER_HEX64 = "fedcba9876543210" * 4
UNPUBLISHED_ARTIFACT_ID = f"{APPROVAL_ARTIFACT_ID_PREFIX}{HEX64}"

#: Deliberately absolute Windows host paths. Nothing derived from them may ever
#: appear in a PR323 result.
STAGED_SOURCE_ROOT = "C:\\ShellForgeAI"
DURABLE_RUNTIME_ROOT = "C:\\ShellForgeAI-Runtime"
HOST_PATH_TOKENS = (
    STAGED_SOURCE_ROOT,
    DURABLE_RUNTIME_ROOT,
    "C:/ShellForgeAI",
    "C:/ShellForgeAI-Runtime",
    "C:\\\\ShellForgeAI",
    "sfai-pr305-backup",
    "<UTCSTAMP>",
    "WIN2025-SFAI01",
    "win2025-sfai01",
    "sfai-operator",
)

PROFILE_SOURCE_SHA256 = "a" * 64
WRAPPER_SOURCE_SHA256 = "b" * 64
STALE_DESTINATION_SHA256 = "c" * 64

_PARENT_RELATIVE = {
    "config/profiles/inspect.yaml": "config/profiles",
    "bin/sfai.cmd": "bin",
}


# --------------------------------------------------------------------------
# Fixed plan-packet fixtures
# --------------------------------------------------------------------------


def plan_operation(index: int, operation: str, existing_destination_sha256: str | None):
    """One byte-fixed saved operation for the exact allowlist entry ``index``."""
    relative_source, relative_destination = ALLOWLIST[index]
    source_sha256 = PROFILE_SOURCE_SHA256 if index == 0 else WRAPPER_SOURCE_SHA256
    destination = f"{DURABLE_RUNTIME_ROOT}\\{relative_destination.replace('/', chr(92))}"
    return {
        "operation": operation,
        "allowlist_source": relative_source,
        "allowlist_destination": relative_destination,
        "source_path": f"{STAGED_SOURCE_ROOT}\\{relative_source.replace('/', chr(92))}",
        "destination_path": destination,
        "source_sha256": source_sha256,
        "existing_destination_sha256": existing_destination_sha256,
        "expected_post_change_sha256": source_sha256,
        "reason": "fixed synthetic fixture",
        "destination_parent": {
            "contract_version": PARENT_CONTRACT_VERSION,
            "relative_path": _PARENT_RELATIVE[relative_destination],
            "state": "present",
            "creation_allowed": relative_destination == "config/profiles/inspect.yaml",
            "creation_chain": [],
            "blockers": [],
        },
        "creation_required": operation == "create_required",
        "replacement_required": operation == "replace_required",
        "backup_path_pattern": f"{destination}.sfai-pr305-backup-<UTCSTAMP>.bak",
        "post_change_pr304_verification": [
            "run PR304 from staged source root",
            "run PR304 from C:\\Windows\\System32",
            "validate both artifacts with multi-artifact acceptance",
        ],
    }


def plan_summary(operations):
    counts = {k: 0 for k in ("no_change", "create_required", "replace_required", "blocked")}
    parents = {k: 0 for k in ("present", "create_required", "blocked")}
    for operation in operations:
        counts[operation["operation"]] = counts.get(operation["operation"], 0) + 1
        parents[operation["destination_parent"]["state"]] += 1
    return {
        "total_operations": len(operations),
        **counts,
        "parent_present": parents["present"],
        "parent_create_required": parents["create_required"],
        "parent_blocked": parents["blocked"],
    }


def plan_packet(*, status="ready", operations=None, **overrides):
    """One byte-fixed saved PR305 packet with exact absolute Windows paths."""
    if operations is None:
        if status == "no_change":
            operations = [
                plan_operation(0, "no_change", PROFILE_SOURCE_SHA256),
                plan_operation(1, "no_change", WRAPPER_SOURCE_SHA256),
            ]
        else:
            operations = [
                plan_operation(0, "replace_required", STALE_DESTINATION_SHA256),
                plan_operation(1, "no_change", WRAPPER_SOURCE_SHA256),
            ]
    packet = {
        "schema_version": 1,
        "mode": PLAN_MODE,
        "recipe_id": RECIPE_ID,
        "destination_parent_contract_version": PARENT_CONTRACT_VERSION,
        "status": status,
        "read_only": True,
        "mutation_performed": False,
        "preview_only": True,
        "execution_available": False,
        "execution_implemented": False,
        "future_confirmation_required": True,
        "future_verification_required": True,
        "future_receipt_required": True,
        "artifact_count": 1,
        "platform": {"system": "windows"},
        "staged_source_root": STAGED_SOURCE_ROOT,
        "durable_runtime_root": DURABLE_RUNTIME_ROOT,
        "allowlist": [{"source": a, "destination": b} for a, b in ALLOWLIST],
        "operations": operations,
        "summary": plan_summary(operations),
        "gates": [
            {"name": name, "status": "future_gate"} for name in sorted(REQUIRED_FUTURE_GATES)
        ],
        "blockers": [],
        "warnings": [],
        "safety": {"read_only": True, **{k: False for k in UNSAFE_SAFETY_FALSE_KEYS}},
    }
    packet.update(overrides)
    return packet


def ready_packet(**overrides):
    return plan_packet(status="ready", **overrides)


def no_change_packet(**overrides):
    return plan_packet(status="no_change", **overrides)


def blocked_packet():
    operations = [
        plan_operation(0, "blocked", None),
        plan_operation(1, "no_change", WRAPPER_SOURCE_SHA256),
    ]
    operations[0]["source_sha256"] = PROFILE_SOURCE_SHA256
    operations[0]["expected_post_change_sha256"] = PROFILE_SOURCE_SHA256
    packet = plan_packet(status="blocked", operations=operations)
    packet["blockers"] = ["source is missing or not a regular file"]
    return packet


def unsupported_packet():
    packet = plan_packet(status="unsupported", operations=[])
    packet["platform"] = {"system": "linux"}
    return packet


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def lane_identity() -> str:
    return compute_capability_lane_declaration_sha256(
        maintained_windows_runtime_reconcile_lane_declaration()
    )


_EXACT = object()


def link(
    artifact_id,
    root,
    packet=_EXACT,
    *,
    catalog=_EXACT,
    lane=_EXACT,
    plan=_EXACT,
):
    """Call the one public PR323 operation with the exact confirmations."""
    supplied = ready_packet() if packet is _EXACT else packet
    if plan is _EXACT:
        plan = canonical_plan_sha256(supplied) if isinstance(supplied, dict) else ""
    return link_persisted_approved_change_to_windows_runtime_reconcile_plan(
        artifact_id,
        supplied,
        data_dir=root,
        confirm_capability_catalog_identity_sha256=(
            catalog_identity() if catalog is _EXACT else catalog
        ),
        confirm_lane_declaration_identity_sha256=(lane_identity() if lane is _EXACT else lane),
        confirm_plan_sha256=plan,
    )


def supported_artifact(root: Path):
    return publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)


def bind(artifact_id, root):
    return construct_persisted_approved_change_capability_binding(
        artifact_id,
        data_dir=root,
        confirm_capability_catalog_identity_sha256=catalog_identity(),
        confirm_lane_declaration_identity_sha256=lane_identity(),
    )


def assert_never_expands(result) -> None:
    """The fields PR323 may never claim, on any status whatsoever."""
    assert result.read_only is True
    assert result.mutation_performed is False
    assert result.artifact_write_performed is False
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.approval_selected is False
    assert result.approval_created is False
    assert result.approval_persisted is False
    assert result.contract_created is False
    assert result.contract_persisted is False
    assert result.binding_persisted is False
    assert result.plan_link_persisted is False
    assert result.plan_packet_written is False
    assert result.subject_semantic_compatibility_evaluated is False
    assert result.target_compatibility_evaluated is False
    assert result.procedure_compatibility_evaluated is False
    assert result.evidence_compatibility_evaluated is False
    assert result.current_state_preflight_evaluated is False
    assert result.authorization_evaluated is False
    assert result.preflight_evaluated is False
    assert result.receipt_created is False
    assert result.receipt_linked is False
    assert result.host_configuration_mutation_performed is False
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"
    assert result.warnings == PERMANENT_PLAN_LINK_WARNINGS


def assert_no_link(result) -> None:
    """No failure may ever return a partial link."""
    assert result.plan_link is None
    assert result.plan_linked is False
    assert result.link_complete is False
    assert result.plan_link_identity_sha256 == ""
    assert_never_expands(result)


def serialized(result) -> str:
    return json.dumps(result.model_dump(mode="json"), ensure_ascii=False)


def assert_no_host_paths(result, *extra: str) -> None:
    text = serialized(result)
    for token in (*HOST_PATH_TOKENS, *extra):
        assert token not in text, token
    assert "Traceback" not in text


class WriteWatch:
    """Fail loudly on any write-capable primitive PR323 could reach."""

    def __init__(self, monkeypatch) -> None:
        self.calls: list[str] = []
        real_open = builtins.open

        def guarded_open(file, mode="r", *args, **kwargs):
            if any(flag in mode for flag in ("w", "a", "x", "+")):
                self.calls.append("open(write)")
                raise AssertionError("a write-capable open was reached")
            return real_open(file, mode, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", guarded_open)

        real_os_open = os.open

        def guarded_os_open(path, flags, *args, **kwargs):
            writable = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
            if flags & writable:
                self.calls.append("os.open(write)")
                raise AssertionError("a write-capable os.open was reached")
            return real_os_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", guarded_os_open)
        for name in (
            "mkdir",
            "makedirs",
            "rename",
            "replace",
            "unlink",
            "remove",
            "rmdir",
            "truncate",
            "link",
            "symlink",
        ):
            if hasattr(os, name):
                monkeypatch.setattr(os, name, self._raiser(f"os.{name}"))
        for name in ("write_text", "write_bytes", "mkdir", "unlink", "rmdir", "rename", "replace"):
            monkeypatch.setattr(Path, name, self._raiser(f"Path.{name}"))
        for name in (
            "NamedTemporaryFile",
            "TemporaryFile",
            "TemporaryDirectory",
            "mkdtemp",
            "mkstemp",
        ):
            monkeypatch.setattr(tempfile, name, self._raiser(f"tempfile.{name}"))

    def _raiser(self, name):
        def boom(*args, **kwargs):
            self.calls.append(name)
            raise AssertionError(f"{name} was reached; PR323 is read-only")

        return boom


@pytest.fixture
def binding_watch(monkeypatch):
    """Fail loudly if the maintained PR322 operation is called at all."""
    seen: list[str] = []

    def boom(*args, **kwargs):
        seen.append("binding")
        raise AssertionError("the PR322 binding operation was called before confirmation succeeded")

    monkeypatch.setattr(link_module, "construct_persisted_approved_change_capability_binding", boom)
    return seen


def injected_binding_result(root: Path, **binding_overrides):
    """One real PR322 result, minimally reshaped to exercise a refusal path."""
    artifact = supported_artifact(root)
    real = bind(artifact.approval_artifact_id, root)
    assert real.status == "capability_binding_constructed"
    if not binding_overrides:
        return real
    binding = real.binding.model_copy(update=binding_overrides)
    validation = real.binding_validation.model_copy(
        update={"status": "capability_binding_valid", "binding_valid": True}
    )
    return real.model_copy(
        update={
            "binding": binding,
            "binding_validation": validation,
            "capability_id": binding.capability_id,
            "lane_id": binding.lane_id,
        }
    )


# --------------------------------------------------------------------------
# Maintained plan authority
# --------------------------------------------------------------------------


def test_the_maintained_plan_validator_and_identity_are_used(tmp_path, monkeypatch):
    calls: list[str] = []
    real = link_module.validate_saved_windows_runtime_reconcile_plan_packet

    def spy(packet):
        calls.append("validate")
        return real(packet)

    monkeypatch.setattr(link_module, "validate_saved_windows_runtime_reconcile_plan_packet", spy)
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    packet = ready_packet()
    result = link(artifact.approval_artifact_id, root, packet)
    assert result.status == "plan_link_constructed"
    assert calls == ["validate"]
    assert result.plan_sha256 == canonical_plan_sha256(packet) == READY_PLAN_SHA256


def test_the_committed_plan_fixtures_hash_to_their_fixed_identities():
    assert canonical_plan_sha256(ready_packet()) == READY_PLAN_SHA256
    assert canonical_plan_sha256(no_change_packet()) == NO_CHANGE_PLAN_SHA256
    assert READY_PLAN_SHA256 != NO_CHANGE_PLAN_SHA256


def test_an_exact_ready_packet_is_accepted(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    result = link(artifact.approval_artifact_id, root, ready_packet())
    assert result.status == "plan_link_constructed"
    assert result.plan_status == "ready"


def test_an_exact_no_change_packet_is_accepted(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    packet = no_change_packet()
    result = link(artifact.approval_artifact_id, root, packet)
    assert result.status == "plan_link_constructed"
    assert result.plan_status == "no_change"
    assert result.plan_sha256 == NO_CHANGE_PLAN_SHA256


def _reordered_allowlist_packet():
    packet = ready_packet()
    packet["allowlist"] = list(reversed(packet["allowlist"]))
    return packet


def _widened_allowlist_packet():
    packet = ready_packet()
    packet["allowlist"] = [*packet["allowlist"], {"source": "x/y.txt", "destination": "z/y.txt"}]
    return packet


def _extra_operation_packet():
    operations = [
        plan_operation(0, "replace_required", STALE_DESTINATION_SHA256),
        plan_operation(1, "no_change", WRAPPER_SOURCE_SHA256),
        plan_operation(1, "no_change", WRAPPER_SOURCE_SHA256),
    ]
    return plan_packet(status="ready", operations=operations)


def _invalid_hash_packet():
    packet = ready_packet()
    packet["operations"][0]["source_sha256"] = "NOTAHASH"
    packet["operations"][0]["expected_post_change_sha256"] = "NOTAHASH"
    return packet


def _unsafe_safety_packet():
    packet = ready_packet()
    packet["safety"]["execution_available"] = True
    return packet


def _wrong_parent_version_packet():
    packet = ready_packet()
    packet["destination_parent_contract_version"] = 2
    return packet


@pytest.mark.parametrize(
    "packet_factory,label",
    [
        (blocked_packet, "blocked"),
        (unsupported_packet, "unsupported"),
        (lambda: {"mode": PLAN_MODE}, "malformed"),
        (lambda: ready_packet(mode="windows_runtime_reconcile_execute"), "wrong mode"),
        (lambda: ready_packet(recipe_id="windows.runtime_reconcile.v2"), "wrong recipe"),
        (_reordered_allowlist_packet, "reordered allowlist"),
        (_widened_allowlist_packet, "widened allowlist"),
        (_extra_operation_packet, "extra operation"),
        (_wrong_parent_version_packet, "wrong parent contract version"),
        (_invalid_hash_packet, "invalid hash"),
        (_unsafe_safety_packet, "unsafe safety flags"),
        (lambda: ready_packet(schema_version=2), "wrong schema version"),
    ],
)
def test_packets_the_maintained_validator_refuses_are_never_linked(tmp_path, packet_factory, label):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    packet = packet_factory()
    result = link(artifact.approval_artifact_id, root, packet)
    assert result.status == "plan_not_accepted", label
    assert result.plan_validated is False
    assert result.plan_validation_status == "plan_packet_rejected"
    assert result.filesystem_accessed is False
    assert result.capability_binding_evaluated is False
    assert result.errors
    assert_no_link(result)


@pytest.mark.parametrize("supplied", [None, "packet", 7, [], ()])
def test_a_non_mapping_plan_is_invalid_input(tmp_path, supplied):
    root = data_dir(tmp_path)
    result = link(UNPUBLISHED_ARTIFACT_ID, root, supplied, plan=HEX64)
    assert result.status == "invalid_plan_link_input"
    assert result.plan_validated is False
    assert result.filesystem_accessed is False
    assert_no_link(result)


def test_the_supplied_plan_mapping_is_never_mutated(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    packet = ready_packet()
    before = json.dumps(packet, sort_keys=True, ensure_ascii=False)
    result = link(artifact.approval_artifact_id, root, packet)
    assert result.status == "plan_link_constructed"
    assert json.dumps(packet, sort_keys=True, ensure_ascii=False) == before


def test_the_full_plan_packet_is_never_returned(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    result = link(artifact.approval_artifact_id, root, ready_packet())
    dumped = result.model_dump(mode="json")
    assert "operations" not in dumped
    assert "allowlist" not in dumped
    assert "summary" not in dumped
    assert "gates" not in dumped
    assert "safety" not in dumped


# --------------------------------------------------------------------------
# Confirmation gates
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [None, "", " ", HEX64.upper(), f"sha256:{HEX64}", HEX64[:-1], 7])
def test_a_malformed_plan_confirmation_is_refused_before_any_access(
    tmp_path, monkeypatch, binding_watch, bad
):
    root = data_dir(tmp_path)
    FsWatch(monkeypatch)
    result = link(UNPUBLISHED_ARTIFACT_ID, root, ready_packet(), plan=bad)
    assert result.status == "invalid_plan_link_input"
    assert result.plan_validated is True
    assert result.plan_identity_confirmed is False
    assert result.filesystem_accessed is False
    assert result.capability_support_evaluated is False
    assert result.capability_binding_evaluated is False
    assert result.capability_bound is False
    assert result.plan_link_evaluated is False
    assert binding_watch == []
    assert_no_link(result)


@pytest.mark.parametrize("bad", [None, "", HEX64.upper(), f"catalog:{HEX64}", HEX64[:10]])
def test_a_malformed_catalog_confirmation_is_refused_before_any_access(
    tmp_path, monkeypatch, binding_watch, bad
):
    root = data_dir(tmp_path)
    FsWatch(monkeypatch)
    result = link(UNPUBLISHED_ARTIFACT_ID, root, ready_packet(), catalog=bad)
    assert result.status == "invalid_plan_link_input"
    assert result.filesystem_accessed is False
    assert binding_watch == []
    assert_no_link(result)


@pytest.mark.parametrize("bad", [None, "", HEX64.upper(), f"lane:{HEX64}", HEX64[:10]])
def test_a_malformed_lane_confirmation_is_refused_before_any_access(
    tmp_path, monkeypatch, binding_watch, bad
):
    root = data_dir(tmp_path)
    FsWatch(monkeypatch)
    result = link(UNPUBLISHED_ARTIFACT_ID, root, ready_packet(), lane=bad)
    assert result.status == "invalid_plan_link_input"
    assert result.filesystem_accessed is False
    assert binding_watch == []
    assert_no_link(result)


def test_a_wrong_plan_sha_is_refused_before_any_access(tmp_path, monkeypatch, binding_watch):
    root = data_dir(tmp_path)
    FsWatch(monkeypatch)
    result = link(UNPUBLISHED_ARTIFACT_ID, root, ready_packet(), plan=OTHER_HEX64)
    assert result.status == "plan_confirmation_mismatch"
    assert result.plan_validated is True
    assert result.plan_identity_confirmed is False
    assert result.confirmed_plan_sha256 == OTHER_HEX64
    assert result.plan_sha256 == READY_PLAN_SHA256
    assert result.filesystem_accessed is False
    assert binding_watch == []
    assert_no_link(result)


def test_the_no_change_plan_sha_does_not_confirm_the_ready_plan(
    tmp_path, monkeypatch, binding_watch
):
    root = data_dir(tmp_path)
    FsWatch(monkeypatch)
    result = link(UNPUBLISHED_ARTIFACT_ID, root, ready_packet(), plan=NO_CHANGE_PLAN_SHA256)
    assert result.status == "plan_confirmation_mismatch"
    assert binding_watch == []
    assert_no_link(result)


def test_a_stale_catalog_identity_is_refused_before_any_access(
    tmp_path, monkeypatch, binding_watch
):
    root = data_dir(tmp_path)
    FsWatch(monkeypatch)
    result = link(UNPUBLISHED_ARTIFACT_ID, root, ready_packet(), catalog=OTHER_HEX64)
    assert result.status == "capability_catalog_confirmation_mismatch"
    assert result.plan_identity_confirmed is True
    assert result.filesystem_accessed is False
    assert binding_watch == []
    assert_no_link(result)


def test_a_stale_lane_identity_is_refused_before_any_access(tmp_path, monkeypatch, binding_watch):
    root = data_dir(tmp_path)
    FsWatch(monkeypatch)
    result = link(UNPUBLISHED_ARTIFACT_ID, root, ready_packet(), lane=OTHER_HEX64)
    assert result.status == "lane_declaration_confirmation_mismatch"
    assert result.plan_identity_confirmed is True
    assert result.filesystem_accessed is False
    assert binding_watch == []
    assert_no_link(result)


def test_swapped_identity_confirmations_are_refused(tmp_path, monkeypatch, binding_watch):
    root = data_dir(tmp_path)
    FsWatch(monkeypatch)
    result = link(
        UNPUBLISHED_ARTIFACT_ID,
        root,
        ready_packet(),
        catalog=lane_identity(),
        lane=catalog_identity(),
    )
    assert result.status == "capability_catalog_confirmation_mismatch"
    assert binding_watch == []
    assert_no_link(result)


def test_the_plan_sha_is_never_accepted_as_a_catalog_or_lane_confirmation(
    tmp_path, monkeypatch, binding_watch
):
    root = data_dir(tmp_path)
    FsWatch(monkeypatch)
    plan_sha = canonical_plan_sha256(ready_packet())
    assert link(UNPUBLISHED_ARTIFACT_ID, root, ready_packet(), catalog=plan_sha).status == (
        "capability_catalog_confirmation_mismatch"
    )
    assert link(UNPUBLISHED_ARTIFACT_ID, root, ready_packet(), lane=plan_sha).status == (
        "lane_declaration_confirmation_mismatch"
    )
    assert binding_watch == []


def test_a_random_sha_confirms_nothing(tmp_path, monkeypatch, binding_watch):
    root = data_dir(tmp_path)
    FsWatch(monkeypatch)
    noise = hashlib.sha256(b"pr323-noise").hexdigest()
    assert link(UNPUBLISHED_ARTIFACT_ID, root, ready_packet(), plan=noise).status == (
        "plan_confirmation_mismatch"
    )
    assert binding_watch == []


def test_exact_confirmations_reach_the_maintained_binding_operation(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    result = link(artifact.approval_artifact_id, root, ready_packet())
    assert result.status == "plan_link_constructed"
    assert result.confirmed_plan_sha256 == result.plan_sha256
    assert result.confirmed_capability_catalog_identity_sha256 == catalog_identity()
    assert result.confirmed_lane_declaration_identity_sha256 == lane_identity()


def test_confirmations_are_compared_with_compare_digest():
    source = Path(link_module.__file__).read_text(encoding="utf-8")
    assert source.count("hmac.compare_digest") >= 3
    assert "==" in source  # sanity: the file is real source, not an empty stub


# --------------------------------------------------------------------------
# The successful link
# --------------------------------------------------------------------------


def test_a_supported_approval_and_ready_plan_produce_one_exact_link(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    binding = bind(artifact.approval_artifact_id, root)
    before = snapshot(publication_root(root))

    packet = ready_packet()
    result = link(artifact.approval_artifact_id, root, packet)

    assert result.status == "plan_link_constructed"
    assert result.reason
    assert result.link_complete is True
    assert result.requested_approval_artifact_id == artifact.approval_artifact_id
    assert result.errors == ()

    assert result.plan_validated is True
    assert result.plan_validation_status == "plan_packet_accepted"
    assert result.plan_identity_confirmed is True
    assert result.plan_sha256 == READY_PLAN_SHA256
    assert result.plan_status == "ready"
    assert result.plan_mode == PLAN_MODE
    assert result.plan_recipe_id == RECIPE_ID
    assert result.destination_parent_contract_version == PARENT_CONTRACT_VERSION == 1

    assert result.capability_support_evaluated is True
    assert result.capability_supported is True
    assert result.capability_binding_evaluated is True
    assert result.capability_bound is True
    assert result.capability_binding_identity_sha256 == binding.binding_identity_sha256
    assert result.capability_id == WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID
    assert result.lane_id == WINDOWS_RUNTIME_RECONCILE_LANE_ID

    assert result.plan_link_evaluated is True
    assert result.plan_linked is True
    assert result.filesystem_accessed is True

    stored = result.plan_link
    assert isinstance(stored, ApprovedChangeWindowsRuntimeReconcilePlanLink)
    assert stored.approval_artifact_id == artifact.approval_artifact_id
    assert stored.subject_sha256 == artifact.subject_sha256
    assert stored.capability_binding_identity_sha256 == binding.binding_identity_sha256
    assert stored.plan_sha256 == READY_PLAN_SHA256
    assert stored.plan_status == "ready"
    assert stored.comparison_scope == PLAN_LINK_COMPARISON_SCOPE
    assert result.plan_link_validation.link_valid is True

    assert snapshot(publication_root(root)) == before
    assert_never_expands(result)
    assert_no_host_paths(result, str(root))


def test_a_supported_approval_and_no_change_plan_produce_one_exact_link(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    before = snapshot(publication_root(root))
    result = link(artifact.approval_artifact_id, root, no_change_packet())
    assert result.status == "plan_link_constructed"
    assert result.plan_status == "no_change"
    assert result.plan_link.plan_status == "no_change"
    assert result.plan_sha256 == NO_CHANGE_PLAN_SHA256
    assert snapshot(publication_root(root)) == before
    assert_never_expands(result)


def test_a_no_change_link_grants_no_execution_eligibility(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    result = link(artifact.approval_artifact_id, root, no_change_packet())
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"
    assert result.current_state_preflight_evaluated is False


def test_the_committed_link_fixtures_are_exact(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    assert artifact.approval_artifact_id == SUPPORTED_LINK_APPROVAL_ARTIFACT_ID
    assert artifact.subject_sha256 == SUPPORTED_LINK_SUBJECT_SHA256
    result = link(artifact.approval_artifact_id, root, ready_packet())
    assert result.capability_binding_identity_sha256 == SUPPORTED_BINDING_IDENTITY_SHA256
    assert result.plan_link_canonical_byte_length == READY_LINK_BYTE_LENGTH
    assert result.plan_link_identity_sha256 == READY_LINK_IDENTITY_SHA256


def test_repeated_links_are_byte_identical(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    first = link(artifact.approval_artifact_id, root, ready_packet())
    second = link(artifact.approval_artifact_id, root, ready_packet())
    assert canonical_approved_change_plan_link_json(
        first.plan_link
    ) == canonical_approved_change_plan_link_json(second.plan_link)
    assert first.plan_link_identity_sha256 == second.plan_link_identity_sha256
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_canonical_link_bytes_carry_no_bom_no_newline_and_compact_separators(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    canonical = canonical_approved_change_plan_link_json(
        link(artifact.approval_artifact_id, root, ready_packet()).plan_link
    )
    encoded = canonical.encode("utf-8")
    assert not encoded.startswith(b"\xef\xbb\xbf")
    assert not canonical.endswith("\n")
    assert "\r" not in canonical
    assert ", " not in canonical and ": " not in canonical


def test_the_canonical_payload_sorts_keys_and_carries_nothing_derived(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    stored = link(artifact.approval_artifact_id, root, ready_packet()).plan_link
    payload = canonical_approved_change_plan_link_payload(stored)
    assert list(payload) == sorted(payload)
    assert set(payload) == {
        "approval_artifact_id",
        "approval_artifact_identity_sha256",
        "capability_binding_identity_sha256",
        "capability_catalog_identity_sha256",
        "capability_id",
        "comparison_scope",
        "destination_parent_contract_version",
        "lane_declaration_identity_sha256",
        "lane_id",
        "link_type",
        "plan_mode",
        "plan_recipe_id",
        "plan_sha256",
        "plan_status",
        "schema_version",
        "subject_sha256",
    }
    assert payload["schema_version"] == PLAN_LINK_SCHEMA_VERSION == "1"
    assert payload["link_type"] == PLAN_LINK_TYPE
    for forbidden in (
        "plan_link_identity_sha256",
        "staged_source_root",
        "durable_runtime_root",
        "source_path",
        "destination_path",
        "backup_path_pattern",
        "created_at",
        "timestamp",
        "host",
        "user",
        "authorization",
        "receipt_id",
        "execution_status",
    ):
        assert forbidden not in payload


def test_the_link_identity_is_sha256_of_its_exact_canonical_utf8_bytes(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    stored = link(artifact.approval_artifact_id, root, ready_packet()).plan_link
    canonical = canonical_approved_change_plan_link_json(stored)
    assert compute_approved_change_plan_link_sha256(stored) == (
        hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    )


# --------------------------------------------------------------------------
# Identity behaviour
# --------------------------------------------------------------------------


def test_the_same_binding_and_a_different_valid_plan_change_the_link_identity(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    ready = link(artifact.approval_artifact_id, root, ready_packet())
    no_change = link(artifact.approval_artifact_id, root, no_change_packet())
    assert ready.plan_sha256 != no_change.plan_sha256
    assert ready.capability_binding_identity_sha256 == no_change.capability_binding_identity_sha256
    assert ready.plan_link_identity_sha256 != no_change.plan_link_identity_sha256


def test_a_different_approved_subject_changes_the_link_identity(tmp_path):
    root = data_dir(tmp_path)
    first = supported_artifact(root)
    second = publish_for(alternate_supported_bundle(), root)
    assert first.subject_sha256 != second.subject_sha256

    packet = ready_packet()
    one = link(first.approval_artifact_id, root, packet)
    two = link(second.approval_artifact_id, root, packet)
    assert one.status == two.status == "plan_link_constructed"
    assert one.plan_sha256 == two.plan_sha256
    assert one.capability_binding_identity_sha256 != two.capability_binding_identity_sha256
    assert one.plan_link_identity_sha256 != two.plan_link_identity_sha256


def test_the_link_identity_differs_from_every_upstream_identity(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    result = link(artifact.approval_artifact_id, root, ready_packet())
    identity = result.plan_link_identity_sha256
    for upstream in (
        artifact.subject_sha256,
        artifact.approval_artifact_identity_sha256,
        artifact.source_bundle_identity_sha256,
        catalog_identity(),
        lane_identity(),
        result.capability_binding_identity_sha256,
        result.plan_sha256,
    ):
        assert identity != upstream


# --------------------------------------------------------------------------
# Unsupported and mismatched bindings
# --------------------------------------------------------------------------


def test_an_unsupported_capability_produces_no_link(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(UNKNOWN_CAPABILITY_ID), root)
    result = link(artifact.approval_artifact_id, root, ready_packet())
    assert result.status == "capability_binding_not_available"
    assert result.capability_bound is False
    assert result.plan_identity_confirmed is True
    assert_no_link(result)


@pytest.mark.parametrize("capability", NEAR_MISS_CAPABILITY_IDS)
def test_a_near_miss_capability_produces_no_link(tmp_path, capability):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(capability), root)
    result = link(artifact.approval_artifact_id, root, ready_packet())
    assert result.status == "capability_binding_not_available"
    assert_no_link(result)


def test_an_unpublished_artifact_produces_no_link(tmp_path):
    root = data_dir(tmp_path)
    result = link(UNPUBLISHED_ARTIFACT_ID, root, ready_packet())
    assert result.status == "plan_link_blocked"
    assert result.capability_bound is False
    assert_no_link(result)
    assert_no_host_paths(result, str(root))


def test_a_binding_capability_that_is_not_the_plan_recipe_blocks(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    injected = injected_binding_result(root, capability_id="example.other_capability")
    monkeypatch.setattr(
        link_module,
        "construct_persisted_approved_change_capability_binding",
        lambda *a, **k: injected,
    )
    result = link(SUPPORTED_LINK_APPROVAL_ARTIFACT_ID, root, ready_packet())
    assert result.status == "binding_plan_mismatch"
    assert result.plan_link_evaluated is True
    assert_no_link(result)


def test_a_binding_lane_that_is_not_the_maintained_lane_blocks(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    injected = injected_binding_result(root, lane_id="pr999.other_lane")
    monkeypatch.setattr(
        link_module,
        "construct_persisted_approved_change_capability_binding",
        lambda *a, **k: injected,
    )
    result = link(SUPPORTED_LINK_APPROVAL_ARTIFACT_ID, root, ready_packet())
    assert result.status == "binding_plan_mismatch"
    assert_no_link(result)


@pytest.mark.parametrize(
    "update",
    [
        {"binding_complete": False},
        {"binding_created": False},
        {"binding": None},
    ],
)
def test_an_incomplete_pr322_result_blocks(tmp_path, monkeypatch, update):
    root = data_dir(tmp_path)
    real = injected_binding_result(root)
    monkeypatch.setattr(
        link_module,
        "construct_persisted_approved_change_capability_binding",
        lambda *a, **k: real.model_copy(update=update),
    )
    result = link(SUPPORTED_LINK_APPROVAL_ARTIFACT_ID, root, ready_packet())
    assert result.status == "plan_link_blocked"
    assert_no_link(result)


def test_an_injected_pr322_failure_blocks(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    real = injected_binding_result(root)
    monkeypatch.setattr(
        link_module,
        "construct_persisted_approved_change_capability_binding",
        lambda *a, **k: real.model_copy(
            update={"status": "capability_binding_blocked", "binding": None}
        ),
    )
    result = link(SUPPORTED_LINK_APPROVAL_ARTIFACT_ID, root, ready_packet())
    assert result.status == "plan_link_blocked"
    assert_no_link(result)


def test_an_invalid_pr322_binding_validation_blocks(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    real = injected_binding_result(root)
    broken = real.binding_validation.model_copy(
        update={"status": "capability_binding_invalid", "binding_valid": False}
    )
    monkeypatch.setattr(
        link_module,
        "construct_persisted_approved_change_capability_binding",
        lambda *a, **k: real.model_copy(update={"binding_validation": broken}),
    )
    result = link(SUPPORTED_LINK_APPROVAL_ARTIFACT_ID, root, ready_packet())
    assert result.status == "plan_link_blocked"
    assert_no_link(result)


def test_pr322_is_the_only_binding_authority(tmp_path, monkeypatch):
    """PR323 must never construct a competing binding of its own."""
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    calls: list[tuple] = []
    real = link_module.construct_persisted_approved_change_capability_binding

    def spy(artifact_id, **kwargs):
        calls.append((artifact_id, tuple(sorted(kwargs))))
        return real(artifact_id, **kwargs)

    monkeypatch.setattr(link_module, "construct_persisted_approved_change_capability_binding", spy)
    result = link(artifact.approval_artifact_id, root, ready_packet())
    assert result.status == "plan_link_constructed"
    assert len(calls) == 1
    assert calls[0][0] == artifact.approval_artifact_id
    assert calls[0][1] == (
        "confirm_capability_catalog_identity_sha256",
        "confirm_lane_declaration_identity_sha256",
        "data_dir",
    )
    source = module_code_without_strings(link_module)
    assert "ApprovedChangeCapabilityBinding(" not in source


def test_no_caller_supplied_binding_contract_or_declaration_is_accepted():
    import inspect

    signature = inspect.signature(link_persisted_approved_change_to_windows_runtime_reconcile_plan)
    assert list(signature.parameters) == [
        "approval_artifact_id",
        "plan_packet",
        "data_dir",
        "confirm_capability_catalog_identity_sha256",
        "confirm_lane_declaration_identity_sha256",
        "confirm_plan_sha256",
    ]
    for forbidden in (
        "binding",
        "contract",
        "artifact",
        "lane_declaration",
        "catalog",
        "inventory",
        "plan_path",
        "packet_path",
        "out_json",
        "staged_source_root",
        "durable_runtime_root",
        "authorization",
        "receipt",
        "confirm_execute",
    ):
        assert forbidden not in signature.parameters


# --------------------------------------------------------------------------
# Structural comparison scope only
# --------------------------------------------------------------------------


def test_two_materially_different_subjects_link_to_the_same_plan_structurally(tmp_path):
    """The essential proof that PR323 implemented no semantic interpretation."""
    root = data_dir(tmp_path)
    first = supported_artifact(root)
    second = publish_for(alternate_supported_bundle(), root)

    subject_one = first.contract.subject
    subject_two = second.contract.subject
    assert subject_one.capability_id == subject_two.capability_id
    assert subject_one.model_dump(mode="json") != subject_two.model_dump(mode="json")

    packet = ready_packet()
    one = link(first.approval_artifact_id, root, packet)
    two = link(second.approval_artifact_id, root, packet)

    assert one.status == two.status == "plan_link_constructed"
    assert one.plan_link_identity_sha256 != two.plan_link_identity_sha256
    for result in (one, two):
        assert result.subject_semantic_compatibility_evaluated is False
        assert result.target_compatibility_evaluated is False
        assert result.procedure_compatibility_evaluated is False
        assert result.evidence_compatibility_evaluated is False
        assert result.current_state_preflight_evaluated is False
        assert "plan link does not validate target semantics" in result.warnings
        assert "plan link does not validate procedure semantics" in result.warnings
        assert "plan link is not current-state preflight" in result.warnings
        assert "plan link does not validate PR304 evidence freshness" in result.warnings


def test_no_broad_full_compatibility_field_exists(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    dumped = link(artifact.approval_artifact_id, root, ready_packet()).model_dump(mode="json")
    for forbidden in (
        "subject_fully_compatible",
        "fully_compatible",
        "compatible",
        "ready_to_execute",
        "safe_to_run",
        "eligible",
    ):
        assert forbidden not in dumped


def test_no_free_text_subject_field_is_read_or_reported(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    result = link(artifact.approval_artifact_id, root, ready_packet())
    text = serialized(result)
    subject = artifact.contract.subject.model_dump(mode="json")
    for field in ("target", "procedure", "diagnosis", "desired_outcome", "rollback_posture"):
        value = subject.get(field)
        if isinstance(value, str) and value:
            assert value not in text


def test_every_permanent_warning_is_present_on_every_status(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    results = [
        link(artifact.approval_artifact_id, root, ready_packet()),
        link(artifact.approval_artifact_id, root, blocked_packet()),
        link(artifact.approval_artifact_id, root, ready_packet(), plan=OTHER_HEX64),
        link(artifact.approval_artifact_id, root, ready_packet(), catalog=OTHER_HEX64),
        link(UNPUBLISHED_ARTIFACT_ID, root, ready_packet()),
    ]
    assert {result.status for result in results} == {
        "plan_link_constructed",
        "plan_not_accepted",
        "plan_confirmation_mismatch",
        "capability_catalog_confirmation_mismatch",
        "plan_link_blocked",
    }
    for result in results:
        assert result.warnings == PERMANENT_PLAN_LINK_WARNINGS
        for phrase in (
            "in-memory identity association only",
            "is not authorization",
            "is not current-state preflight",
            "does not inspect the live staged source",
            "does not inspect the live durable runtime",
            "does not inspect System32",
            "does not validate target semantics",
            "does not validate procedure semantics",
            "does not validate PR304 evidence freshness",
            "does not prove preconditions remain true",
            "does not create or link a receipt",
            "grants no execution eligibility",
            "does not invoke PR313 execution",
            "an exact aca_ approval-artifact ID remains required",
            "no approval was selected through inventory",
            "self-asserted metadata",
            "no CLI or natural-language plan-link or execution route exists",
        ):
            assert any(phrase in warning for warning in result.warnings), phrase


# --------------------------------------------------------------------------
# Confidentiality
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "packet_factory",
    [ready_packet, no_change_packet, blocked_packet, unsupported_packet],
)
def test_no_host_path_from_the_packet_ever_reaches_a_result(tmp_path, packet_factory):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    result = link(artifact.approval_artifact_id, root, packet_factory())
    text = serialized(result)
    for token in (
        "staged_source_root",
        "durable_runtime_root",
        "source_path",
        "destination_path",
        "backup_path_pattern",
        "config/profiles/inspect.yaml",
        "scripts/windows/sfai.cmd",
        "bin/sfai.cmd",
        "C:\\",
        "C:/",
        "c:\\",
        "\\\\",
        str(root),
        str(root.resolve()),
    ):
        assert token not in text, token
    assert_no_host_paths(result, str(root))


def test_only_safe_fixed_values_and_hashes_are_reported(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    dumped = link(artifact.approval_artifact_id, root, ready_packet()).plan_link.model_dump(
        mode="json"
    )
    assert dumped["capability_id"] == WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID
    assert dumped["lane_id"] == WINDOWS_RUNTIME_RECONCILE_LANE_ID
    assert dumped["plan_mode"] == PLAN_MODE
    assert dumped["plan_recipe_id"] == RECIPE_ID
    for key in (
        "approval_artifact_identity_sha256",
        "subject_sha256",
        "capability_binding_identity_sha256",
        "capability_catalog_identity_sha256",
        "lane_declaration_identity_sha256",
        "plan_sha256",
    ):
        assert len(dumped[key]) == 64
        assert set(dumped[key]) <= set("0123456789abcdef")


def test_validator_failures_never_leak_a_host_path(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    result = link(artifact.approval_artifact_id, root, blocked_packet())
    assert result.status == "plan_not_accepted"
    assert result.errors
    joined = " ".join(result.errors)
    for token in (STAGED_SOURCE_ROOT, DURABLE_RUNTIME_ROOT, "C:\\", str(root)):
        assert token not in joined


# --------------------------------------------------------------------------
# No writes and no hidden expansion
# --------------------------------------------------------------------------


def test_no_write_capable_primitive_is_ever_reached(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    before = snapshot(publication_root(root))
    watch = WriteWatch(monkeypatch)
    result = link(artifact.approval_artifact_id, root, ready_packet())
    assert result.status == "plan_link_constructed"
    assert watch.calls == []
    assert snapshot(publication_root(root)) == before


_FORBIDDEN_MODULE_ATTRS = (
    ("shellforgeai.core.windows_runtime_reconcile_execution", "execute_windows_runtime_reconcile"),
    ("shellforgeai.core.windows_runtime_reconcile_execution", "write_execution_receipt"),
    ("shellforgeai.core.windows_runtime_reconcile_execution", "validate_saved_receipt"),
    (
        "shellforgeai.core.approved_change_approval_inventory",
        "inventory_persisted_approved_change_approval_artifacts",
    ),
)


def test_no_pr313_execution_receipt_verification_or_inventory_path_is_reached(
    tmp_path, monkeypatch
):
    import importlib

    reached: list[str] = []
    for module_name, attribute in _FORBIDDEN_MODULE_ATTRS:
        module = importlib.import_module(module_name)
        if hasattr(module, attribute):

            def boom(*args, _label=f"{module_name}.{attribute}", **kwargs):
                reached.append(_label)
                raise AssertionError(f"{_label} was reached; PR323 must never call it")

            monkeypatch.setattr(module, attribute, boom)

    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    assert link(artifact.approval_artifact_id, root, ready_packet()).status == (
        "plan_link_constructed"
    )
    assert reached == []


def test_no_shell_network_docker_model_clock_or_randomness_path_is_reached(tmp_path, monkeypatch):
    calls: list[str] = []

    def raiser(label):
        def boom(*args, **kwargs):
            calls.append(label)
            raise AssertionError(f"{label} was reached; PR323 must never use it")

        return boom

    monkeypatch.setattr(subprocess, "run", raiser("subprocess.run"))
    monkeypatch.setattr(subprocess, "Popen", raiser("subprocess.Popen"))
    monkeypatch.setattr(os, "system", raiser("os.system"))
    monkeypatch.setattr(os, "popen", raiser("os.popen"))
    monkeypatch.setattr(socket, "socket", raiser("socket.socket"))
    monkeypatch.setattr(socket, "gethostname", raiser("socket.gethostname"))
    monkeypatch.setattr(time, "time", raiser("time.time"))
    monkeypatch.setattr(uuid, "uuid4", raiser("uuid.uuid4"))
    monkeypatch.setattr(random, "random", raiser("random.random"))
    monkeypatch.setattr(platform, "system", raiser("platform.system"))
    monkeypatch.setattr(platform, "node", raiser("platform.node"))
    if hasattr(os, "getlogin"):
        monkeypatch.setattr(os, "getlogin", raiser("os.getlogin"))

    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    assert link(artifact.approval_artifact_id, root, ready_packet()).status == (
        "plan_link_constructed"
    )
    assert calls == []


def test_no_environment_variable_changes_the_link(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    baseline = link(artifact.approval_artifact_id, root, ready_packet())
    for name, value in (
        ("SHELLFORGEAI_PROFILE", "danger"),
        ("USER", "someone-else"),
        ("COMPUTERNAME", "WIN2025-SFAI01"),
        ("TZ", "UTC+9"),
    ):
        monkeypatch.setenv(name, value)
    repeat = link(artifact.approval_artifact_id, root, ready_packet())
    assert repeat.plan_link_identity_sha256 == baseline.plan_link_identity_sha256
    assert repeat.model_dump(mode="json") == baseline.model_dump(mode="json")


# --------------------------------------------------------------------------
# Cross-platform parity
# --------------------------------------------------------------------------


def test_cross_platform_parity_of_plan_and_link_bytes_and_identity(tmp_path):
    """These exact values must hold byte for byte on Linux and on Windows."""
    assert canonical_plan_sha256(ready_packet()) == READY_PLAN_SHA256
    assert canonical_plan_sha256(no_change_packet()) == NO_CHANGE_PLAN_SHA256

    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    result = link(artifact.approval_artifact_id, root, ready_packet())
    canonical = canonical_approved_change_plan_link_json(result.plan_link)
    assert "\r" not in canonical
    assert len(canonical.encode("utf-8")) == READY_LINK_BYTE_LENGTH
    assert result.plan_link_canonical_byte_length == READY_LINK_BYTE_LENGTH
    assert result.plan_link_identity_sha256 == READY_LINK_IDENTITY_SHA256
    assert result.status == "plan_link_constructed"
    assert result.warnings == PERMANENT_PLAN_LINK_WARNINGS
    assert_never_expands(result)

    no_change = link(artifact.approval_artifact_id, root, no_change_packet())
    assert no_change.plan_link_identity_sha256 == NO_CHANGE_LINK_IDENTITY_SHA256


def test_the_link_never_depends_on_the_path_separator_of_the_running_host(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    with_path = link(artifact.approval_artifact_id, root, ready_packet())
    with_string = link_persisted_approved_change_to_windows_runtime_reconcile_plan(
        artifact.approval_artifact_id,
        ready_packet(),
        data_dir=str(root),
        confirm_capability_catalog_identity_sha256=catalog_identity(),
        confirm_lane_declaration_identity_sha256=lane_identity(),
        confirm_plan_sha256=READY_PLAN_SHA256,
    )
    assert with_string.status == "plan_link_constructed"
    assert with_string.plan_link_identity_sha256 == with_path.plan_link_identity_sha256


# --------------------------------------------------------------------------
# Immutability, validation, and structured failures
# --------------------------------------------------------------------------


def test_the_link_the_validation_and_the_result_are_all_frozen(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    result = link(artifact.approval_artifact_id, root, ready_packet())
    for model, field, value in (
        (result, "status", "plan_link_constructed"),
        (result.plan_link, "plan_status", "ready"),
        (result.plan_link_validation, "link_valid", True),
    ):
        with pytest.raises(ValidationError):
            setattr(model, field, value)


def test_unknown_fields_are_refused_on_every_model():
    with pytest.raises(ValidationError):
        ApprovedChangeWindowsRuntimeReconcilePlanLink.model_validate(
            {**_valid_link_payload(), "extra": 1}
        )
    with pytest.raises(ValidationError):
        ApprovedChangePlanLinkResult.model_validate({"status": "plan_link_constructed", "x": 1})
    with pytest.raises(ValidationError):
        ApprovedChangePlanLinkValidationResult.model_validate(
            {"status": "approved_change_plan_link_valid", "link_valid": True, "x": 1}
        )


def _valid_link_payload(**overrides):
    payload = {
        "schema_version": "1",
        "link_type": PLAN_LINK_TYPE,
        "approval_artifact_id": f"{APPROVAL_ARTIFACT_ID_PREFIX}{HEX64}",
        "approval_artifact_identity_sha256": HEX64,
        "subject_sha256": OTHER_HEX64,
        "capability_binding_identity_sha256": "a" * 64,
        "capability_catalog_identity_sha256": "b" * 64,
        "capability_id": WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
        "lane_declaration_identity_sha256": "c" * 64,
        "lane_id": WINDOWS_RUNTIME_RECONCILE_LANE_ID,
        "plan_mode": PLAN_MODE,
        "plan_recipe_id": RECIPE_ID,
        "plan_sha256": "d" * 64,
        "plan_status": "ready",
        "destination_parent_contract_version": 1,
        "comparison_scope": PLAN_LINK_COMPARISON_SCOPE,
    }
    payload.update(overrides)
    return payload


def test_a_well_formed_payload_validates():
    result = validate_approved_change_plan_link(_valid_link_payload())
    assert result.status == "approved_change_plan_link_valid"
    assert result.link_valid is True
    assert len(result.plan_link_identity_sha256) == 64
    assert result.canonical_byte_length > 0


@pytest.mark.parametrize(
    "overrides",
    [
        {"capability_id": "example.other"},
        {"lane_id": "pr999.other"},
        {"plan_mode": "windows_runtime_reconcile_execute"},
        {"plan_recipe_id": "windows.runtime_reconcile.v2"},
        {"plan_status": "blocked"},
        {"plan_status": "unsupported"},
        {"destination_parent_contract_version": 2},
        {"plan_sha256": "NOTAHASH"},
        {"subject_sha256": HEX64.upper()},
    ],
)
def test_a_malformed_payload_is_invalid(overrides):
    result = validate_approved_change_plan_link(_valid_link_payload(**overrides))
    assert result.status == "approved_change_plan_link_invalid"
    assert result.link_valid is False
    assert result.errors


@pytest.mark.parametrize("supplied", [None, "link", 7, [], ()])
def test_validation_input_that_is_not_a_link_is_structured_not_raised(supplied):
    result = validate_approved_change_plan_link(supplied)
    assert result.status == "invalid_approved_change_plan_link_validation_input"
    assert result.link_valid is False


def test_validation_cross_checks_the_supplied_binding_and_plan(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    binding_result = bind(artifact.approval_artifact_id, root)
    plan_validation = validate_saved_windows_runtime_reconcile_plan_packet(ready_packet())
    stored = link(artifact.approval_artifact_id, root, ready_packet()).plan_link

    assert (
        validate_approved_change_plan_link(
            stored, binding=binding_result.binding, plan_validation=plan_validation
        ).link_valid
        is True
    )

    other = validate_saved_windows_runtime_reconcile_plan_packet(no_change_packet())
    mismatched = validate_approved_change_plan_link(
        stored, binding=binding_result.binding, plan_validation=other
    )
    assert mismatched.link_valid is False
    assert mismatched.errors


def test_the_binding_identity_cross_check_is_recomputed(tmp_path):
    root = data_dir(tmp_path)
    artifact = supported_artifact(root)
    binding_result = bind(artifact.approval_artifact_id, root)
    stored = link(artifact.approval_artifact_id, root, ready_packet()).plan_link
    assert stored.capability_binding_identity_sha256 == (
        compute_approved_change_capability_binding_sha256(binding_result.binding)
    )
    assert validate_approved_change_capability_binding(binding_result.binding).binding_valid


def test_errors_are_immutable_sorted_and_deduplicated(tmp_path):
    root = data_dir(tmp_path)
    result = link(UNPUBLISHED_ARTIFACT_ID, root, blocked_packet())
    assert isinstance(result.errors, tuple)
    assert list(result.errors) == sorted(set(result.errors))


def test_no_failure_raises_or_leaks_a_traceback(tmp_path):
    root = data_dir(tmp_path)
    for packet, plan, catalog in (
        (blocked_packet(), _EXACT, _EXACT),
        (ready_packet(), OTHER_HEX64, _EXACT),
        (ready_packet(), _EXACT, OTHER_HEX64),
        ({"broken": True}, HEX64, _EXACT),
    ):
        result = link(UNPUBLISHED_ARTIFACT_ID, root, packet, plan=plan, catalog=catalog)
        assert isinstance(result, ApprovedChangePlanLinkResult)
        assert "Traceback" not in serialized(result)
        assert_no_link(result)


def test_every_declared_status_is_reachable_or_declared():
    assert set(PLAN_LINK_STATUSES) == {
        "plan_link_constructed",
        "plan_not_accepted",
        "plan_confirmation_mismatch",
        "capability_catalog_confirmation_mismatch",
        "lane_declaration_confirmation_mismatch",
        "capability_binding_not_available",
        "binding_plan_mismatch",
        "plan_link_blocked",
        "invalid_plan_link_input",
        "plan_link_validation_failed",
    }
    assert set(PLAN_LINK_VALIDATION_STATUSES) == {
        "approved_change_plan_link_valid",
        "approved_change_plan_link_invalid",
        "invalid_approved_change_plan_link_validation_input",
    }


# --------------------------------------------------------------------------
# Static boundaries
# --------------------------------------------------------------------------


def test_static_the_import_set_is_exactly_the_maintained_dependencies():
    tree = ast.parse(Path(link_module.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    assert imported == {
        "__future__",
        "collections.abc",
        "hashlib",
        "hmac",
        "json",
        "pathlib",
        "pydantic",
        "shellforgeai.core.approved_change_capability_binding",
        "shellforgeai.core.approved_change_capability_support",
        "shellforgeai.core.windows_runtime_reconcile_plan_contract",
        "typing",
    }


def test_static_no_forbidden_boundary_token_appears():
    source = module_code_without_strings(link_module)
    for token in (
        "approved_change_approval_inventory",
        "inventory_persisted",
        "core.approvals",
        "Proposal",
        "recipe_registry",
        "windows_runtime_reconcile_execution",
        "execute_windows_runtime_reconcile",
        "write_execution_receipt",
        "validate_saved_receipt",
        "verify_windows_runtime_reconcile",
        "load_validators",
        "load_helper_module",
        "subprocess",
        "socket",
        "requests",
        "httpx",
        "docker",
        "compose",
        "powershell",
        "winrm",
        "credential",
        "secret",
        "token",
        "datetime",
        "uuid",
        "random",
        "getlogin",
        "gethostname",
        "environ",
        "getenv",
        "mkdir",
        "makedirs",
        "write_text",
        "write_bytes",
        "read_text",
        "read_bytes",
        "open(",
        "os.",
        "latest",
        "most_recent",
        "most recent",
        "resolve_current",
    ):
        assert token not in source, token


def test_static_the_pure_plan_contract_reaches_no_boundary_at_all():
    from shellforgeai.core import windows_runtime_reconcile_plan_contract as plan_contract

    source = module_code_without_strings(plan_contract)
    for token in (
        "open(",
        "os.",
        "Path(",
        "pathlib",
        "mkdir",
        "makedirs",
        "write_bytes",
        "write_text",
        "read_bytes",
        "read_text",
        "subprocess",
        "socket",
        "platform",
        "datetime",
        "uuid",
        "random",
        "environ",
        "execute",
        "receipt",
        "backup",
        "compensat",
    ):
        assert token not in source, token


def test_the_module_is_not_imported_by_cli_approvals_recipes_or_execution():
    offenders = [
        str(path)
        for base in (Path("src/shellforgeai/cli"), Path("src/shellforgeai/core"))
        for path in base.rglob("*.py")
        if path.name
        not in {
            "approved_change_plan_link.py",
            "approved_change_plan_current_state.py",
            "approved_change_plan_link_artifact_persistence.py",
        }
        and "approved_change_plan_link" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_no_cli_surface_was_added():
    cli = Path("docs/cli.md").read_text(encoding="utf-8")
    assert "plan-link" not in cli
    assert "approved_change_plan_link" not in cli
    offenders = [
        str(path)
        for path in Path("src/shellforgeai/cli").rglob("*.py")
        if "plan_link" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_no_new_persisted_artifact_was_introduced():
    layout = Path("docs/data-layout.md").read_text(encoding="utf-8")
    assert "plan_link" not in layout
    assert "plan-link" not in layout


def test_importing_the_module_touches_nothing(tmp_path, monkeypatch):
    import importlib

    calls: list[str] = []
    monkeypatch.chdir(tmp_path)
    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append("subprocess.run"))
    monkeypatch.setattr(os, "system", lambda *a, **k: calls.append("os.system"))
    monkeypatch.setattr(socket, "socket", lambda *a, **k: calls.append("socket"))
    sys.modules.pop("shellforgeai.core.approved_change_plan_link", None)
    importlib.import_module("shellforgeai.core.approved_change_plan_link")
    assert sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")) == before
    assert calls == []


def test_the_public_surface_is_exactly_the_maintained_operations():
    public = {
        name
        for name in dir(link_module)
        if not name.startswith("_") and callable(getattr(link_module, name))
    }
    expected_owned = {
        "canonical_approved_change_plan_link_json",
        "canonical_approved_change_plan_link_payload",
        "compute_approved_change_plan_link_sha256",
        "link_persisted_approved_change_to_windows_runtime_reconcile_plan",
        "validate_approved_change_plan_link",
    }
    assert expected_owned <= public
    for forbidden in (
        "publish_approved_change_plan_link",
        "load_persisted_approved_change_plan_link",
        "inventory_approved_change_plan_links",
        "authorize_approved_change_plan_link",
        "preflight_approved_change_plan_link",
        "execute_approved_change_plan_link",
    ):
        assert forbidden not in public
