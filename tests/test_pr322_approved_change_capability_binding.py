"""Focused PR322 tests: approved-change capability binding.

PR309 owns the subject schema, the subject identity, the attestation, the
contract, approval-binding verification, the capability-ID syntax, and
``validate_approved_change_contract``. PR316 owns the reviewed bundle. PR317
owns the governed bundle publisher and its exact-ID loader. PR318 owns the one
read-only approval-binding operation. PR319 owns the canonical approval
artifact, the ``aca_`` identity, the fixed ``approved_change_approvals``
subtree, and the exact-ID approval-artifact loader. PR320 owns bounded
read-only discovery. PR321 owns the capability-support catalog and the support
decision.

These tests prove PR322 adds exactly one thing on top of those maintained
contracts: one immutable, deterministic, in-memory association between one
exact approved subject identity and one exact source-maintained named PR313
lane declaration.

A binding is an identity association only. It is not authorization, target or
procedure compatibility, PR304/PR305 evidence compatibility, subject-to-plan
agreement, current-state readiness, preflight, receipt linkage, or execution.
"""

from __future__ import annotations

import ast
import builtins
import hashlib
import inspect
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

# The PR316 focused suite owns the maintained reviewed-context fixtures, the
# PR319 focused suite owns the maintained publication helpers, and the PR321
# focused suite owns the maintained capability fixtures. All three are reused
# verbatim so PR322 never invents its own context, subject, bundle, approval,
# artifact, or catalog schema.
from test_pr319_approved_change_approval_artifact_persistence import (  # noqa: E402
    FIXTURE_A_APPROVAL_ARTIFACT_ID,
    FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256,
    artifact_for,
    bundle_a,
    data_dir,
    module_code_without_strings,
    publication_root,
    snapshot,
    write_artifact_directory,
)
from test_pr321_approved_change_capability_support import (  # noqa: E402
    MAINTAINED_CATALOG_CANONICAL_JSON,
    NEAR_MISS_CAPABILITY_IDS,
    UNKNOWN_CAPABILITY_ID,
    FsWatch,
    alternate_supported_bundle,
    capability_bundle,
    catalog_identity,
    publish_for,
)

from shellforgeai.core import approved_change_capability_binding as binding_module
from shellforgeai.core.approvals import Proposal
from shellforgeai.core.approved_change_approval_artifact import (
    APPROVAL_ARTIFACT_ID_PREFIX,
    APPROVED_CHANGE_APPROVAL_FILENAME,
)
from shellforgeai.core.approved_change_approval_persistence import (
    load_persisted_approved_change_approval_artifact,
)
from shellforgeai.core.approved_change_capability_binding import (
    BINDING_SCOPE_EXACT_SUBJECT_TO_EXACT_LANE_ONLY,
    BINDING_STATUS_DECLARED_BINDABLE,
    BINDING_STATUSES,
    BINDING_VALIDATION_STATUSES,
    CAPABILITY_BINDING_SCHEMA_VERSION,
    CAPABILITY_BINDING_TYPE,
    IMPLEMENTATION_SCOPE_WINDOWS_TWO_FILE_ONLY,
    LANE_DECLARATION_VALIDATION_STATUSES,
    LANE_KIND_NAMED_GOVERNED_IMPLEMENTATION_LANE,
    PERMANENT_CAPABILITY_BINDING_WARNINGS,
    WINDOWS_RUNTIME_RECONCILE_LANE_ID,
    ApprovedChangeCapabilityBinding,
    ApprovedChangeCapabilityBindingResult,
    ApprovedChangeCapabilityBindingValidationResult,
    ApprovedChangeCapabilityLaneDeclaration,
    ApprovedChangeCapabilityLaneDeclarationValidationResult,
    canonical_approved_change_capability_binding_json,
    canonical_approved_change_capability_binding_payload,
    canonical_capability_lane_declaration_json,
    canonical_capability_lane_declaration_payload,
    compute_approved_change_capability_binding_sha256,
    compute_capability_lane_declaration_sha256,
    construct_persisted_approved_change_capability_binding,
    maintained_windows_runtime_reconcile_lane_declaration,
    validate_approved_change_capability_binding,
    validate_capability_lane_declaration,
)
from shellforgeai.core.approved_change_capability_support import (
    MATCH_RULE_EXACT_CAPABILITY_ID_ONLY,
    WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
    compute_approved_change_capability_support_catalog_sha256,
    evaluate_persisted_approved_change_capability_support,
    maintained_approved_change_capability_support_catalog,
    validate_approved_change_capability_support_catalog,
)

# --------------------------------------------------------------------------
# Committed fixed-fixture values
#
# These are the exact expected Linux and Windows canonical bytes and identities
# of the updated PR321 catalog, the one maintained lane declaration, and the
# binding produced for the maintained supported fixture. They are recorded here
# so any declaration, ordering, encoding, schema, or policy drift fails loudly
# on either platform instead of silently changing what ShellForgeAI binds.
# --------------------------------------------------------------------------

UPDATED_CATALOG_BYTE_LENGTH = 464
UPDATED_CATALOG_IDENTITY_SHA256 = "762d8263642289f4c7230e0e4c625720c3cee461c6f229a724a8b2e15cc0786d"

LANE_DECLARATION_BYTE_LENGTH = 550
LANE_DECLARATION_IDENTITY_SHA256 = (
    "3f94c038a65f9af863fce646342e8f06f4c25b3a417736aff941b3bccd7b5316"
)
LANE_DECLARATION_CANONICAL_JSON = (
    '{"authorization_available":false,"binding_persistence_available":false,'
    '"binding_scope":"exact_approved_subject_to_exact_named_lane_declaration_only",'
    '"binding_status":"declared_bindable","capability_id":"windows.runtime_reconcile",'
    '"execution_available":false,'
    '"implementation_scope":"windows_exact_two_file_runtime_reconciliation_only",'
    '"lane_id":"pr313.windows_runtime_reconcile",'
    '"lane_kind":"named_governed_implementation_lane",'
    '"match_rule":"exact_capability_id_only","preflight_available":false,'
    '"receipt_linkage_available":false,"schema_version":"1"}'
)

#: The exact binding produced for the maintained supported fixture. Every field
#: is deterministic, so the whole payload and its identity are fixed fixtures.
SUPPORTED_BINDING_APPROVAL_ARTIFACT_ID = (
    "aca_c6ba9c51e9efa77c9df355cb87e0c5ceebd580a81c327a7a4806ce0ee7240f9f"
)
SUPPORTED_BINDING_SUBJECT_SHA256 = (
    "f643bdcf2d5674a8d9b1771e5e60af7f962e2b0ee73c24833113f973102fcc96"
)
SUPPORTED_BINDING_BYTE_LENGTH = 803
SUPPORTED_BINDING_IDENTITY_SHA256 = (
    "08a396a106aad7fdedf6491137631456ab9d8a1722d9582f69ddd44b15ab3c81"
)

HEX64 = "0123456789abcdef" * 4
OTHER_HEX64 = "fedcba9876543210" * 4
UNPUBLISHED_ARTIFACT_ID = f"{APPROVAL_ARTIFACT_ID_PREFIX}{HEX64}"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def lane_identity() -> str:
    return compute_capability_lane_declaration_sha256(
        maintained_windows_runtime_reconcile_lane_declaration()
    )


_EXACT = object()


def bind(artifact_id, root, *, catalog=_EXACT, lane=_EXACT):
    return construct_persisted_approved_change_capability_binding(
        artifact_id,
        data_dir=root,
        confirm_capability_catalog_identity_sha256=(
            catalog_identity() if catalog is _EXACT else catalog
        ),
        confirm_lane_declaration_identity_sha256=(lane_identity() if lane is _EXACT else lane),
    )


def lane_payload(**overrides):
    payload = {
        "schema_version": "1",
        "capability_id": WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
        "lane_id": WINDOWS_RUNTIME_RECONCILE_LANE_ID,
        "lane_kind": LANE_KIND_NAMED_GOVERNED_IMPLEMENTATION_LANE,
        "binding_status": BINDING_STATUS_DECLARED_BINDABLE,
        "match_rule": MATCH_RULE_EXACT_CAPABILITY_ID_ONLY,
        "binding_scope": BINDING_SCOPE_EXACT_SUBJECT_TO_EXACT_LANE_ONLY,
        "implementation_scope": IMPLEMENTATION_SCOPE_WINDOWS_TWO_FILE_ONLY,
        "binding_persistence_available": False,
        "authorization_available": False,
        "preflight_available": False,
        "receipt_linkage_available": False,
        "execution_available": False,
    }
    payload.update(overrides)
    return payload


def binding_payload(**overrides):
    payload = {
        "schema_version": "1",
        "binding_type": CAPABILITY_BINDING_TYPE,
        "approval_artifact_id": f"{APPROVAL_ARTIFACT_ID_PREFIX}{HEX64}",
        "approval_artifact_identity_sha256": HEX64,
        "subject_sha256": OTHER_HEX64,
        "capability_catalog_identity_sha256": UPDATED_CATALOG_IDENTITY_SHA256,
        "capability_id": WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
        "lane_declaration_identity_sha256": LANE_DECLARATION_IDENTITY_SHA256,
        "lane_id": WINDOWS_RUNTIME_RECONCILE_LANE_ID,
        "binding_scope": BINDING_SCOPE_EXACT_SUBJECT_TO_EXACT_LANE_ONLY,
        "implementation_scope": IMPLEMENTATION_SCOPE_WINDOWS_TWO_FILE_ONLY,
    }
    payload.update(overrides)
    return payload


def assert_never_expands(result) -> None:
    """The fields PR322 may never claim, on any status whatsoever."""
    assert result.read_only is True
    assert result.mutation_performed is False
    assert result.artifact_write_performed is False
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.binding_persisted is False
    assert result.authorization_evaluated is False
    assert result.preflight_evaluated is False
    assert result.receipt_created is False
    assert result.receipt_linked is False
    assert result.host_configuration_mutation_performed is False
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"
    assert result.warnings == PERMANENT_CAPABILITY_BINDING_WARNINGS


def assert_binding_never_expands(result) -> None:
    assert_never_expands(result)
    assert result.approval_selected is False
    assert result.approval_created is False
    assert result.approval_persisted is False
    assert result.contract_created is False
    assert result.contract_persisted is False
    assert result.source_bundle_mutation_performed is False
    assert result.overwrite_performed is False


def assert_no_host_paths(result, root: Path) -> None:
    text = json.dumps(result.model_dump(mode="json"), ensure_ascii=False)
    assert str(root) not in text
    assert str(root.resolve()) not in text
    assert "Traceback" not in text


@pytest.fixture
def authority_watch(monkeypatch):
    """Fail loudly if either maintained authority is reached at all."""
    seen: list[str] = []

    def boom(name):
        def raiser(*args, **kwargs):
            seen.append(name)
            raise AssertionError(f"{name} was called before both confirmations succeeded")

        return raiser

    monkeypatch.setattr(
        binding_module,
        "evaluate_persisted_approved_change_capability_support",
        boom("pr321_evaluator"),
    )
    monkeypatch.setattr(
        binding_module,
        "load_persisted_approved_change_approval_artifact",
        boom("pr319_loader"),
    )
    return seen


class AuthoritySpy:
    """Record every maintained PR321 and PR319 call PR322 makes."""

    def __init__(self, monkeypatch, *, support=None, load=None):
        self.support_calls: list[tuple] = []
        self.load_calls: list[tuple] = []
        real_support = evaluate_persisted_approved_change_capability_support
        real_load = load_persisted_approved_change_approval_artifact

        def support_spy(artifact_id, *, data_dir, confirm_capability_catalog_identity_sha256):
            self.support_calls.append(
                (artifact_id, data_dir, confirm_capability_catalog_identity_sha256)
            )
            result = real_support(
                artifact_id,
                data_dir=data_dir,
                confirm_capability_catalog_identity_sha256=(
                    confirm_capability_catalog_identity_sha256
                ),
            )
            return result if support is None else result.model_copy(update=support)

        def load_spy(artifact_id, *, data_dir):
            self.load_calls.append((artifact_id, data_dir))
            result = real_load(artifact_id, data_dir=data_dir)
            return result if load is None else result.model_copy(update=load)

        monkeypatch.setattr(
            binding_module,
            "evaluate_persisted_approved_change_capability_support",
            support_spy,
        )
        monkeypatch.setattr(
            binding_module,
            "load_persisted_approved_change_approval_artifact",
            load_spy,
        )


# --------------------------------------------------------------------------
# The updated PR321 capability-support catalog
# --------------------------------------------------------------------------


def test_the_updated_catalog_still_holds_exactly_one_declaration():
    catalog = maintained_approved_change_capability_support_catalog()
    assert len(catalog.declarations) == 1
    (declaration,) = catalog.declarations
    assert declaration.capability_id == WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID
    assert declaration.support_status == "declared_supported"
    assert declaration.match_rule == "exact_capability_id_only"
    assert declaration.validation_scope == "approved_change_contract_validation_only"


def test_capability_binding_availability_is_the_only_field_pr322_flipped():
    (declaration,) = maintained_approved_change_capability_support_catalog().declarations
    assert declaration.capability_binding_available is True
    assert declaration.authorization_available is False
    assert declaration.preflight_available is False
    assert declaration.receipt_linkage_available is False
    assert declaration.execution_available is False


def test_the_updated_catalog_bytes_and_identity_are_the_committed_fixtures():
    catalog = maintained_approved_change_capability_support_catalog()
    canonical = MAINTAINED_CATALOG_CANONICAL_JSON
    assert '"capability_binding_available":true' in canonical
    assert len(canonical.encode("utf-8")) == UPDATED_CATALOG_BYTE_LENGTH == 464
    assert (
        compute_approved_change_capability_support_catalog_sha256(catalog)
        == UPDATED_CATALOG_IDENTITY_SHA256
    )
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == (
        UPDATED_CATALOG_IDENTITY_SHA256
    )


def test_the_updated_catalog_still_validates_and_is_deterministic():
    catalog = maintained_approved_change_capability_support_catalog()
    results = [validate_approved_change_capability_support_catalog(catalog) for _ in range(4)]
    for result in results:
        assert result.status == "capability_support_catalog_valid"
        assert result.errors == ()
        assert result.declaration_count == 1
        assert result.capability_ids == (WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,)
        assert result.canonical_byte_length == UPDATED_CATALOG_BYTE_LENGTH
        assert result.catalog_identity_sha256 == UPDATED_CATALOG_IDENTITY_SHA256


def test_the_stale_pre_pr322_catalog_identity_fails_closed(tmp_path, monkeypatch, authority_watch):
    stale = "7dcf112b0807bd7388912b5b1cf59f2be8c0d5b30ec6fa0d05265d88b936da61"
    assert stale != UPDATED_CATALOG_IDENTITY_SHA256
    watch = FsWatch(monkeypatch)
    result = bind(UNPUBLISHED_ARTIFACT_ID, tmp_path, catalog=stale)
    assert result.status == "capability_catalog_confirmation_mismatch"
    assert result.filesystem_accessed is False
    assert result.capability_bound is False
    assert watch.calls == []
    assert authority_watch == []


# --------------------------------------------------------------------------
# The maintained lane declaration
# --------------------------------------------------------------------------


def test_every_lane_declaration_field_has_its_exact_expected_value():
    declaration = maintained_windows_runtime_reconcile_lane_declaration()
    assert declaration.model_dump(mode="python") == {
        "schema_version": "1",
        "capability_id": "windows.runtime_reconcile",
        "lane_id": "pr313.windows_runtime_reconcile",
        "lane_kind": "named_governed_implementation_lane",
        "binding_status": "declared_bindable",
        "match_rule": "exact_capability_id_only",
        "binding_scope": "exact_approved_subject_to_exact_named_lane_declaration_only",
        "implementation_scope": "windows_exact_two_file_runtime_reconciliation_only",
        "binding_persistence_available": False,
        "authorization_available": False,
        "preflight_available": False,
        "receipt_linkage_available": False,
        "execution_available": False,
    }


def test_every_lane_availability_field_is_false():
    declaration = maintained_windows_runtime_reconcile_lane_declaration()
    assert declaration.binding_persistence_available is False
    assert declaration.authorization_available is False
    assert declaration.preflight_available is False
    assert declaration.receipt_linkage_available is False
    assert declaration.execution_available is False


def test_the_maintained_lane_accessor_returns_the_exact_same_immutable_declaration():
    first = maintained_windows_runtime_reconcile_lane_declaration()
    second = maintained_windows_runtime_reconcile_lane_declaration()
    assert first is second
    assert first == second


def test_canonical_lane_json_matches_the_committed_fixture():
    declaration = maintained_windows_runtime_reconcile_lane_declaration()
    canonical = canonical_capability_lane_declaration_json(declaration)
    assert canonical == LANE_DECLARATION_CANONICAL_JSON
    assert len(canonical.encode("utf-8")) == LANE_DECLARATION_BYTE_LENGTH


def test_lane_identity_is_sha256_of_the_exact_canonical_utf8_bytes():
    declaration = maintained_windows_runtime_reconcile_lane_declaration()
    canonical = canonical_capability_lane_declaration_json(declaration)
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert compute_capability_lane_declaration_sha256(declaration) == expected
    assert expected == LANE_DECLARATION_IDENTITY_SHA256


def test_repeated_lane_builds_are_byte_identical():
    values = {
        canonical_capability_lane_declaration_json(
            maintained_windows_runtime_reconcile_lane_declaration()
        )
        for _ in range(8)
    }
    assert values == {LANE_DECLARATION_CANONICAL_JSON}


def test_lane_canonical_bytes_carry_no_bom_no_trailing_newline_and_compact_separators():
    canonical = canonical_capability_lane_declaration_json(
        maintained_windows_runtime_reconcile_lane_declaration()
    )
    encoded = canonical.encode("utf-8")
    assert not encoded.startswith(b"\xef\xbb\xbf")
    assert not canonical.endswith("\n")
    assert ", " not in canonical
    assert ": " not in canonical
    assert canonical == canonical.strip()
    assert "\r" not in canonical


def test_lane_canonical_payload_sorts_mapping_keys_and_carries_nothing_derived():
    payload = canonical_capability_lane_declaration_payload(
        maintained_windows_runtime_reconcile_lane_declaration()
    )
    assert list(payload) == sorted(payload)
    serialized = json.dumps(payload)
    assert LANE_DECLARATION_IDENTITY_SHA256 not in serialized
    assert "lane_declaration_identity" not in serialized
    assert "byte_length" not in serialized


def test_lane_ensure_ascii_is_off_and_separators_are_compact():
    source = inspect.getsource(canonical_capability_lane_declaration_json)
    assert "ensure_ascii=False" in source
    assert 'separators=(",", ":")' in source
    assert "sort_keys=True" in source


def test_no_timestamp_host_platform_environment_or_randomness_affects_lane_identity(monkeypatch):
    baseline = compute_capability_lane_declaration_sha256(
        maintained_windows_runtime_reconcile_lane_declaration()
    )
    monkeypatch.setenv("SFAI_DATA_DIR", "/somewhere/else")
    monkeypatch.setenv("HOSTNAME", "another-host")
    monkeypatch.setattr(time, "time", lambda: 1.0)
    monkeypatch.setattr(platform, "system", lambda: "Plan9")
    monkeypatch.setattr(platform, "node", lambda: "other-node")
    monkeypatch.setattr(random, "random", lambda: 0.5)
    assert (
        compute_capability_lane_declaration_sha256(
            maintained_windows_runtime_reconcile_lane_declaration()
        )
        == baseline
        == LANE_DECLARATION_IDENTITY_SHA256
    )
    source = module_code_without_strings(binding_module)
    for token in (
        "time.time",
        "time.monotonic",
        "datetime",
        "os.environ",
        "os.getenv",
        "getlogin",
        "gethostname",
        "uuid",
        "random",
        "secrets",
        "platform.",
    ):
        assert token not in source, token


# --------------------------------------------------------------------------
# Lane-declaration validation
# --------------------------------------------------------------------------


def test_the_maintained_lane_declaration_validates_successfully():
    result = validate_capability_lane_declaration(
        maintained_windows_runtime_reconcile_lane_declaration()
    )
    assert result.status == "capability_lane_declaration_valid"
    assert result.declaration_valid is True
    assert result.errors == ()
    assert result.capability_id == WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID
    assert result.lane_id == WINDOWS_RUNTIME_RECONCILE_LANE_ID
    assert result.lane_declaration_identity_sha256 == LANE_DECLARATION_IDENTITY_SHA256
    assert result.canonical_byte_length == LANE_DECLARATION_BYTE_LENGTH
    assert_never_expands(result)
    assert result.filesystem_accessed is False
    assert result.capability_binding_evaluated is False
    assert result.capability_bound is False
    assert result.binding_created is False


def test_the_exact_maintained_lane_payload_validates_from_a_mapping():
    result = validate_capability_lane_declaration(lane_payload())
    assert result.status == "capability_lane_declaration_valid"
    assert result.lane_declaration_identity_sha256 == LANE_DECLARATION_IDENTITY_SHA256


@pytest.mark.parametrize(
    "overrides",
    [
        {"schema_version": "2"},
        {"schema_version": 1},
        {"schema_version": ""},
        {"capability_id": "windows.runtime_reconcile.v2"},
        {"capability_id": "windows.runtime-reconcile"},
        {"capability_id": "Windows.runtime_reconcile"},
        {"capability_id": "*"},
        {"capability_id": " windows.runtime_reconcile"},
        {"capability_id": ""},
        {"capability_id": None},
        {"lane_id": "windows.runtime_reconcile"},
        {"lane_id": "pr313.windows_runtime_reconcile.v2"},
        {"lane_id": "PR313.windows_runtime_reconcile"},
        {"lane_id": "*"},
        {"lane_id": ""},
        {"lane_kind": "recipe"},
        {"lane_kind": "named_governed_implementation_lane_v2"},
        {"binding_status": "bound"},
        {"binding_status": "declared_bindable_preview"},
        {"match_rule": "prefix_match"},
        {"binding_scope": "any_approved_subject_to_any_lane"},
        {"implementation_scope": "windows_runtime_reconciliation"},
        {"implementation_scope": ""},
    ],
)
def test_malformed_lane_declaration_fields_are_invalid(overrides):
    result = validate_capability_lane_declaration(lane_payload(**overrides))
    assert result.status == "capability_lane_declaration_invalid"
    assert result.declaration_valid is False
    assert result.errors


@pytest.mark.parametrize(
    "field",
    [
        "binding_persistence_available",
        "authorization_available",
        "preflight_available",
        "receipt_linkage_available",
        "execution_available",
    ],
)
def test_any_lane_availability_field_set_true_is_invalid(field):
    result = validate_capability_lane_declaration(lane_payload(**{field: True}))
    assert result.status == "capability_lane_declaration_invalid"
    assert result.declaration_valid is False
    assert any(field in item and "must be false" in item for item in result.errors)


def test_a_lane_availability_field_set_true_on_the_model_is_still_rejected():
    declaration = ApprovedChangeCapabilityLaneDeclaration(
        capability_id=WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
        lane_id=WINDOWS_RUNTIME_RECONCILE_LANE_ID,
        execution_available=True,
    )
    result = validate_capability_lane_declaration(declaration)
    assert result.status == "capability_lane_declaration_invalid"
    assert any("execution_available must be false" in item for item in result.errors)


def test_extra_lane_declaration_fields_are_refused():
    result = validate_capability_lane_declaration(lane_payload(extra_field="x"))
    assert result.status == "capability_lane_declaration_invalid"
    assert result.declaration_valid is False
    with pytest.raises(ValidationError):
        ApprovedChangeCapabilityLaneDeclaration(
            capability_id=WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
            lane_id=WINDOWS_RUNTIME_RECONCILE_LANE_ID,
            extra="x",
        )


@pytest.mark.parametrize("value", [None, "lane", b"lane", 1, 1.5, True, [], (), ["lane_id"]])
def test_structurally_impossible_lane_input_is_reported_separately(value):
    result = validate_capability_lane_declaration(value)
    assert result.status == "invalid_capability_lane_declaration_input"
    assert result.declaration_valid is False
    assert result.lane_declaration_identity_sha256 == ""


def test_lane_validation_statuses_are_exactly_the_maintained_set():
    assert set(LANE_DECLARATION_VALIDATION_STATUSES) == {
        "capability_lane_declaration_valid",
        "capability_lane_declaration_invalid",
        "invalid_capability_lane_declaration_input",
    }


def test_the_lane_declaration_is_never_derived_from_the_repository(monkeypatch):
    """No registry, module, script, path, or environment feeds the declaration."""
    baseline = maintained_windows_runtime_reconcile_lane_declaration()
    monkeypatch.setenv("SFAI_LANE_ID", "attacker.lane")

    def boom(*args, **kwargs):
        raise AssertionError("the lane declaration must never inspect the filesystem")

    monkeypatch.setattr(Path, "exists", boom)
    monkeypatch.setattr(Path, "glob", boom)
    assert maintained_windows_runtime_reconcile_lane_declaration() == baseline
    source = module_code_without_strings(binding_module)
    for token in (
        "recipe_registry",
        "_RECIPES",
        "importlib",
        "pkgutil",
        "entry_points",
        "glob",
        "rglob",
        "iterdir",
        "listdir",
        "scandir",
    ):
        assert token not in source, token


# --------------------------------------------------------------------------
# The binding payload and its identity
# --------------------------------------------------------------------------


def test_the_binding_canonical_payload_holds_exactly_the_maintained_keys():
    payload = canonical_approved_change_capability_binding_payload(binding_payload())
    assert set(payload) == {
        "schema_version",
        "binding_type",
        "approval_artifact_id",
        "approval_artifact_identity_sha256",
        "subject_sha256",
        "capability_catalog_identity_sha256",
        "capability_id",
        "lane_declaration_identity_sha256",
        "lane_id",
        "binding_scope",
        "implementation_scope",
    }
    assert list(payload) == sorted(payload)


def test_the_binding_payload_carries_no_derived_identity():
    binding = ApprovedChangeCapabilityBinding.model_validate(binding_payload())
    identity = compute_approved_change_capability_binding_sha256(binding)
    canonical = canonical_approved_change_capability_binding_json(binding)
    assert identity not in canonical
    assert "binding_identity" not in canonical
    assert "byte_length" not in canonical
    assert "binding_id" not in canonical
    assert not canonical.endswith("\n")
    assert ", " not in canonical
    assert ": " not in canonical
    assert not canonical.encode("utf-8").startswith(b"\xef\xbb\xbf")


def test_binding_identity_is_sha256_of_the_exact_canonical_utf8_bytes():
    binding = ApprovedChangeCapabilityBinding.model_validate(binding_payload())
    canonical = canonical_approved_change_capability_binding_json(binding)
    assert compute_approved_change_capability_binding_sha256(binding) == (
        hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    )


# --------------------------------------------------------------------------
# Successful binding
# --------------------------------------------------------------------------


def test_a_supported_approval_binds_to_the_exact_maintained_lane(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    before = snapshot(root)

    support = evaluate_persisted_approved_change_capability_support(
        artifact.approval_artifact_id,
        data_dir=root,
        confirm_capability_catalog_identity_sha256=catalog_identity(),
    )
    assert support.status == "capability_support_confirmed"

    result = bind(artifact.approval_artifact_id, root)

    assert result.status == "capability_binding_constructed"
    assert result.binding_complete is True
    assert result.requested_approval_artifact_id == artifact.approval_artifact_id
    assert result.loaded_approval_artifact_id == artifact.approval_artifact_id
    assert result.approval_artifact_load_status == "persisted_approval_artifact_loaded"
    assert result.approval_artifact_loaded is True
    assert result.approval_artifact_valid is True
    assert result.approval_binding_valid is True
    assert result.capability_support_status == "capability_support_confirmed"
    assert result.capability_id == WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID
    assert result.capability_catalog_identity_sha256 == UPDATED_CATALOG_IDENTITY_SHA256
    assert result.confirmed_capability_catalog_identity_sha256 == UPDATED_CATALOG_IDENTITY_SHA256
    assert result.lane_declaration_identity_sha256 == LANE_DECLARATION_IDENTITY_SHA256
    assert result.confirmed_lane_declaration_identity_sha256 == LANE_DECLARATION_IDENTITY_SHA256
    assert result.lane_id == WINDOWS_RUNTIME_RECONCILE_LANE_ID
    assert result.lane_declaration == maintained_windows_runtime_reconcile_lane_declaration()
    assert result.errors == ()

    binding = result.binding
    assert binding is not None
    assert binding.schema_version == CAPABILITY_BINDING_SCHEMA_VERSION == "1"
    assert binding.binding_type == CAPABILITY_BINDING_TYPE
    assert binding.approval_artifact_id == artifact.approval_artifact_id
    expected_identity = artifact.approval_artifact_identity_sha256
    assert binding.approval_artifact_identity_sha256 == expected_identity
    assert binding.subject_sha256 == artifact.subject_sha256
    assert binding.capability_catalog_identity_sha256 == UPDATED_CATALOG_IDENTITY_SHA256
    assert binding.capability_id == WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID
    assert binding.lane_declaration_identity_sha256 == LANE_DECLARATION_IDENTITY_SHA256
    assert binding.lane_id == WINDOWS_RUNTIME_RECONCILE_LANE_ID
    assert binding.binding_scope == BINDING_SCOPE_EXACT_SUBJECT_TO_EXACT_LANE_ONLY
    assert binding.implementation_scope == IMPLEMENTATION_SCOPE_WINDOWS_TWO_FILE_ONLY

    canonical = canonical_approved_change_capability_binding_json(binding)
    assert result.binding_identity_sha256 == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert result.binding_canonical_byte_length == len(canonical.encode("utf-8"))
    assert result.binding_validation is not None
    assert result.binding_validation.status == "capability_binding_valid"
    assert result.binding_validation.binding_valid is True

    assert result.capability_support_evaluated is True
    assert result.capability_supported is True
    assert result.capability_binding_evaluated is True
    assert result.capability_bound is True
    assert result.binding_created is True
    assert result.filesystem_accessed is True
    assert_binding_never_expands(result)
    assert snapshot(root) == before


def test_the_successful_binding_matches_the_committed_fixture(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    result = bind(artifact.approval_artifact_id, root)
    assert result.binding.approval_artifact_id == SUPPORTED_BINDING_APPROVAL_ARTIFACT_ID
    assert result.binding.subject_sha256 == SUPPORTED_BINDING_SUBJECT_SHA256
    assert result.binding_canonical_byte_length == SUPPORTED_BINDING_BYTE_LENGTH
    assert result.binding_identity_sha256 == SUPPORTED_BINDING_IDENTITY_SHA256


def test_a_successful_binding_never_claims_authorization_preflight_receipt_or_execution(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    result = bind(artifact.approval_artifact_id, root)
    assert result.capability_bound is True
    assert result.binding_persisted is False
    assert result.authorization_evaluated is False
    assert result.preflight_evaluated is False
    assert result.receipt_created is False
    assert result.receipt_linked is False
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"
    assert result.lane_declaration.binding_persistence_available is False
    assert result.lane_declaration.authorization_available is False
    assert result.lane_declaration.preflight_available is False
    assert result.lane_declaration.receipt_linkage_available is False
    assert result.lane_declaration.execution_available is False


def test_no_binding_artifact_is_ever_persisted(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    before = snapshot(root)
    result = bind(artifact.approval_artifact_id, root)
    assert result.status == "capability_binding_constructed"
    assert snapshot(root) == before
    payload = json.dumps(result.model_dump(mode="json"))
    for banned in ("acb_binding", "binding_artifact", "binding_path", "binding_directory"):
        assert banned not in payload
    fields = set(ApprovedChangeCapabilityBinding.model_fields)
    for banned in ("binding_id", "binding_artifact_id", "relative_binding_directory"):
        assert banned not in fields


def test_permanent_warnings_state_every_maintained_limit(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    for result in (
        bind(artifact.approval_artifact_id, root),
        bind(artifact.approval_artifact_id, root, lane="nope"),
        validate_capability_lane_declaration(
            maintained_windows_runtime_reconcile_lane_declaration()
        ),
        validate_approved_change_capability_binding(binding_payload()),
    ):
        for statement in (
            "capability binding is an in-memory identity association only",
            "capability binding is not authorization",
            "capability binding does not validate target compatibility",
            "capability binding does not validate procedure compatibility",
            "capability binding does not validate PR304 or PR305 evidence",
            "capability binding does not compare the approved subject with a PR313 plan",
            "capability binding does not evaluate current state",
            "capability binding does not run a preflight",
            "capability binding does not create or link a receipt",
            "capability binding grants no execution eligibility",
            "capability binding does not invoke PR313",
            "an exact aca_ approval-artifact ID remains required",
            "no approval was selected through inventory",
            "persisted approved_by remains self-asserted metadata, not authenticated identity",
            "no CLI or natural-language capability-binding or execution route exists",
        ):
            assert statement in result.warnings


# --------------------------------------------------------------------------
# Binding identity exactness
# --------------------------------------------------------------------------


def test_repeated_binding_of_the_same_artifact_is_identical(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    results = [bind(artifact.approval_artifact_id, root) for _ in range(5)]
    identities = {item.binding_identity_sha256 for item in results}
    payloads = {canonical_approved_change_capability_binding_json(item.binding) for item in results}
    assert len(identities) == 1
    assert len(payloads) == 1
    assert all(item.binding == results[0].binding for item in results)


def test_two_different_subjects_sharing_one_capability_get_different_binding_identities(tmp_path):
    root = data_dir(tmp_path)
    first = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    second = publish_for(alternate_supported_bundle(), root)
    assert first.subject_sha256 != second.subject_sha256

    one = bind(first.approval_artifact_id, root)
    two = bind(second.approval_artifact_id, root)

    assert one.status == two.status == "capability_binding_constructed"
    assert one.binding.capability_id == two.binding.capability_id
    assert one.binding.lane_id == two.binding.lane_id
    assert one.binding.lane_declaration_identity_sha256 == (
        two.binding.lane_declaration_identity_sha256
    )
    assert one.binding.capability_catalog_identity_sha256 == (
        two.binding.capability_catalog_identity_sha256
    )
    assert one.binding.subject_sha256 != two.binding.subject_sha256
    assert one.binding_identity_sha256 != two.binding_identity_sha256


@pytest.mark.parametrize(
    "field",
    [
        "approval_artifact_identity_sha256",
        "subject_sha256",
        "capability_catalog_identity_sha256",
        "lane_declaration_identity_sha256",
    ],
)
def test_changing_any_upstream_identity_changes_the_binding_identity(field):
    baseline = compute_approved_change_capability_binding_sha256(binding_payload())
    changed = compute_approved_change_capability_binding_sha256(
        binding_payload(
            **{field: hashlib.sha256(field.encode("utf-8")).hexdigest()},
            **(
                {
                    "approval_artifact_id": (
                        f"{APPROVAL_ARTIFACT_ID_PREFIX}"
                        f"{hashlib.sha256(field.encode('utf-8')).hexdigest()}"
                    )
                }
                if field == "approval_artifact_identity_sha256"
                else {}
            ),
        )
    )
    assert changed != baseline


def test_the_binding_identity_is_distinct_from_every_upstream_identity(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    result = bind(artifact.approval_artifact_id, root)
    identity = result.binding_identity_sha256
    assert identity not in {
        artifact.subject_sha256,
        artifact.source_bundle_identity_sha256,
        artifact.approval_artifact_identity_sha256,
        UPDATED_CATALOG_IDENTITY_SHA256,
        LANE_DECLARATION_IDENTITY_SHA256,
    }
    assert len(identity) == 64
    assert identity == identity.lower()


# --------------------------------------------------------------------------
# Unsupported capability and exact-match refusal
# --------------------------------------------------------------------------


def test_an_unknown_capability_produces_no_binding(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(bundle_a(), root)
    before = snapshot(root)

    result = bind(artifact.approval_artifact_id, root)

    assert result.status == "capability_binding_not_available"
    assert result.capability_id == UNKNOWN_CAPABILITY_ID
    assert result.capability_support_evaluated is True
    assert result.capability_supported is False
    assert result.capability_binding_evaluated is True
    assert result.capability_bound is False
    assert result.binding_created is False
    assert result.binding is None
    assert result.binding_validation is None
    assert result.binding_identity_sha256 == ""
    assert result.execution_allowed is False
    assert result.filesystem_accessed is True
    assert_binding_never_expands(result)
    assert snapshot(root) == before


@pytest.mark.parametrize("capability", NEAR_MISS_CAPABILITY_IDS)
def test_syntactically_valid_near_misses_remain_unbound(tmp_path, capability):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(capability), root)
    result = bind(artifact.approval_artifact_id, root)
    assert result.status == "capability_binding_not_available"
    assert result.capability_id == capability
    assert result.capability_supported is False
    assert result.capability_bound is False
    assert result.binding is None
    assert_binding_never_expands(result)


def test_binding_is_exact_case_sensitive_equality_only():
    lane = maintained_windows_runtime_reconcile_lane_declaration()
    for near_miss in NEAR_MISS_CAPABILITY_IDS:
        assert near_miss != lane.capability_id
    source = module_code_without_strings(binding_module)
    for token in (
        ".startswith(",
        ".endswith(",
        ".casefold()",
        ".lower()",
        ".upper()",
        "fnmatch",
        "difflib",
        "SequenceMatcher",
    ):
        if token == ".startswith(":
            # The one permitted use is the maintained PR319 aca_ prefix check.
            assert source.count(token) == 1
            continue
        assert token not in source, token


# --------------------------------------------------------------------------
# The two explicit confirmation gates
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "confirmation",
    [
        None,
        "",
        "   ",
        "not-a-hash",
        UPDATED_CATALOG_IDENTITY_SHA256.upper(),
        f"sha256:{UPDATED_CATALOG_IDENTITY_SHA256}",
        UPDATED_CATALOG_IDENTITY_SHA256[:63],
        UPDATED_CATALOG_IDENTITY_SHA256 + "0",
        f" {UPDATED_CATALOG_IDENTITY_SHA256}",
        123,
        b"a" * 64,
    ],
)
def test_a_malformed_catalog_confirmation_is_structurally_rejected(
    tmp_path, monkeypatch, authority_watch, confirmation
):
    watch = FsWatch(monkeypatch)
    result = bind(UNPUBLISHED_ARTIFACT_ID, tmp_path, catalog=confirmation)
    assert result.status == "invalid_capability_binding_input"
    assert result.binding_complete is False
    assert result.capability_support_evaluated is False
    assert result.capability_binding_evaluated is False
    assert result.capability_bound is False
    assert result.binding_created is False
    assert result.filesystem_accessed is False
    assert result.binding is None
    assert result.errors
    assert watch.calls == []
    assert authority_watch == []
    assert_binding_never_expands(result)


@pytest.mark.parametrize(
    "confirmation",
    [
        None,
        "",
        "   ",
        "not-a-hash",
        LANE_DECLARATION_IDENTITY_SHA256.upper(),
        f"lane_{LANE_DECLARATION_IDENTITY_SHA256}",
        LANE_DECLARATION_IDENTITY_SHA256[:63],
        LANE_DECLARATION_IDENTITY_SHA256 + "0",
        f" {LANE_DECLARATION_IDENTITY_SHA256}",
        123,
        b"a" * 64,
    ],
)
def test_a_malformed_lane_confirmation_is_structurally_rejected(
    tmp_path, monkeypatch, authority_watch, confirmation
):
    watch = FsWatch(monkeypatch)
    result = bind(UNPUBLISHED_ARTIFACT_ID, tmp_path, lane=confirmation)
    assert result.status == "invalid_capability_binding_input"
    assert result.capability_support_evaluated is False
    assert result.capability_binding_evaluated is False
    assert result.capability_bound is False
    assert result.filesystem_accessed is False
    assert watch.calls == []
    assert authority_watch == []
    assert_binding_never_expands(result)


@pytest.mark.parametrize(
    "confirmation",
    [
        "0" * 64,
        "a" * 64,
        OTHER_HEX64,
        HEX64,
        FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256,
        LANE_DECLARATION_IDENTITY_SHA256,
        hashlib.sha256(b"a stale catalog").hexdigest(),
    ],
)
def test_a_mismatched_catalog_confirmation_never_reaches_the_filesystem(
    tmp_path, monkeypatch, authority_watch, confirmation
):
    watch = FsWatch(monkeypatch)
    result = bind(UNPUBLISHED_ARTIFACT_ID, tmp_path, catalog=confirmation)
    assert result.status == "capability_catalog_confirmation_mismatch"
    assert result.confirmed_capability_catalog_identity_sha256 == confirmation
    assert result.capability_catalog_identity_sha256 == UPDATED_CATALOG_IDENTITY_SHA256
    assert result.filesystem_accessed is False
    assert result.capability_support_evaluated is False
    assert result.capability_bound is False
    assert result.binding is None
    assert watch.calls == []
    assert authority_watch == []
    assert_binding_never_expands(result)


@pytest.mark.parametrize(
    "confirmation",
    [
        "0" * 64,
        "a" * 64,
        OTHER_HEX64,
        HEX64,
        FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256,
        UPDATED_CATALOG_IDENTITY_SHA256,
        hashlib.sha256(b"a stale lane").hexdigest(),
    ],
)
def test_a_mismatched_lane_confirmation_never_reaches_the_filesystem(
    tmp_path, monkeypatch, authority_watch, confirmation
):
    watch = FsWatch(monkeypatch)
    result = bind(UNPUBLISHED_ARTIFACT_ID, tmp_path, lane=confirmation)
    assert result.status == "lane_declaration_confirmation_mismatch"
    assert result.confirmed_lane_declaration_identity_sha256 == confirmation
    assert result.lane_declaration_identity_sha256 == LANE_DECLARATION_IDENTITY_SHA256
    assert result.filesystem_accessed is False
    assert result.capability_support_evaluated is False
    assert result.capability_binding_evaluated is False
    assert result.capability_bound is False
    assert result.binding is None
    assert watch.calls == []
    assert authority_watch == []
    assert_binding_never_expands(result)


def test_swapped_confirmations_fail_closed(tmp_path, monkeypatch, authority_watch):
    watch = FsWatch(monkeypatch)
    result = bind(
        UNPUBLISHED_ARTIFACT_ID,
        tmp_path,
        catalog=LANE_DECLARATION_IDENTITY_SHA256,
        lane=UPDATED_CATALOG_IDENTITY_SHA256,
    )
    assert result.status == "capability_catalog_confirmation_mismatch"
    assert result.filesystem_accessed is False
    assert watch.calls == []
    assert authority_watch == []


def test_a_subject_or_artifact_identity_is_never_accepted_as_a_confirmation(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    watch = FsWatch(monkeypatch)
    for value in (artifact.subject_sha256, artifact.approval_artifact_identity_sha256):
        assert bind(artifact.approval_artifact_id, root, catalog=value).status == (
            "capability_catalog_confirmation_mismatch"
        )
        assert bind(artifact.approval_artifact_id, root, lane=value).status == (
            "lane_declaration_confirmation_mismatch"
        )
    assert watch.calls == []


def test_both_confirmations_are_compared_with_compare_digest():
    source = inspect.getsource(construct_persisted_approved_change_capability_binding)
    assert source.count("hmac.compare_digest") >= 2


def test_the_exact_pair_of_identities_is_the_only_accepted_confirmation(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    result = construct_persisted_approved_change_capability_binding(
        artifact.approval_artifact_id,
        data_dir=root,
        confirm_capability_catalog_identity_sha256=UPDATED_CATALOG_IDENTITY_SHA256,
        confirm_lane_declaration_identity_sha256=LANE_DECLARATION_IDENTITY_SHA256,
    )
    assert result.status == "capability_binding_constructed"


# --------------------------------------------------------------------------
# Artifact input and load failures
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "artifact_id",
    [
        "",
        "   ",
        "not-an-id",
        FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256,
        f"{APPROVAL_ARTIFACT_ID_PREFIX}{HEX64[:63]}",
        f"{APPROVAL_ARTIFACT_ID_PREFIX}{HEX64.upper()}",
        f" {UNPUBLISHED_ARTIFACT_ID}",
        f"{UNPUBLISHED_ARTIFACT_ID}/../..",
        None,
        123,
        "latest",
        "current",
        "most_recent",
        APPROVAL_ARTIFACT_ID_PREFIX,
    ],
)
def test_a_malformed_artifact_id_is_never_a_binding(tmp_path, artifact_id):
    root = data_dir(tmp_path)
    result = bind(artifact_id, root)
    assert result.status == "invalid_capability_binding_input"
    assert result.binding_complete is False
    assert result.capability_bound is False
    assert result.binding is None
    assert_binding_never_expands(result)
    assert_no_host_paths(result, root)


def test_an_absent_artifact_is_never_a_binding(tmp_path):
    root = data_dir(tmp_path)
    result = bind(UNPUBLISHED_ARTIFACT_ID, root)
    assert result.status == "approval_artifact_not_available"
    assert result.approval_artifact_loaded is False
    assert result.capability_bound is False
    assert result.binding is None
    assert_binding_never_expands(result)
    assert_no_host_paths(result, root)
    assert not publication_root(root).exists()


def test_an_invalid_persisted_artifact_is_never_a_binding(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    write_artifact_directory(
        root,
        artifact,
        mutate=lambda payload: {APPROVED_CHANGE_APPROVAL_FILENAME: b"{not json"},
    )
    result = bind(artifact.approval_artifact_id, root)
    assert result.status == "approval_artifact_invalid"
    assert result.capability_bound is False
    assert result.binding is None
    assert_binding_never_expands(result)
    assert_no_host_paths(result, root)


@pytest.mark.parametrize("root_value", ["relative/path", "", None, 7, Path("relative")])
def test_an_unsafe_data_root_is_never_a_binding(tmp_path, root_value):
    result = bind(UNPUBLISHED_ARTIFACT_ID, root_value)
    assert result.status in {"approval_artifact_not_available", "invalid_capability_binding_input"}
    assert result.capability_bound is False
    assert result.binding is None
    assert_binding_never_expands(result)


def test_binding_statuses_are_exactly_the_maintained_set():
    assert set(BINDING_STATUSES) == {
        "capability_binding_constructed",
        "capability_binding_not_available",
        "capability_binding_blocked",
        "invalid_capability_binding_input",
        "capability_catalog_confirmation_mismatch",
        "lane_declaration_confirmation_mismatch",
        "approval_artifact_not_available",
        "approval_artifact_invalid",
        "capability_support_not_confirmed",
        "capability_binding_validation_failed",
    }
    assert set(BINDING_VALIDATION_STATUSES) == {
        "capability_binding_valid",
        "capability_binding_invalid",
        "invalid_capability_binding_validation_input",
    }


# --------------------------------------------------------------------------
# PR321 and PR319 remain the authorities
# --------------------------------------------------------------------------


def test_the_pr321_evaluator_is_called_exactly_once_with_the_exact_inputs(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    spy = AuthoritySpy(monkeypatch)
    result = bind(artifact.approval_artifact_id, root)
    assert result.status == "capability_binding_constructed"
    assert len(spy.support_calls) == 1
    artifact_id, passed_root, confirmation = spy.support_calls[0]
    assert artifact_id == artifact.approval_artifact_id
    assert passed_root == root
    assert confirmation == UPDATED_CATALOG_IDENTITY_SHA256


def test_the_pr319_loader_is_used_only_once_for_the_exact_binding_metadata(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    spy = AuthoritySpy(monkeypatch)
    result = bind(artifact.approval_artifact_id, root)
    assert result.status == "capability_binding_constructed"
    assert len(spy.load_calls) == 1
    assert spy.load_calls[0] == (artifact.approval_artifact_id, root)


def test_pr322_never_claims_support_the_pr321_evaluator_denied(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    AuthoritySpy(monkeypatch, support={"status": "capability_not_declared"})
    result = bind(artifact.approval_artifact_id, root)
    assert result.status == "capability_binding_not_available"
    assert result.capability_supported is False
    assert result.capability_bound is False
    assert result.binding is None


@pytest.mark.parametrize(
    "override,expected",
    [
        ({"capability_supported": False}, "capability_support_not_confirmed"),
        ({"evaluation_complete": False}, "capability_support_not_confirmed"),
        ({"declaration_found": False, "declaration": None}, "capability_support_not_confirmed"),
        ({"contract_validation": None}, "capability_support_not_confirmed"),
        ({"status": "capability_support_evaluation_blocked"}, "capability_support_not_confirmed"),
        ({"status": "capability_contract_validation_failed"}, "capability_support_not_confirmed"),
        ({"status": "invalid_capability_support_input"}, "invalid_capability_binding_input"),
        ({"status": "approval_artifact_not_available"}, "approval_artifact_not_available"),
        ({"status": "approval_artifact_invalid"}, "approval_artifact_invalid"),
        (
            {"status": "capability_catalog_confirmation_mismatch"},
            "capability_catalog_confirmation_mismatch",
        ),
        ({"status": "some_new_status"}, "capability_support_not_confirmed"),
    ],
)
def test_every_non_confirming_pr321_result_fails_closed(tmp_path, monkeypatch, override, expected):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    AuthoritySpy(monkeypatch, support=override)
    result = bind(artifact.approval_artifact_id, root)
    assert result.status == expected
    assert result.capability_bound is False
    assert result.binding is None
    assert_binding_never_expands(result)


@pytest.mark.parametrize(
    "override",
    [
        {"subject_sha256": "0" * 64},
        {"approval_artifact_identity_sha256": "0" * 64},
        {"approval_binding_valid": False},
        {"source_bundle_revalidated": False},
        {"status": "some_new_status"},
    ],
)
def test_disagreement_between_pr321_and_pr319_fails_closed(tmp_path, monkeypatch, override):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    AuthoritySpy(monkeypatch, load=override)
    result = bind(artifact.approval_artifact_id, root)
    assert result.status == "capability_binding_blocked"
    assert result.capability_bound is False
    assert result.binding is None
    assert result.errors
    assert_binding_never_expands(result)


def test_an_artifact_id_disagreement_fails_closed(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    AuthoritySpy(
        monkeypatch,
        support={"loaded_approval_artifact_id": UNPUBLISHED_ARTIFACT_ID},
    )
    result = bind(artifact.approval_artifact_id, root)
    assert result.status == "capability_binding_blocked"
    assert result.capability_bound is False
    assert result.binding is None


def test_pr322_defines_no_competing_support_validator_or_identity_rule():
    source = Path(binding_module.__file__).read_text(encoding="utf-8")
    assert "evaluate_persisted_approved_change_capability_support" in source
    assert "def evaluate_persisted_approved_change_capability_support" not in source
    assert "def validate_approved_change_contract" not in source
    assert "compute_subject_sha256" not in source
    assert "verify_approval_binding" not in source
    assert "def derive_approval_artifact_id" not in source


# --------------------------------------------------------------------------
# Binding validation
# --------------------------------------------------------------------------


def test_the_maintained_binding_validates_and_cross_checks_every_authority(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    result = bind(artifact.approval_artifact_id, root)
    support = evaluate_persisted_approved_change_capability_support(
        artifact.approval_artifact_id,
        data_dir=root,
        confirm_capability_catalog_identity_sha256=catalog_identity(),
    )
    validation = validate_approved_change_capability_binding(
        result.binding,
        catalog=maintained_approved_change_capability_support_catalog(),
        lane_declaration=maintained_windows_runtime_reconcile_lane_declaration(),
        support_result=support,
        approval_artifact=artifact,
    )
    assert validation.status == "capability_binding_valid"
    assert validation.binding_valid is True
    assert validation.errors == ()
    assert validation.binding_identity_sha256 == result.binding_identity_sha256
    assert validation.canonical_byte_length == result.binding_canonical_byte_length
    assert_never_expands(validation)
    assert validation.filesystem_accessed is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"schema_version": "2"},
        {"binding_type": "approved_change_binding"},
        {"capability_id": "windows.runtime_reconcile.v2"},
        {"capability_id": "example.other"},
        {"lane_id": "windows.runtime_reconcile"},
        {"lane_id": "pr313.other_lane"},
        {"binding_scope": "any_subject_to_any_lane"},
        {"implementation_scope": "windows_runtime_reconciliation"},
        {"approval_artifact_id": HEX64},
        {"approval_artifact_id": f"acb_{HEX64}"},
        {"approval_artifact_id": f"{APPROVAL_ARTIFACT_ID_PREFIX}{OTHER_HEX64}"},
        {"approval_artifact_identity_sha256": HEX64.upper()},
        {"approval_artifact_identity_sha256": HEX64[:63]},
        {"subject_sha256": "not-a-sha"},
        {"capability_catalog_identity_sha256": ""},
        {"lane_declaration_identity_sha256": "zz" * 32},
        {"extra_field": "x"},
    ],
)
def test_a_malformed_binding_is_invalid(overrides):
    result = validate_approved_change_capability_binding(binding_payload(**overrides))
    assert result.status == "capability_binding_invalid"
    assert result.binding_valid is False
    assert result.errors


@pytest.mark.parametrize("value", [None, "binding", b"binding", 1, 1.5, True, [], ()])
def test_structurally_impossible_binding_input_is_reported_separately(value):
    result = validate_approved_change_capability_binding(value)
    assert result.status == "invalid_capability_binding_validation_input"
    assert result.binding_valid is False
    assert result.binding_identity_sha256 == ""


def test_a_binding_that_disagrees_with_a_cross_check_is_invalid(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    other = publish_for(alternate_supported_bundle(), root)
    binding = bind(artifact.approval_artifact_id, root).binding
    result = validate_approved_change_capability_binding(binding, approval_artifact=other)
    assert result.status == "capability_binding_invalid"
    assert result.binding_valid is False
    assert any("approval artifact" in item for item in result.errors)


def test_the_binding_validator_performs_no_io(tmp_path, monkeypatch):
    binding = ApprovedChangeCapabilityBinding.model_validate(binding_payload())
    watch = FsWatch(monkeypatch)
    result = validate_approved_change_capability_binding(binding)
    assert result.status == "capability_binding_valid"
    assert watch.calls == []


# --------------------------------------------------------------------------
# Binding is not semantic compatibility
#
# This is the essential proof that PR322 did not silently implement preflight:
# two materially different approved subjects sharing only the exact declared
# capability ID both bind, with distinct identities and identical warnings.
# --------------------------------------------------------------------------


def test_binding_never_evaluates_target_procedure_evidence_or_current_state(tmp_path):
    root = data_dir(tmp_path)
    first = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    second = publish_for(alternate_supported_bundle(), root)

    subjects = [item.contract.subject for item in (first, second)]
    assert subjects[0].target != subjects[1].target
    assert subjects[0].procedure != subjects[1].procedure
    assert subjects[0].evidence_references != subjects[1].evidence_references
    assert subjects[0].risk != subjects[1].risk
    assert subjects[0].rollback_posture != subjects[1].rollback_posture

    results = [bind(item.approval_artifact_id, root) for item in (first, second)]
    assert results[0].binding_identity_sha256 != results[1].binding_identity_sha256

    for result in results:
        assert result.status == "capability_binding_constructed"
        assert result.capability_bound is True
        assert result.lane_declaration == results[0].lane_declaration
        assert result.preflight_evaluated is False
        assert "capability binding does not validate target compatibility" in result.warnings
        assert "capability binding does not validate procedure compatibility" in result.warnings
        assert "capability binding does not validate PR304 or PR305 evidence" in result.warnings
        assert (
            "capability binding does not compare the approved subject with a PR313 plan"
            in result.warnings
        )
        assert "capability binding does not evaluate current state" in result.warnings
        assert "capability binding does not run a preflight" in result.warnings


def test_no_binding_field_carries_target_procedure_or_plan_data(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    payload = canonical_approved_change_capability_binding_json(
        bind(artifact.approval_artifact_id, root).binding
    )
    for banned in (
        "target",
        "procedure",
        "evidence",
        "precondition",
        "plan_hash",
        "System32",
        "staged",
        "durable",
        "receipt",
        "authorization",
    ):
        assert banned not in payload, banned


# --------------------------------------------------------------------------
# No PR313 invocation, no inventory, no recipe registry
# --------------------------------------------------------------------------


def test_no_pr313_pr304_pr305_or_recipe_path_is_ever_reached(tmp_path, monkeypatch):
    from shellforgeai.core import recipe_registry
    from shellforgeai.core import windows_runtime_reconcile_execution as pr313

    def boom(name):
        def raiser(*args, **kwargs):
            raise AssertionError(f"PR322 must never reach {name}")

        return raiser

    for module in (recipe_registry, pr313):
        for name in [n for n in dir(module) if not n.startswith("_")]:
            if callable(getattr(module, name, None)):
                monkeypatch.setattr(module, name, boom(f"{module.__name__}.{name}"), raising=False)

    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    result = bind(artifact.approval_artifact_id, root)
    assert result.status == "capability_binding_constructed"
    assert result.capability_bound is True
    assert result.preflight_evaluated is False
    assert result.execution_status == "not_executed"


def test_no_pr313_script_helper_is_importable_from_this_module():
    source = module_code_without_strings(binding_module)
    for token in (
        "windows_runtime_reconcile_execution",
        "windows_runtime_reconcile_preflight",
        "windows_runtime_reconcile_execute",
        "windows_runtime_reconcile_receipt",
        "windows_runtime_reconcile_verify",
        "windows_runtime_integrity",
        "runtime_preview",
        "System32",
        "sfai",
        "plan_hash",
        "create_receipt",
        "receipt_writer",
        "run_preflight",
        "executor",
        "adapter",
        "recipe",
    ):
        assert token not in source, token


def test_the_pr320_inventory_is_never_called(tmp_path, monkeypatch):
    from shellforgeai.core import approved_change_approval_inventory as inventory_module

    def boom(*args, **kwargs):
        raise AssertionError("PR322 must never call the PR320 inventory")

    monkeypatch.setattr(
        inventory_module,
        "inventory_persisted_approved_change_approval_artifacts",
        boom,
    )
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    assert bind(artifact.approval_artifact_id, root).status == "capability_binding_constructed"


def test_static_no_inventory_import_or_selection_vocabulary():
    source = module_code_without_strings(binding_module)
    for token in (
        "approved_change_approval_inventory",
        "inventory_persisted_approved_change_approval_artifacts",
        "inventory",
        "selected_artifact",
        "selected_approval",
        "preferred",
        "latest",
        "current",
        "most_recent",
    ):
        assert token not in source, token
    fields = set(ApprovedChangeCapabilityBindingResult.model_fields)
    for banned in ("selected_approval_artifact_id", "latest", "current", "preferred_lane"):
        assert banned not in fields


def test_an_exact_artifact_id_is_always_required(tmp_path):
    root = data_dir(tmp_path)
    publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    for reference in ("latest", "current", "most_recent", APPROVAL_ARTIFACT_ID_PREFIX):
        result = bind(reference, root)
        assert result.status == "invalid_capability_binding_input"
        assert result.capability_bound is False


# --------------------------------------------------------------------------
# No writes and no hidden expansion
# --------------------------------------------------------------------------


def test_lane_and_binding_operations_reach_no_filesystem_primitive(monkeypatch):
    watch = FsWatch(monkeypatch)
    real_open = builtins.open

    def guarded(file, mode="r", *args, **kwargs):
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            raise AssertionError("a write-capable open was reached")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded)
    monkeypatch.setattr(Path, "write_text", watch._raiser("Path.write_text"))
    monkeypatch.setattr(Path, "write_bytes", watch._raiser("Path.write_bytes"))
    monkeypatch.setattr(tempfile, "mkdtemp", watch._raiser("tempfile.mkdtemp"))
    monkeypatch.setattr(tempfile, "mkstemp", watch._raiser("tempfile.mkstemp"))

    lane = maintained_windows_runtime_reconcile_lane_declaration()
    canonical_capability_lane_declaration_payload(lane)
    canonical_capability_lane_declaration_json(lane)
    compute_capability_lane_declaration_sha256(lane)
    assert validate_capability_lane_declaration(lane).declaration_valid is True
    binding = ApprovedChangeCapabilityBinding.model_validate(binding_payload())
    canonical_approved_change_capability_binding_payload(binding)
    canonical_approved_change_capability_binding_json(binding)
    compute_approved_change_capability_binding_sha256(binding)
    assert validate_approved_change_capability_binding(binding).binding_valid is True
    assert watch.calls == []


def test_binding_reaches_no_write_capable_primitive(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    before = snapshot(root)

    def raiser(name):
        def boom(*args, **kwargs):
            raise AssertionError(f"{name} was reached during a read-only binding")

        return boom

    for name in ("mkdir", "makedirs", "rename", "replace", "rmdir", "unlink", "remove", "truncate"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, raiser(f"os.{name}"))
    monkeypatch.setattr(Path, "write_text", raiser("Path.write_text"))
    monkeypatch.setattr(Path, "write_bytes", raiser("Path.write_bytes"))
    monkeypatch.setattr(Path, "mkdir", raiser("Path.mkdir"))
    monkeypatch.setattr(Path, "unlink", raiser("Path.unlink"))
    monkeypatch.setattr(tempfile, "mkdtemp", raiser("tempfile.mkdtemp"))
    monkeypatch.setattr(tempfile, "mkstemp", raiser("tempfile.mkstemp"))
    monkeypatch.setattr(tempfile, "TemporaryDirectory", raiser("tempfile.TemporaryDirectory"))

    real_os_open = os.open

    def guarded_os_open(path, flags, *args, **kwargs):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC):
            raise AssertionError("a write-capable os.open was reached")
        return real_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded_os_open)
    real_open = builtins.open

    def guarded_open(file, mode="r", *args, **kwargs):
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            raise AssertionError("a write-capable open was reached")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_open)

    assert bind(artifact.approval_artifact_id, root).status == "capability_binding_constructed"
    assert snapshot(root) == before


def test_no_shell_network_model_credential_clock_or_randomness_is_reached(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)

    def raiser(name):
        def boom(*args, **kwargs):
            raise AssertionError(f"{name} was reached during a read-only binding")

        return boom

    monkeypatch.setattr(subprocess, "run", raiser("subprocess.run"))
    monkeypatch.setattr(subprocess, "Popen", raiser("subprocess.Popen"))
    monkeypatch.setattr(subprocess, "check_output", raiser("subprocess.check_output"))
    monkeypatch.setattr(os, "system", raiser("os.system"))
    monkeypatch.setattr(socket, "socket", raiser("socket.socket"))
    monkeypatch.setattr(socket, "create_connection", raiser("socket.create_connection"))
    monkeypatch.setattr(socket, "gethostname", raiser("socket.gethostname"))
    monkeypatch.setattr(time, "time", raiser("time.time"))
    monkeypatch.setattr(time, "monotonic", raiser("time.monotonic"))
    monkeypatch.setattr(uuid, "uuid4", raiser("uuid.uuid4"))
    monkeypatch.setattr(random, "random", raiser("random.random"))
    monkeypatch.setattr(random, "getrandbits", raiser("random.getrandbits"))
    monkeypatch.setattr(platform, "system", raiser("platform.system"))
    monkeypatch.setattr(platform, "node", raiser("platform.node"))
    monkeypatch.setattr(os, "getenv", raiser("os.getenv"))
    monkeypatch.setattr(os.environ, "get", raiser("os.environ.get"))
    if hasattr(os, "getlogin"):
        monkeypatch.setattr(os, "getlogin", raiser("os.getlogin"))

    assert bind(artifact.approval_artifact_id, root).status == "capability_binding_constructed"


def test_static_the_import_set_is_exactly_the_maintained_dependencies():
    tree = ast.parse(Path(binding_module.__file__).read_text(encoding="utf-8"))
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
        "pathlib",
        "pydantic",
        "shellforgeai.core.approved_change_approval_artifact",
        "shellforgeai.core.approved_change_approval_persistence",
        "shellforgeai.core.approved_change_capability_support",
        "shellforgeai.core.approved_change_contract",
        "typing",
    }


def test_static_no_publisher_executor_preflight_or_receipt_call():
    source = module_code_without_strings(binding_module)
    for token in (
        "publish_approved_change_approval_artifact",
        "publish_approved_change_artifact_bundle",
        "build_approved_change_approval_artifact",
        "construct_approved_change_contract_from_persisted_bundle",
        "load_persisted_approved_change_artifact_bundle",
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
    ):
        assert token not in source, token


def test_no_legacy_proposal_type_is_named_or_imported():
    tree = ast.parse(Path(binding_module.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.module != "shellforgeai.core.approvals"
        if isinstance(node, ast.Name):
            assert node.id != "Proposal"
    source = module_code_without_strings(binding_module)
    for token in ("Proposal", "core.approvals", "approve_proposal", "fingerprint"):
        assert token not in source, token


def test_signatures_never_take_or_return_legacy_approval_types():
    for _, obj in inspect.getmembers(binding_module, inspect.isfunction):
        signature = inspect.signature(obj)
        assert all(param.annotation is not Proposal for param in signature.parameters.values())
        assert "Proposal" not in str(signature)


def test_the_public_surface_is_exactly_the_maintained_operations():
    public = sorted(
        name
        for name, obj in inspect.getmembers(binding_module, inspect.isfunction)
        if not name.startswith("_") and obj.__module__ == binding_module.__name__
    )
    assert public == [
        "canonical_approved_change_capability_binding_json",
        "canonical_approved_change_capability_binding_payload",
        "canonical_capability_lane_declaration_json",
        "canonical_capability_lane_declaration_payload",
        "compute_approved_change_capability_binding_sha256",
        "compute_capability_lane_declaration_sha256",
        "construct_persisted_approved_change_capability_binding",
        "maintained_windows_runtime_reconcile_lane_declaration",
        "validate_approved_change_capability_binding",
        "validate_capability_lane_declaration",
    ]
    for banned in (
        "authorize",
        "preflight",
        "create_receipt",
        "link_receipt",
        "execute",
        "publish_binding",
        "persist_binding",
        "load_binding",
        "register_lane",
        "discover_lanes",
    ):
        assert not hasattr(binding_module, banned), banned


def test_the_module_is_not_imported_by_cli_approvals_recipes_or_execution():
    # The PR323 read-only plan-link module is the only permitted consumer: it
    # obtains its binding solely through this maintained operation instead of
    # constructing a competing binding of its own.
    permitted = {
        "approved_change_capability_binding.py",
        "approved_change_plan_link.py",
        "approved_change_plan_current_state.py",
    }
    offenders = [
        str(path)
        for base in (Path("src/shellforgeai/cli"), Path("src/shellforgeai/core"))
        for path in base.rglob("*.py")
        if path.name not in permitted
        and "approved_change_capability_binding" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_the_only_permitted_consumer_uses_the_maintained_binding_operation():
    source = Path("src/shellforgeai/core/approved_change_plan_link.py").read_text(encoding="utf-8")
    assert "construct_persisted_approved_change_capability_binding" in source
    assert "evaluate_persisted_approved_change_capability_support" not in source
    assert "load_persisted_approved_change_approval_artifact" not in source


def test_no_cli_surface_was_added():
    cli = Path("docs/cli.md").read_text(encoding="utf-8")
    assert "capability-binding" not in cli
    assert "approved_change_capability_binding" not in cli
    offenders = [
        str(path)
        for path in Path("src/shellforgeai/cli").rglob("*.py")
        if "capability_binding" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_no_new_persisted_artifact_was_introduced():
    layout = Path("docs/data-layout.md").read_text(encoding="utf-8")
    assert "capability_binding" not in layout
    assert "capability-binding" not in layout


def test_importing_the_module_touches_nothing(tmp_path, monkeypatch):
    import importlib

    calls: list[str] = []
    monkeypatch.chdir(tmp_path)
    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append("subprocess.run"))
    monkeypatch.setattr(os, "system", lambda *a, **k: calls.append("os.system"))
    monkeypatch.setattr(socket, "socket", lambda *a, **k: calls.append("socket"))
    sys.modules.pop("shellforgeai.core.approved_change_capability_binding", None)
    importlib.import_module("shellforgeai.core.approved_change_capability_binding")
    assert sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")) == before
    assert calls == []


# --------------------------------------------------------------------------
# Cross-platform parity
# --------------------------------------------------------------------------


def test_cross_platform_parity_of_catalog_and_lane_bytes_and_identity():
    """These exact values must hold byte for byte on Linux and on Windows."""
    catalog = maintained_approved_change_capability_support_catalog()
    assert compute_approved_change_capability_support_catalog_sha256(catalog) == (
        UPDATED_CATALOG_IDENTITY_SHA256
    )
    assert len(MAINTAINED_CATALOG_CANONICAL_JSON.encode("utf-8")) == UPDATED_CATALOG_BYTE_LENGTH

    lane = maintained_windows_runtime_reconcile_lane_declaration()
    canonical = canonical_capability_lane_declaration_json(lane)
    assert canonical == LANE_DECLARATION_CANONICAL_JSON
    assert canonical.encode("utf-8") == LANE_DECLARATION_CANONICAL_JSON.encode("utf-8")
    assert len(canonical.encode("utf-8")) == LANE_DECLARATION_BYTE_LENGTH == 550
    assert "\r" not in canonical
    assert compute_capability_lane_declaration_sha256(lane) == LANE_DECLARATION_IDENTITY_SHA256


def test_cross_platform_parity_of_bound_and_unbound_results(tmp_path):
    """Identical persisted artifacts must produce identical results everywhere."""
    root = data_dir(tmp_path)
    supported = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    unsupported = publish_for(bundle_a(), root)
    assert unsupported.approval_artifact_id == FIXTURE_A_APPROVAL_ARTIFACT_ID

    ok = bind(supported.approval_artifact_id, root)
    no = bind(unsupported.approval_artifact_id, root)

    assert ok.status == "capability_binding_constructed"
    assert ok.binding.model_dump(mode="json") == {
        "schema_version": "1",
        "binding_type": "approved_change_capability_binding",
        "approval_artifact_id": SUPPORTED_BINDING_APPROVAL_ARTIFACT_ID,
        "approval_artifact_identity_sha256": SUPPORTED_BINDING_APPROVAL_ARTIFACT_ID.removeprefix(
            APPROVAL_ARTIFACT_ID_PREFIX
        ),
        "subject_sha256": SUPPORTED_BINDING_SUBJECT_SHA256,
        "capability_catalog_identity_sha256": UPDATED_CATALOG_IDENTITY_SHA256,
        "capability_id": "windows.runtime_reconcile",
        "lane_declaration_identity_sha256": LANE_DECLARATION_IDENTITY_SHA256,
        "lane_id": "pr313.windows_runtime_reconcile",
        "binding_scope": "exact_approved_subject_to_exact_named_lane_declaration_only",
        "implementation_scope": "windows_exact_two_file_runtime_reconciliation_only",
    }
    assert ok.binding_identity_sha256 == SUPPORTED_BINDING_IDENTITY_SHA256
    assert ok.binding_canonical_byte_length == SUPPORTED_BINDING_BYTE_LENGTH
    assert ok.warnings == PERMANENT_CAPABILITY_BINDING_WARNINGS

    assert no.status == "capability_binding_not_available"
    assert no.capability_id == UNKNOWN_CAPABILITY_ID
    assert no.binding is None
    assert no.warnings == PERMANENT_CAPABILITY_BINDING_WARNINGS
    assert no.loaded_approval_artifact_id == FIXTURE_A_APPROVAL_ARTIFACT_ID

    for result in (ok, no):
        assert result.capability_support_evaluated is True
        assert result.capability_binding_evaluated is True
        assert result.approval_binding_valid is True
        assert result.filesystem_accessed is True
        assert_binding_never_expands(result)


# --------------------------------------------------------------------------
# Immutability and structured failure
# --------------------------------------------------------------------------


def test_every_model_is_frozen_and_forbids_extra_fields(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    lane = maintained_windows_runtime_reconcile_lane_declaration()
    lane_result = validate_capability_lane_declaration(lane)
    result = bind(artifact.approval_artifact_id, root)

    for model in (
        ApprovedChangeCapabilityLaneDeclaration,
        ApprovedChangeCapabilityLaneDeclarationValidationResult,
        ApprovedChangeCapabilityBinding,
        ApprovedChangeCapabilityBindingValidationResult,
        ApprovedChangeCapabilityBindingResult,
    ):
        assert model.model_config["frozen"] is True
        assert model.model_config["extra"] == "forbid"

    with pytest.raises(ValidationError):
        lane.execution_available = True
    with pytest.raises(ValidationError):
        lane_result.declaration_valid = False
    with pytest.raises(ValidationError):
        result.binding.lane_id = "other"
    with pytest.raises(ValidationError):
        result.capability_bound = False
    with pytest.raises(ValidationError):
        result.execution_allowed = True
    with pytest.raises(ValidationError):
        result.binding_validation.binding_valid = False


def test_errors_and_warnings_are_immutable_sorted_and_deduplicated(tmp_path):
    root = data_dir(tmp_path)
    result = bind(UNPUBLISHED_ARTIFACT_ID, root, catalog="zz")
    assert isinstance(result.errors, tuple)
    assert isinstance(result.warnings, tuple)
    assert list(result.errors) == sorted(set(result.errors))
    with pytest.raises((AttributeError, TypeError)):
        result.errors.append("x")

    lane_result = validate_capability_lane_declaration(
        lane_payload(execution_available=True, preflight_available=True)
    )
    assert list(lane_result.errors) == sorted(set(lane_result.errors))


def test_no_partial_binding_survives_a_failed_operation(tmp_path):
    root = data_dir(tmp_path)
    for result in (
        bind(UNPUBLISHED_ARTIFACT_ID, root),
        bind(UNPUBLISHED_ARTIFACT_ID, root, catalog="0" * 64),
        bind(UNPUBLISHED_ARTIFACT_ID, root, lane="0" * 64),
        bind("not-an-id", root),
    ):
        assert result.binding is None
        assert result.binding_validation is None
        assert result.binding_identity_sha256 == ""
        assert result.binding_canonical_byte_length == 0
        assert result.capability_bound is False
        assert result.binding_created is False
        assert result.binding_complete is False


def test_no_traceback_or_host_path_is_ever_reported(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    write_artifact_directory(
        root, artifact, mutate=lambda payload: {APPROVED_CHANGE_APPROVAL_FILENAME: b"\xff\xfe"}
    )
    for result in (
        bind(artifact.approval_artifact_id, root),
        bind(UNPUBLISHED_ARTIFACT_ID, root),
        bind(UNPUBLISHED_ARTIFACT_ID, tmp_path / "missing-root"),
    ):
        assert_no_host_paths(result, root)
        assert_no_host_paths(result, tmp_path)
        assert 'File "' not in json.dumps(result.model_dump(mode="json"))
