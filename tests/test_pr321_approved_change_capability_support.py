"""Focused PR321 tests: approved-change capability-support declaration.

PR309 owns the subject schema, the subject identity, the attestation, the
contract, approval-binding verification, the capability-ID syntax, and
``validate_approved_change_contract``. PR316 owns the reviewed bundle. PR317
owns the governed bundle publisher and its exact-ID loader. PR318 owns the one
read-only approval-binding operation. PR319 owns the canonical approval
artifact, the ``aca_`` identity, the fixed ``approved_change_approvals``
subtree, and the exact-ID approval-artifact loader. PR320 owns bounded
read-only discovery.

These tests prove PR321 adds exactly two things on top of those maintained
contracts: one immutable, canonical, product-maintained capability-support
declaration catalog with a deterministic SHA-256 identity that declares exactly
``windows.runtime_reconcile``, and one read-only evaluator that loads one exact
persisted PR319 approval artifact and evaluates its approved contract against
that exact catalog through the maintained PR309 validator.

Declared support is approved-change contract validation only. It is not
capability binding, authorization, target or procedure compatibility,
current-state readiness, PR313 eligibility, preflight, receipt linkage, or
execution.
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

# The PR316 focused suite owns the maintained reviewed-context fixtures and the
# PR319 focused suite owns the maintained publication helpers. Both are reused
# verbatim so PR321 never invents its own context, subject, bundle, approval,
# or artifact schema.
from test_pr316_approved_change_artifact_bundle import (  # noqa: E402
    CANDIDATE_VALUES_A,
    EXPLICIT_VALUES_A,
    build,
    candidate_reviews,
    evidence,
    explicit_reviews,
    provenance,
    rollback,
    steps,
    target,
)
from test_pr319_approved_change_approval_artifact_persistence import (  # noqa: E402
    FIXTURE_A_APPROVAL_ARTIFACT_ID,
    FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256,
    artifact_for,
    bundle_a,
    data_dir,
    module_code_without_strings,
    publication_root,
    publish_artifact,
    publish_bundle,
    snapshot,
    workflow_for,
    write_artifact_directory,
)

from shellforgeai.core import approved_change_capability_support as support_module
from shellforgeai.core.approvals import Proposal
from shellforgeai.core.approved_change_approval_artifact import (
    APPROVAL_ARTIFACT_ID_PREFIX,
    APPROVED_CHANGE_APPROVAL_FILENAME,
    build_approved_change_approval_artifact,
)
from shellforgeai.core.approved_change_approval_persistence import (
    LOAD_STATUSES,
    load_persisted_approved_change_approval_artifact,
)
from shellforgeai.core.approved_change_capability_support import (
    CAPABILITY_SUPPORT_CATALOG_TYPE,
    CAPABILITY_SUPPORT_SCHEMA_VERSION,
    CATALOG_VALIDATION_STATUSES,
    EVALUATION_STATUSES,
    MATCH_RULE_EXACT_CAPABILITY_ID_ONLY,
    PERMANENT_CAPABILITY_SUPPORT_WARNINGS,
    REQUIRED_APPROVAL_ARTIFACT_LOAD_STATUS,
    SUPPORT_STATUS_DECLARED_SUPPORTED,
    VALIDATION_SCOPE_CONTRACT_VALIDATION_ONLY,
    WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
    ApprovedChangeCapabilitySupportCatalog,
    ApprovedChangeCapabilitySupportCatalogValidationResult,
    ApprovedChangeCapabilitySupportDeclaration,
    ApprovedChangeCapabilitySupportEvaluationResult,
    canonical_approved_change_capability_support_catalog_json,
    canonical_approved_change_capability_support_catalog_payload,
    compute_approved_change_capability_support_catalog_sha256,
    evaluate_persisted_approved_change_capability_support,
    maintained_approved_change_capability_support_catalog,
    validate_approved_change_capability_support_catalog,
)
from shellforgeai.core.approved_change_contract import (
    ContractValidationResult,
    validate_approved_change_contract,
)
from shellforgeai.core.approved_change_supplemental_context import (
    ApprovedChangeSupplementalContext,
)

# --------------------------------------------------------------------------
# Committed fixed-fixture catalog values
#
# These are the exact expected Linux and Windows canonical bytes and identity
# of the one maintained catalog. They are recorded here so any declaration,
# ordering, encoding, schema, or policy drift fails loudly on either platform
# instead of silently changing what ShellForgeAI claims to support.
# --------------------------------------------------------------------------

MAINTAINED_CATALOG_BYTE_LENGTH = 465
MAINTAINED_CATALOG_IDENTITY_SHA256 = (
    "7dcf112b0807bd7388912b5b1cf59f2be8c0d5b30ec6fa0d05265d88b936da61"
)
MAINTAINED_CATALOG_CANONICAL_JSON = (
    '{"catalog_type":"approved_change_capability_support_catalog","declarations":'
    '[{"authorization_available":false,"capability_binding_available":false,'
    '"capability_id":"windows.runtime_reconcile","execution_available":false,'
    '"match_rule":"exact_capability_id_only","preflight_available":false,'
    '"receipt_linkage_available":false,"schema_version":"1",'
    '"support_status":"declared_supported",'
    '"validation_scope":"approved_change_contract_validation_only"}],"schema_version":"1"}'
)

#: The exact tuple PR309 must receive. Nothing wider, nothing aliased.
EXPECTED_SUPPORTED_CAPABILITY_IDS = ("windows.runtime_reconcile",)

#: The unknown-but-syntactically-valid capability the PR316 fixture A carries.
UNKNOWN_CAPABILITY_ID = "example.synthetic_bounded_change"

#: Syntactically valid PR309 capability IDs that are deliberately *not* the
#: declared one. None of them may ever be treated as a near match.
NEAR_MISS_CAPABILITY_IDS = (
    "windows.runtime_reconcile.v2",
    "windows.runtime-reconcile",
    "windows.runtime_reconcile_preview",
    "example.windows.runtime_reconcile",
)

HEX64 = "0123456789abcdef" * 4
OTHER_HEX64 = "fedcba9876543210" * 4
UNPUBLISHED_ARTIFACT_ID = f"{APPROVAL_ARTIFACT_ID_PREFIX}{HEX64}"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def catalog_identity() -> str:
    return compute_approved_change_capability_support_catalog_sha256(
        maintained_approved_change_capability_support_catalog()
    )


def capability_context(capability_id, *, candidates=None, prov=None, **overrides):
    """Fixture A's reviewed context with one exact reviewed ``capability_id``."""
    return ApprovedChangeSupplementalContext(
        explicit_context_reviews=explicit_reviews(
            dict(EXPLICIT_VALUES_A, capability_id=capability_id), prov=prov, **overrides
        ),
        legacy_candidate_reviews=candidate_reviews(candidates, prov=prov),
    )


def capability_bundle(capability_id, **kwargs):
    result = build(capability_context(capability_id, **kwargs))
    assert result.status == "bundle_constructed", result.errors
    return result.bundle


def alternate_supported_bundle():
    """A second declared-capability subject with a different everything else."""
    return capability_bundle(
        WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
        candidates=dict(CANDIDATE_VALUES_A, risk="low"),
        target=target(claims=(("id", "zzz999"), ("host", "win2025-sfai01")), name="other"),
        procedure=steps(("alt-1", "alt-2")),
        rollback_posture=rollback(("alt-rollback-1",)),
        evidence_references=evidence(order=("ev-9", "ev-8")),
        prov=provenance("operator-w", reason="second declared-capability review"),
    )


def publish_for(bundle, root: Path):
    """Publish one bundle plus its approval artifact into ``root``."""
    artifact = artifact_for(bundle, root)
    assert publish_artifact(artifact, root).status == "approval_artifact_published"
    return artifact


def evaluate(artifact_id, root, confirmation=None):
    return evaluate_persisted_approved_change_capability_support(
        artifact_id,
        data_dir=root,
        confirm_capability_catalog_identity_sha256=(
            catalog_identity() if confirmation is None else confirmation
        ),
    )


def declaration_payload(**overrides):
    payload = {
        "schema_version": "1",
        "capability_id": WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
        "support_status": SUPPORT_STATUS_DECLARED_SUPPORTED,
        "match_rule": MATCH_RULE_EXACT_CAPABILITY_ID_ONLY,
        "validation_scope": VALIDATION_SCOPE_CONTRACT_VALIDATION_ONLY,
        "capability_binding_available": False,
        "authorization_available": False,
        "preflight_available": False,
        "receipt_linkage_available": False,
        "execution_available": False,
    }
    payload.update(overrides)
    return payload


def catalog_payload(*declarations, **overrides):
    payload = {
        "schema_version": "1",
        "catalog_type": CAPABILITY_SUPPORT_CATALOG_TYPE,
        "declarations": list(declarations) or [declaration_payload()],
    }
    payload.update(overrides)
    return payload


def assert_never_expands(result) -> None:
    """The fields PR321 may never claim, on any status whatsoever."""
    assert result.read_only is True
    assert result.mutation_performed is False
    assert result.artifact_write_performed is False
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.capability_bound is False
    assert result.authorization_evaluated is False
    assert result.preflight_evaluated is False
    assert result.receipt_created is False
    assert result.receipt_linked is False
    assert result.host_configuration_mutation_performed is False
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"
    assert result.warnings == PERMANENT_CAPABILITY_SUPPORT_WARNINGS


def assert_evaluation_never_expands(result) -> None:
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


class FsWatch:
    """Fail loudly on any filesystem primitive the loader could reach."""

    NAMES = (
        "lstat",
        "stat",
        "scandir",
        "listdir",
        "open",
        "mkdir",
        "makedirs",
        "rmdir",
        "unlink",
        "remove",
        "rename",
        "replace",
        "fsync",
        "truncate",
    )

    def __init__(self, monkeypatch) -> None:
        self.calls: list[str] = []
        for name in self.NAMES:
            if hasattr(os, name):
                monkeypatch.setattr(os, name, self._raiser(name))
        for name in ("resolve", "exists", "is_dir", "iterdir", "read_bytes", "read_text"):
            monkeypatch.setattr(Path, name, self._raiser(f"Path.{name}"))

    def _raiser(self, name):
        def boom(*args, **kwargs):
            self.calls.append(name)
            raise AssertionError(f"{name} was reached before any load was permitted")

        return boom


@pytest.fixture
def loader_watch(monkeypatch):
    """Fail loudly if the maintained PR319 loader is called at all."""
    seen: list[str] = []

    def boom(*args, **kwargs):
        seen.append("loader")
        raise AssertionError("the PR319 loader was called before confirmation succeeded")

    monkeypatch.setattr(support_module, "load_persisted_approved_change_approval_artifact", boom)
    return seen


class ValidatorSpy:
    """Record every maintained PR309 validator call PR321 makes."""

    def __init__(self, monkeypatch, *, result=None, status=None):
        self.calls: list[tuple] = []
        self.override = result
        self.status = status
        real = validate_approved_change_contract

        def spy(contract, supported_capability_ids):
            self.calls.append((contract, supported_capability_ids))
            actual = real(contract, supported_capability_ids)
            if self.override is not None:
                return self.override
            if self.status is not None:
                return actual.model_copy(update={"status": self.status})
            return actual

        monkeypatch.setattr(support_module, "validate_approved_change_contract", spy)


# --------------------------------------------------------------------------
# The maintained declaration catalog
# --------------------------------------------------------------------------


def test_the_maintained_catalog_holds_exactly_one_declaration():
    catalog = maintained_approved_change_capability_support_catalog()
    assert isinstance(catalog, ApprovedChangeCapabilitySupportCatalog)
    assert catalog.schema_version == CAPABILITY_SUPPORT_SCHEMA_VERSION == "1"
    assert catalog.catalog_type == CAPABILITY_SUPPORT_CATALOG_TYPE
    assert len(catalog.declarations) == 1


def test_the_only_declared_capability_is_windows_runtime_reconcile():
    catalog = maintained_approved_change_capability_support_catalog()
    assert WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID == "windows.runtime_reconcile"
    assert tuple(item.capability_id for item in catalog.declarations) == (
        EXPECTED_SUPPORTED_CAPABILITY_IDS
    )


def test_every_declaration_field_has_its_exact_expected_value():
    (declaration,) = maintained_approved_change_capability_support_catalog().declarations
    assert declaration.model_dump(mode="python") == {
        "schema_version": "1",
        "capability_id": "windows.runtime_reconcile",
        "support_status": "declared_supported",
        "match_rule": "exact_capability_id_only",
        "validation_scope": "approved_change_contract_validation_only",
        "capability_binding_available": False,
        "authorization_available": False,
        "preflight_available": False,
        "receipt_linkage_available": False,
        "execution_available": False,
    }


def test_every_availability_field_is_false():
    for declaration in maintained_approved_change_capability_support_catalog().declarations:
        assert declaration.capability_binding_available is False
        assert declaration.authorization_available is False
        assert declaration.preflight_available is False
        assert declaration.receipt_linkage_available is False
        assert declaration.execution_available is False


def test_no_other_capability_is_ever_declared():
    declared = {
        item.capability_id
        for item in maintained_approved_change_capability_support_catalog().declarations
    }
    for forbidden in (
        "docker.disposable_restart",
        "docker.compose_restart",
        "status",
        "triage",
        "propose",
        "verify",
        "handoff",
        "*",
        "any",
        "all",
        "example.synthetic_bounded_change",
        "windows_runtime_reconcile_execute",
        "sfai.cmd",
    ):
        assert forbidden not in declared


def test_the_maintained_accessor_returns_the_exact_same_immutable_catalog():
    first = maintained_approved_change_capability_support_catalog()
    second = maintained_approved_change_capability_support_catalog()
    assert first is second
    assert first == second


# --------------------------------------------------------------------------
# Canonicalization and deterministic identity
# --------------------------------------------------------------------------


def test_canonical_catalog_json_matches_the_committed_fixture():
    catalog = maintained_approved_change_capability_support_catalog()
    canonical = canonical_approved_change_capability_support_catalog_json(catalog)
    assert canonical == MAINTAINED_CATALOG_CANONICAL_JSON
    assert len(canonical.encode("utf-8")) == MAINTAINED_CATALOG_BYTE_LENGTH


def test_catalog_identity_is_sha256_of_the_exact_canonical_utf8_bytes():
    catalog = maintained_approved_change_capability_support_catalog()
    canonical = canonical_approved_change_capability_support_catalog_json(catalog)
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert compute_approved_change_capability_support_catalog_sha256(catalog) == expected
    assert expected == MAINTAINED_CATALOG_IDENTITY_SHA256


def test_repeated_builds_are_byte_identical():
    values = {
        canonical_approved_change_capability_support_catalog_json(
            maintained_approved_change_capability_support_catalog()
        )
        for _ in range(8)
    }
    assert values == {MAINTAINED_CATALOG_CANONICAL_JSON}


def test_canonical_bytes_carry_no_bom_no_trailing_newline_and_compact_separators():
    canonical = canonical_approved_change_capability_support_catalog_json(
        maintained_approved_change_capability_support_catalog()
    )
    encoded = canonical.encode("utf-8")
    assert not encoded.startswith(b"\xef\xbb\xbf")
    assert not canonical.endswith("\n")
    assert ", " not in canonical
    assert ": " not in canonical
    assert canonical == canonical.strip()


def test_canonical_payload_sorts_mapping_keys_and_declarations():
    payload = canonical_approved_change_capability_support_catalog_payload(
        maintained_approved_change_capability_support_catalog()
    )
    assert list(payload) == sorted(payload)
    for declaration in payload["declarations"]:
        assert list(declaration) == sorted(declaration)
    assert [item["capability_id"] for item in payload["declarations"]] == sorted(
        item["capability_id"] for item in payload["declarations"]
    )


def test_declaration_order_never_changes_canonical_bytes_or_identity():
    forward = ApprovedChangeCapabilitySupportCatalog(
        declarations=(
            ApprovedChangeCapabilitySupportDeclaration(capability_id="a.first"),
            ApprovedChangeCapabilitySupportDeclaration(capability_id="z.last"),
        )
    )
    reversed_order = ApprovedChangeCapabilitySupportCatalog(
        declarations=tuple(reversed(forward.declarations))
    )
    assert canonical_approved_change_capability_support_catalog_json(
        forward
    ) == canonical_approved_change_capability_support_catalog_json(reversed_order)
    assert compute_approved_change_capability_support_catalog_sha256(
        forward
    ) == compute_approved_change_capability_support_catalog_sha256(reversed_order)


def test_ensure_ascii_is_off_so_unicode_is_preserved_exactly():
    source = inspect.getsource(canonical_approved_change_capability_support_catalog_json)
    assert "ensure_ascii=False" in source
    assert 'separators=(",", ":")' in source
    assert "sort_keys=True" in source


def test_no_timestamp_host_platform_environment_or_randomness_affects_identity(monkeypatch):
    baseline = compute_approved_change_capability_support_catalog_sha256(
        maintained_approved_change_capability_support_catalog()
    )
    monkeypatch.setenv("SFAI_DATA_DIR", "/somewhere/else")
    monkeypatch.setenv("HOSTNAME", "another-host")
    monkeypatch.setattr(time, "time", lambda: 1.0)
    monkeypatch.setattr(platform, "system", lambda: "Plan9")
    monkeypatch.setattr(platform, "node", lambda: "other-node")
    monkeypatch.setattr(random, "random", lambda: 0.5)
    assert (
        compute_approved_change_capability_support_catalog_sha256(
            maintained_approved_change_capability_support_catalog()
        )
        == baseline
        == MAINTAINED_CATALOG_IDENTITY_SHA256
    )
    source = module_code_without_strings(support_module)
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


def test_the_canonical_payload_carries_nothing_derived():
    payload = canonical_approved_change_capability_support_catalog_payload(
        maintained_approved_change_capability_support_catalog()
    )
    assert set(payload) == {"schema_version", "catalog_type", "declarations"}
    serialized = json.dumps(payload)
    assert MAINTAINED_CATALOG_IDENTITY_SHA256 not in serialized
    assert "catalog_identity" not in serialized
    assert "byte_length" not in serialized


# --------------------------------------------------------------------------
# Catalog validation
# --------------------------------------------------------------------------


def test_the_maintained_catalog_validates_successfully():
    result = validate_approved_change_capability_support_catalog(
        maintained_approved_change_capability_support_catalog()
    )
    assert result.status == "capability_support_catalog_valid"
    assert result.catalog_valid is True
    assert result.errors == ()
    assert result.declaration_count == 1
    assert result.capability_ids == EXPECTED_SUPPORTED_CAPABILITY_IDS
    assert result.catalog_identity_sha256 == MAINTAINED_CATALOG_IDENTITY_SHA256
    assert result.canonical_byte_length == MAINTAINED_CATALOG_BYTE_LENGTH
    assert_never_expands(result)
    assert result.filesystem_accessed is False
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False


def test_the_exact_maintained_payload_validates_from_a_mapping():
    result = validate_approved_change_capability_support_catalog(catalog_payload())
    assert result.status == "capability_support_catalog_valid"
    assert result.catalog_identity_sha256 == MAINTAINED_CATALOG_IDENTITY_SHA256


@pytest.mark.parametrize(
    "payload",
    [
        catalog_payload(schema_version="2"),
        catalog_payload(schema_version=1),
        catalog_payload(schema_version=""),
        catalog_payload(catalog_type="approved_change_capability_catalog"),
        catalog_payload(catalog_type=""),
        catalog_payload(catalog_type=CAPABILITY_SUPPORT_CATALOG_TYPE.upper()),
    ],
)
def test_malformed_schema_version_or_catalog_type_is_invalid(payload):
    result = validate_approved_change_capability_support_catalog(payload)
    assert result.status == "capability_support_catalog_invalid"
    assert result.catalog_valid is False
    assert result.errors


def test_empty_declarations_is_invalid():
    result = validate_approved_change_capability_support_catalog(catalog_payload(declarations=[]))
    assert result.status == "capability_support_catalog_invalid"
    assert any("at least one declaration" in item for item in result.errors)


def test_duplicate_capability_ids_are_invalid():
    result = validate_approved_change_capability_support_catalog(
        catalog_payload(declaration_payload(), declaration_payload())
    )
    assert result.status == "capability_support_catalog_invalid"
    assert any("duplicate declared capability_id" in item for item in result.errors)


@pytest.mark.parametrize("capability", ["*", "any", "all", "ANY", "  *  "])
def test_wildcard_capabilities_are_invalid(capability):
    result = validate_approved_change_capability_support_catalog(
        catalog_payload(declaration_payload(capability_id=capability))
    )
    assert result.status == "capability_support_catalog_invalid"
    assert result.catalog_valid is False


@pytest.mark.parametrize(
    "capability",
    [
        "Windows.runtime_reconcile",
        "WINDOWS.RUNTIME_RECONCILE",
        ".windows",
        "windows runtime reconcile",
        "windows/runtime_reconcile",
        "",
        "   ",
        " windows.runtime_reconcile",
        "windows.runtime_reconcile ",
        123,
        None,
    ],
)
def test_malformed_capability_ids_are_invalid(capability):
    result = validate_approved_change_capability_support_catalog(
        catalog_payload(declaration_payload(capability_id=capability))
    )
    assert result.status == "capability_support_catalog_invalid"
    assert result.catalog_valid is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"support_status": "supported"},
        {"support_status": "declared_unsupported"},
        {"support_status": ""},
        {"match_rule": "prefix_match"},
        {"match_rule": "exact_capability_id"},
        {"validation_scope": "execution"},
        {"validation_scope": "approved_change_contract_validation"},
    ],
)
def test_wrong_declaration_enums_are_invalid(overrides):
    result = validate_approved_change_capability_support_catalog(
        catalog_payload(declaration_payload(**overrides))
    )
    assert result.status == "capability_support_catalog_invalid"
    assert result.catalog_valid is False


@pytest.mark.parametrize(
    "field",
    [
        "capability_binding_available",
        "authorization_available",
        "preflight_available",
        "receipt_linkage_available",
        "execution_available",
    ],
)
def test_any_availability_field_set_true_is_invalid(field):
    result = validate_approved_change_capability_support_catalog(
        catalog_payload(declaration_payload(**{field: True}))
    )
    assert result.status == "capability_support_catalog_invalid"
    assert result.catalog_valid is False
    assert any(field in item and "must be false" in item for item in result.errors)


def test_an_availability_field_set_true_on_the_model_is_still_rejected():
    catalog = ApprovedChangeCapabilitySupportCatalog(
        declarations=(
            ApprovedChangeCapabilitySupportDeclaration(
                capability_id=WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
                execution_available=True,
            ),
        )
    )
    result = validate_approved_change_capability_support_catalog(catalog)
    assert result.status == "capability_support_catalog_invalid"
    assert any("execution_available must be false" in item for item in result.errors)


@pytest.mark.parametrize(
    "payload",
    [
        catalog_payload(extra_field="x"),
        catalog_payload(declaration_payload(extra_field="x")),
    ],
)
def test_extra_fields_are_invalid(payload):
    result = validate_approved_change_capability_support_catalog(payload)
    assert result.status == "capability_support_catalog_invalid"
    assert result.catalog_valid is False


def test_noncanonical_declaration_order_still_validates_and_keeps_one_identity():
    forward = catalog_payload(
        declaration_payload(capability_id="a.first"),
        declaration_payload(capability_id="z.last"),
    )
    backward = catalog_payload(
        declaration_payload(capability_id="z.last"),
        declaration_payload(capability_id="a.first"),
    )
    first = validate_approved_change_capability_support_catalog(forward)
    second = validate_approved_change_capability_support_catalog(backward)
    assert first.status == second.status == "capability_support_catalog_valid"
    assert first.catalog_identity_sha256 == second.catalog_identity_sha256
    assert first.capability_ids == second.capability_ids == ("a.first", "z.last")


@pytest.mark.parametrize(
    "value", [None, "catalog", b"catalog", 1, 1.5, True, [], (), ["declarations"]]
)
def test_structurally_impossible_catalog_input_is_reported_separately(value):
    result = validate_approved_change_capability_support_catalog(value)
    assert result.status == "invalid_capability_support_catalog_input"
    assert result.catalog_valid is False
    assert result.catalog_identity_sha256 == ""


def test_catalog_validation_statuses_are_exactly_the_maintained_set():
    assert set(CATALOG_VALIDATION_STATUSES) == {
        "capability_support_catalog_valid",
        "capability_support_catalog_invalid",
        "invalid_capability_support_catalog_input",
    }


# --------------------------------------------------------------------------
# Supported evaluation
# --------------------------------------------------------------------------


def test_supported_evaluation_confirms_declared_capability_support(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    before = snapshot(root)

    result = evaluate(artifact.approval_artifact_id, root)

    assert result.status == "capability_support_confirmed"
    assert result.evaluation_complete is True
    assert result.requested_approval_artifact_id == artifact.approval_artifact_id
    assert result.loaded_approval_artifact_id == artifact.approval_artifact_id
    assert result.approval_artifact_load_status == REQUIRED_APPROVAL_ARTIFACT_LOAD_STATUS
    assert result.approval_artifact_loaded is True
    assert result.approval_artifact_valid is True
    assert result.approval_binding_valid is True
    assert result.capability_id == WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID
    assert result.catalog_valid is True
    assert result.catalog_identity_sha256 == MAINTAINED_CATALOG_IDENTITY_SHA256
    assert result.confirmed_catalog_identity_sha256 == MAINTAINED_CATALOG_IDENTITY_SHA256
    assert result.supported_capability_ids == EXPECTED_SUPPORTED_CAPABILITY_IDS
    assert result.declaration_found is True
    assert result.declaration is not None
    assert result.declaration.capability_id == WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID
    assert result.declaration.support_status == SUPPORT_STATUS_DECLARED_SUPPORTED
    assert result.declaration.match_rule == MATCH_RULE_EXACT_CAPABILITY_ID_ONLY
    assert result.declaration.validation_scope == VALIDATION_SCOPE_CONTRACT_VALIDATION_ONLY
    assert result.contract_validation is not None
    assert result.contract_validation.status == "contract_valid"
    assert result.contract_validation.capability_supported is True
    assert result.errors == ()

    assert result.capability_support_evaluated is True
    assert result.capability_supported is True
    assert result.filesystem_accessed is True
    assert_evaluation_never_expands(result)
    assert snapshot(root) == before


def test_a_supported_result_never_claims_binding_authorization_preflight_or_execution(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    result = evaluate(artifact.approval_artifact_id, root)
    assert result.capability_bound is False
    assert result.authorization_evaluated is False
    assert result.preflight_evaluated is False
    assert result.receipt_created is False
    assert result.receipt_linked is False
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"
    assert result.declaration.capability_binding_available is False
    assert result.declaration.authorization_available is False
    assert result.declaration.preflight_available is False
    assert result.declaration.receipt_linkage_available is False
    assert result.declaration.execution_available is False


# --------------------------------------------------------------------------
# Unsupported evaluation
# --------------------------------------------------------------------------


def test_an_unknown_capability_is_a_completed_fail_closed_evaluation(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(bundle_a(), root)
    before = snapshot(root)

    load_result = load_persisted_approved_change_approval_artifact(
        artifact.approval_artifact_id, data_dir=root
    )
    assert load_result.status == REQUIRED_APPROVAL_ARTIFACT_LOAD_STATUS
    assert load_result.approval_binding_valid is True
    assert load_result.artifact.contract.subject.capability_id == UNKNOWN_CAPABILITY_ID

    result = evaluate(artifact.approval_artifact_id, root)

    assert result.status == "capability_not_declared"
    assert result.evaluation_complete is True
    assert result.capability_support_evaluated is True
    assert result.capability_supported is False
    assert result.declaration_found is False
    assert result.declaration is None
    assert result.capability_id == UNKNOWN_CAPABILITY_ID
    assert result.approval_artifact_loaded is True
    assert result.approval_artifact_valid is True
    assert result.approval_binding_valid is True
    assert result.contract_validation is not None
    assert result.contract_validation.status == "unsupported_capability"
    assert result.contract_validation.approval_binding_valid is True
    assert result.contract_validation.capability_supported is False
    assert any(UNKNOWN_CAPABILITY_ID in item for item in result.errors)
    assert result.filesystem_accessed is True
    assert_evaluation_never_expands(result)
    assert snapshot(root) == before


@pytest.mark.parametrize("capability", NEAR_MISS_CAPABILITY_IDS)
def test_syntactically_valid_near_misses_remain_unsupported(tmp_path, capability):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(capability), root)
    result = evaluate(artifact.approval_artifact_id, root)
    assert result.status == "capability_not_declared"
    assert result.capability_id == capability
    assert result.capability_supported is False
    assert result.declaration_found is False
    assert result.contract_validation.status == "unsupported_capability"
    assert_evaluation_never_expands(result)


def test_support_is_exact_case_sensitive_equality_only():
    catalog = maintained_approved_change_capability_support_catalog()
    declared = {item.capability_id for item in catalog.declarations}
    for near_miss in NEAR_MISS_CAPABILITY_IDS:
        assert near_miss not in declared
    source = module_code_without_strings(support_module)
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
        assert token not in source, token


# --------------------------------------------------------------------------
# Capability-ID-only scope
#
# This is the essential proof that PR321 did not silently implement capability
# binding: two entirely different approved subjects that share only the exact
# declared capability ID are both declared supported.
# --------------------------------------------------------------------------


def test_two_different_subjects_sharing_one_capability_id_are_both_supported(tmp_path):
    root = data_dir(tmp_path)
    first = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    second = publish_for(alternate_supported_bundle(), root)
    assert first.approval_artifact_id != second.approval_artifact_id
    assert first.subject_sha256 != second.subject_sha256

    results = [evaluate(item.approval_artifact_id, root) for item in (first, second)]
    subjects = [item.contract.subject for item in (first, second)]

    assert subjects[0].target != subjects[1].target
    assert subjects[0].procedure != subjects[1].procedure
    assert subjects[0].evidence_references != subjects[1].evidence_references
    assert subjects[0].risk != subjects[1].risk
    assert subjects[0].rollback_posture != subjects[1].rollback_posture

    for result in results:
        assert result.status == "capability_support_confirmed"
        assert result.capability_id == WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID
        assert result.capability_supported is True
        assert result.capability_bound is False
        assert result.declaration == results[0].declaration
        assert "capability support does not validate target compatibility" in result.warnings
        assert "capability support does not validate procedure compatibility" in result.warnings
        assert "capability support does not evaluate current state" in result.warnings
        assert "capability support is not capability binding" in result.warnings


def test_permanent_warnings_state_every_maintained_limit(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    for result in (
        evaluate(artifact.approval_artifact_id, root),
        evaluate(artifact.approval_artifact_id, root, confirmation="nope"),
        validate_approved_change_capability_support_catalog(
            maintained_approved_change_capability_support_catalog()
        ),
    ):
        for statement in (
            "declared capability support is approved-change contract validation only",
            "support is decided only by exact case-sensitive capability_id equality",
            "capability support is not capability binding",
            "capability support is not authorization",
            "capability support does not validate target compatibility",
            "capability support does not validate procedure compatibility",
            "capability support does not evaluate current state",
            "capability support does not run a preflight",
            "capability support does not create or link a receipt",
            "capability support grants no execution eligibility",
            "windows.runtime_reconcile is not bound to the PR313 lane by this declaration",
            "an exact aca_ approval-artifact ID remains required",
            "no approval was selected through inventory",
            "persisted approved_by remains self-asserted metadata, not authenticated identity",
            "reviewer provenance is not approval",
            "no CLI or natural-language capability-support or execution route exists",
        ):
            assert statement in result.warnings


# --------------------------------------------------------------------------
# The explicit catalog-identity confirmation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "confirmation",
    [
        None,
        "",
        "   ",
        "not-a-hash",
        MAINTAINED_CATALOG_IDENTITY_SHA256.upper(),
        f"sha256:{MAINTAINED_CATALOG_IDENTITY_SHA256}",
        f"catalog_{MAINTAINED_CATALOG_IDENTITY_SHA256}",
        MAINTAINED_CATALOG_IDENTITY_SHA256[:63],
        MAINTAINED_CATALOG_IDENTITY_SHA256 + "0",
        f" {MAINTAINED_CATALOG_IDENTITY_SHA256}",
        123,
        b"a" * 64,
    ],
)
def test_malformed_catalog_confirmation_is_structurally_rejected(
    tmp_path, monkeypatch, loader_watch, confirmation
):
    watch = FsWatch(monkeypatch)
    result = evaluate_persisted_approved_change_capability_support(
        UNPUBLISHED_ARTIFACT_ID,
        data_dir=tmp_path,
        confirm_capability_catalog_identity_sha256=confirmation,
    )
    assert result.status == "invalid_capability_support_input"
    assert result.evaluation_complete is False
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert result.filesystem_accessed is False
    assert result.declaration is None
    assert result.contract_validation is None
    assert result.errors
    assert watch.calls == []
    assert loader_watch == []
    assert_evaluation_never_expands(result)


@pytest.mark.parametrize(
    "confirmation",
    [
        "0" * 64,
        "a" * 64,
        OTHER_HEX64,
        HEX64,
        FIXTURE_A_APPROVAL_ARTIFACT_IDENTITY_SHA256,
        hashlib.sha256(b"a stale catalog").hexdigest(),
    ],
)
def test_mismatched_catalog_confirmation_never_reaches_the_filesystem(
    tmp_path, monkeypatch, loader_watch, confirmation
):
    watch = FsWatch(monkeypatch)
    result = evaluate_persisted_approved_change_capability_support(
        UNPUBLISHED_ARTIFACT_ID,
        data_dir=tmp_path,
        confirm_capability_catalog_identity_sha256=confirmation,
    )
    assert result.status == "capability_catalog_confirmation_mismatch"
    assert result.evaluation_complete is False
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert result.filesystem_accessed is False
    assert result.confirmed_catalog_identity_sha256 == confirmation
    assert result.catalog_identity_sha256 == MAINTAINED_CATALOG_IDENTITY_SHA256
    assert result.declaration is None
    assert watch.calls == []
    assert loader_watch == []
    assert_evaluation_never_expands(result)


def test_a_subject_sha256_is_never_accepted_as_a_catalog_identity(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    subject_sha = artifact.subject_sha256
    assert subject_sha != MAINTAINED_CATALOG_IDENTITY_SHA256
    watch = FsWatch(monkeypatch)
    result = evaluate(artifact.approval_artifact_id, root, confirmation=subject_sha)
    assert result.status == "capability_catalog_confirmation_mismatch"
    assert result.filesystem_accessed is False
    assert watch.calls == []


def test_an_artifact_identity_is_never_accepted_as_a_catalog_identity(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    watch = FsWatch(monkeypatch)
    result = evaluate(
        artifact.approval_artifact_id,
        root,
        confirmation=artifact.approval_artifact_identity_sha256,
    )
    assert result.status == "capability_catalog_confirmation_mismatch"
    assert result.filesystem_accessed is False
    assert watch.calls == []


def test_the_exact_catalog_identity_is_the_only_accepted_confirmation(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    result = evaluate_persisted_approved_change_capability_support(
        artifact.approval_artifact_id,
        data_dir=root,
        confirm_capability_catalog_identity_sha256=MAINTAINED_CATALOG_IDENTITY_SHA256,
    )
    assert result.status == "capability_support_confirmed"


def test_the_confirmation_is_compared_with_compare_digest():
    source = inspect.getsource(evaluate_persisted_approved_change_capability_support)
    assert "hmac.compare_digest" in source


# --------------------------------------------------------------------------
# Artifact loading failures
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
    ],
)
def test_a_malformed_artifact_id_is_never_support(tmp_path, artifact_id):
    root = data_dir(tmp_path)
    result = evaluate(artifact_id, root)
    assert result.status == "invalid_capability_support_input"
    assert result.evaluation_complete is False
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert result.declaration is None
    assert result.contract_validation is None
    assert_evaluation_never_expands(result)
    assert_no_host_paths(result, root)


def test_an_absent_artifact_is_never_support(tmp_path):
    root = data_dir(tmp_path)
    result = evaluate(UNPUBLISHED_ARTIFACT_ID, root)
    assert result.status == "approval_artifact_not_available"
    assert result.evaluation_complete is False
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert result.approval_artifact_loaded is False
    assert_evaluation_never_expands(result)
    assert_no_host_paths(result, root)


@pytest.mark.parametrize("root_value", ["relative/path", "", None, 7, Path("relative")])
def test_an_unsafe_data_root_is_never_support(tmp_path, root_value):
    result = evaluate(UNPUBLISHED_ARTIFACT_ID, root_value)
    assert result.status in {"approval_artifact_not_available", "invalid_capability_support_input"}
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert_evaluation_never_expands(result)


def test_a_missing_data_root_is_never_support(tmp_path):
    result = evaluate(UNPUBLISHED_ARTIFACT_ID, tmp_path / "absent")
    assert result.status == "approval_artifact_not_available"
    assert result.capability_supported is False
    assert_no_host_paths(result, tmp_path)


def test_an_invalid_persisted_artifact_is_never_support(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    write_artifact_directory(
        root,
        artifact,
        mutate=lambda payload: {APPROVED_CHANGE_APPROVAL_FILENAME: b"{not json"},
    )
    result = evaluate(artifact.approval_artifact_id, root)
    assert result.status == "approval_artifact_invalid"
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert result.declaration is None
    assert_evaluation_never_expands(result)
    assert_no_host_paths(result, root)


def test_a_missing_source_bundle_is_never_support(tmp_path):
    """The artifact is valid, but its exact PR317 source bundle is absent."""
    staging = tmp_path / "staging"
    staging.mkdir()
    built = build_approved_change_approval_artifact(
        workflow_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), staging)
    )
    assert built.status == "approval_artifact_constructed"
    root = data_dir(tmp_path)
    write_artifact_directory(root, built.artifact)
    result = evaluate(built.artifact.approval_artifact_id, root)
    assert result.status == "approval_artifact_invalid"
    assert result.capability_supported is False
    assert result.capability_support_evaluated is False
    assert_no_host_paths(result, root)


def test_an_injected_loader_failure_is_never_support(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    real = load_persisted_approved_change_approval_artifact

    def broken(artifact_id, *, data_dir):
        loaded = real(artifact_id, data_dir=data_dir)
        return loaded.model_copy(update={"approval_binding_valid": False})

    monkeypatch.setattr(support_module, "load_persisted_approved_change_approval_artifact", broken)
    result = evaluate(artifact.approval_artifact_id, root)
    assert result.status == "capability_support_evaluation_blocked"
    assert result.capability_supported is False
    assert result.capability_support_evaluated is False
    assert result.declaration is None
    assert any("approval binding" in item for item in result.errors)


def test_an_unexpected_loader_status_blocks(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    real = load_persisted_approved_change_approval_artifact

    def surprising(artifact_id, *, data_dir):
        loaded = real(artifact_id, data_dir=data_dir)
        return loaded.model_copy(update={"status": "some_new_status"})

    monkeypatch.setattr(
        support_module, "load_persisted_approved_change_approval_artifact", surprising
    )
    result = evaluate(artifact.approval_artifact_id, root)
    assert result.status == "capability_support_evaluation_blocked"
    assert result.approval_artifact_load_status == "some_new_status"
    assert result.capability_supported is False


def test_a_loader_result_without_source_revalidation_blocks(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    real = load_persisted_approved_change_approval_artifact

    def unrevalidated(artifact_id, *, data_dir):
        loaded = real(artifact_id, data_dir=data_dir)
        return loaded.model_copy(update={"source_bundle_revalidated": False})

    monkeypatch.setattr(
        support_module, "load_persisted_approved_change_approval_artifact", unrevalidated
    )
    result = evaluate(artifact.approval_artifact_id, root)
    assert result.status == "capability_support_evaluation_blocked"
    assert any("source-bundle provenance" in item for item in result.errors)


def test_every_maintained_loader_status_is_classified():
    classified = {
        "persisted_approval_artifact_loaded",
        "persisted_approval_artifact_not_found",
        "persisted_approval_artifact_invalid",
        "invalid_approval_artifact_reference",
        "unsafe_approval_persistence_root",
    }
    assert set(LOAD_STATUSES) == classified


# --------------------------------------------------------------------------
# PR309 remains the validation authority
# --------------------------------------------------------------------------


def test_pr309_is_called_exactly_once_with_the_exact_contract_and_tuple(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    spy = ValidatorSpy(monkeypatch)
    result = evaluate(artifact.approval_artifact_id, root)
    assert result.status == "capability_support_confirmed"
    assert len(spy.calls) == 1
    contract, supported = spy.calls[0]
    assert contract == artifact.contract
    assert supported == EXPECTED_SUPPORTED_CAPABILITY_IDS
    assert isinstance(supported, tuple)


def test_pr309_receives_the_exact_tuple_even_for_an_unsupported_capability(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(bundle_a(), root)
    spy = ValidatorSpy(monkeypatch)
    result = evaluate(artifact.approval_artifact_id, root)
    assert result.status == "capability_not_declared"
    assert len(spy.calls) == 1
    assert spy.calls[0][1] == EXPECTED_SUPPORTED_CAPABILITY_IDS


def test_pr321_never_skips_pr309_for_its_own_membership_answer(tmp_path, monkeypatch):
    """PR309 says unsupported for the declared capability; PR321 must obey."""
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    ValidatorSpy(monkeypatch, status="unsupported_capability")
    result = evaluate(artifact.approval_artifact_id, root)
    assert result.status == "capability_not_declared"
    assert result.capability_supported is False
    assert result.declaration_found is False
    assert result.capability_id == WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID


def test_pr309_accepting_an_undeclared_capability_fails_closed(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(bundle_a(), root)
    ValidatorSpy(monkeypatch, status="contract_valid")
    result = evaluate(artifact.approval_artifact_id, root)
    assert result.status == "capability_support_evaluation_blocked"
    assert result.capability_supported is False
    assert result.declaration_found is False
    assert result.declaration is None


@pytest.mark.parametrize(
    "status", ["contract_invalid", "approval_mismatch", "invalid_validation_input"]
)
def test_unexpected_pr309_statuses_fail_closed(tmp_path, monkeypatch, status):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    ValidatorSpy(monkeypatch, status=status)
    result = evaluate(artifact.approval_artifact_id, root)
    assert result.status == "capability_contract_validation_failed"
    assert result.evaluation_complete is False
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert result.declaration is None
    assert_evaluation_never_expands(result)


def test_a_pr309_binding_failure_fails_closed(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    ValidatorSpy(
        monkeypatch,
        result=ContractValidationResult(
            status="approval_mismatch",
            contract_valid=False,
            approval_binding_valid=False,
            capability_supported=False,
            computed_subject_sha256="0" * 64,
        ),
    )
    result = evaluate(artifact.approval_artifact_id, root)
    assert result.status == "capability_contract_validation_failed"
    assert result.approval_binding_valid is False
    assert result.capability_supported is False
    assert result.capability_support_evaluated is False


def test_pr321_defines_no_competing_contract_validator():
    source = Path(support_module.__file__).read_text(encoding="utf-8")
    assert "validate_approved_change_contract" in source
    assert "def validate_approved_change_contract" not in source
    assert "compute_subject_sha256" not in source
    assert "verify_approval_binding" not in source
    assert "subject_sha256 ==" not in source


def test_evaluation_statuses_are_exactly_the_maintained_set():
    assert set(EVALUATION_STATUSES) == {
        "capability_support_confirmed",
        "capability_not_declared",
        "capability_support_evaluation_blocked",
        "invalid_capability_support_input",
        "capability_catalog_confirmation_mismatch",
        "approval_artifact_not_available",
        "approval_artifact_invalid",
        "capability_contract_validation_failed",
    }


# --------------------------------------------------------------------------
# No inventory selection
# --------------------------------------------------------------------------


def test_the_pr320_inventory_is_never_called(tmp_path, monkeypatch):
    from shellforgeai.core import approved_change_approval_inventory as inventory_module

    def boom(*args, **kwargs):
        raise AssertionError("PR321 must never call the PR320 inventory")

    monkeypatch.setattr(
        inventory_module,
        "inventory_persisted_approved_change_approval_artifacts",
        boom,
    )
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    assert evaluate(artifact.approval_artifact_id, root).status == "capability_support_confirmed"


def test_static_no_inventory_import_or_selection_vocabulary():
    source = module_code_without_strings(support_module)
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
    fields = set(ApprovedChangeCapabilitySupportEvaluationResult.model_fields)
    for banned in ("selected_approval_artifact_id", "latest", "current", "preferred_declaration"):
        assert banned not in fields


def test_an_exact_artifact_id_is_always_required(tmp_path):
    root = data_dir(tmp_path)
    publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    for reference in ("latest", "current", "most_recent", APPROVAL_ARTIFACT_ID_PREFIX):
        result = evaluate(reference, root)
        assert result.status == "invalid_capability_support_input"
        assert result.capability_supported is False


# --------------------------------------------------------------------------
# No recipe registry, no PR313 binding
# --------------------------------------------------------------------------


def test_no_recipe_registry_or_pr313_module_is_reached(tmp_path, monkeypatch):
    from shellforgeai.core import recipe_registry
    from shellforgeai.core import windows_runtime_reconcile_execution as pr313

    def boom(name):
        def raiser(*args, **kwargs):
            raise AssertionError(f"PR321 must never reach {name}")

        return raiser

    for module, names in (
        (recipe_registry, [n for n in dir(recipe_registry) if not n.startswith("_")]),
        (pr313, [n for n in dir(pr313) if not n.startswith("_")]),
    ):
        for name in names:
            if callable(getattr(module, name, None)):
                monkeypatch.setattr(module, name, boom(f"{module.__name__}.{name}"), raising=False)

    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    result = evaluate(artifact.approval_artifact_id, root)
    assert result.status == "capability_support_confirmed"
    assert result.capability_bound is False


def test_static_no_recipe_pr313_pr304_or_pr305_reference():
    source = module_code_without_strings(support_module)
    for token in (
        "recipe",
        "_RECIPES",
        "windows_runtime_reconcile_execution",
        "windows_runtime_reconcile_preflight",
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
    ):
        assert token not in source, token


def test_the_declaration_never_claims_a_pr313_binding(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    result = evaluate(artifact.approval_artifact_id, root)
    assert result.capability_bound is False
    assert result.declaration.capability_binding_available is False
    assert (
        "windows.runtime_reconcile is not bound to the PR313 lane by this declaration"
        in result.warnings
    )
    payload = json.dumps(result.model_dump(mode="json"))
    assert "binding_id" not in payload
    assert "bound_lane" not in payload


# --------------------------------------------------------------------------
# No writes and no hidden expansion
# --------------------------------------------------------------------------


def test_catalog_operations_reach_no_filesystem_primitive(monkeypatch):
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

    catalog = maintained_approved_change_capability_support_catalog()
    canonical_approved_change_capability_support_catalog_payload(catalog)
    canonical_approved_change_capability_support_catalog_json(catalog)
    compute_approved_change_capability_support_catalog_sha256(catalog)
    result = validate_approved_change_capability_support_catalog(catalog)
    assert result.catalog_valid is True
    assert watch.calls == []


def test_evaluation_reaches_no_write_capable_primitive(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    before = snapshot(root)

    def raiser(name):
        def boom(*args, **kwargs):
            raise AssertionError(f"{name} was reached during a read-only evaluation")

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

    assert evaluate(artifact.approval_artifact_id, root).status == "capability_support_confirmed"
    assert snapshot(root) == before


def test_no_shell_network_model_credential_clock_or_randomness_is_reached(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)

    def raiser(name):
        def boom(*args, **kwargs):
            raise AssertionError(f"{name} was reached during a read-only evaluation")

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

    assert evaluate(artifact.approval_artifact_id, root).status == "capability_support_confirmed"


def test_static_the_import_set_is_exactly_the_maintained_dependencies():
    tree = ast.parse(Path(support_module.__file__).read_text(encoding="utf-8"))
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
        "shellforgeai.core.approved_change_approval_persistence",
        "shellforgeai.core.approved_change_contract",
        "typing",
    }


def test_static_no_publisher_executor_preflight_or_receipt_call():
    source = module_code_without_strings(support_module)
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
    tree = ast.parse(Path(support_module.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.module != "shellforgeai.core.approvals"
        if isinstance(node, ast.Name):
            assert node.id != "Proposal"
    source = module_code_without_strings(support_module)
    for token in ("Proposal", "core.approvals", "approve_proposal", "fingerprint"):
        assert token not in source, token


def test_signatures_never_take_or_return_legacy_approval_types():
    for _, obj in inspect.getmembers(support_module, inspect.isfunction):
        signature = inspect.signature(obj)
        assert all(param.annotation is not Proposal for param in signature.parameters.values())
        assert "Proposal" not in str(signature)


def test_the_public_surface_is_exactly_the_maintained_operations():
    public = sorted(
        name
        for name, obj in inspect.getmembers(support_module, inspect.isfunction)
        if not name.startswith("_") and obj.__module__ == support_module.__name__
    )
    assert public == [
        "canonical_approved_change_capability_support_catalog_json",
        "canonical_approved_change_capability_support_catalog_payload",
        "compute_approved_change_capability_support_catalog_sha256",
        "evaluate_persisted_approved_change_capability_support",
        "maintained_approved_change_capability_support_catalog",
        "validate_approved_change_capability_support_catalog",
    ]
    for banned in (
        "bind_capability",
        "authorize",
        "preflight",
        "create_receipt",
        "execute",
        "register_capability",
        "discover_capabilities",
        "persist_catalog",
        "load_catalog",
    ):
        assert not hasattr(support_module, banned), banned


def test_the_module_is_not_imported_by_cli_approvals_recipes_or_execution():
    roots = [Path("src/shellforgeai/cli"), Path("src/shellforgeai/core")]
    offenders = [
        str(path)
        for base in roots
        for path in base.rglob("*.py")
        if path.name != "approved_change_capability_support.py"
        and "approved_change_capability_support" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_no_cli_surface_was_added():
    cli = Path("docs/cli.md").read_text(encoding="utf-8")
    assert "capability-support" not in cli
    assert "approved_change_capability_support" not in cli
    offenders = [
        str(path)
        for path in Path("src/shellforgeai/cli").rglob("*.py")
        if "capability_support" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_no_new_persisted_artifact_was_introduced():
    layout = Path("docs/data-layout.md").read_text(encoding="utf-8")
    assert "capability_support" not in layout
    assert "capability-support" not in layout


def test_importing_the_module_touches_nothing(tmp_path, monkeypatch):
    import importlib

    calls: list[str] = []
    monkeypatch.chdir(tmp_path)
    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append("subprocess.run"))
    monkeypatch.setattr(os, "system", lambda *a, **k: calls.append("os.system"))
    monkeypatch.setattr(socket, "socket", lambda *a, **k: calls.append("socket"))
    sys.modules.pop("shellforgeai.core.approved_change_capability_support", None)
    importlib.import_module("shellforgeai.core.approved_change_capability_support")
    assert sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")) == before
    assert calls == []


# --------------------------------------------------------------------------
# Cross-platform parity
# --------------------------------------------------------------------------


def test_cross_platform_parity_of_catalog_bytes_and_identity():
    """These exact values must hold byte for byte on Linux and on Windows."""
    catalog = maintained_approved_change_capability_support_catalog()
    canonical = canonical_approved_change_capability_support_catalog_json(catalog)
    assert canonical == MAINTAINED_CATALOG_CANONICAL_JSON
    assert canonical.encode("utf-8") == MAINTAINED_CATALOG_CANONICAL_JSON.encode("utf-8")
    assert len(canonical.encode("utf-8")) == MAINTAINED_CATALOG_BYTE_LENGTH == 465
    assert "\r" not in canonical
    assert compute_approved_change_capability_support_catalog_sha256(catalog) == (
        MAINTAINED_CATALOG_IDENTITY_SHA256
    )


def test_cross_platform_parity_of_supported_and_unsupported_evaluation(tmp_path):
    """Identical persisted artifacts must produce identical results everywhere."""
    root = data_dir(tmp_path)
    supported = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    unsupported = publish_for(bundle_a(), root)

    assert unsupported.approval_artifact_id == FIXTURE_A_APPROVAL_ARTIFACT_ID

    ok = evaluate(supported.approval_artifact_id, root)
    no = evaluate(unsupported.approval_artifact_id, root)

    assert ok.status == "capability_support_confirmed"
    assert ok.capability_id == "windows.runtime_reconcile"
    assert ok.contract_validation.status == "contract_valid"
    assert ok.declaration.model_dump(mode="json") == {
        "schema_version": "1",
        "capability_id": "windows.runtime_reconcile",
        "support_status": "declared_supported",
        "match_rule": "exact_capability_id_only",
        "validation_scope": "approved_change_contract_validation_only",
        "capability_binding_available": False,
        "authorization_available": False,
        "preflight_available": False,
        "receipt_linkage_available": False,
        "execution_available": False,
    }
    assert ok.warnings == PERMANENT_CAPABILITY_SUPPORT_WARNINGS
    assert ok.catalog_identity_sha256 == MAINTAINED_CATALOG_IDENTITY_SHA256

    assert no.status == "capability_not_declared"
    assert no.capability_id == UNKNOWN_CAPABILITY_ID
    assert no.contract_validation.status == "unsupported_capability"
    assert no.declaration is None
    assert no.warnings == PERMANENT_CAPABILITY_SUPPORT_WARNINGS
    assert no.loaded_approval_artifact_id == FIXTURE_A_APPROVAL_ARTIFACT_ID

    for result in (ok, no):
        assert result.evaluation_complete is True
        assert result.capability_support_evaluated is True
        assert result.approval_binding_valid is True
        assert result.filesystem_accessed is True
        assert_evaluation_never_expands(result)


# --------------------------------------------------------------------------
# Immutability and structured failure
# --------------------------------------------------------------------------


def test_every_model_is_frozen_and_forbids_extra_fields(tmp_path):
    root = data_dir(tmp_path)
    artifact = publish_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    catalog = maintained_approved_change_capability_support_catalog()
    (declaration,) = catalog.declarations
    catalog_result = validate_approved_change_capability_support_catalog(catalog)
    evaluation = evaluate(artifact.approval_artifact_id, root)

    for model in (
        ApprovedChangeCapabilitySupportDeclaration,
        ApprovedChangeCapabilitySupportCatalog,
        ApprovedChangeCapabilitySupportCatalogValidationResult,
        ApprovedChangeCapabilitySupportEvaluationResult,
    ):
        assert model.model_config["frozen"] is True
        assert model.model_config["extra"] == "forbid"

    with pytest.raises(ValidationError):
        declaration.execution_available = True
    with pytest.raises(ValidationError):
        catalog.declarations = ()
    with pytest.raises(ValidationError):
        catalog_result.catalog_valid = False
    with pytest.raises(ValidationError):
        evaluation.capability_supported = False
    with pytest.raises(ValidationError):
        evaluation.execution_allowed = True
    with pytest.raises(ValidationError):
        ApprovedChangeCapabilitySupportDeclaration(
            capability_id=WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID, extra="x"
        )


def test_errors_and_warnings_are_immutable_sorted_and_deduplicated(tmp_path):
    root = data_dir(tmp_path)
    result = evaluate(UNPUBLISHED_ARTIFACT_ID, root, confirmation="zz")
    assert isinstance(result.errors, tuple)
    assert isinstance(result.warnings, tuple)
    assert list(result.errors) == sorted(set(result.errors))
    with pytest.raises((AttributeError, TypeError)):
        result.errors.append("x")

    catalog_result = validate_approved_change_capability_support_catalog(
        catalog_payload(declaration_payload(), declaration_payload())
    )
    assert list(catalog_result.errors) == sorted(set(catalog_result.errors))


def test_no_partial_declaration_survives_a_failed_evaluation(tmp_path):
    root = data_dir(tmp_path)
    for result in (
        evaluate(UNPUBLISHED_ARTIFACT_ID, root),
        evaluate(UNPUBLISHED_ARTIFACT_ID, root, confirmation="0" * 64),
        evaluate("not-an-id", root),
    ):
        assert result.declaration is None
        assert result.declaration_found is False
        assert result.contract_validation is None
        assert result.capability_supported is False
        assert result.evaluation_complete is False


def test_no_traceback_or_host_path_is_ever_reported(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID), root)
    write_artifact_directory(
        root, artifact, mutate=lambda payload: {APPROVED_CHANGE_APPROVAL_FILENAME: b"\xff\xfe"}
    )
    for result in (
        evaluate(artifact.approval_artifact_id, root),
        evaluate(UNPUBLISHED_ARTIFACT_ID, root),
        evaluate(UNPUBLISHED_ARTIFACT_ID, tmp_path / "missing-root"),
    ):
        assert_no_host_paths(result, root)
        assert_no_host_paths(result, tmp_path)
        assert 'File "' not in json.dumps(result.model_dump(mode="json"))


def test_the_publication_root_is_never_created_by_an_evaluation(tmp_path):
    root = data_dir(tmp_path)
    result = evaluate(UNPUBLISHED_ARTIFACT_ID, root)
    assert result.status == "approval_artifact_not_available"
    assert not publication_root(root).exists()


def test_a_valid_bundle_without_an_approval_is_never_support(tmp_path):
    root = data_dir(tmp_path)
    bundle = capability_bundle(WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID)
    publish_bundle(bundle, root)
    result = evaluate(UNPUBLISHED_ARTIFACT_ID, root)
    assert result.capability_supported is False
    assert result.status == "approval_artifact_not_available"
