"""Canonical approved-change approval artifact contract (PR319).

PR318 binds one explicit approval to one exact persisted reviewed-change bundle
and returns exactly one immutable ``ApprovalAttestation`` and one immutable
``ApprovedChangeContract`` — in memory, and nowhere else. An in-memory approval
disappears with the process.

This module defines exactly one pure, immutable, deterministic,
checksum-protected approval artifact: the complete persistence payload that a
governed writer publishes to preserve one successful PR318 approval and its
source provenance. It holds one canonical UTF-8 JSON logical file, its exact
byte length, a non-circular approval-artifact identity, and the derived full
``aca_`` artifact ID.

It is deliberately inert. It touches no filesystem, creates no file or
directory, performs no persistence or publication, creates no approval or
``ApprovedChangeContract`` of its own, evaluates or binds no capability, runs no
preflight, creates or links no receipt, and enables no execution. It records the
approval that PR318 already created; ``approved_change_approval_persistence``
(PR319) owns the filesystem boundary.

Private canonicalization helpers are imported from the maintained upstream
modules on purpose: stored approval bytes must obey exactly the same canonical
ordering and timestamp rules as the maintained PR309 schemas, and the source
bundle ID must obey exactly the PR316 rule. Nothing is redefined here.

``pathlib`` is not imported at all: this module holds no path, and every value
it uses is either a maintained upstream result or derived from one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from shellforgeai.core.approved_change_approval_workflow import (
    ApprovedChangeApprovalWorkflowResult,
)
from shellforgeai.core.approved_change_artifact_bundle import (
    BUNDLE_ID_PREFIX,
    _is_sha256,
    derive_bundle_id,
)
from shellforgeai.core.approved_change_contract import (
    APPROVAL_SCOPE_EXACT_SUBJECT_ONLY,
    EXECUTION_STATUS_NOT_EXECUTED,
    ApprovedChangeContract,
    ContractValidationResult,
    _canonicalize,
    canonical_subject_payload,
    compute_subject_sha256,
    verify_approval_binding,
)
from shellforgeai.core.approved_change_contract import (
    SCHEMA_VERSION as APPROVED_CHANGE_SCHEMA_VERSION,
)

APPROVAL_ARTIFACT_SCHEMA_VERSION = "1"

#: The fixed artifact type literal. There is no alias or caller-defined kind.
APPROVAL_ARTIFACT_TYPE = "approved_change_approval"

#: The one fixed canonical logical filename. There is no caller-defined name,
#: alias, optional file, sidecar, marker, pointer, subdirectory, glob, case
#: variant, or alternate extension.
APPROVED_CHANGE_APPROVAL_FILENAME = "approved-change-approval.json"

#: The approval-artifact ID prefix. It is permanently distinct from the PR316
#: reviewed-bundle prefix and from every other identity in the repository.
APPROVAL_ARTIFACT_ID_PREFIX = "aca_"

#: Exactly the fields that form the canonical persisted payload, in no
#: particular order: the canonical serializer always sorts mapping keys.
APPROVAL_ARTIFACT_PAYLOAD_FIELDS: tuple[str, ...] = (
    "schema_version",
    "artifact_type",
    "source_bundle_id",
    "source_bundle_identity_sha256",
    "subject_sha256",
    "contract",
)

#: The derived fields that are never part of the canonical payload, so the
#: approval-artifact identity can never hash itself.
APPROVAL_ARTIFACT_IDENTITY_EXCLUDED_FIELDS: tuple[str, ...] = (
    "canonical_content_utf8",
    "byte_length",
    "approval_artifact_identity_sha256",
    "approval_artifact_id",
)

#: The one PR318 workflow status this builder accepts. Nothing else is an
#: approval, and no other status is upgraded, retried, or repaired.
REQUIRED_APPROVAL_WORKFLOW_STATUS = "approval_contract_constructed"

BUILD_STATUSES = (
    "approval_artifact_constructed",
    "approval_artifact_construction_blocked",
    "invalid_approval_artifact_construction_input",
)
VALIDATION_STATUSES = (
    "approval_artifact_valid",
    "approval_artifact_invalid",
    "invalid_approval_artifact_validation_input",
)

BuildStatus = Literal[
    "approval_artifact_constructed",
    "approval_artifact_construction_blocked",
    "invalid_approval_artifact_construction_input",
]
ValidationStatus = Literal[
    "approval_artifact_valid",
    "approval_artifact_invalid",
    "invalid_approval_artifact_validation_input",
]

PERMANENT_APPROVAL_ARTIFACT_WARNINGS: tuple[str, ...] = (
    "persisted approved_by remains self-asserted metadata, not authenticated identity",
    "reviewer provenance is not approval",
    "the artifact records one immutable approval event, not mutable approval state",
    "persistence is not authorization",
    "a persisted ApprovedChangeContract is not capability support",
    "no capability registry has been consulted",
    "no current-state preflight has run",
    "no receipt has been created or linked",
    "no execution eligibility is granted",
    "there is no revocation, cancellation, expiration, supersession, or quorum semantics",
    "no overwrite is permitted: a persisted approval artifact is never replaced, repaired, "
    "renamed, quarantined, or deleted",
    "reviewed artifacts may contain operational context and must be reviewed before sharing",
    "no redaction is performed because redaction would change artifact identity",
)


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Canonical payload, non-circular identity, and the derived artifact ID
# ---------------------------------------------------------------------------


def _require_sha256(value: Any, label: str) -> str:
    if not _is_sha256(value):
        raise ValueError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _contract_payload(contract: ApprovedChangeContract) -> dict[str, Any]:
    """Serialize one maintained contract through the maintained canonicalizers.

    The subject goes through PR309 ``canonical_subject_payload`` so subject
    collection semantics stay exactly PR309's, and the approval goes through the
    maintained PR309 canonicalizer so ``approved_at`` is normalized to the
    maintained canonical UTC representation. No competing canonicalizer exists.
    """
    return {
        "schema_version": contract.schema_version,
        "subject": canonical_subject_payload(contract.subject),
        "approval": _canonicalize(contract.approval.model_dump(mode="python")),
    }


def canonical_approval_artifact_payload(
    artifact: ApprovedChangeApprovalArtifact | dict[str, Any],
) -> dict[str, Any]:
    """Return the canonical approval-artifact payload.

    The payload is exactly the six persisted fields. The canonical bytes, the
    byte length, the artifact identity, and the artifact ID are all derived from
    it and are never part of it, so the identity can never hash itself.
    """
    if isinstance(artifact, ApprovedChangeApprovalArtifact):
        fields: dict[str, Any] = {
            "schema_version": artifact.schema_version,
            "artifact_type": artifact.artifact_type,
            "source_bundle_id": artifact.source_bundle_id,
            "source_bundle_identity_sha256": artifact.source_bundle_identity_sha256,
            "subject_sha256": artifact.subject_sha256,
            "contract": artifact.contract,
        }
    else:
        fields = dict(artifact)
        for excluded in APPROVAL_ARTIFACT_IDENTITY_EXCLUDED_FIELDS:
            fields.pop(excluded, None)
    contract = fields.get("contract")
    if not isinstance(contract, ApprovedChangeContract):
        contract = ApprovedChangeContract.model_validate(contract)
    fields["contract"] = _contract_payload(contract)
    return _canonicalize(fields)


def canonical_approval_artifact_json(
    artifact: ApprovedChangeApprovalArtifact | dict[str, Any],
) -> str:
    """Return deterministic canonical approval-artifact JSON.

    Mapping keys are sorted, separators are compact, ``ensure_ascii`` is off so
    Unicode is preserved exactly, and there is no BOM and no trailing newline.
    Nothing is redacted, because redaction would change artifact identity.
    """
    return json.dumps(
        canonical_approval_artifact_payload(artifact),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_approval_artifact_identity_sha256(
    artifact: ApprovedChangeApprovalArtifact | dict[str, Any],
) -> str:
    """Compute the full, untruncated approval-artifact identity SHA-256.

    This identity is permanently distinct from the PR314 supplemental-context
    identity, the PR309 subject identity, the PR315 construction-evidence
    identity, the PR316 bundle identity, a legacy ``Proposal`` fingerprint, and
    the approval-to-subject binding. It is never capability support, an
    authorization, or execution confirmation.
    """
    return hashlib.sha256(canonical_approval_artifact_json(artifact).encode("utf-8")).hexdigest()


def derive_approval_artifact_id(approval_artifact_identity_sha256: str) -> str:
    """Derive the artifact ID from the full 64-character artifact identity."""
    return f"{APPROVAL_ARTIFACT_ID_PREFIX}{approval_artifact_identity_sha256}"


# ---------------------------------------------------------------------------
# The immutable in-memory approval artifact
# ---------------------------------------------------------------------------


class ApprovedChangeApprovalArtifact(_FrozenModel):
    """The immutable single-file approval artifact. It has no host path."""

    schema_version: Literal["1"] = APPROVAL_ARTIFACT_SCHEMA_VERSION
    artifact_type: Literal["approved_change_approval"] = APPROVAL_ARTIFACT_TYPE
    source_bundle_id: str
    source_bundle_identity_sha256: str
    subject_sha256: str
    contract: ApprovedChangeContract
    canonical_content_utf8: str
    byte_length: int
    approval_artifact_identity_sha256: str
    approval_artifact_id: str

    @field_validator("source_bundle_identity_sha256", "subject_sha256")
    @classmethod
    def _validate_sha256(cls, value: str) -> str:
        return _require_sha256(value, "approval artifact sha256")

    @model_validator(mode="after")
    def _validate_artifact(self) -> ApprovedChangeApprovalArtifact:
        if self.source_bundle_id != derive_bundle_id(self.source_bundle_identity_sha256):
            raise ValueError("source_bundle_id must be the prefixed full PR316 bundle identity")
        content = canonical_approval_artifact_json(self)
        if self.canonical_content_utf8 != content:
            raise ValueError("canonical_content_utf8 is not the canonical approval-artifact JSON")
        encoded = content.encode("utf-8")
        if self.byte_length != len(encoded):
            raise ValueError("byte_length does not match the canonical UTF-8 content")
        identity = hashlib.sha256(encoded).hexdigest()
        if not hmac.compare_digest(self.approval_artifact_identity_sha256, identity):
            raise ValueError(
                "approval_artifact_identity_sha256 is not the SHA-256 of the canonical bytes"
            )
        if self.approval_artifact_id != derive_approval_artifact_id(identity):
            raise ValueError("approval_artifact_id must be the prefixed full artifact identity")
        return self


# ---------------------------------------------------------------------------
# Structured results
# ---------------------------------------------------------------------------


class ApprovedChangeApprovalArtifactValidationResult(_FrozenModel):
    """Structured, non-throwing approval-artifact validation result.

    Validation is pure and inert: it recomputes canonical bytes, byte length,
    artifact identity, artifact ID, subject identity, and the PR309 approval
    binding, and it touches nothing.
    """

    schema_version: Literal["1"] = APPROVAL_ARTIFACT_SCHEMA_VERSION
    status: ValidationStatus
    reason: str = ""
    artifact_valid: bool
    source_bundle_id: str = ""
    source_bundle_identity_sha256: str = ""
    subject_sha256: str = ""
    computed_subject_sha256: str = ""
    computed_byte_length: int = 0
    computed_approval_artifact_identity_sha256: str = ""
    computed_approval_artifact_id: str = ""
    approval_binding_valid: bool = False
    approval_scope: str = ""
    binding_validation: ContractValidationResult | None = None
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_APPROVAL_ARTIFACT_WARNINGS

    # Accurate safety ledger. Validation reaches nothing.
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    filesystem_accessed: Literal[False] = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    approval_created: Literal[False] = False
    contract_created: Literal[False] = False
    approval_persisted: Literal[False] = False
    contract_persisted: Literal[False] = False
    overwrite_performed: Literal[False] = False
    source_bundle_mutation_performed: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    capability_support_evaluated: Literal[False] = False
    capability_supported: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


class ApprovedChangeApprovalArtifactBuildResult(_FrozenModel):
    """Structured, non-throwing approval-artifact construction result.

    A successful result means only that a complete, canonical, internally
    consistent in-memory persistence payload exists for one approval PR318
    already created. PR319 creates no approval and no contract of its own.
    """

    schema_version: Literal["1"] = APPROVAL_ARTIFACT_SCHEMA_VERSION
    status: BuildStatus
    reason: str = ""
    build_succeeded: bool
    source_bundle_id: str = ""
    source_bundle_identity_sha256: str = ""
    subject_sha256: str = ""
    approval_artifact_identity_sha256: str = ""
    approval_artifact_id: str = ""
    byte_length: int = 0
    artifact: ApprovedChangeApprovalArtifact | None = None
    artifact_validation: ApprovedChangeApprovalArtifactValidationResult | None = None
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_APPROVAL_ARTIFACT_WARNINGS

    # Accurate safety ledger. Building reaches nothing.
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    filesystem_accessed: Literal[False] = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    approval_created: Literal[False] = False
    contract_created: Literal[False] = False
    approval_persisted: Literal[False] = False
    contract_persisted: Literal[False] = False
    overwrite_performed: Literal[False] = False
    source_bundle_mutation_performed: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    capability_support_evaluated: Literal[False] = False
    capability_supported: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


# ---------------------------------------------------------------------------
# Canonical-payload reconstruction
# ---------------------------------------------------------------------------


def _artifact_from_canonical_payload(
    payload: Any,
) -> tuple[ApprovedChangeApprovalArtifact | None, list[str]]:
    """Reconstruct one artifact from an untrusted canonical payload mapping.

    Every derived field is recomputed from the maintained canonicalizer, never
    taken from the payload, so a persisted payload can never assert its own
    identity, byte length, or ID.
    """
    if not isinstance(payload, dict):
        return None, ["the approval artifact payload must be a JSON object"]
    fields = dict(payload)
    errors = [
        *(
            f"the approval artifact payload is missing the required field: {name}"
            for name in sorted(set(APPROVAL_ARTIFACT_PAYLOAD_FIELDS) - set(fields))
        ),
        *(
            f"the approval artifact payload carries an unexpected field: {name}"
            for name in sorted(set(fields) - set(APPROVAL_ARTIFACT_PAYLOAD_FIELDS))
        ),
    ]
    if errors:
        return None, errors
    try:
        contract = ApprovedChangeContract.model_validate(fields["contract"])
    except Exception as exc:  # untrusted stored bytes must never raise publicly
        return None, [
            f"the approval artifact contract does not parse into the maintained PR309 "
            f"contract: {exc}"
        ]
    try:
        content = canonical_approval_artifact_json({**fields, "contract": contract})
        encoded = content.encode("utf-8")
        identity = hashlib.sha256(encoded).hexdigest()
        artifact = ApprovedChangeApprovalArtifact(
            schema_version=fields["schema_version"],
            artifact_type=fields["artifact_type"],
            source_bundle_id=fields["source_bundle_id"],
            source_bundle_identity_sha256=fields["source_bundle_identity_sha256"],
            subject_sha256=fields["subject_sha256"],
            contract=contract,
            canonical_content_utf8=content,
            byte_length=len(encoded),
            approval_artifact_identity_sha256=identity,
            approval_artifact_id=derive_approval_artifact_id(identity),
        )
    except Exception as exc:  # untrusted stored bytes must never raise publicly
        return None, [f"the payload does not form one maintained approval artifact: {exc}"]
    return artifact, []


# ---------------------------------------------------------------------------
# Public artifact validation
# ---------------------------------------------------------------------------


def _validation_result(
    status: ValidationStatus,
    errors: list[str],
    *,
    reason: str = "",
    source_bundle_id: str = "",
    source_bundle_identity_sha256: str = "",
    subject_sha256: str = "",
    computed_subject_sha256: str = "",
    computed_byte_length: int = 0,
    computed_identity: str = "",
    computed_artifact_id: str = "",
    approval_binding_valid: bool = False,
    approval_scope: str = "",
    binding_validation: ContractValidationResult | None = None,
) -> ApprovedChangeApprovalArtifactValidationResult:
    return ApprovedChangeApprovalArtifactValidationResult(
        status=status,
        reason=reason,
        artifact_valid=status == "approval_artifact_valid",
        source_bundle_id=source_bundle_id,
        source_bundle_identity_sha256=source_bundle_identity_sha256,
        subject_sha256=subject_sha256,
        computed_subject_sha256=computed_subject_sha256,
        computed_byte_length=computed_byte_length,
        computed_approval_artifact_identity_sha256=computed_identity,
        computed_approval_artifact_id=computed_artifact_id,
        approval_binding_valid=approval_binding_valid,
        approval_scope=approval_scope,
        binding_validation=binding_validation,
        errors=tuple(sorted(set(errors))),
    )


def validate_approved_change_approval_artifact(
    artifact: ApprovedChangeApprovalArtifact | dict[str, Any],
) -> ApprovedChangeApprovalArtifactValidationResult:
    """Validate one complete approval artifact and its whole identity chain.

    The validator is pure and fail closed. It recomputes the canonical payload,
    the canonical bytes, the byte length, the artifact identity, the artifact ID,
    the PR309 subject identity, and the PR309 approval binding, and it requires
    the outer subject identity, the contract subject identity, and the approval
    subject identity to agree exactly.

    A valid result means only that the in-memory persistence payload is
    complete, canonical, and internally consistent. It is never authorization,
    capability support, a preflight result, a receipt, or execution eligibility.
    """
    # 1. Top-level model.
    if isinstance(artifact, ApprovedChangeApprovalArtifact):
        parsed = artifact
    elif isinstance(artifact, dict):
        try:
            parsed = ApprovedChangeApprovalArtifact.model_validate(artifact)
        except Exception as exc:  # pydantic exposes many structured subclasses.
            return _validation_result(
                "approval_artifact_invalid",
                [f"approval artifact model validation failed: {exc}"],
                reason="the approval artifact is not one maintained artifact",
            )
    else:
        return _validation_result(
            "invalid_approval_artifact_validation_input",
            ["approval artifact must be a model instance or a mapping"],
            reason="the approval artifact input is not a model instance or a mapping",
        )

    errors: list[str] = []

    # 2-3. Fixed schema version and artifact type.
    if parsed.schema_version != APPROVAL_ARTIFACT_SCHEMA_VERSION:
        errors.append("approval artifact schema_version is not the maintained version")
    if parsed.artifact_type != APPROVAL_ARTIFACT_TYPE:
        errors.append("approval artifact artifact_type is not the maintained artifact type")

    # 4-5. Exact source-provenance formats.
    if not _is_sha256(parsed.source_bundle_identity_sha256):
        errors.append("source_bundle_identity_sha256 must be 64 lowercase hexadecimal characters")
    if not parsed.source_bundle_id.startswith(BUNDLE_ID_PREFIX) or not _is_sha256(
        parsed.source_bundle_id[len(BUNDLE_ID_PREFIX) :]
    ):
        errors.append(
            f"source_bundle_id must be exactly {BUNDLE_ID_PREFIX!r} followed by 64 lowercase "
            "hexadecimal characters"
        )
    elif parsed.source_bundle_id != derive_bundle_id(parsed.source_bundle_identity_sha256):
        errors.append("source_bundle_id is not the prefixed source bundle identity")
    if not _is_sha256(parsed.subject_sha256):
        errors.append("subject_sha256 must be 64 lowercase hexadecimal characters")

    # 6-9. Canonical bytes, byte length, artifact identity, and artifact ID.
    try:
        content = canonical_approval_artifact_json(parsed)
    except Exception as exc:  # untrusted input must never raise publicly
        return _validation_result(
            "approval_artifact_invalid",
            [*errors, f"the approval artifact could not be canonically serialized: {exc}"],
            reason="the approval artifact could not be canonically serialized",
            source_bundle_id=parsed.source_bundle_id,
            source_bundle_identity_sha256=parsed.source_bundle_identity_sha256,
            subject_sha256=parsed.subject_sha256,
        )
    encoded = content.encode("utf-8")
    computed_identity = hashlib.sha256(encoded).hexdigest()
    computed_artifact_id = derive_approval_artifact_id(computed_identity)
    if parsed.canonical_content_utf8 != content:
        errors.append("canonical_content_utf8 is not the canonical approval-artifact JSON")
    if parsed.byte_length != len(encoded):
        errors.append("byte_length does not match the canonical UTF-8 content")
    if not hmac.compare_digest(parsed.approval_artifact_identity_sha256, computed_identity):
        errors.append(
            "approval_artifact_identity_sha256 does not match the recomputed artifact identity"
        )
    if parsed.approval_artifact_id != computed_artifact_id:
        errors.append("approval_artifact_id does not match the recomputed artifact identity")

    # 10-12. PR309 subject identity and exact agreement across all three records.
    computed_subject_sha256 = compute_subject_sha256(parsed.contract.subject)
    if not hmac.compare_digest(computed_subject_sha256, parsed.subject_sha256):
        errors.append("subject_sha256 does not match the recomputed PR309 subject identity")
    if not hmac.compare_digest(computed_subject_sha256, parsed.contract.approval.subject_sha256):
        errors.append(
            "the contract approval subject_sha256 does not match the recomputed subject identity"
        )

    # 13-14. Exact PR309 approval binding and exact approval scope.
    binding = verify_approval_binding(parsed.contract)
    binding_ok = (
        binding.status == "contract_valid"
        and binding.approval_binding_valid
        and hmac.compare_digest(binding.computed_subject_sha256, computed_subject_sha256)
    )
    if not binding_ok:
        errors.append("the PR309 approval-to-subject binding is not valid")
        errors.extend(binding.errors)
    if parsed.contract.approval.scope != APPROVAL_SCOPE_EXACT_SUBJECT_ONLY:
        errors.append("the approval scope must be the maintained PR309 exact-subject scope")
    if parsed.contract.schema_version != APPROVED_CHANGE_SCHEMA_VERSION:
        errors.append("the contract schema_version is not the maintained PR309 version")

    return _validation_result(
        "approval_artifact_invalid" if errors else "approval_artifact_valid",
        errors,
        reason=(
            "the approval artifact failed maintained PR319 validation"
            if errors
            else "the approval artifact is complete, canonical, and internally consistent"
        ),
        source_bundle_id=parsed.source_bundle_id,
        source_bundle_identity_sha256=parsed.source_bundle_identity_sha256,
        subject_sha256=parsed.subject_sha256,
        computed_subject_sha256=computed_subject_sha256,
        computed_byte_length=len(encoded),
        computed_identity=computed_identity,
        computed_artifact_id=computed_artifact_id,
        approval_binding_valid=binding_ok,
        approval_scope=parsed.contract.approval.scope,
        binding_validation=binding,
    )


# ---------------------------------------------------------------------------
# Fail-closed build results
# ---------------------------------------------------------------------------


def _echo(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _build_blocked(
    status: BuildStatus,
    reason: str,
    errors: list[str],
    *,
    source_bundle_id: str = "",
    source_bundle_identity_sha256: str = "",
    subject_sha256: str = "",
) -> ApprovedChangeApprovalArtifactBuildResult:
    """Return a fail-closed build result carrying no artifact at all."""
    return ApprovedChangeApprovalArtifactBuildResult(
        status=status,
        reason=reason,
        build_succeeded=False,
        source_bundle_id=source_bundle_id,
        source_bundle_identity_sha256=source_bundle_identity_sha256,
        subject_sha256=subject_sha256,
        approval_artifact_identity_sha256="",
        approval_artifact_id="",
        byte_length=0,
        artifact=None,
        artifact_validation=None,
        errors=tuple(sorted(set(errors))),
    )


def _workflow_result_gate_errors(result: ApprovedChangeApprovalWorkflowResult) -> list[str]:
    """Require one fully successful, internally consistent PR318 result."""
    errors: list[str] = []
    if result.status != REQUIRED_APPROVAL_WORKFLOW_STATUS:
        errors.append(
            f"the approval workflow result status must be {REQUIRED_APPROVAL_WORKFLOW_STATUS!r}"
        )
    if not result.approval_succeeded:
        errors.append("the approval workflow result does not report a successful approval")
    if not result.source_bundle_loaded or not result.source_bundle_valid:
        errors.append("the approval workflow result does not report a valid loaded source bundle")
    if result.approval is None:
        errors.append("the approval workflow result carries no ApprovalAttestation")
    if result.contract is None:
        errors.append("the approval workflow result carries no ApprovedChangeContract")
    binding = result.binding_validation
    if binding is None:
        errors.append("the approval workflow result carries no PR309 binding validation")
    elif (
        binding.status != "contract_valid"
        or not binding.contract_valid
        or not binding.approval_binding_valid
    ):
        errors.append("the approval workflow result does not carry a successful PR309 binding")
    if not result.approval_binding_valid:
        errors.append("the approval workflow result does not report a valid approval binding")
    if result.approval_scope != APPROVAL_SCOPE_EXACT_SUBJECT_ONLY:
        errors.append(
            "the approval workflow result scope is not the maintained exact-subject scope"
        )

    # Every provenance axis must already agree with itself.
    for label, value in (
        ("requested_bundle_id", result.requested_bundle_id),
        ("loaded_bundle_id", result.loaded_bundle_id),
    ):
        if not value.startswith(BUNDLE_ID_PREFIX) or not _is_sha256(value[len(BUNDLE_ID_PREFIX) :]):
            errors.append(f"the approval workflow result {label} is not one exact PR316 bundle ID")
    for label, value in (
        ("confirmed_bundle_identity_sha256", result.confirmed_bundle_identity_sha256),
        ("computed_bundle_identity_sha256", result.computed_bundle_identity_sha256),
        ("confirmed_subject_sha256", result.confirmed_subject_sha256),
        ("computed_subject_sha256", result.computed_subject_sha256),
    ):
        if not _is_sha256(value):
            errors.append(
                f"the approval workflow result {label} is not 64 lowercase hexadecimal characters"
            )
    if errors:
        return errors

    if not hmac.compare_digest(result.requested_bundle_id, result.loaded_bundle_id):
        errors.append("the requested and loaded source bundle IDs do not agree")
    if not hmac.compare_digest(
        result.confirmed_bundle_identity_sha256, result.computed_bundle_identity_sha256
    ):
        errors.append("the confirmed and computed source bundle identities do not agree")
    if result.loaded_bundle_id != derive_bundle_id(result.computed_bundle_identity_sha256):
        errors.append("the loaded source bundle ID is not the prefixed loaded bundle identity")
    if not hmac.compare_digest(result.confirmed_subject_sha256, result.computed_subject_sha256):
        errors.append("the confirmed and computed subject identities do not agree")
    return errors


def _workflow_capability_gate_errors(result: ApprovedChangeApprovalWorkflowResult) -> list[str]:
    """Refuse any result that already claims capability, preflight, or execution."""
    errors: list[str] = []
    for label, value in (
        ("authorization_evaluated", result.authorization_evaluated),
        ("capability_support_evaluated", result.capability_support_evaluated),
        ("capability_supported", result.capability_supported),
        ("preflight_evaluated", result.preflight_evaluated),
        ("receipt_created", result.receipt_created),
        ("receipt_linked", result.receipt_linked),
        ("execution_allowed", result.execution_allowed),
        ("execution_available", result.execution_available),
        ("approval_persisted", result.approval_persisted),
        ("contract_persisted", result.contract_persisted),
    ):
        if value:
            errors.append(f"the approval workflow result must report {label}=false")
    if result.execution_status != EXECUTION_STATUS_NOT_EXECUTED:
        errors.append("the approval workflow result must report execution_status=not_executed")
    return errors


# ---------------------------------------------------------------------------
# Public artifact construction
# ---------------------------------------------------------------------------


def build_approved_change_approval_artifact(
    workflow_result: ApprovedChangeApprovalWorkflowResult | dict[str, Any],
) -> ApprovedChangeApprovalArtifactBuildResult:
    """Build exactly one immutable approval artifact from one PR318 result.

    The only input is one fully successful PR318 approval workflow result. No
    separately supplied approval, contract, subject, bundle ID, bundle identity,
    subject hash, approver metadata, output path, or persistence confirmation is
    accepted, and no approval is ever invented from arbitrary caller data.

    The operation is pure and fail closed. It reaches no filesystem, clock,
    environment, network, randomness, or UUID, mutates nothing, and every
    failure returns a structured result carrying no artifact at all.
    """
    # 1. Exactly the maintained PR318 result contract.
    if isinstance(workflow_result, ApprovedChangeApprovalWorkflowResult):
        parsed = workflow_result
    elif isinstance(workflow_result, dict):
        try:
            parsed = ApprovedChangeApprovalWorkflowResult.model_validate(workflow_result)
        except Exception as exc:  # pydantic exposes many structured subclasses.
            return _build_blocked(
                "invalid_approval_artifact_construction_input",
                "the approval workflow result is not the maintained PR318 result contract",
                [f"approval workflow result validation failed: {exc}"],
            )
    else:
        return _build_blocked(
            "invalid_approval_artifact_construction_input",
            "the approval workflow result must be a PR318 result or a mapping",
            ["workflow_result must be an ApprovedChangeApprovalWorkflowResult or a mapping"],
        )

    # 2-3. Every PR318 success gate, then the permanent non-expansion gate.
    gate_errors = [
        *_workflow_result_gate_errors(parsed),
        *_workflow_capability_gate_errors(parsed),
    ]
    if gate_errors:
        return _build_blocked(
            "approval_artifact_construction_blocked",
            "the approval workflow result is not one fully successful PR318 approval",
            gate_errors,
            source_bundle_id=_echo(parsed.loaded_bundle_id),
            source_bundle_identity_sha256=_echo(parsed.computed_bundle_identity_sha256),
            subject_sha256=_echo(parsed.computed_subject_sha256),
        )

    approval = parsed.approval
    contract = parsed.contract
    if approval is None or contract is None:  # pragma: no cover - already gated above
        return _build_blocked(
            "approval_artifact_construction_blocked",
            "the approval workflow result is not one fully successful PR318 approval",
            ["the approval workflow result carries no approval and contract pair"],
        )
    echo = {
        "source_bundle_id": parsed.loaded_bundle_id,
        "source_bundle_identity_sha256": parsed.computed_bundle_identity_sha256,
        "subject_sha256": parsed.computed_subject_sha256,
    }

    # 4-6. The contract must be exactly the result's own approval and subject.
    contract_errors: list[str] = []
    if contract.approval != approval:
        contract_errors.append("the contract approval is not the approval workflow's attestation")
    contract_subject_sha256 = compute_subject_sha256(contract.subject)
    if not hmac.compare_digest(contract_subject_sha256, parsed.computed_subject_sha256):
        contract_errors.append("the contract subject is not the approved subject")
    if not hmac.compare_digest(approval.subject_sha256, parsed.computed_subject_sha256):
        contract_errors.append("the approval subject_sha256 is not the computed subject identity")
    if approval.scope != APPROVAL_SCOPE_EXACT_SUBJECT_ONLY:
        contract_errors.append("the approval scope is not the maintained PR309 exact-subject scope")
    if contract_errors:
        return _build_blocked(
            "approval_artifact_construction_blocked",
            "the approval workflow contract does not match its own approved subject",
            contract_errors,
            **echo,
        )

    # 7-9. Canonical bytes, non-circular identity, and the derived artifact ID.
    try:
        payload = {
            "schema_version": APPROVAL_ARTIFACT_SCHEMA_VERSION,
            "artifact_type": APPROVAL_ARTIFACT_TYPE,
            "source_bundle_id": parsed.loaded_bundle_id,
            "source_bundle_identity_sha256": parsed.computed_bundle_identity_sha256,
            "subject_sha256": parsed.computed_subject_sha256,
            "contract": contract,
        }
        content = canonical_approval_artifact_json(payload)
        encoded = content.encode("utf-8")
        identity = hashlib.sha256(encoded).hexdigest()
        artifact = ApprovedChangeApprovalArtifact(
            **payload,
            canonical_content_utf8=content,
            byte_length=len(encoded),
            approval_artifact_identity_sha256=identity,
            approval_artifact_id=derive_approval_artifact_id(identity),
        )
    except Exception as exc:  # assembly stays fail closed on schema drift
        return _build_blocked(
            "approval_artifact_construction_blocked",
            "the approval artifact could not be assembled",
            [f"approval artifact assembly failed: {exc}"],
            **echo,
        )

    # 10. Verify every artifact invariant before returning success.
    validation = validate_approved_change_approval_artifact(artifact)
    if validation.status != "approval_artifact_valid" or not validation.artifact_valid:
        return _build_blocked(
            "approval_artifact_construction_blocked",
            "the constructed approval artifact failed final verification",
            ["the constructed approval artifact failed final verification", *validation.errors],
            **echo,
        )

    return ApprovedChangeApprovalArtifactBuildResult(
        status="approval_artifact_constructed",
        reason="one canonical approval artifact was constructed from one successful PR318 approval",
        build_succeeded=True,
        source_bundle_id=artifact.source_bundle_id,
        source_bundle_identity_sha256=artifact.source_bundle_identity_sha256,
        subject_sha256=artifact.subject_sha256,
        approval_artifact_identity_sha256=artifact.approval_artifact_identity_sha256,
        approval_artifact_id=artifact.approval_artifact_id,
        byte_length=artifact.byte_length,
        artifact=artifact,
        artifact_validation=validation,
        errors=(),
    )
