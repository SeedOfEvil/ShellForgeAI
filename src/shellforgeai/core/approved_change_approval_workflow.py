"""Explicit approval binding for persisted reviewed-change bundles (PR318).

This module adds exactly one read-only operation. It receives one exact
persisted PR317 bundle ID, an explicit confirmation of that exact bundle
identity, an explicit confirmation of the exact PR309 subject SHA-256, and an
explicit approval decision plus explicit approval metadata. It loads the
persisted bundle through the maintained PR317 exact-ID loader, requires the
full PR316 identity chain to remain valid, reconstructs the exact stored PR309
subject, creates exactly one ``ApprovalAttestation`` and exactly one
``ApprovedChangeContract`` in memory, verifies the exact approval-to-subject
binding through PR309, and returns one immutable structured result.

Everything it produces is in memory. It writes no file or directory, persists
no approval, contract, or result, republishes nothing, and changes no persisted
byte. It evaluates no capability support, consults no capability registry, runs
no current-state preflight, creates or links no receipt, and grants no
execution eligibility.

Private helpers are imported from the maintained upstream modules on purpose:
approval metadata must obey exactly the same PR309 text and timestamp rules as
the maintained ``ApprovalAttestation``, and the bundle-identity format must obey
exactly the PR316 rule. Nothing is redefined or duplicated here.

Neither ``datetime`` nor ``pathlib`` is imported at runtime: both appear only in
type annotations, so this module cannot reach a clock or a path constructor at
all. Every value it uses is an explicit caller input or a maintained upstream
result.
"""

from __future__ import annotations

import hmac
import json
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict

from shellforgeai.core.approved_change_artifact_bundle import (
    APPROVED_CHANGE_SUBJECT_FILENAME,
    APPROVED_CHANGE_SUBJECT_ROLE,
    BUNDLE_ID_PREFIX,
    MANIFEST_FILENAME,
    MANIFEST_ROLE,
    ApprovedChangeArtifactBundleManifest,
    _is_sha256,
    derive_bundle_id,
)
from shellforgeai.core.approved_change_artifact_persistence import (
    load_persisted_approved_change_artifact_bundle,
)
from shellforgeai.core.approved_change_contract import (
    APPROVAL_SCOPE_EXACT_SUBJECT_ONLY,
    EXECUTION_STATUS_NOT_EXECUTED,
    ApprovalAttestation,
    ApprovedChangeContract,
    ApprovedChangeSubject,
    ContractValidationResult,
    _require_aware,
    _require_text,
    compute_subject_sha256,
    verify_approval_binding,
)

if TYPE_CHECKING:  # pragma: no cover - annotations only; never imported at runtime
    from datetime import datetime
    from pathlib import Path

APPROVAL_WORKFLOW_SCHEMA_VERSION = "1"

#: The one accepted approval decision literal. There is no alias, truthy value,
#: case variant, whitespace variant, default, or inferred decision.
APPROVAL_DECISION_APPROVE = "approve"

#: Exactly what an explicit bundle-identity confirmation authorizes here.
BUNDLE_CONFIRMATION_SCOPE = "select_this_exact_persisted_reviewed_source_bundle_identity"

#: Exactly what the resulting attestation is scoped to. It is PR309's scope and
#: is never widened by the bundle confirmation.
APPROVAL_CONFIRMATION_SCOPE = "approve_this_exact_pr309_subject_sha256_only"

APPROVAL_WORKFLOW_STATUSES = (
    "approval_contract_constructed",
    "approval_blocked",
    "invalid_approval_input",
    "persisted_bundle_not_available",
    "persisted_bundle_invalid",
    "approval_binding_failed",
)

ApprovalWorkflowStatus = Literal[
    "approval_contract_constructed",
    "approval_blocked",
    "invalid_approval_input",
    "persisted_bundle_not_available",
    "persisted_bundle_invalid",
    "approval_binding_failed",
]

PERMANENT_APPROVAL_WORKFLOW_WARNINGS: tuple[str, ...] = (
    "approved_by is self-asserted metadata, not authenticated identity",
    "reviewer provenance is not approval",
    "approval applies only to the exact confirmed PR309 subject SHA-256",
    "bundle-identity confirmation selects the source bundle but does not expand attestation scope",
    "an in-memory approval is not persisted approval",
    "an ApprovedChangeContract is not authorization",
    "exact approval binding is not capability support",
    "no capability registry has been consulted",
    "no current-state preflight has run",
    "no receipt has been created or linked",
    "no execution eligibility is granted",
    "reviewed artifacts may contain operational context and must be reviewed before sharing",
    "no redaction is performed because redaction would change reviewed identity",
)

#: Loader statuses that mean the persisted source could not be reached at all,
#: as opposed to being reached and failing maintained validation.
_UNAVAILABLE_LOAD_STATUSES = frozenset(
    {
        "persisted_bundle_not_found",
        "unsafe_persistence_root",
        "invalid_persisted_bundle_reference",
    }
)


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Structured result
# ---------------------------------------------------------------------------


class ApprovedChangeApprovalWorkflowResult(_FrozenModel):
    """Structured, non-throwing approval-binding result.

    A successful result means only that one immutable in-memory
    ``ApprovalAttestation`` and one immutable in-memory
    ``ApprovedChangeContract`` exist, and that PR309 verified the exact
    approval-to-subject binding. Nothing was written, persisted, published,
    authorized, capability-checked, preflighted, receipted, or executed.
    """

    schema_version: Literal["1"] = APPROVAL_WORKFLOW_SCHEMA_VERSION
    status: ApprovalWorkflowStatus
    reason: str = ""
    approval_succeeded: bool = False
    approval_decision: str = ""
    requested_bundle_id: str = ""
    loaded_bundle_id: str = ""
    confirmed_bundle_identity_sha256: str = ""
    computed_bundle_identity_sha256: str = ""
    confirmed_subject_sha256: str = ""
    computed_subject_sha256: str = ""
    source_bundle_loaded: bool = False
    source_bundle_valid: bool = False
    approval_binding_valid: bool = False
    approval_scope: str = ""
    bundle_confirmation_scope: str = BUNDLE_CONFIRMATION_SCOPE
    approval_confirmation_scope: str = APPROVAL_CONFIRMATION_SCOPE
    approval: ApprovalAttestation | None = None
    contract: ApprovedChangeContract | None = None
    binding_validation: ContractValidationResult | None = None
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_APPROVAL_WORKFLOW_WARNINGS

    # Accurate safety ledger. Creating immutable in-memory approval metadata is
    # not a host or filesystem mutation.
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    filesystem_accessed: bool = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    approval_input_evaluated: bool = True
    approval_created: bool = False
    approval_persisted: Literal[False] = False
    contract_created: bool = False
    contract_persisted: Literal[False] = False
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
# Deterministic explicit-input validation
# ---------------------------------------------------------------------------


def _bundle_id_format_errors(bundle_id: Any) -> list[str]:
    """Reject anything that is not exactly the full PR316 bundle ID."""
    if not isinstance(bundle_id, str) or not bundle_id:
        return ["bundle_id must be a non-empty string"]
    errors: list[str] = []
    if bundle_id != bundle_id.strip():
        errors.append("bundle_id must not carry leading or trailing whitespace")
    if not bundle_id.startswith(BUNDLE_ID_PREFIX) or not _is_sha256(
        bundle_id[len(BUNDLE_ID_PREFIX) :]
    ):
        errors.append(
            f"bundle_id must be exactly {BUNDLE_ID_PREFIX!r} followed by 64 lowercase "
            "hexadecimal characters"
        )
    return errors


def _decision_errors(approval_decision: Any) -> list[str]:
    """Require exactly the one approval decision literal."""
    if not isinstance(approval_decision, str) or approval_decision != APPROVAL_DECISION_APPROVE:
        return [
            f"approval_decision must be exactly {APPROVAL_DECISION_APPROVE!r}; no alias, "
            "case variant, whitespace variant, truthy value, or default is accepted"
        ]
    return []


def _confirmation_errors(value: Any, label: str) -> list[str]:
    if not _is_sha256(value):
        return [f"{label} must be 64 lowercase hexadecimal characters"]
    return []


def _text_errors(value: Any, label: str) -> list[str]:
    """Require the maintained PR309 ``ApprovalAttestation`` text rules."""
    if not isinstance(value, str):
        return [f"{label} must be a string"]
    try:
        _require_text(value)
    except Exception as exc:  # the maintained validator owns the exact rule
        return [f"{label} is not acceptable approval metadata: {exc}"]
    return []


def _timestamp_errors(value: Any) -> list[str]:
    """Require an explicit timezone-aware ``approved_at``. No clock is read."""
    try:
        _require_aware(value)
    except Exception:
        return ["approved_at must be an explicit timezone-aware datetime"]
    return []


def _explicit_input_errors(
    bundle_id: Any,
    approval_decision: Any,
    confirm_bundle_identity_sha256: Any,
    confirm_subject_sha256: Any,
    approved_by: Any,
    approved_at: Any,
    reason: Any,
) -> list[str]:
    """Validate every explicit input before any filesystem access."""
    return [
        *_decision_errors(approval_decision),
        *_bundle_id_format_errors(bundle_id),
        *_confirmation_errors(confirm_bundle_identity_sha256, "confirm_bundle_identity_sha256"),
        *_confirmation_errors(confirm_subject_sha256, "confirm_subject_sha256"),
        *_text_errors(approved_by, "approved_by"),
        *_text_errors(reason, "reason"),
        *_timestamp_errors(approved_at),
    ]


def _echo_sha256(value: Any) -> str:
    """Echo a confirmation only when it is already a well-formed identity."""
    return value if _is_sha256(value) else ""


def _echo_bundle_id(value: Any) -> str:
    """Echo a requested bundle ID only when it is already well formed."""
    return value if not _bundle_id_format_errors(value) else ""


# ---------------------------------------------------------------------------
# Fail-closed results
# ---------------------------------------------------------------------------


def _blocked(
    status: ApprovalWorkflowStatus,
    *,
    reason: str,
    errors: list[str],
    approval_decision: str = "",
    requested_bundle_id: str = "",
    loaded_bundle_id: str = "",
    confirmed_bundle_identity_sha256: str = "",
    computed_bundle_identity_sha256: str = "",
    confirmed_subject_sha256: str = "",
    computed_subject_sha256: str = "",
    source_bundle_loaded: bool = False,
    source_bundle_valid: bool = False,
    binding_validation: ContractValidationResult | None = None,
    filesystem_accessed: bool = False,
) -> ApprovedChangeApprovalWorkflowResult:
    """Return a fail-closed result carrying no approval and no contract."""
    return ApprovedChangeApprovalWorkflowResult(
        status=status,
        reason=reason,
        approval_succeeded=False,
        approval_decision=approval_decision,
        requested_bundle_id=requested_bundle_id,
        loaded_bundle_id=loaded_bundle_id,
        confirmed_bundle_identity_sha256=confirmed_bundle_identity_sha256,
        computed_bundle_identity_sha256=computed_bundle_identity_sha256,
        confirmed_subject_sha256=confirmed_subject_sha256,
        computed_subject_sha256=computed_subject_sha256,
        source_bundle_loaded=source_bundle_loaded,
        source_bundle_valid=source_bundle_valid,
        approval_binding_valid=False,
        approval_scope="",
        approval=None,
        contract=None,
        binding_validation=binding_validation,
        errors=tuple(sorted(set(errors))),
        filesystem_accessed=filesystem_accessed,
        approval_created=False,
        contract_created=False,
    )


# ---------------------------------------------------------------------------
# Exact subject sourcing from the persisted bundle
# ---------------------------------------------------------------------------


def _stored_file(bundle: Any, filename: str, role: str) -> Any:
    """Return one logical file through the fixed PR316 filename/role contract."""
    return next(
        (item for item in bundle.files if item.role == role and item.relative_path == filename),
        None,
    )


def _parse_stored_json_object(content_utf8: str, label: str, errors: list[str]) -> Any:
    try:
        parsed = json.loads(content_utf8)
    except Exception as exc:  # stored bytes are untrusted and never raise publicly
        errors.append(f"{label} is not parseable JSON: {exc}")
        return None
    if not isinstance(parsed, dict):
        errors.append(f"{label} must contain a JSON object")
        return None
    return parsed


# ---------------------------------------------------------------------------
# Public approval-binding operation
# ---------------------------------------------------------------------------


def construct_approved_change_contract_from_persisted_bundle(
    bundle_id: str,
    *,
    data_dir: Path | str,
    approval_decision: Literal["approve"],
    confirm_bundle_identity_sha256: str,
    confirm_subject_sha256: str,
    approved_by: str,
    approved_at: datetime,
    reason: str,
) -> ApprovedChangeApprovalWorkflowResult:
    """Bind one explicit approval to one exact persisted reviewed-change bundle.

    Every input is explicit. No caller-supplied bundle, subject, attestation, or
    contract is accepted; no arbitrary persisted path, ``latest``/``current``
    reference, legacy ``Proposal``, supported-capability set, capability-registry
    data, authorization token, output path, execution confirmation, receipt, or
    model-generated approval is accepted; and the decision, actor, timestamp,
    reason, and both confirmation hashes are never defaulted or inferred.

    The operation is read-only and fail closed. It loads through the maintained
    PR317 exact-ID loader only, never rewrites, repairs, or republishes persisted
    bytes, and returns a structured result carrying no approval and no contract
    on every failure.
    """
    # 1-4. Every explicit input is validated before any filesystem access.
    input_errors = _explicit_input_errors(
        bundle_id,
        approval_decision,
        confirm_bundle_identity_sha256,
        confirm_subject_sha256,
        approved_by,
        approved_at,
        reason,
    )
    decision = APPROVAL_DECISION_APPROVE if not _decision_errors(approval_decision) else ""
    echoed_bundle_id = _echo_bundle_id(bundle_id)
    echoed_bundle_confirmation = _echo_sha256(confirm_bundle_identity_sha256)
    echoed_subject_confirmation = _echo_sha256(confirm_subject_sha256)
    if input_errors:
        return _blocked(
            "invalid_approval_input",
            reason="the explicit approval input is not acceptable",
            errors=input_errors,
            approval_decision=decision,
            requested_bundle_id=echoed_bundle_id,
            confirmed_bundle_identity_sha256=echoed_bundle_confirmation,
            confirmed_subject_sha256=echoed_subject_confirmation,
        )

    echo = {
        "approval_decision": decision,
        "requested_bundle_id": echoed_bundle_id,
        "confirmed_bundle_identity_sha256": echoed_bundle_confirmation,
        "confirmed_subject_sha256": echoed_subject_confirmation,
    }

    # 5. The maintained PR317 exact-ID loader is the only persisted-source path.
    load = load_persisted_approved_change_artifact_bundle(bundle_id, data_dir=data_dir)

    # 6. The persisted source must have loaded and revalidated completely.
    if load.status != "persisted_bundle_loaded" or load.bundle is None:
        status: ApprovalWorkflowStatus = (
            "persisted_bundle_not_available"
            if load.status in _UNAVAILABLE_LOAD_STATUSES
            else "persisted_bundle_invalid"
        )
        return _blocked(
            status,
            reason="the persisted reviewed-change bundle could not be loaded and revalidated",
            errors=[
                f"persisted bundle load status: {load.status}",
                *load.errors,
            ],
            **echo,
            filesystem_accessed=load.filesystem_accessed,
        )

    bundle = load.bundle
    validation = load.bundle_validation
    if validation is None or validation.status != "bundle_valid" or not validation.bundle_valid:
        return _blocked(
            "persisted_bundle_invalid",
            reason="the persisted bundle did not pass maintained PR316 validation",
            errors=["persisted bundle failed maintained PR316 validation"],
            **echo,
            source_bundle_loaded=True,
            filesystem_accessed=load.filesystem_accessed,
        )

    chain_errors: list[str] = []
    if not hmac.compare_digest(load.bundle_id, bundle_id):
        chain_errors.append("the loaded bundle ID is not the exact requested bundle ID")
    if not hmac.compare_digest(bundle.bundle_id, bundle_id):
        chain_errors.append("the persisted bundle records another bundle ID")
    if not hmac.compare_digest(bundle.bundle_id, derive_bundle_id(bundle.bundle_identity_sha256)):
        chain_errors.append("the loaded bundle ID is not the prefixed loaded bundle identity")
    if not hmac.compare_digest(
        validation.computed_bundle_identity_sha256, bundle.bundle_identity_sha256
    ):
        chain_errors.append("the recomputed bundle identity does not match the loaded bundle")
    if chain_errors:
        return _blocked(
            "persisted_bundle_invalid",
            reason="the persisted bundle identity chain is inconsistent",
            errors=chain_errors,
            **echo,
            loaded_bundle_id=load.bundle_id,
            computed_bundle_identity_sha256=validation.computed_bundle_identity_sha256,
            source_bundle_loaded=True,
            filesystem_accessed=load.filesystem_accessed,
        )

    loaded_echo = {
        **echo,
        "loaded_bundle_id": bundle.bundle_id,
        "computed_bundle_identity_sha256": bundle.bundle_identity_sha256,
        "source_bundle_loaded": True,
        "source_bundle_valid": True,
        "filesystem_accessed": load.filesystem_accessed,
    }

    # 7. The explicit bundle-identity confirmation selects this exact source.
    if not hmac.compare_digest(confirm_bundle_identity_sha256, bundle.bundle_identity_sha256):
        return _blocked(
            "approval_blocked",
            reason="confirm_bundle_identity_sha256 does not match the loaded bundle identity",
            errors=["confirm_bundle_identity_sha256 does not match the loaded bundle identity"],
            **loaded_echo,
        )

    # 8. The subject comes only from the fixed PR316 subject logical file.
    subject_file = _stored_file(
        bundle, APPROVED_CHANGE_SUBJECT_FILENAME, APPROVED_CHANGE_SUBJECT_ROLE
    )
    manifest_file = _stored_file(bundle, MANIFEST_FILENAME, MANIFEST_ROLE)
    source_errors: list[str] = []
    if subject_file is None:
        source_errors.append(
            f"the persisted bundle has no {APPROVED_CHANGE_SUBJECT_FILENAME} logical file"
        )
    if manifest_file is None:
        source_errors.append(f"the persisted bundle has no {MANIFEST_FILENAME} logical file")
    if source_errors:
        return _blocked(
            "persisted_bundle_invalid",
            reason="the persisted bundle does not expose its fixed subject and manifest files",
            errors=source_errors,
            **loaded_echo,
        )

    # 9. Parse the stored bytes into the maintained models. Nothing is rewritten.
    parse_errors: list[str] = []
    subject_payload = _parse_stored_json_object(
        subject_file.content_utf8, APPROVED_CHANGE_SUBJECT_FILENAME, parse_errors
    )
    manifest_payload = _parse_stored_json_object(
        manifest_file.content_utf8, MANIFEST_FILENAME, parse_errors
    )
    subject: ApprovedChangeSubject | None = None
    manifest: ApprovedChangeArtifactBundleManifest | None = None
    if subject_payload is not None:
        try:
            subject = ApprovedChangeSubject.model_validate(subject_payload)
        except Exception as exc:  # stored bytes are untrusted
            parse_errors.append(
                f"{APPROVED_CHANGE_SUBJECT_FILENAME} does not parse into the maintained "
                f"PR309 subject: {exc}"
            )
    if manifest_payload is not None:
        try:
            manifest = ApprovedChangeArtifactBundleManifest.model_validate(manifest_payload)
        except Exception as exc:  # stored bytes are untrusted
            parse_errors.append(
                f"{MANIFEST_FILENAME} does not parse into the maintained PR316 manifest: {exc}"
            )
    if parse_errors or subject is None or manifest is None:
        return _blocked(
            "persisted_bundle_invalid",
            reason="the persisted reviewed-change subject could not be reconstructed",
            errors=parse_errors,
            **loaded_echo,
        )

    # 10. Subject identity is recomputed only through PR309.
    computed_subject_sha256 = compute_subject_sha256(subject)
    subject_echo = {**loaded_echo, "computed_subject_sha256": computed_subject_sha256}

    # 11. The whole stored subject identity chain must agree exactly.
    identity_errors: list[str] = []
    if not hmac.compare_digest(computed_subject_sha256, subject_file.sha256):
        identity_errors.append(
            "the recomputed subject identity does not match the stored subject file checksum"
        )
    if not hmac.compare_digest(computed_subject_sha256, manifest.subject_sha256):
        identity_errors.append(
            "the recomputed subject identity does not match the manifest subject identity"
        )
    if not hmac.compare_digest(computed_subject_sha256, validation.computed_subject_sha256):
        identity_errors.append(
            "the recomputed subject identity does not match the PR316-validated identity chain"
        )
    if identity_errors:
        return _blocked(
            "persisted_bundle_invalid",
            reason="the persisted subject identity chain is inconsistent",
            errors=identity_errors,
            **subject_echo,
        )
    if not hmac.compare_digest(confirm_subject_sha256, computed_subject_sha256):
        return _blocked(
            "approval_blocked",
            reason="confirm_subject_sha256 does not match the recomputed subject identity",
            errors=["confirm_subject_sha256 does not match the recomputed subject identity"],
            **subject_echo,
        )

    # 12-13. Exactly one attestation and exactly one contract, both in memory.
    try:
        approval = ApprovalAttestation(
            approved_by=approved_by,
            approved_at=approved_at,
            reason=reason,
            subject_sha256=computed_subject_sha256,
            scope=APPROVAL_SCOPE_EXACT_SUBJECT_ONLY,
        )
        contract = ApprovedChangeContract(subject=subject, approval=approval)
    except Exception as exc:  # the maintained models own the exact rules
        return _blocked(
            "approval_blocked",
            reason="the maintained PR309 approval or contract model rejected the input",
            errors=[f"approval construction failed: {exc}"],
            **subject_echo,
        )

    # 14-15. PR309 owns approval-binding verification.
    binding = verify_approval_binding(contract)
    if (
        binding.status != "contract_valid"
        or not binding.approval_binding_valid
        or not hmac.compare_digest(binding.computed_subject_sha256, computed_subject_sha256)
        or not hmac.compare_digest(approval.subject_sha256, computed_subject_sha256)
        or approval.scope != APPROVAL_SCOPE_EXACT_SUBJECT_ONLY
    ):
        return _blocked(
            "approval_binding_failed",
            reason="PR309 did not verify the exact approval-to-subject binding",
            errors=["approval binding verification did not succeed", *binding.errors],
            **subject_echo,
            binding_validation=binding,
        )

    # 16. One structured success result.
    return ApprovedChangeApprovalWorkflowResult(
        status="approval_contract_constructed",
        reason="one in-memory approval and contract were bound to the exact persisted subject",
        approval_succeeded=True,
        approval_decision=APPROVAL_DECISION_APPROVE,
        requested_bundle_id=bundle_id,
        loaded_bundle_id=bundle.bundle_id,
        confirmed_bundle_identity_sha256=confirm_bundle_identity_sha256,
        computed_bundle_identity_sha256=bundle.bundle_identity_sha256,
        confirmed_subject_sha256=confirm_subject_sha256,
        computed_subject_sha256=computed_subject_sha256,
        source_bundle_loaded=True,
        source_bundle_valid=True,
        approval_binding_valid=True,
        approval_scope=APPROVAL_SCOPE_EXACT_SUBJECT_ONLY,
        approval=approval,
        contract=contract,
        binding_validation=binding,
        errors=(),
        filesystem_accessed=True,
        approval_created=True,
        contract_created=True,
    )
