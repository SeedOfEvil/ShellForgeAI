"""Typed read-only approved-change capability binding (PR322).

PR321 answers exactly one question: *is this exact approved contract's exact
capability ID declared supported?* That answer is deliberately capability-ID
membership only, so it says nothing about which governed implementation lane an
approved subject would ever belong to. This module closes exactly that gap and
nothing else.

It adds exactly three things:

* one immutable, source-maintained **lane declaration** for the exact named
  PR313 governed Windows two-file runtime-reconciliation lane, with a
  deterministic SHA-256 identity computed only from its own canonical bytes;
* one immutable **capability binding** model whose deterministic identity is the
  SHA-256 of one canonical payload naming the exact approved subject, the exact
  persisted PR319 approval artifact, the exact confirmed PR321 support catalog,
  and the exact confirmed lane declaration;
* one read-only operation that, given one exact ``aca_`` artifact ID, one
  explicit data root, and both exact identity confirmations, confirms support
  through the maintained PR321 evaluator and constructs exactly one in-memory
  binding.

**A capability binding means only** that one exact approved subject identity has
been deterministically associated with one exact immutable named-lane
declaration, in memory.

It does **not** mean the lane can run. It is not authorization, target
compatibility, procedure compatibility, PR304/PR305 evidence compatibility,
subject-to-PR313-plan agreement, current-state readiness, preflight success,
receipt availability, execution eligibility, or execution availability.

The lane declaration is source-maintained and stays in memory: it is never
persisted, published, inventoried, loaded from disk, discovered from plugins,
derived from ``recipe_registry``, derived from script or filesystem contents,
read from the environment, or supplied by a caller. The binding is in-memory
only too: PR322 introduces no persisted binding artifact, no binding ID prefix,
no binding publisher, and no binding loader.

This module reaches the filesystem only indirectly, through the maintained PR321
evaluator and the maintained PR319 exact-ID loader. It never parses persisted
approval JSON, never recomputes an artifact identity rule of its own, never
loads a PR317 source bundle directly, never calls a publisher, and never accepts
an arbitrary artifact path. It performs no approval selection: there is no
inventory call, and no ``latest``, ``current``, or "most recent" resolution.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

from shellforgeai.core.approved_change_approval_artifact import (
    APPROVAL_ARTIFACT_ID_PREFIX,
    ApprovedChangeApprovalArtifact,
    derive_approval_artifact_id,
)
from shellforgeai.core.approved_change_approval_persistence import (
    load_persisted_approved_change_approval_artifact,
)
from shellforgeai.core.approved_change_capability_support import (
    MATCH_RULE_EXACT_CAPABILITY_ID_ONLY,
    WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
    ApprovedChangeCapabilitySupportCatalog,
    ApprovedChangeCapabilitySupportEvaluationResult,
    compute_approved_change_capability_support_catalog_sha256,
    evaluate_persisted_approved_change_capability_support,
    maintained_approved_change_capability_support_catalog,
    validate_approved_change_capability_support_catalog,
)
from shellforgeai.core.approved_change_contract import (
    _CAPABILITY_RE,
    EXECUTION_STATUS_NOT_EXECUTED,
    _is_wildcard,
)

CAPABILITY_BINDING_SCHEMA_VERSION = "1"

#: The one fixed binding type literal. There is no alias, no alternate
#: spelling, no caller-defined kind, and no second binding type.
CAPABILITY_BINDING_TYPE = "approved_change_capability_binding"

#: The one lane kind a maintained declaration may carry today.
LANE_KIND_NAMED_GOVERNED_IMPLEMENTATION_LANE = "named_governed_implementation_lane"

#: The one binding status a maintained lane declaration may carry today.
#: ``declared_bindable`` means the lane declaration exists and may be named by a
#: binding. It is not "runnable", "ready", "eligible", or "authorized".
BINDING_STATUS_DECLARED_BINDABLE = "declared_bindable"

#: The one binding scope. A binding associates exactly one approved subject
#: identity with exactly one named lane declaration, and widens nothing.
BINDING_SCOPE_EXACT_SUBJECT_TO_EXACT_LANE_ONLY = (
    "exact_approved_subject_to_exact_named_lane_declaration_only"
)

#: The one implementation scope the named PR313 lane declares. It restates the
#: maintained PR313 boundary as static declaration text; it is never derived
#: from, and never grants access to, the PR313 runtime.
IMPLEMENTATION_SCOPE_WINDOWS_TWO_FILE_ONLY = "windows_exact_two_file_runtime_reconciliation_only"

#: The exact — and today only — declared governed implementation lane ID. It is
#: a product-maintained source constant, never discovered, never registered at
#: runtime, and never derived from the recipe registry, a PR313 module, a script
#: name, the filesystem, the environment, or an installed plugin.
WINDOWS_RUNTIME_RECONCILE_LANE_ID = "pr313.windows_runtime_reconcile"

#: The exact PR321 evaluation status that alone permits a binding.
REQUIRED_CAPABILITY_SUPPORT_STATUS = "capability_support_confirmed"

#: The exact PR321 evaluation status that means a completed, fail-closed
#: "this exact capability is not declared" answer.
CAPABILITY_NOT_DECLARED_SUPPORT_STATUS = "capability_not_declared"

#: The exact PR319 loader status that alone permits a binding.
REQUIRED_APPROVAL_ARTIFACT_LOAD_STATUS = "persisted_approval_artifact_loaded"

#: The exact PR309 validation status the PR321 result must carry.
PR309_CONTRACT_VALID_STATUS = "contract_valid"

#: The exact scope the explicit lane-declaration confirmation authorizes, and
#: nothing more. It is never approval confirmation, authorization, preflight
#: confirmation, receipt confirmation, or execution confirmation.
LANE_DECLARATION_CONFIRMATION_SCOPE = (
    "bind_this_exact_approved_subject_against_this_exact_maintained_lane_declaration"
)

LANE_DECLARATION_VALIDATION_STATUSES = (
    "capability_lane_declaration_valid",
    "capability_lane_declaration_invalid",
    "invalid_capability_lane_declaration_input",
)
LaneDeclarationValidationStatus = Literal[
    "capability_lane_declaration_valid",
    "capability_lane_declaration_invalid",
    "invalid_capability_lane_declaration_input",
]

BINDING_VALIDATION_STATUSES = (
    "capability_binding_valid",
    "capability_binding_invalid",
    "invalid_capability_binding_validation_input",
)
BindingValidationStatus = Literal[
    "capability_binding_valid",
    "capability_binding_invalid",
    "invalid_capability_binding_validation_input",
]

BINDING_STATUSES = (
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
)
BindingStatus = Literal[
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
]

#: Warnings every PR322 result carries, whatever its status. They state exactly
#: what a binding does and does not mean, so no automated consumer can read an
#: in-memory identity association as compatibility, readiness, authorization, or
#: execution.
PERMANENT_CAPABILITY_BINDING_WARNINGS: tuple[str, ...] = (
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
)

_SHA256_LENGTH = 64
_LOWERCASE_HEX = frozenset("0123456789abcdef")

#: The maintained PR321 evaluation statuses this module classifies explicitly.
#: Any other status is unexpected and blocks rather than being interpreted.
_SUPPORT_INVALID_INPUT_STATUS = "invalid_capability_support_input"
_SUPPORT_CATALOG_MISMATCH_STATUS = "capability_catalog_confirmation_mismatch"
_SUPPORT_ARTIFACT_NOT_AVAILABLE_STATUS = "approval_artifact_not_available"
_SUPPORT_ARTIFACT_INVALID_STATUS = "approval_artifact_invalid"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# The typed lane declaration and the one maintained declaration
# ---------------------------------------------------------------------------


class ApprovedChangeCapabilityLaneDeclaration(_FrozenModel):
    """One immutable statement that one exact capability names one exact lane.

    The declaration carries exactly the static identity and scope required to
    bind, and nothing further. The five availability fields exist so a
    declaration can never be silently read as more than it is; the maintained
    validator requires every one of them to be ``false``, so no declaration in
    this repository can assert binding persistence, authorization, preflight,
    receipt linkage, or execution availability today.
    """

    schema_version: Literal["1"] = CAPABILITY_BINDING_SCHEMA_VERSION
    capability_id: str
    lane_id: str
    lane_kind: Literal["named_governed_implementation_lane"] = (
        LANE_KIND_NAMED_GOVERNED_IMPLEMENTATION_LANE
    )
    binding_status: Literal["declared_bindable"] = BINDING_STATUS_DECLARED_BINDABLE
    match_rule: Literal["exact_capability_id_only"] = MATCH_RULE_EXACT_CAPABILITY_ID_ONLY
    binding_scope: Literal["exact_approved_subject_to_exact_named_lane_declaration_only"] = (
        BINDING_SCOPE_EXACT_SUBJECT_TO_EXACT_LANE_ONLY
    )
    implementation_scope: Literal["windows_exact_two_file_runtime_reconciliation_only"] = (
        IMPLEMENTATION_SCOPE_WINDOWS_TWO_FILE_ONLY
    )
    binding_persistence_available: bool = False
    authorization_available: bool = False
    preflight_available: bool = False
    receipt_linkage_available: bool = False
    execution_available: bool = False

    @field_validator("capability_id")
    @classmethod
    def _validate_capability_id(cls, value: str) -> str:
        """Require exactly the maintained PR309 capability-ID syntax.

        The syntax rule and the wildcard rule are PR309's. They are reused here
        rather than restated so a declared ID can never be a shape an approved
        subject could not carry.
        """
        if not isinstance(value, str) or value != value.strip() or not value:
            raise ValueError("capability_id must be a bounded exact identifier")
        if _is_wildcard(value) or not _CAPABILITY_RE.fullmatch(value):
            raise ValueError("capability_id must be a bounded exact identifier")
        return value

    @field_validator("lane_id")
    @classmethod
    def _validate_lane_id(cls, value: str) -> str:
        """Require one bounded exact lane identifier and no wildcard."""
        if not isinstance(value, str) or value != value.strip() or not value:
            raise ValueError("lane_id must be a bounded exact identifier")
        if _is_wildcard(value) or not _CAPABILITY_RE.fullmatch(value):
            raise ValueError("lane_id must be a bounded exact identifier")
        return value


#: The one maintained lane declaration. Exactly one capability, exactly one lane.
_MAINTAINED_LANE_DECLARATION = ApprovedChangeCapabilityLaneDeclaration(
    capability_id=WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
    lane_id=WINDOWS_RUNTIME_RECONCILE_LANE_ID,
)


def maintained_windows_runtime_reconcile_lane_declaration() -> (
    ApprovedChangeCapabilityLaneDeclaration
):
    """Return the exact immutable lane declaration defined in source.

    This reads no file, reads no environment variable, inspects no installed
    recipe, inspects no script, inspects no OS, host, or platform, reads no
    credential, calls no network service, loads no plugin, and discovers no
    adapter. The returned object is frozen and holds only immutable members, so
    the single maintained instance is safe to hand back to every caller.
    """
    return _MAINTAINED_LANE_DECLARATION


# ---------------------------------------------------------------------------
# Lane-declaration canonicalization and deterministic identity
# ---------------------------------------------------------------------------


def canonical_capability_lane_declaration_payload(
    declaration: ApprovedChangeCapabilityLaneDeclaration | dict[str, Any],
) -> dict[str, Any]:
    """Return the canonical lane-declaration payload.

    Mapping keys are sorted and nothing derived is ever part of the payload, so
    the lane-declaration identity can never hash itself. No timestamp,
    environment value, host value, platform value, path, or randomness enters
    the payload.
    """
    if not isinstance(declaration, ApprovedChangeCapabilityLaneDeclaration):
        declaration = ApprovedChangeCapabilityLaneDeclaration.model_validate(declaration)
    payload = declaration.model_dump(mode="python")
    return {key: payload[key] for key in sorted(payload)}


def canonical_capability_lane_declaration_json(
    declaration: ApprovedChangeCapabilityLaneDeclaration | dict[str, Any],
) -> str:
    """Return deterministic canonical lane-declaration JSON.

    Mapping keys are sorted, separators are compact, ``ensure_ascii`` is off so
    Unicode is preserved exactly, and there is no BOM and no trailing newline.
    """
    return json.dumps(
        canonical_capability_lane_declaration_payload(declaration),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_capability_lane_declaration_sha256(
    declaration: ApprovedChangeCapabilityLaneDeclaration | dict[str, Any],
) -> str:
    """Compute the full, untruncated lane-declaration identity SHA-256.

    This identity is permanently distinct from the PR309 subject identity, the
    PR316 bundle identity, the PR319 approval-artifact identity, the PR321
    capability-support catalog identity, the PR322 binding identity, any PR313
    plan hash, and any receipt identity. It is never approval, authorization,
    preflight, or execution confirmation, and it is never persisted or prefixed
    into a durable ID.
    """
    return hashlib.sha256(
        canonical_capability_lane_declaration_json(declaration).encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------------
# The typed capability binding and its canonicalization
# ---------------------------------------------------------------------------


class ApprovedChangeCapabilityBinding(_FrozenModel):
    """One immutable in-memory association of one subject with one lane.

    The model holds exactly the canonical payload fields and no derived value,
    so the binding identity is non-circular by construction. It has no host
    path, no persisted ID, no prefix, and no timestamp.
    """

    schema_version: Literal["1"] = CAPABILITY_BINDING_SCHEMA_VERSION
    binding_type: Literal["approved_change_capability_binding"] = CAPABILITY_BINDING_TYPE
    approval_artifact_id: str
    approval_artifact_identity_sha256: str
    subject_sha256: str
    capability_catalog_identity_sha256: str
    capability_id: str
    lane_declaration_identity_sha256: str
    lane_id: str
    binding_scope: Literal["exact_approved_subject_to_exact_named_lane_declaration_only"] = (
        BINDING_SCOPE_EXACT_SUBJECT_TO_EXACT_LANE_ONLY
    )
    implementation_scope: Literal["windows_exact_two_file_runtime_reconciliation_only"] = (
        IMPLEMENTATION_SCOPE_WINDOWS_TWO_FILE_ONLY
    )


def canonical_approved_change_capability_binding_payload(
    binding: ApprovedChangeCapabilityBinding | dict[str, Any],
) -> dict[str, Any]:
    """Return the canonical binding payload with sorted mapping keys."""
    if not isinstance(binding, ApprovedChangeCapabilityBinding):
        binding = ApprovedChangeCapabilityBinding.model_validate(binding)
    payload = binding.model_dump(mode="python")
    return {key: payload[key] for key in sorted(payload)}


def canonical_approved_change_capability_binding_json(
    binding: ApprovedChangeCapabilityBinding | dict[str, Any],
) -> str:
    """Return deterministic canonical binding JSON."""
    return json.dumps(
        canonical_approved_change_capability_binding_payload(binding),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_approved_change_capability_binding_sha256(
    binding: ApprovedChangeCapabilityBinding | dict[str, Any],
) -> str:
    """Compute the full, untruncated binding identity SHA-256."""
    return hashlib.sha256(
        canonical_approved_change_capability_binding_json(binding).encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------------
# Structured results
# ---------------------------------------------------------------------------


class ApprovedChangeCapabilityLaneDeclarationValidationResult(_FrozenModel):
    """Structured, non-throwing lane-declaration validation result.

    Validation is pure and inert: it recanonicalizes the declaration,
    recomputes the declaration identity, and touches nothing at all.
    """

    schema_version: Literal["1"] = CAPABILITY_BINDING_SCHEMA_VERSION
    status: LaneDeclarationValidationStatus
    reason: str = ""
    declaration_valid: bool
    capability_id: str = ""
    lane_id: str = ""
    lane_declaration_identity_sha256: str = ""
    canonical_byte_length: int = 0
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_CAPABILITY_BINDING_WARNINGS

    # Accurate safety ledger. Declaration validation reaches nothing.
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    filesystem_accessed: Literal[False] = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    capability_support_evaluated: Literal[False] = False
    capability_supported: Literal[False] = False
    capability_binding_evaluated: Literal[False] = False
    capability_bound: Literal[False] = False
    binding_created: Literal[False] = False
    binding_persisted: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


class ApprovedChangeCapabilityBindingValidationResult(_FrozenModel):
    """Structured, non-throwing binding validation result.

    Validation is pure and inert: it recanonicalizes the binding, recomputes
    the binding identity, rechecks every exact field, and performs no I/O.
    """

    schema_version: Literal["1"] = CAPABILITY_BINDING_SCHEMA_VERSION
    status: BindingValidationStatus
    reason: str = ""
    binding_valid: bool
    binding_identity_sha256: str = ""
    canonical_byte_length: int = 0
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_CAPABILITY_BINDING_WARNINGS

    # Accurate safety ledger. Binding validation reaches nothing.
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    filesystem_accessed: Literal[False] = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    capability_support_evaluated: Literal[False] = False
    capability_supported: Literal[False] = False
    capability_binding_evaluated: Literal[False] = False
    capability_bound: Literal[False] = False
    binding_created: Literal[False] = False
    binding_persisted: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


class ApprovedChangeCapabilityBindingResult(_FrozenModel):
    """Structured, non-throwing read-only capability-binding result.

    ``binding_complete`` is the only field that states whether the exact
    binding question was actually answered. ``capability_bound=true`` means
    exactly one thing: one exact approved subject identity has been associated
    with one exact immutable named-lane declaration in memory. It never means
    the lane can run.
    """

    schema_version: Literal["1"] = CAPABILITY_BINDING_SCHEMA_VERSION
    status: BindingStatus
    reason: str = ""
    binding_complete: bool = False
    requested_approval_artifact_id: str = ""
    loaded_approval_artifact_id: str = ""
    approval_artifact_load_status: str = ""
    approval_artifact_loaded: bool = False
    approval_artifact_valid: bool = False
    approval_binding_valid: bool = False
    capability_support_status: str = ""
    capability_id: str = ""
    capability_catalog_identity_sha256: str = ""
    confirmed_capability_catalog_identity_sha256: str = ""
    lane_declaration_identity_sha256: str = ""
    confirmed_lane_declaration_identity_sha256: str = ""
    lane_id: str = ""
    lane_declaration: ApprovedChangeCapabilityLaneDeclaration | None = None
    binding: ApprovedChangeCapabilityBinding | None = None
    binding_identity_sha256: str = ""
    binding_canonical_byte_length: int = 0
    binding_validation: ApprovedChangeCapabilityBindingValidationResult | None = None
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_CAPABILITY_BINDING_WARNINGS

    # Accurate safety ledger. Binding reads and reports; it changes nothing.
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    filesystem_accessed: bool = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    approval_selected: Literal[False] = False
    approval_created: Literal[False] = False
    approval_persisted: Literal[False] = False
    contract_created: Literal[False] = False
    contract_persisted: Literal[False] = False
    source_bundle_mutation_performed: Literal[False] = False
    overwrite_performed: Literal[False] = False
    capability_support_evaluated: bool = False
    capability_supported: bool = False
    capability_binding_evaluated: bool = False
    capability_bound: bool = False
    binding_created: bool = False
    binding_persisted: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


# ---------------------------------------------------------------------------
# Lane-declaration validation
# ---------------------------------------------------------------------------


def _lane_validation_result(
    status: LaneDeclarationValidationStatus,
    *,
    reason: str = "",
    errors: list[str] | None = None,
    capability_id: str = "",
    lane_id: str = "",
    lane_declaration_identity_sha256: str = "",
    canonical_byte_length: int = 0,
) -> ApprovedChangeCapabilityLaneDeclarationValidationResult:
    return ApprovedChangeCapabilityLaneDeclarationValidationResult(
        status=status,
        reason=reason,
        declaration_valid=status == "capability_lane_declaration_valid",
        capability_id=capability_id,
        lane_id=lane_id,
        lane_declaration_identity_sha256=lane_declaration_identity_sha256,
        canonical_byte_length=canonical_byte_length,
        errors=tuple(sorted(set(errors or ()))),
    )


def _lane_availability_errors(declaration: ApprovedChangeCapabilityLaneDeclaration) -> list[str]:
    """Require every availability field to be false on every lane declaration."""
    errors: list[str] = []
    for field in (
        "binding_persistence_available",
        "authorization_available",
        "preflight_available",
        "receipt_linkage_available",
        "execution_available",
    ):
        if getattr(declaration, field) is not False:
            errors.append(
                f"lane {declaration.lane_id}: {field} must be false — PR322 declares one "
                "in-memory identity association only"
            )
    return errors


def validate_capability_lane_declaration(
    declaration: ApprovedChangeCapabilityLaneDeclaration | dict[str, Any],
) -> ApprovedChangeCapabilityLaneDeclarationValidationResult:
    """Validate one lane declaration. Pure, inert, non-throwing.

    A valid declaration carries the exact schema version, the exact declared
    capability ID, the exact declared lane ID, the exact lane kind, binding
    status, match rule, binding scope and implementation scope, every
    availability field false, a deterministic canonical payload, and a
    deterministic identity.
    """
    if declaration is None or isinstance(declaration, (str, bytes, int, float, bool, list, tuple)):
        return _lane_validation_result(
            "invalid_capability_lane_declaration_input",
            reason="a lane declaration must be the maintained model or a mapping",
            errors=["lane declaration must be the maintained model or a mapping"],
        )
    if not isinstance(declaration, (ApprovedChangeCapabilityLaneDeclaration, dict)):
        return _lane_validation_result(
            "invalid_capability_lane_declaration_input",
            reason="a lane declaration must be the maintained model or a mapping",
            errors=["lane declaration must be the maintained model or a mapping"],
        )
    if not isinstance(declaration, ApprovedChangeCapabilityLaneDeclaration):
        try:
            declaration = ApprovedChangeCapabilityLaneDeclaration.model_validate(declaration)
        except Exception as exc:  # pydantic exposes many structured subclasses.
            return _lane_validation_result(
                "capability_lane_declaration_invalid",
                reason="the lane-declaration payload is not one maintained lane declaration",
                errors=[str(exc)],
            )

    errors: list[str] = []
    if declaration.schema_version != CAPABILITY_BINDING_SCHEMA_VERSION:
        errors.append(f"lane schema_version must be {CAPABILITY_BINDING_SCHEMA_VERSION!r}")
    if declaration.capability_id != WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID:
        errors.append(f"capability_id must be {WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID!r}")
    if declaration.lane_id != WINDOWS_RUNTIME_RECONCILE_LANE_ID:
        errors.append(f"lane_id must be {WINDOWS_RUNTIME_RECONCILE_LANE_ID!r}")
    if declaration.lane_kind != LANE_KIND_NAMED_GOVERNED_IMPLEMENTATION_LANE:
        errors.append(f"lane_kind must be {LANE_KIND_NAMED_GOVERNED_IMPLEMENTATION_LANE!r}")
    if declaration.binding_status != BINDING_STATUS_DECLARED_BINDABLE:
        errors.append(f"binding_status must be {BINDING_STATUS_DECLARED_BINDABLE!r}")
    if declaration.match_rule != MATCH_RULE_EXACT_CAPABILITY_ID_ONLY:
        errors.append(f"match_rule must be {MATCH_RULE_EXACT_CAPABILITY_ID_ONLY!r}")
    if declaration.binding_scope != BINDING_SCOPE_EXACT_SUBJECT_TO_EXACT_LANE_ONLY:
        errors.append(f"binding_scope must be {BINDING_SCOPE_EXACT_SUBJECT_TO_EXACT_LANE_ONLY!r}")
    if declaration.implementation_scope != IMPLEMENTATION_SCOPE_WINDOWS_TWO_FILE_ONLY:
        errors.append(
            f"implementation_scope must be {IMPLEMENTATION_SCOPE_WINDOWS_TWO_FILE_ONLY!r}"
        )
    errors.extend(_lane_availability_errors(declaration))

    canonical = canonical_capability_lane_declaration_json(declaration)
    if canonical != canonical_capability_lane_declaration_json(
        declaration
    ):  # pragma: no cover - defensive determinism guard.
        errors.append("the lane-declaration canonical payload is not deterministic")
    encoded = canonical.encode("utf-8")
    identity = hashlib.sha256(encoded).hexdigest()
    if not hmac.compare_digest(
        identity, compute_capability_lane_declaration_sha256(declaration)
    ):  # pragma: no cover - defensive determinism guard.
        errors.append("the lane-declaration identity is not deterministic")

    reported = dict(
        capability_id=declaration.capability_id,
        lane_id=declaration.lane_id,
        lane_declaration_identity_sha256=identity,
        canonical_byte_length=len(encoded),
    )
    if errors:
        return _lane_validation_result(
            "capability_lane_declaration_invalid",
            reason="the lane declaration failed maintained PR322 validation",
            errors=errors,
            **reported,
        )
    return _lane_validation_result(
        "capability_lane_declaration_valid",
        reason="the lane declaration is the exact maintained named governed implementation lane",
        **reported,
    )


# ---------------------------------------------------------------------------
# Binding validation
# ---------------------------------------------------------------------------


def _binding_validation_result(
    status: BindingValidationStatus,
    *,
    reason: str = "",
    errors: list[str] | None = None,
    binding_identity_sha256: str = "",
    canonical_byte_length: int = 0,
) -> ApprovedChangeCapabilityBindingValidationResult:
    return ApprovedChangeCapabilityBindingValidationResult(
        status=status,
        reason=reason,
        binding_valid=status == "capability_binding_valid",
        binding_identity_sha256=binding_identity_sha256,
        canonical_byte_length=canonical_byte_length,
        errors=tuple(sorted(set(errors or ()))),
    )


def _sha256_field_errors(value: Any, label: str) -> list[str]:
    if not isinstance(value, str) or len(value) != _SHA256_LENGTH:
        return [f"{label} must be exactly 64 lowercase hexadecimal characters"]
    if not set(value) <= _LOWERCASE_HEX:
        return [f"{label} must be exactly 64 lowercase hexadecimal characters"]
    return []


def validate_approved_change_capability_binding(
    binding: ApprovedChangeCapabilityBinding | dict[str, Any],
    *,
    catalog: ApprovedChangeCapabilitySupportCatalog | None = None,
    lane_declaration: ApprovedChangeCapabilityLaneDeclaration | None = None,
    support_result: ApprovedChangeCapabilitySupportEvaluationResult | None = None,
    approval_artifact: ApprovedChangeApprovalArtifact | None = None,
) -> ApprovedChangeCapabilityBindingValidationResult:
    """Validate one capability binding. Pure, inert, non-throwing, no I/O.

    The binding itself is always rechecked: canonical payload, canonical bytes,
    byte length, deterministic identity, exact ``aca_`` artifact-ID format, the
    artifact ID deriving from the artifact identity through the maintained PR319
    rule, valid SHA-256 fields, the exact supported capability ID, the exact
    lane ID, and the exact binding and implementation scopes.

    The optional cross-check inputs are the maintained catalog, the maintained
    lane declaration, the maintained PR321 support result, and the loaded PR319
    artifact. When supplied, every overlapping field must agree exactly. They
    are cross-checks only: none of them is an authority this validator may
    substitute for its own recomputation, and none of them is ever accepted by
    the public binding operation.
    """
    if binding is None or isinstance(binding, (str, bytes, int, float, bool, list, tuple)):
        return _binding_validation_result(
            "invalid_capability_binding_validation_input",
            reason="a capability binding must be the maintained model or a mapping",
            errors=["capability binding must be the maintained model or a mapping"],
        )
    if not isinstance(binding, (ApprovedChangeCapabilityBinding, dict)):
        return _binding_validation_result(
            "invalid_capability_binding_validation_input",
            reason="a capability binding must be the maintained model or a mapping",
            errors=["capability binding must be the maintained model or a mapping"],
        )
    if not isinstance(binding, ApprovedChangeCapabilityBinding):
        try:
            binding = ApprovedChangeCapabilityBinding.model_validate(binding)
        except Exception as exc:  # pydantic exposes many structured subclasses.
            return _binding_validation_result(
                "capability_binding_invalid",
                reason="the binding payload is not one maintained capability binding",
                errors=[str(exc)],
            )

    errors: list[str] = []
    if binding.schema_version != CAPABILITY_BINDING_SCHEMA_VERSION:
        errors.append(f"binding schema_version must be {CAPABILITY_BINDING_SCHEMA_VERSION!r}")
    if binding.binding_type != CAPABILITY_BINDING_TYPE:
        errors.append(f"binding_type must be {CAPABILITY_BINDING_TYPE!r}")
    for value, label in (
        (binding.approval_artifact_identity_sha256, "approval_artifact_identity_sha256"),
        (binding.subject_sha256, "subject_sha256"),
        (binding.capability_catalog_identity_sha256, "capability_catalog_identity_sha256"),
        (binding.lane_declaration_identity_sha256, "lane_declaration_identity_sha256"),
    ):
        errors.extend(_sha256_field_errors(value, label))
    if not binding.approval_artifact_id.startswith(APPROVAL_ARTIFACT_ID_PREFIX):
        errors.append("approval_artifact_id must carry the maintained PR319 aca_ prefix")
    elif not errors and binding.approval_artifact_id != derive_approval_artifact_id(
        binding.approval_artifact_identity_sha256
    ):
        errors.append("approval_artifact_id is not the prefixed full approval-artifact identity")
    if binding.capability_id != WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID:
        errors.append(f"capability_id must be {WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID!r}")
    if binding.lane_id != WINDOWS_RUNTIME_RECONCILE_LANE_ID:
        errors.append(f"lane_id must be {WINDOWS_RUNTIME_RECONCILE_LANE_ID!r}")
    if binding.binding_scope != BINDING_SCOPE_EXACT_SUBJECT_TO_EXACT_LANE_ONLY:
        errors.append(f"binding_scope must be {BINDING_SCOPE_EXACT_SUBJECT_TO_EXACT_LANE_ONLY!r}")
    if binding.implementation_scope != IMPLEMENTATION_SCOPE_WINDOWS_TWO_FILE_ONLY:
        errors.append(
            f"implementation_scope must be {IMPLEMENTATION_SCOPE_WINDOWS_TWO_FILE_ONLY!r}"
        )

    if catalog is not None:
        expected = compute_approved_change_capability_support_catalog_sha256(catalog)
        if not hmac.compare_digest(binding.capability_catalog_identity_sha256, expected):
            errors.append(
                "capability_catalog_identity_sha256 does not match the supplied support catalog"
            )
    if lane_declaration is not None:
        expected = compute_capability_lane_declaration_sha256(lane_declaration)
        if not hmac.compare_digest(binding.lane_declaration_identity_sha256, expected):
            errors.append(
                "lane_declaration_identity_sha256 does not match the supplied lane declaration"
            )
        if binding.lane_id != lane_declaration.lane_id:
            errors.append("lane_id does not match the supplied lane declaration")
        if binding.capability_id != lane_declaration.capability_id:
            errors.append("capability_id does not match the supplied lane declaration")
    if support_result is not None:
        if support_result.status != REQUIRED_CAPABILITY_SUPPORT_STATUS:
            errors.append("the supplied PR321 support result did not confirm capability support")
        if support_result.capability_supported is not True:
            errors.append("the supplied PR321 support result does not report capability support")
        if binding.capability_id != support_result.capability_id:
            errors.append("capability_id does not match the supplied PR321 support result")
        if binding.approval_artifact_id != support_result.loaded_approval_artifact_id:
            errors.append("approval_artifact_id does not match the supplied PR321 support result")
        if not hmac.compare_digest(
            binding.capability_catalog_identity_sha256,
            support_result.catalog_identity_sha256,
        ):
            errors.append(
                "capability_catalog_identity_sha256 does not match the supplied PR321 support "
                "result"
            )
    if approval_artifact is not None:
        if binding.approval_artifact_id != approval_artifact.approval_artifact_id:
            errors.append("approval_artifact_id does not match the supplied approval artifact")
        if not hmac.compare_digest(
            binding.approval_artifact_identity_sha256,
            approval_artifact.approval_artifact_identity_sha256,
        ):
            errors.append(
                "approval_artifact_identity_sha256 does not match the supplied approval artifact"
            )
        if not hmac.compare_digest(binding.subject_sha256, approval_artifact.subject_sha256):
            errors.append("subject_sha256 does not match the supplied approval artifact")
        if binding.capability_id != approval_artifact.contract.subject.capability_id:
            errors.append("capability_id does not match the supplied approval artifact")

    canonical = canonical_approved_change_capability_binding_json(binding)
    if canonical != canonical_approved_change_capability_binding_json(
        binding
    ):  # pragma: no cover - defensive determinism guard.
        errors.append("the binding canonical payload is not deterministic")
    encoded = canonical.encode("utf-8")
    identity = hashlib.sha256(encoded).hexdigest()
    if not hmac.compare_digest(
        identity, compute_approved_change_capability_binding_sha256(binding)
    ):  # pragma: no cover - defensive determinism guard.
        errors.append("the binding identity is not deterministic")

    if errors:
        return _binding_validation_result(
            "capability_binding_invalid",
            reason="the capability binding failed maintained PR322 validation",
            errors=errors,
            binding_identity_sha256=identity,
            canonical_byte_length=len(encoded),
        )
    return _binding_validation_result(
        "capability_binding_valid",
        reason=(
            "the capability binding associates one exact approved subject with one exact "
            "maintained lane declaration"
        ),
        binding_identity_sha256=identity,
        canonical_byte_length=len(encoded),
    )


# ---------------------------------------------------------------------------
# The one public read-only binding operation
# ---------------------------------------------------------------------------


def _binding_result(
    status: BindingStatus,
    *,
    reason: str = "",
    errors: list[str] | None = None,
    binding_complete: bool = False,
    requested_approval_artifact_id: str = "",
    loaded_approval_artifact_id: str = "",
    approval_artifact_load_status: str = "",
    approval_artifact_loaded: bool = False,
    approval_artifact_valid: bool = False,
    approval_binding_valid: bool = False,
    capability_support_status: str = "",
    capability_id: str = "",
    capability_catalog_identity_sha256: str = "",
    confirmed_capability_catalog_identity_sha256: str = "",
    lane_declaration_identity_sha256: str = "",
    confirmed_lane_declaration_identity_sha256: str = "",
    lane_id: str = "",
    lane_declaration: ApprovedChangeCapabilityLaneDeclaration | None = None,
    binding: ApprovedChangeCapabilityBinding | None = None,
    binding_identity_sha256: str = "",
    binding_canonical_byte_length: int = 0,
    binding_validation: ApprovedChangeCapabilityBindingValidationResult | None = None,
    filesystem_accessed: bool = False,
    capability_support_evaluated: bool = False,
    capability_supported: bool = False,
    capability_binding_evaluated: bool = False,
    capability_bound: bool = False,
    binding_created: bool = False,
) -> ApprovedChangeCapabilityBindingResult:
    return ApprovedChangeCapabilityBindingResult(
        status=status,
        reason=reason,
        binding_complete=binding_complete,
        requested_approval_artifact_id=requested_approval_artifact_id,
        loaded_approval_artifact_id=loaded_approval_artifact_id,
        approval_artifact_load_status=approval_artifact_load_status,
        approval_artifact_loaded=approval_artifact_loaded,
        approval_artifact_valid=approval_artifact_valid,
        approval_binding_valid=approval_binding_valid,
        capability_support_status=capability_support_status,
        capability_id=capability_id,
        capability_catalog_identity_sha256=capability_catalog_identity_sha256,
        confirmed_capability_catalog_identity_sha256=confirmed_capability_catalog_identity_sha256,
        lane_declaration_identity_sha256=lane_declaration_identity_sha256,
        confirmed_lane_declaration_identity_sha256=confirmed_lane_declaration_identity_sha256,
        lane_id=lane_id,
        lane_declaration=lane_declaration,
        binding=binding,
        binding_identity_sha256=binding_identity_sha256,
        binding_canonical_byte_length=binding_canonical_byte_length,
        binding_validation=binding_validation,
        errors=tuple(sorted(set(errors or ()))),
        filesystem_accessed=filesystem_accessed,
        capability_support_evaluated=capability_support_evaluated,
        capability_supported=capability_supported,
        capability_binding_evaluated=capability_binding_evaluated,
        capability_bound=capability_bound,
        binding_created=binding_created,
    )


def _confirmation_errors(value: Any, label: str) -> list[str]:
    """Reject anything that is not exactly 64 lowercase hexadecimal characters."""
    if not isinstance(value, str) or not value:
        return [f"{label} must be a non-empty string"]
    if len(value) != _SHA256_LENGTH or not set(value) <= _LOWERCASE_HEX:
        return [f"{label} must be exactly 64 lowercase hexadecimal characters"]
    return []


def construct_persisted_approved_change_capability_binding(
    approval_artifact_id: str,
    *,
    data_dir: Path | str,
    confirm_capability_catalog_identity_sha256: str,
    confirm_lane_declaration_identity_sha256: str,
) -> ApprovedChangeCapabilityBindingResult:
    """Bind one exact persisted approval to the exact maintained PR313 lane.

    The operation accepts exactly four explicit inputs: one exact full PR319
    ``aca_`` approval-artifact ID, one explicit ShellForgeAI ``data_dir``, one
    explicit raw 64-lowercase-hex PR321 catalog-identity confirmation, and one
    explicit raw 64-lowercase-hex lane-declaration-identity confirmation.

    It accepts no inventory result, no selected inventory entry, no ``latest``,
    ``current``, or "most recent" reference, no caller-supplied artifact,
    contract, support result, catalog, or lane declaration, no PR313 plan, no
    PR304 or PR305 artifact, no execution target, no preflight, no receipt, no
    authorization token, no output path, and no execution confirmation.

    Both confirmations are validated and compared with ``hmac.compare_digest``
    **before any filesystem access**. The lane-declaration confirmation means
    exactly one thing — *bind against this exact source-maintained lane
    declaration* — and is never authorization, preflight approval, or execution
    confirmation.
    """
    requested = approval_artifact_id if isinstance(approval_artifact_id, str) else ""

    # 1-2. The maintained PR321 support catalog, validated, with its identity.
    catalog = maintained_approved_change_capability_support_catalog()
    catalog_validation = validate_approved_change_capability_support_catalog(catalog)
    catalog_identity = catalog_validation.catalog_identity_sha256
    if not catalog_validation.catalog_valid:  # pragma: no cover - maintained catalog is valid.
        return _binding_result(
            "capability_binding_blocked",
            reason="the maintained capability-support catalog failed its own validation",
            errors=["the maintained capability-support catalog failed maintained PR321 validation"],
            requested_approval_artifact_id=requested,
            capability_catalog_identity_sha256=catalog_identity,
        )

    # 3-4. The maintained lane declaration, validated, with its identity.
    lane = maintained_windows_runtime_reconcile_lane_declaration()
    lane_validation = validate_capability_lane_declaration(lane)
    lane_identity = lane_validation.lane_declaration_identity_sha256
    if not lane_validation.declaration_valid:  # pragma: no cover - maintained lane is valid.
        return _binding_result(
            "capability_binding_blocked",
            reason="the maintained lane declaration failed its own validation",
            errors=["the maintained lane declaration failed maintained PR322 validation"],
            requested_approval_artifact_id=requested,
            capability_catalog_identity_sha256=catalog_identity,
            lane_declaration_identity_sha256=lane_identity,
        )

    identities = dict(
        capability_catalog_identity_sha256=catalog_identity,
        lane_declaration_identity_sha256=lane_identity,
    )

    # 5. Both explicit confirmations, structurally, before any filesystem access.
    confirmation_errors = _confirmation_errors(
        confirm_capability_catalog_identity_sha256,
        "confirm_capability_catalog_identity_sha256",
    )
    confirmation_errors.extend(
        _confirmation_errors(
            confirm_lane_declaration_identity_sha256,
            "confirm_lane_declaration_identity_sha256",
        )
    )
    if confirmation_errors:
        return _binding_result(
            "invalid_capability_binding_input",
            reason="an explicit identity confirmation is not one raw 64-hex identity",
            errors=confirmation_errors,
            requested_approval_artifact_id=requested,
            **identities,
        )

    # 6. Both exact confirmation matches, still before any filesystem access.
    if not hmac.compare_digest(confirm_capability_catalog_identity_sha256, catalog_identity):
        return _binding_result(
            "capability_catalog_confirmation_mismatch",
            reason="the confirmation does not name the exact maintained capability-support catalog",
            errors=[
                "confirm_capability_catalog_identity_sha256 does not match the maintained "
                "capability-support catalog identity"
            ],
            requested_approval_artifact_id=requested,
            confirmed_capability_catalog_identity_sha256=(
                confirm_capability_catalog_identity_sha256
            ),
            **identities,
        )
    if not hmac.compare_digest(confirm_lane_declaration_identity_sha256, lane_identity):
        return _binding_result(
            "lane_declaration_confirmation_mismatch",
            reason="the confirmation does not name the exact maintained lane declaration",
            errors=[
                "confirm_lane_declaration_identity_sha256 does not match the maintained lane "
                "declaration identity"
            ],
            requested_approval_artifact_id=requested,
            confirmed_capability_catalog_identity_sha256=(
                confirm_capability_catalog_identity_sha256
            ),
            confirmed_lane_declaration_identity_sha256=confirm_lane_declaration_identity_sha256,
            **identities,
        )

    confirmed = dict(
        requested_approval_artifact_id=requested,
        confirmed_capability_catalog_identity_sha256=confirm_capability_catalog_identity_sha256,
        confirmed_lane_declaration_identity_sha256=confirm_lane_declaration_identity_sha256,
        lane_id=lane.lane_id,
        lane_declaration=lane,
        **identities,
    )

    # 7. Exactly one maintained PR321 capability-support evaluation. PR321 owns
    #    the support decision; PR322 never replaces it with its own membership
    #    check and never widens it.
    support = evaluate_persisted_approved_change_capability_support(
        approval_artifact_id,
        data_dir=data_dir,
        confirm_capability_catalog_identity_sha256=confirm_capability_catalog_identity_sha256,
    )
    support_status = str(support.status)
    accessed = bool(support.filesystem_accessed)
    observed = dict(
        capability_support_status=support_status,
        loaded_approval_artifact_id=support.loaded_approval_artifact_id,
        approval_artifact_load_status=support.approval_artifact_load_status,
        approval_artifact_loaded=bool(support.approval_artifact_loaded),
        approval_artifact_valid=bool(support.approval_artifact_valid),
        approval_binding_valid=bool(support.approval_binding_valid),
        capability_id=support.capability_id,
        filesystem_accessed=accessed,
        **confirmed,
    )

    # 8. Only a confirmed, complete, exactly-declared support result may bind.
    if support_status == CAPABILITY_NOT_DECLARED_SUPPORT_STATUS:
        return _binding_result(
            "capability_binding_not_available",
            reason=(
                "the approved subject's exact capability_id is not declared supported, so no "
                "lane binding exists"
            ),
            errors=[f"unbindable capability_id: {support.capability_id}"],
            capability_support_evaluated=True,
            capability_binding_evaluated=True,
            **observed,
        )
    if support_status != REQUIRED_CAPABILITY_SUPPORT_STATUS:
        if support_status == _SUPPORT_INVALID_INPUT_STATUS:
            status: BindingStatus = "invalid_capability_binding_input"
        elif support_status == _SUPPORT_CATALOG_MISMATCH_STATUS:
            status = "capability_catalog_confirmation_mismatch"
        elif support_status == _SUPPORT_ARTIFACT_NOT_AVAILABLE_STATUS:
            status = "approval_artifact_not_available"
        elif support_status == _SUPPORT_ARTIFACT_INVALID_STATUS:
            status = "approval_artifact_invalid"
        else:
            status = "capability_support_not_confirmed"
        return _binding_result(
            status,
            reason=str(support.reason),
            errors=[
                "the maintained PR321 evaluator did not confirm capability support "
                f"(status: {support_status})"
            ],
            **observed,
        )

    gate_errors: list[str] = []
    if not support.evaluation_complete:
        gate_errors.append("the maintained PR321 evaluation did not complete")
    if support.capability_supported is not True:
        gate_errors.append("the maintained PR321 evaluator does not report capability support")
    if support.capability_id != WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID:
        gate_errors.append("the confirmed capability_id is not the exact declared lane capability")
    if not support.declaration_found or support.declaration is None:
        gate_errors.append("the maintained PR321 evaluator found no exact support declaration")
    if support.contract_validation is None or (
        support.contract_validation.status != PR309_CONTRACT_VALID_STATUS
    ):
        gate_errors.append("the maintained PR309 validator did not report contract_valid")
    if gate_errors:
        return _binding_result(
            "capability_support_not_confirmed",
            reason="the confirmed support result did not satisfy every maintained PR321 gate",
            errors=gate_errors,
            capability_support_evaluated=True,
            **observed,
        )

    # 9. One maintained PR319 exact-ID load, solely to obtain the exact binding
    #    metadata the PR321 result does not expose (the artifact identity and
    #    the exact subject SHA-256).
    load_result = load_persisted_approved_change_approval_artifact(
        approval_artifact_id, data_dir=data_dir
    )
    load_status = str(load_result.status)
    artifact = load_result.artifact
    if load_status != REQUIRED_APPROVAL_ARTIFACT_LOAD_STATUS or artifact is None:
        return _binding_result(
            "capability_binding_blocked",
            reason=str(load_result.reason),
            errors=[
                "the maintained PR319 exact-ID loader did not return one fully revalidated "
                f"approval artifact (status: {load_status})"
            ],
            capability_support_evaluated=True,
            capability_supported=True,
            **{**observed, "approval_artifact_load_status": load_status},
        )

    # 10. Exact agreement between the maintained PR321 result and the PR319 load.
    disagreements: list[str] = []
    if artifact.approval_artifact_id != support.loaded_approval_artifact_id:
        disagreements.append("the PR321 result and the PR319 load disagree on the artifact ID")
    if not hmac.compare_digest(
        artifact.approval_artifact_identity_sha256,
        load_result.approval_artifact_identity_sha256,
    ):
        disagreements.append(
            "the PR319 load and its artifact disagree on the approval-artifact identity"
        )
    if not hmac.compare_digest(artifact.subject_sha256, load_result.subject_sha256):
        disagreements.append("the PR319 load and its artifact disagree on the subject SHA-256")
    if artifact.contract.subject.capability_id != support.capability_id:
        disagreements.append("the PR321 result and the PR319 load disagree on the capability ID")
    if not load_result.approval_binding_valid or not support.approval_binding_valid:
        disagreements.append("the PR309 approval binding is not valid on both maintained reads")
    if not load_result.source_bundle_revalidated:
        disagreements.append("the exact PR317 source-bundle provenance was not revalidated")
    if disagreements:
        return _binding_result(
            "capability_binding_blocked",
            reason="the maintained PR321 and PR319 reads did not agree exactly",
            errors=disagreements,
            capability_support_evaluated=True,
            capability_supported=True,
            **{**observed, "approval_artifact_load_status": load_status},
        )

    # 11. The exact capability ID must be the lane declaration's own.
    if artifact.contract.subject.capability_id != lane.capability_id:
        return _binding_result(
            "capability_binding_not_available",
            reason="the approved subject's exact capability_id does not name the declared lane",
            errors=[f"unbindable capability_id: {artifact.contract.subject.capability_id}"],
            capability_support_evaluated=True,
            capability_binding_evaluated=True,
            **{**observed, "approval_artifact_load_status": load_status},
        )

    # 12. Exactly one in-memory binding.
    binding = ApprovedChangeCapabilityBinding(
        approval_artifact_id=artifact.approval_artifact_id,
        approval_artifact_identity_sha256=artifact.approval_artifact_identity_sha256,
        subject_sha256=artifact.subject_sha256,
        capability_catalog_identity_sha256=catalog_identity,
        capability_id=artifact.contract.subject.capability_id,
        lane_declaration_identity_sha256=lane_identity,
        lane_id=lane.lane_id,
    )

    # 13. Its deterministic identity, revalidated against every maintained input.
    binding_validation = validate_approved_change_capability_binding(
        binding,
        catalog=catalog,
        lane_declaration=lane,
        support_result=support,
        approval_artifact=artifact,
    )
    reported = dict(
        binding_identity_sha256=binding_validation.binding_identity_sha256,
        binding_canonical_byte_length=binding_validation.canonical_byte_length,
        binding_validation=binding_validation,
    )
    if not binding_validation.binding_valid:
        return _binding_result(
            "capability_binding_validation_failed",
            reason="the constructed binding failed maintained PR322 validation",
            errors=["the constructed capability binding failed maintained PR322 validation"],
            capability_support_evaluated=True,
            capability_supported=True,
            capability_binding_evaluated=True,
            **{**observed, "approval_artifact_load_status": load_status, **reported},
        )

    # 14. One immutable result.
    return _binding_result(
        "capability_binding_constructed",
        reason=(
            "one exact approved subject identity is associated with one exact maintained named "
            "lane declaration in memory"
        ),
        binding_complete=True,
        capability_support_evaluated=True,
        capability_supported=True,
        capability_binding_evaluated=True,
        capability_bound=True,
        binding_created=True,
        binding=binding,
        **{**observed, "approval_artifact_load_status": load_status, **reported},
    )
