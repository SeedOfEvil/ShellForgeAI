"""Typed read-only approved-change plan link (PR323).

PR322 answers exactly one question: *has this exact approved subject identity
been associated with the exact source-maintained PR313 Windows runtime-reconcile
lane declaration?* That answer names a lane, not a plan, so it says nothing at
all about **which** exact saved plan an approved subject would ever be paired
with. This module closes exactly that gap and nothing else.

It adds exactly two things:

* one immutable **plan link** model whose deterministic identity is the SHA-256
  of one canonical payload naming the exact PR322 binding, the exact approved
  subject, the exact confirmed PR321 catalog, the exact confirmed lane
  declaration, and the exact canonical SHA-256 of one maintained-validator-
  approved saved PR305 Windows runtime-reconcile plan packet;
* one read-only operation that, given one exact ``aca_`` artifact ID, one
  explicitly supplied parsed plan mapping, one explicit data root, and all three
  exact identity confirmations, validates the plan through the maintained
  PR305/PR313 authority, obtains the binding through the maintained PR322
  operation, and constructs exactly one in-memory plan link.

**A plan link means only** that one exact approved binding identity has been
deterministically associated with the exact canonical identity of one
maintained-validator-approved saved Windows reconcile plan, in memory.

It does **not** mean the plan is currently safe to run. It is not target
semantic compatibility, procedure semantic compatibility, free-text intent
equivalence, PR304 evidence freshness, staged-source inspection, durable-runtime
inspection, ``System32`` inspection, current-state readiness, preflight success,
authenticated identity, authorization, receipt linkage, execution eligibility,
or execution.

The link is in-memory only: PR323 introduces no persisted plan-link artifact, no
link ID prefix, no link publisher, and no link loader. This module reaches the
filesystem only indirectly, through the maintained PR322 binding operation. It
never parses persisted approval JSON, never reads a plan file, never accepts a
plan path, never performs approval selection, and never resolves ``latest``,
``current``, or "most recent".
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from shellforgeai.core.approved_change_capability_binding import (
    WINDOWS_RUNTIME_RECONCILE_LANE_ID,
    ApprovedChangeCapabilityBinding,
    ApprovedChangeCapabilityBindingResult,
    compute_approved_change_capability_binding_sha256,
    compute_capability_lane_declaration_sha256,
    construct_persisted_approved_change_capability_binding,
    maintained_windows_runtime_reconcile_lane_declaration,
)
from shellforgeai.core.approved_change_capability_support import (
    WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
    compute_approved_change_capability_support_catalog_sha256,
    maintained_approved_change_capability_support_catalog,
)
from shellforgeai.core.windows_runtime_reconcile_plan_contract import (
    ACCEPTED_PLAN_STATUSES,
    ALLOWLIST,
    PARENT_CONTRACT_VERSION,
    PLAN_MODE,
    RECIPE_ID,
    WindowsRuntimeReconcilePlanValidationResult,
    validate_saved_windows_runtime_reconcile_plan_packet,
)

PLAN_LINK_SCHEMA_VERSION = "1"

#: The one fixed link type literal. There is no alias, no alternate spelling,
#: no caller-defined kind, and no second link type.
PLAN_LINK_TYPE = "approved_change_windows_runtime_reconcile_plan_link"

#: The one comparison scope a plan link may ever declare. It states precisely
#: what was compared: exact binding identity against exact validated plan
#: structure, and nothing semantic and nothing live.
PLAN_LINK_COMPARISON_SCOPE = "exact_binding_to_exact_validated_plan_structure_only"

#: The exact scope each explicit confirmation authorizes, and nothing more.
PLAN_CONFIRMATION_SCOPE = "compare_against_this_exact_validated_saved_plan_packet"

#: The exact PR322 binding status that alone permits a plan link.
REQUIRED_CAPABILITY_BINDING_STATUS = "capability_binding_constructed"

#: The maintained PR322 statuses this module classifies explicitly. Any other
#: status blocks rather than being interpreted.
_BINDING_NOT_AVAILABLE_STATUS = "capability_binding_not_available"
_BINDING_CATALOG_MISMATCH_STATUS = "capability_catalog_confirmation_mismatch"
_BINDING_LANE_MISMATCH_STATUS = "lane_declaration_confirmation_mismatch"
_BINDING_INVALID_INPUT_STATUS = "invalid_capability_binding_input"

PLAN_LINK_VALIDATION_STATUSES = (
    "approved_change_plan_link_valid",
    "approved_change_plan_link_invalid",
    "invalid_approved_change_plan_link_validation_input",
)
PlanLinkValidationStatus = Literal[
    "approved_change_plan_link_valid",
    "approved_change_plan_link_invalid",
    "invalid_approved_change_plan_link_validation_input",
]

PLAN_LINK_STATUSES = (
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
)
PlanLinkStatus = Literal[
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
]

#: Warnings every PR323 result carries, whatever its status. They state exactly
#: what a plan link does and does not mean, so no automated consumer can read an
#: in-memory identity association as semantic compatibility, current-state
#: readiness, authorization, or execution.
PERMANENT_PLAN_LINK_WARNINGS: tuple[str, ...] = (
    "plan link is an in-memory identity association only",
    "plan link is not authorization",
    "plan link is not current-state preflight",
    "plan link does not inspect the live staged source",
    "plan link does not inspect the live durable runtime",
    "plan link does not inspect System32",
    "plan link does not validate target semantics",
    "plan link does not validate procedure semantics",
    "plan link does not validate PR304 evidence freshness",
    "plan link does not prove preconditions remain true",
    "plan link does not create or link a receipt",
    "plan link grants no execution eligibility",
    "plan link does not invoke PR313 execution",
    "an exact aca_ approval-artifact ID remains required",
    "no approval was selected through inventory",
    "persisted approved_by remains self-asserted metadata, not authenticated identity",
    "no CLI or natural-language plan-link or execution route exists",
)

_SHA256_LENGTH = 64
_LOWERCASE_HEX = frozenset("0123456789abcdef")


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# The typed plan link and its canonicalization
# ---------------------------------------------------------------------------


class ApprovedChangeWindowsRuntimeReconcilePlanLink(_FrozenModel):
    """One immutable in-memory association of one binding with one plan.

    The model holds exactly the canonical payload fields and no derived value,
    so the plan-link identity is non-circular by construction. It carries no
    absolute path, no staged-source root, no durable-runtime root, no source or
    destination content, no backup path pattern, no user or host identity, no
    timestamp, no authorization field, no receipt field, and no execution field.
    """

    schema_version: Literal["1"] = PLAN_LINK_SCHEMA_VERSION
    link_type: Literal["approved_change_windows_runtime_reconcile_plan_link"] = PLAN_LINK_TYPE
    approval_artifact_id: str
    approval_artifact_identity_sha256: str
    subject_sha256: str
    capability_binding_identity_sha256: str
    capability_catalog_identity_sha256: str
    capability_id: str
    lane_declaration_identity_sha256: str
    lane_id: str
    plan_mode: str
    plan_recipe_id: str
    plan_sha256: str
    plan_status: str
    destination_parent_contract_version: int
    comparison_scope: Literal["exact_binding_to_exact_validated_plan_structure_only"] = (
        PLAN_LINK_COMPARISON_SCOPE
    )


def canonical_approved_change_plan_link_payload(
    link: ApprovedChangeWindowsRuntimeReconcilePlanLink | dict[str, Any],
) -> dict[str, Any]:
    """Return the canonical plan-link payload with sorted mapping keys.

    Nothing derived is ever part of the payload, so the plan-link identity can
    never hash itself. No timestamp, environment value, host value, platform
    value, path, or randomness enters the payload.
    """
    if not isinstance(link, ApprovedChangeWindowsRuntimeReconcilePlanLink):
        link = ApprovedChangeWindowsRuntimeReconcilePlanLink.model_validate(link)
    payload = link.model_dump(mode="python")
    return {key: payload[key] for key in sorted(payload)}


def canonical_approved_change_plan_link_json(
    link: ApprovedChangeWindowsRuntimeReconcilePlanLink | dict[str, Any],
) -> str:
    """Return deterministic canonical plan-link JSON.

    Mapping keys are sorted, separators are compact, ``ensure_ascii`` is off so
    Unicode is preserved exactly, and there is no BOM and no trailing newline.
    """
    return json.dumps(
        canonical_approved_change_plan_link_payload(link),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_approved_change_plan_link_sha256(
    link: ApprovedChangeWindowsRuntimeReconcilePlanLink | dict[str, Any],
) -> str:
    """Compute the full, untruncated plan-link identity SHA-256.

    This identity is permanently distinct from the PR309 subject identity, the
    PR316 bundle identity, the PR319 approval-artifact identity, the PR321
    catalog identity, the PR322 lane identity, the PR322 binding identity, the
    PR305/PR313 canonical plan SHA-256, and any receipt identity. It is never
    approval, authorization, preflight, or execution confirmation, and it is
    never persisted or prefixed into a durable ID.
    """
    return hashlib.sha256(
        canonical_approved_change_plan_link_json(link).encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------------
# Structured results
# ---------------------------------------------------------------------------


class ApprovedChangePlanLinkValidationResult(_FrozenModel):
    """Structured, non-throwing plan-link validation result.

    Validation is pure and inert: it recanonicalizes the link, recomputes the
    link identity, rechecks every exact field, and performs no I/O.
    """

    schema_version: Literal["1"] = PLAN_LINK_SCHEMA_VERSION
    status: PlanLinkValidationStatus
    reason: str = ""
    link_valid: bool
    plan_link_identity_sha256: str = ""
    canonical_byte_length: int = 0
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_PLAN_LINK_WARNINGS

    # Accurate safety ledger. Plan-link validation reaches nothing.
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
    plan_validated: Literal[False] = False
    plan_identity_confirmed: Literal[False] = False
    plan_link_evaluated: Literal[False] = False
    plan_linked: Literal[False] = False
    plan_link_persisted: Literal[False] = False
    subject_semantic_compatibility_evaluated: Literal[False] = False
    target_compatibility_evaluated: Literal[False] = False
    procedure_compatibility_evaluated: Literal[False] = False
    evidence_compatibility_evaluated: Literal[False] = False
    current_state_preflight_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = "not_executed"


class ApprovedChangePlanLinkResult(_FrozenModel):
    """Structured, non-throwing read-only plan-link result.

    ``link_complete`` is the only field that states whether the exact plan-link
    question was actually answered. ``plan_linked=true`` means exactly one
    thing: the exact approved binding identity has been associated with the
    exact canonical identity of one maintained-validator-approved saved Windows
    reconcile plan. It never means the plan is currently safe to run.

    The full plan packet is never returned, and no host path copied from the
    packet or from the maintained validator is ever reported.
    """

    schema_version: Literal["1"] = PLAN_LINK_SCHEMA_VERSION
    status: PlanLinkStatus
    reason: str = ""
    link_complete: bool = False
    requested_approval_artifact_id: str = ""
    plan_validated: bool = False
    plan_validation_status: str = ""
    plan_mode: str = ""
    plan_recipe_id: str = ""
    plan_sha256: str = ""
    confirmed_plan_sha256: str = ""
    plan_identity_confirmed: bool = False
    plan_status: str = ""
    destination_parent_contract_version: int = 0
    capability_support_evaluated: bool = False
    capability_supported: bool = False
    capability_binding_evaluated: bool = False
    capability_bound: bool = False
    capability_binding_status: str = ""
    capability_binding_identity_sha256: str = ""
    capability_id: str = ""
    capability_catalog_identity_sha256: str = ""
    confirmed_capability_catalog_identity_sha256: str = ""
    lane_id: str = ""
    lane_declaration_identity_sha256: str = ""
    confirmed_lane_declaration_identity_sha256: str = ""
    plan_link_evaluated: bool = False
    plan_linked: bool = False
    plan_link: ApprovedChangeWindowsRuntimeReconcilePlanLink | None = None
    plan_link_identity_sha256: str = ""
    plan_link_canonical_byte_length: int = 0
    plan_link_validation: ApprovedChangePlanLinkValidationResult | None = None
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_PLAN_LINK_WARNINGS

    # Accurate safety ledger. Plan linking reads and reports; it changes nothing.
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
    binding_persisted: Literal[False] = False
    plan_link_persisted: Literal[False] = False
    plan_packet_written: Literal[False] = False
    subject_semantic_compatibility_evaluated: Literal[False] = False
    target_compatibility_evaluated: Literal[False] = False
    procedure_compatibility_evaluated: Literal[False] = False
    evidence_compatibility_evaluated: Literal[False] = False
    current_state_preflight_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = "not_executed"


# ---------------------------------------------------------------------------
# Plan-link validation
# ---------------------------------------------------------------------------


def _link_validation_result(
    status: PlanLinkValidationStatus,
    *,
    reason: str = "",
    errors: list[str] | None = None,
    plan_link_identity_sha256: str = "",
    canonical_byte_length: int = 0,
) -> ApprovedChangePlanLinkValidationResult:
    return ApprovedChangePlanLinkValidationResult(
        status=status,
        reason=reason,
        link_valid=status == "approved_change_plan_link_valid",
        plan_link_identity_sha256=plan_link_identity_sha256,
        canonical_byte_length=canonical_byte_length,
        errors=tuple(sorted(set(errors or ()))),
    )


def _sha256_field_errors(value: Any, label: str) -> list[str]:
    if not isinstance(value, str) or len(value) != _SHA256_LENGTH:
        return [f"{label} must be exactly 64 lowercase hexadecimal characters"]
    if not set(value) <= _LOWERCASE_HEX:
        return [f"{label} must be exactly 64 lowercase hexadecimal characters"]
    return []


def validate_approved_change_plan_link(
    link: ApprovedChangeWindowsRuntimeReconcilePlanLink | dict[str, Any],
    *,
    binding: ApprovedChangeCapabilityBinding | None = None,
    plan_validation: WindowsRuntimeReconcilePlanValidationResult | None = None,
) -> ApprovedChangePlanLinkValidationResult:
    """Validate one plan link. Pure, inert, non-throwing, no I/O.

    The link itself is always rechecked: canonical payload, canonical bytes,
    byte length, deterministic identity, valid SHA-256 fields, the exact
    supported capability ID, the exact maintained lane ID, the exact plan mode
    and recipe ID, an accepted plan status, the exact destination-parent
    contract version, and the exact comparison scope.

    The optional cross-check inputs are the maintained PR322 binding and the
    maintained plan-validation result. When supplied, every overlapping field
    must agree exactly. They are cross-checks only: neither is an authority this
    validator may substitute for its own recomputation, and neither is ever
    accepted by the public plan-link operation.
    """
    if link is None or isinstance(link, (str, bytes, int, float, bool, list, tuple)):
        return _link_validation_result(
            "invalid_approved_change_plan_link_validation_input",
            reason="a plan link must be the maintained model or a mapping",
            errors=["plan link must be the maintained model or a mapping"],
        )
    if not isinstance(link, (ApprovedChangeWindowsRuntimeReconcilePlanLink, dict)):
        return _link_validation_result(
            "invalid_approved_change_plan_link_validation_input",
            reason="a plan link must be the maintained model or a mapping",
            errors=["plan link must be the maintained model or a mapping"],
        )
    if not isinstance(link, ApprovedChangeWindowsRuntimeReconcilePlanLink):
        try:
            link = ApprovedChangeWindowsRuntimeReconcilePlanLink.model_validate(link)
        except Exception as exc:  # pydantic exposes many structured subclasses.
            return _link_validation_result(
                "approved_change_plan_link_invalid",
                reason="the plan-link payload is not one maintained plan link",
                errors=[str(exc)],
            )

    errors: list[str] = []
    if link.schema_version != PLAN_LINK_SCHEMA_VERSION:
        errors.append(f"plan-link schema_version must be {PLAN_LINK_SCHEMA_VERSION!r}")
    if link.link_type != PLAN_LINK_TYPE:
        errors.append(f"link_type must be {PLAN_LINK_TYPE!r}")
    for value, label in (
        (link.approval_artifact_identity_sha256, "approval_artifact_identity_sha256"),
        (link.subject_sha256, "subject_sha256"),
        (link.capability_binding_identity_sha256, "capability_binding_identity_sha256"),
        (link.capability_catalog_identity_sha256, "capability_catalog_identity_sha256"),
        (link.lane_declaration_identity_sha256, "lane_declaration_identity_sha256"),
        (link.plan_sha256, "plan_sha256"),
    ):
        errors.extend(_sha256_field_errors(value, label))
    if link.capability_id != WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID:
        errors.append(f"capability_id must be {WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID!r}")
    if link.lane_id != WINDOWS_RUNTIME_RECONCILE_LANE_ID:
        errors.append(f"lane_id must be {WINDOWS_RUNTIME_RECONCILE_LANE_ID!r}")
    if link.plan_mode != PLAN_MODE:
        errors.append(f"plan_mode must be {PLAN_MODE!r}")
    if link.plan_recipe_id != RECIPE_ID:
        errors.append(f"plan_recipe_id must be {RECIPE_ID!r}")
    if link.plan_status not in ACCEPTED_PLAN_STATUSES:
        errors.append(f"plan_status must be one of {ACCEPTED_PLAN_STATUSES!r}")
    if link.destination_parent_contract_version != PARENT_CONTRACT_VERSION:
        errors.append(f"destination_parent_contract_version must be {PARENT_CONTRACT_VERSION!r}")
    if link.comparison_scope != PLAN_LINK_COMPARISON_SCOPE:
        errors.append(f"comparison_scope must be {PLAN_LINK_COMPARISON_SCOPE!r}")

    if binding is not None:
        if link.approval_artifact_id != binding.approval_artifact_id:
            errors.append("approval_artifact_id does not match the supplied capability binding")
        if not hmac.compare_digest(
            link.approval_artifact_identity_sha256,
            binding.approval_artifact_identity_sha256,
        ):
            errors.append(
                "approval_artifact_identity_sha256 does not match the supplied capability binding"
            )
        if not hmac.compare_digest(link.subject_sha256, binding.subject_sha256):
            errors.append("subject_sha256 does not match the supplied capability binding")
        if not hmac.compare_digest(
            link.capability_catalog_identity_sha256,
            binding.capability_catalog_identity_sha256,
        ):
            errors.append(
                "capability_catalog_identity_sha256 does not match the supplied capability binding"
            )
        if not hmac.compare_digest(
            link.lane_declaration_identity_sha256,
            binding.lane_declaration_identity_sha256,
        ):
            errors.append(
                "lane_declaration_identity_sha256 does not match the supplied capability binding"
            )
        if link.capability_id != binding.capability_id:
            errors.append("capability_id does not match the supplied capability binding")
        if link.lane_id != binding.lane_id:
            errors.append("lane_id does not match the supplied capability binding")
        if not hmac.compare_digest(
            link.capability_binding_identity_sha256,
            compute_approved_change_capability_binding_sha256(binding),
        ):
            errors.append(
                "capability_binding_identity_sha256 does not match the supplied capability binding"
            )
    if plan_validation is not None:
        if not plan_validation.plan_valid:
            errors.append("the supplied plan validation did not accept the saved plan packet")
        if not hmac.compare_digest(link.plan_sha256, plan_validation.plan_sha256 or ""):
            errors.append("plan_sha256 does not match the supplied plan validation")
        if link.plan_status != plan_validation.plan_status:
            errors.append("plan_status does not match the supplied plan validation")
        if link.plan_mode != plan_validation.plan_mode:
            errors.append("plan_mode does not match the supplied plan validation")
        if link.plan_recipe_id != plan_validation.plan_recipe_id:
            errors.append("plan_recipe_id does not match the supplied plan validation")
        if (
            link.destination_parent_contract_version
            != plan_validation.destination_parent_contract_version
        ):
            errors.append(
                "destination_parent_contract_version does not match the supplied plan validation"
            )

    canonical = canonical_approved_change_plan_link_json(link)
    encoded = canonical.encode("utf-8")
    identity = hashlib.sha256(encoded).hexdigest()
    if not hmac.compare_digest(
        identity, compute_approved_change_plan_link_sha256(link)
    ):  # pragma: no cover - defensive determinism guard.
        errors.append("the plan-link identity is not deterministic")

    if errors:
        return _link_validation_result(
            "approved_change_plan_link_invalid",
            reason="the plan link failed maintained PR323 validation",
            errors=errors,
            plan_link_identity_sha256=identity,
            canonical_byte_length=len(encoded),
        )
    return _link_validation_result(
        "approved_change_plan_link_valid",
        reason=(
            "the plan link associates one exact approved binding identity with one exact "
            "validated saved plan identity"
        ),
        plan_link_identity_sha256=identity,
        canonical_byte_length=len(encoded),
    )


# ---------------------------------------------------------------------------
# The one public read-only plan-link operation
# ---------------------------------------------------------------------------


def _result(
    status: PlanLinkStatus,
    *,
    reason: str = "",
    errors: list[str] | None = None,
    link_complete: bool = False,
    requested_approval_artifact_id: str = "",
    plan_validated: bool = False,
    plan_validation_status: str = "",
    plan_mode: str = "",
    plan_recipe_id: str = "",
    plan_sha256: str = "",
    confirmed_plan_sha256: str = "",
    plan_identity_confirmed: bool = False,
    plan_status: str = "",
    destination_parent_contract_version: int = 0,
    capability_support_evaluated: bool = False,
    capability_supported: bool = False,
    capability_binding_evaluated: bool = False,
    capability_bound: bool = False,
    capability_binding_status: str = "",
    capability_binding_identity_sha256: str = "",
    capability_id: str = "",
    capability_catalog_identity_sha256: str = "",
    confirmed_capability_catalog_identity_sha256: str = "",
    lane_id: str = "",
    lane_declaration_identity_sha256: str = "",
    confirmed_lane_declaration_identity_sha256: str = "",
    plan_link_evaluated: bool = False,
    plan_linked: bool = False,
    plan_link: ApprovedChangeWindowsRuntimeReconcilePlanLink | None = None,
    plan_link_identity_sha256: str = "",
    plan_link_canonical_byte_length: int = 0,
    plan_link_validation: ApprovedChangePlanLinkValidationResult | None = None,
    filesystem_accessed: bool = False,
) -> ApprovedChangePlanLinkResult:
    return ApprovedChangePlanLinkResult(
        status=status,
        reason=reason,
        link_complete=link_complete,
        requested_approval_artifact_id=requested_approval_artifact_id,
        plan_validated=plan_validated,
        plan_validation_status=plan_validation_status,
        plan_mode=plan_mode,
        plan_recipe_id=plan_recipe_id,
        plan_sha256=plan_sha256,
        confirmed_plan_sha256=confirmed_plan_sha256,
        plan_identity_confirmed=plan_identity_confirmed,
        plan_status=plan_status,
        destination_parent_contract_version=destination_parent_contract_version,
        capability_support_evaluated=capability_support_evaluated,
        capability_supported=capability_supported,
        capability_binding_evaluated=capability_binding_evaluated,
        capability_bound=capability_bound,
        capability_binding_status=capability_binding_status,
        capability_binding_identity_sha256=capability_binding_identity_sha256,
        capability_id=capability_id,
        capability_catalog_identity_sha256=capability_catalog_identity_sha256,
        confirmed_capability_catalog_identity_sha256=(confirmed_capability_catalog_identity_sha256),
        lane_id=lane_id,
        lane_declaration_identity_sha256=lane_declaration_identity_sha256,
        confirmed_lane_declaration_identity_sha256=confirmed_lane_declaration_identity_sha256,
        plan_link_evaluated=plan_link_evaluated,
        plan_linked=plan_linked,
        plan_link=plan_link,
        plan_link_identity_sha256=plan_link_identity_sha256,
        plan_link_canonical_byte_length=plan_link_canonical_byte_length,
        plan_link_validation=plan_link_validation,
        errors=tuple(sorted(set(errors or ()))),
        filesystem_accessed=filesystem_accessed,
    )


def _confirmation_errors(value: Any, label: str) -> list[str]:
    """Reject anything that is not exactly 64 lowercase hexadecimal characters."""
    if not isinstance(value, str) or not value:
        return [f"{label} must be a non-empty string"]
    if len(value) != _SHA256_LENGTH or not set(value) <= _LOWERCASE_HEX:
        return [f"{label} must be exactly 64 lowercase hexadecimal characters"]
    return []


def _binding_gate_status(binding_result: ApprovedChangeCapabilityBindingResult) -> PlanLinkStatus:
    """Map a non-successful maintained PR322 status onto a PR323 status."""
    status = str(binding_result.status)
    if status == _BINDING_NOT_AVAILABLE_STATUS:
        return "capability_binding_not_available"
    if status == _BINDING_CATALOG_MISMATCH_STATUS:
        return "capability_catalog_confirmation_mismatch"
    if status == _BINDING_LANE_MISMATCH_STATUS:
        return "lane_declaration_confirmation_mismatch"
    if status == _BINDING_INVALID_INPUT_STATUS:
        return "invalid_plan_link_input"
    return "plan_link_blocked"


def link_persisted_approved_change_to_windows_runtime_reconcile_plan(
    approval_artifact_id: str,
    plan_packet: Mapping[str, Any],
    *,
    data_dir: Path | str,
    confirm_capability_catalog_identity_sha256: str,
    confirm_lane_declaration_identity_sha256: str,
    confirm_plan_sha256: str,
) -> ApprovedChangePlanLinkResult:
    """Link one exact approved binding to one exact validated saved plan.

    The operation accepts exactly six explicit inputs: one exact full PR319
    ``aca_`` approval-artifact ID, one explicitly supplied parsed plan mapping,
    one explicit ShellForgeAI ``data_dir``, one explicit raw 64-lowercase-hex
    PR321 catalog-identity confirmation, one explicit raw 64-lowercase-hex
    PR322 lane-declaration-identity confirmation, and one explicit raw
    64-lowercase-hex canonical plan-SHA confirmation.

    It accepts no inventory result, no selected inventory entry, no ``latest``,
    ``current``, or "most recent" reference, no caller-supplied artifact,
    contract, capability binding, or lane declaration, no plan-file path, no
    output path, no PR304 artifact path, no staged-source or durable-runtime
    root, no ``System32`` path, no authorization token, no preflight approval,
    no receipt ID, and no execution confirmation. The caller owns parsing a
    saved packet; PR323 evaluates the supplied mapping and never mutates it.

    All three confirmations are validated structurally and compared with
    ``hmac.compare_digest`` **before any filesystem access**. The plan-SHA
    confirmation means exactly one thing — *compare against this exact validated
    saved plan packet* — and is never authorization, preflight approval, or
    execution confirmation.
    """
    requested = approval_artifact_id if isinstance(approval_artifact_id, str) else ""

    # 1-3. The maintained PR305/PR313 plan validation and canonical plan
    #      identity. Pure, and reached before any filesystem access.
    plan_validation = validate_saved_windows_runtime_reconcile_plan_packet(plan_packet)
    plan_facts = dict(
        requested_approval_artifact_id=requested,
        plan_validation_status=str(plan_validation.status),
        plan_mode=plan_validation.plan_mode,
        plan_recipe_id=plan_validation.plan_recipe_id,
        plan_sha256=plan_validation.plan_sha256,
        plan_status=plan_validation.plan_status,
        destination_parent_contract_version=(plan_validation.destination_parent_contract_version),
    )
    if plan_validation.status == "invalid_plan_packet_input":
        return _result(
            "invalid_plan_link_input",
            reason=plan_validation.reason,
            errors=list(plan_validation.errors),
            **plan_facts,
        )
    if not plan_validation.plan_valid:
        return _result(
            "plan_not_accepted",
            reason=(
                "the supplied plan packet is not one maintained-validator-approved "
                "ready or no_change Windows runtime-reconcile plan"
            ),
            errors=list(plan_validation.errors),
            **plan_facts,
        )

    # 2 (restated as an explicit gate). Only ready or no_change may be linked.
    if plan_validation.plan_status not in ACCEPTED_PLAN_STATUSES:  # pragma: no cover - defensive
        return _result(
            "plan_not_accepted",
            reason="the supplied plan packet status is not ready or no_change",
            errors=["saved plan packet status is not ready or no_change"],
            plan_validated=True,
            **plan_facts,
        )

    validated = dict(plan_validated=True, **plan_facts)

    # 4. All three explicit confirmations, structurally, before any filesystem
    #    access and before the maintained PR322 operation is called at all.
    confirmation_errors = _confirmation_errors(confirm_plan_sha256, "confirm_plan_sha256")
    confirmation_errors.extend(
        _confirmation_errors(
            confirm_capability_catalog_identity_sha256,
            "confirm_capability_catalog_identity_sha256",
        )
    )
    confirmation_errors.extend(
        _confirmation_errors(
            confirm_lane_declaration_identity_sha256,
            "confirm_lane_declaration_identity_sha256",
        )
    )
    if confirmation_errors:
        return _result(
            "invalid_plan_link_input",
            reason="an explicit identity confirmation is not one raw 64-hex identity",
            errors=confirmation_errors,
            **validated,
        )

    # 5. The exact plan-SHA confirmation match.
    if not hmac.compare_digest(confirm_plan_sha256, plan_validation.plan_sha256):
        return _result(
            "plan_confirmation_mismatch",
            reason="the confirmation does not name the exact validated saved plan packet",
            errors=["confirm_plan_sha256 does not match the maintained canonical plan identity"],
            confirmed_plan_sha256=confirm_plan_sha256,
            **validated,
        )

    confirmed_plan = dict(
        confirmed_plan_sha256=confirm_plan_sha256,
        plan_identity_confirmed=True,
        **validated,
    )

    # 6. The current maintained catalog and lane identities, compared before any
    #    filesystem access. PR322 revalidates both; PR323 compares first so a
    #    stale confirmation can never reach the artifact subtree.
    catalog_identity = compute_approved_change_capability_support_catalog_sha256(
        maintained_approved_change_capability_support_catalog()
    )
    lane = maintained_windows_runtime_reconcile_lane_declaration()
    lane_identity = compute_capability_lane_declaration_sha256(lane)
    identities = dict(
        capability_catalog_identity_sha256=catalog_identity,
        lane_declaration_identity_sha256=lane_identity,
    )
    if not hmac.compare_digest(confirm_capability_catalog_identity_sha256, catalog_identity):
        return _result(
            "capability_catalog_confirmation_mismatch",
            reason="the confirmation does not name the exact maintained capability-support catalog",
            errors=[
                "confirm_capability_catalog_identity_sha256 does not match the maintained "
                "capability-support catalog identity"
            ],
            confirmed_capability_catalog_identity_sha256=(
                confirm_capability_catalog_identity_sha256
            ),
            **{**confirmed_plan, **identities},
        )
    if not hmac.compare_digest(confirm_lane_declaration_identity_sha256, lane_identity):
        return _result(
            "lane_declaration_confirmation_mismatch",
            reason="the confirmation does not name the exact maintained lane declaration",
            errors=[
                "confirm_lane_declaration_identity_sha256 does not match the maintained lane "
                "declaration identity"
            ],
            confirmed_capability_catalog_identity_sha256=(
                confirm_capability_catalog_identity_sha256
            ),
            confirmed_lane_declaration_identity_sha256=confirm_lane_declaration_identity_sha256,
            **{**confirmed_plan, **identities},
        )

    confirmed = dict(
        confirmed_capability_catalog_identity_sha256=confirm_capability_catalog_identity_sha256,
        confirmed_lane_declaration_identity_sha256=confirm_lane_declaration_identity_sha256,
        **{**confirmed_plan, **identities},
    )

    # 7. Exactly one maintained PR322 capability-binding construction. PR322
    #    owns the binding decision; PR323 never constructs a competing binding
    #    and never accepts one from a caller.
    binding_result = construct_persisted_approved_change_capability_binding(
        approval_artifact_id,
        data_dir=data_dir,
        confirm_capability_catalog_identity_sha256=confirm_capability_catalog_identity_sha256,
        confirm_lane_declaration_identity_sha256=confirm_lane_declaration_identity_sha256,
    )
    binding_status = str(binding_result.status)
    observed = dict(
        capability_binding_status=binding_status,
        capability_support_evaluated=bool(binding_result.capability_support_evaluated),
        capability_supported=bool(binding_result.capability_supported),
        capability_binding_evaluated=bool(binding_result.capability_binding_evaluated),
        capability_bound=bool(binding_result.capability_bound),
        capability_id=binding_result.capability_id,
        lane_id=binding_result.lane_id,
        capability_binding_identity_sha256=binding_result.binding_identity_sha256,
        filesystem_accessed=bool(binding_result.filesystem_accessed),
        **confirmed,
    )

    # 8. Only a complete, successful, fully bound PR322 result may be linked.
    if binding_status != REQUIRED_CAPABILITY_BINDING_STATUS:
        return _result(
            _binding_gate_status(binding_result),
            reason=str(binding_result.reason),
            errors=[
                "the maintained PR322 operation did not construct one complete capability "
                f"binding (status: {binding_status})"
            ],
            **observed,
        )

    binding = binding_result.binding
    if binding is None:
        return _result(
            "plan_link_blocked",
            reason="the maintained PR322 result carries no capability binding",
            errors=["the maintained PR322 result carries no capability binding"],
            **observed,
        )

    gate_errors: list[str] = []
    if not binding_result.binding_complete:
        gate_errors.append("the maintained PR322 binding did not complete")
    if binding_result.capability_supported is not True:
        gate_errors.append("the maintained PR322 result does not report capability support")
    if binding_result.capability_bound is not True:
        gate_errors.append("the maintained PR322 result does not report a bound capability")
    if binding_result.binding_created is not True:
        gate_errors.append("the maintained PR322 result did not create a binding")
    if binding_result.binding_persisted is not False:  # pragma: no cover - typed False
        gate_errors.append("the maintained PR322 binding must never be persisted")
    if binding_result.binding_validation is None or not (
        binding_result.binding_validation.binding_valid
    ):
        gate_errors.append("the maintained PR322 binding failed its own validation")
    if _sha256_field_errors(
        binding_result.binding_identity_sha256, "capability_binding_identity_sha256"
    ):
        gate_errors.append("the maintained PR322 binding identity is not one raw 64-hex identity")
    if gate_errors:
        return _result(
            "plan_link_blocked",
            reason="the maintained PR322 result did not satisfy every maintained binding gate",
            errors=gate_errors,
            **observed,
        )

    # 9. Exact structural agreement between the maintained binding facts and the
    #    maintained validated plan facts. Only typed identifiers are compared:
    #    no subject target text, procedure text, diagnosis text, desired-outcome
    #    text, risk wording, rollback prose, evidence reference, precondition, or
    #    live filesystem state is read or interpreted here or anywhere in PR323.
    mismatches: list[str] = []
    if binding.capability_id != plan_validation.plan_recipe_id:
        mismatches.append("the bound capability_id does not equal the validated plan recipe_id")
    if binding.capability_id != WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID:
        mismatches.append("the bound capability_id is not the exact supported capability")
    if binding.lane_id != WINDOWS_RUNTIME_RECONCILE_LANE_ID:
        mismatches.append("the bound lane_id is not the maintained Windows reconcile lane")
    if plan_validation.plan_mode != PLAN_MODE:
        mismatches.append("the validated plan mode is not windows_runtime_reconcile")
    if plan_validation.plan_recipe_id != RECIPE_ID:
        mismatches.append("the validated plan recipe_id is not windows.runtime_reconcile")
    if plan_validation.allowlist != ALLOWLIST:  # pragma: no cover - defensive
        mismatches.append("the validated plan does not carry the exact fixed two-file allowlist")
    if plan_validation.destination_parent_contract_version != PARENT_CONTRACT_VERSION:
        mismatches.append("the validated plan destination-parent contract version is not 1")
    if mismatches:
        return _result(
            "binding_plan_mismatch",
            reason="the exact binding and the exact validated plan do not agree structurally",
            errors=mismatches,
            plan_link_evaluated=True,
            **observed,
        )

    # 10-11. Exactly one in-memory plan link and its deterministic identity.
    link = ApprovedChangeWindowsRuntimeReconcilePlanLink(
        approval_artifact_id=binding.approval_artifact_id,
        approval_artifact_identity_sha256=binding.approval_artifact_identity_sha256,
        subject_sha256=binding.subject_sha256,
        capability_binding_identity_sha256=binding_result.binding_identity_sha256,
        capability_catalog_identity_sha256=binding.capability_catalog_identity_sha256,
        capability_id=binding.capability_id,
        lane_declaration_identity_sha256=binding.lane_declaration_identity_sha256,
        lane_id=binding.lane_id,
        plan_mode=plan_validation.plan_mode,
        plan_recipe_id=plan_validation.plan_recipe_id,
        plan_sha256=plan_validation.plan_sha256,
        plan_status=plan_validation.plan_status,
        destination_parent_contract_version=(plan_validation.destination_parent_contract_version),
    )

    # 12. The completed link, revalidated against every maintained input.
    link_validation = validate_approved_change_plan_link(
        link, binding=binding, plan_validation=plan_validation
    )
    reported = dict(
        plan_link_identity_sha256=link_validation.plan_link_identity_sha256,
        plan_link_canonical_byte_length=link_validation.canonical_byte_length,
        plan_link_validation=link_validation,
    )
    if not link_validation.link_valid:
        return _result(
            "plan_link_validation_failed",
            reason="the constructed plan link failed maintained PR323 validation",
            errors=["the constructed plan link failed maintained PR323 validation"],
            plan_link_evaluated=True,
            **{**observed, **reported},
        )

    # 13. One immutable result.
    return _result(
        "plan_link_constructed",
        reason=(
            "the exact approved binding identity is associated with the exact canonical "
            "identity of one maintained-validator-approved saved Windows reconcile plan"
        ),
        link_complete=True,
        plan_link_evaluated=True,
        plan_linked=True,
        plan_link=link,
        **{**observed, **reported},
    )
