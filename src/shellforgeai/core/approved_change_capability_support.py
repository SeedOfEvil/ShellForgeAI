"""Typed read-only approved-change capability-support declaration (PR321).

PR309 already validates one ``ApprovedChangeContract`` against a
*caller-supplied* collection of supported capability IDs. That is deliberately
inert: PR309 owns no catalog, so every caller has been free to invent its own
idea of what ShellForgeAI supports. This module closes exactly that gap and
nothing else.

It adds exactly two things:

* one immutable, canonical, product-maintained capability-support declaration
  catalog with a deterministic SHA-256 identity, declaring exactly one
  currently recognized approved-change capability — ``windows.runtime_reconcile``;
* one read-only evaluator that loads one exact persisted PR319 approval
  artifact by its exact full ``aca_`` ID and evaluates that artifact's approved
  ``ApprovedChangeContract`` against that exact maintained catalog through the
  maintained PR309 ``validate_approved_change_contract``.

**Declared capability support means only** that the approved subject's exact
``capability_id`` appears in the exact confirmed ShellForgeAI capability-support
catalog, and that PR309 validated the contract against that catalog.

It does **not** mean runtime compatibility, target compatibility, current-state
readiness, authorization, capability binding, PR313 eligibility, preflight
success, receipt availability, execution eligibility, or execution
availability. ``windows.runtime_reconcile`` is *not* bound to the PR313 lane
here: this declaration recognizes the exact capability ID for approved-change
contract validation only.

The catalog is source-maintained and stays in memory: it is never persisted,
published, inventoried, loaded from disk, discovered from plugins, derived from
``recipe_registry``, or assembled from a caller-supplied set. The evaluator
reaches the filesystem only indirectly, through the maintained PR319 exact-ID
loader; it never parses persisted approval JSON, never recomputes an artifact
identity, never loads a PR317 source bundle directly, never calls the PR319 or
PR317 publisher, and never accepts an arbitrary artifact path. It performs no
approval selection: there is no inventory call, and no ``latest``, ``current``,
or "most recent" resolution.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

from shellforgeai.core.approved_change_approval_persistence import (
    load_persisted_approved_change_approval_artifact,
)
from shellforgeai.core.approved_change_contract import (
    _CAPABILITY_RE,
    EXECUTION_STATUS_NOT_EXECUTED,
    ContractValidationResult,
    _is_wildcard,
    validate_approved_change_contract,
)

CAPABILITY_SUPPORT_SCHEMA_VERSION = "1"

#: The one fixed catalog type literal. There is no alias, no alternate
#: spelling, no caller-defined kind, and no second catalog.
CAPABILITY_SUPPORT_CATALOG_TYPE = "approved_change_capability_support_catalog"

#: The one support status a maintained declaration may carry today.
SUPPORT_STATUS_DECLARED_SUPPORTED = "declared_supported"

#: The one match rule. Support is exact, case-sensitive capability-ID equality
#: and nothing else: no prefix, suffix, namespace, alias, case folding, fuzzy
#: match, wildcard, caller-supplied regex, recipe-ID mapping, target inference,
#: or procedure inference.
MATCH_RULE_EXACT_CAPABILITY_ID_ONLY = "exact_capability_id_only"

#: The one validation scope a declaration authorizes.
VALIDATION_SCOPE_CONTRACT_VALIDATION_ONLY = "approved_change_contract_validation_only"

#: The exact — and today only — declared approved-change capability ID. It is a
#: product-maintained source constant, never discovered, never registered at
#: runtime, and never derived from the recipe registry or a PR313 script name.
WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID = "windows.runtime_reconcile"

#: The exact PR319 loader status that alone permits a capability evaluation.
REQUIRED_APPROVAL_ARTIFACT_LOAD_STATUS = "persisted_approval_artifact_loaded"

#: The exact PR309 validation statuses this evaluator classifies. Any other
#: status is an unexpected validator outcome and fails closed.
PR309_CONTRACT_VALID_STATUS = "contract_valid"
PR309_UNSUPPORTED_CAPABILITY_STATUS = "unsupported_capability"

#: The exact scope the explicit catalog-identity confirmation authorizes, and
#: nothing more. It is never approval confirmation, authorization, capability
#: binding, preflight confirmation, or execution confirmation.
CAPABILITY_CATALOG_CONFIRMATION_SCOPE = (
    "evaluate_this_approved_contract_against_this_exact_maintained_capability_support_catalog"
)

CATALOG_VALIDATION_STATUSES = (
    "capability_support_catalog_valid",
    "capability_support_catalog_invalid",
    "invalid_capability_support_catalog_input",
)
CatalogValidationStatus = Literal[
    "capability_support_catalog_valid",
    "capability_support_catalog_invalid",
    "invalid_capability_support_catalog_input",
]

EVALUATION_STATUSES = (
    "capability_support_confirmed",
    "capability_not_declared",
    "capability_support_evaluation_blocked",
    "invalid_capability_support_input",
    "capability_catalog_confirmation_mismatch",
    "approval_artifact_not_available",
    "approval_artifact_invalid",
    "capability_contract_validation_failed",
)
EvaluationStatus = Literal[
    "capability_support_confirmed",
    "capability_not_declared",
    "capability_support_evaluation_blocked",
    "invalid_capability_support_input",
    "capability_catalog_confirmation_mismatch",
    "approval_artifact_not_available",
    "approval_artifact_invalid",
    "capability_contract_validation_failed",
]

#: Warnings every PR321 result carries, whatever its status. They state exactly
#: what a declaration does and does not mean, so no automated consumer can read
#: declared support as binding, authorization, readiness, or execution.
PERMANENT_CAPABILITY_SUPPORT_WARNINGS: tuple[str, ...] = (
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
)

_SHA256_LENGTH = 64
_LOWERCASE_HEX = frozenset("0123456789abcdef")

#: The maintained PR319 loader statuses this module classifies explicitly. Any
#: other status is unexpected and blocks rather than being interpreted.
_LOADER_NOT_FOUND_STATUSES = frozenset(
    {"persisted_approval_artifact_not_found", "unsafe_approval_persistence_root"}
)
_LOADER_INVALID_STATUS = "persisted_approval_artifact_invalid"
_LOADER_INVALID_REFERENCE_STATUS = "invalid_approval_artifact_reference"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# The typed capability-support declaration and the maintained catalog
# ---------------------------------------------------------------------------


class ApprovedChangeCapabilitySupportDeclaration(_FrozenModel):
    """One immutable statement that one exact capability ID is recognized.

    The declaration carries exactly the semantics required to state support
    without implying anything further. The five availability fields exist so a
    declaration can never be silently read as more than it is; the maintained
    catalog validator requires every one of them to be ``false``, so no
    declaration in this repository can assert binding, authorization,
    preflight, receipt linkage, or execution availability today.
    """

    schema_version: Literal["1"] = CAPABILITY_SUPPORT_SCHEMA_VERSION
    capability_id: str
    support_status: Literal["declared_supported"] = SUPPORT_STATUS_DECLARED_SUPPORTED
    match_rule: Literal["exact_capability_id_only"] = MATCH_RULE_EXACT_CAPABILITY_ID_ONLY
    validation_scope: Literal["approved_change_contract_validation_only"] = (
        VALIDATION_SCOPE_CONTRACT_VALIDATION_ONLY
    )
    capability_binding_available: bool = False
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


class ApprovedChangeCapabilitySupportCatalog(_FrozenModel):
    """The immutable capability-support catalog. It has no host path or ID.

    The catalog is source-maintained and in-memory only. It is never persisted,
    published, inventoried, cached, loaded from disk, extended at runtime, or
    assembled from caller input; its only identity is the deterministic SHA-256
    of its own canonical bytes.
    """

    schema_version: Literal["1"] = CAPABILITY_SUPPORT_SCHEMA_VERSION
    catalog_type: Literal["approved_change_capability_support_catalog"] = (
        CAPABILITY_SUPPORT_CATALOG_TYPE
    )
    declarations: tuple[ApprovedChangeCapabilitySupportDeclaration, ...]


#: The one maintained catalog. Exactly one declaration, exactly one capability.
_MAINTAINED_CATALOG = ApprovedChangeCapabilitySupportCatalog(
    declarations=(
        ApprovedChangeCapabilitySupportDeclaration(
            capability_id=WINDOWS_RUNTIME_RECONCILE_CAPABILITY_ID,
        ),
    ),
)


def maintained_approved_change_capability_support_catalog() -> (
    ApprovedChangeCapabilitySupportCatalog
):
    """Return the exact immutable capability-support catalog defined in source.

    This reads no file, reads no environment variable, inspects no installed
    recipe, inspects no OS, host, or platform, reads no credential, calls no
    network service, loads no plugin, and discovers no adapter. The returned
    object is frozen and holds only immutable members, so the single maintained
    instance is safe to hand back to every caller.
    """
    return _MAINTAINED_CATALOG


# ---------------------------------------------------------------------------
# Canonicalization and deterministic catalog identity
# ---------------------------------------------------------------------------


def canonical_approved_change_capability_support_catalog_payload(
    catalog: ApprovedChangeCapabilitySupportCatalog | dict[str, Any],
) -> dict[str, Any]:
    """Return the canonical capability-support catalog payload.

    Declaration mappings are sorted by key, declarations are sorted
    lexicographically by exact ``capability_id``, and nothing derived is ever
    part of the payload, so the catalog identity can never hash itself. No
    timestamp, environment value, host value, platform value, or randomness
    enters the payload.
    """
    if not isinstance(catalog, ApprovedChangeCapabilitySupportCatalog):
        catalog = ApprovedChangeCapabilitySupportCatalog.model_validate(catalog)
    declarations = [
        {key: declaration[key] for key in sorted(declaration)}
        for declaration in sorted(
            (item.model_dump(mode="python") for item in catalog.declarations),
            key=lambda item: item["capability_id"],
        )
    ]
    return {
        "catalog_type": catalog.catalog_type,
        "declarations": declarations,
        "schema_version": catalog.schema_version,
    }


def canonical_approved_change_capability_support_catalog_json(
    catalog: ApprovedChangeCapabilitySupportCatalog | dict[str, Any],
) -> str:
    """Return deterministic canonical capability-support catalog JSON.

    Mapping keys are sorted, separators are compact, ``ensure_ascii`` is off so
    Unicode is preserved exactly, and there is no BOM and no trailing newline.
    """
    return json.dumps(
        canonical_approved_change_capability_support_catalog_payload(catalog),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_approved_change_capability_support_catalog_sha256(
    catalog: ApprovedChangeCapabilitySupportCatalog | dict[str, Any],
) -> str:
    """Compute the full, untruncated catalog identity SHA-256.

    This identity is permanently distinct from the PR309 subject identity, the
    PR314 supplemental-context identity, the PR315 construction-evidence
    identity, the PR316 bundle identity, the PR319 approval-artifact identity,
    and any legacy ``Proposal`` fingerprint. It is never approval, capability
    binding, authorization, or execution confirmation, and it is never
    persisted or prefixed into a durable ID.
    """
    return hashlib.sha256(
        canonical_approved_change_capability_support_catalog_json(catalog).encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------------
# Structured results
# ---------------------------------------------------------------------------


class ApprovedChangeCapabilitySupportCatalogValidationResult(_FrozenModel):
    """Structured, non-throwing capability-support catalog validation result.

    Validation is pure and inert: it recanonicalizes the catalog, recomputes
    the catalog identity, and touches nothing at all.
    """

    schema_version: Literal["1"] = CAPABILITY_SUPPORT_SCHEMA_VERSION
    status: CatalogValidationStatus
    reason: str = ""
    catalog_valid: bool
    catalog_type: str = ""
    declaration_count: int = 0
    capability_ids: tuple[str, ...] = ()
    catalog_identity_sha256: str = ""
    canonical_byte_length: int = 0
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_CAPABILITY_SUPPORT_WARNINGS

    # Accurate safety ledger. Catalog validation reaches nothing.
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    filesystem_accessed: Literal[False] = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    capability_support_evaluated: Literal[False] = False
    capability_supported: Literal[False] = False
    capability_bound: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


class ApprovedChangeCapabilitySupportEvaluationResult(_FrozenModel):
    """Structured, non-throwing read-only capability-support evaluation result.

    ``evaluation_complete`` is the only field that states whether the exact
    capability question was actually answered. ``capability_supported=true``
    means exactly one thing: the loaded approved subject's exact
    ``capability_id`` is declared in the confirmed maintained catalog, and PR309
    returned ``contract_valid`` against exactly that catalog's capability IDs.
    """

    schema_version: Literal["1"] = CAPABILITY_SUPPORT_SCHEMA_VERSION
    status: EvaluationStatus
    reason: str = ""
    evaluation_complete: bool = False
    requested_approval_artifact_id: str = ""
    loaded_approval_artifact_id: str = ""
    approval_artifact_load_status: str = ""
    approval_artifact_loaded: bool = False
    approval_artifact_valid: bool = False
    approval_binding_valid: bool = False
    capability_id: str = ""
    catalog_identity_sha256: str = ""
    confirmed_catalog_identity_sha256: str = ""
    catalog_valid: bool = False
    supported_capability_ids: tuple[str, ...] = ()
    declaration_found: bool = False
    declaration: ApprovedChangeCapabilitySupportDeclaration | None = None
    contract_validation: ContractValidationResult | None = None
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_CAPABILITY_SUPPORT_WARNINGS

    # Accurate safety ledger. Evaluation reads and reports; it changes nothing.
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
    capability_bound: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


# ---------------------------------------------------------------------------
# Catalog validation
# ---------------------------------------------------------------------------


def _catalog_validation_result(
    status: CatalogValidationStatus,
    *,
    reason: str = "",
    errors: list[str] | None = None,
    catalog_type: str = "",
    declaration_count: int = 0,
    capability_ids: tuple[str, ...] = (),
    catalog_identity_sha256: str = "",
    canonical_byte_length: int = 0,
) -> ApprovedChangeCapabilitySupportCatalogValidationResult:
    return ApprovedChangeCapabilitySupportCatalogValidationResult(
        status=status,
        reason=reason,
        catalog_valid=status == "capability_support_catalog_valid",
        catalog_type=catalog_type,
        declaration_count=declaration_count,
        capability_ids=capability_ids,
        catalog_identity_sha256=catalog_identity_sha256,
        canonical_byte_length=canonical_byte_length,
        errors=tuple(sorted(set(errors or ()))),
    )


def _declaration_availability_errors(
    declaration: ApprovedChangeCapabilitySupportDeclaration,
) -> list[str]:
    """Require every availability field to be false on every declaration."""
    errors: list[str] = []
    for field in (
        "capability_binding_available",
        "authorization_available",
        "preflight_available",
        "receipt_linkage_available",
        "execution_available",
    ):
        if getattr(declaration, field) is not False:
            errors.append(
                f"declaration {declaration.capability_id}: {field} must be false — PR321 declares "
                "contract-validation support only"
            )
    return errors


def validate_approved_change_capability_support_catalog(
    catalog: ApprovedChangeCapabilitySupportCatalog | dict[str, Any],
) -> ApprovedChangeCapabilitySupportCatalogValidationResult:
    """Validate one capability-support catalog. Pure, inert, non-throwing.

    A valid catalog carries the exact schema version, the exact catalog type,
    at least one declaration, unique exact capability IDs in valid PR309
    syntax with no wildcard, the exact declaration enums, every availability
    field false, a deterministic canonical payload, and a deterministic
    identity.
    """
    if catalog is None or isinstance(catalog, (str, bytes, int, float, bool, list, tuple)):
        return _catalog_validation_result(
            "invalid_capability_support_catalog_input",
            reason="a capability-support catalog must be the maintained model or a mapping",
            errors=["capability-support catalog must be the maintained model or a mapping"],
        )
    if not isinstance(catalog, (ApprovedChangeCapabilitySupportCatalog, dict)):
        return _catalog_validation_result(
            "invalid_capability_support_catalog_input",
            reason="a capability-support catalog must be the maintained model or a mapping",
            errors=["capability-support catalog must be the maintained model or a mapping"],
        )
    if not isinstance(catalog, ApprovedChangeCapabilitySupportCatalog):
        try:
            catalog = ApprovedChangeCapabilitySupportCatalog.model_validate(catalog)
        except Exception as exc:  # pydantic exposes many structured subclasses.
            return _catalog_validation_result(
                "capability_support_catalog_invalid",
                reason="the capability-support catalog payload is not one maintained catalog",
                errors=[str(exc)],
            )

    errors: list[str] = []
    if catalog.schema_version != CAPABILITY_SUPPORT_SCHEMA_VERSION:
        errors.append(f"catalog schema_version must be {CAPABILITY_SUPPORT_SCHEMA_VERSION!r}")
    if catalog.catalog_type != CAPABILITY_SUPPORT_CATALOG_TYPE:
        errors.append(f"catalog_type must be {CAPABILITY_SUPPORT_CATALOG_TYPE!r}")
    if not catalog.declarations:
        errors.append("the capability-support catalog must hold at least one declaration")

    capability_ids = tuple(item.capability_id for item in catalog.declarations)
    for duplicate in sorted({item for item in capability_ids if capability_ids.count(item) > 1}):
        errors.append(f"duplicate declared capability_id: {duplicate}")
    for declaration in catalog.declarations:
        capability_id = declaration.capability_id
        if _is_wildcard(capability_id) or not _CAPABILITY_RE.fullmatch(capability_id):
            errors.append(f"invalid declared capability_id: {capability_id}")
        if declaration.schema_version != CAPABILITY_SUPPORT_SCHEMA_VERSION:
            errors.append(f"declaration {capability_id}: schema_version must be '1'")
        if declaration.support_status != SUPPORT_STATUS_DECLARED_SUPPORTED:
            errors.append(
                f"declaration {capability_id}: support_status must be "
                f"{SUPPORT_STATUS_DECLARED_SUPPORTED!r}"
            )
        if declaration.match_rule != MATCH_RULE_EXACT_CAPABILITY_ID_ONLY:
            errors.append(
                f"declaration {capability_id}: match_rule must be "
                f"{MATCH_RULE_EXACT_CAPABILITY_ID_ONLY!r}"
            )
        if declaration.validation_scope != VALIDATION_SCOPE_CONTRACT_VALIDATION_ONLY:
            errors.append(
                f"declaration {capability_id}: validation_scope must be "
                f"{VALIDATION_SCOPE_CONTRACT_VALIDATION_ONLY!r}"
            )
        errors.extend(_declaration_availability_errors(declaration))

    try:
        canonical = canonical_approved_change_capability_support_catalog_json(catalog)
        recanonical = canonical_approved_change_capability_support_catalog_json(catalog)
    except Exception as exc:  # pragma: no cover - defensive, canonicalization is total.
        return _catalog_validation_result(
            "capability_support_catalog_invalid",
            reason="the capability-support catalog does not canonicalize deterministically",
            errors=[*errors, str(exc)],
            catalog_type=catalog.catalog_type,
            declaration_count=len(catalog.declarations),
            capability_ids=tuple(sorted(capability_ids)),
        )
    if canonical != recanonical:  # pragma: no cover - defensive determinism guard.
        errors.append("the capability-support catalog canonical payload is not deterministic")
    encoded = canonical.encode("utf-8")
    identity = hashlib.sha256(encoded).hexdigest()
    if not hmac.compare_digest(
        identity, compute_approved_change_capability_support_catalog_sha256(catalog)
    ):  # pragma: no cover - defensive determinism guard.
        errors.append("the capability-support catalog identity is not deterministic")

    reported = dict(
        catalog_type=catalog.catalog_type,
        declaration_count=len(catalog.declarations),
        capability_ids=tuple(sorted(capability_ids)),
        catalog_identity_sha256=identity,
        canonical_byte_length=len(encoded),
    )
    if errors:
        return _catalog_validation_result(
            "capability_support_catalog_invalid",
            reason="the capability-support catalog failed maintained PR321 validation",
            errors=errors,
            **reported,
        )
    return _catalog_validation_result(
        "capability_support_catalog_valid",
        reason="the capability-support catalog is one exact maintained declaration catalog",
        **reported,
    )


# ---------------------------------------------------------------------------
# The one public read-only evaluation operation
# ---------------------------------------------------------------------------


def _evaluation_result(
    status: EvaluationStatus,
    *,
    reason: str = "",
    errors: list[str] | None = None,
    evaluation_complete: bool = False,
    requested_approval_artifact_id: str = "",
    loaded_approval_artifact_id: str = "",
    approval_artifact_load_status: str = "",
    approval_artifact_loaded: bool = False,
    approval_artifact_valid: bool = False,
    approval_binding_valid: bool = False,
    capability_id: str = "",
    catalog_identity_sha256: str = "",
    confirmed_catalog_identity_sha256: str = "",
    catalog_valid: bool = False,
    supported_capability_ids: tuple[str, ...] = (),
    declaration_found: bool = False,
    declaration: ApprovedChangeCapabilitySupportDeclaration | None = None,
    contract_validation: ContractValidationResult | None = None,
    filesystem_accessed: bool = False,
    capability_support_evaluated: bool = False,
    capability_supported: bool = False,
) -> ApprovedChangeCapabilitySupportEvaluationResult:
    return ApprovedChangeCapabilitySupportEvaluationResult(
        status=status,
        reason=reason,
        evaluation_complete=evaluation_complete,
        requested_approval_artifact_id=requested_approval_artifact_id,
        loaded_approval_artifact_id=loaded_approval_artifact_id,
        approval_artifact_load_status=approval_artifact_load_status,
        approval_artifact_loaded=approval_artifact_loaded,
        approval_artifact_valid=approval_artifact_valid,
        approval_binding_valid=approval_binding_valid,
        capability_id=capability_id,
        catalog_identity_sha256=catalog_identity_sha256,
        confirmed_catalog_identity_sha256=confirmed_catalog_identity_sha256,
        catalog_valid=catalog_valid,
        supported_capability_ids=supported_capability_ids,
        declaration_found=declaration_found,
        declaration=declaration,
        contract_validation=contract_validation,
        errors=tuple(sorted(set(errors or ()))),
        filesystem_accessed=filesystem_accessed,
        capability_support_evaluated=capability_support_evaluated,
        capability_supported=capability_supported,
    )


def _catalog_confirmation_errors(value: Any) -> list[str]:
    """Reject anything that is not exactly 64 lowercase hexadecimal characters."""
    if not isinstance(value, str) or not value:
        return ["confirm_capability_catalog_identity_sha256 must be a non-empty string"]
    if len(value) != _SHA256_LENGTH or not set(value) <= _LOWERCASE_HEX:
        return [
            "confirm_capability_catalog_identity_sha256 must be exactly 64 lowercase hexadecimal "
            "characters"
        ]
    return []


def _supported_capability_ids(
    catalog: ApprovedChangeCapabilitySupportCatalog,
) -> tuple[str, ...]:
    """Return the exact declared capability IDs, sorted, with no widening."""
    return tuple(sorted(item.capability_id for item in catalog.declarations))


def _declaration_for(
    catalog: ApprovedChangeCapabilitySupportCatalog, capability_id: str
) -> ApprovedChangeCapabilitySupportDeclaration | None:
    """Return the declaration whose capability ID is exactly equal, or ``None``."""
    for declaration in catalog.declarations:
        if declaration.capability_id == capability_id:
            return declaration
    return None


def evaluate_persisted_approved_change_capability_support(
    approval_artifact_id: str,
    *,
    data_dir: Path | str,
    confirm_capability_catalog_identity_sha256: str,
) -> ApprovedChangeCapabilitySupportEvaluationResult:
    """Evaluate one exact persisted approval against the maintained catalog.

    The operation accepts exactly three explicit inputs: one exact full PR319
    ``aca_`` approval-artifact ID, one explicit ShellForgeAI ``data_dir``, and
    one explicit raw 64-lowercase-hex maintained-catalog identity confirmation.

    It accepts no inventory result, no selected inventory entry, no ``latest``,
    ``current``, or "most recent" reference, no caller-supplied supported-ID
    collection, declaration, catalog, contract, approval, or artifact object,
    no capability alias, no recipe ID, no PR313 plan, no preflight, no receipt,
    and no execution confirmation.

    The catalog confirmation authorizes exactly one thing — *evaluate against
    this exact maintained declaration catalog* — and is validated before any
    filesystem access whatsoever. A malformed or mismatched confirmation loads
    nothing, touches no filesystem object, evaluates no capability, and returns
    a structured fail-closed result.
    """
    # 1-3. The maintained source catalog, validated, with its canonical identity.
    catalog = maintained_approved_change_capability_support_catalog()
    catalog_validation = validate_approved_change_capability_support_catalog(catalog)
    catalog_identity = catalog_validation.catalog_identity_sha256
    if not catalog_validation.catalog_valid:  # pragma: no cover - maintained catalog is valid.
        return _evaluation_result(
            "capability_support_evaluation_blocked",
            reason="the maintained capability-support catalog failed its own validation",
            errors=["the maintained capability-support catalog failed maintained PR321 validation"],
            requested_approval_artifact_id=(
                approval_artifact_id if isinstance(approval_artifact_id, str) else ""
            ),
            catalog_identity_sha256=catalog_identity,
        )

    # 4-5. The explicit catalog-identity confirmation, before any filesystem access.
    confirmation_errors = _catalog_confirmation_errors(confirm_capability_catalog_identity_sha256)
    if confirmation_errors:
        return _evaluation_result(
            "invalid_capability_support_input",
            reason="the capability-catalog identity confirmation is not one raw 64-hex identity",
            errors=confirmation_errors,
            requested_approval_artifact_id=(
                approval_artifact_id if isinstance(approval_artifact_id, str) else ""
            ),
            catalog_identity_sha256=catalog_identity,
            catalog_valid=True,
        )
    if not hmac.compare_digest(confirm_capability_catalog_identity_sha256, catalog_identity):
        return _evaluation_result(
            "capability_catalog_confirmation_mismatch",
            reason="the confirmation does not name the exact maintained capability-support catalog",
            errors=[
                "confirm_capability_catalog_identity_sha256 does not match the maintained "
                "capability-support catalog identity"
            ],
            requested_approval_artifact_id=(
                approval_artifact_id if isinstance(approval_artifact_id, str) else ""
            ),
            catalog_identity_sha256=catalog_identity,
            confirmed_catalog_identity_sha256=confirm_capability_catalog_identity_sha256,
            catalog_valid=True,
        )

    requested = approval_artifact_id if isinstance(approval_artifact_id, str) else ""
    confirmed = dict(
        requested_approval_artifact_id=requested,
        catalog_identity_sha256=catalog_identity,
        confirmed_catalog_identity_sha256=confirm_capability_catalog_identity_sha256,
        catalog_valid=True,
    )

    # 6. Exactly one maintained PR319 exact-ID load. This is the only path to
    #    the filesystem, and PR321 owns no parser, loader, or identity rule.
    load_result = load_persisted_approved_change_approval_artifact(
        approval_artifact_id, data_dir=data_dir
    )
    load_status = str(load_result.status)
    # Only the maintained loader's fixed status and fixed reason sentence are
    # reported. Its ``errors`` may interpolate host paths, so they are never
    # propagated: PR321 emits its own deterministic, path-free sentences.
    accessed = bool(load_result.filesystem_accessed)

    # 7. Require a fully successful, fully revalidated load.
    if load_status != REQUIRED_APPROVAL_ARTIFACT_LOAD_STATUS:
        if load_status == _LOADER_INVALID_REFERENCE_STATUS:
            status: EvaluationStatus = "invalid_capability_support_input"
        elif load_status in _LOADER_NOT_FOUND_STATUSES:
            status = "approval_artifact_not_available"
        elif load_status == _LOADER_INVALID_STATUS:
            status = "approval_artifact_invalid"
        else:
            status = "capability_support_evaluation_blocked"
        return _evaluation_result(
            status,
            reason=str(load_result.reason),
            errors=[
                "the maintained PR319 exact-ID loader did not return one fully revalidated "
                f"approval artifact (status: {load_status})"
            ],
            approval_artifact_load_status=load_status,
            filesystem_accessed=accessed,
            **confirmed,
        )

    artifact = load_result.artifact
    validation = load_result.artifact_validation
    gate_errors: list[str] = []
    if artifact is None:
        gate_errors.append("the maintained PR319 loader returned no approval artifact")
    if validation is None or not validation.artifact_valid:
        gate_errors.append("the persisted approval artifact is not maintained-valid")
    if not load_result.approval_binding_valid:
        gate_errors.append("the persisted PR309 approval binding is not valid")
    if not load_result.source_bundle_revalidated:
        gate_errors.append("the exact PR317 source-bundle provenance was not revalidated")
    if gate_errors or artifact is None:
        return _evaluation_result(
            "capability_support_evaluation_blocked",
            reason="the loaded approval artifact did not satisfy every maintained PR319 gate",
            errors=gate_errors,
            loaded_approval_artifact_id=load_result.approval_artifact_id,
            approval_artifact_load_status=load_status,
            approval_artifact_loaded=True,
            approval_artifact_valid=bool(validation is not None and validation.artifact_valid),
            approval_binding_valid=bool(load_result.approval_binding_valid),
            filesystem_accessed=accessed,
            **confirmed,
        )

    # 8. The exact approved contract, taken only from the loaded PR319 artifact.
    contract = artifact.contract
    capability_id = contract.subject.capability_id
    loaded = dict(
        loaded_approval_artifact_id=artifact.approval_artifact_id,
        approval_artifact_load_status=load_status,
        approval_artifact_loaded=True,
        approval_artifact_valid=True,
        approval_binding_valid=True,
        capability_id=capability_id,
        filesystem_accessed=accessed,
        **confirmed,
    )

    # 9-10. The exact supported tuple, decided by the maintained PR309 validator.
    supported = _supported_capability_ids(catalog)
    contract_validation = validate_approved_change_contract(contract, supported)

    # 11. The validator's approval-binding result must remain valid.
    if not contract_validation.approval_binding_valid:
        return _evaluation_result(
            "capability_contract_validation_failed",
            reason="the maintained PR309 validator no longer accepts the approval binding",
            errors=["PR309 reported the approved contract's approval binding as invalid"],
            supported_capability_ids=supported,
            contract_validation=contract_validation,
            **{**loaded, "approval_binding_valid": False},
        )

    # 12. Classify strictly from the maintained PR309 status.
    if contract_validation.status == PR309_CONTRACT_VALID_STATUS:
        declaration = _declaration_for(catalog, capability_id)
        # PR309 and the maintained catalog disagreeing is not a decision PR321
        # may resolve on its own, so it blocks rather than reporting support
        # without an exact declaration.
        if declaration is None:
            return _evaluation_result(
                "capability_support_evaluation_blocked",
                reason="PR309 accepted a capability the maintained catalog does not declare",
                errors=["the maintained catalog holds no declaration for the validated capability"],
                supported_capability_ids=supported,
                contract_validation=contract_validation,
                **loaded,
            )
        return _evaluation_result(
            "capability_support_confirmed",
            reason=(
                "the approved subject's exact capability_id is declared supported for "
                "approved-change contract validation only"
            ),
            evaluation_complete=True,
            supported_capability_ids=supported,
            declaration_found=True,
            declaration=declaration,
            contract_validation=contract_validation,
            capability_support_evaluated=True,
            capability_supported=True,
            **loaded,
        )
    if contract_validation.status == PR309_UNSUPPORTED_CAPABILITY_STATUS:
        return _evaluation_result(
            "capability_not_declared",
            reason=(
                "the approved subject's exact capability_id is not declared in the maintained "
                "capability-support catalog"
            ),
            evaluation_complete=True,
            errors=[f"undeclared capability_id: {capability_id}"],
            supported_capability_ids=supported,
            contract_validation=contract_validation,
            capability_support_evaluated=True,
            **loaded,
        )

    # 13. Any other maintained PR309 status fails closed.
    return _evaluation_result(
        "capability_contract_validation_failed",
        reason="the maintained PR309 validator returned neither support nor non-support",
        errors=[
            f"PR309 returned an unexpected contract-validation status: {contract_validation.status}"
        ],
        supported_capability_ids=supported,
        contract_validation=contract_validation,
        **loaded,
    )
