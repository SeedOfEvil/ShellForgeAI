"""Immutable approved-change contract domain types (PR309).

This module is intentionally pure and inert. It defines approval-bound data,
canonical subject identity, and read-only validation only; it performs no I/O,
execution, persistence, registry lookup, or runtime integration.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

SCHEMA_VERSION = "1"
APPROVAL_SCOPE_EXACT_SUBJECT_ONLY = "exact_subject_only"
EXECUTION_STATUS_NOT_EXECUTED = "not_executed"
RISK_VALUES = ("low", "medium", "high")
VALIDATION_STATUSES = (
    "contract_valid",
    "contract_invalid",
    "approval_mismatch",
    "unsupported_capability",
    "invalid_validation_input",
)
_WILDCARDS = {"*", "all", "any"}
_CAPABILITY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _clean_text(value: str) -> str:
    return " ".join(value.strip().split())


def _is_wildcard(value: str) -> bool:
    return value.casefold() in _WILDCARDS


def _require_text(value: str) -> str:
    value = _clean_text(value)
    if not value:
        raise ValueError("must be non-empty")
    if _is_wildcard(value):
        raise ValueError("wildcard values are not allowed")
    return value


def _require_text_tuple(value: tuple[str, ...]) -> tuple[str, ...]:
    out = tuple(_require_text(item) for item in value)
    if not out:
        raise ValueError("must contain at least one entry")
    return out


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value


def _canonical_datetime(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc)
    timespec = "microseconds" if normalized.microsecond else "seconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class TargetIdentityClaim(_FrozenModel):
    key: str
    value: str

    @field_validator("key", "value")
    @classmethod
    def _validate_text(cls, value: str) -> str:
        return _require_text(value)


class ApprovedChangeTarget(_FrozenModel):
    kind: str
    name: str
    identity_claims: tuple[TargetIdentityClaim, ...]

    @field_validator("kind", "name")
    @classmethod
    def _validate_text(cls, value: str) -> str:
        return _require_text(value)

    @model_validator(mode="after")
    def _validate_identity_claims(self) -> ApprovedChangeTarget:
        if not self.identity_claims:
            raise ValueError("target must include at least one identity claim")
        keys = [claim.key for claim in self.identity_claims]
        if len(keys) != len(set(keys)):
            raise ValueError("target identity claim keys must be unique")
        return self


class EvidenceReference(_FrozenModel):
    reference_id: str
    source: str
    sha256: str
    observed_at: datetime

    @field_validator("reference_id", "source")
    @classmethod
    def _validate_text(cls, value: str) -> str:
        return _require_text(value)

    @field_validator("sha256")
    @classmethod
    def _validate_sha(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
        return value

    @field_validator("observed_at")
    @classmethod
    def _validate_observed_at(cls, value: datetime) -> datetime:
        return _require_aware(value)


class ProcedureStep(_FrozenModel):
    step_id: str
    description: str
    expected_effect: str

    @field_validator("step_id", "description", "expected_effect")
    @classmethod
    def _validate_text(cls, value: str) -> str:
        return _require_text(value)


class RollbackPosture(_FrozenModel):
    reversible: bool
    summary: str
    procedure: tuple[ProcedureStep, ...] = ()
    limitations: tuple[str, ...]

    @field_validator("summary")
    @classmethod
    def _validate_summary(cls, value: str) -> str:
        return _require_text(value)

    @field_validator("limitations")
    @classmethod
    def _validate_limitations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_text_tuple(value)

    @model_validator(mode="after")
    def _validate_recovery_posture(self) -> RollbackPosture:
        if not self.procedure and not self.limitations:
            raise ValueError("rollback posture needs procedure or explicit limitation")
        _validate_unique_steps(self.procedure, "rollback procedure")
        return self


class ApprovedChangeSubject(_FrozenModel):
    schema_version: Literal["1"] = SCHEMA_VERSION
    source_proposal_reference: str
    capability_id: str
    target: ApprovedChangeTarget
    desired_outcome: str
    diagnosis_summary: str
    risk: Literal["low", "medium", "high"]
    evidence_references: tuple[EvidenceReference, ...]
    change_summary: str
    impact: str
    blast_radius: str
    procedure: tuple[ProcedureStep, ...]
    preconditions: tuple[str, ...]
    revalidation_requirements: tuple[str, ...]
    verification_criteria: tuple[str, ...]
    rollback_posture: RollbackPosture
    audit_requirements: tuple[str, ...]
    unsupported_or_irreversible_aspects: tuple[str, ...]

    @field_validator(
        "source_proposal_reference",
        "desired_outcome",
        "diagnosis_summary",
        "change_summary",
        "impact",
        "blast_radius",
    )
    @classmethod
    def _validate_text(cls, value: str) -> str:
        return _require_text(value)

    @field_validator(
        "preconditions",
        "revalidation_requirements",
        "verification_criteria",
        "audit_requirements",
        "unsupported_or_irreversible_aspects",
    )
    @classmethod
    def _validate_text_tuple(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_text_tuple(value)

    @field_validator("capability_id")
    @classmethod
    def _validate_capability_id(cls, value: str) -> str:
        value = _require_text(value)
        if _is_wildcard(value) or not _CAPABILITY_RE.fullmatch(value):
            raise ValueError("capability_id must be a bounded exact identifier")
        return value

    @model_validator(mode="after")
    def _validate_collections(self) -> ApprovedChangeSubject:
        if not self.evidence_references:
            raise ValueError("at least one evidence reference is required")
        refs = [ref.reference_id for ref in self.evidence_references]
        if len(refs) != len(set(refs)):
            raise ValueError("evidence reference IDs must be unique")
        if not self.procedure:
            raise ValueError("at least one procedure step is required")
        _validate_unique_steps(self.procedure, "procedure")
        return self


class ApprovalAttestation(_FrozenModel):
    schema_version: Literal["1"] = SCHEMA_VERSION
    approved_by: str
    approved_at: datetime
    reason: str
    subject_sha256: str
    scope: Literal["exact_subject_only"] = APPROVAL_SCOPE_EXACT_SUBJECT_ONLY

    @field_validator("approved_by", "reason")
    @classmethod
    def _validate_text(cls, value: str) -> str:
        return _require_text(value)

    @field_validator("approved_at")
    @classmethod
    def _validate_approved_at(cls, value: datetime) -> datetime:
        return _require_aware(value)

    @field_validator("subject_sha256")
    @classmethod
    def _validate_sha(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("subject_sha256 must be 64 lowercase hexadecimal characters")
        return value


class ApprovedChangeContract(_FrozenModel):
    schema_version: Literal["1"] = SCHEMA_VERSION
    subject: ApprovedChangeSubject
    approval: ApprovalAttestation


class ContractValidationResult(_FrozenModel):
    status: Literal[
        "contract_valid",
        "contract_invalid",
        "approval_mismatch",
        "unsupported_capability",
        "invalid_validation_input",
    ]
    contract_valid: bool
    approval_binding_valid: bool
    capability_supported: bool
    computed_subject_sha256: str
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


def _validate_unique_steps(steps: tuple[ProcedureStep, ...], label: str) -> None:
    ids = [step.step_id for step in steps]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{label} step IDs must be unique")


def _canonicalize(value: Any) -> Any:
    if isinstance(value, datetime):
        return _canonical_datetime(value)
    if isinstance(value, BaseModel):
        return _canonicalize(value.model_dump(mode="python"))
    if isinstance(value, dict):
        return {key: _canonicalize(value[key]) for key in sorted(value)}
    if isinstance(value, (tuple, list)):
        return [_canonicalize(item) for item in value]
    return value


def canonical_subject_payload(subject: ApprovedChangeSubject) -> dict[str, Any]:
    payload = subject.model_dump(mode="python")
    payload["target"]["identity_claims"] = sorted(
        payload["target"]["identity_claims"], key=lambda item: (item["key"], item["value"])
    )
    payload["evidence_references"] = sorted(
        payload["evidence_references"], key=lambda item: item["reference_id"]
    )
    return _canonicalize(payload)


def canonical_subject_json(subject: ApprovedChangeSubject) -> str:
    return json.dumps(
        canonical_subject_payload(subject),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_subject_sha256(subject: ApprovedChangeSubject) -> str:
    return hashlib.sha256(canonical_subject_json(subject).encode("utf-8")).hexdigest()


def verify_approval_binding(contract: ApprovedChangeContract) -> ContractValidationResult:
    computed = compute_subject_sha256(contract.subject)
    ok = computed == contract.approval.subject_sha256
    return ContractValidationResult(
        status="contract_valid" if ok else "approval_mismatch",
        contract_valid=ok,
        approval_binding_valid=ok,
        capability_supported=False,
        computed_subject_sha256=computed,
        errors=() if ok else ("approval subject_sha256 does not match subject",),
        warnings=("approval attestation is not authenticated identity or external authorization",),
    )


def _validate_supported_capabilities(
    supported_capability_ids: Any,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    errors: list[str] = []
    if supported_capability_ids is None:
        return (), ("supported_capability_ids must be explicitly supplied",)
    if isinstance(supported_capability_ids, str):
        return (), ("supported_capability_ids must be a collection, not a string",)
    try:
        values = tuple(supported_capability_ids)
    except TypeError:
        return (), ("supported_capability_ids must be a collection",)
    normalized: list[str] = []
    for item in values:
        if not isinstance(item, str):
            errors.append("supported capability IDs must be strings")
            continue
        capability = item.strip()
        if _is_wildcard(capability) or not _CAPABILITY_RE.fullmatch(capability):
            errors.append(f"invalid supported capability ID: {item}")
        else:
            normalized.append(capability)
    return tuple(normalized), tuple(errors)


def validate_approved_change_contract(
    contract: ApprovedChangeContract | dict[str, Any], supported_capability_ids: Any
) -> ContractValidationResult:
    errors: list[str] = []
    if not isinstance(contract, ApprovedChangeContract):
        try:
            contract = ApprovedChangeContract.model_validate(contract)
        except Exception as exc:  # pydantic exposes many structured subclasses.
            return ContractValidationResult(
                status="contract_invalid",
                contract_valid=False,
                approval_binding_valid=False,
                capability_supported=False,
                computed_subject_sha256="",
                errors=(str(exc),),
            )
    supported, support_errors = _validate_supported_capabilities(supported_capability_ids)
    computed = compute_subject_sha256(contract.subject)
    binding = computed == contract.approval.subject_sha256
    capability_supported = contract.subject.capability_id in set(supported)
    if support_errors:
        errors.extend(support_errors)
    if not binding:
        errors.append("approval subject_sha256 does not match subject")
    if not capability_supported:
        errors.append(f"unsupported capability_id: {contract.subject.capability_id}")
    if support_errors:
        status = "invalid_validation_input"
    elif not binding:
        status = "approval_mismatch"
    elif not capability_supported:
        status = "unsupported_capability"
    else:
        status = "contract_valid"
    return ContractValidationResult(
        status=status,
        contract_valid=status == "contract_valid",
        approval_binding_valid=binding,
        capability_supported=capability_supported and not support_errors,
        computed_subject_sha256=computed,
        errors=tuple(errors),
        warnings=("contract validity grants no execution eligibility",),
    )
