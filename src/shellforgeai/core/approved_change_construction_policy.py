"""Field-source policy for future approved-change construction (PR311).

This module is pure metadata plus validation. It does not accept legacy
Proposal instances, extract values, construct subjects/contracts/approvals,
persist state, register runtime behavior, or enable execution.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, model_validator

from shellforgeai.core.approved_change_compatibility import CANDIDATE_SOURCE_FIELDS
from shellforgeai.core.approved_change_contract import (
    SCHEMA_VERSION as APPROVED_CHANGE_SCHEMA_VERSION,
)
from shellforgeai.core.approved_change_contract import (
    ApprovedChangeSubject,
)

CONSTRUCTION_POLICY_SCHEMA_VERSION = "1"
EXECUTION_STATUS_NOT_EXECUTED = "not_executed"

SourceClassification = Literal[
    "contract_constant",
    "legacy_candidate_requires_explicit_review",
    "explicit_context_only",
]
ValidationStatus = Literal["policy_valid", "policy_invalid"]

CONTRACT_CONSTANT_FIELDS: tuple[str, ...] = ("schema_version",)
DIRECT_CANDIDATE_ALLOWLIST: tuple[tuple[str, str], ...] = (
    ("impact", "impact"),
    ("preconditions", "preconditions"),
    ("risk", "risk"),
    ("source_proposal_reference", "proposal_id"),
    ("verification_criteria", "verification"),
)
EXPLICIT_CONTEXT_ONLY_FIELDS: tuple[str, ...] = (
    "audit_requirements",
    "blast_radius",
    "capability_id",
    "change_summary",
    "desired_outcome",
    "diagnosis_summary",
    "evidence_references",
    "procedure",
    "revalidation_requirements",
    "rollback_posture",
    "target",
    "unsupported_or_irreversible_aspects",
)
REVIEW_CONTEXT_ALLOWLIST: tuple[str, ...] = (
    "notes",
    "rollback",
    "source.evidence",
    "source.runbook",
    "source.summary",
    "source_hashes",
    "title",
)
DESTINATION_REVIEW_CONTEXT_ALLOWLIST: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("change_summary", ("notes", "title")),
    ("desired_outcome", ("notes", "title")),
    ("diagnosis_summary", ("notes", "source.evidence", "source.summary", "title")),
    (
        "evidence_references",
        ("source.evidence", "source.runbook", "source.summary", "source_hashes"),
    ),
    ("rollback_posture", ("rollback",)),
)
PROHIBITED_LEGACY_DIRECT_SOURCES: tuple[tuple[str, str], ...] = (
    ("capability_id", "kind"),
    ("evidence_references", "evidence"),
    ("evidence_references", "source_hashes"),
    ("procedure", "proposed_steps"),
    ("rollback_posture", "rollback"),
    ("target", "component"),
    ("target", "target"),
)
PROHIBITED_ANY_DESTINATION_DIRECT_SOURCES: tuple[str, ...] = ("approval", "fingerprint")
_WILDCARDS = {"*", "all", "any", "fallback", "catch_all", "catch-all"}


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ConstructionFieldSourceRule(_FrozenModel):
    destination_field: str
    source_classification: SourceClassification
    legacy_candidate_fields: tuple[str, ...] = ()
    legacy_review_context_fields: tuple[str, ...] = ()
    explicit_review_required: bool
    auto_copy_allowed: Literal[False] = False
    inference_allowed: Literal[False] = False
    default_allowed: Literal[False] = False
    approval_portable: Literal[False] = False
    fingerprint_reusable: Literal[False] = False
    notes: str

    @model_validator(mode="after")
    def _freeze_nested_order(self) -> ConstructionFieldSourceRule:
        object.__setattr__(self, "legacy_candidate_fields", tuple(self.legacy_candidate_fields))
        object.__setattr__(
            self, "legacy_review_context_fields", tuple(self.legacy_review_context_fields)
        )
        return self


class ApprovedChangeConstructionPolicy(_FrozenModel):
    schema_version: Literal["1"] = CONSTRUCTION_POLICY_SCHEMA_VERSION
    legacy_schema_version: str = "1"
    approved_change_schema_version: Literal["1"] = APPROVED_CHANGE_SCHEMA_VERSION
    rules: tuple[ConstructionFieldSourceRule, ...]
    legacy_direct_candidate_allowlist: tuple[tuple[str, str], ...] = DIRECT_CANDIDATE_ALLOWLIST
    legacy_review_context_allowlist: tuple[str, ...] = REVIEW_CONTEXT_ALLOWLIST
    prohibited_legacy_direct_sources: tuple[tuple[str, str], ...] = PROHIBITED_LEGACY_DIRECT_SOURCES
    policy_name: str = "approved_change_construction_field_source_policy"

    @model_validator(mode="after")
    def _normalize_tuples(self) -> ApprovedChangeConstructionPolicy:
        object.__setattr__(self, "rules", tuple(self.rules))
        object.__setattr__(
            self, "legacy_direct_candidate_allowlist", tuple(self.legacy_direct_candidate_allowlist)
        )
        object.__setattr__(
            self, "legacy_review_context_allowlist", tuple(self.legacy_review_context_allowlist)
        )
        object.__setattr__(
            self, "prohibited_legacy_direct_sources", tuple(self.prohibited_legacy_direct_sources)
        )
        return self


class ConstructionPolicyValidationResult(_FrozenModel):
    status: ValidationStatus
    policy_valid: bool
    coverage_complete: bool
    expected_destination_fields: tuple[str, ...]
    covered_destination_fields: tuple[str, ...]
    missing_destination_fields: tuple[str, ...]
    unknown_destination_fields: tuple[str, ...]
    duplicate_destination_fields: tuple[str, ...]
    errors: tuple[str, ...]
    warnings: tuple[str, ...] = ()
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    subject_created: Literal[False] = False
    contract_created: Literal[False] = False
    approval_created: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


def _rule(
    destination: str,
    classification: SourceClassification,
    *,
    candidates: tuple[str, ...] = (),
    context: tuple[str, ...] = (),
    explicit: bool = True,
    notes: str,
) -> ConstructionFieldSourceRule:
    return ConstructionFieldSourceRule(
        destination_field=destination,
        source_classification=classification,
        legacy_candidate_fields=candidates,
        legacy_review_context_fields=context,
        explicit_review_required=explicit,
        notes=notes,
    )


def _canonical_rules() -> tuple[ConstructionFieldSourceRule, ...]:
    candidate_map = dict(DIRECT_CANDIDATE_ALLOWLIST)
    context_map = dict(DESTINATION_REVIEW_CONTEXT_ALLOWLIST)
    rules: list[ConstructionFieldSourceRule] = []
    for field in sorted(ApprovedChangeSubject.model_fields):
        if field in CONTRACT_CONSTANT_FIELDS:
            rules.append(
                _rule(
                    field,
                    "contract_constant",
                    explicit=False,
                    notes="Value authority is the approved-change contract schema.",
                )
            )
        elif field in candidate_map:
            rules.append(
                _rule(
                    field,
                    "legacy_candidate_requires_explicit_review",
                    candidates=(candidate_map[field],),
                    notes=(
                        "Legacy value may be displayed only as field-specific candidate "
                        "input requiring explicit review."
                    ),
                )
            )
        else:
            rules.append(
                _rule(
                    field,
                    "explicit_context_only",
                    context=context_map.get(field, ()),
                    notes=(
                        "Value must be supplied through explicit reviewed context; "
                        "review context is display-only."
                    ),
                )
            )
    return tuple(rules)


APPROVED_CHANGE_CONSTRUCTION_POLICY = ApprovedChangeConstructionPolicy(rules=_canonical_rules())


def _result(
    errors: list[str],
    expected: tuple[str, ...],
    covered: tuple[str, ...],
    missing: tuple[str, ...],
    unknown: tuple[str, ...],
    duplicate: tuple[str, ...],
) -> ConstructionPolicyValidationResult:
    unique_errors = tuple(sorted(set(errors)))
    valid = not unique_errors
    return ConstructionPolicyValidationResult(
        status="policy_valid" if valid else "policy_invalid",
        policy_valid=valid,
        coverage_complete=not missing and not unknown and not duplicate,
        expected_destination_fields=expected,
        covered_destination_fields=covered,
        missing_destination_fields=missing,
        unknown_destination_fields=unknown,
        duplicate_destination_fields=duplicate,
        errors=unique_errors,
    )


def validate_approved_change_construction_policy(
    policy: ApprovedChangeConstructionPolicy | dict[str, Any],
) -> ConstructionPolicyValidationResult:
    expected = tuple(sorted(ApprovedChangeSubject.model_fields))
    errors: list[str] = []
    try:
        parsed = (
            policy
            if isinstance(policy, ApprovedChangeConstructionPolicy)
            else ApprovedChangeConstructionPolicy.model_validate(policy)
        )
    except Exception as exc:  # validation result must stay non-throwing for bad dicts
        return _result([f"policy model validation failed: {exc}"], expected, (), expected, (), ())

    destinations = tuple(rule.destination_field for rule in parsed.rules)
    counts = Counter(destinations)
    duplicate = tuple(sorted(field for field, count in counts.items() if count > 1))
    covered = tuple(sorted(set(destinations) & set(expected)))
    missing = tuple(sorted(set(expected) - set(destinations)))
    unknown = tuple(sorted(set(destinations) - set(expected)))
    if tuple(destinations) != tuple(sorted(destinations)):
        errors.append("rules must be sorted deterministically by destination_field")
    for field in duplicate:
        errors.append(f"duplicate destination field: {field}")
    for field in missing:
        errors.append(f"missing destination field: {field}")
    for field in unknown:
        errors.append(f"unknown destination field: {field}")
    allowed_candidates = set(parsed.legacy_direct_candidate_allowlist)
    if tuple(
        sorted(parsed.legacy_direct_candidate_allowlist)
    ) != parsed.legacy_direct_candidate_allowlist or set(
        parsed.legacy_direct_candidate_allowlist
    ) != set(DIRECT_CANDIDATE_ALLOWLIST):
        errors.append(
            "legacy_direct_candidate_allowlist must exactly match the canonical five mappings"
        )
    if tuple(
        sorted(parsed.legacy_review_context_allowlist)
    ) != parsed.legacy_review_context_allowlist or set(
        parsed.legacy_review_context_allowlist
    ) != set(REVIEW_CONTEXT_ALLOWLIST):
        errors.append(
            "legacy_review_context_allowlist must exactly match the canonical review-context fields"
        )
    if set(parsed.prohibited_legacy_direct_sources) != set(PROHIBITED_LEGACY_DIRECT_SOURCES):
        errors.append(
            "prohibited_legacy_direct_sources must include the canonical prohibited mappings"
        )
    context_map = dict(DESTINATION_REVIEW_CONTEXT_ALLOWLIST)
    legacy_known = set(CANDIDATE_SOURCE_FIELDS) | {
        "kind",
        "target",
        "component",
        "proposed_steps",
        "evidence",
        "approval",
        "fingerprint",
    }
    for rule in parsed.rules:
        dest = rule.destination_field
        if not dest or dest in _WILDCARDS:
            errors.append(f"invalid destination field: {dest!r}")
        if any(
            field in _WILDCARDS or not field
            for field in (*rule.legacy_candidate_fields, *rule.legacy_review_context_fields)
        ):
            errors.append(f"wildcard, fallback, or empty legacy field on {dest}")
        if (
            rule.auto_copy_allowed
            or rule.inference_allowed
            or rule.default_allowed
            or rule.approval_portable
            or rule.fingerprint_reusable
        ):
            errors.append(f"permanent false safety flag enabled on {dest}")
        if len(rule.legacy_candidate_fields) > 1:
            errors.append(f"multiple direct candidates are prohibited on {dest}")
        for legacy in rule.legacy_candidate_fields:
            if legacy not in legacy_known:
                errors.append(f"unknown legacy direct candidate {legacy} on {dest}")
            if (
                legacy in PROHIBITED_ANY_DESTINATION_DIRECT_SOURCES
                or (dest, legacy) in PROHIBITED_LEGACY_DIRECT_SOURCES
            ):
                errors.append(f"prohibited direct mapping {legacy} -> {dest}")
            if (dest, legacy) not in allowed_candidates:
                errors.append(f"direct candidate mapping is not allowlisted: {legacy} -> {dest}")
        if dest == "schema_version" and rule.source_classification != "contract_constant":
            errors.append("schema_version must be the only contract-constant rule")
        if (
            dest in EXPLICIT_CONTEXT_ONLY_FIELDS
            and rule.source_classification != "explicit_context_only"
        ):
            errors.append(f"explicit-context-only field has wrong classification: {dest}")
        if (
            dest in dict(DIRECT_CANDIDATE_ALLOWLIST)
            and rule.source_classification != "legacy_candidate_requires_explicit_review"
        ):
            errors.append(f"direct-candidate field has wrong classification: {dest}")
        if rule.source_classification == "contract_constant":
            if (
                dest != "schema_version"
                or rule.explicit_review_required
                or rule.legacy_candidate_fields
                or rule.legacy_review_context_fields
            ):
                errors.append(f"invalid contract-constant rule on {dest}")
        elif rule.source_classification == "legacy_candidate_requires_explicit_review":
            if (
                not rule.explicit_review_required
                or len(rule.legacy_candidate_fields) != 1
                or (dest, rule.legacy_candidate_fields[0]) not in allowed_candidates
            ):
                errors.append(f"invalid legacy candidate rule on {dest}")
        elif rule.source_classification == "explicit_context_only" and (
            not rule.explicit_review_required or rule.legacy_candidate_fields
        ):
            errors.append(f"invalid explicit-context-only rule on {dest}")
        if set(rule.legacy_review_context_fields) - set(REVIEW_CONTEXT_ALLOWLIST):
            errors.append(f"review context outside global allowlist on {dest}")
        if tuple(sorted(rule.legacy_review_context_fields)) != rule.legacy_review_context_fields:
            errors.append(f"review context must be sorted on {dest}")
        if set(rule.legacy_review_context_fields) != set(context_map.get(dest, ())):
            errors.append(f"review context mapping is not destination-specific on {dest}")
        for review_field in rule.legacy_review_context_fields:
            if review_field in rule.legacy_candidate_fields:
                errors.append(f"review context used as direct candidate on {dest}: {review_field}")
    return _result(errors, expected, covered, missing, unknown, duplicate)
