from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
import os
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from shellforgeai.core import approved_change_artifact_bundle as bundle_module
from shellforgeai.core.approvals import Proposal
from shellforgeai.core.approved_change_artifact_bundle import (
    APPROVED_CHANGE_SUBJECT_FILENAME,
    APPROVED_CHANGE_SUBJECT_ROLE,
    ARTIFACT_BUNDLE_KIND,
    ARTIFACT_BUNDLE_SCHEMA_VERSION,
    BUNDLE_FILE_ORDER,
    BUNDLE_FILENAMES,
    BUNDLE_ID_PREFIX,
    BUNDLE_IDENTITY_EXCLUDED_FIELDS,
    BUNDLE_ROLES,
    CONSTRUCTION_EVIDENCE_FILENAME,
    CONSTRUCTION_EVIDENCE_ROLE,
    MANIFEST_FILENAME,
    MANIFEST_ROLE,
    OVERWRITE_POLICY,
    PAYLOAD_FILE_ORDER,
    PERMANENT_BUNDLE_WARNINGS,
    PUBLICATION_POLICY,
    SUPPLEMENTAL_CONTEXT_FILENAME,
    SUPPLEMENTAL_CONTEXT_ROLE,
    ApprovedChangeArtifactBundle,
    ApprovedChangeArtifactBundleBuildResult,
    ApprovedChangeArtifactBundleFile,
    ApprovedChangeArtifactBundleManifest,
    ApprovedChangeArtifactBundlePayloadFile,
    ApprovedChangeArtifactBundleValidationResult,
    build_approved_change_artifact_bundle,
    canonical_bundle_manifest_identity_json,
    canonical_bundle_manifest_identity_payload,
    canonical_bundle_manifest_json,
    compute_bundle_identity_sha256,
    derive_bundle_id,
    validate_approved_change_artifact_bundle,
)
from shellforgeai.core.approved_change_contract import (
    ApprovalAttestation,
    ApprovedChangeContract,
    ApprovedChangeTarget,
    EvidenceReference,
    ProcedureStep,
    RollbackPosture,
    TargetIdentityClaim,
    canonical_subject_json,
    compute_subject_sha256,
)
from shellforgeai.core.approved_change_subject_construction import (
    canonical_construction_evidence_json,
    compute_construction_evidence_sha256,
    construct_approved_change_subject,
)
from shellforgeai.core.approved_change_supplemental_context import (
    ApprovedChangeSupplementalContext,
    AuditRequirementsContextReview,
    BlastRadiusContextReview,
    CapabilityIdContextReview,
    ChangeSummaryContextReview,
    DesiredOutcomeContextReview,
    DiagnosisSummaryContextReview,
    EvidenceReferencesContextReview,
    ImpactCandidateReview,
    PreconditionsCandidateReview,
    ProcedureContextReview,
    RevalidationRequirementsContextReview,
    ReviewProvenance,
    RiskCandidateReview,
    RollbackPostureContextReview,
    SourceProposalReferenceCandidateReview,
    TargetContextReview,
    UnsupportedOrIrreversibleAspectsContextReview,
    VerificationCriteriaCandidateReview,
    canonical_supplemental_context_json,
    compute_candidate_sha256,
    compute_supplemental_context_sha256,
)

REVIEW_TIME = datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc)
#: The same instant spelled with a +02:00 offset instead of UTC.
ALT_ZONE_REVIEW_TIME = datetime(2026, 7, 26, 14, 0, 0, tzinfo=timezone(timedelta(hours=2)))
NOT_A_HASH = "0" * 64

# --------------------------------------------------------------------------
# Committed fixed-fixture reference values
#
# These are the exact expected Linux and Windows bytes for fixture A. They are
# recorded here so any canonicalization, ordering, encoding, schema, warning, or
# fixed-policy drift fails loudly instead of silently changing stored artifacts.
# --------------------------------------------------------------------------

FIXTURE_A_CONTEXT_SHA256 = "7a9a2b9c893dd4514e479348758a9e9b9a482dff31c8019f51448c8572714d4e"
FIXTURE_A_SUBJECT_SHA256 = "c125a2989279958fe1a09d325e02ebac44efad0ebe11140b0bc045f46a1d3cfe"
FIXTURE_A_EVIDENCE_SHA256 = "b3c966e453ca26e2efb680ae9dab9d4558bd96fb639a5ef8514d982666f7ee3d"
FIXTURE_A_BUNDLE_IDENTITY_SHA256 = (
    "160419b4edacb99b672a9234b37cdb8e2e8e558057c6329dad9da0657df8fa11"
)
FIXTURE_A_FILE_SIZES: dict[str, int] = {
    SUPPLEMENTAL_CONTEXT_FILENAME: 5846,
    APPROVED_CHANGE_SUBJECT_FILENAME: 1987,
    CONSTRUCTION_EVIDENCE_FILENAME: 8644,
    MANIFEST_FILENAME: 2400,
}
FIXTURE_A_FILE_SHA256: dict[str, str] = {
    SUPPLEMENTAL_CONTEXT_FILENAME: FIXTURE_A_CONTEXT_SHA256,
    APPROVED_CHANGE_SUBJECT_FILENAME: FIXTURE_A_SUBJECT_SHA256,
    CONSTRUCTION_EVIDENCE_FILENAME: FIXTURE_A_EVIDENCE_SHA256,
    MANIFEST_FILENAME: "1fe71bfbb47c52e7d6a538856d621963f8568a0686e6130a6dba48061bdf1dc5",
}

EXPECTED_CANDIDATE_SOURCES = {
    "source_proposal_reference": "proposal_id",
    "risk": "risk",
    "impact": "impact",
    "preconditions": "preconditions",
    "verification_criteria": "verification",
}
CANDIDATE_CLASSES = {
    "source_proposal_reference": SourceProposalReferenceCandidateReview,
    "risk": RiskCandidateReview,
    "impact": ImpactCandidateReview,
    "preconditions": PreconditionsCandidateReview,
    "verification_criteria": VerificationCriteriaCandidateReview,
}
EXPLICIT_CLASSES = {
    "audit_requirements": AuditRequirementsContextReview,
    "blast_radius": BlastRadiusContextReview,
    "capability_id": CapabilityIdContextReview,
    "change_summary": ChangeSummaryContextReview,
    "desired_outcome": DesiredOutcomeContextReview,
    "diagnosis_summary": DiagnosisSummaryContextReview,
    "evidence_references": EvidenceReferencesContextReview,
    "procedure": ProcedureContextReview,
    "revalidation_requirements": RevalidationRequirementsContextReview,
    "rollback_posture": RollbackPostureContextReview,
    "target": TargetContextReview,
    "unsupported_or_irreversible_aspects": UnsupportedOrIrreversibleAspectsContextReview,
}

# Fixture A deliberately carries non-ASCII reviewed text so canonical
# ``ensure_ascii=False`` output is exercised on every platform.
CANDIDATE_VALUES_A = {
    "source_proposal_reference": "prop-2026-07-26-01",
    "risk": "medium",
    "impact": "un solo contenedor revisado — sin otros objetivos",
    "preconditions": ("operator confirms maintenance window", "backup verified"),
    "verification_criteria": ("fresh evidence satisfies health criteria", "no restart loop"),
}
EXPLICIT_VALUES_A = {
    "audit_requirements": ("record reviewed context hash and verification outcome",),
    "blast_radius": "one reviewed target only — no neighbours",
    "capability_id": "example.synthetic_bounded_change",
    "change_summary": "corrección descriptiva acotada",
    "desired_outcome": "restore the reviewed healthy state",
    "diagnosis_summary": "reviewed evidence indicates configuration drift",
    "revalidation_requirements": ("re-check target identity and current evidence",),
    "unsupported_or_irreversible_aspects": ("none identified",),
}
CANDIDATE_VALUES_B = {
    "source_proposal_reference": "prop-2026-07-26-02",
    "risk": "low",
    "impact": "a second reviewed container only",
    "preconditions": ("second operator confirms the window",),
    "verification_criteria": ("second fixture evidence satisfies health criteria",),
}
EXPLICIT_VALUES_B = {
    "audit_requirements": ("record the second reviewed context hash",),
    "blast_radius": "one second reviewed target only",
    "capability_id": "example.second_synthetic_bounded_change",
    "change_summary": "second bounded descriptive correction",
    "desired_outcome": "restore the second reviewed healthy state",
    "diagnosis_summary": "second reviewed evidence indicates configuration drift",
    "revalidation_requirements": ("re-check the second target identity",),
    "unsupported_or_irreversible_aspects": ("none identified for the second fixture",),
}


# --------------------------------------------------------------------------
# Reviewed-context fixtures
# --------------------------------------------------------------------------


def provenance(actor="operator-a", at=REVIEW_TIME, reason="explicit field review"):
    return ReviewProvenance(reviewed_by=actor, reviewed_at=at, review_reason=reason)


def target(claims=(("id", "abc123"), ("host", "docker01")), name="demo"):
    return ApprovedChangeTarget(
        kind="container",
        name=name,
        identity_claims=tuple(TargetIdentityClaim(key=k, value=v) for k, v in claims),
    )


def evidence(order=("ev-1", "ev-2"), at=REVIEW_TIME):
    return tuple(
        EvidenceReference(
            reference_id=ref,
            source="informe-ops",
            sha256="a" * 64 if ref == "ev-1" else "b" * 64,
            observed_at=at,
        )
        for ref in order
    )


def steps(ids=("step-1", "step-2")):
    return tuple(
        ProcedureStep(
            step_id=step_id,
            description=f"perform reviewed action {step_id}",
            expected_effect=f"target matches reviewed state after {step_id}",
        )
        for step_id in ids
    )


def rollback(procedure_ids=("rollback-1", "rollback-2")):
    return RollbackPosture(
        reversible=True,
        summary="manual recovery expected",
        procedure=steps(procedure_ids),
        limitations=("automatic rollback unsupported",),
    )


def explicit_reviews(values=None, prov=None, at=REVIEW_TIME, **overrides):
    resolved = dict(EXPLICIT_VALUES_A if values is None else values)
    resolved.update(
        {
            "evidence_references": evidence(at=at),
            "procedure": steps(),
            "rollback_posture": rollback(),
            "target": target(),
        }
    )
    resolved.update(overrides)
    return tuple(
        EXPLICIT_CLASSES[field](
            reviewed_value=resolved[field], provenance=prov or provenance(at=at)
        )
        for field in sorted(EXPLICIT_CLASSES)
    )


def candidate(destination, *, value, decision="accepted", final=None, prov=None, sha=None):
    source = EXPECTED_CANDIDATE_SOURCES[destination]
    return CANDIDATE_CLASSES[destination](
        candidate_value=value,
        candidate_sha256=sha or compute_candidate_sha256(destination, source, value),
        decision=decision,
        final_reviewed_value=value if final is None else final,
        provenance=prov or provenance(),
    )


def candidate_reviews(values=None, prov=None, at=REVIEW_TIME, **overrides):
    resolved = dict(CANDIDATE_VALUES_A if values is None else values)
    return tuple(
        overrides.get(destination)
        or candidate(destination, value=resolved[destination], prov=prov or provenance(at=at))
        for destination in sorted(resolved)
    )


def context(explicit=None, candidates=None, **overrides):
    payload = {
        "explicit_context_reviews": explicit_reviews() if explicit is None else explicit,
        "legacy_candidate_reviews": candidate_reviews() if candidates is None else candidates,
    }
    payload.update(overrides)
    return ApprovedChangeSupplementalContext(**payload)


def context_b():
    return ApprovedChangeSupplementalContext(
        explicit_context_reviews=explicit_reviews(
            EXPLICIT_VALUES_B, prov=provenance("operator-b", reason="second fixture review")
        ),
        legacy_candidate_reviews=candidate_reviews(
            CANDIDATE_VALUES_B, prov=provenance("operator-b", reason="second fixture review")
        ),
    )


def context_alt_provenance():
    """Fixture A's exact subject values reviewed by a different actor."""
    actor = provenance("operator-z", reason="identical values re-reviewed")
    return ApprovedChangeSupplementalContext(
        explicit_context_reviews=explicit_reviews(prov=actor),
        legacy_candidate_reviews=candidate_reviews(prov=actor),
    )


def context_alt_timezone():
    """Fixture A with every reviewed timestamp spelled as +02:00."""
    return ApprovedChangeSupplementalContext(
        explicit_context_reviews=explicit_reviews(at=ALT_ZONE_REVIEW_TIME),
        legacy_candidate_reviews=candidate_reviews(at=ALT_ZONE_REVIEW_TIME),
    )


# --------------------------------------------------------------------------
# Build helpers
# --------------------------------------------------------------------------


_UNSET = object()


def identities(fixture):
    """Return the exact (context, subject, evidence) identities of a fixture."""
    context_sha256 = compute_supplemental_context_sha256(fixture)
    result = construct_approved_change_subject(
        fixture, expected_supplemental_context_sha256=context_sha256
    )
    return (
        context_sha256,
        result.computed_subject_sha256,
        result.computed_construction_evidence_sha256,
    )


def build(fixture=None, *, context_sha=_UNSET, subject_sha=_UNSET, evidence_sha=_UNSET):
    """Build a bundle from a fixture using its own exact semantic identities."""
    fixture = context() if fixture is None else fixture
    known = (
        identities(fixture)
        if isinstance(fixture, ApprovedChangeSupplementalContext)
        else ("", "", "")
    )
    return build_approved_change_artifact_bundle(
        fixture,
        expected_supplemental_context_sha256=known[0] if context_sha is _UNSET else context_sha,
        expected_subject_sha256=known[1] if subject_sha is _UNSET else subject_sha,
        expected_construction_evidence_sha256=known[2] if evidence_sha is _UNSET else evidence_sha,
    )


def bundle_data(fixture=None):
    """Return a mutable JSON-shaped copy of a freshly built valid bundle."""
    result = build(fixture)
    assert result.status == "bundle_constructed"
    return result.bundle.model_dump(mode="json")


def files_by_role(data):
    return {entry["role"]: entry for entry in data["files"]}


def refresh(entry):
    """Recompute one logical file record's byte length and checksum."""
    encoded = entry["content_utf8"].encode("utf-8")
    entry["size_bytes"] = len(encoded)
    entry["sha256"] = hashlib.sha256(encoded).hexdigest()
    return entry


def set_content(data, role, content, *, refresh_metadata=True):
    entry = files_by_role(data)[role]
    entry["content_utf8"] = content
    if refresh_metadata:
        refresh(entry)
    return data


def stored(data, role):
    return files_by_role(data)[role]["content_utf8"]


def manifest_fields(manifest):
    """Return the manifest's identity-relevant fields only."""
    fields = manifest.model_dump(mode="python")
    for excluded in BUNDLE_IDENTITY_EXCLUDED_FIELDS:
        fields.pop(excluded)
    return fields


def assert_build_blocked(result, *, expected_status=None):
    assert result.build_succeeded is False
    assert result.status in {"bundle_construction_blocked", "invalid_bundle_construction_input"}
    if expected_status is not None:
        assert result.status == expected_status
    assert result.bundle is None
    assert result.manifest is None
    assert result.bundle_id == ""
    assert result.bundle_identity_sha256 == ""
    assert result.bundle_constructed is False
    assert result.manifest_constructed is False
    assert result.errors
    assert all(isinstance(error, str) for error in result.errors)
    assert "Traceback" not in " ".join(result.errors)
    assert list(result.errors) == sorted(set(result.errors))
    assert_permanent_safety(result)


def assert_bundle_invalid(result, *, expected_status="bundle_invalid"):
    assert isinstance(result, ApprovedChangeArtifactBundleValidationResult)
    assert result.bundle_valid is False
    assert result.status == expected_status
    assert result.errors
    assert "Traceback" not in " ".join(result.errors)
    assert list(result.errors) == sorted(set(result.errors))
    assert_permanent_safety(result)


def assert_permanent_safety(result):
    assert result.read_only is True
    assert result.mutation_performed is False
    assert result.artifact_write_performed is False
    assert result.filesystem_accessed is False
    assert result.publication_performed is False
    assert result.overwrite_performed is False
    assert result.persistence_performed is False
    assert result.approval_created is False
    assert result.contract_created is False
    assert result.receipt_created is False
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert result.approval_evaluated is False
    assert result.authorization_evaluated is False
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"


# --------------------------------------------------------------------------
# Successful bundle construction
# --------------------------------------------------------------------------


def test_complete_fixture_builds_one_four_file_bundle_and_one_manifest():
    fixture = context()
    context_sha256, subject_sha256, evidence_sha256 = identities(fixture)
    result = build(fixture)

    assert result.status == "bundle_constructed"
    assert result.build_succeeded is True
    assert result.bundle_constructed is True
    assert result.manifest_constructed is True
    assert result.errors == ()
    assert isinstance(result.bundle, ApprovedChangeArtifactBundle)
    assert isinstance(result.manifest, ApprovedChangeArtifactBundleManifest)
    assert result.computed_supplemental_context_sha256 == context_sha256
    assert result.computed_subject_sha256 == subject_sha256
    assert result.computed_construction_evidence_sha256 == evidence_sha256
    assert result.expected_supplemental_context_sha256 == context_sha256
    assert result.expected_subject_sha256 == subject_sha256
    assert result.expected_construction_evidence_sha256 == evidence_sha256
    assert result.warnings == PERMANENT_BUNDLE_WARNINGS
    assert_permanent_safety(result)


def test_bundle_files_use_the_exact_fixed_names_roles_and_order():
    bundle = build().bundle
    assert len(bundle.files) == 4
    assert tuple(item.relative_path for item in bundle.files) == (
        "supplemental-context.json",
        "approved-change-subject.json",
        "construction-evidence.json",
        "manifest.json",
    )
    assert tuple(item.role for item in bundle.files) == (
        "supplemental_context",
        "approved_change_subject",
        "construction_evidence",
        "manifest",
    )
    assert tuple(name for name, _ in BUNDLE_FILE_ORDER) == BUNDLE_FILENAMES
    assert tuple(role for _, role in BUNDLE_FILE_ORDER) == BUNDLE_ROLES
    assert BUNDLE_FILE_ORDER[:3] == PAYLOAD_FILE_ORDER
    assert all(name == name.lower() and name.isascii() for name in BUNDLE_FILENAMES)
    assert all(name.endswith(".json") for name in BUNDLE_FILENAMES)


def test_bundle_bytes_are_the_maintained_canonical_serializations():
    fixture = context()
    result = build(fixture)
    construction = construct_approved_change_subject(
        fixture, expected_supplemental_context_sha256=compute_supplemental_context_sha256(fixture)
    )
    files = {item.role: item for item in result.bundle.files}
    assert files[SUPPLEMENTAL_CONTEXT_ROLE].content_utf8 == canonical_supplemental_context_json(
        fixture
    )
    assert files[APPROVED_CHANGE_SUBJECT_ROLE].content_utf8 == canonical_subject_json(
        construction.subject
    )
    assert files[CONSTRUCTION_EVIDENCE_ROLE].content_utf8 == canonical_construction_evidence_json(
        construction.construction_evidence
    )
    assert files[MANIFEST_ROLE].content_utf8 == canonical_bundle_manifest_json(result.manifest)
    for logical in result.bundle.files:
        assert not logical.content_utf8.startswith("\ufeff")
        assert not logical.content_utf8.endswith("\n")
        assert "\r" not in logical.content_utf8
        assert ": " not in logical.content_utf8.replace('": "', "")
        assert logical.size_bytes == len(logical.content_utf8.encode("utf-8"))
        assert logical.sha256 == hashlib.sha256(logical.content_utf8.encode("utf-8")).hexdigest()


def test_payload_checksums_equal_the_maintained_semantic_identities():
    fixture = context()
    context_sha256, subject_sha256, evidence_sha256 = identities(fixture)
    result = build(fixture)
    files = {item.role: item for item in result.bundle.files}
    assert files[SUPPLEMENTAL_CONTEXT_ROLE].sha256 == context_sha256
    assert files[APPROVED_CHANGE_SUBJECT_ROLE].sha256 == subject_sha256
    assert files[CONSTRUCTION_EVIDENCE_ROLE].sha256 == evidence_sha256
    for descriptor in result.manifest.payload_files:
        assert descriptor.content_sha256 == descriptor.semantic_identity_sha256


def test_manifest_records_the_fixed_contract_metadata():
    manifest = build().manifest
    assert manifest.schema_version == ARTIFACT_BUNDLE_SCHEMA_VERSION == "1"
    assert manifest.kind == ARTIFACT_BUNDLE_KIND == "approved_change_reviewed_artifact_bundle"
    assert manifest.manifest_filename == "manifest.json"
    assert manifest.publication_policy == "prepare_verify_then_atomic_publish"
    assert manifest.atomicity_policy == (
        "publish_complete_verified_bundle_with_one_final_directory_transition"
    )
    assert manifest.overwrite_policy == "forbid"
    assert manifest.existing_identical_policy == "validate_and_return_already_present"
    assert manifest.destination_policy == "fixed_full_bundle_id_directory"
    assert manifest.warnings == PERMANENT_BUNDLE_WARNINGS
    assert manifest.supplemental_context_schema_version == "1"
    assert manifest.approved_change_schema_version == "1"
    assert manifest.construction_policy_schema_version == "1"
    assert manifest.construction_evidence_schema_version == "1"
    assert tuple(item.relative_path for item in manifest.payload_files) == (
        "supplemental-context.json",
        "approved-change-subject.json",
        "construction-evidence.json",
    )


def test_bundle_id_is_the_prefixed_full_untruncated_identity():
    result = build()
    assert BUNDLE_ID_PREFIX == "acb_"
    assert result.bundle_id == f"acb_{result.bundle_identity_sha256}"
    assert len(result.bundle_identity_sha256) == 64
    assert len(result.bundle_id) == 68
    assert result.bundle.bundle_id == result.manifest.bundle_id == result.bundle_id
    assert result.bundle.bundle_identity_sha256 == result.manifest.bundle_identity_sha256


def test_committed_fixed_fixture_reference_values():
    """Guard the exact committed fixture bytes, lengths, hashes, and identity."""
    fixture = context()
    context_sha256, subject_sha256, evidence_sha256 = identities(fixture)
    result = build(fixture)

    assert context_sha256 == FIXTURE_A_CONTEXT_SHA256
    assert subject_sha256 == FIXTURE_A_SUBJECT_SHA256
    assert evidence_sha256 == FIXTURE_A_EVIDENCE_SHA256
    assert result.bundle_identity_sha256 == FIXTURE_A_BUNDLE_IDENTITY_SHA256
    assert result.bundle_id == f"acb_{FIXTURE_A_BUNDLE_IDENTITY_SHA256}"
    for logical in result.bundle.files:
        assert logical.size_bytes == FIXTURE_A_FILE_SIZES[logical.relative_path]
        assert logical.sha256 == FIXTURE_A_FILE_SHA256[logical.relative_path]


def test_valid_bundle_validates_cleanly():
    result = build()
    validation = validate_approved_change_artifact_bundle(result.bundle)
    assert validation.status == "bundle_valid"
    assert validation.bundle_valid is True
    assert validation.errors == ()
    assert validation.bundle_id == result.bundle_id
    assert validation.bundle_identity_sha256 == result.bundle_identity_sha256
    assert validation.computed_bundle_identity_sha256 == result.bundle_identity_sha256
    assert validation.computed_supplemental_context_sha256 == (
        result.computed_supplemental_context_sha256
    )
    assert validation.computed_subject_sha256 == result.computed_subject_sha256
    assert validation.computed_construction_evidence_sha256 == (
        result.computed_construction_evidence_sha256
    )
    assert validation.warnings == PERMANENT_BUNDLE_WARNINGS
    assert_permanent_safety(validation)


def test_valid_bundle_dictionary_validates_cleanly():
    assert validate_approved_change_artifact_bundle(bundle_data()).status == "bundle_valid"


# --------------------------------------------------------------------------
# Exact four-file allowlist
# --------------------------------------------------------------------------


@pytest.mark.parametrize("role", list(BUNDLE_ROLES))
def test_missing_file_is_rejected(role):
    data = bundle_data()
    data["files"] = [entry for entry in data["files"] if entry["role"] != role]
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


def test_extra_file_is_rejected():
    data = bundle_data()
    data["files"].append(copy.deepcopy(files_by_role(data)[MANIFEST_ROLE]))
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


def test_duplicate_file_and_duplicate_role_are_rejected():
    data = bundle_data()
    data["files"][3] = copy.deepcopy(data["files"][2])
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))

    other = bundle_data()
    other["files"][1]["role"] = other["files"][0]["role"]
    assert_bundle_invalid(validate_approved_change_artifact_bundle(other))


def test_reordered_files_are_rejected():
    data = bundle_data()
    data["files"][0], data["files"][1] = data["files"][1], data["files"][0]
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


@pytest.mark.parametrize(
    "filename",
    [
        "context.json",
        "supplemental_context.json",
        "supplemental-context.JSON",
        "supplemental-context.txt",
        "supplemental-context.json.bak",
        "Supplemental-Context.json",
        "SUPPLEMENTAL-CONTEXT.JSON",
        "",
        " supplemental-context.json",
        "supplemental-context.json ",
        "\tsupplemental-context.json",
        "nested/supplemental-context.json",
        "nested\\supplemental-context.json",
        "../supplemental-context.json",
        "..",
        "./supplemental-context.json",
        "/etc/supplemental-context.json",
        "//server/share/supplemental-context.json",
        "\\\\server\\share\\supplemental-context.json",
        "C:\\bundles\\supplemental-context.json",
        "c:/bundles/supplemental-context.json",
        "supplemental-cоntext.json",
        "ѕupplemental-context.json",
        "supplemental-context\u200b.json",
        "supplemental-context.jsοn",
    ],
)
def test_unsafe_or_renamed_filenames_are_rejected(filename):
    data = bundle_data()
    data["files"][0]["relative_path"] = filename
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))
    with pytest.raises(ValidationError):
        ApprovedChangeArtifactBundleFile(
            relative_path=filename,
            role=SUPPLEMENTAL_CONTEXT_ROLE,
            content_utf8="{}",
            size_bytes=2,
            sha256=hashlib.sha256(b"{}").hexdigest(),
        )


@pytest.mark.parametrize("filename", [MANIFEST_FILENAME, "manifest.json"])
def test_manifest_filename_may_not_be_used_by_a_payload_descriptor(filename):
    with pytest.raises(ValidationError):
        ApprovedChangeArtifactBundlePayloadFile(
            relative_path=filename,
            role=MANIFEST_ROLE,
            size_bytes=10,
            content_sha256=NOT_A_HASH,
            semantic_identity_sha256=NOT_A_HASH,
        )


def test_bundle_defines_no_subdirectory_glob_or_optional_file():
    for name in BUNDLE_FILENAMES:
        assert "/" not in name and "\\" not in name and "*" not in name and "?" not in name
    assert len(set(BUNDLE_FILENAMES)) == len(BUNDLE_FILENAMES) == 4
    assert len(set(BUNDLE_ROLES)) == len(BUNDLE_ROLES) == 4


# --------------------------------------------------------------------------
# Builder identity gates
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"context_sha": None},
        {"context_sha": ""},
        {"context_sha": "abc"},
        {"context_sha": "z" * 64},
        {"context_sha": 5},
        {"subject_sha": None},
        {"subject_sha": "abc"},
        {"evidence_sha": None},
        {"evidence_sha": "abc"},
        {"evidence_sha": ("a" * 64,)},
    ],
)
def test_malformed_expected_identities_are_structured_invalid_input(kwargs):
    assert_build_blocked(build(**kwargs), expected_status="invalid_bundle_construction_input")


@pytest.mark.parametrize("field", ["context_sha", "subject_sha", "evidence_sha"])
def test_uppercase_expected_identities_are_rejected(field):
    fixture = context()
    index = ["context_sha", "subject_sha", "evidence_sha"].index(field)
    upper = identities(fixture)[index].upper()
    assert_build_blocked(
        build(fixture, **{field: upper}), expected_status="invalid_bundle_construction_input"
    )


@pytest.mark.parametrize("field", ["context_sha", "subject_sha", "evidence_sha"])
def test_stale_or_foreign_expected_identities_block_construction(field):
    fixture = context()
    other = identities(context_b())
    index = ["context_sha", "subject_sha", "evidence_sha"].index(field)
    assert_build_blocked(
        build(fixture, **{field: other[index]}), expected_status="bundle_construction_blocked"
    )
    assert_build_blocked(
        build(fixture, **{field: NOT_A_HASH}), expected_status="bundle_construction_blocked"
    )


def test_swapped_expected_identities_block_construction():
    fixture = context()
    context_sha256, subject_sha256, evidence_sha256 = identities(fixture)
    assert_build_blocked(
        build(fixture, subject_sha=evidence_sha256, evidence_sha=subject_sha256),
        expected_status="bundle_construction_blocked",
    )
    assert_build_blocked(
        build(fixture, context_sha=subject_sha256),
        expected_status="bundle_construction_blocked",
    )


def test_bundle_identity_is_not_accepted_as_a_semantic_identity():
    fixture = context()
    result = build(fixture)
    for field in ("context_sha", "subject_sha", "evidence_sha"):
        assert_build_blocked(
            build(fixture, **{field: result.bundle_identity_sha256}),
            expected_status="bundle_construction_blocked",
        )


def test_candidate_and_field_value_hashes_are_not_accepted_identities():
    fixture = context()
    candidate_hash = compute_candidate_sha256("risk", "risk", CANDIDATE_VALUES_A["risk"])
    assert_build_blocked(
        build(fixture, subject_sha=candidate_hash), expected_status="bundle_construction_blocked"
    )


def test_exact_valid_identities_are_required_together():
    fixture = context()
    context_sha256, subject_sha256, evidence_sha256 = identities(fixture)
    assert build(fixture).status == "bundle_constructed"
    assert_build_blocked(build(fixture, subject_sha=NOT_A_HASH))
    assert_build_blocked(build(fixture, evidence_sha=NOT_A_HASH))
    assert_build_blocked(build(fixture, context_sha=NOT_A_HASH))
    assert context_sha256 != subject_sha256 != evidence_sha256


def test_builder_takes_no_subject_evidence_manifest_or_destination_input():
    signature = inspect.signature(build_approved_change_artifact_bundle)
    assert list(signature.parameters) == [
        "context",
        "expected_supplemental_context_sha256",
        "expected_subject_sha256",
        "expected_construction_evidence_sha256",
    ]
    for name in ("subject", "construction_evidence", "manifest", "bundle_id", "output_dir"):
        assert name not in signature.parameters


# --------------------------------------------------------------------------
# Canonical stored bytes
# --------------------------------------------------------------------------


def pretty(content):
    return json.dumps(json.loads(content), indent=2, sort_keys=True, ensure_ascii=False)


def key_reordered(content):
    payload = json.loads(content)
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False, sort_keys=False)


@pytest.mark.parametrize(
    "role",
    [
        SUPPLEMENTAL_CONTEXT_ROLE,
        APPROVED_CHANGE_SUBJECT_ROLE,
        CONSTRUCTION_EVIDENCE_ROLE,
        MANIFEST_ROLE,
    ],
)
@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(pretty, id="pretty-printed"),
        pytest.param(lambda content: f" {content}", id="leading-whitespace"),
        pytest.param(lambda content: f"{content} ", id="trailing-whitespace"),
        pytest.param(lambda content: f"{content}\n", id="trailing-newline"),
        pytest.param(lambda content: content.replace(",", ",\r\n", 1), id="crlf"),
        pytest.param(lambda content: f"\ufeff{content}", id="utf8-bom"),
        pytest.param(
            lambda content: json.dumps(
                json.loads(content), separators=(", ", ": "), ensure_ascii=False, sort_keys=True
            ),
            id="loose-separators",
        ),
        pytest.param(
            lambda content: json.dumps(
                json.loads(content), separators=(",", ":"), ensure_ascii=True, sort_keys=True
            ),
            id="escaped-non-ascii",
        ),
    ],
)
def test_noncanonical_stored_bytes_are_rejected(role, mutate):
    data = bundle_data()
    mutated = mutate(stored(data, role))
    if mutated == stored(data, role):
        pytest.skip("mutation is a no-op for this payload")
    assert_bundle_invalid(
        validate_approved_change_artifact_bundle(set_content(data, role, mutated))
    )


def test_reordered_mapping_keys_are_rejected():
    data = bundle_data()
    content = stored(data, MANIFEST_ROLE)
    payload = json.loads(content)
    reordered = {key: payload[key] for key in reversed(list(payload))}
    mutated = json.dumps(reordered, separators=(",", ":"), ensure_ascii=False)
    assert mutated != content
    assert_bundle_invalid(
        validate_approved_change_artifact_bundle(set_content(data, MANIFEST_ROLE, mutated))
    )


def test_equivalent_timestamp_spelling_is_rejected_in_stored_bytes():
    data = bundle_data()
    content = stored(data, SUPPLEMENTAL_CONTEXT_ROLE)
    mutated = content.replace("2026-07-26T12:00:00Z", "2026-07-26T14:00:00+02:00")
    assert mutated != content
    assert_bundle_invalid(
        validate_approved_change_artifact_bundle(
            set_content(data, SUPPLEMENTAL_CONTEXT_ROLE, mutated)
        )
    )


def test_reordered_semantic_sequences_are_rejected_in_stored_bytes():
    data = bundle_data()
    payload = json.loads(stored(data, APPROVED_CHANGE_SUBJECT_ROLE))
    payload["procedure"] = list(reversed(payload["procedure"]))
    mutated = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    assert_bundle_invalid(
        validate_approved_change_artifact_bundle(
            set_content(data, APPROVED_CHANGE_SUBJECT_ROLE, mutated)
        )
    )


@pytest.mark.parametrize("key", ["identity_claims", "evidence_references"])
def test_noncanonical_set_like_order_is_rejected_in_stored_bytes(key):
    data = bundle_data()
    payload = json.loads(stored(data, APPROVED_CHANGE_SUBJECT_ROLE))
    if key == "identity_claims":
        payload["target"][key] = list(reversed(payload["target"][key]))
    else:
        payload[key] = list(reversed(payload[key]))
    mutated = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    assert mutated != stored(data, APPROVED_CHANGE_SUBJECT_ROLE)
    assert_bundle_invalid(
        validate_approved_change_artifact_bundle(
            set_content(data, APPROVED_CHANGE_SUBJECT_ROLE, mutated)
        )
    )


def test_altered_boolean_representation_is_rejected():
    data = bundle_data()
    payload = json.loads(stored(data, APPROVED_CHANGE_SUBJECT_ROLE))
    payload["rollback_posture"]["reversible"] = 1
    mutated = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    assert_bundle_invalid(
        validate_approved_change_artifact_bundle(
            set_content(data, APPROVED_CHANGE_SUBJECT_ROLE, mutated)
        )
    )


@pytest.mark.parametrize("role", list(BUNDLE_ROLES))
def test_unparseable_stored_bytes_are_rejected(role):
    data = bundle_data()
    assert_bundle_invalid(
        validate_approved_change_artifact_bundle(set_content(data, role, "not json"))
    )
    other = bundle_data()
    assert_bundle_invalid(
        validate_approved_change_artifact_bundle(set_content(other, role, "[1, 2, 3]"))
    )


def test_invalid_stored_payload_is_never_reserialized_into_acceptance():
    data = bundle_data()
    original = stored(data, SUPPLEMENTAL_CONTEXT_ROLE)
    result = validate_approved_change_artifact_bundle(
        set_content(data, SUPPLEMENTAL_CONTEXT_ROLE, pretty(original))
    )
    assert_bundle_invalid(result)
    assert stored(data, SUPPLEMENTAL_CONTEXT_ROLE) != original


# --------------------------------------------------------------------------
# File metadata
# --------------------------------------------------------------------------


@pytest.mark.parametrize("role", list(BUNDLE_ROLES))
def test_wrong_byte_length_is_rejected(role):
    data = bundle_data()
    files_by_role(data)[role]["size_bytes"] += 1
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


@pytest.mark.parametrize("role", list(BUNDLE_ROLES))
def test_wrong_checksum_is_rejected(role):
    data = bundle_data()
    files_by_role(data)[role]["sha256"] = NOT_A_HASH
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


def test_malformed_checksum_is_rejected():
    data = bundle_data()
    data["files"][0]["sha256"] = "ABC"
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


def test_wrong_role_for_a_correct_filename_is_rejected():
    data = bundle_data()
    data["files"][0]["role"] = MANIFEST_ROLE
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


def test_correct_payload_under_the_wrong_role_is_rejected():
    data = bundle_data()
    context_content = stored(data, SUPPLEMENTAL_CONTEXT_ROLE)
    evidence_content = stored(data, CONSTRUCTION_EVIDENCE_ROLE)
    set_content(data, SUPPLEMENTAL_CONTEXT_ROLE, evidence_content)
    set_content(data, CONSTRUCTION_EVIDENCE_ROLE, context_content)
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


@pytest.mark.parametrize(
    "field, value",
    [
        ("size_bytes", 1),
        ("content_sha256", NOT_A_HASH),
        ("relative_path", CONSTRUCTION_EVIDENCE_FILENAME),
    ],
)
def test_manifest_descriptor_mismatch_is_rejected(field, value):
    data = bundle_data()
    manifest = json.loads(stored(data, MANIFEST_ROLE))
    manifest["payload_files"][0][field] = value
    if field == "content_sha256":
        manifest["payload_files"][0]["semantic_identity_sha256"] = value
        manifest["supplemental_context_sha256"] = value
    mutated = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    assert_bundle_invalid(
        validate_approved_change_artifact_bundle(set_content(data, MANIFEST_ROLE, mutated))
    )


def test_descriptor_content_and_semantic_identity_must_agree():
    with pytest.raises(ValidationError):
        ApprovedChangeArtifactBundlePayloadFile(
            relative_path=SUPPLEMENTAL_CONTEXT_FILENAME,
            role=SUPPLEMENTAL_CONTEXT_ROLE,
            size_bytes=10,
            content_sha256="a" * 64,
            semantic_identity_sha256="b" * 64,
        )


def test_logical_file_metadata_must_match_its_content():
    content = '{"a":1}'
    with pytest.raises(ValidationError):
        ApprovedChangeArtifactBundleFile(
            relative_path=MANIFEST_FILENAME,
            role=MANIFEST_ROLE,
            content_utf8=content,
            size_bytes=len(content) + 1,
            sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        )
    with pytest.raises(ValidationError):
        ApprovedChangeArtifactBundleFile(
            relative_path=MANIFEST_FILENAME,
            role=MANIFEST_ROLE,
            content_utf8=content,
            size_bytes=len(content),
            sha256=NOT_A_HASH,
        )


# --------------------------------------------------------------------------
# Tampering
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "role, path, value",
    [
        (APPROVED_CHANGE_SUBJECT_ROLE, ("blast_radius",), "a widened blast radius"),
        (APPROVED_CHANGE_SUBJECT_ROLE, ("risk",), "low"),
        (CONSTRUCTION_EVIDENCE_ROLE, ("subject_sha256",), NOT_A_HASH),
        (CONSTRUCTION_EVIDENCE_ROLE, ("supplemental_context_sha256",), NOT_A_HASH),
    ],
)
def test_payload_tampering_is_rejected(role, path, value):
    data = bundle_data()
    payload = json.loads(stored(data, role))
    cursor = payload
    for key in path[:-1]:
        cursor = cursor[key]
    if cursor[path[-1]] == value:
        pytest.skip("tamper value equals the canonical value")
    cursor[path[-1]] = value
    mutated = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    assert_bundle_invalid(
        validate_approved_change_artifact_bundle(set_content(data, role, mutated))
    )


def test_reviewed_context_value_tampering_is_rejected():
    data = bundle_data()
    content = stored(data, SUPPLEMENTAL_CONTEXT_ROLE)
    mutated = content.replace(
        "restore the reviewed healthy state", "restore some other reviewed state"
    )
    assert mutated != content
    result = validate_approved_change_artifact_bundle(
        set_content(data, SUPPLEMENTAL_CONTEXT_ROLE, mutated)
    )
    assert_bundle_invalid(result)
    assert any("does not match the subject reconstructed" in error for error in result.errors)


def test_content_tampering_without_metadata_refresh_is_rejected():
    data = bundle_data()
    entry = files_by_role(data)[APPROVED_CHANGE_SUBJECT_ROLE]
    entry["content_utf8"] = entry["content_utf8"].replace("medium", "low", 1)
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


@pytest.mark.parametrize(
    "field, value",
    [
        ("kind", "some_other_bundle_kind"),
        ("schema_version", "2"),
        ("publication_policy", "write_directly"),
        ("atomicity_policy", "best_effort"),
        ("overwrite_policy", "allow"),
        ("existing_identical_policy", "overwrite"),
        ("destination_policy", "caller_supplied_directory"),
        ("manifest_filename", "bundle-manifest.json"),
        ("supplemental_context_schema_version", "2"),
        ("approved_change_schema_version", "2"),
        ("construction_policy_schema_version", "2"),
        ("construction_evidence_schema_version", "2"),
    ],
)
def test_manifest_metadata_tampering_is_rejected(field, value):
    data = bundle_data()
    manifest = json.loads(stored(data, MANIFEST_ROLE))
    manifest[field] = value
    mutated = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    assert_bundle_invalid(
        validate_approved_change_artifact_bundle(set_content(data, MANIFEST_ROLE, mutated))
    )


def test_manifest_warning_tampering_is_rejected():
    data = bundle_data()
    manifest = json.loads(stored(data, MANIFEST_ROLE))
    manifest["warnings"] = ["this bundle is approved"]
    mutated = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    assert_bundle_invalid(
        validate_approved_change_artifact_bundle(set_content(data, MANIFEST_ROLE, mutated))
    )

    dropped = bundle_data()
    payload = json.loads(stored(dropped, MANIFEST_ROLE))
    payload["warnings"] = payload["warnings"][:-1]
    assert_bundle_invalid(
        validate_approved_change_artifact_bundle(
            set_content(
                dropped,
                MANIFEST_ROLE,
                json.dumps(payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True),
            )
        )
    )


def test_bundle_identity_and_bundle_id_tampering_is_rejected():
    data = bundle_data()
    data["bundle_identity_sha256"] = NOT_A_HASH
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))

    other = bundle_data()
    other["bundle_id"] = f"acb_{NOT_A_HASH}"
    assert_bundle_invalid(validate_approved_change_artifact_bundle(other))

    truncated = bundle_data()
    truncated["bundle_id"] = f"acb_{truncated['bundle_identity_sha256'][:16]}"
    assert_bundle_invalid(validate_approved_change_artifact_bundle(truncated))

    consistent = bundle_data()
    consistent["bundle_identity_sha256"] = NOT_A_HASH
    consistent["bundle_id"] = f"acb_{NOT_A_HASH}"
    assert_bundle_invalid(validate_approved_change_artifact_bundle(consistent))


def test_manifest_identity_tampering_is_rejected():
    data = bundle_data()
    manifest = json.loads(stored(data, MANIFEST_ROLE))
    manifest["bundle_identity_sha256"] = NOT_A_HASH
    manifest["bundle_id"] = f"acb_{NOT_A_HASH}"
    mutated = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    assert_bundle_invalid(
        validate_approved_change_artifact_bundle(set_content(data, MANIFEST_ROLE, mutated))
    )


def test_bundle_schema_version_tampering_is_rejected():
    data = bundle_data()
    data["schema_version"] = "2"
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


# --------------------------------------------------------------------------
# Mixed fixtures
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "roles",
    [
        pytest.param((APPROVED_CHANGE_SUBJECT_ROLE,), id="subject-from-b"),
        pytest.param((CONSTRUCTION_EVIDENCE_ROLE,), id="evidence-from-b"),
        pytest.param((SUPPLEMENTAL_CONTEXT_ROLE,), id="context-from-b"),
        pytest.param(
            (APPROVED_CHANGE_SUBJECT_ROLE, CONSTRUCTION_EVIDENCE_ROLE), id="subject-evidence-from-b"
        ),
        pytest.param((MANIFEST_ROLE,), id="manifest-from-b"),
    ],
)
def test_mixed_artifacts_from_two_fixtures_are_rejected(roles):
    data = bundle_data()
    other = bundle_data(context_b())
    for role in roles:
        set_content(data, role, stored(other, role))
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


def test_manifest_a_around_payloads_b_is_rejected():
    data = bundle_data(context_b())
    reference = bundle_data()
    set_content(data, MANIFEST_ROLE, stored(reference, MANIFEST_ROLE))
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


def test_same_subject_semantics_with_changed_provenance_is_rejected():
    fixture = context()
    alternate = context_alt_provenance()
    assert identities(fixture)[1] == identities(alternate)[1]
    assert identities(fixture)[0] != identities(alternate)[0]
    assert identities(fixture)[2] != identities(alternate)[2]

    data = bundle_data(fixture)
    other = bundle_data(alternate)
    assert stored(data, APPROVED_CHANGE_SUBJECT_ROLE) == stored(other, APPROVED_CHANGE_SUBJECT_ROLE)
    set_content(data, SUPPLEMENTAL_CONTEXT_ROLE, stored(other, SUPPLEMENTAL_CONTEXT_ROLE))
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


def test_evidence_from_another_construction_is_rejected():
    data = bundle_data()
    other = bundle_data(context_alt_provenance())
    set_content(data, CONSTRUCTION_EVIDENCE_ROLE, stored(other, CONSTRUCTION_EVIDENCE_ROLE))
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


def test_stale_expected_identities_from_another_fixture_block_the_builder():
    fixture = context()
    stale = identities(context_alt_provenance())
    assert_build_blocked(build(fixture, context_sha=stale[0]))
    assert_build_blocked(build(fixture, evidence_sha=stale[2]))


# --------------------------------------------------------------------------
# Identity chain
# --------------------------------------------------------------------------


def test_identity_chain_agrees_across_manifest_context_subject_and_evidence():
    fixture = context()
    context_sha256, subject_sha256, evidence_sha256 = identities(fixture)
    result = build(fixture)
    manifest = result.manifest
    construction = construct_approved_change_subject(
        fixture, expected_supplemental_context_sha256=context_sha256
    )
    stored_evidence = construction.construction_evidence

    assert manifest.supplemental_context_sha256 == context_sha256
    assert manifest.supplemental_context_sha256 == stored_evidence.supplemental_context_sha256
    assert manifest.subject_sha256 == subject_sha256
    assert manifest.subject_sha256 == stored_evidence.subject_sha256
    assert manifest.subject_sha256 == compute_subject_sha256(construction.subject)
    assert manifest.construction_evidence_sha256 == evidence_sha256
    assert manifest.construction_evidence_sha256 == compute_construction_evidence_sha256(
        stored_evidence
    )
    assert (
        len({context_sha256, subject_sha256, evidence_sha256, manifest.bundle_identity_sha256}) == 4
    )


# --------------------------------------------------------------------------
# Non-circular bundle identity
# --------------------------------------------------------------------------


def test_bundle_identity_and_bundle_id_are_deterministic():
    first = build()
    second = build()
    assert first.bundle_identity_sha256 == second.bundle_identity_sha256
    assert first.bundle_id == second.bundle_id
    assert canonical_bundle_manifest_json(first.manifest) == canonical_bundle_manifest_json(
        second.manifest
    )
    for left, right in zip(first.bundle.files, second.bundle.files, strict=True):
        assert left.content_utf8 == right.content_utf8
        assert left.size_bytes == right.size_bytes
        assert left.sha256 == right.sha256


def test_bundle_identity_payload_excludes_its_own_identity_fields():
    manifest = build().manifest
    payload = canonical_bundle_manifest_identity_payload(manifest)
    identity_json = canonical_bundle_manifest_identity_json(manifest)
    assert BUNDLE_IDENTITY_EXCLUDED_FIELDS == ("bundle_id", "bundle_identity_sha256")
    for excluded in BUNDLE_IDENTITY_EXCLUDED_FIELDS:
        assert excluded not in payload
        assert f'"{excluded}":' not in identity_json
    assert manifest.bundle_identity_sha256 not in identity_json
    assert manifest.bundle_id not in identity_json
    assert '"bundle_identity_sha256":' in canonical_bundle_manifest_json(manifest)
    assert '"bundle_id":' in canonical_bundle_manifest_json(manifest)
    assert compute_bundle_identity_sha256(manifest) == manifest.bundle_identity_sha256


def test_bundle_identity_ignores_changes_to_the_excluded_fields():
    manifest = build().manifest
    base = compute_bundle_identity_sha256(manifest)
    fields = manifest.model_dump(mode="python")
    fields["bundle_identity_sha256"] = NOT_A_HASH
    fields["bundle_id"] = f"acb_{NOT_A_HASH}"
    assert compute_bundle_identity_sha256(fields) == base


@pytest.mark.parametrize(
    "field, value",
    [
        ("schema_version", "2"),
        ("kind", "other_kind"),
        ("supplemental_context_schema_version", "2"),
        ("approved_change_schema_version", "2"),
        ("construction_policy_schema_version", "2"),
        ("construction_evidence_schema_version", "2"),
        ("supplemental_context_sha256", NOT_A_HASH),
        ("subject_sha256", NOT_A_HASH),
        ("construction_evidence_sha256", NOT_A_HASH),
        ("manifest_filename", "other-manifest.json"),
        ("publication_policy", "write_directly"),
        ("atomicity_policy", "best_effort"),
        ("overwrite_policy", "allow"),
        ("existing_identical_policy", "overwrite"),
        ("destination_policy", "caller_supplied_directory"),
        ("warnings", ["this bundle is approved"]),
    ],
)
def test_bundle_identity_changes_with_every_covered_manifest_field(field, value):
    manifest = build().manifest
    base = manifest_fields(manifest)
    assert compute_bundle_identity_sha256(base) == manifest.bundle_identity_sha256
    changed = copy.deepcopy(base)
    changed[field] = value
    assert compute_bundle_identity_sha256(changed) != manifest.bundle_identity_sha256


@pytest.mark.parametrize(
    "field, value",
    [
        ("relative_path", "renamed.json"),
        ("role", "other_role"),
        ("size_bytes", 1),
        ("content_sha256", NOT_A_HASH),
        ("semantic_identity_sha256", NOT_A_HASH),
    ],
)
def test_bundle_identity_changes_with_every_payload_descriptor_field(field, value):
    manifest = build().manifest
    base = manifest_fields(manifest)
    changed = copy.deepcopy(base)
    changed["payload_files"][0][field] = value
    assert compute_bundle_identity_sha256(changed) != manifest.bundle_identity_sha256


def test_bundle_identity_changes_when_payload_order_changes():
    manifest = build().manifest
    base = manifest_fields(manifest)
    changed = copy.deepcopy(base)
    changed["payload_files"] = list(reversed(changed["payload_files"]))
    assert compute_bundle_identity_sha256(changed) != manifest.bundle_identity_sha256


def test_different_fixtures_produce_different_bundle_identities():
    first = build()
    second = build(context_b())
    third = build(context_alt_provenance())
    identities_seen = {
        first.bundle_identity_sha256,
        second.bundle_identity_sha256,
        third.bundle_identity_sha256,
    }
    assert len(identities_seen) == 3


def test_bundle_id_is_never_a_semantic_identity():
    fixture = context()
    context_sha256, subject_sha256, evidence_sha256 = identities(fixture)
    result = build(fixture)
    assert result.bundle_identity_sha256 not in {context_sha256, subject_sha256, evidence_sha256}
    assert result.bundle_id != subject_sha256
    assert derive_bundle_id(result.bundle_identity_sha256) == result.bundle_id


# --------------------------------------------------------------------------
# Cross-platform determinism
# --------------------------------------------------------------------------


def test_non_ascii_reviewed_text_is_stored_unescaped():
    result = build()
    content = {item.role: item.content_utf8 for item in result.bundle.files}
    assert "corrección descriptiva acotada" in content[SUPPLEMENTAL_CONTEXT_ROLE]
    assert "corrección descriptiva acotada" in content[APPROVED_CHANGE_SUBJECT_ROLE]
    assert "\\u00f3" not in content[APPROVED_CHANGE_SUBJECT_ROLE]
    assert "—" in content[APPROVED_CHANGE_SUBJECT_ROLE]


def test_equivalent_timezone_spelling_produces_identical_bytes():
    utc_result = build()
    offset_result = build(context_alt_timezone())
    assert offset_result.status == "bundle_constructed"
    assert offset_result.bundle_identity_sha256 == utc_result.bundle_identity_sha256
    assert offset_result.bundle_id == utc_result.bundle_id
    for left, right in zip(utc_result.bundle.files, offset_result.bundle.files, strict=True):
        assert left.content_utf8 == right.content_utf8
        assert left.size_bytes == right.size_bytes
        assert left.sha256 == right.sha256


@pytest.mark.parametrize(
    "fixture_factory",
    [
        pytest.param(
            lambda: context(
                explicit=explicit_reviews(target=target((("host", "docker01"), ("id", "abc123"))))
            ),
            id="target-identity-claims",
        ),
        pytest.param(
            lambda: context(
                explicit=explicit_reviews(evidence_references=evidence(("ev-2", "ev-1")))
            ),
            id="evidence-references",
        ),
    ],
)
def test_set_like_input_order_does_not_change_any_bundle_byte(fixture_factory):
    base = build()
    reordered = build(fixture_factory())
    assert reordered.status == "bundle_constructed"
    assert reordered.bundle_identity_sha256 == base.bundle_identity_sha256
    for left, right in zip(base.bundle.files, reordered.bundle.files, strict=True):
        assert left.content_utf8 == right.content_utf8


@pytest.mark.parametrize(
    "fixture_factory",
    [
        pytest.param(
            lambda: context(explicit=explicit_reviews(procedure=steps(("step-2", "step-1")))),
            id="procedure",
        ),
        pytest.param(
            lambda: context(
                explicit=explicit_reviews(rollback_posture=rollback(("rollback-2", "rollback-1")))
            ),
            id="rollback-procedure",
        ),
        pytest.param(
            lambda: context(
                candidates=candidate_reviews(
                    preconditions=candidate(
                        "preconditions",
                        value=tuple(reversed(CANDIDATE_VALUES_A["preconditions"])),
                    )
                )
            ),
            id="preconditions",
        ),
        pytest.param(
            lambda: context(
                candidates=candidate_reviews(
                    verification_criteria=candidate(
                        "verification_criteria",
                        value=tuple(reversed(CANDIDATE_VALUES_A["verification_criteria"])),
                    )
                )
            ),
            id="verification-criteria",
        ),
    ],
)
def test_semantic_sequence_order_changes_every_bundle_identity(fixture_factory):
    base = build()
    reordered = build(fixture_factory())
    assert reordered.status == "bundle_constructed"
    assert reordered.bundle_identity_sha256 != base.bundle_identity_sha256
    assert reordered.computed_subject_sha256 != base.computed_subject_sha256


def test_bundle_bytes_carry_no_platform_specific_line_endings_or_separators():
    for logical in build().bundle.files:
        assert "\r\n" not in logical.content_utf8
        assert "\n" not in logical.content_utf8
        assert "\\" not in logical.content_utf8.replace('\\"', "")
        assert logical.content_utf8.encode("utf-8").decode("utf-8") == logical.content_utf8


# --------------------------------------------------------------------------
# Manifest self-canonicalization
# --------------------------------------------------------------------------


def test_manifest_reserialization_equals_the_stored_manifest_bytes():
    result = build()
    stored_manifest = result.bundle.files[3]
    reparsed = ApprovedChangeArtifactBundleManifest.model_validate(
        json.loads(stored_manifest.content_utf8)
    )
    assert canonical_bundle_manifest_json(reparsed) == stored_manifest.content_utf8
    assert stored_manifest.size_bytes == len(stored_manifest.content_utf8.encode("utf-8"))
    assert (
        stored_manifest.sha256
        == hashlib.sha256(stored_manifest.content_utf8.encode("utf-8")).hexdigest()
    )


def test_manifest_never_contains_its_own_checksum():
    result = build()
    stored_manifest = result.bundle.files[3]
    assert stored_manifest.sha256 not in stored_manifest.content_utf8
    field_names = set(ApprovedChangeArtifactBundleManifest.model_fields)
    assert "manifest_sha256" not in field_names
    assert "manifest_content_sha256" not in field_names
    assert "self_sha256" not in field_names
    assert MANIFEST_FILENAME not in {item.relative_path for item in result.manifest.payload_files}


def test_manifest_forbids_extra_fields():
    data = bundle_data()
    manifest = json.loads(stored(data, MANIFEST_ROLE))
    manifest["extra_manifest_claim"] = "approved"
    mutated = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    assert_bundle_invalid(
        validate_approved_change_artifact_bundle(set_content(data, MANIFEST_ROLE, mutated))
    )


# --------------------------------------------------------------------------
# Semantic separation
# --------------------------------------------------------------------------


def test_permanent_warnings_state_the_full_semantic_boundary():
    joined = " ".join(PERMANENT_BUNDLE_WARNINGS)
    for phrase in (
        "not approval",
        "authorization",
        "ApprovedChangeContract",
        "reviewer provenance is not authenticated identity",
        "bundle identity is not subject identity",
        "capability support",
        "not persistence",
        "execution confirmation",
        "no execution eligibility",
        "reviewed before sharing",
        "no redaction is performed",
    ):
        assert phrase in joined


def test_reviewed_by_never_becomes_approved_by():
    result = build()
    for logical in result.bundle.files:
        payload = logical.content_utf8
        assert '"approved_by"' not in payload
        assert '"approved_at"' not in payload
        assert '"approval"' not in payload
        assert '"scope":"exact_subject_only"' not in payload
    assert '"reviewed_by":"operator-a"' in result.bundle.files[0].content_utf8
    assert '"reviewed_by":"operator-a"' in result.bundle.files[2].content_utf8
    assert "reviewed_by" not in result.bundle.files[1].content_utf8


def test_bundle_creates_no_approval_contract_receipt_or_capability_binding():
    result = build()
    assert result.manifest_constructed is True
    assert_permanent_safety(result)
    assert_permanent_safety(validate_approved_change_artifact_bundle(result.bundle))
    assert not hasattr(bundle_module, "ApprovalAttestation")
    assert not hasattr(bundle_module, "ApprovedChangeContract")


def test_publication_metadata_is_not_execution_authorization():
    result = build()
    assert result.manifest.publication_policy == PUBLICATION_POLICY
    assert result.manifest.overwrite_policy == OVERWRITE_POLICY
    assert result.publication_performed is False
    assert result.overwrite_performed is False
    assert result.execution_allowed is False
    assert result.execution_status == "not_executed"


def test_in_memory_bundle_construction_is_not_persistence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = build()
    assert result.persistence_performed is False
    assert result.artifact_write_performed is False
    assert result.filesystem_accessed is False
    assert list(tmp_path.iterdir()) == []


# --------------------------------------------------------------------------
# Structured invalid input
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bad_input", [None, "bundle", 7, [], (), object(), b"{}", 3.5])
def test_non_mapping_validation_input_is_structured_invalid(bad_input):
    result = validate_approved_change_artifact_bundle(bad_input)
    assert_bundle_invalid(result, expected_status="invalid_bundle_validation_input")


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"files": []},
        {"files": [{}]},
        {"bundle_id": "acb_", "files": []},
        {"schema_version": "1", "files": "not-a-list"},
        {"files": [{"relative_path": "manifest.json"}]},
    ],
)
def test_malformed_validation_dictionaries_return_structured_results(data):
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


def test_partial_bundle_is_rejected():
    data = bundle_data()
    data["files"] = data["files"][:2]
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))


def test_extra_model_fields_are_rejected_not_repaired():
    data = bundle_data()
    data["published_to"] = "/var/lib/shellforgeai/bundles"
    assert_bundle_invalid(validate_approved_change_artifact_bundle(data))

    other = bundle_data()
    other["files"][0]["absolute_path"] = "/tmp/supplemental-context.json"
    assert_bundle_invalid(validate_approved_change_artifact_bundle(other))


@pytest.mark.parametrize("bad_input", [None, "context", 7, [], object(), b"{}"])
def test_non_mapping_build_input_is_structured_invalid(bad_input):
    assert_build_blocked(
        build_approved_change_artifact_bundle(
            bad_input,
            expected_supplemental_context_sha256=NOT_A_HASH,
            expected_subject_sha256=NOT_A_HASH,
            expected_construction_evidence_sha256=NOT_A_HASH,
        ),
        expected_status="invalid_bundle_construction_input",
    )


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"explicit_context_reviews": []},
        {"legacy_candidate_reviews": []},
        {"explicit_context_reviews": "x", "legacy_candidate_reviews": 3},
        {"explicit_context_reviews": [{"destination_field": "unknown_field"}]},
    ],
)
def test_malformed_build_dictionaries_return_structured_results(data):
    assert_build_blocked(
        build_approved_change_artifact_bundle(
            data,
            expected_supplemental_context_sha256=NOT_A_HASH,
            expected_subject_sha256=NOT_A_HASH,
            expected_construction_evidence_sha256=NOT_A_HASH,
        )
    )


def test_valid_dictionary_context_input_matches_model_input():
    fixture = context()
    context_sha256, subject_sha256, evidence_sha256 = identities(fixture)
    from_model = build(fixture)
    from_dict = build_approved_change_artifact_bundle(
        fixture.model_dump(mode="json"),
        expected_supplemental_context_sha256=context_sha256,
        expected_subject_sha256=subject_sha256,
        expected_construction_evidence_sha256=evidence_sha256,
    )
    assert from_model.status == from_dict.status == "bundle_constructed"
    assert from_model.bundle_id == from_dict.bundle_id
    assert from_model.bundle == from_dict.bundle


def test_incomplete_context_blocks_construction():
    fixture = context(explicit=explicit_reviews()[:3])
    assert_build_blocked(
        build_approved_change_artifact_bundle(
            fixture,
            expected_supplemental_context_sha256=compute_supplemental_context_sha256(fixture),
            expected_subject_sha256=NOT_A_HASH,
            expected_construction_evidence_sha256=NOT_A_HASH,
        ),
        expected_status="bundle_construction_blocked",
    )


def test_errors_are_deterministic_sorted_and_deduplicated():
    first = validate_approved_change_artifact_bundle({"files": []})
    second = validate_approved_change_artifact_bundle({"files": []})
    assert first.errors == second.errors
    assert list(first.errors) == sorted(set(first.errors))


def test_public_entry_points_never_raise_for_untrusted_input():
    for bad in (None, {}, [], "x", 3, object(), {"files": None}):
        assert isinstance(
            validate_approved_change_artifact_bundle(bad),
            ApprovedChangeArtifactBundleValidationResult,
        )
        for expected in (None, "", NOT_A_HASH, "ZZ", 5):
            result = build_approved_change_artifact_bundle(
                bad,
                expected_supplemental_context_sha256=expected,
                expected_subject_sha256=expected,
                expected_construction_evidence_sha256=expected,
            )
            assert isinstance(result, ApprovedChangeArtifactBundleBuildResult)
            assert result.build_succeeded is False


# --------------------------------------------------------------------------
# Immutability
# --------------------------------------------------------------------------


def test_bundle_manifest_files_and_results_are_frozen():
    result = build()
    with pytest.raises(ValidationError):
        result.status = "bundle_construction_blocked"
    with pytest.raises(ValidationError):
        result.bundle.bundle_id = "acb_other"
    with pytest.raises(ValidationError):
        result.bundle.files[0].content_utf8 = "{}"
    with pytest.raises(ValidationError):
        result.manifest.overwrite_policy = "allow"
    with pytest.raises(ValidationError):
        result.manifest.payload_files[0].size_bytes = 1
    validation = validate_approved_change_artifact_bundle(result.bundle)
    with pytest.raises(ValidationError):
        validation.bundle_valid = False


def test_nested_tuples_and_fixed_warnings_cannot_be_modified():
    result = build()
    assert isinstance(result.bundle.files, tuple)
    assert isinstance(result.manifest.payload_files, tuple)
    assert isinstance(result.manifest.warnings, tuple)
    assert isinstance(result.warnings, tuple)
    assert isinstance(PERMANENT_BUNDLE_WARNINGS, tuple)
    with pytest.raises(AttributeError):
        result.bundle.files.append(result.bundle.files[0])
    with pytest.raises(AttributeError):
        result.manifest.payload_files.append(result.manifest.payload_files[0])
    with pytest.raises(AttributeError):
        result.manifest.warnings.append("extra warning")


def test_reused_fixture_is_not_mutated_by_bundle_construction():
    fixture = context()
    before = fixture.model_dump(mode="json")
    build(fixture)
    validate_approved_change_artifact_bundle(build(fixture).bundle)
    assert fixture.model_dump(mode="json") == before


# --------------------------------------------------------------------------
# Purity: runtime side-effect guards
# --------------------------------------------------------------------------


def test_no_side_effects_on_success_or_failure_paths(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("side effect attempted")

    monkeypatch.setattr(Path, "read_text", boom)
    monkeypatch.setattr(Path, "write_text", boom)
    monkeypatch.setattr(Path, "read_bytes", boom)
    monkeypatch.setattr(Path, "write_bytes", boom)
    monkeypatch.setattr(Path, "open", boom)
    monkeypatch.setattr(Path, "mkdir", boom)
    monkeypatch.setattr(Path, "exists", boom)
    monkeypatch.setattr(Path, "rename", boom)
    monkeypatch.setattr(Path, "replace", boom)
    monkeypatch.setattr(Path, "unlink", boom)
    monkeypatch.setattr(os, "replace", boom)
    monkeypatch.setattr(os, "rename", boom)
    monkeypatch.setattr(os, "mkdir", boom)
    monkeypatch.setattr(os, "makedirs", boom)
    monkeypatch.setattr(os, "fsync", boom)
    monkeypatch.setattr(os, "system", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)

    before = dict(os.environ)
    result = build()
    assert result.status == "bundle_constructed"
    assert validate_approved_change_artifact_bundle(result.bundle).status == "bundle_valid"
    assert build(context_sha=NOT_A_HASH).build_succeeded is False
    assert validate_approved_change_artifact_bundle({}).bundle_valid is False
    assert dict(os.environ) == before


def test_build_and_validation_create_no_files_or_directories(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = build()
    validate_approved_change_artifact_bundle(result.bundle)
    validate_approved_change_artifact_bundle(result.bundle.model_dump(mode="json"))
    build(context_sha=NOT_A_HASH)
    assert list(tmp_path.iterdir()) == []
    assert list(tmp_path.glob("**/*")) == []


# --------------------------------------------------------------------------
# Purity: static source guards
# --------------------------------------------------------------------------


def module_tree_without_docstrings():
    """Return the production module's AST with docstrings removed."""
    tree = ast.parse(Path(bundle_module.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef):
            continue
        first = node.body[0] if node.body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            node.body.pop(0)
            if not node.body:
                node.body.append(ast.Pass())
    return tree


def module_code_without_docstrings():
    """Return the production module's executable code with docstrings removed."""
    return ast.unparse(module_tree_without_docstrings())


def module_code_without_strings():
    """Return executable code with docstrings removed and string literals blanked.

    Fixed policy, warning, and filename literals must never satisfy an
    identifier guard, so the guards below scan code only.
    """
    tree = module_tree_without_docstrings()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            node.value = ""
    return ast.unparse(tree)


def test_static_no_filesystem_or_writer_surface():
    source = module_code_without_strings()
    for token in (
        "pathlib",
        "Path",
        "open(",
        "read_text",
        "write_text",
        "read_bytes",
        "write_bytes",
        "shutil",
        "tempfile",
        "mkdtemp",
        "mkdir",
        "makedirs",
        "fsync",
        "os.replace",
        "os.rename",
        "rmtree",
        "unlink",
        "remove(",
        "glob",
        "listdir",
        "scandir",
        "exists(",
        "json.dump(",
        "json.load(",
    ):
        assert token not in source, token


def test_static_no_execution_network_model_or_randomness():
    source = module_code_without_strings()
    for token in (
        "subprocess",
        "os.system",
        "socket",
        "docker",
        "compose",
        "powershell",
        "winrm",
        "qga",
        "os.environ",
        "getenv",
        "requests",
        "httpx",
        "urllib",
        "provider",
        "uuid",
        "random",
        "datetime.now",
        "utcnow",
        "now()",
        "time.time",
        "monotonic",
    ):
        assert token not in source, token


def test_static_no_approval_capability_receipt_or_cli_surface():
    source = module_code_without_strings()
    for token in (
        "Proposal",
        "core.approvals",
        "ApprovalAttestation",
        "ApprovedChangeContract",
        "verify_approval_binding",
        "capability_registry",
        "CAPABILITY_REGISTRY",
        "bind_capability",
        "evaluate_capability",
        "preflight",
        "receipt_linkage",
        "link_receipt",
        "windows.runtime_reconcile",
        "recipe",
        "RECIPE",
        "typer",
        "app.command",
        "save_",
        "persist_",
        "publish_",
        "write_artifact",
        "load_bundle",
    ):
        assert token not in source, token


def test_static_never_imports_or_names_approval_or_contract_types():
    tree = module_tree_without_docstrings()
    forbidden = {"ApprovalAttestation", "ApprovedChangeContract", "Proposal"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert forbidden.isdisjoint(alias.name for alias in node.names)
        if isinstance(node, ast.Name):
            assert node.id not in forbidden
        if isinstance(node, ast.Attribute):
            assert node.attr not in forbidden


def test_static_import_set_is_exactly_the_maintained_pure_dependencies():
    tree = ast.parse(Path(bundle_module.__file__).read_text(encoding="utf-8"))
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
        "re",
        "typing",
        "pydantic",
        "shellforgeai.core.approved_change_construction_policy",
        "shellforgeai.core.approved_change_contract",
        "shellforgeai.core.approved_change_subject_construction",
        "shellforgeai.core.approved_change_supplemental_context",
    }


def test_static_signatures_never_take_proposal_or_return_approval_types():
    for _, obj in inspect.getmembers(bundle_module, inspect.isfunction):
        signature = inspect.signature(obj)
        assert all(param.annotation is not Proposal for param in signature.parameters.values())
        assert signature.return_annotation not in {ApprovalAttestation, ApprovedChangeContract}
        assert "Proposal" not in str(signature)


def test_module_exposes_no_writer_loader_cli_or_registry_surface():
    for name in (
        "app",
        "cli",
        "main",
        "register",
        "REGISTRY",
        "CAPABILITY_REGISTRY",
        "write_approved_change_artifact_bundle",
        "publish_approved_change_artifact_bundle",
        "load_approved_change_artifact_bundle",
        "read_approved_change_artifact_bundle",
        "persist_bundle",
        "cleanup_bundle",
        "evaluate_capability_support",
        "bind_capability",
        "DATA_ROOT",
        "BUNDLE_ROOT",
    ):
        assert not hasattr(bundle_module, name)


def test_static_uses_only_the_maintained_canonical_serializers():
    source = module_code_without_docstrings()
    assert "canonical_supplemental_context_json(" in source
    assert "canonical_subject_json(" in source
    assert "canonical_construction_evidence_json(" in source
    assert "construct_approved_change_subject(" in source
    # Only the bundle manifest and its identity payload are serialized here; the
    # three semantic payloads use their maintained upstream serializers.
    assert source.count("json.dumps(") == 2
    assert source.count("json.loads(") == 1


def test_fixed_filenames_and_policies_are_literal_module_constants():
    source = module_code_without_docstrings()
    for literal in (
        "supplemental-context.json",
        "approved-change-subject.json",
        "construction-evidence.json",
        "manifest.json",
        "approved_change_reviewed_artifact_bundle",
        "prepare_verify_then_atomic_publish",
        "publish_complete_verified_bundle_with_one_final_directory_transition",
        "forbid",
        "validate_and_return_already_present",
        "fixed_full_bundle_id_directory",
        "acb_",
    ):
        assert literal in source
