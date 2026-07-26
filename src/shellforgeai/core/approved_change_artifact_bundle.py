"""Deterministic reviewed-change artifact bundle contract (PR316).

This module defines exactly one pure, immutable, deterministic,
checksum-protected, in-memory artifact bundle: the complete persistence payload
that a future governed writer would publish for one reviewed change.

A bundle holds exactly four canonical UTF-8 JSON logical files — the PR314
reviewed supplemental context, the PR309 constructed subject, the PR315
construction evidence, and a fixed deterministic manifest — plus their exact
byte lengths, exact content checksums, a non-circular bundle identity, and a
full-hash bundle ID.

It is deliberately inert. It touches no filesystem, creates no file or
directory, performs no persistence or publication, creates no approval,
``ApprovedChangeContract``, or receipt, evaluates or binds no capability, runs
no preflight, and enables no execution. It defines the persistence payload and
the future publication policy only; PR317 owns the governed writer and loader.

Private canonicalization helpers are imported from the PR309 contract module on
purpose: stored bundle bytes must obey exactly the same canonical ordering and
timestamp rules as the maintained upstream schemas.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from shellforgeai.core.approved_change_construction_policy import (
    CONSTRUCTION_POLICY_SCHEMA_VERSION,
)
from shellforgeai.core.approved_change_contract import (
    SCHEMA_VERSION as APPROVED_CHANGE_SCHEMA_VERSION,
)
from shellforgeai.core.approved_change_contract import (
    ApprovedChangeSubject,
    _canonicalize,
    canonical_subject_json,
    compute_subject_sha256,
)
from shellforgeai.core.approved_change_subject_construction import (
    CONSTRUCTION_EVIDENCE_SCHEMA_VERSION,
    ApprovedChangeSubjectConstructionEvidence,
    canonical_construction_evidence_json,
    compute_construction_evidence_sha256,
    construct_approved_change_subject,
)
from shellforgeai.core.approved_change_supplemental_context import (
    SUPPLEMENTAL_CONTEXT_SCHEMA_VERSION,
    ApprovedChangeSupplementalContext,
    canonical_supplemental_context_json,
    compute_supplemental_context_sha256,
    validate_approved_change_supplemental_context,
)

ARTIFACT_BUNDLE_SCHEMA_VERSION = "1"
ARTIFACT_BUNDLE_KIND = "approved_change_reviewed_artifact_bundle"
BUNDLE_ID_PREFIX = "acb_"
EXECUTION_STATUS_NOT_EXECUTED = "not_executed"

#: The exact fixed logical filenames. There is no caller-defined name, alias,
#: optional file, subdirectory, glob, case variant, or alternate extension.
SUPPLEMENTAL_CONTEXT_FILENAME = "supplemental-context.json"
APPROVED_CHANGE_SUBJECT_FILENAME = "approved-change-subject.json"
CONSTRUCTION_EVIDENCE_FILENAME = "construction-evidence.json"
MANIFEST_FILENAME = "manifest.json"

SUPPLEMENTAL_CONTEXT_ROLE = "supplemental_context"
APPROVED_CHANGE_SUBJECT_ROLE = "approved_change_subject"
CONSTRUCTION_EVIDENCE_ROLE = "construction_evidence"
MANIFEST_ROLE = "manifest"

#: The three semantic payload files, in their exact fixed order.
PAYLOAD_FILE_ORDER: tuple[tuple[str, str], ...] = (
    (SUPPLEMENTAL_CONTEXT_FILENAME, SUPPLEMENTAL_CONTEXT_ROLE),
    (APPROVED_CHANGE_SUBJECT_FILENAME, APPROVED_CHANGE_SUBJECT_ROLE),
    (CONSTRUCTION_EVIDENCE_FILENAME, CONSTRUCTION_EVIDENCE_ROLE),
)
#: The complete four-file allowlist, in its exact fixed order.
BUNDLE_FILE_ORDER: tuple[tuple[str, str], ...] = (
    *PAYLOAD_FILE_ORDER,
    (MANIFEST_FILENAME, MANIFEST_ROLE),
)
PAYLOAD_FILENAMES: tuple[str, ...] = tuple(name for name, _ in PAYLOAD_FILE_ORDER)
PAYLOAD_ROLES: tuple[str, ...] = tuple(role for _, role in PAYLOAD_FILE_ORDER)
BUNDLE_FILENAMES: tuple[str, ...] = tuple(name for name, _ in BUNDLE_FILE_ORDER)
BUNDLE_ROLES: tuple[str, ...] = tuple(role for _, role in BUNDLE_FILE_ORDER)

#: Fixed future-writer semantics. PR316 records them as contract metadata only
#: and implements none of them.
PUBLICATION_POLICY = "prepare_verify_then_atomic_publish"
ATOMICITY_POLICY = "publish_complete_verified_bundle_with_one_final_directory_transition"
OVERWRITE_POLICY = "forbid"
EXISTING_IDENTICAL_POLICY = "validate_and_return_already_present"
DESTINATION_POLICY = "fixed_full_bundle_id_directory"

#: The two manifest fields that are never part of the bundle identity payload.
BUNDLE_IDENTITY_EXCLUDED_FIELDS: tuple[str, ...] = ("bundle_id", "bundle_identity_sha256")

BUILD_STATUSES = (
    "bundle_constructed",
    "bundle_construction_blocked",
    "invalid_bundle_construction_input",
)
VALIDATION_STATUSES = (
    "bundle_valid",
    "bundle_invalid",
    "invalid_bundle_validation_input",
)

BuildStatus = Literal[
    "bundle_constructed",
    "bundle_construction_blocked",
    "invalid_bundle_construction_input",
]
ValidationStatus = Literal[
    "bundle_valid",
    "bundle_invalid",
    "invalid_bundle_validation_input",
]

PERMANENT_BUNDLE_WARNINGS: tuple[str, ...] = (
    "a valid bundle is not approval, authorization, or an ApprovedChangeContract",
    "reviewer provenance is not authenticated identity",
    "bundle identity is not subject identity and is not capability support",
    "bundle construction is not persistence; publication policy metadata is not "
    "execution confirmation",
    "no execution eligibility is granted by a valid bundle",
    "reviewed artifacts may contain operational context and must be reviewed before sharing",
    "no redaction is performed because redaction would change reviewed identity",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_ROLE_BY_FILENAME: dict[str, str] = dict(BUNDLE_FILE_ORDER)


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Exact filename and role safety
# ---------------------------------------------------------------------------


def _relative_path_errors(value: str) -> list[str]:
    """Report every unsafe trait of a candidate logical filename."""
    if not isinstance(value, str) or not value:
        return ["bundle filename must be a non-empty string"]
    errors: list[str] = []
    if value != value.strip():
        errors.append("bundle filename must not carry leading or trailing whitespace")
    if not value.isascii():
        errors.append("bundle filename must be lowercase ASCII only")
    if "/" in value or "\\" in value:
        errors.append("bundle filename must not contain a path separator")
    if ".." in value:
        errors.append("bundle filename must not contain a parent-directory reference")
    if value.startswith(("/", "\\")) or _WINDOWS_DRIVE_RE.match(value):
        errors.append("bundle filename must not be an absolute, drive, or UNC path")
    if value != value.lower():
        errors.append("bundle filename must be lowercase")
    return errors


def _require_bundle_filename(value: str, allowed: tuple[str, ...]) -> str:
    """Require an exact, literal, path-safe logical filename."""
    errors = _relative_path_errors(value)
    if errors:
        raise ValueError("; ".join(errors))
    if value not in allowed:
        raise ValueError(f"bundle filename must be one of: {', '.join(allowed)}")
    return value


def _require_role(value: str, allowed: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"bundle role must be one of: {', '.join(allowed)}")
    return value


def _require_sha256(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value))


def _sha256_of_text(content_utf8: str) -> str:
    return hashlib.sha256(content_utf8.encode("utf-8")).hexdigest()


def _size_of_text(content_utf8: str) -> int:
    return len(content_utf8.encode("utf-8"))


# ---------------------------------------------------------------------------
# Logical file, payload descriptor, manifest, and bundle models
# ---------------------------------------------------------------------------


class ApprovedChangeArtifactBundleFile(_FrozenModel):
    """One immutable in-memory logical file. It is never a persisted file."""

    relative_path: str
    role: str
    content_utf8: str
    size_bytes: int
    sha256: str

    @field_validator("relative_path")
    @classmethod
    def _validate_relative_path(cls, value: str) -> str:
        return _require_bundle_filename(value, BUNDLE_FILENAMES)

    @field_validator("role")
    @classmethod
    def _validate_role(cls, value: str) -> str:
        return _require_role(value, BUNDLE_ROLES)

    @field_validator("sha256")
    @classmethod
    def _validate_sha256(cls, value: str) -> str:
        return _require_sha256(value, "logical file sha256")

    @model_validator(mode="after")
    def _validate_file_record(self) -> ApprovedChangeArtifactBundleFile:
        expected_role = _ROLE_BY_FILENAME[self.relative_path]
        if self.role != expected_role:
            raise ValueError(f"{self.relative_path} must use role {expected_role}")
        if self.size_bytes != _size_of_text(self.content_utf8):
            raise ValueError(f"{self.relative_path} size_bytes does not match the UTF-8 content")
        if self.sha256 != _sha256_of_text(self.content_utf8):
            raise ValueError(f"{self.relative_path} sha256 does not match the UTF-8 content")
        return self


class ApprovedChangeArtifactBundlePayloadFile(_FrozenModel):
    """One manifest descriptor for a canonical semantic payload file."""

    relative_path: str
    role: str
    size_bytes: int
    content_sha256: str
    semantic_identity_sha256: str

    @field_validator("relative_path")
    @classmethod
    def _validate_relative_path(cls, value: str) -> str:
        return _require_bundle_filename(value, PAYLOAD_FILENAMES)

    @field_validator("role")
    @classmethod
    def _validate_role(cls, value: str) -> str:
        return _require_role(value, PAYLOAD_ROLES)

    @field_validator("content_sha256", "semantic_identity_sha256")
    @classmethod
    def _validate_sha256(cls, value: str) -> str:
        return _require_sha256(value, "payload descriptor sha256")

    @model_validator(mode="after")
    def _validate_descriptor(self) -> ApprovedChangeArtifactBundlePayloadFile:
        expected_role = _ROLE_BY_FILENAME[self.relative_path]
        if self.role != expected_role:
            raise ValueError(f"{self.relative_path} descriptor must use role {expected_role}")
        if self.size_bytes < 1:
            raise ValueError(f"{self.relative_path} descriptor size_bytes must be positive")
        if self.content_sha256 != self.semantic_identity_sha256:
            raise ValueError(
                f"{self.relative_path} canonical content checksum must equal its maintained "
                "semantic identity"
            )
        return self


class ApprovedChangeArtifactBundleManifest(_FrozenModel):
    """The fixed deterministic manifest describing the three payload files.

    The manifest never contains its own checksum. The top-level bundle file
    record protects the exact final manifest bytes, byte length, and checksum.
    """

    schema_version: Literal["1"] = ARTIFACT_BUNDLE_SCHEMA_VERSION
    kind: Literal["approved_change_reviewed_artifact_bundle"] = ARTIFACT_BUNDLE_KIND
    supplemental_context_schema_version: Literal["1"] = SUPPLEMENTAL_CONTEXT_SCHEMA_VERSION
    approved_change_schema_version: Literal["1"] = APPROVED_CHANGE_SCHEMA_VERSION
    construction_policy_schema_version: Literal["1"] = CONSTRUCTION_POLICY_SCHEMA_VERSION
    construction_evidence_schema_version: Literal["1"] = CONSTRUCTION_EVIDENCE_SCHEMA_VERSION
    supplemental_context_sha256: str
    subject_sha256: str
    construction_evidence_sha256: str
    payload_files: tuple[ApprovedChangeArtifactBundlePayloadFile, ...]
    manifest_filename: Literal["manifest.json"] = MANIFEST_FILENAME
    publication_policy: Literal["prepare_verify_then_atomic_publish"] = PUBLICATION_POLICY
    atomicity_policy: Literal[
        "publish_complete_verified_bundle_with_one_final_directory_transition"
    ] = ATOMICITY_POLICY
    overwrite_policy: Literal["forbid"] = OVERWRITE_POLICY
    existing_identical_policy: Literal["validate_and_return_already_present"] = (
        EXISTING_IDENTICAL_POLICY
    )
    destination_policy: Literal["fixed_full_bundle_id_directory"] = DESTINATION_POLICY
    warnings: tuple[str, ...] = PERMANENT_BUNDLE_WARNINGS
    bundle_identity_sha256: str
    bundle_id: str

    @field_validator(
        "supplemental_context_sha256",
        "subject_sha256",
        "construction_evidence_sha256",
        "bundle_identity_sha256",
    )
    @classmethod
    def _validate_sha256(cls, value: str) -> str:
        return _require_sha256(value, "manifest sha256")

    @model_validator(mode="after")
    def _validate_manifest(self) -> ApprovedChangeArtifactBundleManifest:
        object.__setattr__(self, "payload_files", tuple(self.payload_files))
        object.__setattr__(self, "warnings", tuple(self.warnings))
        if tuple(item.relative_path for item in self.payload_files) != PAYLOAD_FILENAMES:
            raise ValueError(
                "manifest must describe exactly the three payload files in their fixed order"
            )
        if tuple(item.role for item in self.payload_files) != PAYLOAD_ROLES:
            raise ValueError("manifest payload descriptors must use their exact fixed roles")
        if self.warnings != PERMANENT_BUNDLE_WARNINGS:
            raise ValueError("permanent bundle warnings may not be modified")
        semantic = {
            SUPPLEMENTAL_CONTEXT_ROLE: self.supplemental_context_sha256,
            APPROVED_CHANGE_SUBJECT_ROLE: self.subject_sha256,
            CONSTRUCTION_EVIDENCE_ROLE: self.construction_evidence_sha256,
        }
        for descriptor in self.payload_files:
            if descriptor.semantic_identity_sha256 != semantic[descriptor.role]:
                raise ValueError(
                    f"{descriptor.relative_path} descriptor identity does not match the "
                    "manifest semantic identity"
                )
        if self.bundle_id != derive_bundle_id(self.bundle_identity_sha256):
            raise ValueError("bundle_id must be the prefixed full bundle identity SHA-256")
        return self


class ApprovedChangeArtifactBundle(_FrozenModel):
    """The immutable four-file in-memory bundle. It has no host path."""

    schema_version: Literal["1"] = ARTIFACT_BUNDLE_SCHEMA_VERSION
    bundle_id: str
    bundle_identity_sha256: str
    files: tuple[ApprovedChangeArtifactBundleFile, ...]

    @field_validator("bundle_identity_sha256")
    @classmethod
    def _validate_sha256(cls, value: str) -> str:
        return _require_sha256(value, "bundle_identity_sha256")

    @model_validator(mode="after")
    def _validate_bundle(self) -> ApprovedChangeArtifactBundle:
        object.__setattr__(self, "files", tuple(self.files))
        if len(self.files) != len(BUNDLE_FILE_ORDER):
            raise ValueError(f"bundle must contain exactly {len(BUNDLE_FILE_ORDER)} logical files")
        if tuple(item.relative_path for item in self.files) != BUNDLE_FILENAMES:
            raise ValueError("bundle files must be the exact fixed filenames in their fixed order")
        if tuple(item.role for item in self.files) != BUNDLE_ROLES:
            raise ValueError("bundle files must use their exact fixed roles in their fixed order")
        if self.bundle_id != derive_bundle_id(self.bundle_identity_sha256):
            raise ValueError("bundle_id must be the prefixed full bundle identity SHA-256")
        return self


# ---------------------------------------------------------------------------
# Structured results
# ---------------------------------------------------------------------------


class ApprovedChangeArtifactBundleBuildResult(_FrozenModel):
    """Structured, non-throwing bundle-construction result.

    A successful result means only that a complete, canonical, internally
    consistent in-memory persistence payload exists. Nothing was written,
    published, approved, bound, or executed.
    """

    status: BuildStatus
    build_succeeded: bool
    expected_supplemental_context_sha256: str
    expected_subject_sha256: str
    expected_construction_evidence_sha256: str
    computed_supplemental_context_sha256: str
    computed_subject_sha256: str
    computed_construction_evidence_sha256: str
    bundle_identity_sha256: str
    bundle_id: str
    bundle: ApprovedChangeArtifactBundle | None = None
    manifest: ApprovedChangeArtifactBundleManifest | None = None
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_BUNDLE_WARNINGS
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    bundle_constructed: bool
    manifest_constructed: bool
    artifact_write_performed: Literal[False] = False
    filesystem_accessed: Literal[False] = False
    publication_performed: Literal[False] = False
    overwrite_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    approval_created: Literal[False] = False
    contract_created: Literal[False] = False
    receipt_created: Literal[False] = False
    capability_support_evaluated: Literal[False] = False
    capability_supported: Literal[False] = False
    approval_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


class ApprovedChangeArtifactBundleValidationResult(_FrozenModel):
    """Structured, non-throwing bundle-validation result."""

    status: ValidationStatus
    bundle_valid: bool
    bundle_id: str
    bundle_identity_sha256: str
    computed_bundle_identity_sha256: str
    computed_supplemental_context_sha256: str
    computed_subject_sha256: str
    computed_construction_evidence_sha256: str
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_BUNDLE_WARNINGS
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    artifact_write_performed: Literal[False] = False
    filesystem_accessed: Literal[False] = False
    publication_performed: Literal[False] = False
    overwrite_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    approval_created: Literal[False] = False
    contract_created: Literal[False] = False
    receipt_created: Literal[False] = False
    capability_support_evaluated: Literal[False] = False
    capability_supported: Literal[False] = False
    approval_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


# ---------------------------------------------------------------------------
# Canonical manifest and non-circular bundle identity
# ---------------------------------------------------------------------------


def canonical_bundle_manifest_identity_payload(
    manifest: ApprovedChangeArtifactBundleManifest | dict[str, Any],
) -> dict[str, Any]:
    """Return the canonical bundle-identity payload.

    The payload is exactly the canonical manifest payload minus
    ``bundle_identity_sha256`` and ``bundle_id``, so the bundle identity can
    never hash itself. It binds the bundle schema version, the manifest kind,
    every upstream schema version, the three semantic identities, the exact
    payload filenames, roles, byte lengths and content checksums, the manifest
    filename, the fixed publication/atomicity/overwrite/existing-identical/
    destination policies, and the permanent warnings.
    """
    if isinstance(manifest, ApprovedChangeArtifactBundleManifest):
        fields: dict[str, Any] = manifest.model_dump(mode="python")
    else:
        fields = dict(manifest)
    for excluded in BUNDLE_IDENTITY_EXCLUDED_FIELDS:
        fields.pop(excluded, None)
    return _canonicalize(fields)


def canonical_bundle_manifest_identity_json(
    manifest: ApprovedChangeArtifactBundleManifest | dict[str, Any],
) -> str:
    """Return deterministic canonical bundle-identity JSON."""
    return json.dumps(
        canonical_bundle_manifest_identity_payload(manifest),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_bundle_identity_sha256(
    manifest: ApprovedChangeArtifactBundleManifest | dict[str, Any],
) -> str:
    """Compute the full, untruncated bundle identity SHA-256.

    This identity is never a subject identity, a reviewed-context identity, a
    construction-evidence identity, an approval identity, capability support, or
    execution confirmation.
    """
    return hashlib.sha256(
        canonical_bundle_manifest_identity_json(manifest).encode("utf-8")
    ).hexdigest()


def derive_bundle_id(bundle_identity_sha256: str) -> str:
    """Derive the bundle ID from the full 64-character bundle identity."""
    return f"{BUNDLE_ID_PREFIX}{bundle_identity_sha256}"


def canonical_bundle_manifest_payload(
    manifest: ApprovedChangeArtifactBundleManifest,
) -> dict[str, Any]:
    """Return the deterministic canonical manifest payload."""
    return _canonicalize(manifest.model_dump(mode="python"))


def canonical_bundle_manifest_json(manifest: ApprovedChangeArtifactBundleManifest) -> str:
    """Return deterministic canonical manifest JSON (sorted keys, compact, UTF-8)."""
    return json.dumps(
        canonical_bundle_manifest_payload(manifest),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _logical_file(
    relative_path: str, role: str, content_utf8: str
) -> ApprovedChangeArtifactBundleFile:
    return ApprovedChangeArtifactBundleFile(
        relative_path=relative_path,
        role=role,
        content_utf8=content_utf8,
        size_bytes=_size_of_text(content_utf8),
        sha256=_sha256_of_text(content_utf8),
    )


# ---------------------------------------------------------------------------
# Fail-closed build results
# ---------------------------------------------------------------------------


def _echo(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _build_blocked(
    status: BuildStatus,
    errors: list[str],
    expected: dict[str, Any],
    *,
    context_sha256: str = "",
    subject_sha256: str = "",
    evidence_sha256: str = "",
) -> ApprovedChangeArtifactBundleBuildResult:
    """Return a fail-closed build result carrying no bundle and no manifest."""
    return ApprovedChangeArtifactBundleBuildResult(
        status=status,
        build_succeeded=False,
        expected_supplemental_context_sha256=_echo(
            expected.get("expected_supplemental_context_sha256")
        ),
        expected_subject_sha256=_echo(expected.get("expected_subject_sha256")),
        expected_construction_evidence_sha256=_echo(
            expected.get("expected_construction_evidence_sha256")
        ),
        computed_supplemental_context_sha256=context_sha256,
        computed_subject_sha256=subject_sha256,
        computed_construction_evidence_sha256=evidence_sha256,
        bundle_identity_sha256="",
        bundle_id="",
        bundle=None,
        manifest=None,
        errors=tuple(sorted(set(errors))),
        bundle_constructed=False,
        manifest_constructed=False,
    )


# ---------------------------------------------------------------------------
# Public bundle construction
# ---------------------------------------------------------------------------


def build_approved_change_artifact_bundle(
    context: ApprovedChangeSupplementalContext | dict[str, Any],
    *,
    expected_supplemental_context_sha256: str,
    expected_subject_sha256: str,
    expected_construction_evidence_sha256: str,
) -> ApprovedChangeArtifactBundleBuildResult:
    """Build exactly one immutable four-file in-memory artifact bundle.

    The only inputs are a reviewed PR314 supplemental context plus the three
    exact expected semantic identities. No caller-supplied subject, evidence,
    manifest, filename, bundle ID, bundle policy, legacy ``Proposal``, capability
    registry, approval data, or output path is accepted.

    The operation is pure and fail closed. Every failure returns a structured
    result carrying no bundle, no manifest, no bundle ID, no partial file tuple,
    and no persistence or artifact-write claim.
    """
    expected = {
        "expected_supplemental_context_sha256": expected_supplemental_context_sha256,
        "expected_subject_sha256": expected_subject_sha256,
        "expected_construction_evidence_sha256": expected_construction_evidence_sha256,
    }

    # 1. Every expected identity must be exactly 64 lowercase hexadecimal characters.
    format_errors = [
        f"{name} must be 64 lowercase hexadecimal characters"
        for name, value in sorted(expected.items())
        if not _is_sha256(value)
    ]
    if format_errors:
        return _build_blocked("invalid_bundle_construction_input", format_errors, expected)

    # 2. Fresh PR314 reviewed-context validation.
    if isinstance(context, ApprovedChangeSupplementalContext):
        parsed = context
    elif isinstance(context, dict):
        try:
            parsed = ApprovedChangeSupplementalContext.model_validate(context)
        except Exception as exc:  # pydantic exposes many structured subclasses.
            fallback = validate_approved_change_supplemental_context(context)
            return _build_blocked(
                "invalid_bundle_construction_input",
                [f"supplemental context model validation failed: {exc}", *fallback.errors],
                expected,
            )
    else:
        return _build_blocked(
            "invalid_bundle_construction_input",
            ["supplemental context must be a model instance or a mapping"],
            expected,
        )

    validation = validate_approved_change_supplemental_context(parsed)
    if (
        validation.status != "supplemental_context_valid"
        or not validation.context_valid
        or not validation.coverage_complete
    ):
        return _build_blocked(
            "bundle_construction_blocked",
            ["reviewed supplemental context is not valid", *validation.errors],
            expected,
        )

    # 3. Recompute and verify the expected reviewed-context identity.
    context_sha256 = compute_supplemental_context_sha256(parsed)
    if not hmac.compare_digest(context_sha256, expected_supplemental_context_sha256):
        return _build_blocked(
            "bundle_construction_blocked",
            ["expected_supplemental_context_sha256 does not match the reviewed context identity"],
            expected,
            context_sha256=context_sha256,
        )

    # 4-5. Freshly reconstruct exactly one subject and one evidence object.
    construction = construct_approved_change_subject(
        parsed, expected_supplemental_context_sha256=context_sha256
    )
    if (
        construction.status != "subject_constructed"
        or not construction.construction_succeeded
        or construction.subject is None
        or construction.construction_evidence is None
    ):
        return _build_blocked(
            "bundle_construction_blocked",
            ["reviewed subject construction did not succeed", *construction.errors],
            expected,
            context_sha256=context_sha256,
        )
    subject = construction.subject
    evidence = construction.construction_evidence

    # 6-7. Verify the expected subject and construction-evidence identities.
    subject_sha256 = compute_subject_sha256(subject)
    evidence_sha256 = compute_construction_evidence_sha256(evidence)
    identity_errors: list[str] = []
    if not hmac.compare_digest(subject_sha256, expected_subject_sha256):
        identity_errors.append(
            "expected_subject_sha256 does not match the constructed subject identity"
        )
    if not hmac.compare_digest(evidence_sha256, expected_construction_evidence_sha256):
        identity_errors.append(
            "expected_construction_evidence_sha256 does not match the construction-evidence "
            "identity"
        )
    if identity_errors:
        return _build_blocked(
            "bundle_construction_blocked",
            identity_errors,
            expected,
            context_sha256=context_sha256,
            subject_sha256=subject_sha256,
            evidence_sha256=evidence_sha256,
        )

    computed = {
        "context_sha256": context_sha256,
        "subject_sha256": subject_sha256,
        "evidence_sha256": evidence_sha256,
    }
    try:
        # 8-10. Serialize through the maintained canonical serializers only.
        payload_files = (
            _logical_file(
                SUPPLEMENTAL_CONTEXT_FILENAME,
                SUPPLEMENTAL_CONTEXT_ROLE,
                canonical_supplemental_context_json(parsed),
            ),
            _logical_file(
                APPROVED_CHANGE_SUBJECT_FILENAME,
                APPROVED_CHANGE_SUBJECT_ROLE,
                canonical_subject_json(subject),
            ),
            _logical_file(
                CONSTRUCTION_EVIDENCE_FILENAME,
                CONSTRUCTION_EVIDENCE_ROLE,
                canonical_construction_evidence_json(evidence),
            ),
        )
        # 11. Exact payload descriptors; each checksum must equal its semantic identity.
        descriptors = tuple(
            ApprovedChangeArtifactBundlePayloadFile(
                relative_path=logical.relative_path,
                role=logical.role,
                size_bytes=logical.size_bytes,
                content_sha256=logical.sha256,
                semantic_identity_sha256=identity,
            )
            for logical, identity in zip(
                payload_files,
                (context_sha256, subject_sha256, evidence_sha256),
                strict=True,
            )
        )
        # 12-14. Non-circular bundle identity and the derived full-hash bundle ID.
        manifest_fields: dict[str, Any] = {
            "schema_version": ARTIFACT_BUNDLE_SCHEMA_VERSION,
            "kind": ARTIFACT_BUNDLE_KIND,
            "supplemental_context_schema_version": SUPPLEMENTAL_CONTEXT_SCHEMA_VERSION,
            "approved_change_schema_version": APPROVED_CHANGE_SCHEMA_VERSION,
            "construction_policy_schema_version": CONSTRUCTION_POLICY_SCHEMA_VERSION,
            "construction_evidence_schema_version": CONSTRUCTION_EVIDENCE_SCHEMA_VERSION,
            "supplemental_context_sha256": context_sha256,
            "subject_sha256": subject_sha256,
            "construction_evidence_sha256": evidence_sha256,
            "payload_files": descriptors,
            "manifest_filename": MANIFEST_FILENAME,
            "publication_policy": PUBLICATION_POLICY,
            "atomicity_policy": ATOMICITY_POLICY,
            "overwrite_policy": OVERWRITE_POLICY,
            "existing_identical_policy": EXISTING_IDENTICAL_POLICY,
            "destination_policy": DESTINATION_POLICY,
            "warnings": PERMANENT_BUNDLE_WARNINGS,
        }
        bundle_identity_sha256 = compute_bundle_identity_sha256(manifest_fields)
        bundle_id = derive_bundle_id(bundle_identity_sha256)
        # 15-17. The final manifest, its canonical bytes, and its file record.
        manifest = ApprovedChangeArtifactBundleManifest(
            **manifest_fields,
            bundle_identity_sha256=bundle_identity_sha256,
            bundle_id=bundle_id,
        )
        manifest_file = _logical_file(
            MANIFEST_FILENAME, MANIFEST_ROLE, canonical_bundle_manifest_json(manifest)
        )
        # 18. The immutable four-file bundle.
        bundle = ApprovedChangeArtifactBundle(
            bundle_id=bundle_id,
            bundle_identity_sha256=bundle_identity_sha256,
            files=(*payload_files, manifest_file),
        )
    except Exception as exc:  # bundle assembly stays fail closed on schema drift
        return _build_blocked(
            "bundle_construction_blocked",
            [f"artifact bundle assembly failed: {exc}"],
            expected,
            context_sha256=computed["context_sha256"],
            subject_sha256=computed["subject_sha256"],
            evidence_sha256=computed["evidence_sha256"],
        )

    # 19. Verify every bundle invariant before returning success.
    verification = validate_approved_change_artifact_bundle(bundle)
    if verification.status != "bundle_valid" or not verification.bundle_valid:
        return _build_blocked(
            "bundle_construction_blocked",
            ["constructed bundle failed final verification", *verification.errors],
            expected,
            context_sha256=context_sha256,
            subject_sha256=subject_sha256,
            evidence_sha256=evidence_sha256,
        )

    return ApprovedChangeArtifactBundleBuildResult(
        status="bundle_constructed",
        build_succeeded=True,
        expected_supplemental_context_sha256=expected_supplemental_context_sha256,
        expected_subject_sha256=expected_subject_sha256,
        expected_construction_evidence_sha256=expected_construction_evidence_sha256,
        computed_supplemental_context_sha256=context_sha256,
        computed_subject_sha256=subject_sha256,
        computed_construction_evidence_sha256=evidence_sha256,
        bundle_identity_sha256=bundle_identity_sha256,
        bundle_id=bundle_id,
        bundle=bundle,
        manifest=manifest,
        errors=(),
        bundle_constructed=True,
        manifest_constructed=True,
    )


# ---------------------------------------------------------------------------
# Public bundle validation
# ---------------------------------------------------------------------------


def _validation_result(
    status: ValidationStatus,
    errors: list[str],
    *,
    bundle_id: str = "",
    bundle_identity_sha256: str = "",
    computed_bundle_identity_sha256: str = "",
    context_sha256: str = "",
    subject_sha256: str = "",
    evidence_sha256: str = "",
) -> ApprovedChangeArtifactBundleValidationResult:
    return ApprovedChangeArtifactBundleValidationResult(
        status=status,
        bundle_valid=status == "bundle_valid",
        bundle_id=bundle_id,
        bundle_identity_sha256=bundle_identity_sha256,
        computed_bundle_identity_sha256=computed_bundle_identity_sha256,
        computed_supplemental_context_sha256=context_sha256,
        computed_subject_sha256=subject_sha256,
        computed_construction_evidence_sha256=evidence_sha256,
        errors=tuple(sorted(set(errors))),
    )


def _parse_json_object(content_utf8: str, relative_path: str, errors: list[str]) -> Any:
    """Parse one stored logical file's JSON without repairing it."""
    try:
        parsed = json.loads(content_utf8)
    except Exception as exc:  # untrusted stored bytes must never raise publicly
        errors.append(f"{relative_path} is not parseable JSON: {exc}")
        return None
    if not isinstance(parsed, dict):
        errors.append(f"{relative_path} must contain a JSON object")
        return None
    return parsed


def _parse_model(model: Any, data: Any, relative_path: str, errors: list[str]) -> Any:
    if data is None:
        return None
    try:
        return model.model_validate(data)
    except Exception as exc:  # untrusted stored bytes must never raise publicly
        errors.append(f"{relative_path} does not parse into its maintained model: {exc}")
        return None


def _verify_file_records(
    bundle: ApprovedChangeArtifactBundle, errors: list[str]
) -> dict[str, ApprovedChangeArtifactBundleFile]:
    """Independently re-verify the exact four-file set, order, and metadata."""
    files = bundle.files
    if tuple(item.relative_path for item in files) != BUNDLE_FILENAMES:
        errors.append("bundle files must be the exact fixed filenames in their fixed order")
    if tuple(item.role for item in files) != BUNDLE_ROLES:
        errors.append("bundle files must use their exact fixed roles in their fixed order")
    by_role: dict[str, ApprovedChangeArtifactBundleFile] = {}
    for logical in files:
        for error in _relative_path_errors(logical.relative_path):
            errors.append(f"{logical.relative_path!r}: {error}")
        if logical.relative_path not in BUNDLE_FILENAMES:
            errors.append(f"unknown bundle filename: {logical.relative_path!r}")
            continue
        if _ROLE_BY_FILENAME[logical.relative_path] != logical.role:
            errors.append(f"{logical.relative_path} carries the wrong role: {logical.role}")
            continue
        if logical.role in by_role:
            errors.append(f"duplicate bundle role: {logical.role}")
            continue
        if logical.size_bytes != _size_of_text(logical.content_utf8):
            errors.append(f"{logical.relative_path} size_bytes does not match the UTF-8 content")
        if logical.sha256 != _sha256_of_text(logical.content_utf8):
            errors.append(f"{logical.relative_path} sha256 does not match the UTF-8 content")
        by_role[logical.role] = logical
    for role in BUNDLE_ROLES:
        if role not in by_role:
            errors.append(f"missing bundle file for role: {role}")
    return by_role


def _verify_manifest_descriptors(
    manifest: ApprovedChangeArtifactBundleManifest,
    by_role: dict[str, ApprovedChangeArtifactBundleFile],
    errors: list[str],
) -> None:
    """Require every manifest descriptor to describe the stored payload exactly."""
    semantic = {
        SUPPLEMENTAL_CONTEXT_ROLE: manifest.supplemental_context_sha256,
        APPROVED_CHANGE_SUBJECT_ROLE: manifest.subject_sha256,
        CONSTRUCTION_EVIDENCE_ROLE: manifest.construction_evidence_sha256,
    }
    for descriptor in manifest.payload_files:
        logical = by_role.get(descriptor.role)
        if logical is None:
            errors.append(f"manifest describes a missing payload file: {descriptor.relative_path}")
            continue
        if descriptor.relative_path != logical.relative_path:
            errors.append(f"manifest descriptor filename mismatch for role {descriptor.role}")
        if descriptor.size_bytes != logical.size_bytes:
            errors.append(f"manifest descriptor size mismatch for {descriptor.relative_path}")
        if descriptor.content_sha256 != logical.sha256:
            errors.append(f"manifest descriptor checksum mismatch for {descriptor.relative_path}")
        if descriptor.semantic_identity_sha256 != semantic[descriptor.role]:
            errors.append(
                f"manifest descriptor semantic identity mismatch for {descriptor.relative_path}"
            )
        if descriptor.content_sha256 != descriptor.semantic_identity_sha256:
            errors.append(
                f"{descriptor.relative_path} canonical checksum does not equal its semantic "
                "identity"
            )
    if manifest.manifest_filename != MANIFEST_FILENAME:
        errors.append("manifest_filename must be the exact fixed manifest filename")


def validate_approved_change_artifact_bundle(
    bundle: ApprovedChangeArtifactBundle | dict[str, Any],
) -> ApprovedChangeArtifactBundleValidationResult:
    """Validate a complete in-memory artifact bundle and its identity chain.

    The validator is pure and fail closed. It rejects stale, mixed, tampered,
    unsafe, renamed, missing, duplicate, extra, and noncanonical artifacts, and
    it never parses an invalid stored payload and silently reserializes it into
    acceptance: the stored bytes must already be canonical.

    A valid result means only that the in-memory persistence payload is
    complete, canonical, and internally consistent. It is never approval,
    authorization, capability support, persistence, or execution eligibility.
    """
    # 1. Top-level model.
    if isinstance(bundle, ApprovedChangeArtifactBundle):
        parsed_bundle = bundle
    elif isinstance(bundle, dict):
        try:
            parsed_bundle = ApprovedChangeArtifactBundle.model_validate(bundle)
        except Exception as exc:  # pydantic exposes many structured subclasses.
            return _validation_result(
                "bundle_invalid", [f"artifact bundle model validation failed: {exc}"]
            )
    else:
        return _validation_result(
            "invalid_bundle_validation_input",
            ["artifact bundle must be a model instance or a mapping"],
        )

    errors: list[str] = []
    # 2-4. Exact four-file set, deterministic order, path safety, and metadata.
    by_role = _verify_file_records(parsed_bundle, errors)
    if errors:
        return _validation_result(
            "bundle_invalid",
            errors,
            bundle_id=parsed_bundle.bundle_id,
            bundle_identity_sha256=parsed_bundle.bundle_identity_sha256,
        )

    stored_context = by_role[SUPPLEMENTAL_CONTEXT_ROLE]
    stored_subject = by_role[APPROVED_CHANGE_SUBJECT_ROLE]
    stored_evidence = by_role[CONSTRUCTION_EVIDENCE_ROLE]
    stored_manifest = by_role[MANIFEST_ROLE]

    # 5-9. Parse every stored payload into its maintained model.
    context_model = _parse_model(
        ApprovedChangeSupplementalContext,
        _parse_json_object(stored_context.content_utf8, stored_context.relative_path, errors),
        stored_context.relative_path,
        errors,
    )
    subject_model = _parse_model(
        ApprovedChangeSubject,
        _parse_json_object(stored_subject.content_utf8, stored_subject.relative_path, errors),
        stored_subject.relative_path,
        errors,
    )
    evidence_model = _parse_model(
        ApprovedChangeSubjectConstructionEvidence,
        _parse_json_object(stored_evidence.content_utf8, stored_evidence.relative_path, errors),
        stored_evidence.relative_path,
        errors,
    )
    manifest_model = _parse_model(
        ApprovedChangeArtifactBundleManifest,
        _parse_json_object(stored_manifest.content_utf8, stored_manifest.relative_path, errors),
        stored_manifest.relative_path,
        errors,
    )
    if errors or context_model is None or manifest_model is None:
        return _validation_result(
            "bundle_invalid",
            errors,
            bundle_id=parsed_bundle.bundle_id,
            bundle_identity_sha256=parsed_bundle.bundle_identity_sha256,
        )

    # 10-11. Fresh PR314 validation and recomputed reviewed-context identity.
    context_validation = validate_approved_change_supplemental_context(context_model)
    if (
        context_validation.status != "supplemental_context_valid"
        or not context_validation.context_valid
        or not context_validation.coverage_complete
    ):
        errors.append("stored reviewed supplemental context is not valid")
        errors.extend(context_validation.errors)
    context_sha256 = compute_supplemental_context_sha256(context_model)

    # Canonical-byte enforcement for the stored reviewed context.
    if canonical_supplemental_context_json(context_model) != stored_context.content_utf8:
        errors.append(f"{stored_context.relative_path} content is not canonical PR314 JSON")
    if subject_model is not None and canonical_subject_json(subject_model) != (
        stored_subject.content_utf8
    ):
        errors.append(f"{stored_subject.relative_path} content is not canonical PR309 JSON")
    if evidence_model is not None and canonical_construction_evidence_json(evidence_model) != (
        stored_evidence.content_utf8
    ):
        errors.append(f"{stored_evidence.relative_path} content is not canonical PR315 JSON")

    # 12-13. Rerun the maintained constructor from the stored reviewed context.
    construction = construct_approved_change_subject(
        context_model, expected_supplemental_context_sha256=context_sha256
    )
    if (
        construction.status != "subject_constructed"
        or not construction.construction_succeeded
        or construction.subject is None
        or construction.construction_evidence is None
    ):
        errors.append("stored reviewed context does not reconstruct a subject and evidence")
        errors.extend(construction.errors)
        return _validation_result(
            "bundle_invalid",
            errors,
            bundle_id=parsed_bundle.bundle_id,
            bundle_identity_sha256=parsed_bundle.bundle_identity_sha256,
            context_sha256=context_sha256,
        )

    rebuilt_subject_json = canonical_subject_json(construction.subject)
    rebuilt_evidence_json = canonical_construction_evidence_json(construction.construction_evidence)
    subject_sha256 = compute_subject_sha256(construction.subject)
    evidence_sha256 = compute_construction_evidence_sha256(construction.construction_evidence)

    # 14-15. Reconstructed canonical bytes must equal the stored bytes exactly.
    if rebuilt_subject_json != stored_subject.content_utf8:
        errors.append(
            f"{stored_subject.relative_path} does not match the subject reconstructed from the "
            "stored reviewed context"
        )
    if rebuilt_evidence_json != stored_evidence.content_utf8:
        errors.append(
            f"{stored_evidence.relative_path} does not match the evidence reconstructed from the "
            "stored reviewed context"
        )

    # 16. Every semantic identity must agree across the whole chain.
    if manifest_model.supplemental_context_sha256 != context_sha256:
        errors.append("manifest supplemental-context identity does not match the stored context")
    if manifest_model.subject_sha256 != subject_sha256:
        errors.append("manifest subject identity does not match the reconstructed subject")
    if manifest_model.construction_evidence_sha256 != evidence_sha256:
        errors.append("manifest construction-evidence identity does not match the stored evidence")
    if evidence_model is not None:
        if evidence_model.supplemental_context_sha256 != context_sha256:
            errors.append("stored evidence records another reviewed-context identity")
        if evidence_model.subject_sha256 != subject_sha256:
            errors.append("stored evidence records another subject identity")

    # 17. Manifest descriptors must describe the stored payload files exactly.
    _verify_manifest_descriptors(manifest_model, by_role, errors)

    # 18-20. Recompute the non-circular bundle identity and the bundle ID.
    computed_identity = compute_bundle_identity_sha256(manifest_model)
    computed_bundle_id = derive_bundle_id(computed_identity)
    if manifest_model.bundle_identity_sha256 != computed_identity:
        errors.append("manifest bundle_identity_sha256 does not match the recomputed identity")
    if manifest_model.bundle_id != computed_bundle_id:
        errors.append("manifest bundle_id does not match the recomputed bundle identity")
    if parsed_bundle.bundle_identity_sha256 != computed_identity:
        errors.append("bundle_identity_sha256 does not match the recomputed identity")
    if parsed_bundle.bundle_id != computed_bundle_id:
        errors.append("bundle_id does not match the recomputed bundle identity")

    # 21. The canonical manifest reserialization must equal the stored bytes exactly.
    if canonical_bundle_manifest_json(manifest_model) != stored_manifest.content_utf8:
        errors.append(f"{stored_manifest.relative_path} content is not canonical manifest JSON")

    # 22. One structured result.
    return _validation_result(
        "bundle_invalid" if errors else "bundle_valid",
        errors,
        bundle_id=parsed_bundle.bundle_id,
        bundle_identity_sha256=parsed_bundle.bundle_identity_sha256,
        computed_bundle_identity_sha256=computed_identity,
        context_sha256=context_sha256,
        subject_sha256=subject_sha256,
        evidence_sha256=evidence_sha256,
    )
