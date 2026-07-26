# Approved Change Artifact Bundle

PR316 defines exactly one pure, immutable, deterministic, checksum-protected, in-memory artifact bundle for Stage B. It answers exactly one question:

> Given one completely reviewed PR314 supplemental context and its three exact semantic identities, what is the one deterministic set of bytes a future writer would be allowed to publish for that reviewed change — and what proves those bytes are complete, canonical, and internally consistent?

The module `src/shellforgeai/core/approved_change_artifact_bundle.py` is that persistence payload contract plus its builder and validator, and nothing else. It never touches the filesystem.

## Why this slice exists

PR309 defined the destination schema and the subject identity. PR311 defined the field-source policy. PR314 defined the complete reviewed input package. PR315 added the one sanctioned construction operation, producing a subject and field-by-field construction evidence in memory.

At that point a reviewed change existed only as three live Python objects with three separate identities. Any caller wanting to keep it would have had to invent its own file layout, its own serialization, its own checksum scheme, and its own idea of which artifacts belong together — exactly the ad-hoc drift the earlier slices prohibit. Writing files before agreeing on the payload would also have made the filesystem boundary the place where correctness is decided.

PR316 closes that gap in the safe order: define the exact bytes, the exact file set, the exact checksums, and the exact identity chain first; leave the governed writer to PR317.

A valid bundle is still not approved, not authorized, not an `ApprovedChangeContract`, not bound to a capability, not persisted, and not executable.

## Relationship to PR309, PR314, and PR315

| Slice | Owns | PR316 relationship |
| --- | --- | --- |
| PR309 | `ApprovedChangeSubject`, its nested target/evidence/procedure/rollback types, canonical subject serialization, the subject SHA-256, and the separate approval attestation | PR309 remains the sole subject schema and subject-identity authority. PR316 serializes the subject only through `canonical_subject_json` and identifies it only through `compute_subject_sha256`. It creates no `ApprovalAttestation` and no `ApprovedChangeContract` and never imports either type. |
| PR311 | The field-source policy | PR311 remains the sole field-source-policy authority. PR316 consumes only its schema version, which the manifest records and the bundle identity binds. Policy drift fails closed through the PR315 constructor PR316 reruns. |
| PR314 | The reviewed input package, its canonical serialization, and the supplemental-context SHA-256 | PR314 remains reviewed input only. PR316 freshly revalidates the supplied context through `validate_approved_change_supplemental_context`, recomputes its identity, and serializes it only through `canonical_supplemental_context_json`. |
| PR315 | The one sanctioned subject-construction path, the construction evidence, its canonical serialization, and the construction-evidence SHA-256 | PR315 remains the sole construction authority. PR316 accepts no caller-supplied subject or evidence: it reruns `construct_approved_change_subject` and serializes only through `canonical_construction_evidence_json`. |

PR313's `windows.runtime_reconcile` capability remains independent. PR316 does not import, reference, bind, or integrate it.

## The exact four-file logical bundle

A bundle contains exactly four logical files, in exactly this order, with exactly these roles:

| # | Filename | Role | Canonical bytes produced by |
| --- | --- | --- | --- |
| 1 | `supplemental-context.json` | `supplemental_context` | PR314 `canonical_supplemental_context_json` |
| 2 | `approved-change-subject.json` | `approved_change_subject` | PR309 `canonical_subject_json` |
| 3 | `construction-evidence.json` | `construction_evidence` | PR315 `canonical_construction_evidence_json` |
| 4 | `manifest.json` | `manifest` | PR316 `canonical_bundle_manifest_json` |

These are in-memory logical files, not persisted files. A bundle holds no output directory, host path, data root, or destination of any kind.

### Fixed names only

The filenames are fixed literals in a fixed order. There is no caller-defined name, alias, optional file, extra file, subdirectory, glob, alternate extension, case-insensitive alternative, or Unicode-confusable alternative. Names must be lowercase ASCII.

A candidate filename is rejected when it is empty, carries leading or trailing whitespace, is non-ASCII, is not lowercase, or contains or represents `/`, `\`, `..`, an absolute POSIX path, a Windows drive path, or a UNC path. `Manifest.json`, `manifest.JSON`, `manifest.json `, `bundles/manifest.json`, `../manifest.json`, `/etc/manifest.json`, `C:\bundles\manifest.json`, `\\server\share\manifest.json`, and a Cyrillic-`о` spelling of `manifest.json` are all rejected. Anything not byte-identical to one of the four literals is rejected regardless of how it renders.

## Canonical byte requirements

The three semantic payload files use only the maintained upstream serializers. PR316 does not reimplement their canonicalization. Every logical file's bytes are:

- UTF-8, with no byte-order mark;
- compact canonical JSON with sorted mapping keys through the maintained serializers;
- `ensure_ascii=False`, so reviewed non-ASCII text is stored unescaped;
- no indentation, no CRLF translation, no trailing newline;
- byte-for-byte stable across Linux and Windows.

Timestamps are normalized to UTC by the maintained PR309 canonicalization, so a reviewed `+02:00` timestamp and its UTC equivalent produce identical bundle bytes. Set-like target identity claims and evidence references are canonically ordered, so reordering them changes no byte. Procedure, rollback-procedure, precondition, and verification order is semantic, so changing it changes the payload bytes and every identity that covers them.

### File checksum and byte-length semantics

Every logical file record carries the exact UTF-8 byte length and the exact SHA-256 of its own canonical bytes:

```
ApprovedChangeArtifactBundleFile
  relative_path   one of the four fixed literal filenames
  role            that filename's fixed role
  content_utf8    the complete canonical JSON string
  size_bytes      len(content_utf8.encode("utf-8"))
  sha256          sha256(content_utf8.encode("utf-8"))
```

For the three semantic payload files the canonical byte checksum **is** the maintained semantic identity:

```
supplemental-context.json    sha256 == PR314 supplemental-context SHA-256
approved-change-subject.json sha256 == PR309 subject SHA-256
construction-evidence.json   sha256 == PR315 construction-evidence SHA-256
```

That equality is not a coincidence to be assumed; it is enforced. Each manifest payload descriptor requires `content_sha256 == semantic_identity_sha256`, and the validator recomputes both sides.

## Manifest schema

```
ApprovedChangeArtifactBundleManifest
  schema_version                        bundle schema version
  kind                                  approved_change_reviewed_artifact_bundle
  supplemental_context_schema_version    PR314 schema version
  approved_change_schema_version         PR309 schema version
  construction_policy_schema_version     PR311 schema version
  construction_evidence_schema_version   PR315 schema version
  supplemental_context_sha256            PR314 reviewed-input identity
  subject_sha256                         PR309 subject identity
  construction_evidence_sha256           PR315 construction-evidence identity
  payload_files                          exactly three frozen descriptors
  manifest_filename                      manifest.json
  publication_policy                     fixed future-writer semantics
  atomicity_policy                       fixed future-writer semantics
  overwrite_policy                       fixed future-writer semantics
  existing_identical_policy              fixed future-writer semantics
  destination_policy                     fixed future-writer semantics
  warnings                               permanent safety warnings
  bundle_identity_sha256                 the full non-circular bundle identity
  bundle_id                              acb_ + the full bundle identity
```

Each payload descriptor carries `relative_path`, `role`, `size_bytes`, `content_sha256`, and `semantic_identity_sha256`.

The manifest describes exactly the three non-manifest payload files and never contains its own checksum. The manifest's own bytes, byte length, and checksum are protected by the fourth top-level bundle file record.

## Semantic identity chain

Four identities stay permanently distinct, and a valid bundle requires all of them to agree:

```
manifest.supplemental_context_sha256
  == recomputed PR314 supplemental-context SHA-256
  == construction-evidence.supplemental_context_sha256

manifest.subject_sha256
  == recomputed PR309 subject SHA-256
  == construction-evidence.subject_sha256

manifest.construction_evidence_sha256
  == recomputed PR315 construction-evidence SHA-256

manifest.bundle_identity_sha256
  == recomputed bundle identity  (never any of the three above)
```

## Non-circular bundle identity

The bundle identity payload is exactly the canonical manifest payload minus `bundle_identity_sha256` and `bundle_id`. Nothing else is removed, so the identity binds the bundle schema version, the manifest kind, all four upstream schema versions, the three semantic identities, the exact payload filenames, roles, byte lengths and content checksums, the manifest filename, all five fixed policies, and the permanent warnings.

```
bundle_identity_sha256 = SHA-256(canonical bundle identity payload UTF-8 bytes)
bundle_id              = "acb_" + bundle_identity_sha256
```

The bundle ID uses the full 64-character SHA-256 and is never truncated, so a bundle ID is always 68 characters. The final manifest carries both values; the identity payload carries neither, so the identity can never hash itself.

The validator independently reconstructs the identity payload from the stored manifest, recomputes the identity and the bundle ID, and rejects any mismatch against the stored manifest values or the top-level bundle values.

## Builder

```python
build_approved_change_artifact_bundle(
    context: ApprovedChangeSupplementalContext | dict[str, Any],
    *,
    expected_supplemental_context_sha256: str,
    expected_subject_sha256: str,
    expected_construction_evidence_sha256: str,
) -> ApprovedChangeArtifactBundleBuildResult
```

Those are the only inputs. The builder accepts no caller-supplied subject, construction-evidence object, manifest, filename, bundle ID, bundle policy, legacy `Proposal`, capability registry, approval data, or output path.

### Required sequence

1. Validate all three expected SHA-256 values as exactly 64 lowercase hexadecimal characters.
2. Freshly validate the supplied PR314 context.
3. Recompute and verify the expected supplemental-context SHA-256 (constant-time compare).
4. Invoke the maintained PR315 constructor using the exact recomputed context identity.
5. Require a successful PR315 result carrying exactly one subject and one construction-evidence object, with no approval, contract, persistence, capability support, or execution.
6. Verify the expected subject SHA-256.
7. Verify the expected construction-evidence SHA-256.
8. Serialize the context through the maintained PR314 canonical serializer.
9. Serialize the subject through the maintained PR309 canonical serializer.
10. Serialize the construction evidence through the maintained PR315 canonical serializer.
11. Build the exact three payload-file descriptors.
12. Build the canonical bundle-manifest identity payload.
13. Compute the bundle identity SHA-256.
14. Derive the bundle ID from the full bundle identity.
15. Construct the final manifest.
16. Serialize the manifest canonically.
17. Build the fourth manifest-file descriptor.
18. Construct the immutable four-file bundle.
19. Validate the complete bundle before returning success.

### The explicit expected-identity gates

All three expected identities are required. Construction is blocked when any of them is missing, malformed, uppercase, empty, taken from another fixture, stale, a candidate hash, a field-value hash, a bundle identity, or otherwise mismatched. A structurally valid reviewed context is never sufficient on its own, and swapping two otherwise-correct identities blocks construction.

The successful result and the manifest both record the recomputed semantic identities.

Any failure returns a structured blocked or invalid result carrying no bundle, no manifest, no bundle ID, no partial file tuple, no persistence claim, and no artifact-write claim. Invalid external input is never silently repaired, reordered, or normalized into validity.

## Validator

```python
validate_approved_change_artifact_bundle(
    bundle: ApprovedChangeArtifactBundle | dict[str, Any],
) -> ApprovedChangeArtifactBundleValidationResult
```

The validator accepts a model or an untrusted dictionary and:

1. validates the top-level model;
2. validates the exact four-file set and its deterministic order;
3. rejects unsafe or non-literal filenames;
4. re-verifies every logical file's UTF-8 byte length and SHA-256;
5. parses all four stored JSON payloads;
6. requires each payload to parse into its maintained PR314, PR309, PR315, or PR316 model;
7. freshly validates the stored PR314 context and recomputes its identity;
8. reruns the maintained PR315 constructor from that context and identity;
9. compares the reconstructed canonical subject and evidence bytes with the stored bytes;
10. compares every semantic identity across the manifest, the stored evidence, and the recomputation;
11. validates the manifest's exact payload descriptors;
12. recomputes the bundle identity payload, the bundle identity, and the bundle ID;
13. requires the canonical manifest reserialization to equal the stored manifest bytes exactly;
14. returns one structured result.

### Fail-closed canonical-byte enforcement

The stored bytes must already be canonical. A semantically parseable but noncanonical payload is rejected rather than parsed and silently reserialized into acceptance. Rejected forms include pretty-printed JSON, changed insignificant whitespace, loose separators, alternate mapping-key order, CRLF, a trailing newline, a UTF-8 BOM, escaped Unicode where the maintained canonical output is unescaped, an equivalent timestamp spelled with a numeric offset instead of `Z`, reordered semantic sequences, noncanonical target identity-claim or evidence-reference order, and altered numeric or Boolean representations.

### Stale, mixed, and tampered artifacts

A valid bundle must be internally consistent as a whole. The validator rejects a subject or evidence file taken from a different reviewed context, a manifest wrapped around another bundle's payloads, evidence from one construction paired with a subject from another, a context whose reviewed values were edited, a payload placed under the wrong role, a tampered checksum, byte length, schema version, manifest kind, fixed policy, warning, bundle identity, or bundle ID, and a missing, duplicated, renamed, or extra file. Because the reviewed context and the construction evidence carry review provenance, two bundles with an identical subject but different reviewers are still distinguishable and non-interchangeable.

## Structured results and permanent safety posture

A successful build reports `bundle_constructed` and `manifest_constructed`; a successful validation reports `bundle_valid`. Both always report:

```
read_only = true                       mutation_performed = false
artifact_write_performed = false       filesystem_accessed = false
publication_performed = false          overwrite_performed = false
persistence_performed = false          approval_created = false
contract_created = false               receipt_created = false
capability_support_evaluated = false   capability_supported = false
approval_evaluated = false             authorization_evaluated = false
execution_allowed = false              execution_available = false
execution_status = not_executed
```

Blocked and invalid results carry no bundle, no partial-success flag, and deterministic sorted, deduplicated errors. Untrusted input returns a structured result instead of raising, and implementation tracebacks are never the public result.

### Permanent warnings

Every result and every manifest carries the same permanent warnings: a valid bundle is not approval, authorization, or an `ApprovedChangeContract`; reviewer provenance is not authenticated identity; bundle identity is not subject identity and is not capability support; bundle construction is not persistence and publication-policy metadata is not execution confirmation; no execution eligibility is granted.

Reviewed artifacts may contain operational context — hostnames, container identities, evidence references, diagnosis text — and **must be reviewed before sharing**. PR316 performs no redaction, because redaction would change the reviewed identity, and it adds no sharing or export operation.

## Fixed future publication semantics

The manifest records five fixed policy values. They are contract metadata only. PR316 implements none of them.

| Field | Value |
| --- | --- |
| `publication_policy` | `prepare_verify_then_atomic_publish` |
| `atomicity_policy` | `publish_complete_verified_bundle_with_one_final_directory_transition` |
| `overwrite_policy` | `forbid` |
| `existing_identical_policy` | `validate_and_return_already_present` |
| `destination_policy` | `fixed_full_bundle_id_directory` |

The future PR317 writer will be required to derive the destination directory from the full bundle ID, prepare all files outside the final destination, verify all prepared files, publish the complete bundle in one final atomic directory transition, never overwrite, return `already_present` only for an existing fully valid identical bundle, and block on conflicting or invalid existing contents.

## Non-executable, unapproved, unpersisted JSON-shaped example

The shape below is illustrative only. It is **non-executable**, **unapproved**, **not persisted**, and **not authorization**. Hash values are elided and the payload contents are abbreviated.

```json
{
  "schema_version": "1",
  "bundle_id": "acb_<64 lowercase hex>",
  "bundle_identity_sha256": "<the same 64 lowercase hex>",
  "files": [
    {"relative_path": "supplemental-context.json", "role": "supplemental_context", "content_utf8": "{\"approved_change_schema_version\":\"1\",\"...\":\"canonical PR314 JSON\"}", "size_bytes": 5846, "sha256": "<PR314 supplemental-context SHA-256>"},
    {"relative_path": "approved-change-subject.json", "role": "approved_change_subject", "content_utf8": "{\"audit_requirements\":[\"...\"],\"...\":\"canonical PR309 JSON\"}", "size_bytes": 1987, "sha256": "<PR309 subject SHA-256>"},
    {"relative_path": "construction-evidence.json", "role": "construction_evidence", "content_utf8": "{\"approved_change_schema_version\":\"1\",\"...\":\"canonical PR315 JSON\"}", "size_bytes": 8644, "sha256": "<PR315 construction-evidence SHA-256>"},
    {"relative_path": "manifest.json", "role": "manifest", "content_utf8": "{\"approved_change_schema_version\":\"1\",\"...\":\"canonical manifest JSON\"}", "size_bytes": 2400, "sha256": "<manifest content SHA-256, recorded here and never inside the manifest>"}
  ]
}
```

The manifest inside file 4 has this shape:

```json
{
  "schema_version": "1",
  "kind": "approved_change_reviewed_artifact_bundle",
  "supplemental_context_schema_version": "1",
  "approved_change_schema_version": "1",
  "construction_policy_schema_version": "1",
  "construction_evidence_schema_version": "1",
  "supplemental_context_sha256": "<64 lowercase hex>",
  "subject_sha256": "<different 64 lowercase hex>",
  "construction_evidence_sha256": "<third distinct 64 lowercase hex>",
  "payload_files": [
    {"relative_path": "supplemental-context.json", "role": "supplemental_context", "size_bytes": 5846, "content_sha256": "<64 lowercase hex>", "semantic_identity_sha256": "<the same 64 lowercase hex>"},
    {"...": "two further descriptors, three in total"}
  ],
  "manifest_filename": "manifest.json",
  "publication_policy": "prepare_verify_then_atomic_publish",
  "atomicity_policy": "publish_complete_verified_bundle_with_one_final_directory_transition",
  "overwrite_policy": "forbid",
  "existing_identical_policy": "validate_and_return_already_present",
  "destination_policy": "fixed_full_bundle_id_directory",
  "warnings": ["a valid bundle is not approval, authorization, or an ApprovedChangeContract", "..."],
  "bundle_identity_sha256": "<fourth distinct 64 lowercase hex>",
  "bundle_id": "acb_<the same fourth 64 lowercase hex>"
}
```

## Explicit non-goals

PR316 adds no filesystem access, `Path` use, `open` call, file creation, file read, directory creation, temporary file or directory, `fsync`, rename, `os.replace`, cleanup, partial-write recovery, overwrite implementation, existing-directory inspection, persisted-bundle loader, persistence, CLI export or persist command, interactive route, legacy `Proposal` loading, candidate extraction, field inference, value defaulting, value transformation, approval attestation, `ApprovedChangeContract` construction, authenticated identity, approval workflow, capability registry, capability-support decision, capability binding, `windows.runtime_reconcile` binding, PR313 import or integration, current-state execution preflight, subject/live-plan comparison, receipt linkage, execution eligibility, execution, model/provider call, network call, shell command, subprocess, Docker or Compose call, PowerShell, WinRM, QGA, environment mutation, or credential/secret access.

The production module imports only `hashlib`, `hmac`, `json`, `re`, `typing`, `pydantic`, and the maintained PR311/PR309/PR315/PR314 modules. It uses no implicit clock, randomness, or UUID, so identical reviewed input always yields identical bytes.

Current product behavior, the command surface, and mutation refusal are unchanged.

## PR317 writer and loader dependency

The next Stage B dependency is **PR317: publish reviewed-change artifact bundles atomically** — the narrowly governed filesystem boundary that this contract exists to constrain. Its expected scope is a fixed data-root subtree, a full bundle-ID destination directory, a temporary sibling preparation directory, exclusive binary writes, exact byte and checksum verification, flush where supported, one final atomic directory publication step, no overwrite, `already_present` for a valid identical existing bundle, blocking on an invalid or conflicting existing directory, bounded cleanup only of the unpublished temporary directory created by that invocation, and a read-only persisted-bundle loader and validator.

PR316 deliberately pre-implements none of it. Approval attestation, approved-contract construction, authenticated identity, approval workflow and persistence, the capability registry, capability-support evaluation, exact capability binding, `windows.runtime_reconcile` binding, current-state execution preflight, subject/live-plan comparison, subject-to-receipt linkage, execution eligibility, Stage C end-to-end execution, and any additional mutation capability all remain deferred.
