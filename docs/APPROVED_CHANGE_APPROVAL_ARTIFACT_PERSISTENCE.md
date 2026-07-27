# Approved Change Approval Artifact Persistence

PR319 adds exactly one Stage B capability. It answers exactly one question:

> Given one fully successful PR318 approval, how are that exact approval, its exact contract, and its exact source provenance preserved durably, immutably, and verifiably?

Two modules are that capability and nothing else:

- `src/shellforgeai/core/approved_change_approval_artifact.py` — the pure canonical approval-artifact contract, its identity, its builder, and its validator.
- `src/shellforgeai/core/approved_change_approval_persistence.py` — the governed atomic no-replace publisher and the exact-ID read-only loader.

## Why this slice exists

PR318 creates exactly one `ApprovalAttestation` and one `ApprovedChangeContract` **in memory**. An in-memory approval disappears with the process. Every later Stage B step — capability binding, preflight, receipts, execution — needs to point at an approval that still exists, that nobody edited, and whose reviewed source is still provable.

Without one governed operation, each caller would have had to invent its own approval file format, its own approval identity, its own writer, and its own idea of what "the same approval" means. That is exactly the drift the earlier slices exist to prevent, and it would have put durable approval identity in the least reviewable place.

PR319 makes that one step canonical, exact, atomic, and inert with respect to everything else.

## Relationship to PR309, PR317, and PR318

PR309 remains the sole authority for `ApprovedChangeSubject`, `ApprovalAttestation`, `ApprovedChangeContract`, subject canonicalization, subject SHA-256, the approval scope `exact_subject_only`, exact approval-to-subject binding, and inert binding verification. PR319 serializes those maintained models through PR309's own canonicalizers and calls `verify_approval_binding`; it defines no schema, no subject canonicalization, and no approval semantics of its own.

PR316 remains authoritative for the reviewed-change source bundle, its exact four files, its bundle identity, its `acb_` bundle ID, and the canonical stored subject bytes.

PR317 remains the sole governed publisher and the sole exact-ID read-only loader for reviewed-change bundles. PR319 reaches source bundles only through `load_persisted_approved_change_artifact_bundle`. It:

- invents no alternate bundle loader;
- accepts no arbitrary source path;
- resolves no `latest`, `current`, or "most recent" reference;
- never imports or calls PR317's publisher;
- modifies, republishes, repairs, or timestamp-refreshes no persisted bundle byte;
- changes no PR317 on-disk layout.

The atomic no-replace directory primitive is PR319-owned and follows the proven PR317 behaviour exactly, so PR317's public surface stays unchanged.

PR318 remains authoritative for the explicit decision literal `approve`, exact bundle-identity confirmation, exact subject-hash confirmation, explicit approval metadata, the construction of the one in-memory attestation and the one in-memory contract, and exact PR309 binding verification. **PR319 consumes one fully successful PR318 result and creates no approval of its own.**

`src/shellforgeai/core/approvals.py` remains the legacy `Proposal` schema-v1 paper-trail workflow, and PR310's non-portability decision remains in force. PR319 converts no legacy `Proposal`, reads or writes no legacy approval queue directory, imports no legacy approval status, marks no legacy proposal approved, treats no `Proposal` fingerprint as an approved subject identity, and bridges no PR309 approval artifact into the legacy queue.

## Canonical approval artifact

### The exact payload

Exactly one canonical UTF-8 JSON logical file is persisted:

```
approved-change-approval.json
```

Its payload holds exactly six fields:

```json
{
  "schema_version": "1",
  "artifact_type": "approved_change_approval",
  "source_bundle_id": "acb_<64 lowercase hex>",
  "source_bundle_identity_sha256": "<64 lowercase hex>",
  "subject_sha256": "<64 lowercase hex>",
  "contract": {
    "schema_version": "1",
    "subject": { },
    "approval": { }
  }
}
```

The nested `subject` and `approval` schemas remain PR309's maintained models.

There is **no** capability support, authorization, preflight data, receipt data, execution data, mutable status, `current`/`latest` pointer, revocation state, expiration state, environment or host identity, PR314 reviewer provenance as approval identity, and no arbitrary metadata.

### Canonical serialization

Canonical artifact serialization:

- uses PR309 `canonical_subject_payload` for the subject, preserving PR309 subject collection semantics exactly;
- serializes the approval through the maintained PR309 canonicalizer, so the normalized `ApprovalAttestation` values are used verbatim and `approved_at` is normalized to the maintained canonical UTC representation (`2026-07-27T09:00:00Z`);
- sorts mapping keys;
- uses compact JSON separators (`,` and `:`);
- uses UTF-8 with `ensure_ascii=False`, so reviewed Unicode is preserved exactly;
- contains no BOM and no trailing newline;
- performs no redaction, because redaction would change artifact identity.

No competing subject canonicalizer exists.

## Artifact identity and ID

```
approval_artifact_identity_sha256 = SHA256(exact canonical approved-change-approval.json UTF-8 bytes)
approval_artifact_id             = "aca_" + approval_artifact_identity_sha256
```

The identity and ID are **derived** and are never embedded inside the canonical payload, so the identity can never hash itself.

### Distinct identities

| Identity | Prefix / meaning |
| --- | --- |
| PR314 supplemental-context SHA-256 | reviewed input identity |
| PR309 subject SHA-256 | the approved change itself |
| PR315 construction-evidence SHA-256 | how the subject was built |
| PR316 bundle identity / `acb_` | one exact reviewed source bundle |
| **PR319 approval-artifact identity / `aca_`** | **one exact durable approval event** |

They are permanently distinct. Two reviewed bundles may share one subject SHA-256 while carrying different reviewed provenance and different bundle identities; two approvals of the same subject through the same bundle differ if the actor, instant, or reason differs. `aca_` is never `acb_`, and an approval-artifact identity is never a legacy `Proposal` fingerprint or an approval-to-subject binding.

## Builder

```python
build_approved_change_approval_artifact(
    workflow_result: ApprovedChangeApprovalWorkflowResult,
) -> ApprovedChangeApprovalArtifactBuildResult
```

The only input is one PR318 result (or a mapping that satisfies the maintained PR318 result contract). No separately supplied approval, contract, subject, bundle ID, bundle identity, subject hash, approver metadata, output path, or persistence confirmation is accepted.

Every one of these gates must pass:

- exactly the maintained PR318 result contract;
- `status=approval_contract_constructed`;
- `approval_succeeded=true`;
- source bundle loaded and valid;
- the exact requested and loaded bundle IDs agree;
- the confirmed and computed bundle identities agree;
- the confirmed and computed subject SHA-256 values agree;
- one non-null `ApprovalAttestation`;
- one non-null `ApprovedChangeContract`;
- one non-null successful PR309 binding validation;
- the contract subject is the result's exact approved subject;
- the contract approval is the result's exact approval;
- the approval `subject_sha256` equals the computed subject hash;
- the scope is exactly `exact_subject_only`;
- every capability, authorization, preflight, receipt, and execution field is false.

On any failure it returns no artifact at all. It performs no filesystem access, clock lookup, environment lookup, network call, randomness, UUID generation, or mutation.

## Validator

```python
validate_approved_change_approval_artifact(
    artifact: ApprovedChangeApprovalArtifact | dict[str, Any],
) -> ApprovedChangeApprovalArtifactValidationResult
```

It recomputes and requires the canonical payload, the canonical bytes, the byte length, the artifact identity, the artifact ID, the source bundle ID format, the source bundle identity format, the subject SHA-256 format, contract model validity, the PR309 subject SHA-256, the PR309 approval binding, the exact approval scope, and agreement among the outer subject SHA-256, the contract subject SHA-256, and the approval subject SHA-256.

Validation is pure and inert. It never calls `validate_approved_change_contract`: capability-support evaluation remains deferred, and neither module imports it.

## Fixed persistence layout

```
<data_dir>/
  approved_change_approvals/
    aca_<64 lowercase hex>/
      approved-change-approval.json
```

```
APPROVED_CHANGE_APPROVALS_DIRNAME = "approved_change_approvals"
APPROVED_CHANGE_APPROVAL_FILENAME = "approved-change-approval.json"
```

There is no caller override, alternate filename, alias, second file, sidecar, completion marker, mutable status file, pointer file, symlink, or `latest` entry.

Approval artifacts are published beneath the same `<data_dir>` as their PR317 source bundle: the loader revalidates the exact source bundle from that same root, and post-publication verification uses the loader.

## Explicit artifact-identity confirmation

```python
publish_approved_change_approval_artifact(
    artifact: ApprovedChangeApprovalArtifact,
    *,
    data_dir: Path | str,
    confirm_approval_artifact_identity_sha256: str,
) -> ApprovedChangeApprovalArtifactPublicationResult
```

`confirm_approval_artifact_identity_sha256` must be exactly 64 lowercase hexadecimal characters and must equal the fully recomputed artifact identity. The comparison uses `hmac.compare_digest`. The prefixed `aca_` ID is never accepted in its place, and neither is the source bundle identity or the subject SHA-256.

It authorizes only publication of that one exact already-validated approval artifact beneath the fixed approval-artifact subtree. It is **not** approval confirmation, authorization, capability confirmation, execution confirmation, or overwrite permission.

A malformed or mismatched confirmation performs **zero filesystem access**.

## Atomic no-replace publication sequence

1. Validate the artifact in memory.
2. Require an exact valid artifact identity and ID.
3. Validate the publication confirmation format.
4. Compare the confirmation exactly with `hmac.compare_digest`.
5. Validate `data_dir` (absolute, existing, a real directory, not a filesystem or drive root, not a symlink or reparse point).
6. Derive the fixed approval publication root.
7. Preflight the fixed final path length against the platform limit.
8. Inspect or create the fixed publication root.
9. Derive the exact final artifact directory.
10. Inspect an existing destination.
11. Create one private temporary sibling.
12. Write the exact canonical file bytes.
13. Flush and verify the file.
14. Verify the complete temporary artifact contents.
15. Rerun artifact validation from the prepared bytes.
16. Flush the temporary directory where supported.
17. Perform one atomic no-replace directory transition.
18. Load the persisted artifact through the maintained PR319 loader.
19. Require complete post-publication validation.
20. Report the result.

No final artifact directory becomes visible before the atomic transition.

### Temporary directory

One short private sibling named `.pending-<16 lowercase hex>` — exactly 25 characters, always shorter than the 68-character final directory name it prepares. It lives in the same parent and on the same filesystem as the final directory, is created exclusively with mode `0o700` where supported, is verified not to be a symlink or reparse point, and carries no artifact ID or semantic identity. The token is internally generated (never caller-supplied) and never reaches persisted bytes, result identities, or durable identifiers. This is the only place PR319 uses randomness.

### Exact binary write and flush posture

The fixed file is created with `O_CREAT | O_EXCL | O_WRONLY`, plus `O_BINARY` and `O_NOFOLLOW` where available, at mode `0o600` where supported. It is then flushed through a guarded write-capable descriptor and verified for regular-file type, non-reparse identity, pre-open/post-open descriptor identity, exact byte length, and exact SHA-256, and the prepared artifact is reconstructed and revalidated from those bytes.

A file-flush failure blocks publication and is never downgraded to `unsupported`. Directory flush reporting stays truthful — `passed`, `unsupported`, `failed`, or `not_attempted`. **Windows directory flushes report `unsupported`, never invented success.**

### Atomic primitive

- Linux: `renameat2(..., RENAME_NOREPLACE)`, via the glibc wrapper or the architecture's syscall number.
- Windows: `MoveFileExW(source, destination, 0)` with no replace flags.

There is no replace-capable fallback. `os.replace`, `os.rename`, `Path.replace`, `Path.rename`, `shutil.move`, shell, subprocess, PowerShell, and external binaries are all absent. When no proven primitive exists the publication fails closed with `atomic_publication_unsupported`.

## Existing destination behaviour

### Existing identical artifact

`approval_artifact_already_present` is returned only when the existing artifact has the exact expected directory ID, contains exactly the one fixed file, contains canonical bytes, recomputes to the exact artifact identity, validates its PR309 contract binding, validates against its exact PR317 source bundle, and is byte-identical to the input artifact.

No temporary directory is created, no byte is written, no timestamp is refreshed, and nothing is overwritten or mutated.

### Conflict

Publication blocks when the destination contains missing files, extra files, symlinks or reparse points, non-regular entries, different bytes, noncanonical JSON, another artifact identity, an invalid PR309 binding, mismatched source bundle provenance, a tampered subject or approval, or another contract. The destination is never repaired, replaced, quarantined, renamed, deleted, merged, or written around.

### Race

If the destination appears between preparation and commit, the native no-replace primitive refuses replacement. Only the invocation-owned temporary directory is cleaned up, the appeared destination is inspected, and the result is `approval_artifact_already_present` only when it is completely valid and byte-identical — otherwise it blocks as a conflict.

## Bounded cleanup

Cleanup is limited to the unpublished temporary directory created by that exact invocation. It may remove only the exact tracked fixed file after revalidating it, the exact temporary directory when empty, and the fixed publication root only when this invocation created it and it remains empty. There is no recursive deletion. Unknown or extra temporary contents are preserved and reported as incomplete cleanup (`publication_failed_cleanup_incomplete`).

Never deleted: a published approval artifact, another invocation's temporary path, a PR317 source bundle, a pre-existing publication root, and any legacy approval data.

## Post-publication verification

After a successful atomic publication the artifact is loaded through the exact-ID loader and revalidated for canonical bytes, artifact identity, source-bundle provenance, and the PR309 approval binding.

If post-publication verification fails, the final published artifact is **never** deleted or rolled back automatically. The result reports `published_verification_failed`, states that publication and persistence occurred, states that no removal was attempted, and keeps every capability, preflight, receipt, and execution field false.

## Exact-ID read-only loader

```python
load_persisted_approved_change_approval_artifact(
    approval_artifact_id: str,
    *,
    data_dir: Path | str,
) -> ApprovedChangeApprovalArtifactLoadResult
```

Only `aca_` followed by exactly 64 lowercase hexadecimal characters is accepted. Shortened hashes, uppercase, whitespace, arbitrary paths, POSIX traversal, Windows drive paths, UNC paths, separators, globs, aliases, `latest`, `current`, and "most recent" are all rejected.

The loader:

1. validates the exact full artifact ID;
2. validates the explicit data root;
3. derives the fixed publication root and the final directory;
4. rejects symlink and reparse paths;
5. requires exactly one fixed regular file;
6. enforces the conservative 1048576-byte read bound before reading;
7. reads exactly that many bytes with no size drift;
8. parses the maintained artifact model;
9. reserializes canonical bytes and requires exact equality;
10. recomputes the artifact identity and ID;
11. recomputes the PR309 subject SHA-256;
12. verifies the PR309 approval binding;
13. requires `exact_subject_only`;
14. loads the exact source bundle through PR317;
15. requires the exact source bundle ID and identity;
16. requires the source bundle's canonical subject bytes to equal the contract subject's PR309 canonical bytes;
17. requires all subject SHA-256 values to agree;
18. returns a frozen read-only result.

The loader never writes, repairs, republishes, infers an approver, creates a new approval decision, evaluates capabilities, runs a preflight, creates a receipt, or grants execution eligibility.

## Structured results

| Publication status | Meaning |
| --- | --- |
| `approval_artifact_published` | One approval artifact was published atomically and verified. |
| `approval_artifact_already_present` | A fully valid byte-identical artifact was already there; nothing was written. |
| `approval_artifact_publication_blocked` | A safety or conflict gate refused; nothing was overwritten. |
| `invalid_publication_input` | The artifact or the confirmation failed before any filesystem access. |
| `publication_failed_precommit` | Preparation failed; nothing was published and cleanup completed. |
| `publication_failed_cleanup_incomplete` | Preparation failed and an invocation-owned temporary directory remains. |
| `published_verification_failed` | Publication occurred but verification failed; nothing was removed. |
| `atomic_publication_unsupported` | No proven atomic no-replace primitive exists here; failed closed. |

| Loader status | Meaning |
| --- | --- |
| `persisted_approval_artifact_loaded` | One artifact was loaded and fully revalidated. |
| `persisted_approval_artifact_not_found` | No artifact exists for that exact ID under that root. |
| `persisted_approval_artifact_invalid` | The stored artifact, its binding, or its source provenance failed validation. |
| `invalid_approval_artifact_reference` | The reference is not one exact full `aca_` artifact ID. |
| `unsafe_approval_persistence_root` | The data root or the fixed publication root is not safe. |

Build results use `approval_artifact_constructed`, `approval_artifact_construction_blocked`, and `invalid_approval_artifact_construction_input`; validation results use `approval_artifact_valid`, `approval_artifact_invalid`, and `invalid_approval_artifact_validation_input`.

Every failure is non-throwing at the public boundary, returns deterministic sorted and deduplicated errors, leaks no traceback and no host absolute path, returns no partially valid artifact, and reports accurate filesystem and mutation state.

## Accurate safety ledgers

### Artifact build and validation

```
read_only=true                             mutation_performed=false
filesystem_accessed=false                  artifact_write_performed=false
approval_created=false                     contract_created=false
approval_persisted=false                   contract_persisted=false
authorization_evaluated=false              capability_support_evaluated=false
preflight_evaluated=false                  receipt_created=false
execution_allowed=false                    execution_available=false
execution_status=not_executed
```

### Successful first publication

```
read_only=false                            mutation_performed=true
filesystem_accessed=true                   artifact_write_performed=true
publication_performed=true                 persistence_performed=true
approval_created=false                     contract_created=false
approval_persisted=true                    contract_persisted=true
persisted_approval_artifact_present=true   source_bundle_mutation_performed=false
overwrite_performed=false                  authorization_evaluated=false
capability_support_evaluated=false         capability_supported=false
preflight_evaluated=false                  receipt_created=false
receipt_linked=false                       host_configuration_mutation_performed=false
execution_allowed=false                    execution_available=false
execution_status=not_executed
```

PR319 persists the existing PR318 approval and contract; it does not create a new approval or contract. `approval_persisted` and `contract_persisted` describe what *this* invocation durably wrote; `persisted_approval_artifact_present` describes what exists afterwards.

### Existing identical artifact

```
read_only=true                             mutation_performed=false
artifact_write_performed=false             publication_performed=false
persistence_performed=false                persisted_approval_artifact_present=true
overwrite_performed=false
```

### Invalid artifact or confirmation before filesystem access

```
read_only=true                             mutation_performed=false
filesystem_accessed=false                  approval_persisted=false
contract_persisted=false
```

### Loader success

```
read_only=true                             mutation_performed=false
filesystem_accessed=true                   artifact_write_performed=false
persisted_approval_artifact_present=true   approval_loaded=true
contract_loaded=true                       approval_binding_valid=true
authorization_evaluated=false              capability_support_evaluated=false
preflight_evaluated=false                  receipt_created=false
execution_allowed=false                    execution_available=false
execution_status=not_executed
```

## Permanent warnings

Every result states that:

- persisted `approved_by` remains **self-asserted** metadata, not authenticated identity;
- reviewer provenance is not approval;
- the artifact records one **immutable approval event**, not mutable approval state;
- persistence is not authorization;
- a persisted `ApprovedChangeContract` is not capability support;
- no capability registry has been consulted;
- no current-state preflight has run;
- no receipt has been created or linked;
- **no execution eligibility is granted**;
- there is **no revocation**, cancellation, expiration, supersession, or quorum semantics;
- **no overwrite** is permitted: a persisted approval artifact is never replaced, repaired, renamed, quarantined, or deleted;
- reviewed artifacts may contain operational context and must be reviewed before sharing;
- no redaction is performed because redaction would change artifact identity.

## Explicit non-goals

PR319 adds no approval revocation, cancellation, expiration, supersession, approval status transition, approval queue, quorum or multi-approver semantics, authenticated identity, identity-provider integration, role validation, authorization infrastructure, capability registry, capability-support evaluation, capability binding, `windows.runtime_reconcile` binding, PR313 integration, current-state preflight, subject/live-plan comparison, receipt creation, receipt linkage, execution eligibility, execution, CLI command, interactive route, natural-language approval, implicit approval, legacy `Proposal` conversion or status change, arbitrary output path, mutable artifact update, overwrite, persisted-artifact deletion, retention or cleanup policy, `latest` resolution, host configuration change, service or registry change, Docker or Compose call, PowerShell/WinRM/QGA call, shell or subprocess, network call, model or provider call, credential access, and production data publication.

Persisted approval **discovery beyond exact ID** is deliberately absent: there is no listing, search, index, or "most recent approval" resolution.

## Next dependency

Stage B remains incomplete. The next focused dependency remains explicitly **non-execution** work.

Everything beyond PR319 stays deferred to PR320 or later: persisted approval discovery beyond exact ID, approval revocation, cancellation, expiration, supersession, quorum or multi-approver semantics, authenticated identity, role validation, identity-provider integration, a capability registry, capability-support evaluation, exact capability binding, binding `windows.runtime_reconcile`, current-state execution preflight, subject/live-plan comparison, receipt creation and linkage, execution eligibility, Stage C execution, CLI approval commands, natural-language approval or persistence, persisted-artifact deletion, and retention and cleanup policies.
