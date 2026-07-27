# Approved Change Artifact Persistence

PR317 adds exactly one narrowly governed filesystem boundary for Stage B. It answers exactly one question:

> Given one already-valid PR316 artifact bundle and one explicit confirmation of that exact bundle identity, how are those exact bytes published — completely, atomically, without overwrite — beneath one fixed ShellForgeAI-owned subtree, and how are they read back and revalidated afterwards?

The module `src/shellforgeai/core/approved_change_artifact_persistence.py` is that boundary and nothing else: one publisher, one read-only loader, and one narrow platform-safe atomic no-replace directory primitive.

## Why this slice exists

PR316 defined the exact persistence payload — four canonical UTF-8 JSON logical files, exact byte lengths, exact checksums, a non-circular bundle identity, and the derived `acb_` bundle ID — and deliberately recorded the publication, atomicity, overwrite, existing-identical, and destination policies as contract metadata only. It holds no path, opens nothing, and creates no file or directory.

Without PR317 any caller wanting to keep a reviewed change would have had to invent its own writer: its own directory naming, its own temporary-file scheme, its own idea of atomicity, and its own overwrite behaviour. That is precisely the ad-hoc drift the earlier slices prohibit, and it would have put correctness decisions in the least reviewable place.

PR317 implements exactly the policies PR316 recorded, and adds nothing else.

## Relationship to PR316

PR316 remains the sole authority for the four-file contract, the canonical bytes, the manifest contract, the bundle identity, the bundle ID, the builder, and the validator. PR317:

- does not change the four-file contract;
- does not change canonical bytes — it persists `content_utf8.encode("utf-8")` verbatim;
- does not change bundle identity or the bundle ID;
- adds no fifth file;
- accepts no caller-defined filename;
- reconstructs no alternative bundle schema;
- weakens no PR316 validation — it reruns `validate_approved_change_artifact_bundle` on the input bundle, on the prepared bytes, and on the persisted bytes.

PR309 remains the sole subject and approval-attestation authority, PR314 the sole reviewed supplemental-context authority, and PR315 the sole subject-construction and construction-evidence authority. PR313's `windows.runtime_reconcile` capability remains independent: PR317 does not import, reference, bind, or integrate it.

## Exact fixed on-disk layout

```
<data_dir>/
  approved_change_artifacts/
    acb_<64 lowercase hex>/
      supplemental-context.json
      approved-change-subject.json
      construction-evidence.json
      manifest.json
```

- `approved_change_artifacts` is one fixed directory-name constant. There is no caller override, alias, alternate spelling, or configurable variant.
- The final directory name is exactly the PR316 `bundle_id`.
- The persisted bundle directory contains exactly the four PR316 files and nothing else.

There is no completion marker, lock file, checksum sidecar, Markdown rendering, receipt, timestamp file, metadata file, or temporary filename inside the final directory. The structured publication result is never persisted as a fifth file.

## Public API

```python
publish_approved_change_artifact_bundle(
    bundle: ApprovedChangeArtifactBundle | dict[str, Any],
    *,
    data_dir: Path | str,
    confirm_bundle_identity_sha256: str,
) -> ApprovedChangeArtifactBundlePublicationResult

load_persisted_approved_change_artifact_bundle(
    bundle_id: str,
    *,
    data_dir: Path | str,
) -> ApprovedChangeArtifactBundleLoadResult
```

Neither entry point accepts an arbitrary output path, a caller-defined publication root, a caller-defined final directory name, a caller-defined filename, a manifest separately from the bundle, a subject or evidence separately from the bundle, a legacy `Proposal`, approval data, capability-registry data, execution data, a shell command, a URL, or a `latest` / `current` / implicit bundle reference.

## Explicit publication confirmation

`confirm_bundle_identity_sha256` must be exactly 64 lowercase hexadecimal characters and must equal `bundle.bundle_identity_sha256`. The comparison uses `hmac.compare_digest`. The prefixed bundle ID is never accepted as the confirmation value, and confirmation is never inferred from the bundle.

The confirmation authorizes exactly one thing:

> publication of this exact already-validated bundle identity beneath the fixed ShellForgeAI artifact subtree.

It is not approval of the reviewed change, authorization to execute the subject, capability support, confirmation of a plan or recipe, execution confirmation, or permission to overwrite.

An invalid or mismatched confirmation causes zero filesystem access, zero directory creation, zero file creation, zero cleanup, and zero persistence. Fresh in-memory PR316 validation runs before confirmation checking, but no filesystem object is inspected or mutated until both the bundle and the confirmation are valid.

## Data-root and path-safety contract

ShellForgeAI writes artifacts only under the configured `<data_dir>`. The publisher accepts that explicit resolved data root and never an arbitrary final destination. It requires that `data_dir`:

- is absolute;
- already exists;
- is a directory;
- is not the filesystem root or a drive root;
- is not a symlink or reparse point.

The fixed publication root must remain a direct contained child of `data_dir`, and all temporary and final paths must remain direct contained children of that fixed root. Containment is rechecked before preparation and again before final publication, and resolved-path containment is compared with `os.path.realpath` so a final path can never escape the resolved data directory.

Purely structural rejections (a non-string/non-path value, a relative path, a filesystem or drive root) happen before any filesystem object is inspected, so the reported `filesystem_accessed` flag stays truthful.

### Publication root creation

`<data_dir>/approved_change_artifacts` is the only directory the publisher may create beyond its own temporary sibling and the final bundle directory, and it is created only after the bundle has passed fresh PR316 validation and the explicit confirmation has matched.

If the invocation created that root and publication fails before commit, the root is removed only when the invocation created it, its own temporary directory was fully removed, it is still empty, and it is still the exact safe direct child. A pre-existing publication root is never removed.

### Symlink, reparse, and alias safety

Publication and loading fail closed on a symlinked `data_dir`, a symlinked or reparse-point publication root, final bundle directory, temporary directory, or persisted file, on final paths that escape the resolved data directory, on path identity changing between preparation and commit, and on unexpected directory entries. Checks use `lstat`/`fstat` and, where the platform supports it, `O_NOFOLLOW`; where it does not, file type, path containment, and pre-open/post-open `(st_dev, st_ino)` identity are revalidated instead.

The loader never follows a path supplied inside the manifest. The manifest cannot redirect the loader.

## Publication sequence

1. Validate the untrusted bundle through the maintained PR316 validator.
2. Require `status=bundle_valid`, `bundle_valid=true`, the exact bundle identity, and the exact full bundle ID.
3. Validate the confirmation format.
4. Compare the confirmation to the bundle identity with `hmac.compare_digest`.
5. Validate the explicit `data_dir`.
6. Derive the fixed publication root.
7. Safely inspect or create the fixed publication root.
8. Derive the exact final bundle directory from the full bundle ID.
9. If the final directory already exists, load it through the read-only loader and return `bundle_already_present` only when it is fully valid and byte-identical; otherwise block without writing.
10. Create one private temporary sibling directory under the fixed publication root.
11. Write the exact four PR316 byte streams into that temporary directory.
12. Flush and verify every file.
13. Verify the exact temporary directory contents.
14. Reconstruct a PR316 bundle from the prepared bytes.
15. Rerun the maintained PR316 validator on the prepared bundle.
16. Flush the temporary directory where supported.
17. Perform one atomic no-replace directory transition from the temporary sibling to the exact final bundle directory.
18. Load the final persisted bundle through the read-only loader.
19. Require complete post-publication validation.
20. Return the structured publication result.

No final directory is ever visible before step 17.

## Temporary sibling contract

One private temporary directory is created beneath `<data_dir>/approved_change_artifacts/`, named `.pending-<16 lowercase hex>` — a short fixed prefix plus one internally generated token, 25 characters in total. It is:

- a direct child of the fixed publication root, and therefore on the same filesystem as the final directory;
- named internally, with no caller-provided suffix and no bundle ID;
- created exclusively with `os.mkdir` and restrictive mode `0o700` where supported;
- verified not to be a symlink or reparse point;
- never recorded inside the bundle, the manifest, or any persisted file.

Randomness is used only for the unpublished temporary directory name. The private token never affects canonical bytes, bundle identity, the bundle ID, any persisted file, any semantic identity, or any public durable identifier.

### Why the pending name carries no bundle ID

The pending directory deliberately does **not** repeat the 68-character bundle ID. Doing so made the unpublished temporary path 42 characters longer than the durable path it prepares, so a data root whose final bundle path fit could still overflow the Windows `MAX_PATH` limit while writing the temporary copy: under ordinary Windows test-root geometry the temporary `supplemental-context.json` path reached exactly 260 characters and exclusive creation failed with `Errno 2`.

With the short name the pending path is always shorter than the final path it prepares, so preparation can never be the binding length constraint. The full exact PR316 bundle ID remains the final durable directory name, unchanged: `approved_change_artifacts/acb_<64 lowercase hex>/`.

### Addressable final paths

The four persisted filenames are fixed, so the longest final path a publication would ever need is known before anything is created. When that path exceeds what the platform can address without extended-length path syntax — `MAX_PUBLICATION_PATH_CHARS`, 259 on Windows (`MAX_PATH` minus the terminating NUL) and 4095 on POSIX — publication is blocked up front with `publication_blocked`, before the publication root, any temporary directory, or any file is created. Only lengths are reported; no host absolute path enters a result.

PR317 adds no extended-length path support and never emits a `\?\` path in a public result or in persisted data.

## Exact binary writes

Each file is written from `ApprovedChangeArtifactBundle.files` in the exact fixed order, under the exact fixed filename, from `content_utf8.encode("utf-8")`. Files are created with `O_CREAT | O_EXCL | O_WRONLY | O_BINARY | O_NOFOLLOW` and mode `0o600` where supported, so there is no text-mode newline translation, no BOM, no indentation, no reserialization, and no trailing newline. PR316 already defines the exact bytes; PR317 persists them verbatim and never rebuilds or pretty-prints JSON at the persistence layer.

After each write the file is flushed, then reread and verified for regular-file type, exact byte length, and exact SHA-256, with symlink/reparse substitution refused. All four files are prepared and verified before final publication.

## Flush and durability posture

Before final publication each file is flushed with `os.fsync`, and the prepared directory is flushed where supported. The result records whether directory flush `passed`, is `unsupported`, or `failed`. A required file flush failure blocks publication; a prepared-directory flush failure blocks publication.

The prepared-file flush descriptor is opened **write-capable** (`O_RDWR | O_BINARY | O_NOFOLLOW`). On Windows `os.fsync` maps to `FlushFileBuffers`, which requires write access on the handle and fails with `EBADF` on a read-only descriptor. Nothing is written through that descriptor: the file is one this invocation just created exclusively inside its own private temporary directory, and the same no-follow, regular-file, and pre-open/post-open `(st_dev, st_ino)` identity checks apply as for reads. An `EBADF` — or any other — flush failure is never downgraded to `unsupported`, never skipped, and never swallowed: `file_flush_status` becomes `failed` and publication blocks with no final directory and bounded cleanup of the invocation's own temporary files.

Windows offers no directory flush primitive, so `temporary_directory_flush_status` and `publication_root_flush_status` are reported as `unsupported` there. The limitation is stated explicitly and success is never invented.

After final publication the publication root is flushed where supported and full read-only post-publication validation runs. If a post-publication durability flush fails after the atomic commit, the final bundle is not deleted: the result truthfully records that publication occurred but that durability assurance is incomplete.

## Atomic no-replace requirement

The final publication step is atomic, same-parent, same-filesystem, directory-level, and no-replace. A pre-check followed by a replace-capable rename is insufficient, so `os.replace`, `os.rename`, `Path.replace`, `Path.rename`, `shutil`, a shell, a subprocess, and external binaries are all unreachable from this module.

| Platform | Primitive | Behaviour when the destination exists |
| --- | --- | --- |
| Linux | `renameat2(AT_FDCWD, …, RENAME_NOREPLACE)` via the glibc wrapper, falling back to the architecture's `__NR_renameat2` syscall number | fails with `EEXIST`/`ENOTEMPTY`, replacing nothing |
| Windows | `MoveFileExW(source, destination, 0)` — no `MOVEFILE_REPLACE_EXISTING` | fails with `ERROR_ALREADY_EXISTS`/`ERROR_FILE_EXISTS`, replacing nothing |

The primitive never replaces an existing empty directory, an existing invalid directory, an existing valid bundle, or a destination that appeared in a race. It rejects non-`Path`, relative, identical, cross-parent, cross-filesystem, missing, non-directory, and symlinked-source requests before any native call.

If the platform cannot provide a proven atomic no-replace directory publication primitive — an unknown platform, or a kernel/filesystem answering `ENOSYS`/`EINVAL`/`EOPNOTSUPP` — publication fails closed with `atomic_publication_unsupported` before the final transition. It never silently downgrades to replace-capable behaviour.

Native platform API use is confined to `_linux_renameat2_no_replace` and `_windows_move_file_no_replace`. Both use fixed platform API signatures, receive only already-validated invocation-owned temporary and final paths, load no caller-selected library, and expose no generic native invocation.

## Existing-destination behaviour

### Valid identical existing bundle

`bundle_already_present` is returned only when the existing directory loads cleanly through the read-only loader, its bundle ID matches, its bundle identity matches, and all four exact byte streams match. No temporary directory is created, no file is written, no timestamp is refreshed, no overwrite occurs, and no persistence mutation is claimed.

### Invalid or conflicting existing directory

Publication blocks when the directory has missing files, extra files, a symlink/reparse-point or non-regular entry, a differing byte length or checksum, a noncanonical manifest, a failing PR316 validation, a differing bundle identity or bundle ID, or bytes that are not byte-identical. The existing directory is never repaired, replaced, quarantined, renamed, deleted, merged, or written around.

## Destination-appeared race

If the final directory appears after preparation but before commit, the atomic no-replace operation fails without replacing it. The invocation then cleans up only its own unpublished temporary directory, loads and validates the newly appeared final directory, and returns `bundle_already_present` only if it is now a fully valid byte-identical bundle. Every other case returns a conflict/block result. The appeared destination is never overwritten or removed.

## Cleanup boundaries

Cleanup is strictly bounded to an unpublished temporary directory created by that exact invocation. The invocation tracks its exact temporary directory and the exact files it successfully created, and on pre-commit failure it:

1. removes only the exact files it created, after reverifying that each is still a regular non-reparse file inside that temporary directory;
2. refuses to remove unknown or additional entries;
3. removes the temporary directory only when it is empty;
4. removes the publication root only when this invocation created it, the temporary directory is gone, and the root is still empty.

There is no generic recursive deletion against an arbitrary path. The final directory, a pre-existing directory, an unknown file, an unexpected extra entry, and any path outside the fixed publication root are never deleted.

When cleanup is incomplete the result says so explicitly, sets `temporary_cleanup=incomplete`, reports only a safe root-relative temporary reference in `residual_temporary_directory`, and never continues to publication.

## Post-publication verification

After the atomic publication succeeds the final bundle is never automatically deleted, never rolled back to absence, and never overwritten. It is retained for operator investigation.

If final read-back or PR316 validation fails, the result is `published_verification_failed` and truthfully reports that publication occurred, that persistence occurred, that post-verification failed, that no automatic removal was attempted, and that approval and execution remain false.

## Read-only persisted-bundle loader

The loader accepts only `bundle_id` and `data_dir`, never an arbitrary path. Its sequence is:

1. Validate the bundle ID as exactly `acb_` plus 64 lowercase hex.
2. Validate the explicit existing `data_dir`.
3. Derive the fixed publication root.
4. Derive the exact bundle directory.
5. Refuse path separators, traversal, drive paths, UNC paths, case variants, aliases, whitespace, and implicit references.
6. Require a real directory that is not a symlink or reparse point.
7. Require exactly four entries with the exact PR316 filenames.
8. Require all four entries to be regular files that are not symlinks or reparse points.
9. Read the four files in binary mode with explicit size bounds.
10. Decode strict UTF-8.
11. Reconstruct the PR316 logical file records.
12. Parse the manifest only as untrusted data.
13. Construct the PR316 top-level bundle.
14. Run the maintained PR316 validator.
15. Return a structured result.

`latest`, `current`, "most recent", path references, directory paths, filename references, globbing, prefix matching, and shortened hashes are all rejected as `invalid_persisted_bundle_reference`.

### Read-size bounds

```
MAX_PERSISTED_BUNDLE_FILE_BYTES  = 1048576   (1 MiB per file)
MAX_PERSISTED_BUNDLE_TOTAL_BYTES = 4194304   (4 MiB per bundle)
```

Every file's size, regular-file type, and non-reparse status are inspected before any content is read. Files over the per-file limit, bundles over the total limit, negative or inconsistent sizes, and non-regular files are rejected without reading. Reads fail closed if the file is truncated, grows during the read, or changes size between inspection and read. No unbounded untrusted file is ever read into memory.

## Accurate safety ledgers

Publication is an artifact filesystem mutation and is reported truthfully.

| Outcome | `read_only` | `mutation_performed` | `artifact_write_performed` | `filesystem_accessed` | `publication_performed` | `persistence_performed` | `overwrite_performed` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Successful first publication | `false` | `true` | `true` | `true` | `true` | `true` | `false` |
| Existing identical bundle | `true` | `false` | `false` | `true` | `false` | `false` | `false` |
| Pre-commit failure after temporary writes | `false` | `true` | `true` | `true` | `false` | `false` | `false` |
| Invalid bundle or confirmation | `true` | `false` | `false` | `false` | `false` | `false` | `false` |

A temporary write followed by cleanup is still a filesystem mutation. `host_configuration_mutation_performed` is always `false`.

On every publication and load result these remain `false`: `approval_created`, `contract_created`, `receipt_created`, `capability_support_evaluated`, `capability_supported`, `approval_evaluated`, `authorization_evaluated`, `execution_allowed`, `execution_available`; and `execution_status` is always `not_executed`.

### Publication result statuses

| Status | Meaning |
| --- | --- |
| `bundle_published` | The four files were published atomically and revalidated. |
| `bundle_already_present` | A fully valid byte-identical bundle was already published; nothing was written. |
| `publication_blocked` | An unsafe root, unsafe path, or conflicting existing directory blocked publication. |
| `invalid_publication_input` | The bundle or the confirmation failed before any filesystem access. |
| `publication_failed_precommit` | Preparation failed; the invocation's own temporary directory was removed. |
| `publication_failed_cleanup_incomplete` | Preparation failed and the invocation's temporary directory could not be fully removed. |
| `published_verification_failed` | Publication occurred but post-publication verification failed; the bundle was retained. |
| `atomic_publication_unsupported` | No proven atomic no-replace primitive exists here; publication failed closed. |

Result fields include `status`, `reason`, `bundle_id`, `bundle_identity_sha256`, `confirmation_matched`, `confirmation_scope`, `relative_bundle_directory`, `publication_root_created`, `publication_root_removed`, `temporary_directory_created`, `all_files_prepared_before_publish`, `prepared_file_count`, `file_flush_status`, `temporary_directory_flush_status`, `atomic_publish_attempted`, `atomic_publish_succeeded`, `atomic_publish_outcome`, `publication_root_flush_status`, `post_validation_status`, `temporary_cleanup`, `residual_temporary_directory`, `errors`, and `warnings`.

Paths in results are root-relative. No host absolute path is embedded in a result, in the bundle, or in any persisted file, and no credential or secret value is ever recorded.

### Loader result statuses

| Status | Meaning |
| --- | --- |
| `persisted_bundle_loaded` | One persisted bundle was read and revalidated through PR316. |
| `persisted_bundle_not_found` | No persisted bundle exists for that exact bundle ID. |
| `persisted_bundle_invalid` | The persisted directory or bytes failed the fixed file-set, bound, or PR316 checks. |
| `invalid_persisted_bundle_reference` | The reference was not one exact full bundle ID. |
| `unsafe_persistence_root` | The data directory or fixed publication root was not safe. |

The loader returns structured invalid results rather than leaking a traceback.

## Permanent warnings

Every publisher and loader result states that:

- a persisted bundle is not approval and persistence is not authorization;
- a persisted bundle is not an `ApprovedChangeContract`;
- reviewer provenance is not authenticated identity;
- bundle identity is not subject identity and is not capability support;
- explicit publication confirmation is scoped only to artifact publication and is not execution confirmation;
- publication grants no execution eligibility;
- no overwrite is permitted;
- reviewed artifacts may contain operational context and must be reviewed before sharing;
- no redaction is performed because redaction would change reviewed identity.

## Semantic separation

A successfully persisted bundle does not create approval, create an approved contract, evaluate authorization, evaluate capability support, bind a capability, create or link a receipt, enable execution, or integrate PR313. Persistence is an artifact-storage fact about bytes on disk, nothing more.

## Explicit non-goals

PR317 adds no CLI command, interactive route, natural-language publication, implicit publication, approval attestation, approved-contract construction, authenticated identity, approval workflow, approval persistence, capability registry, capability-support evaluation, capability binding, `windows.runtime_reconcile` binding, PR313 integration, current-state preflight, subject/live-plan comparison, receipt creation, receipt linkage, execution eligibility, execution, host-configuration change, service change, registry change, Docker or Compose call, PowerShell/WinRM/QGA call, model or provider call, network call, shell, subprocess, package installation, cleanup of existing persisted bundles, retention integration, bundle deletion, bundle overwrite, bundle update, `latest` reference resolution, export or sharing functionality, or redaction.

The production module imports only `__future__`, `ctypes`, `dataclasses`, `hashlib`, `hmac`, `json`, `os`, `pathlib`, `platform`, `pydantic`, `re`, `secrets`, `stat`, `sys`, `typing`, and the maintained PR316 bundle module.

## Approval-workflow consumer (PR318)

Persisted artifacts are the substrate an approval workflow needs, not the approval itself. PR318 is the first and only consumer of the loader: [Approved Change Approval Workflow](APPROVED_CHANGE_APPROVAL_WORKFLOW.md) calls `load_persisted_approved_change_artifact_bundle` with one exact bundle ID and one explicit `data_dir`, and builds one `ApprovalAttestation` and one `ApprovedChangeContract` in memory from the loaded bundle.

PR317 is unchanged by it. PR318 adds no alternate loader, accepts no arbitrary persisted path, bypasses no PR316 validation, rewrites or repairs no persisted byte, republishes nothing, and changes no publisher behaviour or on-disk layout. Loading for approval remains strictly read-only: after an approval binding the persisted tree is byte- and mtime-identical.

## Remaining deferred work

Approval persistence itself is still not implemented anywhere: PR318 keeps its approval and contract in memory only. Canonical approval-artifact persistence, persisted approval loading, authenticated identity, capability registry, capability-support evaluation, exact capability binding, current-state preflight, subject-to-receipt linkage, execution eligibility, persisted-bundle deletion, retention integration, and any CLI or natural-language access all remain deferred to PR319 or later.
