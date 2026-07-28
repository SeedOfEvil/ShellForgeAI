# Approved Change Approval Inventory

PR320 adds exactly one Stage B capability. It answers exactly one question:

> Which approval artifacts are currently persisted beneath the fixed PR319 approval subtree, and which direct children of that subtree are *not* valid approval artifacts?

One module is that capability and nothing else:

- `src/shellforgeai/core/approved_change_approval_inventory.py` — one bounded, deterministic, read-only inventory over the fixed PR319 approval-artifact root.

## Why this slice exists

PR319 persists approval artifacts and reads exactly one back by its exact full `aca_` artifact ID. That is deliberately the whole read surface: PR319 has no listing, no search, no index, no "latest", and no "current" resolution.

That leaves one honest gap. An operator, an audit, or a later review step that does not already hold an exact artifact ID has no safe way to learn what is actually on disk — and no way to learn that something *unexpected* is on disk. Without one governed operation, every caller would have invented its own directory walk, its own idea of which names count, its own artifact parser, and its own silent skipping of whatever it did not understand. Silent skipping is the dangerous part: an approval subtree that quietly drops the entries it cannot read looks identical to a clean one.

PR320 makes that one discovery step bounded, deterministic, loader-only, and explicitly incomplete when it cannot be complete.

**Inventory is discovery. It is not selection, not authorization, and not capability support.**

## Relationship to PR319

PR319 remains the sole authority for:

- the canonical approval-artifact bytes and their canonicalization;
- approval-artifact identity and the `aca_` artifact ID rule;
- the fixed `<data_dir>/approved_change_approvals` subtree;
- atomic no-replace approval-artifact publication;
- exact-ID approval-artifact loading, including revalidation of the PR309 approval binding and the exact PR317 source bundle.

PR320 adds no parser, no loader, and no identity rule of its own. Every exact candidate is validated **only** by calling:

```python
load_persisted_approved_change_approval_artifact(
    approval_artifact_id: str,
    *,
    data_dir: Path | str,
) -> ApprovedChangeApprovalArtifactLoadResult
```

An inventory entry exists if and only if that maintained loader returned `persisted_approval_artifact_loaded` with a valid artifact and a valid PR309 approval binding. PR320 reads no artifact file itself, parses no artifact JSON, recomputes no identity, recomputes no binding, and never loads a PR317 source bundle directly.

PR320 also never calls the PR319 publisher, and never repairs, rewrites, republishes, renames, quarantines, deletes, or timestamp-refreshes any artifact.

PR309 remains authoritative for the subject, the attestation, the contract, subject canonicalization, subject SHA-256, `exact_subject_only`, and approval-to-subject binding. PR316 remains authoritative for the reviewed bundle and its identity. PR317 remains authoritative for persisted reviewed-change source bundles and their exact-ID loader. PR318 remains authoritative for explicit in-memory approval creation.

`src/shellforgeai/core/approvals.py` remains the legacy `Proposal` schema-v1 workflow, and PR310's non-portability decision remains in force. PR320 scans no legacy approval directory, converts no legacy `Proposal`, reads no legacy approval status, marks no proposal approved, treats no `Proposal` fingerprint as a subject or artifact identity, and never combines legacy proposals with this inventory.

## Public API

Exactly one public operation:

```python
inventory_persisted_approved_change_approval_artifacts(
    *,
    data_dir: Path | str,
) -> ApprovedChangeApprovalArtifactInventoryResult
```

The operation accepts **only** the explicit ShellForgeAI data root. It accepts no arbitrary approval-root path, no arbitrary artifact directory, no artifact-ID query, no subject query, no source-bundle query, no approver query, no approval-time range, no sort key, no descending flag, no entry-limit override, no `latest`, `current`, or "most recent" reference, no capability ID, no capability registry, no execution target, no caller-supplied artifact, and no output path.

## Fixed root and direct-child-only scan

The inventory root is derived, never supplied:

```
<data_dir>/approved_change_approvals
```

Only the **direct children** of that root are inspected. The operation never recurses, never walks grandchildren, never uses a recursive glob, never follows a symlink or reparse point, never accepts a path embedded in artifact content, and never uses a caller-supplied entry path. Validation *inside* an exact candidate directory belongs to the PR319 loader and stays there.

## Fixed entry-count bound

```python
MAX_APPROVAL_ARTIFACT_INVENTORY_ENTRIES = 1024
```

This is a fixed maintained constant, never a caller-controlled parameter.

Every direct child is counted, including malformed and unexpected names. If the root holds more than the bound, the operation fails closed with `approval_artifact_inventory_limit_exceeded`: no partial inventory is returned, nothing is silently truncated, and **no artifact is loaded at all** — the bound is enforced before the first loader call. Only counts and safe root-relative names are reported; no host absolute path ever reaches a result.

The bound protects a read-only operation from unbounded directory and validation work. **It is not a retention policy.** Nothing is ever deleted or cleaned up.

## Exact candidate-name rule

A direct child is an approval-artifact candidate if and only if its name is exactly:

```
aca_ + 64 lowercase hexadecimal characters
```

using the same maintained PR319 artifact-ID rule. Names are evaluated **first**, before the entry is inspected at all, so an unexpected child such as `latest`, `current`, `most-recent`, `aca_short`, an uppercase `ACA_…`, a `.pending-…` remnant, or an `index.json` is reported without ever being opened, followed, or descended into.

## Loader-only validation

For each exact candidate, in deterministic name order:

1. the entry is inspected with no-follow semantics (`lstat`);
2. a symlink or reparse point is reported and never followed;
3. a non-directory is reported;
4. the entry's filesystem identity is captured;
5. the maintained PR319 exact-ID loader is called with the entry's exact name;
6. the entry's filesystem identity is rechecked;
7. an entry is emitted only for a fully valid loaded artifact, and every other loader outcome becomes an explicit anomaly carrying the exact loader status.

## Inventory entry fields

`ApprovedChangeApprovalArtifactInventoryEntry` is frozen and carries only already-validated maintained metadata taken from a successful PR319 load result:

| Field | Meaning |
| --- | --- |
| `approval_artifact_id` | The exact full `aca_` artifact ID. |
| `approval_artifact_identity_sha256` | The maintained artifact identity. |
| `artifact_byte_length` | The canonical artifact byte length. |
| `source_bundle_id` | The exact PR316/PR317 `acb_` source bundle ID. |
| `source_bundle_identity_sha256` | The exact source bundle identity. |
| `subject_sha256` | The exact PR309 subject SHA-256. |
| `approved_by` | Self-asserted approver metadata. |
| `approved_at` | The maintained canonical UTC approval instant. |
| `approval_scope` | Always `exact_subject_only`. |
| `approval_binding_valid` | The revalidated PR309 binding outcome. |

The summary deliberately omits the **approval reason**, the full contract, the canonical content, any filesystem timestamp, any host absolute path, any mutable status, and any capability, preflight, receipt, or execution field. `approved_by` is never treated as authenticated identity.

**The exact-ID PR319 loader remains the only operation that returns the complete artifact and the approval reason.**

## Inventory anomaly fields

`ApprovedChangeApprovalArtifactInventoryAnomaly` is frozen and carries `entry_name`, `category`, `loader_status`, `reason`, and `errors`.

`entry_name` is the direct child's single safe name only — never a host absolute path and never a parent path. Errors are deterministically sorted and deduplicated, carry no traceback, and have the host data root redacted to `<data_dir>`.

| Category | Meaning |
| --- | --- |
| `unexpected_name` | The name is not exactly `aca_` + 64 lowercase hex. The entry is never inspected, followed, or recursed into. |
| `symlink_or_reparse_entry` | An exact-named child is a symlink or reparse point. It is never followed. |
| `non_directory_entry` | An exact-named child exists but is not a directory. |
| `entry_not_inspectable` | An exact-named child could not be safely inspected. |
| `entry_disappeared` | An exact-named child vanished before or during validation. |
| `entry_changed_during_inventory` | An exact-named child's filesystem identity changed during validation. |
| `invalid_approval_artifact` | The maintained PR319 loader did not return a fully valid artifact; its exact status is recorded. |

No anomalous entry is followed, recursed into, repaired, renamed, quarantined, or removed.

## Deterministic ordering

Entries are sorted **lexicographically by exact `approval_artifact_id` and by nothing else**. Anomalies are sorted lexicographically by `(entry_name, category)`.

Ordering never uses filesystem mtime, ctime, birth time, approval timestamp, approver, source bundle, subject, creation order, or filesystem enumeration order. Repeating the inventory over an unchanged root returns a model-dump-identical result, on Linux and on Windows alike.

Ordering is **not** chronological, priority-based, risk-based, or authoritative. It is a stable presentation order, nothing more.

## Statuses

| Status | Meaning | `inventory_complete` |
| --- | --- | --- |
| `approval_artifact_inventory_loaded` | Every direct child is a valid approval artifact. | `true` |
| `approval_artifact_inventory_empty` | The fixed root is absent, or present and empty. | `true` |
| `approval_artifact_inventory_loaded_with_anomalies` | The scan completed safely but at least one direct child is unexpected, unsafe, missing, or invalid. | `false` |
| `approval_artifact_inventory_blocked` | A root-safety gate refused; no entries are returned. | `false` |
| `approval_artifact_inventory_limit_exceeded` | The fixed entry bound was exceeded; no partial inventory is returned. | `false` |
| `invalid_inventory_input` | The explicit data root is structurally invalid; the filesystem was never touched. | `false` |

### Empty inventory

An absent fixed root is an empty **complete** inventory. **The missing root is never created.**

### Blocking conditions

No entries are returned when the explicit data root is structurally invalid or unsafe, the fixed approval root is a symlink or reparse point, the fixed approval root exists but is not a directory, the root cannot be safely inspected, safe direct-child enumeration cannot complete, the root's filesystem identity changes during the inventory, or the fixed entry-count bound is exceeded.

### `inventory_complete` semantics

`inventory_complete` is the only field that states whether the returned entries are the whole safe truth about the fixed root. It is `true` only for a fully clean scan and for an empty root.

**No later automated consumer may treat `inventory_complete=false` as a complete inventory.** An anomalous inventory returns real entries *and* explicit anomalies, and it never implies that the returned entries are a complete trusted approval set.

## Accurate safety ledgers

### Successful, empty, or anomalous inventory

```
read_only=true
mutation_performed=false
filesystem_accessed=true
artifact_write_performed=false
publication_performed=false
persistence_performed=false
inventory_performed=true
inventory_index_written=false
approval_selected=false
approval_created=false
approval_persisted=false
contract_created=false
contract_persisted=false
authorization_evaluated=false
capability_support_evaluated=false
capability_supported=false
capability_bound=false
preflight_evaluated=false
receipt_created=false
receipt_linked=false
host_configuration_mutation_performed=false
execution_allowed=false
execution_available=false
execution_status=not_executed
```

### Structurally invalid input before filesystem access

```
read_only=true
mutation_performed=false
filesystem_accessed=false
inventory_performed=false
```

### Absent fixed approval root

The explicit data root *was* inspected, so the ledger reports it truthfully:

```
filesystem_accessed=true
inventory_root_present=false
inventory_performed=true
status=approval_artifact_inventory_empty
```

No directory is created.

### Blocked and limit-exceeded results

```
filesystem_accessed=true
inventory_performed=false
inventory_complete=false
entries=()
```

## Permanent warnings

Every result states that:

- inventory is **discovery only and selects no approval**;
- inventory ordering is **lexicographic by exact approval-artifact ID only**;
- inventory ordering is **not chronological**, priority-based, risk-based, or authoritative;
- no `latest`, `current`, or "most recent approval" is resolved;
- an exact `aca_` approval-artifact ID remains required for subsequent loading or any future operation;
- an anomalous inventory is **explicitly incomplete** and is never a complete trusted approval set;
- no persisted index, pointer, or cache is created or consulted;
- no artifact is repaired, overwritten, renamed, quarantined, or deleted;
- persisted `approved_by` remains **self-asserted** metadata, not authenticated identity;
- reviewer provenance is not approval;
- the artifact records one immutable approval event, not mutable approval state;
- persistence is not authorization;
- a persisted `ApprovedChangeContract` is not capability support;
- no capability registry has been consulted;
- no current-state preflight has run;
- no receipt has been created or linked;
- **no execution eligibility is granted**;
- there is no revocation, cancellation, expiration, supersession, or quorum semantics;
- no overwrite is permitted;
- reviewed artifacts may contain operational context and must be reviewed before sharing;
- no redaction of artifact content is performed because redaction would change artifact identity.

## Static boundary

The production module imports exactly `__future__`, `os`, `stat`, `pathlib`, `typing`, `pydantic`, and the three maintained ShellForgeAI modules it depends on. It opens no file for writing, creates no file or directory, renames or replaces nothing, unlinks or removes nothing, truncates nothing, uses no temporary directory, uses no recursive traversal, uses no shell or subprocess, uses no PowerShell, uses no network API, uses no Docker or Compose call, makes no model or provider call, accesses no credential, inspects no environment variable, OS user, or hostname for identity, reads no clock, uses no randomness or UUID, imports no PR313 execution module, imports no legacy approvals module, imports no capability registry, never calls `validate_approved_change_contract`, never calls the PR319 publisher, and registers no CLI command.

It reuses PR319's maintained constants, artifact-ID rule, root-safety helpers, and loader rather than duplicating their semantics. The narrow private-helper reuse is covered by import guards and tests in both focused suites.

## Explicit non-goals

PR320 adds no `latest`, `current`, or "most recent" resolution, no automatic approval selection, no preferred-artifact resolution, no mtime ordering, no approval-time ordering, no filtering, no search, no ranking, no pagination, no persisted index, no inventory cache, no index file, no pointer file, no arbitrary root selection, no recursion, no artifact repair, no artifact overwrite, no artifact deletion, no retention or cleanup, no approval revocation, cancellation, expiration, or supersession, no quorum or multi-approver semantics, no authenticated identity, no identity-provider integration, no role validation, no authorization infrastructure, no capability registry, no capability-support evaluation, no capability binding, no `windows.runtime_reconcile` binding, no PR313 integration, no current-state preflight, no subject/live-plan comparison, no receipt creation or linkage, no execution eligibility, no execution, no CLI command, no interactive route, no natural-language approval or discovery, no legacy `Proposal` conversion or status change, no host configuration change, no service or registry change, no Docker or Compose call, no PowerShell/WinRM/QGA call, no shell or subprocess, no network call, no model or provider call, no credential access, no current-time lookup, no randomness or UUID, and **no filesystem write of any kind**.

There is no new persisted subtree and no new persisted file, so the data layout is unchanged.

## Next dependency

Stage B remains incomplete. That typed, read-only capability-support declaration and evaluation contract landed in PR321 in [Approved Change Capability Support](APPROVED_CHANGE_CAPABILITY_SUPPORT.md). PR321 does **not** consume this inventory: it requires one exact `aca_` artifact ID, calls no inventory operation, and resolves no `latest`, `current`, or "most recent" approval. Discovery and evaluation stay separate, and the next focused dependency remains explicitly **non-execution** work: exact read-only capability binding.

Everything else stays deferred to PR322 or later: exact capability binding, binding `windows.runtime_reconcile` to the PR313 lane, authenticated identity, role validation, identity-provider integration, current-state execution preflight, subject/live-plan comparison, receipt creation and linkage, execution eligibility, Stage C execution, approval revocation, cancellation, expiration, supersession, quorum or multi-approver semantics, filtered approval search, automatic artifact selection, `latest` or `current` resolution, persisted indices, CLI approval commands, natural-language approval, inventory, or persistence, artifact deletion, and retention and cleanup policies.
