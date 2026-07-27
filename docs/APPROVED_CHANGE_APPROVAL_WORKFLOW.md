# Approved Change Approval Workflow

PR318 adds exactly one read-only Stage B operation. It answers exactly one question:

> Given one exact persisted PR317 bundle, an explicit confirmation of that exact bundle identity, an explicit confirmation of the exact PR309 subject SHA-256, and explicit approval metadata, how is one `ApprovalAttestation` and one `ApprovedChangeContract` constructed in memory and verified against that exact subject?

The module `src/shellforgeai/core/approved_change_approval_workflow.py` is that operation and nothing else.

## Why this slice exists

PR309 defined the approval contract but deliberately created no approval. PR314–PR316 defined the reviewed context, the constructed subject, the construction evidence, and the four-file bundle. PR317 published those exact bytes and offered one read-only exact-ID loader.

The gap left afterwards was the most dangerous one to leave to callers: turning a reviewed, persisted change into an approval. Without a single governed operation, every caller would have had to reload the bundle its own way, decide for itself which bytes were "the subject", recompute or *not* recompute subject identity, invent its own idea of what an approval decision looks like, and quietly borrow reviewer provenance as the approver. That is exactly the drift the earlier slices exist to prevent, and it would have put approval identity in the least reviewable place.

PR318 makes that one step explicit, exact, and inert.

## Relationship to PR309 and PR317

PR309 remains the sole authority for `ApprovedChangeSubject`, `ApprovalAttestation`, `ApprovedChangeContract`, subject canonicalization, subject SHA-256, the approval scope `exact_subject_only`, exact approval-to-subject binding, and inert contract validation. PR318 constructs those maintained models and calls `verify_approval_binding`; it defines no schema, no canonicalization, and no identity of its own.

PR314–PR316 remain authoritative for reviewed context, subject construction, construction evidence, the four-file bundle, the canonical bytes, and the bundle identity.

PR317 remains the sole governed publisher and the sole exact-ID read-only loader for persisted bundles. PR318 loads through `load_persisted_approved_change_artifact_bundle` and nothing else. It:

- invents no alternate loader;
- accepts no arbitrary filesystem path;
- bypasses no PR316 validation;
- rewrites and repairs no persisted byte;
- republishes nothing;
- changes no PR317 on-disk layout.

`src/shellforgeai/core/approvals.py` remains the legacy `Proposal` schema-v1 paper-trail workflow, and PR310's non-portability decision remains in force. PR318 converts no legacy `Proposal`, reuses no legacy approval status, moves no legacy proposal file, imports no legacy approval identity, marks no legacy proposal approved, and bridges no PR309 approval into the legacy queue.

## Public API

```python
construct_approved_change_contract_from_persisted_bundle(
    bundle_id: str,
    *,
    data_dir: Path | str,
    approval_decision: Literal["approve"],
    confirm_bundle_identity_sha256: str,
    confirm_subject_sha256: str,
    approved_by: str,
    approved_at: datetime,
    reason: str,
) -> ApprovedChangeApprovalWorkflowResult
```

Every argument is explicit and required. The approval decision, actor, timestamp, reason, and both confirmation hashes are never defaulted, inferred, or generated.

The operation accepts no caller-supplied bundle object, subject, attestation, or contract; no arbitrary persisted-bundle path; no `latest`, `current`, or "most recent" reference; no legacy `Proposal`; no supported-capability set; no capability-registry data; no authorization token; no output path; no execution confirmation; no receipt; and no model-generated approval.

## Explicit approval decision

`approval_decision` must be exactly the string `approve`. There is no fuzzy matching, alias, case variant, whitespace variant, truthy value, omitted decision, inferred decision, or default approval: `"approved"`, `"yes"`, `"true"`, `"APPROVE"`, `" approve"`, `True`, and `1` are all rejected.

PR318 adds no rejection, cancellation, revocation, expiration, supersession, or approval-state transition. Those remain deferred.

## Bundle-identity confirmation

`confirm_bundle_identity_sha256` must be exactly 64 lowercase hexadecimal characters and must equal the loaded PR316 bundle identity, so that `bundle_id == "acb_" + bundle_identity_sha256`. The comparison uses `hmac.compare_digest`. The prefixed bundle ID is never accepted as the confirmation value.

This confirmation selects the exact persisted reviewed source bundle. **It does not alter PR309 approval scope.** The resulting attestation remains scoped only to the exact subject SHA-256.

## Subject confirmation

`confirm_subject_sha256` must be exactly 64 lowercase hexadecimal characters and must equal the recomputed PR309 subject SHA-256, which must in turn equal the subject identity recorded throughout the PR316 bundle. The comparison is exact.

The attestation's `subject_sha256` is that exact recomputed and confirmed value — never a caller-supplied hash, a bundle identity, a reviewed-context identity, a construction-evidence identity, or a legacy proposal fingerprint.

## Approval metadata

`approved_by`, `approved_at`, and `reason` are explicit and required.

- `approved_by` and `reason` must satisfy the maintained PR309 `ApprovalAttestation` validation: non-empty after whitespace normalization and never a wildcard.
- `approved_at` must be timezone-aware. A naive datetime, a string, and a numeric timestamp are all rejected.
- No current clock is read. The module imports `datetime` only for type annotations, so it cannot reach a clock at all.
- Identity is never inferred from the OS user, environment, GitHub account, hostname, token, certificate, or credential wrapper.
- The actor is never inferred from PR314 reviewer provenance, and `reviewed_by` is never transformed into `approved_by`.

`approved_by` remains **self-asserted metadata, not authenticated identity**.

## Read-only persisted-bundle loading

The persisted source is reached only through the maintained PR317 exact-ID loader, with the explicit `bundle_id` and the explicit `data_dir`. The loader's own path-safety, size-bound, symlink/reparse, exact-four-file, and PR316 revalidation rules all apply unchanged.

## Exact subject sourcing

The subject is obtained only from the `approved-change-subject.json` logical file, selected through the fixed PR316 filename and role contract. Those stored bytes are parsed into the maintained PR309 `ApprovedChangeSubject` and are never rewritten, repaired, reserialized into acceptance, or republished. Subject identity is recomputed only with PR309 `compute_subject_sha256`.

## Operation sequence

1. Validate the approval decision.
2. Validate the bundle ID as the exact full PR316 bundle ID.
3. Validate both confirmation hashes.
4. Validate `approved_by`, `approved_at`, and `reason` structurally — all before any filesystem access.
5. Call the maintained PR317 exact-ID loader.
6. Require `status=persisted_bundle_loaded`, a non-null bundle, a successful PR316 bundle validation, the exact requested bundle ID, and the exact loaded bundle identity.
7. Compare the explicit bundle-identity confirmation with `hmac.compare_digest`.
8. Obtain the exact `approved-change-subject.json` logical file through the fixed PR316 filename/role contract.
9. Parse it into the maintained PR309 `ApprovedChangeSubject`.
10. Recompute the subject SHA-256 using only PR309 `compute_subject_sha256`.
11. Require agreement among the recomputed subject identity, the subject logical-file SHA-256, the PR316 manifest subject identity, the PR315 construction-evidence subject identity already proven by PR316 validation, and the explicit subject confirmation.
12. Create exactly one `ApprovalAttestation` with the exact explicit actor, timestamp, and reason, the exact recomputed subject SHA-256, and scope `exact_subject_only`.
13. Create exactly one `ApprovedChangeContract`.
14. Call PR309 `verify_approval_binding`.
15. Require exact successful binding.
16. Return one structured success result.

No gate is continued past. `validate_approved_change_contract` is never called: capability-support evaluation remains deferred, and the module never imports it.

## Subject-only attestation scope

The attestation scope is PR309's `exact_subject_only` and nothing else. Two persisted bundles may share one subject identity while carrying different reviewed provenance and different bundle identities; approving through one of them approves the exact subject, not the bundle, not the reviewer, and not the other bundle. The bundle-identity confirmation for one bundle can never authorize loading another, even when the subject SHA-256 is identical.

## Structured result

`ApprovedChangeApprovalWorkflowResult` is frozen and reports:

`status`, `reason`, `approval_succeeded`, `approval_decision`, `requested_bundle_id`, `loaded_bundle_id`, `confirmed_bundle_identity_sha256`, `computed_bundle_identity_sha256`, `confirmed_subject_sha256`, `computed_subject_sha256`, `source_bundle_loaded`, `source_bundle_valid`, `approval_binding_valid`, `approval_scope`, `bundle_confirmation_scope`, `approval_confirmation_scope`, `approval`, `contract`, `binding_validation`, `errors`, and `warnings`, plus the safety ledger.

| Status | Meaning |
| --- | --- |
| `approval_contract_constructed` | One attestation and one contract were created and the exact binding verified. |
| `approval_blocked` | A confirmation did not match the loaded bundle or the recomputed subject. |
| `invalid_approval_input` | The explicit input failed before any filesystem access. |
| `persisted_bundle_not_available` | No persisted bundle could be reached for that exact ID under that data root. |
| `persisted_bundle_invalid` | The persisted bundle or its identity chain failed maintained validation. |
| `approval_binding_failed` | PR309 did not verify the exact approval-to-subject binding. |

On success there is exactly one `ApprovalAttestation`, exactly one `ApprovedChangeContract`, and a present, successful binding validation. On every failure there is no approval, no contract, no partially constructed public object, deterministic sorted and deduplicated errors, and no traceback leakage.

## Accurate safety ledgers

Creating immutable in-memory approval metadata is not a host or filesystem mutation, and the result says so exactly.

### Successful approval binding

```
read_only=true                             approval_input_evaluated=true
mutation_performed=false                   approval_created=true
filesystem_accessed=true                   approval_persisted=false
artifact_write_performed=false             contract_created=true
publication_performed=false                contract_persisted=false
persistence_performed=false                approval_binding_valid=true
authorization_evaluated=false              capability_support_evaluated=false
capability_supported=false                 preflight_evaluated=false
receipt_created=false                      receipt_linked=false
host_configuration_mutation_performed=false
execution_allowed=false                    execution_available=false
execution_status=not_executed
```

### Invalid input before loading

A malformed decision, hash, actor, timestamp, reason, or bundle ID reports `read_only=true`, `mutation_performed=false`, `filesystem_accessed=false`, `approval_created=false`, and `contract_created=false`. The loader is never reached.

### Load or identity failure

When the loader is reached but the bundle is missing, invalid, or mismatched, the result reports `filesystem_accessed=true` (truthfully mirroring the loader's own flag — a structurally rejected data root is refused before any filesystem object is inspected), `approval_created=false`, `contract_created=false`, `persistence_performed=false`, and `execution_allowed=false`.

## Permanent warnings

Every result states that:

- `approved_by` is self-asserted metadata, not authenticated identity;
- reviewer provenance is not approval;
- approval applies only to the exact confirmed PR309 subject SHA-256;
- bundle-identity confirmation selects the source bundle but does not expand attestation scope;
- an in-memory approval is not persisted approval;
- an `ApprovedChangeContract` is not authorization;
- exact approval binding is not capability support;
- no capability registry has been consulted;
- no current-state preflight has run;
- no receipt has been created or linked;
- no execution eligibility is granted;
- reviewed artifacts may contain operational context and must be reviewed before sharing;
- no redaction is performed because redaction would change reviewed identity.

## Semantic separation

A successfully bound contract is not authorization, not capability support, not a preflight result, not a receipt, and not execution eligibility. It is one exact, verifiable statement that a named actor asserted approval of one exact reviewed subject at one exact stated time — held in memory, and nowhere else.

## Explicit non-goals

PR318 adds **no approval persistence**, no approval artifact file, no approval writer or loader, no approval queue state, no rejection/revocation/expiration/cancellation, no CLI command, no interactive route, **no natural-language approval**, no implicit approval, no legacy `Proposal` conversion, no legacy proposal status change, no authenticated identity, no identity-provider integration, no role validation, no authorization infrastructure, no capability registry, **no capability-support evaluation**, no capability binding, no `windows.runtime_reconcile` binding, no PR313 integration, no current-state execution preflight, no subject/live-plan comparison, no receipt creation, no receipt linkage, **no execution eligibility**, no execution, no host configuration change, no service or registry change, no Docker or Compose call, no PowerShell/WinRM/QGA call, no shell or subprocess, no network call, no model or provider call, no current-time lookup, no randomness or UUID, **no new filesystem write**, and no change to the PR317 publisher or its on-disk layout.

The production module imports only `__future__`, `hmac`, `json`, `typing`, `pydantic`, and the maintained PR309/PR316/PR317 modules at runtime; `datetime` and `pathlib` appear only inside a `TYPE_CHECKING` block.

## Future approval-persistence dependency

An in-memory approval disappears with the process. The next focused Stage B dependency is deterministic **approval-artifact persistence** — canonical approval bytes, a governed writer, and an exact-ID loader for them — expected as PR319, **not execution**.

Everything after that remains explicitly deferred: persisted approval loading, approval revocation/cancellation/expiration, authenticated identity, role validation, identity-provider integration, a capability registry, capability-support evaluation, exact capability binding, binding `windows.runtime_reconcile`, current-state execution preflight, subject/live-plan comparison, receipt creation and linkage, execution eligibility, Stage C execution, CLI approval commands, and natural-language approval.
