# Approved Change Subject Construction

PR315 adds exactly one pure, deterministic, fail-closed, in-memory operation to Stage B. It answers exactly one question:

> Given a complete, separately reviewed PR314 supplemental context and its exact expected identity, what is the one PR309 `ApprovedChangeSubject` that the PR311 field-source policy permits — and what proves, field by field, where every value came from?

The module `src/shellforgeai/core/approved_change_subject_construction.py` is that operation plus its construction-evidence contract, and nothing else.

## Why this slice exists

PR309 defined the destination schema and the subject identity. PR310 established that legacy `Proposal` schema v1 is not automatically compatible and that legacy approval is not portable. PR311 established which *source category* is permitted for each destination field. PR314 defined the complete reviewed input package and deliberately exposed no construction operation.

Everything needed to build a subject therefore existed, but nothing was allowed to build one. Any caller wanting a subject would have had to assemble it ad hoc, which is exactly the silent inference PR310 and PR311 prohibit. PR315 closes that gap with a single operation that can only succeed when every reviewed gate passes, and that emits a permanent record of which authority supplied each of the 18 destination fields.

A constructed subject is still not approved, not authorized, not bound to a capability, not persisted, and not executable.

## Relationship to PR309, PR311, and PR314

| Slice | Owns | PR315 relationship |
| --- | --- | --- |
| PR309 | `ApprovedChangeSubject`, its nested target/evidence/procedure/rollback types, canonical subject serialization, the subject SHA-256, and the separate approval attestation | PR309 remains the sole destination schema and subject-identity authority. PR315 instantiates `ApprovedChangeSubject` exactly once on complete success, uses only `compute_subject_sha256` for subject identity, and never weakens PR309 validation. It creates no `ApprovalAttestation` and no `ApprovedChangeContract`. |
| PR311 | The field-source policy: one contract constant, 12 `explicit_context_only` destinations, five reviewed candidate mappings, and the permanent prohibitions on copying, inference, defaulting, approval portability, and fingerprint reuse | PR311 remains the sole field-source-policy authority. PR315 freshly validates the maintained canonical policy at construction time and refuses to accept a caller-supplied policy, override, or field mapping. |
| PR314 | The reviewed input package: 12 typed explicit-context reviews, five typed candidate reviews, final reviewed values, review provenance, candidate identities, the supplemental-context identity, and fail-closed coverage validation | PR314 remains reviewed input only. PR315 freshly revalidates the supplied context through the maintained PR314 validator, and never trusts a previously saved validation result. |

PR313's `windows.runtime_reconcile` capability remains independent. PR315 does not import, reference, bind, or integrate it.

## Construction input contract

```python
construct_approved_change_subject(
    context: ApprovedChangeSupplementalContext | dict[str, Any],
    *,
    expected_supplemental_context_sha256: str,
) -> ApprovedChangeSubjectConstructionResult
```

Those are the only two inputs. The operation accepts no legacy `Proposal`, no field mapping, no policy override, no capability registry, no approval metadata, no execution object, and no arbitrary destination value.

### The explicit expected-identity gate

`expected_supplemental_context_sha256` must be exactly 64 lowercase hexadecimal characters, and it must equal the freshly recomputed PR314 supplemental-context SHA-256 (compared with `hmac.compare_digest`).

Construction is blocked when the expected identity is missing, malformed, uppercase, empty, a candidate SHA-256, a subject SHA-256, a construction-evidence SHA-256, a field-value SHA-256, a legacy proposal fingerprint, taken from a different context, or otherwise mismatched. A structurally valid reviewed context is never sufficient on its own.

A successful result and its evidence both record the expected identity and the recomputed identity; they are always identical on success.

## Required construction sequence

1. Validate the expected supplemental-context SHA-256 format.
2. Freshly validate the canonical PR311 construction policy (`status == policy_valid`, `policy_valid`, `coverage_complete`) and reconfirm that it still defines one contract constant, exactly the 12 explicit-context destinations, exactly the five candidate mappings, and no extra, duplicate, wildcard, fallback, inferred, or default authority.
3. Freshly validate the supplied PR314 context (`status == supplemental_context_valid`, `context_valid`, `coverage_complete`).
4. Recompute the PR314 supplemental-context SHA-256.
5. Compare the recomputed and expected identities exactly, in constant time.
6. Reconfirm exact destination coverage, exact candidate source mappings, and the authority class of every destination.
7. Build one explicit, exhaustive PR309 subject payload.
8. Instantiate exactly one `ApprovedChangeSubject`.
9. Compute the canonical PR309 subject SHA-256.
10. Build complete field-by-field construction evidence.
11. Verify that every evidence record matches the constructed subject.
12. Compute the construction-evidence SHA-256.
13. Return the successful immutable result.

Any failure before step 13 returns a structured blocked or invalid result carrying no subject, no construction evidence, no partial subject, no partial authority map, no subject-created claim, and no persistence or execution claim. Invalid inputs are never caught and silently repaired.

## Exact field-authority map: 1 + 12 + 5

The mapping is explicit, exhaustive, and fail closed. There is no generic fallback, wildcard lookup, dynamic passthrough, default value, or inferred field authority. Adding, removing, or renaming a PR309 subject field, or drifting the PR311 classification of any destination, makes construction fail closed until PR315 is explicitly updated.

### The one contract constant

| Destination | Authority kind | Source |
| --- | --- | --- |
| `schema_version` | `contract_constant` | the PR309 `SCHEMA_VERSION` schema constant |

It never comes from PR314 input, legacy data, caller data, or a default dictionary lookup, and it carries no reviewer provenance.

### The 12 explicit-context destinations

Each takes its value only from the matching PR314 explicit-context review's `reviewed_value`:

`audit_requirements`, `blast_radius`, `capability_id`, `change_summary`, `desired_outcome`, `diagnosis_summary`, `evidence_references`, `procedure`, `revalidation_requirements`, `rollback_posture`, `target`, `unsupported_or_irreversible_aspects`.

No alternate review record and no legacy source may populate them.

### The five candidate-backed destinations

Each takes its value only from the matching PR314 candidate review's `final_reviewed_value`:

| Legacy source | Destination | Value used |
| --- | --- | --- |
| `proposal_id` | `source_proposal_reference` | `final_reviewed_value` |
| `risk` | `risk` | `final_reviewed_value` |
| `impact` | `impact` | `final_reviewed_value` |
| `preconditions` | `preconditions` | `final_reviewed_value` |
| `verification` | `verification_criteria` | `final_reviewed_value` |

A subject field is **never** constructed from `candidate_value`. For an accepted candidate PR314 already requires the final value to equal the candidate value exactly; for a rejected candidate the final value must differ, and the rejected raw candidate never reaches the subject. It survives only as a candidate SHA-256 and an `accepted`/`rejected` decision inside the construction evidence.

## Subject-only output

On complete success PR315 produces exactly one `ApprovedChangeSubject`, one `ApprovedChangeSubjectConstructionEvidence`, and one `ApprovedChangeSubjectConstructionResult`. It never creates a draft subject first, a second validation copy, multiple candidate subjects, an `ApprovalAttestation`, or an `ApprovedChangeContract`. On any blocked or invalid path it constructs zero subjects.

## Construction-evidence contract

```
ApprovedChangeSubjectConstructionEvidence
  schema_version                          evidence schema version
  approved_change_schema_version           PR309 schema version
  construction_policy_schema_version       PR311 policy schema version
  supplemental_context_schema_version      PR314 context schema version
  supplemental_context_sha256              the exact reviewed input identity
  subject_sha256                           the exact constructed subject identity
  field_authorities                        exactly 18 frozen authority records
  warnings                                 permanent safety warnings
```

There is no implicit timestamp. Determinism relies only on the reviewed input and the maintained schema/policy state.

### Field-authority records

There is exactly one authority record for every PR309 destination field — 18 records total — sorted deterministically by destination field, expressed as a frozen discriminated union on `authority_kind`.

| Authority kind | Record | Fields |
| --- | --- | --- |
| `contract_constant` | `ContractConstantFieldAuthority` | destination field, source authority (`approved_change_contract.SCHEMA_VERSION`), final value SHA-256, subject-field match. No reviewer provenance. |
| `explicit_context_reviewed_value` | `ExplicitContextFieldAuthority` | destination field, source section `explicit_context_reviews`, the matching PR314 destination field, review provenance, final value SHA-256, subject-field match. |
| `legacy_candidate_final_reviewed_value` | `LegacyCandidateFieldAuthority` | destination field, source section `legacy_candidate_reviews`, exact legacy source field, candidate decision, candidate SHA-256, review provenance, final value SHA-256, subject-field match. |

The candidate record binds the *final reviewed value* actually used by the subject, not just the original candidate.

Raw destination values are not duplicated into the evidence. Auditors combine the canonical value identities with the returned subject and the original validated context.

### Field-value identity

```python
compute_constructed_field_value_sha256(destination_field: str, value: Any) -> str
```

binds a field-value identity schema version, the exact destination field, and the canonical typed value. It applies the same PR309 canonical ordering as the destination schema: target identity claims and evidence references are sorted; procedure, rollback procedure, precondition, and verification ordering is preserved. It is field audit metadata only — never approval, authorization, or execution eligibility.

### Evidence verification

Before any success is returned, PR315 proves that all 18 subject fields have exactly one authority record; that no authority destination is missing, duplicated, or unknown; that the records are deterministically sorted; that every authority classification matches the live PR311 policy; that every source record matches the supplied PR314 context; that every candidate source mapping is exact; that every authority final-value identity matches the constructed subject field; that candidate-backed subject fields equal `final_reviewed_value`; that explicit-context subject fields equal `reviewed_value`; and that `schema_version` equals the PR309 constant. If verification fails, the result carries no subject and no evidence.

## Three distinct identities

| Identity | Binds | Never is |
| --- | --- | --- |
| Supplemental-context SHA-256 (PR314) | reviewed values, candidate values, final reviewed values, candidate decisions, review provenance, PR314 versions | a subject hash, an evidence hash, an approval hash, or a legacy fingerprint |
| Subject SHA-256 (PR309) | only the final PR309 subject semantics, via `compute_subject_sha256` | a reviewed-input hash or an evidence hash |
| Construction-evidence SHA-256 (PR315) | the evidence schema version, all three upstream schema versions, the exact input context identity, the exact output subject identity, all 18 authority records, candidate decisions and hashes, review provenance, field-value identities, and the permanent safety warnings | a subject hash, an approval hash, or execution confirmation |

The evidence SHA-256 is never included in its own canonical payload.

### Required identity behavior

- Changing review provenance while preserving every final subject value changes the context and evidence identities and leaves the subject identity unchanged.
- Changing a rejected candidate while preserving its explicit final reviewed value changes the context and evidence identities and leaves the subject identity unchanged.
- Changing a final reviewed value changes the context, subject, and evidence identities.
- Changing procedure, rollback-procedure, precondition, or verification order changes all three identities, because that ordering is semantic.
- Reordering set-like target identity claims or evidence references changes none of the three identities, because PR309 canonical ordering governs them.

Canonicalization is UTF-8 JSON with sorted mapping keys, compact separators, `ensure_ascii=False`, timestamps normalized to UTC through the maintained PR309 canonicalization, and deterministic authority-record ordering.

## Construction result

`ApprovedChangeSubjectConstructionResult` is frozen and structured. Its status is one of `subject_constructed`, `construction_blocked`, or `invalid_construction_input`.

| Field | Complete success | Blocked or invalid input |
| --- | --- | --- |
| `construction_succeeded` | `true` | `false` |
| `subject` | one `ApprovedChangeSubject` | `null` |
| `construction_evidence` | one evidence object | `null` |
| `construction_performed` | `true` | `false` |
| `subject_created` | `true` | `false` |
| `computed_subject_sha256` / `computed_construction_evidence_sha256` | computed | `""` |
| `read_only` | `true` | `true` |
| `mutation_performed` | `false` | `false` |
| `approval_created` / `contract_created` | `false` | `false` |
| `persistence_performed` / `receipt_created` | `false` | `false` |
| `capability_support_evaluated` / `capability_supported` | `false` | `false` |
| `approval_evaluated` / `authorization_evaluated` | `false` | `false` |
| `execution_allowed` / `execution_available` | `false` | `false` |
| `execution_status` | `not_executed` | `not_executed` |

Errors are deterministic, sorted, and deduplicated. Untrusted dictionaries return structured results rather than raising, and implementation tracebacks are never the public result. Nothing is silently reordered into validity and no invalid mapping is repaired.

## Reviewer-provenance boundary

Review provenance is bookkeeping only. It is **not** authenticated identity, proof that the stated person controls the identity, approval, authorization, approval portability, an `ApprovalAttestation`, execution confirmation, capability support, or execution eligibility.

PR315 never maps `reviewed_by` to `approved_by` and never creates an approval object. Provenance appears in the construction evidence and in the supplemental-context identity; it never enters the constructed subject or the subject identity.

## Capability-support boundary

A constructed subject carries a syntactically valid `capability_id` because PR314 required a bounded exact identifier for that reviewed destination. That is a naming constraint, not support. PR315 evaluates no capability support, consults no capability registry, and binds no capability. Every result reports `capability_support_evaluated=false` and `capability_supported=false`.

## Fail-closed and permanently inert posture

The production module performs no I/O of any kind. It does not import `Proposal`, accept `Proposal` in a signature, instantiate `ApprovalAttestation` or `ApprovedChangeContract`, import PR313 execution modules or recipe registries, use `Path`, open/read/write files, use implicit timestamps, inspect or mutate environment variables, use subprocess, `os.system`, or sockets, call Docker or Compose, call PowerShell or WinRM, call a model or provider, create artifacts, or persist state. The only PR309 top-level object it may instantiate is `ApprovedChangeSubject`, exactly once, on complete success.

## Non-executable, unapproved JSON-shaped example

The shape below is illustrative only. It is **not** approved, **not** authorized, **not** persisted, **not** bound to any capability, and **not** executable. Hash values are elided.

```json
{
  "status": "subject_constructed",
  "construction_succeeded": true,
  "expected_supplemental_context_sha256": "<64 lowercase hex>",
  "computed_supplemental_context_sha256": "<same 64 lowercase hex>",
  "computed_subject_sha256": "<different 64 lowercase hex>",
  "computed_construction_evidence_sha256": "<third distinct 64 lowercase hex>",
  "subject": {"schema_version": "1", "capability_id": "example.synthetic_bounded_change", "...": "17 further PR309 destination fields"},
  "construction_evidence": {
    "schema_version": "1",
    "approved_change_schema_version": "1",
    "construction_policy_schema_version": "1",
    "supplemental_context_schema_version": "1",
    "supplemental_context_sha256": "<64 lowercase hex>",
    "subject_sha256": "<64 lowercase hex>",
    "field_authorities": [
      {"destination_field": "audit_requirements", "authority_kind": "explicit_context_reviewed_value", "source_section": "explicit_context_reviews", "source_destination_field": "audit_requirements", "provenance": {"reviewed_by": "operator-a", "reviewed_at": "2026-07-24T12:00:00Z", "review_reason": "explicit field review"}, "final_value_sha256": "<64 lowercase hex>", "subject_field_matches": true},
      {"destination_field": "impact", "authority_kind": "legacy_candidate_final_reviewed_value", "source_section": "legacy_candidate_reviews", "legacy_source_field": "impact", "candidate_decision": "rejected", "candidate_sha256": "<64 lowercase hex>", "provenance": {"reviewed_by": "operator-a", "reviewed_at": "2026-07-24T12:00:00Z", "review_reason": "legacy candidate rejected after explicit review"}, "final_value_sha256": "<64 lowercase hex>", "subject_field_matches": true},
      {"destination_field": "schema_version", "authority_kind": "contract_constant", "source_authority": "approved_change_contract.SCHEMA_VERSION", "final_value_sha256": "<64 lowercase hex>", "subject_field_matches": true},
      {"...": "15 further authority records, 18 in total"}
    ],
    "warnings": ["a constructed subject is not approved, authorized, bound, persisted, or executable", "..."]
  },
  "read_only": true,
  "mutation_performed": false,
  "approval_created": false,
  "contract_created": false,
  "persistence_performed": false,
  "receipt_created": false,
  "capability_support_evaluated": false,
  "capability_supported": false,
  "approval_evaluated": false,
  "authorization_evaluated": false,
  "execution_allowed": false,
  "execution_available": false,
  "execution_status": "not_executed"
}
```

## Explicit non-goals

PR315 adds no legacy `Proposal` loading or file reads, candidate extraction, review-context extraction or display, text parsing, field inference, value transformation, defaults, migration, `ApprovalAttestation` construction, `ApprovedChangeContract` construction, authenticated identity, authorization, approval workflow, approval persistence, supplemental-context persistence, subject persistence, construction-evidence persistence, JSON or Markdown artifact writes, filesystem output, CLI commands, interactive routes, capability registry, capability support decisions, capability binding, `windows.runtime_reconcile` binding, PR313 imports or integration, current-state execution preflight, approved-subject/live-plan comparison, receipt linkage, executor changes, mutation, model/provider calls, network calls, shell commands, subprocesses, PowerShell, WinRM, QGA, Docker or Compose operations, service/process/registry/environment changes, or natural-language execution.

Current product behavior, the command surface, and mutation refusal are unchanged.

## Consumer: PR316 reviewed-change artifact bundle

PR316 defines the persistence payload for a constructed change in [Approved Change Artifact Bundle](APPROVED_CHANGE_ARTIFACT_BUNDLE.md). PR315 remains the sole sanctioned construction path and the sole construction-evidence authority: PR316 accepts no caller-supplied subject or evidence, reruns `construct_approved_change_subject` from the reviewed context, and serializes the results only through the maintained `canonical_subject_json` and `canonical_construction_evidence_json`.

PR316 does not replace these identities. The canonical subject bytes hash to exactly the PR309 subject SHA-256 and the canonical evidence bytes hash to exactly the PR315 construction-evidence SHA-256; the bundle manifest records both, and the separate bundle identity binds them without ever becoming either. During validation PR316 reconstructs the subject and evidence from the stored context and requires the reconstructed canonical bytes to equal the stored bytes exactly, so evidence from one construction can never be paired with a subject from another.

A bundled subject is still unapproved, unbound, unpersisted, and non-executable, and PR316 adds no writer: it creates no file or directory.

## Future PR317+ dependencies

The recommended immediate next dependency after PR316 is **PR317: publish reviewed-change artifact bundles atomically** — the narrowly governed non-overwriting writer and read-only loader for the PR316 bundle. PR315 deliberately pre-implements none of it.

Later Stage B and Stage C work remains explicit and separate: approval-attestation creation, an approval review workflow, authenticated identity, approved-contract construction, approval persistence, a capability registry, exact capability binding, binding `windows.runtime_reconcile`, current-state execution preflight, approved-subject versus live-plan comparison, approved-subject-to-receipt linkage, execution eligibility, an end-to-end lifecycle proof, and any additional mutation capability.
