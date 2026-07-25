# Approved Change Supplemental Context

PR314 defines the immutable, typed, deterministic, field-reviewed supplemental-context contract for Stage B. It answers exactly one question:

> What complete and separately reviewed input package must exist before a future operation could construct a PR309 `ApprovedChangeSubject` under the PR311 field-source policy?

PR314 does not construct that subject. The module `src/shellforgeai/core/approved_change_supplemental_context.py` is a contract plus a structured, non-throwing validator, and nothing else.

## Why this contract exists

PR310 established that legacy `Proposal` schema v1 is not automatically compatible, that legacy approval is not portable, and that a legacy fingerprint is not a PR309 subject hash. PR311 then established *which source category* is permitted per destination field, but deliberately stopped short of defining the reviewed input itself.

Without PR314 there is no machine-checkable definition of "complete reviewed input". Any future construction operation would have to invent one implicitly, which is exactly the kind of silent inference PR310 and PR311 prohibit.

## Relationship to PR309, PR310, and PR311

| Slice | Owns | PR314 relationship |
| --- | --- | --- |
| PR309 | The `ApprovedChangeSubject` / `ApprovalAttestation` / `ApprovedChangeContract` schema and subject SHA-256 | PR309 remains the sole destination schema authority. PR314 reuses `ApprovedChangeTarget`, `EvidenceReference`, `ProcedureStep`, and `RollbackPosture` directly rather than defining weaker duplicates, and applies the same text, uniqueness, capability, and timestamp constraints. |
| PR310 | The legacy compatibility decision | PR314 supplies the "separately supplied reviewed context" PR310 requires. It still loads no proposal and carries no legacy approval or fingerprint forward. |
| PR311 | The fail-closed field-source policy | PR311 remains the sole field-source policy. PR314 derives its destination sets directly from `CONTRACT_CONSTANT_FIELDS`, `EXPLICIT_CONTEXT_ONLY_FIELDS`, and `DIRECT_CANDIDATE_ALLOWLIST` so the two cannot drift. |

PR313's `windows.runtime_reconcile` capability is independent. PR314 does not bind, reference, or integrate it.

## Complete destination coverage

```
1 contract constant  (schema_version)
+ 12 explicit-context reviews
+  5 reviewed candidate reviews
= 18 ApprovedChangeSubject fields
```

Coverage is validated against `ApprovedChangeSubject.model_fields` at validation time. Adding, removing, or renaming a PR309 subject field makes validation fail closed until PR314 is explicitly updated.

### The 12 explicit-context destinations

Each has exactly one typed, frozen, field-specific review record carrying a typed `reviewed_value` and a `ReviewProvenance`:

| Destination | Review record | Reviewed value type |
| --- | --- | --- |
| `audit_requirements` | `AuditRequirementsContextReview` | non-empty `tuple[str, ...]` |
| `blast_radius` | `BlastRadiusContextReview` | non-empty text |
| `capability_id` | `CapabilityIdContextReview` | bounded exact capability identifier |
| `change_summary` | `ChangeSummaryContextReview` | non-empty text |
| `desired_outcome` | `DesiredOutcomeContextReview` | non-empty text |
| `diagnosis_summary` | `DiagnosisSummaryContextReview` | non-empty text |
| `evidence_references` | `EvidenceReferencesContextReview` | non-empty `tuple[EvidenceReference, ...]`, unique reference IDs |
| `procedure` | `ProcedureContextReview` | non-empty ordered `tuple[ProcedureStep, ...]`, unique step IDs |
| `revalidation_requirements` | `RevalidationRequirementsContextReview` | non-empty `tuple[str, ...]` |
| `rollback_posture` | `RollbackPostureContextReview` | `RollbackPosture` |
| `target` | `TargetContextReview` | `ApprovedChangeTarget` with unique identity-claim keys |
| `unsupported_or_irreversible_aspects` | `UnsupportedOrIrreversibleAspectsContextReview` | non-empty `tuple[str, ...]` |

The records are combined through a `destination_field`-discriminated union and held in a deterministically sorted tuple. There is no wildcard, catch-all, fallback, generic dictionary, or arbitrary reviewed field. There is no `dict[str, Any]` context bag. Explicit-context values are never populated from legacy review-context fields.

### The five reviewed candidate mappings

| Legacy source | Destination | Review record | Candidate/final value type |
| --- | --- | --- | --- |
| `proposal_id` | `source_proposal_reference` | `SourceProposalReferenceCandidateReview` | text |
| `risk` | `risk` | `RiskCandidateReview` | `low` \| `medium` \| `high` |
| `impact` | `impact` | `ImpactCandidateReview` | text |
| `preconditions` | `preconditions` | `PreconditionsCandidateReview` | ordered non-empty `tuple[str, ...]` |
| `verification` | `verification_criteria` | `VerificationCriteriaCandidateReview` | ordered non-empty `tuple[str, ...]` |

Each record pins its `destination_field` and `legacy_source_field` as exact literals, so an altered, prohibited, unknown, wildcard, or multiplied source is structurally impossible and is additionally rejected by the validator.

## Accepted and rejected candidate semantics

Every candidate review carries a `decision` of exactly `accepted` or `rejected`.

**Accepted** requires the `final_reviewed_value` to equal the typed `candidate_value` exactly, and the supplied `candidate_sha256` to match the canonical candidate payload. The candidate is still only explicitly reviewed input; no legacy approval or fingerprint is carried forward.

**Rejected** requires an explicit typed `final_reviewed_value` that differs from the rejected candidate, plus a non-empty review reason. No alternate legacy field is consulted, and no inference, fallback, mapping, parsing, defaulting, or transformation occurs.

Use `accepted` when the candidate and final value are intentionally identical. A nominal rejection with an unchanged final value is rejected.

## Review provenance semantics

`ReviewProvenance` records `reviewed_by`, a timezone-aware `reviewed_at`, and a `review_reason`. Actor and reason are non-empty, bounded, and may not be wildcards. Timestamps canonicalize to UTC. Extra fields are rejected and the model is frozen.

Review provenance is **not** authenticated identity, an `ApprovalAttestation`, authorization, approval portability, execution confirmation, or proof that the stated actor controls the named identity.

All review timestamps are explicit caller-supplied values. The module never creates a timestamp implicitly.

## Candidate identity

`canonical_candidate_payload`, `canonical_candidate_json`, and `compute_candidate_sha256` bind:

- the candidate-review schema version;
- the exact destination field;
- the exact legacy source field;
- the typed candidate value.

Canonical candidate JSON is UTF-8, sorted-key, compact-separator, `ensure_ascii=False`, and deterministic across Linux and Windows. Ordered semantic tuples such as preconditions and verification criteria preserve reviewed order. A mismatch between the supplied `candidate_sha256` and the computed value invalidates the record and the context.

Candidate identity is not a legacy proposal fingerprint, a PR309 subject hash, approval binding, or authorization.

## Supplemental-context identity

`canonical_supplemental_context_payload`, `canonical_supplemental_context_json`, and `compute_supplemental_context_sha256` produce the **reviewed-input identity** of the whole package. Canonical JSON is UTF-8, sorted-key, compact, `ensure_ascii=False`, with timezone-aware timestamps normalized to UTC.

Ordering rules match PR309 exactly:

- field reviews and candidate reviews are ordered deterministically by destination;
- target identity claims are sorted as PR309 sorts them;
- evidence references are sorted by reference ID as PR309 sorts them;
- reviewed procedure order, rollback procedure order, precondition order, and verification order are preserved.

The context hash binds every reviewed value, every candidate value, every final reviewed value, every decision, every candidate hash, every exact destination/source mapping, every review actor, timestamp, and reason, and all schema and policy versions. Changing any bound field changes the SHA-256.

## Hash separation

The supplemental-context SHA-256 is a reviewed-input identity. It is never:

- a PR309 subject SHA-256;
- a legacy proposal fingerprint;
- an approval SHA-256;
- execution confirmation.

The same is true of a candidate SHA-256. Neither identity validates as an approval subject hash: substituting either into an `ApprovalAttestation.subject_sha256` fails PR309 binding verification. The result field is named `computed_supplemental_context_sha256` precisely so it cannot be confused with `computed_subject_sha256`.

## Schema and policy version binding

The context binds its own `schema_version`, the PR311 `construction_policy_schema_version`, and the PR309 `approved_change_schema_version`. Any mismatch fails closed.

## Fail-closed validation

`validate_approved_change_supplemental_context` accepts an `ApprovedChangeSupplementalContext` or an untrusted dictionary and always returns a frozen `SupplementalContextValidationResult`. A malformed dictionary returns a structured invalid result rather than raising, leaking an implementation traceback, or producing a partial object. Statuses are `supplemental_context_valid`, `supplemental_context_invalid`, and `invalid_validation_input`.

Validation rejects:

1. missing explicit-context reviews;
2. missing candidate reviews;
3. duplicate destination reviews;
4. unknown destination reviews;
5. unsorted review records;
6. wildcard or fallback destinations;
7. incorrect destination/source mappings;
8. multiple candidate sources for one destination;
9. any direct candidate outside the canonical five;
10. direct sourcing of `capability_id` from legacy `kind`;
11. direct sourcing of `target` from `target` or `component`;
12. direct sourcing of `procedure` from `proposed_steps`;
13. direct sourcing of `rollback_posture` from legacy `rollback`;
14. direct sourcing of evidence references from `evidence` or `source_hashes`;
15. use of legacy `approval`;
16. use of legacy `fingerprint`;
17. missing review provenance;
18. naive timestamps;
19. empty review reasons;
20. an invalid or mismatched candidate SHA-256;
21. an accepted candidate with a changed final value;
22. a rejected candidate with an unchanged final value;
23. policy/schema version mismatch;
24. extra model fields;
25. mutable nested collections;
26. partial context objects;
27. defaulted final values;
28. inferred values;
29. automatic repair or reordering;
30. hash confusion with subject or approval identity.

The validator never silently normalizes an invalid mapping into a valid one. Unsorted or duplicated records are reported, not repaired.

## Inert safety posture

Every result, valid or invalid, permanently reports:

```
read_only=true
mutation_performed=false
subject_created=false
contract_created=false
approval_created=false
persistence_performed=false
receipt_created=false
execution_allowed=false
execution_available=false
execution_status=not_executed
```

A `supplemental_context_valid` result means only that reviewed input coverage is complete and internally consistent. It does not mean a subject exists, an approval exists, a contract exists, authorization exists, or execution is eligible.

The production module has no construction function, imports no `Proposal`, accepts no `Proposal` in any signature, returns no PR309 top-level model, instantiates none of them, uses no `Path`, opens no files, reads or writes no files, reads or mutates no environment variables, uses no subprocess/`os.system`/sockets, calls no Docker, Compose, model, or provider, persists nothing, and creates no implicit "now" timestamp.

## Explicit non-goals

PR314 implements and exposes none of: a `Proposal` adapter, proposal-file loading, candidate extraction from `Proposal`, review-context extraction, draft or final subject construction, `ApprovalAttestation` or `ApprovedChangeContract` construction, persistence, JSON artifact writes, file formats, CLI commands, approval transitions, approval workflow integration, a capability registry, capability binding, `windows.runtime_reconcile` integration, current-state execution preflight, receipt linkage, executor changes, mutation, model/provider calls, network calls, shell or subprocess calls, Docker or Compose calls, PowerShell or WinRM, registry/service/process changes, or natural-language execution.

PR313 behavior is unchanged.

## Non-executable example

The following is an illustrative, abbreviated shape only. It is not a runnable command, not an artifact format, not persisted anywhere, and not approved or executable. Only two of the twelve explicit-context reviews and one of the five candidate reviews are shown.

```json
{
  "schema_version": "1",
  "construction_policy_schema_version": "1",
  "approved_change_schema_version": "1",
  "explicit_context_reviews": [
    {
      "destination_field": "blast_radius",
      "reviewed_value": "one reviewed target only",
      "provenance": {
        "reviewed_by": "operator-a",
        "reviewed_at": "2026-07-24T12:00:00Z",
        "review_reason": "explicit field review"
      }
    },
    {
      "destination_field": "capability_id",
      "reviewed_value": "example.synthetic_bounded_change",
      "provenance": {
        "reviewed_by": "operator-a",
        "reviewed_at": "2026-07-24T12:00:00Z",
        "review_reason": "explicit field review"
      }
    }
  ],
  "legacy_candidate_reviews": [
    {
      "destination_field": "impact",
      "legacy_source_field": "impact",
      "candidate_value": "one reviewed container only",
      "candidate_sha256": "397903a71ab66c1dc7cd300b20a98c0fefb1ba9eda144e71c20b4899a45b5f66",
      "decision": "accepted",
      "final_reviewed_value": "one reviewed container only",
      "provenance": {
        "reviewed_by": "operator-a",
        "reviewed_at": "2026-07-24T12:00:00Z",
        "review_reason": "explicit field review"
      }
    }
  ]
}
```

## Future dependency

The next Stage B dependency is an explicit reviewed construction operation (PR315). It would consume a validated PR314 context together with the PR311 policy and produce an `ApprovedChangeSubject` only. PR314 deliberately does not pre-implement any part of it, and persistence, approval workflow, capability binding, preflight, receipt linkage, and Stage C end-to-end execution all remain deferred.
