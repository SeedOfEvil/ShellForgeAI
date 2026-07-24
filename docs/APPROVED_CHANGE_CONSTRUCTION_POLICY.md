# Approved Change Construction Policy

PR311 defines an isolated, immutable field-source policy for any future construction of a PR309 `ApprovedChangeSubject`. It exists before a supplemental-context schema so the repository has a machine-validated answer to a narrower question first: which source category is even permitted for each destination field?

The policy is metadata and validation only. It does not accept a `Proposal`, extract values, define supplemental context, build a draft subject, create an `ApprovedChangeSubject`, create an `ApprovalAttestation`, create an `ApprovedChangeContract`, persist data, wire CLI or approval flows, run preflight, create receipts, or enable execution. Stage B remains incomplete.

## Permanent source classifications

Exactly three source classifications exist:

| Classification | Meaning |
| --- | --- |
| `contract_constant` | The value authority is the PR309 contract schema itself. |
| `legacy_candidate_requires_explicit_review` | A narrowly allowlisted legacy field may be displayed as candidate input, but only after explicit field-specific review. |
| `explicit_context_only` | The destination must be supplied through explicit reviewed context; no direct legacy source is allowed. |

The policy intentionally has no automatic, inferred, default, derived, migrated, passthrough, wildcard, fallback, or compatible classification.

## Policy matrix

| Destination field | Classification | Direct legacy candidate | Review-context-only legacy fields |
| --- | --- | --- | --- |
| `schema_version` | `contract_constant` | None | None |
| `source_proposal_reference` | `legacy_candidate_requires_explicit_review` | `proposal_id` | None |
| `capability_id` | `explicit_context_only` | None | None |
| `target` | `explicit_context_only` | None | None |
| `desired_outcome` | `explicit_context_only` | None | `title`, `notes` |
| `diagnosis_summary` | `explicit_context_only` | None | `title`, `notes`, `source.summary`, `source.evidence` |
| `risk` | `legacy_candidate_requires_explicit_review` | `risk` | None |
| `evidence_references` | `explicit_context_only` | None | `source.evidence`, `source.runbook`, `source.summary`, `source_hashes` |
| `change_summary` | `explicit_context_only` | None | `title`, `notes` |
| `impact` | `legacy_candidate_requires_explicit_review` | `impact` | None |
| `blast_radius` | `explicit_context_only` | None | None |
| `procedure` | `explicit_context_only` | None | None |
| `preconditions` | `legacy_candidate_requires_explicit_review` | `preconditions` | None |
| `revalidation_requirements` | `explicit_context_only` | None | None |
| `verification_criteria` | `legacy_candidate_requires_explicit_review` | `verification` | None |
| `rollback_posture` | `explicit_context_only` | None | `rollback` |
| `audit_requirements` | `explicit_context_only` | None | None |
| `unsupported_or_irreversible_aspects` | `explicit_context_only` | None | None |

The only direct candidate mappings are:

- `source_proposal_reference` <- `proposal_id`
- `risk` <- `risk`
- `impact` <- `impact`
- `preconditions` <- `preconditions`
- `verification_criteria` <- `verification`

Every candidate requires explicit field-specific review. Legacy approval does not approve the candidate, legacy fingerprint does not bind the candidate, absence of a legacy value creates no default, and the policy does not validate eventual semantic correctness.

## Review-context-only allowlist

Only these legacy fields may be displayed as review context without becoming direct sources: `title`, `notes`, `rollback`, `source.evidence`, `source.runbook`, `source.summary`, and `source_hashes`.

Destination-specific review-context mappings are narrow:

- `desired_outcome`: `title`, `notes`
- `diagnosis_summary`: `title`, `notes`, `source.summary`, `source.evidence`
- `evidence_references`: `source.evidence`, `source.runbook`, `source.summary`, `source_hashes`
- `change_summary`: `title`, `notes`
- `rollback_posture`: `rollback`

Review context may be displayed to an operator in future work, but it may not directly populate a destination field, suppress explicit reviewed context, be transformed into a destination value, or be treated as approved.

## Prohibited mappings and inference

The validator rejects attempts to directly source:

- `capability_id` from `kind`
- `target` from `target` or `component`
- `procedure` from `proposed_steps`
- `rollback_posture` from `rollback`
- `evidence_references` from `evidence` or `source_hashes`
- any destination from legacy `approval` or `fingerprint`

It also rejects wildcard, fallback, unknown legacy fields, multiple direct candidates for one destination, automatic copying, inference, defaulting, approval portability, and fingerprint reuse.

## Fail-closed schema coverage

Validation compares policy destinations directly with `ApprovedChangeSubject.model_fields`. The policy must have exactly one rule for every current destination field, no duplicate, and no unknown destination. Adding, removing, or renaming a PR309 subject field makes validation fail closed until the policy is explicitly updated.

## Metadata-only validation result

A `policy_valid` result only means the policy metadata is internally valid. It does not mean supplemental context exists, construction is ready, approval is ready, a contract is ready, authorization exists, or execution is eligible. Validation results permanently report `read_only=true`, `mutation_performed=false`, `subject_created=false`, `contract_created=false`, `approval_created=false`, `execution_allowed=false`, `execution_available=false`, and `execution_status=not_executed`.
