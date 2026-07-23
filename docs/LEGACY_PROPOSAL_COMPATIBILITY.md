# Legacy Proposal Compatibility Assessment

PR310 adds a strict, findings-only compatibility assessment for legacy `Proposal` schema v1 values against the PR309 `ApprovedChangeSubject` / `ApprovedChangeContract` schema v1 boundary.

## Permanent decision

No legacy `Proposal` is automatically compatible with, or approval-portable to, a PR309 approved-change contract as-is. A legacy proposal may contain explicitly identified candidate source values, but creating an approved-change subject requires separately supplied and reviewed information that the legacy schema does not contain.

The assessment does not create an `ApprovedChangeSubject`, `ApprovalAttestation`, or `ApprovedChangeContract`. It does not adapt, convert, migrate, persist, preflight, execute, register a CLI command, or grant execution eligibility.

## Compatibility matrix

| Legacy Proposal schema v1 item | PR309 contract role | PR310 result |
| --- | --- | --- |
| `proposal_id` | Source proposal reference | Candidate source value only. |
| `risk` | Risk | Candidate source value only. |
| `impact` | Impact text | Candidate source value only. |
| `preconditions` | Preconditions | Candidate source text only. |
| `verification` | Verification criteria | Candidate source text only. |
| `rollback` | Rollback posture | Candidate source text only; not structured posture. |
| `title` / `notes` | Reviewed context | Possible reviewed context only. |
| `source.*` / `source_hashes` | Source-location context | Candidate source-location context only. |
| `kind` | Capability identifier | Ambiguous; never mapped or normalized automatically. |
| `target` / `component` | Exact target identity | Ambiguous; no identity claims are inferred. |
| `proposed_steps` | Typed ordered procedure | Ambiguous; free-form text is not parsed into steps. |
| `status=approved` and `approval` | Approval attestation | Non-portable historical metadata only. |
| `fingerprint` | PR309 subject SHA-256 | Non-equivalent; it binds different semantics and fields. |

## Missing PR309 context

Legacy `Proposal` schema v1 does not explicitly and safely provide all required PR309 information. The report identifies missing or insufficient context for: exact supported capability ID, exact structured target kind/name/identity claims, desired outcome, diagnosis summary, evidence reference IDs, PR309 evidence source identity, PR309 evidence SHA-256 references, evidence observation timestamps, change summary, explicit blast radius, typed ordered descriptive procedure steps, current-state revalidation requirements, structured rollback posture, audit requirements, unsupported or irreversible aspects, exact PR309 subject SHA-256, and `exact_subject_only` attestation scope.

Related free-form legacy text does not suppress these findings.

## Semantic ambiguity

PR310 reports ambiguity rather than interpreting legacy fields:

- `kind` is not a PR309 capability ID; no namespace, normalization, known-kind mapping, or capability lookup is performed.
- `target` and `component` are not exact target identity; no hostnames, services, container IDs, wildcards, or environment facts are inferred.
- `proposed_steps` are not PR309 `ProcedureStep` values; commands are not parsed, shells are not classified, step IDs are not created, and expected effects are not derived.
- `rollback` text is not structured `RollbackPosture`; reversibility, limitations, and rollback procedure semantics are not inferred.
- `evidence` and `source_hashes` are not PR309 `EvidenceReference` values; reference IDs, observed timestamps, source identity, and reviewed evidence identity are not synthesized.
- Legacy approval metadata is not a PR309 approval attestation.
- The legacy fingerprint is not a PR309 subject hash.

## Approval and fingerprint boundaries

Legacy `status=approved` and `ProposalApproval` actor/time/reason fields are historical source metadata only. They are not authenticated identity, do not carry `exact_subject_only` scope, and are not bound to a PR309 subject hash. Approval portability is always false.

A legacy proposal fingerprint is not equivalent to a PR309 subject SHA-256. It binds a different field set with different normalization and cannot be reused, copied, renamed, or treated as approval binding. PR310 constructs no PR309 subject and computes no hypothetical replacement hash.

## Prohibited inference

The analyzer explicitly prohibits inference of capability ID, target identity, evidence timestamps, evidence reference identity, desired outcome, diagnosis summary, blast radius, procedure step IDs, expected effects, revalidation requirements, rollback reversibility, audit requirements, unsupported or irreversible aspects, PR309 attestation, and subject hash.

Any future conversion operation must require explicit reviewed context for these items. PR310 does not define a supplemental-context schema, adapter design, migration workflow, draft subject payload, capability registry, or execution path.

## Behavior and safety fields

The analyzer is an isolated in-memory module. It performs no filesystem reads or writes, proposal-file loading, artifact creation, persistence, subprocess calls, shell or PowerShell execution, Docker or Compose calls, network calls, model/provider calls, secret access, credential access, auth-cache inspection, environment mutation, registry lookup, proposal mutation, approval transition, CLI registration, receipt creation, preflight behavior, or execution behavior.

For valid legacy Proposal schema v1 objects, the report always states `compatible_as_is=false`, `approval_portable=false`, and `fingerprint_equivalent=false`. It also fixes `read_only=true`, `mutation_performed=false`, `contract_created=false`, `approval_created=false`, `execution_allowed=false`, `execution_available=false`, and `execution_status=not_executed`.

Current product behavior remains unchanged: V1 is released, early beta-quality, guarded, not production-autonomous, Linux/Docker primary, and Windows preview/early support.
