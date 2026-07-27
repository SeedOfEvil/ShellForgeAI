# Approved Change Contract

PR309 begins Roadmap Stage B by adding an inert approved-change contract foundation. It does not complete Stage B and does not change current product behavior.

## Responsibilities

The contract separates two immutable records:

- **ApprovedChangeSubject**: the exact reviewed change subject.
- **ApprovalAttestation**: a record that an actor string approved one exact subject hash with scope `exact_subject_only`.

The attestation is not authenticated human identity, role validation, authorization infrastructure, identity-provider proof, or proof that the stated actor controls the named identity.

## Approval-bound subject fields

The subject hash binds these field categories: schema version, source proposal reference, capability identifier, exact target kind/name/identity claims, desired outcome, diagnosis summary, risk, evidence references, change summary, impact, blast radius, ordered procedure, preconditions, current-state revalidation requirements, verification criteria, rollback posture, audit requirements, and unsupported or irreversible aspects.

Existing legacy proposal objects are references only. They are not automatically equivalent to this contract, and future integration requires a separately reviewed compatibility or migration decision. PR310 assesses legacy Proposal schema v1 in [Legacy Proposal Compatibility Assessment](LEGACY_PROPOSAL_COMPATIBILITY.md): approval is not portable, fingerprint identity is not equivalent, future conversion requires explicit reviewed supplemental context, and PR310 creates no subject or attestation. PR311 defines field-source permissions for future construction in [Approved Change Construction Policy](APPROVED_CHANGE_CONSTRUCTION_POLICY.md): the PR309 contract remains the sole destination schema authority, no subject or contract is constructed, and all candidate legacy reuse remains explicitly reviewed. PR314 defines the reviewed input package in [Approved Change Supplemental Context](APPROVED_CHANGE_SUPPLEMENTAL_CONTEXT.md): it supplies reviewed values only, reuses the PR309 `ApprovedChangeTarget`, `EvidenceReference`, `ProcedureStep`, and `RollbackPosture` types rather than duplicating them, computes a separate supplemental-context SHA-256 that is never a subject or approval identity, and creates no subject, attestation, contract, approval portability, or execution eligibility. PR315 adds the only construction operation in [Approved Change Subject Construction](APPROVED_CHANGE_SUBJECT_CONSTRUCTION.md): PR309 remains the sole destination schema and the sole subject-identity authority, PR311 remains the sole field-source-policy authority, and PR314 remains reviewed input only. PR315 instantiates exactly one `ApprovedChangeSubject` on complete success, uses only `compute_subject_sha256` for subject identity, creates no `ApprovalAttestation` and no `ApprovedChangeContract`, and never turns reviewer metadata into approval. A constructed subject is unapproved, unbound, unpersisted, and non-executable. PR316 defines the persistence payload for that subject in [Approved Change Artifact Bundle](APPROVED_CHANGE_ARTIFACT_BUNDLE.md): PR309 remains the sole subject schema and subject-identity authority, the bundle stores the subject only as the bytes produced by `canonical_subject_json`, those bytes hash to exactly the PR309 subject SHA-256, and the separate non-circular bundle identity is never a subject identity. PR316 never imports or constructs `ApprovalAttestation` or `ApprovedChangeContract`, performs no filesystem write, and grants no approval, capability support, or execution eligibility. PR317 adds the one governed filesystem boundary for those bundles in [Approved Change Artifact Persistence](APPROVED_CHANGE_ARTIFACT_PERSISTENCE.md): it publishes the exact PR316 bytes beneath the fixed `<data_dir>/approved_change_artifacts/<bundle-id>/` subtree under an explicit bundle-identity confirmation, never overwrites, and likewise never imports or constructs `ApprovalAttestation` or `ApprovedChangeContract`. A persisted bundle remains unapproved, unbound, and non-executable: persistence is not approval, not authorization, and not an `ApprovedChangeContract`. PR318 adds the one explicit approval-binding operation in [Approved Change Approval Workflow](APPROVED_CHANGE_APPROVAL_WORKFLOW.md): it loads one exact persisted PR317 bundle read-only, requires an explicit `approve` decision plus exact bundle-identity and subject-hash confirmations, sources the subject only from the fixed PR316 subject file, recomputes subject identity only with `compute_subject_sha256`, and creates exactly one `ApprovalAttestation` and one `ApprovedChangeContract` — in memory only — whose binding it verifies with `verify_approval_binding`. PR309 remains the sole authority for both models, for subject identity, and for the `exact_subject_only` scope; the bundle-identity confirmation selects the source bundle and never widens that scope. PR318 persists no approval or contract, never calls `validate_approved_change_contract`, evaluates no capability support, and grants no execution eligibility.

## Canonical subject identity

The subject fingerprint exists so approval applies only to the exact reviewed subject. Canonical serialization uses UTF-8 JSON, sorted mapping keys, compact separators, normalized UTC timestamps, deterministic sorting for set-like target identity claims and evidence references, and preserved ordering for reviewed procedural sequences. The approval attestation, validation result, and caller-supplied capability support are excluded from the subject hash.

## Approval binding and capability support

`verify_approval_binding` recomputes the subject SHA-256 and compares it exactly with `approval.subject_sha256`. It never repairs a mismatch, creates an approval, persists state, or grants execution eligibility.

`validate_approved_change_contract` requires an explicit caller-supplied supported-capability set. There is no default allow-all, wildcard, prefix match, fuzzy match, implicit registry lookup, or capability registry in PR309. Unknown capabilities are blocked.

## Validity is not execution eligibility

A structurally valid, correctly bound, supported contract is only `contract_valid`. Validation always reports read-only behavior: mutation not performed, execution not allowed, execution not available, and execution status `not_executed`.

Current-state revalidation remains a mandatory future execution-preflight concern. Rollback posture records awareness, limitations, and descriptive recovery steps, but it is not an automatic rollback promise and provides no rollback executor.

## Explicit non-integration

PR309 adds no persistence, adapter, CLI route, registry, proposal integration, approval workflow integration, preflight integration, receipt linkage, executor, model/provider call, network call, Docker/Compose call, shell, subprocess, or artifact write. The current product behavior remains unchanged.

## Non-executable JSON-shaped example

```json
{
  "subject": {
    "schema_version": "1",
    "source_proposal_reference": "proposal:example",
    "capability_id": "example.synthetic_bounded_change",
    "target": {"kind": "container", "name": "demo", "identity_claims": [{"key": "id", "value": "abc"}]},
    "desired_outcome": "restore the reviewed healthy state",
    "diagnosis_summary": "reviewed evidence indicates configuration drift",
    "risk": "medium",
    "evidence_references": [{"reference_id": "ev-1", "source": "report", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "observed_at": "2026-07-20T12:00:00Z"}],
    "change_summary": "bounded descriptive correction",
    "impact": "single reviewed target",
    "blast_radius": "one target only",
    "procedure": [{"step_id": "step-1", "description": "perform the reviewed bounded correction", "expected_effect": "target matches reviewed state"}],
    "preconditions": ["operator confirms maintenance window"],
    "revalidation_requirements": ["re-check target identity and current evidence"],
    "verification_criteria": ["fresh evidence satisfies health criteria"],
    "rollback_posture": {"reversible": true, "summary": "manual recovery expected", "procedure": [{"step_id": "rollback-1", "description": "restore reviewed prior state", "expected_effect": "target returns to prior state"}], "limitations": ["automatic rollback unsupported"]},
    "audit_requirements": ["record subject hash and verification outcome"],
    "unsupported_or_irreversible_aspects": ["none identified"]
  },
  "approval": {"schema_version": "1", "approved_by": "operator", "approved_at": "2026-07-20T12:05:00Z", "reason": "reviewed exact subject", "subject_sha256": "...", "scope": "exact_subject_only"}
}
```
