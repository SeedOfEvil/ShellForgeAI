# Approved Change Contract

PR309 begins Roadmap Stage B by adding an inert approved-change contract foundation. It does not complete Stage B and does not change current product behavior.

## Responsibilities

The contract separates two immutable records:

- **ApprovedChangeSubject**: the exact reviewed change subject.
- **ApprovalAttestation**: a record that an actor string approved one exact subject hash with scope `exact_subject_only`.

The attestation is not authenticated human identity, role validation, authorization infrastructure, identity-provider proof, or proof that the stated actor controls the named identity.

## Approval-bound subject fields

The subject hash binds these field categories: schema version, source proposal reference, capability identifier, exact target kind/name/identity claims, desired outcome, diagnosis summary, risk, evidence references, change summary, impact, blast radius, ordered procedure, preconditions, current-state revalidation requirements, verification criteria, rollback posture, audit requirements, and unsupported or irreversible aspects.

Existing legacy proposal objects are references only. They are not automatically equivalent to this contract, and future integration requires a separately reviewed compatibility or migration decision.

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
