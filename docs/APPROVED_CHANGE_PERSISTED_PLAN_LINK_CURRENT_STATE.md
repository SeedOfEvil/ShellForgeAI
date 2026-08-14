# Persisted plan-link current-state revalidation

ShellForgeAI exposes one read-only PR338 operation,
`revalidate_persisted_plan_link_artifact_current_state(...)`, to answer one
bounded question: does one exact persisted PR337 `acpl_` plan-link artifact
correspond to one exact caller-supplied saved Windows runtime-reconcile plan, and
do that plan's fixed governed files and destination-parent conditions match at
this instant?

## Required inputs

The caller must supply all of the following explicitly:

- one full `acpl_` artifact ID;
- one parsed saved plan mapping;
- `data_dir` for ShellForgeAI-owned persisted artifacts;
- the staged-source root;
- the durable-runtime root;
- the exact PR337 artifact-identity SHA-256 confirmation;
- the exact canonical plan SHA-256 confirmation.

The full saved plan packet remains caller-supplied. PR337 deliberately persisted
only the canonical PR323 link and duplicated identity fields; it did not persist
the full plan packet, select an inventory item, or record current state.

## Ordering and authorities

The operation is fail-closed:

1. Validate input types, exact `acpl_` shape, both lowercase 64-hex
   confirmations, and the supplied plan through the maintained PR305/PR313 plan
   contract. The canonical plan SHA is computed only through that plan-contract
   seam and must match the explicit plan confirmation before filesystem access.
2. Load exactly one artifact through the maintained PR337 exact-ID loader. No
   inventory, latest/current selection, sibling search, or alternate parser is
   used.
3. Confirm the loaded artifact identity, loaded artifact ID, and embedded PR323
   link. The new path consumes the persisted PR323 link; it does not reconstruct
   provenance through the PR323 construction operation.
4. Compare the persisted link to the supplied plan for maintained structural
   facts: plan SHA, capability, lane, mode, recipe, status,
   destination-parent contract version, fixed two-file allowlist, and operation
   ordering. It does not compare subject prose, desired outcome, diagnosis,
   procedure, rollback prose, approval freshness, or PR304 evidence freshness.
5. Require native Windows before governed-root inspection. Non-Windows returns a
   deterministic `unsupported` result without staged-source or durable-runtime
   access.
6. Reuse the PR328 live-state evaluator for roots, parents, files, hashes,
   containment, symlink/reparse checks, and operation classification.

## Scope

The governed scope remains exactly two ordered mappings:

- `config/profiles/inspect.yaml` → `config/profiles/inspect.yaml`
- `scripts/windows/sfai.cmd` → `bin/sfai.cmd`

There is no caller-supplied allowlist, recursive scan, glob, `System32`
inspection, registry inspection, service inspection, process inspection,
network inspection, arbitrary path access, write, or execution.

## Result and safety

`PersistedPlanLinkCurrentStateResult` is frozen and rejects extra fields. It
reports distinct statuses including `current_state_confirmed`,
`current_state_changed`, `current_state_blocked`, `unsupported`,
`invalid_current_state_input`, `plan_link_artifact_not_available`,
`plan_link_artifact_confirmation_mismatch`, `persisted_link_plan_mismatch`, and
`current_state_validation_failed`.

Every result carries permanent warnings: the result is point-in-time only, may
be stale immediately, the persisted artifact is provenance only, artifact
persistence is not freshness, the full plan was not persisted, the supplied plan
was validated only for this invocation, and the result is not authenticated
identity, approval freshness, authorization, PR304 freshness, execution
preflight, receipt creation/linkage, or execution eligibility. PR313 execution
is not invoked, and natural language cannot invoke this operation.

The fixed safety ledger reports read-only behavior and no mutation,
persistence, receipt, authorization, preflight, service/process/registry
control, shell/subprocess/PowerShell/WinRM/QGA, provider/model, network,
credential, or auth-cache access.

## Canonical evidence consumer

The separate current-state evidence seam calls this maintained PR338 operation
exactly once from the same explicit inputs. Only an internally coherent
`current_state_confirmed` result can become bounded canonical in-memory evidence
with a deterministic, non-circular content identity. PR338 remains the sole
governed-root authority; the consumer performs no second filesystem evaluation.
It includes relative mappings and PR338 root fingerprints, never absolute roots
or raw contents. The identity records point-in-time evidence content only: no
clock or observation timestamp is added, identical content may produce the same
identity across invocations, and state may become stale immediately. This adds
no freshness, authentication, authorization, readiness, preflight, receipt,
persistence, or execution authority.
