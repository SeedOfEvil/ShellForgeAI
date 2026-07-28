# Approved Change Plan Link

PR323 adds exactly one Stage B capability. It answers exactly one question:

> Can this exact PR322 capability binding be deterministically associated with the exact canonical identity of this one maintained-validator-approved saved PR305 Windows runtime-reconcile plan packet?

One module is that capability and nothing else:

- `src/shellforgeai/core/approved_change_plan_link.py` — one immutable plan-link model with a deterministic identity, and one read-only operation that constructs exactly one in-memory plan link.

One further module is a pure seam, not a new rule:

- `src/shellforgeai/core/windows_runtime_reconcile_plan_contract.py` — the maintained PR305 saved-packet acceptance rules, the maintained PR313 executable-plan contract, and the maintained canonical plan identity, extracted verbatim from the standalone acceptance script and the mutation-capable PR313 execution module so exactly one definition exists.

## Why plan linking follows capability binding

PR322 made "which governed lane does this exact approved subject belong to?" one deterministic, read-only, in-memory answer. That answer names a **lane**, not a **plan**. Nothing in the product yet stated *which exact saved plan* an approved binding would ever be paired with, so two entirely different saved plans — a `ready` plan and a stale one, or a plan for a different runtime root — were indistinguishable from the binding's point of view.

PR323 closes exactly that gap: it makes the association of one exact binding identity with the exact canonical SHA-256 of one maintained-validator-approved saved plan a deterministic, in-memory, read-only result.

**A plan link is an identity association only.** `plan_linked=true` means exactly one thing:

> The exact approved binding identity has been associated with the exact canonical identity of one maintained-validator-approved saved Windows reconcile plan.

It does **not** mean the plan is currently safe to run. It is not target semantic compatibility, not procedure semantic compatibility, not free-text intent equivalence, not PR304 evidence freshness, not staged-source inspection, not durable-runtime inspection, not `System32` inspection, not current-state readiness, not preflight success, not authenticated identity, not authorization, not receipt linkage, and not execution eligibility or availability.

## Relationship to PR305, PR313, PR319, PR320, PR321, and PR322

PR305 remains the sole saved-packet acceptance authority. Its rules — schema version, mode, recipe ID, status set, exact two-file allowlist, operation ordering, per-operation hashes, expected post-change hash, backup pattern, destination-parent contract, summary consistency, status precedence, and the required future gates — are unchanged. They now live in the pure plan-contract module, and `scripts/windows_runtime_reconcile_acceptance.py` delegates to it. The operator CLI shape, the `errs`/`parent_errs` names, and every failure string are preserved exactly.

PR313 remains the canonical plan-identity and runtime authority. Its canonical plan JSON, canonical plan SHA-256, plan-SHA format check, constant-time confirmation comparison, and the narrower executable-plan contract (`status` in `ready`/`no_change`, exactly two allowlisted operations in the exact order, no `blocked` operation, destination-parent contract version 1) are unchanged and now also live in the pure module; `windows_runtime_reconcile_execution.py` delegates to it and re-exports the same names. PR313 execution is **not invoked** by PR323: no execute call, no current-state revalidation, no preparation, no backup, no atomic replacement, no compensation, no receipt creation, and no post-change verification.

PR319 remains the sole authority for canonical persisted approval artifacts, `aca_` identities, the fixed `<data_dir>/approved_change_approvals` subtree, and exact-ID loading. PR323 never parses persisted approval JSON and never calls the PR319 loader directly.

PR320 remains discovery only, and PR323 does not use it. There is no inventory call, no automatic selection, no filtering, no ranking, and no `latest`, `current`, or "most recent" resolution. One exact full `aca_` artifact ID is always required.

PR321 remains the sole capability-support authority. PR323 never decides support itself; it reads only the maintained catalog identity so an explicit stale-catalog confirmation can be refused before any filesystem access.

PR322 remains the sole capability-binding authority. PR323 obtains its binding **only** through:

```python
construct_persisted_approved_change_capability_binding(
    approval_artifact_id: str,
    *,
    data_dir: Path | str,
    confirm_capability_catalog_identity_sha256: str,
    confirm_lane_declaration_identity_sha256: str,
) -> ApprovedChangeCapabilityBindingResult
```

called exactly once. PR323 constructs no competing binding, and accepts no caller-supplied binding, contract, artifact, catalog, or lane declaration.

## Public API

```python
canonical_approved_change_plan_link_payload(link) -> dict[str, Any]
canonical_approved_change_plan_link_json(link) -> str
compute_approved_change_plan_link_sha256(link) -> str
validate_approved_change_plan_link(
    link,
    *,
    binding=None,
    plan_validation=None,
) -> ApprovedChangePlanLinkValidationResult

link_persisted_approved_change_to_windows_runtime_reconcile_plan(
    approval_artifact_id: str,
    plan_packet: Mapping[str, Any],
    *,
    data_dir: Path | str,
    confirm_capability_catalog_identity_sha256: str,
    confirm_lane_declaration_identity_sha256: str,
    confirm_plan_sha256: str,
) -> ApprovedChangePlanLinkResult
```

The pure plan-contract seam exposes:

```python
canonical_plan_json(packet) -> str
canonical_plan_sha256(packet) -> str
is_plan_sha256(value) -> bool
confirmation_matches(supplied, expected) -> bool
destination_parent_contract_errors(operation) -> list[str]
saved_plan_packet_acceptance_errors(packet) -> list[str]
saved_plan_executable_contract_errors(packet) -> list[str]
validate_saved_windows_runtime_reconcile_plan_packet(packet)
    -> WindowsRuntimeReconcilePlanValidationResult
```

`validate_approved_change_plan_link` is pure and performs no I/O. Its optional cross-check inputs are checks only, never authorities it may substitute for its own recomputation, and the public operation never accepts them from a caller.

## Explicit inputs only

The operation accepts exactly six explicit inputs: one exact full PR319 `aca_` artifact ID, one explicitly supplied parsed plan mapping, one explicit ShellForgeAI `data_dir`, one explicit raw 64-lowercase-hex PR321 catalog-identity confirmation, one explicit raw 64-lowercase-hex PR322 lane-declaration-identity confirmation, and one explicit raw 64-lowercase-hex canonical plan-SHA confirmation.

It accepts no inventory result, no selected inventory entry, no `latest`/`current`/"most recent" reference, no caller-supplied artifact, contract, capability binding, or lane declaration, no plan-file path, no output path, no PR304 artifact path, no staged-source or durable-runtime root, no `System32` path, no authorization token, no preflight approval, no receipt ID, and no execution confirmation.

**The caller owns parsing a saved packet.** PR323 evaluates the supplied mapping and never mutates it, never writes it anywhere, and never returns it.

## Maintained plan validation and accepted statuses

A supplied packet is accepted only when it passes **both** maintained gates:

1. the maintained PR305 saved-packet acceptance validator, and
2. the narrower maintained PR313 executable-plan contract,

and only when `platform.system` is `windows`.

That means the accepted plan statuses are exactly:

- `ready`
- `no_change`

A `no_change` packet may be linked because it is still the exact validated plan identity for the observed state. **It grants no execution eligibility.**

Packets with status `blocked` or `unsupported`, malformed packets, structurally inconsistent packets, packets with the wrong mode or recipe ID, packets with a reordered or widened allowlist, packets with fewer or more than two operations, packets with a `blocked` operation or blocked destination parent, packets with a wrong destination-parent contract version, packets with an invalid hash, and packets with an unsafe safety flag are all refused with `status=plan_not_accepted` and no link.

## Exact structural comparison scope

PR323 compares only maintained typed facts:

- the PR322 binding `capability_id` equals the validated plan `recipe_id`;
- the PR322 binding `capability_id` is the exact supported `windows.runtime_reconcile`;
- the PR322 binding `lane_id` is the maintained `pr313.windows_runtime_reconcile` lane;
- the plan mode is `windows_runtime_reconcile`;
- the plan recipe ID is `windows.runtime_reconcile`;
- the plan carries the exact fixed two-file allowlist;
- the plan carries destination-parent contract version `1`;
- the plan status is `ready` or `no_change`;
- the plan passes the maintained PR305/PR313 validator.

PR323 explicitly does **not** interpret or compare subject target free text, procedure descriptions, diagnosis text, desired-outcome text, risk wording, rollback prose, evidence freshness, precondition satisfaction, or live filesystem state. Every result therefore reports:

```
subject_semantic_compatibility_evaluated=false
target_compatibility_evaluated=false
procedure_compatibility_evaluated=false
evidence_compatibility_evaluated=false
current_state_preflight_evaluated=false
```

There is deliberately **no** broad field such as `subject_fully_compatible=true`. Two materially different approved subjects that share the declared `capability_id` may both be structurally linked to the same valid plan, and they produce two **different** link identities. That is the intended behaviour: PR323 states structural agreement, not intent agreement.

## The exact plan-link payload and identity

```json
{
  "schema_version": "1",
  "link_type": "approved_change_windows_runtime_reconcile_plan_link",
  "approval_artifact_id": "aca_<64 lowercase hex>",
  "approval_artifact_identity_sha256": "<64 lowercase hex>",
  "subject_sha256": "<64 lowercase hex>",
  "capability_binding_identity_sha256": "<64 lowercase hex>",
  "capability_catalog_identity_sha256": "<64 lowercase hex>",
  "capability_id": "windows.runtime_reconcile",
  "lane_declaration_identity_sha256": "<64 lowercase hex>",
  "lane_id": "pr313.windows_runtime_reconcile",
  "plan_mode": "windows_runtime_reconcile",
  "plan_recipe_id": "windows.runtime_reconcile",
  "plan_sha256": "<64 lowercase hex>",
  "plan_status": "ready|no_change",
  "destination_parent_contract_version": 1,
  "comparison_scope": "exact_binding_to_exact_validated_plan_structure_only"
}
```

```
plan_link_identity_sha256 = SHA256(exact canonical plan-link UTF-8 bytes)
```

Canonicalization sorts mapping keys, uses compact JSON separators, UTF-8, and `ensure_ascii=False`, and emits no BOM and no trailing newline. No current timestamp, environment value, host value, platform value, path, randomness, UUID, or derived identity is ever part of the hashed payload, so the identity can never hash itself and is byte-identical on Linux and Windows.

The payload carries **no** absolute path, staged-source root, durable-runtime root, source or destination content, backup path pattern, user or host identity, timestamp, authorization field, receipt field, or execution field.

The plan-link identity is permanently distinct from the PR309 subject SHA-256, the PR316 bundle identity, the PR319 approval-artifact identity, the PR321 catalog identity, the PR322 lane identity, the PR322 binding identity, the PR305/PR313 canonical plan SHA-256, and any receipt identity.

Same binding + same plan produces byte-identical link bytes and one identical identity. Same binding + a different valid plan produces a different link identity. A different approved subject + the same valid plan produces a different link identity.

There is **no persisted link ID and no link prefix**. The link exists in memory only.

## The three confirmation gates

All three confirmations must be exactly 64 lowercase hexadecimal characters, must equal the freshly computed maintained identities, and are compared with `hmac.compare_digest` **before any filesystem access**. A malformed, empty, uppercase, prefixed, stale, swapped, or mismatched confirmation performs zero filesystem access, calls the maintained PR322 operation zero times, evaluates no plan link, and returns a structured fail-closed result.

The plan-SHA confirmation means exactly one thing:

> Compare against this exact validated saved plan packet.

It is not authorization, preflight approval, or execution confirmation.

The plan packet itself may be structurally validated and hashed before filesystem access, because that work is pure.

## Link sequence

1. Validate the supplied plan mapping with the maintained PR305/PR313 validator.
2. Require status `ready` or `no_change`.
3. Compute the exact maintained canonical plan SHA-256.
4. Validate all three confirmation strings structurally.
5. Require the exact plan-SHA confirmation match.
6. Compute and require the exact current catalog and lane confirmations — still before any filesystem access.
7. Call the maintained PR322 binding operation exactly once.
8. Require a complete, successful, fully bound, non-persisted, self-validated binding.
9. Compare the exact binding capability/lane fields with the validated plan's maintained typed fields.
10. Construct one in-memory plan link.
11. Compute its deterministic identity.
12. Validate the completed link against every maintained input.
13. Return one immutable structured result.

No failed gate is continued past. PR313 execution and current-state revalidation are never called.

## Successful semantics

```
status=plan_link_constructed
link_complete=true
read_only=true
mutation_performed=false
filesystem_accessed=true
artifact_write_performed=false
publication_performed=false
persistence_performed=false
approval_selected=false
approval_created=false
approval_persisted=false
contract_created=false
contract_persisted=false
capability_support_evaluated=true
capability_supported=true
capability_binding_evaluated=true
capability_bound=true
binding_persisted=false
plan_validated=true
plan_identity_confirmed=true
plan_link_evaluated=true
plan_linked=true
plan_link_persisted=false
subject_semantic_compatibility_evaluated=false
target_compatibility_evaluated=false
procedure_compatibility_evaluated=false
evidence_compatibility_evaluated=false
current_state_preflight_evaluated=false
authorization_evaluated=false
preflight_evaluated=false
receipt_created=false
receipt_linked=false
host_configuration_mutation_performed=false
execution_allowed=false
execution_available=false
execution_status=not_executed
```

## Failure before filesystem access

```
read_only=true
mutation_performed=false
filesystem_accessed=false
capability_support_evaluated=false
capability_binding_evaluated=false
capability_bound=false
plan_validated=<true only if plan validation completed>
plan_identity_confirmed=false
plan_link_evaluated=false
plan_linked=false
authorization_evaluated=false
current_state_preflight_evaluated=false
receipt_created=false
receipt_linked=false
execution_allowed=false
execution_available=false
execution_status=not_executed
```

## Structured results

Plan-link statuses:

- `plan_link_constructed`
- `plan_not_accepted`
- `plan_confirmation_mismatch`
- `capability_catalog_confirmation_mismatch`
- `lane_declaration_confirmation_mismatch`
- `capability_binding_not_available`
- `binding_plan_mismatch`
- `plan_link_blocked`
- `invalid_plan_link_input`
- `plan_link_validation_failed`

Plan-link validation statuses: `approved_change_plan_link_valid`, `approved_change_plan_link_invalid`, `invalid_approved_change_plan_link_validation_input`.

Saved-plan validation statuses: `plan_packet_accepted`, `plan_packet_rejected`, `invalid_plan_packet_input`.

Every result is frozen, forbids extra fields, holds immutable deterministic sorted and deduplicated errors, and reports only the maintained authorities' fixed statuses and fixed reason sentences. **The full plan packet is never returned**, no host path copied from the packet or from the maintained validator is ever reported, no traceback is ever reported, and no partial link survives a failed operation.

## Permanent warnings

Every plan-link result states that:

- the plan link is an **in-memory identity association only**;
- the plan link is **not authorization**;
- the plan link is **not current-state preflight**;
- the plan link does not inspect the live staged source;
- the plan link does not inspect the live durable runtime;
- the plan link does not inspect `System32`;
- the plan link does not validate target semantics;
- the plan link does not validate procedure semantics;
- the plan link does not validate PR304 evidence freshness;
- the plan link does not prove preconditions remain true;
- the plan link does not create or link a receipt;
- the plan link grants **no execution eligibility**;
- PR313 execution is not invoked;
- an exact `aca_` approval-artifact ID remains required;
- no approval was selected through inventory;
- persisted `approved_by` remains **self-asserted** metadata, not authenticated identity;
- no CLI or natural-language plan-link or execution route exists.

## Static boundary

The plan-link model, the canonicalization, the validator, and the whole plan-contract seam are pure. The plan-link operation reaches the filesystem only indirectly, through the maintained PR322 binding operation.

The production module imports exactly `__future__`, `collections.abc`, `hashlib`, `hmac`, `json`, `pathlib`, `typing`, `pydantic`, and the three maintained ShellForgeAI modules it depends on — `approved_change_capability_binding`, `approved_change_capability_support`, and `windows_runtime_reconcile_plan_contract`. It imports or calls no PR320 inventory, no legacy approvals module, no PR313 execute, receipt, or verification function, no recipe registry, no CLI module, no shell or subprocess, no PowerShell, no network or socket API, no Docker or Compose call, no model or provider, no credential access, no environment identity, no OS user or hostname, no clock, no randomness or UUID, and no filesystem write primitive.

## The pure plan-contract extraction

The extraction is delegation-only. It moved constants, canonicalization, SHA-256 identity, and structural validation into one module and left everything else where it was. It did **not** move execution, filesystem mutation, current-state revalidation, receipt, backup, or compensation logic; it did not broaden the allowlist; and it did not change the canonical plan identity. `tests/test_pr305_windows_runtime_reconcile.py`, `tests/test_pr313_windows_runtime_reconcile_execute.py`, `tests/test_pr313_windows_runtime_reconcile_receipt.py`, and `tests/test_pr313_windows_runtime_reconcile_verify.py` pass unchanged, which is the regression proof that PR313 behaviour is byte-for-byte the same.

`scripts/windows_runtime_reconcile_acceptance.py` keeps its operator CLI and gains the same source-checkout bootstrap that `scripts/windows_runtime_reconcile_execute.py` already used, so `python scripts/windows_runtime_reconcile_acceptance.py <packet.json> --json` still works from an exact source checkout.

## Explicit non-goals

PR323 adds no live current-state revalidation, PR313 execution preflight, PR313 execution, PR304 artifact collection, PR304 evidence-freshness validation, staged-source inspection, durable-runtime inspection, `System32` inspection, target semantic compatibility, procedure semantic compatibility, natural-language interpretation of subject fields, authenticated identity, role validation, authorization, receipt creation, receipt linkage, execution eligibility, persisted plan link, plan-link publisher or loader, approval selection, inventory selection, `latest`/`current` resolution, CLI command, interactive route, natural-language plan linking, filesystem write, host mutation, Docker or Compose action, PowerShell/WinRM/QGA/shell/subprocess/network/model/credential path, or clock/hostname/OS-user/randomness/UUID dependency.

There is no new persisted subtree and no new persisted file, so the data layout is unchanged. There is no CLI surface, so the command reference is unchanged.

## Next dependency

Stage B remains incomplete. The next focused dependency is **live current-state revalidation of the exact linked plan — still not execution**.

Everything else stays deferred to PR324 or later: staged-source hash rechecks, durable-runtime destination rechecks, destination-parent current-state checks, an exact approved-subject to live-plan semantic policy if separately reviewed and typed, PR304 evidence freshness and compatibility, `System32` validation, persisted plan-link artifacts, authenticated identity, role validation, authorization, receipt linkage, execution eligibility, Stage C execution, additional supported capabilities, and CLI or natural-language plan-link/preflight/execution routes.
