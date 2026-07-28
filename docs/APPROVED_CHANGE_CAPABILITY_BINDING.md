# Approved Change Capability Binding

PR322 adds exactly one Stage B capability. It answers exactly one question:

> Can this exact approved subject be deterministically associated with the exact source-maintained `windows.runtime_reconcile` governed lane declaration?

One module is that capability and nothing else:

- `src/shellforgeai/core/approved_change_capability_binding.py` — one immutable, source-maintained lane declaration, one immutable binding model with a deterministic identity, and one read-only operation that constructs exactly one in-memory binding.

## Why binding follows support

PR321 made the supported capability set a single maintained product artifact and made "is this exact `capability_id` declared supported?" one governed, read-only, fail-closed operation. That answer is deliberately capability-ID membership only: it names no implementation, so nothing in the product yet states *which* governed lane an approved subject would ever belong to. Two approved subjects sharing one declared capability ID were indistinguishable from each other and from a lane that does not exist.

PR322 closes exactly that gap: it names the one governed PR313 implementation lane as an immutable source declaration with its own deterministic identity, and it makes the association of one exact persisted approval with that exact declaration one deterministic, in-memory, read-only result.

**A capability binding is an identity association only.** `capability_bound=true` means exactly one thing:

> One exact approved subject identity has been associated with one exact immutable named-lane declaration in memory.

It does **not** mean the lane can run. It is not authorization, not target compatibility, not procedure compatibility, not PR304/PR305 evidence compatibility, not subject-to-PR313-plan agreement, not current-state readiness, not preflight success, not receipt availability, and not execution eligibility or availability.

## Relationship to PR309, PR319, PR320, PR321, and PR313

PR309 remains the sole authority for `ApprovedChangeSubject`, `ApprovalAttestation`, `ApprovedChangeContract`, subject canonicalization, subject SHA-256, `exact_subject_only`, approval binding, the capability-ID syntax, and `validate_approved_change_contract`. PR322 defines no competing contract validator, no competing subject-identity rule, and no competing binding check.

PR319 remains the sole authority for canonical persisted approval artifacts, `aca_` identities, the fixed `<data_dir>/approved_change_approvals` subtree, exact-ID loading, PR309 binding revalidation, and PR317 source-bundle provenance revalidation. PR322 reaches persisted approvals **only** through:

```python
load_persisted_approved_change_approval_artifact(
    approval_artifact_id: str,
    *,
    data_dir: Path | str,
) -> ApprovedChangeApprovalArtifactLoadResult
```

and it reuses PR319's own `derive_approval_artifact_id` rather than restating how an `aca_` ID relates to an artifact identity. PR322 never parses persisted approval JSON, never loads a PR317 source bundle directly, never calls the PR319 or PR317 publisher, and never accepts an arbitrary artifact path.

PR320 remains discovery only, and PR322 does not use it. There is no inventory call, no automatic selection, no filtering, no ranking, and no `latest`, `current`, or "most recent" resolution. One exact full `aca_` artifact ID is always required.

PR321 remains the sole capability-support authority. PR322 calls:

```python
evaluate_persisted_approved_change_capability_support(
    approval_artifact_id: str,
    *,
    data_dir: Path | str,
    confirm_capability_catalog_identity_sha256: str,
) -> ApprovedChangeCapabilitySupportEvaluationResult
```

exactly once, and never replaces that decision with its own membership check. Support must be confirmed before a binding exists.

PR313 remains the runtime authority and is **not invoked**. PR322 names and describes the governed lane; it imports no PR313 execution, preflight, receipt, or verification module, constructs no PR313 plan, validates no PR304 or PR305 artifact, inspects no staged source, durable runtime root, or `System32` location, calls no executor, creates or validates no receipt, and claims no execution eligibility. The recipe registry stays separate too: the lane declaration is never derived from `recipe_registry.py`, from a PR313 module, from a script name, from filesystem contents, from environment variables, or from an installed plugin.

## The updated PR321 support declaration

PR322 makes the read-only in-memory binding operation available, so exactly one maintained PR321 field changed:

| Field | Before | After |
| --- | --- | --- |
| `capability_binding_available` | `false` | **`true`** |
| `authorization_available` | `false` | `false` |
| `preflight_available` | `false` | `false` |
| `receipt_linkage_available` | `false` | `false` |
| `execution_available` | `false` | `false` |

The capability ID, the support status, the exact-match rule, the validation scope, every other declaration, and the number of declarations are unchanged: the catalog still holds exactly one declaration, and it is still `windows.runtime_reconcile`.

`capability_binding_available=true` states only that the read-only PR322 binding *operation* exists for this exact capability ID. PR321 still performs no binding, names no lane, and reports `capability_bound=false` on every result.

That intentionally changes the PR321 canonical catalog bytes and its SHA-256 identity:

```
canonical byte length : 464   (was 465)
catalog identity      : 762d8263642289f4c7230e0e4c625720c3cee461c6f229a724a8b2e15cc0786d
                        (was 7dcf112b0807bd7388912b5b1cf59f2be8c0d5b30ec6fa0d05265d88b936da61)
```

A stale pre-PR322 catalog confirmation now fails closed with zero filesystem access.

## The exact maintained lane declaration

Exactly one lane is declared today:

| Field | Value |
| --- | --- |
| `schema_version` | `"1"` |
| `capability_id` | `"windows.runtime_reconcile"` |
| `lane_id` | `"pr313.windows_runtime_reconcile"` |
| `lane_kind` | `"named_governed_implementation_lane"` |
| `binding_status` | `"declared_bindable"` |
| `match_rule` | `"exact_capability_id_only"` |
| `binding_scope` | `"exact_approved_subject_to_exact_named_lane_declaration_only"` |
| `implementation_scope` | `"windows_exact_two_file_runtime_reconciliation_only"` |
| `binding_persistence_available` | `false` |
| `authorization_available` | `false` |
| `preflight_available` | `false` |
| `receipt_linkage_available` | `false` |
| `execution_available` | `false` |

`declared_bindable` means the lane declaration exists and may be named by a binding. It does not mean runnable, ready, eligible, or authorized. `implementation_scope` restates the maintained PR313 boundary as static declaration text; it grants no access to the PR313 runtime.

The declaration is **source-maintained and in-memory only**. There is no persisted lane ID, no prefix, no lane file, no lane subtree, no lane publisher, and no lane inventory.

## Lane-declaration canonicalization and identity

Canonicalization sorts mapping keys, uses compact JSON separators, UTF-8, and `ensure_ascii=False`, and emits no BOM and no trailing newline. No current timestamp, environment value, host value, platform value, path, runtime value, or derived identity is ever part of the hashed payload, so the identity can never hash itself and is byte-identical on Linux and Windows.

```
lane_declaration_identity_sha256 = SHA256(exact canonical declaration UTF-8 bytes)
```

For the maintained declaration those values are committed fixtures:

```
canonical byte length : 550
lane identity         : 3f94c038a65f9af863fce646342e8f06f4c25b3a417736aff941b3bccd7b5316
```

## The exact binding payload and identity

```json
{
  "schema_version": "1",
  "binding_type": "approved_change_capability_binding",
  "approval_artifact_id": "aca_<64 lowercase hex>",
  "approval_artifact_identity_sha256": "<64 lowercase hex>",
  "subject_sha256": "<64 lowercase hex>",
  "capability_catalog_identity_sha256": "<64 lowercase hex>",
  "capability_id": "windows.runtime_reconcile",
  "lane_declaration_identity_sha256": "<64 lowercase hex>",
  "lane_id": "pr313.windows_runtime_reconcile",
  "binding_scope": "exact_approved_subject_to_exact_named_lane_declaration_only",
  "implementation_scope": "windows_exact_two_file_runtime_reconciliation_only"
}
```

```
binding_identity_sha256 = SHA256(exact canonical binding payload UTF-8 bytes)
```

The payload carries no derived identity, so the binding identity is non-circular. It is permanently distinct from the PR309 subject SHA-256, the PR316 bundle identity, the PR319 approval-artifact identity, the PR321 capability-catalog identity, the lane-declaration identity, any PR313 plan hash, and any receipt identity.

Two entirely different approved subjects that share the exact declared `capability_id` produce two **different** binding identities, because each binding names its own exact subject and artifact identities. Binding the same artifact repeatedly produces byte-identical payloads and one identical identity.

There is no persisted binding ID and no binding prefix. The binding exists in memory only.

## Public API

```python
maintained_windows_runtime_reconcile_lane_declaration() -> ApprovedChangeCapabilityLaneDeclaration

canonical_capability_lane_declaration_payload(declaration) -> dict[str, Any]
canonical_capability_lane_declaration_json(declaration) -> str
compute_capability_lane_declaration_sha256(declaration) -> str
validate_capability_lane_declaration(declaration)
    -> ApprovedChangeCapabilityLaneDeclarationValidationResult

canonical_approved_change_capability_binding_payload(binding) -> dict[str, Any]
canonical_approved_change_capability_binding_json(binding) -> str
compute_approved_change_capability_binding_sha256(binding) -> str
validate_approved_change_capability_binding(
    binding,
    *,
    catalog=None,
    lane_declaration=None,
    support_result=None,
    approval_artifact=None,
) -> ApprovedChangeCapabilityBindingValidationResult

construct_persisted_approved_change_capability_binding(
    approval_artifact_id: str,
    *,
    data_dir: Path | str,
    confirm_capability_catalog_identity_sha256: str,
    confirm_lane_declaration_identity_sha256: str,
) -> ApprovedChangeCapabilityBindingResult
```

`maintained_windows_runtime_reconcile_lane_declaration` reads no file, reads no environment variable, inspects no installed recipe, inspects no script, inspects no OS, host, or platform, reads no credential, calls no network service, loads no plugin, and discovers no adapter.

`validate_approved_change_capability_binding` is pure and performs no I/O. Its optional cross-check inputs are checks only, never authorities it may substitute for its own recomputation, and the public binding operation never accepts them from a caller.

## Explicit inputs only

The binding operation accepts exactly four explicit inputs: one exact full PR319 `aca_` artifact ID, one explicit ShellForgeAI `data_dir`, one explicit raw 64-lowercase-hex PR321 catalog-identity confirmation, and one explicit raw 64-lowercase-hex lane-declaration-identity confirmation.

It accepts no inventory result, no selected inventory entry, no `latest`, `current`, or "most recent" reference, no caller-supplied artifact, contract, support result, catalog, or lane declaration, no PR313 plan, no PR304 or PR305 artifact, no execution target, no preflight, no receipt, no authorization token, no output path, and no execution confirmation.

## The two confirmation gates

Both confirmations must be exactly 64 lowercase hexadecimal characters, must equal the freshly computed maintained identities, and are compared with `hmac.compare_digest` **before any filesystem access**. A malformed, mismatched, stale, uppercase, or swapped confirmation performs zero filesystem access, calls neither maintained authority, and returns a structured fail-closed result.

The lane-declaration confirmation means exactly one thing:

> Bind against this exact source-maintained lane declaration.

It is not authorization, preflight approval, or execution confirmation.

## Binding sequence

1. Obtain the maintained PR321 support catalog and validate it.
2. Compute its current identity.
3. Obtain the maintained lane declaration and validate it.
4. Compute its identity.
5. Validate both explicit confirmation values structurally.
6. Require both exact confirmation matches.
7. Call the maintained PR321 evaluator with the exact artifact ID, the exact data root, and the exact support-catalog confirmation.
8. Require `capability_support_confirmed`, a completed evaluation, `capability_supported=true`, the exact capability ID `windows.runtime_reconcile`, a found declaration, and PR309 `contract_valid`.
9. Load the same exact artifact through the maintained PR319 exact-ID loader, solely to obtain the exact artifact identity and subject SHA-256 the PR321 result does not expose.
10. Require exact agreement between the PR321 result and the PR319 load on the artifact ID, the artifact identity, the subject SHA-256, the capability ID, and the approval binding.
11. Require the exact capability ID to match the maintained lane declaration.
12. Construct one in-memory binding.
13. Compute and validate its deterministic identity against every maintained input.
14. Return one immutable result.

No failed gate is continued past.

## Successful semantics

```
status=capability_binding_constructed
binding_complete=true
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
binding_created=true
binding_persisted=false
authorization_evaluated=false
preflight_evaluated=false
receipt_created=false
receipt_linked=false
host_configuration_mutation_performed=false
execution_allowed=false
execution_available=false
execution_status=not_executed
```

## Unsupported or unbindable semantics

An approved artifact whose exact capability ID is not declared supported is a **completed fail-closed result**, not an exception:

```
status=capability_binding_not_available
capability_support_evaluated=true
capability_supported=false
capability_binding_evaluated=true
capability_bound=false
binding_created=false
binding=None
execution_allowed=false
```

Syntactically valid near misses stay unbound too: `windows.runtime_reconcile.v2`, `windows.runtime-reconcile`, `windows.runtime_reconcile_preview`, and `example.windows.runtime_reconcile`.

## Failure before filesystem access

```
read_only=true
mutation_performed=false
filesystem_accessed=false
capability_support_evaluated=false
capability_binding_evaluated=false
capability_bound=false
binding_created=false
binding_persisted=false
execution_allowed=false
```

## Structured results

Binding statuses:

- `capability_binding_constructed`
- `capability_binding_not_available`
- `capability_binding_blocked`
- `invalid_capability_binding_input`
- `capability_catalog_confirmation_mismatch`
- `lane_declaration_confirmation_mismatch`
- `approval_artifact_not_available`
- `approval_artifact_invalid`
- `capability_support_not_confirmed`
- `capability_binding_validation_failed`

Lane-declaration validation statuses: `capability_lane_declaration_valid`, `capability_lane_declaration_invalid`, `invalid_capability_lane_declaration_input`.

Binding validation statuses: `capability_binding_valid`, `capability_binding_invalid`, `invalid_capability_binding_validation_input`.

Every result is frozen, forbids extra fields, holds immutable deterministic sorted and deduplicated errors, and reports only the maintained authorities' fixed statuses and fixed reason sentences. No traceback and no host absolute path is ever reported, and no partial binding survives a failed operation.

## Permanent warnings

Every binding result states that:

- capability binding is an **in-memory identity association only**;
- binding is **not authorization**;
- binding does not validate target compatibility;
- binding does not validate procedure compatibility;
- binding does not validate PR304 or PR305 evidence;
- binding does not compare the approved subject with a PR313 plan;
- binding does not evaluate current state;
- binding does not run a preflight;
- binding does not create or link a receipt;
- binding grants **no execution eligibility**;
- binding does not invoke PR313;
- an exact `aca_` approval-artifact ID remains required;
- no approval was selected through inventory;
- persisted `approved_by` remains **self-asserted** metadata, not authenticated identity;
- no CLI or natural-language capability-binding or execution route exists.

## Static boundary

The lane declaration, the canonicalization, and both validators are pure. The binding operation reaches the filesystem only indirectly, through the maintained PR321 evaluator and the maintained PR319 exact-ID loader.

The production module imports exactly `__future__`, `hashlib`, `hmac`, `json`, `pathlib`, `typing`, `pydantic`, and the four maintained ShellForgeAI modules it depends on — `approved_change_contract`, `approved_change_approval_artifact`, `approved_change_approval_persistence`, and `approved_change_capability_support`. It imports or calls no PR320 inventory, no recipe registry, no PR313 execution, preflight, receipt, or verification module, no PR304 or PR305 module, no legacy approvals module, no CLI module, no shell or subprocess, no PowerShell, no network or socket API, no Docker or Compose call, no model or provider, no credential access, no environment identity, no OS user or hostname, no clock, no randomness or UUID, and no filesystem write primitive.

## Explicit non-goals

PR322 adds no persisted binding artifact, binding publication, binding loading, binding ID or prefix, approval selection, `latest`/`current`/"most recent" resolution, target compatibility evaluation, procedure compatibility evaluation, subject-to-plan comparison, PR304 or PR305 validation, staged-source inspection, durable-runtime inspection, `System32` inspection, current-state revalidation, evidence-freshness check, authenticated identity, identity-provider integration, role validation, authorization, preflight, receipt creation or linkage, execution eligibility, execution, PR313 invocation, recipe execution, CLI command, interactive route, natural-language binding or execution, dynamic lane discovery, plugin registration, caller-supplied declaration, filesystem write, host configuration change, Docker or Compose call, PowerShell/WinRM/QGA call, shell or subprocess, network call, model or provider call, credential access, current-time lookup, or randomness/UUID.

There is no new persisted subtree and no new persisted file, so the data layout is unchanged. There is no CLI surface, so the command reference is unchanged.

## Next dependency

Stage B remains incomplete. The next focused dependency is **current-state execution preflight and exact approved-subject to live-PR313-plan comparison — still not execution**.

Everything else stays deferred to PR323 or later: persisted binding artifacts, PR304/PR305 evidence compatibility, target and procedure compatibility, staged-source and durable-runtime validation, `System32` validation, authenticated identity, role validation, authorization, receipt linkage, execution eligibility, Stage C execution, additional supported capabilities, dynamic capability or lane registration, and CLI or natural-language binding or execution routes.
