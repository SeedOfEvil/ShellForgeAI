# Approved Change Capability Support

PR321 adds exactly one Stage B capability. It answers exactly one question:

> Is this exact approved change's exact `capability_id` declared supported by ShellForgeAI **for approved-change contract validation**?

One module is that capability and nothing else:

- `src/shellforgeai/core/approved_change_capability_support.py` — one immutable, canonical, product-maintained capability-support declaration catalog plus one read-only evaluator over one exact persisted PR319 approval artifact.

## Why this slice exists

PR309 already validates an `ApprovedChangeContract` against a supported-capability collection — but that collection is *caller-supplied*. PR309 deliberately owns no catalog, no registry, and no default allow-all, so up to now every caller has been free to invent its own idea of what ShellForgeAI supports. Two callers could disagree, and a test fixture's synthetic capability was indistinguishable from a real product commitment.

PR321 closes exactly that gap: it makes the supported set a single maintained product artifact with a deterministic identity, and it makes the evaluation of one persisted approved contract against that exact catalog one governed, read-only, fail-closed operation.

**Declared capability support is contract validation only.** It is not capability binding, not authorization, not runtime compatibility, not target or procedure compatibility, not current-state readiness, not PR313 eligibility, not preflight success, not receipt availability, and not execution eligibility or availability.

## Relationship to PR309, PR319, PR320, and PR313

PR309 remains the sole authority for `ApprovedChangeSubject`, `ApprovalAttestation`, `ApprovedChangeContract`, subject canonicalization, subject SHA-256, `exact_subject_only`, approval binding, the capability-ID syntax, `validate_approved_change_contract`, and the meaning of `contract_valid`, `unsupported_capability`, `approval_mismatch`, and `invalid_validation_input`. PR321 calls that maintained validator for the actual support decision and defines no competing contract validator, no competing subject-identity rule, and no competing binding check.

PR319 remains the sole authority for canonical persisted approval artifacts, `aca_` identities, the fixed `<data_dir>/approved_change_approvals` subtree, exact-ID loading, PR309 binding revalidation, and PR317 source-bundle provenance revalidation. PR321 reaches persisted approvals **only** through:

```python
load_persisted_approved_change_approval_artifact(
    approval_artifact_id: str,
    *,
    data_dir: Path | str,
) -> ApprovedChangeApprovalArtifactLoadResult
```

PR321 never parses persisted approval JSON, never recomputes an artifact identity, never loads a PR317 source bundle directly, never calls the PR319 or PR317 publisher, never repairs or republishes an artifact, and never accepts an arbitrary artifact path.

PR320 remains discovery only, and PR321 does not use it. There is no inventory call, no automatic selection, no filtering, no ranking, and no `latest`, `current`, or "most recent" resolution. One exact full `aca_` artifact ID is always required.

PR313 remains separate from *this* module. `windows.runtime_reconcile` is the only capability ID PR321 declares, and that declaration imports no PR313 execution code, inspects no PR313 plan, validates no PR304 or PR305 artifact, evaluates no target path, checks no `System32`, calls no preflight, creates or validates no receipt, invokes no recipe or executor, and does not claim that any persisted approved subject is bound to the PR313 lane. The exact read-only in-memory binding itself landed separately in PR322 — see [Approved Change Capability Binding](APPROVED_CHANGE_CAPABILITY_BINDING.md) — and it still invokes no PR313 runtime.

The recipe registry stays separate too. Support is never derived from `recipe_registry.py`: that registry holds read-only, preview-only, disabled, and future recipe states whose semantics are not approved-change capability support. PR321 scans no `_RECIPES`, infers nothing from recipe status or mutation class, imports no recipe command, exposes no recipe ID as a binding, and never converts preview availability into execution availability.

`src/shellforgeai/core/approvals.py` remains the legacy `Proposal` schema-v1 workflow, and PR310's non-portability decision remains in force. PR321 reads no legacy proposal state, converts no `Proposal`, treats no `Proposal` fingerprint as a capability identity, and bridges no legacy proposal status into capability support.

## The exact maintained declaration

Exactly one capability is declared today:

| Field | Value |
| --- | --- |
| `schema_version` | `"1"` |
| `capability_id` | `"windows.runtime_reconcile"` |
| `support_status` | `"declared_supported"` |
| `match_rule` | `"exact_capability_id_only"` |
| `validation_scope` | `"approved_change_contract_validation_only"` |
| `capability_binding_available` | `true` (PR322) |
| `authorization_available` | `false` |
| `preflight_available` | `false` |
| `receipt_linkage_available` | `false` |
| `execution_available` | `false` |

Nothing else is declared: not `docker.disposable_restart`, not a read-only recipe ID, not a metadata operation, not a `status`/`triage`/`propose`/`verify`/`handoff` command, not a wildcard, not a synthetic test capability, and not a PR313 script name.

## The exact catalog payload

```json
{
  "schema_version": "1",
  "catalog_type": "approved_change_capability_support_catalog",
  "declarations": [
    {
      "schema_version": "1",
      "capability_id": "windows.runtime_reconcile",
      "support_status": "declared_supported",
      "match_rule": "exact_capability_id_only",
      "validation_scope": "approved_change_contract_validation_only",
      "capability_binding_available": true,
      "authorization_available": false,
      "preflight_available": false,
      "receipt_linkage_available": false,
      "execution_available": false
    }
  ]
}
```

## Canonicalization and the deterministic catalog identity

Canonicalization sorts declaration mappings by key, sorts declarations lexicographically by exact `capability_id`, uses compact JSON separators, UTF-8, and `ensure_ascii=False`, and emits no BOM and no trailing newline. No current timestamp, environment value, host value, platform value, or derived identity is ever part of the hashed payload, so the identity can never hash itself and is byte-identical on Linux and Windows.

```
catalog_identity_sha256 = SHA256(exact canonical catalog UTF-8 bytes)
```

For the maintained catalog those values are committed fixtures:

```
canonical byte length : 464
catalog identity      : 762d8263642289f4c7230e0e4c625720c3cee461c6f229a724a8b2e15cc0786d
```

The catalog is **source-maintained and in-memory only**. There is no persisted catalog ID, no prefix, no catalog file, no catalog subtree, no catalog publisher, and no catalog inventory.

## Public API

```python
maintained_approved_change_capability_support_catalog() -> ApprovedChangeCapabilitySupportCatalog

canonical_approved_change_capability_support_catalog_payload(catalog) -> dict[str, Any]
canonical_approved_change_capability_support_catalog_json(catalog) -> str
compute_approved_change_capability_support_catalog_sha256(catalog) -> str
validate_approved_change_capability_support_catalog(catalog)
    -> ApprovedChangeCapabilitySupportCatalogValidationResult

evaluate_persisted_approved_change_capability_support(
    approval_artifact_id: str,
    *,
    data_dir: Path | str,
    confirm_capability_catalog_identity_sha256: str,
) -> ApprovedChangeCapabilitySupportEvaluationResult
```

`maintained_approved_change_capability_support_catalog` reads no file, reads no environment variable, inspects no installed recipe, inspects no OS, host, or platform, reads no credential, calls no network service, loads no plugin, and discovers no adapter. It returns the exact immutable catalog defined in source.

## Catalog validation

`validate_approved_change_capability_support_catalog` is pure and non-throwing. It reports one of:

- `capability_support_catalog_valid`
- `capability_support_catalog_invalid`
- `invalid_capability_support_catalog_input`

A valid catalog requires the exact schema version, the exact catalog type, at least one declaration, unique exact capability IDs, valid PR309 capability-ID syntax with no wildcard, the exact declaration enums, every *not-yet-implemented* availability field (`authorization_available`, `preflight_available`, `receipt_linkage_available`, `execution_available`) `false`, a deterministic canonical payload, and a deterministic catalog identity. The maintained source catalog validates successfully.

`capability_binding_available` is the one availability field a declaration may assert, because the read-only PR322 in-memory capability-binding operation exists. Asserting it states only that the operation exists; PR321 still performs no binding and reports `capability_bound=false` on every result.

## Explicit inputs only

The evaluator accepts exactly three explicit inputs: one exact full PR319 `aca_` artifact ID, one explicit ShellForgeAI `data_dir`, and one explicit raw 64-lowercase-hex catalog-identity confirmation.

It accepts no inventory result, no selected inventory entry, no `latest`, `current`, or "most recent" reference, no caller-supplied supported-ID collection, no caller-supplied declaration, catalog, contract, approval, or artifact object, no capability alias, no recipe ID, no PR313 plan, no preflight, no receipt, and no execution confirmation.

## The catalog-identity confirmation

`confirm_capability_catalog_identity_sha256` must be exactly 64 lowercase hexadecimal characters, must equal the freshly computed maintained catalog identity, and is compared with `hmac.compare_digest` **before any filesystem access**. A malformed or mismatched confirmation performs zero filesystem access, loads no artifact, evaluates no capability, and returns a structured fail-closed result.

The confirmation means exactly one thing:

> Evaluate against this exact maintained declaration catalog.

It is not approval confirmation, authorization, capability binding, preflight confirmation, or execution confirmation.

## Evaluation sequence

1. Obtain the maintained source catalog.
2. Validate the maintained catalog.
3. Compute its canonical identity.
4. Validate the explicit catalog-identity confirmation.
5. Require an exact confirmation match.
6. Call the maintained PR319 exact-ID loader with the explicit artifact ID and data root.
7. Require `persisted_approval_artifact_loaded`, a non-null artifact, valid artifact validation, a valid PR309 approval binding, and exact source-bundle provenance.
8. Extract the exact `ApprovedChangeContract` only from the loaded PR319 artifact.
9. Derive the exact supported-capability tuple from the maintained catalog declarations.
10. Call `validate_approved_change_contract(contract, supported_capability_ids)`.
11. Require the validator's approval-binding result to remain valid.
12. Classify: supported on `contract_valid`, unsupported on `unsupported_capability`, validation failure otherwise.
13. Return one immutable structured result.

No gate is continued past. For the maintained catalog, step 9 always produces exactly `("windows.runtime_reconcile",)`.

## Exact-capability-ID-only matching

Support is decided only by exact, case-sensitive equality of the subject's validated `capability_id`. There are no prefixes, suffixes, namespaces, aliases, case folding, fuzzy matching, wildcard matching, caller-supplied regexes, recipe-ID mapping, target inference, or procedure inference. Unknown capability IDs remain unsupported, and so do syntactically valid near misses such as `windows.runtime_reconcile.v2`, `windows.runtime-reconcile`, `windows.runtime_reconcile_preview`, and `example.windows.runtime_reconcile`.

Because matching is capability-ID-only, two entirely different approved subjects — different target, procedure, evidence, risk, and rollback posture — that share the exact declared `capability_id` are **both** declared supported at this stage. That is the correct behaviour for PR321 and is precisely why declared support is not binding.

## Supported semantics

```
status=capability_support_confirmed
evaluation_complete=true
capability_support_evaluated=true
capability_supported=true
declaration_found=true
capability_bound=false
authorization_evaluated=false
preflight_evaluated=false
receipt_created=false
receipt_linked=false
execution_allowed=false
execution_available=false
execution_status=not_executed
```

A supported result means only that the approved subject's exact `capability_id` is declared in the exact confirmed catalog and that PR309 returned `contract_valid` against exactly that catalog's capability IDs.

## Unsupported semantics

An unknown exact capability ID is a **completed fail-closed evaluation**, not an exception:

```
status=capability_not_declared
evaluation_complete=true
capability_support_evaluated=true
capability_supported=false
declaration_found=false
capability_bound=false
execution_allowed=false
```

The approved contract may still have valid structure, a valid subject identity, and a valid approval binding. It remains unsupported because its exact capability ID is absent from the maintained catalog.

## Input or load failure

```
evaluation_complete=false
capability_support_evaluated=false
capability_supported=false
capability_bound=false
execution_allowed=false
```

## Structured results

Evaluation statuses:

- `capability_support_confirmed`
- `capability_not_declared`
- `capability_support_evaluation_blocked`
- `invalid_capability_support_input`
- `capability_catalog_confirmation_mismatch`
- `approval_artifact_not_available`
- `approval_artifact_invalid`
- `capability_contract_validation_failed`

Every result is frozen, forbids extra fields, holds immutable deterministic sorted and deduplicated errors, and reports the maintained PR319 loader's fixed status and fixed reason sentence only. The loader's own `errors` are never propagated, because they may interpolate host absolute paths; PR321 emits only its own deterministic, path-free sentences. No traceback is ever reported, and no partial declaration survives a failed evaluation.

## Accurate safety ledgers

### Catalog build, canonicalization, identity, and validation

```
read_only=true
mutation_performed=false
filesystem_accessed=false
artifact_write_performed=false
publication_performed=false
persistence_performed=false
capability_support_evaluated=false
capability_supported=false
capability_bound=false
authorization_evaluated=false
preflight_evaluated=false
receipt_created=false
receipt_linked=false
host_configuration_mutation_performed=false
execution_allowed=false
execution_available=false
execution_status=not_executed
```

### Successful or unsupported evaluation

```
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
capability_supported=<true or false>
capability_bound=false
authorization_evaluated=false
preflight_evaluated=false
receipt_created=false
receipt_linked=false
host_configuration_mutation_performed=false
execution_allowed=false
execution_available=false
execution_status=not_executed
```

### Invalid or mismatched catalog confirmation, before filesystem access

```
read_only=true
mutation_performed=false
filesystem_accessed=false
capability_support_evaluated=false
capability_supported=false
capability_bound=false
execution_allowed=false
```

## Permanent warnings

Every result states that:

- declared capability support is **approved-change contract validation only**;
- support is decided only by **exact case-sensitive `capability_id` equality**;
- capability support is **not capability binding**;
- capability support is **not authorization**;
- capability support does not validate target compatibility;
- capability support does not validate procedure compatibility;
- capability support does not evaluate current state;
- capability support does not run a preflight;
- capability support does not create or link a receipt;
- capability support grants **no execution eligibility**;
- `windows.runtime_reconcile` is **not bound to the PR313 lane** by this declaration;
- an exact `aca_` approval-artifact ID remains required;
- no approval was selected through inventory;
- persisted `approved_by` remains **self-asserted** metadata, not authenticated identity;
- reviewer provenance is not approval;
- no CLI or natural-language capability-support or execution route exists.

## Static boundary

The catalog and canonicalization logic is pure. The evaluator reaches the filesystem only indirectly, through the maintained PR319 exact-ID loader.

The production module imports exactly `__future__`, `hashlib`, `hmac`, `json`, `pathlib`, `typing`, `pydantic`, and the two maintained ShellForgeAI modules it depends on — `approved_change_contract` and `approved_change_approval_persistence`. It imports or calls no recipe registry, no PR313 execution, preflight, receipt, or verification module, no PR304 or PR305 module, no approval inventory, no legacy approvals module, no shell or subprocess, no PowerShell, no network or socket API, no Docker or Compose call, no model or provider, no credential access, no environment identity, no OS user or hostname, no clock, no randomness or UUID, and no filesystem write primitive. It never calls the PR319 publisher, the PR317 publisher, an executor, a preflight, a receipt writer, or inventory selection, and it registers no CLI command.

## Explicit non-goals

PR321 adds no capability binding, binding identity, adapter binding, executor binding, PR313 integration, PR304 or PR305 validation, Windows path evaluation, `System32` evaluation, target compatibility, procedure compatibility, precondition evaluation, current-state revalidation, evidence-freshness check, authenticated identity, identity-provider integration, role validation, authorization, preflight, receipt creation or linkage, execution eligibility, execution, dynamic capability discovery, plugin loading, recipe-registry-derived support, caller-supplied support set, catalog persistence, catalog loading from disk, catalog publication, catalog inventory, approval selection, `latest`/`current`/"most recent" resolution, CLI command, interactive route, natural-language approval or capability evaluation, legacy `Proposal` conversion, filesystem write, host configuration change, service or registry change, Docker or Compose call, PowerShell/WinRM/QGA call, shell or subprocess, network call, model or provider call, credential access, current-time lookup, or randomness/UUID.

There is no new persisted subtree and no new persisted file, so the data layout is unchanged. There is no CLI surface, so the command reference is unchanged.

## Next dependency

Stage B remains incomplete. PR322 added the exact read-only in-memory capability binding in [Approved Change Capability Binding](APPROVED_CHANGE_CAPABILITY_BINDING.md). The next focused dependency is **current-state execution preflight and exact approved-subject to live-PR313-plan comparison — still not execution**.

Everything else stays deferred to PR323 or later: persisted binding artifacts, target and procedure compatibility evaluation, PR304/PR305 evidence compatibility, current-state execution preflight, subject/live-plan comparison, authenticated identity, role validation, identity-provider integration, authorization, receipt creation and linkage, execution eligibility, Stage C execution, capability catalog persistence, dynamic capability discovery, plugin capability registration, multiple supported mutation capabilities, Docker mutation capability support, filtered approval search, automatic approval selection, `latest` or `current` resolution, and CLI or natural-language approval, capability, or execution routes.
