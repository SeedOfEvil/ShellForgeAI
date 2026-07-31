# Roadmap

## Shared platform-aware operator contract

- The shared immutable platform contract now centralizes local platform
  classification reuse, support-lane identity, high-level route family, generic
  presentation vocabulary, and deterministic unsupported fallback for ask and
  interactive evidence paths. It adds no intent, collector, command, provider,
  model, or execution behavior.
- PR330 is the separate command-suggestion validation seam. PR331 is the
  separate bounded evidence-first timing/progressive-response seam. PR332 is
  the separate short golden-path and advanced-help seam.

The approved-change work now includes point-in-time live current-state
revalidation for one exact PR323-linked Windows runtime-reconcile plan. It does
not execute, and Stage B remains incomplete. Future gates still include PR304
evidence freshness, authenticated identity, authorization, receipt linkage, a
future execution preflight, and separately justified persistence of link or
current-state artifacts.

## OS-aware model-context vocabulary

- The Windows evidence-backed model path has a dedicated Windows-native identity, capability map, bounded evidence projection, precise Linux-primary answer gate, and deterministic Windows evidence fallback.
- Linux/default prompts and the Linux-primary V1 contract remain unchanged. No provider or model-selection modernization occurs here.
- Model-selection modernization may be considered only after separate review. Stage B linked-plan current-state revalidation remains a separate future dependency.

ShellForgeAI's active roadmap is forward-looking. The permanent final-state product contract is defined in [North Star](north-star.md). Historical PR-by-PR engineering chronology has moved to [Project history archive](archive/PROJECT_HISTORY.md).

## Current product

- V1 released; early beta-quality; guarded and not production-autonomous.
- Linux/Docker is the primary supported V1 lane and release-validation basis.
- Windows is preview/early support for local read-only evidence, deterministic operator guidance, and validated Windows Server 2025 workflows.
- Current capabilities include evidence collection, deterministic triage, reports, previews, approval metadata, verification, receipts, and narrow governed proof/testing lanes.
- The maintained PR143 command surface audit remains the active command-surface classification reference for current interface hygiene.
- PR157 remains the validation lane optimizer reference for Lane A/B/C planning.
- The archive source action runbook remains documented in [Archive Source Action Runbook](ARCHIVE_SOURCE_ACTION_RUNBOOK.md); it is non-executable and adds no execution command.
- Windows/PowerShell V1 remains planned as read-only local evidence / Windows read-only doctor prototype support; Linux/Docker remains primary and the safety model remains unchanged.
- The complete final-state lifecycle is not yet implemented across arbitrary operator-developed solutions.

## Windows operator UX — interactive identity (PR324)

- PR324 corrects platform-aware interactive identity only: the startup banner subtitle now reports the local host as Linux, Windows, or macOS from Python's read-only `platform.system()` value, with the safe generic `CLI-first AI Ops for this host` fallback for an empty or unrecognized platform, and the banner quote pool is platform-neutral on non-Linux hosts.
- PR324 changes nothing else: interactive intent classification and route selection, evidence collectors and evidence vocabulary, model context, model prompts, model selection, mutation refusal, trust, workspace, and the CLI command surface all remain unchanged, and no probing, shell, subprocess, PowerShell, WinRM, network call, or persistence was added.
- The Linux-primary V1 product contract is unchanged; PR324 corrects banner presentation only and does not promote Windows beyond preview/early support.
- The next focused Windows UX dependency is Windows-native interactive service routing; Windows-specific service evidence collection, suppression of generic Linux collectors, and OS-aware model-context vocabulary remain deferred beyond it.

## Windows operator UX — interactive service evidence

- The native-Windows `windows_services` interactive route connects directly to the existing bounded local read-only services payload and maintained text renderer. It makes one in-process call with a 25-record limit; no new collector, CLI execution, subprocess, shell, model synthesis, named-service lookup, or service control was added.
- Deterministic output reports payload status, total/state counts, runtime summary, bounded runtime-signal preview, truncation, interpretation limits, and services-first safe-next commands. Point-in-time runtime signals are not health diagnoses, stopped services can be normal, and configuration/recovery policy is not collected.
- Successful collections update only bounded Windows-local latest-context facts; the full service list is neither retained nor persisted. Error and unsupported payloads fail closed without generic or model fallback. Explicit Windows service questions on non-Windows hosts remain guidance-only, and mutation refusal retains priority.
- Top-level `ask`, model context/prompts/vocabulary, model selection, the CLI surface, persistence, authorization, receipts, execution, and the Linux-primary V1 contract are unchanged.
- The next focused Windows UX dependency is OS-aware model-context vocabulary under the narrower live roadmap. Stage B live linked-plan current-state revalidation remains a separate future dependency and is untouched.

## Stage A — Product contract

- Establish the canonical lifecycle and final-state implementation boundary in [North Star](north-star.md).
- Keep document ownership clear: Product Status owns current maturity, V1 Scope owns the released V1 contract, Safety owns current safety and mutation rules, and this Roadmap owns staged delivery.
- Add a documentation drift guard without changing runtime behavior.

## Stage B — Approved-change contract: in progress

- PR309 provides an immutable approval subject, deterministic subject identity, exact attestation binding, and inert structural/capability validation.
- PR310 establishes the strict legacy compatibility decision: automatic conversion from legacy Proposal schema v1 is prohibited, approval is not portable, and separately reviewed context is required for any future conversion.
- PR311 establishes a fail-closed field-source policy for future approved-change subject construction: only five legacy fields may be displayed as explicitly reviewed direct candidates, while all other destination values require explicit reviewed context or review-context-only display.
- PR314 defines the immutable reviewed supplemental-context contract in [Approved Change Supplemental Context](APPROVED_CHANGE_SUPPLEMENTAL_CONTEXT.md): 12 typed explicit-context reviews plus five typed candidate reviews with explicit accept/reject decisions, per-field review provenance, candidate SHA-256 identity, and a separate supplemental-context SHA-256 that is never a subject, approval, or fingerprint identity.
- PR314 still performs no subject construction, persistence, approval, binding, preflight, receipt linkage, or execution; it validates reviewed input coverage only.
- PR315 adds explicit reviewed subject construction in [Approved Change Subject Construction](APPROVED_CHANGE_SUBJECT_CONSTRUCTION.md): one pure, deterministic, fail-closed in-memory operation that consumes a validated PR314 supplemental context plus an explicit expected supplemental-context SHA-256, and freshly revalidates the canonical PR311 policy at construction time.
- PR315 produces one PR309 `ApprovedChangeSubject` plus immutable field-by-field construction evidence only, under an exact 1 contract constant + 12 explicit-context + 5 candidate-final authority map, with three permanently distinct identities: supplemental-context, subject, and construction-evidence SHA-256.
- PR315 adds no approval, contract, persistence, capability registry, capability binding, capability-support decision, preflight, receipt linkage, CLI surface, or execution; a constructed subject is unapproved and non-executable, and reviewer provenance never becomes approval.
- PR316 defines the deterministic reviewed-change artifact-bundle contract in [Approved Change Artifact Bundle](APPROVED_CHANGE_ARTIFACT_BUNDLE.md): one pure, immutable, checksum-protected, in-memory bundle of exactly four canonical UTF-8 JSON logical files — `supplemental-context.json`, `approved-change-subject.json`, `construction-evidence.json`, and `manifest.json` — under a fixed literal filename allowlist and fixed order.
- PR316 binds the reviewed context, the freshly reconstructed subject, the construction evidence, and the manifest into one identity chain, and adds a fourth permanently distinct identity: a non-circular bundle identity SHA-256 that excludes itself and the derived full-hash `acb_` bundle ID.
- PR316 performs no filesystem persistence: it defines the persistence payload and fixed future publication, atomicity, overwrite, existing-identical, and destination policies as contract metadata only, and creates no file or directory.
- PR316 adds no approval, contract, capability registry, capability binding, capability-support decision, preflight, receipt linkage, CLI surface, writer, loader, or execution; a valid bundle is unapproved and non-executable.
- PR317 adds the governed atomic publisher and read-only loader in [Approved Change Artifact Persistence](APPROVED_CHANGE_ARTIFACT_PERSISTENCE.md): the one narrow filesystem boundary that publishes a PR316 bundle beneath the fixed `<data_dir>/approved_change_artifacts/<bundle-id>/` subtree.
- PR317 persists only PR316-valid bundles: it reruns the maintained validator on the input bundle, on the prepared bytes, and on the persisted bytes, and it stores exactly the PR316 canonical bytes verbatim under the four fixed filenames.
- PR317 requires an exact `confirm_bundle_identity_sha256` match against the bundle identity, prepares and verifies every file in a private temporary sibling, publishes with one atomic no-replace directory transition (Linux `renameat2(RENAME_NOREPLACE)`, Windows `MoveFileExW` without replace), never overwrites, returns `bundle_already_present` for a valid byte-identical existing bundle, blocks on conflicting contents, and cleans up only its own unpublished temporary directory.
- PR317 adds no approval, contract, capability registry, capability binding, capability-support decision, preflight, receipt linkage, CLI surface, natural-language route, or execution; a persisted bundle is unapproved and non-executable.
- PR318 integrates explicit approval binding with one exact persisted PR317 bundle in [Approved Change Approval Workflow](APPROVED_CHANGE_APPROVAL_WORKFLOW.md): one read-only operation that loads through the maintained PR317 exact-ID loader, sources the subject only from the fixed PR316 `approved-change-subject.json` file, and recomputes subject identity only with the PR309 `compute_subject_sha256`.
- PR318 requires exact confirmations on both axes: an explicit `approve` decision literal, an exact `confirm_bundle_identity_sha256` match against the loaded bundle identity, and an exact `confirm_subject_sha256` match against the recomputed subject identity; the bundle confirmation selects the source bundle and never widens the `exact_subject_only` attestation scope.
- PR318 creates exactly one PR309 `ApprovalAttestation` and exactly one `ApprovedChangeContract` **in memory only**, verifies the exact binding with `verify_approval_binding`, and persists no approval, contract, result, or new artifact; the persisted tree stays byte- and mtime-identical.
- PR318 does not authenticate identity: `approved_by`, `approved_at`, and `reason` are explicit self-asserted metadata, never inferred from a clock, environment, OS user, hostname, credential, or PR314 reviewer provenance.
- PR318 evaluates no capability support and never calls `validate_approved_change_contract`; it adds no preflight, receipt linkage, CLI surface, natural-language route, or execution.
- PR319 adds deterministic approval-artifact persistence in [Approved Change Approval Artifact Persistence](APPROVED_CHANGE_APPROVAL_ARTIFACT_PERSISTENCE.md): it defines the canonical approval-artifact bytes — one fixed `approved-change-approval.json` holding the schema version, the artifact type, the exact PR316 source bundle ID and identity, the exact PR309 subject SHA-256, and the exact PR318 contract — serialized only through the maintained PR309 canonicalizers.
- PR319 derives a distinct non-circular approval-artifact identity SHA-256 and the full-hash `aca_` artifact ID, permanently separate from the supplemental-context, subject, construction-evidence, and PR316 bundle identities and from any legacy Proposal fingerprint.
- PR319 persists one exact successful PR318 approval and contract under an explicit `confirm_approval_artifact_identity_sha256` match, beneath the fixed `<data_dir>/approved_change_approvals/<approval-artifact-id>/` subtree.
- PR319 publishes atomically with one no-replace directory transition (Linux `renameat2(RENAME_NOREPLACE)`, Windows `MoveFileExW` without replace) and never overwrites: an identical artifact returns `approval_artifact_already_present` with zero writes, a conflicting destination blocks and is never repaired, and cleanup is bounded to the invocation's own unpublished temporary directory.
- PR319 provides one exact-ID read-only loader that revalidates the canonical bytes, the artifact identity, the PR309 approval binding, and the exact PR317 source bundle including its canonical subject bytes; there is no `latest`, `current`, or discovery beyond one exact `aca_` ID.
- PR319 does not authenticate identity: persisted `approved_by` remains self-asserted metadata, and reviewer provenance never becomes the approver.
- PR319 adds no approval revocation, cancellation, expiration, supersession, mutable approval state, capability support, capability binding, preflight, receipt creation or linkage, CLI surface, natural-language route, or execution; persistence is not authorization.
- PR320 adds one bounded read-only inventory over the fixed PR319 approval-artifact root in [Approved Change Approval Inventory](APPROVED_CHANGE_APPROVAL_INVENTORY.md): one operation that takes only an explicit `data_dir`, derives the fixed `<data_dir>/approved_change_approvals` root, and enumerates its direct children once.
- PR320 enumerates direct children only: it never recurses, never walks grandchildren, never uses a recursive glob, never follows a symlink or reparse point, and enforces a fixed maintained bound of 1024 direct children that fails closed rather than returning a partial or silently truncated inventory.
- PR320 treats only exact `aca_` plus 64-lowercase-hex names as candidates and validates each one **only** through the maintained PR319 exact-ID loader; it adds no artifact parser, no alternate loader, no identity recomputation, and no independent binding check.
- PR320 returns immutable summaries sorted lexicographically by exact artifact ID and by nothing else — never by filesystem mtime, approval time, actor, source bundle, or subject — and reports every unexpected, unsafe, missing, or invalid direct child as an explicit anomaly, so an incomplete inventory is `inventory_complete=false` rather than silently skipped.
- PR320 never creates an index, pointer, cache, or preferred approval, adds no `latest`, `current`, or "most recent" resolution, selects no approval, and performs no filesystem write, repair, rename, quarantine, or deletion; an exact `aca_` ID remains required for loading the complete artifact.
- PR320 adds no authenticated identity, capability registry, capability-support evaluation, capability binding, preflight, receipt creation or linkage, CLI surface, natural-language route, or execution; inventory is discovery, not authorization.
- PR321 defines one typed, immutable, canonical, product-maintained capability-support declaration catalog in [Approved Change Capability Support](APPROVED_CHANGE_CAPABILITY_SUPPORT.md), with a deterministic SHA-256 identity computed only from its own canonical UTF-8 bytes.
- PR321 declares exactly one currently recognized approved-change capability, `windows.runtime_reconcile`, with `support_status=declared_supported`, `match_rule=exact_capability_id_only`, `validation_scope=approved_change_contract_validation_only`, and every binding, authorization, preflight, receipt-linkage, and execution availability field `false`.
- The PR321 declaration is **contract-validation-only**: it means the approved subject's exact `capability_id` appears in the exact confirmed maintained catalog, and nothing more.
- PR321 evaluation requires an explicit raw 64-lowercase-hex catalog-identity confirmation, compared with `hmac.compare_digest` before any filesystem access; a malformed or mismatched confirmation loads nothing and touches nothing.
- PR321 evaluation loads exactly one persisted PR319 approval artifact through the maintained exact-ID loader, requiring a valid artifact, a valid PR309 approval binding, and exact PR317 source-bundle provenance.
- PR321 calls the maintained PR309 `validate_approved_change_contract` for the support decision, passing exactly the maintained catalog's capability IDs; it defines no competing validator and accepts no caller-supplied supported-capability collection.
- Unknown capability IDs fail closed as a completed unsupported evaluation — `capability_not_declared`, `capability_supported=false`, no declaration — rather than raising; support is exact, case-sensitive `capability_id` equality only, with no prefix, suffix, alias, case folding, fuzzy, or wildcard matching.
- PR321 adds no capability binding: two entirely different approved subjects sharing the exact declared capability ID are both declared supported, and every result reports `capability_bound=false`.
- PR321 does not connect the declaration to PR313: it imports no PR313 execution, preflight, receipt, or verification module, validates no PR304 or PR305 artifact, evaluates no target path, and derives no support from `recipe_registry`.
- PR321 selects no approval: it calls no PR320 inventory operation and resolves no `latest`, `current`, or "most recent" approval; one exact `aca_` artifact ID remains required.
- PR321 adds no authenticated identity, authorization, preflight, receipt creation or linkage, catalog persistence, dynamic capability discovery, plugin registration, CLI surface, natural-language route, or execution; the catalog stays in memory and source-maintained, and nothing is written.
- PR322 creates the exact read-only in-memory capability binding in [Approved Change Capability Binding](APPROVED_CHANGE_CAPABILITY_BINDING.md): one immutable, source-maintained lane declaration for the named PR313 governed Windows two-file runtime-reconciliation lane — `capability_id=windows.runtime_reconcile`, `lane_id=pr313.windows_runtime_reconcile`, `lane_kind=named_governed_implementation_lane`, `binding_status=declared_bindable`, `binding_scope=exact_approved_subject_to_exact_named_lane_declaration_only`, `implementation_scope=windows_exact_two_file_runtime_reconciliation_only`, and every binding-persistence, authorization, preflight, receipt-linkage, and execution availability field `false`.
- PR322 binds one exact PR319 `aca_` approval artifact to that one exact source-maintained lane declaration, under two explicit raw 64-lowercase-hex confirmations — the PR321 catalog identity and the lane-declaration identity — both compared with `hmac.compare_digest` before any filesystem access.
- PR322 confirms support only through the maintained PR321 evaluator and never replaces that decision with its own membership check; it reaches persisted approvals only through the maintained PR319 exact-ID loader, and any disagreement between the two maintained reads fails closed.
- The PR322 binding has a deterministic non-circular identity — the SHA-256 of its own canonical payload naming the exact artifact ID and identity, subject SHA-256, catalog identity, capability ID, lane identity, lane ID, and both scopes — permanently distinct from the subject, bundle, approval-artifact, catalog, and lane identities and from any PR313 plan hash or receipt identity.
- PR322 flips exactly one maintained PR321 field, `capability_binding_available=false → true`, intentionally changing the catalog canonical bytes (465 → 464) and identity; authorization, preflight, receipt-linkage, and execution availability all stay `false`, and the catalog still declares exactly `windows.runtime_reconcile`.
- `capability_bound=true` means only that one exact approved subject identity has been associated with one exact immutable named-lane declaration in memory; it never means the lane can run.
- PR322 has no binding persistence: there is no persisted binding artifact, binding ID, prefix, publisher, or loader, and the persisted tree stays byte- and mtime-identical.
- PR322 invokes no PR313 runtime: it imports no PR313 execution, preflight, receipt, or verification module, constructs no PR313 plan, validates no PR304 or PR305 evidence, inspects no staged source, durable runtime root, or `System32` location, and derives the lane declaration from no registry, module, script, filesystem, environment, or plugin.
- PR322 evaluates no target, procedure, or current-state compatibility: two materially different approved subjects sharing the declared capability ID both bind, with distinct binding identities, and every result warns that compatibility was not evaluated.
- PR322 adds no preflight, receipt creation or linkage, authorization, authenticated identity, approval selection, `latest`/`current` resolution, CLI surface, natural-language route, or execution.
- PR323 links one exact PR322 binding to one exact validated saved PR305 plan in [Approved Change Plan Link](APPROVED_CHANGE_PLAN_LINK.md): one explicitly supplied parsed plan mapping, one exact `aca_` artifact ID, one explicit data root, and three explicit raw 64-lowercase-hex confirmations — the PR321 catalog identity, the PR322 lane-declaration identity, and the canonical plan SHA-256 — all compared with `hmac.compare_digest` before any filesystem access.
- The PR323 link identity binds the exact binding identity and the exact canonical plan SHA-256: it is the SHA-256 of its own canonical payload naming the exact artifact ID and identity, subject SHA-256, binding identity, catalog identity, capability ID, lane identity, lane ID, plan mode, plan recipe ID, plan SHA-256, plan status, destination-parent contract version, and comparison scope — permanently distinct from every upstream identity and from the plan SHA itself.
- PR323 validates plan structure only through maintained PR305/PR313 authority, extracted verbatim into the pure `core/windows_runtime_reconcile_plan_contract.py` seam that the PR305 acceptance script and the PR313 execution module both now delegate to; the extraction is delegation-only and changes no PR313 behaviour.
- PR323 accepts exactly the plan statuses `ready` and `no_change`; `blocked`, `unsupported`, malformed, wrong-mode, wrong-recipe, reordered/widened-allowlist, extra-operation, wrong-parent-contract-version, invalid-hash, and unsafe-safety packets are all refused with no link.
- `plan_linked=true` means only that the exact approved binding identity has been associated with the exact canonical identity of one maintained-validator-approved saved Windows reconcile plan; it never means the plan is currently safe to run.
- PR323 persists nothing and returns no plan packet and no host path: there is no persisted plan-link artifact, ID, prefix, publisher, or loader; the persisted tree stays byte- and mtime-identical; and no staged-source root, durable-runtime root, source path, destination path, or backup pattern ever reaches a result.
- PR323 interprets no target or procedure semantics: two materially different approved subjects sharing the declared capability ID may both be structurally linked to the same valid plan, with distinct link identities, and every result reports `subject_semantic_compatibility_evaluated=false`, `target_compatibility_evaluated=false`, `procedure_compatibility_evaluated=false`, and `evidence_compatibility_evaluated=false`.
- PR323 inspects no live current state: it never reads the staged source, the durable runtime, or `System32`, never revalidates PR313 current state, and reports `current_state_preflight_evaluated=false` on every result.
- PR323 adds no authorization, preflight, receipt creation or linkage, authenticated identity, approval selection, `latest`/`current` resolution, CLI surface, natural-language route, or execution, and PR313 execution is never invoked.
- The PR309/PR310/PR311/PR314/PR315/PR316/PR317/PR318/PR319/PR320/PR321/PR322/PR323 foundation has no runtime integration, adapter, CLI route, dynamic registry, receipt linkage, preflight hook, or executor.
- Stage B remains incomplete. The next focused Stage B dependency is live current-state revalidation of the exact linked plan — explicitly not execution.
- Future Stage B work remains explicit beyond that: staged-source and durable-runtime rechecks, destination-parent current-state checks, PR304 evidence freshness, persisted binding and plan-link artifacts, authenticated identity, authorization, and receipt linkage.

Stage B is not complete. The PR309/PR310/PR311/PR314/PR315/PR316/PR317/PR318/PR319/PR320/PR321/PR322/PR323 foundation defines inert contract, compatibility-assessment, construction-policy, reviewed-input, in-memory construction, in-memory artifact-bundle, canonical approval-artifact, capability-support-declaration, capability-binding, and plan-link modules, one pure saved-plan contract seam, two governed persistence boundaries, one read-only in-memory approval-binding operation, one bounded read-only approval-artifact inventory, one read-only capability-support evaluator, one read-only in-memory capability-binding operation, and one read-only in-memory plan-link operation only; beyond publishing, reloading, approving, durably recording, naming the governed lane for, and naming the exact validated plan for the PR316 bundle payload it does not design schemas for commands, receipts, executors, adapters, or a mutation engine, and it implements none of them.

## Named Windows two-file governed implementation lane (PR313)

- PR313 establishes exactly one named, local, governed Windows implementation lane: `windows.runtime_reconcile`, limited to `config/profiles/inspect.yaml -> config/profiles/inspect.yaml` and `scripts/windows/sfai.cmd -> bin/sfai.cmd`.
- It consumes and revalidates the PR304 runtime-integrity and PR305 preview contracts, requires an exact canonical plan-hash confirmation, prepares everything before committing, uses verified backups and atomic replacement, writes an auditable receipt, and offers read-only post-change verification.
- It does not complete general Stage B or Stage C: it adds no approval workflow integration, no PR309 approved-change construction, no approval portability, no capability registry or generic capability binding, and no generic execution preflight or receipt linkage.
- Its exact destination-parent contract lets a confirmed create reach only the `config` and `config/profiles` components beneath an already-existing durable runtime root; `bin` and the root itself are never created, and no generic installer, bootstrap, or directory-repair lane was introduced.
- It implies no additional capabilities. Future expansion stays capability by capability, each with typed inputs, scope limits, gates, verification, reporting, receipts, and tests.
- Linux/Docker remains the primary V1 lane and release-validation basis; Windows remains preview/early support, and this lane is a narrow local file-integrity repair capability rather than production autonomy.

## Future Stage C — First narrow end-to-end implementation lane

- Choose one deliberately narrow supported solution type.
- Prove Understand through Report for that solution type.
- Require explicit approval, bounded implementation, fresh verification evidence, and a receipt.
- Avoid generic mutation machinery and avoid selecting additional solution types by implication.

## Future Stage D — Controlled capability expansion

- Add supported implementation capabilities solution type by solution type.
- Require typed inputs, scope limits, gates, verification, reporting, receipts, and tests for each capability.
- Keep arbitrary shell, natural-language execution, and broad infrastructure orchestration out of scope.
- Preserve ShellForgeAI as a focused operator product rather than a general infrastructure platform.

## Final state

ShellForgeAI remains one CLI-first operator interface with the complete lifecycle: Understand → Investigate → Diagnose → Propose → Obtain approval → Implement → Verify → Report. It can implement approved bounded changes through supported capabilities, verify outcomes with fresh evidence, and report facts, receipts, and remaining risk without becoming a dashboard, control plane, generic shell, or broad orchestration platform.
