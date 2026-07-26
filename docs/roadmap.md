# Roadmap

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
- The PR309/PR310/PR311/PR314/PR315/PR316 foundation has no persistence, runtime integration, adapter, CLI route, registry, receipt linkage, preflight hook, or executor.
- The next Stage B dependency is PR317's governed non-overwriting atomic publisher and read-only loader for these bundles, and then approval workflow integration.
- Future Stage B work remains explicit beyond that: capability binding, current-state execution preflight, and receipt linkage.

Stage B is not complete. The PR309/PR310/PR311/PR314/PR315/PR316 foundation defines inert contract, compatibility-assessment, construction-policy, reviewed-input, in-memory construction, and in-memory artifact-bundle modules only; beyond the PR316 in-memory bundle payload it does not design schemas for on-disk persistence, files, commands, receipts, executors, adapters, or a mutation engine, and it implements none of them.

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
