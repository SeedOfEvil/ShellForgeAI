# Data layout

ShellForgeAI writes all artifacts under a single configurable data directory
(`<data_dir>`, default `~/.shellforgeai/data` on the host or `/data` in a
container deployment). Everything ShellForgeAI mutates lives there. Paths
outside `<data_dir>` are never written or deleted by the runtime.

## Top-level layout

```
<data_dir>/
  artifacts/<session-id>/         evidence/runbook/summary per session
  approvals/{pending,approved,rejected,canceled,archived}/<id>.proposal.json
  apply_bundles/<proposal-id>/    apply-preview, operator scripts, preflight
  actions/<proposal-id>/          compiled review-only action records
  rollback_previews/<id>/         rollback / recovery previews
  missions/restart/<mission-id>/  exact-container restart missions
  missions/compose-restart/<…>/   Compose service restart missions
  mission_reports/<mission-id>/   closure reports
  mission_exports/<mission-id>/   portable mission export packs
  execution_receipts/<exec-id>(.json|.md|/)
                                  apply/mission execute receipts + inspect
                                  evidence (before/after)
  exports/<export_id>/            audit export packs + manifest + checksums
  guards/<source-id>/             stale/drift guard reports
  prune_receipts/<…>.json|.md     PR46 metadata prune receipts
  cleanup_plans/<plan-id>/        PR55/71 cleanup plans (dry-run only)
  cleanup_archives/<plan-id>/     PR55/71 archives (required before execute)
  cleanup_receipts/<…>            PR55/71 cleanup execute receipts
  policy/lab-container-restart-allowlist.json
                                  lab restart allowlist (disabled by default)
  audit/events.jsonl              append-only audit timeline
  audit/incident-index.json       PR40 incident index
  approved_change_artifacts/<bundle-id>/
                                  PR317 published reviewed-change artifact
                                  bundles (exactly four PR316 files each)
  approved_change_approvals/<approval-artifact-id>/
                                  PR319 published approval artifacts
                                  (exactly one canonical file each)
```

## Reviewed-change artifact bundles (PR317)

```
<data_dir>/approved_change_artifacts/acb_<64 lowercase hex>/
  supplemental-context.json
  approved-change-subject.json
  construction-evidence.json
  manifest.json
```

- The subtree name `approved_change_artifacts` and the four filenames are fixed literals. There is no caller override, alias, or configurable variant.
- The final directory name is exactly the PR316 `bundle_id` (`acb_` plus the full 64-character bundle identity SHA-256).
- Each published directory contains exactly those four files and nothing else: no completion marker, lock file, checksum sidecar, Markdown rendering, receipt, timestamp file, or metadata file.
- Stored bytes are exactly the PR316 canonical UTF-8 bytes — no BOM, no CRLF, no trailing newline, no reserialization.
- **No overwrite exists.** Publishing an already-published identical bundle returns `bundle_already_present` and writes nothing; a conflicting or invalid existing directory blocks and is never repaired, replaced, quarantined, renamed, deleted, merged, or written around.
- Loading requires one **explicit full bundle ID**. There is no `latest`, `current`, "most recent", prefix, glob, or path reference, and the loader enforces per-file (1 MiB) and per-bundle (4 MiB) read bounds.
- Publication requires an explicit `confirm_bundle_identity_sha256` match. **Persistence is not approval and not execution:** a published bundle is unapproved, unbound, and non-executable, and PR317 creates no approval, contract, or receipt and evaluates no capability.
- PR317 never deletes a published bundle. Retention, cleanup, and deletion of these bundles remain deferred.

See [Approved Change Artifact Persistence](APPROVED_CHANGE_ARTIFACT_PERSISTENCE.md) for the full contract.

## Approval artifacts (PR319)

```
<data_dir>/approved_change_approvals/aca_<64 lowercase hex>/
  approved-change-approval.json
```

- The subtree name `approved_change_approvals` and the filename `approved-change-approval.json` are fixed literals. There is no caller override, alias, or configurable variant.
- The final directory name is exactly the PR319 `approval_artifact_id` (`aca_` plus the full 64-character approval-artifact identity SHA-256, the SHA-256 of the exact canonical file bytes). It is never the `acb_` bundle ID, the subject SHA-256, or a legacy Proposal fingerprint.
- Each published directory contains exactly that one file and nothing else: no second file, sidecar, completion marker, lock file, mutable status file, pointer file, symlink, `latest` entry, Markdown rendering, receipt, or metadata file.
- Stored bytes are the canonical UTF-8 approval bytes — no BOM, no CRLF, no trailing newline, no reserialization, no redaction.
- The artifact records **one immutable approval event**, not mutable approval state. There is no status field, revocation, cancellation, expiration, supersession, quorum, or approval-state transition.
- **No overwrite exists.** Republishing an identical artifact returns `approval_artifact_already_present` and writes nothing; a conflicting or invalid existing directory blocks and is never repaired, replaced, quarantined, renamed, deleted, merged, or written around.
- Loading requires one **explicit full `aca_` artifact ID**. There is no `latest`, `current`, "most recent", prefix, glob, path, or listing reference, and the loader enforces a 1 MiB read bound and revalidates the PR309 approval binding plus the exact PR317 source bundle from the same `<data_dir>`.
- Publication requires an explicit `confirm_approval_artifact_identity_sha256` match. **Persistence is not approval and not authorization:** the approval was created by PR318, and a persisted artifact is unbound to any capability and non-executable. PR319 evaluates no capability, runs no preflight, and creates or links no receipt.
- PR319 never deletes a published approval artifact and never writes to the PR317 bundle subtree. Retention, cleanup, and deletion of approval artifacts are **unsupported** and remain deferred.

See [Approved Change Approval Artifact Persistence](APPROVED_CHANGE_APPROVAL_ARTIFACT_PERSISTENCE.md) for the full contract.

Names may vary slightly across versions; treat the table below as the
canonical lifecycle. Code under `src/shellforgeai/core/` is the source of
truth for exact paths.

## Artifact lifecycle

| Artifact type            | Created by                                    | Read by                                              | Mutation? | Notes                                                                                       |
| ------------------------ | --------------------------------------------- | ---------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------- |
| Evidence bundle          | `diagnose`, ops-shaped `ask`                  | `runbook`, `approvals`, `mission`, `export`, ask     | None      | Read-only; basis of everything downstream.                                                  |
| Runbook                  | `runbook`, `diagnose --with-runbook`          | `approvals create`, `validate-runbook`, `export`     | None      | Labelled operator-run steps; never executed.                                                |
| Proposal                 | `approvals create|propose-restart`, `compose propose-restart` | `approvals show|validate`, `apply`, `mission`, `guard` | None | Paper trail with fingerprint; `execution.allowed=false`.                                    |
| Compiled actions         | `actions compile`, `apply`                    | `actions show|validate`                              | None      | Deterministic classification; mutation steps `blocked`.                                     |
| Apply bundle             | `apply <approved-proposal>`                   | operator review only                                 | None      | Scripts include `exit 2` guard; static files only.                                          |
| Rollback / recovery preview | `rollback preview`                         | `mission`, `rollback validate`                       | None      | Compose lane: `automatic_rollback=false`, `rollback_command_generated=false`.               |
| Mission record           | `mission … prepare`                           | `mission … status|checklist|validate|execute|report` | None      | Refreshed from artifacts; preserves terminal executed/refused state.                        |
| Execution receipt        | `apply --execute --confirm`, mission execute handoff | `mission report`, audit, ask verification queries | **Yes**¹  | The one mutation receipt. Includes before/after inspect evidence and verification block.    |
| Mission report           | `mission … report`                            | operator review, `mission … export`                  | None      | Read-only synthesis from existing artifacts.                                                |
| Export pack              | `export`, `mission … export`                  | `validate-export`, `mission … validate-export`       | None      | Copies files + manifest + `checksums.sha256`; optional redaction.                           |
| Guard report             | `guard check…`                                | `apply`, `mission`, ops review                       | None      | Decides fresh / warning / stale / drift / blocked.                                          |
| Prune receipt (PR46)     | `audit prune --execute --confirm`             | audit, ops review                                    | **Yes**²  | Deletes ShellForgeAI-owned metadata only.                                                   |
| Cleanup plan             | `audit cleanup plan`                          | `audit cleanup archive|validate|execute`             | None      | Always dry-run; carries a deterministic plan fingerprint.                                   |
| Cleanup archive          | `audit cleanup archive <plan-id>`             | `audit cleanup validate|execute`                     | None      | Required before `execute`; fingerprint must match plan.                                     |
| Cleanup receipt          | `audit cleanup execute … --confirm`           | `audit cleanup validate|report`                      | **Yes**²  | PR71-hardened: matching archive + fingerprint + `--confirm` required.                       |
| Audit events             | every command                                 | `audit timeline|show|validate|index|search`          | Append    | `<data_dir>/audit/events.jsonl`; append-only.                                               |
| Incident index           | `audit index [--rebuild]`                     | `audit search`, ops status                           | None      | Single file; navigation only.                                                               |
| Compose context          | docker label parse                            | `compose inspect|list`, proposal/mission enrichment  | None      | Advisory metadata only; no `docker compose` invocation.                                     |

¹ Execution receipts record the one and only allowed real mutation
(`docker restart <allowlisted-container>`, or the disposable Compose
service restart when its env-contract is satisfied).

² Cleanup and prune mutations delete ShellForgeAI-owned metadata only. They
never touch Docker, packages, services, host configuration, or files
outside `<data_dir>`.

## Long-lived `/data` caveat

`<data_dir>` accumulates over time. Older proposals, missions, evidence,
exports, and execution receipts can exist for days, weeks, or months. Two
consequences:

- **Use explicit IDs for audits.** Names like “the latest proposal” shift
  silently as new artifacts are written.
- **PR59 reference resolver** disambiguates implicit references
  (`this/latest/current/most recent proposal|mission`) deterministically,
  warns when the only candidate is stale (>24h by default), and refuses to
  guess across ambiguity. Explicit IDs always win.

Run `shellforgeai audit retention` periodically. Follow the safe sequence:

```
audit retention  →  audit cleanup plan  →  audit cleanup archive
                 →  audit cleanup validate  →  audit cleanup execute --confirm
```

Never delete `<data_dir>` paths manually unless recovering from known
corruption — the cleanup lane preserves audit invariants and writes
receipts; manual deletion does not.

## Out-of-scope paths

ShellForgeAI never writes to or deletes:

- Anything outside `<data_dir>` (and `<data_dir>/audit`).
- `/`, the protected roots (`<data_dir>`, `<data_dir>/audit`).
- Symlinks whose resolved target escapes `<data_dir>`.
- Protected categories (`approvals`, `audit-events`) — refused even with
  `--execute --confirm`.

Path safety is enforced before any delete; refusal exits non-zero with no
mutation.
