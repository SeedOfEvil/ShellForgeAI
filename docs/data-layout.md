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
```

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
