# Audit and cleanup

ShellForgeAI keeps a tamper-evident record of everything it does, exports
that record on demand, and offers a tightly gated cleanup lane for the
metadata it owns. None of these commands ever execute remediation.

## Audit timeline

```
shellforgeai audit list
shellforgeai audit timeline [--latest] [--session <id>] [--proposal <id>] [--kind <k>] [--since <ts>] [--json]
shellforgeai audit show <event_id>
shellforgeai audit validate
```

The append-only event log lives at `<data_dir>/audit/events.jsonl`. Every
event records:

- `safety.execution_allowed=false`
- `safety.execution_status=not_executed`
- `safety.mutation_performed=false`

…except the small set of events emitted by the gated mutation lanes:

- PR46 metadata prune execute (`details.metadata_cleanup_executed=true`,
  `details.remediation_execution=false`).
- PR47/PR48 lab container restart execute
  (`safety.mutation_scope=lab_container_restart_only`,
  `safety.execution_allowed=true`, `mutation_performed=true`) plus
  PR48 verification fields.
- PR71 cleanup execute receipts and audit linkage.

`audit validate` enforces these invariants and rejects any payload that
claims otherwise.

## Incident index and search

```
shellforgeai audit index [--rebuild]
shellforgeai audit index validate
shellforgeai audit search [<query>] [--component C] [--target T] [--kind K] [--status S] [--risk R] [--proposal P] [--session SID] [--type T] [--since TS] [--json]
```

The index (`<data_dir>/audit/incident-index.json`) is built from audit
events, artifact sessions, approvals, apply bundles, exports, and
compiled actions. `audit search` filters with case-insensitive token AND
across title/summary/component/target/kind/status/session_id/
proposal_id/tags/paths plus exact-match filters. Read-only; the index
file is the only file these commands write.

## Exports

```
shellforgeai export <session-id|session-dir>
shellforgeai export --latest
shellforgeai export --proposal <id>
shellforgeai export --latest-approved
shellforgeai export --output <path>
shellforgeai export --redact
shellforgeai validate-export <export-dir|export-manifest.json>
```

Bundles evidence/summary/plan/runbook/proposal/apply-preflight artifacts
into `<data_dir>/exports/<export_id>/` with `export-manifest.json`,
`export-summary.md`, `checksums.sha256`, and the copied files. Missing
optional files are recorded in the manifest. `--redact` best-effort
masks common secrets in text-like files and writes
`redaction-report.json`; raw source artifacts are never modified.
`validate-export` re-verifies checksums, required files, redaction
state, and safety invariants (no `execution_allowed=true` in any copied
preflight). Exports never execute remediation.

Mission exports follow the same shape under
`<data_dir>/mission_exports/<mission-id>/` and are validated by
`mission … validate-export`.

## Metadata hygiene reporting

```
shellforgeai doctor
shellforgeai doctor --json
shellforgeai audit retention [--json] [--top N]
```

`doctor` includes a metadata hygiene status with explicit category-level
reasons (counts, oldest timestamp, estimated size, threshold) and a
`suggested_commands[]` list for safe cleanup. `audit retention` reports
total human-readable size, category severities (sorted largest-first),
and supports `--top N` for the largest items.

Hygiene reporting is read-only and never performs cleanup. It only
classifies state and suggests commands.

`/data` accumulates over time. Old proposals/missions/evidence/exports
can exist for days or weeks; PR59 reference resolution warns when
implicit references resolve to stale candidates. Prefer explicit IDs.

## Cleanup (PR55 + PR71 hardened gate)

The cleanup lane is the only one that may delete ShellForgeAI-owned
metadata under `<data_dir>`. It is strictly sequential and explicitly
gated:

```
shellforgeai audit cleanup plan --category <cat> --max-age-days N --keep-latest M
shellforgeai audit cleanup archive <plan-id>
shellforgeai audit cleanup validate <cleanup-archive.tar.gz>
shellforgeai audit cleanup execute <plan-id> --confirm
shellforgeai audit cleanup validate <cleanup-receipt-or-dir>
shellforgeai audit cleanup report <cleanup-receipt-or-dir>
```

Guardrails:

- `audit cleanup plan` is **always dry-run** —
  `execution_allowed=false`, `mutation_performed=false`. Output
  includes matched/kept/candidate counts and outside-`<data_dir>`
  counters with explicit safety flags.
- `audit cleanup archive <plan-id>` writes a compact archive that
  carries the plan fingerprint.
- `audit cleanup validate` re-checks the archive (or the post-execute
  receipt) and refuses on any tamper.
- `audit cleanup execute <plan-id> --confirm` is the only step that
  deletes. PR71 requires:
  - `--confirm` on the command line,
  - a matching validated cleanup archive,
  - plan fingerprint that matches the archive's recorded fingerprint,
  - every candidate path inside the allowed `<data_dir>` roots,
  - no protected category (`approvals`, `audit-events`).
- A JSON+markdown receipt under `<data_dir>/cleanup_receipts/` records
  plan/archive linkage, candidate/deleted/skipped/failed counters, and
  explicit safety flags. Audit events for cleanup carry
  `safety.execution_allowed=false`,
  `safety.execution_status=not_executed`,
  `safety.mutation_performed=false` at the safety-block level — only
  `details.metadata_cleanup_executed=true` flags the actual operation.

## Legacy `audit prune` (PR46)

```
shellforgeai audit prune --category <cat> --max-age-days N --keep-latest M           # dry-run
shellforgeai audit prune --category <cat> --max-age-days N --execute --confirm       # mutation
shellforgeai audit prune --archive ...
shellforgeai audit archive --older-than-days N --output <path>
shellforgeai audit archive-validate <archive.tar.gz>
```

The PR46 gate has the same scope rules as PR55/PR71 (ShellForgeAI-owned
metadata only, protected categories refused, paths validated). New
workflows should prefer the PR55/PR71 plan → archive → validate → execute
sequence; `audit prune` remains supported.

## Safety summary

- No deletion from ask. Natural-language cleanup phrasing is routed to a
  retention report and prints the explicit CLI guidance.
- No arbitrary paths. Allowed roots are `<data_dir>` and
  `<data_dir>/audit`; protected roots and symlink escapes are refused.
- No Docker/Compose/system cleanup. Cleanup never touches containers,
  volumes, packages, services, firewall, routes, or DNS.
- Receipts validate after execute. A failed validation is loud.
