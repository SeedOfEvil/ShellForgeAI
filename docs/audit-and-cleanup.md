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

## Cleanup review (PR74)

`audit cleanup review` is a read-only operator decision aid that runs
before any `audit cleanup plan`. It answers:

- What is taking space in `<data_dir>`?
- Which categories are safe cleanup candidates?
- Which cleanup plan command should I run next?
- What is the safest narrow lane to start with (default: `exports`)?
- What PR71 gates still prevent deletion?

```
shellforgeai audit cleanup review
shellforgeai audit cleanup review --json
shellforgeai audit cleanup review --category exports
shellforgeai audit cleanup review --top 10
```

`audit cleanup review` differs from `audit cleanup plan`/`archive`/
`execute`:

- It never creates `cleanup_plans/` entries, never writes archives,
  never writes receipts, never deletes files.
- It does not call `docker compose`, does not touch services, packages,
  firewall, or system state.
- `--json` emits strict, parseable JSON only — no text before/after.
- The `safety` block pins `review_only=true`, `cleanup_executed=false`,
  `archive_created=false`, `mutation_performed=false`,
  `arbitrary_paths_allowed=false`, `docker_mutation=false`,
  `system_mutation=false`, `natural_language_execution=false`.
- Recommended first lane defaults to `exports` because exports are
  reviewable artifact bundles already supported by `audit cleanup plan`.
  Categories not supported by cleanup planning (`approvals`,
  `audit-events`, `indexes`) are marked `cleanup_supported=false` and
  never recommended as executable lanes.

The review then restates the PR71 deletion gates so operators see them
before authoring a plan: `cleanup_plan`, `matching_archive`,
`archive_validation`, `matching_plan_fingerprint`, `explicit_confirm`,
`receipt_validation`. Deletion still requires the explicit
`plan → archive → validate → execute --confirm` sequence below.

## Cleanup prepare workflow (PR75)

`audit cleanup prepare` guides an operator through a complete safe
pre-execution sequence in one command:

1. read current cleanup review/retention posture,
2. create a dry-run cleanup plan using the existing plan path,
3. create the matching archive using the existing archive path,
4. validate the archive (members + manifest + fingerprint),
5. emit a decision packet,
6. **stop before execute**,
7. print the exact execute command as operator-approved only.

```
shellforgeai audit cleanup prepare --category exports --max-age-days 7 --keep-latest 5
shellforgeai audit cleanup prepare --category exports --max-age-days 7 --keep-latest 5 --json
```

The workflow distinguishes three stages:

- `audit cleanup review` — read-only; no plan, no archive, no deletion.
- `audit cleanup prepare` — creates plan + archive metadata, validates
  archive, no deletion, no execute.
- `audit cleanup execute <plan> --confirm` — the only deletion path; the
  PR71 gates (matching archive, matching plan fingerprint, archive
  validation, `--confirm`, receipt validation) still apply unchanged.

`audit cleanup validate` accepts three inputs:
- a `cleanup-plan.json` file — checks cleanup-plan semantics
  (`kind=cleanup_plan`, `execution_allowed=false`,
  `mutation_performed=false`, `requires_archive=true`,
  `requires_confirm=true`, `safety.shellforgeai_metadata_only=true`,
  candidate paths free of `..` traversal),
- a `cleanup_archive_*.tar.gz` archive — checks archive members,
  manifest, and the dry-run safety invariants,
- a cleanup receipt directory or `cleanup-receipt.json` — checks the
  post-execute receipt safety block.

`prepare` defaults to `--category exports` (the safest first lane).
Unsupported or path-traversal category strings are refused with a non-
zero exit before any plan or archive is created. The `--json` output is
strict (`schema_version="1"`, `kind="cleanup_prepare_result"`) and pins
`safety.cleanup_executed=false`, `safety.mutation_performed=false`,
`safety.deletion_performed=false`, `safety.arbitrary_paths_allowed=false`,
`safety.docker_mutation=false`, `safety.system_mutation=false`. If
archive validation fails, `decision.ready_for_operator_decision` is
`false` and the execute command is not surfaced as approved.

## Cleanup execute readiness and report (PR76)

PR76 adds two read-only commands that bracket the final
`audit cleanup execute --confirm` step:

```
shellforgeai audit cleanup execute-readiness <plan-id-or-path>
shellforgeai audit cleanup execute-readiness <plan-id-or-path> --json
shellforgeai audit cleanup report <receipt-path-or-dir>
shellforgeai audit cleanup report <receipt-path-or-dir> --json
```

`execute-readiness` re-checks the PR71 gates **before** the operator
runs `execute --confirm`:

- plan exists, `kind=cleanup_plan`, and validates as a cleanup plan,
- `execution_allowed=false`, `mutation_performed=false`,
  `requires_archive=true`, `requires_confirm=true`,
  `safety.shellforgeai_metadata_only=true`,
- a matching cleanup archive exists, validates, and carries the
  plan fingerprint and `plan_id`,
- every candidate path resolves under an allowed ShellForgeAI metadata
  root,
- no existing receipt already records execution of this plan.

`execute-readiness` is strictly read-only: it creates no plans,
archives, or receipts, and deletes nothing. When ready, the JSON
`next_commands.execute` field is the only place the explicit
`execute <plan-id> --confirm` invocation is surfaced — and that command
still goes through the full PR71 enforcement at execute time.

`audit cleanup report` summarizes an execute receipt: plan/archive
linkage, deleted/failed/bytes/skipped counters, the receipt safety
block, and a fingerprint cross-check against the matching archive. The
final operator decision workflow is:

```
review -> prepare -> execute-readiness -> operator approval ->
execute --confirm -> report
```

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
