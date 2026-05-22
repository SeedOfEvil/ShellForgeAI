# Roadmap

> The roadmap captures direction, not commitments. Anything below the
> "Shipped" header is current behavior. Anything below "Next" is intent.

## Shipped

- Deterministic core ops runtime: `diagnose` collects evidence, classifies
  the target, and emits a conservative plan + audit + artifacts.
- Profile system (`inspect`, `assisted`, `lab-direct`, `prod-readonly`).
- LLM provider abstraction with OpenAI Codex CLI as default, plus Ollama,
  vLLM, OpenAI-compatible, and OpenRouter.
- Interactive operator REPL with workspace trust, slash commands, paste
  guard / quarantine, and streaming synthesis.
- Context-first routing: recognized ops intents auto-run typed read-only
  collectors before any model call.
- Adaptive read-only follow-ups (CPU/process, memory/swap, storage/IO,
  network/DNS, service health, general context). Inspect with `/pending`.
- `audit list` / `audit show`; artifacts are written only when produced.
- Build metadata via `SHELLFORGEAI_BUILD_PR` / `_COMMIT` / `_BRANCH` /
  `_DATE` env vars; surfaced by `--version`, `version`, and `doctor`.
- PR30: evidence-backed operator runbooks. `shellforgeai runbook` (and
- PR31: formal runbook validation (`validate-runbook`), schema-versioned `runbook.json`, and stricter advisory risk scoring.
- PR32: mutation proposal objects and approval queue.
  `shellforgeai approvals create [--from-runbook PATH] [--latest] [--include-low]`
  / `list` / `show` / `approve` / `reject` / `cancel` / `archive` /
  `validate`. Proposals live under
  `<data_dir>/approvals/{pending,approved,rejected,canceled,archived}/`
  with a schema-versioned JSON payload (`source`, `kind`, `risk`,
  `confidence`, `safety_labels`, `proposed_steps`, `rollback`,
  `verification`, `execution.allowed=false`). Approval is a paper
  trail — it does not execute anything; ask phrases like "approve
  and run the fix" / "fix everything now" are refused cleanly.
- PR33: apply preflight + operator execution bundle export.
  `shellforgeai apply <approved-proposal>` runs deterministic preflight
  checks and writes `apply-preview.md`, `operator-commands.sh`,
  `rollback.sh`, `validation.md`, and `apply-preflight.json` under
  `<data_dir>/apply_bundles/<id>/`. The generated shell scripts contain
  an early `exit 2` before any operator-run command. ShellForgeAI still
  does not execute anything; `apply` remains validation-only.
  `diagnose --with-runbook`, fix-plan asks) turn existing read-only
  evidence into a labelled operator-run remediation plan with
  prechecks, options, rollback, and post-fix validation. ShellForgeAI
  does not execute any of the steps; `apply` remains validation-only.

## Next

- Model-driven hand-off into a richer plan synthesis surface (still
  validation-only at the boundary).
- `apply` execution behind explicit operator approval and policy gating.
- Optional read-only MCP server (`shellforgeai mcp serve --readonly`)
  exposing `shellforgeai_health`, `shellforgeai_diagnose_*`, and
  `shellforgeai_audit_recent`. See `docs/codex-integration.md`.
- Broader knowledge sources (curated runbooks, opt-in web).
- Richer interactive UX: scoped quoting, evidence breadcrumbs, undo of
  queued follow-ups.

## Non-goals

- Becoming a shell.
- Hidden mutation under workspace trust.
- Auto-apply of model-generated plans.


- PR33: approval/apply hardening milestone: proposal fingerprints + create idempotency, approvals list filters, show/validate polish, idempotent apply bundle refresh status, and script label normalization; apply remains validation-only.
- PR37: policy-gated action compiler milestone. `shellforgeai actions compile`
  turns an approved proposal's operator-run steps into structured, review-only
  action records under `<data_dir>/actions/<proposal-id>/` (`actions.json`,
  `actions.md`). Classification is deterministic string/regex — no LLM call,
  no shell execution. Mutation steps are classified `blocked` with
  `SERVICE-IMPACTING` / `FILESYSTEM-MUTATION` / `PACKAGE-MUTATION` /
  `NETWORK-MUTATION` / `FIREWALL-MUTATION` labels; read-only inspection is
  `read_only_review`; everything else defaults to `manual_only`. `actions
  validate` enforces the review-only invariants (every action carries
  `execution_allowed=false`, top-level `execution_status=not_executed`,
  summary counts match, blocked mutations are never marked read-only). `apply
  <approved-proposal>` also writes the same `actions.json`/`actions.md`
  alongside the static bundle. Compiled does not mean applied; `apply`
  remains validation-only.
- PR34: audit/export pack milestone. `shellforgeai export` packages
  evidence/summary/plan/runbook/proposal/apply-preflight artifacts into
  `<data_dir>/exports/<export_id>/` with `export-manifest.json`,
  `export-summary.md`, and `checksums.sha256`. Supports `<session-id|dir>`,
  `--latest`, `--proposal <id>`, `--latest-approved`, `--output`,
  `--redact`; `--approved` is refused as too broad. `validate-export`
  re-checks manifest, files, checksums, and the apply-preflight
  execution invariants. Export only copies/reads files — no execution,
  no mutation. `apply` remains validation-only.
- PR38: stale-evidence and drift guard milestone. `shellforgeai guard
  check|check-actions|check-export|show` runs deterministic freshness
  and source-hash drift checks against proposals, compiled actions,
  apply preflight bundles, and export packs. Guard reports are written
  under `<data_dir>/guards/<source-id>/` as `guard-report.json` and
  `guard-report.md`, with decisions `fresh`, `warning`, `stale`,
  `drift_detected`, or `blocked`. Default max ages: proposals/actions/apply
  bundles 24h, exports 7d; `--max-age-hours` overrides per call. Newly
  generated proposals and compiled actions record optional `source_hashes`
  so a later guard call can detect post-creation tampering of the
  underlying `evidence.json`, `runbook.json`, `summary.md`, or
  `proposal.json`; older artifacts without recorded hashes validate cleanly
  with `source_hash_status=unknown`. `apply` runs the guard internally and
  refuses by default when the proposal is stale or drifted; `--allow-stale`
  bypasses stale (drift is never bypassed) and `apply-preflight.json`
  records `guard_status` and the guard report path. Every guard report
  records `execution_allowed=false` and `execution_status=not_executed`.
  Guard checks are read-only — no remediation, no host mutation. `apply`
  remains validation-only.

- PR39: guard-aware audit timeline milestone (`audit timeline/show/validate`) for chronological operator incident trails with explicit no-execution safety state.
- PR40: audit-aware incident index / search milestone. `shellforgeai audit
  index [--rebuild]` builds a compact deterministic index
  (`<data_dir>/audit/incident-index.json`) from audit events, artifact
  sessions, approval proposals, apply bundles, exports, and compiled
  actions. `shellforgeai audit search [<query>] [--component/--target/
  --kind/--status/--risk/--proposal/--session/--type/--since] [--json]`
  filters the index with case-insensitive token AND across
  title/summary/component/target/kind/status/session_id/proposal_id/
  tags/paths plus exact-match filters. `shellforgeai audit index validate`
  re-validates the on-disk index (unique `item_id`, required fields,
  numeric `source_counts`, string paths, and safety invariants). The ask
  router (`search audit for ...`, `find drift refusals`, `find approved
  proposals`, `did anything execute?`) routes to the same index. The
  index is read-only metadata navigation: the only file written is the
  index itself, and every indexed item preserves `execution_allowed=false`,
  `execution_status=not_executed`, `mutation_performed=false`. `apply`
  remains validation/preflight-only.

- PR41 completed: audit/index/export retention reporting, dry-run prune planning, explicit `--execute` metadata prune, and compact archive export/validation.

- PR42 completed: ask intent routing hardening for ShellForgeAI-owned workflows (audit/retention/export/index/approvals/actions/guard/apply-preflight), plus safer command suggestions and host-audit disambiguation.

- PR43 completed: operator status dashboard (`shellforgeai status`) with read-only health/safety summary, JSON schema v1 output, ask-route integration for status questions, and explicit non-execution reporting.

- Metadata hygiene visibility and deterministic dry-run cleanup guidance in doctor/retention/ask flows.

- PR46 completed: first guarded mutation gate. `shellforgeai audit prune`
  may now execute deletion limited strictly to ShellForgeAI-owned metadata
  under `<data_dir>` and `<data_dir>/audit`, only after both `--execute` and
  `--confirm` are passed and per-path safety validation succeeds. Each
  execute writes a JSON + markdown receipt under
  `<data_dir>/prune_receipts/`. Audit events for prune carry
  `metadata_cleanup_executed`/`remediation_execution=false`/`shellforgeai_owned_paths_only=true`
  in `details`; the audit safety block remains
  `execution_allowed=false`/`execution_status=not_executed`/`mutation_performed=false`.
  Ask routing for cleanup phrasing refuses to delete and prints the explicit
  `--execute --confirm` CLI guidance. `apply` remains validation/preflight-only.

- PR47 completed: first non-metadata mutation gate. `shellforgeai apply
  <approved-proposal-id> --execute --confirm` may now execute exactly one
  `docker restart <container>` for containers in the explicit allowlist at
  `<data_dir>/policy/lab-container-restart-allowlist.json` (disabled by
  default) when every gate passes: explicit `--execute`/`--confirm`,
  `SHELLFORGEAI_MUTATION_MODE=lab` + `SHELLFORGEAI_ALLOW_LAB_CONTAINER_RESTART=1`,
  allowlist enabled with non-empty entries, proposal status `approved`, PR38
  guard `fresh`/`warning`, the compiled action is exactly
  `docker restart <safe-name>`, the container name passes the safe regex.
  Execution goes through a `CommandExecutor` abstraction with `shell=False`
  and list-form argv only; tests use the fake executor. Each execute (and
  refusal) writes a receipt under `<data_dir>/execution_receipts/`. The
  audit event for a successful lab restart is the first ShellForgeAI event
  with `safety.execution_allowed=true`/`execution_status=executed`/
  `mutation_performed=true` and `safety.mutation_scope=lab_container_restart_only`;
  every other event remains strict no-execution. Ask refuses to execute and
  prints the explicit `--execute --confirm` CLI guidance.

- PR48 completed: post-mutation verification gate for the PR47 lab container
  restart. After the allowed `docker restart <allowlisted-container>` exits
  0, ShellForgeAI automatically runs read-only verification: `docker inspect
  <container>` before and after the restart (via a `ContainerInspector`
  abstraction with `shell=False` argv-only subprocess), a bounded
  post-restart wait, and an optional bounded health-poll loop only when the
  container declares a healthcheck. The receipt JSON gains a
  `verification` block (`status` of `passed`/`warning`/`failed`/`skipped`,
  `started_at_before/after`, `started_at_changed`, `running_after`,
  `health_before/after`, `restart_count_before/after`, `notes`,
  `evidence`) and gets a sibling evidence directory
  `execution_receipts/exec_<id>/{before-inspect.json,after-inspect.json}`
  plus a human-readable `exec_<id>.md`. The audit event adds
  `details.verification_status`, `details.container_running_after`,
  `details.started_at_changed`, `details.health_after`, and
  `details.verification_notes`; event-level `status` becomes `success`,
  `warning`, or `failed`. PR48 does not widen mutation scope: no second
  restart, no `docker exec`, no `docker compose|stop|start|kill|rm|run`,
  no shell, no arbitrary command strings. Ask gains read-only verification
  queries (`did the restart work?`, `show restart verification`, `show
  post-mutation verification`, `show last execution receipt`, `was the
  container running after restart?`) that summarize the latest receipt
  without executing anything. `restart it and verify` is still routed to
  the mutation refusal path with explicit guidance that verification runs
  automatically after the approved CLI execution.


## PR50 — Evidence-to-proposal restart builder

Adds deterministic proposal creation for allowlisted lab/disposable Docker containers from evidence artifacts, with dedupe by fingerprint. This is proposal metadata only and does not approve, rollback, or execute mutation.

- PR51: restart proposal dry-run checklist/readiness preview (`approvals restart-plan`) with JSON + ask surfacing, read-only safety path before approval/execution.
- PR52: guided safe restart mission workflow (`mission restart prepare/status/checklist/validate/export`) that ties evidence, proposal, approval, rollback preview, and apply readiness into a single mission record. Metadata only; no new mutation scope.
- PR53: mission execute handoff (`mission restart execute <mission-id> --execute --confirm`) that verifies mission readiness and delegates to the existing PR47/PR48/PR49 apply gate. No new executor, no broader mutation scope, no natural-language execution. The actual mutation remains the existing allowlisted `docker restart <target>`. The apply receipt path is referenced from the mission record after delegation.
- PR54: mission post-execution report and export pack (`mission restart report`, `mission restart export [--redact]`, `mission restart validate-export`). Read-only. Bundles mission record, mission-report.json/md, proposal, rollback preview, apply receipt, before/after inspect evidence, source evidence, audit events, manifest, and checksums into `<data_dir>/mission_exports/<mission-id>/`. Reuses the PR34 redactor for `--redact`. No new mutation class; report/export commands never execute, apply, approve, or roll back. Manifest carries `safety.execution_status="not_executed_by_export"` and `safety.mutation_performed_by_export=false`.

- PR55 milestone: first-class audit cleanup review workflow (plan/archive/execute/validate/report) for ShellForgeAI-owned metadata only.

## PR56 milestone: Compose ownership/context

- Added read-only Compose project/service ownership detection from Docker labels.
- Added `compose inspect` and `compose list` context commands.
- Added advisory Compose context propagation into docker evidence and restart proposal/plan metadata.
- No `docker compose` mutation path added.

## PR57 milestone: Compose ask-route polish

- Added deterministic ask target extraction for Compose-context question forms.
- Compose context asks now route to the existing read-only inspect/list context path when a safe target is present.
- Missing/invalid targets now produce explicit safe next-step CLI suggestions.
- Natural-language Compose mutation requests remain refused; no new execution/mutation path added.

## PR58 milestone: Compose-aware restart proposal and mission enrichment

- Restart proposals built from evidence now carry a normalized `compose_context`
  block (project/service/working_dir/config_files/version/oneoff/source) when
  the target container has Docker Compose labels. Non-Compose targets record
  `{"detected": false, "reason": "compose labels not present"}`.
- `approvals show`, `approvals restart-plan` (human and `--json`), mission
  records (`mission.json`/`.md`, status/checklist), apply execution receipts,
  and `mission restart report` now surface Compose ownership context, plus
  explicit `restart_scope="container"` and `compose_mutation=false`.
- Restart-plan readiness blocks when a proposal's command preview tries to use
  `docker compose`; readiness is NOT blocked merely because the target is
  Compose-managed.
- Ask integration: read-only queries like "show compose context for this
  restart proposal" / "is this mission targeting a compose service?" answer
  from metadata. Compose service mutation phrasings (e.g. "propose restart for
  compose service X", "docker compose restart X", "compose up X",
  "recreate compose service X") are refused with safe suggestions
  (`compose inspect <container>` and the container-scoped
  `approvals propose-restart`).
- No `docker compose` execution path added. Command preview remains the exact
  `docker restart <container>`; the apply gate remains the only mutation path.
  PR58 is context enrichment only.

## PR60 milestone: read-only ops status board

- Added `shellforgeai ops status` and `shellforgeai ops status --json` for compact
  artifact-backed operator posture reporting.
- Read-only only: no new executor, no apply path changes, no `docker compose`
  mutation, no restart execution from status.

- PR59 milestone: ask-reference disambiguation for implicit proposal/mission references (`this`/`latest`/`current`/`most recent`) with deterministic read-only resolver, stale warning guard (24h default), explicit-ID precedence, and ambiguity listing (no guessing/no execution).

- PR61: added read-only `compose restart-preview` command and ask preview phrasing for Compose service restarts (preview only; no compose execution path).
- PR62: added `compose propose-restart` to create pending `compose_service_restart` proposal artifacts from Compose metadata (proposal-only, non-executable, apply refusal retained).

- PR64: hardened compose-service restart mission preflight diagnostics and post-execution verification evidence so blocked-vs-executed outcomes are explicit without broadening mutation scope.

- PR65: hardened `rollback preview`/`rollback validate` for `compose_service_restart` proposals with recovery-preview schema, command-shape validation, config hashing (hash-only), and explicit non-automatic rollback posture.

- PR66: added read-only `compose env-check` diagnostics to explain Compose restart execution readiness blockers (runtime preflight, compose-file snapshot visibility, and allowlist posture) without creating proposals/missions or executing Compose mutation.

- PR67: added a disposable Compose execution harness (fixture/template,
  external lab helper script, README) plus readiness tests so the
  Compose service restart lane (PR61–PR66 gates) can be proven against a
  throwaway target. ShellForgeAI continues to refuse `docker compose
  up/down/recreate`, never runs the lab helper itself, never executes
  natural-language Compose mutation, and the real `shellforgeai` service
  remains blocked from the restart lane because it is not (and must not
  be) labeled disposable/allow_restart.

- PR68: added an optional live disposable Compose restart proof path
  (`scripts/pr68_disposable_compose_restart_proof.sh` orchestrator and
  docs) so NewTwo/operators can drive the existing PR63-PR67 gated
  Compose service restart lane end-to-end against the disposable PR67
  harness target. The orchestrator is lab-only; ShellForgeAI never
  invokes it. Default behavior is dry-run / readiness only. Even with
  the explicit `--execute-approved-disposable-restart` flag the
  orchestrator only verifies readiness and prints the manual gated
  command sequence; the operator runs `shellforgeai mission
  compose-restart execute <mid> --execute --confirm` directly. The
  orchestrator refuses production-looking target names, pins the exact
  disposable target invariants, and never installs packages, never
  mounts host paths, never prunes, never deletes arbitrary paths, and
  never edits production compose files. PR68 adds no new ShellForgeAI
  mutation capability, no generic Compose executor, no `docker compose
  up/down/recreate` from the app, no host-side bypass, and no
  natural-language execution.

- PR69: added read-only `compose env-contract` execution-environment contract/readiness diagnostics so operators can verify exact disposable-lane prerequisites without executing restart or loosening safety gates.


## PR70 milestone: metadata hygiene status and cleanup polish

- Doctor metadata hygiene now reports explicit category-level reasons and safe, gated cleanup command sequence.
- Doctor JSON now includes structured `metadata_hygiene.reasons[]` and `suggested_commands[]`.
- Cleanup plan output now includes matched/kept/candidate and outside-data-dir counters with explicit safety flags.

## PR71 milestone: metadata cleanup archive/execute live-safe command pass

- Hardened cleanup lane sequencing: retention/report -> plan (dry-run) -> archive -> validate -> execute `--confirm`.
- Execute now requires matching validated archive + plan fingerprint match before any deletion.
- Execute results/receipts include plan/archive linkage, candidate/deleted/skipped/failed counters, and explicit safety flags.
- Scope remains ShellForgeAI-owned metadata only; no Docker/Compose/system mutation and no natural-language cleanup execution.

## PR77 milestone: cleanup execution UX/report polish

- Polished `audit cleanup execute-readiness` so the boundary between
  "gates satisfied" and "operator-approved" is explicit. JSON now
  exposes top-level `ready_for_execute_confirm`,
  `operator_action_required`, `read_only`, `cleanup_executed`,
  `deletion_performed`, and a `gates` block alongside the existing
  `readiness`, `plan`, `archive`, `safety`, and `next_commands`
  payload. Human output begins with `Status:` and `Validated gates:`
  blocks and an `Operator warning:` that explicitly states the command
  did not delete anything; the blocked branch refuses to surface the
  execute command and adds `Do not execute until blockers are
  resolved.`
- Polished `audit cleanup execute` refusal without `--confirm` to list
  the required gates (`matching archive`, `archive validation`,
  `matching plan fingerprint`, `explicit --confirm`), say
  `Nothing was deleted.`, and point back at
  `audit cleanup execute-readiness`.
- Polished `audit cleanup report` to add a `Post-execute checks:`
  block in human output and a `post_execute_checks` array in JSON
  (`audit cleanup validate <receipt>`, `audit retention`,
  `audit cleanup review`, `doctor`). Added top-level `receipt_kind`,
  `receipt_valid`, `receipt_plan_id`, `deleted`, `failed`, and
  `bytes_removed` mirror fields for downstream consumers.
- All PR55/PR71/PR74/PR75/PR76 cleanup gates and read-only properties
  are unchanged. Readiness and report do not call `cleanup execute`,
  do not mutate Docker/Compose/services/packages/firewall/network/
  system, and natural-language `ask` paths still cannot reach
  `cleanup execute`. Only `audit cleanup execute <plan> --confirm`
  deletes.
- Added `tests/test_pr77_cleanup_execute_polish.py` covering
  readiness JSON top-level fields and `gates`, human Status/Validated
  gates/Operator warning blocks, blocked branch hiding the execute
  command, execute-refusal gate listing, refusal non-deletion,
  report `post_execute_checks` and top-level mirror fields, and
  read-only safety regressions.

## PR76 milestone: cleanup execute readiness and post-execute report

- Added read-only `shellforgeai audit cleanup execute-readiness
  <plan-id-or-path>` (and `--json`) that re-checks the PR71 gates
  before the operator runs `cleanup execute --confirm`: plan kind and
  safety fields, matching cleanup archive, archive validation, matching
  plan fingerprint, allowed-root candidate paths. When ready it emits
  an operator-only `next_commands.execute` invocation that still
  includes `--confirm`; when blocked it lists the blockers cleanly.
- Hardened `shellforgeai audit cleanup report
  <cleanup-receipt-or-dir>` with a richer human summary
  (deleted/failed/bytes/skipped, plan/archive linkage, receipt safety,
  fingerprint cross-check) and a strict `--json` output.
- Both commands are strictly read-only: they create no plans, no
  archives, no receipts; delete nothing; never touch Docker/Compose/
  services/packages/firewall/network/system; and never accept
  natural-language cleanup execution. JSON safety blocks pin
  `read_only=true`, `cleanup_executed=false`, `deletion_performed=false`,
  `arbitrary_paths_allowed=false`, `docker_mutation=false`,
  `system_mutation=false`, `natural_language_execution=false`,
  `explicit_confirm_required=true`.
- PR55/PR71 cleanup execute gates are unchanged. `cleanup execute
  <plan> --confirm` with matching validated archive and matching plan
  fingerprint remains the sole deletion path.

## PR75 milestone: /data cleanup prepare workflow

- Added `shellforgeai audit cleanup prepare --category <cat>
  --max-age-days N --keep-latest M` (and `--json`) — a guided
  pre-execution workflow that reads the cleanup review posture, creates
  a dry-run cleanup plan via the existing plan path, creates the
  matching archive via the existing archive path, validates the archive,
  and emits a decision packet. The packet pins `execute_performed=false`
  and `deletion_performed=false` and prints the exact execute command
  marked operator-approved only.
- Prepare never deletes candidate files, never calls cleanup execute,
  never touches Docker/Compose/services/packages/firewall/network/system,
  and never accepts natural-language execution. Unknown or
  path-traversal category values are refused before any plan/archive is
  created. Strict JSON pins `safety.cleanup_executed=false`,
  `safety.mutation_performed=false`, `safety.deletion_performed=false`,
  `safety.arbitrary_paths_allowed=false`, `safety.docker_mutation=false`,
  `safety.system_mutation=false`.
- PR55/PR71 cleanup execute gates are unchanged. Prepare creates plan
  and archive metadata only; the existing
  `cleanup execute <plan> --confirm` with matching archive/fingerprint
  remains the sole deletion path.

## PR74 milestone: /data cleanup review pack

- Added read-only `shellforgeai audit cleanup review` (and `--json`,
  `--category <name>`, `--top N`) that summarizes the ShellForgeAI
  metadata footprint, groups categories by size, marks each as
  `cleanup_supported` or report-only, recommends the safest narrow
  first lane (default: `exports`), restates the PR71 deletion gates,
  and prints the next safe dry-run command.
- Review is strictly read-only: it never creates plans, archives, or
  receipts, never deletes, never calls `docker compose`, never mutates
  services / packages / firewall / files / network, and never accepts
  natural-language execution. The JSON `safety` block pins
  `review_only=true`, `cleanup_executed=false`, `archive_created=false`,
  `mutation_performed=false`, `arbitrary_paths_allowed=false`,
  `docker_mutation=false`, `system_mutation=false`,
  `natural_language_execution=false`.
- PR55/PR71 cleanup gates are unchanged. Review enables operator
  decision-making before the existing
  `plan → archive → validate → execute --confirm → receipt validation`
  sequence; it does not loosen any gate.

## PR73 milestone: compose execution environment readiness plan

- Added read-only `shellforgeai compose env-plan --target <target>`
  (and `--json`) that maps current env-check / env-contract readiness
  blockers to explicit operator-controlled remediation steps for the
  disposable Compose restart proof.
- Every plan entry carries `shellforgeai_action="none"` and
  `automated=false`. Production-like targets are flagged with a warning
  and routed to the PR67 disposable harness recommendation — never to a
  "label production disposable" suggestion.
- env-plan is read-only: no `docker compose` execution, no host-side
  bypass, no host path mount, no package install, no proposal / mission
  / rollback preview / apply / cleanup artifact creation, no
  natural-language mutation execution, and no PR63–PR71 gate weakening.

## Current state (PR71 baseline)

- The safe evidence → runbook → proposal → approval → rollback preview
  → mission → apply → verification → receipt → audit/export spine
  exists end-to-end.
- The exact-container restart lane (PR47/PR48/PR49) is the only
  always-available real mutation lane, and remains allowlist-only,
  env-gated, and `--execute --confirm`-gated.
- The Compose service restart lane (PR61–PR69, PR73) has preview,
  proposal, mission, rollback recovery preview, env-check, env-contract,
  env-plan, and a disposable harness/proof orchestrator. Live execution
  remains gated by the env-contract and is intentionally blocked in
  default production deployments. env-plan is enablement guidance only
  and performs no environment changes.
- Metadata cleanup execution is hardened (PR71): archive + fingerprint
  + `--confirm` before any deletion of ShellForgeAI-owned metadata.

## Next tracks (intent, not commitment)

1. Documentation consolidation and the PR72 handoff baseline.
2. Optional env-contract satisfaction for a deliberate disposable live
   Compose restart proof on Docker01 (Compose CLI inside the runtime,
   readable compose file, disposable target labels).
3. Compose verification / closure-report polish *after* a successful
   disposable proof.
4. Compose recreate **preview only** at a later milestone — never
   recreate execution.
5. Never jump to broad production mutation. The product stays a Tier-3
   triage tool with narrow, audited mutation lanes.

## PR82 milestone: broad ask triage grounding

Live QA on Docker01 (PR81 followup, head `b0d33b4`) confirmed
deterministic `shellforgeai triage docker` ranking of all five
battle-lab suspects (`sfai-crashloop`, `sfai-bad-http`,
`sfai-disk-pressure`, `sfai-noisy-errors`, `sfai-permission-denied`)
with the read-only safety invariants clean (`read_only=true`,
`mutation_performed=false`, every cleanup/proposal/mission/apply/
docker-compose/container-restart/natural-language/shell-true flag
`false`).

Remaining PR81 gap: broad model-backed ask was not reliably consuming
the deterministic triage output. The PR82 fix wires broad Docker /
2AM ask prompts to call `triage_ranking.collect_scene` +
`rank_scene` directly and render the deterministic ranking from the
ask handler — no LLM re-ranking, no invented suspects, no
per-container evidence collapse.

- New ask intent detector
  `ask_routing.is_broad_docker_triage_intent` matches read-only
  broad-Docker prompts: "what's on fire?", "2AM triage", "the Docker
  box feels broken", "rank Docker suspects", "broadly scan the
  current scene", "rank all sfai-battle-lab suspects by severity",
  "what should I inspect first?", "show current Docker suspects",
  "what containers look suspicious?".
- New mutation-intent detector
  `ask_routing.is_triage_mutation_intent` matches phrases that follow
  a ranking ("restart the top suspect", "fix the crashloop", "clean
  up disk pressure now", "stop noisy-errors", "apply the top fix",
  "create a restart proposal for the top suspect", "docker compose
  restart the top one", "delete old files causing disk pressure").
  These refuse from ask with the PR82 no-mutation wording and
  redirect to the explicit gated CLI; they never render the
  deterministic ranking.
- New `cli._handle_broad_triage_ask` is wired into `ask` before the
  existing PR47/PR74-PR80 handlers. It reuses the PR81 engine
  directly (no subprocess, no `shellforgeai triage docker` shell-out)
  and renders a 2AM-readable answer with Safety / Scene summary /
  ranked suspects (severity / confidence / Evidence / Safe next) /
  optional Watch / Next safe steps footer.
- The deterministic ranking, severity/confidence, classes, per-
  container evidence, and per-suspect `safe_next_commands` are taken
  unchanged from the PR81 engine. Per-container evidence isolation
  (PR81 followup anti-attribution guards) survives the renderer:
  `sfai-bad-http` does not pick up `disk_pressure` or
  `permission_denied` evidence, etc.
- Tests added: `tests/test_pr82_broad_ask_triage.py` covers route
  detection (read-only and mutation), the deterministic grounding
  rules (ordering, severity preservation, no invented suspects, no
  omitted fixture suspects, per-container evidence isolation), the
  ask-shape requirements (all five battle-lab suspects rendered,
  crashloop pinned as top, safety statement present, read-only next
  commands, no execution commands), mutation refusal for all five
  PR82 mutation phrasings, the empty-scene and collection-failure
  paths, and safety regressions (handler source has no
  `shell=True`, no mutation-helper calls; broad ask path does not
  fall through to `diagnose_target` or `build_provider`; audit
  events for both render and refusal record every mutation flag
  `false`).
- No mutation behavior added. The ask route never restarts/stops/
  removes containers, never runs `docker compose` mutation, never
  runs `cleanup prepare/archive/execute`, never creates proposals
  or missions, never runs `apply`, and never uses `shell=True`. PR81
  deterministic triage tests, PR79/PR80 self-test profile tests,
  PR74–PR77 cleanup gates, PR56–PR69 compose gates, and the
  natural-language mutation refusal tests all continue to pass.

## PR81 milestone: battle-lab triage ranking and scene awareness

### PR81 followup — Docker01 live QA fixes

Live QA on Docker01 (image `lab/shellforgeai:pr81-3ba2373`) caught four
blockers in the initial PR81 cut:

1. **`sfai-noisy-errors` was missing** despite continuous ERROR/WARN log
   evidence. Root cause: the underlying `tools/containers._classify_log`
   regex requires `^\s*ERROR` (line-anchored), so real timestamp-prefixed
   lines (`2024-05-20T... ERROR ...`) never matched and the container
   was never added to the `noisy` bucket that fed the scene.
2. **`sfai-disk-pressure` was missing** for the same class of reason:
   no regex matched `simulated disk pressure`, `write failed`,
   `filler=`, or `ENOSPC`.
3. **`sfai-bad-http` was misattributed `disk_pressure` and
   `permission_denied`** classes. nginx upstream-refused log lines can
   include incidental `(13: Permission denied)` errno decorations; the
   original scorer triggered on a single hit and pinned the wrong
   class onto a clear bad-http suspect.
4. **Watch lane was empty** even though the ShellForgeAI container
   was running with high CPU. Root cause: `collect_scene()` enriched
   only containers in the `failing`/`noisy` buckets and never pulled
   `docker stats`, so the watch-lane scorer never had `cpu_percent`
   to work with.

Followup fixes:

- The triage module now owns its **own per-container log classifier**
  (`triage_ranking.classify_logs`) with line-anchor-free patterns and
  battle-lab phrasings (`simulated disk pressure`, `filler=`,
  `connect() failed`, `127.0.0.1:9999`, `CRITICAL boot failure`,
  `queue depth high`, `EACCES`, `ENOSPC`, `502/503`, etc.). Classifier
  state is scoped to the input text — never shared across peers.
- `collect_scene()` now independently runs `inspect` + `container_logs`
  + classifier for **each** container in the inventory and optionally
  reads bounded `docker stats --no-stream` for the watch lane. Each
  container's evidence is scoped to that container only.
- Scorers got cross-class anti-attribution guards:
  - `_score_permission_denied` requires `perm >= 2` and is suppressed
    when the dominant signal is bad_http with weak permission_denied.
  - `_score_disk_pressure` requires explicit disk-pressure evidence
    (simulated/write failed/no space/filler/ENOSPC or low free pct),
    no longer triggering on read-only-fs alone.
  - `_score_noisy_errors` is suppressed when the ERROR/WARN lines are
    already explained by a more specific class (bad_http,
    disk_pressure, permission_denied, crashloop_boot) so disk-pressure
    and bad-http suspects don't double-up as "noisy".
  - `_score_high_cpu_watch` is suppressed when any meaningful
    error/disk/permission signal exists, keeping watch a quiet bucket.
- Legacy theme keys from `tools/containers._classify_log` continue to
  be accepted via an alias map so older collectors and fixtures still
  work.
- Tests added: per-container evidence isolation, realistic
  timestamp-prefixed log fixtures matching the Docker01 scene, the
  `collect_scene` per-container isolation contract with stubbed
  collectors, and classifier sanity tests. PR79/PR80 self-test profile
  tests, PR74–PR77 cleanup gates, and the natural-language mutation
  refusal tests all continue to pass.

PR81 remains read-only. No mutation behavior was added; every JSON
payload still reports `safety.read_only=true` and every mutation flag
explicitly `false`.

### PR81 initial cut

- Added a read-only Docker triage ranking command: `shellforgeai triage
  docker [--json]`. It inventories the current Docker scene using the
  existing read-only `docker.containers` + `docker.problem_summary`
  collectors and deterministically ranks multiple suspects across
  failure classes — `crashloop` / `restart_storm`, `noisy_errors`,
  `bad_http`, `disk_pressure`, `permission_denied`, plus a
  `high_cpu_watch` lane for loud-but-healthy containers.
- Each suspect carries severity, confidence, evidence bullets, why
  ranked here, and a single read-only safe next command (always a
  `shellforgeai diagnose …` invocation). Watch entries are listed
  below suspects so they are visible without outranking real failures.
- Strict JSON shape (`schema_version`, `mode=docker_triage_ranking`,
  `summary`, `suspects`, `watch`, `safety`, `warnings`,
  `next_safe_commands`) with `safety.read_only=true` and every
  mutation flag explicitly `false`.
- No mutation behavior added. The command never restarts, stops,
  removes, or prunes containers, never runs docker compose mutation or
  cleanup execute, never creates proposals or missions, never runs
  `apply`, and never uses `shell=True`. The natural-language router is
  not broadened; mutation phrases continue to refuse with the PR74–PR80
  wording.
- Scoring is fixture-driven for testability: the scoring engine
  consumes a plain scene dict, so battle-lab regression coverage runs
  without a live Docker daemon. Tests cover crashloop ranking,
  bad-http / noisy-errors / disk-pressure / permission-denied class
  presence, the high-CPU watch case, evidence/why/safe-next bullets
  per suspect, JSON shape, safety flags, and safety regressions
  (no mutation imports, no `shell=True`).
- PR79/PR80 self-test profiles are unchanged. PR74–PR77 cleanup
  gates, PR56–PR69 compose gates, and the natural-language mutation
  refusal tests continue to pass.

## PR80 milestone: self-test command profiles and QA handoff polish

- Extended `shellforgeai self-test commands` with validation profiles
  (`--profile quick|standard|full`), `--fail-on-warn`, and
  `--include-skipped`. The default profile remains `standard` so the
  PR79 default behavior is preserved.
- `quick` is a cheap, env-independent smoke (`version`, `doctor`,
  `model doctor`, `tools list`, `ops status`, ask refusal) and is the
  recommended first post-deploy gate. `standard` keeps the PR79
  coverage. `full` adds broader read-only checks (`audit list`,
  `audit timeline --latest --json`, `compose list --json`).
- Introduced an explicit warn vs skip distinction: rows backed by
  missing optional artifacts (latest runbook, compose target absent
  from inventory, empty audit storage) are surfaced as `WARN` with a
  reason and contribute to `summary.warned`; the overall `status`
  becomes `warn` (not `failed`). `--fail-on-warn` exits non-zero on
  `warn` and adds `ci_status: "failed_on_warn"` to the JSON payload
  without converting warnings into runtime failures.
- Expanded the JSON schema with `profile`, `summary.warned`, a
  canonical `safety` block (`read_only`, `mutation_performed`,
  `cleanup_execute_run`, `mission_execute_run`, `apply_execute_run`,
  `docker_compose_executed`, `docker_compose_mutation`,
  `natural_language_execution`, `arbitrary_command_execution`),
  `warnings`/`skipped` arrays, and `next_safe_commands`. The PR79
  `mode` block and `no_*` safety keys remain for backward compatibility.
- Improved the human output: explicit `Profile`, `Safety invariants`,
  `Warnings`, and `Next safe commands` sections, plus a one-line "this
  is not a command failure" reminder when warnings are present.
- The harness remains strictly read-only across every profile. PR80
  did not change any mutation gates, did not add any runtime mutation
  capability, did not change cleanup / mission / apply / Compose
  execution behavior, and did not broaden natural-language behavior.
- Tests: added `tests/test_pr80_self_test_profiles.py`; PR79 tests
  adjusted to align with the schema (no behavior regressions). Full
  suite continues to pass with repo-local fixtures only.
- Docs updated: [`docs/cli.md`](cli.md), [`docs/safety.md`](safety.md),
  [`OPS.md`](../OPS.md) (post-deploy smoke workflow + NewTwo Docker01
  QA note).

## PR79 milestone: safe command coverage harness

- Added `shellforgeai self-test commands` (and `--json`), a read-only
  operator command coverage harness that exercises the safe CLI surface
  and reports `PASS`/`FAIL`/`SKIP` per check with a strict JSON payload.
- Covers `version`, `doctor`, `model doctor`, `ops status` (+`--json`),
  `audit retention` (+`--json`), `audit cleanup review` (+`--json`),
  the `audit cleanup execute-readiness <missing-plan>` and
  `audit cleanup report <missing-receipt>` negative refusal paths,
  `compose inspect`/`env-check`/`env-contract`/`env-plan` against the
  local target, `validate-runbook --latest`, locally-routed `ask`
  smokes (`show metadata hygiene`, `clean up now`), and a
  deterministic ask-mutation refusal-routing check.
- The harness never executes cleanup, apply, mission, docker compose
  restart, proposal/mission/archive/plan creation, or natural-language
  mutation; it never uses `shell=True`; it never broadens
  natural-language behavior. Skipped checks include an explicit
  reason so operators can distinguish "not applicable in this
  environment" from a real failure.
- Operator entry point documented in [`OPS.md`](../OPS.md) and
  [`docs/cli.md`](cli.md); safety boundary documented in
  [`docs/safety.md`](safety.md). The optional disposable mutation lane
  is intentionally not implemented and remains `status=manual_only`,
  `implemented=false`, `executed=false` in the JSON payload.
- Repo-local fixtures/mocks only; no live Docker / root / Docker01 /
  internet / systemd dependency for the test suite. No PR56–PR78 gate
  weakening, no new runtime capability, no new mutation surface.

## PR78 milestone: release / handoff baseline after PR56–PR77

- Added [`docs/release-baseline.md`](release-baseline.md), the concise
  operator/QA/contributor baseline summarizing current capabilities,
  the mutation boundary, safety invariants, Docker01 caveats, the
  cleanup operator sequence, the Compose disposable proof posture,
  the standard PR validation checklist, and the next roadmap tracks.
- Linked the baseline from `README.md` and `OPS.md`.
- Release/handoff packaging only: no runtime behavior, CLI behavior,
  mutation surface, safety gate, or test behavior changed.

## Non-goals (current, unchanged)

- Becoming a shell or generic remote-execution agent.
- Autopilot or self-healing infrastructure.
- Production Compose orchestration.
- Hidden mutation under workspace trust.
- Auto-apply of model-generated plans.

- PR83 (May 20, 2026): added read-only deterministic Docker triage detail drilldown (`triage docker detail <suspect>` / `--rank <n>`) with strict JSON mode (`mode=docker_triage_detail`), rank-context/higher-lower neighbors, explicit evidence + why sections, safe-next read-only commands, and unchanged no-mutation safety invariants.

- PR84 (May 21, 2026): added read-only `triage docker snapshot` incident handoff packaging with strict JSON mode (`mode=docker_triage_snapshot`), scene summary, ranked suspects, optional compact details (`--include-details`), `--top N` suspect limiting, safe-next command guidance, and unchanged no-mutation safety invariants.

- PR85 (May 21, 2026): added read-only `triage docker snapshot --save` artifact packet creation and `triage docker snapshot validate` validation (required files, JSON parse/schema/mode/safety invariants, manifest checksum verification), with strict JSON output and no mutation behavior.
- PR86 (May 21, 2026): added read-only triage handoff export flow: `triage docker snapshot export <snapshot-id|path>` packages saved snapshot artifacts into `<data_dir>/exports/...` with export manifest + checksums metadata, and `triage docker snapshot export-validate <export-path>` re-checks required files/JSON/manifest/checksums/safety invariants.
- PR89 (May 22, 2026): added disposable-only governed remediation proof workflow (`remediation plan/validate/execute/status`) with explicit target + scenario gating, dry-run plan artifacts with fingerprint and safety flags, mandatory `--execute --confirm`, bounded disposable action execution, post-check verification receipts, and strict JSON status/error contracts.
- PR88 (May 22, 2026): added read-only `triage docker timeline` rolling incident history over saved snapshots (chronological validation + escalation/recovery/flapping/recurring/stable/new/resolved trend reporting, strict JSON mode, and unchanged no-mutation safety invariants).
