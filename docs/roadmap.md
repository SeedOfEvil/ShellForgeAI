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
