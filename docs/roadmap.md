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
- PR34: audit/export pack milestone. `shellforgeai export` packages
  evidence/summary/plan/runbook/proposal/apply-preflight artifacts into
  `<data_dir>/exports/<export_id>/` with `export-manifest.json`,
  `export-summary.md`, and `checksums.sha256`. Supports `<session-id|dir>`,
  `--latest`, `--proposal <id>`, `--latest-approved`, `--output`,
  `--redact`; `--approved` is refused as too broad. `validate-export`
  re-checks manifest, files, checksums, and the apply-preflight
  execution invariants. Export only copies/reads files — no execution,
  no mutation. `apply` remains validation-only.

- PR35: export redaction hardening milestone with deterministic placeholders, `redaction-report.json`, and validate-export redaction checks for safer shareable audit packs.
