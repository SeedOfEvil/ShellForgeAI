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
