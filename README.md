# ShellForgeAI

ShellForgeAI is a lightweight, portable Tier-3 triage and guarded remediation
tool — a combat knife with a safety catch, receipts, and a flight recorder. It
collects evidence with typed read-only collectors, builds operator runbooks,
stages mutation proposals behind explicit approval/mission/apply gates,
verifies outcomes, and writes auditable receipts. The default LLM (OpenAI
Codex CLI) is used only for advisory synthesis; it never executes commands.

> Status: alpha. Mutation is gated to two narrow lanes: ShellForgeAI-owned
> metadata cleanup, and exact-container Docker restart (with a separate,
> disposable-only Compose service restart lane that remains environment-gated
> in most deployments). Everything else is read-only or proposal-only.

## What it is

- An evidence collector for Linux/Docker/Compose hosts (read-only).
- A runbook / proposal generator from collected evidence.
- An approval / mission / apply workflow helper with deterministic gates.
- An audit, export, receipt, and redaction tool.
- A guarded exact-container restart tool (allowlisted / disposable targets).
- A Compose-aware diagnostic, preview, and proposal tool.
- A metadata cleanup tool with archive + fingerprint + confirm gates.

## What it is not

- Not an autopilot.
- Not a platform.
- Not a generic shell or remote-execution agent.
- Not a production Compose orchestrator.
- Not a natural-language mutation agent.
- Not a package / config / firewall / DNS / route mutator.
- Not self-healing infrastructure.

## Workflow spine

```
Evidence
  → Runbook
  → Proposal
  → Approval
  → Rollback / recovery preview
  → Mission checklist + readiness
  → Explicit execute / apply gate (--execute --confirm)
  → Verification
  → Receipt / closure report
  → Export / audit / cleanup
```

Every mutation passes every gate. Asks never execute. Previews never execute.
Proposals never execute. Approvals never execute. Rollback previews never
execute. Status, checklist, report, and export never execute.

## Capabilities (current)

- `diagnose` for docker / logs / errors / network / nginx / performance /
  disk / packages / package / config / changes (read-only).
- Runbooks (`runbook`, `validate-runbook`).
- Approvals queue (`approvals create|list|show|approve|reject|cancel|
  archive|validate|propose-restart|restart-plan`).
- Exact-container restart lane via `apply <approved-proposal> --execute
  --confirm` (allowlisted lab / disposable targets only).
- Mission workflow for restart and Compose-restart (`mission restart …`,
  `mission compose-restart …`).
- Closure reports and mission exports (`mission … report|export|
  validate-export`).
- Audit timeline, validate, index, search (`audit …`).
- Audit-aware incident index and ops status board (`ops status`).
- Export packs and redaction (`export`, `validate-export`).
- Metadata retention and cleanup (`audit retention`, `audit cleanup
  plan|archive|validate|execute|report`) — PR71-hardened archive +
  fingerprint + `--confirm` gate.
- Compose context (`compose inspect|list`).
- Compose service restart preview / proposal / mission lanes
  (`compose restart-preview|propose-restart`, `mission compose-restart …`).
- Compose env-check and env-contract diagnostics (`compose env-check`,
  `compose env-contract`).
- Disposable Compose harness and optional proof orchestrator
  (`scripts/pr67_disposable_compose_harness.sh`,
  `scripts/pr68_disposable_compose_restart_proof.sh`) — external operator
  helpers, not ShellForgeAI execution paths.

## Safety summary

- Asks do not execute. Previews do not execute. Proposals do not execute.
  Approvals do not execute. Rollback previews do not execute. Status,
  checklist, report, export do not execute.
- Mutation requires the explicit CLI workflow with `--execute --confirm`,
  the matching env vars (for Docker restart), and every prior gate green.
- Cleanup execution additionally requires a valid archive whose fingerprint
  matches the plan, plus `--confirm`.
- Compose service restart execution remains disposable / allowlisted only and
  is blocked unless the environment satisfies the env-contract (Compose CLI
  inside the runtime, readable compose file, populated snapshot hash,
  disposable+allow_restart labels).
- Strict JSON for `--json` modes. Failures are clean operator errors, never
  tracebacks for expected failures. Every mutation path writes a receipt.

See [`docs/safety.md`](docs/safety.md) for the full mutation boundary.

V1 release validation can produce a validated readiness packet artifact:
`./scripts/v1_validate.sh --full --packet`.

## V1 hardening lane: Keep It a Knife, Not a Toolbox

ShellForgeAI V1 is a **CLI-first Linux/Docker operator knife**. It safely
inspects Linux/Docker scenes, ranks suspects, builds evidence-backed operator
reports, preserves/exports/compares report artifacts, routes common operator
asks deterministically, and refuses or gates mutation.

- Final V1 release notes: [`docs/V1_RELEASE_NOTES.md`](docs/V1_RELEASE_NOTES.md)
- Release-candidate checklist/evidence gate: [`docs/V1_RELEASE_CANDIDATE.md`](docs/V1_RELEASE_CANDIDATE.md)
- Command surface audit: [`docs/COMMAND_SURFACE_AUDIT.md`](docs/COMMAND_SURFACE_AUDIT.md)
- V2 command contract: [`docs/V2_COMMAND_CONTRACT.md`](docs/V2_COMMAND_CONTRACT.md)
- CLI internals: `cli.py` is the root Typer entrypoint; commands are being
  split into `src/shellforgeai/commands/` one domain at a time
  (PR182: `status`, `doctor`; PR183: `ops report`/`ops status`, `triage`;
  PR185-PR192: `verify`, `handoff`, `propose`, `apply-preview`, governed
  receipt history/audit/export/compare reporting, read-only receipt
  verify/validate/rollback-preview safety surfaces, read-only
  recipe registry/preflight, and the deterministic `ask` command),
  protected by the PR184 command-surface golden guardrail
  (`tests/test_pr184_cli_command_surface_golden.py`)
  — see [`docs/cli.md`](docs/cli.md).

### What this is (V1)

- Read-only runtime health checks (`doctor`, `model doctor`, self-tests).
- V2 read-only status, triage, propose, apply-preview, verify, and handoff
  entrypoints (`status`, `triage`, `triage --target <target>`, `propose`,
  `propose --target <target>`, `apply-preview`, `apply-preview --target
  <target>`, `verify`, `verify --target <target>`, `handoff`, `handoff --save`)
  backed by deterministic Docker triage compatibility commands (`triage docker`,
  `triage docker detail <target>`). `propose` is preview-only: no plan artifact
  and no action executed. `apply-preview` is an execution-boundary preview only:
  no apply, mission, remediation, rollback, cleanup, Docker, or Compose action
  executes. `verify` checks current observed state by default; `verify --receipt
  <receipt_id>` performs read-only governed execution receipt verification for
  an existing recipe receipt without retrying, rolling back, restarting, or
  running Docker/Compose. The top-level `verify` surface is unchanged while its
  handler lives in the CLI command-module split; future CLI refactors should run
  the PR184 command-surface golden guardrail. `handoff` is a read-only
  operator handoff packet whose unchanged surface now lives in the CLI
  command-module split. It summarizes the golden-path posture and first safe
  command; it does not execute fixes or imply remediation happened, and
  `handoff --save` writes only a ShellForgeAI-owned artifact under
  `<data_dir>/v2_handoffs/`. Governed receipt history/audit/export/compare surfaces
  (`recipes receipt history`, `inspect`, `export`, `export-validate`, `compare`,
  `audit`, `integrity`, `explain`, `audit-bundle`, and `audit-bundle-validate`)
  and the read-only receipt safety surfaces (`recipes receipt verify`,
  `validate`, `rollback-preview`, and the top-level `rollback-preview
  --receipt` alias) are also split into command modules with unchanged
  behavior: read-only surfaces remain read-only, export/audit-bundle remain
  bounded ShellForgeAI-owned artifact-only writes, and rollback-preview still
  never executes rollback or recovery.
- Read-only handoff artifact lifecycle (`handoff --save`, `handoff validate
  <handoff_ref>`, `handoff export <handoff_ref>`, `handoff export-validate
  <export_ref>`, each with `--json`). Save/export write only ShellForgeAI-owned
  artifacts (`<data_dir>/v2_handoffs/...`, `<data_dir>/exports/export_...`);
  validate/export-validate are strictly read-only. No collector rerun, model
  call, Docker/Compose mutation, restart, shell, or arbitrary command.
- Read-only handoff history/compare (`handoff history`, `handoff compare
  <before_ref> <after_ref>`, `handoff compare-latest`, each with `--json`;
  compare accepts `--only-changed`/`--include-stable`) to list recent saved
  handoffs and report status/risk/golden-path/safety drift over time. These
  never write artifacts, rerun collectors, call the model, execute shell, or
  mutate Docker/Compose/host state.
- Deterministic operator report lifecycle (`ops report`, `ops report --brief`,
  `--save`, `history`, `compare`, `compare-latest`, `export`,
  `export-validate`, `validate`).
- Deterministic ask routing for common 2AM/operator prompts, including
  mutation refusal.
- Interactive mode accepts selected safe ShellForgeAI command flag forms (for example
  `v1 check --profile quick --json`, `ops report --brief`, `triage --json`,
  and `triage --target <target> --json`) while refusing shell/mutation input.
- Governed remediation **preview/testing** lanes with explicit gates,
  disposable-only proofs, and no casual production mutation.

### What this is not (V1)

- Not an autonomous infrastructure repair agent.
- Not a production remediation bot.
- Not a web UI, secrets manager, SIEM replacement, or monitoring platform.
- Not a tool that runs arbitrary shell from natural language.
- Not a system that casually restarts/deletes/prunes broad infrastructure.

### 5-minute V1 quickstart

```bash
shellforgeai doctor
shellforgeai remediation self-test --profile quick
shellforgeai ops report
shellforgeai ops report --brief
shellforgeai ops report --save
shellforgeai ops report history --limit 5
shellforgeai ops report compare-latest
shellforgeai triage
shellforgeai propose
shellforgeai propose --target <target>
shellforgeai apply-preview
shellforgeai apply-preview --target <target>
shellforgeai verify
shellforgeai handoff
shellforgeai handoff --save
shellforgeai triage --target <target>
shellforgeai triage docker detail <target>  # compatibility detail path
shellforgeai remediation eligibility --target <target> --explain
```

Optional governed/disposable testing only:

```bash
shellforgeai remediation self-test --profile full
```

### Canonical 2AM operator flow

1. `shellforgeai doctor`
2. `shellforgeai remediation self-test --profile quick`
3. `shellforgeai ops report`
4. `shellforgeai ops report --save`
5. `shellforgeai ops report history --limit 5`
6. `shellforgeai ops report compare-latest`
7. `shellforgeai triage`
8. `shellforgeai propose`
9. `shellforgeai apply-preview`
10. `shellforgeai verify`
11. `shellforgeai handoff` (read-only operator handoff; `--save` writes a ShellForgeAI-owned packet)
12. `shellforgeai triage --target <target>` (compatibility: `shellforgeai triage docker detail <target>`)
13. `shellforgeai remediation eligibility --target <target> --explain`
14. Only for intentional disposable-lane testing: `shellforgeai remediation self-test --profile full`

V2 golden path: `status -> triage -> propose -> apply-preview -> verify -> handoff`.

Safety promise: V1 is read-only by default, deterministic ask routes do not
require model availability for safety/refusal paths, and production mutation is
out of scope.

## Install

Requires Python 3.12+.

```bash
git clone https://github.com/SeedOfEvil/ShellForceAI.git
cd ShellForceAI
make dev          # creates .venv and installs in editable mode with dev extras
# or:
pip install -e .
```

The CLI is exposed as both `shellforgeai` and `sfai`.

## Quick start

```bash
shellforgeai status
shellforgeai triage
shellforgeai triage --target <target>
shellforgeai status --json
shellforgeai doctor
shellforgeai model doctor
shellforgeai ops status
shellforgeai diagnose docker --save-plan --with-runbook
shellforgeai runbook --latest
shellforgeai approvals list --all
shellforgeai compose inspect shellforgeai
shellforgeai compose env-check --target shellforgeai
shellforgeai compose env-contract --target shellforgeai
shellforgeai audit retention
shellforgeai audit cleanup plan --category exports --max-age-days 7 --keep-latest 5
```

Read-only `ask` examples:

```bash
shellforgeai ask "what is this machine doing?"
shellforgeai ask "find failed containers and explain likely cause"
shellforgeai ask "show compose context for this restart proposal"
shellforgeai ask "did the restart work?"
shellforgeai ask "audit retention status"
```

`ask` collects evidence for ops-shaped questions and refuses mutation
phrasing with a safety boundary. It never executes; mutation requires the
explicit CLI lane.

## Deeper documentation

- [`docs/v1-scope.md`](docs/v1-scope.md) — V1 scope, release contract, non-goals, and acceptance checklist.
- [`docs/V1_COMMAND_SURFACE.md`](docs/V1_COMMAND_SURFACE.md) — V1 command surface and safety classes.
- [`docs/demo.md`](docs/demo.md) — 5-minute Linux/Docker operator demo with deterministic refusal path.
- [`docs/V1_VALIDATION.md`](docs/V1_VALIDATION.md) — repeatable V1 validation workflow for local and disposable environments.
- [`docs/V1_RELEASE_CANDIDATE.md`](docs/V1_RELEASE_CANDIDATE.md) — V1 release-candidate gate, required checks, artifacts, and Docker01 handoff template.
- [`docs/release-baseline.md`](docs/release-baseline.md) — PR78
  release/handoff baseline after the PR56–PR77 capability arc
  (capabilities, mutation boundary, safety invariants, operator
  workflows, next tracks).
- [`docs/cli.md`](docs/cli.md) — CLI reference, organized by operator workflow.
- [`docs/safety.md`](docs/safety.md) — mutation boundaries and refusal rules.
- [`docs/architecture.md`](docs/architecture.md) — runtime, workflow spine,
  trust and mutation boundaries.
- [`docs/data-layout.md`](docs/data-layout.md) — `/data` layout, artifact
  lifecycle, and retention.
- [`docs/mission-workflow.md`](docs/mission-workflow.md) — exact-container
  restart and Compose service restart missions.
- [`docs/compose-ops.md`](docs/compose-ops.md) — Compose context, preview,
  proposal, env-check / env-contract, and disposable harness.
- [`docs/audit-and-cleanup.md`](docs/audit-and-cleanup.md) — audit timeline,
  exports, retention reporting, and the hardened cleanup gate.
- [`OPS.md`](OPS.md) — operator field guide.
- [`HOMELAB.md`](HOMELAB.md) — Docker01 / homelab state and caveats.
- [`docs/roadmap.md`](docs/roadmap.md) — milestone history and next tracks.
- [`docs/VALIDATION_LANES.md`](docs/VALIDATION_LANES.md) — PR validation lanes
  (fast / targeted / full), the `scripts/validate_pr.py` lane optimizer, the
  Lane C `scripts/run_full_pytest.py` full-validation runner, optional
  `scripts/track_pytest_durations.py` slow-test duration tracking, and the
  `scripts/validation_heartbeat.py` heartbeat that flags interrupted/incomplete
  runs as `rerun_required` instead of a false pass, the read-only
  `scripts/validation_status.py` viewer that classifies a run as
  passed/failed/incomplete/unknown and reports `pass_eligible`/`rerun_required`
  from existing evidence (its `--latest` deterministically prefers recent
  PR-specific run dirs over older persisted manifests, with `--pr`/`--commit`
  filters and `--explain-selection`), and the read-only
  `scripts/validation_env_preflight.py` environment preflight that detects
  missing host dev tools (ruff/pytest/etc.) before validation phases run and
  classifies that as `setup_failure`, never as product test failure, plus the
  `scripts/validation_container_fallback.py` packet generator that turns a
  setup failure into a copy-pasteable disposable validation-container command
  (packet files only — it never runs Docker or installs host packages); see
  [`docs/VALIDATION_MATRIX.md`](docs/VALIDATION_MATRIX.md) for the impact map.

## Using OpenAI Codex / ChatGPT sign-in

ShellForgeAI does not read or manage ChatGPT credentials; authentication is
handled entirely by the Codex CLI.

1. Install Codex CLI: `npm install -g @openai/codex` (or `brew install --cask codex`).
2. Sign in: `codex login` (or `codex login --device-auth` for headless hosts).
3. Configure ShellForgeAI:
   ```bash
   export SHELLFORGEAI_MODEL_PROVIDER=openai-codex
   export SHELLFORGEAI_MODEL_NAME=gpt-5.5
   export SHELLFORGEAI_MODEL_FALLBACK=gpt-5.4
   export SHELLFORGEAI_CODEX_TIMEOUT_SECONDS=180
   ```
4. Verify: `shellforgeai model doctor`
5. Test: `shellforgeai ask "what is this machine doing?"`

See `docs/model-providers.md` for other providers.

## Interactive mode

Run `shellforgeai` (no subcommand) to start the operator loop:

```text
$ shellforgeai
sfai> /help
sfai> diagnose disk
sfai> ask what services are listening on this host?
sfai> /pending
sfai> /summary
sfai> /exit
```

Type `help`, `/help`, `?`, `commands`, or `what can I do?` in the REPL for a
concise list of supported safe commands, follow-ups, report/history helpers,
session handoff summaries, and refused mutation examples. Run `/summary` before
exiting to get a local read-only summary of checks, findings, refusals, artifact
pointers, and the first safe next command; it does not rerun collectors or call
the model. Use `/summary --save` for a portable handoff artifact, then validate,
export, list, or compare it with `shellforgeai session summary validate <id>`,
`shellforgeai session summary export <id>`, `shellforgeai session summary history --limit 5`,
`shellforgeai session summary compare-latest`, and
`shellforgeai session summary compare-export <before-export> <after-export>` for exported
handoff bundles. These summary history/compare commands read existing artifacts
only; they do not rerun collectors, call the model, execute shell, or mutate
Docker/Compose state.
Interactive mode is *not* a shell:
pasted shell-looking input is blocked unless explicitly prefixed with
`ask explain ...` or `ask review ...`.
See [`docs/interactive-mode.md`](docs/interactive-mode.md).

## Project layout

```
src/shellforgeai/
  cli.py              root Typer app wiring; command handlers are split into commands/
  commands/           behavior-preserving Typer command modules
  core/               session, config, profiles, diagnose, evidence, plans,
                      approvals, mission, compose_context, rollback_preview,
                      retention, metadata_hygiene, reference_resolver
  tools/              typed read-only tools
  llm/                provider abstraction (codex, ollama, vllm, …)
  interactive/        REPL, slash commands, workspace trust, streaming
  policy/             risk classes, rules, approvals
  knowledge/          local docs and audit search
  audit/              JSONL audit logger and artifact storage
  render/             rich console rendering
config/               default.yaml, profiles/, tools/
docs/                 architecture, cli, safety, data-layout, mission-workflow,
                      compose-ops, audit-and-cleanup, interactive-mode, …
scripts/              dev / lint / test helpers, disposable Compose harness,
                      disposable Compose restart proof orchestrator
tests/                pytest suite
```

## Configuration

Defaults live in `config/default.yaml`. Override with a YAML file via
`shellforgeai --config path/to/config.yaml`, or with `SHELLFORGEAI_*`
environment variables (see `docs/model-providers.md`).

Profiles in `config/profiles/` decide which risk classes are allowed, asked,
or denied. The active profile is selected with `--profile` or via
`app.default_profile` in config.

## Development

```bash
make dev      # editable install with dev extras
make lint     # ruff + mypy
make test     # pytest
make check    # format + lint + type + tests
```

## License

MIT. See `LICENSE`.

- Run `shellforgeai v1 check` to verify the V1 knife surface.

## V2 governed recipes

`shellforgeai recipes list` exposes the read-only locked toolbox map for future governed actions. The governed restart frontier now stops at a read-only preflight packet for one exact disposable target:

```bash
shellforgeai recipes eligibility --recipe docker.disposable_restart --target <target> --json
shellforgeai recipes preflight --recipe docker.disposable_restart --target <target> --save
shellforgeai recipes preflight validate <preflight_id>
```

Disposable preflight packets may preview `docker restart <target>` as bounded argv only, but they report `execution_available=false`, `command_preview_only=true`, and `command_executed=false`; no container is restarted and no recipe execution lane is enabled.

### Governed disposable recipe execution

ShellForgeAI's first V2 governed execution lane is intentionally narrow: `docker.disposable_restart` may restart exactly one Docker container only when it is labeled `shellforgeai.disposable=true` and `shellforgeai.allow_restart=true`, has a saved valid preflight packet, and the operator passes `--confirm`. The workflow is:

```bash
shellforgeai recipes preflight --recipe docker.disposable_restart --target <target> --save
shellforgeai recipes preflight validate <preflight_id>
shellforgeai recipes execute <preflight_id> --confirm
shellforgeai recipes receipt validate <receipt_id>
shellforgeai verify --receipt <receipt_id>
shellforgeai recipes receipt rollback-preview <receipt_id>
shellforgeai recipes receipt audit --json
shellforgeai recipes receipt integrity --json
shellforgeai recipes receipt integrity --include-exports --include-audit-bundles
shellforgeai recipes receipt audit-bundle --json
shellforgeai recipes receipt audit-bundle-validate <bundle_id> --json
shellforgeai recipes receipt recovery-execute <receipt_id> --confirm
shellforgeai verify --receipt <recovery_receipt_id> --json
```

Natural-language asks still refuse execution. Production targets, broad targets, unlabeled targets, Docker Compose mutation, cleanup, rollback execution, remediation execution, arbitrary shell, and model-driven execution remain out of scope. Receipt audit and rollback-preview are read-only: audit summarizes local execution/recovery receipt chains and flags malformed receipts, missing originals, failed verification, and safety drift without executing anything; rollback-preview explains that `docker.disposable_restart` has no true rollback. Recovery execution is a separate confirm-gated bounded repeat restart of the exact disposable allowlisted target from a valid receipt; it never runs from natural language and never uses Docker Compose.


`shellforgeai recipes receipt explain` converts governed receipt integrity/audit findings into deterministic local guidance with safe read-only next commands. It supports `--json`, `--source integrity|audit|audit-bundle|compare`, `--finding <code>`, `--target`, `--recipe`, and `--limit`; it never repairs/deletes artifacts, executes recipes, restarts containers, calls Docker/Compose, or calls a model.

`shellforgeai recipes receipt integrity` scans existing ShellForgeAI-owned receipt artifacts for integrity drift without executing anything. It checks required files, JSON parsing, manifest/checksum consistency, recovery original links, unsupported shapes, unsafe safety flags, and production restart records; optional `--include-exports` and `--include-audit-bundles` scan existing owned export/support-packet artifacts without creating or repairing them.

For support handoff, `shellforgeai recipes receipt audit-bundle` packages existing local receipt audit/history evidence into a bounded ShellForgeAI-owned artifact under `<data_dir>/exports/receipt-audit-bundles/`. Bundles include JSON, Markdown, manifest, checksums, receipt audit, and receipt history files; validation uses `shellforgeai recipes receipt audit-bundle-validate <bundle_id>`. Bundle create/validate do not execute recipes, rerun receipts, recover, rollback, restart containers, call Docker/Compose, call a model, or perform cleanup/remediation.
