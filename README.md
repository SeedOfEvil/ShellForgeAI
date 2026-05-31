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

### What this is (V1)

- Read-only runtime health checks (`doctor`, `model doctor`, self-tests).
- Deterministic Docker triage and deep detail (`triage docker`,
  `triage docker detail <target>`).
- Deterministic operator report lifecycle (`ops report`, `ops report --brief`,
  `--save`, `history`, `compare`, `compare-latest`, `export`,
  `export-validate`, `validate`).
- Deterministic ask routing for common 2AM/operator prompts, including
  mutation refusal.
- Interactive mode accepts selected safe ShellForgeAI command flag forms (for example
  `v1 check --profile quick --json`, `ops report --brief`, and
  `triage docker detail <target> --json`) while refusing shell/mutation input.
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
shellforgeai triage docker detail <target>
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
7. `shellforgeai triage docker detail <target>`
8. `shellforgeai remediation eligibility --target <target> --explain`
9. Only for intentional disposable-lane testing: `shellforgeai remediation self-test --profile full`

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
sfai> /exit
```

Type `help`, `/help`, `?`, `commands`, or `what can I do?` in the REPL for a
concise list of supported safe commands, follow-ups, report/history helpers,
and refused mutation examples. Interactive mode is *not* a shell: pasted
shell-looking input is blocked unless explicitly prefixed with `ask explain ...`
or `ask review ...`. See [`docs/interactive-mode.md`](docs/interactive-mode.md).

## Project layout

```
src/shellforgeai/
  cli.py              Typer entry points
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
