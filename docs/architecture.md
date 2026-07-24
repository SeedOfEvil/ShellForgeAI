# Architecture

## V1 architecture contract

CLI → collectors → triage → ops reports → artifacts → governed remediation.

- **CLI entrypoints** perform deterministic routing for explicit subcommands and
  known safety prompts.
- **Collectors** are typed read-only evidence collectors.
- **Triage** ranks suspects deterministically for common Docker/operator scenes.
- **Ops reports** summarize ranked incidents and safe next commands.
- **Artifacts** preserve/save/validate/export/compare report outputs.
- **Governed remediation** remains explicit, gated, and disposable-oriented; not
  casual production automation.

### Safety boundaries

- Read-only default posture.
- Deterministic natural-language mutation refusal.
- No arbitrary shell execution.
- Mutation paths require explicit gated CLI lanes.

### Ask routing boundaries

- Slash commands are deterministic and unknown slash commands do not call the model.
- Recognized operator asks route to deterministic report/triage/refusal paths.
- Deterministic safety routes do not depend on model availability.

### Artifact lifecycle

Ops reports support save, validate, history, compare, compare-latest, export,
and export-validate to preserve and hand off evidence-backed state over time.

ShellForgeAI is structured around a strict separation between **deterministic
runtime** (typed read-only tools, evidence, plans, audit) and **advisory model
synthesis** (LLM providers).

## Layers

```
                ┌──────────────────────────────────────┐
   user input → │  CLI (typer) / Interactive REPL      │
                └──────────────┬───────────────────────┘
                               │
                ┌──────────────▼───────────────────────┐
                │  Core runtime                        │
                │  config · profiles · session         │
                │  diagnose · evidence · plans         │
                │  collectors · instructions · errors  │
                └─────┬─────────────────────────┬──────┘
                      │                         │
        ┌─────────────▼─────┐         ┌─────────▼────────┐
        │  Tools (typed,    │         │  LLM providers   │
        │  read-only):      │         │  codex / ollama  │
        │  host · journal · │         │  vllm / openai-  │
        │  systemd · disk · │         │  compatible /    │
        │  network · ...    │         │  openrouter      │
        └─────────────┬─────┘         └─────────┬────────┘
                      │                         │
                ┌─────▼─────────────────────────▼──────┐
                │  Policy · Audit · Knowledge · Render │
                └──────────────────────────────────────┘
```

## Modules

| Path | Purpose |
| --- | --- |
| `core/config.py` | YAML + env settings (`pydantic-settings`). |
| `core/approved_change_contract.py` | Inert Stage B immutable approved-change subject, attestation binding, canonical hash, and read-only validation; not wired into CLI, proposals, approvals, recipes, persistence, preflight, or execution. |
| `core/approved_change_compatibility.py` | In-memory findings-only PR310 assessment of legacy Proposal schema v1 against PR309 contract requirements; creates no contract, loads no files, and is not wired into CLI, approval flow, persistence, recipes, preflight, or execution. |
| `core/profiles.py` | Risk-class allow/ask/deny profiles. |
| `core/session.py` | Session id, data dir, artifact dir. |
| `core/context.py` | `RuntimeContext` carried through CLI handlers. |
| `core/diagnose.py` | Target classification → collectors → findings → plan. |
| `core/evidence.py` | Evidence model and target classification. |
| `core/plans.py` | `Plan` / `PlanStep` schemas. |
| `core/collectors.py` | Read-only collectors per intent. |
| `tools/*` | Typed read-only tools (`host`, `journal`, `systemd`, `disk`, `network`, `firewall`, `packages`, `services`, `process`, `containers`, `logs`, `storage`, `system`, `files`). |
| `tools/registry.py` | Tool catalog, risk class, schema. |
| `llm/manager.py` | Provider factory. |
| `llm/codex*.py` | OpenAI Codex CLI subprocess provider with JSON event stream parsing. |
| `llm/ollama.py`, `llm/vllm.py`, `llm/openai_compatible.py`, `llm/openrouter.py` | Alternative providers. |
| `llm/prompts.py` · `llm/system_prompt.py` | Canonical system prompt + contextual prompt assembly. |
| `interactive/repl.py` | Operator REPL, slash commands, routing. |
| `interactive/streaming.py` | Streaming synthesis. |
| `interactive/workspace.py` · `guards.py` | Trust prompt, paste guard, quarantine. |
| `policy/*` | Risk classes, rules engine, approval gates. |
| `audit/*` | JSONL audit log + artifact storage. |
| `knowledge/*` | Local docs / audit search; optional web. |
| `render/*` | Rich console rendering and tables. |

## Request flow (interactive ops question)

1. REPL classifies input. Slash commands are deterministic and never call
   the model. Shell-looking pasted input is blocked unless prefixed with
   `ask explain` / `ask review`.
2. For recognized ops intents (disk / performance / health / firewall /
   service / service-discovery), the runtime runs the matching read-only
   collectors and assembles an evidence bundle.
3. The canonical ShellForgeAI system prompt + the evidence bundle + the
   operator question are sent to the configured provider.
4. The model's synthesis is streamed back. A deeper read-only follow-up is
   queued when warranted; `yes` / `proceed` / `dig deeper` / `run it`
   executes it. `/pending` shows the queue.
5. An audit record (session id, command, tools called, artifacts, warnings,
   summary) is appended; artifacts are written to the session artifact dir
   only when produced.

## Workflow spine

```
Evidence
  → Runbook
  → Proposal
  → Approval
  → Rollback / recovery preview
  → Mission checklist + readiness
  → Explicit execute / apply gate
  → Verification
  → Receipt / closure report
  → Export / audit / cleanup
```

Each step writes its artifact under `<data_dir>` (see
[`data-layout.md`](data-layout.md)). Each step refuses to advance unless
the prior step's artifact exists and validates. No step skips ahead, no
step retries automatically, and no step executes the next step on the
operator's behalf.

## Trust boundary

- ShellForgeAI inspects within its configured runtime access only.
- It must not assume host/systemd facts when running inside a container.
  Container limits surface as visibility limitations, never as
  fabricated host health claims.
- It distinguishes container runtime boundaries, Docker state, Compose
  metadata (advisory only), package DB visibility, labels, mounts,
  logs, and its own artifacts.
- Workspace trust grants doc reads and artifact writes under the data
  dir. It never lifts policy, enables mutation, or bypasses gates.

## Approved-change contract boundary

`core/approved_change_contract.py` is an isolated Stage B domain module. It grants no execution eligibility and exists only to provide a stable approval-bound identity for later reviewed integration. It is not connected to current proposal objects, approval transitions, action compilation, recipes, persistence, receipts, CLI commands, preflight, or execution lanes.

`core/approved_change_compatibility.py` is a separate compatibility-boundary module. It performs only in-memory findings assessment of legacy Proposal schema v1; it does not create an approved-change subject, attestation, contract, proposal mutation, adapter, migration, file loader, persistence record, recipe/preflight hook, receipt, CLI command, or execution path. Current Proposal behavior and mutation lanes are unchanged.

## Mutation boundary

The runtime never calls `subprocess` for arbitrary shell. Tools wrap
specific binaries with bounded args via `util.subprocess`. Only three
narrow mutation lanes exist; everything else is read-only.

1. **ShellForgeAI-owned metadata cleanup.** `audit prune` (PR46) and
   `audit cleanup execute` (PR55 + PR71-hardened). Deletes
   ShellForgeAI-owned metadata under `<data_dir>` only. PR71 requires a
   matching validated archive whose fingerprint matches the plan, plus
   `--confirm`.
2. **Exact-container Docker restart.** `apply <approved-proposal>
   --execute --confirm` (PR47/PR48/PR49). Exactly one `docker restart
   <allowlisted-container>`. Allowlist disabled by default; env-gated.
3. **Compose service restart (disposable-only).** `mission compose-restart
   execute <id> --execute --confirm` (PR63+). Exactly one
   `docker compose ... restart <service>` against a disposable +
   allow_restart labelled target, only when the env-contract is fully
   satisfied. Blocked by default in production deployments — this is the
   intended posture.

What ShellForgeAI does not mutate, ever:

- `docker compose up/down/recreate`, `docker stop|start|kill|rm|exec|run`,
  Docker volume/network/image commands.
- `systemctl` / service control.
- `apt`/`yum`/`dnf`/`apk`/`pip` package operations.
- chmod / chown / rm / mv / cp on arbitrary paths.
- firewall / route / DNS / interface changes.
- Generated operator scripts or arbitrary shell strings.

## Data and artifact flow

See [`data-layout.md`](data-layout.md) for the full table. Each
artifact class has a single command that creates it, a defined set of
commands that read or refresh it, and an explicit mutation/non-mutation
posture.

## Design principles

- Read-only first; preview before proposal; proposal before approval.
- Approval before mission; rollback/recovery preview before any execute
  step; explicit `--confirm` before any mutation.
- Verify after mutation; write a receipt; preserve a tamper-evident
  audit trail.
- Refuse natural-language mutation. The only execution paths are the
  explicit CLI lanes above.
- Boring on purpose. Small sharp tool, not a broad control plane.
