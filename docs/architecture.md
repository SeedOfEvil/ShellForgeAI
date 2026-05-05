# Architecture

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

## Safety boundary

- The runtime never calls `subprocess` for arbitrary shell. Tools wrap
  specific binaries with bounded args via `util.subprocess`.
- Mutating actions are policy-gated. `apply` validates plan JSON and
  returns; it never executes steps.
- Workspace trust is scoped to read workspace docs and write artifacts /
  audit under the data dir. It does not change policy.
