# Interactive mode

Running `shellforgeai` (or `sfai`) with no subcommand launches the operator
REPL. The same loop is available explicitly as `shellforgeai interactive`.

## Banner

The banner shows version + build line, mode/profile, model provider/model,
and workspace path. Build metadata env vars: `SHELLFORGEAI_BUILD_PR`,
`SHELLFORGEAI_BUILD_COMMIT`, `SHELLFORGEAI_BUILD_BRANCH`,
`SHELLFORGEAI_BUILD_DATE`.

## Workspace trust

On first run in a workspace you are asked to trust it. Trust is cached under
the data dir; pass `--no-trust-cache` to re-prompt. Trust grants reads of
workspace docs and writes to the audit/artifact dir under the data dir. It
does **not** lift policy or enable mutation.

## Slash commands

Deterministic. Unknown slash commands never call the model.

```
Session
  /help              Show help
  /exit, /quit       Exit
  /clear             Clear screen

Status
  /status            Runtime summary
  /doctor            ShellForgeAI health
  /health            Machine health checks
  /model             Model provider status
  /workspace         Workspace trust/status
  /mode              Current mode
  /profile           Active profile

Evidence
  /tools             List typed tools (technical names)
  /audit             Latest audit entries
  /evidence          Latest evidence bundle
  /pending           Inspect queued read-only follow-up

Ops
  diagnose <target>  Collect evidence and diagnose
  research <query>   Search local knowledge
  plan <goal>        Conservative read-only plan
  ask <question>     Ask the configured model

Debug
  /raw on|off        Toggle raw provider events
  /context <mode>    Set context mode: minimal | standard | full
  /examples          Example queries
```

## Routing

- Slash commands are deterministic.
- `diagnose ...`, `research ...`, `plan ...`, `ask ...` are explicit.
- Free-form text is classified. Recognized ops intents (disk, performance,
  health, firewall, service, service-discovery) auto-run typed read-only
  collectors before any model call.
- Sluggish/laggy symptoms route to performance diagnostics rather than a
  generic ask.
- Service-discovery questions (services / listening / ports / nginx / ssh /
  docker) route to read-only evidence collection before synthesis.

## Streaming synthesis

After collection, the REPL shows a synthesis status and streams the model
answer when the provider supports it. Normal answers hide internal
collector names; technical names remain in `/tools`, `/evidence`, and
debug/raw output.

## Adaptive read-only follow-ups

When the evidence suggests a deeper read-only pass is useful (CPU/process,
memory/swap, storage/IO, network/DNS, service health, or a general context
pass), the REPL queues it. Confirm with `yes`, `proceed`, `dig deeper`,
`y`, or `run it`. Inspect the queue with `/pending`. If nothing is queued,
a confirmation phrase prints a helpful "no pending" message instead of
calling the model. Follow-ups are read-only.

## Paste guard

The REPL is not a shell. Pasted shell-looking input is blocked unless
prefixed with `ask explain ...` or `ask review ...`. After a multi-line
shell paste, a short-lived quarantine blocks follow-on shell fragments
without calling the model; `/help` and `/exit` continue to work.

## Safety

- No destructive execution.
- No package install or service restart.
- `apply` is validation-only.
- Model output is advisory.
- In restricted containers the Codex CLI may emit `bwrap`/namespace
  errors; that is a provider sandbox limitation, not a host failure, and
  the typed read-only tools keep working.
