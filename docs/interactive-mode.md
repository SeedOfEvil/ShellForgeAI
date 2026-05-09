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
- Service and service-health questions (e.g., nginx/ssh/docker status, restart requests, listening ports) route to read-only service investigation evidence before synthesis.
- Log/error questions (e.g. "any errors?", "check logs", "why is nginx
  failing?", "ssh login failing", "permission denied") route to read-only
  log investigation. Requests to delete, truncate, or rotate logs are
  refused; ShellForgeAI collects read-only log evidence instead.

## Streaming synthesis

After collection, the REPL shows a synthesis status and streams the model
answer when the provider supports it. Normal answers hide internal
collector names; technical names remain in `/tools`, `/evidence`, and
debug/raw output.

## Friendly mini-report style

Natural-language answers favor short calm sections (`## Assessment`,
`## What I found`, `## Best read`, `## Safe next step`) over bullet dumps
or repeated safety boilerplate. The on-disk `summary.md` mirrors that
shape — verdict, key evidence, findings, and an artifacts list that only
references files actually written.

The "Collected N read-only evidence item(s)" line, the `Evidence: N` line
in the diagnose footer, and the `Evidence count` line inside `summary.md`
are taken from the same persisted `evidence.json` so the numbers always
agree.

The polite `what did you check?` answer mentions the categories inspected
and only the artifact files that exist on disk for the current session.
Use `what tools did you use?` to see the raw collector names.

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

- Disk-space breakdown queries (e.g., "what is using disk space?") trigger bounded `disk.top_dirs` read-only collection.

Deterministic findings are severity-aware (`critical`, `warning`, `info`, `limitation`). Container-only gaps (for example missing `systemctl`/`journalctl` in Docker) are reported as limitations, not direct faults.


Service inventory follow-ups (`proceed`/`dig deeper` after service-discovery questions) run listener/process/service-manager evidence collection, not a generic health-only pass.


Action-style service requests (for example `restart <service>`) trigger an immediate read-only service check first, then return a safety boundary response (no mutation execution).


For service action follow-ups, ShellForgeAI preserves the detected target service (for example nginx or shellforgeai) so `dig deeper` stays target-specific rather than generic inventory-only.


If a queued follow-up times out or fails, ShellForgeAI reports the failure safely, keeps the REPL alive, and `/pending` remains readable with last error state.


## Runtime hygiene notes

- `/pending` is local/state-only and does not call model providers or collectors.
- Follow-up timeouts and interruptions are handled safely; the REPL remains usable and returns to `sfai>`.
- Exiting the REPL (`/exit` or Ctrl-D) performs ShellForgeAI-owned model subprocess cleanup.


Pending network follow-ups preserve the original target context. When a
user asks a network question — for example `can this server reach
example.com:443?`, `can you open port 443?`, or `check DNS for
example.com` — the queued follow-up records `type=network`, the detected
`subtype` (`reachability`, `port-open`, `listener`, `dns`, `firewall`),
and any `target_host`, `target_port`, or `target_domain` parsed from the
question. `/pending` displays this target alongside the label, and
`proceed` runs a target-specific read-only deep dive that reuses the same
host/port/domain instead of a generic network pass.
