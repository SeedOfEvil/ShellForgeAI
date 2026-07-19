# North star

ShellForgeAI exists to give Linux operators an AI assistant that is
**useful, auditable, and safe by construction** — never the opposite.

## Principles

1. **Evidence before opinion.** For every recognized ops intent, run typed
   read-only collectors first; only then ask the model to synthesize.
2. **Read-only by default.** Mutation is policy-gated; destructive operations
   require an explicit lab/break-glass posture; `apply` is validation-only
   and does not execute operator commands.
3. **Auditable everything.** Every session writes a JSONL record of what
   tools ran, what artifacts were produced, and what was decided.
4. **Operator UX.** Hide internal collector names from normal answers; keep
   technical names available in `/tools`, `/evidence`, debug, and raw views.
5. **Pluggable model, single contract.** Providers expose one interface;
   the runtime owns context, tools, and policy.
6. **No surprise execution.** Slash commands are deterministic. Unknown
   slash commands never call the model. Pasted shell never executes.
