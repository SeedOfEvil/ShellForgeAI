# Safety

ShellForgeAI is built to be safe by construction. The runtime does not run
arbitrary shell, does not mutate the host without policy approval, and
treats model output as advisory.

## Boundaries

- **No arbitrary shell.** Tools are typed wrappers around specific binaries
  with bounded arguments. The interactive REPL is not a shell; pasted
  shell-looking input is blocked unless explicitly prefixed with
  `ask explain ...` or `ask review ...`. A short-lived quarantine blocks
  follow-on shell fragments after a multi-line paste; `/help` and `/exit`
  still work.
- **`apply` is validation-only.** It parses and validates plan JSON and
  exits. It never executes plan steps in this alpha.
- **No package installs, no service restarts** initiated by the runtime.
  Service-impacting commands are described as approval-required and
  operator-run.
- **Workspace trust is scoped.** Trusting a workspace allows reading
  workspace docs and writing artifacts/audit under the data dir. It does
  not lift policy, enable mutation, or bypass approval gates.
- **Slash commands are deterministic.** Unknown slash commands never call
  the model.
- **Read-only follow-ups only.** Adaptive follow-ups (CPU/process,
  memory/swap, storage/IO, network/DNS, service health, general context)
  use the same typed read-only collectors as the initial pass.

## Profiles and risk classes

See `docs/profiles.md`. Risk classes are `read`, `change`, `service`,
`system`, `danger`. Profiles map each class to `allow`, `ask`, or `deny`.

## Containers

In restricted containers, the Codex CLI may emit `bwrap`/namespace errors.
Treat that as a provider sandbox limitation, not a host failure.
ShellForgeAI's typed read-only collectors continue to work; only model
synthesis is affected.
