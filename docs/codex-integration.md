# Codex integration (current + future)

## Current architecture (provider mode)

- ShellForgeAI calls the Codex CLI as a model/provider for analysis text
  generation.
- ShellForgeAI's typed tools and collectors are executed by the
  ShellForgeAI runtime — never by Codex.
- Therefore ShellForgeAI must collect context first for known intents
  before sending prompts.

## Why context-first routing is required

Naming a collector inside a prompt is not equivalent to giving the model
tool access. Without runtime collection (or an exposed tool interface) the
model cannot reliably execute those collectors.

## Immediate approach

- Runtime intent routing + context bundles for `disk`, `performance`,
  `health`, `firewall`, and service diagnostics.
- Already-collected evidence is included in the prompt.
- Arbitrary shell stays blocked.
- Mutation stays blocked or approval-required.
- `apply` is validation-only in this alpha.
- Model subprocesses must use bounded timeouts and explicit cleanup/reaping;
  failures/timeouts should return safely without hanging the REPL.

## Future optional approach (experimental, disabled by default)

Proposed command: `shellforgeai mcp serve --readonly`.

Proposed read-only MCP tools:

- `shellforgeai_health`
- `shellforgeai_diagnose_disk`
- `shellforgeai_diagnose_performance`
- `shellforgeai_diagnose_firewall`
- `shellforgeai_diagnose_service`
- `shellforgeai_audit_recent`

Mutating tools are explicitly excluded from the initial MCP surface.

## Adaptive read-only follow-ups

Natural-language diagnostics may queue an evidence-driven deeper read-only
follow-up (CPU/process, memory/swap, storage/IO, network/DNS, service
health, or a general context pass). Confirm with `yes`, `proceed`, `dig
deeper`, `y`, or `run it`. Normal answers hide internal collector names;
technical names remain in `/tools` and debug/raw views. Safety unchanged:
no arbitrary shell, no destructive execution, `apply` validation-only.


## Model doctor explicit probe

Codex remains a synthesis provider, not a ShellForgeAI tool executor. Default
`shellforgeai model doctor` does not call Codex or the network. The explicit
`--live-probe` flag performs one fixed, bounded readiness/auth probe through the
existing provider path, with no operator-provided prompt text, no tool execution,
and no mutation.
