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

## Tester-scoped CODEX_HOME readiness (PR289)

When a `CODEX_HOME` environment variable is present in the process (for
example a QA lane running as a service account whose profile does not own the
Codex auth state), provider readiness no longer depends on the
profile-default `~/.codex/auth.json` path. Instead, `model doctor` and
`CodexProvider.available()` verify readiness with a safe command-level check:
the resolved Codex CLI is run with `login status` in the inherited process
environment, and login is proven only by exit code 0 plus
`Logged in using ChatGPT` on stdout or stderr. Doctor output reports
`codex_home_configured`, `login_status_checked`, `login_status_ok`,
`login_status_source=codex_login_status`, `codex_resolved_binary`, and
`auth_cache_contents_inspected=false`; readiness is `verified_login_status`
when proven and `login_status_not_proven` otherwise, never
`missing_auth_cache` solely because the current profile lacks the cache. The
`--live-probe` lane treats proven login status as configured credentials.
`CODEX_HOME` is only inherited by Codex CLI child processes — ShellForgeAI
never hardcodes a user-specific value and never reads, copies, prints,
archives, or parses auth-cache/token contents. Without `CODEX_HOME`, the
existing default-profile behavior is unchanged. Codex model calls
(`codex exec`) already inherit the process environment, so the same
tester-scoped `CODEX_HOME` governs model-assisted synthesis.
