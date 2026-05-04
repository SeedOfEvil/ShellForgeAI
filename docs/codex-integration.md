# Codex integration (current + future)

## Current architecture (provider mode)
- ShellForgeAI can call Codex as a model/provider for analysis text generation.
- ShellForgeAI typed tools/collectors are executed by the ShellForgeAI runtime.
- Therefore, ShellForgeAI must collect context first for known intents before sending prompts.

## Why context-first routing is required
Passing collector names in a prompt is not equivalent to tool availability. Without runtime collection (or an exposed tool interface), the model cannot reliably execute those collectors.

## Immediate approach
- Use runtime intent routing + context bundles (`disk`, `performance`, `health`, `firewall`, service diagnostics).
- Provide already-collected evidence block in model prompts.
- Keep arbitrary shell blocked.
- Keep mutation blocked/approval-required.
- Keep `apply` validation-only in alpha.

## Future optional approach (experimental, disabled by default)
Proposed command: `shellforgeai mcp serve --readonly`

Proposed read-only MCP tools:
- `shellforgeai_health`
- `shellforgeai_diagnose_disk`
- `shellforgeai_diagnose_performance`
- `shellforgeai_diagnose_firewall`
- `shellforgeai_diagnose_service`
- `shellforgeai_audit_recent`

Mutating tools are explicitly excluded from the initial MCP surface.

## PR8 adaptive follow-ups
- Natural-language diagnostics now offer an evidence-driven deeper read-only follow-up (CPU/process, memory/swap, storage/I-O, network/DNS, service health, or general context pass).
- Interactive confirmations (`yes`, `proceed`, `dig deeper`, `y`, `run it`) execute the pending read-only follow-up and clear it.
- Normal UX avoids internal collector names; `/tools` and debug/raw remain technical views.
- Safety unchanged: no arbitrary shell execution, no destructive execution, and apply remains validation-only.
