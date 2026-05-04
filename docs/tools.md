placeholder

## Context-first + Codex provider note (PR)
- ShellForgeAI runtime auto-runs approved typed read-only collectors for recognized ops intents (disk/performance/health/firewall/service).
- In current architecture, Codex is used as a model/provider for synthesis; ShellForgeAI tools are executed by the ShellForgeAI runtime.
- Runtime context bundles are the immediate solution; optional MCP exposure of read-only tools is a future path.
- Arbitrary shell remains blocked in interactive mode.
- Mutating/service-impacting actions remain blocked or approval-required/operator-run.
- apply remains validation-only in this alpha.
## Update: streaming synthesis and service-discovery routing\n- Interactive diagnostics now show a post-collection synthesis status and stream model answers when supported.\n- Service-discovery questions (services/listening/ports/nginx/ssh/docker) route to read-only evidence collection before synthesis.\n- Safety boundaries are unchanged: no arbitrary shell execution, no destructive execution, and apply remains validation-only.\n

## Investigation package (read-only)
- Added collectors: system.pressure, process.snapshot, storage.context, storage.pressure, storage.error_summary.
- Diagnose aliases include slow/slowness/host and storage io targets; apply remains validation-only.

## PR8 adaptive follow-ups
- Natural-language diagnostics now offer an evidence-driven deeper read-only follow-up (CPU/process, memory/swap, storage/I-O, network/DNS, service health, or general context pass).
- Interactive confirmations (`yes`, `proceed`, `dig deeper`, `y`, `run it`) execute the pending read-only follow-up and clear it.
- Normal UX avoids internal collector names; `/tools` and debug/raw remain technical views.
- Safety unchanged: no arbitrary shell execution, no destructive execution, and apply remains validation-only.
