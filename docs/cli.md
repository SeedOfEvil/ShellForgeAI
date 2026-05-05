placeholder

## Interactive CLI mode

`shellforgeai` with no subcommand starts interactive mode with workspace trust confirmation, slash commands, natural routing, status spinner, and clean model output.

PR7: ShellForgeAI interactive banner now includes rotating quotes; build metadata env vars SHELLFORGEAI_BUILD_PR/SHELLFORGEAI_BUILD_COMMIT/SHELLFORGEAI_BUILD_BRANCH/SHELLFORGEAI_BUILD_DATE supported; /status and /examples added; artifacts are created on write only; apply remains validation-only; workspace trust does not bypass policy; canonical ShellForgeAI system prompt is required for model-backed flows.
\n## Interactive guardrails update\n- Interactive mode is not a shell; shell-looking pasted input is blocked unless explicitly prefixed with ask explain/review.
- Multiline shell paste recovery uses a short-lived quarantine: subsequent shell fragments are blocked without model calls, while /help and /exit still work.\n- Slash commands are deterministic and unknown slash commands do not call the model.\n- Added /health and /audit latest interactive commands.\n- Apply remains validation-only; workspace trust does not bypass mutation policy.\n- Service-impacting commands must be described as approval-required/operator-run.\n

## Context-first + Codex provider note (PR)
- ShellForgeAI runtime auto-runs approved typed read-only collectors for recognized ops intents (disk/performance/health/firewall/service).
- In current architecture, Codex is used as a model/provider for synthesis; ShellForgeAI tools are executed by the ShellForgeAI runtime.
- Runtime context bundles are the immediate solution; optional MCP exposure of read-only tools is a future path.
- Arbitrary shell remains blocked in interactive mode.
- Mutating/service-impacting actions remain blocked or approval-required/operator-run.
- apply remains validation-only in this alpha.
## Update: streaming synthesis and service-discovery routing\n- Interactive diagnostics now show a post-collection synthesis status and stream model answers when supported.\n- Service-discovery questions (services/listening/ports/nginx/ssh/docker) route to read-only evidence collection before synthesis.\n- Safety boundaries are unchanged: no arbitrary shell execution, no destructive execution, and apply remains validation-only.\n

- New diagnose aliases: performance|slow|slowness|host, storage|disk-performance|io|iowait, services|service-discovery|ports.

## PR8 adaptive follow-ups
- Natural-language diagnostics now offer an evidence-driven deeper read-only follow-up (CPU/process, memory/swap, storage/I-O, network/DNS, service health, or general context pass).
- Interactive confirmations (`yes`, `proceed`, `dig deeper`, `y`, `run it`) execute the pending read-only follow-up and clear it.
- Normal UX avoids internal collector names; `/tools` and debug/raw remain technical views.
- Safety unchanged: no arbitrary shell execution, no destructive execution, and apply remains validation-only.

## PR9 follow-up reliability fixes
- Sluggish/laggy natural-language symptoms now route to performance diagnostics instead of generic ask.
- Added `/pending` to inspect queued deeper read-only investigation state.
- Confirmation phrases run pending follow-up when queued; otherwise a helpful no-pending message is shown.
- Normal synthesized answers hide collector names and keep technical names in evidence/debug surfaces.
- Safety unchanged: read-only follow-ups only, no arbitrary shell execution, apply remains validation-only.
