# Interactive mode

Running `shellforgeai` with no subcommand launches interactive mode.

- Banner shows version, mode/profile, model provider/model, workspace.
- Workspace trust prompt is required unless previously trusted in data-dir cache.
- Slash commands: `/help`, `/exit`, `/quit`, `/doctor`, `/model`, `/tools`, `/audit`, `/workspace`, `/mode`, `/profile`, `/clear`, `/raw on|off`, `/context minimal|standard|full`.
- Natural routing: `diagnose ...`, `research ...`, `plan ...`, otherwise `ask`.
- Spinner/status is shown while processing model-backed and evidence-backed requests.

Safety:
- No destructive execution.
- No package install or service restart.
- Apply remains validation-only.
- Model output is advisory.

PR7: ShellForgeAI interactive banner now includes rotating quotes; build metadata env vars SHELLFORGEAI_BUILD_PR/SHELLFORGEAI_BUILD_COMMIT/SHELLFORGEAI_BUILD_BRANCH/SHELLFORGEAI_BUILD_DATE supported; /status and /examples added; artifacts are created on write only; apply remains validation-only; workspace trust does not bypass policy; canonical ShellForgeAI system prompt is required for model-backed flows.

- Note: In restricted containers, Codex may emit bwrap/namespace errors; treat as provider sandbox limitation, not host failure. ShellForgeAI still collects evidence via typed read-only tools.
\n## Interactive guardrails update\n- Interactive mode is not a shell; shell-looking pasted input is blocked unless explicitly prefixed with ask explain/review.
- Multiline shell paste recovery uses a short-lived quarantine: subsequent shell fragments are blocked without model calls, while /help and /exit still work.\n- Slash commands are deterministic and unknown slash commands do not call the model.\n- Added /health and /audit latest interactive commands.\n- Apply remains validation-only; workspace trust does not bypass mutation policy.\n- Service-impacting commands must be described as approval-required/operator-run.\n

## Context-first + Codex provider note (PR)
- ShellForgeAI runtime auto-runs approved typed read-only collectors for recognized ops intents (disk/performance/health/firewall/service).
- In current architecture, Codex is used as a model/provider for synthesis; ShellForgeAI tools are executed by the ShellForgeAI runtime.
- Runtime context bundles are the immediate solution; optional MCP exposure of read-only tools is a future path.
- Arbitrary shell remains blocked in interactive mode.
- Mutating/service-impacting actions remain blocked or approval-required/operator-run.
- apply remains validation-only in this alpha.

- Natural-language diagnostic questions now collect evidence and then produce a human-readable assessment (facts, clues, missing evidence, safe next steps), while explicit `diagnose <target>` remains artifact-oriented.
## Update: streaming synthesis and service-discovery routing\n- Interactive diagnostics now show a post-collection synthesis status and stream model answers when supported.\n- Service-discovery questions (services/listening/ports/nginx/ssh/docker) route to read-only evidence collection before synthesis.\n- Safety boundaries are unchanged: no arbitrary shell execution, no destructive execution, and apply remains validation-only.\n
