# CLI reference

ShellForgeAI is exposed as `shellforgeai` and `sfai`.

## Global options

```
shellforgeai [--config PATH] [--profile NAME] [--mode NAME]
             [--verbose] [--no-trust-cache]
             [--version]
             <command> [args]
```

Running with no `<command>` enters interactive mode (see
`docs/interactive-mode.md`).

## Commands

| Command | Purpose |
| --- | --- |
| `interactive` | Same as launching with no subcommand. `--no-trust-cache` forces re-prompt of workspace trust. |
| `version` | Print version + build line if available. |
| `doctor` | Show ShellForgeAI runtime health (version, profile, data dir, tool count, model provider). |
| `diagnose <target>` | Collect evidence and propose a conservative plan. Options: `--online`, `--since 30m`, `--save-plan`, `--json`, `--model`, `--raw`, `--full-context`. Writes `evidence.json`, `summary.md` (a friendly mini-report whose evidence count matches `evidence.json`), and `plan.json` when `--save-plan`. The CLI footer only references `model-response.md` when `--model` actually wrote it. Aliases for target include `performance\|slow\|slowness\|host`, `storage\|disk-performance\|io\|iowait`, `services\|service-discovery\|ports`. |
| `research <query>` | Search local knowledge (`SHELLFORGE.md`, `knowledge.local_paths`). With `--model`, ask the provider to synthesize from hits. |
| `plan <goal>` | Emit a deterministic conservative plan JSON. With `--model`, attach a model review. |
| `apply <plan.json>` | Validation-only in this alpha — parses and exits. |
| `runbook [<evidence.json>] [--latest] [--session SID]` | Build an operator-run remediation runbook from existing read-only evidence. Writes `runbook.md` and schema-versioned `runbook.json` next to the evidence. ShellForgeAI does not execute any of the steps; mutating commands are clearly labelled `OPERATOR-RUN` / `REQUIRES APPROVAL` / `SERVICE-IMPACTING`. `diagnose <target> --with-runbook` writes the same artifacts as part of a fresh diagnose run. |
| `validate-runbook [<runbook.json-or-session-dir>] [--latest]` | Validate `runbook.json` schema + safety/risk rules (read-only). Supports direct `runbook.json`, session directory, or `--latest`. Exit code `0` valid, `1` invalid/missing. |
| `ask <question>` | Free-form ask. Options: `--context standard\|minimal\|full`, `--full-context`, `--raw`, `--no-evidence`, `--since 30m`. For recognized ops-shaped questions (e.g. "find failed containers", "network reachability is broken", "why can the service not write to disk?") `ask` reuses the same read-only routing and evidence collection as `diagnose`, writes `evidence.json` + `ask-summary.md`, and answers from the evidence. For network/reachability questions ("upstream unreachable", "DNS errors in logs", "connection refused errors", "why is bad-network failing?", with typo tolerance) `ask` collects combined Docker/log + runtime network evidence and ranks app/container log themes (DNS, upstream, connection refused, timeout, TLS) above runtime network basics — a healthy DNS resolver/default route does NOT cancel an app/container log showing reachability failure. Fix-plan / runbook intents ("give me a safe fix plan for the failed containers", "what should I do next?", "fix bad-network safely", "create a runbook", with typo tolerance) also write `runbook.md` and `runbook.json` next to the evidence. Use `--no-evidence` to force plain model Q&A. `ask` never mutates: a mutation-style request (e.g. "can you restart nginx?", "open port 443", "change DNS") collects read-only evidence and prints a safety boundary. |
| `inspect host` | Host info / resources / uptime. |
| `inspect service <unit>` | `systemctl status` of a unit. |
| `logs <unit> [--since 30m]` | `journalctl -u <unit> --no-pager`. |
| `tools list` | List typed tools, category, and risk class. |
| `tools describe <name>` | Print tool metadata as JSON. |
| `audit list` | List audit session ids. |
| `audit show <session_id>` | Show a session's JSON record. |
| `model doctor` | Provider doctor. Shows whether `codex` and auth cache are present and suggests `codex login` when missing. |
| `model test [prompt]` | One-shot model call. Options: `--raw`, `--timeout`, `--model`. |

## Notable env vars

- `SHELLFORGEAI_MODEL_PROVIDER`, `SHELLFORGEAI_MODEL_NAME`,
  `SHELLFORGEAI_MODEL_FALLBACK`.
- `SHELLFORGEAI_CODEX_BINARY`, `SHELLFORGEAI_CODEX_TIMEOUT_SECONDS`,
  `SHELLFORGEAI_CODEX_SKIP_GIT_REPO_CHECK`.
- `SHELLFORGEAI_BUILD_PR`, `SHELLFORGEAI_BUILD_COMMIT`,
  `SHELLFORGEAI_BUILD_BRANCH`, `SHELLFORGEAI_BUILD_DATE`.

## Safety

`apply` does not execute. Workspace trust does not lift policy.
Service-impacting commands are described as approval-required and
operator-run; ShellForgeAI does not run them.

`diagnose` now reports findings by severity in the terminal summary so informational limitations are not overstated as incidents.


When `--json` is used (for commands that support it), stdout is machine-readable JSON only (no tables/markup), suitable for `json.loads`/`python -m json.tool`.
