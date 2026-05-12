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
| `apply <proposal-id\|proposal.json\|plan.json>` / `apply --latest-approved [--dry-run]` | Apply is **validation-only**. For an approved proposal, runs deterministic preflight checks and writes an operator execution bundle under `<data_dir>/apply_bundles/<proposal-id>/`: `apply-preview.md`, `operator-commands.sh`, `rollback.sh`, `validation.md`, `apply-preflight.json`. Generated shell scripts contain an early `exit 2` so they cannot run if accidentally invoked. Pending/rejected/canceled proposals fail preflight; no operator-run scripts are written. Legacy `plan.json` arguments keep the prior validation-only behavior. ShellForgeAI never executes commands. |
| `actions compile <proposal-id\|proposal.json>` / `actions compile --latest-approved [--allow-pending]` / `actions show <proposal-id\|actions.json>` / `actions validate <actions.json>` | Policy-gated action compiler (PR37). Turns an approved proposal's operator-run steps into structured, **review-only** action records under `<data_dir>/actions/<proposal-id>/`: `actions.json` and `actions.md`. Every record carries `execution_allowed=false` and the top-level file carries `execution_status=not_executed`. Classification is deterministic (string/regex) and labels mutation actions as `blocked` with `SERVICE-IMPACTING`, `FILESYSTEM-MUTATION`, `PACKAGE-MUTATION`, `NETWORK-MUTATION`, or `FIREWALL-MUTATION`; read-only inspection is `read_only_review`; everything else defaults to `manual_only`. `apply <approved-proposal>` also writes the same `actions.json`/`actions.md` alongside the static bundle for review. ShellForgeAI never executes commands. |
| `approvals create [<session>] [--from-runbook PATH] [--latest] [--include-low]` / `list` / `show <id>` / `approve <id> --reason ...` / `reject <id> --reason ...` / `cancel <id> [--reason ...]` / `archive <id> [--reason ...]` / `validate <id-or-json-path>` | Manage mutation proposal objects (read-only metadata). Proposals are derived from `runbook.json` and live under `<data_dir>/approvals/{pending,approved,rejected,canceled,archived}/<id>.proposal.json`. `create` accepts a session id (`sf_*`), an artifact session directory, an explicit `--from-runbook` path, or `--latest` (newest runbook on disk). Low-risk read-only investigation options are skipped by default; pass `--include-low` to include them. Approval is a paper trail — approve/reject/cancel/archive **never** execute anything. `validate` accepts either a proposal id or a direct `*.proposal.json` path. |
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
| `export <session-id\|session-dir>` / `export --latest` / `export --proposal <id>` / `export --latest-approved` / `export --approved` (refused) / `export --output PATH` / `export --redact` | Bundle evidence/summary/plan/runbook/proposal/apply-preflight artifacts into a portable audit pack under `<data_dir>/exports/<export_id>/`. Writes `export-manifest.json`, `export-summary.md`, `checksums.sha256`, and copies any optional artifact files that exist (`evidence.json`, `summary.md`, `plan.json`, `runbook.md`, `runbook.json`, `proposal.json`, `apply-preview.md`, `operator-commands.sh`, `rollback.sh`, `validation.md`, `apply-preflight.json`). Missing optional files are recorded in the manifest. `--approved` is intentionally refused; use `--proposal <id>` or `--latest-approved`. `--redact` best-effort masks common secrets in text-like files, writes `redaction-report.json`, and sets manifest `redaction_applied=true` with a review-before-sharing warning. Export only reads/copies files — no commands are executed. |
| `validate-export <export-dir\|export-manifest.json>` | Validate an export pack: manifest exists, included files present, checksums match, safety note present, and `apply-preflight.json` (when included) records `execution_allowed=false` / `execution_status=not_executed`. For redacted exports (`redaction_applied=true`), validates `redaction-report.json` exists/parsable and summary/manifest redaction state is consistent. Exit `0` valid, `1` invalid/missing. |
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

`apply <approved-proposal>` generates a static operator bundle on disk but
does not run any command. The bundle's `operator-commands.sh` and
`rollback.sh` include a deliberate `exit 2` before any operator-run command
so accidental invocation is a no-op until a human removes the guard.
Marking a proposal `approved` records intent and does not execute anything.

`diagnose` now reports findings by severity in the terminal summary so informational limitations are not overstated as incidents.


When `--json` is used (for commands that support it), stdout is machine-readable JSON only (no tables/markup), suitable for `json.loads`/`python -m json.tool`.


- `approvals create` is idempotent by fingerprint: repeated creation from the same runbook skips existing proposals across pending/approved/rejected/canceled/archived and reports created vs skipped_existing counts.
- `approvals list` supports `--status`, `--all`, `--component`, and `--session` filters and shows fingerprint short ids for queue clarity.
- Re-running `apply <approved-proposal>` refreshes deterministic files in the same `<data_dir>/apply_bundles/<proposal-id>/` directory and records `bundle_status` in `apply-preflight.json`.
