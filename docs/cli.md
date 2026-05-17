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
| `apply <proposal-id\|proposal.json\|plan.json>` / `apply --latest-approved [--dry-run] [--allow-stale] [--max-age-hours N]` | Apply is **validation-only**. For an approved proposal, runs deterministic preflight checks and writes an operator execution bundle under `<data_dir>/apply_bundles/<proposal-id>/`: `apply-preview.md`, `operator-commands.sh`, `rollback.sh`, `validation.md`, `apply-preflight.json`. Generated shell scripts contain an early `exit 2` so they cannot run if accidentally invoked. Pending/rejected/canceled proposals fail preflight; no operator-run scripts are written. Apply runs the PR38 stale-evidence / drift guard internally and refuses by default when the proposal is stale or drifted; pass `--allow-stale` to bypass a stale decision (drift is never bypassed). `apply-preflight.json` records `guard_status` and `guard_report` path. Legacy `plan.json` arguments keep the prior validation-only behavior. ShellForgeAI never executes commands. |
| `actions compile <proposal-id\|proposal.json>` / `actions compile --latest-approved [--allow-pending]` / `actions show <proposal-id\|actions.json>` / `actions validate <actions.json>` | Policy-gated action compiler (PR37). Turns an approved proposal's operator-run steps into structured, **review-only** action records under `<data_dir>/actions/<proposal-id>/`: `actions.json` and `actions.md`. Every record carries `execution_allowed=false` and the top-level file carries `execution_status=not_executed`. Classification is deterministic (string/regex) and labels mutation actions as `blocked` with `SERVICE-IMPACTING`, `FILESYSTEM-MUTATION`, `PACKAGE-MUTATION`, `NETWORK-MUTATION`, or `FIREWALL-MUTATION`; read-only inspection is `read_only_review`; everything else defaults to `manual_only`. `apply <approved-proposal>` also writes the same `actions.json`/`actions.md` alongside the static bundle for review. ShellForgeAI never executes commands. |
| `approvals create [<session>] [--from-runbook PATH] [--latest] [--include-low]` / `list` / `show <id>` / `approve <id> --reason ...` / `reject <id> --reason ...` / `cancel <id> [--reason ...]` / `archive <id> [--reason ...]` / `validate <id-or-json-path>` | Manage mutation proposal objects (read-only metadata). Proposals are derived from `runbook.json` and live under `<data_dir>/approvals/{pending,approved,rejected,canceled,archived}/<id>.proposal.json`. `create` accepts a session id (`sf_*`), an artifact session directory, an explicit `--from-runbook` path, or `--latest` (newest runbook on disk). Low-risk read-only investigation options are skipped by default; pass `--include-low` to include them. Approval is a paper trail — approve/reject/cancel/archive **never** execute anything. `validate` accepts either a proposal id or a direct `*.proposal.json` path. |
| `runbook [<evidence.json>] [--latest] [--session SID]` | Build an operator-run remediation runbook from existing read-only evidence. Writes `runbook.md` and schema-versioned `runbook.json` next to the evidence. ShellForgeAI does not execute any of the steps; mutating commands are clearly labelled `OPERATOR-RUN` / `REQUIRES APPROVAL` / `SERVICE-IMPACTING`. `diagnose <target> --with-runbook` writes the same artifacts as part of a fresh diagnose run. |
| `validate-runbook [<runbook.json-or-session-dir>] [--latest]` | Validate `runbook.json` schema + safety/risk rules (read-only). Supports direct `runbook.json`, session directory, or `--latest`. Exit code `0` valid, `1` invalid/missing. |
| `status [--json] [--verbose] [--since TS] [--include-retention] [--include-index] [--include-audit] [--include-approvals]` | Operator status dashboard (PR43). Read-only summary of ShellForgeAI operational health: build/profile/runtime, model config/auth hints, safety invariants (`apply` validation-only; execution remains not executed), latest artifacts, approvals queue counts, guard/refusal signals, audit/index presence, optional retention footprint, and short next-step commands. No model generation, no remediation execution, no metadata mutation. `--json` emits machine-readable schema v1. |
| `ops status [--json]` | Compact read-only operations status board (PR60): summarizes latest evidence/runbook, proposal/mission latest+counts, compose context already captured in metadata, safety boundary flags, and audit/cleanup posture. No approval/apply/execute/restart/export/cleanup generation. `--json` emits strict JSON. |
| `ask <question>` | Free-form ask. Options: `--context standard\|minimal\|full`, `--full-context`, `--raw`, `--no-evidence`, `--since 30m`. For recognized ops-shaped questions (e.g. "find failed containers", "network reachability is broken", "why can the service not write to disk?") `ask` reuses the same read-only routing and evidence collection as `diagnose`, writes `evidence.json` + `ask-summary.md`, and answers from the evidence. For network/reachability questions ("upstream unreachable", "DNS errors in logs", "connection refused errors", "why is bad-network failing?", with typo tolerance) `ask` collects combined Docker/log + runtime network evidence and ranks app/container log themes (DNS, upstream, connection refused, timeout, TLS) above runtime network basics — a healthy DNS resolver/default route does NOT cancel an app/container log showing reachability failure. Fix-plan / runbook intents ("give me a safe fix plan for the failed containers", "what should I do next?", "fix bad-network safely", "create a runbook", with typo tolerance) also write `runbook.md` and `runbook.json` next to the evidence. Use `--no-evidence` to force plain model Q&A. `ask` never mutates: a mutation-style request (e.g. "can you restart nginx?", "open port 443", "change DNS") collects read-only evidence and prints a safety boundary. |
| `inspect host` | Host info / resources / uptime. |
| `inspect service <unit>` | `systemctl status` of a unit. |
| `logs <unit> [--since 30m]` | `journalctl -u <unit> --no-pager`. |
| `tools list` | List typed tools, category, and risk class. |
| `tools describe <name>` | Print tool metadata as JSON. |
| `audit list` | List audit session ids. |
| `audit timeline [--latest] [--session <id>] [--proposal <id>] [--kind <kind>] [--since <ts>] [--json]` | Show chronological audit operator trail with guard/refusal states. |
| `audit show <event_id>` | Show one structured audit event. |
| `audit validate` | Validate `audit/events.jsonl` schema and non-execution safety invariants. |
| `audit index [--rebuild]` / `audit index validate` / `audit search [<query>] [--component C] [--target T] [--kind K] [--status S] [--risk R] [--proposal P] [--session SID] [--type T] [--since TS] [--json]` | Audit-aware incident index / search (PR40). `audit index` builds `<data_dir>/audit/incident-index.json` from audit events, artifact sessions, approvals, apply bundles, exports, and actions. `--rebuild` overwrites the existing index file (no source artifact is modified). `audit search` filters with case-insensitive substring (AND across whitespace-separated tokens) over title/summary/component/target/kind/status/session_id/proposal_id/tags/paths and combines with exact-match `--component/--target/--kind/--status/--risk/--type/--proposal/--session/--since` filters. `--json` emits the matching item objects. Every indexed item preserves `execution_allowed=false`, `execution_status=not_executed`, `mutation_performed=false`; no operator commands are executed. `audit index validate` re-reads the index, checks the schema/safety invariants (unique `item_id`, required fields, paths are strings, safety fields are still false), and exits 0/1. |
| `export <session-id\|session-dir>` / `export --latest` / `export --proposal <id>` / `export --latest-approved` / `export --approved` (refused) / `export --output PATH` / `export --redact` | Bundle evidence/summary/plan/runbook/proposal/apply-preflight artifacts into a portable audit pack under `<data_dir>/exports/<export_id>/`. Writes `export-manifest.json`, `export-summary.md`, `checksums.sha256`, and copies any optional artifact files that exist (`evidence.json`, `summary.md`, `plan.json`, `runbook.md`, `runbook.json`, `proposal.json`, `apply-preview.md`, `operator-commands.sh`, `rollback.sh`, `validation.md`, `apply-preflight.json`). Missing optional files are recorded in the manifest. `--approved` is intentionally refused; use `--proposal <id>` or `--latest-approved`. `--redact` best-effort masks common secrets in text-like files, writes `redaction-report.json`, and sets manifest `redaction_applied=true` with a review-before-sharing warning. Export only reads/copies files — no commands are executed. |
| `validate-export <export-dir\|export-manifest.json>` | Validate an export pack: manifest exists, included files present, checksums match, safety note present, and `apply-preflight.json` (when included) records `execution_allowed=false` / `execution_status=not_executed`. For redacted exports (`redaction_applied=true`), validates `redaction-report.json` exists/parsable and summary/manifest redaction state is consistent. Exit `0` valid, `1` invalid/missing. |
| `guard check <proposal-id\|proposal.json>` / `guard check --latest-approved [--max-age-hours N]` / `guard check-actions <actions.json> [--max-age-hours N]` / `guard check-export <export-dir> [--max-age-hours N]` / `guard show <guard-report.json\|dir>` | Stale-evidence / drift guard (PR38). Reads source artifacts, computes hashes, compares against the source hashes recorded at creation time, and writes `guard-report.json` + `guard-report.md` under `<data_dir>/guards/<source-id>/`. Decisions: `fresh` (exit 0), `warning` (exit 0), `stale` (exit 2), `drift_detected` (exit 3), `blocked` (exit 1). Default max ages: proposals/actions/apply bundles 24h, exports 7d; override with `--max-age-hours`. The guard never executes anything: `execution_allowed=false` and `execution_status=not_executed` are recorded in every report. |
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

## Audit incident index examples (PR40)

```
# Build / rebuild the incident index from audit events + artifacts.
shellforgeai audit index
shellforgeai audit index --rebuild

# Search the index.
shellforgeai audit search bad-network
shellforgeai audit search --component sfai-bad-network
shellforgeai audit search --kind guard_check --status refused
shellforgeai audit search --risk medium --type proposal
shellforgeai audit search --proposal prop_pr40_001
shellforgeai audit search --session sf_pr40_001
shellforgeai audit search --since 2026-05-12 --json

# Validate the on-disk index.
shellforgeai audit index validate
```

`audit search` is read-only. It does not run operator commands, mutate
proposals/approvals/apply bundles/exports/actions, or change any source
artifact. The only file `audit index` writes is
`<data_dir>/audit/incident-index.json`.

| `audit retention [--json]` / `audit prune [--dry-run] [--execute] [--confirm] [--max-age-days N] [--keep-latest N] [--category exports\|apply-bundles\|actions\|audit-exports\|indexes\|artifacts\|all] [--archive]` / `audit archive [--older-than-days N] [--output PATH]` / `audit archive-validate <archive.tar.gz>` | PR41 housekeeping commands for ShellForgeAI-owned metadata only. `audit prune` defaults to dry-run and does not delete. PR46 adds a second explicit gate: `--execute` only deletes when `--confirm` is also passed. `--archive` writes a compact archive before deletion. Refuses unknown or protected categories (`approvals`, `audit-events`) and any path outside `<data_dir>` allowed roots. |

### PR46 — first guarded mutation gate

`audit prune` is the only mutation step ShellForgeAI executes. It is strictly
limited to deleting ShellForgeAI-owned metadata under `<data_dir>` and
`<data_dir>/audit`. It does not execute remediation, touch Docker containers,
restart services, install packages, modify firewall/routes/DNS, run generated
operator scripts, or change `apply` (which remains validation/preflight-only).

Dry-run is the default:

```bash
shellforgeai audit prune --category exports --max-age-days 30
```

Output:

```
Prune plan (dry-run):
- selected: 5
- would_delete: 5
- bytes: 1.2 MB
- execution: none
- next step: rerun with --execute --confirm after review
```

Execution requires both `--execute` and `--confirm`:

```bash
shellforgeai audit prune --category exports --max-age-days 30 --execute --confirm
```

Output:

```
Prune executed:
- deleted: 5
- failed: 0
- bytes_removed: 1.2 MB
- audit event: evt_...
- scope: ShellForgeAI-owned metadata only
- remediation_execution: false
- receipt: <data_dir>/prune_receipts/prune_<timestamp>_<shortid>.json
```

A JSON + markdown receipt is written under `<data_dir>/prune_receipts/`.
The receipt records the mode, category, selection, deleted paths,
`bytes_removed`, and a `safety` block asserting metadata-only scope and
`remediation_execution: false`.

The execute path refuses, deletes nothing, and exits non-zero when any of:

- `--execute` is provided without `--confirm`
- the selection is empty
- a candidate path resolves outside the allowed roots
- a candidate is a protected root (`/`, `<data_dir>`, `<data_dir>/audit`)
- a candidate symlink escapes the allowed roots
- the category is unknown
- the category is protected (`approvals`, `audit-events`)


### PR47 — first non-metadata mutation gate (lab container restart)

PR47 adds the *first and only* non-metadata mutation gate: restarting an
explicitly allowlisted lab Docker container from an approved, fresh,
guard-passing proposal. Every other Docker/service/package/filesystem/firewall
operation remains review-only. `apply` is still validation/preflight-only
unless every PR47 gate is satisfied.

The only allowed real mutation is exactly:

```
docker restart <explicitly-allowlisted-lab-container>
```

No `docker compose`, no `docker stop|start|rm|exec|run`, no
`systemctl/service`, no package install/remove, no filesystem/firewall/network
changes, no operator-bundle scripts.

Lab restart allowlist policy file (disabled by default):

```
<data_dir>/policy/lab-container-restart-allowlist.json
```

```json
{
  "schema_version": "1",
  "enabled": false,
  "allowed_containers": ["sfai-healthy-web", "sfai-restart-loop"],
  "notes": "Lab-only restart allowlist. No production containers."
}
```

To opt in, the operator must also set both env vars:

```
SHELLFORGEAI_MUTATION_MODE=lab
SHELLFORGEAI_ALLOW_LAB_CONTAINER_RESTART=1
```

CLI:

```bash
# Dry-run (default): refresh bundle, no restart.
shellforgeai apply <approved-proposal-id>

# Wrong gates: refused with non-zero exit, no commands executed.
shellforgeai apply <approved-proposal-id> --execute
shellforgeai apply <approved-proposal-id> --confirm

# Execute the one allowed lab restart (all gates must pass):
shellforgeai apply <approved-proposal-id> --execute --confirm

# When more than one restart action exists, select one explicitly:
shellforgeai apply <approved-proposal-id> --execute --confirm --action-id act_002
```

Success output (PR48 — verification ran automatically and passed):

```
Guarded lab container restart executed:
- proposal: prop_...
- action: act_...
- container: sfai-healthy-web
- command: docker restart sfai-healthy-web
- executor: docker
- mutation_scope: lab_container_restart_only
- verification: passed
- running_after: True
- started_at_changed: True
- health_after: none
- audit event: evt_...
- receipt: <data_dir>/execution_receipts/exec_<timestamp>_<shortid>.json
- rollback: none automatic
```

Verification warning output (mutation happened, post-checks raised a soft
concern such as no `StartedAt` change or healthcheck still in `starting`):

```
Guarded lab container restart executed with verification warning:
- verification: warning
- running_after: True
- started_at_changed: False
  - note: StartedAt did not change after restart command exited 0
  - note: RestartCount did not change; manual docker restart may not increment it.
```

Verification failure output (mutation happened but post-checks failed —
container missing, not running, unhealthy after bounded wait, or inspect
failed). Exit code is non-zero. ShellForgeAI does NOT attempt a second
restart; the operator must investigate.

```
Guarded lab container restart executed but verification failed:
- verification: failed
- running_after: False
  - note: container not running after restart; no second restart attempted
- no additional restart attempted
- receipt: <data_dir>/execution_receipts/exec_<timestamp>_<shortid>.json
- audit event: evt_...
```

Refusal output (`failed gate` is one of `execute_flag_missing`,
`confirm_flag_missing`, `mutation_mode_disabled`, `allowlist_missing`,
`allowlist_disabled`, `allowlist_empty`, `container_not_allowlisted`,
`container_name_unsafe`, `proposal_not_approved`, `guard_failed`,
`no_restart_action_found`, `multiple_restart_actions_require_action_id`,
`action_not_found`, `action_not_lab_container_restart`,
`command_preview_mismatch`):

```
Execution refused:
- failed gate: allowlist_disabled
- mutation_scope: lab_container_restart_only
- no commands executed
- receipt: <data_dir>/execution_receipts/exec_<timestamp>_<shortid>.json
```

PR48 verification block in the receipt JSON:

```
"verification": {
  "status": "passed|warning|failed|skipped",
  "started_at_before": "...",
  "started_at_after": "...",
  "started_at_changed": true,
  "running_after": true,
  "health_before": "none|healthy|starting|unhealthy|unknown",
  "health_after":  "none|healthy|starting|unhealthy|unknown",
  "restart_count_before": 0,
  "restart_count_after": 0,
  "notes": [],
  "evidence": {
    "before_inspect_path": "<data_dir>/execution_receipts/exec_<id>/before-inspect.json",
    "after_inspect_path":  "<data_dir>/execution_receipts/exec_<id>/after-inspect.json"
  }
}
```

Evidence files (before/after `docker inspect` JSON) live in a sibling
directory next to the receipt JSON:

```
<data_dir>/execution_receipts/exec_<timestamp>_<shortid>.json
<data_dir>/execution_receipts/exec_<timestamp>_<shortid>.md
<data_dir>/execution_receipts/exec_<timestamp>_<shortid>/before-inspect.json
<data_dir>/execution_receipts/exec_<timestamp>_<shortid>/after-inspect.json
```

Audit events for the one allowed mutation carry
`safety.mutation_scope=lab_container_restart_only`,
`safety.execution_allowed=true`,
`safety.execution_status=executed`, and
`safety.mutation_performed=true`. PR48 adds verification fields to the
event details: `verification_status`, `container_running_after`,
`started_at_changed`, `health_after`, `verification_notes`. Event-level
`status` is `success` (verification passed), `warning` (verification
warning), or `failed` (verification failed or restart command failed).
Every other audit event continues to assert
`execution_allowed=false`/`execution_status=not_executed`/`mutation_performed=false`.

`ask` cannot execute the restart. Natural-language phrasings such as "restart
sfai-healthy-web", "run the approved restart", "perform the restart", or
"restart it and verify" are refused and print the explicit `--execute
--confirm` CLI guidance — and remind the operator that verification will run
automatically after the approved CLI execution.

PR48 also adds read-only `ask` queries that summarize the most recent
verification block from the latest execution receipt. These never execute
mutation:

```bash
shellforgeai ask "did the restart work?"
shellforgeai ask "show restart verification"
shellforgeai ask "show post-mutation verification"
shellforgeai ask "show last execution receipt"
shellforgeai ask "was the container running after restart?"
```

Ask routing examples for ShellForgeAI-owned workflows:

```bash
shellforgeai ask "audit retention status"
shellforgeai ask "dry run audit cleanup"
shellforgeai ask "search audit for bad-network"
shellforgeai ask "did anything execute"
shellforgeai ask "create a redacted audit pack"
shellforgeai ask "check drift before apply"
```

## Metadata hygiene and cleanup guidance
- `shellforgeai doctor` now includes a concise metadata hygiene summary (severity, totals, largest categories) and safe dry-run recommendations.
- `shellforgeai doctor --json` includes `metadata_hygiene` with category counts/bytes/severity, warnings, and recommendations.
- `shellforgeai audit retention` now reports total human-readable size and category severities, sorted largest-first.
- Use `shellforgeai audit retention --top N` to list the largest ShellForgeAI-owned metadata items.
- Cleanup guidance remains read-only by default; start with dry-run prune/archive commands.


### PR50 — evidence-to-approved-action restart proposal builder

- New command: `shellforgeai approvals propose-restart <container> --latest` (or `--from-session <id>` / `--from-evidence <path>`).
- Creates a **pending** proposal only (no approval, no rollback preview generation, no apply execution).
- Refuses non-allowlisted targets, missing/unsafe targets, and missing evidence.
- Safety labels include `DOCKER-MUTATION` and either `ALLOWLISTED-LAB-TARGET` or `DISPOSABLE-TARGET`.
- Next flow: approve -> rollback preview -> apply `--execute --confirm` with existing PR48/PR49 gates.


### PR51 — restart proposal plan checklist

- New command: `shellforgeai approvals restart-plan <proposal-id>` with `--latest`, `--from-session <id> --container <name>`, `--from-evidence <path> --container <name>`, and `--json`.
- Read-only preview/checklist: evidence source, target, allowlist status, proposal status, rollback preview status, apply readiness blockers, and exact next safe commands.
- `--json` emits strict machine-readable payload (schema v1), including `safety.execution_allowed=false` and `execution_status=not_executed`.


### PR52 — guided safe restart mission workflow

Mission commands stitch the existing diagnose/propose/approve/rollback/restart-plan/apply
steps into one operator-friendly mission record. Metadata only; no mutation.

- `shellforgeai mission restart prepare --container <name>` — find/use evidence,
  create or reuse a pending restart proposal, write a mission record, render an
  operator checklist. Optional sources: `--from-session <sf_*>`,
  `--from-evidence <path>`, `--latest`. Optional `--with-rollback-preview`
  generates the metadata-only rollback preview.
- `shellforgeai mission restart status <mission-id>` — refresh phases from
  artifacts (proposal, rollback preview, apply readiness) and print the current
  state. `--json` emits strict JSON.
- `shellforgeai mission restart checklist <mission-id>` — operator-readable
  checklist with the exact next CLI commands.
- `shellforgeai mission restart validate <mission-id>` — schema/safety
  invariants check. Exits 1 on failure with a punch list (no traceback).
- `shellforgeai mission restart export <mission-id>` — bundle mission files
  plus the proposal, rollback preview (if present), and source evidence into
  `<data_dir>/mission_exports/<mission-id>/` with a manifest.

Mission records live under `<data_dir>/missions/restart/<mission-id>/` as
`mission.json` and `mission.md`. Apply remains the only execution path.

### PR53 — mission execute handoff

PR53 adds a mission-level execute command that delegates to the existing
PR47/PR48/PR49 apply gate. It does **not** introduce a new executor and does
**not** broaden mutation scope: the actual mutation remains the existing
allowlisted `docker restart <target>` performed by `apply`.

- `shellforgeai mission restart execute <mission-id>` — dry-run only. Shows
  readiness and the exact `apply` command that would be delegated. Exits 1 if
  the mission is not ready, 0 if ready (still no mutation).
- `shellforgeai mission restart execute <mission-id> --dry-run` — same as above
  with an explicit flag; never mutates.
- `shellforgeai mission restart execute <mission-id> --execute` — refuses
  without `--confirm`. No mutation.
- `shellforgeai mission restart execute <mission-id> --execute --confirm` —
  verifies mission readiness (approved proposal whose command preview is exactly
  `docker restart <target>`, valid rollback preview, restart-plan readiness,
  guard freshness), then delegates to the existing apply execution path. The
  apply receipt path is recorded into the mission record and the mission status
  is refreshed.

Success output:

```
Mission execution completed through apply gate:
- mission: mission_restart_...
- proposal: prop_...
- apply receipt: <data_dir>/execution_receipts/exec_*.json
- verification: passed
- running_after: true
- started_at_changed: true
- health_after: healthy
- arbitrary_command_execution: false
- execution_path: apply_gate
```

Refusal output (example):

```
Mission execution refused:
- readiness: blocked
- blocker: rollback preview missing
- no commands executed
- next: shellforgeai rollback preview <proposal-id>
```

`shellforgeai mission restart export <mission-id>` after a delegated execute
also copies the referenced apply receipt into the export and records it in the
manifest under `execution_receipt`.


### PR54 — mission post-execution report and export pack

PR54 adds a read-only report and an export-pack/validate command for missions.
None of these commands execute mutation; they collect the existing artifacts
(mission record, proposal, rollback preview, apply receipt, before/after
inspect evidence, audit events) into a single operator-readable report and
optionally bundle them into a portable export directory with checksums.

- `shellforgeai mission restart report <mission-id>` — print a concise
  operator report (mission, target, proposal, status, execution path,
  verification summary, rollback preview status, artifacts, next review
  commands). Writes `mission-report.json` and `mission-report.md` under
  `<data_dir>/mission_reports/<mission-id>/`. Read-only.
- `shellforgeai mission restart report <mission-id> --json` — strict JSON
  only (no rich header). Schema-versioned (`schema_version: "1"`); fields
  include `execution.status`, `execution.command_argv`, `verification.*`,
  `rollback.preview_path`, `safety.arbitrary_command_execution=false`.
- `shellforgeai mission restart export <mission-id>` — bundle the mission
  record, mission report, proposal, rollback preview, apply receipt,
  before/after inspect evidence, source evidence/summary/plan, and relevant
  audit events into `<data_dir>/mission_exports/<mission-id>/` with
  `export-manifest.json`, `export-summary.md`, `checksums.sha256`, and a
  legacy `manifest.json` for backward compatibility. The export command
  itself does not execute anything; it may *describe* a prior gated
  mutation but performs none.
- `shellforgeai mission restart export <mission-id> --redact` — best-effort
  redaction of secret-shaped tokens in exported text copies (uses the same
  redactor as the PR34 export pack). Adds `redaction-report.json`. Source
  artifacts remain unchanged; only the exported copies are redacted.
- `shellforgeai mission restart validate-export <export-dir>` — re-read an
  exported mission pack and verify manifest, checksums, required files,
  redaction report (when applicable), and safety invariants (export did not
  execute anything; `mutation_performed_by_export=false`;
  `arbitrary_command_execution=false`). Exits 0 on success, 1 on failure
  with a punch list (no traceback).

Example report output:

```
Mission restart report
- Mission: mission_restart_...
- Target: sfai-pr54-target
- Proposal: prop_...
- Source session: sf_...
- Status: executed
- Execution path: apply_gate
- Verification: passed
- Command: docker restart sfai-pr54-target
- Arbitrary command execution: false
```

Mission export manifest carries `source_type: "mission_restart"`,
`mission_id`, `proposal_id`, `session_id`, `redaction_applied`,
`included_files`, `missing_optional_files`, `checksums`, and a
`safety.execution_status: "not_executed_by_export"` invariant. Natural-
language asks for "run mission and export" remain refused; only the
explicit `apply --execute --confirm` (or `mission restart execute --execute
--confirm` handoff from PR53) can execute the gated mutation.

### Cleanup review workflow (PR55)

```bash
shellforgeai audit cleanup plan --category exports --max-age-days 7
shellforgeai audit cleanup archive <cleanup-plan-id>
shellforgeai audit cleanup execute <cleanup-plan-id> --confirm
shellforgeai audit cleanup validate <cleanup-receipt-or-dir>
shellforgeai audit cleanup report <cleanup-receipt-or-dir>
```

## Compose ownership context (PR56)

Read-only Compose awareness from Docker container labels.

- `shellforgeai compose inspect <container>`
- `shellforgeai compose inspect --container <container> --json`
- `shellforgeai compose inspect --project <project>`
- `shellforgeai compose list`
- `shellforgeai compose list --json`

`--json` output is strict JSON only. Compose context is advisory and does not execute any `docker compose` command.

Ask-route polish (PR57) also supports deterministic read-only Compose context asks:

- `shellforgeai ask "compose context for shellforgeai"`
- `shellforgeai ask "what compose project owns shellforgeai?"`
- `shellforgeai ask "is shellforgeai compose managed?"`

If no safe target token is extracted, ask suggests:

- `shellforgeai compose list`
- `shellforgeai compose inspect <container>`

## Compose-aware restart proposal/mission enrichment (PR58)

PR58 enriches restart proposals, restart plans, missions, apply receipts, and
mission reports with Compose ownership context when the target container is
Compose-managed. **Context only — no `docker compose` mutation path is added.**

### Proposal view

`approvals show <proposal-id>` now includes a Compose context block when the
target container has Docker Compose labels:

```
Compose context:
- Compose-managed: yes
- Project: shellforgeai
- Service: shellforgeai
- Working dir: /srv/compose/shellforgeai
- Config files:
  - /srv/compose/shellforgeai/compose.yml
- One-off: False
- restart_scope: container
- compose_mutation: False
- This proposal is container-scoped.
- Command preview remains: docker restart <container>
- ShellForgeAI does not run docker compose commands in this flow.
```

Non-Compose targets show `Compose-managed: no`.

### Restart-plan view

`approvals restart-plan <proposal-id>` surfaces the same context, with a scope
warning:

```
Compose context:
- Compose-managed: yes
- Project: ...
- Service: ...
- Working dir: ...
- Config files:
  - ...

Scope warning:
- This restart plan targets the exact container, not the Compose service.
- No docker compose command will be executed.
```

`--json` output adds `compose_context`, `restart_scope: "container"`, and
`compose_mutation: false`. Apply readiness is **not** blocked merely because
the container is Compose-managed; readiness only blocks if a proposal's
command preview tries to use `docker compose`.

### Mission view

`mission restart status/checklist <mission-id>` includes Compose project,
service, working dir, restart scope, and a "Compose service mutation is not
enabled" line. `mission.json` adds top-level `compose_context`,
`restart_scope: "container"`, and `compose_mutation: false`.

### Apply receipt + closure report

When a mission/proposal with Compose context executes through the existing
apply gate (`apply <id> --execute --confirm` or `mission restart execute
<id> --execute --confirm`), the receipt and mission report preserve the
Compose context plus `restart_scope=container`, `compose_mutation=false`, and
the exact `command_argv=["docker", "restart", "<container>"]`. The closure
report records that Compose context was advisory/read-only, no `docker
compose` command was executed, and the restart was exact-container scoped.

### Ask routes

Read-only:

- `shellforgeai ask "show compose context for this restart proposal"`
- `shellforgeai ask "is this mission targeting a compose service?"`

Refused (no new mutation path):

- `shellforgeai ask "propose restart for compose service shellforgeai"`
- `shellforgeai ask "docker compose restart shellforgeai"`
- `shellforgeai ask "compose up shellforgeai"`
- `shellforgeai ask "recreate compose service shellforgeai"`

Refusals suggest `shellforgeai compose inspect <container>` and the existing
container-scoped `shellforgeai approvals propose-restart --latest --container
<container>` (only when the operator names an allowlisted container).


### Ask reference resolution (PR59)
- `ask` phrases that reference implicit artifacts (`this/latest/current/most recent proposal|mission`) now resolve deterministically against proposal/mission artifacts.
- Explicit IDs always win (for example: `show compose context for prop_...`).
- Ambiguous matches are listed (top candidates) instead of guessed.
- Stale-only matches are flagged so long-lived `/data` artifacts are not silently treated as current.

## PR61 Compose restart preview (read-only)

- `shellforgeai compose restart-preview <target>` prints a read-only command preview for a Compose-managed service.
- `shellforgeai compose restart-preview <target> --json` emits strict JSON with `schema_version`, `status`, `preview.command` (argv list), and safety flags.
- Ask preview examples: `show compose restart preview for shellforgeai`, `preview compose service restart for shellforgeai`, `what would docker compose restart do for shellforgeai?`.
- Mutation asks still refuse (`docker compose restart ...`, `restart compose service ...`, `run/execute/apply compose restart ...`).
- Preview-only posture is explicit: `compose_mutation=true`, `preview_only=true`, `execution_allowed=false`, `executed=false`; no `docker compose` command is executed.

### PR62 compose propose-restart (proposal only)

- `shellforgeai compose propose-restart <target>` creates a **pending** `compose_service_restart` proposal artifact.
- `shellforgeai compose propose-restart <target> --reason "<reason>"` stores operator rationale on the proposal.
- `shellforgeai compose propose-restart <target> --json` emits strict JSON only.
- Proposal posture is explicit: `compose_mutation=true`, `proposal_only=true`, `execution_allowed=false`, `executed=false`.
- The proposal includes compose metadata + a future command preview (`preview.command` argv list and `preview.command_display`).
- `apply` refuses this kind in PR62: “Compose service restart proposals are proposal-only in PR62; execution is not implemented.”
