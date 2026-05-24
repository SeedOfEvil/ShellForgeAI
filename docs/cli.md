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
| `ops report [--json] [--top N] [--include-details] [--include-remediation] [--include-timeline]` | PR104 read-only 2AM operator report / incident command-center summary. Aggregates deterministic Docker triage scene + top suspects, safety invariants, canonical safe next commands, and lightweight remediation-lane posture. `--include-details` adds compact evidence summaries; `--include-remediation` adds eligibility/blocker summaries; `--include-timeline` adds timeline context when available. Never creates plans automatically and never executes remediation/rollback/cleanup/restart. `--json` is strict JSON-only output (`mode=ops_report`). |
| `self-test commands [--json] [--profile quick\|standard\|full] [--fail-on-warn] [--include-skipped]` | Safe operator command coverage harness (PR79 + PR80 profiles). Runs core read-only CLI command surfaces in-process and reports `PASS`/`FAIL`/`WARN`/`SKIP` per check with a summary. Profiles: `quick` (version, doctor, model doctor, tools list, ops status, ask refusal — cheap and env-independent; intended as the first post-deploy gate), `standard` (default, PR79 coverage including `audit retention`, `audit cleanup review`, the `audit cleanup execute-readiness <missing>` and `report <missing>` negative paths, `compose inspect` / `env-check` / `env-contract` / `env-plan`, `validate-runbook --latest`, locally-routed `ask` smokes, and the ask-mutation refusal smoke), `full` (standard plus `audit list`, `audit timeline --latest --json`, `compose list --json`). `--fail-on-warn` exits non-zero when status is `warn` (for CI strictness; warnings remain warnings — the flag does not convert them into runtime failures). `--include-skipped` renders profile-excluded rows in the human output. Never executes cleanup, apply, mission, docker/compose restart, proposal/mission/archive/plan creation, or natural-language mutation; never uses `shell=True`. Warned/skipped checks include an explicit reason (e.g. no runbook artifact, compose target unavailable). `--json` emits strict schema-versioned output with `profile`, per-check rows (including per-row `warn` boolean), `summary` (passed/failed/warned/skipped), `safety`, `warnings`, `skipped`, and `next_safe_commands`. |
| `triage docker [--json]` | PR81 read-only Docker triage ranking ("scene awareness"). Inventories the current Docker scene via existing read-only collectors (`docker.containers` + `docker.problem_summary`) and deterministically ranks suspects across multiple failure classes — `crashloop` / `restart_storm`, `noisy_errors`, `bad_http`, `disk_pressure`, `permission_denied`, and a `high_cpu_watch` lane for healthy-but-loud containers. Each suspect carries severity, confidence, evidence bullets, why-ranked-here, and a single read-only safe next command (always canonical read-only triage/remediation-readiness invocations). The watch list contains lower-severity cases (e.g. high CPU but otherwise healthy) so they are visible without outranking real failures. Never restarts/stops/removes containers, never creates proposals/missions, never runs `apply`, `cleanup execute`, or any docker compose mutation, never uses `shell=True`, never broadens natural-language execution. `--json` emits strict schema-versioned output (`schema_version`, `mode=docker_triage_ranking`, `summary`, `suspects`, `watch`, `safety`, `warnings`, `next_safe_commands`) with `safety.read_only=true` and every mutation flag (`mutation_performed`, `cleanup_executed`, `proposal_created`, `mission_created`, `apply_executed`, `docker_compose_executed`, `container_restarted`, `natural_language_execution`, `shell_true`) explicitly `false`. |
| `triage docker snapshot [--top N] [--include-details] [--save] [--json]` | PR84/PR85 read-only Docker triage incident snapshot/handoff. With `--save`, writes a ShellForgeAI-owned artifact packet under `<data_dir>/artifacts/<triage_snapshot_...>/` containing `triage-snapshot.json`, `triage-snapshot.md`, optional `triage-details.json`, and `manifest.json`; no remediation execution. Reuses deterministic triage ranking and packages scene summary, ranked suspects, optional compact per-suspect evidence details (`--include-details`), safe next read-only commands, and explicit no-mutation safety flags. `--top` limits rendered suspects while preserving total summary counts. `--json` emits strict JSON-only output with `schema_version`, `mode=docker_triage_snapshot`, `generated_at`, `summary`, `suspects`, `next_safe_commands`, `safety`, and `warnings`. Never restarts/stops/removes/prunes containers, never runs cleanup/proposal/mission/apply, and never broadens natural-language execution. |
| `ask <question>` | Free-form ask. Options: `--context standard\|minimal\|full`, `--full-context`, `--raw`, `--no-evidence`, `--since 30m`. For recognized ops-shaped questions (e.g. "find failed containers", "network reachability is broken", "why can the service not write to disk?") `ask` reuses the same read-only routing and evidence collection as `diagnose`, writes `evidence.json` + `ask-summary.md`, and answers from the evidence. For network/reachability questions ("upstream unreachable", "DNS errors in logs", "connection refused errors", "why is bad-network failing?", with typo tolerance) `ask` collects combined Docker/log + runtime network evidence and ranks app/container log themes (DNS, upstream, connection refused, timeout, TLS) above runtime network basics — a healthy DNS resolver/default route does NOT cancel an app/container log showing reachability failure. For common 2AM/operator prompts ("it's 2am, what is on fire?", "docker is broken, what should I check first?", "show me the ops report", "summarize current docker incidents"), `ask` now routes deterministically to the same read-only `ops report` engine used by `shellforgeai ops report`, bypassing model auth for that path. For broad read-only Docker/2AM triage prompts ("what's on fire?", "2AM triage", "the Docker box feels broken", "rank Docker suspects", "broadly scan the current scene", "rank all sfai-battle-lab suspects by severity", "what should I inspect first?", "show current Docker suspects", "what containers look suspicious?") `ask` routes to the PR81 deterministic `triage docker` engine (`triage_ranking.collect_scene` + `rank_scene`) and summarizes the ranked suspects directly — no LLM re-ranking, no invented suspects, no per-container evidence collapse. The answer renders Safety (`read_only: true`, `mutation_performed: false`, no restart/stop/delete/prune/apply/cleanup), each suspect with severity/confidence/evidence/safe-next, an optional Watch list, and a Next-safe-steps footer pointing at `shellforgeai triage docker --json` and `diagnose docker --save-plan --with-runbook`. Mutation phrasings tied to the ranking ("restart the top suspect", "fix the crashloop", "clean up disk pressure now", "stop noisy-errors", "apply the top fix") refuse with the no-mutation wording and redirect to the explicit gated CLI. Fix-plan / runbook intents ("give me a safe fix plan for the failed containers", "what should I do next?", "fix bad-network safely", "create a runbook", with typo tolerance) also write `runbook.md` and `runbook.json` next to the evidence. Use `--no-evidence` to force plain model Q&A. `ask` never mutates: obvious natural-language mutation asks (restart/stop/remove/delete/prune/fix/remediate/execute/apply/rollback/cleanup/compose mutation/chmod/chown/install) are now deterministically refused before any model/Codex call, state that no action was performed, and suggest canonical read-only alternatives such as `ops report`, `triage docker`, `triage docker detail <target>`, and `remediation eligibility --target <target> --explain`. Examples: `shellforgeai ask "please restart shellforgeai"` (deterministic refusal) and `shellforgeai ask "what is on fire in docker right now? ops report please"` (deterministic ops report). |
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
- `shellforgeai doctor` now includes metadata hygiene severity with explicit category-level reasons (count, oldest timestamp when available, estimated size, threshold), plus safe cleanup workflow commands.
- `shellforgeai doctor --json` includes `metadata_hygiene.status`, `reasons[]`, `warnings[]`, and `suggested_commands[]` so operators can script safe cleanup guidance without ambiguity.
- `shellforgeai audit retention` now reports total human-readable size and category severities, sorted largest-first.
- Use `shellforgeai audit retention --top N` to list the largest ShellForgeAI-owned metadata items.
- Safe cleanup sequence remains explicit and gated: `audit retention` -> `audit cleanup plan` -> `audit cleanup archive` -> `audit cleanup validate` -> `audit cleanup execute <plan> --confirm`.


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
shellforgeai audit cleanup validate <cleanup-archive.tar.gz>
shellforgeai audit cleanup execute <cleanup-plan-id> --confirm
shellforgeai audit cleanup validate <cleanup-receipt-or-dir>
shellforgeai audit cleanup report <cleanup-receipt-or-dir>
```

Guardrails:
- `audit cleanup plan` is always dry-run (`execution_allowed=false`, `mutation_performed=false`).
- `audit cleanup execute` refuses without `--confirm`.
- `audit cleanup execute` also refuses unless a matching, valid cleanup archive exists for the same plan fingerprint.
- Ask remains report-only for metadata hygiene; natural-language cleanup execution requests are refused.

### Cleanup execute readiness and report (PR76 + PR77)

`audit cleanup execute-readiness <plan-id-or-path>` is a read-only
readiness check that answers whether the operator may run
`audit cleanup execute <plan> --confirm` safely. It re-checks the PR71
gates (plan kind/safety, matching cleanup archive, archive validation,
plan fingerprint, allowed-root candidate paths) and emits an
operator-only `--confirm` command in `next_commands.execute` when ready.

```bash
shellforgeai audit cleanup execute-readiness <plan-id-or-path>
shellforgeai audit cleanup execute-readiness <plan-id-or-path> --json
```

PR77 polish makes the boundary between "ready" and "approved" explicit.
The human output starts with a `Status:` block (`ready_for_execute_confirm`,
`read_only`, `deletion_performed`, `cleanup_executed`,
`operator_action_required`), then a `Validated gates:` block (plan,
matching archive, archive validation, plan fingerprint, explicit confirm),
then an `Operator warning:` block that explicitly states the command did
not delete anything and that readiness means gates are satisfied — not
that deletion is approved. When blocked, the output lists blockers and
adds `Do not execute until blockers are resolved.` instead of showing the
execute command.

`execute-readiness` creates no plans, no archives, no receipts, and
deletes nothing. `--json` emits strict JSON with `schema_version="1"`,
top-level `ready_for_execute_confirm`, `operator_action_required`,
`read_only`, `cleanup_executed`, `deletion_performed` mirrors, a `gates`
block, and a `safety` block pinning `read_only=true`,
`cleanup_executed=false`, `deletion_performed=false`,
`arbitrary_paths_allowed=false`, `docker_mutation=false`,
`system_mutation=false`, `natural_language_execution=false`,
`explicit_confirm_required=true`.

`audit cleanup execute` without `--confirm` refuses with explicit gate
reasons (matching archive, archive validation, matching plan
fingerprint, explicit `--confirm`) and `Nothing was deleted.` It points
back at `audit cleanup execute-readiness` instead of guessing.

`audit cleanup report <receipt-path-or-dir>` summarizes an execute
receipt (plan/archive linkage, deleted/failed/bytes/skipped, receipt
safety, fingerprint cross-check) and supports `--json`. It is
read-only. PR77 adds a `Post-execute checks:` block in human output and
a `post_execute_checks` array in JSON, including
`audit cleanup validate <receipt>`, `audit retention`,
`audit cleanup review`, and `doctor`. Cleanup execute still requires
plan + matching archive + archive validation + matching plan
fingerprint + `--confirm`.

### Cleanup prepare workflow (PR75)

`audit cleanup prepare` is a guided pre-execution decision packet. It runs
the existing read-only review, creates a dry-run cleanup plan via the
existing PR55 plan path, creates the matching archive via the existing
PR71 archive path, validates the archive, and **stops before execute**.
It never deletes candidate files and never invokes `cleanup execute`.

```bash
shellforgeai audit cleanup prepare --category exports --max-age-days 7 --keep-latest 5
shellforgeai audit cleanup prepare --category exports --max-age-days 7 --keep-latest 5 --json
```

The text output prints the review summary, the plan id/path/fingerprint,
the archive path with `archive_validated`/`checksums`, a `Decision`
block (`prepared_for_review`, `ready_for_operator_decision`,
`execute_performed: false`, `deletion_performed: false`) and the exact
execute command marked **operator-approved only**. `--json` emits strict
JSON with `schema_version="1"`, `kind="cleanup_prepare_result"`, and a
`safety` block that pins `cleanup_executed=false`,
`mutation_performed=false`, `deletion_performed=false`,
`arbitrary_paths_allowed=false`, `docker_mutation=false`,
`system_mutation=false`. Category defaults to `exports` and is validated
against the cleanup-supported allowlist (`exports`, `audit-exports`,
`apply-bundles`, `actions`, `artifacts`); unknown or path-traversal
categories are refused with non-zero exit and no plan/archive is created.

Prepare creates plan and archive metadata only — the only path that
deletes is still `audit cleanup execute <plan> --confirm`, which keeps
the full PR71 gate set.

### Cleanup review pack (PR74)

`audit cleanup review` is a read-only operator decision aid. It answers
"what is taking space?", "what is the safest narrow lane to start with?",
"which cleanup plan command should I run next?", and "what gates still
prevent deletion?" without creating plans, archives, or receipts and
without deleting anything.

```bash
shellforgeai audit cleanup review
shellforgeai audit cleanup review --json
shellforgeai audit cleanup review --category exports
shellforgeai audit cleanup review --top 10
```

Output summarizes the total metadata footprint, groups categories by
size, marks each category as `cleanup_supported` (exports, audit-exports,
apply-bundles, actions, artifacts) or report-only (approvals,
audit-events, indexes), recommends `exports` as the safest first lane
when it has items, lists the PR71 deletion gates that still apply, and
prints the next safe dry-run command. `--json` emits strict JSON with
`schema_version="1"` and a `safety` block that pins `review_only=true`,
`cleanup_executed=false`, `archive_created=false`,
`mutation_performed=false`, `arbitrary_paths_allowed=false`,
`docker_mutation=false`, `system_mutation=false`, and
`natural_language_execution=false`. Review never broadens cleanup scope;
the gated PR55/PR71 sequence remains the only deletion path.

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
- `shellforgeai mission compose-restart status|checklist|validate|execute|report --json` includes `compose_preflight` with structured gate diagnostics (`status`, docker/compose availability flags, command checked, return code, snippets, blockers).
- If Compose preflight blocks, execute refusal remains non-mutating and reports `execution.executed=false`, `execution.blocked=true`, `execution.restart_returncode=null`, `safety.docker_compose_executed=false`, and `safety.container_restarted=false`.
- In a capable environment, successful execute output includes verification evidence (`target_exists_after`, `started_at_changed`, compose label stability, sibling-service touch checks) so operators can confirm only the intended service/container changed.
- Preview-only posture is explicit: `compose_mutation=true`, `preview_only=true`, `execution_allowed=false`, `executed=false`; no `docker compose` command is executed.

### PR62 compose propose-restart (proposal only)

- `shellforgeai compose propose-restart <target>` creates a **pending** `compose_service_restart` proposal artifact.
- `shellforgeai compose propose-restart <target> --reason "<reason>"` stores operator rationale on the proposal.
- `shellforgeai compose propose-restart <target> --json` emits strict JSON only.
- Proposal posture is explicit: `compose_mutation=true`, `proposal_only=true`, `execution_allowed=false`, `executed=false`.
- The proposal includes compose metadata + a future command preview (`preview.command` argv list and `preview.command_display`).
- `apply` refuses this kind in PR62: “Compose service restart proposals are proposal-only in PR62; execution is not implemented.”


### Compose rollback/recovery preview (PR65)
- `shellforgeai rollback preview <proposal-id>` now supports `compose_service_restart` proposals and writes a recovery preview artifact with compose target metadata, restart command argv preview, safety flags, before-state placeholders, and operator recovery notes.
- This preview is guidance only: `automatic_rollback=false`, `rollback_command_generated=false`, and ShellForgeAI does not execute `docker compose` from rollback flows.
- `shellforgeai rollback validate <preview-id-or-path>` validates compose recovery previews, including requiring `docker compose ... restart <service>` argv shape and rejecting `up/down/recreate` patterns.

### PR66 compose env-check (read-only diagnostics)
- `shellforgeai compose env-check` reports current runtime readiness for future Compose service restart execution gates.
- `shellforgeai compose env-check --target <target>` adds target diagnostics: compose ownership metadata, compose-file path/readability/hash snapshot state, and disposable/allowlist gate posture.
- `shellforgeai compose env-check --json` and `--target <target> --json` emit strict JSON only with `schema_version`, `environment`, `readiness`, `safety`, blockers, and warnings.
- Typical blocked-state blockers in Docker01-style environments are surfaced together (for example: `docker_compose_cli_unavailable`, `compose_file_snapshot_unavailable`, `target_not_allowlisted`).
- This command does not create proposals, missions, or rollback previews, and it never executes a Compose restart.

### PR67 disposable Compose restart harness (lab readiness)
- A throwaway Compose fixture lives at `examples/compose/disposable-restart/docker-compose.yml` (and a duplicate at `tests/fixtures/compose/disposable-restart/docker-compose.yml`). Project `sfai_pr67_disposable`, service `web`, container `sfai-pr67-compose-web`. It carries the required `shellforgeai.disposable=true`, `shellforgeai.allow_restart=true`, `shellforgeai.test_harness=compose-restart`, and `shellforgeai.scope=pr67` labels.
- `scripts/pr67_disposable_compose_harness.sh up|down|status|print-env|print-commands` is an external operator helper to bring the disposable stack up/down. It refuses to act if the project/service/container names are not the expected disposable ones. ShellForgeAI itself never runs this script; it is outside the gated execution path.
- Against the disposable target, `shellforgeai compose env-check --target sfai-pr67-compose-web --json` reports `readiness.compose_restart_execution_ready=true`, `allowlist.target_allowlisted=true`, `allowlist.disposable=true`, `allowlist.allow_restart=true`, and a real `config_snapshot.compose_file_sha256` when the compose file is readable and the Docker Compose CLI preflight passes.
- Against the real `shellforgeai` service env-check continues to report blockers such as `target_not_allowlisted`, `compose_file_snapshot_unavailable`, and `docker_compose_cli_unavailable`. PR67 does not weaken any of those blockers.
- The full disposable workflow (preview → propose-restart → approvals → rollback preview → mission prepare → checklist → validate → execute --execute --confirm) still goes through every PR61–PR66 gate. Only `--execute --confirm` mutates, and only against the disposable target.

### PR68 optional live disposable Compose restart proof (lab orchestrator)

- Optional external operator helper: `scripts/pr68_disposable_compose_restart_proof.sh`.
  Lab-only. Not invoked by the ShellForgeAI app.
- Subcommands:
  - `print-commands` / `dry-run` - print the exact gated ShellForgeAI
    command sequence. No execution.
  - `check-env` - read-only local readiness (compose file readable, docker
    CLI + compose plugin available). No mutation.
  - `run-readiness` - run `shellforgeai compose env-check --json` and
    `shellforgeai compose restart-preview --json` against the disposable
    target. Read-only.
  - `run-proof [--execute-approved-disposable-restart]` - default mode
    refuses to drive execution and prints the manual command sequence.
    Even with the explicit dangerous flag, the orchestrator only verifies
    `compose env-check` readiness and prints the gated steps; the operator
    runs `shellforgeai mission compose-restart execute <mid> --execute
    --confirm` themselves.
- Hard target pins (refused otherwise):
  - project=`sfai_pr67_disposable`
  - service=`web`
  - container=`sfai-pr67-compose-web`
- Production-looking target names (`shellforgeai`, `*production*`,
  `*prod*`) are explicitly refused by the orchestrator.
- ShellForgeAI's existing gates are unchanged. Execution still requires
  an approved `compose_service_restart` proposal with valid fingerprint,
  disposable/allow_restart labels, populated `compose_file_sha256`,
  valid rollback recovery preview, Compose CLI preflight ok, the target
  service present in `docker compose config --services`, and explicit
  `--execute --confirm` on the mission.
- See OPS.md ("PR68 optional live disposable Compose restart proof") for
  environment prerequisites and the operator workflow.

### PR69 compose env-contract (read-only contract/readiness diagnostics)
- `shellforgeai compose env-contract --target <target>` reports the Compose execution environment contract gates in one view: target metadata, environment prerequisites, compose file snapshot visibility/hash, execution readiness blockers, and explicit safety flags.
- `shellforgeai compose env-contract --target <target> --json` emits strict JSON only with required sections: `schema_version`, `status`, `target`, `environment`, `snapshot`, `readiness`, and `safety`.
- Current Docker01-style blocked example remains expected when environment is not prepared: blockers can include `docker_compose_cli_unavailable`, `compose_file_snapshot_unavailable`, and `target_not_allowlisted`.
- Ready disposable example (conceptual/fixture-backed): disposable+allow_restart target, compose CLI available, required invocation supported, and readable compose file hash => `status=ready`, `readiness.ready=true`, `readiness.ready_for_optional_disposable_proof=true`.

### PR73 compose env-plan (read-only environment readiness plan)

- `shellforgeai compose env-plan --target <target>` consumes the existing
  env-contract / env-check readiness output and maps every current
  readiness blocker to an explicit operator-controlled remediation step.
  It is **read-only** and never performs any of the remediation it
  suggests.
- `shellforgeai compose env-plan --target <target> --json` emits strict
  JSON only with required sections: `schema_version`, `status`, `target`,
  `readiness`, `plan`, `post_conditions`, `safety`, and `warnings`.
- Each `plan` entry includes `blocker`, `meaning`, `operator_remediation`,
  `shellforgeai_action="none"`, `automated=false`,
  `mutation_required_outside_shellforgeai`, `allowed_for_disposable_lab`,
  and `allowed_for_production` (always `false`).
- For production-like targets (`shellforgeai`, anything containing
  `production` / `prod`) that are not already allowlisted, the plan adds
  a warning and recommends using the PR67 disposable harness target
  instead. It does not suggest labeling production services
  `shellforgeai.disposable=true`.
- Safety flags in every plan output: `read_only=true`,
  `docker_compose_executed=false`, `container_restarted=false`,
  `host_side_bypass=false`, `arbitrary_command_execution=false`,
  `natural_language_execution=false`.
- This command does not create proposals, missions, or rollback previews,
  does not run `docker compose`, does not mount host paths, does not
  install packages, and does not weaken any PR63–PR71 gate.

Example (Docker01-style disposable target, environment not yet prepared):

```
$ shellforgeai compose env-plan --target sfai-pr67-compose-web
Compose execution environment plan

Target:
- input: sfai-pr67-compose-web
- compose-managed: true
- ...
- target_allowlisted: true
- production_like: false

Current readiness:
- ready: false
- ready_for_optional_disposable_proof: false

Blockers:
  1. compose_file_snapshot_unavailable
     Meaning: Compose file path is known from Docker labels, but
       ShellForgeAI cannot read or hash it from inside its execution
       environment.
     Operator remediation: Expose the disposable Compose file read-only
       into the ShellForgeAI container/harness at the same path Compose
       recorded, then rerun env-check/env-contract.
     ShellForgeAI action: none; no automated remediation performed.
  2. docker_compose_cli_unavailable
     Meaning: docker compose CLI/plugin is not available inside the
       ShellForgeAI execution environment ...
     Operator remediation: Provide a compatible Docker CLI with Compose
       plugin inside the ShellForgeAI container/harness ...
     ShellForgeAI action: none; no automated remediation performed.

Required after remediation:
- env-check reports compose_restart_execution_ready=true for the
  disposable target
- env-contract reports ready=true and
  ready_for_optional_disposable_proof=true
- production shellforgeai remains not allowlisted
- PR68 run-proof may only be executed with explicit operator approval

Safety:
- read_only: true
- docker_compose_executed: false
- container_restarted: false
- host_side_bypass: false
- arbitrary_command_execution: false
- natural_language_execution: false
```

JSON shape (truncated):

```json
{
  "schema_version": "1",
  "status": "blocked",
  "target": {
    "input": "sfai-pr67-compose-web",
    "compose_managed": true,
    "project": "sfai_pr67_disposable",
    "service": "web",
    "container": "sfai-pr67-compose-web",
    "disposable": true,
    "allow_restart": true,
    "target_allowlisted": true,
    "production_like": false
  },
  "readiness": {
    "ready": false,
    "ready_for_optional_disposable_proof": false,
    "blockers": [
      "compose_file_snapshot_unavailable",
      "docker_compose_cli_unavailable"
    ]
  },
  "plan": [
    {
      "blocker": "compose_file_snapshot_unavailable",
      "meaning": "...",
      "operator_remediation": "...",
      "shellforgeai_action": "none",
      "automated": false,
      "mutation_required_outside_shellforgeai": true,
      "allowed_for_disposable_lab": true,
      "allowed_for_production": false
    }
  ],
  "post_conditions": ["..."],
  "safety": {
    "read_only": true,
    "docker_compose_executed": false,
    "container_restarted": false,
    "host_side_bypass": false,
    "arbitrary_command_execution": false,
    "natural_language_execution": false
  },
  "warnings": []
}
```

## PR79 / PR80 safe command coverage harness

```
shellforgeai self-test commands
shellforgeai self-test commands --json
shellforgeai self-test commands --profile quick
shellforgeai self-test commands --profile standard
shellforgeai self-test commands --profile full
shellforgeai self-test commands --fail-on-warn
shellforgeai self-test commands --include-skipped
```

`self-test commands` exercises the safe read-only operator command surface
in-process and prints a `PASS`/`FAIL`/`WARN`/`SKIP` line per check plus a
summary. The default profile is `standard` (PR79 coverage). It never
executes:

- cleanup execute / archive / prepare
- proposal creation / approval / apply
- mission creation / execute
- docker compose restart (or any docker mutation)
- natural-language mutation

It also never uses `shell=True` and never shells out — checks are invoked
through the in-process Typer/Click runner only.

### Profiles

- `quick` — cheap and environment-independent. Runs `version`, `doctor`
  (+`--json`), `model doctor`, `tools list`, `ops status` (+`--json`), and
  the deterministic ask-mutation refusal smoke. No artifact-dependent
  checks; designed to be reliable immediately after a deploy and the
  recommended first post-deploy gate.
- `standard` (default) — PR79 coverage. Adds `audit retention`,
  `audit cleanup review`, the `audit cleanup execute-readiness <missing>`
  and `audit cleanup report <missing>` negative refusal paths,
  `compose inspect` / `env-check` / `env-contract` / `env-plan` against
  the local target, `validate-runbook --latest`, and the locally-routed
  `ask` smokes (`show metadata hygiene`, `clean up now`). May warn when
  optional artifacts (latest runbook, compose target) are missing.
- `full` — `standard` plus broader read-only coverage: `audit list`,
  `audit timeline --latest --json`, `compose list --json`. May warn more
  often; still never mutates.

### Status / warn / skip / fail semantics

- `pass` — command succeeded and the expected safety invariant held.
- `warn` — command succeeded but the environment/artifact state is
  incomplete (e.g. no latest runbook artifact, compose target absent
  from the local Docker inventory). Not a mutation risk and not a
  command failure. Each warned row carries `warn:true` plus a reason.
- `skip` — the check was intentionally not run (profile-excluded or a
  prerequisite missing). Carries a reason.
- `fail` — the command failed unexpectedly, a safety invariant was
  violated, JSON was unparsable when JSON was expected, or a mutation
  flag was unexpectedly true.

The overall `status` is `failed` if any row failed, `warn` if any row
warned, otherwise `ok`.

### `--fail-on-warn`

`--fail-on-warn` exits non-zero when the overall status would be `warn`.
Warnings remain warnings: the underlying JSON `status` is still `warn`
and a separate `ci_status: "failed_on_warn"` field is emitted. This flag
is intended for CI strictness and does not convert warnings into runtime
failures.

### `--include-skipped`

By default the human output omits profile-excluded `skip` rows (they are
not in the active profile) and surfaces only warnings. `--include-skipped`
renders every row so operators can see what the harness considered.

### JSON schema (`--json`)

```
{
  "schema_version": "1",
  "status": "ok|warn|failed",
  "profile": "quick|standard|full",
  "available_profiles": ["quick", "standard", "full"],
  "default_profile": "standard",
  "summary": {"passed": …, "failed": …, "warned": …, "skipped": …},
  "checks": [
    {"name": …, "command": [...], "status": "pass|fail|skip",
     "category": …, "read_only": true, "mutation": false,
     "warn": false, "reason": null}
  ],
  "safety": {
    "read_only": true,
    "mutation_performed": false,
    "cleanup_execute_run": false,
    "mission_execute_run": false,
    "apply_execute_run": false,
    "docker_compose_executed": false,
    "docker_compose_mutation": false,
    "natural_language_execution": false,
    "arbitrary_command_execution": false
  },
  "warnings": [{"name": …, "reason": …}],
  "skipped": [{"name": …, "reason": …}],
  "failures": [{"name": …, "reason": …}],
  "next_safe_commands": [...],
  "optional_disposable_mutation_lane": {"implemented": false, …}
}
```

The PR79 `mode` block and the PR79 `no_*` safety keys
(`no_cleanup_execute`, …) are retained for backward compatibility.

Exit code is `0` for `ok` or `warn` (warnings present), `1` when at
least one check failed, `1` when `--fail-on-warn` is used and there is
at least one warning, and `2` for an unknown profile.

- `shellforgeai triage docker detail <suspect> [--json]` (PR83) drills into one ranked suspect from deterministic Docker triage. Read-only: emits rank context, severity/confidence/score/classes, why-ranked-here, per-suspect evidence bullets, safe read-only next commands, and explicit no-mutation safety flags.
- `shellforgeai triage docker detail --rank <n> [--json]` selects by rank using the same deterministic ranking snapshot; supports clean `not_found`/`error` JSON statuses without traceback.

- `shellforgeai triage docker snapshot`
- `shellforgeai triage docker snapshot --include-details --json`
- `shellforgeai triage docker snapshot --top 3`

- `shellforgeai triage docker snapshot --save` writes read-only triage handoff metadata only (no proposal/mission/apply/cleanup execution).
- `shellforgeai triage docker snapshot validate <snapshot-id> [--json]` validates required files, JSON parse/schema/mode/safety invariants, and manifest checksums when present.
- `shellforgeai triage docker snapshot export <snapshot-id|path> [--json] [--output <relative-path-under-data-dir/exports>]` packages a saved triage snapshot into a portable ShellForgeAI-owned export directory under `<data_dir>/exports/...` with `triage-snapshot.json`, `triage-snapshot.md`, optional `triage-details.json`, `manifest.json`, and `export-manifest.json`.
- `shellforgeai triage docker snapshot export-validate <export-path> [--json]` re-validates required files, JSON parse, manifest mode, checksums, and no-mutation safety invariants for the triage export bundle.
- `shellforgeai triage docker snapshot compare <snapshot-a> <snapshot-b> [--json] [--top N] [--only-changed] [--include-stable] [--include-evidence]` performs read-only drift comparison (new/recovered suspects, rank/severity/confidence/class drift, scene summary drift) and always reports no-mutation safety flags.
- `shellforgeai triage docker snapshot compare-export <export-a> <export-b> [--json] [--top N] [--only-changed] [--include-stable] [--include-evidence]` validates both exports first and then performs the same read-only drift comparison; malformed/missing/checksum-mismatch exports fail with non-zero exit in JSON mode.
- `shellforgeai triage docker timeline [--window N] [--top N] [--only-regressions] [--include-stable] [--json]` analyzes the latest saved triage snapshots under `<data_dir>/artifacts`, validates each snapshot, sorts chronologically, and reports rolling incident trends (escalating/recovering/flapping/recurring/stable/new/resolved) with explicit read-only safety flags.

## PR104 2AM operator report
- `shellforgeai ops report`
- `shellforgeai ops report --json`
- `shellforgeai ops report --top 3 --include-details`
- `shellforgeai ops report --save` / `--save --json`
- `shellforgeai ops report validate <report-id-or-report-directory-path>`
- `shellforgeai ops report export <report-id-or-path>`
- `shellforgeai ops report export-validate <export-id-or-path>`
- `shellforgeai ops report compare <before> <after>`
- `shellforgeai ops report compare <before> <after> --json`
- `shellforgeai ops report compare <before> <after> --only-changed`
- `shellforgeai ops report compare-latest`
- `shellforgeai ops report compare-latest --json`
- `shellforgeai ops report history`
- `shellforgeai ops report history --json`
- `shellforgeai ops report history --include-drift --json`
- `shellforgeai ops report compare-export <before-export> <after-export>`

## PR89 disposable remediation proof

## PR99 remediation self-test
- `shellforgeai remediation self-test [--profile quick|standard|full] [--json] [--fail-on-warn]` runs a non-mutating remediation-lane readiness/self-test doctor. In PR102, `full` now exercises plan/validate/preflight/refusal/proof-execute/receipt/report/bundle/audit over an isolated temp data dir while still skipping live docker-disposable execute by default.
- PR103 adds an **optional**, explicitly gated lab-only live disposable proof path for `full` profile only:
  - `--include-live-disposable-execute`
  - `--target <exact disposable target>`
  - `--confirm-live-disposable`
- Live disposable proof is refused without explicit target + confirmation and is refused for broad/wildcard/production or non-allowlisted/non-disposable targets.
- Example:
  - `shellforgeai remediation self-test --profile full --include-live-disposable-execute --target sfai-pr103-user-sim --confirm-live-disposable --json`
- Default behavior is non-mutating: no remediation execute, no rollback execute, no cleanup execute, no Docker Compose mutation, and no natural-language execution.
- Example commands:
  - `shellforgeai remediation self-test`
  - `shellforgeai remediation self-test --profile quick --json`
  - `shellforgeai remediation self-test --fail-on-warn`
  - `shellforgeai remediation self-test --profile full --include-live-disposable-execute --target sfai-pr103-user-sim --confirm-live-disposable --json`

- `shellforgeai remediation plan --target sfai-noisy-errors --scenario sfai-noisy-errors [--json]` creates a dry-run disposable-only plan artifact with fingerprint, pre/post checks, rollback note, and explicit no-mutation safety flags.
- `shellforgeai remediation eligibility [--target <name>] [--scenario sfai-noisy-errors] [--json]` maps current triage suspects to read-only remediation eligibility and executor readiness (proof / docker-disposable), explains blockers, and suggests safe **plan-only** next commands. It does **not** create plans and does **not** execute remediation.
- `shellforgeai remediation eligibility --target <name> --explain [--json]` prints a read-only gate-by-gate eligibility explanation report (labels found/missing, failed gates, executor readiness, blocked reasons, what would make the target eligible, and safe next commands). In JSON mode it emits strict machine-parseable output with `mode=remediation_eligibility_explain`.
- Eligible explain example: `shellforgeai remediation eligibility --target sfai-pr97-eligible --explain` includes `eligible_for_plan` and a safe `remediation plan` suggestion only.
- Blocked explain example: `shellforgeai remediation eligibility --target shellforgeai --explain` shows production refusal and safe read-only diagnostics (never execute commands).
- `shellforgeai remediation validate <plan-id> [--json]` validates kind/fingerprint/labels/safety fields and fails nonzero on unsafe plans.
- `shellforgeai remediation execute <plan-id> --execute --confirm [--json]` runs a governed disposable remediation proof executor (not live Docker remediation) only after explicit confirmation and writes a receipt with pre/post state + verification.
- `shellforgeai remediation status <receipt-id> [--json]` reports receipt verification and safety flags.
- `shellforgeai remediation preflight <plan-id> [--executor proof|docker-disposable] [--json]` renders a read-only operator preflight packet (target identity/eligibility, exact action preview, verification expectations, recovery note, decision, and no-mutation safety flags).
- `preflight_status=ready` means gates are satisfied; execution still requires explicit operator approval and `--execute --confirm`.
- Preflight prints execute command only when ready; blocked packets omit execute command and show exact blockers plus safe read-only next steps.

Safety: production `shellforgeai`, unlabeled/non-allowlisted targets, broad selectors (`all`, `*`, `everything`), unsupported scenarios, and suspicious targets are refused.


## PR90 remediation executor modes

## PR91 remediation receipt validation and report

- `shellforgeai remediation receipt validate <receipt-id-or-path> [--json]` performs strict read-only receipt checks (kind/fingerprint/target/safety/executor invariants) and exits nonzero on `failed|not_found|error`.
- `shellforgeai remediation report <receipt-id-or-path> [--json]` renders a concise handoff summary (what happened, safety posture, validation status, and next safe commands).
- Proof executor receipts are explicitly reported as non-mutating (`docker_restart_attempted=false`, `mutation_performed=false`).
- Docker-disposable receipts require exact-target restart proof for successful validation (`verification.restart_verified=true`).


- `shellforgeai remediation execute <plan-id> --execute --confirm [--executor proof|docker-disposable] [--json]`.
- Default executor mode is `proof` and performs **no real Docker mutation**.
- Real mutation requires explicit `--executor docker-disposable` plus all disposable/allowlist gates at execution time.
- `docker-disposable` mode is bounded to exact `docker restart <target>` only for exact eligible targets; broad or production targets are refused.

## PR93/PR94 remediation rollback workflow
- `shellforgeai remediation rollback-preflight <receipt-id> [--json]` emits a read-only rollback posture packet for a disposable remediation receipt.
- `shellforgeai remediation rollback-validate <receipt-id-or-rollback-receipt-id> [--json]` validates rollback readiness (original receipt) and rollback execution integrity (rollback receipt).
- `shellforgeai remediation rollback-execute <receipt-id> --execute --confirm [--json]` executes bounded disposable recovery restart on the exact prior target only and writes a rollback receipt.
- `shellforgeai remediation rollback-status <rollback-receipt-id> [--json]` reports rollback receipt verification/safety summary.
- Rollback strategy is explicit and bounded: `repeat_exact_target_restart` for the same exact disposable target.
- These commands do **not** execute rollback and always keep `automatic_rollback=false`.

- `shellforgeai remediation bundle <plan-id-or-receipt-id>`: read-only lifecycle handoff summary.
- `shellforgeai remediation bundle <id> --save`: write lifecycle JSON/Markdown bundle under data_dir artifacts.
- `shellforgeai remediation bundle validate <bundle-id-or-path>`: validate saved lifecycle bundle.
- `shellforgeai remediation audit [--latest] [--json]`: read-only lifecycle safety audit for remediation plan/receipt/rollback/bundle artifacts; summarizes latest lifecycle, safety flags, invalid artifacts, and safe next commands.

Examples:
- `shellforgeai remediation audit`
- `shellforgeai remediation audit --latest --json`


### Diagnose + Docker triage cohesion
When `shellforgeai diagnose <target>` matches a known Docker/battle-lab container, output may include deterministic triage context (severity/confidence/classes/evidence summary), a container-scope note, and canonical read-only next commands:
- `shellforgeai triage docker detail <target>`
- `shellforgeai remediation eligibility --target <target> --explain`
