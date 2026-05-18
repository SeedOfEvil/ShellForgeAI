# Safety

ShellForgeAI is built to be safe by construction. The runtime does not run
arbitrary shell, does not mutate the host without policy approval, and
treats model output as advisory.

`shellforgeai ops status` is read-only reporting only: it summarizes existing
artifacts/metadata and does not approve, apply, execute, restart, or generate
rollback previews, closure reports, exports, or cleanup plans.

## Boundaries

- **No arbitrary shell.** Tools are typed wrappers around specific binaries
  with bounded arguments. The interactive REPL is not a shell; pasted
  shell-looking input is blocked unless explicitly prefixed with
  `ask explain ...` or `ask review ...`. A short-lived quarantine blocks
  follow-on shell fragments after a multi-line paste; `/help` and `/exit`
  still work.
- **`apply` is validation-only.** It parses and validates plan JSON and
  exits. For approved proposal objects it runs preflight checks and writes
  a static operator execution bundle on disk (`apply-preview.md`,
  `operator-commands.sh`, `rollback.sh`, `validation.md`,
  `apply-preflight.json`) but does **not** run any command. The generated
  shell scripts contain an early `exit 2` before any operator-run command,
  so accidental invocation is a no-op until a human removes the guard.
  `apply-preflight.json` always records `execution_allowed: false` and
  `execution_status: "not_executed"`.
- **Approval is a paper trail.** Marking a proposal `approved` does not
  execute anything. Approval transitions only move proposal metadata
  between `approvals/{pending,approved,rejected,canceled}/` directories.
- **No package installs, no service restarts** initiated by the runtime.
  Service-impacting commands are described as approval-required and
  operator-run.
- **Workspace trust is scoped.** Trusting a workspace allows reading
  workspace docs and writing artifacts/audit under the data dir. It does
  not lift policy, enable mutation, or bypass approval gates.
- **Slash commands are deterministic.** Unknown slash commands never call
  the model.
- **Read-only follow-ups only.** Adaptive follow-ups (CPU/process,
  memory/swap, storage/IO, network/DNS, service health, general context)
  use the same typed read-only collectors as the initial pass.

## Profiles and risk classes

See `docs/profiles.md`. Risk classes are `read`, `change`, `service`,
`system`, `danger`. Profiles map each class to `allow`, `ask`, or `deny`.

## Containers

In restricted containers, the Codex CLI may emit `bwrap`/namespace errors.
Treat that as a provider sandbox limitation, not a host failure.
ShellForgeAI's typed read-only collectors continue to work; only model
synthesis is affected.

- `disk.top_dirs` is bounded read-only (`du -x -d 1`) and never deletes or modifies files.

When ShellForgeAI is running inside a container, unavailable host-only tools/checks are treated as visibility limitations rather than failures.


Restart/reload command examples are only appropriate when service presence and a valid manager/tooling path are confirmed; otherwise ShellForgeAI should advise confirming service ownership/location first.


Failures/timeouts in diagnostics do not trigger mutation; restart/reload/install actions remain operator-run and `apply` remains validation-only.


Targeted network follow-ups (reachability, port-open, listener, DNS,
firewall) preserve and reuse the original `target_host`, `target_port`,
and `target_domain` from the source user message. Follow-up deep dives
for these subtypes use only read-only collectors:

- DNS resolver inspection (`/etc/resolv.conf`).
- Read-only DNS resolution test for the explicit target domain (or the
  project's safe default when no domain is given).
- Read-only route/interface/listener inspection.
- Bounded TCP connect to the explicit target host/port only.
- Firewall context (tooling visibility / container view).

Opening or allowing a port, changing firewall rules, changing routes or
interfaces, restarting networking or services, and Docker port-publish
changes remain operator-run. ShellForgeAI never executes them.

For reachability questions, ShellForgeAI ranks app/container log evidence
(DNS, upstream unreachable, connection refused, timeout, TLS) ahead of
runtime network basics: a healthy DNS resolver and default route do not
cancel an app/container log showing reachability failure. Mutation-style
phrases ("fix the network", "change DNS", "open port 443", "add firewall
rule") are detected and downgraded to read-only evidence collection plus a
safety notice; no DNS/firewall/route/interface change is performed.


Log/error investigation is read-only and bounded. ShellForgeAI never
deletes, truncates, rotates, or `tail -f`s logs. Log file scans cap files,
bytes, and line counts, redact secrets/tokens/passwords/API keys/private
keys/cookies/Authorization headers, and reject binary/oversized targets.
Requests like "delete logs", "clear logs", "truncate logs", "rotate logs",
and "wipe logs" are refused — ShellForgeAI collects read-only log
evidence instead. `apply` remains validation-only.


Docker visibility is read-only. ShellForgeAI's container collectors only
issue `docker ps`, `docker inspect`, and `docker logs --tail N`. They
never run `docker start/stop/restart/rm/exec/cp/build/pull/prune`,
compose mutation, or volume/network mutation, even if the Docker socket
is mounted. Container logs are bounded by line/byte caps, redacted for
secrets/tokens/passwords/API keys/cookies/Authorization headers, and
never followed (`-f` is forbidden). When the Docker CLI/daemon is
unreachable the missing visibility surfaces as a limitation finding;
ShellForgeAI never claims the host is healthy on the basis of its own
container being healthy.


`shellforgeai ask` is read-only. For obvious ops-shaped questions it
reuses the same natural-language router and read-only evidence
collectors as `diagnose` (one source of truth in
`shellforgeai.interactive.commands.route_input`). Mutation-style
phrasing such as "can you restart nginx?", "open port 443", or "delete
logs" is treated as a request to *inspect*: ShellForgeAI collects the
relevant read-only evidence and prints an explicit safety boundary
instead of running the mutation. `--no-evidence` disables routing and
forces plain model Q&A. `apply` remains validation-only.

`shellforgeai runbook` (and `diagnose --with-runbook`, and fix-plan
intents in `ask`) produce an *operator-run* remediation plan from
existing read-only evidence. The runbook is read-only synthesis — no
shell commands are executed, no files are edited, no services are
restarted, no packages are installed/removed/updated, no Docker
containers are mutated, and no firewall/route/DNS state is changed.
Every mutating command in the runbook is shown as a labelled hint
(`OPERATOR-RUN`, `REQUIRES APPROVAL`, `SERVICE-IMPACTING`,
`ROLLBACK ADVISED`) for a human operator to run, and every runbook
explicitly states "ShellForgeAI did not execute these steps. This is an
operator-run plan." Risk levels are advisory; ShellForgeAI does not act
on them.

`shellforgeai apply <approved-proposal>` writes a static operator
execution bundle under `<data_dir>/apply_bundles/<proposal-id>/` but
does not run anything. The bundle's `operator-commands.sh` and
`rollback.sh` both contain a deliberate `exit 2` *before* any
operator-run command, with an explicit "ShellForgeAI did not execute
this script." banner. Pending, rejected, or canceled proposals fail
preflight and no operator-run scripts are written. `approved` is
strictly a paper trail; it does not enable execution. ShellForgeAI's
apply remains validation-only in this alpha.

`shellforgeai approvals create|list|show|approve|reject|cancel|archive|validate`
manages mutation proposal objects on disk only. Proposals are derived
from `runbook.json` and live under
`<data_dir>/approvals/{pending,approved,rejected,canceled,archived}/<id>.proposal.json`.
Every proposal records `execution.allowed = false` and
`execution.status = "not_executed"`, and the JSON schema is validated
by `approvals validate`. Approval, rejection, cancellation, and
archival only update metadata — ShellForgeAI does not execute any
proposed step. "Approved" does not mean "applied". Immediate-fix
asks like "approve and run the fix" or "fix everything now" are
refused cleanly; ShellForgeAI offers to stage proposals for approval
instead.



- Proposal replay protection: ShellForgeAI computes a stable SHA-256 proposal fingerprint from runbook/session content and skips duplicates by default to prevent queue spam.
- Approval transitions and apply preflight remain non-executing; execution fields stay `execution_allowed=false` and `execution_status=not_executed`.

`shellforgeai export` packages evidence/summary/runbook/proposal/apply-preflight
artifacts into a portable audit pack under `<data_dir>/exports/<export_id>/`.
Export is read-only synthesis: it copies files and writes a new manifest +
checksum file but does **not** execute remediation, restart services, edit
files, install/remove packages, modify Docker containers, or change
firewall/route/DNS state. Raw evidence files are preserved verbatim by default
and a manifest warning notes that they may contain environment/config details
and must be reviewed before sharing. `--redact` performs a best-effort secret
mask (`password=`, `token=`, `api_key=`, `secret=`, `Authorization: Bearer`)
on copied text/JSON files. `validate-export` re-checks an export pack: missing
files, checksum mismatches, or an `apply-preflight.json` claiming
`execution_allowed=true` cause validation to fail. **Approved does not mean
applied**, and **exported does not mean applied**. `apply` remains
validation-only.

`shellforgeai guard check|check-actions|check-export|show` (PR38) provides
stale-evidence and drift protection for proposals, compiled actions, apply
preflight bundles, and export packs. The guard reads source files, computes
SHA-256 hashes, compares against hashes recorded at creation time, and writes
a `guard-report.json` / `guard-report.md` pair under
`<data_dir>/guards/<source-id>/`. Decisions are `fresh`, `warning`, `stale`,
`drift_detected`, or `blocked`. Default max ages are 24h for
proposals/actions/apply bundles and 7d for exports; `--max-age-hours`
overrides per-call. The guard is **read-only**: it never executes
remediation, never restarts/reloads/installs/deletes, never mutates
proposals/approvals/actions/exports, and never edits source artifacts. Every
guard report records `execution_allowed=false` and
`execution_status=not_executed`. `apply` runs the guard internally and
refuses to generate an operator bundle from a stale or drifted proposal by
default; `--allow-stale` bypasses a stale decision but drift is never
bypassed. `apply` remains validation-only.

`shellforgeai actions compile` (PR37) compiles an approved proposal into
structured, review-only action records under
`<data_dir>/actions/<proposal-id>/`. Classification is deterministic
string/regex matching — no LLM call, no shell execution. Mutation steps
(restart/recreate, chmod/chown/rm, package install/remove,
iptables/ufw/nft/firewall-cmd, ip route, resolvectl dns) are classified
`blocked` with the appropriate `SERVICE-IMPACTING` / `FILESYSTEM-MUTATION` /
`PACKAGE-MUTATION` / `NETWORK-MUTATION` / `FIREWALL-MUTATION` labels.
Read-only inspection (`docker logs|inspect|ps`, `systemctl status`,
`journalctl`, `cat`, `grep`, `stat`) is `read_only_review`. Unrecognized or
manual steps default to `manual_only`. Every record carries
`execution_allowed=false` and the top-level file carries
`execution_status=not_executed`. **Compiled does not mean applied.** The
action compiler does not execute anything; `apply` remains validation-only.


## Audit timeline safety invariants

`<data_dir>/audit/events.jsonl` records ShellForgeAI timeline events only. Every event records `execution_allowed=false`, `execution_status=not_executed`, and `mutation_performed=false`. Audit events prove ShellForgeAI actions/refusals, not external operator execution.

## Audit incident index / search safety (PR40)

`shellforgeai audit index|search|index validate` is read-only metadata
navigation over `<data_dir>` only. The index file
(`<data_dir>/audit/incident-index.json`) is the single file these commands
write; rebuilding the index never mutates any source artifact, never executes
operator commands, never restarts/reloads services, never installs/removes
packages, never changes Docker/firewall/route/DNS state, and never edits files
outside ShellForgeAI's configured data/audit/index directories. Each indexed
item preserves `execution_allowed=false`, `execution_status=not_executed`,
`mutation_performed=false`; `audit index validate` rejects any index payload
that claims otherwise. The index proves ShellForgeAI's own session/proposal/
export/guard/refusal trail — it does not prove external operator execution.
`apply` remains validation/preflight-only.

- PR41 metadata housekeeping: `audit prune` only targets ShellForgeAI-owned metadata roots under `<data_dir>` and defaults to dry-run. Deletion requires explicit `--execute`; no remediation execution is performed.


### Ask-routing hardening for ShellForgeAI-owned workflows
- Ask routing never executes remediation commands; apply remains validation/preflight-only.
- Ask cleanup/prune phrasing defaults to retention report or prune dry-run; deletion requires explicit CLI `--execute`.
- Ambiguous wording is disambiguated: ShellForgeAI metadata phrases route to ShellForgeAI audit/retention/export commands, while host-audit wording (`auditd`, `ausearch`, `/var/log/audit`, `journalctl`) stays in host diagnostics.

## Status dashboard safety

`shellforgeai status` is strictly read-only. It summarizes ShellForgeAI-owned metadata (audit events, approvals, bundles, exports, indexes, and optional retention counts) and does **not** execute operator commands, run apply, approve/reject proposals, prune/delete/archive metadata, or rebuild indexes.

The status safety block is invariant: `apply_mode=validation-only`, `execution_allowed=false`, `execution_status=not_executed`, and `mutation_performed=false`. The message “No ShellForgeAI remediation execution recorded” means no ShellForgeAI execution markers appear in ShellForgeAI audit metadata; it is not proof of external operator behavior outside ShellForgeAI.

## Metadata hygiene safety
- Doctor/status metadata hygiene is report-and-guidance only.
- No automatic cleanup is performed.
- `shellforgeai audit prune` remains dry-run by default.
- Deletion still requires explicit `--execute --confirm` (PR46).

## PR46 — first guarded mutation gate

PR46 introduces the first intentional mutation step ShellForgeAI will execute.
Scope is strictly bounded:

- The only allowed mutation is deletion of ShellForgeAI-owned metadata under
  `<data_dir>` and `<data_dir>/audit`, selected by the existing retention/prune
  planner.
- Deletion requires both `--execute` and `--confirm` on the `audit prune` CLI.
  Either flag alone refuses, deletes nothing, and exits non-zero.
- Every candidate path is validated against the allowed roots before any
  deletion. Targets that resolve outside the allowed roots, that equal a
  protected root (`/`, `<data_dir>`, `<data_dir>/audit`), or whose symlink
  escapes the allowed roots are refused.
- Protected categories (`approvals`, `audit-events`) are refused; default
  prune excludes artifacts/approvals/audit events.
- Each execute writes a JSON + markdown receipt under
  `<data_dir>/prune_receipts/` recording mode, category, selection, deleted
  paths, `bytes_removed`, and a `safety` block asserting metadata-only scope
  and `remediation_execution: false`.
- Audit events for prune carry `details.metadata_cleanup_executed`,
  `details.remediation_execution=false`, and
  `details.shellforgeai_owned_paths_only=true`. The audit safety block
  remains `execution_allowed=false`, `execution_status=not_executed`,
  `mutation_performed=false`; ShellForgeAI does not claim service or system
  remediation.

Metadata cleanup is **not** remediation execution. PR46 does **not**:

- run Docker commands or mutate containers/volumes,
- run `systemctl`/service control,
- run apt/yum/dnf/apk/pip,
- chmod/chown arbitrary paths,
- run `rm` against arbitrary host paths,
- change firewall/routes/DNS,
- run generated operator scripts,
- change `apply`, which remains validation/preflight-only.

### Natural language cannot delete

Ask routing for cleanup phrasing (`clean up old metadata`, `delete old exports
now`, `cleanup now`, `free up shellforgeai disk`) only returns a retention
report and a dry-run recommendation, and prints the explicit CLI command
needed for execution. Ask refuses to delete and points operators to
`shellforgeai audit prune ... --execute --confirm`.

## PR47 — first non-metadata mutation gate (lab container restart)

PR47 introduces the *first and only* non-metadata mutation step ShellForgeAI
may execute. Scope is intentionally tiny:

- The only allowed mutation is `docker restart <container>` where
  `<container>` is in the explicit lab allowlist at
  `<data_dir>/policy/lab-container-restart-allowlist.json` (disabled by
  default) **and** every gate below passes.
- Required gates: explicit `--execute`, explicit `--confirm`, env
  `SHELLFORGEAI_MUTATION_MODE=lab` and
  `SHELLFORGEAI_ALLOW_LAB_CONTAINER_RESTART=1`, allowlist file present and
  `enabled=true` with a non-empty `allowed_containers`, proposal status
  `approved`, the PR38 guard reports `fresh` (or `warning`) — never `stale`,
  `drift`, or `blocked`, the compiled action is exactly one
  `docker restart <safe-name>` (or operator selects via `--action-id`), the
  container name passes the safe-name regex
  `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$` and contains no shell metacharacters.
- Execution goes through an executor abstraction with `shell=False`, list-form
  `argv` only (`["docker", "restart", "<safe-name>"]`), and a required
  timeout. Tests use a fake executor; no live Docker is required.
- Each execute (and each refusal) writes a JSON receipt under
  `<data_dir>/execution_receipts/exec_<timestamp>_<shortid>.json` recording
  the proposal_id, action_id, container, exact argv, gates dict, exit code,
  short stdout/stderr previews, and a `safety` block asserting
  `scope=lab_container_restart_only`, `arbitrary_command_execution=false`,
  `package_mutation=false`, `filesystem_mutation=false`,
  `firewall_mutation=false`.
- The audit event for a successful lab restart is the first event in
  ShellForgeAI history with `safety.execution_allowed=true`,
  `safety.execution_status=executed`, `safety.mutation_performed=true`, and
  `safety.mutation_scope=lab_container_restart_only`. Every other audit event
  continues to assert `execution_allowed=false`/`execution_status=not_executed`/
  `mutation_performed=false`. Audit validation accepts the new event only
  with this exact kind/action/scope combination.

PR47 explicitly does **not**:

- run `docker compose up/down/restart/recreate`, `docker stop|start|kill|rm`,
  `docker exec`, `docker run`, or docker volume/image/network commands,
- run `systemctl`/service control,
- run apt/yum/dnf/apk/pip,
- chmod/chown/rm/mv/cp anything,
- change firewall/routes/DNS,
- execute generated operator scripts or arbitrary shell strings,
- accept `shell=True`,
- allow wildcards or regex in the allowlist,
- batch multiple actions into one execution.

### Natural language cannot restart

Ask routing for restart phrasing (`restart sfai-healthy-web`, `run the
approved restart`, `apply the approved restart`, `perform the restart`,
`bounce the container`, `restart it and verify`) refuses to execute,
surfaces the lab allowlist state, prints the explicit CLI command needed
(`shellforgeai apply <approved-proposal-id> --execute --confirm`), and
notes that PR48 verification will run automatically after that approved
CLI execution.

## PR48 — post-mutation verification gate (read-only)

PR48 adds **read-only** verification that runs automatically *after* the
PR47-allowed `docker restart <allowlisted-container>` exits 0. It does not
widen mutation scope. The set of allowed mutations is unchanged: exactly
one `docker restart <allowlisted-lab-container>`. PR48's only side effect
is reading state and writing a verification block, evidence files, and an
augmented audit event.

What verification may do:

- call `docker inspect <safe-name>` via `subprocess.run(..., shell=False)`
  on a list-form `argv` only (the `DockerCliInspector` rejects unsafe
  container names *before* invoking subprocess),
- bounded sleep between the restart command exit and the post-restart
  inspect (default 2 s, configurable in code/tests),
- bounded health-poll loop (default 10 s with 1 s interval) only when the
  container declares a healthcheck.

What verification must **not** do:

- re-attempt restart of any kind,
- call `docker exec`, `docker run`, `docker stop|start|kill|rm`, `docker
  compose ...`, `docker network|volume|image ...`,
- run any other system command (no `systemctl`, no package managers, no
  filesystem mutation, no firewall changes),
- accept `shell=True`,
- accept arbitrary command strings or operator-written shell scripts,
- mutate anything outside the receipt directory.

Verification status semantics (recorded in receipt and audit event):

- `passed` — restart exit 0, container exists and is running, `StartedAt`
  changed, healthcheck (if present) is `healthy`.
- `warning` — mutation succeeded but a soft signal triggered: `StartedAt`
  did not change, `RestartCount` did not change, healthcheck still
  `starting` after the bounded wait, or healthcheck status `unknown`.
- `failed` — container missing, container not running after restart,
  inspect failed, or healthcheck `unhealthy` after the bounded wait. The
  CLI exits non-zero and **does not** retry the restart.
- `skipped` — restart command itself failed (mutation never happened), so
  there is nothing to verify post-mutation.

Audit validation continues to accept exactly one mutation event shape:
`kind=execution`, `action=lab_container_restart`,
`safety.mutation_scope=lab_container_restart_only`,
`safety.execution_allowed=true`, `safety.execution_status=executed`,
`safety.mutation_performed=true`. The PR48 verification fields live in
`details.verification_status`, `details.container_running_after`,
`details.started_at_changed`, `details.health_after`, and
`details.verification_notes`. They never relax the mutation scope or
introduce new mutation kinds.

### Natural language cannot verify-and-mutate

Ask routing for verification queries (`did the restart work?`, `show
restart verification`, `show post-mutation verification`, `show last
execution receipt`, `was the container running after restart?`) is
read-only: it summarizes the latest receipt's verification block and
records an `ask` audit event with `mutation_performed=false`. Phrasings
that ask ShellForgeAI to *both* mutate and verify (`restart it and
verify`) are routed to the PR47 mutation refusal path and explicitly
remind the operator that verification runs automatically after the
approved CLI execution.


## PR50 restart proposal builder safety

- `approvals propose-restart` is metadata-only and never executes Docker commands.
- It requires evidence and only proposes for allowlisted/disposable lab targets.
- Natural-language restart execution requests remain refused.
- Rollback preview remains required before any `apply --execute --confirm` path.


## PR51 restart-plan safety

- `approvals restart-plan` is read-only and does not approve, restart, rollback-generate, or apply.
- Readiness evaluation uses existing proposal/evidence/rollback artifacts only and never executes Docker checks.
- Natural-language restart remains refused; ask routing can only show checklist/next commands.


## PR52 mission workflow safety

- `mission restart prepare/status/checklist/validate/export` are metadata only.
- The mission workflow does not approve proposals, generate rollback previews
  (unless `--with-rollback-preview` is passed, and even then only metadata),
  apply proposals, or restart anything.
- Mission records always carry `safety.execution_allowed=false`,
  `execution_status=not_executed`, `mutation_performed=false`, and
  `arbitrary_command_execution=false` unless an executed receipt is recorded
  later through the existing apply gate.
- `mission restart validate` enforces the schema, allowed phase statuses,
  exact `docker restart <target>` command preview, and refuses any
  `next_commands` that contain shell chains.
- Natural-language requests to "run the restart mission" remain refused; the
  only execution path is `apply <approved-proposal-id> --execute --confirm`
  with the existing PR47/PR48/PR49 gates.


## PR53 mission execute handoff safety

- `mission restart execute` does not introduce a new executor. It delegates to
  the same guarded code path used by `apply --execute --confirm`. The actual
  mutation remains the existing allowlisted `docker restart <target>` only.
- Without `--execute`, the command is dry-run only and prints the exact apply
  delegation command. `--execute` without `--confirm` is refused. Mission
  readiness must be green (approved proposal, exact `docker restart <target>`
  command preview, valid rollback preview, restart-plan readiness, guard
  freshness) or the handoff is refused with no mutation.
- Mission records reference (do not duplicate) the apply receipt under
  `phases.execution.receipt` and copy verification summary fields into
  `phases.verification`. `arbitrary_command_execution` remains false.
- Refusals are audited with `kind=restart_mission`,
  `action=execute_refused`; successful delegations are audited with
  `action=execute_delegated`. The actual mutation event remains recorded by
  the apply gate under `kind=execution` / `action=lab_container_restart` —
  the mission audit event does not duplicate the mutation safety flags.
- Natural-language asks ("run/execute the mission", "approve and run the
  mission") remain refused. `ask` never invokes the apply gate.


## PR54 mission report and export pack safety

- `mission restart report` and `mission restart export` are read-only with
  respect to source artifacts. They never approve, restart, roll back, or
  apply anything. They may *describe* a prior gated mutation if one occurred
  through the apply gate (PR47/PR48/PR49/PR53), but the report/export
  commands themselves perform no mutation.
- The mission report and export pack write only ShellForgeAI-owned files
  (`<data_dir>/mission_reports/<mission-id>/mission-report.{json,md}`,
  `<data_dir>/mission_exports/<mission-id>/...`). The mission record refresh
  performed when building the report preserves terminal executed/refused
  state (PR53 invariant): a report run never erases an apply receipt nor
  downgrades `executed` back to `ready`.
- Export manifests carry `safety.execution_allowed=false`,
  `safety.execution_status="not_executed_by_export"`,
  `safety.mutation_performed_by_export=false`,
  `safety.arbitrary_command_execution=false`, and
  `safety.rollback_execution=false`. Validation enforces these invariants
  and refuses an export with checksum mismatches, missing required files, or
  any of those safety flags flipped.
- Redaction is best-effort using the existing PR34 redactor. Operators
  should still review redacted exports before sharing. Raw source artifacts
  are never modified — only the exported copies under the export directory
  are redacted, and a `redaction-report.json` is included.
- `mission restart validate-export` is read-only. It re-reads the export
  directory and re-verifies checksums and safety invariants; it does not
  execute anything.
- Natural-language asks ("show mission report", "make a redacted mission
  pack", "did the mission execute safely") return the read-only report or
  the export pack. Asks that imply execution ("run mission and export")
  remain refused; only the explicit `mission restart execute --execute
  --confirm` (PR53) or `apply <approved-proposal-id> --execute --confirm`
  (PR47) can execute the gated mutation.

- PR55 cleanup review is metadata-only. `audit cleanup plan` and `audit cleanup archive` never delete; `audit cleanup execute` requires `--confirm` and path safety guards.

## PR56 Compose ownership context safety

- Compose context is read-only/advisory only in PR56.
- ShellForgeAI does not execute `docker compose` commands in PR56.
- Restart command preview remains exact `docker restart <container>` for allowlisted targets.
- Future compose service mutations require separate policy gates in a separate PR.

PR57 extends this with deterministic ask routing for Compose context phrasing
only. Natural-language Compose mutation requests (for example restart/up/down/
recreate) are refused and redirected to read-only `compose inspect` plus the
existing proposal/mission/apply safety gates.

## PR58 Compose-aware restart enrichment safety

- Compose context is still advisory/read-only. PR58 only enriches existing
  proposal/restart-plan/mission/receipt/closure metadata with Compose
  ownership info parsed from Docker labels (PR56 parser, unchanged).
- Restart scope remains the exact container. The proposal command preview
  remains exactly `docker restart <container>`; readiness blocks if a
  proposal's command preview ever tries to use `docker compose`.
- Apply receipts and mission reports record `restart_scope=container`,
  `compose_mutation=false`, and `arbitrary_command_execution=false`. The
  closure report explicitly states that no `docker compose` command was
  executed and the restart was exact-container scoped.
- `docker compose` mutation is **not enabled** in PR58. Compose service
  mutation asks ("propose restart for compose service X",
  "docker compose restart X", "compose up X", "recreate compose service X",
  "create compose restart proposal for X") are refused, with read-only
  suggestions and the existing container-scoped workflow as the only
  alternatives.
- Apply remains the only execution gate. PR58 adds no new mutation class,
  no new executor, no `docker compose` argv, and no broader mutation
  scope.


## Ask reference disambiguation (PR59)
- Reference resolution for implicit proposal/mission phrases is read-only.
- Ambiguous references are never guessed; ShellForgeAI asks for explicit IDs.
- Stale long-lived `/data` artifacts are warned for `this/latest/current` references.
- Natural-language execution remains refused.
- No docker compose mutation path is introduced.

## PR61 compose restart preview-only

- Compose service restart support is preview-only in PR61.
- Preview output marks the future command nature with `compose_mutation=true` while still enforcing `execution_allowed=false`.
- ShellForgeAI does not execute `docker compose` in this flow (`docker_compose_executed=false`, read-only).

## PR62 compose restart proposal builder (non-executable)

- ShellForgeAI can create a pending `compose_service_restart` proposal artifact from read-only compose metadata.
- Proposal records `compose_mutation=true` and `proposal_only=true` while enforcing `execution_allowed=false`.
- `apply` must refuse this proposal kind in PR62; compose execution is not implemented yet.
- No docker compose command is executed (`docker_compose_executed=false`), no container is restarted, and no mission/rollback preview is auto-created.
- Future execution requires proposal, approval, rollback preview, mission readiness, apply gate, verification, and receipts.

## PR64 compose restart preflight and verification hardening

- Compose service restart mission execution is gated by explicit Compose CLI/plugin preflight before mutation.
- Preflight failures block execution before `docker compose restart` and surface structured blockers in mission status/checklist/validate/execute/report outputs.
- On preflight block, safety fields remain `docker_compose_executed=false` and `container_restarted=false`, with restart returncode unset/null because restart was never invoked.
- ShellForgeAI does not use host-side bypass wrappers; no SSH/nsenter/sudo workaround path is introduced.
- ShellForgeAI still does not support `docker compose up/down/recreate` and still refuses natural-language mutation execution.


## PR65 compose rollback/recovery preview hardening
- Compose rollback preview is explicitly a **recovery preview** (metadata + operator guidance), not automatic rollback execution.
- ShellForgeAI does not run `docker compose` in rollback preview/validation, does not run `up/down/recreate`, and does not generate executable compose rollback scripts.
- Config evidence in this lane is hash-only where available (e.g., compose file checksum); env/config contents are not stored.
- A valid compose recovery preview is required for compose restart mission readiness gates.

## PR66 compose execution environment diagnostics

- `shellforgeai compose env-check` is read-only diagnostics only.
- It may run bounded read-only preflight checks (Docker CLI/socket/Compose capability probes) and inspect existing Compose metadata/snapshots.
- It does not create proposals, missions, or rollback previews.
- It does not execute `docker compose restart` (or any Compose mutation command).
- Host-side bypasses (manual mounts/nsenter/ssh/sudo wrappers) remain intentionally out of scope.
