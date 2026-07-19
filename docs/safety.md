# Safety

## V1 safety contract

V1 release validation must explicitly prove deterministic refusal and governed
gates. Use [`docs/V1_RELEASE_CANDIDATE.md`](V1_RELEASE_CANDIDATE.md) as the
release-candidate checklist.

- Safety classes for V1 command inventory are defined in [`docs/V1_COMMAND_SURFACE.md`](V1_COMMAND_SURFACE.md): READ_ONLY, ARTIFACT_WRITE, GOVERNED_PLAN_ONLY, GOVERNED_DISPOSABLE_MUTATION, REFUSED_BY_DEFAULT, and OUT_OF_V1.
- Read-only by default.
- Natural-language mutation requests are refused deterministically.
- No `shell=True` and no arbitrary command execution from prompts.
- Governed remediation lanes are explicit and gated.
- Disposable-only proof language applies to remediation execution paths.

### What self-tests prove

- Runtime, command surface, deterministic safety routing, and mutation refusal
  remain intact for the configured profile.
- Self-tests do **not** grant production mutation rights or bypass gates.

### What V1 does not promise

- No autonomous production remediation.
- No automatic repair or production restart from natural language.
- No broad Docker/Compose execution outside governed disposable lanes.

ShellForgeAI is built to be safe by construction. The runtime does not run
arbitrary shell, does not mutate the host without policy approval, and
treats model output as advisory.

`shellforgeai ops status` is read-only reporting only: it summarizes existing
artifacts/metadata and does not approve, apply, execute, restart, or generate
rollback previews, closure reports, exports, or cleanup plans.


## Product maturity context

Current product maturity is defined in [Product status](PRODUCT_STATUS.md): V1 released; early beta-quality; guarded and not production-autonomous. Safety boundaries are part of that guarded product model, not an Alpha classification. Linux/Docker remains the primary V1 lane; Windows preview maturity is tracked separately.

## North Star implementation boundary

Future approved implementation remains subject to the [North Star](north-star.md) contract: supported, typed, bounded implementation of the exact approved solution, not raw natural-language or arbitrary command execution.

## Boundaries

- **No arbitrary shell.** Tools are typed wrappers around specific binaries
  with bounded arguments. The interactive REPL is not a shell; pasted

Automatic role/health handling for broad operator questions is read-only only: it reuses existing diagnosis context and built-in collectors, does not run arbitrary shell, and does not execute remediation/rollback/cleanup/restart actions.
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
ShellForgeAI does not escape container namespaces to bypass these gaps; it reports visibility limits explicitly and keeps diagnosis/readouts truthful to container-visible scope.


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
apply remains validation-only in this guarded V1 boundary.

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

Model-provider auth failures are reported as clean operator messages, with raw JSONL/provider event streams suppressed from assessment prose. ShellForgeAI never auto-runs login and never prints auth tokens/secrets.

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

### Command-help vs mutation (PR131)
- Command-help is explanation only: ShellForgeAI can show the safe command without running it. Requests like "what command would restart this?", "show me the command to inspect sfai-crashloop", "how would I propose remediation?", and "how do I review cleanup safely?" are answered with `No action was taken.` plus safe read-only or clearly-labelled plan-only commands. No command is executed and no plan/proposal is created from a command-help answer.
- Command-help answers never suggest `--execute --confirm`, `remediation execute`, `rollback execute`, `audit cleanup execute`, `docker restart`, or `docker compose restart` as next commands. Plan-only guidance is always labelled `Plan-only; does not execute remediation.` and notes that execution remains gated by validate, preflight, and explicit confirmation.
- A mutation verb embedded inside a command-help frame is guidance, not execution: "what command would restart this?" is command-help; "restart this" is a refused mutation. Ambiguous "run that" / "do it now" phrasings are refused deterministically with no action taken, and remain distinct from PR124's safe read-only follow-up phrases (`get that info`, `do that`) which only resolve pending read-only checks.
- Mutation still requires the explicit governed CLI gates; natural language never executes restart/remediation/cleanup/rollback or Docker/Compose changes.

## Status dashboard safety

`shellforgeai status` is strictly read-only. It is the V2 golden-path entrypoint and wraps the concise ops-report ranking path: no model/Codex call, no artifact write by default, no proposal/mission/apply creation, and no cleanup/remediation/rollback/Docker/Compose/restart execution. Use `shellforgeai ops report --save` when a persisted report artifact is needed.

The status safety block is invariant: `read_only=true`, `mutation_performed=false`, `artifact_written=false`, `model_called=false`, `shell_true=false`, and `arbitrary_command_execution=false`. It reports ShellForgeAI's current read-only inspection result; it is not proof of external operator behavior outside ShellForgeAI.

## Apply-preview safety

`shellforgeai apply-preview` is strictly read-only. It previews the V2 execution boundary after `propose` by reporting no-action, blocked, or gated preview state for an exact target. It does not apply anything, create a mission, create an apply record, create a remediation execution receipt, create an executable plan, call Docker or Docker Compose, restart containers, mutate files/services/host state, call the model, or use shell execution.

The apply-preview JSON safety block is invariant: `read_only=true`, `mutation_performed=false`, `apply_executed=false`, `mission_created=false`, `plan_created=false`, `remediation_executed=false`, `rollback_executed=false`, `cleanup_executed=false`, `docker_compose_executed=false`, `container_restarted=false`, `shell_true=false`, `arbitrary_command_execution=false`, `natural_language_execution=false`, and `model_called=false`. Production-like targets are refused, missing targets are blocked, and mixed natural-language preview-plus-mutation asks keep the preview read-only while refusing the mutation part.

## Metadata hygiene safety
- Doctor/status metadata hygiene is report-and-guidance only.
- A metadata hygiene `warning`/`critical` is ShellForgeAI-owned artifact hygiene (accumulated reports/exports/bundles under `data_dir`). It is **not** an automatic Docker/system runtime failure, and it does **not** mean any cleanup was performed.
- The safe first response to a metadata hygiene warning is the read-only `shellforgeai audit cleanup review`. Cleanup execution stays gated: `review -> plan -> archive -> validate -> execute --confirm`.
- Doctor/ops metadata hygiene output is read-only and may suggest commands, but never performs cleanup.
- No automatic cleanup is performed.
- Cleanup is limited to ShellForgeAI-owned metadata under `data_dir`; paths resolving outside `data_dir` are refused/skipped.
- No Docker/Compose/system cleanup is performed by hygiene, retention, or cleanup review commands.
- `shellforgeai audit prune` remains dry-run by default.
- Deletion still requires explicit `--execute --confirm` (PR46).
- `shellforgeai audit cleanup review` (PR74) is strictly read-only: it
  summarizes the footprint, marks supported vs report-only categories,
  recommends a conservative `--max-age-days 7 --keep-latest 5` dry-run
  plan for `exports`, and restates the PR71 deletion gates. It never
  creates plans/archives/receipts, never deletes, never touches Docker
  or the system, and never accepts natural-language execution.
- The PR55/PR71 cleanup execute gates are unchanged: `--confirm`,
  matching validated archive, matching plan fingerprint, candidate paths
  inside allowed `<data_dir>` roots, and receipt validation are all
  still required before any deletion.
- `shellforgeai audit cleanup prepare` (PR75) is a guided pre-execution
  workflow. It creates ShellForgeAI-owned plan and archive metadata, runs
  the existing archive validation, and emits a decision packet — then
  stops. It never deletes candidate files, never calls cleanup execute,
  never touches Docker/Compose/services/packages/firewall/network/system,
  and never accepts natural-language execution. Unknown or path-traversal
  category values are refused before any plan/archive is created.
  Cleanup execute remains separate and still requires `--confirm` plus
  the full PR71 archive/fingerprint/validation gate.
- `shellforgeai audit cleanup execute-readiness` (PR76) is a read-only
  readiness check that re-asserts the PR71 gates (plan kind/safety,
  matching cleanup archive, archive validation, plan fingerprint,
  allowed-root candidate paths) before the operator runs
  `cleanup execute --confirm`. It creates no plans, no archives, no
  receipts, deletes nothing, never touches Docker/Compose/services/
  packages/firewall/network/system, and never accepts natural-language
  cleanup execution. The matching `audit cleanup report` command is also
  read-only. Cleanup execute remains gated by `--confirm`, matching
  archive, archive validation, and matching plan fingerprint.
- PR77 polishes the operator-facing UX around the final boundary
  without changing any gate. `audit cleanup execute-readiness` now
  emits explicit top-level `ready_for_execute_confirm`,
  `operator_action_required`, `read_only`, `cleanup_executed`, and
  `deletion_performed` fields, plus a `gates` block, and the human
  output states `This command did not delete anything.` whether the
  plan is ready or blocked. The blocked branch refuses to show the
  execute command as safe. `audit cleanup execute` refusal without
  `--confirm` now lists `matching archive`, `archive validation`,
  `matching plan fingerprint`, and `explicit --confirm` as required
  gates and explicitly says `Nothing was deleted.` `audit cleanup
  report` now exposes a `post_execute_checks` array
  (`audit cleanup validate <receipt>`, `audit retention`,
  `audit cleanup review`, `doctor`). None of these changes broaden
  cleanup scope, automate cleanup, or weaken PR55/PR71 gates;
  readiness and report remain strictly read-only, and only
  `audit cleanup execute <plan> --confirm` deletes.

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

- PR55/PR71 cleanup review is metadata-only. `audit cleanup plan` and `audit cleanup archive` never delete; `audit cleanup execute` requires `--confirm`, a matching validated archive, and path safety guards. Cleanup remains restricted to ShellForgeAI-owned metadata paths only (no Docker/Compose/system cleanup).

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

## PR67 disposable Compose execution harness policy

- The disposable Compose harness (`examples/compose/disposable-restart/`,
  `tests/fixtures/compose/disposable-restart/`, and
  `scripts/pr67_disposable_compose_harness.sh`) is a lab-only target range.
- Real ShellForgeAI services remain blocked from Compose restart execution.
  Production services must not be labeled `shellforgeai.disposable=true` or
  `shellforgeai.allow_restart=true` to make tests pass. The disposable label
  is reserved for throwaway test stacks.
- A target only becomes execution-eligible when it carries the
  `shellforgeai.disposable=true` (or `shellforgeai.allow_restart=true`)
  label *and* every PR61–PR66 gate still passes: approved proposal with valid
  fingerprint, complete Compose metadata, readable compose file with
  `compose_file_sha256`, valid rollback recovery preview, Compose CLI
  preflight ok, and `--execute --confirm` on the mission.
- The disposable harness does not bypass any of these gates. It is the
  *only* shape of target that can pass them.
- ShellForgeAI app commands still never run `docker compose up`, `docker
  compose down`, or `docker compose recreate`. The optional
  `scripts/pr67_disposable_compose_harness.sh` is an external operator
  helper, not a ShellForgeAI execution path; it refuses to act on anything
  but the disposable `sfai_pr67_disposable` project.
- Natural-language Compose mutation (`docker compose restart …`, `execute
  latest compose restart mission`, etc.) is still refused and routed to the
  gated CLI lane.
- No host-side bypass (SSH/nsenter/sudo wrappers) was introduced.
- No generic Compose executor was introduced.

## PR68 optional live disposable Compose restart proof policy

- PR68 adds no new ShellForgeAI mutation capability. It adds a lab-only
  orchestrator script (`scripts/pr68_disposable_compose_restart_proof.sh`)
  plus docs so NewTwo/operators can prove the existing PR63-PR67 gated
  Compose service restart lane end-to-end against the PR67 disposable
  harness target.
- The orchestrator is external to the ShellForgeAI app. The app never
  invokes it. The orchestrator never bypasses ShellForgeAI gates.
- Default mode is dry-run / print-only / read-only readiness. The
  orchestrator does not pass `--execute --confirm` for the operator. It
  refuses to drive any execution unless the explicit dangerous flag
  `--execute-approved-disposable-restart` is provided AND
  `compose env-check` reports `compose_restart_execution_ready=true`
  AND the target name is exactly `sfai-pr67-compose-web`.
- Even with the dangerous flag, the orchestrator only verifies readiness
  and prints the manual gated command sequence. The operator runs
  `shellforgeai mission compose-restart execute <mid> --execute --confirm`
  themselves. The app's gates remain the source of truth.
- The orchestrator refuses production-looking target names
  (`shellforgeai`, anything containing `production`/`prod`).
- PR68 does not add `docker compose up/down/recreate` from ShellForgeAI.
- PR68 does not add a generic Compose executor.
- PR68 does not install packages at runtime, does not mount host paths
  from inside ShellForgeAI, does not SSH/nsenter/sudo to the host, does
  not run `docker system prune`, and does not delete arbitrary paths.
- PR68 does not enable natural-language Compose mutation. Asks like
  "docker compose restart sfai-pr67-compose-web" remain refused and
  routed to the gated CLI lane.
- Environment readiness (Compose CLI inside the ShellForgeAI runtime,
  readable compose file path, populated `compose_file_sha256`,
  allowlist labels) remains a deliberate operator-prepared property.
  PR68 documents how to prepare it; it does not auto-configure it.

## PR69 compose execution environment contract

- `shellforgeai compose env-contract` is diagnostics/readiness reporting only; it does not execute restart or any Compose mutation command.
- PR69 does not loosen existing safety gates. Production targets remain blocked unless explicitly disposable+allow_restart in a disposable test scope.
- Contract gates are explicit across environment, target safety, and compose-file snapshot/rollback prerequisites.
- Host-side bypasses are out of scope: no host path remount automation, no ssh/nsenter/sudo host pivoting, and no generic Compose executor path is introduced.
- Natural-language execution requests for Compose mutation remain refused.

## PR73 compose execution environment readiness plan

- `shellforgeai compose env-plan` is read-only enablement guidance only.
  It consumes env-check / env-contract output and maps each readiness
  blocker to an explicit operator-controlled remediation step.
- ShellForgeAI does **not** install Docker Compose, does **not** mount
  host paths from inside the container, does **not** edit compose files,
  does **not** label production services disposable, does **not** run
  `docker compose` (restart / up / down / recreate / config), and does
  **not** create proposals, missions, rollback previews, apply, or
  cleanup artifacts from env-plan.
- Environment changes are operator-controlled external setup only.
  Every plan entry carries `shellforgeai_action="none"` and
  `automated=false`. The `allowed_for_production` flag is always `false`.
- Production-like targets (`shellforgeai`, anything containing
  `production` / `prod`) that are not already allowlisted are flagged
  with a warning and routed to the PR67 disposable harness recommendation.
  env-plan will never suggest labeling production services
  `shellforgeai.disposable=true` or `shellforgeai.allow_restart=true`.
- No host-side bypass (SSH / nsenter / sudo wrappers) was introduced.
  No generic Compose executor was introduced. No `shell=True` invocation
  was introduced.
- Natural-language Compose mutation (`docker compose restart …`,
  `fix compose execution environment`, `install docker compose`,
  `mount the compose file`, `label shellforgeai disposable`,
  `restart compose service now`, `execute the proof`) remains refused
  and routed to the explicit gated CLI lane.
- env-plan does not weaken any PR63–PR71 gate. The PR68 optional
  disposable Compose restart proof remains blocked until every
  env-contract / env-plan blocker is resolved by deliberate operator
  action outside ShellForgeAI, with explicit operator approval.

## PR70 metadata hygiene reporting safety

- Doctor / status / retention hygiene output is read-only.
- Doctor JSON includes structured `metadata_hygiene.reasons[]` and
  `suggested_commands[]` so operators can script the safe sequence
  without ambiguity. Suggestions are commands, not actions; nothing is
  performed by reporting.
- Cleanup plan output adds matched/kept/candidate and
  outside-`<data_dir>` counters with explicit safety flags. No deletion
  occurs at planning time.

## PR71 cleanup execute archive/fingerprint gate

- `audit cleanup execute <plan-id> --confirm` is the only command that
  may delete under the PR55 cleanup lane.
- Execute refuses unless **all** of the following are true:
  - `--confirm` is present on the command line.
  - A matching, validated cleanup archive exists for the same plan.
  - The plan fingerprint recorded in the archive matches the plan
    fingerprint on disk.
  - Every candidate path resolves inside the allowed `<data_dir>`
    roots (no symlink escapes, no protected roots).
  - The category is not protected (`approvals`, `audit-events`).
- A JSON+markdown receipt under `<data_dir>/cleanup_receipts/` records
  plan/archive linkage, candidate/deleted/skipped/failed counters, and
  explicit safety flags. Receipts validate after execute.
- Scope remains ShellForgeAI-owned metadata only. No Docker/Compose/
  system mutation. Natural-language cleanup execution remains refused
  and is routed to the explicit `--confirm` CLI guidance.

## Quick mutation boundary summary (current)

| Lane                                 | Allowed real mutation                                          | Required gates                                                                                                                                                  |
| ------------------------------------ | -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Metadata cleanup (PR46)              | delete ShellForgeAI metadata under `<data_dir>`                | `audit prune … --execute --confirm`, allowed root, non-protected category                                                                                       |
| Metadata cleanup (PR55 + PR71)       | delete ShellForgeAI metadata under `<data_dir>`                | plan → archive → validate → `cleanup execute <plan-id> --confirm` with matching fingerprint and validated archive                                              |
| Exact-container restart (PR47/48/49) | exactly one `docker restart <allowlisted-container>`           | allowlist enabled with the target, `SHELLFORGEAI_MUTATION_MODE=lab`, `SHELLFORGEAI_ALLOW_LAB_CONTAINER_RESTART=1`, approved proposal, fresh guard, `--execute --confirm` |
| Compose service restart (PR63+)      | exactly one `docker compose … restart <disposable-service>`    | approved `compose_service_restart` proposal, valid recovery preview, env-contract green (compose CLI in runtime, readable compose file, hash), disposable + allow_restart labels, `--execute --confirm` |

Everything outside this table is read-only / preview-only / proposal-only
/ refused. `apply` for any non-PR47 proposal kind remains
validation/preflight-only.

## PR79 / PR80 safe command coverage harness safety

`shellforgeai self-test commands` (and `--json`,
`--profile quick|standard|full`, `--fail-on-warn`, `--include-skipped`)
is a strictly read-only operator coverage harness. It exercises core CLI
command surfaces in sequence and reports pass/fail/warn/skip. Every
profile (`quick`, `standard`, `full`) is read-only and safe to run after
every deployment. None of the profiles:

- run `audit cleanup execute`, `audit cleanup prepare`, or
  `audit cleanup archive`,
- create cleanup plans, cleanup archives, cleanup receipts, proposals,
  missions, apply bundles, exports, or actions,
- execute `apply`, mission execute, lab container restart, or any docker
  / docker compose mutation,
- broaden natural-language behavior — it only verifies that the existing
  router already flags the phrases it checks as mutation requests; no
  new phrases are added to the router,
- shell out — invocations go through the in-process Typer/Click runner
  and never use `shell=True`,
- depend on a live Docker daemon, real `/data`, root, internet, or
  systemd/journal access for its automated tests.

If a check cannot run (no runbook artifact, compose target absent from
Docker inventory, Docker unavailable, audit storage empty), the harness
records it as `skip` with an explicit reason and — when the cause is an
incomplete environment rather than a profile exclusion — sets the row's
`warn:true` flag and counts it in `summary.warned`. Real failures are
surfaced as `fail` with their exit code or exception type, not hidden.

`--fail-on-warn` exits non-zero when the overall status is `warn`. It is
a CI strictness knob: warnings remain warnings (the JSON `status` stays
`warn` and a `ci_status: "failed_on_warn"` field is emitted). It does
not convert warnings into runtime failures and does not change which
checks are run.

The optional disposable mutation lane is intentionally **not** implemented:
the JSON payload reports it as `implemented=false`, `executed=false`,
`status=manual_only`. A future PR (with its own gate, allowlist,
receipt, and audit event) would be required to enable it.

## PR81 triage ranking safety

`shellforgeai triage docker` (PR81) is **read-only**. It inventories the
current Docker scene through the existing read-only `docker.containers`
and `docker.problem_summary` collectors and deterministically ranks
suspects across multiple failure classes (crashloop, noisy errors, bad
HTTP / upstream / refused, disk pressure, permission denied, plus a
high-CPU watch lane for loud-but-healthy containers).

The command never:

- starts, stops, restarts, removes, or prunes containers,
- runs `docker compose` mutation,
- runs `cleanup prepare/archive/execute`,
- creates proposals or missions,
- runs `apply`,
- writes outside its in-memory JSON/human payload,
- uses `shell=True` or any natural-language execution path.

Every `triage docker --json` payload sets `safety.read_only=true`,
`safety.mutation_performed=false`, and explicitly `false` for
`cleanup_executed`, `proposal_created`, `mission_created`,
`apply_executed`, `docker_compose_executed`, `container_restarted`,
`natural_language_execution`, and `shell_true`. Per-suspect
`safe_next_commands` are constrained to canonical read-only `shellforgeai triage ...` / `shellforgeai remediation eligibility ... --explain` flows
invocations — never a restart, never a remediation execution.

Natural-language mutation refusal is unchanged. PR81 does not broaden the
ask router; mutation phrases ("restart the top suspect", "fix the
crashloop", "clean up disk now") continue to refuse with the existing
PR74–PR80 wording.

## PR82 broad ask triage grounding safety

`shellforgeai ask` routes broad read-only Docker / 2AM triage prompts
("what's on fire?", "2AM triage", "the Docker box feels broken", "rank
Docker suspects", "broadly scan the current scene", "rank all
sfai-battle-lab suspects by severity", "what should I inspect first?",
"show current Docker suspects", "what containers look suspicious?") to
the PR81 deterministic triage engine (`triage_ranking.collect_scene` +
`rank_scene`) rather than to a model-only rephrase. The handler reads
the scene through the same read-only Docker collectors PR81 uses,
preserves the deterministic ranking/severity/confidence/evidence, and
renders the answer with a Safety block (`read_only: true`,
`mutation_performed: false`, no restart/stop/delete/prune/apply/cleanup),
per-suspect read-only `Safe next` commands (always `shellforgeai
diagnose …`), and a Next-safe-steps footer pointing at the explicit
`triage docker --json` and `diagnose docker --save-plan --with-runbook`
commands.

The broad ask triage route may rank suspects, but it never executes
fixes. It does not:

- restart/stop/remove containers,
- run `docker compose` mutation,
- run `cleanup prepare/archive/execute`,
- create proposals or missions,
- run `apply`,
- use `shell=True` or any natural-language execution path.

Mutation phrasings tied to the ranking ("restart the top suspect",
"fix the crashloop", "clean up disk pressure now", "stop
noisy-errors", "apply the top fix", "create a restart proposal for
the top suspect", "docker compose restart the top one", "delete old
files causing disk pressure") refuse from ask with the PR82
no-mutation wording (`I can rank suspects read-only, but I will not
execute fixes from ask.` / `No restart, cleanup, apply, or proposal
was executed.`) and redirect the operator to the explicit gated CLI
(`shellforgeai triage docker`, `shellforgeai diagnose docker
--container <name> --json`). The PR47 lab-restart refusal and the
PR58/PR63 Compose mutation refusal remain the source of truth for
container-level / compose-level mutation execution requests.

The broad ask triage path is fixture-driven for testability — the
test suite drives the scoring engine directly via
`triage_ranking.collect_scene` patches, so battle-lab regression
coverage runs without a live Docker daemon and never mutates the host.

PR105 extends this safety model with deterministic ask-to-ops-report routing for
common operator prompts (`it's 2am, what is on fire?`, `docker is broken, what
should I check first?`, `show me the ops report`, `summarize current docker
incidents`). This route bypasses model-backed ask/auth and runs the same
read-only report builder as `shellforgeai ops report`. It still reports
`natural_language_execution=false` because natural language only selected a
deterministic read-only report path; no mutation path was executed.

## PR83 triage detail drilldown safety

`shellforgeai triage docker detail` is read-only evidence drilldown. It reuses deterministic triage scoring, selects one suspect by name or rank, and reports evidence/why/next read-only checks. It never restarts/stops/removes containers, never runs compose mutation, never executes cleanup/apply/mission, and never creates proposals or missions. Natural-language mutation requests remain refused.

## PR84 triage snapshot safety

`shellforgeai triage docker snapshot` is read-only incident handoff packaging. It reuses deterministic triage ranking/detail evidence to emit scene summary, ranked suspects, optional compact details, safe next read-only commands, and explicit safety flags. It does not restart/stop/remove/prune containers, does not run cleanup, does not create proposals/missions, does not run apply/remediation execution, and natural-language mutation requests remain refused.


## PR85 triage snapshot save/validate safety

`shellforgeai triage docker snapshot --save` writes only ShellForgeAI-owned artifact metadata under `<data_dir>/artifacts` (snapshot JSON/Markdown + manifest/checksums metadata) and never executes remediation. `shellforgeai triage docker snapshot validate` is read-only verification of required files/JSON/safety/checksums and never creates proposals/missions or runs cleanup/apply/compose mutation. Snapshot id/path resolution is constrained to avoid arbitrary path writes/traversal.

`shellforgeai triage docker snapshot export` packages a previously saved triage snapshot into a ShellForgeAI-owned export directory under `<data_dir>/exports` and records export manifest/checksum metadata. `shellforgeai triage docker snapshot export-validate` is read-only verification of that bundle (files, JSON parse, checksums, safety flags). These commands do not execute cleanup/proposals/missions/apply/remediation and reject unsafe output paths.



PR97 adds `shellforgeai remediation eligibility` as a **read-only** triage-to-remediation map. It never creates a plan, never executes remediation/rollback/cleanup, and only suggests safe plan-stage commands (for example `remediation plan`, `triage docker detail`, `remediation audit`).

PR99/PR102/PR103: `shellforgeai remediation self-test` is non-mutating by default. The `full` profile runs an isolated lifecycle readiness probe (plan/validate/preflight/refusal/proof execute/receipt/report/bundle/audit) in temp data; proof executor remains non-mutating, and live docker-disposable execute is skipped by default.

PR103 adds an optional **lab-only** live disposable proof gate behind explicit flags:
- `--include-live-disposable-execute`
- `--target <exact target>`
- `--confirm-live-disposable`

Safety gates refuse mutation unless the target is exact, non-production, and labeled disposable + allow_restart. This path does not enable production remediation, does not add Docker Compose mutation, does not execute cleanup, and does not enable natural-language execution.
PR98 adds `shellforgeai remediation eligibility --target <name> --explain` as a **read-only explain/report** mode. It explains gate outcomes and label blockers only, includes explicit no-mutation safety flags, never creates plans, never executes remediation/rollback/cleanup, and never suggests bypassing safety gates. Production targets remain intentionally ineligible; do not add `shellforgeai.allow_restart=true` to production targets.

PR89 adds a **governed disposable remediation proof** CLI (`remediation plan/validate/execute/status`) scoped to an explicit disposable and allowlisted battle-lab target only. Safety gates refuse production `shellforgeai`, unlabeled targets, missing allowlist labels, broad selectors (`all`, `*`, `everything`), unsupported scenarios, and suspicious target strings. Execution is blocked unless `--execute --confirm` is provided, and natural-language execution remains refused. Receipts include post-check verification and immutable safety flags (`shell_true=false`, `arbitrary_command_execution=false`, no cleanup/mission/apply/compose mutation).

`shellforgeai triage docker timeline` is read-only incident trend analysis over previously saved triage snapshots under `<data_dir>/artifacts`. It validates snapshots before use, computes timeline drift intelligence only, and does not execute cleanup/proposal/mission/apply/remediation or Docker/Compose mutation.


PR89 execution path currently uses a governed disposable proof executor for receipt/verification flow validation and is explicitly **not live Docker remediation**.


## PR90 disposable executor mode contract

PR90 introduces explicit executor modes for disposable remediation execution:

PR91 adds read-only remediation receipt hardening and handoff reporting:
- `remediation receipt validate` verifies receipt schema, plan linkage/fingerprint (when plan exists), disposable/allowlist gates, executor-mode invariants, and safety flags.
- `remediation report` summarizes receipt evidence for operator handoff and never executes Docker/Compose/cleanup/apply/mission actions.
- No production remediation behavior is added; validate/report are artifact-only.


Verification for `docker-disposable` uses exact-target pre/post `docker inspect` evidence (bounded to the planned target only), with restart success requiring changed `StartedAt` or restart-count evidence plus successful `docker restart` return code.

- `proof` (default): artifact/receipt proof only, no real Docker restart, `proof_executor=true`, `real_docker_executor=false`.
- `docker-disposable` (explicit opt-in): exact-target-only `docker restart <target>` for disposable + `shellforgeai.allow_restart=true` targets, with pre/post verification and production refusal.

Safety remains invariant: no natural-language execution, no arbitrary command execution, no `shell=True`, no Docker Compose mutation, and no production mutation.


## PR92 remediation preflight packet safety

- `shellforgeai remediation preflight <plan-id>` is strictly read-only: it does not execute remediation, does not restart targets, does not create receipts, and does not perform cleanup/mission/apply/compose mutation.
- Preflight re-checks target eligibility using live metadata when available and applies the same production, allowlist, disposable, and broad-target refusal gates as governed execution.
- `ready` means gates are satisfied; it is not execution approval. Actual mutation still requires `shellforgeai remediation execute <plan-id> --executor docker-disposable --execute --confirm`.

## PR93 disposable remediation rollback posture safety
- Rollback for disposable remediation is modeled as bounded recovery only: `rollback_kind=bounded_recovery_restart` and `rollback_strategy=repeat_exact_target_restart`.
- `remediation rollback-preflight` is read-only. `remediation rollback-execute` is disposable-only, exact-target-only, requires explicit `--execute --confirm`, blocks production/unlabeled targets, and writes rollback receipts with StartedAt verification.
- Automatic rollback stays disabled (`automatic_rollback=false`), and production rollback remains refused.

- Remediation lifecycle bundles are read-only packaging/report artifacts.
- `remediation bundle` and `remediation bundle validate` never execute remediation or rollback.
- `remediation audit` is read-only lifecycle visibility: it only reads plan/receipt/rollback/bundle artifacts, summarizes latest lifecycle state, reports invariant/safety flags, and can surface unsafe historical artifacts as warnings without mutating those artifacts.


### Diagnose/Triage cohesion (read-only)
Diagnose enrichment for known Docker/battle-lab targets is read-only: it does not create plans, does not execute remediation/rollback/cleanup, and only suggests canonical read-only next commands.

## PR106 deterministic ask mutation-refusal routing safety

`ask` now performs a deterministic pre-model mutation-intent check. Obvious natural-language mutation prompts (for restart/stop/remove/delete/prune/fix/remediate/execute/apply/rollback/cleanup/compose mutation/chmod/chown/install classes) are refused **before** model/Codex invocation.

- No model/auth dependency is required for these refusals.
- Refusal output states that no action was performed.
- Refusals only suggest canonical read-only alternatives.
- `ask` never executes remediation/rollback/cleanup/Docker/Compose mutation.


## PR122 interactive latest-evidence follow-ups

Interactive follow-up questions that reuse the latest in-session diagnosis
context (for example `what did you find?`, `why is it slow?`, `is it
running normally?`, `what does this system do?`) are strictly read-only.

- They answer from a compact in-memory snapshot of the latest diagnosis
  (target, evidence highlights, artifact paths, limitations, safe next
  commands) plus already-written artifact summaries.
- They never run new collectors, execute shell, or invoke
  remediation/rollback/cleanup or Docker/Compose mutation.
- The stored snapshot holds only summaries/metadata — no raw logs, no
  secrets, and no raw Codex JSONL.
- Short natural-language continuations like `get that info` / `do that` / `proceed`
  only auto-resolve when the pending action is explicit read-only evidence
  collection. If the pending action is mutating/gated, ShellForgeAI refuses
  and reports that no action was taken.

- Mutation-style follow-ups (`fix it`, `restart it`) are never answered
  from latest context; they are refused with no action taken.
- `/pending` surfacing the latest diagnosis context is display-only and
  does not call model providers or collectors.

### Ops report handoff artifacts
`ops report --save` and `ops report export` only write ShellForgeAI-owned metadata bundles (JSON/Markdown/manifest/checksums) under the configured data directory. They do not create plans and do not execute remediation, rollback, cleanup, Docker, or Compose mutation. `ops report validate` and `ops report export-validate` are read-only verification commands. `ops report compare` and `ops report compare-export` are also read-only: they validate both inputs, compare drift (suspects/remediation-lane/safety), surface safety-flag false→true drift warnings, and never create plans or execute remediation/rollback/cleanup/restart.

`ops report history` and `ops report compare-latest` are read-only report discovery/drift shortcuts: they scan ShellForgeAI-owned report artifacts, never save/export/delete by themselves, and never execute remediation/rollback/cleanup/restart.

- `shellforgeai v1 check` is read-only/non-mutating; full profile does not execute live remediation by default.
shellforgeai v1 packet is read-only by default; --save/export only write ShellForgeAI-owned artifacts and never mutate Docker/system state.
`scripts/v1_validate.sh --packet` keeps this in the validation lane: after validation passes it saves + validates a V1 packet (optional export validation), writes only ShellForgeAI-owned packet/export artifacts, and does not execute remediation/rollback/cleanup or Docker/Compose mutation.

`shellforgeai v1 packet history`, `shellforgeai v1 packet compare`, and `shellforgeai v1 packet compare-latest` are read-only artifact lifecycle commands: they read saved packet artifacts, compare in memory, and never regenerate checks, save packets, export bundles, or mutate packet files.

## Governed disposable restart boundary

The only V2 governed execution lane currently available is `docker.disposable_restart` through `shellforgeai recipes execute <preflight_ref> --confirm`. It must come from a valid saved ShellForgeAI preflight packet and may run only `docker restart <exact-target>` for a target that is still labeled `shellforgeai.disposable=true` and `shellforgeai.allow_restart=true`. Production targets, broad targets, unlabeled targets, Docker Compose mutation, cleanup execution, rollback execution, arbitrary shell, and natural-language mutation remain refused. Execution writes a receipt and verifies the restart with Docker inspect evidence; rollback posture is documented but no rollback is executed.

## Governed receipt recovery execution

`recipes receipt recovery-execute <receipt_ref> --confirm` is the only governed receipt recovery execution lane. It applies only to valid `docker.disposable_restart` receipts and is not true rollback: a Docker restart cannot restore the previous process state. The command reloads the exact target from the receipt, revalidates the receipt, refuses broad or production targets, rechecks current labels `shellforgeai.disposable=true` and `shellforgeai.allow_restart=true`, requires explicit CLI `--confirm`, and then performs exactly one argv-list restart (`["docker", "restart", "<target>"]`). It writes a recovery receipt and requires receipt-aware verification afterward.

Safety invariants: no natural-language recovery execution, no production restart, no Docker Compose mutation, no cleanup execution, no arbitrary remediation or rollback execution, no `shell=True`, no broad target restart, no arbitrary command execution, and no model-driven execution. Missing/malformed/unsupported receipts, no-confirm invocations, missing targets, label drift, broad targets, Docker failures, and verification failures return controlled output without traceback.
