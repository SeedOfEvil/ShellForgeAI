# Safety

ShellForgeAI is built to be safe by construction. The runtime does not run
arbitrary shell, does not mutate the host without policy approval, and
treats model output as advisory.

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
- Deletion still requires explicit `--execute`.
