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

