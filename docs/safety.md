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
  exits. It never executes plan steps in this alpha.
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
