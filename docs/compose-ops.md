# Compose ops

ShellForgeAI's Compose support is layered: read-only awareness on every
deployment, preview/proposal on top of that, and a tightly gated execution
lane that is **disposable-only** by design.

## Capabilities

| Command                                              | Mode             | Notes                                                                 |
| ---------------------------------------------------- | ---------------- | --------------------------------------------------------------------- |
| `compose list`                                       | read-only        | Compose-managed containers from Docker labels.                        |
| `compose inspect <container>`                        | read-only        | Project / service / config files / labels for a container.            |
| `ask "compose context for X"` / similar              | read-only        | Routed to the same inspect/list path.                                 |
| `compose restart-preview <target>`                   | preview-only     | `compose_mutation=true`, `preview_only=true`, `executed=false`.       |
| `compose propose-restart <target>`                   | proposal-only    | Creates a pending `compose_service_restart` proposal artifact.        |
| `rollback preview <proposal-id>` (compose proposals) | preview-only    | Recovery preview, hash-only config evidence, no auto-rollback.        |
| `compose env-check [--target T]`                     | read-only        | Diagnostics: Compose CLI/plugin, snapshot, allowlist posture.         |
| `compose env-contract [--target T]`                  | read-only        | Full execution-environment contract / readiness in one view.          |
| `compose env-plan [--target T]`                      | read-only        | Maps current readiness blockers to operator-controlled remediation.   |
| `mission compose-restart …`                          | metadata, gated  | Prepare/status/checklist/validate/execute/report/export.              |
| `scripts/pr67_disposable_compose_harness.sh`         | external helper  | Bring up/down the disposable test stack. Not invoked by the app.      |
| `scripts/pr68_disposable_compose_restart_proof.sh`   | external helper  | Optional readiness/proof orchestrator. Not invoked by the app.        |

ShellForgeAI itself never runs `docker compose up`, `docker compose
down`, or `docker compose recreate`. The only Compose mutation it may
ever invoke is `docker compose ... restart <service>` against a
disposable + allow_restart labelled target, and only when every gate
below passes.

## Compose context fields

`compose inspect <container> --json` (and proposal/mission/receipt
enrichment) surface:

- `project` — Compose project name (label `com.docker.compose.project`).
- `service` — service name (`com.docker.compose.service`).
- `container` — Docker container name.
- `container_number` — Compose replica index when present.
- `working_dir` — `com.docker.compose.project.working_dir`.
- `compose_file` / `config_files` — Compose file paths recorded by Compose.
- `labels` — Compose-related labels passed through verbatim.
- `oneoff` — `True` if Compose marked the container one-off.
- `version` — Compose version recorded by labels, when available.

For non-Compose targets the context is `{"detected": false, "reason":
"compose labels not present"}`.

## Restart states

A Compose service restart passes through explicit states. Each is a
strict superset of the previous in terms of gates passed; none of them
implies execution.

1. **Preview-only.** `compose restart-preview` shows the future argv. No
   proposal, no mission. `executed=false`.
2. **Proposal-only.** `compose propose-restart` creates a pending
   `compose_service_restart` proposal. `proposal_only=true`,
   `execution_allowed=false`.
3. **Mission prepared.** `mission compose-restart prepare` ties proposal,
   rollback recovery preview, and readiness together. Still no execution.
4. **Blocked by readiness.** Mission `status` / `validate` / `execute`
   report explicit blockers; `execute` refuses non-mutatively.
5. **Executable.** Every gate green and `--execute --confirm` provided.
   This is the only path through which ShellForgeAI may invoke
   `docker compose ... restart <service>`.

## Readiness blockers

Common blockers reported by `compose env-check` / `env-contract` /
mission `status|validate|execute`:

- `target_not_allowlisted` — target does not carry
  `shellforgeai.disposable=true` and/or `shellforgeai.allow_restart=true`.
- `compose_file_snapshot_unavailable` — compose file not readable from
  inside the ShellForgeAI runtime, so no `compose_file_sha256` can be
  computed.
- `docker_compose_cli_unavailable` — `docker compose` CLI / plugin is
  not present in the runtime.
- `required_invocation_unsupported` — the exact `docker compose …
  restart <service>` invocation form is not supported in the detected
  Compose version.
- rollback preview missing / invalid (recovery preview required for
  compose lane).
- proposal fingerprint invalid / proposal not approved.
- missing `--confirm`.

When any blocker is present, `execute` refuses with:
- `execution.executed=false`
- `execution.blocked=true`
- `execution.restart_returncode=null`
- `safety.docker_compose_executed=false`
- `safety.container_restarted=false`

## Environment enablement plan (PR73)

`shellforgeai compose env-plan --target <target>` is a read-only enablement
plan. It does **not** perform any of the remediation it suggests. It only
maps the readiness blockers reported by `env-check` / `env-contract` to
explicit operator-controlled remediation steps.

- ShellForgeAI does not install Compose, mount host paths, edit compose
  files, label production services disposable, restart services, or run
  `docker compose` of any kind from this command.
- For each blocker, the plan entry includes `meaning`,
  `operator_remediation`, `shellforgeai_action="none"`, `automated=false`,
  and explicit `allowed_for_disposable_lab` / `allowed_for_production`
  flags.
- If the target looks production-like (e.g. `shellforgeai`,
  anything containing `production` / `prod`) and is **not** already
  allowlisted, the plan output adds a warning and recommends using the
  PR67 disposable harness instead. It will never suggest labeling a
  production service `shellforgeai.disposable=true`.
- The PR68 optional disposable Compose restart proof remains blocked until
  every env-contract / env-plan blocker is resolved by deliberate operator
  action **outside** ShellForgeAI, and an explicit operator approval is
  granted.

Blocker-to-remediation mapping (abbreviated):

- `compose_file_snapshot_unavailable` → expose the disposable Compose file
  read-only into the ShellForgeAI runtime at the same path Compose
  recorded. ShellForgeAI action: none.
- `docker_compose_cli_unavailable` → provide a compatible Docker CLI +
  Compose plugin inside the ShellForgeAI container/harness. ShellForgeAI
  action: none.
- `required_invocation_unsupported` → fix Compose plugin/CLI compatibility
  so the `docker compose -f <file> --project-directory <dir> restart
  <service>` argv form is supported. ShellForgeAI action: none.
- `target_not_allowlisted` → use the PR67 disposable harness for lab
  proof. Do not label production services disposable. ShellForgeAI
  action: none.
- `rollback_preview_missing` / `rollback_preview_invalid` → run
  `shellforgeai rollback preview <proposal-id>` and
  `shellforgeai rollback validate <rollback-preview>`. ShellForgeAI
  action: none from env-plan (which never mutates).
- `proposal_not_approved` / `fingerprint_invalid` / `missing_confirm` →
  operator approval / explicit `--execute --confirm` on the mission only
  after every other gate is green. ShellForgeAI action: none from
  env-plan.

Unknown blocker names are preserved verbatim with a generic explanation;
no automatic remediation is offered. See `docs/cli.md` for the JSON
schema.

## Docker01 current caveat

On the current Docker01 / homelab deployment:

- The real `shellforgeai` service is Compose-managed but **not**
  allowlisted (and must not be) — `target_not_allowlisted` is the
  correct blocker.
- The long-lived `shellforgeai` container in production typically lacks
  the inside-container Compose CLI / plugin and cannot read host compose
  paths, producing `docker_compose_cli_unavailable` and
  `compose_file_snapshot_unavailable`.
- The disposable PR67 target (`sfai-pr67-compose-web`) can be
  allowlisted and proven through the gated lane when its environment is
  prepared.

These are not regressions. They are the contract being enforced.

## Disposable harness

`examples/compose/disposable-restart/docker-compose.yml` (mirrored under
`tests/fixtures/`) defines a throwaway stack:

- project: `sfai_pr67_disposable`
- service: `web`
- container: `sfai-pr67-compose-web`
- labels: `shellforgeai.disposable=true`,
  `shellforgeai.allow_restart=true`,
  `shellforgeai.test_harness=compose-restart`,
  `shellforgeai.scope=pr67`

`scripts/pr67_disposable_compose_harness.sh up|down|status|print-env|
print-commands` brings the stack up/down. The script refuses to operate
on anything other than the disposable target.

`scripts/pr68_disposable_compose_restart_proof.sh` is an *optional*
orchestrator that prints the gated command sequence and verifies
readiness. Default mode is dry-run / read-only. Even with the explicit
`--execute-approved-disposable-restart` flag, it does **not** drive
execution: it only verifies `compose env-check
compose_restart_execution_ready=true` and prints the manual command
sequence. The operator runs the final mission execute themselves.

Warnings:

- **Do not** label production services `shellforgeai.disposable=true` or
  `shellforgeai.allow_restart=true` to make tests pass.
- **Do not** bypass ShellForgeAI gates by running `docker compose`
  manually on the host and reporting the result as if ShellForgeAI
  performed it.

The disposable labels are reserved for throwaway test stacks.
