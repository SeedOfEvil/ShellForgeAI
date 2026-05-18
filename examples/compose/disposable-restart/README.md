# PR67 disposable Compose restart harness

A throwaway Docker Compose stack used to exercise the ShellForgeAI
Compose service restart lane (PR61 → PR66) end-to-end without touching
production ShellForgeAI services.

## What this is

- Project name: `sfai_pr67_disposable`
- Service name: `web`
- Container name: `sfai-pr67-compose-web`
- Image: `nginx:alpine`
- Required ShellForgeAI safety labels:
  - `shellforgeai.disposable=true`
  - `shellforgeai.allow_restart=true`
  - `shellforgeai.test_harness=compose-restart`
  - `shellforgeai.scope=pr67`

The stack is intentionally minimal: no privileged mode, no host
networking, no host PID/IPC, no Docker socket mount, no bind mounts of
host paths, no secrets.

## What this is not

This harness is **not** a ShellForgeAI execution path. ShellForgeAI does
not bring this stack up or tear it down. The disposable stack is created
and destroyed by the operator (or the `scripts/pr67_disposable_compose_harness.sh`
lab helper) entirely outside the gated ShellForgeAI mutation lane.

ShellForgeAI's role against this stack is:

1. Read-only inspection (`compose inspect`, `compose list`).
2. Read-only readiness diagnostics (`compose env-check --target ...`).
3. Read-only proposal/preview/approval/rollback-preview/mission/checklist.
4. Gated execution via `mission compose-restart execute --execute --confirm`.

All existing PR62/PR63/PR64/PR65/PR66 gates still apply. Production
ShellForgeAI services remain blocked from execution because they are not
labeled disposable/allow_restart and must not be.

## Manual operator workflow (lab only)

See `OPS.md` ("PR67 disposable Compose harness lab workflow") for the
full step-by-step. The short form is:

```
./scripts/pr67_disposable_compose_harness.sh up
shellforgeai compose env-check --target sfai-pr67-compose-web
shellforgeai compose restart-preview sfai-pr67-compose-web
shellforgeai compose propose-restart sfai-pr67-compose-web --reason "PR67 disposable harness test"
shellforgeai approvals approve <proposal-id> --reason "PR67 disposable harness test"
shellforgeai rollback preview <proposal-id>
shellforgeai mission compose-restart prepare <proposal-id>
shellforgeai mission compose-restart checklist <mission-id>
shellforgeai mission compose-restart validate <mission-id>
shellforgeai mission compose-restart execute <mission-id> --execute --confirm
./scripts/pr67_disposable_compose_harness.sh down
```

Do not label production ShellForgeAI services disposable to make tests
pass.
