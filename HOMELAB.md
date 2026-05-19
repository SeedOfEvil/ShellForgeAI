# Homelab / Docker01 state

This file captures the *current* deployed reality of the homelab Docker01
environment as of the PR71 baseline. It is operator notes, not a contract.

## Role

- **Docker01 / lab-docker01** runs the long-lived `shellforgeai` Compose
  service used for live QA, plus disposable test stacks when needed.
- The production `shellforgeai` container is Compose-managed but **not**
  on the lab restart allowlist and **must not** be added to it.

## Latest baseline

- PR71 — metadata cleanup archive/fingerprint/execute hardening — is the
  current stable head for documentation / handoff purposes.
- Earlier PRs (PR56–PR70) continue to apply and are not regressed by
  PR71 or by this docs refresh.

## Current caveats

### Metadata hygiene

`/data` on Docker01 has accumulated historical artifacts from many
prior PR exercises (evidence sessions, proposals, missions, exports,
guard reports, prune receipts). Expect:

- `shellforgeai doctor` metadata hygiene to report non-`ok` severity.
- `shellforgeai audit retention` to show several large categories.

This is expected. Use the PR55/PR71 cleanup lane to reduce it, never
manual deletion:

```
shellforgeai audit retention
shellforgeai audit cleanup plan --category exports --max-age-days 7 --keep-latest 5
shellforgeai audit cleanup archive <plan-id>
shellforgeai audit cleanup validate <cleanup-archive.tar.gz>
shellforgeai audit cleanup execute <plan-id> --confirm
shellforgeai doctor
```

### Compose execution environment

`shellforgeai compose env-contract --target shellforgeai` typically
reports blockers on Docker01:

- `target_not_allowlisted` (correct — production must not be allowlisted)
- `docker_compose_cli_unavailable` (no Compose CLI/plugin inside the
  ShellForgeAI runtime)
- `compose_file_snapshot_unavailable` (host compose file paths are not
  readable from inside the container)

These blockers are the contract being enforced, not bugs. The
disposable PR67 target (`sfai-pr67-compose-web`) is the lane for proving
the gated Compose service restart end-to-end.

PR73 adds `shellforgeai compose env-plan --target <target>` (read-only)
that maps each current blocker to an explicit operator-controlled
remediation step. It does not change Docker, Compose, files, packages,
firewall, services, or labels on its own. The blockers above remain
until an operator deliberately changes the ShellForgeAI runtime
environment outside the app, then re-runs env-check / env-contract.

### Exact-container restart

The PR47 lab container restart lane is disabled by default on Docker01.
To enable for a specific disposable lab container, an operator must:

1. Populate `<data_dir>/policy/lab-container-restart-allowlist.json`
   with `enabled=true` and the disposable container name.
2. Export `SHELLFORGEAI_MUTATION_MODE=lab` and
   `SHELLFORGEAI_ALLOW_LAB_CONTAINER_RESTART=1`.
3. Run the full proposal → approve → rollback-preview → mission →
   `apply --execute --confirm` sequence.

The production `shellforgeai` container is never a valid target.

## Validated safety behavior (Docker01)

Confirmed working on Docker01 against disposable / fixture targets:

- Read-only `ops status`, `doctor`, `audit retention`, `audit timeline`.
- Diagnose/runbook/proposal/approval/rollback-preview flows are
  metadata-only and idempotent.
- Exact-container restart lane refuses every wrong-gate state and
  executes only the exact `docker restart <allowlisted-name>` when
  every gate is green.
- Compose readiness gates block safely (correctly) on the production
  service; disposable harness can be brought to readiness=true.
- PR71 cleanup archive/fingerprint gate works in a disposable data dir
  and refuses on mismatched/missing archive, mismatched fingerprint,
  and missing `--confirm`.

## Live QA checklist

Before any change-touching exercise on Docker01:

1. Take a Proxmox snapshot of the VM.
2. Verify the deployed image / commit / labels:
   ```
   shellforgeai version
   docker inspect shellforgeai --format '{{.Image}} {{.Config.Labels}}'
   ```
3. Run smoke checks in a disposable validation container:
   ```
   ruff format --check .
   ruff check .
   python -m compileall src tests
   pytest -q
   ```
4. Stay on read-only / preview / proposal / mission-prepare commands
   unless explicitly running an approved gated mutation against a
   disposable target.
5. Tear down disposable stacks afterwards
   (`scripts/pr67_disposable_compose_harness.sh down`).

## What this file does not contain

- No secrets, tokens, API keys, or credentials.
- No private compose file contents.
- No internal-only paths beyond those already documented in `OPS.md`.

The actual live Compose restart proof against the disposable target
still requires deliberately satisfying the env-contract (Compose CLI
inside the runtime, readable compose file). The current Docker01
long-lived harness does not satisfy that contract by default, and this
is the correct posture for production.
