# Mission workflow

A *mission* binds evidence → proposal → approval → rollback preview →
readiness → gated execute → verification → receipt → report → export into
one operator-friendly record. Two mission types exist; they share a shape
but differ in the underlying mutation lane.

| Mission type              | Mutation lane                                | Real mutation that may happen                              |
| ------------------------- | -------------------------------------------- | ---------------------------------------------------------- |
| `restart` (PR52–PR54)     | `apply` gate (PR47/PR48/PR49)                | exactly one `docker restart <allowlisted-container>`       |
| `compose-restart` (PR63–) | gated Compose lane, disposable-only          | exactly one `docker compose ... restart <service>` against a disposable + allow_restart labelled service when the env-contract is fully satisfied |

Mission commands themselves are metadata-only. They never approve, never
roll back, never restart, never execute. The only execution path is the
explicit `--execute --confirm` step at the end of each lane.

## Exact-container restart mission

### Prepare

```
shellforgeai approvals propose-restart <container> --latest
shellforgeai approvals approve <proposal-id> --reason "<why>"
shellforgeai rollback preview <proposal-id>
shellforgeai mission restart prepare --container <container>
```

`mission restart prepare` finds or reuses a pending proposal, writes a
mission record under `<data_dir>/missions/restart/<mission-id>/`, and
renders an operator checklist. `--with-rollback-preview` will also write
the metadata-only rollback preview.

### Inspect

```
shellforgeai mission restart status <mission-id>
shellforgeai mission restart checklist <mission-id>
shellforgeai mission restart validate <mission-id>
```

`status` and `checklist` refresh phases from artifacts (proposal,
rollback preview, apply readiness, guard freshness). `validate` enforces
schema and safety invariants (exact `docker restart <target>` preview,
no shell chains in `next_commands`).

### Execute (handoff to `apply`)

```
shellforgeai mission restart execute <mission-id>                         # dry-run
shellforgeai mission restart execute <mission-id> --execute --confirm     # gated mutation
```

`execute` without flags is dry-run. `--execute` without `--confirm` is
refused. With both flags, mission readiness is checked again and the
command delegates to the same `apply --execute --confirm` path. The actual
mutation is still the exact-container `docker restart <target>` allowed
under PR47/PR48/PR49. The apply receipt path is recorded into the mission.

Required env for execution:

```
SHELLFORGEAI_MUTATION_MODE=lab
SHELLFORGEAI_ALLOW_LAB_CONTAINER_RESTART=1
```

Plus an allowlist enabled at
`<data_dir>/policy/lab-container-restart-allowlist.json`.

### Report / export

```
shellforgeai mission restart report <mission-id>
shellforgeai mission restart export <mission-id> [--redact]
shellforgeai mission restart validate-export <export-dir>
```

The report writes `mission-report.json` / `mission-report.md` under
`<data_dir>/mission_reports/<mission-id>/`. The export pack bundles the
mission record, report, proposal, rollback preview, apply receipt,
before/after inspect evidence, source evidence, and relevant audit events
into `<data_dir>/mission_exports/<mission-id>/` with a manifest and
`checksums.sha256`. Validate-export re-verifies checksums and safety
invariants (`execution_status="not_executed_by_export"`, no mutation
performed by export).

## Compose service restart mission

### Preview / propose / approve

```
shellforgeai compose inspect <container>
shellforgeai compose restart-preview <target>
shellforgeai compose propose-restart <target> --reason "<why>"
shellforgeai approvals approve <proposal-id> --reason "<why>"
shellforgeai rollback preview <proposal-id>
shellforgeai rollback validate <preview-id-or-path>
```

The Compose preview/proposal/rollback are metadata only. Rollback for
`compose_service_restart` is a **recovery preview**:
`automatic_rollback=false`, `rollback_command_generated=false`. The
expected restart argv shape is `docker compose ... restart <service>`;
`up`, `down`, and `recreate` patterns are refused.

### Readiness

```
shellforgeai compose env-check --target <target>
shellforgeai compose env-contract --target <target>
shellforgeai mission compose-restart prepare --target <target>
shellforgeai mission compose-restart status <mission-id>
shellforgeai mission compose-restart checklist <mission-id>
shellforgeai mission compose-restart validate <mission-id>
```

Readiness blocks if any of the following are true (see
[`docs/compose-ops.md`](compose-ops.md) for the full list):

- `target_not_allowlisted` (no `shellforgeai.disposable=true` /
  `allow_restart=true` labels)
- `compose_file_snapshot_unavailable` (no readable file / no
  `compose_file_sha256`)
- `docker_compose_cli_unavailable`
- `required_invocation_unsupported`
- rollback recovery preview missing or invalid
- proposal fingerprint invalid
- missing `--confirm`

When readiness is blocked, `execute` refuses with
`execution.blocked=true`, `safety.docker_compose_executed=false`, and
`safety.container_restarted=false`.

### Execute

```
shellforgeai mission compose-restart execute <mission-id>                       # dry-run
shellforgeai mission compose-restart execute <mission-id> --execute --confirm  # gated mutation
```

Even with the right flags, execution only proceeds when every gate is
green. In a capable environment, the receipt records verification evidence
(`target_exists_after`, `started_at_changed`, compose label stability,
sibling-service touch checks) so operators can confirm only the intended
service / container changed.

### Report / export

`mission compose-restart report` and `mission compose-restart export`
mirror the exact-container lane.

## Blocked states are not failures

A blocked readiness state is the correct outcome when the environment is
not prepared. Treat blockers as guidance, not regressions:

- `target_not_allowlisted` — production target, refuse and use a
  disposable target instead.
- `compose_file_snapshot_unavailable` / `docker_compose_cli_unavailable`
  — environment is not yet prepared for live Compose execution. See
  [`docs/compose-ops.md`](compose-ops.md).
- guard `stale` / `drift_detected` — regenerate proposal/runbook from
  fresh evidence before re-approving.

ShellForgeAI never retries mutation on its own. The operator decides
whether to fix the blocker or stand down.
