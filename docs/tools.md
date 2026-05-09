# Tools

ShellForgeAI tools are typed Python wrappers in `src/shellforgeai/tools/`.
Each tool runs a specific command with bounded arguments and returns a
structured result. The runtime — not the model — decides which tools run.

List tools at runtime:

```bash
shellforgeai tools list
shellforgeai tools describe <name>
```

## Tool modules

| Module | Purpose |
| --- | --- |
| `host` | Host info, resources, uptime. |
| `journal` | `journalctl --no-pager` for units, with `--since`. |
| `systemd` | Unit `status`, `is-active`, `is-enabled`. |
| `disk` | Block devices, free space, mounts. |
| `storage` | Storage context, pressure, error summary. |
| `network` | Interfaces, routes, listening sockets, DNS. |
| `firewall` | Read-only firewall view. |
| `packages` | Installed packages and versions. |
| `services` | Service investigation collectors (manager/status/processes/ports/logs/config hints). |
| `process` | Process snapshot. |
| `containers` | Container introspection (read-only). |
| `logs` | Log fan-out around an intent. |
| `system` | Pressure (`/proc/pressure/*`), kernel/version. |
| `files` | Bounded file reads (no writes from tools). |
| `executor` | Internal: dispatch + risk gating. |
| `registry` | Tool catalog and metadata. |
| `schemas` | Pydantic result models. |
| `shell` | Internal helper used by typed tools — never exposes raw shell. |

## Investigation collectors

For ops intents the runtime composes collectors that call several tools:

- `system.pressure` — CPU/IO/memory pressure stalls.
- `process.snapshot` — top processes by CPU/RSS.
- `storage.context` / `storage.pressure` / `storage.error_summary` —
  capacity, throughput, dmesg/journal hints.
- Disk, performance, health, firewall, service, and service-discovery
  bundles are wired into `diagnose <target>` and the interactive natural-
  language router.

`diagnose` aliases include `performance|slow|slowness|host`,
`storage|disk-performance|io|iowait`, `services|service-discovery|ports`.

## Adaptive follow-ups

Natural-language diagnostics may queue an evidence-driven deeper read-only
follow-up (CPU/process, memory/swap, storage/IO, network/DNS, service
health, or a general context pass). Confirm with `yes`, `proceed`, `dig
deeper`, `y`, or `run it`. Inspect the queue with `/pending`. Follow-ups
remain read-only.

- `process.io` — Process I/O snapshot.
- `system.cgroup_limits` — Container cgroup limits.
- `disk.top_dirs` — Bounded top-level disk usage.
- `storage.mounts` — Mount and filesystem context.
- `audit.recent` — Recent ShellForgeAI session trends.


Service investigation adds read-only collectors: `service.manager_detect`, `service.status`, `service.unit_file`, `service.processes`, `service.ports`, `service.config_hints`, and `service.logs`.

Log/error investigation adds read-only collectors: `logs.common_paths`,
`logs.recent_errors`, `logs.service_errors`, `logs.auth_errors`,
`logs.kernel_errors`, `logs.error_themes`, and `logs.safe_tail`. All log
collectors do bounded reads, redact secrets/tokens/passwords/keys, and
never tail `-f`, delete, truncate, or rotate logs. `diagnose logs`,
`diagnose errors`, `diagnose auth`, and `diagnose logs:<service>` route
into these bundles.
