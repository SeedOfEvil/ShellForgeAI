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

Performance/health collection is platform-aware (PR279): on Windows the
Linux-only collectors above are skipped as structured
`linux_only_collector_skipped` evidence instead of executed, missing metrics
are marked `windows_metric_unavailable`, and the bundle reuses only the
existing stdlib-only `windows status`/`windows disks` read-only payloads.

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

Container failure investigation adds read-only Docker collectors:
`docker.containers` (inventory), `docker.inspect` (state, exit code,
restart count, health), `docker.container_logs` (bounded redacted tail,
no follow), and `docker.problem_summary` (failing/noisy classification
with log-theme signals: missing_required_setting, simulated_crash,
permission_denied, read_only_fs, dns_failure, upstream_unreachable, oom,
config_error, traceback). ShellForgeAI never invokes mutating Docker
commands (`start`, `stop`, `restart`, `rm`, `exec`, `cp`, `build`,
`pull`, `prune`, compose mutation). When the Docker CLI/daemon is
unreachable the missing visibility surfaces as a limitation finding
instead of false-healthy output.

### Windows volumes

`shellforgeai windows volumes [--json] [--limit N]` is a bounded read-only local Windows drive-root volume/filesystem collector. It uses the existing `psutil>=5.9` runtime dependency to inspect only local drive-root partition metadata and capacity; it skips UNC, remote/mapped-network, volume-GUID, and folder-mounted paths, and it emits aggregate skipped counts rather than raw unsafe identifiers. The command reports safe drive letters/mountpoints, filesystem, conservative kind/access classification, capacity when available, limitations, and safety flags. It does not inspect files, directories, labels, serials, BitLocker, physical disks, SMART/health, remote shares, or perform mount/format/repair/resize/cleanup/recovery actions. On unsupported hosts it returns structured unsupported output and does not substitute Linux collectors. `windows disks` remains the separate stdlib-only root/capacity command.

`shellforgeai windows events [--json] [--limit N] [--since-hours N]` provides a bounded local Windows System Event Log metadata slice. It queries only the local `System` channel for Critical, Error, and Warning records in a bounded UTC lookback (default 24 hours, valid 1-168) and returns at most the bounded limit (default 50, valid 1-200); invalid bounds fail clearly. JSON contains provider, nonnegative Event ID, normalized level, UTC `time_created_utc`, record ID, optional numeric task/opcode/keywords, truncation state, counts, and at most ten deterministic provider/Event-ID aggregation rows. Text mode shows at most ten recent rows and ten aggregation rows. Empty results are `status=ok`. The command is read-only and local-only: it does not retrieve rendered messages, XML, EventData, UserData, identities, computer names, process/thread context, arbitrary parameters, Security/Application/custom/remote channels, subscriptions, exports, clears, retention changes, generated events, model assistance, PowerShell, WinRM, shell, subprocess fallback, or host mutation. Non-Windows hosts return structured unsupported output and do not substitute Linux logs. Native handles are closed on success, empty results, truncation, and errors. The native decoder reads `EVT_VARIANT` through exact tagged-union members for the selected property contract (Provider=String, EventID=UInt16, Level=Byte, TimeCreated=FileTime, EventRecordID=UInt64, optional Task=UInt16, Opcode=Byte, Keywords=UInt64/HexInt64), so dirty upper union bytes cannot corrupt low-width fields. Invalid required metadata is omitted with bounded warnings/errors rather than fabricated zero values, successful fixed-query output cannot emit `unknown` severity, and live Windows acceptance requires metadata-only record-level parity against an independent reference. Messages, XML, EventData, and UserData remain uncollected. Native Windows FILETIME timestamps are preserved at 100-nanosecond precision and emitted as canonical UTC `YYYY-MM-DDTHH:MM:SS.fffffffZ`; ordering and provider/Event-ID `most_recent_utc` aggregation use the same seven-digit fractional precision, and exact live record-level timestamp parity is required.

PR297 enriches `shellforgeai windows services [--json] [--limit N]` without adding a new command or collection path. The existing local read-only Service Control Manager enumeration (`OpenSCManagerW` enumerate rights, `EnumServicesStatusExW`, `CloseServiceHandle`) now preserves bounded runtime-state fields already present in `SERVICE_STATUS_PROCESS`: process ID, accepted-controls bitmask, Win32 and service-specific exit codes, checkpoint, wait hint, and service flags. JSON service items add `process_id`, `controls_accepted`, `controls_accepted_unknown_mask`, `win32_exit_code`, `service_specific_exit_code`, `checkpoint`, `wait_hint_ms`, `runs_in_system_process`, and ordered `runtime_signals`; `services.runtime_summary` counts these observations across the full enumerated set before item truncation. Text mode stays concise with one runtime summary line and at most ten deterministic pending/nonzero-exit-code preview rows. These are point-in-time observations only: accepted controls are reported, never executed; nonzero exit codes are not automatic failure diagnoses; a PID is reported without opening or inspecting the process; checkpoint and wait hint do not prove progress or a hang. The command still does not collect service binary paths, executable command lines, accounts, descriptions, dependencies, delayed-auto-start or trigger configuration, recovery/failure actions, security descriptors/ACLs, registry configuration, process owner/command line/environment/modules/handles, event logs, restart history, or remote service state, and it does not start, stop, restart, pause, continue, configure, or modify services. Unsupported platforms keep the structured unsupported response and do not substitute Linux collectors.
