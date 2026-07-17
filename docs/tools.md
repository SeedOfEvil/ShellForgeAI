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

`shellforgeai windows evidence --include-events [--events-limit N] [--events-since-hours N] [--json]` explicitly opts the existing evidence bundle into the same PR298 local `System` Event metadata component. Events are not included by default; the default evidence bundle remains doctor/status only. The embedded component reuses `windows_events_payload()` directly, defaults to limit 50 and lookback 24 hours, enforces limit 1-200 and lookback 1-168, and preserves the standalone schema, safety fields, privacy fields, canonical seven-digit FILETIME timestamps, and metadata-only Event ID/level/record fields. Evidence text renders only one bounded component summary line; JSON adds `components.events` plus an `embedded_events` count/truncation summary. Event-component failures are isolated as component failures and do not erase doctor, status, services, disks, or processes. The embedded path does not collect messages, XML, EventData, UserData, identities, computer fields, Security/Application/custom/remote channels, correlations, PowerShell, WinRM, subprocess/shell fallback, network/model calls, registry reads, Event Log writes/clears/exports/subscriptions, service/process control, cleanup, remediation, rollback, or recovery.

PR297 enriches `shellforgeai windows services [--json] [--limit N]` without adding a new command or collection path. The existing local read-only Service Control Manager enumeration (`OpenSCManagerW` enumerate rights, `EnumServicesStatusExW`, `CloseServiceHandle`) now preserves bounded runtime-state fields already present in `SERVICE_STATUS_PROCESS`: process ID, accepted-controls bitmask, Win32 and service-specific exit codes, checkpoint, wait hint, and service flags. JSON service items add `process_id`, `controls_accepted`, `controls_accepted_unknown_mask`, `win32_exit_code`, `service_specific_exit_code`, `checkpoint`, `wait_hint_ms`, `runs_in_system_process`, and ordered `runtime_signals`; `services.runtime_summary` counts these observations across the full enumerated set before item truncation. Text mode stays concise with one runtime summary line and at most ten deterministic pending/nonzero-exit-code preview rows. These are point-in-time observations only: accepted controls are reported, never executed; nonzero exit codes are not automatic failure diagnoses; a PID is reported without opening or inspecting the process; checkpoint and wait hint do not prove progress or a hang. The command still does not collect service binary paths, executable command lines, accounts, descriptions, dependencies, delayed-auto-start or trigger configuration, recovery/failure actions, security descriptors/ACLs, registry configuration, process owner/command line/environment/modules/handles, event logs, restart history, or remote service state, and it does not start, stop, restart, pause, continue, configure, or modify services. Unsupported platforms keep the structured unsupported response and do not substitute Linux collectors.

### Windows evidence opt-in network component

` shellforgeai windows evidence --include-network [--json]` adds a bounded network component to the Windows evidence bundle only when explicitly requested. The optional bounds are `--network-interface-limit INTEGER` (default 32, range 1-32) and `--network-address-limit INTEGER` (default 16, range 1-16); supplying either bound without `--include-network` fails clearly and does not silently enable or ignore the component.

JSON adds `components.network` with the standalone `windows_network` schema (`schema_version`, `mode`, `status`, `platform`, `read_only`, `mutation_performed`, `method`, `caps`, `summary`, `interfaces`, `limitations`, `warnings`, `errors`, and `safety`) plus an opt-in `embedded_network` summary containing only inclusion/status, caps, aggregate interface/address counts, error-interface count, and truncation. The embedded summary does not duplicate interface rows, addresses, counters, names, or IP addresses. Evidence text adds exactly one summary line when included and prints no interface names, addresses, netmasks, broadcasts, counters, warnings, diagnosis, or remediation advice.

The bundle reuses `windows_network_payload()` through an injectable builder boundary and does not introduce a second collector, dependency, or collection surface. It performs no packet capture, socket inventory, DNS lookup, route lookup, remote probing, PowerShell, WinRM, shell/subprocess fallback, MAC/GUID/PNP collection, or network mutation. If the network component raises, returns an error/unsupported payload on Windows, or returns malformed data, only `components.network` is normalized to a bounded `network_component_failed` envelope; doctor/status and other selected healthy components remain present and the bundle status becomes `component_failure`.


### Windows evidence opt-in volumes component

`shellforgeai windows evidence --include-volumes [--volumes-limit INTEGER] [--json]` adds bounded local drive-root volume/filesystem metadata to the Windows evidence bundle only when explicitly requested. `--volumes-limit` defaults to 32, accepts integers in the range 1-64, rejects booleans programmatically, and is valid only with `--include-volumes`; using the bound without the flag fails clearly before collection.

The bundle reuses the existing standalone `windows_volumes_payload()` collector through an injectable builder boundary and introduces no second collector, dependency, disk/partition/filesystem/storage-health surface, or standalone `windows volumes` option change. Default evidence remains doctor/status only, with no `components.volumes`, no `embedded_volumes`, unchanged default text, and the default next-safe command unchanged. When volumes are included, component order is deterministic and appends volumes after network: doctor, status, services, disks, processes, events, network, volumes. The next safe command becomes `shellforgeai windows volumes --json`.

Healthy JSON adds `components.volumes` with the standalone schema (`schema_version`, `mode`, `status`, `platform`, `read_only`, `mutation_performed`, `collection`, `summary`, `volumes`, `limitations`, `warnings`, `errors`, and `safety`). The `embedded_volumes` summary contains exactly aggregate fields: `included`, `status`, `limit`, `partitions_observed`, `local_drive_roots`, `returned_volumes`, `available_volumes`, `unavailable_volumes`, `fixed_volumes`, `removable_volumes`, `cdrom_volumes`, `read_only_volumes`, `skipped_remote`, `skipped_non_drive_root`, `skipped_unsafe_identifier`, and `truncated`. It does not duplicate drive letters, mount points, filesystem names, capacity values, warnings, errors, labels, serials, or identifiers. Evidence text adds one concise summary line only.

A healthy empty result with zero local roots and `volumes=[]` remains `status=ok`. If the builder raises, returns error/unsupported on a Windows evidence path, or returns malformed data, only the volumes component is normalized to a stable bounded failure envelope; doctor/status and other selected healthy components remain present and top-level status becomes `component_failure`. The component is local, read-only, and drive-root-only: no files, directories, network shares, GUID paths, labels, serials, BitLocker/encryption state, physical disks, SMART/storage health, remote probes, PowerShell, WinRM, QGA, subprocess/shell fallback, registry/model/auth-cache/secret access, mount/unmount/eject/format/repair, cleanup, remediation, rollback, recovery, network call, or mutation is performed. Unsupported non-Windows evidence output remains structured unsupported and does not substitute Linux storage collection.

### Windows evidence standard profile

`shellforgeai windows evidence --profile standard [--json]` selects one optional deterministic profile. No profile is selected by default: default evidence remains doctor/status only, default text is unchanged, and the default next safe command remains `shellforgeai windows status --json`. Manual composition with `--include-services`, `--include-disks`, `--include-processes`, `--include-events`, `--include-network`, and `--include-volumes` remains available and unchanged when `--profile` is omitted.

The only supported profile name is exactly `standard`. It selects existing bounded read-only components in this exact order: `doctor`, `status`, `services`, `processes`, `events`, `network`, `volumes`. It uses the established bounds: `services_limit=25`, `processes_limit=25`, `events_limit=50`, `events_since_hours=24`, `network_interface_limit=32`, `network_address_limit=16`, and `volumes_limit=32`. The profile deliberately excludes `disks` because the volumes component already provides bounded local drive-root capacity and filesystem classification. There is no separate memory component because physical memory is already included in the existing status component.

Profile mode is mutually exclusive with every manual component-selection or component-bound option. Combining `--profile standard` with any manual `--include-*` option or component limit option exits with a controlled usage error before collection. Unknown, empty, whitespace-altered, or case-altered profile names also fail as usage errors. Programmatic calls to `windows_evidence_payload(profile="standard", ...)` enforce the same validation and conflict behavior before platform detection or builder invocation.

On Windows, the JSON payload includes exactly this profile metadata block during successful collection and component-failure collection:

```json
"profile": {
  "name": "standard",
  "components": ["doctor", "status", "services", "processes", "events", "network", "volumes"],
  "bounds": {
    "services_limit": 25,
    "processes_limit": 25,
    "events_limit": 50,
    "events_since_hours": 24,
    "network_interface_limit": 32,
    "network_address_limit": 16,
    "volumes_limit": 32
  }
}
```

Text output adds exactly one aggregate profile line after `Components included:` and before `Component summary:`: `Evidence profile: standard; components=doctor,status,services,processes,events,network,volumes`. Bounds and detailed rows are not printed. The profile resolves into the existing evidence composition path, so removing only the top-level `profile` block from a standard-profile payload is structurally equivalent to the matching manual composition. The next safe command is the manual-equivalent final selected component command: `shellforgeai windows volumes --json`.

Component failures remain isolated at component level: healthy components remain present, the failed component remains in order, `summary.failed_components` is ordered by component order, top-level status becomes `component_failure`, and the profile block remains unchanged. Healthy empty selected components remain healthy. Unsupported non-Windows platforms return the existing structured unsupported Windows evidence payload with no `profile`, no components, no embedded component blocks, and no selected builder invocation. The profile adds no collector, execution, mutation, PowerShell, WinRM, QGA, subprocess/shell, registry, network, model, auth-cache, secret, diagnostic, or remediation path; it exposes only the profile name, fixed component names, and fixed numeric bounds.
