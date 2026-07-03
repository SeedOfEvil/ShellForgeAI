# Windows smoke harness runbook

## Purpose

This runbook defines repeatable acceptance for Windows-lane pull requests. It
validates real on-VM ShellForgeAI CLI execution while preserving the product
posture: ShellForgeAI remains read-only by default, and Windows smoke evidence
must prove that product commands did not execute PowerShell, use WinRM, perform
remote execution, or mutate the host.

The runbook is for operator QA. It does not expand Windows product evidence
collection and does not authorize ShellForgeAI to stage source, contact the VM,
use QEMU Guest Agent, or run host-management tools.

## Current Windows smoke baseline

- VM: `WIN2025-SFAI01`
- Proxmox VMID: `101`
- Durable runtime root: `C:\Tools\ShellForgeAI`
- Embedded CPython: `C:\Tools\ShellForgeAI\Python314`
- Wrappers: `C:\Tools\ShellForgeAI\bin\shellforgeai.cmd` and
  `C:\Tools\ShellForgeAI\bin\sfai.cmd`
- Source root pattern: `C:\Tools\ShellForgeAI\src\ShellForgeAI-pr<PR_NUMBER>`
- Do not rely on the broken system Python at `C:\Program Files\Python312`.
- QGA PATH caveat: the QEMU Guest Agent service may not immediately observe
  Machine PATH updates until service restart or reboot. Prefer explicit wrapper
  paths in smoke commands. This is a harness nuance, not a product blocker.

## Operator acceptance pattern

1. Take a VM snapshot before staging a PR source tree.
2. Stage the exact PR source under
   `C:\Tools\ShellForgeAI\src\ShellForgeAI-pr<PR_NUMBER>`.
3. Verify the staged archive SHA256 before running smoke commands.
4. Run from a sane source/runtime current working directory under the durable
   root.
5. Enforce native process exit codes; do not treat captured text as success
   when the process failed.
6. Capture the normal Windows smoke artifact set:
   - `windows-evidence.json` from `shellforgeai windows evidence --json`
   - `windows-evidence-services.json` from
     `shellforgeai windows evidence --json --include-services --services-limit 25`
     (PR269 opt-in bounded services component; the default bundle stays
     doctor/status-only)
   - `windows-status.json` from `shellforgeai windows status --json`
   - `windows-doctor.json` from `shellforgeai windows doctor --json`
   - `windows-services.json` from `shellforgeai windows services --json --limit 25`
     (PR267 standalone read-only services preview; validated by the saved-JSON
     acceptance validator and reported by the packet helper since PR268 via
     `--services-json`)
   - `windows-evidence-with-disks.json` from
     `shellforgeai windows evidence --json --include-disks`
     (PR272 opt-in bounded disks component; the default bundle stays
     doctor/status-only, disks are included only with `--include-disks`, and
     `--disks-limit` is bounded to 1-64 and valid only with `--include-disks`)
   - `windows-disks.json` from `shellforgeai windows disks --json`
     (PR270 standalone local read-only disk/root usage preview; validated by
     the saved-JSON acceptance validator and reported by the packet helper
     since PR271 via `--disks-json`, and since PR272 also available inside the
     evidence bundle as an opt-in bounded component)
   - `windows-processes.json` from `shellforgeai windows processes --json`
     (PR274 standalone local read-only bounded process preview; validated by
     the saved-JSON acceptance validator and reported by the packet helper
     since PR275 via `--processes-json`, and since PR276 also available inside
     the evidence bundle as an opt-in bounded component)
   - `windows-evidence-with-processes.json` from
     `shellforgeai windows evidence --json --include-processes`
     (PR276 opt-in bounded processes component; the default bundle stays
     doctor/status-only, processes are included only with
     `--include-processes`, and `--processes-limit` is bounded to 1-200 with a
     conservative embedded default of 25 and valid only with
     `--include-processes`; the embedded component reuses the PR274 read-only
     payload and never collects command lines, environments, memory, handles,
     modules, owners/users/tokens, or network connections)
   - optional text outputs for human-facing smoke evidence.

   The normal Windows smoke artifact set may now include
   `windows-evidence.json`, `windows-evidence-with-disks.json`,
   `windows-evidence-with-processes.json`, `windows-status.json`,
   `windows-doctor.json`, `windows-services.json`, `windows-disks.json`, and
   `windows-processes.json`.

   Windows smoke commands for the current lane:

   ```text
   shellforgeai windows evidence --json
   shellforgeai windows evidence --json --include-services --services-limit 25
   shellforgeai windows evidence --json --include-disks
   shellforgeai windows evidence --json --include-disks --disks-limit 5
   shellforgeai windows evidence --json --include-processes
   shellforgeai windows evidence --json --include-processes --processes-limit 10
   shellforgeai windows evidence --include-processes
   shellforgeai windows processes --json
   shellforgeai windows processes --json --limit 10
   shellforgeai windows processes
   shellforgeai windows services --json --limit 25
   shellforgeai windows disks --json
   ```
7. PR265 extends the saved-JSON acceptance validator to support `shellforgeai windows evidence --json` artifacts. PR268 adds saved-artifact validation and packet support for `windows-services.json`. PR269 validates evidence bundles that embed the opt-in services component with the same key safety expectations as the standalone services artifact; a standalone `--services-json` artifact is not required when the bundle embeds services. PR271 extends the saved-artifact validator and packet helper support to `windows-disks.json`; the disks artifact validator accepts unavailable roots only when they are sanitized as safe disk usage failures (for example `disk_usage_failed`), never tracebacks or raw exception detail. PR272 validates evidence bundles that embed the opt-in disks component with the same key safety expectations as the standalone disks artifact; a standalone `--disks-json` artifact is not required when the bundle embeds disks, and standalone `windows-disks.json` support from PR271 remains valid. PR275 adds saved-artifact validator and packet support for `windows-processes.json` via `--processes-json`: it validates saved PR274 process artifacts only, runs no ShellForgeAI product commands, collects no new process data, does not add processes to the evidence bundle, and validates that process artifacts carry only PID, parent PID, image basename/name, and thread count — never command lines, environments, memory, handles, modules, owners/users, or network connections. PR276 validates evidence bundles that embed the opt-in processes component with the same key safety expectations as the standalone processes artifact (including the per-item field allowlist); a standalone `--processes-json` artifact is not required when the bundle embeds processes, and standalone `windows-processes.json` support from PR275 remains valid.
8. Use `scripts/windows_smoke_packet.py` when a PR needs a deterministic QA handoff packet from saved evidence/status/doctor JSON, optionally including services JSON.
9. Archive the raw JSON artifacts exactly as captured. Deterministic capture
   methods are preferred, but operators do not need to rewrite files that include
   a UTF-8 BOM or Windows PowerShell 5.1 default UTF-16LE BOM. The local
   validator accepts UTF-8, UTF-8 with BOM, and UTF-16 with BOM JSON artifacts.
10. Validate the saved JSON artifacts locally with:

   ```bash
   python scripts/windows_smoke_acceptance.py \
     --evidence-json windows-evidence.json \
     --status-json windows-status.json \
     --doctor-json windows-doctor.json \
     --services-json windows-services.json \
     --disks-json windows-disks.json \
     --expected-host WIN2025-SFAI01 \
     --expected-python 3.14.6 \
     --json
   ```

   Validate the include-services evidence bundle (embedded services) with:

   ```bash
   python scripts/windows_smoke_acceptance.py \
     --evidence-json windows-evidence-services.json \
     --expected-host WIN2025-SFAI01 \
     --expected-python 3.14.6 \
     --json
   ```

   Validate the include-disks evidence bundle (embedded disks, PR272) plus the
   standalone disks artifact with:

   ```bash
   python scripts/windows_smoke_acceptance.py --evidence-json windows-evidence-with-disks.json --status-json windows-status.json --doctor-json windows-doctor.json --disks-json windows-disks.json --expected-host WIN2025-SFAI01 --expected-python 3.14.6 --json
   ```

   Validate the standalone processes artifact (PR274/PR275) alongside the
   existing artifacts with:

   ```bash
   shellforgeai windows processes --json > windows-processes.json

   python scripts/windows_smoke_acceptance.py \
     --evidence-json windows-evidence.json \
     --status-json windows-status.json \
     --doctor-json windows-doctor.json \
     --processes-json windows-processes.json \
     --expected-host WIN2025-SFAI01 \
     --expected-python 3.14.6 \
     --json
   ```

   Validate the include-processes evidence bundle (embedded processes, PR276)
   plus the standalone processes artifact with:

   ```bash
   shellforgeai windows evidence --json --include-processes > windows-evidence-with-processes.json

   python scripts/windows_smoke_acceptance.py \
     --evidence-json windows-evidence-with-processes.json \
     --status-json windows-status.json \
     --doctor-json windows-doctor.json \
     --processes-json windows-processes.json \
     --expected-host WIN2025-SFAI01 \
     --expected-python 3.14.6 \
     --json
   ```

11. Build a paste-ready saved evidence packet when needed:

   ```bash
   python scripts/windows_smoke_packet.py \
     --evidence-json windows-evidence.json \
     --status-json windows-status.json \
     --doctor-json windows-doctor.json \
     --services-json windows-services.json \
     --disks-json windows-disks.json \
     --expected-host WIN2025-SFAI01 \
     --expected-python 3.14.6 \
     --commit <commit-sha> \
     --pr 271 \
     --json \
     --markdown
   ```

   For a PR272 include-disks packet (embedded disks plus the standalone disks
   artifact):

   ```bash
   python scripts/windows_smoke_packet.py --evidence-json windows-evidence-with-disks.json --status-json windows-status.json --doctor-json windows-doctor.json --disks-json windows-disks.json --expected-host WIN2025-SFAI01 --expected-python 3.14.6 --pr 272 --commit <sha> --json --markdown
   ```

   For a PR275 packet that includes the standalone processes artifact:

   ```bash
   python scripts/windows_smoke_packet.py \
     --evidence-json windows-evidence.json \
     --status-json windows-status.json \
     --doctor-json windows-doctor.json \
     --processes-json windows-processes.json \
     --expected-host WIN2025-SFAI01 \
     --expected-python 3.14.6 \
     --pr 275 \
     --commit <sha> \
     --json \
     --markdown
   ```

   For a PR276 include-processes packet (embedded processes plus the
   standalone processes artifact):

   ```bash
   python scripts/windows_smoke_packet.py \
     --evidence-json windows-evidence-with-processes.json \
     --status-json windows-status.json \
     --doctor-json windows-doctor.json \
     --processes-json windows-processes.json \
     --expected-host WIN2025-SFAI01 \
     --expected-python 3.14.6 \
     --pr 276 \
     --commit <sha> \
     --json \
     --markdown
   ```

12. Report whether ShellForgeAI itself executed PowerShell, used WinRM, performed
   remote execution, or mutated the host. Expected answer for the current lane
   is always no.

## Required safety expectations

Saved Windows smoke JSON must show:

- `read_only=true`
- `mutation_performed=false`
- `powershell_executed=false`
- `winrm_used=false`
- `remote_execution=false`
- `shell_true=false`
- `arbitrary_command_execution=false`
- `network_call=false`
- `model_called=false`
- `secret_read=false`
- `auth_cache_read=false`
- for disks artifacts (standalone and embedded, PR273+): explicit
  `directory_scan_performed=false`, `file_scan_performed=false`, and
  `disk_mutation_performed=false`
- for processes preview artifacts: only PID, parent PID, image basename/name,
  and thread count are collected; command lines, environments, memory, handles,
  modules, owners/tokens, and network connections are not collected
- no service restart
- no process termination
- no registry modification
- no execution policy modification
- no install, remediation, rollback, or recovery by ShellForgeAI

## Operator/tooling distinction

Operator-approved staging may use external infrastructure tools such as Proxmox
or QGA to copy archives, control VM snapshots, or collect VM console/process
exit evidence. That tooling belongs to the acceptance harness. ShellForgeAI
product commands must still remain local, read-only, and must not execute
PowerShell, WinRM/PSRemoting, remote execution, service restarts, process
termination, registry changes, execution-policy changes, installs, remediation,
rollback, recovery, or other mutation.

## Local saved-JSON validator

`scripts/windows_smoke_acceptance.py` is a QA helper, not a ShellForgeAI product
command. It reads saved local JSON files only, including PR264
`windows_evidence_bundle` artifacts from `windows evidence --json`, since
PR268 the PR267 `windows_services` artifacts from `windows services --json`,
since PR271 the PR270 `windows_disks` artifacts from `windows disks --json`,
and since PR275 the PR274 `windows_processes` artifacts from
`windows processes --json`,
captured as UTF-8, UTF-8 with BOM, UTF-16 with BOM, or Windows PowerShell 5.1
default UTF-16LE with BOM. Raw/UTF-8 capture is still preferred where practical,
but UTF-16LE PowerShell 5.1 artifacts are accepted. It never invokes
ShellForgeAI commands, never contacts Windows hosts, never uses QGA or Proxmox
APIs, never uses PowerShell, never uses WinRM, never uses subprocess, never
uses network or model calls, and never mutates the Windows VM. Operator staging
may use approved external tooling, but ShellForgeAI product commands and
validator behavior remain read-only. It exits `0` only when required product
and safety checks pass, otherwise it emits failed check names and exits nonzero.

The optional `--services-json` input validates the PR267 services artifact:
`mode=windows_services`, `status=ok`, Windows platform, read-only/no-mutation
flags, `windows_v1.available`, the services summary with non-negative
total/running/stopped/unknown counts, the services list, truncation-limit
consistency, and the full services safety-flag set (no service
control/restart/config mutation, no PowerShell/WinRM/remote execution, no
registry or execution-policy changes, no secret/auth-cache reads, no
model/network calls). Omitting `--services-json` leaves existing validator
behavior unchanged.

Since PR269, an evidence bundle that embeds the opt-in services component
(`shellforgeai windows evidence --json --include-services`) is validated with
the same key safety expectations as the standalone services artifact, plus the
bounded-output fields (`limit`, `returned_count`, `total_count`, `truncated`)
and a summary `component_count` of 3 with `services` among the ok components.
A default doctor/status-only bundle continues to validate exactly as before,
and a standalone `--services-json` artifact is not required when the bundle
embeds services. When both are provided, the validator cross-checks the
embedded and standalone services mode/status and total counts.

Since PR271, the optional `--disks-json` input validates the PR270 disks
artifact: `mode=windows_disks`, `schema_version` 1, `status=ok`, Windows
platform, read-only/no-mutation flags, `windows_v1.available` with the
`local_read_only_disks` scope, the `stdlib_only` collection method, bounded
output fields (integer `limit` within the accepted 1-64 command range, boolean
`truncated`, non-negative total/returned/available/unavailable root counts,
returned <= total, truncation consistency, and a disks list bounded by the
limit), and the full disks safety-flag set (no PowerShell/WinRM/remote
execution, no directory or file scanning, no disk mutation/mount/format flags
when present, no registry or execution-policy changes, no secret/auth-cache
reads, no model/network calls). Since PR273, disks artifacts (standalone and
embedded) must also carry the explicit `disk_mutation_performed=false` safety
flag alongside `directory_scan_performed=false` and `file_scan_performed=false`;
legacy artifacts missing the key fail strict validation with a clear per-key
check name. PR273 is safety-schema normalization only: no new disk collection,
no directory/file scan, no disk mutation, and no PowerShell/WinRM/remoting.
Unavailable roots are accepted only when they
are sanitized as safe disk usage failures (for example
`{"status": "unavailable", "error": "disk_usage_failed"}`); tracebacks or raw
exception detail fields fail validation, while sanitized unavailable roots do
not fail an artifact whose top-level status is ok. Omitting `--disks-json`
leaves existing validator behavior unchanged.

Since PR272, an evidence bundle that embeds the opt-in disks component
(`shellforgeai windows evidence --json --include-disks`) is validated with the
same key safety expectations as the standalone disks artifact, plus the
bounded-output fields (`limit`, `returned_roots`, `total_roots`, `truncated`),
the top-level `embedded_disks` summary block consistency, and a summary
`component_count` of 3 with `disks` among the ok components (4 when the bundle
also embeds services). A default doctor/status-only bundle continues to
validate exactly as before, and a standalone `--disks-json` artifact is not
required when the bundle embeds disks. When both are provided, the validator
cross-checks the embedded and standalone disks mode/status and total root
counts. The embedded disks component reuses the existing PR270 read-only disks
payload: it does not scan directories/files, does not mutate disks, does not
run PowerShell, does not use WinRM/remoting, and does not perform
cleanup/remediation/rollback/recovery.

Since PR275, the optional `--processes-json` input validates the PR274
processes artifact: `mode=windows_processes`, `schema_version` 1, `status=ok`,
Windows platform, read-only/no-mutation flags, `windows_v1.available` with the
`local_read_only_processes_preview` scope, the `ctypes_toolhelp32_snapshot`
method, bounded output fields (integer `limit` within the accepted 1-200
command range, boolean `truncated`, non-negative `total_count` and
`returned_count`, `returned_count <= limit`, `returned_count <= total_count`,
truncation consistency, and a processes list bounded by the limit), the
per-item field allowlist (each process item may carry only `pid`,
`parent_pid`, `name`, and `thread_count`; command lines, environments, memory,
handles, modules, owners/users, network connections, and executable paths fail
validation), the `not_collected_in_pr274` notes, and the full processes
safety-flag set (no PowerShell/WinRM/remote execution, no process
termination/control/config mutation, no process memory/command-line/
environment/handles/modules/owner reads, no registry or execution-policy
changes, no cleanup/remediation/rollback/recovery, no shell/arbitrary
execution, no secret/auth-cache reads, no model/network calls). PR275
validates saved artifacts only: it does not run ShellForgeAI product commands,
does not collect new process data, does not add processes to the evidence
bundle, does not execute PowerShell, does not use WinRM/remoting, and does not
mutate the Windows VM. Omitting `--processes-json` leaves existing validator
behavior unchanged.

Since PR276, an evidence bundle that embeds the opt-in processes component
(`shellforgeai windows evidence --json --include-processes`) is validated with
the same key safety expectations as the standalone processes artifact
(including the per-item field allowlist of `pid`/`parent_pid`/`name`/
`thread_count`), plus the bounded-output fields (`limit`, `returned_count`,
`total_count`, `truncated`), the top-level `embedded_processes` summary block
consistency, and a summary `component_count` of 3 with `processes` among the
ok components (up to 5 when the bundle also embeds services and disks). A
default doctor/status-only bundle continues to validate exactly as before, and
a standalone `--processes-json` artifact is not required when the bundle
embeds processes. When both are provided, the validator cross-checks the
embedded and standalone processes mode/status/method. The embedded processes
component reuses the existing PR274 read-only processes payload: it does not
collect command lines, environments, memory, handles, modules, owners/users/
tokens, or network connections, does not terminate/control processes, does not
run PowerShell, does not use WinRM/remoting, and does not perform
cleanup/remediation/rollback/recovery.

Useful forms:

```bash
python scripts/windows_smoke_acceptance.py --evidence-json windows-evidence.json --json
python scripts/windows_smoke_acceptance.py --status-json status.json
python scripts/windows_smoke_acceptance.py --status-json status.json --doctor-json doctor.json
python scripts/windows_smoke_acceptance.py --services-json windows-services.json --json
python scripts/windows_smoke_acceptance.py --disks-json windows-disks.json --json
python scripts/windows_smoke_acceptance.py --processes-json windows-processes.json --json
python scripts/windows_smoke_acceptance.py --processes-json windows-processes.json --expected-host WIN2025-SFAI01 --expected-python 3.14.6 --json
python scripts/windows_smoke_acceptance.py --evidence-json windows-evidence.json --status-json windows-status.json --doctor-json windows-doctor.json --disks-json windows-disks.json --expected-host WIN2025-SFAI01 --expected-python 3.14.6 --json
python scripts/windows_smoke_acceptance.py --evidence-json windows-evidence.json --status-json windows-status.json --doctor-json windows-doctor.json --processes-json windows-processes.json --expected-host WIN2025-SFAI01 --expected-python 3.14.6 --json
python scripts/windows_smoke_acceptance.py --evidence-json windows-evidence.json --status-json windows-status.json --doctor-json windows-doctor.json --services-json windows-services.json --disks-json windows-disks.json --expected-host WIN2025-SFAI01 --expected-python 3.14.6 --json
python scripts/windows_smoke_acceptance.py --evidence-json windows-evidence-with-disks.json --status-json windows-status.json --doctor-json windows-doctor.json --disks-json windows-disks.json --expected-host WIN2025-SFAI01 --expected-python 3.14.6 --json
python scripts/windows_smoke_acceptance.py --evidence-json windows-evidence-with-processes.json --status-json windows-status.json --doctor-json windows-doctor.json --processes-json windows-processes.json --expected-host WIN2025-SFAI01 --expected-python 3.14.6 --json
```

## Saved evidence packet helper

`scripts/windows_smoke_packet.py` turns saved Windows smoke artifacts into a
deterministic QA evidence packet. It reads the saved `windows-evidence.json`,
`windows-status.json`, `windows-doctor.json`, and optional
`windows-services.json`, `windows-disks.json`, and `windows-processes.json`
files only; validates them via the PR265/PR268/PR271/PR275/PR276 acceptance
checks;
computes SHA256 and byte size for each input; and emits deterministic JSON
and/or concise Markdown for PR handoff.
When `--services-json` is provided, the packet includes the services artifact
path, SHA256, size, mode, status, and total/running/stopped/unknown service
counts in both the JSON artifact block and the Markdown artifact table plus a
short services summary; omitting it leaves the PR266 packet behavior unchanged.
When `--disks-json` is provided (PR271), the packet includes the disks artifact
path, SHA256, byte size, mode, status, and the safe disk summary fields
(total/returned/available/unavailable root counts, limit, truncated) in both
the JSON artifact block and the Markdown artifact table plus a short disks
summary noting that unavailable roots are accepted only when sanitized as safe
disk usage failures; since PR273 the disks summary also reports the explicit
disk safety flags (`directory_scan_performed`, `file_scan_performed`,
`disk_mutation_performed`) from the saved artifact, and validation fails when
a PR273+ disks artifact carries unsafe or missing disk safety flags. Omitting
`--disks-json` leaves existing packet behavior unchanged. When
`--processes-json` is provided (PR275), the packet includes the processes
artifact path, SHA256, byte size, mode, and status in the JSON artifact block
and Markdown artifact table, a `windows.processes` summary (method,
total/returned counts, limit, truncated) in the packet JSON, and a concise
Markdown "Processes summary" section that also notes explicitly that command
lines, environments, memory, handles, modules, owners/users, and network
connections were not collected; packet validation fails when the processes
artifact fails the PR275 acceptance checks, and omitting `--processes-json`
leaves existing packet behavior unchanged. Since
PR269, when the evidence bundle itself embeds the opt-in services component the
packet also emits an `embedded_services` summary (mode, status, limit,
returned/total counts, truncated flag, and running/stopped/unknown counts) in
JSON and a short Markdown section; a standalone `--services-json` artifact is
not required when the bundle embeds services, and when both are present the
shared validator cross-checks their mode/status/count fields. Since PR272,
when the evidence bundle embeds the opt-in disks component the packet also
emits an `embedded_disks` summary (mode, status, limit, returned/total root
counts, available/unavailable root counts, and truncated flag) in JSON and a
short Markdown section; a standalone `--disks-json` artifact is not required
when the bundle embeds disks, standalone `disks_json` support from PR271
remains valid, and when both are present the shared validator cross-checks
their mode/status/root-count fields. Since PR276, when the evidence bundle
embeds the opt-in processes component the packet also emits an
`embedded_processes` summary (mode, status, method, limit, returned/total
counts, and truncated flag) in JSON and a short Markdown section that notes
explicitly that command lines, environments, memory, handles, modules,
owners/users, and network connections were not collected; a standalone
`--processes-json` artifact is not required when the bundle embeds processes,
standalone `processes_json` support from PR275 remains valid, and when both
are present the shared validator cross-checks their mode/status/method fields.
It accepts UTF-8, UTF-8 with BOM, UTF-16 with BOM, and Windows PowerShell 5.1
UTF-16LE/BOM artifacts through the shared saved-JSON validator.

The packet helper is not a product collection command. It is safe to execute
directly by absolute path with the durable Windows embedded Python runtime; no
`PYTHONPATH` setting or scripts-directory cwd trick is required. It does not run
ShellForgeAI commands, contact Windows hosts, use PowerShell, WinRM, QGA,
Proxmox, subprocess, network calls, model calls, or mutation. By default it
writes to stdout only; it writes files only when an operator explicitly passes
`--out-json` and/or `--out-markdown`. At least one output mode is required.

Useful packet forms:

```bash
python scripts/windows_smoke_packet.py \
  --evidence-json windows-evidence.json \
  --status-json windows-status.json \
  --doctor-json windows-doctor.json \
  --services-json windows-services.json \
  --disks-json windows-disks.json \
  --expected-host WIN2025-SFAI01 \
  --expected-python 3.14.6 \
  --commit <commit-sha> \
  --pr 271 \
  --json \
  --markdown

python scripts/windows_smoke_packet.py \
  --evidence-json windows-evidence.json \
  --status-json windows-status.json \
  --doctor-json windows-doctor.json \
  --services-json windows-services.json \
  --disks-json windows-disks.json \
  --expected-host WIN2025-SFAI01 \
  --expected-python 3.14.6 \
  --commit <commit-sha> \
  --pr 271 \
  --out-json packet.json \
  --out-markdown PR271-QA-EVIDENCE.md

python scripts/windows_smoke_packet.py \
  --evidence-json windows-evidence.json \
  --status-json windows-status.json \
  --doctor-json windows-doctor.json \
  --processes-json windows-processes.json \
  --expected-host WIN2025-SFAI01 \
  --expected-python 3.14.6 \
  --commit <commit-sha> \
  --pr 275 \
  --json \
  --markdown

python scripts/windows_smoke_packet.py \
  --evidence-json windows-evidence-with-processes.json \
  --status-json windows-status.json \
  --doctor-json windows-doctor.json \
  --processes-json windows-processes.json \
  --expected-host WIN2025-SFAI01 \
  --expected-python 3.14.6 \
  --commit <commit-sha> \
  --pr 276 \
  --json \
  --markdown
```

## Future PR guidance

Each Windows feature PR should include:

- Docker01 Linux unsupported smoke for Windows-specific commands.
- Windows Server on-VM CLI smoke when the command is Windows-specific.
- Saved JSON output from the relevant Windows command.
- Validator result from `scripts/windows_smoke_acceptance.py` and, when a handoff packet is useful, `scripts/windows_smoke_packet.py`.
- A clear statement that deeper Windows evidence collection, if any, is split
  into a separate PR.

Do not combine this harness with new PowerShell probing, WinRM/PSRemoting,
service/process/event-log inventory, firewall evidence, Windows Update evidence,
package install/bootstrap logic, or mutation recipes.
