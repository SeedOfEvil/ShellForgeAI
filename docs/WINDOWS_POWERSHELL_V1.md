# Windows/PowerShell V1

## Goal

Windows/PowerShell V1 is a planned local, read-only evidence lane for Windows operators. It extends ShellForgeAI's evidence-first posture to a Windows host without turning the product into a PowerShell executor, remote administration tool, or autonomous repair agent.

The V1 lane should help answer:

- What Windows host am I on?
- What PowerShell version is available?
- What is the current execution policy?
- What OS build, edition, and OS info are present?
- What services, processes, disks, filesystems, network adapters, IP settings, and DNS basics are visible?
- What recent critical, error, or warning event-log signals exist?
- What should I inspect first from local host evidence first?

## Target test environment

The first target is the Windows Server 2025 ShellForgeAI test VM. Work should start on a local test host first, with no production Windows mutation, no production cleanup, and no domain-wide action.

Windows V1 does not include WinRM, PSRemoting, or remote fleet management. The test VM support goal means ShellForgeAI can eventually collect safe local evidence from that VM and report clear unsupported behavior elsewhere; it does not mean ShellForgeAI may mutate the VM or production Windows hosts.

## V1 read-only evidence scope

The V1 scope is read-only evidence collection only. Candidate local evidence categories are:

- OS info, build, edition, architecture, and install context where available without privileged secret reads.
- Hostname plus domain or workgroup basics.
- PowerShell version and compatible host/runtime information.
- Execution policy as reported by the local PowerShell environment.
- User and session context without reading secrets, tokens, auth caches, credential stores, or protected material.
- Service status inventory and summary counts.
- Process summary with bounded metadata suitable for triage.
- Disk and filesystem capacity, filesystem type, and basic volume health signals.
- Network adapter, IP address, gateway, and DNS summary.
- Windows Update or update-status signals where available through safe read-only local APIs.
- Recent Windows event logs summarized for critical, error, and warning signals.
- Firewall profile and status summary when it can be collected safely and read-only.
- Installed roles and features summary when available read-only and local.

## Explicit non-goals

Windows V1 does not:

- Run arbitrary PowerShell supplied by a user.
- Execute natural-language commands.
- Mutate services or restart services.
- Reboot hosts.
- Change PowerShell execution policy.
- Install software.
- Enable or disable firewall profiles or rules.
- Change the registry.
- Change local users or groups.
- Use WinRM, PSRemoting, remote execution, or remote fleet management.
- Collect secrets, read auth caches, scrape credentials, or inspect credential stores.
- Perform remediation, rollback, recovery, production cleanup, or autonomous self-healing.

## Platform detection direction

ShellForgeAI now includes a narrow read-only platform detector and `shellforgeai platform doctor` status command. This foundation recognizes Linux, Windows, Darwin, and unknown platforms using Python standard library metadata only. On Windows, the platform doctor emits a small deterministic evidence block for OS family/name, Windows version/build when available through Python, architecture, Python version/platform, and PowerShell/pwsh availability discovered with safe local path checks. It does not execute PowerShell, WinRM/PSRemoting, Docker, Compose, host probing, service inventory, process inventory, event-log reads, network calls, model calls, secret reads, installs, or mutations.

ShellForgeAI should detect platform early through a read-only, safe platform detector. Linux/Docker lanes must not accidentally run Windows logic, and Windows lanes must not pretend Docker/Linux evidence exists.

On unsupported platforms or unsupported commands, ShellForgeAI should emit a graceful structured message instead of throwing an implementation-specific traceback or silently switching lanes. The current platform doctor reports Linux as the supported Linux/Docker operational lane, Windows as a limited `windows_read_only_doctor_v1` evidence lane, and Darwin/unknown as unsupported for current operational lanes. A platform result can look like:

```json
{
  "platform": "windows",
  "supported": false,
  "lane": "windows_read_only_doctor_v1",
  "windows_evidence": {
    "os_family": "windows",
    "read_only": true,
    "mutation_performed": false
  },
  "read_only": true,
  "mutation_performed": false
}
```

## Graceful unsupported behavior

Unsupported Windows commands, unsupported Linux/Docker commands on Windows, and unsupported platforms should return an explicit unsupported status, the detected platform if known, a short reason, and a safe next inspection command when one exists. Unsupported behavior must remain non-mutating and must not call a model to guess platform-specific actions.

## Future command shape

The platform doctor command is available now. The first Windows-specific prototypes are available as local-only read-only doctor and status reports:

```bash
shellforgeai platform doctor --json
shellforgeai platform doctor
shellforgeai windows doctor --json
shellforgeai windows doctor
shellforgeai windows status --json
shellforgeai windows status
shellforgeai windows evidence --json
shellforgeai windows evidence
shellforgeai windows evidence --json --include-services
shellforgeai windows evidence --json --include-services --services-limit 25
shellforgeai windows evidence --json --include-disks
shellforgeai windows evidence --json --include-disks --disks-limit 5
shellforgeai windows services --json
shellforgeai windows services
shellforgeai windows disks --json
shellforgeai windows disks
shellforgeai ask "It is 2AM and this Windows server feels broken. What should I check first?"
```

The `ask` example should remain evidence-first: collect typed local Windows evidence first when a Windows lane exists, then synthesize a safe inspection summary. It must not run natural-language commands.

## Safety model

The Windows lane preserves ShellForgeAI's core safety model:

- Read-only by default.
- Local host evidence first.
- Mutations only through named, narrow, auditable recipes if any future Windows recipe is approved.
- Explicit confirmation for any future mutation recipe.
- No natural-language execution.
- No broad autonomy.
- No arbitrary PowerShell execution.
- No WinRM/remote execution in V1.
- No remediation, rollback, recovery, production cleanup, secret reads, or auth-cache reads.

## Proposed implementation sequence

1. Add a read-only platform detector and graceful unsupported message contract. (Complete.)
2. Add a narrow Windows read-only doctor evidence foundation for local OS/Python metadata and shell availability signals without executing PowerShell. (Current platform foundation.)
3. Add the first `shellforgeai windows doctor` prototype for local, read-only Windows host basics using Python standard library only. It does not execute PowerShell, use WinRM/PSRemoting, mutate the Windows VM, or collect services/processes/event logs yet. Linux/Docker behavior remains unchanged and returns structured unsupported output for this command. (Complete.)
4. PR262 adds the first `shellforgeai windows status` report for safe stdlib-only host basics: platform metadata, hostname/FQDN, current working directory, Python runtime, and disk-capacity summaries for the current directory and Windows root. It is local-only, does not execute PowerShell, does not use WinRM/PSRemoting, does not mutate the Windows VM, and does not collect services/processes/event logs yet. Linux/Docker behavior remains unchanged and returns structured unsupported output pointing to `shellforgeai platform doctor --json`. Windows Server 2025 VM acceptance should verify `shellforgeai windows status --json` and `shellforgeai windows status`. (Current prototype.)
5. Windows Server 2025 VM smoke for the local status report. (Complete for the PR262 baseline.)
6. Use `docs/runbooks/WINDOWS_SMOKE_HARNESS.md` and `scripts/windows_smoke_acceptance.py` to validate saved Windows `status`/`doctor` JSON before expanding Windows evidence collection. The validator is local-only and does not execute ShellForgeAI commands, PowerShell, WinRM/PSRemoting, QGA, subprocesses, network calls, or mutation.
7. Add `shellforgeai windows evidence` as a bundle/preview command over the existing read-only doctor/status payloads. It reuses those payload builders, adds no new Windows evidence collection, does not execute PowerShell, does not use WinRM/PSRemoting, does not mutate the Windows VM, and leaves services, processes, event logs, firewall, and Windows Update for later separate PRs. Windows Server 2025 acceptance should run `shellforgeai windows evidence --json`, `shellforgeai windows evidence`, `shellforgeai windows status --json`, and `shellforgeai windows doctor --json`. (Current bundle preview.)
8. PR265 extends the saved-artifact acceptance validator to cover the PR264 evidence bundle as a QA gate before deeper Windows evidence slices; it adds no new collection.
9. Add the saved evidence packet helper as the handoff/reporting step for saved Windows smoke artifacts. It validates existing artifacts, records hashes/sizes, and emits JSON/Markdown without new collection, PowerShell, WinRM, or mutation.
10. PR267 adds `shellforgeai windows services` as the first narrow deeper Windows evidence slice: a standalone local read-only service state summary preview. On Windows it enumerates service names, display names, and current states through read-only `ctypes` Service Control Manager enumeration only (`OpenSCManagerW` with enumerate rights, `EnumServicesStatusExW`, `CloseServiceHandle`) and summarizes counts by state with a bounded collection limit. It does not execute PowerShell, does not use WinRM/PSRemoting, does not use subprocess, does not start/stop/restart/control/configure services, does not read service binary paths, service accounts, service configuration, or the registry, and does not mutate the Windows VM. Linux/Docker and unsupported platforms return structured unsupported output pointing to `shellforgeai platform doctor --json`. The services preview is not yet included in `shellforgeai windows evidence`; bundle integration may follow in a later PR only after the standalone services surface is proven safe. (Current services preview.)
11. PR268 extends the saved-artifact acceptance validator and packet helper with optional `--services-json` support for PR267 `windows_services` artifacts. Services saved-artifact validation is the QA gate before deeper Windows evidence slices; it reads saved local files only and adds no new collection, PowerShell, WinRM, or mutation.
12. PR269 adds an explicit, bounded, opt-in services component to `shellforgeai windows evidence` via `--include-services` and `--services-limit N`. Services in the evidence bundle are opt-in and bounded: the default bundle stays doctor/status-only, and when `--include-services` is passed the bundle embeds the existing PR267 read-only services collector output with a conservative default limit of 25 (validated range 1-500). This reuses the existing read-only services collector and adds no new Windows collection surface. No PowerShell is executed, no WinRM/PSRemoting is used, no service control/restart/configuration mutation is performed, and no registry or execution-policy change occurs. (Current opt-in bundle component.)
13. PR270 adds `shellforgeai windows disks [--json] [--limit N]` as the next standalone Windows read-only evidence slice: a local disk/root usage preview. On Windows it discovers local drive roots with `os.listdrives` when available (feature-detected; otherwise it falls back safely to the current drive root only) and reads per-root total/used/free bytes via `shutil.disk_usage`, using the Python standard library only, with a bounded deterministic `--limit` (default 32, range 1-64). It does not scan directories or files, does not read user files, does not read secrets or auth caches, does not execute PowerShell, does not use WinRM/PSRemoting, does not use subprocess, does not collect drive labels, volume serials, BitLocker status, SMART/health status, or file/directory inventory, and does not mutate the Windows VM. Linux/Docker and unsupported platforms return structured unsupported output pointing to `shellforgeai platform doctor --json`. The sequence was standalone disks preview first (PR270), then saved-artifact validator/packet support for disks (PR271), then opt-in evidence bundle integration for disks (PR272).
14. PR271 extends the saved-artifact acceptance validator and packet helper with optional `--disks-json` support for PR270 `windows_disks` artifacts, accepting unavailable roots only when sanitized as safe disk usage failures. Disks saved-artifact validation and packet support are complete; the helpers read saved local files only and add no new collection, PowerShell, WinRM, or mutation. Deeper disk inspection, disk cleanup, disk repair, and mount/format remain out of scope.
15. PR272 adds an explicit, bounded, opt-in disks component to `shellforgeai windows evidence` via `--include-disks` and `--disks-limit N`. Disks in the evidence bundle are opt-in and bounded: the default bundle stays doctor/status-only, and when `--include-disks` is passed the bundle embeds the existing PR270 read-only disks payload with the same safe default limit of 32 (validated range 1-64). This reuses the existing read-only disks payload builder and adds no new Windows collection surface. It does not scan directories or files, does not mutate disks (no mount/unmount/format/repair), does not execute PowerShell, does not use WinRM/PSRemoting, and does not perform cleanup, remediation, rollback, or recovery. The saved-artifact validator and packet helper understand evidence bundles with embedded disks, and standalone `windows-disks.json` support from PR271 remains valid. (Current opt-in bundle component.)
16. PR273 normalizes the Windows disks safety flags: both the standalone `shellforgeai windows disks` payload and the embedded evidence disks component now explicitly report `directory_scan_performed=false`, `file_scan_performed=false`, and `disk_mutation_performed=false` in their safety blocks, matching the top-level PR272 evidence safety block. The saved-artifact validator and packet helper expect the explicit disk safety flags for PR273+ disks artifacts. This is schema consistency only: no new disk collection is added, no directory or file scan is added, no disk mutation is possible, and no PowerShell/WinRM/remoting is used.
17. Add Windows read-only service deep detail (descriptions, dependencies, recovery options), process, and event-log evidence in separate PRs; firewall and Windows Update evidence also remain future separate PRs.
18. Packaging/install spike.
19. Later, only after evidence, tests, and review, consider narrowly scoped Windows recipes if a real operator need exists.
