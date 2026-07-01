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
8. Add Windows read-only service, process, and event-log evidence in separate PRs.
9. Packaging/install spike.
10. Later, only after evidence, tests, and review, consider narrowly scoped Windows recipes if a real operator need exists.
