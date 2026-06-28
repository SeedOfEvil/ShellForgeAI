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

ShellForgeAI now includes a narrow read-only platform detector and `shellforgeai platform doctor` status command. This foundation recognizes Linux, Windows, Darwin, and unknown platforms using Python standard library metadata only. It does not run PowerShell, WinRM/PSRemoting, Docker, Compose, host probing, service inventory, process inventory, event-log reads, network calls, model calls, secret reads, installs, or mutations.

ShellForgeAI should detect platform early through a read-only, safe platform detector. Linux/Docker lanes must not accidentally run Windows logic, and Windows lanes must not pretend Docker/Linux evidence exists.

On unsupported platforms or unsupported commands, ShellForgeAI should emit a graceful structured message instead of throwing an implementation-specific traceback or silently switching lanes. The current platform doctor reports Linux as the supported Linux/Docker operational lane, Windows as recognized with Windows V1 planned but not evidence-collecting yet, and Darwin/unknown as unsupported for current operational lanes. A platform result can look like:

```json
{
  "platform": "windows",
  "supported": false,
  "lane": "windows_v1_planned",
  "read_only": true,
  "mutation_performed": false
}
```

## Graceful unsupported behavior

Unsupported Windows commands, unsupported Linux/Docker commands on Windows, and unsupported platforms should return an explicit unsupported status, the detected platform if known, a short reason, and a safe next inspection command when one exists. Unsupported behavior must remain non-mutating and must not call a model to guess platform-specific actions.

## Future command shape

The platform doctor command is available now; Windows-specific commands remain future design sketches only:

```bash
shellforgeai platform doctor --json
shellforgeai platform doctor
shellforgeai windows doctor --json
shellforgeai windows status --json
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

1. Add a read-only platform detector and graceful unsupported message contract. (Current foundation.)
2. Prototype a Windows read-only doctor for local OS info, PowerShell version, execution policy, and host context.
3. Prototype a Windows read-only status/report for services, processes, disks, network basics, event logs, and safe update/firewall/roles signals.
4. Run a packaging/install spike after the evidence path is clear.
5. Later, only after evidence, tests, and review, consider narrowly scoped Windows recipes if a real operator need exists.
