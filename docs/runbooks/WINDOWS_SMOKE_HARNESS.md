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
- Embedded CPython: `C:\Tools\ShellForgeAI\Python312`
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
6. Capture JSON output for:
   - `shellforgeai windows status --json`
   - `shellforgeai windows doctor --json`
7. Capture text output where relevant for human-facing smoke evidence.
8. Archive the raw JSON artifacts exactly as captured. Deterministic capture
   methods are preferred, but operators do not need to rewrite files that include
   a UTF-8 BOM. The local validator accepts UTF-8 JSON with or without BOM.
9. Validate the saved JSON artifacts locally with:

   ```bash
   python scripts/windows_smoke_acceptance.py --status-json path/to/status.json --doctor-json path/to/doctor.json
   python scripts/windows_smoke_acceptance.py --status-json path/to/status.json --doctor-json path/to/doctor.json --json
   ```

10. Report whether ShellForgeAI itself executed PowerShell, used WinRM, performed
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
command. It reads local UTF-8 JSON files with or without BOM only, never
invokes ShellForgeAI commands, never contacts Windows hosts, never uses QGA,
never uses PowerShell, never uses WinRM, never uses subprocess, and never
mutates the host. It exits `0` only when required product and safety checks
pass, otherwise it emits failed check names and exits nonzero.

Useful forms:

```bash
python scripts/windows_smoke_acceptance.py --status-json status.json
python scripts/windows_smoke_acceptance.py --status-json status.json --doctor-json doctor.json
python scripts/windows_smoke_acceptance.py --status-json status.json --doctor-json doctor.json --expected-host WIN2025-SFAI01 --expected-python 3.12.10 --json
```

## Future PR guidance

Each Windows feature PR should include:

- Docker01 Linux unsupported smoke for Windows-specific commands.
- Windows Server on-VM CLI smoke when the command is Windows-specific.
- Saved JSON output from the relevant Windows command.
- Validator result from `scripts/windows_smoke_acceptance.py`.
- A clear statement that deeper Windows evidence collection, if any, is split
  into a separate PR.

Do not combine this harness with new PowerShell probing, WinRM/PSRemoting,
service/process/event-log inventory, firewall evidence, Windows Update evidence,
package install/bootstrap logic, or mutation recipes.
