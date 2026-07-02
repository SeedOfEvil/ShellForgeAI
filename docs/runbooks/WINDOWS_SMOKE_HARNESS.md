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
   - optional `windows-disks.json` from `shellforgeai windows disks --json`
     (PR270 standalone local read-only disk/root usage preview; not part of
     the evidence bundle yet and not validated by the saved-JSON acceptance
     validator or packet helper yet)
   - optional text outputs for human-facing smoke evidence.

   Windows smoke commands for the current lane:

   ```text
   shellforgeai windows evidence --json
   shellforgeai windows evidence --json --include-services --services-limit 25
   shellforgeai windows services --json --limit 25
   shellforgeai windows disks --json
   ```
7. PR265 extends the saved-JSON acceptance validator to support `shellforgeai windows evidence --json` artifacts. PR268 adds saved-artifact validation and packet support for `windows-services.json`. PR269 validates evidence bundles that embed the opt-in services component with the same key safety expectations as the standalone services artifact; a standalone `--services-json` artifact is not required when the bundle embeds services.
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

11. Build a paste-ready saved evidence packet when needed:

   ```bash
   python scripts/windows_smoke_packet.py \
     --evidence-json windows-evidence.json \
     --status-json windows-status.json \
     --doctor-json windows-doctor.json \
     --services-json windows-services.json \
     --expected-host WIN2025-SFAI01 \
     --expected-python 3.14.6 \
     --commit <commit-sha> \
     --pr 268 \
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
`windows_evidence_bundle` artifacts from `windows evidence --json` and, since
PR268, PR267 `windows_services` artifacts from `windows services --json`,
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

Useful forms:

```bash
python scripts/windows_smoke_acceptance.py --evidence-json windows-evidence.json --json
python scripts/windows_smoke_acceptance.py --status-json status.json
python scripts/windows_smoke_acceptance.py --status-json status.json --doctor-json doctor.json
python scripts/windows_smoke_acceptance.py --services-json windows-services.json --json
python scripts/windows_smoke_acceptance.py --evidence-json windows-evidence.json --status-json windows-status.json --doctor-json windows-doctor.json --services-json windows-services.json --expected-host WIN2025-SFAI01 --expected-python 3.14.6 --json
```

## Saved evidence packet helper

`scripts/windows_smoke_packet.py` turns saved Windows smoke artifacts into a
deterministic QA evidence packet. It reads the saved `windows-evidence.json`,
`windows-status.json`, `windows-doctor.json`, and optional
`windows-services.json` files only; validates them via the PR265/PR268
acceptance checks; computes SHA256 and byte size for each input; and emits
deterministic JSON and/or concise Markdown for PR handoff. When
`--services-json` is provided, the packet includes the services artifact path,
SHA256, size, mode, status, and total/running/stopped/unknown service counts in
both the JSON artifact block and the Markdown artifact table plus a short
services summary; omitting it leaves the PR266 packet behavior unchanged. Since
PR269, when the evidence bundle itself embeds the opt-in services component the
packet also emits an `embedded_services` summary (mode, status, limit,
returned/total counts, truncated flag, and running/stopped/unknown counts) in
JSON and a short Markdown section; a standalone `--services-json` artifact is
not required when the bundle embeds services, and when both are present the
shared validator cross-checks their mode/status/count fields. It
accepts UTF-8, UTF-8 with BOM, UTF-16 with BOM, and Windows PowerShell 5.1
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
  --expected-host WIN2025-SFAI01 \
  --expected-python 3.14.6 \
  --commit <commit-sha> \
  --pr 268 \
  --json \
  --markdown

python scripts/windows_smoke_packet.py \
  --evidence-json windows-evidence.json \
  --status-json windows-status.json \
  --doctor-json windows-doctor.json \
  --services-json windows-services.json \
  --expected-host WIN2025-SFAI01 \
  --expected-python 3.14.6 \
  --commit <commit-sha> \
  --pr 268 \
  --out-json packet.json \
  --out-markdown PR268-QA-EVIDENCE.md
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
