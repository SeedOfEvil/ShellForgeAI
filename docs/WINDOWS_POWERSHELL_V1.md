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
shellforgeai windows processes --json
shellforgeai windows processes --json --limit 10
shellforgeai windows processes
shellforgeai ask "It is 2AM and this Windows server feels broken. What should I check first?"
```

The `ask` example should remain evidence-first: collect typed local Windows evidence first when a Windows lane exists, then synthesize a safe inspection summary. It must not run natural-language commands.

## Interactive performance diagnostics on Windows

Since PR279, interactive slow-system/performance diagnostics (for example "Hey this system feels a bit slow" inside `shellforgeai interactive`) are Windows-aware. On Windows the route skips Linux-only collectors (`uptime`, `df`, `ip`, `ss`, `ps`, `systemctl`, `/proc` reads, `/etc/resolv.conf` reads) and records them as structured `linux_only_collector_skipped` evidence instead of running them or rendering their failures. Missing metrics (load average, `/proc`-based memory totals) render explicit unavailable markers instead of `loadavg=None` or fake `0.0GiB/0.0GiB` values. The bounded read-only summary reuses only the existing stdlib-only `windows status` and `windows disks` payloads and points at safe next commands such as `shellforgeai windows status --json` and `shellforgeai windows processes --json --limit 10`. No PowerShell is executed and no WinRM/PSRemoting is used; the route stays read-only and non-mutating, and it degrades to a deterministic summary when model synthesis is unavailable.

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
17. PR274 adds `shellforgeai windows processes [--json] [--limit N]` as a standalone local Windows read-only bounded process preview (default limit 50, range 1-200). On Windows it uses Python standard library plus `ctypes` Toolhelp process snapshots to collect only PID, parent PID, image basename/name, and thread count. It does not execute PowerShell, use WinRM/remoting, terminate/control/suspend processes, read command lines, read environments, inspect memory, handles, modules, owners/tokens, or map network connections. Linux/Docker and unsupported platforms return structured unsupported output pointing to `shellforgeai platform doctor --json`. Opt-in evidence bundle inclusion for processes landed separately in PR276; services and disks behavior remains unchanged.
18. PR275 extends the saved-artifact acceptance validator and packet helper with optional `--processes-json` support for PR274 `windows_processes` artifacts. It validates saved artifacts only: it does not run ShellForgeAI product commands, does not collect new process data, does not add processes to the evidence bundle, does not execute PowerShell, does not use WinRM/remoting, and does not mutate the Windows VM. It validates that process artifacts carry only PID, parent PID, image basename/name, and thread count — never command lines, environments, memory, handles, modules, owners/users, or network connections. Evidence-bundle integration for processes landed separately in PR276.
19. PR276 adds an explicit, bounded, opt-in processes component to `shellforgeai windows evidence` via `--include-processes` and `--processes-limit N`. Processes in the evidence bundle are opt-in and bounded: the default bundle stays doctor/status-only, and when `--include-processes` is passed the bundle embeds the existing PR274 read-only processes payload with a conservative default limit of 25 (validated range 1-200; `--processes-limit` is valid only with `--include-processes`). This reuses the existing read-only PR274 processes payload builder and adds no new Windows collection surface. It does not collect command lines, does not collect environments, does not read process memory, does not inspect handles/modules/owners/users/tokens, does not map network connections, does not terminate/control processes, does not execute PowerShell, does not use WinRM/remoting, and does not perform cleanup, remediation, rollback, or recovery. The saved-artifact validator and packet helper understand evidence bundles with embedded processes, and standalone `windows-processes.json` support from PR275 remains valid. (Current opt-in bundle component.)
20. PR287 enriches the local read-only Windows memory and disk evidence with honest Windows-native semantics. A new read-only `windows_memory` collector reports physical memory posture (`available`, `total_bytes`, `available_bytes`, `used_bytes`, `used_percent`, `source`) using the same bounded `ctypes`/`kernel32` pattern as the process/service previews, calling only the documented read-only `GlobalMemoryStatusEx` API; it fails soft with an explicit "Memory summary unavailable from this collector on Windows" limitation when memory cannot be collected, and always marks "Load average is not available on Windows" (no fake Linux load average). `shellforgeai windows status --json` now carries a `memory` block plus a `resource_limitations` load-average marker, and `shellforgeai windows disks --json` adds per-root `used_percent`, a `summary.primary_root_free_bytes`, and an explicit `limitations` list ("Inodes are not available on Windows"; "Linux-only disk inode collectors skipped on Windows") — no inode values are ever reported on Windows. The evidence bundle surfaces the enriched memory/disk facts transitively through its reused status/disks components. Every deterministic Windows operator answer that mentions memory — slow/latency first-pass, CPU/memory/disk/process strongest-signal comparison, the "what to check first" guidance, and the read-only status/intent guidance — reflects real Windows memory posture when the collector reports it available, and only states "Memory summary unavailable from this collector on Windows" when memory is actually unavailable; the load-average and inode markers stay explicit in both cases. All additive: existing JSON fields are preserved. It executes no PowerShell, uses no WinRM/PSRemoting, spawns no shell/subprocess, reads no process memory/secrets/auth caches, makes no network/model calls, and performs no mutation, cleanup, remediation, rollback, recovery, service control, process termination, or registry/execution-policy change.
21. Add Windows read-only service deep detail (descriptions, dependencies, recovery options) and event-log evidence in separate PRs; firewall and Windows Update evidence also remain future separate PRs.
22. Packaging/install spike.
23. Later, only after evidence, tests, and review, consider narrowly scoped Windows recipes if a real operator need exists.


## Saved interactive transcript acceptance

Windows interactive performance diagnostics have a QA/harness-only saved-transcript acceptance helper: `python scripts/windows_interactive_acceptance.py --slow-transcript interactive-slow.txt --mutation-transcript interactive-mutation-refusal.txt --json --markdown`. The helper validates saved text only and does not execute PowerShell, use WinRM/PSRemoting, launch interactive mode, contact a Windows host, or mutate the VM. ShellForgeAI itself also uses no PowerShell or WinRM for this Windows interactive performance path.

## Saved interactive transcript packet support

For QA handoff only, `scripts/windows_smoke_packet.py` can include saved Windows interactive slow/performance and mutation-refusal transcripts alongside saved JSON artifacts by passing both `--slow-transcript` and `--mutation-transcript`. The helper reuses the saved-transcript acceptance checks, reports transcript path, SHA256, byte size, accepted/failed state, and an interactive summary in deterministic JSON/Markdown. It reads saved local files only and does not launch ShellForgeAI interactive mode, execute PowerShell, use WinRM/PSRemoting, contact QGA/Proxmox, call the network or a model, or mutate the Windows host.

## Interactive Windows read-only request routing

Interactive mode recognizes explicit safe Windows read-only requests such as `show me the windows status`, `windows status`, `windows doctor`, `windows evidence`, and `windows processes limit 10`. These phrases are deterministic allowlisted routing only: ShellForgeAI renders the corresponding safe command guidance (`sfai.cmd windows status --json`, `sfai.cmd windows doctor --json`, `sfai.cmd windows evidence --json`, and `sfai.cmd windows processes --json --limit 10`) and updates `/pending` to a `windows-local-read-only` context. The route does not invoke model/system-prompt synthesis first, does not execute PowerShell, does not use WinRM/PSRemoting, does not spawn a shell or subprocess, and does not mutate services, processes, disks, Docker/Compose, registry, execution policy, or the filesystem.

On Linux/non-Windows hosts, the same Windows phrases return unsupported/Windows-only safe guidance and `shellforgeai platform doctor --json`; they do not probe Windows or switch to Linux/Docker collectors. Broad natural-language execution remains out of scope.

## Interactive assessment leakage guard

Windows interactive performance diagnosis keeps the existing local read-only evidence path, but provider assessment text is now guarded against project/system-prompt acknowledgement leakage. If the provider returns AGENTS.md, workspace/project-instruction, documentation-invariant, or evidence-first-routing acknowledgement text instead of a diagnosis, ShellForgeAI suppresses that text and renders the deterministic Windows evidence-grounded fallback with safe next commands. This adds no new Windows collectors or command payloads and does not execute PowerShell, use WinRM/PSRemoting, spawn shell/subprocess execution, call a model again, or mutate the host.

### Generic interactive parity prompts

In a Windows local read-only interactive context, generic prompts such as `Show me the system status` and `What should I check first?` are handled deterministically with Windows safe-next guidance (`sfai.cmd windows status --json`, `sfai.cmd windows doctor --json`, `sfai.cmd windows evidence --json`, `sfai.cmd windows processes --json --limit 10`, and `sfai.cmd windows disks --json`). Cleanup/restart/services requests are refused clearly as mutating/service-impacting and are paired with the same read-only alternatives. These routes do not shell out to the wrapper, execute PowerShell, use WinRM/PSRemoting, call the model for next-check guidance, or mutate the host.

### Human SSH assessment acknowledgement fallback

The Windows interactive performance path rejects provider assessments that merely acknowledge ShellForgeAI repo/workspace conventions or safety/CLI/routing/UX invariants. Smart-apostrophe and mojibake variants are normalized, and Windows evidence collection falls back to the deterministic read-only summary when provider text is non-diagnostic or lacks Windows evidence-bearing terms. The raw provider text may still be written to `model-response.md` for audit, but stdout stays operator-facing. No PowerShell, WinRM/PSRemoting, shell/subprocess execution, new collectors, or mutation are added.

### Windows interactive operator parity

Windows interactive mode rejects provider output that is only a project/repo/system-instruction acknowledgement (for example AGENTS.md invariants, ShellForgeAI repo conventions, project constraints, or system-prompt/workspace-instruction acknowledgements). The raw model response may remain in `model-response.md` for audit, but operator stdout falls back to deterministic Windows read-only summaries.

Windows generic latency, status/next-check, CPU/memory/disk/process comparison, and current-host handoff prompts use Windows-local read-only guidance and safe next commands such as `sfai.cmd windows status --json`, `sfai.cmd windows doctor --json`, `sfai.cmd windows evidence --json`, `sfai.cmd windows processes --json --limit 10`, `sfai.cmd windows disks --json`, and `sfai.cmd windows services --json --limit 25`. The summaries state limitations honestly when load average, memory, or process detail is unavailable. No PowerShell, WinRM/PSRemoting, shell, subprocess, cleanup, remediation, rollback, recovery, service control, or mutation is used by these deterministic interactive routes.

Transcript acceptance for Windows interactive parity smoke is line-oriented and negation-aware. Safe refusal lines such as `No shell or remoting execution, no service restart, no process termination, no cleanup, and no file changes were performed.` are accepted as no-mutation evidence; direct execution claims still fail the helper. The product path remains read-only and uses no PowerShell, WinRM, shell, subprocess, cleanup, remediation, rollback, recovery, service control, or mutation.

Windows interactive sensitive diagnostic paths now use deterministic routing or capture-then-gate rendering before stdout. The app-latency, slow, status, next-check, and handoff prompts should not stream AGENTS/repo/project/invariant acknowledgement text to the operator; contaminated captured model output is replaced by Windows read-only fallback. The mutation refusal text is ASCII-safe for Windows console encodings and remains non-mutating.

The top-level `ask` path follows the same Windows routing rules as interactive mode. Windows host hints override Docker/container framing, and contaminated AGENTS/repo/project/invariant model text is rejected before stdout. Acceptance transcripts must include Windows-aware, unavailable/skipped metric, and safe Windows follow-up markers.

### Windows authenticated evidence-to-model acceptance (PR289 fix)

Product model readiness honors the same tester-scoped `CODEX_HOME` context that direct `codex.CMD login status` uses: when `CODEX_HOME` is present, `sfai model doctor` verifies readiness via safe `codex login status` (exit 0 plus `Logged in using ChatGPT` on stdout or stderr) instead of the profile-default auth-cache path, reports `codex_home_configured` / `login_status_checked` / `login_status_ok` / `login_status_source=codex_login_status` / `auth_cache_contents_inspected=false`, never reports `missing_auth_cache` solely because the QGA/SYSTEM profile lacks the cache, and the `--live-probe` lane no longer skips as `not_configured` when login status is proven. Codex model calls inherit the process environment, so the same `CODEX_HOME` governs model-assisted synthesis. On Windows the model prompt is sent to `codex exec` over stdin (documented `-` prompt argument) instead of as a `.CMD` argv element, avoiding the cmd.exe 8191-character command-line limit and `%`/`!` expansion mangling that previously wedged authenticated model calls into timeouts; POSIX invocation is unchanged. Timeouts stay bounded and precise (`codex timed out after <N>s`), timed-out children are signalled via their own Windows process group before terminate/kill so nothing lingers, and the live-probe budget is 60 seconds. The Windows QA lane proves the authenticated model-assisted evidence path with `scripts/windows_authenticated_model_acceptance.py`; a fallback/model-unavailable or timed-out answer reports `model_assisted_answer_ran=false` and `fallback_used=true`, and never passes authenticated acceptance. The helper accepts a tester-scoped `CODEX_HOME` via `--codex-home <path>` (or respects the pre-existing environment variable) and uses the SAME process environment for both the `codex login status` check and the model-assisted `What is running on this system?` run, so login is proven in the process context that actually produced the answer. Login is accepted only on exit 0 with `Logged in using ChatGPT` on stdout or stderr; auth-cache/token contents are never read, copied, printed, archived, or parsed, and no user-specific `CODEX_HOME` path is hardcoded in product code (the product Codex provider simply inherits the process environment). The model-assisted step never runs when login is not proven. The summary is strict and evidence-aware: the final answer is compared with the same structured Windows evidence packet used for the run, so available process facts (total count, bounded/returned count, bounded names, collection marker, or explicit limitation) and available service facts (total/running/stopped counts, bounded names, collection marker, or explicit limitation) must be represented concretely; when both categories are available, both must be grounded. Thin evidence can pass the grounding side only when the answer names the missing category and gives the matching safe command, while generic process/service wording, safe commands with no evidence summary, invented facts, one-category-only answers, deterministic-fallback/model-unavailable output, preamble, metadata-primary output, and Docker/container-first framing never count as a model-assisted pass. `targeted_tests_ok` is based on the pytest exit code plus reliable completion evidence (quiet dot progress/`[100%]` counts; no brittle literal `passed` requirement), and `validation_status` is PASS only when auth, evidence, context, grounding, and tests are all proven. The product interactive/ask Windows paths persist the exact packet passed into model context as `windows-evidence-context.json` in the established artifact flow for lane verification. Saved-artifact mode runs nothing; the opt-in `--live` lane runs exactly two fixed argv commands with no shell, no PowerShell, no WinRM/remoting, and no mutation.

### Windows interactive evidence-context parity (PR289)

Fallthrough model-backed prompts on a Windows host (for example `What is running on this system?`) now carry a bounded read-only Windows evidence packet into the model context instead of being answered by phrase-keyed canned handlers. The shared builder (`shellforgeai.core.windows_evidence_context`) reuses only the existing read-only payloads — status, memory (PR287), disks, processes, services — plus explicit limitations (load average unavailable, inodes unavailable, Linux-only collectors skipped), `read_only: true`, and `mutation_performed: false`; each component fails soft into an explicit limitation. Model output for these prompts is captured before stdout and gated: project/policy preamble, AGENTS.md leakage, provider-metadata-primary answers, and Docker/container-first framing are replaced by a deterministic evidence-grounded Windows answer, with the raw rejected text kept only in the existing `model-response.md` audit artifact. Thin packets are stated honestly ("I do not have process/service detail in this evidence packet") with the safe read-only commands that fill the gap. The builder and gate add no new collection surface and execute no shell, PowerShell, WinRM/remoting, subprocess, service control, process termination, or mutation.
