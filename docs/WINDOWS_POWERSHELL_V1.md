# Windows/PowerShell V1

Windows is validated preview/early support; Linux/Docker remains the released V1 core. Windows operator paths use the same evidence-backed guidance contract: platform routing, bounded local typed collectors, provenance, deterministic assessment, optional grounded synthesis, operator-ready procedures, non-executing recommendation validation, and report/handoff.

The Windows confirm-gated runtime-reconciliation utility remains a bounded governed compatibility/testing surface outside the primary recommended workflow. Its existing identity, plan, current-state, containment, confirmation, verification, and receipt requirements remain unchanged.

## Status

Windows support is preview/early support. It provides local, read-only evidence commands, deterministic operator guidance, and validated Windows Server 2025 workflows without changing ShellForgeAI's overall product maturity: V1 released; early beta-quality; guarded and not production-autonomous. Linux/Docker remains the primary V1 lane.

## Operator outcomes

The validated Windows preview helps operators identify the local host and runtime
context, review bounded OS, service, process, disk, memory, network, volume, and
System event metadata, rank visible signals deterministically, and prepare an
evidence-backed procedure and handoff. Optional model synthesis remains grounded
in collected evidence and advisory.

## Validation and support basis

Windows Server 2025 is the validated preview environment. Support is local-first
and read-only, with structured platform diagnostics whenever a requested evidence
lane is unavailable. Linux/Docker remains the released V1 core and release-
validation basis.

## Current evidence coverage

Current Windows commands provide bounded local coverage for:

- platform, OS, architecture, Python, PowerShell availability, and execution-policy context;
- host and session basics that omit secrets, tokens, credential stores, and auth caches;
- service state and bounded runtime signals;
- process identity summaries without command lines, environments, or process control;
- disk, physical-memory, network-interface, and volume-capacity evidence; and
- bounded System event metadata.

Collectors return explicit unavailable states instead of fabricating Linux data
or silently switching platform lanes. Evidence and provenance remain authoritative;
deterministic assessment precedes optional evidence-grounded model synthesis.

## Current command surface

```bash
shellforgeai platform doctor --json
shellforgeai windows doctor --json
shellforgeai windows status --json
shellforgeai windows evidence --json
shellforgeai windows evidence --json --include-services --include-disks --include-processes
shellforgeai windows services --json
shellforgeai windows disks --json
shellforgeai windows memory --json
shellforgeai windows processes --json --limit 10
shellforgeai windows network --json
shellforgeai windows volumes --json
shellforgeai ask "It is 2AM and this Windows server feels broken. What should I check first?"
```

The ask path collects typed local Windows evidence first, then produces safe
operator guidance. Platform detection keeps Linux/Docker and Windows collectors
separate and gives unavailable operational routes a structured status, detected
platform, reason, and safe diagnostic next step before any model use. Payloads
identify Windows and preserve read-only safety state, including:

```json
{
  "platform": "windows",
  "read_only": true,
  "mutation_performed": false
}
```

## Safety and operator guidance

The Windows preview is local host evidence first. Arbitrary PowerShell execution,
WinRM/PSRemoting and remote execution, service restart or mutation, registry and
execution-policy mutation, software installation, credential access, and
natural-language execution remain outside the evidence-and-guidance surface.
Recommendations cover prerequisites, operator-run steps, verification, rollback,
and recovery guidance while leaving action under operator control.

## Governed compatibility utility

The confirm-gated Windows runtime-reconciliation utility is a bounded governed
compatibility/testing and reference subsystem outside the primary recommended
workflow. It is not a general Windows mutation lane. Its exact two-file scope,
local-host requirement, accepted evidence and plan binding, containment checks,
explicit hash confirmation, fresh-state validation, verification, compensation,
and receipt contracts remain authoritative.

## Historical implementation notes

The following sections preserve implementation sequencing and detailed contracts
for the validated Windows surfaces. They are historical and technical reference,
not the current product roadmap or a future execution destination.

### Windows preview implementation sequence

The preview developed incrementally through platform detection, doctor/status and
evidence bundles, saved-artifact acceptance, services, disks, processes, memory,
network, volumes, event metadata, interactive routing, and Windows Server 2025
validation. Historical PR-specific details below remain factual records of those
additions.

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

### Windows Codex repository-trust bypass (PR291)

Three distinct trust/safety layers apply to authenticated Windows model assessments, and they must not be conflated:

- **ShellForgeAI interactive trust**: `--yes-trust` skips ShellForgeAI's own workspace trust prompt only. It does not enable shell execution, does not enable mutation, and does not bypass ShellForgeAI safety refusals.
- **Codex repository trust**: the Codex CLI rejects execution from directories it does not treat as trusted git repositories. Staged QGA/SYSTEM source directories (`C:\Tools\ShellForgeAI\src\ShellForgeAI-pr<PR>-<head>`) are exactly that case, failing with `Not inside a trusted directory and --skip-git-repo-check was not specified.` The `--skip-git-repo-check` flag bypasses only that Codex repository/git trust gate — nothing else.
- **Codex sandbox**: `--sandbox read-only` (short form `-s`) remains mandatory on every product Codex invocation, passed as a GLOBAL flag before `exec`. The repository trust bypass does not weaken sandboxing and does not authorize mutation.

The product fix is one centralized provider option: `CodexProvider(skip_git_repo_check=...)` defaults to `false` and is enabled explicitly by configuration (`model.codex_skip_git_repo_check`, default `true`, passed by `build_provider`) or by the scoped Windows Codex lane, where `skip_git_repo_check_used()` reports the effective state. The provider builds one canonical invocation on every platform (PR291 fix), with global flags strictly before the `exec` subcommand — `codex --model <model> --sandbox read-only --ask-for-approval never exec --skip-git-repo-check [--json] [--output-last-message <path>] -` — with the prompt over stdin on Windows. The installed Windows Codex CLI (v0.137.0) rejects global options after `exec` (`error: unexpected argument '--ask-for-approval' found`), so `--model`, long-form `--sandbox`, and `--ask-for-approval never` always precede `exec`, and only exec-scoped flags (`--skip-git-repo-check`, `--output-last-message`) follow it; a parse rejection classifies as `cli_argument_order`. `codex exec` is non-interactive by design, so no interactive trust prompt can appear. This scoped path covers the model doctor live probe, `ask` model-assisted assessment, interactive model-assisted assessment, and authenticated Windows model acceptance, because all of them execute through the same provider.

The Windows QA lane supplies the tester-scoped `CODEX_HOME` externally; `codex login status` is verified in the same process context, auth-cache/token contents are never inspected, and staged source paths may require the scoped git-repo-check bypass. Failure reporting is bounded and sanitized: every provider result carries `codex_exec_attempted`, `codex_exec_exit_code`, `codex_exec_timed_out`, `codex_exec_error_class` (`repository_trust`, `timeout`, `binary_resolution`, `auth`, `model`), `codex_exec_error_message`, a control-character-sanitized `codex_exec_stderr_excerpt` (max 400 chars, token lines redacted), `codex_binary`, `sandbox_mode`, and `skip_git_repo_check_used`. `model doctor --live-probe --json` surfaces `sandbox_mode` and `skip_git_repo_check_used` and keeps the failure class precise — a repository-trust rejection is never collapsed into missing authentication. The Windows `ask` fallback prints `Model failure class: <class>` and writes `model-failure-diagnostics.json` into the established artifact flow, and `scripts/windows_authenticated_model_acceptance.py` reports the same bounded diagnostics in its summary. Windows targeted test selection is deterministic (PR291 fix): the maintained Windows runner launches processes without a shell (ProcessStartInfo), so a literal `tests/test_pr291_*.py` wildcard reaches pytest unexpanded and pytest exits 4 with `file or directory not found` — a selection failure, not a product test failure. The acceptance helper now resolves the targeted set with Python filesystem APIs (`resolve_targeted_test_files`: `test_pr291_*.py` expanded via `pathlib.Path.glob` plus the explicit `test_codex_provider.py`, sorted, duplicates removed) and can run it directly with explicit file paths via `--run-targeted-tests` (argv list, no shell) or print the resolved list via `--print-targeted-tests` for external runners. The summary reports `targeted_test_files_resolved`, `targeted_test_file_count`, `targeted_pytest_exit_code`, and `targeted_test_selection_error`; an empty resolution is a clear selection error that never reports `targeted_tests_ok=true`, and a saved output showing the literal-wildcard pytest signature is classified as a selection error so the cause is explicit. Execution detection in `scripts/windows_interactive_acceptance.py` is negation-scope-aware AND console-wrap-aware (PR291 fix): physical transcript lines are first rejoined into logical statements (a line continues when it lacks terminal punctuation and either ends with a list cue — comma/`or`/`and`/`/` — or the next line starts lowercase; bullet/status lines never merge), so an explicit "no <list> was executed/performed" statement keeps governing its comma list even when the console wrapped the sentence and the continuation line reads `recovery was executed.` in isolation. The list may contain arbitrary comma/or/slash-separated noun phrases (the live transcript's `no shell, subprocess, PowerShell, WinRM, service change, process termination, cleanup, remediation, rollback, or recovery was executed`), while scope-breaking conjunctions/verbs keep sentences like "no issues found, but cleanup was executed" unsafe; structured safety fields take precedence (`recovery_executed=false`/`mutation_performed=false` stay clean; `recovery_executed=true` or `mutation_performed=true` fail regardless of surrounding prose), and positive execution wording still fails. Command start success is never treated as response capture (PR291 fix): the provider requests `--output-last-message` for deterministic final-response capture, reads it only after exit, and reports `codex_command_built`/`codex_command_started` separately from `model_response_captured`/`model_response_nonempty` plus a bounded sanitized `model_response_excerpt`; exit 0 with a missing capture file classifies as `output_capture_missing` and an empty file as `empty_response`. A bounded live-probe timeout after proven login keeps auth readiness verified (`live_probe_timed_out=true`, error class `model_probe_timeout`, doctor status `warning`) and is never reported as `missing_auth_cache`/`not_configured`/auth failure. Authenticated acceptance stays HOLD whenever CLI argument parsing fails, repository trust blocks execution, the model invocation times out, the captured answer is missing or empty, `model_assisted_answer_ran=false`, `fallback_used=true`, process/service grounding is missing, or project/policy preamble reaches the final answer; the trust bypass never loosens PASS criteria.

### Windows interactive evidence-context parity (PR289)

Fallthrough model-backed prompts on a Windows host (for example `What is running on this system?`) now carry a bounded read-only Windows evidence packet into the model context instead of being answered by phrase-keyed canned handlers. The shared builder (`shellforgeai.core.windows_evidence_context`) reuses only the existing read-only payloads — status, memory (PR287), disks, processes, services — plus explicit limitations (load average unavailable, inodes unavailable, Linux-only collectors skipped), `read_only: true`, and `mutation_performed: false`; each component fails soft into an explicit limitation. Model output for these prompts is captured before stdout and gated: project/policy preamble, AGENTS.md leakage, provider-metadata-primary answers, and Docker/container-first framing are replaced by a deterministic evidence-grounded Windows answer, with the raw rejected text kept only in the existing `model-response.md` audit artifact. Thin packets are stated honestly ("I do not have process/service detail in this evidence packet") with the safe read-only commands that fill the gap. The builder and gate add no new collection surface and execute no shell, PowerShell, WinRM/remoting, subprocess, service control, process termination, or mutation.

## Codex UTF-8 subprocess I/O

Windows model-assisted ask and interactive paths do not rely on PowerShell console encoding, `PYTHONUTF8`, `PYTHONIOENCODING`, or a UTF-8 system locale. ShellForgeAI explicitly uses UTF-8 at the Codex subprocess boundary for stdin, stdout, stderr, and the deterministic final-message capture file. If Codex reports invalid UTF-8 input, ShellForgeAI classifies that as a provider stdin encoding failure rather than authentication, runtime-profile, or repository-trust failure. No PowerShell, WinRM/PSRemoting, shell execution, or mutation behavior is added.

## Windows network command

`shellforgeai windows network` and `shellforgeai windows network --json` inspect local Windows network interfaces with a bounded read-only collector. The command reports deterministic interface ordering, up/down state, MTU, reported link speed, reliable duplex when available, IPv4/IPv6 addresses, and cumulative per-interface byte/packet/error/drop counters when the in-process API provides them. Output is capped at 32 interfaces and 16 IPv4/IPv6 addresses per interface; JSON includes total/returned counts plus truncation flags, and text output stays concise for operators.

The collector uses local in-process Python network interface APIs and does not execute PowerShell, WinRM/PSRemoting, shell commands, `ipconfig`, `netsh`, route commands, DNS lookups, reverse DNS, packet capture, socket/connection enumeration, remote probes, firewall inventory, or network mutation. MAC/link-layer addresses, adapter GUIDs, PNP identifiers, Wi-Fi profiles, credentials, and hardware serials are omitted. Counters are cumulative snapshots, not throughput, bandwidth, packet-loss, or internet-reachability measurements. On non-Windows hosts the command returns the established structured unsupported response and does not substitute the Linux network collector.

### Windows volumes snapshot

`shellforgeai windows volumes [--json] [--limit N]` is a standalone bounded read-only Windows local drive-root volume/filesystem command. It reuses the declared `psutil>=5.9` dependency (`disk_partitions(all=False)` and `disk_usage`) with no new dependency and no subprocess, shell, PowerShell, WinRM, registry, remote-share, directory, or file enumeration fallback. It reports only safe drive-letter roots, filesystem strings, conservative kind/access classifications, capacity values when available, aggregate skipped counts, truncation state, limitations, and safety flags. UNC paths, remote/mapped-network entries, volume GUID paths, raw identifiers, and folder-mounted volumes are skipped or sanitized; labels, serials, BitLocker, physical disks, SMART/health, mount/format/repair/resize/cleanup/recovery behavior, model calls, auth-cache reads, and aggregate evidence integration are out of scope. Non-Windows hosts return the established unsupported-platform envelope. `windows disks` remains the stdlib-only root/capacity command and is not replaced.

PR297 enriches `shellforgeai windows services [--json] [--limit N]` without adding a new command or collection path. The existing local read-only Service Control Manager enumeration (`OpenSCManagerW` enumerate rights, `EnumServicesStatusExW`, `CloseServiceHandle`) now preserves bounded runtime-state fields already present in `SERVICE_STATUS_PROCESS`: process ID, accepted-controls bitmask, Win32 and service-specific exit codes, checkpoint, wait hint, and service flags. JSON service items add `process_id`, `controls_accepted`, `controls_accepted_unknown_mask`, `win32_exit_code`, `service_specific_exit_code`, `checkpoint`, `wait_hint_ms`, `runs_in_system_process`, and ordered `runtime_signals`; `services.runtime_summary` counts these observations across the full enumerated set before item truncation. Text mode stays concise with one runtime summary line and at most ten deterministic pending/nonzero-exit-code preview rows. These are point-in-time observations only: accepted controls are reported, never executed; nonzero exit codes are not automatic failure diagnoses; a PID is reported without opening or inspecting the process; checkpoint and wait hint do not prove progress or a hang. The command still does not collect service binary paths, executable command lines, accounts, descriptions, dependencies, delayed-auto-start or trigger configuration, recovery/failure actions, security descriptors/ACLs, registry configuration, process owner/command line/environment/modules/handles, event logs, restart history, or remote service state, and it does not start, stop, restart, pause, continue, configure, or modify services. Unsupported platforms keep the structured unsupported response and do not substitute Linux collectors.

## Reference: Windows durable runtime reconciliation preflight

`scripts/windows_runtime_reconcile_preflight.py` is a standalone PR305 governed preview helper for the Windows embedded/durable runtime. It is not a product CLI command and it does not rerun Windows discovery. It consumes one or two saved PR304 `windows_runtime_integrity` packets, validates them with `scripts/windows_runtime_integrity_acceptance.py`, and requires stable identity agreement when two artifacts are supplied; the only allowed difference between the two PR304 packets is invocation context such as current working directory already allowed by the PR304 validator.

The helper requires explicit `--staged-source-root` and `--durable-runtime-root` paths and previews reconciliation for exactly two durable files:

| Staged source | Durable destination |
| --- | --- |
| `config/profiles/inspect.yaml` | `config/profiles/inspect.yaml` |
| `scripts/windows/sfai.cmd` | `bin/sfai.cmd` |

The output mode is `windows_runtime_reconcile` for recipe `windows.runtime_reconcile`. Status is deterministic: `unsupported` on non-Windows hosts, `blocked` for evidence/identity/source/destination/containment/reparse/hash/contract failures, `ready` when one or two future create/replace operations are eligible, and `no_change` when both durable files already match. Operations are ordered as the profile then wrapper and are limited to `no_change`, `create_required`, `replace_required`, or `blocked`. Each operation reports canonical source/destination paths, source and destination SHA-256 values when available, expected post-change SHA-256, reason, whether creation or replacement would be required, a same-directory backup path pattern for any future replacement, and the required post-change PR304 verification from the staged source root and from `C:\Windows\System32` with multi-artifact acceptance.

The preflight is read-only and preview-only. It never copies, creates, replaces, deletes, renames, backs up, repairs, cleans up, installs, invokes wrappers, executes PowerShell/CMD/WinRM/QGA/WMI/CIM/subprocess/shell, restarts services or processes, mutates the registry/PATH/environment/execution policy, calls a model/network, or reads secrets/auth caches. Saving a ShellForgeAI-owned metadata packet is allowed only with `--out-json`; output is deterministic and overwrite is refused. Known PR304 `~hellforgeai*` invalid-distribution residue remains a deferred warning only and never creates an operation or blocks `ready`/`no_change`.

The separate governed execute reference retains explicit operator confirmation, saved-preflight validation, unchanged evidence/source/destination rechecks, same-directory backup before replacement, atomic replacement, post-copy hash verification, receipt creation, and post-change PR304 runs from both the staged root and `C:\Windows\System32` accepted together.

Manual validation examples:

```bash
python scripts/windows_runtime_reconcile_preflight.py pr304-source.json pr304-system32.json --staged-source-root C:/ShellForgeAI --durable-runtime-root C:/ShellForgeAI-Runtime --out-json pr305-reconcile.json --json
python scripts/windows_runtime_reconcile_acceptance.py pr305-reconcile.json --json
```

## Reference: Windows durable runtime reconciliation execute lane (PR313)

`scripts/windows_runtime_reconcile_execute.py` completes the deliberately deferred PR305 apply lane for exactly one named capability, `windows.runtime_reconcile`. It is the authoritative direct entry point and is invoked with a known exact Python interpreter and an exact source checkout, so repairing the durable wrapper never depends on the durable wrapper. The testable core lives in `src/shellforgeai/core/windows_runtime_reconcile_execution.py`; no product CLI command, `copy`, `repair`, or `apply-files` surface is added, and natural language never reaches this lane.

### Exact scope

Only these two fixed mappings are reachable, in this order:

| Staged source | Durable destination |
| --- | --- |
| `config/profiles/inspect.yaml` | `config/profiles/inspect.yaml` |
| `scripts/windows/sfai.cmd` | `bin/sfai.cmd` |

The left side is relative to the explicit staged source root and the right side is relative to the explicit durable runtime root. There is no user-defined mapping, prefix match, glob, directory recursion, alias, `shellforgeai.cmd` reconciliation, package file, residue file, or backup cleanup. This is a local Windows file-integrity repair lane, not a generic file copier, launcher generator, release activator, package installer, cleanup lane, remote-administration facility, or autonomous remediation system.

### Required input

1. One saved PR305 `windows_runtime_reconcile` packet that passes `scripts/windows_runtime_reconcile_acceptance.py`, with status `ready` or `no_change`.
2. One or two freshly generated PR304 `windows_runtime_integrity` artifacts that pass `scripts/windows_runtime_integrity_acceptance.py`, compared for stable identity when two are supplied.
3. Explicit `--staged-source-root` and `--durable-runtime-root`, both absolute and both normalizing to the roots recorded in the accepted plan.
4. `--confirm-plan-sha256` matching the accepted plan exactly.
5. `--data-dir` naming a ShellForgeAI-owned receipt/data root.
6. A local Windows host.

```bash
python scripts/windows_runtime_reconcile_execute.py pr305-reconcile.json pr304-staged.json pr304-system32.json --staged-source-root C:/ShellForgeAI --durable-runtime-root C:/ShellForgeAI-Runtime --confirm-plan-sha256 <64-lowercase-hex> --data-dir C:/ShellForgeAI-Data --json
```

### Canonical plan-hash confirmation

The confirmation identity is the SHA-256 of the deterministic canonical JSON of the loaded packet object (`json.dumps(packet, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` encoded as UTF-8). It must be exactly 64 lowercase hexadecimal characters and is compared in constant time. Changing any packet field changes the required confirmation. The raw packet file SHA-256 is also recorded in the receipt, but confirmation binds the canonical packet hash.

This confirmation is recipe-specific authorization only. It is not a PR309 `ApprovalAttestation`, not portable approval, not authenticated enterprise identity, not approval of any other plan, and not approval of future drift. Natural-language confirmation, `--yes`, bare booleans, arbitrary mapping/destination/operation arguments, and wildcard paths are all refused. A missing or mismatched confirmation causes zero destination mutation, zero backup creation, zero temporary files, no execution receipt, and deterministic blocked output.

### Fresh revalidation and safe narrowing

The saved plan is an authorization ceiling and a historical claim, never an instruction to overwrite blindly. Before any preparation the executor revalidates the saved packet, revalidates each fresh PR304 artifact, requires the explicit roots to match the accepted plan, re-evaluates both files through the maintained PR305 planner, and rehashes every source and destination.

- A saved `create_required` or `replace_required` narrows safely to `no_change` when the current destination is a safe regular file whose SHA-256 already equals the current validated source.
- A saved `create_required` executes when the destination is still absent, and blocks the whole transaction when a conflicting destination appeared.
- A saved `replace_required` executes when the destination still carries the recorded `existing_destination_sha256`, and blocks when it disappeared or changed to a third hash.
- A saved `no_change` stays a no-op and never becomes a mutation; it blocks if the destination drifted or disappeared.
- Any staged source hash drift from the accepted plan blocks the whole transaction.

If either allowlisted operation is blocked or stale, the entire execution is blocked: the other file is not mutated, no backup or temporary replacement file is created, and the deterministic reason requires fresh PR304 evidence and a new PR305 plan.

### Source and containment gates

`inspect.yaml` must be the exact allowlisted path, a regular file with no reparse point, symlink, or junction anywhere in its path chain, contained under the staged source root, matching the accepted plan's source SHA-256, at most 1 MiB, readable as UTF-8 or UTF-8 with BOM, safe-parsable YAML with no custom object construction, and valid against the maintained inspect profile contract. `sfai.cmd` must meet the same path, containment, reparse, and hash rules, be at most 256 KiB, and carry every maintained PR304 canonical-wrapper semantic marker. Source bytes are never normalized or rewritten; only exact validated bytes are copied.

Each destination must resolve beneath the durable runtime root, have an already-existing exact parent directory, and be either absent or a regular file. No directory is created outside the existing exact parent. Windows path comparison is case-insensitive, and there is no recursive glob, `rglob`, parent-tree search, home search, drive enumeration, PATH search, or arbitrary root discovery.

### All-prepared-before-commit, backups, and atomic replacement

No destination mutation begins until every gate for both files has passed. Each eligible replacement first gets one verified same-directory backup created exclusively (`O_CREAT | O_EXCL`), flushed and `fsync`ed, hash-verified against the pre-change destination, and named from the destination file name plus a stable ShellForgeAI marker, a UTC timestamp, the short canonical plan hash, and a collision suffix when required. Each eligible create or replace then gets a same-directory temporary file created exclusively, written with the exact validated source bytes, flushed, `fsync`ed, and hash-verified. Only after every required backup and temporary file is verified are operations committed in exact allowlist order with `os.replace()`, and each committed destination is hash-verified immediately.

There is no direct destination write, append, in-place edit, shell copy, PowerShell, `cmd.exe`, `robocopy`, `xcopy`, or subprocess anywhere in this lane. A create is refused if its destination appeared between preparation and commit; only the execution-owned temporary file is removed.

### Bounded same-run compensation

If a failure occurs after one or more commits, PR313 runs transaction-local compensation only. A committed replacement is restored only from the verified backup created by this execution, using a same-directory temporary restore, atomic replacement, and post-restore hash verification. A committed create is removed only when it did not exist at validated pre-state, its current hash still equals the expected source hash, and it is the exact allowlisted destination; a drifted created file is never deleted and the incomplete recovery is reported honestly. Compensation may touch only files committed by this exact execution. It is not a general rollback command, and a successful commit followed later by a post-verification failure never triggers automatic restoration: backups are retained and the verification failure is reported.

Execution statuses are `executed`, `partial_executed`, `no_change`, `verification_failed`, `failed_compensated`, `failed_compensation_incomplete`, `blocked`, and `unsupported`.

### Receipts, verification, and idempotence

Every confirmed execution that reaches current-state evaluation writes a ShellForgeAI-owned, non-overwriting receipt bundle (`windows-runtime-reconcile-receipt.json`, `windows-runtime-reconcile-receipt.md`, `manifest.json`) under `<data-dir>/windows_runtime_reconcile_receipts/<receipt-id>/`. Blocked-before-confirmation paths and non-Windows hosts write no receipt at all. Validate a saved bundle with:

```bash
python scripts/windows_runtime_reconcile_receipt_acceptance.py <receipt-id> --data-dir C:/ShellForgeAI-Data --json
```

Post-change verification is read-only and performs no repair or rollback:

```bash
python scripts/windows_runtime_reconcile_verify.py <receipt-id> --staged-pr304 pr304-post-staged.json --system32-pr304 pr304-post-system32.json --staged-source-root C:/ShellForgeAI --durable-runtime-root C:/ShellForgeAI-Runtime --data-dir C:/ShellForgeAI-Data --json
```

The verifier validates the receipt bundle, validates both fresh PR304 artifacts, compares stable identity, requires the staged artifact to come from the staged source context and the System32 artifact to report a `C:\Windows\System32` invocation context, requires runtime/profile resolution, durable wrapper existence, semantic markers, canonical match, and exact source/import identity, rehashes both durable destinations, and requires them to equal the receipt's expected post-change hashes. Statuses are `verified`, `verification_failed`, `blocked`, and `unsupported`. It saves an artifact only with an explicit `--out-json` and refuses to overwrite.

The PR312 V1 quick and standard checks from real `C:\Windows\System32` remain required host acceptance and are run separately by the operator through the exact installed executable. The executor never invokes V1 through an internal shell or subprocess.

After a successful execution, a second run with a newly generated and confirmed compliant plan produces status `no_change`, zero mutation, no backup, no temporary replacement, `mutation_performed=false`, and a valid no-op receipt. A stale plan is never silently replayed.

### Privacy posture

Receipts and logs record only fixed relative paths, hashes, counts, stable classifications, root fingerprints, bounded sanitized error class/message strings, and backup paths relative to the durable runtime root. They never record file contents, wrapper text, YAML contents, environment dumps, process environment, credentials, secrets, tokens, auth-cache data, or sensitive absolute staged/durable paths. The receipt validator rejects any receipt that carries content, environment, credential, or absolute-path fields.

### Deferred

Packaging the five V1 resources into wheel/install artifacts, installed-release activation and current-release lifecycle, durable launcher lifecycle beyond exact `sfai.cmd` reconciliation, `shellforgeai.cmd` reconciliation, post-success operator-triggered rollback, backup retention/pruning, metadata or package-residue cleanup, package install/update/uninstall, service restart or reboot, registry/policy changes, remote execution, additional Windows files, broader mutation recipes, and PR309 approval-workflow integration all remain out of scope for later PRs.

### Exact destination-parent contract (contract version 1)

A normally installed Windows runtime can lack `config\profiles` entirely. PR313 therefore carries a fixed destination-parent contract so a confirmed `create_required` operation for `config/profiles/inspect.yaml` can create the exact missing parent chain — and nothing else.

| Destination | Fixed parent | Creation |
| --- | --- | --- |
| `config/profiles/inspect.yaml` | `config/profiles` | allowed, only the exact `config` then `config/profiles` components |
| `scripts/windows/sfai.cmd` → `bin/sfai.cmd` | `bin` | never created; a missing or unsafe `bin` is a blocking runtime-layout failure |

The durable runtime root itself must already exist as an absolute, safe, non-reparse directory that matches the accepted plan. PR313 never creates it, never infers it, and never discovers it through PATH, home search, drive enumeration, globbing, or parent walking. There is no generic `mkdir`, installer, bootstrapper, directory-repair, or runtime-layout command, and no caller-supplied directory is reachable.

Every PR305 operation now carries deterministic `destination_parent` metadata — contract version, exact relative parent path, current state (`present`, `create_required`, or `blocked`), whether creation is allowed, the exact ordered missing relative directories, and sanitized blockers — plus `parent_present`, `parent_create_required`, and `parent_blocked` summary counts and a top-level `destination_parent_contract_version`. The packet is `blocked` when the durable root is missing or unsafe, when the `config` chain holds a conflicting file or a reparse point, when the chain escapes the durable root, when `bin` is missing or unsafe, or when parent metadata contradicts the fixed contract.

Because the metadata lives inside the packet, it is inside the canonical JSON and therefore inside `--confirm-plan-sha256`. Any change to parent state, creation permission, creation chain, blocker, relative path, or contract version changes the required confirmation. A plan generated before this contract has no `destination_parent_contract_version` and is refused outright — it is never silently upgraded. A plan that previously blocked on a missing parent must be regenerated, revalidated, and re-confirmed.

Saved parent metadata is an authorization ceiling. Immediately before preparation the exact chain is revalidated: a saved `present` parent must still be a safe directory or the whole transaction blocks; a saved `create_required` chain may narrow to the still-missing exact suffix, or narrow to no parent action when every component appeared safely, but it can never grow, move, or reach outside the fixed contract. Any parent blocker for either file blocks the entire transaction before any directory creation, backup, temporary file, atomic replacement, or file mutation.

Authorized directories are created one exact component at a time with `os.mkdir` — never `parents=True`, `os.makedirs` over caller-supplied paths, a shell, PowerShell, `cmd.exe`, a subprocess, or any recursive filesystem operation. Before each component the safe prefix, absence, containment, and reparse state are rechecked; after each component existence, directory-ness, and non-reparse state are verified and the exact relative directory is recorded as owned by this execution. A benign race is accepted only when the directory appeared as the exact safe directory expected.

Directory creation happens after every gate for both files has passed and before backups and temporary files, preserving all-prepared-before-file-commit ordering. On any preparation, commit, hash-verification, or compensation failure, file compensation runs first and then directories created by this exact execution are removed in reverse order — only when they are authorized, still directories, non-reparse, under the durable root, and empty. Pre-existing directories are never removed, non-empty directories are never removed, nothing is ever removed recursively, and incomplete compensation is reported honestly. After a successful execution the created `config` / `config/profiles` directories are retained as intended durable runtime state; a later post-verification failure never removes them.

Receipts record only fixed relative directory information — contract version, relative parent path, saved and revalidated state, saved and revalidated chains, created, compensated, and retained relative directories, preparation and compensation results, and sanitized blockers. The receipt validator rejects absolute created-directory paths, arbitrary or extra directories, reordered chains, anything outside `config` / `config/profiles`, creation metadata for `bin`, contradictory state and safety flags, directory creation on no-op/unsupported/blocked states, and tampered parent metadata or checksums. The safety ledger gains `parent_directory_create_executed` and `parent_directory_compensation_executed`; `cleanup_executed`, `rollback_executed`, and `recovery_executed` stay false, because removing this execution's own empty directories is transaction compensation, not a cleanup lane.

The read-only verifier additionally confirms every retained execution-created directory still exists as a safe non-reparse directory under the durable root. It never creates, repairs, or removes a directory.

Manual directory creation is not the supported solution: `config` and `config/profiles` must be created only as the exact confirmed PR313 parent action.
