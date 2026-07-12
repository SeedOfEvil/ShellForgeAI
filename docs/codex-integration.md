# Codex integration (current + future)

## Current architecture (provider mode)

- ShellForgeAI calls the Codex CLI as a model/provider for analysis text
  generation.
- ShellForgeAI's typed tools and collectors are executed by the
  ShellForgeAI runtime — never by Codex.
- Therefore ShellForgeAI must collect context first for known intents
  before sending prompts.

## Why context-first routing is required

Naming a collector inside a prompt is not equivalent to giving the model
tool access. Without runtime collection (or an exposed tool interface) the
model cannot reliably execute those collectors.

## Immediate approach

- Runtime intent routing + context bundles for `disk`, `performance`,
  `health`, `firewall`, and service diagnostics.
- Already-collected evidence is included in the prompt.
- Arbitrary shell stays blocked.
- Mutation stays blocked or approval-required.
- `apply` is validation-only in this alpha.
- Model subprocesses must use bounded timeouts and explicit cleanup/reaping;
  failures/timeouts should return safely without hanging the REPL.

## Future optional approach (experimental, disabled by default)

Proposed command: `shellforgeai mcp serve --readonly`.

Proposed read-only MCP tools:

- `shellforgeai_health`
- `shellforgeai_diagnose_disk`
- `shellforgeai_diagnose_performance`
- `shellforgeai_diagnose_firewall`
- `shellforgeai_diagnose_service`
- `shellforgeai_audit_recent`

Mutating tools are explicitly excluded from the initial MCP surface.

## Adaptive read-only follow-ups

Natural-language diagnostics may queue an evidence-driven deeper read-only
follow-up (CPU/process, memory/swap, storage/IO, network/DNS, service
health, or a general context pass). Confirm with `yes`, `proceed`, `dig
deeper`, `y`, or `run it`. Normal answers hide internal collector names;
technical names remain in `/tools` and debug/raw views. Safety unchanged:
no arbitrary shell, no destructive execution, `apply` validation-only.


## Model doctor explicit probe

Codex remains a synthesis provider, not a ShellForgeAI tool executor. Default
`shellforgeai model doctor` does not call Codex or the network. The explicit
`--live-probe` flag performs one fixed, bounded readiness/auth probe through the
existing provider path, with no operator-provided prompt text, no tool execution,
and no mutation.

## Tester-scoped CODEX_HOME readiness (PR289)

When a `CODEX_HOME` environment variable is present in the process (for
example a QA lane running as a service account whose profile does not own the
Codex auth state), provider readiness no longer depends on the
profile-default `~/.codex/auth.json` path. Instead, `model doctor` and
`CodexProvider.available()` verify readiness with a safe command-level check:
the resolved Codex CLI is run with `login status` in the inherited process
environment, and login is proven only by exit code 0 plus
`Logged in using ChatGPT` on stdout or stderr. Doctor output reports
`codex_home_configured`, `login_status_checked`, `login_status_ok`,
`login_status_source=codex_login_status`, `codex_resolved_binary`, and
`auth_cache_contents_inspected=false`; readiness is `verified_login_status`
when proven and `login_status_not_proven` otherwise, never
`missing_auth_cache` solely because the current profile lacks the cache. The
`--live-probe` lane treats proven login status as configured credentials.
`CODEX_HOME` is only inherited by Codex CLI child processes — ShellForgeAI
never hardcodes a user-specific value and never reads, copies, prints,
archives, or parses auth-cache/token contents. Without `CODEX_HOME`, the
existing default-profile behavior is unchanged. Codex model calls
(`codex exec`) already inherit the process environment, so the same
tester-scoped `CODEX_HOME` governs model-assisted synthesis.

## Windows Codex invocation (PR289)

On Windows the Codex CLI is a `.CMD` batch wrapper, so CreateProcess routes
`codex exec` through `cmd.exe`. A multi-kilobyte evidence prompt passed as an
argv element there hits the cmd.exe 8191-character command-line limit and its
`%`/`!`/metacharacter expansion rules, which can mangle or wedge the exec call
even though short invocations like `codex login status` work — the observed
symptom was an authenticated model call that only ever timed out. Since PR289,
Windows invocations send the prompt over stdin using the documented `-`
prompt argument, keeping the command line tiny and the prompt byte-exact;
POSIX/Linux invocation is unchanged (prompt in argv, stdin closed). Timeouts
remain bounded and precise (`codex timed out after <N>s`), a timed-out child
is signalled via its own Windows process group before terminate/kill so no
codex process lingers, and the `model doctor --live-probe` budget is 60
seconds — a realistic single model roundtrip, still never indefinite. A
timed-out invocation is reported as a failure and keeps the authenticated
Windows acceptance lane HOLD; it is never hidden as success.

## Windows Codex repository trust (PR291)

Codex separately gates execution on repository trust: it refuses `codex exec`
from a directory it does not treat as a trusted git repository, failing with
`Not inside a trusted directory and --skip-git-repo-check was not specified.`
Staged Windows QGA/SYSTEM source directories
(`C:\Tools\ShellForgeAI\src\ShellForgeAI-pr<PR>-<head>`) are exactly that
case, so authenticated read-only Windows model assessments could fail even
with proven login and collected evidence. This is distinct from
ShellForgeAI's interactive workspace trust (`--yes-trust` skips only
ShellForgeAI's own prompt) and from the Codex sandbox (`--sandbox read-only`, short form `-s`, stays
mandatory; the trust bypass does not weaken sandboxing or authorize
mutation).

The fix is one centralized provider option: `CodexProvider`'s
`skip_git_repo_check` defaults to `false` and is enabled explicitly by
configuration (`model.codex_skip_git_repo_check`, default `true`) or by the
scoped Windows Codex lane; `skip_git_repo_check_used()` reports the
effective state and appears in doctor/live-probe output. The bypass is
exec-scoped and never weakens the sandbox or the approval policy.

## Codex CLI argument ordering (PR291 fix)

The Codex CLI separates global options from `exec`-scoped options, and the
installed CLIs (codex 0.130.0 on Linux/Docker, codex 0.137.0 on the Windows
QA lane) reject global options placed after the subcommand with
`error: unexpected argument '--ask-for-approval' found`. The provider builds
one canonical invocation on every platform, in explicit sections —
executable, global options, `exec`, exec-scoped options, prompt:

`codex --model <model> --sandbox read-only --ask-for-approval never exec
--skip-git-repo-check [--json] [--output-last-message <path>] <prompt|->`

- `--model`, long-form `--sandbox`, and `--ask-for-approval` are GLOBAL
  flags: they must appear before `exec` and are never emitted after it.
- `--skip-git-repo-check` and `--output-last-message` are exec-scoped flags:
  they follow `exec`.
- `--sandbox read-only` and `--ask-for-approval never` are always present.
- On Windows the prompt travels over stdin (`-`); that is the only
  platform-specific difference. The previously-verified short form
  `exec -s read-only --skip-git-repo-check` also parses on the installed
  Windows CLI, but the product emits only the canonical global form so the
  ordering contract stays testable in one place.

A CLI parse rejection classifies as `cli_argument_order` — never as a model
or auth failure — with a bounded stderr excerpt retained.

## Deterministic final-response capture (PR291 fix)

Command parse/start success is NOT the same as a captured model response.
Every provider invocation requests `--output-last-message <path>` under a
bounded temp flow, reads the file only after the process ends (or during the
bounded timeout cleanup, before the temp directory is removed), and reports
the distinction explicitly in `ModelResponse.metadata`:
`codex_command_built`/`codex_command_started` track the launch;
`codex_process_completed` tracks whether the child finished inside the
bounded timeout; `codex_child_cleanup_performed` records timeout cleanup;
`output_last_message_path`/`output_file_created` describe the capture file;
`stdin_prompt_sent`/`stdin_closed` describe the stdin prompt lifecycle; and
`model_response_captured` is true only when the capture file held a
non-empty final response, with `model_response_nonempty` and a bounded
sanitized `model_response_excerpt` (240 chars). Exit code 0 with a missing
capture file classifies as `output_capture_missing`; an empty capture file
classifies as `empty_response`; both fail the invocation and keep
authenticated acceptance HOLD. A capture produced before a timeout is
reported honestly (`output_file_created=true`, `model_response_captured=true`
with `codex_exec_timed_out=true`, `codex_process_completed=false`) so the
failure is explainable — but a timeout is never hidden and never converted
into success: authenticated PASS still requires `codex_exec_timed_out=false`
and exit code 0.

A bounded model-response timeout is a live-probe/invocation outcome, not an
authentication failure: when `codex login status` was already proven in the
same process context, `model doctor --live-probe` keeps auth readiness
verified, reports `live_probe_timed_out=true` with error class
`model_probe_timeout`, and the overall doctor status is `warning` — never
`missing_auth_cache`, `not_configured`, or `auth_readiness=failed`.

Failure reporting is bounded and sanitized: every `ModelResponse.metadata`
carries `codex_command_built`, `codex_command_started`,
`codex_exec_attempted`/`model_call_attempted`, `codex_exec_exit_code`,
`codex_exec_timed_out`, `codex_exec_error_class` (`cli_argument_order`,
`repository_trust`, `timeout`, `binary_resolution`,
`output_capture_missing`, `empty_response`, `auth`, `model`),
`codex_exec_error_message`, `codex_exec_stderr_excerpt` (max 400 chars,
control characters sanitized, token-like lines redacted),
`output_last_message_requested`, `model_response_captured`,
`model_response_nonempty`, `model_response_excerpt`, `codex_binary`,
`sandbox_mode`, `approval_policy`, and `skip_git_repo_check_used`. A
repository-trust rejection classifies as `repository_trust` — never as
missing authentication — and keeps the authenticated Windows acceptance
lane HOLD until a real model-assisted answer is captured without fallback.

## Windows runtime-root parity

On Windows installed deployments, Codex-backed `ask`, `interactive`, and `model doctor` share the same ShellForgeAI runtime/profile context. The official `sfai.cmd` wrapper derives `SHELLFORGEAI_RUNTIME_ROOT` from its own `bin` directory and product code uses that bounded root before considering the current working directory. This lets normal operator sessions launched outside the source tree still collect Windows evidence and pass it to Codex when tester-scoped `CODEX_HOME` authentication is available. Missing `CODEX_HOME`, unverified login status, repository trust, and probe timeout remain distinct bounded diagnostics.

## Codex subprocess UTF-8 boundary

ShellForgeAI sends Codex prompts over stdin using explicit UTF-8 text-mode subprocess I/O (`encoding="utf-8"`, `errors="replace"`) and captures stdout/stderr with the same explicit encoding. The deterministic `--output-last-message` response file is read as UTF-8. This avoids Windows ANSI-code-page or console-locale dependence and does not require operators to set `PYTHONUTF8`, `PYTHONIOENCODING`, or `chcp 65001`. Diagnostics record safe encoding names and prompt counts, not prompt contents, auth-cache contents, tokens, or environment dumps.
