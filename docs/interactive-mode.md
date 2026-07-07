# Interactive mode

Running `shellforgeai` (or `sfai`) with no subcommand launches the operator
REPL. The same loop is available explicitly as `shellforgeai interactive`.

## Banner

The banner shows version + build line, mode/profile, model provider/model,
and workspace path. Build metadata env vars: `SHELLFORGEAI_BUILD_PR`,
`SHELLFORGEAI_BUILD_COMMIT`, `SHELLFORGEAI_BUILD_BRANCH`,
`SHELLFORGEAI_BUILD_DATE`.

## Workspace trust

On first run in a workspace you are asked to trust it. Trust is cached under
the data dir; pass `--no-trust-cache` to re-prompt. Trust grants reads of
workspace docs and writes to the audit/artifact dir under the data dir. It
does **not** lift policy or enable mutation.

## Slash commands

Deterministic. Unknown slash commands never call the model.

```
Session
  /help              Show help
  /exit, /quit       Exit
  /clear             Clear screen

Status
  /status            Runtime summary
  /doctor            ShellForgeAI health
  /health            Machine health checks
  /model             Model provider status
  /workspace         Workspace trust/status
  /mode              Current mode
  /profile           Active profile

Evidence
  /tools             List typed tools (technical names)
  /audit             Latest audit entries
  /evidence          Latest evidence bundle
  /pending           Inspect queued read-only follow-up
  /summary           Local session handoff summary (use --json or --save)

Ops
  diagnose <target>  Collect evidence and diagnose
  research <query>   Search local knowledge
  plan <goal>        Conservative read-only plan
  ask <question>     Ask the configured model

Debug
  /raw on|off        Toggle raw provider events
  /context <mode>    Set context mode: minimal | standard | full
  /examples          Example queries
```

## Routing

- Slash commands are deterministic.
- `diagnose ...`, `research ...`, `plan ...`, `ask ...` are explicit.
- Free-form text is classified. Recognized ops intents (disk, performance,
  health, firewall, service, service-discovery) auto-run typed read-only
  collectors before any model call.
- Sluggish/laggy symptoms route to performance diagnostics rather than a
  generic ask. Since PR279 this route is platform-aware: on Windows it skips
  Linux-only collectors (`uptime`, `df`, `ip`, `ss`, `ps`, `systemctl`,
  `/proc` and `/etc/resolv.conf` reads), records them as structured
  `linux_only_collector_skipped` evidence, marks missing metrics as
  unavailable instead of rendering `loadavg=None` or fake `0.0GiB/0.0GiB`
  memory, and renders a bounded read-only Windows summary that points at
  `shellforgeai windows status --json` and
  `shellforgeai windows processes --json --limit 10`. No PowerShell or
  WinRM is used and the route stays non-mutating.
- Service and service-health questions (e.g., nginx/ssh/docker status, restart requests, listening ports) route to read-only service investigation evidence before synthesis.
- Log/error questions (e.g. "any errors?", "check logs", "why is nginx
  failing?", "ssh login failing", "permission denied") route to read-only
  log investigation. Requests to delete, truncate, or rotate logs are
  refused; ShellForgeAI collects read-only log evidence instead.
- Container failure questions (e.g. "why is the app restarting?", "why
  did the container exit?", "is anything crashing?", "what containers
  are failing?", "show container logs", "restart loop", "crash loop",
  including typos like "restaring", "crasing") route to the read-only
  Docker investigation: `docker.containers`, `docker.inspect`, bounded
  `docker.container_logs`, and `docker.problem_summary`. No mutating
  Docker commands are ever issued.
- Triage prompts and safe command-style entries (`triage`, `triage --brief`,
  `triage --json`, `triage --target <target>`, `triage --target <target>
  --json`, "what is the likely suspect?", "what is broken?", "what should I
  inspect first?") route to the V2 read-only triage entrypoint. The response
  ranks suspects, shows the first safe inspection command, and does not call
  the model or run mutation.
- The Docker compatibility forms `triage docker`, `triage docker --brief`,
  `triage docker --json`, and `triage docker detail <target>` are also
  supported. `triage docker --brief` is a safe alias that mirrors the bounded
  `triage --brief` view, so the brief shape is identical regardless of which
  entrypoint you type.
- Brief-style triage asks ("quick triage", "no novel, triage") render the
  bounded read-only triage view; mutation phrasings tied to triage ("restart
  the top suspect", "fix the top suspect", "docker compose restart") are
  refused with no action taken.
- Proposal entries (`propose`, `propose --brief`, `propose --json`,
  `propose --target <target>`, `propose --target <target> --json`, and
  `propose --from-triage`) route to the V2 read-only proposal preview. Natural
  proposal prompts such as "what would you propose?" route deterministically to
  the same read-only preview; mixed prompts like "show me the proposal and
  restart it" show/refers to the preview and refuse the mutation part.
- Apply-preview entries (`apply-preview`, `apply-preview --brief`,
  `apply-preview --json`, `apply-preview --target <target>`, and
  `apply-preview --from-propose`) route to the V2 read-only execution-boundary
  preview.
- Verify entries (`verify`, `verify --brief`, `verify --json`,
  `verify --target <target>`, `verify --from-status`, `verify --from-triage`,
  `verify --from-propose`, `verify --from-apply-preview`,
  `verify --receipt <receipt_id>`, and `verify --receipt <receipt_id> --json`)
  route to the V2 read-only verification entrypoint. Natural verify prompts
  such as "verify status", "verify the system", "did anything improve?", and
  "is it fixed?" verify current observed state only; they do not claim a
  completed remediation. Receipt prompts such as "verify receipt <id>" show the
  safe receipt verification command. Mixed mutation phrasing such as "verify and
  restart", "retry the receipt", or "rollback it" is refused with no action
  taken. Example:

  ```text
  > verify --receipt <receipt_id>
  > verify --receipt <receipt_id> --json
  > recipes receipt verify <receipt_id> --json
  > recipes receipt rollback-preview <receipt_id> --json
  ```
- Handoff entries (`handoff`, `handoff --brief`, `handoff --json`,
  `handoff --save`, `handoff summary`, `handoff --target <target>`, and
  `handoff --from-status` / `--from-triage` / `--from-propose` /
  `--from-apply-preview` / `--from-verify`) route to the V2 read-only operator
  handoff packet. Natural handoff prompts such as "give me a handoff", "give me
  the operator handoff", "handoff summary", "what should I tell the next
  operator?", "what do I hand over?", and "make a shift handoff" produce the
  same read-only handoff. `handoff --save` writes only a ShellForgeAI-owned
  artifact under `<data_dir>/v2_handoffs/`. Mixed mutation phrasing such as
  "handoff and restart", "handoff then apply", "summarize and fix it", or "give
  me a handoff and restart compose" is refused with no action taken; the handoff
  itself never executes fixes or implies remediation happened.
- Handoff artifact lifecycle entries route through the safe interactive
  allowlist: `handoff --save`, `handoff validate <ref>`,
  `handoff export <ref>`, and `handoff export-validate <ref>` (each accepts a
  trailing `--json`) dispatch to the read-only handoff lifecycle. Save/export
  write only ShellForgeAI-owned artifacts; validate/export-validate are
  read-only. Natural prompts mentioning "validate handoff" or "export handoff"
  show the read-only handoff plus safe lifecycle command guidance and never
  mutate. Example session:

  ```text
  > handoff --save
  > handoff validate <handoff_id>
  > handoff export <handoff_id>
  > handoff export-validate <export_id>
  ```

- Handoff history/compare entries also route through the safe allowlist:
  `handoff history`, `handoff history --limit 5`, `handoff compare <before>
  <after>`, and `handoff compare-latest` (each accepts a trailing `--json`)
  dispatch to the strictly read-only history/compare workflow. Natural prompts
  such as "show handoff history", "compare latest handoffs", and "what changed
  since last handoff?" route deterministically to the read-only history /
  compare-latest guidance without a model fallback or mutation. Example session:

  ```text
  > handoff history
  > handoff compare-latest
  > handoff compare <before_id> <after_id>
  ```


## Interactive help

Type `help`, `/help`, `?`, `commands`, or `what can I do?` inside the REPL to
show a short operator help screen. The help lists exact interactive-supported
forms for fast status (`status`, `status --brief`, `status --json`, `ops report --brief`, `v1 check quick`, `doctor`),
V2 verification (`verify`, `verify --json`, `verify --target <target>`),
V2 handoff (`handoff`, `handoff --json`, `handoff --save`, `handoff summary`),
Docker triage (`triage docker detail <target>`), reports/artifacts (`ops report
history --limit 5`, `ops report compare-latest`), safe remediation readiness
(`remediation eligibility --target <target> --explain`), and session follow-ups
(`what happened in this session?`, `what did you find?`, `get that info`, `dig deeper`, `pending`, `summary`, `exit`).

The help also has a refused-here section for mutation-shaped examples such as
Docker/Compose restart, cleanup execute, remediation execute, rollback execute,
and `rm -rf /`. Those examples are shown only as not-run/refused examples.
Interactive mode is not a shell; no Docker/Compose/remediation/cleanup command
runs from natural language, and mutation requires governed explicit workflows.


## Session handoff summary

Run `summary` or `/summary` before exiting interactive mode to get a concise
local handoff for the current REPL session. Natural-language aliases such as
`session summary`, `what happened in this session?`, `what did you check?`,
`what did you find?`, `what did you refuse?`, and `what should I hand off?`
route to the same deterministic summary.

The summary is generated from session-local metadata only: safe commands handled,
latest diagnosis/ops-report context, known artifact paths, top Docker suspects,
refusals, visibility caveats, and the first safe next command. It does **not**
call the model, does **not** run collectors again, and does **not** execute shell,
Docker/Compose, cleanup, remediation, rollback, or restart commands.

Example:

```text
sfai> status
sfai> status --json
sfai> ops report --brief
sfai> /summary
Session summary: read-only inspection session.

What was checked:
- ops report

First safe next command:
  shellforgeai ops report --json

Safety:
- No cleanup/remediation/rollback/Compose mutation executed.
- No arbitrary shell executed.
- Natural-language mutation remained blocked.
```

For automation or copy/paste into another tool, use `summary --json` or
`/summary --json`. It emits strict JSON only and uses the same local in-memory
session state.

To create a portable handoff artifact, use `/summary --save` or
`/summary --save --json`. Saving writes only ShellForgeAI-owned files under
`<data_dir>/interactive_summaries/<summary_id>/`:

- `interactive-summary.json`
- `interactive-summary.md`
- `manifest.json`

The human save output prints the summary id/path and only suggests read-only
handoff commands:

```text
sfai> /summary --save
Session summary saved:
  id: interactive_summary_<timestamp>_<suffix>
  path: <data_dir>/interactive_summaries/interactive_summary_<timestamp>_<suffix>

Next safe commands:
  shellforgeai session summary validate <id>
  shellforgeai session summary export <id>
```

Validate/export saved summaries outside the REPL with:

```text
shellforgeai session summary validate <summary_id_or_path> [--json]
shellforgeai session summary export <summary_id_or_path> [--json]
shellforgeai session summary export-validate <export_id_or_path> [--json]
shellforgeai session summary compare-export <before_export_id_or_path> <after_export_id_or_path> [--json]
shellforgeai session summary compare-export <before_export> <after_export> --include-stable
shellforgeai session summary compare-export <before_export> <after_export> --only-changed
```

Validation checks required files, JSON/schema, checksums, non-mutating safety
flags, and obvious secret-shaped artifact fields. Export copies the saved
summary into `<data_dir>/exports/export_interactive_summary_<summary_id>/` with
an `export-manifest.json`; repeated exports reuse an already-valid export.
`compare-export` validates two exported handoff bundles, compares their embedded
summary payloads, and reports changed or stable checks, findings, refusals, safe
next commands, artifact references, metadata, and safety flags. It is read-only
and does not write a comparison artifact.

Saved summaries also support read-only history and comparison commands for
follow-up handoffs over time:

```text
shellforgeai interactive
sfai> /summary --save
shellforgeai session summary history --limit 5
shellforgeai session summary history --json
shellforgeai session summary compare <before_summary_id_or_path> <after_summary_id_or_path>
shellforgeai session summary compare <before> <after> --only-changed --json
shellforgeai session summary compare <before> <after> --include-stable
shellforgeai session summary compare-latest
shellforgeai session summary compare-latest --json
```

History lists saved summary ids, timestamps, event/check/finding/refusal counts,
the first safe next command, and artifact paths. Compare reads two already-saved
summary artifacts, validates them, and reports changes in events, checks,
findings, refusals, safe next commands, artifact references, runtime visibility,
and safety flags. `compare-latest` compares the newest two saved summaries and
returns controlled `empty` / `not_enough_data` output when there are fewer than
two. These commands are artifact-read-only: they do not collect new evidence,
call the model, execute shell commands, run cleanup/remediation/rollback, or
mutate Docker/Compose state.

## Safe command-style dispatch

Interactive mode accepts a focused allowlist of ShellForgeAI CLI-style inputs
without requiring a leading slash. These are dispatched only to ShellForgeAI-owned
read-only or safety/readiness handlers:

- `version`, `doctor`, `model doctor`
- `v1 check quick|standard|full` and `v1 check --profile quick|standard|full [--json]`
- `status`, `status --brief`, and `status --json` for the V2 read-only golden-path entrypoint.
- `ops report`, `ops report --brief`, `ops report --json`, `ops report --save`, `ops report history`, `ops report history --limit 5`, `ops report compare-latest`, and `ops report compare-latest --json`
  - Pressure phrases such as `no novel`, `quick status`, and `what is on fire, keep it short` dispatch to the same read-only brief status / ops report shape.
- `triage`, `triage --brief`, `triage --json`, and `triage --target <target>` for the V2 read-only triage entrypoint.
- `propose`, `propose --brief`, `propose --json`, `propose --target <target>`, `propose --target <target> --json`, and `propose --from-triage` for the V2 read-only next-action proposal preview.
- `apply-preview`, `apply-preview --brief`, `apply-preview --json`, `apply-preview --target <target>`, `apply-preview --target <target> --json`, and `apply-preview --from-propose` for the V2 read-only execution-boundary preview.
- `triage docker`, `triage docker --brief` (safe alias for `triage --brief`), `triage docker --json`, `triage docker detail <target>`, and `triage docker detail <target> --json`
- `diagnose <target>` through the existing read-only diagnose route
- `remediation self-test quick|standard|full` and `remediation self-test --profile quick|standard|full [--json]`
- `remediation eligibility --target <target> --explain [--json]`
- `recipes [--json]`, `recipes list [--json]`, `recipes inspect <recipe_id> [--json]`, `recipes eligibility --recipe <recipe_id> --target <target> [--json]`, and `safe-actions [--target <target>] [--json]` for the read-only governed recipe registry and safe-action eligibility map.
- `pending`/`/pending`, `help`/`/help`, `exit`/`/exit`

Recipe and safe-action commands never execute recipes; interactive mutation phrases such as `execute recipe`, `run restart recipe`, and `restart it now` are refused.

Mistyped ShellForgeAI command-like input does not execute and does not call the
model. If a close safe allowlisted command exists, interactive mode prints
`Unknown command`, `No action was taken.`, a short `Did you mean:` list, and
`Type help for supported commands.` Suggestions are never auto-run; copy and run
one only if it is the read-only ShellForgeAI command you intended.

Unknown conversational text still falls back to the existing safe ask/routing
path. Shell-like or mutation-shaped inputs such as Docker/Compose restart, `rm`,
`sudo`, `apply`, cleanup execute, remediation execute, rollback execute /
rollback-execute, production restart, `chmod`, `chown`, or mission execute are
refused with no command execution and no action taken. JSON flags on supported
safe forms print the underlying command JSON without an extra human wrapper.

## Mistyped commands

Interactive mode gives deterministic guidance for near-miss ShellForgeAI
commands such as `ops reprot`, `triage dockre`, or `v1 chek quick`. The REPL
prints that the command is unknown, confirms that no action was taken, and lists
only safe allowlisted ShellForgeAI suggestions. Suggestions are advisory only;
ShellForgeAI never autocorrects and runs a typo.

Dangerous or shell-shaped input still refuses instead of suggesting a raw shell
command. Interactive mode is not a shell, and it does not run Docker/Compose,
cleanup, remediation, rollback, restart, or arbitrary host commands from typed
input or natural language.

## Streaming synthesis

After collection, the REPL shows a synthesis status and streams the model
answer when the provider supports it. Normal answers hide internal
collector names; technical names remain in `/tools`, `/evidence`, and
debug/raw output.

## Friendly mini-report style

Natural-language answers favor short calm sections (`## Assessment`,
`## What I found`, `## Best read`, `## Safe next step`) over bullet dumps
or repeated safety boilerplate. The on-disk `summary.md` mirrors that
shape — verdict, key evidence, findings, and an artifacts list that only
references files actually written.

The "Collected N read-only evidence item(s)" line, the `Evidence: N` line
in the diagnose footer, and the `Evidence count` line inside `summary.md`
are taken from the same persisted `evidence.json` so the numbers always
agree.

The polite `what did you check?` answer mentions the categories inspected
and only the artifact files that exist on disk for the current session.
Use `what tools did you use?` to see the raw collector names.

## Adaptive read-only follow-ups

When the evidence suggests a deeper read-only pass is useful (CPU/process,
memory/swap, storage/IO, network/DNS, service health, or a general context
pass), the REPL queues it. Confirm with `yes`, `proceed`, `dig deeper`,
`y`, or `run it`. Inspect the queue with `/pending`. If nothing is queued,
a confirmation phrase prints a helpful "no pending" message instead of
calling the model. Follow-ups are read-only.

## Latest-evidence follow-ups (PR122)

After a diagnosis or evidence-producing command (for example `diagnose
performance`, a "the system feels slow" performance pass, a firewall or
machine-health check, or a service check), the REPL remembers a compact,
read-only snapshot of the latest diagnosis: target, diagnosis kind,
artifact/evidence/summary paths, evidence highlights, limitations, and
safe read-only next commands.

Interactive follow-up questions then reuse that latest context instead of
answering from generic kernel/libc/workspace context. Examples:

- `what did you find?` / `summarize the latest diagnosis` / `show the latest evidence`
- `why is it slow?`
- `is it running normally?`
- `what does this system do?`
- `what should I check next?`
- `where are the artifacts?`
- `what were the limitations?`

Answers are concise and evidence-backed, state limitations (for example
"container-limited view"), and list safe read-only next commands. They do
not run new collectors and never invent a system role beyond what the
evidence supports.

If no evidence has been collected yet, the REPL says so plainly and
suggests read-only commands (`diagnose performance`, `diagnose disk`,
`shellforgeai ops report`) instead of hallucinating findings.

`/pending` also surfaces this latest diagnosis context (timestamp, target,
diagnosis kind, artifact/evidence/summary paths, suggested follow-up
categories, and safe next commands) when there is no formal pending
investigation. A formal pending follow-up still takes precedence.

The REPL also keeps a small session-local grounding snapshot for the latest
known target/top suspect, target kind, intent, evidence/artifact paths, safe
next command, and safe read-only action. Rank/pronoun references such as
`the first one`, `top suspect`, `that one`, `that container`, `what about it?`,
and `show me details` resolve only when there is one clear latest target (for
example the top suspect from `ops report` or a target from `triage docker
detail <target>`). Ambiguous references ask for clarification or show safe
choices instead of picking a target.

Mutation-style follow-ups (`fix it`, `restart it`, `run that`) are never
executed from latest context. If a target is unambiguous, the refusal names it
(for example, "I’m not restarting sfai-crashloop from natural language"),
states that no action was taken, and suggests read-only triage detail /
remediation eligibility explanation.

## Interactive mode is not a shell

Interactive mode routes known ShellForgeAI read-only commands and deterministic
read-only operator asks. It is **not a shell**: typed text is never executed as a
shell command, and no command runs from arbitrary or natural-language input.

Shell-shaped input is refused with explicit wording — "Interactive mode is not a
shell.", "No command was executed.", "No action was taken." — plus safe read-only
alternatives. Refused categories include:

- arbitrary shell commands and shell command invocations
  (`touch ...`, `rm ...`, `mv ...`, `cp ...`, `chmod ...`, `chown ...`);
- arbitrary file reads (`cat /etc/passwd`, `cat ~/.ssh/id_rsa`);
- Docker/Compose mutation (`docker restart ...`, `docker compose restart ...`,
  `docker compose up`, `docker compose down`, `docker volume prune`);
- cleanup / remediation / rollback / recovery execution;
- network/download commands (`curl ...`, `wget ...`);
- package installs (`apt install ...`, `pip install ...`);
- cloud / VCS / orchestration mutation (`git push`, `gh pr merge`,
  `codex apply`, `kubectl apply`);
- shell metacharacters / pipelines / redirections (`|`, `>`, `>>`, `&&`, `;`,
  command substitution);
- natural-language mutation requests.

Real fixes only run through governed, named recipes with explicit confirmation.

`uname -a` and other bare host-evidence shell invocations are refused as
not-a-shell: interactive mode cannot guarantee a non-shell evidence path for a
raw `uname` invocation, so it answers with the not-a-shell refusal rather than
executing anything. Use the ShellForgeAI read-only evidence surfaces instead
(`status`, `ops report`, `diagnose health`).

Legitimate ShellForgeAI subcommands with flags/arguments (for example
`triage docker --json`, `ops report --json`, `verify --target <target>`) keep
working and are not blocked by this policy.

## Paste guard

The REPL is not a shell. Pasted shell-looking input is blocked unless
prefixed with `ask explain ...` or `ask review ...`. After a multi-line
shell paste, a short-lived quarantine blocks follow-on shell fragments
without calling the model; `/help` and `/exit` continue to work.

## Safety

- No destructive execution.
- No package install or service restart.
- `apply` is validation-only.
- Model output is advisory.
- In restricted containers the Codex CLI may emit `bwrap`/namespace
  errors; that is a provider sandbox limitation, not a host failure, and
  the typed read-only tools keep working.

- Disk-space breakdown queries (e.g., "what is using disk space?") trigger bounded `disk.top_dirs` read-only collection.

Deterministic findings are severity-aware (`critical`, `warning`, `info`, `limitation`). Container-only gaps (for example missing `systemctl`/`journalctl` in Docker) are reported as limitations, not direct faults.


Service inventory follow-ups (`proceed`/`dig deeper` after service-discovery questions) run listener/process/service-manager evidence collection, not a generic health-only pass.


Action-style service requests (for example `restart <service>`) trigger an immediate read-only service check first, then return a safety boundary response (no mutation execution).


For service action follow-ups, ShellForgeAI preserves the detected target service (for example nginx or shellforgeai) so `dig deeper` stays target-specific rather than generic inventory-only.


If a queued follow-up times out or fails, ShellForgeAI reports the failure safely, keeps the REPL alive, and `/pending` remains readable with last error state.


## Runtime hygiene notes

- `/pending` is local/state-only and does not call model providers or collectors.
- Follow-up timeouts and interruptions are handled safely; the REPL remains usable and returns to `sfai>`.
- Exiting the REPL (`/exit` or Ctrl-D) performs ShellForgeAI-owned model subprocess cleanup.


Pending network follow-ups preserve the original target context. When a
user asks a network question — for example `can this server reach
example.com:443?`, `can you open port 443?`, or `check DNS for
example.com` — the queued follow-up records `type=network`, the detected
`subtype` (`reachability`, `port-open`, `listener`, `dns`, `firewall`),
and any `target_host`, `target_port`, or `target_domain` parsed from the
question. `/pending` displays this target alongside the label, and
`proceed` runs a target-specific read-only deep dive that reuses the same
host/port/domain instead of a generic network pass.

## Governed recipe preflight in interactive mode

Interactive mode accepts the same read-only governed recipe preflight forms as the CLI dispatcher:

```text
recipes preflight --recipe docker.disposable_restart --target sfai-test
recipes preflight --recipe docker.disposable_restart --target sfai-test --json
recipes preflight --recipe docker.disposable_restart --target sfai-test --save
recipes preflight validate <preflight_id>
recipes preflight validate <preflight_id> --json
preflight restart sfai-test
preflight docker restart sfai-test
```

These routes build or validate preflight packets only. Dangerous phrases such as `execute the recipe`, `restart it now`, and `run docker restart` are refused by interactive mode; no Docker/Compose/remediation/cleanup/rollback command is executed.

## Governed recipe execution in interactive mode

Interactive mode may dispatch the explicit CLI form `recipes execute <preflight_id> --confirm [--json]`, `recipes receipt validate <receipt_id> [--json]`, and `recipes receipt rollback-preview <receipt_id> [--json]`. Rollback-preview is read-only and only explains receipt rollback/recovery posture; it does not rollback or restart anything. Natural-language mutation phrases such as "execute the recipe", "restart it now", "rollback now", "execute rollback", "run that", or "do it" are refused and show the governed workflow instead. Interactive mode is still not a shell and does not run raw Docker, Docker Compose, cleanup, remediation, rollback, or arbitrary commands from natural language.

## Governed receipt recovery in interactive mode

Interactive mode supports the exact command-form `recipes receipt recovery-execute <receipt_id> --confirm [--json]` and read-only `recipes receipt recovery-status <recovery_receipt_id>` / `recipes receipt recovery-validate <recovery_receipt_id>`. Natural-language recovery requests such as “recover it now”, “rollback now”, and “restart it again” remain refused. Recovery for `docker.disposable_restart` is a bounded repeat exact-target disposable restart, not true rollback, and still requires the same receipt validation, current target labels, non-production gate, argv-list Docker restart, recovery receipt, and verification.


## Recipe receipt audit commands

Interactive mode accepts exact read-only receipt audit commands through the safe CLI dispatcher:

```text
recipes receipt audit [--json]
recipes receipt audit --target <target>
recipes receipt audit --recipe docker.disposable_restart
recipes receipt audit --limit 10 [--json]
recipes receipt integrity [--json]
recipes receipt integrity --target <target>
recipes receipt integrity --recipe docker.disposable_restart
recipes receipt integrity --limit 10
recipes receipt integrity --include-exports
recipes receipt integrity --include-audit-bundles
recipes receipt history [--json]
recipes receipt history --limit 10 [--json]
recipes receipt inspect <receipt_ref> [--json]
recipes receipt export <receipt_ref> [--json]
recipes receipt export-validate <export_ref> [--json]
recipes receipt compare <a> <b> [--json|--only-changed]
recipes receipt compare-latest [--json]
```

Natural-language audit phrasing such as `audit recipe receipts`, `show disposable restart audit`, `what happened with the restart recipe?`, `summarize recovery receipts`, and `show receipt chain` routes to read-only audit guidance. Natural-language receipt mutation remains refused. Phrases such as `recover latest receipt now`, `rollback latest receipt`, `restart it again`, `rerun the receipt`, `rerun the last receipt`, `recover it again`, `execute the last recipe`, `rollback the last recovery`, `restart from the receipt`, `apply the receipt`, and `cleanup old receipts` do not execute recovery, rollback, restart, cleanup, remediation, shell, Docker, Compose, or model-driven actions.


### Governed receipt integrity scan

Interactive mode accepts exact `recipes receipt integrity` commands through the safe CLI dispatcher. The scan is read-only and checks existing ShellForgeAI-owned receipts for required files, JSON parseability, manifest/checksum drift, recovery original linkage, supported shapes, unsafe safety flags, and production restart records. `--include-exports` and `--include-audit-bundles` scan existing owned export and audit-bundle artifacts only; they do not create bundles or exports. Natural-language mutation phrases such as “rerun receipt”, “cleanup old receipts”, “delete bad artifacts”, or “fix corrupt receipts” remain refused. Support-handoff wording that clearly mentions receipts, audit, or recipe receipts routes to receipt audit-bundle guidance instead of generic handoff.

### Governed receipt audit bundles

Interactive mode allows exact command dispatch for `recipes receipt audit-bundle`, `recipes receipt audit-bundle --json`, filtered bundle creation (`--target`, `--recipe`, `--limit`), and `recipes receipt audit-bundle-validate <bundle_ref> [--json]`. These commands package or validate existing ShellForgeAI-owned receipt audit/history artifacts only. They do not execute recipes, rerun receipts, recover, rollback, restart containers, run Docker/Compose, call the model, or authorize natural-language mutation. Mutation phrases such as “rerun receipt”, “recover it again”, “rollback now”, or “restart from receipt” remain refused.
## Governed receipt finding explanation

`shellforgeai recipes receipt explain` is a deterministic, local, read-only explanation surface for governed receipt audit, integrity, audit-bundle, and compare findings. It reads existing ShellForgeAI-owned receipt/audit/integrity artifacts and maps known finding codes (for example `checksum_mismatch`, `missing_original_receipt`, `safety_drift`, and `production_restart_recorded`) to operator-facing meaning, impact, and safe next commands.

Command forms:

```bash
shellforgeai recipes receipt explain
shellforgeai recipes receipt explain --json
shellforgeai recipes receipt explain --source integrity
shellforgeai recipes receipt explain --source audit
shellforgeai recipes receipt explain --source audit-bundle
shellforgeai recipes receipt explain --source compare
shellforgeai recipes receipt explain --finding checksum_mismatch
shellforgeai recipes receipt explain --target <target>
shellforgeai recipes receipt explain --recipe docker.disposable_restart
shellforgeai recipes receipt explain --limit 20
```

Supported categories include malformed JSON, missing required files/manifests/checksums, checksum mismatch, unsupported artifacts/receipts, missing original receipts, verification failure, safety drift, production restart records, Docker Compose/shell/arbitrary-command/natural-language execution records, receipt export and audit-bundle validation failures, and compare categories such as status/target/recipe/action/safety-flag changes. Unknown finding codes return controlled `unknown_finding` guidance instead of a traceback.

`recipes receipt explain` never repairs, deletes, cleans up, recovers, rolls back, restarts, reruns receipts, calls Docker/Compose, executes shell, creates exports/bundles, or calls a model. Safe next commands are limited to read-only receipt integrity/audit/history/inspect/validate/compare/verify surfaces. Ask and interactive phrasing such as “explain receipt integrity findings”, “what does checksum_mismatch mean?”, and “what should I do about safety drift?” routes to this explanation guidance; mutation phrasing such as “explain and fix corrupt receipts” refuses the mutation part. Support-handoff phrasing that clearly mentions receipt audit or recipe receipts routes to receipt audit-bundle guidance.


## Implementation note: command-module split (PR200)

The top-level `interactive` launcher is registered from
`src/shellforgeai/commands/interactive.py` as part of the behavior-preserving
CLI command-module split. The launcher is Typer wiring only: it resolves the
runtime context and hands off to the existing
`shellforgeai.interactive.start_interactive` REPL, which was not moved or
redesigned. The interactive command surface is unchanged
(`interactive --help`, `--no-trust-cache`, `--yes-trust`, startup/exit
behavior). Interactive mode remains not-a-shell: deterministic read-only
routing is unchanged, broad/freeform mutation phrases stay refused, and natural
language never executes governed fixes. The root callback's no-subcommand
interactive fallback intentionally stays in `cli.py`. Future CLI refactors
should keep running the PR184 command-surface golden guardrail.

## Windows read-only phrases

Interactive mode deterministically recognizes explicit Windows read-only phrases such as `show me the windows status`, `windows doctor`, `windows evidence`, and `windows processes limit 10`. These phrases only render allowlisted safe command guidance and set `/pending` to a `windows-local-read-only` context with Windows safe-next commands. They do not execute shell commands, PowerShell, WinRM/PSRemoting, subprocesses, Docker/Compose, cleanup, remediation, rollback, recovery, or mutation, and broad natural-language execution remains out of scope.

### Windows operator-parity prompts

When the active context is Windows local read-only, interactive mode answers common operator prompts with Windows-native guidance instead of repo/project acknowledgements or Docker/container framing. Generic latency prompts get a first-pass Windows diagnosis from bounded read-only evidence; CPU/memory/disk/process comparison prompts explicitly compare the available categories, state when load average or memory summaries are unavailable, and identify the strongest available signal or say that no single strong signal was found. Current-host handoff prompts render a Windows host handoff with local visibility, evidence summary, limitations, and safe next checks.

Safe Windows next checks are:

```text
sfai.cmd windows status --json
sfai.cmd windows doctor --json
sfai.cmd windows evidence --json
sfai.cmd windows processes --json --limit 10
sfai.cmd windows disks --json
sfai.cmd windows services --json --limit 25
```

Interactive mode is not a shell. Natural-language cleanup, restart, service-control, process-control, rollback, recovery, or remediation requests are refused; the refusal states that no command/action was executed and offers read-only alternatives. These routes do not execute PowerShell, WinRM/PSRemoting, subprocesses, shell commands, Docker/Compose mutation, cleanup, remediation, rollback, recovery, service restart, or process termination.

Transcript acceptance for Windows interactive smoke logs is negation-aware: statements such as `No cleanup was performed.`, `No cleanup was executed.`, `No rollback/recovery was executed.`, and `No command was executed.` are treated as safe refusal evidence, while true execution statements such as `cleanup executed` or `service restart executed` still fail validation.

Windows latency/slow/status/next-check/handoff paths either route deterministically or capture model output before operator stdout. Captured AGENTS/repo/project/invariant acknowledgements are written only to audit artifacts when applicable and are replaced on stdout with deterministic Windows read-only summaries. Windows mutation-refusal text is ASCII-safe for legacy consoles and continues to state that no command/action was executed.

Windows ask and interactive routing share the same operator-first rules: explicit Windows host hints such as `Windows host` or `WIN2025-SFAI01` select Windows-native read-only output before Docker triage or model fallback. `show me the windows status`, app-latency, strongest-signal, next-check, and handoff prompts print the status/diagnosis/guidance itself, not just provider metadata or artifact links.
