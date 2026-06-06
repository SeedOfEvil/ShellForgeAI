# OPS

## V2 2AM golden path

1. `shellforgeai status` — read-only concise status; no model call and no mutation.
2. `shellforgeai triage --brief` — bounded read-only ranked suspect view with the first safe command.
3. `shellforgeai propose` — read-only next-action proposal preview; no plan created and no action executed.
4. `shellforgeai apply-preview` — read-only execution-boundary preview; no apply, mission, remediation, rollback, cleanup, Docker, Compose, or restart action executed.
5. `shellforgeai verify` — read-only current-state verification; no applied action or remediation receipt is assumed.
6. `shellforgeai handoff` — read-only operator handoff packet summarizing the golden-path posture and first safe command; it does not execute fixes or imply remediation happened. `shellforgeai handoff --save` writes only a ShellForgeAI-owned artifact under `<data_dir>/v2_handoffs/`.
   - Handoff artifact lifecycle (read-only except ShellForgeAI-owned writes):
     - `shellforgeai handoff --save` — write the handoff artifact (`<data_dir>/v2_handoffs/<handoff_id>/`).
     - `shellforgeai handoff validate <handoff_id>` — read-only validation (required files, JSON, manifest, checksums, safety, secrets).
     - `shellforgeai handoff export <handoff_id>` — copy a validated handoff into a portable export (`<data_dir>/exports/export_<handoff_id>/`); idempotent if it already exists.
     - `shellforgeai handoff export-validate <export_id>` — read-only validation of the exported bundle.
     - `shellforgeai handoff history [--limit N]` — read-only list of recent saved handoffs (latest first; empty → `shellforgeai handoff --save`).
     - `shellforgeai handoff compare <before_id> <after_id>` — read-only drift compare of two saved handoffs (status/risk/target/current_status/golden-path/first-safe-command/safe-next-commands/limitations/warnings/safety drift); `--only-changed`/`--include-stable` available.
     - `shellforgeai handoff compare-latest` — read-only compare of the two most recent saved handoffs (or `not_enough_history`).
     - Each step accepts `--json` for strict output. Missing/malformed refs fail cleanly (non-zero, no traceback). No collector rerun, model call, Docker/Compose mutation, restart, shell, or arbitrary command.
7. `shellforgeai triage docker detail <target>` — inspect one suspect without mutation.
8. `shellforgeai remediation eligibility --target <target> --explain` — explain gated readiness only.
9. `shellforgeai ops report --save` — preserve an evidence-backed report when handoff or comparison is needed.

Safe V2 path: `status -> triage -> propose -> apply-preview -> verify -> handoff`.

`shellforgeai triage` (full), `shellforgeai triage --json`, and the compatibility
`shellforgeai triage docker` / `triage docker --brief` views all share the same
read-only safety wording. When there are no suspects, the first safe command is a
read-only status/report command (`shellforgeai status --json`), never a detail
command for a missing suspect.


## V1 canonical operator path (knife, not toolbox)

## Safe compose update pattern (Docker01/lab)

Use this runbook pattern to avoid accidental compose truncation:

1. Take a Proxmox/LXC snapshot first.
2. Backup compose file: `cp compose.yml compose.yml.bak-<tag>`.
3. Write edits to a temp file (example: `compose.yml.tmp`).
4. Validate temp file is non-empty before any replace step.
5. Validate rendered config:
   `docker compose -f compose.yml.tmp config >/tmp/compose-check.yml`.
6. Only then move the temp file into place.
7. Avoid sudo/pipeline write patterns that can truncate `compose.yml` when a command fails.
8. Recreate and verify: source HEAD, compose image, container image,
   `homelab.pr` label, `homelab.commit` label, health, and restart count.
9. Keep rollback backup references until QA passes.

Safety reminders for shared lab environments:
- Do not prune volumes.
- Do not remove running containers.


Use this concise, safe path for the V1 demo and handoff contract:

1. `shellforgeai version`
2. `shellforgeai doctor`
3. `shellforgeai model doctor`
4. `shellforgeai v1 check --profile quick`
5. `shellforgeai remediation self-test --profile quick`
6. `shellforgeai status`
7. `shellforgeai triage`
8. `shellforgeai propose`
9. `shellforgeai apply-preview`
10. `shellforgeai verify`
11. `shellforgeai handoff` (read-only operator handoff; `--save` for a ShellForgeAI-owned packet)
12. `shellforgeai triage --target <target>`
13. `shellforgeai remediation eligibility --target <target> --explain`
14. `shellforgeai ops report --save`
15. `shellforgeai ops report history --limit 5`
16. `shellforgeai ops report compare-latest`
17. `shellforgeai ask "It's 2AM; what is on fire?"`
18. Pressure-mode quick status: `shellforgeai status` / `shellforgeai status --brief` or `shellforgeai ask "quick status"`
19. `shellforgeai ask "please restart shellforgeai"` (expected deterministic refusal)
20. `shellforgeai ask "show me the command to inspect sfai-crashloop"` (command-help: returns the read-only `shellforgeai triage docker detail sfai-crashloop` with `No action was taken.`; nothing is executed)
21. `shellforgeai ask "what should I tell the next operator?"` (read-only handoff routing; nothing is executed)

Safety reminder: read-only by default; no casual restart/remediation/cleanup execute in the V1 demo path. Command-help ("show me the command ...", "how would I propose ..."), apply-preview prompts ("apply preview", "show apply gates"), verify prompts ("verify status", "did anything improve?"), and handoff prompts ("give me a handoff", "what should I tell the next operator?") explain safe current state/gates/posture without running anything or assuming an apply happened; "do it" / "run that" / "handoff and restart" mutation phrasings are refused.

Operator smoke tests and runbook tips.

For V1 release promotion, run the release-candidate validation flow in
[`docs/V1_RELEASE_CANDIDATE.md`](docs/V1_RELEASE_CANDIDATE.md).
For V2 command-surface planning and anti-bloat guardrails, use
[`docs/COMMAND_SURFACE_AUDIT.md`](docs/COMMAND_SURFACE_AUDIT.md) and
[`docs/V2_COMMAND_CONTRACT.md`](docs/V2_COMMAND_CONTRACT.md).

## Current baseline / handoff

The PR78 release/handoff baseline is the current operator reference
for what ShellForgeAI can do today, what is safely gated, what is
intentionally blocked, the safe cleanup sequence, and the Compose
disposable proof posture. Start there if you are picking the tool up
after the PR56–PR77 arc:

- [`docs/release-baseline.md`](docs/release-baseline.md)


## What can ShellForgeAI safely do next?

Use the governed recipe registry before thinking about fixes:

```bash
shellforgeai recipes list
shellforgeai recipes inspect docker.disposable_restart
shellforgeai recipes eligibility --recipe docker.disposable_restart --target <target>
shellforgeai safe-actions --target <target>
```

Interpretation:

- `available_read_only` recipes are safe reports/previews operators can run now.
- `disabled_until_execute_lane` and `disabled_until_explicit_cleanup_lane` recipes
  document future gates only; they do not execute.
- Production targets such as `shellforgeai`, broad targets such as `all`, missing
  targets, and unlabeled targets are blocked.
- If asked to restart, fix, clean up, roll back, or execute a recipe, ShellForgeAI
  must refuse and state that no action was taken.

## Interactive smoke test

```bash
shellforgeai
```

Inside the REPL:

```text
/help
/tools
/pending
my device feels a bit sluggish today
/pending
dig deeper
/pending
/exit
```

2AM handoff tip: before exiting interactive mode, run `/summary` to capture a concise local session handoff without collecting new evidence or executing commands. For a portable handoff artifact, save, validate, and export the summary without suggesting mutation:

```text
sfai> /summary --save
shellforgeai session summary validate <id>
shellforgeai session summary export <id>
shellforgeai session summary export-validate <export_id_or_path>
shellforgeai session summary compare-export <before_export_id_or_path> <after_export_id_or_path>
shellforgeai session summary history --limit 5
shellforgeai session summary compare-latest
```

For a follow-up handoff, use `shellforgeai session summary history --limit 5`
to find recent saved REPL summaries, `shellforgeai session summary
compare-latest` to compare the newest two saved summaries, or
`shellforgeai session summary compare-export <before_export> <after_export>`
to compare two already-exported handoff bundles without collecting new evidence,
calling the model, executing shell, or mutating Docker/Compose/system state.

For REPL discoverability, type `help`, `/help`, `?`, `commands`, or `what can I do?`. The help screen lists exact safe interactive forms for fast status, triage/detail, reports/artifacts, readiness checks, follow-ups, pressure-mode brief status, and refused mutation examples. Mistyped ShellForgeAI-like commands get deterministic safe suggestions that are never auto-run. It also repeats the safety boundary: interactive mode is not a shell and does not run Docker/Compose/remediation/cleanup commands from natural language.

Selected safe CLI-style commands also work directly inside the REPL, including common read-only flags such as `--profile`, `--brief`, `--json`, and `--limit` for the allowlisted commands:

```text
shellforgeai interactive
doctor
ops report
triage docker detail sfai-crashloop
remediation eligibility --target sfai-crashloop --explain
```

Canonical flagged examples for scripted demos or operator handoff:

```text
shellforgeai interactive --yes-trust
v1 check --profile quick --json
ops report --brief
triage docker detail sfai-crashloop --json
```

### Scripted / non-interactive sessions

Already-trusted workspaces are not re-prompted, so the first piped line is
treated as a command (not as a trust answer). For a fresh/untrusted
workspace in a scripted session, pass `--yes-trust` to skip the trust
prompt without weakening safety:

```text
shellforgeai interactive --yes-trust
doctor
ops report
/exit
```

`--yes-trust` only trusts the current workspace for this session and skips
the trust prompt. It does **not** grant mutation, shell execution,
Docker/Compose mutation, remediation/cleanup/rollback execution, or bypass
the paste guard or natural-language mutation refusals — those stay refused
with no action taken (e.g. `docker compose restart shellforgeai`, `rm -rf /`,
`remediation execute --confirm`). When untrusted and no flag is passed,
only `y`/`yes` grant trust; `n`/`no`/empty decline and exit safely; any
other input is an invalid trust response that reprompts with clear
guidance rather than running as a command.


Expected outcomes:
- Sluggish phrasing routes to performance diagnostics before synthesis.
- Evidence highlights stay compact in normal UX while `/tools` and debug
  views preserve technical names.
- `/pending` shows queued read-only follow-ups (or explicit none queued).
- The "Collected N read-only evidence item(s)" line, the diagnose footer
  `Evidence:` line, and `Evidence count` in `summary.md` all show the
  same number (sourced from `evidence.json`).
- `summary.md` reads as a friendly mini-report (Assessment / Key evidence
  / Findings / Artifacts / Safety note) and only references artifact
  files that actually exist on disk.

After a diagnosis, follow-up questions like `what did you find?`, `why is
it slow?`, or `is it running normally?` use the latest evidence collected
in the current interactive session (target, evidence highlights, artifact
paths, limitations, and safe next commands) instead of generic context.
With no formal pending investigation, `/pending` also surfaces that latest
diagnosis context. These follow-ups are read-only and never run new
collectors or execute mutation.
After ShellForgeAI asks for read-only evidence, short continuations like
`get that info`, `then get that info`, `do that`, `proceed`, or `dig deeper`
continue only the safe read-only path. Without a pending safe follow-up, those
phrases produce no-context guidance instead of inventing evidence. Paste-like
or mutation-shaped input is still refused and no command is executed.

The human-feel regression suite (`tests/test_pr134_human_feel_regression.py`) keeps messy pressure prompts, command-help phrasing, follow-up pronouns, paste-like snippets, and natural-language mutation refusals covered as a UX/safety guardrail. Report command-help prompts route to canonical `shellforgeai ops report` guidance.

## Apply safety check

```bash
shellforgeai apply <valid-plan-file>
```

Expected outcome: apply execution is intentionally disabled in this alpha
(validation-only parse/validate path).

For approved proposal objects:

```bash
shellforgeai apply <approved-proposal-id>
shellforgeai apply --latest-approved
shellforgeai apply --dry-run <approved-proposal-id>
```

Expected outcome: preflight passes, a static bundle is written under
`<data_dir>/apply_bundles/<id>/` (`apply-preview.md`,
`operator-commands.sh`, `rollback.sh`, `validation.md`,
`apply-preflight.json`), and no commands are executed. The shell scripts
contain an early `exit 2` and the banner "ShellForgeAI did not execute
this script." Pending, rejected, or canceled proposals fail preflight and
no operator-run scripts are written.

## Non-interactive smoke test

```bash
shellforgeai doctor
shellforgeai inspect host
shellforgeai tools list
shellforgeai diagnose disk --save-plan
shellforgeai audit list
shellforgeai audit timeline
shellforgeai ops status
```

Use `shellforgeai ops status` as the quick posture board (evidence/proposal/mission/audit/cleanup),
then follow up with explicit proposal/mission IDs; PR59 "this/latest/current"
ask-reference disambiguation remains available for read-only follow-ups.

## Restricted containers

In restricted containers, the Codex CLI may emit `bwrap`/namespace errors.
Treat that as a provider sandbox limitation, not a host failure: ShellForgeAI
still collects evidence via its typed read-only tools, and `model doctor`
will report whether `codex` is reachable. If model-assisted assessment is unavailable, run `codex login --device-auth`; deterministic diagnosis/reporting remains available.

## Safety reminders

- `apply` is validation-only.
- Service-impacting actions are described as approval-required / operator-run.
  ShellForgeAI does not execute them.
- Mutation is blocked or asks regardless of workspace trust.

- For "what is using disk space?", expect bounded top-level directory breakdown (`disk.top_dirs`) in addition to usage/inodes.

Smoke checks should confirm `storage.error_summary` outputs such as “no recent storage error patterns found” do not produce a warning finding.


## Service investigation smoke

In the REPL, run: `can you restart nginx for me?`, `/pending`, `dig deeper`, `is nginx running?`, `what services are running?`, `what ports are listening?`, `is ssh running?`, `docker status`.
Expected: read-only service evidence collection, no restart/reload/stop/start execution, and useful container-limit context when service managers are unavailable.


JSON smoke:
`shellforgeai diagnose nginx --json | python -m json.tool >/dev/null`
`shellforgeai diagnose performance --json | python -m json.tool >/dev/null`
`shellforgeai diagnose disk --json | python -m json.tool >/dev/null`


Additional service-action smoke: `can you restart shellforgeai?` should collect read-only service evidence immediately, queue pending service health, and refuse mutation execution.

Role/health smoke examples (read-only):
- `what does this system do?`
- `is it running normally?`
Expected next commands remain safe: `shellforgeai ops report`, `shellforgeai triage docker`, `shellforgeai triage docker detail <target>`, `shellforgeai remediation eligibility --target <target> --explain`.
Read the first safe command first; artifacts/details follow.


No-hang follow-up smoke: run `can you restart nginx`, `/pending`, `proceed`, `/pending`, `can you restart shellforgeai`, `/pending`, `dig deeper`, `/pending`, `/exit` and confirm prompt returns each time without session drop.

Zombie/process smoke: compare `ps -eo pid,ppid,stat,comm,args | grep -E "codex|defunct|shellforgeai" | grep -v grep || true` before/after interactive checks; no accumulating defunct children should remain.

Runtime hygiene check: `shellforgeai doctor` should report `runtime_hygiene ... init_reaper=yes` when compose is running with `init: true`.


## Targeted network follow-up smoke

In the REPL, run:

```
can this server reach example.com:443?
/pending
proceed
can you open port 443?
/pending
proceed
check DNS for example.com
/pending
proceed
```

Expected:

- `/pending` shows target context (host:port, port, or domain).
- `proceed` after a reachability question runs a target-specific deep dive
  (namespace context, default route, DNS resolver, target DNS resolution,
  bounded TCP connect to the same host:port, firewall context). It does
  not fall back to a generic network deep dive.
- `proceed` after `can you open port 443?` focuses on port 443
  (listeners, listener ownership, firewall context, container/route view)
  and does not mutate or emit unconditional firewall commands.
- `proceed` after a DNS question repeats the resolver/resolution test
  for the requested domain (or notes the safe default if no domain was
  given).
- Apply remains validation-only.


## Docker01 lab smoke (read-only logs/error/container)

A repeatable failure range exists at `/srv/lab-cases` on Docker01. The
lab cases drive container failure detection scenarios used to validate
read-only log/error/Docker triage:

- `missing-env` — exits 42, logs `REQUIRED_SETTING is missing`.
- `restart-loop` — restarting/crashing, repeated simulated crash.
- `noisy-logs` — running with WARN/ERROR noise (not a crash).
- `bad-volume-perms` — exits, read-only filesystem / permission denied.
- `bad-network` — running with DNS/reachability errors in logs.

Bring up + status:

```
sudo /srv/lab-cases/bin/lab-clean
sudo /srv/lab-cases/bin/lab-up missing-env
sudo /srv/lab-cases/bin/lab-up restart-loop
sudo /srv/lab-cases/bin/lab-up noisy-logs
sudo /srv/lab-cases/bin/lab-up bad-volume-perms
sudo /srv/lab-cases/bin/lab-up bad-network
sudo /srv/lab-cases/bin/lab-status
```

ShellForgeAI checks (all read-only):

```
sudo docker compose exec -T shellforgeai shellforgeai diagnose docker --save-plan
sudo docker compose exec -T shellforgeai shellforgeai diagnose logs --save-plan
sudo docker compose exec -T shellforgeai shellforgeai diagnose errors --save-plan
sudo docker compose exec -T shellforgeai shellforgeai diagnose "is anything crashing?" --save-plan
sudo docker compose exec -T shellforgeai shellforgeai diagnose "why did the container exit?" --save-plan
sudo docker compose exec -T shellforgeai shellforgeai diagnose "find recent logs and errors" --save-plan
```

Expected findings:

- missing-env: warning — exited with code 42 + missing required setting.
- restart-loop: critical — restart loop / repeated simulated crash.
- noisy-logs: info — running but logs contain noise (not crashed).
- bad-volume-perms: warning — exited with write/permission failure.
- bad-network: warning — running with DNS/reachability errors in logs.

Network/log ask smoke (PR28):

```
sudo docker compose exec -T shellforgeai shellforgeai ask "network reachability is broken"
sudo docker compose exec -T shellforgeai shellforgeai ask "why is bad-network failing?"
sudo docker compose exec -T shellforgeai shellforgeai ask "DNS errors in logs"
sudo docker compose exec -T shellforgeai shellforgeai ask "app cannot reach upstream"
```

Expected: the answer mentions `sfai-bad-network`, says it is running but logging
DNS/upstream/reachability errors, separates app/container failure from host-wide
network health (a healthy DNS resolver/default route does not cancel app log
evidence), and never mutates. The prompt sent to the model carries an explicit
`network_reachability_brief` block with `container_log_evidence` (per-container
themes labelled `dns_resolution` / `upstream_unreachable` / `connection_refused`
/ `timeout` / `tls_certificate`) listed before `runtime_network_basics`; when
the question names a lab case (e.g. `bad-network`) the targeted container is
pinned to the front of `container_log_evidence` and is never truncated out.
Mutation-style asks ("fix the network", "open port 443", "change DNS") collect
read-only evidence and emit a safety boundary; `apply` remains validation-only.

Operator runbook smoke (PR30):

```
sudo docker compose exec -T shellforgeai shellforgeai diagnose docker --save-plan --with-runbook
sudo docker compose exec -T shellforgeai shellforgeai runbook --latest
sudo docker compose exec -T shellforgeai shellforgeai validate-runbook --latest
sudo docker compose exec -T shellforgeai shellforgeai ask "give me a safe fix plan for the failed containers"
sudo docker compose exec -T shellforgeai shellforgeai ask "fix bad-network safely"
sudo docker compose exec -T shellforgeai shellforgeai ask "fix write permissions safely"
sudo docker compose exec -T shellforgeai shellforgeai ask "fix missing env safely"
sudo docker compose exec -T shellforgeai shellforgeai ask "what should I do next?"
```

Expected: a `runbook.md` (and `runbook.json`) artifact is written next
to `evidence.json`. The runbook covers `sfai-missing-env`,
`sfai-bad-volume-perms`, `sfai-restart-loop`, and `sfai-bad-network`
with prechecks, operator-run options, rollback, and post-fix
validation; `sfai-noisy-logs` is recommended for investigation only and
sorted last; `sfai-healthy-web` is listed as a known-good baseline.
Every mutating step is labelled `OPERATOR-RUN` (also
`SERVICE-IMPACTING` / `REQUIRES APPROVAL` / `ROLLBACK ADVISED` where
appropriate) and the runbook explicitly states "ShellForgeAI did not
execute these steps." `apply` remains validation-only — no mutation.

Cleanup:

```
sudo /srv/lab-cases/bin/lab-clean
sudo /srv/lab-cases/bin/lab-status
```

ShellForgeAI's Docker visibility is read-only by convention: only
`docker ps`, `docker inspect`, and `docker logs --tail N` are issued.
Mutation (start/stop/restart/rm/exec/cp/build/pull/prune, compose
mutation, volume/network mutation) is never executed. `apply` remains
validation-only.
When ShellForgeAI runs in Docker, host-oriented checks are container-limited
unless host mounts/namespaces expose more visibility.

Compose ownership troubleshooting (PR57 ask polish):

- `shellforgeai ask "compose context for <container>"`
- `shellforgeai compose inspect <container>`
- For any restart intent, follow proposal/mission/apply gates; ask will refuse natural-language Compose mutation.

Approval queue smoke (PR32):

```
sudo docker compose exec -T shellforgeai shellforgeai diagnose docker --save-plan --with-runbook
latest=$(sudo docker compose exec -T shellforgeai sh -lc 'find /data/artifacts -maxdepth 1 -type d -name "sf_*" | sort | tail -n 1' | tr -d "\r")
sudo docker compose exec -T shellforgeai shellforgeai approvals create "$latest"
sudo docker compose exec -T shellforgeai shellforgeai approvals list
first=$(sudo docker compose exec -T shellforgeai sh -lc 'find /data/approvals/pending -name "*.proposal.json" | sort | head -n 1 | xargs -r basename | sed "s/.proposal.json$//"' | tr -d "\r")
sudo docker compose exec -T shellforgeai shellforgeai approvals show "$first"
sudo docker compose exec -T shellforgeai shellforgeai approvals validate "$first"
sudo docker compose exec -T shellforgeai shellforgeai approvals approve "$first" --reason "Docker01 PR32 approval test"
sudo docker compose exec -T shellforgeai shellforgeai approvals list
sudo docker compose exec -T shellforgeai sh -lc 'find /data/approvals -maxdepth 2 -type f -name "*.proposal.json" -print | sort'
sudo docker compose exec -T shellforgeai shellforgeai ask "queue the safe fixes for approval"
sudo docker compose exec -T shellforgeai shellforgeai ask "approve and run the fix"
sudo docker compose exec -T shellforgeai shellforgeai ask "fix everything now"
```

Expected: proposals are created for `sfai-missing-env`,
`sfai-bad-volume-perms`, `sfai-restart-loop`, `sfai-bad-network`
(noisy-logs/healthy-web skipped by default). `approvals show` displays
preconditions/steps/rollback/verification with safety labels and an
explicit "Not executed by ShellForgeAI" line. `approvals validate`
reports `execution: disabled`, `schema: ok`, `safety: ok`. `approve`
only updates status and moves the JSON file between
`/data/approvals/{pending,approved}/`. Asks like "approve and run the
fix" and "fix everything now" refuse execution and point at
`approvals create` / `approvals approve` / `apply` flow. No mutation
is performed.

Apply preflight + operator bundle smoke (PR33):

```
sudo docker compose exec -T shellforgeai shellforgeai diagnose docker --save-plan --with-runbook
latest=$(sudo docker compose exec -T shellforgeai sh -lc 'find /data/artifacts -maxdepth 1 -type d -name "sf_*" | sort | tail -n 1' | tr -d "\r")
sudo docker compose exec -T shellforgeai shellforgeai runbook validate "$latest"
sudo docker compose exec -T shellforgeai shellforgeai approvals create "$latest"
sudo docker compose exec -T shellforgeai shellforgeai approvals list
first=$(sudo docker compose exec -T shellforgeai sh -lc 'find /data/approvals/pending -name "*.proposal.json" | sort | head -n 1 | xargs -r basename | sed "s/.proposal.json$//"' | tr -d "\r")
# Pending apply should fail preflight with no operator-run scripts written.
sudo docker compose exec -T shellforgeai shellforgeai apply "$first"
sudo docker compose exec -T shellforgeai shellforgeai approvals approve "$first" --reason "Docker01 PR33 preflight test"
# Approved apply should generate the bundle but not execute anything.
sudo docker compose exec -T shellforgeai shellforgeai apply "$first"
sudo docker compose exec -T shellforgeai sh -lc "
bundle=\$(find /data/apply_bundles -maxdepth 1 -type d -name '${first}*' | sort | tail -n 1)
python -m json.tool \"\$bundle/apply-preflight.json\" >/dev/null && echo OK apply-preflight.json valid
grep -RInE 'ShellForgeAI did not execute|exit 2|execution_allowed|not_executed' \"\$bundle\"
"
```

Expected: pending apply refuses, approved apply creates the bundle, the
shell scripts contain an early `exit 2` and the "ShellForgeAI did not
execute" banner, and `apply-preflight.json` records
`execution_allowed: false` and `execution_status: "not_executed"`. Ask
safety:

```
sudo docker compose exec -T shellforgeai shellforgeai ask "apply the approved proposal"
sudo docker compose exec -T shellforgeai shellforgeai ask "can you run the approved fix?"
sudo docker compose exec -T shellforgeai shellforgeai ask "prepare the approved fix bundle"
```

Expected: execution-style asks refuse cleanly; preview/prepare-style asks
generate the operator preflight bundle. No mutation in either case.


## Audit/export pack smoke (PR34)

Local-only flow (no Docker, no root, no host mutation):

```
shellforgeai diagnose docker --save-plan --with-runbook
shellforgeai export --latest
shellforgeai validate-export <data_dir>/exports/<export_id>
shellforgeai approvals create --latest
shellforgeai approvals approve <id> --reason "PR34 export smoke"
shellforgeai apply <id>
shellforgeai export --latest-approved
shellforgeai validate-export <data_dir>/exports/<latest_approved_export_id>
shellforgeai ask "create an audit pack"
shellforgeai ask "export the approved proposal"
```

Expected: an export pack is written under `<data_dir>/exports/<export_id>/`
containing `export-manifest.json`, `export-summary.md`, `checksums.sha256`,
and copies of evidence/summary/plan/runbook/proposal/apply-preflight files
that exist for the source. Missing optional files are recorded in the
manifest. `validate-export` reports `safety: ok` and `execution: none`.
ShellForgeAI does not execute any remediation.

## Stale/drift guard smoke (PR38)

Repo-local fixture flow (no Docker, no root, no host mutation):

```
shellforgeai diagnose docker --save-plan --with-runbook
shellforgeai approvals create --latest
shellforgeai approvals approve <id> --reason "PR38 guard smoke"
shellforgeai guard check --latest-approved
shellforgeai guard check --latest-approved --max-age-hours 1
shellforgeai actions compile --latest-approved
shellforgeai guard check-actions <data_dir>/actions/<id>/actions.json
shellforgeai export --latest-approved
shellforgeai guard check-export <data_dir>/exports/<export_id>
shellforgeai guard show <data_dir>/guards/<id>/guard-report.json
shellforgeai apply --latest-approved
shellforgeai ask "is the approved proposal still fresh?"
shellforgeai ask "check drift before apply"
shellforgeai ask "run it anyway"
```

Expected: each guard call writes `guard-report.json` and `guard-report.md`
under `<data_dir>/guards/<source-id>/` with `execution_allowed=false` and
`execution_status=not_executed`. Fresh artifacts return `decision: fresh`;
overriding `--max-age-hours` to a very small value flips the decision to
`stale`. `apply` records `guard_status` and `guard_report` in
`apply-preflight.json` and refuses by default when the proposal is stale
or drifted. ShellForgeAI does not execute any remediation.

## Audit-aware incident index/search smoke (PR40)

Repo-local fixture flow (no Docker, no root, no host mutation, no network):

```
shellforgeai audit index
shellforgeai audit index --rebuild
shellforgeai audit index validate
shellforgeai audit search bad-network
shellforgeai audit search --component sfai-bad-network
shellforgeai audit search --kind guard_check --status refused
shellforgeai audit search --risk medium --type proposal
shellforgeai audit search --proposal <id>
shellforgeai audit search --session <sf_*>
shellforgeai audit search --json
shellforgeai ask "search audit for bad-network"
shellforgeai ask "find drift refusals"
shellforgeai ask "did anything execute?"
```

Expected: `audit index` writes only
`<data_dir>/audit/incident-index.json` (no source artifact is modified)
and prints per-source counts plus `execution: none`. `audit search`
prints a table or `--json` array of matching items. Every indexed item
records `execution_allowed=false`, `execution_status=not_executed`,
`mutation_performed=false`; `audit index validate` re-asserts those
invariants. ShellForgeAI does not execute any remediation.

## Local validation (fixtures/mocks only)

Run local validation without Docker daemon, root, or service mutation:

- `ruff format .`
- `ruff check .`
- `mypy src/shellforgeai tests`
- `pytest -q`
- `python -m compileall src`
- `env -u PYTHONPATH pytest -q`
- `pytest -q tests -k "export or audit or approval or apply or runbook"`
- `pytest -q tests -k "guard or stale or drift or apply or actions"`
- `pytest -q tests -k "audit or index or search or timeline"`

- PR41 validation remains repo-local fixtures/mocks only: no Docker daemon, no systemd/journal dependencies, no host mutation outside `tmp_path`.


## Repo-local fixture validation only
- PR validation for ask-routing changes must run with repo fixtures/mocks only (no Docker daemon, no systemd/journal dependencies, no root-only setup).


## PR43 status dashboard validation

- Run status/dashboard tests with repo-local fixtures only (tmp_path/mocks).
- Do not require Docker, root, systemd/journal, or internet for status validation.

## Disk growth operational note
When ShellForgeAI metadata grows, run `shellforgeai audit retention` first, then run dry-run prune/archive commands to review impact before any explicit execution.

## Safe cleanup flow (PR46)

The first guarded mutation step is limited to ShellForgeAI-owned metadata
cleanup. Follow this sequence:

1. `shellforgeai doctor` — review metadata hygiene severity and totals.
2. `shellforgeai audit retention --top 20` — see the largest categories/items.
3. `shellforgeai audit prune --category exports --max-age-days 30` — dry-run
   (the default); deletes nothing and prints the plan plus the next-step
   command.
4. (Optional) `shellforgeai audit archive --older-than-days 30` — create a
   compact archive before pruning.
5. `shellforgeai audit prune --category exports --max-age-days 30 --execute
   --confirm` — execute only after reviewing the dry-run. Writes a receipt
   under `<data_dir>/prune_receipts/` and an audit event marked
   `metadata_cleanup_executed=true`, `remediation_execution=false`.

PR46 does not execute remediation, Docker/systemd/package commands, firewall
changes, or generated operator scripts. `apply` remains
validation/preflight-only.

## Lab container restart flow (PR47)

PR47 adds the *first non-metadata* mutation gate: one Docker container
restart, only for explicitly allowlisted lab containers, only behind every
gate. Validation is repo-local fixtures/mocks only — no live Docker, no root,
no systemd/journal, no internet.

Operational sequence:

1. `shellforgeai diagnose <target>` — collect read-only evidence.
2. `shellforgeai runbook` — render the operator runbook.
3. `shellforgeai approvals create <session>` — stage proposals (no execution).
4. `shellforgeai approvals approve <id> --reason "..."` — record approval
   (no execution).
5. `shellforgeai actions compile <id>` — compile review-only actions; docker
   restart is classified `docker/restart`, decision `blocked`,
   `SERVICE-IMPACTING`. `execution_allowed` stays `false` here.
6. `shellforgeai guard check <id>` — confirm freshness and no drift.
7. Configure the lab restart allowlist (disabled by default):
   ```bash
   mkdir -p <data_dir>/policy
   cat > <data_dir>/policy/lab-container-restart-allowlist.json <<'EOF'
   {
     "schema_version": "1",
     "enabled": true,
     "allowed_containers": ["sfai-healthy-web"],
     "notes": "Lab-only restart allowlist."
   }
   EOF
   export SHELLFORGEAI_MUTATION_MODE=lab
   export SHELLFORGEAI_ALLOW_LAB_CONTAINER_RESTART=1
   ```
8. `shellforgeai apply <approved-proposal-id> --execute --confirm` — runs
   exactly one `docker restart <allowlisted-container>` if every gate passes.
   Writes a JSON receipt under `<data_dir>/execution_receipts/` and a scoped
   audit event (`kind=execution`, `action=lab_container_restart`,
   `safety.mutation_scope=lab_container_restart_only`).

PR47 does not execute `docker compose`, `docker stop|start|kill|rm|exec|run`,
docker volume/image/network commands, `systemctl`/service control,
apt/yum/dnf/apk/pip, chmod/chown/rm/mv/cp, firewall/routes/DNS changes,
generated operator scripts, or arbitrary shell strings. `apply` remains
validation/preflight-only for every other action kind.

PR47 validation remains repo-local fixtures/mocks only: no Docker daemon, no
systemd/journal, no root, no internet. Tests use the `FakeCommandExecutor`
exposed by `shellforgeai.core.lab_restart`.

## Post-mutation verification flow (PR48)

PR48 does not widen mutation scope. After the PR47 `docker restart
<allowlisted-container>` exits 0, ShellForgeAI automatically runs bounded
read-only verification: `docker inspect <container>` before and after the
restart, plus an optional bounded health-poll loop when the container has a
healthcheck. There is no second restart attempt and no `docker exec`.

Operational sequence after PR47 step 8:

9. The CLI captures `before-inspect` and `after-inspect` JSON, computes a
   verification status, and writes everything to:
   ```
   <data_dir>/execution_receipts/exec_<timestamp>_<shortid>.json   # receipt + verification block
   <data_dir>/execution_receipts/exec_<timestamp>_<shortid>.md     # human-readable summary
   <data_dir>/execution_receipts/exec_<timestamp>_<shortid>/before-inspect.json
   <data_dir>/execution_receipts/exec_<timestamp>_<shortid>/after-inspect.json
   ```
10. The audit event for the restart includes
    `details.verification_status=passed|warning|failed|skipped`,
    `details.container_running_after`, `details.started_at_changed`,
    `details.health_after`, and `details.verification_notes`. Event-level
    `status` is `success` (verification passed), `warning` (verification
    warning), or `failed` (verification failed or restart command itself
    failed).
11. Inspect the result with read-only tooling:
    ```bash
    shellforgeai audit timeline
    shellforgeai ask "did the restart work?"
    shellforgeai ask "show post-mutation verification"
    shellforgeai ask "show last execution receipt"
    ```
12. Diagnose if verification failed:
    - `verification: failed` with `running_after: false` → container exited
      after restart. Check `<data_dir>/execution_receipts/exec_<id>/after-inspect.json`
      and the operator runbook. ShellForgeAI does **not** retry the restart.
    - `verification: warning` with `Healthcheck still starting after timeout`
      → service is slow to come up; re-run `shellforgeai ask "show
      verification"` after a longer manual wait, or inspect the container
      health logs out-of-band.
    - `verification: warning` with `RestartCount did not change` → expected
      for manual `docker restart`; not actionable on its own.
    - `verification: skipped` → restart command itself failed (the receipt's
      `result.status` is `failed`). Investigate the docker error before
      proposing a new restart.

PR48 validation remains repo-local fixtures/mocks only: no Docker daemon, no
real `time.sleep`, no root, no systemd/journal, no internet. Tests use
`FakeContainerInspector` (read-only) and `FakeCommandExecutor` (only argv
`["docker", "restart", "<safe-name>"]`) from
`shellforgeai.core.lab_restart`.


## Safe restart proposal workflow (PR50)

1. `shellforgeai diagnose <target> --with-runbook`
2. `shellforgeai approvals propose-restart <container> --latest`
3. `shellforgeai approvals approve <id> --reason "..."`
4. `shellforgeai rollback preview <id>`
5. `shellforgeai apply <id> --execute --confirm`
6. verify/audit/export as needed.


## Restart plan checklist flow (PR51)

1. `shellforgeai diagnose docker --save-plan`
2. `shellforgeai approvals propose-restart --latest --container <target>`
3. `shellforgeai approvals restart-plan <proposal-id>`
4. `shellforgeai approvals approve <proposal-id> --reason "..."`
5. `shellforgeai rollback preview <proposal-id>`
6. `shellforgeai approvals restart-plan <proposal-id>`
7. `shellforgeai apply <proposal-id> --execute --confirm`
8. verify/audit/export


## Safe restart mission flow (PR52)

A guided wrapper that records each step in one mission file. Metadata only.

1. `shellforgeai diagnose docker --save-plan`
2. `shellforgeai mission restart prepare --container <target>`
3. `shellforgeai mission restart checklist <mission-id>`
4. `shellforgeai approvals approve <proposal-id> --reason "..."`
5. `shellforgeai rollback preview <proposal-id>`
6. `shellforgeai mission restart checklist <mission-id>`
7. `shellforgeai apply <proposal-id> --execute --confirm`
8. `shellforgeai mission restart validate <mission-id>` and audit/export

Mission preparation/status/checklist never restart anything; apply is still the
only execution gate.


## Safe restart mission flow with mission execute handoff (PR53)

PR53 adds a mission-level execute command that delegates to the existing apply
gate without introducing a new executor or broadening mutation scope.

1. `shellforgeai diagnose docker --save-plan`
2. `shellforgeai mission restart prepare --container <target>`
3. `shellforgeai mission restart checklist <mission-id>`
4. `shellforgeai approvals approve <proposal-id> --reason "..."`
5. `shellforgeai rollback preview <proposal-id>`
6. `shellforgeai mission restart checklist <mission-id>`
7. `shellforgeai mission restart execute <mission-id> --execute --confirm`
8. `shellforgeai mission restart validate <mission-id>` and audit/export

Step 7 verifies mission readiness, then delegates to the same guarded code path
as `shellforgeai apply <proposal-id> --execute --confirm`. The apply receipt is
referenced from the mission record. Without `--execute --confirm`, step 7 is
dry-run only and prints the exact apply delegation command.


## Post-execution mission review flow (PR54)

After a mission executes through the apply gate, PR54 adds a single read-only
review/export flow. None of these commands mutate Docker, services, packages,
filesystem, firewall, network, or system state.

1. `shellforgeai mission restart status <mission-id>` — refresh phases and
   confirm `status=executed`.
2. `shellforgeai mission restart report <mission-id>` — print the post-
   execution report; writes `mission-report.json` and `mission-report.md`
   under `<data_dir>/mission_reports/<mission-id>/`. Add `--json` for strict
   machine-readable output.
3. `shellforgeai mission restart export <mission-id> --redact` — bundle the
   mission record, report, proposal, rollback preview, apply receipt,
   before/after inspect evidence, and relevant audit events into
   `<data_dir>/mission_exports/<mission-id>/`. The `--redact` flag applies
   best-effort redaction to exported text copies; source artifacts remain
   unchanged.
4. `shellforgeai mission restart validate-export
   <data_dir>/mission_exports/<mission-id>/` — re-verify manifest, files,
   checksums, redaction report (when applicable), and safety invariants.
5. `shellforgeai audit timeline --proposal <proposal-id>` — replay the full
   audit timeline (apply gate execution + restart_mission delegated events +
   mission_report / mission_export read-only events).

Steps 2–5 are read-only. The export pack itself does not execute mutation; it
may describe a prior gated mutation if one occurred. Natural-language asks for
"run mission and export" remain refused — only the explicit
`mission restart execute --execute --confirm` (PR53) or
`apply <approved-proposal-id> --execute --confirm` (PR47) can execute the
gated mutation.

## PR55 cleanup review workflow

1. shellforgeai doctor
2. shellforgeai audit retention --top 20
3. shellforgeai audit cleanup plan --category exports --max-age-days 7
4. shellforgeai audit cleanup archive <plan-id>
5. shellforgeai audit cleanup execute <plan-id> --confirm
6. shellforgeai audit cleanup validate <receipt>
7. shellforgeai doctor

## Compose ownership check flow (PR56)

1. `shellforgeai diagnose docker --save-plan`
2. `shellforgeai compose inspect <container>`
3. Confirm compose project/service ownership before creating restart proposals.
4. Continue through existing proposal/mission/apply gates only for allowlisted containers.

## Compose-aware restart enrichment (PR58)

Operator notes for safely using PR58 Compose context enrichment:

- Use `shellforgeai compose inspect <container>` first to understand project /
  service ownership. The same context is automatically surfaced inside
  proposals, restart plans, missions, apply receipts, and mission reports.
- The restart proposal remains container-scoped. PR58 does not add
  `docker compose restart/up/down/recreate` and does not change the
  command preview, which stays exactly `docker restart <container>`.
- If you see `docker compose` in a proposal's command preview, restart-plan
  readiness will block. Fix the proposal — do not bypass the block.
- Future Compose service mutations need a separate policy gate and a separate
  PR. PR58 only enriches metadata; it never executes `docker compose`.


## PR59 operator note: ask-reference disambiguation
- Prefer explicit proposal/mission IDs when multiple candidates exist.
- `this/latest/current` now prefers fresh active artifacts.
- Stale matches are warned instead of silently treated as current.
- Long-lived `/data` may contain old artifacts; explicit IDs are safest for audits.

## PR61 Compose restart preview note

- Use `shellforgeai compose restart-preview <target>` to inspect Compose service blast radius and command shape.
- Use `shellforgeai compose propose-restart <target>` to create an auditable pending Compose restart proposal (proposal-only).
- Review with `shellforgeai approvals show <id>` and `shellforgeai approvals validate <id>`.
- Approval does not make Compose execution available yet; PR62 has no Compose execution lane.
- Preview is read-only and does not execute Docker Compose.
- Use exact IDs or PR59-style ask references (`this/latest/current proposal/mission`) when previewing from artifacts.
- Do not treat preview as approval or execution readiness.

## Compose restart mission preflight guidance

- If Compose restart mission preflight is blocked, fix the runtime/harness environment (Docker CLI/plugin/socket/project wiring) instead of bypassing ShellForgeAI gates.
- Use `shellforgeai mission compose-restart checklist <mission-id>` or `status` to read the exact preflight blocker.
- Do not treat host-side manual compose commands as an in-product workaround; those are outside ShellForgeAI policy scope.
- In Docker01-style containerized runs, preflight can block when the container does not expose a working `docker compose` plugin path.


### Compose restart with recovery-preview gate (PR65)
1. `shellforgeai compose propose-restart <target>`
2. `shellforgeai approvals approve <proposal-id> --reason "..."`
3. `shellforgeai rollback preview <proposal-id>`
4. `shellforgeai rollback validate <proposal-id-or-preview-path>`
5. `shellforgeai mission compose-restart checklist <mission-id>` / `validate`
6. Continue only when all gates pass; recovery remains manual/operator-led.

> Compose recovery is not magic rollback: it depends on known-good image/config state, source control, and backups.

## Compose execution environment readiness workflow (PR66)

- Run `shellforgeai compose env-check` to confirm runtime-level prerequisites before expecting Compose restart mission readiness.
- Run `shellforgeai compose env-check --target <target>` to see target-specific blockers in one place.
- If `compose_file_snapshot_unavailable` appears, either deliberately expose a readable compose-file snapshot to the ShellForgeAI runtime or accept that execution remains blocked.
- If `docker_compose_cli_unavailable` appears, deliberately provide Compose CLI/plugin support in the runtime or accept blocked readiness.
- Never bypass ShellForgeAI gates with host-side workarounds and then claim ShellForgeAI executed the restart flow.

## PR67 disposable Compose harness lab workflow

The disposable Compose harness lets an operator exercise the Compose
service restart lane end-to-end against a throwaway target. The real
ShellForgeAI service is intentionally still blocked from this lane.

> Do not label production services disposable just to make tests pass.
> The disposable labels are for throwaway test stacks only.

Steps:

1. Bring the disposable stack up (outside ShellForgeAI):

   ```
   ./scripts/pr67_disposable_compose_harness.sh up
   ./scripts/pr67_disposable_compose_harness.sh status
   ```

2. Verify readiness with read-only ShellForgeAI diagnostics:

   ```
   shellforgeai compose env-check --target sfai-pr67-compose-web --json
   ```

   Expect `readiness.compose_restart_execution_ready=true`,
   `allowlist.target_allowlisted=true`, `allowlist.disposable=true`, and
   a populated `config_snapshot.compose_file_sha256`.

3. Read-only preview:

   ```
   shellforgeai compose restart-preview sfai-pr67-compose-web
   ```

4. Build the proposal:

   ```
   shellforgeai compose propose-restart sfai-pr67-compose-web \
       --reason "PR67 disposable harness test"
   ```

5. Approve and create the rollback recovery preview:

   ```
   shellforgeai approvals validate <proposal-id>
   shellforgeai approvals approve <proposal-id> \
       --reason "PR67 disposable harness test"
   shellforgeai rollback preview <proposal-id>
   shellforgeai rollback validate <rollback-preview>
   ```

6. Prepare and inspect the mission:

   ```
   shellforgeai mission compose-restart prepare <proposal-id>
   shellforgeai mission compose-restart checklist <mission-id>
   shellforgeai mission compose-restart validate <mission-id>
   ```

7. Execute only with explicit `--execute --confirm`, and only against
   the disposable target, and only with Hector's go-ahead:

   ```
   shellforgeai mission compose-restart execute <mission-id> \
       --execute --confirm
   ```

8. Tear the disposable stack down (outside ShellForgeAI):

   ```
   ./scripts/pr67_disposable_compose_harness.sh down
   ```

Reminders:

- PR67 never runs `--execute --confirm` automatically. The gated mission
  still requires both flags.
- PR67 does not introduce a generic Compose executor. The only argv
  shape on this lane remains `docker compose -f <compose_file>
  --project-directory <working_dir> restart <service>`.
- PR67 does not add `docker compose up/down/recreate` from ShellForgeAI.
- PR67 does not enable natural-language Compose mutation.

## PR68 optional live disposable Compose restart proof

PR68 adds an **optional** lab-only orchestrator script that makes it easy
to prove the existing PR63-PR67 gated Compose restart lane end-to-end
against the disposable PR67 harness target. It adds no new mutation
capability to the ShellForgeAI app.

The orchestrator lives at:

```
scripts/pr68_disposable_compose_restart_proof.sh
```

It is operator/NewTwo tooling only. It is not invoked by the
ShellForgeAI app. It does not bypass any ShellForgeAI gate. It never
auto-passes `--execute --confirm`.

### Environment prerequisites for a successful live proof

Before the gated mission `execute` step can succeed against the
disposable harness, all of the following must be true:

1. The disposable Compose stack is up (via the PR67 harness helper),
   labels `shellforgeai.disposable=true` and
   `shellforgeai.allow_restart=true` are present on the service.
2. ShellForgeAI resolves the target as Compose-managed
   (`shellforgeai compose inspect sfai-pr67-compose-web`).
3. The host compose file path recorded in Compose labels is **readable
   from inside the ShellForgeAI execution environment**. If you run
   ShellForgeAI in a container, this typically means deliberately bind
   mounting the compose file (read-only is fine) into the ShellForgeAI
   container at the same path the Compose labels record. Do not have
   ShellForgeAI mount host paths itself.
4. The Docker CLI + Compose plugin is available inside the ShellForgeAI
   execution environment. `docker compose version` must succeed and
   `docker compose -f <compose-file> --project-directory <working-dir>
   config --services` must list the disposable service. If you run
   ShellForgeAI in a container, this is a build-time concern for that
   container; this PR does not install packages at runtime.
5. `shellforgeai compose env-check --target sfai-pr67-compose-web --json`
   returns `readiness.compose_restart_execution_ready=true` with no
   blockers.
6. `shellforgeai rollback preview <proposal-id>` returns a recovery
   preview with `compose_file_sha256` populated and
   `shellforgeai rollback validate` accepts it.
7. `shellforgeai mission compose-restart validate <mission-id>` reports
   all gates true.
8. The operator (Hector) explicitly approves the live execute step.

If any of these is false, the gated mission `execute` step will refuse
and `docker_compose_executed=false`, `container_restarted=false` will
remain in the receipt. That is the intended behavior - do not work around
it.

### Operator workflow

1. Print the exact gated command sequence (no execution):

   ```
   ./scripts/pr68_disposable_compose_restart_proof.sh print-commands
   ```

2. Confirm local environment readiness (read-only, no mutation):

   ```
   ./scripts/pr68_disposable_compose_restart_proof.sh check-env
   ```

3. Bring up the disposable harness (external, not ShellForgeAI):

   ```
   ./scripts/pr67_disposable_compose_harness.sh up
   ./scripts/pr67_disposable_compose_harness.sh status
   ```

4. Run the read-only ShellForgeAI readiness checks:

   ```
   ./scripts/pr68_disposable_compose_restart_proof.sh run-readiness
   ```

5. Drive the gated lane manually through the ShellForgeAI CLI exactly as
   printed by `print-commands`. The orchestrator never passes
   `--execute --confirm` for you. Even with
   `--execute-approved-disposable-restart`, the orchestrator only
   verifies env-check readiness and then prints the manual steps; the
   operator runs `shellforgeai mission compose-restart execute
   <mission-id> --execute --confirm` directly.

6. Tear the disposable stack down:

   ```
   ./scripts/pr67_disposable_compose_harness.sh down
   ```

### Safety reminders

- Do **not** label production services disposable to make tests pass.
  The real `shellforgeai` service must remain blocked from this lane.
- The orchestrator refuses targets whose names look production-like.
- The orchestrator never runs `docker system prune`, never deletes
  arbitrary paths, never installs packages, never edits production
  compose files, and never invokes `docker compose up/down/recreate`
  against the production project.
- All actual gated execution still happens through
  `shellforgeai mission compose-restart execute <mission-id>
  --execute --confirm`. The orchestrator is an external lab helper;
  ShellForgeAI's gates are unchanged.

## PR69 operator contract checklist (compose disposable proof readiness)

1. Bring up disposable harness externally (do not relabel production).
2. Run `shellforgeai compose env-contract --target sfai-pr67-compose-web` (or `--json`).
3. Confirm `target.target_allowlisted=true` (disposable + allow_restart only).
4. Confirm `snapshot.compose_file_snapshot_available=true`.
5. Confirm `environment.docker_compose_cli_available=true` and `environment.required_invocation_supported=true`.
6. Only then consider PR68 optional disposable proof workflow.

**Warning:** Do not label production services as disposable just to satisfy the contract.

## PR73 environment readiness plan workflow (operator-enablement)

`shellforgeai compose env-plan --target <target>` is the read-only
enablement plan. It answers: *what must change outside ShellForgeAI for
the disposable Compose restart proof to become ready?* It never performs
the changes itself.

Operator workflow:

1. Bring up the PR67 disposable harness externally
   (`scripts/pr67_disposable_compose_harness.sh up`). Never relabel
   production services to satisfy gates.
2. Run `shellforgeai compose env-contract --target sfai-pr67-compose-web`
   to see the current contract state.
3. Run `shellforgeai compose env-plan --target sfai-pr67-compose-web`
   (or `--json`) to see each blocker mapped to an explicit
   operator-controlled remediation step. Every entry carries
   `shellforgeai_action="none"` and `automated=false`.
4. Apply the listed remediation **externally** (out of ShellForgeAI):
   for example, provide a compatible Docker CLI + Compose plugin inside
   the ShellForgeAI runtime; expose the disposable Compose file
   read-only at the path Compose recorded.
5. Re-run env-check / env-contract. Confirm
   `ready_for_optional_disposable_proof=true`.
6. Only then consider the PR68 optional disposable proof workflow,
   with explicit operator approval. The PR47 production allowlist
   remains unchanged: production `shellforgeai` must stay not
   allowlisted.

**Refused operations.** ShellForgeAI itself will not, in any path:

- install Docker Compose,
- mount host paths,
- edit compose files,
- label production services disposable,
- run `docker compose` (restart / up / down / recreate / config),
- create proposals, missions, rollback previews, apply, or cleanup
  artifacts from env-plan,
- execute natural-language mutation asks
  (`fix compose execution environment`, `install docker compose`,
  `mount the compose file`, `label shellforgeai disposable`,
  `restart compose service now`, `execute the proof`).


## Operator workflow for reducing metadata hygiene critical state

> Operator note (PR127): If `doctor` reports metadata hygiene `critical` (or
> `warning`) on a long-lived lab, this is ShellForgeAI-owned historical
> artifact accumulation — not an active runtime failure, and no cleanup has
> run. Run `shellforgeai audit cleanup review` first. Do not jump to
> `cleanup execute`.

1. `shellforgeai doctor`
2. `shellforgeai audit retention`
3. `shellforgeai audit cleanup plan --category exports --max-age-days 7 --keep-latest 5`
4. `shellforgeai audit cleanup archive <plan-id>`
5. `shellforgeai audit cleanup validate <cleanup-archive.tar.gz>`
6. `shellforgeai audit cleanup execute <plan-id> --confirm`
7. `shellforgeai doctor`

Do not manually delete random `/data` paths unless recovering from known corruption.
Do not run step 6 unless operator-approved; start with narrow categories (for example `exports`) and verify archive validation before execution.

## PR74 Docker01 housekeeping runbook (read-only review first)

When `doctor` reports metadata hygiene `critical`, do not jump to
broad deletion. The cleanup review pack lets Hector/NewTwo decide what
is worth cleaning before any plan is written.

1. `shellforgeai doctor` — confirm severity and read the suggested
   commands. No cleanup runs from doctor.
2. `shellforgeai audit retention` (optionally `--top 20` or `--json`) —
   see the size/severity by category.
3. `shellforgeai audit cleanup review` (or `--json` for tooling) —
   read-only decision aid. Reports the largest categories, marks each
   category as `cleanup_supported` or report-only, recommends `exports`
   as the safest narrow first lane when it has items, restates the
   PR71 deletion gates, and prints the next safe dry-run command.
   No plans/archives/receipts are created and no files are deleted.
4. Choose a narrow category (default: `exports`). Avoid broad
   `--include-artifacts` cleanup unless the artifacts category has been
   reviewed item-by-item.
5. `shellforgeai audit cleanup plan --category exports --max-age-days 7
   --keep-latest 5 --json` — still dry-run, still no deletion.
6. `shellforgeai audit cleanup archive <plan-id>` — writes the
   fingerprinted cleanup archive.
7. `shellforgeai audit cleanup validate <cleanup-archive.tar.gz>` —
   reject the run on any validation error.
8. `shellforgeai audit cleanup execute <plan-id> --confirm` — only run
   this if Hector approves and the previous gates have passed.
9. `shellforgeai audit cleanup validate <cleanup-receipt-or-dir>` —
   verify the receipt is well-formed and safety-clean.

Do not run broad cleanup blindly. Do not use natural-language asks to
delete (ask routing refuses and prints the explicit guarded CLI). Do
not touch `/data` paths outside ShellForgeAI's owned roots; the cleanup
lane enforces this and any path resolving outside is refused. PR74 adds
review-only reporting; it does not loosen the PR71 deletion gates.

## PR75 Docker01 cleanup prepare workflow

When PR74 review says `exports` is the safest first lane and the
operator wants a decision packet without writing five commands by hand,
use `audit cleanup prepare`:

1. `shellforgeai audit cleanup review` — confirm severity, safest first
   lane, and that gates are understood.
2. `shellforgeai audit cleanup prepare --category exports --max-age-days
   7 --keep-latest 5` — creates the plan, creates the matching archive,
   validates the archive, and prints the decision packet. No deletion.
3. Inspect the plan path and candidates list printed by `prepare`.
4. `shellforgeai audit cleanup validate <cleanup-archive.tar.gz>` —
   re-check the archive on its own if desired.
5. Stop here for Hector/operator approval. `prepare` will not execute,
   and the printed execute command is marked operator-approved only.
6. Only if explicitly approved:
   `shellforgeai audit cleanup execute <plan-id> --confirm`. PR71 gates
   (matching archive, matching plan fingerprint, validation, `--confirm`)
   still all apply.
7. `shellforgeai audit cleanup validate <cleanup-receipt-or-dir>` —
   verify the post-execute receipt is well-formed and safety-clean.

`prepare` never broadens cleanup beyond ShellForgeAI-owned metadata,
never accepts arbitrary paths, refuses unknown/path-traversal categories
before creating anything, and never invokes Docker/Compose/services or
the apply/mission paths.

## PR76 Docker01 cleanup final-decision sequence

PR76 adds an explicit readiness gate and a post-execute report between
`prepare` and the eventual `execute --confirm`. The full Docker01
sequence is:

1. `shellforgeai audit cleanup review` — confirm severity and the
   safest first lane.
2. `shellforgeai audit cleanup prepare --category exports
   --max-age-days 7 --keep-latest 5` — produce plan + archive.
3. `shellforgeai audit cleanup execute-readiness <plan-id>` — re-check
   the PR71 gates (plan kind/safety, matching archive, archive
   validation, plan fingerprint, allowed-root candidate paths). This is
   read-only and creates nothing.
4. Manual review of the plan candidate list and the archive
   manifest/fingerprint as printed by `execute-readiness`.
5. Only if Hector approves and `ready_for_execute_confirm=true`:
   `shellforgeai audit cleanup execute <plan-id> --confirm`. PR71
   archive/fingerprint/validation/confirm gates still all apply at
   execute time.
6. `shellforgeai audit cleanup report <cleanup-receipt-or-dir>` —
   summarize the execute receipt (deleted/failed/bytes/skipped, safety
   block, fingerprint cross-check). Also read-only.
7. `shellforgeai doctor` and `shellforgeai audit retention` to confirm
   post-execute posture.

`execute-readiness` and `report` never delete anything, never create
plans/archives/receipts, never touch Docker/Compose/services/packages/
firewall/network/system, and never accept natural-language cleanup
execution.

## PR77 last-mile cleanup execution checklist

PR77 is UX/safety polish around the final cleanup boundary — no new
mutation surface, no gate weakening. Use this checklist when running
real `/data` cleanup on Docker01 or any live host:

1. `audit cleanup review` (read-only).
2. `audit cleanup prepare --category <cat> ...` (creates plan + archive,
   stops before execute).
3. `audit cleanup execute-readiness <plan-id>` and **read the output**:
   - Confirm `read_only: true`,
     `deletion_performed: false`,
     `cleanup_executed: false`,
     `ready_for_execute_confirm: true`.
   - Confirm the `Validated gates` block: plan present, matching
     archive present, archive validation passed, plan fingerprint
     matched, explicit confirm still required.
   - If `Blockers:` appear, **stop**. Do not execute until they are
     resolved.
4. **Operator decision.** This is the only step where a human chooses
   to delete. Do not run `execute` just because readiness is `true`;
   readiness means gates are satisfied, not that deletion is
   approved.
5. `audit cleanup execute <plan-id> --confirm` (the only command that
   deletes). Without `--confirm` it refuses, prints
   `Nothing was deleted.`, and lists `matching archive`,
   `archive validation`, `matching plan fingerprint`,
   `explicit --confirm` as required.
6. `audit cleanup report <receipt>` and read the
   `Post-execute checks:` block.
7. `audit cleanup validate <receipt>` to re-check receipt safety
   flags.
8. `audit retention` and `shellforgeai doctor` to confirm the host is
   still healthy.

Reminder: ShellForgeAI is a Tier-3 triage tool. Cleanup remains
scoped to ShellForgeAI-owned metadata under `<data_dir>`. PR77 does
not change that scope, does not add arbitrary path deletion, does not
mutate Docker/Compose/services/packages/firewall/network/system, and
does not let natural-language `ask` flows execute cleanup.

## PR79 / PR80 safe operator command pass

After a deploy / image sync / restart, run the safe command coverage
harness to confirm the read-only command surface still works.

### Post-deploy smoke workflow

Recommended sequence (every step is read-only):

1. `shellforgeai self-test commands --profile quick` — fast, env-independent
   smoke. Reliably reports `ok` on a fresh container.
2. `shellforgeai self-test commands --profile standard --json` — broad
   coverage with a parseable payload. May report `warn` when optional
   artifacts (latest runbook, compose target) are not yet present —
   that is expected and is not a command failure.
3. `shellforgeai doctor` — final sanity check on the runtime.
4. `shellforgeai ops status` — operations status board.

For CI / strict pipelines that should not tolerate optional-artifact
warnings:

```
shellforgeai self-test commands --profile standard --fail-on-warn --json
```

`--fail-on-warn` exits non-zero on `warn` and adds `ci_status: "failed_on_warn"`
to the JSON payload. Warnings remain warnings — the flag does not convert
them into runtime failures.

### Profiles

- `quick` — cheap, env-independent. Best first gate after a deploy.
  Runs `version`, `doctor`, `model doctor`, `tools list`, `ops status`,
  and the ask-mutation refusal smoke. Avoids artifact-dependent checks.
- `standard` (default) — PR79 coverage: cleanup review / readiness /
  report negative paths, compose env-check / env-contract / env-plan,
  validate-runbook --latest, locally-routed ask smokes, and the
  ask-mutation refusal smoke.
- `full` — `standard` plus `audit list`, `audit timeline --latest --json`,
  and `compose list --json`. May warn more often when those artifacts
  are absent; still strictly read-only.

### Operator expectations

- `status: ok` — every check passed.
- `status: warn` — every check passed but at least one was warned or
  skipped because an optional artifact is missing (e.g. no runbook
  artifact on the host, compose target absent from the local Docker
  inventory, audit storage empty). Read the `(reason)` next to each
  `WARN` / `SKIP` line. Do not treat warnings as failures.
- `status: failed` — at least one check failed. Investigate the
  `(reason)` next to the `FAIL` line before continuing other work.

The harness is read-only across every profile. It does not execute
cleanup, apply, mission, docker compose restart, proposal/mission/archive/plan
creation, or natural-language mutation, and it never uses `shell=True`.
It is safe to run on Docker01 against production data.

### NewTwo Docker01 QA note

The runtime container image may lack developer tools (ruff, pytest,
mypy). Use a disposable dev-validation container alongside Docker01 for
`ruff format` / `ruff check` / `pytest -q` / `mypy src/shellforgeai tests`.
The self-test harness itself runs in the runtime image because it only
exercises ShellForgeAI's own CLI surface.

### When to use it

1. After image sync / container recreate on Docker01.
2. After approving and merging a new PR locally, before live QA.
3. As a quick smoke any time the operator wants an "everything still
   safe?" signal.

## PR81 / PR82 — 2AM triage ranking workflow (read-only)

When the page is "the server feels broken" or "what's on fire?" — not a
named container — start with the broad-first read-only ladder. None of
these steps mutate anything.

1. **Self-test, quick profile** to confirm the CLI is healthy:

       shellforgeai self-test commands --profile quick

   Expect `status: passed` or `status: warn` (PR79/PR80 semantics).

2. **Rank the Docker scene** with PR81 triage ranking:

       shellforgeai triage docker

   or strict JSON for capture:

       shellforgeai triage docker --json

   Read the ranked suspects in order. Severity / confidence / classes
   are deterministic; no LLM. Watch-list entries (e.g. high CPU but
   currently healthy) are listed below suspects on purpose — they are
   visible but do not outrank real failures.

3. **Ask broad triage questions in natural language (PR82)** — the
   `ask` command routes broad Docker / 2AM prompts to the same PR81
   deterministic engine instead of falling back on the model:

       shellforgeai ask "2AM triage"
       shellforgeai ask "what's on fire?"
       shellforgeai ask "rank all sfai-battle-lab suspects by severity"

   The answer is grounded in `triage_ranking.collect_scene` +
   `rank_scene`. It preserves the deterministic ranking, severity,
   confidence, and per-container evidence; it never invents suspects
   and never collapses one container's evidence onto another. Every
   suspect carries a read-only `Safe next` command (always
   `shellforgeai diagnose …`).

4. **Inspect the top suspect's evidence** using the safe next command
   the report printed — always a `shellforgeai diagnose …` invocation:

       shellforgeai diagnose docker --container <name> --json
       # or
       shellforgeai triage docker detail <name> --json

5. **Only then** decide whether to engage an existing gated workflow:
   restart proposal (PR50/PR58), restart mission (PR52/PR53), or the
   cleanup ladder (PR74–PR77). The triage ranking command does not
   create proposals, missions, plans, archives, or apply receipts.

Do **not** jump from "ranking" to "restart". The ranking is evidence
synthesis only. A restart still requires the explicit proposal /
mission / apply gates with their own approvals and rollback previews.
The PR82 ask route is identical in shape: it ranks suspects, but
refuses mutation phrasings ("restart the top suspect", "fix the
crashloop", "clean up disk pressure now", "stop noisy-errors", "apply
the top fix") and redirects to the explicit gated CLI.

The triage ranking command never starts, stops, restarts, removes, or
prunes containers, never runs docker compose mutation, never runs
`apply`, `cleanup execute`, `mission execute`, or any natural-language
execution path, and never uses `shell=True`. Mutation-style asks
("restart the top suspect", "fix the crashloop", "clean up disk now")
continue to refuse with the existing PR74–PR80 wording, plus the PR82
no-mutation wording on broad-triage prompts.

- PR83 drilldown step added after broad ranking: `shellforgeai triage docker detail <suspect>` (or `--rank <n>`) to inspect why/evidence before any gated remediation workflow.


## PR84 update — 2AM triage snapshot handoff

Recommended read-only workflow:
1. `shellforgeai self-test commands --profile quick`
2. `shellforgeai triage docker`
3. `shellforgeai triage docker snapshot`
4. `shellforgeai triage docker detail <suspect>`
5. targeted read-only diagnose (`diagnose docker --save-plan --with-runbook`)
6. only then decide whether to enter proposal/mission gates


## PR85 update — 2AM triage snapshot save/validate handoff

1. `shellforgeai self-test commands --profile quick`
2. `shellforgeai triage docker`
3. `shellforgeai triage docker snapshot --save --include-details`
4. `shellforgeai triage docker snapshot validate <snapshot-id>`
5. Hand off the saved snapshot path/id
6. Only then decide whether explicit proposal/mission gates are needed

## PR86 update — 2AM triage snapshot export/validate handoff

1. `shellforgeai self-test commands --profile quick`
2. `shellforgeai triage docker`
3. `shellforgeai triage docker snapshot --save --include-details`
4. `shellforgeai triage docker snapshot validate <snapshot-id>`
5. `shellforgeai triage docker snapshot export <snapshot-id>`
6. `shellforgeai triage docker snapshot export-validate <export-path>`
7. Hand off the export path
8. Only then decide whether explicit proposal/mission gates are needed



### PR89 governed disposable remediation proof workflow

### PR91 disposable remediation receipt validation and handoff

Governed workflow now includes:
1. `shellforgeai remediation plan ...`
2. `shellforgeai remediation validate <plan-id>`
3. `shellforgeai remediation execute <plan-id> --executor ... --execute --confirm`
4. `shellforgeai remediation receipt validate <receipt-id-or-path>`
5. `shellforgeai remediation report <receipt-id-or-path>`
6. handoff using report + next safe commands

1. triage
2. detail/snapshot/timeline if needed
3. `shellforgeai remediation plan --target sfai-noisy-errors --scenario sfai-noisy-errors`
4. `shellforgeai remediation validate <plan-id>`
5. `shellforgeai remediation execute <plan-id> --execute --confirm` only with explicit operator approval
6. `shellforgeai remediation status <receipt-id>`
7. verify production `shellforgeai` remained untouched


## PR90 operator flow (disposable executor modes)

Live QA note: proof mode is non-mutating; docker-disposable mode is exact-target-only, and successful verification requires exact-target pre/post evidence (for example changed `StartedAt`).

1. Run triage (read-only).
2. Create remediation plan.
3. Validate plan.
4. Optionally execute `--executor proof` (or default) to verify artifact flow without mutation.
5. Execute `--executor docker-disposable --execute --confirm` only for exact disposable+allowlisted target.
6. Check `remediation status <receipt-id>` and verify restart evidence.
7. Confirm production `shellforgeai` remained untouched.

## PR93 governed remediation rollback posture workflow
- `shellforgeai remediation plan`
- `shellforgeai remediation validate`
- `shellforgeai remediation preflight`
- explicit operator confirm + `remediation execute`
- `remediation receipt validate` / `remediation report`
- `remediation rollback-preflight`
- `remediation rollback-validate`
- `remediation rollback-execute --execute --confirm`
- `remediation rollback-status`

Rollback packet commands are decision support only (posture/preconditions/verification preview). They do not execute rollback.

9. remediation bundle --save
10. remediation bundle validate
11. remediation audit


## PR97 operator flow (read-only remediation eligibility map)

## PR99 post-deploy remediation-lane readiness workflow
1. `shellforgeai self-test commands --profile quick`
2. `shellforgeai remediation self-test --profile quick`
3. `shellforgeai remediation self-test --profile standard --json`
4. `shellforgeai remediation self-test --profile full` now validates non-mutating lifecycle readiness end-to-end in temp artifacts (including proof execute + receipt/report/bundle/audit) and still skips live docker-disposable execute by default.
5. Optional lab QA live disposable proof (off by default): `shellforgeai remediation self-test --profile full --include-live-disposable-execute --target <exact-disposable-target> --confirm-live-disposable --json`
6. Validate receipt/bundle/audit outputs.
7. Clean up the disposable target outside ShellForgeAI.
1. `shellforgeai triage docker`
2. `shellforgeai remediation eligibility`
3. `shellforgeai remediation eligibility --target <target> --explain`
4. `shellforgeai remediation plan --target <target> --scenario <scenario>` only if operator chooses
5. `shellforgeai remediation validate <plan-id>`
6. `shellforgeai remediation preflight <plan-id>`
7. explicit `shellforgeai remediation execute <plan-id> --execute --confirm` only with approval


2AM flow (read-only first):
1. `shellforgeai ask "it's 2am, what is on fire?"` (deterministic ask route), or `shellforgeai ops report`
2. `shellforgeai triage docker detail <target>`
3. `shellforgeai remediation eligibility --target <target> --explain`
4. Plan only if operator chooses (`shellforgeai remediation plan ...`).
5. Validate/preflight/execute only through the governed remediation lane.

## PR106 update — ask mutation refusal before model

2AM flow reminder:
- `shellforgeai ask` can request read-only ops summaries (for example: `shellforgeai ask "what is on fire in docker right now? ops report please"`).
- `shellforgeai ask` cannot execute mutation; obvious mutation asks are deterministically refused before model/Codex.
- For any disposable proof workflow, use explicit governed CLI gates (`plan -> validate -> preflight -> execute --confirm`).


## PR107 update — 2AM ops report handoff bundle
1. `shellforgeai ops report`
2. `shellforgeai ops report --save`
3. `shellforgeai ops report validate <id>`
4. `shellforgeai ops report history`
5. `shellforgeai ops report compare-latest`
6. `shellforgeai ops report compare <old> <new>` (explicit refs when needed)
5. `shellforgeai triage docker detail <changed-suspect>`
6. `shellforgeai remediation eligibility --target <target> --explain`
7. `shellforgeai ops report export <id>`
8. `shellforgeai ops report export-validate <path>`
6. Hand off the export bundle

## V1 operator lane (canonical)

Use this 2AM sequence first:

1. `shellforgeai doctor`
2. `shellforgeai remediation self-test --profile quick`
3. `shellforgeai ops report`
4. `shellforgeai ops report --save`
5. `shellforgeai ops report history --limit 5`
6. `shellforgeai ops report compare-latest`
7. `shellforgeai triage docker detail <target>`
8. `shellforgeai remediation eligibility --target <target> --explain`

Mutation remains gated/disposable only; do not treat this guide as production
remediation automation.

Interactive follow-up grounding example (session-local, read-only):

```text
ops report
the first one
is that scary?
restart it
```

`the first one` and `is that scary?` resolve to the latest top suspect when
unambiguous and suggest/read from safe triage detail. `restart it` is still
refused from natural language; no restart is performed, and ShellForgeAI
suggests read-only triage detail / remediation eligibility explanation instead.


- V1 post-deploy check: `shellforgeai v1 check --profile standard --json`
scripts/v1_validate.sh --full --packet
shellforgeai v1 packet history
shellforgeai v1 packet compare-latest
shellforgeai v1 packet export <packet>
shellforgeai v1 packet export-validate <export>

## V1 release readiness

1. `./scripts/v1_validate.sh --quick`
2. `./scripts/v1_validate.sh --full --packet`
3. `shellforgeai v1 packet history`
4. `shellforgeai v1 packet compare-latest`

- When reviewing V1 release readiness, check `docs/V1_COMMAND_SURFACE.md` and keep packet mode in the validation lane.


## PR validation lane policy (PR157)

Full `pytest` is no longer the default confidence blanket for every PR. Choose a
validation lane explicitly, state why, and reserve full validation for
execution/safety/packaging boundaries. Targeted validation is the default; full
validation is exceptional. Safety gates are never weakened to go faster.

Lanes (see [`docs/VALIDATION_LANES.md`](docs/VALIDATION_LANES.md) and
[`docs/VALIDATION_MATRIX.md`](docs/VALIDATION_MATRIX.md)):

- **Lane A (fast)** — docs / README / OPS / roadmap / wording / tests-only.
- **Lane B (targeted runtime)** — read-only ask routing, intent, dispatch,
  interactive UX, JSON/output shape, artifact read/validate/export, doctor,
  status/triage/propose/apply-preview/verify/handoff wording, recipe
  registry/preflight read-only logic.
- **Lane C (full)** — cleanup/remediation/rollback/restart/recipe/apply/mission
  execution, Docker/Compose behavior, safety-gate or refusal-core rewrites,
  broad command-router rewrites, `pyproject`/dependency/`Dockerfile`/packaging,
  and validation-infrastructure changes. Lane C runs the bounded full pytest
  runner: `python scripts/run_full_pytest.py`. The runner uses `pytest-xdist`
  when available, falls back to serial pytest when unavailable, streams pytest
  output during execution, and always includes slow-test duration reporting
  (`--durations=25`).

Pick the lane from the changed files with the read-only optimizer (it never
mutates, deploys, or runs Docker/Compose; it only plans unless you pass
`--execute`):

```bash
python scripts/validate_pr.py --changed-files <files...>
python scripts/validate_pr.py --base main --head HEAD --json
python scripts/validate_pr.py --changed-files docs/cli.md            # Lane A
python scripts/validate_pr.py --changed-files src/shellforgeai/core/ask_routing.py --pr 156  # Lane B
python scripts/validate_pr.py --changed-files src/shellforgeai/core/disposable_remediation.py # Lane C
python scripts/validate_pr.py --changed-files docs/cli.md --full-validation  # force Lane C
```


The guarded Docker01 PR lane helper (`scripts/sfai_docker01_pr_lane.py`) uses
the same Lane C runner command as the planner: `python scripts/run_full_pytest.py`.
It prints the selected lane, the full-validation reason, the runner command,
duration reporting (`--durations=25`), live pytest progress/output, elapsed
runtime, and the runner output showing whether xdist was available/used or
whether serial fallback occurred. Lane C remains exceptional and explicit; Lane
A/B runs do not invoke the full runner by default.

Docker01 may optionally use a reusable ShellForgeAI validation image with dev
dependencies preinstalled (for example `pytest-xdist`, included in the project
`dev` extra) to reduce setup cost and enable parallel full validation. This is
only a validation-speed optimization: if the image is unavailable, use the
current writable validation container path, let the runner report the serial
fallback, and never use the image to skip tests or weaken Lane C safety gates.

Every Docker01 PR report now has two durable evidence artifacts from
`scripts/sfai_docker01_pr_lane.py`: a structured JSON manifest
(`mode=docker01_pr_validation_manifest`, `schema_version=1`) and a bounded
human summary. Architect/safety review should prefer the manifest values for
lane selection, lane reason, validation status, safety flags, command/phase
durations, log paths, final container health, final disk state when available,
known non-blockers, and the final verdict. The human summary is the
copy/paste-friendly companion for PR comments, not the source of truth.

If full validation or QA already completed in a separate operator log, do not rerun expensive validation solely to populate `not_run` manifest fields. Finalize/import the completed evidence instead:

```bash
python scripts/finalize_validation_manifest.py /tmp/sfai-pr162-manifest.json \
  --validation-log /tmp/sfai-pr162-validation.log \
  --qa-log /tmp/sfai-pr162-qa.log \
  --status passed \
  --verdict pass \
  --summary-output /tmp/sfai-pr162-finalized-summary.txt
```

The finalizer reads the existing manifest, parses conservative pass/fail signals from supplied logs, writes `<manifest>.finalized.json` by default, and records `evidence_source=imported_log`, `imported=true`, and `executed_by_helper=false` on imported command statuses. It treats explicit zero-failure summaries such as `failed: 0`, `failed=0`, and `0 failed` as pass-safe evidence instead of conflicts, while real or ambiguous failures remain conservative warnings. Repeated non-blocker notes are trimmed and de-duplicated in first-seen order. Use `--in-place` only when you intentionally want to update the original manifest. Imported evidence is different from helper-executed evidence: the finalizer does not run pytest, Docker, Compose, cleanup, remediation, rollback, deploy, restart, or any arbitrary command. Ambiguous or conflicting logs are recorded as warnings and must not be treated as an automatic pass without an explicit operator `--status` / `--verdict` override.

Every Docker01 PR report should record through the manifest/summary:

- the **selected lane** (A / B / C) and **why**,
- the **commands run** and their durations/log paths,
- the validation phases completed and the failed phase/error summary on hold or
  failure,
- whether **full `pytest`** was required,
- for Lane C, the `python scripts/run_full_pytest.py` command output, including
  live pytest progress and the slow-test duration table,
- whether the runner used xdist or printed the serial fallback warning,
- final container status/health/restart count when available,
- snapshot/compose backup/final config/image metadata when available,
- explicit safety flags showing no cleanup/remediation/rollback execution, no
  prune, no direct compose write, no production restart, no `shell=True`, no
  arbitrary command execution, and no natural-language mutation,
- if full `pytest` was **skipped**, why that is acceptable (e.g. "Lane B
  read-only routing change; targeted regression group green; no safety or
  execution boundary touched").

Rules of the road:

- Full validation is **required** for execution/safety boundary PRs and stays
  **always available** (`--profile full` / `--full-validation`); it is never
  removed.
- Review `--durations=25` output for future slow-test follow-up. Optimize
  repeated expensive setup when coverage remains equivalent; do not skip slow
  tests silently.
- Targeted validation is **acceptable** for docs / routing / output polish.
- Safety/execution keywords in changed **code** content (`shell=True`,
  `docker compose`, `os.system`, `*_executed`, `rm -rf`, …) escalate to full;
  documentation that merely describes those keywords does not.
- Live smoke on Docker01 should match the changed behavior.
- Deploy/snapshot/compose railings are **unchanged**: snapshot before mutation,
  atomic/temp compose config update, cached build default, no direct compose
  write, no destructive cleanup, no volume prune, and no
  remediation/rollback/cleanup execution outside an explicit, scoped PR. The
  lane optimizer touches none of these — it is planning-only.


## V1 release handoff (PR120)

ShellForgeAI V1 handoff packet is finalized for operator/admin sign-off.

- Primary release notes: [`docs/V1_RELEASE_NOTES.md`](docs/V1_RELEASE_NOTES.md)
- Release-candidate evidence checklist: [`docs/V1_RELEASE_CANDIDATE.md`](docs/V1_RELEASE_CANDIDATE.md)
- Changelog release entry: [`CHANGELOG.md`](CHANGELOG.md)

Handoff emphasis:

- Deterministic ask routing and deterministic mutation refusal are core V1 safety behavior.
- Ops report artifact lifecycle (`save/validate/export/export-validate/history/compare-latest`) is core operator workflow.
- `v1_validate` packet/export helpers are for the dev-validation lane, not minimal runtime image.
- Normal V1 validation path remains read-only and non-mutating.

## Safe governed recipe preflight workflow

Use this read-only sequence before any future governed execution lane exists:

```bash
shellforgeai recipes list
shellforgeai recipes eligibility --recipe docker.disposable_restart --target <target> --json
shellforgeai recipes preflight --recipe docker.disposable_restart --target <target> --save
shellforgeai recipes preflight validate <preflight_id>
```

The preflight packet may preview the bounded argv `docker restart <target>` for an eligible disposable allowlisted container, but it is preview-only: `execution_available=false`, `command_preview_only=true`, `command_executed=false`, and `container_restarted=false`. Production targets, broad targets (`all`, `*`), missing targets, unlabeled targets, and Docker Compose patterns remain blocked.

Do not treat a preflight packet as permission to execute. Future execution must require explicit confirmation, an execution receipt, post-verification, and rollback posture handling.
