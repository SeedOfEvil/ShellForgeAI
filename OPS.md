# OPS

Operator smoke tests and runbook tips.

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

## Apply safety check

```bash
shellforgeai apply <valid-plan-file>
```

Expected outcome: apply execution is intentionally disabled in this alpha
(validation-only parse/validate path).

## Non-interactive smoke test

```bash
shellforgeai doctor
shellforgeai inspect host
shellforgeai tools list
shellforgeai diagnose disk --save-plan
shellforgeai audit list
```

## Restricted containers

In restricted containers, the Codex CLI may emit `bwrap`/namespace errors.
Treat that as a provider sandbox limitation, not a host failure: ShellForgeAI
still collects evidence via its typed read-only tools, and `model doctor`
will report whether `codex` is reachable.

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


No-hang follow-up smoke: run `can you restart nginx`, `/pending`, `proceed`, `/pending`, `can you restart shellforgeai`, `/pending`, `dig deeper`, `/pending`, `/exit` and confirm prompt returns each time without session drop.

Zombie/process smoke: compare `ps -eo pid,ppid,stat,comm,args | grep -E "codex|defunct|shellforgeai" | grep -v grep || true` before/after interactive checks; no accumulating defunct children should remain.
