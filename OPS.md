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
