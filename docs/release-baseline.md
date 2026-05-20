# Release / Handoff Baseline (PR78)

This document is the concise operator/QA/contributor baseline for
ShellForgeAI after the PR56–PR77 capability arc. It is **release
packaging only** — no runtime behavior, gates, or mutation surface
changed in PR78.

For deeper detail, follow the links in each section.

---

## A. Product identity

> ShellForgeAI is a lightweight, portable Tier-3 triage tool —
> a combat knife with a safety catch, receipts, and a flight recorder.

It is intentionally **not**:

- not an autopilot,
- not a platform,
- not a generic shell or remote-execution agent,
- not a production Compose orchestrator,
- not a natural-language mutation agent.

Mutation lives in narrow, audited lanes behind explicit CLI gates.
Asks/previews/proposals/approvals/rollback-previews/status/checklist/
report/export **never** execute.

See also: [`safety.md`](safety.md), [`architecture.md`](architecture.md),
[`north-star.md`](north-star.md).

---

## B. Current stable capabilities

### 1. Health / status

- `shellforgeai version`
- `shellforgeai doctor` (metadata hygiene severity + suggested commands)
- `shellforgeai model doctor`
- `shellforgeai ops status` (read-only posture board, PR60)

### 2. Diagnosis / evidence (read-only)

- `shellforgeai diagnose docker | logs | errors | network | nginx |
  performance | disk | packages | package | config | changes`
- Compose ownership and context auto-enriched into docker evidence
  (PR56–PR58).

### 3. Runbooks

- `shellforgeai diagnose <target> --with-runbook`
- `shellforgeai runbook --latest`
- `shellforgeai validate-runbook --latest`

### 4. Proposals / approvals

- `shellforgeai approvals create | list | show | approve | reject |
  cancel | archive | validate`
- `shellforgeai approvals propose-restart` / `restart-plan`
- Proposal fingerprints + dedupe; approval is a paper trail, not
  execution.

### 5. Exact-container restart (PR47/PR48/PR49 + PR50–PR54)

- Allowlisted / disposable containers only.
- Proposal → approval → rollback preview → mission checklist →
  `apply <id> --execute --confirm` → verification → receipt.
- `shellforgeai mission restart prepare | status | checklist |
  validate | execute | report | export | validate-export`.

### 6. Compose (PR56–PR69, PR73)

- `shellforgeai compose list | inspect <container>` (context only).
- `shellforgeai compose restart-preview <target>` (read-only).
- `shellforgeai compose propose-restart <target>` (proposal only).
- `shellforgeai compose env-check [--target ...]`.
- `shellforgeai compose env-contract --target ...`.
- `shellforgeai compose env-plan --target ...` (read-only remediation
  guidance, PR73).
- `shellforgeai mission compose-restart prepare | checklist | validate
  | execute | report | export | validate-export`.
- Disposable lab harness (`scripts/pr67_disposable_compose_harness.sh`)
  and optional proof orchestrator
  (`scripts/pr68_disposable_compose_restart_proof.sh`).
- The `compose_service_restart` mission lane remains
  env-contract / readiness / allowlist gated.

### 7. Audit / export / redaction

- `shellforgeai audit list | show | timeline | validate | index |
  index validate | search`.
- `shellforgeai export [--latest | --proposal <id> | --latest-approved]
  [--redact]`.
- `shellforgeai validate-export <export-dir>`.
- `shellforgeai guard check | check-actions | check-export | show`.

### 8. Cleanup (PR55, PR71, PR74–PR77)

ShellForgeAI-owned `<data_dir>` metadata only.

- `shellforgeai audit retention [--top N] [--json]`
- `shellforgeai audit cleanup review` (read-only decision aid, PR74)
- `shellforgeai audit cleanup prepare --category <cat>
  --max-age-days N --keep-latest M` (plan + archive + validate, PR75)
- `shellforgeai audit cleanup plan` (dry-run plan)
- `shellforgeai audit cleanup archive <plan-id>`
- `shellforgeai audit cleanup validate <archive-or-receipt>`
- `shellforgeai audit cleanup execute-readiness <plan-id>` (read-only
  gate re-check, PR76)
- `shellforgeai audit cleanup execute <plan-id> --confirm`
  (PR71 archive + fingerprint + `--confirm` gates)
- `shellforgeai audit cleanup report <receipt>` (PR76 + PR77 polish)

Deeper reference: [`cli.md`](cli.md),
[`mission-workflow.md`](mission-workflow.md),
[`compose-ops.md`](compose-ops.md),
[`audit-and-cleanup.md`](audit-and-cleanup.md),
[`data-layout.md`](data-layout.md).

---

## C. Current mutation boundary

**Allowed today:**

1. ShellForgeAI-owned metadata cleanup under `<data_dir>`, only via
   `audit cleanup execute <plan-id> --confirm` with a matching
   validated archive and matching plan fingerprint.
2. Exact Docker container restart (single `docker restart <container>`)
   for entries in the explicit lab allowlist, only via
   `apply <approved-proposal-id> --execute --confirm` plus the lab
   env vars.
3. The `compose_service_restart` mission lane exists structurally
   (PR61–PR69, PR73). Live execution requires every env-contract /
   readiness / allowlist / disposable gate to pass. In default
   production deployments this lane is intentionally **blocked**.

**Not allowed today (and not on the roadmap as broad mutation):**

- production Compose restart,
- `docker compose up | down | recreate` from ShellForgeAI,
- config / compose-file edits,
- package installs (`apt`, `yum`, `dnf`, `apk`, `pip`, etc.),
- `chmod` / `chown` / arbitrary `rm` / `mv` / `cp`,
- firewall / iptables / nftables / route / DNS changes,
- host service restarts (`systemctl`, init scripts),
- arbitrary shell execution,
- natural-language mutation (`ask` never executes mutation).

---

## D. Critical safety invariants

These hold across every command, regardless of profile or workspace
trust:

- `ask` does **not** execute.
- `preview` (any flavor) does **not** execute.
- `proposal` creation does **not** execute.
- `approval` alone does **not** execute.
- `rollback preview` does **not** execute.
- `status` / `checklist` / `report` / `export` do **not** execute.
- `cleanup review` / `prepare` / `execute-readiness` / `report` do
  **not** delete.
- `cleanup execute` requires matching archive + matching plan
  fingerprint + `--confirm`.
- Compose service restart execution requires env-contract readiness
  AND a disposable/allowlisted target.
- All mutation paths emit a receipt and a scoped audit event.

Detail: [`safety.md`](safety.md).

---

## E. Current Docker01 / homelab caveats

- Metadata hygiene on long-lived Docker01 has accumulated historical
  artifacts. The PR74–PR77 cleanup review/prepare/readiness/report
  chain now makes it safe to inspect before any deletion.
- Compose service restart execution against the real production
  `shellforgeai` service is intentionally **blocked**. Production
  `shellforgeai` is not (and must not be) labeled
  `shellforgeai.disposable=true` / `shellforgeai.allow_restart=true`.
- Live disposable Compose restart proof remains blocked until the
  ShellForgeAI runtime provides:
  - a working inside-container Docker CLI + Compose plugin,
  - a readable/hashable compose-file snapshot at the path Compose
    labels record,
  - a disposable / allowlisted target (the PR67 harness is the
    intended subject).
- The PR67 disposable harness and the optional PR68 proof
  orchestrator exist to exercise this lane safely against a
  throwaway stack.

Reference: [`HOMELAB.md`](../HOMELAB.md),
[`compose-ops.md`](compose-ops.md).

---

## F. Daily operator quick commands

```
shellforgeai doctor
shellforgeai model doctor
shellforgeai ops status
shellforgeai audit retention
shellforgeai audit cleanup review
shellforgeai compose env-contract --target shellforgeai
shellforgeai compose env-plan --target shellforgeai
```

None of the above mutate anything.

---

## G. Cleanup operator sequence (Docker01-safe)

```
shellforgeai audit cleanup review
shellforgeai audit cleanup prepare --category exports \
    --max-age-days 7 --keep-latest 5
shellforgeai audit cleanup execute-readiness <plan-id>
# STOP HERE unless Hector has explicitly approved.
shellforgeai audit cleanup execute <plan-id> --confirm
shellforgeai audit cleanup report <receipt>
shellforgeai audit cleanup validate <receipt>
```

- Readiness `true` means PR71 gates are satisfied. It does **not**
  mean approval to delete.
- Only `audit cleanup execute <plan-id> --confirm` deletes. Without
  `--confirm` it refuses and lists the required gates.
- Start with the narrow `exports` lane. Avoid broad
  `--include-artifacts` cleanup without item-level review.

Deeper: [`audit-and-cleanup.md`](audit-and-cleanup.md).

---

## H. Compose disposable proof sequence (lab-only, currently blocked)

```
scripts/pr67_disposable_compose_harness.sh up
shellforgeai compose env-contract --target sfai-pr67-compose-web
shellforgeai compose env-plan    --target sfai-pr67-compose-web
scripts/pr68_disposable_compose_restart_proof.sh print-commands
scripts/pr68_disposable_compose_restart_proof.sh run-readiness
```

- Do **not** run proof execution unless `compose env-contract`
  returns `ready_for_optional_disposable_proof=true` and Hector
  approves.
- Do **not** label production `shellforgeai` disposable to satisfy
  the contract. The orchestrator refuses production-looking targets.
- The orchestrator never auto-passes `--execute --confirm`. The
  operator runs `shellforgeai mission compose-restart execute
  <mission-id> --execute --confirm` directly.

Deeper: [`compose-ops.md`](compose-ops.md).

---

## I. Standard PR validation checklist

Repo-local (fixtures/mocks only — no Docker daemon, no root, no
network):

```
ruff format .
ruff check .
python -m compileall src tests
pytest -q
mypy src/shellforgeai tests    # if green in the current tree
```

Docker01 live QA checklist (NewTwo / operator):

1. Take a Proxmox snapshot of the target VM first.
2. Sync the new branch / image to the host.
3. Rebuild / recreate the ShellForgeAI container.
4. Verify source / image / labels match the intended PR.
5. `version` / `doctor` / `model doctor`.
6. Targeted feature QA for the new PR.
7. Safety QA: confirm no execution from `ask`, no broader mutation,
   gates still refuse without `--execute --confirm`.
8. Cleanup any disposable lab leftovers (lab-cases, PR67 harness).
9. Final `doctor` + `audit retention` + disk check.
10. Record merge verdict (go / hold / revert) on the PR.

---

## J. Next roadmap tracks (intent, not commitment)

1. Optional real `/data` cleanup execution against a narrow category,
   only with explicit Hector approval, using the PR74–PR77 chain.
2. Compose environment enablement so the disposable proof becomes
   ready (Compose CLI + Compose plugin in the runtime, readable
   compose-file snapshot). **No gate bypass.**
3. A successful disposable Compose restart proof against the PR67
   harness, only after env-contract is ready.
4. Verification / closure-report polish *after* a successful proof.
5. Compose recreate **preview only** at a later milestone — never
   recreate execution.
6. Production Compose mutation only much later, if ever, and only via
   a new, separately-gated lane with its own narrow allowlist.

Non-goals stay unchanged: no shell, no autopilot, no auto-apply of
model plans, no hidden mutation under workspace trust.

---

## K. What future PRs must preserve

- The Tier-3 triage framing in section A.
- The mutation boundary in section C.
- The safety invariants in section D.
- Cleanup remains scoped to ShellForgeAI-owned metadata under
  `<data_dir>`.
- `ask` never executes mutation.
- Every mutation path emits a receipt and a scoped audit event.
- Production `shellforgeai` stays out of any disposable / restart
  allowlist.

If a future PR needs to broaden any of the above, it must do so
deliberately, in its own PR, with its own gate, its own tests, and
its own documentation update — not as a side effect.
