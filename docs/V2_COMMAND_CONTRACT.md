# V2 Command Contract


## Receipt recovery execution

`shellforgeai recipes receipt recovery-execute <receipt_ref> --confirm [--json]` is the confirm-gated governed recovery lane for `docker.disposable_restart` receipts only. It is not true rollback: Docker restart cannot restore the previous process state. The command may only repeat the exact target from a valid governed receipt after receipt validation, target existence check, production/broad-target refusal, and current labels `shellforgeai.disposable=true` plus `shellforgeai.allow_restart=true`. The executor uses an argv list only: `["docker", "restart", "<target>"]`; it never uses `shell=True`, Docker Compose, cleanup, arbitrary remediation, arbitrary rollback, natural-language execution, or model-driven execution.

No-confirm recovery (`recipes receipt recovery-execute <receipt_ref>`) returns a controlled blocked response with `mutation_performed=false` and no restart. Successful recovery writes a recovery receipt and `verify --receipt <recovery_receipt_id> --json` is the first safe follow-up. `recipes receipt recovery-status` and `recipes receipt recovery-validate` are read-only receipt helpers.

## Principle

**One golden path, many compatibility paths.**

ShellForgeAI V2 should feel like a CLI-first Linux/Docker operator knife, not a
toolbox. The golden path should be small, pressure-friendly, deterministic, and
safe by default. Existing compatibility commands can remain, but docs should not
force operators to learn every historical lane before they can get useful
status, triage, proposal, preview, verification, and handoff artifacts.

## Command naming rules

- Prefer verbs operators understand: `status`, `triage`, `propose`, `preview`,
`verify`, and `handoff`.
- Prefer one command family per operator job.
- Avoid adding new nouns unless a genuinely new operator concept exists.
- Avoid duplicate mental models; aliases can hide complexity later without
removing compatibility.
- Keep technical collector names out of normal synthesized answers. Preserve
technical names in `/tools`, `/evidence`, debug, raw, and validation views.
- Future names must make safety state obvious: report, proposal, preview,
validation, receipt, and handoff must not sound like execution.

## Safety rules

- Read-only by default.
- Proposal/preview before apply.
- No execution without an explicit gate.
- No natural-language mutation.
- No arbitrary shell execution.
- No `shell=True` execution surface.
- No broad Docker/Compose mutation from casual commands or asks.
- Workspace trust never lifts policy.
- Unknown slash commands and command-like typos must not call the model or run
anything.

## V2 golden path sketch

1. **status**
   - First command: `shellforgeai status`.
   - Brief/JSON forms: `shellforgeai status --brief` and `shellforgeai status --json`.
   - Underlying compatibility path: `shellforgeai ops report --brief` / `shellforgeai ops report`.
2. **triage**
   - Second command: `shellforgeai triage`.
   - Brief/JSON/detail forms: `shellforgeai triage --brief`,
     `shellforgeai triage --json`, and `shellforgeai triage --target <target>`.
   - Underlying compatibility path: `shellforgeai triage docker`,
     `shellforgeai triage docker --brief` (a safe alias that mirrors
     `triage --brief`), and `shellforgeai triage docker detail <target>`. The
     V2 entrypoint remains read-only, ranks suspects deterministically, and
     prints the first safe inspection command.
   - Consistency contract (PR146): every triage view leads with `Status:` /
     `Risk:` and closes with `Safety: Read-only. No mutation executed.`. With
     suspects, the detail/eligibility drilldown is the first safe command
     (`triage --target <top>` from the entrypoint, `triage docker detail
     <top>` from the compatibility path). With no suspects, the first safe
     command is a read-only status/report command (`shellforgeai status
     --json`) — never a detail command for a suspect that does not exist.
   - Golden path: `status -> triage -> propose -> apply-preview -> verify ->
     handoff`, with `triage --target <target>` / `triage docker detail
     <target>` and gated `remediation eligibility --target <target> --explain`
     available as review drilldowns.
3. **propose**
   - Third command: `shellforgeai propose`.
   - Brief/JSON/target forms: `shellforgeai propose --brief`,
     `shellforgeai propose --json`, `shellforgeai propose --target <target>`,
     and `shellforgeai propose --from-triage`.
   - Contract: read-only deterministic next-action preview only. It summarizes
     likely target, evidence, eligibility, first safe command, and governed
     review/plan-only command when applicable. It does not create a remediation
     plan artifact and never executes cleanup, remediation, rollback,
     Docker/Compose, restart, shell, or natural-language mutation.
   - Eligible disposable targets may show `shellforgeai remediation plan ...` as
     **Plan-only. Does not execute remediation.** Execute commands are never
     shown from `propose`.
4. **apply-preview**
   - Fourth command: `shellforgeai apply-preview`.
   - Brief/JSON/target forms: `shellforgeai apply-preview --brief`,
     `shellforgeai apply-preview --json`, `shellforgeai apply-preview --target
     <target>`, `shellforgeai apply-preview --from-propose`, and optional
     `shellforgeai apply-preview --from-triage`.
   - Contract: read-only execution-boundary preview only. It answers whether an
     action is eligible to preview, the exact target, production/disposable/
     allowlist gates, approval/confirm expectations, rollback/verification
     expectations, and the first safe read-only command. It does **not** apply,
     create a mission, create an apply record, create a remediation receipt, run
     Docker/Compose, restart containers, write a plan artifact, call the model,
     or cross the execution boundary.
5. **verify**
   - Fifth command: `shellforgeai verify`.
   - Brief/JSON/target/source forms: `shellforgeai verify --brief`,
     `shellforgeai verify --json`, `shellforgeai verify --target <target>`,
     `shellforgeai verify --from-status`, `shellforgeai verify --from-triage`,
     `shellforgeai verify --from-propose`, and `shellforgeai verify
     --from-apply-preview`.
   - Receipt-aware forms: `shellforgeai verify --receipt <receipt_ref>`,
     `shellforgeai verify --receipt <receipt_ref> --brief`, and
     `shellforgeai verify --receipt <receipt_ref> --json`; the recipe namespace
     also exposes `shellforgeai recipes receipt verify <receipt_ref> [--json]`.
   - Rollback-preview forms: `shellforgeai recipes receipt rollback-preview
     <receipt_ref> [--json]` and optional top-level `shellforgeai
     rollback-preview --receipt <receipt_ref> [--json]`. This is a read-only
     receipt posture step: it explains whether true rollback exists, the
     future recovery gates, and the first safe verify command; it never
     executes rollback or restart.
   - Current-state contract: read-only current-state verification. It
     collects/reuses deterministic status/triage evidence, reports `ok`,
     `degraded`, `blocked`, or `unknown`, lists evidence/limitations, and
     suggests a first safe command. `--from-propose` and `--from-apply-preview`
     only name the previous context; they do not prove an action was executed.
   - Receipt contract: read-only post-execution receipt verification. It loads a
     ShellForgeAI-owned governed recipe execution receipt, validates structure,
     manifest/checksum/safety signals, identifies the recorded recipe/target/argv
     and execution result, reports the receipt's recorded post-check status, and
     suggests the next safe read-only command. It verifies what the receipt says
     happened; it does not re-run the recipe or assume current state equals the
     recorded state.
   - Both verify modes do not apply, create a receipt, create a mission or plan,
     execute remediation/rollback/cleanup, run Docker/Compose, restart
     containers, call the model, retry, roll back, or perform natural-language
     mutation.
   - Command ownership: the top-level Typer handler is registered from
     `shellforgeai.commands.verify`; `cli.py` remains the root app and shared
     helper owner. This is a behavior-preserving module split, not a new verify
     mode. Future command-module refactors should run the PR184
     command-surface golden guardrail.
6. **handoff**
   - Sixth command: `shellforgeai handoff`.
   - Brief/JSON/save/source forms: `shellforgeai handoff --brief`,
     `shellforgeai handoff --json`, `shellforgeai handoff --save`,
     `shellforgeai handoff --target <target>`, and `shellforgeai handoff
     --from-status` / `--from-triage` / `--from-propose` /
     `--from-apply-preview` / `--from-verify`.
   - Contract: read-only operator handoff packet only. It collects/reuses the
     deterministic status/triage/propose/apply-preview/verify posture, reports a
     concise current status, risk, suspect count, proposal/apply-preview/verify
     state, the first safe next command, and what was **not** done. It does
     **not** execute fixes, create an executable mission, create an apply record
     or remediation receipt, imply remediation happened, restart containers, run
     Docker/Compose, call the model, or assume any action was applied. When no
     action was applied it states `No applied action was detected or assumed`
     and `This handoff is a read-only operator summary`.
   - `--save` writes only a ShellForgeAI-owned artifact under
     `<data_dir>/v2_handoffs/<handoff_id>/` (`handoff.json`, `handoff.md`,
     `manifest.json`) with checksums and explicit non-mutating safety flags. It
     never writes outside that ShellForgeAI-owned path and never mutates Docker,
     Compose, files, services, containers, or host state.
   - **Handoff artifact lifecycle** (read-only except ShellForgeAI-owned writes):
     `shellforgeai handoff --save` → `shellforgeai handoff validate
     <handoff_ref>` → `shellforgeai handoff export <handoff_ref>` →
     `shellforgeai handoff export-validate <export_ref>`, each with an optional
     `--json` strict mode (`v2_handoff`, `v2_handoff_validate`,
     `v2_handoff_export`, `v2_handoff_export_validate`).
     - `validate` is read-only: it checks required files, JSON parse,
       `schema_version`, `mode=v2_handoff`, manifest, checksum match, the
       non-mutating safety block, and obvious secret leakage. Missing/unsafe
       refs return a controlled `not_found`/`failed` with a non-zero exit and no
       traceback.
     - `export` copies a validated handoff into a portable, ShellForgeAI-owned
       export under `<data_dir>/exports/export_<handoff_id>/`
       (`handoff.json`, `handoff.md`, `manifest.json`, `export-manifest.json`).
       It records an `artifact_export_only=true` / `arbitrary_path_write=false`
       safety block, reruns no collectors, calls no model, mutates nothing, and
       is idempotent (`existing: true`) when the export already exists and
       validates. It accepts a handoff id or a ShellForgeAI-owned path only.
     - `export-validate` is read-only: it checks the export's required files,
       export manifest, source manifest, checksum match, the source and export
       safety blocks, and secret leakage.
   - **Handoff artifact history/compare** (strictly read-only):
     `shellforgeai handoff history`, `shellforgeai handoff compare
     <before_ref> <after_ref>`, and `shellforgeai handoff compare-latest`, each
     with an optional `--json` strict mode (`v2_handoff_history`,
     `v2_handoff_compare`, `v2_handoff_compare_latest`).
     - `history` lists recent saved handoffs (latest first) with id, timestamp,
       status, risk, target, and quick local validity. Empty history returns a
       controlled `empty` status with `shellforgeai handoff --save` as the first
       safe command (no traceback). `--limit N` bounds the rendered list.
     - `compare` loads two saved handoffs by id or ShellForgeAI-owned path and
       reports drift in status/risk/target/current_status, the golden-path stage
       summaries, the first safe command, safe-next commands, limitations,
       warnings, and safety flags, including critical safety drift. `--only-changed`
       suppresses stable items; `--include-stable` lists them. Missing/unsafe/
       malformed refs return a controlled `not_found`/`failed` with a non-zero
       exit and no traceback.
     - `compare-latest` compares the two most recent saved handoffs or returns a
       controlled `not_enough_history` status with `shellforgeai handoff --save`
       as the first safe command. None of these rerun collectors, call the model,
       execute shell, write artifacts, or mutate Docker/Compose/host state.
7. **approve/gate**
   - Future or existing governed policy gate flow, not expanded here.
   - Gate decisions must be explicit and auditable.
8. **receipt/export**
   - Current support includes ops report exports, session summary artifacts,
receipts, and validation reports.

## Golden-path command families

| V2 job | Current command family | Contract |
|---|---|---|
| Status | `status`, `status --brief`, `status --json`; compatibility: `ops report --brief`, `ops report` | CORE / READ_ONLY first operator posture. |
| Triage | `triage`, `triage --brief`, `triage --json`, `triage --target <target>`; compatibility: `triage docker`, `triage docker --brief`, `triage docker detail <target>` | Read-only deterministic suspect ranking with consistent `Status:`/`Risk:`/`Safety:` wording and a first-safe-command flow before any proposal/remediation lane. |
| Propose | `propose`, `propose --brief`, `propose --json`, `propose --target <target>`, `propose --from-triage` | Read-only deterministic next-action proposal preview; no plan artifact and no execution. |
| Apply preview | `apply-preview`, `apply-preview --brief`, `apply-preview --json`, `apply-preview --target <target>`, `apply-preview --from-propose`, `apply-preview --from-triage` | Read-only execution-boundary preview; no apply, mission, plan artifact, remediation receipt, Docker/Compose action, restart, shell, model call, or mutation. |
| Verify | `verify`, `verify --brief`, `verify --json`, `verify --target <target>`, `verify --from-status`, `verify --from-triage`, `verify --from-propose`, `verify --from-apply-preview` | Read-only current-state verification; no action/receipt assumed and no execution. |
| Handoff | `handoff`, `handoff --brief`, `handoff --json`, `handoff --save`, `handoff --target <target>`, `handoff --from-status`, `handoff --from-triage`, `handoff --from-propose`, `handoff --from-apply-preview`, `handoff --from-verify` | Read-only operator handoff packet summarizing the deterministic golden-path posture and first safe command. It does not execute fixes, create an executable mission/apply record/receipt, imply remediation happened, or mutate Docker/Compose/host state. `--save` writes only a ShellForgeAI-owned artifact under `<data_dir>/v2_handoffs/<handoff_id>/`. |
| Handoff artifact lifecycle | `handoff --save`, `handoff validate <handoff_ref>`, `handoff export <handoff_ref>`, `handoff export-validate <export_ref>` (each `--json`) | Read-only deterministic handoff artifact lifecycle. Save/export write only ShellForgeAI-owned artifacts (`<data_dir>/v2_handoffs/...`, `<data_dir>/exports/export_...`); validate/export-validate are strictly read-only. No collector rerun, model call, Docker/Compose mutation, restart, shell, arbitrary command, or natural-language execution. Missing/malformed refs fail cleanly (non-zero, no traceback). |
| Handoff artifact history/compare | `handoff history [--limit N]`, `handoff compare <before_ref> <after_ref>`, `handoff compare-latest` (each `--json`; compare/compare-latest accept `--only-changed`/`--include-stable`) | Strictly read-only history and drift compare for saved handoff artifacts. `history` lists recent saved handoffs (empty → controlled `empty`); `compare` reports status/risk/target/current_status/golden-path/first-safe-command/safe-next-commands/limitations/warnings/safety-flag drift; `compare-latest` compares the newest two (or `not_enough_history`). No artifact writes, collector rerun, model call, shell, or Docker/Compose/host mutation. Missing/malformed refs fail cleanly (non-zero, no traceback). |
| Recipe registry / eligibility / preflight | `recipes`, `recipes --json`, `recipes list`, `recipes inspect <recipe_id>`, `recipes eligibility --recipe <recipe_id> --target <target>`, `recipes preflight --recipe docker.disposable_restart --target <target> [--save] [--json]`, `recipes preflight validate <preflight_ref> [--json]`, `safe-actions [--target <target>]` | Read-only locked-toolbox map for future governed execution. Lists recipe status/mutation class/gates, evaluates exact-target eligibility/blockers, and can save/validate a ShellForgeAI-owned preflight packet for `docker.disposable_restart`. Preflight sits between eligibility and any future execute lane: it records target labels, blockers, future confirm/receipt/verification/rollback gates, and bounded argv preview only with `execution_available=false`, `command_preview_only=true`, and `command_executed=false`. No recipe execution, cleanup, remediation, rollback, Docker/Compose mutation, restart, shell, model call, arbitrary command, or natural-language execution. |
| Gate | Existing/future approval and guard lanes | Explicit, auditable, not natural-language approval. |
| Receipt/export | report export, session summary, receipts | Portable evidence and receipts without mutation. |

## Support commands

Support commands can stay documented, but below the golden path:

- V1 readiness and packet lifecycle.
- Interactive summary save/validate/history/compare/export lifecycle.
- Remediation self-test and eligibility explanations.
- Audit retention and cleanup review/plan/archive/validate/report/readiness.
- Tools/inspect/debug views for advanced operators and tests.
- Validation helper scripts.

## Compatibility policy

- Governed execution frontier: `recipe registry -> eligibility -> preflight packet -> explicit confirm boundary -> execution receipt -> verification -> rollback posture`. Current behavior stops at the read-only `docker.disposable_restart` preflight packet and does not add execution.
- Existing commands can remain.
- Documentation should push the V2 golden path first.
- Aliases may hide complexity later, but alias work requires a separate PR.
- Deprecation candidates are documentation-only until a dedicated deprecation PR
updates code, docs, tests, and migration guidance.
- Compatibility paths must not create a second casual mutation story.

## Anti-bloat rules

- Do not add a command because an existing support command has an awkward name;
consider documentation, aliasing, or consolidation first.
- Do not add a new noun if a current golden-path verb can carry the workflow.
- Do not promote lab/proof/harness/internal commands to the operator first
screen.
- Do not expose implementation structure as product structure.
- Do not expand into GUI/dashboard/platform work in V2.
- Do not add runtime behavior in command-contract PRs.

## V2 non-goals

- Broad autonomous remediation is out of V2.
- GUI/dashboard/platform expansion is out of scope.
- SIEM/monitoring platform behavior is out of scope.
- Secrets manager behavior is out of scope.
- Arbitrary shell executor behavior is out of scope.
- Production mutation from natural language is out of scope.
- Broad Docker/Compose mutation is out of scope.

## Dangerous command presentation rule

Dangerous strings, if mentioned in docs, must appear only in governed,
non-goal, or refused context. They are not V2 golden-path commands. Dangerous governed/non-goal/refused examples:

- `docker restart` — dangerous; governed/non-goal/refused context only
- `docker compose restart` — dangerous; governed/non-goal/refused context only
- `cleanup execute --confirm` — dangerous; governed/non-goal/refused context only
- `remediation execute --confirm` — dangerous; governed/non-goal/refused context only
- `rollback-execute --confirm` — dangerous; governed/non-goal/refused context only

`shellforgeai status` is the first V2 golden-path command and is CORE / READ_ONLY: it renders concise human status by default, strict JSON with `--json`, and writes no artifacts unless the operator uses the separate `ops report --save` compatibility path.

The V2 casual command path is status, triage, propose, approve/gate,
apply-preview, verify, and handoff/receipt — not execution expansion.

## Governed recipe execution boundary

`recipes execute <preflight_ref> --confirm` is the first V2 governed execution boundary and supports only `docker.disposable_restart`. It requires a ShellForgeAI-owned saved preflight packet that validates successfully, `recipe_id=docker.disposable_restart`, `status=preflight_ready`, an exact target that is still present, current labels `shellforgeai.disposable=true` and `shellforgeai.allow_restart=true`, a non-production/non-broad target, and explicit `--confirm`. The only command it may run is the argv list `docker restart <exact-target>`; it does not use `shell=True`.

`recipes execute <preflight_ref> --confirm --json` emits strict JSON with action, verification, receipt, rollback posture, and safety fields. Blocked paths return nonzero, do not run Docker, and report `mutation_performed=false`, `container_restarted=false`, and `command_executed=false`. Successful execution writes `recipe-receipt.json`, `recipe-receipt.md`, and `manifest.json` under ShellForgeAI's recipe receipt data path.

`recipes receipt validate <receipt_ref> [--json]` validates receipt files, checksums, recipe/target metadata, verification presence, and safety flags. Receipt validation is read-only. Production restart, Docker Compose mutation, cleanup execution, remediation execution outside this named recipe semantics, rollback execution, arbitrary shell, and natural-language execution remain refused.

`recipes receipt rollback-preview <receipt_ref> [--json]` loads an existing governed receipt from ShellForgeAI-owned receipt storage, validates enough receipt structure to trust recipe/target/safety metadata, and renders rollback posture/gates. For `docker.disposable_restart`, it must state that no true state rollback exists for a container restart. A bounded recovery action may only be a future exact-target disposable restart in a separate confirm-gated lane, with disposable/allow_restart labels rechecked at execution time, a rollback/recovery receipt required, and post-rollback verification required. Production targets are blocked. The command is read-only: it does not execute rollback, retry the recipe, restart a container, create a rollback receipt, call Docker/Compose, call shell, call the model, or mutate host/container state.

Rollback posture for this recipe is not true undo: bounded recovery is a future repeat exact-target restart requiring explicit confirmation; automatic rollback is disabled and rollback-preview executes no rollback.


### Governed receipt audit/history layer

Governed recipe receipts now have a read-only audit surface after execute, verify, rollback-preview, and recovery-execute:

```bash
shellforgeai recipes receipt audit [--target <target>] [--recipe <recipe_id>] [--limit 20] [--include-exports] [--include-compare-summary] [--json]
shellforgeai recipes receipt integrity [--target <target>] [--recipe <recipe_id>] [--limit 50] [--include-exports] [--include-audit-bundles] [--json]
shellforgeai recipes receipt history [--limit 10] [--json]
shellforgeai recipes receipt inspect <receipt_ref> [--json]
shellforgeai recipes receipt export <receipt_ref> [--json]
shellforgeai recipes receipt export-validate <export_ref> [--json]
shellforgeai recipes receipt compare <before_receipt_ref> <after_receipt_ref> [--json|--only-changed]
shellforgeai recipes receipt compare-latest [--json]
```

`integrity` reads ShellForgeAI-owned receipt artifacts and, only when requested, existing receipt exports and audit bundles. JSON mode emits strict JSON with `mode=v2_recipe_receipt_integrity`, `read_only=true`, `mutation_performed=false`, filters, summary counters, check statuses, findings, warnings, first safe command, safe next commands, and safety booleans. It validates required files, JSON parsing, manifest/checksum consistency where available, recovery original linkage, supported receipt shapes, and unsafe safety flags. Findings cover malformed JSON, missing required files, checksum failures, missing original receipts, unsupported artifacts, safety drift, and production restart records. It never creates exports/bundles, repairs/deletes artifacts, executes recipes or receipts, recovers, rolls back, restarts containers, calls Docker/Compose, uses `shell=True`, performs arbitrary command execution, accepts natural-language mutation, or calls a model.

`audit` reads only ShellForgeAI-owned receipt artifacts and summarizes execution/recovery chains, original/recovery links, status, verification status, target, recipe, timestamps, and safety flags. It reports anomalies such as malformed receipts, unsupported recipes, missing original receipts, failed verification, production restart flags, Docker Compose flags, `shell_true`, arbitrary command execution, and natural-language execution; it never executes recipes, reruns receipts, restarts containers, calls Docker/Compose, creates exports, runs compare, or calls a model. History, inspect, export-validate, compare, and compare-latest read only ShellForgeAI-owned receipt/export artifacts. Export first validates a ShellForgeAI-owned receipt and writes only a portable receipt export bundle under ShellForgeAI-owned export metadata; it does not inspect Docker, execute verify, recover, rollback, remediate, clean up, restart, call a model, or run shell commands. JSON modes emit strict JSON with `read_only`, `mutation_performed`, safety flags, warnings, and receipt lineage fields for recovery receipts.


## Governed receipt audit bundle export

`shellforgeai recipes receipt audit-bundle [--json] [--target <target>] [--recipe docker.disposable_restart] [--limit N] [--include-exports] [--include-compare-summary]` creates a bounded support packet from existing ShellForgeAI-owned receipt audit/history evidence. The packet is written only under `<data_dir>/exports/receipt-audit-bundles/<audit_bundle_id>/` and contains `audit-bundle.json`, `audit-bundle.md`, `receipt-audit.json`, `receipt-history.json`, `manifest.json`, and `checksums.json`; optional local summary files are `receipt-compare-summary.json` and `receipt-export-index.json`. JSON output is strict JSON with `mode=v2_recipe_receipt_audit_bundle`, `artifact_export_only=true`, `read_only=true`, and `mutation_performed=false`.

`shellforgeai recipes receipt audit-bundle-validate <bundle_ref> [--json]` resolves only ShellForgeAI-owned bundle ids/paths, rejects traversal/non-owned paths, checks required files, parses JSON files, verifies manifest consistency, and validates SHA256 checksums. It returns `ok`, `failed`, or `not_found` and never executes recipes or receipts. Both commands forbid cleanup/remediation/rollback/recovery execution, Docker/Compose mutation, container/production restart, `shell=True`, arbitrary command execution, natural-language execution, and model calls.
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

