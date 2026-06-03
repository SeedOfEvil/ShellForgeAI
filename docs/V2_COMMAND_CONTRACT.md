# V2 Command Contract

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
   - Contract: read-only current-state verification only. It collects/reuses
     deterministic status/triage evidence, reports `ok`, `degraded`, `blocked`,
     or `unknown`, lists evidence/limitations, and suggests a first safe
     command. It does not apply, create a receipt, create a mission or plan,
     execute remediation/rollback/cleanup, run Docker/Compose, restart
     containers, call the model, or assume any action happened. `--from-propose`
     and `--from-apply-preview` only name the previous context; they do not
     prove an action was executed unless a future receipt/artifact is supplied.
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
     Compose, files, services, containers, or host state. Validate/export of
     saved handoffs is deferred to a later PR.
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
