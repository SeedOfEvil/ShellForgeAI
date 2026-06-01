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
   - Underlying compatibility path: `shellforgeai triage docker` and
     `shellforgeai triage docker detail <target>`. The V2 entrypoint remains
     read-only, ranks suspects deterministically, and prints the first safe
     inspection command.
3. **propose**
   - Future V2 command family, not implemented here.
   - Planned artifact fields: issue, evidence, proposed fix, risk, blast radius,
rollback, and validation.
4. **approve/gate**
   - Future or existing governed policy gate flow, not expanded here.
   - Gate decisions must be explicit and auditable.
5. **apply-preview**
   - Future non-executing command bundle, not implemented here.
   - The bundle should show exact commands, preflight checks, expected output,
rollback, and validation commands for an operator to review.
6. **verify**
   - Current commands include `shellforgeai ops report compare-latest`,
`compare`, export validation commands, and artifact validation commands.
7. **handoff/receipt**
   - Current support includes ops report exports, session summary artifacts,
receipts, and validation reports.

## Golden-path command families

| V2 job | Current command family | Contract |
|---|---|---|
| Status | `status`, `status --brief`, `status --json`; compatibility: `ops report --brief`, `ops report` | CORE / READ_ONLY first operator posture. |
| Triage | `triage`, `triage --brief`, `triage --json`, `triage --target <target>`; compatibility: `triage docker`, `triage docker detail <target>` | Read-only deterministic suspect ranking and first-safe-command flow before any proposal/remediation lane. |
| Propose | Future V2 proposal command | Deterministic proposal artifact; no execution. |
| Gate | Existing/future approval and guard lanes | Explicit, auditable, not natural-language approval. |
| Apply preview | Future V2 apply-preview command | Non-executing bundle only. |
| Verify | `ops report compare/latest`, validation commands | Operator verifies with evidence and artifact deltas. |
| Handoff | report export, session summary, receipts | Portable evidence and receipts without mutation. |

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
