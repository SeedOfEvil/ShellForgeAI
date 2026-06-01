# Command Surface Audit

## Purpose

This audit is the V2 planning map for ShellForgeAI's command surface. It does
not add, remove, deprecate, or change commands. It documents the current CLI as
a **CLI-first Linux/Docker operator knife**: inspect safely, produce
evidence-backed reports, preserve/export/compare reports, route common operator
asks deterministically, and refuse or gate mutation.

V2 should keep one clear operator path while preserving compatibility for the
wider V1/post-V1 surface.

## Classification legend

- **CORE** — part of the primary operator knife workflow and expected in the V2
golden path.
- **SUPPORT** — useful operator/support workflow, but not first-screen golden
path.
- **GOVERNED** — safe only behind explicit plan, validate, preflight, approval,
receipt, or environment gates; not casual V2.
- **LEGACY** — older command path kept for compatibility; not recommended as new
V2 documentation spine.
- **INTERNAL-ISH** — mainly for tests, artifact internals, lab QA, or advanced
operators; not the primary user-facing path.
- **ALIAS / COMPATIBILITY** — supported spelling or compatibility path that
should not create a new mental model.
- **CANDIDATE_FOR_ALIAS_OR_DEPRECATION** — docs-only flag for a command or naming
pattern that may be folded into a simpler V2 workflow later; requires a separate
PR before any code deprecation.
- **OUT_OF_V2** — behavior explicitly not in V2.

Safety classes used below:

- **READ_ONLY** — no Docker/system mutation and no ShellForgeAI artifact write.
- **ARTIFACT_WRITE** — writes ShellForgeAI-owned reports, summaries, exports, or
metadata only.
- **PLAN_OR_PREVIEW_ONLY** — produces/validates plans, proposals, previews, or
checks; no execution.
- **METADATA_MUTATION / GATED** — mutates ShellForgeAI-owned metadata only behind
explicit archive/validate/confirm gates.
- **DISPOSABLE_MUTATION / GATED** — lab/disposable mutation lane only behind
explicit environment, allowlist, preflight, and confirm gates.
- **REFUSED_BY_DEFAULT** — natural-language or broad mutation request is refused
and rerouted to safe inspection.
- **OUT_OF_SCOPE** — not part of ShellForgeAI V2.

## V2 golden path summary

1. **Status** — `shellforgeai status`, then `shellforgeai status --brief` or the underlying `shellforgeai ops report` compatibility path.
2. **Triage** — `shellforgeai triage docker`, `shellforgeai triage docker detail <target>`, and `shellforgeai diagnose <target>`.
3. **Proposal** — future deterministic proposal artifact, not implemented here:
issue, evidence, proposed fix, risk, blast radius, rollback, validation.
4. **Approval / Gate** — future policy gate/approval flow, not implemented here.
5. **Apply Preview** — future non-executing command bundle: exact commands,
preflight checks, expected output, rollback, and validation commands.
6. **Operator Verification** — `shellforgeai ops report compare-latest`,
`shellforgeai ops report compare <before> <after>`, summary/receipt artifacts,
and validation commands.

## Core commands

| Command / family | Classification | Current status | Safety class | V2 role | Notes |
|---|---|---|---|---|---|
| `shellforgeai doctor` | CORE | Active | READ_ONLY | Status | Runtime health baseline and quick sanity check. |
| `shellforgeai model doctor` | CORE | Active | READ_ONLY | Status | Provider diagnostics; synthesis-only model posture. |
| `shellforgeai v1 check` | CORE | Active | READ_ONLY / ARTIFACT_WRITE for full validation artifacts | Status/readiness | V1 readiness remains a compatibility confidence gate during V2. |
| `shellforgeai status` | CORE | Active | READ_ONLY | Status | First V2 golden-path entrypoint; concise wrapper around the ops report ranking path, with `--brief` and strict `--json`. |
| `shellforgeai ops report --brief` | CORE / ALIAS / COMPATIBILITY | Active | READ_ONLY | Status | Underlying pressure-mode command kept for compatibility; `status --brief` mirrors it. |
| `shellforgeai ops report` | CORE | Active | READ_ONLY | Status | Evidence-backed operator report view. |
| `shellforgeai ops report save/validate/history/compare/export` | CORE | Active | READ_ONLY / ARTIFACT_WRITE | Verify/handoff | Preserves, validates, compares, and exports operator reports. Current spellings include `--save`, `validate`, `history`, `compare`, `compare-latest`, `export`, `export-validate`, and `compare-export`. |
| `shellforgeai triage docker` | CORE | Active | READ_ONLY | Triage | Deterministic Docker suspect ranking. |
| `shellforgeai triage docker detail <target>` | CORE | Active | READ_ONLY | Triage | Evidence-backed suspect drilldown. |
| `shellforgeai diagnose <target>` | CORE | Active | READ_ONLY / ARTIFACT_WRITE with save flags | Triage | Read-only diagnostics for known operator targets and symptoms. |
| `shellforgeai ask` deterministic report/refusal routes | CORE | Active | READ_ONLY / REFUSED_BY_DEFAULT | Status/triage/refusal | Common operator asks route to reports/triage or deterministic mutation refusal before model synthesis. |
| Interactive `help`, `/help`, `?`, `commands`, `/summary` | CORE | Active | READ_ONLY / ARTIFACT_WRITE when saving summaries | Handoff | Safe interactive discovery and session summary lifecycle; not a shell. |

## Support commands

| Command / family | Classification | Current status | Safety class | V2 role | Notes |
|---|---|---|---|---|---|
| `shellforgeai v1 packet save/validate/history/compare/export` | SUPPORT | Active | READ_ONLY / ARTIFACT_WRITE | Compatibility evidence packet | Packet lifecycle remains useful for release/readiness handoff; not first-screen V2. Current spellings include `v1 packet --save`, `validate`, `history`, `compare`, `compare-latest`, `export`, and `export-validate`. |
| `shellforgeai session summary save/validate/history/compare/export` | SUPPORT | Active | READ_ONLY / ARTIFACT_WRITE | Handoff/receipt | Interactive session summary artifact lifecycle. Current spellings include `/summary --save`, `session summary validate`, `history`, `compare`, `compare-latest`, `export`, `export-validate`, and `compare-export`. |
| `shellforgeai remediation self-test` | SUPPORT | Active | READ_ONLY | Lane confidence | Validates governed remediation support without executing mutation. |
| `shellforgeai audit retention` | SUPPORT | Active | READ_ONLY | Metadata hygiene | Shows retention posture; not the V2 golden path. |
| `shellforgeai audit cleanup review` | SUPPORT | Active | READ_ONLY | Metadata hygiene | Review-only cleanup posture. Execution remains governed, not casual. |
| `shellforgeai audit cleanup prepare/plan/archive/validate/report/execute-readiness` | SUPPORT | Active | READ_ONLY / ARTIFACT_WRITE | Metadata hygiene | Plan/archive/validate/report/readiness support for ShellForgeAI-owned metadata cleanup; includes `audit cleanup plan`, `audit cleanup archive`, and `audit cleanup validate`. |
| `shellforgeai audit timeline/show/validate/index/search/archive/archive-validate` | SUPPORT | Active | READ_ONLY / ARTIFACT_WRITE for archive/index writes | Audit navigation | Useful audit trail and export navigation; not first-screen V2. |
| `shellforgeai tools list/describe` | SUPPORT | Active | READ_ONLY | Explainability | Technical collector names stay here and in raw/debug views. |
| `shellforgeai inspect host/service` | SUPPORT | Active | READ_ONLY | Diagnostics | Older direct inspection path; useful but not primary V2 mental model. |
| `shellforgeai logs <service>` | SUPPORT | Active | READ_ONLY | Diagnostics | Focused log view; V2 docs should usually prefer `diagnose`/`triage`. |
| `shellforgeai export` / `shellforgeai validate-export` | SUPPORT | Active | ARTIFACT_WRITE / READ_ONLY | Handoff | Generic artifact export helpers. |
| `shellforgeai self-test commands` | SUPPORT | Active | READ_ONLY | Validation helper | Contract helper for command safety checks. |
| `./scripts/v1_validate.sh --quick` | SUPPORT | Active | READ_ONLY / ARTIFACT_WRITE by mode | Validation helper | Scripted validation lane; not a runtime command. |

## Governed commands

| Command / family | Classification | Current status | Safety class | V2 role | Notes |
|---|---|---|---|---|---|
| `shellforgeai remediation eligibility` | GOVERNED | Active | READ_ONLY | Support only | Explains whether a governed lane could apply; safe to mention, but not a fixer. |
| `shellforgeai remediation plan` | GOVERNED | Active | PLAN_OR_PREVIEW_ONLY | Not golden path | Proposal-style planning lane; no casual execution. |
| `shellforgeai remediation validate` | GOVERNED | Active | PLAN_OR_PREVIEW_ONLY | Not golden path | Validates remediation artifacts. |
| `shellforgeai remediation preflight` | GOVERNED | Active | PLAN_OR_PREVIEW_ONLY | Not golden path | Preflight only. |
| `shellforgeai remediation execute` | GOVERNED | Active | DISPOSABLE_MUTATION / GATED | Not golden path | Must remain gated; `remediation execute --confirm` is governed context only, never a casual V2 command. |
| `shellforgeai remediation receipt validate` | GOVERNED | Active | READ_ONLY | Support only | Receipt validation for governed lanes. |
| `shellforgeai remediation report/bundle/bundle-validate/audit/status` | GOVERNED | Active | READ_ONLY / ARTIFACT_WRITE | Support only | Governed artifact and receipt support. |
| `shellforgeai remediation rollback-preflight/rollback-validate/rollback-status` | GOVERNED | Active | PLAN_OR_PREVIEW_ONLY | Support only | Rollback-related checks and status; no casual execution. |
| `shellforgeai remediation rollback-execute` | GOVERNED | Active | DISPOSABLE_MUTATION / GATED | Not golden path | `rollback-execute --confirm` belongs only in governed/disposable context. |
| `shellforgeai rollback preview/validate/show` | GOVERNED | Active | PLAN_OR_PREVIEW_ONLY | Support only | Rollback preview/validation family; not an apply lane. |
| `shellforgeai approvals create/list/show/approve/reject/cancel/archive/validate` | GOVERNED | Active | ARTIFACT_WRITE | Gate/support | Approval metadata is a gate, not execution. |
| `shellforgeai approvals propose-restart/restart-plan` | GOVERNED | Active | PLAN_OR_PREVIEW_ONLY | Compatibility/support | Historical restart proposal helpers; consider simplification for V2. |
| `shellforgeai actions compile/show/validate` | GOVERNED | Active | PLAN_OR_PREVIEW_ONLY | Support only | Review-only action records for gated workflows. |
| `shellforgeai guard check/check-actions/check-export/show` | GOVERNED | Active | READ_ONLY / ARTIFACT_WRITE reports | Gate/support | Freshness/drift guard for existing artifacts. |
| `shellforgeai apply` | GOVERNED | Active | PLAN_OR_PREVIEW_ONLY; narrow lab gates if execute flags/environment allow | Apply-preview precursor | V2 should document preview semantics first; execution is not a casual path. |
| `shellforgeai mission restart prepare/status/checklist/validate/report/export/validate-export` | GOVERNED | Active | PLAN_OR_PREVIEW_ONLY / ARTIFACT_WRITE | Support only | Mission checklist/receipt path. |
| `shellforgeai mission restart execute` | GOVERNED | Active | DISPOSABLE_MUTATION / GATED | Not golden path | Explicit execute gate only; not V2 casual command. |
| `shellforgeai mission compose-restart prepare/status/checklist/validate` | GOVERNED | Active | PLAN_OR_PREVIEW_ONLY / ARTIFACT_WRITE | Support only | Compose mission support for governed/disposable lane. |
| `shellforgeai mission compose-restart execute` | GOVERNED | Active | DISPOSABLE_MUTATION / GATED | Not golden path | Disposable Compose lane only. |
| `shellforgeai compose restart-preview/propose-restart` | GOVERNED | Active | PLAN_OR_PREVIEW_ONLY | Support only | Preview/proposal only; no Compose mutation from ask. |
| `shellforgeai audit cleanup execute` | GOVERNED | Active | METADATA_MUTATION / GATED | Support only | ShellForgeAI-owned metadata only; `cleanup execute --confirm` is governed context only with archive/validate/confirm gates. |
| `shellforgeai audit prune --execute --confirm` | GOVERNED | Active | METADATA_MUTATION / GATED | Legacy/support | Older metadata prune lane; not V2 golden path. |

## Legacy/internal-ish commands

| Command / family | Classification | Current status | Safety class | V2 role | Notes |
|---|---|---|---|---|---|
| `shellforgeai version` | ALIAS / COMPATIBILITY | Active | READ_ONLY | Support | Useful sanity check; `doctor`/brief report should be V2 status spine. |
| `shellforgeai research` | LEGACY | Active | READ_ONLY / model synthesis | Out of golden path | General research is not the operator knife spine. Needs review before V2 prominence. |
| `shellforgeai plan` | LEGACY | Active | READ_ONLY / model synthesis | Out of golden path | Generic planning risks duplicate mental model with future `propose`/`preview`. |
| `shellforgeai runbook` / `shellforgeai validate-runbook` | LEGACY | Active | ARTIFACT_WRITE / READ_ONLY | Compatibility | Earlier runbook workflow; may fold into V2 proposal/handoff language later. |
| `shellforgeai compose inspect/list/env-check/env-contract/env-plan` | INTERNAL-ISH | Active | READ_ONLY / ARTIFACT_WRITE for env-plan | Support | Advanced Compose context and lab contract checks; not a platform expansion. |
| `shellforgeai triage docker snapshot validate/export/compare/compare-export/export-validate/timeline` | INTERNAL-ISH | Active | READ_ONLY / ARTIFACT_WRITE | Support | Snapshot artifact internals and advanced comparisons. |
| `shellforgeai audit index validate` | INTERNAL-ISH | Active | READ_ONLY | Support | Artifact/index integrity check. |
| `scripts/pr67_disposable_compose_harness.sh` / `scripts/pr68_disposable_compose_restart_proof.sh` | INTERNAL-ISH | Active | Lab harness | Lab QA only | External proof helpers, not ShellForgeAI runtime commands. |

## Alias/deprecation candidates

| Command / family | Classification | Current status | Safety class | V2 role | Notes |
|---|---|---|---|---|---|
| `ops status` vs `ops report --brief` | CANDIDATE_FOR_ALIAS_OR_DEPRECATION | Active | READ_ONLY | Status | Consider one V2 status mental model; do not remove here. |
| `research`, `plan`, `runbook` | CANDIDATE_FOR_ALIAS_OR_DEPRECATION | Active | READ_ONLY / ARTIFACT_WRITE | Compatibility | May fold under future `propose`, `preview`, or handoff language. |
| `approvals propose-restart`, `approvals restart-plan`, `compose propose-restart`, `compose restart-preview` | CANDIDATE_FOR_ALIAS_OR_DEPRECATION | Active | PLAN_OR_PREVIEW_ONLY | Governed support | Multiple restart/proposal nouns may become aliases behind one V2 proposal/preview workflow. |
| `audit prune` and `audit cleanup ...` | CANDIDATE_FOR_ALIAS_OR_DEPRECATION | Active | METADATA_MUTATION / GATED where executed | Support | Prefer one cleanup mental model in docs; code changes require a separate PR. |
| `rollback ...` and `remediation rollback-*` | CANDIDATE_FOR_ALIAS_OR_DEPRECATION | Active | PLAN_OR_PREVIEW_ONLY / DISPOSABLE_MUTATION where executed | Support | Rollback naming should be simplified before any V2 apply-preview lane is promoted. |
| `triage docker snapshot ...` | CANDIDATE_FOR_ALIAS_OR_DEPRECATION | Active | READ_ONLY / ARTIFACT_WRITE | Support | Snapshot lifecycle may remain advanced/internal while reports carry golden-path comparisons. |

## Out-of-V2/non-goals

| Command / family | Classification | Current status | Safety class | V2 role | Notes |
|---|---|---|---|---|---|
| Broad autonomous remediation | OUT_OF_V2 | Not a V2 goal | OUT_OF_SCOPE | None | ShellForgeAI is not autopilot/self-healing infrastructure. |
| Production restart from natural language | OUT_OF_V2 | Refused | REFUSED_BY_DEFAULT | None | Natural-language mutation remains refused; use evidence/proposal/gates. |
| Arbitrary shell execution | OUT_OF_V2 | Refused | OUT_OF_SCOPE | None | No arbitrary command runner and no `shell=True` execution surface. |
| Broad Docker mutation such as `docker restart` | OUT_OF_V2 | Refused except narrow governed lab lanes | OUT_OF_SCOPE / GATED | None | Broad Docker restart is not V2. |
| Broad Compose mutation such as `docker compose restart` | OUT_OF_V2 | Refused except narrow disposable gates | OUT_OF_SCOPE / GATED | None | No casual Compose restart/up/down/recreate path. |
| GUI/dashboard/platform expansion | OUT_OF_V2 | Not planned for V2 | OUT_OF_SCOPE | None | Keep CLI-first knife posture; do not become a platform. |
| SIEM/monitoring/secrets manager expansion | OUT_OF_V2 | Not planned for V2 | OUT_OF_SCOPE | None | Avoid platform sprawl. |

## Safety notes

- Read-only by default.
- Normal synthesized answers hide internal collector names; `/tools`,
`/evidence`, debug, and raw views may show technical names.
- Unknown slash commands and ShellForgeAI-like typos must not call the model or
execute anything.
- Proposal, preview, approval, rollback preview, report, export, status, and ask
routes do not execute mutation.
- Execution-shaped commands are governed only. They require explicit gates and
must not appear as casual V2 examples.
- V2 docs should keep dangerous examples in governed, non-goal, or refusal
context only: `docker restart`, `docker compose restart`, `cleanup execute --confirm`,
`remediation execute --confirm`, and `rollback-execute --confirm`.
- This audit is documentation only; it does not implement `propose`, `gate`, or
`apply-preview` commands.

## Open questions for V2

- Should `ops report --brief` become the only promoted pressure-mode status
entry, with `ops status` kept as compatibility/support?
- Should future proposal language consolidate older `plan`, `runbook`, restart
proposal, and remediation plan nouns?
- Should summary/receipt artifacts share one public `handoff` vocabulary while
keeping existing command compatibility?
- Which governed execution lanes should remain documented only in safety docs
rather than command-first operator docs?
- What is the smallest alias set that reduces cognitive load without breaking
existing scripts?
