# ShellForgeAI CLI Refactor Map

This map is an inventory aid for command-module extraction planning. It is not a runtime command and does not change ShellForgeAI command behavior.

## Status

- Status: `ok`
- Extracted command modules: 16
- Remaining inline CLI handlers: 101
- Unknown inline handlers: 0

## How to run the inventory

```bash
python scripts/cli_refactor_inventory.py
python scripts/cli_refactor_inventory.py --json
python scripts/cli_refactor_inventory.py --markdown
python scripts/cli_refactor_inventory.py --write-doc docs/CLI_REFACTOR_MAP.md
```

Default, JSON, and Markdown modes are read-only. `--write-doc` writes only the explicitly named Markdown file.

## Extracted command modules

| Command/group | Module | Category | PR |
| --- | --- | --- | --- |
| `apply-preview` | `src/shellforgeai/commands/apply_preview.py` | `preview_only` | PR187 |
| `ask` | `src/shellforgeai/commands/ask.py` | `read_only` | PR190 |
| `doctor` | `src/shellforgeai/commands/doctor.py` | `read_only` | PR182 |
| `handoff` | `src/shellforgeai/commands/handoff.py` | `artifact_only` | PR186 |
| `model` | `src/shellforgeai/commands/model.py` | `read_only` | PR196 |
| `ops` | `src/shellforgeai/commands/ops.py` | `read_only` | PR183 |
| `propose` | `src/shellforgeai/commands/propose.py` | `artifact_only` | PR187 |
| `receipt audit` | `src/shellforgeai/commands/receipt_audit.py` | `artifact_only` | PR191 |
| `receipt recovery execute` | `src/shellforgeai/commands/receipt_recovery_execute.py` | `confirm_gated_mutation` | PR194 |
| `receipt recovery readonly` | `src/shellforgeai/commands/receipt_recovery_readonly.py` | `artifact_only` | PR193 |
| `receipt safety` | `src/shellforgeai/commands/receipt_safety.py` | `preview_only` | PR192 |
| `recipes/preflight` | `src/shellforgeai/commands/recipes.py` | `read_only` | PR189 |
| `status` | `src/shellforgeai/commands/status.py` | `read_only` | PR182 |
| `triage` | `src/shellforgeai/commands/triage.py` | `read_only` | PR183 |
| `v1` | `src/shellforgeai/commands/v1.py` | `read_only` | PR195 |
| `verify` | `src/shellforgeai/commands/verify.py` | `read_only` | PR185 |

## Remaining inline handlers in `src/shellforgeai/cli.py`

| Handler/group | Function | Line | Category | Risk | Validation | Suggested PR | Notes |
| --- | --- | ---: | --- | --- | --- | --- | --- |
| `root callback / interactive fallback` | `main` | 696 | `read_only` | `medium` | `Lane C` | later / not first wave | Root no-subcommand behavior is CLI-surface sensitive; move only with full guardrails. |
| `interactive mode` | `interactive` | 734 | `read_only` | `high` | `Lane C` | later / not first wave | Interactive routing/refusal semantics are safety-critical and should move late. |
| `version` | `version_cmd` | 753 | `read_only` | `low` | `Lane B` | PR199 | Small read-only root command; good low-risk extraction candidate. |
| `inspect (inspect_host)` | `inspect_host` | 765 | `read_only` | `low` | `Lane B` | PR199 | Read-only inspect group is a low-risk extraction candidate. |
| `inspect (inspect_service)` | `inspect_service` | 772 | `read_only` | `low` | `Lane B` | PR199 | Read-only inspect group is a low-risk extraction candidate. |
| `logs` | `logs` | 779 | `read_only` | `medium` | `Lane C` | later / not first wave | Evidence-facing log command; preserve no-mutation boundaries. |
| `tools (tools_list)` | `tools_list` | 786 | `read_only` | `low` | `Lane B` | PR199 | Read-only tool catalog/help surface. |
| `tools (tools_describe)` | `tools_describe` | 792 | `read_only` | `low` | `Lane B` | PR199 | Read-only tool catalog/help surface. |
| `audit readonly (audit_list)` | `audit_list` | 800 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `audit readonly (audit_timeline)` | `audit_timeline` | 811 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `audit readonly (audit_show)` | `audit_show` | 844 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `audit readonly (audit_validate)` | `audit_validate` | 854 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `audit readonly (audit_retention)` | `audit_retention` | 870 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `audit cleanup readonly/preview` | `audit_cleanup_review` | 1426 | `preview_only` | `medium` | `Lane C` | later / not first wave | Cleanup planning/review/reporting must stay non-destructive. |
| `audit cleanup prepare` | `audit_cleanup_prepare` | 1654 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Writes ShellForgeAI-owned cleanup metadata only. |
| `audit cleanup readonly/preview` | `audit_cleanup_plan` | 1760 | `preview_only` | `medium` | `Lane C` | later / not first wave | Cleanup planning/review/reporting must stay non-destructive. |
| `audit cleanup archive` | `audit_cleanup_archive` | 1803 | `artifact_only` | `high` | `Lane C` | later / not first wave | Cleanup archive is artifact mutation; require full safety validation. |
| `audit cleanup execute` | `audit_cleanup_execute` | 1811 | `confirm_gated_mutation` | `high` | `Lane C` | later / not first wave | Governed cleanup execution must move last or with full validation. |
| `audit cleanup readonly/preview` | `audit_cleanup_validate` | 1905 | `preview_only` | `medium` | `Lane C` | later / not first wave | Cleanup planning/review/reporting must stay non-destructive. |
| `audit cleanup execute` | `audit_cleanup_execute_readiness` | 2245 | `confirm_gated_mutation` | `high` | `Lane C` | later / not first wave | Governed cleanup execution must move last or with full validation. |
| `audit cleanup readonly/preview` | `audit_cleanup_report` | 2513 | `preview_only` | `medium` | `Lane C` | later / not first wave | Cleanup planning/review/reporting must stay non-destructive. |
| `audit prune` | `audit_prune` | 2575 | `artifact_only` | `high` | `Lane C` | later / not first wave | Prune/archive behavior is artifact-mutating and needs full validation. |
| `audit archive` | `audit_archive` | 2805 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Audit archive mutates ShellForgeAI-owned artifacts only. |
| `audit archive` | `audit_archive_validate` | 2846 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Audit archive mutates ShellForgeAI-owned artifacts only. |
| `audit readonly (audit_index_main)` | `audit_index_main` | 2881 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `audit readonly (audit_index_validate)` | `audit_index_validate` | 2906 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `audit readonly (audit_search)` | `audit_search` | 2954 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `diagnose` | `diagnose` | 3028 | `read_only` | `medium` | `Lane C` | later / not first wave | Core diagnostic collector path; require command-surface and evidence regression coverage. |
| `research` | `research` | 3206 | `read_only` | `medium` | `Lane C` | later / not first wave | May involve synthesis/provider plumbing; preserve advisory-only semantics. |
| `plan` | `plan` | 3232 | `preview_only` | `medium` | `Lane C` | later / not first wave | Plan generation must remain non-executing. |
| `runbook` | `runbook` | 3268 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Runbook artifacts must remain review-only. |
| `validate-runbook` | `validate_runbook_cmd` | 3335 | `read_only` | `low` | `Lane B` | PR199 | Read-only validator; can pair with runbook if scoped tightly. |
| `apply` | `apply` | 3462 | `preview_only` | `high` | `Lane C` | later / not first wave | Alpha behavior is validation-only; dangerous/broad if mishandled; extraction must prove no broad/freeform mutation. |
| `actions compile` | `actions_compile` | 4158 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Compiles review-only action records from approved proposals; no execution. |
| `actions readonly (actions_show)` | `actions_show` | 4197 | `read_only` | `low` | `Lane B` | PR200 | Read-only action record show/validate surface. |
| `actions readonly (actions_validate)` | `actions_validate` | 4241 | `read_only` | `low` | `Lane B` | PR200 | Read-only action record show/validate surface. |
| `rollback preview/validate/show` | `rollback_preview_cmd` | 4269 | `preview_only` | `medium` | `Lane C` | later / not first wave | Rollback remains preview/validation only; no rollback execution in this group. |
| `rollback preview/validate/show` | `rollback_validate_cmd` | 4298 | `preview_only` | `medium` | `Lane C` | later / not first wave | Rollback remains preview/validation only; no rollback execution in this group. |
| `rollback preview/validate/show` | `rollback_show_cmd` | 4336 | `preview_only` | `medium` | `Lane C` | later / not first wave | Rollback remains preview/validation only; no rollback execution in this group. |
| `guard (guard_check)` | `guard_check` | 4423 | `read_only` | `low` | `Lane B` | PR200 | Read-only stale-evidence/drift guard checks. |
| `guard (guard_check_actions)` | `guard_check_actions` | 4461 | `read_only` | `low` | `Lane B` | PR200 | Read-only stale-evidence/drift guard checks. |
| `guard (guard_check_export)` | `guard_check_export` | 4481 | `read_only` | `low` | `Lane B` | PR200 | Read-only stale-evidence/drift guard checks. |
| `guard (guard_show)` | `guard_show` | 4501 | `read_only` | `low` | `Lane B` | PR200 | Read-only stale-evidence/drift guard checks. |
| `export` | `export_cmd` | 4570 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Writes export packs; should remain ShellForgeAI-artifact-only. |
| `validate-export` | `validate_export_cmd` | 4637 | `read_only` | `low` | `Lane B` | PR200 | Read-only export validator. |
| `approvals` | `approvals_create` | 4744 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `approvals` | `approvals_propose_restart` | 4811 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `approvals` | `approvals_restart_plan` | 4878 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `mission metadata/readiness` | `mission_restart_prepare` | 4930 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_restart_status` | 5023 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_restart_checklist` | 5067 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_restart_validate` | 5084 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission restart execute` | `mission_restart_execute` | 5180 | `confirm_gated_mutation` | `high` | `Lane C` | later / not first wave | Governed execution handler; leave for last and require full validation. |
| `mission metadata/readiness` | `mission_restart_report` | 5542 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_restart_export` | 5630 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_restart_validate_export` | 5697 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `approvals` | `approvals_list` | 5744 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `approvals` | `approvals_show` | 5857 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `approvals approve` | `approvals_approve` | 5868 | `artifact_only` | `high` | `Lane C` | later / not first wave | Approval metadata can unlock later governed flows; move late with full validation. |
| `approvals` | `approvals_reject` | 5889 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `approvals` | `approvals_cancel` | 5907 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `approvals` | `approvals_archive` | 5925 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `approvals` | `approvals_validate` | 5943 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `mission metadata/readiness` | `mission_compose_restart_prepare` | 7874 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_compose_restart_status` | 7910 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_compose_restart_checklist` | 7940 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_compose_restart_validate` | 7949 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission compose-restart execute` | `mission_compose_restart_execute` | 7982 | `confirm_gated_mutation` | `high` | `Lane C` | later / not first wave | Compose restart execution is governed and safety-sensitive; move last. |
| `recipes execute` | `recipes_execute` | 11300 | `confirm_gated_mutation` | `high` | `Lane C` | later / not first wave | Named governed recipe execution; leave for last or isolate with full validation. |
| `safe-actions` | `safe_actions` | 11750 | `read_only` | `medium` | `Lane C` | later / not first wave | Safe-command suggestion surface; preserve refusal and safe-next-command wording. |
| `compose readonly/context (compose_inspect)` | `compose_inspect` | 11975 | `read_only` | `low` | `Lane B` | PR199 | Read-only Compose ownership/environment context. |
| `compose readonly/context (compose_list)` | `compose_list` | 12037 | `read_only` | `low` | `Lane B` | PR199 | Read-only Compose ownership/environment context. |
| `compose restart-preview` | `compose_restart_preview` | 12066 | `preview_only` | `medium` | `Lane C` | later / not first wave | Compose restart preview must not execute Compose. |
| `compose propose-restart` | `compose_propose_restart` | 12134 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal artifact only; no Compose execution. |
| `compose readonly/context (compose_env_check)` | `compose_env_check` | 12202 | `read_only` | `low` | `Lane B` | PR199 | Read-only Compose ownership/environment context. |
| `compose readonly/context (compose_env_contract)` | `compose_env_contract` | 12394 | `read_only` | `low` | `Lane B` | PR199 | Read-only Compose ownership/environment context. |
| `compose readonly/context (compose_env_plan)` | `compose_env_plan` | 12457 | `read_only` | `low` | `Lane B` | PR199 | Read-only Compose ownership/environment context. |
| `v1 packet callback` | `v1_packet` | 12523 | `artifact_only` | `medium` | `Lane C` | later / not first wave | V1 packet group callback belongs with packet artifact lifecycle extraction. |
| `v1 packet readonly/artifact` | `v1_packet_validate` | 12564 | `artifact_only` | `medium` | `Lane C` | later / not first wave | V1 packet lifecycle should preserve readiness guidance and artifact-only behavior. |
| `v1 packet export` | `v1_packet_export` | 12581 | `artifact_only` | `medium` | `Lane C` | later / not first wave | V1 packet export/history/compare artifact lifecycle; v1 check is already extracted. |
| `v1 packet export` | `v1_packet_export_validate` | 12599 | `artifact_only` | `medium` | `Lane C` | later / not first wave | V1 packet export/history/compare artifact lifecycle; v1 check is already extracted. |
| `v1 packet readonly/artifact` | `v1_packet_history` | 12616 | `artifact_only` | `medium` | `Lane C` | later / not first wave | V1 packet lifecycle should preserve readiness guidance and artifact-only behavior. |
| `v1 packet readonly/artifact` | `v1_packet_compare` | 12646 | `artifact_only` | `medium` | `Lane C` | later / not first wave | V1 packet lifecycle should preserve readiness guidance and artifact-only behavior. |
| `v1 packet readonly/artifact` | `v1_packet_compare_latest` | 12704 | `artifact_only` | `medium` | `Lane C` | later / not first wave | V1 packet lifecycle should preserve readiness guidance and artifact-only behavior. |
| `self-test commands` | `self_test_commands` | 12729 | `read_only` | `medium` | `Lane C` | later / not first wave | Validation harness surface; must not start mutation or Docker operations. |
| `remediation readonly/preview` | `remediation_eligibility` | 12887 | `preview_only` | `medium` | `Lane C` | later / not first wave | Keep eligibility/plan/preflight/report/audit/status separate from execute. |
| `remediation readonly/preview` | `remediation_plan` | 13121 | `preview_only` | `medium` | `Lane C` | later / not first wave | Keep eligibility/plan/preflight/report/audit/status separate from execute. |
| `remediation readonly/preview` | `remediation_validate` | 13162 | `preview_only` | `medium` | `Lane C` | later / not first wave | Keep eligibility/plan/preflight/report/audit/status separate from execute. |
| `remediation readonly/preview` | `remediation_preflight` | 13203 | `preview_only` | `medium` | `Lane C` | later / not first wave | Keep eligibility/plan/preflight/report/audit/status separate from execute. |
| `remediation execute` | `remediation_execute` | 13269 | `confirm_gated_mutation` | `high` | `Lane C` | later / not first wave | Governed disposable remediation execution; leave for last. |
| `remediation receipt` | `remediation_receipt_validate` | 13476 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Receipt validation/reporting; avoid artifact repair/delete. |
| `remediation readonly/preview` | `remediation_report` | 13496 | `preview_only` | `medium` | `Lane C` | later / not first wave | Keep eligibility/plan/preflight/report/audit/status separate from execute. |
| `remediation bundle` | `remediation_bundle` | 13542 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Bundle artifact lifecycle; no execution. |
| `remediation bundle` | `remediation_bundle_validate` | 13594 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Bundle artifact lifecycle; no execution. |
| `remediation readonly/preview` | `remediation_audit` | 13660 | `preview_only` | `medium` | `Lane C` | later / not first wave | Keep eligibility/plan/preflight/report/audit/status separate from execute. |
| `remediation readonly/preview` | `remediation_self_test` | 13722 | `preview_only` | `medium` | `Lane C` | later / not first wave | Keep eligibility/plan/preflight/report/audit/status separate from execute. |
| `remediation readonly/preview` | `remediation_status` | 14193 | `preview_only` | `medium` | `Lane C` | later / not first wave | Keep eligibility/plan/preflight/report/audit/status separate from execute. |
| `remediation rollback preview/validate/status` | `remediation_rollback_preflight` | 14232 | `preview_only` | `high` | `Lane C` | later / not first wave | Rollback-adjacent surface is safety-sensitive even when preview-only. |
| `remediation rollback preview/validate/status` | `remediation_rollback_validate` | 14255 | `preview_only` | `high` | `Lane C` | later / not first wave | Rollback-adjacent surface is safety-sensitive even when preview-only. |
| `remediation rollback-execute` | `remediation_rollback_execute` | 14273 | `confirm_gated_mutation` | `high` | `Lane C` | later / not first wave | Governed rollback execution; leave for last with full validation. |
| `remediation rollback preview/validate/status` | `remediation_rollback_status` | 14417 | `preview_only` | `high` | `Lane C` | later / not first wave | Rollback-adjacent surface is safety-sensitive even when preview-only. |

## Recommended next extraction order

1. **inspect/tools/version helpers**
   - Reason: lowest-risk remaining read-only handlers with small command surfaces
   - Validation: Lane B
   - Required regressions: PR184 command-surface golden guardrail; targeted module-split tests; full pytest if command registration/safety surface changes
2. **audit readonly and guard/actions validators**
   - Reason: read-only or validator-heavy groups after low-risk helpers
   - Validation: Lane B
   - Required regressions: PR184 command-surface golden guardrail; targeted module-split tests; full pytest if command registration/safety surface changes
3. **compose context and V1 packet artifact lifecycle**
   - Reason: read-only/artifact-only groups with broader operator-facing behavior
   - Validation: Lane C
   - Required regressions: PR184 command-surface golden guardrail; targeted module-split tests; full pytest if command registration/safety surface changes
4. **approvals/actions compile/export/mission metadata**
   - Reason: artifact-only workflow groups that influence governed execution readiness
   - Validation: Lane C
   - Required regressions: PR184 command-surface golden guardrail; targeted module-split tests; full pytest if command registration/safety surface changes
5. **interactive, apply, mission/recipe/remediation execute and rollback-adjacent handlers**
   - Reason: mutation-capable, broad, or safety-sensitive handlers should move last
   - Validation: Lane C
   - Required regressions: PR184 command-surface golden guardrail; targeted module-split tests; full pytest if command registration/safety surface changes

## Validation requirements for future module-split PRs

- The PR184 golden command-surface guardrail must run for every CLI split.
- Add targeted module-split tests that prove the new module owns registration and imports without runtime side effects.
- Use Lane B for narrow read-only moves that do not alter command registration, option names, refusal wording, or safety surfaces beyond the intended module ownership proof.
- Use Lane C / full validation for safety-sensitive or broad command-surface moves, including interactive mode, ask routing, apply/refusal semantics, recovery, rollback-adjacent flows, recipe execution, mission execution, or anything that can affect governed mutation readiness.
- Mutation-capable governed execution handlers move last, or move only with full validation and explicit confirmation that execution/refusal semantics are unchanged.

## Safety summary

- Inventory only.
- No ShellForgeAI runtime command execution.
- No Docker/Compose operation or mutation.
- No pytest, ruff, validation, cleanup, rollback, recovery, or recipe execution from the helper.
- No model/Codex call.
- No artifact repair/delete.
- No source mutation; `--write-doc` may write only the requested Markdown doc.
