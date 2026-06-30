# ShellForgeAI CLI Refactor Map

This map is an inventory aid for command-module extraction planning. It is not a runtime command and does not change ShellForgeAI command behavior.

## Status

- Status: `ok`
- Extracted command modules: 19
- Remaining inline CLI handlers: 99
- Unknown inline handlers: 0

## cli.py inline-handler debt

- `src/shellforgeai/cli.py` line count: 14021 (threshold 14500, within: true)
- Inline Typer handlers in cli.py: 99 (threshold 105, within: true)
- `cli.py` remains Typer/app wiring plus the explicitly inventoried remaining inline handlers below; the PR202 enforcement guardrail (`tests/test_pr202_cli_refactor_inventory_enforcement.py`) fails if a new large inline handler is added without lowering the debt or updating these thresholds and docs.

## CLI refactor closure status

- Closure status: `ok`
- `cli.py` role: `typer_wiring`
- Command-surface guardrail (PR184): `present`
- Extracted command modules: 19
- Missing expected modules: none
- Intentional Typer wiring/glue (callbacks) left in cli.py: `audit_index_main`, `main`, `v1_packet`
- Classified inline command handlers remaining (future-extraction candidates): 96
- Unexpected (unclassified) inline handlers: none
- Recommendation: cli split enforced and behavior-preserving: 19 command modules extracted; 96 classified inline command handlers remain as documented future-extraction candidates; 3 Typer callbacks intentionally remain as wiring; 0 unexpected inline handlers; PR184/PR202 guardrails present

## CLI wiring-only enforcement (`--check`)

`src/shellforgeai/cli.py` is treated as **wiring-only**: Typer app/group creation, command-module registration, shared app metadata, and thin root/bootstrap helpers. The split is guarded by a strict check that fails if an unapproved inline command handler appears in `cli.py`.

```bash
python scripts/cli_refactor_inventory.py --check
python scripts/cli_refactor_inventory.py --check --json
```

The check is read-only (AST inspection only) and sorts every inline Typer callable in `cli.py` into one of three buckets:

- **Allowed** — explicitly allowlisted Typer wiring / root bootstrap. Every allowlist entry must carry a reason.
- **Remaining extraction candidate** — a classified inline command handler documented as future-extraction debt (tracked, not silently allowlisted).
- **Unapproved** — an unclassified inline command handler or a non-allowlisted Typer callback. These fail the check and must move into `src/shellforgeai/commands/` or earn an explicit allowlist reason.

### Allowlist (intentional remaining inline callables)

| Symbol | Reason |
| --- | --- |
| `main` | Typer root @app.callback() / app bootstrap and no-subcommand interactive fallback (intentional Typer entrypoint). |
| `version_cmd` | Intentional tiny read-only `version` root command kept inline. |
| `audit_index_main` | Typer `audit index` group @*.callback() registration glue. |
| `v1_packet` | Typer `v1 packet` group @*.callback() registration glue. |

The allowlist is deliberately tiny and must stay reasoned. A future PR that needs to keep a new inline callable in `cli.py` must add an explicit entry **with a reason**; an entry without a reason is rejected. If the allowlist would grow beyond a few genuine wiring/bootstrap items, extract the handler into `src/shellforgeai/commands/` instead — new command handlers belong in a command module, not inline in `cli.py`. The PR184 golden command-surface guardrail remains required for any command refactor.

## Import side-effect guardrail (PR205)

The command-module split closes two ways, not one. The PR184 golden
command-surface guardrail protects **user-visible commands**; the PR205 import
side-effect guardrail protects against **hidden import-time behavior**.

Importing `src/shellforgeai/cli.py`, `src/shellforgeai/commands/__init__.py`, and
every module under `src/shellforgeai/commands/` must be **import-safe**:

- Allowed at import: defining Typer apps/functions/classes, importing local
  modules, defining constants and option metadata, registering commands, and
  harmless pure-Python setup.
- Not allowed at import: calling Docker/Compose, restarting containers, running
  subprocesses, `os.system`, `shell=True`, calling a model/Codex client, network
  requests, cleanup/remediation/rollback/recovery execution, writing/repairing/
  deleting artifacts, or any other operational mutation. Those belong only inside
  the command's execution path (the handler body), which runs when the command is
  invoked — never at import.

The guardrail lives in
`tests/test_pr205_command_module_import_side_effects.py` and combines:

- a **static** AST scan that rejects top-level subprocess/`shell=True`/cleanup/
  remediation/rollback/recovery/model calls while leaving harmless help text and
  command strings untouched, and
- a **runtime** check that purges the audited modules from `sys.modules` and
  reimports them under monkeypatched recording stubs over the dangerous
  primitives (subprocess, `os.system`, network sockets, the model/provider
  factory, the Docker/restart executors, and artifact write/delete), asserting
  none fired at import time.

A read-only helper runs the same audit in a fresh process and reports per-module
import status plus any blocked side-effect attempts:

```bash
python scripts/cli_import_audit.py
python scripts/cli_import_audit.py --json
python scripts/cli_import_audit.py --markdown
```

The helper is read-only and local-only: it executes no ShellForgeAI command and
performs no Docker/Compose/subprocess/model/network call and no artifact/`/data`
mutation. Run this guardrail (and the PR184 command-surface guardrail) for any
future command-module change.

## Intentional `cli.py` responsibilities (allowed Typer wiring/glue)

`src/shellforgeai/cli.py` is intended to remain the Typer app entrypoint and registration glue. The following are allowed to stay:

- Typer `app`/group creation and shared app wiring (`typer.Typer(...)`).
- Root `@app.callback()` (`main`) including the no-subcommand interactive fallback.
- Typer group `@*.callback()` glue (for example `audit index` and `v1 packet`).
- `from shellforgeai.commands import <module> as <module>_commands` imports.
- `<module>_commands.register(...)` registration calls for extracted modules.
- Compatibility command/alias registration that preserves the public surface.
- Minimal bootstrap constants and shared option/context helpers.

## Not allowed in `cli.py`

The following belong in command modules, not inline in `cli.py`:

- Large command handler bodies (extract into `src/shellforgeai/commands/`).
- Docker/Compose mutation or restart logic.
- Remediation/recovery/rollback execution logic.
- Ask deterministic routing/refusal decision bodies.
- Receipt artifact business logic.
- Interactive REPL loop internals.
- Model/Codex call logic.
- Large JSON response builders.

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
| `interactive` | `src/shellforgeai/commands/interactive.py` | `read_only` | PR200 |
| `model` | `src/shellforgeai/commands/model.py` | `read_only` | PR196 |
| `ops` | `src/shellforgeai/commands/ops.py` | `read_only` | PR183 |
| `platform doctor` | `src/shellforgeai/commands/platform.py` | `read_only` | PR259 |
| `windows doctor` | `src/shellforgeai/commands/windows.py` | `read_only` | PR261 |
| `propose` | `src/shellforgeai/commands/propose.py` | `artifact_only` | PR187 |
| `receipt audit` | `src/shellforgeai/commands/receipt_audit.py` | `artifact_only` | PR191 |
| `receipt recovery execute` | `src/shellforgeai/commands/receipt_recovery_execute.py` | `confirm_gated_mutation` | PR194 |
| `receipt recovery readonly` | `src/shellforgeai/commands/receipt_recovery_readonly.py` | `artifact_only` | PR193 |
| `receipt safety` | `src/shellforgeai/commands/receipt_safety.py` | `preview_only` | PR192 |
| `recipes/preflight` | `src/shellforgeai/commands/recipes.py` | `read_only` | PR189 |
| `remediation self-test` | `src/shellforgeai/commands/remediation.py` | `preview_only` | PR199 |
| `status` | `src/shellforgeai/commands/status.py` | `read_only` | PR182 |
| `triage` | `src/shellforgeai/commands/triage.py` | `read_only` | PR183 |
| `v1` | `src/shellforgeai/commands/v1.py` | `read_only` | PR195 |
| `verify` | `src/shellforgeai/commands/verify.py` | `read_only` | PR185 |

## Remaining inline handlers in `src/shellforgeai/cli.py`

| Handler/group | Function | Line | Category | Risk | Validation | Suggested PR | Notes |
| --- | --- | ---: | --- | --- | --- | --- | --- |
| `root callback / interactive fallback` | `main` | 696 | `read_only` | `medium` | `Lane C` | later / not first wave | Root no-subcommand behavior is CLI-surface sensitive; move only with full guardrails. |
| `version` | `version_cmd` | 734 | `read_only` | `low` | `Lane B` | PR199 | Small read-only root command; good low-risk extraction candidate. |
| `inspect (inspect_host)` | `inspect_host` | 747 | `read_only` | `low` | `Lane B` | PR199 | Read-only inspect group is a low-risk extraction candidate. |
| `inspect (inspect_service)` | `inspect_service` | 754 | `read_only` | `low` | `Lane B` | PR199 | Read-only inspect group is a low-risk extraction candidate. |
| `logs` | `logs` | 761 | `read_only` | `medium` | `Lane C` | later / not first wave | Evidence-facing log command; preserve no-mutation boundaries. |
| `tools (tools_list)` | `tools_list` | 768 | `read_only` | `low` | `Lane B` | PR199 | Read-only tool catalog/help surface. |
| `tools (tools_describe)` | `tools_describe` | 774 | `read_only` | `low` | `Lane B` | PR199 | Read-only tool catalog/help surface. |
| `audit readonly (audit_list)` | `audit_list` | 782 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `audit readonly (audit_timeline)` | `audit_timeline` | 793 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `audit readonly (audit_show)` | `audit_show` | 826 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `audit readonly (audit_validate)` | `audit_validate` | 836 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `audit readonly (audit_retention)` | `audit_retention` | 852 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `audit cleanup readonly/preview` | `audit_cleanup_review` | 1408 | `preview_only` | `medium` | `Lane C` | later / not first wave | Cleanup planning/review/reporting must stay non-destructive. |
| `audit cleanup prepare` | `audit_cleanup_prepare` | 1636 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Writes ShellForgeAI-owned cleanup metadata only. |
| `audit cleanup readonly/preview` | `audit_cleanup_plan` | 1742 | `preview_only` | `medium` | `Lane C` | later / not first wave | Cleanup planning/review/reporting must stay non-destructive. |
| `audit cleanup archive` | `audit_cleanup_archive` | 1785 | `artifact_only` | `high` | `Lane C` | later / not first wave | Cleanup archive is artifact mutation; require full safety validation. |
| `audit cleanup execute` | `audit_cleanup_execute` | 1793 | `confirm_gated_mutation` | `high` | `Lane C` | later / not first wave | Governed cleanup execution must move last or with full validation. |
| `audit cleanup readonly/preview` | `audit_cleanup_validate` | 1887 | `preview_only` | `medium` | `Lane C` | later / not first wave | Cleanup planning/review/reporting must stay non-destructive. |
| `audit cleanup execute` | `audit_cleanup_execute_readiness` | 2227 | `confirm_gated_mutation` | `high` | `Lane C` | later / not first wave | Governed cleanup execution must move last or with full validation. |
| `audit cleanup readonly/preview` | `audit_cleanup_report` | 2495 | `preview_only` | `medium` | `Lane C` | later / not first wave | Cleanup planning/review/reporting must stay non-destructive. |
| `audit prune` | `audit_prune` | 2557 | `artifact_only` | `high` | `Lane C` | later / not first wave | Prune/archive behavior is artifact-mutating and needs full validation. |
| `audit archive` | `audit_archive` | 2787 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Audit archive mutates ShellForgeAI-owned artifacts only. |
| `audit archive` | `audit_archive_validate` | 2828 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Audit archive mutates ShellForgeAI-owned artifacts only. |
| `audit readonly (audit_index_main)` | `audit_index_main` | 2863 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `audit readonly (audit_index_validate)` | `audit_index_validate` | 2888 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `audit readonly (audit_search)` | `audit_search` | 2936 | `read_only` | `low` | `Lane B` | PR200 | Mostly read-only audit views and validators; keep artifact-mutating variants separate. |
| `diagnose` | `diagnose` | 3010 | `read_only` | `medium` | `Lane C` | later / not first wave | Core diagnostic collector path; require command-surface and evidence regression coverage. |
| `research` | `research` | 3188 | `read_only` | `medium` | `Lane C` | later / not first wave | May involve synthesis/provider plumbing; preserve advisory-only semantics. |
| `plan` | `plan` | 3214 | `preview_only` | `medium` | `Lane C` | later / not first wave | Plan generation must remain non-executing. |
| `runbook` | `runbook` | 3250 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Runbook artifacts must remain review-only. |
| `validate-runbook` | `validate_runbook_cmd` | 3317 | `read_only` | `low` | `Lane B` | PR199 | Read-only validator; can pair with runbook if scoped tightly. |
| `apply` | `apply` | 3444 | `preview_only` | `high` | `Lane C` | later / not first wave | Alpha behavior is validation-only; dangerous/broad if mishandled; extraction must prove no broad/freeform mutation. |
| `actions compile` | `actions_compile` | 4140 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Compiles review-only action records from approved proposals; no execution. |
| `actions readonly (actions_show)` | `actions_show` | 4179 | `read_only` | `low` | `Lane B` | PR200 | Read-only action record show/validate surface. |
| `actions readonly (actions_validate)` | `actions_validate` | 4223 | `read_only` | `low` | `Lane B` | PR200 | Read-only action record show/validate surface. |
| `rollback preview/validate/show` | `rollback_preview_cmd` | 4251 | `preview_only` | `medium` | `Lane C` | later / not first wave | Rollback remains preview/validation only; no rollback execution in this group. |
| `rollback preview/validate/show` | `rollback_validate_cmd` | 4280 | `preview_only` | `medium` | `Lane C` | later / not first wave | Rollback remains preview/validation only; no rollback execution in this group. |
| `rollback preview/validate/show` | `rollback_show_cmd` | 4318 | `preview_only` | `medium` | `Lane C` | later / not first wave | Rollback remains preview/validation only; no rollback execution in this group. |
| `guard (guard_check)` | `guard_check` | 4405 | `read_only` | `low` | `Lane B` | PR200 | Read-only stale-evidence/drift guard checks. |
| `guard (guard_check_actions)` | `guard_check_actions` | 4443 | `read_only` | `low` | `Lane B` | PR200 | Read-only stale-evidence/drift guard checks. |
| `guard (guard_check_export)` | `guard_check_export` | 4463 | `read_only` | `low` | `Lane B` | PR200 | Read-only stale-evidence/drift guard checks. |
| `guard (guard_show)` | `guard_show` | 4483 | `read_only` | `low` | `Lane B` | PR200 | Read-only stale-evidence/drift guard checks. |
| `export` | `export_cmd` | 4552 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Writes export packs; should remain ShellForgeAI-artifact-only. |
| `validate-export` | `validate_export_cmd` | 4619 | `read_only` | `low` | `Lane B` | PR200 | Read-only export validator. |
| `approvals` | `approvals_create` | 4726 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `approvals` | `approvals_propose_restart` | 4793 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `approvals` | `approvals_restart_plan` | 4860 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `mission metadata/readiness` | `mission_restart_prepare` | 4912 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_restart_status` | 5005 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_restart_checklist` | 5049 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_restart_validate` | 5066 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission restart execute` | `mission_restart_execute` | 5162 | `confirm_gated_mutation` | `high` | `Lane C` | later / not first wave | Governed execution handler; leave for last and require full validation. |
| `mission metadata/readiness` | `mission_restart_report` | 5524 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_restart_export` | 5612 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_restart_validate_export` | 5679 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `approvals` | `approvals_list` | 5726 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `approvals` | `approvals_show` | 5839 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `approvals approve` | `approvals_approve` | 5850 | `artifact_only` | `high` | `Lane C` | later / not first wave | Approval metadata can unlock later governed flows; move late with full validation. |
| `approvals` | `approvals_reject` | 5871 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `approvals` | `approvals_cancel` | 5889 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `approvals` | `approvals_archive` | 5907 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `approvals` | `approvals_validate` | 5925 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal metadata lifecycle; no host/container mutation. |
| `mission metadata/readiness` | `mission_compose_restart_prepare` | 7856 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_compose_restart_status` | 7892 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_compose_restart_checklist` | 7922 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission metadata/readiness` | `mission_compose_restart_validate` | 7931 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Mission metadata/checklist/report/export flows; split execution separately. |
| `mission compose-restart execute` | `mission_compose_restart_execute` | 7964 | `confirm_gated_mutation` | `high` | `Lane C` | later / not first wave | Compose restart execution is governed and safety-sensitive; move last. |
| `recipes execute` | `recipes_execute` | 11282 | `confirm_gated_mutation` | `high` | `Lane C` | later / not first wave | Named governed recipe execution; leave for last or isolate with full validation. |
| `safe-actions` | `safe_actions` | 11732 | `read_only` | `medium` | `Lane C` | later / not first wave | Safe-command suggestion surface; preserve refusal and safe-next-command wording. |
| `compose readonly/context (compose_inspect)` | `compose_inspect` | 11957 | `read_only` | `low` | `Lane B` | PR199 | Read-only Compose ownership/environment context. |
| `compose readonly/context (compose_list)` | `compose_list` | 12019 | `read_only` | `low` | `Lane B` | PR199 | Read-only Compose ownership/environment context. |
| `compose restart-preview` | `compose_restart_preview` | 12048 | `preview_only` | `medium` | `Lane C` | later / not first wave | Compose restart preview must not execute Compose. |
| `compose propose-restart` | `compose_propose_restart` | 12116 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Proposal artifact only; no Compose execution. |
| `compose readonly/context (compose_env_check)` | `compose_env_check` | 12184 | `read_only` | `low` | `Lane B` | PR199 | Read-only Compose ownership/environment context. |
| `compose readonly/context (compose_env_contract)` | `compose_env_contract` | 12376 | `read_only` | `low` | `Lane B` | PR199 | Read-only Compose ownership/environment context. |
| `compose readonly/context (compose_env_plan)` | `compose_env_plan` | 12439 | `read_only` | `low` | `Lane B` | PR199 | Read-only Compose ownership/environment context. |
| `v1 packet callback` | `v1_packet` | 12505 | `artifact_only` | `medium` | `Lane C` | later / not first wave | V1 packet group callback belongs with packet artifact lifecycle extraction. |
| `v1 packet readonly/artifact` | `v1_packet_validate` | 12546 | `artifact_only` | `medium` | `Lane C` | later / not first wave | V1 packet lifecycle should preserve readiness guidance and artifact-only behavior. |
| `v1 packet export` | `v1_packet_export` | 12563 | `artifact_only` | `medium` | `Lane C` | later / not first wave | V1 packet export/history/compare artifact lifecycle; v1 check is already extracted. |
| `v1 packet export` | `v1_packet_export_validate` | 12581 | `artifact_only` | `medium` | `Lane C` | later / not first wave | V1 packet export/history/compare artifact lifecycle; v1 check is already extracted. |
| `v1 packet readonly/artifact` | `v1_packet_history` | 12598 | `artifact_only` | `medium` | `Lane C` | later / not first wave | V1 packet lifecycle should preserve readiness guidance and artifact-only behavior. |
| `v1 packet readonly/artifact` | `v1_packet_compare` | 12628 | `artifact_only` | `medium` | `Lane C` | later / not first wave | V1 packet lifecycle should preserve readiness guidance and artifact-only behavior. |
| `v1 packet readonly/artifact` | `v1_packet_compare_latest` | 12686 | `artifact_only` | `medium` | `Lane C` | later / not first wave | V1 packet lifecycle should preserve readiness guidance and artifact-only behavior. |
| `self-test commands` | `self_test_commands` | 12711 | `read_only` | `medium` | `Lane C` | later / not first wave | Validation harness surface; must not start mutation or Docker operations. |
| `remediation readonly/preview` | `remediation_eligibility` | 12869 | `preview_only` | `medium` | `Lane C` | later / not first wave | Keep eligibility/plan/preflight/report/audit/status separate from execute. |
| `remediation readonly/preview` | `remediation_plan` | 13103 | `preview_only` | `medium` | `Lane C` | later / not first wave | Keep eligibility/plan/preflight/report/audit/status separate from execute. |
| `remediation readonly/preview` | `remediation_validate` | 13144 | `preview_only` | `medium` | `Lane C` | later / not first wave | Keep eligibility/plan/preflight/report/audit/status separate from execute. |
| `remediation readonly/preview` | `remediation_preflight` | 13185 | `preview_only` | `medium` | `Lane C` | later / not first wave | Keep eligibility/plan/preflight/report/audit/status separate from execute. |
| `remediation execute` | `remediation_execute` | 13251 | `confirm_gated_mutation` | `high` | `Lane C` | later / not first wave | Governed disposable remediation execution; leave for last. |
| `remediation receipt` | `remediation_receipt_validate` | 13458 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Receipt validation/reporting; avoid artifact repair/delete. |
| `remediation readonly/preview` | `remediation_report` | 13478 | `preview_only` | `medium` | `Lane C` | later / not first wave | Keep eligibility/plan/preflight/report/audit/status separate from execute. |
| `remediation bundle` | `remediation_bundle` | 13524 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Bundle artifact lifecycle; no execution. |
| `remediation bundle` | `remediation_bundle_validate` | 13576 | `artifact_only` | `medium` | `Lane C` | later / not first wave | Bundle artifact lifecycle; no execution. |
| `remediation readonly/preview` | `remediation_audit` | 13642 | `preview_only` | `medium` | `Lane C` | later / not first wave | Keep eligibility/plan/preflight/report/audit/status separate from execute. |
| `remediation readonly/preview` | `remediation_status` | 13707 | `preview_only` | `medium` | `Lane C` | later / not first wave | Keep eligibility/plan/preflight/report/audit/status separate from execute. |
| `remediation rollback preview/validate/status` | `remediation_rollback_preflight` | 13746 | `preview_only` | `high` | `Lane C` | later / not first wave | Rollback-adjacent surface is safety-sensitive even when preview-only. |
| `remediation rollback preview/validate/status` | `remediation_rollback_validate` | 13769 | `preview_only` | `high` | `Lane C` | later / not first wave | Rollback-adjacent surface is safety-sensitive even when preview-only. |
| `remediation rollback-execute` | `remediation_rollback_execute` | 13787 | `confirm_gated_mutation` | `high` | `Lane C` | later / not first wave | Governed rollback execution; leave for last with full validation. |
| `remediation rollback preview/validate/status` | `remediation_rollback_status` | 13931 | `preview_only` | `high` | `Lane C` | later / not first wave | Rollback-adjacent surface is safety-sensitive even when preview-only. |

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
