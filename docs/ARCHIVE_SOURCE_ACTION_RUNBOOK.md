# Archive Source-Action Operator Runbook

This runbook consolidates the archive/source-action evidence chain into one operator-facing path. It is for review, audit, and future-PR readiness only. Source action is not available in this workflow, cleanup is not available, and execution is not available. SeedOfEvil remains the final merge owner for any future change.

## What this workflow is good at

- Evidence-backed Docker/Linux artifact review with plan, archive, validation, and status evidence kept together.
- Guarded operator workflows that separate collection, validation, review, decision receipts, readiness checks, and status reporting.
- Audit-friendly receipts, manifests, checksums, Markdown summaries, and machine-readable JSON contracts.
- Deterministic refusal of unsafe broad mutation, including cleanup-shaped, delete-shaped, move-shaped, prune-shaped, restart-shaped, and execute-shaped lanes.
- Human-readable status reports that let an operator decide whether evidence is complete enough to review.
- Machine-readable JSON contracts that can be validated without Docker, Compose, network, GitHub, model calls, or mutation.

## What this workflow does not do

- Does not execute cleanup.
- Does not delete sources.
- Does not move sources.
- Does not copy sources from status/reporting commands.
- Does not prune Docker.
- Does not restart containers.
- Does not remediate, roll back, or recover.
- Does not authorize source action.
- Does not bypass SeedOfEvil final merge ownership.

The only copy lane in this evidence chain is the existing, confirm-gated archive bundle creation step. `--create-archive-bundle` is copy-only archive bundle creation: it copies selected evidence into an archive bundle and does not delete, move, modify, clean up, prune, restart, remediate, roll back, recover, or execute source action. Every later source-action, validation, review, decision, readiness, and status command is read-only/reporting.

## Evidence chain overview

The chain starts with a plan and ends with an operator status report. PR239 through PR244 added the source-action dry run, dry-run validator, human review packet, operator decision receipt, final readiness gate, and operator status report. Those steps remain read-only/reporting after the archive bundle creation runway. A status of `ready`, `ready_for_operator_review`, or `ready_for_future_pr_review` means the evidence is reviewable; it does not mean executable.

Source action remains unavailable. Any future source-action capability would require a separate PR, a separate validation lane, explicit review, and SeedOfEvil final merge ownership. This runbook does not document or imply a real source-action execution command.

## Command sequence

Use existing command names only, with operator-controlled placeholders for directories and plan id:

```bash
python3 scripts/docker01_artifact_archive_plan.py --root "$FIXTURE_ROOT" --out "$PLAN_DIR"
python3 scripts/docker01_artifact_archive_plan.py --validate "$PLAN_DIR" --json
python3 scripts/docker01_artifact_archive_plan.py --dry-run-receipt "$PLAN_DIR" --plan-id "$PLAN_ID" --out "$DRY_RUN_DIR" --json
python3 scripts/docker01_artifact_archive_plan.py --validate-dry-run-receipt "$DRY_RUN_DIR" --plan-dir "$PLAN_DIR" --out "$DRY_RUN_VALIDATION_DIR" --json
python3 scripts/docker01_artifact_archive_plan.py --execution-readiness "$PLAN_DIR" --dry-run-receipt "$DRY_RUN_DIR" --out "$EXECUTION_READINESS_DIR" --json
python3 scripts/docker01_artifact_archive_plan.py --create-archive-bundle "$PLAN_DIR" --dry-run-receipt "$DRY_RUN_DIR" --plan-id "$PLAN_ID" --confirm CONFIRM_SHELLFORGEAI_ARTIFACT_ARCHIVE --archive-out "$ARCHIVE_DIR" --json
python3 scripts/docker01_artifact_archive_plan.py --validate-archive-bundle "$ARCHIVE_DIR" --plan-dir "$PLAN_DIR" --dry-run-receipt "$DRY_RUN_DIR" --out "$ARCHIVE_VALIDATION_DIR" --json
python3 scripts/docker01_artifact_archive_plan.py --archive-eligibility-review "$ARCHIVE_DIR" --plan-dir "$PLAN_DIR" --dry-run-receipt "$DRY_RUN_DIR" --out "$ELIGIBILITY_DIR" --json
python3 scripts/docker01_artifact_archive_plan.py --archive-source-action-dry-run "$ARCHIVE_DIR" --plan-dir "$PLAN_DIR" --dry-run-receipt "$DRY_RUN_DIR" --archive-eligibility-review "$ELIGIBILITY_DIR" --plan-id "$PLAN_ID" --out "$SOURCE_ACTION_DRY_RUN_DIR" --json
python3 scripts/docker01_artifact_archive_plan.py --validate-archive-source-action-dry-run "$SOURCE_ACTION_DRY_RUN_DIR" --archive-bundle "$ARCHIVE_DIR" --plan-dir "$PLAN_DIR" --dry-run-receipt "$DRY_RUN_DIR" --archive-eligibility-review "$ELIGIBILITY_DIR" --out "$SOURCE_ACTION_VALIDATION_DIR" --json
python3 scripts/docker01_artifact_archive_plan.py --archive-source-action-review-packet "$SOURCE_ACTION_DRY_RUN_DIR" --source-action-validation "$SOURCE_ACTION_VALIDATION_DIR" --archive-bundle "$ARCHIVE_DIR" --plan-dir "$PLAN_DIR" --dry-run-receipt "$DRY_RUN_DIR" --archive-eligibility-review "$ELIGIBILITY_DIR" --plan-id "$PLAN_ID" --out "$REVIEW_PACKET_DIR" --json
python3 scripts/docker01_artifact_archive_plan.py --archive-source-action-decision-receipt "$REVIEW_PACKET_DIR" --plan-id "$PLAN_ID" --decision ready_for_future_pr_review --out "$DECISION_RECEIPT_DIR" --json
python3 scripts/docker01_artifact_archive_plan.py --archive-source-action-readiness-gate "$DECISION_RECEIPT_DIR" --review-packet "$REVIEW_PACKET_DIR" --source-action-dry-run "$SOURCE_ACTION_DRY_RUN_DIR" --source-action-validation "$SOURCE_ACTION_VALIDATION_DIR" --archive-bundle "$ARCHIVE_DIR" --plan-dir "$PLAN_DIR" --dry-run-receipt "$DRY_RUN_DIR" --archive-eligibility-review "$ELIGIBILITY_DIR" --plan-id "$PLAN_ID" --out "$READINESS_GATE_DIR" --json
python3 scripts/docker01_artifact_archive_plan.py --archive-source-action-status-report "$READINESS_GATE_DIR" --decision-receipt "$DECISION_RECEIPT_DIR" --review-packet "$REVIEW_PACKET_DIR" --source-action-dry-run "$SOURCE_ACTION_DRY_RUN_DIR" --source-action-validation "$SOURCE_ACTION_VALIDATION_DIR" --archive-bundle "$ARCHIVE_DIR" --plan-dir "$PLAN_DIR" --dry-run-receipt "$DRY_RUN_DIR" --archive-eligibility-review "$ELIGIBILITY_DIR" --plan-id "$PLAN_ID" --out "$STATUS_REPORT_DIR" --json
```

## Artifact map

| Step | Command | Main JSON artifact | Summary Markdown artifact | Safety expectation |
| --- | --- | --- | --- | --- |
| Plan | `--root` with `--out` | `artifact-archive-plan.json` | plan summary | Read-only scan plus plan artifact write only. |
| Plan validation | `--validate` | validation JSON | validation summary | Validates the plan; no source or Docker mutation. |
| Dry-run receipt | `--dry-run-receipt` | `archive-dry-run-receipt.json` | dry-run receipt summary | Records non-executable dry-run evidence. |
| Dry-run receipt validation | `--validate-dry-run-receipt` | validation JSON | validation summary | Checks receipt and plan consistency. |
| Execution readiness | `--execution-readiness` | readiness JSON | readiness summary | Review signal only, not execution approval. |
| Archive bundle | `--create-archive-bundle` | archive manifest JSON | archive summary | Existing confirm-gated copy-only archive bundle creation; no source deletion, movement, or cleanup. |
| Archive bundle validation | `--validate-archive-bundle` | archive validation JSON | validation summary | Validates copied archive artifacts only. |
| Archive eligibility review | `--archive-eligibility-review` | eligibility review JSON | eligibility summary | Read-only eligibility/reporting. |
| Source-action dry run | `--archive-source-action-dry-run` | `archive-source-action-dry-run.json` | `archive-source-action-dry-run-summary.md` | Read-only/reporting; source action unavailable. |
| Source-action dry-run validation | `--validate-archive-source-action-dry-run` | `archive-source-action-dry-run-validation.json` | `archive-source-action-dry-run-validation-summary.md` | Validates dry-run packet; does not authorize source action. |
| Human review packet | `--archive-source-action-review-packet` | `archive-source-action-review-packet.json` | `archive-source-action-human-review.md` | Pasteable human review evidence only. |
| Decision receipt | `--archive-source-action-decision-receipt` | `archive-source-action-decision-receipt.json` | `archive-source-action-decision-receipt-summary.md` | Records operator review decision; not approval or execution. |
| Readiness gate | `--archive-source-action-readiness-gate` | `archive-source-action-readiness-gate.json` | `archive-source-action-readiness-summary.md` | Final reviewability gate for a future PR/lane only. |
| Operator status report | `--archive-source-action-status-report` | `archive-source-action-status-report.json` | `archive-source-action-operator-status.md` | Human/machine status report; no copy, source action, cleanup, or execution. |

## Operator decision matrix

| Status | What it means | Operator may do next | Operator must not do | Source action available | Cleanup available | Execution available |
| --- | --- | --- | --- | --- | --- | --- |
| `ready_for_operator_review` | Evidence is coherent enough for operator inspection. | Read the status report, review artifacts, and decide whether a future PR should be proposed. | Treat readiness as permission to execute or clean up. | No | No | No |
| `ready_for_future_pr_review` | Evidence may be reviewable in a separate future PR/lane. | Prepare a future review request for SeedOfEvil if policy allows. | Execute source action from this lane. | No | No | No |
| `ready_for_human_review` | The human review packet is complete enough to read. | Complete manual review checklist. | Treat the packet as approval. | No | No | No |
| `ready_for_source_action_review` | The dry-run evidence is ready to be reviewed as a source-action proposal concept. | Inspect candidates, checksums, and safety notes. | Run source action; no source-action command exists here. | No | No | No |
| `decision_recorded` | An operator decision receipt was written. | Feed it to the readiness gate or status report. | Treat the receipt as merge approval or execution authorization. | No | No | No |
| `partial` | Some evidence exists but the chain is incomplete or optional cross-checks are missing. | Re-run missing read-only/reporting validation steps against controlled fixture paths. | Fill gaps with mutation, cleanup, or manual source changes. | No | No | No |
| `not_ready` | Required evidence is inconsistent, missing, stale, or not reviewable. | Stop and inspect the failing artifact, checksum, plan id, or status reason. | Continue to future source-action review as if ready. | No | No | No |
| `failed` | Validation failed or the artifact contract was violated. | Stop, preserve evidence, and fix the documentation/test/evidence issue in a new safe pass. | Execute, clean up, repair sources, or bypass review. | No | No | No |

## Status meaning

`ready_for_operator_review`, `ready_for_future_pr_review`, `ready_for_human_review`, and `ready_for_source_action_review` are reviewability statuses. They mean the operator has evidence to read; they do not mean executable, approved, merged, remediated, recovered, or cleaned up.

`decision_recorded` means a decision receipt exists. It is a receipt, not approval to mutate. `partial`, `not_ready`, and `failed` mean the operator should stop and inspect the evidence chain before any future PR/lane discussion.

## Troubleshooting partial/not_ready/failed

- Confirm every command used the same `$PLAN_ID` and the intended evidence directories.
- Check `manifest.json` and `checksums.json` for missing, stale, or mismatched artifacts.
- Read the Markdown summary first, then the main JSON artifact for machine-readable reasons.
- For `partial`, identify which optional or required upstream artifact was absent and rerun only the missing read-only/reporting step.
- For `not_ready`, inspect status reasons and fix the evidence chain before requesting review.
- For `failed`, preserve the failing artifact and stop; do not repair by modifying sources, cleaning up paths, restarting containers, pruning Docker, or bypassing validation.

## Safety contract

This workflow is docs/runbook/evidence oriented. It preserves no-cleanup-shaped command-surface guardrails: no cleanup execution command is documented, no delete/move/prune/restart/source-action execution command is documented, and no status/reporting command copies, moves, deletes, modifies, remediates, rolls back, recovers, restarts, prunes, or executes. Source action is not available; cleanup is not available; execution is not available.

## Future PR/lane requirements

Future source action would require a separate PR/lane, explicit command-surface review, safety tests, validation evidence, and SeedOfEvil final merge ownership. The future lane would need to define a named, narrow, auditable recipe and prove that it does not expand into broad cleanup, arbitrary shell execution, Docker/Compose mutation, remediation, rollback, recovery, or natural-language execution. This runbook is not that lane.
