# Validation Matrix (test impact map)

This is the human-readable view of the validation impact map. The machine
source of truth is
[`../scripts/validation_matrix.json`](../scripts/validation_matrix.json), which
is consumed by [`../scripts/validate_pr.py`](../scripts/validate_pr.py). Lane
definitions and policy live in [`VALIDATION_LANES.md`](VALIDATION_LANES.md).

When the JSON and this table disagree, **the JSON wins** — it is what the
optimizer actually uses. Keep them in sync when editing.

For every **full** row, the full-suite command is the bounded runner
`python scripts/run_full_pytest.py`, not raw `pytest -q`. The runner uses
`pytest-xdist` when available, falls back to serial pytest when unavailable, and
always includes `--durations=25` so slow tests are visible. For validation
infrastructure changes or suspect Docker01/dev containers, preflight the
environment first with `python scripts/check_validation_env.py --profile
docker01`; the doctor is read-only and classifies missing dev dependencies, OS
tools, Python path mismatches, xdist availability, and cache hygiene before the
expensive lane runs.

After a full/Lane C run, inspect the recorded heartbeat/status/manifest evidence
with the read-only viewer `python scripts/validation_status.py --latest`
(or `--run-dir <run_dir>` / `--json`). It classifies the run as
passed/failed/incomplete/unknown and reports `pass_eligible` and
`rerun_required` so an interrupted/incomplete run is never mistaken for merge
evidence. `--latest` deterministically prefers recent PR-specific run
directories over older persisted manifests and can be filtered with `--pr`/
`--commit` or explained with `--explain-selection`; pass `--run-dir <path>` to
force a specific run. See [`VALIDATION_LANES.md`](VALIDATION_LANES.md) for the
viewer's status table, merge rule, and latest-discovery priority.

How matching works:

- Patterns are matched **first-match-wins, in order**, against each changed
  file path (`**` crosses directories; `*` stays within a path segment).
- A change's lane is the **highest** lane across all its files, plus any safety
  escalation.
- `src/**/*.py` that matches no rule falls back to **targeted_runtime with a
  warning**. Any other unrecognized path falls back to **full** as a safe
  default.

---

## Changed-file pattern → lane → tests

| Pattern | Lane | Recommended regression tests |
| --- | --- | --- |
| `docs/**` | fast | `test_pr110_v1_docs_contract`, `test_pr112_v1_demo_contract`, `test_pr114_v1_command_surface`, `test_pr119_v1_release_candidate_docs`, `test_pr143_command_surface_audit` |
| `README.md` | fast | `test_pr110_v1_docs_contract`, `test_pr114_v1_command_surface` |
| `OPS.md` | fast | `test_pr110_v1_docs_contract` |
| `CHANGELOG.md` | fast | `test_pr120_v1_release_notes` |
| `*.md`, `examples/**`, `LICENSE`, `.gitignore`, `.env.example` | fast | — (docs/contract) |
| `src/shellforgeai/core/ask_routing.py` | targeted_runtime | `test_pr105_*`, `test_pr106_*`, `test_pr42_ask_routing_hardening`, `test_pr131_*`, `test_pr134_*`, `test_pr135_*`, `test_pr156_*`, `test_pr222_ask_docker_evidence_grounding` |
| `src/shellforgeai/core/ask_docker_grounding.py` | targeted_runtime | `test_pr222_ask_docker_evidence_grounding`, `test_pr223_ask_safe_command_suggestions`, `test_pr82_broad_ask_triage` |
| `src/shellforgeai/core/command_suggestions.py` | targeted_runtime | `test_pr100_command_suggestions`, `test_pr222_ask_docker_evidence_grounding`, `test_pr223_safe_command_registry`, `test_pr223_ask_safe_command_suggestions` |
| `src/shellforgeai/core/safe_commands.py` | targeted_runtime | `test_pr223_safe_command_registry`, `test_pr223_ask_safe_command_suggestions`, `test_pr222_ask_docker_evidence_grounding` |
| `src/shellforgeai/core/intent_nuance.py` | targeted_runtime | `test_pr131_*`, `test_pr134_*`, `test_pr135_*` |
| `src/shellforgeai/core/recipe_registry.py` | targeted_runtime | `test_pr154_v2_recipe_registry`, `test_pr155_v2_recipe_preflight`, `test_pr156_*` |
| `src/shellforgeai/core/recipe_preflight.py` | targeted_runtime | `test_pr155_v2_recipe_preflight`, `test_pr156_*`, `test_pr99_remediation_self_test` |
| `src/shellforgeai/core/*handoff*` | targeted_runtime | `test_pr150_*`, `test_pr152_*`, `test_pr153_*` |
| `src/shellforgeai/core/ops_report_artifact.py` | targeted_runtime | `test_pr104_*`, `test_pr107_*`, `test_pr108_*`, `test_pr109_*` |
| `src/shellforgeai/core/triage_ranking.py` | targeted_runtime | `test_pr81_*`, `test_pr82_*`, `test_pr83_*`, `test_pr146_*` |
| `src/shellforgeai/interactive/**` | targeted_runtime | `test_pr122_*`, `test_pr124_*`, `test_pr128_*`, `test_pr129_*`, `test_pr130_*`, `test_pr132_*`, `test_pr136_*` … `test_pr142_*` |
| `src/shellforgeai/cli.py` | targeted_runtime | `test_cli`, `test_pr114_*`, `test_pr143_*`, `test_pr184_cli_command_surface_golden` (broad router rewrites → use `--profile full`) |
| `src/shellforgeai/commands/**` | targeted_runtime | `test_pr182_*`, `test_pr183_*`, `test_pr184_cli_command_surface_golden` (command-module extraction; broad/core moves → use `--profile full`) |
| `tests/golden/cli_command_surface_pr184.json` | targeted_runtime | `test_pr184_cli_command_surface_golden` |
| `tests/helpers/cli_surface.py` | targeted_runtime | `test_pr184_cli_command_surface_golden` + `test_pr208_command_surface_performance_polish` (shared invocation cache + duration report) |
| `tests/test_pr208_command_surface_performance_polish.py` | targeted_runtime | `test_pr208_command_surface_performance_polish` (cache correctness, coverage-preserved, deterministic duration report) |
| `scripts/cli_surface_snapshot.py` | fast | `test_pr184_cli_command_surface_golden` (read-only snapshot aid) |
| `src/shellforgeai/render/**` | targeted_runtime | `test_pr126_*`, `test_pr22_json_stdout_validity` |
| `src/shellforgeai/core/*remediation*` | **full** | remediation suite (`test_pr89_*`, `test_pr91_*`–`test_pr99_*`) + `python scripts/run_full_pytest.py` |
| `src/shellforgeai/core/*rollback*` | **full** | `test_pr93_*`, `test_pr94_rollback_execute`, `test_pr65_*` + `python scripts/run_full_pytest.py` |
| `src/shellforgeai/core/*restart*` | **full** | restart/mission suite + `python scripts/run_full_pytest.py` |
| `src/shellforgeai/core/*mission*` | **full** | `test_pr52_*`, `test_pr53_mission_execute`, `test_pr54_*` + `python scripts/run_full_pytest.py` |
| `src/shellforgeai/core/*cleanup*` | **full** | cleanup suite (`test_pr55_*`, `test_pr74_*`–`test_pr77_*`) + `python scripts/run_full_pytest.py` |
| `src/shellforgeai/core/apply_bundle.py` | **full** | `test_pr33_apply_preflight`, `test_pr37_action_compiler` + `python scripts/run_full_pytest.py` |
| `src/shellforgeai/core/approvals.py` | **full** | `test_pr32_approvals`, `test_pr46_mutation_gate` + `python scripts/run_full_pytest.py` |
| `src/shellforgeai/core/guards.py` | **full** | `test_pr46_mutation_gate`, `test_pr42_ask_routing_hardening` + `python scripts/run_full_pytest.py` |
| `src/shellforgeai/core/disposable_*` | **full** | disposable harness + remediation suite + `python scripts/run_full_pytest.py` |
| `src/shellforgeai/core/compose_context.py` | **full** | compose suite + `python scripts/run_full_pytest.py` |
| `src/shellforgeai/policy/**` | **full** | `test_policy`, `test_pr46_mutation_gate` + `python scripts/run_full_pytest.py` |
| `src/shellforgeai/tools/**` | **full** | tool suites + `python scripts/run_full_pytest.py` |
| `src/shellforgeai/util/subprocess.py` | **full** | `test_investigation_tools` + `python scripts/run_full_pytest.py` |
| `Dockerfile`, `*.Dockerfile` | **full** | packaging/import + `python scripts/run_full_pytest.py` |
| `pyproject.toml` | **full** | `test_cli`, `test_config` + `python scripts/run_full_pytest.py` |
| `requirements*` | **full** | packaging/import + `python scripts/run_full_pytest.py` |
| `compose.yaml` / `compose.yml` / `docker-compose*` | **full** | `test_compose_runtime_hygiene` + `python scripts/run_full_pytest.py` |
| `Makefile` | **full** | build + `python scripts/run_full_pytest.py` |
| `config/**` | **full** | `test_config`, `test_profiles` + `python scripts/run_full_pytest.py` |
| `.github/**` | **full** | CI/workflow + `python scripts/run_full_pytest.py` |
| `scripts/v1_validate.sh` | **full** | `test_pr113_*`, `test_pr118_*` + `python scripts/run_full_pytest.py` |
| `scripts/validate_pr.py` | **full** | `test_pr157_validation_lane_optimizer` + `python scripts/run_full_pytest.py` |
| `scripts/validation_matrix.json` | **full** | `test_pr157_validation_lane_optimizer` + `python scripts/run_full_pytest.py` |
| `scripts/sfai_docker01_pr_lane.py` | **full** | validation-lane helper tests (`test_pr161_*`, `test_pr176_*`) + `python scripts/run_full_pytest.py` |
| `scripts/validation_heartbeat.py` | **full** | `test_pr176_validation_heartbeat_incomplete` + `python scripts/run_full_pytest.py` |
| `scripts/validation_env_preflight.py` | **full** | `test_pr178_validation_env_preflight` + `python scripts/run_full_pytest.py` |
| `scripts/validation_container_fallback.py` | **full** | `test_pr179_validation_container_fallback_packet` + `python scripts/run_full_pytest.py` |
| `scripts/validation_status.py` | **full** | `test_pr177_*`, `test_pr178_*`, `test_pr179_*` + `python scripts/run_full_pytest.py` |
| `scripts/run_full_pytest.py` | **full** | `test_pr160_*`, `test_pr176_*` + `python scripts/run_full_pytest.py` |
| `scripts/docker01_operator_qa_bundle.py` | **full** | `test_pr206_docker01_operator_qa_bundle` + `test_pr207_qa_bundle_lifecycle` + `python scripts/run_full_pytest.py` |
| `scripts/docker01_artifact_archive_plan.py` | targeted_runtime | `test_pr231_docker01_artifact_archive_plan` + storage/hygiene/QA/command-surface/mutation-refusal targeted checks |
| `scripts/**` (other) | **full** | + `python scripts/run_full_pytest.py` |
| `tests/conftest.py` | **full** | shared harness → `python scripts/run_full_pytest.py` |
| `tests/**` | fast | the changed test files are run directly |
| `src/**/*.py` (unmatched) | targeted_runtime | PR-specific tests + **warning** if none resolve |
| anything else (unmatched) | **full** | safe default |

---

## Safety-boundary triggers → full

When changed **non-documentation** content (a diff, provided content, or
`--scan-content`) contains any of these keywords, the change escalates to
**full** regardless of its path lane:

```
execute            confirm              cleanup_executed
remediation_executed  rollback_executed   docker_compose_executed
container_restarted   shell_true           subprocess
os.system          shell=True           docker restart
docker compose     rm -rf               chmod
chown              apply_executed       mission_created
plan_created
```

Documentation that merely *describes* these keywords does not escalate. This is
intentional: editing `docs/safety.md` to explain that ShellForgeAI never uses
`shell=True` stays in Lane A; adding `shell=True` to a `.py` file jumps to
Lane C.

A `--profile` override may escalate a lane but may never de-escalate below a
safety-required full lane.

---

## Examples

```bash
# docs-only → Lane A (fast), no full pytest
python scripts/validate_pr.py --changed-files docs/cli.md

# ask routing → Lane B (targeted), PR-specific + related tests, no full pytest
python scripts/validate_pr.py --changed-files src/shellforgeai/core/ask_routing.py --pr 156

# remediation execution → Lane C (full), includes python scripts/run_full_pytest.py
python scripts/validate_pr.py --changed-files src/shellforgeai/core/disposable_remediation.py

# Dockerfile / dependency → Lane C (full)
python scripts/validate_pr.py --changed-files Dockerfile

# validation infrastructure → Lane C (full)
python scripts/validate_pr.py --changed-files scripts/v1_validate.sh

# force full validation on any change
python scripts/validate_pr.py --changed-files docs/cli.md --full-validation
```

## Docker01 hygiene report checks

| Check | Command | Purpose | Mutates state |
| --- | --- | --- | --- |
| Hygiene dry run | `python scripts/docker01_hygiene_report.py --dry-run` | Lists planned read-only Docker01 hygiene checks and output path. | No |
| Hygiene report | `python scripts/docker01_hygiene_report.py --out /tmp/sfai-docker01-hygiene-report` | Writes disk/image/artifact inventory, raw command captures, strict JSON, and proposal-only cleanup candidates. | No |
| Hygiene unit tests | `pytest -q tests/test_pr209_docker01_hygiene_report.py` | Verifies report creation, dry-run behavior, command allowlist, parsing, partial failures, and proposal-only cleanup semantics with fakes. | No |

The hygiene report uses a fixed allowlist for `df` and Docker inspection commands and must not run cleanup, prune, image removal, file deletion, Docker Compose mutation, restart, package install, network, or cloud merge/apply operations.

## Docker01 storage health report checks

| Check | Command | Purpose | Mutates state |
| --- | --- | --- | --- |
| Storage health JSON | `python scripts/docker01_storage_health_report.py --json` | Emits strict read-only JSON: root capacity, filesystems/device mapping, disk pressure, Docker data-path pressure, and bounded EXT4/dm/IO-journal-inode kernel warning evidence. | No |
| Storage health report dir | `python scripts/docker01_storage_health_report.py --out /tmp/sfai-docker01-storage-health --json` | Writes `storage-health-report.json`, `storage-health-summary.md`, `commands-run.json`, `manifest.json`, `checksums.json` (SHA256 + sizes). | No, except writing the report directory |
| Storage health unit tests | `pytest -q tests/test_pr230_docker01_storage_health_report.py` | Verifies JSON/human output, warning-pattern detection and bounding, output files, partial-on-denied-dmesg, and read-only safety with fakes. | No |

## Docker01 artifact archive dry-run receipt checks

| Check | Command | Purpose | Mutates state |
| --- | --- | --- | --- |
| Archive plan | `python3 scripts/docker01_artifact_archive_plan.py --root /tmp --out /tmp/sfai-pr231-artifact-archive-plan` | Writes read-only plan metadata for bounded ShellForgeAI evidence artifacts. | No, except writing the plan directory |
| Plan validation | `python3 scripts/docker01_artifact_archive_plan.py --validate /tmp/sfai-pr231-artifact-archive-plan --json` | Validates required files, manifest/checksums, plan id, candidate scope, confirmation contract, and safety flags. | No |
| Dry-run receipt | `python3 scripts/docker01_artifact_archive_plan.py --dry-run-receipt /tmp/sfai-pr231-artifact-archive-plan --plan-id sha256:<plan-id> --json` | Produces strict read-only receipt JSON after validation and exact plan-id match. | No |
| Dry-run receipt dir | `python3 scripts/docker01_artifact_archive_plan.py --dry-run-receipt /tmp/sfai-pr231-artifact-archive-plan --plan-id sha256:<plan-id> --out /tmp/sfai-pr233-artifact-archive-dry-run --json` | Writes receipt metadata, future checklist, manifest, and checksums only. | No, except writing the receipt directory |
| Dry-run receipt validation | `python3 scripts/docker01_artifact_archive_plan.py --validate-dry-run-receipt /tmp/sfai-pr233-artifact-archive-dry-run --json` | Validates receipt required files, JSON, manifest/checksums, safety flags, candidate scope, and future contract; plan cross-check is `not_requested`. | No |
| Dry-run receipt validation + plan | `python3 scripts/docker01_artifact_archive_plan.py --validate-dry-run-receipt /tmp/sfai-pr233-artifact-archive-dry-run --plan-dir /tmp/sfai-pr231-artifact-archive-plan --json` | Also validates the source plan and checks plan id plus candidate counts/classes/bytes and contract consistency. | No |
| Dry-run receipt validation dir | `python3 scripts/docker01_artifact_archive_plan.py --validate-dry-run-receipt /tmp/sfai-pr233-artifact-archive-dry-run --out /tmp/sfai-pr234-artifact-archive-dry-run-validation --json` | Writes validation JSON, summary, manifest, and checksums only. | No, except writing the validation directory |
| Execution readiness | `python3 scripts/docker01_artifact_archive_plan.py --execution-readiness /tmp/sfai-pr235-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr235-artifact-archive-dry-run --json` | Validates the full plan + dry-run receipt evidence chain and reports human-review eligibility for a future separate PR/lane only. | No |
| Execution readiness dir | `python3 scripts/docker01_artifact_archive_plan.py --execution-readiness /tmp/sfai-pr235-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr235-artifact-archive-dry-run --out /tmp/sfai-pr235-artifact-archive-readiness --json` | Writes readiness JSON, summary, future checklist, safety notes, manifest, and checksums only. | No, except writing the readiness directory |

The dry-run receipt, receipt-validation, and execution-readiness lanes never create an archive, copy/move/modify/delete source artifacts, modify the source plan directory, run cleanup/prune/delete/restart/remediation/rollback/recovery, executes Docker/Compose mutation, runs validation/pytest/QA from the helper, calls network/model/Codex/GitHub/cloud actions, or uses `shell=True`. `execution_available=false` remains explicit; any real archive execution would be a separate PR/lane requiring exact plan id and `CONFIRM_SHELLFORGEAI_ARTIFACT_ARCHIVE`. SeedOfEvil remains final merge owner.

The storage health report uses a fixed read-only command allowlist (`df -P -B1`, `findmnt --json`, `dmesg --level=err,warn --ctime`, `journalctl -k -p warning..alert --no-pager -n <bounded>`) plus `shutil.disk_usage` and `/proc/mounts`, always with `shell=False`. It must not run `fsck`/`e2fsck`/`xfs_repair`, mount/remount/umount, Docker prune/image/volume/container removal, file deletion, restart, Docker/Compose mutation, remediation/rollback/recovery, package install, network, model/Codex, or GitHub/cloud merge/apply operations.

## Docker01 hygiene validator impact

Changes to `scripts/docker01_hygiene_report.py` validation behavior or `tests/test_pr210_docker01_hygiene_validate.py` are safety/reporting infrastructure changes and should run the focused PR209/PR210 hygiene tests plus full validation when practical:

```bash
pytest -q tests/test_pr209_docker01_hygiene_report.py
pytest -q tests/test_pr210_docker01_hygiene_validate.py
pytest -q tests -k "hygiene_report or hygiene_validate or qa_bundle or validation_status"
python scripts/run_full_pytest.py
```

The validator is read-only and uses bounded reads: report JSON is sized for realistic Docker01 outputs, commands/Markdown have separate caps, and raw captures remain tightly bounded. Oversized files fail safely. It never executes Docker, Docker Compose, cleanup, restart, package install, network fetch, model/Codex, merge, push, or arbitrary shell commands.
## Docker01 hygiene history and compare

Docker01 hygiene reports are useful when disk, image, and artifact pressure can be trended instead of reviewed as a single point-in-time snapshot. The helper can now read previously generated PR209/PR210 report directories and produce history or comparison output without running Docker and without generating a new report.

Use these read-only forms when reviewing whether Docker01 artifact/image pressure is growing before any future scoped cleanup lane is considered:

```bash
python scripts/docker01_hygiene_report.py --history --json
python scripts/docker01_hygiene_report.py --compare <old_report_dir> <new_report_dir> --json
python scripts/docker01_hygiene_report.py --compare-latest --json
```

`--history` and `--compare-latest` discover reports under `/tmp` by default; pass `--root <dir>` for a scoped offline location. Candidate directories must contain `hygiene-report.json`, `hygiene-summary.md`, `candidate-cleanup-plan.md`, and `commands-run.json` to be treated as valid hygiene reports. Stale/non-report candidates, including old hygiene review-bundle-shaped directories, are reported separately as bounded ignored candidates with a count and stable reason; they do not make history `partial` when valid reports can be read. `--compare-latest` and `--review-bundle-latest` select valid hygiene reports only.

These modes read existing report files only. They do not run Docker, Docker Compose, report generation, cleanup, prune, image removal, file deletion, restart, remediation, rollback, recovery, model calls, network calls, or arbitrary shell execution. A passing validation result or comparison summary is review evidence only and does not authorize cleanup execution.

## Docker01 hygiene review bundle checks

| Check | Command | Purpose | Mutates state |
| --- | --- | --- | --- |
| Hygiene review bundle | `python scripts/docker01_hygiene_report.py --review-bundle <report_dir> --json` | Packages an existing report, validation, optional history/compare context, candidate plan copy, safety notes, manifest, checksums, and strict JSON rollup. | No, except writing the bundle directory |
| Latest hygiene review bundle | `python scripts/docker01_hygiene_report.py --review-bundle-latest --root /tmp --json` | Selects the newest valid existing report under a discovery root and writes the same bounded review packet. | No, except writing the bundle directory |
| Hygiene review tests | `pytest -q tests/test_pr212_docker01_hygiene_review_bundle.py` | Verifies bundle files, JSON, partial/warning behavior, bounded copies, latest discovery, and no Docker/report generation/source mutation. | No |

Review bundles are evidence only. Validation, compare, and bundle output do not authorize cleanup execution; any cleanup requires a separate narrow reviewed lane.

## Docker01 QA bundle hygiene evidence checks

| Check | Command | Purpose | Mutates state |
| --- | --- | --- | --- |
| QA bundle with hygiene summary | `python scripts/docker01_operator_qa_bundle.py --pr 213 --commit <sha> --json` | Adds existing hygiene history/compare-latest status and latest report metrics to the operator QA evidence bundle. | No |
| QA bundle with hygiene review bundle | `python scripts/docker01_operator_qa_bundle.py --pr 213 --commit <sha> --include-hygiene-review-bundle --json` | Opts in to bounded latest hygiene review-bundle packaging and records its status/path. | Only writes the bounded review bundle artifact |
| QA bundle hygiene tests | `pytest -q tests/test_pr213_docker01_qa_bundle_hygiene_integration.py` | Verifies raw outputs, non-critical command entries, narrow allowlist, dry-run behavior, opt-in review bundle, and hygiene safety drift failure. | No |

Hygiene evidence inside the QA bundle is review-only. Missing history/compare evidence is non-blocking; cleanup/prune/delete/restart or Docker/Compose mutation safety flags fail QA safety.

## Docker01 QA bundle model receipt evidence checks

| Check | Command | Purpose | Mutates state |
| --- | --- | --- | --- |
| QA bundle with model receipt evidence | `python scripts/docker01_operator_qa_bundle.py --pr 229 --commit <sha> --json` | Adds read-only Model Doctor receipt history status, latest receipt path/validation, latest probe status/auth readiness, and valid/invalid counts to the operator QA bundle without a live probe or model call. | No |
| QA bundle skipping model receipts | `python scripts/docker01_operator_qa_bundle.py --pr 229 --commit <sha> --skip-model-receipts --json` | Opts out of model receipt evidence collection. | No |
| QA bundle model receipt tests | `pytest -q tests/test_pr229_docker01_qa_bundle_model_receipts.py` | Verifies the `model_receipts` block, summary section, raw artifacts, empty/unavailable handling, secret/drift safety failure, and that no live probe/model call/Docker mutation is performed. | No |

Model receipt evidence inside the QA bundle is read-only. The QA bundle performs no live probe and no model call (`model_receipts.safety` reports `model_called=false`/`live_probe_performed=false`); a historical receipt's `model_called=true` is accepted as evidence of an earlier explicit probe. Empty/unavailable receipt history is non-blocking; a secret marker or historical safety drift fails QA safety.

## Docker01 PR-lane manifest discovery

The Docker01 PR lane emits a scoped validation packet under `/tmp/sfai-pr<PR>-<shortsha>-validation-<timestamp>/`. `validation_status.py --latest --pr <PR> --commit <sha>` selects only exact PR/commit evidence and ignores stale packets from other PRs or commits. QA bundles may use the packet's `validation-status.json` and `validation-manifest.json` to populate validation sections without falling back to scoped `not_found` when current lane evidence exists.

## Docker01 PR-lane status/resume evidence checks

| Check | Command | Purpose | Mutates state |
| --- | --- | --- | --- |
| PR-lane status JSON | `python scripts/sfai_docker01_pr_lane.py --pr <PR> --commit <sha> --status --json` | Emits strict JSON describing source, container, validation, QA bundle, safety flags, classification, and safe next command. | No |
| PR-lane status human | `python scripts/sfai_docker01_pr_lane.py --pr <PR> --commit <sha> --status` | Prints a concise pasteable interrupted-lane resume summary. | No |
| PR215 status tests | `pytest -q tests/test_pr215_docker01_pr_lane_status.py` | Verifies JSON contract, deterministic classifications, exact evidence discovery, mutual exclusion, and read-only allowlist behavior without Docker. | No |

Classifications are deterministic: matching source/container/labels/image plus pass-eligible validation and passed QA is `already_complete`; matching deploy plus missing/partial/failed QA is `needs_qa`; matching deploy plus missing or rerun-required validation is `needs_validation`; source/compose/container mismatch is `needs_deploy`; unhealthy containers, restart drift, label/image mismatch, failed validation, or setup-failure evidence are `blocked`. Safe-next guidance is non-mutating and favors evidence readers or the guarded lane helper, never direct Compose, cleanup, prune, restart, or direct pytest.

PR-lane status image matching compares the trusted Compose `image:` tag and container `Config.Image` tag to the expected `lab/shellforgeai:pr<PR>-<shortsha>` tag; Docker-resolved `sha256:` IDs/digests do not force a deploy mismatch. Validation evidence selection prefers exact PR/commit pass-eligible packets over older setup-failure packets, and QA discovery includes exact PR/commit `operator-qa-bundle` directories.

## Docker01 merge-readiness evidence checks

| Check | Command | Purpose | Mutates state |
| --- | --- | --- | --- |
| Merge-readiness JSON | `python scripts/docker01_merge_readiness.py --pr <PR> --commit <sha> --json` | Emits strict JSON summarizing existing exact PR/commit PR-lane, validation, QA, hygiene, and safety evidence. | No |
| Merge-readiness packet | `python scripts/docker01_merge_readiness.py --pr <PR> --commit <sha> --out /tmp/sfai-pr<PR>-<short>-merge-readiness` | Writes bounded JSON/Markdown/manifest/checksum review files plus bounded raw evidence JSON. | No, except writing the report directory |
| Merge comment draft | `python scripts/docker01_merge_readiness.py --pr <PR> --commit <sha> --comment` | Prints paste-ready Markdown reviewer text from existing evidence. | No |
| Merge comment file | `python scripts/docker01_merge_readiness.py --pr <PR> --commit <sha> --out /tmp/sfai-pr<PR>-<short>-merge-readiness --comment` | Writes `merge-comment.md` beside the report packet. | No, except writing the report directory |
| Merge-readiness tests | `pytest -q tests/test_pr216_docker01_merge_readiness.py` | Verifies JSON/Markdown contracts, exact evidence discovery, deterministic classification, warnings vs blockers, output packet files, and safety allowlist behavior without Docker. | No |

`pass_candidate` is possible only when exact PR/commit evidence is present, PR-lane status is complete, validation passed and is pass-eligible without rerun, QA passed with zero safety assertion failures, available source/container evidence is clean, and all mutation safety flags are false. `hold_candidate` is used for explicit blockers. `unknown` is used for incomplete evidence without a proven blocker. `--comment` maps them to `PASS / mergeable`, `HOLD / needs follow-up`, and `NEEDS EVIDENCE / cannot determine`. The report and comment are reviewer evidence only, never GitHub posting/approval/merge, and SeedOfEvil remains final merge owner.


### Docker01 validation evidence finalization

| Check | Command | Purpose | Mutates services? |
| --- | --- | --- | --- |
| Finalize existing validation log | `python scripts/docker01_validation_evidence.py --pr <PR> --commit <sha> --log <validation-log-path> --status passed --json` | Writes PR214-compatible validation evidence from an already-completed Docker01 validation attempt. | No; evidence files only |
| Exact latest validation evidence | `python scripts/validation_status.py --latest --pr <PR> --commit <sha> --json --explain-selection` | Selects exact PR/commit evidence by pass, failed, setup-failure, interrupted, then not-found precedence. | No |

The finalizer is evidence lifecycle tooling only. It does not run validation,
pytest, QA, Docker/Compose, cleanup, restart, prune, delete, remediation,
rollback, recovery, network calls, or model calls. Failed, setup-failure,
interrupted, and unknown evidence is recorded but never pass eligible.

Automatic PR-lane evidence finalization is part of the guarded lane terminal
path: success, failure, setup failure, and interrupted outcomes write exact
PR/commit validation evidence without a manual finalizer step. Lane C/full runs
preserve `full_validation=true` through validation status, PR-lane status,
merge-readiness JSON, and merge-comment rendering.

The disposable validation fallback packet includes an in-container bootstrap
step (`apt-get update` plus `procps`, `git`, and `rsync`) so tests that inspect
process state have `ps` available. The generator still writes inert command
text/argv evidence only and performs no host package installation.

When the disposable fallback command completes, it calls the evidence finalizer
inside the container and writes final PR/commit validation evidence into the
mounted run directory. That directory is the same lane evidence directory read
by `validation_status.py --latest --pr <PR> --commit <sha>`.

Default PR-lane validation evidence now lives under
`/tmp/shellforgeai-validation-runs/`, a writable discovery root scanned by the
validation-status viewer, avoiding a manual `sudo` finalizer step for the normal
lane path.

Validation discovery treats environment-configured roots as additive: configured
persisted roots do not suppress the built-in writable lane evidence root.

For split host/fallback runs in the same exact PR/commit/run directory, the
terminal disposable fallback finalizer packet is the selected final validation
attempt. A later fallback pass supersedes earlier host `setup_failure` evidence
and is pass eligible; the setup failure remains visible as a warning/process
note. Without a later successful exact validation attempt, failed, setup, and
interrupted evidence remains non-pass-eligible.


### Docker01 PR lane validation evidence self-check

After the guarded Docker01 PR lane writes/finalizes validation evidence, it now performs a read-only validation evidence self-check for the exact PR/commit through `validation_status.py --latest --pr <PR> --commit <sha> --json --explain-selection`. The lane writes `validation-evidence-check.json` and `validation-evidence-check.md` in the validation run directory and references the check from the lane manifest and summary.

The self-check proves whether exact PR/commit evidence was selected, whether it is pass-eligible, whether a rerun is required, whether full validation ran, and whether duplicate full pytest evidence was detected. If host setup fails but a later disposable fallback validation passes, the fallback pass can supersede the earlier setup failure while preserving the earlier setup failure as a warning/process note. If evidence is not discoverable after validation, the lane reports a validation evidence lifecycle failure/needs-followup rather than silently treating the run as merge-ready.

The self-check does not run validation, pytest, the operator QA bundle, cleanup, Docker prune, Docker image removal, Docker/Compose mutation, restarts, remediation, rollback, recovery, GitHub posting/approval/merge, model calls, or cloud apply/merge/push. Merge-readiness and merge-comment tools remain separate read-only post-QA checks. SeedOfEvil remains final merge owner.

### Docker01 V2 readiness evidence snapshot

`scripts/docker01_v2_readiness.py` creates a read-only evidence snapshot for an exact Docker01 PR/commit and classifies it as `v2_candidate`, `v2_not_ready`, or `v2_unknown`. It consumes existing PR-lane status, validation status, operator QA bundle, merge-readiness, and available hygiene evidence only; it does not deploy, build, run validation, run pytest, generate QA, clean/prune/delete, restart containers, mutate Docker/Compose, post to GitHub, call a model, or replace reviewer/operator judgment. SeedOfEvil remains final merge owner.

Examples:

```bash
python scripts/docker01_v2_readiness.py --pr <PR> --commit <sha> --json
python scripts/docker01_v2_readiness.py --pr <PR> --commit <sha>
python scripts/docker01_v2_readiness.py --pr <PR> --commit <sha> --out /tmp/sfai-pr<PR>-<short>-v2-readiness
```

When `--out` is supplied, the helper writes `v2-readiness.json`, `v2-readiness-summary.md`, `manifest.json`, `checksums.json`, and bounded raw evidence JSON files for validation status, PR-lane status, merge-readiness, and QA bundle summary. Missing evidence is recorded as `status=not_available`/`not_found` rather than crashing.

`v2_candidate` requires exact PR/commit evidence, matching source/Compose/container state, running healthy container with acceptable restart count, passed pass-eligible validation with no rerun required, passed operator QA and QA safety assertions, `pass_candidate` merge-readiness, and no mutation safety drift. Explicit failures become `v2_not_ready`; missing or incomplete evidence without an explicit failure becomes `v2_unknown`. Known metadata hygiene advisories, ignored stale/non-report hygiene candidates, and model-doctor `auth_readiness=unknown` warnings are non-blocking when the rest of the evidence is clean.

Missing exact validation or QA evidence is reported as incomplete `v2_unknown` evidence, not as a false validation/QA failure; explicit failed/setup/interrupted/rerun-required validation or failed QA remains `v2_not_ready`. The operator QA bundle's read-only Docker ask uses deterministic local triage wording and should not require Codex auth.
Successful targeted Docker01 validation lanes automatically finalize structured validation evidence in the validation-runs discovery root. The lane writes `validation-status.json`, `validation-manifest.json`, `validation-summary.md`, `commands-run.json`, `validation-evidence-check.json`, and `validation-evidence-check.md` for the exact PR/commit; `validation_status.py --latest --pr <PR> --commit <sha>` can discover it immediately with `lane=targeted`, `full_validation=false`, `pass_eligible=true`, and `rerun_required=false` when the targeted run passed. No manual finalizer normalization or duplicate pytest is required. If validation passed but the exact evidence cannot be rediscovered, the lane self-check fails clearly instead of leaving downstream tools to report `needs_validation`; full/fallback behavior remains unchanged, and read-only status/merge-readiness/V2 readiness tools still never execute validation or QA. Completed guarded lane logs that use the standard `sfai-pr<PR>-<short>-validation-<timestamp>.log` name are also treated as bounded read-only evidence by `validation_status.py --latest` so a completed full lane can converge without manual evidence normalization. Exact legacy Docker01 validation logs are pass-eligible only when trusted terminal markers are present (for example ruff and compileall passed plus full pytest 100%/exit 0 for full lanes); ambiguous, truncated, failed, setup-failure, or interrupted logs remain non-pass-eligible. Read-only status/readiness tools never run validation, pytest, QA, deploy, cleanup, or restart.

Nested Docker01 convergence QA bundle directories such as `/tmp/sfai-pr<PR>-<short>-convergence-<timestamp>/operator-qa/` are valid exact PR/commit QA evidence sources for PR-lane status, merge-readiness, and V2 readiness; stale PR/commit bundles are ignored.

`shellforgeai model doctor --json` is part of Docker01 live QA and emits strict read-only model readiness JSON; unavailable or unknown model auth is reported structurally instead of as a CLI option failure.

### Model doctor auth readiness

`shellforgeai model doctor` and `shellforgeai model doctor --json` are local,
read-only diagnostics. By default they inspect the configured Codex binary,
version, and whether local auth material appears present; they do not call the
model, perform a network probe, write credentials, or mutate the host. The
default no-probe state reports `live_probe_requested=false`,
`live_probe_performed=false`, and `auth_readiness=not_verified` with
`auth_reason=auth_cache_present_live_probe_not_run`, meaning live readiness was
not requested or performed.

Operators can explicitly request one bounded auth/readiness check with
`shellforgeai model doctor --live-probe --json` or human output with
`shellforgeai model doctor --live-probe`. The probe uses a fixed internal
readiness ping through the configured model client, does not accept operator
prompt text, does not execute tools, and performs no mutation. Tests use fake
clients only; no real model or network calls are required in tests.

A bounded, pasteable receipt can be written with
`shellforgeai model doctor --live-probe --receipt-out /tmp/sfai-model-probe`.

Operators can validate an existing live-probe receipt without a new probe or
model call with
`shellforgeai model doctor --validate-receipt /tmp/sfai-model-probe --json`.
Add `--validation-out /tmp/sfai-model-probe-validation` to write validator
artifacts (`model-doctor-receipt-validation.json`,
`model-doctor-receipt-validation-summary.md`, `manifest.json`, and
`checksums.json`). The validator checks required files, JSON parse, manifest,
SHA256/size metadata, bounded summary Markdown, known secret markers, probe
metadata, and read-only/no-mutation safety posture. It does not run a live
probe, call a model/Codex/network, invoke Docker/Compose, clean up, delete,
restart, remediate, roll back, or recover; SeedOfEvil remains final merge owner.
The directory contains `model-doctor-live-probe.json`,
`model-doctor-live-probe-summary.md`, `manifest.json`, and `checksums.json`
with SHA256, size, and read-only/no-mutation safety metadata. Receipt files
omit secrets, tokens, auth headers, and raw credential material. SeedOfEvil remains the final merge owner.

For exact PR/commit lane runs, a later successful disposable validation fallback supersedes earlier host setup_failure evidence in `validation_status.py --latest`; the setup failure remains in warnings/process notes, while failed or interrupted evidence without a later exact pass stays non-pass-eligible.

### Safe ask command suggestion registry

Changes to model-backed ask command suggestions or `src/shellforgeai/core/safe_commands.py` should run the PR223 registry and ask integration tests plus the PR222 Docker grounding regression. Changes to `ask --explain-evidence` or Docker ask explainability should also run `pytest -q tests/test_pr224_ask_evidence_explainability.py`. The registry is read-only and suggestion-only: it validates real supported ShellForgeAI commands, filters unknown `shellforgeai ...` surfaces, filters Docker cleanup/prune/image-removal/restart/Compose mutation, and rejects shell-like pipes/redirects/passthrough. It must not execute commands, run validation/QA from ask, mutate Docker/Compose, restart containers, delete files, or invoke remediation/rollback/recovery.

### Model Doctor receipt history and compare

Existing Model Doctor live-probe receipts can be inspected without a new probe or model call:

```bash
shellforgeai model receipt history --root /tmp --json
shellforgeai model receipt compare /tmp/old-receipt /tmp/new-receipt --json
```

History scans only a bounded root for known Model Doctor receipt-shaped directories, validates each candidate with the same required-file, JSON, manifest, checksum, secret-marker, and safety checks used by receipt validation, and reports valid, invalid, and ignored candidates. Compare validates both receipt directories before reporting status, auth-readiness, latency, timeout, provider, and model drift. These commands are read-only: they do not run a live probe, call a model, call network/Codex, clean/prune/delete, repair/move artifacts, mutate Docker/Compose, restart containers, remediate, roll back, or recover. Default `shellforgeai model doctor` still performs no model call; explicit `--live-probe` remains opt-in and bounded. SeedOfEvil remains final merge owner.

## Docker01 artifact archive bundle validation checks

| Lane | Command | Purpose | Mutates sources? |
| --- | --- | --- | --- |
| Archive bundle validation | `python3 scripts/docker01_artifact_archive_plan.py --validate-archive-bundle /tmp/sfai-pr237-artifact-archive-bundle --json` | Validates PR236 archive receipt, archive manifest, archive checksums, payload files, source-preservation metadata, and validator safety flags. | No |
| Bundle validation + evidence chain | `python3 scripts/docker01_artifact_archive_plan.py --validate-archive-bundle /tmp/sfai-pr237-artifact-archive-bundle --plan-dir /tmp/sfai-pr237-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr237-artifact-archive-dry-run --json` | Also cross-checks plan id, candidate counts/classes/bytes, source paths, payload coverage, and confirmation phrase consistency against the original plan and dry-run receipt. | No |
| Bundle validation dir | `python3 scripts/docker01_artifact_archive_plan.py --validate-archive-bundle /tmp/sfai-pr237-artifact-archive-bundle --out /tmp/sfai-pr237-artifact-archive-bundle-validation --json` | Writes validator JSON, summary, manifest, and checksums only. | No, except writing the validation directory |

Archive bundle validation is read-only. The archive receipt may record that PR236 created a copy-only bundle, but the PR237 validator reports `archive_created=false`, `source_copied=false`, and `mutation_performed=false` for itself. It does not authorize cleanup/deletion; source deletion/move remains a separate future lane requiring a separate PR and confirmation. No cleanup/prune/delete/restart/remediation/rollback/recovery, Docker/Compose mutation, `shell=True`, network/model/Codex/GitHub/cloud action, or package install is performed. SeedOfEvil remains final merge owner.
