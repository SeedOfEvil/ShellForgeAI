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
| `src/shellforgeai/platform_detection.py` | targeted_runtime | `test_pr259_platform_detection` + command-surface/mutation-refusal targeted checks |
| `src/shellforgeai/windows_doctor.py` | targeted_runtime | `test_pr261_windows_read_only_doctor` + command-surface/mutation-refusal targeted checks |
| `src/shellforgeai/windows_status.py` | targeted_runtime | `test_pr262_windows_read_only_status`, `test_pr261_windows_read_only_doctor`, `test_pr259_platform_detection` + command-surface/mutation-refusal targeted checks |
| `src/shellforgeai/windows_services.py` | targeted_runtime | `test_pr267_windows_read_only_services`, `test_pr264_windows_read_only_evidence`, `test_pr262_windows_read_only_status`, `test_pr261_windows_read_only_doctor`, `test_pr259_platform_detection` + command-surface/mutation-refusal targeted checks |
| `src/shellforgeai/windows_disks.py` | targeted_runtime | `test_pr270_windows_read_only_disks`, `test_pr262_windows_read_only_status`, `test_pr261_windows_read_only_doctor`, `test_pr259_platform_detection` + command-surface/mutation-refusal targeted checks |
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
| `scripts/windows_smoke_packet.py` | targeted_runtime | `test_pr266_windows_smoke_packet`, `test_pr265_windows_evidence_bundle_acceptance`, `test_pr264_windows_read_only_evidence`, `test_pr263_windows_smoke_acceptance`, `test_pr262_windows_read_only_status`, `test_pr261_windows_read_only_doctor`, `test_pr259_platform_detection` + command-surface/mutation-refusal targeted checks |
| `scripts/windows_smoke_acceptance.py` | targeted_runtime | `test_pr265_windows_evidence_bundle_acceptance`, `test_pr263_windows_smoke_acceptance`, `test_pr264_windows_read_only_evidence`, `test_pr262_windows_read_only_status`, `test_pr261_windows_read_only_doctor`, `test_pr259_platform_detection` + command-surface/mutation-refusal targeted checks |
| `scripts/windows_interactive_acceptance.py` | targeted_runtime | `test_pr280_windows_interactive_acceptance`, `test_pr279_windows_interactive_platform_aware_performance`, `test_pr278_collectors_json_null_parsing` + command-surface/mutation-refusal targeted checks |
| `scripts/**` (other) | **full** | + `python scripts/run_full_pytest.py` |
| `tests/conftest.py` | **full** | shared harness → `python scripts/run_full_pytest.py` |
| `tests/**` | fast | the changed test files are run directly |
| `src/**/*.py` (unmatched) | targeted_runtime | PR-specific tests + **warning** if none resolve |
| anything else (unmatched) | **full** | safe default |

### Windows local processes preview

`shellforgeai windows processes [--json] [--limit N]` is a standalone local Windows read-only process preview. It is bounded (default 50, maximum 200) and collects only PID, parent PID, process image basename/name, and thread count. It does not execute PowerShell, use WinRM/remoting, terminate/control/suspend processes, read command lines, read environments, inspect memory, handles, modules, owners/tokens, map network connections, write files, call a model, or contact the network. On Linux/Docker and other unsupported hosts it returns structured unsupported output and points to `shellforgeai platform doctor --json` without probing local Linux/Docker processes. Since PR275, saved `windows-processes.json` artifacts are validated by `scripts/windows_smoke_acceptance.py` and reported by `scripts/windows_smoke_packet.py` via `--processes-json` (saved-artifact validation only: no product command execution, no new process collection, no PowerShell, no WinRM/remoting, no mutation). Since PR276, `shellforgeai windows evidence` embeds the same read-only PR274 processes payload as an explicit opt-in bounded component via `--include-processes [--processes-limit N]` (default 25, range 1-200, valid only with `--include-processes`); default evidence remains doctor/status-only and services/disks behavior remains unchanged.

### Windows smoke saved-JSON acceptance

`scripts/windows_smoke_acceptance.py` validates saved JSON artifacts from `shellforgeai windows evidence --json`, `shellforgeai windows status --json`, and optionally `shellforgeai windows doctor --json`; PR265 adds evidence-bundle validator coverage without adding collection. It is a local QA helper rather than a ShellForgeAI product command: it reads saved local files only, accepts UTF-8, UTF-8 with BOM, and Windows PowerShell 5.1 default UTF-16LE with BOM artifacts, uses the Python standard library, does not import ShellForgeAI runtime command modules, does not invoke subprocesses, does not contact Windows hosts, and does not use PowerShell, WinRM/PSRemoting, QGA, Proxmox, network calls, secrets, or mutation. The targeted/default lane is appropriate when only this helper, its PR-specific tests, and narrow Windows harness documentation change. Windows VM smoke is optional for PR265 because the PR validates saved artifacts, but running it against PR264/PR265 saved artifacts is useful. `scripts/windows_smoke_packet.py` is the PR266 saved evidence packet helper: it requires saved evidence/status/doctor JSON, reuses the acceptance validator, computes SHA256 and byte sizes, and emits deterministic JSON/Markdown without product command execution or new collection. Windows VM smoke is optional for PR266 because it validates saved artifacts, but running the helper against saved PR264/PR265-style artifacts is useful. PR268 extends both helpers with optional `--services-json` support for PR267 `windows_services` artifacts: the validator checks the services artifact schema, summary counts, truncation-limit consistency, and services safety flags, and the packet helper reports the services artifact hash/size/mode/status and service count summary. PR268 coverage is `tests/test_pr268_windows_services_artifact_validation.py` plus the existing PR263/PR264/PR265/PR266/PR267 Windows test suites. Windows VM smoke is optional for PR268 because it validates saved artifacts, but running the helpers against PR267 saved artifacts is useful.

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

Manual fallback containers must preserve that parity baseline before their results are trusted: `python3`, `pytest`, `procps`/`ps`, `git`, and `rsync`. Missing `ps` is a known validation-environment false-failure mode for `tests/test_investigation_tools.py::test_process_snapshot_shape`; fix the container baseline and rerun that narrow test before any single, final full pytest run. Do not duplicate full pytest to chase a missing-tool setup failure, and do not convert the fallback snippet into production Docker/Compose mutation, cleanup, prune, restart, remediation, rollback, or recovery.

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

## Docker01 artifact archive eligibility review checks

| Lane | Command | Purpose | Mutates sources? |
| --- | --- | --- | --- |
| Archive eligibility review | `python3 scripts/docker01_artifact_archive_plan.py --archive-eligibility-review /tmp/sfai-pr238-artifact-archive-bundle --plan-dir /tmp/sfai-pr238-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr238-artifact-archive-dry-run --json` | Validates the archive bundle, source preservation, plan, dry-run receipt, payload checksums, and read-only source recheck evidence before classifying candidates for future human source-action review only. | No |
| Archive eligibility review dir | `python3 scripts/docker01_artifact_archive_plan.py --archive-eligibility-review /tmp/sfai-pr238-artifact-archive-bundle --plan-dir /tmp/sfai-pr238-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr238-artifact-archive-dry-run --out /tmp/sfai-pr238-archive-eligibility-review --json` | Writes eligibility report JSON, summary, candidate review, future checklist, safety notes, manifest, and checksums only. | No, except writing the report directory |

Archive eligibility review is read-only reporting. `eligible_for_review` means human-reviewable in a future separate PR/lane, not executable source action. The helper does not create archives, copy/move/delete/modify source artifacts, authorize cleanup, run cleanup/prune/delete/restart/remediation/rollback/recovery, mutate Docker/Compose, invoke validation/pytest/QA, use natural-language execution or `shell=True`, or perform model/Codex/network/GitHub/package/cloud actions. Future source action remains separate, confirmation-gated, and review-owned by SeedOfEvil.

## Docker01 archive-backed source-action dry-run checks

| Lane | Command | Purpose | Mutates sources? |
| --- | --- | --- | --- |
| Source-action dry run | `python3 scripts/docker01_artifact_archive_plan.py --archive-source-action-dry-run /tmp/sfai-pr239-artifact-archive-bundle --plan-dir /tmp/sfai-pr239-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr239-artifact-archive-dry-run --archive-eligibility-review /tmp/sfai-pr239-artifact-eligibility-review --plan-id sha256:<plan-id> --json` | Validates archive bundle, plan, dry-run receipt, archive eligibility review, exact plan id, candidates, payload checksums, source preservation, and read-only source recheck evidence before producing a non-executable source-action review manifest. | No |
| Source-action dry-run dir | `python3 scripts/docker01_artifact_archive_plan.py --archive-source-action-dry-run /tmp/sfai-pr239-artifact-archive-bundle --plan-dir /tmp/sfai-pr239-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr239-artifact-archive-dry-run --archive-eligibility-review /tmp/sfai-pr239-artifact-eligibility-review --plan-id sha256:<plan-id> --out /tmp/sfai-pr239-source-action-dry-run --json` | Writes source-action dry-run JSON, summary, candidate manifest, future checklist, safety notes, manifest, and checksums only. | No, except writing the report directory |


| Source-action dry-run validation | `python3 scripts/docker01_artifact_archive_plan.py --validate-archive-source-action-dry-run /tmp/sfai-pr240-source-action-dry-run --archive-bundle /tmp/sfai-pr240-artifact-archive-bundle --plan-dir /tmp/sfai-pr240-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr240-artifact-archive-dry-run --archive-eligibility-review /tmp/sfai-pr240-artifact-eligibility-review --json` | Validates the written source-action dry-run packet, manifest, checksums, safety contract, read-only source rechecks, and optional evidence chain. `passed` is human-reviewable only and does not authorize source action. | No |

The source-action dry run is read-only reporting. `ready_for_source_action_review` means human-reviewable in a future separate PR/lane, not executable cleanup or source action. The helper does not create archives, copy/move/delete/modify sources, run cleanup/prune/delete/restart/remediation/rollback/recovery, mutate Docker/Compose, invoke validation/pytest/QA, use natural-language execution or `shell=True`, or perform model/Codex/network/GitHub/package/cloud actions. SeedOfEvil remains final merge owner.


### Docker01 archive source-action human review packet

The archive helper can now create a read-only human review packet from the PR239 source-action dry run, PR240 source-action validation, archive bundle, plan, dry-run receipt, and archive eligibility review evidence chain:

```bash
python3 scripts/docker01_artifact_archive_plan.py --archive-source-action-review-packet /tmp/sfai-pr241-source-action-dry-run --source-action-validation /tmp/sfai-pr241-source-action-validation --archive-bundle /tmp/sfai-pr241-artifact-archive-bundle --plan-dir /tmp/sfai-pr241-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr241-artifact-archive-dry-run --archive-eligibility-review /tmp/sfai-pr241-archive-eligibility-review --plan-id sha256:<plan-id> --json
python3 scripts/docker01_artifact_archive_plan.py --archive-source-action-review-packet /tmp/sfai-pr241-source-action-dry-run --source-action-validation /tmp/sfai-pr241-source-action-validation --archive-bundle /tmp/sfai-pr241-artifact-archive-bundle --plan-dir /tmp/sfai-pr241-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr241-artifact-archive-dry-run --archive-eligibility-review /tmp/sfai-pr241-archive-eligibility-review --plan-id sha256:<plan-id> --out /tmp/sfai-pr241-source-action-review-packet --json
```

The packet cross-checks exact plan id, candidate manifests, archive payload checksums, source-preservation metadata, eligibility status, dry-run status, and validation status. `ready_for_human_review` means only that a human has a complete pasteable review packet; it is not approval, not execution, and not authorization. `source_action_available=false` remains explicit. With `--out`, it writes `archive-source-action-review-packet.json`, `archive-source-action-human-review.md`, `candidate-review-summary.json`, `operator-review-checklist.md`, `future-source-action-signoff-template.md`, `safety-notes.md`, `manifest.json`, and `checksums.json` only. The review-packet command does not create archives, copy/move/delete/modify sources, run cleanup/prune/delete/restart/remediation/rollback/recovery, mutate Docker/Compose, invoke validation/pytest/QA, use natural-language execution or `shell=True`, call model/Codex/network/GitHub, install packages, or apply cloud changes. Future source action remains a separate PR/lane requiring `CONFIRM_SHELLFORGEAI_SOURCE_ACTION_AFTER_ARCHIVE`; SeedOfEvil remains final merge owner.
### Docker01 archive source-action operator decision receipt

The archive helper can record a read-only operator decision receipt from the source-action human review packet:

```bash
python3 scripts/docker01_artifact_archive_plan.py --archive-source-action-decision-receipt /tmp/sfai-pr242-source-action-review-packet --plan-id sha256:<plan-id> --decision ready_for_future_pr_review --json
python3 scripts/docker01_artifact_archive_plan.py --archive-source-action-decision-receipt /tmp/sfai-pr242-source-action-review-packet --plan-id sha256:<plan-id> --decision defer --out /tmp/sfai-pr242-source-action-decision-receipt --json
```

`--decision` accepts only `ready_for_future_pr_review`, `defer`, `reject`, or `needs_more_evidence`; free-form decisions are rejected. The command validates the review packet structure, manifest, checksums, exact plan id, safety contract, candidate summary, and operator review contract, and can optionally cross-check source-action dry-run, validation, archive bundle, plan, dry-run receipt, and eligibility-review evidence directories. `decision_recorded` means evidence was recorded only: it is not approval, not execution, and does not authorize cleanup or source action. `source_action_available=false` remains explicit, and any future source action remains a separate PR/lane requiring `CONFIRM_SHELLFORGEAI_SOURCE_ACTION_AFTER_ARCHIVE`, exact evidence, source recheck, archive validation, operator review, and SeedOfEvil final merge ownership.

With `--out`, the helper writes report artifacts only: `archive-source-action-decision-receipt.json`, `archive-source-action-decision-receipt-summary.md`, `candidate-decision-summary.json`, `future-source-action-requirements.md`, `safety-notes.md`, `manifest.json`, and `checksums.json`. It does not modify the review packet or optional evidence directories; does not create archives; does not copy/move/delete/modify sources; and does not run cleanup/prune/delete/restart/remediation/rollback/recovery, Docker/Compose mutation, validation, pytest, QA, model/Codex, network, GitHub, package install, or cloud apply/merge/push behavior.

### Docker01 archive source-action readiness gate

The archive helper now provides a final read-only source-action readiness gate for the PR239–PR242 evidence chain. It consumes the operator decision receipt, human review packet, source-action dry run, source-action validation, archive bundle, original plan, dry-run receipt, and archive eligibility review with an exact plan id, then reports whether a future separate source-action PR/lane would be reviewable by SeedOfEvil. `ready_for_future_pr_review` is not approval, not execution, and does not authorize cleanup or source action; `source_action_available=false` remains explicit. With `--out`, it writes only readiness/report artifacts (`archive-source-action-readiness-gate.json`, summary, candidate readiness summary, future PR checklist, non-execution contract, safety notes, manifest, and checksums). The gate does not create archives, copy/move/delete/modify sources, add a source-action command, run cleanup/prune/delete/restart/remediation/rollback/recovery, mutate Docker/Compose, invoke validation/pytest/QA, use natural-language execution or `shell=True`, call model/Codex/network/GitHub, install packages, or apply cloud changes.
### Docker01 archive source-action operator status report

The archive helper can now summarize the completed archive-backed source-action evidence chain with a read-only operator status report:

```bash
python3 scripts/docker01_artifact_archive_plan.py --archive-source-action-status-report /tmp/sfai-pr244-source-action-readiness-gate --json
```

When optional evidence directories are supplied, the report requires an exact `--plan-id` and cross-checks the readiness gate against the decision receipt, review packet, source-action dry run, source-action validation, archive bundle, plan, dry-run receipt, and archive eligibility review. With `--out <status_report_dir>`, it writes status/report artifacts only: `archive-source-action-status-report.json`, `archive-source-action-operator-status.md`, `candidate-status-summary.json`, `operator-next-steps.md`, `non-execution-contract.md`, `safety-notes.md`, `manifest.json`, and `checksums.json`.

`ready_for_operator_review` means the evidence is inspectable by an operator for a future separate PR/lane; it is not approval, not execution, and does not authorize cleanup or source action. The report does not create a source-action command, create archives, copy/move/modify/delete sources, run cleanup/prune/delete/restart/remediation/rollback/recovery, mutate Docker/Compose, invoke validation/pytest/QA from the helper, use natural-language execution or `shell=True`, or perform model/Codex/network/GitHub/package/cloud actions. `source_action_available=false` remains explicit, source delete/move defaults remain false, and SeedOfEvil remains final merge owner.

## Archive/source-action operator runbook docs lane

`docs/ARCHIVE_SOURCE_ACTION_RUNBOOK.md` and its docs/golden tests are Lane A when the script command surface and runtime behavior are unchanged. The runbook documents the existing PR239-PR244 archive/source-action evidence chain, points operators to the current command sequence, and keeps the status chain non-executable. It adds no execution command and must not introduce new source-action, cleanup, delete, move, prune, restart, approval, merge, apply, or execution command flags.

### Docker01 fixture-only source-action rehearsal

ShellForgeAI includes a narrow `--archive-source-action-fixture-rehearsal` helper mode for synthetic fixtures only. It requires `--fixture-root`, an exact `--plan-id`, `--out`, and `--confirm CONFIRM_SHELLFORGEAI_FIXTURE_SOURCE_ACTION_REHEARSAL`; `--restore-before-exit` can restore synthetic fixture sources before the command exits. The fixture root must be a safe absolute `/tmp/sfai-fixture-source-action-*` path, outside the repository and outside `/srv`, `/data`, `/var`, `/etc`, `/home`, `/root`, `/opt`, Docker, Compose, and runtime paths, with no symlinks and no non-fixture content.

The lane may create synthetic fixture files, archive those fixture files, rehearse a reversible fixture-only hold state, and write `fixture-source-action-rehearsal.json`, summary, fixture candidate and archive manifests, rollback proof, safety notes, manifest, and checksums under `--out`. `mutation_performed=true` applies only to these helper-owned fixture files. It is not production cleanup, not production source action, does not target real artifact evidence, and does not copy, move, delete, or modify production sources. Future production source action remains a separate PR/lane with SeedOfEvil as final merge owner.

### Fixture source-action rehearsal audit

ShellForgeAI includes a read-only auditor for fixture-only source-action rehearsal evidence. The auditor inspects an existing PR246-style fixture rehearsal output directory with:

```bash
python3 scripts/docker01_artifact_archive_plan.py \
  --archive-source-action-fixture-audit <fixture_rehearsal_dir> \
  --json
```

The audit validates required evidence files, JSON parsing, manifest/checksum integrity, fixture-only flags, rollback/restore proof, path guards, and the non-execution safety contract. It does not repeat rehearsal, create fixture files, archive files, restore files, or touch production paths. It can write audit artifacts only when `--out <fixture_audit_dir>` is supplied, and it can compare two fixture rehearsal evidence directories with `--compare-to <previous_fixture_rehearsal_dir>`.

A passing fixture audit is evidence quality control only. It is not production readiness, does not enable production source action, and does not enable production cleanup. Future production source action still requires a separate reviewed lane and PR. SeedOfEvil remains final merge owner.

## Docker01 build path diagnostic report

| Area | Command | Expected behavior |
| --- | --- | --- |
| Docker01 build-path evidence | `python3 scripts/docker01_build_path_diagnostic_report.py --dockerfile /srv/compose/shellforgeai/Dockerfile --json` | Emits strict JSON describing Dockerfile recursive ownership/permission lines, known paths, named path stat metadata, tool availability, and safety flags for Docker01's external Dockerfile path. |
| Docker01 report artifacts | `python3 scripts/docker01_build_path_diagnostic_report.py --dockerfile /srv/compose/shellforgeai/Dockerfile --out /tmp/sfai-build-path-diagnostic --json` | Writes report artifacts only into an empty explicit output directory. |

The diagnostic exists for the PR247/PR248 Docker/LXC chown-layer operational context (`chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai`). Docker01 Compose uses the external Dockerfile path `/srv/compose/shellforgeai/Dockerfile`, and the helper supports `--dockerfile` for that path. It is read-only and not remediation: it does not build, run Docker/Compose, chown, chmod, install packages, prune, restart, roll back, recover, or mutate Docker/Compose. It does not fix the chown-layer hang. Any Dockerfile/build remediation belongs in a separate PR. Missing manual-fallback `procps`/`ps` should be resolved in the disposable validation environment and checked narrowly; no duplicate full pytest is required for that baseline-only issue.

## Docker01 build path ownership proposal

| Area | Command | Expected behavior |
| --- | --- | --- |
| Docker01 ownership proposal | `python3 scripts/docker01_build_path_ownership_proposal.py --dockerfile /srv/compose/shellforgeai/Dockerfile --json` | Emits strict JSON for a read-only Docker01 build path ownership proposal, including detected recursive ownership operations, known risky paths, `apply_available=false`, and safety flags. |
| Docker01 proposal artifacts | `python3 scripts/docker01_build_path_ownership_proposal.py --dockerfile /srv/compose/shellforgeai/Dockerfile --diagnostic <diagnostic_report_dir> --out <proposal_report_dir> --json` | Writes proposal/report artifacts only into an empty explicit output directory and can cross-check the PR249 diagnostic report. |

The helper is for the Docker/LXC build-path `chown -R appuser:appuser /data
/home/appuser/.codex /opt/shellforgeai` risk. It is read-only and proposal only:
it does not edit Dockerfile, does not run Docker/Compose/build, does not run
chown/chmod/chgrp, does not install packages, and does not perform cleanup,
prune, restart, remediation, rollback, or recovery. Actual Dockerfile/build
remediation remains a separate PR or operator-reviewed change. No duplicate full
pytest is required for a Docker01 build-path investigation-only change.

## Docker01 build path ownership patch preview

| Area | Command | Expected behavior |
| --- | --- | --- |
| Docker01 ownership patch preview | `python3 scripts/docker01_build_path_patch_preview.py --dockerfile /srv/compose/shellforgeai/Dockerfile --json` | Emits strict JSON for a read-only Docker01 build path ownership patch preview, including detected recursive ownership operations, known risky paths, `apply_available=false`, `dockerfile_modified=false`, `compose_modified=false`, and safety flags. |
| Docker01 patch preview artifacts | `python3 scripts/docker01_build_path_patch_preview.py --dockerfile /srv/compose/shellforgeai/Dockerfile --out <patch_preview_dir> --json` | Writes review-only preview/report artifacts into an empty explicit output directory, including a unified diff, preview Dockerfile text, static verification JSON, manifest, and checksums. |
| Docker01 patch preview from PR250 proposal | `python3 scripts/docker01_build_path_patch_preview.py --proposal <ownership_proposal_dir> --out <patch_preview_dir> --json` | Consumes a PR250 ownership proposal directory when present, cross-checks the Dockerfile path/SHA, and still writes only patch-preview artifacts under the explicit output directory. |

The helper is for the Docker/LXC build-path `chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai` risk. It follows the PR249 diagnostic and PR250 proposal and remains read-only and patch preview only: it does not edit Dockerfile, does not edit Compose, does not run Docker/Compose/build, does not run chown/chmod/chgrp, does not install packages, and does not perform cleanup, prune, restart, remediation, rollback, or recovery. Static verification proves only that the preview text removes broad recursive ownership over the known risky paths and includes targeted ownership plus `COPY --chown` guidance; actual Dockerfile/build remediation remains a separate PR or operator-reviewed change. No duplicate full pytest is required for a Docker01 build-path investigation-only patch preview change.

## Docker01 build path ownership patch rehearsal

| Area | Command | Expected behavior |
| --- | --- | --- |
| Docker01 ownership patch rehearsal | `python3 scripts/docker01_build_path_patch_rehearsal.py --dockerfile /srv/compose/shellforgeai/Dockerfile --patch-preview <patch_preview_dir> --out <patch_rehearsal_dir> --json` | Consumes PR251 preview artifacts, writes copied rehearsal/report artifacts only into an empty explicit output directory, records original Dockerfile SHA256 before/after, and emits strict JSON with `production_dockerfile_modified=false`, `compose_modified=false`, and `docker_build_available=false`. |
| Docker01 standalone preview Dockerfile rehearsal | `python3 scripts/docker01_build_path_patch_rehearsal.py --dockerfile /srv/compose/shellforgeai/Dockerfile --preview-dockerfile <path/to/dockerfile-ownership-preview.Dockerfile> --out <patch_rehearsal_dir> --json` | Treats the supplied preview Dockerfile as the candidate rehearsed artifact and still writes only under `--out`. |

The helper is for artifact-only review of the Docker/LXC build-path `chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai` risk. It follows the PR249 diagnostic, PR250 proposal, and PR251 preview and remains patch rehearsal only: it does not edit Dockerfile, does not edit Compose, does not run Docker/Compose/build, does not run chown/chmod/chgrp, does not install packages, and does not perform cleanup, prune, restart, remediation, rollback, or recovery. Static verification proves only that the rehearsed artifact removes broad recursive ownership over the known risky paths and includes targeted ownership plus `COPY --chown` guidance; actual Dockerfile/build remediation remains a separate PR or operator-reviewed change. No duplicate full pytest is required for a Docker01 build-path investigation-only patch rehearsal change.

## Docker01 ownership candidate/static verifier

| Change area | Default lane | Required focus |
| --- | --- | --- |
| Repository-owned Docker01 ownership candidate artifact, README, and static verifier | Lane B targeted/default | Run the PR-specific candidate verifier tests, PR250/PR251/PR252 build-path verifier regressions, compile checks, ruff, and command-surface/mutation-refusal guardrails. The helper must remain review-only: no production Dockerfile or Compose edits, no Docker/Compose/build, no ownership commands, no package installs, and no remediation/rollback/recovery/cleanup/prune/restart. |
| Docker01 ownership handoff packet helper, tests, and docs | Lane B targeted/default | Run the PR-specific handoff-packet tests, PR253/PR252/PR251 build-path regressions, compile checks, ruff, and command-surface/mutation-refusal guardrails. The helper writes handoff/report artifacts only under explicit `--out`; it must not edit `/srv/compose/shellforgeai/Dockerfile`, edit Compose, run Docker/Compose/build, run ownership commands, install packages, or perform remediation/rollback/recovery/cleanup/prune/restart. Future Dockerfile/build remediation remains a separate PR or operator-reviewed change. |

Future Dockerfile/build remediation is not part of this lane; it must be a separate PR or operator-reviewed change.

| Docker01 external Dockerfile ownership update recipe | `python3 scripts/docker01_external_dockerfile_ownership_update.py --preflight ... --json` | Read-only preflight for exact source/candidate SHA guards and candidate safety. Future confirmed write creates a backup and updates only `/srv/compose/shellforgeai/Dockerfile`; it stops before Docker build, Compose config, recreate, restart, prune, cleanup, remediation, rollback, or recovery. Codex/PR tasks must not run production write mode. |

### Docker01 external Dockerfile ownership update validator

| Surface | Command | Expected result | Mutates runtime? |
| --- | --- | --- | --- |
| Current target status | `python3 scripts/docker01_external_dockerfile_ownership_update_validate.py --target /srv/compose/shellforgeai/Dockerfile --json` | Reports `validated`, `not_updated`, `partial`, or `failed` from static Dockerfile analysis. | No |
| Receipt audit | `python3 scripts/docker01_external_dockerfile_ownership_update_validate.py --receipt <ownership_update_receipt_dir> --target /srv/compose/shellforgeai/Dockerfile --json` | Validates receipt JSON, manifest, checksums, backup metadata, allowed scope, and safety flags. | No |
| Artifact report | `python3 scripts/docker01_external_dockerfile_ownership_update_validate.py --target /srv/compose/shellforgeai/Dockerfile --out <validation_report_dir> --json` | Writes validation/report artifacts only under `--out`. | Report artifacts only |

The validator is read-only and not remediation. It does not execute the guarded
recipe, edit `/srv/compose/shellforgeai/Dockerfile`, edit Compose, run Docker or
Compose, run build/recreate validation, run `chown`/`chmod`/`chgrp`, install
packages, clean up, prune, restart, remediate, roll back, or recover. Docker
build/recreate validation is a separate operator action/change window after an
actual recipe run.

## Windows read-only doctor prototype

`shellforgeai windows doctor --json` is validated from source with mocked Windows metadata and native Linux/Docker unsupported behavior. The PR-specific test file is `tests/test_pr261_windows_read_only_doctor.py` so Docker01 helpers can discover it directly. Validation must confirm strict JSON, concise text output, read-only safety flags, no mutation, no PowerShell execution, no WinRM/PSRemoting, no services/processes/event-log collection, and the unsupported Linux/Docker response pointing to `shellforgeai platform doctor --json`. Windows Server 2025 VM smoke should run only after merge/QA and should verify the JSON contract without manually running PowerShell.


## Windows evidence bundle preview validation

Validate `shellforgeai windows evidence [--json]` with targeted PR264 tests plus existing Windows doctor/status/smoke tests. The command is bundle-only and adds no new collection, PowerShell, WinRM/PSRemoting, or mutation.


## Windows local services read-only preview validation

PR267 adds `shellforgeai windows services [--json]`, a standalone local read-only Windows service state summary preview validated with `tests/test_pr267_windows_read_only_services.py` plus existing Windows doctor/status/evidence/smoke tests and command-surface/mutation-refusal guardrails. On Windows it collects service names, display names, and current states only, through read-only `ctypes` Service Control Manager enumeration (`OpenSCManagerW` enumerate rights, `EnumServicesStatusExW`, `CloseServiceHandle`) with a bounded collection limit. It does not execute PowerShell, does not use WinRM/PSRemoting, does not use subprocess, does not start/stop/restart/control/configure services, does not read service binary paths/accounts/config or the registry, and does not mutate the Windows VM. The services preview is not yet included in `shellforgeai windows evidence`; bundle integration is a later PR after the standalone surface is proven safe. Linux/Docker01 must return structured unsupported output pointing to `shellforgeai platform doctor --json`. Because PR267 adds a new Windows-specific product command, real Windows Server 2025 smoke (`shellforgeai windows services --json` and text mode, plus doctor/status/evidence regression) is required before merge.


## Windows services saved-artifact validation

PR268 extends `scripts/windows_smoke_acceptance.py` and `scripts/windows_smoke_packet.py` with optional `--services-json` support for saved PR267 `windows_services` artifacts. Both helpers read saved local JSON files only (UTF-8, UTF-8 BOM, UTF-16 with BOM, and Windows PowerShell 5.1 UTF-16LE/BOM); they never invoke ShellForgeAI product commands, never contact Windows hosts, and never use PowerShell, WinRM, QGA, Proxmox, subprocess, network calls, model calls, or mutation. Coverage is `tests/test_pr268_windows_services_artifact_validation.py` plus the existing PR261–PR267 Windows suites and command-surface/mutation-refusal guardrails; the targeted/default lane applies when only the two helpers, their tests, and narrow docs change. Windows VM smoke is optional for PR268 because it validates saved artifacts, but running the validator and packet helper against PR267 saved artifacts (for example `windows-services.json` and `windows-services-limit5.json` from `WIN2025-SFAI01`) is useful.


## Windows evidence bundle opt-in services component validation

PR269 adds an explicit, bounded, opt-in services component to `shellforgeai windows evidence` via `--include-services [--services-limit N]`, reusing the existing PR267 read-only services payload builder with a conservative default limit of 25 (validated range 1-500) and no new Windows collection surface. The default bundle stays doctor/status-only and PR264-compatible. Coverage is `tests/test_pr269_windows_evidence_services_component.py` plus the existing PR261–PR268 Windows suites and command-surface/mutation-refusal guardrails: mocked-Windows bundle contracts (default component_count 2; include-services component_count 3 with `mode=windows_services`, `status=ok`, bounded `limit`/`returned_count`/`total_count`/`truncated` fields, and honest `failed_components` surfacing on services failure), clean rejection of invalid limits, concise text summaries without unbounded service listings, and full safety-flag assertions (no PowerShell, no WinRM/remote execution, no service restart/control/config mutation, no registry/execution-policy changes, no shell/arbitrary execution, no network/model calls, no secret/auth-cache reads). `scripts/windows_smoke_acceptance.py` validates embedded services components with the same key safety expectations as standalone `windows-services.json` and rejects bundles with services failures or mutation flags; `scripts/windows_smoke_packet.py` summarizes embedded services and cross-checks embedded vs standalone artifacts when both are provided. Docker01 unsupported smoke must show `shellforgeai windows evidence --json --include-services` returning structured unsupported output with no services collection attempt, and mutation asks must still refuse. Because PR269 changes an existing Windows-specific product command, real Windows Server 2025 embedded-runtime acceptance (default bundle, include-services bundle at default and `--services-limit 5`, standalone services, status/doctor regression, plus validator/packet runs over the saved artifacts) is required before merge.


## Windows local disks read-only preview validation

PR270 adds `shellforgeai windows disks [--json] [--limit N]`, a standalone local read-only Windows disk/root usage preview validated with `tests/test_pr270_windows_read_only_disks.py` plus existing Windows doctor/status/services/evidence/smoke tests and command-surface/mutation-refusal guardrails. On Windows it discovers local drive roots with `os.listdrives` when available (feature-detected; otherwise it falls back safely to the current drive root only) and collects per-root total/used/free bytes via `shutil.disk_usage`, using the Python standard library only, with a bounded deterministic `--limit` (default 32, range 1-64; invalid limits fail cleanly) and sanitized per-root `unavailable` entries instead of tracebacks. It does not scan directories or files, does not read user files, does not read secrets or auth caches, does not execute PowerShell, does not use WinRM/PSRemoting, does not use subprocess, does not collect drive labels, volume serials, BitLocker status, SMART/health status, or file/directory inventory, and does not mutate the Windows VM. Disk evidence is not yet included in `shellforgeai windows evidence`; saved-artifact validator/packet support for disks lands in PR271, and opt-in evidence bundle integration for disks remains a later PR only if PR270 stays stable. Linux/Docker01 must return structured unsupported output pointing to `shellforgeai platform doctor --json`. Because PR270 adds a new Windows-specific product command, real Windows Server 2025 smoke (`shellforgeai windows disks --json`, text mode, and `--limit 1`, plus status/doctor regression) is required before merge.


## Windows disks saved-artifact validation

PR271 extends `scripts/windows_smoke_acceptance.py` and `scripts/windows_smoke_packet.py` with optional `--disks-json` support for saved PR270 `windows_disks` artifacts, with no product command changes and no new Windows evidence collection. The validator checks the disks artifact schema (`schema_version` 1, `mode=windows_disks`, `status=ok`, Windows platform, read-only/no-mutation flags, `windows_v1.available` with the `local_read_only_disks` scope, `stdlib_only` collection method), the bounded output fields (integer `limit` within the accepted 1-64 range, boolean `truncated`, non-negative total/returned/available/unavailable root counts, returned <= total, truncation and availability consistency, disks list bounded by the limit), and the full disks safety-flag set (no PowerShell/WinRM/remote execution, no directory or file scanning, no disk mutation/mount/format flags when present, no registry or execution-policy changes, no cleanup/remediation/rollback/recovery, no shell/arbitrary execution, no secret/auth-cache reads, no model/network calls). Unavailable roots are accepted only when sanitized as safe disk usage failures (for example `disk_usage_failed`); tracebacks or raw exception detail fields fail validation, while sanitized unavailable roots do not fail an ok artifact. The packet helper reports the disks artifact hash/size/mode/status and the safe disk summary (root counts, limit, truncated) in JSON and Markdown. Both helpers read saved local JSON files only (UTF-8, UTF-8 BOM, UTF-16 with BOM, and Windows PowerShell 5.1 UTF-16LE/BOM); they never invoke ShellForgeAI product commands, never contact Windows hosts, and never use PowerShell, WinRM, QGA, Proxmox, subprocess, network calls, model calls, or mutation. Coverage is `tests/test_pr271_windows_disks_artifact_validation.py` plus the existing PR261–PR270 Windows suites and command-surface/mutation-refusal guardrails; the targeted/default lane applies when only the two helpers, their tests, and narrow docs change. Windows VM smoke is optional for PR271 because it validates saved artifacts, but running the validator and packet helper against PR270 saved artifacts (for example `windows-disks.json` from `WIN2025-SFAI01`, which showed 3 roots total with 1 available and 2 sanitized as `disk_usage_failed`) is useful.


## Windows evidence bundle opt-in disks component validation

PR272 adds an explicit, bounded, opt-in disks component to `shellforgeai windows evidence` via `--include-disks [--disks-limit N]`, reusing the existing PR270 read-only disks payload builder with the same safe default limit of 32 (validated range 1-64) and no new Windows collection surface.

## Windows disks safety-flag normalization validation

PR273 normalizes the Windows disks safety schema only: the standalone `shellforgeai windows disks --json` payload and the embedded disks component in `shellforgeai windows evidence --json --include-disks` now both explicitly report `directory_scan_performed=false`, `file_scan_performed=false`, and `disk_mutation_performed=false` in their safety blocks, matching the top-level PR272 evidence safety block (which already carried the three flags when disks are included). This closes the PR272 reviewer note that the embedded PR270 disks payload did not internally carry the newer disk-specific safety keys. It is schema consistency only: no new disk collection is added, no directory or file scan is added, no disk mutation is possible, no PowerShell/WinRM/remoting is used, and default evidence, `--include-disks` opt-in, disks limit, and services behavior are unchanged. `scripts/windows_smoke_acceptance.py` requires the explicit `disk_mutation_performed=false` flag (alongside the existing directory/file scan flags) for PR273+ disks artifacts, standalone and embedded; legacy artifacts missing the key fail strict validation with a clear per-key check name. `scripts/windows_smoke_packet.py` reports the three disk safety flags in the disks artifact summary (`disk_safety` block in JSON plus Markdown lines) and reports failed validation when a disks artifact carries unsafe disk flags. Coverage is `tests/test_pr273_windows_disks_safety_flags.py` plus the existing PR267–PR272 Windows suites and command-surface/mutation-refusal guardrails, including Linux/Docker01 structured-unsupported regression and source safety guards (no subprocess, no PowerShell/WinRM execution behavior, no Docker/Compose execution, no product file writes from `windows disks`/`windows evidence`). Because PR273 changes the safety fields of an existing Windows-specific product payload, real Windows Server 2025 smoke (standalone disks default and `--limit 1`, default evidence, include-disks evidence at default and `--disks-limit 5`, services + disks combination, plus validator/packet runs over the saved artifacts) is required before merge. The default bundle stays doctor/status-only and PR264-compatible, and the existing PR269 services opt-in behavior is unchanged (services and disks can be combined for a component count of 4). Coverage is `tests/test_pr272_windows_evidence_disks_component.py` plus the existing PR261–PR271 Windows suites and command-surface/mutation-refusal guardrails: mocked-Windows bundle contracts (default component_count 2; include-disks component_count 3 with `mode=windows_disks`, `status=ok`, bounded `limit`/`returned_roots`/`total_roots`/`truncated` fields, an explicit top-level `embedded_disks` summary block plus `not_collected_in_pr272` notes, and honest `failed_components` surfacing on disks failure), clean rejection of invalid limits (`0`, above 64, or `--disks-limit` without `--include-disks`), concise text summaries without per-root listings, and full safety-flag assertions (no PowerShell, no WinRM/remote execution, no directory or file scanning, no disk mutation/mount/unmount/format/repair, no registry/execution-policy changes, no cleanup/remediation/rollback/recovery, no shell/arbitrary execution, no network/model calls, no secret/auth-cache reads). `scripts/windows_smoke_acceptance.py` validates embedded disks components with the same key safety expectations as standalone `windows-disks.json`, checks the bounded fields and `embedded_disks` block consistency, rejects bundles with disks failures or mutation/scan flags, and cross-checks embedded vs standalone disks artifacts when both are provided; standalone `--disks-json` support from PR271 remains valid. `scripts/windows_smoke_packet.py` summarizes embedded disks (`embedded_disks` block in JSON plus a Markdown section) and still supports standalone `disks_json`. Docker01 unsupported smoke must show `shellforgeai windows evidence --json --include-disks` returning structured unsupported output with no disks probing attempt, and mutation asks must still refuse. Because PR272 changes an existing Windows-specific product command, real Windows Server 2025 embedded-runtime acceptance (default bundle, include-disks bundle at default and `--disks-limit 5`, standalone disks, status/doctor regression, plus validator/packet runs over the saved artifacts) is required before merge.


## Windows processes saved-artifact validation

PR275 extends `scripts/windows_smoke_acceptance.py` and `scripts/windows_smoke_packet.py` with optional `--processes-json` support for saved PR274 `windows_processes` artifacts, with no product command changes and no new Windows evidence collection. It validates saved artifacts only: it does not run ShellForgeAI product commands, does not collect new process data, does not add processes to the evidence bundle, does not execute PowerShell, does not use WinRM/remoting, and does not mutate the Windows VM. The validator checks the processes artifact schema (`schema_version` 1, `mode=windows_processes`, `status=ok`, Windows platform, read-only/no-mutation flags, `windows_v1.available` with the `local_read_only_processes_preview` scope, the `ctypes_toolhelp32_snapshot` method), the bounded output fields (integer `limit` within the accepted 1-200 range, boolean `truncated`, non-negative `total_count`/`returned_count`, `returned_count <= limit`, `returned_count <= total_count`, truncation consistency, processes list bounded by the limit and matching `returned_count`), the per-item field allowlist (each process item may carry only `pid`, `parent_pid`, `name`, and `thread_count`; command lines, environments, memory, handles, modules, owners/users, network connections, and executable paths fail validation), the `not_collected_in_pr274` notes (`command_line`, `environment`, `memory`, `handles`, `modules`, `owner_user`, `network_connections`), and the full processes safety-flag set (no PowerShell/WinRM/remote execution, no process termination/control/config mutation, no process memory/command-line/environment/handles/modules/owner reads, no service restart, no registry or execution-policy changes, no software installs, no cleanup/remediation/rollback/recovery, no natural-language/shell/arbitrary execution, no secret/auth-cache reads, no model/network calls). The packet helper reports the processes artifact hash/size/mode/status, a `windows.processes` summary (method, total/returned counts, limit, truncated) in JSON, and a concise Markdown "Processes summary" section that notes explicitly that command lines, environments, memory, handles, modules, owners/users, and network connections were not collected; packet validation fails when the processes artifact fails acceptance. Both helpers read saved local JSON files only (UTF-8, UTF-8 BOM, UTF-16 with BOM, and Windows PowerShell 5.1 UTF-16LE/BOM); they never invoke ShellForgeAI product commands, never contact Windows hosts, and never use PowerShell, WinRM, QGA, Proxmox, subprocess, network calls, model calls, or mutation. Evidence-bundle integration for processes is future work. Coverage is `tests/test_pr275_windows_processes_artifact_validation.py` plus the existing PR267–PR274 Windows suites and command-surface/mutation-refusal guardrails; the targeted/default lane applies when only the two helpers, their tests, and narrow docs change. Windows VM smoke is optional for PR275 because it validates saved artifacts, but running the validator and packet helper against a real `windows-processes.json` from `WIN2025-SFAI01` is useful.

## Windows evidence opt-in processes component validation

PR276 adds an explicit, bounded, opt-in processes component to `shellforgeai windows evidence` via `--include-processes [--processes-limit N]`, reusing the existing PR274 read-only processes payload builder with a conservative default limit of 25 (validated range 1-200, matching the standalone processes bounds) and no new Windows collection surface. The default bundle stays doctor/status-only and PR264-compatible (`component_count=2`), and the existing PR269 services and PR272 disks opt-in behaviors are unchanged (services, disks, and processes can be combined for a component count of 5). The embedded processes component reports `mode=windows_processes`, `status=ok`, bounded `limit`/`returned_count`/`total_count`/`truncated` fields, an explicit top-level `embedded_processes` summary block plus `not_collected_in_pr276` notes, and honest `failed_components` surfacing when process enumeration fails inside the reused payload. It does not collect command lines, does not collect environments, does not read process memory, does not inspect handles/modules/owners/users/tokens, does not map network connections, does not terminate/control processes, does not execute PowerShell, does not use WinRM/remoting, and does not perform cleanup, remediation, rollback, or recovery. `--processes-limit` is valid only with `--include-processes`; invalid limits (`0`, above 200, or `--processes-limit` without `--include-processes`) fail cleanly with nonzero exit. `scripts/windows_smoke_acceptance.py` validates embedded processes components with the same key safety expectations as standalone `windows-processes.json` (including the per-item allowlist of `pid`/`parent_pid`/`name`/`thread_count`), checks the bounded fields and `embedded_processes` block consistency, rejects bundles with processes failures or mutation flags, and cross-checks embedded vs standalone processes artifacts (mode/status/method) when both are provided; standalone `--processes-json` support from PR275 remains valid. `scripts/windows_smoke_packet.py` summarizes embedded processes (`embedded_processes` block in JSON plus a Markdown section that notes explicitly that command lines, environments, memory, handles, modules, owners/users, and network connections were not collected) and still supports standalone `processes_json`. Coverage is `tests/test_pr276_windows_evidence_processes_component.py` plus the existing PR261–PR275 Windows suites and command-surface/mutation-refusal guardrails, including Linux/Docker01 structured-unsupported regression (no Linux/Docker process probing for this Windows-only command) and source safety guards (no subprocess, no PowerShell/WinRM execution behavior, no Docker/Compose execution, no product file writes from `windows evidence`). Docker01 unsupported smoke must show `shellforgeai windows evidence --json --include-processes` returning structured unsupported output with no processes probing attempt, and mutation asks must still refuse. Because PR276 changes an existing Windows-specific product command, real Windows Server 2025 embedded-runtime acceptance (default bundle, include-processes bundle at default and `--processes-limit 10`, combined services + disks + processes, standalone processes, status/doctor regression, plus validator/packet runs over the saved artifacts) is required before merge.

## Collector JSON payload parsing validation

PR278 fixes the interactive slow-system diagnostics crash where collector payloads containing JSON `null` (for example `system.cpu_memory` with `mem_percent: null` on Windows) were parsed with `ast.literal_eval` and raised `ValueError: malformed node or string ... Name(id='null')`. Collector payload parsing now tries `json.loads` first (accepting `null`/`true`/`false`, strings, numbers, arrays, and objects), keeps `ast.literal_eval` only as a fallback for legacy `str(dict)` payloads such as `host.info`, and degrades to a safe summary (for example `cpu/memory summary unavailable`) instead of a traceback when neither parser accepts the payload. The fix is parsing-only: no new collectors, no PowerShell/WinRM, no `eval`, no `shell=True`, no mutation, and Linux summary output is unchanged for valid payloads. Coverage is `tests/test_pr278_collectors_json_null_parsing.py` (JSON null/true/false/nested payloads, the Windows-like `system.cpu_memory` payload, Python-literal fallback, garbage-payload degradation, an interactive slow-system route regression with mocked JSON-null collector output, and source safety guards) plus the existing collector, interactive, performance, and command-surface/mutation-refusal suites. Because the crash was found on real Windows, Windows Server 2025 smoke (`sfai.cmd interactive --yes-trust`, then "Hey this system feels a bit slow") should confirm no traceback and a safe read-only summary before merge.

## Windows interactive performance platform-awareness validation

PR279 makes the interactive slow-system/performance diagnosis route platform-aware on Windows. `diagnose_target` detects the platform through the existing `platform_detection` helpers before any collector runs; on Windows the performance/health family (slow/performance/host/health/storage-performance) returns bounded read-only Windows evidence instead of executing Linux-only collectors (`uptime`, `df`, `df -i`, `ip`, `ss`, `ps`, `systemctl`, `/proc` reads, `/etc/resolv.conf` reads). Skipped Linux collectors are recorded as structured `linux_only_collector_skipped` evidence (reason `not_collected_on_windows`) instead of scary failures; missing metrics render explicit `windows_metric_unavailable` markers ("Load average is not available on Windows", "Memory summary unavailable from this collector") instead of `loadavg=None` or fake `0.0GiB/0.0GiB` memory; and the summary points at safe next commands (`shellforgeai windows status --json`, `shellforgeai windows disks --json`, `shellforgeai windows processes --json --limit 10`). The only Windows payloads reused are the existing stdlib-only `windows status` and `windows disks` read-only payloads — no new Windows collection surface, no PowerShell/WinRM, no `eval`, no `shell=True`, no mutation, and no model synthesis requirement (the deterministic Windows summary renders even when the model is unavailable). PR278 JSON-null parsing behavior is preserved and Linux/Docker performance diagnostics are unchanged. Coverage is `tests/test_pr279_windows_interactive_platform_aware_performance.py` (Linux-only collector sentinels proving nothing Linux-oriented runs on the Windows route, structured skip records, unavailable-metric markers, interactive end-to-end slow-system runs with and without model synthesis, Linux-route regression, and source safety guards) plus the existing PR278, collector, interactive, performance, and command-surface/mutation-refusal suites. Windows Server 2025 smoke (`sfai.cmd interactive --yes-trust`, then "Hey this system feels a bit slow") should confirm a clean Windows-aware read-only summary with no Linux collector noise before merge.


## Windows interactive transcript acceptance helper

`scripts/windows_interactive_acceptance.py` validates saved PR279-style Windows interactive performance and mutation-refusal transcripts only. It reads local text files, accepts UTF-8, UTF-8 BOM, UTF-16 with BOM, and Windows PowerShell 5.1 UTF-16LE/BOM transcripts, emits deterministic JSON/Markdown, and does not run ShellForgeAI, PowerShell, WinRM, QGA/Proxmox, subprocesses, network/model calls, or mutation. The helper accepts real PR279 Windows markers such as `Visibility: windows-local-read-only`, read-only evidence counts, and Linux-only collector skip messages. It treats negated execution statements such as `No command was executed.` as safe refusal evidence, while true cleanup/remediation/rollback/recovery/Docker restart/prune execution indicators still fail. The targeted/default lane is appropriate when only this helper, `tests/test_pr280_windows_interactive_acceptance.py`, and narrow docs change.

## Windows smoke packet interactive transcript integration

PR281 extends `scripts/windows_smoke_packet.py` with optional `--slow-transcript` and `--mutation-transcript` inputs for saved PR279/PR280-style Windows interactive transcripts. The packet helper reuses `scripts/windows_interactive_acceptance.py` acceptance checks, requires both transcript arguments together, and reports transcript path, SHA256, byte size, accepted/failed state, an `interactive` JSON summary, and an "Interactive transcript summary" Markdown section. This is packet-helper integration only: it validates saved local files, does not launch ShellForgeAI interactive mode or product commands, does not add collectors or runtime behavior, and does not use PowerShell, WinRM/remoting, QGA/Proxmox, subprocess, network/model calls, secrets/auth-cache reads, cleanup/remediation/rollback/recovery, or mutation. Transcript support is optional; omitting both transcript arguments preserves existing JSON-only artifact packet behavior. Coverage is `tests/test_pr281_windows_smoke_packet_interactive_transcripts.py` plus existing PR280 transcript acceptance, PR266 packet, PR275 processes, PR271 disks, PR268 services, and command-surface/mutation-refusal regression tests. The targeted/default lane applies when only the packet helper, tests, and narrow docs change; Windows VM smoke is optional because PR281 validates saved files only.



## Docker01 ownership-fix readiness packet

PR284 adds `scripts/docker01_ownership_fix_readiness.py`, a standalone read-only Docker01 ownership-fix readiness packet helper. The targeted/default lane applies when only this helper, `tests/test_pr284_docker01_ownership_fix_readiness.py`, and narrow docs change. Validate with `ruff format .`, `ruff check .`, `python -m compileall -q src scripts tests`, `pytest -q tests/test_pr284_docker01_ownership_fix_readiness.py`, `pytest -q tests/test_pr283_docker01_build_health_dockerfile_discovery.py`, `pytest -q tests/test_pr282_docker01_build_health_report.py`, `pytest -q tests -k "command_surface or mutation_refusal"`, and `scripts/v1_validate.sh --quick` when available.

The helper prepares an operator-reviewed fix path for the broad recursive Dockerfile ownership layer only. Operators can run `python scripts/docker01_ownership_fix_readiness.py --dockerfile /srv/compose/shellforgeai/Dockerfile --json`, `python scripts/docker01_ownership_fix_readiness.py --dockerfile /srv/compose/shellforgeai/Dockerfile --markdown`, or pair it with `python scripts/docker01_build_health_report.py --dockerfile /srv/compose/shellforgeai/Dockerfile --out-json docker01-build-health.json` followed by `python scripts/docker01_ownership_fix_readiness.py --dockerfile /srv/compose/shellforgeai/Dockerfile --health-json docker01-build-health.json --out-json docker01-ownership-readiness.json --out-markdown DOCKER01-OWNERSHIP-READINESS.md`. It reads local files only, inspects the active Dockerfile for `chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai`, inspects an existing guarded recipe if present, and statically checks recipe existence, confirmation/apply gates, backup/receipt indicators, and absence of obvious unsafe commands.

It does not apply the fix, execute any recipe, modify `/srv/compose/shellforgeai/Dockerfile`, run Docker build, Docker Compose, Docker prune, cleanup, remediation, rollback, process kill, service restart, Proxmox/QGA, PowerShell/WinRM, source-action execution, model/network calls, GitHub approval/merge, or cloud apply/merge/push. Recipe execution remains a separate explicit operator action after SeedOfEvil approval.

## Docker01 build lane health report

PR282 adds `scripts/docker01_build_health_report.py`, a standalone read-only Docker01 build-lane readiness report. PR283 improves its Dockerfile discovery so it can be run from the repo root, `/srv/compose/shellforgeai`, or an arbitrary current working directory. The targeted/default lane applies when only the helper, `tests/test_pr282_docker01_build_health_report.py`, `tests/test_pr283_docker01_build_health_dockerfile_discovery.py`, and narrow docs change. Validate with `ruff format .`, `ruff check .`, `python -m compileall -q src scripts tests`, `pytest -q tests/test_pr283_docker01_build_health_dockerfile_discovery.py`, `pytest -q tests/test_pr282_docker01_build_health_report.py`, `pytest -q tests -k "command_surface or mutation_refusal"`, and `scripts/v1_validate.sh --quick` when available.

The helper exists because PR281 Docker01 deploy validation was blocked by host I/O/BuildKit behavior before product validation. It reports root/Docker/workspace disk usage, build-related processes, possible `D`-state I/O stalls, Docker CLI read-only command availability, and the known broad recursive ownership/chown Dockerfile pattern in the selected Dockerfile. Dockerfile discovery checks a small explicit allowlist only: user-provided `--dockerfile PATH`, current working directory `Dockerfile`, `/srv/compose/shellforgeai/Dockerfile`, repository-root `Dockerfile`, `/srv/data/shellforgeai/src/Dockerfile`, and the legacy default path when distinct. Operators can run `python scripts/docker01_build_health_report.py --json`, `python scripts/docker01_build_health_report.py --dockerfile /srv/compose/shellforgeai/Dockerfile --json`, or `python scripts/docker01_build_health_report.py --dockerfile /srv/compose/shellforgeai/Dockerfile --markdown`. The report includes candidates checked, selected path/source, discovery status, and read-only broad recursive ownership/chown risk detection. It exits 0 after successful report generation even when readiness is `attention`, `blocked`, or `unknown`, so operators can classify infrastructure blockers separately from product/test failures. It must not run Docker builds, Compose mutation, prune/remove commands, process kills, service restarts, filesystem cleanup/delete/repair, package installs, pytest, remediation, rollback, recovery, Proxmox/QGA, PowerShell/WinRM, model/network/secret/auth-cache behavior, GitHub approval/merge, or cloud apply/merge/push. Cleanup/snapshot retirement/BuildKit repair remains outside this report and approval-gated.

## Windows interactive deterministic status routing validation

PR285 adds deterministic allowlisted interactive routing for explicit Windows local read-only requests such as `show me the windows status`, `windows status`, `windows doctor`, `windows evidence`, and `windows processes limit 10`. The route runs before model fallback and renders safe command guidance for `sfai.cmd windows status --json`, `sfai.cmd windows doctor --json`, `sfai.cmd windows evidence --json`, and `sfai.cmd windows processes --json --limit 10`; it does not execute shell commands, subprocesses, PowerShell, WinRM/PSRemoting, Docker/Compose, cleanup, remediation, rollback, recovery, or mutation. `/pending` now records the active `windows-local-read-only` context for these requests and prioritizes Windows safe-next commands instead of stale Docker/performance remediation-oriented suggestions. Linux/non-Windows hosts return structured unsupported Windows-only guidance without probing Windows. Coverage is `tests/test_pr285_windows_interactive_status_routing.py` plus the existing Windows interactive performance/transcript, interactive/pending/windows, command-surface, and mutation-refusal suites.

## Windows interactive assessment leakage guard validation

PR286 prevents Windows interactive performance diagnoses from rendering provider text that is only a project/system-prompt acknowledgement, such as AGENTS.md or project-instruction invariant restatements. When assessment text is non-diagnostic or contaminated with project-instruction acknowledgement phrases, ShellForgeAI uses the deterministic evidence-grounded Windows fallback instead, preserving the PR279 platform-aware read-only evidence path. The guard adds no commands, collectors, model providers, PowerShell, WinRM/PSRemoting, shell execution, subprocess execution, Docker/Compose mutation, cleanup, remediation, rollback, recovery, or other mutation behavior. Windows acceptance should run `sfai.cmd interactive --yes-trust` and cover the operator-parity prompts for app latency, CPU/memory/disk/process strongest signal, Windows next checks, current-host handoff, and cleanup/restart refusal. Expected output is Windows-native, evidence-grounded, and read-only; it includes Windows safe-next commands, states load/memory/process limitations when unavailable, identifies the strongest available signal or says no single strong signal was found, and excludes AGENTS.md, `treat this repo as ShellForgeAI`, `ShellForgeAI project constraints`, `preserving the existing CLI surface`, Docker/container primary framing, and project/system-prompt acknowledgement language. Transcript-inclusive validation is negation-aware, so lines such as `No cleanup was performed.` and `No command was executed.` count as safe refusal evidence rather than cleanup execution.

### PR285 Windows interactive parity prompts

The PR285 Windows interactive lane also handles generic parity prompts in a Windows local read-only context: `Show me the system status` renders deterministic Windows status guidance, `What should I check first?` uses the active Windows context without a model call and prioritizes Windows status/doctor/evidence/process/disks safe-next commands, and `Clean up and restart services to fix it` refuses as mutating/service-impacting while offering Windows read-only alternatives. `/pending` remains Windows-primary after these routes and must not surface Docker triage or remediation commands as the active safe-next set. This adds no shell, subprocess, PowerShell, WinRM, new collectors, model/provider/auth changes, cleanup, remediation, rollback, recovery, service control, or mutation behavior.

### PR285 Windows human SSH assessment acknowledgement fallback

The Windows interactive assessment guard also rejects the human SSH repro class where the provider says it will operate within ShellForgeAI repo/workspace conventions or preserve safety/CLI/routing/UX invariants instead of diagnosing collected Windows evidence. Mojibake, Unicode, and ASCII apostrophe variants are normalized before matching. In Windows local read-only diagnose/performance output, a short repo-conventions/invariants acknowledgement or a response without Windows evidence-bearing terms falls back to the deterministic Windows operator summary while the raw `model-response.md` artifact remains available for audit. This adds no new collectors, model/provider/auth changes, shell/subprocess execution, PowerShell, WinRM, cleanup, remediation, rollback, recovery, or mutation behavior.
