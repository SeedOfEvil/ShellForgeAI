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
| `src/shellforgeai/core/ask_routing.py` | targeted_runtime | `test_pr105_*`, `test_pr106_*`, `test_pr42_ask_routing_hardening`, `test_pr131_*`, `test_pr134_*`, `test_pr135_*`, `test_pr156_*` |
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
