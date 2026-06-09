# Validation Lanes

> Faster validation with explicit confidence, not weaker safety.

ShellForgeAI is a CLI-first Linux/Docker operator knife. It is moving toward
governed execution through named, narrow, auditable recipes. Validation must
stay safety-first, but **full `pytest` should not be the default confidence
blanket for every small docs / routing / wording PR.**

This document defines three validation lanes and the policy for choosing one.
The machine-readable impact map lives in
[`../scripts/validation_matrix.json`](../scripts/validation_matrix.json); the
human-readable table is in [`VALIDATION_MATRIX.md`](VALIDATION_MATRIX.md). The
lane optimizer that turns a changed-file list into a recommendation is
[`../scripts/validate_pr.py`](../scripts/validate_pr.py).

The optimizer is **planning/dry-run only**. It never mutates anything, never
runs Docker/Compose, and never runs remediation, rollback, cleanup, or restart.
It only runs validation commands when you explicitly pass `--execute`, and even
then only the recommended `ruff` / `compileall` / `pytest` commands.

---

## TL;DR

```bash
# What lane does this change need, and why?
python scripts/validate_pr.py --changed-files docs/cli.md
python scripts/validate_pr.py --changed-files src/shellforgeai/core/ask_routing.py --pr 156
python scripts/validate_pr.py --base main --head HEAD --json
```

- **Lane A (fast)** is the default for docs / wording / tests-only changes.
- **Lane B (targeted runtime)** is the default for read-only routing / UX /
  artifact / output-shape changes.
- **Lane C (full)** is **exceptional** — reserved for execution, safety,
  packaging, and validation-infrastructure boundaries (and anything unknown or
  suspicious).

Targeted validation is the default. Full validation is the exception. Safety
gates are never weakened to go faster.

---


## Mainline full baseline lane

`mainline_full` is a separate manual/scheduled baseline lane for validating the
current checkout or current deployed source state. It complements Lane A/B/C PR
validation; it is not a replacement for PR-specific impact analysis, and it is
not a hidden requirement that every PR run the full suite.

Run it with:

```bash
python scripts/run_mainline_validation.py --dry-run
python scripts/run_mainline_validation.py
python scripts/run_mainline_validation.py --output-dir /srv/data/shellforgeai/validation-runs --baseline-name main
```

The default mainline baseline is explicit full validation: `ruff check .`,
`python -m compileall -q src tests`, V1 quick validation when available, the
full pytest runner, and duration tracking on the full pytest log. Outputs are a
mainline validation manifest, human summary, logs, duration report, and duration
history under the selected output directory. `--no-full-pytest` exists only for
local quick checks and is recorded as `full_pytest=skipped_by_operator`; it is
not recommended for the official scheduled baseline.

The lane is validation/evidence only. It never auto-merges, deploys, builds
images, edits Compose files, calls Docker/Compose, restarts containers, prunes,
cleans up, remediates, rolls back, or expands ShellForgeAI runtime execution
behavior.

## Lane A — fast default

**Use for**

- docs-only changes
- README / OPS / roadmap edits
- CLI help text only
- wording-only changes
- tests-only additions for docs/contract

**Commands**

```bash
ruff check .
python -m compileall -q src tests
pytest -q <PR-specific tests>
pytest -q <docs/contract tests if applicable>
```

No full `pytest` by default. Estimated runtime class: **short**.

---

## Lane B — targeted runtime

**Use for**

- ask routing
- intent parsing
- command dispatch
- interactive UX
- JSON output shape
- artifact read / validate / export behavior
- doctor output
- status / triage / propose / apply-preview / verify / handoff wording or routing
- recipe registry or preflight **read-only** logic

**Commands**

```bash
ruff check .
python -m compileall -q src tests
pytest -q <PR-specific tests>
pytest -q <related regression group>
# optional focused live smoke on Docker01 if deployed
```

No full `pytest` by default **unless**:

- targeted tests fail
- the change touched a safety boundary
- the change touched an execution boundary
- unexpected behavior appears in live smoke
- a reviewer explicitly requests full validation

Estimated runtime class: **medium**.

---

## Manifest finalization/import workflow

Docker01 validation reports may be finalized from already-completed evidence when rerunning full pytest would only duplicate an expensive validation run. Use the offline finalizer to attach completed logs to an existing `mode=docker01_pr_validation_manifest` JSON artifact:

```bash
python scripts/finalize_validation_manifest.py /tmp/sfai-pr162-manifest.json \
  --validation-log /tmp/sfai-pr162-validation.log \
  --qa-log /tmp/sfai-pr162-qa.log \
  --status passed \
  --verdict pass
```

By default the helper preserves the original manifest and writes `<manifest>.finalized.json`; `--in-place` is required to overwrite the source manifest. It imports conservative known pass/fail signals, distinguishes zero-failure summaries such as `failed: 0` or `0 failed` from real failures, records imported evidence metadata, de-duplicates repeated non-blocker notes while preserving order, and can render a finalized human summary with `--summary-output`. It does not run tests, call Docker/Compose, deploy, restart, clean up, remediate, roll back, or execute arbitrary commands. Missing, ambiguous, and genuinely conflicting logs are captured as evidence-import warnings instead of silently becoming a pass.

## Lane C — full validation

**Use for**

- cleanup execution
- remediation execution
- rollback execution
- Docker / Compose behavior
- container restart behavior
- recipe execution
- apply / mission execution
- safety gates / refusal core rewrites
- broad command router rewrites
- `pyproject` / dependency / `Dockerfile` changes
- packaging / import changes
- test harness or validation-infrastructure changes that affect broad confidence
- failing or suspicious targeted results
- high-risk unknown changes

**Commands**

```bash
ruff check .
python -m compileall -q src tests
pytest -q <PR-specific tests>
pytest -q <related regression group>
python scripts/run_full_pytest.py
```

Estimated runtime class: **long**.

Full `pytest` belongs in Lane C, in scheduled / nightly / mainline runs, or in
explicit reviewer-requested validation. Lane C uses the bounded full-validation
runner:

```bash
python scripts/run_full_pytest.py
```

Before expensive Docker01/full validation, run the read-only validation
environment doctor when the container or dev environment is new, stale, or
suspect:

```bash
python scripts/check_validation_env.py --profile docker01
```

The doctor separates required checks from optional/recommended checks. Required
checks cover the active Python interpreter, `shellforgeai` importability,
`pytest`, `ruff`, `compileall`, core OS tools (`git`, `rsync`, `ps`/procps,
`timeout`), and validation helper presence. Optional checks include
`pytest-xdist`, `/usr/bin/python3`, package metadata in source/editable contexts,
and Docker/Docker Compose CLI presence for Docker01. It is read-only: it does
not install packages, delete caches, chmod/chown, contact the Docker daemon, or
run Docker/Compose mutation.

Use `--json` for strict machine-readable preflight evidence and `--strict` when
Docker01 validation should fail fast on missing recommended acceleration such as
`pytest-xdist`. Without `--strict`, missing xdist is a warning and the serial
full-pytest fallback remains valid, just slower.

The runner detects `pytest-xdist` and, when available, runs
`python -m pytest -q -n auto --dist loadscope --durations=25`. If xdist is not
installed, it prints a clear fallback warning and runs serial
`python -m pytest -q --durations=25`. The serial fallback is acceptable; it must
be reported in QA notes so reviewers know why the run was slower. Execution mode
streams pytest output directly, prints the exact command before pytest starts,
and reports elapsed time when pytest exits. Dry-run JSON remains strict metadata
only for planning automation. Slow-test reporting is always enabled by default
through `--durations=25`, keeping the slow tail visible without skipping tests.

Full-validation logs can be converted into trendable slow-test evidence with
`python scripts/track_pytest_durations.py --log <pytest-log> --json`. The helper
parses the `slowest 25 durations` section, emits structured records, can append
to an explicit local history only with `--history <history.json> --update-history`,
and can compare against `--baseline <history.json>` to surface warning-only
regressions. A regression warning never skips tests and does not fail Lane C by
default; it identifies slow tests for follow-up optimization PRs. When an
explicit `--manifest <manifest.json>` is supplied, the helper backs up that
manifest as `<manifest>.bak` and adds an additive `duration_report` field.

Docker01 PR lane integration: the guarded Docker01 lane helper uses this same
Lane C command (`python scripts/run_full_pytest.py`) for full validation instead
of raw `pytest -q`. Its dry-run/planning output shows the runner command, and
execution logs preserve the runner output so reviewers can see xdist
availability/use, serial fallback, and slow-test duration reporting.

Optional Docker01/dev optimization: a reusable ShellForgeAI validation image may
be named `shellforgeai-test-runner` and may preinstall Python 3.12, `git`,
`rsync`, procps/`ps`, `pytest`, `pytest-xdist`, `ruff`, and the project dev
extras to avoid repeated setup cost and enable parallel full validation. That
image is an optimization only, not a normal-user requirement and not a test
skipping mechanism. If unavailable, the current writable validation-container
path still works, the runner reports serial fallback, and the image must not be
used to skip or weaken selected tests, selected commands, or safety gates.

> Visibility, not skipping. PR158/PR160 do not mark any test slow and do not
> skip any test. `--durations=25` only reports timing. Use the slowest-test
> table and optional duration history/regression report to identify repeated
> expensive setup, replace repetitive CLI setup with
> equivalent helper-level fixture builders where safe, and keep one
> representative CLI path when CLI behavior itself is the coverage target. Any
> skip or marker policy must be explicit and safety-reviewed.

---

## Validation heartbeat and interrupted-run evidence

Long Docker01 / full-validation runs can be SIGTERM/SIGINT/timeout-interrupted
(or SIGKILLed) before the helper records full `pytest` completion. PR175's first
full-validation helper run was SIGKILLed near the end and could not be counted as
a pass; a clean rerun was required. To make that situation obvious in the
evidence instead of silent, the validation lane writes a lightweight
**heartbeat / checkpoint / status** JSON file
([`../scripts/validation_heartbeat.py`](../scripts/validation_heartbeat.py)) that
is updated **before and after each phase**:

```bash
# Heartbeat is written automatically when the Docker01 lane executes validation:
python scripts/sfai_docker01_pr_lane.py --changed-files Dockerfile --pr 176 \
  --full-validation --full-validation-reason "validation helper changed" \
  --execute-validation \
  --manifest-output /tmp/sfai-pr176-manifest.json \
  --summary-output  /tmp/sfai-pr176-summary.txt \
  --heartbeat-file  /tmp/sfai-pr176-heartbeat.json \
  --checkpoint-file /tmp/sfai-pr176-checkpoints.json \
  --status-file     /tmp/sfai-pr176-status.json

# The Lane C runner can also write its own single-phase heartbeat:
python scripts/run_full_pytest.py --heartbeat-file /tmp/sfai-pr176-fullpytest.json
```

The heartbeat records `schema_version`, `run_id`, `pr`, `commit`, `status`
(`running` / `passed` / `failed` / `incomplete`), `active_phase`,
`last_completed_phase`, a per-phase `phase_status`
(`not_started` / `running` / `passed` / `failed` / `interrupted` / `unknown`),
`full_pytest_exit_code`, `full_pytest_result`
(`passed` / `failed` / `unknown`), `pass_eligible`, `rerun_required`,
`started_at`, `last_update`, and `pid`.

**Run classification.** The deterministic classifier turns phase status plus an
optional captured full-`pytest` exit code into one of:

| Result | When | `pass_eligible` | `rerun_required` |
| --- | --- | --- | --- |
| `passed` | every required phase passed **and** full `pytest` exit code `0` was captured | `true` | `false` |
| `failed` (`test_failure`) | a test phase failed or full `pytest` exited nonzero | `false` | `true` |
| `failed` (`setup_failure`) | a pre-test phase (`ruff`/`compileall`) failed, or the helper could not set up before tests | `false` | `true` |
| `incomplete` (`interrupted_or_incomplete`) | the run ended before full `pytest` completion was recorded | `false` | `true` |

- **`pass_eligible`** means this run is allowed to count as merge evidence. It is
  `true` **only** when `status == passed`. An incomplete or failed run is never
  pass-eligible.
- **`rerun_required`** means a clean validation rerun is needed before this change
  can be treated as validated. It is `true` for anything that is not a clean pass.

A `status == passed` is recorded **only** when every required phase passed and a
full-`pytest` exit code of `0` was captured. If the helper exits before the
full-`pytest` result is captured, the run is `incomplete`, not `passed`, and
`full_pytest_result` stays `unknown` (it is never reported as `passed` without a
captured exit code).

**SIGKILL caveat.** SIGKILL cannot be caught, so no finalizing heartbeat can be
written when a run is `kill -9`'d. That is intentional and safe: the *last*
heartbeat written before the kill still shows the active phase as `running`
(never `passed`), and the classifier reads that as `incomplete` /
`rerun_required`. SIGTERM/SIGINT/timeout interruptions are caught: the active
phase is marked `interrupted`, an `incomplete` manifest/summary is written, and
the helper exits non-zero.

**Merge rule.** An `incomplete` validation run is **not** merge evidence. The
human summary prints `Validation result: INCOMPLETE`, `Rerun required: yes`, and
a `*** RERUN REQUIRED ***` banner with the last active/completed phase. Do not
merge on an interrupted run; a clean rerun that reports `passed` /
`pass_eligible: yes` is required. If a clean rerun later passes, that run's
manifest reports the clean run as a pass.

The helper runs full `pytest` **once** per invocation and never auto-reruns it.
The heartbeat/classification path is validation evidence only: it writes JSON
artifacts and never mutates Docker/Compose/services/containers, never runs
cleanup/remediation/rollback/recovery, never restarts anything, never uses a
shell or arbitrary commands, and never calls a model.

## Validation evidence status viewer (PR177)

To inspect that heartbeat/status/manifest evidence after a run without rerunning
anything, use the read-only viewer
[`../scripts/validation_status.py`](../scripts/validation_status.py):

```bash
# Most recent run under the known validation artifact roots:
python scripts/validation_status.py --latest
python scripts/validation_status.py --latest --json

# A specific run directory or explicit evidence files:
python scripts/validation_status.py --run-dir <run_dir>
python scripts/validation_status.py --run-dir <run_dir> --json
python scripts/validation_status.py --heartbeat <path> --json
python scripts/validation_status.py --status-file <path> --json
python scripts/validation_status.py --manifest <path> --json
```

It answers, for a single run: did it **pass / fail / end incomplete / unknown**,
is it `pass_eligible` (usable as merge evidence), is a `rerun_required`, what
phase was active when it stopped, and where the heartbeat/status/manifest/log
files are.

| Status | Meaning | `pass_eligible` | `rerun_required` |
| --- | --- | --- | --- |
| `passed` | every required phase passed **and** full `pytest` exit `0` / passed result recorded | `true` | `false` |
| `failed` | a phase failed (`test_failure` or `setup_failure`); the failed phase is reported | `false` | `true` |
| `incomplete` (`interrupted_or_incomplete`) | the run ended before full `pytest` completion was recorded | `false` | `true` |
| `unknown` (`no_evidence`) | no heartbeat/status/manifest evidence was found | `false` | `true` |

`pass_eligible=true` is reported **only** when the status is `passed` and the
full-`pytest` completion evidence is present. If multiple evidence sources
disagree (for example a manifest claims `passed` while a heartbeat is
`incomplete`), the viewer prefers the conservative result, emits a warning, and
never reports `pass_eligible=true`. **An incomplete or unknown validation run is
not merge evidence** — require a clean rerun that the viewer reports as
`passed` / `Pass eligible: yes`.

The viewer is **read-only**. It reads ShellForgeAI validation evidence files and
renders human/JSON status only. It never executes validation, never runs
`pytest`, never calls Docker/Compose, never restarts/mutates anything, never runs
cleanup/remediation/rollback/recovery, never uses a shell, and never calls a
model.

## Full `pytest` policy

| Situation | Full `pytest`? |
| --- | --- |
| docs / wording / README / OPS / roadmap | No (Lane A) |
| read-only ask routing / intent / dispatch / UX / output / artifact | No (Lane B) |
| targeted tests fail or look suspicious | **Yes** (escalate to Lane C) |
| safety / execution boundary touched | **Yes** (Lane C) |
| Docker / Compose / restart / cleanup / remediation / rollback / mission / apply | **Yes** (Lane C) |
| `pyproject` / dependency / `Dockerfile` / packaging / import | **Yes** (Lane C) |
| validation infrastructure (`scripts/v1_validate.sh`, `validate_pr.py`, matrix, conftest) | **Yes** (Lane C) |
| reviewer explicitly requests it | **Yes** (Lane C) |
| unknown / high-risk change | **Yes** (escalate or require a reviewer reason) |

Full validation is **always available** and is never removed. Pass
`--profile full` (or `--full-validation`) to force Lane C on any change.

---

## Safety-boundary escalation

Two independent mechanisms keep safety-critical changes in Lane C:

1. **Structural (path) rules.** Execution/safety/packaging paths map directly to
   Lane C in the impact map — for example
   `src/shellforgeai/core/*remediation*`, `src/shellforgeai/core/*rollback*`,
   `src/shellforgeai/policy/**`, `Dockerfile`, `pyproject.toml`, and
   `scripts/v1_validate.sh`. This is deterministic and always on.

2. **Content / diff keyword scan.** When a diff or file content is available
   (via `--base/--head` or `--scan-content`), the optimizer scans **non-doc**
   changed content for safety/execution-boundary keywords and escalates to
   Lane C if any are present:

   `execute`, `confirm`, `cleanup_executed`, `remediation_executed`,
   `rollback_executed`, `docker_compose_executed`, `container_restarted`,
   `shell_true`, `subprocess`, `os.system`, `shell=True`, `docker restart`,
   `docker compose`, `rm -rf`, `chmod`, `chown`, `apply_executed`,
   `mission_created`, `plan_created`.

   Documentation that merely *describes* these keywords (for example
   `docs/safety.md`) does **not** escalate — only changed code/script/config
   content does. This is why a docs PR that talks about `shell=True` stays in
   Lane A while a code change that adds `shell=True` jumps to Lane C.

A `--profile` override may **escalate** a lane freely, but it can never
de-escalate below a safety-required full lane. If a safety keyword is present,
`--profile fast` is raised back to full with a warning. Safety gates cannot be
weakened to go faster.

Unmatched source modules (`src/**/*.py` with no mapped tests) default to
Lane B **with a warning** to pass `--pr <n>`, add a matrix entry, or escalate to
full. Unrecognized paths default to Lane C as a safe default.

---

## Docker01 PR lane report requirements

Full validation on Docker01 is **exceptional, not default**. Every Docker01 PR
run must produce a structured validation evidence manifest and a concise human
summary from `scripts/sfai_docker01_pr_lane.py`. The manifest is the review
source of truth: `schema_version=1`,
`mode=docker01_pr_validation_manifest`, lane selection/reason, whether full
validation was required, commands and phases with durations, log paths,
deploy/snapshot/image metadata when available, final container health when
available, validation statuses, safety flags, known non-blockers, and final
verdict. Missing optional Docker01 metadata should be `null` or `unknown`, not
invented.

Every Docker01 PR report must state through the manifest/summary:

- the **selected lane** (A / B / C)
- **why** that lane was selected
- the **commands run** plus durations/log paths
- the **phases** completed and any failed phase/error summary
- whether **full `pytest`** was required
- when a full pytest log is available, the optional duration tracking summary
  path/report and any warning-only slow-test regressions
- final container status/health/restart count when available
- safety flags for snapshot-before-mutation, compose atomic update, direct
  compose write, cleanup/remediation/rollback, prune, mutation beyond deploy,
  production restart, `shell=True`, arbitrary command execution, and
  natural-language mutation
- known non-blockers
- if full `pytest` was **skipped**, why that is acceptable (e.g. "Lane B
  read-only routing change; targeted regression group green; no safety or
  execution boundary touched")

Verdicts:

- **PASS** requires the selected lane to complete, validation statuses to be
  green or explicitly not required, final container health to be acceptable when
  collected, safety flags to remain within the Docker01 railings, and log paths
  or artifacts to be present for review.
- **HOLD** is for incomplete/partial evidence or known non-blockers needing
  reviewer acknowledgement; the manifest should explain the missing data or
  non-blocker without inventing success.
- **FAIL** is for failed commands/phases, unhealthy final container state, or a
  broken safety railing. The manifest must record the failed phase and error
  summary when available.

Rules:

- Full validation is **required** for execution / safety boundary PRs.
- Targeted validation is **acceptable** for docs / routing / output polish.
- Live smoke on Docker01 should match the changed behavior.
- Full validation is never removed — it remains available on demand.

The Docker01 deploy/snapshot/compose railings are unchanged and must stay
intact: snapshot before mutation, atomic/temp compose config update, cached
build default, no direct compose write, no destructive cleanup, no volume
prune, and no remediation/rollback/cleanup execution outside an explicit,
scoped PR. The lane optimizer does not deploy and does not touch any of these
railings.

See [`../OPS.md`](../OPS.md) ("PR validation lane policy") for the operator
runbook steps.

Self-test profile checks that probe `compose env-check --target shellforgeai --json` treat a blocked/non-allowlisted production target as expected safe behavior, not as execution readiness. Positive readiness checks must use disposable allowlisted fixtures; production `shellforgeai` must remain blocked and non-mutating.
