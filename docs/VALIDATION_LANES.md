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

CLI command-module splits must also consult the read-only refactor inventory in
[`CLI_REFACTOR_MAP.md`](CLI_REFACTOR_MAP.md). Every split must run the PR184
golden command-surface guardrail. Use Lane B only for narrow read-only moves;
use Lane C/full validation for broad command-surface moves, ask/refusal routing,
interactive mode, rollback/recovery/recipe/mission execution surfaces, or any
mutation-capable governed handler.

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
- model-backed `ask` Docker evidence grounding + ask-output unsupported-command
  filtering (read-only deterministic triage evidence; no mutation)
- intent parsing
- command dispatch
- interactive UX
- JSON output shape
- artifact read / validate / export behavior
- governed copy-only archive bundle creation when bounded by exact plan id, exact confirmation phrase, explicit output directory, targeted safety tests, and no source deletion/move/cleanup/Docker mutation
- model doctor live-probe receipt validation, including optional validator
  artifact output, because it reads existing files only and performs no model
  call or live probe
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

### Command-module refactors (PR184 command-surface guardrail)

The CLI command-module split (PR182/PR183 and the riskier extractions that
follow — `verify`, `handoff`, recipes, receipts, ask routing, governed
execution helpers) is exactly the kind of broad/core command refactor that
belongs in **Lane C**. To make those refactors safer, PR184 adds a
behavior-preserving golden command-surface guardrail:

```bash
pytest -q tests/test_pr184_cli_command_surface_golden.py
```

- Every command-module extraction PR should run the PR184 guardrail in addition
  to its normal lane, so a refactor cannot silently drop a command, a JSON flag,
  help text, a governed-execution `--confirm` requirement, or a mutation-refusal
  path.
- The guardrail is a fast, read-only safety net (no Docker, no model call, no
  mutation). It is **not** a substitute for full validation: broad/core command
  refactors still require Lane C (`python scripts/run_full_pytest.py`), because
  moving command implementations can expose hidden CLI import issues the
  surface snapshot alone will not catch.
- When the command surface changes *intentionally*, update
  `tests/golden/cli_command_surface_pr184.json` in the same PR; see
  [`cli.md`](cli.md) for the fixture contract and update workflow.

#### Command-surface guardrail performance (PR208)

The golden guardrail invokes the same read-only commands many times (the
parametrized sweep, the explicit numbered tests, and the whole-surface safety
sweep). The expensive ones — `v1 check` readiness, `status --json`,
`ops report` — each cost seconds of real, read-only host inspection, so the
PR205 `test_23` subprocess (which runs the whole PR184 suite) was repeatedly the
slowest validation path (~360s on Docker01).

PR208 adds a shared, process-wide invocation cache in
`tests/helpers/cli_surface.py` (`invoke_cached`) so each *unique* argv runs at
most once per test process, plus a deterministic duration report
(`invocation_duration_report` / `format_duration_report`). This is
**validation-performance/diagnostics work only**:

- Command-surface coverage is unchanged — every command, JSON flag, help
  surface, governed `--confirm` requirement, and mutation-refusal path is still
  asserted. The cache is correctness-neutral (every cached command is read-only
  and deterministic w.r.t. its argv), so a cached result is identical to a fresh
  invocation; a regression still fails every test that reads it.
- Import side-effect coverage (PR205) is unchanged; `test_23` simply runs the
  faster PR184 suite and now passes `--durations=15` for observability.
- Full validation is still appropriate when touching CLI registration or the
  import guardrails: run `pytest -q tests/test_pr208_command_surface_performance_polish.py`
  alongside the PR184/PR204/PR205 suites and `python scripts/run_full_pytest.py`.

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
# Most relevant recent run under the known validation artifact roots:
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

### Latest-artifact discovery and selection (PR181)

`--latest` selects the **most relevant** validation artifact deterministically
and explains why. It no longer just picks the newest file across every root —
which could surface an older persisted `/srv/data/.../validation-runs` manifest
even when a newer PR-specific run directory existed. Discovery is now ordered:

1. An explicit `--run-dir <path>` (or explicit `--heartbeat`/`--status-file`/
   `--manifest`) always wins — discovery is skipped entirely.
2. Recent PR-specific run directories
   (`/tmp/sfai-pr<PR>-<sha>-validation-*`).
3. Recent PR-specific validation-**container** run directories
   (`/tmp/sfai-pr<PR>-<sha>-validation-container-*`).
4. Recent mainline temp runs (`/tmp/shellforgeai-validation-runs/*`).
5. ShellForgeAI-owned persisted manifests
   (`/srv/data/shellforgeai/validation-runs/*`).
6. Legacy/persisted-only artifacts (`/data/validation-runs/*`) — **only** when
   `--include-legacy` is passed.

Within an eligible set, a more-preferred **kind** wins first (a recent
PR-specific run dir outranks an older persisted manifest even if the manifest is
newer), then the **newest timestamp** breaks ties. A legacy artifact never
outranks a recent PR-specific run directory. Only these bounded, ShellForgeAI-owned
locations are scanned — there is no arbitrary host crawl and no path traversal.

```bash
# Filter to a PR and/or commit (commit accepts an unambiguous prefix):
python scripts/validation_status.py --latest --pr 181
python scripts/validation_status.py --latest --commit 0b407fa
python scripts/validation_status.py --latest --pr 181 --commit 0b407fa

# Include older legacy/persisted-only artifacts in the search:
python scripts/validation_status.py --latest --include-legacy

# Scan only within one bounded run root (no host crawl; traversal rejected):
python scripts/validation_status.py --latest --run-root /srv/data/shellforgeai/validation-runs

# Explain which candidate was selected and why the others were skipped:
python scripts/validation_status.py --latest --explain-selection
python scripts/validation_status.py --latest --json --explain-selection
```

Both human and JSON output carry the **selected artifact path**, the
**selection reason** (e.g. `latest matching PR-specific validation run`), the
matched PR/commit, and `source.selected_by`
(`latest`/`pr`/`commit`/`pr_commit`/`run_root`/`run_dir`). `--explain-selection`
adds a `selection.candidates` list marking the selected candidate and the
`skipped_reason` for each other candidate (for example `older persisted manifest
(PR-specific run preferred)`, `PR mismatch`, `commit mismatch`). When several
eligible candidates tie at the top, the newest is chosen and a
`multiple matching candidates, newest selected` warning is emitted.

When no candidate is found at all (including for an unmatched `--pr`/`--commit`),
the viewer returns a controlled `status=not_found` / `classification=not_found`,
`pass_eligible=false`, `rerun_required=true` report — no traceback — and its
first safe command suggests a read-only re-scan
(`--latest --explain-selection`) and lists the known artifact locations to
check. Nothing is executed automatically.

**Forcing a specific run dir.** Because `--latest` is conservative, it may
report `failed`/`incomplete` for the most relevant artifact (that is the point —
a setup failure or interrupted run is not merge evidence). To inspect a
different run, pass `--run-dir <path>` explicitly; that bypasses discovery and
the latest-selection block is omitted.

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

## Docker01 operator QA evidence bundle (PR206)

Docker01 PR QA is strong, but the reviewer handoff was still assembled by hand
from many command outputs and logs. The read-only bundle helper
[`../scripts/docker01_operator_qa_bundle.py`](../scripts/docker01_operator_qa_bundle.py)
removes that copy/paste step: it runs the standard read-only smoke QA set once,
captures raw stdout/stderr/exit codes, parses the key JSON outputs, evaluates
explicit safety assertions, and writes a small, pasteable evidence packet.

**Run it from the Docker01 host.** ShellForgeAI product smoke commands are
executed *inside* the running `shellforgeai` container through a narrow
read-only `docker exec shellforgeai shellforgeai …` argv allowlist, so the host
does **not** need `shellforgeai` on its PATH. Host/system checks
(`docker ps` / `docker inspect shellforgeai` / `df -h /` / the validation status
viewer) run host-side; the validation status viewer runs with the helper's own
Python interpreter (`sys.executable`) so hosts that have `python3` but no
`python` alias work too, and it is scoped to the PR/commit under review so stale
evidence from another PR is never embedded.

```bash
# Preview the plan without running anything or writing a bundle:
python3 scripts/docker01_operator_qa_bundle.py --pr 206 --commit <sha> --dry-run
python3 scripts/docker01_operator_qa_bundle.py --pr 206 --commit <sha> --dry-run --json

# Generate the evidence bundle (default path under /tmp):
python3 scripts/docker01_operator_qa_bundle.py --pr 206 --commit <sha>
python3 scripts/docker01_operator_qa_bundle.py --pr 206 --commit <sha> --out /tmp/sfai-pr206-qa-bundle
python3 scripts/docker01_operator_qa_bundle.py --pr 206 --commit <sha> --json
```

**When to run it:** from the Docker01 host during PR QA, after the container is
deployed and the standard smoke checks are expected to be green. Running from
the host (not inside the container) keeps the host-side validation artifacts
produced by the guarded lane visible to the helper. **Dry-run first** to confirm
the plan, then generate the bundle.

The default bundle path is
`/tmp/sfai-pr<PR>-<shortsha>-qa-bundle-<timestamp>/` and contains:

- `qa-summary.md` — the pasteable Markdown handoff (paste this into the PR).
- `qa-results.json` — strict machine-readable rollup (status, per-command
  results, safety block).
- `safety-assertions.json` — explicit read-only safety assertion results.
- `container-state.json` — status/health/restart_count/image/labels/disk.
- `validation-status.json` — latest validation evidence status (or a clean
  `not_available`).
- `commands-run.json` — the audited command list (argv, allowlist, exit codes).
- `raw/` — captured stdout for each command (plus `.stderr.txt` on failure).

**Collected commands:** the ShellForgeAI product smoke checks run as
`docker exec shellforgeai shellforgeai <command>` — `version`, `doctor`,
`model doctor`, `v1 check --profile quick/standard --json`, `ops report --json`,
`status --json`, `triage docker --json`, `propose --json`,
`apply-preview --json`, `verify --json`, `handoff --json`, a read-only Docker
`ask`, a mutation `ask` (expected to be refused), and
`remediation self-test --profile full --json` (live disposable execution stays
skipped by default). The read-only host checks run host-side:
`docker ps --filter name=shellforgeai`, `docker inspect shellforgeai`,
`df -h /`, and the validation status viewer **scoped to the PR/commit under
review**:

```bash
<current-python> scripts/validation_status.py --latest --pr <PR> --commit <sha> --json --explain-selection
```

Scoping matters: an unscoped `--latest` could select stale validation evidence
from another PR (e.g. an older PR179 run) and embed it into this bundle. With
`--pr`/`--commit`, matching validation evidence is included when found; if none
exists for this PR/commit the bundle reports `not_found` / `not_available`
cleanly; and concrete evidence for a different PR/commit is never treated as
current evidence (`validation-status.json` records the scoped target and a
`scope_matched` flag).

**Paste into the PR handoff:** copy the contents of `qa-summary.md` into the PR.
The summary reports container state, smoke results, ask safety, the remediation
self-test rollup, validation status, and the safety-assertion verdicts. If a
non-critical host check (Docker daemon, model, prior validation run) is absent,
the bundle status is `partial` rather than `failed`; a failed ShellForgeAI
product check or a failed safety assertion makes it `failed`.

**Safety boundaries:** this is evidence collection only. Commands come from a
small fixed allowlist limited to `docker ps --filter name=shellforgeai`,
`docker inspect shellforgeai`, `docker exec shellforgeai shellforgeai <approved
read-only command>`, `df -h /`, and `validation_status.py`. Any other family is
rejected — including `docker restart`, `docker compose restart/down`,
`docker volume prune`, a `docker exec` into a shell
(`docker exec shellforgeai sh -lc …` / `bash -lc …`) or any other binary
(`docker exec shellforgeai rm/touch/curl/wget/apt/pip …`), injected `docker
exec` flags (`-u`/`-i`/`-e`), and `gh pr merge` / `codex apply`. Subprocess
execution uses argv lists with bounded timeouts and never `shell=True` (no
`sh -lc`/`bash -lc` shell strings). The helper performs no cleanup, remediation,
rollback, recovery, Docker/Compose mutation, container/production restart,
prune, package install, network call, or cloud apply/merge/push. The bundle
**never auto-declares a PR mergeable** — the reviewer still gives the final merge
verdict.

### QA bundle lifecycle: validate / history / compare / compare-latest (PR207)

PR206 generates bundles; PR207 adds four **artifact-only** lifecycle modes that
prove bundles are complete, internally consistent, discoverable, and comparable
**without re-running smoke QA and without mutating Docker01**. They only read
existing bundle files, parse JSON, list bundle directories under a chosen root,
and compute sha256 hashes. They **do not** run ShellForgeAI, Docker,
`docker exec`, or `validation_status.py`, use no subprocess at all, and never
modify/delete/repair a bundle, restart anything, prune, call the network, or
apply/merge/push.

```bash
# Validate one bundle (structure + internal consistency + manifest integrity):
python3 scripts/docker01_operator_qa_bundle.py --validate-bundle <bundle_dir>
python3 scripts/docker01_operator_qa_bundle.py --validate-bundle <bundle_dir> --json

# Discover/filter bundles under a root (default /tmp), newest first:
python3 scripts/docker01_operator_qa_bundle.py --history --root /tmp
python3 scripts/docker01_operator_qa_bundle.py --history --root /tmp --pr 206 --json
python3 scripts/docker01_operator_qa_bundle.py --history --root /tmp --pr 206 --status passed --limit 5

# Compare two bundles, or the newest two matching a PR/commit:
python3 scripts/docker01_operator_qa_bundle.py --compare <old_bundle> <new_bundle>
python3 scripts/docker01_operator_qa_bundle.py --compare-latest --root /tmp --pr 206
python3 scripts/docker01_operator_qa_bundle.py --compare-latest --root /tmp --pr 206 --commit <sha> --json
```

**validate** returns `valid` / `warning` / `invalid` after checking: the bundle
directory and required files exist; required JSON parses strictly; `qa-summary.md`
is non-empty; `qa-results.json` carries `schema_version`/`mode`/`status` and
`pr`/`commit`/`short_sha`; a safety block exists with `read_only=true` and
`mutation_performed=false` (unless `status=failed` is honestly reported);
`first_safe_command` points at `qa-summary.md`; raw outputs exist for every
listed command; command and safety-assertion summary counts match their entries;
and `validation-status.json`'s `requested_pr`/`requested_commit` match the
bundle. A **scoped validation `not_found`** is *clean* (valid) when it belongs to
the requested PR/commit and does not claim `pass_eligible=true`; a
`scope_matched=false` is surfaced as a **warning** (evidence for a different
PR/commit is never treated as current). When a `bundle-manifest.json` is present,
validate recomputes each file's sha256 and flags any mismatch as `invalid`.

**bundle-manifest.json** is written into newly generated bundles: it records the
`size_bytes` + `sha256` of `qa-summary.md`, every top-level JSON file, and each
`raw/*` output. **Legacy PR206 bundles without it stay usable** — validate falls
back to structural checks and emits the warning `bundle-manifest.json missing;
legacy bundle integrity checks limited to structural validation`.

**history** discovers directories matching
`sfai-pr<PR>-<shortsha>-qa-bundle-<timestamp>` under the root, runs lightweight
validation on each, extracts pr/commit/short_sha/created_at/status, command and
safety counts, and the validation status block, then sorts newest first. Filter
with `--pr`, `--commit`, `--status`, and `--limit`. Unrelated directories and
corrupt bundles are skipped/flagged without crashing.

**compare** / **compare-latest** classify the delta as `regressed`, `improved`,
`changed`, or `same` (`invalid` if a bundle can't load; `not_enough_bundles` for
compare-latest when fewer than two match — exit 1 for human use, strict JSON
otherwise). Regressions include `passed -> failed`, a command or safety assertion
flipping `passed -> failed`, `mutation_performed false -> true`, validation
`scope_matched true/null -> false`, `restart_count` increasing, and health
`healthy -> unhealthy`; improvements are the inverse (including validation
`not_found -> passed`). **PR handoff:** attach the compare output to show a new
bundle did not regress against the prior one. The reviewer still gives the final
merge verdict.

## Validation environment preflight (PR178)

Before any ruff/compileall/pytest phase runs on a host, the validation
environment itself must have the dev tools those phases need. PR177 QA showed
the failure mode: a host without dev dependencies produced a real ruff
setup-failure artifact mid-run. The read-only preflight
[`../scripts/validation_env_preflight.py`](../scripts/validation_env_preflight.py)
detects that *before* validation phases start:

```bash
python scripts/validation_env_preflight.py
python scripts/validation_env_preflight.py --json

# Through the Docker01 PR lane helper:
python scripts/sfai_docker01_pr_lane.py --preflight-only
```

It checks (availability/presence only — nothing is executed or installed):
Python executable/version, `ruff`, `pytest`, `pytest-xdist` (warning unless
required), `shellforgeai` package importability (spec lookup only), presence of
`scripts/run_full_pytest.py` / `scripts/validation_heartbeat.py` /
`scripts/validation_status.py`, write access to the validation artifact
directory, and the ability to create a heartbeat/status-style JSON probe file.

| Preflight result | Meaning | `pass_eligible` | `rerun_required` |
| --- | --- | --- | --- |
| `passed` | all required tools/checks present; validation can continue | — | `false` |
| `passed_with_warnings` | validation can continue; warnings (e.g. missing `pytest-xdist`) are preserved in the final evidence | — | `false` |
| `failed` (`setup_failure`) | a required dev tool/check is missing; validation must not start | `false` | `true` |

When `--execute-validation` is used, the Docker01 PR lane helper runs this
preflight as an `environment_preflight` phase **before** ruff/compileall/pytest:

- **Preflight passed** — validation continues normally; the preflight result is
  recorded in the heartbeat, manifest (`environment_preflight`), and the
  preflight JSON (`validation-preflight.json` next to the manifest, or
  `--preflight-output <path>`).
- **Preflight failed** — the helper stops *before* any validation phase, writes
  the full evidence set (manifest/summary/heartbeat/status/checkpoint plus the
  preflight JSON), and classifies the run as `status=failed`,
  `classification=setup_failure`, `failed_phase=environment_preflight`,
  `pass_eligible=false`, `rerun_required=true`. The human summary states
  explicitly: this is **setup failure, not product test failure**.
- **Warnings only** — validation continues and the warnings are kept as
  non-blocker notes in the manifest.

**Setup failure is not product test failure, and it is not merge evidence.**
The recommended next step on a failed preflight is to run validation in the
disposable validation container path, or prepare the host dev environment
outside ShellForgeAI, then rerun validation. The preflight never installs
packages, never modifies venvs or host Python, never runs `pytest` or
`ruff check`, never runs a subprocess, never calls Docker/Compose (the
container path is recommendation text only), and never mutates anything beyond
one tiny probe file written and removed inside the artifact directory.

Use `python scripts/validation_status.py --run-dir <run_dir> --json` to inspect
a preflight setup-failure run afterwards; the viewer reports
`classification=setup_failure`, `failed_phase=environment_preflight`,
`pass_eligible=false`, `rerun_required=true`, and points its first safe command
at the preflight. (The broader environment doctor
[`../scripts/check_validation_env.py`](../scripts/check_validation_env.py)
remains available for deeper, standalone environment inspection.)

## Validation container fallback packet (PR179)

When a run stops on a preflight `setup_failure` (missing host `ruff`/`pytest`/
etc.), the fallback packet generator
[`../scripts/validation_container_fallback.py`](../scripts/validation_container_fallback.py)
turns that evidence into a safe, copy-pasteable **disposable validation
container** path — without installing anything on the host:

```bash
python scripts/validation_container_fallback.py --run-dir <validation_run_dir>
python scripts/validation_container_fallback.py --run-dir <validation_run_dir> --json
python scripts/validation_container_fallback.py --run-dir <validation_run_dir> --lane full
python scripts/validation_container_fallback.py --run-dir <validation_run_dir> --pr 179 --commit <sha>
python scripts/validation_container_fallback.py --run-dir <validation_run_dir> --image lab/shellforgeai:pr179-<sha>
```

It reads `validation-preflight.json` / `validation-status.json` / the manifest
in the run directory and, when they record a `setup_failure`, writes a packet
into the same run directory:

- `validation-container-fallback.json` — strict-JSON packet evidence
- `validation-container-fallback.md` — why host validation stopped, missing
  tools, recommended container approach, expected phases, safety notes
- `validation-container-command.txt` — the exact operator-run command
- `validation-container-command.argv.json` — the same command as an argv list

The generated command starts a disposable container (`--rm`), mounts the repo
read-only, mounts the run dir for artifacts, installs dev dependencies *inside
the container only*, and runs ruff/compileall/pytest there. Inspect it first:

```bash
cat <validation_run_dir>/validation-container-command.txt
```

| Run-dir state | Packet result | Exit code |
| --- | --- | --- |
| `setup_failure` evidence present | `created` (packet files written) | 0 |
| clean/passed run | `not_needed` (no files written; `--force` overrides) | 0 |
| run dir missing | `not_found` | nonzero |
| evidence present but malformed | `failed` (controlled warning) | nonzero |

The Docker01 PR lane helper generates this packet automatically when its
`environment_preflight` phase fails, records the packet path in the manifest
(`environment_preflight.fallback_packet_path`) and human summary, and the
PR177 viewer reports `fallback_packet_present` / `fallback_packet_path` and
adds the packet command to `safe_next_commands` for setup failures.

**The generator is packet-only.** It never runs Docker or Docker Compose,
never restarts containers, never runs `pytest` or `ruff`, never installs host
packages, never runs a subprocess, and never executes the generated command —
the operator must run container validation explicitly if they choose to. A
setup-failure run, with or without a packet, is **not merge evidence**; only a
clean validation rerun can pass.

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

## Docker01 hygiene report lane

`python scripts/docker01_hygiene_report.py --dry-run` previews the fixed read-only checks and intended report path without executing commands or writing the full report. `python scripts/docker01_hygiene_report.py --out /tmp/sfai-docker01-hygiene-report` writes a Docker01 hygiene evidence directory for handoff review.

The lane is operational visibility only: it captures disk, Docker image, container, compose-backup, validation-evidence, QA-bundle, and support-artifact inventory. `candidate-cleanup-plan.md` is not executable and records only proposal-only cleanup candidates for future operator review. Cleanup, prune, image removal, file deletion, Compose mutation, and restart remain out of scope.

## Docker01 hygiene cleanup-plan validation

Use the explicit validation mode when reviewing an existing Docker01 hygiene report / candidate cleanup plan:

```bash
python scripts/docker01_hygiene_report.py --validate /tmp/sfai-docker01-hygiene-report --json
```

This is a Lane C safety-boundary check for hygiene/reporting infrastructure, even though it is read-only. The helper reads the existing report files with bounded caps sized for realistic Docker01 report JSON, validates strict JSON shape, checks the fixed PR209 read-only command list, verifies proposal-only/no-cleanup language, bounds candidates and raw files separately, fails oversized files safely, and rejects executable cleanup/prune/delete/restart/network/package/cloud/Codex patterns. A pass means the artifact is safer for operator review; it does not authorize automatic cleanup or future mutation.

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

## Docker01 hygiene review bundle

Use the review bundle when an operator needs one bounded packet containing an existing hygiene report, validation result, optional history/compare context, candidate cleanup plan copy, safety notes, manifest, checksums, and strict JSON rollup before any future cleanup lane is considered:

```bash
python scripts/docker01_hygiene_report.py --review-bundle <report_dir> --json
python scripts/docker01_hygiene_report.py --review-bundle-latest --root /tmp --json
```

Bundle mode reads existing report artifacts only. It does not run Docker, generate a new hygiene report, clean up files, prune/remove Docker images, restart containers, mutate Compose, or authorize cleanup. Missing history/compare context is recorded as a warning or `not_available` so the evidence packet can still be reviewed when safe source files are readable.

## Docker01 storage health report lane

`python scripts/docker01_storage_health_report.py --json` emits a strict, read-only storage/filesystem health report; `--out <dir>` additionally writes `storage-health-report.json`, `storage-health-summary.md`, `commands-run.json`, `manifest.json`, and `checksums.json`. This lane exists because PR229 observed a slow Docker build chown layer and pre-existing EXT4/dm-10 kernel warnings on Docker01 that are host storage signals rather than PR cleanup/remediation work.

```bash
python scripts/docker01_storage_health_report.py --json
python scripts/docker01_storage_health_report.py --out /tmp/sfai-docker01-storage-health --json
```

The lane is evidence-only and uses a fixed read-only command allowlist (`df -P -B1`, `findmnt --json`, `dmesg --level=err,warn --ctime`, `journalctl -k -p warning..alert --no-pager -n <bounded>`) plus `shutil.disk_usage` and `/proc/mounts`, always with `shell=False`. Denied `dmesg`/`journalctl` access yields `partial` (not a crash); a missing `findmnt` falls back to `/proc/mounts`. It never runs `fsck`/`e2fsck`/`xfs_repair`, mount/remount/umount, Docker prune/image/volume/container removal, file deletion, container restart, Docker/Compose mutation, or remediation/rollback/recovery, and adds no mutation switches.

## Docker01 QA bundle hygiene evidence

Docker01 operator QA bundles include hygiene evidence by default using existing history and compare-latest report readers:

```bash
python scripts/docker01_operator_qa_bundle.py --pr 213 --commit <sha> --json
python scripts/docker01_operator_qa_bundle.py --pr 213 --commit <sha> --include-hygiene-review-bundle --json
```

The default QA bundle records hygiene history and compare-latest status in `qa-results.json`, `qa-summary.md`, `commands-run.json`, and `raw/hygiene-*.json`. Review bundle creation is explicit opt-in with `--include-hygiene-review-bundle`; otherwise review bundle status is `skipped`. Missing hygiene history is non-blocking and is reported as `not_available`, `empty`, or `partial` with warnings.

QA hygiene integration is evidence-only. It does not run cleanup, Docker prune, Docker image removal, file deletion, Docker/Compose mutation, container restart, model/Codex calls, network calls, or package installs.

## Docker01 QA bundle model receipt evidence

Docker01 operator QA bundles include read-only Model Doctor receipt evidence by default, so a reviewer can see whether model/auth readiness was recently verified by an explicit previous live probe without the QA bundle itself calling the model:

```bash
python scripts/docker01_operator_qa_bundle.py --pr 229 --commit <sha> --json
python scripts/docker01_operator_qa_bundle.py --pr 229 --commit <sha> --skip-model-receipts --json
```

The QA bundle runs only the existing read-only `shellforgeai model receipt history --root /tmp --json` reader and records a `model_receipts` block in `qa-results.json` (receipt history status, latest receipt path/validation, latest probe status, latest auth readiness, valid/invalid counts, warnings, safe next command), a `Model receipt evidence` section in `qa-summary.md`, the command in `commands-run.json`, and `raw/model-receipt-history.json` plus `raw/model-receipt-evidence.json`.

This is evidence-only. The QA bundle performs no live probe and no model call: its `model_receipts.safety` block always reports `model_called=false`/`live_probe_performed=false`. A historical receipt's `model_called=true` is accepted as evidence of an earlier explicit probe (PR226). Empty or unavailable receipt history is non-blocking and reported as `empty`/`not_available` with warnings; a secret marker or a historical safety drift in the receipt evidence is surfaced as a blocking safety failure. The integration runs no cleanup, Docker prune/image removal, file deletion, Docker/Compose mutation, container restart, remediation/rollback/recovery, network call, or package install. SeedOfEvil remains final merge owner.

## Docker01 PR-lane validation evidence

Guarded Docker01 PR-lane runs write a discoverable validation evidence directory by default at:

```text
/tmp/sfai-pr<PR>-<shortsha>-validation-<timestamp>/
```

The directory contains `validation-status.json`, `validation-manifest.json`, `validation-summary.md`, `commands-run.json`, and `logs/`. The manifest records SHA256 and byte size metadata for the evidence files so downstream QA bundles can cite the exact validation packet. Inspect it with:

```bash
cat <run_dir>/validation-summary.md
python scripts/validation_status.py --latest --pr <PR> --commit <sha> --json --explain-selection
```

`failed`, `setup_failure`, and `interrupted` evidence is never pass-eligible and always requires a rerun. This evidence writer is validation-only: it does not execute cleanup, Docker prune, image removal, file deletion, remediation, rollback, recovery, natural-language execution, `shell=True`, cloud apply/merge/push, or Docker/Compose mutation beyond the separately guarded deploy/recreate lane.

## Docker01 PR-lane status/resume helper

Use the Docker01 PR-lane status helper after an interrupted or aborted guarded lane run to inspect what is already true before rerunning anything:

```bash
python scripts/sfai_docker01_pr_lane.py --pr <PR> --commit <sha> --status --json
python scripts/sfai_docker01_pr_lane.py --pr <PR> --commit <sha> --status
```

`--status` is read-only. It checks the current source HEAD, existing Docker container labels/image/health/restart evidence, exact PR/commit validation evidence, and exact PR/commit QA bundle evidence. It emits `already_complete`, `needs_qa`, `needs_validation`, `needs_deploy`, `blocked`, `ready_to_continue`, or `unknown`, plus a bounded `safe_next.command`. The command is guidance only; it never auto-resumes the lane and never declares the PR mergeable. The reviewer still gives the final merge verdict.

Status mode does not snapshot, deploy, write Compose, build images, restart containers, run validation, run QA, clean up, prune, delete files, remediate, roll back, recover, call a model/Codex, fetch from the network, install packages, merge, push, or use `shell=True`.

`--status` reads the configured Compose image tag from the trusted Compose file when available and treats Docker image IDs/digests as runtime metadata, not as the configured PR image tag. Exact PR/commit validation evidence is ranked so a later pass-eligible result is not masked by an earlier setup-failure packet. QA bundle discovery accepts exact PR/commit operator bundle directories such as `/tmp/sfai-pr<PR>-<shortsha>-operator-qa-bundle-<timestamp>/` and prefers passed bundles.

## Docker01 merge-readiness evidence report

Use the merge-readiness helper when reviewers need one bounded read-only packet that summarizes existing Docker01 evidence for an exact PR/commit:

```bash
python scripts/docker01_merge_readiness.py --pr <PR> --commit <sha> --json
python scripts/docker01_merge_readiness.py --pr <PR> --commit <sha> --comment
python scripts/docker01_merge_readiness.py --pr <PR> --commit <sha> --out /tmp/sfai-pr<PR>-<short>-merge-readiness --comment
```

The helper consumes existing PR-lane status, scoped validation status, exact PR/commit operator QA bundle evidence, and hygiene status embedded in the QA bundle. With `--out`, it writes `merge-readiness.json`, `merge-readiness-summary.md`, `manifest.json`, `checksums.json`, and bounded raw JSON captures for validation status, PR-lane status, and QA-bundle summary. `--comment` renders a paste-ready Markdown reviewer comment only; with `--out --comment`, the directory also contains `merge-comment.md`. The renderer does not post to GitHub, approve, merge, or replace reviewer judgment.

Statuses are evidence classifications only: `pass_candidate` means existing exact PR/commit evidence appears merge-ready and renders as `PASS / mergeable`; `hold_candidate` means a blocker such as failed validation, failed QA, stale/mismatched source/container evidence, restart drift, or safety drift was found and renders as `HOLD / needs follow-up`; `unknown` means evidence is too incomplete to decide and renders as `NEEDS EVIDENCE / cannot determine`. Safe warnings include partial older hygiene history when compare-latest is ok, known pre-existing metadata advisories, model-doctor auth readiness unknown when other readiness evidence is acceptable, and skipped review bundles when not required.

This helper does not deploy, build, validate, run QA, restart, clean, prune, delete, remediate, roll back, recover, mutate Docker/Compose, use `shell=True`, execute natural-language commands, call models/Codex, install packages, call the network, apply cloud changes, merge, or push. SeedOfEvil remains final merge owner.

### Docker01 validation evidence finalizer

The Docker01 PR lane now finalizes structured validation evidence after each
validation attempt. The finalizer records an already-completed result only; it
does not run validation, pytest, QA, Docker, Compose, cleanup, restart, prune,
delete, remediation, rollback, recovery, network calls, or model calls. The
optional recovery shape is:

```bash
python scripts/docker01_validation_evidence.py --pr <PR> --commit <sha> --log <validation-log-path> --status passed --json
```

Evidence is written under the established PR/commit-scoped validation directory
shape, for example `/tmp/sfai-pr<PR>-<shortsha>-validation-<timestamp>/`, with
`validation-status.json`, `validation-manifest.json`, `validation-summary.md`,
`commands-run.json`, and a bounded `source-log-excerpt.txt` when a log exists.
Statuses are deterministic: `passed` is pass eligible and does not require a
rerun; `failed`, `setup_failure`, `interrupted`, and `unknown` are never pass
eligible and always require a rerun. If a host setup failure is followed by a
successful disposable-container validation for the same PR/commit, the later
pass evidence is selected and the earlier setup failure is retained only as a
warning/process note.

`validation_status.py --latest --pr <PR> --commit <sha> --json
--explain-selection` selects exact PR/commit evidence by safe precedence:
latest pass-eligible completed evidence, then failed evidence, then setup
failure, then interrupted/incomplete, then `not_found`. Stale evidence for a
different PR or commit is ignored, and read-only status, merge-readiness, and
comment rendering tools continue to read evidence only.

The automatic finalizer uses the requested PR head commit supplied to the lane
(`--head-commit` or `--commit`) when writing validation evidence, so the standard
lane path is immediately discoverable by exact PR/commit status checks after a
terminal validation result. Full Lane C metadata is carried in
`validation-status.json` as `full_validation=true` with the recorded reason, and
read-only status/merge-readiness/comment tools surface that metadata without
running validation or QA.

Disposable validation fallback commands now prepare the slim Python container for
the full project test suite by installing `procps` (for `ps`), `git`, and
`rsync` inside the disposable container before copying the read-only source tree
and running validation. This package installation is part of the generated
container command only; the packet generator does not install host packages and
does not change the production container.

Manual fallback validation containers use the same minimum baseline as the official Docker01 lane helper: `python3`, `pytest`, `procps`/`ps`, `git`, and `rsync`. In particular, `tests/test_investigation_tools.py::test_process_snapshot_shape` requires `ps`; if that test fails because `ps` is absent, treat it as validation-environment drift, install the missing baseline package in the disposable container, rerun only that narrow test first, and run full pytest once only if whole-suite evidence is still needed.

```bash
apt-get update
apt-get install -y --no-install-recommends procps git rsync
python3 -m pytest -q tests/test_investigation_tools.py::test_process_snapshot_shape
```

This snippet is not a production Docker/Compose mutation workflow and must not be expanded into cleanup, prune, restart, remediation, rollback, recovery, or broad infrastructure repair. The PR247 Docker/LXC `chown -R` build-path hang remains operational setup context, separate from ShellForgeAI's read-only runtime posture.

The generated disposable fallback command also invokes the validation evidence
finalizer inside the copied repo after the container validation command exits,
writing final `validation-status.json`, `validation-manifest.json`,
`validation-summary.md`, and `commands-run.json` into the mounted run directory
(`/artifacts`, the host lane run directory). A successful fallback therefore
turns the exact PR/commit evidence packet into pass-eligible validation evidence
without a manual finalizer command.

By default, new lane validation evidence is created under
`/tmp/shellforgeai-validation-runs/sfai-pr<PR>-<shortsha>-validation-<timestamp>/`.
This keeps the normal path writable by the lane process without `sudo` while
remaining within a root scanned by `validation_status.py --latest`.

`SFAI_VALIDATION_RUNS_DIR` and other discovery-root overrides add search roots for
operators, but they do not hide the built-in writable lane root. This prevents a
persisted root that needs elevated writes from masking automatically finalized
standard-lane evidence.

When the host validation setup fails and the disposable fallback later completes
for the same PR/commit/run directory, the fallback's terminal finalizer packet is
the selected result. A successful fallback is reported as final `passed` /
`pass_eligible=true` evidence, while the earlier host `setup_failure` remains in
warnings/process notes for auditability. If the fallback fails, the final result
is `failed`; if no later fallback pass/fail exists, setup/interrupted evidence is
never pass eligible. `validation_status.py --explain-selection` reports when
earlier setup evidence was superseded by the completed fallback attempt, and the
status/merge-readiness/comment tools remain read-only: they do not run
validation or QA.


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

`shellforgeai model doctor --json` is part of Docker01 live QA and emits strict read-only model readiness JSON; unavailable or unknown model auth is reported structurally instead of as a CLI option failure. By default no live probe is performed and `auth_readiness=not_verified` means live auth was not requested. `--live-probe` is explicit and bounded; `--receipt-out <dir>` writes requested receipt artifacts with read-only/no-mutation safety metadata and no secrets, cleanup, remediation, rollback, recovery, Docker mutation, or Compose mutation.

For exact PR/commit lane runs, a later successful disposable validation fallback supersedes earlier host setup_failure evidence in `validation_status.py --latest`; the setup failure remains in warnings/process notes, while failed or interrupted evidence without a later exact pass stays non-pass-eligible.

### Model Doctor receipt history and compare

Existing Model Doctor live-probe receipts can be inspected without a new probe or model call:

```bash
shellforgeai model receipt history --root /tmp --json
shellforgeai model receipt compare /tmp/old-receipt /tmp/new-receipt --json
```

History scans only a bounded root for known Model Doctor receipt-shaped directories, validates each candidate with the same required-file, JSON, manifest, checksum, secret-marker, and safety checks used by receipt validation, and reports valid, invalid, and ignored candidates. Compare validates both receipt directories before reporting status, auth-readiness, latency, timeout, provider, and model drift. These commands are read-only: they do not run a live probe, call a model, call network/Codex, clean/prune/delete, repair/move artifacts, mutate Docker/Compose, restart containers, remediate, roll back, or recover. Default `shellforgeai model doctor` still performs no model call; explicit `--live-probe` remains opt-in and bounded. SeedOfEvil remains final merge owner.
## Docker01 artifact archive plan

`scripts/docker01_artifact_archive_plan.py` is the first governed mutation-runway step for ShellForgeAI-owned historical evidence artifacts. It is a read-only plan contract only: it discovers bounded `/tmp/sfai-*` evidence artifacts, classifies known candidate classes, estimates counts/bytes, emits a deterministic `plan_id`, and documents explicit exclusions plus the future confirmation/receipt/manifest/checksum requirements. Execution is not available in this PR.

Examples:

```bash
python3 scripts/docker01_artifact_archive_plan.py --root /tmp --json
python3 scripts/docker01_artifact_archive_plan.py --root /tmp
python3 scripts/docker01_artifact_archive_plan.py --root /tmp --out /tmp/sfai-pr231-artifact-archive-plan
```

`--out` writes plan metadata files only (`artifact-archive-plan.json`, summary, candidate/excluded manifests, safety notes, manifest, checksums). It does not create an archive and does not copy, move, modify, or delete source candidates. Candidate scope is limited to known ShellForgeAI evidence artifact patterns such as QA bundles, validation artifacts, merge/v2 readiness artifacts, hygiene reports, model receipts, receipt validation, and storage-health reports. Docker volumes/images/containers, Compose/source/runtime paths, `/var/lib/docker`, `/srv/compose`, home directories, system logs, package caches, unmatched arbitrary files, and symlinks remain out of scope.

Any future execution lane would be separate and must require the exact `plan_id`, exact `CONFIRM_SHELLFORGEAI_ARTIFACT_ARCHIVE` phrase, bounded candidate classes, a validated candidate manifest, archive and receipt output targets, a dry-run preview first, and operator review. Future execution must still never allow Docker prune, image/volume removal, container restart, Compose mutation, remediation, rollback, recovery, wildcard/arbitrary deletion, natural-language command execution, or `shell=True`. SeedOfEvil remains final merge owner.

The dry-run receipt step remains read-only and requires an exact validated plan id:

```bash
python3 scripts/docker01_artifact_archive_plan.py --dry-run-receipt /tmp/sfai-pr231-artifact-archive-plan --plan-id sha256:<plan-id> --json
python3 scripts/docker01_artifact_archive_plan.py --dry-run-receipt /tmp/sfai-pr231-artifact-archive-plan --plan-id sha256:<plan-id> --out /tmp/sfai-pr233-artifact-archive-dry-run --json
```

The helper validates the source plan first, refuses missing/mismatched plan ids, and reports `ready_for_review` only for a valid human-reviewable future lane preview. Receipt output files are metadata only: no archive is created, no source is copied/moved/modified/deleted, the source plan directory is not modified, and cleanup/prune/delete/restart/remediation/rollback/recovery plus Docker/Compose mutation remain unavailable. Future execution remains a separate PR/lane gated by exact plan id and `CONFIRM_SHELLFORGEAI_ARTIFACT_ARCHIVE`; SeedOfEvil remains final merge owner.

The receipt validator is also read-only:

```bash
python3 scripts/docker01_artifact_archive_plan.py --validate-dry-run-receipt /tmp/sfai-pr233-artifact-archive-dry-run --json
python3 scripts/docker01_artifact_archive_plan.py --validate-dry-run-receipt /tmp/sfai-pr233-artifact-archive-dry-run --plan-dir /tmp/sfai-pr231-artifact-archive-plan --json
python3 scripts/docker01_artifact_archive_plan.py --validate-dry-run-receipt /tmp/sfai-pr233-artifact-archive-dry-run --plan-dir /tmp/sfai-pr231-artifact-archive-plan --out /tmp/sfai-pr234-artifact-archive-dry-run-validation --json
```

It validates receipt required files, JSON, manifest, checksums, safety flags, candidate scope, and future contract. With `--plan-dir`, it validates the source plan first and cross-checks plan id, candidate counts/classes/bytes, exclusions, confirmation phrase, and future execution contract consistency; without `--plan-dir`, it records `plan_cross_check_status=not_requested`. `--out` writes validation artifacts only. No archive is created, no source is copied/moved/modified/deleted, source receipt/plan directories are not modified, and future execution remains unavailable.

The execution-readiness gate is the final read-only evidence-chain report before any future archive mutation lane exists:

```bash
python3 scripts/docker01_artifact_archive_plan.py --execution-readiness /tmp/sfai-pr235-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr235-artifact-archive-dry-run --json
python3 scripts/docker01_artifact_archive_plan.py --execution-readiness /tmp/sfai-pr235-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr235-artifact-archive-dry-run --out /tmp/sfai-pr235-artifact-archive-readiness --json
```

It validates the plan and dry-run receipt chain, optionally consumes prior receipt-validation output, cross-checks plan id, candidates, exclusions, confirmation phrase, future contract, and safety flags, and writes readiness report artifacts only when `--out` is supplied. `ready_for_execution_review` is human-review evidence for a future separate PR/lane only; execution remains unavailable. No archive creation, source copy/move/delete/modify, cleanup/prune/delete/restart, remediation/rollback/recovery, Docker/Compose mutation, helper-triggered validation/pytest/QA, natural-language execution, or `shell=True` is allowed. SeedOfEvil remains final merge owner.


### Docker01 artifact archive bundle validation

PR237 adds a read-only validator for PR236 copy-only archive bundles:

```bash
python3 scripts/docker01_artifact_archive_plan.py --validate-archive-bundle /tmp/sfai-pr237-artifact-archive-bundle --json
python3 scripts/docker01_artifact_archive_plan.py --validate-archive-bundle /tmp/sfai-pr237-artifact-archive-bundle --plan-dir /tmp/sfai-pr237-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr237-artifact-archive-dry-run --json
python3 scripts/docker01_artifact_archive_plan.py --validate-archive-bundle /tmp/sfai-pr237-artifact-archive-bundle --out /tmp/sfai-pr237-artifact-archive-bundle-validation --json
```

The validator checks the archive receipt, manifest, checksums, payload files, source-preservation metadata, safety flags, and optional plan/dry-run receipt cross-checks. It never creates an archive, copies sources, moves sources, deletes sources, authorizes cleanup, runs cleanup/prune/delete/restart/remediation/rollback/recovery, or performs Docker/Compose mutation. `future_cleanup_eligible_for_review=true` is evidence for future human review only; source deletion/move remains out of scope and would require a separate PR/lane with a new confirmation. `--out` writes validator artifacts only (`artifact-archive-bundle-validation.json`, summary, manifest, checksums). SeedOfEvil remains final merge owner.

### Docker01 artifact archive eligibility review

The artifact archive helper includes a read-only archive eligibility review:

```bash
python3 scripts/docker01_artifact_archive_plan.py --archive-eligibility-review /tmp/sfai-pr238-artifact-archive-bundle --plan-dir /tmp/sfai-pr238-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr238-artifact-archive-dry-run --json
```

This lane validates archive-bundle evidence, source-preservation metadata, the source plan, and the dry-run receipt, then uses read-only stat checks to classify archived candidates for future review. It never deletes, moves, modifies, or copies sources; never creates archives; never runs cleanup/prune/delete/restart/remediation/rollback/recovery; and never mutates Docker/Compose. `eligible_for_review` is not cleanup authorization, and `cleanup_available=false` remains explicit. Future cleanup requires a separate PR/lane, new confirmation phrase, dry-run deletion manifest, fresh source recheck, operator review, and SeedOfEvil final merge ownership.

### Docker01 archive-backed source-action dry run

The artifact archive helper can produce a read-only, archive-backed source-action dry-run manifest after a governed archive bundle and archive eligibility review exist:

```bash
python3 scripts/docker01_artifact_archive_plan.py --archive-source-action-dry-run /tmp/sfai-pr239-artifact-archive-bundle --plan-dir /tmp/sfai-pr239-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr239-artifact-archive-dry-run --archive-eligibility-review /tmp/sfai-pr239-artifact-eligibility-review --plan-id sha256:<plan-id> --json
python3 scripts/docker01_artifact_archive_plan.py --archive-source-action-dry-run /tmp/sfai-pr239-artifact-archive-bundle --plan-dir /tmp/sfai-pr239-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr239-artifact-archive-dry-run --archive-eligibility-review /tmp/sfai-pr239-artifact-eligibility-review --plan-id sha256:<plan-id> --out /tmp/sfai-pr239-source-action-dry-run --json
```

This lane validates the archive bundle, plan, dry-run receipt, and PR238 archive eligibility review, then cross-checks exact plan id, archive receipt, candidate manifests, source paths, classes, bytes, payload files, checksums, source-preservation metadata, and eligibility status. It stats candidate source paths read-only and classifies each candidate as `would_review_for_source_action`, `blocked`, `warning`, or `unknown`. `ready_for_source_action_review` means reviewable by a human in a future separate PR/lane; it does not authorize cleanup, source deletion, source movement, or any executable action, and `source_action_available=false` remains explicit.

With `--out`, the helper writes dry-run report artifacts only: `archive-source-action-dry-run.json`, `archive-source-action-dry-run-summary.md`, `candidate-source-action-manifest.json`, `future-source-action-checklist.md`, `safety-notes.md`, `manifest.json`, and `checksums.json`. It does not modify the archive bundle, plan, dry-run receipt, eligibility review, or source artifacts; does not create archives; does not copy/move/delete/modify sources; and does not run cleanup/prune/delete/restart/remediation/rollback/recovery, Docker/Compose mutation, validation, pytest, QA, model/Codex, network, GitHub, package install, or cloud apply/merge/push behavior. Future source action remains a separate confirmation-gated PR/lane using `CONFIRM_SHELLFORGEAI_SOURCE_ACTION_AFTER_ARCHIVE`; SeedOfEvil remains final merge owner.

### Docker01 archive source-action dry-run validation

The archive helper can validate a previously written source-action dry-run packet without making it executable:

```bash
python3 scripts/docker01_artifact_archive_plan.py --validate-archive-source-action-dry-run /tmp/sfai-pr240-source-action-dry-run --json
python3 scripts/docker01_artifact_archive_plan.py --validate-archive-source-action-dry-run /tmp/sfai-pr240-source-action-dry-run --archive-bundle /tmp/sfai-pr240-artifact-archive-bundle --plan-dir /tmp/sfai-pr240-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr240-artifact-archive-dry-run --archive-eligibility-review /tmp/sfai-pr240-artifact-eligibility-review --out /tmp/sfai-pr240-source-action-dry-run-validation --json
```

The validator checks the PR239 dry-run JSON, candidate manifest, manifest, checksums, read-only/source-action-unavailable contract, safety flags, source stats, and optional archive bundle, plan, dry-run receipt, and eligibility review evidence chain. `passed` means the packet is human-reviewable for a future separate lane only; it does not authorize source action and `source_action_available=false` remains explicit. With `--out`, it writes `archive-source-action-dry-run-validation.json`, `archive-source-action-dry-run-validation-summary.md`, `candidate-source-action-validation.json`, `future-source-action-review-checklist.md`, `safety-notes.md`, `manifest.json`, and `checksums.json` only. The validator does not create archives, copy/move/delete/modify sources, run cleanup/prune/delete/restart/remediation/rollback/recovery, mutate Docker/Compose, invoke validation/pytest/QA, use natural-language execution or `shell=True`, call model/Codex/network/GitHub, install packages, or apply cloud changes. Future source action remains a separate PR/lane requiring `CONFIRM_SHELLFORGEAI_SOURCE_ACTION_AFTER_ARCHIVE`; SeedOfEvil remains final merge owner.


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

## Archive/source-action runbook consolidation lane

Archive/source-action operator runbook updates, including `docs/ARCHIVE_SOURCE_ACTION_RUNBOOK.md`, fit Lane A when they only change docs and docs/golden tests. The runbook consolidates the PR239-PR244 evidence chain for operator review and does not add a new execution command. The archive/source-action status chain remains non-executable: after the existing confirm-gated copy-only archive bundle creation runway, source-action dry-run, validation, review packet, decision receipt, readiness gate, and status report commands are read-only/reporting only.

Expected checks are `ruff check .`, `python -m compileall -q scripts tests`, the PR-specific docs/golden test, the existing PR242-PR244 source-action status-chain tests, command-surface guardrails, and mutation-refusal guardrails. Full pytest is not required for this docs/test lane unless non-documentation runtime behavior changes.

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

## Docker01 build path diagnostic lane

For the Docker/LXC build-path symptom seen during PR247/PR248, where image build progress can hang around the Dockerfile `chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai` layer, use the standalone Docker01 build path diagnostic before considering any infrastructure or Dockerfile change:

```bash
python3 scripts/docker01_build_path_diagnostic_report.py --json
python3 scripts/docker01_build_path_diagnostic_report.py --dockerfile /srv/compose/shellforgeai/Dockerfile --json
python3 scripts/docker01_build_path_diagnostic_report.py --dockerfile /srv/compose/shellforgeai/Dockerfile --out /tmp/sfai-build-path-diagnostic --json
```

This is a targeted/default-lane evidence capture helper. Docker01 Compose uses an external Dockerfile path at `/srv/compose/shellforgeai/Dockerfile`; pass it with `--dockerfile` when checking the real Docker01 build path. The helper is read-only, does not run Docker/Compose, does not remediate, and does not perform cleanup, restart, prune, package install, chown, chmod, rollback, or recovery. It does not fix the chown-layer hang. With `--out <diagnostic_report_dir>` it writes only report artifacts into an empty operator-supplied directory. Future Dockerfile/build remediation must be a separate PR.

The manual fallback validation-container guidance still applies: install the expected disposable-container baseline such as `procps`, `git`, and `rsync`, rerun the narrow missing-tool check, and avoid duplicate full pytest churn. Full pytest should run once only when the change scope requires it.

## Docker01 build path ownership proposal lane

The Docker01 build path ownership proposal helper is a targeted/default
read-only lane when only `scripts/docker01_build_path_ownership_proposal.py`, its
tests, and docs change:

```bash
python3 scripts/docker01_build_path_ownership_proposal.py --dockerfile /srv/compose/shellforgeai/Dockerfile --json
python3 scripts/docker01_build_path_ownership_proposal.py --dockerfile /srv/compose/shellforgeai/Dockerfile --diagnostic <diagnostic_report_dir> --out <proposal_report_dir> --json
```

It follows the PR249 Docker01 build path diagnostic report and may consume that
report for cross-checking. The proposal helper is read-only and proposal only: it
scans the explicit external Dockerfile path, reports `chown -R` ownership risks,
and explains safer future patterns. It does not edit Dockerfile, does not run
Docker or Docker Compose, does not run build/chown/chmod/chgrp/package install,
and does not remediate. Future Dockerfile/build remediation must be a separate
PR or operator-reviewed change. This lane should not cause duplicate full pytest;
full pytest should run once only if the change broadens into shared runtime,
Dockerfile/Compose/deploy, or safety machinery.

## Docker01 build path ownership patch preview lane

The Docker01 build path ownership patch preview helper is a targeted/default read-only lane when only `scripts/docker01_build_path_patch_preview.py`, its tests, and docs change:

```bash
python3 scripts/docker01_build_path_patch_preview.py --dockerfile /srv/compose/shellforgeai/Dockerfile --json
python3 scripts/docker01_build_path_patch_preview.py --dockerfile /srv/compose/shellforgeai/Dockerfile --out <patch_preview_dir> --json
python3 scripts/docker01_build_path_patch_preview.py --proposal <ownership_proposal_dir> --out <patch_preview_dir> --json
```

It follows the PR249 Docker01 build path diagnostic report and PR250 ownership proposal report. The helper scans the explicit external Dockerfile path, reports broad `chown -R` ownership risks, emits a review-only diff/preview Dockerfile under an empty explicit output directory, and statically verifies that the preview removes broad recursive ownership over `/data`, `/home/appuser/.codex`, and `/opt/shellforgeai`. This is patch preview only: it does not edit Dockerfile, does not edit Compose, does not run Docker/Compose/build/chown/chmod/chgrp/package install, and does not remediate. Future Dockerfile/build remediation must be a separate PR or operator-reviewed change. This lane should not cause duplicate full pytest; full pytest should run once only if the change broadens into shared runtime, Dockerfile/Compose/deploy, or safety machinery.

## Docker01 build path ownership patch rehearsal lane

The Docker01 build path ownership patch rehearsal helper is a targeted/default artifact-only lane when only `scripts/docker01_build_path_patch_rehearsal.py`, its tests, and docs change:

```bash
python3 scripts/docker01_build_path_patch_rehearsal.py --dockerfile /srv/compose/shellforgeai/Dockerfile --patch-preview <patch_preview_dir> --out <patch_rehearsal_dir> --json
python3 scripts/docker01_build_path_patch_rehearsal.py --dockerfile /srv/compose/shellforgeai/Dockerfile --preview-dockerfile <path/to/dockerfile-ownership-preview.Dockerfile> --out <patch_rehearsal_dir> --json
```

It follows the PR249 diagnostic, PR250 ownership proposal, and PR251 patch preview. The helper consumes the review-only preview Dockerfile/diff artifacts, writes copied rehearsal Dockerfile/diff/report artifacts only under an empty explicit output directory, proves the original Dockerfile SHA256 is unchanged, and statically verifies that the rehearsed artifact removes broad recursive ownership over `/data`, `/home/appuser/.codex`, and `/opt/shellforgeai`. This is patch rehearsal only: it does not edit Dockerfile, does not edit Compose, does not run Docker/Compose/build/chown/chmod/chgrp/package install, and does not remediate. Future Dockerfile/build remediation must be a separate PR or operator-reviewed change. This lane should not cause duplicate full pytest; full pytest should run once only if the change broadens into shared runtime, Dockerfile/Compose/deploy, or safety machinery.

## Docker01 ownership candidate lane

Repository-owned Docker01 ownership candidate changes (`ops/docker/Dockerfile.docker01.ownership-candidate`, its README, and `scripts/docker01_build_path_candidate_verify.py`) fit the targeted/default validation lane when they remain static and review-only. The verifier reads only the candidate and an optional explicitly supplied source Dockerfile, writes reports only under `--out`, and does not edit the external Docker01 Dockerfile, edit Compose, run Docker/Compose/build, run ownership commands, install packages, clean up, prune, restart, remediate, roll back, or recover.

Use the PR-specific verifier tests plus the related PR250/PR251/PR252 build-path tests and command-surface/mutation-refusal guardrails. Docker01 build-path investigation alone should not trigger duplicate full pytest; reserve one full run only for broad runtime, deploy, command-surface policy, or shared safety machinery changes.

## Docker01 ownership handoff packet lane

Docker01 ownership handoff packet changes (`scripts/docker01_build_path_ownership_handoff_packet.py`, its tests, and focused docs) fit the targeted/default validation lane when they remain read-only/report-only. The helper reads only the explicitly supplied source Dockerfile, repository-owned candidate, and optional candidate-verification artifacts; writes only handoff/report artifacts under an empty explicit `--out`; and does not edit `/srv/compose/shellforgeai/Dockerfile`, edit Compose, run Docker/Compose/build, run ownership commands, install packages, clean up, prune, restart, remediate, roll back, or recover.

Use the PR-specific handoff-packet tests plus PR253/PR252/PR251 build-path regressions and command-surface/mutation-refusal guardrails. Any actual Dockerfile/build remediation must be a separate PR or operator-reviewed change. Docker01 build-path investigation alone should not trigger duplicate full pytest; reserve one full run only for broad runtime, deploy, command-surface policy, or shared safety machinery changes.
