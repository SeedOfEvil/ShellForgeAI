# Changelog

All notable changes to ShellForgeAI are documented in this file.

## [Unreleased]

### Docker01 QA bundle validate/history/compare lifecycle (PR207)

- Extended `scripts/docker01_operator_qa_bundle.py` with four **artifact-only**
  lifecycle modes that make PR206 bundles validateable, discoverable, and
  comparable without re-running smoke QA or mutating Docker01:
  `--validate-bundle <dir>` (structure + internal-consistency + manifest
  integrity, reporting `valid`/`warning`/`invalid`), `--history --root <dir>`
  (discover/filter bundles by `--pr`/`--commit`/`--status`/`--limit`, newest
  first), `--compare <old> <new>` and `--compare-latest --root <dir> --pr <PR>`
  (classify deltas as `regressed`/`improved`/`changed`/`same`, or
  `not_enough_bundles`/`invalid`). The original PR206 generation command forms
  are unchanged.
- Newly generated bundles now include a `bundle-manifest.json` (size + sha256 of
  `qa-summary.md`, every top-level JSON file, and each `raw/*` output) so later
  integrity/tamper checks are possible. **Legacy PR206 bundles without a manifest
  remain valid** — validation falls back to structural checks and adds a warning.
- Validation treats a scoped validation `not_found` as clean evidence-of-absence
  (valid when it belongs to the requested PR/commit and does not claim
  `pass_eligible=true`) and surfaces `scope_matched=false` as a warning, never as
  current passing evidence.
- Lifecycle modes are read-only and **use no subprocess at all**: they only read
  bundle files, parse JSON, list directories under the chosen root, and compute
  hashes. They never run ShellForgeAI/Docker/`validation_status.py`, never mutate
  or delete/repair bundles, never restart/prune anything, and never call the
  network. New coverage in `tests/test_pr207_qa_bundle_lifecycle.py`; PR206 tests
  remain green.

### Fallback packet non-execution contract + Lane B QA marker (PR180)

- Added durable regression coverage (`tests/test_pr180_fallback_packet_safety.py`)
  that locks down the PR179 disposable validation-container fallback packet
  contract: on missing host tooling (`ruff`/`pytest`) the generator reports a
  `setup_failure`, writes an **inert** packet (the container command exists only
  as an argv list / copy-paste string inside the packet object), and never
  auto-executes it. The tests prove no subprocess/shell execution path is
  triggered (static import check plus monkeypatched `subprocess`/`os.system`
  boundaries), and assert no cleanup/remediation/rollback/recovery/restart, no
  Docker/Compose mutation, no package install, no `shell=True`, no artifact
  repair/delete, and no model call.
- `scripts/validation_status.py` now emits an explicit Lane A/B/C QA marker
  (`qa_marker`) in its JSON and human output, derived read-only from the
  manifest lane evidence: `validation_lane`, `validation_scope`,
  `full_pytest_run`, `full_pytest_reason`, and `fallback_packet_present`. This
  makes targeted-only Lane B validation legible to reviewers (full `pytest`
  intentionally not run) without re-deriving lane policy. The viewer remains
  read-only — no execution, no mutation, no model call.

### Validation environment preflight (PR178)

- Added the read-only validation environment preflight
  `scripts/validation_env_preflight.py` (human and strict `--json` modes). It
  checks Python executable/version, `ruff`, `pytest`, `pytest-xdist` (warning
  unless required), `shellforgeai` importability (spec lookup only), presence of
  the validation helper scripts, artifact-directory write access, and a
  heartbeat/status JSON probe write — availability/presence only; it never
  installs packages, never modifies venvs/host Python, never runs `pytest` or
  `ruff check`, never runs a subprocess, and never calls Docker/Compose.
- `scripts/sfai_docker01_pr_lane.py` now runs this preflight as an
  `environment_preflight` phase before ruff/compileall/pytest when
  `--execute-validation` is used (plus standalone `--preflight-only` /
  `--preflight-output`). A failed preflight stops before any validation phase
  and writes setup-failure evidence (`status=failed`,
  `classification=setup_failure`, `failed_phase=environment_preflight`,
  `pass_eligible=false`, `rerun_required=true`) including the preflight JSON;
  warning-only preflights continue with warnings preserved as non-blockers.
  Setup failure is never reported as product test failure, never as a pass, and
  is not merge evidence.
- `scripts/validation_status.py` now summarizes preflight setup failures
  (including a run dir with only a failed preflight report), preserves stored
  `setup_failure` classifications instead of misreading them as incomplete,
  lists the preflight evidence file, and points its first safe command at the
  preflight for setup failures. Recommended fix remains the disposable
  validation container path or preparing dev dependencies outside ShellForgeAI
  (recommendation text only; nothing is executed).
- Documentation: `docs/VALIDATION_LANES.md`, `docs/VALIDATION_MATRIX.md`,
  `OPS.md`, `README.md`, `docs/roadmap.md`. Process/evidence tooling only — no
  runtime recipe execution behavior change, no package installation, no
  cleanup/remediation/rollback/recovery execution, no Docker/Compose/service/
  container mutation, no restart, no `shell=True`, no arbitrary command
  execution, no natural-language execution, and no model call.

### Validation heartbeat and interrupted-run evidence (PR176)

- Added `scripts/validation_heartbeat.py` and wired heartbeat/checkpoint/status
  JSON into `scripts/sfai_docker01_pr_lane.py` and `scripts/run_full_pytest.py`.
  Long Docker01/full-validation runs that are SIGTERM/SIGINT/timeout-interrupted
  (or SIGKILLed) now leave clear partial evidence instead of a silent false pass:
  the heartbeat is updated before/after each phase with `active_phase`,
  `last_completed_phase`, and per-phase `phase_status`.
- Manifest/summary now carry an explicit `status`
  (`passed`/`failed`/`incomplete`), `classification`
  (`passed`/`test_failure`/`setup_failure`/`interrupted_or_incomplete`),
  `pass_eligible`, `rerun_required`, `full_pytest_exit_code`, and
  `full_pytest_result`. `status=passed` is recorded only when a full-`pytest`
  exit code of `0` is captured; an interrupted run is `incomplete` /
  `pass_eligible=false` / `rerun_required=true` with a `*** RERUN REQUIRED ***`
  human summary and is never merge evidence (a clean rerun is required).
- Documentation: `docs/VALIDATION_LANES.md`, `OPS.md`, `docs/roadmap.md`. Process/
  tooling and validation-evidence only — no runtime recipe execution behavior
  change, no cleanup/remediation/rollback/recovery execution, no
  Docker/Compose/service/container mutation, no restart, no `shell=True`, no
  arbitrary command execution, no natural-language execution, and no model call.

### Validation lanes (PR157)

- Added the validation-lane optimizer `scripts/validate_pr.py` and the test
  impact map `scripts/validation_matrix.json`: changed-file patterns map to a
  validation lane (Lane A fast / Lane B targeted_runtime / Lane C full),
  recommended regression tests, exact commands, an explicit
  `full_pytest_required` answer with reason, and an estimated runtime class.
- Targeted validation is now the documented default; full `pytest` is
  exceptional. Execution/safety/packaging boundaries and safety keywords in
  changed code still escalate to Lane C (`pytest -q --durations=25`).
- Documentation: `docs/VALIDATION_LANES.md`, `docs/VALIDATION_MATRIX.md`, and an
  OPS PR-lane policy. The helper is planning/dry-run only — no mutation,
  Docker/Compose, remediation/rollback/cleanup/restart, `shell=True`, or
  arbitrary command execution; `--execute` runs only the recommended
  `ruff`/`compileall`/`pytest` commands.

## [1.0.0] - 2026-05-26

### V1 release cut: Keep It a Knife, Not a Toolbox

- Declared ShellForgeAI V1 baseline as a **CLI-first Linux/Docker operator knife** focused on read-only inspection, deterministic routing, evidence-backed reports, and governed mutation boundaries.
- Published final V1 release notes and handoff packet guidance for operator/admin sign-off.
- Linked release documentation from README, roadmap, and ops handoff docs.
- Added PR120 release-doc contract tests to keep V1 scope/safety wording stable.

### Validation summary (human)

- Docker01 container healthy during release-candidate validation.
- V1 quick/standard checks passed.
- Ops report artifact lifecycle passed (save/validate/export/export-validate/history/compare-latest).
- Deterministic 2AM ask route passed.
- Deterministic mutation refusal passed.
- Remediation self-test full passed.
- Packet/export validation passed in dev-validation lane.
- Targeted/regression tests passed.
- Safety invariants held (no casual mutation paths).
