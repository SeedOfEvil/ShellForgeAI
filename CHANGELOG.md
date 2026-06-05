# Changelog

All notable changes to ShellForgeAI are documented in this file.

## [Unreleased]

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
