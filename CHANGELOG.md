# Changelog

All notable changes to ShellForgeAI are documented in this file.

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
