# V1 Release Candidate Checklist

## Purpose

This document is the V1 release-candidate gate for ShellForgeAI. Use it to
answer whether a build is V1-ready, blocked, or ready with caveats.

## V1 promise

ShellForgeAI V1 is a **CLI-first Linux/Docker operator knife**:

- Evidence-backed operator reports from typed read-only inspection.
- Report and packet artifacts that can be saved, validated, exported, and compared.
- Deterministic ask routing for common operator prompts.
- Deterministic refusal for natural-language mutation asks.
- Governed mutation only outside the casual V1 path and only behind explicit gates.

## What V1 includes

- `doctor` / `model doctor`
- `v1 check`
- `v1_validate.sh` helper
- `ops report`
- `ops report save/validate/export/history/compare/compare-latest`
- `triage docker` / `triage docker detail`
- `remediation eligibility` / `remediation explain`
- deterministic ask-to-report routing
- deterministic mutation refusal
- V1 packet save/validate/export/history/compare

## What V1 does not include

- production autonomous remediation
- broad Docker/Compose mutation
- arbitrary shell execution
- web UI
- secrets platform
- production cleanup execution by default
- natural-language mutation execution

## Required local/dev validation

Run all commands below from repo root:

```bash
ruff check .
python -m compileall -q src tests
pytest -q
./scripts/v1_validate.sh --quick
./scripts/v1_validate.sh --full
./scripts/v1_validate.sh --quick --packet
./scripts/v1_validate.sh --quick --export-packet
```

## Required Docker01 smoke validation

```bash
shellforgeai version
shellforgeai doctor
shellforgeai model doctor
shellforgeai v1 check --profile quick --json
shellforgeai v1 check --profile standard --json
shellforgeai ops report --json
shellforgeai remediation self-test --profile full --json
```

## Required deterministic ask validation

```bash
shellforgeai ask "It's 2AM; what is on fire?"
shellforgeai ask "please restart shellforgeai"
```

Expected results:

- First ask routes to read-only ops/triage reporting.
- Second ask refuses mutation and points to governed explicit CLI gates.

## Required artifact validation

```bash
shellforgeai ops report --save --json
shellforgeai ops report validate <report-id> --json
shellforgeai ops report export <report-id> --json
shellforgeai ops report export-validate <export-id> --json
shellforgeai ops report history --limit 5 --json
shellforgeai ops report compare-latest --json
shellforgeai v1 packet --save --json
shellforgeai v1 packet validate <packet-id> --json
shellforgeai v1 packet export <packet-id> --json
shellforgeai v1 packet export-validate <export-id> --json
```

## Safety invariants

Normal V1 validation paths must show all of the following:

- no remediation execute
- no rollback execute
- no cleanup execute
- no Docker Compose mutation
- no production restart
- no `shell=True`
- no arbitrary command execution
- no natural-language mutation

## Known acceptable caveats

- Historical metadata hygiene warning may exist in long-lived labs.
- Validation container must include expected tools (`procps`, `git`, `rsync`, dev deps).
- Runtime image may not include `pytest`/`ruff`.
- Battle-lab fixtures may remain intentionally broken for negative-path checks.

## Hard blockers

Any item below blocks V1 release:

- `shellforgeai version` fails.
- `v1 check` fails.
- `ops report` JSON is invalid.
- Mutation ask executes action instead of refusing.
- Production `shellforgeai` restarts unexpectedly.
- cleanup/remediation/rollback executes without explicit governed gates.
- full `pytest -q` fails.
- packet/export validation fails.

## Rollback / recovery note

If release-candidate validation regresses, stop promotion and return to the
last known-good PR/commit with passing V1 packet and smoke evidence. Re-run the
checklist from this document before any re-promotion decision.

## Merge/release decision criteria

A merge/release decision requires:

1. Required local/dev validation passes.
2. Required Docker01 smoke validation passes.
3. Required deterministic ask validation passes.
4. Required artifact validation passes.
5. Safety invariants remain true.
6. Any caveats are recorded in handoff with explicit operator acknowledgement.

## Docker01 handoff template

Copy/paste template:

```text
PR: #119
Commit: <commit-sha>
Image: <image-ref>
Snapshot: <snapshot-id-or-note>

Source/Image/Label Verification:
- source repo/branch/commit: <...>
- runtime image digest/tag: <...>
- expected labels (pr/commit/build): <...>

Smoke:
- shellforgeai version: PASS|FAIL
- shellforgeai doctor: PASS|FAIL
- shellforgeai model doctor: PASS|FAIL

Validation:
- v1 check quick: PASS|FAIL
- v1 check standard: PASS|FAIL
- local/dev validation command set: PASS|FAIL

V1 checks:
- deterministic ask-to-report: PASS|FAIL
- deterministic mutation refusal: PASS|FAIL

Artifact checks:
- ops report save/validate/export/export-validate: PASS|FAIL
- ops report history/compare-latest: PASS|FAIL
- v1 packet save/validate/export/export-validate: PASS|FAIL

Safety checks:
- no cleanup execute in normal path: PASS|FAIL
- no remediation execute in normal path: PASS|FAIL
- no rollback execute in normal path: PASS|FAIL
- no Docker/Compose mutation in normal path: PASS|FAIL
- no production restart: PASS|FAIL
- no shell=True/arbitrary command execution: PASS|FAIL
- no natural-language mutation execution: PASS|FAIL

Caveats:
- <none | list>

Verdict:
- V1-ready | V1-blocked | V1-ready with caveats
```

## Final V1 release sign-off

- Decision: **V1-ready** | **V1-blocked** | **V1-ready with caveats**
- Operator:
- Signature:
- Date:
