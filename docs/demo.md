# 5-Minute Linux/Docker Operator Demo (V1)

## What this demo proves

- ShellForgeAI can inspect a Linux/Docker scene safely with read-only defaults.
- The V1 command spine is real, current, and evidence-first.
- Operator artifacts can be produced, saved, compared, and handed off.
- Deterministic ask routing can summarize incidents and refuse mutation.

## What this demo does not do

- It does not restart production services.
- It does not run `shellforgeai remediation execute --confirm` (gated/non-goal for this demo).
- It does not run `shellforgeai remediation rollback-execute --confirm` (gated/non-goal for this demo).
- It does not run `shellforgeai audit cleanup execute --confirm` (metadata cleanup is governed and gated).
- It does not run Docker Compose mutation (`docker compose restart/up/down`) in this gated non-goal demo path.
- It does not require secrets, external internet, or a web UI.

## Prerequisites

- Disposable Linux/Docker environment.
- ShellForgeAI installed.
- Fixture containers (or equivalent suspects):
  - `sfai-crashloop`
  - `sfai-bad-http` (bad HTTP)
  - `sfai-disk-pressure` (disk pressure)
  - `sfai-noisy-errors`
  - `sfai-permission-denied` (permission denied)

## 5-minute path

```bash
shellforgeai version
shellforgeai doctor
shellforgeai model doctor
shellforgeai v1 check --profile quick
shellforgeai v1 check --profile standard
shellforgeai remediation self-test --profile quick
shellforgeai ops report
shellforgeai ops report --json
shellforgeai ops report --save
shellforgeai ops report history --limit 5
shellforgeai ops report compare-latest
shellforgeai triage docker
shellforgeai triage docker detail sfai-crashloop
shellforgeai triage docker detail sfai-bad-http
shellforgeai triage docker detail sfai-disk-pressure
shellforgeai triage docker detail sfai-noisy-errors
shellforgeai triage docker detail sfai-permission-denied
shellforgeai remediation eligibility --target sfai-crashloop --explain
shellforgeai remediation eligibility --target sfai-noisy-errors --explain
shellforgeai ask "It's 2AM; what is on fire?"
shellforgeai ask "please restart shellforgeai"
```

## Expected suspects

Common ranking shape in a seeded lab:

- `sfai-crashloop` (critical)
- `sfai-bad-http` (bad HTTP) (high)
- `sfai-disk-pressure` (disk pressure) (high)
- `sfai-noisy-errors` (high)
- `sfai-permission-denied` (permission denied) (high/medium)

## Artifact handoff

Use saved reports as handoff-ready evidence:

- `shellforgeai ops report --save`
- `shellforgeai ops report history --limit 5`
- `shellforgeai ops report compare-latest`

Share the latest saved report plus compare output with the next operator.

## Mutation refusal demo

Run:

```bash
shellforgeai ask "please restart shellforgeai"
```

Expected behavior:

- deterministic refusal (no natural-language mutation)
- read-only alternatives (ops report, triage detail, eligibility explain)
- no restart, no cleanup execute, no remediation execute

## Cleanup / reset

- Keep artifacts for compare/export validation.
- If reset is needed, follow governed metadata workflows only.
- `shellforgeai remediation self-test --profile quick` is safe to rerun.

## Troubleshooting

- If provider/model checks fail, continue with deterministic read-only routes (`ops report`, `triage docker`, `ask` refusal paths).
- If suspects are missing, verify fixtures and rerun `shellforgeai ops report`.
- For release readiness confirmation, rerun:
  - `shellforgeai v1 check --profile quick`
  - `shellforgeai v1 check --profile standard`
