# 5-Minute Linux/Docker Operator Demo (V1)

This demo is for disposable battle-lab fixtures only. Do not use it as a
production remediation guide.

## Preconditions

- Disposable Linux/Docker environment.
- ShellForgeAI installed.
- Fixture containers present (or equivalent):
  - healthy baseline
  - crashloop (`sfai-crashloop`)
  - bad HTTP (`sfai-bad-http`)
  - disk pressure (`sfai-disk-pressure`)
  - noisy logs (`sfai-noisy-errors`)
  - permission denied (`sfai-permission-denied`)

## Demo steps

1. Run scene-level operator report:

   ```bash
   shellforgeai ops report
   ```

   Expected shape:
   - `sfai-crashloop` ranked critical
   - `sfai-bad-http` ranked high
   - `sfai-disk-pressure` ranked high
   - `sfai-noisy-errors` ranked high
   - `sfai-permission-denied` ranked high/medium

2. Drill into one suspect:

   ```bash
   shellforgeai triage docker detail sfai-crashloop
   ```

3. Check governed remediation eligibility (read-only gate check):

   ```bash
   shellforgeai remediation eligibility --target sfai-crashloop --explain
   ```

   Expected shape:
   - crashloop evidence is present
   - eligibility blocks unless allowlist labels are present
   - no mutation occurs

4. Preserve report artifact and inspect short history:

   ```bash
   shellforgeai ops report --save
   shellforgeai ops report history --limit 3
   shellforgeai ops report compare-latest
   ```

5. Optional deterministic ask route demo:

   ```bash
   shellforgeai ask "It's 2AM, what is on fire?"
   ```

   Expected:
   - deterministic ops-report path
   - no model/auth dependency for this route

6. Mutation refusal demo:

   ```bash
   shellforgeai ask "please restart shellforgeai"
   ```

   Expected:
   - deterministic refusal
   - no mutation
   - safe read-only alternatives

## Cleanup

- Keep artifacts for comparison/export validation, or clean up using the
  governed metadata cleanup workflow only (archive/validate/confirm gates).
- Do not run production restart/remediation commands from this demo.

- Optional gate: `shellforgeai v1 check --profile standard --json` before/after demo flow.
