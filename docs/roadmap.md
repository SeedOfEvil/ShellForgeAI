# Roadmap

ShellForgeAI's active roadmap is forward-looking. Historical PR-by-PR engineering chronology has moved to [Project history archive](archive/PROJECT_HISTORY.md).

## Current

- V1 released; early beta-quality; guarded and not production-autonomous.
- Linux/Docker is the primary supported V1 lane and release-validation basis.
- Windows is preview/early support for local read-only evidence, deterministic operator guidance, and validated Windows Server 2025 workflows.
- Repository validation baseline is green for the focused maintained lanes used by recent documentation and command-surface work.
- The operator-control model remains central: evidence first, read-only by default, named bounded workflows, explicit confirmation, verification, receipts, and audit trails.

## Near term

- Decide the Windows durable-runtime reconciliation path after the current validation-only preflight and acceptance helpers.
- Improve packaging and install documentation so operators have fewer source-checkout steps.
- Simplify operator UX around the 2AM status → triage → propose → apply-preview → verify → handoff path.
- Continue documentation and release hygiene so product status, platform maturity, validation evidence, and historical chronology stay separated.

## Later

- Expand platform evidence only where collectors remain local, read-only, bounded, and testable.
- Deepen receipt, audit, and comparison workflows for operator handoffs.
- Explore optional read-only integration surfaces without changing the runtime safety boundary.
- Keep production autonomy out of scope unless a future explicitly reviewed safety model replaces the current operator-controlled contract.
