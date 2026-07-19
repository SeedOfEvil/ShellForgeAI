# Roadmap

ShellForgeAI's active roadmap is forward-looking. The permanent final-state product contract is defined in [North Star](north-star.md). Historical PR-by-PR engineering chronology has moved to [Project history archive](archive/PROJECT_HISTORY.md).

## Current product

- V1 released; early beta-quality; guarded and not production-autonomous.
- Linux/Docker is the primary supported V1 lane and release-validation basis.
- Windows is preview/early support for local read-only evidence, deterministic operator guidance, and validated Windows Server 2025 workflows.
- Current capabilities include evidence collection, deterministic triage, reports, previews, approval metadata, verification, receipts, and narrow governed proof/testing lanes.
- The maintained PR143 command surface audit remains the active command-surface classification reference for current interface hygiene.
- The complete final-state lifecycle is not yet implemented across arbitrary operator-developed solutions.

## Stage A — Product contract

- Establish the canonical lifecycle and final-state implementation boundary in [North Star](north-star.md).
- Keep document ownership clear: Product Status owns current maturity, V1 Scope owns the released V1 contract, Safety owns current safety and mutation rules, and this Roadmap owns staged delivery.
- Add a documentation drift guard without changing runtime behavior.

## Future Stage B — Approved change contract

- Define an exact, reviewable approved-solution representation.
- Capture target, scope, impact, ordered procedure, precondition/current-state gates, verification criteria, rollback or recovery awareness, audit requirements, and unsupported aspects.
- Preserve stable identity after approval so approval applies to that exact solution only.

This stage describes the desired outcome only; it does not design schemas, files, classes, commands, receipts, executors, or a mutation engine.

## Future Stage C — First narrow end-to-end implementation lane

- Choose one deliberately narrow supported solution type.
- Prove Understand through Report for that solution type.
- Require explicit approval, bounded implementation, fresh verification evidence, and a receipt.
- Avoid generic mutation machinery and avoid selecting additional solution types by implication.

## Future Stage D — Controlled capability expansion

- Add supported implementation capabilities solution type by solution type.
- Require typed inputs, scope limits, gates, verification, reporting, receipts, and tests for each capability.
- Keep arbitrary shell, natural-language execution, and broad infrastructure orchestration out of scope.
- Preserve ShellForgeAI as a focused operator product rather than a general infrastructure platform.

## Final state

ShellForgeAI remains one CLI-first operator interface with the complete lifecycle: Understand → Investigate → Diagnose → Propose → Obtain approval → Implement → Verify → Report. It can implement approved bounded changes through supported capabilities, verify outcomes with fresh evidence, and report facts, receipts, and remaining risk without becoming a dashboard, control plane, generic shell, or broad orchestration platform.
