# Roadmap

This active roadmap is forward-looking and organized by operator outcomes, not PR chronology. [Product Status](PRODUCT_STATUS.md) owns current maturity, [V1 Scope](v1-scope.md) owns the released V1 contract, [Safety](safety.md) owns current safety and mutation rules, and this roadmap owns staged delivery. The permanent product contract is defined in [North Star](north-star.md).

## Current product

V1 is released and early beta-quality. Linux/Docker is the primary supported V1 lane; Windows is validated preview/early support. Evidence collection, deterministic triage, evidence-grounded synthesis, reports, validation surfaces, and handoffs provide the current foundation. Existing governed execution/remediation commands remain bounded compatibility/testing surfaces outside the primary recommended workflow. The PR143 command surface audit remains the current classification reference.

## Outcome workstream: dependable observation

- Maintain platform-aware routing and bounded typed collectors.
- Preserve provenance, explicit unavailable states, and deterministic unsupported-platform behavior.
- Improve evidence continuity without creating hidden background control or unbounded memory.

## Outcome workstream: evidence-backed diagnosis

- Strengthen deterministic assessment, ranking, and confidence communication.
- Keep facts, inferences, model synthesis, and unknowns visibly distinct.
- Expand supported operator intents only with evidence-first routing.

## Outcome workstream: operator-ready solutions

- Generate specific plans and recommendations with prerequisites, impact, ordered procedures, decision points, and alternatives.
- Validate procedure coherence, verification criteria, and rollback/recovery guidance without executing recommendations.
- Keep model synthesis grounded in the evidence bundle and deterministic assessment.

## Outcome workstream: reports and handoff

- Make reports and handoff packets concise, portable, comparable, and useful across shifts or reviewers.
- Preserve provenance, limitations, remaining risk, and safe next steps.
- Keep artifact validation deterministic and auditable.

## Outcome workstream: platform confidence

- Keep Linux/Docker as the released V1 core and validation basis.
- Mature Windows from validated preview/early support through parity evidence and operator acceptance.
- Fail closed on unsupported operational routes without weakening help or plain conversation.

## Outcome workstream: governed compatibility surfaces

- Preserve confirm-gated execution/remediation utilities for bounded compatibility and testing needs.
- Keep capability, target identity, approval, current-state, scope, verification, receipt, and recovery gates explicit.
- Avoid generic mutation machinery and do not move these utilities into the primary recommended workflow.

## Delivery policy

Documentation-contract tests protect canonical ownership and product truth without changing runtime behavior. New work should improve a named operator outcome, preserve the evidence-first and safety boundaries, and avoid PR-numbered roadmap narration. Historical implementation chronology stays in [Project history](archive/PROJECT_HISTORY.md).
