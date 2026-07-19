# North Star

This document is the canonical permanent final-state product contract for ShellForgeAI. Current maturity, current V1 scope, and current safety rules remain defined in [Product Status](PRODUCT_STATUS.md), [V1 Scope](v1-scope.md), and [Safety](safety.md); the staged path is tracked in [Roadmap](roadmap.md).

## Canonical final-state promise

ShellForgeAI is one interactive CLI that turns operator intent into an evidence-backed plan, procedure, solution, or fix and, after explicit operator approval, can safely implement that bounded change, verify the outcome, and report it.

Implementation is part of the final product promise, but only inside the operator-controlled lifecycle and implementation boundary defined here.

## Operator lifecycle

Understand → Investigate → Diagnose → Propose → Obtain approval → Implement → Verify → Report

1. **Understand:** establish the operator's intended outcome, target, urgency, and constraints.
2. **Investigate:** collect bounded, typed, current evidence before recommendation.
3. **Diagnose:** identify the likely cause and separate facts from uncertainty.
4. **Propose:** present the specific change, expected impact, procedure, preconditions, verification criteria, and rollback posture.
5. **Obtain approval:** receive explicit operator approval for that exact bounded change.
6. **Implement:** execute only through a supported implementation capability whose scope matches the approved proposal.
7. **Verify:** collect fresh evidence proving success, failure, partial success, inconclusive outcome, or changed conditions.
8. **Report:** state factually what was attempted, what changed, what did not change, verification results, receipts, and any remaining risk.

## What an approved change must contain

An executable approved change must identify, at minimum:

- the exact target;
- the desired outcome;
- the evidence and diagnosis supporting the proposal;
- the exact bounded proposed change;
- the expected impact and blast radius;
- the ordered procedure;
- prerequisites and current-state gates;
- approval identity or explicit confirmation;
- verification criteria;
- rollback or recovery awareness;
- audit and receipt requirements;
- unsupported or irreversible aspects.

PR308 defines no JSON schema, database object, CLI syntax, executor interface, or mutation engine for this contract.

## Implementation boundary

Implementation is part of the product promise. ShellForgeAI may implement only the specific solution it developed with the operator, represented as an exact, reviewable, explicitly approved, bounded, and auditable change.

Operator intent, free-form model output, or natural-language approval alone never becomes an executable command. Approval authorizes only a supported implementation capability whose target, scope, impact, procedure, preconditions, verification criteria, and rollback posture match the approved change.

Approval does not bypass capability support, safety gates, target identity, current-state checks, preconditions, state revalidation, scope limits, verification requirements, or audit requirements. Unsupported actions, changed targets, stale evidence, failed preconditions, expanded blast radius, or materially changed conditions block implementation and return the workflow to investigation or proposal.

This boundary does not authorize arbitrary shell, arbitrary PowerShell, arbitrary subprocesses, commands invented by a model, or open-ended natural-language execution.

## Verification and reporting

Implementation is never the final lifecycle stage. Fresh post-change evidence is required before ShellForgeAI reports an outcome. Verification may conclude success, failure, partial success, inconclusive, or blocked.

Reporting must distinguish observed facts from assumptions. The final report must identify the exact approved change, actions attempted, actions completed, verification results, artifacts or receipts, and remaining risk. ShellForgeAI must not claim success when verification is missing, stale, failed, or inconclusive.

Rollback and recovery awareness are permanent requirements. Reversible and irreversible effects must be identified, and a rollback or recovery procedure should be proposed where feasible. Automatic rollback is not guaranteed. Rollback itself requires support, validation, bounded scope, and approval where applicable.

## Permanent product boundaries

ShellForgeAI remains one CLI-first interactive operator product:

- no dashboard;
- no autonomous background control plane;
- no general-purpose shell;
- no arbitrary natural-language execution;
- no general-purpose remote administration product;
- no broad infrastructure orchestration or management platform;
- no competing user interface that fragments the operator lifecycle;
- no open-ended capability expansion through unrestricted plugins or model-generated execution;
- no implementation outside specifically supported solution types.

"One interactive CLI" means one coherent ShellForgeAI CLI product, including its interactive operator experience and supported deterministic subcommands. It does not require removing deterministic subcommands, and it does not authorize additional competing product interfaces.

ShellForgeAI may expand implementation capability one reviewed solution type at a time without becoming a general infrastructure platform.

## Current product versus final state

The North Star is a final-state contract, not a claim that every stage is universally implemented today. Current maturity remains defined by [Product Status](PRODUCT_STATUS.md): V1 released, early beta-quality, guarded, and not production-autonomous. Current released scope remains defined by [V1 Scope](v1-scope.md), and current safety and mutation rules remain defined by [Safety](safety.md).

V1 is the released foundation for the final lifecycle, not the complete final-state lifecycle across arbitrary operator-developed solutions.
