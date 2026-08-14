# North Star

This is ShellForgeAI's canonical permanent product contract. [Product Status](PRODUCT_STATUS.md) owns current maturity, [V1 Scope](v1-scope.md) owns released scope, and [Safety](safety.md) owns current policy.

## Product promise

ShellForgeAI turns operator intent and current, typed evidence into an operator-ready solution and handoff through one coherent CLI product.

**Observe → Investigate → Diagnose → Plan → Recommend → Validate → Report → Handoff**

1. **Observe:** identify the target, desired outcome, urgency, and constraints.
2. **Investigate:** collect bounded typed evidence before recommendation and retain provenance.
3. **Diagnose:** distinguish observed facts, deterministic assessment, likely causes, and uncertainty.
4. **Plan:** define prerequisites, ordered procedure, expected impact, decision points, and blast radius.
5. **Recommend:** provide the best-supported solution and explain why it ranks above alternatives.
6. **Validate:** validate the recommendation and procedure, prerequisites, verification criteria, and rollback or recovery guidance. This stage does not execute the procedure.
7. **Report:** preserve evidence, diagnosis, recommendation, limitations, and remaining risk.
8. **Handoff:** give the operator or next reviewer an actionable, reviewable packet with safe next steps.

## Operator-ready solution contract

A complete recommendation identifies the exact target and desired outcome; evidence and provenance; diagnosis and uncertainty; prerequisites and current-state assumptions; expected impact and blast radius; ordered procedure and decision points; verification criteria; rollback or recovery guidance; limitations; and audit or handoff artifacts.

Validation evaluates whether that guidance is coherent, sufficiently evidenced, feasible for the stated environment, verifiable, and recoverable. It never implies that a recommendation was executed or that an outcome was verified.

## Reasoning and trust boundary

Platform routing selects supported typed collectors. Evidence and provenance feed deterministic assessment and ranking before evidence-grounded model synthesis. The model explains and composes guidance; ShellForgeAI's runtime executes collectors, and model output never becomes an executable command.

The primary workflow ends at operator handoff. Existing confirm-gated execute and remediation utilities remain bounded, governed compatibility/testing surfaces outside the primary recommended workflow. They require their existing explicit policy, approval, identity, current-state, scope, verification, and receipt gates and do not create general execution authority.

ShellForgeAI remains one coherent CLI product with supported deterministic subcommands: no dashboard, autonomous background control plane, general-purpose shell, arbitrary natural-language execution, broad infrastructure management platform, or competing interface.

## Current product relationship

This product contract is not a claim that every guidance capability has equal maturity today. V1 is the released foundation, not the complete product trajectory. Linux/Docker is the released core; Windows is validated preview/early support. Delivery priorities are tracked by outcomes in [Roadmap](roadmap.md).
