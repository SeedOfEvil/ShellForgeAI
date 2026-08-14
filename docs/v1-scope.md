# V1 Scope and Release Contract

ShellForgeAI V1 is released. V1 is the released foundation, not the complete product trajectory described by the [North Star](north-star.md). Linux/Docker is the primary supported V1 lane; Windows remains validated preview/early support.

## V1 operator contract

The released core supports an evidence-backed path from observation to handoff:

- bounded typed Linux/Docker evidence collection and provenance;
- deterministic assessment, suspect ranking, and diagnosis;
- optional evidence-grounded model synthesis;
- operator plans and recommended procedures;
- validation of prerequisites, verification criteria, and rollback/recovery guidance without executing the recommendation;
- saved reports, history, comparison, exports, and handoff artifacts.

## V1 core capabilities

Core surfaces include `doctor`, `model doctor`, `status`, `diagnose`, `triage docker`, `ask`, `ops report`, `plan`, `apply` validation, `verify`, `handoff`, `audit`, `tools`, `inspect`, and `model`. The auditable inventory and classifications are in [V1 Command Surface](V1_COMMAND_SURFACE.md).

Canonical safe examples include `shellforgeai ops report`, `shellforgeai ops report --save`, `shellforgeai ops report history`, `shellforgeai ops report compare-latest`, `shellforgeai triage docker detail <target>`, `shellforgeai remediation eligibility --target <target> --explain`, and `shellforgeai remediation self-test --profile quick`.

## Mutation boundaries

- Read-only by default.
- Natural-language mutation requests are deterministically refused.
- `apply` remains validation-only in the alpha workflow.
- Governed mutation lanes are explicit, gated compatibility/testing surfaces outside the primary recommended workflow.
- Production mutation is not part of the V1 release promise; there is no autonomous production remediation.

Existing confirm-gated execute and recovery utilities remain available under their narrow target, approval, policy, current-state, verification, and receipt contracts. Their existence does not authorize arbitrary shell or model-directed execution.

## Release acceptance

V1 acceptance preserves evidence-first routing, deterministic slash-command behavior, safe command compatibility, artifact validation, Linux/Docker release checks, and truthful Windows preview labeling. See the [release candidate checklist](V1_RELEASE_CANDIDATE.md), [Safety](safety.md), and [V1 validation](V1_VALIDATION.md).
