# Approved-change approval assertion recency

ShellForgeAI has one pure, deterministic, read-only policy authority for
classifying the recency of one exact PR353 approval-assertion age evaluation.
Its scope is deliberately narrow: it says whether the chronology of the
self-asserted `approved_at` timestamp falls within or outside a maintained age
window. It does not decide approval validity or authority.

## Fixed policy and exact boundary

The source-maintained window is exactly 24 hours. Its normative representation
is `86_400_000_000` integer microseconds (equivalently 86,400 seconds or
86,400,000 milliseconds). Callers cannot override this threshold.

The comparison uses only PR353's exact `age_microseconds`:

- `age_microseconds <= 86_400_000_000` is within the age window;
- `age_microseconds > 86_400_000_000` is outside the age window.

Exactly 24 hours is therefore within; 24 hours plus one microsecond is outside.
PR353's ceiling-millisecond presentation value never controls this boundary.

The frozen policy records this comparison basis, inclusive boundary rule,
trust labels, and recency-only scope. Its sorted, compact, UTF-8 canonical JSON
has a deterministic lowercase SHA-256 identity. Evaluation requires an explicit
confirmation of that identity; the policy is not configurable through a clock,
environment variable, or caller-supplied duration.

## Sole chronology authority and identity binding

PR353 remains the sole authority for validating and canonicalizing approval
assertion chronology. PR354 consumes one already-constructed
`ApprovedChangeApprovalAssertionAgeEvaluation`, validates it with the maintained
PR353 model, and recomputes its identity only with PR353's maintained SHA-256
authority. The caller must explicitly confirm that exact PR353 evaluation
identity before the fixed policy is constructed or evaluated. The maintained
PR354 policy identity must then also be explicitly confirmed. Both digest
confirmations use constant-time comparisons and fail closed.

Identity confirmation proves the exact PR353 evaluation bytes, not their
internal chronology truth by itself. Before applying the policy, PR354 parses
both canonical UTC timestamps and independently verifies that reference time is
not earlier than asserted time, their exact integer-microsecond delta equals
`age_microseconds`, and `age_milliseconds_ceiling` is the correct presentation
of that exact age. Contradictory facts receive no recency classification or
recency-evaluation identity; PR354 rejects rather than repairs them.

An eligible successful PR353 chronology must report its successful outcome,
`clock_consistent=true`, and a present, non-negative exact age. A PR353
`approval_assertion_clock_inconsistent` outcome receives the deterministic
`approval_assertion_recency_unavailable` status; PR354 does not clamp it to zero,
recompute it, or classify it as either within or outside the window.

Successful classification creates an immutable in-memory recency evaluation.
Its identity is independently computed as SHA-256 over its exact sorted,
compact, UTF-8 canonical JSON. The digest is non-circular: it is not included in
the canonical evaluation payload. Identical PR353 facts and the same maintained
policy produce the same identity; a relevant bound fact change produces a
different identity.

## Trust and safety boundary

`approved_at` remains `self_asserted_untrusted_assertion` metadata. The exact
persisted artifact commits to what timestamp was asserted, not when a real-world
approval occurred. The evaluator reference UTC already captured by PR353 remains
an `untrusted_local_system_clock`. Applying a fixed policy upgrades neither
trust domain, and no trusted-time authority is consulted.

“Within the age window” means only that this exact PR353 approval assertion
chronology falls within the maintained 24-hour window. It is not authenticated
approval, approval validity, authorization, or execution eligibility. “Outside
the age window” does not expire, revoke, cancel, delete, supersede, or mutate the
approval artifact.

PR354 performs no clock read, filesystem access, approval-artifact reload,
inventory or latest/current resolution, environment lookup, network access,
Windows API call, subprocess, shell, or model/provider call. It does not consume
PR319, PR352 identity provenance, PR304 evidence freshness, or current-state
authority. It authenticates no approver and evaluates no credentials, MFA,
groups, roles, privileges, elevation, integrity level, or RBAC.

The operation performs no authorization or execution preflight, creates or
links no receipt, persists no result, and writes no artifact. It has no CLI,
interactive, ask, or natural-language route. It does not invoke PR313 or any
other execution path and permanently reports execution as unavailable and not
executed.
