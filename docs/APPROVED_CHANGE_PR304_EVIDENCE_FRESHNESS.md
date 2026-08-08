# Approved-change PR304 evidence freshness

This read-only authority answers exactly whether one confirmed PR304 two-packet
evidence set is within the product-maintained age window according to the
evaluator's local UTC clock. It is a temporal classification only: fresh never
means approved, authorized, safe to apply, preflight-passed, or executable.

## Fixed policy and identities

The immutable version-1 policy type is
`pr304_runtime_integrity_evidence_freshness`. Its fixed
`max_oldest_evidence_age_ms` is `300000`, its age basis is
`earliest_capture_start_to_evaluator_local_utc`, and its clock is
`local_system_utc` with trust stated as `untrusted_local_system_clock`. There is
no caller, CLI, environment, configuration, model, or network override.

Policy and evaluation identities are complete lowercase SHA-256 hashes of
sorted-key, compact, UTF-8 canonical JSON (`ensure_ascii=False`, no BOM or
trailing newline). They are separate from packet, evidence-set, PR339 binding,
plan, plan-link, artifact, approval, authorization, receipt, and execution
identities. Neither canonical payload contains its own identity.

## Evaluation order and outcomes

The evaluator validates argument formats and the exact PR340 evidence-set
model, recomputes and constant-time confirms its identity, loads and confirms
the fixed policy, and requires stable-field consistency before clock access.
It then requires available, valid canonical pair chronology. Legacy untimed
evidence returns `freshness_unavailable` without a clock read or invented time;
malformed chronology fails closed.

Only after those gates does the evaluator read local UTC exactly once. That
clock is neither authenticated nor externally synchronized. A reference time
before the latest completion returns `freshness_clock_inconsistent`, never a
clamped negative age. Otherwise the evaluator calculates age from the earliest
capture start with integer microsecond arithmetic. Reported integer
milliseconds are rounded upward, so they never understate age:

- oldest age `<= 300000 ms`: `evidence_fresh`;
- oldest age `> 300000 ms`: `evidence_stale`.

Thus 299999 ms and exactly 300000 ms are fresh; 300001 ms and even one
microsecond beyond 300000 ms are stale. Same confirmed identities, reference
UTC, derived ages, and outcome produce the same evaluation identity.

## Non-authority boundary

Packet status is orthogonal: blocked or attention evidence can be temporally
fresh without changing that status. Freshness is not approval freshness,
authenticated identity, current-state revalidation, authorization, execution
preflight, receipt linkage, or execution eligibility. It invokes neither the
PR328/PR338 current-state authority nor PR313 execution, persists nothing, has
no CLI or natural-language route, and performs no filesystem, model, network,
credential, shell, subprocess, PowerShell, WinRM, QGA, service, or host
mutation. State may change immediately after capture; freshness does not solve
TOCTOU, and capture and evaluation clocks may be wrong or unsynchronized.
