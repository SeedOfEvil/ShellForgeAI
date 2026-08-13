# Approved change approval-assertion age

This authority answers one narrow chronology question: for one exact validated
persisted PR319 approval artifact, what age does its immutable self-asserted
`approved_at` value have relative to one evaluator-local UTC reading, and is
that ordering clock-consistent?

## Sources and trust

The operation requires one complete `aca_<64 lowercase hex>` artifact ID, an
explicit `data_dir`, and one exact raw 64-lowercase-hex artifact-identity
confirmation. It validates both pure identifiers before filesystem access,
then calls only the maintained PR319 exact-ID loader. The loaded artifact ID
must match the request and its recomputed identity is constant-time compared
with the confirmation before chronology begins. There is no inventory,
latest/current alias, fuzzy lookup, arbitrary path, or sibling fallback.

The approval assertion comes only from the validated loaded contract's
`ApprovalAttestation.approved_at`. That value was supplied by the PR318 caller:
it is **self-asserted, untrusted approval metadata**, not an authenticated time
authority. Persistence proves exactly what timestamp the artifact commits to;
it does not prove when a real-world approval event occurred. No caller can
override the assertion time and no filesystem timestamp is consulted.

Only after exact artifact confirmation and extraction of the timezone-aware
assertion does the evaluator read its local system UTC clock. It reads that
clock exactly once. Evaluator-local UTC is also untrusted local-clock evidence,
not an authenticated time authority. Clock consistency establishes ordering
between these two values, not correctness of either clock.

## Canonical chronology

Both timezone-aware values are normalized to canonical UTC with six-digit
microseconds and a `Z` suffix. The exact elapsed age is computed with integer
day, second, and microsecond arithmetic. `age_microseconds` is the exact
non-negative delta. `age_milliseconds_ceiling` is
`(age_microseconds + 999) // 1000`, so bounded millisecond reporting never
understates the age.

If evaluator UTC precedes the assertion, the result is
`approval_assertion_clock_inconsistent`. Negative chronology is neither
clamped to zero nor converted to an absolute value, and no age is reported.

The immutable evaluation payload contains only bounded artifact provenance,
assertion/reference chronology, trust/source labels, clock consistency, and
age. Its independent identity is SHA-256 over compact, sorted-key, UTF-8 JSON
with no BOM or trailing newline. The identity is not included in its own
payload.

## Deliberate non-authority

There is no approval-age threshold, TTL, grace period, validity interval, or
expiration duration. This authority does not classify an approval as fresh,
stale, expired, valid, or eligible. `approval_freshness_evaluated` remains
false. A future separately reviewed policy may consume chronology evidence;
this module does not provide that policy.

It also does not consume or combine the separate PR352 Windows identity and
approval-provenance binding. It authenticates no approver and evaluates no
credentials, MFA, groups, roles, privileges, elevation, integrity level, or
RBAC. It reaches no conclusion about authorization, current state, PR304
evidence freshness, execution preflight, receipts, or execution.

The operation is pure apart from the maintained read-only artifact load and
one clock read. It persists nothing, mutates nothing, calls no shell,
subprocess, network, model, provider, PR313 execution, or remote system, and
registers no CLI, interactive, ask, or natural-language route.
