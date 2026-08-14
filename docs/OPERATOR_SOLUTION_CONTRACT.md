# Operator solution contract

`shellforgeai.core.operator_solution` defines the versioned, platform-neutral
North Star endpoint for an evidence-backed operator handoff. Version `v1` is a
normalized domain contract, not a persisted artifact and not an integration
with diagnosis, plans, runbooks, reports, handoffs, or the CLI. A later adapter
may translate those authorities into this contract without embedding them.

The contract captures target and desired outcome; diagnosis, bounded confidence,
likely-cause inference and uncertainty; logical provenance; prerequisites;
impact, blast radius, and risk; an ordered advisory procedure; optional
alternatives; verification criteria; controlled rollback/recovery guidance;
assumptions, open questions, and visibility limits. Raw evidence content and
whole upstream objects are deliberately excluded. Provenance consists only of a
bounded source kind, safe logical reference, and an optional lowercase SHA-256
when the source genuinely supplies one.

All models are frozen and reject unknown fields. IDs, text, and collections are
bounded; IDs are unique in their scopes; every evidence reference resolves to a
declared provenance entry. At least one provenance reference, operator step,
verification criterion, and visibility limit is required. Recovery modes reject
missing or contradictory guidance. Confidence expresses strength of inference,
never proof.

The permanent safety posture is advisory-only, read-only, non-mutating,
non-executable, and `not_executed`. Validation means only that a `v1` solution
is structurally and semantically coherent. It does not mean that instructions
are safe, authorized, approved, fresh, preflighted, executed, or verified.

Canonical JSON uses sorted keys, compact separators, UTF-8-compatible Unicode,
and no trailing newline. Its SHA-256 is lowercase and computed solely from those
canonical JSON bytes; the digest is not embedded in the payload. Markdown has a
fixed section order and preserves caller-provided semantic ordering. None of
these helpers reads a clock, environment, host, network, process, or filesystem.

PR359 owns deterministic producer/adapter work. This contract intentionally
provides no builder, executor interface, persistence hierarchy, or CLI surface.
