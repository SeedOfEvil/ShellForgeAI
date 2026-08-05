# Approved-change plan-link artifact persistence

ShellForgeAI can persist the exact deterministic approved-change-to-plan link
defined by the maintained plan-link contract. This is durable **provenance
only**: persistence is not authentication, authorization, approval freshness,
current-state validation, execution preflight, receipt linkage, or execution.

## Artifact contract

Schema version `1` has artifact type `approved_change_plan_link_artifact`. The
only location is:

```text
<data_dir>/approved_change_plan_links/acpl_<64-lowercase-hex>/
  approved-change-plan-link.json
```

The payload contains the complete canonical PR323 link plus only its exact
approval-artifact, subject, capability-binding, catalog, lane-declaration,
capability, lane, plan, and plan-link identities. It contains no artifact ID or
artifact identity, avoiding a circular hash. It never contains the full saved
plan packet, host paths, current-state observations, timestamps, environment
values, receipts, authorization, preflight, or execution fields.

Canonical JSON is UTF-8 without BOM or trailing newline, with sorted keys,
compact separators, and `ensure_ascii=False`. The artifact identity is SHA-256
of those bytes. Its ID is `acpl_` followed by that full identity. This domain is
permanently distinct from subject, bundle, approval-artifact, catalog,
lane-declaration, capability-binding, canonical-plan, and PR323 link identities.

## Publication and loading

Publication accepts one exact `aca_` ID, a caller-parsed plan mapping, an
explicit data directory, and exact catalog, lane, plan, and new artifact
identity confirmations. The maintained PR323 operation validates the plan and
constructs the link. All confirmations are exact raw lowercase SHA-256 values;
the artifact confirmation is checked before publication writes.

One private temporary sibling and one fixed file are prepared, flushed,
reread, and validated. Publication reuses the maintained cross-platform atomic
directory no-replace seam. There is no overwrite fallback. An already-present,
fully valid, byte-identical artifact is a zero-write no-op; any malformed,
different, partial, linked, reparse, or otherwise unsafe destination is a
conflict and is never repaired, renamed, deleted, or quarantined. Cleanup is
limited to the unpublished temporary directory owned by the invocation.

The read-only loader accepts only an exact full `acpl_` ID. It derives the fixed
path, rejects links/reparse points and extra entries, bounds the single read,
requires canonical bytes, and recomputes both identities. It never enumerates
siblings, selects `latest` or `current`, or repairs an artifact.

Every successful construction, publication, no-op, and load reports permanent
non-authority warnings. PR328 current-state observations remain transient and
are neither invoked nor persisted. PR313 execution is never invoked. No CLI,
interactive, or natural-language route publishes this artifact.


## PR338 consumption

A PR337 `acpl_` artifact may be consumed by the PR338 read-only persisted plan-link current-state operation. That consumption does not change the PR337 schema, canonical bytes, identity, ID derivation, fixed layout, publisher, or exact-ID loader. Artifact persistence remains provenance only; it is not current-state freshness, authorization, approval freshness, execution preflight, receipt linkage, or execution eligibility.
