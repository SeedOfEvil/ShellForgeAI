# Approved-change current-state evidence identity

ShellForgeAI can construct one immutable, bounded in-memory evidence record from
the exact result of one maintained PR338 persisted-plan-link current-state
revalidation. The public operation accepts PR338's explicit upstream inputs; it
does not accept a caller-created PR338 result. It calls
`revalidate_persisted_plan_link_artifact_current_state(...)` exactly once and
constructs evidence only for a fully coherent `current_state_confirmed` result.

PR338 remains the sole live-state authority. This evidence seam does not open,
hash, stat, enumerate, or otherwise inspect either governed root. It verifies
the returned success prerequisites, exact requested artifact chain, bounded
identities, fixed two-mapping scope and order, and agreement between the
top-level match and every mapping. Incomplete, duplicate, reordered, unmatched,
or operation-contradictory mappings fail closed with no evidence and no
identity. Every non-confirmed PR338 status likewise produces neither.

PR355 reports whether maintained PR338 governed current-state revalidation was
evaluated, but intentionally does not expose a generic filesystem-access flag:
PR338 may perform persisted-artifact loading before governed-root revalidation
begins, and its phase flags are not generic filesystem telemetry.

## Canonical content

The record binds the schema and evidence types; source operation and status;
plan-link artifact ID and identity; plan-link identity; approval-artifact ID and
identity; subject, capability-binding, capability-catalog, and lane-declaration
identities; capability and lane IDs; plan SHA, mode, recipe, and status; the
fixed current-state and evidence scopes; both bounded root fingerprints; and
both ordered relative-path mapping observations. Each mapping includes its
relative source and destination, planned and current operation, source and
destination existence, source and destination hash-match facts, parent state,
match fact, and bounded reason codes.

Absolute governed-root paths, file contents, plan YAML, wrapper text,
credentials, arbitrary exceptions, and secrets are excluded. The canonical
JSON is the validated frozen model serialized with sorted keys, compact
separators, UTF-8, `ensure_ascii=False`, no BOM, and no trailing newline. Its
lowercase SHA-256 is non-circular: the derived evidence identity is not a field
of the hashed evidence payload. Nothing is written or persisted, and no new ID
prefix exists.

## Point-in-time and authority boundary

The identity names exact canonical evidence **content**, not a unique
wall-clock occurrence. No clock is read and no observation timestamp, TTL,
freshness window, or expiration is added. Identical evidence content from
separate PR338 invocations may intentionally have the same identity. State may
change immediately after inspection, so the identity does not establish
freshness.

Current-state match and persisted provenance are not authenticated approval or
authorization. This seam does not authenticate a human; compare SID/LUID with
`approved_by`; evaluate credentials, MFA, groups, roles, privileges, elevation,
or RBAC; consume PR341, PR352, or PR354 output; aggregate readiness; run
execution preflight; create or link receipts; persist anything; or invoke PR313
execution. It adds no CLI, interactive, natural-language, model/provider,
network, shell, subprocess, service, process, registry, mutation, or execution
path. Execution remains unavailable and not executed.
