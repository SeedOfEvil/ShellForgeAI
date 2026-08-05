# Approved-change current-state revalidation

ShellForgeAI exposes
`revalidate_linked_windows_runtime_reconcile_plan_current_state(...)` as one
local, read-only answer to one question: does the exact PR323-linked plan still
match the governed files and destination-parent conditions at this instant?

The explicit inputs are one full `aca_` artifact ID, one caller-parsed saved
plan mapping, `data_dir`, staged-source root, durable-runtime root, and exact
lowercase SHA-256 confirmations for the PR321 catalog, PR322 lane declaration,
canonical plan, and PR323 plan link. The operation validates the maintained
PR305/PR313 packet first, confirms the plan, catalog, and lane identities,
constructs the PR323 link exactly once, confirms that link, and only then may
touch either governed root. All comparisons use constant-time digest matching.

## Filesystem boundary

The fixed ordered scope is only:

1. `config/profiles/inspect.yaml` to `config/profiles/inspect.yaml`;
2. `scripts/windows/sfai.cmd` to `bin/sfai.cmd`.

Only the durable root and governed `config`, `config/profiles`, and `bin` parent
components are considered. PR328 reuses PR313's maintained source validation,
size bounds, hashing, containment, parent-state, symlink/reparse, and operation
revalidation helpers. There is no recursion, enumeration, wildcard, caller
allowlist, `System32` access, or returned absolute path or file content.

## Results and limits

The immutable extra-field-forbidden result uses `current_state_confirmed`,
`current_state_changed`, `current_state_blocked`, `unsupported`,
`invalid_current_state_input`, or `current_state_validation_failed`. Per-file
records contain fixed relative identifiers, classifications, match booleans,
and bounded reason codes; roots are represented only by non-reversible PR313
fingerprints. A complete exact match alone sets `current_state_matched=true`.

Every result carries permanent warnings that the observation is point-in-time,
may immediately become stale, is neither authenticated approval nor approval
freshness, does not assess free-text/target/procedure semantics or PR304
evidence freshness, creates no receipt, grants no execution eligibility, and
does not invoke PR313 execution. Natural language cannot invoke this API and
all exact identifiers remain mandatory.

The safety ledger records zero mutation, persistence, publication, receipt,
authorization, preflight, shell, subprocess, PowerShell, WinRM, QGA, service,
registry, network, model, credential, backup, temporary-file, replacement, or
parent-creation activity. This operation is not authorization and is not an
execution preflight.


## PR338 persisted-artifact provenance path

PR328 reconstruction-based current-state revalidation remains supported with the same public entrypoint, statuses, mappings, warnings, and safety ledger. PR338 adds a second provenance-acquisition path: `revalidate_persisted_plan_link_artifact_current_state(...)` loads one exact PR337 `acpl_` artifact through the maintained exact-ID loader, confirms its artifact identity, validates its embedded PR323 link, compares that persisted link to the caller-supplied validated plan, and only then reuses the same live-state evaluator. Neither path is authorization, approval freshness, PR304 evidence freshness, execution preflight, receipt linkage, or execution, and neither persists current-state observations.
