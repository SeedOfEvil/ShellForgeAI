# Approved-change Windows identity binding

This Stage B contract answers one narrow question: were one exact, validated
Windows current-process primary-token identity-evidence object and one exact,
durable approved-change approval artifact intentionally associated under the
maintained ShellForgeAI contracts? A successful result is an in-memory
provenance association only.

## Exact inputs and authority order

The operation requires one complete `aca_<64 lowercase hex>` ID, an explicit
data directory, one PR342 `WindowsProcessIdentityEvidence` object or mapping,
the raw 64-lowercase-hex approval-artifact identity confirmation, and the raw
64-lowercase-hex identity-evidence SHA-256 confirmation. It accepts no prefix,
alias, wildcard, inventory selection, or `latest`/`current` reference.

Validation is fail-closed and ordered:

1. Validate the complete approval ID and both confirmation formats without
   filesystem access.
2. Validate the supplied evidence through PR342's maintained model, recompute
   it through PR342's canonical hash authority, and constant-time compare its
   explicit confirmation.
3. Only then invoke PR319's exact-ID loader once for the requested artifact.
   Require its maintained loaded/validated state, the exact requested ID, and
   a constant-time match with the artifact identity confirmation.
4. Construct and validate the bounded binding, serialize sorted compact UTF-8
   JSON with `ensure_ascii=False`, and hash those non-circular canonical bytes.

PR352 does not parse approval JSON, walk an inventory, repair an artifact, or
fall back to a sibling artifact. PR342 remains the sole SID/LUID model and
evidence canonicalization authority. PR319 remains the sole exact persisted
approval loader, including its PR309 approval-contract validation.

## Bounded identity

The immutable, extra-field-forbidden binding records its schema and type; the
exact approval artifact ID and identity; subject SHA-256; PR342 evidence type,
source, collector scope, principal SID, AuthenticationId/LUID, and primary
token type; exact evidence SHA-256; and a fixed comparison scope. It includes
neither its own SHA-256 nor raw approval JSON, the full approval contract,
paths, process IDs, account aliases, credentials, groups, or privileges.

The binding SHA-256 is a new deterministic identity for this exact association.
It is not the PR309 subject, PR319 approval-artifact, PR339 evidence-binding,
PR341 freshness, PR342 evidence, receipt, or execution identity. Any changed
bound provenance fact changes the binding identity. The binding is not
persisted and has no artifact prefix, publisher, loader, inventory, or pointer.

## Identity-domain boundary

`ApprovalAttestation.approved_by` remains explicit, self-asserted approval
metadata. The Windows SID is OS current-process-token principal evidence, and
AuthenticationId/LUID is session-local logon-session evidence that may change
between logons and is not durable. PR352 never compares, normalizes, resolves,
or copies `approved_by` into SID/LUID, and it infers no physical human from a
SID. Valid service-account SIDs are ordinary provenance evidence, not an
authorization grant or a human-identity claim.

No account, domain, UPN, directory, group, role, privilege, elevation,
integrity-level, credential, MFA, secret, or authentication-cache lookup or
evaluation occurs. The operation consumes already-created evidence and calls
no PowerShell, WinRM, QGA, shell, subprocess, network service, or model.

## Permanent safety boundary

A successful binding is not human authentication, MFA or credential validity,
approval/evidence freshness, RBAC, authorization, current-state revalidation,
execution preflight, receipt creation/linkage, or execution eligibility. It
does not invoke PR313, execute or mutate anything, persist the binding, or add
a CLI, interactive, ask, or natural-language route. Natural language cannot
convert this provenance record into execution. The structured result keeps
these non-actions explicitly false and always reports execution as unavailable,
not allowed, and `not_executed`.
