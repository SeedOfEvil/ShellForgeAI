# Windows current-process token identity evidence

> **This is operating-system process identity evidence. It is neither verified
> physical-human identity nor authorization.**

This read-only Windows-only collector answers one question: which Windows
security principal and authentication/logon session does the current
ShellForgeAI process run under according to its current-process primary access
token? It does not identify a person at the keyboard.

## Native authority and evidence

The collector calls `GetCurrentProcess`, opens only that process token with
`TOKEN_QUERY`, and reads `TokenUser` and `TokenStatistics`. The canonical
principal is the exact bounded SID text returned by
`ConvertSidToStringSidW`; account names, domains, UPNs, environment variables,
and aliases are not consulted. `AuthenticationId` is encoded from the LUID's
unsigned high/low 32-bit pattern as exactly 16 zero-padded lowercase hex
characters without `0x`. It identifies the authentication/logon session
associated with the token, is not a durable principal identifier, and can
change between logons. A current process token must report type `primary`.

`WindowsProcessIdentityEvidence` is frozen and rejects extra fields. Its fixed
contract facts, SID, LUID, and primary token type are serialized as sorted-key,
compact UTF-8 JSON (`ensure_ascii=False`, no BOM/newline). The distinct evidence
identity is the full lowercase SHA-256 of those bytes and is not inside its own
payload. PID, host, path, clock, randomness, and process metadata cannot affect
it.

The native implementation uses the documented two-call buffer-sizing pattern
and accepts only `ERROR_INSUFFICIENT_BUFFER` from sizing. Every successfully
opened token is closed exactly once in `finally`; every successfully converted
SID string is released exactly once with `LocalFree`, including downstream
failure. Raw handles, pointers, and token buffers are never returned or kept.

On non-Windows platforms the result is deterministically `unsupported` before
any Windows DLL is loaded. Other statuses distinguish
`identity_evidence_collected`, `identity_evidence_unavailable`,
`identity_evidence_invalid`, and `identity_collection_failed`.

## Safety and non-authority ledger

All results are read-only and report no mutation. Only native query progress and
OS-identity availability vary. The collector does **not** evaluate or perform:

- physical-human identity, MFA, current domain authentication, credential
  freshness/validity, credentials, secrets, or authentication caches;
- comparison or binding to self-asserted `approved_by`, approval/evidence
  freshness, authorization, roles, RBAC, groups, privileges, elevation,
  integrity level, current-state validation, or execution preflight;
- receipts, persistence, artifact writes, publication, eligibility, PR313
  execution, service/process/registry/host mutation, or natural-language action;
- account-name/domain lookup, PowerShell, WinRM, QGA, remote execution,
  subprocesses, shells, network calls, or model calls.

Service identities, including Local Service, Network Service, and SYSTEM, are
valid possible principal results. The SID says which principal the OS token
represents, not what that principal is allowed to do. The LUID says which logon
session is associated with the token; it proves neither MFA nor fresh/usable
credentials. A future, separately reviewed authority must decide whether and
how this evidence binds to approval provenance. Approval freshness,
authorization, and preflight remain later gates.

