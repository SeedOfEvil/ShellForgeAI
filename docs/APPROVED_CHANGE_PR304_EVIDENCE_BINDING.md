# Approved-change PR304 evidence binding

This contract answers one question: can one exact persisted `acpl_` plan-link artifact, its exact maintained-validator-approved plan, and one exact ordered pair of PR304 Windows runtime-integrity packets be associated deterministically in memory? A successful result says only that these structures and identities agree.

## Authorities and ordering

`windows_runtime_integrity_contract.py` is the pure authority for the PR304 packet checks formerly held by the acceptance script. The script still owns file reading and its unchanged CLI, human/JSON output, and exit codes, but delegates packet validation and stable-field comparison. The pure preparation API accepts fixed `source_root_observation` and `system32_observation` arguments; caller-assigned roles are not authenticated. Invocation-context differences such as the working directory remain outside stable comparison.

Before filesystem access, binding validates all input formats, validates the plan through the maintained PR305/PR313 contract, confirms its canonical SHA-256, validates both packets, constructs the exact evidence set, and confirms its SHA-256. It then invokes the PR337 exact-ID loader once, confirms the artifact identity, validates the embedded PR323 link without calling PR323 construction, and compares that link to the supplied plan. It neither calls nor extends PR328/PR338 current-state evaluation.

## Canonical identities

Packet, evidence-set, and binding JSON use sorted keys, compact separators, UTF-8, `ensure_ascii=False`, no BOM, and no trailing newline. Each full lowercase SHA-256 hashes its own non-circular payload. Packet paths are not normalized before hashing. Evidence-set output contains bounded packet facts and identities, never raw packets; binding output contains bounded upstream identities, never a plan, artifact, packet, or absolute path. These three identities are separate domains from plan, plan-link, PR337 artifact, approval, subject, catalog, lane, capability-binding, receipt, and execution identities.

## Results and non-authority boundary

Results distinguish invalid evidence, inconsistent stable fields, evidence confirmation mismatch, unavailable artifact, artifact confirmation mismatch, plan mismatch, invalid input, internal validation failure, and successful construction. `attention` and `blocked` packet statuses can be structurally valid evidence facts; they do not grant authority.

Every result is immutable and reports a permanent false safety ledger: no persistence or publication, current-state or freshness evaluation, authenticated identity, approval freshness, authorization, preflight, receipt, execution eligibility, model/network/credential access, subprocess/shell/PowerShell/WinRM/QGA, or host mutation. PR313 execution is not invoked and natural language cannot reach the operation.

New packet identities naturally include the collector-owned capture block because identity remains SHA-256 of canonical exact packet JSON; no timeless identity exists. The evidence set exposes each packet's bounded chronology and, when both are available and valid, the earliest start, latest completion, and combined endpoint span. Source-root and System32 collection is sequential, so capture fields are deliberately excluded from stable-field equality and need not overlap. Roles and local wall-clock values remain unauthenticated, monotonic duration is local-process-only, freshness is not evaluated, state may already have changed, and exact confirmations do not cure TOCTOU.

PR339 remains a provenance-binding authority only. The separate downstream
[PR304 evidence freshness](APPROVED_CHANGE_PR304_EVIDENCE_FRESHNESS.md)
evaluation does not enter or change PR339 canonical binding bytes or identity.
Fresh evidence is not authorized evidence.
