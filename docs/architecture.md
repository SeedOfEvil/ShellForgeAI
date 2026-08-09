# Architecture

The approved-change chain separates structural and live facts: PR323 associates
one approved capability binding with one validated saved plan, while the
read-only current-state revalidation API compares that exact link with only the
fixed PR313 two-file filesystem scope at one instant. Authorization and any
future execution preflight remain later, separate gates. The mutation-capable
PR313 execution operation is not invoked by current-state revalidation.

## V1 architecture contract

CLI → collectors → triage → ops reports → artifacts → governed remediation.

- **CLI entrypoints** perform deterministic routing for explicit subcommands and
  known safety prompts.
- **Collectors** are typed read-only evidence collectors.
- **Triage** ranks suspects deterministically for common Docker/operator scenes.
- **Ops reports** summarize ranked incidents and safe next commands.
- **Artifacts** preserve/save/validate/export/compare report outputs.
- **Governed remediation** remains explicit, gated, and disposable-oriented; not
  casual production automation.

### Safety boundaries

- Read-only default posture.
- Deterministic natural-language mutation refusal.
- No arbitrary shell execution.
- Mutation paths require explicit gated CLI lanes.

### Ask routing boundaries

- Slash commands are deterministic and unknown slash commands do not call the model.
- Recognized operator asks route to deterministic report/triage/refusal paths.
- Deterministic safety routes do not depend on model availability.
- The immutable shared platform operator contract derives classification and
  support-lane identity from maintained `detect_platform()` / `support_status()`
  behavior. Existing intent authorities select a route first; the contract
  supplies only generic platform dispatch and presentation metadata.
- Linux/Docker and Windows specialized renderers remain authoritative. For an
  already-selected generic evidence route on Darwin or an unknown platform,
  ask and interactive mode return the shared deterministic unsupported response
  before collection, provider construction, or model use.
- Later command validation, timed/progressive response, and golden-path/help
  work may consume this contract but are not part of it.

### Artifact lifecycle

Ops reports support save, validate, history, compare, compare-latest, export,
and export-validate to preserve and hand off evidence-backed state over time.

ShellForgeAI is structured around a strict separation between **deterministic
runtime** (typed read-only tools, evidence, plans, audit) and **advisory model
synthesis** (LLM providers).

## Layers

```
                ┌──────────────────────────────────────┐
   user input → │  CLI (typer) / Interactive REPL      │
                └──────────────┬───────────────────────┘
                               │
                ┌──────────────▼───────────────────────┐
                │  Core runtime                        │
                │  config · profiles · session         │
                │  diagnose · evidence · plans         │
                │  collectors · instructions · errors  │
                └─────┬─────────────────────────┬──────┘
                      │                         │
        ┌─────────────▼─────┐         ┌─────────▼────────┐
        │  Tools (typed,    │         │  LLM providers   │
        │  read-only):      │         │  codex / ollama  │
        │  host · journal · │         │  vllm / openai-  │
        │  systemd · disk · │         │  compatible /    │
        │  network · ...    │         │  openrouter      │
        └─────────────┬─────┘         └─────────┬────────┘
                      │                         │
                ┌─────▼─────────────────────────▼──────┐
                │  Policy · Audit · Knowledge · Render │
                └──────────────────────────────────────┘
```

## Modules

| Path | Purpose |
| --- | --- |
| `core/config.py` | YAML + env settings (`pydantic-settings`). |
| `core/approved_change_contract.py` | Inert Stage B immutable approved-change subject, attestation binding, canonical hash, and read-only validation; not wired into CLI, proposals, approvals, recipes, persistence, preflight, or execution. |
| `core/approved_change_compatibility.py` | In-memory findings-only PR310 assessment of legacy Proposal schema v1 against PR309 contract requirements; creates no contract, loads no files, and is not wired into CLI, approval flow, persistence, recipes, preflight, or execution. |
| `core/approved_change_construction_policy.py` | Immutable PR311 field-source policy metadata and pure validation for future approved-change construction; takes no `Proposal` instance, creates no subject or contract, and is not wired to CLI, approvals, persistence, recipes, preflight, receipts, platforms, or execution. |
| `core/approved_change_supplemental_context.py` | Immutable PR314 reviewed supplemental-context contract, candidate/context canonical SHA-256 identity, and pure structured validation of reviewed input coverage; provides no construction function, takes no `Proposal`, creates no subject, attestation, or contract, and is not wired to CLI, approvals, persistence, recipes, preflight, receipts, platforms, or execution. |
| `core/approved_change_subject_construction.py` | Pure, deterministic, fail-closed PR315 in-memory construction of exactly one PR309 `ApprovedChangeSubject` from a freshly revalidated PR314 reviewed context plus an explicit expected context SHA-256, under a freshly revalidated PR311 policy; emits immutable field-by-field construction evidence and a separate construction-evidence SHA-256, takes no `Proposal`, creates no attestation or contract, evaluates no capability support, and is not wired to CLI, approvals, persistence, recipes, preflight, receipts, platforms, or execution. |
| `core/approved_change_artifact_bundle.py` | Pure, deterministic, checksum-protected PR316 in-memory artifact-bundle contract: exactly four canonical UTF-8 JSON logical files (reviewed context, constructed subject, construction evidence, manifest) under a fixed literal filename allowlist, with exact byte lengths, content checksums equal to the maintained semantic identities, a non-circular bundle identity, and a full-hash bundle ID; it accesses no filesystem, writes no artifact, persists nothing, takes no `Proposal`, creates no attestation or contract, evaluates no capability support, and is not wired to CLI, approvals, persistence, recipes, preflight, receipts, platforms, or execution. |
| `core/approved_change_artifact_persistence.py` | The one PR317 filesystem boundary for Stage B artifacts: publishes an already-valid PR316 bundle beneath the fixed `<data_dir>/approved_change_artifacts/<bundle-id>/` subtree after an exact `confirm_bundle_identity_sha256` match, prepares and verifies all four canonical files in a private temporary sibling, commits with one atomic no-replace directory transition, never overwrites, cleans up only its own unpublished temporary directory, and exposes one read-only explicit-ID loader that reruns PR316 validation; it accepts no arbitrary destination, creates no approval, attestation, contract, or receipt, evaluates or binds no capability, and is not wired to CLI, approvals, recipes, preflight, platforms, or execution. |
| `core/approved_change_approval_workflow.py` | The one PR318 approval-binding operation for Stage B: loads exactly one persisted PR316 bundle through the maintained PR317 exact-ID loader, requires an explicit `approve` decision plus exact bundle-identity and subject-hash confirmations, sources the subject only from the fixed `approved-change-subject.json` logical file, recomputes subject identity only with PR309 `compute_subject_sha256`, and creates exactly one `ApprovalAttestation` and one `ApprovedChangeContract` in memory whose binding it verifies with `verify_approval_binding`; it writes nothing, persists no approval or contract, takes no `Proposal`, never calls `validate_approved_change_contract`, evaluates or binds no capability, reads no clock, and is not wired to CLI, approvals, recipes, preflight, receipts, platforms, or execution. |
| `core/windows_process_identity_evidence.py` | Windows-only read-only authority for the current process primary token: `TOKEN_QUERY` obtains the native `TokenUser` SID and `TokenStatistics.AuthenticationId` LUID, with deterministic evidence identity and strict native cleanup. It performs no name/domain, group, privilege, elevation, human-identity, approval-binding, authorization, preflight, persistence, or execution work. |
| `core/approved_change_approval_artifact.py` | The pure PR319 approval-artifact contract: turns one fully successful PR318 approval-workflow result into exactly one immutable canonical UTF-8 JSON approval artifact (`approved-change-approval.json`) holding the schema version, the artifact type, the exact PR316 source bundle ID and identity, the exact PR309 subject SHA-256, and the exact PR318 contract, serialized only through the maintained PR309 canonicalizers, with a non-circular approval-artifact identity SHA-256 and the derived full-hash `aca_` artifact ID; it accesses no filesystem, reads no clock, uses no randomness, takes no `Proposal`, creates no approval or contract of its own, never calls `validate_approved_change_contract`, evaluates no capability support, and is not wired to CLI, approvals, persistence, recipes, preflight, receipts, platforms, or execution. |
| `core/approved_change_approval_persistence.py` | The one PR319 filesystem boundary for approval artifacts: publishes an already-valid approval artifact beneath the fixed `<data_dir>/approved_change_approvals/<approval-artifact-id>/` subtree after an exact `confirm_approval_artifact_identity_sha256` match, prepares and verifies the one canonical file in a private temporary sibling, commits with one PR319-owned atomic no-replace directory transition, never overwrites, cleans up only its own unpublished temporary directory, and exposes one read-only exact-ID loader that reruns PR319 validation, the PR309 approval binding, and the exact PR317 source-bundle revalidation; it accepts no arbitrary destination, never calls PR317's publisher, never writes to the PR317 bundle subtree, creates no approval, contract, or receipt, evaluates or binds no capability, and is not wired to CLI, approvals, recipes, preflight, platforms, or execution. |
| `core/approved_change_approval_inventory.py` | The one PR320 read-only discovery layer for approval artifacts: takes only an explicit `data_dir`, derives the fixed `<data_dir>/approved_change_approvals` root, enumerates its direct children exactly once without recursion and without following any symlink or reparse point, enforces the fixed maintained bound of 1024 direct children before loading anything, treats only exact `aca_` plus 64-lowercase-hex names as candidates, validates each one solely through the maintained PR319 exact-ID loader, and returns immutable summaries sorted lexicographically by artifact ID plus one explicit anomaly for every other direct child; it writes nothing, creates no directory or index, repairs and deletes nothing, orders by no timestamp, selects no approval, resolves no `latest`/`current`, never calls PR319's publisher, reads no clock, takes no `Proposal`, evaluates or binds no capability, and is not wired to CLI, approvals, recipes, preflight, receipts, platforms, or execution. |
| `core/approved_change_capability_support.py` | The one PR321 typed capability-support declaration and evaluation module: holds one immutable, canonical, source-maintained catalog with a deterministic SHA-256 identity that declares exactly `windows.runtime_reconcile` for approved-change contract validation only, and exposes one read-only evaluator that requires an exact 64-lowercase-hex catalog-identity confirmation before any filesystem access, loads exactly one persisted PR319 approval artifact through the maintained exact-ID loader, and decides support only by calling the maintained PR309 `validate_approved_change_contract` with exactly the catalog's capability IDs; it writes nothing, persists and publishes no catalog, accepts no caller-supplied capability set, calls no inventory, resolves no `latest`/`current`, reads no clock, environment, host, or credential, takes no `Proposal`, imports no recipe registry or PR313/PR304/PR305 module, binds no capability, evaluates no authorization, runs no preflight, creates or links no receipt, and is not wired to CLI, approvals, recipes, platforms, or execution. |
| `core/approved_change_capability_binding.py` | The one PR322 read-only capability-binding module: holds one immutable, source-maintained lane declaration for the named PR313 governed Windows two-file runtime-reconciliation lane (`capability_id=windows.runtime_reconcile`, `lane_id=pr313.windows_runtime_reconcile`, `binding_status=declared_bindable`) with a deterministic SHA-256 identity, and exposes one read-only operation that requires exact 64-lowercase-hex PR321 catalog-identity and lane-declaration-identity confirmations before any filesystem access, confirms support only through the maintained PR321 evaluator, obtains exact binding metadata only through the maintained PR319 exact-ID loader, and constructs exactly one in-memory `ApprovedChangeCapabilityBinding` with a non-circular deterministic identity; it writes nothing, persists and publishes no binding, accepts no caller-supplied artifact, contract, support result, catalog, or lane declaration, calls no inventory, resolves no `latest`/`current`, reads no clock, environment, host, or credential, takes no `Proposal`, imports no recipe registry or PR313/PR304/PR305 module, evaluates no target, procedure, evidence, or current-state compatibility, evaluates no authorization, runs no preflight, creates or links no receipt, and is not wired to CLI, approvals, recipes, platforms, or execution. |
| `core/approved_change_plan_link.py` | The one PR323 read-only plan-link module: holds one immutable in-memory `ApprovedChangeWindowsRuntimeReconcilePlanLink` with a non-circular deterministic SHA-256 identity, and exposes one read-only operation that validates one explicitly supplied parsed plan mapping through the maintained PR305/PR313 plan-contract seam, requires exact 64-lowercase-hex canonical plan-SHA, PR321 catalog-identity, and PR322 lane-declaration-identity confirmations before any filesystem access, obtains its binding only through the maintained PR322 operation called exactly once, and compares only maintained typed capability/lane/mode/recipe/allowlist/parent-contract/status facts; it writes nothing, persists and publishes no link, accepts no caller-supplied binding, contract, artifact, catalog, lane declaration, plan path, or output path, calls no inventory, resolves no `latest`/`current`, reads no clock, environment, host, or credential, never returns the plan packet or any host path, interprets no target, procedure, or evidence semantics, inspects no live staged source, durable runtime, or `System32`, invokes no PR313 execution, current-state revalidation, receipt, or verification path, evaluates no authorization, and is not wired to CLI, approvals, recipes, platforms, or execution. |
| `core/windows_runtime_reconcile_plan_contract.py` | The one pure saved-plan contract seam for the `windows.runtime_reconcile` lane: holds the exact fixed two-file allowlist, the exact destination-parent contract, the accepted plan statuses, the maintained PR305 saved-packet acceptance rules, the narrower maintained PR313 executable-plan contract, and the maintained canonical plan JSON/SHA-256 identity, so exactly one definition exists and `scripts/windows_runtime_reconcile_acceptance.py` and `core/windows_runtime_reconcile_execution.py` both delegate to it; it is pure — no filesystem, current-state, preparation, backup, atomic-replacement, compensation, receipt, verification, subprocess, shell, network, clock, environment, or mutation path — and it never inspects a staged source root, a durable runtime root, `System32`, or any host path. |
| `core/profiles.py` | Risk-class allow/ask/deny profiles. |
| `core/session.py` | Session id, data dir, artifact dir. |
| `core/context.py` | `RuntimeContext` carried through CLI handlers. |
| `core/diagnose.py` | Target classification → collectors → findings → plan. |
| `core/evidence.py` | Evidence model and target classification. |
| `core/plans.py` | `Plan` / `PlanStep` schemas. |
| `core/collectors.py` | Read-only collectors per intent. |
| `tools/*` | Typed read-only tools (`host`, `journal`, `systemd`, `disk`, `network`, `firewall`, `packages`, `services`, `process`, `containers`, `logs`, `storage`, `system`, `files`). |
| `tools/registry.py` | Tool catalog, risk class, schema. |
| `llm/manager.py` | Provider factory. |
| `llm/codex*.py` | OpenAI Codex CLI subprocess provider with JSON event stream parsing. |
| `llm/ollama.py`, `llm/vllm.py`, `llm/openai_compatible.py`, `llm/openrouter.py` | Alternative providers. |
| `llm/prompts.py` · `llm/system_prompt.py` | Canonical system prompt + contextual prompt assembly. |
| `interactive/repl.py` | Operator REPL, slash commands, routing. |
| `interactive/streaming.py` | Streaming synthesis. |
| `interactive/workspace.py` · `guards.py` | Trust prompt, paste guard, quarantine. |
| `policy/*` | Risk classes, rules engine, approval gates. |
| `audit/*` | JSONL audit log + artifact storage. |
| `knowledge/*` | Local docs / audit search; optional web. |
| `render/*` | Rich console rendering and tables. |

## Request flow (interactive ops question)

1. REPL classifies input. Slash commands are deterministic and never call
   the model. Shell-looking pasted input is blocked unless prefixed with
   `ask explain` / `ask review`.
2. For recognized ops intents (disk / performance / health / firewall /
   service / service-discovery), the runtime runs the matching read-only
   collectors and assembles an evidence bundle.
3. The canonical ShellForgeAI system prompt + the evidence bundle + the
   operator question are sent to the configured provider.
4. The model's synthesis is streamed back. A deeper read-only follow-up is
   queued when warranted; `yes` / `proceed` / `dig deeper` / `run it`
   executes it. `/pending` shows the queue.
5. An audit record (session id, command, tools called, artifacts, warnings,
   summary) is appended; artifacts are written to the session artifact dir
   only when produced.

## Workflow spine

```
Evidence
  → Runbook
  → Proposal
  → Approval
  → Rollback / recovery preview
  → Mission checklist + readiness
  → Explicit execute / apply gate
  → Verification
  → Receipt / closure report
  → Export / audit / cleanup
```

Each step writes its artifact under `<data_dir>` (see
[`data-layout.md`](data-layout.md)). Each step refuses to advance unless
the prior step's artifact exists and validates. No step skips ahead, no
step retries automatically, and no step executes the next step on the
operator's behalf.

## Trust boundary

- ShellForgeAI inspects within its configured runtime access only.
- It must not assume host/systemd facts when running inside a container.
  Container limits surface as visibility limitations, never as
  fabricated host health claims.
- It distinguishes container runtime boundaries, Docker state, Compose
  metadata (advisory only), package DB visibility, labels, mounts,
  logs, and its own artifacts.
- Workspace trust grants doc reads and artifact writes under the data
  dir. It never lifts policy, enables mutation, or bypasses gates.

## Approved-change contract boundary

`core/approved_change_contract.py` is an isolated Stage B domain module. It grants no execution eligibility and exists only to provide a stable approval-bound identity for later reviewed integration. It is not connected to current proposal objects, approval transitions, action compilation, recipes, persistence, receipts, CLI commands, preflight, or execution lanes.

`core/approved_change_supplemental_context.py` is the PR314 reviewed-input boundary module. It defines the complete reviewed value package a future construction operation would require, with per-field review provenance and a supplemental-context identity that is deliberately distinct from the PR309 subject hash. It constructs nothing, persists nothing, and grants no approval or execution eligibility.

`core/approved_change_subject_construction.py` is the PR315 construction boundary module. It is the only place a PR309 `ApprovedChangeSubject` is assembled from reviewed input, and it does so exactly once, in memory, only when the expected reviewed-context identity, the canonical PR311 policy, the PR314 context, the exact 1+12+5 field-authority map, and full field-by-field evidence verification all pass. It keeps three permanently distinct identities — supplemental-context, subject, and construction-evidence SHA-256 — performs no I/O, and grants no approval, capability support, persistence, or execution eligibility.

`core/approved_change_artifact_bundle.py` is the PR316 persistence-payload boundary module. It defines the exact bytes a future writer would be allowed to publish — four fixed logical files, fixed order, fixed roles, canonical upstream serialization only — and validates a complete bundle by revalidating the stored reviewed context, rerunning the PR315 constructor, comparing reconstructed canonical bytes with stored bytes, and recomputing the non-circular bundle identity. The filesystem boundary itself stays out of the module: it holds no path, opens nothing, creates no file or directory, and records publication, atomicity, overwrite, existing-identical, and destination policies as contract metadata that `core/approved_change_artifact_persistence.py` (PR317) implements.

`core/approved_change_artifact_persistence.py` is the PR317 artifact-persistence boundary module. It is the only place a PR316 bundle reaches the filesystem. Nothing is inspected or created until the bundle passes fresh PR316 validation and the explicit bundle-identity confirmation matches; the fixed publication root, the temporary sibling, and the final bundle directory are all rechecked for direct containment, symlink/reparse safety, and resolved-path containment before preparation and again before commit. Files are written exclusively in binary mode from `content_utf8.encode("utf-8")`, flushed, and reread and checksum-verified; the whole prepared bundle is reconstructed and revalidated before a single atomic no-replace directory transition publishes it. Native platform API use is confined to that one primitive (Linux `renameat2(RENAME_NOREPLACE)`, Windows `MoveFileExW` without replace) and fails closed rather than downgrading. Cleanup is bounded to the invocation's own unpublished temporary directory, a published bundle is never removed, and the read-only loader accepts only one exact `acb_` bundle ID under explicit size bounds.

`core/approved_change_approval_workflow.py` is the PR318 approval-binding boundary module. It is the only place a PR309 `ApprovalAttestation` and `ApprovedChangeContract` are constructed from a persisted reviewed change, and it does so exactly once, in memory, only when the explicit `approve` decision, the exact full PR316 bundle ID, both explicit confirmation hashes, and the explicit approval metadata all validate before any filesystem access, and the persisted bundle then loads and revalidates through the maintained PR317 exact-ID loader with its whole subject identity chain in agreement. Its dependencies are deliberately narrow: PR309 models and functions, PR316 fixed filename/role constants, and the PR317 loader. It never opens a file, writes a byte, reads a clock, consults a capability registry, or calls `validate_approved_change_contract`; `datetime` and `pathlib` appear only in annotations, so the module cannot reach a clock or construct a path at all. Approval binding leaves the persisted tree byte- and mtime-identical, and the resulting contract is authorization for nothing.

`core/approved_change_approval_artifact.py` is the PR319 approval-artifact contract module. It is the only place a durable approval payload is defined, and it defines exactly the bytes a governed writer may publish: one fixed logical file, six canonical fields, and PR309 canonical serialization only. It never opens a file, holds a path, reads a clock, or reaches randomness — `pathlib` is not imported at all — and it creates no approval or contract, because PR318 already created both. Its identity is deliberately non-circular and permanently distinct from the supplemental-context, subject, construction-evidence, and PR316 bundle identities.

`core/approved_change_approval_persistence.py` is the PR319 approval-persistence boundary module. It is the only place an approval artifact reaches the filesystem. Nothing is inspected or created until the artifact passes fresh PR319 validation and the explicit artifact-identity confirmation matches; the fixed publication root, the temporary sibling, and the final artifact directory are all rechecked for direct containment, symlink/reparse safety, and resolved-path containment before preparation and again before commit. The one canonical file is written exclusively in binary mode, flushed, reread, checksum-verified, and reconstructed and revalidated before a single atomic no-replace directory transition publishes it. Native platform API use is confined to that one PR319-owned primitive (Linux `renameat2(RENAME_NOREPLACE)`, Windows `MoveFileExW` without replace) and fails closed rather than downgrading, so PR317's public surface is unchanged. Cleanup is bounded to the invocation's own unpublished temporary directory, a published artifact is never removed, the PR317 bundle subtree is read-only here, and the loader accepts only one exact `aca_` artifact ID under explicit size bounds before revalidating the artifact, its PR309 binding, and its exact PR317 source bundle.

`core/approved_change_approval_inventory.py` is the PR320 approval-inventory module. It is the only place the fixed approval-artifact root is enumerated, and it is deliberately the smallest thing that can safely answer "what is persisted here?". It owns no parser, no loader, and no identity rule: it reuses PR319's maintained artifact-ID rule, root-safety helpers, and exact-ID loader rather than duplicating their semantics, and an entry exists only because that loader returned a fully valid artifact. The scan is bounded before any artifact is loaded, is strictly direct-child-only, uses no-follow inspection throughout, captures and rechecks the root's filesystem identity so a mid-scan replacement fails closed, and rechecks each candidate's identity around the loader call. Discovery is not selection: ordering is lexicographic by exact artifact ID and by nothing else, no `latest`, `current`, or "most recent" approval is resolved, and an exact `aca_` ID is still required to retrieve the complete artifact. Anomalies are explicit rather than silent, so an inventory that could not be complete says so with `inventory_complete=false`, and no direct child is ever followed, recursed into, repaired, renamed, or removed.

`core/approved_change_capability_support.py` is the PR321 capability-support module. It is the only place ShellForgeAI states which approved-change capabilities it recognizes, and it states exactly one: `windows.runtime_reconcile`, for approved-change contract validation only. The catalog is source-maintained and in-memory — never persisted, published, inventoried, loaded from disk, discovered from plugins, derived from `recipe_registry`, or supplied by a caller — and its only identity is the deterministic SHA-256 of its own canonical bytes, which carry no timestamp, environment, host, platform, or derived value. The evaluator validates the maintained catalog, computes its identity, and requires an exact `hmac.compare_digest` match against the caller's explicit confirmation *before* touching the filesystem, so a malformed or mismatched confirmation loads nothing at all. It owns no parser, loader, or identity rule: the approved contract comes only from one fully revalidated PR319 exact-ID load, and the support decision comes only from the maintained PR309 `validate_approved_change_contract` called with exactly the catalog's capability IDs. Declared support is not binding: matching is exact, case-sensitive `capability_id` equality alone, so two entirely different approved subjects sharing that ID are both supported and every result reports `capability_bound=false`, `authorization_evaluated=false`, `preflight_evaluated=false`, `receipt_created=false`, and `execution_allowed=false`. Discovery stays in PR320 and is never called here; one exact `aca_` artifact ID remains required.

`core/approved_change_capability_binding.py` is the PR322 capability-binding module. It is the only place ShellForgeAI states which governed implementation lane a declared capability names, and it names exactly one: `pr313.windows_runtime_reconcile`. The lane declaration is source-maintained and in-memory — never persisted, published, inventoried, loaded from disk, discovered from plugins, derived from `recipe_registry`, derived from a PR313 module, script name, filesystem entry, or environment variable, or supplied by a caller — and its only identity is the deterministic SHA-256 of its own canonical bytes. The operation validates the maintained catalog and the maintained lane declaration, computes both identities, and requires exact `hmac.compare_digest` matches against the caller's two explicit confirmations *before* touching the filesystem, so a malformed, stale, swapped, or mismatched confirmation reaches neither maintained authority. It owns no support decision and no loader: support comes only from the maintained PR321 evaluator, and the exact artifact identity and subject SHA-256 come only from one maintained PR319 exact-ID load, with any disagreement between the two failing closed. Binding is identity association, not compatibility: two entirely different approved subjects sharing the declared capability ID both bind, with distinct binding identities, and every result reports `binding_persisted=false`, `authorization_evaluated=false`, `preflight_evaluated=false`, `receipt_created=false`, and `execution_allowed=false`. The binding exists in memory only; there is no persisted binding artifact, ID, prefix, publisher, or loader, and no PR313 runtime is ever reached.

`core/approved_change_plan_link.py` is the PR323 plan-link module. It is the only place ShellForgeAI states which exact saved plan an approved binding names, and it states it as one canonical identity pair: the exact PR322 binding identity and the exact PR305/PR313 canonical plan SHA-256. The plan packet arrives already parsed from the caller and is read, never modified, never written, and never returned; the module accepts no plan path, no output path, no staged-source or durable-runtime root, and no `System32` path. Plan validation is never re-invented: acceptance, the executable-plan contract, and the canonical plan identity all come from the pure `core/windows_runtime_reconcile_plan_contract.py` seam, and the binding comes only from the maintained PR322 operation called exactly once. All three explicit confirmations are compared with `hmac.compare_digest` before any filesystem access, so a malformed, stale, swapped, or mismatched confirmation reaches neither the artifact subtree nor PR322. Linking is structural identity association, not semantic compatibility and not live readiness: only typed capability, lane, mode, recipe, allowlist, destination-parent-contract, and status facts are compared, so two materially different approved subjects sharing the declared capability ID may both link to the same valid plan with distinct link identities, and every result reports `subject_semantic_compatibility_evaluated=false`, `target_compatibility_evaluated=false`, `procedure_compatibility_evaluated=false`, `evidence_compatibility_evaluated=false`, `current_state_preflight_evaluated=false`, `authorization_evaluated=false`, `receipt_linked=false`, and `execution_allowed=false`. The link exists in memory only; there is no persisted plan-link artifact, ID, prefix, publisher, or loader, and no PR313 runtime is ever reached.

`core/approved_change_compatibility.py` is a separate compatibility-boundary module. It performs only in-memory findings assessment of legacy Proposal schema v1; it does not create an approved-change subject, attestation, contract, proposal mutation, adapter, migration, file loader, persistence record, recipe/preflight hook, receipt, CLI command, or execution path. Current Proposal behavior and mutation lanes are unchanged.

## Mutation boundary

The runtime never calls `subprocess` for arbitrary shell. Tools wrap
specific binaries with bounded args via `util.subprocess`. Only three
narrow mutation lanes exist; everything else is read-only.

1. **ShellForgeAI-owned metadata cleanup.** `audit prune` (PR46) and
   `audit cleanup execute` (PR55 + PR71-hardened). Deletes
   ShellForgeAI-owned metadata under `<data_dir>` only. PR71 requires a
   matching validated archive whose fingerprint matches the plan, plus
   `--confirm`.
2. **Exact-container Docker restart.** `apply <approved-proposal>
   --execute --confirm` (PR47/PR48/PR49). Exactly one `docker restart
   <allowlisted-container>`. Allowlist disabled by default; env-gated.
3. **Compose service restart (disposable-only).** `mission compose-restart
   execute <id> --execute --confirm` (PR63+). Exactly one
   `docker compose ... restart <service>` against a disposable +
   allow_restart labelled target, only when the env-contract is fully
   satisfied. Blocked by default in production deployments — this is the
   intended posture.

What ShellForgeAI does not mutate, ever:

- `docker compose up/down/recreate`, `docker stop|start|kill|rm|exec|run`,
  Docker volume/network/image commands.
- `systemctl` / service control.
- `apt`/`yum`/`dnf`/`apk`/`pip` package operations.
- chmod / chown / rm / mv / cp on arbitrary paths.
- firewall / route / DNS / interface changes.
- Generated operator scripts or arbitrary shell strings.

## Data and artifact flow

See [`data-layout.md`](data-layout.md) for the full table. Each
artifact class has a single command that creates it, a defined set of
commands that read or refresh it, and an explicit mutation/non-mutation
posture.

## Design principles

- Read-only first; preview before proposal; proposal before approval.
- Approval before mission; rollback/recovery preview before any execute
  step; explicit `--confirm` before any mutation.
- Verify after mutation; write a receipt; preserve a tamper-evident
  audit trail.
- Refuse natural-language mutation. The only execution paths are the
  explicit CLI lanes above.
- Boring on purpose. Small sharp tool, not a broad control plane.
# Persisted plan-link provenance

The approved-change persistence layer includes a fixed, atomic no-replace
`approved_change_plan_links` subtree for exact PR323 link provenance. Its
distinct `acpl_` identity covers canonical payload bytes and grants no runtime
authority. Current-state revalidation remains a separate transient operation.


## Persisted plan-link current-state consumer

PR338 adds a local read-only API that consumes one exact PR337 `acpl_` artifact and one caller-supplied saved plan. It validates the plan through the maintained PR305/PR313 contract, validates the embedded PR323 link, compares persisted provenance to the supplied plan, gates governed-root inspection to native Windows, and then uses the shared PR328 live-state evaluator for the fixed two-file scope. It adds no CLI, interactive, provider/model, network, authorization, preflight, receipt, or execution path.

### Exact runtime-integrity evidence association

The reviewed-change chain can now proceed from exact approval provenance through capability binding, plan link, persisted `acpl_` provenance, and point-in-time governed-file state to a separate in-memory identity association with an exact ordered PR304 source-root/System32 evidence pair, then to a separate temporal freshness classification. The PR304 validator is pure; the acceptance CLI delegates to it. Freshness uses one untrusted evaluator-local UTC read and a fixed five-minute oldest-evidence window. It is separate from current-state validation and stops before authenticated identity, authorization, execution preflight, receipts, and execution.

PR304 collection brackets its existing bounded host observation with local wall-clock UTC and a local monotonic counter. The exact observation mapping participates in the existing canonical packet identity; the pure validator only parses caller-supplied values and reads no clock or environment. Two-packet stable comparison excludes chronology, while the evidence-set model reports bounded endpoint facts. These observational readings provide no trusted-time, freshness, authorization, or execution authority and introduce no network or mutation path.
