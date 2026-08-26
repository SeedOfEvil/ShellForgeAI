# Operator solution contract

`shellforgeai.core.operator_solution` defines the versioned, platform-neutral
North Star endpoint for an evidence-backed operator handoff. Version `v1` is a
normalized domain contract, not a persisted artifact. Maintained Linux/Docker
and Windows-native producers translate structured evidence authorities into the
contract, and the handoff CLI can render it explicitly without embedding them.

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

## Deterministic Linux/Docker producer

`build_linux_operator_solution_from_diagnosis()` in
`shellforgeai.core.operator_solution_builder` is the single Linux/Docker
producer. Its input authority is an already-completed `DiagnosisResult`; it
reuses `build_runbook()` over that diagnosis's existing evidence and findings,
then normalizes the result into the canonical `OperatorSolution`. It does not
diagnose, collect evidence, call a provider/model, invoke commands, persist an
artifact, authorize work, or execute a procedure.

Critical and warning findings can become likely causes. Information and
limitation findings cannot; limitations instead contribute to the visibility
boundary. Every generated cause, procedure step, and verification criterion
declares a bounded logical evidence, finding, plan, or runbook reference.
References never contain raw evidence or whole upstream objects, and the
producer does not invent source SHA-256 values.

Runbook corrective options supply prerequisites, impact, risk, ordered
operator-run procedure, rollback, and verification when available. The
diagnosis proposed plan is a conservative procedure fallback. Distinct options
for distinct problems form one recommended procedure rather than fabricated
alternatives. Rollback is present only when selected change guidance owns
actual rollback instructions; otherwise recovery is explicitly not applicable.

The producer rejects structured Windows diagnoses, unusable/empty evidence,
destructive fallback plan steps, and diagnosis safety flags that report
execution or mutation. The builder's solution ID is a bounded hash of semantic session, target, and
target type values. Diagnosis/plan timestamps, random plan IDs, runbook generation
times, clocks, UUIDs, paths, and runtime environment metadata do not participate
in the canonical output. Consequently, semantically identical recreated inputs
produce byte-identical canonical JSON, Markdown, and solution SHA-256.

## Deterministic Windows-native producer

`build_windows_operator_solution_from_evidence()` in
`shellforgeai.core.windows_operator_solution_builder` is the corresponding
Windows-native producer. It consumes only an already-built bounded packet from
the structured `windows_evidence_context` contract, an already-classified
`WindowsOperatorRoute`, and minimal target/session semantics. It neither calls
the packet builder nor classifies raw operator text. It performs no collection,
routing, provider/model call, CLI or handoff callback, persistence, host access,
approval, preflight, authorization, or execution.

Observed Windows memory, disk/volume, process, service, event, and network
metadata contributes only a concise assessment. The producer does not treat a
stopped service as a failure, missing metrics as healthy, interface metadata as
end-to-end network health, or absent event evidence as proof that no crash
occurred. It creates no likely cause when the bounded packet cannot support one.
Packet limitations, evidence gaps, unavailable components, and the point-in-time
boundary remain first-class visibility limits.

The ordered advisory procedure is drawn from the maintained read-only Windows
safe-command authority for the structured route. Verification requires fresh
read-only evidence and comparison with the original snapshot. Because the
procedure is non-mutating, recovery is `not_applicable` and no rollback guidance
is fabricated. Logical evidence/route provenance contains neither raw payloads
nor invented hashes.

Stable semantic target, session, route, observations, and visibility inputs
determine the bounded solution identity. Mapping insertion order, limitation
ordering, incidental metadata, clocks, paths, random values, and runtime state do
not affect the canonical solution. Equivalent structured inputs therefore yield
byte-identical canonical JSON, Markdown, and solution SHA-256.

## Canonical handoff rendering

`shellforgeai handoff --operator-solution` renders the maintained canonical
solution for the current Linux/Docker or native Windows host. Linux uses one
completed diagnosis and `build_linux_operator_solution_from_diagnosis()`;
Windows uses one bounded native evidence packet, the maintained handoff route,
and `build_windows_operator_solution_from_evidence()`. Human output comes from
the canonical Markdown renderer. Adding `--json` emits the canonical
`OperatorSolution` JSON directly, without a handoff wrapper.

Pure, unsaved natural-language handoff requests in evidence-aware `ask` and
interactive mode render that same canonical Markdown on supported Linux/Docker
and native Windows hosts. They consume the maintained final handoff route,
collect once, build once, and render once; they do not reclassify prose, call a
model, persist an artifact, authorize work, or execute procedure text. Save
handoff requests retain the legacy V2 lifecycle, and mixed handoff/action
requests remain refused. A canonical production failure is bounded and does
not fall back to the legacy handoff or a model.

Natural-language Windows planning/help in `ask` and interactive mode also uses
one bounded native Windows evidence packet and this same producer, then renders
the canonical `OperatorSolution` Markdown. The route is advisory and read-only:
it does not call a model, execute a procedure, or authorize an action. Missing
evidence remains visible as limitations and unresolved questions. Direct
natural-language mutation continues to be refused, and the standalone V2
`propose` contract is unchanged.

On Linux, evidence-aware pure planning/help uses the same canonical Markdown
when maintained intent/routing output already supplies a concrete target or
diagnostic scope. The adapter performs one read-only diagnosis, passes that
completed result once to the Linux/Docker producer, and renders the resulting
solution once. It does not classify prose or invent a host, container, or
service identity. Unresolved prompts retain bounded plan-only guidance; mixed
planning plus a distinct requested action remains refused. `ask --no-evidence`
does not enter this route. Canonical natural-language rendering calls no model,
persists nothing, authorizes nothing, and executes nothing; standalone V2
`propose` behavior is unchanged.

This mode remains advisory-only and read-only. It does not call a model, execute
procedure text, or mutate a host. Adding `--save` publishes the same solution
once beneath `<data_dir>/operator_solutions/<artifact_id>/`; `--json` and
`--target` remain supported with save. The default
`shellforgeai handoff` command and its save/validate/export/history/compare V2
artifact lifecycle remain supported unchanged for compatibility. Report
integration and migration or replacement of the legacy V2 artifact lifecycle
remain deferred. Neither producer or rendering mode adds an executor interface.

## Optional canonical artifact persistence

The core persistence authority can durably publish an **already-validated**
canonical `OperatorSolution`. The handoff CLI's explicit canonical `--save`
mode calls this authority exactly once with the same solution it built exactly
once. `solution_id` remains the producer-owned semantic identity. The
separate persisted identity is `osol_<64 lowercase hex>`, where the full
SHA-256 is derived only from the exact UTF-8 bytes returned by
`canonical_operator_solution_json()`. Time, randomness, paths, host data,
publication state, and the artifact ID itself do not enter that identity.

The only layout is
`<data_dir>/operator_solutions/<artifact_id>/operator-solution.json` and
`operator-solution.md`. The files are, respectively, the exact canonical JSON
and exact `render_operator_solution_markdown()` output owned by this contract;
there is no persistence envelope or decoration. Publication writes and flushes
both files in a private sibling directory, validates the complete private
representation, and uses one maintained atomic no-replace directory transition
before validating the durable result. An existing identical artifact is a
no-rewrite success. A partial, malformed, tampered, unsafe, or conflicting
destination fails closed and is never overwritten, repaired, deleted, or
normalized in place.

Loading accepts only an exact canonical persisted ID and derives the fixed path
and filenames internally. It refuses traversal, symlink/reparse indirection,
unexpected entries or file types, and oversized files. It strictly decodes and
validates the JSON as an `OperatorSolution`, regenerates and compares both
canonical JSON and Markdown exactly, and recomputes the requested content
identity. No partial or repaired object is returned.

`shellforgeai handoff operator-solution-validate <osol_id> [--json]` is the
bounded, read-only CLI projection of that loader. It accepts only the exact
`osol_<64 lowercase hex>` identity; it does not accept a path or perform fallback
interpretation. The command reports `loaded`, `not_found`, `invalid_id`,
`invalid`, or `load_blocked`, along with bounded access and byte-count metadata,
but never displays the loaded `OperatorSolution`. Only `loaded` is a successful,
valid result. This validates **persisted artifact integrity only**. It does not
establish freshness, current host state, current-state validity, approval,
authorization, execution eligibility, or successful execution.

Persistence and loading perform no evidence collection, model/provider call,
operational host inspection, network operation, shell/subprocess, Docker, or
PowerShell operation. Persistence does not imply approval, authorization,
freshness, preflight, execution, verification, remediation, or rollback or
recovery permission. The persisted solution retains its advisory-only,
read-only, non-executed operational safety ledger; storing bytes is not an
operational mutation described by that ledger.

The canonical contract and Linux/Docker and Windows producers remain unchanged,
as do canonical handoff rendering and the legacy V2 lifecycle. Save reports
`published` or `already_present` as success and reports `conflict` or
`publication_blocked` as a controlled failure. Its bounded result includes the
artifact identity, fixed relative location, write/no-op state, and the unchanged
`mutation_performed=false` and `execution_status=not_executed` safety state.
