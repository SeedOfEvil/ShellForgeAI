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
execution or mutation. Windows-native production is deferred to PR361. The
builder's solution ID is a bounded hash of semantic session, target, and target
type values. Diagnosis/plan timestamps, random plan IDs, runbook generation
times, clocks, UUIDs, paths, and runtime environment metadata do not participate
in the canonical output. Consequently, semantically identical recreated inputs
produce byte-identical canonical JSON, Markdown, and solution SHA-256.

CLI, artifact persistence, and report/handoff integration remain deferred to
PR360. This producer adds no executor interface or broader runtime surface.
