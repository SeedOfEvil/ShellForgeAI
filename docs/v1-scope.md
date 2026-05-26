# V1 Scope and Release Contract

## V1 contract

Authoritative release promotion checklist: [`docs/V1_RELEASE_CANDIDATE.md`](V1_RELEASE_CANDIDATE.md).

ShellForgeAI V1 is a CLI-first Linux/Docker operator knife. It safely inspects
Linux/Docker scenes, ranks suspects, creates evidence-backed operator reports,
saves/validates/exports/compares those reports, routes common operator asks
deterministically, and refuses or gates mutation.

## V1 core capabilities

1. Runtime/health
   - `shellforgeai --version`
   - `shellforgeai doctor`
   - `shellforgeai model doctor`
   - `shellforgeai self-test commands`
   - `shellforgeai remediation self-test`
2. Linux/Docker inspection
   - deterministic Docker triage ranking (`triage docker`)
   - deterministic triage detail (`triage docker detail <target>`)
   - diagnose/triage cohesion for container targets
   - no mutation in inspection lanes
3. Ops report lifecycle
   - `shellforgeai ops report`
   - `shellforgeai ops report --json`
   - `shellforgeai ops report --save`
   - `shellforgeai ops report validate`
   - `shellforgeai ops report history`
   - `shellforgeai ops report compare`
   - `shellforgeai ops report compare-latest`
   - `shellforgeai ops report export`
   - `shellforgeai ops report export-validate`
4. Deterministic ask routing
   - 2AM/operator prompts route to deterministic ops report/triage paths
   - “what is on fire” style prompts route deterministically
   - mutation prompts refuse deterministically with safe read-only alternatives
5. Governed remediation preview/testing
   - eligibility and explain surfaces
   - plan/validate/preflight metadata and receipts
   - self-test coverage for quick/full profiles
   - disposable proof paths clearly labeled
   - no casual production remediation in V1

## V1 non-goals

V1 is not an autonomous infra repair agent, production remediation bot, web UI,
secrets manager, monitoring platform replacement, SIEM replacement, generalized
knowledge/research engine, or broad “AI can do everything” framework.

V1 does not run arbitrary shell from user prompts, mutate production from
natural language, or casually prune/delete/restart broad infrastructure.

## Supported environment assumptions

- Linux host or Linux container runtime context.
- Docker-oriented evidence collection available for container triage/report.
- No external internet requirement for deterministic safety routes.
- Model/provider availability is optional for deterministic safety/reporting
  routes; refusal and deterministic operator paths remain available.

## Mutation boundaries

- Read-only by default.
- Natural-language mutation requests are deterministically refused.
- Governed mutation lanes are explicit, gated, and documented as disposable
  proof/testing pathways.
- Production mutation is not part of the V1 release promise.
- No autonomous production remediation.

## V1 release acceptance checklist

- README clearly states what ShellForgeAI is and is not.
- Architecture documents CLI → collectors → triage → ops reports → artifacts → governed remediation.
- Safety docs state read-only defaults, mutation refusal, and governed gates.
- Demo docs provide a 5-minute Linux/Docker workflow and mutation refusal demo.
- Docs use canonical safe commands (`ops report`, `--save`, `history`, `compare-latest`, triage detail, remediation eligibility).
- Docs avoid casual dangerous commands outside clearly gated sections.
- Regression tests cover doc presence, V1 command spine, and safety wording.

- Release acceptance includes: `shellforgeai v1 check --profile standard --json` passes.

## Command inventory reference

For the auditable V1 command inventory and safety classification matrix, see
[`docs/V1_COMMAND_SURFACE.md`](V1_COMMAND_SURFACE.md).
