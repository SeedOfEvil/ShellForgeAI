# V1 Command Surface and Safety Classification

## Purpose

Release-candidate gate and required validation commands: [`docs/V1_RELEASE_CANDIDATE.md`](V1_RELEASE_CANDIDATE.md).

This document is the ShellForgeAI V1 command inventory and safety map. It
makes the V1 command surface explicit and auditable: what each command does,
which safety class it belongs to, whether it is read-only, whether it writes
ShellForgeAI-owned artifacts, and whether it can mutate Docker/system state.

## Safety classes

- **READ_ONLY**
  - No file writes.
  - No Docker/system mutation.
- **ARTIFACT_WRITE**
  - Writes only ShellForgeAI-owned artifacts (reports/exports/metadata).
  - No Docker/system mutation.
- **GOVERNED_PLAN_ONLY**
  - Creates/validates/preflights plans/metadata/receipts.
  - No mutation execution.
- **GOVERNED_DISPOSABLE_MUTATION**
  - Mutation can occur only for explicit disposable/allowlisted targets behind
    `--execute --confirm` and lane-specific gates.
  - Not part of casual V1 demo flow.
- **REFUSED_BY_DEFAULT**
  - Natural-language mutation asks and broad mutation prompts are refused and
    rerouted to read-only evidence paths.
- **OUT_OF_V1**
  - Explicitly outside V1 release promise.

## V1 core commands

| Command | Role | Safety class | Writes ShellForgeAI artifacts? | Mutates Docker/system? | Notes |
|---|---|---|---|---|---|
| `shellforgeai version` | Runtime version check | READ_ONLY | No | No | Fast CLI sanity check. |
| `shellforgeai doctor` | Runtime health baseline | READ_ONLY | No | No | Read-only runtime checks. |
| `shellforgeai model doctor` | Provider/model diagnostics | READ_ONLY | No | No | Safety routes remain deterministic without model auth. |
| `shellforgeai v1 check --profile quick` | V1 quick readiness | READ_ONLY | No | No | Contract and safety checks only. |
| `shellforgeai v1 check --profile standard` | V1 standard readiness | READ_ONLY | No | No | Read-only readiness checks. |
| `shellforgeai v1 packet` | V1 readiness packet summary | READ_ONLY | No | No | Aggregates docs/surface/readiness/report/refusal/self-test/safety into non-mutating packet payload. |
| `shellforgeai v1 packet --save` | V1 packet artifact write | ARTIFACT_WRITE | Yes | No | Writes `/data/v1_packets/<packet_id>` with packet json/md/manifest. |
| `shellforgeai v1 packet validate <packet-ref>` | Validate saved packet | READ_ONLY | No | No | Validates packet files, checksums, safety and status consistency. |
| `shellforgeai v1 packet export <packet-ref>` | Export saved packet | ARTIFACT_WRITE | Yes | No | Writes `/data/exports/export_<packet_id>` bundle. |
| `shellforgeai v1 packet export-validate <export-ref>` | Validate packet export | READ_ONLY | No | No | Validates exported packet bundle and safety metadata. |
| `shellforgeai v1 packet history [--limit N]` | List saved packets | READ_ONLY | No | No | Lists saved V1 packets newest-first without creating/validating/exporting artifacts. |
| `shellforgeai v1 packet compare <before> <after>` | Compare two packets | READ_ONLY | No | No | Compares saved packet artifacts by id/path for readiness/safety/check drift only. |
| `shellforgeai v1 packet compare-latest` | Compare latest two packets | READ_ONLY | No | No | Resolves latest two saved packets and compares read-only; returns controlled not_enough_history when fewer than two. |
| `shellforgeai triage` | V2 deterministic suspect ranking entrypoint | READ_ONLY | No | No | Shows top suspect, evidence summary, and first safe command; no remediation execution. |
| `shellforgeai triage --target <target>` | V2 deterministic suspect detail | READ_ONLY | No | No | Wraps Docker triage detail with first safe eligibility command. |
| `shellforgeai apply-preview` | V2 execution-boundary preview | READ_ONLY | No | No | Shows no-action/blocked/gated apply requirements only; no apply, mission, remediation, rollback, Docker, Compose, restart, shell, or model execution. |
| `shellforgeai apply-preview --target <target>` | V2 exact-target execution-boundary preview | READ_ONLY | No | No | Refuses production targets and unknown targets; no action created or executed. |
| `shellforgeai triage docker` | Deterministic suspect ranking compatibility path | READ_ONLY | No | No | No remediation execution. |
| `shellforgeai triage docker --brief` | Safe alias mirroring `triage --brief` | READ_ONLY | No | No | Bounded brief triage view; no mutation. |
| `shellforgeai triage docker detail <target>` | Deterministic deep detail | READ_ONLY | No | No | Container-focused evidence detail. |
| `shellforgeai ops report` | Operator report synthesis | READ_ONLY | No | No | Evidence-backed report view. |
| `shellforgeai ops report history` | Report history view | READ_ONLY | No | No | Reads saved artifacts only. |
| `shellforgeai ops report compare-latest` | Latest report delta | READ_ONLY | No | No | Compares existing artifacts only. |
| `shellforgeai remediation eligibility --target <target> --explain` | Governed lane eligibility preview | READ_ONLY | No | No | Explains whether governed remediation lane could apply. |

## Artifact lifecycle commands

These commands preserve/export/compare ShellForgeAI-owned artifacts. They do
not mutate Docker/system state.

| Command | Safety class | Writes ShellForgeAI artifacts? | Mutates Docker/system? | Notes |
|---|---|---|---|---|
| `shellforgeai ops report --save` | ARTIFACT_WRITE | Yes | No | Saves report artifact. |
| `shellforgeai ops report validate` | READ_ONLY | No | No | Validates existing report artifact content. |
| `shellforgeai ops report export <report>` | ARTIFACT_WRITE | Yes | No | Writes export bundle. |
| `shellforgeai ops report export-validate <export>` | READ_ONLY | No | No | Validates export bundle. |
| `shellforgeai ops report history` | READ_ONLY | No | No | Lists saved reports. |
| `shellforgeai ops report compare <left> <right>` | READ_ONLY | No | No | Diff of existing reports. |
| `shellforgeai ops report compare-latest` | READ_ONLY | No | No | Diff latest two reports. |
| `shellforgeai triage docker snapshot --save` | ARTIFACT_WRITE | Yes | No | Saves triage snapshot artifact. |
| `shellforgeai triage docker snapshot validate <snapshot>` | READ_ONLY | No | No | Validates saved snapshot. |
| `shellforgeai triage docker snapshot export <snapshot>` | ARTIFACT_WRITE | Yes | No | Exports snapshot bundle. |
| `shellforgeai triage docker snapshot compare <left> <right>` | READ_ONLY | No | No | Snapshot diff only. |
| `shellforgeai triage docker snapshot timeline` | READ_ONLY | No | No | Read-only timeline of snapshots. |
| `shellforgeai v1 check --profile full` | ARTIFACT_WRITE | Yes (validation artifacts) | No | May write ShellForgeAI-owned validation artifacts depending on profile output options. |

## Ask routing commands

Deterministic ask routing is part of V1 safety. Safety-critical routes do not
require model auth.

- **2AM operator report asks** (example: `shellforgeai ask "It's 2AM; give me an operator report."`)
  - Route: deterministic ops-report/triage path.
  - Class: READ_ONLY.
- **"what is on fire" prompts**
  - Route: deterministic triage + ops-report summary path.
  - Class: READ_ONLY.
- **mutation prompts** (example: `shellforgeai ask "restart everything now"`)
  - Route: deterministic refusal with safe read-only alternatives.
  - Class: REFUSED_BY_DEFAULT.

## Governed remediation lane

Governed remediation in V1 is separation-first: planning and evidence are in
scope; disposable-gated execution is never a casual step.

- `shellforgeai remediation eligibility --target <target> --explain` → READ_ONLY
- `shellforgeai remediation self-test --profile quick|standard` → READ_ONLY
- `shellforgeai remediation plan` / `validate` / `preflight` → GOVERNED_PLAN_ONLY
- `shellforgeai remediation receipt` / `report` / `audit` / `bundle` → GOVERNED_PLAN_ONLY

Disposable mutation lane (governed-only, not casual V1 demo path):

- `shellforgeai remediation execute --execute --confirm` → GOVERNED_DISPOSABLE_MUTATION
- `shellforgeai remediation rollback-execute --execute --confirm` → GOVERNED_DISPOSABLE_MUTATION

Both execution forms require explicit disposable/allowlist gates and are not
part of normal V1 operator report flow. **Production remediation is not V1.**

## Non-goals / out of V1

OUT_OF_V1 includes:

- Production autonomous remediation.
- Broad Docker restart/delete/prune actions (`docker restart`, `docker system prune`, `docker volume prune`).
- Broad Docker Compose mutation (`docker compose restart`, `docker compose up`, `docker compose down`).
- Arbitrary shell execution (including `shell=True` style execution paths).
- Web UI expansion.
- Secrets/config/inventory platform sprawl.

## V1 demo safe path

Safe demo commands (read-only + artifact-preserving only):

1. `shellforgeai doctor`
2. `shellforgeai v1 check --profile quick`
3. `shellforgeai ops report`
4. `shellforgeai ops report --save`
5. `shellforgeai ops report history --limit 5`
6. `shellforgeai ops report compare-latest`
7. `shellforgeai triage`
8. `shellforgeai apply-preview`
9. `shellforgeai triage --target <target>` (compatibility: `shellforgeai triage docker detail <target>`)
10. `shellforgeai remediation eligibility --target <target> --explain`
11. `shellforgeai ask "It's 2AM; what is on fire?"`
12. `shellforgeai ask "please restart shellforgeai"` (expected deterministic mutation refusal)

No casual execution steps are part of this path.

## Release checklist

- `./scripts/v1_validate.sh --quick`
- `./scripts/v1_validate.sh --full`
- `./scripts/v1_validate.sh --full --packet` (validation helper ARTIFACT_WRITE; writes V1 packet artifacts only)
- `shellforgeai v1 check --profile quick --json`
- `shellforgeai v1 check --profile standard --json`
- `shellforgeai v1 check --profile full --json`
- `shellforgeai ops report --json`
- deterministic ask-route check (`2AM operator report` / `what is on fire`)
- mutation refusal check (`restart/delete/prune` prompts)
- `pytest -q`


## V2 support: governed recipe registry

`recipes` and `safe-actions` are V2 support commands, not V1 mutation lanes.
They classify the future locked toolbox, expose strict JSON safety flags, and
perform read-only eligibility checks for named recipes/targets. They do not
execute cleanup, remediation, rollback, Docker/Compose mutation, container
restart, production restart, arbitrary shell commands, or natural-language
mutation.
