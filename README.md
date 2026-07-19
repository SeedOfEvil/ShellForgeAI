# ShellForgeAI

ShellForgeAI is a guarded operator assistant for Linux and Docker.

ShellForgeAI turns messy Linux and Docker incidents into ranked evidence, reviewable next steps, and auditable handoffs—without surrendering operator control.

It helps on-call operators, platform owners, and maintainers answer practical questions such as "what looks unhealthy?", "what should I inspect first?", and "what evidence should I hand to the next reviewer?" The product is CLI-first Linux/Docker operator tooling and evidence-first: it collects evidence-backed typed read-only signals, ranks likely suspects, explains what it found, and keeps action behind named guarded workflows.

**Maturity:** [V1 released and early beta-quality](docs/PRODUCT_STATUS.md). ShellForgeAI is guarded, operator-controlled, and not production-autonomous. Linux/Docker is the primary V1 lane; Windows support is preview/early support.

## What this is

ShellForgeAI is a guarded operator assistant for Linux and Docker.

## What it helps with

## What ShellForgeAI helps you accomplish

- Understand unhealthy Linux/Docker state from real local evidence and validation lane context.
- Rank likely Docker, host, service, disk, network, and health suspects.
- Answer 2AM operator questions without guessing or hiding evidence.
- Produce reviewable reports, manifests, receipts, and shift handoffs.
- Save, validate, export, and compare evidence over time.
- Use grounded model assistance when a configured provider is available.
- Preview and govern actions with operator approval instead of autonomous repair.

## What this is not

ShellForgeAI is not self-healing infrastructure, not a natural-language mutation agent, and not production-autonomous.

## Core workflows

### 2AM Docker triage

```bash
shellforgeai status
shellforgeai triage --brief
shellforgeai triage docker detail <target>
```

Use this path when Docker feels broken and you need the first ranked suspects plus safe next inspection commands.

### Evidence-grounded ask

```bash
shellforgeai ask "what is on fire in Docker right now?"
shellforgeai ask "what should I inspect first?" --explain-evidence
```

Recognized operator questions route through deterministic read-only evidence before any synthesis. Mutation-shaped asks are refused and redirected to a safe read-only next command or review surface.

### Report, history, and compare

```bash
shellforgeai ops report --save
shellforgeai ops report history
shellforgeai ops report compare-latest
```

Use saved reports for incident follow-up, review packets, and drift comparison.

### Propose, preview, verify, and hand off

```bash
shellforgeai propose --from-triage
shellforgeai apply-preview --from-propose
shellforgeai verify --from-apply-preview
shellforgeai handoff --save
shellforgeai remediation eligibility --target <target> --explain
```

This is the guarded review path: propose a next step, preview the execution boundary, verify current state, and produce an auditable handoff. The preview path does not execute a fix.

## Operating model

## How it works

**Observe → Rank → Explain → Report → Review → Governed action → Verify → Receipt**

- **Typed evidence:** collectors gather bounded host, Docker, platform, and artifact data.
- **Deterministic triage:** known operations intents route to read-only collectors and ranking before model assistance.
- **Grounded model assistance:** model output is advisory and based on collected evidence when the provider is configured.
- **Auditable artifacts:** reports, exports, manifests, checksums, receipts, and handoffs preserve review context.
- **Approval-aware workflows:** named recipes, explicit confirmation, and current-state gates protect mutation paths.
- **Verification and receipts:** post-checks and receipt validation make outcomes reviewable.

## Guarded by design

ShellForgeAI treats safety as a product capability:

- Evidence-first routing for recognized disk, performance, health, firewall, service, Docker, and operator intents.
- Read-only by default for status, triage, ask, reports, previews, verification, and handoffs.
- Deterministic mutation refusal/routing: ShellForgeAI refuses unsafe broad mutation and unknown slash commands.
- Named, narrow, auditable recipes and bounded mutation workflows only where the command surface explicitly supports them.
- Explicit confirmation, approval metadata, current-state gates, verification, receipts, and audit trails.

ShellForgeAI is not production-autonomous. Detailed boundaries live in [Safety](docs/safety.md).

## Install

ShellForgeAI currently installs from the repository source.

```bash
git clone https://github.com/SeedOfEvil/ShellForgeAI.git
cd ShellForgeAI
python -m pip install -e .
```

For contributor tools:

```bash
python -m pip install -e ".[dev]"
# or, equivalently:
make dev
```

The project requires Python `>=3.12` and installs the console scripts `shellforgeai` and `sfai`.

## Quick start

```bash
shellforgeai doctor
shellforgeai status
shellforgeai triage --brief
shellforgeai ops report --save
shellforgeai handoff --save
```

Run `shellforgeai --help` for the full command surface.

## Where it runs

- **Linux/Docker:** primary supported V1 operating lane and release-validation basis.
- **Windows:** preview/early support for local read-only evidence, deterministic operator guidance, and validated Windows Server 2025 workflows. See [Windows/PowerShell V1](docs/WINDOWS_POWERSHELL_V1.md).
- **Other platforms:** no supported operational lane is currently promised.

## Documentation map

- [Product status](docs/PRODUCT_STATUS.md)
- [V1 scope and release contract](docs/v1-scope.md)
- [Demo and quick start](docs/demo.md)
- [V1 validation guide](docs/V1_VALIDATION.md)
- [CLI reference](docs/cli.md)
- [Safety](docs/safety.md)
- [Architecture](docs/architecture.md)
- [Windows support](docs/WINDOWS_POWERSHELL_V1.md)
- [Validation matrix](docs/VALIDATION_MATRIX.md)
- [V1 release notes](docs/V1_RELEASE_NOTES.md)
- [Roadmap](docs/roadmap.md)
- [Project history archive](docs/archive/PROJECT_HISTORY.md)

## Development and validation

Common local checks:

```bash
ruff format .
ruff check .
pytest -q
```

For command-surface changes, run the focused command-surface tests documented in [CLI reference](docs/cli.md). This README is product-facing; deeper safety catalogues, platform notes, and historical PR chronology live in the linked reference documents.
