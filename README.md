# ShellForgeAI

ShellForgeAI is a CLI-first operator assistant that turns live system evidence into a diagnosis, a reviewable plan, and an operator-ready solution handoff. It helps on-call operators, platform owners, and maintainers move from an unclear incident to practical next steps without giving up control.

**Maturity:** [V1 is released and early beta-quality](docs/PRODUCT_STATUS.md). Linux/Docker is the released V1 core. Windows is validated preview/early support.

## Evidence-backed operator guidance

ShellForgeAI follows one primary workflow:

**Observe → Investigate → Diagnose → Plan → Recommend → Validate → Report → Handoff**

- **Observe and investigate:** recognized operations intents route to bounded, typed, read-only collectors before any model call.
- **Diagnose:** deterministic assessment ranks likely disk, performance, health, firewall, service, and Docker causes while preserving evidence and provenance.
- **Plan and recommend:** ShellForgeAI turns findings into an ordered operator procedure with expected impact and safe decision points.
- **Validate:** it checks the recommendation, prerequisites, verification criteria, and rollback or recovery guidance. Validation does not execute the procedure.
- **Report and hand off:** saved reports and handoff packets preserve facts, uncertainty, next steps, and verification criteria for the operator or next reviewer.

The result is operator-ready guidance: a specific target and desired outcome, evidence-backed diagnosis, prerequisites, ordered procedure, verification criteria, rollback or recovery guidance, limitations, and remaining risks.

## Evidence and model reasoning

Typed collectors and deterministic assessment establish the factual base. When configured, a model synthesizes that bounded evidence into a clearer explanation and solution; it does not run ShellForgeAI tools or turn free-form text into commands. Provider failure leaves the deterministic evidence available.

ShellForgeAI is read-only by default. Deterministic mutation refusal applies to mutation-shaped asks, unsafe broad mutation is refused, and unknown slash commands never reach a model. Existing confirm-gated execution and remediation utilities remain bounded, governed compatibility/testing surfaces outside the primary recommended workflow; they are not a natural-language mutation agent or production-autonomous operation.

## Quick start

```bash
shellforgeai doctor
shellforgeai status
shellforgeai triage --brief
shellforgeai ask "what should I inspect first?" --explain-evidence
shellforgeai ops report --save
shellforgeai handoff --save
```

Useful focused views include:

```bash
shellforgeai triage docker detail <target>
shellforgeai remediation eligibility --target <target> --explain
shellforgeai ops report history
shellforgeai ops report compare-latest
```

Run `shellforgeai --help` for the complete command surface.

## Install

ShellForgeAI currently installs from repository source and requires Python 3.12 or newer.

```bash
git clone https://github.com/SeedOfEvil/ShellForgeAI.git
cd ShellForgeAI
python -m pip install -e .
```

Contributor setup:

```bash
python -m pip install -e ".[dev]"
```

The installed console commands are `shellforgeai` and `sfai`.

## Platforms

- **Linux/Docker:** primary supported V1 operating lane and release-validation basis.
- **Windows:** validated preview/early support for bounded local evidence and operator guidance, including Windows Server 2025 workflows. See [Windows/PowerShell V1](docs/WINDOWS_POWERSHELL_V1.md).
- **Other platforms:** conversation and help remain available, while unsupported operator evidence routes fail closed and direct the operator to platform diagnostics.

## Documentation

- [Product status](docs/PRODUCT_STATUS.md), [V1 scope](docs/v1-scope.md), and [Safety](docs/safety.md)
- [North Star](docs/north-star.md) and [Roadmap](docs/roadmap.md)
- [Architecture](docs/architecture.md), [CLI reference](docs/cli.md), and [Operator demo](docs/demo.md)
- [V1 command surface](docs/V1_COMMAND_SURFACE.md) and [Command surface audit](docs/COMMAND_SURFACE_AUDIT.md)
- [V1 validation](docs/V1_VALIDATION.md), [release candidate checklist](docs/V1_RELEASE_CANDIDATE.md), and [V1 release notes](docs/V1_RELEASE_NOTES.md)
- [Project history archive](docs/archive/PROJECT_HISTORY.md)

The permanent direction lives in [North Star](docs/north-star.md); current maturity and released behavior remain owned by the active status, scope, and safety documents.
