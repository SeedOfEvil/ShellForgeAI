# ShellForgeAI V1 Release Notes

Release line: **V1 baseline / 1.0.0**  
Date: **2026-05-26**

## 1) What ShellForgeAI is

ShellForgeAI V1 is a **CLI-first Linux/Docker operator knife** for quick troubleshooting and status checks.

It is built for:

- evidence-backed operator reporting and handoff artifacts,
- deterministic routing of common operator asks,
- deterministic refusal for risky natural-language mutation asks.

## 2) What ShellForgeAI is not

ShellForgeAI V1 is intentionally narrow:

- not an autonomous remediation agent,
- not a production repair bot,
- not a web UI,
- not a monitoring platform,
- not a SIEM,
- not a secrets manager,
- not a broad infrastructure platform.

## 3) Core V1 capabilities

- `doctor` / `model doctor` / runtime hygiene checks
- deterministic Docker triage (`triage docker`)
- triage detail (`triage docker detail <target>`)
- `ops report`
- `ops report` save/validate/export/export-validate
- `ops report` history/compare/compare-latest
- deterministic 2AM ask routing
- deterministic mutation refusal
- remediation eligibility/explain
- remediation self-test
- V1 readiness check (`v1 check`)
- V1 packet save/validate/export/history/compare
- V1 validation helper (`./scripts/v1_validate.sh`)

## 4) Safety boundaries

- read-only by default,
- no natural-language mutation execution,
- no arbitrary shell execution,
- no `shell=True`,
- no casual production restart,
- no Docker Compose mutation in V1,
- remediation execution is governed/disposable-only and not part of casual V1 demo path,
- cleanup execution remains gated and deliberate.

## 5) Validated release evidence (PR119, human summary)

- Docker01 container healthy.
- V1 quick and standard checks passed.
- Ops report JSON and artifact lifecycle checks passed.
- Deterministic ask route passed.
- Deterministic mutation refusal passed.
- Remediation self-test full passed.
- V1 packet/export validation passed in the dev-validation lane.
- Targeted and regression pytest checks passed.
- Safety invariants held across validation runs.

## 6) Known caveats

- Historical metadata hygiene warning may appear in long-lived lab data.
- `v1_validate` packet/export helpers require a dev-validation lane (not minimal runtime image).
- Some output remains dense for tired operators.
- V1 is CLI-only by design.
- Production remediation is not V1.

## 7) Recommended first commands

```bash
shellforgeai doctor
shellforgeai model doctor
shellforgeai v1 check --profile quick
shellforgeai ops report
shellforgeai ops report --save
shellforgeai ops report history --limit 5
shellforgeai ops report compare-latest
shellforgeai triage docker detail <target>
shellforgeai remediation eligibility --target <target> --explain
```

## 8) Release sign-off template

Copy/paste and complete:

```text
ShellForgeAI V1 Sign-off

Version / Commit:
Image:
Validation date:
Validation host:

Checks passed:
- Docker01 healthy:
- v1 check quick:
- v1 check standard:
- ops report lifecycle:
- deterministic ask route:
- deterministic mutation refusal:
- remediation self-test full:
- v1 packet/export validation (dev-validation lane):
- targeted/regression pytest:

Safety invariants:
- no remediation execute in normal V1 validation path
- no rollback execute in normal V1 validation path
- no cleanup execute in normal V1 validation path
- no Docker/Compose mutation in normal V1 validation path
- no production restart
- no shell=True / arbitrary command execution
- no natural-language mutation execution

Known caveats:

Release verdict: V1-ready | V1-ready with caveats | V1-blocked
```
