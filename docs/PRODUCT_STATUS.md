# Product status

This is the canonical active maturity source for ShellForgeAI.

> Overall product maturity: V1 released; early beta-quality; guarded and not production-autonomous.
> Primary operating lane: Linux/Docker is the supported V1 core and the basis of release validation.
> Windows support: Preview/early support for local, read-only evidence, deterministic operator guidance, and validated Windows Server 2025 workflows. Windows platform maturity does not change the overall product classification.
> Other platforms: No supported operational lane is currently promised.

## What the maturity terms mean

**Early beta-quality** means V1 is released and usable for its supported lane, while operator experience, packaging, documentation, and platform breadth are still being hardened. Operators should expect a guarded CLI product with active validation, not a fully polished autonomous operations platform.

**Guarded** means ShellForgeAI favors evidence, review, approval, and receipts over direct action. Model output is advisory and grounded in collected evidence. Named, bounded workflows and explicit approval or confirmation protect mutation paths; current-state gates, verification, receipts, and audit artifacts keep operators in control.

**Not production-autonomous** means ShellForgeAI does not independently repair production infrastructure, run arbitrary shell from prompts, or improvise broad cleanup/restart/remediation. This boundary does not mean V1 is unreleased or Alpha: V1 is released, early beta-quality, guarded, and operator-controlled.

## Where to go next

- [Safety](safety.md) details refusal, approval, verification, and receipt boundaries.
- [V1 scope](v1-scope.md) defines the release contract and core Linux/Docker lane.
- [Windows/PowerShell V1](WINDOWS_POWERSHELL_V1.md) describes preview Windows evidence support.
- [Validation matrix](VALIDATION_MATRIX.md) summarizes maintained validation evidence.
- [V1 release notes](V1_RELEASE_NOTES.md) preserve release-line notes.
- [Roadmap](roadmap.md) describes current, near-term, and later product direction.
