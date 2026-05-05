# AGENTS

Conventions for any agent (human or LLM) modifying ShellForgeAI.

## Invariants — must be preserved

- **Safety boundary.** No arbitrary shell execution from interactive mode, no
  destructive execution anywhere, no package installs, no service restarts.
  `apply` remains validation-only in this alpha. Workspace trust never lifts
  policy.
- **CLI surface.** Do not break:
  - launching with no subcommand (interactive mode)
  - `--help` and `--version`
  - existing non-interactive subcommands (`doctor`, `diagnose`, `research`,
    `plan`, `apply`, `ask`, `audit`, `tools`, `inspect`, `model`)
- **Evidence-first routing.** Recognized ops intents (disk, performance,
  health, firewall, service) must run typed read-only collectors before any
  model call. Slash commands are deterministic; unknown slash commands must
  not call the model.
- **UX.** Normal synthesized answers hide internal collector names; technical
  names stay in `/tools`, `/evidence`, debug, and raw views.

## Documentation

- Update relevant `docs/*.md` and `README.md` when changing user-visible
  behavior.
- Do not append PR-numbered changelog blobs to docs. Document the current
  behavior; use git history / PR descriptions for what-changed-when.
- Before opening a PR, complete the documentation-impact checklist in
  `.github/PULL_REQUEST_TEMPLATE.md`.

## Codex provider note

In the current architecture, Codex is used as a model/provider for synthesis
only. ShellForgeAI's typed tools are executed by the ShellForgeAI runtime,
not by Codex. Runtime context bundles are the immediate solution; an optional
read-only MCP surface is a future path (see `docs/codex-integration.md`).
