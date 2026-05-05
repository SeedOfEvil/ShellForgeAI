# ShellForgeAI

A lean, CLI-first AI ops harness for Linux systems. ShellForgeAI collects
evidence with typed, read-only tools, proposes conservative plans, writes
auditable artifacts, and uses an LLM (default: OpenAI Codex CLI) only for
advisory synthesis.

> Status: alpha. `apply` is intentionally validation-only — ShellForgeAI
> never executes mutating commands automatically. Model output is advisory.

## Highlights

- **Read-only by default.** No arbitrary shell, no package install, no service
  restart, no destructive actions.
- **Evidence-first.** Recognized intents (disk, performance, health, firewall,
  service) auto-run typed read-only collectors before any model call.
- **Auditable.** Every session writes JSONL audit records and artifacts under
  the data dir.
- **Profiles.** `inspect`, `assisted`, `lab-direct`, `prod-readonly` gate which
  risk classes are allowed, asked, or denied.
- **Pluggable models.** Codex CLI (default), Ollama, vLLM, and any
  OpenAI-compatible endpoint (e.g. OpenRouter).
- **Interactive operator loop.** Run `shellforgeai` with no subcommand for a
  REPL with slash commands, workspace trust, and streaming synthesis.

## Install

Requires Python 3.12+.

```bash
git clone https://github.com/SeedOfEvil/ShellForceAI.git
cd ShellForceAI
make dev          # creates .venv and installs in editable mode with dev extras
# or:
pip install -e .
```

The CLI is exposed as both `shellforgeai` and `sfai`.

## Quick start

```bash
shellforgeai doctor                       # runtime health
shellforgeai inspect host                 # host snapshot
shellforgeai diagnose nginx               # evidence + conservative plan
shellforgeai diagnose disk --save-plan
shellforgeai research "nginx permission denied"
shellforgeai plan "investigate high disk usage"
shellforgeai audit list
shellforgeai ask "what is this machine doing?"
```

## Using OpenAI Codex / ChatGPT sign-in

ShellForgeAI does not read or manage ChatGPT credentials; authentication is
handled entirely by the Codex CLI.

1. Install Codex CLI: `npm install -g @openai/codex` (or `brew install --cask codex`).
2. Sign in: `codex login` (or `codex login --device-auth` for headless hosts).
3. Configure ShellForgeAI:
   ```bash
   export SHELLFORGEAI_MODEL_PROVIDER=openai-codex
   export SHELLFORGEAI_MODEL_NAME=gpt-5.5
   export SHELLFORGEAI_MODEL_FALLBACK=gpt-5.4
   export SHELLFORGEAI_CODEX_TIMEOUT_SECONDS=180
   ```
4. Verify: `shellforgeai model doctor`
5. Test: `shellforgeai ask "what is this machine doing?"`

See `docs/model-providers.md` for other providers.

## Interactive mode

Run `shellforgeai` (no subcommand) to start the operator loop:

```text
$ shellforgeai
sfai> /help
sfai> diagnose disk
sfai> ask what services are listening on this host?
sfai> /pending
sfai> /exit
```

Slash commands include `/help`, `/status`, `/doctor`, `/health`, `/model`,
`/tools`, `/audit`, `/workspace`, `/mode`, `/profile`, `/evidence`, `/pending`,
`/examples`, `/clear`, `/raw on|off`, `/context minimal|standard|full`,
`/exit`. See `docs/interactive-mode.md`.

Natural-language diagnostic questions auto-collect evidence and stream a
synthesized operator answer (facts, clues, missing evidence, safe next
steps). When a deeper read-only follow-up makes sense, ShellForgeAI queues it
and runs it when you confirm with `yes` / `proceed` / `dig deeper`.

Interactive mode is *not* a shell: pasted shell-looking input is blocked
unless explicitly prefixed with `ask explain ...` or `ask review ...`.

## Project layout

```
src/shellforgeai/
  cli.py              Typer entry points
  core/               session, config, profiles, diagnose, evidence, plans
  tools/              typed read-only tools (host, journal, systemd, network, ...)
  llm/                provider abstraction (codex, ollama, vllm, openai-compatible, openrouter)
  interactive/        REPL, slash commands, workspace trust, streaming synthesis
  policy/             risk classes, rules, approvals
  knowledge/          local docs and audit search
  audit/              JSONL audit logger and artifact storage
  render/             rich console rendering
config/               default.yaml, profiles/, tools/
docs/                 architecture, cli, interactive-mode, model-providers, safety, tools, ...
tests/                pytest suite
```

## Configuration

Defaults live in `config/default.yaml`. Override with a YAML file via
`shellforgeai --config path/to/config.yaml`, or with `SHELLFORGEAI_*`
environment variables (see `docs/model-providers.md`).

Profiles in `config/profiles/` decide which risk classes are allowed, asked,
or denied. The active profile is selected with `--profile` or via
`app.default_profile` in config.

## Safety

- `apply` is validation-only in this alpha (it parses and validates plans,
  never executes them).
- Workspace trust grants doc reads and artifact writes — it never lifts
  policy or enables mutation.
- Service-impacting commands are described as approval-required and
  operator-run; ShellForgeAI does not run them.
- In restricted containers, the Codex CLI may emit `bwrap`/namespace errors;
  treat as a provider sandbox limitation, not a host failure. ShellForgeAI's
  typed read-only collectors keep working.

See `docs/safety.md`.

## Development

```bash
make dev      # editable install with dev extras
make lint     # ruff + mypy
make test     # pytest
make check    # format + lint + type + tests
```

## License

MIT. See `LICENSE`.
