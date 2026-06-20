# Model providers

ShellForgeAI uses a single provider abstraction. The provider is selected
by `model.provider` in config or `SHELLFORGEAI_MODEL_PROVIDER`.

Available providers: `openai-codex` (default), `ollama`, `vllm`,
`openai-compatible`, `openrouter`.

## openai-codex (default)

Uses the local `codex` CLI with ChatGPT sign-in (`codex login` or
`codex login --device-auth`). ShellForgeAI does not read or parse
`~/.codex/auth.json`; it only checks whether the file is present.
ShellForgeAI invokes the local `codex` subprocess in read-only sandbox
mode.

Config keys (under `model:`):

| Key | Default | Notes |
| --- | --- | --- |
| `provider` | `openai-codex` | |
| `model` | `gpt-5.5` | |
| `fallback_model` | `gpt-5.4` | Used if `allow_model_fallback`. |
| `timeout_seconds` | `180` | |
| `codex_binary` | `codex` | |
| `codex_sandbox` | `read-only` | |
| `codex_json` | `true` | Parse JSON event stream. |
| `codex_skip_git_repo_check` | `true` | |
| `allow_model_fallback` | `true` | |

Env overrides:

- `SHELLFORGEAI_MODEL_PROVIDER`
- `SHELLFORGEAI_MODEL_NAME`
- `SHELLFORGEAI_MODEL_FALLBACK`
- `SHELLFORGEAI_CODEX_BINARY`
- `SHELLFORGEAI_CODEX_TIMEOUT_SECONDS`
- `SHELLFORGEAI_CODEX_SKIP_GIT_REPO_CHECK`

Headless installs should use `codex login --device-auth`. In restricted
containers the Codex CLI may emit `bwrap`/namespace errors — that is a
provider sandbox limitation, not a host failure.

## ollama

Local Ollama daemon. Configure `model.base_url` (e.g.
`http://localhost:11434`) and `model.model` (e.g. `llama3.1`).

## vllm

OpenAI-compatible vLLM endpoint. Set `model.base_url`, `model.model`, and
the API key env via `model.api_key_env` (default `SHELLFORGEAI_API_KEY`).

## openai-compatible

Any OpenAI-Chat-Completions-compatible endpoint. Same keys as vLLM.

## openrouter

OpenRouter OpenAI-compatible endpoint. Set `model.base_url` to
`https://openrouter.ai/api/v1`, choose a `model.model`, and provide the API
key via `model.api_key_env`.

## Interactive behavior

Interactive mode uses the same provider abstraction. If the model is
unavailable, the REPL shows setup guidance (`shellforgeai model doctor`)
instead of crashing.


## Model doctor live probe

`shellforgeai model doctor` remains no-call/no-network by default. Use
`--live-probe` only when an operator explicitly wants one bounded readiness/auth
check through the configured provider. The probe uses a fixed internal payload,
does not accept operator prompt text, does not execute tools, and performs no
mutation. `--receipt-out DIR` writes bounded receipt artifacts without secrets.
Tests for this surface use fake clients and do not call real providers.
