# V1 validation runbook (repeatable, non-mutating)

## Purpose

This runbook defines a repeatable V1 validation workflow for local development and disposable containers.
It is for validation only and does not perform production mutation.

## Standard validation gates

Run the same gates used in V1 QA:

```bash
python -m ruff check .
python -m compileall -q src tests
python -m pytest -q
```

Or use the helper script:

```bash
./scripts/v1_validate.sh --full
```

Quick path (docs/readiness-focused checks):

```bash
./scripts/v1_validate.sh --quick
```

## Disposable container recipe (python:3.12-slim / bookworm)

Use a disposable validation container and a writable copy of the source.

```bash
docker run --rm -it python:3.12-slim bash
apt-get update && apt-get install -y --no-install-recommends procps git rsync
mkdir -p /work && rsync -a /src/ /work/ShellForgeAI/
cd /work/ShellForgeAI
python -m pip install -e .[dev]
RUFF_CACHE_DIR=/tmp/ruff-cache PYTHONPYCACHEPREFIX=/tmp/pycache ./scripts/v1_validate.sh --full
```

Notes:
- `python:3.12-bookworm` is also acceptable for disposable validation.
- Do not install test dependencies into the production ShellForgeAI runtime container/image.
- The install commands above are for disposable validation environments only.

## Why `procps` matters

Some tests rely on `ps` (for example process snapshot shape checks). Minimal `python:3.12-slim` images often omit `ps` unless `procps` is installed.

If `ps` is missing, treat that as an environment dependency failure, not a product regression.

## Cache and write behavior

Read-only mounted source trees can fail validation because tooling may need writeable cache/bytecode locations.

Set:
- `RUFF_CACHE_DIR=/tmp/ruff-cache`
- `PYTHONPYCACHEPREFIX=/tmp/pycache`

Prefer validating against a writable copy of the source. If you use a read-only mount, redirect caches to `/tmp`.

## Docker01 lab notes

- Take a Proxmox/LXC snapshot before lab mutation.
- Preserve `/data` and Codex mounts.
- Never prune volumes in shared lab validation.
- Never remove running containers during normal V1 validation.
- Preserve battle-lab fixtures unless explicitly testing fixture reset behavior.
