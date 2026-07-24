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
./scripts/v1_validate.sh --full --packet
```

Quick path (docs/readiness-focused checks):

```bash
./scripts/v1_validate.sh --quick
```

Packet artifact path (opt-in):

```bash
./scripts/v1_validate.sh --quick --packet
./scripts/v1_validate.sh --full --packet
./scripts/v1_validate.sh --full --packet --export-packet
```

`--packet` writes only ShellForgeAI-owned V1 packet artifacts and runs packet validation.
It does not run remediation execute, rollback execute, cleanup execute, Docker restart, or Docker Compose mutation.



## V1 contract resource discovery

`v1 check` resolves the required V1 contract resources from the imported ShellForgeAI package/source lineage before considering the caller's current working directory. The maintained resource contract is `README.md`, `docs/v1-scope.md`, `docs/safety.md`, `docs/cli.md`, and `OPS.md`. The current working directory is a final bounded fallback only when it independently contains that complete exact set.

The resolver uses a fixed, read-only candidate list derived from the imported `shellforgeai` package location, the current Python executable lineage, and then the current working directory. It does not change directories, search home directories or drives, recursively walk parents, use glob/rglob discovery, or pick the first matching filename. If no bounded candidate contains the complete contract, `docs_v1_contract_present` fails and reports the missing relative resource names instead of relying on wrapper CWD behavior or silently passing partial resources. Ordinary wheel layouts that do not carry the full repository documentation set are therefore reported honestly rather than hidden by the caller's CWD.

Wrappers do not need to change CWD for `v1 check`. PR304 Windows runtime-integrity diagnostics and PR305 Windows runtime reconciliation remain unchanged: PR304 is read-only, while PR305 remains preview-only/non-executable with apply/execute, confirmation, backup, atomic replacement, hash verification, receipt, and post-change verification deferred.

## Disposable container recipe (python:3.12-slim / bookworm)

Use a disposable validation container and a writable copy of the source.

```bash
docker run --rm -it python:3.12-slim bash
apt-get update && apt-get install -y --no-install-recommends procps git rsync
mkdir -p /work && rsync -a /src/ /work/ShellForgeAI/
cd /work/ShellForgeAI
python -m pip install -e .[dev]
RUFF_CACHE_DIR=/tmp/ruff-cache PYTHONPYCACHEPREFIX=/tmp/pycache ./scripts/v1_validate.sh --full
./scripts/v1_validate.sh --full --packet
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

## Example packet summary output

```text
ShellForgeAI V1 validation
profile: full
validation: passed

V1 packet:
- packet_id: v1_packet_...
- packet_path: /data/v1_packets/...
- validation: ok
- read_only: True
- mutation_performed: False

Done.
```
