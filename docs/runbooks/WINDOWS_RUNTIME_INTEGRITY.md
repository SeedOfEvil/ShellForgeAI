# Windows Runtime Integrity Preflight

PR304 adds a standalone, deterministic Windows runtime-integrity preflight packet for staged ShellForgeAI runtimes. The helper is intentionally a script, not a `shellforgeai` product command, so operators can run it with a known Python interpreter even when the normal console entry point or durable `sfai.cmd` wrapper is stale, missing, or points at the wrong runtime.

## Boundary

The preflight observes and reports only. It does not install, repair, clean, delete, rewrite wrappers, run PowerShell, use WinRM/QGA/WMI/CIM, call a model, open the network, read secrets or auth caches, invoke subprocesses, or execute the wrapper, entry point, or a second Python interpreter. The only allowed write is an explicitly requested JSON artifact from `--out-json`; existing artifacts are not overwritten.

## Helper

```bash
PYTHONPATH=src python scripts/windows_runtime_integrity.py --json
```

Arguments:

- `--expected-source-root PATH`: directory containing the expected `shellforgeai` package directory, normally the staged repository `src` directory.
- `--runtime-root PATH`: installed runtime root, such as `C:\Tools\ShellForgeAI`.
- `--wrapper-path PATH`: durable wrapper to inspect, such as `C:\Tools\ShellForgeAI\bin\sfai.cmd`.
- `--canonical-wrapper-path PATH`: canonical wrapper from the staged exact-head source tree.
- `--entrypoint-path PATH`: embedded Scripts entry point to inspect.
- `--profile NAME`: runtime profile to resolve; defaults to `inspect`.
- `--json`: emit compact deterministic JSON.
- `--out-json PATH`: save the same JSON packet to a new explicit artifact path.

On non-Windows hosts the helper returns `status=unsupported`, includes platform and safety metadata, and skips Windows path inspection, wrapper comparison, and site-package residue scanning.

## Packet schema and status semantics

The packet contains `schema_version`, `mode=windows_runtime_integrity`, top-level `status`, platform and invocation blocks, active Python runtime details, ShellForgeAI import details, runtime/profile resolution, wrapper checks, embedded Python and entry-point checks, bounded invalid-distribution residue results, ordered checks, summary counts, `first_safe_command`, and safety flags.

Status precedence is deterministic:

1. `unsupported` when the current platform is not Windows.
2. `blocked` when any requested integrity contract fails.
3. `attention` when no requested contract is blocked but a hygiene finding or omitted optional comparison exists.
4. `ok` when every requested integrity check passes and no residue or warning exists.

## Integrity checks

The expected-source comparison imports the active `shellforgeai` package in-process and verifies its package root is contained within `--expected-source-root`. A mismatch or import failure is `blocked`.

Runtime/profile resolution reuses `shellforgeai.core.runtime_resolution.resolve_runtime_profile_context`. When `--runtime-root` is supplied, the helper constructs `<runtime-root>\config\profiles\<profile>.yaml` and passes that explicit config path to the established resolver.

Wrapper comparison reads only the supplied durable and canonical wrapper files. It reports SHA-256 hashes, normalizes line endings and trailing whitespace only, and checks the merged wrapper markers: `%~dp0`, `SHELLFORGEAI_RUNTIME_ROOT`, `Python314\python.exe`, `-m shellforgeai %*`, and `%ERRORLEVEL%`.

The embedded Python check derives `<runtime-root>\Python314\python.exe` from `--runtime-root` or the narrow durable-wrapper parent contract. It checks existence and active-interpreter relationship without executing that interpreter.

The entry-point check inspects only `--entrypoint-path`, verifies it exists, and reports whether it is under the derived embedded `Scripts` directory.

The invalid-distribution residue check inspects only direct children of bounded site-package roots associated with the active interpreter and reports names beginning with `~hellforgeai` case-insensitively. It does not recurse or inspect contents. Residue is `attention`, not `blocked`, because PR304 diagnoses stale residue but does not clean or repair it.

## Saved-artifact validation

Validate one or more saved packets without re-inspecting the host:

```bash
python scripts/windows_runtime_integrity_acceptance.py runtime-integrity.json --expect-status unsupported --json
python scripts/windows_runtime_integrity_acceptance.py source-root.json system32.json --json
```

The validator enforces schema, mode, allowed statuses, ordered check structure, exact summary counts, status precedence, safety flags, and non-mutating first-safe-command text. With multiple artifacts, it allows invocation CWD differences while comparing stable runtime-identity fields so a source-root run and a `C:\Windows\System32` run must agree on import path, runtime resolution, wrapper hashes, embedded Python, entry point, residue names/count, and status.

## Acceptance guidance

Docker01 or Linux developer-container acceptance should expect `status=unsupported` and validate the saved artifact. No Docker deployment is required for this scripts/tests/docs-only change unless the maintained external process separately mandates an identity lane.

Actual Windows acceptance should run the helper through the embedded Python with `PYTHONPATH` pointing at the staged exact-head `src` tree, once from the source root and once from `C:\Windows\System32`, then validate both saved artifacts together. `status=attention` caused only by known `~hellforgeai*` residue is an honest finding, not a PR304 product failure. `status=blocked` caused by independently confirmed durable-wrapper drift is likewise a correct diagnosis when the packet identifies the drift accurately.

## Limitations and non-goals

PR304 does not provide an installer, updater, frozen package, wrapper repair, PATH modification, cleanup workflow, or product CLI command. Packaging and install decisions remain deferred; this preflight is the read-only observation stage that can be used before later packaging/install work.
