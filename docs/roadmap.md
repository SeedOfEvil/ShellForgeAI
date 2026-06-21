- Current: `shellforgeai ask --explain-evidence` exposes bounded Docker/operator evidence explainability: deterministic sources used or missing, top suspect/severity/confidence/themes, registry-backed safe next command, and no-mutation grounding boundaries. JSON ask explainability remains deferred because `ask` has no broad JSON mode. This is read-only explainability only; no cleanup, restart, prune, remediation, rollback, recovery, validation/QA execution, Docker/Compose mutation, shell execution, or natural-language execution is added.
- PR208 (June 14, 2026): command-surface golden/import guardrail performance polish. Validation-performance and diagnostics work only — no ShellForgeAI product runtime behavior change, no new command, no new execution lane. The PR184 golden command-surface guardrail invokes the same read-only commands many times (the parametrized sweep, the explicit numbered tests, and the whole-surface safety sweep), and the expensive ones — `v1 check` readiness, `status --json`, `ops report` — each cost seconds of real, read-only host inspection. Running them two-to-three times each made the PR205 `test_23` subprocess (which runs the entire PR184 suite) the repeatedly slowest validation path (~360s on Docker01). PR208 adds a shared, process-wide invocation cache in `tests/helpers/cli_surface.py` (`invoke_cached`) so each *unique* argv runs at most once per test process, plus a deterministic duration report (`invocation_duration_report` / `format_duration_report`). The cache is correctness-neutral: every cached command is read-only and deterministic with respect to its argv (help text is static; the JSON inspection commands probe the host read-only against an always-empty tmp data dir), so a cached result is identical to a fresh invocation and a regression still fails every test that reads it. PR184's explicit re-invocations (`test_17`/`test_34`) and the whole-surface safety sweep (`test_35_*`) now reuse the cache; the PR205 regression subprocesses pass `--durations=15` for observability. Local measurement: the PR184 suite dropped from ~132s to ~42s (≈68% faster) with each expensive command invoked exactly once. New `tests/test_pr208_command_surface_performance_polish.py` proves coverage is preserved (the golden fixture still covers every expected command/refusal and the governed recovery-execute `--confirm`), that cached invocation matches uncached invocation, that a cache hit does not re-run the CliRunner path, that failure output still names the offending command and missing/unexpected token, that the PR184/PR204/PR205 suites remain present and collectible, that the cached helper introduces no `shell=True`/subprocess/Docker/network/model/artifact mutation, and that the duration report is deterministic. Command-surface coverage and import side-effect coverage are unchanged; full validation remains appropriate when touching CLI registration or the import guardrails. Test/helper/docs only: no product command, no handler moved, no command semantics change, no cleanup/remediation/rollback/recovery execution, no Docker/Compose mutation, no restart, no production restart, no `shell=True`, no arbitrary command execution, no natural-language execution, no model/Codex call, no artifact repair/delete, no network call, no package install, no cloud apply/merge/push, and no intentional runtime behavior change was added.
- PR205 (June 13, 2026): command-module import side-effect guardrail. With the CLI command-module split closed (PR182–PR204), PR205 protects the new architecture from **hidden import-time behavior**: where the PR184 golden command-surface guardrail protects user-visible commands, PR205 proves that importing `shellforgeai.cli`, `shellforgeai.commands.__init__`, and every module under `src/shellforgeai/commands/` is import-safe — definitions, local imports, constants/option metadata, and Typer registration only. Importing a command module must never execute operational logic: no subprocess/`os.system`/`shell=True` execution, no Docker/Compose call or container/production restart, no cleanup/remediation/rollback/recovery execution, no model/Codex call, no network call, and no artifact write/repair/delete — those run only inside the command's execution path (the handler body) when the command is invoked. New `tests/test_pr205_command_module_import_side_effects.py` combines a **static** AST scan (rejects top-level subprocess/`shell=True`/cleanup/remediation/rollback/recovery/model calls while leaving harmless help text and command strings untouched) with a **runtime** check that purges the audited modules from `sys.modules` and reimports them under monkeypatched recording stubs over the dangerous primitives (subprocess, `os.system`, network sockets, the model/provider factory, the Docker/restart executors, and artifact write/delete), asserting none fired at import time; it also covers module discovery, the read-only helper's JSON/Markdown contract, and a full safety-invariant block (no cleanup/remediation/rollback/recovery execute, no Docker/Compose mutation, no Docker/production restart, no `shell=True`, no arbitrary/natural-language execution, no model call, no artifact repair/delete, no network call, no package install, no cloud apply/merge/push). A new read-only helper, `python scripts/cli_import_audit.py [--json|--markdown]`, runs the same audit in a fresh process and reports per-module import status and blocked side-effect attempts; it is read-only and local-only (no command/Docker/Compose/subprocess/model/network execution and no artifact/`/data` mutation). The PR184 command-surface golden and PR204 wiring-only guardrails remain green. Test/helper/docs only: PR205 adds tests, the read-only audit helper, docs (`docs/CLI_REFACTOR_MAP.md`, `docs/cli.md`, `docs/V2_COMMAND_CONTRACT.md`, `OPS.md`, `docs/roadmap.md`), and an import-safe `commands/__init__.py` `__all__` normalization (adds the already-present `v1` module); no new product command, no handler moved, no command semantics change, no cleanup/remediation/rollback/recovery execution, no Docker/Compose mutation, no restart, no production restart, no `shell=True`, no arbitrary command execution, no natural-language execution, no model/Codex call, no artifact repair/delete, no network call, no package install, no cloud apply/merge/push, and no intentional runtime behavior change was added.
- PR204 (June 13, 2026): CLI wiring-only enforcement guardrail. Closes the CLI command-module split by adding a strict `--check` mode to the read-only `scripts/cli_refactor_inventory.py` helper (`python scripts/cli_refactor_inventory.py --check` and `--check --json`) that treats `src/shellforgeai/cli.py` as wiring-only — Typer app/group creation, command-module registration, shared app metadata, and thin root/bootstrap helpers. The check parses `cli.py` with `ast` and sorts every inline Typer callable into exactly one bucket: **allowed** (an explicit, reasoned `INLINE_ALLOWLIST` — `main` root callback/bootstrap, the tiny read-only `version_cmd`, and the `audit index`/`v1 packet` group callbacks; every entry must carry a `reason`, enforced by `validate_allowlist`), **remaining extraction candidate** (a classified inline command handler reported as the tracked future-extraction map rather than silently allowlisted), or **unapproved** (an unclassified inline command handler or a non-allowlisted Typer callback). An unapproved handler fails the check (`status: failed`, exit code 1) and names the offending handler with guidance to move it into `src/shellforgeai/commands/` or add an explicit allowlist reason; on the current tree the check passes with 4 allowlisted callables, 0 unapproved handlers, and the remaining classified handlers tracked as `cli_py_role: wiring_with_tracked_remaining`. The `--check --json` payload is strict JSON with `read_only`/`mutation_performed`, the `allowlist` with reasons, `unapproved_inline_handlers`, `remaining_extraction_candidates`, a `summary`, a non-mutating `first_safe_command`, and a read-only `safety` block. New `tests/test_pr204_cli_wiring_only_enforcement.py` (30 checks) covers the passing current tree, the strict JSON contract, synthetic failure modes (unapproved inline handler fails with nonzero exit and is named; a malformed/reasonless allowlist is rejected; an allowed-only fake passes as literal `wiring_only`), prior-guardrail presence (PR184/PR198/PR202/PR203 and recent module-split tests), the doc updates, and that the check runs no cleanup/remediation/rollback/recovery, no Docker/Compose, no container/production restart, no `shell=True`, no arbitrary/natural-language execution, no model/Codex call, and mutates no files. `docs/CLI_REFACTOR_MAP.md` was regenerated to add a "CLI wiring-only enforcement (`--check`)" section and allowlist table; `docs/cli.md`, `OPS.md`, and `docs/V2_COMMAND_CONTRACT.md` document the wiring-only role, how to run `--check`, and the rule that new command handlers belong in command modules and allowlist entries must carry reasons. Guardrail/test/docs only: no handler was moved, no new product command, no ask/interactive/recipe/recovery/rollback/remediation behavior change, no cleanup/remediation/rollback/recovery execution, no Docker/Compose mutation, no restart, no production restart, no `shell=True`, no arbitrary command execution, no natural-language execution, no model/Codex call, no artifact repair/delete, and no intentional runtime behavior change was added.
- PR203 (June 13, 2026): CLI refactor closure map and remaining-inline guardrail review. Closure/verification step (not a new extraction) that locks in the result of the PR182–PR202 command-module split using the PR202 inventory/enforcement as the source of truth. The read-only `scripts/cli_refactor_inventory.py` now emits a `closure` block in `--json`/`--markdown` (and `summary.closure_status`) that distinguishes intentional Typer wiring/glue (`@*.callback()`, e.g. the root `main`, `audit index`, and `v1 packet` callbacks) from business-logic command handlers (`@*.command()`), confirms the expected PR182–PR201 modules exist, checks the PR184 command-surface guardrail files are present, and reports any *unexpected* (unclassified) inline handlers. It never claims a false OK: an unexpected inline handler, a missing expected module, a missing guardrail, or a cli.py threshold breach downgrades `closure_status` to `needs_attention` (top-level `status` semantics are unchanged). `docs/CLI_REFACTOR_MAP.md` was regenerated to add a closure-status section, an "Intentional `cli.py` responsibilities (allowed Typer wiring/glue)" section, and a "Not allowed in `cli.py`" section. Current closure state: `closure_status: ok` — 18 extracted command modules, 3 intentional callbacks, 96 classified future-extraction candidates, 0 unexpected inline handlers, PR184/PR202 guardrails present. New `tests/test_pr203_cli_refactor_closure.py` (30 checks) covers the map document, the JSON/Markdown/`--write-doc` closure contract, the false-OK guard on a synthetic repo with an unclassified handler, cli.py import/register + threshold enforcement, prior-guardrail presence (PR184/PR198/PR202 and recent module-split tests), and that the helper itself runs no cleanup/remediation/rollback/recovery, no Docker/Compose, no container/production restart, no `shell=True`, no arbitrary/natural-language execution, no model/Codex call, and mutates no source files. `OPS.md`/`docs/cli.md` document the closure view, how to read the closure output, and what counts as intentional glue. Closure/verification only: no handler was moved, no new product command, no ask/interactive/recipe/recovery/rollback/remediation behavior change, no cleanup/remediation/rollback/recovery execution, no Docker/Compose mutation, no restart, no production restart, no `shell=True`, no arbitrary command execution, no natural-language execution, no model/Codex call, no artifact repair/delete, and no intentional runtime behavior change was added.
- PR202 (June 13, 2026): CLI refactor inventory enforcement guardrail. Turns the read-only PR198 `scripts/cli_refactor_inventory.py` inventory into a regression guardrail so future command-module work cannot silently reintroduce large inline command handlers into `src/shellforgeai/cli.py`. The inventory `--json` now exposes a `cli_py` block (line count, inline Typer-handler count, and the documented `CLI_LINE_COUNT_THRESHOLD`/`CLI_INLINE_HANDLER_THRESHOLD` debt thresholds, mirrored into `summary`); JSON/Markdown/`--write-doc` modes stay read-only and the explicit-target `--write-doc` behavior is unchanged. New `tests/test_pr202_cli_refactor_inventory_enforcement.py` asserts the JSON/Markdown contract is parseable and stable, every PR182–PR201 command module exists and is imported/registered by `cli.py` (not owned inline), `cli.py` stays at/below the documented inline-handler debt thresholds, remaining inline handlers stay explicitly inventoried, and the inventory helper itself imports no runtime/Docker/Compose/model code, uses no `shell=True` or command-execution primitive, and mutates no source files; a synthetic over-threshold repo proves the guardrail fails clearly when a large new inline handler is added without updating the inventory/docs. `docs/CLI_REFACTOR_MAP.md` was regenerated to record the cli.py debt section, and `docs/cli.md`/`OPS.md` document how to run the inventory and what the enforcement checks. The PR198 inventory tests and the PR184 golden command-surface guardrail remain green. Process/test only: no new product command, no handler moved, no ask/interactive/recipe/recovery/rollback/remediation behavior change, no cleanup/remediation/rollback/recovery execution, no Docker/Compose mutation, no restart, no production restart, no `shell=True`, no arbitrary command execution, no natural-language execution, no model/Codex call, no artifact repair/delete, and no intentional runtime behavior change was added.
- PR200 (June 13, 2026): CLI command-module split continues with the top-level `interactive` launcher. `src/shellforgeai/commands/interactive.py` now owns Typer registration for `shellforgeai interactive` while `src/shellforgeai/cli.py` remains root app wiring. The launcher is Typer wiring only: it resolves the runtime context and hands off to the existing `shellforgeai.interactive.start_interactive` REPL, which was not moved or redesigned. The command surface and behavior are preserved: `interactive --help`, `--no-trust-cache`, and `--yes-trust` (including the trust-prompt help text and startup/exit behavior) are unchanged, and the top-level `--help` still lists `interactive`. Interactive mode remains not-a-shell: deterministic read-only routing (`status`, `ops report`, `triage docker`, `recipes receipt audit/integrity/explain`) is unchanged, broad/freeform mutation phrases (`clean up docker and restart compose`, `rollback now`, `recover it again`, `rerun receipt`, `restart from receipt`) are still refused with no action taken, and natural language never executes governed fixes. The `--yes-trust` flag still only gates the workspace trust prompt; it does not grant mutation, shell execution, or bypass any safety refusal. The root callback's no-subcommand interactive fallback intentionally stays in `cli.py`. The PR198 CLI refactor inventory/`docs/CLI_REFACTOR_MAP.md` now lists `interactive` as extracted (PR200). This is extraction-only: no cleanup, arbitrary remediation, rollback, recovery, Docker/Compose mutation, restart, production restart, `shell=True`, arbitrary command execution, natural-language execution, model/Codex call, artifact repair/delete, or intentional runtime behavior change was added. Future CLI refactors should keep running the PR184 command-surface golden guardrail.
- PR199 (June 13, 2026): CLI command-module split continues with the `remediation self-test` readiness/testing surface. `src/shellforgeai/commands/remediation.py` now owns Typer registration for `remediation self-test` while `src/shellforgeai/cli.py` remains root/remediation app wiring and keeps every other remediation handler (eligibility/plan/validate/preflight/execute/report/bundle/audit/status/rollback/receipt) unchanged. The command surface and behavior are preserved: `remediation --help`, `remediation self-test --help`, `--profile quick|standard|full`, `--json`, and `--fail-on-warn` keep the same checks, pass/fail/warn/skipped summary shape, `status`/`ci_status`, JSON/human output, exit codes, and safety flags; the full profile still drives the non-mutating lifecycle probe over an isolated temp data dir; live docker-disposable execute remains skipped by default and still requires the explicit `--include-live-disposable-execute --target <exact> --confirm-live-disposable` lab-only gate. The PR184 golden command-surface fixture gained additive coverage for `remediation --help`, `remediation self-test --help`, and the quick-profile JSON safety flags. This is extraction-only: no cleanup, arbitrary remediation, rollback, recovery, Docker/Compose mutation, restart, production restart, `shell=True`, arbitrary command execution, natural-language execution, model/Codex call, artifact repair/delete, or intentional runtime behavior change was added. Future CLI refactors should keep running the PR184 command-surface golden guardrail.
- PR198 (June 12, 2026): CLI refactor inventory and remaining-handler extraction map. Adds the read-only `scripts/cli_refactor_inventory.py` helper with human, strict `--json`, `--markdown`, and explicit `--write-doc` modes. The helper parses `src/shellforgeai/cli.py` and `src/shellforgeai/commands/*.py` with `ast`/filesystem inspection only; it does not import or execute the ShellForgeAI Typer app, run pytest/ruff/validation, call Docker/Compose, call a model/Codex, mutate host/services/containers/artifacts, or repair/delete artifacts. `docs/CLI_REFACTOR_MAP.md` records extracted modules, remaining inline handlers, safety/risk classifications, recommended extraction order, and future split validation expectations: PR184 command-surface golden guardrail for every split, Lane C/full validation for safety-sensitive or broad command moves, and mutation-capable governed execution handlers last or only with full validation. Inventory/process only: no handler extraction, no new product commands, no command registration/output/option behavior change, no ask routing change, no recipe/recovery execution change, no cleanup/arbitrary remediation/rollback/recovery execution, no Docker/Compose mutation, no restart, no `shell=True`, no arbitrary or natural-language execution, no model-driven execution, and no runtime behavior change was added.
- PR197 (June 12, 2026): Operator-trust polish — V1 safe-next-command guidance includes the valid read-only `shellforgeai model doctor --json` surface alongside machine-readable general health guidance `shellforgeai doctor --json`. `model doctor --json` is restored as a read-only structured readiness surface; `--brief` remains unsupported. V1 readiness semantics (pass/fail criteria, `status`/`ci_status`, safety flags) are unchanged; only the guidance strings were corrected. `tests/test_pr197_v1_next_safe_commands_model_doctor.py` asserts the JSON command is present, every suggested next-safe command resolves to a registered command with valid options, and safety flags stay non-mutating. Guidance-string correction only: no cleanup, arbitrary remediation, rollback, recovery, Docker/Compose mutation, restart, production restart, `shell=True`, arbitrary command execution, natural-language execution, model/Codex call, artifact repair/delete, or new execution behavior was added.

### Model doctor auth readiness

`shellforgeai model doctor` and `shellforgeai model doctor --json` are local,
read-only diagnostics. By default they inspect the configured Codex binary,
version, and whether local auth material appears present; they do not call the
model, perform a network probe, write credentials, or mutate the host. The
default no-probe state reports `live_probe_requested=false`,
`live_probe_performed=false`, and `auth_readiness=not_verified` with
`auth_reason=auth_cache_present_live_probe_not_run`, meaning live readiness was
not requested or performed.

Operators can explicitly request one bounded auth/readiness check with
`shellforgeai model doctor --live-probe --json` or human output with
`shellforgeai model doctor --live-probe`. The probe uses a fixed internal
readiness ping through the configured model client, does not accept operator
prompt text, does not execute tools, and performs no mutation. Tests use fake
clients only; no real model or network calls are required in tests.

A bounded, pasteable receipt can be written with
`shellforgeai model doctor --live-probe --receipt-out /tmp/sfai-model-probe`.
The directory contains `model-doctor-live-probe.json`,
`model-doctor-live-probe-summary.md`, `manifest.json`, and `checksums.json`
with SHA256, size, and read-only/no-mutation safety metadata. Receipt files
omit secrets, tokens, auth headers, and raw credential material. SeedOfEvil remains the final merge owner.
- PR196 (June 12, 2026): CLI command-module split continues with the `model` command group. `src/shellforgeai/commands/model.py` now owns Typer registration for `model doctor` (moved from `commands/doctor.py`, where it had lived since PR182) and `model test` (moved from `cli.py`), while `src/shellforgeai/cli.py` remains root app wiring. The command surface and behavior are preserved: `model --help`, `model doctor --help`, and `model test --help` (with the existing positional prompt and `--raw`/`--timeout`/`--model` options) are unchanged; `model doctor` remains the read-only provider-readiness report with the same provider/model/fallback fields, `shutil.which`-based codex binary detection, auth cache presence with `status_unknown` readiness and `codex login --device-auth` recovery hint, sandbox/approval reporting, and no `--json` flag in the current surface. `model doctor` still makes no model inference call and starts no Codex task; `model test` remains the group's only explicit one-shot model call, unchanged. This is extraction-only: no cleanup, arbitrary remediation, rollback, recovery, Docker/Compose mutation, restart, production restart, `shell=True`, arbitrary command execution, natural-language execution, new model command, artifact repair/delete, or intentional runtime behavior change was added. Future CLI refactors should keep running the PR184 command-surface golden guardrail.
- PR195 (June 12, 2026): CLI command-module split continues with the read-only V1 readiness surface. `src/shellforgeai/commands/v1.py` now owns Typer registration for `v1 check` while `src/shellforgeai/cli.py` remains root/V1 app wiring and keeps the V1 packet lifecycle unchanged. The command surface and behavior are preserved: `v1 --help`, `v1 check --help`, `v1 check --profile quick|standard|full`, `--json`, and `--fail-on-warn` keep the same JSON/human output, pass/fail/warn/skip counts, `status`/`ci_status`, and safety fields. This is extraction-only: no cleanup, arbitrary remediation, rollback, recovery, Docker/Compose mutation, restart, production restart, `shell=True`, arbitrary command execution, natural-language execution, model/Codex call, artifact repair/delete, or intentional runtime behavior change was added. Future CLI refactors should keep running the PR184 command-surface golden guardrail.
- PR194 (June 12, 2026): CLI command-module split continues with the governed, confirm-gated receipt recovery execution lane. `src/shellforgeai/commands/receipt_recovery_execute.py` now owns Typer registration for `recipes receipt recovery-execute <receipt_ref>` (with its existing explicit `--confirm` option and `--json`), while `src/shellforgeai/cli.py` remains root wiring and keeps governed `recipes execute` behind its existing confirmation gate. The command surface and behavior are preserved: recovery-execute still requires explicit `--confirm`, still re-gates the exact single receipt target (exists, non-production, `shellforgeai.disposable=true`, `shellforgeai.allow_restart=true`, not broad), still executes only the exact argv `["docker", "restart", "<target>"]` with no `shell=True`, still writes and verifies a recovery receipt, and still blocks no-confirm, missing/malformed/unsupported receipts, production/missing/label-drift/broad targets, and Docker command failures with controlled output, `mutation_performed=false`, `recovery_executed=false`, and `container_restarted=false`. Read-only `recovery-status`/`recovery-validate` from PR193 are unchanged. No Docker Compose, cleanup, remediation, rollback, natural-language, model-driven, or broad mutation behavior was added. Future CLI refactors should keep running the PR184 command-surface golden guardrail.
- PR193 (June 12, 2026): CLI command-module split continues with the remaining read-only recovery receipt inspection surfaces. `src/shellforgeai/commands/receipt_recovery_readonly.py` now owns Typer registration for `recipes receipt recovery-status <recovery_receipt_ref>` and `recipes receipt recovery-validate <recovery_receipt_ref>` (including `--json` where previously present), while `src/shellforgeai/cli.py` remains root wiring and keeps governed `recipes execute` and receipt `recovery-execute` behind their existing confirmation gates. The command surfaces and behavior are preserved: recovery-status reads receipt-aware recorded verification evidence only, recovery-validate validates recovery receipt artifacts only, missing/malformed receipts fail cleanly, strict JSON output remains strict, and neither command reruns recovery, rolls back, restarts containers, executes Docker Compose, runs cleanup/remediation, calls shell/model paths, or repairs/deletes artifacts. Future CLI refactors should keep running the PR184 command-surface golden guardrail.
- Current CLI command-module split: `src/shellforgeai/cli.py` remains root Typer wiring while read-only/status/reporting handlers live under `src/shellforgeai/commands/`, including governed receipt history/audit/export/compare/integrity/explain surfaces (`recipes receipt history`, `inspect`, `export`, `export-validate`, `compare`, `compare-latest`, `audit`, `audit-bundle`, `audit-bundle-validate`, `integrity`, and `explain`) in `commands/receipt_audit.py`, the read-only receipt safety surfaces (`recipes receipt verify`, `recipes receipt validate`, `recipes receipt rollback-preview`, and the top-level `rollback-preview --receipt` alias) in `commands/receipt_safety.py`, the read-only recovery receipt inspection surfaces (`recipes receipt recovery-status` and `recipes receipt recovery-validate`) in `commands/receipt_recovery_readonly.py`, the read-only recipe registry/preflight surfaces (`recipes`, `recipes list`, `recipes inspect`, `recipes eligibility`, `recipes preflight`, `recipes preflight validate`) in `commands/recipes.py`, the governed confirm-gated receipt recovery execution lane (`recipes receipt recovery-execute`) in `commands/receipt_recovery_execute.py`, the top-level deterministic `ask` command in `commands/ask.py`, and the `model` command group (read-only `model doctor` provider readiness plus the explicit one-shot `model test`) in `commands/model.py`. These receipt surfaces are unchanged: history/inspect/compare/audit/integrity/explain/verify/validation/rollback-preview/recovery-status/recovery-validate remain read-only; export and audit-bundle remain bounded ShellForgeAI-owned artifact-only writes; recipe list/eligibility/preflight remain read-only and never execute; ask remains deterministic where possible and still refuses broad/freeform mutation (natural language never executes governed fixes); recovery-execute keeps its exact-target, disposable-only, allowlisted, explicit `--confirm` gates; governed `recipes execute` stays outside these modules in `cli.py`. Future CLI refactors should continue running the PR184 command-surface golden guardrail.
- PR192 (June 12, 2026): CLI command-module split continues with the read-only governed receipt safety surfaces. `src/shellforgeai/commands/receipt_safety.py` now owns Typer registration for `recipes receipt verify`, `recipes receipt validate`, `recipes receipt rollback-preview`, and the existing top-level `rollback-preview --receipt <receipt_ref>` alias (all with `--json` where previously present), while `src/shellforgeai/cli.py` remains root wiring and keeps governed `recipes execute`, receipt `recovery-execute` (with its explicit `--confirm` gate), `recovery-status`, and `recovery-validate` unchanged. The rollback-preview handlers moved from `commands/receipt_audit.py` to `commands/receipt_safety.py` as wiring only. The command surfaces and behavior are preserved: receipt verify still verifies execution and recovery receipts from recorded evidence without rerunning recipes; receipt validate still checks structure/schema/checksums without repairing or deleting artifacts; rollback-preview remains read-only, still truthfully reports that `docker.disposable_restart` has no true rollback, still blocks production targets, and still never executes rollback/recovery or restarts containers; missing/malformed refs still fail cleanly with strict JSON. The PR184 golden command-surface fixture gained additive coverage for `recipes receipt verify --help`, `recipes receipt validate --help`, and the top-level `rollback-preview --help`. No cleanup/remediation/rollback/recovery execution, Docker/Compose mutation, container/production restart, `shell=True`, arbitrary command execution, natural-language execution, model call, artifact repair/delete, or runtime behavior change was added. Future CLI refactors should keep running the PR184 command-surface golden guardrail alongside targeted module-split tests.
- PR191 (June 11, 2026): CLI command-module split continues with read-only/artifact-only governed receipt history/audit/export/compare/integrity/explain/rollback-preview surfaces. `src/shellforgeai/commands/receipt_audit.py` now owns Typer registration for receipt history, inspect, export, export-validate, compare, compare-latest, audit, audit-bundle, audit-bundle-validate, integrity, explain, and rollback-preview while `src/shellforgeai/cli.py` remains root wiring and keeps governed `recipes execute`, receipt recovery-execute, recovery status, and recovery validate unchanged. The command surfaces and behavior are preserved: read-only surfaces remain read-only; export/audit-bundle write only the same bounded ShellForgeAI-owned artifacts; rollback-preview still never executes rollback/recovery or restarts containers; and no cleanup/remediation/rollback/recovery execution, Docker/Compose mutation, container/production restart, `shell=True`, arbitrary command execution, natural-language execution, model call, artifact repair/delete, or runtime behavior change was added. Future CLI refactors should keep running the PR184 command-surface golden guardrail alongside targeted module-split tests.
- PR190 (June 11, 2026): CLI command-module split continues with the top-level deterministic `ask` command. `src/shellforgeai/commands/ask.py` now owns Typer registration for `shellforgeai ask "<question>"` (with the existing `--context`, `--full-context`, `--raw`, `--no-evidence`, and `--since` options), while `src/shellforgeai/cli.py` remains root app wiring and keeps the shared deterministic `_handle_*` routing/refusal helpers (interactive mode and other surfaces use them too). The command surface and behavior are preserved: deterministic read-only routing (status, triage, ops report, receipt audit/integrity/explain/bundle guidance, recipe registry, handoff/verify/propose/apply-preview guidance) is unchanged; broad/freeform mutation asks (cleanup/restart/rollback/recover/rerun/fix/delete/execute phrasings and mixed phrasings) are still refused with the same no-action-taken wording and safe first/next read-only command guidance; deterministic routes still make no model call; the evidence-backed model path is unchanged and still resolves `diagnose_target`/`build_provider` through `cli.py` so existing hooks keep working. Interactive mode, governed recipe execution, and recovery execution handlers remain separately guarded. No cleanup/remediation/rollback/recovery execution, Docker/Compose mutation, container/production restart, `shell=True`, arbitrary command execution, natural-language execution, new model fallback behavior, artifact repair/delete, or runtime behavior change was added. Future CLI refactors should keep running the PR184 command-surface golden guardrail alongside targeted module-split tests.
- PR189 (June 11, 2026): CLI command-module split continues with the read-only governed recipe registry/preflight surfaces. `src/shellforgeai/commands/recipes.py` now owns Typer registration for `shellforgeai recipes` (root listing), `recipes list`, `recipes inspect <recipe_id>`, `recipes eligibility --recipe <recipe_id> --target <target>`, `recipes preflight --recipe <recipe_id> --target <target> [--save]`, and `recipes preflight validate <preflight_ref>` (all with `--json` where previously present), while `src/shellforgeai/cli.py` remains root app wiring and still owns governed execution: `recipes execute`, `recipes receipt recovery-execute`, `recovery-status`, and `recovery-validate` remain unchanged. The command surfaces and behavior are preserved: registry/list/eligibility remain read-only, preflight remains read-only packet generation with exact-target extraction, production/broad-target blocking, disposable/allowlist gate reporting, first-safe-command guidance, strict JSON, and the existing ShellForgeAI-owned `--save` packet artifact; `safe-actions` and deterministic ask routing reuse the moved renderers so output is identical. Rollback-preview is now covered by the receipt audit module split. No cleanup/remediation/rollback/recovery execution, Docker/Compose mutation, container/production restart, `shell=True`, arbitrary command execution, natural-language execution, model call, artifact repair/delete, or runtime behavior change was added. Future CLI refactors should keep running the PR184 command-surface golden guardrail alongside targeted module-split tests.
- PR187 (June 11, 2026): CLI command-module split continues with the read-only V2 planning/preview surfaces. `src/shellforgeai/commands/propose.py` now owns Typer registration for `shellforgeai propose` (`--json`, `--brief`, `--target`, `--from-triage`) and `src/shellforgeai/commands/apply_preview.py` owns `shellforgeai apply-preview` (`--json`, `--brief`, `--target`, `--from-propose`, `--from-triage`), while `src/shellforgeai/cli.py` remains root app wiring and the payload/render helper home. The command surfaces and behavior are unchanged: propose remains a read-only deterministic planning/proposal surface, apply-preview remains a preview-only execution-boundary surface that never applies or executes, first-safe-command and safe-next-command guidance and JSON safety fields (`read_only`, `mutation_performed`, etc.) are preserved, and no cleanup/remediation/rollback/recovery execution, Docker/Compose mutation, container restart, `shell=True`, arbitrary command execution, natural-language execution, model call, artifact repair/delete, or runtime behavior change was added. Future CLI refactors should keep running the PR184 command-surface golden guardrail alongside targeted module-split tests.
- PR186 (June 11, 2026): CLI command-module split continues with the read-only V2 operator `handoff` surface. `src/shellforgeai/commands/handoff.py` now owns Typer registration for `shellforgeai handoff`, `handoff --json`, `handoff --brief`, `handoff --save`, and the existing validate/export/export-validate/history/compare/compare-latest artifact lifecycle while `src/shellforgeai/cli.py` remains root app wiring. The command surface and behavior are unchanged: handoff remains read-only/artifact-oriented, first-safe-command and safe-next-command output is preserved, save/export write only ShellForgeAI-owned artifacts, missing/malformed refs fail cleanly, and no cleanup/remediation/rollback/recovery execution, Docker/Compose mutation, container restart, shell execution, arbitrary command execution, natural-language execution, model call, artifact repair/delete, or runtime behavior change was added. Future CLI refactors should keep running the PR184 command-surface golden guardrail alongside targeted module-split tests.
- PR185 (June 10, 2026): CLI command-module split continues with the read-only top-level `verify` handler. `src/shellforgeai/commands/verify.py` now owns Typer registration for `shellforgeai verify`, including current-state forms (`verify`, `verify --json`, `verify --brief`) and receipt-aware forms (`verify --receipt <receipt_ref>`, with `--json`/`--brief`), while `src/shellforgeai/cli.py` remains the root app/wiring owner and shared helper home. The command surface and behavior are unchanged: current-state verify is read-only, receipt-aware verify uses recorded governed execution or recovery receipt evidence only, missing receipts fail cleanly, and verify still creates no receipt and performs no retry, recovery, rollback, Docker/Compose call, container restart, shell execution, natural-language execution, model call, or artifact repair/delete. Future CLI refactors should keep running the PR184 command-surface golden guardrail alongside targeted module-split tests.
- PR184 (June 10, 2026): CLI command-surface golden guardrail milestone. Before the CLI command-module split continues onto riskier surfaces (`verify`, `handoff`, recipes, receipts, ask routing, governed execution helpers), PR184 adds a behavior-preserving refactor safety net so extractions cannot silently drop commands, JSON flags, help text, governed-execution confirmation requirements, or mutation-refusal paths. It adds a compact golden fixture (`tests/golden/cli_command_surface_pr184.json`) recording per-command `argv`, expected `--help` exit code, required help substrings, JSON-capability/required-JSON-and-safety fields, and `--confirm`/read-only markers; a read-only helper (`tests/helpers/cli_surface.py`) that loads/validates the fixture and invokes the CLI in-process via `CliRunner` with the model/provider factory blocked; tests (`tests/test_pr184_cli_command_surface_golden.py`) covering core/V1/V2/ops/recipes/receipts/ask surfaces, the six mutation-refusal smoke phrases, and JSON read-only safety fields; and an optional read-only snapshot aid (`scripts/cli_surface_snapshot.py`) that prints the current surface and only writes when given an explicit temp/test `--output` path. `model doctor` is covered help-only because it has no `--json` flag and builds a provider when invoked. This is test infrastructure only and does not replace full validation when core command surfaces move (Lane C remains appropriate for broad/core command refactors). No new product command, runtime behavior change, cleanup/remediation/rollback/recovery execution, Docker/Compose mutation, container/production restart, `shell=True`, arbitrary command execution, natural-language execution, model call, or artifact repair/delete was added.
- PR183 (June 10, 2026): CLI command-module split continues for read-only operator surfaces. `src/shellforgeai/cli.py` remains the root Typer wiring while `src/shellforgeai/commands/ops.py` owns the read-only `ops status` / `ops report` handler family and `src/shellforgeai/commands/triage.py` owns the read-only `triage` / `triage docker` handler family, including existing report/snapshot artifact lifecycle commands. This follows PR182 (`status`, `doctor`) and is intended to be behavior-preserving only: command names, help surface, JSON schemas, read-only safety flags, first-safe-command guidance, deterministic ask routing, and mutation refusal posture remain unchanged. No cleanup/remediation/rollback/recovery execution, Docker/Compose mutation, container/production restart, `shell=True`, arbitrary command execution, natural-language execution, model call, artifact repair/delete, or governed recipe behavior change was added.
- PR181 (June 10, 2026): validation latest-artifact discovery polish. Improves the read-only `scripts/validation_status.py --latest` selector so it chooses the most relevant validation evidence artifact deterministically and explains the choice, addressing the PR180 observation that `--latest` could surface an older persisted `/srv/data/.../validation-runs` manifest (and conservatively report incomplete/rerun_required) even when a newer PR-specific run directory existed. Discovery is now ordered by candidate kind first (recent PR-specific run directories `/tmp/sfai-pr<PR>-<sha>-validation-*`, then PR-specific validation-container run dirs, then mainline temp runs `/tmp/shellforgeai-validation-runs/*`, then persisted manifests `/srv/data/shellforgeai/validation-runs/*`, then — only with `--include-legacy` — legacy `/data/validation-runs/*`) and by newest timestamp within a kind, so a recent PR-specific run dir outranks an older (or even newer) persisted manifest and a legacy artifact never outranks a recent run. New selectors extend the viewer: `--pr <N>` and `--commit <sha>` (unambiguous prefix match) filter candidates and require a match (an unmatched filter yields a controlled `not_found`), `--pr` + `--commit` requires both, `--run-root <path>` scans only one bounded root (rejecting `/`/broad roots and `..` path traversal, no host crawl), `--include-legacy` opts into older artifacts, and `--explain-selection` lists the selected and skipped candidates with per-candidate `skipped_reason` (for example `older persisted manifest (PR-specific run preferred)`, `PR mismatch`, `commit mismatch`). Human and strict-`--json` output now carry the selected artifact path, selection reason, matched PR/commit, `source.selected_by` (`latest`/`pr`/`commit`/`pr_commit`/`run_root`/`run_dir`), and a `selection` block (with a `candidates` list under `--explain-selection`); tying eligible candidates pick the newest and emit a `multiple matching candidates, newest selected` warning; no candidate at all returns `status=not_found`/`classification=not_found`, `pass_eligible=false`, `rerun_required=true` with no traceback and a read-only re-scan/known-locations hint. An explicit `--run-dir` still bypasses discovery. Conservative classification is unchanged: a pass still requires recorded full-`pytest` completion, setup/test failures stay failed, incomplete stays incomplete, a fallback-packet/Lane B targeted-only manifest never becomes a pass without required evidence, and selecting a different artifact never converts incomplete/failed evidence into a pass. Validation tooling and evidence only: read-only except optional stdout, no validation execution, no `pytest`, no `ruff`, no Docker/Compose call or mutation, no container/production restart, no cleanup/remediation/rollback/recovery execution, no `shell=True`, no arbitrary command execution, no natural-language execution, no model/Codex call, and no artifact repair/delete. No ShellForgeAI runtime recipe execution behavior changed.
- PR179 (June 10, 2026): validation container fallback packet milestone. Adds `scripts/validation_container_fallback.py` (human and strict `--json` modes, plus `--lane/--pr/--commit/--image/--force`) which reads a validation run directory's evidence (`validation-preflight.json` / `validation-status.json` / manifest) and, when the run stopped on a PR178 `setup_failure`, writes a disposable validation-container fallback packet into the same run directory: `validation-container-fallback.json`, `validation-container-fallback.md`, `validation-container-command.txt`, and `validation-container-command.argv.json`. The packet explains why host validation stopped (setup failure, not product test failure), carries the missing dev tools from the preflight evidence, recommends the disposable validation container path, and gives an exact operator-run command (disposable `--rm` container, read-only repo mount, run-dir artifact mount, dev dependencies installed inside the container only — host package set unchanged; no Compose/restart/prune/cleanup/secret mounts) plus expected phases, safety notes, a first safe command, and a no-pass-until-clean-rerun warning. Clean/passed runs return `not_needed` without artifact churn (`--force` overrides), missing run dirs return `not_found`, and malformed evidence fails with a controlled warning — never a traceback. The Docker01 PR lane helper now generates the packet automatically (evidence files only) when its `environment_preflight` phase fails and records the packet path in the manifest and human summary; the PR177 viewer reports `fallback_packet_present`/`fallback_packet_path`, lists the packet as evidence, and adds the packet command to `safe_next_commands` for setup failures while keeping the preflight as the first safe command. Process/evidence tooling only: the generator never runs Docker or Docker Compose, never restarts containers or production, never runs `pytest`/`ruff`, never installs host packages, never runs a subprocess or uses a shell, never executes the generated command, never runs cleanup/remediation/rollback/recovery execution, never calls a model, never performs natural-language execution, and changes no ShellForgeAI runtime product behavior.
- PR178 (June 9, 2026): validation environment preflight milestone. Adds the read-only preflight `scripts/validation_env_preflight.py` (human and strict `--json` modes) that checks, before any ruff/compileall/pytest validation phase runs, whether the environment has the required dev tools: Python executable/version, `ruff`, `pytest`, `pytest-xdist` (warning unless required), `shellforgeai` package importability (spec lookup only), presence of `scripts/run_full_pytest.py`/`scripts/validation_heartbeat.py`/`scripts/validation_status.py`, artifact-directory write access, and a heartbeat/status JSON probe write. A failed preflight is a controlled `setup_failure`: `status=failed`, `pass_eligible=false`, `rerun_required=true`, exit nonzero, with the recommendation to use the disposable validation container path or prepare dev dependencies outside ShellForgeAI (text only; never executed). The Docker01 PR lane helper (`scripts/sfai_docker01_pr_lane.py`) now runs this preflight as an `environment_preflight` phase before validation when `--execute-validation` is used (plus a standalone `--preflight-only` mode and `--preflight-output`): a failed preflight stops before ruff/compileall/pytest, writes manifest/summary/heartbeat/status/checkpoint plus `validation-preflight.json`, and classifies the run as `setup_failure` with `failed_phase=environment_preflight`; warnings-only preflights continue with the warnings preserved as non-blockers; passed preflights are recorded in the evidence. The PR177 viewer `scripts/validation_status.py` now summarizes preflight setup failures (including a run dir holding only a failed preflight report), keeps stored `setup_failure` classifications instead of misreading them as incomplete, lists the preflight evidence file, and points its first safe command at the preflight for setup failures. Setup failure is never reported as product test failure, never as a pass, and is not merge evidence — a rerun in a valid environment is required. Process/evidence tooling only: no package installation, no venv/host Python mutation, no `pytest`/`ruff check` execution by the preflight, no subprocess in the preflight, no Docker/Compose call or mutation, no container/production restart, no cleanup/remediation/rollback/recovery execution, no `shell=True`, no arbitrary command execution, no natural-language execution, no model/Codex call, and no ShellForgeAI runtime recipe execution behavior change.
- PR177 (June 9, 2026): validation evidence status viewer milestone. Adds the read-only viewer `scripts/validation_status.py` so operators can quickly inspect the PR176 heartbeat/status/manifest evidence after a long Docker01/full-validation run without rerunning anything. The viewer supports `--latest` (scans only known ShellForgeAI-owned validation artifact roots, with a `SFAI_VALIDATION_RUNS_DIR` test override), `--run-dir <path>`, and explicit `--heartbeat`/`--status-file`/`--manifest` paths, in human or strict-`--json` form. It reuses the deterministic `validation_heartbeat.classify_run` classifier to report `status` (`passed`/`failed`/`incomplete`/`unknown`), `classification` (`passed`/`test_failure`/`setup_failure`/`interrupted_or_incomplete`/`no_evidence`/`unknown`), `pass_eligible`, `rerun_required`, `phase_status`, the active/last-completed phase, the full-`pytest` exit code/result, heartbeat age, and the evidence file paths. Classification is conservative: a pass requires recorded full-`pytest` completion, missing full-`pytest` completion is `incomplete` (never a pass), missing evidence is `unknown`/`no_evidence`, and conflicting evidence prefers the conservative result with a warning and never reports `pass_eligible=true`. The Docker01 PR lane helper's final output now prints the matching `validation_status.py --run-dir <run_dir> --json` command. Validation tooling and evidence only: read-only except optional stdout, no validation execution, no `pytest`, no Docker/Compose call or mutation, no container/production restart, no cleanup/remediation/rollback/recovery execution, no `shell=True`, no arbitrary command execution, no natural-language execution, and no model/Codex call. No ShellForgeAI runtime recipe execution behavior changed.
- PR176 (June 9, 2026): validation-lane heartbeat and interrupted-run evidence milestone. Adds `scripts/validation_heartbeat.py` plus heartbeat/checkpoint/status JSON wiring in `scripts/sfai_docker01_pr_lane.py` and `scripts/run_full_pytest.py` so long Docker01/full-validation runs that are SIGTERM/SIGINT/timeout-interrupted (or SIGKILLed, as happened on PR175's first helper run) leave clear partial evidence instead of a silent false pass. The heartbeat is updated before and after each phase with `active_phase`, `last_completed_phase`, per-phase `phase_status` (`not_started`/`running`/`passed`/`failed`/`interrupted`/`unknown`), `full_pytest_exit_code`, and `full_pytest_result`. A deterministic classifier records `status` (`passed`/`failed`/`incomplete`), `classification` (`passed`/`test_failure`/`setup_failure`/`interrupted_or_incomplete`), `pass_eligible`, and `rerun_required`; `status=passed` is recorded only when full `pytest` exit `0` is captured, an interrupted run is `incomplete`/`pass_eligible=false`/`rerun_required=true` with a `*** RERUN REQUIRED ***` human summary, and an incomplete run is never merge evidence (a clean rerun is required). SIGKILL cannot be caught, but the last heartbeat still shows the active phase as `running` and classifies as incomplete. The helper runs full `pytest` once per invocation and never auto-reruns it. Process/tooling and validation-evidence only: no ShellForgeAI runtime recipe execution behavior change, no cleanup/remediation/rollback/recovery execution, no Docker/Compose/service/container mutation, no container or production restart, no `shell=True`, no arbitrary command execution, no natural-language execution, and no model/Codex call was added.
- PR166 (June 7, 2026): Docker01 validation environment hardening and preflight doctor milestone. Adds the read-only `scripts/check_validation_env.py` helper for Docker01/local validation environments, with human and strict JSON output for Python/version/path, `shellforgeai` importability, pytest/ruff/compileall, required OS tools (`git`, `rsync`, procps/`ps`, `timeout`), validation helper presence, xdist availability/strict-mode gating, optional Docker/Docker Compose CLI presence without daemon contact, source-tree writability, and generated cache/root-owned `__pycache__` hygiene hints. Validation reliability only: no runtime product feature, cleanup/remediation/rollback execution, Docker/Compose mutation, container or production restart, package install/delete/chmod/chown, `shell=True`, arbitrary command execution, or natural-language mutation was added.
- PR164 (June 6, 2026): full-validation duration history and regression tracking milestone. Adds `scripts/track_pytest_durations.py` to parse pytest `--durations` output from full-validation logs, emit strict JSON slow-test records, compare against explicit local history/baseline files for warning-only regressions, append to explicit history only with `--update-history`, and attach an additive `duration_report` to explicit validation manifests with a `.bak` copy. Docker01 Lane C documentation now treats slow-test history as optimization evidence; no tests are skipped and no runtime product feature, cleanup/remediation/rollback execution, Docker/Compose mutation, restart, `shell=True`, arbitrary command execution, or natural-language mutation was added.
- PR162 (June 6, 2026): Docker01 validation manifest finalization/import milestone. Adds an offline `scripts/finalize_validation_manifest.py` helper that attaches already-completed validation/QA/runner/targeted/full-pytest logs to an existing Docker01 validation manifest, conservatively imports known pass/fail signals, records `evidence_import` metadata and explicit operator status/verdict overrides, writes a `.finalized.json` copy by default, and can render a finalized human summary that states tests were not rerun. Validation/reporting infrastructure only: no runtime feature work, cleanup/remediation/rollback execution, Docker/Compose mutation, container restart, production restart, `shell=True`, arbitrary command execution, or natural-language mutation.

## PR143 command surface audit

- PR159 (June 6, 2026): Docker01 PR lane full-validation runner integration. Adds `scripts/sfai_docker01_pr_lane.py` as a validation-only Docker01 PR helper that plans through `scripts/validate_pr.py` and, when Lane C/full validation is selected, executes `python scripts/run_full_pytest.py` instead of raw `pytest -q`. The lane logs the full-validation reason, runner command, xdist availability/use or serial fallback from the runner output, and duration reporting (`--durations=25`). Dev validation keeps `pytest-xdist` in the project `dev` extra for parallel full validation when installed. Lane A/B remain targeted by default, Docker01 compose/deploy railings remain checklist-only/unchanged, and no runtime product feature, cleanup/remediation/rollback execution, Docker/Compose mutation, restart, `shell=True`, arbitrary command execution, or natural-language mutation was added.

PR143 adds the command-surface audit and V2 anti-bloat map for the planning
lane. It documents command classifications, the V2 golden path, support and
governed lanes, compatibility/deprecation candidates, and explicit non-goals
without changing runtime behavior. See [`COMMAND_SURFACE_AUDIT.md`](COMMAND_SURFACE_AUDIT.md)
and [`V2_COMMAND_CONTRACT.md`](V2_COMMAND_CONTRACT.md).


## V1 hardening lane (PR110)

- Define and publish the V1 contract (scope, non-goals, safety boundary).
- Normalize canonical operator flow around `doctor`, `ops report`, artifact lifecycle, and deterministic triage detail.
- Keep behavior-preserving hardening first: docs/tests/regressions before broad feature expansion.

# Roadmap

- PR161 (June 6, 2026): Docker01 validation evidence manifest and structured run summary. The guarded Docker01 PR lane helper now writes a stable JSON manifest (`schema_version=1`, `mode=docker01_pr_validation_manifest`) plus a bounded human summary for each run. The manifest captures PR/source metadata, selected lane and reason, full-validation requirement, commands/phases with durations, log paths, deployment/snapshot/image metadata when provided, final container and disk state when provided, validation statuses, explicit safety flags, known non-blockers, artifacts, and pass/hold/fail verdict/failure details. This is validation/reporting infrastructure only: no ShellForgeAI runtime product feature, cleanup/remediation/rollback execution, Docker/Compose mutation beyond the existing guarded deploy/recreate lane, production/container restart expansion, `shell=True`, arbitrary command execution, or natural-language mutation was added.
> The roadmap captures direction, not commitments. Anything below the
> "Shipped" header is current behavior. Anything below "Next" is intent.

## Shipped

- Docker01 hygiene cleanup-plan validation: `python scripts/docker01_hygiene_report.py --validate <report_dir> [--json]` validates PR209 report artifacts, strict JSON shape, safety flags, bounded proposal-only candidates (sized for current Docker01 reality), cleanup-plan language, realistic bounded report reads, and the fixed read-only commands-run allowlist. It is review validation only and adds no cleanup execution, Docker prune/image removal, file deletion, Docker/Compose mutation, restart, shell, model/Codex, network, package install, apply/merge/push, or runtime behavior expansion.
- PR172 (June 8, 2026): V2 governed recipe receipt audit report milestone. `recipes receipt audit [--json] [--target <target>] [--recipe <recipe_id>] [--limit N]` summarizes local execution/recovery receipt chains, links recovery receipts to original receipts, counts verification and safety findings, and flags malformed receipts, missing originals, unsupported recipes, production restart flags, Docker Compose flags, `shell_true`, arbitrary command execution, and natural-language execution. It is read-only and does not execute recipes, rerun receipts, restart containers, recover, rollback, clean up, remediate, call Docker/Compose, call shell, call a model, create exports, or add natural-language execution.
- PR170 (June 8, 2026): V2 governed receipt recovery execution milestone. `recipes receipt recovery-execute <receipt_ref> --confirm [--json]` executes only bounded `docker.disposable_restart` recovery from a valid receipt, rechecks exact current disposable/allowlisted non-production target gates, writes a recovery receipt, and supports read-only recovery status/validation plus `verify --receipt`. This is not true rollback of prior process state and does not add natural-language execution, production restart, broad targets, Docker Compose, cleanup, arbitrary remediation/rollback, `shell=True`, arbitrary commands, or model-driven execution.
- PR169 (June 7, 2026): V2 receipt rollback-preview milestone. `recipes receipt rollback-preview <receipt_ref> [--json]` and optional `rollback-preview --receipt <receipt_ref> [--json]` inspect existing governed receipts, explain rollback posture/gates, block production targets, and keep rollback execution, Docker/Compose calls, container restarts, rollback receipt creation, shell/model calls, and natural-language mutation out of scope. For `docker.disposable_restart`, the preview states that no true rollback exists and that any future recovery would be a separate exact-target, confirm-gated disposable restart with verification and receipt gates.
- PR168 (June 7, 2026): V2 receipt-aware verify milestone. `verify --receipt <receipt_ref>` and `recipes receipt verify <receipt_ref>` validate existing governed recipe execution receipts, report recorded `docker.disposable_restart` recipe/target/action/post-check evidence, distinguish historical receipt mutation from verify's read-only behavior, and keep retry/rollback/Docker/Compose/container restart/natural-language execution/model calls out of verify.
- PR160 (June 6, 2026): full-validation slow-test optimization and live runner output. The Lane C full pytest runner now streams pytest output in normal execution, prints xdist use, the exact command, and elapsed time, while preserving strict JSON dry-run planning, `pytest-xdist` (`-n auto --dist loadscope`) when available, serial fallback when unavailable, and `--durations=25` slow-test reporting. The slow V1 readiness profile-shape test now uses a fast in-process payload for repetitive profile JSON coverage while retaining a real quick readiness CLI smoke, and PR116 packet history/compare tests build ShellForgeAI-owned packet fixtures directly instead of repeatedly generating full packets through expensive CLI setup; schema/checksum/safety compare coverage remains. Validation-speed/visibility only: no runtime product feature, cleanup/remediation/rollback execution, Docker/Compose mutation, restart, `shell=True`, arbitrary command execution, or natural-language mutation was added.
- PR158 (June 5, 2026): parallel full-validation runner and slow-test visibility. Adds `scripts/run_full_pytest.py` for Lane C full validation; it uses `pytest-xdist` (`-n auto --dist loadscope`) when available, falls back cleanly to serial pytest when unavailable, and always reports slow tests with `--durations=25`. The PR lane helper now recommends the bounded runner for full validation and exposes `full_pytest_runner`, `duration_reporting`, and `xdist_used_if_available` metadata while Lane A/B remain targeted. Marker definitions are added for future partitioning without changing default test selection. Validation-speed/visibility only: no runtime product feature, cleanup/remediation/rollback execution, Docker/Compose mutation, restart, `shell=True`, arbitrary command execution, or natural-language mutation was added.
- PR157 (June 5, 2026): validation-lane optimizer and test impact map. Adds a read-only planning helper `scripts/validate_pr.py` plus the machine-readable impact map `scripts/validation_matrix.json` that map changed-file patterns to a validation lane (Lane A fast / Lane B targeted_runtime / Lane C full), the recommended regression tests, the exact commands, an explicit `full_pytest_required` answer with reason, and an estimated runtime class. Targeted validation becomes the default and full `pytest` becomes exceptional, while safety/execution/packaging boundaries (`*remediation*`, `*rollback*`, `*restart*`, `*mission*`, `*cleanup*`, `policy/**`, `tools/**`, `Dockerfile`, `pyproject.toml`, `scripts/v1_validate.sh`, …) and safety/execution keywords in changed code content still escalate to full. Documentation: `docs/VALIDATION_LANES.md`, `docs/VALIDATION_MATRIX.md`, OPS PR-lane policy. The helper is planning/dry-run only — it never mutates, deploys, runs Docker/Compose, or executes remediation/rollback/cleanup/restart; `--execute` (optional) runs only the recommended `ruff`/`compileall`/`pytest` commands from a fixed allowlist with no `shell=True` and no arbitrary command execution. No runtime product behavior changed.
- PR155 (June 5, 2026): V2 governed recipe preflight packet milestone for `docker.disposable_restart`. `recipes preflight --recipe docker.disposable_restart --target <target> [--save] [--json]` evaluates exact disposable restart readiness, previews only the bounded argv, writes/validates ShellForgeAI-owned preflight artifacts, and keeps execution disabled (`execution_available=false`, `command_executed=false`, no restart, no Docker/Compose/remediation/cleanup/rollback/shell/natural-language mutation).
- PR127: Doctor metadata hygiene clarity. `doctor` now separates runtime health from ShellForgeAI-owned historical artifact hygiene, states that no cleanup was performed, and points operators to the read-only `audit cleanup review` as the first safe command (cleanup execution stays gated). JSON adds additive, backwards-compatible `metadata_hygiene` context (`human_context`, `active_runtime_failure`, `cleanup_performed`, `first_safe_command`, `cleanup_execution_gated`) plus a top-level `safety` block. Warning/UX clarity only — no mutation, cleanup, remediation, or rollback behavior added.
- PR120: V1 release cut packaging completed with changelog, release notes, and ops handoff packet updates. V1 remains a CLI-first Linux/Docker operator knife with deterministic ask routing, deterministic mutation refusal, and ops report artifact lifecycle as the primary operator path.
- PR126: concise operator output and first-safe-command polish for 2AM readability across ops report/triage/diagnose/eligibility human views.
- PR132: session-local follow-up grounding for interactive references (`the first one`, `top suspect`, `that container`, `what about it?`) with deterministic mutation refusal preserved.
- PR133: concise/no-novel operator mode added `ops report --brief` plus deterministic ask/interactive pressure phrases (`no novel`, `quick status`, `what is on fire, keep it short`) for bounded read-only status without changing evidence collection, JSON schema, or safety gates.
- PR135: generic report/status command-help prompts now route deterministically to canonical `shellforgeai ops report` save/export/history/compare guidance in ask and interactive mode, with mutation-plus-report prompts still refused and no model fallback.
- PR136: interactive safe-command flag parity. The REPL now accepts a focused allowlist of canonical safe ShellForgeAI CLI flag forms (`v1 check --profile ... --json`, `ops report --brief/--json/history --limit 5/compare-latest --json`, `triage docker ... --json`, and remediation self-test/eligibility read-only forms) while mutation-like commands still refuse before fallback with no shell execution.
- PR137 (May 31, 2026): interactive help/discoverability polish. `help`, `/help`, `?`, `commands`, and `what can I do?` now render a concise deterministic operator help screen that lists exact supported safe interactive commands, pressure-mode brief status phrases, report/history/compare helpers, read-only follow-ups, safe remediation readiness checks, refused mutation examples, and the not-a-shell safety boundary. No mutation, Docker/Compose execution, cleanup/remediation/rollback execution, production restart, arbitrary shell execution, or model call was added for help rendering.
- PR139 (May 31, 2026): interactive session handoff summary. `summary`, `/summary`, `/summary --json`, and handoff questions such as `what happened in this session?` render a deterministic local summary of checks, latest evidence/artifact pointers, findings, refusals, first safe next command, and safety posture. Summary rendering does not call the model, rerun collectors, execute shell, or add cleanup/remediation/rollback/Docker/Compose mutation.
- PR140 (May 31, 2026): interactive summary artifact handoff workflow. `/summary --save` and `/summary --save --json` save portable summary artifacts, while `shellforgeai session summary validate/export/export-validate` checks and copies those handoffs with manifests, checksums, explicit non-mutating safety flags, controlled failure output, and no model call or execution expansion.
- PR141 (May 31, 2026): interactive summary history/compare workflow. `shellforgeai session summary history`, `compare`, and `compare-latest` make saved REPL handoff summaries useful over time by validating and reading existing artifacts, listing recent summaries, and comparing checks/findings/refusals/safe commands/artifacts/runtime visibility/safety drift. The workflow is artifact-read-only: no collectors rerun, model call, shell execution, cleanup/remediation/rollback execution, or Docker/Compose mutation is added.
- PR142 (May 31, 2026): interactive summary export-compare workflow. `shellforgeai session summary compare-export <before-export> <after-export>` validates two exported interactive summary handoff bundles and compares the embedded summary payloads in human or strict JSON mode, including checks/findings/refusals/safe commands/artifact references/metadata/safety drift plus `--only-changed` and `--include-stable`. It is read-only and does not rerun collectors, call the model, execute shell, write comparison artifacts, or mutate Docker/Compose/system state.
- PR146 (June 2, 2026): triage UX consistency milestone. The V2 triage family (`triage`, `triage --brief`, `triage --json`, `triage --target <target>`, and the compatibility `triage docker` views) now shares one consistent operator shape — every human view leads with `Status:` / `Risk:` and closes with `Safety: Read-only. No mutation executed.`. `triage docker --brief` is a new safe compatibility alias that mirrors `triage --brief`, no-suspect output points the first safe command at a read-only status/report command (never a detail command for a missing suspect), brief-style triage asks (`quick triage`, `no novel, triage`) render the bounded read-only view, and interactive help/allowlist list the supported triage forms. Read-only polish only: no mutation, cleanup execution, remediation execution, rollback execution, Docker/Compose mutation, production restart, `shell=True`, arbitrary command execution, or natural-language mutation was added.
- PR148 (June 2, 2026): V2 `apply-preview` execution-boundary preview milestone. The golden path now includes `status -> triage -> propose -> apply-preview`; the new command supports brief/JSON/source/target forms, deterministic ask routing for apply-preview phrasing, and interactive allowlist/help coverage while refusing production targets and mutation phrasing. It is read-only only: no apply, mission, plan artifact, remediation receipt, cleanup/remediation/rollback execution, Docker/Compose mutation, container restart, production restart, `shell=True`, arbitrary command execution, natural-language mutation, or model call was added.

- Deterministic core ops runtime: `diagnose` collects evidence, classifies
  the target, and emits a conservative plan + audit + artifacts.
- Profile system (`inspect`, `assisted`, `lab-direct`, `prod-readonly`).
- LLM provider abstraction with OpenAI Codex CLI as default, plus Ollama,
  vLLM, OpenAI-compatible, and OpenRouter.
- Interactive operator REPL with workspace trust, slash commands, paste
  guard / quarantine, and streaming synthesis.
- Context-first routing: recognized ops intents auto-run typed read-only
  collectors before any model call.
- Adaptive read-only follow-ups (CPU/process, memory/swap, storage/IO,
  network/DNS, service health, general context). Inspect with `/pending`.
- `audit list` / `audit show`; artifacts are written only when produced.
- Build metadata via `SHELLFORGEAI_BUILD_PR` / `_COMMIT` / `_BRANCH` /
  `_DATE` env vars; surfaced by `--version`, `version`, and `doctor`.
- PR30: evidence-backed operator runbooks. `shellforgeai runbook` (and
- PR31: formal runbook validation (`validate-runbook`), schema-versioned `runbook.json`, and stricter advisory risk scoring.
- PR32: mutation proposal objects and approval queue.
  `shellforgeai approvals create [--from-runbook PATH] [--latest] [--include-low]`
  / `list` / `show` / `approve` / `reject` / `cancel` / `archive` /
  `validate`. Proposals live under
  `<data_dir>/approvals/{pending,approved,rejected,canceled,archived}/`
  with a schema-versioned JSON payload (`source`, `kind`, `risk`,
  `confidence`, `safety_labels`, `proposed_steps`, `rollback`,
  `verification`, `execution.allowed=false`). Approval is a paper
  trail — it does not execute anything; ask phrases like "approve
  and run the fix" / "fix everything now" are refused cleanly.
- PR33: apply preflight + operator execution bundle export.
  `shellforgeai apply <approved-proposal>` runs deterministic preflight
  checks and writes `apply-preview.md`, `operator-commands.sh`,
  `rollback.sh`, `validation.md`, and `apply-preflight.json` under
  `<data_dir>/apply_bundles/<id>/`. The generated shell scripts contain
  an early `exit 2` before any operator-run command. ShellForgeAI still
  does not execute anything; `apply` remains validation-only.
  `diagnose --with-runbook`, fix-plan asks) turn existing read-only
  evidence into a labelled operator-run remediation plan with
  prechecks, options, rollback, and post-fix validation. ShellForgeAI
  does not execute any of the steps; `apply` remains validation-only.


## Validation discipline milestones

- Completed: Docker01 merge-readiness comment drafting. `scripts/docker01_merge_readiness.py --comment` renders the existing merge-readiness evidence as a concise paste-ready Markdown review comment, and `--out --comment` also writes `merge-comment.md` in the report directory. Status wording maps `pass_candidate` to `PASS / mergeable`, `hold_candidate` to `HOLD / needs follow-up`, and `unknown` to `NEEDS EVIDENCE / cannot determine`. The renderer is evidence-only: no GitHub post/comment/approval/merge, no validation or QA execution, no Docker/Compose mutation, no cleanup/prune/delete/restart, no model/Codex/network/package install, and SeedOfEvil remains final merge owner.
- Completed: PR165 mainline/scheduled validation baseline helper.
  `scripts/run_mainline_validation.py` creates validation-only baseline
  manifests, summaries, logs, and duration reports/history for the current
  checkout. It keeps full-suite confidence in an explicit mainline lane instead
  of overloading every PR, and it does not auto-merge, deploy, remediate, call
  Docker/Compose, restart, prune, or change runtime product behavior.
- Completed: PR206 Docker01 operator QA evidence bundle.
  `scripts/docker01_operator_qa_bundle.py` runs the standard read-only smoke QA
  set once and writes a bounded, pasteable evidence packet (`qa-summary.md`,
  `qa-results.json`, `safety-assertions.json`, `container-state.json`,
  `validation-status.json`, `commands-run.json`, `raw/`) so the Docker01 PR
  handoff is no longer assembled by hand. It is run from the Docker01 host:
  product smoke commands execute inside the running container through a narrow
  `docker exec shellforgeai shellforgeai …` allowlist (no host `shellforgeai` on
  PATH required), while host checks and the validation status viewer (run with
  the current Python interpreter and scoped to the PR/commit under review via
  `--pr`/`--commit`, so stale evidence from another PR is never embedded) stay
  host-side so the guarded lane's host artifacts stay visible. Evidence collection only: a small fixed command
  allowlist that rejects unsafe `docker exec` shell/binary forms, argv-list
  subprocesses with no `shell=True`, no cleanup/remediation/rollback/recovery,
  no Docker/Compose mutation or restart/prune, no package install/network, and
  no cloud apply/merge/push. The bundle never auto-declares a PR mergeable; the
  reviewer still gives the final verdict.
- Completed: PR207 Docker01 QA bundle validate/history/compare lifecycle.
  The same helper gains four **artifact-only** modes — `--validate-bundle`,
  `--history`, `--compare`, `--compare-latest` — that prove bundles are complete,
  internally consistent, discoverable, and comparable without re-running smoke QA
  or mutating Docker01. They only read bundle files, parse JSON, and compute
  sha256 hashes (no subprocess, no Docker/ShellForgeAI/validation execution).
  Newly generated bundles carry a `bundle-manifest.json` (size + sha256 of every
  file) for tamper detection; legacy PR206 bundles without it stay valid with a
  warning. Scoped validation `not_found` is treated as clean evidence-of-absence;
  `scope_matched=false` is surfaced as a warning, never as current evidence.
  Compare classifies deltas as regressed/improved/changed/same so a new bundle
  can be shown not to regress against the prior one in the PR handoff. Reviewer
  still gives the final merge verdict.

## V2 golden-path milestones

- Completed: V2 read-only `status` entrypoint.
- Completed: V2 read-only `triage` entrypoint and command consistency.
- Completed: PR147 V2 read-only `propose` entrypoint for next-action proposal previews. `propose` creates no remediation plan artifact and executes nothing.
- Completed: PR148 V2 read-only `apply-preview` entrypoint for execution-boundary previews. `apply-preview` creates no mission, apply record, plan artifact, or remediation receipt and executes nothing.
- Completed: PR149 V2 read-only `verify` entrypoint for current-state verification. `verify` assumes no applied action and consumes no receipt.
- Completed: PR150 V2 read-only `handoff` entrypoint — the final golden-path step (`status -> triage -> propose -> apply-preview -> verify -> handoff`). `handoff` summarizes the deterministic posture and first safe command, optionally saves a ShellForgeAI-owned artifact, and never executes fixes or implies remediation happened.
- Completed: PR152 V2 read-only handoff artifact lifecycle — `handoff --save -> validate -> export -> export-validate`. Save/export write only ShellForgeAI-owned artifacts; validate/export-validate are strictly read-only. Missing/malformed refs fail cleanly with no traceback, and no mutation/execution behavior was added.
- Completed: PR153 V2 read-only handoff artifact history/compare — `handoff history`, `handoff compare <before> <after>`, and `handoff compare-latest` make saved handoffs reviewable over time. History lists recent saved handoffs; compare reports status/risk/target/current_status/golden-path/first-safe-command/safe-next-commands/limitations/warnings/safety drift; compare-latest compares the newest two. Strictly read-only: no artifact writes, collector rerun, model call, shell, or Docker/Compose/host mutation.

## Next

- Model-driven hand-off into a richer plan synthesis surface (still
  validation-only at the boundary).
- `apply` execution behind explicit operator approval and policy gating.
- Optional read-only MCP server (`shellforgeai mcp serve --readonly`)
  exposing `shellforgeai_health`, `shellforgeai_diagnose_*`, and
  `shellforgeai_audit_recent`. See `docs/codex-integration.md`.
- Broader knowledge sources (curated runbooks, opt-in web).
- Richer interactive UX: scoped quoting, evidence breadcrumbs, undo of
  queued follow-ups.

## Non-goals

- Becoming a shell.
- Hidden mutation under workspace trust.
- Auto-apply of model-generated plans.


- PR33: approval/apply hardening milestone: proposal fingerprints + create idempotency, approvals list filters, show/validate polish, idempotent apply bundle refresh status, and script label normalization; apply remains validation-only.
- PR37: policy-gated action compiler milestone. `shellforgeai actions compile`
  turns an approved proposal's operator-run steps into structured, review-only
  action records under `<data_dir>/actions/<proposal-id>/` (`actions.json`,
  `actions.md`). Classification is deterministic string/regex — no LLM call,
  no shell execution. Mutation steps are classified `blocked` with
  `SERVICE-IMPACTING` / `FILESYSTEM-MUTATION` / `PACKAGE-MUTATION` /
  `NETWORK-MUTATION` / `FIREWALL-MUTATION` labels; read-only inspection is
  `read_only_review`; everything else defaults to `manual_only`. `actions
  validate` enforces the review-only invariants (every action carries
  `execution_allowed=false`, top-level `execution_status=not_executed`,
  summary counts match, blocked mutations are never marked read-only). `apply
  <approved-proposal>` also writes the same `actions.json`/`actions.md`
  alongside the static bundle. Compiled does not mean applied; `apply`
  remains validation-only.
- PR34: audit/export pack milestone. `shellforgeai export` packages
  evidence/summary/plan/runbook/proposal/apply-preflight artifacts into
  `<data_dir>/exports/<export_id>/` with `export-manifest.json`,
  `export-summary.md`, and `checksums.sha256`. Supports `<session-id|dir>`,
  `--latest`, `--proposal <id>`, `--latest-approved`, `--output`,
  `--redact`; `--approved` is refused as too broad. `validate-export`
  re-checks manifest, files, checksums, and the apply-preflight
  execution invariants. Export only copies/reads files — no execution,
  no mutation. `apply` remains validation-only.
- PR38: stale-evidence and drift guard milestone. `shellforgeai guard
  check|check-actions|check-export|show` runs deterministic freshness
  and source-hash drift checks against proposals, compiled actions,
  apply preflight bundles, and export packs. Guard reports are written
  under `<data_dir>/guards/<source-id>/` as `guard-report.json` and
  `guard-report.md`, with decisions `fresh`, `warning`, `stale`,
  `drift_detected`, or `blocked`. Default max ages: proposals/actions/apply
  bundles 24h, exports 7d; `--max-age-hours` overrides per call. Newly
  generated proposals and compiled actions record optional `source_hashes`
  so a later guard call can detect post-creation tampering of the
  underlying `evidence.json`, `runbook.json`, `summary.md`, or
  `proposal.json`; older artifacts without recorded hashes validate cleanly
  with `source_hash_status=unknown`. `apply` runs the guard internally and
  refuses by default when the proposal is stale or drifted; `--allow-stale`
  bypasses stale (drift is never bypassed) and `apply-preflight.json`
  records `guard_status` and the guard report path. Every guard report
  records `execution_allowed=false` and `execution_status=not_executed`.
  Guard checks are read-only — no remediation, no host mutation. `apply`
  remains validation-only.

- PR39: guard-aware audit timeline milestone (`audit timeline/show/validate`) for chronological operator incident trails with explicit no-execution safety state.
- PR40: audit-aware incident index / search milestone. `shellforgeai audit
  index [--rebuild]` builds a compact deterministic index
  (`<data_dir>/audit/incident-index.json`) from audit events, artifact
  sessions, approval proposals, apply bundles, exports, and compiled
  actions. `shellforgeai audit search [<query>] [--component/--target/
  --kind/--status/--risk/--proposal/--session/--type/--since] [--json]`
  filters the index with case-insensitive token AND across
  title/summary/component/target/kind/status/session_id/proposal_id/
  tags/paths plus exact-match filters. `shellforgeai audit index validate`
  re-validates the on-disk index (unique `item_id`, required fields,
  numeric `source_counts`, string paths, and safety invariants). The ask
  router (`search audit for ...`, `find drift refusals`, `find approved
  proposals`, `did anything execute?`) routes to the same index. The
  index is read-only metadata navigation: the only file written is the
  index itself, and every indexed item preserves `execution_allowed=false`,
  `execution_status=not_executed`, `mutation_performed=false`. `apply`
  remains validation/preflight-only.

- PR41 completed: audit/index/export retention reporting, dry-run prune planning, explicit `--execute` metadata prune, and compact archive export/validation.

- PR42 completed: ask intent routing hardening for ShellForgeAI-owned workflows (audit/retention/export/index/approvals/actions/guard/apply-preflight), plus safer command suggestions and host-audit disambiguation.

- PR43 completed: operator status dashboard (`shellforgeai status`) with read-only health/safety summary, JSON schema v1 output, ask-route integration for status questions, and explicit non-execution reporting.

- Metadata hygiene visibility and deterministic dry-run cleanup guidance in doctor/retention/ask flows.

- PR46 completed: first guarded mutation gate. `shellforgeai audit prune`
  may now execute deletion limited strictly to ShellForgeAI-owned metadata
  under `<data_dir>` and `<data_dir>/audit`, only after both `--execute` and
  `--confirm` are passed and per-path safety validation succeeds. Each
  execute writes a JSON + markdown receipt under
  `<data_dir>/prune_receipts/`. Audit events for prune carry
  `metadata_cleanup_executed`/`remediation_execution=false`/`shellforgeai_owned_paths_only=true`
  in `details`; the audit safety block remains
  `execution_allowed=false`/`execution_status=not_executed`/`mutation_performed=false`.
  Ask routing for cleanup phrasing refuses to delete and prints the explicit
  `--execute --confirm` CLI guidance. `apply` remains validation/preflight-only.

- PR47 completed: first non-metadata mutation gate. `shellforgeai apply
  <approved-proposal-id> --execute --confirm` may now execute exactly one
  `docker restart <container>` for containers in the explicit allowlist at
  `<data_dir>/policy/lab-container-restart-allowlist.json` (disabled by
  default) when every gate passes: explicit `--execute`/`--confirm`,
  `SHELLFORGEAI_MUTATION_MODE=lab` + `SHELLFORGEAI_ALLOW_LAB_CONTAINER_RESTART=1`,
  allowlist enabled with non-empty entries, proposal status `approved`, PR38
  guard `fresh`/`warning`, the compiled action is exactly
  `docker restart <safe-name>`, the container name passes the safe regex.
  Execution goes through a `CommandExecutor` abstraction with `shell=False`
  and list-form argv only; tests use the fake executor. Each execute (and
  refusal) writes a receipt under `<data_dir>/execution_receipts/`. The
  audit event for a successful lab restart is the first ShellForgeAI event
  with `safety.execution_allowed=true`/`execution_status=executed`/
  `mutation_performed=true` and `safety.mutation_scope=lab_container_restart_only`;
  every other event remains strict no-execution. Ask refuses to execute and
  prints the explicit `--execute --confirm` CLI guidance.

- PR48 completed: post-mutation verification gate for the PR47 lab container
  restart. After the allowed `docker restart <allowlisted-container>` exits
  0, ShellForgeAI automatically runs read-only verification: `docker inspect
  <container>` before and after the restart (via a `ContainerInspector`
  abstraction with `shell=False` argv-only subprocess), a bounded
  post-restart wait, and an optional bounded health-poll loop only when the
  container declares a healthcheck. The receipt JSON gains a
  `verification` block (`status` of `passed`/`warning`/`failed`/`skipped`,
  `started_at_before/after`, `started_at_changed`, `running_after`,
  `health_before/after`, `restart_count_before/after`, `notes`,
  `evidence`) and gets a sibling evidence directory
  `execution_receipts/exec_<id>/{before-inspect.json,after-inspect.json}`
  plus a human-readable `exec_<id>.md`. The audit event adds
  `details.verification_status`, `details.container_running_after`,
  `details.started_at_changed`, `details.health_after`, and
  `details.verification_notes`; event-level `status` becomes `success`,
  `warning`, or `failed`. PR48 does not widen mutation scope: no second
  restart, no `docker exec`, no `docker compose|stop|start|kill|rm|run`,
  no shell, no arbitrary command strings. Ask gains read-only verification
  queries (`did the restart work?`, `show restart verification`, `show
  post-mutation verification`, `show last execution receipt`, `was the
  container running after restart?`) that summarize the latest receipt
  without executing anything. `restart it and verify` is still routed to
  the mutation refusal path with explicit guidance that verification runs
  automatically after the approved CLI execution.


## PR50 — Evidence-to-proposal restart builder

Adds deterministic proposal creation for allowlisted lab/disposable Docker containers from evidence artifacts, with dedupe by fingerprint. This is proposal metadata only and does not approve, rollback, or execute mutation.

- PR51: restart proposal dry-run checklist/readiness preview (`approvals restart-plan`) with JSON + ask surfacing, read-only safety path before approval/execution.
- PR52: guided safe restart mission workflow (`mission restart prepare/status/checklist/validate/export`) that ties evidence, proposal, approval, rollback preview, and apply readiness into a single mission record. Metadata only; no new mutation scope.
- PR53: mission execute handoff (`mission restart execute <mission-id> --execute --confirm`) that verifies mission readiness and delegates to the existing PR47/PR48/PR49 apply gate. No new executor, no broader mutation scope, no natural-language execution. The actual mutation remains the existing allowlisted `docker restart <target>`. The apply receipt path is referenced from the mission record after delegation.
- PR54: mission post-execution report and export pack (`mission restart report`, `mission restart export [--redact]`, `mission restart validate-export`). Read-only. Bundles mission record, mission-report.json/md, proposal, rollback preview, apply receipt, before/after inspect evidence, source evidence, audit events, manifest, and checksums into `<data_dir>/mission_exports/<mission-id>/`. Reuses the PR34 redactor for `--redact`. No new mutation class; report/export commands never execute, apply, approve, or roll back. Manifest carries `safety.execution_status="not_executed_by_export"` and `safety.mutation_performed_by_export=false`.

- PR55 milestone: first-class audit cleanup review workflow (plan/archive/execute/validate/report) for ShellForgeAI-owned metadata only.

## PR56 milestone: Compose ownership/context

- Added read-only Compose project/service ownership detection from Docker labels.
- Added `compose inspect` and `compose list` context commands.
- Added advisory Compose context propagation into docker evidence and restart proposal/plan metadata.
- No `docker compose` mutation path added.

## PR57 milestone: Compose ask-route polish

- Added deterministic ask target extraction for Compose-context question forms.
- Compose context asks now route to the existing read-only inspect/list context path when a safe target is present.
- Missing/invalid targets now produce explicit safe next-step CLI suggestions.
- Natural-language Compose mutation requests remain refused; no new execution/mutation path added.

## PR58 milestone: Compose-aware restart proposal and mission enrichment

- Restart proposals built from evidence now carry a normalized `compose_context`
  block (project/service/working_dir/config_files/version/oneoff/source) when
  the target container has Docker Compose labels. Non-Compose targets record
  `{"detected": false, "reason": "compose labels not present"}`.
- `approvals show`, `approvals restart-plan` (human and `--json`), mission
  records (`mission.json`/`.md`, status/checklist), apply execution receipts,
  and `mission restart report` now surface Compose ownership context, plus
  explicit `restart_scope="container"` and `compose_mutation=false`.
- Restart-plan readiness blocks when a proposal's command preview tries to use
  `docker compose`; readiness is NOT blocked merely because the target is
  Compose-managed.
- Ask integration: read-only queries like "show compose context for this
  restart proposal" / "is this mission targeting a compose service?" answer
  from metadata. Compose service mutation phrasings (e.g. "propose restart for
  compose service X", "docker compose restart X", "compose up X",
  "recreate compose service X") are refused with safe suggestions
  (`compose inspect <container>` and the container-scoped
  `approvals propose-restart`).
- No `docker compose` execution path added. Command preview remains the exact
  `docker restart <container>`; the apply gate remains the only mutation path.
  PR58 is context enrichment only.

## PR60 milestone: read-only ops status board

- Added `shellforgeai ops status` and `shellforgeai ops status --json` for compact
  artifact-backed operator posture reporting.
- Read-only only: no new executor, no apply path changes, no `docker compose`
  mutation, no restart execution from status.

- PR59 milestone: ask-reference disambiguation for implicit proposal/mission references (`this`/`latest`/`current`/`most recent`) with deterministic read-only resolver, stale warning guard (24h default), explicit-ID precedence, and ambiguity listing (no guessing/no execution).

- PR61: added read-only `compose restart-preview` command and ask preview phrasing for Compose service restarts (preview only; no compose execution path).
- PR62: added `compose propose-restart` to create pending `compose_service_restart` proposal artifacts from Compose metadata (proposal-only, non-executable, apply refusal retained).

- PR119 planned/completed: V1 release-candidate checklist and handoff documentation (`docs/V1_RELEASE_CANDIDATE.md`) plus contract tests to prevent release-gate drift.

- PR64: hardened compose-service restart mission preflight diagnostics and post-execution verification evidence so blocked-vs-executed outcomes are explicit without broadening mutation scope.

- PR65: hardened `rollback preview`/`rollback validate` for `compose_service_restart` proposals with recovery-preview schema, command-shape validation, config hashing (hash-only), and explicit non-automatic rollback posture.

- PR66: added read-only `compose env-check` diagnostics to explain Compose restart execution readiness blockers (runtime preflight, compose-file snapshot visibility, and allowlist posture) without creating proposals/missions or executing Compose mutation.

- PR67: added a disposable Compose execution harness (fixture/template,
  external lab helper script, README) plus readiness tests so the
  Compose service restart lane (PR61–PR66 gates) can be proven against a
  throwaway target. ShellForgeAI continues to refuse `docker compose
  up/down/recreate`, never runs the lab helper itself, never executes
  natural-language Compose mutation, and the real `shellforgeai` service
  remains blocked from the restart lane because it is not (and must not
  be) labeled disposable/allow_restart.

- PR68: added an optional live disposable Compose restart proof path
  (`scripts/pr68_disposable_compose_restart_proof.sh` orchestrator and
  docs) so NewTwo/operators can drive the existing PR63-PR67 gated
  Compose service restart lane end-to-end against the disposable PR67
  harness target. The orchestrator is lab-only; ShellForgeAI never
  invokes it. Default behavior is dry-run / readiness only. Even with
  the explicit `--execute-approved-disposable-restart` flag the
  orchestrator only verifies readiness and prints the manual gated
  command sequence; the operator runs `shellforgeai mission
  compose-restart execute <mid> --execute --confirm` directly. The
  orchestrator refuses production-looking target names, pins the exact
  disposable target invariants, and never installs packages, never
  mounts host paths, never prunes, never deletes arbitrary paths, and
  never edits production compose files. PR68 adds no new ShellForgeAI
  mutation capability, no generic Compose executor, no `docker compose
  up/down/recreate` from the app, no host-side bypass, and no
  natural-language execution.

- PR69: added read-only `compose env-contract` execution-environment contract/readiness diagnostics so operators can verify exact disposable-lane prerequisites without executing restart or loosening safety gates.


## PR70 milestone: metadata hygiene status and cleanup polish

- Doctor metadata hygiene now reports explicit category-level reasons and safe, gated cleanup command sequence.
- Doctor JSON now includes structured `metadata_hygiene.reasons[]` and `suggested_commands[]`.
- Cleanup plan output now includes matched/kept/candidate and outside-data-dir counters with explicit safety flags.

## PR71 milestone: metadata cleanup archive/execute live-safe command pass

- Hardened cleanup lane sequencing: retention/report -> plan (dry-run) -> archive -> validate -> execute `--confirm`.
- Execute now requires matching validated archive + plan fingerprint match before any deletion.
- Execute results/receipts include plan/archive linkage, candidate/deleted/skipped/failed counters, and explicit safety flags.
- Scope remains ShellForgeAI-owned metadata only; no Docker/Compose/system mutation and no natural-language cleanup execution.

## PR77 milestone: cleanup execution UX/report polish

- Polished `audit cleanup execute-readiness` so the boundary between
  "gates satisfied" and "operator-approved" is explicit. JSON now
  exposes top-level `ready_for_execute_confirm`,
  `operator_action_required`, `read_only`, `cleanup_executed`,
  `deletion_performed`, and a `gates` block alongside the existing
  `readiness`, `plan`, `archive`, `safety`, and `next_commands`
  payload. Human output begins with `Status:` and `Validated gates:`
  blocks and an `Operator warning:` that explicitly states the command
  did not delete anything; the blocked branch refuses to surface the
  execute command and adds `Do not execute until blockers are
  resolved.`
- Polished `audit cleanup execute` refusal without `--confirm` to list
  the required gates (`matching archive`, `archive validation`,
  `matching plan fingerprint`, `explicit --confirm`), say
  `Nothing was deleted.`, and point back at
  `audit cleanup execute-readiness`.
- Polished `audit cleanup report` to add a `Post-execute checks:`
  block in human output and a `post_execute_checks` array in JSON
  (`audit cleanup validate <receipt>`, `audit retention`,
  `audit cleanup review`, `doctor`). Added top-level `receipt_kind`,
  `receipt_valid`, `receipt_plan_id`, `deleted`, `failed`, and
  `bytes_removed` mirror fields for downstream consumers.
- All PR55/PR71/PR74/PR75/PR76 cleanup gates and read-only properties
  are unchanged. Readiness and report do not call `cleanup execute`,
  do not mutate Docker/Compose/services/packages/firewall/network/
  system, and natural-language `ask` paths still cannot reach
  `cleanup execute`. Only `audit cleanup execute <plan> --confirm`
  deletes.
- Added `tests/test_pr77_cleanup_execute_polish.py` covering
  readiness JSON top-level fields and `gates`, human Status/Validated
  gates/Operator warning blocks, blocked branch hiding the execute
  command, execute-refusal gate listing, refusal non-deletion,
  report `post_execute_checks` and top-level mirror fields, and
  read-only safety regressions.

## PR76 milestone: cleanup execute readiness and post-execute report

- Added read-only `shellforgeai audit cleanup execute-readiness
  <plan-id-or-path>` (and `--json`) that re-checks the PR71 gates
  before the operator runs `cleanup execute --confirm`: plan kind and
  safety fields, matching cleanup archive, archive validation, matching
  plan fingerprint, allowed-root candidate paths. When ready it emits
  an operator-only `next_commands.execute` invocation that still
  includes `--confirm`; when blocked it lists the blockers cleanly.
- Hardened `shellforgeai audit cleanup report
  <cleanup-receipt-or-dir>` with a richer human summary
  (deleted/failed/bytes/skipped, plan/archive linkage, receipt safety,
  fingerprint cross-check) and a strict `--json` output.
- Both commands are strictly read-only: they create no plans, no
  archives, no receipts; delete nothing; never touch Docker/Compose/
  services/packages/firewall/network/system; and never accept
  natural-language cleanup execution. JSON safety blocks pin
  `read_only=true`, `cleanup_executed=false`, `deletion_performed=false`,
  `arbitrary_paths_allowed=false`, `docker_mutation=false`,
  `system_mutation=false`, `natural_language_execution=false`,
  `explicit_confirm_required=true`.
- PR55/PR71 cleanup execute gates are unchanged. `cleanup execute
  <plan> --confirm` with matching validated archive and matching plan
  fingerprint remains the sole deletion path.

## PR75 milestone: /data cleanup prepare workflow

- Added `shellforgeai audit cleanup prepare --category <cat>
  --max-age-days N --keep-latest M` (and `--json`) — a guided
  pre-execution workflow that reads the cleanup review posture, creates
  a dry-run cleanup plan via the existing plan path, creates the
  matching archive via the existing archive path, validates the archive,
  and emits a decision packet. The packet pins `execute_performed=false`
  and `deletion_performed=false` and prints the exact execute command
  marked operator-approved only.
- Prepare never deletes candidate files, never calls cleanup execute,
  never touches Docker/Compose/services/packages/firewall/network/system,
  and never accepts natural-language execution. Unknown or
  path-traversal category values are refused before any plan/archive is
  created. Strict JSON pins `safety.cleanup_executed=false`,
  `safety.mutation_performed=false`, `safety.deletion_performed=false`,
  `safety.arbitrary_paths_allowed=false`, `safety.docker_mutation=false`,
  `safety.system_mutation=false`.
- PR55/PR71 cleanup execute gates are unchanged. Prepare creates plan
  and archive metadata only; the existing
  `cleanup execute <plan> --confirm` with matching archive/fingerprint
  remains the sole deletion path.

## PR74 milestone: /data cleanup review pack

- Added read-only `shellforgeai audit cleanup review` (and `--json`,
  `--category <name>`, `--top N`) that summarizes the ShellForgeAI
  metadata footprint, groups categories by size, marks each as
  `cleanup_supported` or report-only, recommends the safest narrow
  first lane (default: `exports`), restates the PR71 deletion gates,
  and prints the next safe dry-run command.
- Review is strictly read-only: it never creates plans, archives, or
  receipts, never deletes, never calls `docker compose`, never mutates
  services / packages / firewall / files / network, and never accepts
  natural-language execution. The JSON `safety` block pins
  `review_only=true`, `cleanup_executed=false`, `archive_created=false`,
  `mutation_performed=false`, `arbitrary_paths_allowed=false`,
  `docker_mutation=false`, `system_mutation=false`,
  `natural_language_execution=false`.
- PR55/PR71 cleanup gates are unchanged. Review enables operator
  decision-making before the existing
  `plan → archive → validate → execute --confirm → receipt validation`
  sequence; it does not loosen any gate.

## PR73 milestone: compose execution environment readiness plan

- Added read-only `shellforgeai compose env-plan --target <target>`
  (and `--json`) that maps current env-check / env-contract readiness
  blockers to explicit operator-controlled remediation steps for the
  disposable Compose restart proof.
- Every plan entry carries `shellforgeai_action="none"` and
  `automated=false`. Production-like targets are flagged with a warning
  and routed to the PR67 disposable harness recommendation — never to a
  "label production disposable" suggestion.
- env-plan is read-only: no `docker compose` execution, no host-side
  bypass, no host path mount, no package install, no proposal / mission
  / rollback preview / apply / cleanup artifact creation, no
  natural-language mutation execution, and no PR63–PR71 gate weakening.

## Current state (PR71 baseline)

- The safe evidence → runbook → proposal → approval → rollback preview
  → mission → apply → verification → receipt → audit/export spine
  exists end-to-end.
- The exact-container restart lane (PR47/PR48/PR49) is the only
  always-available real mutation lane, and remains allowlist-only,
  env-gated, and `--execute --confirm`-gated.
- The Compose service restart lane (PR61–PR69, PR73) has preview,
  proposal, mission, rollback recovery preview, env-check, env-contract,
  env-plan, and a disposable harness/proof orchestrator. Live execution
  remains gated by the env-contract and is intentionally blocked in
  default production deployments. env-plan is enablement guidance only
  and performs no environment changes.
- Metadata cleanup execution is hardened (PR71): archive + fingerprint
  + `--confirm` before any deletion of ShellForgeAI-owned metadata.

## Next tracks (intent, not commitment)

1. Documentation consolidation and the PR72 handoff baseline.
2. Optional env-contract satisfaction for a deliberate disposable live
   Compose restart proof on Docker01 (Compose CLI inside the runtime,
   readable compose file, disposable target labels).
3. Compose verification / closure-report polish *after* a successful
   disposable proof.
4. Compose recreate **preview only** at a later milestone — never
   recreate execution.
5. Never jump to broad production mutation. The product stays a Tier-3
   triage tool with narrow, audited mutation lanes.

## PR82 milestone: broad ask triage grounding

Live QA on Docker01 (PR81 followup, head `b0d33b4`) confirmed
deterministic `shellforgeai triage docker` ranking of all five
battle-lab suspects (`sfai-crashloop`, `sfai-bad-http`,
`sfai-disk-pressure`, `sfai-noisy-errors`, `sfai-permission-denied`)
with the read-only safety invariants clean (`read_only=true`,
`mutation_performed=false`, every cleanup/proposal/mission/apply/
docker-compose/container-restart/natural-language/shell-true flag
`false`).

Remaining PR81 gap: broad model-backed ask was not reliably consuming
the deterministic triage output. The PR82 fix wires broad Docker /
2AM ask prompts to call `triage_ranking.collect_scene` +
`rank_scene` directly and render the deterministic ranking from the
ask handler — no LLM re-ranking, no invented suspects, no
per-container evidence collapse.

- New ask intent detector
  `ask_routing.is_broad_docker_triage_intent` matches read-only
  broad-Docker prompts: "what's on fire?", "2AM triage", "the Docker
  box feels broken", "rank Docker suspects", "broadly scan the
  current scene", "rank all sfai-battle-lab suspects by severity",
  "what should I inspect first?", "show current Docker suspects",
  "what containers look suspicious?".
- New mutation-intent detector
  `ask_routing.is_triage_mutation_intent` matches phrases that follow
  a ranking ("restart the top suspect", "fix the crashloop", "clean
  up disk pressure now", "stop noisy-errors", "apply the top fix",
  "create a restart proposal for the top suspect", "docker compose
  restart the top one", "delete old files causing disk pressure").
  These refuse from ask with the PR82 no-mutation wording and
  redirect to the explicit gated CLI; they never render the
  deterministic ranking.
- New `cli._handle_broad_triage_ask` is wired into `ask` before the
  existing PR47/PR74-PR80 handlers. It reuses the PR81 engine
  directly (no subprocess, no `shellforgeai triage docker` shell-out)
  and renders a 2AM-readable answer with Safety / Scene summary /
  ranked suspects (severity / confidence / Evidence / Safe next) /
  optional Watch / Next safe steps footer.
- The deterministic ranking, severity/confidence, classes, per-
  container evidence, and per-suspect `safe_next_commands` are taken
  unchanged from the PR81 engine. Per-container evidence isolation
  (PR81 followup anti-attribution guards) survives the renderer:
  `sfai-bad-http` does not pick up `disk_pressure` or
  `permission_denied` evidence, etc.
- Tests added: `tests/test_pr82_broad_ask_triage.py` covers route
  detection (read-only and mutation), the deterministic grounding
  rules (ordering, severity preservation, no invented suspects, no
  omitted fixture suspects, per-container evidence isolation), the
  ask-shape requirements (all five battle-lab suspects rendered,
  crashloop pinned as top, safety statement present, read-only next
  commands, no execution commands), mutation refusal for all five
  PR82 mutation phrasings, the empty-scene and collection-failure
  paths, and safety regressions (handler source has no
  `shell=True`, no mutation-helper calls; broad ask path does not
  fall through to `diagnose_target` or `build_provider`; audit
  events for both render and refusal record every mutation flag
  `false`).
- No mutation behavior added. The ask route never restarts/stops/
  removes containers, never runs `docker compose` mutation, never
  runs `cleanup prepare/archive/execute`, never creates proposals
  or missions, never runs `apply`, and never uses `shell=True`. PR81
  deterministic triage tests, PR79/PR80 self-test profile tests,
  PR74–PR77 cleanup gates, PR56–PR69 compose gates, and the
  natural-language mutation refusal tests all continue to pass.

## PR81 milestone: battle-lab triage ranking and scene awareness

### PR81 followup — Docker01 live QA fixes

Live QA on Docker01 (image `lab/shellforgeai:pr81-3ba2373`) caught four
blockers in the initial PR81 cut:

1. **`sfai-noisy-errors` was missing** despite continuous ERROR/WARN log
   evidence. Root cause: the underlying `tools/containers._classify_log`
   regex requires `^\s*ERROR` (line-anchored), so real timestamp-prefixed
   lines (`2024-05-20T... ERROR ...`) never matched and the container
   was never added to the `noisy` bucket that fed the scene.
2. **`sfai-disk-pressure` was missing** for the same class of reason:
   no regex matched `simulated disk pressure`, `write failed`,
   `filler=`, or `ENOSPC`.
3. **`sfai-bad-http` was misattributed `disk_pressure` and
   `permission_denied`** classes. nginx upstream-refused log lines can
   include incidental `(13: Permission denied)` errno decorations; the
   original scorer triggered on a single hit and pinned the wrong
   class onto a clear bad-http suspect.
4. **Watch lane was empty** even though the ShellForgeAI container
   was running with high CPU. Root cause: `collect_scene()` enriched
   only containers in the `failing`/`noisy` buckets and never pulled
   `docker stats`, so the watch-lane scorer never had `cpu_percent`
   to work with.

Followup fixes:

- The triage module now owns its **own per-container log classifier**
  (`triage_ranking.classify_logs`) with line-anchor-free patterns and
  battle-lab phrasings (`simulated disk pressure`, `filler=`,
  `connect() failed`, `127.0.0.1:9999`, `CRITICAL boot failure`,
  `queue depth high`, `EACCES`, `ENOSPC`, `502/503`, etc.). Classifier
  state is scoped to the input text — never shared across peers.
- `collect_scene()` now independently runs `inspect` + `container_logs`
  + classifier for **each** container in the inventory and optionally
  reads bounded `docker stats --no-stream` for the watch lane. Each
  container's evidence is scoped to that container only.
- Scorers got cross-class anti-attribution guards:
  - `_score_permission_denied` requires `perm >= 2` and is suppressed
    when the dominant signal is bad_http with weak permission_denied.
  - `_score_disk_pressure` requires explicit disk-pressure evidence
    (simulated/write failed/no space/filler/ENOSPC or low free pct),
    no longer triggering on read-only-fs alone.
  - `_score_noisy_errors` is suppressed when the ERROR/WARN lines are
    already explained by a more specific class (bad_http,
    disk_pressure, permission_denied, crashloop_boot) so disk-pressure
    and bad-http suspects don't double-up as "noisy".
  - `_score_high_cpu_watch` is suppressed when any meaningful
    error/disk/permission signal exists, keeping watch a quiet bucket.
- Legacy theme keys from `tools/containers._classify_log` continue to
  be accepted via an alias map so older collectors and fixtures still
  work.
- Tests added: per-container evidence isolation, realistic
  timestamp-prefixed log fixtures matching the Docker01 scene, the
  `collect_scene` per-container isolation contract with stubbed
  collectors, and classifier sanity tests. PR79/PR80 self-test profile
  tests, PR74–PR77 cleanup gates, and the natural-language mutation
  refusal tests all continue to pass.

PR81 remains read-only. No mutation behavior was added; every JSON
payload still reports `safety.read_only=true` and every mutation flag
explicitly `false`.

### PR81 initial cut

- Added a read-only Docker triage ranking command: `shellforgeai triage
  docker [--json]`. It inventories the current Docker scene using the
  existing read-only `docker.containers` + `docker.problem_summary`
  collectors and deterministically ranks multiple suspects across
  failure classes — `crashloop` / `restart_storm`, `noisy_errors`,
  `bad_http`, `disk_pressure`, `permission_denied`, plus a
  `high_cpu_watch` lane for loud-but-healthy containers.
- Each suspect carries severity, confidence, evidence bullets, why
  ranked here, and a single read-only safe next command (always a
  `shellforgeai diagnose …` invocation). Watch entries are listed
  below suspects so they are visible without outranking real failures.
- Strict JSON shape (`schema_version`, `mode=docker_triage_ranking`,
  `summary`, `suspects`, `watch`, `safety`, `warnings`,
  `next_safe_commands`) with `safety.read_only=true` and every
  mutation flag explicitly `false`.
- No mutation behavior added. The command never restarts, stops,
  removes, or prunes containers, never runs docker compose mutation or
  cleanup execute, never creates proposals or missions, never runs
  `apply`, and never uses `shell=True`. The natural-language router is
  not broadened; mutation phrases continue to refuse with the PR74–PR80
  wording.
- Scoring is fixture-driven for testability: the scoring engine
  consumes a plain scene dict, so battle-lab regression coverage runs
  without a live Docker daemon. Tests cover crashloop ranking,
  bad-http / noisy-errors / disk-pressure / permission-denied class
  presence, the high-CPU watch case, evidence/why/safe-next bullets
  per suspect, JSON shape, safety flags, and safety regressions
  (no mutation imports, no `shell=True`).
- PR79/PR80 self-test profiles are unchanged. PR74–PR77 cleanup
  gates, PR56–PR69 compose gates, and the natural-language mutation
  refusal tests continue to pass.

## PR80 milestone: self-test command profiles and QA handoff polish

- Extended `shellforgeai self-test commands` with validation profiles
  (`--profile quick|standard|full`), `--fail-on-warn`, and
  `--include-skipped`. The default profile remains `standard` so the
  PR79 default behavior is preserved.
- `quick` is a cheap, env-independent smoke (`version`, `doctor`,
  `model doctor`, `tools list`, `ops status`, ask refusal) and is the
  recommended first post-deploy gate. `standard` keeps the PR79
  coverage. `full` adds broader read-only checks (`audit list`,
  `audit timeline --latest --json`, `compose list --json`).
- Introduced an explicit warn vs skip distinction: rows backed by
  missing optional artifacts (latest runbook, compose target absent
  from inventory, empty audit storage) are surfaced as `WARN` with a
  reason and contribute to `summary.warned`; the overall `status`
  becomes `warn` (not `failed`). `--fail-on-warn` exits non-zero on
  `warn` and adds `ci_status: "failed_on_warn"` to the JSON payload
  without converting warnings into runtime failures.
- Expanded the JSON schema with `profile`, `summary.warned`, a
  canonical `safety` block (`read_only`, `mutation_performed`,
  `cleanup_execute_run`, `mission_execute_run`, `apply_execute_run`,
  `docker_compose_executed`, `docker_compose_mutation`,
  `natural_language_execution`, `arbitrary_command_execution`),
  `warnings`/`skipped` arrays, and `next_safe_commands`. The PR79
  `mode` block and `no_*` safety keys remain for backward compatibility.
- Improved the human output: explicit `Profile`, `Safety invariants`,
  `Warnings`, and `Next safe commands` sections, plus a one-line "this
  is not a command failure" reminder when warnings are present.
- The harness remains strictly read-only across every profile. PR80
  did not change any mutation gates, did not add any runtime mutation
  capability, did not change cleanup / mission / apply / Compose
  execution behavior, and did not broaden natural-language behavior.
- Tests: added `tests/test_pr80_self_test_profiles.py`; PR79 tests
  adjusted to align with the schema (no behavior regressions). Full
  suite continues to pass with repo-local fixtures only.
- Docs updated: [`docs/cli.md`](cli.md), [`docs/safety.md`](safety.md),
  [`OPS.md`](../OPS.md) (post-deploy smoke workflow + NewTwo Docker01
  QA note).

## PR79 milestone: safe command coverage harness

- Added `shellforgeai self-test commands` (and `--json`), a read-only
  operator command coverage harness that exercises the safe CLI surface
  and reports `PASS`/`FAIL`/`SKIP` per check with a strict JSON payload.
- Covers `version`, `doctor`, `model doctor`, `ops status` (+`--json`),
  `audit retention` (+`--json`), `audit cleanup review` (+`--json`),
  the `audit cleanup execute-readiness <missing-plan>` and
  `audit cleanup report <missing-receipt>` negative refusal paths,
  `compose inspect`/`env-check`/`env-contract`/`env-plan` against the
  local target, `validate-runbook --latest`, locally-routed `ask`
  smokes (`show metadata hygiene`, `clean up now`), and a
  deterministic ask-mutation refusal-routing check.
- The harness never executes cleanup, apply, mission, docker compose
  restart, proposal/mission/archive/plan creation, or natural-language
  mutation; it never uses `shell=True`; it never broadens
  natural-language behavior. Skipped checks include an explicit
  reason so operators can distinguish "not applicable in this
  environment" from a real failure.
- Operator entry point documented in [`OPS.md`](../OPS.md) and
  [`docs/cli.md`](cli.md); safety boundary documented in
  [`docs/safety.md`](safety.md). The optional disposable mutation lane
  is intentionally not implemented and remains `status=manual_only`,
  `implemented=false`, `executed=false` in the JSON payload.
- Repo-local fixtures/mocks only; no live Docker / root / Docker01 /
  internet / systemd dependency for the test suite. No PR56–PR78 gate
  weakening, no new runtime capability, no new mutation surface.

## PR78 milestone: release / handoff baseline after PR56–PR77

- Added [`docs/release-baseline.md`](release-baseline.md), the concise
  operator/QA/contributor baseline summarizing current capabilities,
  the mutation boundary, safety invariants, Docker01 caveats, the
  cleanup operator sequence, the Compose disposable proof posture,
  the standard PR validation checklist, and the next roadmap tracks.
- Linked the baseline from `README.md` and `OPS.md`.
- Release/handoff packaging only: no runtime behavior, CLI behavior,
  mutation surface, safety gate, or test behavior changed.

## Non-goals (current, unchanged)

- Becoming a shell or generic remote-execution agent.
- Autopilot or self-healing infrastructure.
- Production Compose orchestration.
- Hidden mutation under workspace trust.
- Auto-apply of model-generated plans.

- PR83 (May 20, 2026): added read-only deterministic Docker triage detail drilldown (`triage docker detail <suspect>` / `--rank <n>`) with strict JSON mode (`mode=docker_triage_detail`), rank-context/higher-lower neighbors, explicit evidence + why sections, safe-next read-only commands, and unchanged no-mutation safety invariants.

- PR84 (May 21, 2026): added read-only `triage docker snapshot` incident handoff packaging with strict JSON mode (`mode=docker_triage_snapshot`), scene summary, ranked suspects, optional compact details (`--include-details`), `--top N` suspect limiting, safe-next command guidance, and unchanged no-mutation safety invariants.

- PR85 (May 21, 2026): added read-only `triage docker snapshot --save` artifact packet creation and `triage docker snapshot validate` validation (required files, JSON parse/schema/mode/safety invariants, manifest checksum verification), with strict JSON output and no mutation behavior.
- PR86 (May 21, 2026): added read-only triage handoff export flow: `triage docker snapshot export <snapshot-id|path>` packages saved snapshot artifacts into `<data_dir>/exports/...` with export manifest + checksums metadata, and `triage docker snapshot export-validate <export-path>` re-checks required files/JSON/manifest/checksums/safety invariants.
- PR89 (May 22, 2026): added disposable-only governed remediation proof workflow (`remediation plan/validate/execute/status`) with explicit target + scenario gating, dry-run plan artifacts with fingerprint and safety flags, mandatory `--execute --confirm`, bounded disposable proof execution (governed proof executor; not live Docker remediation), post-check verification receipts, and strict JSON status/error contracts.
- PR88 (May 22, 2026): added read-only `triage docker timeline` rolling incident history over saved snapshots (chronological validation + escalation/recovery/flapping/recurring/stable/new/resolved trend reporting, strict JSON mode, and unchanged no-mutation safety invariants).

- PR90 (May 22, 2026): introduces disposable remediation executor mode contract (`proof` default vs explicit `docker-disposable`) and bounded exact-target Docker restart lane for eligible disposable allowlisted targets only, with strict safety/receipt and JSON status semantics.


- PR91: disposable remediation receipt validation + handoff reporting (read-only, audit-grade checks; no new execution power).

- PR92 (May 23, 2026): operator preflight packet for governed remediation (`remediation preflight`) with strict read-only decision UX, live target eligibility re-checks, exact bounded action preview, verification expectations, recovery note, ready-vs-blocked status, and automation-safe JSON output.

- PR93 (May 23, 2026): disposable remediation rollback posture + verification scaffold (`remediation rollback-preflight`, `remediation rollback-validate`), receipt rollback metadata, strict read-only packets, automatic rollback disabled, and no rollback execution path.

- PR94 (May 23, 2026): adds governed disposable rollback execution (`remediation rollback-execute`) plus rollback receipts, rollback status, and rollback receipt integrity validation.

- PR95: Added disposable remediation lifecycle bundle + bundle validation commands for audit handoff.
- PR96 (May 23, 2026): added `remediation audit` read-only lifecycle visibility and safety audit summary (latest bundle linkage, artifact health warnings, strict JSON output, and invariant reporting with no remediation/rollback execution).

- PR97: Read-only triage-to-remediation eligibility mapping (`remediation eligibility`) with explicit safety flags and plan-only command suggestions.
- PR98 (May 23, 2026): Read-only remediation eligibility explain/report polish (`remediation eligibility --target <name> --explain [--json]`) with gate-by-gate blocker reasoning, labels found/missing, executor readiness, safe eligibility hints, strict JSON mode, and explicit no-mutation safety flags.

- PR99 (May 23, 2026): added `remediation self-test` readiness doctor with quick/standard/full profiles, strict JSON mode, fail-on-warn CI behavior, remediation-lane contract checks, and explicit default read-only/non-mutation safety invariants.
- 
- PR102 (May 24, 2026): upgraded `remediation self-test --profile full` from fixture-only checks to a deterministic non-mutating lifecycle readiness probe (temp lane plan/validate/preflight/refusal/proof execute/receipt/report/bundle/bundle-validate/audit), with live docker-disposable execute explicitly skipped by default.
- PR103 (May 24, 2026): added optional lab-only live disposable remediation proof gate to `remediation self-test --profile full` behind explicit `--include-live-disposable-execute --target <exact> --confirm-live-disposable`; default quick/standard/full remain non-mutating and live mutation remains off by default.
PR100 (May 23, 2026): normalized canonical safe-next command suggestions across triage, triage detail, remediation eligibility/explain, remediation self-test, and ask refusal/broad-triage output to remove stale `diagnose ... --target` forms and prefer read-only triage detail + eligibility explain guidance.

- Diagnose now adds deterministic Docker triage context for known battle-lab container targets and recommends canonical read-only next commands (`triage docker detail` + `remediation eligibility --explain`).

- PR104 (May 24, 2026): added read-only `shellforgeai ops report` 2AM operator command-center summary (strict JSON `mode=ops_report`, top suspect/evidence rollup, explicit no-mutation safety flags, safe-next command guidance, optional remediation/timeline sections, and no auto-plan/no execute behavior).
- PR105 (May 24, 2026): added deterministic ask routing for common 2AM/operator prompts (for example `it's 2am, what is on fire?`, `docker is broken, what should I check first?`, `show me the ops report`) directly to the read-only `ops report` engine, bypassing model-auth dependencies for that path while keeping mutation refusal and no-execution safety invariants unchanged.
- PR106 (May 24, 2026): added deterministic pre-model ask mutation-refusal routing for obvious natural-language mutation intents (restart/stop/remove/delete/prune/fix/remediate/execute/apply/rollback/cleanup/compose mutation/system mutation terms), with explicit no-action wording and canonical read-only command suggestions; preserves PR105 deterministic ops-report ask routing and keeps execution/mutation surfaces unchanged.

- PR107 (May 24, 2026): added read-only ops report artifact handoff workflow (`ops report --save`, `ops report validate`, `ops report export`, `ops report export-validate`) with manifest/checksum safety validation and strict JSON outputs.

- PR108 (May 24, 2026): added read-only ops report drift comparison (`ops report compare` plus `compare-export`) with strict JSON `mode=ops_report_compare`, suspect/new-resolved/escalation/improvement/rank-confidence-class drift categories, remediation-lane drift, and safety false→true warning surfacing; no mutation execution added.
- PR109 (May 24, 2026): added read-only `ops report history` and `ops report compare-latest` shortcuts for saved report handoffs, including strict JSON history listing, latest-two valid report resolution, and controlled `not_enough_reports` responses without mutation behavior.

- PR111: add `shellforgeai v1 check` readiness contract command (quick/standard/full).


- PR112 completed: V1 demo/docs command contract hardening. Canonical V1 demo commands are documented, dangerous casual demo steps are explicitly excluded, and tests enforce markdown command-surface safety/validity contracts.


- PR114 milestone: Added `docs/V1_COMMAND_SURFACE.md` as the explicit V1 command-surface inventory and safety classification map, with doc-linking and regression coverage for safe-path command constraints.
PR115 (May 25, 2026): added `shellforgeai v1 packet` release-readiness packet generation/save/validate/export/export-validate workflow as auditable V1 handoff artifact.

- PR116 (May 25, 2026): added read-only `shellforgeai v1 packet history`, `shellforgeai v1 packet compare`, and `shellforgeai v1 packet compare-latest` commands for saved readiness packet lifecycle drift tracking without packet regeneration/export/mutation.

- PR117 (May 25, 2026): integrated `scripts/v1_validate.sh --packet` (`--export-packet` optional) so V1 quick/full validation can leave a validated readiness packet artifact in-lane, with artifact-only safety boundaries.

- PR118 (May 26, 2026): stabilized the `scripts/v1_validate.sh` packet lane parsing/control flow — packet and export refs are parsed from stdout JSON only (stderr warnings no longer fail valid stdout), accepting `packet_id`/`packet_path` (and nested `packet.*`/`artifact.*`) plus `export_id`/`export_path` (and nested `export.*`/`artifact.*`), with controlled distinct diagnostics on invalid/missing refs and no added mutation/execution.


- PR121 (May 27, 2026): model-failure/auth UX hardening so model assessment suppresses raw Codex JSONL event output, classifies auth/token failures, and preserves deterministic diagnosis messaging with `codex login --device-auth` recovery guidance.

- PR122 (May 27, 2026): interactive latest-evidence memory. After a diagnosis or evidence-producing command, the REPL stores a compact in-session latest diagnosis context (target, diagnosis kind, artifact/evidence/summary paths, evidence highlights, limitations, safe next commands, suggested follow-up categories) and reuses it for read-only follow-up questions (`what did you find?`, `why is it slow?`, `is it running normally?`, `what does this system do?`, `what should I check next?`). `/pending` surfaces this latest context when no formal pending investigation exists. No new collectors auto-run, no mutation/remediation/rollback/cleanup/Docker-Compose execution is added, and mutation-style follow-ups stay refused.

- PR123 (May 27, 2026): automatic read-only system-role/health handling for broad operator questions in interactive mode (`what does this system do?`, `is it running normally?`, `what should I check first?`). Reuses latest diagnosis context when present, otherwise triggers safe built-in health evidence collection; responses remain evidence-backed, limitation-aware (including container-limited scope), and non-mutating.
- PR124 (May 27, 2026): interactive short follow-up phrase resolution (`get that info`, `do that`, `proceed`, `dig deeper`) now safely resolves to pending read-only evidence actions when available; paste guard still blocks shell snippets and mutation commands, and mutation/gated follow-ups are refused with no action taken.
- PR125 (May 28, 2026): host/container wording clarity polish. Diagnose summaries, interactive outputs, and JSON diagnosis payloads now label runtime visibility explicitly (for example `inside_container`, `visibility=container_limited`, host-oriented view from container namespace) so host-only gaps are framed as visibility limits, not false host-health certainty.

- PR128 (May 28, 2026): added the V1 interactive transcript regression harness covering slow-system latest-evidence continuity, system role/health reuse, pending follow-up phrase resolution, paste/mutation refusal, Codex auth JSONL suppression, and container-limited truthfulness with offline fixtures and no new mutation capability.

- PR129 (May 29, 2026): interactive command dispatch polish. The REPL now recognizes a focused allowlist of safe ShellForgeAI command-style inputs (`doctor`, `model doctor`, `ops report`, `triage docker detail <target>`, `v1 check <profile>`, remediation self-test/eligibility checks, and session helpers) and refuses shell/Docker/cleanup/remediation/rollback/apply mutation-shaped inputs with no action taken. No mutation, arbitrary shell execution, Docker/Compose execution, or natural-language execution was added.

- PR131 (May 29, 2026): intent nuance for command-help vs mutation requests. A small deterministic classifier (`shellforgeai.core.intent_nuance`) lets `ask` and interactive mode distinguish read-only guidance requests ("what command would restart this?", "show me the command to inspect sfai-crashloop", "how would I propose remediation?", "how do I review cleanup safely?") from execution requests ("restart it", "execute the plan", "clean it up", "run that", "do it now"). Command-help responses state "No action was taken." and present only safe read-only or clearly-labelled plan-only commands; they never suggest execute/confirm, `docker restart`, or `docker compose restart`. A mutation verb embedded inside a command-help frame is treated as guidance, not execution ("what command would restart this?" = guidance; "restart this" = refused mutation), and ambiguous "run that"/"do it now" phrasings are refused without confusing PR124's safe read-only follow-up phrases. No mutation, remediation/cleanup/rollback execution, Docker/Compose mutation, production restart, `shell=True`, arbitrary command execution, or natural-language mutation was added.

- PR130 (May 29, 2026): interactive trust prompt UX and scripted-session safety. The interactive workspace trust prompt no longer eats the first real command: already-trusted workspaces proceed straight to the command loop with no re-prompt, and the new `shellforgeai interactive --yes-trust` flag trusts the current workspace for this session and skips the prompt (script-friendly). When untrusted and no flag is passed, only `y`/`yes` grant trust and `n`/`no`/empty decline safely; any other input is treated as an invalid trust response (never executed as a command, never silently discarded) and reprompts with `Please answer y or n. Commands are accepted after trust is set.`. `--yes-trust` only gates the workspace prompt — it does not grant mutation, shell execution, Docker/Compose mutation, remediation/cleanup/rollback execution, or bypass the paste guard / natural-language mutation refusals. No mutation, arbitrary execution, or `shell=True` was added.

- PR138 (May 31, 2026): interactive unknown-command guidance and typo-safe suggestions. Command-like near misses such as `ops reprot`, `triage dockre`, and `v1 chek quick` now produce deterministic `Unknown command` guidance with `No action was taken`, safe allowlisted suggestions only, and a help fallback. Dangerous shell/mutation-shaped input still refuses instead of suggesting execution, and natural-language asks keep their existing routing. No mutation, cleanup/remediation/rollback execution, Docker/Compose mutation, production restart, `shell=True`, arbitrary command execution, or natural-language mutation was added.

- PR144 (June 1, 2026): V2 status entrypoint. `shellforgeai status` is now the first golden-path command with concise human output, `--brief` parity with ops report brief mode, strict `--json`, no artifact writes by default, no model/Codex dependency, and no mutation/execution expansion.

- PR145 (June 1, 2026): V2 triage entrypoint. `shellforgeai triage` is now the second golden-path command after status, with concise ranked suspect output, `--brief`, strict `--json`, `--target <target>` detail, ask/interactive routing for likely-suspect prompts, compatibility for `triage docker`, and explicit read-only/no-mutation safety flags. No cleanup/remediation/rollback execution, Docker/Compose mutation, `shell=True`, arbitrary command execution, natural-language mutation, or model/Codex dependency was added.

- PR149 (June 2, 2026): V2 verify entrypoint. `shellforgeai verify` adds read-only current-state verification after apply-preview with `--brief`, strict `--json`, `--target <target>`, `--from-status`, `--from-triage`, `--from-propose`, and `--from-apply-preview`. It reports OK/degraded/blocked/unknown from deterministic evidence, refuses to assume a proposal/apply happened without a receipt, includes safety-complete JSON flags, and routes verify asks/interactive entries while refusing mixed mutation phrasing. No cleanup/remediation/rollback execution, Docker/Compose mutation, container/production restart, `shell=True`, arbitrary command execution, natural-language mutation, or model/Codex dependency was added.

- PR150 (June 2, 2026): V2 handoff entrypoint — the final golden-path step. `shellforgeai handoff` produces a read-only operator handoff packet that collects/reuses the deterministic status/triage/propose/apply-preview/verify posture and presents current status, risk, suspect count, proposal/apply-preview/verify state, the first safe next command, and what was not done. It supports `--brief`, strict `--json`, `--save`, `--target <target>`, and `--from-status` / `--from-triage` / `--from-propose` / `--from-apply-preview` / `--from-verify`, plus deterministic ask routing ("give me a handoff", "what should I tell the next operator?", "handoff summary") and interactive allowlist/help coverage. The golden path is now `status -> triage -> propose -> apply-preview -> verify -> handoff`. `handoff --save` writes only a ShellForgeAI-owned artifact under `<data_dir>/v2_handoffs/<handoff_id>/` (`handoff.json`, `handoff.md`, `manifest.json`) with checksums and non-mutating safety flags. Handoff never executes fixes, creates an executable mission/apply record/remediation receipt, implies remediation happened, restarts anything, runs Docker/Compose, uses `shell=True`/arbitrary command execution, performs natural-language mutation, or calls the model; mutation phrasing ("handoff and restart", "summarize and fix it") remains refused with no action taken.
- PR152 (June 3, 2026): V2 handoff artifact validate/export lifecycle. Completed the first handoff artifact lifecycle step on top of PR150 `handoff --save`: `shellforgeai handoff validate <handoff_ref>`, `shellforgeai handoff export <handoff_ref>`, and `shellforgeai handoff export-validate <export_ref>`, each with a strict `--json` mode (`v2_handoff_validate`, `v2_handoff_export`, `v2_handoff_export_validate`). `validate` checks required files, JSON parse, `schema_version`, `mode=v2_handoff`, manifest kind, checksum match, the non-mutating safety block, and obvious secret leakage. `export` copies a validated handoff into a portable ShellForgeAI-owned bundle under `<data_dir>/exports/export_<handoff_id>/` (`handoff.json`, `handoff.md`, `manifest.json`, `export-manifest.json`) with an `artifact_export_only`/`arbitrary_path_write=false` safety block and is idempotent when a valid export already exists. `export-validate` re-checks the exported bundle's required files, manifests, checksums, source/export safety blocks, and secrets. Refs may be an id or a ShellForgeAI-owned path only; missing/unsafe/malformed refs return controlled `not_found`/`failed` with a non-zero exit and no traceback. Ask routing for "validate/export handoff" shows the read-only handoff plus safe lifecycle command guidance, and the interactive allowlist/help cover save/validate/export/export-validate. No cleanup/remediation/rollback execution, Docker/Compose mutation, container/production restart, `shell=True`, arbitrary command execution, natural-language mutation, or model/Codex dependency was added; validate/export-validate are read-only and save/export write only ShellForgeAI-owned artifacts.
- PR153 (June 4, 2026): V2 handoff artifact history/compare workflow. Made saved handoff artifacts reviewable over time on top of the PR152 lifecycle: `shellforgeai handoff history [--limit N]`, `shellforgeai handoff compare <before_ref> <after_ref>`, and `shellforgeai handoff compare-latest`, each with a strict `--json` mode (`v2_handoff_history`, `v2_handoff_compare`, `v2_handoff_compare_latest`) and `--only-changed`/`--include-stable` on compare/compare-latest. `history` lists recent saved handoffs (latest first) with id, `created_at`, status, risk, target, and quick local validity, plus `latest_handoff_id`; empty history returns a controlled `empty` status with `shellforgeai handoff --save` as the first safe command. `compare` loads two saved handoffs by id or ShellForgeAI-owned path and reports drift in status/risk/target/current_status, the golden-path stage summaries, first safe command, safe-next commands, limitations, warnings, and safety flags (including critical false→true safety drift), with a `summary` of `new`/`resolved_or_missing`/`changed`/`stable`/`safety_drift`. `compare-latest` compares the newest two saved handoffs or returns a controlled `not_enough_history` status. Missing/unsafe/malformed refs return controlled `not_found`/`failed` with a non-zero exit and no traceback. Ask routing handles "show handoff history", "compare latest handoffs", and "what changed since last handoff?" deterministically without a model fallback, and the interactive allowlist/help cover `handoff history`/`compare`/`compare-latest`. Strictly read-only: no artifact writes, collector rerun, model/Codex call, `shell=True`, arbitrary command execution, natural-language mutation, Docker/Compose mutation, or container/production restart was added.


## Governed execution frontier

The current V2 frontier includes a read-only governed recipe registry and
safe-action eligibility map. This milestone defines the locked toolbox before
real fixes: named recipes, statuses, mutation classes, required labels,
preflight/approval/verification/receipt/rollback posture, and deterministic
blockers for production, broad, missing, and unlabeled targets. Execution lanes
remain future work.

## Governed execution milestone

The first V2 governed execution milestone adds `docker.disposable_restart`: an exact-target, disposable-label, allowlist-label Docker restart that requires saved preflight validation, explicit confirmation, receipt creation, post-restart verification, and documented rollback posture. This is not general remediation or production restart support.


- Governed receipt audit/history: operators can list, inspect, validate/export, and compare disposable restart execution and recovery receipts without executing anything.

- Governed receipt audit bundle export: operators can package existing receipt audit/history evidence into a bounded ShellForgeAI-owned support packet with manifest/checksums and validate that packet without recipe execution, receipt rerun, recovery, rollback, Docker/Compose mutation, model calls, or host/container mutation.

- Governed receipt artifact integrity scan: operators can run `recipes receipt integrity` to scan ShellForgeAI-owned receipts, optional receipt exports, and optional audit bundles for missing files, malformed JSON, checksum drift, missing recovery originals, unsupported shapes, unsafe safety flags, and production restart records without creating artifacts, repairing/deleting anything, executing recipes, rerunning receipts, recovery, rollback, Docker/Compose mutation, shell execution, natural-language execution, or model calls.
## Governed receipt finding explanation

`shellforgeai recipes receipt explain` is a deterministic, local, read-only explanation surface for governed receipt audit, integrity, audit-bundle, and compare findings. It reads existing ShellForgeAI-owned receipt/audit/integrity artifacts and maps known finding codes (for example `checksum_mismatch`, `missing_original_receipt`, `safety_drift`, and `production_restart_recorded`) to operator-facing meaning, impact, and safe next commands.

Command forms:

```bash
shellforgeai recipes receipt explain
shellforgeai recipes receipt explain --json
shellforgeai recipes receipt explain --source integrity
shellforgeai recipes receipt explain --source audit
shellforgeai recipes receipt explain --source audit-bundle
shellforgeai recipes receipt explain --source compare
shellforgeai recipes receipt explain --finding checksum_mismatch
shellforgeai recipes receipt explain --target <target>
shellforgeai recipes receipt explain --recipe docker.disposable_restart
shellforgeai recipes receipt explain --limit 20
```

Supported categories include malformed JSON, missing required files/manifests/checksums, checksum mismatch, unsupported artifacts/receipts, missing original receipts, verification failure, safety drift, production restart records, Docker Compose/shell/arbitrary-command/natural-language execution records, receipt export and audit-bundle validation failures, and compare categories such as status/target/recipe/action/safety-flag changes. Unknown finding codes return controlled `unknown_finding` guidance instead of a traceback.

`recipes receipt explain` never repairs, deletes, cleans up, recovers, rolls back, restarts, reruns receipts, calls Docker/Compose, executes shell, creates exports/bundles, or calls a model. Safe next commands are limited to read-only receipt integrity/audit/history/inspect/validate/compare/verify surfaces. Ask and interactive phrasing such as “explain receipt integrity findings”, “what does checksum_mismatch mean?”, and “what should I do about safety drift?” routes to this explanation guidance; mutation phrasing such as “explain and fix corrupt receipts” refuses the mutation part. Support-handoff phrasing that clearly mentions receipt audit or recipe receipts routes to receipt audit-bundle guidance.

## PR182 milestone: CLI command-module split begins

`src/shellforgeai/cli.py` had grown too large, so PR182 starts a staged,
behavior-preserving modularization. `cli.py` remains the canonical Typer
entrypoint and root app owner; it now imports and registers command modules
from the new `src/shellforgeai/commands/` package.

The first slice extracts only the safest read-only domains:

- `commands/status.py` — the `status` golden-path command.
- `commands/doctor.py` — `doctor` and `model doctor`.
- `commands/ops.py` and `commands/triage.py` — the read-only ops report/status and triage handler families.
- `commands/verify.py` — the read-only top-level `verify` current-state and receipt-aware handler.

This is a pure code-move: command names, aliases, help order, JSON schemas,
exit codes, strict-JSON behavior, advisory wording, refusal behavior, and all
safety gates are unchanged, and no new execution, mutation, Docker/Compose
call, shell, natural-language execution, or model call is introduced. Future
PRs will migrate further domains (validation, audit, compose, mission,
governed receipts, etc.) one domain at a time, the same way. The PR184
command-surface golden guardrail should be run for these refactors so help,
JSON flags, receipt-aware verify, confirmation markers, and mutation-refusal
paths remain visible.

## PR201 milestone: interactive "not-a-shell" policy guardrail

PR201 makes the interactive safety posture explicit and tests it: **interactive
mode is not a shell.** It routes known ShellForgeAI read-only commands and
deterministic read-only operator asks, and refuses shell-shaped input rather
than executing it. Refusals carry clear wording — "Interactive mode is not a
shell.", "No command was executed.", "No action was taken." — and offer safe
read-only alternatives.

Refused categories: arbitrary shell commands; filesystem mutation
(`touch`/`rm`/`mv`/`cp`/`chmod`/`chown`); arbitrary file reads
(`cat /etc/passwd`, `cat ~/.ssh/id_rsa`); Docker/Compose mutation
(`docker restart`, `docker compose restart`/`up`/`down`, `docker volume prune`);
cleanup/remediation/rollback/recovery execution; network/download commands
(`curl`/`wget`); package installs (`apt install`/`pip install`); cloud/VCS
mutation (`git push`, `gh pr merge`, `codex apply`, `kubectl apply`); and shell
metacharacters/pipelines/redirections (`|`, `>`, `>>`, `&&`, `;`).

`uname -a` decision: bare host-evidence shell invocations are refused as
not-a-shell rather than answered, because interactive cannot guarantee a
non-shell evidence path for a raw `uname` invocation. Use the read-only
ShellForgeAI evidence surfaces (`status`, `ops report`, `diagnose health`).

This PR is behavior-preserving except for clearer wording and stricter tests. It
adds no shell execution, no new interactive execution lane, no Docker/Compose
mutation, no `shell=True`, and no model call, and it does not weaken read-only
command routing — legitimate subcommands with flags/arguments
(`triage docker --json`, `ops report --json`, `verify --target <target>`) still
dispatch. Tests live in `tests/test_pr201_interactive_not_a_shell_policy.py`.


## Docker01 operational hygiene visibility

ShellForgeAI includes a read-only Docker01 hygiene report helper for operators who need disk, image, and artifact inventory before cleanup is considered. The helper produces a report directory containing Markdown summary, strict JSON, raw evidence, command provenance, and a proposal-only candidate cleanup plan. It intentionally performs no cleanup or Docker mutation; any real cleanup remains future work and requires a separate reviewed lane.
## Docker01 hygiene history and compare

Docker01 hygiene reports are useful when disk, image, and artifact pressure can be trended instead of reviewed as a single point-in-time snapshot. The helper can now read previously generated PR209/PR210 report directories and produce history or comparison output without running Docker and without generating a new report.

Use these read-only forms when reviewing whether Docker01 artifact/image pressure is growing before any future scoped cleanup lane is considered:

```bash
python scripts/docker01_hygiene_report.py --history --json
python scripts/docker01_hygiene_report.py --compare <old_report_dir> <new_report_dir> --json
python scripts/docker01_hygiene_report.py --compare-latest --json
```

`--history` and `--compare-latest` discover reports under `/tmp` by default; pass `--root <dir>` for a scoped offline location. Candidate directories must contain `hygiene-report.json`, `hygiene-summary.md`, `candidate-cleanup-plan.md`, and `commands-run.json` to be treated as valid hygiene reports. Stale/non-report candidates, including old hygiene review-bundle-shaped directories, are reported separately as bounded ignored candidates with a count and stable reason; they do not make history `partial` when valid reports can be read. `--compare-latest` and `--review-bundle-latest` select valid hygiene reports only.

These modes read existing report files only. They do not run Docker, Docker Compose, report generation, cleanup, prune, image removal, file deletion, restart, remediation, rollback, recovery, model calls, network calls, or arbitrary shell execution. A passing validation result or comparison summary is review evidence only and does not authorize cleanup execution.

### Docker01 hygiene review bundles

Docker01 hygiene evidence now supports a bounded review bundle around existing reports: validation result, optional history and compare-latest snapshots, candidate cleanup plan copy, safety notes, manifest, checksums, and strict JSON rollup. This keeps artifact/disk pressure review evidence-first while preserving the boundary that cleanup requires a separate narrow reviewed lane.

### Docker01 QA bundle hygiene evidence integration

Docker01 PR QA bundles now surface existing hygiene history and compare-latest evidence in the operator handoff. The default remains read-only: it summarizes existing hygiene reports and does not create a hygiene review bundle. Operators can explicitly opt in to bounded review-bundle packaging with `--include-hygiene-review-bundle` when a review packet is useful.

This integration does not add cleanup execution, Docker prune, image removal, file deletion, Docker/Compose mutation, restart, natural-language execution, model/Codex calls, network calls, or package installs. Missing hygiene evidence remains non-blocking and visible as `not_available`, `empty`, or `partial`.

## Validation evidence discoverability

Docker01 PR-lane validation now writes a small PR/commit-scoped evidence packet that downstream QA can discover. The packet documents validation commands, status, checksums, and safety boundaries without adding cleanup or Docker mutation behavior.

### Docker01 PR-lane resume/status evidence

Docker01 PR-lane operations now include a read-only `--status` / `--resume-status` helper for interrupted runs. It inspects current source/container labels plus existing validation and QA bundle evidence, classifies the lane state, and prints a bounded safe next command without deploying, rebuilding, validating, running QA, restarting, cleaning, pruning, deleting, or changing product runtime behavior.

The status helper now treats Docker image digests as runtime metadata rather than configured image tags, prefers later pass-eligible exact PR/commit validation evidence over older setup failures, and discovers exact PR/commit operator QA bundles.

### Docker01 merge-readiness evidence

Docker01 review flow includes a read-only merge-readiness helper that consolidates existing PR-lane status, validation status, operator QA bundle, and hygiene evidence for an exact PR/commit. It emits strict JSON, a concise Markdown summary, and an optional bounded report directory. It is not a product runtime command and does not deploy, build, validate, run QA, restart, clean, prune, remediate, roll back, recover, merge, or push. SeedOfEvil remains final merge owner.

## Docker01 validation evidence lifecycle

Docker01 validation evidence finalization is now part of the PR-lane evidence
lifecycle: completed validation attempts write structured PR/commit-scoped
status, manifest, summary, command, and bounded log-excerpt artifacts without
rerunning validation. Status, merge-readiness, and merge-comment rendering stay
read-only and consume the same exact evidence, with pass evidence preferred over
earlier setup-failure/interrupted attempts for the same PR and commit.

Follow-up PR219 integration tightened the standard guarded lane path: automatic
finalization now keys evidence to the requested PR head commit and carries Lane
C/full-validation metadata through downstream read-only status and merge-review
helpers.

The disposable Docker01 validation fallback has been hardened so the generated
container command installs the minimal OS tools required by the full test suite
(`procps`/`ps`, `git`, and `rsync`) inside the disposable container only.

The fallback command now closes the evidence lifecycle itself by invoking the
validation finalizer inside the disposable container and writing the final
PR/commit status packet into the mounted lane run directory.


### Docker01 PR lane validation evidence self-check

After the guarded Docker01 PR lane writes/finalizes validation evidence, it now performs a read-only validation evidence self-check for the exact PR/commit through `validation_status.py --latest --pr <PR> --commit <sha> --json --explain-selection`. The lane writes `validation-evidence-check.json` and `validation-evidence-check.md` in the validation run directory and references the check from the lane manifest and summary.

The self-check proves whether exact PR/commit evidence was selected, whether it is pass-eligible, whether a rerun is required, whether full validation ran, and whether duplicate full pytest evidence was detected. If host setup fails but a later disposable fallback validation passes, the fallback pass can supersede the earlier setup failure while preserving the earlier setup failure as a warning/process note. If evidence is not discoverable after validation, the lane reports a validation evidence lifecycle failure/needs-followup rather than silently treating the run as merge-ready.

The self-check does not run validation, pytest, the operator QA bundle, cleanup, Docker prune, Docker image removal, Docker/Compose mutation, restarts, remediation, rollback, recovery, GitHub posting/approval/merge, model calls, or cloud apply/merge/push. Merge-readiness and merge-comment tools remain separate read-only post-QA checks. SeedOfEvil remains final merge owner.

- Docker01 V2 readiness evidence snapshot: adds `scripts/docker01_v2_readiness.py`, a read-only report helper that classifies exact PR/commit Docker01 evidence as `v2_candidate`, `v2_not_ready`, or `v2_unknown` without deploy/build/validation/QA/cleanup/restart behavior. SeedOfEvil remains final merge owner.

- PR221 follow-up: V2 readiness now treats missing exact validation/QA evidence as incomplete `v2_unknown` warnings instead of false failures, preserves explicit failures as `v2_not_ready`, and the operator QA read-only Docker ask uses deterministic local triage wording rather than Codex-auth-gated synthesis.

- PR221 follow-up: targeted Docker01 validation lanes auto-finalize exact PR/commit validation evidence (`lane=targeted`, `full_validation=false`) and immediately self-check discovery; no manual finalizer normalization or duplicate pytest is required, and read-only downstream tools still do not execute validation or QA.

- PR221 follow-up: `validation_status.py --latest` now recognizes completed standard guarded lane logs as bounded evidence for exact PR/commit discovery, preserving full-validation metadata for downstream merge/V2 readiness without manual normalization. Exact legacy logs are pass-eligible only with trusted terminal pass markers (including full pytest 100%/exit 0 for full lanes); ambiguous, truncated, failed, setup-failure, or interrupted logs remain non-pass-eligible.

Nested Docker01 convergence QA bundle directories such as `/tmp/sfai-pr<PR>-<short>-convergence-<timestamp>/operator-qa/` are valid exact PR/commit QA evidence sources for PR-lane status, merge-readiness, and V2 readiness; stale PR/commit bundles are ignored.

`shellforgeai model doctor --json` is part of Docker01 live QA and emits strict read-only model readiness JSON; unavailable or unknown model auth is reported structurally instead of as a CLI option failure.

Model doctor live-probe receipt validation is available with
`shellforgeai model doctor --validate-receipt <receipt_dir> [--json]` and
optional `--validation-out <out_dir>`. It validates existing PR226-style
receipt bundles for required files, JSON parse, manifest/checksum consistency,
bounded summary Markdown, secret markers, probe metadata, and read-only
safety posture without running a live probe, calling a model/Codex/network,
using Docker/Compose, cleaning up, deleting, restarting, remediating, rolling
back, recovering, posting/approving/merging on GitHub, or applying cloud
changes. Default model doctor remains no-call; explicit live probe remains
opt-in and bounded. SeedOfEvil remains final merge owner.

For exact PR/commit lane runs, a later successful disposable validation fallback supersedes earlier host setup_failure evidence in `validation_status.py --latest`; the setup failure remains in warnings/process notes, while failed or interrupted evidence without a later exact pass stays non-pass-eligible.

- PR222 (first V2-oriented trust improvement): model-backed `shellforgeai ask` for Docker/operator questions is grounded in deterministic ShellForgeAI Docker triage evidence before model assistance is formatted. Deterministic CLI evidence remains the source of truth; the model may explain and route from it but must not invent tools, execute natural language, or suggest unsupported mutation. When the read-only triage scene has a top suspect, the grounded answer names the actual suspect, severity, confidence, and evidence themes and offers a real supported read-only safe next command (`shellforgeai triage docker detail <suspect> --json`); when evidence is missing it points to a real evidence-gathering command (`shellforgeai triage docker --json`) instead of guessing a diagnosis. A tiny local ask-output guard (`core.command_suggestions.filter_unsupported_command_suggestions`) strips unsupported/mutation command suggestions (`shellforgeai diagnose <container>`, `shellforgeai fix docker`, `shellforgeai restart compose`, bare `docker prune`/`docker image rm`) from the model answer and replaces them with the deterministic safe next command, while real read-only suggestions are preserved. Broad mutation/auto-fix asks ("clean up docker and restart compose", "prune docker images", "fix beszel-agent automatically") stay refused. New `core.ask_docker_grounding` builds the bounded read-only evidence context from the existing `core.triage_ranking` engine; when model auth is unavailable the deterministic evidence still answers and `shellforgeai model doctor --json` is the auth-diagnostic path. Read-only ask grounding only: no cleanup execution, Docker prune, Docker image removal, file deletion, stale-artifact repair/move/delete, Docker/Compose mutation, restart, validation/QA execution from ask, remediation/rollback/recovery execution, natural-language execution, `shell=True`, GitHub post/approve/merge, cloud apply/merge/push, or new product runtime mutation behavior; no new `--execute`/`--apply`/`--cleanup`/`--delete`/`--prune`/`--restart`/`--fix` CLI switches. New `tests/test_pr222_ask_docker_evidence_grounding.py` covers grounding, unsupported-command filtering, mutation refusal, model-auth fallback, and safety. Docs: `OPS.md`, `README.md`, `docs/roadmap.md`, `docs/VALIDATION_MATRIX.md`, `docs/VALIDATION_LANES.md`. SeedOfEvil remains final merge owner.
## Safe ask command suggestions

Model-backed `ask` may explain deterministic evidence and suggest a next operator command, but those suggestions are now validated through a static safe-command registry. Registry entries are real ShellForgeAI commands, marked `read_only=true` and `mutation=false`, and are suggestion-only: `ask` never executes them. Unknown `shellforgeai ...` suggestions and mutation-shaped commands such as cleanup, prune, image removal, Compose restart, shell pipes, redirects, or shell passthrough are removed or replaced with a registry command such as `shellforgeai triage docker --json`, `shellforgeai triage docker detail <suspect> --json`, or `shellforgeai ops report --json` when appropriate.

Natural-language requests still cannot execute commands. Future mutation recipes must remain named, narrow, auditable, and confirmation-gated outside model-backed ask.
