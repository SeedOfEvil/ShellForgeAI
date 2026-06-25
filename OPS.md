# OPS

## V2 2AM golden path

1. `shellforgeai status` — read-only concise status; no model call and no mutation.
2. `shellforgeai triage --brief` — bounded read-only ranked suspect view with the first safe command.
3. `shellforgeai propose` — read-only next-action proposal preview; no plan created and no action executed.
4. `shellforgeai apply-preview` — read-only execution-boundary preview; no apply, mission, remediation, rollback, cleanup, Docker, Compose, or restart action executed.
5. `shellforgeai verify` — read-only current-state verification; no applied action or remediation receipt is assumed. Use `shellforgeai verify --receipt <receipt_id>` after governed recipe execution to verify the existing receipt without retrying, rolling back, restarting, or running Docker/Compose.
6. `shellforgeai handoff` — read-only operator handoff packet summarizing the golden-path posture and first safe command; it does not execute fixes or imply remediation happened. `shellforgeai handoff --save` writes only a ShellForgeAI-owned artifact under `<data_dir>/v2_handoffs/`.
   - Handoff artifact lifecycle (read-only except ShellForgeAI-owned writes):
     - `shellforgeai handoff --save` — write the handoff artifact (`<data_dir>/v2_handoffs/<handoff_id>/`).
     - `shellforgeai handoff validate <handoff_id>` — read-only validation (required files, JSON, manifest, checksums, safety, secrets).
     - `shellforgeai handoff export <handoff_id>` — copy a validated handoff into a portable export (`<data_dir>/exports/export_<handoff_id>/`); idempotent if it already exists.
     - `shellforgeai handoff export-validate <export_id>` — read-only validation of the exported bundle.
     - `shellforgeai handoff history [--limit N]` — read-only list of recent saved handoffs (latest first; empty → `shellforgeai handoff --save`).
     - `shellforgeai handoff compare <before_id> <after_id>` — read-only drift compare of two saved handoffs (status/risk/target/current_status/golden-path/first-safe-command/safe-next-commands/limitations/warnings/safety drift); `--only-changed`/`--include-stable` available.
     - `shellforgeai handoff compare-latest` — read-only compare of the two most recent saved handoffs (or `not_enough_history`).
     - Each step accepts `--json` for strict output. Missing/malformed refs fail cleanly (non-zero, no traceback). No collector rerun, model call, Docker/Compose mutation, restart, shell, or arbitrary command.
7. `shellforgeai triage docker detail <target>` — inspect one suspect without mutation.
8. `shellforgeai remediation eligibility --target <target> --explain` — explain gated readiness only.
9. `shellforgeai ops report --save` — preserve an evidence-backed report when handoff or comparison is needed.

Safe V2 path: `status -> triage -> propose -> apply-preview -> verify -> handoff`.

CLI refactor guardrail: `verify` is implemented as a command module while keeping
its surface unchanged. For future CLI command moves, run the PR184
command-surface golden guardrail plus targeted module tests so read-only verify,
receipt-aware verify, JSON flags, help text, and mutation-refusal paths remain
protected.

Governed disposable recipe path after preflight: `recipes preflight --save -> recipes preflight validate -> recipes execute <preflight_id> --confirm -> recipes receipt validate <receipt_id> -> verify --receipt <receipt_id> -> recipes receipt audit -> recipes receipt rollback-preview <receipt_id> -> recipes receipt recovery-execute <receipt_id> --confirm -> verify --receipt <recovery_receipt_id> -> handoff`. Receipt-aware verify is read-only: it reads the governed execution or recovery receipt and reports recorded post-check evidence; it never re-executes the recipe, retries, rolls back, restarts containers, or calls Docker Compose. Receipt rollback-preview is also read-only: for `docker.disposable_restart` it states that no true rollback exists. Receipt recovery-execute is the only recovery execution lane and can only repeat the exact disposable restart target from a valid receipt after current label/production/broad-target gates and explicit `--confirm`; it does not execute Docker Compose, shell, model, cleanup, remediation, or arbitrary rollback.

`shellforgeai triage` (full), `shellforgeai triage --json`, and the compatibility
`shellforgeai triage docker` / `triage docker --brief` views all share the same
read-only safety wording. When there are no suspects, the first safe command is a
read-only status/report command (`shellforgeai status --json`), never a detail
command for a missing suspect.

`shellforgeai ask "what is wrong with docker?" --explain-evidence` keeps ask read-only while showing what deterministic ShellForgeAI evidence fed a Docker/operator answer. The explanation lists Docker triage/status evidence as used or missing, includes top suspect/severity/confidence/evidence themes when available, and shows only a safe next command from the safe-command registry (for example `shellforgeai triage docker detail <suspect> --json` or `shellforgeai triage docker --json`). Missing evidence is called out explicitly and is not guessed. Mutation requests remain refused; ask does not clean up, prune, restart, remediate, roll back, recover, execute validation/QA, run Docker/Compose mutation, or execute natural language.

Model doctor remains no-call by default: `shellforgeai model doctor` and
`shellforgeai model doctor --json` do not run a live probe or call a model.
When an operator has an existing explicit live-probe receipt, validate it with
`shellforgeai model doctor --validate-receipt <receipt_dir> --json`; add
`--validation-out <out_dir>` to write validator JSON/Markdown plus manifest and
checksums. Receipt validation is read-only against the receipt: it checks
required files, JSON parse, manifest/checksum metadata, bounded summary
Markdown, known secret markers, probe metadata, and no-mutation safety posture.
It does not run a live probe, call a model/Codex/network, invoke Docker/Compose,
clean up, delete, restart, remediate, roll back, or recover. SeedOfEvil remains
the final merge owner.


## CLI implementation note

`src/shellforgeai/cli.py` remains the root Typer app wiring. The staged
command-module split keeps behavior unchanged while moving handlers into
`src/shellforgeai/commands/`: PR182 extracted `status`/`doctor`, PR183 extracted
`ops report`/`ops status` and `triage`/`triage docker`, PR185 extracted
`verify`, PR186 extracted `handoff`, PR187 extracted `propose` and
`apply-preview`, PR189 extracted the read-only recipe registry/preflight
surfaces, PR190 extracted deterministic `ask`, PR191 extracted governed receipt
history/audit/export/compare surfaces, PR192 extracted read-only receipt safety
surfaces, PR193 extracted read-only recovery receipt status/validate, PR194
extracted confirm-gated receipt recovery-execute, PR195 extracted the
read-only `v1 check` readiness handler into `commands/v1.py`, PR196
extracts the `model` command group (`model doctor` and `model test`) into
`commands/model.py`, and PR199 extracts the `remediation self-test`
readiness/testing handler into `commands/remediation.py` (quick/standard/full
profiles, JSON/human output, and safety flags unchanged; live
docker-disposable execute stays skipped by default behind its explicit
lab-only opt-in/confirm gate; no cleanup/remediation/rollback/recovery
execution added; the other remediation handlers stay in `cli.py`), and PR200
extracts the top-level `interactive` launcher into `commands/interactive.py`
(Typer wiring only that hands off to the existing
`shellforgeai.interactive.start_interactive` REPL; the `interactive` command
surface, `--no-trust-cache`/`--yes-trust` options, deterministic read-only
routing, and mutation refusal are unchanged; interactive mode remains
not-a-shell and natural language never executes governed fixes; the root
callback's no-subcommand interactive fallback stays in `cli.py`).
This is an internal layout hardening only: command UX,
quick/standard/full V1 readiness behavior, JSON schemas, safety flags, ask
routing, and mutation refusal are unchanged. `model doctor` remains the
read-only provider-readiness report after the move: it does not call model
inference, start Codex tasks, or mutate anything; `model test` remains the
group's only explicit one-shot model call, unchanged. PR197 fixes
pre-existing guidance drift: V1 readiness `next_safe_commands` no longer
uses `shellforgeai model doctor --json` for read-only structured model readiness; machine-readable general health remains `shellforgeai doctor --json`.

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
Receipt history/inspect/compare/audit/integrity/explain/verify/validate/
rollback-preview and audit-bundle/export validation stay read-only; export and
audit-bundle stay bounded ShellForgeAI-owned artifact-only writes;
rollback-preview and recovery status/validate still never execute rollback,
recovery, cleanup, remediation, Docker/Compose, shell, or model calls. Recipe
list/eligibility/preflight stay read-only and never execute; governed `recipes
execute` remains separately guarded in `cli.py` and unchanged. Receipt
recovery execution (`recipes receipt recovery-execute`) keeps its exact
command surface and stays exact-target, disposable-only, allowlisted, and
explicit `--confirm` gated after the PR194 move; no-confirm and all blocked
cases still perform no restart and write no successful recovery receipt.

PR201 adds a focused **interactive "not-a-shell" guardrail and wording polish**.
Interactive mode routes known ShellForgeAI read-only commands and deterministic
read-only operator asks; it is not a shell and never executes typed text as a
shell command. Shell-shaped input is refused with explicit wording ("Interactive
mode is not a shell.", "No command was executed.", "No action was taken.") plus
safe read-only alternatives: arbitrary shell commands, filesystem mutation
(`touch`/`rm`/`mv`/`cp`/`chmod`/`chown`), arbitrary file reads
(`cat /etc/passwd`, `cat ~/.ssh/id_rsa`), Docker/Compose mutation
(`docker restart`, `docker compose restart`/`up`/`down`, `docker volume prune`),
cleanup/remediation/rollback/recovery execution, network/download commands
(`curl`/`wget`), package installs (`apt install`/`pip install`), cloud/VCS
mutation (`git push`, `gh pr merge`, `codex apply`, `kubectl apply`), and shell
metacharacters/pipelines/redirections (`|`, `>`, `>>`, `&&`, `;`). Bare
host-evidence shell invocations such as `uname -a` are refused as not-a-shell
rather than answered, since interactive cannot guarantee a non-shell evidence
path for them; use `status`/`ops report`/`diagnose health` instead. This PR is
behavior-preserving except for clearer wording and stricter tests: it adds no
shell execution, no new interactive execution lane, no Docker/Compose mutation,
no `shell=True`, no model call, and does not weaken read-only command routing
(legitimate subcommands with flags/arguments still dispatch). Tests live in
`tests/test_pr201_interactive_not_a_shell_policy.py`.

PR184 adds a behavior-preserving **command-surface golden guardrail** to protect
this split as it continues onto riskier surfaces. Run it on every CLI
command-module extraction PR, in addition to the change's normal lane:

```bash
pytest -q tests/test_pr184_cli_command_surface_golden.py
```

It asserts important commands, `--help` surfaces, JSON flags, governed-execution
`--confirm` requirements, and mutation-refusal phrases stay registered (read-only,
no Docker, no model call). When the surface changes intentionally, update
`tests/golden/cli_command_surface_pr184.json` in the same PR. It does not replace
full validation — broad/core command refactors still require Lane C
(`python scripts/run_full_pytest.py`). See [`docs/cli.md`](docs/cli.md) and
[`docs/VALIDATION_LANES.md`](docs/VALIDATION_LANES.md).

## Mainline/scheduled validation baseline

Use `scripts/run_mainline_validation.py` when the operator needs an explicit
mainline/current-checkout validation baseline that is separate from PR deploy
validation. The helper is intended for manual runs today and for a future
scheduled lane; it writes evidence artifacts only and does not change runtime
ShellForgeAI product behavior.

Recommended Docker01 artifact location for scheduled/mainline runs:

```bash
python scripts/run_mainline_validation.py \
  --baseline-name main \
  --output-dir /srv/data/shellforgeai/validation-runs/
```

Safe local planning and smoke forms:

```bash
python scripts/run_mainline_validation.py --dry-run
python scripts/run_mainline_validation.py --dry-run --json
python scripts/run_mainline_validation.py --output-dir /tmp/sfai-mainline-validation-test --no-full-pytest
```

The default executed baseline runs validation-only commands: `ruff check .`,
`python -m compileall -q src tests`, `scripts/v1_validate.sh --quick` when the
script is available/executable, `python scripts/run_full_pytest.py`, and
duration tracking on the full pytest log when the tracker is available. It
writes a manifest JSON, human summary, validation logs, and duration report /
history under the selected output directory. `--no-full-pytest` is only a local
quick-check escape hatch and is recorded in the manifest as
`skipped_by_operator`; do not use it for the official scheduled baseline.

Safety boundary: the mainline baseline helper does **not** auto-merge,
auto-deploy, auto-remediate, build Docker images, edit Compose files, call
Docker/Compose, restart containers, restart production, prune, clean up,
remediate, roll back, push to GitHub, or execute model/natural-language driven
commands. It is evidence generation, not deployment or remediation.

## Docker01 operator QA evidence bundle (PR206)

When QA'ing a Docker01 PR, assemble the reviewer handoff with the read-only
bundle helper instead of copy/pasting each command's output by hand. **Run it
from the Docker01 host** — ShellForgeAI product smoke commands are executed
inside the running `shellforgeai` container through a narrow `docker exec
shellforgeai shellforgeai …` argv allowlist, so the host does not need
`shellforgeai` on its PATH. Host checks and the validation status viewer stay
host-side:

```bash
# Dry-run first (lists the real plan, executes nothing, writes nothing):
python3 scripts/docker01_operator_qa_bundle.py --pr <PR> --commit <sha> --dry-run

# Generate the evidence bundle:
python3 scripts/docker01_operator_qa_bundle.py --pr <PR> --commit <sha>
python3 scripts/docker01_operator_qa_bundle.py --pr <PR> --commit <sha> --out /tmp/sfai-pr<PR>-qa-bundle
python3 scripts/docker01_operator_qa_bundle.py --pr <PR> --commit <sha> --json
```

It runs the standard read-only smoke set inside the container via `docker exec
shellforgeai shellforgeai …` (`version`, `doctor`, `model doctor`, `v1 check
--profile quick/standard`, `ops report`, `status`, `triage docker`, `propose`,
`apply-preview`, `verify`, `handoff`, a read-only Docker `ask`, a mutation `ask`
expected to be refused, and `remediation self-test --profile full` with live
disposable execution skipped by default) plus the host-side checks `docker ps
--filter name=shellforgeai`, `docker inspect shellforgeai`, `df -h /`, and the
validation status viewer run with the helper's own Python interpreter (so
`python3`-only hosts work) and **scoped to the PR/commit under review**
(`<current-python> scripts/validation_status.py --latest --pr <PR> --commit <sha>
--json --explain-selection`). Scoping keeps the bundle from silently embedding
stale validation evidence from another PR/commit: matching evidence is included
when found, missing evidence is reported `not_found`/`not_available` cleanly, and
evidence for a different PR/commit is never treated as current. It writes a
bounded bundle under
`/tmp/sfai-pr<PR>-<shortsha>-qa-bundle-<timestamp>/` containing `qa-summary.md`,
`qa-results.json`, `safety-assertions.json`, `container-state.json`,
`validation-status.json`, `commands-run.json`, and `raw/`. Running from the host
keeps the guarded lane's host `/tmp` validation artifacts visible to the helper.

Paste the contents of `qa-summary.md` into the PR handoff. A missing non-critical
host check (Docker daemon, model, prior validation run) yields `partial`; a
failed ShellForgeAI product check or safety assertion yields `failed`.

Safety boundary: evidence collection only. Commands come from a small fixed
allowlist (`docker ps --filter name=shellforgeai`, `docker inspect
shellforgeai`, `docker exec shellforgeai shellforgeai <approved read-only
command>`, `df -h /`, `validation_status.py`); any other family is rejected —
`docker restart`, `docker compose restart/down`, `docker volume prune`, a
`docker exec` into a shell (`sh -lc`/`bash -lc`) or other binary
(`rm`/`touch`/`curl`/`wget`/`apt`/`pip`), `gh pr merge`, `codex apply`, … .
Subprocess execution uses argv lists with bounded timeouts and never
`shell=True`. The helper performs no cleanup, remediation, rollback, recovery,
Docker/Compose mutation, container/production restart, prune, package install,
network call, or cloud apply/merge/push, and does not fix anything. The bundle
never auto-declares a PR mergeable — the reviewer still gives the final merge
verdict. See [`docs/VALIDATION_LANES.md`](docs/VALIDATION_LANES.md) for details.

### QA bundle lifecycle: validate / history / compare (PR207)

The same helper has four **artifact-only** lifecycle modes that prove bundles are
complete, discoverable, and comparable *without* re-running smoke QA, running
Docker, or touching the live container. They only read existing bundle files,
parse JSON, and compute hashes — no subprocess, no Docker/ShellForgeAI/validation
commands, no mutation:

```bash
# Validate a bundle is structurally complete and internally consistent:
python3 scripts/docker01_operator_qa_bundle.py --validate-bundle <bundle_dir>
python3 scripts/docker01_operator_qa_bundle.py --validate-bundle <bundle_dir> --json

# Discover bundles under a root (default /tmp); filter by pr/commit/status:
python3 scripts/docker01_operator_qa_bundle.py --history --root /tmp
python3 scripts/docker01_operator_qa_bundle.py --history --root /tmp --pr 206 --json

# Compare two bundles and report deltas (regressed/improved/changed/same):
python3 scripts/docker01_operator_qa_bundle.py --compare <old_bundle> <new_bundle>

# Compare the newest two matching bundles for a PR (or exact PR/commit):
python3 scripts/docker01_operator_qa_bundle.py --compare-latest --root /tmp --pr 206
python3 scripts/docker01_operator_qa_bundle.py --compare-latest --root /tmp --pr 206 --commit <sha> --json
```

`validate` reports `valid|warning|invalid`: it checks required files exist and
parse, command/assertion summary counts match their entries, raw outputs exist
for every listed command, `read_only=true`, `mutation_performed=false` (unless
the bundle honestly reports `status=failed`), `first_safe_command` points at
`qa-summary.md`, and — when a `bundle-manifest.json` is present — that every
file's sha256 matches (tamper detection). A **scoped validation `not_found`** is
treated as *clean evidence-of-absence* (valid) as long as it belongs to the
requested PR/commit and does not claim `pass_eligible=true`; a
`scope_matched=false` (evidence captured for a different PR/commit) is surfaced
as a **warning**, never as current passing evidence.

Newly generated bundles include a `bundle-manifest.json` (sha256 + size of every
file) so integrity can be verified later. **Legacy PR206 bundles without a
manifest remain valid** — validation falls back to structural checks and adds a
warning that integrity checks are limited.

`compare` / `compare-latest` classify the delta as `regressed` (e.g.
`passed -> failed`, a command or safety assertion `passed -> failed`,
`mutation_performed false -> true`, validation `scope_matched true/null -> false`,
`restart_count` increased, health `healthy -> unhealthy`), `improved` (the
inverse), `changed` (other differences), or `same`. Use the compare output in the
PR handoff to show that a new bundle did not regress against the prior one — the
reviewer still gives the final merge verdict.

## V1 canonical operator path (knife, not toolbox)

## Safe compose update pattern (Docker01/lab)

Use this runbook pattern to avoid accidental compose truncation:

1. Take a Proxmox/LXC snapshot first.
2. Backup compose file: `cp compose.yml compose.yml.bak-<tag>`.
3. Write edits to a temp file (example: `compose.yml.tmp`).
4. Validate temp file is non-empty before any replace step.
5. Validate rendered config:
   `docker compose -f compose.yml.tmp config >/tmp/compose-check.yml`.
6. Only then move the temp file into place.
7. Avoid sudo/pipeline write patterns that can truncate `compose.yml` when a command fails.
8. Recreate and verify: source HEAD, compose image, container image,
   `homelab.pr` label, `homelab.commit` label, health, and restart count.
9. Keep rollback backup references until QA passes.

Safety reminders for shared lab environments:
- Do not prune volumes.
- Do not remove running containers.


Use this concise, safe path for the V1 demo and handoff contract:

1. `shellforgeai version`
2. `shellforgeai doctor`
3. `shellforgeai model doctor`
4. `shellforgeai v1 check --profile quick`
5. `shellforgeai remediation self-test --profile quick`
6. `shellforgeai status`
7. `shellforgeai triage`
8. `shellforgeai propose`
9. `shellforgeai apply-preview`
10. `shellforgeai verify`
11. `shellforgeai handoff` (read-only operator handoff; `--save` for a ShellForgeAI-owned packet)
12. `shellforgeai triage --target <target>`
13. `shellforgeai remediation eligibility --target <target> --explain`
14. `shellforgeai ops report --save`
15. `shellforgeai ops report history --limit 5`
16. `shellforgeai ops report compare-latest`
17. `shellforgeai ask "It's 2AM; what is on fire?"`
18. Pressure-mode quick status: `shellforgeai status` / `shellforgeai status --brief` or `shellforgeai ask "quick status"`
19. `shellforgeai ask "please restart shellforgeai"` (expected deterministic refusal)
20. `shellforgeai ask "show me the command to inspect sfai-crashloop"` (command-help: returns the read-only `shellforgeai triage docker detail sfai-crashloop` with `No action was taken.`; nothing is executed)
21. `shellforgeai ask "what should I tell the next operator?"` (read-only handoff routing; nothing is executed)

Safety reminder: read-only by default; no casual restart/remediation/cleanup execute in the V1 demo path. Command-help ("show me the command ...", "how would I propose ..."), apply-preview prompts ("apply preview", "show apply gates"), verify prompts ("verify status", "did anything improve?"), and handoff prompts ("give me a handoff", "what should I tell the next operator?") explain safe current state/gates/posture without running anything or assuming an apply happened; "do it" / "run that" / "handoff and restart" mutation phrasings are refused.

Operator smoke tests and runbook tips.

For V1 release promotion, run the release-candidate validation flow in
[`docs/V1_RELEASE_CANDIDATE.md`](docs/V1_RELEASE_CANDIDATE.md).
For V2 command-surface planning and anti-bloat guardrails, use
[`docs/COMMAND_SURFACE_AUDIT.md`](docs/COMMAND_SURFACE_AUDIT.md) and
[`docs/V2_COMMAND_CONTRACT.md`](docs/V2_COMMAND_CONTRACT.md).

CLI maintainability note (PR182-PR202): `src/shellforgeai/cli.py` is being
split into a `src/shellforgeai/commands/` package one domain at a time,
behavior-preserving at each step. `cli.py` stays the root Typer entrypoint;
extracted domains include `status`, `doctor`, `ops`/`triage`, `verify`,
`handoff`, `propose`, `apply-preview`, `ask`, governed recipe/receipt safety
surfaces, `v1 check`, `model`, the `remediation self-test` readiness handler,
and the top-level `interactive` launcher. Command names, output, exit codes, JSON
behavior, and safety gates are unchanged. Before moving more handlers, use the
read-only inventory map in [`docs/CLI_REFACTOR_MAP.md`](docs/CLI_REFACTOR_MAP.md)
and run the PR184 command-surface golden guardrail for every split. See
[`docs/cli.md`](docs/cli.md) and [`docs/roadmap.md`](docs/roadmap.md).

PR202 turns the read-only `scripts/cli_refactor_inventory.py` inventory into a
regression guardrail (`tests/test_pr202_cli_refactor_inventory_enforcement.py`).
The inventory's `--json` now exposes a `cli_py` block (line count, inline
Typer-handler count, and documented debt thresholds); the guardrail fails if a
large new inline `@app.command` body is added to `cli.py` without extracting a
handler or deliberately updating the thresholds and docs, and it checks that
every PR182–PR201 command module exists and is imported/registered (not owned
inline). When you intentionally extract or add a command module, update the
inventory helper's module list/thresholds, regenerate `docs/CLI_REFACTOR_MAP.md`
with `--write-doc`, and run the PR184 golden command-surface guardrail plus the
appropriate validation lane. The inventory guardrail is read-only process tooling
and adds no runtime command or execution behavior.

PR203 closes the loop with a refactor-closure view. The inventory `--json`/
`--markdown` now emit a `closure` block and `docs/CLI_REFACTOR_MAP.md` documents:
`cli.py`'s intended role (`typer_wiring`), the intentional Typer wiring/glue that
is allowed to stay (Typer app/group creation, the root `@app.callback()` and
group `@*.callback()` glue such as `audit index`/`v1 packet`, command-module
imports/`register(...)` calls, compatibility aliases, and minimal bootstrap),
what is *not* allowed inline (large handler bodies, Docker/Compose mutation,
remediation/recovery/rollback execution, ask routing bodies, receipt artifact
logic, interactive REPL internals, model calls, large JSON builders), and the
closure status. Glue is detected from `@*.callback()` decorators; every other
inline handler is a classified future-extraction candidate. The closure never
claims a false OK: an unexpected (unclassified) inline handler, a missing
expected module, a missing command-surface guardrail, or a threshold breach
downgrades `closure_status` to `needs_attention`. Current state:
`closure_status: ok` with 18 extracted modules, 3 intentional callbacks, 96
classified future-extraction candidates, and 0 unexpected inline handlers.
Closure is verification only — no handler was moved and no runtime/execution
behavior was added (see `tests/test_pr203_cli_refactor_closure.py`).

PR204 adds a strict wiring-only enforcement mode:
`python scripts/cli_refactor_inventory.py --check` (and `--check --json`). It
treats `cli.py` as wiring-only and sorts every inline Typer callable into one of
three buckets: explicitly allowlisted wiring/bootstrap (a tiny, reasoned
`INLINE_ALLOWLIST` — `main`, `version_cmd`, and the `audit index`/`v1 packet`
group callbacks; every entry must carry a reason), documented
remaining-extraction candidates (classified debt, reported as the tracked
extraction map rather than silently allowed), and unapproved inline handlers
(unclassified handlers or non-allowlisted callbacks). An unapproved handler fails
the check with a nonzero exit and names the offending handler. A future PR that
wants to keep a new inline callable in `cli.py` must add an allowlist entry with
a reason; if the allowlist would grow beyond a few genuine wiring/bootstrap
items, extract the handler into `src/shellforgeai/commands/` instead, and run the
PR184 command-surface golden guardrail. The check is read-only AST inspection —
no command/Docker/Compose/model execution and no file mutation — and is enforced
by `tests/test_pr204_cli_wiring_only_enforcement.py`.

PR205 protects the *other* face of the closed command-module split: hidden
import-time behavior. Where the PR184 golden command-surface guardrail protects
user-visible commands, the PR205 import side-effect guardrail proves that
importing `shellforgeai.cli` and every `shellforgeai.commands.*` module is
import-safe — definitions, local imports, constants/option metadata, and Typer
registration only. Importing a command module must never execute operational
logic: no subprocess/`os.system`/`shell=True` execution, no Docker/Compose call
or container/production restart, no cleanup/remediation/rollback/recovery
execution, no model/Codex call, no network call, and no artifact
write/repair/delete. The guardrail lives in
`tests/test_pr205_command_module_import_side_effects.py` and combines a static
AST scan (no top-level operational calls; harmless help text is not flagged) with
a runtime check that purges the audited modules from `sys.modules` and reimports
them under monkeypatched recording stubs over the dangerous primitives, asserting
none fired at import time. A read-only helper,
`python scripts/cli_import_audit.py [--json|--markdown]`, runs the same audit in a
fresh process and reports per-module import status and any blocked side-effect
attempts; it is read-only and local-only (no command/Docker/Compose/model/network
execution and no artifact/`/data` mutation). Run this guardrail for any future
command-module change.

## Current baseline / handoff

The PR78 release/handoff baseline is the current operator reference
for what ShellForgeAI can do today, what is safely gated, what is
intentionally blocked, the safe cleanup sequence, and the Compose
disposable proof posture. Start there if you are picking the tool up
after the PR56–PR77 arc:

- [`docs/release-baseline.md`](docs/release-baseline.md)


## What can ShellForgeAI safely do next?

Use the governed recipe registry before thinking about fixes:

```bash
shellforgeai recipes list
shellforgeai recipes inspect docker.disposable_restart
shellforgeai recipes eligibility --recipe docker.disposable_restart --target <target>
shellforgeai safe-actions --target <target>
```

Interpretation:

- `available_read_only` recipes are safe reports/previews operators can run now.
- `disabled_until_execute_lane` and `disabled_until_explicit_cleanup_lane` recipes
  document future gates only; they do not execute.
- Production targets such as `shellforgeai`, broad targets such as `all`, missing
  targets, and unlabeled targets are blocked.
- If asked to restart, fix, clean up, roll back, or execute a recipe, ShellForgeAI
  must refuse and state that no action was taken.

## Interactive smoke test

```bash
shellforgeai
```

Inside the REPL:

```text
/help
/tools
/pending
my device feels a bit sluggish today
/pending
dig deeper
/pending
/exit
```

2AM handoff tip: before exiting interactive mode, run `/summary` to capture a concise local session handoff without collecting new evidence or executing commands. For a portable handoff artifact, save, validate, and export the summary without suggesting mutation:

```text
sfai> /summary --save
shellforgeai session summary validate <id>
shellforgeai session summary export <id>
shellforgeai session summary export-validate <export_id_or_path>
shellforgeai session summary compare-export <before_export_id_or_path> <after_export_id_or_path>
shellforgeai session summary history --limit 5
shellforgeai session summary compare-latest
```

For a follow-up handoff, use `shellforgeai session summary history --limit 5`
to find recent saved REPL summaries, `shellforgeai session summary
compare-latest` to compare the newest two saved summaries, or
`shellforgeai session summary compare-export <before_export> <after_export>`
to compare two already-exported handoff bundles without collecting new evidence,
calling the model, executing shell, or mutating Docker/Compose/system state.

For REPL discoverability, type `help`, `/help`, `?`, `commands`, or `what can I do?`. The help screen lists exact safe interactive forms for fast status, triage/detail, reports/artifacts, readiness checks, follow-ups, pressure-mode brief status, and refused mutation examples. Mistyped ShellForgeAI-like commands get deterministic safe suggestions that are never auto-run. It also repeats the safety boundary: interactive mode is not a shell and does not run Docker/Compose/remediation/cleanup commands from natural language.

Selected safe CLI-style commands also work directly inside the REPL, including common read-only flags such as `--profile`, `--brief`, `--json`, and `--limit` for the allowlisted commands:

```text
shellforgeai interactive
doctor
ops report
triage docker detail sfai-crashloop
remediation eligibility --target sfai-crashloop --explain
```

Canonical flagged examples for scripted demos or operator handoff:

```text
shellforgeai interactive --yes-trust
v1 check --profile quick --json
ops report --brief
triage docker detail sfai-crashloop --json
```

### Scripted / non-interactive sessions

Already-trusted workspaces are not re-prompted, so the first piped line is
treated as a command (not as a trust answer). For a fresh/untrusted
workspace in a scripted session, pass `--yes-trust` to skip the trust
prompt without weakening safety:

```text
shellforgeai interactive --yes-trust
doctor
ops report
/exit
```

`--yes-trust` only trusts the current workspace for this session and skips
the trust prompt. It does **not** grant mutation, shell execution,
Docker/Compose mutation, remediation/cleanup/rollback execution, or bypass
the paste guard or natural-language mutation refusals — those stay refused
with no action taken (e.g. `docker compose restart shellforgeai`, `rm -rf /`,
`remediation execute --confirm`). When untrusted and no flag is passed,
only `y`/`yes` grant trust; `n`/`no`/empty decline and exit safely; any
other input is an invalid trust response that reprompts with clear
guidance rather than running as a command.


Expected outcomes:
- Sluggish phrasing routes to performance diagnostics before synthesis.
- Evidence highlights stay compact in normal UX while `/tools` and debug
  views preserve technical names.
- `/pending` shows queued read-only follow-ups (or explicit none queued).
- The "Collected N read-only evidence item(s)" line, the diagnose footer
  `Evidence:` line, and `Evidence count` in `summary.md` all show the
  same number (sourced from `evidence.json`).
- `summary.md` reads as a friendly mini-report (Assessment / Key evidence
  / Findings / Artifacts / Safety note) and only references artifact
  files that actually exist on disk.

After a diagnosis, follow-up questions like `what did you find?`, `why is
it slow?`, or `is it running normally?` use the latest evidence collected
in the current interactive session (target, evidence highlights, artifact
paths, limitations, and safe next commands) instead of generic context.
With no formal pending investigation, `/pending` also surfaces that latest
diagnosis context. These follow-ups are read-only and never run new
collectors or execute mutation.
After ShellForgeAI asks for read-only evidence, short continuations like
`get that info`, `then get that info`, `do that`, `proceed`, or `dig deeper`
continue only the safe read-only path. Without a pending safe follow-up, those
phrases produce no-context guidance instead of inventing evidence. Paste-like
or mutation-shaped input is still refused and no command is executed.

The human-feel regression suite (`tests/test_pr134_human_feel_regression.py`) keeps messy pressure prompts, command-help phrasing, follow-up pronouns, paste-like snippets, and natural-language mutation refusals covered as a UX/safety guardrail. Report command-help prompts route to canonical `shellforgeai ops report` guidance.

## Apply safety check

```bash
shellforgeai apply <valid-plan-file>
```

Expected outcome: apply execution is intentionally disabled in this alpha
(validation-only parse/validate path).

For approved proposal objects:

```bash
shellforgeai apply <approved-proposal-id>
shellforgeai apply --latest-approved
shellforgeai apply --dry-run <approved-proposal-id>
```

Expected outcome: preflight passes, a static bundle is written under
`<data_dir>/apply_bundles/<id>/` (`apply-preview.md`,
`operator-commands.sh`, `rollback.sh`, `validation.md`,
`apply-preflight.json`), and no commands are executed. The shell scripts
contain an early `exit 2` and the banner "ShellForgeAI did not execute
this script." Pending, rejected, or canceled proposals fail preflight and
no operator-run scripts are written.

## Non-interactive smoke test

```bash
shellforgeai doctor
shellforgeai inspect host
shellforgeai tools list
shellforgeai diagnose disk --save-plan
shellforgeai audit list
shellforgeai audit timeline
shellforgeai ops status
```

Use `shellforgeai ops status` as the quick posture board (evidence/proposal/mission/audit/cleanup),
then follow up with explicit proposal/mission IDs; PR59 "this/latest/current"
ask-reference disambiguation remains available for read-only follow-ups.

## Restricted containers

In restricted containers, the Codex CLI may emit `bwrap`/namespace errors.
Treat that as a provider sandbox limitation, not a host failure: ShellForgeAI
still collects evidence via its typed read-only tools, and `model doctor`
will report whether `codex` is reachable. If model-assisted assessment is unavailable, run `codex login --device-auth`; deterministic diagnosis/reporting remains available.

## Safety reminders

- `apply` is validation-only.
- Service-impacting actions are described as approval-required / operator-run.
  ShellForgeAI does not execute them.
- Mutation is blocked or asks regardless of workspace trust.

- For "what is using disk space?", expect bounded top-level directory breakdown (`disk.top_dirs`) in addition to usage/inodes.

Smoke checks should confirm `storage.error_summary` outputs such as “no recent storage error patterns found” do not produce a warning finding.


## Service investigation smoke

In the REPL, run: `can you restart nginx for me?`, `/pending`, `dig deeper`, `is nginx running?`, `what services are running?`, `what ports are listening?`, `is ssh running?`, `docker status`.
Expected: read-only service evidence collection, no restart/reload/stop/start execution, and useful container-limit context when service managers are unavailable.


JSON smoke:
`shellforgeai diagnose nginx --json | python -m json.tool >/dev/null`
`shellforgeai diagnose performance --json | python -m json.tool >/dev/null`
`shellforgeai diagnose disk --json | python -m json.tool >/dev/null`


Additional service-action smoke: `can you restart shellforgeai?` should collect read-only service evidence immediately, queue pending service health, and refuse mutation execution.

Role/health smoke examples (read-only):
- `what does this system do?`
- `is it running normally?`
Expected next commands remain safe: `shellforgeai ops report`, `shellforgeai triage docker`, `shellforgeai triage docker detail <target>`, `shellforgeai remediation eligibility --target <target> --explain`.
Read the first safe command first; artifacts/details follow.


No-hang follow-up smoke: run `can you restart nginx`, `/pending`, `proceed`, `/pending`, `can you restart shellforgeai`, `/pending`, `dig deeper`, `/pending`, `/exit` and confirm prompt returns each time without session drop.

Zombie/process smoke: compare `ps -eo pid,ppid,stat,comm,args | grep -E "codex|defunct|shellforgeai" | grep -v grep || true` before/after interactive checks; no accumulating defunct children should remain.

Runtime hygiene check: `shellforgeai doctor` should report `runtime_hygiene ... init_reaper=yes` when compose is running with `init: true`.


## Targeted network follow-up smoke

In the REPL, run:

```
can this server reach example.com:443?
/pending
proceed
can you open port 443?
/pending
proceed
check DNS for example.com
/pending
proceed
```

Expected:

- `/pending` shows target context (host:port, port, or domain).
- `proceed` after a reachability question runs a target-specific deep dive
  (namespace context, default route, DNS resolver, target DNS resolution,
  bounded TCP connect to the same host:port, firewall context). It does
  not fall back to a generic network deep dive.
- `proceed` after `can you open port 443?` focuses on port 443
  (listeners, listener ownership, firewall context, container/route view)
  and does not mutate or emit unconditional firewall commands.
- `proceed` after a DNS question repeats the resolver/resolution test
  for the requested domain (or notes the safe default if no domain was
  given).
- Apply remains validation-only.


## Docker01 lab smoke (read-only logs/error/container)

A repeatable failure range exists at `/srv/lab-cases` on Docker01. The
lab cases drive container failure detection scenarios used to validate
read-only log/error/Docker triage:

- `missing-env` — exits 42, logs `REQUIRED_SETTING is missing`.
- `restart-loop` — restarting/crashing, repeated simulated crash.
- `noisy-logs` — running with WARN/ERROR noise (not a crash).
- `bad-volume-perms` — exits, read-only filesystem / permission denied.
- `bad-network` — running with DNS/reachability errors in logs.

Bring up + status:

```
sudo /srv/lab-cases/bin/lab-clean
sudo /srv/lab-cases/bin/lab-up missing-env
sudo /srv/lab-cases/bin/lab-up restart-loop
sudo /srv/lab-cases/bin/lab-up noisy-logs
sudo /srv/lab-cases/bin/lab-up bad-volume-perms
sudo /srv/lab-cases/bin/lab-up bad-network
sudo /srv/lab-cases/bin/lab-status
```

ShellForgeAI checks (all read-only):

```
sudo docker compose exec -T shellforgeai shellforgeai diagnose docker --save-plan
sudo docker compose exec -T shellforgeai shellforgeai diagnose logs --save-plan
sudo docker compose exec -T shellforgeai shellforgeai diagnose errors --save-plan
sudo docker compose exec -T shellforgeai shellforgeai diagnose "is anything crashing?" --save-plan
sudo docker compose exec -T shellforgeai shellforgeai diagnose "why did the container exit?" --save-plan
sudo docker compose exec -T shellforgeai shellforgeai diagnose "find recent logs and errors" --save-plan
```

Expected findings:

- missing-env: warning — exited with code 42 + missing required setting.
- restart-loop: critical — restart loop / repeated simulated crash.
- noisy-logs: info — running but logs contain noise (not crashed).
- bad-volume-perms: warning — exited with write/permission failure.
- bad-network: warning — running with DNS/reachability errors in logs.

Network/log ask smoke (PR28):

```
sudo docker compose exec -T shellforgeai shellforgeai ask "network reachability is broken"
sudo docker compose exec -T shellforgeai shellforgeai ask "why is bad-network failing?"
sudo docker compose exec -T shellforgeai shellforgeai ask "DNS errors in logs"
sudo docker compose exec -T shellforgeai shellforgeai ask "app cannot reach upstream"
```

Expected: the answer mentions `sfai-bad-network`, says it is running but logging
DNS/upstream/reachability errors, separates app/container failure from host-wide
network health (a healthy DNS resolver/default route does not cancel app log
evidence), and never mutates. The prompt sent to the model carries an explicit
`network_reachability_brief` block with `container_log_evidence` (per-container
themes labelled `dns_resolution` / `upstream_unreachable` / `connection_refused`
/ `timeout` / `tls_certificate`) listed before `runtime_network_basics`; when
the question names a lab case (e.g. `bad-network`) the targeted container is
pinned to the front of `container_log_evidence` and is never truncated out.
Mutation-style asks ("fix the network", "open port 443", "change DNS") collect
read-only evidence and emit a safety boundary; `apply` remains validation-only.

Docker/operator ask grounding smoke (PR222):

```
sudo docker compose exec -T shellforgeai shellforgeai ask "2AM docker feels broken"
sudo docker compose exec -T shellforgeai shellforgeai ask "what is wrong with docker?"
sudo docker compose exec -T shellforgeai shellforgeai ask "why is beszel-agent suspicious?"
sudo docker compose exec -T shellforgeai shellforgeai ask "Clean up docker and restart compose to fix it"
```

Model-backed `ask` for Docker/operator questions is grounded in deterministic
ShellForgeAI Docker triage evidence — deterministic CLI evidence remains the
source of truth and model assistance may only explain and route from it. When a
top suspect exists, the answer names the actual suspect, severity, confidence,
and evidence themes and offers a real supported read-only safe next command
(e.g. `shellforgeai triage docker detail <suspect> --json`). If no top suspect
is `beszel-agent`, the answer references the real top suspect from triage, not a
guessed one. When deterministic evidence is missing it says so and points to a
real evidence-gathering command (`shellforgeai triage docker --json`,
`shellforgeai ops report --json`, `shellforgeai status --json`) instead of
inventing a diagnosis. The model must not invent commands or actions: any
unsupported suggestion (`shellforgeai diagnose <container>`, `shellforgeai fix
docker`, `shellforgeai restart compose`, bare `docker prune` / `docker image
rm`) is stripped from the answer and replaced with the deterministic safe next
command. Broad mutation/auto-fix asks ("clean up docker and restart compose",
"prune docker images", "fix beszel-agent automatically") remain refused. `ask`
grounding performs no cleanup, Docker prune, image removal, file deletion,
Docker/Compose mutation, restart, remediation, rollback, recovery, or
natural-language execution — even when model auth is unavailable, the
deterministic evidence still answers and `shellforgeai model doctor --json` is
the auth-diagnostic path.

Operator runbook smoke (PR30):

```
sudo docker compose exec -T shellforgeai shellforgeai diagnose docker --save-plan --with-runbook
sudo docker compose exec -T shellforgeai shellforgeai runbook --latest
sudo docker compose exec -T shellforgeai shellforgeai validate-runbook --latest
sudo docker compose exec -T shellforgeai shellforgeai ask "give me a safe fix plan for the failed containers"
sudo docker compose exec -T shellforgeai shellforgeai ask "fix bad-network safely"
sudo docker compose exec -T shellforgeai shellforgeai ask "fix write permissions safely"
sudo docker compose exec -T shellforgeai shellforgeai ask "fix missing env safely"
sudo docker compose exec -T shellforgeai shellforgeai ask "what should I do next?"
```

Expected: a `runbook.md` (and `runbook.json`) artifact is written next
to `evidence.json`. The runbook covers `sfai-missing-env`,
`sfai-bad-volume-perms`, `sfai-restart-loop`, and `sfai-bad-network`
with prechecks, operator-run options, rollback, and post-fix
validation; `sfai-noisy-logs` is recommended for investigation only and
sorted last; `sfai-healthy-web` is listed as a known-good baseline.
Every mutating step is labelled `OPERATOR-RUN` (also
`SERVICE-IMPACTING` / `REQUIRES APPROVAL` / `ROLLBACK ADVISED` where
appropriate) and the runbook explicitly states "ShellForgeAI did not
execute these steps." `apply` remains validation-only — no mutation.

Cleanup:

```
sudo /srv/lab-cases/bin/lab-clean
sudo /srv/lab-cases/bin/lab-status
```

ShellForgeAI's Docker visibility is read-only by convention: only
`docker ps`, `docker inspect`, and `docker logs --tail N` are issued.
Mutation (start/stop/restart/rm/exec/cp/build/pull/prune, compose
mutation, volume/network mutation) is never executed. `apply` remains
validation-only.
When ShellForgeAI runs in Docker, host-oriented checks are container-limited
unless host mounts/namespaces expose more visibility.

Compose ownership troubleshooting (PR57 ask polish):

- `shellforgeai ask "compose context for <container>"`
- `shellforgeai compose inspect <container>`
- For any restart intent, follow proposal/mission/apply gates; ask will refuse natural-language Compose mutation.

Approval queue smoke (PR32):

```
sudo docker compose exec -T shellforgeai shellforgeai diagnose docker --save-plan --with-runbook
latest=$(sudo docker compose exec -T shellforgeai sh -lc 'find /data/artifacts -maxdepth 1 -type d -name "sf_*" | sort | tail -n 1' | tr -d "\r")
sudo docker compose exec -T shellforgeai shellforgeai approvals create "$latest"
sudo docker compose exec -T shellforgeai shellforgeai approvals list
first=$(sudo docker compose exec -T shellforgeai sh -lc 'find /data/approvals/pending -name "*.proposal.json" | sort | head -n 1 | xargs -r basename | sed "s/.proposal.json$//"' | tr -d "\r")
sudo docker compose exec -T shellforgeai shellforgeai approvals show "$first"
sudo docker compose exec -T shellforgeai shellforgeai approvals validate "$first"
sudo docker compose exec -T shellforgeai shellforgeai approvals approve "$first" --reason "Docker01 PR32 approval test"
sudo docker compose exec -T shellforgeai shellforgeai approvals list
sudo docker compose exec -T shellforgeai sh -lc 'find /data/approvals -maxdepth 2 -type f -name "*.proposal.json" -print | sort'
sudo docker compose exec -T shellforgeai shellforgeai ask "queue the safe fixes for approval"
sudo docker compose exec -T shellforgeai shellforgeai ask "approve and run the fix"
sudo docker compose exec -T shellforgeai shellforgeai ask "fix everything now"
```

Expected: proposals are created for `sfai-missing-env`,
`sfai-bad-volume-perms`, `sfai-restart-loop`, `sfai-bad-network`
(noisy-logs/healthy-web skipped by default). `approvals show` displays
preconditions/steps/rollback/verification with safety labels and an
explicit "Not executed by ShellForgeAI" line. `approvals validate`
reports `execution: disabled`, `schema: ok`, `safety: ok`. `approve`
only updates status and moves the JSON file between
`/data/approvals/{pending,approved}/`. Asks like "approve and run the
fix" and "fix everything now" refuse execution and point at
`approvals create` / `approvals approve` / `apply` flow. No mutation
is performed.

Apply preflight + operator bundle smoke (PR33):

```
sudo docker compose exec -T shellforgeai shellforgeai diagnose docker --save-plan --with-runbook
latest=$(sudo docker compose exec -T shellforgeai sh -lc 'find /data/artifacts -maxdepth 1 -type d -name "sf_*" | sort | tail -n 1' | tr -d "\r")
sudo docker compose exec -T shellforgeai shellforgeai runbook validate "$latest"
sudo docker compose exec -T shellforgeai shellforgeai approvals create "$latest"
sudo docker compose exec -T shellforgeai shellforgeai approvals list
first=$(sudo docker compose exec -T shellforgeai sh -lc 'find /data/approvals/pending -name "*.proposal.json" | sort | head -n 1 | xargs -r basename | sed "s/.proposal.json$//"' | tr -d "\r")
# Pending apply should fail preflight with no operator-run scripts written.
sudo docker compose exec -T shellforgeai shellforgeai apply "$first"
sudo docker compose exec -T shellforgeai shellforgeai approvals approve "$first" --reason "Docker01 PR33 preflight test"
# Approved apply should generate the bundle but not execute anything.
sudo docker compose exec -T shellforgeai shellforgeai apply "$first"
sudo docker compose exec -T shellforgeai sh -lc "
bundle=\$(find /data/apply_bundles -maxdepth 1 -type d -name '${first}*' | sort | tail -n 1)
python -m json.tool \"\$bundle/apply-preflight.json\" >/dev/null && echo OK apply-preflight.json valid
grep -RInE 'ShellForgeAI did not execute|exit 2|execution_allowed|not_executed' \"\$bundle\"
"
```

Expected: pending apply refuses, approved apply creates the bundle, the
shell scripts contain an early `exit 2` and the "ShellForgeAI did not
execute" banner, and `apply-preflight.json` records
`execution_allowed: false` and `execution_status: "not_executed"`. Ask
safety:

```
sudo docker compose exec -T shellforgeai shellforgeai ask "apply the approved proposal"
sudo docker compose exec -T shellforgeai shellforgeai ask "can you run the approved fix?"
sudo docker compose exec -T shellforgeai shellforgeai ask "prepare the approved fix bundle"
```

Expected: execution-style asks refuse cleanly; preview/prepare-style asks
generate the operator preflight bundle. No mutation in either case.


## Audit/export pack smoke (PR34)

Local-only flow (no Docker, no root, no host mutation):

```
shellforgeai diagnose docker --save-plan --with-runbook
shellforgeai export --latest
shellforgeai validate-export <data_dir>/exports/<export_id>
shellforgeai approvals create --latest
shellforgeai approvals approve <id> --reason "PR34 export smoke"
shellforgeai apply <id>
shellforgeai export --latest-approved
shellforgeai validate-export <data_dir>/exports/<latest_approved_export_id>
shellforgeai ask "create an audit pack"
shellforgeai ask "export the approved proposal"
```

Expected: an export pack is written under `<data_dir>/exports/<export_id>/`
containing `export-manifest.json`, `export-summary.md`, `checksums.sha256`,
and copies of evidence/summary/plan/runbook/proposal/apply-preflight files
that exist for the source. Missing optional files are recorded in the
manifest. `validate-export` reports `safety: ok` and `execution: none`.
ShellForgeAI does not execute any remediation.

## Stale/drift guard smoke (PR38)

Repo-local fixture flow (no Docker, no root, no host mutation):

```
shellforgeai diagnose docker --save-plan --with-runbook
shellforgeai approvals create --latest
shellforgeai approvals approve <id> --reason "PR38 guard smoke"
shellforgeai guard check --latest-approved
shellforgeai guard check --latest-approved --max-age-hours 1
shellforgeai actions compile --latest-approved
shellforgeai guard check-actions <data_dir>/actions/<id>/actions.json
shellforgeai export --latest-approved
shellforgeai guard check-export <data_dir>/exports/<export_id>
shellforgeai guard show <data_dir>/guards/<id>/guard-report.json
shellforgeai apply --latest-approved
shellforgeai ask "is the approved proposal still fresh?"
shellforgeai ask "check drift before apply"
shellforgeai ask "run it anyway"
```

Expected: each guard call writes `guard-report.json` and `guard-report.md`
under `<data_dir>/guards/<source-id>/` with `execution_allowed=false` and
`execution_status=not_executed`. Fresh artifacts return `decision: fresh`;
overriding `--max-age-hours` to a very small value flips the decision to
`stale`. `apply` records `guard_status` and `guard_report` in
`apply-preflight.json` and refuses by default when the proposal is stale
or drifted. ShellForgeAI does not execute any remediation.

## Audit-aware incident index/search smoke (PR40)

Repo-local fixture flow (no Docker, no root, no host mutation, no network):

```
shellforgeai audit index
shellforgeai audit index --rebuild
shellforgeai audit index validate
shellforgeai audit search bad-network
shellforgeai audit search --component sfai-bad-network
shellforgeai audit search --kind guard_check --status refused
shellforgeai audit search --risk medium --type proposal
shellforgeai audit search --proposal <id>
shellforgeai audit search --session <sf_*>
shellforgeai audit search --json
shellforgeai ask "search audit for bad-network"
shellforgeai ask "find drift refusals"
shellforgeai ask "did anything execute?"
```

Expected: `audit index` writes only
`<data_dir>/audit/incident-index.json` (no source artifact is modified)
and prints per-source counts plus `execution: none`. `audit search`
prints a table or `--json` array of matching items. Every indexed item
records `execution_allowed=false`, `execution_status=not_executed`,
`mutation_performed=false`; `audit index validate` re-asserts those
invariants. ShellForgeAI does not execute any remediation.

## Local validation (fixtures/mocks only)

Run local validation without Docker daemon, root, or service mutation:

- `ruff format .`
- `ruff check .`
- `mypy src/shellforgeai tests`
- `pytest -q`
- `python -m compileall src`
- `env -u PYTHONPATH pytest -q`
- `pytest -q tests -k "export or audit or approval or apply or runbook"`
- `pytest -q tests -k "guard or stale or drift or apply or actions"`
- `pytest -q tests -k "audit or index or search or timeline"`

- PR41 validation remains repo-local fixtures/mocks only: no Docker daemon, no systemd/journal dependencies, no host mutation outside `tmp_path`.


## Repo-local fixture validation only
- PR validation for ask-routing changes must run with repo fixtures/mocks only (no Docker daemon, no systemd/journal dependencies, no root-only setup).


## PR43 status dashboard validation

- Run status/dashboard tests with repo-local fixtures only (tmp_path/mocks).
- Do not require Docker, root, systemd/journal, or internet for status validation.

## Disk growth operational note
When ShellForgeAI metadata grows, run `shellforgeai audit retention` first, then run dry-run prune/archive commands to review impact before any explicit execution.

## Safe cleanup flow (PR46)

The first guarded mutation step is limited to ShellForgeAI-owned metadata
cleanup. Follow this sequence:

1. `shellforgeai doctor` — review metadata hygiene severity and totals.
2. `shellforgeai audit retention --top 20` — see the largest categories/items.
3. `shellforgeai audit prune --category exports --max-age-days 30` — dry-run
   (the default); deletes nothing and prints the plan plus the next-step
   command.
4. (Optional) `shellforgeai audit archive --older-than-days 30` — create a
   compact archive before pruning.
5. `shellforgeai audit prune --category exports --max-age-days 30 --execute
   --confirm` — execute only after reviewing the dry-run. Writes a receipt
   under `<data_dir>/prune_receipts/` and an audit event marked
   `metadata_cleanup_executed=true`, `remediation_execution=false`.

PR46 does not execute remediation, Docker/systemd/package commands, firewall
changes, or generated operator scripts. `apply` remains
validation/preflight-only.

## Lab container restart flow (PR47)

PR47 adds the *first non-metadata* mutation gate: one Docker container
restart, only for explicitly allowlisted lab containers, only behind every
gate. Validation is repo-local fixtures/mocks only — no live Docker, no root,
no systemd/journal, no internet.

Operational sequence:

1. `shellforgeai diagnose <target>` — collect read-only evidence.
2. `shellforgeai runbook` — render the operator runbook.
3. `shellforgeai approvals create <session>` — stage proposals (no execution).
4. `shellforgeai approvals approve <id> --reason "..."` — record approval
   (no execution).
5. `shellforgeai actions compile <id>` — compile review-only actions; docker
   restart is classified `docker/restart`, decision `blocked`,
   `SERVICE-IMPACTING`. `execution_allowed` stays `false` here.
6. `shellforgeai guard check <id>` — confirm freshness and no drift.
7. Configure the lab restart allowlist (disabled by default):
   ```bash
   mkdir -p <data_dir>/policy
   cat > <data_dir>/policy/lab-container-restart-allowlist.json <<'EOF'
   {
     "schema_version": "1",
     "enabled": true,
     "allowed_containers": ["sfai-healthy-web"],
     "notes": "Lab-only restart allowlist."
   }
   EOF
   export SHELLFORGEAI_MUTATION_MODE=lab
   export SHELLFORGEAI_ALLOW_LAB_CONTAINER_RESTART=1
   ```
8. `shellforgeai apply <approved-proposal-id> --execute --confirm` — runs
   exactly one `docker restart <allowlisted-container>` if every gate passes.
   Writes a JSON receipt under `<data_dir>/execution_receipts/` and a scoped
   audit event (`kind=execution`, `action=lab_container_restart`,
   `safety.mutation_scope=lab_container_restart_only`).

PR47 does not execute `docker compose`, `docker stop|start|kill|rm|exec|run`,
docker volume/image/network commands, `systemctl`/service control,
apt/yum/dnf/apk/pip, chmod/chown/rm/mv/cp, firewall/routes/DNS changes,
generated operator scripts, or arbitrary shell strings. `apply` remains
validation/preflight-only for every other action kind.

PR47 validation remains repo-local fixtures/mocks only: no Docker daemon, no
systemd/journal, no root, no internet. Tests use the `FakeCommandExecutor`
exposed by `shellforgeai.core.lab_restart`.

## Post-mutation verification flow (PR48)

PR48 does not widen mutation scope. After the PR47 `docker restart
<allowlisted-container>` exits 0, ShellForgeAI automatically runs bounded
read-only verification: `docker inspect <container>` before and after the
restart, plus an optional bounded health-poll loop when the container has a
healthcheck. There is no second restart attempt and no `docker exec`.

Operational sequence after PR47 step 8:

9. The CLI captures `before-inspect` and `after-inspect` JSON, computes a
   verification status, and writes everything to:
   ```
   <data_dir>/execution_receipts/exec_<timestamp>_<shortid>.json   # receipt + verification block
   <data_dir>/execution_receipts/exec_<timestamp>_<shortid>.md     # human-readable summary
   <data_dir>/execution_receipts/exec_<timestamp>_<shortid>/before-inspect.json
   <data_dir>/execution_receipts/exec_<timestamp>_<shortid>/after-inspect.json
   ```
10. The audit event for the restart includes
    `details.verification_status=passed|warning|failed|skipped`,
    `details.container_running_after`, `details.started_at_changed`,
    `details.health_after`, and `details.verification_notes`. Event-level
    `status` is `success` (verification passed), `warning` (verification
    warning), or `failed` (verification failed or restart command itself
    failed).
11. Inspect the result with read-only tooling:
    ```bash
    shellforgeai audit timeline
    shellforgeai ask "did the restart work?"
    shellforgeai ask "show post-mutation verification"
    shellforgeai ask "show last execution receipt"
    ```
12. Diagnose if verification failed:
    - `verification: failed` with `running_after: false` → container exited
      after restart. Check `<data_dir>/execution_receipts/exec_<id>/after-inspect.json`
      and the operator runbook. ShellForgeAI does **not** retry the restart.
    - `verification: warning` with `Healthcheck still starting after timeout`
      → service is slow to come up; re-run `shellforgeai ask "show
      verification"` after a longer manual wait, or inspect the container
      health logs out-of-band.
    - `verification: warning` with `RestartCount did not change` → expected
      for manual `docker restart`; not actionable on its own.
    - `verification: skipped` → restart command itself failed (the receipt's
      `result.status` is `failed`). Investigate the docker error before
      proposing a new restart.

PR48 validation remains repo-local fixtures/mocks only: no Docker daemon, no
real `time.sleep`, no root, no systemd/journal, no internet. Tests use
`FakeContainerInspector` (read-only) and `FakeCommandExecutor` (only argv
`["docker", "restart", "<safe-name>"]`) from
`shellforgeai.core.lab_restart`.


## Safe restart proposal workflow (PR50)

1. `shellforgeai diagnose <target> --with-runbook`
2. `shellforgeai approvals propose-restart <container> --latest`
3. `shellforgeai approvals approve <id> --reason "..."`
4. `shellforgeai rollback preview <id>`
5. `shellforgeai apply <id> --execute --confirm`
6. verify/audit/export as needed.


## Restart plan checklist flow (PR51)

1. `shellforgeai diagnose docker --save-plan`
2. `shellforgeai approvals propose-restart --latest --container <target>`
3. `shellforgeai approvals restart-plan <proposal-id>`
4. `shellforgeai approvals approve <proposal-id> --reason "..."`
5. `shellforgeai rollback preview <proposal-id>`
6. `shellforgeai approvals restart-plan <proposal-id>`
7. `shellforgeai apply <proposal-id> --execute --confirm`
8. verify/audit/export


## Safe restart mission flow (PR52)

A guided wrapper that records each step in one mission file. Metadata only.

1. `shellforgeai diagnose docker --save-plan`
2. `shellforgeai mission restart prepare --container <target>`
3. `shellforgeai mission restart checklist <mission-id>`
4. `shellforgeai approvals approve <proposal-id> --reason "..."`
5. `shellforgeai rollback preview <proposal-id>`
6. `shellforgeai mission restart checklist <mission-id>`
7. `shellforgeai apply <proposal-id> --execute --confirm`
8. `shellforgeai mission restart validate <mission-id>` and audit/export

Mission preparation/status/checklist never restart anything; apply is still the
only execution gate.


## Safe restart mission flow with mission execute handoff (PR53)

PR53 adds a mission-level execute command that delegates to the existing apply
gate without introducing a new executor or broadening mutation scope.

1. `shellforgeai diagnose docker --save-plan`
2. `shellforgeai mission restart prepare --container <target>`
3. `shellforgeai mission restart checklist <mission-id>`
4. `shellforgeai approvals approve <proposal-id> --reason "..."`
5. `shellforgeai rollback preview <proposal-id>`
6. `shellforgeai mission restart checklist <mission-id>`
7. `shellforgeai mission restart execute <mission-id> --execute --confirm`
8. `shellforgeai mission restart validate <mission-id>` and audit/export

Step 7 verifies mission readiness, then delegates to the same guarded code path
as `shellforgeai apply <proposal-id> --execute --confirm`. The apply receipt is
referenced from the mission record. Without `--execute --confirm`, step 7 is
dry-run only and prints the exact apply delegation command.


## Post-execution mission review flow (PR54)

After a mission executes through the apply gate, PR54 adds a single read-only
review/export flow. None of these commands mutate Docker, services, packages,
filesystem, firewall, network, or system state.

1. `shellforgeai mission restart status <mission-id>` — refresh phases and
   confirm `status=executed`.
2. `shellforgeai mission restart report <mission-id>` — print the post-
   execution report; writes `mission-report.json` and `mission-report.md`
   under `<data_dir>/mission_reports/<mission-id>/`. Add `--json` for strict
   machine-readable output.
3. `shellforgeai mission restart export <mission-id> --redact` — bundle the
   mission record, report, proposal, rollback preview, apply receipt,
   before/after inspect evidence, and relevant audit events into
   `<data_dir>/mission_exports/<mission-id>/`. The `--redact` flag applies
   best-effort redaction to exported text copies; source artifacts remain
   unchanged.
4. `shellforgeai mission restart validate-export
   <data_dir>/mission_exports/<mission-id>/` — re-verify manifest, files,
   checksums, redaction report (when applicable), and safety invariants.
5. `shellforgeai audit timeline --proposal <proposal-id>` — replay the full
   audit timeline (apply gate execution + restart_mission delegated events +
   mission_report / mission_export read-only events).

Steps 2–5 are read-only. The export pack itself does not execute mutation; it
may describe a prior gated mutation if one occurred. Natural-language asks for
"run mission and export" remain refused — only the explicit
`mission restart execute --execute --confirm` (PR53) or
`apply <approved-proposal-id> --execute --confirm` (PR47) can execute the
gated mutation.

## PR55 cleanup review workflow

1. shellforgeai doctor
2. shellforgeai audit retention --top 20
3. shellforgeai audit cleanup plan --category exports --max-age-days 7
4. shellforgeai audit cleanup archive <plan-id>
5. shellforgeai audit cleanup execute <plan-id> --confirm
6. shellforgeai audit cleanup validate <receipt>
7. shellforgeai doctor

## Compose ownership check flow (PR56)

1. `shellforgeai diagnose docker --save-plan`
2. `shellforgeai compose inspect <container>`
3. Confirm compose project/service ownership before creating restart proposals.
4. Continue through existing proposal/mission/apply gates only for allowlisted containers.

## Compose-aware restart enrichment (PR58)

Operator notes for safely using PR58 Compose context enrichment:

- Use `shellforgeai compose inspect <container>` first to understand project /
  service ownership. The same context is automatically surfaced inside
  proposals, restart plans, missions, apply receipts, and mission reports.
- The restart proposal remains container-scoped. PR58 does not add
  `docker compose restart/up/down/recreate` and does not change the
  command preview, which stays exactly `docker restart <container>`.
- If you see `docker compose` in a proposal's command preview, restart-plan
  readiness will block. Fix the proposal — do not bypass the block.
- Future Compose service mutations need a separate policy gate and a separate
  PR. PR58 only enriches metadata; it never executes `docker compose`.


## PR59 operator note: ask-reference disambiguation
- Prefer explicit proposal/mission IDs when multiple candidates exist.
- `this/latest/current` now prefers fresh active artifacts.
- Stale matches are warned instead of silently treated as current.
- Long-lived `/data` may contain old artifacts; explicit IDs are safest for audits.

## PR61 Compose restart preview note

- Use `shellforgeai compose restart-preview <target>` to inspect Compose service blast radius and command shape.
- Use `shellforgeai compose propose-restart <target>` to create an auditable pending Compose restart proposal (proposal-only).
- Review with `shellforgeai approvals show <id>` and `shellforgeai approvals validate <id>`.
- Approval does not make Compose execution available yet; PR62 has no Compose execution lane.
- Preview is read-only and does not execute Docker Compose.
- Use exact IDs or PR59-style ask references (`this/latest/current proposal/mission`) when previewing from artifacts.
- Do not treat preview as approval or execution readiness.

## Compose restart mission preflight guidance

- If Compose restart mission preflight is blocked, fix the runtime/harness environment (Docker CLI/plugin/socket/project wiring) instead of bypassing ShellForgeAI gates.
- Use `shellforgeai mission compose-restart checklist <mission-id>` or `status` to read the exact preflight blocker.
- Do not treat host-side manual compose commands as an in-product workaround; those are outside ShellForgeAI policy scope.
- In Docker01-style containerized runs, preflight can block when the container does not expose a working `docker compose` plugin path.


### Compose restart with recovery-preview gate (PR65)
1. `shellforgeai compose propose-restart <target>`
2. `shellforgeai approvals approve <proposal-id> --reason "..."`
3. `shellforgeai rollback preview <proposal-id>`
4. `shellforgeai rollback validate <proposal-id-or-preview-path>`
5. `shellforgeai mission compose-restart checklist <mission-id>` / `validate`
6. Continue only when all gates pass; recovery remains manual/operator-led.

> Compose recovery is not magic rollback: it depends on known-good image/config state, source control, and backups.

## Compose execution environment readiness workflow (PR66)

- Run `shellforgeai compose env-check` to confirm runtime-level prerequisites before expecting Compose restart mission readiness.
- Run `shellforgeai compose env-check --target <target>` to see target-specific blockers in one place.
- If `compose_file_snapshot_unavailable` appears, either deliberately expose a readable compose-file snapshot to the ShellForgeAI runtime or accept that execution remains blocked.
- If `docker_compose_cli_unavailable` appears, deliberately provide Compose CLI/plugin support in the runtime or accept blocked readiness.
- Never bypass ShellForgeAI gates with host-side workarounds and then claim ShellForgeAI executed the restart flow.

## PR67 disposable Compose harness lab workflow

The disposable Compose harness lets an operator exercise the Compose
service restart lane end-to-end against a throwaway target. The real
ShellForgeAI service is intentionally still blocked from this lane.

> Do not label production services disposable just to make tests pass.
> The disposable labels are for throwaway test stacks only.

Steps:

1. Bring the disposable stack up (outside ShellForgeAI):

   ```
   ./scripts/pr67_disposable_compose_harness.sh up
   ./scripts/pr67_disposable_compose_harness.sh status
   ```

2. Verify readiness with read-only ShellForgeAI diagnostics:

   ```
   shellforgeai compose env-check --target sfai-pr67-compose-web --json
   ```

   Expect `readiness.compose_restart_execution_ready=true`,
   `allowlist.target_allowlisted=true`, `allowlist.disposable=true`, and
   a populated `config_snapshot.compose_file_sha256`.

3. Read-only preview:

   ```
   shellforgeai compose restart-preview sfai-pr67-compose-web
   ```

4. Build the proposal:

   ```
   shellforgeai compose propose-restart sfai-pr67-compose-web \
       --reason "PR67 disposable harness test"
   ```

5. Approve and create the rollback recovery preview:

   ```
   shellforgeai approvals validate <proposal-id>
   shellforgeai approvals approve <proposal-id> \
       --reason "PR67 disposable harness test"
   shellforgeai rollback preview <proposal-id>
   shellforgeai rollback validate <rollback-preview>
   ```

6. Prepare and inspect the mission:

   ```
   shellforgeai mission compose-restart prepare <proposal-id>
   shellforgeai mission compose-restart checklist <mission-id>
   shellforgeai mission compose-restart validate <mission-id>
   ```

7. Execute only with explicit `--execute --confirm`, and only against
   the disposable target, and only with Hector's go-ahead:

   ```
   shellforgeai mission compose-restart execute <mission-id> \
       --execute --confirm
   ```

8. Tear the disposable stack down (outside ShellForgeAI):

   ```
   ./scripts/pr67_disposable_compose_harness.sh down
   ```

Reminders:

- PR67 never runs `--execute --confirm` automatically. The gated mission
  still requires both flags.
- PR67 does not introduce a generic Compose executor. The only argv
  shape on this lane remains `docker compose -f <compose_file>
  --project-directory <working_dir> restart <service>`.
- PR67 does not add `docker compose up/down/recreate` from ShellForgeAI.
- PR67 does not enable natural-language Compose mutation.

## PR68 optional live disposable Compose restart proof

PR68 adds an **optional** lab-only orchestrator script that makes it easy
to prove the existing PR63-PR67 gated Compose restart lane end-to-end
against the disposable PR67 harness target. It adds no new mutation
capability to the ShellForgeAI app.

The orchestrator lives at:

```
scripts/pr68_disposable_compose_restart_proof.sh
```

It is operator/NewTwo tooling only. It is not invoked by the
ShellForgeAI app. It does not bypass any ShellForgeAI gate. It never
auto-passes `--execute --confirm`.

### Environment prerequisites for a successful live proof

Before the gated mission `execute` step can succeed against the
disposable harness, all of the following must be true:

1. The disposable Compose stack is up (via the PR67 harness helper),
   labels `shellforgeai.disposable=true` and
   `shellforgeai.allow_restart=true` are present on the service.
2. ShellForgeAI resolves the target as Compose-managed
   (`shellforgeai compose inspect sfai-pr67-compose-web`).
3. The host compose file path recorded in Compose labels is **readable
   from inside the ShellForgeAI execution environment**. If you run
   ShellForgeAI in a container, this typically means deliberately bind
   mounting the compose file (read-only is fine) into the ShellForgeAI
   container at the same path the Compose labels record. Do not have
   ShellForgeAI mount host paths itself.
4. The Docker CLI + Compose plugin is available inside the ShellForgeAI
   execution environment. `docker compose version` must succeed and
   `docker compose -f <compose-file> --project-directory <working-dir>
   config --services` must list the disposable service. If you run
   ShellForgeAI in a container, this is a build-time concern for that
   container; this PR does not install packages at runtime.
5. `shellforgeai compose env-check --target sfai-pr67-compose-web --json`
   returns `readiness.compose_restart_execution_ready=true` with no
   blockers.
6. `shellforgeai rollback preview <proposal-id>` returns a recovery
   preview with `compose_file_sha256` populated and
   `shellforgeai rollback validate` accepts it.
7. `shellforgeai mission compose-restart validate <mission-id>` reports
   all gates true.
8. The operator (Hector) explicitly approves the live execute step.

If any of these is false, the gated mission `execute` step will refuse
and `docker_compose_executed=false`, `container_restarted=false` will
remain in the receipt. That is the intended behavior - do not work around
it.

### Operator workflow

1. Print the exact gated command sequence (no execution):

   ```
   ./scripts/pr68_disposable_compose_restart_proof.sh print-commands
   ```

2. Confirm local environment readiness (read-only, no mutation):

   ```
   ./scripts/pr68_disposable_compose_restart_proof.sh check-env
   ```

3. Bring up the disposable harness (external, not ShellForgeAI):

   ```
   ./scripts/pr67_disposable_compose_harness.sh up
   ./scripts/pr67_disposable_compose_harness.sh status
   ```

4. Run the read-only ShellForgeAI readiness checks:

   ```
   ./scripts/pr68_disposable_compose_restart_proof.sh run-readiness
   ```

5. Drive the gated lane manually through the ShellForgeAI CLI exactly as
   printed by `print-commands`. The orchestrator never passes
   `--execute --confirm` for you. Even with
   `--execute-approved-disposable-restart`, the orchestrator only
   verifies env-check readiness and then prints the manual steps; the
   operator runs `shellforgeai mission compose-restart execute
   <mission-id> --execute --confirm` directly.

6. Tear the disposable stack down:

   ```
   ./scripts/pr67_disposable_compose_harness.sh down
   ```

### Safety reminders

- Do **not** label production services disposable to make tests pass.
  The real `shellforgeai` service must remain blocked from this lane.
- The orchestrator refuses targets whose names look production-like.
- The orchestrator never runs `docker system prune`, never deletes
  arbitrary paths, never installs packages, never edits production
  compose files, and never invokes `docker compose up/down/recreate`
  against the production project.
- All actual gated execution still happens through
  `shellforgeai mission compose-restart execute <mission-id>
  --execute --confirm`. The orchestrator is an external lab helper;
  ShellForgeAI's gates are unchanged.

## PR69 operator contract checklist (compose disposable proof readiness)

1. Bring up disposable harness externally (do not relabel production).
2. Run `shellforgeai compose env-contract --target sfai-pr67-compose-web` (or `--json`).
3. Confirm `target.target_allowlisted=true` (disposable + allow_restart only).
4. Confirm `snapshot.compose_file_snapshot_available=true`.
5. Confirm `environment.docker_compose_cli_available=true` and `environment.required_invocation_supported=true`.
6. Only then consider PR68 optional disposable proof workflow.

**Warning:** Do not label production services as disposable just to satisfy the contract.

## PR73 environment readiness plan workflow (operator-enablement)

`shellforgeai compose env-plan --target <target>` is the read-only
enablement plan. It answers: *what must change outside ShellForgeAI for
the disposable Compose restart proof to become ready?* It never performs
the changes itself.

Operator workflow:

1. Bring up the PR67 disposable harness externally
   (`scripts/pr67_disposable_compose_harness.sh up`). Never relabel
   production services to satisfy gates.
2. Run `shellforgeai compose env-contract --target sfai-pr67-compose-web`
   to see the current contract state.
3. Run `shellforgeai compose env-plan --target sfai-pr67-compose-web`
   (or `--json`) to see each blocker mapped to an explicit
   operator-controlled remediation step. Every entry carries
   `shellforgeai_action="none"` and `automated=false`.
4. Apply the listed remediation **externally** (out of ShellForgeAI):
   for example, provide a compatible Docker CLI + Compose plugin inside
   the ShellForgeAI runtime; expose the disposable Compose file
   read-only at the path Compose recorded.
5. Re-run env-check / env-contract. Confirm
   `ready_for_optional_disposable_proof=true`.
6. Only then consider the PR68 optional disposable proof workflow,
   with explicit operator approval. The PR47 production allowlist
   remains unchanged: production `shellforgeai` must stay not
   allowlisted.

**Refused operations.** ShellForgeAI itself will not, in any path:

- install Docker Compose,
- mount host paths,
- edit compose files,
- label production services disposable,
- run `docker compose` (restart / up / down / recreate / config),
- create proposals, missions, rollback previews, apply, or cleanup
  artifacts from env-plan,
- execute natural-language mutation asks
  (`fix compose execution environment`, `install docker compose`,
  `mount the compose file`, `label shellforgeai disposable`,
  `restart compose service now`, `execute the proof`).


## Operator workflow for reducing metadata hygiene critical state

> Operator note (PR127): If `doctor` reports metadata hygiene `critical` (or
> `warning`) on a long-lived lab, this is ShellForgeAI-owned historical
> artifact accumulation — not an active runtime failure, and no cleanup has
> run. Run `shellforgeai audit cleanup review` first. Do not jump to
> `cleanup execute`.

1. `shellforgeai doctor`
2. `shellforgeai audit retention`
3. `shellforgeai audit cleanup plan --category exports --max-age-days 7 --keep-latest 5`
4. `shellforgeai audit cleanup archive <plan-id>`
5. `shellforgeai audit cleanup validate <cleanup-archive.tar.gz>`
6. `shellforgeai audit cleanup execute <plan-id> --confirm`
7. `shellforgeai doctor`

Do not manually delete random `/data` paths unless recovering from known corruption.
Do not run step 6 unless operator-approved; start with narrow categories (for example `exports`) and verify archive validation before execution.

## PR74 Docker01 housekeeping runbook (read-only review first)

When `doctor` reports metadata hygiene `critical`, do not jump to
broad deletion. The cleanup review pack lets Hector/NewTwo decide what
is worth cleaning before any plan is written.

1. `shellforgeai doctor` — confirm severity and read the suggested
   commands. No cleanup runs from doctor.
2. `shellforgeai audit retention` (optionally `--top 20` or `--json`) —
   see the size/severity by category.
3. `shellforgeai audit cleanup review` (or `--json` for tooling) —
   read-only decision aid. Reports the largest categories, marks each
   category as `cleanup_supported` or report-only, recommends `exports`
   as the safest narrow first lane when it has items, restates the
   PR71 deletion gates, and prints the next safe dry-run command.
   No plans/archives/receipts are created and no files are deleted.
4. Choose a narrow category (default: `exports`). Avoid broad
   `--include-artifacts` cleanup unless the artifacts category has been
   reviewed item-by-item.
5. `shellforgeai audit cleanup plan --category exports --max-age-days 7
   --keep-latest 5 --json` — still dry-run, still no deletion.
6. `shellforgeai audit cleanup archive <plan-id>` — writes the
   fingerprinted cleanup archive.
7. `shellforgeai audit cleanup validate <cleanup-archive.tar.gz>` —
   reject the run on any validation error.
8. `shellforgeai audit cleanup execute <plan-id> --confirm` — only run
   this if Hector approves and the previous gates have passed.
9. `shellforgeai audit cleanup validate <cleanup-receipt-or-dir>` —
   verify the receipt is well-formed and safety-clean.

Do not run broad cleanup blindly. Do not use natural-language asks to
delete (ask routing refuses and prints the explicit guarded CLI). Do
not touch `/data` paths outside ShellForgeAI's owned roots; the cleanup
lane enforces this and any path resolving outside is refused. PR74 adds
review-only reporting; it does not loosen the PR71 deletion gates.

## PR75 Docker01 cleanup prepare workflow

When PR74 review says `exports` is the safest first lane and the
operator wants a decision packet without writing five commands by hand,
use `audit cleanup prepare`:

1. `shellforgeai audit cleanup review` — confirm severity, safest first
   lane, and that gates are understood.
2. `shellforgeai audit cleanup prepare --category exports --max-age-days
   7 --keep-latest 5` — creates the plan, creates the matching archive,
   validates the archive, and prints the decision packet. No deletion.
3. Inspect the plan path and candidates list printed by `prepare`.
4. `shellforgeai audit cleanup validate <cleanup-archive.tar.gz>` —
   re-check the archive on its own if desired.
5. Stop here for Hector/operator approval. `prepare` will not execute,
   and the printed execute command is marked operator-approved only.
6. Only if explicitly approved:
   `shellforgeai audit cleanup execute <plan-id> --confirm`. PR71 gates
   (matching archive, matching plan fingerprint, validation, `--confirm`)
   still all apply.
7. `shellforgeai audit cleanup validate <cleanup-receipt-or-dir>` —
   verify the post-execute receipt is well-formed and safety-clean.

`prepare` never broadens cleanup beyond ShellForgeAI-owned metadata,
never accepts arbitrary paths, refuses unknown/path-traversal categories
before creating anything, and never invokes Docker/Compose/services or
the apply/mission paths.

## PR76 Docker01 cleanup final-decision sequence

PR76 adds an explicit readiness gate and a post-execute report between
`prepare` and the eventual `execute --confirm`. The full Docker01
sequence is:

1. `shellforgeai audit cleanup review` — confirm severity and the
   safest first lane.
2. `shellforgeai audit cleanup prepare --category exports
   --max-age-days 7 --keep-latest 5` — produce plan + archive.
3. `shellforgeai audit cleanup execute-readiness <plan-id>` — re-check
   the PR71 gates (plan kind/safety, matching archive, archive
   validation, plan fingerprint, allowed-root candidate paths). This is
   read-only and creates nothing.
4. Manual review of the plan candidate list and the archive
   manifest/fingerprint as printed by `execute-readiness`.
5. Only if Hector approves and `ready_for_execute_confirm=true`:
   `shellforgeai audit cleanup execute <plan-id> --confirm`. PR71
   archive/fingerprint/validation/confirm gates still all apply at
   execute time.
6. `shellforgeai audit cleanup report <cleanup-receipt-or-dir>` —
   summarize the execute receipt (deleted/failed/bytes/skipped, safety
   block, fingerprint cross-check). Also read-only.
7. `shellforgeai doctor` and `shellforgeai audit retention` to confirm
   post-execute posture.

`execute-readiness` and `report` never delete anything, never create
plans/archives/receipts, never touch Docker/Compose/services/packages/
firewall/network/system, and never accept natural-language cleanup
execution.

## PR77 last-mile cleanup execution checklist

PR77 is UX/safety polish around the final cleanup boundary — no new
mutation surface, no gate weakening. Use this checklist when running
real `/data` cleanup on Docker01 or any live host:

1. `audit cleanup review` (read-only).
2. `audit cleanup prepare --category <cat> ...` (creates plan + archive,
   stops before execute).
3. `audit cleanup execute-readiness <plan-id>` and **read the output**:
   - Confirm `read_only: true`,
     `deletion_performed: false`,
     `cleanup_executed: false`,
     `ready_for_execute_confirm: true`.
   - Confirm the `Validated gates` block: plan present, matching
     archive present, archive validation passed, plan fingerprint
     matched, explicit confirm still required.
   - If `Blockers:` appear, **stop**. Do not execute until they are
     resolved.
4. **Operator decision.** This is the only step where a human chooses
   to delete. Do not run `execute` just because readiness is `true`;
   readiness means gates are satisfied, not that deletion is
   approved.
5. `audit cleanup execute <plan-id> --confirm` (the only command that
   deletes). Without `--confirm` it refuses, prints
   `Nothing was deleted.`, and lists `matching archive`,
   `archive validation`, `matching plan fingerprint`,
   `explicit --confirm` as required.
6. `audit cleanup report <receipt>` and read the
   `Post-execute checks:` block.
7. `audit cleanup validate <receipt>` to re-check receipt safety
   flags.
8. `audit retention` and `shellforgeai doctor` to confirm the host is
   still healthy.

Reminder: ShellForgeAI is a Tier-3 triage tool. Cleanup remains
scoped to ShellForgeAI-owned metadata under `<data_dir>`. PR77 does
not change that scope, does not add arbitrary path deletion, does not
mutate Docker/Compose/services/packages/firewall/network/system, and
does not let natural-language `ask` flows execute cleanup.

## PR79 / PR80 safe operator command pass

After a deploy / image sync / restart, run the safe command coverage
harness to confirm the read-only command surface still works.

### Post-deploy smoke workflow

Recommended sequence (every step is read-only):

1. `shellforgeai self-test commands --profile quick` — fast, env-independent
   smoke. Reliably reports `ok` on a fresh container.
2. `shellforgeai self-test commands --profile standard --json` — broad
   coverage with a parseable payload. May report `warn` when optional
   artifacts (latest runbook, compose target) are not yet present —
   that is expected and is not a command failure.
3. `shellforgeai doctor` — final sanity check on the runtime.
4. `shellforgeai ops status` — operations status board.

For CI / strict pipelines that should not tolerate optional-artifact
warnings:

```
shellforgeai self-test commands --profile standard --fail-on-warn --json
```

`--fail-on-warn` exits non-zero on `warn` and adds `ci_status: "failed_on_warn"`
to the JSON payload. Warnings remain warnings — the flag does not convert
them into runtime failures.

### Profiles

- `quick` — cheap, env-independent. Best first gate after a deploy.
  Runs `version`, `doctor`, `model doctor`, `tools list`, `ops status`,
  and the ask-mutation refusal smoke. Avoids artifact-dependent checks.
- `standard` (default) — PR79 coverage: cleanup review / readiness /
  report negative paths, compose env-check / env-contract / env-plan,
  validate-runbook --latest, locally-routed ask smokes, and the
  ask-mutation refusal smoke.
- `full` — `standard` plus `audit list`, `audit timeline --latest --json`,
  and `compose list --json`. May warn more often when those artifacts
  are absent; still strictly read-only.

### Operator expectations

- `status: ok` — every check passed.
- `status: warn` — every check passed but at least one was warned or
  skipped because an optional artifact is missing (e.g. no runbook
  artifact on the host, compose target absent from the local Docker
  inventory, audit storage empty). Read the `(reason)` next to each
  `WARN` / `SKIP` line. Do not treat warnings as failures.
- `status: failed` — at least one check failed. Investigate the
  `(reason)` next to the `FAIL` line before continuing other work.

The harness is read-only across every profile. It does not execute
cleanup, apply, mission, docker compose restart, proposal/mission/archive/plan
creation, or natural-language mutation, and it never uses `shell=True`.
It is safe to run on Docker01 against production data.

### NewTwo Docker01 QA note

The runtime container image may lack developer tools (ruff, pytest,
mypy). Use a disposable dev-validation container alongside Docker01 for
`ruff format` / `ruff check` / `pytest -q` / `mypy src/shellforgeai tests`.
The self-test harness itself runs in the runtime image because it only
exercises ShellForgeAI's own CLI surface.

### When to use it

1. After image sync / container recreate on Docker01.
2. After approving and merging a new PR locally, before live QA.
3. As a quick smoke any time the operator wants an "everything still
   safe?" signal.

## PR81 / PR82 — 2AM triage ranking workflow (read-only)

When the page is "the server feels broken" or "what's on fire?" — not a
named container — start with the broad-first read-only ladder. None of
these steps mutate anything.

1. **Self-test, quick profile** to confirm the CLI is healthy:

       shellforgeai self-test commands --profile quick

   Expect `status: passed` or `status: warn` (PR79/PR80 semantics).

2. **Rank the Docker scene** with PR81 triage ranking:

       shellforgeai triage docker

   or strict JSON for capture:

       shellforgeai triage docker --json

   Read the ranked suspects in order. Severity / confidence / classes
   are deterministic; no LLM. Watch-list entries (e.g. high CPU but
   currently healthy) are listed below suspects on purpose — they are
   visible but do not outrank real failures.

3. **Ask broad triage questions in natural language (PR82)** — the
   `ask` command routes broad Docker / 2AM prompts to the same PR81
   deterministic engine instead of falling back on the model:

       shellforgeai ask "2AM triage"
       shellforgeai ask "what's on fire?"
       shellforgeai ask "rank all sfai-battle-lab suspects by severity"

   The answer is grounded in `triage_ranking.collect_scene` +
   `rank_scene`. It preserves the deterministic ranking, severity,
   confidence, and per-container evidence; it never invents suspects
   and never collapses one container's evidence onto another. Every
   suspect carries a read-only `Safe next` command (always
   `shellforgeai diagnose …`).

4. **Inspect the top suspect's evidence** using the safe next command
   the report printed — always a `shellforgeai diagnose …` invocation:

       shellforgeai diagnose docker --container <name> --json
       # or
       shellforgeai triage docker detail <name> --json

5. **Only then** decide whether to engage an existing gated workflow:
   restart proposal (PR50/PR58), restart mission (PR52/PR53), or the
   cleanup ladder (PR74–PR77). The triage ranking command does not
   create proposals, missions, plans, archives, or apply receipts.

Do **not** jump from "ranking" to "restart". The ranking is evidence
synthesis only. A restart still requires the explicit proposal /
mission / apply gates with their own approvals and rollback previews.
The PR82 ask route is identical in shape: it ranks suspects, but
refuses mutation phrasings ("restart the top suspect", "fix the
crashloop", "clean up disk pressure now", "stop noisy-errors", "apply
the top fix") and redirects to the explicit gated CLI.

The triage ranking command never starts, stops, restarts, removes, or
prunes containers, never runs docker compose mutation, never runs
`apply`, `cleanup execute`, `mission execute`, or any natural-language
execution path, and never uses `shell=True`. Mutation-style asks
("restart the top suspect", "fix the crashloop", "clean up disk now")
continue to refuse with the existing PR74–PR80 wording, plus the PR82
no-mutation wording on broad-triage prompts.

- PR83 drilldown step added after broad ranking: `shellforgeai triage docker detail <suspect>` (or `--rank <n>`) to inspect why/evidence before any gated remediation workflow.


## PR84 update — 2AM triage snapshot handoff

Recommended read-only workflow:
1. `shellforgeai self-test commands --profile quick`
2. `shellforgeai triage docker`
3. `shellforgeai triage docker snapshot`
4. `shellforgeai triage docker detail <suspect>`
5. targeted read-only diagnose (`diagnose docker --save-plan --with-runbook`)
6. only then decide whether to enter proposal/mission gates


## PR85 update — 2AM triage snapshot save/validate handoff

1. `shellforgeai self-test commands --profile quick`
2. `shellforgeai triage docker`
3. `shellforgeai triage docker snapshot --save --include-details`
4. `shellforgeai triage docker snapshot validate <snapshot-id>`
5. Hand off the saved snapshot path/id
6. Only then decide whether explicit proposal/mission gates are needed

## PR86 update — 2AM triage snapshot export/validate handoff

1. `shellforgeai self-test commands --profile quick`
2. `shellforgeai triage docker`
3. `shellforgeai triage docker snapshot --save --include-details`
4. `shellforgeai triage docker snapshot validate <snapshot-id>`
5. `shellforgeai triage docker snapshot export <snapshot-id>`
6. `shellforgeai triage docker snapshot export-validate <export-path>`
7. Hand off the export path
8. Only then decide whether explicit proposal/mission gates are needed



### PR89 governed disposable remediation proof workflow

### PR91 disposable remediation receipt validation and handoff

Governed workflow now includes:
1. `shellforgeai remediation plan ...`
2. `shellforgeai remediation validate <plan-id>`
3. `shellforgeai remediation execute <plan-id> --executor ... --execute --confirm`
4. `shellforgeai remediation receipt validate <receipt-id-or-path>`
5. `shellforgeai remediation report <receipt-id-or-path>`
6. handoff using report + next safe commands

1. triage
2. detail/snapshot/timeline if needed
3. `shellforgeai remediation plan --target sfai-noisy-errors --scenario sfai-noisy-errors`
4. `shellforgeai remediation validate <plan-id>`
5. `shellforgeai remediation execute <plan-id> --execute --confirm` only with explicit operator approval
6. `shellforgeai remediation status <receipt-id>`
7. verify production `shellforgeai` remained untouched


## PR90 operator flow (disposable executor modes)

Live QA note: proof mode is non-mutating; docker-disposable mode is exact-target-only, and successful verification requires exact-target pre/post evidence (for example changed `StartedAt`).

1. Run triage (read-only).
2. Create remediation plan.
3. Validate plan.
4. Optionally execute `--executor proof` (or default) to verify artifact flow without mutation.
5. Execute `--executor docker-disposable --execute --confirm` only for exact disposable+allowlisted target.
6. Check `remediation status <receipt-id>` and verify restart evidence.
7. Confirm production `shellforgeai` remained untouched.

## PR93 governed remediation rollback posture workflow
- `shellforgeai remediation plan`
- `shellforgeai remediation validate`
- `shellforgeai remediation preflight`
- explicit operator confirm + `remediation execute`
- `remediation receipt validate` / `remediation report`
- `remediation rollback-preflight`
- `remediation rollback-validate`
- `remediation rollback-execute --execute --confirm`
- `remediation rollback-status`

Rollback packet commands are decision support only (posture/preconditions/verification preview). They do not execute rollback.

9. remediation bundle --save
10. remediation bundle validate
11. remediation audit


## PR97 operator flow (read-only remediation eligibility map)

## PR99 post-deploy remediation-lane readiness workflow
1. `shellforgeai self-test commands --profile quick`
2. `shellforgeai remediation self-test --profile quick`
3. `shellforgeai remediation self-test --profile standard --json`
4. `shellforgeai remediation self-test --profile full` now validates non-mutating lifecycle readiness end-to-end in temp artifacts (including proof execute + receipt/report/bundle/audit) and still skips live docker-disposable execute by default.
5. Optional lab QA live disposable proof (off by default): `shellforgeai remediation self-test --profile full --include-live-disposable-execute --target <exact-disposable-target> --confirm-live-disposable --json`
6. Validate receipt/bundle/audit outputs.
7. Clean up the disposable target outside ShellForgeAI.
1. `shellforgeai triage docker`
2. `shellforgeai remediation eligibility`
3. `shellforgeai remediation eligibility --target <target> --explain`
4. `shellforgeai remediation plan --target <target> --scenario <scenario>` only if operator chooses
5. `shellforgeai remediation validate <plan-id>`
6. `shellforgeai remediation preflight <plan-id>`
7. explicit `shellforgeai remediation execute <plan-id> --execute --confirm` only with approval


2AM flow (read-only first):
1. `shellforgeai ask "it's 2am, what is on fire?"` (deterministic ask route), or `shellforgeai ops report`
2. `shellforgeai triage docker detail <target>`
3. `shellforgeai remediation eligibility --target <target> --explain`
4. Plan only if operator chooses (`shellforgeai remediation plan ...`).
5. Validate/preflight/execute only through the governed remediation lane.

## PR106 update — ask mutation refusal before model

2AM flow reminder:
- `shellforgeai ask` can request read-only ops summaries (for example: `shellforgeai ask "what is on fire in docker right now? ops report please"`).
- `shellforgeai ask` cannot execute mutation; obvious mutation asks are deterministically refused before model/Codex.
- For any disposable proof workflow, use explicit governed CLI gates (`plan -> validate -> preflight -> execute --confirm`).


## PR107 update — 2AM ops report handoff bundle
1. `shellforgeai ops report`
2. `shellforgeai ops report --save`
3. `shellforgeai ops report validate <id>`
4. `shellforgeai ops report history`
5. `shellforgeai ops report compare-latest`
6. `shellforgeai ops report compare <old> <new>` (explicit refs when needed)
5. `shellforgeai triage docker detail <changed-suspect>`
6. `shellforgeai remediation eligibility --target <target> --explain`
7. `shellforgeai ops report export <id>`
8. `shellforgeai ops report export-validate <path>`
6. Hand off the export bundle

## V1 operator lane (canonical)

Use this 2AM sequence first:

1. `shellforgeai doctor`
2. `shellforgeai remediation self-test --profile quick`
3. `shellforgeai ops report`
4. `shellforgeai ops report --save`
5. `shellforgeai ops report history --limit 5`
6. `shellforgeai ops report compare-latest`
7. `shellforgeai triage docker detail <target>`
8. `shellforgeai remediation eligibility --target <target> --explain`

Mutation remains gated/disposable only; do not treat this guide as production
remediation automation.

Interactive follow-up grounding example (session-local, read-only):

```text
ops report
the first one
is that scary?
restart it
```

`the first one` and `is that scary?` resolve to the latest top suspect when
unambiguous and suggest/read from safe triage detail. `restart it` is still
refused from natural language; no restart is performed, and ShellForgeAI
suggests read-only triage detail / remediation eligibility explanation instead.


- V1 post-deploy check: `shellforgeai v1 check --profile standard --json`
scripts/v1_validate.sh --full --packet
shellforgeai v1 packet history
shellforgeai v1 packet compare-latest
shellforgeai v1 packet export <packet>
shellforgeai v1 packet export-validate <export>

## V1 release readiness

1. `./scripts/v1_validate.sh --quick`
2. `./scripts/v1_validate.sh --full --packet`
3. `shellforgeai v1 packet history`
4. `shellforgeai v1 packet compare-latest`

- When reviewing V1 release readiness, check `docs/V1_COMMAND_SURFACE.md` and keep packet mode in the validation lane.


## PR validation lane policy (PR157)

Full `pytest` is no longer the default confidence blanket for every PR. Choose a
validation lane explicitly, state why, and reserve full validation for
execution/safety/packaging boundaries. Targeted validation is the default; full
validation is exceptional. Safety gates are never weakened to go faster.

Lanes (see [`docs/VALIDATION_LANES.md`](docs/VALIDATION_LANES.md) and
[`docs/VALIDATION_MATRIX.md`](docs/VALIDATION_MATRIX.md)):

- **Lane A (fast)** — docs / README / OPS / roadmap / wording / tests-only.
- **Lane B (targeted runtime)** — read-only ask routing, intent, dispatch,
  interactive UX, JSON/output shape, artifact read/validate/export, doctor,
  status/triage/propose/apply-preview/verify/handoff wording, recipe
  registry/preflight read-only logic.
- **Lane C (full)** — cleanup/remediation/rollback/restart/recipe/apply/mission
  execution, Docker/Compose behavior, safety-gate or refusal-core rewrites,
  broad command-router rewrites, `pyproject`/dependency/`Dockerfile`/packaging,
  and validation-infrastructure changes. Lane C runs the bounded full pytest
  runner: `python scripts/run_full_pytest.py`. The runner uses `pytest-xdist`
  when available, falls back to serial pytest when unavailable, streams pytest
  output during execution, and always includes slow-test duration reporting
  (`--durations=25`).

Pick the lane from the changed files with the read-only optimizer (it never
mutates, deploys, or runs Docker/Compose; it only plans unless you pass
`--execute`):

```bash
python scripts/validate_pr.py --changed-files <files...>
python scripts/validate_pr.py --base main --head HEAD --json
python scripts/validate_pr.py --changed-files docs/cli.md            # Lane A
python scripts/validate_pr.py --changed-files src/shellforgeai/core/ask_routing.py --pr 156  # Lane B
python scripts/validate_pr.py --changed-files src/shellforgeai/core/disposable_remediation.py # Lane C
python scripts/validate_pr.py --changed-files docs/cli.md --full-validation  # force Lane C
```


The guarded Docker01 PR lane helper (`scripts/sfai_docker01_pr_lane.py`) uses
the same Lane C runner command as the planner: `python scripts/run_full_pytest.py`.
When the validation container is new, stale, or suspect, first run the read-only
environment doctor and carry any warnings into the QA handoff:

```bash
python scripts/check_validation_env.py --profile docker01
```

Use `--json` when the preflight should be attached as machine evidence, and use
`--strict` only when missing recommended acceleration such as `pytest-xdist`
should block Docker01 validation. Do not auto-install, delete caches, chmod,
chown, or fix Docker/Compose during PR validation unless a human operator
explicitly chooses a separate setup action outside the doctor. The doctor never
contacts the Docker daemon by default.

The lane helper prints the selected lane, the full-validation reason, the runner
command, duration reporting (`--durations=25`), live pytest progress/output,
elapsed runtime, and the runner output showing whether xdist was available/used
or whether serial fallback occurred. Lane C can also parse the full pytest log
with `scripts/track_pytest_durations.py` (or the helper's `--duration-log`) so
the manifest includes a warning-only duration report with the slowest tests and
any regressions against an explicit local history/baseline. Lane C remains
exceptional and explicit; Lane A/B runs do not invoke the full runner by
default.

Docker01 may optionally use a reusable ShellForgeAI validation image, for
example `shellforgeai-test-runner`, with Python 3.12, `git`, `rsync`,
procps/`ps`, `pytest`, `pytest-xdist`, `ruff`, and the project dev extras
preinstalled to reduce setup cost and enable parallel full validation. This is
operator convenience only, not a normal-user requirement and not a
test-selection input. Always run the same selected validation commands, always
report xdist use/unavailability or serial fallback, and never use the image to
skip tests or weaken Lane C safety gates.

Every Docker01 PR report now has two durable evidence artifacts from
`scripts/sfai_docker01_pr_lane.py`: a structured JSON manifest
(`mode=docker01_pr_validation_manifest`, `schema_version=1`) and a bounded
human summary. Architect/safety review should prefer the manifest values for
lane selection, lane reason, validation status, safety flags, command/phase
durations, slow-test duration records when supplied, log paths, final container
health, final disk state when available, known non-blockers, and the final
verdict. The human summary is the copy/paste-friendly companion for PR
comments, not the source of truth.

If full validation or QA already completed in a separate operator log, do not rerun expensive validation solely to populate `not_run` manifest fields. Finalize/import the completed evidence instead:

```bash
python scripts/finalize_validation_manifest.py /tmp/sfai-pr162-manifest.json \
  --validation-log /tmp/sfai-pr162-validation.log \
  --qa-log /tmp/sfai-pr162-qa.log \
  --status passed \
  --verdict pass \
  --summary-output /tmp/sfai-pr162-finalized-summary.txt
```

The finalizer reads the existing manifest, parses conservative pass/fail signals from supplied logs, writes `<manifest>.finalized.json` by default, and records `evidence_source=imported_log`, `imported=true`, and `executed_by_helper=false` on imported command statuses. It treats explicit zero-failure summaries such as `failed: 0`, `failed=0`, and `0 failed` as pass-safe evidence instead of conflicts, while real or ambiguous failures remain conservative warnings. Repeated non-blocker notes are trimmed and de-duplicated in first-seen order. Use `--in-place` only when you intentionally want to update the original manifest. Imported evidence is different from helper-executed evidence: the finalizer does not run pytest, Docker, Compose, cleanup, remediation, rollback, deploy, restart, or any arbitrary command. Ambiguous or conflicting logs are recorded as warnings and must not be treated as an automatic pass without an explicit operator `--status` / `--verdict` override.

### Validation heartbeat and interrupted/incomplete runs (PR176)

Long Docker01/full-validation runs can be SIGTERM/SIGINT/timeout-interrupted (or
SIGKILLed) before the helper records full `pytest` completion — exactly what
happened on PR175, whose first full-validation helper run was SIGKILLed near the
end and could not be counted as a pass. When executing validation, the lane
helper now writes a heartbeat/checkpoint/status JSON
(`scripts/validation_heartbeat.py`) updated before and after each phase, and the
manifest/summary carry an explicit run classification:

```bash
python scripts/sfai_docker01_pr_lane.py --changed-files Dockerfile --pr 176 \
  --full-validation --full-validation-reason "validation helper changed" \
  --execute-validation \
  --manifest-output /tmp/sfai-pr176-manifest.json \
  --summary-output  /tmp/sfai-pr176-summary.txt \
  --heartbeat-file  /tmp/sfai-pr176-heartbeat.json \
  --checkpoint-file /tmp/sfai-pr176-checkpoints.json \
  --status-file     /tmp/sfai-pr176-status.json
```

When `--heartbeat-file` / `--checkpoint-file` / `--status-file` are omitted, the
helper writes default heartbeat/checkpoint/status artifacts next to the manifest.
The Lane C runner accepts the same `--heartbeat-file` / `--status-file` /
`--checkpoint-file` for a single-phase `full_pytest` heartbeat.

Interpret the manifest/summary classification as follows:

- **passed** (`pass_eligible=true`, `rerun_required=false`) — every required phase
  passed **and** a full-`pytest` exit code of `0` was captured. Only this counts
  as merge evidence.
- **failed** — `test_failure` (a test phase failed or full `pytest` exited
  nonzero) or `setup_failure` (a pre-test `ruff`/`compileall` phase failed, or the
  helper could not set up before tests). `pass_eligible=false`.
- **incomplete** (`interrupted_or_incomplete`, `pass_eligible=false`,
  `rerun_required=true`) — the run ended before full-`pytest` completion was
  recorded. The summary prints `Validation result: INCOMPLETE`, a
  `*** RERUN REQUIRED ***` banner, and the last active/last-completed phase.

`status=passed` is recorded **only** when full `pytest` exit `0` is captured;
`full_pytest_result` stays `unknown` if no exit code was captured and is never
reported as `passed` on an interrupted run. SIGKILL cannot be caught, so no
finalizing heartbeat is written on `kill -9`; the last heartbeat still shows the
active phase as `running` (never `passed`), which classifies as incomplete.

Merge rule: **an incomplete validation run is not merge evidence.** Do not merge
on an interrupted/SIGKILLed run — require a clean rerun that reports
`Validation result: PASSED` / `Pass eligible: yes`. If a clean rerun later passes,
that run's manifest reports the clean run as the pass. The helper runs full
`pytest` once per invocation and never auto-reruns it; it writes evidence JSON
only and performs no Docker/Compose/service/container mutation, cleanup,
remediation, rollback, recovery, restart, `shell=True`, or model call.

Every Docker01 PR report should record through the manifest/summary:

- the **selected lane** (A / B / C) and **why**,
- the **commands run** and their durations/log paths,
- the validation phases completed and the failed phase/error summary on hold or
  failure,
- whether **full `pytest`** was required,
- for Lane C, the `python scripts/run_full_pytest.py` command output, including
  live pytest progress and the slow-test duration table,
- when available, a `duration_report` parsed from the full pytest log with the
  slowest tests, total runtime, local-history comparison, and warning-only
  regressions for follow-up optimization work,
- whether the runner used xdist or printed the serial fallback warning,
- final container status/health/restart count when available,
- snapshot/compose backup/final config/image metadata when available,
- explicit safety flags showing no cleanup/remediation/rollback execution, no
  prune, no direct compose write, no production restart, no `shell=True`, no
  arbitrary command execution, and no natural-language mutation,
- if full `pytest` was **skipped**, why that is acceptable (e.g. "Lane B
  read-only routing change; targeted regression group green; no safety or
  execution boundary touched").

Rules of the road:

- Full validation is **required** for execution/safety boundary PRs and stays
  **always available** (`--profile full` / `--full-validation`); it is never
  removed.
- Review `--durations=25` output and the optional `duration_report` / local
  history from `scripts/track_pytest_durations.py` for future slow-test
  follow-up. Duration regressions are warnings for operator review, not
  automatic validation failures, and no tests are skipped. Optimize
  repeated expensive setup when coverage remains equivalent; do not skip slow
  tests silently.
- Targeted validation is **acceptable** for docs / routing / output polish.
- Safety/execution keywords in changed **code** content (`shell=True`,
  `docker compose`, `os.system`, `*_executed`, `rm -rf`, …) escalate to full;
  documentation that merely describes those keywords does not.
- Live smoke on Docker01 should match the changed behavior.
- Deploy/snapshot/compose railings are **unchanged**: snapshot before mutation,
  atomic/temp compose config update, cached build default, no direct compose
  write, no destructive cleanup, no volume prune, and no
  remediation/rollback/cleanup execution outside an explicit, scoped PR. The
  lane optimizer touches none of these — it is planning-only.


### Validation evidence status viewer (PR177)

After a long Docker01/full-validation run, use the read-only viewer to inspect
the PR176 heartbeat/status/manifest evidence without rerunning anything:

```bash
# Most relevant recent run under the known validation artifact roots:
python scripts/validation_status.py --latest
python scripts/validation_status.py --latest --json

# Latest-artifact discovery filters / explanation (PR181):
python scripts/validation_status.py --latest --pr 181
python scripts/validation_status.py --latest --commit 0b407fa
python scripts/validation_status.py --latest --pr 181 --commit 0b407fa
python scripts/validation_status.py --latest --include-legacy
python scripts/validation_status.py --latest --run-root /srv/data/shellforgeai/validation-runs
python scripts/validation_status.py --latest --explain-selection
python scripts/validation_status.py --latest --json --explain-selection

# A specific run directory or explicit evidence files:
python scripts/validation_status.py --run-dir /srv/data/shellforgeai/validation-runs/<run>
python scripts/validation_status.py --run-dir <run_dir> --json
python scripts/validation_status.py --heartbeat <path> --json
python scripts/validation_status.py --status-file <path> --json
python scripts/validation_status.py --manifest <path> --json
```

`--latest` selects the most relevant artifact deterministically: it prefers
recent PR-specific run directories (`/tmp/sfai-pr<PR>-<sha>-validation-*`) over
older persisted `/srv/data/.../validation-runs` manifests, breaking ties by
newest timestamp, and explains the choice (`selection`/`source.selected_by`,
plus the selected/skipped candidate list under `--explain-selection`). `--pr`/
`--commit` filter candidates (an unmatched filter returns a controlled
`not_found` — no traceback); `--include-legacy` opts into older `/data/...`
artifacts; `--run-root` scans only one bounded root (broad roots and `..`
traversal are rejected). Selecting a different artifact never changes pass/fail
semantics; to force a specific run, pass `--run-dir <path>` (discovery is then
skipped).

The viewer classifies a run and answers the merge question directly:

- **passed** (`pass_eligible=true`, `rerun_required=false`) — every required
  phase passed and a full-`pytest` exit `0` / passed result was recorded. Only
  this is merge evidence.
- **failed** (`test_failure` or `setup_failure`, `pass_eligible=false`) — a phase
  failed; it reports the failed phase.
- **incomplete** (`interrupted_or_incomplete`, `pass_eligible=false`,
  `rerun_required=true`) — the run ended before full-`pytest` completion was
  recorded. It shows the active and last-completed phase and the last heartbeat
  update.
- **unknown** (`no_evidence`, `pass_eligible=false`, `rerun_required=true`) — no
  heartbeat/status/manifest evidence was found.

`pass_eligible` means the run is usable as merge evidence; `rerun_required` means
a clean rerun is needed before merge. If evidence sources disagree (for example
a manifest says passed but a heartbeat says incomplete), the viewer prefers the
conservative result, emits a warning, and never reports `pass_eligible=true`.

**Merge rule: an incomplete or unknown validation run is not merge evidence.**
The viewer is read-only — it reads ShellForgeAI validation evidence and renders
human/JSON status only. It never executes validation, never runs `pytest`, never
calls Docker/Compose, never restarts/mutates anything, never runs
cleanup/remediation/rollback/recovery, never uses `shell=True`, and never calls a
model.

### Validation environment preflight (PR178)

Before starting a host validation run, check that the environment actually has
the dev tools the ruff/compileall/pytest phases need:

```bash
python scripts/validation_env_preflight.py
python scripts/validation_env_preflight.py --json
python scripts/sfai_docker01_pr_lane.py --preflight-only
```

The Docker01 PR lane helper runs the same preflight automatically as an
`environment_preflight` phase when `--execute-validation` is used:

- **passed** — validation continues; the preflight result is recorded in the
  heartbeat/manifest and written as `validation-preflight.json` next to the
  manifest.
- **passed_with_warnings** (e.g. missing `pytest-xdist`) — validation continues;
  warnings are preserved as non-blockers in the final evidence.
- **failed** — the helper stops **before** any ruff/compileall/pytest phase and
  writes setup-failure evidence: `status=failed`,
  `classification=setup_failure`, `failed_phase=environment_preflight`,
  `pass_eligible=false`, `rerun_required=true`.

**A failed preflight is validation environment setup failure, not evidence that
product tests failed — and it is never merge evidence.** Rerun validation in the
disposable validation container path, or prepare the host dev environment
outside ShellForgeAI, then rerun. The preflight never installs packages, never
modifies venvs or host Python, never runs `pytest` or `ruff check`, never runs a
subprocess, and never calls Docker/Compose — the container path is a
recommendation in text only.

Inspect a preflight setup failure afterwards with the read-only viewer:

```bash
python scripts/validation_status.py --run-dir <run_dir> --json
```

It reports `classification=setup_failure` / `failed_phase=environment_preflight`
with `pass_eligible=false` / `rerun_required=true`, and its first safe command
points back at the preflight.

### Validation container fallback packet (PR179)

After a preflight `setup_failure`, generate a disposable validation-container
fallback packet from the run's evidence (the Docker01 PR lane helper also does
this automatically when its `environment_preflight` phase fails):

```bash
python scripts/validation_container_fallback.py --run-dir <validation_run_dir>
python scripts/validation_container_fallback.py --run-dir <validation_run_dir> --json
python scripts/validation_container_fallback.py --run-dir <validation_run_dir> --lane full --pr <n> --commit <sha>
```

It writes `validation-container-fallback.json` / `.md`,
`validation-container-command.txt`, and `validation-container-command.argv.json`
into the run directory. The packet explains why host validation stopped (setup
failure, **not** product test failure), lists the missing dev tools, and gives
an exact operator-run command that runs validation in a disposable container
(`--rm`, read-only repo mount, dev dependencies installed inside the container
only — the host package set is never changed). Inspect the command first:

```bash
cat <validation_run_dir>/validation-container-command.txt
```

The generator is packet-only: it never runs Docker/Compose, never restarts
containers, never runs `pytest`/`ruff`, never installs host packages, and never
executes the generated command — the operator must run container validation
explicitly if they choose to. Clean/passed runs return `not_needed` (no files
written; `--force` overrides), a missing run dir returns `not_found`, and
malformed evidence fails with a controlled warning. The PR177 viewer reports
`fallback_packet_present` / `fallback_packet_path` and adds the packet command
to `safe_next_commands` for setup failures. A setup-failure run — with or
without a packet — is not merge evidence until a clean validation rerun passes.


## V1 release handoff (PR120)

ShellForgeAI V1 handoff packet is finalized for operator/admin sign-off.

- Primary release notes: [`docs/V1_RELEASE_NOTES.md`](docs/V1_RELEASE_NOTES.md)
- Release-candidate evidence checklist: [`docs/V1_RELEASE_CANDIDATE.md`](docs/V1_RELEASE_CANDIDATE.md)
- Changelog release entry: [`CHANGELOG.md`](CHANGELOG.md)

Handoff emphasis:

- Deterministic ask routing and deterministic mutation refusal are core V1 safety behavior.
- Ops report artifact lifecycle (`save/validate/export/export-validate/history/compare-latest`) is core operator workflow.
- `v1_validate` packet/export helpers are for the dev-validation lane, not minimal runtime image.
- Normal V1 validation path remains read-only and non-mutating.

## Safe governed recipe preflight workflow

Use this read-only sequence before any future governed execution lane exists:

```bash
shellforgeai recipes list
shellforgeai recipes eligibility --recipe docker.disposable_restart --target <target> --json
shellforgeai recipes preflight --recipe docker.disposable_restart --target <target> --save
shellforgeai recipes preflight validate <preflight_id>
```

The preflight packet may preview the bounded argv `docker restart <target>` for an eligible disposable allowlisted container, but it is preview-only: `execution_available=false`, `command_preview_only=true`, `command_executed=false`, and `container_restarted=false`. Production targets, broad targets (`all`, `*`), missing targets, unlabeled targets, and Docker Compose patterns remain blocked.

Do not treat a preflight packet as permission to execute. Future execution must require explicit confirmation, an execution receipt, post-verification, and rollback posture handling.

## Docker01 lab-only disposable execution QA

For lab QA of the governed disposable restart lane, use only a throwaway container explicitly labeled for this recipe. Confirm the target is not `shellforgeai`, not broad, and not a Compose service pattern. Suggested manual flow:

```bash
docker run -d --name sfai-pr167-user-sim --label shellforgeai.disposable=true --label shellforgeai.allow_restart=true alpine sleep 3600
shellforgeai recipes preflight --recipe docker.disposable_restart --target sfai-pr167-user-sim --save
shellforgeai recipes preflight validate <preflight_id>
shellforgeai recipes execute <preflight_id> --confirm
shellforgeai recipes receipt validate <receipt_id>
shellforgeai verify --receipt <receipt_id>
shellforgeai recipes receipt rollback-preview <receipt_id>
shellforgeai handoff --json
docker rm -f sfai-pr167-user-sim
```

Expected: only the exact disposable allowlisted target restarts, a receipt is written and verifies, and `shellforgeai` is not restarted. Do not run Docker Compose restart/up/down, cleanup execute, rollback execute, production restart, or raw shell remediation as part of this QA.


## Governed receipt audit flow

For the disposable restart recipe, the audit-oriented operator flow is:

```bash
shellforgeai recipes preflight --recipe docker.disposable_restart --target <target> --save
shellforgeai recipes execute <preflight_id> --confirm
shellforgeai recipes receipt verify <receipt_id>
shellforgeai recipes receipt rollback-preview <receipt_id>
shellforgeai recipes receipt recovery-execute <receipt_id> --confirm
shellforgeai recipes receipt verify <recovery_receipt_id>
shellforgeai recipes receipt audit
shellforgeai recipes receipt audit --json
shellforgeai recipes receipt audit --target <target>
shellforgeai recipes receipt audit --recipe docker.disposable_restart
shellforgeai recipes receipt integrity
shellforgeai recipes receipt integrity --json
shellforgeai recipes receipt integrity --target <target>
shellforgeai recipes receipt integrity --recipe docker.disposable_restart
shellforgeai recipes receipt integrity --limit 50
shellforgeai recipes receipt integrity --include-exports
shellforgeai recipes receipt integrity --include-audit-bundles
shellforgeai recipes receipt history
shellforgeai recipes receipt inspect <receipt_id>
shellforgeai recipes receipt export <receipt_id>
shellforgeai recipes receipt compare <before_receipt_id> <after_receipt_id>
shellforgeai recipes receipt audit-bundle
shellforgeai recipes receipt audit-bundle --json
shellforgeai recipes receipt audit-bundle --target <target>
shellforgeai recipes receipt audit-bundle --recipe docker.disposable_restart
shellforgeai recipes receipt audit-bundle --limit 20
shellforgeai recipes receipt audit-bundle-validate <bundle_id>
shellforgeai recipes receipt audit-bundle-validate <bundle_id> --json
```

`recipes receipt integrity` is read-only. It scans owned receipt artifacts, plus existing receipt exports or audit bundles only when their include flags are passed, for required files, JSON parseability, manifest/checksum drift, recovery original linkage, unsupported shapes, unsafe safety flags, and production restart records. It reports findings without creating exports/bundles, repairing/deleting artifacts, executing recipes, rerunning receipts, recovering, rolling back, cleaning up, remediating, restarting containers, calling Docker/Compose, shelling out, or calling a model.

`recipes receipt audit` is read-only. It summarizes governed execution/recovery chains, links recovery receipts to original receipts, reports verification and safety flags, and flags malformed receipts, missing originals, unsupported recipes, production restart flags, Docker Compose flags, `shell_true`, arbitrary command execution, and natural-language execution. It does not execute recipes, rerun receipts, recover, rollback, clean up, remediate, restart containers, call Docker/Compose, call shell, or call a model.

The receipt audit commands are for history, inspection, portable metadata export, export validation, comparison, and governed audit-bundle handoff. `recipes receipt audit-bundle` writes a bounded ShellForgeAI-owned support packet under `<data_dir>/exports/receipt-audit-bundles/<audit_bundle_id>/` with `audit-bundle.json`, `audit-bundle.md`, `receipt-audit.json`, `receipt-history.json`, `manifest.json`, and `checksums.json`; optional local-only summaries include `receipt-compare-summary.json` and `receipt-export-index.json`. `recipes receipt audit-bundle-validate <bundle_ref>` resolves only owned bundle ids/paths, checks required files, parses JSON, verifies manifest consistency, and validates SHA256 checksums. Apart from explicit owned artifact/export writes, these commands are read-only and do not execute Docker/Compose, recovery, rollback, cleanup, remediation, shell commands, or model-driven actions. Audit bundles never execute or rerun receipts and are not recipe/recovery/rollback instructions. Support-handoff phrasing that clearly mentions receipts, receipt audit, or recipe receipts should use the receipt audit-bundle guidance rather than generic handoff.
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


## Docker01 hygiene report

Use the Docker01 hygiene report when an operator needs a read-only inventory of Docker01 disk, image, and ShellForgeAI artifact pressure before any cleanup is considered:

```bash
python scripts/docker01_hygiene_report.py
python scripts/docker01_hygiene_report.py --out /tmp/sfai-docker01-hygiene-report
python scripts/docker01_hygiene_report.py --dry-run
python scripts/docker01_hygiene_report.py --json
```

By default the helper writes `/tmp/sfai-docker01-hygiene-report-<timestamp>/` with `hygiene-summary.md`, `hygiene-report.json`, `candidate-cleanup-plan.md`, `commands-run.json`, and raw captures under `raw/`. It inventories root disk use, `shellforgeai` container state, Docker images, `lab/shellforgeai` PR/latest images, compose backups, validation evidence, QA bundles, support packets, and receipt/audit/handoff/release artifacts where discoverable.

The candidate cleanup plan is proposal-only. It does not delete files, prune Docker, remove images, restart containers, run Docker Compose mutation, or perform service changes. Any future cleanup must be reviewed and implemented in a separate narrow lane with explicit operator approval.

## Docker01 hygiene report validation

Docker01 hygiene reports can be validated before an operator reviews any future cleanup lane:

```bash
python scripts/docker01_hygiene_report.py --validate /tmp/sfai-docker01-hygiene-report --json
```

The validator reads an existing report directory only using bounded file reads sized for realistic Docker01 reports: report JSON is capped separately from Markdown and commands-run files, while raw captures remain more tightly bounded. It expects `hygiene-summary.md`, `hygiene-report.json`, `candidate-cleanup-plan.md`, `commands-run.json`, and bounded `raw/` captures when present. Oversized files fail safely with the file path, size, and cap used. It emits `mode=docker01_hygiene_report_validate` JSON with `status=passed|failed`, check counts, candidate counts, safety flags, and `first_safe_command="cat <report_dir>/hygiene-summary.md"`. Exit code is `0` only when all checks pass.

The validation lane proves that the PR209 report is ShellForgeAI-shaped, proposal-only, bounded, non-executable, and honest about safety flags. It rejects malformed JSON, missing required files, non-read-only safety fields, overlarge candidate sets, unsafe cleanup/delete/prune/restart/network/package/cloud/Codex command patterns, and commands-run entries outside the fixed PR209 read-only collector allowlist. Validation does not run Docker, rescan broad filesystem roots, regenerate reports, delete files, prune Docker, remove images, restart containers, run Docker Compose, call a model, call Codex, fetch from the network, install packages, or make cleanup safe to execute automatically. The reviewer/operator still decides any future named cleanup lane.
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

## Docker01 hygiene review bundle

When Docker01 hygiene pressure needs human review, create a bundle from an existing hygiene report instead of rerunning collectors:

```bash
python scripts/docker01_hygiene_report.py --review-bundle /tmp/sfai-docker01-hygiene-report --json
python scripts/docker01_hygiene_report.py --review-bundle-latest --root /tmp --json
```

The default bundle path is `/tmp/sfai-docker01-hygiene-review-bundle-<timestamp>/`. The bundle contains `hygiene-review-summary.md`, `hygiene-review.json`, `manifest.json`, `checksums.json`, source report/summary/plan copies, `validation-result.json`, `history-snapshot.json`, `compare-latest.json`, and `safety-notes.md`.

Bundle mode reads existing report files only. It does not run Docker, generate a report, delete source artifacts, clean up files, prune/remove images, mutate Docker Compose, restart containers, call a model, or authorize cleanup. `partial` or `not_available` history/compare statuses are review warnings, not cleanup approval.

## Docker01 storage health report

PR229 observed two non-PR operational signals on Docker01: the Docker build spent unusually long in a user/group/chown layer, and `dmesg` carried pre-existing EXT4 journal/inode warning/error-count messages on `dm-10`. These are host storage signals, not cleanup/remediation work, so they are tracked through a separate read-only evidence helper:

```bash
python scripts/docker01_storage_health_report.py --json
python scripts/docker01_storage_health_report.py
python scripts/docker01_storage_health_report.py --out /tmp/sfai-docker01-storage-health --json
```

The helper collects bounded, read-only evidence: filesystem usage, root filesystem capacity, mounted filesystems / device mapping, disk-pressure level, Docker data-path pressure indicators when safely readable, and bounded/sanitized recent kernel storage warning lines if accessible. It scores each kernel-log line against known EXT4, dm/device-mapper, and I/O/journal/inode patterns and reports the counts and an overall `status` (`ok|warning|partial|failed`). Use `--max-dmesg-lines` and `--max-warning-lines` to bound the kernel-log scan.

`status` is `ok` when there is no high disk pressure and no storage/kernel warning patterns, `warning` when disk pressure or relevant kernel warning patterns are found, `partial` when some evidence (for example `dmesg`/`journalctl`) is unavailable but core disk usage is collected, and `failed` only when core disk usage cannot be collected. The helper uses a fixed read-only command allowlist (`df -P -B1`, `findmnt --json`, `dmesg --level=err,warn --ctime`, `journalctl -k -p warning..alert --no-pager -n <bounded>`) plus `shutil.disk_usage` and `/proc/mounts`, always with `shell=False`. When `findmnt` is missing it falls back to `/proc/mounts`; when kernel-log access is denied it records the source as `not_available` and returns `partial`.

With `--out <dir>` it writes `storage-health-report.json`, `storage-health-summary.md`, `commands-run.json`, `manifest.json`, and `checksums.json`; manifest and checksums include SHA256 and sizes, `commands-run.json` records only the read-only commands attempted, and raw logs are not copied in full.

This report is evidence-only. It does not repair filesystems, run `fsck`/`e2fsck`/`xfs_repair`, mount/remount/umount, prune Docker, remove images/volumes/containers, delete files, restart containers, mutate Docker/Compose, or run remediation/rollback/recovery. There are no `--execute`/`--apply`/`--cleanup`/`--delete`/`--prune`/`--repair`/`--fsck`/`--restart`/`--fix` switches. If host storage warnings persist, investigate them outside ShellForgeAI mutation lanes. SeedOfEvil remains final merge owner.

## Docker01 QA bundle hygiene evidence

Docker01 operator QA bundles summarize existing hygiene evidence by default:

```bash
python scripts/docker01_operator_qa_bundle.py --pr 213 --commit <sha> --json
python scripts/docker01_operator_qa_bundle.py --pr 213 --commit <sha> --include-hygiene-review-bundle --json
```

Default mode runs only the existing hygiene history and compare-latest JSON readers against `/tmp`. The QA bundle records `hygiene.history_status`, `hygiene.compare_latest_status`, latest report metrics, notable changes, warnings, command provenance, and raw JSON captures. Review bundle creation is opt-in and records `hygiene.review_bundle_status` plus the bundle path when available.

This is review-only evidence. The QA bundle hygiene integration does not clean files, prune Docker, remove images, mutate Docker/Compose, restart containers, run arbitrary shell commands, call a model/Codex, call the network, or install packages. Missing hygiene evidence is a warning, not a core QA failure.

## Docker01 QA bundle model receipt evidence

Docker01 operator QA bundles also surface existing Model Doctor live-probe receipt evidence by default, so a reviewer can see whether model/auth readiness was recently verified by an explicit previous live probe — without the QA bundle itself calling the model:

```bash
python scripts/docker01_operator_qa_bundle.py --pr 229 --commit <sha> --json
python scripts/docker01_operator_qa_bundle.py --pr 229 --commit <sha> --skip-model-receipts --json
```

Default mode runs only the existing read-only `shellforgeai model receipt history --root /tmp --json` reader. The QA bundle records `model_receipts.status`, `history_status`, the latest receipt path and validation status, latest probe status, latest auth readiness, valid/invalid receipt counts, warnings, the operator's safe next command, and raw captures under `raw/model-receipt-history.json` and `raw/model-receipt-evidence.json`.

The QA bundle does **not** perform a live probe and does **not** call the model: the bundle's own `model_receipts.safety` block always reports `model_called=false` and `live_probe_performed=false`. A historical receipt may report `model_called=true` because an *earlier explicit* live probe (PR226) called the model; that is accepted as historical evidence. Empty or unavailable receipt history is reported as `empty`/`not_available` with a warning only — it does not fail the QA bundle. A secret marker or a historical safety drift in the receipt evidence is surfaced as a blocking safety failure. SeedOfEvil remains final merge owner.

## Docker01 PR-lane validation evidence

After a guarded Docker01 PR-lane validation run, inspect the generated packet:

```bash
cat /tmp/sfai-pr<PR>-<shortsha>-validation-<timestamp>/validation-summary.md
python scripts/validation_status.py --latest --pr <PR> --commit <sha> --json --explain-selection
```

The packet is evidence-only and includes status, manifest/checksums, command records, and a `logs/` directory. Non-pass statuses (`failed`, `setup_failure`, `interrupted`) are not merge evidence and require a rerun. The writer does not perform cleanup, Docker prune/image removal, file deletion, remediation, rollback/recovery, natural-language execution, `shell=True`, cloud apply/merge/push, or Docker/Compose mutation beyond the existing guarded deploy/recreate path.

## Docker01 interrupted PR-lane status

After an interrupted guarded Docker01 PR lane, inspect status before rerunning deploy, validation, or QA:

```bash
python scripts/sfai_docker01_pr_lane.py --pr <PR> --commit <sha> --status --json
python scripts/sfai_docker01_pr_lane.py --pr <PR> --commit <sha> --status
```

The helper is resume guidance only. It reads source/container/label/image status and existing validation/QA evidence, then suggests the safest next command. It does not deploy, build, write Compose, restart, run validation, run QA, clean up, prune, delete files, remediate, roll back, recover, or merge. `already_complete` means the expected evidence is present; the reviewer still gives the final merge verdict.

Status matching uses the configured Compose image tag and container `Config.Image`, not Docker's resolved image digest. If an earlier setup-failure packet and a later successful exact PR/commit validation packet both exist, the later pass-eligible validation evidence is used. Exact PR/commit operator QA bundles are discoverable before suggesting another QA run.

## Docker01 merge-readiness evidence report

Before merge review, produce a read-only Docker01 evidence packet for the exact PR and commit:

```bash
python scripts/docker01_merge_readiness.py --pr <PR> --commit <sha> --json
python scripts/docker01_merge_readiness.py --pr <PR> --commit <sha> --comment
python scripts/docker01_merge_readiness.py --pr <PR> --commit <sha> --out /tmp/sfai-pr<PR>-<short>-merge-readiness --comment
cat /tmp/sfai-pr<PR>-<short>-merge-readiness/merge-comment.md
```

The output directory contains `merge-readiness.json`, `merge-readiness-summary.md`, `manifest.json`, `checksums.json`, `raw-validation-status.json`, `raw-pr-lane-status.json`, and `raw-qa-bundle-summary.json`; with `--comment`, it also contains `merge-comment.md`. Missing raw evidence is recorded as `not_available`; huge logs and arbitrary filesystem listings are not copied.

The helper is evidence-only. `--comment` prints paste-ready Markdown only and does not post to GitHub, approve, merge, or replace reviewer judgment. It does not deploy, build, validate, run QA, restart, clean, prune, delete files, mutate Docker/Compose, remediate, roll back, recover, call models/Codex, install packages, call the network, merge, push, or use `shell=True`. `pass_candidate`, `hold_candidate`, and `unknown` are review aids rendered as `PASS / mergeable`, `HOLD / needs follow-up`, and `NEEDS EVIDENCE / cannot determine`, not approval. SeedOfEvil remains final merge owner.


## Docker01 validation evidence finalizer

After a Docker01 PR-lane validation attempt completes, the lane writes a
structured validation evidence packet automatically. Operators may also recover
from an already-completed log without rerunning validation:

```bash
python3 scripts/docker01_validation_evidence.py --pr <PR> --commit <sha> --log <validation-log-path> --status passed --json
python3 scripts/validation_status.py --latest --pr <PR> --commit <sha> --json --explain-selection
```

The packet lives in `/tmp/sfai-pr<PR>-<shortsha>-validation-<timestamp>/` unless
a run directory is supplied, and contains `validation-status.json`,
`validation-manifest.json`, `validation-summary.md`, `commands-run.json`, and a
bounded log excerpt. The finalizer records evidence only: it does not execute
validation or QA and does not perform cleanup, prune, delete, restart,
Docker/Compose mutation, remediation, rollback, recovery, GitHub actions, cloud
apply/merge/push, package installs, network calls, or model calls. For the same
PR/commit, latest pass-eligible evidence wins over earlier setup-failure or
interrupted evidence so host setup failures do not dominate a later successful
disposable validation fallback.

The guarded PR lane records automatic validation evidence against the requested
PR head commit (`--head-commit` or `--commit`) after terminal validation
outcomes. Lane C/full validation packets preserve `full_validation=true` and the
full-validation reason so read-only merge-readiness and comment rendering do not
misreport full pytest as absent.

Disposable validation fallback packets now bootstrap the disposable
`python:3.12-slim` environment with `procps` (providing `ps`), `git`, and
`rsync` inside the container before validation. This is not a Docker01 host
package install and does not modify the production ShellForgeAI container.

When operators run the generated disposable fallback command, it finalizes the
completed validation result back into the mounted lane evidence directory
(`/artifacts` inside the container). Do not run a separate manual finalizer after
a successful standard fallback; use the read-only `validation_status.py --latest
--pr <PR> --commit <sha> --json --explain-selection` check instead.

Normal PR-lane validation evidence is written below
`/tmp/shellforgeai-validation-runs/`, so the lane process owns the evidence
packet and `validation_status.py --latest` can discover it without a manual
`sudo` finalizer.

If `SFAI_VALIDATION_RUNS_DIR` points at a persisted validation location, the
viewer still also scans the built-in writable lane evidence root so standard
lane finalization remains discoverable without sudo.

If the host setup preflight failed but a later disposable fallback validation
completed in the same exact PR/commit/run directory, the terminal fallback
finalizer packet is the selected final attempt. A fallback pass reports
`passed`, `pass_eligible=true`, and `rerun_required=false`; the earlier
`setup_failure` remains in warnings/process notes for auditability. Without a
later exact fallback pass, failed/setup/interrupted evidence is not pass
eligible. `validation_status.py --explain-selection` shows when earlier setup
evidence was superseded; status, merge-readiness, and comment tools still do not
run validation or QA.


### Docker01 PR lane validation evidence self-check

After the guarded Docker01 PR lane writes/finalizes validation evidence, it now performs a read-only validation evidence self-check for the exact PR/commit through `validation_status.py --latest --pr <PR> --commit <sha> --json --explain-selection`. The lane writes `validation-evidence-check.json` and `validation-evidence-check.md` in the validation run directory and references the check from the lane manifest and summary.

The self-check proves whether exact PR/commit evidence was selected, whether it is pass-eligible, whether a rerun is required, whether full validation ran, and whether duplicate full pytest evidence was detected. If host setup fails but a later disposable fallback validation passes, the fallback pass can supersede the earlier setup failure while preserving the earlier setup failure as a warning/process note. If evidence is not discoverable after validation, the lane reports a validation evidence lifecycle failure/needs-followup rather than silently treating the run as merge-ready.

The self-check does not run validation, pytest, the operator QA bundle, cleanup, Docker prune, Docker image removal, Docker/Compose mutation, restarts, remediation, rollback, recovery, GitHub posting/approval/merge, model calls, or cloud apply/merge/push. Merge-readiness and merge-comment tools remain separate read-only post-QA checks. SeedOfEvil remains final merge owner.

### Docker01 V2 readiness evidence snapshot

`scripts/docker01_v2_readiness.py` creates a read-only evidence snapshot for an exact Docker01 PR/commit and classifies it as `v2_candidate`, `v2_not_ready`, or `v2_unknown`. It consumes existing PR-lane status, validation status, operator QA bundle, merge-readiness, and available hygiene evidence only; it does not deploy, build, run validation, run pytest, generate QA, clean/prune/delete, restart containers, mutate Docker/Compose, post to GitHub, call a model, or replace reviewer/operator judgment. SeedOfEvil remains final merge owner.

Examples:

```bash
python scripts/docker01_v2_readiness.py --pr <PR> --commit <sha> --json
python scripts/docker01_v2_readiness.py --pr <PR> --commit <sha>
python scripts/docker01_v2_readiness.py --pr <PR> --commit <sha> --out /tmp/sfai-pr<PR>-<short>-v2-readiness
```

When `--out` is supplied, the helper writes `v2-readiness.json`, `v2-readiness-summary.md`, `manifest.json`, `checksums.json`, and bounded raw evidence JSON files for validation status, PR-lane status, merge-readiness, and QA bundle summary. Missing evidence is recorded as `status=not_available`/`not_found` rather than crashing.

`v2_candidate` requires exact PR/commit evidence, matching source/Compose/container state, running healthy container with acceptable restart count, passed pass-eligible validation with no rerun required, passed operator QA and QA safety assertions, `pass_candidate` merge-readiness, and no mutation safety drift. Explicit failures become `v2_not_ready`; missing or incomplete evidence without an explicit failure becomes `v2_unknown`. Known metadata hygiene advisories, ignored stale/non-report hygiene candidates, and model-doctor `auth_readiness=unknown` warnings are non-blocking when the rest of the evidence is clean.

Missing exact validation or QA evidence is reported as incomplete `v2_unknown` evidence, not as a false validation/QA failure; explicit failed/setup/interrupted/rerun-required validation or failed QA remains `v2_not_ready`. The operator QA bundle's read-only Docker ask uses deterministic local triage wording and should not require Codex auth.
Successful targeted Docker01 validation lanes automatically finalize structured validation evidence in the validation-runs discovery root. The lane writes `validation-status.json`, `validation-manifest.json`, `validation-summary.md`, `commands-run.json`, `validation-evidence-check.json`, and `validation-evidence-check.md` for the exact PR/commit; `validation_status.py --latest --pr <PR> --commit <sha>` can discover it immediately with `lane=targeted`, `full_validation=false`, `pass_eligible=true`, and `rerun_required=false` when the targeted run passed. No manual finalizer normalization or duplicate pytest is required. If validation passed but the exact evidence cannot be rediscovered, the lane self-check fails clearly instead of leaving downstream tools to report `needs_validation`; full/fallback behavior remains unchanged, and read-only status/merge-readiness/V2 readiness tools still never execute validation or QA. Completed guarded lane logs that use the standard `sfai-pr<PR>-<short>-validation-<timestamp>.log` name are also treated as bounded read-only evidence by `validation_status.py --latest` so a completed full lane can converge without manual evidence normalization. Exact legacy Docker01 validation logs are pass-eligible only when trusted terminal markers are present (for example ruff and compileall passed plus full pytest 100%/exit 0 for full lanes); ambiguous, truncated, failed, setup-failure, or interrupted logs remain non-pass-eligible. Read-only status/readiness tools never run validation, pytest, QA, deploy, cleanup, or restart.

Nested Docker01 convergence QA bundle directories such as `/tmp/sfai-pr<PR>-<short>-convergence-<timestamp>/operator-qa/` are valid exact PR/commit QA evidence sources for PR-lane status, merge-readiness, and V2 readiness; stale PR/commit bundles are ignored.

`shellforgeai model doctor --json` is part of Docker01 live QA and emits strict read-only model readiness JSON; unavailable or unknown model auth is reported structurally instead of as a CLI option failure.

For exact PR/commit lane runs, a later successful disposable validation fallback supersedes earlier host setup_failure evidence in `validation_status.py --latest`; the setup failure remains in warnings/process notes, while failed or interrupted evidence without a later exact pass stays non-pass-eligible.
## Safe ask command suggestions

Model-backed `ask` may explain deterministic evidence and suggest a next operator command, but those suggestions are now validated through a static safe-command registry. Registry entries are real ShellForgeAI commands, marked `read_only=true` and `mutation=false`, and are suggestion-only: `ask` never executes them. Unknown `shellforgeai ...` suggestions and mutation-shaped commands such as cleanup, prune, image removal, Compose restart, shell pipes, redirects, or shell passthrough are removed or replaced with a registry command such as `shellforgeai triage docker --json`, `shellforgeai triage docker detail <suspect> --json`, or `shellforgeai ops report --json` when appropriate.

Natural-language requests still cannot execute commands. Future mutation recipes must remain named, narrow, auditable, and confirmation-gated outside model-backed ask.

### Model Doctor receipt history and compare

Existing Model Doctor live-probe receipts can be inspected without a new probe or model call:

```bash
shellforgeai model receipt history --root /tmp --json
shellforgeai model receipt compare /tmp/old-receipt /tmp/new-receipt --json
```

History scans only a bounded root for known Model Doctor receipt-shaped directories, validates each candidate with the same required-file, JSON, manifest, checksum, secret-marker, and safety checks used by receipt validation, and reports valid, invalid, and ignored candidates. Compare validates both receipt directories before reporting status, auth-readiness, latency, timeout, provider, and model drift. These commands are read-only: they do not run a live probe, call a model, call network/Codex, clean/prune/delete, repair/move artifacts, mutate Docker/Compose, restart containers, remediate, roll back, or recover. Default `shellforgeai model doctor` still performs no model call; explicit `--live-probe` remains opt-in and bounded. SeedOfEvil remains final merge owner.
## Docker01 artifact archive plan

`scripts/docker01_artifact_archive_plan.py` is the first governed mutation-runway step for ShellForgeAI-owned historical evidence artifacts. It starts with read-only planning/validation/readiness for bounded `/tmp/sfai-*` evidence artifacts, then exposes one named governed mutation lane for copy-only archive bundle creation. The bundle lane requires exact prior evidence, exact plan id, exact confirmation phrase, and an explicit output directory; cleanup and source deletion remain out of scope.

Examples:

```bash
python3 scripts/docker01_artifact_archive_plan.py --root /tmp --json
python3 scripts/docker01_artifact_archive_plan.py --root /tmp
python3 scripts/docker01_artifact_archive_plan.py --root /tmp --out /tmp/sfai-pr231-artifact-archive-plan
```

`--out` writes plan metadata files only (`artifact-archive-plan.json`, summary, candidate/excluded manifests, safety notes, manifest, checksums). It does not create an archive and does not copy, move, modify, or delete source candidates. Candidate scope is limited to known ShellForgeAI evidence artifact patterns such as QA bundles, validation artifacts, merge/v2 readiness artifacts, hygiene reports, model receipts, receipt validation, and storage-health reports. Docker volumes/images/containers, Compose/source/runtime paths, `/var/lib/docker`, `/srv/compose`, home directories, system logs, package caches, unmatched arbitrary files, and symlinks remain out of scope.

The same helper validates an existing plan directory with `--validate <plan_dir>` (read-only):

```bash
python3 scripts/docker01_artifact_archive_plan.py --validate /tmp/sfai-pr231-artifact-archive-plan --json
python3 scripts/docker01_artifact_archive_plan.py --validate /tmp/sfai-pr231-artifact-archive-plan
python3 scripts/docker01_artifact_archive_plan.py --validate /tmp/sfai-pr231-artifact-archive-plan --out /tmp/sfai-pr232-validation --json
```

Validation confirms the required plan files exist and parse, the manifest/checksums match the current plan output files (SHA256 + size), the `plan_id` is present and well-formed, `read_only=true`/`mutation_performed=false`/`execution_available=false`, the candidate manifest is bounded and limited to known ShellForgeAI evidence patterns (out-of-scope paths and symlink candidates are rejected and never followed), the `CONFIRM_SHELLFORGEAI_ARTIFACT_ARCHIVE` confirmation phrase is present, the future contract keeps execution unavailable and source deletion out of scope, and every safety mutation flag is false. Output is `status=passed|failed|partial` with a concise pasteable summary or strict JSON (`mode=docker01_artifact_archive_plan_validation`). `--out` writes validator artifacts only (`artifact-archive-plan-validation.json`, `artifact-archive-plan-validation-summary.md`, `manifest.json`, `checksums.json`); it does not modify the source plan directory. Validation does not create an archive, does not copy/move/delete sources, and does not authorize execution.

The helper can also emit a dry-run receipt for a validated plan. The receipt requires the exact plan id and first runs the same read-only validation checks; missing or mismatched `--plan-id` fails clearly and never reports `ready_for_review`.

```bash
python3 scripts/docker01_artifact_archive_plan.py --dry-run-receipt /tmp/sfai-pr231-artifact-archive-plan --plan-id sha256:<plan-id> --json
python3 scripts/docker01_artifact_archive_plan.py --dry-run-receipt /tmp/sfai-pr231-artifact-archive-plan --plan-id sha256:<plan-id>
python3 scripts/docker01_artifact_archive_plan.py --dry-run-receipt /tmp/sfai-pr231-artifact-archive-plan --plan-id sha256:<plan-id> --out /tmp/sfai-pr233-artifact-archive-dry-run --json
```

The dry-run receipt summarizes the future archive preview (candidate counts/classes/bytes and explicit exclusions), repeats the future confirmation phrase, and records receipt/manifest/checksum/rollback/source-preservation requirements. `--out` writes receipt metadata only (`artifact-archive-dry-run-receipt.json`, `artifact-archive-dry-run-summary.md`, candidate/excluded manifests, future checklist, safety notes, manifest, checksums). It never creates an archive, never copies/moves/modifies/deletes source artifacts, never touches the source plan directory, and never runs cleanup/prune/delete/restart/remediation/rollback/recovery, Docker/Compose mutation, validation, pytest, QA, network/model/Codex, GitHub, or cloud apply/merge/push behavior. `execution_available=false` remains explicit; future execution is a separate PR/lane only and would require the exact plan id plus `CONFIRM_SHELLFORGEAI_ARTIFACT_ARCHIVE`.

The helper can validate a PR233 dry-run receipt directory with `--validate-dry-run-receipt <receipt_dir>`. Standalone validation checks the receipt required files, JSON parseability, manifest, checksums, safety flags, candidate scope, and future execution contract while recording `plan_cross_check_status=not_requested`. Supplying `--plan-dir <plan_dir>` first validates the original PR231/PR232 plan and cross-checks plan id, candidate counts/classes/bytes, exclusions, confirmation phrase, and future execution contract consistency. `--out <dir>` writes validator artifacts only (`artifact-archive-dry-run-receipt-validation.json`, `artifact-archive-dry-run-receipt-validation-summary.md`, `manifest.json`, `checksums.json`).

```bash
python3 scripts/docker01_artifact_archive_plan.py --validate-dry-run-receipt /tmp/sfai-pr233-artifact-archive-dry-run --json
python3 scripts/docker01_artifact_archive_plan.py --validate-dry-run-receipt /tmp/sfai-pr233-artifact-archive-dry-run --plan-dir /tmp/sfai-pr231-artifact-archive-plan --json
python3 scripts/docker01_artifact_archive_plan.py --validate-dry-run-receipt /tmp/sfai-pr233-artifact-archive-dry-run --plan-dir /tmp/sfai-pr231-artifact-archive-plan --out /tmp/sfai-pr234-artifact-archive-dry-run-validation --json
```

Dry-run receipt validation is read-only and never creates an archive, copies/moves/modifies/deletes source artifacts, modifies the source receipt or plan directories, runs cleanup/prune/delete/restart/remediation/rollback/recovery, executes Docker/Compose mutation, invokes validation/pytest/QA from the helper, uses natural-language execution or `shell=True`, or authorizes future execution. `future_execution_available=false` remains explicit; future archive execution remains a separate PR/lane.

The helper also provides a final read-only execution-readiness gate that combines the validated plan, dry-run receipt, and optionally a prior receipt-validation directory. It validates the plan, validates (or reads) the dry-run receipt validation, then cross-checks the exact plan id, candidate paths/counts/classes/bytes, exclusions, confirmation phrase, future source-delete/source-move defaults, and safety contract. `ready_for_execution_review` means only that the evidence chain is internally consistent for human review of a future separate PR/lane; it does not authorize execution and `execution_available=false` remains explicit.

```bash
python3 scripts/docker01_artifact_archive_plan.py --execution-readiness /tmp/sfai-pr235-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr235-artifact-archive-dry-run --json
python3 scripts/docker01_artifact_archive_plan.py --execution-readiness /tmp/sfai-pr235-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr235-artifact-archive-dry-run
python3 scripts/docker01_artifact_archive_plan.py --execution-readiness /tmp/sfai-pr235-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr235-artifact-archive-dry-run --receipt-validation /tmp/sfai-pr235-artifact-archive-dry-run-validation --json
python3 scripts/docker01_artifact_archive_plan.py --execution-readiness /tmp/sfai-pr235-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr235-artifact-archive-dry-run --out /tmp/sfai-pr235-artifact-archive-readiness --json
```

With `--out`, readiness writes report artifacts only (`artifact-archive-execution-readiness.json`, `artifact-archive-execution-readiness-summary.md`, `future-execution-checklist.md`, `safety-notes.md`, `manifest.json`, `checksums.json`). It never creates an archive, never copies/moves/modifies/deletes source artifacts, never modifies the source plan or receipt directories, never runs cleanup/prune/delete/restart/remediation/rollback/recovery, never performs Docker/Compose mutation, never runs validation/pytest/QA from the helper, never uses natural-language execution or `shell=True`, and never performs network/model/Codex/package/GitHub/cloud actions. Future execution remains unavailable and would require a separate PR/lane with the exact plan id and `CONFIRM_SHELLFORGEAI_ARTIFACT_ARCHIVE`; SeedOfEvil remains final merge owner.


Any future cleanup or source-deletion lane would be separate and must require a new contract, review, exact confirmation, and fresh safety gates. Cleanup/deletion work must still never allow Docker prune, image/volume removal, container restart, Compose mutation, remediation, rollback, recovery, wildcard/arbitrary deletion, natural-language command execution, or `shell=True`. SeedOfEvil remains final merge owner.

The archive helper now has one controlled mutation lane: `--create-archive-bundle <plan_dir>`. It creates a directory bundle by copying only validated ShellForgeAI-owned evidence candidates into `payload/`; it requires the exact `--plan-id`, the exact `--confirm CONFIRM_SHELLFORGEAI_ARTIFACT_ARCHIVE` phrase, and an explicit `--archive-out <archive_bundle_dir>`. Before copying, it validates the plan, validates the dry-run receipt with plan cross-check, runs the execution-readiness checks in-process, verifies candidate scope/path safety, and refuses broad archive outputs such as `/`, `/tmp`, `/srv`, or `/data` and non-empty output directories.

```bash
python3 scripts/docker01_artifact_archive_plan.py --root /tmp --out /tmp/sfai-pr236-artifact-archive-plan
python3 scripts/docker01_artifact_archive_plan.py --validate /tmp/sfai-pr236-artifact-archive-plan --json
PLAN_ID=$(python3 -c 'import json; print(json.load(open("/tmp/sfai-pr236-artifact-archive-plan/artifact-archive-plan.json"))["plan_id"])')
python3 scripts/docker01_artifact_archive_plan.py --dry-run-receipt /tmp/sfai-pr236-artifact-archive-plan --plan-id "$PLAN_ID" --out /tmp/sfai-pr236-artifact-archive-dry-run --json
python3 scripts/docker01_artifact_archive_plan.py --execution-readiness /tmp/sfai-pr236-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr236-artifact-archive-dry-run --json
python3 scripts/docker01_artifact_archive_plan.py --create-archive-bundle /tmp/sfai-pr236-artifact-archive-plan --dry-run-receipt /tmp/sfai-pr236-artifact-archive-dry-run --plan-id "$PLAN_ID" --confirm CONFIRM_SHELLFORGEAI_ARTIFACT_ARCHIVE --archive-out /tmp/sfai-pr236-artifact-archive-bundle --json
```

The bundle writes `archive-receipt.json`, `archive-summary.md`, `archive-manifest.json`, `archive-checksums.json`, `source-candidate-manifest.json`, `source-exclusions.json`, `source-preservation.json`, `future-cleanup-notes.md`, `safety-notes.md`, and `payload/`. This lane is copy-only: it does not delete, move, or modify sources; does not clean/prune/restart/remediate/rollback/recover; does not mutate Docker/Compose; does not run validation/pytest/QA from the helper; and does not use natural-language execution or `shell=True`. Source deletion remains out of scope and would require a separate lane and confirmation.

