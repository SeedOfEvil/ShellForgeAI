# Validation Matrix (test impact map)

This is the human-readable view of the validation impact map. The machine
source of truth is
[`../scripts/validation_matrix.json`](../scripts/validation_matrix.json), which
is consumed by [`../scripts/validate_pr.py`](../scripts/validate_pr.py). Lane
definitions and policy live in [`VALIDATION_LANES.md`](VALIDATION_LANES.md).

When the JSON and this table disagree, **the JSON wins** — it is what the
optimizer actually uses. Keep them in sync when editing.

How matching works:

- Patterns are matched **first-match-wins, in order**, against each changed
  file path (`**` crosses directories; `*` stays within a path segment).
- A change's lane is the **highest** lane across all its files, plus any safety
  escalation.
- `src/**/*.py` that matches no rule falls back to **targeted_runtime with a
  warning**. Any other unrecognized path falls back to **full** as a safe
  default.

---

## Changed-file pattern → lane → tests

| Pattern | Lane | Recommended regression tests |
| --- | --- | --- |
| `docs/**` | fast | `test_pr110_v1_docs_contract`, `test_pr112_v1_demo_contract`, `test_pr114_v1_command_surface`, `test_pr119_v1_release_candidate_docs`, `test_pr143_command_surface_audit` |
| `README.md` | fast | `test_pr110_v1_docs_contract`, `test_pr114_v1_command_surface` |
| `OPS.md` | fast | `test_pr110_v1_docs_contract` |
| `CHANGELOG.md` | fast | `test_pr120_v1_release_notes` |
| `*.md`, `examples/**`, `LICENSE`, `.gitignore`, `.env.example` | fast | — (docs/contract) |
| `src/shellforgeai/core/ask_routing.py` | targeted_runtime | `test_pr105_*`, `test_pr106_*`, `test_pr42_ask_routing_hardening`, `test_pr131_*`, `test_pr134_*`, `test_pr135_*`, `test_pr156_*` |
| `src/shellforgeai/core/intent_nuance.py` | targeted_runtime | `test_pr131_*`, `test_pr134_*`, `test_pr135_*` |
| `src/shellforgeai/core/recipe_registry.py` | targeted_runtime | `test_pr154_v2_recipe_registry`, `test_pr155_v2_recipe_preflight`, `test_pr156_*` |
| `src/shellforgeai/core/recipe_preflight.py` | targeted_runtime | `test_pr155_v2_recipe_preflight`, `test_pr156_*`, `test_pr99_remediation_self_test` |
| `src/shellforgeai/core/*handoff*` | targeted_runtime | `test_pr150_*`, `test_pr152_*`, `test_pr153_*` |
| `src/shellforgeai/core/ops_report_artifact.py` | targeted_runtime | `test_pr104_*`, `test_pr107_*`, `test_pr108_*`, `test_pr109_*` |
| `src/shellforgeai/core/triage_ranking.py` | targeted_runtime | `test_pr81_*`, `test_pr82_*`, `test_pr83_*`, `test_pr146_*` |
| `src/shellforgeai/interactive/**` | targeted_runtime | `test_pr122_*`, `test_pr124_*`, `test_pr128_*`, `test_pr129_*`, `test_pr130_*`, `test_pr132_*`, `test_pr136_*` … `test_pr142_*` |
| `src/shellforgeai/cli.py` | targeted_runtime | `test_cli`, `test_pr114_*`, `test_pr143_*` (broad router rewrites → use `--profile full`) |
| `src/shellforgeai/render/**` | targeted_runtime | `test_pr126_*`, `test_pr22_json_stdout_validity` |
| `src/shellforgeai/core/*remediation*` | **full** | remediation suite (`test_pr89_*`, `test_pr91_*`–`test_pr99_*`) + full pytest |
| `src/shellforgeai/core/*rollback*` | **full** | `test_pr93_*`, `test_pr94_rollback_execute`, `test_pr65_*` + full pytest |
| `src/shellforgeai/core/*restart*` | **full** | restart/mission suite + full pytest |
| `src/shellforgeai/core/*mission*` | **full** | `test_pr52_*`, `test_pr53_mission_execute`, `test_pr54_*` + full pytest |
| `src/shellforgeai/core/*cleanup*` | **full** | cleanup suite (`test_pr55_*`, `test_pr74_*`–`test_pr77_*`) + full pytest |
| `src/shellforgeai/core/apply_bundle.py` | **full** | `test_pr33_apply_preflight`, `test_pr37_action_compiler` + full pytest |
| `src/shellforgeai/core/approvals.py` | **full** | `test_pr32_approvals`, `test_pr46_mutation_gate` + full pytest |
| `src/shellforgeai/core/guards.py` | **full** | `test_pr46_mutation_gate`, `test_pr42_ask_routing_hardening` + full pytest |
| `src/shellforgeai/core/disposable_*` | **full** | disposable harness + remediation suite + full pytest |
| `src/shellforgeai/core/compose_context.py` | **full** | compose suite + full pytest |
| `src/shellforgeai/policy/**` | **full** | `test_policy`, `test_pr46_mutation_gate` + full pytest |
| `src/shellforgeai/tools/**` | **full** | tool suites + full pytest |
| `src/shellforgeai/util/subprocess.py` | **full** | `test_investigation_tools` + full pytest |
| `Dockerfile`, `*.Dockerfile` | **full** | packaging/import + full pytest |
| `pyproject.toml` | **full** | `test_cli`, `test_config` + full pytest |
| `requirements*` | **full** | packaging/import + full pytest |
| `compose.yaml` / `compose.yml` / `docker-compose*` | **full** | `test_compose_runtime_hygiene` + full pytest |
| `Makefile` | **full** | build + full pytest |
| `config/**` | **full** | `test_config`, `test_profiles` + full pytest |
| `.github/**` | **full** | CI/workflow + full pytest |
| `scripts/v1_validate.sh` | **full** | `test_pr113_*`, `test_pr118_*` + full pytest |
| `scripts/validate_pr.py` | **full** | `test_pr157_validation_lane_optimizer` + full pytest |
| `scripts/validation_matrix.json` | **full** | `test_pr157_validation_lane_optimizer` + full pytest |
| `scripts/sfai_docker01_pr_lane.py` | **full** | validation-lane helper tests + full pytest |
| `scripts/**` (other) | **full** | + full pytest |
| `tests/conftest.py` | **full** | shared harness → full pytest |
| `tests/**` | fast | the changed test files are run directly |
| `src/**/*.py` (unmatched) | targeted_runtime | PR-specific tests + **warning** if none resolve |
| anything else (unmatched) | **full** | safe default |

---

## Safety-boundary triggers → full

When changed **non-documentation** content (a diff, provided content, or
`--scan-content`) contains any of these keywords, the change escalates to
**full** regardless of its path lane:

```
execute            confirm              cleanup_executed
remediation_executed  rollback_executed   docker_compose_executed
container_restarted   shell_true           subprocess
os.system          shell=True           docker restart
docker compose     rm -rf               chmod
chown              apply_executed       mission_created
plan_created
```

Documentation that merely *describes* these keywords does not escalate. This is
intentional: editing `docs/safety.md` to explain that ShellForgeAI never uses
`shell=True` stays in Lane A; adding `shell=True` to a `.py` file jumps to
Lane C.

A `--profile` override may escalate a lane but may never de-escalate below a
safety-required full lane.

---

## Examples

```bash
# docs-only → Lane A (fast), no full pytest
python scripts/validate_pr.py --changed-files docs/cli.md

# ask routing → Lane B (targeted), PR-specific + related tests, no full pytest
python scripts/validate_pr.py --changed-files src/shellforgeai/core/ask_routing.py --pr 156

# remediation execution → Lane C (full), includes pytest -q --durations=25
python scripts/validate_pr.py --changed-files src/shellforgeai/core/disposable_remediation.py

# Dockerfile / dependency → Lane C (full)
python scripts/validate_pr.py --changed-files Dockerfile

# validation infrastructure → Lane C (full)
python scripts/validate_pr.py --changed-files scripts/v1_validate.sh

# force full validation on any change
python scripts/validate_pr.py --changed-files docs/cli.md --full-validation
```
