#!/usr/bin/env bash
# PR68 optional live disposable Compose restart proof orchestrator.
#
# This is a LAB-ONLY operator helper that orchestrates the optional
# end-to-end proof of the existing PR63-PR67 gated Compose service
# restart lane against the disposable PR67 harness target.
#
# This script:
#   - operates ONLY on the disposable PR67 target
#       project=sfai_pr67_disposable
#       service=web
#       container=sfai-pr67-compose-web
#   - refuses to act if those names are not the disposable ones
#   - refuses if production-looking target names appear (shellforgeai)
#   - never passes --execute --confirm unless the explicit dangerous flag
#       --execute-approved-disposable-restart
#     is provided AND every gate reports ready
#   - never runs `docker system prune`
#   - never deletes arbitrary paths
#   - never edits production compose files
#   - never installs packages
#   - never mounts host paths from inside ShellForgeAI
#
# It is NOT a ShellForgeAI app mutation feature. All actual gated
# execution still happens through:
#   shellforgeai mission compose-restart execute <mid> --execute --confirm
#
# See OPS.md ("PR68 optional live disposable Compose restart proof")
# and docs/safety.md for context.

set -euo pipefail

EXPECTED_PROJECT="sfai_pr67_disposable"
EXPECTED_SERVICE="web"
EXPECTED_CONTAINER="sfai-pr67-compose-web"
DANGEROUS_FLAG="--execute-approved-disposable-restart"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/examples/compose/disposable-restart/docker-compose.yml"
HARNESS_SCRIPT="$REPO_ROOT/scripts/pr67_disposable_compose_harness.sh"

SHELLFORGEAI_BIN="${SHELLFORGEAI_BIN:-shellforgeai}"

usage() {
    cat <<EOF
Usage: $0 <subcommand> [options]

Subcommands:
  print-commands    Print the exact gated ShellForgeAI command sequence
                    (dry-run/print-only; never executes anything).
  check-env         Read-only environment readiness checks against the
                    disposable target (no mutation).
  dry-run           Same as print-commands; explicit no-op.
  run-readiness     Run env-check / restart-preview against the disposable
                    target (read-only ShellForgeAI commands only).
  run-proof         Orchestrate the proof. Refuses to execute the gated
                    mission unless $DANGEROUS_FLAG is passed AND every
                    gate reports ready AND target is exactly
                    $EXPECTED_CONTAINER.
  help              Show this help.

Target invariants (refused otherwise):
  project   = $EXPECTED_PROJECT
  service   = $EXPECTED_SERVICE
  container = $EXPECTED_CONTAINER

This script never bypasses ShellForgeAI gates. All gated execution still
runs through:
  shellforgeai mission compose-restart execute <mid> --execute --confirm

Production target names like 'shellforgeai' are explicitly refused.
EOF
}

guard_disposable_target() {
    # Hard-coded invariants. We refuse to operate on anything else.
    if [ "$EXPECTED_PROJECT" != "sfai_pr67_disposable" ]; then
        echo "Refusing: project '$EXPECTED_PROJECT' is not the disposable PR67 project." >&2
        exit 2
    fi
    if [ "$EXPECTED_SERVICE" != "web" ]; then
        echo "Refusing: service '$EXPECTED_SERVICE' is not the disposable PR67 service." >&2
        exit 2
    fi
    if [ "$EXPECTED_CONTAINER" != "sfai-pr67-compose-web" ]; then
        echo "Refusing: container '$EXPECTED_CONTAINER' is not the disposable PR67 container." >&2
        exit 2
    fi
    case "$EXPECTED_CONTAINER" in
        *shellforgeai*)
            echo "Refusing: production-looking target name '$EXPECTED_CONTAINER'." >&2
            exit 2
            ;;
    esac
    case "$EXPECTED_PROJECT" in
        shellforgeai|*production*|*prod*)
            echo "Refusing: production-looking project '$EXPECTED_PROJECT'." >&2
            exit 2
            ;;
    esac
    if [ ! -f "$COMPOSE_FILE" ]; then
        echo "Refusing: disposable compose file not found at $COMPOSE_FILE" >&2
        exit 2
    fi
    if ! grep -q "shellforgeai.disposable: \"true\"" "$COMPOSE_FILE"; then
        echo "Refusing: compose file is missing shellforgeai.disposable=true label." >&2
        exit 2
    fi
    if ! grep -q "shellforgeai.allow_restart: \"true\"" "$COMPOSE_FILE"; then
        echo "Refusing: compose file is missing shellforgeai.allow_restart=true label." >&2
        exit 2
    fi
}

cmd_print_commands() {
    cat <<EOF
PR68 optional live disposable Compose restart proof - manual command sequence.

This sequence is print-only. This script never auto-executes the gated
mission unless explicitly told to with $DANGEROUS_FLAG.

1) Bring up the disposable stack (external, outside ShellForgeAI):
   $HARNESS_SCRIPT up
   $HARNESS_SCRIPT status

2) Readiness checks (read-only ShellForgeAI commands):
   $SHELLFORGEAI_BIN compose env-check --target $EXPECTED_CONTAINER --json
   $SHELLFORGEAI_BIN compose restart-preview $EXPECTED_CONTAINER --json

3) Proposal + approvals:
   $SHELLFORGEAI_BIN compose propose-restart $EXPECTED_CONTAINER \\
       --reason "PR68 disposable proof" --json
   $SHELLFORGEAI_BIN approvals validate <proposal-id>
   $SHELLFORGEAI_BIN approvals approve <proposal-id> \\
       --reason "PR68 disposable proof"

4) Rollback recovery preview:
   $SHELLFORGEAI_BIN rollback preview <proposal-id>
   $SHELLFORGEAI_BIN rollback validate <rollback-preview>

5) Mission preparation:
   $SHELLFORGEAI_BIN mission compose-restart prepare <proposal-id>
   $SHELLFORGEAI_BIN mission compose-restart checklist <mission-id>
   $SHELLFORGEAI_BIN mission compose-restart validate <mission-id>

6) Gated execution (ONLY with Hector approval):
   $SHELLFORGEAI_BIN mission compose-restart execute <mission-id> \\
       --execute --confirm

7) Teardown (external):
   $HARNESS_SCRIPT down

Do not run --execute --confirm against the production 'shellforgeai'
target. Do not label production services disposable. The ShellForgeAI
app gates still enforce this regardless of this orchestrator.
EOF
}

cmd_check_env() {
    guard_disposable_target
    echo "PR68 readiness checks (read-only):"
    echo "- expected project   = $EXPECTED_PROJECT"
    echo "- expected service   = $EXPECTED_SERVICE"
    echo "- expected container = $EXPECTED_CONTAINER"
    echo "- compose file       = $COMPOSE_FILE"
    if command -v docker >/dev/null 2>&1; then
        echo "- docker CLI         = $(command -v docker)"
    else
        echo "- docker CLI         = MISSING (env-check will block)"
    fi
    if docker compose version >/dev/null 2>&1; then
        echo "- docker compose CLI = ok"
    else
        echo "- docker compose CLI = MISSING (env-check will block)"
    fi
    if [ -r "$COMPOSE_FILE" ]; then
        echo "- compose file read  = ok"
    else
        echo "- compose file read  = NOT READABLE"
    fi
    echo "Note: actual ShellForgeAI readiness must be confirmed via:"
    echo "  $SHELLFORGEAI_BIN compose env-check --target $EXPECTED_CONTAINER --json"
}

cmd_run_readiness() {
    guard_disposable_target
    echo "Running read-only ShellForgeAI readiness against $EXPECTED_CONTAINER ..."
    "$SHELLFORGEAI_BIN" compose env-check --target "$EXPECTED_CONTAINER" --json
    "$SHELLFORGEAI_BIN" compose restart-preview "$EXPECTED_CONTAINER" --json
}

# Helper: extract a key from JSON via python (avoid requiring jq).
_json_get() {
    local key="$1"
    python3 -c 'import json,sys; d=json.load(sys.stdin); k=sys.argv[1].split("."); v=d
for p in k: v=v.get(p) if isinstance(v,dict) else None
print("" if v is None else v)' "$key"
}

cmd_run_proof() {
    local dangerous="no"
    for arg in "$@"; do
        if [ "$arg" = "$DANGEROUS_FLAG" ]; then
            dangerous="yes"
        fi
    done

    guard_disposable_target

    if [ "$dangerous" != "yes" ]; then
        echo "Default mode: dry-run/readiness only."
        echo "Refusing to execute the gated mission without explicit flag:"
        echo "  $DANGEROUS_FLAG"
        echo
        cmd_print_commands
        return 0
    fi

    echo "Dangerous flag $DANGEROUS_FLAG is set."
    echo "Verifying ALL gates against disposable target $EXPECTED_CONTAINER ..."

    # env-check
    local envjson
    envjson="$("$SHELLFORGEAI_BIN" compose env-check --target "$EXPECTED_CONTAINER" --json)"
    local ready
    ready="$(printf '%s' "$envjson" | _json_get readiness.compose_restart_execution_ready)"
    local allow
    allow="$(printf '%s' "$envjson" | _json_get allowlist.target_allowlisted)"
    if [ "$ready" != "True" ] && [ "$ready" != "true" ]; then
        echo "Refusing: env-check readiness is not true." >&2
        exit 3
    fi
    if [ "$allow" != "True" ] && [ "$allow" != "true" ]; then
        echo "Refusing: target is not allowlisted." >&2
        exit 3
    fi

    echo "env-check ready. The remaining gated steps (proposal/approval/"
    echo "rollback/mission prepare/checklist/validate/execute) must be run"
    echo "by the operator through the ShellForgeAI CLI. This script does"
    echo "not bypass --execute --confirm; the operator runs that command"
    echo "directly. See OPS.md PR68 workflow."
}

main() {
    if [ "$#" -lt 1 ]; then
        usage
        exit 1
    fi
    local sub="$1"
    shift
    case "$sub" in
        print-commands|dry-run) cmd_print_commands ;;
        check-env) cmd_check_env ;;
        run-readiness) cmd_run_readiness ;;
        run-proof) cmd_run_proof "$@" ;;
        help|-h|--help) usage ;;
        *)
            echo "Unknown subcommand: $sub" >&2
            usage
            exit 1
            ;;
    esac
}

main "$@"
