#!/usr/bin/env bash
# PR67 disposable Compose harness lab helper.
#
# This script is a LAB / operator helper for creating and tearing down a
# throwaway Compose stack to exercise the ShellForgeAI Compose service
# restart lane against a disposable target. It is intentionally outside
# the ShellForgeAI gated execution path.
#
# This script:
#   - operates only on the disposable Compose project sfai_pr67_disposable
#   - refuses to act if the resolved project/service/container names do
#     not match the expected disposable names
#   - never runs `docker system prune` and never deletes arbitrary paths
#   - never runs ShellForgeAI execution automatically; it only prints the
#     exact manual ShellForgeAI commands the operator can run
#
# It is NOT a ShellForgeAI app mutation path. ShellForgeAI itself never
# invokes `docker compose up/down/recreate`. See docs/safety.md and
# examples/compose/disposable-restart/README.md for context.

set -euo pipefail

EXPECTED_PROJECT="sfai_pr67_disposable"
EXPECTED_SERVICE="web"
EXPECTED_CONTAINER="sfai-pr67-compose-web"
EXPECTED_SCOPE_LABEL="pr67"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/examples/compose/disposable-restart/docker-compose.yml"

usage() {
    cat <<EOF
Usage: $0 <subcommand>

Subcommands:
  up              Start the disposable Compose stack (docker compose up -d).
  down            Stop and remove the disposable Compose stack.
  status          Show docker compose ps for the disposable stack.
  print-env       Print expected project/service/container/labels and compose file path.
  print-commands  Print the manual ShellForgeAI commands an operator can run.
  help            Show this help.

This helper only operates on:
  project   = $EXPECTED_PROJECT
  service   = $EXPECTED_SERVICE
  container = $EXPECTED_CONTAINER

It will refuse to run if those names are not the disposable ones.
EOF
}

guard_disposable_names() {
    case "$EXPECTED_PROJECT" in
        sfai_pr67_disposable) ;;
        *)
            echo "Refusing: project '$EXPECTED_PROJECT' is not the disposable PR67 project." >&2
            exit 2
            ;;
    esac
    case "$EXPECTED_CONTAINER" in
        sfai-pr67-compose-web) ;;
        *)
            echo "Refusing: container '$EXPECTED_CONTAINER' is not the disposable PR67 container." >&2
            exit 2
            ;;
    esac
    case "$EXPECTED_SERVICE" in
        web) ;;
        *)
            echo "Refusing: service '$EXPECTED_SERVICE' is not the disposable PR67 service." >&2
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
    if ! grep -q "shellforgeai.scope: \"$EXPECTED_SCOPE_LABEL\"" "$COMPOSE_FILE"; then
        echo "Refusing: compose file is missing shellforgeai.scope=$EXPECTED_SCOPE_LABEL label." >&2
        exit 2
    fi
}

cmd_up() {
    guard_disposable_names
    echo "Bringing up disposable Compose stack: $EXPECTED_PROJECT"
    docker compose -f "$COMPOSE_FILE" --project-name "$EXPECTED_PROJECT" up -d
}

cmd_down() {
    guard_disposable_names
    echo "Tearing down disposable Compose stack: $EXPECTED_PROJECT"
    docker compose -f "$COMPOSE_FILE" --project-name "$EXPECTED_PROJECT" down
}

cmd_status() {
    guard_disposable_names
    docker compose -f "$COMPOSE_FILE" --project-name "$EXPECTED_PROJECT" ps
}

cmd_print_env() {
    cat <<EOF
project        = $EXPECTED_PROJECT
service        = $EXPECTED_SERVICE
container      = $EXPECTED_CONTAINER
compose_file   = $COMPOSE_FILE
labels         = shellforgeai.disposable=true,
                 shellforgeai.allow_restart=true,
                 shellforgeai.test_harness=compose-restart,
                 shellforgeai.scope=$EXPECTED_SCOPE_LABEL
EOF
}

cmd_print_commands() {
    cat <<EOF
Manual ShellForgeAI commands for the disposable Compose harness
(run these yourself; this helper never runs them for you):

  shellforgeai compose env-check --target $EXPECTED_CONTAINER
  shellforgeai compose restart-preview $EXPECTED_CONTAINER
  shellforgeai compose propose-restart $EXPECTED_CONTAINER --reason "PR67 disposable harness test"
  shellforgeai approvals validate <proposal-id>
  shellforgeai approvals approve <proposal-id> --reason "PR67 disposable harness test"
  shellforgeai rollback preview <proposal-id>
  shellforgeai rollback validate <rollback-preview>
  shellforgeai mission compose-restart prepare <proposal-id>
  shellforgeai mission compose-restart checklist <mission-id>
  shellforgeai mission compose-restart validate <mission-id>
  shellforgeai mission compose-restart execute <mission-id> --execute --confirm

Do not run --execute --confirm unless the operator (Hector) explicitly
approves the live mutation. Do not run against the production
shellforgeai service. Do not label production services disposable.
EOF
}

main() {
    if [ "$#" -lt 1 ]; then
        usage
        exit 1
    fi
    case "$1" in
        up) cmd_up ;;
        down) cmd_down ;;
        status) cmd_status ;;
        print-env) cmd_print_env ;;
        print-commands) cmd_print_commands ;;
        help|-h|--help) usage ;;
        *)
            echo "Unknown subcommand: $1" >&2
            usage
            exit 1
            ;;
    esac
}

main "$@"
