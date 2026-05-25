#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: ./scripts/v1_validate.sh [--quick|--full]

V1 validation helper (non-mutating):
  --quick   Run ruff + compileall + targeted V1 docs/readiness tests
  --full    Run full gates (default): ruff + compileall + full pytest
  --help    Show this message
USAGE
}

mode="full"
case "${1:-}" in
  --quick) mode="quick" ;;
  --full|"") mode="full" ;;
  --help|-h) usage; exit 0 ;;
  *)
    echo "Unknown option: $1" >&2
    usage >&2
    exit 2
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python_bin=""
if command -v python >/dev/null 2>&1; then
  python_bin="python"
elif command -v python3 >/dev/null 2>&1; then
  python_bin="python3"
else
  echo "python/python3 not found; install Python before running validation" >&2
  exit 1
fi

if ! "$python_bin" -m ruff --version >/dev/null 2>&1; then
  echo "python -m ruff not available; install project dev dependencies before validation" >&2
  exit 1
fi

echo "==> ruff"
"$python_bin" -m ruff check .

echo "==> compileall"
"$python_bin" -m compileall -q src tests

if [[ "$mode" == "quick" ]]; then
  echo "==> pytest (quick targeted V1 docs/readiness tests)"
  "$python_bin" -m pytest -q \
    tests/test_pr111_v1_readiness_check.py \
    tests/test_pr112_v1_demo_contract.py \
    tests/test_pr113_v1_validation_hardening.py
  exit 0
fi

if ! command -v ps >/dev/null 2>&1; then
  echo "ps not found; install procps in disposable validation containers before running full pytest" >&2
  exit 1
fi

echo "==> pytest"
"$python_bin" -m pytest -q
