#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: ./scripts/v1_validate.sh [--quick|--full] [--packet] [--export-packet]

V1 validation helper (non-mutating):
  --quick          Run ruff + compileall + targeted V1 docs/readiness tests
  --full           Run full gates (default): ruff + compileall + full pytest
  --packet         After successful validation, save and validate a V1 packet artifact
  --export-packet  With --packet, export and export-validate the saved packet artifact
  --help           Show this message
USAGE
}

mode="full"
packet_mode=0
export_packet_mode=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) mode="quick" ;;
    --full) mode="full" ;;
    --packet) packet_mode=1 ;;
    --export-packet) export_packet_mode=1 ;;
    --help|-h) usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ "$export_packet_mode" -eq 1 ]]; then
  packet_mode=1
fi

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
  echo "python -m ruff not available; v1_validate.sh requires dev validation dependencies." >&2
  echo "Run this helper from the writable validation container/lane, not the minimal runtime image." >&2
  exit 1
fi

echo "ShellForgeAI V1 validation"
echo "profile: $mode"

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
else
  if ! command -v ps >/dev/null 2>&1; then
    echo "ps not found; install procps in disposable validation containers before running full pytest" >&2
    exit 1
  fi

  echo "==> pytest"
  "$python_bin" -m pytest -q
fi

echo "validation: passed"

if [[ "$packet_mode" -eq 1 ]]; then
  packet_timeout_seconds="${SFAI_VALIDATE_COMMAND_TIMEOUT_SECONDS:-60}"
  have_timeout=0
  if command -v timeout >/dev/null 2>&1; then
    have_timeout=1
  else
    echo "warning: timeout command not found; packet commands will run without timeout guard" >&2
  fi

  run_packet_cmd() {
    if [[ "$have_timeout" -eq 1 ]]; then
      timeout "$packet_timeout_seconds" "$@"
    else
      "$@"
    fi
  }

  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT
  save_stdout="$tmp_dir/packet-save.stdout.json"
  save_stderr="$tmp_dir/packet-save.stderr.log"
  validate_stdout="$tmp_dir/packet-validate.stdout.json"
  validate_stderr="$tmp_dir/packet-validate.stderr.log"
  export_stdout="$tmp_dir/packet-export.stdout.json"
  export_stderr="$tmp_dir/packet-export.stderr.log"
  export_validate_stdout="$tmp_dir/packet-export-validate.stdout.json"
  export_validate_stderr="$tmp_dir/packet-export-validate.stderr.log"

  show_snippet() {
    local label="$1"
    local path="$2"
    echo "$label (first 20 lines):" >&2
    if [[ -s "$path" ]]; then
      sed -n '1,20p' "$path" >&2
    else
      echo "<empty>" >&2
    fi
  }

  parse_json_value() {
    local json_path="$1"
    local expr="$2"
    "$python_bin" -c "import json,sys; p=json.load(open(sys.argv[1], encoding='utf-8')); print(${expr})" "$json_path"
  }

  echo
  echo "==> shellforgeai v1 packet --save --json"
  rc=0
  run_packet_cmd shellforgeai v1 packet --save --json >"$save_stdout" 2>"$save_stderr" || rc=$?
  if [[ "${rc:-0}" -ne 0 ]]; then
    echo "Packet save failed: shellforgeai v1 packet --save --json" >&2
    echo "rc: $rc" >&2
    if [[ "$rc" -eq 124 ]]; then
      echo "command timed out after ${packet_timeout_seconds}s" >&2
    fi
    show_snippet "stdout" "$save_stdout"
    show_snippet "stderr" "$save_stderr"
    exit 1
  fi

  packet_ref="$(parse_json_value "$save_stdout" "p.get('packet_id') or (p.get('artifact') or {}).get('id') or p.get('packet_path') or (p.get('artifact') or {}).get('path') or ''" 2>/dev/null || true)"
  if [[ -z "$packet_ref" ]]; then
    echo "Failed to parse packet JSON from shellforgeai v1 packet --save --json" >&2
    show_snippet "stdout" "$save_stdout"
    show_snippet "stderr" "$save_stderr"
    exit 1
  fi

  packet_id="$packet_ref"
  packet_path="$(parse_json_value "$save_stdout" "p.get('packet_path') or (p.get('artifact') or {}).get('path') or ''" 2>/dev/null || true)"

  echo "==> shellforgeai v1 packet validate $packet_id --json"
  rc=0
  run_packet_cmd shellforgeai v1 packet validate "$packet_id" --json >"$validate_stdout" 2>"$validate_stderr" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    echo "Packet validation failed: shellforgeai v1 packet validate $packet_id --json" >&2
    echo "rc: $rc" >&2
    show_snippet "stdout" "$validate_stdout"
    show_snippet "stderr" "$validate_stderr"
    exit 1
  fi

  validate_out="$tmp_dir/packet-validate-summary.out"
  if ! "$python_bin" -c 'import json,sys;p=json.load(open(sys.argv[1],encoding="utf-8"));s=p.get("safety") or {};c=p.get("checks") or {};print(p.get("status","unknown"));print(s.get("read_only"));print(s.get("mutation_performed"));print((c.get("readiness") or {}).get("status","n/a"));print((c.get("docs") or {}).get("status","n/a"));print((c.get("command_surface") or {}).get("status","n/a"))' "$validate_stdout" >"$validate_out"
  then
    echo "Failed to parse packet validate JSON from shellforgeai v1 packet validate $packet_id --json" >&2
    show_snippet "stdout" "$validate_stdout"
    show_snippet "stderr" "$validate_stderr"
    exit 1
  fi

  validation_status="$(sed -n '1p' "$validate_out")"
  read_only="$(sed -n '2p' "$validate_out")"
  mutation_performed="$(sed -n '3p' "$validate_out")"
  readiness_status="$(sed -n '4p' "$validate_out")"
  docs_status="$(sed -n '5p' "$validate_out")"
  command_surface_status="$(sed -n '6p' "$validate_out")"

  echo
  echo "V1 packet:"
  echo "- packet_id: $packet_id"
  echo "- packet_path: $packet_path"
  echo "- validation: $validation_status"
  echo "- read_only: $read_only"
  echo "- mutation_performed: $mutation_performed"
  echo "- readiness_status: $readiness_status"
  echo "- docs_status: $docs_status"
  echo "- command_surface_status: $command_surface_status"

  if [[ "$export_packet_mode" -eq 1 ]]; then
    echo
    echo "==> shellforgeai v1 packet export $packet_id --json"
    rc=0
    run_packet_cmd shellforgeai v1 packet export "$packet_id" --json >"$export_stdout" 2>"$export_stderr" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
      echo "Packet export failed: shellforgeai v1 packet export $packet_id --json" >&2
      echo "rc: $rc" >&2
      show_snippet "stdout" "$export_stdout"
      show_snippet "stderr" "$export_stderr"
      exit 1
    fi

    export_parse="$tmp_dir/packet-export-parse.out"
    if ! "$python_bin" -c 'import json,sys;p=json.load(open(sys.argv[1],encoding="utf-8"));a=p.get("artifact") or p.get("export") or {};eid=a.get("id") or p.get("export_id") or "";ep=a.get("path") or p.get("export_path") or "";print(eid);print(ep);raise SystemExit(0 if eid and ep else 1)' "$export_stdout" >"$export_parse"
    then
      echo "Failed to parse packet export JSON from shellforgeai v1 packet export $packet_id --json" >&2
      show_snippet "stdout" "$export_stdout"
      show_snippet "stderr" "$export_stderr"
      exit 1
    fi

    export_id="$(sed -n '1p' "$export_parse")"
    export_path="$(sed -n '2p' "$export_parse")"

    echo "==> shellforgeai v1 packet export-validate $export_id --json"
    rc=0
    run_packet_cmd shellforgeai v1 packet export-validate "$export_id" --json >"$export_validate_stdout" 2>"$export_validate_stderr" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
      echo "Packet export validation failed: shellforgeai v1 packet export-validate $export_id --json" >&2
      echo "rc: $rc" >&2
      show_snippet "stdout" "$export_validate_stdout"
      show_snippet "stderr" "$export_validate_stderr"
      exit 1
    fi

    echo "V1 packet export:"
    echo "- export_id: $export_id"
    echo "- export_path: $export_path"
  fi
fi

echo
echo "Done."
