#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="$(mktemp -d "$repo_root/.tmp-analyze-semantic-qa-XXXXXX")"
home_dir="$run_dir/home"
data_dir="$run_dir/data"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
skwaq_bin="$target_dir/debug/skwaq"

cleanup() {
  rm -rf "$run_dir"
}

trap cleanup EXIT

mkdir -p "$home_dir" "$data_dir"

cd "$repo_root"
cargo build -q -p skwaq

echo "=== ingest-source ==="
ingest_output="$(
  HOME="$home_dir" XDG_DATA_HOME="$data_dir" \
    "$skwaq_bin" ingest source tests/fixtures/buffer_overflow.c 2>&1
)"
echo "$ingest_output"

investigation_id="$(printf '%s\n' "$ingest_output" | grep -o 'inv-[a-z0-9]\+' | tail -n 1)"
if [[ -z "$investigation_id" ]]; then
  echo "failed to parse investigation id from ingest output" >&2
  exit 1
fi

echo
echo "=== analyze-quick ==="
analyze_output="$(
  HOME="$home_dir" XDG_DATA_HOME="$data_dir" \
    "$skwaq_bin" analyze --quick --investigation "$investigation_id" 2>&1
)"
echo "$analyze_output"

if [[ "$analyze_output" != *"SEMANTIC"* ]]; then
  echo "missing semantic column in quick analysis output" >&2
  exit 1
fi

if [[ "$analyze_output" != *"buffer_overflow"* ]]; then
  echo "missing semantic buffer_overflow classification" >&2
  exit 1
fi
