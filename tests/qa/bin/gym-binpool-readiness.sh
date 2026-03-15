#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="$(mktemp -d "$repo_root/.tmp-gym-binpool-qa-XXXXXX")"
home_dir="$run_dir/home"
data_dir="$run_dir/data"

cleanup() {
  rm -rf "$run_dir"
}

trap cleanup EXIT

mkdir -p "$home_dir" "$data_dir"

cd "$repo_root"
cargo build -q -p skwaq

echo "=== unknown-suite ==="
unknown_output="$("$repo_root/target/debug/skwaq" gym run does-not-exist --quick 2>&1 || true)"
echo "$unknown_output"

if [[ "$unknown_output" != *"Unknown suite. Available: "* ]]; then
  echo "missing unknown-suite error banner" >&2
  exit 1
fi

if [[ "$unknown_output" != *"binpool"* ]]; then
  echo "missing binpool in available suite list" >&2
  exit 1
fi

echo
echo "=== binpool-missing-data ==="
binpool_output="$(
  HOME="$home_dir" XDG_DATA_HOME="$data_dir" \
    "$repo_root/target/debug/skwaq" gym run binpool --quick --max-cases 1 2>&1 || true
)"
echo "$binpool_output"

if [[ "$binpool_output" != *"BinPool data is not auto-downloaded by skwaq."* ]]; then
  echo "missing manual BinPool setup guidance" >&2
  exit 1
fi

if [[ "$binpool_output" != *"binpool_artifact/"* ]]; then
  echo "missing binpool_artifact extraction path" >&2
  exit 1
fi
