#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="$(mktemp -d "$repo_root/.tmp-gym-binpool-qa-XXXXXX")"
home_dir="$run_dir/home"
data_dir="$run_dir/data"
staged_cache="$data_dir/skwaq/gym/cache/binpool"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
skwaq_bin="$target_dir/debug/skwaq"

cleanup() {
  rm -rf "$run_dir"
}

trap cleanup EXIT

mkdir -p "$home_dir" "$data_dir"

cd "$repo_root"
cargo build -q -p skwaq

echo "=== unknown-suite ==="
unknown_output="$("$skwaq_bin" gym run does-not-exist --quick 2>&1 || true)"
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
    "$skwaq_bin" gym run binpool --quick --max-cases 1 2>&1 || true
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

echo
echo "=== binpool-empty-extract ==="
mkdir -p "$staged_cache/binpool_artifact"
empty_extract_output="$(
  HOME="$home_dir" XDG_DATA_HOME="$data_dir" \
    "$skwaq_bin" gym run binpool --quick --max-cases 1 2>&1 || true
)"
echo "$empty_extract_output"

if [[ "$empty_extract_output" != *"The extracted tree is incomplete"* ]]; then
  echo "missing incomplete extraction error" >&2
  exit 1
fi

echo
echo "=== binpool-source-only ==="
STAGED_CACHE="$staged_cache" python3 - <<'PY'
import os
import tomllib
from pathlib import Path

manifest = Path("data/gym/ground_truth/binpool.toml")
data = tomllib.loads(manifest.read_text(encoding="utf-8"))
staged_cache = Path(os.environ["STAGED_CACHE"])
for case in data["cases"]:
    binary_path = staged_cache / case["binary_path"]
    binary_path.parent.mkdir(parents=True, exist_ok=True)
    binary_path.touch()
PY
source_only_output="$(
  HOME="$home_dir" XDG_DATA_HOME="$data_dir" \
    "$skwaq_bin" gym run binpool --quick --max-cases 1 --source-only 2>&1 || true
)"
echo "$source_only_output"

if [[ "$source_only_output" != *"BinPool only supports binary analysis"* ]]; then
  echo "missing source-only rejection" >&2
  exit 1
fi

if [[ "$source_only_output" == *"produced no scored cases"* ]]; then
  echo "source-only path still falls through to misleading no-scored-cases summary" >&2
  exit 1
fi
