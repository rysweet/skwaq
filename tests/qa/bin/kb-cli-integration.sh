#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="$(mktemp -d "$repo_root/.tmp-kb-cli-XXXXXX")"

cleanup() {
  rm -rf "$run_dir"
}

trap cleanup EXIT

if [[ -n "${SKWAQ_BIN:-}" ]]; then
  skwaq_bin="$SKWAQ_BIN"
else
  target_root="${CARGO_TARGET_DIR:-$repo_root/target}"
  skwaq_bin="$target_root/debug/skwaq"
  if [[ ! -x "$skwaq_bin" ]]; then
    (cd "$repo_root" && cargo build -q -p skwaq)
  fi
  if [[ ! -x "$skwaq_bin" ]]; then
    echo "skwaq binary not found after build: $skwaq_bin" >&2
    exit 1
  fi
fi

mkdir -p "$run_dir/data/knowledge"
cp "$repo_root"/data/knowledge/*.md "$run_dir/data/knowledge/"

cat >"$run_dir/skwaq.toml" <<EOF
[general]
database_path = "$run_dir/.skwaq/graph"
EOF

cd "$run_dir"

echo "=== kb init ==="
"$skwaq_bin" kb init

echo
echo "=== kb search json ==="
"$skwaq_bin" kb search "cwe-119 buffer overflow" --json
