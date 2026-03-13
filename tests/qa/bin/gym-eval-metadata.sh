#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="$(mktemp -d "$repo_root/.tmp-gym-eval-XXXXXX")"
temp_out="$(mktemp -d)"

cleanup() {
  rm -rf "$run_dir" "$temp_out"
}

trap cleanup EXIT

mkdir -p "$run_dir/.skwaq"
cat >"$run_dir/.skwaq/config.toml" <<'EOF'
[llm]
reasoning = "copilot"
decompilation = "copilot"

[llm.copilot]
model = "claude-opus-4.6"
EOF

cd "$run_dir"
"$repo_root/target/debug/skwaq" gym eval --quick --suites fixtures --procs 1 --concurrency 1 --output "$temp_out"

echo
echo "=== metadata.json ==="
cat "$temp_out/metadata.json"
echo
echo "=== summary.json ==="
cat "$temp_out/summary.json"
