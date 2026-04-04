#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="$(mktemp -d "$repo_root/.tmp-gym-eval-azure-clamp-XXXXXX")"
temp_out="$(mktemp -d)"

cleanup() {
  rm -rf "$run_dir" "$temp_out"
}

trap cleanup EXIT

mkdir -p "$run_dir/.skwaq"
cat >"$run_dir/.skwaq/config.toml" <<'EOF'
[llm]
reasoning = "azure"
decompilation = "azure"

[llm.azure]
endpoint = "https://example.cognitiveservices.azure.com/"
deployment = "gpt-54-test"
api_version = "2024-10-21"
EOF

cd "$run_dir"
"$repo_root/target/debug/skwaq" gym eval --quick --suites fixtures --procs 9 -j 32 --output "$temp_out" >"$temp_out/cmd.log" 2>&1

echo "=== command.log ==="
cat "$temp_out/cmd.log"
echo
echo "=== metadata.json ==="
jq '{llm_backend, procs_per_suite, concurrency}' "$temp_out/metadata.json"
