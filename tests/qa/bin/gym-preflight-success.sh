#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="$(mktemp -d "$repo_root/.tmp-gym-preflight-XXXXXX")"

cleanup() {
  rm -rf "$run_dir"
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
"$repo_root/target/debug/skwaq" gym preflight
