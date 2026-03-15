#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="$(mktemp -d "$repo_root/.tmp-gym-improve-kb-XXXXXX")"
github_token="$(gh auth token)"

cleanup() {
  rm -rf "$run_dir"
}

trap cleanup EXIT

export HOME="$run_dir/home"
export GITHUB_TOKEN="$github_token"
mkdir -p "$HOME/.skwaq"
ln -s "$repo_root/agents" "$run_dir/agents"
ln -s "$repo_root/data" "$run_dir/data"
cat >"$HOME/.skwaq/config.toml" <<'EOF'
[llm]
reasoning = "copilot"
decompilation = "copilot"

[llm.copilot]
model = "claude-opus-4.6"
EOF

cd "$run_dir"
"$repo_root/target/debug/skwaq" gym improve cyberseceval --max-cases 5
