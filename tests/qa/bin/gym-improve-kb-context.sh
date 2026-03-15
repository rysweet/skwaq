#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="$(mktemp -d "$repo_root/.tmp-gym-improve-kb-XXXXXX")"
host_home="${HOME:-}"

if ! github_token="$(gh auth token)"; then
  echo "ERROR: failed to retrieve a GitHub token via 'gh auth token'" >&2
  exit 1
fi

cleanup() {
  rm -rf "$run_dir"
}

trap cleanup EXIT

cd "$repo_root"
cargo build -q -p skwaq

export HOME="$run_dir/home"
export GITHUB_TOKEN="$github_token"
if [[ -n "$host_home" ]]; then
  export CARGO_HOME="${CARGO_HOME:-$host_home/.cargo}"
  export RUSTUP_HOME="${RUSTUP_HOME:-$host_home/.rustup}"
fi
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
output="$("$repo_root/target/debug/skwaq" gym improve cyberseceval --max-cases 5 2>&1)"
printf '%s\n' "$output"

printf '%s\n' "$output" | grep -Eq "KB query 'methodology' returned [1-9][0-9]* hit\\(s\\)" || {
  echo "ERROR: methodology KB query did not return a positive hit count" >&2
  exit 1
}
printf '%s\n' "$output" | grep -Eq "KB query 'cwe-families' returned [1-9][0-9]* hit\\(s\\)" || {
  echo "ERROR: cwe-families KB query did not return a positive hit count" >&2
  exit 1
}
printf '%s\n' "$output" | grep -Eq "Prepared [1-9][0-9]* KB guidance snippet\\(s\\) for improve cycle context" || {
  echo "ERROR: improve cycle did not prepare non-empty KB guidance snippets" >&2
  exit 1
}

echo "QA CHECK: methodology KB query returned positive hits"
echo "QA CHECK: cwe-families KB query returned positive hits"
echo "QA CHECK: improve cycle prepared non-empty KB guidance snippets"
