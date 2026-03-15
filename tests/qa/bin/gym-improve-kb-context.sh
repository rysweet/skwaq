#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="$(mktemp -d "$repo_root/.tmp-gym-improve-kb-XXXXXX")"
host_home="${HOME:-}"
insights_file="$repo_root/data/knowledge/fn-insights.md"
insights_before_size=0

if [[ -f "$insights_file" ]]; then
  insights_before_size="$(wc -c < "$insights_file" | tr -d ' ')"
fi

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
export RUST_LOG="${RUST_LOG:-info}"
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

if [[ ! -f "$insights_file" ]]; then
  echo "ERROR: fn-insights file was not created" >&2
  exit 1
fi

new_insights="$run_dir/fn-insights-current-run.md"
python3 - "$insights_file" "$insights_before_size" "$new_insights" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
offset = int(sys.argv[2])
dest = Path(sys.argv[3])
data = source.read_bytes()
if offset > len(data):
    offset = 0
dest.write_bytes(data[offset:])
PY

[[ -s "$new_insights" ]] || {
  echo "ERROR: current run did not append any fn-insights content" >&2
  exit 1
}

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
printf '%s\n' "$output" | grep -Fq "Proposals rejected by review:" || {
  echo "ERROR: improve output did not surface overfitting review counts" >&2
  exit 1
}
printf '%s\n' "$output" | grep -Eq "Evidence: \[(KB|MEMORY|HEURISTIC)\]" || {
  echo "ERROR: improve output did not surface analyst evidence" >&2
  exit 1
}
printf '%s\n' "$output" | grep -Eq "Review evidence: \[(KB|MEMORY|HEURISTIC)\]" || {
  echo "ERROR: improve output did not surface review evidence" >&2
  exit 1
}
printf '%s\n' "$output" | grep -Eq "Review: (ACCEPT|REJECT|MODIFY) \| Risk=(LOW|MEDIUM|HIGH) \| Applicability=(LOW|MEDIUM|HIGH)" || {
  echo "ERROR: improve output did not surface structured review verdicts" >&2
  exit 1
}
grep -Fq "### Reviewed Improvement Proposals" "$new_insights" || {
  echo "ERROR: fn-insights did not record reviewed proposal decisions" >&2
  exit 1
}
grep -Eq "Overfitting review: (ACCEPT|REJECT|MODIFY)" "$new_insights" || {
  echo "ERROR: fn-insights did not preserve structured review verdicts" >&2
  exit 1
}
grep -Eq "\[(KB|MEMORY|HEURISTIC)\]" "$new_insights" || {
  echo "ERROR: fn-insights did not preserve cited evidence" >&2
  exit 1
}

memory_stats="$("$repo_root/target/debug/skwaq" memory stats --agent failure-analyst 2>&1)"
printf '%s\n' "$memory_stats"
printf '%s\n' "$memory_stats" | grep -Eq "Total:[[:space:]]*[1-9][0-9]*" || {
  echo "ERROR: improve command did not persist durable memory lessons for failure-analyst" >&2
  exit 1
}

echo "QA CHECK: methodology KB query returned positive hits"
echo "QA CHECK: cwe-families KB query returned positive hits"
echo "QA CHECK: improve cycle prepared non-empty KB guidance snippets"
echo "QA CHECK: improve output surfaced cited review evidence"
echo "QA CHECK: fn-insights preserved reviewed proposal evidence"
echo "QA CHECK: improve command persisted durable memory lessons"
