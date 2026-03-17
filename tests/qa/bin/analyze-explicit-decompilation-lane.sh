#!/usr/bin/env bash
set -euo pipefail

script_path="$(readlink -f "${BASH_SOURCE[0]}")"
repo_root="$(cd "$(dirname "$script_path")/../../.." && pwd)"
run_dir="$(mktemp -d "$repo_root/.tmp-explicit-decomp-lane-XXXXXX")"
home_dir="$run_dir/home"
data_dir="$run_dir/data"
workspace_dir="$run_dir/workspace"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
skwaq_bin="$target_dir/debug/skwaq"

cleanup() {
  rm -rf "$run_dir"
}

trap cleanup EXIT

mkdir -p "$home_dir" "$data_dir" "$workspace_dir"

cd "$repo_root"
cargo build -q -p skwaq

cat >"$workspace_dir/skwaq.toml" <<'EOF'
[llm]
reasoning = "anthropic"
decompilation = "auto"

[analysis]
default_token_budget = 0
EOF

cat >"$workspace_dir/sample.c" <<'EOF'
#include <stdio.h>

int main(void) {
    puts("hello");
    return 0;
}
EOF

common_env=(
  "HOME=$home_dir"
  "XDG_DATA_HOME=$data_dir"
  "ANTHROPIC_API_KEY=sk-ant-test-key-123"
)

echo "=== ingest-source ==="
ingest_output="$(
  cd "$workspace_dir" &&
    env "${common_env[@]}" "$skwaq_bin" ingest source sample.c 2>&1
)"
echo "$ingest_output"

investigation_id="$(printf '%s\n' "$ingest_output" | grep -o 'inv-[a-z0-9]\+' | tail -n 1)"
if [[ -z "$investigation_id" ]]; then
  echo "failed to parse investigation id from ingest output" >&2
  exit 1
fi

echo
echo "=== analyze-default-source ==="
default_output="$(
  cd "$workspace_dir" &&
    env "${common_env[@]}" \
      "$skwaq_bin" analyze --investigation "$investigation_id" --budget 0 2>&1
)"
echo "$default_output"

if [[ "$default_output" == *"Unsupported llm.decompilation backend"* ]]; then
  echo "default source pipeline still rejected unused llm.decompilation" >&2
  exit 1
fi

if [[ "$default_output" != *"Pipeline: attack-surface -> vuln-hunter -> critic"* ]]; then
  echo "default source pipeline did not stay on the reasoning-only source path" >&2
  exit 1
fi

echo "default source pipeline stayed on reasoning lane"

echo
echo "=== analyze-reasoning-only ==="
reasoning_output="$(
  cd "$workspace_dir" &&
    env "${common_env[@]}" \
      "$skwaq_bin" analyze --investigation "$investigation_id" --agent attack-surface --budget 0 2>&1
)"
echo "$reasoning_output"

if [[ "$reasoning_output" == *"Unsupported llm.decompilation backend"* ]]; then
  echo "reasoning-only pipeline still rejected unused llm.decompilation" >&2
  exit 1
fi

if [[ "$reasoning_output" != *"Pipeline: attack-surface"* ]]; then
  echo "reasoning-only pipeline did not report the selected agent" >&2
  exit 1
fi

if [[ "$reasoning_output" != *"Total tokens used: 0"* ]]; then
  echo "reasoning-only pipeline did not honor zero-budget execution" >&2
  exit 1
fi

echo "reasoning-only pipeline ignored unused llm.decompilation"

echo
echo "=== analyze-decompile-only ==="
set +e
decompilation_output="$(
  cd "$workspace_dir" &&
    env "${common_env[@]}" \
      "$skwaq_bin" analyze --investigation "$investigation_id" --agent decompile-analyst --budget 0 2>&1
)"
decompilation_status=$?
set -e
echo "$decompilation_output"

if [[ $decompilation_status -eq 0 ]]; then
  echo "decompile-only pipeline unexpectedly succeeded with invalid llm.decompilation" >&2
  exit 1
fi

if [[ "$decompilation_output" != *"Unsupported llm.decompilation backend"* ]]; then
  echo "decompile-only pipeline did not fail with explicit llm.decompilation error" >&2
  exit 1
fi

echo "decompile pipeline failed explicitly on llm.decompilation"
