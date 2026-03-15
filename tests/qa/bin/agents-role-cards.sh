#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="$(mktemp -d /tmp/skwaq-agents-role-cards-XXXXXX)"
target_dir="${CARGO_TARGET_DIR:-/tmp/skwaq-agent-context-target}"
skwaq_bin="$target_dir/debug/skwaq"

cleanup() {
  rm -rf "$run_dir"
}

trap cleanup EXIT

cd "$repo_root"
CARGO_TARGET_DIR="$target_dir" cargo build -q -p skwaq

echo "=== agents-list-command ==="
command_output="$("$skwaq_bin" agents list 2>&1)"
echo "$command_output"

AGENTS_OUTPUT="$command_output" python3 - >"$run_dir/agents-check.txt" <<'PY'
import os

output = os.environ["AGENTS_OUTPUT"]
required = [
    "ROLE",
    "vuln-hunter",
    "Primary discovery specialist",
    "exploit-analyst",
    "Exploitability specialist",
    "defense-analyst",
    "Defensive controls specialist",
    "verdict-synthesizer",
    "Final evidence-weighting synthesizer",
]

missing = [item for item in required if item not in output]
if missing:
    raise SystemExit(f"missing expected agents/roles: {missing}")

print("validated role titles in agents list output")
PY

echo
echo "=== agents-check ==="
cat "$run_dir/agents-check.txt"
