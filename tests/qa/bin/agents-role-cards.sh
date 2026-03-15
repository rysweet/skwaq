#!/usr/bin/env bash
set -euo pipefail

if script_path="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null)"; then
  :
else
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  script_path="$script_dir/$(basename "${BASH_SOURCE[0]}")"
fi
repo_root="${SKWAQ_REPO_ROOT:-$(cd "$(dirname "$script_path")/../../.." && pwd)}"
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
    "SCHEMA",
    "ROLE",
    "vuln-hunter",
    "Primary discovery specialist",
    "vuln-hunter-v1",
    "exploit-analyst",
    "Exploitability specialist",
    "exploit-analyst-v1",
    "defense-analyst",
    "Defensive controls specialist",
    "defense-analyst-v1",
    "verdict-synthesizer",
    "Final evidence-weighting synthesizer",
]

missing = [item for item in required if item not in output]
if missing:
    raise SystemExit(f"missing expected agents/roles: {missing}")

print("validated role titles and schema metadata in agents list output")
PY

echo
echo "=== agents-check ==="
cat "$run_dir/agents-check.txt"
