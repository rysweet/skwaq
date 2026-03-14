#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="$(mktemp -d)"
chmod 700 "$run_dir"
home_dir="$run_dir/home"
out_dir="$run_dir/out"

cleanup() {
  rm -rf "$run_dir"
}

trap cleanup EXIT HUP INT TERM

mkdir -p "$home_dir/.skwaq" "$home_dir/.local/share" "$home_dir/.config" "$out_dir"

cat >"$home_dir/.skwaq/config.toml" <<'EOF'
[llm]
reasoning = "copilot"
decompilation = "copilot"

[llm.copilot]
model = "claude-opus-4.6"
EOF

if [ -d "$HOME/.config/gh" ]; then
  cp -R "$HOME/.config/gh" "$home_dir/.config/gh"
fi

make -C "$repo_root/tests/fixtures" buffer_overflow_O0
python3 \
  "$repo_root/tests/gadugi/seed_ghidra_cache.py" \
  "$repo_root/tests/fixtures/binaries/buffer_overflow_O0" \
  "$home_dir" \
  >"$run_dir/cache-path.txt"

(
  cd "$repo_root"
  HOME="$home_dir" \
  XDG_DATA_HOME="$home_dir/.local/share" \
  GHIDRA_INSTALL_DIR="/nonexistent/ghidra" \
  RUST_LOG=info \
  CARGO_TERM_COLOR=never \
    "$repo_root/target/debug/skwaq" \
    gym run fixtures --cwe CWE-121 --max-cases 1 -j 1 \
    --json "$out_dir/report.json"
) >"$run_dir/command.log" 2>&1

python3 - "$out_dir/report.json" >"$run_dir/report-check.txt" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
for result in report.get("per_cwe", []):
    if result.get("cwe_id") == 119 and result.get("true_positives", 0) >= 1:
        print(f'validated cwe_family=119 true_positives={result["true_positives"]}')
        raise SystemExit(0)

raise SystemExit("expected cached Ghidra run to produce a CWE-119-family true positive")
PY

echo "=== cache-path ==="
cat "$run_dir/cache-path.txt"
echo
echo "=== command.log ==="
cat "$run_dir/command.log"
echo
echo "=== report-check ==="
cat "$run_dir/report-check.txt"
echo
echo "=== report.json ==="
cat "$out_dir/report.json"
