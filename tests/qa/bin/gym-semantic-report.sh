#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="$(mktemp -d "$repo_root/.tmp-gym-semantic-report-XXXXXX")"
home_dir="$run_dir/home"
data_dir="$run_dir/data"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
skwaq_bin="$target_dir/debug/skwaq"
report_json="$run_dir/report.json"
report_md="$run_dir/report.md"

cleanup() {
  rm -rf "$run_dir"
}

trap cleanup EXIT

mkdir -p "$home_dir" "$data_dir"

cd "$repo_root"
cargo build -q -p skwaq

echo "=== semantic-report-command ==="
command_output="$(
  HOME="$home_dir" XDG_DATA_HOME="$data_dir" \
    "$skwaq_bin" gym run fixtures --quick --source-only --cwe CWE-121 --max-cases 1 -j 1 \
    --json "$report_json" --markdown "$report_md" 2>&1
)"
echo "$command_output"

python3 - "$report_json" "$report_md" >"$run_dir/report-check.txt" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
classes = {entry["class_name"] for entry in report.get("per_semantic", [])}
if "buffer_overflow" not in classes:
    raise SystemExit(f"expected buffer_overflow in per_semantic, got {sorted(classes)}")

markdown = Path(sys.argv[2]).read_text()
if "## Per-Semantic Detection Rates" not in markdown:
    raise SystemExit("missing semantic section heading in markdown report")
if "buffer_overflow" not in markdown:
    raise SystemExit("missing buffer_overflow row in markdown report")

print("validated semantic report classes:", ", ".join(sorted(classes)))
PY

echo
echo "=== report-check ==="
cat "$run_dir/report-check.txt"
echo
echo "=== report.json ==="
cat "$report_json"
echo
echo "=== report.md ==="
cat "$report_md"
