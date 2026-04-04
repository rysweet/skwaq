#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="$(mktemp -d "$repo_root/.tmp-gym-cybergym-case-targeting-XXXXXX")"
home_dir="$run_dir/home"
data_home="$run_dir/data"
skwaq_root="$run_dir/skwaq-root"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
skwaq_bin="$target_dir/debug/skwaq"
report_json="$run_dir/report.json"
command_log="$run_dir/command.log"
case_cache="$data_home/skwaq/gym/cache/cybergym"
dataset_dir="$case_cache/dataset"
cases_dir="$case_cache/cases"
fix_case_dir="$cases_dir/arvo_1065-fix"

cleanup() {
  rm -rf "$run_dir"
}

trap cleanup EXIT HUP INT TERM

mkdir -p "$home_dir" "$case_cache" "$cases_dir" "$skwaq_root/data/gym/ground_truth"

cat >"$skwaq_root/Cargo.toml" <<'EOF'
[workspace]
members = []
EOF

cat >"$skwaq_root/data/gym/ground_truth/fixtures.toml" <<'EOF'
suite = "fixtures"
version = "qa"
download_url = ""
download_sha256 = ""
cases = []
EOF

cat >"$skwaq_root/data/gym/ground_truth/cybergym.toml" <<'EOF'
suite = "cybergym"
version = "qa"
download_url = ""
download_sha256 = ""

[[cases]]
id = "arvo:12096"
path = "cases/arvo:12096"
expected_cwes = [401]
is_negative = false
language = "cpp"

[[cases]]
id = "arvo:1065"
path = "cases/arvo:1065"
expected_cwes = [457]
is_negative = false
language = "cpp"

[[cases]]
id = "arvo:1065-fix"
path = "cases/arvo:1065-fix"
expected_cwes = [457]
is_negative = true
language = "cpp"
EOF

ln -s /data/cybergym/dataset "$dataset_dir"
touch "$case_cache/.ready"
mkdir -p "$cases_dir/arvo_12096"
tar -xzf /data/cybergym/dataset/data/arvo/12096/repo-vul.tar.gz -C "$cases_dir/arvo_12096"
mkdir -p "$cases_dir/arvo_1065"
tar -xzf /data/cybergym/dataset/data/arvo/1065/repo-vul.tar.gz -C "$cases_dir/arvo_1065"

echo "=== cybergym-targeting-command ==="
(
  cd "$repo_root"
  HOME="$home_dir" \
  XDG_DATA_HOME="$data_home" \
  SKWAQ_ROOT="$skwaq_root" \
  CARGO_TERM_COLOR=never \
    "$skwaq_bin" \
    gym run cybergym --quick --source-only --max-cases 3 -j 1 \
    --json "$report_json"
) >"$command_log" 2>&1
cat "$command_log"

python3 - "$report_json" "$fix_case_dir" "$command_log" >"$run_dir/report-check.txt" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
fix_case_dir = Path(sys.argv[2])
command_log = Path(sys.argv[3]).read_text()

if report.get("suite") != "cybergym":
    raise SystemExit(f"expected cybergym suite, got {report.get('suite')!r}")

expected_totals = {401: 1, 457: 2}
actual_totals = {entry.get("cwe_id"): entry.get("total_cases") for entry in report.get("per_cwe", [])}
for cwe_id, total_cases in expected_totals.items():
    if actual_totals.get(cwe_id) != total_cases:
        raise SystemExit(
            f"expected CWE-{cwe_id} total_cases={total_cases} in report, got {report.get('per_cwe')!r}"
        )

if not fix_case_dir.is_dir():
    raise SystemExit(f"expected fix case extraction at {fix_case_dir}")

if "No C/C++ source files found" in command_log:
    raise SystemExit("deep-tree source fallback still reported missing source files")

if "CyberGym case arvo:1065-fix unavailable" in command_log:
    raise SystemExit("fix case still unavailable during stale-cache run")

print("validated cybergym report cwe_totals=401:1,457:2")
print("validated missing fix case extracted on demand")
print("validated deep-tree case avoided missing-source warning")
PY

echo
echo "=== report-check ==="
cat "$run_dir/report-check.txt"
echo
echo "=== report.json ==="
cat "$report_json"
