#!/usr/bin/env bash
set -euo pipefail

if script_path="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null)"; then
  :
else
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  script_path="$script_dir/$(basename "${BASH_SOURCE[0]}")"
fi
repo_root="${SKWAQ_REPO_ROOT:-$(cd "$(dirname "$script_path")/../../.." && pwd)}"
run_dir="$(mktemp -d /tmp/skwaq-debate-thresholds-XXXXXX)"
target_dir="${CARGO_TARGET_DIR:-/tmp/skwaq-confidence-threshold-target}"

cleanup() {
  rm -rf "$run_dir"
}

trap cleanup EXIT

cd "$repo_root"

echo "=== threshold-tests ==="
CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
  test_build_debate_summary_marks_high_confidence_confirm -- --nocapture \
  | tee "$run_dir/high-confirm.txt"
CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
  test_build_debate_summary_marks_high_confidence_reject -- --nocapture \
  | tee "$run_dir/high-reject.txt"
CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
  test_build_debate_summary_prefers_weighted_structured_outputs -- --nocapture \
  | tee "$run_dir/review-required.txt"

echo
echo "validated confidence threshold hints in weighted debate summaries"
