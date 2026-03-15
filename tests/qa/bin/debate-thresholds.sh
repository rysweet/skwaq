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
echo "CASE: vulnerable-consensus"
CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
  test_build_debate_summary_marks_high_confidence_confirm_for_vulnerable_consensus -- --nocapture \
  | tee "$run_dir/high-confirm.txt"
echo "PASS: vulnerable-consensus"
echo "CASE: mitigated-consensus"
CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
  test_build_debate_summary_marks_high_confidence_confirm_for_mitigated_consensus -- --nocapture \
  | tee "$run_dir/mitigated-confirm.txt"
echo "PASS: mitigated-consensus"
echo "CASE: high-confidence-reject"
CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
  test_build_debate_summary_marks_high_confidence_reject -- --nocapture \
  | tee "$run_dir/high-reject.txt"
echo "PASS: high-confidence-reject"
echo "CASE: offense-only-review"
CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
  test_build_debate_summary_requires_review_for_offense_only_signal -- --nocapture \
  | tee "$run_dir/offense-only-review.txt"
echo "PASS: offense-only-review"
echo "CASE: defense-only-review"
CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
  test_build_debate_summary_requires_review_for_defense_only_signal -- --nocapture \
  | tee "$run_dir/defense-only-review.txt"
echo "PASS: defense-only-review"
echo "CASE: weak-consensus-review"
CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
  test_build_debate_summary_requires_review_for_weak_consensus -- --nocapture \
  | tee "$run_dir/weak-consensus-review.txt"
echo "PASS: weak-consensus-review"
echo "CASE: context-summary-thresholds"
CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
  test_build_debate_context_summary_preserves_threshold_hints -- --nocapture \
  | tee "$run_dir/context-summary.txt"
echo "PASS: context-summary-thresholds"
echo "CASE: previous-results-structured-summary"
CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
  test_build_previous_results_context_prefers_structured_summary_over_raw_excerpt -- --nocapture \
  | tee "$run_dir/previous-results-summary.txt"
echo "PASS: previous-results-structured-summary"
echo "CASE: newest-debate-context"
CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
  test_build_previous_results_context_preserves_newest_debate_summary_when_truncated -- --nocapture \
  | tee "$run_dir/newest-debate-context.txt"
echo "PASS: newest-debate-context"
echo "CASE: structured-frame-rendering"
CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
  format_context_frame_includes_structured_summary -- --nocapture \
  | tee "$run_dir/structured-frame-rendering.txt"
echo "PASS: structured-frame-rendering"
echo "CASE: threshold-hints-unavailable"
CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
  test_build_debate_summary_marks_threshold_hints_unavailable_on_parse_failure -- --nocapture \
  | tee "$run_dir/threshold-hints-unavailable.txt"
echo "PASS: threshold-hints-unavailable"
echo "CASE: weighted-structured-summary"
CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
  test_build_debate_summary_prefers_weighted_structured_outputs -- --nocapture \
  | tee "$run_dir/weighted-structured.txt"
echo "PASS: weighted-structured-summary"

echo
echo "validated confidence threshold hints in weighted debate summaries"
