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

run_case() {
  local case_name="$1"
  local test_filter="$2"
  local output_file="$3"

  echo "CASE: $case_name"
  CARGO_TARGET_DIR="$target_dir" cargo test -q -p skwaq-core \
    "$test_filter" -- --nocapture | tee "$run_dir/$output_file"
  grep -q "running 1 test" "$run_dir/$output_file"
  grep -q "test result: ok. 1 passed; 0 failed;" "$run_dir/$output_file"
  echo "PASS: $case_name"
}

echo "=== threshold-tests ==="
run_case "vulnerable-consensus" \
  "test_build_debate_summary_marks_high_confidence_confirm_for_vulnerable_consensus" \
  "high-confirm.txt"
run_case "mitigated-consensus" \
  "test_build_debate_summary_marks_high_confidence_confirm_for_mitigated_consensus" \
  "mitigated-confirm.txt"
run_case "high-confidence-reject" \
  "test_build_debate_summary_marks_high_confidence_reject" \
  "high-reject.txt"
run_case "offense-only-review" \
  "test_build_debate_summary_requires_review_for_offense_only_signal" \
  "offense-only-review.txt"
run_case "defense-only-review" \
  "test_build_debate_summary_requires_review_for_defense_only_signal" \
  "defense-only-review.txt"
run_case "weak-consensus-review" \
  "test_build_debate_summary_requires_review_for_weak_consensus" \
  "weak-consensus-review.txt"
run_case "confirm-requires-strong-offense" \
  "test_build_debate_summary_requires_strong_offense_signal_for_auto_confirm" \
  "confirm-requires-strong-offense.txt"
run_case "duplicate-title-no-inflation" \
  "test_build_debate_summary_does_not_inflate_duplicate_title_scores" \
  "duplicate-title-no-inflation.txt"
run_case "duplicate-title-conflict-review" \
  "test_build_debate_summary_reviews_conflicting_duplicate_titles_regardless_of_order" \
  "duplicate-title-conflict-review.txt"
run_case "context-summary-thresholds" \
  "test_build_debate_context_summary_preserves_threshold_hints" \
  "context-summary.txt"
run_case "previous-results-structured-summary" \
  "test_build_previous_results_context_prefers_structured_summary_over_raw_excerpt" \
  "previous-results-summary.txt"
run_case "newest-debate-context" \
  "test_build_previous_results_context_preserves_newest_debate_summary_when_truncated" \
  "newest-debate-context.txt"
run_case "oversized-newest-context" \
  "test_build_previous_results_context_keeps_truncated_newest_section_when_oversized" \
  "oversized-newest-context.txt"
run_case "structured-frame-rendering" \
  "format_context_frame_includes_structured_summary" \
  "structured-frame-rendering.txt"
run_case "threshold-hints-unavailable" \
  "test_build_debate_summary_marks_threshold_hints_unavailable_on_parse_failure" \
  "threshold-hints-unavailable.txt"
run_case "fallback-context-unavailable-note" \
  "test_build_debate_context_summary_preserves_unavailable_note_on_fallback_summary" \
  "fallback-context-unavailable-note.txt"
run_case "fallback-disagreement-warning" \
  "test_build_debate_context_summary_preserves_fallback_disagreement_warning" \
  "fallback-disagreement-warning.txt"
run_case "weighted-structured-summary" \
  "test_build_debate_summary_prefers_weighted_structured_outputs" \
  "weighted-structured.txt"

echo
echo "validated confidence threshold hints in weighted debate summaries"
